//! Files and folders: listing, details, create folder, rename, move, trash.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use leptiq_core::{
    AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult, code},
    util::{new_id, now, ok, ok_empty},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::model::{self, ACTIVE, FOLDER, Link, TRASHED};

const CHILDREN_PAGE: usize = 150;
const TRASH_PAGE: usize = 150;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChildrenQuery {
    #[serde(rename = "AnchorID")]
    anchor_id: Option<String>,
    folders_only: Option<i64>,
}

/// `GET drive/v2/volumes/{v}/folders/{l}/children`: active children IDs,
/// paged by `AnchorID`.
pub async fn children(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id)): Path<(String, String)>,
    Query(q): Query<ChildrenQuery>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    model::active_folder(&state, &v.id, &link_id).await?;
    let folders_only = q.folders_only.unwrap_or(0) == 1;
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM drive_links WHERE volume_id = $1 AND parent_id = $2 AND state = 1 \
         AND ($3 = 0 OR link_type = 1) ORDER BY created, id",
    )
    .bind(&v.id)
    .bind(&link_id)
    .bind(folders_only as i64)
    .fetch_all(&state.db)
    .await?;
    let ids: Vec<String> = rows.into_iter().map(|r| r.0).collect();
    let start = match q.anchor_id.as_deref().filter(|a| !a.is_empty()) {
        Some(a) => ids
            .iter()
            .position(|i| i == a)
            .map(|i| i + 1)
            .unwrap_or(ids.len()),
        None => 0,
    };
    let page: Vec<&String> = ids.iter().skip(start).take(CHILDREN_PAGE).collect();
    let more = start + page.len() < ids.len();
    let anchor = if more {
        page.last().map(|s| s.to_string())
    } else {
        None
    };
    Ok(ok(
        json!({ "LinkIDs": page, "AnchorID": anchor, "More": more }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LinkIdsReq {
    #[serde(rename = "LinkIDs")]
    link_ids: Vec<String>,
}

/// `POST drive/v2/volumes/{v}/links` (and the photos variant): details of up
/// to 100 links; unknown IDs are left out.
pub async fn details(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<LinkIdsReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let owner = model::owner_email(&state, &user.user_id).await?;
    let mut out = Vec::new();
    for id in r.link_ids.iter().take(100) {
        if let Some(l) = model::find_link(&state, &v.id, id).await? {
            out.push(model::link_details(&state, &v, &l, &owner).await?);
        }
    }
    Ok(ok(json!({ "Links": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFolderReq {
    #[serde(rename = "ParentLinkID")]
    parent_link_id: String,
    node_key: String,
    node_hash_key: String,
    node_passphrase: String,
    node_passphrase_signature: String,
    #[serde(default)]
    signature_email: Option<String>,
    #[serde(default)]
    signature_address: Option<String>,
    name: String,
    hash: String,
    #[serde(rename = "XAttr", default)]
    xattr: Option<String>,
}

pub async fn create_folder(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<CreateFolderReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    model::active_folder(&state, &v.id, &r.parent_link_id).await?;
    model::check_name_free(&state, &v.id, &r.parent_link_id, &r.hash, None).await?;
    let email = r.signature_email.or(r.signature_address);
    let id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO drive_links (id, volume_id, parent_id, link_type, state, name, name_hash, node_key, \
         node_passphrase, node_passphrase_signature, node_hash_key, xattr, signature_email, name_signature_email, \
         created, modified) VALUES ($1, $2, $3, 1, 1, $4, $5, $6, $7, $8, $9, $10, $11, $11, $12, $12)",
    )
    .bind(&id)
    .bind(&v.id)
    .bind(&r.parent_link_id)
    .bind(&r.name)
    .bind(&r.hash)
    .bind(&r.node_key)
    .bind(&r.node_passphrase)
    .bind(&r.node_passphrase_signature)
    .bind(&r.node_hash_key)
    .bind(&r.xattr)
    .bind(&email)
    .bind(t)
    .execute(&state.db)
    .await?;
    let l = model::link(&state, &v.id, &id).await?;
    model::event(&state, &v.id, model::EVENT_CREATE, &l).await?;
    Ok(ok(json!({ "Folder": { "ID": id } })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RenameReq {
    name: String,
    #[serde(default)]
    name_signature_email: Option<String>,
    hash: String,
    #[serde(default)]
    original_hash: Option<String>,
}

pub async fn rename(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id)): Path<(String, String)>,
    Json(r): Json<RenameReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    let Some(parent) = l.parent_id.as_deref() else {
        return Err(ApiError::bad_request("The root folder cannot be renamed"));
    };
    if let Some(orig) = &r.original_hash
        && l.name_hash.as_deref() != Some(orig.as_str())
    {
        return Err(model::invalid_requirements(
            "The name changed in the meantime",
        ));
    }
    model::check_name_free(&state, &v.id, parent, &r.hash, Some(&l.id)).await?;
    sqlx::query(
        "UPDATE drive_links SET name = $1, name_hash = $2, name_signature_email = COALESCE($3, name_signature_email), \
         modified = $4 WHERE id = $5",
    )
    .bind(&r.name)
    .bind(&r.hash)
    .bind(&r.name_signature_email)
    .bind(now())
    .bind(&l.id)
    .execute(&state.db)
    .await?;
    model::event(&state, &v.id, model::EVENT_UPDATE, &l).await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MoveReq {
    #[serde(rename = "ParentLinkID")]
    parent_link_id: String,
    node_passphrase: String,
    #[serde(default)]
    node_passphrase_signature: Option<String>,
    #[serde(default)]
    signature_email: Option<String>,
    name: String,
    #[serde(default)]
    name_signature_email: Option<String>,
    hash: String,
    #[serde(default)]
    original_hash: Option<String>,
}

/// Is `id` the folder `ancestor` or below it?
async fn is_within(state: &AppState, volume_id: &str, id: &str, ancestor: &str) -> ApiResult<bool> {
    let mut cur = Some(id.to_string());
    let mut guard = 0;
    while let Some(c) = cur {
        if c == ancestor {
            return Ok(true);
        }
        guard += 1;
        if guard > 1000 {
            break;
        }
        cur = model::find_link(state, volume_id, &c)
            .await?
            .and_then(|l| l.parent_id);
    }
    Ok(false)
}

pub async fn move_link(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id)): Path<(String, String)>,
    Json(r): Json<MoveReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    if l.parent_id.is_none() {
        return Err(ApiError::bad_request("The root folder cannot be moved"));
    }
    model::active_folder(&state, &v.id, &r.parent_link_id).await?;
    if is_within(&state, &v.id, &r.parent_link_id, &l.id).await? {
        return Err(ApiError::bad_request(
            "A folder cannot be moved into itself",
        ));
    }
    if let Some(orig) = &r.original_hash
        && l.name_hash.as_deref() != Some(orig.as_str())
    {
        return Err(model::invalid_requirements(
            "The name changed in the meantime",
        ));
    }
    model::check_name_free(&state, &v.id, &r.parent_link_id, &r.hash, Some(&l.id)).await?;
    sqlx::query(
        "UPDATE drive_links SET parent_id = $1, node_passphrase = $2, \
         node_passphrase_signature = COALESCE($3, node_passphrase_signature), \
         signature_email = COALESCE($4, signature_email), name = $5, \
         name_signature_email = COALESCE($6, name_signature_email), name_hash = $7, modified = $8 WHERE id = $9",
    )
    .bind(&r.parent_link_id)
    .bind(&r.node_passphrase)
    .bind(&r.node_passphrase_signature)
    .bind(&r.signature_email)
    .bind(&r.name)
    .bind(&r.name_signature_email)
    .bind(&r.hash)
    .bind(now())
    .bind(&l.id)
    .execute(&state.db)
    .await?;
    let moved = model::link(&state, &v.id, &l.id).await?;
    model::event(&state, &v.id, model::EVENT_UPDATE, &moved).await?;
    Ok(ok_empty())
}

/// Per-link results, as Proton returns them for bulk operations.
fn multi(results: Vec<(String, Option<ApiError>)>) -> Json<Value> {
    let responses: Vec<Value> = results
        .into_iter()
        .map(|(id, err)| match err {
            None => json!({ "LinkID": id, "Response": { "Code": 1000 } }),
            Some(e) => json!({ "LinkID": id, "Response": { "Code": e.code, "Error": e.message } }),
        })
        .collect();
    Json(json!({ "Code": 1001, "Responses": responses }))
}

async fn set_trashed(
    state: &AppState,
    volume_id: &str,
    link_id: &str,
    trashed: bool,
) -> ApiResult<()> {
    let l = model::link(state, volume_id, link_id).await?;
    if l.parent_id.is_none() {
        return Err(ApiError::bad_request("The root folder cannot be trashed"));
    }
    if trashed {
        if l.state != ACTIVE {
            return Err(ApiError::not_found("Link"));
        }
    } else {
        if l.state != TRASHED {
            return Err(ApiError::not_found("Link"));
        }
        if let (Some(p), Some(h)) = (&l.parent_id, &l.name_hash) {
            model::active_folder(state, volume_id, p).await?;
            model::check_name_free(state, volume_id, p, h, Some(&l.id)).await?;
        }
    }
    let t = now();
    sqlx::query("UPDATE drive_links SET state = $1, trash_time = $2, modified = $3 WHERE id = $4")
        .bind(if trashed { TRASHED } else { ACTIVE })
        .bind(if trashed { Some(t) } else { None })
        .bind(t)
        .bind(&l.id)
        .execute(&state.db)
        .await?;
    let l = model::link(state, volume_id, &l.id).await?;
    model::event(state, volume_id, model::EVENT_UPDATE, &l).await
}

pub async fn trash(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<LinkIdsReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let mut res = Vec::new();
    for id in r.link_ids {
        let e = set_trashed(&state, &v.id, &id, true).await.err();
        res.push((id, e));
    }
    Ok(multi(res))
}

pub async fn restore(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<LinkIdsReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let mut res = Vec::new();
    for id in r.link_ids {
        let e = set_trashed(&state, &v.id, &id, false).await.err();
        res.push((id, e));
    }
    Ok(multi(res))
}

/// Deletes a link and everything below it, with their stored blobs.
pub async fn delete_tree(state: &AppState, volume_id: &str, link_id: &str) -> ApiResult<()> {
    // Collect the subtree.
    let mut ids = vec![link_id.to_string()];
    let mut i = 0;
    while i < ids.len() {
        let kids: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM drive_links WHERE volume_id = $1 AND parent_id = $2")
                .bind(volume_id)
                .bind(&ids[i])
                .fetch_all(&state.db)
                .await?;
        ids.extend(kids.into_iter().map(|k| k.0));
        i += 1;
    }
    let mut freed = 0i64;
    let mut blobs = Vec::new();
    for id in &ids {
        let revs: Vec<(String, i64)> =
            sqlx::query_as("SELECT id, size FROM drive_revisions WHERE link_id = $1")
                .bind(id)
                .fetch_all(&state.db)
                .await?;
        for (rid, size) in revs {
            freed += size;
            let b: Vec<(String,)> = sqlx::query_as(
                "SELECT blob_id FROM drive_blocks WHERE revision_id = $1 \
                 UNION ALL SELECT blob_id FROM drive_thumbnails WHERE revision_id = $1",
            )
            .bind(&rid)
            .fetch_all(&state.db)
            .await?;
            blobs.extend(b.into_iter().map(|b| b.0));
        }
    }
    let root = model::link(state, volume_id, link_id).await?;
    let mut tx = state.db.begin().await?;
    // Children first (no ON DELETE CASCADE on parent_id).
    for id in ids.iter().rev() {
        sqlx::query("DELETE FROM drive_links WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE drive_volumes SET used_space = used_space - $1 WHERE id = $2")
        .bind(freed)
        .bind(volume_id)
        .execute(&mut *tx)
        .await?;
    model::push_event(
        &mut tx,
        volume_id,
        model::EVENT_DELETE,
        &root.id,
        root.parent_id.as_deref(),
        false,
    )
    .await?;
    tx.commit().await?;
    // Keep the counter non-negative (a portable clamp for SQLite and Postgres).
    sqlx::query("UPDATE drive_volumes SET used_space = 0 WHERE id = $1 AND used_space < 0")
        .bind(volume_id)
        .execute(&state.db)
        .await?;
    for b in blobs {
        state.blobs.delete(&b).await;
    }
    Ok(())
}

/// `POST drive/v2/volumes/{v}/trash/delete_multiple`: delete trashed links.
pub async fn delete_trashed(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<LinkIdsReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let mut res = Vec::new();
    for id in r.link_ids {
        let e = async {
            let l = model::link(&state, &v.id, &id).await?;
            if l.state != TRASHED {
                return Err(ApiError::new(
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                    code::NOT_ALLOWED,
                    "Only trashed items can be deleted",
                ));
            }
            delete_tree(&state, &v.id, &id).await
        }
        .await
        .err();
        res.push((id, e));
    }
    Ok(multi(res))
}

/// `POST drive/v2/volumes/{v}/delete_multiple`: delete drafts.
pub async fn delete_drafts(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<LinkIdsReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let mut res = Vec::new();
    for id in r.link_ids {
        let e = async {
            let l = model::link(&state, &v.id, &id).await?;
            if l.state != model::DRAFT {
                return Err(ApiError::bad_request("Not a draft"));
            }
            delete_tree(&state, &v.id, &id).await
        }
        .await
        .err();
        res.push((id, e));
    }
    Ok(multi(res))
}

/// `DELETE drive/volumes/{v}/trash`: empty the trash.
pub async fn empty_trash(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM drive_links WHERE volume_id = $1 AND state = 2")
            .bind(&v.id)
            .fetch_all(&state.db)
            .await?;
    for (id,) in rows {
        // A trashed folder's trashed descendants may already be gone.
        if model::find_link(&state, &v.id, &id).await?.is_some() {
            delete_tree(&state, &v.id, &id).await?;
        }
    }
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PageQuery {
    page: Option<usize>,
    page_size: Option<usize>,
}

/// `GET drive/volumes/{v}/trash?Page=N`: the client asks for pages until one
/// comes back empty.
pub async fn list_trash(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Query(q): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let size = q.page_size.unwrap_or(TRASH_PAGE).clamp(1, 1000);
    let page = q.page.unwrap_or(0);
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, parent_id FROM drive_links WHERE volume_id = $1 AND state = 2 ORDER BY trash_time, id",
    )
    .bind(&v.id)
    .fetch_all(&state.db)
    .await?;
    let slice: Vec<&(String, Option<String>)> = rows.iter().skip(page * size).take(size).collect();
    let ids: Vec<&String> = slice.iter().map(|r| &r.0).collect();
    let parents: Vec<Option<&String>> = slice.iter().map(|r| r.1.as_ref()).collect();
    let trash = if ids.is_empty() {
        vec![]
    } else {
        vec![json!({ "ShareID": v.share_id, "LinkIDs": ids, "ParentIDs": parents })]
    };
    Ok(ok(json!({ "Trash": trash })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HashesReq {
    hashes: Vec<String>,
}

/// `POST .../links/{parent}/checkAvailableHashes`: which name hashes are free.
pub async fn available_hashes(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, parent_id)): Path<(String, String)>,
    Json(r): Json<HashesReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let mut available = Vec::new();
    let mut pending = Vec::new();
    for h in r.hashes {
        let row: Option<(String, i64, Option<String>)> = sqlx::query_as(
            "SELECT id, state, client_uid FROM drive_links WHERE volume_id = $1 AND parent_id = $2 \
             AND name_hash = $3 AND state IN (0, 1)",
        )
        .bind(&v.id)
        .bind(&parent_id)
        .bind(&h)
        .fetch_optional(&state.db)
        .await?;
        match row {
            None => available.push(h),
            Some((id, model::DRAFT, client_uid)) => {
                let rev: Option<(String,)> = sqlx::query_as(
                    "SELECT id FROM drive_revisions WHERE link_id = $1 AND state = 0 LIMIT 1",
                )
                .bind(&id)
                .fetch_optional(&state.db)
                .await?;
                pending.push(json!({
                    "Hash": h, "RevisionID": rev.map(|r| r.0), "LinkID": id, "ClientUID": client_uid,
                }));
            }
            Some(_) => {}
        }
    }
    Ok(ok(
        json!({ "AvailableHashes": available, "PendingHashes": pending }),
    ))
}

/// `GET drive/volumes/{v}/folders/{l}/calculate-descendents-size`.
pub async fn descendants_size(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let mut stack = vec![link_id];
    let (mut size, mut count) = (0i64, 0i64);
    while let Some(id) = stack.pop() {
        let kids: Vec<Link> = sqlx::query_as(leptiq_core::sql!(
            "SELECT {} FROM drive_links WHERE volume_id = $1 AND parent_id = $2 AND state = 1",
            model::LINK_COLS
        ))
        .bind(&v.id)
        .bind(&id)
        .fetch_all(&state.db)
        .await?;
        for k in kids {
            count += 1;
            if k.link_type == FOLDER {
                stack.push(k.id);
            } else if let Some(rid) = &k.active_revision_id {
                size += model::revision(&state, &k.id, rid).await?.size;
            }
        }
    }
    Ok(ok(
        json!({ "DescendentsSize": size, "DescendentsCount": count }),
    ))
}
