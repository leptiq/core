//! Folders inside a vault (nested, each with its own key).

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{
    items::{self, KeyPair},
    shares::{self, Share},
};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, now, ok, ok_empty},
};

#[derive(sqlx::FromRow)]
struct Folder {
    id: String,
    vault_id: String,
    parent_id: Option<String>,
    key_rotation: i64,
    folder_key: String,
    content_format_version: i64,
    content: String,
}

const COLS: &str =
    "id, vault_id, parent_id, key_rotation, folder_key, content_format_version, content";
const MAX_DEPTH: usize = 10;

fn folder_json(f: &Folder) -> Value {
    json!({
        "VaultID": f.vault_id,
        "FolderID": f.id,
        "ParentFolderID": f.parent_id,
        "KeyRotation": f.key_rotation,
        "FolderKey": f.folder_key,
        "ContentFormatVersion": f.content_format_version,
        "Content": f.content,
    })
}

async fn load(conn: &mut AnyConnection, share: &Share, folder_id: &str) -> ApiResult<Folder> {
    if !share.is_vault() {
        return Err(ApiError::not_found("Folder"));
    }
    let f: Option<Folder> = sqlx::query_as(crate::sql!(
        "SELECT {COLS} FROM folders WHERE id = $1 AND vault_id = $2"
    ))
    .bind(folder_id)
    .bind(&share.vault_id)
    .fetch_optional(&mut *conn)
    .await?;
    f.ok_or_else(|| ApiError::not_found("Folder"))
}

/// Depth of a folder chain, failing on cycles.
async fn ancestors(
    conn: &mut AnyConnection,
    vault_id: &str,
    mut id: Option<String>,
) -> ApiResult<Vec<String>> {
    let mut chain = vec![];
    while let Some(cur) = id {
        if chain.contains(&cur) || chain.len() > MAX_DEPTH {
            return Err(ApiError::bad_request("Folder nesting too deep"));
        }
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT parent_id FROM folders WHERE id = $1 AND vault_id = $2")
                .bind(&cur)
                .bind(vault_id)
                .fetch_optional(&mut *conn)
                .await?;
        let Some((parent,)) = row else {
            return Err(ApiError::not_found("Folder"));
        };
        chain.push(cur);
        id = parent;
    }
    Ok(chain)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListQuery {
    pub since: Option<String>,
    pub page_size: Option<i64>,
}

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    if !share.is_vault() {
        return Ok(ok(
            json!({ "Folders": { "Folders": [], "Total": 0, "LastToken": null } }),
        ));
    }
    let page = q.page_size.unwrap_or(100).clamp(1, 1000);
    let rows: Vec<Folder> = sqlx::query_as(crate::sql!(
        "SELECT {COLS} FROM folders WHERE vault_id = $1 AND id > $2 ORDER BY id LIMIT $3"
    ))
    .bind(&share.vault_id)
    .bind(q.since.unwrap_or_default())
    .bind(page + 1)
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() as i64 > page;
    let folders: Vec<Value> = rows.iter().take(page as usize).map(folder_json).collect();
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM folders WHERE vault_id = $1")
        .bind(&share.vault_id)
        .fetch_one(&state.db)
        .await?;
    let last = if more {
        rows.get(page as usize - 1).map(|f| f.id.clone())
    } else {
        None
    };
    Ok(ok(
        json!({ "Folders": { "Folders": folders, "Total": total, "LastToken": last } }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateReq {
    #[serde(rename = "ParentFolderID")]
    pub parent_folder_id: Option<String>,
    pub content_format_version: i64,
    pub content: String,
    pub key_rotation: i64,
    pub folder_key: String,
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    if !share.is_vault() {
        return Err(ApiError::bad_request("Folders live in vaults"));
    }
    let mut tx = state.db.begin().await?;
    if ancestors(&mut tx, &share.vault_id, req.parent_folder_id.clone())
        .await?
        .len()
        >= MAX_DEPTH
    {
        return Err(ApiError::bad_request("Folder nesting too deep"));
    }
    let id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO folders (id, vault_id, parent_id, key_rotation, folder_key, content_format_version, content, created, modified) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)",
    )
    .bind(&id)
    .bind(&share.vault_id)
    .bind(&req.parent_folder_id)
    .bind(req.key_rotation)
    .bind(&req.folder_key)
    .bind(req.content_format_version)
    .bind(&req.content)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    events::push_vault(&mut tx, &share.vault_id, kind::FOLDER_UPDATED, Some(&id)).await?;
    let f = load(&mut tx, &share, &id).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Folder": folder_json(&f) })))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, folder_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut conn = state.db.acquire().await?;
    let f = load(&mut conn, &share, &folder_id).await?;
    Ok(ok(json!({ "Folder": folder_json(&f) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContentUpdate {
    pub content_format_version: i64,
    pub content: String,
    pub key_rotation: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateReq {
    pub content: Option<ContentUpdate>,
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, folder_id)): Path<(String, String)>,
    Json(req): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let f = load(&mut tx, &share, &folder_id).await?;
    if let Some(c) = &req.content {
        sqlx::query("UPDATE folders SET content = $1, content_format_version = $2, modified = $3 WHERE id = $4")
            .bind(&c.content)
            .bind(c.content_format_version)
            .bind(now())
            .bind(&f.id)
            .execute(&mut *tx)
            .await?;
    }
    events::push_vault(&mut tx, &share.vault_id, kind::FOLDER_UPDATED, Some(&f.id)).await?;
    let f = load(&mut tx, &share, &folder_id).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Folder": folder_json(&f) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FolderKeyPair {
    pub key_rotation: i64,
    pub folder_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MoveReq {
    #[serde(rename = "ParentFolderID")]
    pub parent_folder_id: Option<String>,
    pub folder_keys: Vec<FolderKeyPair>,
}

pub async fn move_folder(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, folder_id)): Path<(String, String)>,
    Json(req): Json<MoveReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let f = load(&mut tx, &share, &folder_id).await?;
    let chain = ancestors(&mut tx, &share.vault_id, req.parent_folder_id.clone()).await?;
    if chain.contains(&f.id) {
        return Err(ApiError::bad_request("Cannot move a folder into itself"));
    }
    let key = req
        .folder_keys
        .iter()
        .max_by_key(|k| k.key_rotation)
        .ok_or_else(|| ApiError::bad_request("Folder key required"))?;
    sqlx::query("UPDATE folders SET parent_id = $1, folder_key = $2, key_rotation = $3, modified = $4 WHERE id = $5")
        .bind(&req.parent_folder_id)
        .bind(&key.folder_key)
        .bind(key.key_rotation)
        .bind(now())
        .bind(&f.id)
        .execute(&mut *tx)
        .await?;
    events::push_vault(&mut tx, &share.vault_id, kind::FOLDER_UPDATED, Some(&f.id)).await?;
    let f = load(&mut tx, &share, &folder_id).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Folder": folder_json(&f) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteReq {
    #[serde(rename = "FolderIDs")]
    pub folder_ids: Vec<String>,
}

/// Deletes folders together with their subfolders and items.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<DeleteReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let mut queue: Vec<String> = vec![];
    for id in &req.folder_ids {
        queue.push(load(&mut tx, &share, id).await?.id);
    }
    let mut all = vec![];
    while let Some(id) = queue.pop() {
        let children: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM folders WHERE parent_id = $1 AND vault_id = $2")
                .bind(&id)
                .bind(&share.vault_id)
                .fetch_all(&mut *tx)
                .await?;
        queue.extend(children.into_iter().map(|c| c.0));
        all.push(id);
    }
    for id in &all {
        let item_ids: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM items WHERE folder_id = $1 AND vault_id = $2")
                .bind(id)
                .bind(&share.vault_id)
                .fetch_all(&mut *tx)
                .await?;
        for (iid,) in item_ids {
            let item = items::load(&mut tx, &share, &iid).await?;
            items::delete_item(&mut tx, &item).await?;
        }
        sqlx::query("DELETE FROM folders WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        events::push_vault(&mut tx, &share.vault_id, kind::FOLDER_DELETED, Some(id)).await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ItemMove {
    #[serde(rename = "ItemID")]
    pub item_id: String,
    pub item_keys: Vec<KeyPair>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ItemsMoveReq {
    #[serde(rename = "FolderID")]
    pub folder_id: Option<String>,
    pub items: Vec<ItemMove>,
}

/// `PUT share/{}/item/folder`: move items into (or out of) a folder.
pub async fn move_items(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<ItemsMoveReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    items::check_folder(&mut tx, &share.vault_id, req.folder_id.as_deref()).await?;
    let mut out = vec![];
    for m in &req.items {
        let item = items::load(&mut tx, &share, &m.item_id).await?;
        let rotation = items::replace_keys(&mut tx, &item.id, &m.item_keys).await?;
        sqlx::query(
            "UPDATE items SET folder_id = $1, key_rotation = $2, modify_time = $3 WHERE id = $4",
        )
        .bind(&req.folder_id)
        .bind(rotation)
        .bind(now())
        .bind(&item.id)
        .execute(&mut *tx)
        .await?;
        events::push_item(&mut tx, &share.vault_id, &item.id, kind::ITEM_UPDATED).await?;
        let item = items::load(&mut tx, &share, &item.id).await?;
        out.push(items::item_short(&item));
    }
    tx.commit().await?;
    Ok(ok(json!({ "Items": out })))
}
