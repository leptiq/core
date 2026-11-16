//! Items: encrypted entries in a vault, with full revision history.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::shares::{self, Share};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult, code},
    events::{self, kind},
    util::{new_id, now, ok, ok_empty},
};

pub const STATE_ACTIVE: i64 = 1;
pub const STATE_TRASHED: i64 = 2;
pub const FLAG_SKIP_HEALTH: i64 = 1;
pub const FLAG_ALIAS_DISABLED: i64 = 4;
pub const FLAG_HAS_FILES: i64 = 8;
pub const FLAG_HAD_FILES: i64 = 16;
pub const FLAG_SKIP_WEAK: i64 = 32;
pub const FLAG_SKIP_COMPROMISED: i64 = 64;
pub const FLAG_SKIP_REUSED: i64 = 128;
pub const FLAG_SKIP_2FA: i64 = 256;
pub const MAX_BATCH: usize = 100;
pub const DEFAULT_PAGE: i64 = 100;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Item {
    pub id: String,
    pub vault_id: String,
    pub folder_id: Option<String>,
    pub revision: i64,
    pub content_format_version: i64,
    pub content: String,
    pub key_rotation: i64,
    pub state: i64,
    pub flags: i64,
    pub alias_email: Option<String>,
    pub create_time: i64,
    pub modify_time: i64,
    pub revision_time: i64,
    pub last_use_time: i64,
}

pub const ITEM_COLS: &str = "id, vault_id, folder_id, revision, content_format_version, content, key_rotation, state, \
    flags, alias_email, create_time, modify_time, revision_time, last_use_time";

pub async fn load(conn: &mut AnyConnection, share: &Share, item_id: &str) -> ApiResult<Item> {
    if !share.covers_item(item_id) {
        return Err(ApiError::not_found("Item"));
    }
    let item: Option<Item> = sqlx::query_as(crate::sql!(
        "SELECT {ITEM_COLS} FROM items WHERE id = $1 AND vault_id = $2"
    ))
    .bind(item_id)
    .bind(&share.vault_id)
    .fetch_optional(&mut *conn)
    .await?;
    item.ok_or_else(|| ApiError::not_found("Item"))
}

/// `ItemRevisionContentsResponse` for the current revision of an item.
pub async fn item_json(conn: &mut AnyConnection, share: &Share, item: &Item) -> ApiResult<Value> {
    let pin: Option<(i64,)> =
        sqlx::query_as("SELECT pin_time FROM item_pins WHERE user_id = $1 AND item_id = $2")
            .bind(&share.user_id)
            .bind(&item.id)
            .fetch_optional(&mut *conn)
            .await?;
    let (share_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shares WHERE vault_id = $1 AND target_type = 2 AND target_id = $2 AND deleted = 0",
    )
    .bind(&item.vault_id)
    .bind(&item.id)
    .fetch_one(&mut *conn)
    .await?;
    let item_key = if share.is_vault() {
        latest_key(conn, &item.id).await?.map(|(_, k)| k)
    } else {
        None
    };
    let alias_owner = match &item.alias_email {
        Some(email) => super::alias::is_owner(conn, &share.user_id, email).await?,
        None => false,
    };
    let key_rotation = if share.is_vault() {
        item.key_rotation
    } else {
        // Item shares use their own share key rotation.
        let (r,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(MAX(key_rotation), 1) FROM share_keys WHERE share_id = $1",
        )
        .bind(&share.id)
        .fetch_one(&mut *conn)
        .await?;
        r
    };
    Ok(json!({
        "ItemID": item.id,
        "Revision": item.revision,
        "ContentFormatVersion": item.content_format_version,
        "Flags": item.flags,
        "KeyRotation": key_rotation,
        "Content": item.content,
        "ItemKey": item_key,
        "State": item.state,
        "Pinned": pin.is_some(),
        "PinTime": pin.map(|p| p.0),
        "ShareCount": share_count,
        "FolderID": item.folder_id,
        "AliasEmail": item.alias_email,
        "AliasOwner": alias_owner,
        "CreateTime": item.create_time,
        "ModifyTime": item.modify_time,
        "LastUseTime": item.last_use_time,
        "RevisionTime": item.revision_time,
    }))
}

/// `ItemRevisionResponse` (the short form used by trash/untrash/folder moves).
pub fn item_short(item: &Item) -> Value {
    json!({
        "ItemID": item.id,
        "Revision": item.revision,
        "State": item.state,
        "Flags": item.flags,
        "FolderID": item.folder_id,
        "ModifyTime": item.modify_time,
        "RevisionTime": item.revision_time,
    })
}

pub async fn latest_key(
    conn: &mut AnyConnection,
    item_id: &str,
) -> ApiResult<Option<(i64, String)>> {
    Ok(sqlx::query_as("SELECT key_rotation, key FROM item_keys WHERE item_id = $1 ORDER BY key_rotation DESC LIMIT 1")
        .bind(item_id)
        .fetch_optional(&mut *conn)
        .await?)
}

async fn reload(conn: &mut AnyConnection, item_id: &str) -> ApiResult<Item> {
    Ok(
        sqlx::query_as(crate::sql!("SELECT {ITEM_COLS} FROM items WHERE id = $1"))
            .bind(item_id)
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// Snapshots the current item state as a revision row.
async fn record_revision(conn: &mut AnyConnection, item: &Item) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO item_revisions (item_id, revision, content_format_version, content, key_rotation, state, flags, \
         modify_time, revision_time) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(&item.id)
    .bind(item.revision)
    .bind(item.content_format_version)
    .bind(&item.content)
    .bind(item.key_rotation)
    .bind(item.state)
    .bind(item.flags)
    .bind(item.modify_time)
    .bind(item.revision_time)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn vault_rotation(conn: &mut AnyConnection, vault_id: &str) -> ApiResult<i64> {
    let (r,): (i64,) = sqlx::query_as("SELECT current_rotation FROM vaults WHERE id = $1")
        .bind(vault_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(r)
}

pub async fn check_folder(
    conn: &mut AnyConnection,
    vault_id: &str,
    folder_id: Option<&str>,
) -> ApiResult<()> {
    if let Some(f) = folder_id {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM folders WHERE id = $1 AND vault_id = $2")
                .bind(f)
                .bind(vault_id)
                .fetch_optional(&mut *conn)
                .await?;
        row.ok_or_else(|| ApiError::not_found("Folder"))?;
    }
    Ok(())
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct CreateReq {
    pub key_rotation: i64,
    pub content_format_version: i64,
    pub content: String,
    pub item_key: String,
    #[serde(rename = "FolderID")]
    pub folder_id: Option<String>,
}

#[derive(Default)]
pub struct NewItemOpts {
    pub alias_email: Option<String>,
    pub trashed: bool,
    pub create_time: Option<i64>,
    pub modify_time: Option<i64>,
}

/// Inserts a new item in the share's vault (within a transaction).
pub async fn insert_item(
    conn: &mut AnyConnection,
    share: &Share,
    req: &CreateReq,
    opts: NewItemOpts,
) -> ApiResult<Item> {
    if !share.is_vault() {
        return Err(ApiError::forbidden("Cannot create items in an item share"));
    }
    share.require_write()?;
    if req.key_rotation != vault_rotation(conn, &share.vault_id).await? {
        return Err(ApiError::bad_request(
            "Item key must be encrypted with the latest vault key",
        ));
    }
    check_folder(conn, &share.vault_id, req.folder_id.as_deref()).await?;
    let id = new_id();
    let t = now();
    let create_time = opts.create_time.unwrap_or(t);
    let modify_time = opts.modify_time.unwrap_or(t);
    let item_state = if opts.trashed {
        STATE_TRASHED
    } else {
        STATE_ACTIVE
    };
    sqlx::query(
        "INSERT INTO items (id, vault_id, folder_id, revision, content_format_version, content, key_rotation, state, flags, \
         alias_email, create_time, modify_time, revision_time, last_use_time) VALUES ($1,$2,$3,1,$4,$5,$6,$7,0,$8,$9,$10,$11,0)",
    )
    .bind(&id)
    .bind(&share.vault_id)
    .bind(&req.folder_id)
    .bind(req.content_format_version)
    .bind(&req.content)
    .bind(req.key_rotation)
    .bind(item_state)
    .bind(&opts.alias_email)
    .bind(create_time)
    .bind(modify_time)
    .bind(t)
    .execute(&mut *conn)
    .await?;
    sqlx::query("INSERT INTO item_keys (item_id, key_rotation, key) VALUES ($1, $2, $3)")
        .bind(&id)
        .bind(req.key_rotation)
        .bind(&req.item_key)
        .execute(&mut *conn)
        .await?;
    let item = reload(conn, &id).await?;
    record_revision(conn, &item).await?;
    events::push_item(conn, &share.vault_id, &id, kind::ITEM_UPDATED).await?;
    Ok(item)
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut tx = state.db.begin().await?;
    let item = insert_item(&mut tx, &share, &req, NewItemOpts::default()).await?;
    let out = item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListQuery {
    pub since: Option<String>,
    pub page_size: Option<i64>,
    pub only_alias: Option<String>,
    pub event_token: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let page = q.page_size.unwrap_or(DEFAULT_PAGE).clamp(1, 1000);
    let only_alias = matches!(q.only_alias.as_deref(), Some("1") | Some("true"));
    let since = q.since.filter(|s| !s.is_empty()).unwrap_or_default();
    let mut conn = state.db.acquire().await?;
    let mut sql = format!("SELECT {ITEM_COLS} FROM items WHERE vault_id = $1 AND id > $2");
    if !share.is_vault() {
        sql.push_str(" AND id = $4");
    }
    if only_alias {
        sql.push_str(" AND alias_email IS NOT NULL");
    }
    sql.push_str(" ORDER BY id LIMIT $3");
    let mut query = sqlx::query_as::<_, Item>(sqlx::AssertSqlSafe(sql))
        .bind(&share.vault_id)
        .bind(&since)
        .bind(page + 1);
    if !share.is_vault() {
        query = query.bind(&share.target_id);
    }
    let rows: Vec<Item> = query.fetch_all(&mut *conn).await?;
    let more = rows.len() as i64 > page;
    let mut data = vec![];
    for item in rows.iter().take(page as usize) {
        data.push(item_json(&mut conn, &share, item).await?);
    }
    let (total,): (i64,) = if share.is_vault() {
        sqlx::query_as("SELECT COUNT(*) FROM items WHERE vault_id = $1")
            .bind(&share.vault_id)
            .fetch_one(&mut *conn)
            .await?
    } else {
        (1,)
    };
    let last = if more {
        rows.get(page as usize - 1).map(|i| i.id.clone())
    } else {
        None
    };
    Ok(ok(
        json!({ "Items": { "RevisionsData": data, "Total": total, "LastToken": last } }),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut conn = state.db.acquire().await?;
    let item = load(&mut conn, &share, &item_id).await?;
    Ok(ok(
        json!({ "Item": item_json(&mut conn, &share, &item).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateReq {
    pub key_rotation: i64,
    pub last_revision: i64,
    pub content: String,
    pub content_format_version: i64,
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let item = load(&mut tx, &share, &item_id).await?;
    if item.revision != req.last_revision {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            code::REVISION_CONFLICT,
            "Item has been modified; please sync",
        ));
    }
    let t = now();
    sqlx::query(
        "UPDATE items SET revision = revision + 1, content = $1, content_format_version = $2, modify_time = $3, \
         revision_time = $3 WHERE id = $4",
    )
    .bind(&req.content)
    .bind(req.content_format_version)
    .bind(t)
    .bind(&item.id)
    .execute(&mut *tx)
    .await?;
    let item = reload(&mut tx, &item.id).await?;
    record_revision(&mut tx, &item).await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let out = item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ItemIdRevision {
    #[serde(rename = "ItemID")]
    pub item_id: String,
    pub revision: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ItemsReq {
    pub items: Vec<ItemIdRevision>,
    pub skip_trash: Option<bool>,
}

async fn set_state(
    state: &AppState,
    user: &AuthUser,
    share_id: &str,
    req: &ItemsReq,
    new_state: i64,
) -> ApiResult<Vec<Value>> {
    if req.items.len() > MAX_BATCH {
        return Err(ApiError::bad_request("Too many items"));
    }
    let share = shares::load(state, &user.user_id, share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let mut out = vec![];
    for i in &req.items {
        let item = load(&mut tx, &share, &i.item_id).await?;
        if item.state != new_state {
            sqlx::query("UPDATE items SET state = $1, modify_time = $2 WHERE id = $3")
                .bind(new_state)
                .bind(now())
                .bind(&item.id)
                .execute(&mut *tx)
                .await?;
            events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
        }
        out.push(item_short(&reload(&mut tx, &item.id).await?));
    }
    tx.commit().await?;
    Ok(out)
}

pub async fn trash(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<ItemsReq>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Items": set_state(&state, &user, &share_id, &req, STATE_TRASHED).await? }),
    ))
}

pub async fn untrash(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<ItemsReq>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Items": set_state(&state, &user, &share_id, &req, STATE_ACTIVE).await? }),
    ))
}

/// Permanently deletes an item and notifies everyone who could see it.
pub async fn delete_item(conn: &mut AnyConnection, item: &Item) -> ApiResult<()> {
    events::push_item(conn, &item.vault_id, &item.id, kind::ITEM_DELETED).await?;
    // Remove item shares targeting this item.
    let item_shares: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM shares WHERE target_type = 2 AND target_id = $1 AND deleted = 0",
    )
    .bind(&item.id)
    .fetch_all(&mut *conn)
    .await?;
    for (sid,) in item_shares {
        let s = shares::load_any(conn, &sid).await?;
        shares::remove_share(conn, &s).await?;
    }
    sqlx::query("UPDATE files SET orphaned = 1 WHERE id IN (SELECT file_id FROM item_files WHERE item_id = $1)")
        .bind(&item.id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM items WHERE id = $1")
        .bind(&item.id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<ItemsReq>,
) -> ApiResult<Json<Value>> {
    if req.items.len() > MAX_BATCH {
        return Err(ApiError::bad_request("Too many items"));
    }
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    for i in &req.items {
        let item = load(&mut tx, &share, &i.item_id).await?;
        if item.state != STATE_TRASHED && !req.skip_trash.unwrap_or(false) {
            return Err(ApiError::bad_request(
                "Item must be trashed before deletion",
            ));
        }
        delete_item(&mut tx, &item).await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RevisionQuery {
    pub page_size: Option<i64>,
    pub since: Option<String>,
}

pub async fn revisions(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut conn = state.db.acquire().await?;
    let item = load(&mut conn, &share, &item_id).await?;
    let base = item_json(&mut conn, &share, &item).await?;
    let page = q.page_size.unwrap_or(DEFAULT_PAGE).clamp(1, 1000);
    let since: i64 = q.since.and_then(|s| s.parse().ok()).unwrap_or(i64::MAX);
    let rows: Vec<(i64, i64, String, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT revision, content_format_version, content, key_rotation, state, flags, revision_time FROM item_revisions \
         WHERE item_id = $1 AND revision < $2 ORDER BY revision DESC LIMIT $3",
    )
    .bind(&item.id)
    .bind(since)
    .bind(page + 1)
    .fetch_all(&mut *conn)
    .await?;
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM item_revisions WHERE item_id = $1")
        .bind(&item.id)
        .fetch_one(&mut *conn)
        .await?;
    let more = rows.len() as i64 > page;
    let data: Vec<Value> = rows
        .iter()
        .take(page as usize)
        .map(|(rev, cfv, content, _kr, st, flags, rtime)| {
            let mut v = base.clone();
            v["Revision"] = json!(rev);
            v["ContentFormatVersion"] = json!(cfv);
            v["Content"] = json!(content);
            v["State"] = json!(st);
            v["Flags"] = json!(flags);
            v["RevisionTime"] = json!(rtime);
            v["ModifyTime"] = json!(rtime);
            v
        })
        .collect();
    let last = if more {
        rows.get(page as usize - 1).map(|r| r.0.to_string())
    } else {
        None
    };
    Ok(ok(
        json!({ "Revisions": { "RevisionsData": data, "Total": total, "LastToken": last } }),
    ))
}

/// `DELETE share/{}/item/{}/revisions`: drop history, keep current revision.
pub async fn clear_revisions(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let item = load(&mut tx, &share, &item_id).await?;
    sqlx::query("DELETE FROM item_revisions WHERE item_id = $1 AND revision <> $2")
        .bind(&item.id)
        .bind(item.revision)
        .execute(&mut *tx)
        .await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let out = item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

async fn set_pin(
    state: &AppState,
    user: &AuthUser,
    share_id: &str,
    item_id: &str,
    pinned: bool,
) -> ApiResult<Value> {
    let share = shares::load(state, &user.user_id, share_id).await?;
    let mut tx = state.db.begin().await?;
    let item = load(&mut tx, &share, item_id).await?;
    sqlx::query("DELETE FROM item_pins WHERE user_id = $1 AND item_id = $2")
        .bind(&user.user_id)
        .bind(&item.id)
        .execute(&mut *tx)
        .await?;
    if pinned {
        sqlx::query("INSERT INTO item_pins (user_id, item_id, pin_time) VALUES ($1, $2, $3)")
            .bind(&user.user_id)
            .bind(&item.id)
            .bind(now())
            .execute(&mut *tx)
            .await?;
    }
    events::push(
        &mut tx,
        &user.user_id,
        kind::ITEM_UPDATED,
        Some(&share.id),
        Some(&item.id),
    )
    .await?;
    let out = item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(out)
}

pub async fn pin(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Item": set_pin(&state, &user, &share_id, &item_id, true).await? }),
    ))
}

pub async fn unpin(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Item": set_pin(&state, &user, &share_id, &item_id, false).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FlagsReq {
    pub skip_health_check: Option<bool>,
    pub skip_weak_password_check: Option<bool>,
    pub skip_compromised_password_check: Option<bool>,
    pub skip_reused_password_check: Option<bool>,
    #[serde(rename = "Skip2FACheck")]
    pub skip_2fa_check: Option<bool>,
}

pub async fn flags(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<FlagsReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let item = load(&mut tx, &share, &item_id).await?;
    let mut f = item.flags;
    for (opt, bit) in [
        (req.skip_health_check, FLAG_SKIP_HEALTH),
        (req.skip_weak_password_check, FLAG_SKIP_WEAK),
        (req.skip_compromised_password_check, FLAG_SKIP_COMPROMISED),
        (req.skip_reused_password_check, FLAG_SKIP_REUSED),
        (req.skip_2fa_check, FLAG_SKIP_2FA),
    ] {
        match opt {
            Some(true) => f |= bit,
            Some(false) => f &= !bit,
            None => {}
        }
    }
    sqlx::query("UPDATE items SET flags = $1 WHERE id = $2")
        .bind(f)
        .bind(&item.id)
        .execute(&mut *tx)
        .await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let item = reload(&mut tx, &item.id).await?;
    let out = item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LastUseReq {
    pub last_use_time: Option<i64>,
}

pub async fn last_use(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<LastUseReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut tx = state.db.begin().await?;
    let item = load(&mut tx, &share, &item_id).await?;
    let t = req.last_use_time.unwrap_or_else(now).min(now());
    sqlx::query("UPDATE items SET last_use_time = $1 WHERE id = $2 AND last_use_time < $1")
        .bind(t)
        .bind(&item.id)
        .execute(&mut *tx)
        .await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_LAST_USE).await?;
    let item = reload(&mut tx, &item.id).await?;
    let out = item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Revision": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ReadTime {
    #[serde(rename = "ItemID")]
    pub item_id: String,
    pub timestamp: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MarkReadReq {
    pub item_times: Vec<ReadTime>,
}

pub async fn mark_read(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<MarkReadReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut tx = state.db.begin().await?;
    for r in &req.item_times {
        let item = load(&mut tx, &share, &r.item_id).await?;
        sqlx::query("DELETE FROM item_reads WHERE user_id = $1 AND item_id = $2")
            .bind(&user.user_id)
            .bind(&item.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO item_reads (user_id, item_id, read_time) VALUES ($1, $2, $3)")
            .bind(&user.user_id)
            .bind(&item.id)
            .bind(r.timestamp)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct KeyPair {
    pub key_rotation: i64,
    #[serde(alias = "ItemKey")]
    pub key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MoveItem {
    #[serde(rename = "ItemID")]
    pub item_id: String,
    #[serde(rename = "DestinationFolderID")]
    pub destination_folder_id: Option<String>,
    pub item_keys: Vec<KeyPair>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MoveReq {
    #[serde(rename = "ShareID")]
    pub share_id: String,
    pub items: Vec<MoveItem>,
}

/// Replaces an item's keys (after moving it to another vault or folder).
pub async fn replace_keys(
    conn: &mut AnyConnection,
    item_id: &str,
    keys: &[KeyPair],
) -> ApiResult<i64> {
    if keys.is_empty() {
        return Err(ApiError::bad_request("Item keys are required"));
    }
    sqlx::query("DELETE FROM item_keys WHERE item_id = $1")
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    let mut max = 0;
    for k in keys {
        sqlx::query("INSERT INTO item_keys (item_id, key_rotation, key) VALUES ($1, $2, $3)")
            .bind(item_id)
            .bind(k.key_rotation)
            .bind(&k.key)
            .execute(&mut *conn)
            .await?;
        max = max.max(k.key_rotation);
    }
    Ok(max)
}

/// `PUT share/{src}/item/share`: move items to another vault.
pub async fn move_to_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<MoveReq>,
) -> ApiResult<Json<Value>> {
    if req.items.len() > MAX_BATCH {
        return Err(ApiError::bad_request("Too many items"));
    }
    let src = shares::load(&state, &user.user_id, &share_id).await?;
    let dst = shares::load(&state, &user.user_id, &req.share_id).await?;
    src.require_write()?;
    dst.require_write()?;
    if !dst.is_vault() || !src.is_vault() {
        return Err(ApiError::bad_request(
            "Items can only be moved between vaults",
        ));
    }
    let mut tx = state.db.begin().await?;
    let mut out = vec![];
    for m in &req.items {
        let item = load(&mut tx, &src, &m.item_id).await?;
        check_folder(&mut tx, &dst.vault_id, m.destination_folder_id.as_deref()).await?;
        events::push_item(&mut tx, &src.vault_id, &item.id, kind::ITEM_DELETED).await?;
        let item_shares: Vec<(String,)> = sqlx::query_as(
            "SELECT id FROM shares WHERE target_type = 2 AND target_id = $1 AND deleted = 0",
        )
        .bind(&item.id)
        .fetch_all(&mut *tx)
        .await?;
        for (sid,) in item_shares {
            let s = shares::load_any(&mut tx, &sid).await?;
            shares::remove_share(&mut tx, &s).await?;
        }
        let rotation = replace_keys(&mut tx, &item.id, &m.item_keys).await?;
        sqlx::query("UPDATE items SET vault_id = $1, folder_id = $2, key_rotation = $3, modify_time = $4 WHERE id = $5")
            .bind(&dst.vault_id)
            .bind(&m.destination_folder_id)
            .bind(rotation)
            .bind(now())
            .bind(&item.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM item_pins WHERE item_id = $1 AND user_id <> $2")
            .bind(&item.id)
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await?;
        events::push_item(&mut tx, &dst.vault_id, &item.id, kind::ITEM_UPDATED).await?;
        let item = reload(&mut tx, &item.id).await?;
        out.push(item_json(&mut tx, &dst, &item).await?);
    }
    tx.commit().await?;
    Ok(ok(json!({ "Items": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImportItem {
    pub item: CreateReq,
    pub alias_email: Option<String>,
    pub trashed: Option<bool>,
    pub create_time: Option<i64>,
    pub modify_time: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImportReq {
    pub items: Vec<ImportItem>,
}

pub async fn import_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<ImportReq>,
) -> ApiResult<Json<Value>> {
    if req.items.len() > MAX_BATCH {
        return Err(ApiError::bad_request("Too many items"));
    }
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut tx = state.db.begin().await?;
    let mut out = vec![];
    for i in &req.items {
        // Imported aliases only keep the address if it is ours.
        let alias = match &i.alias_email {
            Some(a) if super::alias::is_owner(&mut tx, &user.user_id, a).await? => Some(a.clone()),
            _ => None,
        };
        let opts = NewItemOpts {
            alias_email: alias,
            trashed: i.trashed.unwrap_or(false),
            create_time: i.create_time,
            modify_time: i.modify_time,
        };
        let item = insert_item(&mut tx, &share, &i.item, opts).await?;
        out.push(item_json(&mut tx, &share, &item).await?);
    }
    tx.commit().await?;
    Ok(ok(
        json!({ "Revisions": { "RevisionsData": out, "Total": req.items.len(), "LastToken": null } }),
    ))
}

pub async fn keys(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut conn = state.db.acquire().await?;
    let item = load(&mut conn, &share, &item_id).await?;
    if !share.is_vault() {
        return Err(ApiError::forbidden("Item shares use share keys"));
    }
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT key_rotation, key FROM item_keys WHERE item_id = $1 ORDER BY key_rotation",
    )
    .bind(&item.id)
    .fetch_all(&mut *conn)
    .await?;
    let keys: Vec<Value> = rows
        .into_iter()
        .map(|(r, k)| json!({ "KeyRotation": r, "Key": k }))
        .collect();
    Ok(ok(json!({ "Keys": { "Keys": keys, "Total": keys.len() } })))
}

pub async fn latest_key_handler(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut conn = state.db.acquire().await?;
    let item = load(&mut conn, &share, &item_id).await?;
    if !share.is_vault() {
        return Err(ApiError::forbidden("Item shares use share keys"));
    }
    let (r, k) = latest_key(&mut conn, &item.id)
        .await?
        .ok_or_else(|| ApiError::not_found("Item key"))?;
    Ok(ok(json!({ "Key": { "KeyRotation": r, "Key": k } })))
}
