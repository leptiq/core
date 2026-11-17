//! Leptiq Authenticator: the sync API of the official Proton Authenticator
//! apps (`authenticator/v1/...`), as a [`Product`] on top of `leptiq-core`.
//!
//! The server only stores ciphertext: each user has authenticator keys
//! (encrypted by the client with one of the user's keys), and every entry is
//! encrypted by the client with an authenticator key.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, put},
};
use leptiq_core::{
    AppState, Product,
    auth::AuthUser,
    error::{ApiError, ApiResult, code},
    util::{new_id, now, ok, ok_empty},
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Entries returned per page of `GET authenticator/v1/entry`.
const PAGE_SIZE: usize = 100;

/// Authenticator database migrations (versions 2000+).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub struct AuthenticatorProduct;

/// The Authenticator product, ready to register with the server.
pub fn product() -> Arc<dyn Product> {
    Arc::new(AuthenticatorProduct)
}

impl Product for AuthenticatorProduct {
    fn name(&self) -> &'static str {
        "authenticator"
    }

    fn migrator(&self) -> &'static sqlx::migrate::Migrator {
        &MIGRATOR
    }

    fn routes(&self, _state: &AppState) -> Router<AppState> {
        Router::new()
            .route("/authenticator/v1/key", get(list_keys).post(create_key))
            .route(
                "/authenticator/v1/entry",
                get(list_entries).post(create_entry),
            )
            .route(
                "/authenticator/v1/entry/bulk",
                axum::routing::post(create_entries)
                    .put(update_entries)
                    .delete(delete_entries),
            )
            .route("/authenticator/v1/entry/order", put(reorder_batch))
            .route(
                "/authenticator/v1/entry/{id}",
                put(update_entry).delete(delete_entry),
            )
            .route("/authenticator/v1/entry/{id}/order", put(reorder_entry))
    }
}

// --- Keys -----------------------------------------------------------------

async fn list_keys(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, user_key_id, key FROM authenticator_keys WHERE user_id = $1 ORDER BY created",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let keys: Vec<Value> = rows
        .into_iter()
        .map(|(id, user_key_id, key)| json!({ "KeyID": id, "UserKeyID": user_key_id, "Key": key }))
        .collect();
    Ok(ok(json!({ "Keys": { "Keys": keys } })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeyReq {
    key: String,
}

/// Stores a new authenticator key. Clients encrypt it with their primary user
/// key, so it is recorded against that key.
async fn create_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<KeyReq>,
) -> ApiResult<Json<Value>> {
    let primary: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM user_keys WHERE user_id = $1 AND active = 1 ORDER BY is_primary DESC, created LIMIT 1",
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let (user_key_id,) = primary.ok_or_else(|| ApiError::bad_request("User has no keys"))?;
    let id = new_id();
    sqlx::query(
        "INSERT INTO authenticator_keys (id, user_id, user_key_id, key, created) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&user_key_id)
    .bind(&req.key)
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(ok(
        json!({ "Key": { "KeyID": id, "UserKeyID": user_key_id, "Key": req.key } }),
    ))
}

// --- Entries --------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct Entry {
    id: String,
    key_id: String,
    content: String,
    content_format_version: i64,
    revision: i64,
    flags: i64,
    created: i64,
    modified: i64,
}

const ENTRY_COLS: &str =
    "id, key_id, content, content_format_version, revision, flags, created, modified";

impl Entry {
    fn json(&self) -> Value {
        json!({
            "EntryID": self.id,
            "AuthenticatorKeyID": self.key_id,
            "Revision": self.revision,
            "ContentFormatVersion": self.content_format_version,
            "Content": self.content,
            "Flags": self.flags,
            "CreateTime": self.created,
            "ModifyTime": self.modified,
        })
    }
}

async fn load_entry(state: &AppState, user_id: &str, id: &str) -> ApiResult<Entry> {
    sqlx::query_as(leptiq_core::sql!(
        "SELECT {ENTRY_COLS} FROM authenticator_entries WHERE id = $1 AND user_id = $2"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("Entry"))
}

/// The key an entry is encrypted with must be one of the user's.
async fn check_key(state: &AppState, user_id: &str, key_id: &str) -> ApiResult<()> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT id FROM authenticator_keys WHERE id = $1 AND user_id = $2")
            .bind(key_id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    row.map(|_| ())
        .ok_or_else(|| ApiError::bad_request("Unknown authenticator key"))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListQuery {
    since: Option<String>,
}

/// Entries in display order, a page at a time. `Since` is the `LastID` of the
/// previous page; `LastID` is null on the last page.
async fn list_entries(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let ordered = ordered_ids(&state, &user.user_id).await?;
    let start = match q.since.as_deref().filter(|s| !s.is_empty()) {
        Some(since) => ordered
            .iter()
            .position(|id| id == since)
            .map(|i| i + 1)
            .unwrap_or(ordered.len()),
        None => 0,
    };
    let page: Vec<&String> = ordered.iter().skip(start).take(PAGE_SIZE).collect();
    let mut entries = Vec::with_capacity(page.len());
    for id in &page {
        entries.push(load_entry(&state, &user.user_id, id).await?.json());
    }
    let last_id = (page.len() == PAGE_SIZE && start + PAGE_SIZE < ordered.len())
        .then(|| page.last().map(|s| s.to_string()))
        .flatten();
    Ok(ok(json!({
        "Entries": { "Entries": entries, "Total": ordered.len(), "LastID": last_id }
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateReq {
    #[serde(rename = "AuthenticatorKeyID")]
    key_id: String,
    content: String,
    content_format_version: i64,
}

async fn insert_entry(state: &AppState, user_id: &str, req: &CreateReq) -> ApiResult<Entry> {
    check_key(state, user_id, &req.key_id).await?;
    let (max,): (Option<i64>,) =
        sqlx::query_as("SELECT MAX(position) FROM authenticator_entries WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    let id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO authenticator_entries (id, user_id, key_id, content, content_format_version, \
         revision, flags, position, created, modified) VALUES ($1, $2, $3, $4, $5, 1, 0, $6, $7, $7)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.key_id)
    .bind(&req.content)
    .bind(req.content_format_version)
    .bind(max.unwrap_or(-1) + 1)
    .bind(t)
    .execute(&state.db)
    .await?;
    load_entry(state, user_id, &id).await
}

async fn create_entry(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    let entry = insert_entry(&state, &user.user_id, &req).await?;
    Ok(ok(json!({ "Entry": entry.json() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateBulkReq {
    entries: Vec<CreateReq>,
}

async fn create_entries(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateBulkReq>,
) -> ApiResult<Json<Value>> {
    let mut out = Vec::with_capacity(req.entries.len());
    for e in &req.entries {
        out.push(insert_entry(&state, &user.user_id, e).await?.json());
    }
    Ok(ok(json!({ "Entries": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateReq {
    #[serde(rename = "EntryID", default)]
    entry_id: Option<String>,
    #[serde(rename = "AuthenticatorKeyID")]
    key_id: String,
    content: String,
    content_format_version: i64,
    last_revision: i64,
}

/// Replaces an entry's content if the client saw its latest revision.
async fn apply_update(
    state: &AppState,
    user_id: &str,
    id: &str,
    req: &UpdateReq,
) -> ApiResult<Entry> {
    check_key(state, user_id, &req.key_id).await?;
    let res = sqlx::query(
        "UPDATE authenticator_entries SET key_id = $1, content = $2, content_format_version = $3, \
         revision = revision + 1, modified = $4 WHERE id = $5 AND user_id = $6 AND revision = $7",
    )
    .bind(&req.key_id)
    .bind(&req.content)
    .bind(req.content_format_version)
    .bind(now())
    .bind(id)
    .bind(user_id)
    .bind(req.last_revision)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        // Distinguish a missing entry from a stale revision.
        load_entry(state, user_id, id).await?;
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            code::REVISION_CONFLICT,
            "Entry was modified by another client",
        ));
    }
    load_entry(state, user_id, id).await
}

async fn update_entry(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    let entry = apply_update(&state, &user.user_id, &id, &req).await?;
    Ok(ok(json!({ "Entry": entry.json() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateBulkReq {
    entries: Vec<UpdateReq>,
}

async fn update_entries(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpdateBulkReq>,
) -> ApiResult<Json<Value>> {
    let mut out = Vec::with_capacity(req.entries.len());
    for e in &req.entries {
        let id = e
            .entry_id
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("Missing EntryID"))?;
        out.push(apply_update(&state, &user.user_id, id, e).await?.json());
    }
    Ok(ok(json!({ "Entries": out })))
}

async fn delete_entry(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM authenticator_entries WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteBulkReq {
    #[serde(rename = "EntryIDs")]
    entry_ids: Vec<String>,
}

async fn delete_entries(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<DeleteBulkReq>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    for id in &req.entry_ids {
        sqlx::query("DELETE FROM authenticator_entries WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

// --- Ordering -------------------------------------------------------------

async fn ordered_ids(state: &AppState, user_id: &str) -> ApiResult<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM authenticator_entries WHERE user_id = $1 ORDER BY position, created, id",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Stores `ids` as the user's full display order (positions 0..n).
async fn save_order(state: &AppState, user_id: &str, ids: &[String]) -> ApiResult<()> {
    let mut tx = state.db.begin().await?;
    for (pos, id) in ids.iter().enumerate() {
        sqlx::query(
            "UPDATE authenticator_entries SET position = $1 WHERE id = $2 AND user_id = $3",
        )
        .bind(pos as i64)
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ReorderReq {
    #[serde(rename = "AfterID", default)]
    after_id: Option<String>,
}

/// Moves one entry right after `AfterID` (or to the top when it is null).
async fn reorder_entry(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ReorderReq>,
) -> ApiResult<Json<Value>> {
    let mut ids = ordered_ids(&state, &user.user_id).await?;
    let from = ids
        .iter()
        .position(|e| *e == id)
        .ok_or_else(|| ApiError::not_found("Entry"))?;
    let moved = ids.remove(from);
    let to = match req.after_id.as_deref() {
        None => 0,
        Some(after) => ids
            .iter()
            .position(|e| e == after)
            .map(|i| i + 1)
            .ok_or_else(|| ApiError::not_found("Entry"))?,
    };
    ids.insert(to, moved);
    save_order(&state, &user.user_id, &ids).await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ReorderBatchReq {
    starting_position: usize,
    entries: Vec<String>,
}

/// Places `Entries`, in order, starting at `StartingPosition`.
async fn reorder_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ReorderBatchReq>,
) -> ApiResult<Json<Value>> {
    if req.entries.len() > 500 {
        return Err(ApiError::bad_request(
            "At most 500 entries can be reordered at once",
        ));
    }
    let mut ids = ordered_ids(&state, &user.user_id).await?;
    if let Some(unknown) = req.entries.iter().find(|e| !ids.contains(e)) {
        return Err(ApiError::not_found(&format!("Entry {unknown}")));
    }
    ids.retain(|e| !req.entries.contains(e));
    let at = req.starting_position.min(ids.len());
    for (i, id) in req.entries.iter().enumerate() {
        ids.insert(at + i, id.clone());
    }
    save_order(&state, &user.user_id, &ids).await?;
    Ok(ok_empty())
}
