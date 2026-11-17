//! `lumo/v1/...`: encrypted storage of spaces, conversations, messages,
//! assets and settings, plus their event loop. All payloads (`Encrypted`,
//! `SpaceKey`, `MasterKey`) are client ciphertext.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use leptiq_core::{
    AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult, code},
    util::{new_id, now, ok, ok_empty},
};
use serde::Deserialize;
use serde_json::{Value, json};

pub const ACTION_DELETE: i64 = 0;
pub const ACTION_CREATE: i64 = 1;
pub const ACTION_UPDATE: i64 = 2;

/// Unix seconds as an ISO 8601 UTC timestamp (the client expects serialized
/// dates).
pub fn iso(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

async fn event(
    state: &AppState,
    user_id: &str,
    kind: &str,
    id: &str,
    action: i64,
) -> ApiResult<()> {
    let mut conn = state.db.acquire().await?;
    let seq = leptiq_core::db::next_counter(&mut conn, &format!("lumo_events:{user_id}")).await?;
    sqlx::query(
        "INSERT INTO lumo_events (user_id, seq, kind, item_id, action, created) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(user_id)
    .bind(seq)
    .bind(kind)
    .bind(id)
    .bind(action)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Maps a unique-tag violation to the 409 the client treats as "exists".
fn tag_conflict(e: sqlx::Error) -> ApiError {
    let msg = e.to_string().to_lowercase();
    if msg.contains("unique") || msg.contains("duplicate") {
        ApiError::new(
            StatusCode::CONFLICT,
            code::ALREADY_EXISTS,
            "Resource already exists",
        )
    } else {
        e.into()
    }
}

// --- Master keys -------------------------------------------------------------

pub async fn get_master_keys(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, master_key, version, created FROM lumo_master_keys WHERE user_id = $1 ORDER BY created",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let n = rows.len();
    let keys: Vec<Value> = rows
        .into_iter()
        .enumerate()
        .map(|(i, (id, key, version, created))| {
            json!({ "ID": id, "IsLatest": i + 1 == n, "Version": version, "CreateTime": iso(created), "MasterKey": key })
        })
        .collect();
    Ok(ok(json!({ "Eligibility": 0, "MasterKeys": keys })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MasterKeyReq {
    master_key: String,
}

pub async fn post_master_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(r): Json<MasterKeyReq>,
) -> ApiResult<Json<Value>> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM lumo_master_keys WHERE user_id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
    sqlx::query("INSERT INTO lumo_master_keys (id, user_id, master_key, version, created) VALUES ($1, $2, $3, $4, $5)")
        .bind(new_id())
        .bind(&user.user_id)
        .bind(&r.master_key)
        .bind(count + 1)
        .bind(now())
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

// --- Spaces ------------------------------------------------------------------

type SpaceRow = (String, i64, String, String, Option<String>, i64, i64);

async fn space_json(state: &AppState, user_id: &str, s: SpaceRow) -> ApiResult<Value> {
    let (id, space_type, space_key, tag, encrypted, created, updated) = s;
    let convs: Vec<(String, i64, String, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT id, is_starred, tag, encrypted, created, updated FROM lumo_conversations \
         WHERE space_id = $1 AND user_id = $2 ORDER BY created",
    )
    .bind(&id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    let assets: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT id, tag, created FROM lumo_assets WHERE space_id = $1 AND user_id = $2 ORDER BY created",
    )
    .bind(&id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(json!({
        "ID": id,
        "SpaceType": space_type,
        "CreateTime": iso(created),
        "UpdateTime": iso(updated),
        "DeleteTime": null,
        "SpaceKey": space_key,
        "SpaceTag": tag,
        "Encrypted": encrypted,
        "Conversations": convs.into_iter().map(|(cid, starred, ctag, cenc, cc, cu)| json!({
            "ID": cid, "SpaceID": id, "CreateTime": iso(cc), "UpdateTime": iso(cu), "DeleteTime": null,
            "IsStarred": starred != 0, "Encrypted": cenc, "ConversationTag": ctag, "Messages": [],
        })).collect::<Vec<_>>(),
        "Assets": assets.into_iter().map(|(aid, atag, ac)| json!({
            "ID": aid, "SpaceID": id, "AssetTag": atag, "CreateTime": iso(ac), "DeleteTime": null,
        })).collect::<Vec<_>>(),
    }))
}

const SPACE_COLS: &str = "id, space_type, space_key, tag, encrypted, created, updated";

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SpacesQuery {
    create_time_since: Option<i64>,
    create_time_until: Option<i64>,
    page_size: Option<i64>,
}

/// Spaces newest first, with their conversations (without messages).
pub async fn list_spaces(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<SpacesQuery>,
) -> ApiResult<Json<Value>> {
    let rows: Vec<SpaceRow> = sqlx::query_as(leptiq_core::sql!(
        "SELECT {SPACE_COLS} FROM lumo_spaces WHERE user_id = $1 AND created >= $2 AND created <= $3 \
         ORDER BY created DESC, id DESC LIMIT $4"
    ))
    .bind(&user.user_id)
    .bind(q.create_time_since.unwrap_or(0))
    .bind(q.create_time_until.unwrap_or(i64::MAX))
    .bind(q.page_size.unwrap_or(100).clamp(1, 1000))
    .fetch_all(&state.db)
    .await?;
    let mut spaces = Vec::new();
    for r in rows {
        spaces.push(space_json(&state, &user.user_id, r).await?);
    }
    Ok(ok(json!({ "Spaces": spaces })))
}

async fn load_space(state: &AppState, user_id: &str, id: &str) -> ApiResult<SpaceRow> {
    sqlx::query_as(leptiq_core::sql!(
        "SELECT {SPACE_COLS} FROM lumo_spaces WHERE id = $1 AND user_id = $2"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("Space"))
}

pub async fn get_space(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let s = load_space(&state, &user.user_id, &id).await?;
    Ok(ok(
        json!({ "Space": space_json(&state, &user.user_id, s).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SpaceReq {
    #[serde(default)]
    space_type: Option<i64>,
    space_key: String,
    space_tag: String,
    #[serde(default)]
    encrypted: Option<String>,
}

pub async fn create_space(
    State(state): State<AppState>,
    user: AuthUser,
    Json(r): Json<SpaceReq>,
) -> ApiResult<Json<Value>> {
    let id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO lumo_spaces (id, user_id, space_type, space_key, tag, encrypted, created, updated) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(r.space_type.unwrap_or(0))
    .bind(&r.space_key)
    .bind(&r.space_tag)
    .bind(&r.encrypted)
    .bind(t)
    .execute(&state.db)
    .await
    .map_err(tag_conflict)?;
    event(&state, &user.user_id, "LumoSpaces", &id, ACTION_CREATE).await?;
    Ok(ok(json!({ "Space": { "ID": id } })))
}

pub async fn update_space(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(r): Json<SpaceReq>,
) -> ApiResult<Json<Value>> {
    load_space(&state, &user.user_id, &id).await?;
    sqlx::query(
        "UPDATE lumo_spaces SET space_type = COALESCE($1, space_type), space_key = $2, encrypted = $3, updated = $4 \
         WHERE id = $5 AND user_id = $6",
    )
    .bind(r.space_type)
    .bind(&r.space_key)
    .bind(&r.encrypted)
    .bind(now())
    .bind(&id)
    .bind(&user.user_id)
    .execute(&state.db)
    .await?;
    event(&state, &user.user_id, "LumoSpaces", &id, ACTION_UPDATE).await?;
    Ok(ok_empty())
}

pub async fn delete_space(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    load_space(&state, &user.user_id, &id).await?;
    sqlx::query("DELETE FROM lumo_spaces WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    event(&state, &user.user_id, "LumoSpaces", &id, ACTION_DELETE).await?;
    Ok(ok_empty())
}

pub async fn delete_all_spaces(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    let ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM lumo_spaces WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_all(&state.db)
        .await?;
    sqlx::query("DELETE FROM lumo_spaces WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    for (id,) in &ids {
        event(&state, &user.user_id, "LumoSpaces", id, ACTION_DELETE).await?;
    }
    Ok(ok(json!({ "DeletedCount": ids.len() })))
}

// --- Conversations -----------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConversationReq {
    #[serde(default)]
    is_starred: Option<bool>,
    #[serde(default)]
    encrypted: Option<String>,
    conversation_tag: String,
}

pub async fn create_conversation(
    State(state): State<AppState>,
    user: AuthUser,
    Path(space_id): Path<String>,
    Json(r): Json<ConversationReq>,
) -> ApiResult<Json<Value>> {
    load_space(&state, &user.user_id, &space_id).await?;
    let id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO lumo_conversations (id, user_id, space_id, is_starred, tag, encrypted, created, updated) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&space_id)
    .bind(r.is_starred.unwrap_or(false) as i64)
    .bind(&r.conversation_tag)
    .bind(&r.encrypted)
    .bind(t)
    .execute(&state.db)
    .await
    .map_err(tag_conflict)?;
    event(
        &state,
        &user.user_id,
        "LumoConversations",
        &id,
        ACTION_CREATE,
    )
    .await?;
    Ok(ok(json!({ "Conversation": { "ID": id } })))
}

type ConvRow = (String, String, i64, String, Option<String>, i64, i64);

async fn load_conversation(state: &AppState, user_id: &str, id: &str) -> ApiResult<ConvRow> {
    sqlx::query_as(
        "SELECT id, space_id, is_starred, tag, encrypted, created, updated FROM lumo_conversations \
         WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("Conversation"))
}

fn conversation_json(c: &ConvRow, messages: Vec<Value>) -> Value {
    json!({
        "ID": c.0, "SpaceID": c.1, "IsStarred": c.2 != 0, "ConversationTag": c.3, "Encrypted": c.4,
        "CreateTime": iso(c.5), "UpdateTime": iso(c.6), "DeleteTime": null, "Messages": messages,
    })
}

/// A conversation with its messages (without their encrypted contents).
pub async fn get_conversation(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let c = load_conversation(&state, &user.user_id, &id).await?;
    let msgs: Vec<(String, i64, Option<i64>, Option<String>, String, i64)> = sqlx::query_as(
        "SELECT id, role, status, parent_id, tag, created FROM lumo_messages WHERE conversation_id = $1 ORDER BY created, id",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    let messages = msgs
        .into_iter()
        .map(|(mid, role, status, parent, tag, created)| {
            json!({
                "ID": mid, "ConversationID": id, "CreateTime": iso(created), "Role": role,
                "Status": status, "ParentID": parent, "MessageTag": tag,
            })
        })
        .collect();
    Ok(ok(
        json!({ "Conversation": conversation_json(&c, messages) }),
    ))
}

pub async fn update_conversation(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(r): Json<ConversationReq>,
) -> ApiResult<Json<Value>> {
    load_conversation(&state, &user.user_id, &id).await?;
    sqlx::query(
        "UPDATE lumo_conversations SET is_starred = COALESCE($1, is_starred), encrypted = $2, updated = $3 \
         WHERE id = $4 AND user_id = $5",
    )
    .bind(r.is_starred.map(|b| b as i64))
    .bind(&r.encrypted)
    .bind(now())
    .bind(&id)
    .bind(&user.user_id)
    .execute(&state.db)
    .await?;
    event(
        &state,
        &user.user_id,
        "LumoConversations",
        &id,
        ACTION_UPDATE,
    )
    .await?;
    let c = load_conversation(&state, &user.user_id, &id).await?;
    Ok(ok(json!({ "Conversation": conversation_json(&c, vec![]) })))
}

pub async fn delete_conversation(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    load_conversation(&state, &user.user_id, &id).await?;
    sqlx::query("DELETE FROM lumo_conversations WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    event(
        &state,
        &user.user_id,
        "LumoConversations",
        &id,
        ACTION_DELETE,
    )
    .await?;
    Ok(ok_empty())
}

// --- Messages ----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageReq {
    role: i64,
    #[serde(rename = "ParentID", default)]
    parent_id: Option<String>,
    #[serde(rename = "ParentId", default)]
    parent_id_alt: Option<String>,
    #[serde(default)]
    status: Option<i64>,
    #[serde(default)]
    encrypted: Option<String>,
    message_tag: String,
}

pub async fn create_message(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
    Json(r): Json<MessageReq>,
) -> ApiResult<Json<Value>> {
    load_conversation(&state, &user.user_id, &conversation_id).await?;
    let id = new_id();
    let t = now();
    let parent = r.parent_id.or(r.parent_id_alt);
    sqlx::query(
        "INSERT INTO lumo_messages (id, user_id, conversation_id, role, status, parent_id, tag, encrypted, created) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&conversation_id)
    .bind(r.role)
    .bind(r.status)
    .bind(&parent)
    .bind(&r.message_tag)
    .bind(&r.encrypted)
    .bind(t)
    .execute(&state.db)
    .await
    .map_err(tag_conflict)?;
    sqlx::query("UPDATE lumo_conversations SET updated = $1 WHERE id = $2")
        .bind(t)
        .bind(&conversation_id)
        .execute(&state.db)
        .await?;
    event(&state, &user.user_id, "LumoMessages", &id, ACTION_CREATE).await?;
    Ok(ok(json!({ "Message": {
        "ID": id, "ConversationID": conversation_id, "CreateTime": iso(t), "Role": r.role,
        "Status": r.status, "ParentID": parent, "MessageTag": r.message_tag,
    } })))
}

pub async fn get_message(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let m: Option<(String, i64, Option<i64>, Option<String>, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT conversation_id, role, status, parent_id, tag, encrypted, created FROM lumo_messages \
         WHERE id = $1 AND user_id = $2",
    )
    .bind(&id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let (conv, role, status, parent, tag, encrypted, created) =
        m.ok_or_else(|| ApiError::not_found("Message"))?;
    Ok(ok(json!({ "Message": {
        "ID": id, "ConversationID": conv, "CreateTime": iso(created), "Role": role, "Status": status,
        "ParentID": parent, "MessageTag": tag, "Encrypted": encrypted,
    } })))
}

pub async fn delete_message(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let res = sqlx::query("DELETE FROM lumo_messages WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Message"));
    }
    event(&state, &user.user_id, "LumoMessages", &id, ACTION_DELETE).await?;
    Ok(ok_empty())
}

// --- Assets ------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssetReq {
    #[serde(default)]
    encrypted: Option<String>,
    asset_tag: String,
    #[serde(default)]
    asset_type: Option<i64>,
}

pub async fn create_asset(
    State(state): State<AppState>,
    user: AuthUser,
    Path(space_id): Path<String>,
    Json(r): Json<AssetReq>,
) -> ApiResult<Json<Value>> {
    load_space(&state, &user.user_id, &space_id).await?;
    let id = new_id();
    sqlx::query(
        "INSERT INTO lumo_assets (id, user_id, space_id, asset_type, tag, encrypted, created) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&space_id)
    .bind(r.asset_type)
    .bind(&r.asset_tag)
    .bind(&r.encrypted)
    .bind(now())
    .execute(&state.db)
    .await
    .map_err(tag_conflict)?;
    event(&state, &user.user_id, "LumoAssets", &id, ACTION_CREATE).await?;
    Ok(ok(json!({ "Asset": { "ID": id } })))
}

type AssetRow = (String, String, String, Option<String>, i64);

async fn load_asset(state: &AppState, user_id: &str, id: &str) -> ApiResult<AssetRow> {
    sqlx::query_as("SELECT id, space_id, tag, encrypted, created FROM lumo_assets WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("Asset"))
}

fn asset_json(a: &AssetRow) -> Value {
    json!({
        "ID": a.0, "SpaceID": a.1, "AssetTag": a.2, "Encrypted": a.3, "CreateTime": iso(a.4), "DeleteTime": null,
    })
}

pub async fn get_asset(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let a = load_asset(&state, &user.user_id, &id).await?;
    Ok(ok(json!({ "Asset": asset_json(&a) })))
}

pub async fn update_asset(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(r): Json<AssetReq>,
) -> ApiResult<Json<Value>> {
    load_asset(&state, &user.user_id, &id).await?;
    sqlx::query("UPDATE lumo_assets SET encrypted = $1 WHERE id = $2 AND user_id = $3")
        .bind(&r.encrypted)
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    event(&state, &user.user_id, "LumoAssets", &id, ACTION_UPDATE).await?;
    let a = load_asset(&state, &user.user_id, &id).await?;
    Ok(ok(json!({ "Asset": asset_json(&a) })))
}

pub async fn delete_asset(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    load_asset(&state, &user.user_id, &id).await?;
    sqlx::query("DELETE FROM lumo_assets WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    event(&state, &user.user_id, "LumoAssets", &id, ACTION_DELETE).await?;
    Ok(ok_empty())
}

// --- Settings ----------------------------------------------------------------

pub async fn get_settings(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let row: Option<(String, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT tag, encrypted, created, updated FROM lumo_settings WHERE user_id = $1",
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(ok(match row {
        Some((tag, enc, c, u)) => json!({ "UserSettings": {
            "UserSettingsTag": tag, "Encrypted": enc, "CreateTime": iso(c), "UpdateTime": iso(u),
        } }),
        None => json!({}),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SettingsReq {
    user_settings_tag: String,
    #[serde(default)]
    encrypted: Option<String>,
}

pub async fn put_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Json(r): Json<SettingsReq>,
) -> ApiResult<Json<Value>> {
    let t = now();
    sqlx::query(
        "INSERT INTO lumo_settings (user_id, tag, encrypted, created, updated) VALUES ($1, $2, $3, $4, $4) \
         ON CONFLICT (user_id) DO UPDATE SET tag = excluded.tag, encrypted = excluded.encrypted, updated = excluded.updated",
    )
    .bind(&user.user_id)
    .bind(&r.user_settings_tag)
    .bind(&r.encrypted)
    .bind(t)
    .execute(&state.db)
    .await?;
    event(
        &state,
        &user.user_id,
        "LumoUserSettings",
        &user.user_id,
        ACTION_UPDATE,
    )
    .await?;
    Ok(ok_empty())
}

// --- Events ------------------------------------------------------------------

fn event_id(seq: i64) -> String {
    format!("{seq:020}")
}

async fn latest_seq(state: &AppState, user_id: &str) -> ApiResult<i64> {
    let (seq,): (Option<i64>,) =
        sqlx::query_as("SELECT MAX(seq) FROM lumo_events WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    Ok(seq.unwrap_or(0))
}

pub async fn latest_event(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "EventID": event_id(latest_seq(&state, &user.user_id).await?) }),
    ))
}

const KINDS: [&str; 6] = [
    "LumoSpaces",
    "LumoConversations",
    "LumoMessages",
    "LumoAssets",
    "LumoUserSettings",
    "LumoSkills",
];

pub async fn events(
    State(state): State<AppState>,
    user: AuthUser,
    Path(event): Path<String>,
) -> ApiResult<Json<Value>> {
    let latest = latest_seq(&state, &user.user_id).await?;
    let since = match event.parse::<i64>() {
        Ok(s) if s <= latest => s,
        _ => {
            let mut body = json!({ "More": false, "Refresh": true, "EventID": event_id(latest) });
            for k in KINDS {
                body[k] = Value::Null;
            }
            return Ok(ok(body));
        }
    };
    let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
        "SELECT seq, kind, item_id, action FROM lumo_events WHERE user_id = $1 AND seq > $2 ORDER BY seq LIMIT 200",
    )
    .bind(&user.user_id)
    .bind(since)
    .fetch_all(&state.db)
    .await?;
    let last = rows.last().map(|r| r.0).unwrap_or(since);
    let mut body = json!({ "More": last < latest, "Refresh": false, "EventID": event_id(last) });
    for k in KINDS {
        let items: Vec<Value> = rows
            .iter()
            .filter(|r| r.1 == k)
            .map(|r| json!({ "ID": r.2, "Action": r.3 }))
            .collect();
        body[k] = if items.is_empty() {
            Value::Null
        } else {
            json!(items)
        };
    }
    Ok(ok(body))
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso_dates() {
        assert_eq!(super::iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(super::iso(1_794_960_000), "2026-11-18T00:00:00.000Z");
        assert_eq!(super::iso(951_782_400), "2000-02-29T00:00:00.000Z");
    }
}
