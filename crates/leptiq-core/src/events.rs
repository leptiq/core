//! Per-user append-only event log backing both the core event loop
//! (`core/v4/events`) and Pass sync (`pass/v1/user/sync_event`,
//! `pass/v1/share/{id}/event`).

use crate::{db::Pool, error::ApiResult, util::now};
use sqlx::AnyConnection;

/// Event kinds.
pub mod kind {
    pub const USER: &str = "user";
    pub const USER_SETTINGS: &str = "user_settings";
    pub const ADDRESS: &str = "address";
    pub const ADDRESS_DELETED: &str = "address_deleted";
    pub const ITEM_UPDATED: &str = "item_updated";
    pub const ITEM_DELETED: &str = "item_deleted";
    pub const ITEM_LAST_USE: &str = "item_last_use";
    pub const ALIAS_NOTE: &str = "alias_note";
    pub const SHARE_CREATED: &str = "share_created";
    pub const SHARE_UPDATED: &str = "share_updated";
    pub const SHARE_DELETED: &str = "share_deleted";
    pub const SHARE_KEY: &str = "share_key";
    pub const FOLDER_UPDATED: &str = "folder_updated";
    pub const FOLDER_DELETED: &str = "folder_deleted";
    pub const INVITES: &str = "invites";
    pub const REFRESH_USER: &str = "refresh_user";
}

/// Maximum events returned per poll before `More`/`EventsPending` is set.
pub const PAGE: i64 = 500;

pub fn encode_id(seq: i64) -> String {
    // Opaque, fixed-width so clients can't confuse it with other IDs.
    format!("ev{seq:020}")
}

pub fn decode_id(id: &str) -> Option<i64> {
    id.strip_prefix("ev")?.parse().ok()
}

#[derive(Debug, Clone)]
pub struct Event {
    pub seq: i64,
    pub kind: String,
    pub share_id: Option<String>,
    pub target_id: Option<String>,
    pub data: Option<String>,
}

/// Appends an event for one user. Must run inside the transaction that made
/// the change so that the log and the data stay consistent.
pub async fn push(
    conn: &mut AnyConnection,
    user_id: &str,
    kind: &str,
    share_id: Option<&str>,
    target_id: Option<&str>,
) -> ApiResult<i64> {
    push_data(conn, user_id, kind, share_id, target_id, None).await
}

pub async fn push_data(
    conn: &mut AnyConnection,
    user_id: &str,
    kind: &str,
    share_id: Option<&str>,
    target_id: Option<&str>,
    data: Option<&str>,
) -> ApiResult<i64> {
    let (seq,): (i64,) = sqlx::query_as(
        "INSERT INTO event_counters (user_id, seq) VALUES ($1, 1) \
         ON CONFLICT (user_id) DO UPDATE SET seq = event_counters.seq + 1 RETURNING seq",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO events (user_id, seq, kind, share_id, target_id, data, created) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(user_id)
    .bind(seq)
    .bind(kind)
    .bind(share_id)
    .bind(target_id)
    .bind(data)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(seq)
}

/// Pushes an event to every member of a vault, with each member's own share
/// ID for that vault.
pub async fn push_vault(
    conn: &mut AnyConnection,
    vault_id: &str,
    kind: &str,
    target_id: Option<&str>,
) -> ApiResult<()> {
    let members: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_id, id FROM shares WHERE vault_id = $1 AND target_type = 1 AND deleted = 0",
    )
    .bind(vault_id)
    .fetch_all(&mut *conn)
    .await?;
    for (user_id, share_id) in members {
        push(conn, &user_id, kind, Some(&share_id), target_id).await?;
    }
    Ok(())
}

/// Pushes an item event to every share that can see the item: all vault
/// members plus members with a direct item share.
pub async fn push_item(
    conn: &mut AnyConnection,
    vault_id: &str,
    item_id: &str,
    kind: &str,
) -> ApiResult<()> {
    let members: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_id, id FROM shares WHERE vault_id = $1 AND deleted = 0 AND (target_type = 1 OR target_id = $2)",
    )
    .bind(vault_id)
    .bind(item_id)
    .fetch_all(&mut *conn)
    .await?;
    for (user_id, share_id) in members {
        push(conn, &user_id, kind, Some(&share_id), Some(item_id)).await?;
    }
    Ok(())
}

pub async fn latest_seq(db: &Pool, user_id: &str) -> ApiResult<i64> {
    let (seq,): (i64,) =
        sqlx::query_as("SELECT COALESCE(MAX(seq), 0) FROM events WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(db)
            .await?;
    Ok(seq)
}

pub async fn latest_id(db: &Pool, user_id: &str) -> ApiResult<String> {
    Ok(encode_id(latest_seq(db, user_id).await?))
}

/// Events after `since`, at most `PAGE`. Returns (events, more).
pub async fn since(db: &Pool, user_id: &str, since: i64) -> ApiResult<(Vec<Event>, bool)> {
    let rows: Vec<(i64, String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT seq, kind, share_id, target_id, data FROM events WHERE user_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
    )
    .bind(user_id)
    .bind(since)
    .bind(PAGE + 1)
    .fetch_all(db)
    .await?;
    let more = rows.len() as i64 > PAGE;
    let events = rows
        .into_iter()
        .take(PAGE as usize)
        .map(|(seq, kind, share_id, target_id, data)| Event {
            seq,
            kind,
            share_id,
            target_id,
            data,
        })
        .collect();
    Ok((events, more))
}
