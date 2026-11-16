//! Public ("secure") links: read-only, expiring access to one item revision.
//! The link key lives only in the URL fragment, so the server never sees it.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{items, shares};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    util::{new_id, new_token, now, ok, ok_empty},
};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateReq {
    pub revision: i64,
    pub expiration_time: i64,
    pub max_read_count: Option<i64>,
    pub encrypted_item_key: String,
    pub encrypted_link_key: String,
    pub link_key_share_key_rotation: i64,
    pub link_key_encrypted_with_item_key: Option<bool>,
}

/// Max lifetime of a link (30 days), like the official service.
const MAX_TTL: i64 = 30 * 24 * 3600;

fn link_url(state: &AppState, token: &str) -> String {
    format!(
        "{}/u/{}",
        state.config.public_url.trim_end_matches('/'),
        token
    )
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut conn = state.db.acquire().await?;
    let item = items::load(&mut conn, &share, &item_id).await?;
    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT revision FROM item_revisions WHERE item_id = $1 AND revision = $2")
            .bind(&item.id)
            .bind(req.revision)
            .fetch_optional(&mut *conn)
            .await?;
    exists.ok_or_else(|| ApiError::not_found("Revision"))?;
    let t = now();
    // Clients send either an absolute timestamp or a duration in seconds.
    let expiration = if req.expiration_time > t {
        req.expiration_time
    } else {
        t + req.expiration_time
    };
    if expiration > t + MAX_TTL + 60 {
        return Err(ApiError::bad_request("Expiration too far in the future"));
    }
    let id = new_id();
    let token = new_token(40);
    sqlx::query(
        "INSERT INTO public_links (id, token, user_id, share_id, vault_id, item_id, revision, encrypted_item_key, \
         encrypted_link_key, link_key_share_key_rotation, link_key_encrypted_with_item_key, max_read_count, expiration_time, created) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(&id)
    .bind(&token)
    .bind(&user.user_id)
    .bind(&share.id)
    .bind(&share.vault_id)
    .bind(&item.id)
    .bind(req.revision)
    .bind(&req.encrypted_item_key)
    .bind(&req.encrypted_link_key)
    .bind(req.link_key_share_key_rotation)
    .bind(req.link_key_encrypted_with_item_key.unwrap_or(false) as i64)
    .bind(req.max_read_count)
    .bind(expiration)
    .bind(t)
    .execute(&mut *conn)
    .await?;
    Ok(ok(
        json!({ "PublicLink": { "Url": link_url(&state, &token), "PublicLinkID": id, "ExpirationTime": expiration } }),
    ))
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, i64, Option<i64>, i64, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, token, read_count, max_read_count, expiration_time, share_id, item_id, encrypted_link_key, \
         link_key_share_key_rotation, link_key_encrypted_with_item_key FROM public_links WHERE user_id = $1 ORDER BY created",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let t = now();
    let links: Vec<Value> = rows
        .into_iter()
        .map(|(id, token, reads, max, exp, share, item, lk, rot, with_item)| {
            let active = exp > t && max.map(|m| reads < m).unwrap_or(true);
            json!({
                "LinkID": id, "ReadCount": reads, "MaxReadCount": max.unwrap_or(0), "ExpirationTime": exp,
                "ShareID": share, "ItemID": item, "LinkURL": link_url(&state, &token), "EncryptedLinkKey": lk,
                "LinkKeyShareKeyRotation": rot, "Active": active, "LinkKeyEncryptedWithItemKey": with_item != 0, "Flags": 0,
            })
        })
        .collect();
    Ok(ok(json!({ "PublicLinks": links })))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM public_links WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

pub async fn delete_inactive(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    sqlx::query(
        "DELETE FROM public_links WHERE user_id = $1 AND (expiration_time < $2 OR (max_read_count IS NOT NULL AND read_count >= max_read_count))",
    )
    .bind(&user.user_id)
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(ok_empty())
}

/// `GET public_link/content/{token}`: unauthenticated read of a link.
pub async fn content(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let row: Option<(String, String, i64, String, i64, Option<i64>, i64, i64)> = sqlx::query_as(
        "SELECT id, item_id, revision, encrypted_item_key, read_count, max_read_count, expiration_time, \
         link_key_encrypted_with_item_key FROM public_links WHERE token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await?;
    let Some((id, item_id, revision, item_key, reads, max, exp, with_item)) = row else {
        return Err(ApiError::not_found("Link"));
    };
    if exp < now() || max.map(|m| reads >= m).unwrap_or(false) {
        return Err(ApiError::not_found("Link"));
    }
    let (content, cfv): (String, i64) =
        sqlx::query_as("SELECT content, content_format_version FROM item_revisions WHERE item_id = $1 AND revision = $2")
            .bind(&item_id)
            .bind(revision)
            .fetch_one(&state.db)
            .await?;
    sqlx::query("UPDATE public_links SET read_count = read_count + 1 WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    let (files,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM item_files WHERE item_id = $1 AND revision_added <= $2 AND (revision_removed IS NULL OR revision_removed > $2)",
    )
    .bind(&item_id)
    .bind(revision)
    .fetch_one(&state.db)
    .await?;
    Ok(ok(json!({ "PublicLinkContent": {
        "Contents": content,
        "ItemKey": item_key,
        "FilesToken": if files > 0 { Some(token.clone()) } else { None },
        "ContentFormatVersion": cfv,
        "ReadCount": reads + 1,
        "MaxReadCount": max.unwrap_or(0),
        "ExpirationTime": exp,
        "LinkKeyEncryptedWithItemKey": with_item != 0,
        "Flags": 0,
    }})))
}
