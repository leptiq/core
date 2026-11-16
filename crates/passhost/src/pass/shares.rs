//! Shares: a user's access to a vault (TargetType 1) or a single item (2).

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{b, now, ok, ok_empty},
};

pub const TARGET_VAULT: i64 = 1;
pub const TARGET_ITEM: i64 = 2;
pub const ROLE_MANAGER: &str = "1";
pub const ROLE_WRITE: &str = "2";
pub const ROLE_READ: &str = "3";
pub const FLAG_HIDDEN: i64 = 1;

/// Maximum members per shared vault/item.
pub const MAX_MEMBERS: i64 = 100;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Share {
    pub id: String,
    pub vault_id: String,
    pub user_id: String,
    pub address_id: String,
    pub target_type: i64,
    pub target_id: String,
    pub share_role_id: String,
    pub owner: i64,
    pub is_primary: i64,
    pub flags: i64,
    pub expire_time: Option<i64>,
    pub created: i64,
}

const SHARE_COLS: &str = "id, vault_id, user_id, address_id, target_type, target_id, share_role_id, owner, is_primary, flags, expire_time, created";

impl Share {
    pub fn is_vault(&self) -> bool {
        self.target_type == TARGET_VAULT
    }
    pub fn can_write(&self) -> bool {
        self.owner == 1 || self.share_role_id == ROLE_MANAGER || self.share_role_id == ROLE_WRITE
    }
    pub fn can_manage(&self) -> bool {
        self.owner == 1 || self.share_role_id == ROLE_MANAGER
    }
    pub fn require_write(&self) -> ApiResult<()> {
        if self.can_write() {
            Ok(())
        } else {
            Err(ApiError::forbidden("Read-only access"))
        }
    }
    pub fn require_manage(&self) -> ApiResult<()> {
        if self.can_manage() {
            Ok(())
        } else {
            Err(ApiError::forbidden("Manager access required"))
        }
    }
    /// Whether the share gives access to the given item.
    pub fn covers_item(&self, item_id: &str) -> bool {
        self.is_vault() || self.target_id == item_id
    }
    /// Permission bitmask (read=1, write=2, manage=4, owner=8).
    pub fn permission(&self) -> i64 {
        let mut p = 1;
        if self.can_write() {
            p |= 2;
        }
        if self.can_manage() {
            p |= 4;
        }
        if self.owner == 1 {
            p |= 8;
        }
        p
    }
}

/// Loads a live share owned by `user_id`.
pub async fn load(state: &AppState, user_id: &str, share_id: &str) -> ApiResult<Share> {
    let share: Option<Share> = sqlx::query_as(crate::sql!(
        "SELECT {SHARE_COLS} FROM shares WHERE id = $1 AND user_id = $2 AND deleted = 0"
    ))
    .bind(share_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let share = share.ok_or_else(|| ApiError::not_found("Share"))?;
    if share.expire_time.map(|t| t < now()).unwrap_or(false) {
        return Err(ApiError::not_found("Share"));
    }
    Ok(share)
}

pub async fn load_any(conn: &mut AnyConnection, share_id: &str) -> ApiResult<Share> {
    let share: Option<Share> = sqlx::query_as(crate::sql!(
        "SELECT {SHARE_COLS} FROM shares WHERE id = $1 AND deleted = 0"
    ))
    .bind(share_id)
    .fetch_optional(&mut *conn)
    .await?;
    share.ok_or_else(|| ApiError::not_found("Share"))
}

/// Live member shares of a vault (vault-level and item-level).
pub async fn vault_members(conn: &mut AnyConnection, vault_id: &str) -> ApiResult<Vec<Share>> {
    Ok(sqlx::query_as(crate::sql!(
        "SELECT {SHARE_COLS} FROM shares WHERE vault_id = $1 AND deleted = 0 ORDER BY created"
    ))
    .bind(vault_id)
    .fetch_all(&mut *conn)
    .await?)
}

/// Builds the `ShareGetResponse` JSON for a share.
pub async fn share_json(state: &AppState, share: &Share) -> ApiResult<Value> {
    let mut conn = state.db.acquire().await?;
    share_json_conn(&mut conn, share).await
}

pub async fn share_json_conn(conn: &mut AnyConnection, share: &Share) -> ApiResult<Value> {
    let (members,): (i64,) = if share.is_vault() {
        sqlx::query_as("SELECT COUNT(*) FROM shares WHERE vault_id = $1 AND deleted = 0")
            .bind(&share.vault_id)
            .fetch_one(&mut *conn)
            .await?
    } else {
        sqlx::query_as(
            "SELECT COUNT(*) FROM shares WHERE vault_id = $1 AND deleted = 0 AND (target_type = 1 OR target_id = $2)",
        )
        .bind(&share.vault_id)
        .bind(&share.target_id)
        .fetch_one(&mut *conn)
        .await?
    };
    let (pending,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM invites WHERE vault_id = $1 AND target_type = $2 AND target_id = $3",
    )
    .bind(&share.vault_id)
    .bind(share.target_type)
    .bind(&share.target_id)
    .fetch_one(&mut *conn)
    .await?;
    let (new_user_ready,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM new_user_invites WHERE vault_id = $1 AND target_id = $2 AND state = 2",
    )
    .bind(&share.vault_id)
    .bind(&share.target_id)
    .fetch_one(&mut *conn)
    .await?;
    let mut out = json!({
        "ShareID": share.id,
        "VaultID": share.vault_id,
        "AddressID": share.address_id,
        "Primary": b(share.is_primary),
        "Owner": b(share.owner),
        "TargetType": share.target_type,
        "TargetID": share.target_id,
        "TargetMembers": members,
        "TargetMaxMembers": MAX_MEMBERS,
        "Shared": members > 1 || pending > 0,
        "PendingInvites": pending,
        "NewUserInvitesReady": new_user_ready,
        "Permission": share.permission(),
        "CanAutoFill": true,
        "ShareRoleID": share.share_role_id,
        "Content": null,
        "ContentKeyRotation": null,
        "ContentFormatVersion": null,
        "GroupID": null,
        "ExpireTime": share.expire_time,
        "CreateTime": share.created,
        "Flags": share.flags,
    });
    if share.is_vault() {
        let (content, cfv, ckr): (String, i64, i64) = sqlx::query_as(
            "SELECT content, content_format_version, content_key_rotation FROM vaults WHERE id = $1",
        )
        .bind(&share.vault_id)
        .fetch_one(&mut *conn)
        .await?;
        out["Content"] = json!(content);
        out["ContentFormatVersion"] = json!(cfv);
        out["ContentKeyRotation"] = json!(ckr);
    }
    Ok(out)
}

pub async fn user_shares(state: &AppState, user_id: &str) -> ApiResult<Vec<Share>> {
    Ok(sqlx::query_as(crate::sql!(
        "SELECT {SHARE_COLS} FROM shares WHERE user_id = $1 AND deleted = 0 AND (expire_time IS NULL OR expire_time > $2) \
         ORDER BY created"
    ))
    .bind(user_id)
    .bind(now())
    .fetch_all(&state.db)
    .await?)
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let shares = user_shares(&state, &user.user_id).await?;
    let mut out = Vec::with_capacity(shares.len());
    for s in &shares {
        out.push(share_json(&state, s).await?);
    }
    Ok(ok(
        json!({ "Shares": out, "Total": out.len(), "LastToken": null }),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = load(&state, &user.user_id, &id).await?;
    Ok(ok(json!({ "Share": share_json(&state, &share).await? })))
}

async fn set_hidden(
    state: &AppState,
    user_id: &str,
    share_id: &str,
    hidden: bool,
) -> ApiResult<Share> {
    let share = load(state, user_id, share_id).await?;
    let flags = if hidden {
        share.flags | FLAG_HIDDEN
    } else {
        share.flags & !FLAG_HIDDEN
    };
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE shares SET flags = $1 WHERE id = $2")
        .bind(flags)
        .bind(share_id)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, user_id, kind::SHARE_UPDATED, Some(share_id), None).await?;
    tx.commit().await?;
    load(state, user_id, share_id).await
}

pub async fn hide(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let s = set_hidden(&state, &user.user_id, &id, true).await?;
    Ok(ok(json!({ "Share": share_json(&state, &s).await? })))
}

pub async fn unhide(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let s = set_hidden(&state, &user.user_id, &id, false).await?;
    Ok(ok(json!({ "Share": share_json(&state, &s).await? })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HideBatchReq {
    #[serde(default)]
    pub shares_to_hide: Vec<String>,
    #[serde(default)]
    pub shares_to_unhide: Vec<String>,
}

pub async fn hide_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<HideBatchReq>,
) -> ApiResult<Json<Value>> {
    for id in &req.shares_to_hide {
        set_hidden(&state, &user.user_id, id, true).await?;
    }
    for id in &req.shares_to_unhide {
        set_hidden(&state, &user.user_id, id, false).await?;
    }
    list(State(state), user).await
}

/// Marks a share deleted and records events. If it was the vault owner's
/// share, the whole vault goes away for everyone.
pub async fn remove_share(conn: &mut AnyConnection, share: &Share) -> ApiResult<()> {
    sqlx::query("UPDATE shares SET deleted = 1 WHERE id = $1")
        .bind(&share.id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM share_keys WHERE share_id = $1")
        .bind(&share.id)
        .execute(&mut *conn)
        .await?;
    events::push(
        conn,
        &share.user_id,
        kind::SHARE_DELETED,
        Some(&share.id),
        None,
    )
    .await?;
    // Other members see the member count change.
    events::push_vault(conn, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    Ok(())
}

/// `DELETE share/{id}`: leave a share (non-owners).
pub async fn leave(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = load(&state, &user.user_id, &id).await?;
    if share.owner == 1 {
        return Err(ApiError::forbidden(
            "Owners cannot leave their vault; delete or transfer it",
        ));
    }
    let mut tx = state.db.begin().await?;
    remove_share(&mut tx, &share).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeysQuery {
    pub page: Option<i64>,
}

/// `GET share/{id}/key`: this user's copies of the share key, per rotation.
pub async fn keys(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(_q): Query<KeysQuery>,
) -> ApiResult<Json<Value>> {
    let _share = load(&state, &user.user_id, &id).await?;
    let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
        "SELECT key_rotation, key, user_key_id, created FROM share_keys WHERE share_id = $1 ORDER BY key_rotation",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    let keys: Vec<Value> = rows
        .into_iter()
        .map(
            |(r, k, uk, c)| json!({ "KeyRotation": r, "Key": k, "UserKeyID": uk, "CreateTime": c }),
        )
        .collect();
    Ok(ok(
        json!({ "ShareKeys": { "Keys": keys, "Total": keys.len() } }),
    ))
}

/// The user's primary user key ID (share keys are encrypted to it).
pub async fn primary_user_key(conn: &mut AnyConnection, user_id: &str) -> ApiResult<String> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM user_keys WHERE user_id = $1 ORDER BY is_primary DESC, created LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|r| r.0)
        .ok_or_else(|| ApiError::bad_request("User has no keys set up"))
}

/// Removes every share a user holds (used on account deletion). Vaults the
/// user owns are deleted entirely.
pub async fn delete_all_for_user(state: &AppState, user_id: &str) -> ApiResult<()> {
    let shares = user_shares(state, user_id).await?;
    let mut tx = state.db.begin().await?;
    for s in shares {
        if s.owner == 1 && s.is_vault() {
            super::vaults::delete_vault_conn(&mut tx, &s.vault_id).await?;
        } else {
            remove_share(&mut tx, &s).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
