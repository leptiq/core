//! Vaults: create/update/delete, primary vault, ownership transfer.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::shares::{self, ROLE_MANAGER, Share, TARGET_VAULT};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, now, ok, ok_empty},
};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateReq {
    #[serde(rename = "AddressID")]
    pub address_id: String,
    pub content: String,
    pub content_format_version: i64,
    pub encrypted_vault_key: String,
}

/// Creates a vault plus the owner's share; returns the new share.
pub async fn create_vault(state: &AppState, user_id: &str, req: &CreateReq) -> ApiResult<Share> {
    crate::core::addresses::owned(state, user_id, &req.address_id).await?;
    let vault_id = new_id();
    let share_id = new_id();
    let t = now();
    let mut tx = state.db.begin().await?;
    let user_key = shares::primary_user_key(&mut tx, user_id).await?;
    let (existing,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shares WHERE user_id = $1 AND owner = 1 AND target_type = 1 AND deleted = 0",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO vaults (id, content, content_format_version, content_key_rotation, current_rotation, owner_user_id, created, modified) \
         VALUES ($1,$2,$3,1,1,$4,$5,$5)",
    )
    .bind(&vault_id)
    .bind(&req.content)
    .bind(req.content_format_version)
    .bind(user_id)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO shares (id, vault_id, user_id, address_id, target_type, target_id, share_role_id, owner, is_primary, created) \
         VALUES ($1,$2,$3,$4,$5,$2,$6,1,$7,$8)",
    )
    .bind(&share_id)
    .bind(&vault_id)
    .bind(user_id)
    .bind(&req.address_id)
    .bind(TARGET_VAULT)
    .bind(ROLE_MANAGER)
    .bind((existing == 0) as i64)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO share_keys (share_id, key_rotation, key, user_key_id, created) VALUES ($1, 1, $2, $3, $4)")
        .bind(&share_id)
        .bind(&req.encrypted_vault_key)
        .bind(&user_key)
        .bind(t)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, user_id, kind::SHARE_CREATED, Some(&share_id), None).await?;
    tx.commit().await?;
    shares::load(state, user_id, &share_id).await
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    let share = create_vault(&state, &user.user_id, &req).await?;
    Ok(ok(
        json!({ "Share": shares::share_json(&state, &share).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateReq {
    pub content: String,
    pub content_format_version: i64,
    pub key_rotation: i64,
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    if !share.is_vault() {
        return Err(ApiError::bad_request("Not a vault share"));
    }
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    let (current,): (i64,) = sqlx::query_as("SELECT current_rotation FROM vaults WHERE id = $1")
        .bind(&share.vault_id)
        .fetch_one(&mut *tx)
        .await?;
    if req.key_rotation != current {
        return Err(ApiError::bad_request(
            "Content must be encrypted with the latest vault key",
        ));
    }
    sqlx::query("UPDATE vaults SET content = $1, content_format_version = $2, content_key_rotation = $3, modified = $4 WHERE id = $5")
        .bind(&req.content)
        .bind(req.content_format_version)
        .bind(req.key_rotation)
        .bind(now())
        .bind(&share.vault_id)
        .execute(&mut *tx)
        .await?;
    events::push_vault(&mut tx, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "Share": shares::share_json(&state, &share).await? }),
    ))
}

/// Deletes a vault and everything in it, notifying all members.
pub async fn delete_vault_conn(conn: &mut AnyConnection, vault_id: &str) -> ApiResult<()> {
    let members = shares::vault_members(conn, vault_id).await?;
    for m in &members {
        events::push(conn, &m.user_id, kind::SHARE_DELETED, Some(&m.id), None).await?;
    }
    let files: Vec<(String,)> = sqlx::query_as(
        "SELECT f.id FROM files f JOIN item_files i ON i.file_id = f.id JOIN items it ON it.id = i.item_id WHERE it.vault_id = $1",
    )
    .bind(vault_id)
    .fetch_all(&mut *conn)
    .await?;
    for (f,) in files {
        sqlx::query("UPDATE files SET orphaned = 1 WHERE id = $1")
            .bind(&f)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("DELETE FROM vaults WHERE id = $1")
        .bind(vault_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    if !share.is_vault() || share.owner != 1 {
        return Err(ApiError::forbidden("Only the owner can delete a vault"));
    }
    let mut tx = state.db.begin().await?;
    delete_vault_conn(&mut tx, &share.vault_id).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

pub async fn set_primary(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut tx = state.db.begin().await?;
    let previous: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM shares WHERE user_id = $1 AND is_primary = 1")
            .bind(&user.user_id)
            .fetch_all(&mut *tx)
            .await?;
    sqlx::query("UPDATE shares SET is_primary = 0 WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE shares SET is_primary = 1 WHERE id = $1")
        .bind(&share.id)
        .execute(&mut *tx)
        .await?;
    for (p,) in previous {
        events::push(&mut tx, &user.user_id, kind::SHARE_UPDATED, Some(&p), None).await?;
    }
    events::push(
        &mut tx,
        &user.user_id,
        kind::SHARE_UPDATED,
        Some(&share.id),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TransferReq {
    #[serde(rename = "NewOwnerShareID")]
    pub new_owner_share_id: String,
}

/// `PUT vault/{shareId}/owner`: hand the vault to another member.
pub async fn transfer_owner(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<TransferReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    if share.owner != 1 || !share.is_vault() {
        return Err(ApiError::forbidden("Only the owner can transfer a vault"));
    }
    let mut tx = state.db.begin().await?;
    let target = shares::load_any(&mut tx, &req.new_owner_share_id).await?;
    if target.vault_id != share.vault_id || !target.is_vault() {
        return Err(ApiError::bad_request(
            "Target share is not a member of this vault",
        ));
    }
    sqlx::query("UPDATE shares SET owner = 0, share_role_id = $1 WHERE id = $2")
        .bind(ROLE_MANAGER)
        .bind(&share.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE shares SET owner = 1, share_role_id = $1 WHERE id = $2")
        .bind(ROLE_MANAGER)
        .bind(&target.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE vaults SET owner_user_id = $1 WHERE id = $2")
        .bind(&target.user_id)
        .bind(&share.vault_id)
        .execute(&mut *tx)
        .await?;
    events::push_vault(&mut tx, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

/// `GET vault/share/{vaultId}`: the user's share for a vault, if any.
pub async fn share_for_vault(
    State(state): State<AppState>,
    user: AuthUser,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = shares::user_shares(&state, &user.user_id)
        .await?
        .into_iter()
        .find(|s| s.vault_id == vault_id && s.is_vault());
    let share = match share {
        Some(s) => Some(shares::share_json(&state, &s).await?),
        None => None,
    };
    Ok(ok(json!({ "Share": share })))
}
