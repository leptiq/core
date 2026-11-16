//! Share key rotation and pending (not yet re-encrypted) share keys.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::shares;
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, now, ok},
};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ItemKey {
    #[serde(rename = "ItemID")]
    pub item_id: String,
    pub item_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeyForShare {
    #[serde(rename = "ShareID")]
    pub share_id: String,
    #[serde(rename = "AddressID")]
    pub address_id: String,
    pub encrypted_key_for_address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RotateReq {
    pub current_key_rotation: i64,
    pub vault_key: String,
    #[serde(default)]
    pub item_keys: Vec<ItemKey>,
    #[serde(default)]
    pub vault_key_for_shares: Vec<KeyForShare>,
    #[serde(default)]
    pub item_keys_for_shares: Vec<KeyForShare>,
}

/// `POST share/{id}/key`: rotate the vault key. The rotating manager supplies
/// the new key for themselves, every item key re-encrypted with it, and the
/// new key encrypted to every other member's address key.
pub async fn rotate(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<RotateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    if !share.is_vault() {
        return Err(ApiError::bad_request("Only vault keys can be rotated"));
    }
    let mut tx = state.db.begin().await?;
    let (current,): (i64,) = sqlx::query_as("SELECT current_rotation FROM vaults WHERE id = $1")
        .bind(&share.vault_id)
        .fetch_one(&mut *tx)
        .await?;
    if req.current_key_rotation != current {
        return Err(ApiError::conflict("Key rotation is outdated"));
    }
    let new = current + 1;
    let t = now();
    let user_key = shares::primary_user_key(&mut tx, &user.user_id).await?;
    sqlx::query("INSERT INTO share_keys (share_id, key_rotation, key, user_key_id, created) VALUES ($1,$2,$3,$4,$5)")
        .bind(&share.id)
        .bind(new)
        .bind(&req.vault_key)
        .bind(&user_key)
        .bind(t)
        .execute(&mut *tx)
        .await?;
    // Every item at the top level of the vault must get a new key.
    let (top_level,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM items WHERE vault_id = $1 AND folder_id IS NULL")
            .bind(&share.vault_id)
            .fetch_one(&mut *tx)
            .await?;
    if (req.item_keys.len() as i64) < top_level {
        return Err(ApiError::bad_request("All item keys must be re-encrypted"));
    }
    for ik in &req.item_keys {
        let r = sqlx::query("UPDATE items SET key_rotation = $1 WHERE id = $2 AND vault_id = $3")
            .bind(new)
            .bind(&ik.item_id)
            .bind(&share.vault_id)
            .execute(&mut *tx)
            .await?;
        if r.rows_affected() == 0 {
            return Err(ApiError::not_found("Item"));
        }
        sqlx::query("INSERT INTO item_keys (item_id, key_rotation, key) VALUES ($1,$2,$3)")
            .bind(&ik.item_id)
            .bind(new)
            .bind(&ik.item_key)
            .execute(&mut *tx)
            .await?;
    }
    // Folder keys encrypted with the vault key keep their rotation; clients
    // re-encrypt them via folder moves when needed.
    let (my_address,): (String,) = (share.address_id.clone(),);
    for k in req
        .vault_key_for_shares
        .iter()
        .chain(req.item_keys_for_shares.iter())
    {
        let target = shares::load_any(&mut tx, &k.share_id).await?;
        if target.vault_id != share.vault_id {
            return Err(ApiError::bad_request("Share does not belong to this vault"));
        }
        sqlx::query(
            "INSERT INTO pending_share_keys (id, share_id, address_id, rotator_address_id, key_rotation, encrypted_key, created) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(new_id())
        .bind(&target.id)
        .bind(&k.address_id)
        .bind(&my_address)
        .bind(new)
        .bind(&k.encrypted_key_for_address)
        .bind(t)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE vaults SET current_rotation = $1, modified = $2 WHERE id = $3")
        .bind(new)
        .bind(t)
        .bind(&share.vault_id)
        .execute(&mut *tx)
        .await?;
    let members = shares::vault_members(&mut tx, &share.vault_id).await?;
    for m in &members {
        events::push_data(
            &mut tx,
            &m.user_id,
            kind::SHARE_KEY,
            Some(&m.id),
            None,
            Some(&new.to_string()),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(ok(
        json!({ "ShareKey": { "KeyRotation": new, "Key": req.vault_key, "UserKeyID": user_key, "CreateTime": t } }),
    ))
}

pub async fn pending(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let rows: Vec<(String, String, String, i64, String)> = sqlx::query_as(
        "SELECT id, address_id, rotator_address_id, key_rotation, encrypted_key FROM pending_share_keys \
         WHERE share_id = $1 ORDER BY key_rotation",
    )
    .bind(&share.id)
    .fetch_all(&state.db)
    .await?;
    let pending: Vec<Value> = rows
        .into_iter()
        .map(|(id, a, r, kr, k)| {
            json!({ "PendingShareKeyID": id, "AddressID": a, "RotatorAddressID": r, "KeyRotation": kr, "EncryptedKey": k })
        })
        .collect();
    Ok(ok(json!({ "PendingShareKeys": { "Pending": pending } })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PromoteKey {
    pub key_rotation: i64,
    pub encrypted_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PromoteReq {
    pub keys: Vec<PromoteKey>,
}

/// `POST share/{id}/key/pending`: store pending keys re-encrypted to the user key.
pub async fn promote(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<PromoteReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut tx = state.db.begin().await?;
    let user_key = shares::primary_user_key(&mut tx, &user.user_id).await?;
    for k in &req.keys {
        sqlx::query("DELETE FROM share_keys WHERE share_id = $1 AND key_rotation = $2")
            .bind(&share.id)
            .bind(k.key_rotation)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO share_keys (share_id, key_rotation, key, user_key_id, created) VALUES ($1,$2,$3,$4,$5)")
            .bind(&share.id)
            .bind(k.key_rotation)
            .bind(&k.encrypted_key)
            .bind(&user_key)
            .bind(now())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM pending_share_keys WHERE share_id = $1 AND key_rotation = $2")
            .bind(&share.id)
            .bind(k.key_rotation)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
        "SELECT key_rotation, key, user_key_id, created FROM share_keys WHERE share_id = $1 ORDER BY key_rotation",
    )
    .bind(&share.id)
    .fetch_all(&state.db)
    .await?;
    let keys: Vec<Value> = rows
        .into_iter()
        .map(|(r, k, u, c)| json!({ "KeyRotation": r, "Key": k, "UserKeyID": u, "CreateTime": c }))
        .collect();
    Ok(ok(
        json!({ "ShareKeys": { "Keys": keys, "Total": keys.len() } }),
    ))
}
