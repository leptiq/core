//! Members of a shared vault/item: list, change role/expiry, remove.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::shares::{self, ROLE_MANAGER, ROLE_READ, ROLE_WRITE, Share};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{ok, ok_empty},
};

async fn member_json(state: &AppState, s: &Share) -> ApiResult<Value> {
    let (name, email): (String, String) = sqlx::query_as(
        "SELECT u.display_name, a.email FROM users u JOIN addresses a ON a.id = $1 WHERE u.id = $2",
    )
    .bind(&s.address_id)
    .bind(&s.user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(json!({
        "ShareID": s.id,
        "UserName": name,
        "UserEmail": email,
        "Owner": s.owner == 1,
        "TargetType": s.target_type,
        "TargetID": s.target_id,
        "Permission": s.permission(),
        "ShareRoleID": s.share_role_id,
        "ExpireTime": s.expire_time,
        "CreateTime": s.created,
        "IsGroupShare": false,
    }))
}

async fn list_members(
    state: &AppState,
    share: &Share,
    item_id: Option<&str>,
) -> ApiResult<Json<Value>> {
    let mut conn = state.db.acquire().await?;
    let members = shares::vault_members(&mut conn, &share.vault_id).await?;
    drop(conn);
    let mut out = vec![];
    for m in members {
        let visible = match item_id {
            // Item view: vault members plus direct shares of that item.
            Some(i) => m.is_vault() || m.target_id == i,
            // Vault view from a vault share: everyone; from an item share: same item only.
            None if share.is_vault() => true,
            None => m.is_vault() || m.target_id == share.target_id,
        };
        if visible {
            out.push(member_json(state, &m).await?);
        }
    }
    Ok(ok(
        json!({ "Shares": out, "Total": out.len(), "LastToken": "" }),
    ))
}

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    list_members(&state, &share, None).await
}

pub async fn list_for_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    if !share.covers_item(&item_id) {
        return Err(ApiError::not_found("Item"));
    }
    list_members(&state, &share, Some(&item_id)).await
}

async fn member_of(state: &AppState, share: &Share, member_share_id: &str) -> ApiResult<Share> {
    let mut conn = state.db.acquire().await?;
    let m = shares::load_any(&mut conn, member_share_id).await?;
    if m.vault_id != share.vault_id {
        return Err(ApiError::not_found("Share"));
    }
    Ok(m)
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, member)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let m = member_of(&state, &share, &member).await?;
    Ok(ok(json!({ "Share": member_json(&state, &m).await? })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateReq {
    #[serde(rename = "ShareRoleID")]
    pub share_role_id: Option<String>,
    pub expire_time: Option<i64>,
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, member)): Path<(String, String)>,
    Json(req): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let m = member_of(&state, &share, &member).await?;
    if m.owner == 1 {
        return Err(ApiError::forbidden("Cannot change the owner's role"));
    }
    let mut tx = state.db.begin().await?;
    if let Some(role) = &req.share_role_id {
        if ![ROLE_MANAGER, ROLE_WRITE, ROLE_READ].contains(&role.as_str()) {
            return Err(ApiError::bad_request("Invalid share role"));
        }
        sqlx::query("UPDATE shares SET share_role_id = $1 WHERE id = $2")
            .bind(role)
            .bind(&m.id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(exp) = req.expire_time {
        sqlx::query("UPDATE shares SET expire_time = $1 WHERE id = $2")
            .bind(exp)
            .bind(&m.id)
            .execute(&mut *tx)
            .await?;
    }
    events::push(&mut tx, &m.user_id, kind::SHARE_UPDATED, Some(&m.id), None).await?;
    events::push_vault(&mut tx, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

pub async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, member)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let m = member_of(&state, &share, &member).await?;
    if m.owner == 1 {
        return Err(ApiError::forbidden("Cannot remove the owner"));
    }
    let mut tx = state.db.begin().await?;
    shares::remove_share(&mut tx, &m).await?;
    tx.commit().await?;
    Ok(ok_empty())
}
