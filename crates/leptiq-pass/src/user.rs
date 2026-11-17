//! Pass user endpoints: access/plan, default share, monitor settings.

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
    util::{now, ok, ok_empty},
};

/// Ensures the pass_user row exists; returns (default_share, monitor_proton,
/// monitor_aliases, notifications_disabled, activation_time).
pub async fn ensure(
    state: &AppState,
    user_id: &str,
) -> ApiResult<(Option<String>, i64, i64, i64, i64)> {
    let row: Option<(Option<String>, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT default_share_id, monitor_proton, monitor_aliases, inapp_notifications_disabled, activation_time \
         FROM pass_user WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some(r) = row {
        return Ok(r);
    }
    let t = now();
    sqlx::query("INSERT INTO pass_user (user_id, activation_time) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING")
        .bind(user_id)
        .bind(t)
        .execute(&state.db)
        .await?;
    Ok((None, 1, 1, 0, t))
}

/// The unlimited "plan" every user on a self-hosted instance gets.
pub fn plan_json(state: &AppState, storage_used: i64) -> Value {
    json!({
        "Type": "plus",
        "InternalName": "passhost",
        "DisplayName": "Self-hosted",
        "ManageSubscription": false,
        "SubscriptionEnd": null,
        "SubscriptionCycle": null,
        "SubscriptionRenewal": false,
        "SubscriptionCoupon": null,
        "SubscriptionOffer": null,
        "HideUpgrade": true,
        "TrialEnd": null,
        "VaultLimit": null,
        "AliasLimit": null,
        "TotpLimit": null,
        "ManageAlias": state.ext::<crate::PassConfig>().alias.enabled,
        "StorageAllowed": true,
        "StorageMaxFileSize": 100 * 1024 * 1024,
        "StorageUsed": storage_used,
        "StorageQuota": state.config.storage_quota_bytes,
        "CliAllowed": true,
        "FolderAllowed": true,
        "FolderMaxCount": null,
        "FolderMaxChildren": null,
        "FolderMaxDepth": 10,
        "CustomFields": true,
        "CreditCardType": true,
        "ItemHistory": true,
        "ItemSharing": true,
        "FolderSharing": false,
        "PublicLinkCreationAllowed": true,
        "AutoTypeAllowed": true,
        "SshAgentAllowed": true,
        "OrganizationPolicies": true,
        "OrganizationActivityLog": false,
        "OrganizationUserReports": false,
        "MonitorInactive2FA": true,
        "MonitorDarkWeb": false,
        "MonitorMaxCustomEmails": 0,
        "MonitorCompromisedPasswords": false,
        "MonitorDeduplication": true,
    })
}

pub async fn access_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let (default_share, mp, ma, _, _) = ensure(state, user_id).await?;
    let (used,): (i64,) = sqlx::query_as("SELECT used_space FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    let emails = super::invites::user_emails(state, user_id).await?;
    let mut pending = 0;
    for e in &emails {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invites WHERE invitee_email = $1")
            .bind(e)
            .fetch_one(&state.db)
            .await?;
        pending += n;
    }
    let (waiting,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM new_user_invites n JOIN shares s ON s.vault_id = n.vault_id \
         WHERE s.user_id = $1 AND s.deleted = 0 AND s.share_role_id = '1' AND n.state = 2",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(json!({
        "Plan": plan_json(state, used),
        "Monitor": { "ProtonAddress": mp != 0, "Aliases": ma != 0 },
        "PendingInvites": pending,
        "WaitingNewUserInvites": waiting,
        "MinVersionUpgrade": null,
        "UserData": { "DefaultShareID": default_share, "AliasSyncEnabled": false, "PendingAliasToSync": 0 },
    }))
}

pub async fn access(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Access": access_json(&state, &user.user_id).await? }),
    ))
}

pub async fn access_check(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let (_, _, _, _, activation) = ensure(&state, &user.user_id).await?;
    Ok(ok(json!({ "Data": { "ActivationTime": activation } })))
}

pub async fn set_default_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    shares::load(&state, &user.user_id, &share_id).await?;
    ensure(&state, &user.user_id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE pass_user SET default_share_id = $1 WHERE user_id = $2")
        .bind(&share_id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, &user.user_id, kind::REFRESH_USER, None, None).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MonitorReq {
    pub proton_address: Option<bool>,
    pub aliases: Option<bool>,
}

pub async fn set_monitor(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<MonitorReq>,
) -> ApiResult<Json<Value>> {
    let (_, mp, ma, _, _) = ensure(&state, &user.user_id).await?;
    let mp = req.proton_address.map(|v| v as i64).unwrap_or(mp);
    let ma = req.aliases.map(|v| v as i64).unwrap_or(ma);
    sqlx::query(
        "UPDATE pass_user SET monitor_proton = $1, monitor_aliases = $2 WHERE user_id = $3",
    )
    .bind(mp)
    .bind(ma)
    .bind(&user.user_id)
    .execute(&state.db)
    .await?;
    Ok(ok(
        json!({ "Monitor": { "ProtonAddress": mp != 0, "Aliases": ma != 0 } }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NotificationsReq {
    pub in_app_notifications_disabled: bool,
}

pub async fn set_notifications(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<NotificationsReq>,
) -> ApiResult<Json<Value>> {
    ensure(&state, &user.user_id).await?;
    sqlx::query("UPDATE pass_user SET inapp_notifications_disabled = $1 WHERE user_id = $2")
        .bind(req.in_app_notifications_disabled as i64)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

pub async fn redeem_coupon(_user: AuthUser) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("Coupons"))
}

pub async fn notifications(_user: AuthUser) -> Json<Value> {
    ok(json!({ "Notifications": { "Notifications": [], "Total": 0, "LastID": null } }))
}

pub async fn notification_state(_user: AuthUser, Path(_id): Path<String>) -> Json<Value> {
    ok_empty()
}
