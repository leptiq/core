//! Sharing invites: to existing users (keys encrypted to their address key)
//! and to emails without an account yet ("new user invites").

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::shares::{self, ROLE_MANAGER, ROLE_READ, ROLE_WRITE, Share, TARGET_ITEM, TARGET_VAULT};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, now, ok, ok_empty},
};

pub const NEW_USER_WAITING: i64 = 1;
pub const NEW_USER_READY: i64 = 2;

/// All email addresses a user owns (lowercase).
pub async fn user_emails(state: &AppState, user_id: &str) -> ApiResult<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT email FROM addresses WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct KeyPair {
    pub key_rotation: i64,
    pub key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateReq {
    pub keys: Vec<KeyPair>,
    pub email: String,
    pub target_type: i64,
    #[serde(rename = "ShareRoleID")]
    pub share_role_id: String,
    #[serde(rename = "SourceNewUserInviteID")]
    pub source_new_user_invite_id: Option<String>,
    #[serde(rename = "ItemID")]
    pub item_id: Option<String>,
    pub expiration_time: Option<i64>,
}

fn valid_role(role: &str) -> ApiResult<()> {
    if [ROLE_MANAGER, ROLE_WRITE, ROLE_READ].contains(&role) {
        Ok(())
    } else {
        Err(ApiError::bad_request("Invalid share role"))
    }
}

/// Resolves the invite target: (target_type, target_id).
async fn target(
    conn: &mut AnyConnection,
    share: &Share,
    target_type: i64,
    item_id: Option<&str>,
) -> ApiResult<(i64, String)> {
    match target_type {
        TARGET_VAULT if share.is_vault() => Ok((TARGET_VAULT, share.vault_id.clone())),
        TARGET_ITEM => {
            let item_id = item_id.ok_or_else(|| ApiError::bad_request("ItemID required"))?;
            super::items::load(conn, share, item_id).await?;
            Ok((TARGET_ITEM, item_id.to_string()))
        }
        _ => Err(ApiError::bad_request("Invalid target type")),
    }
}

async fn inviter_email(conn: &mut AnyConnection, share: &Share) -> ApiResult<String> {
    let (email,): (String,) = sqlx::query_as("SELECT email FROM addresses WHERE id = $1")
        .bind(&share.address_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(email)
}

async fn create_one(conn: &mut AnyConnection, share: &Share, req: &CreateReq) -> ApiResult<String> {
    valid_role(&req.share_role_id)?;
    if req.keys.is_empty() {
        return Err(ApiError::bad_request("Keys required"));
    }
    let (tt, tid) = target(conn, share, req.target_type, req.item_id.as_deref()).await?;
    let email = req.email.trim().to_lowercase();
    let invitee: Option<(String,)> =
        sqlx::query_as("SELECT user_id FROM addresses WHERE email = $1")
            .bind(&email)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((invitee_user,)) = invitee else {
        return Err(ApiError::bad_request(
            "No account with this address; use a new user invite",
        ));
    };
    let already: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM shares WHERE vault_id = $1 AND user_id = $2 AND deleted = 0 AND (target_type = 1 OR target_id = $3)",
    )
    .bind(&share.vault_id)
    .bind(&invitee_user)
    .bind(&tid)
    .fetch_optional(&mut *conn)
    .await?;
    if already.is_some() {
        return Err(ApiError::conflict("User already has access"));
    }
    sqlx::query(
        "DELETE FROM invites WHERE vault_id = $1 AND target_id = $2 AND invitee_email = $3",
    )
    .bind(&share.vault_id)
    .bind(&tid)
    .bind(&email)
    .execute(&mut *conn)
    .await?;
    let id = new_id();
    let t = now();
    let from_new_user = req.source_new_user_invite_id.is_some();
    sqlx::query(
        "INSERT INTO invites (id, vault_id, inviter_share_id, inviter_user_id, inviter_email, invitee_email, invitee_user_id, \
         target_type, target_id, share_role_id, keys, from_new_user, expiration_time, created, modified) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)",
    )
    .bind(&id)
    .bind(&share.vault_id)
    .bind(&share.id)
    .bind(&share.user_id)
    .bind(inviter_email(conn, share).await?)
    .bind(&email)
    .bind(&invitee_user)
    .bind(tt)
    .bind(&tid)
    .bind(&req.share_role_id)
    .bind(serde_json::to_string(&req.keys)?)
    .bind(from_new_user as i64)
    .bind(req.expiration_time)
    .bind(t)
    .execute(&mut *conn)
    .await?;
    if let Some(src) = &req.source_new_user_invite_id {
        sqlx::query("DELETE FROM new_user_invites WHERE id = $1 AND vault_id = $2")
            .bind(src)
            .bind(&share.vault_id)
            .execute(&mut *conn)
            .await?;
    }
    events::push(conn, &invitee_user, kind::INVITES, None, Some(&id)).await?;
    events::push_vault(conn, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    Ok(id)
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    create_one(&mut tx, &share, &req).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BatchReq {
    pub invites: Vec<CreateReq>,
}

pub async fn create_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<BatchReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    for i in &req.invites {
        create_one(&mut tx, &share, i).await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CheckReq {
    pub emails: Vec<String>,
}

/// No organization restrictions on a self-hosted server: all emails allowed.
pub async fn check_address(
    user: AuthUser,
    Path(_s): Path<String>,
    Json(req): Json<CheckReq>,
) -> Json<Value> {
    let _ = user;
    ok(json!({ "Emails": req.emails }))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NewUserReq {
    pub email: String,
    pub target_type: i64,
    pub signature: String,
    #[serde(rename = "ShareRoleID")]
    pub share_role_id: String,
    #[serde(rename = "ItemID")]
    pub item_id: Option<String>,
    pub expiration_time: Option<i64>,
}

async fn create_new_user(
    conn: &mut AnyConnection,
    share: &Share,
    req: &NewUserReq,
) -> ApiResult<()> {
    valid_role(&req.share_role_id)?;
    let (tt, tid) = target(conn, share, req.target_type, req.item_id.as_deref()).await?;
    let email = req.email.trim().to_lowercase();
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM addresses WHERE email = $1")
        .bind(&email)
        .fetch_optional(&mut *conn)
        .await?;
    let t = now();
    sqlx::query(
        "INSERT INTO new_user_invites (id, vault_id, inviter_share_id, inviter_user_id, inviter_email, invitee_email, target_type, \
         target_id, share_role_id, signature, state, expiration_time, created, modified) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)",
    )
    .bind(new_id())
    .bind(&share.vault_id)
    .bind(&share.id)
    .bind(&share.user_id)
    .bind(inviter_email(conn, share).await?)
    .bind(&email)
    .bind(tt)
    .bind(&tid)
    .bind(&req.share_role_id)
    .bind(&req.signature)
    .bind(if exists.is_some() { NEW_USER_READY } else { NEW_USER_WAITING })
    .bind(req.expiration_time)
    .bind(t)
    .execute(&mut *conn)
    .await?;
    events::push_vault(conn, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    Ok(())
}

pub async fn create_new_user_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<NewUserReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    create_new_user(&mut tx, &share, &req).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NewUserBatchReq {
    pub new_user_invites: Vec<NewUserReq>,
}

pub async fn create_new_user_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<NewUserBatchReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    for r in &req.new_user_invites {
        create_new_user(&mut tx, &share, r).await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

/// Called when an address is created: pending new-user invites for that email
/// become ready, and the vault managers are told to send the real invite.
pub async fn on_address_created(conn: &mut AnyConnection, email: &str) -> ApiResult<()> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, vault_id FROM new_user_invites WHERE invitee_email = $1 AND state = $2",
    )
    .bind(email)
    .bind(NEW_USER_WAITING)
    .fetch_all(&mut *conn)
    .await?;
    for (id, vault_id) in rows {
        sqlx::query("UPDATE new_user_invites SET state = $1, modified = $2 WHERE id = $3")
            .bind(NEW_USER_READY)
            .bind(now())
            .bind(&id)
            .execute(&mut *conn)
            .await?;
        let managers: Vec<(String, String)> = sqlx::query_as(
            "SELECT user_id, id FROM shares WHERE vault_id = $1 AND deleted = 0 AND target_type = 1 AND share_role_id = '1'",
        )
        .bind(&vault_id)
        .fetch_all(&mut *conn)
        .await?;
        for (uid, sid) in managers {
            events::push_data(
                conn,
                &uid,
                kind::SHARE_UPDATED,
                Some(&sid),
                None,
                Some("invites_ready"),
            )
            .await?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PromoteReq {
    pub keys: Vec<KeyPair>,
}

/// `POST share/{}/invite/new_user/{id}/keys`: the new user exists now; turn
/// the placeholder into a real invite with keys encrypted to their address.
pub async fn promote_new_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, invite_id)): Path<(String, String)>,
    Json(req): Json<PromoteReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    let row: Option<(String, i64, String, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT invitee_email, target_type, target_id, share_role_id, state, expiration_time FROM new_user_invites \
         WHERE id = $1 AND vault_id = $2",
    )
    .bind(&invite_id)
    .bind(&share.vault_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, tt, tid, role, st, exp)) = row else {
        return Err(ApiError::not_found("Invite"));
    };
    if st != NEW_USER_READY {
        return Err(ApiError::bad_request(
            "The invited user has not signed up yet",
        ));
    }
    let create = CreateReq {
        keys: req.keys,
        email,
        target_type: tt,
        share_role_id: role,
        source_new_user_invite_id: Some(invite_id),
        item_id: if tt == TARGET_ITEM { Some(tid) } else { None },
        expiration_time: exp,
    };
    create_one(&mut tx, &share, &create).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

pub async fn delete_new_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, invite_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM new_user_invites WHERE id = $1 AND vault_id = $2")
        .bind(&invite_id)
        .bind(&share.vault_id)
        .execute(&mut *tx)
        .await?;
    events::push_vault(&mut tx, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

/// `GET share/{id}/invite`: pending invites for this vault/item.
pub async fn list_for_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let filter = if share.is_vault() {
        ""
    } else {
        " AND target_id = $2"
    };
    let invites: Vec<(String, String, String, String, i64, String, i64, i64, i64)> = sqlx::query_as(crate::sql!(
        "SELECT id, invitee_email, inviter_email, share_role_id, target_type, target_id, reminders_sent, created, modified \
         FROM invites WHERE vault_id = $1{filter} ORDER BY created"
    ))
    .bind(&share.vault_id)
    .bind(&share.target_id)
    .fetch_all(&state.db)
    .await?;
    let new_users: Vec<(String, i64, i64, String, String, String, String, String, i64, i64)> = sqlx::query_as(crate::sql!(
        "SELECT id, state, target_type, target_id, share_role_id, invitee_email, inviter_email, signature, created, modified \
         FROM new_user_invites WHERE vault_id = $1{filter} ORDER BY created"
    ))
    .bind(&share.vault_id)
    .bind(&share.target_id)
    .fetch_all(&state.db)
    .await?;
    let invites: Vec<Value> = invites
        .into_iter()
        .map(|(id, invited, inviter, role, tt, tid, rem, c, m)| {
            json!({ "InviteID": id, "InvitedEmail": invited, "InviterEmail": inviter, "ShareRoleID": role,
                    "TargetType": tt, "TargetID": tid, "RemindersSent": rem, "CreateTime": c, "ModifyTime": m })
        })
        .collect();
    let new_users: Vec<Value> = new_users
        .into_iter()
        .map(|(id, st, tt, tid, role, invited, inviter, sig, c, m)| {
            json!({ "NewUserInviteID": id, "State": st, "TargetType": tt, "TargetID": tid, "ShareRoleID": role,
                    "InvitedEmail": invited, "InviterEmail": inviter, "Signature": sig, "CreateTime": c, "ModifyTime": m })
        })
        .collect();
    Ok(ok(
        json!({ "Invites": invites, "NewUserInvites": new_users }),
    ))
}

pub async fn delete_for_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, invite_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let mut tx = state.db.begin().await?;
    let invitee: Option<(Option<String>,)> =
        sqlx::query_as("SELECT invitee_user_id FROM invites WHERE id = $1 AND vault_id = $2")
            .bind(&invite_id)
            .bind(&share.vault_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((invitee,)) = invitee else {
        return Err(ApiError::not_found("Invite"));
    };
    sqlx::query("DELETE FROM invites WHERE id = $1")
        .bind(&invite_id)
        .execute(&mut *tx)
        .await?;
    if let Some(u) = invitee {
        events::push(&mut tx, &u, kind::INVITES, None, Some(&invite_id)).await?;
    }
    events::push_vault(&mut tx, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

pub async fn reminder(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, invite_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_manage()?;
    let res = sqlx::query("UPDATE invites SET reminders_sent = reminders_sent + 1, modified = $1 WHERE id = $2 AND vault_id = $3")
        .bind(now())
        .bind(&invite_id)
        .bind(&share.vault_id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Invite"));
    }
    Ok(ok_empty())
}

/// Emails of people this user already shares with (for the invite UI).
pub async fn recommended(
    State(state): State<AppState>,
    user: AuthUser,
    Path(_s): Path<String>,
) -> ApiResult<Json<Value>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT a.email FROM shares mine JOIN shares other ON other.vault_id = mine.vault_id AND other.deleted = 0 \
         JOIN addresses a ON a.id = other.address_id WHERE mine.user_id = $1 AND mine.deleted = 0 AND other.user_id <> $1 LIMIT 50",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let emails: Vec<String> = rows.into_iter().map(|r| r.0).collect();
    Ok(ok(json!({ "Recommendation": {
        "RecommendedEmails": emails, "PlanInternalName": "", "GroupDisplayName": "",
        "PlanRecommendedEmails": [], "PlanRecommendedEmailsNextToken": "",
    }})))
}

pub async fn recommended_org(_user: AuthUser, Path(_s): Path<String>) -> Json<Value> {
    ok(
        json!({ "Recommendation": { "Entries": [], "Total": 0, "LastToken": null, "GroupDisplayName": "" } }),
    )
}

pub async fn recommended_suggested(_user: AuthUser, Path(_s): Path<String>) -> Json<Value> {
    ok(json!({ "Suggested": [], "Total": 0 }))
}

/// `GET invite`: invites addressed to the current user.
pub async fn list_mine(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, i64, String, String, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT i.id, i.vault_id, i.target_type, i.target_id, i.inviter_email, i.invitee_email, a.id, i.keys, i.from_new_user, i.created \
         FROM invites i JOIN addresses a ON a.email = i.invitee_email WHERE a.user_id = $1 \
         AND (i.expiration_time IS NULL OR i.expiration_time > $2) ORDER BY i.created",
    )
    .bind(&user.user_id)
    .bind(now())
    .fetch_all(&state.db)
    .await?;
    let mut out = vec![];
    for (id, vault_id, tt, tid, inviter, invited, addr_id, keys, from_new, created) in rows {
        let (rem,): (i64,) = sqlx::query_as("SELECT reminders_sent FROM invites WHERE id = $1")
            .bind(&id)
            .fetch_one(&state.db)
            .await?;
        let vault_data = if tt == TARGET_VAULT {
            let (content, ckr, cfv): (String, i64, i64) = sqlx::query_as(
                "SELECT content, content_key_rotation, content_format_version FROM vaults WHERE id = $1",
            )
            .bind(&vault_id)
            .fetch_one(&state.db)
            .await?;
            let (members,): (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM shares WHERE vault_id = $1 AND deleted = 0")
                    .bind(&vault_id)
                    .fetch_one(&state.db)
                    .await?;
            let (items,): (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM items WHERE vault_id = $1 AND state = 1")
                    .bind(&vault_id)
                    .fetch_one(&state.db)
                    .await?;
            json!({ "Content": content, "ContentKeyRotation": ckr, "ContentFormatVersion": cfv,
                    "MemberCount": members, "ItemCount": items })
        } else {
            Value::Null
        };
        out.push(json!({
            "InviteToken": id,
            "RemindersSent": rem,
            "TargetType": tt,
            "TargetID": tid,
            "InviterEmail": inviter,
            "InvitedEmail": invited,
            "InvitedAddressID": addr_id,
            "Keys": serde_json::from_str::<Value>(&keys)?,
            "VaultData": vault_data,
            "Data": null,
            "FromNewUser": from_new != 0,
            "CreateTime": created,
        }));
    }
    Ok(ok(json!({ "Invites": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AcceptReq {
    pub keys: Vec<KeyPair>,
}

/// `POST invite/{token}`: accept; keys are re-encrypted to the user key.
pub async fn accept(
    State(state): State<AppState>,
    user: AuthUser,
    Path(token): Path<String>,
    Json(req): Json<AcceptReq>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let row: Option<(String, String, i64, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT i.vault_id, i.invitee_email, i.target_type, i.target_id, i.share_role_id, i.expiration_time FROM invites i \
         JOIN addresses a ON a.email = i.invitee_email WHERE i.id = $1 AND a.user_id = $2",
    )
    .bind(&token)
    .bind(&user.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((vault_id, email, tt, tid, role, exp)) = row else {
        return Err(ApiError::not_found("Invite"));
    };
    if req.keys.is_empty() {
        return Err(ApiError::bad_request("Keys required"));
    }
    let (address_id,): (String,) = sqlx::query_as("SELECT id FROM addresses WHERE email = $1")
        .bind(&email)
        .fetch_one(&mut *tx)
        .await?;
    let user_key = shares::primary_user_key(&mut tx, &user.user_id).await?;
    let share_id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO shares (id, vault_id, user_id, address_id, target_type, target_id, share_role_id, owner, is_primary, \
         expire_time, created) VALUES ($1,$2,$3,$4,$5,$6,$7,0,0,$8,$9)",
    )
    .bind(&share_id)
    .bind(&vault_id)
    .bind(&user.user_id)
    .bind(&address_id)
    .bind(tt)
    .bind(&tid)
    .bind(&role)
    .bind(exp)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    for k in &req.keys {
        sqlx::query("INSERT INTO share_keys (share_id, key_rotation, key, user_key_id, created) VALUES ($1,$2,$3,$4,$5)")
            .bind(&share_id)
            .bind(k.key_rotation)
            .bind(&k.key)
            .bind(&user_key)
            .bind(t)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM invites WHERE id = $1")
        .bind(&token)
        .execute(&mut *tx)
        .await?;
    events::push(
        &mut tx,
        &user.user_id,
        kind::SHARE_CREATED,
        Some(&share_id),
        None,
    )
    .await?;
    events::push(&mut tx, &user.user_id, kind::INVITES, None, Some(&token)).await?;
    events::push_vault(&mut tx, &vault_id, kind::SHARE_UPDATED, None).await?;
    let share = shares::load_any(&mut tx, &share_id).await?;
    let out = shares::share_json_conn(&mut tx, &share).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Share": out })))
}

pub async fn reject(
    State(state): State<AppState>,
    user: AuthUser,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT i.vault_id FROM invites i JOIN addresses a ON a.email = i.invitee_email WHERE i.id = $1 AND a.user_id = $2",
    )
    .bind(&token)
    .bind(&user.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((vault_id,)) = row else {
        return Err(ApiError::not_found("Invite"));
    };
    sqlx::query("DELETE FROM invites WHERE id = $1")
        .bind(&token)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, &user.user_id, kind::INVITES, None, Some(&token)).await?;
    events::push_vault(&mut tx, &vault_id, kind::SHARE_UPDATED, None).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

/// Group invites (organization groups) are not supported: always empty.
pub async fn group_invites(_user: AuthUser) -> Json<Value> {
    ok(json!({ "Invites": { "Invites": [], "Total": 0 } }))
}
