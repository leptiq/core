//! Personal access tokens (PATs), used by the Pass CLI (`pass login --pat`).
//!
//! A PAT is a hidden pseudo-user owned by a real user, with its own keys
//! (locked with a key that only exists in the token string the user copies:
//! `pst_<token>::<base64url key>`). The owner grants it access to vaults or
//! items by sharing keys encrypted to the PAT's address key.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::shares::{self, ROLE_MANAGER, ROLE_READ, ROLE_WRITE, TARGET_ITEM, TARGET_VAULT};
use crate::{
    app::AppState,
    auth::{AuthUser, sessions},
    core::pgp,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, new_token, now, ok, ok_empty, sha256_hex},
};

pub const TOKEN_PREFIX: &str = "pst_";
pub const TOKEN_LEN: usize = 40;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeyPayload {
    pub private_key: String,
    pub token: Option<String>,
    pub signature: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateReq {
    pub name: String,
    pub expiration_time: Option<i64>,
    /// The PAT's user key, locked with the token key.
    pub user_key: KeyPayload,
    /// The PAT's address key (locked via Token or the token key).
    pub address_key: KeyPayload,
    pub key_salt: Option<String>,
}

fn pat_json(
    id: &str,
    name: &str,
    created: i64,
    expire: Option<i64>,
    last_used: Option<i64>,
    address_id: &str,
    email: &str,
) -> Value {
    json!({ "PersonalAccessTokenID": id, "ID": id, "Name": name, "CreateTime": created, "ExpireTime": expire,
            "LastUsedTime": last_used, "AddressID": address_id, "Email": email })
}

/// `POST account/v4/personal-access-token`: create a PAT identity.
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    crate::auth::login::require_password_scope(&user)?;
    let user_info = pgp::inspect_private(&req.user_key.private_key)
        .ok_or_else(|| ApiError::bad_request("Invalid user key"))?;
    let addr_info = pgp::inspect_private(&req.address_key.private_key)
        .ok_or_else(|| ApiError::bad_request("Invalid address key"))?;
    let id = new_id();
    let pat_user = new_id();
    let address_id = new_id();
    let name_tag = new_token(12);
    let email = format!("pat-{name_tag}@pat.{}", state.config.mail_domain);
    let token = format!("{TOKEN_PREFIX}{}", new_token(TOKEN_LEN));
    let t = now();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO users (id, name, display_name, email, srp_version, srp_modulus_id, srp_salt, srp_verifier, pat_owner_id, created) \
         VALUES ($1,$2,$3,$4,0,'','','',$5,$6)",
    )
    .bind(&pat_user)
    .bind(format!("pat-{name_tag}"))
    .bind(&req.name)
    .bind(&email)
    .bind(&user.user_id)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO user_keys (id, user_id, private_key, key_salt, is_primary, fingerprint, created) VALUES ($1,$2,$3,$4,1,$5,$6)",
    )
    .bind(new_id())
    .bind(&pat_user)
    .bind(&req.user_key.private_key)
    .bind(&req.key_salt)
    .bind(&user_info.fingerprint)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO addresses (id, user_id, email, display_name, addr_type, created) VALUES ($1,$2,$3,$4,5,$5)")
        .bind(&address_id)
        .bind(&pat_user)
        .bind(&email)
        .bind(&req.name)
        .bind(t)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO address_keys (id, address_id, user_id, private_key, public_key, token, signature, is_primary, fingerprint, created) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9)",
    )
    .bind(new_id())
    .bind(&address_id)
    .bind(&pat_user)
    .bind(&req.address_key.private_key)
    .bind(&addr_info.public_armored)
    .bind(&req.address_key.token)
    .bind(&req.address_key.signature)
    .bind(&addr_info.fingerprint)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO personal_access_tokens (id, owner_id, pat_user_id, name, token_hash, expire_time, created) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&pat_user)
    .bind(&req.name)
    .bind(sha256_hex(&token))
    .bind(req.expiration_time)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut out = pat_json(
        &id,
        &req.name,
        t,
        req.expiration_time,
        None,
        &address_id,
        &email,
    );
    out["Token"] = json!(token);
    Ok(ok(json!({ "PersonalAccessToken": out })))
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, i64, Option<i64>, Option<i64>, String, String)> = sqlx::query_as(
        "SELECT p.id, p.name, p.created, p.expire_time, p.last_used, a.id, a.email FROM personal_access_tokens p \
         JOIN addresses a ON a.user_id = p.pat_user_id WHERE p.owner_id = $1 ORDER BY p.created",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let tokens: Vec<Value> = rows
        .iter()
        .map(|(id, n, c, e, l, a, m)| pat_json(id, n, *c, *e, *l, a, m))
        .collect();
    Ok(ok(
        json!({ "PersonalAccessTokens": tokens, "Total": tokens.len() }),
    ))
}

async fn owned_pat(state: &AppState, owner: &str, id: &str) -> ApiResult<(String, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT p.pat_user_id, a.id FROM personal_access_tokens p JOIN addresses a ON a.user_id = p.pat_user_id \
         WHERE p.id = $1 AND p.owner_id = $2",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(&state.db)
    .await?;
    row.ok_or_else(|| ApiError::not_found("Personal access token"))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let (pat_user, _) = owned_pat(&state, &user.user_id, &id).await?;
    // Removing the pseudo-user cascades to its shares, keys and sessions.
    let mut tx = state.db.begin().await?;
    let pat_shares: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM shares WHERE user_id = $1 AND deleted = 0")
            .bind(&pat_user)
            .fetch_all(&mut *tx)
            .await?;
    for (sid,) in pat_shares {
        let s = shares::load_any(&mut tx, &sid).await?;
        shares::remove_share(&mut tx, &s).await?;
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&pat_user)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SessionReq {
    pub token: String,
}

/// `POST account/v4/personal-access-token/session`: log in with a PAT.
pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SessionReq>,
) -> ApiResult<Json<Value>> {
    let token = req.token.split("::").next().unwrap_or_default();
    let row: Option<(String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, pat_user_id, expire_time FROM personal_access_tokens WHERE token_hash = $1",
    )
    .bind(sha256_hex(token))
    .fetch_optional(&state.db)
    .await?;
    let Some((id, pat_user, expire)) = row else {
        return Err(ApiError::unauthorized());
    };
    if expire.map(|e| e < now()).unwrap_or(false) {
        return Err(ApiError::unauthorized());
    }
    sqlx::query("UPDATE personal_access_tokens SET last_used = $1 WHERE id = $2")
        .bind(now())
        .bind(&id)
        .execute(&state.db)
        .await?;
    let client = headers
        .get("x-pm-appversion")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split('@').next())
        .unwrap_or("pat");
    let created = sessions::create(&state, Some(&pat_user), client, false, false).await?;
    let t = now();
    Ok(ok(json!({ "Session": {
        "SessionUID": created.uid,
        "UID": created.uid,
        "UserID": pat_user,
        "AccessToken": created.access_token,
        "RefreshToken": created.refresh_token,
        "AccessExpirationTime": t + state.config.access_token_ttl,
        "RefreshExpirationTime": t + state.config.refresh_token_ttl,
        "Scopes": created.scopes,
    }})))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GrantReq {
    #[serde(rename = "ShareID")]
    pub share_id: String,
    #[serde(rename = "TargetID")]
    pub target_id: Option<String>,
    pub target_type: i64,
    #[serde(rename = "ShareRoleID")]
    pub share_role_id: String,
    pub keys: Vec<super::invites::KeyPair>,
}

/// `POST pass/v1/personal-access-token/{id}/access`: share a vault/item with a PAT.
pub async fn grant(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<GrantReq>,
) -> ApiResult<Json<Value>> {
    let (pat_user, address_id) = owned_pat(&state, &user.user_id, &id).await?;
    let share = shares::load(&state, &user.user_id, &req.share_id).await?;
    share.require_manage()?;
    if ![ROLE_MANAGER, ROLE_WRITE, ROLE_READ].contains(&req.share_role_id.as_str())
        || req.keys.is_empty()
    {
        return Err(ApiError::bad_request("Invalid role or keys"));
    }
    let mut tx = state.db.begin().await?;
    let (tt, tid) = match req.target_type {
        TARGET_VAULT if share.is_vault() => (TARGET_VAULT, share.vault_id.clone()),
        TARGET_ITEM => {
            let item_id = req
                .target_id
                .clone()
                .ok_or_else(|| ApiError::bad_request("TargetID required"))?;
            super::items::load(&mut tx, &share, &item_id).await?;
            (TARGET_ITEM, item_id)
        }
        _ => return Err(ApiError::bad_request("Invalid target")),
    };
    // Replace an existing grant on the same target.
    let existing: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM shares WHERE user_id = $1 AND vault_id = $2 AND target_id = $3 AND deleted = 0")
            .bind(&pat_user)
            .bind(&share.vault_id)
            .bind(&tid)
            .fetch_all(&mut *tx)
            .await?;
    for (sid,) in existing {
        let s = shares::load_any(&mut tx, &sid).await?;
        shares::remove_share(&mut tx, &s).await?;
    }
    let user_key = shares::primary_user_key(&mut tx, &pat_user).await?;
    let new_share = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO shares (id, vault_id, user_id, address_id, target_type, target_id, share_role_id, owner, is_primary, created) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,0,0,$8)",
    )
    .bind(&new_share)
    .bind(&share.vault_id)
    .bind(&pat_user)
    .bind(&address_id)
    .bind(tt)
    .bind(&tid)
    .bind(&req.share_role_id)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    for k in &req.keys {
        sqlx::query("INSERT INTO share_keys (share_id, key_rotation, key, user_key_id, created) VALUES ($1,$2,$3,$4,$5)")
            .bind(&new_share)
            .bind(k.key_rotation)
            .bind(&k.key)
            .bind(&user_key)
            .bind(t)
            .execute(&mut *tx)
            .await?;
    }
    events::push(
        &mut tx,
        &pat_user,
        kind::SHARE_CREATED,
        Some(&new_share),
        None,
    )
    .await?;
    events::push_vault(&mut tx, &share.vault_id, kind::SHARE_UPDATED, None).await?;
    let s = shares::load_any(&mut tx, &new_share).await?;
    let out = shares::share_json_conn(&mut tx, &s).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Share": out })))
}

/// `DELETE pass/v1/personal-access-token/{id}/access/{shareId}`. Accepts the
/// PAT's share ID or the owner's share ID of the vault.
pub async fn revoke(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, share_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (pat_user, _) = owned_pat(&state, &user.user_id, &id).await?;
    let own_vault = shares::load(&state, &user.user_id, &share_id)
        .await
        .ok()
        .map(|s| s.vault_id);
    let mut tx = state.db.begin().await?;
    let mut targets: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM shares WHERE id = $1 AND user_id = $2 AND deleted = 0")
            .bind(&share_id)
            .bind(&pat_user)
            .fetch_all(&mut *tx)
            .await?;
    if targets.is_empty() {
        if let Some(vault_id) = &own_vault {
            targets = sqlx::query_as(
                "SELECT id FROM shares WHERE vault_id = $1 AND user_id = $2 AND deleted = 0",
            )
            .bind(vault_id)
            .bind(&pat_user)
            .fetch_all(&mut *tx)
            .await?;
        }
    }
    for (sid,) in targets {
        let s = shares::load_any(&mut tx, &sid).await?;
        shares::remove_share(&mut tx, &s).await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MonitorRecord {
    #[serde(rename = "VaultID")]
    pub vault_id: String,
    #[serde(rename = "ObjectID")]
    pub object_id: Option<String>,
    pub action: i64,
    pub payload: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MonitorReq {
    pub records: Vec<MonitorRecord>,
}

/// `POST pat/monitor`: a PAT session records what it did (audit log).
pub async fn monitor_store(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<MonitorReq>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    for r in req.records.iter().take(500) {
        let id = crate::db::next_counter(&mut tx, "pat_monitor").await?;
        sqlx::query(
            "INSERT INTO pat_monitor (id, pat_user_id, vault_id, object_id, action, payload, created) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id)
        .bind(&user.user_id)
        .bind(&r.vault_id)
        .bind(&r.object_id)
        .bind(r.action)
        .bind(&r.payload)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MonitorQuery {
    pub since: Option<i64>,
}

/// `GET pat/monitor/{patId}`: the owner reads a PAT's audit log.
pub async fn monitor_list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<MonitorQuery>,
) -> ApiResult<Json<Value>> {
    let (pat_user, _) = owned_pat(&state, &user.user_id, &id).await?;
    let rows: Vec<(i64, String, Option<String>, i64, String, i64)> = sqlx::query_as(
        "SELECT id, vault_id, object_id, action, payload, created FROM pat_monitor WHERE pat_user_id = $1 AND id > $2 \
         ORDER BY id LIMIT 101",
    )
    .bind(&pat_user)
    .bind(q.since.unwrap_or(0))
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() > 100;
    let records: Vec<Value> = rows
        .iter()
        .take(100)
        .map(|(id, v, o, a, p, c)| json!({ "ID": id, "VaultID": v, "ObjectID": o, "Action": a, "Payload": p, "CreateTime": c }))
        .collect();
    let next = if more {
        rows.get(99).map(|r| r.0.to_string())
    } else {
        None
    };
    Ok(ok(
        json!({ "Actions": { "Records": records, "NextSince": next } }),
    ))
}
