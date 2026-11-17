//! Session lifecycle: creation, refresh, cookies, listing, revocation.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AuthUser, extract::MaybeSession};
use crate::{
    app::AppState,
    error::{ApiError, ApiResult, code},
    util::{new_token, now, ok, ok_empty, sha256_hex},
};

pub const USER_SCOPES: &[&str] = &[
    "full",
    "self",
    "user",
    "loggedin",
    "nondelinquent",
    "verified",
    "settings",
    "keys",
    "pass",
    "parent",
    "organization",
];

pub struct Created {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
}

fn scopes_for(user: bool, pending_2fa: bool) -> Vec<String> {
    if !user {
        vec![]
    } else if pending_2fa {
        vec!["twofactor".into()]
    } else {
        USER_SCOPES.iter().map(|s| s.to_string()).collect()
    }
}

pub async fn create(
    state: &AppState,
    user_id: Option<&str>,
    client_id: &str,
    pending_2fa: bool,
    persistent: bool,
) -> ApiResult<Created> {
    let uid = new_token(32);
    let access_token = new_token(32);
    let refresh_token = new_token(32);
    let scopes = scopes_for(user_id.is_some(), pending_2fa);
    let t = now();
    sqlx::query(
        "INSERT INTO sessions (uid, user_id, access_hash, refresh_hash, scopes, pending_2fa, client_id, persistent, \
         created, access_expires, refresh_expires, last_used) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(&uid)
    .bind(user_id)
    .bind(sha256_hex(&access_token))
    .bind(sha256_hex(&refresh_token))
    .bind(scopes.join(" "))
    .bind(pending_2fa as i64)
    .bind(client_id)
    .bind(persistent as i64)
    .bind(t)
    .bind(t + state.config.access_token_ttl)
    .bind(t + state.config.refresh_token_ttl)
    .bind(t)
    .execute(&state.db)
    .await?;
    Ok(Created {
        uid,
        access_token,
        refresh_token,
        scopes,
    })
}

/// Logs an existing unauthenticated session in, keeping its UID. Web clients
/// create an unauthenticated cookie session first and keep using it after
/// `auth`, so the login has to upgrade that session rather than start a new
/// one.
pub async fn upgrade(
    state: &AppState,
    uid: &str,
    user_id: &str,
    pending_2fa: bool,
    persistent: bool,
) -> ApiResult<Created> {
    let access_token = new_token(32);
    let refresh_token = new_token(32);
    let scopes = scopes_for(true, pending_2fa);
    let t = now();
    sqlx::query(
        "UPDATE sessions SET user_id = $1, access_hash = $2, refresh_hash = $3, scopes = $4, pending_2fa = $5, \
         persistent = $6, access_expires = $7, refresh_expires = $8, last_used = $9 WHERE uid = $10 AND user_id IS NULL",
    )
    .bind(user_id)
    .bind(sha256_hex(&access_token))
    .bind(sha256_hex(&refresh_token))
    .bind(scopes.join(" "))
    .bind(pending_2fa as i64)
    .bind(persistent as i64)
    .bind(t + state.config.access_token_ttl)
    .bind(t + state.config.refresh_token_ttl)
    .bind(t)
    .bind(uid)
    .execute(&state.db)
    .await?;
    Ok(Created {
        uid: uid.to_string(),
        access_token,
        refresh_token,
        scopes,
    })
}

/// Marks a session's 2FA step complete, granting full scopes.
pub async fn complete_2fa(state: &AppState, uid: &str) -> ApiResult<Vec<String>> {
    let scopes = scopes_for(true, false);
    sqlx::query("UPDATE sessions SET pending_2fa = 0, scopes = $1 WHERE uid = $2")
        .bind(scopes.join(" "))
        .bind(uid)
        .execute(&state.db)
        .await?;
    Ok(scopes)
}

pub async fn cleanup(state: &AppState) -> anyhow::Result<()> {
    let t = now();
    sqlx::query("DELETE FROM sessions WHERE refresh_expires < $1")
        .bind(t)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM srp_challenges WHERE created < $1")
        .bind(t - 3600)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM session_forks WHERE expires < $1")
        .bind(t)
        .execute(&state.db)
        .await?;
    Ok(())
}

fn refresh_invalid() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        code::REFRESH_TOKEN_INVALID,
        "Invalid refresh token",
    )
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RefreshReq {
    #[serde(rename = "UID")]
    pub uid: Option<String>,
    pub refresh_token: Option<String>,
    pub persistent: Option<i64>,
    pub state: Option<String>,
}

/// Rotates the tokens of a session given its refresh token.
async fn rotate(
    state: &AppState,
    uid: &str,
    refresh_token: &str,
) -> ApiResult<(String, String, Vec<String>)> {
    let row: Option<(String, String, i64)> =
        sqlx::query_as("SELECT refresh_hash, scopes, refresh_expires FROM sessions WHERE uid = $1")
            .bind(uid)
            .fetch_optional(&state.db)
            .await?;
    let Some((refresh_hash, scopes, refresh_expires)) = row else {
        return Err(refresh_invalid());
    };
    if refresh_hash != sha256_hex(refresh_token) || refresh_expires < now() {
        return Err(refresh_invalid());
    }
    let access = new_token(32);
    let refresh = new_token(32);
    let t = now();
    sqlx::query(
        "UPDATE sessions SET access_hash = $1, refresh_hash = $2, access_expires = $3, refresh_expires = $4, last_used = $5 \
         WHERE uid = $6",
    )
    .bind(sha256_hex(&access))
    .bind(sha256_hex(&refresh))
    .bind(t + state.config.access_token_ttl)
    .bind(t + state.config.refresh_token_ttl)
    .bind(t)
    .bind(uid)
    .execute(&state.db)
    .await?;
    Ok((
        access,
        refresh,
        scopes.split_whitespace().map(String::from).collect(),
    ))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn cookie_from(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all("cookie") {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=')
                && k == name
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

pub fn auth_cookies(
    state: &AppState,
    uid: &str,
    access: &str,
    refresh: &str,
    persistent: bool,
) -> Vec<HeaderValue> {
    let secure = if state.config.public_url.starts_with("https") {
        "; Secure; SameSite=None"
    } else {
        "; SameSite=Lax"
    };
    let max_age = if persistent {
        format!("; Max-Age={}", state.config.refresh_token_ttl)
    } else {
        String::new()
    };
    [
        format!("AUTH-{uid}={access}; Path=/; HttpOnly{secure}{max_age}"),
        format!("REFRESH-{uid}={refresh}; Path=/; HttpOnly{secure}{max_age}"),
        format!("Session-Id={uid}; Path=/; HttpOnly{secure}{max_age}"),
    ]
    .into_iter()
    .filter_map(|c| HeaderValue::from_str(&c).ok())
    .collect()
}

/// `POST auth/v4/refresh` / `auth/refresh`: token refresh, either with the
/// refresh token in the body (native clients) or via cookies (web clients).
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Response> {
    let req: RefreshReq = if body.is_empty() {
        RefreshReq::default()
    } else {
        serde_json::from_slice(&body)?
    };
    let uid = req
        .uid
        .clone()
        .or_else(|| header_str(&headers, "x-pm-uid").map(String::from))
        .ok_or_else(refresh_invalid)?;
    let (token, via_cookie) = match req.refresh_token.clone() {
        Some(t) => (t, false),
        None => (
            cookie_from(&headers, &format!("REFRESH-{uid}")).ok_or_else(refresh_invalid)?,
            true,
        ),
    };
    let (access, refresh, scopes) = rotate(&state, &uid, &token).await?;
    let body = ok(json!({
        "UID": uid,
        "AccessToken": access,
        "RefreshToken": refresh,
        "TokenType": "Bearer",
        "ExpiresIn": state.config.access_token_ttl,
        "Scope": scopes.join(" "),
        "Scopes": scopes,
        "RefreshCounter": 1,
    }));
    let mut resp = body.into_response();
    if via_cookie {
        for c in auth_cookies(&state, &uid, &access, &refresh, true) {
            resp.headers_mut().append(SET_COOKIE, c);
        }
    }
    Ok(resp)
}

/// `POST core/v4/auth/cookies`: converts a token session into a cookie session.
pub async fn set_cookies(
    State(state): State<AppState>,
    Json(req): Json<RefreshReq>,
) -> ApiResult<Response> {
    let uid = req.uid.clone().ok_or_else(refresh_invalid)?;
    let token = req.refresh_token.clone().ok_or_else(refresh_invalid)?;
    let (access, refresh, _) = rotate(&state, &uid, &token).await?;
    let persistent = req.persistent == Some(1);
    let mut resp = ok(json!({ "UID": uid, "LocalID": 0, "RefreshCounter": 1, "State": req.state }))
        .into_response();
    for c in auth_cookies(&state, &uid, &access, &refresh, persistent) {
        resp.headers_mut().append(SET_COOKIE, c);
    }
    Ok(resp)
}

pub async fn logout(
    State(state): State<AppState>,
    MaybeSession(session): MaybeSession,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM sessions WHERE uid = $1")
        .bind(&session.uid)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

pub async fn scopes(MaybeSession(session): MaybeSession) -> Json<Value> {
    ok(json!({ "Scopes": session.scopes }))
}

/// `POST auth/v4/sessions`: an unauthenticated session (used before login and
/// to pull session forks).
pub async fn create_unauth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let client_id = header_str(&headers, "x-pm-appversion")
        .and_then(|v| v.split('@').next())
        .unwrap_or("");
    let created = create(&state, None, client_id, false, false).await?;
    Ok(ok(json!({
        "UID": created.uid,
        "AccessToken": created.access_token,
        "RefreshToken": created.refresh_token,
        "TokenType": "Bearer",
        "ExpiresIn": state.config.access_token_ttl,
        "Scopes": created.scopes,
        "Scope": "",
    })))
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT uid, created, client_id FROM sessions WHERE user_id = $1 ORDER BY created DESC",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let sessions: Vec<Value> = rows
        .into_iter()
        .map(|(uid, created, client)| {
            json!({
                "UID": uid,
                "CreateTime": created,
                "ClientID": client,
                "LocalizedClientName": client,
                "MemberID": null,
                "Revocable": (uid != user.uid) as i64,
            })
        })
        .collect();
    Ok(ok(json!({ "Sessions": sessions })))
}

pub async fn revoke_others(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND uid <> $2")
        .bind(&user.user_id)
        .bind(&user.uid)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

pub async fn revoke_one(
    State(state): State<AppState>,
    user: AuthUser,
    Path(uid): Path<String>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND uid = $2")
        .bind(&user.user_id)
        .bind(&uid)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

pub async fn get_local_key(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    let key: Option<(Option<String>,)> =
        sqlx::query_as("SELECT local_key FROM sessions WHERE uid = $1")
            .bind(&user.uid)
            .fetch_optional(&state.db)
            .await?;
    match key.and_then(|k| k.0) {
        Some(k) => Ok(ok(json!({ "Key": k }))),
        None => Err(ApiError::not_found("Local key")),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LocalKeyReq {
    pub key: String,
}

pub async fn set_local_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<LocalKeyReq>,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE sessions SET local_key = $1 WHERE uid = $2")
        .bind(&req.key)
        .bind(&user.uid)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

pub async fn lock_password_scope(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE sessions SET password_scope_until = 0 WHERE uid = $1")
        .bind(&user.uid)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}
