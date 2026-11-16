//! SRP login (`auth/v4/info` + `auth/v4`) and password-scope unlock.

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AuthUser, extract::MaybeSession, sessions, twofa};
use crate::{
    app::AppState,
    error::{ApiError, ApiResult, code},
    srp::Challenge,
    util::{now, ok},
};

/// Credentials row used for SRP.
pub struct SrpUser {
    pub id: String,
    pub name: String,
    pub version: i64,
    pub salt: String,
    pub verifier: String,
}

/// Finds a user by username or by one of their addresses.
pub async fn find_user(state: &AppState, username: &str) -> ApiResult<Option<SrpUser>> {
    let username = username.trim().to_lowercase();
    let row: Option<(String, String, i64, String, String)> = if username.contains('@') {
        sqlx::query_as(
            "SELECT u.id, u.name, u.srp_version, u.srp_salt, u.srp_verifier FROM users u \
             JOIN addresses a ON a.user_id = u.id WHERE a.email = $1",
        )
        .bind(&username)
        .fetch_optional(&state.db)
        .await?
    } else {
        None
    };
    let row = match row {
        Some(r) => Some(r),
        None => {
            let local = username.split('@').next().unwrap_or_default().to_string();
            sqlx::query_as(
                "SELECT id, name, srp_version, srp_salt, srp_verifier FROM users WHERE name = $1",
            )
            .bind(&local)
            .fetch_optional(&state.db)
            .await?
        }
    };
    Ok(row.map(|(id, name, version, salt, verifier)| SrpUser {
        id,
        name,
        version,
        salt,
        verifier,
    }))
}

/// Stores a server challenge and returns its SRPSession id.
pub async fn store_challenge(
    state: &AppState,
    purpose: &str,
    username: &str,
    ch: &Challenge,
) -> ApiResult<String> {
    let id = crate::util::new_token(32);
    sqlx::query(
        "INSERT INTO srp_challenges (id, purpose, username, server_secret, server_ephemeral, created) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(purpose)
    .bind(username)
    .bind(&ch.server_secret)
    .bind(&ch.server_ephemeral)
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(id)
}

/// Consumes (deletes) a challenge; each SRP session allows one attempt.
pub async fn take_challenge(
    state: &AppState,
    id: &str,
    purpose: &str,
) -> ApiResult<(String, Challenge)> {
    let row: Option<(String, String, String, i64)> = sqlx::query_as(
        "SELECT username, server_secret, server_ephemeral, created FROM srp_challenges WHERE id = $1 AND purpose = $2",
    )
    .bind(id)
    .bind(purpose)
    .fetch_optional(&state.db)
    .await?;
    sqlx::query("DELETE FROM srp_challenges WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    let Some((username, server_secret, server_ephemeral, created)) = row else {
        return Err(ApiError::bad_request("Invalid SRP session"));
    };
    if created + 3600 < now() {
        return Err(ApiError::bad_request("SRP session expired"));
    }
    Ok((
        username,
        Challenge {
            server_secret,
            server_ephemeral,
        },
    ))
}

pub fn wrong_password() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        code::PASSWORD_WRONG,
        "Incorrect login credentials. Please try again.",
    )
}

/// Fake-but-stable SRP parameters for unknown users, so the response doesn't
/// reveal whether an account exists.
fn decoy(state: &AppState, username: &str) -> (String, String) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&state.secret).expect("hmac");
    mac.update(username.as_bytes());
    let digest = mac.finalize().into_bytes();
    let salt = STANDARD.encode(&digest[..10]);
    // Verifier: any 256-byte value below the modulus works for the challenge.
    let mut verifier = vec![0u8; 256];
    for (i, b) in verifier.iter_mut().enumerate().take(255) {
        *b = digest[i % 32] ^ (i as u8);
    }
    (salt, STANDARD.encode(verifier))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InfoReq {
    pub username: Option<String>,
}

pub async fn info(
    State(state): State<AppState>,
    Json(req): Json<InfoReq>,
) -> ApiResult<Json<Value>> {
    let username = req.username.unwrap_or_default();
    let user = find_user(&state, &username).await?;
    let (version, salt, verifier, twofa) = match &user {
        Some(u) => (
            u.version,
            u.salt.clone(),
            u.verifier.clone(),
            twofa::info(&state, &u.id).await?,
        ),
        None => {
            let (salt, verifier) = decoy(&state, &username);
            (4, salt, verifier, twofa::empty_info())
        }
    };
    let challenge = state
        .modulus
        .challenge(&verifier)
        .map_err(|e| ApiError::internal(format!("{e:?}")))?;
    let srp_session = store_challenge(&state, "login", &username, &challenge).await?;
    Ok(ok(json!({
        "Version": version,
        "Modulus": state.modulus.signed,
        "ServerEphemeral": challenge.server_ephemeral,
        "Salt": salt,
        "SRPSession": srp_session,
        "2FA": twofa,
        "Username": user.map(|u| u.name).unwrap_or(username),
    })))
}

pub async fn modulus(State(state): State<AppState>) -> Json<Value> {
    ok(json!({ "Modulus": state.modulus.signed, "ModulusID": state.modulus.id }))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthReq {
    pub username: Option<String>,
    pub client_ephemeral: String,
    pub client_proof: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
    pub persistent_cookies: Option<i64>,
    pub two_factor_code: Option<String>,
}

/// Checks an SRP proof for a challenge; returns (user, server proof).
pub async fn verify_srp(
    state: &AppState,
    purpose: &str,
    srp_session: &str,
    client_ephemeral: &str,
    client_proof: &str,
) -> ApiResult<(SrpUser, String)> {
    let (username, challenge) = take_challenge(state, srp_session, purpose).await?;
    let user = find_user(state, &username)
        .await?
        .ok_or_else(wrong_password)?;
    let proof = state
        .modulus
        .verify(&user.verifier, &challenge, client_ephemeral, client_proof)
        .ok_or_else(wrong_password)?;
    Ok((user, proof))
}

pub async fn auth(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuthReq>,
) -> ApiResult<Json<Value>> {
    let (user, server_proof) = verify_srp(
        &state,
        "login",
        &req.srp_session,
        &req.client_ephemeral,
        &req.client_proof,
    )
    .await?;
    let twofa = twofa::info(&state, &user.id).await?;
    let needs_2fa = twofa["Enabled"].as_i64().unwrap_or(0) != 0;
    if needs_2fa {
        if let Some(code) = req.two_factor_code.as_deref() {
            if !twofa::check_totp(&state, &user.id, code).await? {
                return Err(wrong_password());
            }
        }
    }
    let pending = needs_2fa && req.two_factor_code.is_none();
    let client_id = headers
        .get("x-pm-appversion")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split('@').next())
        .unwrap_or("")
        .to_string();
    let created = sessions::create(
        &state,
        Some(&user.id),
        &client_id,
        pending,
        req.persistent_cookies == Some(1),
    )
    .await?;
    Ok(ok(json!({
        "UserID": user.id,
        "UID": created.uid,
        "AccessToken": created.access_token,
        "RefreshToken": created.refresh_token,
        "TokenType": "Bearer",
        "ExpiresIn": state.config.access_token_ttl,
        "ServerProof": server_proof,
        "Scope": created.scopes.join(" "),
        "Scopes": created.scopes,
        "2FA": twofa,
        "PasswordMode": 1,
        "LocalID": 0,
        "EventID": crate::events::latest_id(&state.db, &user.id).await?,
        "TemporaryPassword": 0,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UnlockReq {
    pub client_ephemeral: String,
    pub client_proof: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
}

/// `PUT core/v4/users/unlock`: re-prove the password to get the `password`
/// scope (needed for sensitive operations such as changing keys or 2FA).
pub async fn unlock_password_scope(
    State(state): State<AppState>,
    MaybeSession(session): MaybeSession,
    Json(req): Json<UnlockReq>,
) -> ApiResult<Json<Value>> {
    let user_id = session.user_id.clone().ok_or_else(ApiError::unauthorized)?;
    let (user, server_proof) = verify_srp(
        &state,
        "login",
        &req.srp_session,
        &req.client_ephemeral,
        &req.client_proof,
    )
    .await?;
    if user.id != user_id {
        return Err(wrong_password());
    }
    sqlx::query("UPDATE sessions SET password_scope_until = $1 WHERE uid = $2")
        .bind(now() + 600)
        .bind(&session.uid)
        .execute(&state.db)
        .await?;
    Ok(ok(json!({ "ServerProof": server_proof })))
}

/// Requires the session to have recently re-proven the password.
pub fn require_password_scope(user: &AuthUser) -> ApiResult<()> {
    if user.session.has_password_scope() {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            code::REAUTH_REQUIRED,
            "Password scope required",
        ))
    }
}
