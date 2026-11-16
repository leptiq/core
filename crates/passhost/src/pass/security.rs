//! Pass session PIN lock and the optional Pass "extra password" (a second
//! SRP verifier that must be proven before Pass data is accessible).

use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    app::AppState,
    auth::{AuthUser, extract::MaybeSession, login},
    error::{ApiError, ApiResult, code},
    util::{new_token, now, ok, ok_empty, sha256_hex},
};

/// Wrong PIN attempts before the session is revoked.
pub const MAX_LOCK_ATTEMPTS: i64 = 3;

fn locked_error() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        code::SESSION_LOCKED,
        "Session locked",
    )
}

/// Whether the session is locked, either explicitly or by inactivity.
async fn is_locked(state: &AppState, uid: &str) -> ApiResult<bool> {
    let row: Option<(i64, i64, i64)> = sqlx::query_as(
        "SELECT locked, unlocked_secs, last_activity FROM session_locks WHERE uid = $1",
    )
    .bind(uid)
    .fetch_optional(&state.db)
    .await?;
    Ok(match row {
        None => false,
        Some((locked, secs, last)) => locked != 0 || (secs > 0 && last + secs < now()),
    })
}

async fn touch(state: &AppState, uid: &str) -> ApiResult<()> {
    sqlx::query("UPDATE session_locks SET last_activity = $1 WHERE uid = $2")
        .bind(now())
        .bind(uid)
        .execute(&state.db)
        .await?;
    Ok(())
}

async fn needs_extra_password(state: &AppState, user_id: &str, uid: &str) -> ApiResult<bool> {
    let has: Option<(String,)> = sqlx::query_as("SELECT user_id FROM pass_srp WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    if has.is_none() {
        return Ok(false);
    }
    let unlocked: Option<(i64,)> =
        sqlx::query_as("SELECT unlocked FROM pass_unlocked_sessions WHERE uid = $1")
            .bind(uid)
            .fetch_optional(&state.db)
            .await?;
    Ok(unlocked.is_none())
}

/// Middleware for `pass/v1`: enforces the extra password and the PIN lock.
pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let exempt_lock = path.contains("/user/session/lock") || path.contains("/public_link/");
    let exempt_srp = path.contains("/user/srp") || exempt_lock;
    let (mut parts, body) = req.into_parts();
    let session =
        match <MaybeSession as axum::extract::FromRequestParts<AppState>>::from_request_parts(
            &mut parts, &state,
        )
        .await
        {
            Ok(MaybeSession(s)) => Some(s),
            Err(_) => None,
        };
    if let Some(s) = &session
        && let Some(user_id) = &s.user_id
    {
        if !exempt_srp {
            match needs_extra_password(&state, user_id, &s.uid).await {
                Ok(true) => {
                    return ApiError::new(
                        StatusCode::FORBIDDEN,
                        code::MISSING_SCOPE,
                        "Extra password required",
                    )
                    .into_response();
                }
                Ok(false) => {}
                Err(e) => return e.into_response(),
            }
        }
        if !exempt_lock {
            match is_locked(&state, &s.uid).await {
                Ok(true) => return locked_error().into_response(),
                Ok(false) => {
                    if let Err(e) = touch(&state, &s.uid).await {
                        return e.into_response();
                    }
                }
                Err(e) => return e.into_response(),
            }
        }
    }
    next.run(Request::from_parts(parts, body)).await
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LockReq {
    pub lock_code: String,
    pub unlocked_secs: Option<i64>,
}

/// `POST user/session/lock`: register a PIN for this session.
pub async fn create_lock(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<LockReq>,
) -> ApiResult<Json<Value>> {
    let token = new_token(64);
    sqlx::query("DELETE FROM session_locks WHERE uid = $1")
        .bind(&user.uid)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO session_locks (uid, user_id, lock_code_hash, storage_token, unlocked_secs, last_activity) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&user.uid)
    .bind(&user.user_id)
    .bind(sha256_hex(&req.lock_code))
    .bind(&token)
    .bind(req.unlocked_secs.unwrap_or(0).max(0))
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(ok(json!({ "LockData": { "StorageToken": token } })))
}

/// Checks a PIN; too many failures revoke the session.
async fn check_code(state: &AppState, uid: &str, code_in: &str) -> ApiResult<String> {
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT lock_code_hash, storage_token, failed_attempts FROM session_locks WHERE uid = $1",
    )
    .bind(uid)
    .fetch_optional(&state.db)
    .await?;
    let Some((hash, token, failed)) = row else {
        return Err(ApiError::not_found("Session lock"));
    };
    if hash == sha256_hex(code_in) {
        sqlx::query("UPDATE session_locks SET failed_attempts = 0, locked = 0, last_activity = $1 WHERE uid = $2")
            .bind(now())
            .bind(uid)
            .execute(&state.db)
            .await?;
        return Ok(token);
    }
    if failed + 1 >= MAX_LOCK_ATTEMPTS {
        sqlx::query("DELETE FROM sessions WHERE uid = $1")
            .bind(uid)
            .execute(&state.db)
            .await?;
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::PASSWORD_WRONG,
            "Too many attempts; session closed",
        ));
    }
    sqlx::query("UPDATE session_locks SET failed_attempts = failed_attempts + 1 WHERE uid = $1")
        .bind(uid)
        .execute(&state.db)
        .await?;
    Err(ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        code::PASSWORD_WRONG,
        "Wrong PIN",
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UnlockReq {
    pub lock_code: String,
}

/// `DELETE user/session/lock`: remove the PIN (requires the PIN).
pub async fn delete_lock(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UnlockReq>,
) -> ApiResult<Json<Value>> {
    let token = check_code(&state, &user.uid, &req.lock_code).await?;
    sqlx::query("DELETE FROM session_locks WHERE uid = $1")
        .bind(&user.uid)
        .execute(&state.db)
        .await?;
    Ok(ok(json!({ "LockData": { "StorageToken": token } })))
}

pub async fn unlock(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UnlockReq>,
) -> ApiResult<Json<Value>> {
    let token = check_code(&state, &user.uid, &req.lock_code).await?;
    Ok(ok(json!({ "LockData": { "StorageToken": token } })))
}

pub async fn check(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT unlocked_secs FROM session_locks WHERE uid = $1")
            .bind(&user.uid)
            .fetch_optional(&state.db)
            .await?;
    Ok(ok(
        json!({ "LockInfo": { "Exists": row.is_some(), "UnlockedSecs": row.map(|r| r.0) } }),
    ))
}

pub async fn force_lock(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE session_locks SET locked = 1 WHERE uid = $1")
        .bind(&user.uid)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

// ---- Extra password ----

pub async fn has_srp(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let has: Option<(String,)> = sqlx::query_as("SELECT user_id FROM pass_srp WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(ok(json!({ "HasSRP": has.is_some() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddSrpReq {
    #[serde(rename = "SrpModulusID")]
    pub srp_modulus_id: String,
    pub srp_verifier: String,
    pub srp_salt: String,
}

/// `POST user/srp`: set the extra password (needs the account password scope).
pub async fn add_srp(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AddSrpReq>,
) -> ApiResult<Json<Value>> {
    login::require_password_scope(&user)?;
    if req.srp_modulus_id != state.modulus.id {
        return Err(ApiError::bad_request("Unknown modulus"));
    }
    sqlx::query("DELETE FROM pass_srp WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    sqlx::query("INSERT INTO pass_srp (user_id, modulus_id, salt, verifier, created) VALUES ($1,$2,$3,$4,$5)")
        .bind(&user.user_id)
        .bind(&req.srp_modulus_id)
        .bind(&req.srp_salt)
        .bind(&req.srp_verifier)
        .bind(now())
        .execute(&state.db)
        .await?;
    // The session that set it stays unlocked.
    mark_unlocked(&state, &user.uid).await?;
    Ok(ok_empty())
}

async fn mark_unlocked(state: &AppState, uid: &str) -> ApiResult<()> {
    sqlx::query("DELETE FROM pass_unlocked_sessions WHERE uid = $1")
        .bind(uid)
        .execute(&state.db)
        .await?;
    sqlx::query("INSERT INTO pass_unlocked_sessions (uid, unlocked) VALUES ($1, $2)")
        .bind(uid)
        .bind(now())
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn remove_srp(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    login::require_password_scope(&user)?;
    sqlx::query("DELETE FROM pass_srp WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

pub async fn srp_info(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT salt, verifier FROM pass_srp WHERE user_id = $1")
            .bind(&user.user_id)
            .fetch_optional(&state.db)
            .await?;
    let (salt, verifier) = row.ok_or_else(|| ApiError::not_found("Extra password"))?;
    let ch = state
        .modulus
        .challenge(&verifier)
        .map_err(|e| ApiError::internal(format!("{e:?}")))?;
    let session = login::store_challenge(&state, "pass_extra", &user.user_id, &ch).await?;
    Ok(ok(json!({ "SRPData": {
        "Modulus": state.modulus.signed,
        "ServerEphemeral": ch.server_ephemeral,
        "SrpSessionID": session,
        "SrpSalt": salt,
        "Version": 4,
    }})))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SrpAuthReq {
    pub client_ephemeral: String,
    pub client_proof: String,
    #[serde(rename = "SrpSessionID")]
    pub srp_session_id: String,
}

pub async fn srp_auth(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SrpAuthReq>,
) -> ApiResult<Json<Value>> {
    let (owner, challenge) =
        login::take_challenge(&state, &req.srp_session_id, "pass_extra").await?;
    if owner != user.user_id {
        return Err(login::wrong_password());
    }
    let (verifier,): (String,) = sqlx::query_as("SELECT verifier FROM pass_srp WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    let proof = state
        .modulus
        .verify(
            &verifier,
            &challenge,
            &req.client_ephemeral,
            &req.client_proof,
        )
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                2026,
                "Wrong extra password",
            )
        })?;
    mark_unlocked(&state, &user.uid).await?;
    Ok(ok(json!({ "ServerProof": proof })))
}
