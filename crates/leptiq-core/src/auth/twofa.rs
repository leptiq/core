//! Two-factor authentication: TOTP (and FIDO2 info shape for clients).

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use totp_rs::{Algorithm, Secret, TOTP};

use super::{extract::MaybeSession, sessions};
use crate::{
    app::AppState,
    error::{ApiError, ApiResult, code},
    util::ok,
};

pub fn empty_info() -> Value {
    json!({ "Enabled": 0, "FIDO2": { "AuthenticationOptions": null, "RegisteredKeys": [] }, "TOTP": 0 })
}

/// The `2FA` object returned by `auth/v4/info` and `auth/v4`.
pub async fn info(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let (totp_enabled,): (i64,) = sqlx::query_as("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    let fido2 = crate::core::webauthn::login_info(state, user_id).await?;
    let has_fido2 = !fido2["RegisteredKeys"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true);
    let enabled = match (totp_enabled != 0, has_fido2) {
        (false, false) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (true, true) => 3,
    };
    Ok(json!({ "Enabled": enabled, "TOTP": totp_enabled, "FIDO2": fido2 }))
}

pub fn totp_for(secret_b32: &str) -> Option<TOTP> {
    let bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().ok()?;
    Some(TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, bytes))
}

pub fn verify_code(secret_b32: &str, code: &str) -> bool {
    totp_for(secret_b32)
        .map(|t| t.check_current(code.trim()).unwrap_or(false))
        .unwrap_or(false)
}

pub async fn check_totp(state: &AppState, user_id: &str, code: &str) -> ApiResult<bool> {
    let (secret, enabled): (Option<String>, i64) =
        sqlx::query_as("SELECT totp_secret, totp_enabled FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    Ok(enabled != 0 && secret.map(|s| verify_code(&s, code)).unwrap_or(false))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFaReq {
    pub two_factor_code: Option<String>,
    #[serde(rename = "FIDO2")]
    pub fido2: Option<Value>,
}

/// `POST auth/v4/2fa`: completes login for a session pending 2FA.
pub async fn submit_2fa(
    State(state): State<AppState>,
    MaybeSession(session): MaybeSession,
    Json(req): Json<TwoFaReq>,
) -> ApiResult<Json<Value>> {
    let user_id = session.user_id.clone().ok_or_else(ApiError::unauthorized)?;
    if !session.pending_2fa {
        return Ok(ok(
            json!({ "Scopes": session.scopes, "Scope": session.scopes.join(" ") }),
        ));
    }
    let valid = if let Some(code) = &req.two_factor_code {
        check_totp(&state, &user_id, code).await?
    } else if let Some(fido2) = &req.fido2 {
        crate::core::webauthn::verify_login(&state, &user_id, fido2).await?
    } else {
        false
    };
    if !valid {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::TWO_FA_WRONG,
            "Incorrect code",
        ));
    }
    let scopes = sessions::complete_2fa(&state, &session.uid).await?;
    Ok(ok(json!({ "Scopes": scopes, "Scope": scopes.join(" ") })))
}
