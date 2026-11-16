use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    app::AppState,
    auth::{AuthUser, login::require_password_scope},
    error::{ApiError, ApiResult, code},
    events::{self, kind},
    util::ok,
};

pub async fn settings_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let (email, settings, totp_enabled): (String, String, i64) =
        sqlx::query_as("SELECT email, settings, totp_enabled FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    let fido2 = super::webauthn::registered_keys(state, user_id).await?;
    let enabled = (totp_enabled != 0) as i64 | if fido2.is_empty() { 0 } else { 2 };
    let mut base = json!({
        "Email": { "Value": email, "Status": 1, "Notify": 0, "Reset": 0 },
        "Phone": { "Value": null, "Status": 0, "Notify": 0, "Reset": 0 },
        "Password": { "Mode": 1, "ExpirationTime": null },
        "2FA": { "Enabled": enabled, "Allowed": 3, "ExpirationTime": null, "RegisteredKeys": fido2 },
        "News": 0,
        "Locale": "en_US",
        "LogAuth": 0,
        "InvoiceText": "",
        "Density": 0,
        "Theme": null,
        "ThemeType": 0,
        "WeekStart": 0,
        "DateFormat": 0,
        "TimeFormat": 0,
        "Welcome": 1,
        "WelcomeFlag": 1,
        "EarlyAccess": 0,
        "Flags": { "Welcomed": 1, "SupportPgpV6Keys": 0 },
        "Referral": null,
        "DeviceRecovery": 0,
        "Telemetry": 0,
        "CrashReports": 0,
        "HideSidePanel": 0,
        "HighSecurity": { "Eligible": 0, "Value": 0 },
        "SessionAccountRecovery": 0,
        "Checklists": [],
        "UsedClientFlags": 0,
        "AIAssistantFlags": 0,
        "BreachAlerts": { "Eligible": 0, "Value": 0, "EmailNotifications": 0 },
    });
    if let Ok(Value::Object(overrides)) = serde_json::from_str::<Value>(&settings) {
        merge(&mut base, Value::Object(overrides));
    }
    Ok(base)
}

fn merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                merge(b.entry(k).or_insert(Value::Null), v);
            }
        }
        (b, p) => *b = p,
    }
}

pub async fn get(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "UserSettings": settings_json(&state, &user.user_id).await? }),
    ))
}

/// Generic `PUT core/v4/settings/<field>`: stores the request body under the
/// field name (e.g. `settings/locale` with `{"Locale": "fr_FR"}`).
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(field): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let (settings,): (String,) = sqlx::query_as("SELECT settings FROM users WHERE id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    let mut current: Value =
        serde_json::from_str(&settings).unwrap_or_else(|_| Value::Object(Map::new()));
    match body {
        Value::Object(map)
            if map.len() == 1 && !map.values().next().map(Value::is_object).unwrap_or(false) =>
        {
            merge(&mut current, Value::Object(map));
        }
        other => {
            // Nested fields like "flags/welcomed" → {"Flags": {...}}.
            let key = field.split('/').next().unwrap_or(&field);
            let mut cap = key.to_string();
            if let Some(f) = cap.get_mut(0..1) {
                f.make_ascii_uppercase();
            }
            let mut patch = Map::new();
            patch.insert(cap, other);
            merge(&mut current, Value::Object(patch));
        }
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET settings = $1 WHERE id = $2")
        .bind(current.to_string())
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, &user.user_id, kind::USER_SETTINGS, None, None).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "UserSettings": settings_json(&state, &user.user_id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PasswordReq {
    pub auth: super::users::AuthVerifier,
}

/// `PUT core/v4/settings/password`: change the login (SRP) password.
pub async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<PasswordReq>,
) -> ApiResult<Json<Value>> {
    require_password_scope(&user)?;
    sqlx::query("UPDATE users SET srp_version = $1, srp_modulus_id = $2, srp_salt = $3, srp_verifier = $4 WHERE id = $5")
        .bind(req.auth.version)
        .bind(&req.auth.modulus_id)
        .bind(&req.auth.salt)
        .bind(&req.auth.verifier)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "UserSettings": settings_json(&state, &user.user_id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EnableTotpReq {
    #[serde(rename = "TOTPSharedSecret")]
    pub totp_shared_secret: String,
    #[serde(rename = "TOTPConfirmation")]
    pub totp_confirmation: String,
}

pub async fn enable_totp(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<EnableTotpReq>,
) -> ApiResult<Json<Value>> {
    require_password_scope(&user)?;
    if !crate::auth::twofa::verify_code(&req.totp_shared_secret, &req.totp_confirmation) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::TWO_FA_WRONG,
            "Incorrect code",
        ));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET totp_secret = $1, totp_enabled = 1 WHERE id = $2")
        .bind(&req.totp_shared_secret)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, &user.user_id, kind::USER_SETTINGS, None, None).await?;
    tx.commit().await?;
    Ok(ok(json!({
        "TwoFactorRecoveryCodes": [],
        "UserSettings": settings_json(&state, &user.user_id).await?,
    })))
}

pub async fn disable_totp(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    require_password_scope(&user)?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, &user.user_id, kind::USER_SETTINGS, None, None).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "UserSettings": settings_json(&state, &user.user_id).await? }),
    ))
}
