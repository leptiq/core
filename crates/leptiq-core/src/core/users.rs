use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    app::AppState,
    auth::AuthUser,
    config::SignupPolicy,
    error::{ApiError, ApiResult, code},
    events::{self, kind},
    util::{new_id, now, ok, ok_empty},
};

/// Builds the `User` object returned by `core/v4/users` and events.
pub async fn user_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let (id, name, display_name, email, used_space, created): (
        String,
        String,
        String,
        String,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT id, name, display_name, email, used_space, created FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    let keys: Vec<(String, String, i64, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, private_key, is_primary, active, flags, fingerprint FROM user_keys WHERE user_id = $1 ORDER BY created",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    let keys: Vec<Value> = keys
        .into_iter()
        .map(|(id, pk, primary, active, flags, fp)| {
            json!({ "ID": id, "Version": 3, "PrivateKey": pk, "Primary": primary, "Active": active,
                    "Flags": flags, "Fingerprint": fp, "RecoverySecret": null, "RecoverySecretSignature": null })
        })
        .collect();
    let quota = state.config.file_quota_bytes;
    Ok(json!({
        "ID": id,
        "Name": name,
        "DisplayName": display_name,
        "Email": email,
        "Keys": keys,
        "UsedSpace": used_space,
        "UsedBaseSpace": used_space,
        "UsedDriveSpace": 0,
        "MaxSpace": quota,
        "MaxBaseSpace": quota,
        "MaxDriveSpace": 0,
        "MaxUpload": quota,
        "ProductUsedSpace": { "Calendar": 0, "Contact": 0, "Drive": 0, "Mail": 0, "Pass": used_space },
        "Credit": 0,
        "Currency": "USD",
        "Role": 0,
        "Private": 1,
        "Type": 1,
        "Subscribed": 0,
        "Services": 1,
        "Delinquent": 0,
        "DriveEarlyAccess": 0,
        "ToMigrate": 0,
        "MnemonicStatus": 0,
        "Idle": 0,
        "CreateTime": created,
        "NumAI": 0,
        "NumLumo": 0,
        "Flags": {
            "protected": false, "drive-early-access": false, "onboard-checklist-storage-granted": false,
            "has-temporary-password": false, "test-account": false, "no-login": false,
            "no-proton-address": false, "recovery-attempt": false, "pass-lifetime": false,
            "pass-from-sl": false, "sso": false, "has-a-byoe-address": false,
            "delegated-access": false, "org-access": false
        },
        "AccountRecovery": null,
    }))
}

pub async fn get_user(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "User": user_json(&state, &user.user_id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthVerifier {
    pub version: i64,
    #[serde(rename = "ModulusID")]
    pub modulus_id: String,
    pub salt: String,
    pub verifier: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateUserReq {
    pub username: Option<String>,
    pub email: Option<String>,
    pub domain: Option<String>,
    pub auth: AuthVerifier,
    pub invite_code: Option<String>,
    #[serde(rename = "ReferralID")]
    pub referral_id: Option<String>,
    pub token_payment: Option<String>,
}

pub fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
}

/// `POST core/v4/users`: sign up.
pub async fn create_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateUserReq>,
) -> ApiResult<Json<Value>> {
    let invite = req
        .invite_code
        .clone()
        .or(req.referral_id.clone())
        .or(req.token_payment.clone())
        .or_else(|| {
            headers
                .get("x-pm-invite")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        });
    match state.config.signup {
        SignupPolicy::Open => {}
        SignupPolicy::Closed => {
            return Err(ApiError::forbidden("Signups are disabled on this server"));
        }
        SignupPolicy::Invite => {
            let code = invite
                .clone()
                .ok_or_else(|| ApiError::forbidden("An invite code is required"))?;
            let res = sqlx::query(
                "UPDATE signup_invites SET used_by = $1 WHERE code = $2 AND used_by IS NULL",
            )
            .bind("pending")
            .bind(&code)
            .execute(&state.db)
            .await?;
            if res.rows_affected() != 1 {
                return Err(ApiError::forbidden("Invalid invite code"));
            }
        }
    }
    let raw = req
        .username
        .clone()
        .or(req.email.clone())
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let name = raw.split('@').next().unwrap_or_default().to_string();
    if !valid_username(&name) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::USERNAME_INVALID,
            "Invalid username",
        ));
    }
    if req.auth.version != 4 || req.auth.modulus_id != state.modulus.id {
        return Err(ApiError::bad_request("Unsupported auth version or modulus"));
    }
    let domain = req
        .domain
        .clone()
        .unwrap_or_else(|| state.config.mail_domain.clone())
        .to_lowercase();
    // External signups (an existing email as the login) keep that address;
    // internal ones get <username>@<domain>.
    let email = if req.username.is_none() && raw.contains('@') {
        raw.clone()
    } else {
        format!("{name}@{domain}")
    };
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE name = $1")
        .bind(&name)
        .fetch_optional(&state.db)
        .await?;
    let addr_exists: Option<(String,)> =
        sqlx::query_as("SELECT id FROM addresses WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_some() || addr_exists.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            code::USERNAME_TAKEN,
            "Username already used",
        ));
    }
    let id = new_id();
    let first_user: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO users (id, name, display_name, email, srp_version, srp_modulus_id, srp_salt, srp_verifier, is_admin, created) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&name)
    .bind(&email)
    .bind(req.auth.version)
    .bind(&req.auth.modulus_id)
    .bind(&req.auth.salt)
    .bind(&req.auth.verifier)
    .bind((first_user.0 == 0) as i64)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    // Like Proton, signup creates the user's first address (without keys);
    // the client then calls `keys/setup` for it.
    let address_id = new_id();
    sqlx::query(
        "INSERT INTO addresses (id, user_id, email, display_name, signature, ordering, created) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&address_id)
    .bind(&id)
    .bind(&email)
    .bind(&name)
    .bind("")
    .bind(1i64)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    crate::events::push(
        &mut tx,
        &id,
        crate::events::kind::ADDRESS,
        None,
        Some(&address_id),
    )
    .await?;
    for product in &state.products {
        product.on_address_created(&mut tx, &email).await?;
    }
    tx.commit().await?;
    if let (SignupPolicy::Invite, Some(code)) = (state.config.signup, invite) {
        sqlx::query("UPDATE signup_invites SET used_by = $1 WHERE code = $2")
            .bind(&id)
            .bind(&code)
            .execute(&state.db)
            .await?;
    }
    Ok(ok(json!({ "User": user_json(&state, &id).await? })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AvailableQuery {
    pub name: Option<String>,
    #[serde(rename = "ParseDomain")]
    pub _parse_domain: Option<i64>,
}

pub async fn available(
    State(state): State<AppState>,
    Query(q): Query<AvailableQuery>,
) -> ApiResult<Json<Value>> {
    let raw = q.name.unwrap_or_default().to_lowercase();
    let name = raw.split('@').next().unwrap_or_default();
    if !valid_username(name) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::USERNAME_INVALID,
            "Invalid username",
        ));
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE name = $1")
        .bind(name)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            code::USERNAME_TAKEN,
            "Username already used",
        ));
    }
    Ok(ok_empty())
}

/// Verification codes (email/SMS human verification) are not used: accept.
pub async fn send_code() -> Json<Value> {
    ok_empty()
}

pub async fn check_code() -> Json<Value> {
    ok_empty()
}

/// `PUT core/v4/users/delete`: delete own account (needs password scope).
pub async fn delete_user(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    crate::auth::login::require_password_scope(&user)?;
    for product in &state.products {
        product.on_user_deleted(&state, &user.user_id).await?;
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

/// Records a core "user changed" event.
pub async fn user_changed(state: &AppState, user_id: &str) -> ApiResult<()> {
    let mut conn = state.db.acquire().await?;
    events::push(&mut conn, user_id, kind::USER, None, None).await?;
    Ok(())
}
