//! FIDO2 / WebAuthn second factor (security keys), using webauthn-rs.
//!
//! Proton clients serialize binary WebAuthn fields (challenge, user id,
//! credential ids) as arrays of numbers and send authenticator outputs as
//! base64 strings; this module converts between that and webauthn-rs.

use axum::{
    Json,
    extract::{Path, State},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::*;

use crate::{
    app::AppState,
    auth::{AuthUser, login::require_password_scope},
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, now, ok},
};

fn webauthn(state: &AppState) -> ApiResult<Webauthn> {
    let rp_id = &state.config.webauthn_rp_id;
    let scheme = if rp_id == "localhost" {
        "http"
    } else {
        "https"
    };
    let origin = Url::parse(&format!("{scheme}://{rp_id}")).map_err(ApiError::internal)?;
    WebauthnBuilder::new(rp_id, &origin)
        .map_err(ApiError::internal)?
        .rp_name("passhost")
        .allow_subdomains(true)
        .allow_any_port(true)
        .build()
        .map_err(ApiError::internal)
}

fn user_uuid(user_id: &str) -> Uuid {
    let d = Sha256::digest(user_id.as_bytes());
    Uuid::from_bytes(d[..16].try_into().expect("16 bytes"))
}

fn b64url_to_array(v: &Value) -> Value {
    match v
        .as_str()
        .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok())
    {
        Some(bytes) => json!(bytes),
        None => v.clone(),
    }
}

fn array_to_bytes(v: &Value) -> Option<Vec<u8>> {
    v.as_array()?
        .iter()
        .map(|n| n.as_u64().map(|n| n as u8))
        .collect()
}

/// Converts webauthn-rs JSON (base64url strings) to Proton's serialized form.
fn to_proton(mut options: Value) -> Value {
    let pk = &mut options["publicKey"];
    pk["challenge"] = b64url_to_array(&pk["challenge"]);
    if pk.get("user").is_some() {
        pk["user"]["id"] = b64url_to_array(&pk["user"]["id"]);
    }
    for list in ["excludeCredentials", "allowCredentials"] {
        if let Some(arr) = pk.get_mut(list).and_then(Value::as_array_mut) {
            for c in arr {
                c["id"] = b64url_to_array(&c["id"]);
            }
        }
    }
    options
}

fn challenge_key(options: &Value) -> ApiResult<String> {
    let bytes = array_to_bytes(&options["publicKey"]["challenge"])
        .ok_or_else(|| ApiError::bad_request("Missing challenge"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn std_to_url(s: &str) -> ApiResult<String> {
    let bytes = STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')))
        .map_err(|_| ApiError::bad_request("Invalid base64"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

struct StoredKey {
    id: String,
    name: String,
    credential_id: String,
    passkey: SecurityKey,
    format: String,
}

async fn load_keys(state: &AppState, user_id: &str) -> ApiResult<Vec<StoredKey>> {
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT id, name, credential_id, passkey, attestation_format FROM fido2_keys WHERE user_id = $1 ORDER BY created",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, name, credential_id, pk, format)| {
            serde_json::from_str(&pk).ok().map(|passkey| StoredKey {
                id,
                name,
                credential_id,
                passkey,
                format,
            })
        })
        .collect())
}

/// Registered keys as shown in user settings / login info.
pub async fn registered_keys(state: &AppState, user_id: &str) -> ApiResult<Vec<Value>> {
    Ok(load_keys(state, user_id)
        .await?
        .into_iter()
        .map(|k| {
            let cred = URL_SAFE_NO_PAD.decode(&k.credential_id).unwrap_or_default();
            json!({ "ID": k.id, "AttestationFormat": k.format, "CredentialID": cred, "Name": k.name, "Flags": 0 })
        })
        .collect())
}

async fn save_state(
    state: &AppState,
    key: &str,
    user_id: &str,
    kind: &str,
    value: &impl serde::Serialize,
) -> ApiResult<()> {
    sqlx::query("DELETE FROM webauthn_states WHERE created < $1")
        .bind(now() - 600)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO webauthn_states (id, user_id, kind, state, created) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(key)
    .bind(user_id)
    .bind(kind)
    .bind(serde_json::to_string(value)?)
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn take_state<T: serde::de::DeserializeOwned>(
    state: &AppState,
    key: &str,
    user_id: &str,
    kind: &str,
) -> ApiResult<T> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT state FROM webauthn_states WHERE id = $1 AND user_id = $2 AND kind = $3 AND created > $4")
            .bind(key)
            .bind(user_id)
            .bind(kind)
            .bind(now() - 600)
            .fetch_optional(&state.db)
            .await?;
    sqlx::query("DELETE FROM webauthn_states WHERE id = $1")
        .bind(key)
        .execute(&state.db)
        .await?;
    let (s,) = row.ok_or_else(|| ApiError::bad_request("Unknown or expired WebAuthn challenge"))?;
    Ok(serde_json::from_str(&s)?)
}

/// The `FIDO2` part of the login `2FA` info, with a fresh challenge.
pub async fn login_info(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let keys = load_keys(state, user_id).await?;
    if keys.is_empty() {
        return Ok(json!({ "AuthenticationOptions": null, "RegisteredKeys": [] }));
    }
    let passkeys: Vec<SecurityKey> = keys.iter().map(|k| k.passkey.clone()).collect();
    let (rcr, auth_state) = webauthn(state)?
        .start_securitykey_authentication(&passkeys)
        .map_err(ApiError::internal)?;
    let options = to_proton(serde_json::to_value(&rcr)?);
    save_state(
        state,
        &challenge_key(&options)?,
        user_id,
        "auth",
        &auth_state,
    )
    .await?;
    Ok(
        json!({ "AuthenticationOptions": options, "RegisteredKeys": registered_keys(state, user_id).await? }),
    )
}

/// Verifies a FIDO2 assertion sent to `auth/v4/2fa`.
pub async fn verify_login(state: &AppState, user_id: &str, payload: &Value) -> ApiResult<bool> {
    let key = challenge_key(&payload["AuthenticationOptions"])?;
    let auth_state: SecurityKeyAuthentication = take_state(state, &key, user_id, "auth").await?;
    let cred_id = array_to_bytes(&payload["CredentialID"])
        .ok_or_else(|| ApiError::bad_request("Missing CredentialID"))?;
    let cred_b64 = URL_SAFE_NO_PAD.encode(&cred_id);
    let credential: PublicKeyCredential = serde_json::from_value(json!({
        "id": cred_b64,
        "rawId": cred_b64,
        "response": {
            "authenticatorData": std_to_url(payload["AuthenticatorData"].as_str().unwrap_or_default())?,
            "clientDataJSON": std_to_url(payload["ClientData"].as_str().unwrap_or_default())?,
            "signature": std_to_url(payload["Signature"].as_str().unwrap_or_default())?,
            "userHandle": null,
        },
        "type": "public-key",
        "extensions": {},
    }))?;
    let Ok(result) = webauthn(state)?.finish_securitykey_authentication(&credential, &auth_state)
    else {
        return Ok(false);
    };
    // Persist the updated signature counter.
    for mut k in load_keys(state, user_id).await? {
        if k.passkey.update_credential(&result).unwrap_or(false) {
            sqlx::query("UPDATE fido2_keys SET passkey = $1 WHERE id = $2")
                .bind(serde_json::to_string(&k.passkey)?)
                .bind(&k.id)
                .execute(&state.db)
                .await?;
        }
    }
    Ok(true)
}

/// `GET core/v4/settings/2fa/register`: registration options.
pub async fn register_options(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    let (name, display): (String, String) =
        sqlx::query_as("SELECT name, display_name FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
    let existing = load_keys(&state, &user.user_id).await?;
    let exclude: Vec<CredentialID> = existing
        .iter()
        .map(|k| k.passkey.cred_id().clone())
        .collect();
    let (ccr, reg_state) = webauthn(&state)?
        .start_securitykey_registration(
            user_uuid(&user.user_id),
            &name,
            &display,
            Some(exclude),
            None,
            None,
        )
        .map_err(ApiError::internal)?;
    let options = to_proton(serde_json::to_value(&ccr)?);
    save_state(
        &state,
        &challenge_key(&options)?,
        &user.user_id,
        "register",
        &reg_state,
    )
    .await?;
    Ok(ok(json!({
        "RegistrationOptions": options,
        "RegisteredKeys": registered_keys(&state, &user.user_id).await?,
        "AttestationFormats": ["packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple", "none"],
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterReq {
    pub registration_options: Value,
    pub client_data: String,
    pub attestation_object: String,
    #[serde(default)]
    pub transports: Vec<String>,
    pub name: String,
}

/// `POST core/v4/settings/2fa/register`: add a security key.
pub async fn register(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RegisterReq>,
) -> ApiResult<Json<Value>> {
    require_password_scope(&user)?;
    let key = challenge_key(&req.registration_options)?;
    let reg_state: SecurityKeyRegistration =
        take_state(&state, &key, &user.user_id, "register").await?;
    let credential: RegisterPublicKeyCredential = serde_json::from_value(json!({
        "id": "",
        "rawId": "",
        "response": {
            "attestationObject": std_to_url(&req.attestation_object)?,
            "clientDataJSON": std_to_url(&req.client_data)?,
            "transports": req.transports,
        },
        "type": "public-key",
        "extensions": {},
    }))?;
    let passkey = webauthn(&state)?
        .finish_securitykey_registration(&credential, &reg_state)
        .map_err(|e| ApiError::bad_request(format!("Registration failed: {e}")))?;
    let format = serde_json::to_value(&passkey)?
        .pointer("/cred/attestation_format")
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_lowercase();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO fido2_keys (id, user_id, name, credential_id, passkey, attestation_format, created) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(new_id())
    .bind(&user.user_id)
    .bind(&req.name)
    .bind(URL_SAFE_NO_PAD.encode(passkey.cred_id().as_slice()))
    .bind(serde_json::to_string(&passkey)?)
    .bind(&format)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    events::push(&mut tx, &user.user_id, kind::USER_SETTINGS, None, None).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "UserSettings": super::settings::settings_json(&state, &user.user_id).await? }),
    ))
}

pub async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_password_scope(&user)?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM fido2_keys WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, &user.user_id, kind::USER_SETTINGS, None, None).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "UserSettings": super::settings::settings_json(&state, &user.user_id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RenameReq {
    pub name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RenameReq>,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE fido2_keys SET name = $1 WHERE id = $2 AND user_id = $3")
        .bind(&req.name)
        .bind(&id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "UserSettings": super::settings::settings_json(&state, &user.user_id).await? }),
    ))
}
