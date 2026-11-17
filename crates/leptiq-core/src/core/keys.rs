use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::pgp;
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, now, ok, ok_empty},
};

#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SignedKeyList {
    pub data: String,
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddressKeyPayload {
    #[serde(rename = "AddressID")]
    pub address_id: String,
    pub private_key: String,
    pub token: Option<String>,
    pub signature: Option<String>,
    pub signed_key_list: Option<SignedKeyList>,
    pub primary: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetupReq {
    pub primary_key: String,
    pub key_salt: String,
    #[serde(default)]
    pub address_keys: Vec<AddressKeyPayload>,
    pub auth: Option<super::users::AuthVerifier>,
}

async fn insert_address_key(
    conn: &mut sqlx::AnyConnection,
    user_id: &str,
    k: &AddressKeyPayload,
    primary: bool,
) -> ApiResult<String> {
    let info = pgp::inspect_private(&k.private_key)
        .ok_or_else(|| ApiError::bad_request("Invalid address key"))?;
    let id = new_id();
    sqlx::query(
        "INSERT INTO address_keys (id, address_id, user_id, private_key, public_key, token, signature, is_primary, \
         fingerprint, created) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(&id)
    .bind(&k.address_id)
    .bind(user_id)
    .bind(&k.private_key)
    .bind(&info.public_armored)
    .bind(&k.token)
    .bind(&k.signature)
    .bind(primary as i64)
    .bind(&info.fingerprint)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    if let Some(skl) = &k.signed_key_list {
        sqlx::query("UPDATE addresses SET skl_data = $1, skl_signature = $2 WHERE id = $3")
            .bind(&skl.data)
            .bind(&skl.signature)
            .bind(&k.address_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(id)
}

/// `POST core/v4/keys/setup`: first-time key setup after signup.
pub async fn setup(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SetupReq>,
) -> ApiResult<Json<Value>> {
    let (existing,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_keys WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    if existing > 0 {
        return Err(ApiError::conflict("Keys are already set up"));
    }
    let info = pgp::inspect_private(&req.primary_key)
        .ok_or_else(|| ApiError::bad_request("Invalid primary key"))?;
    for k in &req.address_keys {
        super::addresses::owned(&state, &user.user_id, &k.address_id).await?;
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO user_keys (id, user_id, private_key, key_salt, is_primary, fingerprint, created) \
         VALUES ($1,$2,$3,$4,1,$5,$6)",
    )
    .bind(new_id())
    .bind(&user.user_id)
    .bind(&req.primary_key)
    .bind(&req.key_salt)
    .bind(&info.fingerprint)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    let mut seen = std::collections::HashSet::new();
    for k in &req.address_keys {
        let primary = seen.insert(k.address_id.clone());
        insert_address_key(&mut tx, &user.user_id, k, primary).await?;
        events::push(
            &mut tx,
            &user.user_id,
            kind::ADDRESS,
            None,
            Some(&k.address_id),
        )
        .await?;
    }
    if let Some(auth) = &req.auth {
        sqlx::query("UPDATE users SET srp_version = $1, srp_modulus_id = $2, srp_salt = $3, srp_verifier = $4 WHERE id = $5")
            .bind(auth.version)
            .bind(&auth.modulus_id)
            .bind(&auth.salt)
            .bind(&auth.verifier)
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await?;
    }
    events::push(&mut tx, &user.user_id, kind::USER, None, None).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "User": super::users::user_json(&state, &user.user_id).await? }),
    ))
}

pub async fn salts(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT id, key_salt FROM user_keys WHERE user_id = $1")
            .bind(&user.user_id)
            .fetch_all(&state.db)
            .await?;
    let salts: Vec<Value> = rows
        .into_iter()
        .map(|(id, salt)| json!({ "ID": id, "KeySalt": salt }))
        .collect();
    Ok(ok(json!({ "KeySalts": salts })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeysQuery {
    pub email: String,
}

/// Active public keys of a local address: (flags, armored public key, primary).
pub async fn public_keys_for(
    state: &AppState,
    email: &str,
) -> ApiResult<Option<(Vec<(i64, String, i64)>, Option<(String, Option<String>)>)>> {
    let addr: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, skl_data, skl_signature FROM addresses WHERE email = $1 AND status = 1",
    )
    .bind(email.trim().to_lowercase())
    .fetch_optional(&state.db)
    .await?;
    let Some((address_id, skl_data, skl_sig)) = addr else {
        return Ok(None);
    };
    let keys: Vec<(i64, Option<String>, i64)> = sqlx::query_as(
        "SELECT flags, public_key, is_primary FROM address_keys WHERE address_id = $1 AND active = 1 \
         ORDER BY is_primary DESC, created",
    )
    .bind(&address_id)
    .fetch_all(&state.db)
    .await?;
    let keys = keys
        .into_iter()
        .filter_map(|(f, k, p)| k.map(|k| (f, k, p)))
        .collect();
    Ok(Some((keys, skl_data.map(|d| (d, skl_sig)))))
}

/// `GET core/v4/keys/all?Email=`: recipient public keys.
pub async fn public_keys_all(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(q): Query<KeysQuery>,
) -> ApiResult<Json<Value>> {
    match public_keys_for(&state, &q.email).await? {
        Some((keys, skl)) => {
            let keys: Vec<Value> = keys
                .into_iter()
                .map(|(flags, pk, primary)| json!({ "Flags": flags, "PublicKey": pk, "Primary": primary, "Source": 0 }))
                .collect();
            let skl = skl.map(|(d, s)| json!({ "Data": d, "Signature": s, "MinEpochID": null, "MaxEpochID": null }));
            Ok(ok(json!({
                "Address": { "Keys": keys, "SignedKeyList": skl },
                "CatchAll": null,
                "Unverified": null,
                "ProtonMX": true,
                "IsProton": 1,
                "Warnings": [],
            })))
        }
        None => Ok(ok(json!({
            "Address": { "Keys": [], "SignedKeyList": null },
            "CatchAll": null,
            "Unverified": null,
            "ProtonMX": false,
            "IsProton": 0,
            "Warnings": [],
        }))),
    }
}

/// Legacy `GET core/v4/keys?Email=`.
pub async fn public_keys_legacy(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(q): Query<KeysQuery>,
) -> ApiResult<Json<Value>> {
    match public_keys_for(&state, &q.email).await? {
        Some((keys, _)) => {
            let keys: Vec<Value> = keys
                .into_iter()
                .map(|(flags, pk, _)| json!({ "Flags": flags, "PublicKey": pk }))
                .collect();
            Ok(ok(
                json!({ "RecipientType": 1, "MIMEType": "text/html", "Keys": keys }),
            ))
        }
        None => Ok(ok(
            json!({ "RecipientType": 2, "MIMEType": "text/html", "Keys": [] }),
        )),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateUserKeyReq {
    pub private_key: String,
    pub primary: Option<i64>,
}

pub async fn create_user_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateUserKeyReq>,
) -> ApiResult<Json<Value>> {
    let info = pgp::inspect_private(&req.private_key)
        .ok_or_else(|| ApiError::bad_request("Invalid key"))?;
    let salt: Option<(Option<String>,)> =
        sqlx::query_as("SELECT key_salt FROM user_keys WHERE user_id = $1 AND is_primary = 1")
            .bind(&user.user_id)
            .fetch_optional(&state.db)
            .await?;
    let mut tx = state.db.begin().await?;
    let primary = req.primary.unwrap_or(0) == 1;
    if primary {
        sqlx::query("UPDATE user_keys SET is_primary = 0 WHERE user_id = $1")
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await?;
    }
    let id = new_id();
    sqlx::query(
        "INSERT INTO user_keys (id, user_id, private_key, key_salt, is_primary, fingerprint, created) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&req.private_key)
    .bind(salt.and_then(|s| s.0))
    .bind(primary as i64)
    .bind(&info.fingerprint)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    events::push(&mut tx, &user.user_id, kind::USER, None, None).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "Key": { "ID": id, "Primary": primary as i64 } }),
    ))
}

pub async fn create_address_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AddressKeyPayload>,
) -> ApiResult<Json<Value>> {
    super::addresses::owned(&state, &user.user_id, &req.address_id).await?;
    let mut tx = state.db.begin().await?;
    let primary = req.primary.unwrap_or(0) == 1;
    if primary {
        sqlx::query("UPDATE address_keys SET is_primary = 0 WHERE address_id = $1")
            .bind(&req.address_id)
            .execute(&mut *tx)
            .await?;
    }
    let id = insert_address_key(&mut tx, &user.user_id, &req, primary).await?;
    events::push(
        &mut tx,
        &user.user_id,
        kind::ADDRESS,
        None,
        Some(&req.address_id),
    )
    .await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "Key": { "ID": id, "Primary": primary as i64 } }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeyUpdate {
    #[serde(rename = "ID")]
    pub id: String,
    pub private_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdatePrivateReq {
    pub key_salt: String,
    #[serde(default)]
    pub keys: Vec<KeyUpdate>,
    #[serde(default)]
    pub user_keys: Vec<KeyUpdate>,
    pub auth: Option<super::users::AuthVerifier>,
}

/// `PUT core/v4/keys/private`: re-encrypted keys after a password change.
pub async fn update_private_keys(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpdatePrivateReq>,
) -> ApiResult<Json<Value>> {
    crate::auth::login::require_password_scope(&user)?;
    let mut tx = state.db.begin().await?;
    for k in req.user_keys.iter().chain(req.keys.iter()) {
        let r = sqlx::query(
            "UPDATE user_keys SET private_key = $1, key_salt = $2 WHERE id = $3 AND user_id = $4",
        )
        .bind(&k.private_key)
        .bind(&req.key_salt)
        .bind(&k.id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
        if r.rows_affected() == 0 {
            // Legacy address keys (no token) are also locked with the passphrase.
            sqlx::query("UPDATE address_keys SET private_key = $1 WHERE id = $2 AND user_id = $3")
                .bind(&k.private_key)
                .bind(&k.id)
                .bind(&user.user_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    if let Some(auth) = &req.auth {
        sqlx::query("UPDATE users SET srp_version = $1, srp_modulus_id = $2, srp_salt = $3, srp_verifier = $4 WHERE id = $5")
            .bind(auth.version)
            .bind(&auth.modulus_id)
            .bind(&auth.salt)
            .bind(&auth.verifier)
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await?;
    }
    events::push(&mut tx, &user.user_id, kind::USER, None, None).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateSklReq {
    #[serde(rename = "AddressID")]
    pub address_id: Option<String>,
    pub signed_key_list: Option<SignedKeyList>,
    #[serde(default)]
    pub signed_key_lists: std::collections::HashMap<String, SignedKeyList>,
}

pub async fn update_skl(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpdateSklReq>,
) -> ApiResult<Json<Value>> {
    let mut lists = req.signed_key_lists.clone();
    if let (Some(a), Some(s)) = (req.address_id, req.signed_key_list) {
        lists.insert(a, s);
    }
    let mut tx = state.db.begin().await?;
    for (address_id, skl) in lists {
        sqlx::query(
            "UPDATE addresses SET skl_data = $1, skl_signature = $2 WHERE id = $3 AND user_id = $4",
        )
        .bind(&skl.data)
        .bind(&skl.signature)
        .bind(&address_id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
        events::push(
            &mut tx,
            &user.user_id,
            kind::ADDRESS,
            None,
            Some(&address_id),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(ok_empty())
}

pub async fn get_skl(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(q): Query<KeysQuery>,
) -> ApiResult<Json<Value>> {
    let skl = public_keys_for(&state, &q.email)
        .await?
        .and_then(|(_, s)| s);
    Ok(ok(
        json!({ "SignedKeyList": skl.map(|(d, s)| json!({ "Data": d, "Signature": s })) }),
    ))
}
