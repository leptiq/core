use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_id, now, ok},
};

pub async fn address_json(state: &AppState, address_id: &str) -> ApiResult<Value> {
    let (id, email, display_name, signature, status, addr_type, ordering, skl_data, skl_sig): (
        String, String, String, String, i64, i64, i64, Option<String>, Option<String>,
    ) = sqlx::query_as(
        "SELECT id, email, display_name, signature, status, addr_type, ordering, skl_data, skl_signature \
         FROM addresses WHERE id = $1",
    )
    .bind(address_id)
    .fetch_one(&state.db)
    .await?;
    let keys: Vec<(String, String, Option<String>, Option<String>, Option<String>, i64, i64, i64, Option<String>)> =
        sqlx::query_as(
            "SELECT id, private_key, public_key, token, signature, is_primary, active, flags, fingerprint \
             FROM address_keys WHERE address_id = $1 ORDER BY created",
        )
        .bind(address_id)
        .fetch_all(&state.db)
        .await?;
    let keys: Vec<Value> = keys
        .into_iter()
        .map(|(kid, pk, pubk, token, sig, primary, active, flags, fp)| {
            json!({
                "ID": kid, "Version": 3, "PrivateKey": pk, "PublicKey": pubk, "Token": token,
                "Signature": sig, "Primary": primary, "Active": active, "Flags": flags,
                "Fingerprint": fp, "Fingerprints": fp.map(|f| vec![f]).unwrap_or_default(),
                "AddressForwardingID": null,
            })
        })
        .collect();
    let skl = skl_data.map(|data| {
        json!({ "Data": data, "Signature": skl_sig, "MinEpochID": null, "MaxEpochID": null, "ExpectedMinEpochID": null })
    });
    Ok(json!({
        "ID": id,
        "DomainID": "default",
        "Email": email,
        "Status": status,
        "Type": addr_type,
        "Receive": 1,
        "Send": 1,
        "DisplayName": display_name,
        "Signature": signature,
        "Order": ordering,
        "Priority": ordering,
        "CatchAll": false,
        "ProtonMX": true,
        "ConfirmationState": 1,
        "HasKeys": (!keys.is_empty()) as i64,
        "Flags": 0,
        "Permissions": 0,
        "Keys": keys,
        "SignedKeyList": skl,
    }))
}

pub async fn list_for_user(state: &AppState, user_id: &str) -> ApiResult<Vec<Value>> {
    let ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM addresses WHERE user_id = $1 ORDER BY ordering, created")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    let mut out = Vec::with_capacity(ids.len());
    for (id,) in ids {
        out.push(address_json(state, &id).await?);
    }
    Ok(out)
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let addresses = list_for_user(&state, &user.user_id).await?;
    Ok(ok(
        json!({ "Total": addresses.len(), "Addresses": addresses }),
    ))
}

pub async fn owned(state: &AppState, user_id: &str, address_id: &str) -> ApiResult<()> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT id FROM addresses WHERE id = $1 AND user_id = $2")
            .bind(address_id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    row.map(|_| ())
        .ok_or_else(|| ApiError::not_found("Address"))
}

pub async fn get_one(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    owned(&state, &user.user_id, &id).await?;
    Ok(ok(json!({ "Address": address_json(&state, &id).await? })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateReq {
    pub display_name: Option<String>,
    pub signature: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    owned(&state, &user.user_id, &id).await?;
    let mut tx = state.db.begin().await?;
    if let Some(n) = &req.display_name {
        sqlx::query("UPDATE addresses SET display_name = $1 WHERE id = $2")
            .bind(n)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(s) = &req.signature {
        sqlx::query("UPDATE addresses SET signature = $1 WHERE id = $2")
            .bind(s)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    events::push(&mut tx, &user.user_id, kind::ADDRESS, None, Some(&id)).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Address": address_json(&state, &id).await? })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetupReq {
    pub domain: Option<String>,
    pub display_name: Option<String>,
    pub signature: Option<String>,
}

/// `POST core/v4/addresses/setup`: creates the user's first address.
pub async fn setup(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SetupReq>,
) -> ApiResult<Json<Value>> {
    let (name, display): (String, String) =
        sqlx::query_as("SELECT name, display_name FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_one(&state.db)
            .await?;
    let domain = req
        .domain
        .unwrap_or_else(|| state.config.mail_domain.clone())
        .to_lowercase();
    let email = format!("{name}@{domain}");
    if let Some((existing,)) =
        sqlx::query_as::<_, (String,)>("SELECT id FROM addresses WHERE email = $1 AND user_id = $2")
            .bind(&email)
            .bind(&user.user_id)
            .fetch_optional(&state.db)
            .await?
    {
        return Ok(ok(
            json!({ "Address": address_json(&state, &existing).await? }),
        ));
    }
    let id = new_id();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM addresses WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO addresses (id, user_id, email, display_name, signature, ordering, created) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&email)
    .bind(req.display_name.unwrap_or(display))
    .bind(req.signature.unwrap_or_default())
    .bind(count + 1)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE users SET email = $1 WHERE id = $2 AND $3 = 0")
        .bind(&email)
        .bind(&user.user_id)
        .bind(count)
        .execute(&mut *tx)
        .await?;
    events::push(&mut tx, &user.user_id, kind::ADDRESS, None, Some(&id)).await?;
    for product in &state.products {
        product.on_address_created(&mut tx, &email).await?;
    }
    tx.commit().await?;
    Ok(ok(json!({ "Address": address_json(&state, &id).await? })))
}

pub async fn domains(State(state): State<AppState>) -> Json<Value> {
    ok(json!({ "Domains": [state.config.mail_domain] }))
}

pub async fn premium_domains(State(state): State<AppState>) -> Json<Value> {
    ok(json!({ "Domains": [state.config.mail_domain] }))
}
