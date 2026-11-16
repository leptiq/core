//! FIDO2 / WebAuthn second factor. Phase 6 fills this in.

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
};

pub async fn registered_keys(_state: &AppState, _user_id: &str) -> ApiResult<Vec<Value>> {
    Ok(vec![])
}

pub async fn login_info(state: &AppState, user_id: &str) -> ApiResult<Value> {
    Ok(
        json!({ "AuthenticationOptions": null, "RegisteredKeys": registered_keys(state, user_id).await? }),
    )
}

pub async fn verify_login(_state: &AppState, _user_id: &str, _payload: &Value) -> ApiResult<bool> {
    Ok(false)
}

pub async fn register_options(_state: State<AppState>, _user: AuthUser) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("FIDO2"))
}

pub async fn register(_state: State<AppState>, _user: AuthUser) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("FIDO2"))
}

pub async fn remove(
    _state: State<AppState>,
    _user: AuthUser,
    Path(_id): Path<String>,
) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("FIDO2"))
}

pub async fn rename(
    _state: State<AppState>,
    _user: AuthUser,
    Path(_id): Path<String>,
) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("FIDO2"))
}
