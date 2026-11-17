//! Session forking: how the account app hands a logged-in session to the Pass
//! web app / browser extension, and how the CLI logs in via a user code.
//!
//! * Parent (logged in) `POST auth/v4/sessions/forks` with an encrypted
//!   `Payload` → `{Selector}`.
//! * Child `GET auth/v4/sessions/forks/{selector}` → a fresh child session.
//! * CLI style: child first `GET auth/v4/sessions/forks` → `{Selector, UserCode}`,
//!   the user enters the code in the parent, which pushes with `UserCode`.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{AuthUser, sessions};
use crate::{
    app::AppState,
    error::{ApiError, ApiResult, code},
    util::{new_token, now, ok},
};

const FORK_TTL: i64 = 10 * 60;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PushReq {
    pub payload: Option<String>,
    #[serde(rename = "ChildClientID")]
    pub child_client_id: String,
    pub independent: Option<i64>,
    pub fork_challenge: Option<String>,
    pub selector: Option<String>,
    pub user_code: Option<String>,
}

pub async fn push(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<PushReq>,
) -> ApiResult<Json<Value>> {
    // The fork challenge is stored in the `user_code` column's sibling: we keep
    // it inside `payload` metadata to avoid an extra column.
    let meta = json!({ "Payload": req.payload, "ForkChallenge": req.fork_challenge }).to_string();
    let existing = if let Some(code) = &req.user_code {
        sqlx::query_as::<_, (String,)>("SELECT selector FROM session_forks WHERE user_code = $1 AND user_id IS NULL AND expires > $2")
            .bind(code.to_uppercase())
            .bind(now())
            .fetch_optional(&state.db)
            .await?
            .map(|r| r.0)
            .ok_or_else(|| ApiError::not_found("Fork"))
            .map(Some)?
    } else if let Some(sel) = &req.selector {
        sqlx::query_as::<_, (String,)>(
            "SELECT selector FROM session_forks WHERE selector = $1 AND user_id IS NULL",
        )
        .bind(sel)
        .fetch_optional(&state.db)
        .await?
        .map(|r| r.0)
    } else {
        None
    };
    let selector = match existing {
        Some(sel) => {
            sqlx::query(
                "UPDATE session_forks SET parent_uid = $1, user_id = $2, child_client_id = $3, independent = $4, \
                 payload = $5, expires = $6 WHERE selector = $7",
            )
            .bind(&user.uid)
            .bind(&user.user_id)
            .bind(&req.child_client_id)
            .bind(req.independent.unwrap_or(0))
            .bind(&meta)
            .bind(now() + FORK_TTL)
            .bind(&sel)
            .execute(&state.db)
            .await?;
            sel
        }
        None => {
            let sel = new_token(32);
            sqlx::query(
                "INSERT INTO session_forks (selector, parent_uid, user_id, child_client_id, independent, payload, created, expires) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(&sel)
            .bind(&user.uid)
            .bind(&user.user_id)
            .bind(&req.child_client_id)
            .bind(req.independent.unwrap_or(0))
            .bind(&meta)
            .bind(now())
            .bind(now() + FORK_TTL)
            .execute(&state.db)
            .await?;
            sel
        }
    };
    Ok(ok(json!({ "Selector": selector })))
}

/// `GET auth/v4/sessions/forks`: child-initiated fork with a user code.
pub async fn init_user_code(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let selector = new_token(32);
    let user_code: String = new_token(8).to_uppercase();
    sqlx::query(
        "INSERT INTO session_forks (selector, child_client_id, user_code, created, expires) VALUES ($1, '', $2, $3, $4)",
    )
    .bind(&selector)
    .bind(&user_code)
    .bind(now())
    .bind(now() + FORK_TTL)
    .execute(&state.db)
    .await?;
    Ok(ok(
        json!({ "Selector": selector, "UserCode": user_code, "ExpiresIn": FORK_TTL }),
    ))
}

pub async fn code_location() -> Json<Value> {
    ok(json!({ "IP": null, "CountryCode": null }))
}

pub async fn pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(selector): Path<String>,
) -> ApiResult<Json<Value>> {
    // user_id, child_client_id, payload, expires, child_uid, parent_uid
    type ForkRow = (
        Option<String>,
        String,
        Option<String>,
        i64,
        Option<String>,
        Option<String>,
    );
    let row: Option<ForkRow> = sqlx::query_as(
        "SELECT user_id, child_client_id, payload, expires, child_uid, parent_uid FROM session_forks WHERE selector = $1",
    )
    .bind(&selector)
    .fetch_optional(&state.db)
    .await?;
    let Some((user_id, client_id, meta, expires, child_uid, parent_uid)) = row else {
        return Err(ApiError::not_found("Fork"));
    };
    if expires < now() || child_uid.is_some() {
        return Err(ApiError::not_found("Fork"));
    }
    let Some(user_id) = user_id else {
        // Not yet pushed by the parent (CLI polling).
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::NOT_FOUND,
            "Fork not yet available",
        ));
    };
    let meta: Value = meta
        .and_then(|m| serde_json::from_str(&m).ok())
        .unwrap_or(Value::Null);
    if let Some(challenge) = meta["ForkChallenge"].as_str() {
        let secret = headers
            .get("x-pm-fork-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if hex::encode(Sha256::digest(secret.as_bytes())) != challenge.to_lowercase() {
            return Err(ApiError::forbidden("Invalid fork secret"));
        }
    }
    let created = sessions::create(&state, Some(&user_id), &client_id, false, false).await?;
    // The child keeps the parent's per-browser account index.
    let local_id = match &parent_uid {
        Some(p) => sessions::local_id(&state, p).await?,
        None => 0,
    };
    sessions::set_local_id(&state, &created.uid, local_id).await?;
    sqlx::query("UPDATE session_forks SET child_uid = $1 WHERE selector = $2")
        .bind(&created.uid)
        .bind(&selector)
        .execute(&state.db)
        .await?;
    Ok(ok(json!({
        "Payload": meta["Payload"],
        "LocalID": local_id,
        "UID": created.uid,
        "AccessToken": created.access_token,
        "RefreshToken": created.refresh_token,
        "ExpiresIn": state.config.access_token_ttl,
        "TokenType": "Bearer",
        "UserID": user_id,
        "Scopes": created.scopes,
    })))
}
