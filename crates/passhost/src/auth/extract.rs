//! Request extractors for authenticated sessions.
//!
//! A session is identified by the `x-pm-uid` header plus either an
//! `Authorization: Bearer <token>` header or an `AUTH-<UID>` cookie.

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    app::AppState,
    error::ApiError,
    util::{now, sha256_hex},
};

#[derive(Debug, Clone)]
pub struct Session {
    pub uid: String,
    pub user_id: Option<String>,
    pub scopes: Vec<String>,
    pub pending_2fa: bool,
    pub password_scope_until: i64,
}

impl Session {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
    pub fn has_password_scope(&self) -> bool {
        self.password_scope_until > now()
    }
}

/// Any valid session (authenticated or not, 2FA pending or not).
pub struct MaybeSession(pub Session);

/// A fully authenticated user session.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub uid: String,
    pub user_id: String,
    pub session: Session,
}

fn header<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

pub fn cookie<'a>(parts: &'a Parts, name: &str) -> Option<String> {
    for value in parts.headers.get_all("cookie") {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

async fn load_session(parts: &Parts, state: &AppState) -> Result<Session, ApiError> {
    let uid = header(parts, "x-pm-uid")
        .ok_or_else(ApiError::unauthorized)?
        .to_string();
    let token = match header(parts, "authorization") {
        Some(h) => h
            .strip_prefix("Bearer ")
            .or_else(|| h.strip_prefix("bearer "))
            .unwrap_or(h)
            .trim()
            .to_string(),
        None => cookie(parts, &format!("AUTH-{uid}")).ok_or_else(ApiError::unauthorized)?,
    };
    let row: Option<(Option<String>, String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT user_id, access_hash, scopes, pending_2fa, access_expires, password_scope_until FROM sessions WHERE uid = $1",
    )
    .bind(&uid)
    .fetch_optional(&state.db)
    .await?;
    let Some((user_id, access_hash, scopes, pending_2fa, access_expires, password_scope_until)) =
        row
    else {
        return Err(ApiError::unauthorized());
    };
    if access_hash != sha256_hex(&token) || access_expires < now() {
        return Err(ApiError::unauthorized());
    }
    Ok(Session {
        uid,
        user_id,
        scopes: scopes.split_whitespace().map(String::from).collect(),
        pending_2fa: pending_2fa != 0,
        password_scope_until,
    })
}

impl FromRequestParts<AppState> for MaybeSession {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if let Some(s) = parts.extensions.get::<Session>() {
            return Ok(MaybeSession(s.clone()));
        }
        let s = load_session(parts, state).await?;
        parts.extensions.insert(s.clone());
        Ok(MaybeSession(s))
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let MaybeSession(session) = MaybeSession::from_request_parts(parts, state).await?;
        let Some(user_id) = session.user_id.clone() else {
            return Err(ApiError::unauthorized());
        };
        if session.pending_2fa {
            return Err(ApiError::new(
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                crate::error::code::NOT_ALLOWED,
                "Two-factor authentication required",
            ));
        }
        Ok(AuthUser {
            uid: session.uid.clone(),
            user_id,
            session,
        })
    }
}
