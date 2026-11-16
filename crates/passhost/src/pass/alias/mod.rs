//! Email aliases.

pub mod smtp;

use sqlx::AnyConnection;

use crate::error::ApiResult;

/// Whether `email` is an alias owned by `user_id`.
pub async fn is_owner(_conn: &mut AnyConnection, _user_id: &str, _email: &str) -> ApiResult<bool> {
    Ok(false)
}
