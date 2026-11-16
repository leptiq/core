//! Vault and item sharing invites.

use crate::{app::AppState, error::ApiResult};

/// All email addresses a user owns (lowercase).
pub async fn user_emails(state: &AppState, user_id: &str) -> ApiResult<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT email FROM addresses WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}
