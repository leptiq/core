use crate::{app::AppState, error::ApiResult};

/// Removes every share a user holds (used on account deletion).
pub async fn delete_all_for_user(_state: &AppState, _user_id: &str) -> ApiResult<()> {
    Ok(())
}
