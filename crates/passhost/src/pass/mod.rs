//! Proton Pass API (`pass/v1/...`).

pub mod alias;
pub mod files;
pub mod shares;

use axum::Router;

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
}
