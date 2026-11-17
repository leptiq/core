//! Leptiq server: assembles `leptiq-core` with the product crates.

pub mod admin;

use std::sync::Arc;

use leptiq_core::db;
pub use leptiq_core::{AppState, Config, Product, build_router};

/// The products this server runs.
pub fn products() -> Vec<Arc<dyn Product>> {
    vec![
        leptiq_pass::product(),
        leptiq_authenticator::product(),
        leptiq_drive::product(),
        leptiq_assistant::product(),
    ]
}

/// Connects to the database, applies core and product migrations, and builds
/// the shared state.
pub async fn build_state(config: Config) -> anyhow::Result<AppState> {
    let products = products();
    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool, &products).await?;
    AppState::new(config, pool, products).await
}
