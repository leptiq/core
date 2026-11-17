//! Products (Pass, and later Mail, Drive...) plug into the core server
//! through this trait. Core never names a product: it only calls these hooks.

use axum::Router;
use futures_util::future::BoxFuture;
use http::Extensions;

use crate::{app::AppState, config::Config, db::Tx, error::ApiResult};

pub trait Product: Send + Sync + 'static {
    /// Short app name, as reported by `core/v4/users/apps` (e.g. "pass").
    fn name(&self) -> &'static str;

    /// The product's own database migrations. Versions must not overlap with
    /// core's (1–999) or other products' ranges.
    fn migrator(&self) -> &'static sqlx::migrate::Migrator;

    /// Called once before the server starts. Products put the state they
    /// need at runtime into `ext`; handlers read it with [`AppState::ext`].
    fn init(&self, _config: &Config, _ext: &mut Extensions) -> anyhow::Result<()> {
        Ok(())
    }

    /// Routes, relative to the API root (the product adds its own prefix,
    /// e.g. `/pass/v1`).
    fn routes(&self, state: &AppState) -> Router<AppState>;

    /// Starts background jobs (cleanups, listeners...).
    fn spawn_background(&self, _state: &AppState) {}

    /// A new address now exists (signup or address creation), inside the
    /// transaction that created it.
    fn on_address_created<'a>(
        &'a self,
        _tx: &'a mut Tx<'_>,
        _email: &'a str,
    ) -> BoxFuture<'a, ApiResult<()>> {
        Box::pin(async { Ok(()) })
    }

    /// A user is about to be deleted.
    fn on_user_deleted<'a>(
        &'a self,
        _state: &'a AppState,
        _user_id: &'a str,
    ) -> BoxFuture<'a, ApiResult<()>> {
        Box::pin(async { Ok(()) })
    }
}
