//! Authentication: SRP login, sessions, tokens, cookies, session forking.

pub mod extract;
pub mod forks;
pub mod login;
pub mod sessions;
pub mod twofa;

pub use extract::{AuthUser, MaybeSession, Session};

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    let mut r = Router::new();
    // Clients use both the legacy `auth/v4/*` and the `core/v4/auth/*` prefix.
    for prefix in ["/auth/v4", "/core/v4/auth"] {
        r = r
            .route(&format!("{prefix}/info"), post(login::info))
            .route(&format!("{prefix}/modulus"), get(login::modulus))
            .route(prefix, post(login::auth).delete(sessions::logout))
            .route(&format!("{prefix}/2fa"), post(twofa::submit_2fa))
            .route(&format!("{prefix}/refresh"), post(sessions::refresh))
            .route(&format!("{prefix}/cookies"), post(sessions::set_cookies))
            .route(&format!("{prefix}/scopes"), get(sessions::scopes));
    }
    r.route("/auth/refresh", post(sessions::refresh))
        .route(
            "/auth/v4/sessions",
            post(sessions::create_unauth)
                .get(sessions::list)
                .delete(sessions::revoke_others),
        )
        .route("/auth/v4/sessions/{uid}", delete(sessions::revoke_one))
        .route(
            "/auth/v4/sessions/local/key",
            get(sessions::get_local_key).put(sessions::set_local_key),
        )
        .route(
            "/auth/v4/sessions/forks",
            post(forks::push).get(forks::init_user_code),
        )
        .route("/auth/sessions/forks", get(forks::init_user_code))
        .route(
            "/auth/v4/sessions/forks/code/{code}",
            get(forks::code_location),
        )
        .route("/auth/v4/sessions/forks/{selector}", get(forks::pull))
        .route("/auth/sessions/forks/{selector}", get(forks::pull))
        .route("/core/v4/users/unlock", put(login::unlock_password_scope))
        .route("/core/v4/users/lock", put(sessions::lock_password_scope))
}
