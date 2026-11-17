//! Proton core account API: users, addresses, keys, settings, events.

pub mod addresses;
pub mod events;
pub mod keys;
pub mod misc;
pub mod pgp;
pub mod settings;
pub mod users;
pub mod webauthn;

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/core/v4/users",
            get(users::get_user).post(users::create_user),
        )
        .route("/core/v4/users/available", get(users::available))
        .route("/core/v4/users/availableExternal", get(users::available))
        .route("/core/v4/users/code", post(users::send_code))
        .route("/core/v4/users/check", put(users::check_code))
        .route("/core/v4/users/delete", put(users::delete_user))
        .route("/core/v4/addresses", get(addresses::list))
        .route("/core/v4/addresses/setup", post(addresses::setup))
        .route(
            "/core/v4/addresses/{id}",
            get(addresses::get_one).put(addresses::update),
        )
        .route("/core/v4/domains/available", get(addresses::domains))
        .route("/core/v4/domains/premium", get(addresses::premium_domains))
        .route("/domains/available", get(addresses::domains))
        .route("/domains/premium", get(addresses::premium_domains))
        .route("/core/v4/keys/setup", post(keys::setup))
        .route("/core/v4/keys/salts", get(keys::salts))
        .route("/core/v4/keys/all", get(keys::public_keys_all))
        .route("/core/v4/keys", get(keys::public_keys_legacy))
        .route("/core/v4/keys/user", post(keys::create_user_key))
        .route("/core/v4/keys/address", post(keys::create_address_key))
        .route("/core/v4/keys/private", put(keys::update_private_keys))
        .route("/core/v4/keys/signedkeylists", post(keys::update_skl))
        .route("/core/v4/keys/signedkeylist", get(keys::get_skl))
        .route("/core/v4/settings", get(settings::get))
        .route("/core/v4/settings/password", put(settings::change_password))
        .route("/core/v4/settings/2fa/totp", post(settings::enable_totp))
        .route(
            "/core/v4/settings/2fa/totp/disable",
            put(settings::disable_totp),
        )
        .route(
            "/core/v4/settings/2fa/register",
            get(webauthn::register_options).post(webauthn::register),
        )
        .route("/core/v4/settings/2fa/{id}/remove", post(webauthn::remove))
        .route("/core/v4/settings/2fa/{id}/rename", put(webauthn::rename))
        .route("/core/v4/settings/{*field}", put(settings::update))
        .route("/core/v4/events/latest", get(events::latest))
        .route("/core/v4/events/{id}", get(events::get))
        // v5 has the same response shape as v4.
        .route("/core/v5/events/latest", get(events::latest))
        .route("/core/v5/events/{id}", get(events::get))
        .route(
            "/account/v4/personal-access-token",
            get(crate::pass::pat::list).post(crate::pass::pat::create),
        )
        .route(
            "/account/v4/personal-access-token/session",
            post(crate::pass::pat::session),
        )
        .route(
            "/account/v4/personal-access-token/{id}",
            axum::routing::delete(crate::pass::pat::delete),
        )
        .merge(misc::routes())
}
