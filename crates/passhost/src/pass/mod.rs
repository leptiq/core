//! Proton Pass API (`pass/v1/...`).

pub mod alias;
pub mod files;
pub mod folders;
pub mod invites;
pub mod items;
pub mod shares;
pub mod sync;
pub mod user;
pub mod vaults;

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        // user
        .route("/user/access", get(user::access).post(user::access))
        .route("/user/access/check", get(user::access_check))
        .route("/user/default_share/{share}", put(user::set_default_share))
        .route("/user/monitor", put(user::set_monitor))
        .route(
            "/user/inapp_notifications_disabled",
            put(user::set_notifications),
        )
        .route("/user/coupon/redeem", post(user::redeem_coupon))
        .route("/user/sync_event", get(sync::latest))
        .route("/user/sync_event/{event}", get(sync::get))
        .route("/notification", get(user::notifications))
        .route("/notification/{id}", put(user::notification_state))
        // shares
        .route("/share", get(shares::list))
        .route("/share/hide", put(shares::hide_batch))
        .route("/share/{share}", get(shares::get).delete(shares::leave))
        .route("/share/{share}/hide", put(shares::hide))
        .route("/share/{share}/unhide", put(shares::unhide))
        .route("/share/{share}/key", get(shares::keys))
        .route("/share/{share}/event", get(sync::share_latest))
        .route("/share/{share}/event/{event}", get(sync::share_events))
        // vaults
        .route("/vault", post(vaults::create))
        .route("/vault/{share}", put(vaults::update).delete(vaults::delete))
        .route("/vault/{share}/primary", put(vaults::set_primary))
        .route("/vault/{share}/owner", put(vaults::transfer_owner))
        .route("/vault/share/{vault}", get(vaults::share_for_vault))
        // items
        .route(
            "/share/{share}/item",
            get(items::list).post(items::create).delete(items::delete),
        )
        .route("/share/{share}/item/trash", post(items::trash))
        .route("/share/{share}/item/untrash", post(items::untrash))
        .route("/share/{share}/item/read", put(items::mark_read))
        .route("/share/{share}/item/share", put(items::move_to_share))
        .route("/share/{share}/item/folder", put(folders::move_items))
        .route(
            "/share/{share}/item/import/batch",
            post(items::import_batch),
        )
        .route(
            "/share/{share}/item/{item}",
            get(items::get).put(items::update),
        )
        .route("/share/{share}/item/{item}/revision", get(items::revisions))
        .route(
            "/share/{share}/item/{item}/revisions",
            axum::routing::delete(items::clear_revisions),
        )
        .route(
            "/share/{share}/item/{item}/pin",
            post(items::pin).delete(items::unpin),
        )
        .route("/share/{share}/item/{item}/flags", put(items::flags))
        .route("/share/{share}/item/{item}/lastuse", put(items::last_use))
        .route("/share/{share}/item/{item}/key", get(items::keys))
        .route(
            "/share/{share}/item/{item}/key/latest",
            get(items::latest_key_handler),
        )
        // folders
        .route(
            "/share/{share}/folder",
            get(folders::list)
                .post(folders::create)
                .delete(folders::delete),
        )
        .route(
            "/share/{share}/folder/{folder}",
            get(folders::get).put(folders::update),
        )
        .route(
            "/share/{share}/folder/{folder}/move",
            put(folders::move_folder),
        )
}
