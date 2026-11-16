//! Proton Pass API (`pass/v1/...`).

pub mod alias;
pub mod files;
pub mod folders;
pub mod invites;
pub mod items;
pub mod keys;
pub mod members;
pub mod public_links;
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
        .route("/share/{share}/key", get(shares::keys).post(keys::rotate))
        .route(
            "/share/{share}/key/pending",
            get(keys::pending).post(keys::promote),
        )
        // members
        .route("/share/{share}/user", get(members::list))
        .route(
            "/share/{share}/user/item/{item}",
            get(members::list_for_item),
        )
        .route(
            "/share/{share}/user/{member}",
            get(members::get)
                .put(members::update)
                .delete(members::remove),
        )
        // invites
        .route(
            "/share/{share}/invite",
            get(invites::list_for_share).post(invites::create),
        )
        .route("/share/{share}/invite/batch", post(invites::create_batch))
        .route(
            "/share/{share}/invite/check_address",
            post(invites::check_address),
        )
        .route(
            "/share/{share}/invite/new_user",
            post(invites::create_new_user_invite),
        )
        .route(
            "/share/{share}/invite/new_user/batch",
            post(invites::create_new_user_batch),
        )
        .route(
            "/share/{share}/invite/new_user/{invite}",
            axum::routing::delete(invites::delete_new_user),
        )
        .route(
            "/share/{share}/invite/new_user/{invite}/keys",
            post(invites::promote_new_user),
        )
        .route(
            "/share/{share}/invite/recommended_emails",
            get(invites::recommended),
        )
        .route(
            "/share/{share}/invite/recommended_emails/organization",
            get(invites::recommended_org),
        )
        .route(
            "/share/{share}/invite/recommended_emails/suggested",
            get(invites::recommended_suggested),
        )
        .route(
            "/share/{share}/invite/{invite}",
            axum::routing::delete(invites::delete_for_share),
        )
        .route(
            "/share/{share}/invite/{invite}/reminder",
            post(invites::reminder),
        )
        .route("/invite", get(invites::list_mine))
        .route("/invite/group", get(invites::group_invites))
        .route(
            "/invite/{token}",
            post(invites::accept).delete(invites::reject),
        )
        // files
        .route("/file", post(files::create_pending))
        .route("/file/{file}/metadata", put(files::update_pending_metadata))
        .route(
            "/file/{file}/chunk",
            post(files::upload_chunk).layer(axum::extract::DefaultBodyLimit::max(
                files::MAX_CHUNK + 64 * 1024,
            )),
        )
        .route(
            "/share/{share}/item/{item}/link_files",
            post(files::link_files),
        )
        .route("/share/{share}/item/{item}/files", get(files::item_files))
        .route(
            "/share/{share}/item/{item}/revisions/files",
            get(files::item_revision_files),
        )
        .route(
            "/share/{share}/item/{item}/file/restore",
            post(files::restore_batch),
        )
        .route(
            "/share/{share}/item/{item}/file/{file}/metadata",
            put(files::update_metadata),
        )
        .route(
            "/share/{share}/item/{item}/file/{file}/restore",
            post(files::restore),
        )
        .route(
            "/share/{share}/item/{item}/file/{file}/chunk/{chunk}",
            get(files::download_chunk),
        )
        .route("/vault/usage/{share}", get(files::vault_usage))
        .route("/public_link/files/{token}", get(files::public_files))
        .route(
            "/public_link/files/{token}/{file}/{chunk}",
            get(files::public_chunk),
        )
        // public links
        .route(
            "/share/{share}/item/{item}/public_link",
            post(public_links::create),
        )
        .route("/public_link", get(public_links::list))
        .route(
            "/public_link/inactive",
            axum::routing::delete(public_links::delete_inactive),
        )
        .route("/public_link/content/{token}", get(public_links::content))
        .route(
            "/public_link/{id}",
            axum::routing::delete(public_links::delete),
        )
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
