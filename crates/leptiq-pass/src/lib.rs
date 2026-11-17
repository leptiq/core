//! Leptiq Pass: the Proton Pass API (`pass/v1/...`), aliases and personal
//! access tokens, as a [`Product`] on top of `leptiq-core`.

pub mod alias;
pub mod files;
pub mod folders;
pub mod invites;
pub mod items;
pub mod keys;
pub mod members;
pub mod org;
pub mod pat;
pub mod public_links;
pub mod security;
pub mod shares;
pub mod sync;
pub mod user;
pub mod vaults;

use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};
use futures_util::future::BoxFuture;
use leptiq_core::Product;

// Core modules, re-exported so Pass code can keep writing `crate::app`,
// `crate::auth`, ... for the shared platform.
pub(crate) use leptiq_core::{app, auth, config, core, db, error, events, sql, util};

use crate::app::AppState;

/// Pass database migrations (versions 1000+).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Proton Pass as a Leptiq product.
pub struct PassProduct;

/// The Pass product, ready to register with the server.
pub fn product() -> Arc<dyn Product> {
    Arc::new(PassProduct)
}

impl Product for PassProduct {
    fn name(&self) -> &'static str {
        "pass"
    }

    fn migrator(&self) -> &'static sqlx::migrate::Migrator {
        &MIGRATOR
    }

    fn init(&self, config: &config::Config, ext: &mut http::Extensions) -> anyhow::Result<()> {
        ext.insert(files::BlobStore::new(&config.data_dir)?);
        Ok(())
    }

    fn routes(&self, state: &AppState) -> Router<AppState> {
        Router::new()
            .nest(
                "/pass/v1",
                routes().layer(middleware::from_fn_with_state(
                    state.clone(),
                    security::guard,
                )),
            )
            // Personal access tokens (used by the Pass CLI) live under the
            // account API path.
            .route(
                "/account/v4/personal-access-token",
                get(pat::list).post(pat::create),
            )
            .route(
                "/account/v4/personal-access-token/session",
                post(pat::session),
            )
            .route(
                "/account/v4/personal-access-token/{id}",
                delete(pat::delete),
            )
    }

    fn spawn_background(&self, state: &AppState) {
        let s = state.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = files::cleanup(&s).await {
                    tracing::warn!("file cleanup failed: {e:?}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
        alias::smtp::spawn(state.clone());
    }

    fn on_address_created<'a>(
        &'a self,
        tx: &'a mut db::Tx<'_>,
        email: &'a str,
    ) -> BoxFuture<'a, error::ApiResult<()>> {
        Box::pin(invites::on_address_created(tx, email))
    }

    fn on_user_deleted<'a>(
        &'a self,
        state: &'a AppState,
        user_id: &'a str,
    ) -> BoxFuture<'a, error::ApiResult<()>> {
        Box::pin(shares::delete_all_for_user(state, user_id))
    }
}

fn routes() -> Router<AppState> {
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
        .route(
            "/user/session/lock",
            post(security::create_lock).delete(security::delete_lock),
        )
        .route("/user/session/lock/check", get(security::check))
        .route("/user/session/lock/unlock", post(security::unlock))
        .route("/user/session/lock/force_lock", post(security::force_lock))
        .route(
            "/user/srp",
            get(security::has_srp)
                .post(security::add_srp)
                .delete(security::remove_srp),
        )
        .route("/user/srp/info", get(security::srp_info))
        .route("/user/srp/auth", post(security::srp_auth))
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
        // aliases
        .route("/share/{share}/alias/options", get(alias::options))
        .route("/share/{share}/alias/custom", post(alias::create_custom))
        .route("/share/{share}/alias/random", post(alias::create_random))
        .route("/share/{share}/alias/bulk/get", post(alias::bulk_get))
        .route(
            "/share/{share}/item/with_alias",
            post(alias::create_with_item),
        )
        .route("/share/{share}/alias/{item}", get(alias::get))
        .route(
            "/share/{share}/alias/{item}/mailbox",
            post(alias::set_mailboxes),
        )
        .route("/share/{share}/alias/{item}/name", put(alias::set_name))
        .route("/share/{share}/alias/{item}/note", put(alias::set_note))
        .route("/share/{share}/alias/{item}/status", put(alias::set_status))
        .route(
            "/share/{share}/alias/{item}/contact",
            get(alias::list_contacts).post(alias::create_contact),
        )
        .route(
            "/share/{share}/alias/{item}/contact/{contact}",
            get(alias::get_contact).delete(alias::delete_contact),
        )
        .route(
            "/share/{share}/alias/{item}/contact/{contact}/blocked",
            put(alias::block_contact),
        )
        .route("/share/{share}/alias/{item}/breaches", get(alias::breaches))
        .route(
            "/share/{share}/alias/{item}/breaches/resolved",
            post(alias::breaches_resolved),
        )
        .route(
            "/share/{share}/alias/{item}/breaches/{breach}/resolve",
            post(alias::breach_resolve),
        )
        .route("/user/alias/settings", get(alias::get_settings))
        .route(
            "/user/alias/settings/default_alias_domain",
            put(alias::set_default_domain),
        )
        .route(
            "/user/alias/settings/default_mailbox_id",
            put(alias::set_default_mailbox),
        )
        .route("/user/alias/domain", get(alias::list_domains))
        .route("/user/alias/count", get(alias::count))
        .route("/user/alias/missing", get(alias::missing))
        .route(
            "/user/alias/mailbox",
            get(alias::mailboxes::list).post(alias::mailboxes::create),
        )
        .route(
            "/user/alias/mailbox/{id}",
            axum::routing::delete(alias::mailboxes::delete),
        )
        .route(
            "/user/alias/mailbox/{id}/verify",
            post(alias::mailboxes::verify).get(alias::mailboxes::resend),
        )
        .route(
            "/user/alias/mailbox/{id}/email",
            put(alias::mailboxes::change_email).delete(alias::mailboxes::cancel_email_change),
        )
        .route(
            "/user/alias/custom_domain",
            get(alias::domains::list).post(alias::domains::create),
        )
        .route(
            "/user/alias/custom_domain/{id}",
            get(alias::domains::get)
                .post(alias::domains::verify)
                .delete(alias::domains::delete),
        )
        .route(
            "/user/alias/custom_domain/{id}/settings",
            get(alias::domains::get_settings),
        )
        .route(
            "/user/alias/custom_domain/{id}/settings/catch_all",
            put(alias::domains::set_catch_all),
        )
        .route(
            "/user/alias/custom_domain/{id}/settings/mailboxes",
            put(alias::domains::set_mailboxes),
        )
        .route(
            "/user/alias/custom_domain/{id}/settings/name",
            put(alias::domains::set_name),
        )
        .route(
            "/user/alias/custom_domain/{id}/settings/random_prefix",
            put(alias::domains::set_random_prefix),
        )
        .route("/alias_sync/pending", get(alias::sl_pending))
        .route("/alias_sync/status", get(alias::sl_status))
        .route("/alias_sync/sync", post(alias::sl_disabled))
        .route(
            "/alias_sync/share/{share}/create",
            post(alias::sl_disabled_share),
        )
        // organization
        .route("/organization", get(org::get))
        .route("/organization/settings", put(org::update))
        .route(
            "/organization/settings/password_policy",
            put(org::update_password_policy),
        )
        .route("/organization/report", get(org::reports))
        .route("/organization/report/client_data", post(org::store_report))
        .route(
            "/organization/report/user_shares",
            get(org::user_shares_report),
        )
        .route(
            "/organization/urlpause",
            get(org::list_pauses).post(org::create_pause),
        )
        .route(
            "/organization/urlpause/{id}",
            put(org::update_pause).delete(org::delete_pause),
        )
        // breach monitoring (no data source)
        .route("/breach", get(org::breaches))
        .route("/breach/address/{a}/breaches", get(org::breaches))
        .route("/breach/address/{a}/monitor", put(org::breach_noop))
        .route("/breach/address/{a}/resolved", post(org::breach_noop))
        .route("/breach/custom_email", post(org::breach_unavailable))
        .route(
            "/breach/custom_email/{e}",
            axum::routing::delete(org::breach_noop),
        )
        .route("/breach/custom_email/{e}/breaches", get(org::breaches))
        .route(
            "/breach/custom_email/{e}/breaches/{b}/resolve",
            put(org::breach_noop),
        )
        .route(
            "/breach/custom_email/{e}/monitor",
            put(org::breach_unavailable),
        )
        .route(
            "/breach/custom_email/{e}/resend_verification",
            post(org::breach_unavailable),
        )
        .route(
            "/breach/custom_email/{e}/resolved",
            put(org::breach_unavailable),
        )
        .route(
            "/breach/custom_email/{e}/verify",
            put(org::breach_unavailable),
        )
        // personal access tokens
        .route("/personal-access-token/{pat}/access", post(pat::grant))
        .route(
            "/personal-access-token/{pat}/access/{share}",
            axum::routing::delete(pat::revoke),
        )
        .route("/pat/monitor", post(pat::monitor_store))
        .route("/pat/monitor/{pat}", get(pat::monitor_list))
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
