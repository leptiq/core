//! Leptiq Drive: the Proton Drive API (`drive/...`) used by the official
//! Drive clients through Proton's Drive SDK, as a [`Product`] on top of
//! `leptiq-core`.
//!
//! The server is zero-knowledge: names, keys, passphrases, extended
//! attributes and file blocks are client ciphertext. It only checks name-hash
//! uniqueness, tracks revisions and sizes, and hashes stored blocks so the
//! client can verify them.

mod files;
mod model;
mod nodes;
mod volumes;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    routing::{get, post, put},
};
use leptiq_core::{
    AppState, Config, Product,
    auth::AuthUser,
    error::ApiResult,
    util::{ok, ok_empty},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The `[drive]` config section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DriveConfig {
    /// Base URL clients upload and download file blocks to/from (a token is
    /// appended). Relative URLs are resolved against the Drive web app's
    /// origin, whose `/api` is proxied to this server.
    pub storage_url: String,
}

impl Default for DriveConfig {
    fn default() -> Self {
        Self {
            storage_url: "/api/drive/storage".into(),
        }
    }
}

/// Drive database migrations (versions 3000+).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub struct DriveProduct;

/// The Drive product, ready to register with the server.
pub fn product() -> Arc<dyn Product> {
    Arc::new(DriveProduct)
}

impl Product for DriveProduct {
    fn name(&self) -> &'static str {
        "drive"
    }

    fn migrator(&self) -> &'static sqlx::migrate::Migrator {
        &MIGRATOR
    }

    fn init(&self, config: &Config, ext: &mut http::Extensions) -> anyhow::Result<()> {
        ext.insert(config.section::<DriveConfig>("drive")?);
        Ok(())
    }

    fn routes(&self, _state: &AppState) -> Router<AppState> {
        Router::new()
            // Volumes, shares, roots.
            .route("/drive/volumes", get(volumes::list).post(volumes::create))
            .route("/drive/volumes/{volume}", get(volumes::get))
            .route("/drive/photos/volumes", post(volumes::create_photos))
            .route("/drive/v2/shares/my-files", get(volumes::my_files))
            .route("/drive/v2/shares/photos", get(volumes::photos))
            .route("/drive/shares/{share}", get(volumes::get_share))
            // Nodes.
            .route(
                "/drive/v2/volumes/{volume}/folders/{link}/children",
                get(nodes::children),
            )
            .route("/drive/v2/volumes/{volume}/links", post(nodes::details))
            .route("/drive/photos/volumes/{volume}/links", post(nodes::details))
            .route(
                "/drive/v2/volumes/{volume}/folders",
                post(nodes::create_folder),
            )
            .route(
                "/drive/v2/volumes/{volume}/links/{link}/rename",
                put(nodes::rename),
            )
            .route(
                "/drive/v2/volumes/{volume}/links/{link}/move",
                put(nodes::move_link),
            )
            .route(
                "/drive/v2/volumes/{volume}/trash_multiple",
                post(nodes::trash),
            )
            .route(
                "/drive/v2/volumes/{volume}/trash/restore_multiple",
                put(nodes::restore),
            )
            .route(
                "/drive/v2/volumes/{volume}/trash/delete_multiple",
                post(nodes::delete_trashed),
            )
            .route(
                "/drive/v2/volumes/{volume}/delete_multiple",
                post(nodes::delete_drafts),
            )
            .route(
                "/drive/volumes/{volume}/trash",
                get(nodes::list_trash).delete(nodes::empty_trash),
            )
            .route(
                "/drive/v2/volumes/{volume}/links/{link}/checkAvailableHashes",
                post(nodes::available_hashes),
            )
            .route(
                "/drive/volumes/{volume}/folders/{link}/calculate-descendents-size",
                get(nodes::descendants_size),
            )
            // Files and revisions.
            .route("/drive/v2/volumes/{volume}/files", post(files::create_file))
            .route(
                "/drive/v2/volumes/{volume}/files/{link}/revisions",
                get(files::list_revisions).post(files::create_revision_handler),
            )
            .route(
                "/drive/v2/volumes/{volume}/files/{link}/revisions/{revision}",
                get(files::get_revision)
                    .put(files::commit_revision)
                    .delete(files::delete_revision),
            )
            .route(
                "/drive/v2/volumes/{volume}/files/{link}/revisions/{revision}/restore",
                post(files::restore_revision),
            )
            .route(
                "/drive/v2/volumes/{volume}/links/{link}/revisions/{revision}/verification",
                get(files::verification),
            )
            .route("/drive/blocks", post(files::request_blocks))
            .route(
                "/drive/volumes/{volume}/thumbnails",
                post(files::thumbnails),
            )
            .route(
                "/drive/storage/{token}",
                get(files::storage_download)
                    .post(files::storage_upload)
                    .layer(DefaultBodyLimit::max(files::MAX_BLOCK + 64 * 1024)),
            )
            // Events.
            .route("/drive/volumes/{volume}/events/latest", get(latest_event))
            .route("/drive/v2/volumes/{volume}/events/{event}", get(events))
            .route("/drive/volumes/{volume}/events/{event}", get(events))
            // Settings and features without data on a self-hosted server.
            .route("/drive/me/settings", get(get_settings).put(put_settings))
            .route("/drive/me/active", get(|| async { ok_empty() }))
            .route(
                "/drive/devices",
                get(|| async { ok(json!({ "Devices": [] })) }),
            )
            .route("/drive/v2/sharedwithme", get(empty_page("Links")))
            .route(
                "/drive/v2/shares/invitations",
                get(empty_page("Invitations")),
            )
            .route(
                "/drive/v2/shares/external-invitations",
                get(empty_page("ExternalInvitations")),
            )
            .route(
                "/drive/v2/shared-bookmarks",
                get(|| async { ok(json!({ "Bookmarks": [] })) }),
            )
            .route(
                "/drive/v2/volumes/{volume}/shares",
                get(empty_page("Links")),
            )
            .route(
                "/drive/migrations/shareaccesswithnode/unmigrated",
                get(|| async { ok(json!({ "ShareIDs": [] })) }),
            )
            .route(
                "/drive/v2/onboarding",
                get(|| async { ok(json!({ "IsFreshAccount": false })) }),
            )
            .route(
                "/drive/v2/onboarding/fresh-account",
                get(|| async { ok(json!({ "EndTime": null })) }),
            )
            .route(
                "/drive/volumes/{volume}/photos",
                get(|| async { ok(json!({ "Photos": [] })) }),
            )
            .route(
                "/drive/photos/volumes/{volume}/albums",
                get(empty_page("Albums")),
            )
            .route(
                "/drive/photos/albums/shared-with-me",
                get(empty_page("Albums")),
            )
            .route(
                "/drive/v2/user-link-access",
                get(|| async { ok(json!({ "Links": [] })) }),
            )
    }

    fn skips_app_version(&self, path: &str) -> bool {
        // Block uploads/downloads are plain fetches with a storage token.
        path.contains("/drive/storage/")
    }

    fn spawn_background(&self, state: &AppState) {
        let s = state.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = files::cleanup(&s).await {
                    tracing::warn!("drive token cleanup failed: {e:?}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
    }
}

/// A paginated list that is always empty (`{<field>: [], AnchorID, More}`).
fn empty_page(
    field: &'static str,
) -> impl Fn() -> std::future::Ready<Json<Value>> + Clone + Send + 'static {
    move || std::future::ready(ok(json!({ field: [], "AnchorID": null, "More": false })))
}

fn event_id(seq: i64) -> String {
    format!("{seq:020}")
}

async fn latest_seq(state: &AppState, volume_id: &str) -> ApiResult<i64> {
    let (seq,): (Option<i64>,) =
        sqlx::query_as("SELECT MAX(seq) FROM drive_events WHERE volume_id = $1")
            .bind(volume_id)
            .fetch_one(&state.db)
            .await?;
    Ok(seq.unwrap_or(0))
}

async fn latest_event(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    Ok(ok(
        json!({ "EventID": event_id(latest_seq(&state, &v.id).await?) }),
    ))
}

const EVENTS_PAGE: i64 = 100;

/// `GET drive/v2/volumes/{v}/events/{id}`: changes after `id`.
async fn events(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, event)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let latest = latest_seq(&state, &v.id).await?;
    let Ok(since) = event.parse::<i64>() else {
        return Ok(ok(json!({
            "Events": [], "ConvertibleExternalInvitations": [], "EventID": event_id(latest),
            "More": false, "Refresh": true, "DisableSdkQuotaChecks": false,
        })));
    };
    let rows: Vec<(i64, i64, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT seq, event_type, link_id, parent_id, is_trashed FROM drive_events \
         WHERE volume_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
    )
    .bind(&v.id)
    .bind(since)
    .bind(EVENTS_PAGE)
    .fetch_all(&state.db)
    .await?;
    let last = rows.last().map(|r| r.0).unwrap_or(since.min(latest));
    let events: Vec<Value> = rows
        .iter()
        .map(|(seq, ty, link, parent, trashed)| {
            json!({
                "EventID": event_id(*seq),
                "EventType": ty,
                "Link": { "LinkID": link, "ParentLinkID": parent, "IsShared": false, "IsTrashed": *trashed != 0 },
            })
        })
        .collect();
    Ok(ok(json!({
        "Events": events,
        "ConvertibleExternalInvitations": [],
        "EventID": event_id(last),
        "More": last < latest,
        "Refresh": since > latest,
        "DisableSdkQuotaChecks": false,
    })))
}

fn default_settings() -> Value {
    json!({
        "Layout": null, "Sort": null, "RevisionRetentionDays": null, "PhotoTags": null,
        "B2BPhotosEnabled": null,
    })
}

async fn get_settings(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT settings FROM drive_settings WHERE user_id = $1")
            .bind(&user.user_id)
            .fetch_optional(&state.db)
            .await?;
    let mut settings = default_settings();
    if let Some((s,)) = row
        && let Ok(Value::Object(saved)) = serde_json::from_str::<Value>(&s)
    {
        for (k, v) in saved {
            settings[k] = v;
        }
    }
    Ok(ok(json!({
        "UserSettings": settings,
        "Defaults": {
            "RevisionRetentionDays": 30,
            "PhotoTags": [],
            "B2BPhotosEnabled": false,
            "DocsCommentsNotificationsEnabled": false,
            "DocsCommentsNotificationsIncludeDocumentName": false,
        },
    })))
}

async fn put_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Json(patch): Json<Value>,
) -> ApiResult<Json<Value>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT settings FROM drive_settings WHERE user_id = $1")
            .bind(&user.user_id)
            .fetch_optional(&state.db)
            .await?;
    let mut saved: Value = row
        .and_then(|(s,)| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));
    if let (Value::Object(saved), Value::Object(patch)) = (&mut saved, patch) {
        for (k, v) in patch {
            saved.insert(k, v);
        }
    }
    sqlx::query(
        "INSERT INTO drive_settings (user_id, settings) VALUES ($1, $2) \
         ON CONFLICT (user_id) DO UPDATE SET settings = excluded.settings",
    )
    .bind(&user.user_id)
    .bind(saved.to_string())
    .execute(&state.db)
    .await?;
    get_settings(State(state), user).await
}
