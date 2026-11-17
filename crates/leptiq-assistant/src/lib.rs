//! Leptiq Assistant: the server side of Proton's Lumo clients, as a
//! [`Product`] on top of `leptiq-core`.
//!
//! - `ai/v1/chat/completions` forwards conversations to any OpenAI-compatible
//!   chat API (`[assistant]` config); prompts and answers are end-to-end
//!   encrypted between the client and this server with Lumo's U2L scheme.
//! - `lumo/v1/...` stores conversations as client ciphertext.

mod chat;
mod keys;
mod store;

use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

use axum::{
    Json, Router,
    extract::State,
    http::header,
    response::IntoResponse,
    routing::{get, post, put},
};
use leptiq_core::{AppState, Config, Product, error::ApiResult, util::ok};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::OnceCell;

/// The `[assistant]` config section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AssistantConfig {
    /// OpenAI-compatible API base (`<base_url>/chat/completions`).
    pub base_url: String,
    /// Bearer token for the API ("" sends none).
    pub api_key: String,
    /// Model used for every request, unless `models` maps the client's model.
    pub model: String,
    /// Client model name (`lumo-lite`, `lumo-max`...) to upstream model.
    pub models: BTreeMap<String, String>,
    /// Optional cap on generated tokens.
    pub max_tokens: Option<u32>,
    /// Optional system prompt added before the conversation.
    pub system_prompt: String,
    /// Armored private key for U2L encryption. Empty: generated on first
    /// start and kept in the database.
    pub server_key_file: String,
}

impl Default for AssistantConfig {
    fn default() -> Self {
        Self {
            // OpenCode Zen; `public` is its anonymous key for free models.
            base_url: "https://opencode.ai/zen/v1".into(),
            api_key: "public".into(),
            model: "big-pickle".into(),
            models: BTreeMap::new(),
            max_tokens: None,
            system_prompt: String::new(),
            server_key_file: String::new(),
        }
    }
}

/// Assistant database migrations (versions 4000+).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

type KeyCell = Arc<OnceCell<keys::ServerKey>>;

pub struct AssistantProduct;

/// The Assistant product, ready to register with the server.
pub fn product() -> Arc<dyn Product> {
    Arc::new(AssistantProduct)
}

pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(concat!("leptiq/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client")
    })
}

/// The server's U2L key, loaded (or generated) on first use.
pub async fn server_key(state: &AppState) -> anyhow::Result<keys::ServerKey> {
    let cell = state.ext::<KeyCell>().clone();
    let path = state.ext::<AssistantConfig>().server_key_file.clone();
    let key = cell
        .get_or_try_init(|| async { keys::load(&state.db, Some(&path)).await })
        .await?;
    Ok(key.clone())
}

impl Product for AssistantProduct {
    fn name(&self) -> &'static str {
        "lumo"
    }

    fn migrator(&self) -> &'static sqlx::migrate::Migrator {
        &MIGRATOR
    }

    fn init(&self, config: &Config, ext: &mut http::Extensions) -> anyhow::Result<()> {
        ext.insert(config.section::<AssistantConfig>("assistant")?);
        ext.insert(KeyCell::default());
        Ok(())
    }

    fn feature_flags(&self) -> Vec<&'static str> {
        // Guest mode needs no account; Leptiq requires sign-in.
        vec!["LumoDeactivateGuestModeFrontend"]
    }

    fn routes(&self, _state: &AppState) -> Router<AppState> {
        Router::new()
            // Generation.
            .route("/ai/v1/chat/completions", post(chat::completions))
            .route("/ai/v1/models", get(models))
            .route("/ai/v1/limits", get(limits))
            .route("/ai/v1/feedback", post(|| async { ok(json!({})) }))
            .route("/assistant/public-key", get(public_key))
            // Storage.
            .route(
                "/lumo/v1/masterkeys",
                get(store::get_master_keys).post(store::post_master_key),
            )
            .route(
                "/lumo/v1/spaces",
                get(store::list_spaces)
                    .post(store::create_space)
                    .delete(store::delete_all_spaces),
            )
            .route(
                "/lumo/v1/spaces/{id}",
                get(store::get_space)
                    .put(store::update_space)
                    .delete(store::delete_space),
            )
            .route(
                "/lumo/v1/spaces/{id}/conversations",
                post(store::create_conversation),
            )
            .route("/lumo/v1/spaces/{id}/assets", post(store::create_asset))
            .route(
                "/lumo/v1/conversations/{id}",
                get(store::get_conversation)
                    .put(store::update_conversation)
                    .delete(store::delete_conversation),
            )
            .route(
                "/lumo/v1/conversations/{id}/messages",
                post(store::create_message),
            )
            .route(
                "/lumo/v1/messages/{id}",
                get(store::get_message).delete(store::delete_message),
            )
            .route(
                "/lumo/v1/assets/{id}",
                get(store::get_asset)
                    .put(store::update_asset)
                    .delete(store::delete_asset),
            )
            .route(
                "/lumo/v1/assets/generated",
                get(|| async { ok(json!({ "Assets": [] })) }),
            )
            .route(
                "/lumo/v1/settings",
                get(store::get_settings)
                    .post(store::put_settings)
                    .put(store::put_settings),
            )
            .route(
                "/lumo/v1/skills",
                get(|| async { ok(json!({ "Skills": [] })) }),
            )
            .route(
                "/lumo/v1/invitation/remaining",
                get(|| async { ok(json!({ "Remaining": 0 })) }),
            )
            .route("/lumo/v1/events/latest", get(store::latest_event))
            .route("/lumo/v1/events/{id}", get(store::events))
            .route("/lumo/v1/settings/{*rest}", put(|| async { ok(json!({})) }))
    }
}

/// The models clients can pick; all map to the configured upstream model(s).
async fn models(State(state): State<AppState>) -> Json<Value> {
    let config = state.ext::<AssistantConfig>();
    let data: Vec<Value> = ["lumo-lite", "lumo-max"]
        .iter()
        .map(|id| {
            json!({
                "object": "model", "id": id, "created": 0, "owned_by": "leptiq",
                "max_context_length": 128_000,
                "name": config.models.get(*id).unwrap_or(&config.model),
            })
        })
        .collect();
    Json(json!({ "object": "list", "data": data }))
}

/// No per-user quotas on a self-hosted server (the upstream may still limit).
async fn limits() -> Json<Value> {
    Json(json!({ "Code": 1000, "limits": { "lite": 1_000_000, "max": 1_000_000, "images": 0 } }))
}

/// The armored public key Lumo clients must be built with
/// (`LUMO_PUB_KEY_PATH`).
async fn public_key(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let key = server_key(&state)
        .await
        .map_err(leptiq_core::error::ApiError::internal)?;
    Ok((
        [(header::CONTENT_TYPE, "application/pgp-keys")],
        key.public_armored,
    ))
}
