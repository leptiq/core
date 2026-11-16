pub mod admin;

use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    config::Config,
    db::Pool,
    error::{ApiError, code},
    srp::SrpModulus,
};

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

pub struct Inner {
    pub config: Config,
    pub db: Pool,
    pub modulus: SrpModulus,
    /// Server secret for HMACs (persisted in the kv table if not configured).
    pub secret: Vec<u8>,
    pub blobs: crate::pass::files::BlobStore,
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub async fn new(config: Config, db: Pool) -> anyhow::Result<Self> {
        let modulus = SrpModulus::load(config.srp_modulus_file.as_deref())?;
        let secret = if config.secret_key.is_empty() {
            load_or_create_secret(&db).await?
        } else {
            config.secret_key.as_bytes().to_vec()
        };
        let blobs = crate::pass::files::BlobStore::new(&config.data_dir)?;
        Ok(Self(Arc::new(Inner {
            config,
            db,
            modulus,
            secret,
            blobs,
        })))
    }

    /// Starts background jobs (expired session cleanup, alias SMTP server...).
    pub fn spawn_background_tasks(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = crate::auth::sessions::cleanup(&state).await {
                    tracing::warn!("session cleanup failed: {e:?}");
                }
                if let Err(e) = crate::pass::files::cleanup(&state).await {
                    tracing::warn!("file cleanup failed: {e:?}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
        crate::pass::alias::smtp::spawn(self.clone());
    }
}

async fn load_or_create_secret(db: &Pool) -> anyhow::Result<Vec<u8>> {
    let existing: Option<(String,)> = sqlx::query_as("SELECT v FROM kv WHERE k = 'secret_key'")
        .fetch_optional(db)
        .await?;
    if let Some((v,)) = existing {
        return Ok(hex::decode(v)?);
    }
    let secret = crate::util::random_bytes(32);
    sqlx::query("INSERT INTO kv (k, v) VALUES ('secret_key', $1) ON CONFLICT (k) DO NOTHING")
        .bind(hex::encode(&secret))
        .execute(db)
        .await?;
    // Another instance may have won the race; use whatever is stored.
    let (v,): (String,) = sqlx::query_as("SELECT v FROM kv WHERE k = 'secret_key'")
        .fetch_one(db)
        .await?;
    Ok(hex::decode(v)?)
}

/// All API routes, relative to a base path.
fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/tests/ping", get(|| async { crate::util::ok_empty() }))
        .merge(crate::auth::routes())
        .merge(crate::core::routes())
        .nest("/pass/v1", crate::pass::routes())
}

pub fn build_router(state: AppState) -> Router {
    let api = api_routes().layer(middleware::from_fn_with_state(state.clone(), app_version));
    let mut router = Router::new();
    for base in &state.config.base_paths {
        let base = base.trim_end_matches('/');
        router = if base.is_empty() {
            router.merge(api.clone())
        } else {
            router.nest(base, api.clone())
        };
    }
    router
        .fallback(|| async {
            ApiError::new(StatusCode::NOT_FOUND, code::NOT_FOUND, "Route not found").into_response()
        })
        .layer(cors(&state.config))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn cors(config: &Config) -> CorsLayer {
    let base = CorsLayer::new().allow_methods([
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::OPTIONS,
    ]);
    if config.cors_origins.iter().any(|o| o == "*") {
        base.allow_origin(Any)
            .allow_headers(Any)
            .expose_headers(Any)
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        base.allow_origin(AllowOrigin::list(origins))
            .allow_credentials(true)
            .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
    }
}

/// Proton requires `x-pm-appversion` on every request (`<client>@<semver>`).
async fn app_version(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.config.require_app_version && req.method() != Method::OPTIONS {
        let path = req.uri().path();
        let exempt = path.ends_with("/tests/ping") || path.contains("/public_link/");
        match req
            .headers()
            .get("x-pm-appversion")
            .and_then(|v| v.to_str().ok())
        {
            None if !exempt => {
                return ApiError::new(
                    StatusCode::BAD_REQUEST,
                    code::APP_VERSION_MISSING,
                    "Missing app version",
                )
                .into_response();
            }
            Some(v) if !exempt && !valid_app_version(v) => {
                return ApiError::new(
                    StatusCode::BAD_REQUEST,
                    code::APP_VERSION_BAD,
                    "Invalid app version",
                )
                .into_response();
            }
            _ => {}
        }
    }
    next.run(req).await
}

fn valid_app_version(v: &str) -> bool {
    // e.g. "web-pass@1.20.0", "android-pass@1.2.3", "web-pass@1.20.0+beta", "Other"
    v.contains('@') || v == "Other" || v.starts_with('_')
}
