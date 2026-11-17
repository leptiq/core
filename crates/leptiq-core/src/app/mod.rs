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
    product::Product,
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
    /// The products this server runs (Pass, ...).
    pub products: Vec<Arc<dyn Product>>,
    /// Product-owned runtime state, set up by [`Product::init`].
    ext: http::Extensions,
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    /// Builds the state for `products`, running their migrations and
    /// [`Product::init`]. Core migrations must already have run
    /// ([`crate::db::migrate`]).
    pub async fn new(
        config: Config,
        db: Pool,
        products: Vec<Arc<dyn Product>>,
    ) -> anyhow::Result<Self> {
        let modulus = SrpModulus::load(config.srp_modulus_file.as_deref())?;
        let secret = if config.secret_key.is_empty() {
            load_or_create_secret(&db).await?
        } else {
            config.secret_key.as_bytes().to_vec()
        };
        let mut ext = http::Extensions::new();
        for product in &products {
            product.init(&config, &mut ext)?;
        }
        Ok(Self(Arc::new(Inner {
            config,
            db,
            modulus,
            secret,
            products,
            ext,
        })))
    }

    /// Product-owned state stored by [`Product::init`].
    ///
    /// Panics if no product registered a value of this type: that is a
    /// wiring bug, not a runtime condition.
    pub fn ext<T: Send + Sync + Clone + 'static>(&self) -> &T {
        self.0.ext.get::<T>().unwrap_or_else(|| {
            panic!(
                "no {} registered by any product",
                std::any::type_name::<T>()
            )
        })
    }

    /// Starts background jobs: core's expired-session cleanup plus each
    /// product's own jobs.
    pub fn spawn_background_tasks(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = crate::auth::sessions::cleanup(&state).await {
                    tracing::warn!("session cleanup failed: {e:?}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
        for product in &self.products {
            product.spawn_background(self);
        }
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
fn api_routes(state: &AppState) -> Router<AppState> {
    let mut router = Router::new()
        .route("/tests/ping", get(|| async { crate::util::ok_empty() }))
        .merge(crate::auth::routes())
        .merge(crate::core::routes());
    for product in &state.products {
        router = router.merge(product.routes(state));
    }
    router
}

pub fn build_router(state: AppState) -> Router {
    let api = api_routes(&state).layer(middleware::from_fn_with_state(state.clone(), app_version));
    // Proton's anti-abuse challenge iframe (served on `account-api.<domain>`);
    // loaded by a plain iframe, so it is outside the app-version check.
    let mut router = Router::new().route(
        "/challenge/v4/html",
        get(|| async {
            (
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                include_str!("challenge.html"),
            )
        }),
    );
    // The Leptiq mark, for browsers that open the server directly.
    let favicon = get(|| async {
        (
            [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
            include_str!("../../../../assets/leptiq-mark.svg"),
        )
    });
    router = router
        .route("/favicon.svg", favicon.clone())
        .route("/favicon.ico", favicon);
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
        // Plain browser requests (images, public links) carry no app version.
        let exempt = path.ends_with("/tests/ping")
            || path.contains("/public_link/")
            || path.ends_with("/core/v4/images/logo");
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
