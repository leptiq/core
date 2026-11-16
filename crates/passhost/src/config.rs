use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignupPolicy {
    /// Anyone can create an account.
    Open,
    /// Accounts need an invite code created with `passhost admin invite`.
    Invite,
    /// Only admins can create accounts.
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to listen on.
    pub bind: String,
    /// sqlx database URL: `sqlite://data/passhost.db?mode=rwc` or `postgres://...`.
    pub database_url: String,
    /// Path prefixes the API is served under. Clients use `/api` on the web
    /// and a bare host for `api.<domain>` style deployments; both work.
    pub base_paths: Vec<String>,
    /// Public URL of this instance (used for links in emails, public links...).
    pub public_url: String,
    /// The mail domain users get addresses on (`user@<mail_domain>`).
    pub mail_domain: String,
    pub signup: SignupPolicy,
    /// Reject requests without an `x-pm-appversion` header (like Proton does).
    pub require_app_version: bool,
    /// Optional path to an armored, clearsigned SRP modulus. Defaults to the
    /// publicly known modulus signed by Proton, which unmodified clients accept.
    pub srp_modulus_file: Option<String>,
    /// Directory for attachments and other blobs.
    pub data_dir: String,
    /// Access token lifetime in seconds.
    pub access_token_ttl: i64,
    /// Refresh token lifetime in seconds.
    pub refresh_token_ttl: i64,
    /// Secret used for HMAC signatures (alias suffixes, ...). Generated if empty.
    pub secret_key: String,
    /// Allowed CORS origins ("*" for any).
    pub cors_origins: Vec<String>,
    /// Per-user storage quota for attachments, in bytes.
    pub file_quota_bytes: i64,
    pub alias: AliasConfig,
    pub smtp: SmtpConfig,
    /// WebAuthn relying party id (usually the parent domain of account/pass apps).
    pub webauthn_rp_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasConfig {
    pub enabled: bool,
    /// Domains aliases can be created on.
    pub domains: Vec<String>,
    /// Address the inbound SMTP server listens on (e.g. "0.0.0.0:25"). Empty disables it.
    pub smtp_listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// Outbound relay host. Empty disables sending mail (codes are logged instead).
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    /// "starttls", "tls" or "none".
    pub security: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".into(),
            database_url: "sqlite://passhost.db?mode=rwc".into(),
            base_paths: vec!["/api".into(), "".into()],
            public_url: "http://localhost:8080".into(),
            mail_domain: "passhost.local".into(),
            signup: SignupPolicy::Open,
            require_app_version: true,
            srp_modulus_file: None,
            data_dir: "data".into(),
            access_token_ttl: 24 * 3600,
            refresh_token_ttl: 180 * 24 * 3600,
            secret_key: String::new(),
            cors_origins: vec!["*".into()],
            file_quota_bytes: 10 * 1024 * 1024 * 1024,
            alias: AliasConfig {
                enabled: false,
                domains: vec![],
                smtp_listen: String::new(),
            },
            smtp: SmtpConfig {
                host: String::new(),
                port: 587,
                username: String::new(),
                password: String::new(),
                from: "passhost@localhost".into(),
                security: "starttls".into(),
            },
            webauthn_rp_id: "localhost".into(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let config: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(path))
            .merge(Env::prefixed("PASSHOST_").split("__"))
            .extract()?;
        Ok(config)
    }
}
