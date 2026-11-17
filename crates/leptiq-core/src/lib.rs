#![recursion_limit = "512"]
//! leptiq-core: the shared platform of Leptiq, a self-hostable server for the
//! official Proton apps (accounts, auth, sessions, keys, events, storage).
//!
//! The server is zero-knowledge: it stores and relays the encrypted blobs,
//! OpenPGP keys and SRP verifiers produced by clients. Its only real
//! cryptographic job is SRP verification during login.

pub mod app;
pub mod auth;
pub mod config;
pub mod core;
pub mod db;
pub mod error;
pub mod events;
pub mod product;
pub mod srp;
pub mod util;

pub use app::{AppState, build_router};
pub use config::Config;
pub use product::Product;
