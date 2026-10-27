//! gateway — a personal LLM gateway.
//!
//! Layers (one-way dependencies, bottom-up):
//! - `protocol`: protocol kernels (validate/prepare/observe), the bounded SSE
//!   framer and usage evidence — pure data transformations producing `Prepared` DTOs;
//! - `metering`: usage certainty classification, a leaf module;
//! - `translation`: hub-and-spoke IR translation, a pure-function layer;
//! - `upstream`: connection layer (DNS target policy + bounded HTTP client), consuming `Prepared`;
//! - `relay`: orchestration layer (route/direct model resolution, key failover), composing the layers above;
//! - `providers`: upstream auth injection; `store`: persistence;
//! - `gateway`: the composition root, the assembly entry point shared by the binary and lib embedding ([`gateway::Gateway`]).
//!
//! The binary entry point is `src/bin/main.rs` — a thin shell that installs
//! logging, loads config, and waits for signals. Test hosts embedding the
//! crate call `gateway::gateway::Gateway::start` directly.

pub mod access_log;
pub mod activity;
pub mod admin;
pub mod admin_ops;
pub mod agent;
pub mod api;
pub mod body_log;
pub mod client;
pub mod config;
pub mod db;
pub mod gateway;
pub mod http_client;
pub mod kiro;
pub mod metering;
pub mod models;
pub mod prices;
pub mod probe;
pub mod protocol;
pub mod providers;
pub mod quota;
pub mod relay;
pub mod standalone;
pub mod store;
pub mod translation;
pub mod upstream;
pub mod user_usage;

/// This crate's schema migrator (`migrations/`). Composition roots run it
/// once at startup via `crate::db::Db::migrate("gateway", gateway::migrator())`.
pub fn migrator() -> sqlx::migrate::Migrator {
    sqlx::migrate!("./migrations")
}
