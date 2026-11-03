//! Native Kiro upstream support: the OAuth credential bundle shared by the
//! admin surface, the store and (later) the relay, plus the KAS wire profile
//! ([`profile`]) that owns the client identity and retry-header grammar, and
//! the GPT model-alias mapping ([`gpt_model`]).
//!
//! Kiro authenticates with AWS SSO OIDC (device-code / Builder ID), not an
//! API key: a key row of `auth_kind = "kiro_oidc"` carries [`KiroOAuth`] in
//! `gateway_provider_keys.oauth` instead of `api_key`. The credential *kind*
//! vocabulary lives in [`crate::credentials`]; this module owns only the Kiro
//! bundle and the pure Kiro-specific decisions over it. Nothing here performs
//! I/O.

mod credentials;
mod models;
pub mod profile;

pub use credentials::{
    AuthMethod, KiroOAuth, kas_endpoint_matches, parse_import_credentials, valid_region,
};
pub use models::gpt_model;
pub use profile::KasCall;
