//! Upstream connection layer.
//!
//! Owns everything about *reaching* a provider: DNS resolution with
//! destination policy (`dns`), the bounded HTTP client (`transport`), and
//! egress proxy handling. This layer consumes the protocol-neutral
//! [`crate::protocol::Prepared`] DTO and returns raw bytes / SSE frames —
//! it never interprets protocol payloads, never sees credentials beyond
//! pass-through injection, and performs exactly one send per attempt
//! (retry policy belongs to `relay`).

pub(crate) mod dns;
pub mod kiro_tokens;
pub mod transport;

pub use kiro_tokens::{KiroCallContext, KiroProbeCredential, KiroTokenError, KiroTokens};
