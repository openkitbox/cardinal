//! Upstream connection layer.
//!
//! Owns everything about *reaching* a provider: DNS resolution with
//! destination policy (`dns`), the bounded HTTP client (`transport`), and
//! egress proxy handling. This layer consumes the protocol-neutral
//! [`crate::protocol::Prepared`] DTO and returns raw bytes / SSE frames —
//! it never interprets protocol payloads, never sees credentials beyond
//! pass-through injection, and performs exactly one send per attempt
//! (retry policy belongs to `relay`). The one exception is `cursor_run`: a
//! Cursor Run is two HTTP legs that must be driven together, and the driver
//! answers the protocol's own bookkeeping requests (blob lookups, the tool
//! list) from a plan the kernel prepared — still without reading the model's
//! words.

pub mod cursor_run;
pub mod cursor_tokens;
pub mod cursor_usage;
pub(crate) mod dns;
pub mod kiro_tokens;
pub mod openai_tokens;
pub mod opencode_tokens;
pub mod transport;

pub use cursor_tokens::{CursorTokenError, CursorTokens};
pub use cursor_usage::CursorUsage;
pub use kiro_tokens::{KiroCallContext, KiroProbeCredential, KiroTokenError, KiroTokens};
pub use openai_tokens::{OpenaiBearer, OpenaiTokenError, OpenaiTokens};
pub use opencode_tokens::{OpencodeTokenError, OpencodeTokens};
