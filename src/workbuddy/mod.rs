//! WorkBuddy OAuth bundle, login/refresh client, and login session registry.
//!
//! This module owns the persisted OAuth shape, the vendor wire client, and the
//! in-memory login sessions. It owns no I/O orchestration: `admin_ops` drives
//! login and the token manager caches the bundle.

pub mod auth;
pub mod login;
pub mod oauth;

pub use auth::{AccountPoll, BuildInfo, Client, LoginStart, TokenPoll, WorkbuddyError};
pub use login::{Session, SessionState, Status, WorkbuddyLogins};
pub use oauth::WorkbuddyOAuth;
