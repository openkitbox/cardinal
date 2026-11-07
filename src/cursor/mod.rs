//! Cursor account login (plan §2.1.2, D5): the browser handoff that turns an
//! operator's sign-in on `cursor.com` into a stored `cursor_oauth` bundle.
//!
//! - [`auth`]: the wire half — the challenge pair, the login URL, the
//!   anonymous poll and its verdicts.
//! - [`login`]: the in-memory session registry the GUI polls.
//!
//! Orchestration (start, poll loop, commit to the key row, token adoption)
//! lives in [`crate::admin_ops`]; token refresh and the per-key bearer cache
//! in [`crate::upstream::cursor_tokens`]; the bundle type itself is
//! [`crate::credentials::CursorOAuth`].

pub mod auth;
pub mod login;

pub use auth::Client;
pub use login::CursorLogins;
