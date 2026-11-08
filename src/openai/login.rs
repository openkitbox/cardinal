//! The in-memory registry of in-flight OpenAI Codex device logins.
//!
//! A device login has a human in the middle: the operator types a code at
//! [`VERIFICATION_URL`], the gateway polls the issuer, and minutes pass before
//! the verdict. This module is the state that gap needs — which sessions exist,
//! which grant each one polls, and what became of it — and nothing else: no
//! HTTP, no database, no polling loop of its own.
//!
//! It is the OpenCode registry's shape ([`crate::opencode::login`]) with a
//! user code shown to the operator and the verdict carrying the account's
//! identity. [`crate::admin_ops::Admin`] owns the orchestration and moves a
//! session to its verdict through [`Session::finish`], a compare-and-swap:
//! whichever of the poller, [`OpenaiLogins::prune`] (a waiting session whose
//! grant deadline passed) and an operator's cancel arrives first decides, and
//! the others find a terminal session and leave it alone.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use chrono::DateTime;
use chrono::Utc;
use dashmap::DashMap;
use uuid::Uuid;

/// The page the operator types the user code into.
pub const VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";

/// How long a finished session stays readable after its verdict, so a GUI that
/// polled once a second can still fetch the outcome it missed. Anything older
/// is dropped by [`OpenaiLogins::prune`].
const TERMINAL_RETENTION_SECS: i64 = 600;

/// The lifecycle state of one login.
///
/// The first variant is the only non-terminal one: a login either succeeds,
/// fails, expires, or is cancelled, and a state never moves again once it has
/// left [`SessionState::Waiting`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The operator has the code; the poller is waiting for approval.
    Waiting,
    /// The issuer granted tokens and the account key row is committed.
    Succeeded {
        /// The account key the login landed on.
        key_id: i64,
        /// The account's email, when the token named it.
        email: Option<String>,
        /// The subscription plan, when the token named it.
        plan_type: Option<String>,
    },
    /// The login cannot finish. `message` is shown to the operator and never
    /// carries a token, a device code or an `authorization` value.
    Failed { message: String },
    /// The device grant ran out before the human approved it.
    Expired,
    /// An operator cancelled the login.
    Cancelled,
}

impl SessionState {
    /// Whether the login has reached its verdict.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Waiting)
    }

    /// The wire spelling of the state (`waiting`, `succeeded`, …): the admin
    /// API forwards it verbatim and the GUI switches on it.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Succeeded { .. } => "succeeded",
            Self::Failed { .. } => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The status document one login answers with: the state, the code to type
/// while it waits, the account it landed on when it succeeded, and the reason
/// when it failed. Never a token or the device grant id.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LoginStatus {
    /// One of `waiting`, `succeeded`, `failed`, `expired`, `cancelled`.
    pub state: &'static str,
    /// The account key the login landed on (only for `succeeded`).
    pub key_id: Option<i64>,
    /// The account's email (only for `succeeded`, when known).
    pub email: Option<String>,
    /// The subscription plan (only for `succeeded`, when known).
    pub plan_type: Option<String>,
    /// The code the operator types (only while `waiting`).
    pub user_code: Option<String>,
    /// Where the operator types it (only while `waiting`).
    pub verification_url: Option<&'static str>,
    /// Why the login failed (only for `failed`); never a secret.
    pub message: Option<String>,
}

/// One device login: the grant being polled and its lifecycle.
pub struct Session {
    /// The issuer's grant id the poller redeems. A secret for as long as the
    /// grant lives, so it never leaves this struct except into the one poll
    /// call, and it has no `Debug`.
    device_auth_id: String,
    /// The code the operator types at [`VERIFICATION_URL`]. Not a credential
    /// on its own, but the poll also sends it.
    user_code: String,
    /// How long to wait between polls, as the issuer asked.
    interval: Duration,
    /// When the grant stops being redeemable, computed once at start and
    /// bounded by the caller's maximum login lifetime. It bounds the GRANT, not
    /// residency: [`OpenaiLogins::prune`] turns a still-waiting session past
    /// this instant `Expired`, and how long a finished session stays readable
    /// is the separate [`TERMINAL_RETENTION_SECS`] window.
    expires_at: DateTime<Utc>,
    /// The existing account key this login replaces (a re-login); `None` means
    /// the login creates a new key once the issuer grants tokens.
    key_id: Option<i64>,
    /// State and its verdict timestamp under one lock, so a terminal state can
    /// never be observed without the timestamp cleanup needs.
    outcome: Mutex<Outcome>,
}

/// A session's state plus when it reached a terminal one.
struct Outcome {
    state: SessionState,
    finished_at: Option<DateTime<Utc>>,
}

impl Session {
    /// Build a waiting session. `expires_at` is `started_at` plus the grant
    /// lifetime; the caller bounds it before calling.
    #[must_use]
    pub fn new(
        device_auth_id: String,
        user_code: String,
        interval: Duration,
        expires_at: DateTime<Utc>,
        key_id: Option<i64>,
    ) -> Self {
        Self {
            device_auth_id,
            user_code,
            interval,
            expires_at,
            key_id,
            outcome: Mutex::new(Outcome {
                state: SessionState::Waiting,
                finished_at: None,
            }),
        }
    }

    /// The grant id the poller redeems.
    #[must_use]
    pub fn device_auth_id(&self) -> &str {
        &self.device_auth_id
    }

    /// The code the operator types.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The pause between polls.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// When the grant stops being redeemable.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// The existing account key this login replaces, when it is a re-login.
    #[must_use]
    pub fn key_id(&self) -> Option<i64> {
        self.key_id
    }

    /// The current state (terminal states are returned unchanged).
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.lock().state.clone()
    }

    /// Whether the login has reached its verdict.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.lock().state.is_terminal()
    }

    /// The status document `GET /api/openai-logins/{session}` answers with.
    #[must_use]
    pub fn status(&self) -> LoginStatus {
        let state = self.state();
        let mut status = LoginStatus {
            state: state.as_str(),
            key_id: None,
            email: None,
            plan_type: None,
            user_code: None,
            verification_url: None,
            message: None,
        };
        match state {
            SessionState::Waiting => {
                status.user_code = Some(self.user_code.clone());
                status.verification_url = Some(VERIFICATION_URL);
            }
            SessionState::Succeeded {
                key_id,
                email,
                plan_type,
            } => {
                status.key_id = Some(key_id);
                status.email = email;
                status.plan_type = plan_type;
            }
            SessionState::Failed { message } => status.message = Some(message),
            SessionState::Expired | SessionState::Cancelled => {}
        }
        status
    }

    /// Move a waiting session to `next` and stamp the verdict time. Returns
    /// false when the session was already terminal (or `next` is not terminal):
    /// the poller, the expiry check and a cancel race, and only the first
    /// verdict stands.
    pub fn finish(&self, next: SessionState, now: DateTime<Utc>) -> bool {
        if !next.is_terminal() {
            tracing::warn!(
                state = next.as_str(),
                "OpenAI login session transition ignored: not a terminal state"
            );
            return false;
        }
        let mut outcome = self.lock();
        if outcome.state.is_terminal() {
            return false;
        }
        outcome.state = next;
        outcome.finished_at = Some(now);
        true
    }

    /// Whether this session is terminal and its verdict is older than the
    /// retention window.
    fn is_stale(&self, now: DateTime<Utc>) -> bool {
        let outcome = self.lock();
        outcome.finished_at.is_some_and(|finished_at| {
            now.signed_duration_since(finished_at).num_seconds() > TERMINAL_RETENTION_SECS
        })
    }

    /// Lock the outcome, recovering a poisoned lock. The critical sections here
    /// only move plain data, so the recovered state is always consistent and a
    /// panic is never the right answer on the login path.
    fn lock(&self) -> std::sync::MutexGuard<'_, Outcome> {
        match self.outcome.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("OpenAI login session state lock was poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

/// The process's in-flight login sessions, keyed by the id the admin API hands
/// the GUI.
///
/// Cheap to clone (one `Arc`), so [`crate::api::AppState`] owns the single
/// instance and every admin facade shares it.
#[derive(Clone, Default)]
pub struct OpenaiLogins {
    sessions: Arc<DashMap<Uuid, Arc<Session>>>,
}

impl OpenaiLogins {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a started login and return the id the GUI polls with, together
    /// with the shared session the poller will drive.
    pub fn insert(&self, session: Session, now: DateTime<Utc>) -> (Uuid, Arc<Session>) {
        self.prune(now);
        let id = Uuid::new_v4();
        let session = Arc::new(session);
        self.sessions.insert(id, Arc::clone(&session));
        (id, session)
    }

    /// The session `id` names while it is still known. Prunes first, so a
    /// finished session older than the retention window can never answer as if
    /// it were live.
    #[must_use]
    pub fn get(&self, id: &Uuid, now: DateTime<Utc>) -> Option<Arc<Session>> {
        self.prune(now);
        self.sessions.get(id).map(|entry| Arc::clone(entry.value()))
    }

    /// Cancel a waiting session; false when the id is unknown or the login had
    /// already reached a verdict.
    pub fn cancel(&self, id: &Uuid, now: DateTime<Utc>) -> bool {
        self.get(id, now)
            .is_some_and(|session| session.finish(SessionState::Cancelled, now))
    }

    /// Drop sessions whose verdict is older than the retention window, and
    /// expire a session still waiting past the grant deadline it was given: a
    /// poller that died (a panic, a runtime shutdown) must not leave a
    /// `waiting` login that no grant can ever finish. Called from the paths
    /// that touch the registry (`insert`, `get`), so the map never needs a
    /// cleanup task of its own.
    pub fn prune(&self, now: DateTime<Utc>) {
        // Collect first: removing while iterating a DashMap can deadlock on a
        // shard this thread already holds.
        let mut expired: Vec<(Uuid, Arc<Session>)> = Vec::new();
        let mut stale: Vec<Uuid> = Vec::new();
        for entry in self.sessions.iter() {
            let session = entry.value();
            if !session.is_terminal() && now >= session.expires_at() {
                expired.push((*entry.key(), Arc::clone(session)));
            } else if session.is_stale(now) {
                stale.push(*entry.key());
            }
        }
        // `finish` is the same compare-and-swap every other verdict goes
        // through, so a poller answering in this instant still wins.
        for (id, session) in expired {
            if session.finish(SessionState::Expired, now) {
                tracing::warn!(
                    session = %id,
                    "OpenAI login session outlived its grant deadline; marking it expired"
                );
            }
        }
        for id in stale {
            self.sessions.remove(&id);
        }
    }
}
