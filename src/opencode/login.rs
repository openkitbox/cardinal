//! The in-memory registry of in-flight OpenCode Console device logins.
//!
//! A device login has a human in the middle: the browser shows a code, the
//! gateway polls the console, and minutes pass before the verdict. This module
//! is the state that gap needs — which sessions exist, which grant each one
//! polls, and what became of it — and deliberately nothing else: no HTTP, no
//! database, no polling loop of its own.
//!
//! [`crate::admin_ops::Admin`] owns the orchestration. It starts a session here,
//! spawns the poller, and moves the session to its verdict through
//! [`Session::finish`], which is a compare-and-swap: whichever of the poller,
//! [`OpencodeLogins::prune`] (a waiting session whose grant deadline passed) and
//! an operator's cancel arrives first decides, and the others find a terminal
//! session and leave it alone.

use std::sync::Arc;
use std::sync::Mutex;

use chrono::DateTime;
use chrono::Utc;
use dashmap::DashMap;
use uuid::Uuid;

/// How long a finished session stays readable after its verdict, so a GUI that
/// polled once a second can still fetch the outcome it missed. Anything older
/// is dropped by [`OpencodeLogins::prune`].
const TERMINAL_RETENTION_SECS: i64 = 600;

/// The lifecycle state of one login.
///
/// The first variant is the only non-terminal one: a login either succeeds,
/// fails, expires, or is cancelled, and a state never moves again once it has
/// left [`SessionState::Waiting`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The browser has the code; the poller is waiting for approval.
    Waiting,
    /// The console issued tokens and the account key row is committed.
    Succeeded {
        /// The account key the logins landed on.
        key_id: i64,
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

    /// The status document `GET /api/opencode-logins/{session}` answers with.
    #[must_use]
    pub fn status(&self) -> LoginStatus {
        match self {
            Self::Waiting => LoginStatus {
                state: "waiting",
                key_id: None,
                message: None,
            },
            Self::Succeeded { key_id } => LoginStatus {
                state: "succeeded",
                key_id: Some(*key_id),
                message: None,
            },
            Self::Failed { message } => LoginStatus {
                state: "failed",
                key_id: None,
                message: Some(message.clone()),
            },
            Self::Expired => LoginStatus {
                state: "expired",
                key_id: None,
                message: None,
            },
            Self::Cancelled => LoginStatus {
                state: "cancelled",
                key_id: None,
                message: None,
            },
        }
    }
}

/// The status document one login answers with: the state, the account it
/// landed on when it succeeded, and the reason when it failed.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LoginStatus {
    /// One of `waiting`, `succeeded`, `failed`, `expired`, `cancelled`.
    pub state: &'static str,
    /// The account key the login landed on (only for `succeeded`).
    pub key_id: Option<i64>,
    /// Why the login failed (only for `failed`); never a secret.
    pub message: Option<String>,
}

/// One device login: the grant being polled and its lifecycle.
pub struct Session {
    /// The console credential the poller trades for tokens. A secret for as
    /// long as the grant lives, so it never leaves this struct except into the
    /// one console call that redeems it.
    device_code: String,
    /// When the grant stops being redeemable, computed once at start from the
    /// console's `expires_in` and bounded by the caller's maximum login
    /// lifetime. It bounds the GRANT, not residency: [`OpencodeLogins::prune`]
    /// turns a still-waiting session past this instant `Expired`, and how long a
    /// finished session stays readable is the separate
    /// [`TERMINAL_RETENTION_SECS`] window.
    expires_at: DateTime<Utc>,
    /// The existing account key this login replaces (a re-login); `None` means
    /// the login creates a new key once the console issues tokens.
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
    /// Build a waiting session. `expires_at` is `started_at + expires_in`; the
    /// caller bounds the lifetime before calling.
    #[must_use]
    pub fn new(device_code: String, expires_at: DateTime<Utc>, key_id: Option<i64>) -> Self {
        Self {
            device_code,
            expires_at,
            key_id,
            outcome: Mutex::new(Outcome {
                state: SessionState::Waiting,
                finished_at: None,
            }),
        }
    }

    /// The grant the poller redeems.
    #[must_use]
    pub fn device_code(&self) -> &str {
        &self.device_code
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

    /// Move a waiting session to `next` and stamp the verdict time. Returns
    /// false when the session was already terminal (or `next` is not terminal):
    /// the poller, the expiry check and a cancel race, and only the first
    /// verdict stands.
    pub fn finish(&self, next: SessionState, now: DateTime<Utc>) -> bool {
        if !next.is_terminal() {
            tracing::warn!(
                state = next.as_str(),
                "OpenCode login session transition ignored: not a terminal state"
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
                tracing::warn!("OpenCode login session state lock was poisoned; recovering");
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
pub struct OpencodeLogins {
    sessions: Arc<DashMap<Uuid, Arc<Session>>>,
}

impl OpencodeLogins {
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
    /// `waiting` login that no grant can ever finish. Called from the two paths
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
                    "OpenCode login session outlived its grant deadline; marking it expired"
                );
            }
        }
        for id in stale {
            self.sessions.remove(&id);
        }
    }
}
