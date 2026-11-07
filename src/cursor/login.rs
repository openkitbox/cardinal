//! The in-memory registry of in-flight Cursor browser logins.
//!
//! A browser login has a human in the middle: the operator opens the URL,
//! signs in on `cursor.com`, and the gateway polls until the tokens land.
//! This module is the state that gap needs — which sessions exist, which
//! challenge each one polls with, and what became of it — and nothing else:
//! no HTTP (`auth`), no database, no polling loop (`admin_ops`).
//!
//! It is the OpenCode registry's shape ([`crate::opencode::login`]) with a
//! [`Challenge`] in place of the device code; [`Session::finish`] is the same
//! compare-and-swap, so whichever of the poller, [`CursorLogins::prune`] and
//! an operator's cancel arrives first decides.

use std::sync::Arc;
use std::sync::Mutex;

use chrono::DateTime;
use chrono::Utc;
use dashmap::DashMap;
use uuid::Uuid;

use super::auth::Challenge;

/// How long a finished session stays readable after its verdict, so a GUI
/// that polled once a second can still fetch the outcome it missed (plan: ten
/// minutes).
const TERMINAL_RETENTION_SECS: i64 = 600;

/// The lifecycle state of one login. Only [`SessionState::Waiting`] is
/// non-terminal; a state never moves again once it has left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The operator has the URL; the poller is waiting for the sign-in.
    Waiting,
    /// The tokens landed and the account key row is committed.
    Succeeded {
        /// The account key the login landed on.
        key_id: i64,
        /// The account's email, when the backend named it.
        email: Option<String>,
        /// The team the operator signed into, when it was a team login.
        team_id: Option<String>,
    },
    /// The login cannot finish. `message` is a fixed short sentence for the
    /// operator and never carries a token or a verifier.
    Failed { message: String },
    /// The poll window ran out before the operator signed in.
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

    /// The wire spelling of the state (`waiting`, `succeeded`, …).
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

    /// The status document `GET /api/cursor-logins/{session}` answers with.
    #[must_use]
    pub fn status(&self) -> LoginStatus {
        let mut status = LoginStatus {
            state: self.as_str(),
            key_id: None,
            email: None,
            team_id: None,
            message: None,
        };
        match self {
            Self::Succeeded {
                key_id,
                email,
                team_id,
            } => {
                status.key_id = Some(*key_id);
                status.email = email.clone();
                status.team_id = team_id.clone();
            }
            Self::Failed { message } => status.message = Some(message.clone()),
            Self::Waiting | Self::Expired | Self::Cancelled => {}
        }
        status
    }
}

/// The status document one login answers with. Never a token: on success
/// the GUI learns the key id, the email and the team, nothing else.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LoginStatus {
    /// One of `waiting`, `succeeded`, `failed`, `expired`, `cancelled`.
    pub state: &'static str,
    /// The account key the login landed on (only for `succeeded`).
    pub key_id: Option<i64>,
    /// The account's email (only for `succeeded`, when known).
    pub email: Option<String>,
    /// The selected team (only for `succeeded`, when a team login).
    pub team_id: Option<String>,
    /// Why the login failed (only for `failed`); never a secret.
    pub message: Option<String>,
}

/// One browser login: the challenge being polled and its lifecycle.
pub struct Session {
    /// The verifier/uuid pair. The verifier is a secret for as long as the
    /// login lives, so it never leaves this struct except into the poll.
    challenge: Challenge,
    /// When polling stops (start + the plan's 180s). Bounds the poll, not
    /// residency: [`CursorLogins::prune`] turns a still-waiting session past
    /// this instant `Expired`; a finished session stays readable for the
    /// separate [`TERMINAL_RETENTION_SECS`] window.
    expires_at: DateTime<Utc>,
    /// The existing account key this login replaces (a re-login); `None`
    /// means the login creates a new key once the tokens land.
    key_id: Option<i64>,
    /// State and its verdict timestamp under one lock.
    outcome: Mutex<Outcome>,
}

struct Outcome {
    state: SessionState,
    finished_at: Option<DateTime<Utc>>,
}

impl Session {
    /// Build a waiting session.
    #[must_use]
    pub fn new(challenge: Challenge, expires_at: DateTime<Utc>, key_id: Option<i64>) -> Self {
        Self {
            challenge,
            expires_at,
            key_id,
            outcome: Mutex::new(Outcome {
                state: SessionState::Waiting,
                finished_at: None,
            }),
        }
    }

    /// The pair the poller asks with.
    #[must_use]
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// When polling stops.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// The existing account key this login replaces, when it is a re-login.
    #[must_use]
    pub fn key_id(&self) -> Option<i64> {
        self.key_id
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.lock().state.clone()
    }

    /// Whether the login has reached its verdict.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.lock().state.is_terminal()
    }

    /// Move a waiting session to `next` and stamp the verdict time. False when
    /// the session was already terminal (or `next` is not terminal): only the
    /// first verdict stands.
    pub fn finish(&self, next: SessionState, now: DateTime<Utc>) -> bool {
        if !next.is_terminal() {
            tracing::warn!(
                state = next.as_str(),
                "Cursor login session transition ignored: not a terminal state"
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

    fn is_stale(&self, now: DateTime<Utc>) -> bool {
        let outcome = self.lock();
        outcome.finished_at.is_some_and(|finished_at| {
            now.signed_duration_since(finished_at).num_seconds() > TERMINAL_RETENTION_SECS
        })
    }

    /// Lock the outcome, recovering a poisoned lock: the critical sections
    /// only move plain data, so the recovered state is always consistent.
    fn lock(&self) -> std::sync::MutexGuard<'_, Outcome> {
        match self.outcome.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("Cursor login session state lock was poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

/// The process's in-flight Cursor logins, keyed by the id the admin API hands
/// the GUI (distinct from the challenge's own uuid, which the vendor sees).
/// Cheap to clone (one `Arc`).
#[derive(Clone, Default)]
pub struct CursorLogins {
    sessions: Arc<DashMap<Uuid, Arc<Session>>>,
}

impl CursorLogins {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a started login and return the id the GUI polls with,
    /// together with the shared session the poller will drive.
    pub fn insert(&self, session: Session, now: DateTime<Utc>) -> (Uuid, Arc<Session>) {
        self.prune(now);
        let id = Uuid::new_v4();
        let session = Arc::new(session);
        self.sessions.insert(id, Arc::clone(&session));
        (id, session)
    }

    /// The session `id` names while it is still known (prunes first).
    #[must_use]
    pub fn get(&self, id: &Uuid, now: DateTime<Utc>) -> Option<Arc<Session>> {
        self.prune(now);
        self.sessions.get(id).map(|entry| Arc::clone(entry.value()))
    }

    /// Cancel a waiting session; false when the id is unknown or the login
    /// had already reached a verdict.
    pub fn cancel(&self, id: &Uuid, now: DateTime<Utc>) -> bool {
        self.get(id, now)
            .is_some_and(|session| session.finish(SessionState::Cancelled, now))
    }

    /// Drop sessions whose verdict is older than the retention window, and
    /// expire a session still waiting past its poll deadline, so a poller
    /// that died cannot leave a `waiting` login nothing can finish.
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
        for (id, session) in expired {
            if session.finish(SessionState::Expired, now) {
                tracing::warn!(
                    session = %id,
                    "Cursor login session outlived its poll deadline; marking it expired"
                );
            }
        }
        for id in stale {
            self.sessions.remove(&id);
        }
    }
}
