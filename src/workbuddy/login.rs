use std::sync::Arc;
use std::sync::Mutex;

use chrono::DateTime;
use chrono::Utc;
use dashmap::DashMap;
use uuid::Uuid;

const TERMINAL_RETENTION_SECS: i64 = 600;

/// The lifecycle state of a WorkBuddy browser login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    Waiting,
    Succeeded,
    Failed { message: String },
    Expired,
    Cancelled,
}

impl SessionState {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Waiting)
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Succeeded => "succeeded",
            Self::Failed { .. } => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Serializable status returned to the admin login API. It contains no token.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Status {
    pub session: Uuid,
    pub state: &'static str,
    pub message: Option<String>,
    pub login_url: Option<String>,
    pub expires_in: i64,
}

/// One in-memory login and the vendor state needed by its poller.
pub struct Session {
    vendor_state: String,
    login_url: String,
    expires_at: DateTime<Utc>,
    outcome: Mutex<Outcome>,
}

struct Outcome {
    state: SessionState,
    finished_at: Option<DateTime<Utc>>,
}

impl Session {
    fn new(vendor_state: String, login_url: String, expires_at: DateTime<Utc>) -> Self {
        Self {
            vendor_state,
            login_url,
            expires_at,
            outcome: Mutex::new(Outcome {
                state: SessionState::Waiting,
                finished_at: None,
            }),
        }
    }

    /// The vendor state string used by the poller.
    #[must_use]
    pub fn vendor_state(&self) -> &str {
        &self.vendor_state
    }

    /// The URL shown to the operator.
    #[must_use]
    pub fn login_url(&self) -> &str {
        &self.login_url
    }

    /// The polling deadline.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.lock().state.clone()
    }

    /// Render this session as an admin status document.
    #[must_use]
    pub fn status(&self, session: Uuid, now: DateTime<Utc>) -> Status {
        let outcome = self.lock();
        let message = match &outcome.state {
            SessionState::Failed { message } => Some(message.clone()),
            _ => None,
        };
        let login_url =
            matches!(&outcome.state, SessionState::Waiting).then(|| self.login_url.clone());
        let expires_in = (self.expires_at - now).num_seconds().max(0);
        Status {
            session,
            state: outcome.state.as_str(),
            message,
            login_url,
            expires_in,
        }
    }

    /// Complete a waiting session exactly once. Returns false for a terminal
    /// session or a non-terminal transition.
    pub fn finish(&self, next: SessionState, now: DateTime<Utc>) -> bool {
        if !next.is_terminal() {
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Outcome> {
        match self.outcome.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("WorkBuddy login session state lock was poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

/// Process-local registry of browser logins. Cloning shares the registry.
#[derive(Clone, Default)]
pub struct WorkbuddyLogins {
    sessions: Arc<DashMap<Uuid, Arc<Session>>>,
}

impl WorkbuddyLogins {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a waiting login and return its public id plus the poller's
    /// shared session handle.
    pub fn start(
        &self,
        vendor_state: String,
        login_url: String,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> (Uuid, Arc<Session>) {
        self.expire(now);
        let id = Uuid::new_v4();
        let session = Arc::new(Session::new(vendor_state, login_url, expires_at));
        self.sessions.insert(id, Arc::clone(&session));
        (id, session)
    }

    /// Look up a session, expiring overdue and stale entries first.
    #[must_use]
    pub fn get(&self, id: &Uuid, now: DateTime<Utc>) -> Option<Arc<Session>> {
        self.expire(now);
        self.sessions.get(id).map(|entry| Arc::clone(entry.value()))
    }

    /// Render a status document for a public session id.
    #[must_use]
    pub fn status(&self, id: &Uuid, now: DateTime<Utc>) -> Option<Status> {
        self.get(id, now).map(|session| session.status(*id, now))
    }

    pub fn finish(&self, id: &Uuid, state: SessionState, now: DateTime<Utc>) -> bool {
        self.get(id, now)
            .is_some_and(|session| session.finish(state, now))
    }

    pub fn fail(&self, id: &Uuid, message: String, now: DateTime<Utc>) -> bool {
        self.finish(id, SessionState::Failed { message }, now)
    }

    pub fn cancel(&self, id: &Uuid, now: DateTime<Utc>) -> bool {
        self.finish(id, SessionState::Cancelled, now)
    }

    /// Expire waiting sessions and remove terminal sessions older than ten
    /// minutes. Collection precedes removal to avoid DashMap shard deadlocks.
    pub fn expire(&self, now: DateTime<Utc>) {
        let mut waiting = Vec::new();
        let mut stale = Vec::new();
        for entry in self.sessions.iter() {
            let session = entry.value();
            if !session.state().is_terminal() && now >= session.expires_at() {
                waiting.push(Arc::clone(session));
            } else if session.is_stale(now) {
                stale.push(*entry.key());
            }
        }
        for session in waiting {
            session.finish(SessionState::Expired, now);
        }
        for id in stale {
            self.sessions.remove(&id);
        }
    }
}
