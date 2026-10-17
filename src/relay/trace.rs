//! Routing trace: records the full decision context of each dispatch —
//! which candidates were available, which were skipped and why, and which
//! was selected. Stored in a ring buffer for the admin API and GUI.

use std::collections::VecDeque;
use std::sync::Mutex;

/// One candidate's trace entry: who it was and why it was/wasn't picked.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CandidateTrace {
    pub key_label: String,
    pub provider_name: String,
    pub model: String,
    /// Why this candidate was skipped; None = it was tried.
    pub skipped: Option<SkipReason>,
    /// Smart verdict reason (empty for ordered routes).
    pub smart_reason: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Key disabled or provider disabled.
    Disabled,
    /// Entry's availability window denies this time.
    WindowSkipped,
    /// Key is resting (cooldown).
    Resting,
    /// Key's allowed_models doesn't include this model.
    ModelNotAllowed,
    /// Secret unreadable.
    SecretSkipped,
    /// Candidate's concurrency cap was full.
    ConcurrencyFull,
    /// Queue wait timed out.
    QueueTimeout,
}

/// One dispatch's full routing trace.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DispatchTrace {
    pub request_id: String,
    pub model: String,
    pub alias: Option<String>,
    pub strategy: String,
    pub candidates: Vec<CandidateTrace>,
    pub ts: chrono::DateTime<chrono::Utc>,
}

/// Ring buffer for recent traces. Capacity is fixed; oldest entries are evicted.
pub struct TraceRing {
    inner: Mutex<VecDeque<DispatchTrace>>,
}

impl TraceRing {
    pub const CAPACITY: usize = 128;

    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(Self::CAPACITY)),
        }
    }

    pub fn push(&self, trace: DispatchTrace) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.len() >= Self::CAPACITY {
            inner.pop_front();
        }
        inner.push_back(trace);
    }

    /// List all traces, newest first.
    pub fn list(&self) -> Vec<DispatchTrace> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.iter().rev().cloned().collect()
    }

    /// Get a trace by request_id.
    pub fn get(&self, request_id: &str) -> Option<DispatchTrace> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.iter().find(|t| t.request_id == request_id).cloned()
    }
}

impl Default for TraceRing {
    fn default() -> Self {
        Self::new()
    }
}
