//! Cursor usage reconciliation (plan §2.8, D4, D9, D10).
//!
//! A Run that calls the caller's tools ends without a `TurnEndedUpdate`:
//! Cursor counts the turn only after the tools ran, and the relay closes the
//! Run before that. Such a step has no inline usage at all — Cursor reports
//! nothing for a leg it has not billed yet (T3) — so this reconciler is its
//! only source besides the estimate.
//! The account's dashboard still counts every Run, by its
//! `conversation_id`, about 2.5 s after the Run closes. [`CursorUsage::resolve`]
//! asks the dashboard for that event — first after [`FIRST_WAIT`], then every
//! [`EVERY_WAIT`] until [`UNTIL`] — and hands back its token counts; when none
//! shows in time, or the account cannot read its events, the caller falls
//! back to [`estimate`].
//!
//! Two pieces of process state keep the count honest:
//!
//! * `claimed`: events already counted, so two Runs of one conversation (a
//!   concurrent pair sharing a conversation, or a late event showing up in
//!   the next Run's window) never count the same event twice. Keyed by the
//!   vendor's `usageEventId` when present, else by (key, conversation,
//!   timestamp); aged out after [`CLAIMED_FOR`];
//! * `unreadable`: accounts whose dashboard refused (a 4xx that is neither
//!   401 nor 429 — a team-scoped login, typically). Their Runs are estimated
//!   without asking for [`UNREADABLE_FOR`].
//!
//! The reference's cross-request debt (`owed`/`carry`) is deliberately absent
//! (D10): cardinal bills per request, so an event that shows after the wait
//! leaves that request estimated, and the error is bounded by one tool
//! step's tokens.
//!
//! No bearer is logged here; the dashboard's answer is parsed for numbers
//! and never printed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Deserialize;

use crate::protocol::cursor::request as cursor_request;
use crate::protocol::usage::UsageCounts;
use crate::upstream::cursor_tokens::CursorBearer;
use crate::upstream::transport::Transport;

/// The dashboard origin.
const BACKEND_URL: &str = crate::protocol::cursor::API_ORIGIN;
/// The usage events endpoint (unary Connect, JSON).
const EVENTS_PATH: &str = "aiserver.v1.DashboardService/GetFilteredUsageEvents";
/// Wait before the first ask: the event shows about 2.5 s after the close.
pub const FIRST_WAIT: Duration = Duration::from_millis(1500);
/// Wait between asks.
pub const EVERY_WAIT: Duration = Duration::from_millis(500);
/// Total time an event is looked for.
pub const UNTIL: Duration = Duration::from_secs(6);
/// One ask's own timeout.
pub const ASK: Duration = Duration::from_secs(5);
/// How long an account that refused stays unasked.
pub const UNREADABLE_FOR: Duration = Duration::from_secs(600);
/// How long a counted event's id is remembered (twice the reference's debt
/// window, as the reference keeps it).
pub const CLAIMED_FOR: Duration = Duration::from_secs(1200);
/// The window's slack on both sides, in milliseconds.
const WINDOW_SLACK_MS: i64 = 60_000;
/// How far before the Run's start an event may still be the Run's.
const SINCE_SLACK_MS: i64 = 1000;
/// Largest dashboard answer read.
const MAX_BODY: usize = 1 << 20;
/// Event kinds the dashboard lists but never charges for.
const UNCHARGED_KINDS: &[&str] = &["ERRORED_NOT_CHARGED", "ABORTED_NOT_CHARGED", "FREE_CREDIT"];

/// The process's usage reconciler: one per process, shared by every
/// settlement.
pub struct CursorUsage {
    transport: Transport,
    backend: String,
    /// Counted events, by claim key, with the instant of the claim.
    claimed: DashMap<String, Instant>,
    /// Accounts (by key id) whose dashboard refused, with the instant.
    unreadable: DashMap<i64, Instant>,
}

/// What one reconciliation produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// The dashboard's count for the Run.
    Dashboard(UsageCounts),
    /// No event in time; the caller estimates.
    Missing,
    /// This account cannot read its events; the caller estimates, and the
    /// account is not asked again for [`UNREADABLE_FOR`].
    Unreadable,
}

impl CursorUsage {
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            backend: BACKEND_URL.to_owned(),
            claimed: DashMap::new(),
            unreadable: DashMap::new(),
        }
    }

    /// The dashboard's count for the Run of `conversation_id` opened at
    /// `since` on account `key_id`, looked for as the module docs say.
    pub async fn resolve(
        self: &Arc<Self>,
        key_id: i64,
        bearer: &CursorBearer,
        conversation_id: &str,
        since: DateTime<Utc>,
    ) -> Resolved {
        if self.is_unreadable(key_id) {
            return Resolved::Unreadable;
        }
        self.forget_old_claims();
        let end = Instant::now() + UNTIL;
        tokio::time::sleep(FIRST_WAIT).await;
        loop {
            match self.ask(key_id, bearer, conversation_id, since).await {
                Ask::Found(counts) => return Resolved::Dashboard(counts),
                Ask::Refused => {
                    self.unreadable.insert(key_id, Instant::now());
                    tracing::warn!(
                        key_id,
                        "Cursor dashboard refused this account's usage events; estimating for {}s",
                        UNREADABLE_FOR.as_secs()
                    );
                    return Resolved::Unreadable;
                }
                Ask::Nothing => {}
            }
            if Instant::now() + EVERY_WAIT > end {
                return Resolved::Missing;
            }
            tokio::time::sleep(EVERY_WAIT).await;
        }
    }

    fn is_unreadable(&self, key_id: i64) -> bool {
        let fresh = self
            .unreadable
            .get(&key_id)
            .is_some_and(|at| at.elapsed() < UNREADABLE_FOR);
        if !fresh {
            self.unreadable
                .remove_if(&key_id, |_, at| at.elapsed() >= UNREADABLE_FOR);
        }
        fresh
    }

    fn forget_old_claims(&self) {
        self.claimed.retain(|_, at| at.elapsed() < CLAIMED_FOR);
    }

    /// One ask: the first unclaimed event of the conversation in the Run's
    /// window, oldest first, claimed before it is returned.
    async fn ask(
        &self,
        key_id: i64,
        bearer: &CursorBearer,
        conversation_id: &str,
        since: DateTime<Utc>,
    ) -> Ask {
        let since_ms = since.timestamp_millis();
        let now_ms = Utc::now().timestamp_millis();
        let mut body = serde_json::Map::new();
        if let Some(team_id) = bearer.team_id()
            && let Ok(team_id) = team_id.parse::<i64>()
        {
            body.insert("teamId".to_owned(), team_id.into());
        }
        body.insert(
            "startDate".to_owned(),
            (since_ms - WINDOW_SLACK_MS).to_string().into(),
        );
        body.insert(
            "endDate".to_owned(),
            (now_ms + WINDOW_SLACK_MS).to_string().into(),
        );
        body.insert("page".to_owned(), 1.into());
        body.insert("pageSize".to_owned(), 50.into());
        // The shell comes from the shared builder; the origin is this
        // reconciler's (a test stub's when a test drives it).
        let mut prepared = cursor_request::unary_json(
            EVENTS_PATH,
            serde_json::Value::Object(body).to_string().into(),
        );
        prepared.url = format!("{}/{EVENTS_PATH}", self.backend);
        let headers = cursor_request::unary_headers(bearer.access_token(), bearer.team_id());
        let deadline = Instant::now() + ASK;
        let response = match self
            .transport
            .send_with_headers(&prepared, &headers, &[], deadline)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(key_id, ?error, "Cursor usage events ask failed");
                return Ask::Nothing;
            }
        };
        let status = response.status().as_u16();
        // A 4xx other than "come back later" (429) or "not this bearer" (401)
        // says the account cannot read its events at all.
        if (400..500).contains(&status) && status != 429 && status != 401 {
            return Ask::Refused;
        }
        if !(200..300).contains(&status) {
            return Ask::Nothing;
        }
        let Ok(body) = self.transport.read_body(response, MAX_BODY, deadline).await else {
            return Ask::Nothing;
        };
        let Ok(answer) = serde_json::from_slice::<EventsAnswer>(&body) else {
            return Ask::Nothing;
        };
        let mut events: Vec<&Event> = answer
            .usage_events_display
            .iter()
            .filter(|event| event.conversation_id.as_deref() == Some(conversation_id))
            .filter(|event| event.token_usage.is_some())
            .filter(|event| event.timestamp_ms() >= since_ms - SINCE_SLACK_MS)
            .filter(|event| {
                !event
                    .kind
                    .as_deref()
                    .is_some_and(|kind| UNCHARGED_KINDS.contains(&kind))
            })
            .collect();
        events.sort_by_key(|event| event.timestamp_ms());
        for event in events {
            let claim = event.claim_key(key_id, conversation_id);
            if self.claimed.contains_key(&claim) {
                continue;
            }
            // One Run, one event: the oldest unclaimed one is this Run's.
            self.claimed.insert(claim, Instant::now());
            if let Some(counts) = event.token_usage.as_ref().map(TokenUsage::counts) {
                return Ask::Found(counts);
            }
        }
        Ask::Nothing
    }
}

/// One ask's verdict.
enum Ask {
    Found(UsageCounts),
    Nothing,
    Refused,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventsAnswer {
    #[serde(default)]
    usage_events_display: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    #[serde(default)]
    conversation_id: Option<String>,
    /// Milliseconds since the epoch, as a string or a number.
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
    #[serde(default)]
    usage_event_id: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    token_usage: Option<TokenUsage>,
}

impl Event {
    fn timestamp_ms(&self) -> i64 {
        match &self.timestamp {
            Some(serde_json::Value::String(text)) => text.parse().unwrap_or(0),
            Some(serde_json::Value::Number(number)) => number
                .as_i64()
                .or_else(|| number.as_f64().map(|f| f as i64))
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// The vendor's idempotency key when it gives one, else the account,
    /// conversation and millisecond.
    fn claim_key(&self, key_id: i64, conversation_id: &str) -> String {
        match self.usage_event_id.as_deref().filter(|id| !id.is_empty()) {
            Some(id) => format!("id\0{key_id}\0{id}"),
            None => format!("at\0{key_id}\0{conversation_id}\0{}", self.timestamp_ms()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenUsage {
    #[serde(default)]
    input_tokens: serde_json::Value,
    #[serde(default)]
    output_tokens: serde_json::Value,
    #[serde(default)]
    cache_read_tokens: serde_json::Value,
    #[serde(default)]
    cache_write_tokens: serde_json::Value,
}

impl TokenUsage {
    /// The dashboard's `inputTokens` is the uncached part alone, so the
    /// kernel's prompt total (cache read and write included) is the three
    /// summed; the cache parts are listed beside it.
    fn counts(&self) -> UsageCounts {
        let cache_read = number(&self.cache_read_tokens);
        let cache_write = number(&self.cache_write_tokens);
        UsageCounts {
            input_tokens: number(&self.input_tokens) + cache_read + cache_write,
            output_tokens: number(&self.output_tokens),
            cached_input_tokens: (cache_read > 0).then_some(cache_read),
            cache_creation_input_tokens: (cache_write > 0).then_some(cache_write),
            ..UsageCounts::default()
        }
    }
}

/// A dashboard number: a JSON number or a numeric string; anything else is 0.
fn number(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().map(|f| f.max(0.0) as u64))
            .unwrap_or(0),
        serde_json::Value::String(text) => {
            text.parse::<f64>().map(|f| f.max(0.0) as u64).unwrap_or(0)
        }
        _ => 0,
    }
}

/// The reference's estimate when Cursor counted nothing: the prompt at four
/// characters a token, the output at the same rate rounded up. The cache is
/// never guessed. Never both zero for a Run that said anything.
#[must_use]
pub fn estimate(prompt_chars: u64, output_chars: u64) -> UsageCounts {
    UsageCounts {
        input_tokens: prompt_chars / 4,
        output_tokens: output_chars.div_ceil(4),
        ..UsageCounts::default()
    }
}
