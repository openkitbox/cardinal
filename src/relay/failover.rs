//! Failure taxonomy: classify one attempt's failure into failover policy —
//! whether to fail over, how long to rest the key, and whether the key is even
//! at fault. Transport stays facts-only (status + bounded error body); all
//! word-table interpretation lives here.
//!
//! Word tables: bilingual (English/Chinese), case-insensitive, compiled once,
//! trimmed to the key-centric model. A RATE table
//! (`rate.?limit|too many requests|per.?(second|sec|minute|min)\b|\b[rt]pm\b|
//! 频率|太频繁`) is documentary only: a 429 whose body carries no quota words IS
//! a short rate limit, so the classifier never needs to look those words up.

use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;

use super::optional;
use crate::protocol::ProtocolError;
use crate::upstream::kiro_tokens::KiroTokenError;
use crate::upstream::transport::TransportError;

/// Mapping transport failures → protocol error codes is orchestration policy, owned by the relay layer;
/// upstream only reports transport facts and knows nothing about protocol error taxonomy.
fn as_protocol_error(error: &TransportError) -> ProtocolError {
    match error {
        TransportError::Connect => ProtocolError::UpstreamError,
        TransportError::Timeout => ProtocolError::UpstreamTimeout,
        TransportError::Status { status, .. } => match status {
            401 | 403 => ProtocolError::UpstreamAuthenticationFailed,
            429 => ProtocolError::UpstreamRateLimited,
            _ => ProtocolError::UpstreamError,
        },
        TransportError::BodyTooLarge | TransportError::InvalidBody | TransportError::ClientGone => {
            ProtocolError::InvalidUpstreamResponse
        }
    }
}

/// The failure of one attempt. `Protocol` means the request itself is at fault.
#[derive(Debug)]
pub enum AttemptError {
    Transport(TransportError),
    /// Every candidate's concurrency gate saturated and the dispatch's queue
    /// wait elapsed: the gateway is the limiting factor, not any upstream. The
    /// client gets 429 with a Retry-After (the configured queue wait) — waiting
    /// is exactly what a healthy caller should do; the ledger must be able to
    /// tell this apart from a real upstream timeout (which reads as 504).
    #[allow(dead_code)] // Will be used by the dispatcher in the future
    ConcurrencyBusy {
        queue_timeout: std::time::Duration,
    },
    /// The stream's upstream died before the pump's commit point (the 200
    /// headers were out but nothing reached the client): the attempt may fail
    /// over invisibly. It classifies as the connection/timeout family —
    /// [`Failure::Other`] — so a pre-commit abort rests and retries exactly
    /// like a mid-read transport error.
    AbortedStream,
    /// The candidate's Kiro OIDC credential could not produce a bearer (lazy
    /// refresh failed) or the runtime host did not match the credential's
    /// region. Carries the token module's own verdict — never a token — so the
    /// relay can skip a dead account without either blaming the request or
    /// forwarding a token-plane error to the client.
    KiroTokenError(KiroTokenError),
    Protocol(ProtocolError),
}

impl From<TransportError> for AttemptError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl AttemptError {
    /// The HTTP status the client sees (the failure of the last attempt, or a
    /// non-transferable failure). A status-bearing transport error shows the
    /// upstream's own code — collapsing 404/503 to 502 would hide the vendor's
    /// actual verdict from the caller and the request log.
    pub fn client_status(&self) -> u16 {
        match self {
            Self::Transport(TransportError::Status { status, .. }) => *status,
            Self::Transport(error) => as_protocol_error(error).status(),
            // Gateway-side saturation: the caller should retry after the queue wait.
            Self::ConcurrencyBusy { .. } => 429,
            // An abort only ever surfaces when every candidate died pre-commit: the
            // upstream family, not the request's fault.
            Self::AbortedStream => ProtocolError::UpstreamError.status(),
            Self::KiroTokenError(error) => error.client_status(),
            Self::Protocol(error) => error.status(),
        }
    }

    /// The status a ledger row records. Same as [`Self::client_status`] except
    /// for [`TransportError::ClientGone`]: the 502 it maps to ("invalid upstream
    /// response") would blame the vendor for a request that died because the
    /// caller left, so the row carries nginx's 499 client-closed verdict.
    /// Salvo clamps 499 to 500 for the (already disconnected) client, so this
    /// is a record, not a wire status.
    pub fn ledger_status(&self) -> u16 {
        match self {
            Self::Transport(TransportError::ClientGone) => 499,
            other => other.client_status(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Transport(error) => as_protocol_error(error).code(),
            Self::ConcurrencyBusy { .. } => "concurrency_busy",
            Self::AbortedStream => ProtocolError::UpstreamError.code(),
            Self::KiroTokenError(error) => error.code(),
            Self::Protocol(error) => error.code(),
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Transport(error) => error.to_string(),
            Self::ConcurrencyBusy { queue_timeout } => {
                format!(
                    "gateway busy: every candidate at its concurrency limit, queue timed out after {}s",
                    queue_timeout.as_secs()
                )
            }
            Self::AbortedStream => "upstream stream died before the response committed".to_owned(),
            // Safe to surface: the token error carries no OAuth material.
            Self::KiroTokenError(error) => error.to_string(),
            Self::Protocol(error) => format!("{error:?}"),
        }
    }

    /// The upstream `Retry-After` ask as a wall-clock duration, for in-place
    /// retry pauses.
    pub fn retry_after_duration(&self) -> Option<std::time::Duration> {
        match self {
            Self::Transport(error) => error.retry_after().and_then(|d| d.to_std().ok()),
            Self::KiroTokenError(error) => error.retry_after().and_then(|d| d.to_std().ok()),
            _ => None,
        }
    }
}

/// Why one attempt failed, as failover policy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Out of money: rest 30min.
    Credit,
    /// Plan allowance used up: rest until a vendor-stated reset time when the
    /// refusal carries one (body timestamp, reset header, or Retry-After —
    /// precedence in that order), capped at [`MAX_QUOTA_REST`]; 15min when it
    /// says nothing of when.
    Quota {
        reset_until: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Short rate limit: rest Retry-After (≤30min) else 1min.
    Rate {
        retry_after: Option<chrono::Duration>,
    },
    /// The plan/channel does not serve THIS model: fail over, rest the
    /// (key, model) pair for a fixed 15min (deliberately NOT parsed from any
    /// resets_at the body may carry — the pairing matters
    /// more than the duration). The key's other models stay usable.
    Unserved,
    /// Neither the key nor the model is at fault (request shape / channel
    /// refusal): fail over, rest NOBODY.
    Blameless,
    /// The request itself is at fault (plain 400/413/422, overflow, odd 4xx):
    /// do NOT fail over, rest nobody, return to the client.
    Request,
    /// Everything else transferable (connect, timeout, 5xx, 408, 401/403/404,
    /// body too large/invalid): rest 1min, doubling per consecutive failure, cap 10min.
    Other,
}

/// Who cools down after a failure, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestTarget {
    /// The whole key: every model on it rests.
    Key(chrono::Duration),
    /// Only the (key, model) pair of the failed candidate: sibling models on
    /// the same key stay usable.
    KeyModel(chrono::Duration),
}

impl Failure {
    /// Transferable = another candidate might succeed: everything but `Request`.
    pub fn transferable(&self) -> bool {
        !matches!(self, Self::Request)
    }

    /// The cooldown target; `None` = rest nobody. `consecutive_failures` is the
    /// key's consecutive-failure counter (after this bump) and only `Other` uses
    /// it (the named classes have fixed durations and never bump the counter).
    /// `now` anchors the Quota reset cap.
    pub fn rest_target(
        &self,
        consecutive_failures: u32,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<RestTarget> {
        let key = |duration| Some(RestTarget::Key(duration));
        match self {
            Self::Credit => key(chrono::Duration::minutes(30)),
            Self::Quota { reset_until } => key(match *reset_until {
                // A vendor-stated reset is trusted up to MAX_QUOTA_REST (a
                // week's window plus a day over); past that the word
                // is wrong and the 15min re-probe is the honest answer.
                Some(t) if t > now => (t - now).min(MAX_QUOTA_REST),
                _ => chrono::Duration::minutes(15),
            }),
            Self::Rate { retry_after } => key(match retry_after {
                Some(d) => (*d).min(chrono::Duration::minutes(30)),
                None => chrono::Duration::minutes(1),
            }),
            Self::Unserved => Some(RestTarget::KeyModel(chrono::Duration::minutes(15))),
            Self::Blameless | Self::Request => None,
            Self::Other => {
                let shift = consecutive_failures.saturating_sub(1).min(10);
                key(chrono::Duration::minutes(1i64 << shift).min(chrono::Duration::minutes(10)))
            }
        }
    }
}

// ---------- word tables ----------

/// Out of money. English words carry word boundaries — bare substrings like
/// "billing" would otherwise turn a 500 "internal error in billing service"
/// into a 30-minute rest of a healthy key.
const CREDIT: &str = r"\binsufficient.?(balance|credit|funds?)\b|\bbalance\b|\bbilling\b|\barrears?\b|\boverdue\b|余额|欠费|充值|账户.*(不足|停)";
/// The "broke" subset: on a 429, credit only counts when the body also says one of these.
const BROKE: &str = r"余额不足|欠费|请充值|\binsufficient.?(balance|credit|funds?)\b";
/// Plan allowance used up. `exceeded` is tied to `plan` (not `limit`) so a
/// context-length 400 ("exceeded the maximum length limit") stays a Request.
const QUOTA: &str = r"quota|usage.?limit|out of budget|budget (exceeded|exhausted)|limit.?reached|hit your .*limit|limit.{0,24}resets|exceeded.*plan|per.?(day|week|month)|\bdaily\b|\bweekly\b|\bmonthly\b|resource.?exhausted|usage_limit_reached|额度|用量|套餐|上限|限额已用完";
/// The key/channel does not serve this model.
const UNSERVED: &str = r"model.{0,80}(not (supported|accessible|available|found|enabled|allowed)|unsupported|does ?n[o']t exist|unknown|invalid)|(no such|unknown|invalid|unsupported) model|model_not_found|模型.{0,12}(不存在|不支持|无权|未开通)";
/// The channel rejected the request shape (not the request itself).
const SHAPE: &str = r"failed to deserialize|unknown (item |content |input )?(type|variant|field|parameter)|unknown_parameter|unrecognized (request argument|field|parameter)|extra (inputs|fields) are not permitted|additional properties are not allowed";
/// The channel refuses us outright.
const REFUSED: &str = r"unapproved channel|illegal api invocation";

/// Word tables, compiled once. The patterns are compile-time constants; a pattern
/// that somehow failed to compile degrades its family to never-match instead of
/// panicking on a request path (classification is best-effort evidence, and the
/// status-only rules still apply).
struct Tables {
    credit: Option<Regex>,
    broke: Option<Regex>,
    quota: Option<Regex>,
    unserved: Option<Regex>,
    shape: Option<Regex>,
    refused: Option<Regex>,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let compile = |pattern: &str| Regex::new(&format!("(?i){pattern}")).ok();
        Tables {
            credit: compile(CREDIT),
            broke: compile(BROKE),
            quota: compile(QUOTA),
            unserved: compile(UNSERVED),
            shape: compile(SHAPE),
            refused: compile(REFUSED),
        }
    })
}

fn hits(table: &Option<Regex>, text: &str) -> bool {
    table.as_ref().is_some_and(|re| re.is_match(text))
}

/// Classify one attempt's failure. The body is scanned once (families run in
/// priority order against the lossy-borrowed text); this is the error path.
pub fn classify(error: &AttemptError) -> Failure {
    let (status, retry_after_raw, reset_header_raw, body) = match error {
        AttemptError::Transport(TransportError::Status {
            status,
            retry_after,
            reset_header,
            body,
        }) => (
            *status,
            retry_after.as_deref(),
            reset_header.as_deref(),
            body.as_ref(),
        ),
        // Non-status transport failures (connect, timeout, body too large/invalid,
        // client gone). `ClientGone` IS constructed today (a streaming hold can end
        // because the client left), but dispatch special-cases it before classify:
        // no cool-down, no counter, no failover. The `Other` mapping here stays as
        // a defensive fallback should a future call site skip the special case.
        AttemptError::Transport(_) => return Failure::Other,
        // Gateway-side saturation never reaches classify either: the gate path
        // `continue`s before classify (busy ≠ broken — no cooldown, no counter).
        AttemptError::ConcurrencyBusy { .. } => return Failure::Other,
        // Pre-commit stream abort: the upstream died before producing anything —
        // the connection/timeout family, resting and retrying like a mid-read error.
        AttemptError::AbortedStream => return Failure::Other,
        // The credential plane, not the request: a dead refresh token (or a
        // runtime host that contradicts its region) is permanent — fail over
        // without resting or blaming anybody; the account needs a re-import,
        // which is the operator's call, not a backoff's. Everything temporary
        // (429, 5xx, timeout, unreachable) follows the existing transient
        // policy, and a 429 keeps its Retry-After.
        AttemptError::KiroTokenError(error) => {
            return match error {
                KiroTokenError::Invalidated
                | KiroTokenError::MissingCredential
                | KiroTokenError::EndpointMismatch => Failure::Blameless,
                KiroTokenError::Status {
                    status: 429,
                    retry_after,
                } => Failure::Rate {
                    retry_after: retry_after
                        .as_deref()
                        .and_then(crate::upstream::transport::parse_retry_after),
                },
                _ => Failure::Other,
            };
        }
        // Request-shape problems: the request itself is at fault.
        AttemptError::Protocol(_) => return Failure::Request,
    };
    let now = chrono::Utc::now();
    let retry_after = retry_after_raw.and_then(crate::upstream::transport::parse_retry_after);
    let header_reset =
        reset_header_raw.and_then(|raw| crate::upstream::transport::parse_reset_header(raw, now));
    let text = String::from_utf8_lossy(body);
    let tables = tables();
    let credit = hits(&tables.credit, &text);
    let broke = hits(&tables.broke, &text);
    let quota = hits(&tables.quota, &text);
    let unserved = hits(&tables.unserved, &text);
    let shape = hits(&tables.shape, &text);
    let refused = hits(&tables.refused, &text);

    // 2. Out of money: 402 always; credit words only on 400/403 (a 5xx mentioning
    // "billing" is an internal error, not a credit failure); on a 429 only the
    // broke subset counts. Quota words outrank credit's bare "billing": a
    // "monthly usage limit for this billing cycle" refusal is a full plan, not
    // an empty wallet.
    if status == 402
        || (credit && !quota && matches!(status, 400 | 403))
        || (status == 429 && broke)
    {
        return Failure::Credit;
    }
    // 3. The plan/channel does not serve this model: cool the (key, model) pair,
    // never the whole key — a route may hang several models on one key.
    if matches!(status, 400 | 403 | 404 | 422) && unserved && !quota && !refused {
        return Failure::Unserved;
    }
    // 4. The channel rejected the request shape.
    if matches!(status, 400 | 422) && shape && !quota && !unserved && !refused {
        return Failure::Blameless;
    }
    // 5. The channel refuses us outright.
    if refused {
        return Failure::Blameless;
    }
    // 6. A 429 is a short rate limit unless the body carries quota words. Quota
    //    rest evidence ladder: a body
    //    reset beats a reset header beats Retry-After — the more the vendor
    //    named the actual window end, the more precisely we sit out. Rate only
    //    trusts a header ask, capped at 30min.
    if status == 429 {
        return if quota {
            Failure::Quota {
                reset_until: body_reset(&text, now)
                    .or(header_reset)
                    .or_else(|| retry_after.map(|d| now + d.min(chrono::Duration::hours(1)))),
            }
        } else {
            Failure::Rate {
                retry_after: retry_after
                    .or_else(|| header_reset.map(|t| (t - now).min(chrono::Duration::minutes(30)))),
            }
        };
    }
    // 7. Quota words on any other status.
    if quota {
        return Failure::Quota {
            reset_until: body_reset(&text, now)
                .or(header_reset)
                .or_else(|| retry_after.map(|d| now + d.min(chrono::Duration::hours(1)))),
        };
    }
    // 8. Transferable statuses: auth-ish, request timeout, server errors.
    if matches!(status, 401 | 403 | 404 | 408) || status >= 500 {
        return Failure::Other;
    }
    // 9. Everything else (plain 400/413/422, any other 4xx): the request itself.
    Failure::Request
}

/// The most a vendor-stated quota reset is trusted (a week's window plus a
/// day over). Enforced in `Failure::rest_target`.
pub const MAX_QUOTA_REST: chrono::Duration = chrono::Duration::days(8);

/// A quota refusal's own word of when the allowance returns: Claude Code's
/// "usage limit reached|<unix>" in the message text, the ChatGPT-style JSON
/// `error.resets_at` / `error.resets_in_seconds`, or Google's
/// `error.details[].retryDelay` ("26s"). Absolutize at `now`; past resets
/// count as no word at all.
fn body_reset(
    text: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    static RESETS_WORDS: OnceLock<Option<Regex>> = OnceLock::new();
    if let Some(t) = RESETS_WORDS
        .get_or_init(|| Regex::new(r"(?i)limit reached\|(\d{9,13})\b").ok())
        .as_ref()
        && let Some(m) = t.captures(text)
        && let Ok(n) = m[1].parse::<i64>()
    {
        let (n, unit) = if n > 1_000_000_000_000 {
            (n, "ms")
        } else {
            (n, "s")
        };
        let t = if unit == "ms" {
            chrono::DateTime::from_timestamp_millis(n)
        } else {
            chrono::DateTime::from_timestamp(n, 0)
        };
        if let Some(t) = t.map(|t| t.with_timezone(&chrono::Utc))
            && t > now
        {
            return Some(t);
        }
    }
    if !text.contains("resets_at")
        && !text.contains("resets_in_seconds")
        && !text.contains("retryDelay")
    {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let error = value.get("error")?;
    if let Some(at) = error.get("resets_at").and_then(serde_json::Value::as_i64)
        && let Some(t) =
            chrono::DateTime::from_timestamp(at, 0).map(|t| t.with_timezone(&chrono::Utc))
        && t > now
    {
        return Some(t);
    }
    if let Some(secs) = error
        .get("resets_in_seconds")
        .and_then(serde_json::Value::as_i64)
        && secs > 0
    {
        return Some(now + chrono::Duration::seconds(secs));
    }
    if let Some(delay) = error
        .get("details")
        .and_then(serde_json::Value::as_array)
        .and_then(|details| {
            details
                .iter()
                .find_map(|d| d.get("retryDelay"))
                .and_then(|d| d.as_str())
        })
    {
        return crate::upstream::transport::parse_reset_header(delay, now).filter(|t| *t > now);
    }
    None
}

/// Consecutive-failure registry, identity = the key alone. Drives `Other`
/// backoff; cleared on success. Deleting a key may leave a stale entry here until the
/// process restarts — negligible.
pub struct Failures {
    counts: dashmap::DashMap<i64, u32>,
}

impl Failures {
    pub fn new() -> Self {
        Self {
            counts: dashmap::DashMap::new(),
        }
    }

    /// Record one more consecutive failure, returning the new count (1-based).
    pub fn bump(&self, key_id: i64) -> u32 {
        let mut entry = self.counts.entry(key_id).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    /// Reset the counter (a success breaks the streak).
    pub fn clear(&self, key_id: i64) {
        self.counts.remove(&key_id);
    }
}

impl Default for Failures {
    fn default() -> Self {
        Self::new()
    }
}

/// Failover state owned by the core: the consecutive-failure
/// registry plus the last-candidate retry pause base (test-injectable).
pub struct Failover {
    failures: Failures,
    /// Learned per-upstream optional-field refusals (`relay::optional`).
    unfit: optional::Unfit,
    /// Base of the last-candidate retry pause schedule (pause = base << attempt).
    retry_pause: Duration,
}

impl Failover {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            failures: Failures::new(),
            unfit: optional::Unfit::new(),
            retry_pause: Duration::from_secs(1),
        })
    }

    pub fn failures(&self) -> &Failures {
        &self.failures
    }

    pub fn unfit(&self) -> &optional::Unfit {
        &self.unfit
    }

    pub fn retry_pause(&self) -> Duration {
        self.retry_pause
    }

    /// Test hook: shrink the last-candidate retry pause.
    #[doc(hidden)]
    pub fn set_retry_pause(&mut self, pause: Duration) {
        self.retry_pause = pause;
    }
}
