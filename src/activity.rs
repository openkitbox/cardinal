//! Live activity feed: the relay publishes attempt lifecycle events on an
//! in-process broadcast channel and the GUI subscribes for its in-flight
//! block and ledger auto-refresh.
//!
//! Why an in-process broadcast channel: the gateway serves both the dispatch
//! entry points (publishers) and the admin SSE endpoint (subscriber) from the
//! same process, so a shared `tokio::sync::broadcast` channel needs no broker
//! at all. The GUI is DB-direct for management (#1249) but reaches this feed
//! over the gateway's own HTTP SSE endpoint, never directly.
//!
//! Semantics and budget discipline (mirrors the body capture's):
//! - Events are transient and lossy by design: nobody listening = events
//!   dropped; a listener that joins late sees nothing retroactive (a slow
//!   receiver loses the oldest events to `Lagged` — each SSE client holds its
//!   own receiver). The ledger rows in `gateway_requests` remain the source
//!   of truth; this feed only ever decorates the UI. The GUI self-heals drift
//!   with a slow poll.
//! - Publishing is fire-and-forget through the bounded channel; a full ring
//!   lags the slowest subscriber rather than blocking the hot path — the same
//!   fail-open rule accounting follows. Serialization now happens once per
//!   SSE frame (subscriber side), not once per event.
//! - The hot path (per SSE frame) only bumps two counters; the throttle
//!   gate runs before any serialization, so at most one Progress event per
//!   attempt per 500ms allocates an event.
//!
//! Wire shape (internally tagged, abbreviated):
//! - start: `{"t":"start","origin":2147483647,"seq":42,"client_model":"…","route":"…","account":"…","served_model":"…","protocol":"openai_chat","client_protocol":"…","effort":null,"reason":null,"caller":null,"agent":null,"key_id":7,"stream":true}`
//!   (`reason` = the Smart routing verdict for this candidate; `null` on
//!   ordered routes and resting candidates — a client treats null as "no
//!   reason", and the wire shape of pre-reason payloads is unchanged)
//! - first: `{"t":"first","origin":…,"seq":…}` · progress: `{"t":"progress","origin":…,"seq":…,"bytes":…,"frames":…}`
//! - end: `{"t":"end","origin":…,"seq":…,"status":"ok"}` — `status` is `"ok"`
//!   only for a genuine success; `"error"` for pre-commit failures/aborts/
//!   disconnects. A committed stream reads `"ok"` even if the client hangs up
//!   (the response committed, matching its 200 ledger row).
//! - persisted: `{"t":"persisted"}`

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Broadcast ring capacity (events). A slow SSE subscriber that falls this
/// far behind loses the oldest events to `Lagged` — the feed is decorative,
/// and the subscriber compensates with one synthetic
/// [`ActivityEvent::Persisted`] (the same self-heal a dropped frame needs).
const BROADCAST_CAPACITY: usize = 256;

/// Default minimum interval between Progress events of one attempt.
const DEFAULT_THROTTLE: Duration = Duration::from_millis(500);

/// Byte cap for user-controlled strings (labels, model names) in payloads
/// (the NOTIFY budget is bytes; truncation is char-boundary safe).
const MAX_LABEL: usize = 64;

/// One attempt lifecycle event (the wire contract shared by publisher and
/// subscriber). `origin` + `seq` identify an attempt across processes: `seq`
/// is a per-process counter, `origin` a random per-process tag, so a hosted
/// and an adopted standalone relay never collide.
///
/// Not `PartialEq`: [`Self::Bootstrap`] carries vendor quota readings, whose
/// float fields have no `Eq`. Tests match on variants instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ActivityEvent {
    /// An attempt started against an upstream (one per ledger row it will
    /// write; a failover reads as End → Start with a new seq). Exception:
    /// concurrency-gate rejections (queue timeout) write a ledger row without
    /// ever attempting upstream — they get no Start and never render in-flight.
    /// Boxed: a dozen string fields would bloat the enum far past its
    /// counters-only siblings. Serializes flat (tag + the struct's fields), so
    /// the wire shape is unchanged.
    Start(Box<StartEvent>),
    /// The response committed and the client starts receiving bytes (streaming
    /// attempts only; a JSON attempt stays "connecting" until End — the gap
    /// between headers and full body is not observed).
    First { origin: u32, seq: u64 },
    /// Client-bound byte/frame counters (throttled per attempt).
    Progress {
        origin: u32,
        seq: u64,
        bytes: u64,
        frames: u64,
    },
    /// The attempt resolved. `status` is `"ok"` only for a genuine successful
    /// completion — pre-commit failures, aborts and disconnects read `"error"`;
    /// a committed stream reads `"ok"` even if the client hangs up (the ledger
    /// row carries the precise outcome; the feed just says how the live row
    /// went away). `metrics` are that row's numbers, so a settled feed row
    /// shows the same duration and t/s as the 请求 page without a ledger read;
    /// absent on a payload from a publisher that predates them.
    End {
        origin: u32,
        seq: u64,
        status: EndStatus,
        #[serde(default)]
        metrics: EndMetrics,
    },
    /// Ledger rows were just inserted (the GUI refreshes its newest page and
    /// usage aggregates). Carries no payload: the reload is a full re-read.
    Persisted,
    /// A key-level concurrency slot was taken or released. `inflight` is the
    /// occupancy **after** the change (absolute, not a delta), so a dropped
    /// frame self-heals on the next event for that key. The GUI mirrors these
    /// directly instead of re-reading the admin API per request.
    Slot { key_id: i64, inflight: u32 },
    /// The subscriber missed events (ring lag): every mirror may be wrong, so
    /// pages re-read their sources. Carries no payload, like
    /// [`Self::Persisted`].
    Resync,
    /// A quota probe round completed (the GUI refreshes its quota cards).
    /// Carries no payload: the reload is a full re-read from the snapshot table.
    QuotaRefreshed,
    /// The admin bootstrap document: every parameterless read the status pages
    /// render from ([`crate::admin_ops::Bootstrap`]), assembled when a
    /// subscriber connects. Sent as the FIRST frame of a subscription, so
    /// opening the client costs one connection instead of a request per page.
    /// Boxed: the document dwarfs every other variant.
    Bootstrap(Box<crate::admin_ops::Bootstrap>),
}

/// The outcome an [`ActivityEvent::End`] reports: `"ok"` only when the
/// attempt completed genuinely successfully (including a committed stream
/// whose client later hung up), `"error"` for every pre-commit failure,
/// abort or disconnect (serialized snake_case on the wire).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndStatus {
    Ok,
    Error,
}

/// The ledger numbers an [`ActivityEvent::End`] reports — the token split and
/// timing of the row that attempt just wrote, i.e. what the feed's speed and
/// token group read (the same `decode_window` the 请求 page's 速度 column uses).
/// Every field is absent when the ledger has no such number (a pre-commit
/// failure billed no tokens) and on a payload from a publisher that predates
/// the struct.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndMetrics {
    /// Output tokens the upstream billed; None when the attempt never got a
    /// response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<i64>,
    /// The attempt's total wall-clock, as the ledger's `total_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<i32>,
    /// Time to first content (streaming attempts only; None otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<i64>,
    /// Prompt tokens as the kernel normalized them — the whole prompt, cache
    /// reads and writes included (so `input + output` is the row's token total).
    /// None when the attempt never got a response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<i64>,
    /// The cache-read slice of [`Self::input_tokens`] (None when the vendor
    /// reported no caching, or never answered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<i64>,
}

/// Why the candidate sits where it does in this request's order (Smart
/// routing verdict), `""` for ordered routes and resting candidates. Empty
/// strings serialize as `null` so pre-reason payloads stay byte-identical;
/// both `""` and `null` deserialize back to the empty reason.
///
/// A newtype with hand-written serde, not an `Option`-with-
/// `skip_serializing_if` like [`EndMetrics`]: a pre-reason payload carries the
/// field as `null`, so "absent" must decode to the empty reason rather than to
/// a missing field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerdictReason(String);

impl VerdictReason {
    fn new(reason: String) -> Self {
        Self(reason)
    }

    /// The wire value (`""` = no reason); what a listener reads.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The wire value, moved out — for the one consumer that must own it (the
    /// GUI's Start handler hands it to its feed state).
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Serialize for VerdictReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.is_empty() {
            serializer.serialize_none()
        } else {
            serializer.serialize_str(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for VerdictReason {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(
            Option::<String>::deserialize(deserializer)?.unwrap_or_default(),
        ))
    }
}

/// The payload of an [`ActivityEvent::Start`] (the old struct variant, boxed
/// so the whole enum stays small).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartEvent {
    pub origin: u32,
    pub seq: u64,
    /// Model id as the client sent it (route alias or `provider/model`).
    pub client_model: String,
    /// Route alias when the client hit a route.
    pub route: Option<String>,
    /// Account (key) label.
    pub account: Option<String>,
    /// Model the upstream is actually asked for.
    pub served_model: String,
    /// Client-facing protocol id (e.g. `openai_chat`).
    pub protocol: String,
    /// The protocol the client request arrived as (None: not yet stamped).
    pub client_protocol: Option<String>,
    /// The reasoning effort the client asked for.
    pub effort: Option<String>,
    /// Why the candidate sits where it does in this request's order — the
    /// Smart routing verdict reason, `""` for ordered routes / resting
    /// candidates (see [`AttemptStart::reason`]). Absent on the wire decodes to
    /// the empty reason like an explicit `null` does.
    #[serde(default)]
    pub reason: VerdictReason,
    /// The caller's identity (the gateway key's label); None for a loopback
    /// or in-process call.
    pub caller: Option<String>,
    /// Which client the request's User-Agent named (None = no header or an
    /// in-process call).
    pub agent: Option<String>,
    /// The provider key serving the attempt (identity for GUI-side matching —
    /// labels are clipped display strings, ids are not).
    pub key_id: Option<i64>,
    pub stream: bool,
}

impl StartEvent {
    /// The wire value's reason string (`""` = no reason).
    pub fn reason(&self) -> &str {
        self.reason.as_str()
    }
}

/// Publisher handle. Cheap to clone (Arc inside), shared by the dispatch
/// entry points exactly like `BodyLog`/`Failover`.
#[derive(Clone)]
pub struct ActivitySink {
    inner: Arc<Inner>,
}

struct Inner {
    /// `None` = disabled (unit tests drive the throttle without a channel).
    /// Events go through this single broadcast ring: one slot allocation per
    /// event on the publish path, zero tasks between publisher and subscriber
    /// — every SSE client's drain task holds its own receiver.
    tx: Option<tokio::sync::broadcast::Sender<ActivityEvent>>,
    origin: u32,
    seq: AtomicU64,
    /// Per-attempt Progress throttle, cleared on End (size = in-flight count).
    last_progress: dashmap::DashMap<u64, Instant>,
    throttle: Duration,
}

/// The identity of one upstream attempt, passed to [`ActivitySink::start`].
/// Strings are user-controlled and get truncated to the payload budget.
pub struct AttemptStart<'a> {
    /// Model id as the client sent it (route alias or `provider/model`).
    pub client_model: &'a str,
    /// Route alias when the client hit a route.
    pub route: Option<&'a str>,
    /// Account (key) label.
    pub account: Option<&'a str>,
    /// Model the upstream is actually asked for.
    pub served_model: &'a str,
    /// Client-facing protocol id (e.g. `openai_chat`).
    pub protocol: &'a str,
    /// The protocol the client request arrived as.
    pub client_protocol: Option<&'a str>,
    /// The reasoning effort the client asked for.
    pub effort: Option<&'a str>,
    /// The caller's identity (the gateway key's label); None for a loopback or
    /// in-process call.
    pub caller: Option<&'a str>,
    /// Which client the request's User-Agent named.
    pub agent: Option<&'a str>,
    /// Why the candidate sits where it does in this request's order — the
    /// Smart routing verdict ([`crate::relay::SmartVerdict::reason`]).
    /// Empty for ordered routes and for resting candidates; serialized as
    /// `null` on the wire (a listener treats null/`""` as "no reason").
    pub reason: &'a str,
    /// The provider key serving the attempt (identity for GUI-side matching).
    pub key_id: Option<i64>,
    pub stream: bool,
}

impl ActivitySink {
    /// Process-wide sink; `origin` distinguishes its events from any other
    /// publisher a subscriber might merge with.
    pub fn new() -> Self {
        // No rand dependency: pid ^ clock nanos is unique enough across two
        // local processes started milliseconds apart.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let (tx, _) = tokio::sync::broadcast::channel::<ActivityEvent>(BROADCAST_CAPACITY);
        Self::with_throttle(Some(tx), nanos ^ std::process::id(), DEFAULT_THROTTLE)
    }

    fn with_throttle(
        tx: Option<tokio::sync::broadcast::Sender<ActivityEvent>>,
        origin: u32,
        throttle: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                tx,
                origin,
                seq: AtomicU64::new(1),
                last_progress: dashmap::DashMap::new(),
                throttle,
            }),
        }
    }

    /// Publish a Start event and hand back this attempt's seq. Truncates
    /// user-controlled strings to keep payloads far under the NOTIFY limit.
    pub fn start(&self, attempt: AttemptStart<'_>) -> u64 {
        let seq = self.inner.seq.fetch_add(1, Ordering::Relaxed);
        self.publish(ActivityEvent::Start(Box::new(StartEvent {
            origin: self.inner.origin,
            seq,
            client_model: clip(attempt.client_model),
            route: attempt.route.map(clip),
            account: attempt.account.map(clip),
            served_model: clip(attempt.served_model),
            protocol: clip(attempt.protocol),
            client_protocol: attempt.client_protocol.map(clip),
            effort: attempt.effort.map(clip),
            caller: attempt.caller.map(clip),
            agent: attempt.agent.map(clip),
            reason: VerdictReason::new(clip(attempt.reason)),
            key_id: attempt.key_id,
            stream: attempt.stream,
        })));
        seq
    }

    /// The response committed; the client starts receiving bytes.
    pub fn first(&self, seq: u64) {
        self.publish(ActivityEvent::First {
            origin: self.inner.origin,
            seq,
        });
    }

    /// Client-bound counters, throttled: at most one event per attempt per
    /// throttle window (the gate runs before serialization).
    pub fn progress(&self, seq: u64, bytes: u64, frames: u64) {
        let now = Instant::now();
        if let Some(last) = self.inner.last_progress.get(&seq)
            && now.duration_since(*last) < self.inner.throttle
        {
            return;
        }
        self.inner.last_progress.insert(seq, now);
        self.publish(ActivityEvent::Progress {
            origin: self.inner.origin,
            seq,
            bytes,
            frames,
        });
    }

    /// The attempt resolved; clears its throttle slot. `status` is
    /// [`EndStatus::Ok`] only for a genuine successful completion; `metrics` are
    /// the ledger numbers of the row this attempt is about to write.
    pub fn end(&self, seq: u64, status: EndStatus, metrics: EndMetrics) {
        self.inner.last_progress.remove(&seq);
        self.publish(ActivityEvent::End {
            origin: self.inner.origin,
            seq,
            status,
            metrics,
        });
    }

    /// Ledger rows landed; listeners should re-read their view. Fired after
    /// the insert *attempt* — a swallowed insert failure still notifies (the
    /// refresh then simply re-reads unchanged data, same as a dropped event).
    pub fn persisted(&self) {
        self.publish(ActivityEvent::Persisted);
    }

    /// Announce a key-level slot's new occupancy (absolute count). The
    /// dispatcher calls this on acquire and release; the GUI mirrors it onto
    /// the account cards, so live concurrency costs no admin round-trip.
    pub fn slot(&self, key_id: i64, inflight: usize) {
        self.publish(ActivityEvent::Slot {
            key_id,
            inflight: u32::try_from(inflight).unwrap_or(u32::MAX),
        });
    }

    /// A quota probe round completed; listeners should re-read their quota
    /// cards from the snapshot table.
    pub fn quota_refreshed(&self) {
        self.publish(ActivityEvent::QuotaRefreshed);
    }

    /// Fire-and-forget: the broadcast `send` only fails when no subscriber
    /// exists (nobody listening = the event was decorative anyway — the GUI's
    /// slow poll self-heals any gap). A slow subscriber lags on its own ring
    /// and never blocks the publish path. A disabled sink (`tx: None`, unit
    /// tests) drops silently.
    fn publish(&self, event: ActivityEvent) {
        let Some(tx) = &self.inner.tx else { return };
        let _ = tx.send(event);
    }
}

impl Default for ActivitySink {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a user-controlled label ends after truncation to the payload budget,
/// on a char boundary. WIRE CONTRACT, shared at the rule level: this crate's
/// `clip` cuts a `String` for the wire and the GUI's `clipped()`
/// (crates/gui/src/activity.rs) borrows the same cut to compare wire values
/// against equally-truncated local labels. The GUI must stay allocation-free
/// there (it runs once per route entry against every live attempt on the
/// stage's 66ms beat), so the borrow half is not `clip` itself — both sides
/// ask this for the boundary instead. `MAX_LABEL` stays private.
pub fn clip_len(text: &str) -> usize {
    if text.len() <= MAX_LABEL {
        return text.len();
    }
    let mut end = MAX_LABEL;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Truncate a user-controlled string to the payload budget (char-boundary
/// safe) — the owned half of [`clip_len`].
fn clip(text: &str) -> String {
    text[..clip_len(text)].to_owned()
}

/// Subscribe to the activity feed: a drain task reads the sink's broadcast
/// ring and forwards events into a per-client mpsc channel (the stream type
/// [`ActivityReceiver`] has always carried). Must be called from within a
/// tokio runtime. The returned receiver is single-consumer — exactly one
/// drain (one SSE client) per `listen` call.
///
/// A receiver that falls more than [`BROADCAST_CAPACITY`] events behind the
/// publisher loses the gap to `Lagged`; the drain injects one synthetic
/// [`ActivityEvent::Resync`] in its place (and one at the start of every
/// subscription) so the pages re-read their sources and self-heal.
///
/// The drain is cancellation-aware: it watches the channel's closed state, so
/// a dropped receiver terminates the task promptly even on a quiet feed — not
/// only when the next event arrives. The returned handle joins the drain
/// task; dropping the handle detaches it (the task still self-terminates with
/// the receiver).
pub type ActivityReceiver = tokio::sync::mpsc::Receiver<ActivityEvent>;

/// Subscribe to the activity feed. `initial` is the connect frame sent before
/// anything from the ring: normally [`ActivityEvent::Bootstrap`], or
/// [`ActivityEvent::Resync`] when the caller could not assemble a bootstrap
/// (the subscriber then re-reads whatever it can).
pub fn listen(
    sink: &ActivitySink,
    initial: ActivityEvent,
) -> (ActivityReceiver, tokio::task::JoinHandle<()>) {
    let (tx, rx) = tokio::sync::mpsc::channel(256);
    let mut events = sink
        .inner
        .tx
        .as_ref()
        .map(tokio::sync::broadcast::Sender::subscribe);
    let drain = tokio::spawn(async move {
        let Some(events) = events.as_mut() else {
            return;
        }; // disabled sink: nothing to forward
        // The connect frame goes first: a fresh bootstrap makes the mirrors
        // correct without a re-read burst; a Resync makes them re-read.
        if tx.send(initial).await.is_err() {
            return; // GUI gone
        }
        loop {
            tokio::select! {
              event = events.recv() => match event {
                Ok(event) => {
                  if tx.send(event).await.is_err() {
                    return; // GUI gone
                  }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                  tracing::debug!("activity listener: {skipped} events lost (subscriber lagged); injecting Resync re-read");
                  if tx.send(ActivityEvent::Resync).await.is_err() {
                    return; // GUI gone
                  }
                }
                // The broadcast ring closed (every sink dropped): the feed is gone
                // for good — close the channel so the SSE stream ends.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
              },
              // A disconnected downstream terminates the drain promptly — without
              // this arm the task only exited when an event ARRIVED at the closed
              // channel: never, on a quiet feed.
              () = tx.closed() => return,
            }
        }
    });
    (rx, drain)
}
