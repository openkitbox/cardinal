//! Streaming relay pump: the pre-commit hold and the frame loop.
//!
//! Transport mechanics only — frames arrive from a `StreamReader`, buffer behind
//! the commit hold (an upstream that dies before the commit point can still be
//! failed over invisibly), then flush to the client as SSE byte chunks. No
//! vendor or dialect knowledge lives here (see [`super::dialects`]).

use crate::protocol::sse::RawFrame;
use crate::protocol::{self, ProtocolId};

use crate::activity::ActivitySink;
use crate::body_log::CapturedBody;
use crate::translation;
use crate::upstream::transport::{self, StreamReader};

use super::dispatcher::SlotGuard;
use super::{PAYLOAD_TARGET, truncate_payload};

/// Relay result: non-streaming JSON or streaming SSE.
pub(super) enum RelayOutcome {
    /// Non-streaming: JSON bytes to return plus observation.
    Json {
        status: u16,
        body: Vec<u8>,
        observed: protocol::ObservedResponse,
    },
    /// Streaming: the upstream 200 response is ready; the handler takes over streaming from here.
    Stream {
        status: u16,
        reader: Box<StreamReader>,
        /// Passthrough observer (same protocol) or translation synthesizer (cross-protocol).
        pump: StreamPump,
    },
}

/// What one attempt settled into before post-processing. Unlike
/// [`RelayOutcome`], a stream appears here only after the pump's hold
/// committed (the 200 headers alone no longer count as success).
pub(super) enum AttemptSuccess {
    /// Non-streaming success (see [`RelayOutcome::Json`]).
    Json {
        status: u16,
        body: Vec<u8>,
        observed: protocol::ObservedResponse,
    },
    /// Committed streaming success: the client is receiving frames; the usage
    /// rides in when the pump ends.
    Stream {
        status: u16,
        frames: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>,
        usage_rx: tokio::sync::oneshot::Receiver<StreamOutcome>,
    },
}

/// Streaming relay pump.
pub(super) enum StreamPump {
    /// Same-protocol passthrough: forward upstream frames verbatim, observing usage on the side.
    PassThrough { decoder: protocol::Decoder },
    /// Cross-protocol translation: synthesize upstream events into source-protocol SSE frames.
    Translated {
        upstream: ProtocolId,
        translator: translation::stream::StreamTranslator,
    },
}

/// The pump's one-shot verdict to the dispatcher, sent exactly once per
/// streaming attempt (a dropped channel means the pump panicked and reads as
/// `Aborted`).
pub(super) enum HoldSignal {
    /// The commit point passed: the buffered frames flush right after this
    /// signal and the client receives the stream. The attempt is locked in —
    /// no more failover. Signaled before the flush: the frame channel is not
    /// drained until the dispatcher sees this, so flushing first would
    /// deadlock past 32 buffered frames (see [`commit_hold`]).
    Committed,
    /// The upstream died before the commit point: nothing reached the client,
    /// so the attempt may fail over invisibly.
    Aborted,
    /// The client disconnected while the pump was still holding: stop the
    /// dispatch, blame nobody. Defensive and practically unreachable: the
    /// frame channel's receiver is only dropped after the dispatcher sees a
    /// signal, so its sends can never fail while the hold stands.
    ClientGone,
}

/// Pre-commit buffer cap: past it the hold commits with what it has (memory
/// safety outranks failover coverage).
const HOLD_MAX_BYTES: usize = 1024 * 1024;
/// Pre-commit wait cap: past it the hold commits with what it has (a slow
/// upstream is not a dead one). The request deadline bounds the hold window
/// from above — the reader never outlives the request budget.
const HOLD_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// Streaming hold: client frames are buffered until the
/// response provably commits — first content, a terminal frame, a full
/// buffer, or the wait cap — so an upstream that dies before the commit point
/// can be failed over without the client ever seeing a byte.
struct HoldState {
    buf: Vec<RawFrame>,
    bytes: usize,
    started: std::time::Instant,
    max_bytes: usize,
    max_wait: std::time::Duration,
}

impl HoldState {
    fn new() -> Self {
        Self::with_limits(HOLD_MAX_BYTES, HOLD_MAX_WAIT)
    }

    /// Explicit limits — the test hook for the cap/timeout commit paths.
    fn with_limits(max_bytes: usize, max_wait: std::time::Duration) -> Self {
        Self {
            buf: Vec::new(),
            bytes: 0,
            started: std::time::Instant::now(),
            max_bytes,
            max_wait,
        }
    }

    /// Buffer one client frame (a RawFrame clone is a `Bytes` refcount bump,
    /// not a copy).
    fn push(&mut self, frame: &RawFrame) {
        self.bytes += frame.data.len() + frame.event.as_deref().map_or(0, str::len);
        self.buf.push(frame.clone());
    }

    /// Remaining pre-commit read wait (zero once the window expired).
    fn remaining(&self) -> std::time::Duration {
        self.max_wait.saturating_sub(self.started.elapsed())
    }

    /// Commit test after buffering: real content or a terminal frame commits
    /// the response (an empty response is a legal response and must be
    /// delivered); a full buffer commits degenerately. `content`/`terminal`
    /// come from the protocol decoder or the translated event stream — the
    /// relay never sniffs bytes.
    fn commits(&self, content: bool, terminal: bool) -> bool {
        content || terminal || self.bytes >= self.max_bytes
    }

    /// EOF-while-holding test: only a Completed stream is delivered (possibly
    /// empty); anything else means the upstream died before producing a
    /// response — abort for failover.
    fn delivers(finish: protocol::Terminal) -> bool {
        matches!(finish, protocol::Terminal::Completed)
    }
}

/// One read step of the pump loop.
enum PumpRead {
    Frame(RawFrame),
    Eof,
    /// The hold's commit window expired while waiting: commit with whatever was
    /// buffered and continue as a normal stream.
    WindowExpired,
    Transport(transport::TransportError),
}

/// One read step of the pump loop, bounding the wait by the remaining commit
/// window while the hold stands. The read future is passed in (the caller
/// borrows the reader) so unit tests can drive the timing with a fake read.
async fn read_frame(
    read: impl std::future::Future<Output = Result<Option<RawFrame>, transport::TransportError>>,
    hold: Option<&HoldState>,
) -> PumpRead {
    let result = match hold {
        Some(hold) => {
            let remaining = hold.remaining();
            if remaining.is_zero() {
                return PumpRead::WindowExpired;
            }
            match tokio::time::timeout(remaining, read).await {
                Ok(result) => result,
                Err(_elapsed) => return PumpRead::WindowExpired,
            }
        }
        None => read.await,
    };
    match result {
        Ok(Some(frame)) => PumpRead::Frame(frame),
        Ok(None) => PumpRead::Eof,
        Err(error) => PumpRead::Transport(error),
    }
}

/// Flush the held buffer to the client and lift the hold. `false` = the
/// client is gone (the buffer is dropped either way). Flushed frames count
/// toward the activity feed like post-commit frames.
async fn flush_hold(
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    hold: &mut Option<HoldState>,
    activity: &mut Option<PumpActivity>,
    wire: &mut bytes::BytesMut,
) -> bool {
    let Some(held) = hold.take() else { return true };
    for frame in &held.buf {
        match send_frame(tx, frame, wire).await {
            Ok(bytes) => {
                if let Some(activity) = activity {
                    activity.frame(bytes);
                }
            }
            Err(_) => return false,
        }
    }
    true
}

/// Send the commit verdict exactly once; after that (or if the dispatcher
/// stopped listening) the send is a no-op.
fn signal_hold(
    commit_tx: &mut Option<tokio::sync::oneshot::Sender<HoldSignal>>,
    signal: HoldSignal,
) {
    if let Some(tx) = commit_tx.take() {
        let _ = tx.send(signal);
    }
}

/// Commit the hold: signal FIRST, then flush. The frame channel holds 32
/// slots and the dispatcher does not drain it until after `commit_rx`
/// resolves — flushing first would deadlock the pump once a commit fires
/// past 32 buffered frames, which would be wrong on every commit reason.
/// After the signal the dispatcher returns the Stream outcome and the HTTP
/// layer starts draining, so the flush merely waits for capacity and no
/// frame is lost; a flush failure is the pre-existing post-commit truncation
/// (the attempt is already locked in — no failover).
async fn commit_hold(
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    hold: &mut Option<HoldState>,
    commit_tx: &mut Option<tokio::sync::oneshot::Sender<HoldSignal>>,
    activity: &mut Option<PumpActivity>,
    wire: &mut bytes::BytesMut,
) {
    signal_hold(commit_tx, HoldSignal::Committed);
    if let Some(activity) = activity {
        activity.committed();
    }
    if !flush_hold(tx, hold, activity, wire).await {
        tracing::info!(
            "client disconnected while flushing the commit buffer; delivering the truncation"
        );
    }
}

/// Observed summary of one stream (for writing the requests row).
#[derive(Clone, Copy, Debug)]
pub(super) struct StreamUsage {
    pub(super) input_tokens: i64,
    pub(super) output_tokens: i64,
    pub(super) cached_input_tokens: Option<i64>,
    pub(super) cache_creation_input_tokens: Option<i64>,
    pub(super) cache_creation_1h_input_tokens: Option<i64>,
}

/// What the pump hands back when the stream ends: the observed usage plus the
/// captured response body (`Some` only when payload capture is on). An
/// aborted attempt's outcome is dropped unread with its receiver.
pub(super) struct StreamOutcome {
    pub(super) usage: Option<StreamUsage>,
    /// Attempt start → first content frame (text/reasoning/tool-call), from
    /// the attempt's own clock. None until the first content arrives; stays
    /// None for a stream that died contentless.
    pub(super) ttft_ms: Option<i64>,
    pub(super) captured: Option<CapturedBody>,
}

/// Live-activity reporter for one streaming attempt: counts client-bound
/// wire bytes/frames, publishes First at the commit point and throttled
/// Progress after it. Purely additive — a publish failure never touches the
/// stream (the sink is fire-and-forget).
struct PumpActivity {
    sink: ActivitySink,
    seq: u64,
    bytes: u64,
    frames: u64,
}

impl PumpActivity {
    fn new(sink: ActivitySink, seq: u64) -> Self {
        Self {
            sink,
            seq,
            bytes: 0,
            frames: 0,
        }
    }

    /// The hold committed: the client starts receiving bytes.
    fn committed(&self) {
        self.sink.first(self.seq);
    }

    /// One frame (of `bytes` wire bytes) reached the client.
    fn frame(&mut self, bytes: usize) {
        self.bytes += bytes as u64;
        self.frames += 1;
        self.sink.progress(self.seq, self.bytes, self.frames);
    }
}

/// Optional side-channel plumbing for the stream pump: payload logging,
/// body capture, the live-activity feed, and the attempt's start clock (the
/// ttft baseline — the pump reads frames after connect+opening, so it cannot
/// re-derive this).
pub(super) struct PumpSide {
    pub(super) payload_log: bool,
    pub(super) captured: Option<CapturedBody>,
    pub(super) activity: Option<(ActivitySink, u64)>,
    pub(super) started: std::time::Instant,
    /// Dispatch request id, so a post-commit upstream death can be traced back
    /// to its ledger row and routing trace.
    pub(super) request_id: String,
}

/// Start the streaming relay pump: a background task turns upstream frames
/// into client SSE byte chunks pushed via `tx`; when the stream ends it sends
/// the usage to `usage_tx`. `commit_tx` carries the one-shot hold verdict the
/// dispatcher waits on before locking the attempt in; `permit_rx` is the
/// dispatcher's permit handoff — a committed attempt's permits ride it and
/// are released when this task ends.
pub(super) fn spawn_stream_pump(
    mut reader: Box<StreamReader>,
    pump: StreamPump,
    usage_tx: tokio::sync::oneshot::Sender<StreamOutcome>,
    commit_tx: tokio::sync::oneshot::Sender<HoldSignal>,
    permit_rx: tokio::sync::oneshot::Receiver<SlotGuard>,
    side: PumpSide,
) -> tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(32);
    tokio::spawn(async move {
        let (usage, ttft_ms, captured) =
            drive_stream(&mut reader, pump, &tx, commit_tx, side).await;
        drop(reader); // release the upstream response
        drop(tx); // close the client stream
        // A committed attempt's permits sit in this channel and are released only
        // now — the stream has ended. An aborted attempt never sent them (the
        // dispatcher kept ownership through the failure path).
        drop(permit_rx);
        let _ = usage_tx.send(StreamOutcome {
            usage,
            ttft_ms,
            captured,
        });
    });
    rx
}

/// Pump main loop: process frame by frame until upstream EOF or client
/// disconnect. Returns the observed usage.
///
/// The streaming hold (see [`HoldState`]): client frames are buffered until
/// the response commits; the one-shot verdict goes to `commit_tx` so the
/// dispatcher can fail an aborted attempt over invisibly. Once committed,
/// behavior is exactly the pre-hold pump.
async fn drive_stream(
    reader: &mut StreamReader,
    pump: StreamPump,
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    commit_tx: tokio::sync::oneshot::Sender<HoldSignal>,
    side: PumpSide,
) -> (Option<StreamUsage>, Option<i64>, Option<CapturedBody>) {
    let PumpSide {
        payload_log,
        mut captured,
        activity,
        started,
        request_id,
    } = side;
    let mut activity = activity.map(|(sink, seq)| PumpActivity::new(sink, seq));
    let mut usage: Option<crate::protocol::usage::UsageCounts> = None;
    // Attempt start → first content frame. The kernel decoders' content_seen
    // is protocol-aware (text, reasoning or a
    // tool-call delta — role-only deltas don't count); the pump just reads the
    // flag after each observe.
    let mut ttft_ms: Option<i64> = None;
    let mut hold = Some(HoldState::new());
    let mut commit_tx = Some(commit_tx);
    // One SSE render buffer for the whole pump: every send freezes its bytes
    // out of it (`split()`), so the client-held `Bytes` stay independent while
    // the allocation is reused (held frames re-render from their own `RawFrame`
    // clones — `split()` is what makes that safe).
    let mut wire = bytes::BytesMut::new();
    match pump {
        StreamPump::PassThrough { mut decoder } => {
            loop {
                // A client that left mid-hold never commits: stop, don't fail over.
                if hold.is_some() && tx.is_closed() {
                    signal_hold(&mut commit_tx, HoldSignal::ClientGone);
                    return (None, ttft_ms, captured);
                }
                match read_frame(reader.next_raw_frame(), hold.as_ref()).await {
                    PumpRead::WindowExpired => {
                        // The wait cap commits the hold with whatever was buffered.
                        commit_hold(tx, &mut hold, &mut commit_tx, &mut activity, &mut wire).await;
                    }
                    PumpRead::Frame(frame) => {
                        if payload_log {
                            tracing::debug!(
                              target: PAYLOAD_TARGET,
                              direction = "upstream_frame",
                              event = frame.event.as_deref().unwrap_or(""),
                              data = %truncate_payload(&String::from_utf8_lossy(&frame.data), frame.data.len()),
                            );
                        }
                        // Body capture: the client receives held frames verbatim too
                        // (flushed on commit), so capture at read time either way.
                        if let Some(captured) = &mut captured {
                            captured.push(&frame.data);
                        }
                        // Observe on the side (a bad frame does not block forwarding).
                        let _ = decoder.observe_raw_for_relay(&frame);
                        if ttft_ms.is_none() && decoder.content_seen() {
                            ttft_ms = Some(started.elapsed().as_millis() as i64);
                        }
                        // Passthrough observation: raw observation yields no events; usage comes from the decoder.
                        if let Some(counts) = decoder.usage() {
                            usage = Some(counts);
                        }
                        if let Some(held) = &mut hold {
                            held.push(&frame);
                            if held.commits(decoder.content_seen(), decoder.terminal_seen()) {
                                commit_hold(
                                    tx,
                                    &mut hold,
                                    &mut commit_tx,
                                    &mut activity,
                                    &mut wire,
                                )
                                .await;
                            }
                        } else {
                            match send_frame(tx, &frame, &mut wire).await {
                                Ok(bytes) => {
                                    if let Some(activity) = &mut activity {
                                        activity.frame(bytes);
                                    }
                                }
                                Err(_) => return (None, ttft_ms, captured), // client disconnected
                            }
                        }
                    }
                    PumpRead::Eof => {
                        if hold.is_some() {
                            if HoldState::delivers(decoder.finish()) {
                                // A Completed stream is a legal (possibly empty) response:
                                // deliver it, never fail it over.
                                commit_hold(
                                    tx,
                                    &mut hold,
                                    &mut commit_tx,
                                    &mut activity,
                                    &mut wire,
                                )
                                .await;
                            } else {
                                // Died before the commit point: nothing reached the client.
                                tracing::info!(
                                    "stream ended before the commit point; aborting for failover"
                                );
                                signal_hold(&mut commit_tx, HoldSignal::Aborted);
                                return (None, ttft_ms, captured);
                            }
                        }
                        break;
                    }
                    PumpRead::Transport(error) => {
                        if hold.is_some() {
                            tracing::info!(
                                "stream read failed before the commit point ({error}); aborting for failover"
                            );
                            signal_hold(&mut commit_tx, HoldSignal::Aborted);
                            return (None, ttft_ms, captured);
                        }
                        tracing::warn!(
                            request_id = %request_id,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "upstream stream interrupted: {error}"
                        );
                        break;
                    }
                }
            }
        }
        StreamPump::Translated {
            upstream,
            mut translator,
        } => {
            let mut upstream = protocol::Decoder::new(upstream);
            let mut done = false;
            while !done {
                if hold.is_some() && tx.is_closed() {
                    signal_hold(&mut commit_tx, HoldSignal::ClientGone);
                    return (None, ttft_ms, captured);
                }
                match read_frame(reader.next_raw_frame(), hold.as_ref()).await {
                    PumpRead::WindowExpired => {
                        commit_hold(tx, &mut hold, &mut commit_tx, &mut activity, &mut wire).await;
                    }
                    PumpRead::Frame(frame) => {
                        if payload_log {
                            tracing::debug!(
                              target: PAYLOAD_TARGET,
                              direction = "upstream_frame",
                              event = frame.event.as_deref().unwrap_or(""),
                              data = %truncate_payload(&String::from_utf8_lossy(&frame.data), frame.data.len()),
                            );
                        }
                        // Observe + synthesize events straight from the raw frame bytes:
                        // no `String` re-framing hop, no per-frame payload copy. An
                        // undecodable frame (bad UTF-8 or bad JSON) is skipped whole.
                        let Ok(events) = upstream.observe_raw(&frame) else {
                            tracing::warn!("translated stream: undecodable upstream frame skipped");
                            continue;
                        };
                        if events.is_empty() {
                            continue;
                        }
                        for event in &events {
                            if let protocol::StreamEvent::Usage(counts) = event {
                                usage = Some(counts.clone());
                            }
                        }
                        let terminal_at_eof = events
                            .iter()
                            .any(|event| matches!(event, protocol::StreamEvent::Finish { .. }));
                        let content = events.iter().any(|event| {
                            matches!(
                                event,
                                protocol::StreamEvent::TextDelta(_)
                                    | protocol::StreamEvent::ReasoningDelta(_)
                                    | protocol::StreamEvent::ToolCallDelta { .. }
                            )
                        });
                        if ttft_ms.is_none() && content {
                            ttft_ms = Some(started.elapsed().as_millis() as i64);
                        }
                        // Event → source-protocol client frame.
                        let Ok(frames) = translator.translate(events) else {
                            tracing::warn!(
                                "translated stream: event failed to translate; frame skipped"
                            );
                            continue;
                        };
                        // Body capture records the CLIENT-facing (translated) frames.
                        if let Some(captured) = &mut captured {
                            for frame in &frames {
                                captured.push(&frame.data);
                            }
                        }
                        if let Some(held) = &mut hold {
                            for frame in &frames {
                                held.push(frame);
                            }
                            if held.commits(content, terminal_at_eof) {
                                commit_hold(
                                    tx,
                                    &mut hold,
                                    &mut commit_tx,
                                    &mut activity,
                                    &mut wire,
                                )
                                .await;
                            }
                        } else {
                            for frame in frames {
                                match send_frame(tx, &frame, &mut wire).await {
                                    Ok(bytes) => {
                                        if let Some(activity) = &mut activity {
                                            activity.frame(bytes);
                                        }
                                    }
                                    Err(_) => return (None, ttft_ms, captured), // client disconnected
                                }
                            }
                        }
                        if terminal_at_eof {
                            done = true;
                        }
                    }
                    PumpRead::Eof => {
                        if hold.is_some() {
                            if HoldState::delivers(upstream.finish()) {
                                // Empty-but-complete: close the translator into the hold so
                                // the client receives the full (empty) stream.
                                if let Ok(frames) =
                                    translator.close_after_eof(protocol::Terminal::Completed)
                                {
                                    if let Some(captured) = &mut captured {
                                        for frame in &frames {
                                            captured.push(&frame.data);
                                        }
                                    }
                                    if let Some(held) = &mut hold {
                                        for frame in &frames {
                                            held.push(frame);
                                        }
                                    }
                                }
                                commit_hold(
                                    tx,
                                    &mut hold,
                                    &mut commit_tx,
                                    &mut activity,
                                    &mut wire,
                                )
                                .await;
                            } else {
                                tracing::info!(
                                    "translated stream ended before the commit point; aborting for failover"
                                );
                                signal_hold(&mut commit_tx, HoldSignal::Aborted);
                                return (None, ttft_ms, captured);
                            }
                            break;
                        }
                        // Upstream EOF: finish as Completed; a truncated stream counts as Incomplete.
                        if let Ok(frames) =
                            translator.close_after_eof(protocol::Terminal::Completed)
                        {
                            if let Some(captured) = &mut captured {
                                for frame in &frames {
                                    captured.push(&frame.data);
                                }
                            }
                            for frame in frames {
                                match send_frame(tx, &frame, &mut wire).await {
                                    Ok(bytes) => {
                                        if let Some(activity) = &mut activity {
                                            activity.frame(bytes);
                                        }
                                    }
                                    Err(_) => return (None, ttft_ms, captured),
                                }
                            }
                        }
                        done = true;
                    }
                    PumpRead::Transport(error) => {
                        if hold.is_some() {
                            tracing::info!(
                                "translated stream read failed before the commit point ({error}); aborting for failover"
                            );
                            signal_hold(&mut commit_tx, HoldSignal::Aborted);
                            return (None, ttft_ms, captured);
                        }
                        tracing::warn!(
                            request_id = %request_id,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "upstream stream interrupted: {error}"
                        );
                        if let Ok(frames) =
                            translator.close_after_eof(protocol::Terminal::Incomplete)
                        {
                            if let Some(captured) = &mut captured {
                                for frame in &frames {
                                    captured.push(&frame.data);
                                }
                            }
                            for frame in frames {
                                match send_frame(tx, &frame, &mut wire).await {
                                    Ok(bytes) => {
                                        if let Some(activity) = &mut activity {
                                            activity.frame(bytes);
                                        }
                                    }
                                    Err(_) => return (None, ttft_ms, captured),
                                }
                            }
                        }
                        done = true;
                    }
                }
            }
        }
    }
    let usage = usage.map(|counts| StreamUsage {
        input_tokens: counts.input_tokens as i64,
        output_tokens: counts.output_tokens as i64,
        cached_input_tokens: counts.cached_input_tokens.map(|v| v as i64),
        cache_creation_input_tokens: counts.cache_creation_input_tokens.map(|v| v as i64),
        cache_creation_1h_input_tokens: counts.cache_creation_1h_input_tokens.map(|v| v as i64),
    });
    (usage, ttft_ms, captured)
}

/// Render one frame into SSE wire bytes. `wire` is a render buffer reused
/// across frames: each send reserves into it and freezes its bytes out with
/// `split()`, so the `Bytes` the client channel holds are independent of the
/// buffer while the allocation is amortized instead of fresh per frame.
async fn send_frame(
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    frame: &RawFrame,
    wire: &mut bytes::BytesMut,
) -> Result<usize, std::io::Error> {
    wire.reserve(frame.data.len() + 8 + frame.event.as_deref().map_or(0, |event| event.len() + 8));
    if let Some(event) = &frame.event {
        wire.extend_from_slice(b"event: ");
        wire.extend_from_slice(event.as_bytes());
        wire.extend_from_slice(b"\n");
    }
    wire.extend_from_slice(b"data: ");
    wire.extend_from_slice(&frame.data);
    wire.extend_from_slice(b"\n\n");
    let len = wire.len();
    tx.send(Ok(wire.split().freeze()))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client gone"))?;
    Ok(len)
}
