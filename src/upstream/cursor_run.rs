//! One Cursor Run, the way the IDE runs it (plan D1, T6; IDE alignment
//! 2026-11-07).
//!
//! The primary transport is the IDE's: one HTTP/2 Connect bidi stream,
//! `AgentService/Run` on the agent-stream origin, whose request body is the
//! client messages (the `run_request` first, then every answer) and whose
//! response body is the server messages. When that stream cannot open —
//! HTTP/2 unreachable, the route gone, the front door failing — the Run falls
//! back to the IDE's own HTTP/1.1 arrangement, the split transport: two HTTP
//! legs on one `x-request-id`, the downlink a `RunSSE` response whose body is
//! the same Connect frame stream, the uplink one `BidiAppend` POST per client
//! message, numbered from zero, on the provider's origin.
//! `CARDINAL_CURSOR_TRANSPORT=split` skips the stream (the IDE's "disable
//! HTTP/2" setting).
//!
//! Either way [`open`] hands the relay a frame channel it reads like any other
//! upstream body ([`crate::upstream::transport::Transport::stream_frames`]);
//! the driver task behind it does everything the protocol needs while the
//! relay only reads:
//!
//! * every downlink frame is observed by the protocol kernel's pure parts —
//!   [`Uplink::react`] decides what to send up (blob lookups, the tool list,
//!   the environment, refusals of Cursor's own tools), a [`StreamDecoder`]
//!   decides when the Run is over — and then forwarded **unchanged** to the
//!   relay, so the translating pump sees exactly the upstream wire;
//! * the uplink is one ordered channel of client messages, a heartbeat every
//!   [`HEARTBEAT`]. On the stream it is simply the request body; on the split
//!   transport the appender keeps the reference's discipline: at most
//!   [`MAX_IN_FLIGHT`] appends at once, KV replies may overlap, anything else
//!   goes alone after everything before it settled, each append bounded by
//!   [`APPEND_WAIT`] plus one second per 64 KiB;
//! * when the Run must end on this side — the step's calls are complete, an
//!   append failed, Cursor went quiet, the tool count never came — the driver
//!   synthesizes the Connect end frame the peer would have sent
//!   (`{}` or `{"error":…}`), so the relay's decoder reaches its verdict from
//!   the wire alone, and cancels the other leg.
//!
//! Credentials travel only in the headers the relay hands over; nothing here
//! logs them, and the error bodies that reach the relay are Cursor's own
//! words, bounded.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::protocol::cursor::connect::{Frame, Framer, encode_frame};
use crate::protocol::cursor::msg;
use crate::protocol::cursor::pb::Writer;
use crate::protocol::cursor::request::{self as cursor_request, RunPlan};
use crate::protocol::cursor::response::{self, Failure, Retention, StreamDecoder};
use crate::protocol::cursor::uplink::{self, Outbound};
use crate::protocol::usage::UsageCounts;
use crate::protocol::wire::WireFrame;
use crate::protocol::{Prepared, ProtocolId};
use crate::upstream::transport::{self, Transport, TransportError};

/// Appends in flight at once (the reference's `H1.atOnce`).
pub const MAX_IN_FLIGHT: usize = 16;
/// Base wait for one append's answer; a large one gets a second per 64 KiB.
pub const APPEND_WAIT: Duration = Duration::from_secs(60);
/// Client heartbeat period.
pub const HEARTBEAT: Duration = Duration::from_secs(5);
/// No frame at all for this long: the Run is dead.
pub const QUIET_IDLE: Duration = Duration::from_secs(60);
/// Only heartbeats for this long: the Run is dead.
pub const QUIET_HEARTBEATS: Duration = Duration::from_secs(240);
/// Calls came but the step's count never did: after this long since the last
/// real frame, with no call still being written, the calls are the step's.
pub const COUNT_WAIT: Duration = Duration::from_secs(60);
/// Frames buffered toward the relay before the driver waits on it.
const FRAME_CHANNEL: usize = 64;
/// Messages buffered toward the appender.
const UPLINK_CHANNEL: usize = 64;

/// What one Run leaves for the settlement: the conversation it ran under, the
/// clock of its close (the dashboard query's lower bound), and the sizes the
/// estimate falls back on.
#[derive(Clone, Debug)]
pub struct RunReport {
    pub conversation_id: String,
    pub started_at: DateTime<Utc>,
    pub closed_at: DateTime<Utc>,
    /// Characters of the rendered prompt.
    pub prompt_chars: u64,
    /// Characters the model produced (text, reasoning, tool arguments).
    pub output_chars: u64,
    /// The Run's inline usage, when Cursor sent any: the turn total (`#14`)
    /// for a turn that ended with counters. `None` for a tool step and for a
    /// counter-less turn — then the settlement reconciles from the dashboard
    /// or estimates.
    pub inline_usage: Option<UsageCounts>,
    /// Whether the step called tools.
    pub called_tools: bool,
}

/// An open Run, handed to the relay.
pub struct Run {
    /// The HTTP status of the downlink (always 2xx here).
    pub status: u16,
    /// The transport the Run opened on.
    pub leg: Leg,
    /// The downlink frames, as the relay's stream reader takes them.
    pub frames: mpsc::Receiver<Result<WireFrame, TransportError>>,
    /// The Run's report, resolved when it closes.
    pub report: oneshot::Receiver<RunReport>,
}

impl Run {
    /// Read the whole downlink into one byte body (every frame re-encoded as
    /// on the wire), for the non-streaming path's aggregate decode.
    pub async fn collect(
        &mut self,
        limit: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError> {
        let mut body = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout);
            }
            let next = match tokio::time::timeout(remaining, self.frames.recv()).await {
                Err(_) => return Err(TransportError::Timeout),
                Ok(None) => break,
                Ok(Some(Err(error))) => return Err(error),
                Ok(Some(Ok(WireFrame::Connect(frame)))) => frame,
                Ok(Some(Ok(_))) => return Err(TransportError::InvalidBody),
            };
            let encoded = next.encode().map_err(|_| TransportError::BodyTooLarge)?;
            if body.len() + encoded.len() > limit {
                return Err(TransportError::BodyTooLarge);
            }
            body.extend_from_slice(&encoded);
        }
        Ok(body)
    }
}

/// Open one Run: the bidi stream first, the split transport when the stream
/// cannot open (or `CARDINAL_CURSOR_TRANSPORT=split`).
///
/// `auth` is the Authorization header (and the team header) the relay
/// resolved; `prepared` is the kernel's `Run` request with its
/// [`Prepared::cursor`] plan. A non-2xx answer, an uplink failure before
/// anything came down, or an error end frame as the first real frame all
/// return as [`TransportError::Status`] carrying the mapped status and
/// Cursor's words, so the relay treats them like any upstream refusal (401
/// refresh, 429 rest, failover).
pub async fn open(
    transport: &Transport,
    prepared: &Prepared,
    auth: &[(&'static str, String)],
    deadline: Instant,
) -> Result<Run, TransportError> {
    let plan = prepared.cursor.clone().ok_or(TransportError::InvalidBody)?;
    if bidi_enabled() {
        match open_bidi(transport, prepared, &plan, auth, deadline).await {
            Ok(run) => return Ok(run),
            Err(Opening::Refused(error)) => return Err(error),
            Err(Opening::Fallback(error)) => {
                tracing::warn!(
                    request_id = %plan.request_id,
                    %error,
                    "Cursor bidi Run could not open; falling back to the split transport"
                );
            }
        }
    }
    open_split(transport, &plan, auth, deadline).await
}

/// Which transport a Run opens on, as the relay reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leg {
    /// One HTTP/2 Connect bidi stream (`AgentService/Run`).
    Bidi,
    /// `RunSSE` down, `BidiAppend` up, over HTTP/1.1.
    Split,
}

impl Leg {
    /// The label the relay logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bidi => "bidi",
            Self::Split => "split",
        }
    }
}

/// Whether the bidi stream is tried at all. `CARDINAL_CURSOR_TRANSPORT=split`
/// goes straight to the split transport; anything else (or unset) tries the
/// stream first. Read once.
fn bidi_enabled() -> bool {
    static BIDI: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *BIDI.get_or_init(|| {
        let enabled = !std::env::var("CARDINAL_CURSOR_TRANSPORT")
            .map(|value| value.trim().eq_ignore_ascii_case("split"))
            .unwrap_or(false);
        if !enabled {
            tracing::info!(
                "Cursor Runs use the split transport only (CARDINAL_CURSOR_TRANSPORT=split)"
            );
        }
        enabled
    })
}

/// How the bidi leg failed to open.
enum Opening {
    /// Cursor answered and refused: the relay's business (refresh, rest,
    /// failover). The split transport would be refused the same way.
    Refused(TransportError),
    /// The stream itself could not be had: no HTTP/2 connection, no answer in
    /// time, the route or the front door failing. Try the split transport.
    Fallback(TransportError),
}

/// The bidi leg: `POST AgentService/Run` with the client messages as the
/// request body.
async fn open_bidi(
    transport: &Transport,
    prepared: &Prepared,
    plan: &Arc<RunPlan>,
    auth: &[(&'static str, String)],
    deadline: Instant,
) -> Result<Run, Opening> {
    let started_at = Utc::now();
    let (uplink_tx, uplink_rx) = mpsc::channel::<Outbound>(UPLINK_CHANNEL);
    // The first message is the run request; the channel has room, so this
    // never waits.
    if uplink_tx
        .send(Outbound {
            bytes: plan.run_request.clone(),
            overlaps: false,
        })
        .await
        .is_err()
    {
        return Err(Opening::Refused(TransportError::InvalidBody));
    }
    // The request body: every client message, Connect-framed, in order. It
    // ends when the driver drops its sender — the Run is over.
    let body = futures::stream::unfold(uplink_rx, |mut inbox| async move {
        let message = inbox.recv().await?;
        let frame = encode_frame(&message.bytes)
            .map_err(|_| std::io::Error::other("client message too large for a Connect frame"));
        Some((frame, inbox))
    });
    let response = match transport.send_bidi(prepared, auth, body, deadline).await {
        Ok(response) => response,
        Err(error @ (TransportError::Connect | TransportError::Timeout)) => {
            return Err(Opening::Fallback(error));
        }
        Err(error) => return Err(Opening::Refused(error)),
    };
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let headers = response.headers().clone();
        let body = transport
            .read_body(response, transport::MAX_ERROR_BODY, deadline)
            .await
            .unwrap_or_default();
        let error = transport::status_error(status, &headers, Bytes::from(body))
            .unwrap_or(TransportError::InvalidBody);
        // A refusal of the caller (bad request, bearer, quota) stands; the
        // route or the front door failing is the stream's problem.
        return Err(match status {
            400 | 401 | 403 | 429 => Opening::Refused(error),
            _ => Opening::Fallback(error),
        });
    }
    finish_open(
        transport,
        plan,
        Opened {
            leg: Leg::Bidi,
            response,
            uplink_tx,
            fail_rx: None,
            cancel: CancellationToken::new(),
            started_at,
        },
        deadline,
    )
    .await
    .map_err(Opening::Refused)
}

/// The split leg: the downlink `RunSSE`, then the uplink with the
/// `run_request` as append 0.
async fn open_split(
    transport: &Transport,
    plan: &Arc<RunPlan>,
    auth: &[(&'static str, String)],
    deadline: Instant,
) -> Result<Run, TransportError> {
    let started_at = Utc::now();
    let downlink = Prepared {
        protocol: ProtocolId::Cursor,
        url: plan.sse_url.clone(),
        content_type: cursor_request::CONNECT_PROTO,
        body: plan.sse_body.clone(),
        stream: true,
        headers: cursor_request::run_headers(&plan.request_id),
        cursor: None,
    };
    let response = transport
        .send_with_headers(&downlink, auth, &[], deadline)
        .await?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let headers = response.headers().clone();
        let body = transport
            .read_body(response, transport::MAX_ERROR_BODY, deadline)
            .await
            .unwrap_or_default();
        return Err(transport::status_error(status, &headers, Bytes::from(body))
            .unwrap_or(TransportError::InvalidBody));
    }

    let cancel = CancellationToken::new();
    // The uplink: its own task, fed by the driver.
    let (uplink_tx, uplink_rx) = mpsc::channel(UPLINK_CHANNEL);
    let (fail_tx, fail_rx) = oneshot::channel();
    let appender = Appender {
        transport: transport.clone(),
        url: plan.append_url.clone(),
        headers: append_headers(&plan.request_id, auth),
        request_id: plan.request_id.clone(),
        cancel: cancel.clone(),
    };
    tokio::spawn(appender.run(uplink_rx, fail_tx));
    // Append 0 is the run request; the channel has room, so this never waits.
    if uplink_tx
        .send(Outbound {
            bytes: plan.run_request.clone(),
            overlaps: false,
        })
        .await
        .is_err()
    {
        cancel.cancel();
        return Err(TransportError::InvalidBody);
    }
    finish_open(
        transport,
        plan,
        Opened {
            leg: Leg::Split,
            response,
            uplink_tx,
            fail_rx: Some(fail_rx),
            cancel,
            started_at,
        },
        deadline,
    )
    .await
}

/// One leg's 2xx answer with its uplink, before the driver starts.
struct Opened {
    leg: Leg,
    response: reqwest::Response,
    /// The ordered client-message channel the driver writes.
    uplink_tx: mpsc::Sender<Outbound>,
    /// The appender's failure report (split transport only; the stream's
    /// uplink failures surface on the response body).
    fail_rx: Option<oneshot::Receiver<Failure>>,
    cancel: CancellationToken,
    started_at: DateTime<Utc>,
}

/// The part of opening both legs share: start the driver on the 2xx response
/// and wait for the Run's first verdict.
async fn finish_open(
    transport: &Transport,
    plan: &Arc<RunPlan>,
    opened: Opened,
    deadline: Instant,
) -> Result<Run, TransportError> {
    let Opened {
        leg,
        response,
        uplink_tx,
        fail_rx,
        cancel,
        started_at,
    } = opened;
    let status = response.status().as_u16();
    let (frames_tx, frames_rx) = mpsc::channel(FRAME_CHANNEL);
    let (report_tx, report_rx) = oneshot::channel();
    let (first_tx, first_rx) = oneshot::channel();
    let heard = Arc::new(AtomicBool::new(false));
    let driver = Driver {
        plan: Arc::clone(plan),
        decoder: StreamDecoder::new(Retention::CountsOnly),
        frames_tx,
        uplink_tx,
        first_tx: Some(first_tx),
        heard: Arc::clone(&heard),
        started_at,
        deadline,
    };
    let driver_task = tokio::spawn(drive(driver, response, fail_rx, report_tx, cancel.clone()));

    // The first real frame decides whether the Run opened: an error end frame
    // (quota, auth, a model refusal) is an upstream refusal to the relay. A
    // Run that only heartbeats through the opening window is alive and slow
    // — hand it over; the pump's hold takes it from here.
    let opening = transport
        .limits()
        .opening
        .min(deadline.saturating_duration_since(Instant::now()));
    match tokio::time::timeout(opening, first_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(failure))) => {
            cancel.cancel();
            driver_task.abort();
            return Err(TransportError::Status {
                status: failure.status,
                retry_after: None,
                reset_header: None,
                body: Bytes::from(failure.message),
            });
        }
        // The driver died before any verdict.
        Ok(Err(_)) => {
            cancel.cancel();
            return Err(TransportError::InvalidBody);
        }
        Err(_) if heard.load(Ordering::Acquire) => {}
        Err(_) => {
            cancel.cancel();
            driver_task.abort();
            tracing::warn!(request_id = %plan.request_id, leg = leg.as_str(), "Cursor Run sent nothing within the opening deadline");
            return Err(TransportError::Timeout);
        }
    }
    tracing::debug!(request_id = %plan.request_id, leg = leg.as_str(), "Cursor Run opened");
    Ok(Run {
        status,
        leg,
        frames: frames_rx,
        report: report_rx,
    })
}

/// The headers every append carries: the Run's own (client form, request id)
/// plus the relay's credential headers.
fn append_headers(
    request_id: &str,
    auth: &[(&'static str, String)],
) -> Vec<(&'static str, String)> {
    let mut headers = cursor_request::run_headers(request_id);
    headers.extend(auth.iter().cloned());
    headers
}

/// The downlink side of one Run.
struct Driver {
    plan: Arc<RunPlan>,
    decoder: StreamDecoder,
    frames_tx: mpsc::Sender<Result<WireFrame, TransportError>>,
    uplink_tx: mpsc::Sender<Outbound>,
    first_tx: Option<oneshot::Sender<Result<(), Failure>>>,
    heard: Arc<AtomicBool>,
    started_at: DateTime<Utc>,
    deadline: Instant,
}

/// Why the driver stops reading.
enum Stop {
    /// The Run reached its terminal (the decoder said so, or an end frame
    /// was synthesized and forwarded).
    Done,
    /// The relay stopped reading: nobody wants the rest.
    RelayGone,
}

async fn drive(
    mut driver: Driver,
    response: reqwest::Response,
    mut fail_rx: Option<oneshot::Receiver<Failure>>,
    report_tx: oneshot::Sender<RunReport>,
    cancel: CancellationToken,
) {
    let request_id = driver.plan.request_id.clone();
    let mut body = response.bytes_stream();
    // The appender's failure report, on the split transport; the stream has
    // no separate uplink to fail, so its arm never fires.
    let mut uplink_failed = std::pin::pin!(async move {
        match fail_rx.as_mut() {
            Some(fail_rx) => fail_rx.await,
            None => std::future::pending().await,
        }
    });
    let mut framer = Framer::new();
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_any = Instant::now();
    let mut last_real = Instant::now();
    let stop = loop {
        // One wake-up for every clock the Run keeps.
        let mut wake = driver
            .deadline
            .min(last_any + QUIET_IDLE)
            .min(last_real + QUIET_HEARTBEATS);
        let counting = driver.decoder.called_tools()
            && !driver.decoder.listed()
            && driver.decoder.writing() == 0;
        if counting {
            wake = wake.min(last_real + COUNT_WAIT);
        }
        tokio::select! {
            biased;
            failure = &mut uplink_failed => {
                // The uplink failed: the Run cannot go on. Cursor's words
                // travel in the synthesized end frame.
                let failure = failure.unwrap_or_else(|_| response::map_failure(200, "unavailable", "BidiAppend ended"));
                tracing::warn!(request_id = %request_id, status = failure.status, "Cursor uplink failed; ending the Run");
                break driver.end_with(error_end(&failure)).await;
            }
            _ = heartbeat.tick() => {
                let _ = driver.uplink_tx.try_send(uplink::heartbeat());
            }
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {
                let now = Instant::now();
                if now >= driver.deadline {
                    let _ = driver.frames_tx.send(Err(TransportError::Timeout)).await;
                    break Stop::Done;
                }
                if counting && now >= last_real + COUNT_WAIT {
                    tracing::info!(request_id = %request_id, "Cursor sent the step's calls but no count; taking them as the step's");
                    break driver.end_with(clean_end()).await;
                }
                if now >= last_any + QUIET_IDLE {
                    let failure = response::map_failure(200, "unavailable", "Cursor went quiet: no frame for 60s (try again)");
                    break driver.end_with(error_end(&failure)).await;
                }
                if now >= last_real + QUIET_HEARTBEATS {
                    let failure = response::map_failure(200, "unavailable", "Cursor sent only heartbeats for 240s (try again)");
                    break driver.end_with(error_end(&failure)).await;
                }
            }
            chunk = body.next() => {
                match chunk {
                    None => {
                        if framer.finish().is_err() {
                            let _ = driver.frames_tx.send(Err(TransportError::InvalidBody)).await;
                            break Stop::Done;
                        }
                        // EOF with the step's calls out is a finished step
                        // (the reference's rule); with nothing, a broken reply.
                        if driver.decoder.called_tools() {
                            break driver.end_with(clean_end()).await;
                        }
                        let failure = response::map_failure(200, "unavailable", "the reply broke off: EOF");
                        break driver.end_with(error_end(&failure)).await;
                    }
                    Some(Err(error)) => {
                        let error = if error.is_timeout() { TransportError::Timeout } else { TransportError::InvalidBody };
                        let _ = driver.frames_tx.send(Err(error)).await;
                        break Stop::Done;
                    }
                    Some(Ok(chunk)) => {
                        let frames = match framer.push(&chunk) {
                            Ok(frames) => frames,
                            Err(error) => {
                                tracing::warn!(request_id = %request_id, %error, "Cursor downlink framing failed");
                                let _ = driver.frames_tx.send(Err(TransportError::InvalidBody)).await;
                                break Stop::Done;
                            }
                        };
                        let mut stop = None;
                        for frame in frames {
                            let now = Instant::now();
                            last_any = now;
                            if !response::is_heartbeat(&frame) {
                                last_real = now;
                            }
                            if let Some(verdict) = driver.observe(frame).await {
                                stop = Some(verdict);
                                break;
                            }
                        }
                        if let Some(stop) = stop {
                            break stop;
                        }
                    }
                }
            }
        }
    };
    cancel.cancel();
    drop(body);
    let Driver {
        plan,
        decoder,
        frames_tx,
        started_at,
        ..
    } = driver;
    drop(frames_tx);
    if matches!(stop, Stop::RelayGone) {
        tracing::debug!(request_id = %request_id, "relay stopped reading the Cursor Run; closed");
    }
    let _ = report_tx.send(RunReport {
        conversation_id: plan.conversation_id.clone(),
        started_at,
        closed_at: Utc::now(),
        prompt_chars: plan.prompt_chars,
        output_chars: decoder.output_chars() as u64,
        inline_usage: decoder.usage(),
        called_tools: decoder.called_tools(),
    });
}

impl Driver {
    /// Handle one downlink frame: answer it, observe it, forward it. `Some`
    /// when the Run is over.
    async fn observe(&mut self, frame: Frame) -> Option<Stop> {
        self.heard.store(true, Ordering::Release);
        match self.plan.uplink.react(&frame) {
            Ok(replies) => {
                for reply in replies {
                    if self.uplink_tx.send(reply).await.is_err() {
                        // The appender is gone (it failed and reported); the
                        // failure channel ends the Run on the next turn.
                        break;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(request_id = %self.plan.request_id, %error, "Cursor server message could not be answered");
            }
        }
        // The driver's own copy of the state machine: termination only.
        let _ = self.decoder.observe(&frame);
        if frame.is_end()
            && let Some(failure) = self.decoder.failure()
        {
            // The client gets the platform's fixed words; Cursor's own go to
            // the operator's log, with anything token-shaped excised.
            tracing::warn!(
                request_id = %self.plan.request_id,
                status = failure.status,
                message = %without_tokens(&failure.message),
                "Cursor ended the Run with an error"
            );
        }
        let real = !response::is_heartbeat(&frame);
        if real && let Some(first) = self.first_tx.take() {
            let verdict = match (frame.is_end(), self.decoder.failure()) {
                (true, Some(failure)) => Err(failure.clone()),
                _ => Ok(()),
            };
            let refused = verdict.is_err();
            // Reported as the open's error when the open is still waiting;
            // then the relay never reads the frames and there is nothing to
            // forward. After a heartbeat-only opening the open has already
            // handed the Run over (the receiver is gone): the relay owns the
            // frames and must see this one.
            if first.send(verdict).is_ok() && refused {
                return Some(Stop::Done);
            }
        }
        let done = self.decoder.done();
        if self
            .frames_tx
            .send(Ok(WireFrame::Connect(frame)))
            .await
            .is_err()
        {
            return Some(Stop::RelayGone);
        }
        done.then_some(Stop::Done)
    }

    /// End the Run with a synthesized end frame: observed here (so the report
    /// reflects it) and forwarded to the relay.
    async fn end_with(&mut self, frame: Frame) -> Stop {
        if self.decoder.done() {
            return Stop::Done;
        }
        let _ = self.decoder.observe(&frame);
        if let Some(first) = self.first_tx.take() {
            let verdict = match self.decoder.failure() {
                Some(failure) => Err(failure.clone()),
                None => Ok(()),
            };
            let refused = verdict.is_err();
            // As in `observe`: only an open still waiting takes the verdict
            // in place of the frame.
            if first.send(verdict).is_ok() && refused {
                return Stop::Done;
            }
        }
        if self
            .frames_tx
            .send(Ok(WireFrame::Connect(frame)))
            .await
            .is_err()
        {
            return Stop::RelayGone;
        }
        Stop::Done
    }
}

/// Cursor's words with any JWT-shaped run (an echoed bearer) replaced by
/// `[token]`, so the log never carries a credential.
fn without_tokens(message: &str) -> String {
    use std::sync::LazyLock;
    static JWT: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
            .expect("jwt pattern")
    });
    JWT.replace_all(message, "[token]").into_owned()
}

/// The clean end frame.
fn clean_end() -> Frame {
    Frame::end(Bytes::from_static(b"{}"))
}

/// An error end frame in Connect's shape, carrying the failure's code word
/// and message.
fn error_end(failure: &Failure) -> Frame {
    let code = match failure.status {
        400 => "invalid_argument",
        401 => "unauthenticated",
        403 => "permission_denied",
        429 => "resource_exhausted",
        503 => "unavailable",
        _ => "unknown",
    };
    let json = serde_json::json!({"error": {"code": code, "message": failure.message}});
    Frame::end(Bytes::from(json.to_string()))
}

/// The uplink: one task per Run, appending messages in order.
struct Appender {
    transport: Transport,
    url: String,
    headers: Vec<(&'static str, String)>,
    request_id: String,
    cancel: CancellationToken,
}

impl Appender {
    async fn run(self, mut inbox: mpsc::Receiver<Outbound>, fail_tx: oneshot::Sender<Failure>) {
        let this = Arc::new(self);
        let mut in_flight: JoinSet<Result<(), Failure>> = JoinSet::new();
        let mut seqno = 0u64;
        let failure = loop {
            tokio::select! {
                biased;
                () = this.cancel.cancelled() => break None,
                Some(settled) = in_flight.join_next(), if !in_flight.is_empty() => {
                    match settled {
                        Ok(Ok(())) => {}
                        Ok(Err(failure)) => break Some(failure),
                        Err(_) => break Some(response::map_failure(200, "unavailable", "BidiAppend task failed")),
                    }
                }
                message = inbox.recv() => {
                    let Some(message) = message else { break None };
                    if !message.overlaps {
                        // Alone: after every append before it is answered, and
                        // answered itself before the next one goes.
                        if let Some(failure) = drain(&mut in_flight).await {
                            break Some(failure);
                        }
                        let result = Arc::clone(&this).append(message.bytes, seqno).await;
                        seqno += 1;
                        if let Err(failure) = result {
                            break Some(failure);
                        }
                        continue;
                    }
                    if in_flight.len() >= MAX_IN_FLIGHT
                        && let Some(Ok(Err(failure))) = in_flight.join_next().await
                    {
                        break Some(failure);
                    }
                    in_flight.spawn(Arc::clone(&this).append(message.bytes, seqno));
                    seqno += 1;
                }
            }
        };
        in_flight.abort_all();
        if let Some(failure) = failure
            && !this.cancel.is_cancelled()
        {
            let _ = fail_tx.send(failure);
        }
    }

    /// One `BidiAppend`: `{2 request_id{1}, 3 seqno, 4 data}`.
    async fn append(self: Arc<Self>, data: Bytes, seqno: u64) -> Result<(), Failure> {
        let mut request_id = Writer::new();
        request_id.string(msg::BIDI_REQUEST_ID_VALUE, &self.request_id);
        let mut body = Writer::new();
        body.message(msg::BIDI_REQUEST_ID, request_id);
        body.varint(msg::BIDI_SEQNO, seqno);
        body.bytes(msg::BIDI_DATA, &data);
        let body = body.into_bytes();
        let wait = APPEND_WAIT + Duration::from_secs(body.len().div_ceil(65_536) as u64);
        let deadline = Instant::now() + wait;
        let prepared = Prepared {
            protocol: ProtocolId::Cursor,
            url: self.url.clone(),
            content_type: cursor_request::PROTO,
            body,
            stream: false,
            headers: Vec::new(),
            cursor: None,
        };
        let sent = tokio::select! {
            () = self.cancel.cancelled() => return Ok(()),
            sent = self.transport.send_with_headers(&prepared, &self.headers, &[], deadline) => sent,
        };
        let response = match sent {
            Ok(response) => response,
            Err(TransportError::Timeout) => {
                return Err(response::map_failure(
                    200,
                    "deadline_exceeded",
                    &format!("BidiAppend got no answer in {}s", wait.as_secs()),
                ));
            }
            Err(error) => {
                return Err(response::map_failure(
                    200,
                    "unavailable",
                    &format!("BidiAppend: {error}"),
                ));
            }
        };
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            // Drain the (empty) answer so the connection returns to the pool.
            let _ = self
                .transport
                .read_body(response, transport::MAX_ERROR_BODY, deadline)
                .await;
            return Ok(());
        }
        let body = self
            .transport
            .read_body(response, transport::MAX_ERROR_BODY, deadline)
            .await
            .unwrap_or_default();
        Err(append_failure(status, &body))
    }
}

/// Wait for every in-flight append; the first failure wins.
async fn drain(in_flight: &mut JoinSet<Result<(), Failure>>) -> Option<Failure> {
    let mut failure: Option<Failure> = None;
    while let Some(settled) = in_flight.join_next().await {
        let verdict = match settled {
            Ok(Ok(())) => continue,
            Ok(Err(error)) => error,
            Err(_) => response::map_failure(200, "unavailable", "BidiAppend task failed"),
        };
        failure.get_or_insert(verdict);
    }
    failure
}

/// A failed append's verdict: Cursor's own Connect error when the body is
/// one, else the status mapped to Connect's code with the body as the words.
fn append_failure(status: u16, body: &[u8]) -> Failure {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if let Ok(parsed) = serde_json::from_str::<Value>(text)
        && let Some(code) = parsed.get("code").and_then(Value::as_str)
    {
        let message = parsed.get("message").and_then(Value::as_str).unwrap_or("");
        return response::map_failure(status, code, message);
    }
    let code = match status {
        400 => "invalid_argument",
        401 => "unauthenticated",
        403 => "permission_denied",
        429 => "resource_exhausted",
        _ => "unavailable",
    };
    let message = if text.is_empty() {
        format!("HTTP {status}")
    } else {
        text.to_owned()
    };
    response::map_failure(status, code, &message)
}
