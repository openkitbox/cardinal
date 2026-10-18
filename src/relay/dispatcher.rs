//! Centralized dispatcher: a single tokio task that atomically assigns
//! incoming requests to candidates. Replaces the per-request distributed
//! semaphore queuing with a global view of slot availability.
//!
//! The dispatcher owns all slot state and the pending queue. It knows
//! nothing about HTTP, upstreams, or protocols — only slot counts, FIFO
//! ordering, and the activity sink it announces occupancy to (so the GUI
//! mirrors live concurrency without polling the admin API).

use std::collections::{HashMap, VecDeque};

use tokio::sync::{mpsc, oneshot};

use crate::activity::ActivitySink;

/// Events the dispatcher processes.
pub enum DispatchEvent {
    /// A new request to assign.
    Request(DispatchRequest),
    /// A slot was released (SlotGuard dropped).
    Release { key: SlotKey },
    /// A pending request timed out.
    Timeout { request_id: u64 },
    /// Admin query: current inflight count per key-level slot.
    QueryInflight {
        reply: oneshot::Sender<HashMap<u64, usize>>,
    },
}

/// Namespaced key for the slot-state map. Prevents collision between raw
/// key IDs and hashed entry IDs.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum SlotKey {
    /// Key-level concurrency slot.
    Key(u64),
    /// Route-entry-level concurrency slot.
    Entry(u64),
}

/// A request for the dispatcher to assign a candidate.
pub struct DispatchRequest {
    /// Unique ID for timeout tracking.
    pub id: u64,
    /// Precomputed (key_slot, entry_slot) pairs per candidate, in stored
    /// order. Entry slot is `Some` only when the candidate has an
    /// entry-level cap.
    pub slot_keys: Vec<(SlotKey, Option<SlotKey>)>,
    /// smart-sorted order: indices into the candidate list.
    pub order: Vec<usize>,
    /// Per-candidate concurrency caps (key_cap, entry_cap), pre-computed.
    pub caps: Vec<CandidateCaps>,
    /// Reply channel: Some(Assignment) = assigned, None = timed out.
    pub reply: oneshot::Sender<Option<Assignment>>,
}

/// Concurrency caps for one candidate.
#[derive(Clone, Copy, Debug)]
pub struct CandidateCaps {
    /// Key-level cap (None = unlimited).
    pub key_cap: Option<usize>,
    /// Route-entry-level cap (None = unlimited).
    pub entry_cap: Option<usize>,
    /// Whether this candidate is resting (cooldown). Rested candidates are
    /// deprioritized behind ready ones but still tried when nothing else is
    /// available.
    pub rested: bool,
}

/// The dispatcher's assignment of a candidate to a request.
pub struct Assignment {
    /// Index into `candidates`.
    pub index: usize,
    /// Slot handle: drop releases the slot.
    pub slot: SlotGuard,
    /// The dispatcher's lightweight decision record.
    pub decision: DispatchDecision,
}

/// Lightweight decision record: indices and states only, no candidate metadata.
/// The relay layer enriches this with labels/models to produce a DispatchTrace.
#[derive(Clone, Debug)]
pub struct DispatchDecision {
    /// Index of the selected candidate.
    pub selected: usize,
    /// State of each candidate, indexed by candidate index (not order position):
    /// `candidates[i]` describes the request's `candidates[i]`.
    pub candidates: Vec<CandidateState>,
}

/// State of one candidate during dispatch.
#[derive(Clone, Debug)]
pub enum CandidateState {
    /// Candidate was available and selected.
    Selected,
    /// Candidate was available but not selected (earlier candidate was chosen).
    Ready,
    /// Candidate's concurrency cap was full.
    Full,
    /// Candidate was resting (cooldown).
    Rested,
}

/// RAII slot handle: drop releases the slot back to the dispatcher.
pub struct SlotGuard {
    /// The key-level slot to decrement on drop.
    key_slot_key: SlotKey,
    /// The entry-level slot to decrement on drop (if any).
    entry_slot_key: Option<SlotKey>,
    release_tx: mpsc::UnboundedSender<DispatchEvent>,
}

impl std::fmt::Debug for SlotGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotGuard")
            .field("key_slot_key", &self.key_slot_key)
            .field("entry_slot_key", &self.entry_slot_key)
            .finish()
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // UnboundedSender::send never blocks and never fails silently when the
        // receiver is alive — the only error is a disconnected receiver, which
        // is a shutdown signal and safe to ignore.
        let _ = self.release_tx.send(DispatchEvent::Release {
            key: self.key_slot_key,
        });
        if let Some(entry_key) = self.entry_slot_key {
            let _ = self
                .release_tx
                .send(DispatchEvent::Release { key: entry_key });
        }
    }
}

/// Internal slot state for one candidate.
struct SlotState {
    /// Current number of in-flight requests using this slot.
    inflight: usize,
    /// Maximum allowed (None = unlimited).
    cap: Option<usize>,
}

/// A request that couldn't be assigned immediately.
struct PendingRequest {
    request: DispatchRequest,
}

/// Create a dispatcher channel pair. The sender is shared with the relay
/// for submitting requests; the receiver is consumed by [`run`].
pub fn channel() -> (
    mpsc::UnboundedSender<DispatchEvent>,
    mpsc::UnboundedReceiver<DispatchEvent>,
) {
    mpsc::unbounded_channel()
}

/// The dispatcher's main loop. Spawn this as a single tokio task.
///
/// The `release_tx` sender must feed back into the same event channel that
/// `rx` receives from. In production, clone the sender returned by
/// [`channel`] before passing the receiver here.
pub async fn run(
    mut rx: mpsc::UnboundedReceiver<DispatchEvent>,
    release_tx: mpsc::UnboundedSender<DispatchEvent>,
    sink: ActivitySink,
) {
    let mut slots: HashMap<SlotKey, SlotState> = HashMap::new();
    let mut pending: VecDeque<PendingRequest> = VecDeque::new();

    while let Some(event) = rx.recv().await {
        match event {
            DispatchEvent::Request(mut req) => match try_assign(&mut req, &mut slots) {
                Some((index, decision)) => {
                    let key_slot = req.slot_keys[index].0;
                    let slot = make_slot_guard(&req, index, &release_tx);
                    let _ = req.reply.send(Some(Assignment {
                        index,
                        slot,
                        decision,
                    }));
                    publish_slot(&sink, &slots, key_slot);
                }
                None => {
                    pending.push_back(PendingRequest { request: req });
                }
            },
            DispatchEvent::Release { key } => {
                if let Some(state) = slots.get_mut(&key) {
                    state.inflight = state.inflight.saturating_sub(1);
                }
                publish_slot(&sink, &slots, key);
                // Try to assign pending requests
                drain_pending(&mut pending, &mut slots, &release_tx, &sink);
            }
            DispatchEvent::Timeout { request_id } => {
                if let Some(pos) = pending.iter().position(|p| p.request.id == request_id) {
                    let req = pending.remove(pos).expect("position valid");
                    let _ = req.request.reply.send(None);
                }
            }
            DispatchEvent::QueryInflight { reply } => {
                let counts: HashMap<u64, usize> = slots
                    .iter()
                    .filter_map(|(key, state)| match key {
                        SlotKey::Key(id) if state.inflight > 0 => Some((*id, state.inflight)),
                        _ => None,
                    })
                    .collect();
                let _ = reply.send(counts);
            }
        }
    }
}

/// Construct a SlotGuard for the given assignment.
fn make_slot_guard(
    req: &DispatchRequest,
    index: usize,
    release_tx: &mpsc::UnboundedSender<DispatchEvent>,
) -> SlotGuard {
    let (key_slot_key, entry_slot_key) = req.slot_keys[index];
    SlotGuard {
        key_slot_key,
        entry_slot_key,
        release_tx: release_tx.clone(),
    }
}

/// Try to assign a request to a candidate. Returns (index, decision) on success.
/// The caller (run) constructs the SlotGuard.
///
/// Implements restLast: first tries ready (non-rested) candidates in order;
/// if none are available, falls back to rested candidates in order.
fn try_assign(
    req: &mut DispatchRequest,
    slots: &mut HashMap<SlotKey, SlotState>,
) -> Option<(usize, DispatchDecision)> {
    // Build the full state vector, indexed by candidate index (not order
    // position) so consumers can look up states directly by candidate.
    let mut states = vec![CandidateState::Ready; req.order.len()];

    // Pass 1: try ready candidates in order.
    for &index in &req.order {
        let caps = &req.caps[index];
        if caps.rested {
            states[index] = CandidateState::Rested;
            continue;
        }
        if let Some(result) = try_one(req, index, slots, &mut states) {
            return Some(result);
        }
    }

    // Pass 2: fall back to rested candidates in order.
    for &index in &req.order {
        let caps = &req.caps[index];
        if !caps.rested {
            continue; // already tried in pass 1
        }
        if let Some(result) = try_one(req, index, slots, &mut states) {
            return Some(result);
        }
    }

    // No candidate available.
    None
}

/// Try to assign a single candidate. Returns Some((index, decision))
/// on success, None if the candidate's slots are full.
fn try_one(
    req: &DispatchRequest,
    index: usize,
    slots: &mut HashMap<SlotKey, SlotState>,
    states: &mut [CandidateState],
) -> Option<(usize, DispatchDecision)> {
    let caps = &req.caps[index];
    let (key_slot_key, entry_slot_key) = req.slot_keys[index];

    // Check key-level cap
    let key_state = slots.entry(key_slot_key).or_insert_with(|| SlotState {
        inflight: 0,
        cap: caps.key_cap,
    });

    if let Some(cap) = key_state.cap
        && key_state.inflight >= cap
    {
        states[index] = CandidateState::Full;
        return None;
    }

    // Check entry-level cap (if this candidate is from a route entry)
    if let (Some(entry_cap), Some(entry_key)) = (caps.entry_cap, entry_slot_key) {
        let entry_state = slots.entry(entry_key).or_insert_with(|| SlotState {
            inflight: 0,
            cap: Some(entry_cap),
        });
        if entry_state.inflight >= entry_cap {
            states[index] = CandidateState::Full;
            return None;
        }
    }

    // Both caps available: assign!

    // Increment inflight counts
    let key_state = slots.get_mut(&key_slot_key).expect("key slot exists");
    key_state.inflight += 1;

    if let Some(entry_key) = entry_slot_key {
        let entry_state = slots.get_mut(&entry_key).expect("entry slot exists");
        entry_state.inflight += 1;
    }

    states[index] = CandidateState::Selected;

    let decision = DispatchDecision {
        selected: index,
        candidates: states.to_vec(),
    };

    Some((index, decision))
}

/// Try to assign pending requests after a slot release.
/// Processes in FIFO order; stops at the first request that can't be assigned
/// (preserves FIFO fairness — no skipping ahead).
fn drain_pending(
    pending: &mut VecDeque<PendingRequest>,
    slots: &mut HashMap<SlotKey, SlotState>,
    release_tx: &mpsc::UnboundedSender<DispatchEvent>,
    sink: &ActivitySink,
) {
    while let Some(pending_req) = pending.pop_front() {
        let mut req = pending_req.request;
        // The relay may have already timed out waiting and dropped its receiver;
        // skip silently rather than handing a slot to nobody.
        if req.reply.is_closed() {
            continue;
        }
        match try_assign(&mut req, slots) {
            Some((index, decision)) => {
                let key_slot = req.slot_keys[index].0;
                let slot = make_slot_guard(&req, index, release_tx);
                let _ = req.reply.send(Some(Assignment {
                    index,
                    slot,
                    decision,
                }));
                publish_slot(sink, slots, key_slot);
            }
            None => {
                // Can't assign this one — push it back to the front and stop.
                pending.push_front(PendingRequest { request: req });
                break;
            }
        }
    }
}

/// Announce a key-level slot's occupancy (absolute, after the change) to the
/// live activity feed. Entry-level slots are per-candidate and have no admin
/// surface, so only key slots are published.
fn publish_slot(sink: &ActivitySink, slots: &HashMap<SlotKey, SlotState>, key: SlotKey) {
    if let SlotKey::Key(id) = key
        && let Some(state) = slots.get(&key)
    {
        sink.slot(id as i64, state.inflight);
    }
}
