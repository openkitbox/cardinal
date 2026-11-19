//! Sliding-window budgets for portal requests, normalized identities, and mail.
//! Only digests are retained; no client-supplied source IP is trusted.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const GLOBAL: usize = 120;
const MAIL: usize = 30;
const MAX_IDENTITIES: usize = 2 * GLOBAL;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum Operation {
    Register,
    Forgot,
    Login,
    KeyLogin,
    Complete,
    Reset,
}

#[derive(Default)]
pub(crate) struct AuthLimits {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    requests: VecDeque<Instant>,
    mail: VecDeque<Instant>,
    identities: HashMap<(Operation, [u8; 32]), VecDeque<Instant>>,
}

impl AuthLimits {
    pub(crate) fn request(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|mut state| take(&mut state.requests, Instant::now(), GLOBAL))
    }

    pub(crate) fn identity(&self, op: Operation, digest: [u8; 32]) -> bool {
        self.state
            .lock()
            .is_ok_and(|mut state| state.identity(op, digest, Instant::now()))
    }

    pub(crate) fn mail(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|mut state| take(&mut state.mail, Instant::now(), MAIL))
    }
}

impl State {
    fn identity(&mut self, op: Operation, digest: [u8; 32], now: Instant) -> bool {
        let key = (op, digest);
        if !self.identities.contains_key(&key) && self.identities.len() == MAX_IDENTITIES {
            // Expire stale identities before admitting new ones. Never evict a
            // live bucket: doing so would let a flood reset an existing limit.
            self.identities.retain(|_, hits| {
                hits.back()
                    .is_some_and(|hit| now.duration_since(*hit) < WINDOW)
            });
            if self.identities.len() == MAX_IDENTITIES {
                return false;
            }
        }
        let limit = match op {
            Operation::Register | Operation::Forgot => 2,
            Operation::Login | Operation::KeyLogin | Operation::Complete | Operation::Reset => 5,
        };
        take(self.identities.entry(key).or_default(), now, limit)
    }
}

fn take(hits: &mut VecDeque<Instant>, now: Instant, limit: usize) -> bool {
    while hits
        .front()
        .is_some_and(|hit| now.duration_since(*hit) >= WINDOW)
    {
        hits.pop_front();
    }
    if hits.len() >= limit {
        return false;
    }
    hits.push_back(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_auth_windows_expire_and_keep_identity_operations_separate() {
        let mut state = State::default();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(state.identity(Operation::Login, [0; 32], now));
        }
        assert!(!state.identity(Operation::Login, [0; 32], now));
        assert!(state.identity(Operation::Forgot, [0; 32], now));
        assert!(state.identity(Operation::Login, [1; 32], now));
        assert!(state.identity(Operation::Login, [0; 32], now + WINDOW));
    }

    #[test]
    fn account_auth_identity_budget_never_evicts_live_buckets() {
        let mut state = State::default();
        let now = Instant::now();
        for number in 0..MAX_IDENTITIES {
            let digest = crate::account_auth::digest(&number.to_string());
            assert!(state.identity(Operation::Login, digest, now));
        }
        assert!(!state.identity(Operation::Login, [0; 32], now));
        assert!(state.identity(Operation::Login, [0; 32], now + WINDOW));
        assert_eq!(state.identities.len(), 1);
    }
}
