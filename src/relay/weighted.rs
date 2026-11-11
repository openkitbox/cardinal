//! Smooth weighted selection for one route configuration. Cache publication
//! retires old states under their lock before exposing a replacement snapshot.
use std::sync::{Arc, Mutex};

use super::candidates::Candidate;

pub(super) type Snapshot = (Arc<WeightedState>, u64);

#[derive(Default)]
pub(super) struct WeightedState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    retired: bool,
    generation: u64,
    scores: Vec<Score>,
}

struct Score {
    key_id: i64,
    model: String,
    current: i64,
}

impl WeightedState {
    pub(super) fn advance(&self, generation: u64) {
        match self.inner.lock() {
            Ok(mut state) => state.generation = generation,
            Err(_) => tracing::warn!("weighted state lock poisoned while advancing generation"),
        }
    }

    pub(super) fn retire(&self) {
        match self.inner.lock() {
            Ok(mut state) => state.retired = true,
            Err(_) => tracing::warn!("weighted state lock poisoned while retiring route"),
        }
    }

    pub(super) fn order(&self, generation: u64, mut ready: Vec<Candidate>) -> Vec<Candidate> {
        let Ok(mut state) = self.inner.lock() else {
            tracing::warn!("weighted state lock poisoned; retaining route order");
            return ready;
        };
        if state.retired || state.generation != generation {
            return ready;
        }
        if let Some(index) = select(&mut state.scores, &ready) {
            let selected = ready.remove(index);
            ready.insert(0, selected);
        }
        ready
    }
}

/// Update only the supplied scores and return the stable-order SWRR winner.
fn select(scores: &mut Vec<Score>, ready: &[Candidate]) -> Option<usize> {
    scores.retain(|score| {
        ready.iter().any(|candidate| {
            candidate.key.id == score.key_id && candidate.upstream_model == score.model
        })
    });
    let mut winner = None;
    let mut highest = i64::MIN;
    let mut total = 0_i64;
    for (index, candidate) in ready.iter().enumerate() {
        let score_index = match scores.iter().position(|score| {
            score.key_id == candidate.key.id && score.model == candidate.upstream_model
        }) {
            Some(index) => index,
            None => {
                scores.push(Score {
                    key_id: candidate.key.id,
                    model: candidate.upstream_model.clone(),
                    current: 0,
                });
                scores.len() - 1
            }
        };
        let weight = i64::from(candidate.weight);
        total += weight;
        let score = &mut scores[score_index];
        score.current += weight;
        if score.current > highest {
            highest = score.current;
            winner = Some((index, score_index));
        }
    }
    let (index, score_index) = winner?;
    scores[score_index].current -= total;
    Some(index)
}
