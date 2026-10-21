//! Candidate expansion: a candidate is one key row (plus its provider and the
//! upstream model it should serve); failure cooldown policy lives in `failover`.
//!
//! Ordering contracts, flattened onto keys:
//! - the direct path (`provider/model`) tries the provider's enabled keys in
//!   their single global (position, id) order — the store's ORDER BY contract;
//! - a route tries its entries in STORED order (the user arranges them in the
//!   GUI); key position never reorders a route;
//! - a failure cools at its own granularity (whole key, or one (key, model)
//!   pair for an unserved model — see `failover`); resting candidates are
//!   deferred behind ready ones (restLast) instead of being skipped, so a
//!   lone resting key is still tried.

use std::collections::HashMap;

use secrecy::SecretString;

use super::trace::SkipReason;
use crate::store::{ProviderKeyRow, ProviderRow, RouteEntry};
use crate::translation::ir::Effort;

/// One triable candidate: a key, the provider it belongs to, and the upstream model to request.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub key: ProviderKeyRow,
    /// The key's secret, resolved from the secret store in one batch at resolve
    /// time (SecretString: zeroize-on-drop, redacted Debug — never log it).
    pub secret: SecretString,
    pub provider: ProviderRow,
    pub upstream_model: String,
    /// Route alias this candidate came from (None on the direct path).
    pub route_alias: Option<String>,
    /// Per-item concurrency cap of the route entry (None = only the key-level
    /// cap applies).
    pub entry_cap: Option<i32>,
    /// Effort levels the candidate's snapshot says its upstream model accepts,
    /// canonical and ascending. `None` = unconstrained (no snapshot, model
    /// absent from it, or nothing listed): dispatch passes effort through.
    pub supported_efforts: Option<Box<[Effort]>>,
}

impl Candidate {
    /// The key half of the candidate's (key, model) rest identity — a
    /// model-scoped rest only defers entries serving that model.
    pub fn rest_key(&self) -> i64 {
        self.key.id
    }

    /// Credential injection material (expose only at the injection point).
    pub fn credential(&self) -> &SecretString {
        &self.secret
    }
}

/// The key's model whitelist: None or an empty list = unrestricted; a
/// non-empty list must contain `upstream_model` (exact string match, no
/// globbing) for the key to be a candidate for it.
fn serves_model(key: &ProviderKeyRow, upstream_model: &str) -> bool {
    key.allowed_models.as_ref().is_none_or(|allowed| {
        allowed.is_empty() || allowed.iter().any(|model| model == upstream_model)
    })
}

/// The candidate model's supported effort levels from the key's cached
/// model-list snapshot, canonicalized and ascending. `None` when the snapshot
/// cannot answer — dispatch then leaves the client's dial untouched.
fn supported_efforts(key: &ProviderKeyRow, model: &str) -> Option<Box<[Effort]>> {
    let entry = key.models.as_ref()?.iter().find(|entry| entry.id == model)?;
    let mut levels: Vec<Effort> = entry
        .effort_levels
        .iter()
        .filter_map(|name| Effort::parse_name(name))
        .filter(|level| !matches!(level, Effort::None))
        .collect();
    levels.sort_by_key(|level| level.rank().unwrap_or(u8::MAX));
    levels.dedup();
    if levels.is_empty() {
        return None;
    }
    Some(levels.into_boxed_slice())
}

/// Direct path ("<provider>/<model>"): the provider's enabled keys — which must arrive in global
/// (position, id) order (the store's ORDER BY contract), each paired with its resolved secret —
/// all serving the same upstream model. Returns the candidates plus the excluded ones with their reasons.
pub fn expand_direct(
    provider: ProviderRow,
    keys: Vec<(ProviderKeyRow, SecretString)>,
    upstream_model: &str,
) -> (Vec<Candidate>, Vec<(Candidate, SkipReason)>) {
    let mut candidates = Vec::new();
    let mut excluded = Vec::new();
    for (key, secret) in keys {
        let supported = supported_efforts(&key, upstream_model);
        if !key.enabled {
            excluded.push((
                Candidate {
                    provider: provider.clone(),
                    key: key.clone(),
                    secret: secret.clone(),
                    upstream_model: upstream_model.to_owned(),
                    route_alias: None,
                    entry_cap: None,
                    supported_efforts: supported.clone(),
                },
                SkipReason::Disabled,
            ));
            continue;
        }
        if !serves_model(&key, upstream_model) {
            excluded.push((
                Candidate {
                    provider: provider.clone(),
                    key: key.clone(),
                    secret: secret.clone(),
                    upstream_model: upstream_model.to_owned(),
                    route_alias: None,
                    entry_cap: None,
                    supported_efforts: supported.clone(),
                },
                SkipReason::ModelNotAllowed,
            ));
            continue;
        }
        candidates.push(Candidate {
            provider: provider.clone(),
            key,
            secret,
            upstream_model: upstream_model.to_owned(),
            route_alias: None,
            entry_cap: None,
            supported_efforts: supported,
        });
    }
    (candidates, excluded)
}

/// Route expansion result: the candidates plus how many entries were skipped
/// purely because their availability rules deny the dispatch time (so an
/// empty result can tell "no route" apart from "nothing active right now").
pub struct Expansion {
    pub candidates: Vec<Candidate>,
    pub window_skipped: usize,
    /// Candidates excluded during expansion, with the reason.
    pub excluded: Vec<(Candidate, SkipReason)>,
}

/// Route path: ONE CANDIDATE PER ENTRY — the same key may appear several times
/// with different models. Order is the entries' STORED order (the order the
/// user arranged in the GUI). Disabled keys, keys of disabled providers,
/// dangling entries, and entries whose availability rules deny `now` are
/// skipped.
pub fn expand_route(
    entries: &[RouteEntry],
    keys: Vec<(ProviderKeyRow, SecretString)>,
    providers: &HashMap<i64, ProviderRow>,
    now: chrono::DateTime<chrono::Local>,
) -> Expansion {
    let keys_by_id: HashMap<i64, (ProviderKeyRow, SecretString)> = keys
        .into_iter()
        .map(|(key, secret)| (key.id, (key, secret)))
        .collect();
    let mut window_skipped = 0;
    let mut candidates = Vec::with_capacity(entries.len());
    let mut excluded = Vec::new();
    for entry in entries {
        let Some((key, secret)) = keys_by_id.get(&entry.key_id) else {
            continue;
        }; // dangling key
        let Some(provider) = providers.get(&key.provider_id) else {
            continue;
        }; // dangling provider
        if !key.enabled {
            excluded.push((
                make_candidate(key, secret, provider, &entry.model, entry),
                SkipReason::Disabled,
            ));
            continue;
        }
        if !serves_model(key, &entry.model) {
            excluded.push((
                make_candidate(key, secret, provider, &entry.model, entry),
                SkipReason::ModelNotAllowed,
            ));
            continue;
        }
        if !provider.enabled {
            excluded.push((
                make_candidate(key, secret, provider, &entry.model, entry),
                SkipReason::Disabled,
            ));
            continue;
        }
        if !entry.is_available(now) {
            window_skipped += 1;
            excluded.push((
                make_candidate(key, secret, provider, &entry.model, entry),
                SkipReason::WindowSkipped,
            ));
            continue;
        }
        candidates.push(make_candidate(key, secret, provider, &entry.model, entry));
    }
    // Stored order = dispatch order: the entries arrive in the order the user
    // arranged them; no re-sorting by key position.
    Expansion {
        candidates,
        window_skipped,
        excluded,
    }
}

/// Build a Candidate for either the candidates or excluded list.
fn make_candidate(
    key: &ProviderKeyRow,
    secret: &SecretString,
    provider: &ProviderRow,
    model: &str,
    entry: &RouteEntry,
) -> Candidate {
    Candidate {
        key: key.clone(),
        // A key serving several entries clones its secret per candidate (each
        // clone is its own zeroizing allocation; route entries are few).
        secret: secret.clone(),
        provider: provider.clone(),
        upstream_model: model.to_owned(),
        route_alias: None, // set by the resolver, which owns the alias
        // The store's ensure rejects caps beyond i32::MAX; the try_from is a
        // belt-and-suspenders for rows written before that check existed.
        entry_cap: entry
            .max_concurrency
            .and_then(|cap| i32::try_from(cap).ok()),
        supported_efforts: supported_efforts(key, model),
    }
}

