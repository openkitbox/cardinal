//! Candidate expansion: a candidate is ONE ROUTE ENTRY — one account (key row)
//! plus its provider and the single upstream model it serves. Failure cooldown
//! policy lives in `failover`.
//!
//! Ordering contracts:
//! - the direct path (`provider/model`) expands to the provider's active keys
//!   in their single global (position, id) order — the store's ORDER BY
//!   contract — all serving the same model. That is the EXPANSION order only:
//!   `relay::order_ready` ranks it by quota, because direct resolution is
//!   deliberately Smart (see [`expand_direct`]);
//! - a route expands to one candidate per entry, in the entries' STORED order
//!   (the order the user arranged in the GUI); `relay::order_ready` then
//!   applies the route's strategy to that whole list — Ordered keeps it,
//!   Rotate moves the cursor over it, Smart ranks it by quota;
//! - a failure cools at its own granularity (whole key, or one (key, model)
//!   pair for an unserved model — see `failover`); resting candidates are
//!   deferred behind ready ones (restLast) instead of being skipped, so a
//!   lone resting key is still tried.

use std::collections::HashMap;

use secrecy::SecretString;

use super::trace::SkipReason;
use crate::store::{ProviderKeyRow, ProviderRow, RouteEntry};
use crate::translation::ir::Effort;

/// One triable candidate: the route entry's account (key row), the provider it
/// belongs to, and the upstream model to request.
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
    /// absent from it, or nothing listed).
    pub supported_efforts: Option<Box<[Effort]>>,
    /// The vendor-declared default level for this model, canonical; `None`
    /// when the snapshot does not name one.
    pub default_effort: Option<Effort>,
    /// The context window the vendor advertises for THIS candidate's upstream
    /// model, from the key's cached model-list snapshot (`ProbeModel::context`,
    /// i.e. the model's input window). `None` when the snapshot has no such
    /// entry, which the Kiro decoder reads as "no input estimate" — never zero.
    pub context_window: Option<u64>,
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

/// A snapshot entry is selected by its exact configured id first. An alias, a
/// provider prefix, or a thinking suffix falls back to the canonical id only
/// for a recognized GPT variant (the same mapping the KAS body uses); any other
/// writing stays without metadata, so derived accounting fails closed.
fn snapshot_entry<'a>(
    key: &'a ProviderKeyRow,
    model: &str,
) -> Option<&'a crate::probe::ProbeModel> {
    let models = key.models.as_ref()?;
    if let Some(entry) = models.iter().find(|entry| entry.id == model) {
        return Some(entry);
    }
    let lower = model.trim().to_ascii_lowercase();
    if !lower.contains("gpt") {
        return None;
    }
    let canonical = crate::kiro::gpt_model(&lower)?;
    models
        .iter()
        .find(|entry| entry.id.eq_ignore_ascii_case(canonical))
}

/// The candidate model's effort dial from the key's cached model-list
/// snapshot: canonical levels (ascending) plus the vendor-declared default.
/// A missing snapshot/model or an empty level list yields `(None, default)`,
/// meaning dispatch does not clamp (the default may still repair unknown
/// names).
fn effort_support(key: &ProviderKeyRow, model: &str) -> (Option<Box<[Effort]>>, Option<Effort>) {
    let Some(entry) = snapshot_entry(key, model) else {
        return (None, None);
    };
    let mut levels: Vec<Effort> = entry
        .effort_levels
        .iter()
        .filter_map(|name| Effort::parse_name(name))
        .filter(|level| !matches!(level, Effort::None))
        .collect();
    levels.sort_by_key(|level| level.rank().unwrap_or(u8::MAX));
    levels.dedup();
    let default = entry
        .default_effort
        .as_deref()
        .and_then(Effort::parse_name)
        .filter(|level| !matches!(level, Effort::None));
    if levels.is_empty() {
        return (None, default);
    }
    (Some(levels.into_boxed_slice()), default)
}

/// The candidate model's declared context window from the key's cached
/// model-list snapshot. A missing snapshot or entry yields `None`.
fn model_context(key: &ProviderKeyRow, model: &str) -> Option<u64> {
    snapshot_entry(key, model).and_then(|entry| entry.context)
}

/// Direct path ("<provider>/<model>"): the provider's active keys — which must arrive in global
/// (position, id) order (the store's ORDER BY contract), each paired with its resolved secret —
/// all serving the same upstream model. This is the expansion order; quota ranking happens in
/// `relay::order_ready`.
///
/// Direct resolution is deliberately `RouteStrategy::Smart` even though entries are per account
/// again: these keys are interchangeable routes to ONE model, so ranking them by quota surplus is
/// what keeps a multi-account provider from always using the first account. Their stored
/// (position, id) order only breaks quota ties. Returns the candidates plus the excluded ones
/// with their reasons.
pub fn expand_direct(
    provider: ProviderRow,
    keys: Vec<(ProviderKeyRow, SecretString)>,
    upstream_model: &str,
) -> (Vec<Candidate>, Vec<(Candidate, SkipReason)>) {
    let mut candidates = Vec::with_capacity(keys.len());
    let mut excluded = Vec::new();
    for (key, secret) in keys {
        // `fetch_key_secrets` hands inactive rows through on purpose, so a
        // disabled or archived account is excluded here with a reason instead
        // of silently disappearing from the provider's key list.
        let skip = if !key.active() {
            Some(SkipReason::Disabled)
        } else if !serves_model(&key, upstream_model) {
            Some(SkipReason::ModelNotAllowed)
        } else {
            None
        };
        let (supported, default) = effort_support(&key, upstream_model);
        let context_window = model_context(&key, upstream_model);
        let candidate = Candidate {
            provider: provider.clone(),
            key,
            secret,
            upstream_model: upstream_model.to_owned(),
            route_alias: None,
            entry_cap: None,
            supported_efforts: supported,
            default_effort: default,
            context_window,
        };
        match skip {
            Some(reason) => excluded.push((candidate, reason)),
            None => candidates.push(candidate),
        }
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

/// Route path: ONE CANDIDATE PER ENTRY — the same account may appear several
/// times with different models, and one entry never expands to another
/// account. Candidates keep the entries' STORED order (the order the user
/// arranged in the GUI); key position never reorders a route. A dangling entry
/// (its account is gone from `keys`) is skipped silently. An inactive account
/// or a disabled provider excludes the entry as `Disabled`, a whitelist that
/// lacks the entry's model as `ModelNotAllowed`, and an entry whose
/// availability rules deny `now` as `WindowSkipped`.
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
            continue; // dangling entry: its account is gone
        };
        let Some(provider) = providers.get(&key.provider_id) else {
            continue; // dangling provider
        };
        // `fetch_key_secrets` hands inactive rows through on purpose, so a
        // route entry naming a disabled or archived account is reported here
        // instead of vanishing as a dangling entry.
        let skip = if !provider.enabled || !key.active() {
            Some(SkipReason::Disabled)
        } else if !serves_model(key, &entry.model) {
            Some(SkipReason::ModelNotAllowed)
        } else if !entry.is_available(now) {
            // One candidate per entry, so one denied entry is one skip.
            window_skipped += 1;
            Some(SkipReason::WindowSkipped)
        } else {
            None
        };
        let candidate = make_candidate(key, secret, provider, entry);
        match skip {
            Some(reason) => excluded.push((candidate, reason)),
            None => candidates.push(candidate),
        }
    }
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
    entry: &RouteEntry,
) -> Candidate {
    let model = entry.model.as_str();
    let (supported, default) = effort_support(key, model);
    Candidate {
        key: key.clone(),
        // A key serving several entries clones its row and secret per
        // candidate (each secret clone is its own zeroizing allocation; route
        // entries are few, and this runs once per request at resolve time).
        secret: secret.clone(),
        provider: provider.clone(),
        upstream_model: model.to_owned(),
        route_alias: None, // set by the resolver, which owns the alias
        // The store's ensure rejects caps beyond i32::MAX; the try_from is a
        // belt-and-suspenders for rows written before that check existed.
        entry_cap: entry
            .max_concurrency
            .and_then(|cap| i32::try_from(cap).ok()),
        supported_efforts: supported,
        default_effort: default,
        context_window: model_context(key, model),
    }
}
