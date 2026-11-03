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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::store::{ActiveWindow, AvailabilityRule, RuleEffect};

    fn provider(id: i64, enabled: bool) -> ProviderRow {
        ProviderRow {
            id,
            name: format!("p{id}"),
            protocol: "openai_chat".to_owned(),
            base_url: "http://upstream".to_owned(),
            auth_scheme: "bearer".to_owned(),
            enabled,
        }
    }

    fn key(id: i64, provider_id: i64, allowed: Option<&[&str]>) -> (ProviderKeyRow, SecretString) {
        (
            ProviderKeyRow {
                id,
                provider_id,
                label: format!("k{id}"),
                api_key: Some("secret".to_owned()),
                enabled: true,
                position: 0,
                max_concurrency: None,
                models: None,
                allowed_models: allowed
                    .map(|models| models.iter().map(|model| (*model).to_owned()).collect()),
                auth_kind: "static".to_owned(),
                oauth: None,
                archived_at: None,
            },
            SecretString::from("secret".to_owned()),
        )
    }

    fn entry(key_id: i64, model: &str) -> RouteEntry {
        RouteEntry {
            key_id,
            model: model.to_owned(),
            label: None,
            max_concurrency: None,
            rules: Vec::new(),
            active_window: None,
        }
    }

    fn providers(rows: &[ProviderRow]) -> HashMap<i64, ProviderRow> {
        rows.iter().map(|row| (row.id, row.clone())).collect()
    }

    fn now() -> chrono::DateTime<chrono::Local> {
        chrono::Local
            .with_ymd_and_hms(2026, 11, 1, 12, 0, 0)
            .single()
            .expect("noon on a weekday is an unambiguous local time")
    }

    fn ids(candidates: &[Candidate]) -> Vec<i64> {
        candidates
            .iter()
            .map(|candidate| candidate.key.id)
            .collect()
    }

    fn served(candidates: &[Candidate]) -> Vec<(i64, &str)> {
        candidates
            .iter()
            .map(|candidate| (candidate.key.id, candidate.upstream_model.as_str()))
            .collect()
    }

    #[test]
    fn expand_route_yields_one_candidate_per_entry() {
        // Three accounts of one provider, two entries: an entry only ever
        // yields itself, never the provider's other accounts.
        let entries = vec![entry(1, "m"), entry(2, "n")];
        let keys = vec![key(1, 1, None), key(2, 1, None), key(3, 1, None)];
        let expansion = expand_route(&entries, keys, &providers(&[provider(1, true)]), now());
        assert_eq!(
            served(&expansion.candidates),
            vec![(1, "m"), (2, "n")],
            "one candidate per entry, each carrying its own model"
        );
        assert!(expansion.excluded.is_empty(), "nothing to exclude");
        assert_eq!(expansion.window_skipped, 0, "no availability window");
    }

    #[test]
    fn expand_route_excludes_an_entry_whose_key_whitelist_lacks_the_model() {
        let entries = vec![entry(1, "m")];
        let keys = vec![key(1, 1, Some(&["other"])), key(2, 1, Some(&["m"]))];
        let expansion = expand_route(&entries, keys, &providers(&[provider(1, true)]), now());
        assert!(
            expansion.candidates.is_empty(),
            "the whitelisted-out entry serves nothing"
        );
        assert_eq!(expansion.excluded.len(), 1, "one entry is excluded");
        let (excluded, reason) = &expansion.excluded[0];
        assert_eq!(excluded.key.id, 1, "the whitelisted-out account");
        assert!(
            matches!(reason, SkipReason::ModelNotAllowed),
            "reason: {reason:?}"
        );
    }

    #[test]
    fn expand_route_marks_an_entry_of_a_disabled_provider_disabled() {
        let entries = vec![entry(1, "m"), entry(3, "n")];
        let keys = vec![key(1, 1, None), key(3, 2, None)];
        let expansion = expand_route(
            &entries,
            keys,
            &providers(&[provider(1, false), provider(2, true)]),
            now(),
        );
        assert_eq!(
            served(&expansion.candidates),
            vec![(3, "n")],
            "only the enabled provider's entry serves"
        );
        assert_eq!(expansion.excluded.len(), 1, "one entry is excluded");
        let (excluded, reason) = &expansion.excluded[0];
        assert_eq!(excluded.key.id, 1, "the disabled provider's account");
        assert!(matches!(reason, SkipReason::Disabled), "reason: {reason:?}");
    }

    #[test]
    fn expand_route_counts_a_denied_window_once_per_entry() {
        // A deny-all rule: 00:00–00:00 covers the whole day.
        let deny = AvailabilityRule {
            window: ActiveWindow {
                start: "00:00".to_owned(),
                end: "00:00".to_owned(),
                days: None,
            },
            effect: RuleEffect::Deny,
        };
        let mut denied = entry(1, "m");
        denied.rules = vec![deny];
        let entries = vec![denied, entry(3, "n")];
        let keys = vec![key(1, 1, None), key(3, 2, None)];
        let expansion = expand_route(
            &entries,
            keys,
            &providers(&[provider(1, true), provider(2, true)]),
            now(),
        );
        assert_eq!(
            served(&expansion.candidates),
            vec![(3, "n")],
            "the denied entry serves nothing"
        );
        assert_eq!(expansion.window_skipped, 1, "one denied entry is one skip");
        assert_eq!(expansion.excluded.len(), 1, "the denied entry is reported");
        let (_, reason) = &expansion.excluded[0];
        assert!(
            matches!(reason, SkipReason::WindowSkipped),
            "reason: {reason:?}"
        );
    }

    #[test]
    fn expand_route_skips_a_dangling_entry_silently() {
        let entries = vec![entry(9, "m"), entry(1, "n")];
        let keys = vec![key(1, 1, None), key(2, 9, None)];
        let expansion = expand_route(&entries, keys, &providers(&[provider(1, true)]), now());
        assert_eq!(
            served(&expansion.candidates),
            vec![(1, "n")],
            "an entry whose account is gone is skipped"
        );
        assert!(
            expansion.excluded.is_empty(),
            "a dangling entry has no candidate to report"
        );
        assert_eq!(
            expansion.window_skipped, 0,
            "a dangling entry is not a window skip"
        );
    }

    #[test]
    fn expand_direct_expands_the_providers_active_keys() {
        let keys = vec![key(1, 1, None), key(2, 1, Some(&["m"]))];
        let (candidates, excluded) = expand_direct(provider(1, true), keys, "m");
        assert_eq!(
            ids(&candidates),
            vec![1, 2],
            "every key of the provider serves the direct model"
        );
        assert!(excluded.is_empty(), "both keys serve the model");
    }

    #[test]
    fn expand_route_keeps_two_models_of_one_account_as_two_candidates() {
        // One account listed twice, once per model: two independent candidates
        // in stored order.
        let entries = vec![entry(1, "m"), entry(2, "x"), entry(1, "n")];
        let keys = vec![key(1, 1, None), key(2, 1, None)];
        let expansion = expand_route(&entries, keys, &providers(&[provider(1, true)]), now());
        assert_eq!(
            served(&expansion.candidates),
            vec![(1, "m"), (2, "x"), (1, "n")],
            "one candidate per entry, in stored order"
        );
    }

    #[test]
    fn expand_direct_excludes_a_key_whose_whitelist_lacks_the_model() {
        let keys = vec![key(1, 1, Some(&["other"])), key(2, 1, None)];
        let (candidates, excluded) = expand_direct(provider(1, true), keys, "m");
        assert_eq!(
            ids(&candidates),
            vec![2],
            "only the unrestricted key serves"
        );
        assert_eq!(excluded.len(), 1, "one key is excluded");
        let (excluded, reason) = &excluded[0];
        assert_eq!(excluded.key.id, 1, "the whitelisted-out key");
        assert!(
            matches!(reason, SkipReason::ModelNotAllowed),
            "reason: {reason:?}"
        );
    }
}
