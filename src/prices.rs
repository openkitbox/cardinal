//! The models.dev price catalog: a background sync keeps
//! `gateway_model_prices` filled for the models this gateway actually serves,
//! without ever touching a price the user seeded — config prices are
//! `source='manual'` and own their rows, catalog prices are
//! `source='catalog'` (the user's word always beats the list price).
//!
//! Freshness: sync at startup when the cached catalog is missing or older
//! than a day, recheck hourly, and when a request's model has no price
//! (`missing`) refetch in the background once the cache and the last attempt
//! are both older than six hours — models.dev may have listed the model by
//! now. Pricing itself stays write-time (the user's call): a fresher catalog
//! only changes what FUTURE requests bill at.
//!
//! The catalog is a process-wide singleton: only the standalone binary
//! starts it, so test processes (which build routers directly) never fetch.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use sqlx::PgPool;

/// Where the list prices come from.
const MODELS_DEV_URL: &str = "https://models.dev/api.json";
/// How old the cached catalog may be before it is fetched again.
const STALE_AFTER: Duration = Duration::from_secs(24 * 3600);
/// How old the cache and the last fetch attempt must both be before a model
/// with no price triggers a background refetch.
const MISSING_AFTER: Duration = Duration::from_secs(6 * 3600);
/// How often the keeper loop looks at the cache's age.
const RECHECK_EVERY: Duration = Duration::from_secs(3600);
/// A failed fetch is retried after this delay, doubling on each further
/// failure up to `RETRY_MAX`.
const RETRY_BASE: Duration = Duration::from_secs(120);
const RETRY_MAX: Duration = Duration::from_secs(3600);
/// The download is capped.
const MAX_BYTES: u64 = 64 << 20;
/// One fetch may not hang the keeper forever.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

static CATALOG: OnceLock<Catalog> = OnceLock::new();

/// The running catalog sync. Started once per process by the standalone
/// binary; `missing` is a no-op before that.
pub struct Catalog {
    pool: PgPool,
    /// The shared in-memory price cache (the Core's own): catalog upserts are
    /// write-through, so the live relay sees catalog prices without a restart.
    price_cache: crate::relay::PriceCache,
    cache_path: PathBuf,
    /// One fetch at a time.
    fetching: AtomicBool,
    state: Mutex<CatalogState>,
}

#[derive(Default)]
struct CatalogState {
    /// When a fetch last started, for the miss-trigger throttle.
    last_attempt: Option<Instant>,
    /// Models already reported missing, with when — one trigger per model per
    /// MISSING_AFTER window.
    missing: HashMap<String, Instant>,
    /// Consecutive failed syncs, reset by any success.
    failures: u32,
}

/// Start the catalog keeper for this process (the standalone binary only).
/// Idempotent; a second call keeps the first keeper. `price_cache` is the
/// Core's shared cache: catalog upserts write through to it so the live
/// relay sees catalog prices immediately.
pub fn start(pool: PgPool, price_cache: crate::relay::PriceCache) {
    if CATALOG.get().is_some() {
        return;
    }
    let Some(home) = dirs::home_dir() else { return };
    let catalog = Catalog {
        pool,
        price_cache,
        cache_path: home.join(".ox").join("models-dev.json"),
        fetching: AtomicBool::new(false),
        state: Mutex::new(CatalogState::default()),
    };
    let catalog = CATALOG.get_or_init(|| catalog);
    tokio::spawn(keep_fresh(catalog));
}

/// A request's model has no price: when the cache and the
/// last fetch attempt are both older than MISSING_AFTER, refetch in the
/// background — models.dev may list the model by now. No-op when no keeper
/// runs (tests, in-process hosts).
pub fn missing(model: &str) {
    let Some(catalog) = CATALOG.get() else { return };
    let should_fetch = {
        let mut state = catalog.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if state
            .last_attempt
            .is_some_and(|t| now.duration_since(t) < MISSING_AFTER)
        {
            return;
        }
        if let Some(age) = cache_age(&catalog.cache_path)
            && age < MISSING_AFTER
        {
            return;
        }
        match state.missing.get(model) {
            Some(t) if now.duration_since(*t) < MISSING_AFTER => false,
            _ => {
                state.missing.insert(model.to_owned(), now);
                true
            }
        }
    };
    if should_fetch {
        tokio::spawn(sync(catalog));
    }
}

/// The keeper loop: sync when stale, retry a failed sync with a bounded
/// backoff, otherwise look again in an hour, forever. Never returns; the
/// process exit ends it.
async fn keep_fresh(catalog: &'static Catalog) {
    loop {
        let retry = if cache_age(&catalog.cache_path).is_none_or(|age| age > STALE_AFTER) {
            sync(catalog).await
        } else {
            None
        };
        tokio::time::sleep(retry.unwrap_or(RECHECK_EVERY)).await;
    }
}

/// Cache file age; None when missing or unreadable (treated as stale).
fn cache_age(path: &PathBuf) -> Option<Duration> {
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(mtime).ok()
}

/// Retry delay after `failures` consecutive sync failures: 2min, 4min, 8min,
/// …, capped at an hour; zero after a success.
fn next_retry(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    // Cap the shift so neither the shift nor the multiplication overflows;
    // the first failure is one base delay.
    let shift = failures.saturating_sub(1).min(5);
    RETRY_BASE.saturating_mul(1u32 << shift).min(RETRY_MAX)
}

/// The cached catalog file is the freshness record: only advance its mtime
/// once every DB write in the sync succeeded.
fn should_persist_cache(db_ok: bool) -> bool {
    db_ok
}

/// One fetch + upsert pass, single-flight: a keeper sync
/// and a miss-triggered one cannot interleave writes.
///
/// Returns the next retry delay on failure, `None` on success.
async fn sync(catalog: &'static Catalog) -> Option<Duration> {
    if catalog.fetching.swap(true, Ordering::SeqCst) {
        return None;
    }
    catalog
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .last_attempt = Some(Instant::now());
    let result = sync_inner(catalog).await;
    catalog.fetching.store(false, Ordering::SeqCst);
    let retry = {
        let mut state = catalog.state.lock().unwrap_or_else(|e| e.into_inner());
        if result.is_ok() {
            state.failures = 0;
            None
        } else {
            state.failures = state.failures.saturating_add(1);
            Some(next_retry(state.failures))
        }
    };
    if let Err(error) = result {
        tracing::warn!(%error, "models.dev catalog sync failed");
    }
    retry
}

/// Served models plus the names that missed pricing, deduped and sorted so a
/// miss-triggered sync can actually upsert the model that triggered it.
fn upsert_candidates(served: Vec<String>, missing: &HashMap<String, Instant>) -> Vec<String> {
    let mut names: BTreeSet<&str> = served.iter().map(String::as_str).collect();
    names.extend(missing.keys().map(String::as_str));
    names.into_iter().map(str::to_owned).collect()
}

async fn sync_inner(catalog: &Catalog) -> anyhow::Result<()> {
    let bytes = fetch().await?;
    let parsed = parse_catalog(&bytes)?;
    // One lookup index for this sync, built from the parsed payload and never
    // cached process-wide, so it cannot drift from what we fetched.
    let index = PriceIndex::new(&parsed);
    let served = crate::store::served_models_for_pricing(&catalog.pool).await?;
    // Copy the missing names and drop the guard before any await.
    let models = {
        let state = catalog.state.lock().unwrap_or_else(|e| e.into_inner());
        upsert_candidates(served, &state.missing)
    };
    let mut db_error = None;
    for model in &models {
        let Some(cost) = index.find(model) else {
            continue;
        };
        if let Err(error) = catalog
            .price_cache
            .upsert(
                &catalog.pool,
                0,
                model,
                crate::relay::PriceInput {
                    input: cost.input,
                    output: cost.output,
                    cache_read: Some(cost.cache_read),
                    cache_write: Some(cost.cache_write),
                },
            )
            .await
        {
            db_error = Some(error);
            break;
        }
    }
    if should_persist_cache(db_error.is_none()) {
        if let Some(dir) = catalog.cache_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&catalog.cache_path, &bytes)?;
    }
    match db_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn fetch() -> anyhow::Result<Vec<u8>> {
    let resolvers = crate::upstream::dns::Resolvers::new()?;
    let client = reqwest::Client::builder()
        .dns_resolver(std::sync::Arc::clone(
            // models.dev is a fixed overseas endpoint, not a provider.
            resolvers.resolver(crate::upstream::Dns::Overseas),
        ))
        .user_agent("cardinal")
        .timeout(FETCH_TIMEOUT)
        .build()?;
    let response = client
        .get(MODELS_DEV_URL)
        .send()
        .await?
        .error_for_status()?;
    let bytes = response.bytes().await?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "models.dev: payload over {MAX_BYTES} bytes"
    );
    Ok(bytes.to_vec())
}

// ---------- parsing and matching (pure) ----------

/// One model's list price from the catalog, USD per million tokens; absent
/// parts are zero (models.dev omits the field for "free"/unpriced buckets).
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Deserialize)]
pub struct CostEntry {
    #[serde(default)]
    pub input: f64,
    #[serde(default)]
    pub output: f64,
    #[serde(default)]
    pub cache_read: f64,
    #[serde(default)]
    pub cache_write: f64,
}

#[derive(serde::Deserialize)]
struct ModelEntry {
    cost: Option<CostEntry>,
    /// The maker's own id for a renamed listing (DeepSeek sells
    /// `deepseek-flash`, canonical `deepseek/deepseek-v4.1-flash`).
    canonical_model_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct ProviderEntry {
    #[serde(default)]
    models: HashMap<String, ModelEntry>,
}

/// The whole catalog: models.dev provider id → entry.
type CatalogJson = HashMap<String, ProviderEntry>;

/// Parse a models.dev api.json payload; an empty or malformed one is an
/// error, not an empty catalog (never let a bad fetch wipe prices).
fn parse_catalog(bytes: &[u8]) -> anyhow::Result<CatalogJson> {
    let parsed: CatalogJson = serde_json::from_slice(bytes)?;
    anyhow::ensure!(!parsed.is_empty(), "models.dev: empty catalog");
    Ok(parsed)
}

/// Providers whose own models.dev entries price their models authoritatively
/// (verified ids against the live catalog, 2026-10-13). Only maker prices
/// are auto-imported: reseller listings differ from what our upstreams bill
/// by up to 10x, and a wrong price is worse than none — an unpriced model
/// stays NULL (the project's deliberate semantic) until the user seeds it.
const MAKERS: &[&str] = &[
    "openai",
    "anthropic",
    "google",
    "xai",
    "deepseek",
    "moonshotai",
    "moonshotai-cn",
    "zhipuai",
    "zai",
    "alibaba",
];

/// A price with both legs at zero is a subscription plan's listing, not a
/// price (a membership endpoint can bill 937K tokens at ¥0.000).
fn is_priced(cost: &CostEntry) -> bool {
    cost.input != 0.0 || cost.output != 0.0
}

/// The id without its path head ("deepseek/deepseek-v4.1-flash" →
/// "deepseek-v4.1-flash"). Shared by the catalog import and the request-path
/// price lookup (aggregator-served ids keep the vendor prefix the price
/// table doesn't).
pub(crate) fn bare(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

/// A one-shot lookup index built from a parsed catalog once per sync, never
/// cached process-wide, so it cannot drift from the payload we fetched.
///
/// Only MAKER entries contribute prices; any provider may still declare an
/// alias (`canonical_model_id`) pointing at one of those maker prices.
struct PriceIndex {
    /// Priced maker entry by bare lowercase id. First maker wins, unchanged
    /// from the previous exact-match behaviour.
    ids: HashMap<String, CostEntry>,
    /// The same entries with dots replaced by dashes: relays spell Anthropic
    /// `claude-opus-5.5`, the maker lists `claude-opus-5-5`.
    dashed_ids: HashMap<String, CostEntry>,
    /// A served id (from any provider) → the maker price its canonical names.
    /// `None` means alias sources disagree, so the alias stays unpriced.
    aliases: HashMap<String, Option<CostEntry>>,
}

impl PriceIndex {
    fn new(catalog: &CatalogJson) -> Self {
        let mut ids = HashMap::new();
        let mut dashed_ids = HashMap::new();
        // Canonical id → price agreed across the maker entries that declare
        // it. A reseller's listing under someone else's canonical is not that
        // maker's price (moonshotai-cn relists moonshotai/kimi-k3 at a
        // different rate), so it may only act as an alias source below.
        let mut shared: HashMap<String, Option<CostEntry>> = HashMap::new();
        // Of those entries, the one whose own id IS the canonical names the
        // base model; a differently priced sibling variant sharing the same
        // canonical (kimi-k3.1-pro-highspeed) must not decide its price.
        let mut owners: HashMap<String, Option<CostEntry>> = HashMap::new();
        let mut aliases: HashMap<String, Option<CostEntry>> = HashMap::new();
        for maker in MAKERS {
            let Some(provider) = catalog.get(*maker) else {
                continue;
            };
            for (id, entry) in &provider.models {
                let Some(cost) = entry.cost else { continue };
                if !is_priced(&cost) {
                    continue;
                }
                let id_bare = bare(&id.to_lowercase()).to_owned();
                ids.entry(id_bare.clone()).or_insert(cost);
                dashed_ids.entry(dashed(&id_bare)).or_insert(cost);
                let Some(spec) = entry.canonical_model_id.as_deref() else {
                    continue;
                };
                let Some((head, tail)) = spec.split_once('/') else {
                    continue;
                };
                if !head.eq_ignore_ascii_case(maker) {
                    continue;
                }
                let key = canonical_key(tail);
                agree(&mut shared, key.clone(), cost);
                if canonical_key(id) == key {
                    agree(&mut owners, key, cost);
                }
            }
        }
        let mut canonical = shared;
        for (key, cost) in owners {
            canonical.insert(key, cost);
        }
        // The maker's own canonical is also a name relays serve the model
        // under, so keep the old direct canonical lookup. Only resolved
        // prices seed aliases: an unresolved canonical must never clobber a
        // healthy alias contributed by another provider.
        for maker in MAKERS {
            let Some(provider) = catalog.get(*maker) else {
                continue;
            };
            for entry in provider.models.values() {
                let Some(spec) = entry.canonical_model_id.as_deref() else {
                    continue;
                };
                let Some((head, tail)) = spec.split_once('/') else {
                    continue;
                };
                if !head.eq_ignore_ascii_case(maker) {
                    continue;
                }
                let Some(Some(cost)) = canonical.get(&canonical_key(tail)) else {
                    continue;
                };
                agree(&mut aliases, bare(&spec.to_lowercase()).to_owned(), *cost);
            }
        }
        for provider in catalog.values() {
            for (id, entry) in &provider.models {
                let Some((_, tail)) = entry
                    .canonical_model_id
                    .as_deref()
                    .and_then(|spec| spec.split_once('/'))
                else {
                    continue;
                };
                let Some(Some(cost)) = canonical.get(&canonical_key(tail)) else {
                    continue;
                };
                agree(&mut aliases, bare(&id.to_lowercase()).to_owned(), *cost);
            }
        }
        Self {
            ids,
            dashed_ids,
            aliases,
        }
    }

    /// The catalog cost of a served model id: exact maker id, then the same
    /// with dots as dashes, then a canonical alias resolved to a maker price.
    /// Reseller prices are never used and a disagreement stays unpriced.
    fn find(&self, model: &str) -> Option<CostEntry> {
        let target = model.to_lowercase();
        let target = bare(&target);
        if let Some(cost) = self.ids.get(target) {
            return Some(*cost);
        }
        let dashed = dashed(target);
        if let Some(cost) = self.dashed_ids.get(&dashed) {
            return Some(*cost);
        }
        self.aliases.get(target).copied().flatten()
    }
}

/// Dots and dashes are interchangeable across relays and makers.
fn dashed(id: &str) -> String {
    id.replace('.', "-")
}

/// Strip one path head, lowercase and normalize a canonical id, dropping a
/// date-like snapshot suffix (`deepseek-v4.1-flash-1017` is the maker's
/// `deepseek-v4.1-flash`). Short numeric tails are part of the model's name —
/// `claude-opus-5-5` must not become `claude-opus-5`.
fn canonical_key(id: &str) -> String {
    let lower = id.to_lowercase();
    let bare = bare(&lower);
    let dashed = dashed(bare);
    strip_snapshot(&dashed).to_owned()
}

fn strip_snapshot(id: &str) -> &str {
    let Some((head, tail)) = id.rsplit_once('-') else {
        return id;
    };
    if tail.len() >= 4 && tail.bytes().all(|byte| byte.is_ascii_digit()) {
        head
    } else {
        id
    }
}

/// Keep a price only while every maker entry for the key agrees; a conflict
/// poisons the key so lookup fails closed instead of guessing a rate.
fn agree(by: &mut HashMap<String, Option<CostEntry>>, key: String, cost: CostEntry) {
    match by.entry(key) {
        Entry::Vacant(slot) => {
            slot.insert(Some(cost));
        }
        Entry::Occupied(mut slot) => {
            if slot.get().is_some_and(|was| was != cost) {
                slot.insert(None);
            }
        }
    }
}
