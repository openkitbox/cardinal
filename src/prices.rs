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

use std::collections::HashMap;
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

/// The keeper loop: sync when stale, look again in an
/// hour, forever. Never returns; the process exit ends it.
async fn keep_fresh(catalog: &'static Catalog) {
    loop {
        if cache_age(&catalog.cache_path).is_none_or(|age| age > STALE_AFTER) {
            sync(catalog).await;
        }
        tokio::time::sleep(RECHECK_EVERY).await;
    }
}

/// Cache file age; None when missing or unreadable (treated as stale).
fn cache_age(path: &PathBuf) -> Option<Duration> {
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(mtime).ok()
}

/// One fetch + upsert pass, single-flight: a keeper sync
/// and a miss-triggered one cannot interleave writes.
async fn sync(catalog: &'static Catalog) {
    if catalog.fetching.swap(true, Ordering::SeqCst) {
        return;
    }
    catalog
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .last_attempt = Some(Instant::now());
    let result = sync_inner(catalog).await;
    catalog.fetching.store(false, Ordering::SeqCst);
    if let Err(error) = result {
        tracing::warn!(%error, "models.dev catalog sync failed");
    }
}

async fn sync_inner(catalog: &Catalog) -> anyhow::Result<()> {
    let bytes = fetch().await?;
    let parsed = parse_catalog(&bytes)?;
    // Cache write first: the file's mtime is the freshness record, so it must
    // only move once the payload parsed.
    if let Some(dir) = catalog.cache_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&catalog.cache_path, &bytes)?;
    let models = crate::store::served_models_for_pricing(&catalog.pool).await?;
    for model in &models {
        if let Some(cost) = find_cost(&parsed, model) {
            catalog
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
                .await?;
        }
    }
    Ok(())
}

async fn fetch() -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
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

/// The catalog cost of a served model id, conservatively:
/// 1. a MAKER provider's entry whose bare key is the id (zhipuai's
///    `glm-5.3-flash`), else
/// 2. a MAKER entry whose `canonical_model_id` names the id (deepseek's
///    `deepseek-flash` → `deepseek/deepseek-v4.1-flash`), else
/// 3. None — reseller prices are never imported.
fn find_cost(catalog: &CatalogJson, model: &str) -> Option<CostEntry> {
    let target = model.to_lowercase();
    for maker in MAKERS {
        let Some(provider) = catalog.get(*maker) else {
            continue;
        };
        for (model_id, entry) in &provider.models {
            let Some(cost) = entry.cost else { continue };
            if is_priced(&cost) && bare(&model_id.to_lowercase()) == target {
                return Some(cost);
            }
        }
    }
    for maker in MAKERS {
        let Some(provider) = catalog.get(*maker) else {
            continue;
        };
        for entry in provider.models.values() {
            let (Some(cost), Some(canonical)) = (entry.cost, &entry.canonical_model_id) else {
                continue;
            };
            if is_priced(&cost) && bare(&canonical.to_lowercase()) == target {
                return Some(cost);
            }
        }
    }
    None
}
