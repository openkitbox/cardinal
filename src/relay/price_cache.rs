//! In-memory cache of model prices.
//! Write-through: PG is always written first, then the cache is updated.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::store::ModelPrice;

/// The four rate legs of one price row, USD per million tokens.
/// `cache_read`/`cache_write` are `None` when the row carries no cached-token
/// rates (kept distinct from "priced at zero").
#[derive(Clone, Copy, Debug, Default)]
pub struct PriceInput {
    pub input: f64,
    pub output: f64,
    pub cache_read: Option<f64>,
    pub cache_write: Option<f64>,
}

#[derive(Clone)]
pub struct PriceCache {
    inner: Arc<RwLock<PriceCacheInner>>,
}

struct PriceCacheInner {
    /// Provider-scoped rows: provider_id → model → price.
    scoped: HashMap<i64, HashMap<String, ModelPrice>>,
    /// The global fallback rows (provider_id = 0): model → price.
    global: HashMap<String, ModelPrice>,
}

impl PriceCacheInner {
    fn insert(&mut self, provider_id: i64, model: String, price: ModelPrice) {
        if provider_id == 0 {
            self.global.insert(model, price);
        } else {
            self.scoped
                .entry(provider_id)
                .or_default()
                .insert(model, price);
        }
    }
}

impl PriceCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PriceCacheInner {
                scoped: HashMap::new(),
                global: HashMap::new(),
            })),
        }
    }

    /// Load from PG at startup. Swap-atomic: the replacement map is built
    /// outside the lock and installed with a single write.
    pub async fn load(&self, pool: &sqlx::PgPool) -> anyhow::Result<()> {
        let rows = sqlx::query_as::<_, (i64, String, f64, f64, f64, f64, Option<f64>, Option<String>)>(
      "SELECT provider_id, model, input_usd::float8, output_usd::float8, cache_read_usd::float8, cache_write_usd::float8,
              cache_write_1h_usd::float8, tiers::text
       FROM gateway_model_prices",
    )
    .fetch_all(pool)
    .await?;

        let mut map = PriceCacheInner {
            scoped: HashMap::new(),
            global: HashMap::new(),
        };
        for (
            provider_id,
            model,
            input_usd,
            output_usd,
            cache_read_usd,
            cache_write_usd,
            cache_write_1h_usd,
            tiers,
        ) in rows
        {
            let tiers = match tiers {
                Some(json) => serde_json::from_str::<Vec<crate::store::PriceTier>>(&json)?,
                None => Vec::new(),
            };
            let price = ModelPrice {
                input_usd,
                output_usd,
                cache_read_usd,
                cache_write_usd,
                cache_write_1h_usd,
                tiers,
            };
            map.insert(provider_id, model, price);
        }
        *self
            .inner
            .write()
            .map_err(|e| anyhow::anyhow!("price cache lock poisoned: {e}"))? = map;
        Ok(())
    }

    pub fn get(&self, provider_id: i64, model: &str) -> Option<ModelPrice> {
        let inner = self.inner.read().ok()?;
        // Provider-scoped row first, then the global fallback (provider_id = 0).
        // Aggregator routes serve vendor-prefixed ids (`deepseek/deepseek-v4.1-flash`)
        // the price table doesn't carry; a global miss retries the bare id —
        // the same one-path-head strip the catalog import normalizes with
        // (`crate::prices::bare`).
        inner
            .scoped
            .get(&provider_id)
            .and_then(|m| m.get(model))
            .or_else(|| inner.global.get(model))
            .or_else(|| inner.global.get(crate::prices::bare(model)))
            .cloned()
    }

    /// Upsert a catalog price (write-through: PG first, then cache).
    /// Only updates the cache if the row is actually written (source = 'catalog').
    pub async fn upsert(
        &self,
        pool: &sqlx::PgPool,
        provider_id: i64,
        model: &str,
        price: PriceInput,
    ) -> anyhow::Result<()> {
        let read = price.cache_read.unwrap_or(0.0);
        let write = price.cache_write.unwrap_or(0.0);
        crate::store::upsert_catalog_price(pool, model, price.input, price.output, read, write)
            .await?;
        // Refresh from PG to get the merged state (including tiers if any).
        let row = crate::store::get_price(pool, provider_id, model).await?;
        if let Some(price) = row {
            let mut inner = self
                .inner
                .write()
                .map_err(|e| anyhow::anyhow!("price cache lock poisoned: {e}"))?;
            inner.insert(provider_id, model.to_owned(), price);
        }
        Ok(())
    }
}

impl Default for PriceCache {
    fn default() -> Self {
        Self::new()
    }
}
