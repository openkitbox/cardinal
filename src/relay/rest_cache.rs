//! In-memory cache of key cooldowns (gateway_key_rests).
//! Write-through: PG is always written first, then the cache is updated.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};

use crate::store::{ActiveRestRow, RestRow};

type RestMap = HashMap<(i64, Option<String>), RestEntry>;

#[derive(Clone)]
pub struct RestCache {
    inner: Arc<RwLock<RestMap>>,
    pool: sqlx::PgPool, // for write-through
}

#[derive(Clone, Debug)]
pub struct RestEntry {
    pub rest_until: DateTime<Utc>,
    pub reason: String,
}

impl RestCache {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            pool,
        }
    }

    /// Load from PG at startup. Swap-atomic: the replacement map is built
    /// outside the lock and installed with a single write, so a concurrent
    /// `insert` can never land between a clear and a rebuild and be lost.
    pub async fn load(&self) -> anyhow::Result<()> {
        let rows = crate::store::active_rest_rows(&self.pool).await?;
        let mut map = RestMap::new();
        for row in rows {
            map.insert(
                (row.key_id, row.model.clone()),
                RestEntry {
                    rest_until: row.rest_until,
                    reason: row.reason.unwrap_or_default(),
                },
            );
        }
        *self
            .inner
            .write()
            .map_err(|e| anyhow::anyhow!("rest cache lock poisoned: {e}"))? = map;
        Ok(())
    }

    /// All currently-unexpired rest rows (replaces `active_rest_rows`).
    pub fn active_rows(&self) -> Vec<ActiveRestRow> {
        let now = Utc::now();
        self.inner
            .read()
            .map(|inner| {
                inner
                    .iter()
                    .filter(|(_, entry)| entry.rest_until > now)
                    .map(|((key_id, model), entry)| ActiveRestRow {
                        key_id: *key_id,
                        model: model.clone(),
                        rest_until: entry.rest_until,
                        reason: Some(entry.reason.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Insert a rest (write-through: PG first, then cache).
    pub async fn insert(
        &self,
        key_id: i64,
        model: Option<&str>,
        rest_until: DateTime<Utc>,
        reason: &str,
    ) -> anyhow::Result<()> {
        crate::store::insert_rest(&self.pool, key_id, model, rest_until, reason).await?;
        let mut inner = self
            .inner
            .write()
            .map_err(|e| anyhow::anyhow!("rest cache lock poisoned: {e}"))?;
        inner.insert(
            (key_id, model.map(str::to_owned)),
            RestEntry {
                rest_until,
                reason: reason.to_owned(),
            },
        );
        Ok(())
    }

    /// Clear a key's whole-key rest + the named model's rest (write-through).
    pub async fn clear_for_model(&self, key_id: i64, model: &str) -> anyhow::Result<()> {
        crate::store::clear_rest_for_model(&self.pool, key_id, model).await?;
        let mut inner = self
            .inner
            .write()
            .map_err(|e| anyhow::anyhow!("rest cache lock poisoned: {e}"))?;
        inner.remove(&(key_id, None));
        inner.remove(&(key_id, Some(model.to_owned())));
        Ok(())
    }

    /// Clear ALL rest rows for a key (write-through).
    pub async fn clear_key(&self, key_id: i64) -> anyhow::Result<()> {
        crate::store::clear_rest(&self.pool, key_id).await?;
        let mut inner = self
            .inner
            .write()
            .map_err(|e| anyhow::anyhow!("rest cache lock poisoned: {e}"))?;
        inner.retain(|(k, _), _| *k != key_id);
        Ok(())
    }

    /// Clear all rest rows for all keys of a provider (write-through).
    pub async fn clear_provider(&self, provider_id: i64) -> anyhow::Result<()> {
        crate::store::clear_provider_rests(&self.pool, provider_id).await?;
        // The cache doesn't know provider→key mapping; reload from PG (the table
        // is tiny, <10 rows). Brief staleness window: a concurrent rest insert
        // between the DELETE and the reload is overwritten by the snapshot — it
        // re-populates on the next failure, so this is accepted.
        self.load().await
    }

    /// List all rest rows for admin display (replaces `list_rests`).
    /// Keeps using PG for the JOIN with provider/key names (admin reads are not hot path).
    pub async fn list_all(&self) -> anyhow::Result<Vec<RestRow>> {
        crate::store::list_rests(&self.pool).await
    }
}
