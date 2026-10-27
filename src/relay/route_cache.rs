//! In-memory cache of providers, keys, and routes — the data `resolve()` needs.
//! Seeded from PG at startup, refreshed after any admin write.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::protocol::ProtocolId;
use crate::store::{
    EnabledKeyModels, KeyModels, LimitedKeyRow, ProviderKeyRow, ProviderRow, RouteRow,
};

#[derive(Clone)]
pub struct RouteCache {
    inner: Arc<RwLock<RouteCacheInner>>,
    generation: Arc<AtomicU64>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

struct RouteCacheInner {
    providers_by_name: HashMap<String, ProviderRow>,
    providers_by_id: HashMap<i64, ProviderRow>,
    keys_by_id: HashMap<i64, ProviderKeyRow>,
    keys_by_provider: HashMap<i64, Vec<ProviderKeyRow>>, // provider_id → keys
    routes_by_alias: HashMap<String, RouteRow>,
    all_routes: Vec<RouteRow>,
}

impl RouteCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RouteCacheInner {
                providers_by_name: HashMap::new(),
                providers_by_id: HashMap::new(),
                keys_by_id: HashMap::new(),
                keys_by_provider: HashMap::new(),
                routes_by_alias: HashMap::new(),
                all_routes: Vec::new(),
            })),
            generation: Arc::new(AtomicU64::new(0)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// One-shot load from PG at startup.
    pub async fn load(&self, pool: &sqlx::PgPool) -> anyhow::Result<()> {
        self.refresh(pool).await
    }

    /// Full reload after admin mutations (create/update/delete provider/key/route).
    pub async fn refresh(&self, pool: &sqlx::PgPool) -> anyhow::Result<()> {
        let _refresh_guard = self.refresh_lock.lock().await;
        let inner = Self::load_inner(pool).await?;
        self.replace_inner(inner);
        Ok(())
    }

    /// Reload a complete snapshot and publish its cap table to the dispatcher.
    /// The dispatcher activates it immediately, retries queued requests, and
    /// preserves existing inflight work when a cap decreases.
    pub async fn refresh_and_sync(
        &self,
        pool: &sqlx::PgPool,
        dispatcher: &tokio::sync::mpsc::UnboundedSender<crate::relay::dispatcher::DispatchEvent>,
    ) -> anyhow::Result<()> {
        let _refresh_guard = self.refresh_lock.lock().await;
        let inner = Self::load_inner(pool).await?;
        let generation = self.generation() + 1;
        let caps = Self::concurrency_caps_for(&inner);
        let (reply, response) = tokio::sync::oneshot::channel();
        if dispatcher
            .send(crate::relay::dispatcher::DispatchEvent::SyncKeyCaps {
                caps,
                generation,
                reply,
            })
            .is_err()
        {
            tracing::warn!("dispatcher unavailable while syncing route concurrency caps");
        } else if response.await.is_err() {
            tracing::warn!("dispatcher stopped while syncing route concurrency caps");
        }
        self.replace_inner(inner);
        Ok(())
    }

    async fn load_inner(pool: &sqlx::PgPool) -> anyhow::Result<RouteCacheInner> {
        let providers = crate::store::list_providers(pool).await?;
        let keys = crate::store::list_all_keys(pool).await?;
        let routes = crate::store::list_routes(pool).await?;

        let mut providers_by_name = HashMap::new();
        let mut providers_by_id = HashMap::new();
        for p in providers {
            providers_by_name.insert(p.name.clone(), p.clone());
            providers_by_id.insert(p.id, p);
        }

        let mut keys_by_id = HashMap::new();
        let mut keys_by_provider: HashMap<i64, Vec<ProviderKeyRow>> = HashMap::new();
        for k in keys {
            keys_by_provider
                .entry(k.provider_id)
                .or_default()
                .push(k.clone());
            keys_by_id.insert(k.id, k);
        }

        let mut routes_by_alias = HashMap::new();
        for r in &routes {
            routes_by_alias.insert(r.alias.clone(), r.clone());
        }

        Ok(RouteCacheInner {
            providers_by_name,
            providers_by_id,
            keys_by_id,
            keys_by_provider,
            routes_by_alias,
            all_routes: routes,
        })
    }

    fn replace_inner(&self, new_inner: RouteCacheInner) {
        let Ok(mut inner) = self.inner.write() else {
            tracing::warn!("route cache lock poisoned while replacing snapshot");
            return;
        };
        *inner = new_inner;
        self.generation.fetch_add(1, Ordering::Release);
    }

    // Sync read methods used by resolve():
    pub fn provider_by_name(&self, name: &str) -> Option<ProviderRow> {
        self.inner.read().ok()?.providers_by_name.get(name).cloned()
    }

    pub fn keys_for_provider(&self, provider_id: i64) -> Vec<ProviderKeyRow> {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.keys_by_provider.get(&provider_id).cloned())
            .unwrap_or_default()
    }

    pub fn route_by_alias(&self, alias: &str) -> Option<RouteRow> {
        self.inner.read().ok()?.routes_by_alias.get(alias).cloned()
    }

    pub fn keys_by_ids(&self, ids: &[i64]) -> Vec<ProviderKeyRow> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        let mut rows: Vec<ProviderKeyRow> = ids
            .iter()
            .filter_map(|id| inner.keys_by_id.get(id).cloned())
            .collect();
        rows.sort_by_key(|k| (k.position, k.id));
        rows
    }

    pub fn providers_by_ids(&self, ids: &[i64]) -> Vec<ProviderRow> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        ids.iter()
            .filter_map(|id| inner.providers_by_id.get(id).cloned())
            .collect()
    }

    // Used by api.rs / admin_ops.rs:
    pub fn all_routes(&self) -> Vec<RouteRow> {
        self.inner
            .read()
            .map(|inner| inner.all_routes.clone())
            .unwrap_or_default()
    }

    /// Every route with the kind derived from its entries: `true` = chat-capable
    /// (some entry's provider serves a chat protocol), `false` = retrieval-only.
    ///
    /// Derived, never stored: the kind follows whatever the route currently
    /// points at, so re-pointing an alias changes its kind with no migration.
    /// A mixed route is chat-capable — its chat half is real.
    pub fn routes_with_kind(&self) -> Vec<(RouteRow, bool)> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        inner
            .all_routes
            .iter()
            .map(|route| {
                let chat_capable = route.entries.iter().any(|entry| {
                    inner
                        .keys_by_id
                        .get(&entry.key_id)
                        .and_then(|key| inner.providers_by_id.get(&key.provider_id))
                        .is_some_and(chat_capable)
                });
                (route.clone(), chat_capable)
            })
            .collect()
    }

    /// The routes a chat model picker may advertise: every chat-capable route.
    /// A retrieval route has no `messages` body and no chat attributes, so
    /// offering it to an agent offers a model that refuses every chat call.
    pub fn chat_routes(&self) -> Vec<RouteRow> {
        self.routes_with_kind()
            .into_iter()
            .filter_map(|(route, chat_capable)| chat_capable.then_some(route))
            .collect()
    }

    pub fn all_enabled_key_models(&self) -> Vec<EnabledKeyModels> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        // Replicates: SELECT p.name AS provider, k.models, k.allowed_models
        //   FROM gateway_provider_keys k JOIN gateway_providers p ON p.id = k.provider_id
        //   WHERE p.enabled AND k.enabled ORDER BY p.name, k.position, k.id
        //   — minus the retrieval-only providers (see [`chat_capable`]): their
        //   models are embeddings ids, not chat model ids.
        let mut rows: Vec<EnabledKeyModels> = Vec::new();
        let mut providers: Vec<&ProviderRow> = inner
            .providers_by_id
            .values()
            .filter(|p| p.enabled && chat_capable(p))
            .collect();
        providers.sort_by(|a, b| a.name.cmp(&b.name));
        for provider in providers {
            let mut keys: Vec<&ProviderKeyRow> = inner
                .keys_by_provider
                .get(&provider.id)
                .map(|keys| keys.iter().filter(|k| k.enabled).collect())
                .unwrap_or_default();
            keys.sort_by_key(|k| (k.position, k.id));
            for key in keys {
                rows.push(EnabledKeyModels {
                    provider: provider.name.clone(),
                    models: key.models.clone(),
                    allowed_models: key.allowed_models.clone(),
                });
            }
        }
        rows
    }

    pub fn all_limited_keys(&self) -> Vec<LimitedKeyRow> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        // Replicates: SELECT k.id AS key_id, k.provider_id, p.name AS provider_name, k.label AS key_label, k.max_concurrency
        //   FROM gateway_provider_keys k JOIN gateway_providers p ON p.id = k.provider_id
        //   WHERE k.max_concurrency IS NOT NULL ORDER BY p.name, k.label, k.id
        let mut rows: Vec<LimitedKeyRow> = Vec::new();
        for key in inner.keys_by_id.values() {
            if let (Some(max_concurrency), Some(provider)) = (
                key.max_concurrency,
                inner.providers_by_id.get(&key.provider_id),
            ) {
                rows.push(LimitedKeyRow {
                    key_id: key.id,
                    provider_id: key.provider_id,
                    provider_name: provider.name.clone(),
                    key_label: key.label.clone(),
                    max_concurrency,
                });
            }
        }
        rows.sort_by(|a, b| {
            a.provider_name
                .cmp(&b.provider_name)
                .then(a.key_label.cmp(&b.key_label))
                .then(a.key_id.cmp(&b.key_id))
        });
        rows
    }

    pub fn all_key_caps(&self) -> Vec<(i64, Option<i32>)> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        inner
            .keys_by_id
            .values()
            .map(|key| (key.id, key.max_concurrency))
            .collect()
    }

    /// Complete cap view for the dispatcher. Uncapped route entries are
    /// included as `None` so clearing an entry cap cannot leave an old slot
    /// cap behind.
    pub fn all_concurrency_caps(&self) -> Vec<(crate::relay::SlotKey, Option<usize>)> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        Self::concurrency_caps_for(&inner)
    }

    fn concurrency_caps_for(
        inner: &RouteCacheInner,
    ) -> Vec<(crate::relay::SlotKey, Option<usize>)> {
        let mut caps = Vec::new();
        for key in inner.keys_by_id.values() {
            let Some(provider) = inner.providers_by_id.get(&key.provider_id) else {
                continue;
            };
            if !key.enabled || !provider.enabled {
                continue;
            }
            caps.push((
                crate::relay::SlotKey::Key(key.id as u64),
                key.max_concurrency.map(|cap| cap as usize),
            ));
        }
        for route in &inner.all_routes {
            for entry in &route.entries {
                let Some(key) = inner.keys_by_id.get(&entry.key_id) else {
                    continue;
                };
                let Some(provider) = inner.providers_by_id.get(&key.provider_id) else {
                    continue;
                };
                if !key.enabled || !provider.enabled {
                    continue;
                }
                caps.push((
                    crate::relay::dispatcher::entry_slot_key(
                        &route.alias,
                        entry.key_id as u64,
                        &entry.model,
                    ),
                    entry
                        .max_concurrency
                        .and_then(|cap| usize::try_from(cap).ok()),
                ));
            }
        }
        caps
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn all_key_models(&self) -> Vec<KeyModels> {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };
        // Replicates: SELECT id, models, allowed_models FROM gateway_provider_keys ORDER BY id
        let mut rows: Vec<KeyModels> = inner
            .keys_by_id
            .values()
            .map(|k| KeyModels {
                id: k.id,
                models: k.models.clone(),
                allowed_models: k.allowed_models.clone(),
            })
            .collect();
        rows.sort_by_key(|k| k.id);
        rows
    }

    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .map(|inner| inner.providers_by_id.is_empty() && inner.keys_by_id.is_empty())
            .unwrap_or(true)
    }
}

/// Whether a provider row can serve a chat-shaped request — the filter that
/// keeps retrieval-only rows (and their models) out of chat model pickers.
///
/// Deliberately a denylist of ONE closed protocol, not an allowlist of the
/// chat three: a row whose protocol this build does not know is still offered
/// (the relay is the source of truth for dispatch failure), while a retrieval
/// row is known to be the wrong kind for a conversation.
fn chat_capable(provider: &ProviderRow) -> bool {
    provider.protocol != ProtocolId::OpenAiEmbeddings.as_str()
}

impl Default for RouteCache {
    fn default() -> Self {
        Self::new()
    }
}
