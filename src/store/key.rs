use sqlx::PgPool;

use crate::probe::ProbeModel;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct ProviderKeyRow {
    pub id: i64,
    pub provider_id: i64,
    pub label: String,
    /// The row-stored plaintext credential (0013). NULL = not entered yet;
    /// the relay skips such rows with a warning.
    pub api_key: Option<String>,
    pub enabled: bool,
    /// Single global ordering across all providers (app-maintained).
    pub position: i32,
    /// Per-key in-flight cap; NULL = unlimited.
    pub max_concurrency: Option<i32>,
    /// The key's cached model-list snapshot: what its provider's /models last
    /// answered (NULL until the first successful probe). Feeds the /v1/models
    /// route-object derivation.
    #[sqlx(json(nullable))]
    pub models: Option<Vec<ProbeModel>>,
    /// Model whitelist: NULL/empty = unrestricted (every model servable);
    /// a non-empty list = the exact upstream model ids this key may serve
    /// (relay candidate filtering).
    #[sqlx(json(nullable))]
    pub allowed_models: Option<Vec<String>>,
}

/// Public view of ProviderKeyRow: hides api_key. `inflight` is the live
/// semaphore occupancy (`Some` only for limited keys), filled by the caller
/// from the concurrency registry.
///
/// This is the shape everything that lists keys renders from — including the
/// pushed bootstrap document — so it carries no credential by construction.
/// The plaintext stays behind the single reveal endpoint.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProviderKeyView {
    pub id: i64,
    pub provider_id: i64,
    pub label: String,
    pub enabled: bool,
    pub position: i32,
    pub max_concurrency: Option<i32>,
    pub inflight: Option<i32>,
    /// The key's cached model-list snapshot (None until the first successful
    /// probe). The key editor prefills its model picker from this instead of
    /// re-probing the vendor on open.
    pub models: Option<Vec<ProbeModel>>,
    /// The key's model whitelist (None = unrestricted).
    pub allowed_models: Option<Vec<String>>,
}

impl ProviderKeyView {
    pub fn new(row: &ProviderKeyRow, inflight: Option<i32>) -> Self {
        Self {
            id: row.id,
            provider_id: row.provider_id,
            label: row.label.clone(),
            enabled: row.enabled,
            position: row.position,
            max_concurrency: row.max_concurrency,
            inflight,
            models: row.models.clone(),
            allowed_models: row.allowed_models.clone(),
        }
    }
}

/// One provider's keys in global (position, id) order.
pub async fn list_provider_keys(
    pool: &PgPool,
    provider_id: i64,
) -> anyhow::Result<Vec<ProviderKeyRow>> {
    let rows = sqlx::query_as::<_, ProviderKeyRow>(
    "SELECT id, provider_id, label, api_key, enabled, position, max_concurrency, models, allowed_models FROM gateway_provider_keys
         WHERE provider_id = $1 ORDER BY position, id",
  )
  .bind(provider_id)
  .fetch_all(pool)
  .await?;
    Ok(rows)
}

/// Every key across all providers, in global (position, id) order — the
/// /v1/models route-object derivation resolves route entries against it.
pub async fn list_all_keys(pool: &PgPool) -> anyhow::Result<Vec<ProviderKeyRow>> {
    let rows = sqlx::query_as::<_, ProviderKeyRow>(
    "SELECT id, provider_id, label, api_key, enabled, position, max_concurrency, models, allowed_models FROM gateway_provider_keys
         ORDER BY position, id",
  )
  .fetch_all(pool)
  .await?;
    Ok(rows)
}

/// The (key id, model snapshot) pairs the /v1/models route-object derivation
/// needs — nothing else: no api_key plaintext, no concurrency lookups.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct KeyModels {
    pub id: i64,
    #[sqlx(json(nullable))]
    pub models: Option<Vec<ProbeModel>>,
    /// The key's model whitelist (NULL/empty = every model). The /v1/models
    /// derivation honors it: a route entry whose key does not serve the entry's
    /// model contributes nothing, so we never advertise a model that would 404.
    #[sqlx(json(nullable))]
    pub allowed_models: Option<Vec<String>>,
}

pub async fn list_all_key_models(pool: &PgPool) -> anyhow::Result<Vec<KeyModels>> {
    let rows = sqlx::query_as::<_, KeyModels>(
        "SELECT id, models, allowed_models FROM gateway_provider_keys ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// One enabled account's model snapshot under its enabled provider — the
/// direct `provider/model` half of the chat picker's model list.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct EnabledKeyModels {
    pub provider: String,
    /// Probe snapshot; None until the account was probed once.
    #[sqlx(json(nullable))]
    pub models: Option<Vec<ProbeModel>>,
    #[sqlx(json(nullable))]
    pub allowed_models: Option<Vec<String>>,
}

/// Enabled providers' enabled keys with their model snapshots (provider
/// order, then global key order).
pub async fn list_enabled_key_models(pool: &PgPool) -> anyhow::Result<Vec<EnabledKeyModels>> {
    let rows = sqlx::query_as::<_, EnabledKeyModels>(
        "SELECT p.name AS provider, k.models, k.allowed_models FROM gateway_provider_keys k
     JOIN gateway_providers p ON p.id = k.provider_id
     WHERE p.enabled AND k.enabled
     ORDER BY p.name, k.position, k.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Keys by id (route expansion), in global (position, id) order.
pub async fn list_keys_by_ids(pool: &PgPool, ids: &[i64]) -> anyhow::Result<Vec<ProviderKeyRow>> {
    let rows = sqlx::query_as::<_, ProviderKeyRow>(
    "SELECT id, provider_id, label, api_key, enabled, position, max_concurrency, models, allowed_models FROM gateway_provider_keys
         WHERE id = ANY($1) ORDER BY position, id",
  )
  .bind(ids)
  .fetch_all(pool)
  .await?;
    Ok(rows)
}

/// Persist one key's model-list snapshot (the probe result that doubles as key
/// validation), refreshing the probe timestamp.
pub async fn update_key_models(
    pool: &PgPool,
    key_id: i64,
    models: &[ProbeModel],
) -> anyhow::Result<bool> {
    let payload = serde_json::to_value(models)?;
    let result = sqlx::query(
        "UPDATE gateway_provider_keys SET models = $2, models_probed_at = now() WHERE id = $1",
    )
    .bind(key_id)
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Every key is named and holds a credential; new keys append to the end of the global ordering.
/// The advisory lock serializes the MAX(position)+1 append against concurrent inserts and reorders.
/// `allowed_models`: the key's model whitelist (None/empty = unrestricted).
/// `api_key` is the plaintext credential stored in the row (DB-backed since
/// 0013 — the Keychain round-trip caused per-read authorization prompts and
/// bought nothing for a single-user local service).
pub async fn insert_provider_key(
    pool: &PgPool,
    provider_id: i64,
    label: &str,
    api_key: &str,
    max_concurrency: Option<i32>,
    allowed_models: Option<Vec<String>>,
) -> anyhow::Result<i64> {
    anyhow::ensure!(!label.is_empty(), "label must not be empty");
    ensure_valid_max_concurrency(max_concurrency)?;
    let allowed_models = normalize_allowed_models(allowed_models)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('gateway_provider_keys.position'))")
        .execute(&mut *tx)
        .await?;
    let id: (i64,) = sqlx::query_as(
    "INSERT INTO gateway_provider_keys (provider_id, label, api_key, position, max_concurrency, allowed_models)
         VALUES ($1, $2, $3, (SELECT COALESCE(MAX(position) + 1, 0) FROM gateway_provider_keys), $4, $5) RETURNING id",
  )
  .bind(provider_id)
  .bind(label)
  .bind(api_key)
  .bind(max_concurrency)
  .bind(allowed_models.map(serde_json::to_value).transpose()?)
  .fetch_one(&mut *tx)
  .await?;
    tx.commit().await?;
    Ok(id.0)
}

/// The concurrency cap must be positive when set (mirrors the column CHECK,
/// with a readable error instead of a database violation).
fn ensure_valid_max_concurrency(max_concurrency: Option<i32>) -> anyhow::Result<()> {
    if let Some(limit) = max_concurrency {
        anyhow::ensure!(limit > 0, "max_concurrency must be positive");
    }
    Ok(())
}

/// Normalize a model whitelist for storage: trim each entry (a trimmed-empty
/// entry is a caller mistake, not data — rejected), dedupe in input order,
/// and normalize an empty result to None, so the column is either NULL
/// (unrestricted) or a non-empty array of distinct ids.
fn normalize_allowed_models(models: Option<Vec<String>>) -> anyhow::Result<Option<Vec<String>>> {
    let Some(models) = models else {
        return Ok(None);
    };
    let mut out: Vec<String> = Vec::with_capacity(models.len());
    for model in models {
        let model = model.trim();
        anyhow::ensure!(
            !model.is_empty(),
            "allowed_models entries must not be empty"
        );
        if !out.iter().any(|kept| kept == model) {
            out.push(model.to_owned());
        }
    }
    Ok((!out.is_empty()).then_some(out))
}

/// Partial update (PATCH semantics): only the supplied fields change.
/// `max_concurrency` is three-state: outer None = untouched, inner None = clear to unlimited.
/// `allowed_models` is three-state likewise: outer None = untouched, inner None
/// (or an empty list) = clear to unrestricted (stored as NULL).
/// Credential rotation is deliberately NOT here: rotate by delete + recreate
/// (a new row gets a fresh position and a fresh cooldown identity).
pub async fn update_provider_key(
    pool: &PgPool,
    provider_id: i64,
    key_id: i64,
    label: Option<&str>,
    enabled: Option<bool>,
    max_concurrency: Option<Option<i32>>,
    allowed_models: Option<Option<Vec<String>>>,
) -> anyhow::Result<bool> {
    if let Some(label) = label {
        anyhow::ensure!(!label.is_empty(), "label must not be empty");
    }
    ensure_valid_max_concurrency(max_concurrency.flatten())?;
    let allowed_models = match allowed_models {
        Some(list) => Some(normalize_allowed_models(list)?),
        None => None,
    };
    let result = sqlx::query(
        "UPDATE gateway_provider_keys SET
           label = COALESCE($3, label),
           enabled = COALESCE($4, enabled),
           max_concurrency = CASE WHEN $5 THEN $6 ELSE max_concurrency END,
           allowed_models = CASE WHEN $7 THEN $8 ELSE allowed_models END
         WHERE id = $1 AND provider_id = $2",
    )
    .bind(key_id)
    .bind(provider_id)
    .bind(label)
    .bind(enabled)
    .bind(max_concurrency.is_some())
    .bind(max_concurrency.flatten())
    .bind(allowed_models.is_some())
    .bind(
        allowed_models
            .flatten()
            .map(serde_json::to_value)
            .transpose()?,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// The key's stored secret reference (None = no such row or no reference).
/// The admin delete path reads it BEFORE the row goes away so the secret
/// store's item can be removed with it (admin_ops::delete_key).
pub async fn key_api_key(
    pool: &PgPool,
    provider_id: i64,
    key_id: i64,
) -> anyhow::Result<Option<String>> {
    let reference = sqlx::query_scalar(
        "SELECT api_key FROM gateway_provider_keys WHERE id = $1 AND provider_id = $2",
    )
    .bind(key_id)
    .bind(provider_id)
    .fetch_optional(pool)
    .await?;
    Ok(reference.flatten())
}

/// Delete a key row and strip dangling route entries in the same transaction.
pub async fn delete_provider_key(
    pool: &PgPool,
    provider_id: i64,
    key_id: i64,
) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let result =
        sqlx::query("DELETE FROM gateway_provider_keys WHERE id = $1 AND provider_id = $2")
            .bind(key_id)
            .bind(provider_id)
            .execute(&mut *tx)
            .await?;
    if result.rows_affected() > 0 {
        // Cascade into routes: an entry pointing at a deleted key is a dangling
        // reference that resolves to zero candidates (a misleading 404). Strip it
        // in the same transaction; a route left empty keeps its alias so it can be
        // re-pointed instead of silently vanishing from /v1/models.
        sqlx::query(
      "UPDATE gateway_routes
       SET entries = COALESCE(
         (SELECT jsonb_agg(entry) FROM jsonb_array_elements(entries) AS entry WHERE (entry->>'key_id')::bigint <> $1),
         '[]'::jsonb
       )
       WHERE entries @> jsonb_build_array(jsonb_build_object('key_id', $1))",
    )
    .bind(key_id)
    .execute(&mut *tx)
    .await?;
    }
    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}

/// Reorder keys globally: `ids` must list every key exactly once (full-list contract keeps the
/// single-global-ordering invariant intact); positions are assigned 0..n in array order.
pub async fn reorder_keys(pool: &PgPool, ids: &[i64]) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('gateway_provider_keys.position'))")
        .execute(&mut *tx)
        .await?;
    let existing: Vec<(i64,)> = sqlx::query_as("SELECT id FROM gateway_provider_keys")
        .fetch_all(&mut *tx)
        .await?;
    let existing: std::collections::HashSet<i64> = existing.into_iter().map(|(id,)| id).collect();
    let submitted: std::collections::HashSet<i64> = ids.iter().copied().collect();
    anyhow::ensure!(
        submitted.len() == ids.len(),
        "reorder list contains duplicate key ids"
    );
    anyhow::ensure!(
        submitted == existing,
        "reorder list must contain every key exactly once (got {}, expected {})",
        ids.len(),
        existing.len()
    );
    for (position, key_id) in ids.iter().enumerate() {
        sqlx::query("UPDATE gateway_provider_keys SET position = $2 WHERE id = $1")
            .bind(key_id)
            .bind(position as i32)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

// ---------- availability rules (route entry scheduling) ----------

/// One route entry: a key plus the upstream model it should serve. The same
/// key may appear several times (one entry per model); `label` is an optional
/// display name — clients and the GUI show the model id when it is unset.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RouteEntry {
    pub key_id: i64,
    pub model: String,
    #[serde(default)]
    pub label: Option<String>,
    /// Per-item concurrency cap inside this route (None = unlimited at the item
    /// level; the key-level cap still applies). Identity = (route, key, model).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<i64>,
    /// Ordered availability rules (first match wins, top to bottom). A matched
    /// rule's effect decides the entry; a NON-EMPTY list that matches nothing
    /// denies (a declared list means "only what a rule allows"), and an empty
    /// list means always available. Read-compatible with the legacy
    /// `active_window` field (see [`RouteEntry::rules`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<AvailabilityRule>,
    /// LEGACY single-window field, superseded by `rules`. Kept for reading
    /// rows written before rules existed; writes never emit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_window: Option<ActiveWindow>,
}

impl RouteEntry {
    /// The effective rule list: `rules` when present, otherwise the legacy
    /// `active_window` as one allow-rule (its exact old meaning). The result is
    /// borrowed; it never allocates.
    pub fn rules(&self) -> Vec<AvailabilityRule> {
        if !self.rules.is_empty() {
            self.rules.clone()
        } else if let Some(window) = &self.active_window {
            vec![AvailabilityRule {
                window: window.clone(),
                effect: RuleEffect::Allow,
            }]
        } else {
            Vec::new()
        }
    }

    /// Whether this entry is available at `now`: the first rule whose window
    /// contains `now` decides; an unmatched list with rules present is ALLOWED
    /// (every rule names a window it governs, so a moment no rule covers is the
    /// unrestricted default — a deny-only list cannot accidentally deny the
    /// whole day); no rules at all means always available.
    pub fn is_available(&self, now: chrono::DateTime<chrono::Local>) -> bool {
        let rules = self.rules();
        if rules.is_empty() {
            return true;
        }
        for rule in &rules {
            if rule.window.contains(now) {
                return rule.effect == RuleEffect::Allow;
            }
        }
        true
    }
}

/// One availability rule: when `window` covers the request moment, `effect`
/// applies. Rules are evaluated top to bottom; the first match wins and no
/// later rule is consulted.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AvailabilityRule {
    pub window: ActiveWindow,
    pub effect: RuleEffect,
}

/// What a matched rule does: `Allow` admits the entry, `Deny` skips it
/// (silently, never rested).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Deny,
}

/// A local-time active window for a route entry, `start`/`end` as "HH:MM".
/// `start > end` wraps across midnight ("22:00"–"06:00" = the night window).
/// `days` restricts the window to those ISO weekdays (1 = Monday … 7 =
/// Sunday), judged by the weekday OF THE REQUEST MOMENT (no carry-over from
/// a wrap start); absent/empty = every day.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ActiveWindow {
    pub start: String,
    pub end: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<u8>>,
}

impl ActiveWindow {
    fn parse_hhmm(text: &str) -> Option<chrono::NaiveTime> {
        chrono::NaiveTime::parse_from_str(text, "%H:%M").ok()
    }

    /// Persist-time validation: both ends must parse as HH:MM, and every
    /// declared day must be an ISO weekday (1..=7). `start == end` means "the
    /// whole day" — only meaningful with a day restriction (the GUI builds it
    /// for days-only entries); without `days` it is rejected (a window that
    /// always matches should just be absent).
    pub fn validate(&self) -> anyhow::Result<()> {
        let (Some(start), Some(end)) = (Self::parse_hhmm(&self.start), Self::parse_hhmm(&self.end))
        else {
            anyhow::bail!(
                "active window must be HH:MM (got {:?}–{:?})",
                self.start,
                self.end
            );
        };
        anyhow::ensure!(
            start != end || self.days.as_ref().is_some_and(|days| !days.is_empty()),
            "active window start and end must differ (unless days restrict it)"
        );
        if let Some(days) = &self.days {
            anyhow::ensure!(
                days.iter().all(|day| (1..=7).contains(day)),
                "active window days must be ISO weekdays 1..=7 (got {days:?})"
            );
        }
        Ok(())
    }

    /// Whether `now` is inside the window: the weekday test (when `days` is
    /// declared) uses the request moment's own weekday, and the time-of-day
    /// test is [start, end), wrapping across midnight when start > end —
    /// `start == end` covers the whole day (only storable with `days`). An
    /// unparseable stored window is treated as always-active (writes are
    /// validated; this is only defensive).
    pub fn contains(&self, now: chrono::DateTime<chrono::Local>) -> bool {
        if let Some(days) = &self.days
            && !days.is_empty()
            && !days.contains(
                &u8::try_from(chrono::Datelike::weekday(&now).number_from_monday()).unwrap_or(0),
            )
        {
            return false;
        }
        let (Some(start), Some(end)) = (Self::parse_hhmm(&self.start), Self::parse_hhmm(&self.end))
        else {
            return true;
        };
        if start == end {
            return true;
        }
        let time = now.time();
        if start < end {
            time >= start && time < end
        } else {
            time >= start || time < end
        }
    }
}

/// How a route picks among its entries at dispatch. `ordered` walks the
/// stored order (first live candidate wins — the only behaviour before
/// strategies existed); `smart` re-orders by quota snapshots (tier by max
/// window usage; the soonest renewal first) — see `relay::smart`.
/// Serialized snake_case on the wire; rows written before 0020 (and old
/// clients omitting the field) deserialize as [`RouteStrategy::Ordered`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStrategy {
    /// Dispatch walks entries in stored order, first live candidate wins.
    #[default]
    Ordered,
    /// Dispatch scores entries by health/latency and picks the best.
    Smart,
    /// Dispatch round-robins through ready candidates, ignoring quota/balance.
    Rotate,
}

impl RouteStrategy {
    /// The column spelling; kept in sync with the serde rename above.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ordered => "ordered",
            Self::Smart => "smart",
            Self::Rotate => "rotate",
        }
    }

    /// Parse the column spelling; unknown values fail loudly (same posture as
    /// undecodable entries JSON — a tampered row must not dispatch wrong).
    pub fn from_column(value: &str) -> anyhow::Result<Self> {
        match value {
            "ordered" => Ok(Self::Ordered),
            "smart" => Ok(Self::Smart),
            "rotate" => Ok(Self::Rotate),
            other => anyhow::bail!("unknown route strategy {other:?}"),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RouteRow {
    pub alias: String,
    pub entries: Vec<RouteEntry>,
    /// Declared context window in tokens; `None` = undeclared (/v1/models then
    /// derives it from the member keys' model snapshots when they all carry one).
    pub context_window: Option<i64>,
    /// Dispatch strategy; rows and clients predating 0020 default to `ordered`.
    #[serde(default)]
    pub strategy: RouteStrategy,
    /// Admin-facing display note (备注); `None` = unset. Never read by the
    /// relay resolution path — it exists for the GUI's route header only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// 路由层固定对外 effort 档位(规范名,升序):`None` = legacy 派生
    /// (/v1/models 走成员快照交集), `Some([])` = 显式无变体,
    /// `Some([..])` = 固定列表,数组顺序即展示顺序。写路径经
    /// [`crate::translation::ir::Effort::route_levels`] 归一化。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub efforts: Option<Vec<String>>,
}

/// One concurrency-limited key, joined with its provider name so UIs can read it directly.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct LimitedKeyRow {
    pub key_id: i64,
    pub provider_id: i64,
    pub provider_name: String,
    pub key_label: String,
    pub max_concurrency: i32,
}

/// Every key with a concurrency cap, ordered for display. Live occupancy is
/// not in the database — the caller fills it from the concurrency registry.
pub async fn list_limited_keys(pool: &PgPool) -> anyhow::Result<Vec<LimitedKeyRow>> {
    let rows = sqlx::query_as::<_, LimitedKeyRow>(
    "SELECT k.id AS key_id, k.provider_id, p.name AS provider_name, k.label AS key_label, k.max_concurrency
         FROM gateway_provider_keys k
         JOIN gateway_providers p ON p.id = k.provider_id
         WHERE k.max_concurrency IS NOT NULL
         ORDER BY p.name, k.label, k.id",
  )
  .fetch_all(pool)
  .await?;
    Ok(rows)
}

/// The per-key quota anchors the probe merges into vendor readings:
/// (key_id, monthly reset day-of-month in UTC). Keys without a configured
/// `monthly_reset_day` are absent — the chart simply stays resetless for them.
///
/// Column overrides live on `gateway_provider_keys.quota_overrides` and are
/// read straight from the JSON: the row struct stays narrow and this stays a
/// probe-only concern.
pub async fn list_quota_reset_anchors(
    pool: &PgPool,
) -> anyhow::Result<std::collections::HashMap<i64, u32>> {
    let rows: Vec<(i64, Option<i32>)> = sqlx::query_as(
        "SELECT id, (quota_overrides ->> 'monthly_reset_day')::int
         FROM gateway_provider_keys
         WHERE quota_overrides ? 'monthly_reset_day'",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, day)| {
            day.and_then(|day| u32::try_from(day).ok())
                .map(|day| (id, day))
        })
        .collect())
}
