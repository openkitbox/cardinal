use sqlx::PgPool;

use crate::protocol::ProtocolId;

use crate::config::{ModelPriceSeed, ProviderSeed};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct ProviderRow {
    pub id: i64,
    pub name: String,
    pub protocol: String,
    pub base_url: String,
    pub auth_scheme: String,
    pub enabled: bool,
}

/// Auth scheme inferred from the protocol when a declaration omits it.
/// Also consumed by the GUI's provider editor — keep it the single source.
pub fn default_auth_scheme(protocol: &str) -> &'static str {
    match protocol {
        "anthropic_messages" => "x_api_key",
        "gemini" => "x_goog_api_key",
        _ => "bearer",
    }
}

pub async fn list_providers(pool: &PgPool) -> anyhow::Result<Vec<ProviderRow>> {
    let rows =
    sqlx::query_as::<_, ProviderRow>("SELECT id, name, protocol, base_url, auth_scheme, enabled FROM gateway_providers ORDER BY id")
      .fetch_all(pool)
      .await?;
    Ok(rows)
}

pub async fn get_provider(pool: &PgPool, id: i64) -> anyhow::Result<Option<ProviderRow>> {
    let row =
    sqlx::query_as::<_, ProviderRow>("SELECT id, name, protocol, base_url, auth_scheme, enabled FROM gateway_providers WHERE id = $1")
      .bind(id)
      .fetch_optional(pool)
      .await?;
    Ok(row)
}

/// Direct-addressing lookup: the prefix of a "<name>/<model>" client model string.
pub async fn get_provider_by_name(
    pool: &PgPool,
    name: &str,
) -> anyhow::Result<Option<ProviderRow>> {
    let row =
    sqlx::query_as::<_, ProviderRow>("SELECT id, name, protocol, base_url, auth_scheme, enabled FROM gateway_providers WHERE name = $1")
      .bind(name)
      .fetch_optional(pool)
      .await?;
    Ok(row)
}

#[derive(Debug)]
pub struct ProviderInput<'a> {
    pub name: &'a str,
    pub protocol: &'a str,
    pub base_url: &'a str,
    pub auth_scheme: Option<&'a str>,
    pub enabled: bool,
}

impl ProviderInput<'_> {
    pub fn resolved_auth_scheme(&self) -> &str {
        self.auth_scheme
            .unwrap_or_else(|| default_auth_scheme(self.protocol))
    }
}

/// provider names are direct-address prefixes ("<name>/<model>"), so they must not contain '/'.
fn validate_provider_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.is_empty(), "provider name must not be empty");
    anyhow::ensure!(
        !name.contains('/'),
        "provider name must not contain '/' (it is the direct-address prefix)"
    );
    Ok(())
}

pub async fn insert_provider(pool: &PgPool, input: &ProviderInput<'_>) -> anyhow::Result<i64> {
    validate_provider_name(input.name)?;
    let id: (i64,) = sqlx::query_as(
        "INSERT INTO gateway_providers (name, protocol, base_url, auth_scheme, enabled)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(input.name)
    .bind(input.protocol)
    .bind(input.base_url)
    .bind(input.resolved_auth_scheme())
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;
    Ok(id.0)
}

/// Idempotent create keyed by the unique name: returns the existing row's id
/// when the name is taken (`ON CONFLICT DO NOTHING` + re-select keeps it
/// race-safe without error-string sniffing). The existing row's endpoint is
/// NOT clobbered — the name is the identity, the caller's endpoint only
/// applies to a genuinely new row. A same-name row pointing at a DIFFERENT
/// base_url is an error, not a silent reuse: the two entries mean different
/// upstreams and must coexist under distinct names (e.g. region variants).
pub async fn find_or_create_provider(
    pool: &PgPool,
    input: &ProviderInput<'_>,
) -> anyhow::Result<i64> {
    validate_provider_name(input.name)?;
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO gateway_providers (name, protocol, base_url, auth_scheme, enabled)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (name) DO NOTHING
         RETURNING id",
    )
    .bind(input.name)
    .bind(input.protocol)
    .bind(input.base_url)
    .bind(input.resolved_auth_scheme())
    .bind(input.enabled)
    .fetch_optional(pool)
    .await?;
    if let Some((id,)) = inserted {
        return Ok(id);
    }
    let existing = get_provider_by_name(pool, input.name).await?;
    let Some(row) = existing else {
        anyhow::bail!(
            "provider {} vanished between insert conflict and re-select",
            input.name
        )
    };
    // Compare on the trimmed form: a trailing slash is semantically identical
    // (capabilities trim it before appending the protocol leaf) and must not
    // trip the drift guard.
    anyhow::ensure!(
        row.base_url.trim_end_matches('/') == input.base_url.trim_end_matches('/'),
        "provider '{}' 已存在且指向 {}（与当前选择 {} 不同）——如需并存请用另一区域的入口",
        input.name,
        row.base_url,
        input.base_url
    );
    Ok(row.id)
}

/// Replace a provider's endpoint config. Errors when the id does not exist.
pub async fn update_provider(
    pool: &PgPool,
    id: i64,
    input: &ProviderInput<'_>,
) -> anyhow::Result<bool> {
    validate_provider_name(input.name)?;
    let result =
    sqlx::query("UPDATE gateway_providers SET name = $2, protocol = $3, base_url = $4, auth_scheme = $5, enabled = $6 WHERE id = $1")
      .bind(id)
      .bind(input.name)
      .bind(input.protocol)
      .bind(input.base_url)
      .bind(input.resolved_auth_scheme())
      .bind(input.enabled)
      .execute(pool)
      .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn set_provider_enabled(pool: &PgPool, id: i64, enabled: bool) -> anyhow::Result<bool> {
    let result = sqlx::query("UPDATE gateway_providers SET enabled = $2 WHERE id = $1")
        .bind(id)
        .bind(enabled)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProviderDeleteOutcome {
    Missing,
    Deleted { kiro_key_ids: Vec<i64> },
}

#[derive(Debug, PartialEq, Eq)]
pub enum EmptyProviderDeleteOutcome {
    Missing,
    HasKeys,
    Deleted,
}

pub async fn delete_provider(pool: &PgPool, id: i64) -> anyhow::Result<ProviderDeleteOutcome> {
    let mut tx = pool.begin().await?;
    let provider: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM gateway_providers WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if provider.is_none() {
        tx.rollback().await?;
        return Ok(ProviderDeleteOutcome::Missing);
    }
    let keys: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, auth_kind FROM gateway_provider_keys WHERE provider_id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let key_ids: Vec<i64> = keys
        .iter()
        .filter(|(_, auth_kind)| auth_kind == "kiro_oidc")
        .map(|(key_id, _)| *key_id)
        .collect();
    let all_key_ids: Vec<i64> = keys.into_iter().map(|(key_id, _)| key_id).collect();
    if !all_key_ids.is_empty() {
        sqlx::query(
            "UPDATE gateway_routes
             SET entries = COALESCE(
                 (SELECT jsonb_agg(entry) FROM jsonb_array_elements(entries) AS entry
                  WHERE NOT ((entry->>'key_id')::bigint = ANY($1))),
                 '[]'::jsonb)
             WHERE EXISTS (
                 SELECT 1 FROM jsonb_array_elements(entries) AS entry
                 WHERE (entry->>'key_id')::bigint = ANY($1))",
        )
        .bind(&all_key_ids)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM gateway_providers WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ProviderDeleteOutcome::Deleted {
        kiro_key_ids: key_ids,
    })
}

/// Delete a provider only while it has no keys. The predicate is part of the
/// DELETE so a concurrent key insert cannot turn this into an orphaning race.
pub async fn delete_provider_if_empty(
    pool: &PgPool,
    id: i64,
) -> anyhow::Result<EmptyProviderDeleteOutcome> {
    let mut tx = pool.begin().await?;
    let provider: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM gateway_providers WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(_) = provider else {
        tx.rollback().await?;
        return Ok(EmptyProviderDeleteOutcome::Missing);
    };
    let keys: Vec<(i64,)> =
        sqlx::query_as("SELECT id FROM gateway_provider_keys WHERE provider_id = $1")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    if !keys.is_empty() {
        tx.rollback().await?;
        return Ok(EmptyProviderDeleteOutcome::HasKeys);
    }
    sqlx::query("DELETE FROM gateway_providers WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(EmptyProviderDeleteOutcome::Deleted)
}

pub async fn list_providers_by_ids(pool: &PgPool, ids: &[i64]) -> anyhow::Result<Vec<ProviderRow>> {
    let rows = sqlx::query_as::<_, ProviderRow>(
    "SELECT id, name, protocol, base_url, auth_scheme, enabled FROM gateway_providers WHERE id = ANY($1) ORDER BY id",
  )
  .bind(ids)
  .fetch_all(pool)
  .await?;
    Ok(rows)
}

/// Startup seeding: idempotently write the providers declared in the config into the database.
///
/// name is the primary key and config is the source of truth — existing same-name rows are overwritten,
/// rows with different names created manually via the admin API are unaffected.
/// Keys and routes are NOT seeded: they are runtime state managed via the admin API / GUI.
pub async fn seed_from_config(
    pool: &PgPool,
    providers: &[ProviderSeed],
    prices: &[ModelPriceSeed],
) -> anyhow::Result<()> {
    for p in providers {
        anyhow::ensure!(
            ProtocolId::parse(&p.protocol).is_some(),
            "config provider {} has an invalid protocol: {}",
            p.name,
            p.protocol
        );
        let auth_scheme = p
            .auth_scheme
            .as_deref()
            .unwrap_or_else(|| default_auth_scheme(&p.protocol));
        sqlx::query(
            "INSERT INTO gateway_providers (name, protocol, base_url, auth_scheme, enabled)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (name) DO UPDATE SET
               protocol = EXCLUDED.protocol, base_url = EXCLUDED.base_url,
               auth_scheme = EXCLUDED.auth_scheme, enabled = EXCLUDED.enabled",
        )
        .bind(&p.name)
        .bind(&p.protocol)
        .bind(&p.base_url)
        .bind(auth_scheme)
        .bind(p.enabled)
        .execute(pool)
        .await?;
    }
    for price in prices {
        let provider_id = match &price.provider {
            // Config is the truth source: a price naming a provider the seed
            // doesn't define is a typo, and starting with it would silently
            // price nothing.
            Some(name) => {
                let id: Option<i64> =
                    sqlx::query_scalar("SELECT id FROM gateway_providers WHERE name = $1")
                        .bind(name)
                        .fetch_optional(pool)
                        .await?;
                anyhow::ensure!(
                    id.is_some(),
                    "config price {} names provider {name}, which the seed does not define",
                    price.model
                );
                id.unwrap()
            }
            None => 0,
        };
        let tiers = if price.tiers.is_empty() {
            None
        } else {
            Some(serde_json::to_value(&price.tiers)?)
        };
        sqlx::query(
      "INSERT INTO gateway_model_prices (provider_id, model, input_usd, output_usd, cache_read_usd, cache_write_usd, cache_write_1h_usd, tiers, source)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'manual')
             ON CONFLICT (provider_id, model) DO UPDATE SET
               input_usd = EXCLUDED.input_usd, output_usd = EXCLUDED.output_usd,
               cache_read_usd = EXCLUDED.cache_read_usd, cache_write_usd = EXCLUDED.cache_write_usd,
               cache_write_1h_usd = EXCLUDED.cache_write_1h_usd, tiers = EXCLUDED.tiers,
               source = 'manual', updated_at = now()",
    )
    .bind(provider_id)
    .bind(&price.model)
    .bind(price.input_usd)
    .bind(price.output_usd)
    .bind(price.cache_read_usd)
    .bind(price.cache_write_usd)
    .bind(price.cache_write_1h_usd)
    .bind(tiers)
    .execute(pool)
    .await?;
    }
    Ok(())
}
