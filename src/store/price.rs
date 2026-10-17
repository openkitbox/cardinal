use sqlx::PgPool;

/// One volume tier: a request whose prompt total is
/// strictly above `above` bills whole at the tier's unit prices.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PriceTier {
    pub above: i64,
    #[serde(default)]
    pub input_usd: f64,
    #[serde(default)]
    pub output_usd: f64,
    #[serde(default)]
    pub cache_read_usd: f64,
    #[serde(default)]
    pub cache_write_usd: f64,
    #[serde(default)]
    pub cache_write_1h_usd: Option<f64>,
}

/// The flat unit prices one request bills at.
#[derive(Clone, Copy)]
struct UnitPrices {
    input: f64,
    output: f64,
    cache_read: f64,
    cache_write: f64,
    cache_write_1h: Option<f64>,
}

/// Price per million tokens (USD) — flat unit prices plus optional volume
/// tiers. A request's cost comes from
/// [`ModelPrice::cost_split`].
#[derive(Clone, Debug)]
pub struct ModelPrice {
    pub input_usd: f64,
    pub output_usd: f64,
    pub cache_read_usd: f64,
    pub cache_write_usd: f64,
    /// The 1-hour cache-write price; `None` bills the whole write at the
    /// 5-minute price. A Claude model's missing one is
    /// defaulted to 2x input at load time (Anthropic
    /// bills the 1-hour TTL at 2x the 5-minute one for every model).
    pub cache_write_1h_usd: Option<f64>,
    /// Volume tiers ascending by `above`; empty = flat pricing.
    pub tiers: Vec<PriceTier>,
}

impl ModelPrice {
    /// The request bills whole at the unit prices of the
    /// highest tier its prompt total passes (OpenAI counts a request's input
    /// with its cached tokens in it, and the tier is chosen on that total),
    /// then per bucket — non-cached input, output, cache read, and the cache
    /// write split into its 1-hour and 5-minute parts. `input_tokens` is the
    /// kernel-normalized prompt total (cached and written tokens included).
    /// Reasoning tokens bill as output with every vendor and are already
    /// inside the output count.
    pub fn cost_split(
        &self,
        input_tokens: i64,
        output_tokens: i64,
        cached_input: i64,
        cache_write: i64,
        cache_write_1h: i64,
    ) -> f64 {
        let prompt = input_tokens.max(0);
        let unit = self.at(prompt);
        // The buckets partition the prompt (the kernels normalize them mutually
        // exclusive; nonsense input clamps without double-counting): the read
        // takes what it can of the prompt, the write takes what is left, the
        // rest is non-cached input.
        let read = cached_input.clamp(0, prompt);
        let written = cache_write.clamp(0, prompt - read);
        let write_1h = cache_write_1h.clamp(0, written) as f64;
        let one_hour = unit.cache_write_1h.unwrap_or(unit.cache_write);
        let non_cached = (prompt - read - written) as f64;
        (non_cached * unit.input
            + output_tokens.max(0) as f64 * unit.output
            + read as f64 * unit.cache_read
            + (written as f64 - write_1h) * unit.cache_write
            + write_1h * one_hour)
            / 1_000_000.0
    }

    /// The flat unit prices a request with this prompt total
    /// bills at — of the highest tier it is over, else the base price.
    fn at(&self, prompt: i64) -> UnitPrices {
        let mut flat = UnitPrices {
            input: self.input_usd,
            output: self.output_usd,
            cache_read: self.cache_read_usd,
            cache_write: self.cache_write_usd,
            cache_write_1h: self.cache_write_1h_usd,
        };
        for tier in &self.tiers {
            if prompt > tier.above {
                flat = UnitPrices {
                    input: tier.input_usd,
                    output: tier.output_usd,
                    cache_read: tier.cache_read_usd,
                    cache_write: tier.cache_write_usd,
                    cache_write_1h: tier.cache_write_1h_usd,
                };
            }
        }
        flat
    }
}

/// A Claude model whose 1-hour cache-write price was
/// left out gets 2x input — Anthropic bills the 1-hour TTL at 2x the
/// 5-minute one for every model it prices a 5-minute write on.
fn claude_one_hour_default(model: &str, input_usd: f64, cache_write_usd: f64) -> Option<f64> {
    if cache_write_usd > 0.0 && model.to_ascii_lowercase().contains("claude") {
        Some(2.0 * input_usd)
    } else {
        None
    }
}

type PriceRow = (f64, f64, f64, f64, Option<f64>, Option<String>);

async fn load_price_row(
    pool: &PgPool,
    provider_id: i64,
    model: &str,
) -> anyhow::Result<Option<PriceRow>> {
    Ok(
    sqlx::query_as::<_, PriceRow>(
      "SELECT input_usd::float8, output_usd::float8, cache_read_usd::float8, cache_write_usd::float8,
            cache_write_1h_usd::float8, tiers::text
         FROM gateway_model_prices WHERE provider_id = $1 AND model = $2",
    )
    .bind(provider_id)
    .bind(model)
    .fetch_optional(pool)
    .await?,
  )
}

fn parse_price_row(model: &str, row: PriceRow) -> anyhow::Result<ModelPrice> {
    let (input_usd, output_usd, cache_read_usd, cache_write_usd, cache_write_1h_usd, tiers) = row;
    let tiers = match tiers {
        Some(json) => serde_json::from_str::<Vec<PriceTier>>(&json)?,
        None => Vec::new(),
    };
    Ok(ModelPrice {
        input_usd,
        output_usd,
        cache_read_usd,
        cache_write_usd,
        cache_write_1h_usd: cache_write_1h_usd
            .or_else(|| claude_one_hour_default(model, input_usd, cache_write_usd)),
        tiers,
    })
}

/// The effective price for a call to `model` through provider `provider_id`:
/// the provider-scoped row when one exists, else the global row (a relay
/// marking a model up gets its own row, everyone else shares the flat one).
pub async fn get_price(
    pool: &PgPool,
    provider_id: i64,
    model: &str,
) -> anyhow::Result<Option<ModelPrice>> {
    if let Some(row) = load_price_row(pool, provider_id, model).await? {
        return parse_price_row(model, row).map(Some);
    }
    match load_price_row(pool, 0, model).await? {
        Some(row) => parse_price_row(model, row).map(Some),
        None => Ok(None),
    }
}

/// Catalog sync write (prices.rs): fill or refresh the GLOBAL row for a
/// model, but only when no manual price owns it — a config-seeded price is
/// the user's word and always beats the catalog.
/// Flat prices only: models.dev lists no tiers.
pub async fn upsert_catalog_price(
    pool: &PgPool,
    model: &str,
    input_usd: f64,
    output_usd: f64,
    cache_read_usd: f64,
    cache_write_usd: f64,
) -> anyhow::Result<()> {
    sqlx::query(
    "INSERT INTO gateway_model_prices (provider_id, model, input_usd, output_usd, cache_read_usd, cache_write_usd, source)
           VALUES (0, $1, $2, $3, $4, $5, 'catalog')
           ON CONFLICT (provider_id, model) DO UPDATE SET
             input_usd = EXCLUDED.input_usd, output_usd = EXCLUDED.output_usd,
             cache_read_usd = EXCLUDED.cache_read_usd, cache_write_usd = EXCLUDED.cache_write_usd,
             cache_write_1h_usd = NULL, tiers = NULL,
             updated_at = now()
           WHERE gateway_model_prices.source = 'catalog'",
  )
  .bind(model)
  .bind(input_usd)
  .bind(output_usd)
  .bind(cache_read_usd)
  .bind(cache_write_usd)
  .execute(pool)
  .await?;
    Ok(())
}

/// The models worth pricing from the catalog: everything actually served
/// recently (so a new upstream model gets priced after its first call) plus
/// every model holding a catalog row (so its price stays fresh). Manual rows
/// are excluded nowhere — the upsert itself refuses to touch them.
pub async fn served_models_for_pricing(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let models = sqlx::query_scalar(
        "SELECT model FROM gateway_model_prices WHERE source = 'catalog'
           UNION
           SELECT DISTINCT served_model FROM gateway_requests
           WHERE served_model IS NOT NULL AND served_model <> ''
             AND ts > now() - interval '30 days'",
    )
    .fetch_all(pool)
    .await?;
    Ok(models)
}

/// Latest successful request time per (key, served model), for the routes
/// stage's "上次成功" marker on idle entries.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct ModelSuccessRow {
    pub key_id: i64,
    pub served_model: String,
    pub last_ok: chrono::DateTime<chrono::Utc>,
}

/// Latest successful request time grouped by (key, served model) over the
/// last 30 days (matching the other ledger reads' window).
pub async fn last_model_success(pool: &PgPool) -> anyhow::Result<Vec<ModelSuccessRow>> {
    let rows = sqlx::query_as::<_, ModelSuccessRow>(
    "SELECT provider_key_id AS key_id, served_model, MAX(ts) AS last_ok
         FROM gateway_requests
         WHERE error IS NULL AND provider_key_id IS NOT NULL AND served_model IS NOT NULL AND served_model <> ''
           AND ts > now() - interval '30 days'
         GROUP BY provider_key_id, served_model",
  )
  .fetch_all(pool)
  .await?;
    Ok(rows)
}
