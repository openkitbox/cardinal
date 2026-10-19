use std::path::Path;

use serde::Deserialize;

/// TLS termination for the gateway listener (optional): PEM cert/key paths.
#[derive(Debug, Clone, Deserialize)]
pub struct SslConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// The gateway's configuration, owned by the main program: it lives in the
/// `[gateway]` section of the cardinal config file (`~/.ox/config.toml`),
/// not in a gateway-specific file. Missing file/section → [`Config::default`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: String,
    /// Optional TLS termination for the gateway listener; omitted = plaintext.
    pub ssl: Option<SslConfig>,
    pub sql_dsn: String,
    pub gateway_key: String,
    /// Allow non-loopback access to the admin API (`/api/*`). Off by default:
    /// the management surface is loopback-only. Set to `true` when the gateway
    /// is deployed remotely and the GUI connects from another machine.
    pub admin_remote: bool,
    /// Development mode: allow plaintext loopback upstreams and unusual ports (for local mock upstreams).
    pub allow_insecure_upstream: bool,
    /// Mirror request/response payloads into the log (target `gateway::payload`,
    /// truncated at 256 KiB per body). Off by default: payloads contain user
    /// conversations. Silence the target via RUST_LOG (`gateway::payload=off`)
    /// even when on. A relay behavior flag — the logging subscriber itself is
    /// the `cardinal-gateway` binary's `[log]` section.
    pub payloads: bool,
    /// How many days of `~/.ox/payloads` captures to keep (default 7; `0` keeps
    /// them all). The capture is a diagnostic aid, not an archive, and it holds
    /// user conversations: an unbounded one grows into a permanent local
    /// transcript. Swept at startup and hourly, same as the log sink.
    /// Ignored when `payloads` is off.
    #[serde(default = "default_payload_retain_days")]
    pub payload_retain_days: u64,
    /// Provider declarations idempotently written to the DB at startup (name is the primary key; config is the source of truth).
    /// Keys and routes are NOT seeded — they are managed at runtime via the admin API / GUI.
    pub providers: Vec<ProviderSeed>,
    /// Model price table (USD per million tokens; config is the source of truth). Models without a price are not charged.
    pub prices: Vec<ModelPriceSeed>,
    /// How long a dispatch queues on a saturated key before failing over to the
    /// next candidate (seconds; default 30). A saturated single-key provider
    /// with a tight client deadline wants this larger; see also the
    /// transport's `opening` for the upstream-first-byte patience.
    pub queue_timeout_secs: Option<u64>,
}

impl Default for Config {
    /// Defaults for the embedded relay: loopback listener aligned with the
    /// engine's default `[model].gateway_url`, the shared database URL, and a
    /// seed key that loopback callers don't even need (loopback is trusted).
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8787".to_string(),
            ssl: None,
            sql_dsn: crate::db::DEFAULT_DATABASE_URL.to_string(),
            gateway_key: "cardinal".to_string(),
            admin_remote: false,
            allow_insecure_upstream: false,
            payloads: false,
            payload_retain_days: default_payload_retain_days(),
            providers: Vec::new(),
            prices: Vec::new(),
            queue_timeout_secs: None,
        }
    }
}

/// Model price declaration in the main config's `[gateway.prices]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelPriceSeed {
    /// Upstream model id (matches the served model written to gateway_requests).
    pub model: String,
    /// Scope the price to the seeded provider with this name (a relay marking
    /// the model up gets its own row); omitted = the global row every provider
    /// falls back to.
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub input_usd: f64,
    #[serde(default)]
    pub output_usd: f64,
    #[serde(default)]
    pub cache_read_usd: f64,
    #[serde(default)]
    pub cache_write_usd: f64,
    /// The 1-hour cache-write price (Anthropic); omitted bills writes at the
    /// 5-minute price, except a Claude model's is defaulted to 2x input.
    #[serde(default)]
    pub cache_write_1h_usd: Option<f64>,
    /// Volume tiers ascending by `above`: a request
    /// whose prompt total passes a tier bills whole at that tier's prices.
    #[serde(default)]
    pub tiers: Vec<PriceTierSeed>,
}

/// One volume tier of a [`ModelPriceSeed`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PriceTierSeed {
    /// The prompt total the tier starts strictly above.
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

/// Provider declaration in the main config's `[gateway.providers]` table. A
/// provider is only a protocol + endpoint (+ auth scheme); credentials live
/// exclusively in `gateway_provider_keys`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderSeed {
    /// Unique name; also the direct-addressing prefix (clients may call "<name>/<upstream model>").
    pub name: String,
    pub protocol: String,
    pub base_url: String,
    /// Inferred from the protocol when omitted (anthropic_messages → x_api_key, otherwise bearer).
    pub auth_scheme: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// A week: long enough to debug last week's traffic, short enough that the
/// capture does not become a permanent local transcript.
fn default_payload_retain_days() -> u64 {
    7
}

impl Config {
    /// Read the `[gateway]` section of the main config file at `path`
    /// (`~/.ox/config.toml`). A missing file or a missing section yields the
    /// embedded defaults — the gateway runs out of the box.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        /// Extraction view: everything outside `[gateway]` belongs to other
        /// sections of the main config and is ignored here.
        #[derive(Deserialize)]
        struct MainConfig {
            gateway: Option<Config>,
        }

        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to read config {}: {error}",
                    path.display()
                ));
            }
        };
        let main: MainConfig = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;
        Ok(main.gateway.unwrap_or_default())
    }
}
