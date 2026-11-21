use std::path::Path;

use crate::upstream::Dns;
use crate::xiaodou_pay::{PlatformKeys, SigningKey};
use secrecy::SecretString;
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
    /// truncated at 64 KiB per body). Off by default: payloads contain user
    /// conversations. Silence the target via RUST_LOG (`gateway::payload=off`)
    /// even when on. A relay behavior flag — the logging subscriber itself is
    /// the `cardinal-gateway` binary's `[log]` section.
    pub payloads: bool,
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
    pub portal: PortalConfig,
    /// Deployment-level online-payment settings. The RSA private key is never
    /// read from this file; it is injected from the environment on load.
    pub payments: PaymentsConfig,
}

/// Deployment-level portal settings retained in the config file. Runtime
/// secrets and mail transport live in the database; only the BFF shared secret
/// and the default registration group remain here as deployment policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PortalConfig {
    pub default_customer_group: Option<String>,
    /// Shared secret presented by the browser-facing frontend. Stored as a
    /// digest in the runtime snapshot; never returned by an API.
    pub bff_secret: Option<String>,
}

/// Online payment providers enabled by deployment configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PaymentsConfig {
    /// `None` means online payments are disabled (fail closed).
    pub xiaodou: Option<XiaodouConfig>,
}

/// `[gateway.payments.xiaodou]`: public configuration only. The private key
/// is attached by [`XiaodouConfig::with_private_key`] at load time and has a
/// redacted `Debug` representation.
#[derive(Debug, Clone, Deserialize)]
pub struct XiaodouConfig {
    pub base_url: String,
    pub app_id: String,
    pub merchant_kid: String,
    pub channel: String,
    pub trade_scope: String,
    pub notify_url: String,
    pub return_url: String,
    pub usd_micros_per_cny_fen: u64,
    pub time_expire_seconds: u64,
    pub fee_bearer: String,
    /// Platform signature keys, keyed by the kid carried on responses/events.
    pub platform_keys: std::collections::HashMap<String, PlatformKeyConfig>,
    #[serde(skip)]
    private_key: Option<SecretString>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlatformKeyConfig {
    pub pem: String,
    pub fingerprint: String,
}

impl XiaodouConfig {
    /// Validate the section and attach the key injected from
    /// `CARDINAL_XIAODOU_PRIVATE_KEY`. Missing or invalid input fails closed.
    pub fn with_private_key(mut self, private_key: Option<&str>) -> anyhow::Result<Self> {
        self.validate()?;
        let private_key = private_key.ok_or_else(|| {
            anyhow::anyhow!(
                "CARDINAL_XIAODOU_PRIVATE_KEY is required when payments.xiaodou is configured"
            )
        })?;
        SigningKey::from_pem(private_key).map_err(|_| {
            anyhow::anyhow!("CARDINAL_XIAODOU_PRIVATE_KEY is not a valid RSA private key")
        })?;
        self.private_key = Some(SecretString::from(private_key.to_owned()));
        Ok(self)
    }

    pub fn private_key(&self) -> Option<&SecretString> {
        self.private_key.as_ref()
    }

    pub fn platform_keys(&self) -> anyhow::Result<PlatformKeys> {
        let entries = self
            .platform_keys
            .iter()
            .map(|(kid, key)| (kid.as_str(), key.pem.as_str(), key.fingerprint.as_str()));
        PlatformKeys::from_entries(entries).map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            valid_https_url(&self.base_url),
            "payments.xiaodou.base_url must be an absolute https URL"
        );
        anyhow::ensure!(
            self.app_id
                .strip_prefix("xdop_")
                .is_some_and(|suffix| suffix.len() == 16
                    && suffix.bytes().all(|b| b.is_ascii_alphanumeric())),
            "payments.xiaodou.app_id must be xdop_ followed by 16 alphanumerics"
        );
        anyhow::ensure!(
            !self.merchant_kid.is_empty() && self.merchant_kid.len() <= 128,
            "payments.xiaodou.merchant_kid must be 1-128 characters"
        );
        anyhow::ensure!(
            self.channel == "ALIPAY_H5",
            "payments.xiaodou.channel must be ALIPAY_H5"
        );
        anyhow::ensure!(
            matches!(
                self.trade_scope.as_str(),
                "PHYSICAL_FACE_TO_FACE" | "CARD_VIRTUAL"
            ),
            "payments.xiaodou.trade_scope must be a declared Xiaodou trade scope"
        );
        anyhow::ensure!(
            valid_https_url(&self.notify_url)
                && !self.notify_url.contains(['?', '#'])
                && !notify_path(&self.notify_url).is_empty(),
            "payments.xiaodou.notify_url must be an absolute https URL with a non-root path and no query/fragment"
        );
        anyhow::ensure!(
            valid_https_url(&self.return_url) && !self.return_url.contains(['?', '#']),
            "payments.xiaodou.return_url must be an absolute https URL without query/fragment"
        );
        anyhow::ensure!(
            self.usd_micros_per_cny_fen > 0,
            "payments.xiaodou.usd_micros_per_cny_fen must be positive"
        );
        anyhow::ensure!(
            (300..=86400).contains(&self.time_expire_seconds),
            "payments.xiaodou.time_expire_seconds must be 300-86400"
        );
        anyhow::ensure!(
            self.fee_bearer == "SELLER",
            "payments.xiaodou.fee_bearer must be SELLER"
        );
        anyhow::ensure!(
            !self.platform_keys.is_empty(),
            "payments.xiaodou.platform_keys must contain at least one key"
        );
        self.platform_keys()?;
        Ok(())
    }
}

fn valid_https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty() && !authority.contains(['@', ' '])
}

fn notify_path(url: &str) -> &str {
    url.strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, path)| path)
        .unwrap_or_default()
}

/// Mail transport shape still used by the HTTP mailer. Its values are read
/// from `portal_settings` at startup and on reload, not from the config file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PortalMailConfig {
    pub url: String,
    pub token: String,
    pub from: String,
    pub origin: String,
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
            providers: Vec::new(),
            prices: Vec::new(),
            queue_timeout_secs: None,
            portal: PortalConfig::default(),
            payments: PaymentsConfig::default(),
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
    #[serde(default)]
    pub dns: Dns,
    /// Inferred from the protocol when omitted (anthropic_messages → x_api_key, otherwise bearer).
    pub auth_scheme: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Read the `[gateway]` section of the main config file at `path`
    /// (`~/.ox/config.toml`). A missing file or a missing section yields the
    /// embedded defaults — the gateway runs out of the box.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let private_key = match std::env::var_os("CARDINAL_XIAODOU_PRIVATE_KEY") {
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("CARDINAL_XIAODOU_PRIVATE_KEY must be UTF-8"))?,
            ),
            None => None,
        };
        Self::load_with_private_key(path, private_key.as_deref())
    }

    /// Same as [`Config::load`], with the private key supplied by the caller.
    /// Keeping the injection point explicit makes startup behavior testable
    /// without mutating process-global environment variables.
    pub fn load_with_private_key(path: &Path, private_key: Option<&str>) -> anyhow::Result<Self> {
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
        let mut config = main.gateway.unwrap_or_default();
        if let Some(xiaodou) = config.payments.xiaodou.take() {
            config.payments.xiaodou = Some(xiaodou.with_private_key(private_key)?);
        }
        Ok(config)
    }
}
