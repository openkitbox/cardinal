//! Agent wiring: register beaver into each agent's private-format config file.
//!
//! The LLM protocol side is standard — every agent sends OpenAI-compatible requests
//! to beaver's `/v1/chat/completions`; there is no protocol code here. The only per-agent difference is
//! the config file's path, format, and provider-node schema.
//!
//! Shared mechanics: back up (`*.beaver-bak`, refuse if it already exists) → merge the beaver node →
//! atomically replace via `*.tmp` + rename; disconnect restores byte-for-byte from the backup. YAML and JSON
//! are both handled through `serde_json::Value` (serde_yaml converts losslessly to and from JSON Value).

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde_json::{Map, Value};

/// beaver's node name in each agent's config.
const PROVIDER_ID: &str = "beaver";
const BACKUP_SUFFIX: &str = ".beaver-bak";

/// Default context/output window for omp model entries (users can edit it manually in models.yml).
const OMP_DEFAULT_CONTEXT_WINDOW: i64 = 128_000;
const OMP_DEFAULT_MAX_TOKENS: i64 = 8_192;

/// Agents supported for wiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Opencode,
    Omp,
}

impl Agent {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "opencode" => Some(Self::Opencode),
            "omp" => Some(Self::Omp),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Opencode => "opencode",
            Self::Omp => "omp",
        }
    }

    /// Default config file path; None means HOME is missing.
    pub fn default_path(self) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        Some(match self {
            Self::Opencode => home.join(".config/opencode/opencode.json"),
            Self::Omp => home.join(".omp/agent/models.yml"),
        })
    }

    fn format(self) -> Format {
        match self {
            Self::Opencode => Format::Json,
            Self::Omp => Format::Yaml,
        }
    }

    /// Top-level key holding the provider table ("provider" / "providers").
    fn providers_key(self) -> &'static str {
        match self {
            Self::Opencode => "provider",
            Self::Omp => "providers",
        }
    }

    /// Build beaver's provider node (the schema differs per agent).
    fn provider_node(self, input: &ConnectInput<'_>) -> Value {
        let base_url = format!("http://{}/v1", input.listen_addr);
        match self {
            Self::Opencode => {
                let mut models = Map::new();
                for alias in &input.models {
                    models.insert(alias.clone(), serde_json::json!({ "name": alias }));
                }
                serde_json::json!({
                    "name": "beaver",
                    "npm": "@ai-sdk/openai-compatible",
                    "options": {
                        "apiKey": input.gateway_key,
                        "baseURL": base_url,
                    },
                    "models": Value::Object(models),
                })
            }
            Self::Omp => {
                let models: Vec<Value> = input
                    .models
                    .iter()
                    .map(|alias| {
                        serde_json::json!({
                            "id": alias,
                            "name": alias,
                            "contextWindow": OMP_DEFAULT_CONTEXT_WINDOW,
                            "maxTokens": OMP_DEFAULT_MAX_TOKENS,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "baseUrl": base_url,
                    "api": "openai-completions",
                    "apiKey": input.gateway_key,
                    "models": models,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Format {
    Json,
    Yaml,
}

impl Format {
    fn read(self, path: &Path) -> anyhow::Result<Value> {
        if !path.exists() {
            return Ok(Value::Object(Map::new()));
        }
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(match self {
            Self::Json => {
                serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?
            }
            // serde_yaml can deserialize into serde_json::Value (lossless for the pure YAML 1.2 subset).
            Self::Yaml => {
                serde_yaml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?
            }
        })
    }

    fn write(self, path: &Path, value: &Value) -> anyhow::Result<()> {
        let tmp = path.with_extension("tmp");
        let body = match self {
            Self::Json => serde_json::to_string_pretty(value)?,
            Self::Yaml => serde_yaml::to_string(value)?,
        };
        std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))
    }
}

/// Connection parameters.
pub struct ConnectInput<'a> {
    pub listen_addr: &'a str,
    pub gateway_key: &'a str,
    /// Route aliases exposed to each agent as its model ids.
    pub models: Vec<String>,
}

fn backup_path(config: &Path) -> PathBuf {
    let name = config
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    config.with_file_name(format!("{name}{BACKUP_SUFFIX}"))
}

/// Connect: back up → merge the beaver node → atomic write.
pub fn connect_at(
    agent: Agent,
    config_path: &Path,
    input: &ConnectInput<'_>,
) -> anyhow::Result<()> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let backup = backup_path(config_path);
    if backup.exists() {
        bail!(
            "backup {} already exists; disconnect before connecting again",
            backup.display()
        );
    }
    if config_path.exists() {
        std::fs::copy(config_path, &backup)
            .with_context(|| format!("back up {}", backup.display()))?;
    }

    let mut config = agent.format().read(config_path)?;
    let Some(root) = config.as_object_mut() else {
        bail!("{} config root is not an object", agent.name());
    };
    let providers = root
        .entry(agent.providers_key())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(providers) = providers.as_object_mut() else {
        bail!(
            "{}'s {} node is not an object",
            agent.name(),
            agent.providers_key()
        );
    };
    providers.insert(PROVIDER_ID.to_owned(), agent.provider_node(input));

    agent.format().write(config_path, &config)
}

/// Disconnect: if the backup exists, restore atomically; returns whether a restore happened. No backup → idempotently returns false.
pub fn disconnect_at(_agent: Agent, config_path: &Path) -> anyhow::Result<bool> {
    let backup = backup_path(config_path);
    if !backup.exists() {
        return Ok(false);
    }
    std::fs::rename(&backup, config_path)
        .with_context(|| format!("restore {}", config_path.display()))?;
    Ok(true)
}

/// Wiring status: whether connected, config path, and the model aliases registered under beaver.
pub fn status(agent: Agent) -> anyhow::Result<Value> {
    let path = agent
        .default_path()
        .context("cannot locate home directory")?;
    let mut aliases = Vec::new();
    let mut connected = false;
    if path.exists() {
        let config = agent.format().read(&path)?;
        if let Some(node) = config
            .get(agent.providers_key())
            .and_then(|p| p.get(PROVIDER_ID))
        {
            connected = true;
            match node.get("models") {
                Some(Value::Object(models)) => aliases.extend(models.keys().cloned()),
                Some(Value::Array(models)) => aliases.extend(
                    models
                        .iter()
                        .filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_owned)),
                ),
                _ => {}
            }
        }
    }
    Ok(serde_json::json!({
        "agent": agent.name(),
        "connected": connected,
        "config": path.display().to_string(),
        "aliases": aliases,
    }))
}
