//! cardinal-gateway: the standalone personal LLM gateway binary.
//!
//! Thin shell over the `gateway` lib: install the panic hook and the logging
//! subscriber, load the `[gateway]` section of the main config file, and serve
//! until Ctrl-C / SIGTERM (`cardinal::standalone::run`).

use std::path::{Path, PathBuf};

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "cardinal-gateway",
    version,
    about = "cardinal's standalone personal LLM gateway"
)]
struct Cli {
    /// Path to the main config file; defaults to `~/.ox/config.toml`.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("\n━━━ cardinal-gateway panicked ━━━");
        eprintln!("{info}");
        eprintln!("\nBacktrace:");
        eprintln!("{}", std::backtrace::Backtrace::capture());
    }));
}

fn main() -> anyhow::Result<()> {
    install_panic_hook();
    let cli = Cli::parse();
    let config_path = cli
        .config
        .clone()
        .or_else(|| dirs::home_dir().map(|home| home.join(".ox").join("config.toml")));
    let _log_guard = log::init(&log::load(config_path.as_deref()));
    let config = load_config(cli.config.as_deref())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(cardinal::standalone::run(config))
}

/// The gateway's config: the `[gateway]` section of the main config file.
/// The gateway is a per-machine personal service — one database, one listen
/// port — so the section lives at the user level only; `--config` overrides
/// the path. A missing file/section yields the defaults.
fn load_config(path: Option<&Path>) -> anyhow::Result<cardinal::config::Config> {
    let path = path
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".ox").join("config.toml")));
    match path {
        Some(path) => cardinal::config::Config::load(&path),
        None => Ok(cardinal::config::Config::default()),
    }
}

/// Process-global logging for the standalone binary, from the `[log]` section
/// of the main config file (`~/.ox/config.toml`):
///
/// ```toml
/// [log]
/// level = "info"                        # EnvFilter directives; RUST_LOG wins
/// file = "/tmp/cardinal/gateway.log"    # optional hourly-rotated file sink
/// ```
///
/// The console sink (stderr) is always on. Deliberately a minimal copy of the
/// main binary's logging (src/log.rs) — the two consumers' needs have
/// diverged (the GUI's panic-flush machinery vs a service's steady file log),
/// so no shared crate until a third binary appears.
mod log {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    /// The `[log]` section of the main config file.
    #[derive(Debug, Clone, serde::Deserialize)]
    #[serde(default)]
    pub struct LogSection {
        /// EnvFilter directives (e.g. "info", "debug", "gateway=debug").
        /// `RUST_LOG` overrides this entirely.
        pub level: String,
        /// Full path of the log file. Hourly-rotated (a date+hour suffix is appended);
        /// the parent directory is created on startup. Omit to disable the file sink.
        pub file: Option<String>,
    }

    impl Default for LogSection {
        fn default() -> Self {
            Self {
                level: "info".to_string(),
                file: None,
            }
        }
    }

    /// Read the `[log]` section of the main config file. A missing
    /// file or section yields the defaults; a malformed file degrades to
    /// defaults with a stderr note — logging must never block startup.
    pub fn load(path: Option<&std::path::Path>) -> LogSection {
        let Some(path) = path else {
            return LogSection::default();
        };
        match std::fs::read_to_string(path) {
            Ok(raw) => parse(&raw).unwrap_or_else(|error| {
                eprintln!(
                    "invalid [log] config in {}: {error}; logging falls back to defaults",
                    path.display()
                );
                LogSection::default()
            }),
            Err(_) => LogSection::default(),
        }
    }

    /// Extract `[log]` from main config TOML; everything outside belongs to
    /// other sections and is ignored here.
    fn parse(raw: &str) -> Result<LogSection, toml::de::Error> {
        #[derive(serde::Deserialize)]
        struct MainConfig {
            log: Option<LogSection>,
        }
        Ok(toml::from_str::<MainConfig>(raw)?.log.unwrap_or_default())
    }

    /// Install the global subscriber. Call once at the very start of `main()`.
    ///
    /// Returns the `WorkerGuard` — **keep it alive for the entire program
    /// lifetime**; dropping it early truncates the file writer's buffered tail.
    pub fn init(config: &LogSection) -> Option<tracing_appender::non_blocking::WorkerGuard> {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::try_new(&config.level).unwrap_or_else(|error| {
                eprintln!(
                    "invalid [log] level {:?}: {error}; falling back to \"info\"",
                    config.level
                );
                tracing_subscriber::EnvFilter::new("info")
            })
        });

        // Console sink is always on: local dev needs stderr even when a file
        // sink is configured; systemd deployments simply don't set `file`.
        let console_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

        let file_sink = config.file.as_ref().and_then(|file| {
            let path = std::path::Path::new(file);
            let dir = path
                .parent()
                .filter(|dir| !dir.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let prefix = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("cardinal-gateway.log");
            if let Err(error) = std::fs::create_dir_all(dir) {
                eprintln!(
                    "cannot create log dir {}: {error}; the file sink is disabled",
                    dir.display()
                );
                return None;
            }
            let (writer, guard) =
                tracing_appender::non_blocking(tracing_appender::rolling::hourly(dir, prefix));
            let layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339());
            Some((layer, guard))
        });
        let (file_layer, guard) = match file_sink {
            Some((layer, guard)) => (Some(layer), Some(guard)),
            None => (None, None),
        };

        tracing_subscriber::registry()
            .with(filter)
            .with(console_layer)
            .with(file_layer)
            .init();
        guard
    }
}
