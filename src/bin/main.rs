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
        /// Mirror events to stderr. Defaults to true; a service deployment that
        /// sets `file` turns it off so the file is the only sink — under systemd
        /// an always-on stderr would duplicate every line into the journal.
        pub console: bool,
        /// Delete hourly files older than this many hours. Omit to keep them
        /// all. `tracing_appender` rotates but never deletes, so retention is
        /// this binary's own hourly sweep (see [`start_retention`]).
        pub retain_hours: Option<u64>,
    }

    impl Default for LogSection {
        fn default() -> Self {
            Self {
                level: "info".to_string(),
                file: None,
                console: true,
                retain_hours: None,
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

        // Console sink: stderr, on unless the config turns it off. Local dev
        // keeps it even when a file sink is configured; a systemd deployment
        // turns it off so the journal does not duplicate the file.
        let console_layer = config
            .console
            .then(|| tracing_subscriber::fmt::layer().with_writer(std::io::stderr));

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
            Some((layer, guard, dir.to_path_buf(), prefix.to_string()))
        });
        let (file_layer, guard, retention) = match file_sink {
            Some((layer, guard, dir, prefix)) => (Some(layer), Some(guard), Some((dir, prefix))),
            None => (None, None, None),
        };

        if let (Some((dir, prefix)), Some(hours)) = (retention, config.retain_hours) {
            start_retention(dir, prefix, hours);
        }

        tracing_subscriber::registry()
            .with(filter)
            .with(console_layer)
            .with(file_layer)
            .init();
        guard
    }

    /// Sweep the sink's directory at startup and then hourly, dropping files
    /// older than `retain_hours`. `tracing_appender` has no retention of its
    /// own; an in-process sweep keeps the policy next to the sink it belongs
    /// to, with no external timer to install or drift.
    fn start_retention(dir: std::path::PathBuf, prefix: String, retain_hours: u64) {
        // A zero or absurd hour count must not unlink the file being written.
        let max_age = std::time::Duration::from_secs(retain_hours.max(1) * 3600);
        // A plain thread: `init` runs before the tokio runtime exists, and the
        // sweep needs nothing from it.
        let spawned = std::thread::Builder::new()
            .name("cardinal-log-retention".to_string())
            .spawn(move || {
                loop {
                    sweep(&dir, &prefix, max_age);
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            });
        if spawned.is_err() {
            // Logging must never block startup; the files simply pile up.
            eprintln!("cannot start the log retention thread; old log files are kept");
        }
    }

    /// Delete `prefix.*` files in `dir` older than `max_age`, keeping the
    /// newest one: the appender holds that file open, and unlinking it would
    /// silently swallow every line written until the next rotation.
    fn sweep(dir: &std::path::Path, prefix: &str, max_age: std::time::Duration) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let now = std::time::SystemTime::now();
        let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                let stamp = name.to_str()?.strip_prefix(prefix)?.strip_prefix('.')?;
                if stamp.is_empty() {
                    return None;
                }
                let metadata = entry.metadata().ok()?;
                if !metadata.is_file() {
                    return None;
                }
                Some((metadata.modified().ok()?, entry.path()))
            })
            .collect();
        files.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        for (modified, path) in files.into_iter().skip(1) {
            if now.duration_since(modified).unwrap_or_default() > max_age {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{parse, sweep};
        use std::time::{Duration, SystemTime};

        /// A scratch directory removed when the test ends.
        struct Scratch(std::path::PathBuf);

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn scratch() -> Scratch {
            let dir = std::env::temp_dir()
                .join(format!("cardinal-log-retention-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        /// A `name` file whose mtime is `age` in the past.
        fn write_log(dir: &std::path::Path, name: &str, age: Duration) {
            let file = std::fs::File::create(dir.join(name)).unwrap();
            file.set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - age))
                .unwrap();
        }

        #[test]
        fn defaults_to_console_on_and_no_file_sink() {
            let section = parse("").unwrap();
            assert_eq!(section.level, "info");
            assert!(section.file.is_none());
            assert!(section.console);
            assert!(section.retain_hours.is_none());
        }

        #[test]
        fn reads_the_service_sink_settings() {
            let section = parse(
                r#"
                [log]
                level = "debug"
                file = "/var/log/cardinal/gateway.log"
                console = false
                retain_hours = 72
                "#,
            )
            .unwrap();
            assert_eq!(section.level, "debug");
            assert_eq!(
                section.file.as_deref(),
                Some("/var/log/cardinal/gateway.log")
            );
            assert!(!section.console);
            assert_eq!(section.retain_hours, Some(72));
        }

        #[test]
        fn sweep_drops_only_its_own_files_past_retention() {
            let dir = scratch();
            write_log(
                &dir.0,
                "gateway.log.2026-10-15-05",
                Duration::from_secs(73 * 3600),
            );
            write_log(&dir.0, "gateway.log.2026-10-18-02", Duration::from_secs(60));
            write_log(
                &dir.0,
                "other.log.2026-10-15-05",
                Duration::from_secs(100 * 3600),
            );

            sweep(&dir.0, "gateway.log", Duration::from_secs(72 * 3600));

            assert!(!dir.0.join("gateway.log.2026-10-15-05").exists());
            assert!(dir.0.join("gateway.log.2026-10-18-02").exists());
            assert!(dir.0.join("other.log.2026-10-15-05").exists());
        }

        #[test]
        fn sweep_keeps_the_newest_file_even_when_stale() {
            let dir = scratch();
            write_log(
                &dir.0,
                "gateway.log.2026-10-10-00",
                Duration::from_secs(200 * 3600),
            );
            write_log(
                &dir.0,
                "gateway.log.2026-10-09-00",
                Duration::from_secs(210 * 3600),
            );

            sweep(&dir.0, "gateway.log", Duration::from_secs(72 * 3600));

            assert!(dir.0.join("gateway.log.2026-10-10-00").exists());
            assert!(!dir.0.join("gateway.log.2026-10-09-00").exists());
        }
    }
}
