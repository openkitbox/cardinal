//! Standalone lifecycle for the gateway: serve until Ctrl-C / SIGTERM, then
//! shut down gracefully. Used by the `cardinal-gateway` binary
//! (`src/bin/main.rs`), which installs the logging subscriber itself before
//! calling [`run`].

use crate::config;
use crate::gateway::Gateway;

/// Serve until Ctrl-C / SIGTERM, then shut the gateway down gracefully.
pub async fn run(cfg: config::Config) -> anyhow::Result<()> {
    let gateway = Gateway::start(cfg).await?;
    shutdown_signal().await;
    tracing::info!("shutdown signal received, exiting");
    gateway.shutdown().await
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
