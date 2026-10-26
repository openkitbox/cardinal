//! Composition root: the assembly entry point for the gateway service.
//!
//! The `cardinal-gateway` binary (`src/bin/main.rs`, via [`crate::standalone`]) and
//! embedding test hosts call [`Gateway::start`] and hold the handle to decide when
//! to shut down. There is exactly one gateway per listen address: gateway state
//! (relay failover, metering) lives in the serving process, so a second process
//! binding the same address fails with AddrInUse instead of being adopted.
//!
//! Candidate model: the client-supplied `model` string is either a route alias (a named key subset,
//! tried in the keys' global position order) or `"<provider>/<upstream model>"` addressing one
//! provider's keys directly; a failed key cools down alone and failover walks the remaining keys.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use salvo::conn::Acceptor as _;
use salvo::conn::rustls::{Keycert, RustlsConfig, RustlsListener};
use salvo::conn::tcp::{DynTcpAcceptors, TcpListener};
use salvo::prelude::*;
use salvo::server::ServerHandle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::relay;
use crate::relay::dispatcher;
use crate::upstream::transport;
use crate::{admin, admin_ops, api, config, store};

/// Maximum wait for in-flight requests during graceful shutdown (long SSE streams may linger; forced stop after timeout).
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Cadence of the background vendor-quota prober. The Smart route strategy
/// ranks a route's candidates by their stored quota snapshots, read by relay
/// dispatch per request, so the snapshots must be refreshed without a GUI
/// round-trip.
const QUOTA_PROBE_INTERVAL: Duration = Duration::from_secs(300);

/// Orchestration core handle: connection pool + upstream transport + dispatcher queue wait + failover state.
/// Shared by all three modes, independent of whether a port is listened on.
struct Core {
    pool: sqlx::PgPool,
    transport: transport::Transport,
    /// Wait for a dispatcher slot assignment before answering 429
    /// ([gateway].queue_timeout_secs; at least one second).
    queue_timeout: Duration,
    failover: Arc<relay::Failover>,
    /// Routing trace ring (last N dispatches), shared by the relay and the
    /// admin surface.
    trace_ring: Arc<relay::trace::TraceRing>,
    /// Diagnostic body ring, shared by the relay, the HTTP
    /// admin surface and the in-process admin facade.
    body_log: crate::body_log::BodyLog,
    /// Batch ledger writer: the relay queues attempt rows here; a background
    /// flush task writes them to PG. `writer_handle` is its graceful-shutdown
    /// handle.
    ledger: crate::relay::LedgerWriter,
    writer_handle: crate::relay::LedgerWriterHandle,
    /// Live-activity publisher, shared by every dispatch entry.
    activity: crate::activity::ActivitySink,
    /// Shutdown signal for the process-level background daemons (currently the
    /// quota prober) — cancelled by [`Gateway::shutdown`] before the pool
    /// closes so no daemon round ever races pool teardown.
    prober_cancel: CancellationToken,
    /// The quota prober's join handle, awaited in [`Gateway::shutdown`] after
    /// cancellation so an in-flight probe round finishes before the pool closes.
    prober_join: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// In-memory quota snapshots for Smart ordering — the prober writes,
    /// relay reads; no PG round-trip on the request path.
    smart_cache: relay::SmartCache,
    /// The process's single Kiro token manager: dispatch, the admin surface and
    /// the quota prober all share this instance, so a Kiro credential refresh
    /// happens once and its rotated bundle is visible to every caller.
    kiro_tokens: Arc<crate::upstream::KiroTokens>,
    /// Per-alias round-robin cursors for Rotate ordering — one atomic
    /// increment per dispatch, no lock, no allocation.
    rotate_cursors: relay::RotateCursors,
    /// In-memory route/provider/key cache — seeded from PG at startup, refreshed
    /// after admin writes; no PG round-trip on the request path.
    route_cache: relay::RouteCache,
    /// In-memory cooldown cache — seeded from PG at startup, write-through on
    /// rest insert/clear; no PG round-trip on the request path.
    rest_cache: relay::RestCache,
    /// In-memory price cache — seeded from PG at startup, write-through on
    /// catalog upsert; no PG round-trip on the request path.
    price_cache: relay::PriceCache,
    /// `[gateway].payloads`: relay mirrors request/response bodies into the log.
    payload_log: bool,
}

impl Core {
    async fn build(config: &config::Config) -> anyhow::Result<Self> {
        let db = crate::db::Db::connect(&config.sql_dsn).await?;
        db.migrate("gateway", crate::migrator()).await?;
        let pool = db.pool().clone();
        // Provider-key credentials live in the database (0013); no secret store
        // at all — the Keychain round-trip caused per-read authorization prompts
        // for the locally-signed dev binary and bought nothing for a single-user
        // local service.
        store::seed_gateway_key(&pool, &config.gateway_key).await?;
        // Config is the source of truth for its seeds: a base_url that violates
        // the relay's version-root contract fails startup loudly rather than
        // double-appending a protocol leaf into an upstream 404 at relay time.
        for provider in &config.providers {
            crate::relay::capabilities::validate_base_url(&provider.name, &provider.base_url)?;
        }
        store::seed_from_config(&pool, &config.providers, &config.prices).await?;
        // Existing rows (GUI/admin-created) predate the version-root contract: a
        // leaf-carrying base_url would silently double-append at relay time. Warn
        // per offender; DB rows must never block startup.
        for provider in store::list_providers(&pool).await? {
            if let Err(error) =
                crate::relay::capabilities::validate_base_url(&provider.name, &provider.base_url)
            {
                tracing::warn!(provider = %provider.name, base_url = %provider.base_url, %error, "stored provider violates the base_url contract; fix it in the GUI");
            }
        }
        let activity = crate::activity::ActivitySink::new();
        let queue_timeout = config
            .queue_timeout_secs
            .map_or_else(
                || std::time::Duration::from_secs(30),
                std::time::Duration::from_secs,
            )
            .max(std::time::Duration::from_secs(1));
        let smart_cache = relay::SmartCache::new();
        // Seed the cache from PG so a restart does not wait for the first probe
        // round — Smart routes fall back to stored order only until this load.
        match store::list_quota_snapshots(&pool).await {
            Ok(rows) => {
                let snapshots: std::collections::HashMap<i64, crate::quota::KeyQuota> = rows
                    .into_iter()
                    .map(|(key_id, quota, _)| (key_id, quota))
                    .collect();
                if !snapshots.is_empty() {
                    smart_cache.refresh(snapshots);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "smart cache seed failed; Smart routes degrade to stored order until the first probe")
            }
        }
        let route_cache = relay::RouteCache::new();
        if let Err(error) = route_cache.load(&pool).await {
            tracing::warn!(%error, "route cache seed failed; all requests will 404 until the first admin write refreshes the cache");
        }
        let rest_cache = relay::RestCache::new(pool.clone());
        if let Err(error) = rest_cache.load().await {
            tracing::warn!(%error, "rest cache seed failed; all keys treated as un-rested until the first rest write or admin clear");
        }
        let price_cache = relay::PriceCache::new();
        if let Err(error) = price_cache.load(&pool).await {
            tracing::warn!(%error, "price cache seed failed; cost tracking disabled until the first price upsert");
        }
        // Batch ledger writer: the request path queues attempt rows; the flush
        // task batches them into PG (default cadence/trigger — the relay traffic
        // of a personal gateway never strains these). Spawns the flush task.
        let (ledger, writer_handle) = crate::relay::LedgerWriter::new(
            pool.clone(),
            activity.clone(),
            crate::relay::ledger_writer::DEFAULT_FLUSH_INTERVAL,
            crate::relay::ledger_writer::DEFAULT_BATCH_SIZE,
        );
        // One upstream transport for the whole process: chat dispatch, OIDC
        // token refreshes and the vendor-quota probe share its destination
        // policy and connection pool. The Kiro token manager owns a handle to
        // it, so the quota probe reaches Kiro through the same policy.
        let transport = transport::Transport::new(limits(config))?;
        let kiro_tokens = Arc::new(crate::upstream::KiroTokens::new(transport.clone()));
        Ok(Self {
            pool,
            transport,
            kiro_tokens,
            queue_timeout,
            failover: relay::Failover::new(),
            trace_ring: Arc::new(relay::trace::TraceRing::new()),
            body_log: crate::body_log::BodyLog::new(),
            ledger,
            writer_handle,
            activity,
            prober_cancel: CancellationToken::new(),
            prober_join: std::sync::Mutex::new(None),
            smart_cache,
            rotate_cursors: relay::RotateCursors::new(),
            route_cache,
            rest_cache,
            price_cache,
            payload_log: config.payloads,
        })
    }
}

/// Background vendor-quota prober: every [`QUOTA_PROBE_INTERVAL`], run the
/// [`admin_ops::probe_all_quotas`] fan-out, which probes each enabled key that
/// has a quota source and persists its snapshot. `tokio::time::interval`'s
/// first tick fires immediately, so the first round runs at boot rather than
/// after one full interval.
///
/// The loop never panics on a failure: `probe_all_quotas` logs every vendor,
/// credential, and store failure internally and still returns the readings it
/// did get, so there is no error to propagate — a bad round simply retries on
/// the next tick. Rounds are sequential (the join set drains before the next
/// tick), so concurrent probes can never build up, and the prober touches no
/// request-path lock: relay dispatch reads snapshots from the database.
/// `cancel` ends the loop between ticks at shutdown, before the pool closes.
async fn quota_prober(
    pool: sqlx::PgPool,
    smart_cache: relay::SmartCache,
    kiro_tokens: Arc<crate::upstream::KiroTokens>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(QUOTA_PROBE_INTERVAL);
    // Delay, not the default Burst: if a round ever runs past the interval, skip
    // the missed tick(s) and wait a full interval rather than firing rounds
    // back-to-back.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
          _ = ticker.tick() => {
            admin_ops::probe_all_quotas(&pool, Some(&smart_cache), Some(&kiro_tokens)).await;
          }
          // Shutdown: stop between rounds (a round in flight finishes; the pool
          // stays open until this task's owner proceeds past the cancel).
          () = cancel.cancelled() => return,
        }
    }
}

/// A running gateway instance. The holder (binary or embedding test host) decides when to [`Self::shutdown`].
pub struct Gateway {
    core: Core,
    server: ServerGuard,
}

/// Handle to the HTTP listening surface.
struct ServerGuard {
    addr: SocketAddr,
    handle: ServerHandle,
    join: JoinHandle<()>,
}

impl Gateway {
    /// Fully assemble and start the HTTP service: bind listener, then build
    /// the core (migrate + reconcile), then spawn the server.
    /// On return the port is already listening; on failure the whole call errors out (any established pool is dropped with it).
    ///
    /// The bind happens BEFORE [`Core::build`] on purpose: only the process
    /// that owns the port may run the destructive startup migration (the
    /// reconciler drops the legacy `api_key` column). A process that loses the
    /// bind race surfaces AddrInUse and never touches the schema — adopting a
    /// still-running old binary would DROP the column under its feet.
    pub async fn start(config: config::Config) -> anyhow::Result<Self> {
        // try_bind, not bind: bind() panics on failure, and a port conflict must
        // surface as AddrInUse, not a panic. salvo's Error has an empty source()
        // chain, so unwrap Error::Io here: callers must see the real io::ErrorKind,
        // not the locale-dependent "Address already in use" display string.
        let tcp = TcpListener::new(config.listen.clone());
        let acceptor = match &config.ssl {
            // TLS termination in-process: rustls wrapping the plain TCP listener.
            // `DynTcpAcceptors` erases the branch difference (salvo's `Server::new`
            // is generic over one acceptor type; TLS and plaintext acceptors are
            // different concrete types).
            Some(ssl) => {
                let keycert = Keycert::new()
                    .cert_from_path(&ssl.cert_path)
                    .and_then(|keycert| keycert.key_from_path(&ssl.key_path))
                    .with_context(|| {
                        format!("load TLS keypair ({} / {})", ssl.cert_path, ssl.key_path)
                    })?;
                DynTcpAcceptors::new(vec![
                    RustlsListener::new(RustlsConfig::new(keycert), tcp)
                        .try_bind()
                        .await
                        .map_err(|error| match error {
                            salvo::Error::Io(io) => anyhow::Error::from(io),
                            other => anyhow::anyhow!(other),
                        })
                        .with_context(|| format!("bind {}", config.listen))?
                        .into_boxed(),
                ])
            }
            None => DynTcpAcceptors::new(vec![
                tcp.try_bind()
                    .await
                    .map_err(|error| match error {
                        salvo::Error::Io(io) => anyhow::Error::from(io),
                        other => anyhow::anyhow!(other),
                    })
                    .with_context(|| format!("bind {}", config.listen))?
                    .into_boxed(),
            ]),
        };
        // Convert salvo's `conn::SocketAddr` back to `std` — TCP bindings are
        // always IPv4/IPv6.
        let holding = acceptor
            .holdings()
            .first()
            .context("bound listener reported no holdings")?
            .clone();
        let addr = match holding.local_addr {
            salvo::conn::addr::SocketAddr::IPv4(v4) => std::net::SocketAddr::V4(v4),
            salvo::conn::addr::SocketAddr::IPv6(v6) => std::net::SocketAddr::V6(v6),
            other => anyhow::bail!("unexpected bound address kind: {other:?}"),
        };
        let core = Core::build(&config).await?;
        // Process-level background daemons are spawned here, beside the price
        // keeper: both poll an external system for the lifetime of the process and
        // need only the pool. `Core::build` hosts wiring (store, transport,
        // registries), not daemons. Spawning here — past the bind and the config/
        // migration startup — means the standalone `cardinal-gateway` binary
        // (bin/main.rs → standalone::run → Gateway::start) and any embedding test
        // host that calls Gateway::start both inherit them. The GUI does not run a
        // Core at all (it is a separate process talking to the gateway over HTTP).
        // The prober honors `prober_cancel` (see `Gateway::shutdown`); the price
        // keeper has no shutdown signal — process exit aborts it.
        //
        // Price catalog keeper (models.dev): only the process that owns the port
        // syncs prices; tests build routers directly and never fetch.
        crate::prices::start(core.pool.clone(), core.price_cache.clone());
        // Vendor-quota prober: keeps the snapshots the Smart route strategy ranks
        // by fresh (relay dispatch reads them from the database per request).
        let prober_handle = tokio::spawn(quota_prober(
            core.pool.clone(),
            core.smart_cache.clone(),
            Arc::clone(&core.kiro_tokens),
            core.prober_cancel.clone(),
        ));
        *core.prober_join.lock().expect("prober_join poisoned") = Some(prober_handle);
        // Centralized dispatcher: owns all slot state and the pending queue,
        // atomically assigning requests to candidates.
        let (dispatcher_tx, dispatcher_rx) = dispatcher::channel();
        let release_tx = dispatcher_tx.clone();
        tokio::spawn(dispatcher::run(
            dispatcher_rx,
            release_tx,
            core.activity.clone(),
        ));
        let admin_key = Arc::new(admin::AdminKey(config.gateway_key.clone()));
        let admin_remote = Arc::new(admin::AdminRemote(config.admin_remote));
        let state = Arc::new(api::AppState {
            pool: core.pool.clone(),
            transport: core.transport.clone(),
            queue_timeout: core.queue_timeout,
            failover: Arc::clone(&core.failover),
            dispatcher: dispatcher_tx.clone(),
            trace_ring: Arc::clone(&core.trace_ring),
            body_log: core.body_log.clone(),
            activity: core.activity.clone(),
            smart_cache: core.smart_cache.clone(),
            rotate_cursors: core.rotate_cursors.clone(),
            route_cache: core.route_cache.clone(),
            rest_cache: core.rest_cache.clone(),
            price_cache: core.price_cache.clone(),
            kiro_tokens: core.kiro_tokens.clone(),
            ledger: core.ledger.clone(),
            payload_log: core.payload_log,
        });

        let server = Server::new(acceptor);
        let handle = server.handle();
        let join = tokio::spawn(server.serve(api::router(state, admin_key, admin_remote)));
        tracing::info!("listening on {addr}");
        Ok(Self {
            core,
            server: ServerGuard { addr, handle, join },
        })
    }

    /// The actual listen address. When `listen` is configured with `:0`, the
    /// system assigns the port, and the holder learns the real port from this.
    pub fn local_addr(&self) -> SocketAddr {
        self.server.addr
    }

    /// Graceful shutdown: the HTTP surface stops accepting new connections and waits for in-flight requests
    /// (at most [`SHUTDOWN_TIMEOUT`]), then the ledger writer flushes its buffered rows, then the database pool closes.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.server.handle.stop_graceful(SHUTDOWN_TIMEOUT);
        self.server
            .join
            .await
            .map_err(|error| anyhow::anyhow!("server task join failed: {error}"))?;
        // Stop the quota prober and wait for any in-flight round to finish
        // before the pool closes — no probe round ever races pool teardown.
        self.core.prober_cancel.cancel();
        let prober = self
            .core
            .prober_join
            .lock()
            .expect("prober_join poisoned")
            .take();
        if let Some(handle) = prober {
            let _ = handle.await;
        }
        // In-flight requests have settled (their rows are queued); flush before
        // the pool closes — the final batch still needs a live connection.
        self.core.writer_handle.flush_and_shutdown().await;
        self.core.pool.close().await;
        Ok(())
    }
}

/// Deterministic Keychain availability probe, run right after reconciliation.
/// Production default limits; with `allow_insecure_upstream`, plaintext loopback and arbitrary ports are permitted (local mock upstream).
fn limits(cfg: &config::Config) -> transport::Limits {
    let mut limits = transport::Limits::default();
    if cfg.allow_insecure_upstream {
        limits.allow_plaintext_loopback = true;
        limits.allowed_ports = (1024..=65535).collect();
        limits.allow_private_destinations = true;
    }
    limits
}
