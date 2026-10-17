//! Test support: per-test PostgreSQL schema isolation for the gateway store.
//!
//! Mirrors the fixture convention in `crates/context/src/testing.rs`: each
//! fixture creates a dedicated schema (`oxt_<millis>_<pid>_<counter>`) plus a
//! pool whose connections pin `search_path` to it, so tests share one
//! database without colliding. The `oxt_` prefix is shared with the other
//! crates' fixtures on purpose — any crate's janitor sweeps all of them.
//!
//! Connection string: `OX_PG_TEST_URL` → `DATABASE_URL` →
//! [`crate::db::DEFAULT_DATABASE_URL`]. When PG is unreachable the fixture returns
//! `None` (printing the reason) so machines without PG stay green; set
//! `OX_PG_TEST_REQUIRED=1` to turn the soft skip into a panic, so a broken
//! PG on a machine expected to have one can't hide behind skips.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result};
use sqlx::PgPool;

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Test schemas older than this are swept by the janitor.
const JANITOR_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// A per-test database fixture: one schema, one pool pinned to it, migrated
/// with this crate's gateway migrations.
pub struct TestDatabase {
    pool: PgPool,
}

impl TestDatabase {
    /// Create the fixture, or `None` when PostgreSQL is unreachable and the
    /// test should skip (panics instead when `OX_PG_TEST_REQUIRED=1`).
    pub async fn connect() -> Option<Self> {
        let url = test_url();
        match Self::connect_inner(&url).await {
            Ok(fixture) => Some(fixture),
            Err(error) => {
                if pg_required() {
                    panic!("OX_PG_TEST_REQUIRED is set but PostgreSQL is unreachable: {error:#}");
                }
                eprintln!("skipping PG integration test: {error:#}");
                None
            }
        }
    }

    /// The schema-pinned pool, for store calls and raw assertions in tests.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Connect with the full migration set applied (the production startup
    /// shape). The name is historical: tests were written against a fixture
    /// that also ran the Keychain reconciler, which is gone (keys moved back
    /// into the database, 0013).
    pub async fn connect_reconciled() -> Option<Self> {
        Self::connect().await
    }

    async fn connect_inner(url: &str) -> Result<Self> {
        let (options, label) = crate::db::parse_pg_options(url)?;
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await
            .with_context(|| {
                format!("failed to connect to PostgreSQL at {label} (credentials omitted)")
            })?;

        janitor(&admin).await;

        let schema = format!(
            "oxt_{}_{}_{}",
            now_millis(),
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        // The schema name is self-generated (`oxt_<millis>_<pid>_<counter>`,
        // digits and underscores only) — never user input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
            .execute(&admin)
            .await
            .context("failed to create test schema")?;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
                    // No `public` fallback, deliberately: 0001_init.sql issues
                    // unqualified DROP TABLE IF EXISTS statements, and with public on
                    // the path they would resolve to (and destroy) real tables there
                    // whenever the local dev database is migrated.
                    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                        "SET search_path TO \"{schema}\""
                    )))
                    .execute(conn)
                    .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .with_context(|| format!("failed to connect test pool to PostgreSQL at {label}"))?;

        // The fixture owns its schema, so it migrates it (production
        // composition roots migrate once at startup before connecting).
        crate::db::Db::from_pool(pool.clone())
            .migrate("gateway", crate::migrator())
            .await?;
        Ok(Self { pool })
    }
}

fn test_url() -> String {
    std::env::var("OX_PG_TEST_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| crate::db::DEFAULT_DATABASE_URL.to_string())
}

fn pg_required() -> bool {
    std::env::var("OX_PG_TEST_REQUIRED").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ---------- admin API test server ----------

/// The admin key every admin-API test request authenticates with; the router
/// holds its plaintext (admin_auth hashes both sides before comparing).
pub const ADMIN_TEST_KEY: &str = "admin-test-key";

/// A test server bound on loopback (so `admin_local_only` passes) serving
/// the admin router over the fixture's migrated schema.
pub struct AdminTestServer {
    base: String,
    handle: salvo::server::ServerHandle,
    state: std::sync::Arc<crate::api::AppState>,
}

impl AdminTestServer {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// The shared app state (failover registry): tests assert
    /// the in-memory side effects an HTTP handler must trigger (e.g. clearing
    /// a rest forgives the consecutive-failure streak).
    pub fn state(&self) -> &crate::api::AppState {
        &self.state
    }

    /// GET with admin-key auth.
    pub async fn get(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(self.url(path))
            .bearer_auth(ADMIN_TEST_KEY)
            .send()
            .await
            .expect("GET")
    }

    /// The Step-2 HTTP client pointed at this server (admin key wired in).
    pub fn client(&self) -> crate::http_client::GatewayHttpClient {
        self.client_with(ADMIN_TEST_KEY)
    }

    /// The Step-2 HTTP client pointed at this server with a custom key (the
    /// auth-guard test passes a wrong one).
    pub fn client_with(&self, admin_key: &str) -> crate::http_client::GatewayHttpClient {
        crate::http_client::GatewayHttpClient::new(
            self.base.trim_start_matches("http://"),
            admin_key,
        )
    }
}

impl Drop for AdminTestServer {
    fn drop(&mut self) {
        self.handle.stop_graceful(None);
    }
}

/// AppState construction for the admin-API tests: dev limits so save-time
/// endpoint validation accepts plaintext loopback stubs.
fn test_state(pool: &PgPool) -> std::sync::Arc<crate::api::AppState> {
    let limits = crate::upstream::transport::Limits {
        allow_plaintext_loopback: true,
        allow_private_destinations: true,
        ..Default::default()
    };

    // Spawn the dispatcher for tests.
    let activity = crate::activity::ActivitySink::new();
    let (dispatcher, rx) = crate::relay::dispatcher::channel();
    tokio::spawn(crate::relay::dispatcher::run(
        rx,
        dispatcher.clone(),
        activity.clone(),
    ));

    let route_cache = crate::relay::RouteCache::new();
    let rest_cache = crate::relay::RestCache::new(pool.clone());
    let price_cache = crate::relay::PriceCache::new();
    // Tight flush cadence so test assertions see the ledger rows without sleeps;
    // the shutdown handle is dropped (test servers stop ungracefully anyway).
    let (ledger, _writer_handle) = crate::relay::LedgerWriter::new(
        pool.clone(),
        activity.clone(),
        std::time::Duration::from_millis(50),
        1,
    );
    std::sync::Arc::new(crate::api::AppState {
        transport: crate::upstream::transport::Transport::new(limits).expect("test transport"),
        pool: pool.clone(),
        queue_timeout: std::time::Duration::from_secs(30),
        dispatcher,
        failover: crate::relay::Failover::new(),
        trace_ring: std::sync::Arc::new(crate::relay::trace::TraceRing::new()),
        body_log: crate::body_log::BodyLog::new(),
        activity,
        smart_cache: crate::relay::SmartCache::new(),
        rotate_cursors: crate::relay::RotateCursors::new(),
        route_cache,
        rest_cache,
        price_cache,
        ledger,
        payload_log: false,
    })
}

/// Serve the FULL gateway router (what the standalone `cardinal-gateway`
/// mounts: `/health`, the `/v1*` relay endpoints, `/api/*` behind the auth
/// hoops) against the fixture's pool on a loopback port.
pub async fn spawn_admin(db: &TestDatabase) -> AdminTestServer {
    use salvo::prelude::*;
    let state = test_state(db.pool());
    let router = crate::api::router(
        state.clone(),
        std::sync::Arc::new(crate::admin::AdminKey(ADMIN_TEST_KEY.to_owned())),
        std::sync::Arc::new(crate::admin::AdminRemote(false)),
    );
    let acceptor = TcpListener::new("127.0.0.1:0").bind().await;
    let port = acceptor.local_addr().expect("local addr").port();
    let server = salvo::Server::new(acceptor);
    let handle = server.handle();
    tokio::spawn(server.serve(router));
    AdminTestServer {
        base: format!("http://127.0.0.1:{port}"),
        handle,
        state,
    }
}

/// Drop stale test schemas left behind by panicking or killed test runs.
/// Best-effort: a janitor failure never blocks the fixture.
async fn janitor(admin: &PgPool) {
    let names: Vec<String> =
        match sqlx::query_scalar("SELECT nspname FROM pg_namespace WHERE nspname LIKE 'oxt\\_%'")
            .fetch_all(admin)
            .await
        {
            Ok(names) => names,
            Err(error) => {
                tracing::warn!(error = %error, "gateway test janitor failed to list schemas");
                return;
            }
        };
    let cutoff = now_millis() - JANITOR_MAX_AGE_MS;
    for name in names {
        // oxt_<millis>_<pid>_<counter>
        let millis = name
            .split('_')
            .nth(1)
            .and_then(|part| part.parse::<i64>().ok());
        if millis.is_some_and(|millis| millis < cutoff)
            && let Err(error) = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP SCHEMA \"{name}\" CASCADE"
            )))
            .execute(admin)
            .await
        {
            tracing::warn!(error = %error, schema = %name, "gateway test janitor failed to drop stale schema");
        }
    }
}
