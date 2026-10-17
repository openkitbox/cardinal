//! db — PostgreSQL connection + migration infrastructure (inlined from the
//! cardinal monorepo's `db` crate).

use anyhow::{Context as _, Result};

/// Default PostgreSQL DSN: the single `ox` database (PG user `beaver`).
pub const DEFAULT_DATABASE_URL: &str = "postgres://beaver:beaver@127.0.0.1:5432/ox";

/// A shared PostgreSQL handle: one pool for the whole process. Cheap to
/// clone (the pool is internally shared).
#[derive(Clone)]
pub struct Db {
    pool: sqlx::PgPool,
}

/// Parse a DSN, returning the connect options plus a credential-free
/// `host/database` label for error messages. Shared by [`Db::connect`] and
/// test fixtures that build custom pools, so the leak-safe pattern exists
/// exactly once.
pub fn parse_pg_options(url: &str) -> Result<(sqlx::postgres::PgConnectOptions, String)> {
    use std::str::FromStr as _;

    let options =
        sqlx::postgres::PgConnectOptions::from_str(url).context("invalid PostgreSQL DSN")?;
    let label = format!(
        "{}/{}",
        options.get_host(),
        options.get_database().unwrap_or("<default>")
    );
    Ok((options, label))
}

impl Db {
    /// Connect to PostgreSQL with the process-wide pool configuration
    /// (16 connections).
    ///
    /// Error contexts name only host/database — never the full DSN, which
    /// carries credentials and would leak into logs.
    pub async fn connect(url: &str) -> Result<Self> {
        let (options, label) = parse_pg_options(url)?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect_with(options)
            .await
            .with_context(|| {
                format!("failed to connect to PostgreSQL at {label} (credentials omitted)")
            })?;
        Ok(Self { pool })
    }

    /// Wrap an existing pool (test fixtures that pin `search_path` to a
    /// per-test schema, embedders that already own the pool, …).
    pub fn from_pool(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// The shared connection pool, handed to the domain modules.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    /// Run one domain's migrations under its `_sqlx_migrations_{domain}`
    /// bookkeeping table (idempotent). The error context names the domain.
    pub async fn migrate(&self, domain: &str, migrator: sqlx::migrate::Migrator) -> Result<()> {
        let mut migrator = migrator;
        migrator.dangerous_set_table_name(format!("_sqlx_migrations_{domain}"));
        migrator
            .run(&self.pool)
            .await
            .with_context(|| format!("{domain} migrations failed"))?;
        tracing::debug!(domain, "migrations applied");
        Ok(())
    }
}

/// SHA-256 hex digest (gateway key hashing: stored keys are digests, never
/// plaintext).
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}
