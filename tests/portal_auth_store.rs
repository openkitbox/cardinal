//! Integration tests for DB-owned portal settings and OAuth identities.
//! Set CARDINAL_TEST_DATABASE_URL to an isolated PostgreSQL 18 cluster with
//! TimescaleDB >= 2.31. Each test creates and migrates its own database.

use cardinal::db::parse_pg_options;
use cardinal::store;
use jiff::{SignedDuration, Timestamp};
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use sqlx::{ConnectOptions, PgPool, Postgres};
use std::time::Duration;

struct TestDb {
    pool: PgPool,
    url: String,
}

impl TestDb {
    async fn new() -> Self {
        let base_url = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&base_url).expect("parse test DSN");
        let name = format!(
            "cardinal_portal_auth_test_{}",
            uuid::Uuid::new_v4().simple()
        );
        let options = options.database(&name);
        let url = options.to_url_lossy().to_string();
        Postgres::create_database(&url)
            .await
            .expect("create test database");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .expect("connect to test database");
        sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .execute(&pool)
            .await
            .expect("install TimescaleDB in test database");
        Self { pool, url }
    }

    async fn migrated() -> Self {
        let db = Self::new().await;
        cardinal::migrator()
            .run(&db.pool)
            .await
            .expect("migrate empty database");
        store::create_group(&db.pool, "customer", 10000, None)
            .await
            .expect("create customer group");
        db
    }

    async fn close(self) {
        self.pool.close().await;
        Postgres::drop_database(&self.url)
            .await
            .expect("drop test database");
    }
}

fn digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn future_expiry() -> Timestamp {
    Timestamp::now() + SignedDuration::from_hours(1)
}

async fn register(pool: &PgPool, email: &str, seed: u8) -> i64 {
    assert!(
        store::issue_registration_challenge(pool, email, &digest(seed), future_expiry())
            .await
            .expect("issue challenge")
    );
    store::complete_registration(pool, &digest(seed), "test-hash", "customer")
        .await
        .expect("complete registration")
        .expect("new user")
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .expect("count rows")
}

/// Wait until a second transaction is actually blocked on a row lock. A bounded
/// poll avoids fixed sleeps while keeping the race test deterministic.
async fn wait_for_blocked_writer(pool: &PgPool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM pg_stat_activity
              WHERE datname = current_database()
                AND state = 'active'
                AND cardinality(pg_blocking_pids(pid)) > 0",
        )
        .fetch_one(pool)
        .await
        .expect("query pg_stat_activity");
        if blocked > 0 {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "masked writer never blocked on the locked row"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn settings_input(
    transport: &'static str,
    token: &'static str,
    password: &'static str,
) -> store::PortalSettingsInput<'static> {
    store::PortalSettingsInput {
        mail_transport: transport,
        mail_url: "http://mail.internal/send",
        mail_token: token,
        mail_from: "Cardinal <auth@example.test>",
        mail_origin: "https://portal.example.test",
        smtp_host: "smtp.internal",
        smtp_port: 2525,
        smtp_username: "mailer",
        smtp_password: password,
        smtp_tls: "starttls",
        smtp_from: "Cardinal <auth@example.test>",
    }
}

fn provider_input<'a>(
    provider: &'a str,
    secret: &'a str,
    enabled: bool,
    extra: &'a serde_json::Value,
) -> store::AuthProviderInput<'a> {
    store::AuthProviderInput {
        provider,
        client_id: "public-client",
        client_secret: secret,
        redirect_uri: "https://portal.example.test/api/auth/oauth/google/callback",
        enabled,
        extra,
    }
}

#[test]
fn store_mask_secret_hides_configured_values_only() {
    assert_eq!(
        store::mask_secret(""),
        "",
        "unset secrets stay visibly empty"
    );
    assert_eq!(
        store::mask_secret("s3cret"),
        store::SECRET_MASK,
        "configured secrets must be masked"
    );
}

#[tokio::test]
async fn store_migration_creates_singleton_and_constraints() {
    let db = TestDb::new().await;
    let pool = &db.pool;
    cardinal::migrator().run(pool).await.expect("migrate");
    assert_eq!(
        count(pool, "SELECT count(*) FROM public.portal_settings").await,
        1,
        "portal settings must be a singleton"
    );
    assert!(
        sqlx::query("INSERT INTO public.portal_settings (id) VALUES (true)")
            .execute(pool)
            .await
            .is_err(),
        "a second settings row must be rejected"
    );
    assert!(
        sqlx::query("UPDATE public.portal_settings SET mail_transport = 'carrier-pigeon'")
            .execute(pool)
            .await
            .is_err(),
        "unknown mail transports must be rejected"
    );
    assert!(
        sqlx::query("UPDATE public.portal_settings SET smtp_tls = 'maybe'")
            .execute(pool)
            .await
            .is_err(),
        "unknown SMTP TLS modes must be rejected"
    );
    assert!(
        sqlx::query("INSERT INTO public.auth_providers (provider, extra) VALUES ('google', '[]')")
            .execute(pool)
            .await
            .is_err(),
        "provider extra must be a JSON object"
    );
    assert!(
        sqlx::query("INSERT INTO public.auth_providers (provider) VALUES ('Google')")
            .execute(pool)
            .await
            .is_err(),
        "provider names must be normalized"
    );
    let group = store::create_group(pool, "customer", 10000, None)
        .await
        .expect("create group");
    let user = store::create_user(
        pool,
        store::NewUser {
            login: "oauth-migration@example.test",
            display_name: "OAuth",
            group_id: group,
            rate_bp: None,
            max_concurrent: None,
            route_aliases: None,
        },
    )
    .await
    .expect("create user");
    let insert_identity = |subject: &'static str| {
        sqlx::query(
            "INSERT INTO public.account_oauth_identities (provider, subject, user_id, email)
             VALUES ('google', $1, $2, 'oauth@example.test')",
        )
        .bind(subject)
        .bind(user)
        .execute(pool)
    };
    insert_identity("subject-1").await.expect("insert identity");
    assert!(
        insert_identity("subject-1").await.is_err(),
        "(provider, subject) must be unique"
    );
    assert!(
        sqlx::query(
            "INSERT INTO public.account_oauth_identities (provider, subject, user_id, email)
             VALUES ('google', 'bad-email', $1, 'Not-Normalized@example.test')"
        )
        .bind(user)
        .execute(pool)
        .await
        .is_err(),
        "identity email must be normalized"
    );
    sqlx::query("DELETE FROM public.users WHERE id = $1")
        .bind(user)
        .execute(pool)
        .await
        .expect("delete user");
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.account_oauth_identities WHERE user_id = $1",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("count identities for deleted user");
    assert_eq!(remaining, 0, "deleting a user must cascade its identities");
    db.close().await;
}

#[tokio::test]
async fn store_settings_write_masks_secrets_and_preserves_or_clears_them() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let before = store::get_portal_settings(pool)
        .await
        .expect("read default settings");
    assert_eq!(before.mail_transport, "http");
    let stored =
        store::put_portal_settings(pool, &settings_input("smtp", "mail-token", "smtp-pass"))
            .await
            .expect("write settings");
    assert_eq!(
        stored.mail_token, "mail-token",
        "mail token must be stored verbatim"
    );
    assert_eq!(
        stored.smtp_password, "smtp-pass",
        "SMTP password must be stored verbatim"
    );
    let debug = format!("{stored:?}");
    assert!(
        !debug.contains("mail-token") && !debug.contains("smtp-pass"),
        "Debug must not expose plaintext secrets: {debug}"
    );
    assert!(
        debug.contains(store::SECRET_MASK),
        "Debug should still show that secrets are configured: {debug}"
    );
    let view = store::get_portal_settings_masked(pool)
        .await
        .expect("read masked settings");
    assert_eq!(view.mail_token, store::SECRET_MASK);
    assert_eq!(view.smtp_password, store::SECRET_MASK);
    assert_eq!(view.mail_url, "http://mail.internal/send");
    assert!(view.updated_at >= before.updated_at);

    let keep = settings_input("http", store::SECRET_MASK, store::SECRET_MASK);
    let stored = store::put_portal_settings(pool, &keep)
        .await
        .expect("write with masked secrets");
    assert_eq!(stored.mail_token, "mail-token");
    assert_eq!(stored.smtp_password, "smtp-pass");
    assert_eq!(stored.mail_transport, "http");

    let clear = settings_input("http", "", "");
    let stored = store::put_portal_settings(pool, &clear)
        .await
        .expect("clear secrets");
    assert_eq!(stored.mail_token, "");
    assert_eq!(stored.smtp_password, "");
    let view = store::get_portal_settings_masked(pool)
        .await
        .expect("read cleared settings");
    assert_eq!(view.mail_token, "");
    assert_eq!(view.smtp_password, "");
    assert_eq!(
        count(pool, "SELECT count(*) FROM public.portal_settings").await,
        1,
        "writes must keep the singleton invariant"
    );
    db.close().await;
}

#[tokio::test]
async fn store_provider_crud_masks_secret_and_survives_deletion() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user = register(pool, "provider@example.test", 1).await;
    sqlx::query(
        "INSERT INTO public.account_oauth_identities (provider, subject, user_id, email)
         VALUES ('google', 'provider-subject', $1, 'provider@example.test')",
    )
    .bind(user)
    .execute(pool)
    .await
    .expect("insert identity");
    let extra = serde_json::json!({"scopes": ["email"]});
    let stored = store::upsert_auth_provider(
        pool,
        &provider_input("google", "client-secret", false, &extra),
    )
    .await
    .expect("insert provider");
    assert_eq!(
        stored.client_secret, "client-secret",
        "insert must store the provider secret"
    );
    assert_eq!(stored.extra, extra, "extra must round-trip unchanged");
    let debug = format!("{stored:?}");
    assert!(
        !debug.contains("client-secret"),
        "Debug must not expose the provider secret: {debug}"
    );
    assert!(
        debug.contains(store::SECRET_MASK),
        "Debug should still show that a provider secret is configured: {debug}"
    );
    assert!(
        store::list_enabled_auth_providers(pool)
            .await
            .expect("list enabled")
            .is_empty(),
        "a provider without credentials must stay disabled"
    );

    let keep = provider_input("google", store::SECRET_MASK, true, &extra);
    let stored = store::upsert_auth_provider(pool, &keep)
        .await
        .expect("update provider");
    assert_eq!(
        stored.client_secret, "client-secret",
        "mask keeps the secret"
    );
    assert!(stored.enabled);
    let list = store::list_auth_providers(pool)
        .await
        .expect("list providers");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].masked().client_secret, store::SECRET_MASK);
    assert_eq!(
        list[0].masked().client_secret,
        store::SECRET_MASK,
        "admin list must mask the secret"
    );
    let public = store::list_enabled_auth_providers(pool)
        .await
        .expect("list enabled");
    assert_eq!(public.len(), 1, "enabled provider must be listed publicly");
    assert_eq!(public[0].provider, "google", "public provider name");
    assert_eq!(public[0].client_id, "public-client", "public client id");
    let public_json = serde_json::to_value(&public).expect("serialize public providers");
    assert!(
        public_json[0].get("client_secret").is_none(),
        "public provider list must not contain a secret: {public_json}"
    );
    let one = store::get_auth_provider(pool, "google")
        .await
        .expect("get provider")
        .expect("known provider");
    assert_eq!(
        one.masked().client_secret,
        store::SECRET_MASK,
        "single-provider admin read must mask the secret"
    );
    assert!(
        store::get_auth_provider(pool, "facebook")
            .await
            .expect("get missing")
            .is_none()
    );

    let empty_extra = serde_json::json!({});
    let cleared = provider_input("google", "", true, &empty_extra);
    let stored = store::upsert_auth_provider(pool, &cleared)
        .await
        .expect("clear secret");
    assert_eq!(stored.client_secret, "");
    assert!(
        store::delete_auth_provider(pool, "google")
            .await
            .expect("delete")
    );
    assert!(
        !store::delete_auth_provider(pool, "google")
            .await
            .expect("delete twice")
    );
    assert!(
        store::get_auth_provider(pool, "google")
            .await
            .expect("get deleted")
            .is_none()
    );
    assert_eq!(
        count(
            pool,
            "SELECT count(*) FROM public.account_oauth_identities WHERE provider = 'google'"
        )
        .await,
        1,
        "deleting a provider must not invalidate established identities"
    );
    db.close().await;
}

#[tokio::test]
async fn store_masked_settings_write_does_not_revert_concurrent_secret_change() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    store::put_portal_settings(pool, &settings_input("http", "old-token", "old-pass"))
        .await
        .expect("seed secrets");

    let mut tx = pool.begin().await.expect("begin real secret write");
    sqlx::query("SELECT id FROM public.portal_settings WHERE id FOR UPDATE")
        .execute(&mut *tx)
        .await
        .expect("lock settings row");
    let masked_pool = pool.clone();
    let keep = settings_input("http", store::SECRET_MASK, store::SECRET_MASK);
    let masked = tokio::spawn(async move { store::put_portal_settings(&masked_pool, &keep).await });
    wait_for_blocked_writer(pool).await;

    sqlx::query(
        "UPDATE public.portal_settings
            SET mail_token = $1, smtp_password = $2, updated_at = clock_timestamp()
          WHERE id",
    )
    .bind("new-token")
    .bind("new-pass")
    .execute(&mut *tx)
    .await
    .expect("apply real secret change");
    tx.commit().await.expect("commit real secret change");

    let row = masked
        .await
        .expect("join masked writer")
        .expect("masked write");
    assert_eq!(
        row.mail_token, "new-token",
        "a stale masked write must not revert the real mail token"
    );
    assert_eq!(
        row.smtp_password, "new-pass",
        "a stale masked write must not revert the real SMTP password"
    );
    let stored = store::get_portal_settings(pool)
        .await
        .expect("read final settings");
    assert_eq!(stored.mail_token, "new-token", "final mail token");
    assert_eq!(stored.smtp_password, "new-pass", "final SMTP password");
    db.close().await;
}

#[tokio::test]
async fn store_masked_provider_write_does_not_revert_concurrent_secret_change() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let extra = serde_json::json!({"scopes": ["email"]});
    store::upsert_auth_provider(pool, &provider_input("google", "old-secret", true, &extra))
        .await
        .expect("seed provider");
    let mut tx = pool.begin().await.expect("begin real secret write");
    sqlx::query("SELECT provider FROM public.auth_providers WHERE provider = 'google' FOR UPDATE")
        .execute(&mut *tx)
        .await
        .expect("lock provider row");
    let masked_pool = pool.clone();
    let masked = tokio::spawn(async move {
        let keep_extra = serde_json::json!({"scopes": ["email"]});
        let keep = provider_input("google", store::SECRET_MASK, true, &keep_extra);
        store::upsert_auth_provider(&masked_pool, &keep).await
    });
    wait_for_blocked_writer(pool).await;

    sqlx::query(
        "UPDATE public.auth_providers
            SET client_secret = $2, updated_at = clock_timestamp()
          WHERE provider = $1",
    )
    .bind("google")
    .bind("new-secret")
    .execute(&mut *tx)
    .await
    .expect("apply real secret change");
    tx.commit().await.expect("commit real secret change");

    let row = masked
        .await
        .expect("join masked writer")
        .expect("masked write");
    assert_eq!(
        row.client_secret, "new-secret",
        "a stale masked write must not revert the real provider secret"
    );
    let stored = store::get_auth_provider(pool, "google")
        .await
        .expect("read final provider")
        .expect("provider exists");
    assert_eq!(stored.client_secret, "new-secret", "final provider secret");
    db.close().await;
}

#[tokio::test]
async fn store_oauth_identity_links_verified_email_then_reuses_subject() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user = register(pool, " Alice.Smith+Tag@Example.COM ", 2).await;
    let linked = store::find_or_create_oauth_identity(
        pool,
        "google",
        "google-subject-1",
        "alice.smith+tag@example.com",
        true,
        "customer",
        "unusable-hash",
    )
    .await
    .expect("link verified email");
    assert_eq!(
        linked,
        Some(store::OAuthIdentityOutcome::Linked { user_id: user }),
        "verified email must link to the existing credential"
    );
    let reused = store::find_or_create_oauth_identity(
        pool,
        "google",
        "google-subject-1",
        "other@example.com",
        false,
        "customer",
        "unusable-hash",
    )
    .await
    .expect("reuse subject");
    assert_eq!(
        reused,
        Some(store::OAuthIdentityOutcome::Existing { user_id: user }),
        "a subject hit must win even when this call carries an unverified email"
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM public.users").await,
        2,
        "linking and reuse must not create users"
    );
    let email: String = sqlx::query_scalar(
        "SELECT email FROM public.account_oauth_identities WHERE provider = 'google' AND subject = 'google-subject-1'",
    )
    .fetch_one(pool)
    .await
    .expect("stored identity email");
    assert_eq!(email, "alice.smith+tag@example.com");
    db.close().await;
}

#[tokio::test]
async fn store_oauth_identity_creates_customer_and_rejects_unverified_email() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let rejected = store::find_or_create_oauth_identity(
        pool,
        "github",
        "github-subject-unverified",
        "new@example.test",
        false,
        "customer",
        "unusable-hash",
    )
    .await
    .expect("unverified email is a rejection, not an error");
    assert_eq!(rejected, None);
    assert_eq!(count(pool, "SELECT count(*) FROM public.users").await, 1);

    let created = store::find_or_create_oauth_identity(
        pool,
        "github",
        "github-subject-1",
        "  NEW@example.test ",
        true,
        "customer",
        "unusable-hash",
    )
    .await
    .expect("create customer");
    let Some(store::OAuthIdentityOutcome::Created { user_id }) = created else {
        panic!("expected a newly created customer, got {created:?}");
    };
    let user = store::get_user(pool, user_id)
        .await
        .expect("get created user")
        .expect("user exists");
    assert_eq!(user.group_name, "customer");
    assert_eq!(user.balance_microus, 0);
    let hash: String = sqlx::query_scalar(
        "SELECT password_hash FROM public.account_credentials WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("credential");
    assert_eq!(hash, "unusable-hash");
    let reused = store::find_or_create_oauth_identity(
        pool,
        "github",
        "github-subject-1",
        "new@example.test",
        true,
        "customer",
        "unusable-hash",
    )
    .await
    .expect("reuse subject");
    assert_eq!(
        reused,
        Some(store::OAuthIdentityOutcome::Existing { user_id }),
        "a second call with the same subject must reuse the created account"
    );
    assert_eq!(count(pool, "SELECT count(*) FROM public.users").await, 2);
    db.close().await;
}

#[tokio::test]
async fn store_oauth_identity_fails_closed_on_invalid_accounts_and_groups() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let disabled = register(pool, "disabled@example.test", 3).await;
    assert!(
        store::patch_user(
            pool,
            disabled,
            store::UserPatch {
                enabled: Some(false),
                ..store::UserPatch::default()
            }
        )
        .await
        .expect("disable user")
    );
    let rejected = store::find_or_create_oauth_identity(
        pool,
        "google",
        "disabled-subject",
        "disabled@example.test",
        true,
        "customer",
        "unusable-hash",
    )
    .await
    .expect("disabled account is a rejection");
    assert_eq!(rejected, None);

    let owner = store::owner_user_id(pool).await.expect("owner id");
    sqlx::query(
        "INSERT INTO public.account_credentials (user_id, email, password_hash)
         VALUES ($1, 'owner@example.test', 'unusable-hash')",
    )
    .bind(owner)
    .execute(pool)
    .await
    .expect("owner credential");
    let rejected = store::find_or_create_oauth_identity(
        pool,
        "google",
        "owner-subject",
        "owner@example.test",
        true,
        "customer",
        "unusable-hash",
    )
    .await
    .expect("owner is a rejection");
    assert_eq!(rejected, None);

    let error = store::find_or_create_oauth_identity(
        pool,
        "google",
        "no-group-subject",
        "missing-group@example.test",
        true,
        "absent-group",
        "unusable-hash",
    )
    .await;
    assert!(error.is_err(), "missing group must be an error");
    let error = store::find_or_create_oauth_identity(
        pool,
        "google",
        "reserved-group-subject",
        "reserved-group@example.test",
        true,
        "internal",
        "unusable-hash",
    )
    .await;
    assert!(error.is_err(), "reserved group must be an error");
    assert_eq!(
        count(pool, "SELECT count(*) FROM public.account_oauth_identities").await,
        0,
        "rejections must not leave identities behind"
    );
    db.close().await;
}

#[tokio::test]
async fn store_concurrent_same_subject_creates_one_identity_and_one_user() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let (a, b) = tokio::join!(
        store::find_or_create_oauth_identity(
            pool,
            "google",
            "race-subject",
            "race@example.test",
            true,
            "customer",
            "hash-a",
        ),
        store::find_or_create_oauth_identity(
            pool,
            "google",
            "race-subject",
            "race@example.test",
            true,
            "customer",
            "hash-b",
        ),
    );
    let a = a.expect("first lookup");
    let b = b.expect("second lookup");
    let a = a.expect("first identity");
    let b = b.expect("second identity");
    assert_eq!(
        a.user_id(),
        b.user_id(),
        "both calls must resolve one account"
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM public.account_oauth_identities").await,
        1
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM public.account_credentials").await,
        1
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM public.users").await,
        2,
        "owner plus one customer, no orphan user"
    );
    db.close().await;
}
