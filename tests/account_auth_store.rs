//! Set CARDINAL_TEST_DATABASE_URL to an isolated PostgreSQL 18 cluster with
//! TimescaleDB >= 2.31 preloaded and a role able to create databases and the
//! extension. Each test creates and migrates its own temporary database.

use cardinal::db::parse_pg_options;
use cardinal::store;
use jiff::{SignedDuration, Timestamp};
use jiff_sqlx::ToSqlx;
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use sqlx::{ConnectOptions, PgPool, Postgres};

struct TestDb {
    pool: PgPool,
    url: String,
}

impl TestDb {
    async fn new() -> Self {
        let base_url = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&base_url).expect("parse test DSN");
        let name = format!("cardinal_auth_test_{}", uuid::Uuid::new_v4().simple());
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
fn past_expiry() -> Timestamp {
    Timestamp::now() - SignedDuration::from_hours(1)
}

async fn register(pool: &PgPool, seed: u8, email: &str) -> i64 {
    assert!(
        store::issue_registration_challenge(pool, email, &digest(seed), future_expiry())
            .await
            .unwrap()
    );
    store::complete_registration(pool, &digest(seed), "test-hash", "customer")
        .await
        .unwrap()
        .expect("complete registration")
}

async fn key_for(pool: &PgPool, user: i64) -> i64 {
    let key = store::create_gateway_key(pool, user, "test key", store::KeyTerms::default(), None)
        .await
        .unwrap();
    store::authenticate_principal(pool, &key)
        .await
        .unwrap()
        .unwrap()
        .key_id
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[test]
fn email_normalization_preserves_aliases_and_dots() {
    assert_eq!(
        store::normalize_email("  Alice.Smith+TAG@Example.COM\t"),
        "alice.smith+tag@example.com"
    );
}

#[tokio::test]
async fn migration_preserves_legacy_users_and_keys_without_backfill() {
    let db = TestDb::new().await;
    let pool = &db.pool;
    let migrator = cardinal::migrator();
    migrator.run_to(30, pool).await.unwrap();
    let group_id = store::create_group(pool, "customer", 10000, None)
        .await
        .unwrap();
    let legacy = store::create_user(
        pool,
        store::NewUser {
            login: "legacy@example.com",
            display_name: "Legacy",
            group_id,
            rate_bp: None,
            max_concurrent: None,
            route_aliases: None,
        },
    )
    .await
    .unwrap();
    let legacy_key = key_for(pool, legacy).await;
    migrator.run(pool).await.unwrap();
    assert_eq!(
        count(pool, "SELECT count(*) FROM account_credentials").await,
        0
    );
    assert!(
        store::create_key_session(pool, legacy, legacy_key, &digest(1), future_expiry())
            .await
            .unwrap()
    );
    let owner = store::owner_user_id(pool).await.unwrap();
    let owner_key = key_for(pool, owner).await;
    assert!(
        store::create_key_session(pool, owner, owner_key, &digest(2), future_expiry())
            .await
            .unwrap()
    );
    let customer = register(pool, 3, "legacy@example.com").await;
    assert_ne!(
        customer, legacy,
        "registering must not claim the existing billing user"
    );
    assert_eq!(
        store::get_user(pool, legacy)
            .await
            .unwrap()
            .unwrap()
            .display_name,
        "Legacy"
    );
    let user = store::get_user(pool, customer).await.unwrap().unwrap();
    assert_eq!((user.group_id, user.balance_microus), (group_id, 0));
    assert!(
        store::list_gateway_keys(pool, Some(customer))
            .await
            .unwrap()
            .is_empty()
    );
    db.close().await;
}

#[tokio::test]
async fn concurrent_registration_consumes_once_and_normalized_email_is_unique() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let a = digest(1);
    let b = digest(2);
    assert!(
        store::issue_registration_challenge(pool, " ALICE@example.COM", &a, future_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::issue_registration_challenge(pool, "alice@example.com", &b, future_expiry())
            .await
            .unwrap()
    );
    let (a, b, c) = tokio::join!(
        store::complete_registration(pool, &a, "test-a", "customer"),
        store::complete_registration(pool, &a, "test-b", "customer"),
        store::complete_registration(pool, &b, "test-c", "customer"),
    );
    let created = [a.unwrap(), b.unwrap(), c.unwrap()];
    assert_eq!(
        created.iter().flatten().count(),
        1,
        "one normalized address may register exactly once"
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM account_credentials").await,
        1
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM users").await,
        2,
        "owner plus one customer, no orphan billing user"
    );
    assert_eq!(
        count(
            pool,
            "SELECT count(*) FROM account_challenges WHERE consumed_at IS NOT NULL"
        )
        .await,
        1
    );
    let credential = store::lookup_account_credential(pool, " aLiCe@example.com ")
        .await
        .unwrap()
        .unwrap();
    assert!(created.contains(&Some(credential.user_id)));
    assert!(
        !store::issue_registration_challenge(
            pool,
            "alice@example.com",
            &digest(3),
            future_expiry()
        )
        .await
        .unwrap()
    );
    db.close().await;
}

#[tokio::test]
async fn database_rejects_non_normalized_and_duplicate_credential_emails() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let email = "direct@example.com";
    register(pool, 1, email).await;
    let owner = store::owner_user_id(pool).await.unwrap();

    let mixed_case = sqlx::query(
        "INSERT INTO account_credentials (user_id, email, password_hash)
         VALUES ($1, 'MixedCase@example.com', 'test-hash')",
    )
    .bind(owner)
    .execute(pool)
    .await;
    let error = mixed_case.expect_err("mixed-case direct SQL write must fail");
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514"),
        "mixed-case email must violate the normalized-email CHECK"
    );

    let mixed_case_challenge = sqlx::query(
        "INSERT INTO account_challenges (token_digest, email, expires_at)
         VALUES ($1, 'MixedCase@example.com', now() + interval '1 hour')",
    )
    .bind(digest(2).as_slice())
    .execute(pool)
    .await;
    let error = mixed_case_challenge.expect_err("mixed-case challenge write must fail");
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514"),
        "mixed-case challenge email must violate the normalized-email CHECK"
    );

    let duplicate = sqlx::query(
        "INSERT INTO account_credentials (user_id, email, password_hash)
         VALUES ($1, $2, 'test-hash')",
    )
    .bind(owner)
    .bind(email)
    .execute(pool)
    .await;
    let error = duplicate.expect_err("duplicate normalized direct SQL write must fail");
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23505"),
        "normalized duplicate must violate the unique constraint"
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM account_credentials").await,
        1,
        "rejected direct writes must not persist credentials"
    );
    db.close().await;
}

#[tokio::test]
async fn registration_rolls_back_when_credential_write_fails() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let token = digest(1);
    let email = "rollback@example.com";
    assert!(
        store::issue_registration_challenge(pool, email, &token, future_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::complete_registration(pool, &token, "", "customer")
            .await
            .is_err()
    );
    assert!(
        store::lookup_account_credential(pool, email)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        count(pool, "SELECT count(*) FROM users").await,
        1,
        "failed credential write must roll back the new user"
    );
    for group in ["internal", "Owner", "not-configured"] {
        assert!(
            store::configured_group(pool, group)
                .await
                .unwrap()
                .is_none(),
            "must refuse {group}"
        );
        assert!(
            store::complete_registration(pool, &token, "test-hash", group)
                .await
                .is_err()
        );
    }
    let group = store::configured_group(pool, "customer")
        .await
        .unwrap()
        .expect("valid group");
    let user = store::complete_registration(pool, &token, "test-hash", "customer")
        .await
        .unwrap()
        .expect("challenge survives rollback");
    assert_eq!(
        store::get_user(pool, user).await.unwrap().unwrap().group_id,
        group
    );
    db.close().await;
}

#[tokio::test]
async fn challenges_are_expiring_and_purpose_bound() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    assert!(
        store::issue_registration_challenge(pool, "expired@example.com", &digest(1), past_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::complete_registration(pool, &digest(1), "test-hash", "customer")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store::issue_registration_challenge(
            pool,
            "purpose@example.com",
            &digest(2),
            future_expiry()
        )
        .await
        .unwrap()
    );
    assert!(
        !store::complete_password_reset(pool, &digest(2), "new-hash")
            .await
            .unwrap()
    );
    assert!(
        !store::issue_password_reset_challenge(
            pool,
            "purpose@example.com",
            &digest(3),
            future_expiry()
        )
        .await
        .unwrap()
    );
    assert!(
        store::complete_registration(pool, &digest(2), "test-hash", "customer")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store::issue_password_reset_challenge(
            pool,
            " PURPOSE@EXAMPLE.COM ",
            &digest(3),
            future_expiry()
        )
        .await
        .unwrap()
    );
    assert!(
        store::complete_registration(pool, &digest(3), "test-hash", "customer")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store::issue_password_reset_challenge(
            pool,
            "purpose@example.com",
            &digest(4),
            past_expiry()
        )
        .await
        .unwrap()
    );
    assert!(
        !store::complete_password_reset(pool, &digest(4), "new-hash")
            .await
            .unwrap()
    );
    db.close().await;
}

#[tokio::test]
async fn reset_is_atomic_and_revokes_only_account_sessions() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let email = "reset@example.com";
    let user = register(pool, 1, email).await;
    let key = key_for(pool, user).await;
    let version = store::lookup_account_credential(pool, email)
        .await
        .unwrap()
        .unwrap()
        .password_version;
    assert!(
        store::create_account_session(pool, user, version, &digest(2), future_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::create_key_session(pool, user, key, &digest(3), future_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::issue_password_reset_challenge(pool, email, &digest(4), future_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::complete_password_reset(pool, &digest(4), "")
            .await
            .is_err()
    );
    assert!(
        store::lookup_session(pool, &digest(2))
            .await
            .unwrap()
            .is_some(),
        "failed reset may not revoke the existing session"
    );
    let token = digest(4);
    let (a, b) = tokio::join!(
        store::complete_password_reset(pool, &token, "updated-hash"),
        store::complete_password_reset(pool, &token, "updated-hash")
    );
    assert_ne!(
        a.unwrap(),
        b.unwrap(),
        "only one reset can consume the challenge"
    );
    assert!(
        store::lookup_session(pool, &digest(2))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store::lookup_session(pool, &digest(3))
            .await
            .unwrap()
            .unwrap()
            .key_id,
        Some(key)
    );
    let updated = store::lookup_account_credential(pool, email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.password_hash, "updated-hash");
    assert_eq!(updated.password_version, version + 1);
    assert!(
        !store::create_account_session(pool, user, version, &digest(5), future_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::create_account_session(
            pool,
            user,
            updated.password_version,
            &digest(5),
            future_expiry()
        )
        .await
        .unwrap()
    );
    db.close().await;
}

#[tokio::test]
async fn login_waiting_on_reset_rechecks_the_password_version() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user = register(pool, 1, "racing@example.com").await;
    let version = store::lookup_account_credential(pool, "racing@example.com")
        .await
        .unwrap()
        .unwrap()
        .password_version;
    let mut tx = pool.begin().await.unwrap();
    // Hold the same credential row lock a password reset holds until commit.
    sqlx::query(
        "UPDATE account_credentials SET password_version = password_version + 1 WHERE user_id = $1",
    )
    .bind(user)
    .execute(&mut *tx)
    .await
    .unwrap();
    let token = digest(2);
    let mut login = Box::pin(store::create_account_session(
        pool,
        user,
        version,
        &token,
        future_expiry(),
    ));
    tokio::select! {
        result = &mut login => panic!("login bypassed the reset row lock: {result:?}"),
        result = wait_for_blocked_login(pool) => result,
    }
    tx.commit().await.unwrap();
    assert!(
        !login.await.unwrap(),
        "old password must not sign a session after reset commits"
    );
    assert!(store::lookup_session(pool, &token).await.unwrap().is_none());
    db.close().await;
}

async fn wait_for_blocked_login(pool: &PgPool) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%INSERT INTO portal_sessions%')").fetch_one(pool).await.unwrap();
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("login must wait on the credential lock");
}

#[tokio::test]
async fn key_session_rechecks_expiry_revocation_ownership_and_enabled_state() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user = register(pool, 1, "keys@example.com").await;
    let other = register(pool, 2, "other@example.com").await;
    let key = key_for(pool, user).await;
    assert!(
        !store::create_key_session(pool, other, key, &digest(3), future_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::create_key_session(pool, user, key, &digest(3), future_expiry())
            .await
            .unwrap()
    );
    assert_eq!(
        store::lookup_session(pool, &digest(3))
            .await
            .unwrap()
            .unwrap()
            .user_id,
        user
    );
    assert!(store::revoke_session(pool, &digest(3)).await.unwrap());
    assert!(!store::revoke_session(pool, &digest(3)).await.unwrap());
    assert!(
        store::lookup_session(pool, &digest(3))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store::create_key_session(pool, user, key, &digest(4), past_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::lookup_session(pool, &digest(4))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store::create_key_session(pool, user, key, &digest(5), future_expiry())
            .await
            .unwrap()
    );
    sqlx::query("UPDATE gateway_keys SET enabled = false WHERE id = $1")
        .bind(key)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        store::lookup_session(pool, &digest(5))
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("UPDATE gateway_keys SET enabled = true, expires_at = $2 WHERE id = $1")
        .bind(key)
        .bind(past_expiry().to_sqlx())
        .execute(pool)
        .await
        .unwrap();
    assert!(
        store::lookup_session(pool, &digest(5))
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("UPDATE gateway_keys SET expires_at = NULL, user_id = $2 WHERE id = $1")
        .bind(key)
        .bind(other)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        store::lookup_session(pool, &digest(5))
            .await
            .unwrap()
            .is_none()
    );
    db.close().await;
}

#[tokio::test]
async fn account_session_expiry_and_revocation_invalidate_lookup() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user = register(pool, 1, "lifecycle@example.com").await;
    let version = store::lookup_account_credential(pool, "lifecycle@example.com")
        .await
        .unwrap()
        .unwrap()
        .password_version;
    assert!(
        store::create_account_session(pool, user, version, &digest(2), past_expiry())
            .await
            .unwrap()
    );
    assert!(
        store::lookup_session(pool, &digest(2))
            .await
            .unwrap()
            .is_none(),
        "expired account session must not resolve"
    );

    let token = digest(3);
    assert!(
        store::create_account_session(pool, user, version, &token, future_expiry())
            .await
            .unwrap()
    );
    assert_eq!(
        store::lookup_session(pool, &token)
            .await
            .unwrap()
            .unwrap()
            .key_id,
        None,
        "live account session must resolve before revocation"
    );
    assert!(store::revoke_session(pool, &token).await.unwrap());
    assert!(!store::revoke_session(pool, &token).await.unwrap());
    assert!(
        store::lookup_session(pool, &token).await.unwrap().is_none(),
        "revoked account session must not resolve"
    );
    db.close().await;
}

#[tokio::test]
async fn account_session_requires_enabled_user_and_existing_credential() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user = register(pool, 1, "account@example.com").await;
    let version = store::lookup_account_credential(pool, "account@example.com")
        .await
        .unwrap()
        .unwrap()
        .password_version;
    assert!(
        store::create_account_session(pool, user, version, &digest(2), future_expiry())
            .await
            .unwrap()
    );
    sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        store::lookup_session(pool, &digest(2))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !store::create_account_session(pool, user, version, &digest(3), future_expiry())
            .await
            .unwrap()
    );
    sqlx::query("UPDATE users SET enabled = true WHERE id = $1")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM account_credentials WHERE user_id = $1")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        store::lookup_session(pool, &digest(2))
            .await
            .unwrap()
            .is_none()
    );
    db.close().await;
}
