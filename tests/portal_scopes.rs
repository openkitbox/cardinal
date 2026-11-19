//! Portal scope integration tests. Set CARDINAL_TEST_DATABASE_URL to an isolated
//! PostgreSQL 18 cluster with TimescaleDB >= 2.31 and database-create access.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cardinal::config::Config;
use cardinal::db::parse_pg_options;
use cardinal::gateway::Gateway;
use cardinal::store;
use jiff_sqlx::ToSqlx;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use sqlx::{ConnectOptions as _, PgPool, Postgres};

const ADMIN_KEY: &str = "portal-scope-admin-key";
const WAIT: Duration = Duration::from_secs(30);

struct Fixture {
    gateway: Gateway,
    pool: PgPool,
    dsn: String,
    client: Client,
    owner_user: i64,
    user_a: i64,
    user_b: i64,
    zero_key_user: i64,
    owner_key: String,
    a_key: String,
    b_key: String,
    owner_key_id: i64,
    a_key_id: i64,
    a_other_key_id: i64,
    b_key_id: i64,
    disabled_key: String,
    expired_key: String,
    account_token: String,
    zero_key_account_token: String,
    owner_key_session: String,
    key_session: String,
    expired_session: String,
}

impl Fixture {
    async fn new() -> Self {
        let base_url = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&base_url).expect("parse test DSN");
        let name = format!("cardinal_portal_scope_{}", uuid::Uuid::new_v4().simple());
        let options = options.database(&name);
        let dsn = options.to_url_lossy().to_string();
        Postgres::create_database(&dsn)
            .await
            .expect("create isolated test database");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .expect("connect to isolated test database");
        sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .execute(&pool)
            .await
            .expect("install TimescaleDB");

        let config = fixture_config(&dsn);
        let gateway = Gateway::start(config).await.expect("start gateway");
        let group_id = store::create_group(&pool, "customer", 10000, None)
            .await
            .expect("create customer group");
        let user_a = register(&pool, 1, "alice@example.com", group_id).await;
        let user_b = register(&pool, 2, "bob@example.com", group_id).await;
        let zero_key_user = register(&pool, 3, "zero@example.com", group_id).await;
        let owner_user = store::owner_user_id(&pool)
            .await
            .expect("lookup owner user");
        let owner_key = create_key(&pool, owner_user, "owner-main").await;
        let a_key = create_key(&pool, user_a, "alice-main").await;
        let a_other_key = create_key(&pool, user_a, "alice-other").await;
        let b_key = create_key(&pool, user_b, "bob-main").await;
        let owner_key_id = key_id(&pool, &owner_key).await;
        let a_key_id = key_id(&pool, &a_key).await;
        let a_other_key_id = key_id(&pool, &a_other_key).await;
        let b_key_id = key_id(&pool, &b_key).await;
        let disabled_key = create_key(&pool, user_a, "alice-disabled").await;
        let expired_key = create_key(&pool, user_a, "alice-expired").await;
        sqlx::query("UPDATE gateway_keys SET enabled = false WHERE key_plaintext = $1")
            .bind(&disabled_key)
            .execute(&pool)
            .await
            .expect("disable fixture key");
        sqlx::query(
            "UPDATE gateway_keys SET expires_at = now() - interval '1 hour' WHERE key_plaintext = $1",
        )
        .bind(&expired_key)
        .execute(&pool)
        .await
        .expect("expire fixture key");

        let account_token = session_token('A');
        let account_digest = digest(&account_token);
        assert_eq!(
            account_digest.as_slice(),
            Sha256::digest(account_token.as_bytes()).as_slice(),
            "test session digest must match the token"
        );
        let account_credential = store::lookup_account_credential(&pool, "alice@example.com")
            .await
            .expect("lookup account credential")
            .expect("account credential exists");
        assert!(
            store::create_account_session(
                &pool,
                user_a,
                account_credential.password_version,
                &account_digest,
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
            )
            .await
            .expect("create account session")
        );
        assert!(
            store::lookup_session(&pool, &account_digest)
                .await
                .expect("lookup account session")
                .is_some()
        );
        let zero_key_account_token = session_token('Z');
        let zero_key_account_digest = digest(&zero_key_account_token);
        let zero_key_credential = store::lookup_account_credential(&pool, "zero@example.com")
            .await
            .expect("lookup zero-key account credential")
            .expect("zero-key account credential exists");
        assert!(
            store::create_account_session(
                &pool,
                zero_key_user,
                zero_key_credential.password_version,
                &zero_key_account_digest,
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
            )
            .await
            .expect("create zero-key account session")
        );
        let owner_key_session = session_token('O');
        let owner_key_digest = digest(&owner_key_session);
        assert!(
            store::create_key_session(
                &pool,
                owner_user,
                owner_key_id,
                &owner_key_digest,
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
            )
            .await
            .expect("create owner key session")
        );
        let key_session = session_token('B');
        let key_digest = digest(&key_session);
        assert!(
            store::create_key_session(
                &pool,
                user_a,
                a_key_id,
                &key_digest,
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
            )
            .await
            .expect("create key session")
        );
        let expired_session = session_token('E');
        let expired_digest = digest(&expired_session);
        assert!(
            store::create_key_session(
                &pool,
                user_a,
                a_key_id,
                &expired_digest,
                jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1),
            )
            .await
            .expect("create expired key session")
        );
        seed_usage(&pool, user_a, user_b, a_key_id, a_other_key_id, b_key_id).await;
        store::credit(
            &pool,
            user_a,
            store::CreditKind::Topup,
            1_000_000,
            "scope fixture A",
            "portal test",
        )
        .await
        .expect("credit user A")
        .expect("user A exists");
        store::credit(
            &pool,
            user_b,
            store::CreditKind::Topup,
            2_000_000,
            "scope fixture B",
            "portal test",
        )
        .await
        .expect("credit user B")
        .expect("user B exists");
        seed_key_charge(&pool, user_a, a_key_id).await;
        let client = Client::builder()
            .timeout(WAIT)
            .build()
            .expect("build HTTP client");
        Self {
            gateway,
            pool,
            dsn,
            client,
            owner_user,
            user_a,
            user_b,
            zero_key_user,
            owner_key,
            a_key,
            b_key,
            owner_key_id,
            a_key_id,
            a_other_key_id,
            b_key_id,
            disabled_key,
            expired_key,
            account_token,
            zero_key_account_token,
            owner_key_session,
            key_session,
            expired_session,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.gateway.local_addr())
    }

    async fn post_status(&self, token: &str, path: &str) -> StatusCode {
        self.client
            .post(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("POST request")
            .status()
    }

    async fn get(&self, token: &str, path: &str) -> (StatusCode, Value) {
        let response = self
            .client
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("GET request");
        let status = response.status();
        let text = response.text().await.expect("read response");
        let body = serde_json::from_str(&text).unwrap_or_else(|error| {
            panic!("JSON response for {path} (status {status}): {error}; body={text:?}")
        });
        (status, body)
    }

    async fn status(&self, token: &str, path: &str) -> StatusCode {
        self.client
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("GET request")
            .status()
    }

    async fn patch(&self, token: &str, id: i64) -> StatusCode {
        self.client
            .patch(self.url(&format!("/user/keys/{id}")))
            .bearer_auth(token)
            .json(&json!({"label":"renamed"}))
            .send()
            .await
            .expect("PATCH request")
            .status()
    }

    async fn close(self) {
        self.gateway.shutdown().await.expect("shutdown gateway");
        self.pool.close().await;
        Postgres::drop_database(&self.dsn)
            .await
            .expect("drop isolated test database");
    }
}

fn fixture_config(dsn: &str) -> Config {
    toml::from_str(&format!(
        "listen = '127.0.0.1:0'\nsql_dsn = '{dsn}'\ngateway_key = '{ADMIN_KEY}'\n"
    ))
    .expect("parse fixture config")
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn session_token(letter: char) -> String {
    let bytes = [letter as u8; 32];
    format!("ps_{}", URL_SAFE_NO_PAD.encode(bytes))
}

async fn register(pool: &PgPool, seed: u8, email: &str, group_id: i64) -> i64 {
    let challenge = [seed; 32];
    assert!(
        store::issue_registration_challenge(
            pool,
            email,
            &challenge,
            jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
        )
        .await
        .expect("issue registration challenge")
    );
    let user_id = store::complete_registration(pool, &challenge, "test-hash", "customer")
        .await
        .expect("complete registration")
        .expect("registered user");
    let actual_group: i64 = sqlx::query_scalar("SELECT group_id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("read registered group");
    assert_eq!(actual_group, group_id);
    user_id
}

async fn create_key(pool: &PgPool, user_id: i64, label: &str) -> String {
    store::create_gateway_key(pool, user_id, label, store::KeyTerms::default(), None)
        .await
        .expect("create gateway key")
}

async fn seed_usage(
    pool: &PgPool,
    user_a: i64,
    user_b: i64,
    a_key_id: i64,
    a_other_key_id: i64,
    b_key_id: i64,
) {
    let now = jiff::Timestamp::now();
    let rows = [
        (user_a, a_key_id, "a-main-1", 10_i64, 20_i64, "a-main"),
        (user_a, a_key_id, "a-main-2", 30_i64, 40_i64, "a-main"),
        (user_a, a_other_key_id, "a-other", 70_i64, 80_i64, "a-other"),
        (user_b, b_key_id, "b-main", 1_000_i64, 2_000_i64, "b-main"),
    ];
    for (user_id, key_id, request_id, input_tokens, output_tokens, caller_key) in rows {
        sqlx::query(
            "INSERT INTO gateway_requests
                (ts, protocol, alias, status, input_tokens, output_tokens,
                 cached_input_tokens, total_ms, cost_usd, charged_microus,
                 caller_key, gateway_key_id, user_id, request_id)
             VALUES ($1, 'fixture', $2, 200, $3, $4, 0, 25, $5, $6, $7, $8, $9, $10)",
        )
        .bind(now.to_sqlx())
        .bind(request_id)
        .bind(input_tokens)
        .bind(output_tokens)
        .bind((input_tokens + output_tokens) as f64 / 1_000_000.0)
        .bind(input_tokens + output_tokens)
        .bind(caller_key)
        .bind(key_id)
        .bind(user_id)
        .bind(request_id)
        .execute(pool)
        .await
        .expect("insert usage fixture row");
    }
}

async fn seed_key_charge(pool: &PgPool, user_id: i64, key_id: i64) {
    let mut tx = pool.begin().await.expect("begin key ledger fixture");
    let balance: i64 =
        sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .expect("lock user balance");
    let after = balance - 123_000;
    sqlx::query(
        "INSERT INTO billing_entries
            (user_id, kind, amount_microus, balance_after_microus, request_id,
             cost_microus, rate_bp, gateway_key_id, note, operator)
         VALUES ($1, 'charge', -123000, $2, 'portal-scope-key-charge', 123000, 10000, $3, 'scope fixture key', 'portal test')",
    )
    .bind(user_id)
    .bind(after)
    .bind(key_id)
    .execute(&mut *tx)
    .await
    .expect("insert key ledger fixture");
    sqlx::query("UPDATE users SET balance_microus = $2 WHERE id = $1")
        .bind(user_id)
        .bind(after)
        .execute(&mut *tx)
        .await
        .expect("update fixture balance");
    sqlx::query("UPDATE gateway_keys SET spent_microus = spent_microus + 123000 WHERE id = $1")
        .bind(key_id)
        .execute(&mut *tx)
        .await
        .expect("update fixture key spend");
    tx.commit().await.expect("commit key ledger fixture");
}

async fn key_id(pool: &PgPool, key: &str) -> i64 {
    store::authenticate_principal(pool, key)
        .await
        .expect("authenticate gateway key")
        .expect("gateway key exists")
        .key_id
}

fn assert_no_internal_costs(value: &Value) {
    match value {
        Value::Object(object) => {
            assert!(!object.contains_key("cost_usd"));
            assert!(!object.contains_key("cost_microus"));
            for value in object.values() {
                assert_no_internal_costs(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_no_internal_costs(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn key_ids(body: &Value) -> Vec<i64> {
    body["keys"]
        .as_array()
        .expect("me keys array")
        .iter()
        .map(|key| key["id"].as_i64().expect("key id"))
        .collect()
}

#[tokio::test]
async fn portal_scopes_and_topup() {
    let app = Fixture::new().await;

    let (status, body) = app.get(&app.account_token, "/user/me").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["auth"], json!({"kind":"account","key_id":null}));
    assert_no_internal_costs(&body);
    assert_eq!(key_ids(&body).len(), 4);
    assert!(key_ids(&body).contains(&app.a_key_id));
    assert!(key_ids(&body).contains(&app.a_other_key_id));
    assert_eq!(body["usage_30d"]["requests"], 3);
    assert_eq!(body["usage_30d"]["input_tokens"], 110);
    assert_eq!(body["usage_30d"]["output_tokens"], 140);

    let (status, body) = app.get(&app.zero_key_account_token, "/user/me").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["id"], app.zero_key_user);
    assert_eq!(body["auth"], json!({"kind":"account","key_id":null}));
    assert_no_internal_costs(&body);
    assert!(key_ids(&body).is_empty());
    assert_eq!(body["usage_30d"]["requests"], 0);
    assert_eq!(body["usage_30d"]["input_tokens"], 0);
    assert_eq!(body["usage_30d"]["output_tokens"], 0);
    let (status, body) = app
        .get(&app.zero_key_account_token, "/user/topup/capabilities")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"online_payment_available":false}));

    for token in [&app.owner_key, &app.owner_key_session] {
        let (status, body) = app.get(token, "/user/me").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["id"], app.owner_user);
        assert_eq!(
            body["auth"],
            json!({"kind":"key","key_id":app.owner_key_id})
        );
        assert_no_internal_costs(&body);
        assert_eq!(key_ids(&body), vec![app.owner_key_id]);
        assert_eq!(body["usage_30d"]["requests"], 0);
        let (status, _) = app.get(token, "/user/topup/capabilities").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    for path in ["/user/usage/window", "/user/usage/trend"] {
        let (status, body) = app.get(&app.account_token, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_no_internal_costs(&body);
        if path == "/user/usage/window" {
            assert_eq!(body["requests"], 3);
            assert_eq!(body["input_tokens"], 110);
            assert_eq!(body["output_tokens"], 140);
        } else {
            let items = body["items"].as_array().expect("account trend items");
            assert_eq!(
                items
                    .iter()
                    .map(|item| item["requests"].as_i64().expect("trend requests"))
                    .sum::<i64>(),
                3
            );
        }
    }

    for token in [&app.a_key, &app.key_session] {
        let (status, body) = app.get(token, "/user/me").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["auth"], json!({"kind":"key","key_id":app.a_key_id}));
        assert_no_internal_costs(&body);
        assert_eq!(key_ids(&body), vec![app.a_key_id]);
        assert_eq!(body["usage_30d"]["requests"], 2);
        assert_eq!(body["usage_30d"]["input_tokens"], 40);
        assert_eq!(body["usage_30d"]["output_tokens"], 60);
    }
    let (status, body) = app.get(&app.b_key, "/user/me").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["id"], app.user_b);
    assert_eq!(key_ids(&body), vec![app.b_key_id]);

    for path in [
        "/user/usage/window",
        "/user/usage/trend",
        "/user/me/entries",
    ] {
        let (status, body) = app.get(&app.a_key, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_no_internal_costs(&body);
        if path == "/user/usage/window" {
            assert_eq!(body["requests"], 2);
            assert_eq!(body["input_tokens"], 40);
            assert_eq!(body["output_tokens"], 60);
        } else if path == "/user/usage/trend" {
            let items = body["items"].as_array().expect("trend items");
            assert_eq!(
                items
                    .iter()
                    .map(|item| item["requests"].as_i64().expect("trend requests"))
                    .sum::<i64>(),
                2
            );
        } else {
            let items = body["items"].as_array().expect("ledger items");
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["gateway_key_id"], app.a_key_id);
            assert_eq!(items[0]["amount_microus"], -123_000);
        }
    }
    let (status, body) = app.get(&app.account_token, "/user/me/entries").await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("account ledger items");
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| item["user_id"] == app.user_a));
    assert_no_internal_costs(&body);
    let (status, body) = app.get(&app.account_token, "/user/keys").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().expect("key items").len(), 4);
    let (status, body) = app.get(&app.a_key, "/user/keys").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().expect("key items").len(), 1);

    let create = app
        .client
        .post(app.url("/user/keys"))
        .bearer_auth(&app.a_key)
        .json(&json!({"label":"forbidden"}))
        .send()
        .await
        .expect("key create request");
    assert_eq!(create.status(), StatusCode::FORBIDDEN);
    let create = app
        .client
        .post(app.url("/user/keys"))
        .bearer_auth(&app.account_token)
        .json(&json!({"label":"alice-created"}))
        .send()
        .await
        .expect("account key create request");
    assert_eq!(create.status(), StatusCode::OK);
    assert_eq!(
        app.patch(&app.a_key, app.a_other_key_id).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.patch(&app.account_token, app.a_other_key_id).await,
        StatusCode::OK
    );
    assert_eq!(
        app.patch(&app.account_token, app.b_key_id).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        !store::create_key_session(
            &app.pool,
            app.user_b,
            app.a_key_id,
            &digest("cross-user-session"),
            jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
        )
        .await
        .expect("cross-user key session create")
    );

    let (status, body) = app
        .get(&app.account_token, "/user/topup/capabilities")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"online_payment_available":false}));
    for token in [&app.a_key, &app.key_session] {
        let (status, _) = app.get(token, "/user/topup/capabilities").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    for path in ["/user/topup/orders", "/payments/webhook/test"] {
        assert_eq!(
            app.post_status(&app.account_token, path).await,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }

    let balance_before: i64 = sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1")
        .bind(app.user_a)
        .fetch_one(&app.pool)
        .await
        .expect("read balance");
    let ledger_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM billing_entries WHERE user_id = $1")
            .bind(app.user_a)
            .fetch_one(&app.pool)
            .await
            .expect("read ledger count");
    assert_eq!(balance_before, 877_000);
    assert_eq!(ledger_before, 2);

    let malformed = "ps_not-a-session";
    sqlx::query(
        "INSERT INTO gateway_keys (key_plaintext, label, user_id) VALUES ($1, 'portal-prefix', $2)",
    )
    .bind(malformed)
    .bind(app.user_a)
    .execute(&app.pool)
    .await
    .expect("insert portal-prefix key");
    let status = app.status(malformed, "/user/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let status = app.status(ADMIN_KEY, "/user/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    sqlx::query("UPDATE gateway_keys SET enabled = false WHERE id = $1")
        .bind(app.a_key_id)
        .execute(&app.pool)
        .await
        .expect("disable key");
    let status = app.status(&app.key_session, "/user/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let status = app.status(&app.expired_key, "/user/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let status = app.status(&app.disabled_key, "/user/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let status = app.status(&app.expired_session, "/user/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let balance_after: i64 = sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1")
        .bind(app.user_a)
        .fetch_one(&app.pool)
        .await
        .expect("read balance after capability query");
    let ledger_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM billing_entries WHERE user_id = $1")
            .bind(app.user_a)
            .fetch_one(&app.pool)
            .await
            .expect("read ledger count after capability query");
    assert_eq!(balance_after, balance_before);
    assert_eq!(ledger_after, ledger_before);

    app.close().await;
}
