//! Gateway HTTP tests. Set CARDINAL_TEST_DATABASE_URL to an isolated PostgreSQL
//! 18 cluster with TimescaleDB preloaded and a role allowed to create databases.

use std::time::Duration;

use cardinal::config::Config;
use cardinal::db::parse_pg_options;
use cardinal::gateway::Gateway;
use cardinal::store;
use reqwest::{Client, Response, StatusCode, Url};
use salvo::affix_state;
use salvo::conn::{Acceptor as _, Listener as _};
use salvo::{Depot, Request, Router, Server, handler};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use sqlx::{ConnectOptions as _, PgPool, Postgres};
use tokio::sync::mpsc;

const ADMIN_KEY: &str = "config-seeded-admin-key";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "different correct horse battery staple";
const EMAIL: &str = "alice.smith+tag@example.com";
const ORIGIN: &str = "https://portal.example.com";
const WAIT: Duration = Duration::from_secs(15);

struct Fixture {
    gateway: Gateway,
    pool: PgPool,
    dsn: String,
    client: Client,
    inbox: mpsc::UnboundedReceiver<Value>,
    mock: tokio::task::JoinHandle<()>,
    group_id: i64,
}

#[handler]
async fn receive_mail(request: &mut Request, depot: &mut Depot) -> salvo::http::StatusCode {
    assert_eq!(request.headers()["authorization"], "Bearer mock-secret");
    let message: Value = request.parse_json().await.unwrap();
    depot
        .get_typed::<mpsc::UnboundedSender<Value>>()
        .unwrap()
        .send(message)
        .unwrap();
    salvo::http::StatusCode::OK
}

impl Fixture {
    async fn start(group: Option<&str>, mail: bool) -> Self {
        let dsn = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&dsn).unwrap();
        let name = format!("cardinal_auth_http_{}", uuid::Uuid::new_v4().simple());
        let options = options.database(&name);
        let dsn = options.to_url_lossy().to_string();
        Postgres::create_database(&dsn).await.unwrap();
        let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
        sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .execute(&pool)
            .await
            .unwrap();
        let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0")
            .try_bind()
            .await
            .unwrap();
        let mail_addr = acceptor.holdings()[0].local_addr.to_string();
        let port = mail_addr.rsplit(':').next().expect("mock mail port");
        let mail_url = format!("http://127.0.0.1:{port}/emails");
        let (sender, inbox) = mpsc::unbounded_channel::<Value>();
        let mail_router = Router::with_path("emails")
            .hoop(affix_state::inject(sender))
            .post(receive_mail);
        let mock = tokio::spawn(Server::new(acceptor).serve(mail_router));
        let config = fixture_config(&dsn, group, mail.then_some(mail_url.as_str()));
        let gateway = Gateway::start(config).await.unwrap();
        let group_id = store::create_group(&pool, "customer", 10000, None)
            .await
            .unwrap();
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(WAIT)
            .build()
            .unwrap();
        Self {
            gateway,
            pool,
            dsn,
            client,
            inbox,
            mock,
            group_id,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.gateway.local_addr())
    }

    async fn post(&self, path: &str, body: Value) -> Response {
        let response = self
            .client
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("location"));
        response
    }

    async fn assert_post(&self, path: &str, body: Value, status: StatusCode) -> String {
        let response = self.post(path, body).await;
        assert_eq!(response.status(), status, "{path}");
        let body = response.text().await.unwrap();
        assert!(!body.contains("ps_") && !body.contains(PASSWORD));
        body
    }

    async fn link(&mut self, path: &str, email: &str) -> String {
        let message = tokio::time::timeout(WAIT, self.inbox.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message["from"], "Cardinal <auth@example.com>");
        assert_eq!(message["to"], json!([email]));
        let link = message["text"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .find(|part| part.starts_with(ORIGIN))
            .expect("mail contains a portal link");
        let link = Url::parse(link).unwrap();
        assert_eq!(link.origin().ascii_serialization(), ORIGIN);
        assert_eq!(link.path(), path);
        assert!(link.query().is_none());
        let token = link
            .fragment()
            .and_then(|f| f.strip_prefix("token="))
            .unwrap();
        assert_eq!(token.len(), 43);
        token.to_owned()
    }

    async fn register(&mut self) -> (i64, String) {
        let accepted = self
            .assert_post(
                "/auth/register",
                json!({"email":" Alice.Smith+TAG@Example.COM "}),
                StatusCode::ACCEPTED,
            )
            .await;
        let token = self.link("/register/verify", EMAIL).await;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT token_digest FROM account_challenges WHERE email = $1")
                .bind(EMAIL)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        assert_eq!(stored, digest);
        self.assert_post(
            "/auth/register/complete",
            json!({"token":token,"password":PASSWORD}),
            StatusCode::NO_CONTENT,
        )
        .await;
        let credential = store::lookup_account_credential(&self.pool, EMAIL)
            .await
            .unwrap()
            .unwrap();
        assert!(credential.password_hash.starts_with("$argon2id$"));
        let user = store::get_user(&self.pool, credential.user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((user.group_id, user.balance_microus), (self.group_id, 0));
        (credential.user_id, accepted)
    }

    async fn session(&self, path: &str, body: Value) -> String {
        let response = self.post(path, body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = response.json().await.unwrap();
        let token = value["token"].as_str().unwrap();
        assert!(token.starts_with("ps_"));
        assert_eq!(token.len(), 46);
        let expiry: jiff::Timestamp = value["expires_at"].as_str().unwrap().parse().unwrap();
        assert!(expiry > jiff::Timestamp::now());
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        assert!(
            store::lookup_session(&self.pool, &digest)
                .await
                .unwrap()
                .is_some()
        );
        token.to_owned()
    }

    async fn logout(&self, token: &str, status: StatusCode) {
        let response = self
            .client
            .post(self.url("/auth/logout"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert!(response.bytes().await.unwrap().is_empty() || status == StatusCode::UNAUTHORIZED);
    }

    async fn close(self) {
        self.gateway.shutdown().await.unwrap();
        self.mock.abort();
        self.pool.close().await;
        Postgres::drop_database(&self.dsn).await.unwrap();
    }
}

fn fixture_config(dsn: &str, group: Option<&str>, mail: Option<&str>) -> Config {
    let mut config = format!(
        "listen = '127.0.0.1:0'\nsql_dsn = '{dsn}'\ngateway_key = '{ADMIN_KEY}'\n[portal]\n"
    );
    if let Some(group) = group {
        config.push_str(&format!("default_customer_group = '{group}'\n"));
    }
    if let Some(url) = mail {
        config.push_str(&format!("[portal.mail]\nurl = '{url}'\ntoken = 'mock-secret'\nfrom = 'Cardinal <auth@example.com>'\norigin = '{ORIGIN}'\n"));
    }
    toml::from_str(&config).unwrap()
}

#[tokio::test]
async fn account_auth_registration_validates_and_does_not_disclose_duplicates() {
    let mut app = Fixture::start(Some("customer"), true).await;
    let (_, accepted) = app.register().await;
    let duplicate = app
        .assert_post(
            "/auth/register",
            json!({"email":EMAIL}),
            StatusCode::ACCEPTED,
        )
        .await;
    assert_eq!(duplicate, accepted);
    app.assert_post(
        "/auth/register",
        json!({"email":"other@example.com"}),
        StatusCode::ACCEPTED,
    )
    .await;
    let other = app.link("/register/verify", "other@example.com").await;
    app.assert_post(
        "/auth/register/complete",
        json!({"token":"A".repeat(43),"password":PASSWORD}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let digest: [u8; 32] = Sha256::digest(other.as_bytes()).into();
    sqlx::query("UPDATE account_challenges SET expires_at = now() - interval '1 second' WHERE token_digest = $1")
        .bind(digest.as_slice()).execute(&app.pool).await.unwrap();
    app.assert_post(
        "/auth/register/complete",
        json!({"token":other,"password":PASSWORD}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    app.close().await;
}

#[tokio::test]
async fn account_auth_password_reset_revokes_account_sessions_only() {
    let mut app = Fixture::start(Some("customer"), true).await;
    let (user_id, _) = app.register().await;
    let account = app
        .session("/auth/login", json!({"email":EMAIL,"password":PASSWORD}))
        .await;
    let key = store::create_gateway_key(
        &app.pool,
        user_id,
        "ordinary",
        store::KeyTerms::default(),
        None,
    )
    .await
    .unwrap();
    let key_session = app.session("/auth/key-login", json!({"key":key})).await;
    let wrong = app
        .assert_post(
            "/auth/login",
            json!({"email":EMAIL,"password":NEW_PASSWORD}),
            StatusCode::UNAUTHORIZED,
        )
        .await;
    let unknown = app
        .assert_post(
            "/auth/login",
            json!({"email":"unknown@example.com","password":NEW_PASSWORD}),
            StatusCode::UNAUTHORIZED,
        )
        .await;
    assert_eq!(wrong, unknown);
    let forgot_unknown = app
        .assert_post(
            "/auth/password/forgot",
            json!({"email":"unknown@example.com"}),
            StatusCode::ACCEPTED,
        )
        .await;
    let forgot_known = app
        .assert_post(
            "/auth/password/forgot",
            json!({"email":EMAIL}),
            StatusCode::ACCEPTED,
        )
        .await;
    assert_eq!(forgot_unknown, forgot_known);
    let token = app.link("/reset-password", EMAIL).await;
    app.assert_post(
        "/auth/password/reset",
        json!({"token":token,"password":NEW_PASSWORD}),
        StatusCode::NO_CONTENT,
    )
    .await;
    app.assert_post(
        "/auth/password/reset",
        json!({"token":token,"password":PASSWORD}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    app.assert_post(
        "/auth/login",
        json!({"email":EMAIL,"password":PASSWORD}),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let replacement = app
        .session(
            "/auth/login",
            json!({"email":EMAIL,"password":NEW_PASSWORD}),
        )
        .await;
    let digest: [u8; 32] = Sha256::digest(account.as_bytes()).into();
    assert!(
        store::lookup_session(&app.pool, &digest)
            .await
            .unwrap()
            .is_none()
    );
    let digest: [u8; 32] = Sha256::digest(key_session.as_bytes()).into();
    assert_eq!(
        store::lookup_session(&app.pool, &digest)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        user_id
    );
    app.logout(&replacement, StatusCode::NO_CONTENT).await;
    app.logout(&replacement, StatusCode::NO_CONTENT).await;
    let response = app
        .client
        .post(app.url("/auth/logout"))
        .bearer_auth(&key_session)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    app.logout(&key, StatusCode::UNAUTHORIZED).await;
    app.logout(&key_session, StatusCode::NO_CONTENT).await;
    app.close().await;
}

#[tokio::test]
async fn account_auth_key_login_does_not_change_existing_http_auth_boundaries() {
    let app = Fixture::start(None, false).await;
    let owner = store::owner_user_id(&app.pool).await.unwrap();
    let key = store::create_gateway_key(
        &app.pool,
        owner,
        "ordinary",
        store::KeyTerms::default(),
        None,
    )
    .await
    .unwrap();
    let portal = app.session("/auth/key-login", json!({"key":key})).await;
    app.assert_post(
        "/auth/key-login",
        json!({"key":ADMIN_KEY}),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    for (path, credential, status) in [
        ("/v1/models", key.as_str(), StatusCode::OK),
        ("/v1beta/models", key.as_str(), StatusCode::OK),
        ("/user/me", key.as_str(), StatusCode::OK),
        ("/api/users", ADMIN_KEY, StatusCode::OK),
        ("/api/users", portal.as_str(), StatusCode::UNAUTHORIZED),
        ("/v1/models", portal.as_str(), StatusCode::UNAUTHORIZED),
        ("/v1beta/models", portal.as_str(), StatusCode::UNAUTHORIZED),
    ] {
        let response = app
            .client
            .get(app.url(path))
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{path}");
        if status == StatusCode::UNAUTHORIZED {
            assert!(
                !response
                    .text()
                    .await
                    .unwrap()
                    .contains(&portal[portal.len() - 4..]),
                "credential tail must not be echoed"
            );
        }
    }
    sqlx::query("UPDATE gateway_keys SET enabled = false WHERE key_plaintext = $1")
        .bind(&key)
        .execute(&app.pool)
        .await
        .unwrap();
    let response = app
        .client
        .get(app.url("/v1/models"))
        .bearer_auth(&portal)
        .header("x-api-key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    app.close().await;
}

#[tokio::test]
async fn account_auth_missing_or_reserved_config_disables_registration() {
    for (group, mail) in [
        (Some("customer"), false),
        (None, true),
        (Some("internal"), true),
        (Some("owner"), true),
        (Some("does-not-exist"), true),
    ] {
        let app = Fixture::start(group, mail).await;
        app.assert_post(
            "/auth/register",
            json!({"email":EMAIL}),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
        app.assert_post(
            "/auth/password/forgot",
            json!({"email":EMAIL}),
            if mail {
                StatusCode::ACCEPTED
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
        )
        .await;
        app.assert_post(
            "/auth/register/complete",
            json!({"token":"A".repeat(43),"password":PASSWORD}),
            StatusCode::BAD_REQUEST,
        )
        .await;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account_challenges")
            .fetch_one(&app.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        app.close().await;
    }
}

#[tokio::test]
async fn account_auth_rejects_abnormal_input_and_limits_normalized_email() {
    let app = Fixture::start(None, false).await;
    let form = app
        .client
        .post(app.url("/auth/login"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(form.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    app.assert_post(
        "/auth/login",
        json!({"email":"alice@example.com\0","password":PASSWORD}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    app.assert_post(
        "/auth/login",
        json!({"email":EMAIL,"password":"x".repeat(1025)}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    app.assert_post(
        "/auth/login",
        json!({"email":EMAIL,"password":"x".repeat(8192)}),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;
    for attempt in 0..=5 {
        let email = if attempt % 2 == 0 {
            EMAIL
        } else {
            " Alice.Smith+Tag@EXAMPLE.COM "
        };
        let expected = if attempt == 5 {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::UNAUTHORIZED
        };
        app.assert_post(
            "/auth/login",
            json!({"email":email,"password":PASSWORD}),
            expected,
        )
        .await;
    }
    app.close().await;
}

#[tokio::test]
async fn account_auth_store_failure_returns_no_credentials() {
    let mut app = Fixture::start(Some("customer"), true).await;
    app.register().await;
    sqlx::query(
        "ALTER TABLE portal_sessions ADD CONSTRAINT deny_test_session CHECK (false) NOT VALID",
    )
    .execute(&app.pool)
    .await
    .unwrap();
    let response = app
        .post("/auth/login", json!({"email":EMAIL,"password":PASSWORD}))
        .await;
    assert!(response.status().is_server_error());
    let body = response.text().await.unwrap();
    assert!(
        !body.contains("ps_") && !body.contains(PASSWORD) && !body.contains("deny_test_session")
    );
    app.close().await;
}
