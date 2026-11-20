//! T2 integration tests: DB-backed portal runtime and its admin API.
//! Set CARDINAL_TEST_DATABASE_URL to an isolated PostgreSQL 18 cluster with
//! TimescaleDB preloaded and a role allowed to create databases.

use std::time::Duration;

use cardinal::config::Config;
use cardinal::db::parse_pg_options;
use cardinal::gateway::Gateway;
use cardinal::store;
use futures::future::join_all;
use reqwest::{Client, Response, StatusCode};
use salvo::affix_state;
use salvo::conn::{Acceptor as _, Listener as _};
use salvo::{Depot, Request, Router, Server, handler};
use serde_json::{Value, json};
use sqlx::ConnectOptions as _;
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres};
use tokio::sync::mpsc;

const ADMIN_KEY: &str = "portal-admin-key";
const EMAIL: &str = "portal-user@example.com";
const ORIGIN: &str = "https://portal.example.com";
const FROM: &str = "Cardinal <auth@example.com>";
const WAIT: Duration = Duration::from_secs(15);

struct Fixture {
    gateway: Gateway,
    pool: PgPool,
    dsn: String,
    client: Client,
    inbox: mpsc::UnboundedReceiver<Value>,
    mock: tokio::task::JoinHandle<()>,
    mail_url: String,
}

#[handler]
async fn receive_mail(request: &mut Request, depot: &mut Depot) -> salvo::http::StatusCode {
    let message: Value = request.parse_json().await.unwrap();
    depot
        .get_typed::<mpsc::UnboundedSender<Value>>()
        .unwrap()
        .send(message)
        .unwrap();
    salvo::http::StatusCode::OK
}

impl Fixture {
    async fn start(mail: bool) -> Self {
        let base = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&base).unwrap();
        let name = format!("cardinal_portal_admin_{}", uuid::Uuid::new_v4().simple());
        let options = options.database(&name);
        let dsn = options.to_url_lossy().to_string();
        Postgres::create_database(&dsn).await.unwrap();
        let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
        sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .execute(&pool)
            .await
            .unwrap();
        // Same bookkeeping table as Gateway::start, so its own migrate is a no-op.
        let mut migrator = cardinal::migrator();
        migrator.dangerous_set_table_name("_sqlx_migrations_gateway".to_owned());
        migrator.run(&pool).await.unwrap();

        let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0")
            .try_bind()
            .await
            .unwrap();
        let mail_addr = acceptor.holdings()[0].local_addr.to_string();
        let port = mail_addr.rsplit(':').next().expect("mock mail port");
        let mail_url = format!("http://127.0.0.1:{port}/emails");
        let (sender, inbox) = mpsc::unbounded_channel::<Value>();
        let mock = tokio::spawn(
            Server::new(acceptor).serve(
                Router::with_path("emails")
                    .hoop(affix_state::inject(sender))
                    .post(receive_mail),
            ),
        );

        let config: Config = toml::from_str(&format!(
            "listen = '127.0.0.1:0'\nsql_dsn = '{dsn}'\ngateway_key = '{ADMIN_KEY}'\n\
             [portal]\ndefault_customer_group = 'customer'\nbff_secret = 'bff-test-secret'\n"
        ))
        .unwrap();
        let settings = store::PortalSettingsInput {
            mail_transport: "http",
            mail_url: if mail { &mail_url } else { "" },
            mail_token: if mail { "initial-token" } else { "" },
            mail_from: if mail { FROM } else { "" },
            mail_origin: if mail { ORIGIN } else { "" },
            smtp_host: "",
            smtp_port: 587,
            smtp_username: "",
            smtp_password: "",
            smtp_tls: "starttls",
            smtp_from: "",
        };
        store::put_portal_settings(&pool, &settings).await.unwrap();
        let gateway = Gateway::start(config).await.unwrap();
        store::create_group(&pool, "customer", 10000, None)
            .await
            .unwrap();
        let client = Client::builder().timeout(WAIT).build().unwrap();
        Self {
            gateway,
            pool,
            dsn,
            client,
            inbox,
            mock,
            mail_url,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.gateway.local_addr())
    }

    async fn post(&self, path: &str, body: Value) -> Response {
        self.client
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn admin_get(&self, path: &str) -> Response {
        self.client
            .get(self.url(path))
            .bearer_auth(ADMIN_KEY)
            .send()
            .await
            .unwrap()
    }

    async fn admin_put(&self, path: &str, body: Value) -> Response {
        self.client
            .put(self.url(path))
            .bearer_auth(ADMIN_KEY)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn admin_delete(&self, path: &str) -> Response {
        self.client
            .delete(self.url(path))
            .bearer_auth(ADMIN_KEY)
            .send()
            .await
            .unwrap()
    }

    /// Full settings replacement; `token` may be a mask or an empty clear.
    fn settings_body(&self, token: &str) -> Value {
        json!({
            "mail_transport": "http",
            "mail_url": self.mail_url,
            "mail_token": token,
            "mail_from": FROM,
            "mail_origin": ORIGIN,
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_password": "",
            "smtp_tls": "starttls",
            "smtp_from": "",
        })
    }

    async fn mail(&mut self) -> Value {
        tokio::time::timeout(WAIT, self.inbox.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn close(self) {
        self.gateway.shutdown().await.unwrap();
        self.mock.abort();
        self.pool.close().await;
        Postgres::drop_database(&self.dsn).await.unwrap();
    }
}

#[tokio::test]
async fn account_auth_startup_loads_mail_settings_from_database() {
    let mut app = Fixture::start(true).await;
    let response = app.post("/auth/register", json!({"email": EMAIL})).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let message = app.mail().await;
    assert_eq!(message["from"], FROM);
    assert_eq!(message["to"], json!([EMAIL]));
    assert!(message["text"].as_str().unwrap().contains(ORIGIN));
    app.close().await;
}

#[tokio::test]
async fn account_auth_reload_after_admin_settings_put() {
    let mut app = Fixture::start(false).await;
    // The DB row is empty at startup: no mailer, so registration is unavailable.
    let response = app.post("/auth/register", json!({"email": EMAIL})).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let response = app
        .admin_put("/api/portal/settings", app.settings_body("new-token"))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: Value = response.json().await.unwrap();
    assert_eq!(view["mail_token"], store::SECRET_MASK);
    assert!(!view.to_string().contains("new-token"));

    // The same process now uses the swapped-in snapshot, without a restart.
    let response = app.post("/auth/register", json!({"email": EMAIL})).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let message = app.mail().await;
    assert_eq!(message["from"], FROM);
    app.close().await;
}

#[tokio::test]
async fn admin_portal_settings_mask_keep_and_clear_secrets() {
    let app = Fixture::start(true).await;
    let view: Value = app
        .admin_get("/api/portal/settings")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(view["mail_token"], store::SECRET_MASK);
    assert!(!view.to_string().contains("initial-token"));

    let mut body = app.settings_body(store::SECRET_MASK);
    body["mail_from"] = json!("Changed <changed@example.com>");
    let response = app.admin_put("/api/portal/settings", body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let stored: String = sqlx::query_scalar("SELECT mail_token FROM portal_settings WHERE id")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored, "initial-token");
    let view: Value = app
        .admin_get("/api/portal/settings")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(view["mail_from"], "Changed <changed@example.com>");

    // An empty secret clears it, and the rebuilt snapshot has no mailer.
    let response = app
        .admin_put("/api/portal/settings", app.settings_body(""))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let stored: String = sqlx::query_scalar("SELECT mail_token FROM portal_settings WHERE id")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored, "");
    let response = app.post("/auth/register", json!({"email": EMAIL})).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // SMTP is accepted by the admin API but delivery stays disabled until T3.
    let mut body = app.settings_body("");
    body["mail_transport"] = json!("smtp");
    body["smtp_host"] = json!("smtp.example.com");
    body["smtp_from"] = json!(FROM);
    let response = app.admin_put("/api/portal/settings", body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = app.post("/auth/register", json!({"email": EMAIL})).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    app.close().await;
}

#[tokio::test]
async fn admin_portal_providers_mask_keep_delete_and_preserve_identities() {
    let app = Fixture::start(false).await;
    let provider_body = |secret: &str| {
        json!({
            "client_id": "client-1",
            "client_secret": secret,
            "redirect_uri": "https://portal.example.com/callback",
            "enabled": true,
            "extra": {},
        })
    };
    let response = app
        .admin_put(
            "/api/portal/providers/google",
            provider_body("provider-secret"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: Value = response.json().await.unwrap();
    assert_eq!(view["client_secret"], store::SECRET_MASK);
    assert!(!view.to_string().contains("provider-secret"));

    let response = app.admin_get("/api/portal/providers").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains(store::SECRET_MASK));
    assert!(!body.contains("provider-secret"));

    let mut body = provider_body(store::SECRET_MASK);
    body["client_id"] = json!("client-2");
    let response = app.admin_put("/api/portal/providers/google", body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let stored: String =
        sqlx::query_scalar("SELECT client_secret FROM auth_providers WHERE provider = 'google'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(stored, "provider-secret");
    let client_id: String =
        sqlx::query_scalar("SELECT client_id FROM auth_providers WHERE provider = 'google'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(client_id, "client-2");

    // Both the name allowlist and the existing admin gate apply to new routes.
    let response = app
        .admin_put("/api/portal/providers/Bad_Name", provider_body("x"))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = app
        .client
        .put(app.url("/api/portal/providers/google"))
        .bearer_auth("wrong-key")
        .json(&provider_body("x"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .client
        .get(app.url("/api/portal/settings"))
        .bearer_auth(ADMIN_KEY)
        .header("x-forwarded-for", "203.0.113.9")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let owner = store::owner_user_id(&app.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO account_oauth_identities (provider, subject, user_id, email) \
         VALUES ('google', 'subject-1', $1, 'portal-user@example.com')",
    )
    .bind(owner)
    .execute(&app.pool)
    .await
    .unwrap();
    let response = app.admin_delete("/api/portal/providers/google").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_providers")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM account_oauth_identities")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
    let response = app.admin_delete("/api/portal/providers/google").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    app.close().await;
}

#[tokio::test]
async fn admin_concurrent_settings_puts_leave_runtime_matching_db() {
    let mut app = Fixture::start(false).await;
    // Each PUT commits then reloads. Without serialized load+swap, a slower
    // earlier reload can overwrite the generation produced by the last commit.
    let writes = (0..8u16).map(|index| {
        let mut body = app.settings_body("concurrent-token");
        body["mail_origin"] = json!(format!("http://127.0.0.1:{}", 20000 + index));
        app.admin_put("/api/portal/settings", body)
    });
    let responses = tokio::time::timeout(WAIT, join_all(writes))
        .await
        .expect("concurrent settings writes finish within the bound");
    for response in responses {
        assert_eq!(response.status(), StatusCode::OK);
    }

    let stored_origin: String =
        sqlx::query_scalar("SELECT mail_origin FROM portal_settings WHERE id")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let response = app.post("/auth/register", json!({"email": EMAIL})).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let message = app.mail().await;
    let link = message["text"].as_str().unwrap();
    assert!(
        link.contains(&stored_origin),
        "runtime origin in '{link}' must match final DB origin '{stored_origin}'"
    );
    app.close().await;
}
