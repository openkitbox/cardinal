//! Gateway HTTP tests. Set CARDINAL_TEST_DATABASE_URL to an isolated PostgreSQL
//! 18 cluster with TimescaleDB preloaded and a role allowed to create databases.

use std::collections::HashMap;
use std::time::Duration;

use cardinal::config::Config;
use cardinal::db::parse_pg_options;
use cardinal::gateway::Gateway;
use cardinal::store::{self, PortalSettingsInput};
use jiff::{SignedDuration, Timestamp};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::{Client, Response, StatusCode, Url};
use salvo::affix_state;
use salvo::conn::{Acceptor as _, Listener as _};
use salvo::prelude::Json;
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
        // Portal settings are DB-backed: seed the row before the gateway
        // builds its first runtime snapshot.
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
        let mail_router = Router::with_path("emails")
            .hoop(affix_state::inject(sender))
            .post(receive_mail);
        let mock = tokio::spawn(Server::new(acceptor).serve(mail_router));
        let config = fixture_config(&dsn, group);
        let settings = PortalSettingsInput {
            mail_transport: "http",
            mail_url: if mail { &mail_url } else { "" },
            mail_token: if mail { "mock-secret" } else { "" },
            mail_from: if mail {
                "Cardinal <auth@example.com>"
            } else {
                ""
            },
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

fn fixture_config(dsn: &str, group: Option<&str>) -> Config {
    let mut config = format!(
        "listen = '127.0.0.1:0'\nsql_dsn = '{dsn}'\ngateway_key = '{ADMIN_KEY}'\n[portal]\n"
    );
    if let Some(group) = group {
        config.push_str(&format!("default_customer_group = '{group}'\n"));
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

// --- OAuth exchange tests (dev-only loopback provider overrides) -------------

const BFF_SECRET: &str = "bff-shared-secret";
const OAUTH_REDIRECT: &str = "https://portal.example.com/oauth/callback";
const CODE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
const TEST_RSA_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAppTyf1y6n4C3QaDbarWw5x0gHxaX32+XAgyBE/V1TqikoCgo
KMdd5oT1K+8OEUhcoa6OYqBgwCARuxBvFGwHk41mb4oHmX+R2ot01qv2UroB/bYA
ohvRWs2GBLtWAV/k4hSy/mRCwwewEsknIxCI2Bqai/xTUBBoSvaaa3+Vflj8r10T
r/6QY1nA7xzl8P6Zc4YsIvYwVREg87kL7FNcYSdhgr022Xkaa28lR8cXN7NqVYzw
3uJUgJ3+M+7O+c35wp9eC5Vwc7ZOF8kmzsWyJCAAKsIzMvctoV/7F5jNZTo7QrV4
4fvrP5pamtioy1AR+1SBxExvjYqbomTcFK0T/wIDAQABAoIBAAt/qOo8EJEgYEX8
9bhneKHIw7tcTWPPKZ7VayGMENVlqbt5GiXlISkKO3xAC6S2GILRRaMu4Tl8h+Ig
RR1P7wlIj5jFGozbc/TLKeeu8MQOx+1nSfg8BaxdbHyuIRvbg9/2lXvJmEbVzy8f
cylQo7Q7HeOU1Ca+LdzNf0+f+8XqqkR+cCQ0c0Av43CfXmvM4vOmRolxLyxB1tf2
tHXtXm7Xk6RDTOM++WFERqFTFqEttBYV7C79FpGhg+Af7xCn7XM5D3IQzQIYG24d
zAwteh9ZAfTdq+gySn3c1yB0o498eyrdvzmKrvvrJVT3xviuVz/q1jk3lel0nQEw
UW2fjVECgYEA5MdIksxsJPcIF4AlsIWGHHcjFMnmopRig1QW93r1cs14pWTuhl98
DXyX/gTMsC+pW40UT1gh7Z5C3PevqeujFHSFpJEL4UjerLFgV3ikBSx7m16lZAeq
+IHzW/i/v17xB2Jo0S44adnCE2b+02TAUROvovrPA/Ynh8ohvMuWS/ECgYEAumce
3tjhfv7F+UVO2A6Uuxco5cXcG48b+l/8hef1iDtHwLzOsLWt0/ZbpNY19xU5ficx
CjPXrPeI0Net+5bZhh99QV7VGgPMdlBHlTFH+p4cWHfQ0qW8bDG2TR/5W1sjmZDt
s+ZSZq6VNxizZ08KXgnUE5dVnKbfRi6/+seFDu8CgYBiy0AmzIpC6D6hT2B3OyHv
9u66Unn7aVKlXdHRK1MFMX/RBKYQdvluJYjJVC9EQkDDXUgQ/4EfSMGdBITiPvSc
p7jymQRlU/982dg9zcYeydfS/2syqDEHwa5i4CeFr60sQC39bxVDeJrboBWZGiAG
oxasrdxp3ImzlPE+wzfzMQKBgC7Percn6+kCfiENQLGNZ9hcBo89UvswwyvrMvVF
vSlLCcfjIlzKIy8ZrQYGLWMxV1DQ8sXHIyBywU8A+tY1mcbO3Zuu/wEbdxs3KeLT
j2nmjuPAoxZjPKBHE6rmnq5MgvIrrSYCbysOKLa/Yz5MYSQgf7uzw3IljeiIEPof
ZNDNAoGBAIOMdW3mzSA5rOg0Iz89MwuuJQCU/fjkT+93pXfcxHGfp3JzDK6god2O
xxu3NUpaBatH9Yd3FM/YGFcT7T/pbYvYtPoiNYlKtrkqLSWX6JGCFEVfEDRn5/kc
MuwqJe08pDk0+oLcX6W5IDtJ8Tgs3dZvza33xkxra7pxzksOHOBi
-----END RSA PRIVATE KEY-----";
const TEST_RSA_N: &str = "ppTyf1y6n4C3QaDbarWw5x0gHxaX32-XAgyBE_V1TqikoCgoKMdd5oT1K-8OEUhcoa6OYqBgwCARuxBvFGwHk41mb4oHmX-R2ot01qv2UroB_bYAohvRWs2GBLtWAV_k4hSy_mRCwwewEsknIxCI2Bqai_xTUBBoSvaaa3-Vflj8r10Tr_6QY1nA7xzl8P6Zc4YsIvYwVREg87kL7FNcYSdhgr022Xkaa28lR8cXN7NqVYzw3uJUgJ3-M-7O-c35wp9eC5Vwc7ZOF8kmzsWyJCAAKsIzMvctoV_7F5jNZTo7QrV44fvrP5pamtioy1AR-1SBxExvjYqbomTcFK0T_w";

async fn form_params(request: &mut Request) -> HashMap<String, String> {
    let bytes = request.payload_with_max_size(8192).await.unwrap();
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn mock_bearer(request: &Request) -> String {
    request.headers()["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned()
}

#[handler]
async fn mock_google_token(request: &mut Request) -> Json<Value> {
    let params = form_params(request).await;
    assert_eq!(
        params.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        params.get("client_secret").map(String::as_str),
        Some("google-secret-do-not-leak")
    );
    assert_eq!(
        params.get("code_verifier").map(String::as_str),
        Some(CODE_VERIFIER)
    );
    let (subject, email, verified, nonce) = match params["code"].as_str() {
        "google-ok" => ("google-subject-ok", "google.oauth@example.com", true, None),
        "google-changed-email" => ("google-subject-ok", "changed.oauth@example.com", true, None),
        "google-unverified" => (
            "google-subject-unverified",
            "google.unverified@example.com",
            false,
            None,
        ),
        "google-nonce" => (
            "google-subject-nonce",
            "google.nonce@example.com",
            true,
            Some("expected-nonce"),
        ),
        _ => return Json(json!({"error": "invalid_grant"})),
    };
    let now = Timestamp::now().as_second();
    let mut claims = json!({
        "iss": "https://accounts.google.com",
        "aud": "google-client",
        "sub": subject,
        "email": email,
        "email_verified": verified,
        "iat": now,
        "exp": now + 600,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    let key = EncodingKey::from_rsa_pem(TEST_RSA_KEY.as_bytes()).expect("test RSA key");
    let id_token = encode(&header, &claims, &key).expect("sign test ID token");
    Json(json!({"id_token": id_token, "token_type": "Bearer"}))
}

#[handler]
async fn mock_google_jwks() -> Json<Value> {
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-key",
            "use": "sig",
            "alg": "RS256",
            "n": TEST_RSA_N,
            "e": "AQAB",
        }],
    }))
}

#[handler]
async fn mock_github_token(request: &mut Request) -> Json<Value> {
    let params = form_params(request).await;
    assert_eq!(
        params.get("client_secret").map(String::as_str),
        Some("github-secret-do-not-leak")
    );
    assert_eq!(
        params.get("code_verifier").map(String::as_str),
        Some(CODE_VERIFIER)
    );
    let token = match params["code"].as_str() {
        "github-alice" => "gho_alice",
        "github-linked" => "gho_linked",
        "github-created" => "gho_created",
        "github-fail" => return Json(json!({"error": "bad_verification_code"})),
        "github-unverified" => {
            return Json(json!({"error": "unverified_user_email"}));
        }
        _ => return Json(json!({"error": "bad_verification_code"})),
    };
    Json(json!({
        "access_token": token,
        "scope": "read:user,user:email",
        "token_type": "bearer",
    }))
}

#[handler]
async fn mock_github_user(request: &Request) -> Json<Value> {
    let id = match mock_bearer(request).as_str() {
        "gho_alice" => 101,
        "gho_linked" => 303,
        "gho_created" => 404,
        _ => 0,
    };
    Json(json!({"id": id, "login": "oauth-user"}))
}

#[handler]
async fn mock_github_emails(request: &Request) -> Json<Value> {
    let email = match mock_bearer(request).as_str() {
        "gho_alice" => "alice.oauth@example.com",
        "gho_linked" => "linked@example.com",
        "gho_created" => "created@example.com",
        _ => "unknown@example.com",
    };
    Json(json!([{
        "email": email,
        "primary": true,
        "verified": true,
    }]))
}

struct OauthFixture {
    gateway: Gateway,
    pool: PgPool,
    dsn: String,
    client: Client,
    mock: tokio::task::JoinHandle<()>,
    group_id: i64,
}

impl OauthFixture {
    async fn start() -> Self {
        let base_dsn = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&base_dsn).unwrap();
        let name = format!("cardinal_oauth_http_{}", uuid::Uuid::new_v4().simple());
        let options = options.database(&name);
        let dsn = options.to_url_lossy().to_string();
        Postgres::create_database(&dsn).await.unwrap();
        let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
        sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .execute(&pool)
            .await
            .unwrap();
        let mut migrator = cardinal::migrator();
        migrator.dangerous_set_table_name("_sqlx_migrations_gateway".to_owned());
        migrator.run(&pool).await.unwrap();
        let group_id = store::create_group(&pool, "customer", 10000, None)
            .await
            .unwrap();
        let settings = PortalSettingsInput {
            mail_transport: "http",
            mail_url: "",
            mail_token: "",
            mail_from: "",
            mail_origin: "",
            smtp_host: "",
            smtp_port: 587,
            smtp_username: "",
            smtp_password: "",
            smtp_tls: "starttls",
            smtp_from: "",
        };
        store::put_portal_settings(&pool, &settings).await.unwrap();

        let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0")
            .try_bind()
            .await
            .unwrap();
        let local_addr = acceptor.holdings()[0].local_addr.to_string();
        let mock_port = local_addr.rsplit(':').next().expect("mock provider port");
        let mock_base = format!("http://127.0.0.1:{mock_port}");
        let mock_router = Router::new()
            .push(Router::with_path("google/token").post(mock_google_token))
            .push(Router::with_path("google/jwks").get(mock_google_jwks))
            .push(Router::with_path("github/token").post(mock_github_token))
            .push(Router::with_path("github/user").get(mock_github_user))
            .push(Router::with_path("github/emails").get(mock_github_emails));
        let mock = tokio::spawn(Server::new(acceptor).serve(mock_router));

        let google_extra = json!({"endpoints": {
            "authorize": format!("{mock_base}/google/authorize"),
            "token": format!("{mock_base}/google/token"),
            "jwks": format!("{mock_base}/google/jwks"),
            "issuer": "https://accounts.google.com",
        }});
        store::upsert_auth_provider(
            &pool,
            &store::AuthProviderInput {
                provider: "google",
                client_id: "google-client",
                client_secret: "google-secret-do-not-leak",
                redirect_uri: OAUTH_REDIRECT,
                enabled: true,
                extra: &google_extra,
            },
        )
        .await
        .unwrap();
        let github_extra = json!({"endpoints": {
            "authorize": format!("{mock_base}/github/authorize"),
            "token": format!("{mock_base}/github/token"),
            "userinfo": format!("{mock_base}/github/user"),
            "emails": format!("{mock_base}/github/emails"),
        }});
        store::upsert_auth_provider(
            &pool,
            &store::AuthProviderInput {
                provider: "github",
                client_id: "github-client",
                client_secret: "github-secret-do-not-leak",
                redirect_uri: OAUTH_REDIRECT,
                enabled: true,
                extra: &github_extra,
            },
        )
        .await
        .unwrap();
        let disabled_extra = json!({});
        store::upsert_auth_provider(
            &pool,
            &store::AuthProviderInput {
                provider: "blocked",
                client_id: "blocked-client",
                client_secret: "blocked-secret-do-not-leak",
                redirect_uri: OAUTH_REDIRECT,
                enabled: false,
                extra: &disabled_extra,
            },
        )
        .await
        .unwrap();

        let config = toml::from_str(&format!(
            "listen = '127.0.0.1:0'\nsql_dsn = '{dsn}'\ngateway_key = 'admin-key'\n\
             allow_insecure_upstream = true\n[portal]\nbff_secret = '{BFF_SECRET}'\n\
             default_customer_group = 'customer'\n"
        ))
        .unwrap();
        let gateway = Gateway::start(config).await.unwrap();
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            gateway,
            pool,
            dsn,
            client,
            mock,
            group_id,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.gateway.local_addr())
    }

    async fn exchange(&self, body: Value, secret: &str) -> Response {
        let response = self
            .client
            .post(self.url("/auth/oauth/exchange"))
            .bearer_auth(secret)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        response
    }

    async fn session(&self, response: Response, expected_user: Option<i64>) -> String {
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = response.json().await.unwrap();
        let token = value["token"].as_str().unwrap();
        assert!(token.starts_with("ps_"));
        assert_eq!(token.len(), 46);
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let session = store::lookup_session(&self.pool, &digest)
            .await
            .unwrap()
            .expect("issued session must be live");
        // Account-scoped session: no gateway key is attached.
        assert!(session.key_id.is_none());
        if let Some(user_id) = expected_user {
            assert_eq!(session.user_id, user_id);
        }
        token.to_owned()
    }

    async fn close(self) {
        self.gateway.shutdown().await.unwrap();
        self.mock.abort();
        self.pool.close().await;
        Postgres::drop_database(&self.dsn).await.unwrap();
    }
}

fn oauth_body(provider: &str, code: &str) -> Value {
    json!({"provider": provider, "code": code, "code_verifier": CODE_VERIFIER})
}

#[tokio::test]
async fn account_auth_http_oauth_public_providers_hide_secrets_and_use_code_endpoints() {
    let app = OauthFixture::start().await;
    let response = app
        .client
        .get(app.url("/auth/oauth/providers"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(!body.contains("do-not-leak"));
    assert!(!body.contains("endpoints"));
    let providers: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(providers.as_array().unwrap().len(), 2);
    assert_eq!(providers[0]["provider"], "github");
    let github_authorize = providers[0]["authorize_url"].as_str().unwrap();
    assert!(github_authorize.starts_with("http://127.0.0.1:"));
    assert!(github_authorize.ends_with("/github/authorize"));
    assert_eq!(providers[0]["scope"], "read:user user:email");
    assert_eq!(providers[0]["redirect_uri"], OAUTH_REDIRECT);
    assert_eq!(providers[1]["provider"], "google");
    let google_authorize = providers[1]["authorize_url"].as_str().unwrap();
    assert!(google_authorize.starts_with("http://127.0.0.1:"));
    assert!(google_authorize.ends_with("/google/authorize"));
    assert_eq!(providers[1]["scope"], "openid email");
    app.close().await;
}

#[tokio::test]
async fn account_auth_http_oauth_google_exchange_verifies_the_id_token() {
    let app = OauthFixture::start().await;
    let response = app
        .exchange(oauth_body("google", "google-ok"), BFF_SECRET)
        .await;
    app.session(response, None).await;
    let verified: i64 = sqlx::query_scalar(
        "SELECT user_id FROM account_oauth_identities WHERE provider = 'google'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    let user = store::get_user(&app.pool, verified).await.unwrap().unwrap();
    assert_eq!(user.group_id, app.group_id);
    assert_eq!(
        store::lookup_oauth_identity_user_id(&app.pool, "google", "google-subject-ok")
            .await
            .unwrap(),
        Some(verified)
    );
    assert_eq!(
        store::lookup_oauth_identity_user_id(&app.pool, "google", "unknown-subject")
            .await
            .unwrap(),
        None
    );
    let credential = store::lookup_account_credential_by_user_id(&app.pool, verified)
        .await
        .unwrap()
        .expect("OAuth signup must leave a credential");
    assert_eq!(credential.user_id, verified);
    assert!(!credential.password_hash.is_empty());
    assert!(
        store::lookup_account_credential_by_user_id(&app.pool, verified + 1000)
            .await
            .unwrap()
            .is_none()
    );

    // Subject reuse must not depend on the provider's current email: T1 keeps
    // the credential created for the first email.
    let changed = app
        .exchange(oauth_body("google", "google-changed-email"), BFF_SECRET)
        .await;
    app.session(changed, Some(verified)).await;
    let stored_email: String =
        sqlx::query_scalar("SELECT email FROM account_credentials WHERE user_id = $1")
            .bind(verified)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(stored_email, "google.oauth@example.com");

    let unverified = app
        .exchange(oauth_body("google", "google-unverified"), BFF_SECRET)
        .await;
    assert_eq!(unverified.status(), StatusCode::UNAUTHORIZED);
    let mut body = oauth_body("google", "google-nonce");
    body["nonce"] = json!("wrong-nonce");
    assert_eq!(
        app.exchange(body, BFF_SECRET).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut body = oauth_body("google", "google-nonce");
    body["nonce"] = json!("expected-nonce");
    app.session(app.exchange(body, BFF_SECRET).await, None)
        .await;
    app.close().await;
}

#[tokio::test]
async fn account_auth_http_oauth_github_exchange_covers_all_identity_branches() {
    let app = OauthFixture::start().await;
    let created = app
        .exchange(oauth_body("github", "github-created"), BFF_SECRET)
        .await;
    let created_user = {
        let value: Value = created.json().await.unwrap();
        let digest: [u8; 32] = Sha256::digest(value["token"].as_str().unwrap().as_bytes()).into();
        store::lookup_session(&app.pool, &digest)
            .await
            .unwrap()
            .unwrap()
            .user_id
    };
    let created_again = app
        .exchange(oauth_body("github", "github-created"), BFF_SECRET)
        .await;
    let response = app
        .exchange(oauth_body("github", "github-alice"), BFF_SECRET)
        .await;
    app.session(response, None).await;

    // Pre-existing account with the same verified email links instead of creating.
    let challenge: [u8; 32] = Sha256::digest("oauth-link-challenge").into();
    store::issue_registration_challenge(
        &app.pool,
        "linked@example.com",
        &challenge,
        Timestamp::now() + SignedDuration::from_mins(5),
    )
    .await
    .unwrap();
    let linked_user = store::complete_registration(
        &app.pool,
        &challenge,
        "$argon2id$v=19$m=19456,t=2,p=1$MjAxOTAxMDEwMDAwMDAwMA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "customer",
    )
    .await
    .unwrap()
    .unwrap();
    let linked = app
        .exchange(oauth_body("github", "github-linked"), BFF_SECRET)
        .await;
    let session = app.session(linked, Some(linked_user)).await;
    assert_ne!(session, "");
    let existing = app
        .exchange(oauth_body("github", "github-created"), BFF_SECRET)
        .await;
    let value: Value = existing.json().await.unwrap();
    let digest: [u8; 32] = Sha256::digest(value["token"].as_str().unwrap().as_bytes()).into();
    assert_eq!(
        store::lookup_session(&app.pool, &digest)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        created_user
    );
    // The second exchange for the same subject must not create another account.
    let subjects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM account_oauth_identities WHERE provider = 'github' AND subject = '404'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(subjects, 1);
    assert!(created_again.status().is_success());
    app.close().await;
}

#[tokio::test]
async fn account_auth_http_oauth_exchange_rejects_bad_requests() {
    let app = OauthFixture::start().await;
    assert_eq!(
        app.exchange(oauth_body("github", "github-created"), "wrong-secret")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.exchange(oauth_body("blocked", "github-created"), BFF_SECRET)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.exchange(oauth_body("unknown", "github-created"), BFF_SECRET)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.exchange(oauth_body("github", "github-fail"), BFF_SECRET)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.exchange(oauth_body("github", "github-unverified"), BFF_SECRET)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.exchange(
            json!({"provider":"github","code":"github-created","code_verifier":CODE_VERIFIER,"extra":1}),
            BFF_SECRET,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.exchange(
            json!({"provider":"github","code":"github-created","code_verifier":"short"}),
            BFF_SECRET,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    // No token exchange may happen without the BFF secret, even for a valid code.
    assert_eq!(
        app.exchange(oauth_body("github", "github-created"), "")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    app.close().await;
}
