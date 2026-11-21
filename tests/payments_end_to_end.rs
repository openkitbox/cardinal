//! End-to-end Xiaodou payment orchestration tests against a local signed mock
//! upstream. Set CARDINAL_TEST_DATABASE_URL to an isolated PostgreSQL 18
//! cluster with TimescaleDB >= 2.31 and database-create access.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cardinal::config::Config;
use cardinal::db::parse_pg_options;
use cardinal::gateway::Gateway;
use cardinal::store;
use cardinal::xiaodou_pay::{
    PlatformKeys, ResponseFields, SigningKey, WEBHOOK_SUCCESS_BODY, WebhookFields,
    canonical_request, canonical_response, canonical_webhook, fingerprint_public_key_pem,
};
use jiff::Timestamp;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use sqlx::{ConnectOptions as _, PgPool, Postgres};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const ADMIN_KEY: &str = "payments-admin-key";
const APP_ID: &str = "xdop_1234567890abcdef";
const KID: &str = "xdpk-test";
const WAIT: Duration = Duration::from_secs(30);

/// Throwaway 2048-bit RSA key shared by the merchant and the mock platform in
/// this test binary. It is generated locally, not a production credential.
const TEST_PRIVATE_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDoeEGI39t6STg0
3hX697V2UDPBjSAf5Xin/KRVfmqvl75of5uK8Ygr98C9Q4yLMjQq706yE5MC8ckC
+BgIPuRyjt2CFsgk3hmLaxv7jpzodCiR4gw1Nbqr89NIr2jM1EZOjDKdlTbRaAGC
PO6DY2aOER5a55+9T70Fv0lEh1b100aTaQ5QKr0+Jy5sA+puscVvPB0O5MIzqJ3N
qvBNsz906Vz1rucZgk1WuCXPhcD/i62UZrVizjM3f4aTKo5ZKiLu7eqKYSXRD4Yg
rffDYBZZz9r7Zu8O/SAw39Jyc5i+IixdzW0raYi+Z22yEQK7oWHLiV9ZE7Sbgjhz
DgQ/h+9NAgMBAAECggEAN8LgtVw84RA/Ey9SRmi0djS2tW6MjhoU3vaS1I8GOChF
2/r/7EwTRbif2sYhKCJasRHF5qEbWlF0zemEmjW7xl7Ocy3TxEQiDHcctzJ2IKv8
L0Hxe7HvnN9Xhs/Ma5VfZ+fpHDN2erRf6EWFUK6/IsSoa1Wz000VIhPIF0//Y+dc
qJ+wmaDpmE3E8TSrw8x+hnyrqiFJDlHXhwdnnvMxT+BJx1+UPvDJcU+5tKQ7qPX2
qEXFMI46Ubg6rhJWA5LKDITVu4FRRRY50pN/6li+CgVFcQXmIL2fXN7k7pmZC2oR
cEhDafhjdoUlSHO+yluRKtnPpneFLtbxKVOy0UvuYQKBgQD7ZVMFt7enWm6h6GkC
/8fK2Ws6GuYivvcPqPnOCOEPyxnNBqHhvW3AF2PCrn/0fjhI0E/PDEkybKWCb2uW
cA+0Bp87OWy9f1fZarFUCYFxHiK6KUwhsNZW8S4/xNMuJYtubPcJtnOgsmDKeIUQ
KXmm6LH3on0o6h6K5B1lKFY7twKBgQDsujJIzVGNE2nnmK8lkbHKVUZ+ht6nBLxn
TkTDUlMHW1syAetZi2uSjf/qreOHw1np8NVpCTU5mGRNQRuH52WDX2a//Ix/JOjO
1MbLGww8tCGbcR8+3R0DcX0rzEQvG1bTZg/IIHourSwYpWbUgdTx49XNEQQNN8Vj
S2A0LgN1GwKBgQC76D6oNWxnAOdUyf1EKp/R9bV6VwTRz9+nquwdnvFq9qqwX1a8
/vR78n+00u39eCLl+h7NaieEM0V7O4E1j0mNjK2UfRXUhszJTECDyh8gyB+4+olX
XXC4x8mEDMC064dO4M++SMwgv3QtouwC6p1trtzndmMLJAP0WRHHvODH/QKBgQCY
PldAgutDs4yUqZlarAyPd7BShyKCf4U7WxbWFwfW32YTDzDw8b1JD5Hat+Jw2a3l
ykE1v/o/BEbdeFXgXWznxF8scZtZ2b7v5d/Dl62TDLXgZiwWHdYe9MnvdPsU4JxC
cI0Nw/VQN4b4gsdTO/xbZI+Hxr24UnnblgpVBJKsqQKBgQDzFgBYk96viYLGVZT0
4u7PfiesXgQ2L6pUZyj0HYh0qFUbzQOaQdRCajE9SLwa4lZ/N+s1U80EbyaKr7iO
c4pEqUJ/4e5NXgaaO8eWgd5WKnGnugUlOZQQwkdsorUagbAi6N/HAMTkiQ6vniLk
a1YBT8LPeUxHDv+cjGOAzKGcGA==
-----END PRIVATE KEY-----
"#;

const TEST_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6HhBiN/bekk4NN4V+ve1
dlAzwY0gH+V4p/ykVX5qr5e+aH+bivGIK/fAvUOMizI0Ku9OshOTAvHJAvgYCD7k
co7dghbIJN4Zi2sb+46c6HQokeIMNTW6q/PTSK9ozNRGTowynZU20WgBgjzug2Nm
jhEeWuefvU+9Bb9JRIdW9dNGk2kOUCq9PicubAPqbrHFbzwdDuTCM6idzarwTbM/
dOlc9a7nGYJNVrglz4XA/4utlGa1Ys4zN3+GkyqOWSoi7u3qimEl0Q+GIK33w2AW
Wc/a+2bvDv0gMN/ScnOYviIsXc1tK2mIvmdtshECu6Fhy4lfWRO0m4I4cw4EP4fv
TQIDAQAB
-----END PUBLIC KEY-----
"#;

#[derive(Default)]
struct MockState {
    orders: HashMap<String, MockOrder>,
    overrides: HashMap<String, MockOverride>,
    conflict_amount: Option<i64>,
    conflicted_orders: std::collections::HashSet<String>,
    placements: Vec<PlacementCall>,
    queries: Vec<String>,
    refunds: Vec<RefundCall>,
    refund_queries: Vec<String>,
    refund_query_states: HashMap<String, String>,
}

#[derive(Clone)]
struct MockOrder {
    amount_fen: i64,
    status: String,
    pay_url: String,
}

#[derive(Default, Clone)]
struct MockOverride {
    conflict_once: bool,
    status: Option<String>,
    amount_fen: Option<i64>,
    qr_code: Option<String>,
    refund_status: Option<String>,
    refund_fails: bool,
}

#[derive(Clone)]
struct PlacementCall {
    request_id: String,
    nonce: String,
    body: String,
}

#[derive(Clone)]
struct RefundCall {
    out_trade_no: String,
    out_refund_no: String,
    request_id: String,
    amount_fen: i64,
}

struct MockServer {
    addr: SocketAddr,
    state: Arc<Mutex<MockState>>,
    // The mock URL is installed into the process-global payments runtime, so its
    // listener must outlive the per-test Tokio runtimes that first touch it.
    _runtime: tokio::runtime::Runtime,
}

static MOCK: OnceLock<MockServer> = OnceLock::new();

impl MockServer {
    async fn start() -> &'static Self {
        MOCK.get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("cardinal-payments-mock")
                .enable_all()
                .build()
                .expect("mock runtime");
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock");
            listener.set_nonblocking(true).expect("nonblocking mock");
            let addr = listener.local_addr().expect("mock addr");
            let state = Arc::new(Mutex::new(MockState::default()));
            let task_state = Arc::clone(&state);
            runtime.spawn(async move {
                let listener = TcpListener::from_std(listener).expect("tokio mock listener");
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    let state = Arc::clone(&task_state);
                    tokio::spawn(async move {
                        if let Err(error) = serve_mock(&mut socket, state).await {
                            eprintln!("mock upstream error: {error:#}");
                        }
                    });
                }
            });
            MockServer {
                addr,
                state,
                _runtime: runtime,
            }
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn set_override(&self, out_trade_no: &str, value: MockOverride) {
        self.state
            .lock()
            .expect("mock state")
            .overrides
            .insert(out_trade_no.to_owned(), value);
    }

    fn conflict_amount(&self, amount_fen: i64) {
        self.state.lock().expect("mock state").conflict_amount = Some(amount_fen);
    }

    fn placement_calls(&self) -> Vec<PlacementCall> {
        self.state.lock().expect("mock state").placements.clone()
    }

    fn queries(&self) -> Vec<String> {
        self.state.lock().expect("mock state").queries.clone()
    }

    fn refunds(&self) -> Vec<RefundCall> {
        self.state.lock().expect("mock state").refunds.clone()
    }

    fn refund_queries(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("mock state")
            .refund_queries
            .clone()
    }

    fn set_refund_query_state(&self, out_refund_no: &str, state: &str) {
        self.state
            .lock()
            .expect("mock state")
            .refund_query_states
            .insert(out_refund_no.to_owned(), state.to_owned());
    }
}

fn now_secs() -> String {
    Timestamp::now().as_second().to_string()
}

fn mock_nonce(prefix: &str) -> String {
    format!("{prefix}{:024}", Timestamp::now().as_millisecond())
}

fn merchant_keys() -> PlatformKeys {
    let fingerprint = fingerprint_public_key_pem(TEST_PUBLIC_PEM);
    PlatformKeys::from_entries([("mkid-test", TEST_PUBLIC_PEM, fingerprint.as_str())])
        .expect("merchant keys")
}

fn signer() -> SigningKey {
    SigningKey::from_pem(TEST_PRIVATE_PEM).expect("signing key")
}

fn verify_mock_request(uri: &str, headers: &HashMap<String, String>, body: &[u8]) -> bool {
    let url = match reqwest::Url::parse(&format!("http://mock{uri}")) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let get = |name: &str| headers.get(name).map(String::as_str);
    let (Some(timestamp), Some(nonce), Some(app_id), Some(key_id), Some(request_id), Some(sign)) = (
        get("x-xd-app-id").and_then(|_| get("x-xd-timestamp")),
        get("x-xd-nonce"),
        get("x-xd-app-id"),
        get("x-xd-key-id"),
        get("x-xd-request-id"),
        get("x-xd-sign"),
    ) else {
        return false;
    };
    let Ok(canonical) = canonical_request(&cardinal::xiaodou_pay::RequestFields {
        method: headers.get(":method").map_or("GET", String::as_str),
        path: url.path(),
        query: url.query().unwrap_or_default(),
        timestamp,
        nonce,
        app_id,
        key_id,
        request_id,
        content_type: get("content-type"),
        raw_body: body,
    }) else {
        return false;
    };
    merchant_keys().verify(key_id, &canonical, sign).is_ok()
}

async fn serve_mock(
    socket: &mut tokio::net::TcpStream,
    state: Arc<Mutex<MockState>>,
) -> anyhow::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let uri = parts.next().unwrap_or_default().to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    headers.insert(":method".to_owned(), method.clone());
    let content_length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or_default();
    while buffer.len() < header_end + content_length {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = &buffer[header_end..(header_end + content_length).min(buffer.len())];
    let request_id = headers
        .get("x-xd-request-id")
        .cloned()
        .unwrap_or_else(|| "req_missing".to_owned());
    if !verify_mock_request(&uri, &headers, body) {
        let (head, bytes) = unsigned_response(
            401,
            &request_id,
            &json!({"code": "OPEN_API_SIGN_INVALID", "message": "bad signature", "requestId": request_id}),
        );
        socket.write_all(head.as_bytes()).await?;
        socket.write_all(&bytes).await?;
        return Ok(());
    }

    let url = reqwest::Url::parse(&format!("http://mock{uri}"))?;
    let path = url.path().to_owned();
    let (status, payload) =
        dispatch_mock(&method, &path, body, &headers, request_id.as_str(), &state);
    let (head, bytes) = if path == "/api/open/v1/payments" && method == "POST" {
        // conflict responses are intentionally unsigned (early rejection).
        if payload.get("code").is_some() {
            unsigned_response(status, &request_id, &payload)
        } else {
            signed_response(status, &request_id, &payload)
        }
    } else if status >= 400 {
        unsigned_response(status, &request_id, &payload)
    } else {
        signed_response(status, &request_id, &payload)
    };
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(&bytes).await?;
    Ok(())
}

fn signed_response(status: u16, request_id: &str, payload: &Value) -> (String, Vec<u8>) {
    let bytes = serde_json::to_vec(payload).expect("mock body");
    let timestamp = now_secs();
    let nonce = mock_nonce("resp");
    let canonical = canonical_response(&ResponseFields {
        status,
        content_type: Some("application/json"),
        request_id,
        timestamp: &timestamp,
        nonce: &nonce,
        key_id: KID,
        raw_body: &bytes,
    })
    .expect("mock canonical response");
    let sign = signer().sign(&canonical).expect("mock response sign");
    let head = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nX-XD-Request-Id: {request_id}\r\nX-XD-Response-Sign: {sign}\r\nX-XD-Response-Key-Id: {KID}\r\nX-XD-Response-Timestamp: {timestamp}\r\nX-XD-Response-Nonce: {nonce}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    (head, bytes)
}

fn unsigned_response(status: u16, request_id: &str, payload: &Value) -> (String, Vec<u8>) {
    let bytes = serde_json::to_vec(payload).expect("mock error body");
    let head = format!(
        "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nX-XD-Request-Id: {request_id}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    (head, bytes)
}

fn dispatch_mock(
    method: &str,
    path: &str,
    body: &[u8],
    headers: &HashMap<String, String>,
    request_id: &str,
    state: &Arc<Mutex<MockState>>,
) -> (u16, Value) {
    let parsed: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let mut guard = state.lock().expect("mock state");
    let out_trade_no = parsed
        .get("outTradeNo")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if method == "POST" && path == "/api/open/v1/payments" {
        guard.placements.push(PlacementCall {
            request_id: request_id.to_owned(),
            nonce: headers.get("x-xd-nonce").cloned().unwrap_or_default(),
            body: String::from_utf8_lossy(body).to_string(),
        });
        let override_value = guard
            .overrides
            .get(&out_trade_no)
            .cloned()
            .unwrap_or_default();
        let amount_fen = parsed
            .get("amountFen")
            .and_then(Value::as_i64)
            .unwrap_or(1200);
        let conflict = override_value.conflict_once
            || (guard.conflict_amount == Some(amount_fen)
                && !guard.conflicted_orders.contains(&out_trade_no));
        if conflict {
            guard.conflicted_orders.insert(out_trade_no.clone());
            if override_value.conflict_once {
                guard
                    .overrides
                    .entry(out_trade_no.clone())
                    .and_modify(|value| value.conflict_once = false);
            }
            guard.orders.insert(
                out_trade_no.clone(),
                MockOrder {
                    amount_fen,
                    status: "CREATED".to_owned(),
                    pay_url: format!("https://cashier.example.invalid/pay/{out_trade_no}"),
                },
            );
            return (
                409,
                json!({"code": "OPEN_API_IDEMPOTENCY_CONFLICT", "message": "conflict", "requestId": request_id}),
            );
        }
        let pay_url = format!("https://cashier.example.invalid/pay/{out_trade_no}");
        let qr_code = override_value
            .qr_code
            .clone()
            .or_else(|| Some(format!("https://qr.alipay.com/bax{out_trade_no}")));
        guard.orders.insert(
            out_trade_no.clone(),
            MockOrder {
                amount_fen,
                status: "CREATED".to_owned(),
                pay_url: pay_url.clone(),
            },
        );
        return (
            201,
            json!({
                "requestId": request_id,
                "openOrderId": format!("op_{out_trade_no}"),
                "outTradeNo": out_trade_no,
                "status": "CREATED",
                "amountFen": amount_fen,
                "currency": "CNY",
                "expireAt": "2030-01-01T00:00:00.000Z",
                "payUrl": pay_url,
                "qrCode": qr_code,
                "feeProjection": {"ruleVersion": "v1", "tier": "STANDARD"},
                "replayed": false,
            }),
        );
    }
    let prefix = "/api/open/v1/payments/";
    if method == "GET" && path.starts_with(prefix) {
        let no = path[prefix.len()..].to_owned();
        guard.queries.push(no.clone());
        let override_value = guard.overrides.get(&no).cloned().unwrap_or_default();
        let order = guard.orders.get(&no).cloned();
        let status = override_value
            .status
            .clone()
            .or_else(|| order.as_ref().map(|o| o.status.clone()))
            .unwrap_or_else(|| "NOT_FOUND".to_owned());
        let amount_fen = override_value
            .amount_fen
            .or_else(|| order.as_ref().map(|o| o.amount_fen))
            .unwrap_or(1200);
        return (
            200,
            json!({
                "requestId": request_id,
                "openOrderId": format!("op_{no}"),
                "outTradeNo": no,
                "status": status,
                "amountFen": amount_fen,
                "currency": "CNY",
                "payUrl": "https://cashier.example.invalid/QUERY_MUST_BE_IGNORED",
                "qrCode": "https://qr.alipay.com/QUERY_MUST_BE_IGNORED",
                "feeProjection": {"ruleVersion": "v1"},
            }),
        );
    }
    let refund_prefix = "/api/open/v1/refunds/";
    if method == "GET" && path.starts_with(refund_prefix) {
        let no = path[refund_prefix.len()..].to_owned();
        guard.refund_queries.push(no.clone());
        let call = guard
            .refunds
            .iter()
            .rev()
            .find(|refund| refund.out_refund_no == no)
            .cloned();
        let state = guard
            .refund_query_states
            .get(&no)
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        return (
            200,
            json!({
                "requestId": request_id,
                "outTradeNo": call.as_ref().map_or(String::new(), |value| value.out_trade_no.clone()),
                "outRefundNo": no,
                "state": state,
                "amountFen": call.as_ref().map_or(1200, |value| value.amount_fen),
            }),
        );
    }
    if method == "POST" && path.ends_with("/attempts") {
        let no = path[prefix.len()..path.len() - "/attempts".len()].to_owned();
        let pay_url = format!("https://cashier.example.invalid/retry/{no}");
        let qr_code = guard
            .overrides
            .get(&no)
            .and_then(|value| value.qr_code.clone())
            .unwrap_or_else(|| format!("https://qr.alipay.com/retry{no}"));
        if let Some(order) = guard.orders.get_mut(&no) {
            order.pay_url = pay_url.clone();
        }
        return (
            201,
            json!({
                "requestId": request_id,
                "outTradeNo": no,
                "status": "PAYING",
                "payUrl": pay_url,
                "qrCode": qr_code,
                "feeProjection": {"ruleVersion": "v1"},
            }),
        );
    }
    if method == "POST" && path == "/api/open/v1/refunds" {
        let refund_no = parsed
            .get("outRefundNo")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let no = out_trade_no.clone();
        guard.refunds.push(RefundCall {
            out_trade_no: no.clone(),
            out_refund_no: refund_no.clone(),
            request_id: request_id.to_owned(),
            amount_fen: parsed
                .get("refundAmountFen")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
        });
        let override_value = guard.overrides.get(&no).cloned().unwrap_or_default();
        if override_value.refund_fails {
            return (
                502,
                json!({"code": "OPEN_API_PROVIDER_REJECTED", "message": "rejected", "requestId": request_id}),
            );
        }
        let state = override_value
            .refund_status
            .unwrap_or_else(|| "SUCCEEDED".to_owned());
        return (
            201,
            json!({
                "requestId": request_id,
                "outTradeNo": no,
                "outRefundNo": refund_no,
                "state": state,
                "amountFen": parsed.get("refundAmountFen").and_then(Value::as_i64).unwrap_or_default(),
            }),
        );
    }
    (
        404,
        json!({"code": "OPEN_API_NOT_FOUND", "message": "unknown mock route", "requestId": request_id}),
    )
}

struct Fixture {
    gateway: Gateway,
    pool: PgPool,
    dsn: String,
    client: Client,
    account_token: String,
    key_token: String,
    user_id: i64,
}

impl Fixture {
    async fn new() -> Self {
        let mock = MockServer::start().await;
        let base_url = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&base_url).expect("parse test DSN");
        let name = format!("cardinal_payments_test_{}", uuid::Uuid::new_v4().simple());
        let options = options.database(&name);
        let dsn = options.to_url_lossy().to_string();
        Postgres::create_database(&dsn)
            .await
            .expect("create test database");
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect_with(options)
            .await
            .expect("connect to test database");
        sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .execute(&pool)
            .await
            .expect("install TimescaleDB");
        let mut config = toml::from_str::<Config>(&format!(
            "listen = '127.0.0.1:0'\nsql_dsn = '{dsn}'\ngateway_key = '{ADMIN_KEY}'\nallow_insecure_upstream = true\n\
             [payments.xiaodou]\nbase_url = 'https://example.invalid'\napp_id = '{APP_ID}'\nmerchant_kid = 'mkid-test'\n\
             channel = 'ALIPAY_H5'\ntrade_scope = 'CARD_VIRTUAL'\nnotify_url = 'https://example.invalid/hook'\n\
             return_url = 'https://example.invalid/return'\nusd_micros_per_cny_fen = 1000\n\
             time_expire_seconds = 3600\nfee_bearer = 'SELLER'\n\
             [payments.xiaodou.platform_keys.{KID}]\npem = '''{TEST_PUBLIC_PEM}'''\n\
             fingerprint = '{}'\n",
            fingerprint_public_key_pem(TEST_PUBLIC_PEM)
        ))
        .expect("gateway config");
        if let Some(xiaodou) = config.payments.xiaodou.take() {
            config.payments.xiaodou = Some(
                xiaodou
                    .with_private_key(Some(TEST_PRIVATE_PEM))
                    .expect("private key"),
            );
        }
        cardinal::payments::install_runtime(&config, Some(&mock.url()))
            .expect("install payments runtime");
        let gateway = Gateway::start(config).await.expect("start gateway");
        // The mock server is shared by every test in this binary. Each test DB
        // otherwise starts order ids at 1, making outRefundNo collide across
        // tests and letting one test's refund query state settle another's.
        let id_start = (uuid::Uuid::new_v4().as_u128() & 0x0000_ffff_ffff_ffff) as i64 + 1_000_000;
        sqlx::query(
            "SELECT setval(pg_get_serial_sequence('public.payment_orders', 'id'), $1, false)",
        )
        .bind(id_start)
        .execute(&pool)
        .await
        .expect("isolate payment order ids");
        store::create_group(&pool, "customer", 10000, None)
            .await
            .expect("create group");
        let challenge = [7_u8; 32];
        store::issue_registration_challenge(
            &pool,
            "buyer@example.com",
            &challenge,
            Timestamp::now() + jiff::SignedDuration::from_hours(1),
        )
        .await
        .expect("registration challenge");
        let user_id = store::complete_registration(&pool, &challenge, "hash", "customer")
            .await
            .expect("register")
            .expect("user id");
        let credential = store::lookup_account_credential(&pool, "buyer@example.com")
            .await
            .expect("credential")
            .expect("credential exists");
        let account_token = session_token('A');
        let account_digest = Sha256::digest(account_token.as_bytes()).into();
        store::create_account_session(
            &pool,
            user_id,
            credential.password_version,
            &account_digest,
            Timestamp::now() + jiff::SignedDuration::from_hours(1),
        )
        .await
        .expect("account session");
        let key = store::create_gateway_key(
            &pool,
            user_id,
            "buyer-key",
            store::KeyTerms::default(),
            None,
        )
        .await
        .expect("gateway key");
        let key_id = store::authenticate_principal(&pool, &key)
            .await
            .expect("authenticate gateway key")
            .expect("gateway key exists")
            .key_id;
        let key_token = session_token('K');
        let key_digest = Sha256::digest(key_token.as_bytes()).into();
        store::create_key_session(
            &pool,
            user_id,
            key_id,
            &key_digest,
            Timestamp::now() + jiff::SignedDuration::from_hours(1),
        )
        .await
        .expect("key session");

        Self {
            gateway,
            pool,
            dsn,
            client: Client::builder()
                .timeout(WAIT)
                .build()
                .expect("http client"),
            account_token,
            key_token,
            user_id,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.gateway.local_addr())
    }

    async fn post_user(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .client
            .post(self.url(path))
            .bearer_auth(&self.account_token)
            .json(&body)
            .send()
            .await
            .expect("user POST");
        let status = response.status();
        let text = response.text().await.expect("response text");
        (
            status,
            serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text})),
        )
    }

    async fn get_user(&self, path: &str) -> (StatusCode, Value) {
        let response = self
            .client
            .get(self.url(path))
            .bearer_auth(&self.account_token)
            .send()
            .await
            .expect("user GET");
        let status = response.status();
        let text = response.text().await.expect("response text");
        (
            status,
            serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text})),
        )
    }

    async fn admin_post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .client
            .post(self.url(path))
            .bearer_auth(ADMIN_KEY)
            .json(&body)
            .send()
            .await
            .expect("admin POST");
        let status = response.status();
        let text = response.text().await.expect("response text");
        (
            status,
            serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text})),
        )
    }

    async fn admin_get(&self, path: &str) -> (StatusCode, Value) {
        let response = self
            .client
            .get(self.url(path))
            .bearer_auth(ADMIN_KEY)
            .send()
            .await
            .expect("admin GET");
        let status = response.status();
        let text = response.text().await.expect("response text");
        (
            status,
            serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text})),
        )
    }

    async fn close(self) {
        self.gateway.shutdown().await.expect("gateway shutdown");
        self.pool.close().await;
        Postgres::drop_database(&self.dsn)
            .await
            .expect("drop test database");
    }
}

fn session_token(letter: char) -> String {
    format!("ps_{}", URL_SAFE_NO_PAD.encode([letter as u8; 32]))
}

fn webhook_body(
    event_id: &str,
    event_type: &str,
    out_trade_no: &str,
    amount_fen: i64,
    state_version: i64,
    status: &str,
) -> String {
    serde_json::to_string(&json!({
        "eventId": event_id,
        "eventType": event_type,
        "appId": APP_ID,
        "outTradeNo": out_trade_no,
        "outRefundNo": null,
        "eventAmountFen": amount_fen,
        "grossAmountFen": amount_fen,
        "feeBearer": "SELLER",
        "merchantAmountFen": amount_fen,
        "feeAmountFen": 0,
        "status": status,
        "reason": "",
        "occurredAt": Timestamp::now().as_second(),
        "stateVersion": state_version,
        "attach": "",
        "feeProjection": {"ruleVersion": "v1"},
    }))
    .expect("webhook JSON")
}

fn refund_webhook_body(
    event_id: &str,
    event_type: &str,
    out_trade_no: &str,
    out_refund_no: &str,
    amount_fen: i64,
    status: &str,
) -> String {
    serde_json::to_string(&json!({
        "eventId": event_id,
        "eventType": event_type,
        "appId": APP_ID,
        "outTradeNo": out_trade_no,
        "outRefundNo": out_refund_no,
        "eventAmountFen": amount_fen,
        "grossAmountFen": amount_fen,
        "feeBearer": "SELLER",
        "merchantAmountFen": amount_fen,
        "feeAmountFen": 0,
        "status": status,
        "reason": "",
        "occurredAt": Timestamp::now().as_second(),
        "stateVersion": 1,
        "attach": "",
        "feeProjection": {"ruleVersion": "v1"},
    }))
    .expect("refund webhook JSON")
}

async fn refund_number_for(app: &Fixture, out_trade_no: &str) -> String {
    format!("xdr_{:012}", order_row(app, out_trade_no).await.id)
}

async fn refund_status(app: &Fixture, out_refund_no: &str) -> String {
    sqlx::query_scalar("SELECT status FROM payment_refunds WHERE out_refund_no = $1")
        .bind(out_refund_no)
        .fetch_one(&app.pool)
        .await
        .expect("refund status")
}

async fn refund_entry_count(app: &Fixture, out_refund_no: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*)::bigint FROM billing_entries WHERE request_id = $1 AND kind = 'refund'",
    )
    .bind(out_refund_no)
    .fetch_one(&app.pool)
    .await
    .expect("refund entry count")
}

fn signed_webhook(
    app: &Fixture,
    body: &str,
    event_id: &str,
    event_type: &str,
    tamper: bool,
) -> reqwest::RequestBuilder {
    let timestamp = now_secs();
    let nonce = mock_nonce("hook");
    let canonical = canonical_webhook(&WebhookFields {
        event_id,
        event_type,
        timestamp: &timestamp,
        nonce: &nonce,
        key_id: KID,
        raw_body: body.as_bytes(),
    })
    .expect("canonical webhook");
    let mut sign = signer().sign(&canonical).expect("webhook sign");
    if tamper {
        sign.replace_range(0..1, if &sign[0..1] == "A" { "B" } else { "A" });
    }
    app.client
        .post(app.url("/payments/webhook/xiaodou"))
        .header("X-XD-Webhook-Signature", sign)
        .header("X-XD-Webhook-Key-Id", KID)
        .header("X-XD-Webhook-Timestamp", timestamp)
        .header("X-XD-Webhook-Nonce", nonce)
        .header("X-XD-Webhook-Event-Id", event_id)
        .header("X-XD-Webhook-Event-Type", event_type)
        .body(body.to_owned())
}

async fn new_order(app: &Fixture, amount_fen: i64) -> String {
    let (status, body) = app
        .post_user("/user/topup/orders", json!({"amount_fen": amount_fen}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "placement response: {body}");
    let no = body
        .get("out_trade_no")
        .and_then(Value::as_str)
        .expect("out_trade_no");
    no.to_owned()
}

async fn balance(app: &Fixture, user_id: i64) -> i64 {
    sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&app.pool)
        .await
        .expect("balance")
}

async fn order_row(app: &Fixture, out_trade_no: &str) -> store::PaymentOrderRow {
    store::get_order_by_out_trade_no(&app.pool, out_trade_no)
        .await
        .expect("order")
        .expect("order exists")
}

#[tokio::test]
async fn payments_capabilities_are_public_to_sessions_but_key_login_is_forbidden() {
    let app = Fixture::new().await;
    let (status, body) = app.get_user("/user/topup/capabilities").await;
    assert_eq!(status, StatusCode::OK, "capabilities response: {body}");
    assert_eq!(body.get("enabled"), Some(&json!(true)));
    assert_eq!(body.get("usd_micros_per_cny_fen"), Some(&json!(1000)));

    let response = app
        .client
        .post(app.url("/user/topup/orders"))
        .bearer_auth(&app.key_token)
        .json(&json!({"amount_fen": 1200}))
        .send()
        .await
        .expect("key login placement");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "key login must not place orders"
    );
    app.close().await;
}

#[tokio::test]
async fn payments_webhook_settles_only_verified_success_and_deduplicates_event_id() {
    let app = Fixture::new().await;
    let no = new_order(&app, 1200).await;
    assert_eq!(
        balance(&app, app.user_id).await,
        0,
        "placement must not credit"
    );

    let tampered = webhook_body("evt_tamper", "PAYMENT_SUCCEEDED", &no, 1200, 0, "SUCCEEDED");
    let response = signed_webhook(&app, &tampered, "evt_tamper", "PAYMENT_SUCCEEDED", true)
        .send()
        .await
        .expect("tampered webhook");
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "tampered webhook must be rejected"
    );
    assert_ne!(
        response.bytes().await.expect("body").as_ref(),
        WEBHOOK_SUCCESS_BODY
    );
    assert_eq!(balance(&app, app.user_id).await, 0);

    let missing = app
        .client
        .post(app.url("/payments/webhook/xiaodou"))
        .body(webhook_body(
            "evt_missing",
            "PAYMENT_SUCCEEDED",
            &no,
            1200,
            0,
            "SUCCEEDED",
        ))
        .send()
        .await
        .expect("unsigned webhook");
    assert_ne!(
        missing.status(),
        StatusCode::OK,
        "missing signature headers must be rejected early"
    );
    assert_ne!(
        missing.bytes().await.expect("body").as_ref(),
        WEBHOOK_SUCCESS_BODY
    );

    let body = webhook_body("evt_ok", "PAYMENT_SUCCEEDED", &no, 1200, 7, "SUCCEEDED");
    let (first, second) = tokio::join!(
        signed_webhook(&app, &body, "evt_ok", "PAYMENT_SUCCEEDED", false).send(),
        signed_webhook(&app, &body, "evt_ok", "PAYMENT_SUCCEEDED", false).send(),
    );
    for response in [
        first.expect("first webhook"),
        second.expect("second webhook"),
    ] {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.bytes().await.expect("ack").as_ref(),
            WEBHOOK_SUCCESS_BODY
        );
    }
    assert_eq!(
        balance(&app, app.user_id).await,
        1_200_000,
        "one event credits exactly once"
    );
    let entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM billing_entries WHERE request_id = $1")
            .bind(&no)
            .fetch_one(&app.pool)
            .await
            .expect("entry count");
    assert_eq!(entries, 1, "ledger must have exactly one topup entry");
    assert_eq!(order_row(&app, &no).await.status, "SUCCEEDED");
    app.close().await;
}

#[tokio::test]
async fn payments_rejects_amount_mismatch_and_promotes_closed_but_not_unknown() {
    let app = Fixture::new().await;
    let mismatch = new_order(&app, 1200).await;
    let wrong = webhook_body(
        "evt_wrong",
        "PAYMENT_SUCCEEDED",
        &mismatch,
        1300,
        0,
        "SUCCEEDED",
    );
    let response = signed_webhook(&app, &wrong, "evt_wrong", "PAYMENT_SUCCEEDED", false)
        .send()
        .await
        .expect("mismatch webhook");
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "amount mismatch must not be acknowledged"
    );
    assert_eq!(balance(&app, app.user_id).await, 0);
    assert_ne!(order_row(&app, &mismatch).await.status, "SUCCEEDED");

    let unknown = new_order(&app, 1300).await;
    let mock = MockServer::start().await;
    mock.set_override(
        &unknown,
        MockOverride {
            status: Some("UNKNOWN".to_owned()),
            ..MockOverride::default()
        },
    );
    let (status, body) = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(status, StatusCode::OK, "reconciliation: {body}");
    assert_eq!(
        balance(&app, app.user_id).await,
        0,
        "UNKNOWN is never terminal or credited"
    );
    assert_ne!(order_row(&app, &unknown).await.status, "SUCCEEDED");

    mock.set_override(
        &unknown,
        MockOverride {
            status: Some("CLOSED".to_owned()),
            ..MockOverride::default()
        },
    );
    let (second_status, second_body) = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(
        second_status,
        StatusCode::OK,
        "second reconciliation: {second_body}"
    );
    assert_eq!(
        order_row(&app, &unknown).await.status,
        "CLOSED",
        "report: {second_body}"
    );
    let body = webhook_body(
        "evt_late",
        "PAYMENT_SUCCEEDED",
        &unknown,
        1300,
        -42,
        "SUCCEEDED",
    );
    let response = signed_webhook(&app, &body, "evt_late", "PAYMENT_SUCCEEDED", false)
        .send()
        .await
        .expect("late success");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("ack").as_ref(),
        WEBHOOK_SUCCESS_BODY
    );
    assert_eq!(
        order_row(&app, &unknown).await.status,
        "SUCCEEDED",
        "stateVersion must be ignored"
    );
    assert_eq!(balance(&app, app.user_id).await, 1_300_000);
    app.close().await;
}

#[tokio::test]
async fn payments_conflict_queries_before_reusing_the_same_placement() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    mock.conflict_amount(1500);
    let no = new_order(&app, 1500).await;
    assert_eq!(
        order_row(&app, &no).await.status,
        "PAYING",
        "replayed placement must store materials"
    );
    let calls: Vec<_> = mock
        .placement_calls()
        .into_iter()
        .filter(|call| call.body.contains(&no))
        .collect();
    assert_eq!(
        calls.len(),
        2,
        "conflict triggers a query, then a replay of the same placement"
    );
    assert_eq!(
        calls[0].request_id, calls[1].request_id,
        "X-XD-Request-Id must be reused"
    );
    assert_eq!(
        calls[0].body, calls[1].body,
        "the request body must be reused byte-for-byte"
    );
    assert_ne!(
        calls[0].nonce, calls[1].nonce,
        "each retry needs a fresh nonce"
    );
    assert!(
        mock.queries().contains(&no),
        "409 must trigger an authoritative query"
    );
    app.close().await;
}

#[tokio::test]
async fn payments_authoritative_query_settles_and_invalid_qr_is_dropped() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 1900).await;
    let stored = order_row(&app, &no).await;
    assert!(
        stored
            .qr_code
            .as_deref()
            .is_some_and(|qr| qr.starts_with("https://qr.alipay.com/")),
        "valid ALIPAY placement QR must be stored verbatim"
    );
    assert_eq!(balance(&app, app.user_id).await, 0);

    let (status, report) = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(status, StatusCode::OK, "query report: {report}");
    assert_eq!(
        order_row(&app, &no).await.status,
        "PAYING",
        "mock query returns CREATED"
    );

    mock.set_override(
        &no,
        MockOverride {
            status: Some("SUCCEEDED".to_owned()),
            amount_fen: Some(1900),
            qr_code: Some("https://evil.test/not-alipay".to_owned()),
            ..MockOverride::default()
        },
    );
    let _ = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(
        order_row(&app, &no).await.status,
        "SUCCEEDED",
        "query must compensate"
    );
    assert_eq!(
        balance(&app, app.user_id).await,
        1_900_000,
        "query credits exactly once"
    );
    let entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM billing_entries WHERE request_id = $1")
            .bind(&no)
            .fetch_one(&app.pool)
            .await
            .expect("entry count");
    assert_eq!(entries, 1, "query-driven settlement writes one ledger row");
    app.close().await;
}

#[tokio::test]
async fn payments_rejects_non_allowlisted_qr_code() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    mock.set_override(
        "pending",
        MockOverride {
            qr_code: Some("https://evil.test/not-alipay".to_owned()),
            ..MockOverride::default()
        },
    );
    let no = new_order(&app, 1250).await;
    mock.set_override(
        &no,
        MockOverride {
            qr_code: Some("https://evil.test/not-alipay".to_owned()),
            ..MockOverride::default()
        },
    );
    let id = order_row(&app, &no).await.id;
    let (status, attempt) = app
        .post_user(&format!("/user/topup/orders/{id}/attempts"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "attempt: {attempt}");
    assert!(
        order_row(&app, &no).await.qr_code.is_none(),
        "a QR outside the official allowlist must never be stored"
    );
    app.close().await;
}

#[tokio::test]
async fn payments_query_never_accepts_materials_and_attempts_return_new_ones() {
    let app = Fixture::new().await;
    let no = new_order(&app, 1100).await;
    let id = order_row(&app, &no).await.id;
    let (status, detail) = app.get_user(&format!("/user/topup/orders/{id}")).await;
    assert_eq!(status, StatusCode::OK, "detail: {detail}");
    let stored = order_row(&app, &no).await;
    assert!(
        stored
            .qr_code
            .as_deref()
            .is_some_and(|qr| qr.starts_with("https://qr.alipay.com/"))
    );
    assert!(
        !detail.to_string().contains("QUERY_MUST_BE_IGNORED"),
        "query materials must be ignored"
    );

    let (status, attempt) = app
        .post_user(&format!("/user/topup/orders/{id}/attempts"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "attempt: {attempt}");
    assert!(
        attempt
            .get("pay_url")
            .and_then(Value::as_str)
            .is_some_and(|url| url.contains("/retry/"))
    );
    app.close().await;
}

#[tokio::test]
async fn payments_refund_is_full_order_stable_and_reconciliation_reports_differences() {
    let app = Fixture::new().await;
    let no = new_order(&app, 1700).await;
    let body = webhook_body(
        "evt_refund_src",
        "PAYMENT_SUCCEEDED",
        &no,
        1700,
        0,
        "SUCCEEDED",
    );
    let ack = signed_webhook(&app, &body, "evt_refund_src", "PAYMENT_SUCCEEDED", false)
        .send()
        .await
        .expect("settle");
    assert_eq!(ack.status(), StatusCode::OK);

    let id = order_row(&app, &no).await.id;
    let (status, first) = app
        .admin_post(&format!("/api/payment/orders/{id}/refund"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "refund: {first}");
    let (status, second) = app
        .admin_post(&format!("/api/payment/orders/{id}/refund"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "replayed refund: {second}");
    assert_eq!(
        first.get("out_refund_no"),
        second.get("out_refund_no"),
        "outRefundNo must be stable"
    );
    let mock = MockServer::start().await;
    let calls: Vec<_> = mock
        .refunds()
        .into_iter()
        .filter(|call| call.out_trade_no == no)
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "an existing refund must not reach upstream again"
    );
    assert_eq!(
        calls[0].amount_fen, 1700,
        "refund must cover the whole order"
    );
    assert_eq!(
        calls[0].out_refund_no,
        first["out_refund_no"].as_str().expect("out_refund_no"),
        "the upstream refund number must match the stored one"
    );
    assert_eq!(
        calls[0].request_id, calls[0].out_refund_no,
        "the refund request id must be the stable number"
    );
    assert_eq!(
        balance(&app, app.user_id).await,
        0,
        "full refund reverses the credit"
    );

    let (status, report) = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(status, StatusCode::OK, "report: {report}");
    assert!(
        report.get("orders").is_some(),
        "report must contain order diffs"
    );
    app.close().await;
}

#[tokio::test]
async fn payments_lists_account_orders() {
    let app = Fixture::new().await;
    let first = new_order(&app, 1350).await;
    let second = new_order(&app, 1360).await;
    let (status, body) = app.get_user("/user/topup/orders").await;
    assert_eq!(status, StatusCode::OK, "list response: {body}");
    let listed = body["orders"].as_array().expect("orders array");
    assert!(listed.len() >= 2, "list must include both orders: {body}");
    let numbers: Vec<_> = listed
        .iter()
        .filter_map(|order| order["out_trade_no"].as_str())
        .collect();
    assert!(numbers.contains(&first.as_str()), "missing first order");
    assert!(numbers.contains(&second.as_str()), "missing second order");
    app.close().await;
}

#[tokio::test]
async fn payments_promotes_failed_to_succeeded() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 1370).await;
    mock.set_override(
        &no,
        MockOverride {
            status: Some("FAILED".to_owned()),
            ..MockOverride::default()
        },
    );
    let (status, report) = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(status, StatusCode::OK, "report: {report}");
    assert_eq!(order_row(&app, &no).await.status, "FAILED");

    let body = webhook_body(
        "evt_failed_late",
        "PAYMENT_SUCCEEDED",
        &no,
        1370,
        -9,
        "SUCCEEDED",
    );
    let response = signed_webhook(&app, &body, "evt_failed_late", "PAYMENT_SUCCEEDED", false)
        .send()
        .await
        .expect("late success webhook");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("ack").as_ref(),
        WEBHOOK_SUCCESS_BODY
    );
    assert_eq!(
        order_row(&app, &no).await.status,
        "SUCCEEDED",
        "FAILED must be promotable"
    );
    assert_eq!(balance(&app, app.user_id).await, 1_370_000);
    app.close().await;
}

#[tokio::test]
async fn payments_reconciles_window_older_than_newest_hundred_orders() {
    let app = Fixture::new().await;
    let old = format!("xdold{}", uuid::Uuid::new_v4().simple());
    store::create_order(
        &app.pool,
        store::NewPaymentOrder {
            out_trade_no: &old,
            user_id: app.user_id,
            amount_fen: 1380,
            usd_micros_per_cny_fen: 1000,
            credit_usd_micros: 1_380_000,
            channel: "ALIPAY_H5",
            request_id: &format!("req_{}", uuid::Uuid::new_v4().simple()),
        },
    )
    .await
    .expect("seed old order");
    sqlx::query(
        "UPDATE payment_orders SET created_at = now() - interval '2 days' WHERE out_trade_no = $1",
    )
    .bind(&old)
    .execute(&app.pool)
    .await
    .expect("backdate old order");
    for index in 0..105 {
        let no = format!("xdnew{index:03}_{}", uuid::Uuid::new_v4().simple());
        store::create_order(
            &app.pool,
            store::NewPaymentOrder {
                out_trade_no: &no,
                user_id: app.user_id,
                amount_fen: 1400,
                usd_micros_per_cny_fen: 1000,
                credit_usd_micros: 1_400_000,
                channel: "ALIPAY_H5",
                request_id: &format!("req_{}", uuid::Uuid::new_v4().simple()),
            },
        )
        .await
        .expect("seed recent order");
    }

    let from = Timestamp::now() - jiff::SignedDuration::from_secs(3 * 86_400);
    let to = Timestamp::now() - jiff::SignedDuration::from_secs(86_400);
    let (status, report) = app
        .admin_get(&format!("/api/payment/reconciliation?from={from}&to={to}"))
        .await;
    assert_eq!(status, StatusCode::OK, "report: {report}");
    assert_eq!(
        report["checked"].as_u64(),
        Some(1),
        "window outside newest 100 orders must still be checked: {report}"
    );
    app.close().await;
}

#[tokio::test]
async fn payments_refund_webhook_settles_and_deduplicates_event_id() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 1700).await;
    let source = webhook_body(
        "evt_refund_webhook_src",
        "PAYMENT_SUCCEEDED",
        &no,
        1700,
        0,
        "SUCCEEDED",
    );
    let ack = signed_webhook(
        &app,
        &source,
        "evt_refund_webhook_src",
        "PAYMENT_SUCCEEDED",
        false,
    )
    .send()
    .await
    .expect("settle order");
    assert_eq!(ack.status(), StatusCode::OK);

    mock.set_override(
        &no,
        MockOverride {
            refund_status: Some("UNKNOWN".to_owned()),
            ..MockOverride::default()
        },
    );
    let id = order_row(&app, &no).await.id;
    let (status, refund) = app
        .admin_post(&format!("/api/payment/orders/{id}/refund"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "refund: {refund}");
    let refund_no = refund["out_refund_no"]
        .as_str()
        .expect("out_refund_no")
        .to_owned();
    assert_eq!(refund_status(&app, &refund_no).await, "PENDING");
    assert_eq!(balance(&app, app.user_id).await, 1_700_000);

    let body = refund_webhook_body(
        "evt_refund_ok",
        "REFUND_SUCCEEDED",
        &no,
        &refund_no,
        1700,
        "SUCCEEDED",
    );
    let (first, second) = tokio::join!(
        signed_webhook(&app, &body, "evt_refund_ok", "REFUND_SUCCEEDED", false).send(),
        signed_webhook(&app, &body, "evt_refund_ok", "REFUND_SUCCEEDED", false).send(),
    );
    for response in [
        first.expect("first refund webhook"),
        second.expect("second refund webhook"),
    ] {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.bytes().await.expect("ack").as_ref(),
            WEBHOOK_SUCCESS_BODY
        );
    }

    assert_eq!(refund_status(&app, &refund_no).await, "SUCCEEDED");
    assert_eq!(balance(&app, app.user_id).await, 0);
    assert_eq!(refund_entry_count(&app, &refund_no).await, 1);
    let amount: i64 = sqlx::query_scalar(
        "SELECT amount_microus::bigint FROM billing_entries WHERE request_id = $1 AND kind = 'refund'",
    )
    .bind(&refund_no)
    .fetch_one(&app.pool)
    .await
    .expect("refund ledger amount");
    assert_eq!(amount, -1_700_000);
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM payment_events WHERE event_id = 'evt_refund_ok'",
    )
    .fetch_one(&app.pool)
    .await
    .expect("event count");
    assert_eq!(events, 1, "duplicate eventId must not write twice");
    app.close().await;
}

#[tokio::test]
async fn payments_failed_refund_webhook_marks_failed_without_ledger() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 1800).await;
    let source = webhook_body(
        "evt_refund_failed_src",
        "PAYMENT_SUCCEEDED",
        &no,
        1800,
        0,
        "SUCCEEDED",
    );
    let ack = signed_webhook(
        &app,
        &source,
        "evt_refund_failed_src",
        "PAYMENT_SUCCEEDED",
        false,
    )
    .send()
    .await
    .expect("settle order");
    assert_eq!(ack.status(), StatusCode::OK);
    mock.set_override(
        &no,
        MockOverride {
            refund_status: Some("UNKNOWN".to_owned()),
            ..MockOverride::default()
        },
    );
    let id = order_row(&app, &no).await.id;
    let (status, refund) = app
        .admin_post(&format!("/api/payment/orders/{id}/refund"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "refund: {refund}");
    let refund_no = refund["out_refund_no"]
        .as_str()
        .expect("out_refund_no")
        .to_owned();

    let body = refund_webhook_body(
        "evt_refund_failed",
        "REFUND_FAILED",
        &no,
        &refund_no,
        1800,
        "FAILED",
    );
    let body_clone = body.clone();
    let (first, second) = tokio::join!(
        signed_webhook(&app, &body, "evt_refund_failed", "REFUND_FAILED", false).send(),
        signed_webhook(
            &app,
            &body_clone,
            "evt_refund_failed",
            "REFUND_FAILED",
            false
        )
        .send(),
    );
    for response in [
        first.expect("first failed webhook"),
        second.expect("second failed webhook"),
    ] {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.bytes().await.expect("ack").as_ref(),
            WEBHOOK_SUCCESS_BODY
        );
    }

    assert_eq!(refund_status(&app, &refund_no).await, "FAILED");
    assert_eq!(balance(&app, app.user_id).await, 1_800_000);
    assert_eq!(refund_entry_count(&app, &refund_no).await, 0);
    app.close().await;
}

#[tokio::test]
async fn payments_unknown_refund_converges_via_authoritative_query() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 1900).await;
    let source = webhook_body(
        "evt_refund_query_src",
        "PAYMENT_SUCCEEDED",
        &no,
        1900,
        0,
        "SUCCEEDED",
    );
    let ack = signed_webhook(
        &app,
        &source,
        "evt_refund_query_src",
        "PAYMENT_SUCCEEDED",
        false,
    )
    .send()
    .await
    .expect("settle order");
    assert_eq!(ack.status(), StatusCode::OK);

    let refund_no = refund_number_for(&app, &no).await;
    mock.set_override(
        &no,
        MockOverride {
            refund_status: Some("UNKNOWN".to_owned()),
            ..MockOverride::default()
        },
    );
    mock.set_refund_query_state(&refund_no, "SUCCEEDED");
    let id = order_row(&app, &no).await.id;
    let (status, refund) = app
        .admin_post(&format!("/api/payment/orders/{id}/refund"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "refund: {refund}");
    assert_eq!(refund["state"], json!("SUCCEEDED"));
    assert_eq!(refund["out_refund_no"], json!(refund_no));
    assert!(mock.refund_queries().contains(&refund_no));
    assert_eq!(refund_status(&app, &refund_no).await, "SUCCEEDED");
    assert_eq!(balance(&app, app.user_id).await, 0);
    assert_eq!(refund_entry_count(&app, &refund_no).await, 1);
    let calls: Vec<_> = mock
        .refunds()
        .into_iter()
        .filter(|call| call.out_trade_no == no)
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "UNKNOWN must not create a new refund number"
    );
    app.close().await;
}

#[tokio::test]
async fn payments_refund_502_converges_via_authoritative_query() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 1950).await;
    let source = webhook_body(
        "evt_refund_502_src",
        "PAYMENT_SUCCEEDED",
        &no,
        1950,
        0,
        "SUCCEEDED",
    );
    let ack = signed_webhook(
        &app,
        &source,
        "evt_refund_502_src",
        "PAYMENT_SUCCEEDED",
        false,
    )
    .send()
    .await
    .expect("settle order");
    assert_eq!(ack.status(), StatusCode::OK);

    let refund_no = refund_number_for(&app, &no).await;
    mock.set_override(
        &no,
        MockOverride {
            refund_fails: true,
            ..MockOverride::default()
        },
    );
    mock.set_refund_query_state(&refund_no, "SUCCEEDED");
    let id = order_row(&app, &no).await.id;
    let (status, refund) = app
        .admin_post(&format!("/api/payment/orders/{id}/refund"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "refund: {refund}");
    assert_eq!(refund["state"], json!("SUCCEEDED"));
    assert_eq!(refund["out_refund_no"], json!(refund_no));
    assert!(mock.refund_queries().contains(&refund_no));
    assert_eq!(refund_status(&app, &refund_no).await, "SUCCEEDED");
    assert_eq!(balance(&app, app.user_id).await, 0);
    assert_eq!(refund_entry_count(&app, &refund_no).await, 1);
    app.close().await;
}

#[tokio::test]
async fn payments_concurrent_refund_requests_reuse_one_refund() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 2000).await;
    let source = webhook_body(
        "evt_refund_race_src",
        "PAYMENT_SUCCEEDED",
        &no,
        2000,
        0,
        "SUCCEEDED",
    );
    let ack = signed_webhook(
        &app,
        &source,
        "evt_refund_race_src",
        "PAYMENT_SUCCEEDED",
        false,
    )
    .send()
    .await
    .expect("settle order");
    assert_eq!(ack.status(), StatusCode::OK);

    let id = order_row(&app, &no).await.id;
    let path = format!("/api/payment/orders/{id}/refund");
    let (first, second) = tokio::join!(
        app.admin_post(&path, json!({})),
        app.admin_post(&path, json!({})),
    );
    assert_eq!(first.0, StatusCode::CREATED, "first: {}", first.1);
    assert_eq!(second.0, StatusCode::CREATED, "second: {}", second.1);
    assert_eq!(
        first.1["out_refund_no"], second.1["out_refund_no"],
        "concurrent requests must reuse one outRefundNo"
    );
    let refund_no = first.1["out_refund_no"]
        .as_str()
        .expect("out_refund_no")
        .to_owned();
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM payment_refunds WHERE out_refund_no = $1")
            .bind(&refund_no)
            .fetch_one(&app.pool)
            .await
            .expect("refund row count");
    assert_eq!(rows, 1);
    let calls: Vec<_> = mock
        .refunds()
        .into_iter()
        .filter(|call| call.out_trade_no == no)
        .collect();
    assert_eq!(calls.len(), 1, "only one upstream refund must be created");
    assert_eq!(balance(&app, app.user_id).await, 0);
    assert_eq!(refund_entry_count(&app, &refund_no).await, 1);
    app.close().await;
}

#[tokio::test]
async fn payments_reconciliation_settles_pending_refund_left_by_crash() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 2050).await;
    let source = webhook_body(
        "evt_refund_crash_src",
        "PAYMENT_SUCCEEDED",
        &no,
        2050,
        0,
        "SUCCEEDED",
    );
    let ack = signed_webhook(
        &app,
        &source,
        "evt_refund_crash_src",
        "PAYMENT_SUCCEEDED",
        false,
    )
    .send()
    .await
    .expect("settle order");
    assert_eq!(ack.status(), StatusCode::OK);
    mock.set_override(
        &no,
        MockOverride {
            refund_status: Some("UNKNOWN".to_owned()),
            ..MockOverride::default()
        },
    );
    let id = order_row(&app, &no).await.id;
    let (status, refund) = app
        .admin_post(&format!("/api/payment/orders/{id}/refund"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "refund: {refund}");
    let refund_no = refund["out_refund_no"]
        .as_str()
        .expect("out_refund_no")
        .to_owned();
    assert_eq!(refund_status(&app, &refund_no).await, "PENDING");

    mock.set_refund_query_state(&refund_no, "SUCCEEDED");
    let (status, report) = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(status, StatusCode::OK, "report: {report}");
    assert!(mock.refund_queries().contains(&refund_no));
    assert_eq!(refund_status(&app, &refund_no).await, "SUCCEEDED");
    assert_eq!(balance(&app, app.user_id).await, 0);
    assert_eq!(refund_entry_count(&app, &refund_no).await, 1);
    app.close().await;
}

#[tokio::test]
async fn payments_reconciliation_reports_amount_mismatch_without_settling() {
    let app = Fixture::new().await;
    let mock = MockServer::start().await;
    let no = new_order(&app, 2100).await;
    mock.set_override(
        &no,
        MockOverride {
            status: Some("SUCCEEDED".to_owned()),
            amount_fen: Some(2200),
            ..MockOverride::default()
        },
    );
    let (status, report) = app
        .admin_get("/api/payment/reconciliation?from=2020-01-01T00:00:00Z&to=2035-01-01T00:00:00Z")
        .await;
    assert_eq!(status, StatusCode::OK, "report: {report}");
    assert_eq!(report["amount_mismatch"], json!(1), "report: {report}");
    let row = report["orders"]
        .as_array()
        .expect("orders array")
        .iter()
        .find(|entry| entry["out_trade_no"] == json!(no))
        .unwrap_or_else(|| panic!("mismatch row missing: {report}"));
    assert_eq!(row["difference"], json!("amount_mismatch"));
    assert_eq!(row["remote_status"], json!("SUCCEEDED"));
    assert_eq!(row["local_amount_fen"], json!(2100));
    assert_eq!(row["remote_amount_fen"], json!(2200));
    assert_eq!(row["compensated"], json!(false));
    assert_eq!(balance(&app, app.user_id).await, 0);
    assert_ne!(order_row(&app, &no).await.status, "SUCCEEDED");
    let events: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM payment_events WHERE event_id = $1")
            .bind(format!("query:{no}"))
            .fetch_one(&app.pool)
            .await
            .expect("query event count");
    assert_eq!(events, 0, "mismatched query must never settle");
    app.close().await;
}

#[tokio::test]
async fn payments_reconciles_in_window_order_after_backdated_higher_id_row() {
    let app = Fixture::new().await;
    let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
    let in_window = format!("xdwin{}", uuid::Uuid::new_v4().simple());
    store::create_order(
        &app.pool,
        store::NewPaymentOrder {
            out_trade_no: &in_window,
            user_id: app.user_id,
            amount_fen: 2200,
            usd_micros_per_cny_fen: 1000,
            credit_usd_micros: 2_200_000,
            channel: "ALIPAY_H5",
            request_id: &request_id,
        },
    )
    .await
    .expect("seed in-window order");
    for index in 0..105 {
        let no = format!("xdback{index:03}_{}", uuid::Uuid::new_v4().simple());
        let old_request = format!("req_{}", uuid::Uuid::new_v4().simple());
        store::create_order(
            &app.pool,
            store::NewPaymentOrder {
                out_trade_no: &no,
                user_id: app.user_id,
                amount_fen: 2300,
                usd_micros_per_cny_fen: 1000,
                credit_usd_micros: 2_300_000,
                channel: "ALIPAY_H5",
                request_id: &old_request,
            },
        )
        .await
        .expect("seed backdated order");
        sqlx::query(
            "UPDATE payment_orders SET created_at = now() - interval '2 days' WHERE out_trade_no = $1",
        )
        .bind(&no)
        .execute(&app.pool)
        .await
        .expect("backdate order");
    }
    let from = Timestamp::now() - jiff::SignedDuration::from_secs(86_400);
    let to = Timestamp::now() + jiff::SignedDuration::from_secs(86_400);
    let (status, report) = app
        .admin_get(&format!("/api/payment/reconciliation?from={from}&to={to}"))
        .await;
    assert_eq!(status, StatusCode::OK, "report: {report}");
    assert_eq!(
        report["checked"].as_u64(),
        Some(1),
        "backdated higher-id rows must not hide an in-window order: {report}"
    );
    app.close().await;
}
