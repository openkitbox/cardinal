//! Set CARDINAL_TEST_DATABASE_URL to an isolated PostgreSQL 18 cluster with
//! TimescaleDB >= 2.31 preloaded and a role able to create databases and the
//! extension. Each test creates and migrates its own temporary database.

use std::sync::Arc;
use std::time::Duration;

use cardinal::db::parse_pg_options;
use cardinal::store::{
    self, NewPaymentEvent, NewPaymentOrder, NewPaymentRefund, PaymentPlacement, SettleOutcome,
    settle_succeeded_payment_in_tx,
};
use jiff::Timestamp;
use serde_json::{Value, json};
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::PgPoolOptions;
use sqlx::{ConnectOptions, PgPool, Postgres};
use tokio::sync::Barrier;

struct TestDb {
    pool: PgPool,
    url: String,
}

impl TestDb {
    async fn new() -> Self {
        let base_url = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = parse_pg_options(&base_url).expect("parse test DSN");
        let name = format!("cardinal_payment_test_{}", uuid::Uuid::new_v4().simple());
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
        db
    }

    async fn close(self) {
        self.pool.close().await;
        Postgres::drop_database(&self.url)
            .await
            .expect("drop test database");
    }
}

fn order_input<'a>(out_trade_no: &'a str, user_id: i64) -> NewPaymentOrder<'a> {
    NewPaymentOrder {
        out_trade_no,
        user_id,
        amount_fen: 1200,
        usd_micros_per_cny_fen: 1000,
        credit_usd_micros: 600_000,
        channel: "ALIPAY_H5",
        request_id: "req-order",
    }
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn migration_creates_payment_schema_with_constraints() {
    let db = TestDb::new().await;
    cardinal::migrator().run(&db.pool).await.unwrap();
    let user_id = store::owner_user_id(&db.pool).await.unwrap();
    let order = store::create_order(&db.pool, order_input("trade-schema", user_id))
        .await
        .unwrap();

    assert!(
        sqlx::query(
            "INSERT INTO payment_orders
                 (out_trade_no, user_id, amount_fen, currency, usd_micros_per_cny_fen,
                  credit_usd_micros, channel, status, request_id)
             VALUES ('trade-schema', $1, 100, 'CNY', 1, 100, 'ALIPAY_H5', 'CREATED', 'req')"
        )
        .bind(user_id)
        .execute(&db.pool)
        .await
        .is_err(),
        "out_trade_no must be unique"
    );
    for (amount_fen, currency, rate, credit, status) in [
        (0, "CNY", 1_i64, 100_i64, "CREATED"),
        (100, "USD", 1, 100, "CREATED"),
        (100, "CNY", 0, 100, "CREATED"),
        (100, "CNY", 1, 0, "CREATED"),
        (100, "CNY", 1, 100, "PAID"),
    ] {
        assert!(
            sqlx::query(
                "INSERT INTO payment_orders
                     (out_trade_no, user_id, amount_fen, currency, usd_micros_per_cny_fen,
                      credit_usd_micros, channel, status, request_id)
                 VALUES ($1, $2, $3, $4, $5, $6, 'ALIPAY_H5', $7, 'req')"
            )
            .bind(format!(
                "trade-invalid-{amount_fen}-{currency}-{rate}-{credit}-{status}"
            ))
            .bind(user_id)
            .bind(amount_fen)
            .bind(currency)
            .bind(rate)
            .bind(credit)
            .bind(status)
            .execute(&db.pool)
            .await
            .is_err(),
            "invalid order row {amount_fen} {currency} {rate} {credit} {status} must be rejected"
        );
    }
    assert!(
        sqlx::query(
            "INSERT INTO payment_events (event_id, event_type, payload, headers_digest)
             VALUES ('evt-schema', 'PAYMENT_SUCCEEDED', '{}'::jsonb, 'digest')"
        )
        .execute(&db.pool)
        .await
        .is_ok(),
        "an event without a known order is allowed"
    );
    assert!(
        sqlx::query(
            "INSERT INTO payment_events (event_id, event_type, payload, headers_digest)
             VALUES ('evt-schema', 'PAYMENT_SUCCEEDED', '{}'::jsonb, 'digest')"
        )
        .execute(&db.pool)
        .await
        .is_err(),
        "event_id is the idempotency key"
    );
    assert!(
        sqlx::query(
            "INSERT INTO payment_refunds
                 (out_refund_no, order_id, amount_fen, status, request_id)
             VALUES ('refund-schema', $1, 100, 'PENDING', 'req')"
        )
        .bind(-1_i64)
        .execute(&db.pool)
        .await
        .is_err(),
        "refund order must exist"
    );
    assert!(
        sqlx::query(
            "INSERT INTO payment_refunds
                 (out_refund_no, order_id, amount_fen, status, request_id)
             VALUES ('refund-schema', $1, 100, 'PENDING', 'req')"
        )
        .bind(order.id)
        .execute(&db.pool)
        .await
        .is_ok(),
        "a valid refund row must be accepted"
    );
    assert!(
        sqlx::query(
            "INSERT INTO payment_refunds
                 (out_refund_no, order_id, amount_fen, status, request_id)
             VALUES ('refund-schema', $1, 100, 'PENDING', 'req')"
        )
        .bind(order.id)
        .execute(&db.pool)
        .await
        .is_err(),
        "out_refund_no must be unique"
    );
    db.close().await;
}

#[tokio::test]
async fn payment_order_event_refund_crud_roundtrip() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user_id = store::owner_user_id(pool).await.unwrap();
    let order = store::create_order(pool, order_input("trade-crud", user_id))
        .await
        .unwrap();
    assert_eq!(order.status, "CREATED");
    assert_eq!(
        store::get_order(pool, order.id).await.unwrap().unwrap().id,
        order.id
    );
    assert_eq!(
        store::get_order_by_out_trade_no(pool, "trade-crud")
            .await
            .unwrap()
            .unwrap()
            .id,
        order.id
    );
    assert_eq!(
        store::list_orders(pool, Some(user_id), None, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let fee_projection = json!({"platformFeeFen": 12});
    let placement = PaymentPlacement {
        open_order_id: "open-crud",
        pay_url: "https://pay.example/crud",
        qr_code: Some("https://qr.example/crud"),
        expire_at: Some(Timestamp::now()),
        fee_projection: &fee_projection,
        request_id: "req-placement",
    };
    let mut tx = pool.begin().await.unwrap();
    assert!(
        store::record_placement_in_tx(&mut tx, "trade-crud", placement)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let placed = store::get_order_by_out_trade_no(pool, "trade-crud")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(placed.status, "PAYING");
    assert_eq!(placed.open_order_id.as_deref(), Some("open-crud"));
    assert_eq!(
        placed.fee_projection.as_ref().map(|json| json.0.clone()),
        Some(fee_projection)
    );

    let payload = json!({"eventId": "evt-crud"});
    let event = NewPaymentEvent {
        event_id: "evt-crud",
        event_type: "PAYMENT_PENDING",
        payload: &payload,
        headers_digest: "digest-crud",
        out_trade_no: "trade-crud",
    };
    let mut tx = pool.begin().await.unwrap();
    assert!(store::record_event_in_tx(&mut tx, &event).await.unwrap());
    assert!(!store::record_event_in_tx(&mut tx, &event).await.unwrap());
    tx.commit().await.unwrap();
    let stored_event = store::get_event(pool, "evt-crud").await.unwrap().unwrap();
    assert_eq!(stored_event.order_id, Some(order.id));
    assert_eq!(
        store::list_events(pool, Some(order.id), 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let refund = NewPaymentRefund {
        out_refund_no: "refund-crud",
        order_id: order.id,
        amount_fen: 1200,
        request_id: "req-refund",
    };
    let mut tx = pool.begin().await.unwrap();
    let created_refund = store::create_refund_in_tx(&mut tx, &refund).await.unwrap();
    assert_eq!(created_refund.status, "PENDING");
    assert!(
        store::set_refund_status_in_tx(&mut tx, "refund-crud", "SUCCEEDED")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert_eq!(
        store::get_refund(pool, "refund-crud")
            .await
            .unwrap()
            .unwrap()
            .status,
        "SUCCEEDED"
    );
    assert_eq!(
        store::list_refunds(pool, Some(order.id), 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let mut tx = pool.begin().await.unwrap();
    assert!(
        store::set_order_status_in_tx(&mut tx, "trade-crud", "CLOSED")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert_eq!(
        store::get_order_by_out_trade_no(pool, "trade-crud")
            .await
            .unwrap()
            .unwrap()
            .status,
        "CLOSED"
    );
    db.close().await;
}

#[tokio::test]
async fn record_event_keeps_unknown_order_with_null_id() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let payload = json!({"eventId": "evt-unknown-order"});
    let event = NewPaymentEvent {
        event_id: "evt-unknown-order",
        event_type: "REFUND_SUCCEEDED",
        payload: &payload,
        headers_digest: "digest-unknown-order",
        out_trade_no: "trade-does-not-exist",
    };
    let mut tx = pool.begin().await.unwrap();
    assert!(store::record_event_in_tx(&mut tx, &event).await.unwrap());
    tx.commit().await.unwrap();

    let stored = store::get_event(pool, "evt-unknown-order")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.order_id, None);
    db.close().await;
}

async fn ensure_refund_concurrently(
    pool: PgPool,
    barrier: Arc<Barrier>,
    order_id: i64,
) -> (store::PaymentRefundRow, bool) {
    barrier.wait().await;
    let mut tx = pool.begin().await.unwrap();
    let ensured = cardinal::payments::ensure_refund_in_tx(
        &mut tx,
        &NewPaymentRefund {
            out_refund_no: "refund-race",
            order_id,
            amount_fen: 1200,
            request_id: "refund-race",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    ensured
}

#[tokio::test]
async fn concurrent_refund_creation_reuses_one_row() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user_id = store::owner_user_id(pool).await.unwrap();
    let order = store::create_order(pool, order_input("trade-refund-race", user_id))
        .await
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let first = tokio::spawn(ensure_refund_concurrently(
        pool.clone(),
        Arc::clone(&barrier),
        order.id,
    ));
    let second = tokio::spawn(ensure_refund_concurrently(
        pool.clone(),
        Arc::clone(&barrier),
        order.id,
    ));
    let (first, second) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(first, second)
    })
    .await
    .expect("concurrent refund creation did not finish");
    let first = first.expect("first refund task panicked");
    let second = second.expect("second refund task panicked");

    assert_eq!(first.0.id, second.0.id);
    assert_eq!(u8::from(first.1) + u8::from(second.1), 1);
    assert_eq!(
        count(pool, "SELECT count(*)::bigint FROM payment_refunds").await,
        1
    );
    db.close().await;
}

#[tokio::test]
async fn refund_settlement_writes_one_negative_entry_and_dedups_event_id() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user_id = store::owner_user_id(pool).await.unwrap();
    let order = store::create_order(pool, order_input("trade-refund-settle", user_id))
        .await
        .unwrap();
    let topup_payload = json!({"eventId": "evt_topup"});
    let mut tx = pool.begin().await.unwrap();
    let outcome = settle_succeeded_payment_in_tx(
        &mut tx,
        store::SettlePaymentInput {
            event_id: "evt_topup",
            event_type: "PAYMENT_SUCCEEDED",
            payload: &topup_payload,
            headers_digest: "digest-topup",
            out_trade_no: "trade-refund-settle",
            gross_amount_fen: 1200,
            note: "Xiaodou top-up",
            operator: "tester",
        },
    )
    .await
    .unwrap();
    assert!(matches!(outcome, SettleOutcome::Credited { .. }));
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    store::create_refund_in_tx(
        &mut tx,
        &NewPaymentRefund {
            out_refund_no: "refund-settle",
            order_id: order.id,
            amount_fen: 1200,
            request_id: "refund-settle",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let payload = json!({"secret": "PLANTED_REFUND_PAYLOAD_SECRET"});
    let input = cardinal::payments::SettleRefundInput {
        event_id: "evt_refund_ok",
        event_type: "REFUND_SUCCEEDED",
        payload: &payload,
        headers_digest: "digest-refund",
        out_trade_no: "trade-refund-settle",
        out_refund_no: "refund-settle",
        status: cardinal::payments::RefundStatus::Succeeded,
        amount_fen: 1200,
        note: "Xiaodou refund",
        operator: "tester",
    };
    let mut tx = pool.begin().await.unwrap();
    let first = cardinal::payments::settle_refund_in_tx(&mut tx, input)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(first, SettleOutcome::RefundSettled);

    let mut tx = pool.begin().await.unwrap();
    let duplicate = cardinal::payments::settle_refund_in_tx(&mut tx, input)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(duplicate, SettleOutcome::RefundDuplicateEvent);

    assert_eq!(
        store::get_refund(pool, "refund-settle")
            .await
            .unwrap()
            .unwrap()
            .status,
        "SUCCEEDED"
    );
    let balance: i64 = sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(balance, 0);
    assert_eq!(
        count(
            pool,
            "SELECT count(*)::bigint FROM payment_events WHERE event_id = 'evt_refund_ok'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            pool,
            "SELECT count(*)::bigint FROM billing_entries WHERE request_id = 'refund-settle'"
        )
        .await,
        1
    );
    let refund_amount: i64 = sqlx::query_scalar(
        "SELECT amount_microus::bigint FROM billing_entries WHERE request_id = 'refund-settle'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(refund_amount, -600_000);
    db.close().await;
}

async fn settle_concurrently(
    pool: PgPool,
    barrier: Arc<Barrier>,
    event_id: String,
    gross_amount_fen: i64,
) -> SettleOutcome {
    barrier.wait().await;
    let payload: Value = json!({"eventId": event_id, "grossAmountFen": gross_amount_fen});
    let mut tx = pool.begin().await.unwrap();
    let outcome = settle_succeeded_payment_in_tx(
        &mut tx,
        store::SettlePaymentInput {
            event_id: &event_id,
            event_type: "PAYMENT_SUCCEEDED",
            payload: &payload,
            headers_digest: "digest-concurrent",
            out_trade_no: "trade-concurrent",
            gross_amount_fen,
            note: "xiaodou payment",
            operator: "xiaodou",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    outcome
}

#[tokio::test]
async fn concurrent_identical_event_credits_exactly_once() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user_id = store::owner_user_id(pool).await.unwrap();
    store::create_order(pool, order_input("trade-concurrent", user_id))
        .await
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let first = tokio::spawn(settle_concurrently(
        pool.clone(),
        Arc::clone(&barrier),
        "evt-concurrent".to_owned(),
        1200,
    ));
    let second = tokio::spawn(settle_concurrently(
        pool.clone(),
        Arc::clone(&barrier),
        "evt-concurrent".to_owned(),
        1200,
    ));
    let (first, second) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(first, second)
    })
    .await
    .expect("concurrent settlements did not finish");
    let first = first.expect("first settlement task panicked");
    let second = second.expect("second settlement task panicked");

    let credited = [&first, &second]
        .iter()
        .filter(|outcome| matches!(outcome, SettleOutcome::Credited { .. }))
        .count();
    assert_eq!(
        credited, 1,
        "exactly one event must credit, got {first:?} and {second:?}"
    );
    assert_eq!(
        count(
            pool,
            "SELECT count(*)::bigint FROM payment_events WHERE event_id = 'evt-concurrent'"
        )
        .await,
        1
    );
    let balance: i64 = sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(balance, 600_000);
    let entries_sum: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_microus), 0)::bigint FROM billing_entries WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(balance, entries_sum, "balance and ledger must agree");
    assert_eq!(
        count(
            pool,
            "SELECT count(*)::bigint FROM billing_entries WHERE request_id = 'trade-concurrent'"
        )
        .await,
        1
    );
    assert_eq!(
        store::get_order_by_out_trade_no(pool, "trade-concurrent")
            .await
            .unwrap()
            .unwrap()
            .status,
        "SUCCEEDED"
    );
    db.close().await;
}

#[tokio::test]
async fn settlement_rejects_amount_mismatch_without_writing_ledger() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user_id = store::owner_user_id(pool).await.unwrap();
    store::create_order(pool, order_input("trade-mismatch", user_id))
        .await
        .unwrap();
    let payload = json!({"grossAmountFen": 1300});
    let mut tx = pool.begin().await.unwrap();
    let outcome = settle_succeeded_payment_in_tx(
        &mut tx,
        store::SettlePaymentInput {
            event_id: "evt-mismatch",
            event_type: "PAYMENT_SUCCEEDED",
            payload: &payload,
            headers_digest: "digest-mismatch",
            out_trade_no: "trade-mismatch",
            gross_amount_fen: 1300,
            note: "xiaodou payment",
            operator: "xiaodou",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        outcome,
        SettleOutcome::AmountMismatch {
            expected_fen: 1200,
            received_fen: 1300
        }
    ));
    assert_eq!(
        count(pool, "SELECT count(*)::bigint FROM payment_events").await,
        0
    );
    assert_eq!(
        count(pool, "SELECT count(*)::bigint FROM billing_entries").await,
        0
    );
    db.close().await;
}

#[tokio::test]
async fn credit_in_tx_respects_caller_transaction_and_request_id() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user_id = store::owner_user_id(pool).await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    store::credit_in_tx(
        &mut tx,
        user_id,
        "topup",
        900,
        "note",
        "tester",
        Some("req-rollback"),
    )
    .await
    .unwrap()
    .unwrap();
    drop(tx);
    assert_eq!(
        count(
            pool,
            "SELECT count(*)::bigint FROM billing_entries WHERE request_id = 'req-rollback'"
        )
        .await,
        0
    );

    let mut tx = pool.begin().await.unwrap();
    let entry = store::credit_in_tx(
        &mut tx,
        user_id,
        "topup",
        900,
        "note",
        "tester",
        Some("req-credited"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(entry.request_id.as_deref(), Some("req-credited"));
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    assert!(
        store::credit_in_tx(
            &mut tx,
            user_id,
            "topup",
            900,
            "note",
            "tester",
            Some("req-credited"),
        )
        .await
        .is_err(),
        "the same outTradeNo must not credit twice"
    );
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn legacy_credit_still_commits_one_entry_without_request_id() {
    let db = TestDb::migrated().await;
    let pool = &db.pool;
    let user_id = store::owner_user_id(pool).await.unwrap();
    let entry = store::credit(
        pool,
        user_id,
        store::CreditKind::Topup,
        750,
        "manual top-up",
        "admin",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(entry.amount_microus, 750);
    assert_eq!(entry.request_id, None);
    let balance: i64 = sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(balance, entry.balance_after_microus);
    db.close().await;
}

#[test]
fn settle_refund_input_debug_redacts_payload() {
    let secret = "PLANTED_REFUND_PAYLOAD_SECRET";
    let payload = json!({"secret": secret, "nested": [secret]});
    let input = cardinal::payments::SettleRefundInput {
        event_id: "event-12345",
        event_type: "REFUND_SUCCEEDED",
        payload: &payload,
        headers_digest: "digest-12345",
        out_trade_no: "ORDER-12345",
        out_refund_no: "REFUND-12345",
        status: cardinal::payments::RefundStatus::Succeeded,
        amount_fen: 100,
        note: "note",
        operator: "operator",
    };

    let output = format!("{input:?}");

    assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
    assert!(!output.contains(secret), "Debug leaked the refund payload");
    assert!(output.contains("REFUND-12345"), "{output}");
}
