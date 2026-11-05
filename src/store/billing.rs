//! Billing ledger persistence: settle per-request charges into
//! `billing_entries` and keep `users.balance_microus` equal to the sum of a
//! user's entries, and `gateway_keys.spent_microus` equal to the negated sum
//! of the key's charge entries.
//!
//! Pure data layer: amounts arrive already computed (`crate::billing` owns
//! the rules); this module only guarantees atomicity and idempotency. A
//! charge is keyed by its request id through the partial unique index
//! `billing_entries_charge_request`, so settling the same charge twice debits
//! once.

use std::collections::HashMap;

use sqlx::PgPool;

/// The [`EntryRow`] column list, shared by every query that returns entries
/// (a `macro_rules!` so `concat!` keeps each query a `&'static str`).
macro_rules! entry_columns {
    () => {
        "id, user_id, kind, amount_microus, balance_after_microus, request_id, \
         cost_microus, rate_bp, gateway_key_id, note, operator, created_at"
    };
}

/// One debit to settle: the amount a request costs its user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charge {
    pub user_id: i64,
    /// The dispatch request id; the idempotency key of the charge.
    pub request_id: String,
    /// Amount to debit, positive micro-USD (stored negated).
    pub amount_microus: i64,
    /// Provider cost snapshot, micro-USD (None when it could not be converted).
    pub cost_microus: Option<i64>,
    /// The caller's effective rate at request time, basis points (`None`
    /// when the row did not record one; stored as NULL).
    pub rate_bp: Option<i64>,
    /// The gateway key the request used (`None` when the row did not record
    /// one); its `spent_microus` grows with the charge.
    pub gateway_key_id: Option<i64>,
}

/// What one [`settle_charges`] call did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SettleReport {
    /// Charges written (and debited).
    pub settled: usize,
    /// Charges whose request id was already charged; skipped, no debit.
    pub duplicates: usize,
    /// Distinct user ids that no longer exist; their charges were skipped
    /// (retrying cannot succeed, so the caller drops them).
    pub unknown_users: Vec<i64>,
    /// Number of charges skipped because their user no longer exists.
    pub unknown_charges: usize,
    /// Charges skipped because negating the amount or applying it to the
    /// balance would overflow `i64` (retrying cannot succeed).
    pub overflowed: Vec<Overflowed>,
}

/// A charge [`settle_charges`] skipped on `i64` overflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overflowed {
    pub user_id: i64,
    pub request_id: String,
}

/// The answer of `GET /api/users/{id}/reconcile`: the stored balances next
/// to the ledger sums, the request log's charge total next to the ledger's
/// (`uncollected_microus` is the gap), and the server's verdict on whether
/// everything agrees.
///
/// It lives next to [`Reconciliation`] because both ends of the wire need it:
/// the handler serializes it and the GUI deserializes it (re-exported as
/// [`crate::http_client::ReconcileReport`]). Flattening the report means a
/// field added there reaches the GUI without a second place to edit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReconcileReport {
    /// The numbers, flattened into the response object.
    #[serde(flatten)]
    pub report: Reconciliation,
    /// [`Reconciliation::is_consistent`] as of the same read.
    pub consistent: bool,
}

/// A user's stored balance next to the sum of their ledger entries, the same
/// check for each of their keys, and the request log's total charge next to
/// the ledger's; each pair must be equal, and the two totals must agree.
///
/// The pairs are written by one transaction ([`settle_charges`]) and therefore
/// agree by construction; [`Self::uncollected_microus`] is the check that can
/// actually disagree, because it compares the money the request log says was
/// owed (`gateway_requests.charged_microus`, written at dispatch) with the
/// money the ledger took.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Reconciliation {
    pub balance_microus: i64,
    pub entries_sum_microus: i64,
    /// The total the request log says this user should have been charged,
    /// micro-USD, over settled requests only (positive).
    pub requests_sum_microus: i64,
    /// `requests_sum_microus - charged_total`: positive means the ledger did
    /// not take charges the request log recorded — lost revenue, or money
    /// still waiting in the writer's retry queue after a failed settlement;
    /// negative means the ledger charged more than the request rows account
    /// for.
    pub uncollected_microus: i64,
    /// One row per key the user owns, by key id.
    pub keys: Vec<KeyReconciliation>,
}

impl Reconciliation {
    /// Whether every pair the ledger promises agrees: the stored balance with
    /// its entries, each key's spend with its charge entries, and the charged
    /// total with the request log. A non-zero [`Self::uncollected_microus`] is
    /// real money and makes the user inconsistent even when the local pairs
    /// match.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        let keys_agree = self
            .keys
            .iter()
            .all(|key| key.spent_microus == key.entries_sum_microus);
        self.balance_microus == self.entries_sum_microus
            && keys_agree
            && self.uncollected_microus == 0
    }
}

/// A key's stored spend next to the negated sum of its charge entries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::FromRow,
)]
pub struct KeyReconciliation {
    pub key_id: i64,
    pub spent_microus: i64,
    pub entries_sum_microus: i64,
}

/// Settle `charges` in one transaction: lock the affected users in id order
/// (a fixed order, so concurrent settlers cannot deadlock), insert one
/// `charge` entry per new request id in input order, and write each changed
/// balance back, then add each key's newly inserted charges to its
/// `spent_microus` (one update per key, in key id order). Duplicates add
/// nothing. Either the whole batch lands or nothing does. Charges of
/// missing users, and charges whose arithmetic would overflow, are skipped
/// and reported instead of failing the batch.
pub async fn settle_charges(
    pool: &PgPool,
    charges: &[Charge],
) -> Result<SettleReport, sqlx::Error> {
    let mut report = SettleReport::default();
    if charges.is_empty() {
        return Ok(report);
    }
    let mut user_ids: Vec<i64> = charges.iter().map(|charge| charge.user_id).collect();
    user_ids.sort_unstable();
    user_ids.dedup();

    let mut tx = pool.begin().await?;
    let locked: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT id, balance_microus FROM users WHERE id = ANY($1) ORDER BY id FOR UPDATE",
    )
    .bind(&user_ids)
    .fetch_all(&mut *tx)
    .await?;
    // user id -> (running balance, changed)
    let mut balances: HashMap<i64, (i64, bool)> = locked
        .into_iter()
        .map(|(id, balance)| (id, (balance, false)))
        .collect();
    // key id -> micro-USD newly charged through it in this batch
    let mut key_spend: HashMap<i64, i64> = HashMap::new();

    for charge in charges {
        let Some((balance, changed)) = balances.get_mut(&charge.user_id) else {
            report.unknown_charges += 1;
            if !report.unknown_users.contains(&charge.user_id) {
                report.unknown_users.push(charge.user_id);
            }
            continue;
        };
        let Some((amount, after)) = charge
            .amount_microus
            .checked_neg()
            .and_then(|amount| Some((amount, balance.checked_add(amount)?)))
        else {
            report.overflowed.push(Overflowed {
                user_id: charge.user_id,
                request_id: charge.request_id.clone(),
            });
            continue;
        };
        let inserted: Option<i64> = sqlx::query_scalar(
            "INSERT INTO billing_entries
                 (user_id, kind, amount_microus, balance_after_microus, request_id, cost_microus,
                  rate_bp, gateway_key_id)
             VALUES ($1, 'charge', $2, $3, $4, $5, $6, $7)
             ON CONFLICT (request_id) WHERE kind = 'charge' DO NOTHING
             RETURNING id",
        )
        .bind(charge.user_id)
        .bind(amount)
        .bind(after)
        .bind(&charge.request_id)
        .bind(charge.cost_microus)
        .bind(charge.rate_bp)
        .bind(charge.gateway_key_id)
        .fetch_optional(&mut *tx)
        .await?;
        if inserted.is_some() {
            *balance = after;
            *changed = true;
            if let Some(key_id) = charge.gateway_key_id {
                let spent = key_spend.entry(key_id).or_default();
                *spent = spent.saturating_add(charge.amount_microus);
            }
            report.settled += 1;
        } else {
            report.duplicates += 1;
        }
    }

    for (user_id, (balance, changed)) in &balances {
        if !changed {
            continue;
        }
        sqlx::query("UPDATE users SET balance_microus = $2 WHERE id = $1")
            .bind(user_id)
            .bind(balance)
            .execute(&mut *tx)
            .await?;
    }
    let mut key_ids: Vec<(i64, i64)> = key_spend.into_iter().collect();
    key_ids.sort_unstable();
    for (key_id, amount) in key_ids {
        sqlx::query("UPDATE gateway_keys SET spent_microus = spent_microus + $2 WHERE id = $1")
            .bind(key_id)
            .bind(amount)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(report)
}

/// A user's stored balance and the sum of their ledger entries, each owned
/// key's stored spend and the negated sum of its charge entries, and the
/// request log's charge total next to the ledger's charge total, or `None`
/// when the user does not exist.
///
/// `settled_before` bounds both totals: only request rows and ledger entries
/// older than it count. A request row younger than that may still be sitting
/// in the ledger writer's flush buffer, so counting it would read a
/// just-settled charge as uncollected; conversely its ledger entry is already
/// there, so counting that alone would read as an overcharge. The two rows are
/// written by the same flush and both stamp `now()` at insert, so one cutoff
/// covers both. How old is old enough is the caller's policy (`admin` passes
/// the ledger writer's grace), and this layer does not import it: `relay`
/// depends on `store`, never the other way round. The cutoff is not a
/// statement that everything older has been settled — after a failed
/// settlement the entries sit in the retry queue while their request rows are
/// already written, which reads as uncollected until the retry lands.
pub async fn reconcile_user(
    pool: &PgPool,
    user_id: i64,
    settled_before: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Reconciliation>, sqlx::Error> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT u.balance_microus,
                COALESCE((SELECT SUM(e.amount_microus) FROM billing_entries e WHERE e.user_id = u.id), 0)::bigint
           FROM users u
          WHERE u.id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    let Some((balance_microus, entries_sum_microus)) = row else {
        return Ok(None);
    };
    let requests_sum_microus: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(charged_microus), 0)::bigint FROM gateway_requests
          WHERE user_id = $1 AND charged_microus > 0 AND ts < $2",
    )
    .bind(user_id)
    .bind(settled_before)
    .fetch_one(pool)
    .await?;
    let charged_total_microus: i64 = sqlx::query_scalar(
        "SELECT COALESCE(-SUM(amount_microus), 0)::bigint FROM billing_entries
          WHERE user_id = $1 AND kind = 'charge' AND created_at < $2",
    )
    .bind(user_id)
    .bind(settled_before)
    .fetch_one(pool)
    .await?;
    let keys = sqlx::query_as::<_, KeyReconciliation>(
        "SELECT k.id AS key_id, k.spent_microus,
                COALESCE(s.charged, 0)::bigint AS entries_sum_microus
           FROM gateway_keys k
           LEFT JOIN (SELECT e.gateway_key_id, -SUM(e.amount_microus) AS charged
                        FROM billing_entries e
                       WHERE e.user_id = $1 AND e.kind = 'charge'
                       GROUP BY e.gateway_key_id) s ON s.gateway_key_id = k.id
          WHERE k.user_id = $1
          ORDER BY k.id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(Some(Reconciliation {
        balance_microus,
        entries_sum_microus,
        requests_sum_microus,
        uncollected_microus: requests_sum_microus - charged_total_microus,
        keys,
    }))
}

/// A manual balance change made by an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditKind {
    /// Money paid in.
    Topup,
    /// A correction in either direction.
    Adjust,
}

impl CreditKind {
    /// The `billing_entries.kind` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CreditKind::Topup => "topup",
            CreditKind::Adjust => "adjust",
        }
    }
}

/// One ledger entry as stored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct EntryRow {
    pub id: i64,
    pub user_id: i64,
    pub kind: String,
    /// Signed: charges are negative, top-ups positive.
    pub amount_microus: i64,
    pub balance_after_microus: i64,
    pub request_id: Option<String>,
    pub cost_microus: Option<i64>,
    pub rate_bp: Option<i64>,
    /// The key a charge was made through; `None` on other kinds.
    pub gateway_key_id: Option<i64>,
    pub note: String,
    pub operator: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Why a [`credit`] could not be written.
#[derive(Debug, thiserror::Error)]
pub enum CreditError {
    #[error("the new balance would overflow")]
    Overflow,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Write one manual entry of `amount_microus` (signed; validated by the
/// caller) and move the user's balance by it, in one transaction with the
/// user row locked. Returns `None` when the user does not exist.
pub async fn credit(
    pool: &PgPool,
    user_id: i64,
    kind: CreditKind,
    amount_microus: i64,
    note: &str,
    operator: &str,
) -> Result<Option<EntryRow>, CreditError> {
    let mut tx = pool.begin().await?;
    let balance: Option<i64> =
        sqlx::query_scalar("SELECT balance_microus FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(balance) = balance else {
        return Ok(None);
    };
    let after = balance
        .checked_add(amount_microus)
        .ok_or(CreditError::Overflow)?;
    let entry = sqlx::query_as::<_, EntryRow>(concat!(
        "INSERT INTO billing_entries
             (user_id, kind, amount_microus, balance_after_microus, note, operator)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING ",
        entry_columns!()
    ))
    .bind(user_id)
    .bind(kind.as_str())
    .bind(amount_microus)
    .bind(after)
    .bind(note)
    .bind(operator)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE users SET balance_microus = $2 WHERE id = $1")
        .bind(user_id)
        .bind(after)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(entry))
}

/// A user's entries, newest first: at most `limit` rows with an id below
/// `before_id` (keyset pagination; `None` starts from the newest). With
/// `key_id`, only the entries made through that gateway key.
pub async fn list_entries(
    pool: &PgPool,
    user_id: i64,
    key_id: Option<i64>,
    before_id: Option<i64>,
    limit: i64,
) -> Result<Vec<EntryRow>, sqlx::Error> {
    sqlx::query_as::<_, EntryRow>(concat!(
        "SELECT ",
        entry_columns!(),
        " FROM billing_entries
          WHERE user_id = $1 AND ($2::bigint IS NULL OR id < $2)
            AND ($4::bigint IS NULL OR gateway_key_id = $4)
          ORDER BY id DESC
          LIMIT $3"
    ))
    .bind(user_id)
    .bind(before_id)
    .bind(limit)
    .bind(key_id)
    .fetch_all(pool)
    .await
}
