//! Billing ledger persistence: settle per-request charges into
//! `billing_entries` and keep `users.balance_microus` equal to the sum of a
//! user's entries.
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
         cost_microus, rate_bp, note, operator, created_at"
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

/// A user's stored balance next to the sum of their ledger entries; the two
/// must be equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reconciliation {
    pub balance_microus: i64,
    pub entries_sum_microus: i64,
}

/// Settle `charges` in one transaction: lock the affected users in id order
/// (a fixed order, so concurrent settlers cannot deadlock), insert one
/// `charge` entry per new request id in input order, and write each changed
/// balance back. Either the whole batch lands or nothing does. Charges of
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
                 (user_id, kind, amount_microus, balance_after_microus, request_id, cost_microus, rate_bp)
             VALUES ($1, 'charge', $2, $3, $4, $5, $6)
             ON CONFLICT (request_id) WHERE kind = 'charge' DO NOTHING
             RETURNING id",
        )
        .bind(charge.user_id)
        .bind(amount)
        .bind(after)
        .bind(&charge.request_id)
        .bind(charge.cost_microus)
        .bind(charge.rate_bp)
        .fetch_optional(&mut *tx)
        .await?;
        if inserted.is_some() {
            *balance = after;
            *changed = true;
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
    tx.commit().await?;
    Ok(report)
}

/// A user's stored balance and the sum of their ledger entries, or `None`
/// when the user does not exist.
pub async fn reconcile_user(
    pool: &PgPool,
    user_id: i64,
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
    Ok(
        row.map(|(balance_microus, entries_sum_microus)| Reconciliation {
            balance_microus,
            entries_sum_microus,
        }),
    )
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
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
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
/// `before_id` (keyset pagination; `None` starts from the newest).
pub async fn list_entries(
    pool: &PgPool,
    user_id: i64,
    before_id: Option<i64>,
    limit: i64,
) -> Result<Vec<EntryRow>, sqlx::Error> {
    sqlx::query_as::<_, EntryRow>(concat!(
        "SELECT ",
        entry_columns!(),
        " FROM billing_entries
          WHERE user_id = $1 AND ($2::bigint IS NULL OR id < $2)
          ORDER BY id DESC
          LIMIT $3"
    ))
    .bind(user_id)
    .bind(before_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}
