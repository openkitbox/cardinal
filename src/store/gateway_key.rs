use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;

/// The [`GatewayKeyRow`] select list over `gateway_keys k JOIN users u`,
/// shared by every query returning key rows (a `macro_rules!` so `concat!`
/// keeps each query a `&'static str`).
macro_rules! key_row_columns {
    () => {
        "k.id, k.key_plaintext AS key, k.label, k.enabled, k.user_id, u.login,
         k.created_at, k.created_by,
         (SELECT max(r.ts) FROM gateway_requests r WHERE r.gateway_key_id = k.id)
             AS last_used_at,
         k.disabled_at, k.expires_at, k.quota_microus, k.spent_microus"
    };
}

/// Startup seeding: idempotently record the configured gateway auth key,
/// owned by the built-in `owner` user.
pub async fn seed_gateway_key(pool: &PgPool, gateway_key: &str) -> anyhow::Result<()> {
    // Labels are unique per user: if owner's 'default' already belongs to
    // another key (the configured key was rotated), the new one gets a
    // derived label instead of failing startup.
    sqlx::query(
        "WITH owner AS (SELECT id FROM users WHERE login = 'owner')
         INSERT INTO gateway_keys (key_plaintext, label, user_id)
         SELECT $1, CASE WHEN EXISTS (SELECT 1 FROM gateway_keys k, owner
                                       WHERE k.user_id = owner.id AND k.label = 'default')
                         THEN 'default-' || substr(md5($1), 1, 8) ELSE 'default' END,
                (SELECT id FROM owner)
         ON CONFLICT (key_plaintext) DO NOTHING",
    )
    .bind(gateway_key)
    .execute(pool)
    .await?;
    Ok(())
}

/// Gateway key row for admin listing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct GatewayKeyRow {
    pub id: i64,
    /// Original key (plaintext, for display and copy in admin UI).
    pub key: String,
    pub label: String,
    pub enabled: bool,
    /// Owning user and that user's login.
    pub user_id: i64,
    pub login: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
    /// After this instant the key no longer authenticates; `None` = never.
    pub expires_at: Option<DateTime<Utc>>,
    /// Cumulative spending cap, micro-USD; `None` = unlimited.
    pub quota_microus: Option<i64>,
    /// Micro-USD charged through this key so far (the sum of its charge
    /// entries, kept by settlement).
    pub spent_microus: i64,
}

/// List gateway keys, newest first: every key, or only those `user_id` owns.
pub async fn list_gateway_keys(
    pool: &PgPool,
    user_id: Option<i64>,
) -> anyhow::Result<Vec<GatewayKeyRow>> {
    let rows = sqlx::query_as::<_, GatewayKeyRow>(concat!(
        "SELECT ",
        key_row_columns!(),
        " FROM gateway_keys k JOIN users u ON u.id = k.user_id
          WHERE $1::bigint IS NULL OR k.user_id = $1
          ORDER BY k.created_at DESC"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The terms a key is created with, already validated (`crate::key_terms`).
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyTerms {
    /// `None` = never expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Cumulative cap in micro-USD; `None` = unlimited.
    pub quota_microus: Option<i64>,
}

/// A fresh key secret: `sk-` plus 50 lowercase letters and digits (no
/// uppercase, no URL-unsafe characters).
fn new_key_secret() -> String {
    const ALPHABET: [char; 36] = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    format!("sk-{}", nanoid::nanoid!(50, &ALPHABET))
}

/// Create a new gateway key owned by `user_id`. Returns the plaintext key.
/// A label the user already has fails with [`is_label_taken`], an unknown
/// user with [`is_unknown_user`].
pub async fn create_gateway_key(
    pool: &PgPool,
    user_id: i64,
    label: &str,
    terms: KeyTerms,
    created_by: Option<&str>,
) -> anyhow::Result<String> {
    let key = new_key_secret();
    sqlx::query(
        "INSERT INTO gateway_keys
             (key_plaintext, label, created_by, user_id, expires_at, quota_microus)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&key)
    .bind(label)
    .bind(created_by)
    .bind(user_id)
    .bind(terms.expires_at)
    .bind(terms.quota_microus)
    .execute(pool)
    .await?;
    Ok(key)
}

/// Self-service creation: a new key owned by `user_id`, recorded as
/// `created_by = 'user:<login>'`, only while the user holds fewer than
/// `max_keys` keys (disabled ones included). The user row is locked
/// (`FOR NO KEY UPDATE`) before counting, so concurrent creations by the same user
/// serialize and the cap holds exactly. Returns `None` when the cap is
/// reached (or the user does not exist); a label the user already has fails
/// with [`is_label_taken`].
pub async fn create_user_gateway_key(
    pool: &PgPool,
    user_id: i64,
    label: &str,
    terms: KeyTerms,
    max_keys: i64,
) -> anyhow::Result<Option<GatewayKeyRow>> {
    let mut tx = pool.begin().await?;
    // Lock first, count second: a count in the locking statement would read
    // that statement's snapshot, taken before the lock wait, and miss the
    // key the previous lock holder just committed. Under READ COMMITTED the
    // separate count gets a fresh snapshot.
    let login: Option<String> =
        sqlx::query_scalar("SELECT login FROM users WHERE id = $1 FOR NO KEY UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(login) = login else {
        return Ok(None);
    };
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM gateway_keys WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if held >= max_keys {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, GatewayKeyRow>(concat!(
        "WITH k AS (
             INSERT INTO gateway_keys
                 (key_plaintext, label, created_by, user_id, expires_at, quota_microus)
             VALUES ($1, $2, 'user:' || $3, $4, $5, $6)
             RETURNING *
         )
         SELECT ",
        key_row_columns!(),
        " FROM k JOIN users u ON u.id = k.user_id"
    ))
    .bind(new_key_secret())
    .bind(label)
    .bind(&login)
    .bind(user_id)
    .bind(terms.expires_at)
    .bind(terms.quota_microus)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(row))
}

/// Partial key update: `None` leaves a field untouched. `expires_at` and
/// `quota_microus` are three-state: `Some(None)` clears the expiry or the
/// cap. Values are already validated (`crate::key_terms`).
#[derive(Debug, Clone, Copy, Default)]
pub struct GatewayKeyPatch<'a> {
    pub label: Option<&'a str>,
    pub enabled: Option<bool>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub quota_microus: Option<Option<i64>>,
}

/// Apply a partial update to key `id`; with `owner = Some(user_id)` only a
/// key that user owns matches. Returns false when no key matched. Disabling
/// stamps `disabled_at` (kept when already disabled); enabling clears it. A
/// label the owner already has fails with [`is_label_taken`].
pub async fn update_gateway_key(
    pool: &PgPool,
    id: i64,
    owner: Option<i64>,
    patch: GatewayKeyPatch<'_>,
) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE gateway_keys SET
             label = COALESCE($3, label),
             enabled = COALESCE($4, enabled),
             disabled_at = CASE WHEN $4::boolean IS NULL THEN disabled_at
                                WHEN $4 THEN NULL
                                WHEN enabled THEN now()
                                ELSE disabled_at END,
             expires_at = CASE WHEN $5 THEN $6 ELSE expires_at END,
             quota_microus = CASE WHEN $7 THEN $8 ELSE quota_microus END
         WHERE id = $1 AND ($2::bigint IS NULL OR user_id = $2)",
    )
    .bind(id)
    .bind(owner)
    .bind(patch.label)
    .bind(patch.enabled)
    .bind(patch.expires_at.is_some())
    .bind(patch.expires_at.flatten())
    .bind(patch.quota_microus.is_some())
    .bind(patch.quota_microus.flatten())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// True when a key write failed because the owner already has the label.
pub fn is_label_taken(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|db| db.constraint() == Some("gateway_keys_user_label_unique"))
}

/// True when `create_gateway_key` failed because `user_id` names no user
/// (the only foreign key on `gateway_keys`).
pub fn is_unknown_user(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|db| db.is_foreign_key_violation())
}
