//! Users and user groups: who owns a gateway key and how they are priced.
//!
//! A group is the product (pricing rate and route visibility); a user owns
//! keys and a balance. Neither touches upstream account scheduling.

use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;

/// Login of the built-in user that owns pre-existing and config-seeded keys
/// (created by migration 0012, member of the zero-rate `internal` group).
///
/// Its keys belong to no real user identity, so the usage client and user
/// series name them by bare label ([`crate::store::usage::usage_trend`]) rather
/// than `login/label` or an owner aggregate, and the admin UI lists them by
/// label rather than by login.
pub const OWNER_LOGIN: &str = "owner";

/// Authenticated caller identity: one gateway key joined with its owning user
/// and that user's group, read in a single query so auth, admission and
/// pricing all see the same snapshot.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Principal {
    pub key_id: i64,
    pub key_label: String,
    pub key_enabled: bool,
    pub key_expires_at: Option<DateTime<Utc>>,
    /// The key's cumulative spending cap, micro-USD; `None` = unlimited.
    pub key_quota_microus: Option<i64>,
    /// Micro-USD charged through the key so far (lags settlement by up to
    /// one ledger flush).
    pub key_spent_microus: i64,
    pub user_id: i64,
    pub login: String,
    pub user_enabled: bool,
    pub group_id: i64,
    pub group_rate_bp: i64,
    /// User-level rate override; `None` means the group rate applies.
    pub user_rate_bp: Option<i64>,
    pub balance_microus: i64,
    pub max_concurrent: i32,
    /// Route whitelist from the group; `None` means every route is visible.
    pub route_aliases: Option<Vec<String>>,
}

/// Look up the principal behind a plaintext gateway key. Returns `None` when
/// no key matches. Enabled and expiry checks are the caller's job, so a
/// disabled or expired key still comes back as `Some`.
pub async fn authenticate_principal(pool: &PgPool, key: &str) -> anyhow::Result<Option<Principal>> {
    let principal = sqlx::query_as::<_, Principal>(
        "SELECT k.id AS key_id, k.label AS key_label, k.enabled AS key_enabled,
                k.expires_at AS key_expires_at, k.quota_microus AS key_quota_microus,
                k.spent_microus AS key_spent_microus, u.id AS user_id, u.login,
                u.enabled AS user_enabled, g.id AS group_id, g.rate_bp AS group_rate_bp,
                u.rate_bp AS user_rate_bp, u.balance_microus, u.max_concurrent,
                g.route_aliases
         FROM gateway_keys k
         JOIN users u ON u.id = k.user_id
         JOIN user_groups g ON g.id = u.group_id
         WHERE k.key_plaintext = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;
    Ok(principal)
}

/// Id of the built-in `owner` user. Fails if migration 0012 has not run or
/// the row was removed.
pub async fn owner_user_id(pool: &PgPool) -> anyhow::Result<i64> {
    let id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE login = $1")
        .bind(OWNER_LOGIN)
        .fetch_one(pool)
        .await?;
    Ok(id)
}

/// One user for the admin and self-service views: the row joined with its
/// group's name and rate. `rate_bp` is the user override (`None` = the group
/// rate applies); `crate::billing::effective_rate_bp` combines the two.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub login: String,
    pub display_name: String,
    pub enabled: bool,
    pub group_id: i64,
    pub group_name: String,
    pub rate_bp: Option<i64>,
    pub group_rate_bp: i64,
    pub balance_microus: i64,
    pub max_concurrent: i32,
    pub rpm: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// One user group with its member count. `route_aliases` `None` means every
/// route is visible; an array is the whitelist. The built-in `internal`
/// group (rate 0, owner of the built-in `owner` user) is an ordinary row:
/// changing its rate or whitelist changes what in-house callers pay and see.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct GroupRow {
    pub id: i64,
    pub name: String,
    pub rate_bp: i64,
    pub route_aliases: Option<Vec<String>>,
    pub user_count: i64,
}

/// Fields of a new user. The balance always starts at zero: money only
/// enters through a ledger entry.
#[derive(Debug, Clone, Copy)]
pub struct NewUser<'a> {
    pub login: &'a str,
    pub display_name: &'a str,
    pub group_id: i64,
    pub rate_bp: Option<i64>,
    pub max_concurrent: Option<i32>,
}

/// Partial user update: `None` leaves a field untouched. `rate_bp` is
/// three-state: `Some(None)` clears the override back to the group rate.
/// The balance is deliberately absent; it changes only with a ledger entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserPatch<'a> {
    pub display_name: Option<&'a str>,
    pub enabled: Option<bool>,
    pub group_id: Option<i64>,
    pub rate_bp: Option<Option<i64>>,
    pub max_concurrent: Option<i32>,
}

/// Partial group update: `None` leaves a field untouched. `route_aliases`
/// is three-state: `Some(None)` makes every route visible again.
#[derive(Debug, Clone, Copy, Default)]
pub struct GroupPatch<'a> {
    pub name: Option<&'a str>,
    pub rate_bp: Option<i64>,
    pub route_aliases: Option<Option<&'a [String]>>,
}

/// Users joined with their group, every user or only `id`, by id.
async fn select_users(pool: &PgPool, id: Option<i64>) -> sqlx::Result<Vec<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        "SELECT u.id, u.login, u.display_name, u.enabled, u.group_id,
                g.name AS group_name, u.rate_bp, g.rate_bp AS group_rate_bp,
                u.balance_microus, u.max_concurrent, u.rpm, u.created_at
         FROM users u JOIN user_groups g ON g.id = u.group_id
         WHERE $1::bigint IS NULL OR u.id = $1
         ORDER BY u.id",
    )
    .bind(id)
    .fetch_all(pool)
    .await
}

/// Every user, by id.
pub async fn list_users(pool: &PgPool) -> anyhow::Result<Vec<UserRow>> {
    Ok(select_users(pool, None).await?)
}

/// One user, or `None` when the id names no user.
pub async fn get_user(pool: &PgPool, id: i64) -> anyhow::Result<Option<UserRow>> {
    Ok(select_users(pool, Some(id)).await?.pop())
}

/// Insert a user and return its id. A taken login fails with a unique
/// violation ([`is_conflict`]), an unknown group with a foreign-key
/// violation ([`is_unknown_group`]).
pub async fn create_user(pool: &PgPool, user: NewUser<'_>) -> anyhow::Result<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users (login, display_name, group_id, rate_bp, max_concurrent)
         VALUES ($1, $2, $3, $4, COALESCE($5, 4))
         RETURNING id",
    )
    .bind(user.login)
    .bind(user.display_name)
    .bind(user.group_id)
    .bind(user.rate_bp)
    .bind(user.max_concurrent)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// Apply a partial update. Returns false when the id names no user.
pub async fn patch_user(pool: &PgPool, id: i64, patch: UserPatch<'_>) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE users SET
             display_name = COALESCE($2, display_name),
             enabled = COALESCE($3, enabled),
             group_id = COALESCE($4, group_id),
             rate_bp = CASE WHEN $5 THEN $6 ELSE rate_bp END,
             max_concurrent = COALESCE($7, max_concurrent)
         WHERE id = $1",
    )
    .bind(id)
    .bind(patch.display_name)
    .bind(patch.enabled)
    .bind(patch.group_id)
    .bind(patch.rate_bp.is_some())
    .bind(patch.rate_bp.flatten())
    .bind(patch.max_concurrent)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Every group with its member count, by id.
pub async fn list_groups(pool: &PgPool) -> anyhow::Result<Vec<GroupRow>> {
    let rows = sqlx::query_as::<_, GroupRow>(
        "SELECT g.id, g.name, g.rate_bp, g.route_aliases,
                (SELECT COUNT(*) FROM users u WHERE u.group_id = g.id)::bigint AS user_count
         FROM user_groups g
         ORDER BY g.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// One group, or `None` when the id names no group.
pub async fn get_group(pool: &PgPool, id: i64) -> anyhow::Result<Option<GroupRow>> {
    let row = sqlx::query_as::<_, GroupRow>(
        "SELECT g.id, g.name, g.rate_bp, g.route_aliases,
                (SELECT COUNT(*) FROM users u WHERE u.group_id = g.id)::bigint AS user_count
         FROM user_groups g
         WHERE g.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Insert a group and return its id. A taken name fails with a unique
/// violation ([`is_conflict`]).
pub async fn create_group(
    pool: &PgPool,
    name: &str,
    rate_bp: i64,
    route_aliases: Option<&[String]>,
) -> anyhow::Result<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO user_groups (name, rate_bp, route_aliases) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(name)
    .bind(rate_bp)
    .bind(route_aliases)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// Apply a partial update. Returns false when the id names no group.
pub async fn patch_group(pool: &PgPool, id: i64, patch: GroupPatch<'_>) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE user_groups SET
             name = COALESCE($2, name),
             rate_bp = COALESCE($3, rate_bp),
             route_aliases = CASE WHEN $4 THEN $5 ELSE route_aliases END
         WHERE id = $1",
    )
    .bind(id)
    .bind(patch.name)
    .bind(patch.rate_bp)
    .bind(patch.route_aliases.is_some())
    .bind(patch.route_aliases.flatten())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// True when a user or group write failed on a unique name (`login` /
/// group `name`).
pub fn is_conflict(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|db| db.is_unique_violation())
}

/// True when a user write failed because `group_id` names no group (the
/// only foreign key on `users`).
pub fn is_unknown_group(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|db| db.is_foreign_key_violation())
}
