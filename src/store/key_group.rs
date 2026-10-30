//! Account groups: named, many-to-many sets of provider keys.
//!
//! Membership lives only in `gateway_key_group_members`, so a key row carries
//! no group data. Deleting a group or a key cascades to the membership rows
//! and never touches the other side.

use sqlx::PgPool;

/// Longest group name, in characters (mirrors the column CHECK in 0009).
/// The "at most 32 characters" message in `normalize_group_name` must stay in
/// sync with this value.
const MAX_NAME_CHARS: usize = 32;

/// One group with its member key ids (ascending). An empty group has no ids.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyGroupView {
    pub id: i64,
    pub name: String,
    pub key_ids: Vec<i64>,
}

/// Why a group write failed. The admin layer maps the first two to 400/409,
/// so they stay distinguishable from storage failures.
#[derive(Debug, thiserror::Error)]
pub enum KeyGroupError {
    #[error("invalid group name: {0}")]
    InvalidName(&'static str),
    #[error("a group named {0:?} already exists")]
    NameTaken(String),
    #[error(transparent)]
    Other(#[from] sqlx::Error),
}

/// Trim and validate a group name: non-empty, at most 32 characters. The
/// returned slice is what gets stored.
fn normalize_group_name(raw: &str) -> Result<&str, KeyGroupError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(KeyGroupError::InvalidName("must not be empty"));
    }
    if name.chars().any(char::is_control) {
        return Err(KeyGroupError::InvalidName(
            "must not contain control characters",
        ));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(KeyGroupError::InvalidName("must be at most 32 characters"));
    }
    Ok(name)
}

/// Recognize the name-uniqueness violation from the write itself (no
/// check-then-write race).
fn name_write_error(error: sqlx::Error, name: &str) -> KeyGroupError {
    match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            KeyGroupError::NameTaken(name.to_owned())
        }
        _ => KeyGroupError::Other(error),
    }
}

/// Every group in id order, each with its member key ids ascending.
pub async fn list_key_groups(pool: &PgPool) -> anyhow::Result<Vec<KeyGroupView>> {
    let rows: Vec<(i64, String, Vec<i64>)> = sqlx::query_as(
        "SELECT g.id, g.name,
                COALESCE(array_agg(m.key_id ORDER BY m.key_id) FILTER (WHERE m.key_id IS NOT NULL),
                         '{}'::bigint[])
         FROM gateway_key_groups g
         LEFT JOIN gateway_key_group_members m ON m.group_id = g.id
         GROUP BY g.id, g.name
         ORDER BY g.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, key_ids)| KeyGroupView { id, name, key_ids })
        .collect())
}

pub async fn create_key_group(pool: &PgPool, name: &str) -> Result<i64, KeyGroupError> {
    let name = normalize_group_name(name)?;
    sqlx::query_scalar("INSERT INTO gateway_key_groups (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .map_err(|error| name_write_error(error, name))
}

/// Rename a group. `Ok(false)` when no such group exists.
pub async fn rename_key_group(pool: &PgPool, id: i64, name: &str) -> Result<bool, KeyGroupError> {
    let name = normalize_group_name(name)?;
    let result = sqlx::query("UPDATE gateway_key_groups SET name = $2 WHERE id = $1")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .map_err(|error| name_write_error(error, name))?;
    Ok(result.rows_affected() > 0)
}

/// Delete a group; its membership rows cascade, the keys stay. `Ok(false)`
/// when no such group exists.
pub async fn delete_key_group(pool: &PgPool, id: i64) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM gateway_key_groups WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Replace one key's group memberships with exactly `group_ids` (duplicates
/// collapse; empty = leave every group). Runs on the caller's transaction: an
/// unknown group id is an error and the caller rolls back.
pub(super) async fn replace_key_groups(
    conn: &mut sqlx::PgConnection,
    key_id: i64,
    group_ids: &[i64],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM gateway_key_group_members WHERE key_id = $1")
        .bind(key_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO gateway_key_group_members (group_id, key_id)
         SELECT DISTINCT g, $1 FROM unnest($2::bigint[]) AS g",
    )
    .bind(key_id)
    .bind(group_ids)
    .execute(&mut *conn)
    .await
    .map_err(|error| match &error {
        // Keep the constraint name and SQL text out of the message: it reaches
        // the admin API client.
        sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
            anyhow::anyhow!("unknown group id")
        }
        _ => anyhow::Error::new(error),
    })?;
    Ok(())
}
