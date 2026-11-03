use std::collections::HashSet;

use sqlx::PgConnection;
use sqlx::PgPool;

use super::key::{RouteEntry, RouteRow, RouteStrategy};
use crate::translation::ir::Effort;

/// Strip every route entry naming one of `key_ids`, in the caller's transaction.
///
/// The single owner of the "a deleted account leaves no dangling entry" rule:
/// both delete paths ([`super::key::delete_provider_key`] for one account,
/// [`super::provider::delete_provider`] for all of a provider's) call this, so
/// the entry shape is encoded in exactly one statement.
///
/// A dangling entry resolves to zero candidates (a misleading 404) and makes the
/// next whole-route save fail validation, so it is removed here, keeping the
/// remaining entries' order; a route left empty keeps its alias so it can be
/// re-pointed instead of silently vanishing from /v1/models.
///
/// Malformed rows fail closed to "left untouched" so one hand-edited row cannot
/// make every delete fail: a route whose `entries` is not a JSON array is
/// skipped, and an element whose `key_id` is missing or not a JSON number is
/// kept (it names no account, so it is not ours to drop). The type check sits in
/// `CASE` because Postgres does not guarantee `AND`/`OR` evaluation order, and
/// the comparison goes through `numeric` so a fractional or out-of-range value
/// cannot raise a cast error.
pub(super) async fn strip_entries_of_keys(
    conn: &mut PgConnection,
    key_ids: &[i64],
) -> anyhow::Result<()> {
    if key_ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "UPDATE gateway_routes
         SET entries = COALESCE(
             (SELECT jsonb_agg(entry ORDER BY ord)
                FROM jsonb_array_elements(entries) WITH ORDINALITY AS e(entry, ord)
               WHERE NOT CASE WHEN jsonb_typeof(entry->'key_id') = 'number'
                              THEN (entry->>'key_id')::numeric = ANY($1::bigint[])
                              ELSE false END),
             '[]'::jsonb)
         WHERE CASE WHEN jsonb_typeof(entries) = 'array'
                    THEN EXISTS (
                        SELECT 1 FROM jsonb_array_elements(entries) AS x(entry)
                         WHERE CASE WHEN jsonb_typeof(entry->'key_id') = 'number'
                                    THEN (entry->>'key_id')::numeric = ANY($1::bigint[])
                                    ELSE false END)
                    ELSE false END",
    )
    .bind(key_ids)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// One raw `gateway_routes` row straight off SQL, before entries/strategy parsing.
type RawRouteRow = (
    String,
    serde_json::Value,
    Option<i64>,
    String,
    Option<String>,
    Option<serde_json::Value>,
);

pub async fn list_routes(pool: &PgPool) -> anyhow::Result<Vec<RouteRow>> {
    let rows: Vec<RawRouteRow> = sqlx::query_as(
        "SELECT alias, entries, context_window, strategy, note, efforts FROM gateway_routes ORDER BY alias",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(
            |(alias, entries, context_window, strategy, note, efforts)| {
                parse_route(alias, entries, context_window, &strategy, note, efforts)
            },
        )
        .collect()
}

pub async fn get_route(pool: &PgPool, alias: &str) -> anyhow::Result<Option<RouteRow>> {
    let row: Option<RawRouteRow> = sqlx::query_as(
            "SELECT alias, entries, context_window, strategy, note, efforts FROM gateway_routes WHERE alias = $1",
        )
    .bind(alias)
    .fetch_optional(pool)
    .await?;
    row.map(
        |(alias, entries, context_window, strategy, note, efforts)| {
            parse_route(alias, entries, context_window, &strategy, note, efforts)
        },
    )
    .transpose()
}

/// `PUT /api/routes` 的 efforts 三态:字段缺席保留库值(旧客户端重存不抹掉
/// 已配置列表),显式 `null` 清除回 legacy 派生,数组设置新列表。
pub enum EffortsUpdate {
    Preserve,
    Set(Option<Vec<String>>),
}

/// The first entry whose (key, model) pair already appeared earlier in
/// `entries`, if any. A route may list an account once per model; a repeat
/// would be the same candidate twice.
#[must_use]
pub fn duplicate_entry(entries: &[RouteEntry]) -> Option<(i64, &str)> {
    let mut seen: HashSet<(i64, &str)> = HashSet::new();
    entries
        .iter()
        .map(|entry| (entry.key_id, entry.model.as_str()))
        .find(|pair| !seen.insert(*pair))
}

/// Validate and write one route: every referenced account must exist and each
/// (key, model) pair may appear only once (the same account may appear
/// repeatedly, one entry per model; enabled is irrelevant — disabled accounts
/// are skipped at dispatch). Validation and write share one transaction so a key
/// deleted mid-flight cannot leave a dangling entry.
pub async fn put_route(
    pool: &PgPool,
    alias: &str,
    entries: &[RouteEntry],
    context_window: Option<i64>,
    strategy: RouteStrategy,
    note: Option<String>,
    efforts: EffortsUpdate,
) -> anyhow::Result<()> {
    anyhow::ensure!(!alias.is_empty(), "route alias must not be empty");
    anyhow::ensure!(!entries.is_empty(), "route entries must not be empty");
    anyhow::ensure!(
        context_window.is_none_or(|window| window > 0),
        "route {alias} context window must be positive"
    );
    // Empty trims to unset so the DB never stores `""` — `note IS NULL` stays
    // the single "no note" representation.
    let note = note
        .map(|note| note.trim().to_string())
        .filter(|note| !note.is_empty());
    anyhow::ensure!(
        note.as_ref().is_none_or(|note| note.chars().count() <= 200),
        "route {alias} note exceeds 200 characters"
    );
    if let Some((key_id, model)) = duplicate_entry(entries) {
        anyhow::bail!("route {alias} lists key {key_id} with model {model} more than once");
    }
    let mut tx = pool.begin().await?;
    for entry in entries {
        anyhow::ensure!(
            !entry.model.is_empty(),
            "route {alias} has an entry with an empty model name"
        );
        anyhow::ensure!(
            entry.max_concurrency.is_none_or(|cap| cap > 0),
            "route {alias} has a non-positive entry concurrency cap"
        );
        // The registry's caps are i32; reject anything that would not fit rather
        // than letting the conversion failure silently disable the cap.
        anyhow::ensure!(
            entry
                .max_concurrency
                .is_none_or(|cap| cap <= i32::MAX as i64),
            "route {alias} entry concurrency cap exceeds the i32 registry range"
        );
        for rule in entry.rules() {
            rule.window
                .validate()
                .map_err(|error| anyhow::anyhow!("route {alias} entry {}: {error}", entry.model))?;
        }
        let exists: Option<(i64,)> =
            // FOR SHARE: a concurrent delete_provider_key (which deletes the key
            // row and strips its route entries in the same transaction) waits
            // for this transaction instead of deleting the account mid-write.
            sqlx::query_as("SELECT id FROM gateway_provider_keys WHERE id = $1 FOR SHARE")
                .bind(entry.key_id)
                .fetch_optional(&mut *tx)
                .await?;
        anyhow::ensure!(
            exists.is_some(),
            "route {alias} references a nonexistent key {}",
            entry.key_id
        );
    }
    let preserve = matches!(efforts, EffortsUpdate::Preserve);
    let efforts_json = match efforts {
        EffortsUpdate::Preserve | EffortsUpdate::Set(None) => None,
        EffortsUpdate::Set(Some(names)) => {
            let levels = Effort::route_levels(&names).map_err(|bad| {
                anyhow::anyhow!(
                    "route {alias} has an invalid effort level {bad:?} (allowed: low, medium, high, xhigh, max)"
                )
            })?;
            Some(serde_json::to_value(levels)?)
        }
    };
    let json = serde_json::to_value(entries)?;
    sqlx::query(
    "INSERT INTO gateway_routes (alias, entries, context_window, strategy, note, efforts) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (alias) DO UPDATE SET entries = EXCLUDED.entries, context_window = EXCLUDED.context_window, strategy = EXCLUDED.strategy, note = EXCLUDED.note, efforts = CASE WHEN $7 THEN gateway_routes.efforts ELSE EXCLUDED.efforts END",
  )
  .bind(alias)
  .bind(json)
  .bind(context_window)
  .bind(strategy.as_str())
  .bind(note)
  .bind(efforts_json)
  .bind(preserve)
  .execute(&mut *tx)
  .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_route(pool: &PgPool, alias: &str) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM gateway_routes WHERE alias = $1")
        .bind(alias)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

fn parse_route(
    alias: String,
    entries: serde_json::Value,
    context_window: Option<i64>,
    strategy: &str,
    note: Option<String>,
    efforts: Option<serde_json::Value>,
) -> anyhow::Result<RouteRow> {
    // Empty entries are a legitimate state: deleting a key cascades it out of
    // every route, and the emptied route keeps its alias so it can be
    // re-pointed (it expands to zero candidates → 404 at dispatch).
    let entries: Vec<RouteEntry> = serde_json::from_value(entries)
        .map_err(|e| anyhow::anyhow!("route {alias} has invalid entries JSON: {e}"))?;
    let strategy =
        RouteStrategy::from_column(strategy).map_err(|e| anyhow::anyhow!("route {alias}: {e}"))?;
    // 读路径宽容:手写过 SQL 的坏 JSON 不阻塞启动,降级为 legacy 派生并告警。
    let efforts = efforts.and_then(|value| {
        serde_json::from_value::<Vec<String>>(value)
            .map_err(|error| {
                tracing::warn!(
                    "route {alias} has invalid efforts JSON (treated as unset): {error}"
                );
                error
            })
            .ok()
    });
    Ok(RouteRow {
        alias,
        entries,
        context_window,
        strategy,
        note,
        efforts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key_id: i64, model: &str) -> RouteEntry {
        RouteEntry {
            key_id,
            model: model.to_owned(),
            label: None,
            max_concurrency: None,
            rules: Vec::new(),
            active_window: None,
        }
    }

    #[test]
    fn distinct_entries_have_no_duplicate() {
        let entries = [entry(10, "a"), entry(10, "b"), entry(3, "a")];
        assert_eq!(
            duplicate_entry(&entries),
            None,
            "same account with different models is allowed"
        );
    }

    #[test]
    fn repeated_key_and_model_is_reported() {
        let entries = [entry(10, "a"), entry(3, "b"), entry(10, "a")];
        assert_eq!(
            duplicate_entry(&entries),
            Some((10, "a")),
            "second (10, a) must be flagged"
        );
    }

    #[test]
    fn empty_entries_have_no_duplicate() {
        assert_eq!(duplicate_entry(&[]), None, "no entries, no duplicate");
    }
}
