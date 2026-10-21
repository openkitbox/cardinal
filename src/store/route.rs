use sqlx::PgPool;

use super::key::{RouteEntry, RouteRow, RouteStrategy};
use crate::translation::ir::Effort;

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

/// Validate and write one route: every referenced key must exist (the same
/// key may appear repeatedly, one entry per model; enabled is irrelevant —
/// disabled keys are skipped at dispatch). Validation and write share one
/// transaction so a key deleted mid-flight cannot leave a dangling entry.
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
            sqlx::query_as("SELECT id FROM gateway_provider_keys WHERE id = $1")
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
