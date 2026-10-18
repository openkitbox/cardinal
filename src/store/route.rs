use sqlx::PgPool;

use super::key::{RouteEntry, RouteRow, RouteStrategy};

/// One raw `gateway_routes` row straight off SQL, before entries/strategy parsing.
type RawRouteRow = (
    String,
    serde_json::Value,
    Option<i64>,
    String,
    Option<String>,
);

pub async fn list_routes(pool: &PgPool) -> anyhow::Result<Vec<RouteRow>> {
    let rows: Vec<RawRouteRow> = sqlx::query_as(
        "SELECT alias, entries, context_window, strategy, note FROM gateway_routes ORDER BY alias",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(alias, entries, context_window, strategy, note)| {
            parse_route(alias, entries, context_window, &strategy, note)
        })
        .collect()
}

pub async fn get_route(pool: &PgPool, alias: &str) -> anyhow::Result<Option<RouteRow>> {
    let row: Option<RawRouteRow> = sqlx::query_as(
            "SELECT alias, entries, context_window, strategy, note FROM gateway_routes WHERE alias = $1",
        )
    .bind(alias)
    .fetch_optional(pool)
    .await?;
    row.map(|(alias, entries, context_window, strategy, note)| {
        parse_route(alias, entries, context_window, &strategy, note)
    })
    .transpose()
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
    let json = serde_json::to_value(entries)?;
    sqlx::query(
    "INSERT INTO gateway_routes (alias, entries, context_window, strategy, note) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (alias) DO UPDATE SET entries = EXCLUDED.entries, context_window = EXCLUDED.context_window, strategy = EXCLUDED.strategy, note = EXCLUDED.note",
  )
  .bind(alias)
  .bind(json)
  .bind(context_window)
  .bind(strategy.as_str())
  .bind(note)
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
) -> anyhow::Result<RouteRow> {
    // Empty entries are a legitimate state: deleting a key cascades it out of
    // every route, and the emptied route keeps its alias so it can be
    // re-pointed (it expands to zero candidates → 404 at dispatch).
    let entries: Vec<RouteEntry> = serde_json::from_value(entries)
        .map_err(|e| anyhow::anyhow!("route {alias} has invalid entries JSON: {e}"))?;
    let strategy =
        RouteStrategy::from_column(strategy).map_err(|e| anyhow::anyhow!("route {alias}: {e}"))?;
    Ok(RouteRow {
        alias,
        entries,
        context_window,
        strategy,
        note,
    })
}
