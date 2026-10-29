use sqlx::PgPool;

/// Gateway key record: id + label + enabled state for auth decisions.
#[derive(Debug, Clone)]
pub struct GatewayKeyInfo {
    pub id: i64,
    pub label: String,
    pub enabled: bool,
}

/// Startup seeding: idempotently record the configured gateway auth key.
pub async fn seed_gateway_key(pool: &PgPool, gateway_key: &str) -> anyhow::Result<()> {
    // Labels are unique: if 'default' already belongs to another key (the
    // configured key was rotated), the new one gets a derived label instead
    // of failing startup.
    sqlx::query(
        "INSERT INTO gateway_keys (key_plaintext, label)
         SELECT $1, CASE WHEN EXISTS (SELECT 1 FROM gateway_keys WHERE label = 'default')
                         THEN 'default-' || substr(md5($1), 1, 8) ELSE 'default' END
         ON CONFLICT (key_plaintext) DO NOTHING",
    )
    .bind(gateway_key)
    .execute(pool)
    .await?;
    Ok(())
}

/// Authenticate one caller key candidate: plaintext against `gateway_keys`.
/// Returns Some(GatewayKeyInfo) on a match, None if key not found.
/// The caller checks `enabled` — a disabled key is NOT an auth success.
pub async fn gateway_key_info(pool: &PgPool, key: &str) -> anyhow::Result<Option<GatewayKeyInfo>> {
    let row = sqlx::query_as::<_, (i64, String, bool)>(
        "SELECT id, label, enabled FROM gateway_keys WHERE key_plaintext = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, label, enabled)| GatewayKeyInfo { id, label, enabled }))
}

/// Gateway key row for admin listing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GatewayKeyRow {
    pub id: i64,
    /// Original key (plaintext, for display and copy in admin UI).
    pub key: String,
    pub label: String,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<String>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub disabled_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// List all gateway keys for admin UI.
pub async fn list_gateway_keys(pool: &PgPool) -> anyhow::Result<Vec<GatewayKeyRow>> {
    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            bool,
            chrono::DateTime<chrono::Utc>,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT k.id, k.key_plaintext, k.label, k.enabled, k.created_at, k.created_by,
                (SELECT max(r.ts) FROM gateway_requests r WHERE r.caller_key = k.label),
                k.disabled_at
         FROM gateway_keys k ORDER BY k.created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, key, label, enabled, created_at, created_by, last_used_at, disabled_at)| {
                GatewayKeyRow {
                    id,
                    key,
                    label,
                    enabled,
                    created_at,
                    created_by,
                    last_used_at,
                    disabled_at,
                }
            },
        )
        .collect())
}

/// Create a new gateway key. Returns the plaintext key.
pub async fn create_gateway_key(
    pool: &PgPool,
    label: &str,
    created_by: Option<&str>,
) -> anyhow::Result<String> {
    // Lowercase letters + digits only (no uppercase, no URL-unsafe chars).
    const ALPHABET: [char; 36] = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    let key = format!("sk-{}", nanoid::nanoid!(50, &ALPHABET));
    sqlx::query("INSERT INTO gateway_keys (key_plaintext, label, created_by) VALUES ($1, $2, $3)")
        .bind(&key)
        .bind(label)
        .bind(created_by)
        .execute(pool)
        .await?;
    Ok(key)
}

/// True when `create_gateway_key` failed because the label is already taken.
pub fn is_label_taken(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|db| db.constraint() == Some("gateway_keys_label_unique"))
}

/// Enable or disable a gateway key by its id.
pub async fn set_gateway_key_enabled(
    pool: &PgPool,
    id: i64,
    enabled: bool,
) -> anyhow::Result<bool> {
    let result = if enabled {
        sqlx::query("UPDATE gateway_keys SET enabled = true, disabled_at = NULL WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?
    } else {
        sqlx::query("UPDATE gateway_keys SET enabled = false, disabled_at = now() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?
    };
    Ok(result.rows_affected() > 0)
}
