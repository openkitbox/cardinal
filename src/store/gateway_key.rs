use sqlx::PgPool;

/// Startup seeding: idempotently record the configured gateway auth key,
/// owned by the built-in `owner` user.
pub async fn seed_gateway_key(pool: &PgPool, gateway_key: &str) -> anyhow::Result<()> {
    // Labels are unique: if 'default' already belongs to another key (the
    // configured key was rotated), the new one gets a derived label instead
    // of failing startup.
    sqlx::query(
        "INSERT INTO gateway_keys (key_plaintext, label, user_id)
         SELECT $1, CASE WHEN EXISTS (SELECT 1 FROM gateway_keys WHERE label = 'default')
                         THEN 'default-' || substr(md5($1), 1, 8) ELSE 'default' END,
                (SELECT id FROM users WHERE login = 'owner')
         ON CONFLICT (key_plaintext) DO NOTHING",
    )
    .bind(gateway_key)
    .execute(pool)
    .await?;
    Ok(())
}

/// Gateway key row for admin listing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GatewayKeyRow {
    pub id: i64,
    /// Original key (plaintext, for display and copy in admin UI).
    pub key: String,
    pub label: String,
    pub enabled: bool,
    /// Owning user and that user's login.
    pub user_id: i64,
    pub login: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<String>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub disabled_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// List gateway keys, newest first: every key, or only those `user_id` owns.
pub async fn list_gateway_keys(
    pool: &PgPool,
    user_id: Option<i64>,
) -> anyhow::Result<Vec<GatewayKeyRow>> {
    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            bool,
            i64,
            String,
            chrono::DateTime<chrono::Utc>,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT k.id, k.key_plaintext, k.label, k.enabled, k.user_id, u.login,
                k.created_at, k.created_by,
                (SELECT max(r.ts) FROM gateway_requests r WHERE r.gateway_key_id = k.id),
                k.disabled_at
         FROM gateway_keys k JOIN users u ON u.id = k.user_id
         WHERE $1::bigint IS NULL OR k.user_id = $1
         ORDER BY k.created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                key,
                label,
                enabled,
                user_id,
                login,
                created_at,
                created_by,
                last_used_at,
                disabled_at,
            )| {
                GatewayKeyRow {
                    id,
                    key,
                    label,
                    enabled,
                    user_id,
                    login,
                    created_at,
                    created_by,
                    last_used_at,
                    disabled_at,
                }
            },
        )
        .collect())
}

/// Create a new gateway key owned by `user_id`. Returns the plaintext key.
pub async fn create_gateway_key(
    pool: &PgPool,
    user_id: i64,
    label: &str,
    created_by: Option<&str>,
) -> anyhow::Result<String> {
    // Lowercase letters + digits only (no uppercase, no URL-unsafe chars).
    const ALPHABET: [char; 36] = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    let key = format!("sk-{}", nanoid::nanoid!(50, &ALPHABET));
    sqlx::query(
        "INSERT INTO gateway_keys (key_plaintext, label, created_by, user_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&key)
    .bind(label)
    .bind(created_by)
    .bind(user_id)
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

/// True when `create_gateway_key` failed because `user_id` names no user
/// (the only foreign key on `gateway_keys`).
pub fn is_unknown_user(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|db| db.is_foreign_key_violation())
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
