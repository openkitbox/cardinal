//! Portal persistence. The caller verifies passwords and supplies password hashes
//! and 32-byte token digests; plaintext passwords and tokens never enter SQL.

use anyhow::Context as _;
use jiff::Timestamp;
use jiff_sqlx::ToSqlx;
use sqlx::{PgPool, Postgres, Transaction};

use super::user::OWNER_LOGIN;

/// Canonicalize ASCII case and surrounding ASCII whitespace, preserving dots and plus tags.
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email
        .trim_matches(|character: char| matches!(character, ' ' | '\t' | '\n' | '\r'))
        .to_ascii_lowercase()
}

/// Snapshot used to verify a password. Session issuance must check this version.
#[derive(sqlx::FromRow)]
pub struct AccountCredential {
    pub user_id: i64,
    pub password_hash: String,
    pub password_version: i64,
}

/// Resolve the credential by normalized email; the built-in owner has no account login.
pub async fn lookup_account_credential(
    pool: &PgPool,
    email: &str,
) -> sqlx::Result<Option<AccountCredential>> {
    sqlx::query_as(
        "SELECT c.user_id, c.password_hash, c.password_version
           FROM account_credentials c JOIN users u ON u.id = c.user_id
          WHERE c.email = $1 AND u.enabled AND u.login <> $2",
    )
    .bind(normalize_email(email))
    .bind(OWNER_LOGIN)
    .fetch_optional(pool)
    .await
}

/// Resolve the credential by user id. OAuth subject reuse keeps the original
/// credential email, so the provider's current email cannot identify it.
pub async fn lookup_account_credential_by_user_id(
    pool: &PgPool,
    user_id: i64,
) -> sqlx::Result<Option<AccountCredential>> {
    sqlx::query_as(
        "SELECT c.user_id, c.password_hash, c.password_version
           FROM account_credentials c JOIN users u ON u.id = c.user_id
          WHERE c.user_id = $1 AND u.enabled AND u.login <> $2",
    )
    .bind(user_id)
    .bind(OWNER_LOGIN)
    .fetch_optional(pool)
    .await
}

/// The valid user already bound to an OAuth subject, if any. Used to avoid
/// generating a password hash that the identity transaction would discard.
pub async fn lookup_oauth_identity_user_id(
    pool: &PgPool,
    provider: &str,
    subject: &str,
) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar(
        "SELECT i.user_id
           FROM public.account_oauth_identities i
           JOIN public.users u ON u.id = i.user_id
          WHERE i.provider = $1 AND i.subject = $2
            AND u.enabled AND u.login <> $3",
    )
    .bind(provider)
    .bind(subject)
    .bind(OWNER_LOGIN)
    .fetch_optional(pool)
    .await
}

// Also exclude the owner's current group if it was renamed.
macro_rules! customer_group_filter {
    () => {
        " WHERE g.name = $1 AND lower(btrim(g.name)) NOT IN ('internal', 'owner', $2)
            AND NOT EXISTS (SELECT 1 FROM users u WHERE u.login = $2 AND u.group_id = g.id)"
    };
}

/// Find the explicitly configured group, with no fallback to the owner's group.
pub async fn configured_group(pool: &PgPool, name: &str) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar(concat!(
        "SELECT g.id FROM user_groups g",
        customer_group_filter!()
    ))
    .bind(name)
    .bind(OWNER_LOGIN)
    .fetch_optional(pool)
    .await
}

/// Returns false if the address already has a credential. The HTTP layer must
/// not disclose that distinction to the requester.
pub async fn issue_registration_challenge(
    pool: &PgPool,
    email: &str,
    token_digest: &[u8; 32],
    expires_at: Timestamp,
) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "INSERT INTO account_challenges (token_digest, email, expires_at)
         SELECT $1, $2, $3
          WHERE NOT EXISTS (SELECT 1 FROM account_credentials WHERE email = $2)",
    )
    .bind(token_digest.as_slice())
    .bind(normalize_email(email))
    .bind(expires_at.to_sqlx())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Returns false if there is no enabled customer credential for the address.
pub async fn issue_password_reset_challenge(
    pool: &PgPool,
    email: &str,
    token_digest: &[u8; 32],
    expires_at: Timestamp,
) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "INSERT INTO account_challenges (token_digest, email, user_id, expires_at)
         SELECT $1, c.email, c.user_id, $2
           FROM account_credentials c JOIN users u ON u.id = c.user_id
          WHERE c.email = $3 AND u.enabled AND u.login <> $4",
    )
    .bind(token_digest.as_slice())
    .bind(expires_at.to_sqlx())
    .bind(normalize_email(email))
    .bind(OWNER_LOGIN)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Consume the challenge and create a fresh zero-balance user with credentials.
/// Returns `None` for unusable challenges or a race with another registration
/// of the same email. A missing or reserved configured group is an error.
pub async fn complete_registration(
    pool: &PgPool,
    token_digest: &[u8; 32],
    password_hash: &str,
    group_name: &str,
) -> sqlx::Result<Option<i64>> {
    let mut tx = pool.begin().await?;
    let email: Option<String> = sqlx::query_scalar(
        "UPDATE account_challenges SET consumed_at = clock_timestamp()
          WHERE token_digest = $1 AND user_id IS NULL
            AND consumed_at IS NULL AND expires_at > clock_timestamp()
          RETURNING email",
    )
    .bind(token_digest.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(email) = email else {
        return Ok(None);
    };
    let user_id = insert_customer(&mut tx, group_name).await?;
    let credential = sqlx::query(
        "INSERT INTO account_credentials (user_id, email, password_hash)
         VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING",
    )
    .bind(user_id)
    .bind(email)
    .bind(password_hash)
    .execute(&mut *tx)
    .await?;
    if credential.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    tx.commit().await?;
    Ok(Some(user_id))
}

async fn insert_customer(
    tx: &mut Transaction<'_, Postgres>,
    group_name: &str,
) -> sqlx::Result<i64> {
    sqlx::query_scalar(concat!(
        "INSERT INTO users (login, group_id)
         SELECT $3, g.id FROM user_groups g",
        customer_group_filter!(),
        " FOR SHARE OF g RETURNING id",
    ))
    .bind(group_name)
    .bind(OWNER_LOGIN)
    .bind(format!("account-{}", uuid::Uuid::new_v4().simple()))
    .fetch_one(&mut **tx)
    .await
}

/// Consume a reset challenge, update the password, and revoke only account sessions.
pub async fn complete_password_reset(
    pool: &PgPool,
    token_digest: &[u8; 32],
    password_hash: &str,
) -> sqlx::Result<bool> {
    let mut tx = pool.begin().await?;
    let user_id: Option<i64> = sqlx::query_scalar(
        "UPDATE account_challenges SET consumed_at = clock_timestamp()
          WHERE token_digest = $1 AND user_id IS NOT NULL
            AND consumed_at IS NULL AND expires_at > clock_timestamp()
          RETURNING user_id",
    )
    .bind(token_digest.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user_id) = user_id else {
        return Ok(false);
    };
    let updated = sqlx::query(
        "UPDATE account_credentials c
            SET password_hash = $2, password_version = c.password_version + 1
           FROM users u WHERE c.user_id = $1 AND u.id = c.user_id
            AND u.enabled AND u.login <> $3",
    )
    .bind(user_id)
    .bind(password_hash)
    .bind(OWNER_LOGIN)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(false);
    }
    // This statement takes a fresh snapshot after acquiring the credential
    // lock above, so it also sees sessions inserted by prior lock holders.
    sqlx::query(
        "UPDATE portal_sessions SET revoked_at = clock_timestamp()
          WHERE user_id = $1 AND key_id IS NULL AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Serialize issuance against a password reset. After waiting for a reset,
/// PostgreSQL rechecks the version predicate on the updated credential row.
pub async fn create_account_session(
    pool: &PgPool,
    user_id: i64,
    password_version: i64,
    token_digest: &[u8; 32],
    expires_at: Timestamp,
) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "INSERT INTO portal_sessions (token_digest, user_id, expires_at)
         SELECT $1, c.user_id, $2 FROM account_credentials c JOIN users u ON u.id = c.user_id
          WHERE c.user_id = $3 AND c.password_version = $4 AND u.enabled AND u.login <> $5
          FOR SHARE OF c",
    )
    .bind(token_digest.as_slice())
    .bind(expires_at.to_sqlx())
    .bind(user_id)
    .bind(password_version)
    .bind(OWNER_LOGIN)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Issue a Key session for a principal whose plaintext Key was already
/// authenticated by the caller. The caller also rejects the admin Key.
pub async fn create_key_session(
    pool: &PgPool,
    user_id: i64,
    key_id: i64,
    token_digest: &[u8; 32],
    expires_at: Timestamp,
) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "INSERT INTO portal_sessions (token_digest, user_id, key_id, expires_at)
         SELECT $1, k.user_id, k.id, $2 FROM gateway_keys k JOIN users u ON u.id = k.user_id
          WHERE k.id = $3 AND k.user_id = $4 AND u.enabled AND k.enabled
            AND (k.expires_at IS NULL OR k.expires_at > now())",
    )
    .bind(token_digest.as_slice())
    .bind(expires_at.to_sqlx())
    .bind(key_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// A portal identity whose session and underlying principal are currently valid.
#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct PortalSession {
    pub user_id: i64,
    /// `None` is account authentication; `Some` authenticates only this Key.
    pub key_id: Option<i64>,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub expires_at: Timestamp,
}

/// Resolve a live session with its current account or Key state in one snapshot.
pub async fn lookup_session(
    pool: &PgPool,
    token_digest: &[u8; 32],
) -> sqlx::Result<Option<PortalSession>> {
    sqlx::query_as(
        "SELECT s.user_id, s.key_id, s.expires_at
           FROM portal_sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token_digest = $1 AND s.revoked_at IS NULL
            AND s.expires_at > now() AND u.enabled
            AND ((s.key_id IS NULL AND u.login <> $2 AND EXISTS (
                SELECT 1 FROM account_credentials c WHERE c.user_id = s.user_id))
             OR EXISTS (SELECT 1 FROM gateway_keys k WHERE k.id = s.key_id
                  AND k.user_id = s.user_id AND k.enabled
                  AND (k.expires_at IS NULL OR k.expires_at > now())))",
    )
    .bind(token_digest.as_slice())
    .bind(OWNER_LOGIN)
    .fetch_optional(pool)
    .await
}

/// Revoke one session; returns false when absent or already revoked.
pub async fn revoke_session(pool: &PgPool, token_digest: &[u8; 32]) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "UPDATE portal_sessions SET revoked_at = clock_timestamp()
          WHERE token_digest = $1 AND revoked_at IS NULL",
    )
    .bind(token_digest.as_slice())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// How an OAuth subject was resolved. Callers use this to distinguish a reuse
/// from an email link or a freshly provisioned account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthIdentityOutcome {
    Existing { user_id: i64 },
    Linked { user_id: i64 },
    Created { user_id: i64 },
}

impl OAuthIdentityOutcome {
    /// The account whose session may be issued.
    #[must_use]
    pub fn user_id(self) -> i64 {
        match self {
            Self::Existing { user_id } | Self::Linked { user_id } | Self::Created { user_id } => {
                user_id
            }
        }
    }
}

/// User behind a credential or an identity, with the validity checks needed
/// before signing an account session.
#[derive(sqlx::FromRow)]
struct IdentityUser {
    id: i64,
    enabled: bool,
    is_owner: bool,
}

impl IdentityUser {
    fn valid(&self) -> bool {
        self.enabled && !self.is_owner
    }
}

async fn oauth_identity_user(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    subject: &str,
) -> sqlx::Result<Option<IdentityUser>> {
    sqlx::query_as(
        "SELECT u.id, u.enabled, u.login = $3 AS is_owner
           FROM public.account_oauth_identities i
           JOIN public.users u ON u.id = i.user_id
          WHERE i.provider = $1 AND i.subject = $2",
    )
    .bind(provider)
    .bind(subject)
    .bind(OWNER_LOGIN)
    .fetch_optional(&mut **tx)
    .await
}

async fn credential_user(
    tx: &mut Transaction<'_, Postgres>,
    email: &str,
) -> sqlx::Result<Option<IdentityUser>> {
    sqlx::query_as(
        "SELECT u.id, u.enabled, u.login = $2 AS is_owner
           FROM public.account_credentials c
           JOIN public.users u ON u.id = c.user_id
          WHERE c.email = $1
          FOR UPDATE OF c",
    )
    .bind(email)
    .bind(OWNER_LOGIN)
    .fetch_optional(&mut **tx)
    .await
}

/// Resolve an OAuth identity or create the account behind it, atomically.
///
/// Ordering: an existing `(provider, subject)` wins; otherwise a verified email
/// matching `account_credentials.email` links to that account; otherwise a new
/// zero-balance customer is created in `group_name` with the supplied password
/// hash (which must be unusable to anyone but the OAuth flow). `None` means the
/// login must be rejected: unverified email, no email, or an owner/disabled
/// account. A missing or reserved group is an error, never a fallback group.
pub async fn find_or_create_oauth_identity(
    pool: &PgPool,
    provider: &str,
    subject: &str,
    email: &str,
    email_verified: bool,
    group_name: &str,
    password_hash: &str,
) -> anyhow::Result<Option<OAuthIdentityOutcome>> {
    if provider.is_empty() || subject.is_empty() {
        return Ok(None);
    }
    let mut tx = pool.begin().await?;
    if let Some(user) = oauth_identity_user(&mut tx, provider, subject).await? {
        return if user.valid() {
            Ok(Some(OAuthIdentityOutcome::Existing { user_id: user.id }))
        } else {
            Ok(None)
        };
    }
    if !email_verified {
        return Ok(None);
    }
    let email = normalize_email(email);
    if email.is_empty() {
        return Ok(None);
    }
    let existing_credential = credential_user(&mut tx, &email).await?;
    if existing_credential
        .as_ref()
        .is_some_and(|user| !user.valid())
    {
        return Ok(None);
    }
    let mut created_user = None;
    let user_id = match existing_credential {
        Some(user) => user.id,
        None => {
            let id = insert_customer(&mut tx, group_name)
                .await
                .context("no usable customer group for OAuth signup")?;
            created_user = Some(id);
            let inserted = sqlx::query(
                "INSERT INTO public.account_credentials (user_id, email, password_hash)
                 VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING",
            )
            .bind(id)
            .bind(&email)
            .bind(password_hash)
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 0 {
                // A concurrent signup took the address; link to its account
                // rather than leaving behind a user with no credential.
                let Some(winner) = credential_user(&mut tx, &email).await? else {
                    return Ok(None);
                };
                if !winner.valid() {
                    return Ok(None);
                }
                sqlx::query("DELETE FROM public.users WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                created_user = None;
                winner.id
            } else {
                id
            }
        }
    };
    let inserted = sqlx::query(
        "INSERT INTO public.account_oauth_identities (provider, subject, user_id, email)
         VALUES ($1, $2, $3, $4) ON CONFLICT (provider, subject) DO NOTHING",
    )
    .bind(provider)
    .bind(subject)
    .bind(user_id)
    .bind(&email)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        // A concurrent transaction bound the same subject first. Discard only
        // the user this transaction created; the winner may be that same user
        // when both transactions linked the same email.
        let Some(winner) = oauth_identity_user(&mut tx, provider, subject).await? else {
            return Ok(None);
        };
        if !winner.valid() {
            return Ok(None);
        }
        if let Some(created) = created_user.filter(|id| *id != winner.id) {
            sqlx::query("DELETE FROM public.users WHERE id = $1")
                .bind(created)
                .execute(&mut *tx)
                .await?;
        }
        let outcome = if created_user == Some(winner.id) {
            OAuthIdentityOutcome::Created { user_id: winner.id }
        } else {
            OAuthIdentityOutcome::Existing { user_id: winner.id }
        };
        tx.commit().await?;
        return Ok(Some(outcome));
    }
    tx.commit().await?;
    let outcome = if created_user.is_some() {
        OAuthIdentityOutcome::Created { user_id }
    } else {
        OAuthIdentityOutcome::Linked { user_id }
    };
    Ok(Some(outcome))
}
