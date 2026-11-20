//! DB-owned portal configuration: mail transport settings and login providers.
//!
//! Secrets are readable here for the runtime and for admin writes, but every
//! admin-facing or public read goes through a view without plaintext secrets.
//! A masked value sent back on a write means "keep the stored value"; an empty
//! string clears it. Masked writes decide against the locked row in the same
//! transaction as the write, so a stale writer cannot revert a newer secret.

use std::fmt;

use jiff::Timestamp;
use sqlx::PgPool;

/// Fixed value shown in place of a configured secret. It is never stored.
pub const SECRET_MASK: &str = "********";

/// Mask a secret for display, leaving an unset secret visibly empty.
#[must_use]
pub fn mask_secret(secret: &str) -> &str {
    if secret.is_empty() { "" } else { SECRET_MASK }
}

/// Full row, including secrets. Use [`PortalSettingsRow::masked`] for admin reads.
#[derive(Clone, sqlx::FromRow)]
pub struct PortalSettingsRow {
    pub mail_transport: String,
    pub mail_url: String,
    pub mail_token: String,
    pub mail_from: String,
    pub mail_origin: String,
    pub smtp_host: String,
    pub smtp_port: i32,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_tls: String,
    pub smtp_from: String,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub updated_at: Timestamp,
}

impl fmt::Debug for PortalSettingsRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortalSettingsRow")
            .field("mail_transport", &self.mail_transport)
            .field("mail_url", &self.mail_url)
            .field("mail_token", &mask_secret(&self.mail_token))
            .field("mail_from", &self.mail_from)
            .field("mail_origin", &self.mail_origin)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_username", &self.smtp_username)
            .field("smtp_password", &mask_secret(&self.smtp_password))
            .field("smtp_tls", &self.smtp_tls)
            .field("smtp_from", &self.smtp_from)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Admin-facing copy of the settings; secrets never contain plaintext.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalSettingsView {
    pub mail_transport: String,
    pub mail_url: String,
    pub mail_token: String,
    pub mail_from: String,
    pub mail_origin: String,
    pub smtp_host: String,
    pub smtp_port: i32,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_tls: String,
    pub smtp_from: String,
    pub updated_at: Timestamp,
}

impl PortalSettingsRow {
    /// Project the row into its safe admin-facing form.
    #[must_use]
    pub fn masked(&self) -> PortalSettingsView {
        PortalSettingsView {
            mail_transport: self.mail_transport.clone(),
            mail_url: self.mail_url.clone(),
            mail_token: mask_secret(&self.mail_token).to_owned(),
            mail_from: self.mail_from.clone(),
            mail_origin: self.mail_origin.clone(),
            smtp_host: self.smtp_host.clone(),
            smtp_port: self.smtp_port,
            smtp_username: self.smtp_username.clone(),
            smtp_password: mask_secret(&self.smtp_password).to_owned(),
            smtp_tls: self.smtp_tls.clone(),
            smtp_from: self.smtp_from.clone(),
            updated_at: self.updated_at,
        }
    }
}

/// Full replacement write. `mail_token` and `smtp_password` accept
/// [`SECRET_MASK`] to retain the stored value; every other field is written as
/// given. The singleton row is inserted with defaults when it does not exist.
#[derive(Debug, Clone, Copy)]
pub struct PortalSettingsInput<'a> {
    pub mail_transport: &'a str,
    pub mail_url: &'a str,
    pub mail_token: &'a str,
    pub mail_from: &'a str,
    pub mail_origin: &'a str,
    pub smtp_host: &'a str,
    pub smtp_port: i32,
    pub smtp_username: &'a str,
    pub smtp_password: &'a str,
    pub smtp_tls: &'a str,
    pub smtp_from: &'a str,
}

macro_rules! portal_settings_columns {
    () => {
        "mail_transport, mail_url, mail_token, mail_from, mail_origin, smtp_host,\
         smtp_port, smtp_username, smtp_password, smtp_tls, smtp_from"
    };
}

macro_rules! auth_provider_columns {
    () => {
        "provider, client_id, client_secret, redirect_uri, enabled, extra, updated_at"
    };
}

/// Read the singleton row. The migration seeds it; a missing row is an error
/// rather than a set of implicit defaults that callers could disagree on.
pub async fn get_portal_settings(pool: &PgPool) -> sqlx::Result<PortalSettingsRow> {
    sqlx::query_as(concat!(
        "SELECT ",
        portal_settings_columns!(),
        ", updated_at",
        " FROM public.portal_settings WHERE id"
    ))
    .fetch_one(pool)
    .await
}

/// Masked admin read of the singleton row.
pub async fn get_portal_settings_masked(pool: &PgPool) -> sqlx::Result<PortalSettingsView> {
    Ok(get_portal_settings(pool).await?.masked())
}

/// Replace the singleton row. Masked secrets keep the value currently stored
/// when the UPDATE takes the row lock; an empty secret clears it. Insert and
/// update share a transaction so the masked value is never stored literally.
pub async fn put_portal_settings(
    pool: &PgPool,
    input: &PortalSettingsInput<'_>,
) -> sqlx::Result<PortalSettingsRow> {
    let mut tx = pool.begin().await?;
    sqlx::query(concat!(
        "INSERT INTO public.portal_settings (id, ",
        portal_settings_columns!(),
        ")
         VALUES (true, $1, $2,
                 CASE WHEN $3 = $12 THEN '' ELSE $3 END,
                 $4, $5, $6, $7, $8,
                 CASE WHEN $9 = $12 THEN '' ELSE $9 END,
                 $10, $11)
         ON CONFLICT (id) DO NOTHING"
    ))
    .bind(input.mail_transport)
    .bind(input.mail_url)
    .bind(input.mail_token)
    .bind(input.mail_from)
    .bind(input.mail_origin)
    .bind(input.smtp_host)
    .bind(input.smtp_port)
    .bind(input.smtp_username)
    .bind(input.smtp_password)
    .bind(input.smtp_tls)
    .bind(input.smtp_from)
    .bind(SECRET_MASK)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query_as(concat!(
        "UPDATE public.portal_settings SET
             mail_transport = $1,
             mail_url = $2,
             mail_token = CASE WHEN $3 = $12 THEN public.portal_settings.mail_token ELSE $3 END,
             mail_from = $4,
             mail_origin = $5,
             smtp_host = $6,
             smtp_port = $7,
             smtp_username = $8,
             smtp_password = CASE WHEN $9 = $12 THEN public.portal_settings.smtp_password ELSE $9 END,
             smtp_tls = $10,
             smtp_from = $11,
             updated_at = clock_timestamp()
         WHERE id
         RETURNING ",
        portal_settings_columns!(),
        ", updated_at"
    ))
    .bind(input.mail_transport)
    .bind(input.mail_url)
    .bind(input.mail_token)
    .bind(input.mail_from)
    .bind(input.mail_origin)
    .bind(input.smtp_host)
    .bind(input.smtp_port)
    .bind(input.smtp_username)
    .bind(input.smtp_password)
    .bind(input.smtp_tls)
    .bind(input.smtp_from)
    .bind(SECRET_MASK)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Full row for one provider, including its secret.
#[derive(Clone, sqlx::FromRow)]
pub struct AuthProviderRow {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub enabled: bool,
    pub extra: serde_json::Value,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub updated_at: Timestamp,
}

impl fmt::Debug for AuthProviderRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthProviderRow")
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .field("client_secret", &mask_secret(&self.client_secret))
            .field("redirect_uri", &self.redirect_uri)
            .field("enabled", &self.enabled)
            .field("extra", &self.extra)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Admin-facing provider; `client_secret` is masked and never round-tripped.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthProviderView {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub enabled: bool,
    pub extra: serde_json::Value,
    pub updated_at: Timestamp,
}

impl AuthProviderRow {
    /// Project the row into its safe admin-facing form.
    #[must_use]
    pub fn masked(&self) -> AuthProviderView {
        AuthProviderView {
            provider: self.provider.clone(),
            client_id: self.client_id.clone(),
            client_secret: mask_secret(&self.client_secret).to_owned(),
            redirect_uri: self.redirect_uri.clone(),
            enabled: self.enabled,
            extra: self.extra.clone(),
            updated_at: self.updated_at,
        }
    }
}

/// Provider write. `client_secret` accepts [`SECRET_MASK`] to keep the stored
/// value; on a new provider a masked secret becomes empty and the provider
/// stays unusable until a real secret is supplied.
#[derive(Debug, Clone, Copy)]
pub struct AuthProviderInput<'a> {
    pub provider: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub enabled: bool,
    pub extra: &'a serde_json::Value,
}

/// Fields safe to send to the browser for rendering login buttons. No secret
/// and no provider endpoint override (`extra`) is included.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PublicAuthProvider {
    pub provider: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub enabled: bool,
}

/// Every configured provider, by name. Admin/internal read: includes secrets.
pub async fn list_auth_providers(pool: &PgPool) -> sqlx::Result<Vec<AuthProviderRow>> {
    sqlx::query_as(concat!(
        "SELECT ",
        auth_provider_columns!(),
        " FROM public.auth_providers ORDER BY provider"
    ))
    .fetch_all(pool)
    .await
}

/// Enabled providers only, for the public login list. Deliberately projects
/// only non-secret fields; use [`list_auth_providers`] for admin paths.
pub async fn list_enabled_auth_providers(pool: &PgPool) -> sqlx::Result<Vec<PublicAuthProvider>> {
    sqlx::query_as::<_, PublicAuthProvider>(
        "SELECT provider, client_id, redirect_uri, enabled
           FROM public.auth_providers WHERE enabled ORDER BY provider",
    )
    .fetch_all(pool)
    .await
}

/// One provider, or `None` when the name is not configured.
pub async fn get_auth_provider(
    pool: &PgPool,
    provider: &str,
) -> sqlx::Result<Option<AuthProviderRow>> {
    sqlx::query_as(concat!(
        "SELECT ",
        auth_provider_columns!(),
        " FROM public.auth_providers WHERE provider = $1"
    ))
    .bind(provider)
    .fetch_optional(pool)
    .await
}

/// Insert or update a provider in one transaction. A masked secret preserves
/// the value visible when the UPDATE locks the row; an empty secret clears it.
pub async fn upsert_auth_provider(
    pool: &PgPool,
    input: &AuthProviderInput<'_>,
) -> sqlx::Result<AuthProviderRow> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO public.auth_providers
             (provider, client_id, client_secret, redirect_uri, enabled, extra)
         VALUES ($1, $2, CASE WHEN $3 = $7 THEN '' ELSE $3 END, $4, $5, $6)
         ON CONFLICT (provider) DO NOTHING",
    )
    .bind(input.provider)
    .bind(input.client_id)
    .bind(input.client_secret)
    .bind(input.redirect_uri)
    .bind(input.enabled)
    .bind(input.extra)
    .bind(SECRET_MASK)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query_as(concat!(
        "UPDATE public.auth_providers SET
             client_id = $2,
             client_secret = CASE WHEN $3 = $7 THEN public.auth_providers.client_secret ELSE $3 END,
             redirect_uri = $4,
             enabled = $5,
             extra = $6,
             updated_at = clock_timestamp()
         WHERE provider = $1
         RETURNING ",
        auth_provider_columns!()
    ))
    .bind(input.provider)
    .bind(input.client_id)
    .bind(input.client_secret)
    .bind(input.redirect_uri)
    .bind(input.enabled)
    .bind(input.extra)
    .bind(SECRET_MASK)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Delete a provider. Existing `account_oauth_identities` rows are untouched.
pub async fn delete_auth_provider(pool: &PgPool, provider: &str) -> sqlx::Result<bool> {
    let result = sqlx::query("DELETE FROM public.auth_providers WHERE provider = $1")
        .bind(provider)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}
