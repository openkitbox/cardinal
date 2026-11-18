use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

use crate::relay::capabilities::workbuddy::host_build_from_value;

/// Persisted WorkBuddy OAuth credentials and account identity.
#[derive(Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WorkbuddyOAuth {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_expires_at: Option<DateTime<Utc>>,
    pub uid: String,
    /// Human-readable account name for display only (nickname / phone / uid,
    /// with the enterprise suffix). Never used for request headers or identity;
    /// optional so bundles stored before this field round-trip through CAS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    pub domain: Option<String>,
    pub token_type: Option<String>,
    pub enterprise_id: Option<String>,
}

impl std::fmt::Debug for WorkbuddyOAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkbuddyOAuth")
            .field("expires_at", &self.expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("uid", &self.uid)
            .field("account_name", &self.account_name)
            .field("domain", &self.domain)
            .field("token_type", &self.token_type)
            .field("enterprise_id", &self.enterprise_id)
            .finish_non_exhaustive()
    }
}

impl WorkbuddyOAuth {
    /// Validate the shape and bounded lifetime of a persisted bundle.
    ///
    /// An already-expired bundle is accepted deliberately: the token manager
    /// refreshes it before use. The upper bound prevents accidentally storing a
    /// vendor timestamp with the wrong unit or an unbounded credential.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.access_token.trim().is_empty() {
            anyhow::bail!("WorkBuddy access token is empty");
        }
        if self.refresh_token.trim().is_empty() {
            anyhow::bail!("WorkBuddy refresh token is empty");
        }
        let bound = Utc::now()
            .checked_add_signed(Duration::days(730))
            .ok_or_else(|| anyhow::anyhow!("WorkBuddy expiry bound overflowed"))?;
        if self.expires_at > bound {
            anyhow::bail!("WorkBuddy access expiry is too far in the future");
        }
        if self
            .refresh_expires_at
            .is_some_and(|expires_at| expires_at > bound)
        {
            anyhow::bail!("WorkBuddy refresh expiry is too far in the future");
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| host_build_from_value(domain).is_none())
        {
            anyhow::bail!("WorkBuddy domain is not an allowed HTTPS host");
        }
        Ok(())
    }
}
