//! The Kiro OIDC credential bundle: the exact JSON persisted in
//! `gateway_provider_keys.oauth` and accepted by the admin key API. Pure data
//! — validation and freshness decisions only, no I/O and no vendor knowledge.

/// Kiro's AWS SSO OIDC credential (device-code / Builder ID login).
///
/// Persisted as camelCase JSON with a Unix-seconds `expiresAt`. This is the
/// stored/admin shape, NOT the vendor's raw account export: that export
/// carries millisecond `expiresAt` and an account-level `profileArn`, and
/// `scripts/import-kiro-account.py` converts it to this document.
/// Debug output redacts every secret: this value travels through
/// error paths and logs, and a leaked token grants the account.

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KiroOAuth {
    /// Bearer token for the Kiro API (secret).
    pub access_token: String,
    /// Unix seconds at which `access_token` expires.
    pub expires_at: i64,
    /// Refresh token exchanged at the SSO OIDC token endpoint (secret).
    pub refresh_token: String,
    /// AWS SSO OIDC device-registration client id.
    pub client_id: String,
    /// AWS SSO OIDC device-registration client secret (secret).
    pub client_secret: String,
    /// Default AWS region of the credential.
    pub region: String,
    /// Region of the SSO OIDC token endpoint (token refresh).
    pub auth_region: String,
    /// Region of the Kiro API endpoint.
    pub api_region: String,
    /// CodeWhisperer profile ARN, when the login carried one.
    #[serde(default)]
    pub profile_arn: Option<String>,
}

impl KiroOAuth {
    /// Every required field must hold a real value; whitespace-only counts as
    /// empty (an unusable secret must never be stored).
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, value) in [
            ("access_token", &self.access_token),
            ("refresh_token", &self.refresh_token),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("region", &self.region),
            ("auth_region", &self.auth_region),
            ("api_region", &self.api_region),
        ] {
            anyhow::ensure!(
                !value.trim().is_empty(),
                "Kiro OAuth {name} must not be empty"
            );
        }
        if let Some(profile_arn) = &self.profile_arn {
            anyhow::ensure!(
                !profile_arn.trim().is_empty(),
                "Kiro OAuth profile_arn must not be empty when present"
            );
        }
        Ok(())
    }

    /// Whether the access token keeps more than ten minutes of headroom at
    /// `now` (Unix seconds) — the refresh margin every caller shares.
    pub fn fresh_for(&self, now: i64) -> bool {
        self.expires_at > now + 600
    }
}

/// Never prints the access token, refresh token, client secret — nor the
/// client id and profile ARN, which identify the account without being
/// secrets. Only the region coordinates and the expiry stay visible for
/// diagnostics.
impl std::fmt::Debug for KiroOAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KiroOAuth")
            .field("expires_at", &self.expires_at)
            .field("region", &self.region)
            .field("auth_region", &self.auth_region)
            .field("api_region", &self.api_region)
            .finish_non_exhaustive()
    }
}
