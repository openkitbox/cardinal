//! The Kiro OIDC credential bundle: the exact JSON persisted in
//! `gateway_provider_keys.oauth` and accepted by the admin key API. Pure data
//! — validation and freshness decisions only, no I/O and no vendor knowledge.

/// The shared CodeWhisperer profile used by Social logins when the raw
/// `kiro.rs` credential does not carry an explicit `profileArn`.
pub const SOCIAL_PROFILE_ARN: &str =
    "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK";

/// Kiro's AWS SSO OIDC credential (device-code / Builder ID login).
///
/// Persisted as camelCase JSON with a Unix-seconds `expiresAt`. This is the
/// stored/admin shape, NOT the vendor's raw account export: that export
/// carries millisecond `expiresAt` and an account-level `profileArn`, and
/// `scripts/import-kiro-account.py` converts it to this document.
/// Debug output redacts every secret: this value travels through
/// error paths and logs, and a leaked token grants the account.

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Social,
    #[serde(alias = "IdC", alias = "builder-id", alias = "iam")]
    Idc,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
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
    pub profile_arn: Option<String>,
}

impl<'de> serde::Deserialize<'de> for KiroOAuth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Input {
            access_token: Option<String>,
            expires_at: Option<i64>,
            refresh_token: Option<String>,
            client_id: Option<String>,
            client_secret: Option<String>,
            region: Option<String>,
            auth_region: Option<String>,
            api_region: Option<String>,
            profile_arn: Option<String>,
        }

        let input = Input::deserialize(deserializer)?;
        let region = input.region.unwrap_or_else(default_region);
        let auth_region = input.auth_region.unwrap_or_else(|| region.clone());
        let api_region = input.api_region.unwrap_or_else(|| region.clone());
        Ok(Self {
            access_token: input.access_token.unwrap_or_default(),
            expires_at: input.expires_at.unwrap_or_default(),
            refresh_token: input.refresh_token.unwrap_or_default(),
            client_id: input.client_id.unwrap_or_default(),
            client_secret: input.client_secret.unwrap_or_default(),
            region,
            auth_region,
            api_region,
            profile_arn: input.profile_arn,
        })
    }
}

fn default_region() -> String {
    "us-east-1".to_owned()
}

impl KiroOAuth {
    /// Resolve the authentication method without duplicating inference at each
    /// refresh or probe call site.
    pub fn effective_auth_method(&self) -> AuthMethod {
        if !self.client_id.trim().is_empty() && !self.client_secret.trim().is_empty() {
            AuthMethod::Idc
        } else {
            AuthMethod::Social
        }
    }

    /// The profile ARN sent on the KAS wire. Social credentials use the
    /// shared profile when the export omitted an explicit ARN; IdC keeps the
    /// optional value unchanged.
    pub fn effective_profile_arn(&self) -> Option<&str> {
        self.profile_arn.as_deref().or_else(|| {
            (self.effective_auth_method() == AuthMethod::Social).then_some(SOCIAL_PROFILE_ARN)
        })
    }

    /// Every required field must hold a real value; whitespace-only counts as
    /// empty (an unusable secret must never be stored).
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.refresh_token.trim().is_empty(),
            "Kiro OAuth refresh_token must not be empty"
        );
        for (name, value) in [
            ("region", &self.region),
            ("auth_region", &self.auth_region),
            ("api_region", &self.api_region),
        ] {
            anyhow::ensure!(
                !value.trim().is_empty(),
                "Kiro OAuth {name} must not be empty"
            );
            anyhow::ensure!(
                valid_region(value),
                "Kiro OAuth {name} is not an AWS region"
            );
        }
        if self.effective_auth_method() == AuthMethod::Idc {
            for (name, value) in [
                ("access_token", &self.access_token),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ] {
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "Kiro OAuth {name} must not be empty for IdC authentication"
                );
            }
            anyhow::ensure!(
                self.expires_at > 0,
                "Kiro OAuth expires_at must be positive for IdC authentication"
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
        !self.access_token.trim().is_empty() && self.expires_at > now + 600
    }
}

/// AWS region names are safe hostname labels and have the standard
/// partition/service/number shape (for example `us-east-1` or
/// `us-gov-west-1`).
pub fn valid_region(region: &str) -> bool {
    if region.is_empty() || region.len() > 32 {
        return false;
    }
    let parts: Vec<&str> = region.split('-').collect();
    parts.len() >= 3
        && (2..=4).contains(&parts[0].len())
        && parts[0].bytes().all(|byte| byte.is_ascii_lowercase())
        && parts[1..parts.len() - 1]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase()))
        && parts
            .last()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether an endpoint is exactly the KAS origin for `api_region`:
/// `https://runtime.{api_region}.kiro.dev` on port 443, with no userinfo, query,
/// fragment, or non-root path.
pub fn kas_endpoint_matches(endpoint: &str, api_region: &str) -> bool {
    if !valid_region(api_region) {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case(&format!("runtime.{api_region}.kiro.dev"))
        })
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

/// Parse one `kiro.rs` credential object, one selected element of its account
/// array, or one selected account of the IDE export
/// (`{accounts: [{profileArn, credentials: {...}}]}`), into Cardinal's smaller
/// runtime bundle. Unknown export metadata is intentionally ignored at this
/// boundary; numeric `expiresAt` accepts both Unix seconds and milliseconds.
pub fn parse_import_credentials(
    credentials: &serde_json::Value,
    account: usize,
) -> anyhow::Result<KiroOAuth> {
    let (object, account_profile_arn) = match credentials {
        serde_json::Value::Object(root) => {
            if let Some(accounts) = root.get("accounts") {
                let selected = accounts
                    .as_array()
                    .and_then(|accounts| accounts.get(account))
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| anyhow::anyhow!("credential account {account} was not found"))?;
                let object = selected
                    .get("credentials")
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| {
                        anyhow::anyhow!("credential account {account} has no credentials object")
                    })?;
                (object, selected.get("profileArn"))
            } else {
                (root, None)
            }
        }
        serde_json::Value::Array(accounts) => {
            let account = accounts
                .get(account)
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("credential account {account} was not found"))?;
            match account
                .get("credentials")
                .and_then(serde_json::Value::as_object)
            {
                Some(object) => (object, account.get("profileArn")),
                None => (account, None),
            }
        }
        _ => anyhow::bail!("credentials must be a JSON object or array of objects"),
    };

    let string_field = |name: &str| -> anyhow::Result<Option<String>> {
        match object.get(name) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => value
                .as_str()
                .map(str::to_owned)
                .map(Some)
                .ok_or_else(|| anyhow::anyhow!("credential field {name} must be a string")),
        }
    };
    let auth_method: Option<AuthMethod> = match object.get("authMethod") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("authMethod is not supported"))?,
        ),
    };
    let client_id = string_field("clientId")?.unwrap_or_default();
    let client_secret = string_field("clientSecret")?.unwrap_or_default();
    let has_client_id = !client_id.trim().is_empty();
    let has_client_secret = !client_secret.trim().is_empty();
    anyhow::ensure!(
        has_client_id == has_client_secret,
        "clientId and clientSecret must be provided together"
    );
    let inferred_auth_method = if has_client_id && has_client_secret {
        AuthMethod::Idc
    } else {
        AuthMethod::Social
    };
    if let Some(auth_method) = auth_method {
        anyhow::ensure!(
            auth_method == inferred_auth_method,
            "authMethod does not match the supplied credential fields"
        );
    }
    let expires_at = match object.get("expiresAt") {
        None | Some(serde_json::Value::Null) => 0,
        Some(serde_json::Value::Number(number)) => {
            let value = number
                .as_i64()
                .map(i128::from)
                .or_else(|| number.as_u64().map(i128::from))
                .ok_or_else(|| anyhow::anyhow!("expiresAt must be an integer timestamp"))?;
            anyhow::ensure!(value >= 0, "expiresAt must not be negative");
            let seconds = if value >= 100_000_000_000 {
                value / 1_000
            } else {
                value
            };
            i64::try_from(seconds).map_err(|_| anyhow::anyhow!("expiresAt is out of range"))?
        }
        Some(serde_json::Value::String(value)) => {
            let timestamp = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| anyhow::anyhow!("expiresAt must be RFC3339 or Unix timestamp"))?
                .timestamp();
            anyhow::ensure!(timestamp > 0, "expiresAt must be positive");
            timestamp
        }
        Some(_) => anyhow::bail!("expiresAt must be RFC3339 or Unix timestamp"),
    };
    let region = string_field("region")?.unwrap_or_else(default_region);
    let auth_region = string_field("authRegion")?.unwrap_or_else(|| region.clone());
    let api_region = string_field("apiRegion")?.unwrap_or_else(|| region.clone());
    let profile_arn = string_field("profileArn")?
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            account_profile_arn
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .filter(|value| !value.trim().is_empty())
        });
    let oauth = KiroOAuth {
        access_token: string_field("accessToken")?.unwrap_or_default(),
        expires_at,
        refresh_token: string_field("refreshToken")?.unwrap_or_default(),
        client_id,
        client_secret,
        region,
        auth_region,
        api_region,
        profile_arn,
    };
    oauth.validate()?;
    Ok(oauth)
}
