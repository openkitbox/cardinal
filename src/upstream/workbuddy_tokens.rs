//! Single-flight, lazily refreshed WorkBuddy OAuth bundles.
//!
//! The cache is intentionally keyed by provider-key id rather than by account
//! metadata. A cache hit only consults the per-key [`DashMap`]; database and
//! network work happen after the freshness check on the slow path.

use std::sync::Arc;

use chrono::Duration;
use chrono::Utc;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::relay::capabilities::workbuddy::{Build, normalize_credential_origin};
use crate::store;
use crate::workbuddy::WorkbuddyOAuth;
use crate::workbuddy::auth::Client;
use crate::workbuddy::auth::WorkbuddyError;

/// Refresh a bundle before its access token has five minutes of validity left.
pub const REFRESH_SKEW_SECS: i64 = 300;

/// Why a WorkBuddy bearer could not be resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkbuddyTokenError {
    /// The key row is absent, is not a WorkBuddy OAuth row, or does not decode.
    Missing,
    /// WorkBuddy refused the refresh grant. A new login is required.
    Expired,
    /// Storage, transport, or response-shape failure while refreshing.
    Refresh,
}

impl std::fmt::Display for WorkbuddyTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing | Self::Expired | Self::Refresh => "WorkBuddy authentication failed",
        })
    }
}

impl std::error::Error for WorkbuddyTokenError {}

/// Process-local WorkBuddy bearer cache.
pub struct WorkbuddyTokens {
    client: Arc<Client>,
    bundles: DashMap<i64, Arc<WorkbuddyOAuth>>,
    dead: DashMap<i64, ()>,
    gates: DashMap<i64, Arc<Mutex<()>>>,
}

impl WorkbuddyTokens {
    /// Construct a manager using the shared WorkBuddy authentication client.
    #[must_use]
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            bundles: DashMap::new(),
            dead: DashMap::new(),
            gates: DashMap::new(),
        }
    }

    /// Switch the refresh client to the provider's configured DNS while keeping
    /// the same transport and token cache.
    pub fn with_dns(&self, dns: crate::upstream::Dns) -> Self {
        Self {
            client: Arc::new(self.client.with_dns(dns)),
            bundles: DashMap::new(),
            dead: DashMap::new(),
            gates: DashMap::new(),
        }
    }

    pub async fn resolve_with_build(
        &self,
        pool: &PgPool,
        key_id: i64,
        dns: crate::upstream::Dns,
        build: Build,
    ) -> Result<Arc<WorkbuddyOAuth>, WorkbuddyTokenError> {
        if self.dead.contains_key(&key_id) {
            return Err(WorkbuddyTokenError::Expired);
        }
        if let Some(bundle) = self.bundles.get(&key_id)
            && fresh(bundle.value())
        {
            return Ok(Arc::clone(bundle.value()));
        }
        self.resolve_slow(pool, key_id, dns, build).await
    }

    /// Adopt a bundle written by login or credential replacement.
    pub fn adopt(&self, key_id: i64, bundle: WorkbuddyOAuth) -> Arc<WorkbuddyOAuth> {
        let bundle = Arc::new(bundle);
        self.dead.remove(&key_id);
        self.bundles.insert(key_id, Arc::clone(&bundle));
        bundle
    }

    pub async fn resolve_forced_with_build(
        &self,
        pool: &PgPool,
        key_id: i64,
        presented_access_token: &str,
        dns: crate::upstream::Dns,
        build: Build,
    ) -> Result<Arc<WorkbuddyOAuth>, WorkbuddyTokenError> {
        let Some(cached) = self
            .bundles
            .get(&key_id)
            .map(|bundle| Arc::clone(bundle.value()))
        else {
            return self.resolve_with_build(pool, key_id, dns, build).await;
        };
        if cached.access_token != presented_access_token {
            return Ok(cached);
        }
        self.bundles.remove(&key_id);
        self.resolve_slow(pool, key_id, dns, build).await
    }

    /// Forget the process-local state for one key.
    pub fn forget(&self, key_id: i64) {
        self.bundles.remove(&key_id);
        self.dead.remove(&key_id);
    }

    async fn resolve_slow(
        &self,
        pool: &PgPool,
        key_id: i64,
        dns: crate::upstream::Dns,
        build: Build,
    ) -> Result<Arc<WorkbuddyOAuth>, WorkbuddyTokenError> {
        let gate = if let Some(gate) = self.gates.get(&key_id) {
            Arc::clone(gate.value())
        } else {
            Arc::clone(
                self.gates
                    .entry(key_id)
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .value(),
            )
        };
        let _guard = gate.lock().await;
        if self.dead.contains_key(&key_id) {
            return Err(WorkbuddyTokenError::Expired);
        }

        let stored = match store::workbuddy_oauth(pool, key_id).await {
            Ok(Some(bundle)) => bundle,
            Ok(None) => {
                self.bundles.remove(&key_id);
                return Err(WorkbuddyTokenError::Missing);
            }
            Err(_) => return self.cached_if_unexpired(key_id),
        };
        if stored.validate().is_err() {
            self.bundles.remove(&key_id);
            return Err(WorkbuddyTokenError::Missing);
        }
        if fresh(&stored) {
            return Ok(self.adopt(key_id, stored));
        }

        let Some(refresh_base) = refresh_base(&stored, build) else {
            self.bundles.remove(&key_id);
            return Err(WorkbuddyTokenError::Refresh);
        };
        let refreshed = self
            .client
            .with_dns(dns)
            .refresh(&refresh_base, &stored)
            .await;
        let next = match refreshed {
            Ok(bundle) => bundle,
            Err(error) if refresh_was_rejected(&error) => {
                self.bundles.remove(&key_id);
                self.dead.insert(key_id, ());
                return Err(WorkbuddyTokenError::Expired);
            }
            Err(_) => {
                if unexpired(&stored) {
                    return Ok(self.adopt(key_id, stored));
                }
                return self.cached_if_unexpired(key_id);
            }
        };

        match store::replace_workbuddy_oauth(pool, key_id, &stored, &next).await {
            Ok(true) => Ok(self.adopt(key_id, next)),
            Ok(false) => match store::workbuddy_oauth(pool, key_id).await {
                Ok(Some(winner)) if winner.validate().is_ok() => Ok(self.adopt(key_id, winner)),
                Ok(Some(_)) => {
                    self.bundles.remove(&key_id);
                    Err(WorkbuddyTokenError::Missing)
                }
                Ok(None) => {
                    self.bundles.remove(&key_id);
                    Err(WorkbuddyTokenError::Missing)
                }
                Err(_) => self.cached_if_unexpired_matching(key_id, &stored.access_token),
            },
            Err(_) => self.cached_if_unexpired_matching(key_id, &stored.access_token),
        }
    }

    fn cached_if_unexpired(&self, key_id: i64) -> Result<Arc<WorkbuddyOAuth>, WorkbuddyTokenError> {
        self.bundles
            .get(&key_id)
            .filter(|bundle| unexpired(bundle.value()))
            .map(|bundle| Arc::clone(bundle.value()))
            .ok_or(WorkbuddyTokenError::Refresh)
    }

    fn cached_if_unexpired_matching(
        &self,
        key_id: i64,
        access_token: &str,
    ) -> Result<Arc<WorkbuddyOAuth>, WorkbuddyTokenError> {
        self.bundles
            .get(&key_id)
            .filter(|bundle| unexpired(bundle.value()) && bundle.access_token == access_token)
            .map(|bundle| Arc::clone(bundle.value()))
            .ok_or(WorkbuddyTokenError::Refresh)
    }
}

fn fresh(bundle: &WorkbuddyOAuth) -> bool {
    bundle.expires_at - Utc::now() > Duration::seconds(REFRESH_SKEW_SECS)
}

fn unexpired(bundle: &WorkbuddyOAuth) -> bool {
    bundle.expires_at > Utc::now()
}

fn refresh_was_rejected(error: &WorkbuddyError) -> bool {
    match error {
        WorkbuddyError::Envelope { code } => matches!(code, 401 | 403),
        WorkbuddyError::Protocol { operation } => operation
            .split("HTTP ")
            .filter_map(|suffix| suffix.split_whitespace().next())
            .filter_map(|status| status.parse::<u16>().ok())
            .any(|status| matches!(status, 401 | 403)),
        WorkbuddyError::Transport { .. } | WorkbuddyError::Shape { .. } => false,
    }
}

fn refresh_base(bundle: &WorkbuddyOAuth, build: Build) -> Option<String> {
    match bundle.domain.as_deref() {
        Some(domain) => normalize_credential_origin(build, domain),
        None => Some(build.endpoint().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn errors_have_fixed_safe_display() {
        for error in [
            WorkbuddyTokenError::Missing,
            WorkbuddyTokenError::Expired,
            WorkbuddyTokenError::Refresh,
        ] {
            let display = error.to_string();
            assert!(!display.contains("access-secret"));
            assert!(!display.contains("refresh-secret"));
            assert_eq!(display, "WorkBuddy authentication failed");
        }
    }

    #[test]
    fn fresh_requires_more_than_the_refresh_skew() {
        let bundle = WorkbuddyOAuth {
            access_token: "access-secret".to_owned(),
            refresh_token: "refresh-secret".to_owned(),
            expires_at: Utc::now() + TimeDelta::seconds(REFRESH_SKEW_SECS + 1),
            refresh_expires_at: None,
            uid: "uid".to_owned(),
            account_name: None,
            domain: None,
            token_type: None,
            enterprise_id: None,
        };
        assert!(fresh(&bundle));
    }

    #[test]
    fn non_authentication_envelopes_are_transient() {
        assert!(!refresh_was_rejected(&WorkbuddyError::Envelope {
            code: 11217
        }));
        assert!(!refresh_was_rejected(&WorkbuddyError::Envelope {
            code: 500
        }));
    }

    #[test]
    fn explicit_authentication_failures_are_rejected() {
        for error in [
            WorkbuddyError::Envelope { code: 401 },
            WorkbuddyError::Envelope { code: 403 },
            WorkbuddyError::Protocol {
                operation: "auth/token/refresh returned HTTP 401".to_owned(),
            },
            WorkbuddyError::Protocol {
                operation: "auth/token/refresh returned HTTP 403".to_owned(),
            },
        ] {
            assert!(refresh_was_rejected(&error), "{error:?}");
        }
    }

    #[test]
    fn non_authentication_http_failures_are_transient() {
        for error in [
            WorkbuddyError::Protocol {
                operation: "auth/token/refresh returned HTTP 400".to_owned(),
            },
            WorkbuddyError::Protocol {
                operation: "auth/token/refresh returned HTTP 500".to_owned(),
            },
            WorkbuddyError::Protocol {
                operation: "auth/token/refresh returned HTTP 404".to_owned(),
            },
        ] {
            assert!(!refresh_was_rejected(&error), "{error:?}");
        }
    }

    #[test]
    fn refresh_base_fails_closed_without_a_bound_domain() {
        let bundle = WorkbuddyOAuth {
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
            expires_at: Utc::now(),
            refresh_expires_at: None,
            uid: "uid".to_owned(),
            account_name: None,
            domain: None,
            token_type: None,
            enterprise_id: None,
        };
        assert_eq!(
            refresh_base(&bundle, Build::International),
            Some("https://www.workbuddy.ai".to_owned())
        );
    }
}
