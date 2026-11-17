//! Account-level egress proxy: pure parsing, redaction and pool identity.
//!
//! This module owns the *proxy URL itself*: syntax, credential shape and a
//! redacted identity for client-pool partitioning. It performs no I/O and it is
//! not the SSRF authority — [`super::transport::validate_destination`] remains
//! the sole validator of the *target* URL/ports/address policy. A proxy IP
//! literal is checked against the global-unicast allowlist here at parse time;
//! a proxy hostname's resolved addresses are checked against that same
//! allowlist when the transport constructs its client
//! ([`super::transport::Transport::client_for_mode`]). The resolver only
//! performs DNS and never filters addresses. Nothing here relaxes policy.

use crate::upstream::dns::HickoryResolver;
use sha2::{Digest as _, Sha256};
use std::{fmt, net::IpAddr, sync::Arc, time::Duration};

/// Fixed, input-free errors for proxy parsing. Neither `Display` nor `Debug`
/// echoes the URL, the host or any credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// The URL could not be parsed.
    InvalidUrl,
    /// Only `https` and `socks5` proxies are supported.
    UnsupportedScheme,
    /// The URL has no host.
    MissingHost,
    /// The port is missing or out of range.
    InvalidPort,
    /// A query or fragment is not allowed on a proxy endpoint.
    QueryOrFragment,
    /// Credentials are present but incomplete (or malformed).
    InvalidCredentials,
    /// The endpoint is a local or non-global address.
    DisallowedAddress,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidUrl => "proxy URL is invalid",
            Self::UnsupportedScheme => "proxy scheme is not supported",
            Self::MissingHost => "proxy URL has no host",
            Self::InvalidPort => "proxy URL port is invalid",
            Self::QueryOrFragment => "proxy URL must not contain a query or fragment",
            Self::InvalidCredentials => "proxy credentials are incomplete",
            Self::DisallowedAddress => "proxy address is not allowed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProxyError {}

/// A validated account-level proxy endpoint.
///
/// The full URL (including credentials) is kept privately so it can be handed
/// to reqwest for sending. `Debug`/`Display` are deliberately opaque: no part
/// of the endpoint or its credentials may reach a log or an error string.
#[derive(Clone)]
pub struct ProxySpec {
    url: reqwest::Url,
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    /// SHA-256 of the canonical URL; irreversible, safe for cache keys and logs.
    identity: String,
}

impl ProxySpec {
    /// Parse and validate a proxy URL. Accepts `https://host:port` and
    /// `socks5://host:port`, each with optional URL credentials. The port may be
    /// explicit or omitted (the scheme's default is then used); plaintext
    /// `http`, `socks5h`, query/fragment, empty or one-sided credentials and
    /// local/private literal addresses are refused.
    pub fn parse(input: &str) -> Result<Self, ProxyError> {
        let url = reqwest::Url::parse(input).map_err(|_| ProxyError::InvalidUrl)?;
        match url.scheme() {
            "https" | "socks5" => {}
            _ => return Err(ProxyError::UnsupportedScheme),
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ProxyError::QueryOrFragment);
        }
        let host = url.host_str().ok_or(ProxyError::MissingHost)?.to_owned();
        if host.is_empty() {
            return Err(ProxyError::MissingHost);
        }
        // `port_or_known_default()` keeps an explicitly written scheme-default
        // port (e.g. `https://host:443`) instead of normalising it away the way
        // `port()` does, and supplies the scheme default when the port is
        // omitted. Both are safe here: the proxy port does not take part in the
        // upstream target SSRF check (`validate_destination` still owns that).
        // `Url::parse` still rejects out-of-range values and port 0 is unusable.
        let port = url
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or(ProxyError::InvalidPort)?;

        let username = url.username();
        let password = url.password();
        let (username, password) = match (username.is_empty(), password) {
            (true, None) => (String::new(), None),
            (true, Some(_)) => return Err(ProxyError::InvalidCredentials),
            (false, Some(password)) if !password.is_empty() => {
                (username.to_owned(), Some(password.to_owned()))
            }
            (false, _) => return Err(ProxyError::InvalidCredentials),
        };

        // `url::host_str()` returns IPv6 literals with brackets (`[::1]`), which
        // `IpAddr::parse` rejects. Normalise once here so the stored host is the
        // same literal form used by the allowlist check below and by the
        // resolver-facing `host()` accessor; the full URL (and therefore
        // `to_reqwest_proxy`) is untouched.
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host.as_str())
            .to_owned();
        // IP-literal endpoints share the upstream address policy. Hostnames are
        // resolved by the transport's secure resolver, whose answers are checked
        // against the same allowlist when the client is constructed; the target
        // itself is still validated by `validate_destination`.
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !super::transport::is_global_unicast(ip) {
                return Err(ProxyError::DisallowedAddress);
            }
        } else if is_local_hostname(&host) {
            return Err(ProxyError::DisallowedAddress);
        }

        let mut hasher = Sha256::new();
        hasher.update(url.as_str().as_bytes());
        let digest = hasher.finalize();
        let identity = hex::encode(digest);

        Ok(Self {
            url,
            host,
            port,
            username,
            password,
            identity,
        })
    }

    /// Irreversible, stable identity for client-pool partitioning.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Parse the proxy configured on an account row. Every write path validates
    /// the URL before it is stored, so a failure here is defensive: degrade to
    /// the direct path with a redacted warning that never echoes the URL.
    pub fn from_stored(url: Option<&str>, key_id: i64) -> Option<Self> {
        let url = url?;
        match Self::parse(url) {
            Ok(spec) => Some(spec),
            Err(_) => {
                tracing::warn!(
                    key_id,
                    "stored proxy configuration is invalid; sending directly"
                );
                None
            }
        }
    }

    /// Proxy scheme: `https` or `socks5`.
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// Proxy endpoint host, normalised to an unbracketed IP literal when the
    /// endpoint is IPv6 (safe for the resolver and for diagnostics).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Proxy endpoint port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Proxy username, or an empty string for an unauthenticated proxy.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Proxy password, if credentials are configured.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Build the reqwest `Proxy` that carries credentials to the connector.
    pub fn to_reqwest_proxy(&self) -> Result<reqwest::Proxy, ProxyError> {
        reqwest::Proxy::all(self.url.as_str()).map_err(|_| ProxyError::InvalidUrl)
    }
}

impl fmt::Debug for ProxySpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxySpec(<redacted>)")
    }
}

impl fmt::Display for ProxySpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proxy(<redacted>)")
    }
}

fn is_local_hostname(host: &str) -> bool {
    matches!(host, "localhost" | "metadata.google.internal")
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
}

/// The single place that turns a resolver, a connect timeout and an optional
/// proxy into a reqwest client builder. With no proxy this applies exactly the
/// same `.no_proxy()` policy as the existing transport (environment proxies
/// stay ignored); with a proxy the endpoint is configured on the builder.
///
/// Callers own the rest of the builder (redirect policy, pool sizing, HTTP
/// version, request timeout) so authentication clients and the relay share the
/// "how to apply a proxy" knowledge without sharing a connection pool.
pub(crate) fn configure_client_builder(
    builder: reqwest::ClientBuilder,
    resolver: Arc<HickoryResolver>,
    connect_timeout: Duration,
    proxy: Option<&ProxySpec>,
) -> Result<reqwest::ClientBuilder, ProxyError> {
    let builder = builder
        .dns_resolver(resolver)
        .connect_timeout(connect_timeout);
    match proxy {
        None => Ok(builder.no_proxy()),
        Some(spec) => Ok(builder.proxy(spec.to_reqwest_proxy()?)),
    }
}
