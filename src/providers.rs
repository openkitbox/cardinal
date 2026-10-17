//! Upstream authentication injection: the closed `AuthScheme` set plus the
//! per-attempt credential material handed to the transport layer.
//!
//! The material is only exposed at the injection point (as headers or a query
//! pair); the protocol codecs never see it.

use serde::Serialize;
/// How a provider authenticates upstream. Closed set: an unknown or missing
/// value is a configuration error rather than a silent default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    /// `authorization: Bearer <key>` — OpenAI-compatible suppliers.
    Bearer,
    /// `x-api-key: <key>` — Anthropic.
    XApiKey,
    /// `x-goog-api-key: <key>` — Gemini.
    XGoogApiKey,
    /// `?key=<key>` query parameter — Gemini alternative.
    Query,
}

impl AuthScheme {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "bearer" => Ok(Self::Bearer),
            "x_api_key" => Ok(Self::XApiKey),
            "x_goog_api_key" => Ok(Self::XGoogApiKey),
            "query" => Ok(Self::Query),
            other => anyhow::bail!("unsupported provider authentication scheme {other}"),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::XApiKey => "x_api_key",
            Self::XGoogApiKey => "x_goog_api_key",
            Self::Query => "query",
        }
    }

    pub const fn header(self) -> Option<&'static str> {
        match self {
            Self::Bearer => Some("authorization"),
            Self::XApiKey => Some("x-api-key"),
            Self::XGoogApiKey => Some("x-goog-api-key"),
            Self::Query => None,
        }
    }

    fn header_value(self, material: &str) -> String {
        match self {
            Self::Bearer => format!("Bearer {material}"),
            Self::XApiKey | Self::XGoogApiKey => material.to_owned(),
            Self::Query => material.to_owned(),
        }
    }
}

/// Where the injected credential goes. Keeps this module free of HTTP types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthTarget {
    Header(&'static str),
    Query(&'static str),
}

/// Credentials for one attempt: scheme + material. relay calls
/// [`Self::headers`] / [`Self::query`] and hands them to
/// `Transport::send_with_headers`; the material never lands in logs or errors.
#[derive(Clone, Copy)]
pub struct AuthSchemeMaterial<'a> {
    scheme: AuthScheme,
    material: &'a str,
}

impl<'a> AuthSchemeMaterial<'a> {
    pub fn new(scheme: AuthScheme, material: &'a str) -> Self {
        Self { scheme, material }
    }

    /// Where the credential goes (for test and debug assertions; does not include the material).
    pub fn target(&self) -> AuthTarget {
        match self.scheme.header() {
            Some(name) => AuthTarget::Header(name),
            None => AuthTarget::Query("key"),
        }
    }

    /// Credential injected into request headers (bearer / x-api-key / x-goog-api-key).
    /// Query-style schemes return empty — the credential goes through [`Self::query_pairs`].
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        match self.scheme.header() {
            Some(name) => vec![(name, self.scheme.header_value(self.material))],
            None => Vec::new(),
        }
    }

    /// Credential injected into the query string (`?key=<material>`).
    pub fn query_pairs(&self) -> Vec<(&'static str, String)> {
        match self.scheme.header() {
            Some(_) => Vec::new(),
            None => vec![("key", self.material.to_owned())],
        }
    }
}
