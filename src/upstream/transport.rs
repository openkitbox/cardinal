//! Outbound HTTP transport (A §5 `transport`, §7.4; B §3.3, §4.7).
//!
//! One long-lived client per process with bounded resources:
//! - environment proxies are ignored, so `*_PROXY` cannot reroute upstream
//!   traffic past the destination policy (B §3.3 item 5);
//! - connect/opening/idle/total deadlines come from the caller's shared budget;
//! - JSON bodies and SSE frames are read incrementally and refused past their
//!   limit instead of being buffered without bound;
//! - transport performs exactly one send; retry policy belongs to the relay.

use super::dns::Resolvers;
use crate::protocol::Prepared;
use crate::protocol::sse::{Framer, RawFrame, SseError};
use reqwest::header::{CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Shared deadline and size budget (A §7.4 is the single owner of the time
/// values; B §4.7 owns the wire limits).
#[derive(Clone, Debug)]
pub struct Limits {
    pub connect: Duration,
    pub opening: Duration,
    pub idle: Duration,
    pub total: Duration,
    pub max_json_bytes: usize,
    /// Inbound request-body read deadline: how long the gateway waits for the
    /// client to finish sending the body before it gives up with 408. Distinct
    /// from `max_json_bytes` (a size cap) — this is a TIME cap on the read, so a
    /// slow or stalled client (e.g. a request trickling through a CDN/tunnel)
    /// cannot hold the connection open indefinitely while the relay sits
    /// "connecting" without ever dispatching.
    pub body_read: Duration,
    /// Test-only affordance: permits plaintext loopback URLs. Production policy
    /// requires HTTPS to a validated global destination (B §3.3).
    pub allow_plaintext_loopback: bool,
    /// Ports other than 443 that an audited destination policy explicitly allows.
    pub allowed_ports: Vec<u16>,
    /// Development-only escape for environments whose resolver maps every domain
    /// into a private range (fake-IP proxies). Production must keep this false:
    /// it disables the address-class allowlist (B §3.3).
    pub allow_private_destinations: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            // Response-header deadline (3 minutes): waiting for the first byte is
            // the one phase no other bound covers (`connect` ends at the socket,
            // `idle` starts at the first frame). A big prompt on a slow upstream
            // (kimi's coding-plan endpoint takes >30s to first byte on a cache
            // miss; measured p99 total 103s, and the slowest legitimate antb
            // request on prod was 124s) is slow to start anywhere, so the relay
            // fails over instead of calling it dead — but 600s only matched the
            // client's own give-up, so a silent upstream hung the caller for ten
            // minutes with nothing recorded. 180s keeps ~1.5× headroom over the
            // slowest observed legitimate start.
            opening: Duration::from_secs(60),
            idle: Duration::from_secs(60),
            // Whole-dispatch cap: must clear opening plus a long stream; a stalled
            // stream is cut by idle long before this ever fires.
            total: Duration::from_secs(3600),
            max_json_bytes: 32 * 1024 * 1024,
            // Inbound body read deadline (2 minutes): a normal chat body lands in
            // well under a second; 120s absorbs a slow client/CDN hop without ever
            // being the path that stalls an ordinary request.
            body_read: Duration::from_secs(120),
            allow_plaintext_loopback: false,
            allowed_ports: Vec::new(),
            allow_private_destinations: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    Connect,
    Timeout,
    /// Upstream returned a non-success status; `body` is a bounded capture
    /// (≤ [`MAX_ERROR_BODY`] bytes) of the vendor's error body, so the relay can
    /// classify the failure and the attempt log shows the vendor's own words.
    /// The two raw header captures feed the cooldown's recovery-time ladder
    /// (parsing lives in [`Self`], policy in `failover`).
    Status {
        status: u16,
        /// Raw `Retry-After` header value (integer or float seconds).
        retry_after: Option<String>,
        /// Raw value of a vendor reset header (any `*reset*ratelimit*` name).
        reset_header: Option<String>,
        body: bytes::Bytes,
    },
    BodyTooLarge,
    InvalidBody,
    /// The client disconnected while the relay was reading from upstream.
    ClientGone,
}

/// `Retry-After` header value → relative duration. Integer or float seconds
/// (the HTTP-date form is not parsed — no vendor in evidence sends it).
pub fn parse_retry_after(raw: &str) -> Option<chrono::Duration> {
    let secs = raw.trim().parse::<f64>().ok()?;
    (secs > 0.).then(|| chrono::Duration::milliseconds((secs * 1000.) as i64))
}

/// A vendor reset header (`*reset*ratelimit*`) → absolute reset time. RFC 3339
/// timestamp, epoch seconds (>1e9) or milliseconds (>1e12), or a single-unit
/// duration (`26s`, `5m`, `1h`) anchored at `now`.
pub fn parse_reset_header(
    raw: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let raw = raw.trim();
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Some(t.with_timezone(&chrono::Utc));
    }
    if let Ok(n) = raw.parse::<i64>() {
        let t = if n > 1_000_000_000_000 {
            chrono::DateTime::from_timestamp_millis(n)
        } else {
            chrono::DateTime::from_timestamp(n, 0)
        };
        return t.map(|t| t.with_timezone(&chrono::Utc));
    }
    // Single-unit duration: "<float><s|m|h>".
    let (digits, unit) = raw.split_at(raw.len().saturating_sub(1));
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return None,
    };
    let secs = digits.parse::<f64>().ok()?;
    (secs > 0.)
        .then(|| now + chrono::Duration::milliseconds((secs * 1000. * multiplier as f64) as i64))
}

impl TransportError {
    /// The upstream's `Retry-After` ask, parsed from the raw capture.
    pub fn retry_after(&self) -> Option<chrono::Duration> {
        match self {
            Self::Status {
                retry_after: Some(raw),
                ..
            } => parse_retry_after(raw),
            _ => None,
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status { status, body, .. } => {
                let snippet = body_snippet(body);
                if snippet.is_empty() {
                    write!(formatter, "upstream HTTP {status}")
                } else {
                    write!(formatter, "upstream HTTP {status}: {snippet}")
                }
            }
            Self::Connect => formatter.write_str("upstream connection failed"),
            Self::Timeout => formatter.write_str("upstream timed out"),
            Self::BodyTooLarge => formatter.write_str("upstream body exceeded the limit"),
            Self::InvalidBody => formatter.write_str("upstream body could not be read"),
            Self::ClientGone => formatter.write_str("client disconnected"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Per-destination clients keyed by validated address and proxy. A proxy is
/// part of the pool identity so connections are never reused across egresses.
type ClientKey = (String, String, u16, Vec<IpAddr>);
/// Process-wide outbound transport.
#[derive(Clone)]
pub struct Transport {
    clients: Arc<Mutex<HashMap<ClientKey, reqwest::Client>>>,
    resolvers: Resolvers,
    limits: Limits,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Transport")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Destination decision for one URL (B §3.3 items 2, 4, 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub address: IpAddr,
    /// Every validated address for the host. All are pinned so the client can
    /// still use Happy Eyeballs across address families (B §3.3 item 5).
    pub addresses: Vec<IpAddr>,
}

/// Save-time endpoint check for administrator input.
///
/// DNS is intentionally not resolved here (the send path validates the
/// resolved address again, including rebinding); literal private/loopback
/// addresses and well-known local hostnames are refused up front so an
/// obviously internal endpoint cannot be persisted.
pub fn validate_saved_endpoint(url: &str, allow_private: bool) -> anyhow::Result<()> {
    let parsed =
        reqwest::Url::parse(url).map_err(|_| anyhow::anyhow!("endpoint is not a valid URL"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("endpoint must not contain a username or password");
    }
    if parsed.fragment().is_some() {
        anyhow::bail!("endpoint must not contain a fragment");
    }
    for (key, _) in parsed.query_pairs() {
        let key = key.to_ascii_lowercase();
        if [
            "api_key",
            "apikey",
            "access_token",
            "token",
            "secret",
            "password",
            "key",
        ]
        .iter()
        .any(|sensitive| key == *sensitive)
        {
            anyhow::bail!("endpoint query must not contain credential parameters");
        }
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("endpoint must use http(s)");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("endpoint is missing a hostname"))?;
    if !allow_private {
        let local = matches!(host, "localhost")
            || host.ends_with(".localhost")
            || host.ends_with(".local")
            || host.ends_with(".internal")
            || host == "metadata.google.internal";
        if local {
            anyhow::bail!("endpoint must not point to a local or internal host");
        }
        if let Ok(ip) = host.parse::<IpAddr>()
            && !is_global_unicast(ip)
        {
            anyhow::bail!("endpoint must not point to an internal or reserved address");
        }
    }
    Ok(())
}
/// Reject anything that is not a global-unicast address, and any port other
/// than 443. This is an allowlist: unknown or unusual ranges are refused.
pub(crate) async fn validate_destination(
    url: &str,
    resolvers: &Resolvers,
    allow_plaintext_loopback: bool,
    allow_ports: &[u16],
    allow_private_destinations: bool,
) -> Result<Destination, TransportError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| TransportError::Connect)?;
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(TransportError::Connect);
    }
    let scheme = parsed.scheme();
    let host = parsed.host_str().ok_or(TransportError::Connect)?.to_owned();
    let loopback_host = matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1");
    if scheme != "https" && !(allow_plaintext_loopback && scheme == "http" && loopback_host) {
        return Err(TransportError::Connect);
    }
    let port = parsed
        .port_or_known_default()
        .ok_or(TransportError::Connect)?;
    let loopback_plaintext = allow_plaintext_loopback && scheme == "http" && loopback_host;
    if !loopback_plaintext && port != 443 && !allow_ports.contains(&port) {
        return Err(TransportError::Connect);
    }
    if parsed
        .path()
        .contains(|character: char| character.is_control())
    {
        return Err(TransportError::Connect);
    }
    // The provider's host picks the DNS preset (hard-coded pairing in dns.rs);
    // the SSRF address checks below run identically for every preset.
    let resolved = resolvers
        .for_host(&host)
        .resolve_all(&host)
        .await
        .map_err(|_| TransportError::Connect)?;
    if resolved.is_empty() {
        return Err(TransportError::Connect);
    }
    // Every resolved address must be acceptable: one private answer refuses the
    // whole host, so a split-horizon/rebinding record cannot smuggle a private
    // target past the check.
    for ip in &resolved {
        let loopback = ip.is_loopback();
        if allow_plaintext_loopback && loopback && scheme == "http" {
            continue;
        }
        if !allow_private_destinations && !is_global_unicast(*ip) {
            return Err(TransportError::Connect);
        }
    }
    let address = resolved.first().copied().ok_or(TransportError::Connect)?;
    Ok(Destination {
        host,
        port,
        address,
        addresses: resolved,
    })
}

/// Global-unicast allowlist. Explicitly excludes the ranges that matter for
/// SSRF, including RFC6598 (cloud metadata) and every IPv6 form that embeds an
/// IPv4 address (B §3.3 item 4).
pub(crate) fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_private()
        || octets[0] == 0
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        // RFC6598 carrier-grade NAT, includes 100.100.100.200 metadata
        || octets[0] == 100 && (64..128).contains(&octets[1])
        // 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 0
        || octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        || octets[0] == 192 && octets[1] == 88 && octets[2] == 99
        || octets[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global_unicast(IpAddr::V4(mapped));
            }
            // IPv4-compatible ::x/96 is deprecated and must not be used as a target.
            if v6.segments()[..6].iter().all(|segment| *segment == 0) {
                return false;
            }
            let segments = v6.segments();
            !(v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        // unique local fc00::/7
        || segments[0] & 0xfe00 == 0xfc00
        // link-local fe80::/10
        || segments[0] & 0xffc0 == 0xfe80
        // NAT64 64:ff9b::/96 and 64:ff9b:1::/48
        || (segments[0] == 0x64 && segments[1] == 0xff9b)
        // 6to4 2002::/16, Teredo 2001::/32
        || segments[0] == 0x2002
        // 2001:db8::/32 documentation
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x2001 && segments[1] == 0))
        }
    }
}

impl Transport {
    pub fn new(limits: Limits) -> anyhow::Result<Self> {
        // Validate the client configuration at startup so a misconfigured
        // transport fails fast instead of on the first request. Per-destination
        // clients are built lazily in `client_for`.
        let resolvers = Resolvers::new()?;
        reqwest::Client::builder()
            .dns_resolver(Arc::clone(resolvers.default_resolver()))
            // Destination safety must not be delegated to an un-audited proxy.
            .no_proxy()
            // A redirect to another authority would carry the injected credential
            // headers (reqwest only strips authorization/cookie) and would bypass
            // the destination policy entirely (B §3.3 item 5).
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(64)
            .tcp_keepalive(Duration::from_secs(60))
            .connect_timeout(limits.connect)
            .build()?;
        Ok(Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            resolvers,
            limits,
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits.clone()
    }

    /// Send one prepared request. `deadline` is the request's absolute budget.
    pub async fn send(
        &self,
        prepared: &Prepared,
        deadline: Instant,
    ) -> Result<reqwest::Response, TransportError> {
        self.send_with_headers(prepared, &[], &[], deadline).await
    }

    /// Send with authentication headers produced by the credential module. The
    /// caller never receives the secret back from this function.
    pub async fn send_with_headers(
        &self,
        prepared: &Prepared,
        headers: &[(&'static str, String)],
        query: &[(&'static str, String)],
        deadline: Instant,
    ) -> Result<reqwest::Response, TransportError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Timeout);
        }
        // Re-resolve on every send: a host whose DNS answer changed (B §3.3 item 5)
        // gets a fresh destination validation instead of reusing a stale pin.
        let destination = validate_destination(
            &prepared.url,
            &self.resolvers,
            self.limits.allow_plaintext_loopback,
            &self.limits.allowed_ports,
            self.limits.allow_private_destinations,
        )
        .await?;
        let client = self.client_for(&prepared.url, &destination)?;
        let mut request = client
            .post(&prepared.url)
            .header(CONTENT_TYPE, prepared.content_type)
            .header(
                "accept",
                if prepared.stream {
                    "text/event-stream"
                } else {
                    "application/json"
                },
            )
            .body(prepared.body.clone());
        for (name, value) in &prepared.headers {
            request = request.header(*name, value.clone());
        }
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        if !query.is_empty() {
            request = request.query(
                &query
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.clone()))
                    .collect::<Vec<_>>(),
            );
        }
        // The opening deadline (`opening`, capped by the dispatch budget) is the
        // only bound on the wait for response headers: `connect_timeout` ends at
        // the socket and `idle` starts at the first frame, so without it a silent
        // upstream holds the dispatch — and the client — indefinitely.
        let wait = self.limits.opening.min(remaining);
        let sent = tokio::time::timeout(wait, request.send()).await;
        match sent {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) if error.is_timeout() => {
                tracing::warn!(host = %destination.host, "upstream send timed out");
                Err(TransportError::Timeout)
            }
            // Query-carried credentials (e.g. `?key=`) live in the request URL that
            // reqwest's Display renders; the raw error must never reach the log.
            Ok(Err(error)) if error.is_connect() => {
                tracing::warn!(host = %destination.host, category = "connect", "upstream connection failed");
                Err(TransportError::Connect)
            }
            Ok(Err(error)) => {
                let category = if error.is_timeout() {
                    "timeout"
                } else if error.is_body() || error.is_decode() {
                    "body"
                } else {
                    "request"
                };
                tracing::warn!(host = %destination.host, category, "upstream send failed");
                Err(TransportError::InvalidBody)
            }
            // The opening deadline elapsed: the connection is up but the upstream
            // never started answering. Report it as a timeout (transferable, so the
            // relay fails over) and keep `waited_ms` to tell it apart from a
            // reqwest-level one.
            Err(_elapsed) => {
                tracing::warn!(
                    host = %destination.host,
                    waited_ms = wait.as_millis() as u64,
                    "upstream sent no response headers within the opening deadline"
                );
                Err(TransportError::Timeout)
            }
        }
    }

    /// Client pinned to the validated address for one destination. The pool key
    /// is `(scheme, host, port, validated address)`, so a re-resolved host gets a
    /// different client instead of reusing an already-authorized connection.
    fn client_for(
        &self,
        url: &str,
        destination: &Destination,
    ) -> Result<reqwest::Client, TransportError> {
        let parsed = reqwest::Url::parse(url).map_err(|_| TransportError::Connect)?;
        let key: ClientKey = (
            parsed.scheme().to_owned(),
            destination.host.clone(),
            destination.port,
            destination.addresses.clone(),
        );
        if let Some(client) = self
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&key)
        {
            return Ok(client.clone());
        }
        let mut builder = reqwest::Client::builder()
            // Hygiene: the client resolves through the same preset that validated
            // the destination (inert in practice — `resolve_to_addrs` below pins
            // every address and redirects are disabled).
            .dns_resolver(Arc::clone(self.resolvers.for_host(&destination.host)))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(64)
            .tcp_keepalive(Duration::from_secs(60))
            .connect_timeout(self.limits.connect)
            .resolve_to_addrs(
                &destination.host,
                &destination
                    .addresses
                    .iter()
                    .map(|address| SocketAddr::new(*address, destination.port))
                    .collect::<Vec<_>>(),
            );
        builder = builder.no_proxy();
        let client = builder.build().map_err(|_| TransportError::Connect)?;
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if clients.len() >= 64 {
            clients.clear();
        }
        clients.insert(key, client.clone());
        Ok(client)
    }

    /// Read a complete JSON body with a hard size ceiling.
    /// Read the complete body as raw bytes so the caller parses it once and
    /// forwards the same bytes to the client (no re-encoding).
    pub async fn read_body(
        &self,
        mut response: reqwest::Response,
        limit: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError> {
        let mut body = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout);
            }
            let chunk = match tokio::time::timeout(remaining, response.chunk()).await {
                Err(_) => return Err(TransportError::Timeout),
                Ok(Err(error)) if error.is_timeout() => return Err(TransportError::Timeout),
                Ok(Err(_)) => return Err(TransportError::InvalidBody),
                Ok(Ok(chunk)) => chunk,
            };
            let Some(chunk) = chunk else { break };
            if body.len() + chunk.len() > limit {
                return Err(TransportError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Wrap a streaming response in a bounded, deadline-aware frame reader.
    pub fn stream(&self, response: reqwest::Response, deadline: Instant) -> StreamReader {
        StreamReader {
            response,
            framer: Framer::new(),
            idle: self.limits.idle,
            deadline,
            pending: VecDeque::new(),
            finished: false,
        }
    }
}

/// Hard cap on an error body's captured bytes (classification + log snippet
/// never need more than this).
pub const MAX_ERROR_BODY: usize = 8192;

/// Classify a non-success status, capturing the cooldown's reset-evidence
/// headers (raw; parsing lives on [`TransportError`]) and the (already
/// bounded) error body the caller captured.
pub fn status_error(
    status: u16,
    headers: &HeaderMap,
    body: bytes::Bytes,
) -> Option<TransportError> {
    if status < 400 {
        return None;
    }
    let value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let reset_header = headers
        .iter()
        .find(|(name, _)| name.as_str().contains("reset") && name.as_str().contains("ratelimit"))
        .and_then(|(_, value)| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Some(TransportError::Status {
        status,
        retry_after: value(RETRY_AFTER.as_str()),
        reset_header,
        body,
    })
}

/// A ≤200-char lossy, trimmed snippet of an error body, for logs and the
/// requests page. Char-safe: `from_utf8_lossy` output is never byte-sliced.
fn body_snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    text.trim().chars().take(200).collect()
}

/// Incremental SSE reader with an idle ceiling and the request deadline.
pub struct StreamReader {
    response: reqwest::Response,
    framer: Framer,
    idle: Duration,
    deadline: Instant,
    pending: VecDeque<RawFrame>,
    finished: bool,
}

impl StreamReader {
    /// Next complete frame without copying the data payload into a String.
    pub async fn next_raw_frame(&mut self) -> Result<Option<RawFrame>, TransportError> {
        if let Some(frame) = self.pending.pop_front() {
            return Ok(Some(frame));
        }
        if self.finished {
            return Ok(None);
        }
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout);
            }
            let wait = self.idle.min(remaining);
            match tokio::time::timeout(wait, self.response.chunk()).await {
                Err(_) => return Err(TransportError::Timeout),
                Ok(Err(error)) if error.is_timeout() => return Err(TransportError::Timeout),
                Ok(Err(_)) => return Err(TransportError::InvalidBody),
                Ok(Ok(None)) => {
                    self.finished = true;
                    let frames = self.framer.finish_raw().map_err(map_sse)?;
                    self.pending.extend(frames);
                    return Ok(self.pending.pop_front());
                }
                Ok(Ok(Some(chunk))) => {
                    let frames = self.framer.push_raw(&chunk).map_err(map_sse)?;
                    self.pending.extend(frames);
                    if let Some(frame) = self.pending.pop_front() {
                        return Ok(Some(frame));
                    }
                }
            }
        }
    }
}

fn map_sse(error: SseError) -> TransportError {
    match error {
        SseError::InvalidUtf8 | SseError::LineTooLong | SseError::EventTooLarge => {
            TransportError::InvalidBody
        }
    }
}
