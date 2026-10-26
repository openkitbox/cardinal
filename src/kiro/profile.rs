//! Kiro KAS wire profile: the single owner of the identity cardinal presents
//! when it speaks to Kiro's runtime service, plus the retry-header grammar.
//!
//! Values mirror the reference `kiro2claude` `client-profile.ts` snapshot for
//! kiro-cli 2.34.0 (KAS 0.66.62) and the Rust shell 1.3.10. They are a fixed
//! snapshot on purpose: the upstream only cares that the wire is a plausible
//! kiro-cli client, so a stale-but-legal profile beats a guessed-at-new one.
//! The opt-out header is a privacy hard rule (the reference forces it even when
//! its captured fixture says otherwise): conversations are never offered for
//! upstream training.
//!
//! Deliberate deviations from the captured client, all owned here:
//! - `content-type` rides [`crate::protocol::Prepared::content_type`] instead
//!   of a static header, because the transport sets that header for every
//!   protocol; duplicating it would put the same header on the request twice.
//! - `connection: keep-alive` is omitted: the shared connection pool owns
//!   connection lifecycle, and a hand-written hop-by-hop header would only
//!   fight it.
//! - `accept` / `accept-encoding` are transport defaults. The captured KAS
//!   suppresses them; this kernel cannot, and neither header changes how KAS
//!   treats the body.
//! - the Node-style `{jsOs}` token carries only the platform name
//!   (`linux` / `darwin` / `win32`): the kernel release KAS appends is not
//!   available without libc, and a fabricated release would be worse than the
//!   legal, shorter token.

use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU32, Ordering};

/// `x-amz-target` of the conversational call (`GenerateAssistantResponse`).
pub const KAS_TARGET: &str = "KiroRuntimeService.GenerateAssistantResponse";
/// `x-amz-target` of the quota call the Rust shell sends (GetUsageLimits).
pub const USAGE_TARGET: &str = "AmazonCodeWhispererService.GetUsageLimits";
/// Attempts kiro-cli declares to the upstream in both retry headers.
pub const KIRO_MAX_ATTEMPTS: u32 = 3;

/// The KAS origin for a runtime region. Every KAS call POSTs to the root.
pub fn kas_endpoint(region: &str) -> String {
    format!("https://runtime.{region}.kiro.dev/")
}

/// The AWS service host of a runtime region: CodeWhisperer in `us-east-1`,
/// the `q.*` host everywhere else (what kiro-cli's shell talks to).
pub fn runtime_host(region: &str) -> String {
    if region == "us-east-1" {
        format!("codewhisperer.{region}.amazonaws.com")
    } else {
        format!("q.{region}.amazonaws.com")
    }
}

/// kiro-cli's retry header triple — the **only** owner of its grammar.
///
/// The `ttl=` element appears from the second attempt on and is the moment one
/// hour after `now`; `amz-sdk-request` separates its elements with `"; "`
/// while `x-kiro-attempt` uses a bare `";"`. `invocation` is a parameter, not
/// generated here: its lifetime is one logical call (see [`KasCall`]), so a
/// header builder that minted it would turn every retry into a brand-new call
/// in the upstream's eyes.
pub fn retry_headers(
    invocation: &str,
    attempt: u32,
    max: u32,
    kiro: bool,
    now: DateTime<Utc>,
) -> Vec<(&'static str, String)> {
    let ttl = if attempt > 1 {
        format!(
            "ttl={}; ",
            (now + chrono::Duration::hours(1)).format("%Y%m%dT%H%M%SZ")
        )
    } else {
        String::new()
    };
    let mut headers = vec![
        ("amz-sdk-invocation-id", invocation.to_owned()),
        (
            "amz-sdk-request",
            format!("{ttl}attempt={attempt}; max={max}"),
        ),
    ];
    if kiro {
        headers.push(("x-kiro-attempt", format!("{attempt};max={max}")));
    }
    headers
}

/// Rewrite the retry triple **in place** on an already-prepared header list.
///
/// The transport appends a caller's header list after the prepared one, so a
/// retry that merely appended a second `amz-sdk-request` / `x-kiro-attempt`
/// would put two contradictory values on the wire. This finds the existing
/// entries (same names, same positions) and replaces their values, reusing the
/// invocation id: the retry is the same logical call, one attempt later.
pub fn replace_retry_headers(
    headers: &mut Vec<(&'static str, String)>,
    invocation: &str,
    attempt: u32,
    max: u32,
    now: DateTime<Utc>,
) {
    for (name, value) in retry_headers(invocation, attempt, max, true, now) {
        match headers.iter_mut().find(|(existing, _)| *existing == name) {
            Some(slot) => slot.1 = value,
            None => headers.push((name, value)),
        }
    }
}

/// The static KAS headers (everything except the retry triple and the
/// credential, which the relay injects from the resolved key).
pub fn kas_static_headers() -> Vec<(&'static str, String)> {
    vec![
        ("user-agent", kas_user_agent()),
        ("x-amz-user-agent", kas_x_amz_user_agent()),
        ("x-amz-target", KAS_TARGET.to_owned()),
        ("x-amzn-codewhisperer-optout", "true".to_owned()),
        ("x-amzn-kiro-client-attribution", "kiro-cli".to_owned()),
    ]
}

/// KAS `user-agent` (the aws-sdk-js shape KAS uses), rendered for this host.
pub fn kas_user_agent() -> String {
    render(
        "aws-sdk-js/1.0.0 ua/2.1 os/{jsOs} lang/js md/nodejs#22.22.2 \
         api/kiroruntime#1.0.0 m/N KiroCLI/2.34.0 KAS/0.66.62 os/{platform} \
         md/appVersion-2.34.0 app/AmazonQ-For-CLI acp-client/kiro-cli",
    )
}

/// KAS `x-amz-user-agent` — the same identity without the SDK-only fields.
pub fn kas_x_amz_user_agent() -> String {
    render(
        "aws-sdk-js/1.0.0 KiroCLI/2.34.0 KAS/0.66.62 os/{platform} \
         md/appVersion-2.34.0 app/AmazonQ-For-CLI acp-client/kiro-cli",
    )
}

/// The Rust shell's static headers: everything the quota call
/// (`GetUsageLimits`, [`USAGE_TARGET`]) sends besides the credential, the retry
/// pair and `content-type` (which rides
/// [`crate::protocol::Prepared::content_type`]). `accept` /
/// `accept-encoding` are transport defaults — the same deviation as the KAS
/// identity (see the module docs). The opt-out header is the privacy hard rule
/// again: the shell asks for an account summary, never for training consent.
pub fn usage_static_headers() -> Vec<(&'static str, String)> {
    vec![
        ("user-agent", shell_user_agent()),
        ("x-amz-user-agent", shell_x_amz_user_agent()),
        ("x-amz-target", USAGE_TARGET.to_owned()),
        ("x-amzn-codewhisperer-optout", "true".to_owned()),
    ]
}

/// The Rust shell's `user-agent` (GetUsageLimits, the quota probe).
pub fn shell_user_agent() -> String {
    render(
        "aws-sdk-rust/1.3.10 ua/2.1 api/codewhispererruntime/0.1.10231 os/{os} \
         lang/rust/1.94.1 md/appVersion-2.34.0 app/AmazonQ-For-CLI",
    )
}

/// The Rust shell's `x-amz-user-agent` (GetUsageLimits).
pub fn shell_x_amz_user_agent() -> String {
    render(
        "aws-sdk-rust/1.3.10 ua/2.1 api/codewhispererruntime/0.1.10231 os/{os} \
         lang/rust/1.94.1 m/F,C app/AmazonQ-For-CLI",
    )
}

/// One logical KAS call: the invocation id every attempt of it shares, plus
/// the attempt counter the retry headers render from.
///
/// The caller owns one per candidate dispatch — the reference's one
/// `RetryExecutor.execute()` — and hands it to the kernel through
/// [`crate::protocol::TargetView`]. Two properties depend on that ownership:
/// a re-prepare inside the same dispatch (the optional-field strip round) must
/// advance the attempt instead of minting an invocation the upstream has never
/// seen, and a failover to the next candidate must simply build a new value.
/// The interior mutability keeps `prepare` a `&TargetView` call.
#[derive(Debug)]
pub struct KasCall {
    invocation: String,
    attempt: AtomicU32,
}

impl KasCall {
    pub fn new() -> Self {
        Self {
            invocation: uuid::Uuid::new_v4().to_string(),
            attempt: AtomicU32::new(0),
        }
    }

    /// The id shared by every attempt of this call.
    pub fn invocation(&self) -> &str {
        &self.invocation
    }

    /// Advance to the next attempt and return its number (the first call
    /// answers 1, the first retry 2, ...). The declared maximum is a hard
    /// ceiling: a strip round can never produce `attempt=4; max=3`.
    pub fn next_attempt(&self) -> u32 {
        let mut attempt = self.attempt.load(Ordering::Relaxed);
        loop {
            let next = (attempt + 1).min(KIRO_MAX_ATTEMPTS);
            match self.attempt.compare_exchange_weak(
                attempt,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(actual) => attempt = actual,
            }
        }
    }
}

impl Default for KasCall {
    fn default() -> Self {
        Self::new()
    }
}

/// This host's kiro-cli style OS token (`macos` / `linux` / `windows`).
fn os_token() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    }
}

/// The Node `process.platform` token KAS's SDK writes (`darwin` / `linux` /
/// `win32`).
fn js_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        _ => "linux",
    }
}

/// Fill the profile's OS placeholders. `{jsOs}` deliberately renders as the
/// bare platform (see the module docs); `{platform}` is Node's name and `{os}`
/// kiro-cli's.
fn render(template: &str) -> String {
    template
        .replace("{jsOs}", js_platform())
        .replace("{platform}", js_platform())
        .replace("{os}", os_token())
}
