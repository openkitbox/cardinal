//! Client identification from the User-Agent header: agents like opencode,
//! codex, Claude Code and pi name themselves in their User-Agent, so the
//! request ledger records *which client* called beside *which key*
//! (`caller_key`) it used.
//!
//! (The `agent` module is agent *config wiring*; this is request *client*
//! identity.)

/// A client the gateway recognizes by name.
struct Known {
    /// Canonical id the ledger records.
    id: &'static str,
    /// Exact product tokens (the UA's first token, lowercased) that mean this
    /// client.
    names: &'static [&'static str],
    /// Product-token prefixes that mean this client.
    ua: &'static [&'static str],
}

/// The recognized clients (each entry verified against the client's real
/// User-Agent). Exact names precede prefixes: `pi` is exact-only so
/// `pip/25.0` (Python's installer) is not misread as the pi coding agent —
/// pi stays out of the prefix table for the same reason.
const KNOWN: &[Known] = &[
    // opencode/1.18.34 (opencode's own protocol layer)
    Known {
        id: "opencode",
        names: &["opencode"],
        ua: &[],
    },
    // codex_cli_rs/0.41.0 (…) — the token is the full crate name, hence prefix
    Known {
        id: "codex",
        names: &["codex"],
        ua: &["codex"],
    },
    // claude-cli/2.x.x (external, cli)
    Known {
        id: "claude-code",
        names: &["claude-cli", "claude-code"],
        ua: &["claude-cli", "claude-code"],
    },
    // pi/<version> (pi-mono #3877/#8361); the oh-my-pi fork sends omp/<version>
    Known {
        id: "pi",
        names: &["pi"],
        ua: &["omp"],
    },
    // The rest of the curated set that can plausibly reach this gateway.
    Known {
        id: "magpie",
        names: &["magpie"],
        ua: &["magpie"],
    },
    Known {
        id: "cursor",
        names: &["cursor"],
        ua: &["cursor"],
    },
    Known {
        id: "copilot",
        names: &["copilot", "github-copilot"],
        ua: &["copilot", "github-copilot"],
    },
    Known {
        id: "gemini-cli",
        names: &["geminicli", "gemini-cli"],
        ua: &["geminicli", "gemini-cli"],
    },
    Known {
        id: "crush",
        names: &["crush"],
        ua: &["crush"],
    },
    Known {
        id: "cline",
        names: &["cline"],
        ua: &["cline"],
    },
    Known {
        id: "goose",
        names: &["goose"],
        ua: &["goose"],
    },
    Known {
        id: "curl",
        names: &["curl"],
        ua: &["curl"],
    },
];

/// HTTP libraries and SDKs, not clients: their product token carries no
/// client identity (`ai-sdk/...` is alma's HTTP stack, not alma), so
/// recording it as the agent would mask the more informative key label —
/// these fall through to None and the ledger shows the caller key instead.
const LIBRARY_TOKENS: &[&str] = &[
    "ai",
    "ai-sdk", // Vercel AI SDK (alma)
    "python-requests",
    "httpx",
    "aiohttp",
    "urllib3",
    "axios",
    "node-fetch",
    "undici",
    "node",
    "go-http-client",
    "okhttp",
    "java",
];

/// Name the client behind a User-Agent: the first product
/// token (`curl/8.7.1` → `curl`, `claude-cli/2.0.0 (external, cli)` →
/// `claude-cli`) matched against the known table — exact names first, then
/// prefixes. An unknown client keeps its own product token (fallback: better
/// a raw name than "other"); no User-Agent is None.
pub fn agent_of(user_agent: &str) -> Option<String> {
    let ua = user_agent.trim();
    let name = ua.split(['/', ' ']).next().unwrap_or("");
    if name.is_empty() {
        return None;
    }
    let lower = name.to_lowercase();
    if LIBRARY_TOKENS.contains(&lower.as_str()) {
        return None;
    }
    for known in KNOWN {
        if known.names.contains(&lower.as_str()) {
            return Some(known.id.to_owned());
        }
    }
    for known in KNOWN {
        if known.ua.iter().any(|prefix| lower.starts_with(prefix)) {
            return Some(known.id.to_owned());
        }
    }
    Some(name.to_owned())
}
