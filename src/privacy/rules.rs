//! Detection rules for privacy redaction — secrets and personal data.
//!
//! A port of magpie's `internal/redact` rule set (`reference/magpie`, read-only)
//! to the Rust `regex` crate; the patterns stay RE2-compatible (no lookaround,
//! no backreferences). Rules are **marker-gated**: a rule only runs when the
//! text carries one of its markers, so ordinary prose costs almost nothing on
//! the hot path.

use std::sync::LazyLock;

use regex::Regex;

use super::{Repl, Span};

const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const TOKEN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// A field's or a value's quote, if it has one: `"`, `'`, or `\"` inside JSON.
const QUOTE: &str = r#"(?:\\?["']?)?"#;
/// The characters of a secret's value.
const SECRET_CH: &str = r"[A-Za-z0-9_\-./+=~!@#%^&*]";

#[derive(PartialEq, Eq, Clone, Copy)]
enum Cat {
    Secret,
    Personal,
}

struct Rule {
    kind: &'static str,
    re: Regex,
    markers: &'static [&'static str],
    /// Characters that may not touch a match on either side (empty = no bound).
    bound: &'static str,
    cat: Cat,
    ok: Option<fn(&str) -> bool>,
    /// Keep group 1 when the pattern has a group (else the whole match).
    group: bool,
}

/// What a field that holds a secret is called in its name (used to build the
/// `SECRET` rules and, elsewhere, nothing).
const SECRET_NAMES: &str = r"(?i:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization)";

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(build);

fn build() -> Vec<Rule> {
    let mut r = Vec::new();
    let mut add = |kind: &'static str,
                   pat: &str,
                   markers: &'static [&'static str],
                   bound: &'static str,
                   cat: Cat,
                   ok: Option<fn(&str) -> bool>,
                   group: bool| {
        match Regex::new(pat) {
            // A pattern that fails to compile is dropped rather than
            // panicking: redaction degrades, it never takes the gateway down.
            Ok(re) => r.push(Rule {
                kind,
                re,
                markers,
                bound,
                cat,
                ok,
                group,
            }),
            Err(e) => tracing::warn!(kind, error = %e, "privacy rule dropped (bad pattern)"),
        }
    };

    // ---- secrets -----------------------------------------------------------
    add(
        "PRIVATE_KEY",
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        &["PRIVATE KEY"],
        "",
        Cat::Secret,
        None,
        false,
    );
    add(
        "API_KEY",
        r"sk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",
        &["sk-"],
        TOKEN,
        Cat::Secret,
        None,
        false,
    );
    add(
        "API_KEY",
        r"[a-z]{2,4}_sk_[A-Za-z0-9_-]{20,}",
        &["_sk_"],
        TOKEN,
        Cat::Secret,
        Some(secret_value),
        false,
    );
    add(
        "API_KEY",
        r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,})",
        &["gh", "github_pat_", "glpat-"],
        TOKEN,
        Cat::Secret,
        None,
        false,
    );
    add(
        "API_KEY",
        r"AIza[0-9A-Za-z_-]{35}",
        &["AIza"],
        TOKEN,
        Cat::Secret,
        None,
        false,
    );
    add(
        "API_KEY",
        r"xox[abposr]-[0-9A-Za-z-]{10,}",
        &["xox"],
        TOKEN,
        Cat::Secret,
        None,
        false,
    );
    add(
        "API_KEY",
        r"(?:sk|rk)_live_[0-9A-Za-z]{20,}",
        &["_live_"],
        TOKEN,
        Cat::Secret,
        None,
        false,
    );
    add(
        "API_KEY",
        r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        &["AKIA", "ASIA"],
        ALNUM,
        Cat::Secret,
        None,
        false,
    );
    add(
        "API_KEY",
        r"(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})",
        &["hf_", "gsk_", "xai-", "npm_", "pypi-", "dop_v1_", "SG."],
        TOKEN,
        Cat::Secret,
        None,
        false,
    );
    add(
        "TOKEN",
        r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        &["eyJ"],
        TOKEN,
        Cat::Secret,
        None,
        false,
    );
    add(
        "PASSWORD",
        r#"[A-Za-z][A-Za-z0-9+.-]*://[^\s:@/?#"'<>]+:([^\s@/?#"'<>]{3,})@"#,
        &["://"],
        "",
        Cat::Secret,
        Some(not_a_variable),
        true,
    );
    let secret_assign = format!(
        r#"(?i)[A-Za-z0-9_.-]*(?:{SECRET_NAMES})[A-Za-z0-9_.-]*{QUOTE}[ \t]*[:=][ \t]*{QUOTE}({SECRET_CH}{{8,}})"#
    );
    add(
        "SECRET",
        &secret_assign,
        &[
            "pass",
            "secret",
            "token",
            "key",
            "credential",
            "Pass",
            "Secret",
            "Token",
            "Key",
            "Credential",
        ],
        "",
        Cat::Secret,
        Some(secret_value),
        true,
    );
    let key_field = format!(
        r#"(?i)(?:^|[^A-Za-z0-9_.-]){QUOTE}key{QUOTE}[ \t]*[:=][ \t]*{QUOTE}({SECRET_CH}{{16,}})"#
    );
    add(
        "SECRET",
        &key_field,
        &["key", "Key"],
        "",
        Cat::Secret,
        Some(secret_value),
        true,
    );

    // ---- personal data -----------------------------------------------------
    add(
        "EMAIL",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
        &["@"],
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-",
        Cat::Personal,
        Some(real_email),
        false,
    );
    add(
        "ID_CARD",
        r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
        &[],
        ALNUM,
        Cat::Personal,
        Some(chinese_id),
        false,
    );
    add(
        "PHONE",
        r"(?:\+?86[- ]?)?1[3-9]\d{9}",
        &[],
        ALNUM,
        Cat::Personal,
        None,
        false,
    );
    add(
        "BANK_CARD",
        r"[3-6]\d{3}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?",
        &[],
        ALNUM,
        Cat::Personal,
        Some(luhn),
        false,
    );

    r
}

/// A value that looks like a secret, not code: letters and digits both, and not
/// a call, a reference, or a stand-in (`${PASS}`, `<password>`, `****`).
fn secret_value(v: &str) -> bool {
    if !not_a_variable(v) || v.starts_with("process.env") || v.starts_with("os.") {
        return false;
    }
    v.bytes().any(|b| b.is_ascii_digit()) && v.bytes().any(|b| b.is_ascii_alphabetic())
}

fn not_a_variable(v: &str) -> bool {
    match v.as_bytes().first() {
        Some(b'$') | Some(b'%') | Some(b'{') | Some(b'<') | Some(b'[') | Some(b'*') => false,
        _ => !v
            .trim_matches(|c| c == '*' || c == 'x' || c == 'X' || c == '.')
            .is_empty(),
    }
}

fn real_email(v: &str) -> bool {
    let host = match v.rsplit_once('@') {
        Some((_, h)) => h.to_ascii_lowercase(),
        None => return false,
    };
    for fake in [
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        ".test",
        ".invalid",
        ".example",
    ] {
        let f = fake.strip_prefix('.').unwrap_or(fake);
        if host == f || (fake.starts_with('.') && host.ends_with(fake)) {
            return false;
        }
    }
    !host.starts_with("noreply") && !v.contains("noreply@")
}

fn chinese_id(v: &str) -> bool {
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const C: &[u8] = b"10X98765432";
    let b = v.as_bytes();
    if b.len() != 18 {
        return false;
    }
    let mut sum = 0u32;
    for i in 0..17 {
        let Some(d) = (b[i] as char).to_digit(10) else {
            return false;
        };
        sum += d * W[i];
    }
    b[17].to_ascii_uppercase() == C[(sum % 11) as usize]
}

fn luhn(v: &str) -> bool {
    let ds: Vec<u32> = v.bytes().filter_map(|b| (b as char).to_digit(10)).collect();
    if ds.len() < 15 || ds.len() > 19 {
        return false;
    }
    let sum: u32 = ds
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let d = d * 2;
                if d > 9 { d - 9 } else { d }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Spans of what `secrets`/`personal` cover in `s`.
pub(crate) fn spans(s: &str, secrets: bool, personal: bool) -> Vec<Span> {
    let mut out = Vec::new();
    for rule in RULES.iter() {
        let on = match rule.cat {
            Cat::Secret => secrets,
            Cat::Personal => personal,
        };
        if !on {
            continue;
        }
        if !rule.markers.is_empty() && !rule.markers.iter().any(|m| s.contains(m)) {
            continue;
        }
        for caps in rule.re.captures_iter(s) {
            let m = if rule.group {
                match caps.get(1) {
                    Some(g) => g,
                    None => continue,
                }
            } else {
                match caps.get(0) {
                    Some(g) => g,
                    None => continue,
                }
            };
            let (a, b) = (m.start(), m.end());
            if !bounded(s, a, b, rule.bound) {
                continue;
            }
            if let Some(ok) = rule.ok
                && !ok(&s[a..b])
            {
                continue;
            }
            out.push(Span {
                start: a,
                end: b,
                repl: Repl::Derive(rule.kind),
            });
        }
    }
    out
}

/// True when `s[a..b]` may be a value: nothing in `bound` touches it on either side.
fn bounded(s: &str, a: usize, b: usize, bound: &str) -> bool {
    if b <= a {
        return false;
    }
    if bound.is_empty() {
        return true;
    }
    let bytes = s.as_bytes();
    let before = a.checked_sub(1).map(|i| bytes[i] as char);
    let after = bytes.get(b).map(|&c| c as char);
    let hit = |c: Option<char>| c.is_some_and(|c| bound.contains(c));
    !hit(before) && !hit(after)
}

/// Whether any rule matches `s` on its own (used to keep the re-mask index
/// small: a value a rule finds again needs no remembered entry).
pub(crate) fn matches_any(s: &str) -> bool {
    RULES.iter().any(|rule| {
        if !rule.markers.is_empty() && !rule.markers.iter().any(|m| s.contains(m)) {
            return false;
        }
        rule.re.is_match(s)
    })
}
