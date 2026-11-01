//! Billing rules: rate resolution, cost-to-charge conversion, usage
//! certainty and admission. Pure functions only — no I/O, no database, no
//! global state; the relay and the settlement writer do the wiring.
//!
//! Units: money is integer micro-USD (`i64`, 1 USD = 1_000_000); rate
//! multipliers are integer basis points (`i64`, 10_000 = 1.0×). Admin-entered
//! amounts are decimal USD strings converted exactly by [`parse_usd`] (never
//! through a float) and rendered back by [`format_usd`].
//!
//! Rounding: the provider cost (USD float from `ModelPrice::cost_split`) is
//! *rounded* to micro-USD so float noise such as `3.0000000000000004e-6`
//! never adds a unit; the multiplied charge is *ceiled*, so whenever
//! cost > 0 and rate > 0 the charge is at least 1 micro-USD. Overcharging by
//! under one micro-USD is preferred to letting a paid call through for free.
//!
//! Certainty: [`UsageCertainty::Unknown`] is never treated as zero. Callers
//! do not charge an unknown attempt, but they must warn about it. There is
//! no stored "estimated" flag: a charge on estimated usage is recognisable
//! from the ledger row's upstream `protocol = 'kiro'`.
//!
//! Division of labour with `api::refusal`: authentication decides whether an
//! identity is valid (key/user enabled, not expired); [`admit`] decides
//! whether a valid identity may spend on the requested model.

use crate::metering::UsageCertainty;
use crate::protocol::ProtocolId;
use crate::store::CreditKind;
use crate::store::Principal;

/// Basis points meaning a 1.0× multiplier.
const UNIT_BP: i128 = 10_000;
/// Micro-USD per USD.
const MICROUS_PER_USD: f64 = 1_000_000.0;
/// Micro-USD per USD as an integer.
const MICROUS_PER_USD_INT: i64 = 1_000_000;
/// Decimal places of a USD amount in micro-USD.
const USD_SCALE_DIGITS: usize = 6;

/// Largest rate multiplier an operator may set on a user or group:
/// 1_000_000 bp = 100×. Far beyond any real price, and it keeps
/// `cost × rate` well inside `i64` for every plausible cost.
pub const MAX_RATE_BP: i64 = 1_000_000;

/// Rows per ledger page when the client names no limit.
const DEFAULT_ENTRY_PAGE: i64 = 50;
/// Largest ledger page a client may request.
const MAX_ENTRY_PAGE: i64 = 500;

/// Effective rate multiplier: the user override wins over the group rate.
#[must_use]
pub fn rate_bp(principal: &Principal) -> i64 {
    effective_rate_bp(principal.user_rate_bp, principal.group_rate_bp)
}

/// Effective rate from its two sources: the user override when set, else the
/// group rate.
#[must_use]
pub fn effective_rate_bp(user_rate_bp: Option<i64>, group_rate_bp: i64) -> i64 {
    user_rate_bp.unwrap_or(group_rate_bp)
}

/// Parse a decimal USD string (`"10"`, `"0.5"`, `"-1.25"`) into micro-USD
/// exactly, without going through a float. Accepts one leading `-` and at
/// most six fractional digits; anything else (empty, `+`, exponent, more
/// digits, out of range) is `None`.
#[must_use]
pub fn parse_usd(text: &str) -> Option<i64> {
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (whole, fraction) = match unsigned.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
        Some(_) => return None,
        None => (unsigned, ""),
    };
    if whole.is_empty() || fraction.len() > USD_SCALE_DIGITS {
        return None;
    }
    let mut micro = digits_value(whole)?.checked_mul(MICROUS_PER_USD_INT)?;
    if !fraction.is_empty() {
        let scale = 10_i64.checked_pow(u32::try_from(USD_SCALE_DIGITS - fraction.len()).ok()?)?;
        micro = micro.checked_add(digits_value(fraction)?.checked_mul(scale)?)?;
    }
    if negative {
        micro.checked_neg()
    } else {
        Some(micro)
    }
}

/// Value of a non-empty run of ASCII digits, `None` on any other byte or on
/// overflow.
fn digits_value(digits: &str) -> Option<i64> {
    digits.bytes().try_fold(0_i64, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))
    })
}

/// Render micro-USD as a USD string with exactly six decimals
/// (`-1_250_000` → `"-1.250000"`).
#[must_use]
pub fn format_usd(microus: i64) -> String {
    let sign = if microus < 0 { "-" } else { "" };
    let magnitude = microus.unsigned_abs();
    let per_usd = MICROUS_PER_USD_INT.unsigned_abs();
    format!(
        "{sign}{}.{:0width$}",
        magnitude / per_usd,
        magnitude % per_usd,
        width = USD_SCALE_DIGITS
    )
}

/// Validate a manual balance change and return its signed micro-USD amount,
/// or the client-facing reason it is refused: a top-up must be positive; an
/// adjustment must be non-zero and carry a note explaining it.
pub fn credit_amount(kind: CreditKind, amount_usd: &str, note: &str) -> Result<i64, &'static str> {
    let Some(amount) = parse_usd(amount_usd.trim()) else {
        return Err("amount_usd must be a decimal USD string with at most 6 decimals");
    };
    match kind {
        CreditKind::Topup if amount <= 0 => Err("top-up amount must be positive"),
        CreditKind::Adjust if amount == 0 => Err("adjustment amount must not be zero"),
        CreditKind::Adjust if note.trim().is_empty() => Err("adjustment requires a note"),
        CreditKind::Topup | CreditKind::Adjust => Ok(amount),
    }
}

/// Page size of a ledger listing: the requested limit clamped to
/// `1..=500`, 50 when absent.
#[must_use]
pub fn entry_page_limit(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_ENTRY_PAGE)
        .clamp(1, MAX_ENTRY_PAGE)
}

/// Convert a USD cost to micro-USD, rounding to the nearest unit. Returns
/// `None` for non-finite, negative or out-of-range values.
#[must_use]
pub fn cost_microus(cost_usd: f64) -> Option<i64> {
    if !cost_usd.is_finite() || cost_usd < 0.0 {
        return None;
    }
    let micro = (cost_usd * MICROUS_PER_USD).round();
    // `i64::MAX as f64` rounds up to 2^63, which is itself out of range.
    if micro >= i64::MAX as f64 {
        return None;
    }
    Some(micro as i64)
}

/// Amount to debit: `ceil(cost × rate / 10_000)`, saturating at `i64::MAX`.
/// Zero when either the cost or the rate is not positive.
#[must_use]
pub fn charge_microus(cost_microus: i64, rate_bp: i64) -> i64 {
    if cost_microus <= 0 || rate_bp <= 0 {
        return 0;
    }
    let product = i128::from(cost_microus) * i128::from(rate_bp);
    let charge = (product + UNIT_BP - 1) / UNIT_BP;
    i64::try_from(charge).unwrap_or(i64::MAX)
}

/// Amount to debit for one successful attempt, or `None` for "do not
/// charge": unknown usage, no cost (unpriced model), or a cost that cannot
/// be converted. Estimated usage (Kiro) is charged like known usage. A zero
/// rate yields `Some(0)` — a charged-at-zero row, not an unbilled one.
#[must_use]
pub fn attempt_charge(
    cost_usd: Option<f64>,
    certainty: UsageCertainty,
    rate_bp: i64,
) -> Option<i64> {
    match certainty {
        UsageCertainty::Unknown => None,
        UsageCertainty::Known | UsageCertainty::Estimated => {
            let cost = cost_microus(cost_usd?)?;
            Some(charge_microus(cost, rate_bp))
        }
    }
}

/// How far the observed usage can be trusted. No usage is `Unknown`; Kiro
/// token counts are local estimates (see `protocol::kiro`), so `Estimated`.
/// Takes whether usage was observed rather than the counts themselves: the
/// non-streaming path holds `UsageCounts`, the streaming path its own
/// `StreamUsage` summary, and only presence matters here.
#[must_use]
pub fn certainty(usage_observed: bool, upstream: ProtocolId) -> UsageCertainty {
    if !usage_observed {
        return UsageCertainty::Unknown;
    }
    match upstream {
        ProtocolId::Kiro => UsageCertainty::Estimated,
        ProtocolId::OpenAiChat
        | ProtocolId::OpenAiResponses
        | ProtocolId::AnthropicMessages
        | ProtocolId::Gemini
        | ProtocolId::OpenAiEmbeddings => UsageCertainty::Known,
    }
}

/// Why a valid identity may not spend on a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    InsufficientBalance,
    RouteNotAllowed,
}

impl Deny {
    /// HTTP status for the client response.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Deny::InsufficientBalance => 402,
            Deny::RouteNotAllowed => 403,
        }
    }

    /// Client-facing error message.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Deny::InsufficientBalance => "insufficient balance; top up to continue",
            Deny::RouteNotAllowed => "this model is not available on your plan",
        }
    }
}

/// Decide whether `principal` may spend on `model` (the client-requested
/// route alias or `provider/model` direct string).
///
/// The route whitelist is checked before the balance: "this model is not
/// available" is the more accurate answer than "top up" for a model the
/// plan can never use. A whitelist matches exactly, so direct
/// `provider/model` strings are refused unless listed. Free users (rate 0)
/// skip the balance check.
pub fn admit(principal: &Principal, model: &str) -> Result<(), Deny> {
    if let Some(aliases) = &principal.route_aliases
        && !aliases.iter().any(|alias| alias == model)
    {
        return Err(Deny::RouteNotAllowed);
    }
    if rate_bp(principal) > 0 && principal.balance_microus <= 0 {
        return Err(Deny::InsufficientBalance);
    }
    Ok(())
}

/// Whether candidates must carry a price. Billed users (rate > 0) fail
/// closed on unpriced models; free users and in-process calls (`None`) do
/// not need prices.
#[must_use]
pub fn needs_price(principal: Option<&Principal>) -> bool {
    principal.is_some_and(|principal| rate_bp(principal) > 0)
}
