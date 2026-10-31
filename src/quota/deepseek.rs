use super::Balance;
use super::KeyQuota;

/// DeepSeek balance (`/user/balance`):
/// `{"balance_infos":[{"currency":"CNY","total_balance":"12.34"}]}` — the
/// first entry, with the currency folded to its symbol (an unparseable
/// amount is no reading, not "¥abc").
pub(super) fn parse_deepseek_balance(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        #[serde(default)]
        balance_infos: Vec<BalanceInfo>,
    }
    #[derive(serde::Deserialize)]
    struct BalanceInfo {
        currency: String,
        total_balance: String,
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let first = response.balance_infos.into_iter().next()?;
    let symbol = match first.currency.as_str() {
        "CNY" => "¥",
        "USD" => "$",
        _ => return None,
    };
    let amount: f64 = first
        .total_balance
        .trim()
        .parse()
        .ok()
        .filter(|amount: &f64| amount.is_finite())?;
    Some(KeyQuota {
        windows: Vec::new(),
        balance: Some(Balance {
            amount,
            symbol: symbol.to_string(),
        }),
        details: Vec::new(),
    })
}
