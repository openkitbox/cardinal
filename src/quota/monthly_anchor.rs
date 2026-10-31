use chrono::{DateTime, Utc};

use super::KeyQuota;

/// The next monthly reset at UTC midnight of `day`, strictly after `now`.
/// Days past the 28th are rejected — February has no 30th, and an anchor that
/// cannot exist every month is a config error, not something to clamp.
pub fn next_monthly_reset(day: u32, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    use chrono::Datelike as _;
    if !(1..=28).contains(&day) {
        return None;
    }
    let this_month = now.date_naive().with_day(day)?;
    let this_month = this_month.and_hms_opt(0, 0, 0)?.and_utc();
    Some(if this_month > now {
        this_month
    } else {
        this_month
            .date_naive()
            .checked_add_months(chrono::Months::new(1))?
            .and_hms_opt(0, 0, 0)?
            .and_utc()
    })
}

/// Fill the vendor-hidden monthly reset from the key's configured anchor: a
/// long window (period ≥ 28 days) whose probe carried no reset instant —
/// CommandCode's credits month — gets the next anchor midnight. Windows the
/// vendor did date itself are never touched.
pub fn apply_monthly_anchor(quota: &mut KeyQuota, day: u32, now: DateTime<Utc>) {
    let Some(resets_at) = next_monthly_reset(day, now) else {
        return;
    };
    for window in &mut quota.windows {
        if window.resets_at.is_none()
            && window
                .period_minutes
                .is_some_and(|period| period >= 28 * 1440)
        {
            window.resets_at = Some(resets_at);
        }
    }
}
