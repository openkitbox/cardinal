use jiff::Timestamp;
use jiff::civil::Date;

use super::KeyQuota;

pub fn next_monthly_reset(day: u32, now: Timestamp) -> Option<Timestamp> {
    if !(1..=28).contains(&day) {
        return None;
    }
    let utc = now.to_zoned_datetime(jiff::tz::TimeZone::UTC);
    let make = |year, month| -> Option<Timestamp> {
        Some(
            Date::new(year, month, i8::try_from(day).ok()?)
                .ok()?
                .at(0, 0, 0, 0)
                .to_zoned_datetime(jiff::tz::TimeZone::UTC)
                .ok()?
                .timestamp(),
        )
    };
    let current = make(utc.year(), utc.month())?;
    if current > now {
        Some(current)
    } else if utc.month() == 12 {
        make(utc.year() + 1, 1)
    } else {
        make(utc.year(), utc.month() + 1)
    }
}

pub fn apply_monthly_anchor(quota: &mut KeyQuota, day: u32, now: Timestamp) {
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
