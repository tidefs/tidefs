// Snapshot retention policy and time-bucketed evaluation helpers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pruner::SnapshotInfo;

// ---------------------------------------------------------------------------
// SnapshotRetentionPolicy
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotRetentionPolicy {
    pub keep_last: Option<u32>,
    pub keep_hourly: Option<u32>,
    pub keep_daily: Option<u32>,
    pub keep_weekly: Option<u32>,
    pub keep_monthly: Option<u32>,
    pub keep_yearly: Option<u32>,
    pub max_snapshots: Option<u32>,
    pub max_age_days: Option<u32>,
}
impl SnapshotRetentionPolicy {
    pub fn is_empty(&self) -> bool {
        self.keep_last.is_none()
            && self.keep_hourly.is_none()
            && self.keep_daily.is_none()
            && self.keep_weekly.is_none()
            && self.keep_monthly.is_none()
            && self.keep_yearly.is_none()
            && self.max_snapshots.is_none()
            && self.max_age_days.is_none()
    }
}

// ---------------------------------------------------------------------------
// Retention bucket helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BucketKind {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

pub(crate) fn bucket_key(ts: SystemTime, k: BucketKind) -> (i32, u32) {
    let secs = ts
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let days = secs / 86400;
    let (y, m, _) = civil_from_days(days as i64);
    match k {
        BucketKind::Yearly => (y, 0),
        BucketKind::Monthly => (y, m),
        BucketKind::Weekly => {
            let doy = day_of_year(days as i64, y);
            (y, doy / 7)
        }
        BucketKind::Daily => {
            let doy = day_of_year(days as i64, y);
            (y, doy)
        }
        BucketKind::Hourly => {
            let doy = day_of_year(days as i64, y);
            let h = (secs / 3600) % 24;
            (y, doy * 24 + h as u32)
        }
    }
}

pub(crate) fn group_by_bucket<'a>(
    sorted: &[&'a SnapshotInfo],
    k: BucketKind,
) -> Vec<((i32, u32), Vec<&'a SnapshotInfo>)> {
    let mut g: Vec<((i32, u32), Vec<&'a SnapshotInfo>)> = Vec::new();
    for i in sorted {
        let key = bucket_key(i.created_at, k);
        match g.last_mut() {
            Some((kk, v)) if *kk == key => v.push(*i),
            _ => g.push((key, vec![*i])),
        }
    }
    g
}

pub(crate) fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z + 1) / 146097 - 1
    };
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}
pub(crate) fn day_of_year(ds: i64, y: i32) -> u32 {
    let j1 = days_from_civil(y, 1, 1);
    (ds - j1) as u32 + 1
}
pub(crate) fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y + 1) / 400 - 1 };
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m <= 2 { m + 9 } else { m - 3 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    era * 146097 + doe as i64 - 719468
}

// ---------------------------------------------------------------------------
