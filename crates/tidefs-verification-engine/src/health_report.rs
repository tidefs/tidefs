//! Pool-level health report aggregation for segment integrity verification.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Pass {
        segment_id: u64,
        records_verified: u64,
        bytes_scanned: u64,
    },
    Mismatch {
        segment_id: u64,
        mismatched_records: u64,
        records_verified: u64,
    },
    Unreadable {
        segment_id: u64,
        reason: String,
    },
    Truncated {
        segment_id: u64,
    },
}

impl VerificationOutcome {
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentHealthStatus {
    pub segment_id: u64,
    pub outcome: VerificationOutcome,
    pub device_path: Option<std::path::PathBuf>,
    pub check_time: SystemTime,
}

#[derive(Clone, Debug)]
pub struct HealthReport {
    pub segments: BTreeMap<u64, SegmentHealthStatus>,
    pub total_segments: u64,
    pub passed: u64,
    pub mismatches: u64,
    pub unreadable: u64,
    pub truncated: u64,
    pub total_records_verified: u64,
    pub total_bytes_scanned: u64,
    pub scan_duration: Option<Duration>,
    pub pool_healthy: bool,
    pub created_at: SystemTime,
    pub started_at: SystemTime,
}

impl HealthReport {
    #[must_use]
    pub fn new(started_at: SystemTime) -> Self {
        Self {
            segments: BTreeMap::new(),
            total_segments: 0,
            passed: 0,
            mismatches: 0,
            unreadable: 0,
            truncated: 0,
            total_records_verified: 0,
            total_bytes_scanned: 0,
            scan_duration: None,
            pool_healthy: true,
            created_at: SystemTime::now(),
            started_at,
        }
    }

    pub fn record(
        &mut self,
        outcome: VerificationOutcome,
        device_path: Option<std::path::PathBuf>,
    ) {
        let segment_id = match &outcome {
            VerificationOutcome::Pass { segment_id, .. }
            | VerificationOutcome::Mismatch { segment_id, .. }
            | VerificationOutcome::Unreadable { segment_id, .. }
            | VerificationOutcome::Truncated { segment_id } => *segment_id,
        };

        let _existed = self.segments.contains_key(&segment_id);
        let old_outcome = self.segments.get(&segment_id).map(|s| s.outcome.clone());

        let status = SegmentHealthStatus {
            segment_id,
            outcome: outcome.clone(),
            device_path,
            check_time: SystemTime::now(),
        };
        self.segments.insert(segment_id, status);

        // Undo old counters when replacing an existing segment.
        if let Some(old) = old_outcome {
            match old {
                VerificationOutcome::Pass {
                    records_verified,
                    bytes_scanned,
                    ..
                } => {
                    self.passed = self.passed.saturating_sub(1);
                    self.total_records_verified =
                        self.total_records_verified.saturating_sub(records_verified);
                    self.total_bytes_scanned =
                        self.total_bytes_scanned.saturating_sub(bytes_scanned);
                }
                VerificationOutcome::Mismatch {
                    records_verified, ..
                } => {
                    self.mismatches = self.mismatches.saturating_sub(1);
                    self.total_records_verified =
                        self.total_records_verified.saturating_sub(records_verified);
                }
                VerificationOutcome::Unreadable { .. } => {
                    self.unreadable = self.unreadable.saturating_sub(1);
                }
                VerificationOutcome::Truncated { .. } => {
                    self.truncated = self.truncated.saturating_sub(1);
                }
            }
        } else {
            self.total_segments += 1;
        }

        match outcome {
            VerificationOutcome::Pass {
                records_verified,
                bytes_scanned,
                ..
            } => {
                self.passed += 1;
                self.total_records_verified += records_verified;
                self.total_bytes_scanned += bytes_scanned;
            }
            VerificationOutcome::Mismatch {
                records_verified, ..
            } => {
                self.mismatches += 1;
                self.total_records_verified += records_verified;
                self.pool_healthy = false;
            }
            VerificationOutcome::Unreadable { .. } => {
                self.unreadable += 1;
                self.pool_healthy = false;
            }
            VerificationOutcome::Truncated { .. } => {
                self.truncated += 1;
                self.pool_healthy = false;
            }
        }
    }

    pub fn finalize(&mut self) {
        self.created_at = SystemTime::now();
        if let Ok(dur) = self.created_at.duration_since(self.started_at) {
            self.scan_duration = Some(dur);
        }
    }

    #[must_use]
    pub fn unhealthy_count(&self) -> u64 {
        self.mismatches + self.unreadable + self.truncated
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_segments == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    #[test]
    fn new_report_is_healthy() {
        let r = HealthReport::new(now());
        assert!(r.pool_healthy);
        assert!(r.is_empty());
    }

    #[test]
    fn pass_and_mismatch_accumulate() {
        let mut r = HealthReport::new(now());
        r.record(
            VerificationOutcome::Pass {
                segment_id: 1,
                records_verified: 10,
                bytes_scanned: 100,
            },
            None,
        );
        assert_eq!(r.passed, 1);
        assert!(r.pool_healthy);

        r.record(
            VerificationOutcome::Mismatch {
                segment_id: 2,
                mismatched_records: 1,
                records_verified: 5,
            },
            None,
        );
        assert!(!r.pool_healthy);
        assert_eq!(r.unhealthy_count(), 1);
    }

    #[test]
    fn unreadable_and_truncated_increase_unhealthy() {
        let mut r = HealthReport::new(now());
        r.record(
            VerificationOutcome::Unreadable {
                segment_id: 10,
                reason: "io".into(),
            },
            None,
        );
        r.record(VerificationOutcome::Truncated { segment_id: 11 }, None);
        assert_eq!(r.unhealthy_count(), 2);
    }

    #[test]
    fn dedup_by_id_last_wins() {
        let mut r = HealthReport::new(now());
        r.record(
            VerificationOutcome::Pass {
                segment_id: 7,
                records_verified: 1,
                bytes_scanned: 1,
            },
            None,
        );
        r.record(
            VerificationOutcome::Pass {
                segment_id: 7,
                records_verified: 2,
                bytes_scanned: 2,
            },
            None,
        );
        assert_eq!(r.total_segments, 1);
        assert_eq!(r.total_records_verified, 2);
        assert_eq!(r.total_bytes_scanned, 2);
    }

    #[test]
    fn finalize_sets_duration() {
        let mut r = HealthReport::new(now());
        r.finalize();
        assert!(r.scan_duration.is_some());
    }

    #[test]
    fn dedup_replaces_mismatch_with_pass() {
        let mut r = HealthReport::new(now());
        r.record(
            VerificationOutcome::Mismatch {
                segment_id: 5,
                mismatched_records: 1,
                records_verified: 3,
            },
            None,
        );
        assert_eq!(r.mismatches, 1);
        assert!(!r.pool_healthy);

        r.record(
            VerificationOutcome::Pass {
                segment_id: 5,
                records_verified: 3,
                bytes_scanned: 300,
            },
            None,
        );
        assert_eq!(r.total_segments, 1);
        assert_eq!(r.passed, 1);
        assert_eq!(r.mismatches, 0);
        // pool_healthy stays false once set (conservative).
    }
}
