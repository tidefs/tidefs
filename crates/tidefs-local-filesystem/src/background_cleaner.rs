//! Background segment cleaner with operator-configurable throttles.
//!
//! Wraps the watermark-based [`CleanerScheduler`] from
//! `tidefs_space_accounting` with a [`RateLimiter`] from
//! `tidefs_scrub_core` so the cleaner respects I/O bandwidth and
//! IOPS limits and avoids starving foreground FUSE/ublk I/O.
//!
//! Called from [`crate::LocalFileSystem::tick_background_services`]
//! as Duty 4: background cleaning.
//!
//! # Algorithm
//!
//! 1. Query free/total segment counts from the store.
//! 2. Evaluate via [`CleanerScheduler::evaluate`].
//! 3. If `StartBackground` or `BlockWriters`: activate the cleaner.
//! 4. If active: check the rate limiter, then call
//!    [`journal_cleaner::clean_oldest_segment`].
//! 5. Feed the cleaning cost into the rate limiter so burst
//!    capacity and sustained rate are enforced.
//! 6. If `Stop`: deactivate.
//!
//! # Throttle design
//!
//! The rate limiter uses a dual token-bucket (bytes/sec + IOPS).
//! Each tick, the cleaner counts one op and a minimal byte
//! footprint.  Set `max_bytes_per_sec=0` for unlimited bytes;
//! use `max_iops` to control cleaning frequency.  When both
//! limits are zero the limiter never throttles.

#![allow(dead_code)]

use tidefs_local_object_store::Pool;
use tidefs_scrub::rate_limiter::RateLimiter;
use tidefs_space_accounting::{CleanerAction, CleanerScheduler, CleanerWatermarks};

use crate::journal_cleaner;

// ---------------------------------------------------------------------------
// BackgroundCleanerConfig
// ---------------------------------------------------------------------------

/// Operator-configurable background cleaner parameters.
#[derive(Clone, Debug)]
pub struct BackgroundCleanerConfig {
    /// Enable background cleaning.  When false, the cleaner never
    /// activates regardless of free-space position.
    pub enabled: bool,
    /// Watermark thresholds that determine when the cleaner activates.
    pub watermarks: CleanerWatermarks,
    /// Maximum bytes/sec for background cleaning I/O.
    /// 0 means unlimited.
    pub max_bytes_per_sec: u64,
    /// Maximum IOPS for background cleaning I/O.
    /// 0 means unlimited.
    pub max_iops: u64,
}

impl Default for BackgroundCleanerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watermarks: CleanerWatermarks::default(),
            // Conservative default: 128 MiB/s, 1000 IOPS.
            max_bytes_per_sec: 128 * 1024 * 1024,
            max_iops: 1000,
        }
    }
}

impl BackgroundCleanerConfig {
    /// Disable background cleaning entirely.
    #[must_use]
    #[allow(dead_code)]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            watermarks: CleanerWatermarks {
                min_free_segments: 0,
                target_free_segments: 0,
                high_free_segments: 0,
                tail_reserved_segments: 0,
            },
            max_bytes_per_sec: 0,
            max_iops: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BackgroundCleanerStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the background cleaner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackgroundCleanerStats {
    /// Number of cleaning rounds attempted.
    pub rounds_attempted: u64,
    /// Number of cleaning rounds that completed successfully.
    pub rounds_completed: u64,
    /// Number of cleaning rounds skipped because the rate limiter
    /// refused tokens (throttled).
    pub rounds_throttled: u64,
    /// Number of cleaning rounds skipped because the cleaner was
    /// inactive (above high watermark).
    pub rounds_inactive: u64,
    /// Number of cleaning rounds that returned an error.
    pub rounds_errored: u64,
    /// Total segments retired across all completed rounds.
    pub total_segments_retired: u64,
    /// Total protected keys preserved across all completed rounds.
    pub total_protected_keys: u64,
    /// Total I/O bytes consumed through the rate limiter.
    pub total_io_bytes: u64,
    /// Total I/O ops consumed through the rate limiter.
    pub total_io_ops: u64,
    /// Number of times the rate limiter refused tokens.
    pub throttle_rejections: u64,
    /// Most recent free segment count observed.
    pub last_free_segments: u64,
    /// Most recent total segment count observed.
    pub last_total_segments: u64,
    /// Whether the cleaner is currently active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// BackgroundCleaner
// ---------------------------------------------------------------------------

/// Background segment cleaner driven by the watermark-based
/// [`CleanerScheduler`] and governed by a [`RateLimiter`].
pub struct BackgroundCleaner {
    config: BackgroundCleanerConfig,
    scheduler: CleanerScheduler,
    rate_limiter: RateLimiter,
    active: bool,
    stats: BackgroundCleanerStats,
}

impl std::fmt::Debug for BackgroundCleaner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundCleaner")
            .field("active", &self.active)
            .field("stats", &self.stats)
            .field("config", &self.config)
            .finish()
    }
}

impl BackgroundCleaner {
    /// Create a new background cleaner with the given config.
    #[must_use]
    pub fn new(config: BackgroundCleanerConfig) -> Self {
        let scheduler = CleanerScheduler::new(config.watermarks);
        let rate_limiter = RateLimiter::new(config.max_bytes_per_sec, config.max_iops);
        Self {
            config,
            scheduler,
            rate_limiter,
            active: false,
            stats: BackgroundCleanerStats::default(),
        }
    }

    /// Run one tick of the background cleaner.
    ///
    /// Call from [`crate::LocalFileSystem::tick_background_services`]
    /// after each commit.
    pub fn tick(&mut self, store: &mut Pool) {
        if !self.config.enabled {
            return;
        }

        // ── 1. Read current free/total segment counts ─────────────
        let store_stats = store.store_stats();
        let free_segments = store_stats.free_segments;
        let total_segments = store_stats.segment_count as u64;

        self.stats.last_free_segments = free_segments;
        self.stats.last_total_segments = total_segments;

        // ── 2. Evaluate cleaner action ────────────────────────────
        let action = self.scheduler.evaluate(free_segments);

        match action {
            CleanerAction::BlockWriters | CleanerAction::StartBackground => {
                self.active = true;
            }
            CleanerAction::Stop => {
                self.active = false;
                self.stats.rounds_inactive += 1;
                return;
            }
            CleanerAction::NoChange => {
                // Stay in current state.
            }
        }
        self.stats.active = self.active;

        if !self.active {
            self.stats.rounds_inactive += 1;
            return;
        }

        // ── 3. Rate-limit check ───────────────────────────────────
        // Each cleaning round counts as 1 op with a minimal byte
        // footprint.  Set max_bytes_per_sec=0 for unlimited bytes;
        // set max_iops to control cleaning frequency.
        // When both limits are zero the limiter never throttles.
        if !self.rate_limiter.try_consume(1, 1) {
            self.stats.rounds_throttled += 1;
            return;
        }
        self.stats.throttle_rejections = self.rate_limiter.throttled_count();
        self.stats.total_io_bytes = self.rate_limiter.total_bytes();
        self.stats.total_io_ops = self.rate_limiter.total_ops();

        // ── 4. Run cleaning round ─────────────────────────────────
        self.stats.rounds_attempted += 1;
        match journal_cleaner::clean_oldest_segment(store) {
            Ok(report) => {
                self.stats.rounds_completed += 1;
                self.stats.total_segments_retired += report.retired_segments.len() as u64;
                self.stats.total_protected_keys += report.protected_key_count as u64;

                if !report.retired_segments.is_empty() {
                    eprintln!(
                        "background-cleaner: retired {} segments, protected {} keys, free={}/{}",
                        report.retired_segments.len(),
                        report.protected_key_count,
                        free_segments,
                        total_segments,
                    );
                }
            }
            Err(e) => {
                self.stats.rounds_errored += 1;
                eprintln!("background-cleaner: cleaning round failed: {e}");
            }
        }
    }

    /// Manually activate the cleaner (e.g. operator request).
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Manually deactivate the cleaner.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the cleaner is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Current cleaner statistics.
    #[must_use]
    pub fn stats(&self) -> &BackgroundCleanerStats {
        &self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = BackgroundCleanerStats::default();
        self.rate_limiter.reset_stats();
    }

    /// The configured watermarks.
    #[must_use]
    pub fn watermarks(&self) -> &CleanerWatermarks {
        self.scheduler.watermarks()
    }

    /// The rate limiter for external observability.
    #[must_use]
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::{
        DeviceConfig, DeviceIoClass, DeviceKind, ObjectKey, Pool, PoolConfig, PoolProperties,
        StoreOptions,
    };

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-bgcleaner-{ts}-{label}"))
    }

    fn test_pool(root: &std::path::Path) -> Pool {
        let data_dir = root.join("data");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                path: data_dir.clone(),
                media_class: Default::default(),
                class: tidefs_local_object_store::DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        };
        Pool::create(
            config,
            PoolProperties::default(),
            &StoreOptions::test_fast(),
        )
        .unwrap()
    }

    #[test]
    fn cleaner_noop_when_disabled() {
        let root = temp_dir("disabled");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        let config = BackgroundCleanerConfig::disabled();
        let mut cleaner = BackgroundCleaner::new(config);
        cleaner.tick(&mut pool);
        // Disabled cleaner should never attempt a round.
        assert_eq!(cleaner.stats().rounds_attempted, 0);
        assert!(!cleaner.is_active());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleaner_activates_when_below_target() {
        let root = temp_dir("activate");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        // Use watermarks that will trigger at nearly-full pool.
        let watermarks = CleanerWatermarks {
            min_free_segments: 1,
            target_free_segments: u64::MAX, // always below target
            high_free_segments: u64::MAX,
            tail_reserved_segments: 1,
        };
        let config = BackgroundCleanerConfig {
            enabled: true,
            watermarks,
            max_bytes_per_sec: 0, // unlimited for test
            max_iops: 0,
        };
        let mut cleaner = BackgroundCleaner::new(config);
        cleaner.tick(&mut pool);
        // Should have attempted a round (active because below target).
        assert!(cleaner.stats().rounds_attempted >= 1);
        assert!(cleaner.is_active());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleaner_stops_when_above_high_watermark() {
        let root = temp_dir("stop");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        // Set high_free to 0 so any free segments > 0 triggers Stop.
        let watermarks = CleanerWatermarks {
            min_free_segments: 0,
            target_free_segments: 0,
            high_free_segments: 0,
            tail_reserved_segments: 0,
        };
        let config = BackgroundCleanerConfig {
            enabled: true,
            watermarks,
            max_bytes_per_sec: 0,
            max_iops: 0,
        };
        let mut cleaner = BackgroundCleaner::new(config);
        cleaner.tick(&mut pool);
        // Cleaner should be inactive (Stop action).
        assert!(!cleaner.is_active());
        assert!(cleaner.stats().rounds_attempted == 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleaner_idempotent_across_multiple_ticks() {
        let root = temp_dir("idempotent");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        // Write a few objects so cleaner has something to protect.
        for i in 0..5u8 {
            pool.put(DeviceIoClass::Data, ObjectKey::from_name([i; 1]), &[i; 64])
                .unwrap();
        }

        let watermarks = CleanerWatermarks {
            min_free_segments: 1,
            target_free_segments: u64::MAX,
            high_free_segments: u64::MAX,
            tail_reserved_segments: 1,
        };
        let config = BackgroundCleanerConfig {
            enabled: true,
            watermarks,
            max_bytes_per_sec: 0,
            max_iops: 0,
        };
        let mut cleaner = BackgroundCleaner::new(config);

        // First tick.
        cleaner.tick(&mut pool);
        let after_first = cleaner.stats().rounds_attempted;
        assert!(after_first >= 1);

        // Second tick — should still work (idempotent cleaning).
        cleaner.tick(&mut pool);
        let after_second = cleaner.stats().rounds_attempted;
        assert!(after_second >= after_first);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleaner_stats_are_cumulative() {
        let root = temp_dir("stats");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        let watermarks = CleanerWatermarks {
            min_free_segments: 1,
            target_free_segments: u64::MAX,
            high_free_segments: u64::MAX,
            tail_reserved_segments: 1,
        };
        let config = BackgroundCleanerConfig {
            enabled: true,
            watermarks,
            max_bytes_per_sec: 0,
            max_iops: 0,
        };
        let mut cleaner = BackgroundCleaner::new(config);

        cleaner.tick(&mut pool);
        cleaner.tick(&mut pool);

        let stats = cleaner.stats();
        assert!(stats.rounds_attempted >= 2);
        assert_eq!(stats.rounds_errored, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleaner_manual_activate_deactivate() {
        let root = temp_dir("manual");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        let config = BackgroundCleanerConfig {
            enabled: true,
            watermarks: CleanerWatermarks {
                min_free_segments: 0,
                target_free_segments: 0,
                high_free_segments: 0,
                tail_reserved_segments: 0,
            },
            max_bytes_per_sec: 0,
            max_iops: 0,
        };
        let mut cleaner = BackgroundCleaner::new(config);

        // Initially inactive because Stop action fires.
        cleaner.tick(&mut pool);
        assert!(!cleaner.is_active());

        // Manual activate.
        cleaner.activate();
        assert!(cleaner.is_active());
        cleaner.tick(&mut pool);
        assert!(cleaner.is_active());

        // Manual deactivate.
        cleaner.deactivate();
        assert!(!cleaner.is_active());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleaner_reset_stats_zeroes_counters() {
        let root = temp_dir("reset");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        let config = BackgroundCleanerConfig {
            enabled: true,
            watermarks: CleanerWatermarks {
                min_free_segments: 1,
                target_free_segments: u64::MAX,
                high_free_segments: u64::MAX,
                tail_reserved_segments: 1,
            },
            max_bytes_per_sec: 0,
            max_iops: 0,
        };
        let mut cleaner = BackgroundCleaner::new(config);

        cleaner.tick(&mut pool);
        assert!(cleaner.stats().rounds_attempted > 0);

        cleaner.reset_stats();
        assert_eq!(cleaner.stats().rounds_attempted, 0);
        assert_eq!(cleaner.stats().rounds_completed, 0);
        assert_eq!(cleaner.stats().total_segments_retired, 0);

        let _ = std::fs::remove_dir_all(&root);
    }
}
