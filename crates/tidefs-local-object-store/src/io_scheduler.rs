// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Token-bucket I/O scheduler with per-class admission control.
//!
//! The [`IoScheduler`] implements the ZFS I/O scheduler principle: partition
//! operations into priority classes so bulk I/O (scrub, async writes) never
//! starves latency-sensitive operations (metadata, fsync).
//!
//! # I/O classes
//!
//! Four [`IoClass`] lanes are defined, in priority order:
//!
//! 1. [`IoClass::Metadata`] — stat, readdir, inode/directory mutations
//! 2. [`IoClass::SyncData`] — fsync, O_DSYNC writes, intent log commits
//! 3. [`IoClass::AsyncData`] — buffered writes, background compaction
//! 4. [`IoClass::Scrub`] — online integrity verification, rebuild
//!
//! Each class has an independent token bucket with configurable rate and
//! burst. The scheduler can be disabled (always admit) via
//! [`IoSchedulerConfig::disabled`].
//!

use std::collections::BTreeMap;
use std::time::Instant;

/// I/O class for throughput and latency differentiation.
///
/// Without I/O class separation, bulk writes and scrub starve metadata
/// and sync operations — the exact mistake Ceph and early ZFS made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IoClass {
    /// High priority: stat, readdir, inode/directory mutations, quota.
    Metadata = 0,
    /// Interactive priority: sync write intents, fsync, O_DSYNC writes.
    SyncData = 1,
    /// Best-effort: buffered async writes, background compaction.
    AsyncData = 2,
    /// Lowest priority: online scrub, rebuild, backfill.
    Scrub = 3,
}

impl IoClass {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::SyncData => "sync_data",
            Self::AsyncData => "async_data",
            Self::Scrub => "scrub",
        }
    }

    pub const fn priority(self) -> u8 {
        self as u8
    }
}

/// A token-bucket rate limiter. Tokens accumulate at `rate`/s up to `max_tokens`.
/// Each operation consumes one token; when empty, admission is refused.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    rate: f64,
    max_tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            rate,
            max_tokens: burst,
            last_refill: Instant::now(),
        }
    }

    fn consume(&mut self, count: f64) -> bool {
        self.refill();
        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
            self.last_refill = now;
        }
    }

    fn available(&self) -> f64 {
        self.tokens
    }
}

/// Configuration for per-class token buckets.
#[derive(Clone, Debug)]
pub struct IoSchedulerConfig {
    pub metadata_rate: f64,
    pub metadata_burst: f64,
    pub sync_data_rate: f64,
    pub sync_data_burst: f64,
    pub async_data_rate: f64,
    pub async_data_burst: f64,
    pub scrub_rate: f64,
    pub scrub_burst: f64,
}

impl Default for IoSchedulerConfig {
    fn default() -> Self {
        Self {
            metadata_rate: 2000.0,
            metadata_burst: 400.0,
            sync_data_rate: 1000.0,
            sync_data_burst: 200.0,
            async_data_rate: 500.0,
            async_data_burst: 100.0,
            scrub_rate: 100.0,
            scrub_burst: 50.0,
        }
    }
}

impl IoSchedulerConfig {
    pub const fn high_throughput() -> Self {
        Self {
            metadata_rate: 10000.0,
            metadata_burst: 2000.0,
            sync_data_rate: 5000.0,
            sync_data_burst: 1000.0,
            async_data_rate: 2000.0,
            async_data_burst: 500.0,
            scrub_rate: 500.0,
            scrub_burst: 200.0,
        }
    }

    pub const fn spinning_disk() -> Self {
        Self {
            metadata_rate: 200.0,
            metadata_burst: 50.0,
            sync_data_rate: 100.0,
            sync_data_burst: 25.0,
            async_data_rate: 50.0,
            async_data_burst: 10.0,
            scrub_rate: 10.0,
            scrub_burst: 5.0,
        }
    }

    pub const fn disabled() -> Self {
        Self {
            metadata_rate: f64::MAX,
            metadata_burst: f64::MAX,
            sync_data_rate: f64::MAX,
            sync_data_burst: f64::MAX,
            async_data_rate: f64::MAX,
            async_data_burst: f64::MAX,
            scrub_rate: f64::MAX,
            scrub_burst: f64::MAX,
        }
    }
}

/// Per-class token-bucket I/O scheduler.
///
/// Each I/O class has its own token bucket. When a class exhausts its
/// tokens, further operations of that class are refused so higher-priority
/// classes are never starved by bulk I/O (ZFS I/O scheduler principle).
#[derive(Debug)]
pub struct IoScheduler {
    buckets: BTreeMap<IoClass, TokenBucket>,
    enabled: bool,
}

impl IoScheduler {
    pub fn new(config: &IoSchedulerConfig) -> Self {
        let enabled = config.metadata_rate < f64::MAX / 2.0;
        let mut buckets = BTreeMap::new();
        for (class, rate, burst) in [
            (
                IoClass::Metadata,
                config.metadata_rate,
                config.metadata_burst,
            ),
            (
                IoClass::SyncData,
                config.sync_data_rate,
                config.sync_data_burst,
            ),
            (
                IoClass::AsyncData,
                config.async_data_rate,
                config.async_data_burst,
            ),
            (IoClass::Scrub, config.scrub_rate, config.scrub_burst),
        ] {
            buckets.insert(class, TokenBucket::new(rate, burst));
        }
        Self { buckets, enabled }
    }

    /// Check whether an operation of `class` is admitted.
    /// Returns `true` if admitted (token consumed), `false` if the caller
    /// should back off or fall back to a slower path.
    pub fn admit(&mut self, class: IoClass) -> bool {
        if !self.enabled {
            return true;
        }
        self.buckets.get_mut(&class).is_none_or(|b| b.consume(1.0))
    }

    pub fn available_tokens(&self, class: IoClass) -> f64 {
        self.buckets.get(&class).map_or(f64::MAX, |b| b.available())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_consumes_and_depletes() {
        let mut b = TokenBucket::new(10.0, 5.0);
        assert!(b.consume(1.0));
        assert!(b.consume(2.0));
        assert!(b.consume(2.0));
        assert!(!b.consume(1.0));
    }

    #[test]
    fn io_scheduler_per_class_isolation() {
        let cfg = IoSchedulerConfig {
            metadata_rate: 10.0,
            metadata_burst: 3.0,
            sync_data_rate: 10.0,
            sync_data_burst: 3.0,
            async_data_rate: 10.0,
            async_data_burst: 1.0,
            scrub_rate: 10.0,
            scrub_burst: 1.0,
        };
        let mut s = IoScheduler::new(&cfg);
        // Metadata has 3 tokens, async has 1
        assert!(s.admit(IoClass::Metadata));
        assert!(s.admit(IoClass::Metadata));
        assert!(s.admit(IoClass::Metadata));
        assert!(!s.admit(IoClass::Metadata));
        assert!(s.admit(IoClass::SyncData));
        assert!(s.admit(IoClass::AsyncData));
        assert!(!s.admit(IoClass::AsyncData));
        assert!(s.admit(IoClass::Scrub));
        assert!(!s.admit(IoClass::Scrub));
    }

    #[test]
    fn disabled_scheduler_always_admits() {
        let cfg = IoSchedulerConfig::disabled();
        let mut s = IoScheduler::new(&cfg);
        for _ in 0..10000 {
            assert!(s.admit(IoClass::AsyncData));
        }
    }
}
