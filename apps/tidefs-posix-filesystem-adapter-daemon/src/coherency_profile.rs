// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(non_local_definitions)]
//! Named coherency profiles for FUSE daemon caching semantics.
//!
//! Each profile bundles cache timeouts, invalidation strategy, and durability
//! behaviour into a single meaningful name. Operators select a profile per
//! mount or per dataset rather than tuning individual FUSE TTL knobs.
//!
//! Profiles:
//! - `Strict`:   POSIX-exact; every read checks authority, every write
//!   invalidates immediately. No kernel caching. (NFS-level consistency).
//! - `Writeback`: Writes cached locally, flushed on fsync/txg commit. Reads
//!   check authority if cache entry > TTL. Default for single-node.
//! - `Nearline`:  Aggressive local caching with background invalidation feed.
//!   For read-heavy workloads with occasional writes.
//! - `Async`:     Local cache with lazy invalidation. Suitable for datasets
//!   rarely modified by other nodes.
//! - `Offline`:   Full local cache, no invalidation. Suitable for read-only
//!   or single-writer datasets.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

// ── CoherencyProfile ──────────────────────────────────────────────────────

/// Named coherency profile for the FUSE daemon.
///
/// Each variant bundles caching, invalidation, and durability behaviour
/// into a single meaningful name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[derive(Default)]
pub enum CoherencyProfile {
    /// Every read checks authority, every write invalidates immediately.
    /// No kernel caching (attr_timeout=0, entry_timeout=0, no writeback cache).
    /// Target: NFS-level consistency, POSIX-exact behaviour.
    Strict = 0,
    /// Writes cached locally, flushed on fsync/txg commit.
    /// Reads check authority if cache entry exceeds TTL.
    /// Default for single-node deployments.
    #[default]
    Writeback = 1,
    /// Aggressive local caching with background invalidation feed.
    /// For read-heavy workloads with occasional writes.
    Nearline = 2,
    /// Local cache with lazy invalidation.
    /// Suitable for datasets rarely modified by other nodes.
    Async = 3,
    /// Full local cache, no invalidation.
    /// Suitable for read-only or single-writer datasets.
    Offline = 4,
}

impl CoherencyProfile {
    /// Human-readable name for logging and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            CoherencyProfile::Strict => "strict",
            CoherencyProfile::Writeback => "writeback",
            CoherencyProfile::Nearline => "nearline",
            CoherencyProfile::Async => "async",
            CoherencyProfile::Offline => "offline",
        }
    }

    /// Return the caching parameters for this profile.
    pub fn params(self) -> CoherencyProfileParams {
        match self {
            CoherencyProfile::Strict => CoherencyProfileParams {
                attr_ttl: Duration::ZERO,
                entry_ttl: Duration::ZERO,
                negative_ttl: Duration::ZERO,
                kernel_writeback: false,
                invalidation: InvalidationPolicy::Immediate,
            },
            CoherencyProfile::Writeback => CoherencyProfileParams {
                attr_ttl: Duration::from_secs(5),
                entry_ttl: Duration::from_secs(5),
                negative_ttl: Duration::from_millis(250),
                kernel_writeback: true,
                invalidation: InvalidationPolicy::OnWrite,
            },
            CoherencyProfile::Nearline => CoherencyProfileParams {
                attr_ttl: Duration::from_secs(5),
                entry_ttl: Duration::from_secs(5),
                negative_ttl: Duration::from_secs(5),
                kernel_writeback: true,
                invalidation: InvalidationPolicy::TtlBased,
            },
            CoherencyProfile::Async => CoherencyProfileParams {
                attr_ttl: Duration::from_secs(10),
                entry_ttl: Duration::from_secs(10),
                negative_ttl: Duration::from_secs(5),
                kernel_writeback: true,
                invalidation: InvalidationPolicy::Lazy,
            },
            CoherencyProfile::Offline => CoherencyProfileParams {
                attr_ttl: Duration::from_secs(60),
                entry_ttl: Duration::from_secs(60),
                negative_ttl: Duration::from_secs(30),
                kernel_writeback: true,
                invalidation: InvalidationPolicy::None,
            },
        }
    }

    /// When to send FUSE_NOTIFY_INVAL_INODE / FUSE_NOTIFY_INVAL_ENTRY.
    pub fn invalidation_policy(self) -> InvalidationPolicy {
        self.params().invalidation
    }

    /// Whether the kernel writeback cache is enabled for this profile.
    pub fn kernel_writeback_enabled(self) -> bool {
        self.params().kernel_writeback
    }
}

impl FromStr for CoherencyProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "strict" => Ok(CoherencyProfile::Strict),
            "writeback" => Ok(CoherencyProfile::Writeback),
            "nearline" => Ok(CoherencyProfile::Nearline),
            "async" => Ok(CoherencyProfile::Async),
            "offline" => Ok(CoherencyProfile::Offline),
            other => Err(format!(
                "unknown coherency profile `{other}`; expected one of: strict, writeback, nearline, async, offline"
            )),
        }
    }
}

impl fmt::Display for CoherencyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── CoherencyProfileParams ────────────────────────────────────────────────

/// Caching parameters derived from a [`CoherencyProfile`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoherencyProfileParams {
    /// Attribute cache TTL (reported in ReplyAttr and ReplyEntry).
    pub attr_ttl: Duration,
    /// Entry cache TTL (reported in ReplyEntry for directory entries).
    pub entry_ttl: Duration,
    /// Negative cache TTL (for ENOENT responses).
    pub negative_ttl: Duration,
    /// Whether the kernel writeback cache (FUSE writeback_cache) is enabled.
    pub kernel_writeback: bool,
    /// Invalidation strategy: when cached data is invalidated.
    pub invalidation: InvalidationPolicy,
}

// ── InvalidationPolicy ────────────────────────────────────────────────────

/// When the daemon should send FUSE invalidation notifications to the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationPolicy {
    /// Invalidate on every write: send NOTIFY_INVAL_INODE immediately after
    /// any write to the inode, and NOTIFY_INVAL_ENTRY after any namespace
    /// mutation affecting the entry.
    Immediate,
    /// Invalidate when a write is committed (on fsync / txg commit).
    OnWrite,
    /// Invalidate when cache entry exceeds its TTL.
    TtlBased,
    /// Lazy invalidation: invalidate only when the daemon receives an
    /// explicit invalidation signal (e.g., from cluster feed).
    Lazy,
    /// No invalidation: never send invalidation notifications.
    None,
}

// ── CoherencyProfileStats ─────────────────────────────────────────────────

/// Runtime statistics for coherency profile invalidation activity.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct CoherencyProfileStats {
    /// Number of FUSE_NOTIFY_INVAL_INODE / FUSE_NOTIFY_INVAL_ENTRY sent.
    pub inval_notify_sent: u64,
    /// Number of invalidation notifications dropped (e.g. channel full).
    pub inval_notify_dropped: u64,
    /// Approximate cache hit rate (hits / total lookups) as a fraction 0..1.
    /// Updated by the lookup path; -1.0 means no data yet.
    pub cache_hit_rate: f64,
    /// Number of times a stale cache entry was detected (served stale data).
    pub staleness_events: u64,
}
#[allow(dead_code)]
impl CoherencyProfileStats {
    /// Record a successful invalidation notification.
    pub fn record_inval_sent(&mut self) {
        self.inval_notify_sent = self.inval_notify_sent.saturating_add(1);
    }

    /// Record a dropped invalidation notification.
    pub fn record_inval_dropped(&mut self) {
        self.inval_notify_dropped = self.inval_notify_dropped.saturating_add(1);
    }

    /// Update the cache hit rate with a new (hits, total) pair.
    /// Panics if total is 0.
    pub fn record_cache_stats(&mut self, hits: u64, total: u64) {
        assert!(total > 0, "total lookups must be > 0");
        self.cache_hit_rate = (hits as f64) / (total as f64);
    }

    /// Record a staleness event.
    pub fn record_staleness(&mut self) {
        self.staleness_events = self.staleness_events.saturating_add(1);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_params() {
        let p = CoherencyProfile::Strict.params();
        assert_eq!(p.attr_ttl, Duration::ZERO);
        assert_eq!(p.entry_ttl, Duration::ZERO);
        assert_eq!(p.negative_ttl, Duration::ZERO);
        assert!(!p.kernel_writeback);
        assert_eq!(p.invalidation, InvalidationPolicy::Immediate);
    }

    #[test]
    fn writeback_profile_params() {
        let p = CoherencyProfile::Writeback.params();
        assert_eq!(p.attr_ttl, Duration::from_secs(5));
        assert_eq!(p.entry_ttl, Duration::from_secs(5));
        assert_eq!(p.negative_ttl, Duration::from_millis(250));
        assert!(p.kernel_writeback);
        assert_eq!(p.invalidation, InvalidationPolicy::OnWrite);
    }

    #[test]
    fn nearline_profile_params() {
        let p = CoherencyProfile::Nearline.params();
        assert_eq!(p.attr_ttl, Duration::from_secs(5));
        assert_eq!(p.entry_ttl, Duration::from_secs(5));
        assert!(p.kernel_writeback);
        assert_eq!(p.invalidation, InvalidationPolicy::TtlBased);
    }

    #[test]
    fn async_profile_params() {
        let p = CoherencyProfile::Async.params();
        assert_eq!(p.attr_ttl, Duration::from_secs(10));
        assert_eq!(p.entry_ttl, Duration::from_secs(10));
        assert_eq!(p.negative_ttl, Duration::from_secs(5));
        assert!(p.kernel_writeback);
        assert_eq!(p.invalidation, InvalidationPolicy::Lazy);
    }

    #[test]
    fn offline_profile_params() {
        let p = CoherencyProfile::Offline.params();
        assert_eq!(p.attr_ttl, Duration::from_secs(60));
        assert_eq!(p.entry_ttl, Duration::from_secs(60));
        assert_eq!(p.negative_ttl, Duration::from_secs(30));
        assert!(p.kernel_writeback);
        assert_eq!(p.invalidation, InvalidationPolicy::None);
    }

    #[test]
    fn default_is_writeback() {
        assert_eq!(CoherencyProfile::default(), CoherencyProfile::Writeback);
    }

    #[test]
    fn from_str_valid() {
        assert_eq!("strict".parse(), Ok(CoherencyProfile::Strict));
        assert_eq!("writeback".parse(), Ok(CoherencyProfile::Writeback));
        assert_eq!("nearline".parse(), Ok(CoherencyProfile::Nearline));
        assert_eq!("async".parse(), Ok(CoherencyProfile::Async));
        assert_eq!("offline".parse(), Ok(CoherencyProfile::Offline));
        // Case-insensitive
        assert_eq!("STRICT".parse(), Ok(CoherencyProfile::Strict));
        assert_eq!("Writeback".parse(), Ok(CoherencyProfile::Writeback));
    }

    #[test]
    fn from_str_invalid() {
        assert!("invalid".parse::<CoherencyProfile>().is_err());
    }

    #[test]
    fn as_str_roundtrip() {
        for profile in &[
            CoherencyProfile::Strict,
            CoherencyProfile::Writeback,
            CoherencyProfile::Nearline,
            CoherencyProfile::Async,
            CoherencyProfile::Offline,
        ] {
            let s = profile.as_str();
            let parsed: CoherencyProfile = s.parse().unwrap();
            assert_eq!(*profile, parsed);
        }
    }

    #[test]
    fn invalidation_policy_matches_params() {
        for profile in &[
            CoherencyProfile::Strict,
            CoherencyProfile::Writeback,
            CoherencyProfile::Nearline,
            CoherencyProfile::Async,
            CoherencyProfile::Offline,
        ] {
            assert_eq!(profile.invalidation_policy(), profile.params().invalidation);
        }
    }

    #[test]
    fn stats_default() {
        let stats = CoherencyProfileStats::default();
        assert_eq!(stats.inval_notify_sent, 0);
        assert_eq!(stats.inval_notify_dropped, 0);
        assert_eq!(stats.cache_hit_rate, 0.0);
        assert_eq!(stats.staleness_events, 0);
    }

    #[test]
    fn stats_record_inval() {
        let mut stats = CoherencyProfileStats::default();
        stats.record_inval_sent();
        stats.record_inval_sent();
        stats.record_inval_dropped();
        assert_eq!(stats.inval_notify_sent, 2);
        assert_eq!(stats.inval_notify_dropped, 1);
    }

    #[test]
    fn stats_cache_hit_rate() {
        let mut stats = CoherencyProfileStats::default();
        stats.record_cache_stats(75, 100);
        assert!((stats.cache_hit_rate - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn stats_staleness() {
        let mut stats = CoherencyProfileStats::default();
        stats.record_staleness();
        stats.record_staleness();
        assert_eq!(stats.staleness_events, 2);
    }

    #[test]
    fn strict_zero_ttls() {
        // Strict profile must use zero TTLs so the kernel never caches.
        let p = CoherencyProfile::Strict.params();
        assert_eq!(p.attr_ttl, Duration::ZERO);
        assert_eq!(p.entry_ttl, Duration::ZERO);
        assert_eq!(p.negative_ttl, Duration::ZERO);
    }

    #[test]
    fn profile_kernel_writeback() {
        assert!(!CoherencyProfile::Strict.kernel_writeback_enabled());
        assert!(CoherencyProfile::Writeback.kernel_writeback_enabled());
        assert!(CoherencyProfile::Nearline.kernel_writeback_enabled());
        assert!(CoherencyProfile::Async.kernel_writeback_enabled());
        assert!(CoherencyProfile::Offline.kernel_writeback_enabled());
    }
}
