//! Materialized workload-signature cache: a concrete precomputed-view
//! consumer that holds the most recent workload classification with a
//! configurable TTL and exposes it for adaptive subsystem tuning.
//!
//! This is the first materialized-view consumer wired behind the
//! workload observer. Subsystems (page cache, readahead, prefetch,
//! recordsize, ARC) query the cache instead of re-classifying IO
//! patterns internally.
//!
//! Policy:
//! - Build: the cache is refreshed when the WorkloadObserver materializes.
//! - Reclaim: entries expire after a configurable TTL (default 30s).
//!   Expired entries return Unknown, so consumers degrade gracefully.
//! - Budget: a simple capacity of 1 entry per mount; no persistent
//!   budget tracking yet.

use std::sync::Mutex;
use std::time::Instant;
use tidefs_workload::{WorkloadSignature, WorkloadStats};

/// A cached workload classification that expires after a TTL.
///
/// When the TTL expires, queries return `WorkloadSignature::Unknown`
/// (transparent reclaim). The cache is refreshed by the
/// [`WorkloadObserver`](crate::workload_observer::WorkloadObserver)
/// each time it materializes a new window.
pub struct MaterializedSignatureCache {
    inner: Mutex<CachedEntry>,
    /// Time-to-live for cached signatures.
    ttl: std::time::Duration,
}

#[derive(Clone, Copy, Debug, Default)]
struct CachedEntry {
    stats: WorkloadStats,
    materialized_at: Option<Instant>,
    reclaimed: bool,
}

impl MaterializedSignatureCache {
    /// Default TTL for cached signatures (30 seconds).
    pub const DEFAULT_TTL_SECS: u64 = 30;

    /// Create a new cache with the default TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(std::time::Duration::from_secs(Self::DEFAULT_TTL_SECS))
    }

    /// Create a new cache with a custom TTL.
    #[must_use]
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self {
            inner: Mutex::new(CachedEntry::default()),
            ttl,
        }
    }

    /// Refresh the cache with newly materialized stats.
    ///
    /// Called by the workload observer when it materializes a window.
    pub fn refresh(&self, stats: WorkloadStats) {
        let mut entry = self.inner.lock().unwrap();
        entry.stats = stats;
        let prev_signature = entry.stats.current_signature;
        entry.stats = stats;
        entry.materialized_at = Some(Instant::now());
        entry.reclaimed = false;
        drop(entry);
        tracing::info!(
            prev_signature = prev_signature.name(),
            new_signature = stats.current_signature.name(),
            confidence = stats.confidence,
            window_ops = stats.window_ops,
            reads = stats.reads,
            writes = stats.writes,
            fsyncs = stats.fsyncs,
            "materialized_view_build"
        );
    }

    /// Return the current workload signature, or Unknown if expired.
    #[must_use]
    pub fn current_signature(&self) -> WorkloadSignature {
        let mut entry = self.inner.lock().unwrap();
        match entry.materialized_at {
            Some(at) if at.elapsed() < self.ttl => entry.stats.current_signature,
            _ => {
                if !entry.reclaimed {
                    entry.reclaimed = true;
                    let sig = entry.stats.current_signature;
                    let age = entry.materialized_at.map(|at| at.elapsed());
                    let confidence = entry.stats.confidence;
                    drop(entry);
                    tracing::info!(
                        signature = sig.name(),
                        age_secs = age.map(|d| d.as_secs_f64()).unwrap_or(0.0),
                        prev_confidence = confidence,
                        "materialized_view_reclaim"
                    );
                }
                WorkloadSignature::Unknown
            }
        }
    }

    /// Return the current confidence, or 0.0 if expired.
    #[must_use]
    pub fn current_confidence(&self) -> f64 {
        let entry = self.inner.lock().unwrap();
        match entry.materialized_at {
            Some(at) if at.elapsed() < self.ttl => entry.stats.confidence,
            _ => 0.0,
        }
    }

    /// Return the full stats if not expired, otherwise default stats.
    #[must_use]
    pub fn current_stats(&self) -> WorkloadStats {
        let entry = self.inner.lock().unwrap();
        match entry.materialized_at {
            Some(at) if at.elapsed() < self.ttl => entry.stats,
            _ => WorkloadStats::default(),
        }
    }

    /// Return the age of the cached entry, if any.
    #[must_use]
    pub fn age(&self) -> Option<std::time::Duration> {
        self.inner
            .lock()
            .unwrap()
            .materialized_at
            .map(|at| at.elapsed())
    }

    /// Return true if the cache has a live (non-expired) entry.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.current_signature() != WorkloadSignature::Unknown || self.current_confidence() > 0.0
    }

    /// Return the recommended readahead page count based on the
    /// current workload signature.
    ///
    /// This is the first concrete consumer of the materialized view:
    /// the page-cache and FUSE read dispatcher can query this instead
    /// of using a fixed readahead window.
    #[must_use]
    pub fn readahead_pages(&self) -> usize {
        match self.current_signature() {
            WorkloadSignature::Oltp => 1,    // Small random IO: don't waste cache
            WorkloadSignature::Olap => 16,   // Analytics queries: aggressive prefetch
            WorkloadSignature::Backup => 4,  // Sequential writes: moderate
            WorkloadSignature::Media => 16,  // Streaming reads: aggressive prefetch
            WorkloadSignature::Vm => 4,      // Mixed with fsync: moderate
            WorkloadSignature::Unknown => 4, // Default: moderate
        }
    }
}

impl Default for MaterializedSignatureCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cache_is_unknown() {
        let cache = MaterializedSignatureCache::new();
        assert_eq!(cache.current_signature(), WorkloadSignature::Unknown);
        assert!(!cache.is_live());
    }

    #[test]
    fn refresh_updates_signature() {
        let cache = MaterializedSignatureCache::new();
        let stats = WorkloadStats {
            current_signature: WorkloadSignature::Olap,
            confidence: 0.85,
            window_ops: 256,
            reads: 200,
            writes: 50,
            fsyncs: 6,
            read_bytes: 13_107_200,
            write_bytes: 3_276_800,
            sequential_runs: 1,
            random_ops: 10,
        };
        cache.refresh(stats);
        assert_eq!(cache.current_signature(), WorkloadSignature::Olap);
        assert!(cache.is_live());
    }

    #[test]
    fn expiration_returns_unknown() {
        let cache = MaterializedSignatureCache::with_ttl(std::time::Duration::from_millis(1));
        let stats = WorkloadStats {
            current_signature: WorkloadSignature::Oltp,
            confidence: 0.72,
            ..WorkloadStats::default()
        };
        cache.refresh(stats);
        assert_eq!(cache.current_signature(), WorkloadSignature::Oltp);
        std::thread::sleep(std::time::Duration::from_millis(5));
        // After TTL, signature degrades to Unknown (transparent reclaim)
        assert_eq!(cache.current_signature(), WorkloadSignature::Unknown);
        assert!(!cache.is_live());
    }

    #[test]
    fn readahead_pages_by_signature() {
        let cache = MaterializedSignatureCache::new();

        let stats_oltp = WorkloadStats {
            current_signature: WorkloadSignature::Oltp,
            confidence: 0.80,
            ..WorkloadStats::default()
        };
        cache.refresh(stats_oltp);
        assert_eq!(cache.readahead_pages(), 1);

        let stats_olap = WorkloadStats {
            current_signature: WorkloadSignature::Olap,
            confidence: 0.85,
            ..WorkloadStats::default()
        };
        cache.refresh(stats_olap);
        assert_eq!(cache.readahead_pages(), 16);

        let stats_vm = WorkloadStats {
            current_signature: WorkloadSignature::Vm,
            confidence: 0.60,
            ..WorkloadStats::default()
        };
        cache.refresh(stats_vm);
        assert_eq!(cache.readahead_pages(), 4);
    }

    #[test]
    fn age_reported_correctly() {
        let cache = MaterializedSignatureCache::new();
        assert!(cache.age().is_none());

        cache.refresh(WorkloadStats {
            current_signature: WorkloadSignature::Backup,
            confidence: 0.90,
            ..WorkloadStats::default()
        });
        let age = cache.age().expect("should have age");
        assert!(age.as_millis() < 100);
    }
}
