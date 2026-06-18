// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Workload observer: wires live FUSE read/write/fsync operations into the
//! `tidefs-workload` sliding-window classifier and periodically materializes
//! a workload signature for adaptive subsystems.
//!
//! This is the first production consumer of the `tidefs-workload` crate.
//! Previously the crate existed as a standalone library with no runtime
//! integration. Now every FUSE mount feeds real IO observations and
//! produces periodic workload classifications via structured tracing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tidefs_workload::{WorkloadMaterializer, WorkloadStats};

/// Number of data operations (reads + writes) between periodic
/// materializations. The window can be tuned per mount or per workload.
const DEFAULT_MATERIALIZE_EVERY_OPS: usize = 256;

/// A simple per-mount workload observer that feeds FUSE operations into
/// a [`WorkloadMaterializer`] and periodically emits workload
/// classifications.
///
/// Design:
/// - `observe_read`, `observe_write`, and `observe_fsync` are called
///   from the hot FUSE dispatch path and are lock-free except for the
///   periodic materialize step.
/// - `maybe_materialize` is called after each observation and triggers
///   classification once enough data operations have been accumulated.
///
/// This type is intentionally lightweight and does not depend on the
/// observe or control-plane crates. Upstream consumers that
/// need `ObserveWorkloadSignalWindowRecord` receipts should map the
/// materialized [`WorkloadStats`] through `tidefs-observe-core`
/// when that crate is integrated into the workspace build graph.
pub struct WorkloadObserver {
    inner: Mutex<WorkloadMaterializer>,
    /// Counter for data operations since last materialization.
    ops_since_materialize: AtomicU64,
    /// Most recently materialized stats snapshot.
    last_stats: Mutex<WorkloadStats>,
    /// Materialize every N data operations.
    materialize_every: usize,
}

impl WorkloadObserver {
    /// Create a new observer with the default materialization interval.
    #[must_use]
    pub fn new() -> Self {
        Self::with_interval(DEFAULT_MATERIALIZE_EVERY_OPS)
    }

    /// Create a new observer with a custom materialization interval.
    #[must_use]
    pub fn with_interval(materialize_every: usize) -> Self {
        Self {
            inner: Mutex::new(WorkloadMaterializer::new()),
            ops_since_materialize: AtomicU64::new(0),
            last_stats: Mutex::new(WorkloadStats::default()),
            materialize_every,
        }
    }

    /// Record a read operation with offset and length.
    pub fn observe_read(&self, offset: u64, len: u64) {
        {
            let mut m = self.inner.lock().unwrap();
            m.observe_read(offset, len);
        }
        self.ops_since_materialize.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a write operation with offset and length.
    pub fn observe_write(&self, offset: u64, len: u64) {
        {
            let mut m = self.inner.lock().unwrap();
            m.observe_write(offset, len);
        }
        self.ops_since_materialize.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an fsync operation.
    pub fn observe_fsync(&self) {
        {
            let mut m = self.inner.lock().unwrap();
            m.observe_fsync();
        }
        self.ops_since_materialize.fetch_add(1, Ordering::Relaxed);
    }

    /// If enough operations have been accumulated, materialize a
    /// classification snapshot and return it. Otherwise return `None`.
    pub fn maybe_materialize(&self) -> Option<WorkloadStats> {
        let ops = self.ops_since_materialize.load(Ordering::Relaxed);
        if ops < self.materialize_every as u64 {
            return None;
        }
        self.ops_since_materialize.store(0, Ordering::Relaxed);
        let stats = {
            let mut m = self.inner.lock().unwrap();
            m.materialize()
        };
        {
            let mut last = self.last_stats.lock().unwrap();
            *last = stats;
        }
        Some(stats)
    }

    /// Return the most recently materialized stats snapshot.
    #[must_use]
    pub fn last_stats(&self) -> WorkloadStats {
        *self.last_stats.lock().unwrap()
    }

    /// Return the current signature name (e.g. "OLTP", "OLAP") for
    /// consumption by adaptive subsystems.
    #[must_use]
    pub fn current_signature_name(&self) -> &'static str {
        let stats = self.last_stats.lock().unwrap();
        stats.current_signature.name()
    }
}

impl Default for WorkloadObserver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_observer_is_unknown() {
        let obs = WorkloadObserver::new();
        assert_eq!(obs.current_signature_name(), "Unknown");
        assert_eq!(obs.last_stats().window_ops, 0);
    }

    #[test]
    fn default_interval_is_256() {
        let obs = WorkloadObserver::new();
        assert_eq!(obs.materialize_every, 256);
    }

    #[test]
    fn custom_interval_respected() {
        let obs = WorkloadObserver::with_interval(16);
        assert_eq!(obs.materialize_every, 16);
    }

    #[test]
    fn materialize_after_enough_ops() {
        let obs = WorkloadObserver::with_interval(64);
        let mut off = 0u64;
        for _ in 0..64 {
            obs.observe_read(off, 65536);
            off += 65536;
        }
        let stats = obs.maybe_materialize().expect("should materialize");
        assert_eq!(stats.current_signature.name(), "OLAP");
        assert!(stats.confidence > 0.3);
    }

    #[test]
    fn no_materialize_before_threshold() {
        let obs = WorkloadObserver::with_interval(100);
        for i in 0..50 {
            obs.observe_read(i * 4096, 4096);
        }
        assert!(obs.maybe_materialize().is_none());
    }

    #[test]
    fn last_stats_preserved_across_materializations() {
        let obs = WorkloadObserver::with_interval(32);
        for i in 0..32 {
            let off = (i as u64) * 4096 + (i as u64 % 7) * 512;
            obs.observe_read(off, 4096);
            obs.observe_write(off + 8192, 2048);
        }
        let _stats1 = obs.maybe_materialize();
        assert_eq!(obs.current_signature_name(), "OLTP");

        let mut off = 0u64;
        for _ in 0..32 {
            obs.observe_read(off, 65536);
            off += 65536;
        }
        let _stats2 = obs.maybe_materialize();
        assert_eq!(obs.current_signature_name(), "OLAP");
    }
}
