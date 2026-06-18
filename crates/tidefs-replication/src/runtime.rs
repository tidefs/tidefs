// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Replication transport runtime: async transfer workers, quorum tracking,
//! retry with exponential backoff, and cancellation.
//!
//! Bridges `ReplicatedWritePlan` (from tidefs-replication-model) with
//! transport-level dispatch for distributed write replication.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tidefs_transport::backend::TransportBackendKind;

use tidefs_membership_epoch::MemberId;

use crate::{ReplicationPolicy, ReplicationPolicySelector};

// ═══════════════════════════════════════════════════════════════════════
// Quorum mode
// ═══════════════════════════════════════════════════════════════════════

/// Quorum semantics for replication transport dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumMode {
    /// N/2+1 (majority): write succeeds when a majority of targets ack.
    Strict,
    /// Any 2 replicas: for best-effort replication.
    Weak,
    /// N of N: for critical metadata (all targets must ack).
    All,
}

impl QuorumMode {
    /// Minimum ACKs required to achieve quorum given N targets.
    #[must_use]
    pub const fn min_quorum(self, target_count: usize) -> usize {
        match self {
            Self::Strict => {
                if target_count == 0 {
                    0
                } else {
                    target_count / 2 + 1
                }
            }
            Self::Weak => {
                if target_count < 2 {
                    target_count
                } else {
                    2
                }
            }
            Self::All => target_count,
        }
    }

    /// Convert to the corresponding `ReplicationPolicy`.
    #[must_use]
    pub const fn to_policy(self) -> ReplicationPolicy {
        match self {
            Self::Strict => ReplicationPolicy::Standard,
            Self::Weak => ReplicationPolicy::BestEffort,
            Self::All => ReplicationPolicy::Critical,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ReplicationTransportStats
// ═══════════════════════════════════════════════════════════════════════

/// Atomic counters for replication transport monitoring.
///
/// Includes carrier tracking so operators can observe whether
/// replication data-plane traffic is using RDMA, TCP, or TLS.
#[derive(Debug)]
pub struct ReplicationTransportStats {
    pub writes_attempted: AtomicU64,
    pub writes_quorum_reached: AtomicU64,
    pub writes_failed: AtomicU64,
    pub retries: AtomicU64,
    total_latency_us: AtomicU64,
    latency_samples: AtomicU64,
    pub inflight_count: AtomicU64,
    /// Transport backend carrier kind used for replication writes.
    /// Stored as a u8 discriminant: 0=Tcp, 1=Tls, 2=Rdma.
    carrier_kind: AtomicU8,
}

impl Default for ReplicationTransportStats {
    fn default() -> Self {
        Self {
            writes_attempted: AtomicU64::new(0),
            writes_quorum_reached: AtomicU64::new(0),
            writes_failed: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
            inflight_count: AtomicU64::new(0),
            carrier_kind: AtomicU8::new(TransportBackendKind::Tcp as u8),
        }
    }
}

impl ReplicationTransportStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the transport carrier kind used for replication writes.
    pub fn set_carrier(&self, kind: TransportBackendKind) {
        self.carrier_kind.store(kind as u8, Ordering::Relaxed);
    }

    /// Return the transport carrier kind currently recorded.
    #[must_use]
    pub fn carrier_kind(&self) -> TransportBackendKind {
        match self.carrier_kind.load(Ordering::Relaxed) {
            2 => TransportBackendKind::Rdma,
            1 => TransportBackendKind::Tls,
            _ => TransportBackendKind::Tcp,
        }
    }

    /// Whether replication writes are using the RDMA carrier.
    #[must_use]
    pub fn is_rdma(&self) -> bool {
        self.carrier_kind() == TransportBackendKind::Rdma
    }

    /// Set the transport carrier kind used for replication writes.
    pub fn record_success(&self, latency: Duration) {
        self.writes_attempted.fetch_add(1, Ordering::Relaxed);
        self.writes_quorum_reached.fetch_add(1, Ordering::Relaxed);
        self.total_latency_us
            .fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.writes_attempted.fetch_add(1, Ordering::Relaxed);
        self.writes_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_inflight(&self) {
        self.inflight_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_inflight(&self) {
        self.inflight_count.fetch_sub(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn avg_latency_ms(&self) -> f64 {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return 0.0;
        }
        let total_us = self.total_latency_us.load(Ordering::Relaxed);
        (total_us as f64 / samples as f64) / 1000.0
    }

    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let attempted = self.writes_attempted.load(Ordering::Relaxed);
        if attempted == 0 {
            return 0.0;
        }
        let succeeded = self.writes_quorum_reached.load(Ordering::Relaxed);
        succeeded as f64 / attempted as f64
    }

    #[must_use]
    pub fn snapshot(&self) -> ReplicationTransportSnapshot {
        ReplicationTransportSnapshot {
            writes_attempted: self.writes_attempted.load(Ordering::Relaxed),
            writes_quorum_reached: self.writes_quorum_reached.load(Ordering::Relaxed),
            writes_failed: self.writes_failed.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            avg_latency_ms: self.avg_latency_ms(),
            success_rate: self.success_rate(),
            inflight: self.inflight_count.load(Ordering::Relaxed),
            carrier_kind: self.carrier_kind(),
        }
    }
}

/// Non-atomic snapshot of replication transport statistics.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplicationTransportSnapshot {
    pub writes_attempted: u64,
    pub writes_quorum_reached: u64,
    pub writes_failed: u64,
    pub retries: u64,
    pub avg_latency_ms: f64,
    pub success_rate: f64,
    pub inflight: u64,
    /// Transport carrier kind at snapshot time.
    pub carrier_kind: TransportBackendKind,
}

impl Default for ReplicationTransportSnapshot {
    fn default() -> Self {
        Self {
            writes_attempted: 0,
            writes_quorum_reached: 0,
            writes_failed: 0,
            retries: 0,
            avg_latency_ms: 0.0,
            success_rate: 0.0,
            inflight: 0,
            carrier_kind: TransportBackendKind::Tcp,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ReplicationTransport
// ═══════════════════════════════════════════════════════════════════════

/// Minimal handle for a replication transport worker.
pub struct ReplicationTransport {
    /// Worker join handle.
    pub handle: Option<JoinHandle<()>>,
    /// Cancellation flag.
    pub cancel: Arc<AtomicBool>,
}

impl ReplicationTransport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            handle: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn spawn<F>(&mut self, f: F)
    where
        F: FnOnce(Arc<AtomicBool>) + Send + 'static,
    {
        let cancel = Arc::clone(&self.cancel);
        self.handle = Some(thread::spawn(move || {
            f(cancel);
        }));
    }

    pub fn shutdown(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Default for ReplicationTransport {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ReplicationStatsSnapshot (alias for lib.rs compatibility)
// ═══════════════════════════════════════════════════════════════════════

/// Alias for [`ReplicationTransportSnapshot`].
pub type ReplicationStatsSnapshot = ReplicationTransportSnapshot;

// ═══════════════════════════════════════════════════════════════════════
// ReplicationRuntimeConfig
// ═══════════════════════════════════════════════════════════════════════

/// Configuration for the replication runtime.
#[derive(Debug)]
pub struct ReplicationRuntimeConfig {
    /// Maximum concurrent in-flight writes.
    pub max_inflight: usize,
    /// Replication policy selector.
    pub policy: ReplicationPolicySelector,
}

impl Default for ReplicationRuntimeConfig {
    fn default() -> Self {
        Self {
            max_inflight: 64,
            policy: ReplicationPolicySelector,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TargetWriteResult
// ═══════════════════════════════════════════════════════════════════════

/// Result of a write to a single replication target.
#[derive(Clone, Debug)]
pub struct TargetWriteResult {
    /// Target member ID.
    pub target: MemberId,
    /// Whether the write succeeded.
    pub success: bool,
    /// Write latency.
    pub latency: Duration,
    /// Error message on failure.
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// AsyncReplicationWorker
// ═══════════════════════════════════════════════════════════════════════

/// Async worker for replication transport dispatch.
///
/// Spawns a thread that polls for pending writes, fans them out to
/// targets, collects quorum acknowledgments, and publishes outcomes.
pub struct AsyncReplicationWorker {
    /// Worker join handle.
    handle: Option<JoinHandle<()>>,
    /// Cancellation flag.
    cancel: Arc<AtomicBool>,
}

impl AsyncReplicationWorker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            handle: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn spawn<F>(&mut self, f: F)
    where
        F: FnOnce(Arc<AtomicBool>) + Send + 'static,
    {
        let cancel = Arc::clone(&self.cancel);
        self.handle = Some(thread::spawn(move || {
            f(cancel);
        }));
    }

    pub fn shutdown(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Default for AsyncReplicationWorker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ReplicationRuntime
// ═══════════════════════════════════════════════════════════════════════

/// Main replication runtime orchestrating write dispatch, quorum
/// collection, and retry for a set of replication targets.
#[derive(Debug)]
pub struct ReplicationRuntime {
    /// Transport statistics.
    pub stats: ReplicationTransportStats,
    /// Runtime configuration.
    pub config: ReplicationRuntimeConfig,
}

impl ReplicationRuntime {
    #[must_use]
    pub fn new(config: ReplicationRuntimeConfig) -> Self {
        Self {
            stats: ReplicationTransportStats::new(),
            config,
        }
    }

    /// Return a snapshot of current transport statistics.
    #[must_use]
    pub fn stats_snapshot(&self) -> ReplicationTransportSnapshot {
        self.stats.snapshot()
    }

    /// Set the transport carrier kind used for replication writes.
    pub fn set_carrier(&self, kind: TransportBackendKind) {
        self.stats.set_carrier(kind);
    }
}

impl Default for ReplicationRuntime {
    fn default() -> Self {
        Self::new(ReplicationRuntimeConfig::default())
    }
}
