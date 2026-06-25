// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-session-class send-queue depth governance with configurable
//! capacity bounds and caller backpressure propagation.
//!
//! ## Problem
//!
//! When a peer connection stalls or a receiver drains slowly, a fast
//! producer can push frames into outbound queues without bound,
//! growing memory until OOM.  Per-session-class depth caps prevent
//! one lane class from saturating the total outbound buffer pool.
//!
//! ## Architecture
//!
//! ```text
//! Caller
//!   |
//!   +-- try_reserve(lane) → Ok(guard) or Err(SendQueueFull)
//!        |
//!        +-- atomic increment (non-blocking)
//!        +-- return SendQueueDepthGuard (releases on drop or explicit release)
//!              |
//!              v
//!         Message enqueued into SendQueue
//!              |
//!              +-- Drawn by SendDrainer: guard released → decrement atomic
//! ```
//!
//! ## API contract
//!
//! | Method         | Meaning                                          |
//! |----------------|--------------------------------------------------|
//! | `try_reserve`  | Atomically check bound and increment or return  |
//! |                | `SendQueueFull` with lane and current depth.     |
//! | `release`      | Decrement depth for the lane (guard drop).       |
//! | `depth`        | Current depth for a lane.                        |
//!
//! ## Configuration
//!
//! `SendQueueDepthConfig` carries per-lane-class `max_depth` values.
//! A lane class with `max_depth == 0` is ungoverned (depth not tracked).
//!
//! ## Admission Evidence
//!
//! `SendQueueDepthEvidence` exposes this governor as compact source/adapter
//! metadata for no-hidden-queue review.
//!
//! tidefs-queue-root: transport.send_queue_depth
//!
//!
//! Each lane is an `AdmissionPermit`-class resource tracked under a
//! `ServiceCurve`-compatible queue-slots budget. The evidence uses the
//! canonical `tidefs-performance-contract` spellings for work classes,
//! resource domains, and validation tiers. It is not a distributed
//! runtime fairness, throughput, or RDMA readiness claim by itself.
//!
//! ## Integration
//!
//! - **Upstream**: `SendDispatcher::enqueue()` calls `try_reserve()` before
//!   enqueueing into the per-connection `SendQueue`.  On enqueue failure
//!   (backpressure/shutdown), the guard is explicitly released.
//! - **Downstream**: `SendDrainer` releases the guard after dequeuing and
//!   successfully sending the batch.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::lane_demux::LaneClass;
use crate::send_admission::ClusterQueuePressure;

/// Stable queue-root name for transport send depth admission metadata.
pub const SEND_QUEUE_DEPTH_QUEUE_ROOT: &str = "transport.send_queue_depth";
/// Queue-slot resource domain spelling from `tidefs-performance-contract`.
pub const SEND_QUEUE_DEPTH_RESOURCE_DOMAIN: &str = "queue-slots";
/// Source-level validation tier spelling from `tidefs-performance-contract`.
pub const SEND_QUEUE_DEPTH_VALIDATION_TIER: &str = "source-model";

/// Return the canonical `tidefs-performance-contract` work class for a lane.
#[must_use]
pub const fn send_queue_depth_work_class(lane: LaneClass) -> &'static str {
    match lane {
        LaneClass::Control => "control-plane",
        LaneClass::Metadata => "metadata-mutation",
        LaneClass::Demand => "foreground-read",
        LaneClass::Speculative => "scrub",
        LaneClass::Background => "compaction",
    }
}

// ---------------------------------------------------------------------------
// SendQueueDepthConfig
// ---------------------------------------------------------------------------

/// Per-lane-class depth governance configuration.
///
/// Each lane class can have an independent `max_depth` bound.
/// A value of `0` disables governance for that lane (unbounded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendQueueDepthConfig {
    /// Maximum depth per lane class; index with `lane.as_usize()`.
    max_depth: [usize; LaneClass::COUNT],
}

impl SendQueueDepthConfig {
    /// Number of lane classes governed.
    pub const LANE_COUNT: usize = LaneClass::COUNT;

    /// Create a new config with the given per-lane max depths.
    ///
    /// Returns `None` if any max_depth is zero (use
    /// [`SendQueueDepthConfig::with_lanes`] for selective governance).
    pub fn new(max_depths: [usize; LaneClass::COUNT]) -> Option<Self> {
        if max_depths.contains(&0) {
            return None;
        }
        Some(Self {
            max_depth: max_depths,
        })
    }

    /// Create a config governing only the specified lane classes.
    ///
    /// Lanes not present in `governed` will have `max_depth == 0`
    /// (ungoverned). Returns `None` if `governed` is empty.
    pub fn with_lanes(governed: &[(LaneClass, usize)]) -> Option<Self> {
        if governed.is_empty() {
            return None;
        }
        let mut max_depth = [0usize; LaneClass::COUNT];
        for &(lane, depth) in governed {
            if depth == 0 {
                return None; // 0 depth for governed lane is invalid
            }
            max_depth[lane.as_usize()] = depth;
        }
        Some(Self { max_depth })
    }

    /// Return the max_depth for a given lane class.
    /// 0 means ungoverned.
    #[must_use]
    pub fn max_depth(&self, lane: LaneClass) -> usize {
        self.max_depth[lane.as_usize()]
    }

    /// Return the effective max depth after applying governor
    /// `cluster_queues` pressure.
    ///
    /// Ungoverned lanes remain ungoverned (`0`). Soft pressure halves the
    /// queue-slot window; hard pressure reduces it to a minimal positive
    /// window so required drain/receipt work can still be modeled explicitly
    /// by callers that also carry a critical admission class.
    #[must_use]
    pub fn max_depth_under_cluster_pressure(
        &self,
        lane: LaneClass,
        pressure: ClusterQueuePressure,
    ) -> usize {
        pressure_adjusted_depth(self.max_depth(lane), pressure)
    }

    /// Return true if the given lane class is governed (max_depth > 0).
    #[must_use]
    pub fn is_governed(&self, lane: LaneClass) -> bool {
        self.max_depth[lane.as_usize()] > 0
    }

    /// Return all governed lane classes and their max depths.
    #[must_use]
    pub fn governed_lanes(&self) -> Vec<(LaneClass, usize)> {
        LaneClass::all()
            .iter()
            .filter_map(|&lane| {
                let d = self.max_depth[lane.as_usize()];
                if d > 0 {
                    Some((lane, d))
                } else {
                    None
                }
            })
            .collect()
    }
}

fn pressure_adjusted_depth(depth: usize, pressure: ClusterQueuePressure) -> usize {
    if depth == 0 {
        return 0;
    }
    match pressure {
        ClusterQueuePressure::None => depth,
        ClusterQueuePressure::SoftPressure => (depth / 2).max(1),
        ClusterQueuePressure::HardPressure => (depth / 4).max(1),
    }
}

impl Default for SendQueueDepthConfig {
    fn default() -> Self {
        // Sensible defaults: Control is small (command traffic is light),
        // Metadata is moderate, Demand and Speculative are generous,
        // Background is largest (bulk data).
        Self {
            max_depth: [
                64,   // Control
                128,  // Metadata
                512,  // Demand
                256,  // Speculative
                1024, // Background
            ],
        }
    }
}

impl fmt::Display for SendQueueDepthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SendQueueDepthConfig {{ ")?;
        for (i, lane) in LaneClass::all().iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}:{}", lane.as_str(), self.max_depth[lane.as_usize()])?;
        }
        write!(f, " }}")
    }
}

// ---------------------------------------------------------------------------
// SendQueueDepthError
// ---------------------------------------------------------------------------

/// Error returned when the per-class send-queue depth limit is exceeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendQueueDepthError {
    /// The lane class that is at capacity.
    pub lane: LaneClass,
    /// Current depth (number of reserved+queued messages for this lane).
    pub depth: usize,
    /// Configured maximum depth for this lane.
    pub max_depth: usize,
}

impl fmt::Display for SendQueueDepthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "send-queue depth exceeded for lane {}: depth={}, max={}",
            self.lane.as_str(),
            self.depth,
            self.max_depth
        )
    }
}

// ---------------------------------------------------------------------------
// SendQueueDepthEvidence
// ---------------------------------------------------------------------------

/// Compact source/adapter metadata for one bounded send queue lane.
///
/// This record names the queue root and lane, the configured queue-slot limit,
/// the current depth at sampling time, and the canonical
/// `tidefs-performance-contract` metadata labels. It intentionally carries
/// `source-model` validation tier metadata; runtime performance or distributed
/// fairness claims require separate runtime evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendQueueDepthEvidence {
    /// Registered transport queue-root identifier.
    pub queue_root: &'static str,
    /// Stable lane queue name.
    pub queue_name: &'static str,
    /// Configured maximum queue-slot depth for this lane.
    pub limit: usize,
    /// Current reserved+queued depth for this lane.
    pub current_depth: usize,
    /// Canonical performance-contract work-class spelling.
    pub work_class: &'static str,
    /// Canonical performance-contract resource-domain spelling.
    pub resource_domain: &'static str,
    /// Canonical validation-tier spelling for this metadata.
    pub validation_tier: &'static str,
}

/// Evidence validation failure for transport send queue depth metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendQueueDepthEvidenceError {
    /// The caller requested evidence for a queue root this governor does not own.
    UnknownQueueRoot { queue_root: String },
    /// The lane exists but has no positive queue-slot bound to export.
    UnboundedQueueRoot {
        queue_root: &'static str,
        queue_name: &'static str,
    },
}

impl fmt::Display for SendQueueDepthEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownQueueRoot { queue_root } => {
                write!(f, "unknown send queue depth root `{queue_root}`")
            }
            Self::UnboundedQueueRoot {
                queue_root,
                queue_name,
            } => write!(
                f,
                "send queue depth root `{queue_root}` lane `{queue_name}` is unbounded"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// SendQueueDepth
// ---------------------------------------------------------------------------

/// Per-session-class send-queue depth governor.
///
/// Maintains atomic per-lane-class depth counters and enforces
/// configurable `max_depth` bounds. Designed to be shared behind
/// an `Arc` between the dispatch path (producer) and the drainer
/// path (consumer).
///
/// # Thread safety
///
/// `try_reserve` and `release` use `AtomicUsize` fetch_add/sub with
/// `Ordering::Acquire`/`Release` semantics, so they are safe to call
/// from any thread concurrently.
#[derive(Debug)]
pub struct SendQueueDepth {
    config: SendQueueDepthConfig,
    /// Per-lane-class current depths (reserved+queued but not yet drained).
    depth: [AtomicUsize; LaneClass::COUNT],
}

impl SendQueueDepth {
    /// Create a new depth governor with the given config.
    #[must_use]
    pub fn new(config: SendQueueDepthConfig) -> Self {
        Self {
            config,
            depth: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }

    /// Return the current depth for a lane class.
    #[must_use]
    pub fn depth(&self, lane: LaneClass) -> usize {
        self.depth[lane.as_usize()].load(Ordering::Acquire)
    }

    /// Return all lane class depths as a snapshot.
    #[must_use]
    pub fn depth_snapshot(&self) -> Vec<(LaneClass, usize)> {
        LaneClass::all()
            .iter()
            .map(|&lane| (lane, self.depth(lane)))
            .collect()
    }

    /// Return a reference to the config.
    #[must_use]
    pub fn config(&self) -> &SendQueueDepthConfig {
        &self.config
    }

    /// Return this lane's effective queue-slot limit under observed
    /// governor `cluster_queues` pressure.
    #[must_use]
    pub fn max_depth_under_cluster_pressure(
        &self,
        lane: LaneClass,
        pressure: ClusterQueuePressure,
    ) -> usize {
        self.config.max_depth_under_cluster_pressure(lane, pressure)
    }

    /// Return compact source/adapter evidence for a bounded lane.
    ///
    /// This validates the built-in queue root and rejects lanes with a zero
    /// queue-slot limit. It does not reserve or release queue slots.
    pub fn evidence(
        &self,
        lane: LaneClass,
    ) -> Result<SendQueueDepthEvidence, SendQueueDepthEvidenceError> {
        self.evidence_for_root(SEND_QUEUE_DEPTH_QUEUE_ROOT, lane)
    }

    /// Return evidence for an explicitly named queue root.
    ///
    /// Unknown roots are rejected so callers cannot accidentally publish
    /// send-depth metadata under an unreviewed queue-root name.
    pub fn evidence_for_root(
        &self,
        queue_root: &str,
        lane: LaneClass,
    ) -> Result<SendQueueDepthEvidence, SendQueueDepthEvidenceError> {
        if queue_root != SEND_QUEUE_DEPTH_QUEUE_ROOT {
            return Err(SendQueueDepthEvidenceError::UnknownQueueRoot {
                queue_root: queue_root.to_string(),
            });
        }

        let limit = self.config.max_depth(lane);
        if limit == 0 {
            return Err(SendQueueDepthEvidenceError::UnboundedQueueRoot {
                queue_root: SEND_QUEUE_DEPTH_QUEUE_ROOT,
                queue_name: lane.as_str(),
            });
        }

        Ok(SendQueueDepthEvidence {
            queue_root: SEND_QUEUE_DEPTH_QUEUE_ROOT,
            queue_name: lane.as_str(),
            limit,
            current_depth: self.depth(lane),
            work_class: send_queue_depth_work_class(lane),
            resource_domain: SEND_QUEUE_DEPTH_RESOURCE_DOMAIN,
            validation_tier: SEND_QUEUE_DEPTH_VALIDATION_TIER,
        })
    }

    /// Return evidence for every lane, rejecting configurations with an
    /// unbounded lane.
    pub fn evidence_snapshot(
        &self,
    ) -> Result<Vec<SendQueueDepthEvidence>, SendQueueDepthEvidenceError> {
        LaneClass::all()
            .into_iter()
            .map(|lane| self.evidence(lane))
            .collect()
    }

    /// Try to reserve a slot in the send queue for the given lane class.
    ///
    /// Atomically checks whether the current depth is below the configured
    /// `max_depth` for this lane. If so, increments the depth counter and
    /// returns `Ok(())`. If at or above the bound, returns
    /// [`SendQueueDepthError`] with the lane, current depth, and max_depth.
    ///
    /// Ungoverned lanes (max_depth == 0) always succeed without tracking.
    ///
    /// The caller must eventually call [`release`](Self::release) to
    /// decrement the depth counter, typically after the message has been
    /// drained from the send queue.
    pub fn try_reserve(&self, lane: LaneClass) -> Result<(), SendQueueDepthError> {
        let max_depth = self.config.max_depth(lane);

        // Ungoverned lane: always succeed.
        if max_depth == 0 {
            return Ok(());
        }

        let idx = lane.as_usize();
        let current = self.depth[idx].fetch_add(1, Ordering::Acquire);

        if current >= max_depth {
            // Roll back: we're at or past the bound.
            self.depth[idx].fetch_sub(1, Ordering::Release);
            return Err(SendQueueDepthError {
                lane,
                depth: current,
                max_depth,
            });
        }

        Ok(())
    }

    /// Release a reserved slot for the given lane class.
    ///
    /// Decrements the depth counter. Must be paired with a successful
    /// `try_reserve` call. Calling `release` on an ungoverned lane
    /// (max_depth == 0) is a no-op.
    pub fn release(&self, lane: LaneClass) {
        if self.config.max_depth(lane) == 0 {
            return;
        }
        let prev = self.depth[lane.as_usize()].fetch_sub(1, Ordering::Release);
        // Underflow guard: if we released more than reserved, clamp.
        if prev == 0 {
            self.depth[lane.as_usize()].store(0, Ordering::Release);
        }
    }

    /// Current depth for the control lane (convenience).
    #[must_use]
    pub fn control_depth(&self) -> usize {
        self.depth(LaneClass::Control)
    }

    /// Current depth for the metadata lane (convenience).
    #[must_use]
    pub fn metadata_depth(&self) -> usize {
        self.depth(LaneClass::Metadata)
    }

    /// Current depth for the demand lane (convenience).
    #[must_use]
    pub fn demand_depth(&self) -> usize {
        self.depth(LaneClass::Demand)
    }

    /// Current depth for the speculative lane (convenience).
    #[must_use]
    pub fn speculative_depth(&self) -> usize {
        self.depth(LaneClass::Speculative)
    }

    /// Current depth for the background lane (convenience).
    #[must_use]
    pub fn background_depth(&self) -> usize {
        self.depth(LaneClass::Background)
    }
}

impl Default for SendQueueDepth {
    fn default() -> Self {
        Self::new(SendQueueDepthConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;

    // Helper: LaneClass::all() iterable
    // We already have it from the import; tests use it directly.

    #[test]
    fn config_creation_with_all_lanes_set() {
        let cfg = SendQueueDepthConfig::new([10; LaneClass::COUNT]).unwrap();
        assert_eq!(cfg.max_depth(LaneClass::Control), 10);
        assert_eq!(cfg.max_depth(LaneClass::Background), 10);
        assert!(cfg.is_governed(LaneClass::Demand));
    }

    #[test]
    fn config_with_zero_rejected() {
        assert!(SendQueueDepthConfig::new([0; LaneClass::COUNT]).is_none());
    }

    #[test]
    fn config_with_lanes_selective() {
        let cfg =
            SendQueueDepthConfig::with_lanes(&[(LaneClass::Control, 8), (LaneClass::Demand, 64)])
                .unwrap();

        assert_eq!(cfg.max_depth(LaneClass::Control), 8);
        assert_eq!(cfg.max_depth(LaneClass::Demand), 64);
        // Metadata not governed
        assert_eq!(cfg.max_depth(LaneClass::Metadata), 0);
        assert!(!cfg.is_governed(LaneClass::Metadata));
    }

    #[test]
    fn config_with_lanes_empty_rejected() {
        assert!(SendQueueDepthConfig::with_lanes(&[]).is_none());
    }

    #[test]
    fn config_with_lanes_zero_depth_rejected() {
        assert!(SendQueueDepthConfig::with_lanes(&[(LaneClass::Control, 0)]).is_none());
    }

    #[test]
    fn config_default_all_lanes_governed() {
        let cfg = SendQueueDepthConfig::default();
        for lane in LaneClass::all() {
            assert!(cfg.is_governed(lane), "{lane:?} should be governed");
            assert!(cfg.max_depth(lane) > 0, "{lane:?} max_depth should be > 0");
        }
    }

    #[test]
    fn config_governed_lanes_returns_only_nonzero() {
        let cfg = SendQueueDepthConfig::with_lanes(&[
            (LaneClass::Control, 5),
            (LaneClass::Background, 100),
        ])
        .unwrap();
        let governed = cfg.governed_lanes();
        assert_eq!(governed.len(), 2);
        assert!(governed.contains(&(LaneClass::Control, 5)));
        assert!(governed.contains(&(LaneClass::Background, 100)));
    }

    #[test]
    fn try_reserve_succeeds_within_bound() {
        let cfg = SendQueueDepthConfig::new([2; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        // First reserve succeeds (depth 0 -> 1, bound 2)
        assert!(gov.try_reserve(LaneClass::Demand).is_ok());
        assert_eq!(gov.depth(LaneClass::Demand), 1);

        // Second reserve succeeds (depth 1 -> 2, bound 2)
        assert!(gov.try_reserve(LaneClass::Demand).is_ok());
        assert_eq!(gov.depth(LaneClass::Demand), 2);
    }

    #[test]
    fn try_reserve_fails_at_bound() {
        let cfg = SendQueueDepthConfig::new([2; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        gov.try_reserve(LaneClass::Control).unwrap(); // depth 1
        gov.try_reserve(LaneClass::Control).unwrap(); // depth 2

        // Third reserve at bound fails
        let err = gov.try_reserve(LaneClass::Control).unwrap_err();
        assert_eq!(err.lane, LaneClass::Control);
        assert_eq!(err.max_depth, 2);
        // depth should still be 2 (no increment on failure)
        assert_eq!(gov.depth(LaneClass::Control), 2);
    }

    #[test]
    fn try_reserve_fails_rolls_back_atomic() {
        let cfg = SendQueueDepthConfig::new([1; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        gov.try_reserve(LaneClass::Metadata).unwrap(); // depth 1
        assert_eq!(gov.depth(LaneClass::Metadata), 1);

        let err = gov.try_reserve(LaneClass::Metadata).unwrap_err();
        assert_eq!(err.depth, 1); // saw depth 1 before rollback
        assert_eq!(gov.depth(LaneClass::Metadata), 1); // rolled back
    }

    #[test]
    fn release_decrements_depth() {
        let cfg = SendQueueDepthConfig::new([4; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        gov.try_reserve(LaneClass::Background).unwrap();
        assert_eq!(gov.depth(LaneClass::Background), 1);

        gov.release(LaneClass::Background);
        assert_eq!(gov.depth(LaneClass::Background), 0);
    }

    #[test]
    fn release_underflow_guard() {
        let cfg = SendQueueDepthConfig::new([4; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        // Release without reserve: should stay at 0.
        gov.release(LaneClass::Speculative);
        assert_eq!(gov.depth(LaneClass::Speculative), 0);
    }

    #[test]
    fn ungoverned_lane_always_succeeds() {
        let cfg = SendQueueDepthConfig::with_lanes(&[(LaneClass::Control, 5)]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        // Demand is ungoverned (max_depth == 0)
        for _ in 0..1000 {
            assert!(gov.try_reserve(LaneClass::Demand).is_ok());
        }
        // Depth for ungoverned lane stays at 0
        assert_eq!(gov.depth(LaneClass::Demand), 0);
    }

    #[test]
    fn per_class_isolation() {
        let cfg = SendQueueDepthConfig::new([1; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        // Fill up Demand
        gov.try_reserve(LaneClass::Demand).unwrap();
        let err = gov.try_reserve(LaneClass::Demand).unwrap_err();
        assert_eq!(err.lane, LaneClass::Demand);

        // Control should still be independently at 0
        assert_eq!(gov.depth(LaneClass::Control), 0);
        assert!(gov.try_reserve(LaneClass::Control).is_ok());
        assert_eq!(gov.depth(LaneClass::Control), 1);
    }

    #[test]
    fn concurrent_send_interleaving() {
        let cfg = SendQueueDepthConfig::new([100; LaneClass::COUNT]).unwrap();
        let gov = Arc::new(SendQueueDepth::new(cfg));
        let lane = LaneClass::Control;

        let threads: Vec<_> = (0..4)
            .map(|_| {
                let gov = Arc::clone(&gov);
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        gov.try_reserve(lane).unwrap();
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }

        // 4 threads x 25 reserves = 100
        assert_eq!(gov.depth(lane), 100);
        // Next reserve should fail
        let err = gov.try_reserve(lane).unwrap_err();
        assert_eq!(err.max_depth, 100);
    }

    #[test]
    fn concurrent_reserve_and_release() {
        let cfg = SendQueueDepthConfig::new([10; LaneClass::COUNT]).unwrap();
        let gov = Arc::new(SendQueueDepth::new(cfg));
        let lane = LaneClass::Demand;

        let barrier = Arc::new(Barrier::new(2));

        let producer = {
            let gov = Arc::clone(&gov);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for i in 0..20 {
                    match gov.try_reserve(lane) {
                        Ok(()) => { /* reserved */ }
                        Err(e) => {
                            // We expect some failures since consumer releases
                            assert_eq!(e.lane, lane);
                        }
                    }
                    if i % 5 == 0 {
                        std::thread::yield_now();
                    }
                }
            })
        };

        let consumer = {
            let gov = Arc::clone(&gov);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..15 {
                    gov.release(lane);
                    std::thread::yield_now();
                }
            })
        };

        producer.join().unwrap();
        consumer.join().unwrap();

        // Max depth should never have exceeded 10 at any point.
        // Final depth is 0 <= depth <= 10 (depends on interleaving).
        let final_depth = gov.depth(lane);
        assert!(final_depth <= 10, "depth {final_depth} exceeded max 10");
    }

    #[test]
    fn depth_snapshot_reflects_all_lanes() {
        let cfg = SendQueueDepthConfig::new([5; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        gov.try_reserve(LaneClass::Control).unwrap();
        gov.try_reserve(LaneClass::Control).unwrap();
        gov.try_reserve(LaneClass::Demand).unwrap();
        gov.try_reserve(LaneClass::Background).unwrap();
        gov.try_reserve(LaneClass::Background).unwrap();
        gov.try_reserve(LaneClass::Background).unwrap();

        let snap = gov.depth_snapshot();
        let find = |lane: LaneClass| -> usize {
            snap.iter()
                .find(|(l, _)| *l == lane)
                .map(|(_, d)| *d)
                .unwrap_or(0)
        };
        assert_eq!(find(LaneClass::Control), 2);
        assert_eq!(find(LaneClass::Metadata), 0);
        assert_eq!(find(LaneClass::Demand), 1);
        assert_eq!(find(LaneClass::Speculative), 0);
        assert_eq!(find(LaneClass::Background), 3);
    }

    #[test]
    fn evidence_work_class_mapping_uses_performance_contract_spellings() {
        let expected = [
            (LaneClass::Control, "control-plane"),
            (LaneClass::Metadata, "metadata-mutation"),
            (LaneClass::Demand, "foreground-read"),
            (LaneClass::Speculative, "scrub"),
            (LaneClass::Background, "compaction"),
        ];

        for (lane, work_class) in expected {
            assert_eq!(send_queue_depth_work_class(lane), work_class);
        }
    }

    #[test]
    fn evidence_record_reports_compact_bounded_metadata() {
        let cfg = SendQueueDepthConfig::new([8; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        gov.try_reserve(LaneClass::Demand).unwrap();
        gov.try_reserve(LaneClass::Demand).unwrap();

        let evidence = gov.evidence(LaneClass::Demand).unwrap();
        assert_eq!(evidence.queue_root, SEND_QUEUE_DEPTH_QUEUE_ROOT);
        assert_eq!(evidence.queue_name, LaneClass::Demand.as_str());
        assert_eq!(evidence.limit, 8);
        assert_eq!(evidence.current_depth, 2);
        assert_eq!(evidence.work_class, "foreground-read");
        assert_eq!(evidence.resource_domain, SEND_QUEUE_DEPTH_RESOURCE_DOMAIN);
        assert_eq!(evidence.validation_tier, SEND_QUEUE_DEPTH_VALIDATION_TIER);
    }

    #[test]
    fn evidence_snapshot_requires_all_lanes_bounded() {
        let cfg = SendQueueDepthConfig::new([3; LaneClass::COUNT]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        gov.try_reserve(LaneClass::Control).unwrap();
        let snapshot = gov.evidence_snapshot().unwrap();

        assert_eq!(snapshot.len(), LaneClass::COUNT);
        assert_eq!(snapshot[0].queue_name, LaneClass::Control.as_str());
        assert_eq!(snapshot[0].current_depth, 1);
        assert!(snapshot.iter().all(|record| {
            record.queue_root == SEND_QUEUE_DEPTH_QUEUE_ROOT
                && record.limit == 3
                && record.resource_domain == SEND_QUEUE_DEPTH_RESOURCE_DOMAIN
                && record.validation_tier == SEND_QUEUE_DEPTH_VALIDATION_TIER
        }));
    }

    #[test]
    fn evidence_rejects_unbounded_queue_root() {
        let cfg = SendQueueDepthConfig::with_lanes(&[(LaneClass::Control, 5)]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        let err = gov.evidence(LaneClass::Demand).unwrap_err();
        assert_eq!(
            err,
            SendQueueDepthEvidenceError::UnboundedQueueRoot {
                queue_root: SEND_QUEUE_DEPTH_QUEUE_ROOT,
                queue_name: LaneClass::Demand.as_str()
            }
        );
    }

    #[test]
    fn evidence_rejects_unknown_queue_root() {
        let gov = SendQueueDepth::default();

        let err = gov
            .evidence_for_root("transport.unregistered_send_queue", LaneClass::Control)
            .unwrap_err();
        assert_eq!(
            err,
            SendQueueDepthEvidenceError::UnknownQueueRoot {
                queue_root: "transport.unregistered_send_queue".to_string()
            }
        );
    }

    #[test]
    fn convenience_methods_match_depth() {
        let cfg = SendQueueDepthConfig::default();
        let gov = SendQueueDepth::new(cfg);

        gov.try_reserve(LaneClass::Control).unwrap();
        gov.try_reserve(LaneClass::Metadata).unwrap();
        gov.try_reserve(LaneClass::Metadata).unwrap();
        gov.try_reserve(LaneClass::Demand).unwrap();

        assert_eq!(gov.control_depth(), 1);
        assert_eq!(gov.metadata_depth(), 2);
        assert_eq!(gov.demand_depth(), 1);
        assert_eq!(gov.speculative_depth(), 0);
        assert_eq!(gov.background_depth(), 0);
    }

    #[test]
    fn default_queue_depth_creates_with_default_config() {
        let gov = SendQueueDepth::default();
        let cfg = gov.config();
        assert!(cfg.is_governed(LaneClass::Control));
        assert_eq!(gov.depth(LaneClass::Control), 0);
    }

    #[test]
    fn config_display_format() {
        let cfg = SendQueueDepthConfig::default();
        let s = format!("{cfg}");
        assert!(s.contains("lane.transport_session_0.control.l0"));
        assert!(s.contains("lane.transport_session_0.background.l4"));
    }

    #[test]
    fn send_queue_depth_error_display() {
        let err = SendQueueDepthError {
            lane: LaneClass::Demand,
            depth: 512,
            max_depth: 512,
        };
        let s = format!("{err}");
        assert!(s.contains("lane.transport_session_0.demand.l2"));
        assert!(s.contains("depth=512"));
        assert!(s.contains("max=512"));
    }

    #[test]
    fn cluster_pressure_reduces_effective_depth_limits() {
        let cfg = SendQueueDepthConfig::new([100; LaneClass::COUNT]).unwrap();
        assert_eq!(
            cfg.max_depth_under_cluster_pressure(LaneClass::Demand, ClusterQueuePressure::None),
            100
        );
        assert_eq!(
            cfg.max_depth_under_cluster_pressure(
                LaneClass::Demand,
                ClusterQueuePressure::SoftPressure
            ),
            50
        );
        assert_eq!(
            cfg.max_depth_under_cluster_pressure(
                LaneClass::Demand,
                ClusterQueuePressure::HardPressure
            ),
            25
        );
    }

    #[test]
    fn cluster_pressure_keeps_ungoverned_lanes_unbounded() {
        let cfg = SendQueueDepthConfig::with_lanes(&[(LaneClass::Control, 8)]).unwrap();
        let gov = SendQueueDepth::new(cfg);

        assert_eq!(
            gov.max_depth_under_cluster_pressure(
                LaneClass::Demand,
                ClusterQueuePressure::HardPressure
            ),
            0
        );
        assert_eq!(
            gov.max_depth_under_cluster_pressure(
                LaneClass::Control,
                ClusterQueuePressure::SoftPressure
            ),
            4
        );
    }
}
