// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

use tidefs_durability_layout::DurabilityLayoutV1;
use tidefs_quorum_write::DurabilityMode;

/// Configuration for the quorum write runtime.
#[derive(Clone, Debug)]
pub struct QuorumWriteConfig {
    pub durability_mode: DurabilityMode,
    pub min_target_count: usize,
    pub phase_timeout_ms: u64,
    pub total_timeout_ms: u64,
    pub enable_degraded_reads: bool,
    /// Optional durability layout for failure-domain-aware quorum planning.
    pub durability_layout: Option<DurabilityLayoutV1>,
    pub retry_attempts: u32,
}

impl Default for QuorumWriteConfig {
    fn default() -> Self {
        Self {
            durability_mode: DurabilityMode::QuorumFull,
            min_target_count: 0,
            phase_timeout_ms: 5_000,
            total_timeout_ms: 30_000,
            enable_degraded_reads: true,
            durability_layout: None,
            retry_attempts: 2,
        }
    }
}

impl QuorumWriteConfig {
    #[must_use]
    pub fn dev_local() -> Self {
        Self {
            durability_mode: DurabilityMode::QuorumFull,
            min_target_count: 1,
            phase_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            enable_degraded_reads: false,
            durability_layout: None,
            retry_attempts: 0,
        }
    }

    #[must_use]
    pub fn production_witness() -> Self {
        Self {
            durability_mode: DurabilityMode::QuorumWitness,
            min_target_count: 3,
            phase_timeout_ms: 3_000,
            total_timeout_ms: 20_000,
            enable_degraded_reads: true,
            durability_layout: None,
            retry_attempts: 2,
        }
    }

    #[must_use]
    pub fn production_full() -> Self {
        Self {
            durability_mode: DurabilityMode::QuorumFull,
            min_target_count: 3,
            phase_timeout_ms: 3_000,
            total_timeout_ms: 20_000,
            enable_degraded_reads: true,
            durability_layout: None,
            retry_attempts: 2,
        }
    }

    // ── Durability layout integration ───────────────────────────────

    /// Attach a durability layout for failure-domain-aware quorum planning.
    ///
    /// When set, quorum calculations use the layout's
    /// `DurabilityPolicy::total_shards()` as the base replica count.
    #[must_use]
    pub fn with_durability_layout(mut self, layout: DurabilityLayoutV1) -> Self {
        self.durability_layout = Some(layout);
        self
    }

    /// Derive a `WriteQuorumConfig` from the durability layout, if present.
    ///
    /// Returns `None` when no layout is set. When a layout is present,
    /// `total_replicas` = `layout.policy.total_shards()` and
    /// `write_quorum` respects the durability mode.
    pub fn quorum_from_layout(&self) -> Option<WriteQuorumConfig> {
        let layout = self.durability_layout.as_ref()?;
        let total = layout.policy.total_shards();
        if total == 0 {
            return None;
        }
        let w = match self.durability_mode {
            DurabilityMode::QuorumFull => total,
            DurabilityMode::QuorumChain | DurabilityMode::QuorumWitness => total / 2 + 1,
        };
        WriteQuorumConfig::new(total, w).ok()
    }

    /// Set the durability mode (builder pattern).
    #[must_use]
    pub fn with_durability(mut self, mode: DurabilityMode) -> Self {
        self.durability_mode = mode;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_sensible() {
        let c = QuorumWriteConfig::default();
        assert_eq!(c.durability_mode, DurabilityMode::QuorumFull);
        assert!(c.total_timeout_ms > c.phase_timeout_ms);
    }

    #[test]
    fn dev_local_single_target() {
        assert_eq!(QuorumWriteConfig::dev_local().min_target_count, 1);
    }

    #[test]
    fn production_modes_multi_target() {
        assert!(QuorumWriteConfig::production_witness().min_target_count >= 2);
        assert!(QuorumWriteConfig::production_full().min_target_count >= 2);
    }

    #[test]
    fn with_durability_layout_sets_field() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let cfg = QuorumWriteConfig::default().with_durability_layout(layout);
        assert!(cfg.durability_layout.is_some());
        assert_eq!(cfg.durability_layout.unwrap().policy.total_shards(), 3);
    }

    #[test]
    fn quorum_from_layout_mirror_full() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let cfg = QuorumWriteConfig::default()
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumFull);
        let qc = cfg.quorum_from_layout().unwrap();
        assert_eq!(qc.n(), 3);
        assert_eq!(qc.w(), 3);
    }

    #[test]
    fn quorum_from_layout_mirror_witness() {
        let layout = DurabilityLayoutV1::mirror(5).unwrap();
        let cfg = QuorumWriteConfig::default()
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumWitness);
        let qc = cfg.quorum_from_layout().unwrap();
        assert_eq!(qc.n(), 5);
        assert_eq!(qc.w(), 3); // 5/2+1 = 3
    }

    #[test]
    fn quorum_from_layout_erasure_full() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let cfg = QuorumWriteConfig::default()
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumFull);
        let qc = cfg.quorum_from_layout().unwrap();
        assert_eq!(qc.n(), 6); // 4+2
        assert_eq!(qc.w(), 6);
    }

    #[test]
    fn quorum_from_layout_none_when_no_layout() {
        let cfg = QuorumWriteConfig::default();
        assert!(cfg.quorum_from_layout().is_none());
    }

    #[test]
    fn quorum_from_layout_erasure_witness() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let cfg = QuorumWriteConfig::default()
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumWitness);
        let qc = cfg.quorum_from_layout().unwrap();
        assert_eq!(qc.n(), 11); // 8+3
        assert_eq!(qc.w(), 6); // 11/2+1 = 6
    }
}

// ── WriteQuorumConfig: (N, W) quorum threshold ────────────────────────

/// Write quorum configuration: (N, W) tuple defining total replicas
/// and the minimum acknowledgement count required for quorum.
///
/// Invariant: `1 <= W <= N` and `N >= 1`.
/// `N=0` is rejected at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteQuorumConfig {
    /// Total number of replicas (N).
    pub total_replicas: usize,
    /// Minimum acknowledgements required for quorum (W).
    pub write_quorum: usize,
}

impl WriteQuorumConfig {
    /// Create a validated (N, W) config.
    ///
    /// Returns `Err` if `W == 0`, `W > N`, or `N == 0`.
    pub fn new(total_replicas: usize, write_quorum: usize) -> Result<Self, &'static str> {
        if total_replicas == 0 {
            return Err("total_replicas must be at least 1");
        }
        if write_quorum == 0 {
            return Err("write_quorum must be at least 1");
        }
        if write_quorum > total_replicas {
            return Err("write_quorum cannot exceed total_replicas");
        }
        Ok(Self {
            total_replicas,
            write_quorum,
        })
    }

    #[must_use]
    pub const fn n(self) -> usize {
        self.total_replicas
    }

    #[must_use]
    pub const fn w(self) -> usize {
        self.write_quorum
    }

    /// Whether `ack_count` acknowledgements satisfy the write quorum.
    #[must_use]
    pub const fn is_quorum_met(self, ack_count: usize) -> bool {
        ack_count >= self.write_quorum
    }

    /// Whether quorum is impossible given `alive_count` remaining replicas.
    #[must_use]
    pub fn quorum_impossible(self, alive_count: usize) -> bool {
        alive_count < self.write_quorum
    }

    // ── Convenience presets ─────────────────────────────────────────

    /// Single-replica config: N=1, W=1.
    #[must_use]
    pub const fn single_replica() -> Self {
        Self {
            total_replicas: 1,
            write_quorum: 1,
        }
    }

    /// Majority quorum for `n` replicas: W = n/2 + 1.
    #[must_use]
    pub const fn majority_of(n: usize) -> Self {
        Self {
            total_replicas: n,
            write_quorum: n / 2 + 1,
        }
    }
}

#[cfg(test)]
mod write_quorum_config_tests {
    use super::*;

    #[test]
    fn valid_n3_w2() {
        let c = WriteQuorumConfig::new(3, 2).unwrap();
        assert_eq!(c.n(), 3);
        assert_eq!(c.w(), 2);
    }

    #[test]
    fn n_equals_w() {
        let c = WriteQuorumConfig::new(3, 3).unwrap();
        assert!(c.is_quorum_met(3));
        assert!(!c.is_quorum_met(2));
    }

    #[test]
    fn w_must_be_at_least_1() {
        assert!(WriteQuorumConfig::new(3, 0).is_err());
    }

    #[test]
    fn w_cannot_exceed_n() {
        assert!(WriteQuorumConfig::new(2, 3).is_err());
    }

    #[test]
    fn n_zero_rejected() {
        assert!(WriteQuorumConfig::new(0, 1).is_err());
    }

    #[test]
    fn is_quorum_met_exact_threshold() {
        let c = WriteQuorumConfig::new(5, 3).unwrap();
        assert!(c.is_quorum_met(3));
        assert!(c.is_quorum_met(5));
        assert!(!c.is_quorum_met(2));
    }

    #[test]
    fn quorum_impossible_when_too_many_failures() {
        let c = WriteQuorumConfig::new(5, 3).unwrap();
        assert!(c.quorum_impossible(2));
        assert!(!c.quorum_impossible(3));
        assert!(!c.quorum_impossible(4));
    }

    #[test]
    fn single_replica_preset() {
        let c = WriteQuorumConfig::single_replica();
        assert_eq!(c.n(), 1);
        assert_eq!(c.w(), 1);
        assert!(c.is_quorum_met(1));
        assert!(!c.is_quorum_met(0));
    }

    #[test]
    fn majority_of_presets() {
        assert_eq!(WriteQuorumConfig::majority_of(3).w(), 2);
        assert_eq!(WriteQuorumConfig::majority_of(4).w(), 3);
        assert_eq!(WriteQuorumConfig::majority_of(5).w(), 3);
        assert_eq!(WriteQuorumConfig::majority_of(1).w(), 1);
    }

    #[test]
    fn clone_and_eq() {
        let a = WriteQuorumConfig::new(3, 2).unwrap();
        let b = a;
        assert_eq!(a, b);
        let c = WriteQuorumConfig::new(3, 3).unwrap();
        assert_ne!(a, c);
    }
}
