// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool label update abstraction for node drain completion.
//!
//! After a node is drained and decommissioned, its devices must be removed
//! from pool labels so that subsequent pool imports do not attempt to
//! rediscover the evacuated devices.
//!
//! Production implementations of [`PoolLabelOps`] wire this to
//! `tidefs-types-pool-label-core`'s `remove_device_from_label()` and
//! label persistence. Test implementations use mocks.

use std::fmt;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// PoolLabelError
// ---------------------------------------------------------------------------

/// Errors returned by pool label operations during node drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolLabelError {
    /// Failed to remove a device from the pool label.
    LabelUpdateFailed { node_id: MemberId, reason: String },
    /// The pool label is not in a state that permits device removal.
    PoolNotWritable {
        node_id: MemberId,
        pool_state: String,
    },
    /// No devices were found for the drained node.
    NoDevicesFound { node_id: MemberId },
}

impl fmt::Display for PoolLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabelUpdateFailed { node_id, reason } => {
                write!(f, "node {} pool label update failed: {}", node_id.0, reason)
            }
            Self::PoolNotWritable {
                node_id,
                pool_state,
            } => {
                write!(
                    f,
                    "node {} pool not writable (state={})",
                    node_id.0, pool_state
                )
            }
            Self::NoDevicesFound { node_id } => {
                write!(
                    f,
                    "node {} pool label: no devices found for drained node",
                    node_id.0
                )
            }
        }
    }
}

impl std::error::Error for PoolLabelError {}

// ---------------------------------------------------------------------------
// PoolLabelOps trait
// ---------------------------------------------------------------------------

/// Operations for updating pool labels after a successful node drain.
///
/// Production implementations call `tidefs-types-pool-label-core` to
/// mark devices as removed, re-seal labels with BLAKE3 checksums, and
/// persist the updated labels to each remaining device.
pub trait PoolLabelOps {
    /// Return the number of devices belonging to the drained node.
    fn device_count_for_node(&self, node_id: MemberId) -> u64;

    /// Mark all devices belonging to the drained node as removed in pool
    /// labels. Returns the number of devices updated.
    fn remove_node_devices_from_labels(&mut self, node_id: MemberId)
        -> Result<u64, PoolLabelError>;

    /// Verify that all devices for the drained node have been removed from
    /// pool labels.
    fn verify_devices_removed(&self, node_id: MemberId) -> Result<bool, PoolLabelError>;
}

// ---------------------------------------------------------------------------
// DrainPoolLabelUpdater
// ---------------------------------------------------------------------------

/// Orchestrates pool label updates after a successful node drain.
///
/// Usage:
/// 1. Call [`update_labels()`] to remove all of the drained node's devices
///    from pool labels.
/// 2. Call [`verify()`] to confirm the labels were updated correctly.
/// 3. Use [`result()`] for a summary [`PoolLabelResult`].
pub struct DrainPoolLabelUpdater {
    node_id: MemberId,
    devices_removed: u64,
    verified: bool,
}

impl DrainPoolLabelUpdater {
    /// Create a new updater for a drained node.
    #[must_use]
    pub fn new(node_id: MemberId) -> Self {
        Self {
            node_id,
            devices_removed: 0,
            verified: false,
        }
    }

    #[must_use]
    pub fn node_id(&self) -> MemberId {
        self.node_id
    }

    #[must_use]
    pub fn devices_removed(&self) -> u64 {
        self.devices_removed
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Remove all of the drained node's devices from pool labels.
    pub fn update_labels(&mut self, ops: &mut dyn PoolLabelOps) -> Result<u64, PoolLabelError> {
        // Get device count first
        let device_count = ops.device_count_for_node(self.node_id);

        if device_count == 0 {
            // No devices to update — this is fine (observing node with no
            // devices, or pre-evacuated)
            self.devices_removed = 0;
            self.verified = true;
            return Ok(0);
        }

        // Remove devices from labels
        let removed = ops.remove_node_devices_from_labels(self.node_id)?;
        self.devices_removed = removed;

        // Verify the update
        let all_removed = ops.verify_devices_removed(self.node_id).map_err(|e| {
            PoolLabelError::LabelUpdateFailed {
                node_id: self.node_id,
                reason: format!("verification after removal failed: {e}"),
            }
        })?;

        if !all_removed {
            return Err(PoolLabelError::LabelUpdateFailed {
                node_id: self.node_id,
                reason: format!(
                    "{} devices still present after attempted removal",
                    device_count.saturating_sub(removed)
                ),
            });
        }

        self.verified = true;
        Ok(removed)
    }

    /// Return a summary result.
    #[must_use]
    pub fn result(&self) -> PoolLabelResult {
        PoolLabelResult {
            node_id: self.node_id,
            devices_removed: self.devices_removed,
            verified: self.verified,
        }
    }
}

// ---------------------------------------------------------------------------
// PoolLabelResult
// ---------------------------------------------------------------------------

/// Summary of pool label updates after node drain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolLabelResult {
    pub node_id: MemberId,
    pub devices_removed: u64,
    pub verified: bool,
}

impl PoolLabelResult {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.verified
    }
}

// ---------------------------------------------------------------------------
// NoOpPoolLabelOps — default pass-through for testing
// ---------------------------------------------------------------------------

/// A no-op implementation of [`PoolLabelOps`] that always passes.
/// Useful as a default or when label updates are deferred.
pub struct NoOpPoolLabelOps;

impl PoolLabelOps for NoOpPoolLabelOps {
    fn device_count_for_node(&self, _node_id: MemberId) -> u64 {
        0
    }

    fn remove_node_devices_from_labels(
        &mut self,
        _node_id: MemberId,
    ) -> Result<u64, PoolLabelError> {
        Ok(0)
    }

    fn verify_devices_removed(&self, _node_id: MemberId) -> Result<bool, PoolLabelError> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // -------------------------------------------------------------------
    // MockPoolLabelOps
    // -------------------------------------------------------------------

    struct MockPoolLabelOps {
        device_count: u64,
        removal_succeeds: bool,
        removal_count: u64,
        verification_passes: bool,
        removed_devices: Vec<u64>,
    }

    impl MockPoolLabelOps {
        fn new() -> Self {
            Self {
                device_count: 0,
                removal_succeeds: true,
                removal_count: 0,
                verification_passes: true,
                removed_devices: Vec::new(),
            }
        }

        fn with_devices(mut self, count: u64) -> Self {
            self.device_count = count;
            self.removal_count = count;
            self
        }

        fn with_removal_failure(mut self) -> Self {
            self.removal_succeeds = false;
            self
        }

        fn with_verification_failure(mut self) -> Self {
            self.verification_passes = false;
            self
        }
    }

    impl PoolLabelOps for MockPoolLabelOps {
        fn device_count_for_node(&self, _node_id: MemberId) -> u64 {
            self.device_count
        }

        fn remove_node_devices_from_labels(
            &mut self,
            node_id: MemberId,
        ) -> Result<u64, PoolLabelError> {
            if !self.removal_succeeds {
                return Err(PoolLabelError::LabelUpdateFailed {
                    node_id,
                    reason: "simulated removal failure".to_string(),
                });
            }
            for i in 0..self.removal_count {
                self.removed_devices.push(node_id.0 * 100 + i);
            }
            Ok(self.removal_count)
        }

        fn verify_devices_removed(&self, node_id: MemberId) -> Result<bool, PoolLabelError> {
            if self.verification_passes {
                // In verification-passes mode, check that removed == count
                Ok(self.removed_devices.len() as u64 == self.device_count)
            } else {
                Err(PoolLabelError::LabelUpdateFailed {
                    node_id,
                    reason: "verification failed".to_string(),
                })
            }
        }
    }

    // -------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------

    #[test]
    fn pool_label_update_no_devices() {
        let mut ops = MockPoolLabelOps::new();
        let mut updater = DrainPoolLabelUpdater::new(nid(1));
        let removed = updater.update_labels(&mut ops).unwrap();
        assert_eq!(removed, 0);
        assert!(updater.is_verified());
    }

    #[test]
    fn pool_label_update_with_devices() {
        let mut ops = MockPoolLabelOps::new().with_devices(3);
        let mut updater = DrainPoolLabelUpdater::new(nid(2));
        let removed = updater.update_labels(&mut ops).unwrap();
        assert_eq!(removed, 3);
        assert!(updater.is_verified());
        assert_eq!(updater.devices_removed(), 3);
        assert_eq!(ops.removed_devices.len(), 3);
    }

    #[test]
    fn pool_label_update_removal_failure() {
        let mut ops = MockPoolLabelOps::new()
            .with_devices(2)
            .with_removal_failure();
        let mut updater = DrainPoolLabelUpdater::new(nid(3));
        let err = updater.update_labels(&mut ops).unwrap_err();
        assert!(matches!(err, PoolLabelError::LabelUpdateFailed { .. }));
        assert!(!updater.is_verified());
    }

    #[test]
    fn pool_label_update_verification_failure() {
        let mut ops = MockPoolLabelOps::new()
            .with_devices(2)
            .with_verification_failure();
        let mut updater = DrainPoolLabelUpdater::new(nid(4));
        let err = updater.update_labels(&mut ops).unwrap_err();
        assert!(matches!(err, PoolLabelError::LabelUpdateFailed { .. }));
        assert!(!updater.is_verified());
    }

    #[test]
    fn pool_label_result_complete() {
        let mut ops = MockPoolLabelOps::new().with_devices(4);
        let mut updater = DrainPoolLabelUpdater::new(nid(5));
        updater.update_labels(&mut ops).unwrap();

        let result = updater.result();
        assert!(result.is_complete());
        assert_eq!(result.devices_removed, 4);
        assert!(result.verified);
    }

    #[test]
    fn pool_label_result_incomplete() {
        let mut ops = MockPoolLabelOps::new()
            .with_devices(2)
            .with_removal_failure();
        let mut updater = DrainPoolLabelUpdater::new(nid(6));
        let _ = updater.update_labels(&mut ops);

        let result = updater.result();
        assert!(!result.is_complete());
        assert_eq!(result.devices_removed, 0);
    }

    #[test]
    fn noop_pool_label_ops_always_passes() {
        let mut ops = NoOpPoolLabelOps;
        let mut updater = DrainPoolLabelUpdater::new(nid(99));
        assert!(updater.update_labels(&mut ops).is_ok());
        assert!(updater.is_verified());
        assert_eq!(updater.devices_removed(), 0);
    }
}
