// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Replication health verification for node drain.
//!
//! After data evacuation completes, the [`DrainHealthVerifier`] validates
//! that zero replicas remain on the draining node and that every object
//! meets its durability requirements against the replication model.
//!
//! Production implementations of [`HealthVerifyOps`] wire this to
//! `tidefs-replication-model` and the live object-store. Test
//! implementations use mocks.

use std::fmt;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// HealthVerifyError
// ---------------------------------------------------------------------------

/// Errors returned by drain health verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthVerifyError {
    /// Objects still remain on the draining node after evacuation.
    ObjectsRemaining { node_id: MemberId, count: u64 },
    /// Durability requirements are not met after evacuation.
    DurabilityViolation { node_id: MemberId, detail: String },
    /// Verification failed due to an internal error.
    InternalError { node_id: MemberId, reason: String },
}

impl fmt::Display for HealthVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectsRemaining { node_id, count } => {
                write!(
                    f,
                    "node {} health verify: {} objects still remain after evacuation",
                    node_id.0, count
                )
            }
            Self::DurabilityViolation { node_id, detail } => {
                write!(
                    f,
                    "node {} health verify: durability violation: {}",
                    node_id.0, detail
                )
            }
            Self::InternalError { node_id, reason } => {
                write!(
                    f,
                    "node {} health verify internal error: {}",
                    node_id.0, reason
                )
            }
        }
    }
}

impl std::error::Error for HealthVerifyError {}

// ---------------------------------------------------------------------------
// HealthVerifyOps trait
// ---------------------------------------------------------------------------

/// Operations for verifying replication health after node evacuation.
///
/// Production implementations query `tidefs-replication-model`'s
/// `DurabilityLevel` assessment to confirm that every object projected
/// onto the draining node has been relocated and meets its durability
/// requirements.
pub trait HealthVerifyOps {
    /// Return the number of objects that still have replicas on the
    /// draining node after attempted evacuation.
    fn objects_remaining_on_node(&self, node_id: MemberId) -> u64;

    /// Verify that no objects have replicas remaining on the draining node
    /// and that all objects meet their durability requirements.
    ///
    /// Returns `Ok(())` when the node is fully evacuated with intact
    /// durability, or a [`HealthVerifyError`] describing the violation.
    fn verify_node_evacuated(
        &self,
        node_id: MemberId,
        target_nodes: &[MemberId],
    ) -> Result<(), HealthVerifyError>;

    /// Check that every object meets its minimum durability requirement
    /// (replica count or erasure-coding parity) after relocation.
    fn verify_durability_health(
        &self,
        node_id: MemberId,
        target_nodes: &[MemberId],
    ) -> Result<(), HealthVerifyError>;
}

// ---------------------------------------------------------------------------
// DrainHealthVerifier
// ---------------------------------------------------------------------------

/// Orchestrates replication health verification after data evacuation.
///
/// Usage:
/// 1. Call [`verify_evacuation()`] to confirm zero replicas remain on the
///    draining node.
/// 2. Call [`verify_durability()`] to confirm all objects meet their
///    durability requirements.
/// 3. Use [`result()`] for a summary [`HealthVerifyResult`].
pub struct DrainHealthVerifier {
    node_id: MemberId,
    verified: bool,
    objects_checked: u64,
    violations: Vec<String>,
}

impl DrainHealthVerifier {
    /// Create a new verifier for a draining node.
    #[must_use]
    pub fn new(node_id: MemberId) -> Self {
        Self {
            node_id,
            verified: false,
            objects_checked: 0,
            violations: Vec::new(),
        }
    }

    #[must_use]
    pub fn node_id(&self) -> MemberId {
        self.node_id
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    #[must_use]
    pub fn objects_checked(&self) -> u64 {
        self.objects_checked
    }

    #[must_use]
    pub fn violations(&self) -> &[String] {
        &self.violations
    }

    /// Verify that the draining node has zero remaining replicas and that
    /// durability health is intact.
    pub fn verify(
        &mut self,
        ops: &dyn HealthVerifyOps,
        target_nodes: &[MemberId],
    ) -> Result<(), HealthVerifyError> {
        // Step 1: Check for objects remaining on the draining node
        let remaining = ops.objects_remaining_on_node(self.node_id);
        self.objects_checked = remaining;

        if remaining > 0 {
            self.violations.push(format!(
                "{} objects still have replicas on node {}",
                remaining, self.node_id.0
            ));
            return Err(HealthVerifyError::ObjectsRemaining {
                node_id: self.node_id,
                count: remaining,
            });
        }

        // Step 2: Verify evacuation completeness
        ops.verify_node_evacuated(self.node_id, target_nodes)?;

        // Step 3: Verify durability health for all relocated objects
        ops.verify_durability_health(self.node_id, target_nodes)?;

        self.verified = true;
        Ok(())
    }

    /// Run a fast durability-only check (used after a successful evacuation
    /// verification).
    pub fn verify_durability_only(
        &mut self,
        ops: &dyn HealthVerifyOps,
        target_nodes: &[MemberId],
    ) -> Result<(), HealthVerifyError> {
        ops.verify_durability_health(self.node_id, target_nodes)?;
        Ok(())
    }

    /// Return a summary result.
    #[must_use]
    pub fn result(&self) -> HealthVerifyResult {
        HealthVerifyResult {
            node_id: self.node_id,
            verified: self.verified,
            objects_checked: self.objects_checked,
            violation_count: self.violations.len() as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// HealthVerifyResult
// ---------------------------------------------------------------------------

/// Summary of a drain health verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthVerifyResult {
    pub node_id: MemberId,
    pub verified: bool,
    pub objects_checked: u64,
    pub violation_count: u64,
}

impl HealthVerifyResult {
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.verified && self.violation_count == 0
    }
}

// ---------------------------------------------------------------------------
// NoOpHealthVerifyOps — default pass-through for testing
// ---------------------------------------------------------------------------

/// A no-op implementation of [`HealthVerifyOps`] that always passes.
/// Useful as a default or when verification is deferred.
pub struct NoOpHealthVerifyOps;

impl HealthVerifyOps for NoOpHealthVerifyOps {
    fn objects_remaining_on_node(&self, _node_id: MemberId) -> u64 {
        0
    }

    fn verify_node_evacuated(
        &self,
        _node_id: MemberId,
        _target_nodes: &[MemberId],
    ) -> Result<(), HealthVerifyError> {
        Ok(())
    }

    fn verify_durability_health(
        &self,
        _node_id: MemberId,
        _target_nodes: &[MemberId],
    ) -> Result<(), HealthVerifyError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // -------------------------------------------------------------------
    // MockHealthVerifyOps
    // -------------------------------------------------------------------

    struct MockHealthVerifyOps {
        objects_remaining: u64,
        evacuation_passes: bool,
        durability_passes: bool,
        durability_detail: String,
    }

    impl MockHealthVerifyOps {
        fn new() -> Self {
            Self {
                objects_remaining: 0,
                evacuation_passes: true,
                durability_passes: true,
                durability_detail: String::new(),
            }
        }

        fn with_remaining(mut self, count: u64) -> Self {
            self.objects_remaining = count;
            self
        }

        fn with_evacuation_failure(mut self) -> Self {
            self.evacuation_passes = false;
            self
        }

        fn with_durability_violation(mut self, detail: &str) -> Self {
            self.durability_passes = false;
            self.durability_detail = detail.to_string();
            self
        }
    }

    impl HealthVerifyOps for MockHealthVerifyOps {
        fn objects_remaining_on_node(&self, _node_id: MemberId) -> u64 {
            self.objects_remaining
        }

        fn verify_node_evacuated(
            &self,
            node_id: MemberId,
            _target_nodes: &[MemberId],
        ) -> Result<(), HealthVerifyError> {
            if self.evacuation_passes {
                Ok(())
            } else {
                Err(HealthVerifyError::ObjectsRemaining {
                    node_id,
                    count: self.objects_remaining,
                })
            }
        }

        fn verify_durability_health(
            &self,
            node_id: MemberId,
            _target_nodes: &[MemberId],
        ) -> Result<(), HealthVerifyError> {
            if self.durability_passes {
                Ok(())
            } else {
                Err(HealthVerifyError::DurabilityViolation {
                    node_id,
                    detail: self.durability_detail.clone(),
                })
            }
        }
    }

    // -------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------

    #[test]
    fn health_verify_no_objects_remaining() {
        let ops = MockHealthVerifyOps::new();
        let mut verifier = DrainHealthVerifier::new(nid(1));
        let result = verifier.verify(&ops, &[nid(2), nid(3)]);
        assert!(result.is_ok());
        assert!(verifier.is_verified());
        assert_eq!(verifier.objects_checked(), 0);
    }

    #[test]
    fn health_verify_objects_remaining_fails() {
        let ops = MockHealthVerifyOps::new().with_remaining(5);
        let mut verifier = DrainHealthVerifier::new(nid(1));
        let err = verifier.verify(&ops, &[nid(2)]).unwrap_err();
        assert!(matches!(
            err,
            HealthVerifyError::ObjectsRemaining { count: 5, .. }
        ));
        assert!(!verifier.is_verified());
        assert_eq!(verifier.objects_checked(), 5);
    }

    #[test]
    fn health_verify_evacuation_failure() {
        let ops = MockHealthVerifyOps::new().with_evacuation_failure();
        let mut verifier = DrainHealthVerifier::new(nid(1));
        let err = verifier.verify(&ops, &[nid(2)]).unwrap_err();
        assert!(matches!(err, HealthVerifyError::ObjectsRemaining { .. }));
    }

    #[test]
    fn health_verify_durability_violation() {
        let ops = MockHealthVerifyOps::new().with_durability_violation("only 1 replica, need 3");
        let mut verifier = DrainHealthVerifier::new(nid(1));
        let err = verifier.verify(&ops, &[nid(2)]).unwrap_err();
        assert!(matches!(err, HealthVerifyError::DurabilityViolation { .. }));
        assert_eq!(verifier.violations().len(), 0); // no violations recorded on pre-check fail
    }

    #[test]
    fn health_verify_result_summary() {
        let ops = MockHealthVerifyOps::new();
        let mut verifier = DrainHealthVerifier::new(nid(1));
        verifier.verify(&ops, &[nid(2), nid(3)]).unwrap();

        let result = verifier.result();
        assert!(result.is_healthy());
        assert!(result.verified);
        assert_eq!(result.objects_checked, 0);
        assert_eq!(result.violation_count, 0);
    }

    #[test]
    fn health_verify_result_unhealthy() {
        let ops = MockHealthVerifyOps::new().with_remaining(3);
        let mut verifier = DrainHealthVerifier::new(nid(1));
        let _ = verifier.verify(&ops, &[nid(2)]);

        let result = verifier.result();
        assert!(!result.is_healthy());
        assert!(!result.verified);
        assert_eq!(result.violation_count, 1);
    }

    #[test]
    fn noop_health_verify_always_passes() {
        let ops = NoOpHealthVerifyOps;
        let mut verifier = DrainHealthVerifier::new(nid(99));
        assert!(verifier.verify(&ops, &[]).is_ok());
        assert!(verifier.is_verified());
    }

    #[test]
    fn verify_durability_only() {
        let ops = MockHealthVerifyOps::new();
        let mut verifier = DrainHealthVerifier::new(nid(1));
        // Already verified evacuation — durability-only should pass
        verifier.verify(&ops, &[nid(2)]).unwrap();
        assert!(verifier.verify_durability_only(&ops, &[nid(2)]).is_ok());
    }

    #[test]
    fn verify_durability_only_fails_on_violation() {
        let ops = MockHealthVerifyOps::new().with_durability_violation("quorum lost");
        let mut verifier = DrainHealthVerifier::new(nid(1));
        // Simulate state where objects_remaining check passed but durability fails
        // We test directly
        let err = verifier
            .verify_durability_only(&ops, &[nid(2)])
            .unwrap_err();
        assert!(matches!(err, HealthVerifyError::DurabilityViolation { .. }));
    }
}
