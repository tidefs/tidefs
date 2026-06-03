//! Runtime POSIX guarantee verifier.
//!
//! Ensures that the active coordination strategy for an inode or block
//! satisfies the ordering and concurrency guarantees required by each
//! POSIX operation class. Without runtime verification, a strategy
//! transition bug could silently allow an operation under a strategy
//! whose capabilities are insufficient, violating POSIX semantics.
//!
//! # Example
//!
//! ```ignore
//! use tidefs_coordination_strategy::{CoordinationStrategy, PosixOperationClass};
//! use tidefs_posix_guarantee_verifier::POSIXGuaranteeVerifier;
//!
//! let verifier = POSIXGuaranteeVerifier::new();
//! // A rename under Optimistic (no ordering) is a violation.
//! assert!(verifier.verify(
//!     CoordinationStrategy::Optimistic,
//!     PosixOperationClass::Rename,
//!     "inode:42"
//! ).is_err());
//! ```

use tidefs_coordination_strategy::{CoordinationStrategy, OrderingGuarantee, PosixOperationClass};

// ---------------------------------------------------------------------------
// Violation
// ---------------------------------------------------------------------------

/// Describes a POSIX guarantee violation detected at runtime.
///
/// A violation occurs when a POSIX operation is dispatched under a
/// coordination strategy whose capabilities do not satisfy the
/// operation's ordering requirements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The strategy that was active when the violation occurred.
    pub strategy: CoordinationStrategy,
    /// The operation class that was attempted.
    pub operation: PosixOperationClass,
    /// The ordering guarantee required by the operation.
    pub required_guarantee: OrderingGuarantee,
    /// The ordering guarantee actually provided by the strategy.
    pub actual_guarantee: OrderingGuarantee,
    /// Identifier for the object (inode number, block address, etc.).
    pub object_id: String,
    /// Human-readable description of the violation.
    pub description: String,
}

impl Violation {
    /// Create a new violation record.
    /// Create a new violation record.
    pub fn new(
        strategy: CoordinationStrategy,
        operation: PosixOperationClass,
        object_id: impl Into<String>,
    ) -> Self {
        let object_id: String = object_id.into();
        let caps = strategy.capabilities();
        let required = operation.required_guarantee();
        let actual = caps.ordering_guarantee;
        let description = format!(
            "POSIX guarantee violation: {operation:?} requires {required:?} \
             ordering but active strategy {strategy:?} only provides {actual:?} \
             for object {object_id}",
        );
        Self {
            strategy,
            operation,
            required_guarantee: required,
            actual_guarantee: actual,
            object_id,
            description,
        }
    }
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.description)
    }
}

impl std::error::Error for Violation {}

// ---------------------------------------------------------------------------
// VerificationResult
// ---------------------------------------------------------------------------

/// Shorthand result type for verification operations.
pub type VerificationResult = Result<(), Violation>;

// ---------------------------------------------------------------------------
// POSIXGuaranteeVerifier
// ---------------------------------------------------------------------------

/// Runtime verifier that gates POSIX operations on strategy capabilities.
///
/// Before dispatching a POSIX operation (write, truncate, rename, link,
/// unlink, lock), call [`verify`](Self::verify) with the active strategy
/// and the operation class. Returns `Ok(())` if the strategy is sufficient,
/// or `Err(Violation)` if the operation cannot be safely executed.
///
/// The verifier is zero-allocation for the common (success) path.
#[derive(Clone, Debug, Default)]
pub struct POSIXGuaranteeVerifier {
    /// Count of successful verifications (observability).
    pub success_count: u64,
    /// Count of violations detected (observability).
    pub violation_count: u64,
}

impl POSIXGuaranteeVerifier {
    /// Create a new verifier with zeroed counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify that `strategy` satisfies the requirements of `operation`
    /// for the given `object_id`.
    ///
    /// Returns `Ok(())` if the operation can proceed, or `Err(Violation)`
    /// with a structured error describing the mismatch.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut v = POSIXGuaranteeVerifier::new();
    /// // Write under Lease is OK (Lease provides CausalOrder).
    /// assert!(v.verify(
    ///     CoordinationStrategy::Lease,
    ///     PosixOperationClass::Write,
    ///     "inode:1"
    /// ).is_ok());
    /// // Rename under TDMA violates POSIX (needs TotalOrder).
    /// assert!(v.verify(
    ///     CoordinationStrategy::TDMA,
    ///     PosixOperationClass::Rename,
    ///     "inode:1"
    /// ).is_err());
    /// ```
    pub fn verify(
        &mut self,
        strategy: CoordinationStrategy,
        operation: PosixOperationClass,
        object_id: impl Into<String>,
    ) -> VerificationResult {
        let caps = strategy.capabilities();
        if caps.satisfies(operation) {
            self.success_count += 1;
            Ok(())
        } else {
            self.violation_count += 1;
            Err(Violation::new(strategy, operation, object_id))
        }
    }

    /// Verify without mutating counters (const-compatible check).
    ///
    /// Useful when an immutable reference to the verifier is needed,
    /// or when verification should not affect observability counters.
    pub fn check(
        strategy: CoordinationStrategy,
        operation: PosixOperationClass,
        object_id: impl Into<String>,
    ) -> VerificationResult {
        let caps = strategy.capabilities();
        if caps.satisfies(operation) {
            Ok(())
        } else {
            Err(Violation::new(strategy, operation, object_id))
        }
    }

    /// Return the total number of verifications performed.
    pub fn total_verifications(&self) -> u64 {
        self.success_count + self.violation_count
    }

    /// Return the violation rate as a fraction (0.0–1.0).
    ///
    /// Returns 0.0 if no verifications have been performed.
    pub fn violation_rate(&self) -> f64 {
        let total = self.total_verifications();
        if total == 0 {
            0.0
        } else {
            self.violation_count as f64 / total as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_coordination_strategy::CoordinationStrategy;

    // ── Violation ────────────────────────────────────────────────────

    #[test]
    fn violation_contains_strategy_and_operation() {
        let v = Violation::new(
            CoordinationStrategy::Optimistic,
            PosixOperationClass::Rename,
            "inode:42",
        );
        assert_eq!(v.strategy, CoordinationStrategy::Optimistic);
        assert_eq!(v.operation, PosixOperationClass::Rename);
        assert_eq!(v.object_id, "inode:42");
        assert_eq!(v.required_guarantee, OrderingGuarantee::TotalOrder);
        assert_eq!(v.actual_guarantee, OrderingGuarantee::None);
    }

    #[test]
    fn violation_display_is_descriptive() {
        let v = Violation::new(
            CoordinationStrategy::Uncontended,
            PosixOperationClass::Write,
            "block:0x1000",
        );
        let s = v.to_string();
        assert!(s.contains("Write"));
        assert!(s.contains("CausalOrder"));
        assert!(s.contains("Uncontended"));
        assert!(s.contains("None"));
        assert!(s.contains("block:0x1000"));
    }

    #[test]
    fn violation_is_error() {
        let v = Violation::new(
            CoordinationStrategy::Optimistic,
            PosixOperationClass::Truncate,
            "inode:7",
        );
        // Verify we can use it as a std::error::Error.
        let err: Box<dyn std::error::Error> = Box::new(v);
        assert!(err.to_string().contains("Truncate"));
    }

    // ── POSIXGuaranteeVerifier::check (const-compatible) ─────────────

    #[test]
    fn check_write_under_lease_passes() {
        assert!(POSIXGuaranteeVerifier::check(
            CoordinationStrategy::Lease,
            PosixOperationClass::Write,
            "inode:1",
        )
        .is_ok());
    }

    #[test]
    fn check_write_under_uncontended_fails() {
        let err = POSIXGuaranteeVerifier::check(
            CoordinationStrategy::Uncontended,
            PosixOperationClass::Write,
            "inode:1",
        )
        .unwrap_err();
        assert_eq!(err.operation, PosixOperationClass::Write);
        assert_eq!(err.required_guarantee, OrderingGuarantee::CausalOrder);
        assert_eq!(err.actual_guarantee, OrderingGuarantee::None);
    }

    #[test]
    fn check_rename_under_lease_fails() {
        let err = POSIXGuaranteeVerifier::check(
            CoordinationStrategy::Lease,
            PosixOperationClass::Rename,
            "inode:2",
        )
        .unwrap_err();
        assert_eq!(err.required_guarantee, OrderingGuarantee::TotalOrder);
    }

    #[test]
    fn check_rename_under_leader_serialized_passes() {
        assert!(POSIXGuaranteeVerifier::check(
            CoordinationStrategy::LeaderSerialized,
            PosixOperationClass::Rename,
            "inode:2",
        )
        .is_ok());
    }

    #[test]
    fn check_lock_satisfied_by_all_strategies() {
        for s in &[
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ] {
            assert!(
                POSIXGuaranteeVerifier::check(*s, PosixOperationClass::Lock, "inode:1").is_ok(),
                "{s:?} should satisfy Lock",
            );
        }
    }

    // ── POSIXGuaranteeVerifier::verify (mutable, counters) ───────────

    #[test]
    fn verify_increments_counters() {
        let mut v = POSIXGuaranteeVerifier::new();
        assert_eq!(v.success_count, 0);
        assert_eq!(v.violation_count, 0);
        assert_eq!(v.total_verifications(), 0);

        // Successful verification.
        assert!(v
            .verify(
                CoordinationStrategy::Lease,
                PosixOperationClass::Write,
                "inode:1"
            )
            .is_ok());
        assert_eq!(v.success_count, 1);
        assert_eq!(v.violation_count, 0);
        assert_eq!(v.total_verifications(), 1);

        // Failed verification.
        assert!(v
            .verify(
                CoordinationStrategy::Uncontended,
                PosixOperationClass::Truncate,
                "inode:2"
            )
            .is_err());
        assert_eq!(v.success_count, 1);
        assert_eq!(v.violation_count, 1);
        assert_eq!(v.total_verifications(), 2);
    }

    #[test]
    fn violation_rate_computation() {
        let mut v = POSIXGuaranteeVerifier::new();
        assert_eq!(v.violation_rate(), 0.0);

        // 1 pass, 0 violations -> 0.0
        v.verify(
            CoordinationStrategy::Lease,
            PosixOperationClass::Write,
            "inode:1",
        )
        .unwrap();
        assert_eq!(v.violation_rate(), 0.0);

        // 1 pass, 1 violation -> 0.5
        let _ = v.verify(
            CoordinationStrategy::Uncontended,
            PosixOperationClass::Write,
            "inode:2",
        );
        assert!((v.violation_rate() - 0.5).abs() < f64::EPSILON);
    }

    // ── Full 6×5 matrix ─────────────────────────────────────────────

    #[test]
    fn full_operation_class_by_strategy_matrix() {
        // Expected results: [strategy][op_class] -> pass?
        // Operations: Write, Truncate, Rename, Link, Unlink, Lock
        #[rustfmt::skip]
        let expected: [[bool; 6]; 5] = [
            // W     T     R     Lk    Ul    Lo
            [false, false, false, false, false, true ], // Uncontended
            [false, false, false, false, false, true ], // Optimistic
            [true,  true,  false, true,  true,  true ], // Lease
            [true,  true,  false, true,  true,  true ], // TDMA
            [true,  true,  true,  true,  true,  true ], // LeaderSerialized
        ];

        let strategies = [
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ];
        let ops = [
            PosixOperationClass::Write,
            PosixOperationClass::Truncate,
            PosixOperationClass::Rename,
            PosixOperationClass::Link,
            PosixOperationClass::Unlink,
            PosixOperationClass::Lock,
        ];

        for (si, strategy) in strategies.iter().enumerate() {
            for (oi, op) in ops.iter().enumerate() {
                let result = POSIXGuaranteeVerifier::check(*strategy, *op, "inode:1");
                let expected_pass = expected[si][oi];
                assert_eq!(
                    result.is_ok(),
                    expected_pass,
                    "{strategy:?} × {op:?}: expected pass={expected_pass}, got is_ok={}",
                    result.is_ok(),
                );
            }
        }
    }

    // ── Verifier lifecycle ──────────────────────────────────────────

    #[test]
    fn verifier_new_zero_counters() {
        let v = POSIXGuaranteeVerifier::new();
        assert_eq!(v.success_count, 0);
        assert_eq!(v.violation_count, 0);
    }

    #[test]
    fn verifier_default_equals_new() {
        let v1 = POSIXGuaranteeVerifier::new();
        let v2 = POSIXGuaranteeVerifier::default();
        assert_eq!(v1.success_count, v2.success_count);
        assert_eq!(v1.violation_count, v2.violation_count);
    }

    #[test]
    fn verifier_clone_preserves_counters() {
        let mut v = POSIXGuaranteeVerifier::new();
        let _ = v.verify(
            CoordinationStrategy::Lease,
            PosixOperationClass::Write,
            "inode:1",
        );
        let v2 = v.clone();
        assert_eq!(v2.success_count, 1);
        assert_eq!(v2.violation_count, 0);
        let _ = format!("{v2:?}");
    }

    #[test]
    fn verifier_debug_does_not_panic() {
        let mut v = POSIXGuaranteeVerifier::new();
        let _ = v.verify(
            CoordinationStrategy::Lease,
            PosixOperationClass::Write,
            "inode:1",
        );
        let _ = v.verify(
            CoordinationStrategy::Optimistic,
            PosixOperationClass::Rename,
            "inode:2",
        );
        let s = format!("{v:?}");
        assert!(!s.is_empty());
    }

    // ── verify edge cases ───────────────────────────────────────────

    #[test]
    fn verify_empty_object_id() {
        let mut v = POSIXGuaranteeVerifier::new();
        assert!(v
            .verify(CoordinationStrategy::Lease, PosixOperationClass::Write, "",)
            .is_ok());
    }

    #[test]
    fn verify_long_object_id() {
        let mut v = POSIXGuaranteeVerifier::new();
        let long_id = "x".repeat(1024);
        assert!(v
            .verify(
                CoordinationStrategy::Lease,
                PosixOperationClass::Write,
                &long_id,
            )
            .is_ok());
    }

    #[test]
    fn verify_success_does_not_affect_violation_count() {
        let mut v = POSIXGuaranteeVerifier::new();
        for _ in 0..5 {
            v.verify(
                CoordinationStrategy::LeaderSerialized,
                PosixOperationClass::Rename,
                "inode:1",
            )
            .unwrap();
        }
        assert_eq!(v.success_count, 5);
        assert_eq!(v.violation_count, 0);
    }

    #[test]
    fn verify_violation_does_not_affect_success_count() {
        let mut v = POSIXGuaranteeVerifier::new();
        for _ in 0..3 {
            let _ = v.verify(
                CoordinationStrategy::Optimistic,
                PosixOperationClass::Rename,
                "inode:1",
            );
        }
        assert_eq!(v.success_count, 0);
        assert_eq!(v.violation_count, 3);
    }

    // ── check does not mutate counters ───────────────────────────────

    #[test]
    fn check_does_not_mutate_verifier_counters() {
        let mut v = POSIXGuaranteeVerifier::new();
        let _ = v.verify(
            CoordinationStrategy::Lease,
            PosixOperationClass::Write,
            "inode:1",
        );
        let before_s = v.success_count;
        let before_v = v.violation_count;

        let _ = POSIXGuaranteeVerifier::check(
            CoordinationStrategy::Lease,
            PosixOperationClass::Write,
            "inode:3",
        );
        let _ = POSIXGuaranteeVerifier::check(
            CoordinationStrategy::Optimistic,
            PosixOperationClass::Rename,
            "inode:4",
        );

        assert_eq!(v.success_count, before_s);
        assert_eq!(v.violation_count, before_v);
    }

    // ── violation_rate edge cases ───────────────────────────────────

    #[test]
    fn violation_rate_zero_when_no_verifications() {
        let v = POSIXGuaranteeVerifier::new();
        assert_eq!(v.violation_rate(), 0.0);
    }

    #[test]
    fn violation_rate_zero_when_all_success() {
        let mut v = POSIXGuaranteeVerifier::new();
        for i in 0..5 {
            v.verify(
                CoordinationStrategy::LeaderSerialized,
                PosixOperationClass::Write,
                format!("inode:{i}"),
            )
            .unwrap();
        }
        assert_eq!(v.violation_rate(), 0.0);
    }

    #[test]
    fn violation_rate_one_when_all_violations() {
        let mut v = POSIXGuaranteeVerifier::new();
        for i in 0..4 {
            let _ = v.verify(
                CoordinationStrategy::Optimistic,
                PosixOperationClass::Rename,
                format!("inode:{i}"),
            );
        }
        assert_eq!(v.violation_rate(), 1.0);
    }

    #[test]
    fn violation_rate_precise_third() {
        let mut v = POSIXGuaranteeVerifier::new();
        let _ = v.verify(
            CoordinationStrategy::Optimistic,
            PosixOperationClass::Rename,
            "inode:1",
        );
        v.verify(
            CoordinationStrategy::Lease,
            PosixOperationClass::Write,
            "inode:1",
        )
        .unwrap();
        v.verify(
            CoordinationStrategy::Lease,
            PosixOperationClass::Link,
            "inode:2",
        )
        .unwrap();
        let expected = 1.0 / 3.0;
        assert!((v.violation_rate() - expected).abs() < f64::EPSILON);
    }

    // ── Violation edge cases ────────────────────────────────────────

    #[test]
    fn violation_empty_object_id() {
        let v = Violation::new(
            CoordinationStrategy::Optimistic,
            PosixOperationClass::Rename,
            "",
        );
        assert_eq!(v.object_id, "");
        assert!(!v.description.is_empty());
    }

    #[test]
    fn violation_clone_is_equal() {
        let v1 = Violation::new(
            CoordinationStrategy::Lease,
            PosixOperationClass::Truncate,
            "inode:7",
        );
        let v2 = v1.clone();
        assert_eq!(v1, v2);
        assert_eq!(v2.strategy, CoordinationStrategy::Lease);
        assert_eq!(v2.operation, PosixOperationClass::Truncate);
    }

    #[test]
    fn violation_debug_does_not_panic() {
        let v = Violation::new(
            CoordinationStrategy::TDMA,
            PosixOperationClass::Rename,
            "inode:1",
        );
        let s = format!("{v:?}");
        assert!(!s.is_empty());
    }

    // ── TDMA vs Rename boundary ─────────────────────────────────────

    #[test]
    fn tdma_fails_rename() {
        let err = POSIXGuaranteeVerifier::check(
            CoordinationStrategy::TDMA,
            PosixOperationClass::Rename,
            "inode:1",
        )
        .unwrap_err();
        assert_eq!(err.required_guarantee, OrderingGuarantee::TotalOrder);
        assert_eq!(err.actual_guarantee, OrderingGuarantee::CausalOrder);
    }

    #[test]
    fn leader_serialized_satisfies_all_six_ops() {
        let ops = [
            PosixOperationClass::Write,
            PosixOperationClass::Truncate,
            PosixOperationClass::Rename,
            PosixOperationClass::Link,
            PosixOperationClass::Unlink,
            PosixOperationClass::Lock,
        ];
        for op in &ops {
            assert!(
                POSIXGuaranteeVerifier::check(
                    CoordinationStrategy::LeaderSerialized,
                    *op,
                    "inode:1",
                )
                .is_ok(),
                "LeaderSerialized must satisfy {op:?}",
            );
        }
    }

    // ── object_id preservation ───────────────────────────────────────

    #[test]
    fn violation_object_id_preserved_variety() {
        let ids = ["", "inode:0", "block:0xDEADBEEF", "x", "inode:999999999999"];
        for id in &ids {
            let v = Violation::new(
                CoordinationStrategy::Optimistic,
                PosixOperationClass::Rename,
                *id,
            );
            assert_eq!(v.object_id, *id);
        }
    }
}
