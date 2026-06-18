// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Unified release validation outcome classification.
//!
//! Every release validation output must use one of these five statuses
//! consistently so that product failures, harness bugs, environment
//! limitations, intentional skips, and genuine passes are never conflated.
//!
//! # Variant semantics
//!
//! | Variant              | Meaning |
//! |----------------------|---------|
//! | `ValidationStatus::Pass`               | The product behaved correctly and the harness recorded a clean execution. |
//! | `ValidationStatus::ProductFail`        | The TideFS product code itself returned wrong data, hung, crashed, or violated a correctness contract. |
//! | `ValidationStatus::HarnessFail`        | The test harness, validation script, or measurement tooling failed, not the product. |
//! | `ValidationStatus::EnvironmentRefusal` | The environment refused the workload (missing /dev/fuse, /dev/kvm, kernel module, RDMA device, etc.). Not a product defect. |
//! | `ValidationStatus::Skip`               | The validation row was intentionally not exercised for this tier, configuration, or run. |
//!
//! # Tier compatibility
//!
//! - `Pass` rows for live-runtime tiers (mounted userspace, QEMU guest,
//!   Kbuild, mounted kernel VFS, kernel block I/O, full-kernel no-daemon,
//!   multi-process distributed) must carry a concrete
//!   `RuntimeArtifactSource`.
//! - `EnvironmentRefusal` rows must name the missing environment primitive.
//! - `ProductFail` and `HarnessFail` rows should carry the failing command
//!   output or assertion.
//! - `Skip` rows should state the reason (tier out of scope, not yet wired,
//!   intentionally deferred).

use serde::{Deserialize, Serialize};

/// Unified outcome for a single release validation row.
///
/// Every validation row -- whether it comes from a cargo test, a FUSE mount, a
/// QEMU guest, a kernel module load, or a multi-node scenario -- must report
/// exactly one of these five statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationStatus {
    /// Product behaved correctly; harness recorded clean execution.
    Pass,
    /// TideFS code is defective (wrong output, crash, hang, contract violation).
    ProductFail,
    /// Harness/tooling/script is defective, not the product.
    HarnessFail,
    /// Environment cannot satisfy the workload (missing device, kernel feature,
    /// hardware, or privilege).
    EnvironmentRefusal,
    /// Intentionally not exercised for this tier/run.
    Skip,
}

impl ValidationStatus {
    /// Short label for display and summary tables.
    pub fn label(&self) -> &'static str {
        match self {
            ValidationStatus::Pass => "PASS",
            ValidationStatus::ProductFail => "PRODUCT_FAIL",
            ValidationStatus::HarnessFail => "HARNESS_FAIL",
            ValidationStatus::EnvironmentRefusal => "ENV_REFUSAL",
            ValidationStatus::Skip => "SKIP",
        }
    }

    /// Whether this outcome counts as a successful product execution.
    pub fn is_pass(&self) -> bool {
        matches!(self, ValidationStatus::Pass)
    }

    /// Whether this outcome represents a product defect.
    pub fn is_product_fail(&self) -> bool {
        matches!(self, ValidationStatus::ProductFail)
    }

    /// Whether this outcome represents a harness/infrastructure defect.
    pub fn is_harness_fail(&self) -> bool {
        matches!(self, ValidationStatus::HarnessFail)
    }

    /// Whether the environment prevented execution.
    pub fn is_environment_refusal(&self) -> bool {
        matches!(self, ValidationStatus::EnvironmentRefusal)
    }

    /// Whether this row was intentionally skipped.
    pub fn is_skip(&self) -> bool {
        matches!(self, ValidationStatus::Skip)
    }

    /// Whether this outcome is any kind of failure (product or harness).
    pub fn is_any_fail(&self) -> bool {
        matches!(
            self,
            ValidationStatus::ProductFail | ValidationStatus::HarnessFail
        )
    }

    /// Whether this outcome blocks a release gate.
    /// Product failures and harness failures both block; environment refusals
    /// and skips do not.
    pub fn blocks_gate(&self) -> bool {
        self.is_any_fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_is_only_success() {
        assert!(ValidationStatus::Pass.is_pass());
        assert!(!ValidationStatus::ProductFail.is_pass());
        assert!(!ValidationStatus::HarnessFail.is_pass());
        assert!(!ValidationStatus::EnvironmentRefusal.is_pass());
        assert!(!ValidationStatus::Skip.is_pass());
    }

    #[test]
    fn fail_variants_block_gate() {
        assert!(ValidationStatus::ProductFail.blocks_gate());
        assert!(ValidationStatus::HarnessFail.blocks_gate());
        assert!(!ValidationStatus::Pass.blocks_gate());
        assert!(!ValidationStatus::EnvironmentRefusal.blocks_gate());
        assert!(!ValidationStatus::Skip.blocks_gate());
    }

    #[test]
    fn labels_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for s in &[
            ValidationStatus::Pass,
            ValidationStatus::ProductFail,
            ValidationStatus::HarnessFail,
            ValidationStatus::EnvironmentRefusal,
            ValidationStatus::Skip,
        ] {
            assert!(seen.insert(s.label()), "duplicate label: {}", s.label());
        }
    }

    #[test]
    fn json_roundtrip_all_variants() {
        let variants = [
            ValidationStatus::Pass,
            ValidationStatus::ProductFail,
            ValidationStatus::HarnessFail,
            ValidationStatus::EnvironmentRefusal,
            ValidationStatus::Skip,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ValidationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back, "roundtrip failed for {v:?}");
        }
    }

    #[test]
    fn serde_uses_kebab_case() {
        assert_eq!(
            serde_json::to_string(&ValidationStatus::ProductFail).unwrap(),
            "\"product-fail\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationStatus::HarnessFail).unwrap(),
            "\"harness-fail\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationStatus::EnvironmentRefusal).unwrap(),
            "\"environment-refusal\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationStatus::Skip).unwrap(),
            "\"skip\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationStatus::Pass).unwrap(),
            "\"pass\""
        );
    }

    #[test]
    fn is_any_fail_covers_both_fail_variants() {
        assert!(ValidationStatus::ProductFail.is_any_fail());
        assert!(ValidationStatus::HarnessFail.is_any_fail());
        assert!(!ValidationStatus::Pass.is_any_fail());
        assert!(!ValidationStatus::EnvironmentRefusal.is_any_fail());
        assert!(!ValidationStatus::Skip.is_any_fail());
    }
}
