//! Performance budget runtime gate -- turns P10/A16 design laws into
//! benchmark receipts and comparator decisions.

pub mod baseline_package;
pub mod benchmark_harness;
pub mod comparator_harness;
pub mod consolidation;
pub mod degradation_budget;
pub mod validation_tier;
pub mod fuse_fio_harness;
pub mod gate_entry;
pub mod matrix;
pub mod metadata_harness;
pub mod runner;
#[cfg(feature = "fuse")]
pub mod scrub_repair_harness;
pub mod system_info;

pub use comparator_harness::{
    ComparatorHarness, ComparatorKind, ComparatorManifest, ComparatorRun,
};
pub use consolidation::{
    subject_lane, ConsolidatedMatrix, ConsolidatedRow, LaneSummary, SubjectLane,
};
pub use validation_tier::ValidationTier;
pub use gate_entry::{
    default_numeric_budget_for, BudgetBucket, BudgetClass, BudgetDecision, ComparatorRef,
    EnvironmentManifest, MeasurementSource, MultiNodeDegradationBudget, NoisePolicy, NumericBudget,
    PerformanceGateEntry, RegressionLock, RowStatus, WorkloadEnvelope,
};
pub use matrix::PerformanceMatrix;
pub use runner::{GateReceipt, GateRunner, RunVerdict};
pub use baseline_package::{build_receipt_from_baseline, build_receipt_from_baseline_and_current, load_baseline_package, BaselinePackage, CurrentRunEntry, CurrentRunManifest};
#[cfg(feature = "transport")]
pub mod snapshot_send_receive_harness;
pub mod transport_harness;
