//! P5-02 FUSE observe lane: validation sink handoff from maintenance.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.
//!
//! Merged from `tidefs-posix-filesystem-adapter-observe` into the daemon
//! runtime module per #3199 crate consolidation (#3232).

use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterId128;
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterBackpressureStateRecord, PosixFilesystemAdapterSurfaceValidationCase,
    PosixFilesystemAdapterValidationStatus, PosixFilesystemAdapterWorkerPoolSizingRecord,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Validation handoff ────────────────────────────────────────────────────────

/// Create an validation handoff record for the observe lane.
///
/// The observe lane receives validation sink handoff from maintenance
/// and persists it to the validation archive.
#[must_use]
pub fn handoff_validation_snapshot(
    _session_id: u64,
    backpressure: &PosixFilesystemAdapterBackpressureStateRecord,
) -> PosixFilesystemAdapterBackpressureStateRecord {
    *backpressure
}

/// Report whether the validation lane is active (non-zero workers).
#[must_use]
pub fn validation_lane_active(sizing: &PosixFilesystemAdapterWorkerPoolSizingRecord) -> bool {
    sizing.maintenance_workers > 0
}

/// Build a shadow validation handoff ID for a maintenance event.
#[must_use]
pub fn shadow_validation_handoff_id(event_id: u64) -> PosixFilesystemAdapterId128 {
    PosixFilesystemAdapterId128::from_u128_le(event_id as u128)
}

/// Report operational validation status for a surface case.
#[must_use]
pub fn report_surface_validation_status(
    case: &PosixFilesystemAdapterSurfaceValidationCase,
) -> PosixFilesystemAdapterValidationStatus {
    case.status
}

/// Check if a surface validation case is at a gating boundary.
#[must_use]
pub fn is_at_gate_boundary(case: &PosixFilesystemAdapterSurfaceValidationCase) -> bool {
    case.closes_parent_publishing_checklist_item
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterSurfaceValidationClass;

    #[test]
    fn handoff_preserves_backpressure_snapshot() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 10,
            maintenance_backlog: 3,
            ..Default::default()
        };
        let snapshot = handoff_validation_snapshot(1, &bp);
        assert_eq!(snapshot.inflight_request_count, 10);
        assert_eq!(snapshot.maintenance_backlog, 3);
    }

    #[test]
    fn validation_lane_active_with_workers() {
        let sizing = PosixFilesystemAdapterWorkerPoolSizingRecord::default();
        assert!(validation_lane_active(&sizing));
    }

    #[test]
    fn validation_lane_inactive_without_workers() {
        let sizing = PosixFilesystemAdapterWorkerPoolSizingRecord {
            maintenance_workers: 0,
            ..Default::default()
        };
        assert!(!validation_lane_active(&sizing));
    }

    #[test]
    fn shadow_handoff_id_is_deterministic() {
        let id1 = shadow_validation_handoff_id(42);
        let id2 = shadow_validation_handoff_id(42);
        assert_eq!(id1, id2);
    }

    #[test]
    fn surface_case_status_reports_correctly() {
        let case = PosixFilesystemAdapterSurfaceValidationCase {
            stable_id: "test",
            validation_class: PosixFilesystemAdapterSurfaceValidationClass::FileDataIo,
            status: PosixFilesystemAdapterValidationStatus::RecordedScoreboard,
            current_surface: "test surface",
            validation_output: "test validation",
            parent_gate_boundary: "test boundary",
            closes_parent_publishing_checklist_item: false,
        };
        assert_eq!(
            report_surface_validation_status(&case),
            PosixFilesystemAdapterValidationStatus::RecordedScoreboard
        );
        assert!(!is_at_gate_boundary(&case));
    }

    #[test]
    fn is_at_gate_boundary_true_when_closes_checklist_item() {
        let case = PosixFilesystemAdapterSurfaceValidationCase {
            stable_id: "test",
            validation_class: PosixFilesystemAdapterSurfaceValidationClass::FileDataIo,
            status: PosixFilesystemAdapterValidationStatus::RecordedScoreboard,
            current_surface: "test surface",
            validation_output: "test validation",
            parent_gate_boundary: "test boundary",
            closes_parent_publishing_checklist_item: true,
        };
        assert!(is_at_gate_boundary(&case));
    }

    #[test]
    fn handoff_snapshot_identity_preserved() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 12345,
            inflight_request_bytes: 67890,
            reply_bytes_inflight: 111,
            dirty_window_bytes: 222,
            bulk_read_reply_bytes: 333,
            lock_wait_count: 7,
            maintenance_backlog: 999,
            ..Default::default()
        };
        let snapshot = handoff_validation_snapshot(99, &bp);
        assert_eq!(snapshot.inflight_request_count, bp.inflight_request_count);
        assert_eq!(snapshot.inflight_request_bytes, bp.inflight_request_bytes);
        assert_eq!(snapshot.reply_bytes_inflight, bp.reply_bytes_inflight);
        assert_eq!(snapshot.dirty_window_bytes, bp.dirty_window_bytes);
        assert_eq!(snapshot.bulk_read_reply_bytes, bp.bulk_read_reply_bytes);
        assert_eq!(snapshot.lock_wait_count, bp.lock_wait_count);
        assert_eq!(snapshot.maintenance_backlog, bp.maintenance_backlog);
    }

    #[test]
    fn report_surface_validation_status_variants() {
        let statuses = &[
            PosixFilesystemAdapterValidationStatus::SourceBound,
            PosixFilesystemAdapterValidationStatus::ExecutedSmoke,
            PosixFilesystemAdapterValidationStatus::RecordedScoreboard,
            PosixFilesystemAdapterValidationStatus::ExplicitSkip,
            PosixFilesystemAdapterValidationStatus::DeferredNonClosing,
        ];
        for &status in statuses {
            let case = PosixFilesystemAdapterSurfaceValidationCase {
                stable_id: "",
                validation_class: PosixFilesystemAdapterSurfaceValidationClass::FileDataIo,
                status,
                current_surface: "",
                validation_output: "",
                parent_gate_boundary: "",
                closes_parent_publishing_checklist_item: false,
            };
            assert_eq!(report_surface_validation_status(&case), status);
        }
    }

    #[test]
    fn shadow_handoff_id_zero_event() {
        let id = shadow_validation_handoff_id(0);
        assert_eq!(id, PosixFilesystemAdapterId128::ZERO);
    }

    #[test]
    fn shadow_handoff_id_distinct_values() {
        let id1 = shadow_validation_handoff_id(1);
        let id2 = shadow_validation_handoff_id(2);
        let id3 = shadow_validation_handoff_id(u64::MAX);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }
}
