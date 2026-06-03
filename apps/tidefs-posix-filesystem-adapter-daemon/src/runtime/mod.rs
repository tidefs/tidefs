//! Narrow `posix_filesystem_adapter` runtime projection from `publication_pipeline` / `response_registry` outcomes into the first
//! family-local wake receipt.
#[cfg(feature = "receipt-demo")]
pub mod observe;

#[cfg(feature = "receipt-demo")]
pub mod daemon_topology;
#[cfg(feature = "receipt-demo")]
#[allow(unused_imports)]
pub use self::daemon_topology::*;
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterBackpressureStateRecord, PosixFilesystemAdapterRequestClass,
    PosixFilesystemAdapterSessionPhase, PosixFilesystemAdapterSessionRuntimeRecord,
    PosixFilesystemAdapterShardKeyPolicy, PosixFilesystemAdapterWorkerPoolSizingRecord,
};
#[cfg(feature = "receipt-demo")]
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterDigest32, PosixFilesystemAdapterId128,
    PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
    PosixFilesystemAdapterProductWakeReceiptDraft, PosixFilesystemAdapterProductWakeReceiptRecord,
    PosixFilesystemAdapterVisibilityClass, PosixFilesystemAdapterWakeClass,
};

#[cfg(feature = "receipt-demo")]
pub const FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN: &str =
    "queue.publication_pipeline.product_wake.q5 -> join.policy_authority.policy_budget_recipe.w0 -> render.response_registry.posix_filesystem_adapter_wire.r0 -> receipt.posix_filesystem_adapter.wake.namespace_projection.w0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "receipt-demo")]
pub struct PosixFilesystemAdapterDemoPublicationTicketRecord {
    pub ticket_id: PosixFilesystemAdapterId128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "receipt-demo")]
pub enum PosixFilesystemAdapterDemoAnswerKind {
    Bundle,
    Refusal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "receipt-demo")]
pub struct PosixFilesystemAdapterDemoVisibleAnswerRecord {
    pub receipt_id: PosixFilesystemAdapterId128,
    pub request_id: PosixFilesystemAdapterId128,
    pub journal_id: PosixFilesystemAdapterId128,
    pub answer_kind: PosixFilesystemAdapterDemoAnswerKind,
    pub answer_digest: PosixFilesystemAdapterDigest32,
    pub artifact_locator_digest: PosixFilesystemAdapterDigest32,
}

#[cfg(feature = "receipt-demo")]
impl PosixFilesystemAdapterDemoVisibleAnswerRecord {
    #[must_use]
    pub const fn bundle(
        receipt_id: PosixFilesystemAdapterId128,
        request_id: PosixFilesystemAdapterId128,
        journal_id: PosixFilesystemAdapterId128,
        answer_digest: PosixFilesystemAdapterDigest32,
        artifact_locator_digest: PosixFilesystemAdapterDigest32,
    ) -> Self {
        Self {
            receipt_id,
            request_id,
            journal_id,
            answer_kind: PosixFilesystemAdapterDemoAnswerKind::Bundle,
            answer_digest,
            artifact_locator_digest,
        }
    }

    #[must_use]
    pub const fn refusal(
        receipt_id: PosixFilesystemAdapterId128,
        request_id: PosixFilesystemAdapterId128,
        journal_id: PosixFilesystemAdapterId128,
        answer_digest: PosixFilesystemAdapterDigest32,
        artifact_locator_digest: PosixFilesystemAdapterDigest32,
    ) -> Self {
        Self {
            receipt_id,
            request_id,
            journal_id,
            answer_kind: PosixFilesystemAdapterDemoAnswerKind::Refusal,
            answer_digest,
            artifact_locator_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "receipt-demo")]
pub enum PosixFilesystemAdapterProjectionError {
    BundleWithoutTicket,
    RefusalWithTicket,
}

/// Issue a wake receipt from a response-registry answer and optional publication-pipeline ticket.
///
/// # Errors
///
/// Returns [`PosixFilesystemAdapterProjectionError`] if the combination of
/// ticket presence and answer kind is inconsistent.
#[cfg(feature = "receipt-demo")]
pub fn issue_product_wake_receipt(
    publication_pipeline_ticket: Option<PosixFilesystemAdapterDemoPublicationTicketRecord>,
    response_registry_answer: PosixFilesystemAdapterDemoVisibleAnswerRecord,
    witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
) -> Result<PosixFilesystemAdapterProductWakeReceiptRecord, PosixFilesystemAdapterProjectionError> {
    match (
        publication_pipeline_ticket,
        response_registry_answer.answer_kind,
    ) {
        (Some(ticket), PosixFilesystemAdapterDemoAnswerKind::Bundle) => {
            Ok(PosixFilesystemAdapterProductWakeReceiptRecord::new(
                PosixFilesystemAdapterProductWakeReceiptDraft {
                    wake_receipt_id: derive_pair_id(
                        response_registry_answer.receipt_id,
                        ticket.ticket_id,
                        0x71,
                    ),
                    request_id: response_registry_answer.request_id,
                    journal_id: response_registry_answer.journal_id,
                    response_registry_receipt_id: response_registry_answer.receipt_id,
                    publication_pipeline_ticket_id_or_zero: ticket.ticket_id,
                    wake_class: PosixFilesystemAdapterWakeClass::NamespaceProjection,
                    visibility_class: PosixFilesystemAdapterVisibilityClass::CommittedVisible,
                    answer_digest: response_registry_answer.answer_digest,
                    artifact_locator_digest: response_registry_answer.artifact_locator_digest,
                    witness_refs,
                },
            ))
        }
        (None, PosixFilesystemAdapterDemoAnswerKind::Refusal) => {
            Ok(PosixFilesystemAdapterProductWakeReceiptRecord::new(
                PosixFilesystemAdapterProductWakeReceiptDraft {
                    wake_receipt_id: derive_pair_id(
                        response_registry_answer.receipt_id,
                        PosixFilesystemAdapterId128::ZERO,
                        0x72,
                    ),
                    request_id: response_registry_answer.request_id,
                    journal_id: response_registry_answer.journal_id,
                    response_registry_receipt_id: response_registry_answer.receipt_id,
                    publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128::ZERO,
                    wake_class: PosixFilesystemAdapterWakeClass::RefusalProjection,
                    visibility_class: PosixFilesystemAdapterVisibilityClass::NoMutationVisible,
                    answer_digest: response_registry_answer.answer_digest,
                    artifact_locator_digest: response_registry_answer.artifact_locator_digest,
                    witness_refs,
                },
            ))
        }
        (None, PosixFilesystemAdapterDemoAnswerKind::Bundle) => {
            Err(PosixFilesystemAdapterProjectionError::BundleWithoutTicket)
        }
        (Some(_), PosixFilesystemAdapterDemoAnswerKind::Refusal) => {
            Err(PosixFilesystemAdapterProjectionError::RefusalWithTicket)
        }
    }
}

#[cfg(feature = "receipt-demo")]
const fn derive_pair_id(
    left: PosixFilesystemAdapterId128,
    right: PosixFilesystemAdapterId128,
    salt: u8,
) -> PosixFilesystemAdapterId128 {
    let mut out = [0_u8; 16];
    let mut idx = 0;
    while idx < 16 {
        out[idx] = left.0[idx] ^ right.0[15 - idx] ^ salt ^ (idx as u8).wrapping_mul(5);
        idx += 1;
    }
    PosixFilesystemAdapterId128(out)
}

// TURN3_HUMAN_POSIX_FILESYSTEM_ADAPTER_RUNTIME_ALIASES
/// Human-named runtime module for the POSIX Filesystem Adapter projection path.
#[cfg(feature = "receipt-demo")]
pub mod posix_filesystem_adapter_runtime {
    #[allow(unused_imports)]
    pub use super::{
        issue_product_wake_receipt, PosixFilesystemAdapterProjectionError as ProjectionError,
        FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN as FIRST_PUBLICATION_AND_RESPONSE_TO_POSIX_WAKE_CHAIN,
    };
}

/// Human alias namespace. Prefer `human::posix_filesystem_adapter_runtime::*` in new examples.
#[cfg(feature = "receipt-demo")]
pub mod human {
    pub mod posix_filesystem_adapter_runtime {
        #[allow(unused_imports)]
        pub use crate::runtime::posix_filesystem_adapter_runtime::*;
    }
}

// ── P5-02 worker-pool sizing law ─────────────────────────────────────────

/// Compute the default worker-pool sizing policy for a given CPU count.
///
/// This implements the P5-02 §3.3 sizing law:
/// - `R = clamp(cpu / 2, 1, 4)` ingress readers
/// - `M = clamp(cpu, 2, 8)` metadata workers
/// - `N = clamp(cpu / 2, 2, 8)` namespace-mutation workers
/// - `D = clamp(cpu / 4, 1, 4)` directory-stream workers
/// - `W = clamp(cpu / 2, 2, 8)` file read/writeback workers
/// - `L = clamp(cpu / 4, 1, 4)` lock-wait workers
/// - `maintenance = 1` by default, 2 under shadow-pilot
/// - `reply.small = 1`
/// - `reply.bulk = clamp(cpu / 4, 1, 2)`
pub fn compute_worker_pool_sizing(
    cpu_count: u32,
    shadow_pilot: bool,
) -> PosixFilesystemAdapterWorkerPoolSizingRecord {
    let cpu = if cpu_count < 1 { 1 } else { cpu_count };

    PosixFilesystemAdapterWorkerPoolSizingRecord {
        ingress_readers: clamp_div(cpu, 2, 1, 4),
        meta_workers: clamp(cpu, 2, 8),
        namespace_mut_workers: clamp_div(cpu, 2, 2, 8),
        dir_stream_workers: clamp_div(cpu, 4, 1, 4),
        file_read_workers: clamp_div(cpu, 2, 2, 8),
        file_writeback_workers: clamp_div(cpu, 2, 2, 8),
        lock_wait_workers: clamp_div(cpu, 4, 1, 4),
        maintenance_workers: if shadow_pilot { 2 } else { 1 },
        small_reply_committers: 1,
        bulk_reply_committers: clamp_div(cpu, 4, 1, 2),
        urgent_control_workers: 1,
    }
}

const fn clamp(value: u32, min: u32, max: u32) -> u32 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

const fn clamp_div(value: u32, div: u32, min: u32, max: u32) -> u32 {
    let q = value / div;
    if q < min {
        min
    } else if q > max {
        max
    } else {
        q
    }
}

/// Convert a sizing record into a session runtime record.
pub fn build_session_runtime_record(
    sizing: PosixFilesystemAdapterWorkerPoolSizingRecord,
    session_id: u64,
) -> PosixFilesystemAdapterSessionRuntimeRecord {
    PosixFilesystemAdapterSessionRuntimeRecord {
        session_id,
        phase: PosixFilesystemAdapterSessionPhase::Bootstrap.as_u32(),
        ingress_reader_count: sizing.ingress_readers,
        urgent_control_worker_count: sizing.urgent_control_workers,
        meta_worker_count: sizing.meta_workers,
        namespace_mut_worker_count: sizing.namespace_mut_workers,
        dir_stream_worker_count: sizing.dir_stream_workers,
        file_read_worker_count: sizing.file_read_workers,
        file_writeback_worker_count: sizing.file_writeback_workers,
        lock_wait_worker_count: sizing.lock_wait_workers,
        maintenance_worker_count: sizing.maintenance_workers,
        small_reply_committer_count: sizing.small_reply_committers,
        bulk_reply_committer_count: sizing.bulk_reply_committers,
        ..Default::default()
    }
}

// ── P5-02 request classification law ──────────────────────────────────────

/// Classify a FUSE opcode into the canonical 8-class queue topology.
///
/// The mapping follows P5-02 §4.1:
/// - `INIT`, `DESTROY`, `INTERRUPT`, `FORGET`, `BATCH_FORGET` → `ControlUrgent`
/// - `LOOKUP`, `GETATTR`, `ACCESS`, `READLINK`, `STATX` → `MetaRead`
/// - create/unlink/rename/link/symlink/mknod/xattr mutations → `NamespaceMut`
/// - `OPENDIR`, `READDIR`, `READDIRPLUS`, `RELEASEDIR`, `FSYNCDIR` → `DirStream`
/// - `OPEN`, `READ`, `LSEEK`, small ioctls/poll → `FileRead`
/// - `WRITE`, `SETATTR`, `FALLOCATE`, `COPY_FILE_RANGE`, `FLUSH`, `FSYNC`, `RELEASE` → `FileWriteback`
/// - `GETLK`, `SETLK`, `SETLKW`, `FLOCK` → `LockWait`
/// - everything else (drain/release-finalize) → `Maintenance`
pub fn classify_fuse_opcode(opcode: u32) -> PosixFilesystemAdapterRequestClass {
    // FUSE wire opcodes — reference Linux 7.0 `include/uapi/linux/fuse.h`
    // control-urgent lane

    // FUSE opcode numbers from the Linux <linux/fuse.h> header:
    // 1:LOOKUP 2:FORGET 3:GETATTR 4:SETATTR 5:READLINK 6:SYMLINK
    // 7:MKNOD 8:MKDIR 9:UNLINK 10:RMDIR 11:RENAME 12:LINK
    // 13:OPEN 14:READ 15:WRITE 16:STATFS 17:RELEASE
    // 18:FSYNC 19:SETXATTR 20:GETXATTR 21:LISTXATTR 22:REMOVEXATTR
    // 23:FLUSH 24:INIT 25:OPENDIR 26:READDIR 27:RELEASEDIR
    // 28:FSYNCDIR 29:GETLK 30:SETLK 31:SETLKW 32:ACCESS
    // 33:CREATE 34:INTERRUPT 35:BMAP 36:DESTROY
    // 37:IOCTL 38:POLL 39:NOTIFY_REPLY 40:BATCH_FORGET
    // 41:FALLOCATE 42:READDIRPLUS 43:RENAME2 44:LSEEK
    // 45:COPY_FILE_RANGE 46:SETUPMAPPING 47:REMOVEMAPPING
    // 48:? 49:? 50:SYNCFS 51:TMPFILE 52:STATX

    match opcode {
        // queue_class_0.control_urgent
        24 |  // INIT
        36 |  // DESTROY
        34 |  // INTERRUPT
        2  |  // FORGET
        40    // BATCH_FORGET
        => PosixFilesystemAdapterRequestClass::ControlUrgent,

        // queue_class_1.meta_read
        1  |  // LOOKUP
        3  |  // GETATTR
        32 |  // ACCESS
        5  |  // READLINK
        16 |  // STATFS
        52    // STATX
        => PosixFilesystemAdapterRequestClass::MetaRead,

        // queue_class_2.namespace_mut
        6  |  // SYMLINK
        7  |  // MKNOD
        8  |  // MKDIR
        9  |  // UNLINK
        10 |  // RMDIR
        11 |  // RENAME
        12 |  // LINK
        19 |  // SETXATTR
        20 |  // GETXATTR? (read xattr, but metadata)
        21 |  // LISTXATTR
        22 |  // REMOVEXATTR
        33 |  // CREATE
        43 |  // RENAME2
        51    // TMPFILE
        => PosixFilesystemAdapterRequestClass::NamespaceMut,

        // queue_class_3.dir_stream
        25 |  // OPENDIR
        26 |  // READDIR
        42 |  // READDIRPLUS
        27 |  // RELEASEDIR
        28    // FSYNCDIR
        => PosixFilesystemAdapterRequestClass::DirStream,

        // queue_class_4.file_read
        13 |  // OPEN
        14 |  // READ
        44 |  // LSEEK
        37 |  // IOCTL
        38    // POLL
        => PosixFilesystemAdapterRequestClass::FileRead,

        // queue_class_5.file_writeback
        15 |  // WRITE
        4  |  // SETATTR
        41 |  // FALLOCATE
        45 |  // COPY_FILE_RANGE
        23 |  // FLUSH
        18 |  // FSYNC
        50 |  // SYNCFS
        17    // RELEASE
        => PosixFilesystemAdapterRequestClass::FileWriteback,

        // queue_class_6.lock_wait
        29..=31   // SETLKW
        // flock via IOCTL? FUSE doesn't have a direct FLOCK opcode in uapi >=7.12
        => PosixFilesystemAdapterRequestClass::LockWait,

        // queue_class_7.maintenance — explicit for known rare ops, catch-all for unknown
        35 |  // BMAP
        46 |  // SETUPMAPPING
        47 |  // REMOVEMAPPING
        39   // NOTIFY_REPLY
        => PosixFilesystemAdapterRequestClass::Maintenance,

        _ => PosixFilesystemAdapterRequestClass::Maintenance,
    }
}

/// Derive the canonical shard-key policy for a given request class and opcode.
pub fn classify_fuse_request(opcode: u32, _nodeid: u64) -> PosixFilesystemAdapterShardKeyPolicy {
    let req_class = classify_fuse_opcode(opcode);
    match req_class {
        PosixFilesystemAdapterRequestClass::ControlUrgent
        | PosixFilesystemAdapterRequestClass::Maintenance => {
            PosixFilesystemAdapterShardKeyPolicy::Session
        }
        PosixFilesystemAdapterRequestClass::MetaRead => {
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        }
        PosixFilesystemAdapterRequestClass::NamespaceMut => {
            // namespace mutations shard by parent_dir; rename uses dual_parent_pair
            match opcode {
                11 | 43 => PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
                _ => PosixFilesystemAdapterShardKeyPolicy::ParentDir,
            }
        }
        PosixFilesystemAdapterRequestClass::DirStream => {
            PosixFilesystemAdapterShardKeyPolicy::DirHandle
        }
        PosixFilesystemAdapterRequestClass::FileRead => {
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        }
        PosixFilesystemAdapterRequestClass::FileWriteback => {
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite
        }
        PosixFilesystemAdapterRequestClass::LockWait => {
            PosixFilesystemAdapterShardKeyPolicy::LockScope
        }
    }
}

// ── P5-02 backpressure admission law ──────────────────────────────────────

/// Initialize a zeroed backpressure state record.
pub fn init_backpressure_state() -> PosixFilesystemAdapterBackpressureStateRecord {
    PosixFilesystemAdapterBackpressureStateRecord::default()
}

/// Admission check: returns `true` if the request may be enqueued under current backpressure.
///
/// `queue_class_0.control_urgent` always passes (reserved capacity floor per P5-02 §8.1).
/// Other classes may be rejected when counters exceed policy thresholds.
pub fn admit_request_against_backpressure(
    state: &PosixFilesystemAdapterBackpressureStateRecord,
    request_class: PosixFilesystemAdapterRequestClass,
    request_payload_bytes: u64,
) -> bool {
    // P5-02 §8.1: control-urgent has reserved capacity floor — always pass
    if request_class.control_urgent_only() {
        return true;
    }

    // Maintenance always passes (P5-02 §8.2)
    if request_class == PosixFilesystemAdapterRequestClass::Maintenance {
        return true;
    }

    // Lock-wait capped by count (P5-02 §8.2)
    if request_class.may_block_on_lock_waits() {
        const MAX_LOCK_WAIT_COUNT: u32 = 512;
        return state.lock_wait_count < MAX_LOCK_WAIT_COUNT;
    }

    // General admission: reject if inflight + request exceeds a soft ceiling
    const MAX_INFLIGHT_REQUESTS: u64 = 8192;
    const MAX_INFLIGHT_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB soft ceiling

    if state.inflight_request_count >= MAX_INFLIGHT_REQUESTS {
        return false;
    }
    if state.inflight_request_bytes + request_payload_bytes > MAX_INFLIGHT_BYTES {
        return false;
    }

    true
}

#[cfg(feature = "receipt-demo")]
#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterId128;

    const fn bundle_answer() -> PosixFilesystemAdapterDemoVisibleAnswerRecord {
        PosixFilesystemAdapterDemoVisibleAnswerRecord::bundle(
            PosixFilesystemAdapterId128::from_u128_le(0x11),
            PosixFilesystemAdapterId128::from_u128_le(0x22),
            PosixFilesystemAdapterId128::from_u128_le(0x33),
            [0xAA_u8; 32],
            [0xBB_u8; 32],
        )
    }

    const fn refusal_answer() -> PosixFilesystemAdapterDemoVisibleAnswerRecord {
        PosixFilesystemAdapterDemoVisibleAnswerRecord::refusal(
            PosixFilesystemAdapterId128::from_u128_le(0x88),
            PosixFilesystemAdapterId128::from_u128_le(0x99),
            PosixFilesystemAdapterId128::from_u128_le(0xAA),
            [0xCC_u8; 32],
            [0xDD_u8; 32],
        )
    }

    const fn short_refusal_answer() -> PosixFilesystemAdapterDemoVisibleAnswerRecord {
        PosixFilesystemAdapterDemoVisibleAnswerRecord::refusal(
            PosixFilesystemAdapterId128::from_u128_le(0x01),
            PosixFilesystemAdapterId128::from_u128_le(0x02),
            PosixFilesystemAdapterId128::from_u128_le(0x03),
            [0x11_u8; 32],
            [0x22_u8; 32],
        )
    }

    const fn bundle_ticket() -> PosixFilesystemAdapterDemoPublicationTicketRecord {
        PosixFilesystemAdapterDemoPublicationTicketRecord {
            ticket_id: PosixFilesystemAdapterId128::from_u128_le(0x44),
        }
    }

    #[test]
    fn bundle_outcome_projects_committed_wake_receipt() {
        let receipt = issue_product_wake_receipt(
            Some(bundle_ticket()),
            bundle_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                PosixFilesystemAdapterId128::from_u128_le(0x99),
                PosixFilesystemAdapterId128::from_u128_le(0xAA),
                PosixFilesystemAdapterId128::from_u128_le(0xBB),
                PosixFilesystemAdapterId128::from_u128_le(0xCC),
                [0x11_u8; 32],
            ),
        )
        .expect("wake receipt");
        assert_eq!(
            receipt.wake_class(),
            Ok(PosixFilesystemAdapterWakeClass::NamespaceProjection)
        );
        assert_eq!(
            receipt.visibility(),
            Ok(PosixFilesystemAdapterVisibilityClass::CommittedVisible)
        );
        assert!(receipt.has_publication_pipeline_ticket());
        assert!(receipt.has_witness_join());
    }

    #[test]
    fn refusal_outcome_projects_no_mutation_receipt() {
        let receipt = issue_product_wake_receipt(
            None,
            refusal_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                PosixFilesystemAdapterId128::from_u128_le(0xDD),
                PosixFilesystemAdapterId128::from_u128_le(0xEE),
                PosixFilesystemAdapterId128::from_u128_le(0xFF),
                PosixFilesystemAdapterId128::from_u128_le(0x101),
                [0x22_u8; 32],
            ),
        )
        .expect("wake receipt");
        assert_eq!(
            receipt.wake_class(),
            Ok(PosixFilesystemAdapterWakeClass::RefusalProjection)
        );
        assert_eq!(
            receipt.visibility(),
            Ok(PosixFilesystemAdapterVisibilityClass::NoMutationVisible)
        );
        assert!(!receipt.has_publication_pipeline_ticket());
        assert!(receipt.has_witness_join());
    }

    #[test]
    fn bundle_answer_without_ticket_is_rejected() {
        let err = issue_product_wake_receipt(
            None,
            bundle_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::ZERO,
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            PosixFilesystemAdapterProjectionError::BundleWithoutTicket
        );
    }

    #[test]
    fn refusal_answer_with_ticket_is_rejected() {
        let err = issue_product_wake_receipt(
            Some(bundle_ticket()),
            short_refusal_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::ZERO,
        )
        .expect_err("refusal with ticket must be rejected");
        assert_eq!(
            err,
            PosixFilesystemAdapterProjectionError::RefusalWithTicket
        );
    }

    #[test]
    fn bundle_receipt_has_publication_pipeline_ticket() {
        let receipt = issue_product_wake_receipt(
            Some(bundle_ticket()),
            bundle_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                PosixFilesystemAdapterId128::from_u128_le(0x99),
                PosixFilesystemAdapterId128::from_u128_le(0xAA),
                PosixFilesystemAdapterId128::from_u128_le(0xBB),
                PosixFilesystemAdapterId128::from_u128_le(0xCC),
                [0x11_u8; 32],
            ),
        )
        .expect("wake receipt");
        assert!(receipt.has_publication_pipeline_ticket());
    }

    #[test]
    fn refusal_receipt_publication_ticket_id_is_zero() {
        let receipt = issue_product_wake_receipt(
            None,
            refusal_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                PosixFilesystemAdapterId128::from_u128_le(0xDD),
                PosixFilesystemAdapterId128::from_u128_le(0xEE),
                PosixFilesystemAdapterId128::from_u128_le(0xFF),
                PosixFilesystemAdapterId128::from_u128_le(0x101),
                [0x22_u8; 32],
            ),
        )
        .expect("wake receipt");
        assert!(!receipt.has_publication_pipeline_ticket());
    }

    #[test]
    fn bundle_receipt_with_zero_witnesses_reports_no_join() {
        let receipt = issue_product_wake_receipt(
            Some(bundle_ticket()),
            bundle_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::ZERO,
        )
        .expect("wake receipt");
        assert!(!receipt.has_witness_join());
    }

    #[test]
    fn refusal_receipt_with_nonzero_witnesses_reports_has_join() {
        let receipt = issue_product_wake_receipt(
            None,
            short_refusal_answer(),
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                PosixFilesystemAdapterId128::from_u128_le(0x77),
                PosixFilesystemAdapterId128::from_u128_le(0x88),
                PosixFilesystemAdapterId128::from_u128_le(0x99),
                PosixFilesystemAdapterId128::from_u128_le(0xAA),
                [0x66_u8; 32],
            ),
        )
        .expect("wake receipt");
        assert!(receipt.has_witness_join());
    }

    #[test]
    #[allow(clippy::const_is_empty)]
    fn module_aliases_resolve_and_function_calls_compile() {
        use crate::runtime::human::posix_filesystem_adapter_runtime::FIRST_PUBLICATION_AND_RESPONSE_TO_POSIX_WAKE_CHAIN;
        assert!(!FIRST_PUBLICATION_AND_RESPONSE_TO_POSIX_WAKE_CHAIN.is_empty());

        let result =
            crate::runtime::human::posix_filesystem_adapter_runtime::issue_product_wake_receipt(
                None,
                bundle_answer(),
                PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::ZERO,
            );
        assert!(result.is_err());
    }

    // ── compute_worker_pool_sizing tests ────────────────────────────────

    #[test]
    fn worker_pool_sizing_cpu_zero_clamps_to_minimum() {
        let s = compute_worker_pool_sizing(0, false);
        assert_eq!(s.ingress_readers, 1);
        assert_eq!(s.meta_workers, 2);
        assert_eq!(s.namespace_mut_workers, 2);
        assert_eq!(s.dir_stream_workers, 1);
        assert_eq!(s.file_read_workers, 2);
        assert_eq!(s.file_writeback_workers, 2);
        assert_eq!(s.lock_wait_workers, 1);
        assert_eq!(s.maintenance_workers, 1);
        assert_eq!(s.small_reply_committers, 1);
        assert_eq!(s.bulk_reply_committers, 1);
        assert_eq!(s.urgent_control_workers, 1);
    }

    #[test]
    fn worker_pool_sizing_cpu_one_equals_zero_case() {
        let s0 = compute_worker_pool_sizing(0, false);
        let s1 = compute_worker_pool_sizing(1, false);
        assert_eq!(s0.ingress_readers, s1.ingress_readers);
        assert_eq!(s0.meta_workers, s1.meta_workers);
        assert_eq!(s0.namespace_mut_workers, s1.namespace_mut_workers);
        assert_eq!(s0.dir_stream_workers, s1.dir_stream_workers);
    }

    #[test]
    fn worker_pool_sizing_cpu_eight_mid_range() {
        let s = compute_worker_pool_sizing(8, false);
        assert_eq!(s.ingress_readers, 4);
        assert_eq!(s.meta_workers, 8);
        assert_eq!(s.namespace_mut_workers, 4);
        assert_eq!(s.dir_stream_workers, 2);
        assert_eq!(s.file_read_workers, 4);
        assert_eq!(s.file_writeback_workers, 4);
        assert_eq!(s.lock_wait_workers, 2);
        assert_eq!(s.maintenance_workers, 1);
        assert_eq!(s.small_reply_committers, 1);
        assert_eq!(s.bulk_reply_committers, 2);
        assert_eq!(s.urgent_control_workers, 1);
    }

    #[test]
    fn worker_pool_sizing_cpu_high_saturates_at_max_clamps() {
        let s = compute_worker_pool_sizing(255, false);
        assert_eq!(s.ingress_readers, 4);
        assert_eq!(s.meta_workers, 8);
        assert_eq!(s.namespace_mut_workers, 8);
        assert_eq!(s.dir_stream_workers, 4);
        assert_eq!(s.file_read_workers, 8);
        assert_eq!(s.file_writeback_workers, 8);
        assert_eq!(s.lock_wait_workers, 4);
        assert_eq!(s.maintenance_workers, 1);
        assert_eq!(s.small_reply_committers, 1);
        assert_eq!(s.bulk_reply_committers, 2);
        assert_eq!(s.urgent_control_workers, 1);
    }

    #[test]
    fn worker_pool_sizing_shadow_pilot_doubles_maintenance() {
        let normal = compute_worker_pool_sizing(8, false);
        let shadow = compute_worker_pool_sizing(8, true);
        assert_eq!(normal.maintenance_workers, 1);
        assert_eq!(shadow.maintenance_workers, 2);
        // all other fields identical under shadow_pilot
        assert_eq!(normal.ingress_readers, shadow.ingress_readers);
        assert_eq!(normal.meta_workers, shadow.meta_workers);
        assert_eq!(normal.file_read_workers, shadow.file_read_workers);
    }

    #[test]
    fn worker_pool_sizing_all_fields_nonzero() {
        let s = compute_worker_pool_sizing(16, false);
        assert!(s.ingress_readers > 0);
        assert!(s.meta_workers > 0);
        assert!(s.namespace_mut_workers > 0);
        assert!(s.dir_stream_workers > 0);
        assert!(s.file_read_workers > 0);
        assert!(s.file_writeback_workers > 0);
        assert!(s.lock_wait_workers > 0);
        assert!(s.maintenance_workers > 0);
        assert!(s.small_reply_committers > 0);
        assert!(s.bulk_reply_committers > 0);
        assert!(s.urgent_control_workers > 0);
    }

    // ── build_session_runtime_record tests ───────────────────────────────

    #[test]
    fn build_session_runtime_record_maps_sizing_fields() {
        let sizing = PosixFilesystemAdapterWorkerPoolSizingRecord {
            ingress_readers: 3,
            meta_workers: 5,
            namespace_mut_workers: 7,
            dir_stream_workers: 2,
            file_read_workers: 4,
            file_writeback_workers: 6,
            lock_wait_workers: 3,
            maintenance_workers: 1,
            small_reply_committers: 1,
            bulk_reply_committers: 1,
            urgent_control_workers: 2,
        };
        let rec = build_session_runtime_record(sizing, 42);
        assert_eq!(rec.session_id, 42);
        assert_eq!(rec.ingress_reader_count, 3);
        assert_eq!(rec.urgent_control_worker_count, 2);
        assert_eq!(rec.meta_worker_count, 5);
        assert_eq!(rec.namespace_mut_worker_count, 7);
        assert_eq!(rec.dir_stream_worker_count, 2);
        assert_eq!(rec.file_read_worker_count, 4);
        assert_eq!(rec.file_writeback_worker_count, 6);
        assert_eq!(rec.lock_wait_worker_count, 3);
        assert_eq!(rec.maintenance_worker_count, 1);
        assert_eq!(rec.small_reply_committer_count, 1);
        assert_eq!(rec.bulk_reply_committer_count, 1);
    }

    #[test]
    fn build_session_runtime_record_defaults_phase_to_bootstrap() {
        let sizing = PosixFilesystemAdapterWorkerPoolSizingRecord::default();
        let rec = build_session_runtime_record(sizing, 0);
        assert_eq!(
            rec.phase,
            PosixFilesystemAdapterSessionPhase::Bootstrap.as_u32()
        );
    }

    #[test]
    fn build_session_runtime_record_defaults_reserved_to_zero() {
        let sizing = PosixFilesystemAdapterWorkerPoolSizingRecord::default();
        let rec = build_session_runtime_record(sizing, 0);
        assert_eq!(rec._reserved, [0_u32; 2]);
    }

    // ── classify_fuse_opcode tests ───────────────────────────────────────

    #[test]
    fn classify_fuse_opcode_control_urgent() {
        assert_eq!(
            classify_fuse_opcode(24),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // INIT
        assert_eq!(
            classify_fuse_opcode(36),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // DESTROY
        assert_eq!(
            classify_fuse_opcode(34),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // INTERRUPT
        assert_eq!(
            classify_fuse_opcode(2),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // FORGET
        assert_eq!(
            classify_fuse_opcode(40),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // BATCH_FORGET
    }

    #[test]
    fn classify_fuse_opcode_meta_read() {
        assert_eq!(
            classify_fuse_opcode(1),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // LOOKUP
        assert_eq!(
            classify_fuse_opcode(3),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // GETATTR
        assert_eq!(
            classify_fuse_opcode(32),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // ACCESS
        assert_eq!(
            classify_fuse_opcode(5),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // READLINK
        assert_eq!(
            classify_fuse_opcode(16),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // STATFS
        assert_eq!(
            classify_fuse_opcode(52),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // STATX
    }

    #[test]
    fn classify_fuse_opcode_namespace_mut() {
        assert_eq!(
            classify_fuse_opcode(6),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // SYMLINK
        assert_eq!(
            classify_fuse_opcode(7),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // MKNOD
        assert_eq!(
            classify_fuse_opcode(8),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // MKDIR
        assert_eq!(
            classify_fuse_opcode(9),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // UNLINK
        assert_eq!(
            classify_fuse_opcode(10),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // RMDIR
        assert_eq!(
            classify_fuse_opcode(11),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // RENAME
        assert_eq!(
            classify_fuse_opcode(12),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // LINK
        assert_eq!(
            classify_fuse_opcode(33),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // CREATE
        assert_eq!(
            classify_fuse_opcode(43),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // RENAME2
        assert_eq!(
            classify_fuse_opcode(51),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // TMPFILE
        assert_eq!(
            classify_fuse_opcode(19),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // SETXATTR
        assert_eq!(
            classify_fuse_opcode(20),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // GETXATTR
        assert_eq!(
            classify_fuse_opcode(21),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // LISTXATTR
        assert_eq!(
            classify_fuse_opcode(22),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // REMOVEXATTR
    }

    #[test]
    fn classify_fuse_opcode_dir_stream() {
        assert_eq!(
            classify_fuse_opcode(25),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // OPENDIR
        assert_eq!(
            classify_fuse_opcode(26),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // READDIR
        assert_eq!(
            classify_fuse_opcode(42),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // READDIRPLUS
        assert_eq!(
            classify_fuse_opcode(27),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // RELEASEDIR
        assert_eq!(
            classify_fuse_opcode(28),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // FSYNCDIR
    }

    #[test]
    fn classify_fuse_opcode_file_read() {
        assert_eq!(
            classify_fuse_opcode(13),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // OPEN
        assert_eq!(
            classify_fuse_opcode(14),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // READ
        assert_eq!(
            classify_fuse_opcode(44),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // LSEEK
        assert_eq!(
            classify_fuse_opcode(37),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // IOCTL
        assert_eq!(
            classify_fuse_opcode(38),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // POLL
    }

    #[test]
    fn classify_fuse_opcode_file_writeback() {
        assert_eq!(
            classify_fuse_opcode(15),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // WRITE
        assert_eq!(
            classify_fuse_opcode(4),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // SETATTR
        assert_eq!(
            classify_fuse_opcode(41),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // FALLOCATE
        assert_eq!(
            classify_fuse_opcode(45),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // COPY_FILE_RANGE
        assert_eq!(
            classify_fuse_opcode(23),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // FLUSH
        assert_eq!(
            classify_fuse_opcode(18),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // FSYNC
        assert_eq!(
            classify_fuse_opcode(50),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // SYNCFS
        assert_eq!(
            classify_fuse_opcode(17),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // RELEASE
    }

    #[test]
    fn classify_fuse_opcode_lock_wait() {
        assert_eq!(
            classify_fuse_opcode(29),
            PosixFilesystemAdapterRequestClass::LockWait
        ); // GETLK
        assert_eq!(
            classify_fuse_opcode(30),
            PosixFilesystemAdapterRequestClass::LockWait
        ); // SETLK
        assert_eq!(
            classify_fuse_opcode(31),
            PosixFilesystemAdapterRequestClass::LockWait
        ); // SETLKW
    }

    #[test]
    fn classify_fuse_opcode_unknown_maps_to_maintenance() {
        assert_eq!(
            classify_fuse_opcode(0),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
        assert_eq!(
            classify_fuse_opcode(35),
            PosixFilesystemAdapterRequestClass::Maintenance
        ); // BMAP
        assert_eq!(
            classify_fuse_opcode(46),
            PosixFilesystemAdapterRequestClass::Maintenance
        ); // SETUPMAPPING
        assert_eq!(
            classify_fuse_opcode(255),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
        assert_eq!(
            classify_fuse_opcode(u32::MAX),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
    }

    #[test]
    fn classify_fuse_opcode_all_canonical_mapped() {
        // Every opcode 1-52 except BMAP (35) and those explicitly mapped to Maintenance must map to a non-Maintenance class
        let non_maintenance: &[(u32, PosixFilesystemAdapterRequestClass)] = &[
            (1, PosixFilesystemAdapterRequestClass::MetaRead),
            (2, PosixFilesystemAdapterRequestClass::ControlUrgent),
            (3, PosixFilesystemAdapterRequestClass::MetaRead),
            (4, PosixFilesystemAdapterRequestClass::FileWriteback),
            (5, PosixFilesystemAdapterRequestClass::MetaRead),
            (6, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (7, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (8, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (9, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (10, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (11, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (12, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (13, PosixFilesystemAdapterRequestClass::FileRead),
            (14, PosixFilesystemAdapterRequestClass::FileRead),
            (15, PosixFilesystemAdapterRequestClass::FileWriteback),
            (16, PosixFilesystemAdapterRequestClass::MetaRead),
            (17, PosixFilesystemAdapterRequestClass::FileWriteback),
            (18, PosixFilesystemAdapterRequestClass::FileWriteback),
            (19, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (20, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (21, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (22, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (23, PosixFilesystemAdapterRequestClass::FileWriteback),
            (24, PosixFilesystemAdapterRequestClass::ControlUrgent),
            (25, PosixFilesystemAdapterRequestClass::DirStream),
            (26, PosixFilesystemAdapterRequestClass::DirStream),
            (27, PosixFilesystemAdapterRequestClass::DirStream),
            (28, PosixFilesystemAdapterRequestClass::DirStream),
            (29, PosixFilesystemAdapterRequestClass::LockWait),
            (30, PosixFilesystemAdapterRequestClass::LockWait),
            (31, PosixFilesystemAdapterRequestClass::LockWait),
            (32, PosixFilesystemAdapterRequestClass::MetaRead),
            (33, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (34, PosixFilesystemAdapterRequestClass::ControlUrgent),
            (36, PosixFilesystemAdapterRequestClass::ControlUrgent),
            (37, PosixFilesystemAdapterRequestClass::FileRead),
            (38, PosixFilesystemAdapterRequestClass::FileRead),
            (40, PosixFilesystemAdapterRequestClass::ControlUrgent),
            (41, PosixFilesystemAdapterRequestClass::FileWriteback),
            (42, PosixFilesystemAdapterRequestClass::DirStream),
            (43, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (44, PosixFilesystemAdapterRequestClass::FileRead),
            (45, PosixFilesystemAdapterRequestClass::FileWriteback),
            (50, PosixFilesystemAdapterRequestClass::FileWriteback),
            (51, PosixFilesystemAdapterRequestClass::NamespaceMut),
            (52, PosixFilesystemAdapterRequestClass::MetaRead),
        ];
        for &(opcode, expected) in non_maintenance {
            assert_eq!(
                classify_fuse_opcode(opcode),
                expected,
                "opcode {opcode} should not map to Maintenance"
            );
        }
    }

    // ── classify_fuse_request tests ──────────────────────────────────────

    #[test]
    fn classify_fuse_request_control_urgent_session_key() {
        assert_eq!(
            classify_fuse_request(24, 1), // INIT
            PosixFilesystemAdapterShardKeyPolicy::Session
        );
        assert_eq!(
            classify_fuse_request(36, 1), // DESTROY
            PosixFilesystemAdapterShardKeyPolicy::Session
        );
    }

    #[test]
    fn classify_fuse_request_maintenance_session_key() {
        assert_eq!(
            classify_fuse_request(0, 0), // unknown → Maintenance
            PosixFilesystemAdapterShardKeyPolicy::Session
        );
    }

    #[test]
    fn classify_fuse_request_meta_read_object_read_key() {
        assert_eq!(
            classify_fuse_request(1, 100), // LOOKUP
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        );
    }

    #[test]
    fn classify_fuse_request_namespace_mut_rename_dual_parent_pair() {
        assert_eq!(
            classify_fuse_request(11, 0), // RENAME
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair
        );
        assert_eq!(
            classify_fuse_request(43, 0), // RENAME2
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair
        );
    }

    #[test]
    fn classify_fuse_request_namespace_mut_other_parent_dir() {
        assert_eq!(
            classify_fuse_request(9, 0), // UNLINK
            PosixFilesystemAdapterShardKeyPolicy::ParentDir
        );
        assert_eq!(
            classify_fuse_request(33, 0), // CREATE
            PosixFilesystemAdapterShardKeyPolicy::ParentDir
        );
    }

    #[test]
    fn classify_fuse_request_dir_stream_dir_handle_key() {
        assert_eq!(
            classify_fuse_request(26, 0), // READDIR
            PosixFilesystemAdapterShardKeyPolicy::DirHandle
        );
    }

    #[test]
    fn classify_fuse_request_file_read_object_read_key() {
        assert_eq!(
            classify_fuse_request(14, 0), // READ
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        );
    }

    #[test]
    fn classify_fuse_request_file_writeback_object_write_key() {
        assert_eq!(
            classify_fuse_request(15, 0), // WRITE
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite
        );
    }

    #[test]
    fn classify_fuse_request_lock_wait_lock_scope_key() {
        assert_eq!(
            classify_fuse_request(29, 0), // GETLK
            PosixFilesystemAdapterShardKeyPolicy::LockScope
        );
    }

    // ── init_backpressure_state tests ────────────────────────────────────

    #[test]
    fn init_backpressure_state_equals_default() {
        let manual = PosixFilesystemAdapterBackpressureStateRecord::default();
        let init = init_backpressure_state();
        assert_eq!(init.inflight_request_count, manual.inflight_request_count);
        assert_eq!(init.inflight_request_bytes, manual.inflight_request_bytes);
        assert_eq!(init.reply_bytes_inflight, manual.reply_bytes_inflight);
        assert_eq!(init.dirty_window_bytes, manual.dirty_window_bytes);
        assert_eq!(init.bulk_read_reply_bytes, manual.bulk_read_reply_bytes);
        assert_eq!(init.lock_wait_count, manual.lock_wait_count);
        assert_eq!(init.maintenance_backlog, manual.maintenance_backlog);
    }

    #[test]
    fn init_backpressure_state_all_fields_zero() {
        let state = init_backpressure_state();
        assert_eq!(state.inflight_request_count, 0);
        assert_eq!(state.inflight_request_bytes, 0);
        assert_eq!(state.reply_bytes_inflight, 0);
        assert_eq!(state.dirty_window_bytes, 0);
        assert_eq!(state.bulk_read_reply_bytes, 0);
        assert_eq!(state.lock_wait_count, 0);
        assert_eq!(state.maintenance_backlog, 0);
    }

    // ── admit_request_against_backpressure tests ─────────────────────────

    #[test]
    fn admit_control_urgent_always_passes_regardless_of_backpressure() {
        let full = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 9999,
            inflight_request_bytes: 999_999_999,
            lock_wait_count: 999,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &full,
            PosixFilesystemAdapterRequestClass::ControlUrgent,
            1_000_000,
        ));
    }

    #[test]
    fn admit_maintenance_always_passes() {
        let full = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 9999,
            inflight_request_bytes: 999_999_999,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &full,
            PosixFilesystemAdapterRequestClass::Maintenance,
            0,
        ));
    }

    #[test]
    fn admit_lock_wait_rejected_at_ceiling() {
        let at_ceiling = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: 512,
            ..Default::default()
        };
        assert!(!admit_request_against_backpressure(
            &at_ceiling,
            PosixFilesystemAdapterRequestClass::LockWait,
            0,
        ));
    }

    #[test]
    fn admit_lock_wait_rejected_above_ceiling() {
        let above = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: 1024,
            ..Default::default()
        };
        assert!(!admit_request_against_backpressure(
            &above,
            PosixFilesystemAdapterRequestClass::LockWait,
            0,
        ));
    }

    #[test]
    fn admit_lock_wait_accepted_below_ceiling() {
        let below = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: 511,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &below,
            PosixFilesystemAdapterRequestClass::LockWait,
            0,
        ));
    }

    #[test]
    fn admit_rejected_when_inflight_count_at_ceiling() {
        let full_count = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 8192,
            ..Default::default()
        };
        assert!(!admit_request_against_backpressure(
            &full_count,
            PosixFilesystemAdapterRequestClass::MetaRead,
            0,
        ));
    }

    #[test]
    fn admit_rejected_when_inflight_bytes_ceiling_exceeded() {
        let near_full = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_bytes: 64 * 1024 * 1024 - 1,
            ..Default::default()
        };
        // one more byte would exceed 64 MiB
        assert!(!admit_request_against_backpressure(
            &near_full,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            2,
        ));
    }

    #[test]
    fn admit_accepted_when_inflight_bytes_below_ceiling() {
        let below = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_bytes: 32 * 1024 * 1024,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &below,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            1024,
        ));
    }

    #[test]
    fn admit_checks_inflight_bytes_before_inflight_count() {
        // count is fine but bytes are at ceiling — should reject
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 100,
            inflight_request_bytes: 64 * 1024 * 1024,
            ..Default::default()
        };
        assert!(!admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::DirStream,
            1,
        ));
    }

    #[test]
    fn admit_zero_byte_request_accepted_at_full_bytes() {
        // exactly at byte ceiling, zero-length request: check ordering
        // bytes + 0 = bytes, not > ceiling → should pass
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 100,
            inflight_request_bytes: 64 * 1024 * 1024,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::DirStream,
            0,
        ));
    }

    #[test]
    fn admit_namespace_mut_accepted_under_all_ceilings() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 1000,
            inflight_request_bytes: 10 * 1024 * 1024,
            lock_wait_count: 0,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::NamespaceMut,
            4096,
        ));
    }
}

// ── P5-02 worker-pool sizing, classification, and backpressure unit tests ─

#[cfg(test)]
mod p5_02_tests {
    use super::*;
    use tidefs_types_posix_filesystem_adapter_core::{
        PosixFilesystemAdapterBackpressureStateRecord, PosixFilesystemAdapterRequestClass,
        PosixFilesystemAdapterShardKeyPolicy,
    };

    // ── compute_worker_pool_sizing ──────────────────────────────────────

    #[test]
    fn pool_sizing_cpu_zero_clamps_to_one() {
        let s = compute_worker_pool_sizing(0, false);
        assert_eq!(s.ingress_readers, 1, "div(1/2)=0 but min clamp=1");
    }

    #[test]
    fn pool_sizing_cpu_one_minimum() {
        let s = compute_worker_pool_sizing(1, false);
        assert_eq!(s.meta_workers, 2, "clamp(1,2,8)=2");
        assert_eq!(s.namespace_mut_workers, 2, "clamp_div(1/2=0,2,8)=2");
        assert_eq!(s.file_read_workers, 2, "clamp_div(1/2=0,2,8)=2");
        assert_eq!(s.dir_stream_workers, 1, "clamp_div(1/4=0,1,4)=1");
        assert_eq!(s.maintenance_workers, 1, "shadow_pilot=false");
        assert_eq!(s.small_reply_committers, 1);
        assert_eq!(s.urgent_control_workers, 1);
    }

    #[test]
    fn pool_sizing_cpu_sixteen_midrange() {
        let s = compute_worker_pool_sizing(16, false);
        assert_eq!(s.ingress_readers, 4, "div(16/2=8)=8, max clamp=4");
        assert_eq!(s.meta_workers, 8, "clamp(16,2,8)=8");
        assert_eq!(s.namespace_mut_workers, 8, "div(16/2=8)=8, max clamp=8");
        assert_eq!(s.dir_stream_workers, 4, "div(16/4=4)=4");
        assert_eq!(s.file_read_workers, 8, "div(16/2)=8");
        assert_eq!(s.file_writeback_workers, 8);
        assert_eq!(s.lock_wait_workers, 4);
        assert_eq!(s.bulk_reply_committers, 2, "div(16/4=4)=4, max clamp=2");
    }

    #[test]
    fn pool_sizing_cpu_sixtyfour_saturates_all() {
        let s = compute_worker_pool_sizing(64, false);
        // Every clamp_div should hit max
        assert_eq!(s.ingress_readers, 4);
        assert_eq!(s.meta_workers, 8);
        assert_eq!(s.namespace_mut_workers, 8);
        assert_eq!(s.dir_stream_workers, 4);
        assert_eq!(s.file_read_workers, 8);
        assert_eq!(s.file_writeback_workers, 8);
        assert_eq!(s.lock_wait_workers, 4);
        assert_eq!(s.bulk_reply_committers, 2);
        assert_eq!(s.small_reply_committers, 1);
        assert_eq!(s.urgent_control_workers, 1);
    }

    #[test]
    fn pool_sizing_shadow_pilot_doubles_maintenance() {
        let normal = compute_worker_pool_sizing(4, false);
        assert_eq!(normal.maintenance_workers, 1);
        let shadow = compute_worker_pool_sizing(4, true);
        assert_eq!(shadow.maintenance_workers, 2);
        // All other fields identical
        assert_eq!(normal.ingress_readers, shadow.ingress_readers);
        assert_eq!(normal.meta_workers, shadow.meta_workers);
        assert_eq!(normal.namespace_mut_workers, shadow.namespace_mut_workers);
        assert_eq!(normal.file_read_workers, shadow.file_read_workers);
    }

    // ── build_session_runtime_record ────────────────────────────────────

    #[test]
    fn build_session_runtime_converts_all_fields() {
        let sizing = PosixFilesystemAdapterWorkerPoolSizingRecord {
            ingress_readers: 3,
            meta_workers: 7,
            namespace_mut_workers: 5,
            dir_stream_workers: 2,
            file_read_workers: 6,
            file_writeback_workers: 4,
            lock_wait_workers: 3,
            maintenance_workers: 2,
            small_reply_committers: 1,
            bulk_reply_committers: 2,
            urgent_control_workers: 1,
        };
        let rec = build_session_runtime_record(sizing, 42);
        assert_eq!(rec.session_id, 42);
        assert_eq!(rec.ingress_reader_count, 3);
        assert_eq!(rec.meta_worker_count, 7);
        assert_eq!(rec.namespace_mut_worker_count, 5);
        assert_eq!(rec.dir_stream_worker_count, 2);
        assert_eq!(rec.file_read_worker_count, 6);
        assert_eq!(rec.file_writeback_worker_count, 4);
        assert_eq!(rec.lock_wait_worker_count, 3);
        assert_eq!(rec.maintenance_worker_count, 2);
        assert_eq!(rec.small_reply_committer_count, 1);
        assert_eq!(rec.bulk_reply_committer_count, 2);
        assert_eq!(rec.urgent_control_worker_count, 1);
    }

    #[test]
    fn build_session_runtime_phase_defaults_to_bootstrap() {
        let sizing = PosixFilesystemAdapterWorkerPoolSizingRecord::default();
        let rec = build_session_runtime_record(sizing, 1);
        use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterSessionPhase;
        assert_eq!(
            rec.phase,
            PosixFilesystemAdapterSessionPhase::Bootstrap.as_u32()
        );
    }

    // ── classify_fuse_opcode ────────────────────────────────────────────

    #[test]
    fn classify_control_urgent_opcodes() {
        assert_eq!(
            classify_fuse_opcode(24),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // INIT
        assert_eq!(
            classify_fuse_opcode(36),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // DESTROY
        assert_eq!(
            classify_fuse_opcode(34),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // INTERRUPT
        assert_eq!(
            classify_fuse_opcode(2),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // FORGET
        assert_eq!(
            classify_fuse_opcode(40),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ); // BATCH_FORGET
    }

    #[test]
    fn classify_meta_read_opcodes() {
        assert_eq!(
            classify_fuse_opcode(1),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // LOOKUP
        assert_eq!(
            classify_fuse_opcode(3),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // GETATTR
        assert_eq!(
            classify_fuse_opcode(32),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // ACCESS
        assert_eq!(
            classify_fuse_opcode(5),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // READLINK
        assert_eq!(
            classify_fuse_opcode(16),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // STATFS
        assert_eq!(
            classify_fuse_opcode(52),
            PosixFilesystemAdapterRequestClass::MetaRead
        ); // STATX
    }

    #[test]
    fn classify_namespace_mut_opcodes() {
        assert_eq!(
            classify_fuse_opcode(6),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // SYMLINK
        assert_eq!(
            classify_fuse_opcode(9),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // UNLINK
        assert_eq!(
            classify_fuse_opcode(11),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // RENAME
        assert_eq!(
            classify_fuse_opcode(33),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // CREATE
        assert_eq!(
            classify_fuse_opcode(43),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // RENAME2
        assert_eq!(
            classify_fuse_opcode(51),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // TMPFILE
        assert_eq!(
            classify_fuse_opcode(19),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // SETXATTR
        assert_eq!(
            classify_fuse_opcode(22),
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ); // REMOVEXATTR
    }

    #[test]
    fn classify_dir_stream_opcodes() {
        assert_eq!(
            classify_fuse_opcode(25),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // OPENDIR
        assert_eq!(
            classify_fuse_opcode(26),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // READDIR
        assert_eq!(
            classify_fuse_opcode(42),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // READDIRPLUS
        assert_eq!(
            classify_fuse_opcode(27),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // RELEASEDIR
        assert_eq!(
            classify_fuse_opcode(28),
            PosixFilesystemAdapterRequestClass::DirStream
        ); // FSYNCDIR
    }

    #[test]
    fn classify_file_read_opcodes() {
        assert_eq!(
            classify_fuse_opcode(13),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // OPEN
        assert_eq!(
            classify_fuse_opcode(14),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // READ
        assert_eq!(
            classify_fuse_opcode(44),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // LSEEK
        assert_eq!(
            classify_fuse_opcode(37),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // IOCTL
        assert_eq!(
            classify_fuse_opcode(38),
            PosixFilesystemAdapterRequestClass::FileRead
        ); // POLL
    }

    #[test]
    fn classify_file_writeback_opcodes() {
        assert_eq!(
            classify_fuse_opcode(15),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // WRITE
        assert_eq!(
            classify_fuse_opcode(4),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // SETATTR
        assert_eq!(
            classify_fuse_opcode(41),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // FALLOCATE
        assert_eq!(
            classify_fuse_opcode(45),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // COPY_FILE_RANGE
        assert_eq!(
            classify_fuse_opcode(18),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // FSYNC
        assert_eq!(
            classify_fuse_opcode(17),
            PosixFilesystemAdapterRequestClass::FileWriteback
        ); // RELEASE
    }

    #[test]
    fn classify_lock_wait_opcodes() {
        assert_eq!(
            classify_fuse_opcode(29),
            PosixFilesystemAdapterRequestClass::LockWait
        ); // GETLK
        assert_eq!(
            classify_fuse_opcode(30),
            PosixFilesystemAdapterRequestClass::LockWait
        ); // SETLK
        assert_eq!(
            classify_fuse_opcode(31),
            PosixFilesystemAdapterRequestClass::LockWait
        ); // SETLKW
    }

    #[test]
    fn classify_unknown_opcodes_default_to_maintenance() {
        assert_eq!(
            classify_fuse_opcode(0),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
        assert_eq!(
            classify_fuse_opcode(46),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
        assert_eq!(
            classify_fuse_opcode(47),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
        assert_eq!(
            classify_fuse_opcode(99),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
        assert_eq!(
            classify_fuse_opcode(255),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
    }

    /// Every opcode 1-45 should classify into a known class, not Maintenance.
    /// Gaps like 35,39 should still go to Maintenance (opcodes not in FUSE spec).
    #[test]
    fn classify_exhaustiveness_covers_known_range() {
        let known_not_maintenance: &[u32] = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 36, 37, 38, 40, 41, 42, 43, 44, 45, 52,
        ];
        for &op in known_not_maintenance {
            assert_ne!(
                classify_fuse_opcode(op),
                PosixFilesystemAdapterRequestClass::Maintenance,
                "opcode {op} should not be Maintenance"
            );
        }
    }

    // ── classify_fuse_request ───────────────────────────────────────────

    #[test]
    fn classify_request_shard_key_policies() {
        assert_eq!(
            classify_fuse_request(24, 0),
            PosixFilesystemAdapterShardKeyPolicy::Session
        ); // INIT → ControlUrgent → Session
        assert_eq!(
            classify_fuse_request(34, 0),
            PosixFilesystemAdapterShardKeyPolicy::Session
        ); // INTERRUPT
        assert_eq!(
            classify_fuse_request(1, 0),
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        ); // LOOKUP → MetaRead
        assert_eq!(
            classify_fuse_request(3, 0),
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        ); // GETATTR
        assert_eq!(
            classify_fuse_request(9, 0),
            PosixFilesystemAdapterShardKeyPolicy::ParentDir
        ); // UNLINK → NamespaceMut
        assert_eq!(
            classify_fuse_request(33, 0),
            PosixFilesystemAdapterShardKeyPolicy::ParentDir
        ); // CREATE
        assert_eq!(
            classify_fuse_request(25, 0),
            PosixFilesystemAdapterShardKeyPolicy::DirHandle
        ); // OPENDIR → DirStream
        assert_eq!(
            classify_fuse_request(13, 0),
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        ); // OPEN → FileRead
        assert_eq!(
            classify_fuse_request(15, 0),
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite
        ); // WRITE → FileWriteback
        assert_eq!(
            classify_fuse_request(29, 0),
            PosixFilesystemAdapterShardKeyPolicy::LockScope
        ); // GETLK → LockWait
    }

    #[test]
    fn rename_uses_dual_parent_pair() {
        assert_eq!(
            classify_fuse_request(11, 0),
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair
        );
        assert_eq!(
            classify_fuse_request(43, 0),
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair
        );
    }

    #[test]
    fn unknown_opcode_defaults_to_session_shard() {
        // Maintenance → Session shard key
        assert_eq!(
            classify_fuse_request(0, 0),
            PosixFilesystemAdapterShardKeyPolicy::Session
        );
        assert_eq!(
            classify_fuse_request(99, 0),
            PosixFilesystemAdapterShardKeyPolicy::Session
        );
    }

    // ── init_backpressure_state ─────────────────────────────────────────

    #[test]
    fn init_backpressure_state_is_default() {
        let manual = PosixFilesystemAdapterBackpressureStateRecord::default();
        let init = init_backpressure_state();
        assert_eq!(init.inflight_request_count, manual.inflight_request_count);
        assert_eq!(init.inflight_request_bytes, manual.inflight_request_bytes);
        assert_eq!(init.lock_wait_count, manual.lock_wait_count);
        assert_eq!(init.maintenance_backlog, manual.maintenance_backlog);
        assert_eq!(init.dirty_window_bytes, manual.dirty_window_bytes);
    }

    #[test]
    fn init_backpressure_state_all_zeroed() {
        let s = init_backpressure_state();
        assert_eq!(s.inflight_request_count, 0);
        assert_eq!(s.inflight_request_bytes, 0);
        assert_eq!(s.lock_wait_count, 0);
        assert_eq!(s.maintenance_backlog, 0);
    }

    // ── admit_request_against_backpressure ──────────────────────────────

    #[test]
    fn control_urgent_always_admitted_regardless_of_state() {
        let saturated = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 100_000,
            inflight_request_bytes: u64::MAX,
            lock_wait_count: 1000,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &saturated,
            PosixFilesystemAdapterRequestClass::ControlUrgent,
            0
        ));
    }

    #[test]
    fn maintenance_always_admitted() {
        let saturated = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 100_000,
            inflight_request_bytes: u64::MAX,
            lock_wait_count: 1000,
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &saturated,
            PosixFilesystemAdapterRequestClass::Maintenance,
            0
        ));
    }

    #[test]
    fn lock_wait_admitted_when_count_below_ceiling() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: 500,
            ..Default::default()
        };
        // Even with high inflight counts, LockWait bypasses the general ceiling
        assert!(admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::LockWait,
            0
        ));
    }

    #[test]
    fn lock_wait_rejected_when_count_at_ceiling() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: 512,
            ..Default::default()
        };
        assert!(!admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::LockWait,
            0
        ));
    }

    #[test]
    fn lock_wait_rejected_when_count_above_ceiling() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: 1000,
            ..Default::default()
        };
        assert!(!admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::LockWait,
            0
        ));
    }

    #[test]
    fn general_request_admitted_under_ceilings() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 100,
            inflight_request_bytes: 1024 * 1024, // 1 MiB
            ..Default::default()
        };
        assert!(admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::FileRead,
            4096
        ));
    }

    #[test]
    fn general_request_rejected_when_inflight_count_at_ceiling() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 8192,
            inflight_request_bytes: 0,
            ..Default::default()
        };
        assert!(!admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::FileRead,
            0
        ));
    }

    #[test]
    fn general_request_rejected_when_bytes_would_exceed_ceiling() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 1,
            inflight_request_bytes: 64 * 1024 * 1024 - 1, // 1 byte below ceiling
            ..Default::default()
        };
        // Adding 2 bytes pushes over the 64 MiB ceiling
        assert!(!admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            2
        ));
    }

    #[test]
    fn general_request_admitted_when_bytes_exactly_at_ceiling_with_zero_payload() {
        let state = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 1,
            inflight_request_bytes: 64 * 1024 * 1024, // exactly at ceiling
            ..Default::default()
        };
        // Zero-byte payload doesn't push bytes over; count still ok
        assert!(admit_request_against_backpressure(
            &state,
            PosixFilesystemAdapterRequestClass::FileRead,
            0
        ));
    }
}
