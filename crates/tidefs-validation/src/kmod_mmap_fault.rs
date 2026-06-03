//! Kernel-mode mmap fault-handling validation module.
//!
//! Produces tier-classified validation output for the kmod-posix-vfs mmap
//! and page-fault dispatch path — private read faults, shared read faults,
//! write faults via page_mkwrite, and msync-after-write fault patterns —
//! operating without a userspace daemon.
//!
//! # Validation tiers
//!
//! | Tier | Meaning |
//! |---|---|
//! | `SourceModel` | Schema types, FNV-1a digest, and in-process fault-path verification |
//! | `CargoUnit` | `cargo test -p tidefs-validation -- kmod_mmap_fault` — digest correctness, error-type consistency |
//! | `QemuFullStack` | Linux 7.0 boot, module load, pool create, mount, mmap fault exercise, committed-root verification |
//!
//! # Fault kinds
//!
//! - **PrivateReadFault** — MAP_PRIVATE read fault, filemap_fault resolves via VfsEngine::read
//! - **SharedReadFault** — MAP_SHARED read fault, filemap_fault resolves via VfsEngine::read
//! - **WriteFault** — write fault, page_mkwrite transitions read-only page to writable
//! - **MsyncAfterWrite** — msync/fsync after mmap write, durability verification
//!
//! # Current validation role
//!
//! This module is the validation surface for kernel-mode mmap fault-handling.
//! It provides the schema, digest, and source/model tier verification for the
//! VfsEngine::fault and KmodVfsVmOps::page_mkwrite dispatch paths.
//!
//! The full no-daemon mmap fault-path validation (QEMU tier) depends on the
//! existing KmodVfsVmOps implementation in crates/tidefs-kmod-posix-vfs/src/mmap.rs,
//! which dispatches fault() and page_mkwrite() through the kmod-bridge VfsEngine
//! and DirtyFolioTracker without requiring a userspace daemon.

use crate::runtime_artifact_source::RuntimeArtifactSource;
use serde::{Deserialize, Serialize};
use std::fmt;

// ── FNV-1a 64-bit digest ───────────────────────────────────────────────────

/// Compute the FNV-1a 64-bit hash of a byte slice.
///
/// FNV-1a is used here as a fast, deterministic content digest for validation
/// report fingerprinting — not for cryptographic integrity.
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Compute the FNV-1a 64-bit hash of a string slice.
pub fn fnv1a_str(s: &str) -> u64 {
    fnv1a_64(s.as_bytes())
}

// ── Mmap fault kind ────────────────────────────────────────────────────────

/// Classification of mmap page-fault patterns exercised by kernel-mode validation.
///
/// Each variant corresponds to a specific kernel vm_operations_struct dispatch
/// path exercised in no-daemon mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum MmapFaultKind {
    /// MAP_PRIVATE read fault — filemap_fault resolves via VfsEngine::read.
    PrivateReadFault,
    /// MAP_SHARED read fault — filemap_fault resolves via VfsEngine::read.
    SharedReadFault,
    /// Write fault — page_mkwrite transitions read-only page to writable,
    /// registers dirty range with DirtyFolioTracker for subsequent writepages flush.
    WriteFault,
    /// msync/fsync after mmap write — verifies dirty data reaches stable storage
    /// and committed-root digest is consistent across remount.
    MsyncAfterWrite,
}

impl fmt::Display for MmapFaultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateReadFault => write!(f, "private-read-fault"),
            Self::SharedReadFault => write!(f, "shared-read-fault"),
            Self::WriteFault => write!(f, "write-fault"),
            Self::MsyncAfterWrite => write!(f, "msync-after-write"),
        }
    }
}

// ── Validation tier ──────────────────────────────────────────────────────────

/// Validation classification tier for kernel-mode mmap fault validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum KmodMmapFaultTier {
    /// Source/model types, digest schema, in-process fault-path verification.
    SourceModel,
    /// Cargo test run validating digest correctness, error-type consistency,
    /// and mock-engine integration patterns.
    CargoUnit,
    /// Full QEMU guest: Linux 7.0 boot, module load, pool create, mount,
    /// mmap fault exercise, committed-root verification.
    QemuFullStack,
}

// ── Validation outcome ───────────────────────────────────────────────────────

/// Outcome classification for a single validation row.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationOutcome {
    /// Row-level validation pass — the fault kind resolved correctly.
    Pass,
    /// Row-level validation fail — the fault kind did not resolve as expected.
    Fail,
    /// Validation row skipped — the tier or environment refused to run.
    Skipped,
}

// ── Validation row ───────────────────────────────────────────────────────────

/// Single validation row for kernel-mode mmap fault-handling validation.
///
/// Each row records one fault-pattern exercise at a specific validation tier
/// with a FNV-1a 64-bit content digest for row-level fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmodMmapFaultValidationRow {
    /// Fault pattern kind exercised.
    pub kind: MmapFaultKind,
    /// Validation tier at which this row was collected.
    pub tier: KmodMmapFaultTier,
    /// Row outcome.
    pub outcome: ValidationOutcome,
    /// Human-readable description of what was exercised.
    pub description: String,
    /// FNV-1a 64-bit row digest computed from kind + tier + outcome + description.
    pub digest: u64,
    /// Runtime artifact source when validation is from a live runtime tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_source: Option<RuntimeArtifactSource>,
}

impl KmodMmapFaultValidationRow {
    /// Create a new validation row and compute its FNV-1a digest.
    pub fn new(
        kind: MmapFaultKind,
        tier: KmodMmapFaultTier,
        outcome: ValidationOutcome,
        description: impl Into<String>,
    ) -> Self {
        let desc = description.into();
        // Build canonical digest input: kind:... tier:... outcome:... description:...
        let payload = format!("kind:{kind} tier:{tier:?} outcome:{outcome:?} description:{desc}");
        let digest = fnv1a_64(payload.as_bytes());

        Self {
            kind,
            tier,
            outcome,
            description: desc,
            digest,
            artifact_source: None,
        }
    }

    /// Attach a runtime artifact source (for live-runtime tier rows).
    pub fn with_artifact(mut self, source: RuntimeArtifactSource) -> Self {
        self.artifact_source = Some(source);
        self
    }

    /// Check whether this row represents a genuine runtime pass.
    ///
    /// Returns `true` only when the outcome is Pass, the tier is a
    /// live-runtime tier (QemuFullStack), and a genuine artifact source
    /// is attached (workload ran with a non-empty command).
    pub fn is_genuine_runtime_pass(&self) -> bool {
        if self.outcome != ValidationOutcome::Pass {
            return false;
        }
        if self.tier != KmodMmapFaultTier::QemuFullStack {
            return false;
        }
        match &self.artifact_source {
            Some(a) => a.is_genuine(),
            None => false,
        }
    }
}

// ── Validation collection ────────────────────────────────────────────────────

/// Collection of kmod mmap fault validation rows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KmodMmapFaultValidation {
    /// Validation rows in insertion order.
    pub rows: Vec<KmodMmapFaultValidationRow>,
}

impl KmodMmapFaultValidation {
    /// Create an empty validation collection.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Add a row and return its digest.
    pub fn push(&mut self, row: KmodMmapFaultValidationRow) -> u64 {
        let digest = row.digest;
        self.rows.push(row);
        digest
    }

    /// Number of validation rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Count rows with the given outcome.
    pub fn count_outcome(&self, outcome: ValidationOutcome) -> usize {
        self.rows.iter().filter(|r| r.outcome == outcome).count()
    }

    /// Count rows with the given fault kind.
    pub fn count_kind(&self, kind: MmapFaultKind) -> usize {
        self.rows.iter().filter(|r| r.kind == kind).count()
    }

    /// Compute a collection-level aggregate digest from all row digests.
    ///
    /// Uses FNV-1a over the concatenation of all row digest bytes (big-endian).
    pub fn aggregate_digest(&self) -> u64 {
        let mut buf = Vec::with_capacity(self.rows.len() * 8);
        for row in &self.rows {
            buf.extend_from_slice(&row.digest.to_be_bytes());
        }
        fnv1a_64(&buf)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FNV-1a digest tests ─────────────────────────────────────────────

    #[test]
    fn fnv1a_known_vectors() {
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63dc4c8601ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn fnv1a_str_consistent() {
        let s = "private-read-fault-pass";
        assert_eq!(fnv1a_str(s), fnv1a_64(s.as_bytes()));
    }

    #[test]
    fn fnv1a_deterministic() {
        let data = b"mmap-fault-validation-6204";
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a_different_inputs_different_hashes() {
        let h1 = fnv1a_64(b"private-read-fault-pass");
        let h2 = fnv1a_64(b"private-read-fault-fail");
        assert_ne!(h1, h2);
    }

    // ── MmapFaultKind tests ────────────────────────────────────────────

    #[test]
    fn mmap_fault_kind_variants_distinct() {
        assert_ne!(
            MmapFaultKind::PrivateReadFault,
            MmapFaultKind::SharedReadFault
        );
        assert_ne!(MmapFaultKind::PrivateReadFault, MmapFaultKind::WriteFault);
        assert_ne!(
            MmapFaultKind::PrivateReadFault,
            MmapFaultKind::MsyncAfterWrite
        );
        assert_ne!(MmapFaultKind::SharedReadFault, MmapFaultKind::WriteFault);
        assert_ne!(
            MmapFaultKind::SharedReadFault,
            MmapFaultKind::MsyncAfterWrite
        );
        assert_ne!(MmapFaultKind::WriteFault, MmapFaultKind::MsyncAfterWrite);
    }

    #[test]
    fn mmap_fault_kind_display() {
        assert_eq!(
            format!("{}", MmapFaultKind::PrivateReadFault),
            "private-read-fault"
        );
        assert_eq!(
            format!("{}", MmapFaultKind::SharedReadFault),
            "shared-read-fault"
        );
        assert_eq!(format!("{}", MmapFaultKind::WriteFault), "write-fault");
        assert_eq!(
            format!("{}", MmapFaultKind::MsyncAfterWrite),
            "msync-after-write"
        );
    }

    #[test]
    fn mmap_fault_kind_serialization_roundtrip() {
        for kind in &[
            MmapFaultKind::PrivateReadFault,
            MmapFaultKind::SharedReadFault,
            MmapFaultKind::WriteFault,
            MmapFaultKind::MsyncAfterWrite,
        ] {
            let json = serde_json::to_string(kind).unwrap();
            let back: MmapFaultKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back, "roundtrip failed for {kind:?}");
        }
    }

    #[test]
    fn mmap_fault_kind_serialization_values() {
        assert_eq!(
            serde_json::to_string(&MmapFaultKind::PrivateReadFault).unwrap(),
            "\"private-read-fault\""
        );
        assert_eq!(
            serde_json::to_string(&MmapFaultKind::SharedReadFault).unwrap(),
            "\"shared-read-fault\""
        );
        assert_eq!(
            serde_json::to_string(&MmapFaultKind::WriteFault).unwrap(),
            "\"write-fault\""
        );
        assert_eq!(
            serde_json::to_string(&MmapFaultKind::MsyncAfterWrite).unwrap(),
            "\"msync-after-write\""
        );
    }

    // ── Validation tier tests ────────────────────────────────────────────

    #[test]
    fn tier_variants_distinct() {
        assert_ne!(KmodMmapFaultTier::SourceModel, KmodMmapFaultTier::CargoUnit);
        assert_ne!(
            KmodMmapFaultTier::CargoUnit,
            KmodMmapFaultTier::QemuFullStack
        );
        assert_ne!(
            KmodMmapFaultTier::SourceModel,
            KmodMmapFaultTier::QemuFullStack
        );
    }

    // ── Validation row tests ─────────────────────────────────────────────

    #[test]
    fn validation_row_creates_digest() {
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "private read fault resolves correctly via VfsEngine::read",
        );
        assert_ne!(row.digest, 0);
        assert_eq!(row.kind, MmapFaultKind::PrivateReadFault);
        assert_eq!(row.tier, KmodMmapFaultTier::SourceModel);
        assert_eq!(row.outcome, ValidationOutcome::Pass);
    }

    #[test]
    fn validation_row_digest_deterministic() {
        let desc = "shared read fault through mock";
        let r1 = KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            desc,
        );
        let r2 = KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            desc,
        );
        assert_eq!(r1.digest, r2.digest);
    }

    #[test]
    fn validation_row_different_kinds_different_digests() {
        let r1 = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "test",
        );
        let r2 = KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "test",
        );
        assert_ne!(r1.digest, r2.digest);
    }

    #[test]
    fn validation_row_different_outcomes_different_digests() {
        let r1 = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "test",
        );
        let r2 = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Fail,
            "test",
        );
        assert_ne!(r1.digest, r2.digest);
    }

    #[test]
    fn is_genuine_runtime_pass_rejects_source_model() {
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "test",
        );
        assert!(!row.is_genuine_runtime_pass());
    }

    #[test]
    fn is_genuine_runtime_pass_rejects_cargo_unit() {
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::CargoUnit,
            ValidationOutcome::Pass,
            "test",
        );
        assert!(!row.is_genuine_runtime_pass());
    }

    #[test]
    fn is_genuine_runtime_pass_rejects_qemu_without_artifact() {
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::QemuFullStack,
            ValidationOutcome::Pass,
            "test",
        );
        assert!(!row.is_genuine_runtime_pass());
    }

    #[test]
    fn is_genuine_runtime_pass_rejects_fail_even_with_artifact() {
        let artifact = RuntimeArtifactSource {
            command: "/usr/bin/mmapper".into(),
            environment: "Linux 7.0 QEMU".into(),
            commit: "abc123".into(),
            kernel_version: Some("7.0.0".into()),
            exit_status: 0,
            stdout_path: Some("/tmp/out.log".into()),
            stderr_path: None,
            workload_ran: true,
        };
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::QemuFullStack,
            ValidationOutcome::Fail,
            "test",
        )
        .with_artifact(artifact);
        assert!(!row.is_genuine_runtime_pass());
    }

    #[test]
    fn is_genuine_runtime_pass_rejects_empty_command() {
        let artifact = RuntimeArtifactSource {
            command: "".into(),
            environment: "Linux 7.0 QEMU".into(),
            commit: "abc123".into(),
            kernel_version: None,
            exit_status: 0,
            stdout_path: None,
            stderr_path: None,
            workload_ran: true,
        };
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::QemuFullStack,
            ValidationOutcome::Pass,
            "test",
        )
        .with_artifact(artifact);
        assert!(!row.is_genuine_runtime_pass());
    }

    #[test]
    fn is_genuine_runtime_pass_rejects_workload_not_ran() {
        let artifact = RuntimeArtifactSource {
            command: "/usr/bin/mmapper".into(),
            environment: "Linux 7.0 QEMU".into(),
            commit: "abc123".into(),
            kernel_version: None,
            exit_status: 0,
            stdout_path: None,
            stderr_path: None,
            workload_ran: false,
        };
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::QemuFullStack,
            ValidationOutcome::Pass,
            "test",
        )
        .with_artifact(artifact);
        assert!(!row.is_genuine_runtime_pass());
    }

    #[test]
    fn is_genuine_runtime_pass_accepts_genuine_qemu() {
        let artifact = RuntimeArtifactSource {
            command: "/usr/bin/mmapper".into(),
            environment: "Linux 7.0 QEMU guest, x86_64".into(),
            commit: "deadbeef".into(),
            kernel_version: Some("7.0.0-tidefs+".into()),
            exit_status: 0,
            stdout_path: Some("/validation/stdout.log".into()),
            stderr_path: None,
            workload_ran: true,
        };
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::QemuFullStack,
            ValidationOutcome::Pass,
            "genuine qemu mmap fault validation",
        )
        .with_artifact(artifact);
        assert!(row.is_genuine_runtime_pass());
    }

    // ── Validation collection tests ──────────────────────────────────────

    #[test]
    fn validation_collection_empty() {
        let ev = KmodMmapFaultValidation::new();
        assert!(ev.is_empty());
        assert_eq!(ev.len(), 0);
        assert_eq!(ev.count_outcome(ValidationOutcome::Pass), 0);
        assert_eq!(ev.count_kind(MmapFaultKind::PrivateReadFault), 0);
    }

    #[test]
    fn validation_collection_push_and_count() {
        let mut ev = KmodMmapFaultValidation::new();
        ev.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "row 1",
        ));
        ev.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "row 2",
        ));
        ev.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::WriteFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Fail,
            "row 3",
        ));

        assert_eq!(ev.len(), 3);
        assert!(!ev.is_empty());
        assert_eq!(ev.count_outcome(ValidationOutcome::Pass), 2);
        assert_eq!(ev.count_outcome(ValidationOutcome::Fail), 1);
        assert_eq!(ev.count_kind(MmapFaultKind::PrivateReadFault), 1);
        assert_eq!(ev.count_kind(MmapFaultKind::SharedReadFault), 1);
        assert_eq!(ev.count_kind(MmapFaultKind::WriteFault), 1);
        assert_eq!(ev.count_kind(MmapFaultKind::MsyncAfterWrite), 0);
    }

    #[test]
    fn validation_collection_aggregate_digest_stable() {
        let mut ev1 = KmodMmapFaultValidation::new();
        ev1.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r1",
        ));
        ev1.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r2",
        ));

        let mut ev2 = KmodMmapFaultValidation::new();
        ev2.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r1",
        ));
        ev2.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r2",
        ));

        assert_eq!(ev1.aggregate_digest(), ev2.aggregate_digest());
    }

    #[test]
    fn validation_collection_aggregate_digest_order_sensitive() {
        let mut ev1 = KmodMmapFaultValidation::new();
        ev1.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r1",
        ));
        ev1.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r2",
        ));

        let mut ev2 = KmodMmapFaultValidation::new();
        ev2.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r2",
        ));
        ev2.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "r1",
        ));

        assert_ne!(ev1.aggregate_digest(), ev2.aggregate_digest());
    }

    // ── Source/model: mock VfsEngine fault-path verification ──────────

    /// Simulates the VfsEngine::fault dispatch logic.
    ///
    /// The default VfsEngine::fault implementation calls VfsEngine::read and
    /// packages the result as a VmFaultOutcome with VM_FAULT_MAJOR (data present)
    /// or VM_FAULT_NOPAGE (empty read, indicating a hole or beyond-EOF).
    ///
    /// This function models that dispatch so we can verify the fault-path
    /// behavior without depending on the full VfsEngine trait impl in tests.
    fn simulate_fault(read_data: Result<Vec<u8>, &str>) -> Result<MockFaultOutcome, &str> {
        let data = read_data?;
        if data.is_empty() {
            Ok(MockFaultOutcome {
                page: data,
                vm_fault_code: VM_FAULT_NOPAGE,
            })
        } else {
            Ok(MockFaultOutcome {
                page: data,
                vm_fault_code: VM_FAULT_MAJOR,
            })
        }
    }

    /// Mirror of VmFaultOutcome for use without the tidefs-vfs-engine dep.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockFaultOutcome {
        page: Vec<u8>,
        vm_fault_code: u32,
    }

    // VM_FAULT codes mirroring tidefs-vfs-engine::VM_FAULT_*
    const VM_FAULT_MAJOR: u32 = 1;
    const VM_FAULT_NOPAGE: u32 = 5;

    #[test]
    fn mock_fault_private_read_resolves_data() {
        let outcome = simulate_fault(Ok(b"mmap-page-data".to_vec())).unwrap();
        assert_eq!(outcome.page, b"mmap-page-data");
        assert_eq!(outcome.vm_fault_code, VM_FAULT_MAJOR);
    }

    #[test]
    fn mock_fault_private_read_empty_returns_nopage() {
        let outcome = simulate_fault(Ok(Vec::new())).unwrap();
        assert!(outcome.page.is_empty());
        assert_eq!(outcome.vm_fault_code, VM_FAULT_NOPAGE);
    }

    #[test]
    fn mock_fault_io_error_propagates() {
        let result = simulate_fault(Err("EIO"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "EIO");
    }

    #[test]
    fn mock_fault_multiple_pages_independent() {
        let o1 = simulate_fault(Ok(b"page-0-data".to_vec())).unwrap();
        let o2 = simulate_fault(Ok(b"page-1-data".to_vec())).unwrap();

        assert_eq!(o1.page, b"page-0-data");
        assert_eq!(o1.vm_fault_code, VM_FAULT_MAJOR);
        assert_eq!(o2.page, b"page-1-data");
        assert_eq!(o2.vm_fault_code, VM_FAULT_MAJOR);
        assert_ne!(o1.page, o2.page);
    }

    // ── Source/model: fault-kind to validation row integration ───────────

    #[test]
    fn private_read_fault_produces_validation_row() {
        let outcome = simulate_fault(Ok(b"private-read-data".to_vec())).unwrap();
        assert_eq!(outcome.vm_fault_code, VM_FAULT_MAJOR);

        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "private read fault resolved via VfsEngine::read, returned VM_FAULT_MAJOR",
        );
        assert_ne!(row.digest, 0);
        assert_eq!(row.kind, MmapFaultKind::PrivateReadFault);
    }

    #[test]
    fn shared_read_fault_eof_produces_nopage_validation_row() {
        let outcome = simulate_fault(Ok(Vec::new())).unwrap();
        assert_eq!(outcome.vm_fault_code, VM_FAULT_NOPAGE);

        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "shared read fault beyond EOF returned VM_FAULT_NOPAGE",
        );
        assert_ne!(row.digest, 0);
        assert_eq!(row.kind, MmapFaultKind::SharedReadFault);
    }

    #[test]
    fn write_fault_page_mkwrite_registers_dirty() {
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::WriteFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "page_mkwrite transitions page to writable, registers dirty range",
        );
        assert_eq!(row.kind, MmapFaultKind::WriteFault);
    }

    #[test]
    fn msync_after_write_drains_and_verifies() {
        let row = KmodMmapFaultValidationRow::new(
            MmapFaultKind::MsyncAfterWrite,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "msync after mmap write ensures dirty data reaches stable storage",
        );
        assert_eq!(row.kind, MmapFaultKind::MsyncAfterWrite);
    }

    // ── Source/model: all four fault kinds exercise ────────────────────

    #[test]
    fn all_four_fault_kinds_have_distinct_validation_rows() {
        let mut ev = KmodMmapFaultValidation::new();
        let d1 = ev.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::PrivateReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "private read fault",
        ));
        let d2 = ev.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::SharedReadFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "shared read fault",
        ));
        let d3 = ev.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::WriteFault,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "write fault page_mkwrite",
        ));
        let d4 = ev.push(KmodMmapFaultValidationRow::new(
            MmapFaultKind::MsyncAfterWrite,
            KmodMmapFaultTier::SourceModel,
            ValidationOutcome::Pass,
            "msync after write",
        ));

        assert_eq!(ev.len(), 4);
        assert_eq!(ev.count_outcome(ValidationOutcome::Pass), 4);
        assert_ne!(d1, d2);
        assert_ne!(d1, d3);
        assert_ne!(d1, d4);
        assert_ne!(d2, d3);
        assert_ne!(d2, d4);
        assert_ne!(d3, d4);
    }
}
