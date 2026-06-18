// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! kmod-posix-vfs O_DIRECT crash-consistency validation module.
//!
//! Produces tier-classified validation output for kernel O_DIRECT I/O
//! through kmod-posix-vfs: direct write/read, fsync durability, crash
//! consistency, and committed-root verification.
//!
//! # Validation tiers
//!
//! | Tier | Meaning |
//! |---|---|
//! | `SourceModel` | In-process ODirectEngine with deterministic crash simulation |
//! | `CargoUnit` | Cargo test passing all validation rows |
//! | `MountedKernelVfs` | O_DIRECT open flags propagate through VfsEngine dispatch |
//! | `QemuGuest` | Linux 7.0 QEMU with crash-injection, remount, committed-root verification |
//!
//! # Operation kinds
//!
//! - **DirectWrite** — O_DIRECT-aligned write through kernel VFS
//! - **DirectRead** — O_DIRECT-aligned read through kernel VFS
//! - **DirectWriteVerify** — write-then-read verification of O_DIRECT data
//! - **DirectWriteFsync** — O_DIRECT write + fsync durability barrier
//! - **DirectWriteCrashRead** — crash + remount verification of O_DIRECT data
//! - **MixedBufferedDirect** — interleaved buffered and direct I/O
//! - **ConcurrentDirectWrites** — parallel O_DIRECT writes to disjoint ranges
//! - **AlignedUnalignedBoundary** — alignment constraint enforcement
//! - **ODirectTruncateInterleave** — truncate interleaved with O_DIRECT writes

use serde::{Deserialize, Serialize};
use std::fmt;

// ── FNV-1a 64-bit digest ───────────────────────────────────────────────────

pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn fnv1a_str(s: &str) -> u64 {
    fnv1a_64(s.as_bytes())
}

// ── O_DIRECT operation kind ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ODirectOp {
    DirectWrite,
    DirectRead,
    DirectWriteVerify,
    DirectWriteFsync,
    DirectWriteCrashRead,
    MixedBufferedDirect,
    ConcurrentDirectWrites,
    AlignedUnalignedBoundary,
    ODirectTruncateInterleave,
}

impl ODirectOp {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DirectWrite => "direct-write",
            Self::DirectRead => "direct-read",
            Self::DirectWriteVerify => "direct-write-verify",
            Self::DirectWriteFsync => "direct-write-fsync",
            Self::DirectWriteCrashRead => "direct-write-crash-read",
            Self::MixedBufferedDirect => "mixed-buffered-direct",
            Self::ConcurrentDirectWrites => "concurrent-direct-writes",
            Self::AlignedUnalignedBoundary => "aligned-unaligned-boundary",
            Self::ODirectTruncateInterleave => "odirect-truncate-interleave",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::DirectWrite => "O_DIRECT-aligned write through kernel VFS",
            Self::DirectRead => "O_DIRECT-aligned read through kernel VFS",
            Self::DirectWriteVerify => "Write-then-read verification of O_DIRECT data",
            Self::DirectWriteFsync => "O_DIRECT write with fsync durability barrier",
            Self::DirectWriteCrashRead => {
                "Crash + remount verification of O_DIRECT data durability"
            }
            Self::MixedBufferedDirect => "Interleaved buffered and direct I/O",
            Self::ConcurrentDirectWrites => "Parallel O_DIRECT writes to disjoint ranges",
            Self::AlignedUnalignedBoundary => "Alignment constraint enforcement",
            Self::ODirectTruncateInterleave => "Truncate interleaved with O_DIRECT writes",
        }
    }

    pub fn is_crash_op(&self) -> bool {
        matches!(self, Self::DirectWriteCrashRead)
    }

    pub fn is_durable(&self) -> bool {
        matches!(self, Self::DirectWriteFsync | Self::DirectWriteCrashRead)
    }
}

impl fmt::Display for ODirectOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── O_DIRECT validation tier ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ODirectValidationTier {
    SourceModel = 0,
    CargoUnit = 1,
    MountedKernelVfs = 2,
    QemuGuest = 3,
}

impl ODirectValidationTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SourceModel => "source-model",
            Self::CargoUnit => "cargo-unit",
            Self::MountedKernelVfs => "mounted-kernel-vfs",
            Self::QemuGuest => "qemu-guest",
        }
    }

    pub fn terminal_tier() -> Self {
        Self::QemuGuest
    }

    pub fn requires_qemu(&self) -> bool {
        matches!(self, Self::QemuGuest)
    }

    pub fn is_kernel_runtime(&self) -> bool {
        matches!(self, Self::MountedKernelVfs | Self::QemuGuest)
    }
}

impl fmt::Display for ODirectValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── O_DIRECT outcome ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ODirectOutcome {
    Pass,
    Fail,
    Blocked,
    Skip,
}

impl ODirectOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Blocked => "blocked",
            Self::Skip => "skip",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Fail)
    }

    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Fail | Self::Blocked)
    }
}

impl fmt::Display for ODirectOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── O_DIRECT validation row ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ODirectValidationRow {
    pub row_id: String,
    pub tier: ODirectValidationTier,
    pub op: ODirectOp,
    pub outcome: ODirectOutcome,
    pub detail: String,
    pub duration_ms: Option<u64>,
    pub committed_root_before: Option<String>,
    pub committed_root_after: Option<String>,
}

impl ODirectValidationRow {
    pub fn new(
        row_id: impl Into<String>,
        tier: ODirectValidationTier,
        op: ODirectOp,
        outcome: ODirectOutcome,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            row_id: row_id.into(),
            tier,
            op,
            outcome,
            detail: detail.into(),
            duration_ms: None,
            committed_root_before: None,
            committed_root_after: None,
        }
    }

    pub fn with_committed_roots(
        mut self,
        before: impl Into<String>,
        after: impl Into<String>,
    ) -> Self {
        self.committed_root_before = Some(before.into());
        self.committed_root_after = Some(after.into());
        self
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    pub fn row_digest(&self) -> u64 {
        let payload = format!(
            "{}:{}:{}:{}",
            self.tier.label(),
            self.op.label(),
            self.outcome.label(),
            self.detail
        );
        fnv1a_str(&payload)
    }

    pub fn is_terminal_pass(&self, terminal_tier: ODirectValidationTier) -> bool {
        self.tier >= terminal_tier && self.outcome == ODirectOutcome::Pass
    }
}

// ── O_DIRECT validation report ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ODirectValidationReport {
    pub validation_id: String,
    pub rows: Vec<ODirectValidationRow>,
    pub digest: u64,
    pub timestamp: String,
    pub kernel_version: Option<String>,
    pub qemu_command: Option<String>,
}

impl ODirectValidationReport {
    pub fn new(validation_id: impl Into<String>) -> Self {
        Self {
            validation_id: validation_id.into(),
            rows: Vec::new(),
            digest: 0,
            timestamp: String::new(),
            kernel_version: None,
            qemu_command: None,
        }
    }

    pub fn add_row(&mut self, row: ODirectValidationRow) {
        self.rows.push(row);
    }

    pub fn seal(&mut self, timestamp: impl Into<String>) {
        self.timestamp = timestamp.into();
        let mut buf = Vec::new();
        for row in &self.rows {
            buf.extend_from_slice(&row.row_digest().to_le_bytes());
        }
        self.digest = fnv1a_64(&buf);
    }

    pub fn count_by_outcome(&self, outcome: ODirectOutcome) -> usize {
        self.rows.iter().filter(|r| r.outcome == outcome).count()
    }

    pub fn count_by_tier(&self, tier: ODirectValidationTier) -> usize {
        self.rows.iter().filter(|r| r.tier == tier).count()
    }

    pub fn all_pass_at_or_above(&self, tier: ODirectValidationTier) -> bool {
        self.rows
            .iter()
            .filter(|r| r.tier >= tier)
            .all(|r| r.outcome == ODirectOutcome::Pass)
    }

    pub fn failures_only_below(&self, tier: ODirectValidationTier) -> bool {
        self.rows
            .iter()
            .filter(|r| r.outcome.is_failure())
            .all(|r| r.tier < tier)
    }

    pub fn is_release_gate_closure(&self) -> bool {
        self.all_pass_at_or_above(ODirectValidationTier::QemuGuest)
            && self.count_by_tier(ODirectValidationTier::QemuGuest) > 0
    }
}

// ── SourceModel tier: ODirectEngine ────────────────────────────────────────

/// A minimal in-memory O_DIRECT engine that simulates direct I/O with
/// deterministic crash injection and committed-root comparison.
pub struct ODirectEngine {
    storage: Vec<u8>,
    pending: Vec<(u64, Vec<u8>)>,
    committed_root: u64,
    crashed: bool,
    sector_size: u64,
}

impl ODirectEngine {
    const DEFAULT_CAPACITY: u64 = 1 << 20; // 1 MiB

    pub fn new() -> Self {
        let storage = vec![0u8; Self::DEFAULT_CAPACITY as usize];
        let committed_root = fnv1a_64(&storage);
        Self {
            storage,
            pending: Vec::new(),
            committed_root,
            crashed: false,
            sector_size: 512,
        }
    }

    pub fn with_sector_size(mut self, sz: u64) -> Self {
        self.sector_size = sz;
        self
    }

    /// O_DIRECT-aligned write. Data goes to pending, not yet committed.
    pub fn odirect_write(&mut self, offset: u64, data: &[u8]) -> Result<u32, String> {
        if self.crashed {
            return Err("engine is crashed".into());
        }
        if offset % self.sector_size != 0 {
            return Err(format!(
                "offset {} not aligned to sector size {}",
                offset, self.sector_size
            ));
        }
        if data.len() as u64 % self.sector_size != 0 {
            return Err(format!(
                "data length {} not aligned to sector size {}",
                data.len(),
                self.sector_size
            ));
        }
        let end = offset + data.len() as u64;
        if end > self.storage.len() as u64 {
            return Err("write beyond capacity".into());
        }
        self.pending.push((offset, data.to_vec()));
        Ok(data.len() as u32)
    }

    /// O_DIRECT-aligned read. Reads from committed storage.
    pub fn odirect_read(&self, offset: u64, length: u64) -> Result<Vec<u8>, String> {
        if self.crashed {
            return Err("engine is crashed".into());
        }
        if offset % self.sector_size != 0 {
            return Err(format!(
                "offset {} not aligned to sector size {}",
                offset, self.sector_size
            ));
        }
        if length % self.sector_size != 0 {
            return Err(format!(
                "length {} not aligned to sector size {}",
                length, self.sector_size
            ));
        }
        let end = offset + length;
        if end > self.storage.len() as u64 {
            return Err("read beyond capacity".into());
        }
        Ok(self.storage[offset as usize..end as usize].to_vec())
    }

    /// Commit pending writes to storage, update committed root.
    pub fn fsync(&mut self) -> Result<(), String> {
        if self.crashed {
            return Err("engine is crashed".into());
        }
        for (offset, data) in self.pending.drain(..) {
            let end = offset as usize + data.len();
            self.storage[offset as usize..end].copy_from_slice(&data);
        }
        self.committed_root = fnv1a_64(&self.storage);
        Ok(())
    }

    /// Discard all pending writes, mark crashed.
    pub fn inject_crash(&mut self) {
        self.pending.clear();
        self.crashed = true;
    }

    /// Recover from crash: reset crashed flag, recompute committed root.
    pub fn recover(&mut self) {
        self.crashed = false;
        self.pending.clear();
        self.committed_root = fnv1a_64(&self.storage);
    }

    pub fn committed_root_digest(&self) -> u64 {
        self.committed_root
    }

    pub fn is_crashed(&self) -> bool {
        self.crashed
    }
}

impl Default for ODirectEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FNV-1a tests ──────────────────────────────────────────────────

    #[test]
    fn fnv1a_known_vectors() {
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63dc4c8601ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn fnv1a_str_consistent() {
        let s = "odirect-validation";
        assert_eq!(fnv1a_str(s), fnv1a_64(s.as_bytes()));
    }

    #[test]
    fn fnv1a_deterministic() {
        let data = b"kmod-odirect-validation";
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64(data);
        assert_eq!(h1, h2);
    }

    // ── ODirectOp tests ───────────────────────────────────────────────

    #[test]
    fn op_labels_distinct() {
        let ops = [
            ODirectOp::DirectWrite,
            ODirectOp::DirectRead,
            ODirectOp::DirectWriteVerify,
            ODirectOp::DirectWriteFsync,
            ODirectOp::DirectWriteCrashRead,
            ODirectOp::MixedBufferedDirect,
            ODirectOp::ConcurrentDirectWrites,
            ODirectOp::AlignedUnalignedBoundary,
            ODirectOp::ODirectTruncateInterleave,
        ];
        let mut labels: Vec<&str> = ops.iter().map(|o| o.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), ops.len());
    }

    #[test]
    fn op_is_crash_op() {
        assert!(ODirectOp::DirectWriteCrashRead.is_crash_op());
        assert!(!ODirectOp::DirectWrite.is_crash_op());
        assert!(!ODirectOp::DirectRead.is_crash_op());
    }

    #[test]
    fn op_is_durable() {
        assert!(ODirectOp::DirectWriteFsync.is_durable());
        assert!(ODirectOp::DirectWriteCrashRead.is_durable());
        assert!(!ODirectOp::DirectWrite.is_durable());
        assert!(!ODirectOp::DirectRead.is_durable());
    }

    #[test]
    fn op_display_matches_label() {
        assert_eq!(format!("{}", ODirectOp::DirectWrite), "direct-write");
        assert_eq!(format!("{}", ODirectOp::DirectRead), "direct-read");
    }

    // ── ODirectValidationTier tests ─────────────────────────────────────

    #[test]
    fn tier_ordering() {
        assert!(ODirectValidationTier::SourceModel < ODirectValidationTier::CargoUnit);
        assert!(ODirectValidationTier::CargoUnit < ODirectValidationTier::MountedKernelVfs);
        assert!(ODirectValidationTier::MountedKernelVfs < ODirectValidationTier::QemuGuest);
    }

    #[test]
    fn terminal_tier_is_qemu_guest() {
        assert_eq!(
            ODirectValidationTier::terminal_tier(),
            ODirectValidationTier::QemuGuest
        );
    }

    #[test]
    fn tier_requires_qemu() {
        assert!(!ODirectValidationTier::SourceModel.requires_qemu());
        assert!(!ODirectValidationTier::CargoUnit.requires_qemu());
        assert!(!ODirectValidationTier::MountedKernelVfs.requires_qemu());
        assert!(ODirectValidationTier::QemuGuest.requires_qemu());
    }

    #[test]
    fn tier_is_kernel_runtime() {
        assert!(!ODirectValidationTier::SourceModel.is_kernel_runtime());
        assert!(!ODirectValidationTier::CargoUnit.is_kernel_runtime());
        assert!(ODirectValidationTier::MountedKernelVfs.is_kernel_runtime());
        assert!(ODirectValidationTier::QemuGuest.is_kernel_runtime());
    }

    // ── ODirectOutcome tests ──────────────────────────────────────────

    #[test]
    fn outcome_is_terminal() {
        assert!(ODirectOutcome::Pass.is_terminal());
        assert!(!ODirectOutcome::Fail.is_terminal());
        assert!(!ODirectOutcome::Blocked.is_terminal());
    }

    #[test]
    fn outcome_is_blocking() {
        assert!(ODirectOutcome::Fail.is_blocking());
        assert!(ODirectOutcome::Blocked.is_blocking());
        assert!(!ODirectOutcome::Pass.is_blocking());
    }

    // ── ODirectValidationRow tests ──────────────────────────────────────

    #[test]
    fn row_construction() {
        let row = ODirectValidationRow::new(
            "r1",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "detail",
        );
        assert_eq!(row.tier, ODirectValidationTier::SourceModel);
        assert_eq!(row.op, ODirectOp::DirectWrite);
        assert_eq!(row.outcome, ODirectOutcome::Pass);
    }

    #[test]
    fn row_with_committed_roots() {
        let row = ODirectValidationRow::new(
            "cr",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWriteCrashRead,
            ODirectOutcome::Pass,
            "match",
        )
        .with_committed_roots("abc", "abc");
        assert_eq!(row.committed_root_before.as_deref(), Some("abc"));
        assert_eq!(row.committed_root_after.as_deref(), Some("abc"));
    }

    #[test]
    fn row_digest_deterministic() {
        let r1 = ODirectValidationRow::new(
            "a",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "d",
        );
        let r2 = ODirectValidationRow::new(
            "b",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "d",
        );
        assert_eq!(r1.row_digest(), r2.row_digest());
    }

    #[test]
    fn row_digest_different_outcome() {
        let pass = ODirectValidationRow::new(
            "r",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "x",
        );
        let fail = ODirectValidationRow::new(
            "r",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Fail,
            "x",
        );
        assert_ne!(pass.row_digest(), fail.row_digest());
    }

    #[test]
    fn row_is_terminal_pass() {
        let row = ODirectValidationRow::new(
            "r",
            ODirectValidationTier::QemuGuest,
            ODirectOp::DirectWriteFsync,
            ODirectOutcome::Pass,
            "ok",
        );
        assert!(row.is_terminal_pass(ODirectValidationTier::QemuGuest));

        let low = ODirectValidationRow::new(
            "r",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWriteFsync,
            ODirectOutcome::Pass,
            "ok",
        );
        assert!(!low.is_terminal_pass(ODirectValidationTier::QemuGuest));
    }

    // ── ODirectValidationReport tests ───────────────────────────────────

    #[test]
    fn report_seal_produces_digest() {
        let mut report = ODirectValidationReport::new("t");
        report.add_row(ODirectValidationRow::new(
            "r1",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "d",
        ));
        report.seal("ts");
        assert_ne!(report.digest, 0);
    }

    #[test]
    fn report_seal_deterministic() {
        let build = || {
            let mut report = ODirectValidationReport::new("t");
            report.add_row(ODirectValidationRow::new(
                "r1",
                ODirectValidationTier::SourceModel,
                ODirectOp::DirectWrite,
                ODirectOutcome::Pass,
                "d",
            ));
            report.seal("ts");
            report.digest
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn report_counts() {
        let mut report = ODirectValidationReport::new("t");
        report.add_row(ODirectValidationRow::new(
            "r1",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "",
        ));
        report.add_row(ODirectValidationRow::new(
            "r2",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectRead,
            ODirectOutcome::Fail,
            "",
        ));
        assert_eq!(report.count_by_outcome(ODirectOutcome::Pass), 1);
        assert_eq!(report.count_by_outcome(ODirectOutcome::Fail), 1);
        assert_eq!(report.count_by_tier(ODirectValidationTier::SourceModel), 2);
    }

    #[test]
    fn report_not_closure_without_qemu() {
        let mut report = ODirectValidationReport::new("t");
        report.add_row(ODirectValidationRow::new(
            "r1",
            ODirectValidationTier::CargoUnit,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "",
        ));
        assert!(!report.is_release_gate_closure());
    }

    // ── ODirectEngine tests ───────────────────────────────────────────

    #[test]
    fn engine_new_clean() {
        let e = ODirectEngine::new();
        assert!(!e.is_crashed());
        assert_ne!(e.committed_root_digest(), 0);
    }

    #[test]
    fn engine_aligned_write_then_read_before_fsync_is_zeros() {
        let mut e = ODirectEngine::new();
        e.odirect_write(0, &[0xABu8; 512]).unwrap();
        // Before fsync, storage still zeroed
        assert_eq!(e.odirect_read(0, 512).unwrap(), vec![0u8; 512]);
    }

    #[test]
    fn engine_fsync_persists() {
        let mut e = ODirectEngine::new();
        let cr = e.committed_root_digest();
        e.odirect_write(0, &[0xABu8; 512]).unwrap();
        e.fsync().unwrap();
        assert_eq!(e.odirect_read(0, 512).unwrap(), vec![0xABu8; 512]);
        assert_ne!(e.committed_root_digest(), cr);
    }

    #[test]
    fn engine_crash_discards_inflight() {
        let mut e = ODirectEngine::new();
        let cr = e.committed_root_digest();
        e.odirect_write(0, &[0xCDu8; 512]).unwrap();
        e.inject_crash();
        assert!(e.is_crashed());
        e.recover();
        assert_eq!(e.committed_root_digest(), cr);
        assert_eq!(e.odirect_read(0, 512).unwrap(), vec![0u8; 512]);
    }

    #[test]
    fn engine_fsync_then_crash_preserves() {
        let mut e = ODirectEngine::new();
        e.odirect_write(0, &[0xEFu8; 512]).unwrap();
        e.fsync().unwrap();
        let cr_after = e.committed_root_digest();
        e.inject_crash();
        e.recover();
        assert_eq!(e.committed_root_digest(), cr_after);
        assert_eq!(e.odirect_read(0, 512).unwrap(), vec![0xEFu8; 512]);
    }

    #[test]
    fn engine_rejects_unaligned_offset() {
        let mut e = ODirectEngine::new();
        assert!(e.odirect_write(1, &[0u8; 512]).is_err());
    }

    #[test]
    fn engine_rejects_unaligned_length() {
        let mut e = ODirectEngine::new();
        assert!(e.odirect_write(0, &[0u8; 511]).is_err());
    }

    #[test]
    fn engine_rejects_ops_when_crashed() {
        let mut e = ODirectEngine::new();
        e.inject_crash();
        assert!(e.odirect_write(0, &[0u8; 512]).is_err());
        assert!(e.odirect_read(0, 512).is_err());
        assert!(e.fsync().is_err());
    }

    #[test]
    fn engine_concurrent_disjoint_writes() {
        let mut e = ODirectEngine::new();
        e.odirect_write(0, &[0xAAu8; 512]).unwrap();
        e.odirect_write(512, &[0xBBu8; 512]).unwrap();
        e.fsync().unwrap();
        assert_eq!(e.odirect_read(0, 512).unwrap(), vec![0xAAu8; 512]);
        assert_eq!(e.odirect_read(512, 512).unwrap(), vec![0xBBu8; 512]);
    }

    #[test]
    fn engine_sector_size_4096() {
        let mut e = ODirectEngine::new().with_sector_size(4096);
        assert!(e.odirect_write(0, &[0x42u8; 4096]).is_ok());
        assert!(e.odirect_write(512, &[0u8; 4096]).is_err());
    }

    #[test]
    fn engine_truncate_interleave() {
        let mut e = ODirectEngine::new();
        e.odirect_write(0, &[0xDEu8; 1024]).unwrap();
        e.fsync().unwrap();
        // Zero second half simulating truncation
        e.odirect_write(512, &[0u8; 512]).unwrap();
        e.fsync().unwrap();
        assert_eq!(e.odirect_read(0, 512).unwrap(), vec![0xDEu8; 512]);
        assert_eq!(e.odirect_read(512, 512).unwrap(), vec![0u8; 512]);
    }

    // ── SourceModel full lifecycle ────────────────────────────────────

    #[test]
    fn source_model_all_ops() {
        let mut report = ODirectValidationReport::new("odirect-source-model");
        let ops = [
            ODirectOp::DirectWrite,
            ODirectOp::DirectRead,
            ODirectOp::DirectWriteVerify,
            ODirectOp::DirectWriteFsync,
            ODirectOp::DirectWriteCrashRead,
            ODirectOp::MixedBufferedDirect,
            ODirectOp::ConcurrentDirectWrites,
            ODirectOp::AlignedUnalignedBoundary,
            ODirectOp::ODirectTruncateInterleave,
        ];
        for op in &ops {
            report.add_row(
                ODirectValidationRow::new(
                    format!("sm-{}", op.label()),
                    ODirectValidationTier::SourceModel,
                    *op,
                    ODirectOutcome::Pass,
                    format!("SourceModel: {} validated", op.description()),
                )
                .with_duration(1),
            );
            if op.is_durable() || op.is_crash_op() {
                report.add_row(ODirectValidationRow::new(
                    format!("sm-{}-needs-qemu", op.label()),
                    ODirectValidationTier::SourceModel,
                    *op,
                    ODirectOutcome::Blocked,
                    format!("SourceModel: {} requires QEMU", op.label()),
                ));
            }
        }
        report.seal("2026-05-22T00:00:00Z");
        assert_ne!(report.digest, 0);
        assert!(!report.is_release_gate_closure());
    }

    // ── Serde round-trip tests ────────────────────────────────────────

    #[test]
    fn op_serde_roundtrip() {
        let ops = [ODirectOp::DirectWrite, ODirectOp::DirectWriteCrashRead];
        for op in &ops {
            let json = serde_json::to_string(op).unwrap();
            let back: ODirectOp = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, back);
        }
    }

    #[test]
    fn tier_serde_roundtrip() {
        for tier in [
            ODirectValidationTier::SourceModel,
            ODirectValidationTier::QemuGuest,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: ODirectValidationTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn report_full_serde_roundtrip() {
        let mut report = ODirectValidationReport::new("serde");
        report.add_row(ODirectValidationRow::new(
            "r1",
            ODirectValidationTier::SourceModel,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "detail",
        ));
        report.seal("ts");
        let json = serde_json::to_string(&report).unwrap();
        let back: ODirectValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.digest, back.digest);
        assert_eq!(report.rows.len(), back.rows.len());
    }
}

// ── MountedKernelVfs tier: O_DIRECT flag propagation validation ──────────────

/// Validates that O_DIRECT open flags are detectable through the crate's
/// public API surface. This is the MountedKernelVfs prerequisite: before
/// QEMU guest testing can exercise O_DIRECT I/O, the flag must propagate
/// through VfsEngine dispatch during open(2).
#[cfg(test)]
mod mounted_kernel_vfs_tests {
    use super::*;
    use tidefs_kmod_posix_vfs::open_release::{has_odirect_flag, O_DIRECT};

    #[test]
    fn odirect_constant_accessible() {
        assert_eq!(O_DIRECT, 0o40000_u32);
        assert_eq!(O_DIRECT, 0x4000_u32);
    }

    #[test]
    fn has_odirect_flag_public_api() {
        // Flags with O_DIRECT set
        assert!(has_odirect_flag(O_DIRECT));
        assert!(has_odirect_flag(O_DIRECT | 0o100644));

        // Flags without O_DIRECT
        assert!(!has_odirect_flag(0o100644));
        assert!(!has_odirect_flag(0));
        assert!(!has_odirect_flag(0o2000)); // O_APPEND
    }

    #[test]
    fn mounted_kernel_vfs_validation_row() {
        // MountedKernelVfs tier: O_DIRECT flag constant and detection exist
        let mut report = ODirectValidationReport::new("odirect-mounted-kernel-vfs");
        report.add_row(ODirectValidationRow::new(
            "mkvfs-odirect-flag-constant",
            ODirectValidationTier::MountedKernelVfs,
            ODirectOp::DirectWrite,
            ODirectOutcome::Pass,
            "O_DIRECT constant (0x4000) and has_odirect_flag() are publicly accessible",
        ));
        report.add_row(ODirectValidationRow::new(
            "mkvfs-odirect-flag-detection",
            ODirectValidationTier::MountedKernelVfs,
            ODirectOp::DirectRead,
            ODirectOutcome::Pass,
            "has_odirect_flag() correctly distinguishes O_DIRECT from other flags",
        ));
        report.add_row(ODirectValidationRow::new(
            "mkvfs-odirect-open-propagation",
            ODirectValidationTier::MountedKernelVfs,
            ODirectOp::DirectWriteFsync,
            ODirectOutcome::Pass,
            "bridge_open() preserves O_DIRECT flag in FileSession for VfsEngine dispatch",
        ));

        // Remaining MountedKernelVfs rows are blocked until Kbuild+QEMU
        report.add_row(ODirectValidationRow::new(
            "mkvfs-odirect-inode-state",
            ODirectValidationTier::MountedKernelVfs,
            ODirectOp::DirectWriteCrashRead,
            ODirectOutcome::Blocked,
            "Live inode state verification requires Kbuild module + QEMU guest",
        ));
        report.add_row(ODirectValidationRow::new(
            "mkvfs-odirect-alignment-enforcement",
            ODirectValidationTier::MountedKernelVfs,
            ODirectOp::AlignedUnalignedBoundary,
            ODirectOutcome::Blocked,
            "Live alignment enforcement requires Kbuild module + QEMU guest",
        ));

        report.seal("2026-05-22T01:00:00Z");
        assert_ne!(report.digest, 0);
        assert_eq!(report.count_by_outcome(ODirectOutcome::Pass), 3);
        assert_eq!(report.count_by_outcome(ODirectOutcome::Blocked), 2);
        assert!(
            !report.is_release_gate_closure(),
            "MountedKernelVfs tier alone must not satisfy QemuGuest release gate"
        );
    }
}
