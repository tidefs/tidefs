// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted acknowledgment-receipt evidence for issue #2223.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde::Serialize;
use tidefs_local_filesystem::ack_receipt::{
    LocalAckConvergenceState, LocalAckOperation, LocalAckReceipt, LocalAckReceiptDisposition,
};
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_validation::evidence_artifact_manifest::{
    content_digest_for_bytes, BlockingIssueRef, EvidenceArtifactManifest,
    EVIDENCE_ARTIFACT_MANIFEST_VERSION,
};
use tidefs_validation::validation_schema::ValidationTier;
use tidefs_validation::validation_status::ValidationStatus;

const OUTPUT_DIR_ENV: &str = "TIDEFS_ACK_RECEIPT_RUNTIME_OUTPUT_DIR";
const CLAIM_ID: &str = "storage.intent.ack_receipt_honesty.v1";
const EVIDENCE_CLASS: &str = "storage-intent-ack-receipt-runtime";
const ARTIFACT_PATH: &str = "validation/artifacts/storage-intent/ack-receipt-runtime.json";
const MANIFEST_PATH: &str = "validation/artifacts/storage-intent/ack-receipt-runtime.manifest.json";
const SOURCE: &str = "mounted-fuse-ack-receipt-runtime-v1";
const ISSUE_URL: &str = "https://github.com/tidefs/tidefs/issues/2223";
const PARENT_ISSUE_URL: &str = "https://github.com/tidefs/tidefs/issues/1794";
const RECEIPT_CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, Serialize)]
struct RuntimeReport {
    report_version: u32,
    claim_id: &'static str,
    issue: &'static str,
    parent_issue: &'static str,
    run_id: String,
    source_ref: String,
    generated_at: String,
    validation_tier: ValidationTier,
    command: String,
    backend: RuntimeBackend,
    rows: Vec<RuntimeRow>,
    summary: RuntimeSummary,
    residual_risk: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RuntimeBackend {
    kind: &'static str,
    kernel_release: String,
    mount_options: Vec<&'static str>,
    receipt_source: &'static str,
}

#[derive(Debug, Serialize)]
struct RuntimeRow {
    row_id: &'static str,
    syscall: &'static str,
    expected_receipt_operation: &'static str,
    syscall_result: String,
    errno: Option<i32>,
    observed_receipts: Vec<ReceiptObservation>,
    outcome: ValidationStatus,
    reason: String,
}

#[derive(Debug, Serialize)]
struct ReceiptObservation {
    operation: &'static str,
    requested_ack_floor: &'static str,
    earned_ack_class: &'static str,
    disposition: &'static str,
    convergence: &'static str,
    durability_state: String,
    target_inode: Option<u64>,
    target_offset: u64,
    target_length: u64,
    target_has_range: bool,
    evidence_ref_count: usize,
    refusal_reason: String,
    posix_durable_success: bool,
    satisfies_requested_ack_floor: bool,
}

#[derive(Debug, Serialize)]
struct RuntimeSummary {
    status: ValidationStatus,
    passed: usize,
    product_failed: usize,
    harness_failed: usize,
    environment_refused: usize,
    skipped: usize,
}

struct MountedReceiptHarness {
    _root: tempfile::TempDir,
    mountpoint: PathBuf,
    session: Option<fuser::BackgroundSession>,
    receipts: Receiver<LocalAckReceipt>,
}

impl MountedReceiptHarness {
    fn new() -> Result<Self, String> {
        if !Path::new("/dev/fuse").exists() {
            return Err("/dev/fuse is not available".to_string());
        }

        let root = tempfile::Builder::new()
            .prefix("tidefs-ack-receipt-runtime-")
            .tempdir()
            .map_err(|error| format!("create harness root: {error}"))?;
        let store = root.path().join("store");
        let mountpoint = root.path().join("mnt");
        fs::create_dir_all(&store).map_err(|error| format!("create store: {error}"))?;
        fs::create_dir_all(&mountpoint).map_err(|error| format!("create mountpoint: {error}"))?;

        let (sender, receipts) = mpsc::sync_channel(RECEIPT_CHANNEL_CAPACITY);
        let mut filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .map_err(|error| format!("open local filesystem: {error}"))?;
        filesystem.set_auto_commit(false);
        filesystem.set_local_ack_receipt_diagnostic_sink(sender);

        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine))
            .map_err(|error| format!("create FUSE adapter: {error:?}"))?;
        let options = [
            fuser::MountOption::FSName("tidefs-ack-receipt-runtime".to_string()),
            fuser::MountOption::Subtype("tidefs".to_string()),
            fuser::MountOption::RW,
            fuser::MountOption::NoDev,
            fuser::MountOption::NoSuid,
        ];
        let session = fuser::spawn_mount2(adapter, &mountpoint, &options)
            .map_err(|error| format!("mount FUSE adapter: {error}"))?;

        let mut ready = false;
        for _ in 0..50 {
            if fs::metadata(&mountpoint).is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !ready {
            drop(session);
            return Err("mounted FUSE path did not become ready".to_string());
        }

        Ok(Self {
            _root: root,
            mountpoint,
            session: Some(session),
            receipts,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.mountpoint.join(name.trim_start_matches('/'))
    }

    fn clear_receipts(&self) {
        std::thread::sleep(Duration::from_millis(25));
        for _ in self.receipts.try_iter() {}
    }

    fn collect_receipts(&self) -> Vec<LocalAckReceipt> {
        std::thread::sleep(Duration::from_millis(25));
        self.receipts.try_iter().collect()
    }

    fn record_row<F>(
        &self,
        row_id: &'static str,
        syscall: &'static str,
        expected_operation: LocalAckOperation,
        explicit_refusal_allowed: bool,
        operation: F,
    ) -> RuntimeRow
    where
        F: FnOnce() -> io::Result<()>,
    {
        self.clear_receipts();
        let result = operation();
        let receipts = self.collect_receipts();
        classify_row(
            row_id,
            syscall,
            expected_operation,
            explicit_refusal_allowed,
            result,
            receipts,
        )
    }
}

impl Drop for MountedReceiptHarness {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn classify_row(
    row_id: &'static str,
    syscall: &'static str,
    expected_operation: LocalAckOperation,
    explicit_refusal_allowed: bool,
    result: io::Result<()>,
    receipts: Vec<LocalAckReceipt>,
) -> RuntimeRow {
    let observed_receipts = receipts
        .iter()
        .copied()
        .map(receipt_observation)
        .collect::<Vec<_>>();
    let matching_receipt = receipts.iter().copied().find(|receipt| {
        receipt.operation == expected_operation && receipt.satisfies_requested_ack_floor()
    });
    let contradictory_durable_receipt = receipts
        .iter()
        .copied()
        .any(LocalAckReceipt::satisfies_requested_ack_floor);

    let (syscall_result, errno, outcome, reason) = match result {
        Ok(()) if matching_receipt.is_some() => (
            "success".to_string(),
            None,
            ValidationStatus::Pass,
            format!(
                "mounted syscall returned success with an earned {} receipt",
                expected_operation.as_str()
            ),
        ),
        Ok(()) => (
            "success".to_string(),
            None,
            ValidationStatus::ProductFail,
            format!(
                "mounted syscall returned success without an earned {} receipt",
                expected_operation.as_str()
            ),
        ),
        Err(error)
            if explicit_refusal_allowed
                && is_explicit_unsupported_refusal(&error)
                && !contradictory_durable_receipt =>
        {
            (
                "refused".to_string(),
                error.raw_os_error(),
                ValidationStatus::Pass,
                format!("unsupported mounted operation failed closed: {error}"),
            )
        }
        Err(error) => (
            "error".to_string(),
            error.raw_os_error(),
            ValidationStatus::ProductFail,
            format!("mounted syscall did not produce an accepted receipt or refusal: {error}"),
        ),
    };

    RuntimeRow {
        row_id,
        syscall,
        expected_receipt_operation: expected_operation.as_str(),
        syscall_result,
        errno,
        observed_receipts,
        outcome,
        reason,
    }
}

fn is_explicit_unsupported_refusal(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENODEV | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

fn receipt_observation(receipt: LocalAckReceipt) -> ReceiptObservation {
    ReceiptObservation {
        operation: receipt.operation.as_str(),
        requested_ack_floor: receipt.requested_ack_floor.as_str(),
        earned_ack_class: receipt.receipt.ack_class.as_str(),
        disposition: disposition_label(receipt.disposition),
        convergence: convergence_label(receipt.convergence),
        durability_state: format!("{:?}", receipt.receipt.durability.state),
        target_inode: receipt.target.inode_id,
        target_offset: receipt.target.offset,
        target_length: receipt.target.length,
        target_has_range: receipt.target.has_range,
        evidence_ref_count: receipt.receipt.evidence_refs.len(),
        refusal_reason: format!("{:?}", receipt.refusal_reason()),
        posix_durable_success: receipt.is_posix_durable_success(),
        satisfies_requested_ack_floor: receipt.satisfies_requested_ack_floor(),
    }
}

fn disposition_label(disposition: LocalAckReceiptDisposition) -> &'static str {
    match disposition {
        LocalAckReceiptDisposition::DurablePosix => "durable-posix",
        LocalAckReceiptDisposition::WeakerUnsafeVolatile => "weaker-unsafe-volatile",
        LocalAckReceiptDisposition::Refused => "refused",
        LocalAckReceiptDisposition::Unknown => "unknown",
        LocalAckReceiptDisposition::Blocked => "blocked",
    }
}

fn convergence_label(convergence: LocalAckConvergenceState) -> &'static str {
    match convergence {
        LocalAckConvergenceState::Satisfied => "satisfied",
        LocalAckConvergenceState::PendingFullPlacement => "pending-full-placement",
        LocalAckConvergenceState::Converging => "converging",
        LocalAckConvergenceState::DegradedVisible => "degraded-visible",
        LocalAckConvergenceState::Unknown => "unknown",
        LocalAckConvergenceState::Blocked => "blocked",
        LocalAckConvergenceState::Refused => "refused",
    }
}

fn write_payload(path: &Path, flags: i32, payload: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(flags)
        .open(path)?;
    file.write_all(payload)
}

fn fsync_file(path: &Path, datasync: bool) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(b"mounted receipt barrier payload")?;
    if datasync {
        file.sync_data()
    } else {
        file.sync_all()
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)?
        .sync_all()
}

#[allow(unsafe_code)]
fn shared_mmap_msync(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(4096)?;

    // SAFETY: `file` stays open for the mapping lifetime; the mapping length
    // matches the file length, and successful mappings are unmapped exactly
    // once before returning.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `mapping` names a writable 4096-byte mapping returned above.
    unsafe {
        std::ptr::write_volatile(mapping.cast::<u8>(), 0x5a);
    }
    // SAFETY: the mapping remains valid and the requested range is exactly
    // the mapped range.
    let sync_result = unsafe { libc::msync(mapping, 4096, libc::MS_SYNC) };
    let sync_error = (sync_result != 0).then(io::Error::last_os_error);
    // SAFETY: `mapping` is still live and has not previously been unmapped.
    let unmap_result = unsafe { libc::munmap(mapping, 4096) };
    if let Some(error) = sync_error {
        return Err(error);
    }
    if unmap_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn runtime_summary(rows: &[RuntimeRow]) -> RuntimeSummary {
    let count = |status| rows.iter().filter(|row| row.outcome == status).count();
    let product_failed = count(ValidationStatus::ProductFail);
    let harness_failed = count(ValidationStatus::HarnessFail);
    let environment_refused = count(ValidationStatus::EnvironmentRefusal);
    let skipped = count(ValidationStatus::Skip);
    let status = if harness_failed > 0 {
        ValidationStatus::HarnessFail
    } else if product_failed > 0 {
        ValidationStatus::ProductFail
    } else if environment_refused > 0 {
        ValidationStatus::EnvironmentRefusal
    } else if skipped > 0 {
        ValidationStatus::Skip
    } else {
        ValidationStatus::Pass
    };
    RuntimeSummary {
        status,
        passed: count(ValidationStatus::Pass),
        product_failed,
        harness_failed,
        environment_refused,
        skipped,
    }
}

fn provenance(name: &str, fallback: String) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(fallback)
}

fn write_report_and_manifest(output_dir: &Path, report: &RuntimeReport) -> Result<(), String> {
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("create runtime evidence output: {error}"))?;
    let mut report_bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("encode runtime evidence: {error}"))?;
    report_bytes.push(b'\n');
    fs::write(output_dir.join("ack-receipt-runtime.json"), &report_bytes)
        .map_err(|error| format!("write runtime evidence: {error}"))?;

    let blocking_issues = if report.summary.status == ValidationStatus::Pass {
        Vec::new()
    } else {
        vec![BlockingIssueRef {
            repo: Some("tidefs/tidefs".to_string()),
            number: 2223,
            reason: Some(
                "mounted acknowledgment runtime rows have not all earned their exact receipt or explicit refusal"
                    .to_string(),
            ),
        }]
    };
    let manifest = EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: CLAIM_ID.to_string(),
        evidence_class: EVIDENCE_CLASS.to_string(),
        validation_tier: ValidationTier::MountedUserspace,
        scope: format!(
            "live FUSE mounted acknowledgment receipt and refusal rows for write, fsync, fdatasync, O_DSYNC, shared mmap MS_SYNC, namespace mutation, and fsyncdir; outcome={} pass={} product_fail={}",
            report.summary.status.label(), report.summary.passed, report.summary.product_failed
        ),
        artifact_path: ARTIFACT_PATH.to_string(),
        content_digest: content_digest_for_bytes(&report_bytes),
        run_id: report.run_id.clone(),
        source_ref: report.source_ref.clone(),
        outcome: report.summary.status,
        residual_risk: report.residual_risk.join(" "),
        source: SOURCE.to_string(),
        generated_at: report.generated_at.clone(),
        blocking_issues,
    };
    let mut manifest_json = manifest
        .to_json_pretty()
        .map_err(|error| error.to_string())?;
    manifest_json.push('\n');
    fs::write(
        output_dir.join("ack-receipt-runtime.manifest.json"),
        manifest_json,
    )
    .map_err(|error| format!("write runtime evidence manifest: {error}"))?;
    Ok(())
}

#[test]
#[ignore = "manual mounted evidence producer; use Storage Intent Ack Runtime workflow"]
fn produce_mounted_ack_receipt_runtime_evidence() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("ENVIRONMENT REFUSAL: /dev/fuse is not available");
        return;
    }
    let output_dir = env::var_os(OUTPUT_DIR_ENV).map(PathBuf::from);

    let harness = MountedReceiptHarness::new().expect("create mounted receipt harness");
    let mut rows = Vec::new();
    rows.push(harness.record_row(
        "sync-write-receipt",
        "write(O_SYNC)",
        LocalAckOperation::SyncWrite,
        false,
        || write_payload(&harness.path("sync-write.bin"), libc::O_SYNC, b"sync write"),
    ));
    rows.push(harness.record_row(
        "fsync-receipt",
        "fsync",
        LocalAckOperation::Fsync,
        false,
        || fsync_file(&harness.path("fsync.bin"), false),
    ));
    rows.push(harness.record_row(
        "fdatasync-receipt",
        "fdatasync",
        LocalAckOperation::Fdatasync,
        false,
        || fsync_file(&harness.path("fdatasync.bin"), true),
    ));
    rows.push(harness.record_row(
        "odsync-receipt",
        "write(O_DSYNC)",
        LocalAckOperation::Odsync,
        false,
        || write_payload(&harness.path("odsync.bin"), libc::O_DSYNC, b"odsync write"),
    ));
    rows.push(harness.record_row(
        "shared-mmap-msync-receipt-or-refusal",
        "mmap(MAP_SHARED)+msync(MS_SYNC)",
        LocalAckOperation::SharedMmapMsync,
        true,
        || shared_mmap_msync(&harness.path("mmap.bin")),
    ));
    rows.push(harness.record_row(
        "namespace-receipt",
        "create+rename+fsync(parent)",
        LocalAckOperation::FsyncDirectory,
        false,
        || {
            let source = harness.path("namespace-source");
            let target = harness.path("namespace-target");
            File::create(&source)?.write_all(b"namespace payload")?;
            fs::rename(source, target)?;
            sync_directory(&harness.mountpoint)
        },
    ));
    rows.push(harness.record_row(
        "fsyncdir-receipt",
        "fsyncdir",
        LocalAckOperation::FsyncDirectory,
        false,
        || {
            let directory = harness.path("synced-directory");
            fs::create_dir(&directory)?;
            File::create(directory.join("child"))?.write_all(b"fsyncdir payload")?;
            sync_directory(&directory)
        },
    ));

    assert_eq!(rows.len(), 7, "every issue #2223 mounted row is classified");
    let summary = runtime_summary(&rows);
    let report = RuntimeReport {
        report_version: 1,
        claim_id: CLAIM_ID,
        issue: ISSUE_URL,
        parent_issue: PARENT_ISSUE_URL,
        run_id: provenance(
            "TIDEFS_ACK_RECEIPT_RUNTIME_RUN_ID",
            format!("local/{}", std::process::id()),
        ),
        source_ref: provenance(
            "TIDEFS_ACK_RECEIPT_RUNTIME_SOURCE_REF",
            "unknown-local-source".to_string(),
        ),
        generated_at: provenance(
            "TIDEFS_ACK_RECEIPT_RUNTIME_GENERATED_AT",
            "1970-01-01T00:00:00Z".to_string(),
        ),
        validation_tier: ValidationTier::MountedUserspace,
        command: "cargo test -p tidefs-posix-filesystem-adapter-daemon --test ack_receipt_runtime_evidence --locked -- --nocapture".to_string(),
        backend: RuntimeBackend {
            kind: "live-fuse-local-object-store",
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string(),
            mount_options: vec!["rw", "nodev", "nosuid", "subtype=tidefs"],
            receipt_source: "bounded LocalAckReceiptLedger diagnostic copies",
        },
        rows,
        summary,
        residual_risk: vec![
            "This evidence is bounded to one live local FUSE mount and the exact operations recorded; it is not crash, power-loss, stale-media, distributed-quorum, kernel-VFS, successor, production, or release evidence.".to_string(),
            "A product-fail outcome keeps the claim blocked and identifies mounted operations that returned success without the exact earned receipt; workflow success means evidence capture succeeded, not that every product row passed.".to_string(),
            "The receipt channel is best-effort diagnostic output after the authoritative ledger records a receipt; missing diagnostic copies cannot weaken or strengthen an acknowledgment.".to_string(),
        ],
    };

    if let Some(output_dir) = output_dir {
        write_report_and_manifest(&output_dir, &report)
            .expect("write mounted receipt report and manifest");
    }
    eprintln!(
        "mounted ack receipt evidence: outcome={} passed={} product_failed={} artifact={} manifest={} output_enabled={}",
        report.summary.status.label(),
        report.summary.passed,
        report.summary.product_failed,
        ARTIFACT_PATH,
        MANIFEST_PATH,
        env::var_os(OUTPUT_DIR_ENV).is_some(),
    );
}
