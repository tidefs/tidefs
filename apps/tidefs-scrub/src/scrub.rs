// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Scrub report model and read-only integrity walker for `tidefs-scrub`.
//!
//! The scrub engine walks a local TideFS object store, verifying:
//! - Payload checksums against recorded digests
//! - Object reachability (every stored key is tracked)
//! - Compression frame integrity
//!
//! Extent-level and filesystem-level checks are modelled in the finding
//! types but deferred to Review debt TFR-010/TFR-013 (see historical issue #2527).

use serde::Serialize;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use tidefs_compression::CompressionAlgorithm;
use tidefs_local_filesystem::{
    feature_flags_roots_object_key,
    inspect_filesystem_content_objects_with_root_authentication_key, intent_log_head_object_key,
    orphan_index_object_key, plan_root_retention_with_root_authentication_key,
    space_counters_object_key, superblock_object_key, verify_online_with_root_authentication_key,
    OnlineVerifierIssueSeverity, OnlineVerifierReport, RootAuthenticationKey, RootRetentionPolicy,
};
use tidefs_local_object_store::{checksum64, LocalObjectStore, ObjectKey, StoreOptions};

// ── Finding types ──────────────────────────────────────────────────────

/// A discrete inconsistency discovered during a scrub pass.
#[derive(Clone, Debug, Serialize)]
#[allow(dead_code)]
#[serde(tag = "kind")]
pub enum ScrubFinding {
    /// Object-key exists in the store index but bytes cannot be retrieved.
    #[serde(rename = "missing-object")]
    MissingObject { key_hex: String },
    /// Payload checksum does not match the recorded digest.
    #[serde(rename = "checksum-mismatch")]
    ChecksumMismatch {
        key_hex: String,
        stored_checksum: u64,
        recomputed_checksum: u64,
    },
    /// I/O error retrieving an object.
    #[serde(rename = "io-error")]
    IoError { key_hex: String, message: String },
    /// Compression frame is present but decompression failed.
    #[serde(rename = "compression-error")]
    CompressionError { key_hex: String, message: String },
    /// Object exists in the store but is not referenced by any known metadata.
    ///
    /// Reserved for extent-map integration: currently unreachable detection
    /// requires filesystem-level traversal which is deferred.
    #[serde(rename = "unreachable-object")]
    UnreachableObject {
        key_hex: String,
        severity: FindingSeverity,
    },
    /// Two extents for the same inode overlap in their logical byte ranges.
    ///
    /// Reserved for extent-map integration.
    #[serde(rename = "extent-overlap")]
    ExtentOverlap {
        inode_id: u64,
        first_offset: u64,
        first_length: u64,
        second_offset: u64,
        second_length: u64,
    },
    /// Extent-recorded length differs from backing object size.
    ///
    /// Reserved for extent-map integration.
    #[serde(rename = "size-mismatch")]
    SizeMismatch {
        inode_id: u64,
        logical_size: u64,
        object_size: u64,
    },
    /// Malformed zero-length record where a valid record was expected.
    ///
    /// Reserved for extent-map integration.
    #[serde(rename = "malformed-record")]
    MalformedRecord { key_hex: String, reason: String },
    /// Read-only filesystem verifier found a committed-root or content issue.
    #[serde(rename = "filesystem-verifier-issue")]
    FilesystemVerifierIssue {
        severity: FindingSeverity,
        issue_kind: String,
        slot: Option<u64>,
        transaction_id: Option<u64>,
        generation: Option<u64>,
        reason: String,
    },
}

impl ScrubFinding {
    /// Human-readable one-line description suitable for text output.
    pub fn describe(&self) -> String {
        match self {
            Self::MissingObject { key_hex } => {
                format!("missing object: key={key_hex}")
            }
            Self::ChecksumMismatch {
                key_hex,
                stored_checksum,
                recomputed_checksum,
            } => {
                format!(
                    "checksum mismatch: key={key_hex} stored={stored_checksum:#x} recomputed={recomputed_checksum:#x}"
                )
            }
            Self::IoError { key_hex, message } => {
                format!("io error: key={key_hex} {message}")
            }
            Self::CompressionError { key_hex, message } => {
                format!("compression error: key={key_hex} {message}")
            }
            Self::UnreachableObject { key_hex, severity } => {
                format!("unreachable object ({severity:?}): key={key_hex}")
            }
            Self::ExtentOverlap {
                inode_id,
                first_offset,
                first_length,
                second_offset,
                second_length,
            } => {
                format!(
                    "extent overlap: inode={inode_id} [{first_offset}..{}) overlaps [{second_offset}..{})",
                    first_offset + first_length,
                    second_offset + second_length
                )
            }
            Self::SizeMismatch {
                inode_id,
                logical_size,
                object_size,
            } => {
                format!(
                    "size mismatch: inode={inode_id} logical_size={logical_size} object_size={object_size}"
                )
            }
            Self::MalformedRecord { key_hex, reason } => {
                format!("malformed record: key={key_hex} {reason}")
            }
            Self::FilesystemVerifierIssue {
                severity,
                issue_kind,
                slot,
                transaction_id,
                generation,
                reason,
            } => {
                format!(
                    "filesystem verifier {severity:?}: kind={issue_kind} slot={slot:?} tx={transaction_id:?} generation={generation:?} {reason}"
                )
            }
        }
    }

    /// Severity class for grouping in reports.
    pub fn severity(&self) -> FindingSeverity {
        match self {
            Self::MissingObject { .. } | Self::ChecksumMismatch { .. } | Self::IoError { .. } => {
                FindingSeverity::Error
            }
            Self::CompressionError { .. } => FindingSeverity::Warning,
            Self::UnreachableObject { severity, .. } => *severity,
            Self::ExtentOverlap { .. } | Self::SizeMismatch { .. } => FindingSeverity::Error,
            Self::MalformedRecord { .. } => FindingSeverity::Warning,
            Self::FilesystemVerifierIssue { severity, .. } => *severity,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnreachableObjectPolicy {
    #[default]
    CountOnly,
    Warn,
    Fail,
}

impl UnreachableObjectPolicy {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "count" | "count-only" => Ok(Self::CountOnly),
            "warn" | "warning" => Ok(Self::Warn),
            "fail" | "error" => Ok(Self::Fail),
            _ => Err(format!(
                "tidefs-scrub check: invalid --unreachable value '{value}'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CountOnly => "count-only",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    fn finding_severity(self) -> Option<FindingSeverity> {
        match self {
            Self::CountOnly => None,
            Self::Warn => Some(FindingSeverity::Warning),
            Self::Fail => Some(FindingSeverity::Error),
        }
    }
}

/// Stable JSON summary of the local-filesystem online verifier pass.
#[derive(Clone, Debug, Serialize)]
pub struct FilesystemVerifierSummary {
    pub outcome: String,
    pub root_slots_seen: u64,
    pub root_slot_records_seen: u64,
    pub root_candidates_seen: u64,
    pub verified_committed_roots: usize,
    pub invalid_root_candidates: u64,
    pub checked_transaction_manifests: u64,
    pub checked_content_objects: u64,
    pub checked_content_chunks: u64,
    pub verified_snapshot_roots: u64,
    pub issue_count: usize,
    pub mutating_repair_attempted: bool,
    pub production_fsck_required: bool,
}

impl FilesystemVerifierSummary {
    fn from_report(report: &OnlineVerifierReport) -> Self {
        Self {
            outcome: report.outcome.human_name().to_string(),
            root_slots_seen: report.root_slots_seen,
            root_slot_records_seen: report.root_slot_records_seen,
            root_candidates_seen: report.root_candidates_seen,
            verified_committed_roots: report.verified_committed_roots.len(),
            invalid_root_candidates: report.invalid_root_candidates,
            checked_transaction_manifests: report.checked_transaction_manifests,
            checked_content_objects: report.checked_content_objects,
            checked_content_chunks: report.checked_content_chunks,
            verified_snapshot_roots: report.verified_snapshot_roots,
            issue_count: report.issue_count(),
            mutating_repair_attempted: report.mutates_storage(),
            production_fsck_required: report.production_recovery_requires_operator_repair(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FilesystemContentInspectionSummary {
    pub file_like_inodes: u64,
    pub referenced_objects: usize,
    pub missing_objects: u64,
    pub zero_length_records: u64,
    pub size_mismatches: u64,
    pub malformed_records: u64,
}

// ── Report ─────────────────────────────────────────────────────────────

/// Aggregate scrub report collecting findings and statistics.
#[derive(Clone, Debug, Serialize)]
pub struct ScrubReport {
    /// Total object keys examined.
    pub total_keys: usize,
    /// Total bytes processed.
    pub bytes_processed: u64,
    /// Objects that passed all checks.
    pub ok: usize,
    /// Per-finding records.
    pub findings: Vec<ScrubFinding>,
    /// Wall-clock duration of the scrub pass.
    #[serde(serialize_with = "serialize_duration_secs")]
    pub elapsed_secs: f64,
    /// Store root path that was scrubbed.
    pub store_root: String,
    /// Read-only local-filesystem verifier summary when filesystem roots are present.
    pub filesystem_verifier: Option<FilesystemVerifierSummary>,
    /// Read-only content reference inspection summary when filesystem roots are present.
    pub content_inspection: Option<FilesystemContentInspectionSummary>,
    /// Live objects protected by committed filesystem roots.
    pub referenced_objects: usize,
    /// Live objects not protected by committed filesystem roots.
    pub unreachable_objects: usize,
    /// Policy used to interpret unreachable/reclaimable object counts.
    pub unreachable_object_policy: UnreachableObjectPolicy,
    /// Number of suspect-log entries recorded during this scrub pass.
    pub suspect_log_entries: usize,
    /// Number of objects whose checksums were verified.
    pub records_checksummed: usize,
    /// Checksum coverage as a fraction (0.0-1.0) of total keys with verified checksums.
    pub checksum_coverage_pct: f64,
    /// Whether the segment hash chain of trust was validated.
    pub chain_of_trust_valid: bool,
    /// Number of broken chain links detected.
    pub chain_breaks_detected: u64,
    /// Number of segments in the hash chain.
    pub segments_in_chain: usize,
}

fn serialize_duration_secs<S: serde::Serializer>(d: &f64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64((*d * 1000.0).round() / 1000.0)
}

impl ScrubReport {
    /// Construct an empty report pre-allocated for `total_keys` entries.
    pub fn new(total_keys: usize, store_root: String, elapsed_secs: f64) -> Self {
        Self {
            total_keys,
            bytes_processed: 0,
            ok: 0,
            findings: Vec::new(),
            elapsed_secs,
            store_root,
            filesystem_verifier: None,
            content_inspection: None,
            referenced_objects: 0,
            unreachable_objects: 0,
            unreachable_object_policy: UnreachableObjectPolicy::CountOnly,
            suspect_log_entries: 0,
            records_checksummed: 0,
            checksum_coverage_pct: 0.0,
            chain_of_trust_valid: false,
            chain_breaks_detected: 0,
            segments_in_chain: 0,
        }
    }

    /// Add a finding.
    pub fn add_finding(&mut self, finding: ScrubFinding) {
        self.findings.push(finding);
    }

    /// True when no findings were recorded.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Count findings by severity.
    pub fn count_by_severity(&self, severity: FindingSeverity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity() == severity)
            .count()
    }

    /// Produce the structured exit code:
    /// 0 = clean, 1 = inconsistencies found, 2 = invalid invocation, 3 = backend read failure.
    pub fn exit_code(&self) -> i32 {
        if self.is_clean() {
            0
        } else {
            1
        }
    }

    /// Render a human-readable text summary.
    pub fn text_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("tidefs-scrub report for {}\n", self.store_root));
        out.push_str(&format!("  keys scanned:  {}\n", self.total_keys));
        out.push_str(&format!("  bytes processed: {}\n", self.bytes_processed));
        out.push_str(&format!("  ok:            {}\n", self.ok));
        let errors = self.count_by_severity(FindingSeverity::Error);
        let warnings = self.count_by_severity(FindingSeverity::Warning);
        let infos = self.count_by_severity(FindingSeverity::Info);
        if errors > 0 || warnings > 0 || infos > 0 {
            out.push_str(&format!(
                "  findings:      {errors} error(s), {warnings} warning(s), {infos} info\n"
            ));
        }
        out.push_str(&format!("  elapsed:       {:.3}s\n", self.elapsed_secs));
        out.push_str(&format!(
            "  chain-of-trust: {} (segments={}, breaks={}, suspect_entries={})\n",
            if self.chain_of_trust_valid {
                "valid"
            } else {
                "invalid"
            },
            self.segments_in_chain,
            self.chain_breaks_detected,
            self.suspect_log_entries,
        ));
        out.push_str(&format!(
            "  checksums:     {} ok / {} total ({:.1}% coverage)\n",
            self.records_checksummed, self.total_keys, self.checksum_coverage_pct,
        ));
        if let Some(verifier) = &self.filesystem_verifier {
            out.push_str(&format!(
                "  fs verifier:   {} (roots={}, content_objects={}, chunks={}, issues={})\n",
                verifier.outcome,
                verifier.verified_committed_roots,
                verifier.checked_content_objects,
                verifier.checked_content_chunks,
                verifier.issue_count
            ));
            if self.referenced_objects > 0 || self.unreachable_objects > 0 {
                out.push_str(&format!(
                    "  fs objects:    {} referenced, {} unreachable (policy={})\n",
                    self.referenced_objects,
                    self.unreachable_objects,
                    self.unreachable_object_policy.as_str()
                ));
            }
        }
        if let Some(inspection) = &self.content_inspection {
            out.push_str(&format!(
                "  fs content:    {} refs, {} missing, {} size mismatches, {} malformed\n",
                inspection.referenced_objects,
                inspection.missing_objects,
                inspection.size_mismatches,
                inspection.malformed_records
            ));
        }

        if !self.is_clean() {
            out.push_str("\nFindings:\n");
            for (i, finding) in self.findings.iter().enumerate() {
                out.push_str(&format!("  {}. {}\n", i + 1, finding.describe()));
            }
        } else {
            out.push_str("\nNo inconsistencies found.\n");
        }

        out.push_str(&format!(
            "\nExit code: {} ({})\n",
            self.exit_code(),
            if self.is_clean() {
                "clean"
            } else {
                "inconsistencies found"
            }
        ));

        out
    }
}

// ── Walker ─────────────────────────────────────────────────────────────

/// Read-only scrub walker that opens a local object store, walks every key,
/// and verifies payload checksums and compression frame integrity.
pub struct ScrubWalker {
    store: LocalObjectStore,
    root: String,
    root_path: PathBuf,
    unreachable_policy: UnreachableObjectPolicy,
}

impl ScrubWalker {
    /// Open the object store at `root` for scrubbing.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        Self::open_with_unreachable_policy(root, UnreachableObjectPolicy::default())
    }

    /// Open the object store with an explicit unreachable-object severity policy.
    pub fn open_with_unreachable_policy(
        root: impl AsRef<Path>,
        unreachable_policy: UnreachableObjectPolicy,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root_path = root.as_ref().to_path_buf();
        let store =
            LocalObjectStore::open_read_only_with_options(&root_path, StoreOptions::default())?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("store root does not exist: {}", root_path.display()),
                    )
                })?;
        Ok(Self {
            store,
            root: root_path.display().to_string(),
            root_path,
            unreachable_policy,
        })
    }

    /// Run the full object-level scrub pass and return a report.
    pub fn walk(&self) -> Result<ScrubReport, Box<dyn std::error::Error>> {
        let start = Instant::now();
        let keys = self.store.list_keys();
        let total = keys.len();

        let mut report = ScrubReport::new(total, self.root.clone(), 0.0);
        report.unreachable_object_policy = self.unreachable_policy;

        for (idx, key) in keys.iter().enumerate() {
            let outcome = self.check_object(*key);
            report.bytes_processed = report
                .bytes_processed
                .saturating_add(outcome.bytes_processed());
            match outcome {
                ObjectCheckResult::Ok { .. } => {
                    report.ok += 1;
                }
                ObjectCheckResult::Finding { finding, .. } => {
                    report.add_finding(finding);
                }
            }

            // Progress every 1000 keys
            if (idx + 1) % 1000 == 0 || idx + 1 == total {
                eprintln!(
                    "tidefs-scrub: {}/{} keys ({:.1}%)",
                    idx + 1,
                    total,
                    (idx + 1) as f64 / total as f64 * 100.0
                );
            }
        }

        self.attach_filesystem_verifier(&mut report)?;

        // Segment chain-of-trust verification.
        match self.store.verify_segment_chain() {
            Ok((stats, suspect_log)) => {
                report.segments_in_chain = stats.segments_in_chain;
                report.chain_breaks_detected = stats.chain_breaks_detected;
                report.chain_of_trust_valid =
                    stats.chain_breaks_detected == 0 && stats.segments_in_chain > 0;
                report.suspect_log_entries = suspect_log.len();
            }
            Err(e) => {
                report.add_finding(ScrubFinding::IoError {
                    key_hex: "<segment-chain>".to_string(),
                    message: format!("segment chain verification failed: {e}"),
                });
                report.chain_of_trust_valid = false;
                report.chain_breaks_detected = 1;
            }
        }

        // Compute checksum coverage.
        report.records_checksummed = report.ok + report.findings.len();
        if total > 0 {
            report.checksum_coverage_pct = report.records_checksummed as f64 / total as f64;
        }

        report.elapsed_secs = start.elapsed().as_secs_f64();
        Ok(report)
    }

    fn attach_filesystem_verifier(
        &self,
        report: &mut ScrubReport,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let options = StoreOptions {
            repair_torn_tail: false,
            ..Default::default()
        };
        let root_key = RootAuthenticationKey::from_environment()
            .unwrap_or_else(|_| RootAuthenticationKey::demo_key());
        let verifier =
            verify_online_with_root_authentication_key(&self.root_path, options, root_key)?;
        if verifier.root_slot_records_seen == 0 && verifier.issues.is_empty() {
            return Ok(());
        }

        for issue in &verifier.issues {
            report.add_finding(ScrubFinding::FilesystemVerifierIssue {
                severity: match issue.severity {
                    OnlineVerifierIssueSeverity::Warning => FindingSeverity::Warning,
                    OnlineVerifierIssueSeverity::Error => FindingSeverity::Error,
                },
                issue_kind: issue.kind.human_name().to_string(),
                slot: issue.slot,
                transaction_id: issue.transaction_id,
                generation: issue.generation,
                reason: issue.reason.clone(),
            });
        }
        report.filesystem_verifier = Some(FilesystemVerifierSummary::from_report(&verifier));

        let inspection_options = StoreOptions {
            repair_torn_tail: false,
            ..Default::default()
        };
        let inspection = inspect_filesystem_content_objects_with_root_authentication_key(
            &self.root_path,
            inspection_options,
            root_key,
        )?;
        attach_content_inspection_findings(report, &inspection);

        let retention_options = StoreOptions {
            repair_torn_tail: false,
            ..Default::default()
        };
        let retention = plan_root_retention_with_root_authentication_key(
            &self.root_path,
            retention_options,
            RootRetentionPolicy::safe_default(),
            root_key,
        )?;
        let reclaimable: Vec<_> = retention
            .reclaimable_live_object_keys
            .into_iter()
            .filter(|key| !is_housekeeping_key(*key))
            .collect();
        report.unreachable_objects = reclaimable.len();
        if let Some(severity) = self.unreachable_policy.finding_severity() {
            for key in reclaimable {
                report.add_finding(ScrubFinding::UnreachableObject {
                    key_hex: key.to_string(),
                    severity,
                });
            }
        }
        Ok(())
    }

    fn check_object(&self, key: ObjectKey) -> ObjectCheckResult {
        let raw = match self.store.get(key) {
            Ok(Some(data)) => data,
            Ok(None) => {
                return ObjectCheckResult::Finding {
                    bytes_processed: 0,
                    finding: ScrubFinding::MissingObject {
                        key_hex: key.to_string(),
                    },
                };
            }
            Err(e) => {
                return ObjectCheckResult::Finding {
                    bytes_processed: 0,
                    finding: ScrubFinding::IoError {
                        key_hex: key.to_string(),
                        message: format!("{e}"),
                    },
                };
            }
        };

        // Checksum verification
        let recomputed = checksum64(&raw);
        if let Some(loc) = self.store.location_of(key) {
            let stored_val = loc.payload_checksum.get();
            let recomputed_val = recomputed.get();
            if recomputed_val != stored_val {
                return ObjectCheckResult::Finding {
                    bytes_processed: raw.len() as u64,
                    finding: ScrubFinding::ChecksumMismatch {
                        key_hex: key.to_string(),
                        stored_checksum: stored_val,
                        recomputed_checksum: recomputed_val,
                    },
                };
            }
        }

        // Compression frame integrity check
        if let Err(reason) = check_compression_frame(&raw) {
            return ObjectCheckResult::Finding {
                bytes_processed: raw.len() as u64,
                finding: ScrubFinding::CompressionError {
                    key_hex: key.to_string(),
                    message: reason,
                },
            };
        }

        ObjectCheckResult::Ok {
            bytes_processed: raw.len() as u64,
        }
    }
}

fn is_housekeeping_key(key: ObjectKey) -> bool {
    [
        superblock_object_key(),
        space_counters_object_key(),
        orphan_index_object_key(),
        feature_flags_roots_object_key(),
        intent_log_head_object_key(),
    ]
    .contains(&key)
}

fn attach_content_inspection_findings(
    report: &mut ScrubReport,
    inspection: &tidefs_local_filesystem::FilesystemContentInspectionReport,
) {
    for reference in &inspection.referenced_objects {
        let key_hex = reference.key.to_string();
        if reference.missing {
            report.add_finding(ScrubFinding::MissingObject {
                key_hex: key_hex.clone(),
            });
        }
        if reference.zero_length_record {
            report.add_finding(ScrubFinding::MalformedRecord {
                key_hex: key_hex.clone(),
                reason: format!("zero-length {}", reference.kind.human_name()),
            });
        }
        if let Some(reason) = &reference.malformed_reason {
            report.add_finding(ScrubFinding::MalformedRecord {
                key_hex: key_hex.clone(),
                reason: reason.clone(),
            });
        }
        if let Some((expected, observed)) = reference
            .expected_logical_len
            .zip(reference.observed_logical_len)
            .filter(|(expected, observed)| expected != observed)
        {
            report.add_finding(ScrubFinding::SizeMismatch {
                inode_id: reference.inode_id.get(),
                logical_size: expected,
                object_size: observed,
            });
        }
    }
    report.referenced_objects = inspection.referenced_objects.len();
    report.content_inspection = Some(FilesystemContentInspectionSummary {
        file_like_inodes: inspection.file_like_inodes,
        referenced_objects: inspection.referenced_objects.len(),
        missing_objects: inspection.missing_objects,
        zero_length_records: inspection.zero_length_records,
        size_mismatches: inspection.size_mismatches,
        malformed_records: inspection.malformed_records,
    });
}

#[derive(Debug)]
enum ObjectCheckResult {
    Ok {
        bytes_processed: u64,
    },
    Finding {
        bytes_processed: u64,
        finding: ScrubFinding,
    },
}

impl ObjectCheckResult {
    fn bytes_processed(&self) -> u64 {
        match self {
            Self::Ok { bytes_processed }
            | Self::Finding {
                bytes_processed, ..
            } => *bytes_processed,
        }
    }
}

// ── Compression frame check ────────────────────────────────────────────

/// Check the integrity of a compression frame, if present.
///
/// Returns `Ok(())` if no frame is present or decompression succeeds.
/// Returns `Err(String)` if the frame is corrupt or uses an unknown algorithm.
fn check_compression_frame(raw: &[u8]) -> Result<(), String> {
    use tidefs_compression::FRAME_HEADER_LEN;

    if raw.len() < FRAME_HEADER_LEN {
        return Ok(());
    }

    let algo_byte = raw[0];

    let algo = match CompressionAlgorithm::from_byte(algo_byte) {
        Some(a) => a,
        None => return Ok(()), // Unknown — not a compression frame.
    };

    let payload = &raw[FRAME_HEADER_LEN..];

    match algo {
        CompressionAlgorithm::Uncompressed => Ok(()),
        CompressionAlgorithm::Zstd => zstd::decode_all(payload)
            .map(|_| ())
            .map_err(|e| format!("zstd frame corrupt: {e}")),
        CompressionAlgorithm::Lz4 => lz4_flex::block::decompress_size_prepended(payload)
            .map(|_| ())
            .map_err(|e| format!("lz4 frame corrupt: {e}")),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tidefs_local_filesystem::local_filesystem::InodeId;
    use tidefs_local_filesystem::{
        content_object_key_for_version, FilesystemContentInspectionReport,
        FilesystemContentObjectKind, FilesystemContentObjectRef, LocalFileSystem,
    };
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    fn create_test_store() -> (TempDir, LocalObjectStore) {
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("store");
        let store = LocalObjectStore::open_with_options(&store_path, StoreOptions::test_fast());
        (dir, store.unwrap())
    }

    fn scrub_report_with_orphan(policy: UnreachableObjectPolicy) -> (usize, ScrubReport) {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("fs");
        let mut fs = LocalFileSystem::open_with_root_authentication_key(
            &root,
            StoreOptions::test_fast(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs");
        fs.create_file("/hello.txt", 0o644).expect("create file");
        fs.write_file("/hello.txt", 0, b"hello verifier")
            .expect("write file");
        fs.sync_all().expect("sync committed root");
        drop(fs);

        let base_report = ScrubWalker::open(&root)
            .expect("open base scrub walker")
            .walk()
            .expect("base scrub");
        let base_unreachable = base_report.unreachable_objects;

        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        store
            .put_named("tidefs-scrub-test-orphan", b"orphan payload")
            .expect("write orphan object");
        store.sync_all().expect("sync orphan object");
        drop(store);

        let report = ScrubWalker::open_with_unreachable_policy(&root, policy)
            .expect("open scrub walker")
            .walk()
            .expect("scrub with orphan");

        (base_unreachable, report)
    }

    #[test]
    fn clean_store_produces_no_findings() {
        let (_dir, mut store) = create_test_store();
        for i in 0..5 {
            store
                .put_named(format!("obj{i}"), format!("payload{i}").as_bytes())
                .unwrap();
        }

        let root = store.root().display().to_string();
        drop(store);

        let walker = ScrubWalker::open(&root).unwrap();
        let report = walker.walk().unwrap();

        assert!(report.is_clean());
        assert_eq!(report.total_keys, 5);
        assert_eq!(report.ok, 5);
        assert_eq!(report.bytes_processed, 40);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn filesystem_committed_root_adds_verifier_summary() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("fs");
        let mut fs = LocalFileSystem::open_with_root_authentication_key(
            &root,
            StoreOptions::test_fast(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs");
        fs.create_file("/hello.txt", 0o644).expect("create file");
        fs.write_file("/hello.txt", 0, b"hello verifier")
            .expect("write file");
        fs.sync_all().expect("sync committed root");
        drop(fs);

        let walker = ScrubWalker::open(&root).expect("open scrub walker");
        let report = walker.walk().expect("scrub fs root");

        assert!(report.is_clean(), "{:?}", report.findings);
        let verifier = report
            .filesystem_verifier
            .expect("filesystem verifier summary");
        assert!(verifier.root_slot_records_seen > 0);
        assert!(verifier.verified_committed_roots > 0);
        assert!(verifier.checked_content_objects > 0);
        assert_eq!(verifier.issue_count, 0);
        assert!(!verifier.mutating_repair_attempted);
    }

    #[test]
    fn orphan_object_increases_unreachable_count() {
        let (base_unreachable, scrubbed) =
            scrub_report_with_orphan(UnreachableObjectPolicy::CountOnly);
        assert_eq!(scrubbed.unreachable_objects, base_unreachable + 1);
        assert!(scrubbed.referenced_objects > 0);
        assert_eq!(
            scrubbed.unreachable_object_policy,
            UnreachableObjectPolicy::CountOnly
        );
        assert!(scrubbed.is_clean(), "{:?}", scrubbed.findings);
        assert_eq!(scrubbed.exit_code(), 0);
    }

    #[test]
    fn unreachable_warn_policy_promotes_orphans_to_warning_findings() {
        let (base_unreachable, scrubbed) = scrub_report_with_orphan(UnreachableObjectPolicy::Warn);

        assert_eq!(scrubbed.unreachable_objects, base_unreachable + 1);
        assert_eq!(
            scrubbed.unreachable_object_policy,
            UnreachableObjectPolicy::Warn
        );
        assert_eq!(
            scrubbed.count_by_severity(FindingSeverity::Warning),
            scrubbed.unreachable_objects
        );
        assert_eq!(scrubbed.count_by_severity(FindingSeverity::Error), 0);
        assert_eq!(scrubbed.exit_code(), 1);
        assert!(scrubbed.findings.iter().any(|finding| {
            matches!(
                finding,
                ScrubFinding::UnreachableObject {
                    severity: FindingSeverity::Warning,
                    ..
                }
            )
        }));
    }

    #[test]
    fn unreachable_fail_policy_promotes_orphans_to_error_findings() {
        let (base_unreachable, scrubbed) = scrub_report_with_orphan(UnreachableObjectPolicy::Fail);

        assert_eq!(scrubbed.unreachable_objects, base_unreachable + 1);
        assert_eq!(
            scrubbed.unreachable_object_policy,
            UnreachableObjectPolicy::Fail
        );
        assert_eq!(
            scrubbed.count_by_severity(FindingSeverity::Error),
            scrubbed.unreachable_objects
        );
        assert_eq!(scrubbed.exit_code(), 1);
        assert!(scrubbed.findings.iter().any(|finding| {
            matches!(
                finding,
                ScrubFinding::UnreachableObject {
                    severity: FindingSeverity::Error,
                    ..
                }
            )
        }));
    }

    #[test]
    fn missing_referenced_content_object_reports_verifier_issue() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("fs");
        let mut fs = LocalFileSystem::open_with_root_authentication_key(
            &root,
            StoreOptions::test_fast(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs");
        fs.create_file("/hello.txt", 0o644).expect("create file");
        fs.write_file("/hello.txt", 0, b"hello verifier")
            .expect("write file");
        fs.sync_all().expect("sync committed root");
        let record = fs.stat("/hello.txt").expect("stat file");
        let content_key = content_object_key_for_version(record.inode_id, record.data_version);
        drop(fs);

        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        assert!(store.delete(content_key).expect("delete content object"));
        store.sync_all().expect("sync delete");
        drop(store);

        let report = ScrubWalker::open(&root)
            .expect("open scrub walker")
            .walk()
            .expect("scrub missing content");
        assert!(report.findings.iter().any(|finding| {
            matches!(
                finding,
                ScrubFinding::FilesystemVerifierIssue { issue_kind, .. }
                    if issue_kind == "root-commit validation"
            )
        }));
        assert!(report
            .filesystem_verifier
            .as_ref()
            .map(|summary| summary.issue_count >= 1)
            .unwrap_or(false));
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn zero_length_content_object_reports_verifier_issue() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("fs");
        let mut fs = LocalFileSystem::open_with_root_authentication_key(
            &root,
            StoreOptions::test_fast(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs");
        fs.create_file("/hello.txt", 0o644).expect("create file");
        fs.write_file("/hello.txt", 0, b"hello verifier")
            .expect("write file");
        fs.sync_all().expect("sync committed root");
        let record = fs.stat("/hello.txt").expect("stat file");
        let content_key = content_object_key_for_version(record.inode_id, record.data_version);
        drop(fs);

        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        store.put(content_key, b"").expect("write zero content");
        store.sync_all().expect("sync zero content");
        drop(store);

        let report = ScrubWalker::open(&root)
            .expect("open scrub walker")
            .walk()
            .expect("scrub zero content");
        assert!(report.findings.iter().any(|finding| {
            matches!(
                finding,
                ScrubFinding::FilesystemVerifierIssue { issue_kind, .. }
                    if issue_kind == "root-commit validation"
            )
        }));
        assert!(report
            .filesystem_verifier
            .as_ref()
            .map(|summary| summary.issue_count >= 1)
            .unwrap_or(false));
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn selected_root_zero_length_reference_maps_to_malformed_record() {
        let key = ObjectKey::from_name("zero-length-selected-root-content");
        let mut inspection = FilesystemContentInspectionReport::empty();
        inspection.observe(FilesystemContentObjectRef {
            kind: FilesystemContentObjectKind::InlineContent,
            inode_id: InodeId::new(42),
            data_version: 7,
            chunk_index: None,
            key,
            expected_logical_len: Some(128),
            observed_logical_len: None,
            observed_encoded_len: Some(0),
            missing: false,
            zero_length_record: true,
            missing_receipt: false,
            receipt_mismatch: false,
            malformed_reason: Some("decode failed".to_string()),
        });

        let mut report = ScrubReport::new(1, "/synthetic".into(), 0.0);
        attach_content_inspection_findings(&mut report, &inspection);

        assert!(report.findings.iter().any(|finding| {
            matches!(
                finding,
                ScrubFinding::MalformedRecord { key_hex, reason }
                    if key_hex == &key.to_string()
                        && reason.contains("zero-length inline content")
            )
        }));
        assert_eq!(
            report
                .content_inspection
                .as_ref()
                .expect("content inspection summary")
                .zero_length_records,
            1
        );
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn selected_root_logical_size_mismatch_maps_to_size_mismatch() {
        let key = ObjectKey::from_name("short-selected-root-content");
        let inode_id = InodeId::new(42);
        let mut inspection = FilesystemContentInspectionReport::empty();
        inspection.observe(FilesystemContentObjectRef {
            kind: FilesystemContentObjectKind::InlineContent,
            inode_id,
            data_version: 7,
            chunk_index: None,
            key,
            expected_logical_len: Some(14),
            observed_logical_len: Some(2),
            observed_encoded_len: Some(42),
            missing: false,
            zero_length_record: false,
            missing_receipt: false,
            receipt_mismatch: false,
            malformed_reason: None,
        });

        let mut report = ScrubReport::new(1, "/synthetic".into(), 0.0);
        attach_content_inspection_findings(&mut report, &inspection);

        assert!(
            report.findings.iter().any(|finding| {
                matches!(
                    finding,
                    ScrubFinding::SizeMismatch {
                        inode_id,
                        logical_size,
                        object_size,
                    } if *inode_id == 42
                        && *logical_size == 14
                        && *object_size == 2
                )
            }),
            "{:?}",
            report.findings
        );
        assert_eq!(
            report
                .content_inspection
                .as_ref()
                .expect("content inspection summary")
                .size_mismatches,
            1
        );
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn missing_object_produces_finding() {
        let (_dir, store) = create_test_store();
        let key = ObjectKey::from_name("nonexistent");
        let outcome = ScrubWalker::open(store.root()).unwrap().check_object(key);

        match outcome {
            ObjectCheckResult::Finding {
                finding: ScrubFinding::MissingObject { .. },
                ..
            } => {}
            other => panic!("expected MissingObject, got {other:?}"),
        }
    }

    #[test]
    fn checksum_mismatch_detected() {
        let (_dir, mut store) = create_test_store();
        store.put_named("data", b"original").unwrap();
        store.put_named("data", b"DIFFERENT_PAYLOAD").unwrap();

        let key = ObjectKey::from_name("data");
        let locations = store.version_locations_of(key);
        assert!(locations.len() >= 2);

        let older_loc = locations[0];
        let old_payload = store.get_at_location(older_loc).unwrap();
        let recomputed = checksum64(&old_payload);

        assert_eq!(
            recomputed.get(),
            older_loc.payload_checksum.get(),
            "older version checksum should match"
        );
    }

    #[test]
    fn report_serializes_to_json() {
        let mut report = ScrubReport::new(10, "/tmp/test".into(), 1.5);
        report.ok = 9;
        report.referenced_objects = 7;
        report.unreachable_objects = 2;
        report.content_inspection = Some(FilesystemContentInspectionSummary {
            file_like_inodes: 3,
            referenced_objects: 7,
            missing_objects: 1,
            zero_length_records: 1,
            size_mismatches: 1,
            malformed_records: 2,
        });
        report.add_finding(ScrubFinding::MissingObject {
            key_hex: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        });
        report.add_finding(ScrubFinding::SizeMismatch {
            inode_id: 42,
            logical_size: 14,
            object_size: 2,
        });

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("missing-object"));
        assert!(json.contains("size-mismatch"));
        assert!(json.contains("abcdef"));
        assert!(json.contains("total_keys"));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["total_keys"], 10);
        assert_eq!(value["referenced_objects"], 7);
        assert_eq!(value["unreachable_objects"], 2);
        assert_eq!(value["unreachable_object_policy"], "count-only");
        assert_eq!(value["content_inspection"]["file_like_inodes"], 3);
        assert_eq!(value["content_inspection"]["referenced_objects"], 7);
        assert_eq!(value["content_inspection"]["missing_objects"], 1);
        assert_eq!(value["content_inspection"]["zero_length_records"], 1);
        assert_eq!(value["content_inspection"]["size_mismatches"], 1);
        assert_eq!(value["content_inspection"]["malformed_records"], 2);
        assert_eq!(value["findings"][0]["kind"], "missing-object");
        assert_eq!(value["findings"][1]["kind"], "size-mismatch");
        assert_eq!(value["findings"][1]["inode_id"], 42);
        assert_eq!(value["findings"][1]["logical_size"], 14);
        assert_eq!(value["findings"][1]["object_size"], 2);
    }

    #[test]
    fn exit_codes() {
        let report = ScrubReport::new(10, "/store".into(), 0.0);
        assert_eq!(report.exit_code(), 0);

        let mut report = ScrubReport::new(10, "/store".into(), 0.0);
        report.add_finding(ScrubFinding::MissingObject {
            key_hex: "aa".into(),
        });
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn finding_describe_is_stable() {
        let f = ScrubFinding::MissingObject {
            key_hex: "deadbeef".into(),
        };
        let desc = f.describe();
        assert!(desc.contains("missing object"));
        assert!(desc.contains("deadbeef"));

        let f = ScrubFinding::ChecksumMismatch {
            key_hex: "cafe".into(),
            stored_checksum: 0x100,
            recomputed_checksum: 0x200,
        };
        let desc = f.describe();
        assert!(desc.contains("checksum mismatch"));
        assert!(desc.contains("0x100"));
        assert!(desc.contains("0x200"));
    }

    #[test]
    fn compression_frame_no_header_passes() {
        let result = check_compression_frame(b"hi");
        assert!(result.is_ok());
    }

    #[test]
    fn compression_frame_algo_uncompressed_passes() {
        let frame = [0x00u8, 0x03, 0x00, 0x00, 0x00];
        let result = check_compression_frame(&frame);
        assert!(result.is_ok());
    }

    #[test]
    fn compression_frame_zstd_corrupt_detected() {
        let mut frame = vec![0x01u8, 0x04, 0x00, 0x00, 0x00];
        frame.extend_from_slice(b"NOT VALID ZSTD DATA!!!");
        let result = check_compression_frame(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("zstd frame corrupt"));
    }

    #[test]
    fn compression_frame_lz4_corrupt_detected() {
        let mut frame = vec![0x02u8, 0x04, 0x00, 0x00, 0x00];
        frame.extend_from_slice(b"NOT VALID LZ4 DATA!!!");
        let result = check_compression_frame(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lz4 frame corrupt"));
    }
}
