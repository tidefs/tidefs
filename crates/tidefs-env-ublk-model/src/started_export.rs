// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic started-export service-loop receipt fixture.
//!
//! The module models the uBLK daemon service loop that runs after a device is
//! started and exported to the kernel. Every event is a pure model transition;
//! no file descriptors, ioctls, or real block I/O are involved.
//!
//! The receipt records qid/tag generation, queue bounds, completion outcomes,
//! and unsupported-opcode handling for evidence-tier classification. It is
//! source-model evidence and remains insufficient for
//! `runtime-ublk-started-export-admission-artifact`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    CompletionStatus, UblkEnvironmentModel, UblkIoIntent, UblkModelConfig, UblkModelError,
    UblkRequestClass, UblkRequestToken, UblkSlotKey, UblkSlotStateKind,
};
use tidefs_ublk_abi::{
    UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_REPORT_ZONES,
    UBLK_IO_OP_WRITE, UBLK_IO_OP_WRITE_SAME, UBLK_IO_OP_WRITE_ZEROES, UBLK_IO_OP_ZONE_APPEND,
    UBLK_IO_OP_ZONE_CLOSE, UBLK_IO_OP_ZONE_FINISH, UBLK_IO_OP_ZONE_OPEN, UBLK_IO_OP_ZONE_RESET,
    UBLK_IO_OP_ZONE_RESET_ALL, UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH,
};

// ---------------------------------------------------------------------------
// Public claim and evidence constants
// ---------------------------------------------------------------------------

/// Claim id for the started-export live-service-loop under model evidence.
pub const STARTED_EXPORT_MODEL_CLAIM_ID: &str = "ublk.started_export.live_service_loop.v1";

/// Evidence class for the started-export model receipt.
pub const STARTED_EXPORT_MODEL_EVIDENCE_CLASS: &str = "started-export-service-loop-model";

/// Evidence tier: this fixture is source-model evidence, not runtime-tier.
pub const STARTED_EXPORT_MODEL_EVIDENCE_TIER: &str = "source-model";

/// Boundary statement: the fixture does not satisfy runtime admission.
pub const STARTED_EXPORT_RUNTIME_BOUNDARY: &str = "This is source-model evidence only; \
     runtime-ublk-started-export-admission-artifact remains required \
     for live daemon proof.";

// ---------------------------------------------------------------------------
// Receipt types
// ---------------------------------------------------------------------------

/// Top-level deterministic receipt for a started-export service-loop model run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartedExportReceipt {
    pub report_version: u32,
    pub generated_by: String,
    pub claim_id: String,
    pub evidence_class: String,
    pub evidence_tier: String,
    pub runtime_admission_boundary: String,
    pub config: StartedExportConfig,
    pub queue_bounds: QueueBounds,
    pub request_classes_exercised: Vec<String>,
    pub unsupported_opcodes_exercised: Vec<UnsupportedOpcodeRecord>,
    pub events: Vec<StartedExportEvent>,
    pub completion_summary: CompletionSummary,
    pub deterministic_identity: DeterministicIdentity,
}

/// Configuration snapshot recorded in the receipt.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct StartedExportConfig {
    pub queue_count: u16,
    pub queue_depth: u16,
    pub sector_size: u64,
    pub device_id: u64,
}

/// Queue-bounds record comparing configured values against the uBLK ABI.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct QueueBounds {
    pub queue_count: u16,
    pub queue_depth: u16,
    pub max_queue_count_abi: u16,
    pub max_queue_depth_abi: u16,
    pub total_slots: u32,
}

/// Record of an unsupported uBLK opcode that was exercised and rejected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsupportedOpcodeRecord {
    pub opcode: u8,
    pub opcode_name: String,
    pub error_kind: String,
}

/// A single event in the started-export service-loop model run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartedExportEvent {
    pub sequence: u64,
    pub event_kind: StartedExportEventKind,
    pub qid: u16,
    pub tag: u16,
    pub generation: u64,
    pub request_class: Option<String>,
    pub detail: Option<String>,
}

/// Classification of a service-loop event.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartedExportEventKind {
    Submit,
    Complete,
    Abort,
    Timeout,
    ReissueAfterTimeout,
    Release,
    UnsupportedOpcodeRejected,
    QueueBoundExceededRejected,
}

/// Summary counts of terminal outcomes across the model run.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CompletionSummary {
    pub completed: u64,
    pub aborted: u64,
    pub timed_out: u64,
    pub timed_out_reissued: u64,
    pub total_terminal: u64,
}

/// Identity fingerprint so consumers can verify the receipt is deterministic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeterministicIdentity {
    pub seed: u64,
    pub queue_count: u16,
    pub queue_depth: u16,
    pub event_count: u64,
    pub operations_sequence_hash: String,
}

// ---------------------------------------------------------------------------
// Unsupported opcode catalogue
// ---------------------------------------------------------------------------

fn unsupported_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        UBLK_IO_OP_WRITE_SAME => "write_same",
        UBLK_IO_OP_WRITE_ZEROES => "write_zeroes",
        UBLK_IO_OP_ZONE_OPEN => "zone_open",
        UBLK_IO_OP_ZONE_CLOSE => "zone_close",
        UBLK_IO_OP_ZONE_FINISH => "zone_finish",
        UBLK_IO_OP_ZONE_APPEND => "zone_append",
        UBLK_IO_OP_ZONE_RESET_ALL => "zone_reset_all",
        UBLK_IO_OP_ZONE_RESET => "zone_reset",
        UBLK_IO_OP_REPORT_ZONES => "report_zones",
        _ => "unknown_reserved",
    }
}

// ---------------------------------------------------------------------------
// Receipt generation
// ---------------------------------------------------------------------------

/// Errors that can occur during receipt generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptGenerationError {
    InvalidConfig(UblkModelError),
    GenerationLogicBug(&'static str),
}

/// Generate a deterministic started-export service-loop receipt.
///
/// The `seed` parameter ensures reproducible event ordering. The returned
/// receipt is a pure model record; it does not drive a uBLK daemon, issue
/// ioctls, or submit block I/O.
///
/// # Errors
///
/// Returns `ReceiptGenerationError::InvalidConfig` when queue count or depth
/// are zero or exceed the uBLK ABI bounds.
pub fn generate_started_export_receipt(
    queue_count: u16,
    queue_depth: u16,
    seed: u64,
) -> Result<StartedExportReceipt, ReceiptGenerationError> {
    let config = UblkModelConfig::bounded(queue_count, queue_depth);
    let mut env =
        UblkEnvironmentModel::new(config).map_err(ReceiptGenerationError::InvalidConfig)?;

    let mut events: Vec<StartedExportEvent> = Vec::new();
    let mut seq: u64 = 0;
    let mut summary = CompletionSummary::default();
    let mut request_classes_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut unsupported_records: Vec<UnsupportedOpcodeRecord> = Vec::new();

    // Deterministic permutation helpers driven by `seed`.
    let mut rng = SeedRng::new(seed);

    // Helper to push an event.
    let mut push = |kind: StartedExportEventKind,
                    key: UblkSlotKey,
                    generation: u64,
                    class: Option<&str>,
                    detail: Option<String>| {
        seq += 1;
        if let Some(c) = class {
            request_classes_seen.entry(c.to_string()).or_insert(true);
        }
        events.push(StartedExportEvent {
            sequence: seq,
            event_kind: kind,
            qid: key.qid,
            tag: key.tag,
            generation,
            request_class: class.map(|s| s.to_string()),
            detail,
        });
    };

    // ---- Phase 1: Exercise every legal opcode across every slot ----
    let legal_opcodes: &[u8] = &[
        UBLK_IO_OP_READ,
        UBLK_IO_OP_WRITE,
        UBLK_IO_OP_FLUSH,
        UBLK_IO_OP_DISCARD,
    ];

    for qid in 0..queue_count {
        for tag in 0..queue_depth {
            for &opcode in legal_opcodes {
                let key = UblkSlotKey::new(qid, tag);
                let intent = UblkIoIntent::new(
                    UblkRequestClass::from_ublk_opcode(opcode).map_err(|_| {
                        ReceiptGenerationError::GenerationLogicBug("legal opcode must map")
                    })?,
                    0,
                    4096,
                );
                let sub = env.submit(key, intent).map_err(|_| {
                    ReceiptGenerationError::GenerationLogicBug(
                        "submit must succeed for legal opcode in free slot",
                    )
                })?;
                push(
                    StartedExportEventKind::Submit,
                    key,
                    sub.token.generation,
                    Some(request_class_name(opcode)),
                    None,
                );

                // Complete some, abort some, timeout-and-reissue some deterministically.
                let choice = rng.next_bound(4);
                match choice {
                    0 => {
                        let cmd = cmd_for_token(sub.token);
                        let term = env.complete(sub.token, cmd).map_err(|_| {
                            ReceiptGenerationError::GenerationLogicBug("complete must succeed")
                        })?;
                        assert_eq!(term.completion.status, CompletionStatus::Success);
                        push(
                            StartedExportEventKind::Complete,
                            key,
                            sub.token.generation,
                            Some(request_class_name(opcode)),
                            None,
                        );
                        summary.completed += 1;
                    }
                    1 => {
                        let term = env.abort(sub.token).map_err(|_| {
                            ReceiptGenerationError::GenerationLogicBug("abort must succeed")
                        })?;
                        assert_eq!(term.completion.status, CompletionStatus::Cancelled);
                        push(
                            StartedExportEventKind::Abort,
                            key,
                            sub.token.generation,
                            Some(request_class_name(opcode)),
                            None,
                        );
                        summary.aborted += 1;
                    }
                    2 | 3 => {
                        let term = env.timeout(sub.token).map_err(|_| {
                            ReceiptGenerationError::GenerationLogicBug("timeout must succeed")
                        })?;
                        assert_eq!(term.completion.status, CompletionStatus::TimedOut);
                        push(
                            StartedExportEventKind::Timeout,
                            key,
                            sub.token.generation,
                            Some(request_class_name(opcode)),
                            None,
                        );
                        summary.timed_out += 1;

                        let reissue = env.reissue_after_timeout(sub.token).map_err(|_| {
                            ReceiptGenerationError::GenerationLogicBug(
                                "reissue after timeout must succeed",
                            )
                        })?;
                        push(
                            StartedExportEventKind::ReissueAfterTimeout,
                            key,
                            reissue.token.generation,
                            Some(request_class_name(opcode)),
                            None,
                        );

                        let cmd2 = cmd_for_token(reissue.token);
                        let term2 = env.complete(reissue.token, cmd2).map_err(|_| {
                            ReceiptGenerationError::GenerationLogicBug(
                                "reissue complete must succeed",
                            )
                        })?;
                        assert_eq!(term2.completion.status, CompletionStatus::Success);
                        push(
                            StartedExportEventKind::Complete,
                            key,
                            reissue.token.generation,
                            Some(request_class_name(opcode)),
                            None,
                        );
                        summary.timed_out_reissued += 1;
                        summary.completed += 1;
                    }
                    _ => unreachable!(),
                }

                // Release the terminal slot.
                let snap = env.snapshot(key).map_err(|_| {
                    ReceiptGenerationError::GenerationLogicBug("snapshot must succeed")
                })?;
                if snap.state != UblkSlotStateKind::InFlight {
                    let token =
                        snap.current_token
                            .ok_or(ReceiptGenerationError::GenerationLogicBug(
                                "expected terminal token",
                            ))?;
                    env.release(token).map_err(|_| {
                        ReceiptGenerationError::GenerationLogicBug("release must succeed")
                    })?;
                    push(
                        StartedExportEventKind::Release,
                        key,
                        token.generation,
                        Some(request_class_name(opcode)),
                        None,
                    );
                }
            }
        }
    }

    // ---- Phase 2: Exercise unsupported opcodes ----
    let unsupported_opcodes: &[u8] = &[
        UBLK_IO_OP_WRITE_SAME,
        UBLK_IO_OP_WRITE_ZEROES,
        UBLK_IO_OP_ZONE_OPEN,
        UBLK_IO_OP_ZONE_CLOSE,
        UBLK_IO_OP_ZONE_FINISH,
        UBLK_IO_OP_ZONE_APPEND,
        UBLK_IO_OP_ZONE_RESET_ALL,
        UBLK_IO_OP_ZONE_RESET,
        UBLK_IO_OP_REPORT_ZONES,
    ];

    for &opcode in unsupported_opcodes {
        let key = UblkSlotKey::new(0, 0);
        let intent_result = UblkRequestClass::from_ublk_opcode(opcode);
        assert!(
            intent_result.is_err(),
            "unsupported opcode must be rejected"
        );
        let err = intent_result.unwrap_err();
        assert_eq!(err, UblkModelError::UnsupportedOpcode { opcode });

        unsupported_records.push(UnsupportedOpcodeRecord {
            opcode,
            opcode_name: unsupported_opcode_name(opcode).to_string(),
            error_kind: format!("{err:?}"),
        });

        push(
            StartedExportEventKind::UnsupportedOpcodeRejected,
            key,
            0,
            None,
            Some(format!("opcode={opcode} {err}")),
        );
    }

    // ---- Phase 3: Verify queue-bound rejection (events only) ----
    let bound_tests: &[(u16, u16, &str)] = &[
        (0, 0, "zero queues"),
        (0, 1, "zero queue count with depth"),
        (UBLK_MAX_NR_QUEUES + 1, 1, "queue count exceeds ABI max"),
        (1, UBLK_MAX_QUEUE_DEPTH + 1, "queue depth exceeds ABI max"),
    ];

    for &(qc, qd, detail) in bound_tests {
        let cfg = UblkModelConfig::bounded(qc, qd);
        let result = UblkEnvironmentModel::new(cfg);
        assert!(result.is_err(), "bound test ({qc}, {qd}) must be rejected");
        push(
            StartedExportEventKind::QueueBoundExceededRejected,
            UblkSlotKey::new(0, 0),
            0,
            None,
            Some(format!("q={qc} d={qd}: {detail}")),
        );
    }

    // ---- Phase 4: Produce deterministic identity hash ----
    summary.total_terminal = summary.completed + summary.aborted + summary.timed_out;

    let hash_input: String = events
        .iter()
        .map(|e| {
            format!(
                "{}:{}:{}:{}",
                event_kind_tag(e.event_kind),
                e.qid,
                e.tag,
                e.request_class.as_deref().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join("|");

    let ops_hash = stable_sequence_hash(&hash_input);

    let identity = DeterministicIdentity {
        seed,
        queue_count,
        queue_depth,
        event_count: seq,
        operations_sequence_hash: ops_hash,
    };

    Ok(StartedExportReceipt {
        report_version: 1,
        generated_by: format!("tidefs-env-ublk-model-rust-v{}", env!("CARGO_PKG_VERSION")),
        claim_id: STARTED_EXPORT_MODEL_CLAIM_ID.to_string(),
        evidence_class: STARTED_EXPORT_MODEL_EVIDENCE_CLASS.to_string(),
        evidence_tier: STARTED_EXPORT_MODEL_EVIDENCE_TIER.to_string(),
        runtime_admission_boundary: STARTED_EXPORT_RUNTIME_BOUNDARY.to_string(),
        config: StartedExportConfig {
            queue_count,
            queue_depth,
            sector_size: 512,
            device_id: 1,
        },
        queue_bounds: QueueBounds {
            queue_count,
            queue_depth,
            max_queue_count_abi: UBLK_MAX_NR_QUEUES,
            max_queue_depth_abi: UBLK_MAX_QUEUE_DEPTH,
            total_slots: u32::from(queue_count) * u32::from(queue_depth),
        },
        request_classes_exercised: request_classes_seen.into_keys().collect(),
        unsupported_opcodes_exercised: unsupported_records,
        events,
        completion_summary: summary,
        deterministic_identity: identity,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn request_class_name(opcode: u8) -> &'static str {
    match opcode {
        UBLK_IO_OP_READ => "read",
        UBLK_IO_OP_WRITE => "write",
        UBLK_IO_OP_FLUSH => "flush",
        UBLK_IO_OP_DISCARD => "discard",
        _ => "unsupported",
    }
}

fn event_kind_tag(kind: StartedExportEventKind) -> &'static str {
    match kind {
        StartedExportEventKind::Submit => "S",
        StartedExportEventKind::Complete => "C",
        StartedExportEventKind::Abort => "A",
        StartedExportEventKind::Timeout => "T",
        StartedExportEventKind::ReissueAfterTimeout => "R",
        StartedExportEventKind::Release => "L",
        StartedExportEventKind::UnsupportedOpcodeRejected => "U",
        StartedExportEventKind::QueueBoundExceededRejected => "Q",
    }
}

fn stable_sequence_hash(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn cmd_for_token(token: UblkRequestToken) -> tidefs_ublk_abi::UblkSrvIoCmd {
    tidefs_ublk_abi::UblkSrvIoCmd {
        q_id: token.key.qid,
        tag: token.key.tag,
        result: tidefs_ublk_abi::UBLK_IO_RES_OK,
        addr_or_zone_append_lba: 0,
    }
}

// ---------------------------------------------------------------------------
// Tiny deterministic PRNG for generating the op sequence from a seed
// ---------------------------------------------------------------------------

struct SeedRng {
    state: u64,
}

impl SeedRng {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9E3779B97F4A7C15),
        }
    }

    /// Return a value in `[0, bound)`.
    fn next_bound(&mut self, bound: u64) -> u64 {
        // SplitMix64 step
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        (z ^ (z >> 31)) % bound
    }
}

// ---------------------------------------------------------------------------
// Fixture serialization helpers
// ---------------------------------------------------------------------------

/// Error type for writing a receipt to disk.
#[derive(Debug)]
pub enum WriteReceiptError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for WriteReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error writing receipt: {e}"),
            Self::Serialize(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl StartedExportReceipt {
    /// Serialize this receipt to a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Write this receipt as a JSON file to `path`.
    ///
    /// # Errors
    ///
    /// Returns an I/O or serialization error.
    pub fn write_to_path(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), WriteReceiptError> {
        let json = serde_json::to_string_pretty(self).map_err(WriteReceiptError::Serialize)?;
        std::fs::write(path.as_ref(), json).map_err(WriteReceiptError::Io)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical fixture parameters: 2 queues, 3 tags.
    const FIXTURE_Q: u16 = 2;
    const FIXTURE_D: u16 = 3;
    const FIXTURE_SEED: u64 = 0x5449444546533031; // "TIDEFS01"

    #[test]
    fn receipt_is_deterministic() {
        let r1 =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        let r2 =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");

        assert_eq!(r1.events.len(), r2.events.len());
        assert_eq!(r1.completion_summary, r2.completion_summary);
        assert_eq!(
            r1.deterministic_identity.operations_sequence_hash,
            r2.deterministic_identity.operations_sequence_hash
        );
        assert_eq!(r1.request_classes_exercised, r2.request_classes_exercised);

        for (i, (e1, e2)) in r1.events.iter().zip(r2.events.iter()).enumerate() {
            assert_eq!(e1.sequence, e2.sequence, "event {i} sequence mismatch");
            assert_eq!(e1.event_kind, e2.event_kind, "event {i} kind mismatch");
            assert_eq!(e1.qid, e2.qid, "event {i} qid mismatch");
            assert_eq!(e1.tag, e2.tag, "event {i} tag mismatch");
            assert_eq!(e1.generation, e2.generation, "event {i} gen mismatch");
            assert_eq!(
                e1.request_class, e2.request_class,
                "event {i} class mismatch"
            );
        }
    }

    #[test]
    fn receipt_contains_all_request_classes() {
        let r =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        let classes: std::collections::BTreeSet<&str> = r
            .request_classes_exercised
            .iter()
            .map(|s| s.as_str())
            .collect();
        for expected in &["read", "write", "flush", "discard"] {
            assert!(
                classes.contains(expected),
                "missing request class: {expected}"
            );
        }
    }

    #[test]
    fn receipt_exercises_all_unsupported_opcodes() {
        let r =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        let expected_unsupported: &[u8] = &[
            UBLK_IO_OP_WRITE_SAME,
            UBLK_IO_OP_WRITE_ZEROES,
            UBLK_IO_OP_ZONE_OPEN,
            UBLK_IO_OP_ZONE_CLOSE,
            UBLK_IO_OP_ZONE_FINISH,
            UBLK_IO_OP_ZONE_APPEND,
            UBLK_IO_OP_ZONE_RESET_ALL,
            UBLK_IO_OP_ZONE_RESET,
            UBLK_IO_OP_REPORT_ZONES,
        ];
        for &opcode in expected_unsupported {
            let found = r
                .unsupported_opcodes_exercised
                .iter()
                .any(|rec| rec.opcode == opcode);
            assert!(found, "unsupported opcode {opcode} not exercised");
        }
    }

    #[test]
    fn receipt_rejects_zero_queues() {
        let err = generate_started_export_receipt(0, 1, 0).unwrap_err();
        assert_eq!(
            err,
            ReceiptGenerationError::InvalidConfig(UblkModelError::ZeroQueues)
        );
    }

    #[test]
    fn receipt_rejects_zero_queue_depth() {
        let err = generate_started_export_receipt(1, 0, 0).unwrap_err();
        assert_eq!(
            err,
            ReceiptGenerationError::InvalidConfig(UblkModelError::ZeroQueueDepth)
        );
    }

    #[test]
    fn receipt_rejects_queue_count_above_abi_max() {
        let err = generate_started_export_receipt(UBLK_MAX_NR_QUEUES + 1, 1, 0).unwrap_err();
        match err {
            ReceiptGenerationError::InvalidConfig(UblkModelError::QueueCountTooLarge {
                queue_count,
                max,
            }) => {
                assert_eq!(queue_count, UBLK_MAX_NR_QUEUES + 1);
                assert_eq!(max, UBLK_MAX_NR_QUEUES);
            }
            other => panic!("expected QueueCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn receipt_rejects_queue_depth_above_abi_max() {
        let err = generate_started_export_receipt(1, UBLK_MAX_QUEUE_DEPTH + 1, 0).unwrap_err();
        match err {
            ReceiptGenerationError::InvalidConfig(UblkModelError::QueueDepthTooLarge {
                queue_depth,
                max,
            }) => {
                assert_eq!(queue_depth, UBLK_MAX_QUEUE_DEPTH + 1);
                assert_eq!(max, UBLK_MAX_QUEUE_DEPTH);
            }
            other => panic!("expected QueueDepthTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn receipt_events_cover_all_qid_tag_slots() {
        let r =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        let mut slots_touched: BTreeMap<(u16, u16), bool> = BTreeMap::new();
        for e in &r.events {
            if e.event_kind != StartedExportEventKind::UnsupportedOpcodeRejected
                && e.event_kind != StartedExportEventKind::QueueBoundExceededRejected
            {
                slots_touched.insert((e.qid, e.tag), true);
            }
        }
        for qid in 0..FIXTURE_Q {
            for tag in 0..FIXTURE_D {
                assert!(
                    slots_touched.contains_key(&(qid, tag)),
                    "slot qid={qid} tag={tag} not touched"
                );
            }
        }
    }

    #[test]
    fn receipt_events_have_monotonic_sequences() {
        let r =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        let mut prev = 0;
        for e in &r.events {
            assert!(
                e.sequence > prev,
                "non-monotonic sequence at {}",
                e.sequence
            );
            prev = e.sequence;
        }
    }

    #[test]
    fn receipt_json_roundtrip() {
        let r =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        let json = serde_json::to_string_pretty(&r).expect("serialize");
        let r2: StartedExportReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r.report_version, r2.report_version);
        assert_eq!(r.claim_id, r2.claim_id);
        assert_eq!(r.events.len(), r2.events.len());
        assert_eq!(r.completion_summary, r2.completion_summary);
        assert_eq!(
            r.deterministic_identity.event_count,
            r2.deterministic_identity.event_count
        );
        assert_eq!(
            r.deterministic_identity.operations_sequence_hash,
            r2.deterministic_identity.operations_sequence_hash,
        );
    }

    #[test]
    fn receipt_has_stable_sequence_hash() {
        let r =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        assert_eq!(
            r.deterministic_identity.operations_sequence_hash,
            "f3d76916913c049d"
        );
    }

    /// Verify the receipt records the runtime admission boundary statement.
    #[test]
    fn receipt_declares_model_tier_and_runtime_boundary() {
        let r =
            generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED).expect("receipt");
        assert_eq!(r.evidence_tier, "source-model");
        assert!(r
            .runtime_admission_boundary
            .contains("runtime-ublk-started-export-admission-artifact"));
    }

    #[test]
    fn canonical_fixture_matches_generated_receipt() {
        let receipt = generate_started_export_receipt(FIXTURE_Q, FIXTURE_D, FIXTURE_SEED)
            .expect("fixture generation");
        let checked_in: StartedExportReceipt = serde_json::from_str(include_str!(
            "../../../validation/artifacts/ublk/started-export-service-loop-model.json"
        ))
        .expect("checked-in fixture deserialize");
        let generated = serde_json::to_value(&receipt).expect("generated fixture value");
        let committed = serde_json::to_value(&checked_in).expect("committed fixture value");
        assert_eq!(
            generated, committed,
            "checked-in started-export fixture must match generator output"
        );
    }
}
