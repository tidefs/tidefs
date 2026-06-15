use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::PathBuf;

use tidefs_ublk_abi::{
    UblkSrvIoCmd, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE,
    UBLK_IO_OP_WRITE_ZEROES, UBLK_IO_RES_OK,
};

pub const UBLK_COMPLETION_ARTIFACT_ENV: &str = "TIDEFS_UBLK_COMPLETION_ARTIFACT";
pub const UBLK_COMPLETION_ARTIFACT_MAX_COMPLETIONS_ENV: &str =
    "TIDEFS_UBLK_COMPLETION_ARTIFACT_MAX_COMPLETIONS";
pub const UBLK_COMPLETION_ARTIFACT_DEFAULT_MAX_COMPLETIONS: usize = 512;
pub const UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS: &str = "runtime-ublk-completion-artifact";
pub const UBLK_COMPLETION_ARTIFACT_CLAIM_ID: &str = "ublk.qid_tag.exactly_once_completion.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkCompletionOperationKind {
    Fetch,
    Read,
    Write,
    Flush,
    Discard,
    WriteZeroes,
    Unknown(u8),
    Release,
}

impl UblkCompletionOperationKind {
    #[must_use]
    pub const fn from_ublk_op(op: u8) -> Self {
        match op {
            UBLK_IO_OP_READ => Self::Read,
            UBLK_IO_OP_WRITE => Self::Write,
            UBLK_IO_OP_FLUSH => Self::Flush,
            UBLK_IO_OP_DISCARD => Self::Discard,
            UBLK_IO_OP_WRITE_ZEROES => Self::WriteZeroes,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Discard => "discard",
            Self::WriteZeroes => "write_zeroes",
            Self::Unknown(_) => "unknown",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Debug)]
struct UblkCompletionTraceEvent {
    sequence: u64,
    qid: u16,
    tag: u16,
    generation_token: u64,
    operation_kind: UblkCompletionOperationKind,
    lifecycle_state: &'static str,
    terminal_result: Option<i32>,
    source: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct PendingCompletionCqe {
    generation_token: u64,
    operation_kind: UblkCompletionOperationKind,
    terminal_result: i32,
}

#[derive(Clone, Debug, Default)]
struct UblkCompletionSlotTrace {
    current_generation_token: u64,
    in_flight_generation_token: Option<u64>,
    in_flight_operation_kind: Option<UblkCompletionOperationKind>,
    pending_completion_cqe: Option<PendingCompletionCqe>,
    released: bool,
}

pub struct UblkCompletionTrace {
    path: Option<PathBuf>,
    nr_hw_queues: u16,
    queue_depth: u16,
    max_completed_requests: usize,
    completed_requests: usize,
    next_sequence: u64,
    slots: BTreeMap<(u16, u16), UblkCompletionSlotTrace>,
    events: Vec<UblkCompletionTraceEvent>,
}

impl UblkCompletionTrace {
    #[must_use]
    pub fn from_env(nr_hw_queues: u16, queue_depth: u16) -> Self {
        let path = env::var_os(UBLK_COMPLETION_ARTIFACT_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let max_completed_requests = env::var(UBLK_COMPLETION_ARTIFACT_MAX_COMPLETIONS_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(UBLK_COMPLETION_ARTIFACT_DEFAULT_MAX_COMPLETIONS);

        Self {
            path,
            nr_hw_queues,
            queue_depth,
            max_completed_requests,
            completed_requests: 0,
            next_sequence: 1,
            slots: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.path.is_some()
    }

    pub fn record_fetch_submitted(&mut self, qid: u16, tag: u16) {
        if !self.is_enabled() {
            return;
        }
        let generation_token = {
            let slot = self.slots.entry((qid, tag)).or_default();
            slot.current_generation_token
        };
        self.push_event(
            qid,
            tag,
            generation_token,
            UblkCompletionOperationKind::Fetch,
            "fetch_submitted",
            None,
            "initial_fetch_req_submit",
        );
    }

    pub fn record_fetch_cqe_error(
        &mut self,
        qid: u16,
        tag: u16,
        is_commit_and_fetch: bool,
        result: i32,
    ) {
        if !self.is_enabled() {
            return;
        }
        let generation_token = self
            .slots
            .entry((qid, tag))
            .or_default()
            .current_generation_token;
        let (state, source) = if is_commit_and_fetch {
            ("completion_cqe_error", "commit_and_fetch_cqe")
        } else {
            ("fetch_cqe_error", "fetch_req_cqe")
        };
        self.push_event(
            qid,
            tag,
            generation_token,
            UblkCompletionOperationKind::Fetch,
            state,
            Some(result),
            source,
        );
    }

    pub fn record_completion_cqe(&mut self, qid: u16, tag: u16) {
        if !self.is_enabled() {
            return;
        }
        let Some(slot) = self.slots.get_mut(&(qid, tag)) else {
            return;
        };
        let Some(pending) = slot.pending_completion_cqe.take() else {
            return;
        };
        self.push_event(
            qid,
            tag,
            pending.generation_token,
            pending.operation_kind,
            "completion_cqe",
            Some(pending.terminal_result),
            "commit_and_fetch_cqe",
        );
    }

    pub fn record_request_fetched(
        &mut self,
        qid: u16,
        tag: u16,
        operation_kind: UblkCompletionOperationKind,
        is_reissued_fetch: bool,
    ) {
        if !self.is_enabled() || self.completed_requests >= self.max_completed_requests {
            return;
        }
        let generation_token = {
            let slot = self.slots.entry((qid, tag)).or_default();
            slot.current_generation_token = slot.current_generation_token.saturating_add(1);
            slot.in_flight_generation_token = Some(slot.current_generation_token);
            slot.in_flight_operation_kind = Some(operation_kind);
            slot.current_generation_token
        };
        let state = if is_reissued_fetch {
            "request_reissued"
        } else {
            "request_fetched"
        };
        let source = if is_reissued_fetch {
            "commit_and_fetch_cqe"
        } else {
            "fetch_req_cqe"
        };
        self.push_event(
            qid,
            tag,
            generation_token,
            operation_kind,
            state,
            None,
            source,
        );
    }

    pub fn record_completion_submitted(&mut self, qid: u16, tag: u16, result: i32) {
        if !self.is_enabled() {
            return;
        }
        let Some(slot) = self.slots.get_mut(&(qid, tag)) else {
            return;
        };
        let Some(generation_token) = slot.in_flight_generation_token.take() else {
            return;
        };
        let Some(operation_kind) = slot.in_flight_operation_kind.take() else {
            return;
        };
        slot.pending_completion_cqe = Some(PendingCompletionCqe {
            generation_token,
            operation_kind,
            terminal_result: result,
        });
        self.completed_requests = self.completed_requests.saturating_add(1);
        self.push_event(
            qid,
            tag,
            generation_token,
            operation_kind,
            "completion_submitted",
            Some(result),
            "daemon_commit_and_fetch_submit",
        );
    }

    pub fn record_completion_submit_failed(&mut self, qid: u16, tag: u16, result: i32) {
        if !self.is_enabled() {
            return;
        }
        let Some(slot) = self.slots.get(&(qid, tag)) else {
            return;
        };
        let generation_token = slot
            .in_flight_generation_token
            .unwrap_or(slot.current_generation_token);
        let operation_kind = slot
            .in_flight_operation_kind
            .unwrap_or(UblkCompletionOperationKind::Unknown(0));
        self.push_event(
            qid,
            tag,
            generation_token,
            operation_kind,
            "completion_submit_failed",
            Some(result),
            "daemon_commit_and_fetch_submit",
        );
    }

    pub fn record_releases(&mut self) {
        if !self.is_enabled() {
            return;
        }
        let slot_keys = self.slots.keys().copied().collect::<Vec<_>>();
        for (qid, tag) in slot_keys {
            let mut request_release = None;
            let queue_generation_token;
            {
                let Some(slot) = self.slots.get_mut(&(qid, tag)) else {
                    continue;
                };
                if slot.released {
                    continue;
                }
                slot.released = true;
                if let Some(generation_token) = slot.in_flight_generation_token.take() {
                    let operation_kind = slot
                        .in_flight_operation_kind
                        .take()
                        .unwrap_or(UblkCompletionOperationKind::Release);
                    request_release = Some((generation_token, operation_kind));
                }
                queue_generation_token = slot.current_generation_token;
            }
            if let Some((generation_token, operation_kind)) = request_release {
                self.push_event(
                    qid,
                    tag,
                    generation_token,
                    operation_kind,
                    "request_released",
                    Some(-libc::ECANCELED),
                    "data_queue_release",
                );
            }
            self.push_event(
                qid,
                tag,
                queue_generation_token,
                UblkCompletionOperationKind::Release,
                "queue_released",
                None,
                "data_queue_release",
            );
        }
    }

    pub fn write_if_enabled(&self) -> io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_json())
    }

    fn push_event(
        &mut self,
        qid: u16,
        tag: u16,
        generation_token: u64,
        operation_kind: UblkCompletionOperationKind,
        lifecycle_state: &'static str,
        terminal_result: Option<i32>,
        source: &'static str,
    ) {
        self.events.push(UblkCompletionTraceEvent {
            sequence: self.next_sequence,
            qid,
            tag,
            generation_token,
            operation_kind,
            lifecycle_state,
            terminal_result,
            source,
        });
        self.next_sequence = self.next_sequence.saturating_add(1);
    }

    fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str("  \"report_version\": 1,\n");
        out.push_str("  \"generated_by\": \"tidefs-block-volume-adapter-daemon\",\n");
        out.push_str("  \"claim_ids\": [\n");
        let _ = writeln!(out, "    \"{}\"", UBLK_COMPLETION_ARTIFACT_CLAIM_ID);
        out.push_str("  ],\n");
        let _ = writeln!(
            out,
            "  \"evidence_class\": \"{}\",",
            UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS
        );
        out.push_str("  \"evidence_scope\": \"bounded runtime uBLK daemon qid/tag completion lifecycle trace\",\n");
        out.push_str("  \"scenario\": \"qemu-ublk-smoke\",\n");
        let _ = writeln!(out, "  \"nr_hw_queues\": {},", self.nr_hw_queues);
        let _ = writeln!(out, "  \"queue_depth\": {},", self.queue_depth);
        let _ = writeln!(
            out,
            "  \"max_completed_requests\": {},",
            self.max_completed_requests
        );
        out.push_str("  \"events\": [\n");
        for (index, event) in self.events.iter().enumerate() {
            out.push_str("    {\n");
            let _ = writeln!(out, "      \"sequence\": {},", event.sequence);
            let _ = writeln!(out, "      \"qid\": {},", event.qid);
            let _ = writeln!(out, "      \"tag\": {},", event.tag);
            let _ = writeln!(
                out,
                "      \"generation_token\": {},",
                event.generation_token
            );
            let _ = writeln!(
                out,
                "      \"operation_kind\": \"{}\",",
                event.operation_kind.as_str()
            );
            let _ = writeln!(
                out,
                "      \"lifecycle_state\": \"{}\",",
                event.lifecycle_state
            );
            match event.terminal_result {
                Some(result) => {
                    let _ = writeln!(out, "      \"terminal_result\": {},", result);
                }
                None => out.push_str("      \"terminal_result\": null,\n"),
            }
            let _ = writeln!(out, "      \"source\": \"{}\"", event.source);
            out.push_str("    }");
            if index + 1 != self.events.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n");
        out.push_str("}\n");
        out
    }
}

/// Convert an io_uring completion result into a ublk I/O command result.
///
/// Successful operations map to `UBLK_IO_RES_OK`; dispatcher errors carry the
/// kernel errno as a negative result.
pub fn ublk_result_from_completion(
    completion: &crate::ublk_io_uring::UblkIoCompletionResult,
) -> i32 {
    match completion {
        crate::ublk_io_uring::UblkIoCompletionResult::Read { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::Write { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::Flush { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::Discard { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::WriteZeroes { .. } => UBLK_IO_RES_OK,
        crate::ublk_io_uring::UblkIoCompletionResult::Error { errno, .. } => -errno,
    }
}

/// Reap all available completions from the dispatcher and convert them to ublk
/// `UblkSrvIoCmd` results for a given queue.
pub fn reap_ublk_completions(
    dispatcher: &mut crate::ublk_io_uring::UblkIoUringDispatcher,
    queue_id: u16,
) -> Vec<UblkSrvIoCmd> {
    dispatcher
        .reap_completions()
        .into_iter()
        .map(|completion| {
            let tag = completion.tag();
            let result = ublk_result_from_completion(&completion);
            UblkSrvIoCmd {
                q_id: queue_id,
                tag: (tag & 0xFFFF) as u16,
                result,
                addr_or_zone_append_lba: 0,
            }
        })
        .collect()
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use tempfile::tempfile;

    fn create_tempfile_with_data(data: &[u8]) -> (std::fs::File, std::os::fd::RawFd) {
        let mut f = tempfile().expect("tempfile");
        f.write_all(data).expect("write data");
        f.flush().expect("flush");
        let fd = f.as_raw_fd();
        (f, fd)
    }

    #[test]
    fn ublk_result_maps_ok_to_zero() {
        use crate::ublk_io_uring::UblkIoCompletionResult;
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Read { tag: 0, bytes: 512 }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Write {
                tag: 1,
                bytes: 1024
            }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Flush { tag: 2 }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Discard { tag: 3 }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::WriteZeroes { tag: 4 }),
            UBLK_IO_RES_OK
        );
    }

    #[test]
    fn ublk_result_maps_error_to_negative_errno() {
        use crate::ublk_io_uring::UblkIoCompletionResult;
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Error { tag: 0, errno: 5 }),
            -5
        );
    }

    #[test]
    fn reap_ublk_completions_integrates_with_dispatcher() {
        use crate::ublk_io_uring::UblkIoUringDispatcher;

        let data = vec![0u8; 8192];
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        let payload: Vec<u8> = (0..512u16).map(|i| i as u8).collect();
        dispatcher.write_at(0, &payload).expect("write_at");
        dispatcher.flush().expect("flush");

        let cmds = reap_ublk_completions(&mut dispatcher, 0);
        let _ = cmds;

        let mut read_buf = vec![0u8; 512];
        dispatcher.submit_write(0, &payload).expect("submit_write");
        dispatcher.submit_flush().expect("submit_flush");
        dispatcher
            .submit_read(0, &mut read_buf)
            .expect("submit_read");

        dispatcher.submit_and_wait(3).expect("submit_and_wait");

        let cmds = reap_ublk_completions(&mut dispatcher, 1);
        assert_eq!(cmds.len(), 3, "expected 3 completion cmds, got {cmds:?}");
        for cmd in &cmds {
            assert_eq!(cmd.q_id, 1);
            assert_eq!(cmd.result, UBLK_IO_RES_OK);
        }
        assert_eq!(&read_buf[..], &payload[..]);
    }
}
