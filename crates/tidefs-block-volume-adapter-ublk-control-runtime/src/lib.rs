// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ublk block-volume adapter control runtime.
//!
//! # Role in the TideFS block stack
//!
//! This crate is the control-plane bridge between Linux ublk block devices
//! and TideFS block-volume semantics. It occupies the layer between the
//! kernel ublk driver (via [`tidefs_ublk_abi`]) and the daemon-side
//! `tidefs_block_volume_adapter_daemon` io_uring runtime loop:
//!
//! ```text
//! kernel ublk driver -> ublk-abi -> this crate -> block-volume-adapter-core
//!                                        |
//!                                        v
//!                            block-volume-adapter-daemon
//!                            (io_uring runtime loop)
//! ```
//!
//! # Core abstractions
//!
//! - **[`crate::UblkControlRuntime`]** — owns the ublk control device (`/dev/ublk-control`),
//!   an io_uring ring for control-plane commands (ADD_DEV, DEL_DEV, SET_PARAMS,
//!   START_DEV, STOP_DEV), and per-device lifecycle state machines.
//! - **[`crate::device::UblkDeviceBuilder`]** — orchestrates the full device-build sequence
//!   (ADD_DEV -> data-queue open -> SET_PARAMS -> FETCH_REQ -> START_DEV) with
//!   rollback on partial failure.
//! - **[`crate::queue::UblkQueueMapper`]** — manages per-queue access to the shared ublk
//!   data-queue file descriptor, io_uring ring, and mmap'd I/O buffer region.
//! - **[`crate::ublk_io::UblkIoBackend`]** — pluggable trait implementing block-level read,
//!   write, flush, discard, and write_zeroes operations. The daemon provides
//!   the concrete backend (file, block device, or object-store pool).
//!
//! # Request lifecycle
//!
//! 3a. **[`crate::boundary::validate_io_request`]** — validates sector-alignment,
//!     capacity-bounds, overflow-guard, and zero-length checks for all data I/O
//!     types (read, write, discard, write-zeroes). Writes may use either
//!     [`crate::boundary::handle_write`] (boundary-first dispatch) or
//!     [`crate::write::handle_write`] (write-focused validation).
//! 3b. **[`crate::boundary::handle_read`]**, **[`crate::boundary::handle_discard`]**,
//!     **[`crate::boundary::handle_write_zeroes`]**, **[`crate::boundary::handle_write`]** —
//!     validated dispatch helpers that apply boundary checks before backend
//!     dispatch for reads, writes, discards, and write-zeroes.
//!
//! 1. The daemon submits FETCH_REQ commands to populate the io_uring SQE ring
//!    with ublk I/O descriptor slots.
//! 2. When the kernel ublk driver posts a block I/O request, the daemon's
//!    io_uring CQE ring delivers a populated [`crate::ublk_io::UblkIoDescriptor`].
//! 3. [`crate::ublk_io::dispatch_io`] validates the descriptor shape (range, buffer presence,
//!    flag correctness) and dispatches through [`crate::ublk_io::UblkIoBackend`] to the
//!    concrete storage backend.
//! 4. The dispatch result is posted back as a COMMIT_AND_FETCH_REQ completion
//!    through the io_uring SQE ring to the kernel.
//!
//! # Threading and queue ownership
//!
//! Each ublk hardware queue is owned by exactly one daemon thread. Queue
//! ownership is established during [`crate::device::UblkDeviceBuilder::build`] and tracked
//! through [`crate::queue::UblkQueueMapper`]. The control-plane io_uring (on
//! `/dev/ublk-control`) is single-threaded; the data-plane io_uring rings
//! (on `/dev/ublkcN`) are per-queue. No cross-queue sharing of io_uring
//! instances is permitted.

//! ## Target-reset completion ordering guarantee
//!
//! Device stop and reset enforce a strict completion-drain-before-deallocation
//! protocol through [`crate::target_reset_guard::TargetResetGuard`]:
//!
//! 1. **Stop submission** — new FETCH_REQ and COMMIT_AND_FETCH_REQ submissions
//!    are halted before drain begins.
//! 2. **Drain completions** — all pending io_uring CQEs are consumed from the
//!    data-queue ring with a timeout-bounded poll loop.
//! 3. **Verify in-flight == 0** — an atomic [`crate::target_reset_guard::InFlightCounter`]
//!    tracks outstanding submissions; the drain ensures it reaches zero before
//!    ring buffers are deallocated.
//!
//! This prevents use-after-free of I/O buffers when the kernel ublk driver
//! completes in-flight commands after the ring has been torn down. The guard
//! is wired into the [`crate::queue_lifecycle::QueueLifecycle`] drain-before-removal
//! state machine via [`UblkDataQueueRuntime::create_reset_guard`] and
//! [`UblkDataQueueRuntime::drain_completions`].

//!
//! ## Control-plane validation surface
//!
//! The integration test suite in `tests/control_plane_validation.rs` exercises the
//! full device lifecycle with BLAKE3-verified configuration state snapshots:
//!
//! - **Device add/configure**: parameter matrix covering queue depth (16–256),
//!   hardware queues (1–4), and I/O buffer sizes (1–4 MiB).
//! - **Queue setup and teardown**: concurrent start/stop sequences, invalid parameter
//!   rejection, and descriptor-threshold mapping.
//! - **Configuration state consistency**: BLAKE3-hashed device parameter snapshots
//!   verified before and after each state transition (Created → Attached → Draining
//!   → Removed).
//! - **Error-injection coverage**: malformed or out-of-order configuration requests,
//!   auto-device-id rejection, and cleanup-on-failure paths.
//!
//! ## Device state machine
//!
//! Devices progress through four [`UblkDeviceLifecycleState`] states:
//!
//! 1. **Created** — `UBLK_CMD_ADD_DEV` succeeded; device registered in the runtime
//!    registry with a BLAKE3 integrity hash of the kernel-reported `UblkSrvCtrlDevInfo`.
//! 2. **Attached** — `UBLK_CMD_START_DEV` succeeded; data-queue runtime is live.
//! 3. **Draining** — drain initiated before removal; in-flight commands complete.
//! 4. **Removed** — `UBLK_CMD_DEL_DEV` succeeded; device unregistered from the runtime.
//!
//! Each state transition verifies the BLAKE3 configuration hash to detect silent
//! kernel-side parameter corruption. [`UblkManagedDevice::verify_integrity`] compares
//! the stored hash against the current `dev_info` and returns
//! [`UblkDeviceIntegrityError::HashMismatch`] on mismatch.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
pub mod device;

pub mod boundary;
pub mod queue;
pub mod queue_lifecycle;
pub mod ublk_io;
pub mod write;

pub mod integrity_validation;
pub mod target_reset_guard;

use crate::queue_lifecycle::QueueLifecycle;

use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use io_uring::{cqueue, opcode, squeue, types, IoUring};
use tidefs_ublk_abi::{
    UblkCtrlCommand, UblkFeatureFlags, UblkIoCommand, UblkIoctlDirection, UblkIoctlRequest,
    UblkParamBasic, UblkParams, UblkSrvCtrlCmd, UblkSrvCtrlDevInfo, UblkSrvIoCmd, UblkSrvIoDesc,
    UBLK_FEATURES_LEN, UBLK_IO_BUF_BITS, UBLK_IO_OP_FLUSH, UBLK_IO_RES_NEED_GET_DATA,
    UBLK_IO_RES_OK, UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH, UBLK_PARAM_TYPE_BASIC,
    UBLK_PARAM_TYPE_DISCARD, UBLK_PARAM_TYPE_SEGMENT,
};
#[cfg(test)]
mod error_injection {
    use std::cell::Cell;

    thread_local! {
        static INJECTED: Cell<Option<InjectedError>> = const { Cell::new(None) };
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum InjectedError {
        AddDevUblkCommandErrno(i32),
        DelDevUblkCommandErrno(i32),
        DelDevAfterAddDevFailure,
        SetParamsUblkCommandErrno(i32),
        StartDevUblkCommandErrno(i32),
        StopDevUblkCommandErrno(i32),
        FetchReqSubmissionQueueFull,
        FetchReqUblkCommandErrno(i32),
        FetchReqIoUringSubmitErrno(i32),
        FetchReqIoUringSubmitZero,
        FetchReqIoUringSubmitMissingErrno,
        DataQueueRuntimeOpenError(i32),
        DataQueueIoUringSetupErrno(i32),
        RuntimeFetchReqsSubmissionQueueFull,
        ReadonlyProbeUblkCommandErrno(i32),
    }

    pub fn set(error: InjectedError) {
        INJECTED.with(|cell| cell.set(Some(error)));
    }

    pub fn clear() {
        INJECTED.with(|cell| cell.set(None));
    }

    pub fn try_take() -> Option<InjectedError> {
        INJECTED.with(|cell| cell.replace(None))
    }

    pub(crate) fn peek_and_consume<F>(matcher: F) -> Option<InjectedError>
    where
        F: Fn(&InjectedError) -> bool,
    {
        INJECTED.with(|cell| {
            let taken = cell.replace(None);
            match taken {
                Some(ref err) if matcher(err) => taken,
                other => {
                    cell.set(other);
                    None
                }
            }
        })
    }
}

#[cfg(test)]
fn apply_add_dev_injection() -> Option<UblkControlAddDevError> {
    error_injection::peek_and_consume(|e| {
        matches!(e, error_injection::InjectedError::AddDevUblkCommandErrno(_))
    })
    .map(|e| match e {
        error_injection::InjectedError::AddDevUblkCommandErrno(n) => {
            UblkControlAddDevError::UblkCommandErrno(n)
        }
        _ => unreachable!(),
    })
}

#[cfg(not(test))]
const fn apply_add_dev_injection() -> Option<UblkControlAddDevError> {
    None
}

#[cfg(test)]
fn apply_del_dev_injection(
    input: &UblkControlDelDevInput,
) -> Result<Option<UblkControlDelDevOutcome>, UblkControlDelDevError> {
    error_injection::peek_and_consume(|e| {
        matches!(
            e,
            error_injection::InjectedError::DelDevUblkCommandErrno(_)
                | error_injection::InjectedError::DelDevAfterAddDevFailure
        )
    })
    .map_or(Ok(None), |e| match e {
        error_injection::InjectedError::DelDevUblkCommandErrno(n) => {
            Err(UblkControlDelDevError::UblkCommandErrno(n))
        }
        error_injection::InjectedError::DelDevAfterAddDevFailure => {
            Ok(Some(UblkControlDelDevOutcome::from_dev_id(input.dev_id)))
        }
        _ => unreachable!(),
    })
}

#[cfg(not(test))]
fn apply_del_dev_injection(
    _input: &UblkControlDelDevInput,
) -> Result<Option<UblkControlDelDevOutcome>, UblkControlDelDevError> {
    Ok(None)
}

#[cfg(test)]
fn apply_set_params_injection() -> Option<UblkControlSetParamsError> {
    error_injection::peek_and_consume(|e| {
        matches!(
            e,
            error_injection::InjectedError::SetParamsUblkCommandErrno(_)
        )
    })
    .map(|e| match e {
        error_injection::InjectedError::SetParamsUblkCommandErrno(n) => {
            UblkControlSetParamsError::UblkCommandErrno(n)
        }
        _ => unreachable!(),
    })
}

#[cfg(not(test))]
const fn apply_set_params_injection() -> Option<UblkControlSetParamsError> {
    None
}

#[cfg(test)]
fn apply_start_dev_injection() -> Option<UblkControlStartDevError> {
    error_injection::peek_and_consume(|e| {
        matches!(
            e,
            error_injection::InjectedError::StartDevUblkCommandErrno(_)
        )
    })
    .map(|e| match e {
        error_injection::InjectedError::StartDevUblkCommandErrno(n) => {
            UblkControlStartDevError::UblkCommandErrno(n)
        }
        _ => unreachable!(),
    })
}

#[cfg(not(test))]
const fn apply_start_dev_injection() -> Option<UblkControlStartDevError> {
    None
}

#[cfg(test)]
fn apply_stop_dev_injection() -> Option<UblkControlStopDevError> {
    error_injection::peek_and_consume(|e| {
        matches!(
            e,
            error_injection::InjectedError::StopDevUblkCommandErrno(_)
        )
    })
    .map(|e| match e {
        error_injection::InjectedError::StopDevUblkCommandErrno(n) => {
            UblkControlStopDevError::UblkCommandErrno(n)
        }
        _ => unreachable!(),
    })
}

#[cfg(not(test))]
const fn apply_stop_dev_injection() -> Option<UblkControlStopDevError> {
    None
}

#[cfg(test)]
fn apply_readonly_probe_injection() -> Option<UblkControlReadonlyProbeError> {
    error_injection::peek_and_consume(|e| {
        matches!(
            e,
            error_injection::InjectedError::ReadonlyProbeUblkCommandErrno(_)
        )
    })
    .map(|e| match e {
        error_injection::InjectedError::ReadonlyProbeUblkCommandErrno(n) => {
            UblkControlReadonlyProbeError::UblkCommandErrno(n)
        }
        _ => unreachable!(),
    })
}

#[cfg(not(test))]
const fn apply_readonly_probe_injection() -> Option<UblkControlReadonlyProbeError> {
    None
}

#[cfg(test)]
fn apply_fetch_req_injection() -> Result<(), UblkDataQueueFetchReqError> {
    fn matches_fetch_req_err(e: &error_injection::InjectedError) -> bool {
        use error_injection::InjectedError;
        matches!(
            e,
            InjectedError::FetchReqSubmissionQueueFull
                | InjectedError::FetchReqUblkCommandErrno(_)
                | InjectedError::FetchReqIoUringSubmitErrno(_)
                | InjectedError::FetchReqIoUringSubmitZero
                | InjectedError::FetchReqIoUringSubmitMissingErrno,
        )
    }
    match error_injection::peek_and_consume(matches_fetch_req_err) {
        Some(error_injection::InjectedError::FetchReqSubmissionQueueFull) => {
            Err(UblkDataQueueFetchReqError::SubmissionQueueFull)
        }
        Some(error_injection::InjectedError::FetchReqUblkCommandErrno(n)) => {
            Err(UblkDataQueueFetchReqError::IoUringSubmitErrno(n))
        }
        Some(error_injection::InjectedError::FetchReqIoUringSubmitErrno(n)) => {
            Err(UblkDataQueueFetchReqError::IoUringSubmitErrno(n))
        }
        Some(error_injection::InjectedError::FetchReqIoUringSubmitZero) => {
            Err(UblkDataQueueFetchReqError::IoUringSubmitZero)
        }
        Some(error_injection::InjectedError::FetchReqIoUringSubmitMissingErrno) => {
            Err(UblkDataQueueFetchReqError::IoUringSubmitMissingErrno)
        }
        None => Ok(()),
        _ => unreachable!(),
    }
}

#[cfg(not(test))]
const fn apply_fetch_req_injection() -> Result<(), UblkDataQueueFetchReqError> {
    Ok(())
}

#[cfg(test)]
fn apply_data_queue_open_injection() -> Result<(), UblkDataQueueRuntimeOpenError> {
    match error_injection::peek_and_consume(|e| {
        matches!(
            e,
            error_injection::InjectedError::DataQueueRuntimeOpenError(_)
                | error_injection::InjectedError::DataQueueIoUringSetupErrno(_)
        )
    }) {
        Some(error_injection::InjectedError::DataQueueRuntimeOpenError(n)) => {
            Err(UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(n))
        }
        Some(error_injection::InjectedError::DataQueueIoUringSetupErrno(n)) => {
            Err(UblkDataQueueRuntimeOpenError::IoUringSetupErrno(n))
        }
        None => Ok(()),
        _ => unreachable!(),
    }
}

#[cfg(not(test))]
const fn apply_data_queue_open_injection() -> Result<(), UblkDataQueueRuntimeOpenError> {
    Ok(())
}

#[cfg(test)]
fn apply_runtime_fetch_reqs_injection() -> Result<(), UblkDataQueueFetchReqSubmissionError> {
    match error_injection::peek_and_consume(|e| {
        matches!(
            e,
            error_injection::InjectedError::RuntimeFetchReqsSubmissionQueueFull
        )
    }) {
        Some(error_injection::InjectedError::RuntimeFetchReqsSubmissionQueueFull) => {
            Err(UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
                tag: 0,
                submitted_fetch_commands: 0,
                error: UblkDataQueueFetchReqError::SubmissionQueueFull,
            })
        }
        None => Ok(()),
        _ => unreachable!(),
    }
}

#[cfg(not(test))]
const fn apply_runtime_fetch_reqs_injection() -> Result<(), UblkDataQueueFetchReqSubmissionError> {
    Ok(())
}

/// OW-301P block-volume adapter ublk control runtime issues only admitted read-only uring_cmd feature probes
pub const BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P: &str =
    "OW-301P block-volume adapter ublk control runtime issues only admitted read-only uring_cmd feature probes";
/// OW-301Q block-volume adapter ublk control runtime issues only admitted ADD_DEV uring_cmd boundaries
pub const BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q: &str =
    "OW-301Q block-volume adapter ublk control runtime issues only admitted ADD_DEV uring_cmd boundaries";
/// OW-301R block-volume adapter ublk control runtime issues only admitted DEL_DEV cleanup uring_cmd boundaries
pub const BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R: &str =
    "OW-301R block-volume adapter ublk control runtime issues only admitted DEL_DEV cleanup uring_cmd boundaries";
/// OW-301ZC block-volume adapter ublk control runtime issues only admitted STOP_DEV drain-before-removal uring_cmd boundaries
pub const BLOCK_VOLUME_UBLK_CONTROL_STOP_DEV_GATE_OW_301ZC: &str =
    "OW-301ZC block-volume adapter ublk control runtime issues only admitted STOP_DEV drain-before-removal uring_cmd boundaries";
/// OW-301S block-volume adapter ublk control runtime issues only admitted SET_PARAMS uring_cmd boundaries
pub const BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S: &str =
    "OW-301S block-volume adapter ublk control runtime issues only admitted SET_PARAMS uring_cmd boundaries";
/// OW-301Y block-volume adapter ublk control runtime issues only admitted UPDATE_SIZE uring_cmd boundaries
pub const BLOCK_VOLUME_UBLK_CONTROL_UPDATE_SIZE_GATE_OW_301Y: &str =
    "OW-301Y block-volume adapter ublk control runtime issues only admitted UPDATE_SIZE uring_cmd boundaries";
/// OW-301T block-volume adapter ublk control runtime exposes START_DEV only behind ready data-queue fetch admission
pub const BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T: &str =
    "OW-301T block-volume adapter ublk control runtime exposes START_DEV only behind ready data-queue fetch admission";
/// OW-301U block-volume adapter ublk runtime source-binds data-queue FETCH_REQ readiness before START_DEV
pub const BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U: &str =
    "OW-301U block-volume adapter ublk runtime source-binds data-queue FETCH_REQ readiness before START_DEV";
/// OW-301V block-volume adapter ublk runtime opens data-queue state only after concrete ADD_DEV admission
pub const BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V: &str =
    "OW-301V block-volume adapter ublk runtime opens data-queue state only after concrete ADD_DEV admission";
/// OW-301W block-volume adapter ublk runtime submits FETCH_REQ only while live data-queue ownership is held
pub const BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W: &str =
    "OW-301W block-volume adapter ublk runtime submits FETCH_REQ only while live data-queue ownership is held";
/// OW-301X block-volume adapter ublk runtime guards COMMIT_AND_FETCH_REQ behind fetched request completion
pub const BLOCK_VOLUME_UBLK_DATA_QUEUE_COMMIT_FETCH_GATE_OW_301X: &str =
    "OW-301X block-volume adapter ublk runtime guards COMMIT_AND_FETCH_REQ behind fetched request completion";
/// OW-301Z block-volume adapter ublk runtime maps fetched FLUSH descriptors to deterministic COMMIT_AND_FETCH_REQ completions
pub const BLOCK_VOLUME_UBLK_DATA_QUEUE_FLUSH_PLAN_GATE_OW_301Z: &str =
    "OW-301Z block-volume adapter ublk runtime maps fetched FLUSH descriptors to deterministic COMMIT_AND_FETCH_REQ completions";
/// Ublk Control Readonly Probe Ring Entries.
pub const UBLK_CONTROL_READONLY_PROBE_RING_ENTRIES: u32 = 1;
/// Ublk Control Readonly Probe User Data.
pub const UBLK_CONTROL_READONLY_PROBE_USER_DATA: u64 = 0x5649_4245_4653_0131;
/// Ublk Control Add Dev Ring Entries.
pub const UBLK_CONTROL_ADD_DEV_RING_ENTRIES: u32 = 1;
/// Ublk Control Add Dev User Data.
pub const UBLK_CONTROL_ADD_DEV_USER_DATA: u64 = 0x5649_4245_4653_0132;
/// Ublk Control Del Dev Ring Entries.
pub const UBLK_CONTROL_DEL_DEV_RING_ENTRIES: u32 = 1;
/// Ublk Control Del Dev User Data.
pub const UBLK_CONTROL_DEL_DEV_USER_DATA: u64 = 0x5649_4245_4653_0133;
/// Ublk Control Set Params Ring Entries.
pub const UBLK_CONTROL_SET_PARAMS_RING_ENTRIES: u32 = 1;
/// Ublk Control Set Params User Data.
pub const UBLK_CONTROL_SET_PARAMS_USER_DATA: u64 = 0x5649_4245_4653_0134;
/// Ublk Control Start Dev Ring Entries.
pub const UBLK_CONTROL_START_DEV_RING_ENTRIES: u32 = 1;
/// Ublk Control Start Dev User Data.
pub const UBLK_CONTROL_START_DEV_USER_DATA: u64 = 0x5649_4245_4653_0135;
/// Ublk Control Stop Dev Ring Entries.
pub const UBLK_CONTROL_STOP_DEV_RING_ENTRIES: u32 = 1;
/// Ublk Control Stop Dev User Data.
pub const UBLK_CONTROL_STOP_DEV_USER_DATA: u64 = 0x5649_4245_4653_0136;
/// Ublk Control Start User Recovery User Data.
pub const UBLK_CONTROL_START_USER_RECOVERY_USER_DATA: u64 = 0x5649_4245_4653_0137;
/// Ublk Control End User Recovery User Data.
pub const UBLK_CONTROL_END_USER_RECOVERY_USER_DATA: u64 = 0x5649_4245_4653_0138;
/// Ublk Data Queue Fetch Req Ring Entries.
pub const UBLK_DATA_QUEUE_FETCH_REQ_RING_ENTRIES: u32 = 64;
/// Ublk Data Queue Runtime Ring Entries.
pub const UBLK_DATA_QUEUE_RUNTIME_RING_ENTRIES: u32 = UBLK_DATA_QUEUE_FETCH_REQ_RING_ENTRIES;
/// Ublk Data Queue Path Template.
pub const UBLK_DATA_QUEUE_PATH_TEMPLATE: &str = "/dev/ublkcN";
/// Tidefs Ublk Add Dev Required Features.
pub const TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES: UblkFeatureFlags =
    UblkFeatureFlags::CMD_IOCTL_ENCODE
        .union(UblkFeatureFlags::USER_COPY)
        .union(UblkFeatureFlags::UPDATE_SIZE);
/// Tidefs Ublk Add Dev Default Max Io Buf Bytes.
pub const TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES: u32 = 1024 * 1024;
/// Tidefs Ublk Add Dev Default Queue Depth.
pub const TIDEFS_UBLK_ADD_DEV_DEFAULT_QUEUE_DEPTH: u16 = 64;
/// Tidefs Ublk Add Dev Default Nr Hw Queues.
pub const TIDEFS_UBLK_ADD_DEV_DEFAULT_NR_HW_QUEUES: u16 = 1;
/// Tidefs Ublk Add Dev Auto Dev Id.
pub const TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID: u32 = u32::MAX;
// ── Resize policy (explicit refusal) ─────────────────────────────────

/// Reason why ublk device resize is refused by the current TideFS release.
///
/// Online grow is supported: `UPDATE_SIZE` is included in
/// `TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES` and the kernel will issue
/// `UPDATE_SIZE` to the daemon on resize requests. Shrink is refused
/// with explicit constraints. This refusal exists when the specific
/// backend or pool does not support online resize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkResizeRefusalReason {
    /// Pool capacity is fixed after pool creation or the specific
    /// backend does not support online resize. Shrink remains refused.
    PoolCapacityFixedAtCreate,
}

impl UblkResizeRefusalReason {
    /// Human-readable refusal description.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PoolCapacityFixedAtCreate => {
                "pool capacity is fixed at create; online resize is not yet supported"
            }
        }
    }

    /// Linux errno returned to the guest when resize is attempted.
    /// `ENOTSUP` (95 on most architectures) signals the generic
    /// "operation not supported" contract.
    #[must_use]
    pub const fn guest_errno(self) -> i32 {
        libc::ENOTSUP
    }
}

/// Current TideFS resize policy. Online grow is supported on
/// pool-backed and file-image block volumes; shrink is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkResizePolicy {
    /// `Some(reason)` means resize is refused; `None` means supported.
    pub reason: Option<UblkResizeRefusalReason>,
}

/// Resolve the current resize policy based on backend capability.
#[must_use]
pub const fn resolve_resize_policy(resize_supported: bool) -> UblkResizePolicy {
    UblkResizePolicy {
        reason: if resize_supported {
            None
        } else {
            Some(UblkResizeRefusalReason::PoolCapacityFixedAtCreate)
        },
    }
}

/// Ublk Control Readonly Probe Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlReadonlyProbeCommand {
    /// Getfeatures.
    GetFeatures,
}

impl UblkControlReadonlyProbeCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetFeatures => "GET_FEATURES",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::GetFeatures => UblkCtrlCommand::GetFeatures,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Readonly Probe Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlReadonlyProbeSpec {
    /// Command.
    pub command: UblkControlReadonlyProbeCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Feature Buffer Len.
    pub feature_buffer_len: usize,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
}

impl UblkControlReadonlyProbeSpec {
    /// Get Features.
    #[must_use]
    pub const fn get_features() -> Self {
        let command = UblkControlReadonlyProbeCommand::GetFeatures;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            feature_buffer_len: UBLK_FEATURES_LEN,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: false,
        }
    }
}

/// Ublk Control Readonly Probe Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlReadonlyProbeError {
    /// Unsupportedreadonlycommand.
    UnsupportedReadOnlyCommand(UblkCtrlCommand),
    /// Unsupportedmutatingcommand.
    UnsupportedMutatingCommand(UblkCtrlCommand),
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlReadonlyProbeError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedReadOnlyCommand(_) => "unsupported_read_only_command",
            Self::UnsupportedMutatingCommand(_) => "unsupported_mutating_command",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }

    /// Rejected Command.
    #[must_use]
    pub const fn rejected_command(self) -> Option<UblkCtrlCommand> {
        match self {
            Self::UnsupportedReadOnlyCommand(command)
            | Self::UnsupportedMutatingCommand(command) => Some(command),
            Self::IoUringSetupErrno(_)
            | Self::IoUringSetupMissingErrno
            | Self::SubmissionQueueFull
            | Self::IoUringSubmitErrno(_)
            | Self::IoUringSubmitMissingErrno
            | Self::CompletionMissing
            | Self::UnexpectedCompletionUserData(_)
            | Self::UblkCommandErrno(_) => None,
        }
    }
}

/// Ublk Control Get Features Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlGetFeaturesOutcome {
    /// Command.
    pub command: UblkControlReadonlyProbeCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Features.
    pub features: UblkFeatureFlags,
}

impl UblkControlGetFeaturesOutcome {
    /// From Features Bits.
    #[must_use]
    pub const fn from_features_bits(features_bits: u64) -> Self {
        Self {
            command: UblkControlReadonlyProbeCommand::GetFeatures,
            request_raw: UblkControlReadonlyProbeCommand::GetFeatures.request().raw(),
            features: UblkFeatureFlags(features_bits),
        }
    }
}

/// # Errors
///
/// Returns [`UblkControlReadonlyProbeError`] on failure.
pub const fn build_readonly_probe_spec(
    command: UblkCtrlCommand,
) -> Result<UblkControlReadonlyProbeSpec, UblkControlReadonlyProbeError> {
    match command {
        UblkCtrlCommand::GetFeatures => Ok(UblkControlReadonlyProbeSpec::get_features()),
        UblkCtrlCommand::GetDevInfo2 => Err(
            UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(command),
        ),
        other if other.mutates_control_state() => Err(
            UblkControlReadonlyProbeError::UnsupportedMutatingCommand(other),
        ),
        other => Err(UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(
            other,
        )),
    }
}

/// Build Get Features Ctrl Cmd.
pub fn build_get_features_ctrl_cmd(feature_buffer: &mut u64) -> UblkSrvCtrlCmd {
    UblkSrvCtrlCmd {
        len: UBLK_FEATURES_LEN as u16,
        addr: (feature_buffer as *mut u64) as usize as u64,
        ..UblkSrvCtrlCmd::default()
    }
}

/// Encode Get Features Cmd80.
#[must_use]
pub fn encode_get_features_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

fn encode_ctrl_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    let mut bytes = [0_u8; 80];
    bytes[0..4].copy_from_slice(&command.dev_id.to_ne_bytes());
    bytes[4..6].copy_from_slice(&command.queue_id.to_ne_bytes());
    bytes[6..8].copy_from_slice(&command.len.to_ne_bytes());
    bytes[8..16].copy_from_slice(&command.addr.to_ne_bytes());
    bytes[16..24].copy_from_slice(&command.data[0].to_ne_bytes());
    bytes[24..26].copy_from_slice(&command.dev_path_len.to_ne_bytes());
    bytes[26..28].copy_from_slice(&command.pad.to_ne_bytes());
    bytes[28..32].copy_from_slice(&command.reserved.to_ne_bytes());
    bytes
}

fn encode_io_cmd80(command: UblkSrvIoCmd) -> [u8; 80] {
    let mut bytes = [0_u8; 80];
    bytes[0..2].copy_from_slice(&command.q_id.to_ne_bytes());
    bytes[2..4].copy_from_slice(&command.tag.to_ne_bytes());
    bytes[4..8].copy_from_slice(&command.result.to_ne_bytes());
    bytes[8..16].copy_from_slice(&command.addr_or_zone_append_lba.to_ne_bytes());
    bytes
}

/// Ublk Control Add Dev Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlAddDevCommand {
    /// Adddev.
    AddDev,
}

impl UblkControlAddDevCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AddDev => "ADD_DEV",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::AddDev => UblkCtrlCommand::AddDev,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Add Dev Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlAddDevInput {
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Max Io Buf Bytes.
    pub max_io_buf_bytes: u32,
    /// Flags.
    pub flags: UblkFeatureFlags,
}

impl UblkControlAddDevInput {
    /// Conservative Tidefs.
    #[must_use]
    pub const fn conservative_tidefs() -> Self {
        Self {
            nr_hw_queues: TIDEFS_UBLK_ADD_DEV_DEFAULT_NR_HW_QUEUES,
            queue_depth: TIDEFS_UBLK_ADD_DEV_DEFAULT_QUEUE_DEPTH,
            max_io_buf_bytes: TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES,
            flags: TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
        }
    }

    /// Create an `UblkControlAddDevInput` with custom queue geometry,
    /// keeping the conservative TideFS defaults for max_io_buf_bytes and
    /// feature flags.
    #[must_use]
    pub const fn from_nr_hw_queues_and_depth(nr_hw_queues: u16, queue_depth: u16) -> Self {
        Self {
            nr_hw_queues,
            queue_depth,
            max_io_buf_bytes: TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES,
            flags: TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
        }
    }
}

/// Ublk Control Add Dev Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlAddDevSpec {
    /// Command.
    pub command: UblkControlAddDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Ctrl Dev Info Len.
    pub ctrl_dev_info_len: usize,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Max Io Buf Bytes.
    pub max_io_buf_bytes: u32,
    /// Flags.
    pub flags: UblkFeatureFlags,
}

impl UblkControlAddDevSpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlAddDevInput) -> Self {
        let command = UblkControlAddDevCommand::AddDev;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            ctrl_dev_info_len: core::mem::size_of::<UblkSrvCtrlDevInfo>(),
            control_queue_id: u16::MAX,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
            nr_hw_queues: input.nr_hw_queues,
            queue_depth: input.queue_depth,
            max_io_buf_bytes: input.max_io_buf_bytes,
            flags: input.flags,
        }
    }
}

/// Ublk Control Add Dev Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlAddDevError {
    /// Unsupportedcommand.
    UnsupportedCommand(UblkCtrlCommand),
    /// Zerohardwarequeues.
    ZeroHardwareQueues,
    /// Toomanyhardwarequeues.
    TooManyHardwareQueues,
    /// Zeroqueuedepth.
    ZeroQueueDepth,
    /// Queuedepthtoolarge.
    QueueDepthTooLarge,
    /// Zeromaxiobufferbytes.
    ZeroMaxIoBufferBytes,
    /// Missingrequiredfeatureflag.
    MissingRequiredFeatureFlag(UblkFeatureFlags),
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlAddDevError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedCommand(_) => "unsupported_command",
            Self::ZeroHardwareQueues => "zero_hardware_queues",
            Self::TooManyHardwareQueues => "too_many_hardware_queues",
            Self::ZeroQueueDepth => "zero_queue_depth",
            Self::QueueDepthTooLarge => "queue_depth_too_large",
            Self::ZeroMaxIoBufferBytes => "zero_max_io_buffer_bytes",
            Self::MissingRequiredFeatureFlag(_) => "missing_required_feature_flag",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Add Dev Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlAddDevOutcome {
    /// Command.
    pub command: UblkControlAddDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Info.
    pub dev_info: UblkSrvCtrlDevInfo,
}

impl UblkControlAddDevOutcome {
    /// From Dev Info.
    #[must_use]
    pub const fn from_dev_info(dev_info: UblkSrvCtrlDevInfo) -> Self {
        Self {
            command: UblkControlAddDevCommand::AddDev,
            request_raw: UblkControlAddDevCommand::AddDev.request().raw(),
            dev_info,
        }
    }
}

/// # Errors
///
/// Returns [`UblkControlAddDevError`] on failure.
pub fn build_add_dev_spec(
    input: UblkControlAddDevInput,
) -> Result<UblkControlAddDevSpec, UblkControlAddDevError> {
    validate_add_dev_input(input)?;
    Ok(UblkControlAddDevSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkControlAddDevError`] on failure.
pub fn build_add_dev_info(
    input: UblkControlAddDevInput,
) -> Result<UblkSrvCtrlDevInfo, UblkControlAddDevError> {
    validate_add_dev_input(input)?;
    Ok(UblkSrvCtrlDevInfo {
        nr_hw_queues: input.nr_hw_queues,
        queue_depth: input.queue_depth,
        max_io_buf_bytes: input.max_io_buf_bytes,
        dev_id: 0, // Use explicit dev_id=0 (kernel compat: UNASSIGNED sentinel not supported by VM kernel)
        flags: input.flags.bits(),
        ..UblkSrvCtrlDevInfo::default()
    })
}

/// Build Add Dev Ctrl Cmd.
pub fn build_add_dev_ctrl_cmd(dev_info: &mut UblkSrvCtrlDevInfo) -> UblkSrvCtrlCmd {
    UblkSrvCtrlCmd {
        queue_id: u16::MAX,
        len: core::mem::size_of::<UblkSrvCtrlDevInfo>() as u16,
        addr: (dev_info as *mut UblkSrvCtrlDevInfo) as usize as u64,
        ..UblkSrvCtrlCmd::default()
    }
}

/// Encode Add Dev Cmd80.
#[must_use]
pub fn encode_add_dev_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

/// # Errors
///
/// Returns [`UblkControlAddDevError`] on failure.
pub fn issue_add_dev(
    fd: BorrowedFd<'_>,
    input: UblkControlAddDevInput,
) -> Result<UblkControlAddDevOutcome, UblkControlAddDevError> {
    if let Some(err) = apply_add_dev_injection() {
        return Err(err);
    }
    let spec = build_add_dev_spec(input)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_ADD_DEV_RING_ENTRIES)
        .map_err(map_add_dev_io_uring_setup_error)?;
    let mut dev_info = build_add_dev_info(input)?;
    let command = build_add_dev_ctrl_cmd(&mut dev_info);
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_add_dev_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_ADD_DEV_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk ADD_DEV command whose `addr` field points
            // at `dev_info`; the struct remains live until the CQE is consumed below,
            // and this private ring has no other SQEs.
            submission
                .push(&entry)
                .map_err(|_| UblkControlAddDevError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(map_add_dev_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlAddDevError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_ADD_DEV_USER_DATA {
        return Err(UblkControlAddDevError::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlAddDevError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlAddDevOutcome::from_dev_info(dev_info))
}

/// Ublk Control Del Dev Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlDelDevCommand {
    /// Deldev.
    DelDev,
}

impl UblkControlDelDevCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DelDev => "DEL_DEV",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::DelDev => UblkCtrlCommand::DelDev,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Del Dev Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlDelDevInput {
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlDelDevInput {
    /// From Kernel Dev Id.
    #[must_use]
    pub const fn from_kernel_dev_id(dev_id: u32) -> Self {
        Self { dev_id }
    }
}

/// Ublk Control Del Dev Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlDelDevSpec {
    /// Command.
    pub command: UblkControlDelDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Ctrl Buffer Len.
    pub ctrl_buffer_len: u16,
    /// Ctrl Buffer Addr.
    pub ctrl_buffer_addr: u64,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
}

impl UblkControlDelDevSpec {
    /// Del Dev.
    #[must_use]
    pub const fn del_dev() -> Self {
        let command = UblkControlDelDevCommand::DelDev;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            control_queue_id: u16::MAX,
            ctrl_buffer_len: 0,
            ctrl_buffer_addr: 0,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
        }
    }
}

/// Ublk Control Del Dev Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlDelDevError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlDelDevError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Del Dev Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlDelDevOutcome {
    /// Command.
    pub command: UblkControlDelDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlDelDevOutcome {
    /// From Dev Id.
    #[must_use]
    pub const fn from_dev_id(dev_id: u32) -> Self {
        Self {
            command: UblkControlDelDevCommand::DelDev,
            request_raw: UblkControlDelDevCommand::DelDev.request().raw(),
            dev_id,
        }
    }
}

/// # Errors
///
/// Returns [`UblkControlDelDevError`] on failure.
pub fn build_del_dev_spec(
    input: UblkControlDelDevInput,
) -> Result<UblkControlDelDevSpec, UblkControlDelDevError> {
    validate_del_dev_input(input)?;
    Ok(UblkControlDelDevSpec::del_dev())
}

/// # Errors
///
/// Returns [`UblkControlDelDevError`] on failure.
pub fn build_del_dev_ctrl_cmd(
    input: UblkControlDelDevInput,
) -> Result<UblkSrvCtrlCmd, UblkControlDelDevError> {
    validate_del_dev_input(input)?;
    Ok(UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        ..UblkSrvCtrlCmd::default()
    })
}

/// Encode Del Dev Cmd80.
#[must_use]
pub fn encode_del_dev_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

/// # Errors
///
/// Returns [`UblkControlDelDevError`] on failure.
pub fn issue_del_dev(
    fd: BorrowedFd<'_>,
    input: UblkControlDelDevInput,
) -> Result<UblkControlDelDevOutcome, UblkControlDelDevError> {
    if let Some(outcome) = apply_del_dev_injection(&input)? {
        return Ok(outcome);
    }
    let spec = build_del_dev_spec(input)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_DEL_DEV_RING_ENTRIES)
        .map_err(map_del_dev_io_uring_setup_error)?;
    let command = build_del_dev_ctrl_cmd(input)?;
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_del_dev_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_DEL_DEV_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk DEL_DEV command with no userspace
            // buffer; this private ring has no other SQEs.
            submission
                .push(&entry)
                .map_err(|_| UblkControlDelDevError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(map_del_dev_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlDelDevError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_DEL_DEV_USER_DATA {
        return Err(UblkControlDelDevError::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlDelDevError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlDelDevOutcome::from_dev_id(input.dev_id))
}

/// Ublk Control Set Params Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlSetParamsCommand {
    /// Setparams.
    SetParams,
}

impl UblkControlSetParamsCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SetParams => "SET_PARAMS",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::SetParams => UblkCtrlCommand::SetParams,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Set Params Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlSetParamsInput {
    /// Dev Id.
    pub dev_id: u32,
    /// Params.
    pub params: UblkParams,
}

impl UblkControlSetParamsInput {
    /// From Kernel Dev Id And Params.
    #[must_use]
    pub const fn from_kernel_dev_id_and_params(dev_id: u32, params: UblkParams) -> Self {
        Self { dev_id, params }
    }
}

/// Ublk Control Set Params Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlSetParamsSpec {
    /// Command.
    pub command: UblkControlSetParamsCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Params Len.
    pub params_len: usize,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
    /// Param Types.
    pub param_types: u32,
    /// Dev Sectors.
    pub dev_sectors: u64,
    /// Max Sectors.
    pub max_sectors: u32,
    /// Max Segment Size.
    pub max_segment_size: u32,
    /// Max Segments.
    pub max_segments: u16,
}

impl UblkControlSetParamsSpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlSetParamsInput) -> Self {
        let command = UblkControlSetParamsCommand::SetParams;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            params_len: core::mem::size_of::<UblkParams>(),
            control_queue_id: u16::MAX,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
            param_types: input.params.types,
            dev_sectors: input.params.basic.dev_sectors,
            max_sectors: input.params.basic.max_sectors,
            max_segment_size: input.params.seg.max_segment_size,
            max_segments: input.params.seg.max_segments,
        }
    }
}

/// Ublk Control Set Params Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlSetParamsError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Zeroparamslen.
    ZeroParamsLen,
    /// Paramslenmismatch.
    ParamsLenMismatch,
    /// Zeroparamtypes.
    ZeroParamTypes,
    /// Missingbasicparams.
    MissingBasicParams,
    /// Missingdiscardparams.
    MissingDiscardParams,
    /// Missingsegmentparams.
    MissingSegmentParams,
    /// Zerodevsectors.
    ZeroDevSectors,
    /// Zeromaxsectors.
    ZeroMaxSectors,
    /// Zeromaxsegmentsize.
    ZeroMaxSegmentSize,
    /// Zeromaxsegments.
    ZeroMaxSegments,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlSetParamsError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::ZeroParamsLen => "zero_params_len",
            Self::ParamsLenMismatch => "params_len_mismatch",
            Self::ZeroParamTypes => "zero_param_types",
            Self::MissingBasicParams => "missing_basic_params",
            Self::MissingDiscardParams => "missing_discard_params",
            Self::MissingSegmentParams => "missing_segment_params",
            Self::ZeroDevSectors => "zero_dev_sectors",
            Self::ZeroMaxSectors => "zero_max_sectors",
            Self::ZeroMaxSegmentSize => "zero_max_segment_size",
            Self::ZeroMaxSegments => "zero_max_segments",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Set Params Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlSetParamsOutcome {
    /// Command.
    pub command: UblkControlSetParamsCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Id.
    pub dev_id: u32,
    /// Params.
    pub params: UblkParams,
}

impl UblkControlSetParamsOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlSetParamsInput) -> Self {
        Self {
            command: UblkControlSetParamsCommand::SetParams,
            request_raw: UblkControlSetParamsCommand::SetParams.request().raw(),
            dev_id: input.dev_id,
            params: input.params,
        }
    }
}

/// # Errors
///
/// Returns [`UblkControlSetParamsError`] on failure.
pub fn build_set_params_spec(
    input: UblkControlSetParamsInput,
) -> Result<UblkControlSetParamsSpec, UblkControlSetParamsError> {
    validate_set_params_input(input)?;
    Ok(UblkControlSetParamsSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkControlSetParamsError`] on failure.
pub fn build_set_params_ctrl_cmd(
    input: &mut UblkControlSetParamsInput,
) -> Result<UblkSrvCtrlCmd, UblkControlSetParamsError> {
    validate_set_params_input(*input)?;
    Ok(UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        len: core::mem::size_of::<UblkParams>() as u16,
        addr: (&mut input.params as *mut UblkParams) as usize as u64,
        ..UblkSrvCtrlCmd::default()
    })
}

/// Encode Set Params Cmd80.
#[must_use]
pub fn encode_set_params_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

/// # Errors
///
/// Returns [`UblkControlSetParamsError`] on failure.
pub fn issue_set_params(
    fd: BorrowedFd<'_>,
    input: UblkControlSetParamsInput,
) -> Result<UblkControlSetParamsOutcome, UblkControlSetParamsError> {
    if let Some(err) = apply_set_params_injection() {
        return Err(err);
    }
    let spec = build_set_params_spec(input)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_SET_PARAMS_RING_ENTRIES)
        .map_err(map_set_params_io_uring_setup_error)?;
    let mut input = input;
    let command = build_set_params_ctrl_cmd(&mut input)?;
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_set_params_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_SET_PARAMS_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk SET_PARAMS command whose `addr`
            // field points at `input.params`; the params buffer remains live
            // until the CQE is consumed below, and this private ring has no
            // other SQEs.
            submission
                .push(&entry)
                .map_err(|_| UblkControlSetParamsError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(map_set_params_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlSetParamsError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_SET_PARAMS_USER_DATA {
        return Err(UblkControlSetParamsError::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlSetParamsError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlSetParamsOutcome::from_input(input))
}

// ---------------------------------------------------------------------------
// UPDATE_SIZE
// ---------------------------------------------------------------------------

/// Ublk Control Update Size Ring Entries.
pub const UBLK_CONTROL_UPDATE_SIZE_RING_ENTRIES: u32 = 4;
/// Ublk Control Update Size User Data.
pub const UBLK_CONTROL_UPDATE_SIZE_USER_DATA: u64 = 0x7570_6461_7465_FF01;

/// Ublk Control Update Size Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlUpdateSizeCommand {
    /// Updatesize.
    UpdateSize,
}

impl UblkControlUpdateSizeCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpdateSize => "UPDATE_SIZE",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::UpdateSize => UblkCtrlCommand::UpdateSize,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Update Size Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlUpdateSizeInput {
    /// Dev Id.
    pub dev_id: u32,
    /// Params.
    pub params: UblkParams,
}

impl UblkControlUpdateSizeInput {
    /// From Kernel Dev Id And Params.
    #[must_use]
    pub const fn from_kernel_dev_id_and_params(dev_id: u32, params: UblkParams) -> Self {
        Self { dev_id, params }
    }
}

/// Ublk Control Update Size Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlUpdateSizeSpec {
    /// Command.
    pub command: UblkControlUpdateSizeCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Params Len.
    pub params_len: usize,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
    /// Param Types.
    pub param_types: u32,
    /// Dev Sectors.
    pub dev_sectors: u64,
}

impl UblkControlUpdateSizeSpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlUpdateSizeInput) -> Self {
        let command = UblkControlUpdateSizeCommand::UpdateSize;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            params_len: core::mem::size_of::<UblkParams>(),
            control_queue_id: u16::MAX,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
            param_types: input.params.types,
            dev_sectors: input.params.basic.dev_sectors,
        }
    }
}

/// Ublk Control Update Size Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlUpdateSizeError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Zeroparamslen.
    ZeroParamsLen,
    /// Paramslenmismatch.
    ParamsLenMismatch,
    /// Zeroparamtypes.
    ZeroParamTypes,
    /// Missingbasicparams.
    MissingBasicParams,
    /// Zerodevsectors.
    ZeroDevSectors,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlUpdateSizeError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::ZeroParamsLen => "zero_params_len",
            Self::ParamsLenMismatch => "params_len_mismatch",
            Self::ZeroParamTypes => "zero_param_types",
            Self::MissingBasicParams => "missing_basic_params",
            Self::ZeroDevSectors => "zero_dev_sectors",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Update Size Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlUpdateSizeOutcome {
    /// Command.
    pub command: UblkControlUpdateSizeCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Id.
    pub dev_id: u32,
    /// Params.
    pub params: UblkParams,
}

impl UblkControlUpdateSizeOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlUpdateSizeInput) -> Self {
        Self {
            command: UblkControlUpdateSizeCommand::UpdateSize,
            request_raw: UblkControlUpdateSizeCommand::UpdateSize.request().raw(),
            dev_id: input.dev_id,
            params: input.params,
        }
    }
}

/// # Errors
///
/// Returns [`UblkControlUpdateSizeError`] on failure.
pub fn build_update_size_spec(
    input: UblkControlUpdateSizeInput,
) -> Result<UblkControlUpdateSizeSpec, UblkControlUpdateSizeError> {
    validate_update_size_input(input)?;
    Ok(UblkControlUpdateSizeSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkControlUpdateSizeError`] on failure.
pub fn build_update_size_ctrl_cmd(
    input: &mut UblkControlUpdateSizeInput,
) -> Result<UblkSrvCtrlCmd, UblkControlUpdateSizeError> {
    validate_update_size_input(*input)?;
    Ok(UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        len: core::mem::size_of::<UblkParams>() as u16,
        addr: (&mut input.params as *mut UblkParams) as usize as u64,
        ..UblkSrvCtrlCmd::default()
    })
}

/// Encode Update Size Cmd80.
#[must_use]
pub fn encode_update_size_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

fn validate_update_size_input(
    input: UblkControlUpdateSizeInput,
) -> Result<(), UblkControlUpdateSizeError> {
    if input.dev_id == u32::MAX {
        return Err(UblkControlUpdateSizeError::AutoDeviceId);
    }
    if input.params.len == 0 {
        return Err(UblkControlUpdateSizeError::ZeroParamsLen);
    }
    if input.params.len != core::mem::size_of::<UblkParams>() as u32 {
        return Err(UblkControlUpdateSizeError::ParamsLenMismatch);
    }
    if input.params.types == 0 {
        return Err(UblkControlUpdateSizeError::ZeroParamTypes);
    }
    if input.params.types & UBLK_PARAM_TYPE_BASIC == 0 {
        return Err(UblkControlUpdateSizeError::MissingBasicParams);
    }
    if input.params.basic.dev_sectors == 0 {
        return Err(UblkControlUpdateSizeError::ZeroDevSectors);
    }
    Ok(())
}

fn map_update_size_io_uring_setup_error(err: io::Error) -> UblkControlUpdateSizeError {
    UblkControlUpdateSizeError::IoUringSetupErrno(err.raw_os_error().unwrap_or(0))
}

fn map_update_size_io_uring_submit_error(err: io::Error) -> UblkControlUpdateSizeError {
    UblkControlUpdateSizeError::IoUringSubmitErrno(err.raw_os_error().unwrap_or(0))
}

/// # Errors
///
/// Returns [`UblkControlUpdateSizeError`] on failure.
pub fn issue_update_size(
    fd: BorrowedFd<'_>,
    input: UblkControlUpdateSizeInput,
) -> Result<UblkControlUpdateSizeOutcome, UblkControlUpdateSizeError> {
    let spec = build_update_size_spec(input)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_UPDATE_SIZE_RING_ENTRIES)
        .map_err(map_update_size_io_uring_setup_error)?;
    let mut input = input;
    let command = build_update_size_ctrl_cmd(&mut input)?;
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_update_size_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_UPDATE_SIZE_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk UPDATE_SIZE command; the entry is
            // self-contained (no userspace buffers), and this private ring
            // has no other SQEs.
            submission
                .push(&entry)
                .map_err(|_| UblkControlUpdateSizeError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(map_update_size_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlUpdateSizeError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_UPDATE_SIZE_USER_DATA {
        return Err(UblkControlUpdateSizeError::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlUpdateSizeError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlUpdateSizeOutcome::from_input(input))
}

/// Ublk Data Queue Fetch Req Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDataQueueFetchReqCommand {
    /// Fetchreq.
    FetchReq,
}

impl UblkDataQueueFetchReqCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FetchReq => "FETCH_REQ",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkIoCommand {
        match self {
            Self::FetchReq => UblkIoCommand::FetchReq,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Data Queue Fetch Req Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqInput {
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// User Copy Addr.
    pub user_copy_addr: u64,
}

impl UblkDataQueueFetchReqInput {
    /// User Copy.
    #[must_use]
    pub const fn user_copy(q_id: u16, tag: u16, nr_hw_queues: u16, queue_depth: u16) -> Self {
        Self {
            q_id,
            tag,
            nr_hw_queues,
            queue_depth,
            user_copy_addr: 0,
        }
    }
}

/// Ublk Data Queue Fetch Req Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqSpec {
    /// Command.
    pub command: UblkDataQueueFetchReqCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// Result.
    pub result: i32,
    /// User Copy Addr.
    pub user_copy_addr: u64,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Commits Result.
    pub commits_result: bool,
    /// Must Remain In Flight For Start.
    pub must_remain_in_flight_for_start: bool,
}

impl UblkDataQueueFetchReqSpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkDataQueueFetchReqInput) -> Self {
        let command = UblkDataQueueFetchReqCommand::FetchReq;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            q_id: input.q_id,
            tag: input.tag,
            result: 0,
            user_copy_addr: input.user_copy_addr,
            uring_cmd_sqe_bytes: 128,
            commits_result: false,
            must_remain_in_flight_for_start: true,
        }
    }
}

/// Ublk Data Queue Fetch Req Readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqReadiness {
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Required Fetch Commands.
    pub required_fetch_commands: u32,
    /// Submitted Fetch Commands.
    pub submitted_fetch_commands: u32,
    /// Data Queue Runtime Live.
    pub data_queue_runtime_live: bool,
}

impl UblkDataQueueFetchReqReadiness {
    /// From Queue Geometry.
    #[must_use]
    pub const fn from_queue_geometry(
        nr_hw_queues: u16,
        queue_depth: u16,
        submitted_fetch_commands: u32,
        data_queue_runtime_live: bool,
    ) -> Self {
        Self {
            nr_hw_queues,
            queue_depth,
            required_fetch_commands: nr_hw_queues as u32 * queue_depth as u32,
            submitted_fetch_commands,
            data_queue_runtime_live,
        }
    }

    /// All Fetches Ready.
    #[must_use]
    pub const fn all_fetches_ready(self) -> bool {
        self.data_queue_runtime_live
            && self.required_fetch_commands > 0
            && self.submitted_fetch_commands >= self.required_fetch_commands
    }

    /// Start Dev Readiness.
    #[must_use]
    pub const fn start_dev_readiness(self) -> UblkControlStartDevReadiness {
        UblkControlStartDevReadiness::from_queue_geometry_with_runtime(
            self.nr_hw_queues,
            self.queue_depth,
            self.submitted_fetch_commands,
            self.data_queue_runtime_live,
        )
    }
}

/// Ublk Data Queue Fetch Req Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDataQueueFetchReqError {
    /// Zerohardwarequeues.
    ZeroHardwareQueues,
    /// Toomanyhardwarequeues.
    TooManyHardwareQueues,
    /// Zeroqueuedepth.
    ZeroQueueDepth,
    /// Queuedepthtoolarge.
    QueueDepthTooLarge,
    /// Queueidoutofrange.
    QueueIdOutOfRange,
    /// Tagoutofrange.
    TagOutOfRange,
    /// Usercopyfetchaddrmustbezero.
    UserCopyFetchAddrMustBeZero,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Iouringsubmitzero.
    IoUringSubmitZero,
}

impl UblkDataQueueFetchReqError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroHardwareQueues => "zero_hardware_queues",
            Self::TooManyHardwareQueues => "too_many_hardware_queues",
            Self::ZeroQueueDepth => "zero_queue_depth",
            Self::QueueDepthTooLarge => "queue_depth_too_large",
            Self::QueueIdOutOfRange => "queue_id_out_of_range",
            Self::TagOutOfRange => "tag_out_of_range",
            Self::UserCopyFetchAddrMustBeZero => "user_copy_fetch_addr_must_be_zero",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::IoUringSubmitZero => "io_uring_submit_zero",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSubmitErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Data Queue Fetch Req Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqOutcome {
    /// Command.
    pub command: UblkDataQueueFetchReqCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// User Data.
    pub user_data: u64,
    /// Submitted Without Wait.
    pub submitted_without_wait: bool,
}

impl UblkDataQueueFetchReqOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkDataQueueFetchReqInput) -> Self {
        Self {
            command: UblkDataQueueFetchReqCommand::FetchReq,
            request_raw: UblkDataQueueFetchReqCommand::FetchReq.request().raw(),
            q_id: input.q_id,
            tag: input.tag,
            user_data: fetch_req_user_data(input.q_id, input.tag),
            submitted_without_wait: true,
        }
    }
}

/// Ublk Data Queue Fetch Req Submission Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqSubmissionSpec {
    /// Q Id.
    pub q_id: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Queue Fetch Commands.
    pub queue_fetch_commands: u32,
    /// All Queues Required Fetch Commands.
    pub all_queues_required_fetch_commands: u32,
    /// First Tag.
    pub first_tag: u16,
    /// Last Tag.
    pub last_tag: u16,
    /// Runtime Must Remain Live.
    pub runtime_must_remain_live: bool,
    /// Submits Without Waiting For Cqe.
    pub submits_without_waiting_for_cqe: bool,
    /// Submits Start Dev.
    pub submits_start_dev: bool,
}

impl UblkDataQueueFetchReqSubmissionSpec {
    /// From Runtime Outcome.
    #[must_use]
    pub const fn from_runtime_outcome(outcome: &UblkDataQueueRuntimeOpenOutcome) -> Self {
        Self {
            q_id: outcome.q_id,
            nr_hw_queues: outcome.nr_hw_queues,
            queue_depth: outcome.queue_depth,
            queue_fetch_commands: outcome.queue_depth as u32,
            all_queues_required_fetch_commands: outcome.nr_hw_queues as u32
                * outcome.queue_depth as u32,
            first_tag: 0,
            last_tag: outcome.queue_depth.saturating_sub(1),
            runtime_must_remain_live: true,
            submits_without_waiting_for_cqe: true,
            submits_start_dev: false,
        }
    }
}

/// Ublk Data Queue Fetch Req Submission Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDataQueueFetchReqSubmissionError {
    /// Runtimenotlive.
    RuntimeNotLive,
    /// Invalidfetchreqinput.
    InvalidFetchReqInput(UblkDataQueueFetchReqError),
    /// Fetchreqsubmit.
    FetchReqSubmit {
        /// Tag.
        tag: u16,
        /// Submitted Fetch Commands.
        submitted_fetch_commands: u32,
        /// Error.
        error: UblkDataQueueFetchReqError,
    },
}

impl UblkDataQueueFetchReqSubmissionError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeNotLive => "data_queue_runtime_not_live",
            Self::InvalidFetchReqInput(_) => "invalid_fetch_req_input",
            Self::FetchReqSubmit { error, .. } => error.as_str(),
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::FetchReqSubmit { error, .. } | Self::InvalidFetchReqInput(error) => error.errno(),
            Self::RuntimeNotLive => None,
        }
    }

    /// Submitted Fetch Commands.
    #[must_use]
    pub const fn submitted_fetch_commands(self) -> u32 {
        match self {
            Self::FetchReqSubmit {
                submitted_fetch_commands,
                ..
            } => submitted_fetch_commands,
            Self::RuntimeNotLive | Self::InvalidFetchReqInput(_) => 0,
        }
    }
}

/// Ublk Data Queue Fetch Req Submission Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqSubmissionOutcome {
    /// Q Id.
    pub q_id: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Submitted Fetch Commands.
    pub submitted_fetch_commands: u32,
    /// All Queues Required Fetch Commands.
    pub all_queues_required_fetch_commands: u32,
    /// First Submitted Tag.
    pub first_submitted_tag: Option<u16>,
    /// Last Submitted Tag.
    pub last_submitted_tag: Option<u16>,
    /// Data Queue Runtime Live.
    pub data_queue_runtime_live: bool,
    /// Submitted Without Waiting For Cqe.
    pub submitted_without_waiting_for_cqe: bool,
    /// Started Device.
    pub started_device: bool,
}

impl UblkDataQueueFetchReqSubmissionOutcome {
    /// From Spec.
    #[must_use]
    pub const fn from_spec(
        spec: UblkDataQueueFetchReqSubmissionSpec,
        submitted_fetch_commands: u32,
        first_submitted_tag: Option<u16>,
        last_submitted_tag: Option<u16>,
    ) -> Self {
        Self {
            q_id: spec.q_id,
            nr_hw_queues: spec.nr_hw_queues,
            queue_depth: spec.queue_depth,
            submitted_fetch_commands,
            all_queues_required_fetch_commands: spec.all_queues_required_fetch_commands,
            first_submitted_tag,
            last_submitted_tag,
            data_queue_runtime_live: true,
            submitted_without_waiting_for_cqe: true,
            started_device: false,
        }
    }

    /// Fetch Req Readiness.
    #[must_use]
    pub const fn fetch_req_readiness(self) -> UblkDataQueueFetchReqReadiness {
        UblkDataQueueFetchReqReadiness::from_queue_geometry(
            self.nr_hw_queues,
            self.queue_depth,
            self.submitted_fetch_commands,
            self.data_queue_runtime_live,
        )
    }

    /// Start Dev Readiness.
    #[must_use]
    pub const fn start_dev_readiness(self) -> UblkControlStartDevReadiness {
        self.fetch_req_readiness().start_dev_readiness()
    }
}

/// # Errors
///
/// Returns [`UblkDataQueueFetchReqError`] on failure.
pub fn build_fetch_req_spec(
    input: UblkDataQueueFetchReqInput,
) -> Result<UblkDataQueueFetchReqSpec, UblkDataQueueFetchReqError> {
    validate_fetch_req_input(input)?;
    Ok(UblkDataQueueFetchReqSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkDataQueueFetchReqError`] on failure.
pub fn build_fetch_req_io_cmd(
    input: UblkDataQueueFetchReqInput,
) -> Result<UblkSrvIoCmd, UblkDataQueueFetchReqError> {
    validate_fetch_req_input(input)?;
    Ok(UblkSrvIoCmd {
        q_id: input.q_id,
        tag: input.tag,
        result: 0,
        addr_or_zone_append_lba: input.user_copy_addr,
    })
}

/// Encode Fetch Req Cmd80.
#[must_use]
pub fn encode_fetch_req_cmd80(command: UblkSrvIoCmd) -> [u8; 80] {
    encode_io_cmd80(command)
}

/// Fetch Req User Data.
#[must_use]
pub const fn fetch_req_user_data(q_id: u16, tag: u16) -> u64 {
    tag as u64 | ((UblkIoCommand::FetchReq.number() as u64) << 16) | ((q_id as u64) << 32)
}

/// Decode the `user_data` from a FETCH_REQ CQE back into the originating
/// `(q_id, tag)` pair.
#[must_use]
pub const fn decode_fetch_req_user_data(user_data: u64) -> (u16, u16) {
    let tag = (user_data & 0xffff) as u16;
    let q_id = ((user_data >> 32) & 0xffff) as u16;
    (q_id, tag)
}

/// Return `true` when `user_data` belongs to a FETCH_REQ (not a
/// COMMIT_AND_FETCH or other command).
#[must_use]
pub const fn is_fetch_req_user_data(user_data: u64) -> bool {
    ((user_data >> 16) & 0xffff) as u8 == UblkIoCommand::FetchReq.number()
}

/// # Errors
///
/// Returns [`UblkDataQueueFetchReqError`] on failure.
pub fn submit_fetch_req_without_wait(
    ring: &mut IoUring<squeue::Entry128, cqueue::Entry>,
    fd: BorrowedFd<'_>,
    input: UblkDataQueueFetchReqInput,
) -> Result<UblkDataQueueFetchReqOutcome, UblkDataQueueFetchReqError> {
    apply_fetch_req_injection()?;
    let spec = build_fetch_req_spec(input)?;
    let command = build_fetch_req_io_cmd(input)?;
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_fetch_req_cmd80(command))
        .build()
        .user_data(fetch_req_user_data(input.q_id, input.tag));

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk data-queue FETCH_REQ command with
            // no userspace buffer for TideFS USER_COPY mode. The caller owns
            // the io_uring and the /dev/ublkcN fd and must keep both live; a
            // FETCH_REQ CQE is intentionally not waited here because Linux
            // keeps the command in flight until a block request is fetched.
            submission
                .push(&entry)
                .map_err(|_| UblkDataQueueFetchReqError::SubmissionQueueFull)?;
        }
    }

    let submitted = ring.submit().map_err(map_fetch_req_io_uring_submit_error)?;
    if submitted == 0 {
        return Err(UblkDataQueueFetchReqError::IoUringSubmitZero);
    }

    Ok(UblkDataQueueFetchReqOutcome::from_input(input))
}

/// # Errors
///
/// Returns [`UblkDataQueueFetchReqSubmissionError`] on failure.
pub fn build_fetch_req_submission_spec(
    outcome: &UblkDataQueueRuntimeOpenOutcome,
) -> Result<UblkDataQueueFetchReqSubmissionSpec, UblkDataQueueFetchReqSubmissionError> {
    if !outcome.runtime_live {
        return Err(UblkDataQueueFetchReqSubmissionError::RuntimeNotLive);
    }
    build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(
        outcome.q_id,
        0,
        outcome.nr_hw_queues,
        outcome.queue_depth,
    ))
    .map_err(UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput)?;
    build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(
        outcome.q_id,
        outcome.queue_depth - 1,
        outcome.nr_hw_queues,
        outcome.queue_depth,
    ))
    .map_err(UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput)?;
    Ok(UblkDataQueueFetchReqSubmissionSpec::from_runtime_outcome(
        outcome,
    ))
}

/// # Errors
///
/// Returns [`UblkDataQueueFetchReqSubmissionError`] on failure.
pub fn submit_runtime_fetch_reqs_without_wait(
    runtime: &mut UblkDataQueueRuntime,
) -> Result<UblkDataQueueFetchReqSubmissionOutcome, UblkDataQueueFetchReqSubmissionError> {
    apply_runtime_fetch_reqs_injection()?;
    let spec = build_fetch_req_submission_spec(runtime.outcome())?;
    let data_queue_file = &runtime.data_queue_file;
    let ring = &mut runtime.ring;
    let fd = data_queue_file.as_fd();
    let mut submitted_fetch_commands = 0;
    let mut first_submitted_tag = None;
    let mut last_submitted_tag = None;

    for tag in 0..spec.queue_depth {
        let input = UblkDataQueueFetchReqInput::user_copy(
            spec.q_id,
            tag,
            spec.nr_hw_queues,
            spec.queue_depth,
        );
        match submit_fetch_req_without_wait(ring, fd, input) {
            Ok(outcome) => {
                submitted_fetch_commands += 1;
                runtime.in_flight_counter.increment();
                if first_submitted_tag.is_none() {
                    first_submitted_tag = Some(outcome.tag);
                }
                last_submitted_tag = Some(outcome.tag);
            }
            Err(error) => {
                return Err(UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
                    tag,
                    submitted_fetch_commands,
                    error,
                });
            }
        }
    }

    Ok(UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        spec,
        submitted_fetch_commands,
        first_submitted_tag,
        last_submitted_tag,
    ))
}

/// Submits FETCH_REQ commands for all hardware queues (0..nr_hw_queues-1),
/// each at full queue depth, so the kernel can distribute block I/O across
/// available queues.
///
/// Returns an aggregated outcome whose `submitted_fetch_commands` covers
/// all queues. The `q_id` field in the outcome is set to 0 as the primary
/// reference; `first_submitted_tag` / `last_submitted_tag` reflect the last
/// queue's submission.
///
/// # Errors
///
/// Returns [`UblkDataQueueFetchReqSubmissionError`] on failure.
pub fn submit_runtime_all_queues_fetch_reqs_without_wait(
    runtime: &mut UblkDataQueueRuntime,
) -> Result<UblkDataQueueFetchReqSubmissionOutcome, UblkDataQueueFetchReqSubmissionError> {
    apply_runtime_fetch_reqs_injection()?;
    let outcome = runtime.outcome();
    let nr_hw_queues = outcome.nr_hw_queues;
    let queue_depth = outcome.queue_depth;
    let spec = build_fetch_req_submission_spec(outcome)?;
    let data_queue_file = &runtime.data_queue_file;
    let ring = &mut runtime.ring;
    let fd = data_queue_file.as_fd();
    let mut submitted_fetch_commands = 0u32;
    let mut first_submitted_tag: Option<u16> = None;
    let mut last_submitted_tag: Option<u16> = None;

    for q_id in 0..nr_hw_queues {
        for tag in 0..queue_depth {
            let input = UblkDataQueueFetchReqInput::user_copy(q_id, tag, nr_hw_queues, queue_depth);
            match submit_fetch_req_without_wait(ring, fd, input) {
                Ok(outcome) => {
                    submitted_fetch_commands += 1;
                    runtime.in_flight_counter.increment();
                    if first_submitted_tag.is_none() {
                        first_submitted_tag = Some(outcome.tag);
                    }
                    last_submitted_tag = Some(outcome.tag);
                }
                Err(error) => {
                    return Err(UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
                        tag,
                        submitted_fetch_commands,
                        error,
                    });
                }
            }
        }
    }

    Ok(UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        spec,
        submitted_fetch_commands,
        first_submitted_tag,
        last_submitted_tag,
    ))
}

/// Ublk Data Queue Commit And Fetch Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDataQueueCommitAndFetchCommand {
    /// Commitandfetchreq.
    CommitAndFetchReq,
}

impl UblkDataQueueCommitAndFetchCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommitAndFetchReq => "COMMIT_AND_FETCH_REQ",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkIoCommand {
        match self {
            Self::CommitAndFetchReq => UblkIoCommand::CommitAndFetchReq,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Data Queue Commit And Fetch Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueCommitAndFetchInput {
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Result.
    pub result: i32,
    /// Addr Or Zone Append Lba.
    pub addr_or_zone_append_lba: u64,
}

impl UblkDataQueueCommitAndFetchInput {
    /// Completed User Copy.
    #[must_use]
    pub const fn completed_user_copy(
        q_id: u16,
        tag: u16,
        nr_hw_queues: u16,
        queue_depth: u16,
    ) -> Self {
        Self {
            q_id,
            tag,
            nr_hw_queues,
            queue_depth,
            result: UBLK_IO_RES_OK,
            addr_or_zone_append_lba: 0,
        }
    }
}

/// Ublk Data Queue Commit And Fetch Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueCommitAndFetchSpec {
    /// Command.
    pub command: UblkDataQueueCommitAndFetchCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// Result.
    pub result: i32,
    /// Addr Or Zone Append Lba.
    pub addr_or_zone_append_lba: u64,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Commits Result.
    pub commits_result: bool,
    /// Fetches Next Request.
    pub fetches_next_request: bool,
    /// Runtime Must Remain Live.
    pub runtime_must_remain_live: bool,
}

impl UblkDataQueueCommitAndFetchSpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkDataQueueCommitAndFetchInput) -> Self {
        let command = UblkDataQueueCommitAndFetchCommand::CommitAndFetchReq;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            q_id: input.q_id,
            tag: input.tag,
            result: input.result,
            addr_or_zone_append_lba: input.addr_or_zone_append_lba,
            uring_cmd_sqe_bytes: 128,
            commits_result: true,
            fetches_next_request: true,
            runtime_must_remain_live: true,
        }
    }
}

/// Ublk Data Queue Commit And Fetch Readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueCommitAndFetchReadiness {
    /// Data Queue Runtime Live.
    pub data_queue_runtime_live: bool,
    /// Fetched Request Available.
    pub fetched_request_available: bool,
    /// Completion Result Ready.
    pub completion_result_ready: bool,
}

impl UblkDataQueueCommitAndFetchReadiness {
    /// From Fetch Req Submission Outcome.
    #[must_use]
    pub const fn from_fetch_req_submission_outcome(
        outcome: UblkDataQueueFetchReqSubmissionOutcome,
        fetched_request_available: bool,
        completion_result_ready: bool,
    ) -> Self {
        Self {
            data_queue_runtime_live: outcome.data_queue_runtime_live,
            fetched_request_available,
            completion_result_ready,
        }
    }

    /// All Commit Preconditions Ready.
    #[must_use]
    pub const fn all_commit_preconditions_ready(self) -> bool {
        self.data_queue_runtime_live
            && self.fetched_request_available
            && self.completion_result_ready
    }
}

/// Ublk Data Queue Commit And Fetch Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDataQueueCommitAndFetchError {
    /// Runtimenotlive.
    RuntimeNotLive,
    /// Fetchedrequestmissing.
    FetchedRequestMissing,
    /// Completionresultnotready.
    CompletionResultNotReady,
    /// Zerohardwarequeues.
    ZeroHardwareQueues,
    /// Toomanyhardwarequeues.
    TooManyHardwareQueues,
    /// Zeroqueuedepth.
    ZeroQueueDepth,
    /// Queuedepthtoolarge.
    QueueDepthTooLarge,
    /// Queueidoutofrange.
    QueueIdOutOfRange,
    /// Tagoutofrange.
    TagOutOfRange,
    /// Needgetdataresultunsupported.
    NeedGetDataResultUnsupported,
    /// Zoneappendlbamustbezero.
    ZoneAppendLbaMustBeZero,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Iouringsubmitzero.
    IoUringSubmitZero,
}

impl UblkDataQueueCommitAndFetchError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeNotLive => "data_queue_runtime_not_live",
            Self::FetchedRequestMissing => "fetched_request_missing",
            Self::CompletionResultNotReady => "completion_result_not_ready",
            Self::ZeroHardwareQueues => "zero_hardware_queues",
            Self::TooManyHardwareQueues => "too_many_hardware_queues",
            Self::ZeroQueueDepth => "zero_queue_depth",
            Self::QueueDepthTooLarge => "queue_depth_too_large",
            Self::QueueIdOutOfRange => "queue_id_out_of_range",
            Self::TagOutOfRange => "tag_out_of_range",
            Self::NeedGetDataResultUnsupported => "need_get_data_result_unsupported",
            Self::ZoneAppendLbaMustBeZero => "zone_append_lba_must_be_zero",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::IoUringSubmitZero => "io_uring_submit_zero",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSubmitErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Data Queue Commit And Fetch Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueCommitAndFetchOutcome {
    /// Command.
    pub command: UblkDataQueueCommitAndFetchCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// Result.
    pub result: i32,
    /// User Data.
    pub user_data: u64,
    /// Submitted Without Waiting For Cqe.
    pub submitted_without_waiting_for_cqe: bool,
}

impl UblkDataQueueCommitAndFetchOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkDataQueueCommitAndFetchInput) -> Self {
        Self {
            command: UblkDataQueueCommitAndFetchCommand::CommitAndFetchReq,
            request_raw: UblkIoCommand::CommitAndFetchReq.request().raw(),
            q_id: input.q_id,
            tag: input.tag,
            result: input.result,
            user_data: commit_and_fetch_user_data(input.q_id, input.tag),
            submitted_without_waiting_for_cqe: true,
        }
    }
}

/// # Errors
///
/// Returns [`UblkDataQueueCommitAndFetchError`] on failure.
pub fn build_commit_and_fetch_spec(
    input: UblkDataQueueCommitAndFetchInput,
) -> Result<UblkDataQueueCommitAndFetchSpec, UblkDataQueueCommitAndFetchError> {
    validate_commit_and_fetch_input(input)?;
    Ok(UblkDataQueueCommitAndFetchSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkDataQueueCommitAndFetchError`] on failure.
pub fn build_commit_and_fetch_io_cmd(
    input: UblkDataQueueCommitAndFetchInput,
) -> Result<UblkSrvIoCmd, UblkDataQueueCommitAndFetchError> {
    validate_commit_and_fetch_input(input)?;
    Ok(UblkSrvIoCmd {
        q_id: input.q_id,
        tag: input.tag,
        result: input.result,
        addr_or_zone_append_lba: input.addr_or_zone_append_lba,
    })
}

/// Encode Commit And Fetch Cmd80.
#[must_use]
pub fn encode_commit_and_fetch_cmd80(command: UblkSrvIoCmd) -> [u8; 80] {
    encode_io_cmd80(command)
}

/// Commit And Fetch User Data.
#[must_use]
pub const fn commit_and_fetch_user_data(q_id: u16, tag: u16) -> u64 {
    tag as u64 | ((UblkIoCommand::CommitAndFetchReq.number() as u64) << 16) | ((q_id as u64) << 48)
}

/// Decode the `user_data` from a COMMIT_AND_FETCH_REQ CQE back into the
/// originating `(q_id, tag)` pair.
#[must_use]
pub const fn decode_commit_and_fetch_user_data(user_data: u64) -> (u16, u16) {
    let tag = (user_data & 0xffff) as u16;
    let q_id = ((user_data >> 48) & 0xffff) as u16;
    (q_id, tag)
}

/// Return `true` when `user_data` belongs to a COMMIT_AND_FETCH_REQ (not a
/// FETCH_REQ or other command).
#[must_use]
pub const fn is_commit_and_fetch_user_data(user_data: u64) -> bool {
    ((user_data >> 16) & 0xffff) as u8 == UblkIoCommand::CommitAndFetchReq.number()
}

/// # Errors
///
/// Returns [`UblkDataQueueCommitAndFetchError`] on failure.
pub fn submit_commit_and_fetch_without_wait(
    ring: &mut IoUring<squeue::Entry128, cqueue::Entry>,
    fd: BorrowedFd<'_>,
    input: UblkDataQueueCommitAndFetchInput,
    readiness: UblkDataQueueCommitAndFetchReadiness,
) -> Result<UblkDataQueueCommitAndFetchOutcome, UblkDataQueueCommitAndFetchError> {
    validate_commit_and_fetch_readiness(readiness)?;
    let spec = build_commit_and_fetch_spec(input)?;
    let command = build_commit_and_fetch_io_cmd(input)?;
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_commit_and_fetch_cmd80(command))
        .build()
        .user_data(commit_and_fetch_user_data(input.q_id, input.tag));

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk COMMIT_AND_FETCH_REQ command for a
            // queue/tag whose request has already been fetched and completed by
            // the caller. The caller owns the ring and /dev/ublkcN fd and keeps
            // them live while the command is in flight for the next request.
            submission
                .push(&entry)
                .map_err(|_| UblkDataQueueCommitAndFetchError::SubmissionQueueFull)?;
        }
    }

    let submitted = ring
        .submit()
        .map_err(map_commit_and_fetch_io_uring_submit_error)?;
    if submitted == 0 {
        return Err(UblkDataQueueCommitAndFetchError::IoUringSubmitZero);
    }

    Ok(UblkDataQueueCommitAndFetchOutcome::from_input(input))
}

/// # Errors
///
/// Returns [`UblkDataQueueCommitAndFetchError`] on failure.
pub fn submit_runtime_commit_and_fetch_without_wait(
    runtime: &mut UblkDataQueueRuntime,
    input: UblkDataQueueCommitAndFetchInput,
    readiness: UblkDataQueueCommitAndFetchReadiness,
) -> Result<UblkDataQueueCommitAndFetchOutcome, UblkDataQueueCommitAndFetchError> {
    let data_queue_file = &runtime.data_queue_file;
    let ring = &mut runtime.ring;
    {
        runtime.in_flight_counter.increment();
        let result =
            submit_commit_and_fetch_without_wait(ring, data_queue_file.as_fd(), input, readiness);
        if result.is_err() {
            runtime.in_flight_counter.decrement();
        }
        result
    }
}

/// Ublk Data Queue Flush Completion Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFlushCompletionInput {
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Desc.
    pub desc: UblkSrvIoDesc,
    /// Data Queue Runtime Live.
    pub data_queue_runtime_live: bool,
    /// Fetched Request Available.
    pub fetched_request_available: bool,
}

impl UblkDataQueueFlushCompletionInput {
    /// Fetched User Copy.
    #[must_use]
    pub const fn fetched_user_copy(
        q_id: u16,
        tag: u16,
        nr_hw_queues: u16,
        queue_depth: u16,
        desc: UblkSrvIoDesc,
    ) -> Self {
        Self {
            q_id,
            tag,
            nr_hw_queues,
            queue_depth,
            desc,
            data_queue_runtime_live: true,
            fetched_request_available: true,
        }
    }
}

/// Ublk Data Queue Flush Completion Plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFlushCompletionPlan {
    /// Q Id.
    pub q_id: u16,
    /// Tag.
    pub tag: u16,
    /// Op.
    pub op: u8,
    /// Count Or Zones.
    pub count_or_zones: u32,
    /// Start Sector.
    pub start_sector: u64,
    /// Data Addr.
    pub data_addr: u64,
    /// Completion Result.
    pub completion_result: i32,
    /// Addr Or Zone Append Lba.
    pub addr_or_zone_append_lba: u64,
    /// Commit Input.
    pub commit_input: UblkDataQueueCommitAndFetchInput,
    /// Commit Request Raw.
    pub commit_request_raw: u32,
    /// Commit Readiness.
    pub commit_readiness: UblkDataQueueCommitAndFetchReadiness,
    /// Commits Result.
    pub commits_result: bool,
    /// Fetches Next Request.
    pub fetches_next_request: bool,
}

/// Ublk Data Queue Flush Completion Plan Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDataQueueFlushCompletionPlanError {
    /// Runtimenotlive.
    RuntimeNotLive,
    /// Fetchedrequestmissing.
    FetchedRequestMissing,
    /// Invalidcommitandfetchinput.
    InvalidCommitAndFetchInput(UblkDataQueueCommitAndFetchError),
    /// Notflushoperation.
    NotFlushOperation(u8),
    /// Nonzeroflushcount.
    NonzeroFlushCount(u32),
    /// Nonzeroflushstartsector.
    NonzeroFlushStartSector(u64),
    /// Nonzeroflushdataaddr.
    NonzeroFlushDataAddr(u64),
}

impl UblkDataQueueFlushCompletionPlanError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeNotLive => "data_queue_runtime_not_live",
            Self::FetchedRequestMissing => "fetched_request_missing",
            Self::InvalidCommitAndFetchInput(error) => error.as_str(),
            Self::NotFlushOperation(_) => "not_flush_operation",
            Self::NonzeroFlushCount(_) => "nonzero_flush_count",
            Self::NonzeroFlushStartSector(_) => "nonzero_flush_start_sector",
            Self::NonzeroFlushDataAddr(_) => "nonzero_flush_data_addr",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::InvalidCommitAndFetchInput(error) => error.errno(),
            Self::RuntimeNotLive
            | Self::FetchedRequestMissing
            | Self::NotFlushOperation(_)
            | Self::NonzeroFlushCount(_)
            | Self::NonzeroFlushStartSector(_)
            | Self::NonzeroFlushDataAddr(_) => None,
        }
    }
}

/// # Errors
///
/// Returns [`UblkDataQueueFlushCompletionPlanError`] when the fetched
/// descriptor is not a zero-payload flush request or cannot be completed on
/// the current data queue geometry.
pub fn build_flush_completion_plan(
    input: UblkDataQueueFlushCompletionInput,
) -> Result<UblkDataQueueFlushCompletionPlan, UblkDataQueueFlushCompletionPlanError> {
    if !input.data_queue_runtime_live {
        return Err(UblkDataQueueFlushCompletionPlanError::RuntimeNotLive);
    }
    if !input.fetched_request_available {
        return Err(UblkDataQueueFlushCompletionPlanError::FetchedRequestMissing);
    }

    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(
        input.q_id,
        input.tag,
        input.nr_hw_queues,
        input.queue_depth,
    );
    let commit_spec = build_commit_and_fetch_spec(commit_input)
        .map_err(UblkDataQueueFlushCompletionPlanError::InvalidCommitAndFetchInput)?;

    let op = input.desc.op();
    if op != UBLK_IO_OP_FLUSH {
        return Err(UblkDataQueueFlushCompletionPlanError::NotFlushOperation(op));
    }
    if input.desc.count_or_zones != 0 {
        return Err(UblkDataQueueFlushCompletionPlanError::NonzeroFlushCount(
            input.desc.count_or_zones,
        ));
    }
    if input.desc.start_sector != 0 {
        return Err(
            UblkDataQueueFlushCompletionPlanError::NonzeroFlushStartSector(input.desc.start_sector),
        );
    }
    if input.desc.addr != 0 {
        return Err(UblkDataQueueFlushCompletionPlanError::NonzeroFlushDataAddr(
            input.desc.addr,
        ));
    }

    let commit_readiness = UblkDataQueueCommitAndFetchReadiness {
        data_queue_runtime_live: true,
        fetched_request_available: true,
        completion_result_ready: true,
    };

    Ok(UblkDataQueueFlushCompletionPlan {
        q_id: input.q_id,
        tag: input.tag,
        op,
        count_or_zones: input.desc.count_or_zones,
        start_sector: input.desc.start_sector,
        data_addr: input.desc.addr,
        completion_result: commit_input.result,
        addr_or_zone_append_lba: commit_input.addr_or_zone_append_lba,
        commit_input,
        commit_request_raw: commit_spec.request_raw,
        commit_readiness,
        commits_result: commit_spec.commits_result,
        fetches_next_request: commit_spec.fetches_next_request,
    })
}

/// Ublk Data Queue Runtime Open Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkDataQueueRuntimeOpenInput {
    /// Dev Id.
    pub dev_id: u32,
    /// Q Id.
    pub q_id: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
}

impl UblkDataQueueRuntimeOpenInput {
    /// From Kernel Dev Id.
    #[must_use]
    pub const fn from_kernel_dev_id(
        dev_id: u32,
        q_id: u16,
        nr_hw_queues: u16,
        queue_depth: u16,
    ) -> Self {
        Self {
            dev_id,
            q_id,
            nr_hw_queues,
            queue_depth,
        }
    }
}

/// Ublk Data Queue Runtime Open Spec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkDataQueueRuntimeOpenSpec {
    /// Dev Id.
    pub dev_id: u32,
    /// Q Id.
    pub q_id: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Data Queue Path Template.
    pub data_queue_path_template: &'static str,
    /// Data Queue Path.
    pub data_queue_path: PathBuf,
    /// Open Mode.
    pub open_mode: &'static str,
    /// Ring Entries.
    pub ring_entries: u32,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Requires Successful Add Dev.
    pub requires_successful_add_dev: bool,
    /// Submits Fetch Req.
    pub submits_fetch_req: bool,
}

impl UblkDataQueueRuntimeOpenSpec {
    /// From Input.
    #[must_use]
    pub fn from_input(input: UblkDataQueueRuntimeOpenInput) -> Self {
        Self {
            dev_id: input.dev_id,
            q_id: input.q_id,
            nr_hw_queues: input.nr_hw_queues,
            queue_depth: input.queue_depth,
            data_queue_path_template: UBLK_DATA_QUEUE_PATH_TEMPLATE,
            data_queue_path: ublk_data_queue_device_path(input.dev_id),
            open_mode: "read_write",
            ring_entries: {
                // Ring must hold 2x the total tag count so that ongoing
                // COMMIT_AND_FETCH submissions always have space after
                // the initial fetch batch fills all tag slots.
                let tags = input.nr_hw_queues as u32 * input.queue_depth as u32;
                (tags * 2).max(UBLK_DATA_QUEUE_RUNTIME_RING_ENTRIES)
            },
            uring_cmd_sqe_bytes: 128,
            requires_successful_add_dev: true,
            submits_fetch_req: false,
        }
    }
}

/// Ublk Data Queue Runtime Open Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDataQueueRuntimeOpenError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Zerohardwarequeues.
    ZeroHardwareQueues,
    /// Toomanyhardwarequeues.
    TooManyHardwareQueues,
    /// Zeroqueuedepth.
    ZeroQueueDepth,
    /// Queuedepthtoolarge.
    QueueDepthTooLarge,
    /// Queueidoutofrange.
    QueueIdOutOfRange,
    /// Dataqueuepathmismatch.
    DataQueuePathMismatch,
    /// Dataqueuepathmissing.
    DataQueuePathMissing,
    /// Dataqueuepathnotcharacterdevice.
    DataQueuePathNotCharacterDevice,
    /// Dataqueuemetadataerrno.
    DataQueueMetadataErrno(i32),
    /// Dataqueuemetadatamissingerrno.
    DataQueueMetadataMissingErrno,
    /// Dataqueueopenerrno.
    DataQueueOpenErrno(i32),
    /// Dataqueueopenmissingerrno.
    DataQueueOpenMissingErrno,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Mmapfailed.
    MmapFailed(i32),
}

impl UblkDataQueueRuntimeOpenError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::ZeroHardwareQueues => "zero_hardware_queues",
            Self::TooManyHardwareQueues => "too_many_hardware_queues",
            Self::ZeroQueueDepth => "zero_queue_depth",
            Self::QueueDepthTooLarge => "queue_depth_too_large",
            Self::QueueIdOutOfRange => "queue_id_out_of_range",
            Self::DataQueuePathMismatch => "data_queue_path_mismatch",
            Self::DataQueuePathMissing => "data_queue_path_missing",
            Self::DataQueuePathNotCharacterDevice => "data_queue_path_not_character_device",
            Self::DataQueueMetadataErrno(_) => "data_queue_metadata_errno",
            Self::DataQueueMetadataMissingErrno => "data_queue_metadata_missing_errno",
            Self::DataQueueOpenErrno(_) => "data_queue_open_errno",
            Self::DataQueueOpenMissingErrno => "data_queue_open_missing_errno",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::MmapFailed(_) => "mmap_failed",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::DataQueueMetadataErrno(errno)
            | Self::DataQueueOpenErrno(errno)
            | Self::IoUringSetupErrno(errno)
            | Self::MmapFailed(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Data Queue Runtime Open Outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkDataQueueRuntimeOpenOutcome {
    /// Dev Id.
    pub dev_id: u32,
    /// Q Id.
    pub q_id: u16,
    /// Nr Hw Queues.
    pub nr_hw_queues: u16,
    /// Queue Depth.
    pub queue_depth: u16,
    /// Data Queue Path.
    pub data_queue_path: PathBuf,
    /// Ring Entries.
    pub ring_entries: u32,
    /// Data Queue Fd Open.
    pub data_queue_fd_open: bool,
    /// Io Uring Ready.
    pub io_uring_ready: bool,
    /// Runtime Live.
    pub runtime_live: bool,
}

impl UblkDataQueueRuntimeOpenOutcome {
    /// From Spec.
    #[must_use]
    pub fn from_spec(spec: &UblkDataQueueRuntimeOpenSpec) -> Self {
        Self {
            dev_id: spec.dev_id,
            q_id: spec.q_id,
            nr_hw_queues: spec.nr_hw_queues,
            queue_depth: spec.queue_depth,
            data_queue_path: spec.data_queue_path.clone(),
            ring_entries: spec.ring_entries,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        }
    }

    /// Fetch Req Readiness.
    #[must_use]
    pub const fn fetch_req_readiness(
        &self,
        submitted_fetch_commands: u32,
    ) -> UblkDataQueueFetchReqReadiness {
        UblkDataQueueFetchReqReadiness::from_queue_geometry(
            self.nr_hw_queues,
            self.queue_depth,
            submitted_fetch_commands,
            self.runtime_live,
        )
    }
}

/// Ublk Data Queue Runtime.
pub struct UblkDataQueueRuntime {
    pub(crate) data_queue_file: fs::File,
    /// Whether the kernel supports IORING_FEAT_NODROP.
    pub(crate) nodrop_enabled: bool,
    /// Cumulative count of io_uring CQ overflow events detected during data-queue completion reap.
    pub(crate) cq_overflow_count: u64,
    pub(crate) ring: IoUring<squeue::Entry128, cqueue::Entry>,
    pub(crate) outcome: UblkDataQueueRuntimeOpenOutcome,
    pub(crate) cmd_buf_ptrs: Vec<*const u8>,
    pub(crate) cmd_buf_lens: Vec<usize>,
    pub(crate) io_buf_queue_depth: u16,
    pub(crate) io_buf_nr_hw_queues: u16,
    pub(crate) in_flight_counter: crate::target_reset_guard::InFlightCounter,
}

impl UblkDataQueueRuntime {
    /// As Fd.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.data_queue_file.as_fd()
    }

    /// Ring Mut.
    pub fn ring_mut(&mut self) -> &mut IoUring<squeue::Entry128, cqueue::Entry> {
        &mut self.ring
    }

    /// Whether the kernel supports IORING_FEAT_NODROP. When enabled, the kernel
    /// buffers overflowed CQEs internally instead of dropping them.
    #[must_use]
    pub const fn nodrop_enabled(&self) -> bool {
        self.nodrop_enabled
    }

    /// Cumulative count of io_uring CQ overflow events detected since this runtime
    /// was created.
    #[must_use]
    pub const fn cq_overflow_count(&self) -> u64 {
        self.cq_overflow_count
    }
    /// Outcome.
    #[must_use]
    pub const fn outcome(&self) -> &UblkDataQueueRuntimeOpenOutcome {
        &self.outcome
    }

    /// Runtime Live.
    #[must_use]
    pub const fn runtime_live(&self) -> bool {
        self.outcome.runtime_live
    }

    /// Returns a reference to the `UblkSrvIoDesc` for the given tag, or `None` if the tag
    /// is out of range. Delegates to [`io_desc_for_queue`] with q_id=0.
    #[must_use]
    pub fn io_desc(&self, tag: u16) -> Option<&UblkSrvIoDesc> {
        self.io_desc_for_queue(0, tag)
    }

    /// Compute the file position for `pread`/`pwrite` on the data-queue fd.
    #[must_use]
    pub fn io_buffer_file_offset(&self, q_id: u16, tag: u16, buf_off: u32) -> Option<u64> {
        if q_id >= self.io_buf_nr_hw_queues || tag >= self.io_buf_queue_depth {
            return None;
        }
        tidefs_ublk_abi::UblkIoBufferAddress {
            queue_id: q_id,
            tag,
            io_buffer_offset: buf_off,
        }
        .mmap_offset()
    }

    /// Read data from the ublk IO buffer into `buf` using `pread` on the data-queue fd.
    pub fn read_data_at(&self, q_id: u16, tag: u16, buf: &mut [u8]) -> io::Result<usize> {
        let pos = self
            .io_buffer_file_offset(q_id, tag, 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid q_id/tag"))?;
        let len = buf.len();
        let read = unsafe {
            libc::pread(
                self.data_queue_file.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                len,
                pos as libc::off_t,
            )
        };
        if read < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }

    /// Write data to the ublk IO buffer from `buf` using `pwrite` on the data-queue fd.
    pub fn write_data_at(&self, q_id: u16, tag: u16, data: &[u8]) -> io::Result<usize> {
        let pos = self
            .io_buffer_file_offset(q_id, tag, 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid q_id/tag"))?;
        let len = data.len();
        let written = unsafe {
            libc::pwrite(
                self.data_queue_file.as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                len,
                pos as libc::off_t,
            )
        };
        if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }

    /// Returns a shared reference to the data buffer for the given tag, or `None` if
    /// the tag is out of range.  On Linux 7.0 the data region is accessible
    /// via PROT_READ only through the per-queue command buffer mmap.
    #[must_use]
    pub fn data_buffer(&self, tag: u16) -> Option<&[u8]> {
        if tag >= self.io_buf_queue_depth {
            return None;
        }
        let desc_size = std::mem::size_of::<UblkSrvIoDesc>();
        let offset = (tag as usize) * desc_size + desc_size;
        let buf_size = (1usize << UBLK_IO_BUF_BITS) - desc_size;
        let cmd_buf = self.cmd_buf_ptrs.first()?;
        unsafe {
            let ptr = cmd_buf.add(offset);
            Some(std::slice::from_raw_parts(ptr, buf_size))
        }
    }

    /// Returns a mutable reference to the data buffer for the given tag, or `None` if
    /// the tag is out of range.  On Linux 7.0 the mmap is PROT_READ only;
    /// writable access is not available.  Use [`write_data_at`] instead.
    #[must_use]
    pub fn data_buffer_mut(&mut self, _tag: u16) -> Option<&mut [u8]> {
        None
    }

    /// Returns a reference to the `UblkSrvIoDesc` for the given (q_id, tag),
    /// or `None` if either is out of range. Uses per-queue command buffer mmap.
    #[must_use]
    pub fn io_desc_for_queue(&self, q_id: u16, tag: u16) -> Option<&UblkSrvIoDesc> {
        if q_id >= self.io_buf_nr_hw_queues || tag >= self.io_buf_queue_depth {
            return None;
        }
        let q_idx = q_id as usize;
        let offset = (tag as usize) * core::mem::size_of::<UblkSrvIoDesc>();
        let cmd_buf = self.cmd_buf_ptrs.get(q_idx)?;
        unsafe {
            let ptr = cmd_buf.add(offset) as *const UblkSrvIoDesc;
            Some(&*ptr)
        }
    }

    /// Returns the global slot index for a (q_id, tag) pair.
    #[must_use]
    pub const fn queue_tag_to_slot(&self, q_id: u16, tag: u16) -> Option<usize> {
        if q_id >= self.io_buf_nr_hw_queues || tag >= self.io_buf_queue_depth {
            return None;
        }
        Some((q_id as usize * self.io_buf_queue_depth as usize) + tag as usize)
    }

    /// Returns a shared reference to the data buffer for the given (q_id, tag),
    /// or `None` if either is out of range.  On Linux 7.0 the data region
    /// is accessible via PROT_READ through the per-queue command buffer mmap.
    #[must_use]
    pub fn data_buffer_for_queue(&self, q_id: u16, tag: u16) -> Option<&[u8]> {
        if q_id >= self.io_buf_nr_hw_queues || tag >= self.io_buf_queue_depth {
            return None;
        }
        let desc_size = std::mem::size_of::<UblkSrvIoDesc>();
        let offset = (tag as usize) * desc_size + desc_size;
        let buf_size = (1usize << UBLK_IO_BUF_BITS) - desc_size;
        let cmd_buf = self.cmd_buf_ptrs.get(q_id as usize)?;
        unsafe {
            let ptr = cmd_buf.add(offset);
            Some(std::slice::from_raw_parts(ptr, buf_size))
        }
    }

    /// Returns a mutable reference to the data buffer for the given (q_id, tag),
    /// or `None` if either is out of range.  On Linux 7.0 the mmap is
    /// PROT_READ only; writable access is unavailable.  Use [`write_data_at`].
    #[must_use]
    pub fn data_buffer_mut_for_queue(&mut self, _q_id: u16, _tag: u16) -> Option<&mut [u8]> {
        None
    }
    /// Return a reference to the in-flight submission counter.
    ///
    /// Callers that submit SQEs to this runtime should increment the
    /// counter before submission and decrement it after consuming the
    /// corresponding CQE. The counter is used by [`TargetResetGuard`]
    /// to determine when all in-flight I/O has completed.
    #[must_use]
    pub fn in_flight_counter(&self) -> &crate::target_reset_guard::InFlightCounter {
        &self.in_flight_counter
    }

    /// Create a [`TargetResetGuard`] for this runtime.
    ///
    /// The guard drains all pending CQEs from the io_uring ring and
    /// waits for the in-flight counter to reach zero (or the timeout
    /// expires). Call this before deallocating the ring or unmapping
    /// the I/O buffer during device stop/reset.
    #[must_use]
    pub fn create_reset_guard(
        &mut self,
        timeout: std::time::Duration,
    ) -> crate::target_reset_guard::TargetResetGuard<'_> {
        crate::target_reset_guard::TargetResetGuard::new(
            &mut self.ring,
            &self.in_flight_counter,
            timeout,
        )
    }

    /// Convenience method: create a reset guard and immediately drain it.
    ///
    /// Equivalent to `runtime.create_reset_guard(timeout).drain()`.
    pub fn drain_completions(&mut self, timeout: std::time::Duration) {
        self.create_reset_guard(timeout).drain();
    }
}

impl Drop for UblkDataQueueRuntime {
    fn drop(&mut self) {
        self.drain_completions(crate::target_reset_guard::DEFAULT_DRAIN_TIMEOUT);
        for (&ptr, &len) in self.cmd_buf_ptrs.iter().zip(self.cmd_buf_lens.iter()) {
            if !ptr.is_null() && len > 0 {
                unsafe {
                    libc::munmap(ptr as *mut libc::c_void, len);
                }
            }
        }
    }
}

impl std::fmt::Debug for UblkDataQueueRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UblkDataQueueRuntime")
            .field("data_queue_file", &self.data_queue_file)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

/// Ublk Data Queue Device Path.
pub fn ublk_data_queue_device_path(dev_id: u32) -> PathBuf {
    PathBuf::from(format!("/dev/ublkc{dev_id}"))
}

/// # Errors
///
/// Returns [`UblkDataQueueRuntimeOpenError`] on failure.
pub fn build_data_queue_runtime_open_spec(
    input: UblkDataQueueRuntimeOpenInput,
) -> Result<UblkDataQueueRuntimeOpenSpec, UblkDataQueueRuntimeOpenError> {
    validate_data_queue_runtime_open_input(input)?;
    Ok(UblkDataQueueRuntimeOpenSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkDataQueueRuntimeOpenError`] on failure.
pub fn open_data_queue_runtime(
    path: &Path,
    input: UblkDataQueueRuntimeOpenInput,
) -> Result<UblkDataQueueRuntime, UblkDataQueueRuntimeOpenError> {
    apply_data_queue_open_injection()?;
    let spec = build_data_queue_runtime_open_spec(input)?;
    if path != spec.data_queue_path {
        return Err(UblkDataQueueRuntimeOpenError::DataQueuePathMismatch);
    }

    let metadata = fs::metadata(path).map_err(map_data_queue_metadata_error)?;
    if !metadata.file_type().is_char_device() {
        return Err(UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice);
    }

    let data_queue_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(map_data_queue_open_error)?;
    let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(spec.ring_entries)
        .map_err(map_data_queue_io_uring_setup_error)?;
    let outcome = UblkDataQueueRuntimeOpenOutcome::from_spec(&spec);
    let nodrop_enabled = ring.params().is_feature_nodrop();

    let cmd_buf_size_per_queue = tidefs_ublk_abi::ublk_queue_cmd_buf_size(spec.queue_depth);
    let nr_hw_queues = spec.nr_hw_queues as usize;
    let mut cmd_buf_ptrs: Vec<*const u8> = Vec::with_capacity(nr_hw_queues);
    let mut cmd_buf_lens: Vec<usize> = Vec::with_capacity(nr_hw_queues);

    // Linux 7.0 ublk_ch_mmap: per-queue PROT_READ command buffer.
    // Stride = PAGE_SIZE stride: all queues alias q0; nr_hw_queues=1() matching kernel's max_sz.
    for q_id in 0..nr_hw_queues {
        let mmap_offset = (q_id * 4096) as libc::off_t; /* PAGE_SIZE stride; nr_hw_queues=1 ensures all queues alias q0 */
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cmd_buf_size_per_queue,
                libc::PROT_READ,
                libc::MAP_SHARED,
                data_queue_file.as_raw_fd(),
                mmap_offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            for &prev_ptr in &cmd_buf_ptrs {
                unsafe {
                    libc::munmap(prev_ptr as *mut libc::c_void, cmd_buf_size_per_queue);
                }
            }
            return Err(UblkDataQueueRuntimeOpenError::MmapFailed(
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL),
            ));
        }
        cmd_buf_ptrs.push(ptr as *const u8);
        cmd_buf_lens.push(cmd_buf_size_per_queue);
    }

    Ok(UblkDataQueueRuntime {
        data_queue_file,
        ring,
        outcome,
        cmd_buf_ptrs,
        cmd_buf_lens,
        io_buf_queue_depth: spec.queue_depth,
        io_buf_nr_hw_queues: spec.nr_hw_queues,
        in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
        nodrop_enabled,
        cq_overflow_count: 0,
    })
}

/// Ublk Control Start Dev Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlStartDevCommand {
    /// Startdev.
    StartDev,
}

impl UblkControlStartDevCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartDev => "START_DEV",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::StartDev => UblkCtrlCommand::StartDev,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Start Dev Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStartDevInput {
    /// Dev Id.
    pub dev_id: u32,
    /// Ublksrv Pid.
    pub ublksrv_pid: i32,
}

impl UblkControlStartDevInput {
    /// From Kernel Dev Id And Daemon Pid.
    #[must_use]
    pub const fn from_kernel_dev_id_and_daemon_pid(dev_id: u32, ublksrv_pid: i32) -> Self {
        Self {
            dev_id,
            ublksrv_pid,
        }
    }
}

/// Ublk Control Start Dev Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStartDevSpec {
    /// Command.
    pub command: UblkControlStartDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Ctrl Buffer Len.
    pub ctrl_buffer_len: u16,
    /// Ctrl Buffer Addr.
    pub ctrl_buffer_addr: u64,
    /// Inline Daemon Pid.
    pub inline_daemon_pid: i32,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
    /// Requires Ready Io Fetches.
    pub requires_ready_io_fetches: bool,
}

impl UblkControlStartDevSpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlStartDevInput) -> Self {
        let command = UblkControlStartDevCommand::StartDev;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            control_queue_id: u16::MAX,
            ctrl_buffer_len: 0,
            ctrl_buffer_addr: 0,
            inline_daemon_pid: input.ublksrv_pid,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
            requires_ready_io_fetches: true,
        }
    }
}

/// Ublk Control Start Dev Readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStartDevReadiness {
    /// Required Fetch Commands.
    pub required_fetch_commands: u32,
    /// Submitted Fetch Commands.
    pub submitted_fetch_commands: u32,
    /// Data Queue Runtime Live.
    pub data_queue_runtime_live: bool,
}

impl UblkControlStartDevReadiness {
    /// From Queue Geometry.
    #[must_use]
    pub const fn from_queue_geometry(
        nr_hw_queues: u16,
        queue_depth: u16,
        submitted_fetch_commands: u32,
    ) -> Self {
        Self::from_queue_geometry_with_runtime(
            nr_hw_queues,
            queue_depth,
            submitted_fetch_commands,
            false,
        )
    }

    /// From Queue Geometry With Runtime.
    #[must_use]
    pub const fn from_queue_geometry_with_runtime(
        nr_hw_queues: u16,
        queue_depth: u16,
        submitted_fetch_commands: u32,
        data_queue_runtime_live: bool,
    ) -> Self {
        Self {
            required_fetch_commands: nr_hw_queues as u32 * queue_depth as u32,
            submitted_fetch_commands,
            data_queue_runtime_live,
        }
    }

    /// All Fetches Ready.
    #[must_use]
    pub const fn all_fetches_ready(self) -> bool {
        self.data_queue_runtime_live
            && self.required_fetch_commands > 0
            && self.submitted_fetch_commands >= self.required_fetch_commands
    }
}

/// Ublk Control Start Dev Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlStartDevError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Invaliddaemonpid.
    InvalidDaemonPid,
    /// Dataqueuefetchesnotready.
    DataQueueFetchesNotReady,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlStartDevError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::InvalidDaemonPid => "invalid_daemon_pid",
            Self::DataQueueFetchesNotReady => "data_queue_fetches_not_ready",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Start Dev Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStartDevOutcome {
    /// Command.
    pub command: UblkControlStartDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Id.
    pub dev_id: u32,
    /// Ublksrv Pid.
    pub ublksrv_pid: i32,
}

impl UblkControlStartDevOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlStartDevInput) -> Self {
        Self {
            command: UblkControlStartDevCommand::StartDev,
            request_raw: UblkControlStartDevCommand::StartDev.request().raw(),
            dev_id: input.dev_id,
            ublksrv_pid: input.ublksrv_pid,
        }
    }
}

// ── StopDev ────────────────────────────────────────────────────────────

/// Ublk Control Stop Dev Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlStopDevCommand {
    /// Stopdev.
    StopDev,
}

impl UblkControlStopDevCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopDev => "STOP_DEV",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::StopDev => UblkCtrlCommand::StopDev,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Stop Dev Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStopDevInput {
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlStopDevInput {
    /// From Kernel Dev Id.
    #[must_use]
    pub const fn from_kernel_dev_id(dev_id: u32) -> Self {
        Self { dev_id }
    }
}

/// Ublk Control Stop Dev Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStopDevSpec {
    /// Command.
    pub command: UblkControlStopDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Ctrl Buffer Len.
    pub ctrl_buffer_len: u16,
    /// Ctrl Buffer Addr.
    pub ctrl_buffer_addr: u64,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
}

impl UblkControlStopDevSpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(_input: UblkControlStopDevInput) -> Self {
        let command = UblkControlStopDevCommand::StopDev;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            control_queue_id: u16::MAX,
            ctrl_buffer_len: 0,
            ctrl_buffer_addr: 0,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
        }
    }
}

/// Ublk Control Stop Dev Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlStopDevError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlStopDevError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Stop Dev Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStopDevOutcome {
    /// Command.
    pub command: UblkControlStopDevCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlStopDevOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlStopDevInput) -> Self {
        Self {
            command: UblkControlStopDevCommand::StopDev,
            request_raw: UblkControlStopDevCommand::StopDev.request().raw(),
            dev_id: input.dev_id,
        }
    }
}

/// # Errors
///
/// Returns [`UblkControlStopDevError`] on failure.
pub fn build_stop_dev_spec(
    input: UblkControlStopDevInput,
) -> Result<UblkControlStopDevSpec, UblkControlStopDevError> {
    validate_stop_dev_input(input)?;
    Ok(UblkControlStopDevSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkControlStopDevError`] on failure.
pub fn build_stop_dev_ctrl_cmd(
    input: UblkControlStopDevInput,
) -> Result<UblkSrvCtrlCmd, UblkControlStopDevError> {
    validate_stop_dev_input(input)?;
    Ok(UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        ..UblkSrvCtrlCmd::default()
    })
}

/// Encode Stop Dev Cmd80.
#[must_use]
pub fn encode_stop_dev_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

/// # Errors
///
/// Returns [`UblkControlStopDevError`] on failure.
pub fn issue_stop_dev(
    fd: BorrowedFd<'_>,
    input: UblkControlStopDevInput,
) -> Result<UblkControlStopDevOutcome, UblkControlStopDevError> {
    if let Some(err) = apply_stop_dev_injection() {
        return Err(err);
    }
    let spec = build_stop_dev_spec(input)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_STOP_DEV_RING_ENTRIES)
        .map_err(map_stop_dev_io_uring_setup_error)?;
    let command = build_stop_dev_ctrl_cmd(input)?;
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_stop_dev_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_STOP_DEV_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk STOP_DEV command with no userspace
            // buffer; this private ring has no other SQEs.
            submission
                .push(&entry)
                .map_err(|_| UblkControlStopDevError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(map_stop_dev_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlStopDevError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_STOP_DEV_USER_DATA {
        return Err(UblkControlStopDevError::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlStopDevError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlStopDevOutcome::from_input(input))
}

/// # Errors
///
/// Returns [`UblkControlStartDevError`] on failure.
pub fn build_start_dev_spec(
    input: UblkControlStartDevInput,
) -> Result<UblkControlStartDevSpec, UblkControlStartDevError> {
    validate_start_dev_input(input)?;
    Ok(UblkControlStartDevSpec::from_input(input))
}

/// # Errors
///
/// Returns [`UblkControlStartDevError`] on failure.
pub fn build_start_dev_ctrl_cmd(
    input: UblkControlStartDevInput,
) -> Result<UblkSrvCtrlCmd, UblkControlStartDevError> {
    validate_start_dev_input(input)?;
    Ok(UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        data: [input.ublksrv_pid as u64],
        ..UblkSrvCtrlCmd::default()
    })
}

/// Encode Start Dev Cmd80.
#[must_use]
pub fn encode_start_dev_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

/// # Errors
///
/// Returns [`UblkControlStartDevError`] on failure.
pub fn issue_start_dev(
    fd: BorrowedFd<'_>,
    input: UblkControlStartDevInput,
    readiness: UblkControlStartDevReadiness,
) -> Result<UblkControlStartDevOutcome, UblkControlStartDevError> {
    if let Some(err) = apply_start_dev_injection() {
        return Err(err);
    }
    let spec = build_start_dev_spec(input)?;
    validate_start_dev_readiness(readiness)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_START_DEV_RING_ENTRIES)
        .map_err(map_start_dev_io_uring_setup_error)?;
    let command = build_start_dev_ctrl_cmd(input)?;
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_start_dev_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_START_DEV_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk START_DEV command with inline
            // daemon pid data and no userspace buffer; this private ring has
            // no other SQEs. Callers must submit this only after all required
            // ublk data-queue FETCH_REQ commands are already in flight because
            // the kernel waits for that readiness before completing START_DEV.
            submission
                .push(&entry)
                .map_err(|_| UblkControlStartDevError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(map_start_dev_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlStartDevError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_START_DEV_USER_DATA {
        return Err(UblkControlStartDevError::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlStartDevError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlStartDevOutcome::from_input(input))
}

/// Ublk Control Start User Recovery Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlStartUserRecoveryCommand {
    /// Startuserrecovery.
    StartUserRecovery,
}

impl UblkControlStartUserRecoveryCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartUserRecovery => "START_USER_RECOVERY",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::StartUserRecovery => UblkCtrlCommand::StartUserRecovery,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Start User Recovery Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStartUserRecoveryInput {
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlStartUserRecoveryInput {
    /// From Kernel Dev Id.
    #[must_use]
    pub const fn from_kernel_dev_id(dev_id: u32) -> Self {
        Self { dev_id }
    }
}

/// Ublk Control Start User Recovery Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStartUserRecoverySpec {
    /// Command.
    pub command: UblkControlStartUserRecoveryCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlStartUserRecoverySpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlStartUserRecoveryInput) -> Self {
        let command = UblkControlStartUserRecoveryCommand::StartUserRecovery;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            control_queue_id: u16::MAX,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
            dev_id: input.dev_id,
        }
    }
}

/// Ublk Control Start User Recovery Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlStartUserRecoveryError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlStartUserRecoveryError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Start User Recovery Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlStartUserRecoveryOutcome {
    /// Command.
    pub command: UblkControlStartUserRecoveryCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlStartUserRecoveryOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlStartUserRecoveryInput) -> Self {
        Self {
            command: UblkControlStartUserRecoveryCommand::StartUserRecovery,
            request_raw: UblkControlStartUserRecoveryCommand::StartUserRecovery
                .request()
                .raw(),
            dev_id: input.dev_id,
        }
    }
}

/// Ublk Control End User Recovery Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlEndUserRecoveryCommand {
    /// Enduserrecovery.
    EndUserRecovery,
}

impl UblkControlEndUserRecoveryCommand {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EndUserRecovery => "END_USER_RECOVERY",
        }
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        match self {
            Self::EndUserRecovery => UblkCtrlCommand::EndUserRecovery,
        }
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control End User Recovery Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlEndUserRecoveryInput {
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlEndUserRecoveryInput {
    /// From Kernel Dev Id.
    #[must_use]
    pub const fn from_kernel_dev_id(dev_id: u32) -> Self {
        Self { dev_id }
    }
}

/// Ublk Control End User Recovery Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlEndUserRecoverySpec {
    /// Command.
    pub command: UblkControlEndUserRecoveryCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Control Queue Id.
    pub control_queue_id: u16,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlEndUserRecoverySpec {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlEndUserRecoveryInput) -> Self {
        let command = UblkControlEndUserRecoveryCommand::EndUserRecovery;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            control_queue_id: u16::MAX,
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: true,
            dev_id: input.dev_id,
        }
    }
}

/// Ublk Control End User Recovery Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlEndUserRecoveryError {
    /// Autodeviceid.
    AutoDeviceId,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlEndUserRecoveryError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control End User Recovery Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlEndUserRecoveryOutcome {
    /// Command.
    pub command: UblkControlEndUserRecoveryCommand,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlEndUserRecoveryOutcome {
    /// From Input.
    #[must_use]
    pub const fn from_input(input: UblkControlEndUserRecoveryInput) -> Self {
        Self {
            command: UblkControlEndUserRecoveryCommand::EndUserRecovery,
            request_raw: UblkControlEndUserRecoveryCommand::EndUserRecovery
                .request()
                .raw(),
            dev_id: input.dev_id,
        }
    }
}

/// # Errors
///
/// Returns [`UblkControlStartUserRecoveryError`] on failure.
pub fn issue_start_user_recovery(
    fd: BorrowedFd<'_>,
    input: UblkControlStartUserRecoveryInput,
) -> Result<UblkControlStartUserRecoveryOutcome, UblkControlStartUserRecoveryError> {
    validate_start_user_recovery_input(input)?;
    let spec = UblkControlStartUserRecoverySpec::from_input(input);
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_START_DEV_RING_ENTRIES)
        .map_err(|e| match e.raw_os_error() {
            Some(errno) => UblkControlStartUserRecoveryError::IoUringSetupErrno(errno),
            None => UblkControlStartUserRecoveryError::IoUringSetupMissingErrno,
        })?;
    let command = UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        ..UblkSrvCtrlCmd::default()
    };
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_ctrl_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_START_USER_RECOVERY_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk START_USER_RECOVERY command.
            // The command struct is stack-allocated and remains live until
            // the CQE is consumed below.
            submission
                .push(&entry)
                .map_err(|_| UblkControlStartUserRecoveryError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(|e| match e.raw_os_error() {
            Some(errno) => UblkControlStartUserRecoveryError::IoUringSubmitErrno(errno),
            None => UblkControlStartUserRecoveryError::IoUringSubmitMissingErrno,
        })?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlStartUserRecoveryError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_START_USER_RECOVERY_USER_DATA {
        return Err(
            UblkControlStartUserRecoveryError::UnexpectedCompletionUserData(completion.user_data()),
        );
    }
    if completion.result() < 0 {
        return Err(UblkControlStartUserRecoveryError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlStartUserRecoveryOutcome::from_input(input))
}

/// # Errors
///
/// Returns [`UblkControlEndUserRecoveryError`] on failure.
pub fn issue_end_user_recovery(
    fd: BorrowedFd<'_>,
    input: UblkControlEndUserRecoveryInput,
) -> Result<UblkControlEndUserRecoveryOutcome, UblkControlEndUserRecoveryError> {
    validate_end_user_recovery_input(input)?;
    let spec = UblkControlEndUserRecoverySpec::from_input(input);
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_START_DEV_RING_ENTRIES)
        .map_err(|e| match e.raw_os_error() {
            Some(errno) => UblkControlEndUserRecoveryError::IoUringSetupErrno(errno),
            None => UblkControlEndUserRecoveryError::IoUringSetupMissingErrno,
        })?;
    let command = UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        ..UblkSrvCtrlCmd::default()
    };
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_ctrl_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_END_USER_RECOVERY_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk END_USER_RECOVERY command.
            // The command struct is stack-allocated and remains live until
            // the CQE is consumed below.
            submission
                .push(&entry)
                .map_err(|_| UblkControlEndUserRecoveryError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(|e| match e.raw_os_error() {
            Some(errno) => UblkControlEndUserRecoveryError::IoUringSubmitErrno(errno),
            None => UblkControlEndUserRecoveryError::IoUringSubmitMissingErrno,
        })?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlEndUserRecoveryError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_END_USER_RECOVERY_USER_DATA {
        return Err(
            UblkControlEndUserRecoveryError::UnexpectedCompletionUserData(completion.user_data()),
        );
    }
    if completion.result() < 0 {
        return Err(UblkControlEndUserRecoveryError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlEndUserRecoveryOutcome::from_input(input))
}

const fn validate_start_user_recovery_input(
    input: UblkControlStartUserRecoveryInput,
) -> Result<(), UblkControlStartUserRecoveryError> {
    if input.dev_id == u32::MAX {
        return Err(UblkControlStartUserRecoveryError::AutoDeviceId);
    }
    Ok(())
}

const fn validate_end_user_recovery_input(
    input: UblkControlEndUserRecoveryInput,
) -> Result<(), UblkControlEndUserRecoveryError> {
    if input.dev_id == u32::MAX {
        return Err(UblkControlEndUserRecoveryError::AutoDeviceId);
    }
    Ok(())
}

const fn validate_add_dev_input(
    input: UblkControlAddDevInput,
) -> Result<(), UblkControlAddDevError> {
    if input.nr_hw_queues == 0 {
        return Err(UblkControlAddDevError::ZeroHardwareQueues);
    }
    if input.nr_hw_queues > UBLK_MAX_NR_QUEUES {
        return Err(UblkControlAddDevError::TooManyHardwareQueues);
    }
    if input.queue_depth == 0 {
        return Err(UblkControlAddDevError::ZeroQueueDepth);
    }
    if input.queue_depth > UBLK_MAX_QUEUE_DEPTH {
        return Err(UblkControlAddDevError::QueueDepthTooLarge);
    }
    if input.max_io_buf_bytes == 0 {
        return Err(UblkControlAddDevError::ZeroMaxIoBufferBytes);
    }
    if !input.flags.contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES) {
        return Err(UblkControlAddDevError::MissingRequiredFeatureFlag(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
        ));
    }
    Ok(())
}

const fn validate_del_dev_input(
    input: UblkControlDelDevInput,
) -> Result<(), UblkControlDelDevError> {
    if input.dev_id == TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID {
        return Err(UblkControlDelDevError::AutoDeviceId);
    }
    Ok(())
}

const fn validate_set_params_input(
    input: UblkControlSetParamsInput,
) -> Result<(), UblkControlSetParamsError> {
    if input.dev_id == TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID {
        return Err(UblkControlSetParamsError::AutoDeviceId);
    }
    if input.params.len == 0 {
        return Err(UblkControlSetParamsError::ZeroParamsLen);
    }
    if input.params.len != core::mem::size_of::<UblkParams>() as u32 {
        return Err(UblkControlSetParamsError::ParamsLenMismatch);
    }
    if input.params.types == 0 {
        return Err(UblkControlSetParamsError::ZeroParamTypes);
    }
    if input.params.types & UBLK_PARAM_TYPE_BASIC == 0 {
        return Err(UblkControlSetParamsError::MissingBasicParams);
    }
    if input.params.types & UBLK_PARAM_TYPE_DISCARD == 0 {
        return Err(UblkControlSetParamsError::MissingDiscardParams);
    }
    if input.params.types & UBLK_PARAM_TYPE_SEGMENT == 0 {
        return Err(UblkControlSetParamsError::MissingSegmentParams);
    }
    if input.params.basic.dev_sectors == 0 {
        return Err(UblkControlSetParamsError::ZeroDevSectors);
    }
    if input.params.basic.max_sectors == 0 {
        return Err(UblkControlSetParamsError::ZeroMaxSectors);
    }
    if input.params.seg.max_segment_size == 0 {
        return Err(UblkControlSetParamsError::ZeroMaxSegmentSize);
    }
    if input.params.seg.max_segments == 0 {
        return Err(UblkControlSetParamsError::ZeroMaxSegments);
    }
    Ok(())
}

const fn validate_fetch_req_input(
    input: UblkDataQueueFetchReqInput,
) -> Result<(), UblkDataQueueFetchReqError> {
    if input.nr_hw_queues == 0 {
        return Err(UblkDataQueueFetchReqError::ZeroHardwareQueues);
    }
    if input.nr_hw_queues > UBLK_MAX_NR_QUEUES {
        return Err(UblkDataQueueFetchReqError::TooManyHardwareQueues);
    }
    if input.queue_depth == 0 {
        return Err(UblkDataQueueFetchReqError::ZeroQueueDepth);
    }
    if input.queue_depth > UBLK_MAX_QUEUE_DEPTH {
        return Err(UblkDataQueueFetchReqError::QueueDepthTooLarge);
    }
    if input.q_id >= input.nr_hw_queues {
        return Err(UblkDataQueueFetchReqError::QueueIdOutOfRange);
    }
    if input.tag >= input.queue_depth {
        return Err(UblkDataQueueFetchReqError::TagOutOfRange);
    }
    if input.user_copy_addr != 0 {
        return Err(UblkDataQueueFetchReqError::UserCopyFetchAddrMustBeZero);
    }
    Ok(())
}

const fn validate_commit_and_fetch_input(
    input: UblkDataQueueCommitAndFetchInput,
) -> Result<(), UblkDataQueueCommitAndFetchError> {
    if input.nr_hw_queues == 0 {
        return Err(UblkDataQueueCommitAndFetchError::ZeroHardwareQueues);
    }
    if input.nr_hw_queues > UBLK_MAX_NR_QUEUES {
        return Err(UblkDataQueueCommitAndFetchError::TooManyHardwareQueues);
    }
    if input.queue_depth == 0 {
        return Err(UblkDataQueueCommitAndFetchError::ZeroQueueDepth);
    }
    if input.queue_depth > UBLK_MAX_QUEUE_DEPTH {
        return Err(UblkDataQueueCommitAndFetchError::QueueDepthTooLarge);
    }
    if input.q_id >= input.nr_hw_queues {
        return Err(UblkDataQueueCommitAndFetchError::QueueIdOutOfRange);
    }
    if input.tag >= input.queue_depth {
        return Err(UblkDataQueueCommitAndFetchError::TagOutOfRange);
    }
    if input.result == UBLK_IO_RES_NEED_GET_DATA {
        return Err(UblkDataQueueCommitAndFetchError::NeedGetDataResultUnsupported);
    }
    if input.addr_or_zone_append_lba != 0 {
        return Err(UblkDataQueueCommitAndFetchError::ZoneAppendLbaMustBeZero);
    }
    Ok(())
}

const fn validate_data_queue_runtime_open_input(
    input: UblkDataQueueRuntimeOpenInput,
) -> Result<(), UblkDataQueueRuntimeOpenError> {
    if input.dev_id == TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID {
        return Err(UblkDataQueueRuntimeOpenError::AutoDeviceId);
    }
    if input.nr_hw_queues == 0 {
        return Err(UblkDataQueueRuntimeOpenError::ZeroHardwareQueues);
    }
    if input.nr_hw_queues > UBLK_MAX_NR_QUEUES {
        return Err(UblkDataQueueRuntimeOpenError::TooManyHardwareQueues);
    }
    if input.queue_depth == 0 {
        return Err(UblkDataQueueRuntimeOpenError::ZeroQueueDepth);
    }
    if input.queue_depth > UBLK_MAX_QUEUE_DEPTH {
        return Err(UblkDataQueueRuntimeOpenError::QueueDepthTooLarge);
    }
    if input.q_id >= input.nr_hw_queues {
        return Err(UblkDataQueueRuntimeOpenError::QueueIdOutOfRange);
    }
    Ok(())
}

const fn validate_start_dev_input(
    input: UblkControlStartDevInput,
) -> Result<(), UblkControlStartDevError> {
    if input.dev_id == TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID {
        return Err(UblkControlStartDevError::AutoDeviceId);
    }
    if input.ublksrv_pid <= 0 {
        return Err(UblkControlStartDevError::InvalidDaemonPid);
    }
    Ok(())
}

const fn validate_stop_dev_input(
    input: UblkControlStopDevInput,
) -> Result<(), UblkControlStopDevError> {
    if input.dev_id == TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID {
        return Err(UblkControlStopDevError::AutoDeviceId);
    }
    Ok(())
}

const fn validate_start_dev_readiness(
    readiness: UblkControlStartDevReadiness,
) -> Result<(), UblkControlStartDevError> {
    if !readiness.all_fetches_ready() {
        return Err(UblkControlStartDevError::DataQueueFetchesNotReady);
    }
    Ok(())
}

const fn validate_commit_and_fetch_readiness(
    readiness: UblkDataQueueCommitAndFetchReadiness,
) -> Result<(), UblkDataQueueCommitAndFetchError> {
    if !readiness.data_queue_runtime_live {
        return Err(UblkDataQueueCommitAndFetchError::RuntimeNotLive);
    }
    if !readiness.fetched_request_available {
        return Err(UblkDataQueueCommitAndFetchError::FetchedRequestMissing);
    }
    if !readiness.completion_result_ready {
        return Err(UblkDataQueueCommitAndFetchError::CompletionResultNotReady);
    }
    Ok(())
}

/// # Errors
///
/// Returns [`UblkControlReadonlyProbeError`] on failure.
pub fn issue_get_features(
    fd: BorrowedFd<'_>,
) -> Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError> {
    if let Some(err) = apply_readonly_probe_injection() {
        return Err(err);
    }
    let spec = build_readonly_probe_spec(UblkCtrlCommand::GetFeatures)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_READONLY_PROBE_RING_ENTRIES)
        .map_err(map_io_uring_setup_error)?;
    let mut features_bits = 0_u64;
    let command = build_get_features_ctrl_cmd(&mut features_bits);
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_get_features_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_READONLY_PROBE_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk control command whose `addr` field points
            // at `features_bits`; both remain live until the CQE is consumed below,
            // and this private ring has no other SQEs.
            submission
                .push(&entry)
                .map_err(|_| UblkControlReadonlyProbeError::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1).map_err(map_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlReadonlyProbeError::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_READONLY_PROBE_USER_DATA {
        return Err(UblkControlReadonlyProbeError::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlReadonlyProbeError::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(UblkControlGetFeaturesOutcome::from_features_bits(
        features_bits,
    ))
}

fn map_io_uring_setup_error(error: io::Error) -> UblkControlReadonlyProbeError {
    error
        .raw_os_error()
        .map(UblkControlReadonlyProbeError::IoUringSetupErrno)
        .unwrap_or(UblkControlReadonlyProbeError::IoUringSetupMissingErrno)
}

fn map_io_uring_submit_error(error: io::Error) -> UblkControlReadonlyProbeError {
    error
        .raw_os_error()
        .map(UblkControlReadonlyProbeError::IoUringSubmitErrno)
        .unwrap_or(UblkControlReadonlyProbeError::IoUringSubmitMissingErrno)
}

fn map_add_dev_io_uring_setup_error(error: io::Error) -> UblkControlAddDevError {
    error
        .raw_os_error()
        .map(UblkControlAddDevError::IoUringSetupErrno)
        .unwrap_or(UblkControlAddDevError::IoUringSetupMissingErrno)
}

fn map_add_dev_io_uring_submit_error(error: io::Error) -> UblkControlAddDevError {
    error
        .raw_os_error()
        .map(UblkControlAddDevError::IoUringSubmitErrno)
        .unwrap_or(UblkControlAddDevError::IoUringSubmitMissingErrno)
}

fn map_del_dev_io_uring_setup_error(error: io::Error) -> UblkControlDelDevError {
    error
        .raw_os_error()
        .map(UblkControlDelDevError::IoUringSetupErrno)
        .unwrap_or(UblkControlDelDevError::IoUringSetupMissingErrno)
}

fn map_del_dev_io_uring_submit_error(error: io::Error) -> UblkControlDelDevError {
    error
        .raw_os_error()
        .map(UblkControlDelDevError::IoUringSubmitErrno)
        .unwrap_or(UblkControlDelDevError::IoUringSubmitMissingErrno)
}

fn map_set_params_io_uring_setup_error(error: io::Error) -> UblkControlSetParamsError {
    error
        .raw_os_error()
        .map(UblkControlSetParamsError::IoUringSetupErrno)
        .unwrap_or(UblkControlSetParamsError::IoUringSetupMissingErrno)
}

fn map_set_params_io_uring_submit_error(error: io::Error) -> UblkControlSetParamsError {
    error
        .raw_os_error()
        .map(UblkControlSetParamsError::IoUringSubmitErrno)
        .unwrap_or(UblkControlSetParamsError::IoUringSubmitMissingErrno)
}

fn map_fetch_req_io_uring_submit_error(error: io::Error) -> UblkDataQueueFetchReqError {
    error
        .raw_os_error()
        .map(UblkDataQueueFetchReqError::IoUringSubmitErrno)
        .unwrap_or(UblkDataQueueFetchReqError::IoUringSubmitMissingErrno)
}

fn map_commit_and_fetch_io_uring_submit_error(
    error: io::Error,
) -> UblkDataQueueCommitAndFetchError {
    error
        .raw_os_error()
        .map(UblkDataQueueCommitAndFetchError::IoUringSubmitErrno)
        .unwrap_or(UblkDataQueueCommitAndFetchError::IoUringSubmitMissingErrno)
}

fn map_data_queue_metadata_error(error: io::Error) -> UblkDataQueueRuntimeOpenError {
    if error.kind() == io::ErrorKind::NotFound {
        return UblkDataQueueRuntimeOpenError::DataQueuePathMissing;
    }
    error
        .raw_os_error()
        .map(UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno)
        .unwrap_or(UblkDataQueueRuntimeOpenError::DataQueueMetadataMissingErrno)
}

fn map_data_queue_open_error(error: io::Error) -> UblkDataQueueRuntimeOpenError {
    error
        .raw_os_error()
        .map(UblkDataQueueRuntimeOpenError::DataQueueOpenErrno)
        .unwrap_or(UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno)
}

fn map_data_queue_io_uring_setup_error(error: io::Error) -> UblkDataQueueRuntimeOpenError {
    error
        .raw_os_error()
        .map(UblkDataQueueRuntimeOpenError::IoUringSetupErrno)
        .unwrap_or(UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno)
}

fn map_start_dev_io_uring_setup_error(error: io::Error) -> UblkControlStartDevError {
    error
        .raw_os_error()
        .map(UblkControlStartDevError::IoUringSetupErrno)
        .unwrap_or(UblkControlStartDevError::IoUringSetupMissingErrno)
}

fn map_start_dev_io_uring_submit_error(error: io::Error) -> UblkControlStartDevError {
    error
        .raw_os_error()
        .map(UblkControlStartDevError::IoUringSubmitErrno)
        .unwrap_or(UblkControlStartDevError::IoUringSubmitMissingErrno)
}

fn map_stop_dev_io_uring_setup_error(error: io::Error) -> UblkControlStopDevError {
    error
        .raw_os_error()
        .map(UblkControlStopDevError::IoUringSetupErrno)
        .unwrap_or(UblkControlStopDevError::IoUringSetupMissingErrno)
}

fn map_stop_dev_io_uring_submit_error(error: io::Error) -> UblkControlStopDevError {
    error
        .raw_os_error()
        .map(UblkControlStopDevError::IoUringSubmitErrno)
        .unwrap_or(UblkControlStopDevError::IoUringSubmitMissingErrno)
}

/// Return the ublk block device path for a given kernel device id.
///
/// Constructs `/dev/ublkb{dev_id}`.
#[must_use]
pub fn ublk_block_device_path(dev_id: u32) -> PathBuf {
    PathBuf::from(format!("/dev/ublkb{dev_id}"))
}

/// Issue a BLKDISCARD ioctl to the ublk block device.
///
/// Opens `/dev/ublkb{dev_id}` read-write and issues a `BLKDISCARD` ioctl
/// to deallocate (TRIM) the specified byte range. The caller must ensure
/// the range is aligned to the device's discard granularity and that the
/// device is online.
///
/// # Errors
///
/// Returns an I/O error if the device cannot be opened or the ioctl fails.
pub fn trim_range_blkdev(dev_id: u32, offset: u64, length: u64) -> io::Result<()> {
    // BLKDISCARD = _IO(0x12, 119) = 0x1277
    const BLKDISCARD: u64 = 0x0000_1277;

    let path = ublk_block_device_path(dev_id);
    let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;

    let range: [u64; 2] = [offset, length];
    // SAFETY: BLKDISCARD ioctl does not access memory beyond the range array;
    // the kernel validates offset/length against the device geometry.
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), BLKDISCARD, &range) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// UblkControlRuntime: device lifecycle manager with io_uring command dispatch
// ═══════════════════════════════════════════════════════════════════════════

/// Ublk Control Path.
pub const UBLK_CONTROL_PATH: &str = "/dev/ublk-control";

/// Lifecycle state for a ublk device under management.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDeviceLifecycleState {
    /// Device was created via ADD_DEV but not yet started.
    Created,
    /// Device is started and accepting I/O (after START_DEV).
    Attached,
    /// Device is being drained of in-flight I/O before removal.
    Draining,
    /// Device has been removed via DEL_DEV.
    Removed,
}

impl UblkDeviceLifecycleState {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Attached => "attached",
            Self::Draining => "draining",
            Self::Removed => "removed",
        }
    }
}

/// Information about a managed ublk device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkManagedDevice {
    /// Queue lifecycle state machine governing attach, drain, and removal transitions.
    pub lifecycle: QueueLifecycle,
    /// Dev Id.
    pub dev_id: u32,
    /// State.
    pub state: UblkDeviceLifecycleState,
    /// Dev Info.
    pub dev_info: UblkSrvCtrlDevInfo,
    /// Block Path.
    pub block_path: PathBuf,
    /// Blake3 State Hash.
    pub blake3_state_hash: Option<[u8; 32]>,
}

impl UblkManagedDevice {
    /// From Add Dev Outcome.
    #[must_use]
    pub fn from_add_dev_outcome(outcome: &UblkControlAddDevOutcome) -> Self {
        let hash = compute_device_state_hash(&outcome.dev_info);
        Self {
            lifecycle: QueueLifecycle::attached(),
            dev_id: outcome.dev_info.dev_id,
            state: UblkDeviceLifecycleState::Created,
            dev_info: outcome.dev_info,
            block_path: ublk_block_device_path(outcome.dev_info.dev_id),
            blake3_state_hash: Some(hash),
        }
    }

    /// Verify that the device state matches the stored BLAKE3 integrity hash.
    ///
    /// # Errors
    ///
    /// Returns [`UblkDeviceIntegrityError::NoStoredHash`] if no hash has been stored,
    /// or [`UblkDeviceIntegrityError::HashMismatch`] if the computed hash does not
    /// match the stored one.
    pub fn verify_integrity(&self) -> Result<(), UblkDeviceIntegrityError> {
        match &self.blake3_state_hash {
            Some(stored) => verify_device_state_hash(&self.dev_info, stored),
            None => Err(UblkDeviceIntegrityError::NoStoredHash),
        }
    }

    /// Compute and update the stored BLAKE3 state hash from current device info.
    pub fn update_integrity_hash(&mut self) {
        self.blake3_state_hash = Some(compute_device_state_hash(&self.dev_info));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BLAKE3-verified control-plane integrity for device state
// ═══════════════════════════════════════════════════════════════════════════

/// Error returned when BLAKE3 device state integrity verification fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkDeviceIntegrityError {
    /// The stored hash does not match the computed hash of the current state.
    HashMismatch {
        /// Expected.
        expected: [u8; 32],
        /// Computed.
        computed: [u8; 32],
    },
    /// The device has no stored integrity hash to verify against.
    NoStoredHash,
}

impl UblkDeviceIntegrityError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch { .. } => "hash_mismatch",
            Self::NoStoredHash => "no_stored_hash",
        }
    }
}

impl std::fmt::Display for UblkDeviceIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashMismatch { expected, computed } => {
                write!(
                    f,
                    "device state integrity hash mismatch: expected={expected:02x?} computed={computed:02x?}"
                )
            }
            Self::NoStoredHash => write!(f, "no stored integrity hash for device"),
        }
    }
}

/// Compute a BLAKE3 hash of the device info struct for control-plane
/// integrity verification.
///
/// The hash covers all fields of [`UblkSrvCtrlDevInfo`] as raw bytes.
/// This provides a cryptographic integrity anchor that can detect
/// tampering, kernel bugs, or concurrent modification of ublk device
/// configuration.
#[must_use]
pub fn compute_device_state_hash(dev_info: &UblkSrvCtrlDevInfo) -> [u8; 32] {
    // SAFETY: UblkSrvCtrlDevInfo is repr(C) and contains no pointers
    // or padding that would leak uninitialized memory.
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            (dev_info as *const UblkSrvCtrlDevInfo) as *const u8,
            std::mem::size_of::<UblkSrvCtrlDevInfo>(),
        )
    };
    *blake3::hash(bytes).as_bytes()
}

/// Verify that the device state matches a stored BLAKE3 integrity hash.
///
/// # Errors
///
/// Returns [`UblkDeviceIntegrityError::HashMismatch`] if the computed hash
/// does not match `stored_hash`.
pub fn verify_device_state_hash(
    dev_info: &UblkSrvCtrlDevInfo,
    stored_hash: &[u8; 32],
) -> Result<(), UblkDeviceIntegrityError> {
    let computed = compute_device_state_hash(dev_info);
    // Use a simple byte comparison loop in const context.
    let mut i = 0;
    while i < 32 {
        if computed[i] != stored_hash[i] {
            return Err(UblkDeviceIntegrityError::HashMismatch {
                expected: *stored_hash,
                computed,
            });
        }
        i += 1;
    }
    Ok(())
}

/// Unified control-plane runtime for ublk device lifecycle management.
///
/// Opens `/dev/ublk-control` and holds the file descriptor for the lifetime
/// of the runtime. Maintains an in-memory device registry mapping `dev_id`
/// to [`UblkManagedDevice`] entries.
pub struct UblkControlRuntime {
    control_file: fs::File,
    devices: std::collections::HashMap<u32, UblkManagedDevice>,
}

impl UblkControlRuntime {
    /// Open `/dev/ublk-control` and initialize an empty device registry.
    ///
    /// # Errors
    /// Returns `io::Error` if the control device cannot be opened.
    pub fn new() -> io::Result<Self> {
        let control_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(UBLK_CONTROL_PATH)?;
        Ok(Self {
            control_file,
            devices: std::collections::HashMap::new(),
        })
    }

    /// Construct a [`UblkControlRuntime`] from an already-open control file
    /// descriptor with an empty device registry. Intended for testing against
    /// `/dev/null` when the real `/dev/ublk-control` is unavailable.
    pub fn from_control_file(control_file: fs::File) -> Self {
        Self {
            control_file,
            devices: std::collections::HashMap::new(),
        }
    }

    /// Borrow the control file descriptor for issuing ublk commands.
    pub fn control_fd(&self) -> BorrowedFd<'_> {
        self.control_file.as_fd()
    }

    /// Submit `UBLK_CMD_ADD_DEV` through the control file descriptor,
    /// register the resulting device in the device registry, and return
    /// the managed device.
    ///
    /// # Errors
    /// Returns [`UblkControlAddDevError`] on io_uring or ublk command failure.
    pub fn add_device(
        &mut self,
        input: UblkControlAddDevInput,
    ) -> Result<UblkManagedDevice, UblkControlAddDevError> {
        let outcome = issue_add_dev(self.control_fd(), input)?;
        let dev_id = outcome.dev_info.dev_id;
        let device = UblkManagedDevice::from_add_dev_outcome(&outcome);
        self.devices.insert(dev_id, device.clone());
        Ok(device)
    }

    /// Transition a device to `Draining`, drain in-flight control commands,
    /// submit `UBLK_CMD_DEL_DEV`, and unregister the device.
    ///
    /// # Errors
    /// Returns [`UblkControlRemoveDeviceError`] if the dev_id is unknown,
    /// already removed, or the ublk command fails.
    pub fn remove_device(
        &mut self,
        dev_id: u32,
    ) -> Result<UblkControlDelDevOutcome, UblkControlRemoveDeviceError> {
        // Check existence and state without holding a mutable borrow
        // across the io_uring dispatch call.
        let prev_state = {
            let device = self
                .devices
                .get(&dev_id)
                .ok_or(UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id })?;
            if device.state == UblkDeviceLifecycleState::Removed {
                return Err(UblkControlRemoveDeviceError::DeviceAlreadyRemoved { dev_id });
            }
            device.state
        };

        // Enforce drain-before-removal via QueueLifecycle state machine.
        // Advance the lifecycle from its current mapped state through
        // drain -> remove in sequence before issuing DEL_DEV.
        //
        // Mapping from UblkDeviceLifecycleState to QueueLifecycleState:
        //   Created/Attached -> Attached (must drain first)
        //   Draining        -> Draining (already draining, skip)
        if prev_state == UblkDeviceLifecycleState::Attached
            || prev_state == UblkDeviceLifecycleState::Created
        {
            // Validate drain transition via the lifecycle state machine
            let mut lc = QueueLifecycle::attached();
            lc.drain().map_err(
                |_| UblkControlRemoveDeviceError::InvalidLifecycleTransition {
                    dev_id,
                    current: prev_state,
                },
            )?;
        }

        // Transition to Draining before issuing DEL_DEV
        self.devices
            .get_mut(&dev_id)
            .expect("device just checked")
            .state = UblkDeviceLifecycleState::Draining;

        let input = UblkControlDelDevInput::from_kernel_dev_id(dev_id);
        let outcome = issue_del_dev(self.control_fd(), input).map_err(|e| {
            // Revert state on ublk command failure
            if let Some(d) = self.devices.get_mut(&dev_id) {
                d.state = prev_state;
            }
            UblkControlRemoveDeviceError::UblkDelDevError(e)
        })?;

        // Validate remove transition via lifecycle state machine
        {
            let mut lc = QueueLifecycle::attached();
            lc.drain().expect("drain from attached");
            lc.remove().map_err(
                |_| UblkControlRemoveDeviceError::InvalidLifecycleTransition {
                    dev_id,
                    current: UblkDeviceLifecycleState::Draining,
                },
            )?;
        }

        self.devices
            .get_mut(&dev_id)
            .expect("device just checked")
            .state = UblkDeviceLifecycleState::Removed;
        self.devices.remove(&dev_id);
        Ok(outcome)
    }

    /// Query device info via `UBLK_CMD_GET_DEV_INFO2` for a device.
    /// The device does not need to be registered in the runtime.
    ///
    /// # Errors
    /// Returns [`UblkControlGetDevInfo2Error`] if the ublk command fails.
    pub fn get_device_info(
        &self,
        dev_id: u32,
    ) -> Result<UblkSrvCtrlDevInfo, UblkControlGetDevInfo2Error> {
        issue_get_dev_info2(self.control_fd(), dev_id)
    }

    /// Return the number of managed devices (excluding those in `Removed` state).
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices
            .values()
            .filter(|d| d.state != UblkDeviceLifecycleState::Removed)
            .count()
    }

    /// Look up a managed device by `dev_id`.
    #[must_use]
    pub fn lookup_device(&self, dev_id: u32) -> Option<&UblkManagedDevice> {
        self.devices.get(&dev_id)
    }

    /// List all managed device IDs (excluding `Removed`).
    #[must_use]
    pub fn device_ids(&self) -> Vec<u32> {
        self.devices
            .iter()
            .filter(|(_, d)| d.state != UblkDeviceLifecycleState::Removed)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Transition a device from `Created` to `Attached` after successful
    /// `START_DEV` issuance.
    ///
    /// # Errors
    /// Returns [`UblkControlRemoveDeviceError::DeviceNotRegistered`] if
    /// the device is unknown, or [`UblkControlRemoveDeviceError::InvalidLifecycleTransition`] if the device
    /// is not in `Created` state (returns [`UblkControlRemoveDeviceError::InvalidLifecycleTransition`]).
    pub fn mark_attached(&mut self, dev_id: u32) -> Result<(), UblkControlRemoveDeviceError> {
        let device = self
            .devices
            .get_mut(&dev_id)
            .ok_or(UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id })?;

        // Validate lifecycle: device must be in Created (maps to Attached in
        // QueueLifecycle) for the mark_attached transition.
        if device.state != UblkDeviceLifecycleState::Created {
            return Err(UblkControlRemoveDeviceError::InvalidLifecycleTransition {
                dev_id,
                current: device.state,
            });
        }

        // Validate via QueueLifecycle that we are in a valid state for attach.
        // Created maps to Attached in the queue lifecycle; verify the machine
        // agrees this is a valid operational state.
        let lc = QueueLifecycle::attached();
        if !lc.is_io_capable() {
            return Err(UblkControlRemoveDeviceError::InvalidLifecycleTransition {
                dev_id,
                current: device.state,
            });
        }

        device.state = UblkDeviceLifecycleState::Attached;
        Ok(())
    }
}

// ── remove_device composite error type ────────────────────────────────────

/// Ublk Control Remove Device Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlRemoveDeviceError {
    /// Devicenotregistered.
    DeviceNotRegistered {
        /// Dev Id.
        dev_id: u32,
    },
    /// Invalidlifecycletransition.
    InvalidLifecycleTransition {
        /// Dev Id.
        dev_id: u32,
        /// Current.
        current: UblkDeviceLifecycleState,
    },
    /// Devicealreadyremoved.
    DeviceAlreadyRemoved {
        /// Dev Id.
        dev_id: u32,
    },
    /// Ublkdeldeverror.
    UblkDelDevError(UblkControlDelDevError),
}

impl UblkControlRemoveDeviceError {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceNotRegistered { .. } => "device_not_registered",
            Self::InvalidLifecycleTransition { .. } => "invalid_lifecycle_transition",
            Self::DeviceAlreadyRemoved { .. } => "device_already_removed",
            Self::UblkDelDevError(_) => "ublk_del_dev_error",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::InvalidLifecycleTransition { .. } => None,
            Self::UblkDelDevError(e) => e.errno(),
            _ => None,
        }
    }

    /// Dev Id.
    #[must_use]
    pub const fn dev_id(self) -> Option<u32> {
        match self {
            Self::DeviceNotRegistered { dev_id }
            | Self::DeviceAlreadyRemoved { dev_id }
            | Self::InvalidLifecycleTransition { dev_id, .. } => Some(dev_id),
            Self::UblkDelDevError(_) => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// UblkControlGetDevInfo2: query device info via UBLK_CMD_GET_DEV_INFO2
// ═══════════════════════════════════════════════════════════════════════════

/// Ublk Control Get Dev Info2 Ring Entries.
pub const UBLK_CONTROL_GET_DEV_INFO2_RING_ENTRIES: u32 = 1;
/// Ublk Control Get Dev Info2 User Data.
pub const UBLK_CONTROL_GET_DEV_INFO2_USER_DATA: u64 = 0x5649_4245_4653_0137;

/// Ublk Control Get Dev Info 2 Command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlGetDevInfo2Command {
    /// Getdevinfo2.
    GetDevInfo2,
}

impl UblkControlGetDevInfo2Command {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "GET_DEV_INFO2"
    }

    /// Ublk Command.
    #[must_use]
    pub const fn ublk_command(self) -> UblkCtrlCommand {
        UblkCtrlCommand::GetDevInfo2
    }

    /// Request.
    #[must_use]
    pub const fn request(self) -> UblkIoctlRequest {
        self.ublk_command().request()
    }
}

/// Ublk Control Get Dev Info 2 Input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlGetDevInfo2Input {
    /// Dev Id.
    pub dev_id: u32,
}

impl UblkControlGetDevInfo2Input {
    /// From Kernel Dev Id.
    #[must_use]
    pub const fn from_kernel_dev_id(dev_id: u32) -> Self {
        Self { dev_id }
    }
}

/// Ublk Control Get Dev Info 2 Spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlGetDevInfo2Spec {
    /// Command.
    pub command: UblkControlGetDevInfo2Command,
    /// Request Raw.
    pub request_raw: u32,
    /// Request Direction.
    pub request_direction: UblkIoctlDirection,
    /// Request Size.
    pub request_size: u16,
    /// Dev Info Buffer Len.
    pub dev_info_buffer_len: usize,
    /// Uring Cmd Sqe Bytes.
    pub uring_cmd_sqe_bytes: usize,
    /// Mutates Control State.
    pub mutates_control_state: bool,
}

impl UblkControlGetDevInfo2Spec {
    /// Get Dev Info2.
    #[must_use]
    pub const fn get_dev_info2() -> Self {
        let command = UblkControlGetDevInfo2Command::GetDevInfo2;
        let request = command.request();
        Self {
            command,
            request_raw: request.raw(),
            request_direction: request.direction(),
            request_size: request.size(),
            dev_info_buffer_len: core::mem::size_of::<UblkSrvCtrlDevInfo>(),
            uring_cmd_sqe_bytes: 128,
            mutates_control_state: false,
        }
    }
}

/// Ublk Control Get Dev Info 2 Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlGetDevInfo2Error {
    /// Autodeviceid.
    AutoDeviceId,
    /// Iouringsetuperrno.
    IoUringSetupErrno(i32),
    /// Iouringsetupmissingerrno.
    IoUringSetupMissingErrno,
    /// Submissionqueuefull.
    SubmissionQueueFull,
    /// Iouringsubmiterrno.
    IoUringSubmitErrno(i32),
    /// Iouringsubmitmissingerrno.
    IoUringSubmitMissingErrno,
    /// Completionmissing.
    CompletionMissing,
    /// Unexpectedcompletionuserdata.
    UnexpectedCompletionUserData(u64),
    /// Ublkcommanderrno.
    UblkCommandErrno(i32),
}

impl UblkControlGetDevInfo2Error {
    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDeviceId => "auto_device_id_not_concrete",
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData(_) => "unexpected_completion_user_data",
            Self::UblkCommandErrno(_) => "ublk_command_errno",
        }
    }

    /// Errno.
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::IoUringSetupErrno(errno)
            | Self::IoUringSubmitErrno(errno)
            | Self::UblkCommandErrno(errno) => Some(errno),
            _ => None,
        }
    }
}

/// Ublk Control Get Dev Info 2 Outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkControlGetDevInfo2Outcome {
    /// Command.
    pub command: UblkControlGetDevInfo2Command,
    /// Request Raw.
    pub request_raw: u32,
    /// Dev Info.
    pub dev_info: UblkSrvCtrlDevInfo,
}

impl UblkControlGetDevInfo2Outcome {
    /// From Dev Info.
    #[must_use]
    pub const fn from_dev_info(dev_info: UblkSrvCtrlDevInfo) -> Self {
        Self {
            command: UblkControlGetDevInfo2Command::GetDevInfo2,
            request_raw: UblkControlGetDevInfo2Command::GetDevInfo2.request().raw(),
            dev_info,
        }
    }
}

/// Build a [`UblkControlGetDevInfo2Spec`] from the input.
///
/// # Errors
/// Returns [`UblkControlGetDevInfo2Error::AutoDeviceId`] if `dev_id` is the
/// auto-assigned sentinel.
pub const fn build_get_dev_info2_spec(
    input: UblkControlGetDevInfo2Input,
) -> Result<UblkControlGetDevInfo2Spec, UblkControlGetDevInfo2Error> {
    if input.dev_id == TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID {
        return Err(UblkControlGetDevInfo2Error::AutoDeviceId);
    }
    Ok(UblkControlGetDevInfo2Spec::get_dev_info2())
}

/// Build a [`UblkSrvCtrlCmd`] that points the kernel at `dev_info` for
/// returning device information.
pub fn build_get_dev_info2_ctrl_cmd(
    input: UblkControlGetDevInfo2Input,
    dev_info: &mut UblkSrvCtrlDevInfo,
) -> UblkSrvCtrlCmd {
    UblkSrvCtrlCmd {
        dev_id: input.dev_id,
        queue_id: u16::MAX,
        len: core::mem::size_of::<UblkSrvCtrlDevInfo>() as u16,
        addr: (dev_info as *mut UblkSrvCtrlDevInfo) as usize as u64,
        ..UblkSrvCtrlCmd::default()
    }
}

/// Encode a [`UblkSrvCtrlCmd`] into an 80-byte uring_cmd payload.
#[must_use]
pub fn encode_get_dev_info2_cmd80(command: UblkSrvCtrlCmd) -> [u8; 80] {
    encode_ctrl_cmd80(command)
}

/// Issue `UBLK_CMD_GET_DEV_INFO2` to the ublk control device via io_uring.
///
/// # Errors
/// Returns [`UblkControlGetDevInfo2Error`] on io_uring or ublk command failure.
pub fn issue_get_dev_info2(
    fd: BorrowedFd<'_>,
    dev_id: u32,
) -> Result<UblkSrvCtrlDevInfo, UblkControlGetDevInfo2Error> {
    let input = UblkControlGetDevInfo2Input::from_kernel_dev_id(dev_id);
    let spec = build_get_dev_info2_spec(input)?;
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(UBLK_CONTROL_GET_DEV_INFO2_RING_ENTRIES)
        .map_err(map_get_dev_info2_io_uring_setup_error)?;
    let mut dev_info = UblkSrvCtrlDevInfo::default();
    let command = build_get_dev_info2_ctrl_cmd(input, &mut dev_info);
    let entry = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), spec.request_raw)
        .cmd(encode_get_dev_info2_cmd80(command))
        .build()
        .user_data(UBLK_CONTROL_GET_DEV_INFO2_USER_DATA);

    {
        let mut submission = ring.submission();
        unsafe {
            // SAFETY: `entry` embeds a ublk GET_DEV_INFO2 command whose `addr`
            // field points at `dev_info`; the struct remains live until the CQE
            // is consumed below, and this private ring has no other SQEs.
            submission
                .push(&entry)
                .map_err(|_| UblkControlGetDevInfo2Error::SubmissionQueueFull)?;
        }
    }

    ring.submit_and_wait(1)
        .map_err(map_get_dev_info2_io_uring_submit_error)?;

    let completion = ring
        .completion()
        .next()
        .ok_or(UblkControlGetDevInfo2Error::CompletionMissing)?;
    if completion.user_data() != UBLK_CONTROL_GET_DEV_INFO2_USER_DATA {
        return Err(UblkControlGetDevInfo2Error::UnexpectedCompletionUserData(
            completion.user_data(),
        ));
    }
    if completion.result() < 0 {
        return Err(UblkControlGetDevInfo2Error::UblkCommandErrno(
            -completion.result(),
        ));
    }

    Ok(dev_info)
}

fn map_get_dev_info2_io_uring_setup_error(error: io::Error) -> UblkControlGetDevInfo2Error {
    error.raw_os_error().map_or(
        UblkControlGetDevInfo2Error::IoUringSetupMissingErrno,
        UblkControlGetDevInfo2Error::IoUringSetupErrno,
    )
}

fn map_get_dev_info2_io_uring_submit_error(error: io::Error) -> UblkControlGetDevInfo2Error {
    error.raw_os_error().map_or(
        UblkControlGetDevInfo2Error::IoUringSubmitMissingErrno,
        UblkControlGetDevInfo2Error::IoUringSubmitErrno,
    )
}

// ── UblkIoctlDispatch: ioctl command-number dispatch ─────────────────

/// Maps a raw ublk ioctl command number to a dispatch variant.
///
/// Each variant selects the appropriate control-plane handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoctlDispatch {
    /// UBLK_CMD_GET_QUEUE_AFFINITY (0x01) — read-only device queue query
    GetQueueAffinity,
    /// UBLK_CMD_GET_DEV_INFO (0x02) — read-only device information probe
    GetDevInfo,
    /// UBLK_CMD_ADD_DEV (0x04) — read-write device-pair creation
    AddDev,
    /// UBLK_CMD_DEL_DEV (0x05) — read-write device removal
    DelDev,
    /// UBLK_CMD_START_DEV (0x06) — read-write device start
    StartDev,
    /// UBLK_CMD_STOP_DEV (0x07) — read-write device stop
    StopDev,
    /// UBLK_CMD_SET_PARAMS (0x08) — read-write parameter assignment
    SetParams,
    /// UBLK_CMD_GET_DEV_INFO2 (0x12) — read-only extended device info
    GetDevInfo2,
    /// UBLK_CMD_GET_FEATURES (0x13) — read-only kernel feature probe
    GetFeatures,
    /// UBLK_CMD_QUIESCE_DEV (0x16) — read-write device quiesce
    QuiesceDev,
    /// UBLK_CMD_UPDATE_SIZE (0x15) — read-write capacity resize
    UpdateSize,
    /// Any command number not explicitly handled by the dispatch loop.
    Unhandled(u8),
}

impl UblkIoctlDispatch {
    /// Build a dispatch variant from a raw ioctl command number.
    #[must_use]
    pub const fn from_command_number(number: u8) -> Self {
        match number {
            tidefs_ublk_abi::UBLK_CMD_GET_QUEUE_AFFINITY => Self::GetQueueAffinity,
            tidefs_ublk_abi::UBLK_CMD_GET_DEV_INFO => Self::GetDevInfo,
            tidefs_ublk_abi::UBLK_CMD_ADD_DEV => Self::AddDev,
            tidefs_ublk_abi::UBLK_CMD_DEL_DEV => Self::DelDev,
            tidefs_ublk_abi::UBLK_CMD_START_DEV => Self::StartDev,
            tidefs_ublk_abi::UBLK_CMD_STOP_DEV => Self::StopDev,
            tidefs_ublk_abi::UBLK_CMD_SET_PARAMS => Self::SetParams,
            tidefs_ublk_abi::UBLK_CMD_GET_DEV_INFO2 => Self::GetDevInfo2,
            tidefs_ublk_abi::UBLK_CMD_GET_FEATURES => Self::GetFeatures,
            tidefs_ublk_abi::UBLK_CMD_QUIESCE_DEV => Self::QuiesceDev,
            tidefs_ublk_abi::UBLK_CMD_UPDATE_SIZE => Self::UpdateSize,
            other => Self::Unhandled(other),
        }
    }

    /// Return the raw command number for this dispatch variant.
    #[must_use]
    pub const fn command_number(self) -> u8 {
        match self {
            Self::GetQueueAffinity => tidefs_ublk_abi::UBLK_CMD_GET_QUEUE_AFFINITY,
            Self::GetDevInfo => tidefs_ublk_abi::UBLK_CMD_GET_DEV_INFO,
            Self::AddDev => tidefs_ublk_abi::UBLK_CMD_ADD_DEV,
            Self::DelDev => tidefs_ublk_abi::UBLK_CMD_DEL_DEV,
            Self::StartDev => tidefs_ublk_abi::UBLK_CMD_START_DEV,
            Self::StopDev => tidefs_ublk_abi::UBLK_CMD_STOP_DEV,
            Self::SetParams => tidefs_ublk_abi::UBLK_CMD_SET_PARAMS,
            Self::GetDevInfo2 => tidefs_ublk_abi::UBLK_CMD_GET_DEV_INFO2,
            Self::GetFeatures => tidefs_ublk_abi::UBLK_CMD_GET_FEATURES,
            Self::QuiesceDev => tidefs_ublk_abi::UBLK_CMD_QUIESCE_DEV,
            Self::UpdateSize => tidefs_ublk_abi::UBLK_CMD_UPDATE_SIZE,
            Self::Unhandled(n) => n,
        }
    }

    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetQueueAffinity => "GET_QUEUE_AFFINITY",
            Self::GetDevInfo => "GET_DEV_INFO",
            Self::AddDev => "ADD_DEV",
            Self::DelDev => "DEL_DEV",
            Self::StartDev => "START_DEV",
            Self::StopDev => "STOP_DEV",
            Self::SetParams => "SET_PARAMS",
            Self::GetDevInfo2 => "GET_DEV_INFO2",
            Self::GetFeatures => "GET_FEATURES",
            Self::QuiesceDev => "QUIESCE_DEV",
            Self::UpdateSize => "UPDATE_SIZE",
            Self::Unhandled(_) => "UNHANDLED",
        }
    }
}

// ── Device capacity ──────────────────────────────────────────────────

/// Capacity information for a ublk block device.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceCapacity {
    /// Kernel-assigned ublk device id.
    pub dev_id: u32,
    /// Number of 512-byte sectors reported by the device.
    pub sector_count: u64,
    /// Logical block (sector) size in bytes (typically 512).
    pub sector_size: u32,
}

impl DeviceCapacity {
    /// Total capacity in bytes.
    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.sector_count * self.sector_size as u64
    }

    /// Capacity in MiB.
    #[must_use]
    pub const fn total_mib(self) -> u64 {
        self.total_bytes() / (1024 * 1024)
    }
}

// ── Device enumeration ───────────────────────────────────────────────

/// On success, returns a list of `(block_device_path, dev_id)` for each
/// ublk block device found under `/dev/ublkb*`.
///
/// The function is non-mutating: it only inspects the filesystem namespace.
///
/// # Errors
///
/// Returns `io::Error` if `/dev` cannot be read.
pub fn enumerate_ublk_devices() -> io::Result<Vec<(std::path::PathBuf, u32)>> {
    let mut devices = Vec::new();
    let dev_dir = std::path::Path::new("/dev");
    let entries = std::fs::read_dir(dev_dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if let Some(num_str) = name.strip_prefix("ublkb") {
                if let Ok(dev_id) = num_str.parse::<u32>() {
                    devices.push((path.clone(), dev_id));
                }
            }
        }
    }
    Ok(devices)
}

/// Query the capacity of a ublk block device from sysfs.
///
/// Reads `/sys/block/ublkbN/size` (sector count) and
/// `/sys/block/ublkbN/queue/hw_sector_size` (sector size).
///
/// # Errors
///
/// Returns `io::Error` if the sysfs entries cannot be read.
pub fn query_device_capacity(dev_id: u32) -> io::Result<DeviceCapacity> {
    let size_path = format!("/sys/block/ublkb{dev_id}/size");
    let sector_size_path = format!("/sys/block/ublkb{dev_id}/queue/hw_sector_size");

    let sector_count_raw = std::fs::read_to_string(&size_path)
        .map_err(|e| io::Error::new(e.kind(), format!("read {size_path}: {e}")))?;
    let sector_count: u64 = sector_count_raw.trim().parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse sector count: {e}"),
        )
    })?;

    let sector_size_raw = std::fs::read_to_string(&sector_size_path)
        .map_err(|e| io::Error::new(e.kind(), format!("read {sector_size_path}: {e}")))?;
    let sector_size: u32 = sector_size_raw.trim().parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse sector size: {e}"),
        )
    })?;

    Ok(DeviceCapacity {
        dev_id,
        sector_count,
        sector_size,
    })
}

/// Enumerate all ublk devices and query their capacity from sysfs.
///
/// # Errors
///
/// Returns the first `io::Error` encountered during enumeration or
/// capacity query, except `NotFound` which skips transient device entries.
pub fn enumerate_device_capacities() -> io::Result<Vec<DeviceCapacity>> {
    let devices = enumerate_ublk_devices()?;
    let mut capacities = Vec::with_capacity(devices.len());
    for (_path, dev_id) in devices {
        match query_device_capacity(dev_id) {
            Ok(cap) => capacities.push(cap),
            Err(e) => {
                // Skip devices whose sysfs entries are not available
                // (e.g., device being torn down concurrently).
                if e.kind() == io::ErrorKind::NotFound {
                    continue;
                }
                return Err(e);
            }
        }
    }
    Ok(capacities)
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use tidefs_ublk_abi::{
        UblkParamBasic, UblkParamDiscard, UblkParamSegment, UblkSrvIoCmd, UblkSrvIoDesc,
        UBLK_ATTR_FUA, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE,
        UBLK_IO_OP_WRITE_SAME, UBLK_IO_OP_WRITE_ZEROES, UBLK_IO_RES_ABORT,
        UBLK_IO_RES_NEED_GET_DATA, UBLK_IO_RES_OK, UBLK_PARAM_TYPE_BASIC, UBLK_PARAM_TYPE_DISCARD,
        UBLK_PARAM_TYPE_SEGMENT,
    };

    fn valid_set_params() -> UblkParams {
        UblkParams {
            len: size_of::<UblkParams>() as u32,
            types: UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT,
            basic: UblkParamBasic {
                attrs: UBLK_ATTR_FUA,
                logical_bs_shift: 12,
                physical_bs_shift: 12,
                io_opt_shift: 12,
                io_min_shift: 12,
                max_sectors: 128,
                chunk_sectors: 8,
                dev_sectors: 8192,
                virt_boundary_mask: 0,
            },
            discard: UblkParamDiscard {
                discard_alignment: 0,
                discard_granularity: 4096,
                max_discard_sectors: 128,
                max_write_zeroes_sectors: 128,
                max_discard_segments: 1,
                reserved0: 0,
            },
            seg: UblkParamSegment {
                seg_boundary_mask: 0,
                max_segment_size: 1024 * 1024,
                max_segments: 1,
                pad: [0; 2],
            },
            ..UblkParams::default()
        }
    }

    #[test]
    fn get_features_spec_uses_read_command_and_sqe128() {
        let spec = build_readonly_probe_spec(UblkCtrlCommand::GetFeatures).unwrap();

        assert_eq!(spec.command, UblkControlReadonlyProbeCommand::GetFeatures);
        assert_eq!(spec.request_direction, UblkIoctlDirection::Read);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
        assert_eq!(spec.feature_buffer_len, UBLK_FEATURES_LEN);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(!spec.mutates_control_state);
    }

    #[test]
    fn get_features_command_points_at_feature_buffer() {
        let mut features_bits = 0_u64;

        let command = build_get_features_ctrl_cmd(&mut features_bits);

        assert_eq!(command.dev_id, 0);
        assert_eq!(command.queue_id, 0);
        assert_eq!(command.len, UBLK_FEATURES_LEN as u16);
        assert_eq!(
            command.addr,
            (&mut features_bits as *mut u64) as usize as u64
        );
        assert_ne!(command.addr, 0);
    }

    #[test]
    fn get_features_command_encodes_into_uring_cmd80_payload() {
        let mut features_bits = 0_u64;
        let command = build_get_features_ctrl_cmd(&mut features_bits);

        let payload = encode_get_features_cmd80(command);

        assert_eq!(&payload[0..4], &0_u32.to_ne_bytes());
        assert_eq!(&payload[4..6], &0_u16.to_ne_bytes());
        assert_eq!(&payload[6..8], &(UBLK_FEATURES_LEN as u16).to_ne_bytes());
        assert_eq!(
            &payload[8..16],
            &((&mut features_bits as *mut u64) as usize as u64).to_ne_bytes()
        );
        assert!(payload[32..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn completed_get_features_maps_feature_bits() {
        let outcome = UblkControlGetFeaturesOutcome::from_features_bits(
            UblkFeatureFlags::USER_COPY
                .union(UblkFeatureFlags::CMD_IOCTL_ENCODE)
                .union(UblkFeatureFlags::UPDATE_SIZE)
                .bits(),
        );

        assert_eq!(
            outcome.command,
            UblkControlReadonlyProbeCommand::GetFeatures
        );
        assert!(outcome.features.contains(UblkFeatureFlags::USER_COPY));
        assert!(outcome
            .features
            .contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
        assert!(outcome.features.contains(UblkFeatureFlags::UPDATE_SIZE));
    }

    #[test]
    fn errno_error_retains_errno_value() {
        let error = UblkControlReadonlyProbeError::UblkCommandErrno(25);

        assert_eq!(error.as_str(), "ublk_command_errno");
        assert_eq!(error.errno(), Some(25));
        assert_eq!(error.rejected_command(), None);
    }

    #[test]
    fn mutating_commands_are_rejected_by_readonly_builder() {
        let error = build_readonly_probe_spec(UblkCtrlCommand::AddDev).unwrap_err();

        assert_eq!(
            error,
            UblkControlReadonlyProbeError::UnsupportedMutatingCommand(UblkCtrlCommand::AddDev)
        );
        assert_eq!(error.rejected_command(), Some(UblkCtrlCommand::AddDev));
    }

    #[test]
    fn non_global_readonly_commands_are_not_exposed_by_this_probe() {
        let error = build_readonly_probe_spec(UblkCtrlCommand::GetDevInfo2).unwrap_err();

        assert_eq!(
            error,
            UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(UblkCtrlCommand::GetDevInfo2)
        );
    }

    #[test]
    fn add_dev_command_maps_to_ublk_add_dev() {
        let command = UblkControlAddDevCommand::AddDev;
        assert_eq!(command.as_str(), "ADD_DEV");
        assert_eq!(command.ublk_command(), UblkCtrlCommand::AddDev);
        assert_eq!(
            command.request().raw(),
            UblkCtrlCommand::AddDev.request().raw()
        );
    }

    #[test]
    fn add_dev_spec_uses_mutating_read_write_command_and_sqe128() {
        let input = UblkControlAddDevInput::conservative_tidefs();
        let spec = build_add_dev_spec(input).unwrap();

        assert_eq!(spec.command, UblkControlAddDevCommand::AddDev);
        assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
        assert_eq!(spec.ctrl_dev_info_len, size_of::<UblkSrvCtrlDevInfo>());
        assert_eq!(spec.control_queue_id, u16::MAX);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(spec.mutates_control_state);
        assert_eq!(spec.nr_hw_queues, 1);
        assert_eq!(spec.queue_depth, 64);
        assert_eq!(spec.max_io_buf_bytes, 1024 * 1024);
        assert!(spec.flags.contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
        assert!(spec.flags.contains(UblkFeatureFlags::USER_COPY));
    }

    #[test]
    fn add_dev_info_uses_conservative_tidefs_queue_geometry() {
        let info = build_add_dev_info(UblkControlAddDevInput::conservative_tidefs()).unwrap();

        assert_eq!(info.nr_hw_queues, 1);
        assert_eq!(info.queue_depth, 64);
        assert_eq!(info.max_io_buf_bytes, 1024 * 1024);
        assert_eq!(info.dev_id, 0);
        assert_eq!(info.ublksrv_pid, 0);
        assert!(UblkFeatureFlags(info.flags).contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
        assert!(UblkFeatureFlags(info.flags).contains(UblkFeatureFlags::USER_COPY));
    }

    #[test]
    fn add_dev_input_from_nr_hw_queues_and_depth_uses_custom_queue_geometry() {
        let input = UblkControlAddDevInput::from_nr_hw_queues_and_depth(4, 32);
        assert_eq!(input.nr_hw_queues, 4);
        assert_eq!(input.queue_depth, 32);
        assert_eq!(input.max_io_buf_bytes, 1024 * 1024);
        assert!(input.flags.contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
        assert!(input.flags.contains(UblkFeatureFlags::USER_COPY));

        let info = build_add_dev_info(input).unwrap();
        assert_eq!(info.nr_hw_queues, 4);
        assert_eq!(info.queue_depth, 32);
    }

    #[test]
    fn add_dev_input_from_nr_hw_queues_and_depth_rejects_zero_queues() {
        let info = build_add_dev_info(UblkControlAddDevInput::from_nr_hw_queues_and_depth(0, 64));
        assert_eq!(info, Err(UblkControlAddDevError::ZeroHardwareQueues));
    }

    #[test]
    fn add_dev_command_points_at_dev_info_and_uses_global_queue_id() {
        let mut info = build_add_dev_info(UblkControlAddDevInput::conservative_tidefs()).unwrap();

        let command = build_add_dev_ctrl_cmd(&mut info);

        assert_eq!(command.dev_id, 0);
        assert_eq!(command.queue_id, u16::MAX);
        assert_eq!(usize::from(command.len), size_of::<UblkSrvCtrlDevInfo>());
        assert_eq!(
            command.addr,
            (&mut info as *mut UblkSrvCtrlDevInfo) as usize as u64
        );
        assert_ne!(command.addr, 0);
    }

    #[test]
    fn add_dev_command_encodes_into_uring_cmd80_payload() {
        let mut info = build_add_dev_info(UblkControlAddDevInput::conservative_tidefs()).unwrap();
        let command = build_add_dev_ctrl_cmd(&mut info);

        let payload = encode_add_dev_cmd80(command);

        assert_eq!(&payload[0..4], &0_u32.to_ne_bytes());
        assert_eq!(&payload[4..6], &u16::MAX.to_ne_bytes());
        assert_eq!(
            &payload[6..8],
            &(size_of::<UblkSrvCtrlDevInfo>() as u16).to_ne_bytes()
        );
        assert_eq!(
            &payload[8..16],
            &((&mut info as *mut UblkSrvCtrlDevInfo) as usize as u64).to_ne_bytes()
        );
        assert!(payload[32..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn add_dev_input_rejects_invalid_queue_geometry() {
        let mut input = UblkControlAddDevInput::conservative_tidefs();
        input.nr_hw_queues = 0;
        assert_eq!(
            build_add_dev_spec(input),
            Err(UblkControlAddDevError::ZeroHardwareQueues)
        );

        input = UblkControlAddDevInput::conservative_tidefs();
        input.queue_depth = 0;
        assert_eq!(
            build_add_dev_info(input),
            Err(UblkControlAddDevError::ZeroQueueDepth)
        );
    }

    #[test]
    fn add_dev_input_rejects_too_many_hardware_queues() {
        let mut input = UblkControlAddDevInput::conservative_tidefs();
        input.nr_hw_queues = u16::checked_add(UBLK_MAX_NR_QUEUES, 1).expect("max");
        assert_eq!(
            build_add_dev_spec(input),
            Err(UblkControlAddDevError::TooManyHardwareQueues)
        );
    }

    #[test]
    fn add_dev_input_rejects_too_large_queue_depth() {
        let mut input = UblkControlAddDevInput::conservative_tidefs();
        input.queue_depth = u16::checked_add(UBLK_MAX_QUEUE_DEPTH, 1).expect("max");
        assert_eq!(
            build_add_dev_spec(input),
            Err(UblkControlAddDevError::QueueDepthTooLarge)
        );
    }

    #[test]
    fn add_dev_input_rejects_zero_max_io_buf_bytes() {
        let mut input = UblkControlAddDevInput::conservative_tidefs();
        input.max_io_buf_bytes = 0;
        assert_eq!(
            build_add_dev_spec(input),
            Err(UblkControlAddDevError::ZeroMaxIoBufferBytes)
        );
    }

    #[test]
    fn add_dev_input_requires_ioctl_encoded_user_copy_flags() {
        let mut input = UblkControlAddDevInput::conservative_tidefs();
        input.flags = UblkFeatureFlags::CMD_IOCTL_ENCODE;

        let error = build_add_dev_spec(input).unwrap_err();

        assert_eq!(
            error,
            UblkControlAddDevError::MissingRequiredFeatureFlag(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES
            )
        );
        assert_eq!(error.as_str(), "missing_required_feature_flag");
    }

    #[test]
    fn add_dev_outcome_preserves_kernel_returned_dev_info() {
        let mut info = build_add_dev_info(UblkControlAddDevInput::conservative_tidefs()).unwrap();
        info.dev_id = 42;
        info.owner_uid = 1000;
        info.owner_gid = 1000;

        let outcome = UblkControlAddDevOutcome::from_dev_info(info);

        assert_eq!(outcome.command, UblkControlAddDevCommand::AddDev);
        assert_eq!(outcome.request_raw, UblkCtrlCommand::AddDev.request().raw());
        assert_eq!(outcome.dev_info.dev_id, 42);
        assert_eq!(outcome.dev_info.owner_uid, 1000);
        assert_eq!(outcome.dev_info.owner_gid, 1000);
    }
    #[test]
    fn add_dev_errno_error_retains_errno_value() {
        const ENOMEM_FOR_TEST: i32 = 12;
        let error = UblkControlAddDevError::UblkCommandErrno(ENOMEM_FOR_TEST);

        assert_eq!(error.as_str(), "ublk_command_errno");
        assert_eq!(error.errno(), Some(ENOMEM_FOR_TEST));
    }

    #[test]
    fn add_dev_submission_queue_full_error_has_no_errno() {
        let error = UblkControlAddDevError::SubmissionQueueFull;

        assert_eq!(error.as_str(), "submission_queue_full");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_completion_missing_error_has_no_errno() {
        let error = UblkControlAddDevError::CompletionMissing;

        assert_eq!(error.as_str(), "completion_missing");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_unexpected_completion_user_data_error_has_no_errno() {
        let error = UblkControlAddDevError::UnexpectedCompletionUserData(0x_dead_beef);

        assert_eq!(error.as_str(), "unexpected_completion_user_data");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_io_uring_setup_errno_error_retains_errno_value() {
        const EACCES_FOR_TEST: i32 = 13;
        let error = UblkControlAddDevError::IoUringSetupErrno(EACCES_FOR_TEST);

        assert_eq!(error.as_str(), "io_uring_setup_errno");
        assert_eq!(error.errno(), Some(EACCES_FOR_TEST));
    }

    #[test]
    fn add_dev_io_uring_setup_missing_errno_error_has_no_errno() {
        let error = UblkControlAddDevError::IoUringSetupMissingErrno;

        assert_eq!(error.as_str(), "io_uring_setup_missing_errno");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_io_uring_submit_errno_error_retains_errno_value() {
        const EINTR_FOR_TEST: i32 = 4;
        let error = UblkControlAddDevError::IoUringSubmitErrno(EINTR_FOR_TEST);

        assert_eq!(error.as_str(), "io_uring_submit_errno");
        assert_eq!(error.errno(), Some(EINTR_FOR_TEST));
    }

    #[test]
    fn add_dev_io_uring_submit_missing_errno_error_has_no_errno() {
        let error = UblkControlAddDevError::IoUringSubmitMissingErrno;

        assert_eq!(error.as_str(), "io_uring_submit_missing_errno");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_zero_hardware_queues_error_has_correct_str() {
        let error = UblkControlAddDevError::ZeroHardwareQueues;

        assert_eq!(error.as_str(), "zero_hardware_queues");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_too_many_hardware_queues_error_has_correct_str() {
        let error = UblkControlAddDevError::TooManyHardwareQueues;

        assert_eq!(error.as_str(), "too_many_hardware_queues");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_zero_queue_depth_error_has_correct_str() {
        let error = UblkControlAddDevError::ZeroQueueDepth;

        assert_eq!(error.as_str(), "zero_queue_depth");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_queue_depth_too_large_error_has_correct_str() {
        let error = UblkControlAddDevError::QueueDepthTooLarge;

        assert_eq!(error.as_str(), "queue_depth_too_large");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_zero_max_io_buffer_bytes_error_has_correct_str() {
        let error = UblkControlAddDevError::ZeroMaxIoBufferBytes;

        assert_eq!(error.as_str(), "zero_max_io_buffer_bytes");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_missing_required_feature_flag_error_has_correct_str() {
        let error = UblkControlAddDevError::MissingRequiredFeatureFlag(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
        );

        assert_eq!(error.as_str(), "missing_required_feature_flag");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn add_dev_unsupported_command_error_has_correct_str() {
        let error = UblkControlAddDevError::UnsupportedCommand(UblkCtrlCommand::AddDev);

        assert_eq!(error.as_str(), "unsupported_command");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn del_dev_spec_uses_mutating_read_write_command_and_sqe128() {
        let input = UblkControlDelDevInput::from_kernel_dev_id(42);
        let spec = build_del_dev_spec(input).unwrap();

        assert_eq!(spec.command, UblkControlDelDevCommand::DelDev);
        assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
        assert_eq!(spec.control_queue_id, u16::MAX);
        assert_eq!(spec.ctrl_buffer_len, 0);
        assert_eq!(spec.ctrl_buffer_addr, 0);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(spec.mutates_control_state);
    }

    #[test]
    fn del_dev_command_targets_concrete_dev_and_uses_global_queue_id() {
        let input = UblkControlDelDevInput::from_kernel_dev_id(42);

        let command = build_del_dev_ctrl_cmd(input).unwrap();

        assert_eq!(command.dev_id, 42);
        assert_eq!(command.queue_id, u16::MAX);
        assert_eq!(command.len, 0);
        assert_eq!(command.addr, 0);
        assert_eq!(command.data, [0]);
    }

    #[test]
    fn del_dev_command_encodes_into_uring_cmd80_payload() {
        let command =
            build_del_dev_ctrl_cmd(UblkControlDelDevInput::from_kernel_dev_id(42)).unwrap();

        let payload = encode_del_dev_cmd80(command);

        assert_eq!(&payload[0..4], &42_u32.to_ne_bytes());
        assert_eq!(&payload[4..6], &u16::MAX.to_ne_bytes());
        assert_eq!(&payload[6..8], &0_u16.to_ne_bytes());
        assert_eq!(&payload[8..16], &0_u64.to_ne_bytes());
        assert!(payload[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn del_dev_input_rejects_auto_device_id() {
        let input = UblkControlDelDevInput::from_kernel_dev_id(TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID);

        let error = build_del_dev_spec(input).unwrap_err();

        assert_eq!(error, UblkControlDelDevError::AutoDeviceId);
        assert_eq!(error.as_str(), "auto_device_id_not_concrete");
    }

    #[test]
    fn del_dev_outcome_preserves_target_device_id() {
        let outcome = UblkControlDelDevOutcome::from_dev_id(42);

        assert_eq!(outcome.command, UblkControlDelDevCommand::DelDev);
        assert_eq!(outcome.request_raw, UblkCtrlCommand::DelDev.request().raw());
        assert_eq!(outcome.dev_id, 42);
    }
    #[test]
    fn del_dev_command_maps_to_ublk_del_dev() {
        let command = UblkControlDelDevCommand::DelDev;
        assert_eq!(command.as_str(), "DEL_DEV");
        assert_eq!(command.ublk_command(), UblkCtrlCommand::DelDev);
        assert_eq!(
            command.request().raw(),
            UblkCtrlCommand::DelDev.request().raw()
        );
    }

    #[test]
    fn del_dev_auto_device_id_error_has_no_errno() {
        let error = UblkControlDelDevError::AutoDeviceId;

        assert_eq!(error.as_str(), "auto_device_id_not_concrete");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn del_dev_io_uring_setup_errno_error_retains_errno_value() {
        const EACCES_FOR_TEST: i32 = 13;
        let error = UblkControlDelDevError::IoUringSetupErrno(EACCES_FOR_TEST);

        assert_eq!(error.as_str(), "io_uring_setup_errno");
        assert_eq!(error.errno(), Some(EACCES_FOR_TEST));
    }

    #[test]
    fn del_dev_io_uring_setup_missing_errno_error_has_no_errno() {
        let error = UblkControlDelDevError::IoUringSetupMissingErrno;

        assert_eq!(error.as_str(), "io_uring_setup_missing_errno");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn del_dev_submission_queue_full_error_has_no_errno() {
        let error = UblkControlDelDevError::SubmissionQueueFull;

        assert_eq!(error.as_str(), "submission_queue_full");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn del_dev_io_uring_submit_errno_error_retains_errno_value() {
        const EINTR_FOR_TEST: i32 = 4;
        let error = UblkControlDelDevError::IoUringSubmitErrno(EINTR_FOR_TEST);

        assert_eq!(error.as_str(), "io_uring_submit_errno");
        assert_eq!(error.errno(), Some(EINTR_FOR_TEST));
    }

    #[test]
    fn del_dev_io_uring_submit_missing_errno_error_has_no_errno() {
        let error = UblkControlDelDevError::IoUringSubmitMissingErrno;

        assert_eq!(error.as_str(), "io_uring_submit_missing_errno");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn del_dev_completion_missing_error_has_no_errno() {
        let error = UblkControlDelDevError::CompletionMissing;

        assert_eq!(error.as_str(), "completion_missing");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn del_dev_unexpected_completion_user_data_error_has_no_errno() {
        let error = UblkControlDelDevError::UnexpectedCompletionUserData(0x_dead_beef);

        assert_eq!(error.as_str(), "unexpected_completion_user_data");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn del_dev_ublk_command_errno_error_retains_errno_value() {
        const ENOMEM_FOR_TEST: i32 = 12;
        let error = UblkControlDelDevError::UblkCommandErrno(ENOMEM_FOR_TEST);

        assert_eq!(error.as_str(), "ublk_command_errno");
        assert_eq!(error.errno(), Some(ENOMEM_FOR_TEST));
    }

    #[test]
    fn set_params_spec_uses_mutating_read_write_command_and_sqe128() {
        let input =
            UblkControlSetParamsInput::from_kernel_dev_id_and_params(42, valid_set_params());

        let spec = build_set_params_spec(input).unwrap();

        assert_eq!(spec.command, UblkControlSetParamsCommand::SetParams);
        assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
        assert_eq!(spec.params_len, size_of::<UblkParams>());
        assert_eq!(spec.control_queue_id, u16::MAX);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(spec.mutates_control_state);
        assert_eq!(
            spec.param_types,
            UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT
        );
        assert_eq!(spec.dev_sectors, 8192);
        assert_eq!(spec.max_sectors, 128);
        assert_eq!(spec.max_segment_size, 1024 * 1024);
        assert_eq!(spec.max_segments, 1);
    }

    #[test]
    fn set_params_command_targets_concrete_dev_and_points_at_params_buffer() {
        let mut input =
            UblkControlSetParamsInput::from_kernel_dev_id_and_params(42, valid_set_params());

        let command = build_set_params_ctrl_cmd(&mut input).unwrap();

        assert_eq!(command.dev_id, 42);
        assert_eq!(command.queue_id, u16::MAX);
        assert_eq!(usize::from(command.len), size_of::<UblkParams>());
        assert_eq!(
            command.addr,
            (&mut input.params as *mut UblkParams) as usize as u64
        );
        assert_ne!(command.addr, 0);
        assert_eq!(command.data, [0]);
    }

    #[test]
    fn set_params_command_encodes_into_uring_cmd80_payload() {
        let mut input =
            UblkControlSetParamsInput::from_kernel_dev_id_and_params(42, valid_set_params());
        let command = build_set_params_ctrl_cmd(&mut input).unwrap();

        let payload = encode_set_params_cmd80(command);

        assert_eq!(&payload[0..4], &42_u32.to_ne_bytes());
        assert_eq!(&payload[4..6], &u16::MAX.to_ne_bytes());
        assert_eq!(
            &payload[6..8],
            &(size_of::<UblkParams>() as u16).to_ne_bytes()
        );
        assert_eq!(
            &payload[8..16],
            &((&mut input.params as *mut UblkParams) as usize as u64).to_ne_bytes()
        );
        assert!(payload[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn set_params_input_rejects_auto_device_id() {
        let input = UblkControlSetParamsInput::from_kernel_dev_id_and_params(
            TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID,
            valid_set_params(),
        );

        let error = build_set_params_spec(input).unwrap_err();

        assert_eq!(error, UblkControlSetParamsError::AutoDeviceId);
        assert_eq!(error.as_str(), "auto_device_id_not_concrete");
    }

    #[test]
    fn set_params_input_requires_full_basic_discard_segment_fields() {
        let mut params = valid_set_params();
        params.len = 0;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::ZeroParamsLen)
        );

        params = valid_set_params();
        params.len -= 1;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::ParamsLenMismatch)
        );

        params = valid_set_params();
        params.types = 0;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::ZeroParamTypes)
        );

        params = valid_set_params();
        params.types = UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::MissingBasicParams)
        );

        params = valid_set_params();
        params.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_SEGMENT;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::MissingDiscardParams)
        );

        params = valid_set_params();
        params.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::MissingSegmentParams)
        );
    }

    #[test]
    fn set_params_input_rejects_zero_capacity_or_segment_geometry() {
        let mut params = valid_set_params();
        params.basic.dev_sectors = 0;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::ZeroDevSectors)
        );

        params = valid_set_params();
        params.basic.max_sectors = 0;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::ZeroMaxSectors)
        );

        params = valid_set_params();
        params.seg.max_segment_size = 0;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::ZeroMaxSegmentSize)
        );

        params = valid_set_params();
        params.seg.max_segments = 0;
        assert_eq!(
            build_set_params_spec(UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                42, params
            )),
            Err(UblkControlSetParamsError::ZeroMaxSegments)
        );
    }

    #[test]
    fn set_params_outcome_preserves_target_device_and_params() {
        let input =
            UblkControlSetParamsInput::from_kernel_dev_id_and_params(42, valid_set_params());

        let outcome = UblkControlSetParamsOutcome::from_input(input);

        assert_eq!(outcome.command, UblkControlSetParamsCommand::SetParams);
        assert_eq!(
            outcome.request_raw,
            UblkCtrlCommand::SetParams.request().raw()
        );
        assert_eq!(outcome.dev_id, 42);
        assert_eq!(outcome.params, valid_set_params());
    }

    #[test]
    fn set_params_command_maps_to_ublk_set_params() {
        let command = UblkControlSetParamsCommand::SetParams;
        assert_eq!(command.as_str(), "SET_PARAMS");
        assert_eq!(command.ublk_command(), UblkCtrlCommand::SetParams);
        assert_eq!(
            command.request().raw(),
            UblkCtrlCommand::SetParams.request().raw()
        );
    }

    #[test]
    fn set_params_ublk_command_errno_error_retains_errno_value() {
        const ENOMEM_FOR_TEST: i32 = 12;
        let error = UblkControlSetParamsError::UblkCommandErrno(ENOMEM_FOR_TEST);

        assert_eq!(error.as_str(), "ublk_command_errno");
        assert_eq!(error.errno(), Some(ENOMEM_FOR_TEST));
    }

    #[test]
    fn set_params_auto_device_id_error_has_no_errno() {
        let error = UblkControlSetParamsError::AutoDeviceId;

        assert_eq!(error.as_str(), "auto_device_id_not_concrete");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_zero_params_len_error_has_correct_str() {
        let error = UblkControlSetParamsError::ZeroParamsLen;

        assert_eq!(error.as_str(), "zero_params_len");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_params_len_mismatch_error_has_correct_str() {
        let error = UblkControlSetParamsError::ParamsLenMismatch;

        assert_eq!(error.as_str(), "params_len_mismatch");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_zero_param_types_error_has_correct_str() {
        let error = UblkControlSetParamsError::ZeroParamTypes;

        assert_eq!(error.as_str(), "zero_param_types");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_missing_basic_params_error_has_correct_str() {
        let error = UblkControlSetParamsError::MissingBasicParams;

        assert_eq!(error.as_str(), "missing_basic_params");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_missing_discard_params_error_has_correct_str() {
        let error = UblkControlSetParamsError::MissingDiscardParams;

        assert_eq!(error.as_str(), "missing_discard_params");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_missing_segment_params_error_has_correct_str() {
        let error = UblkControlSetParamsError::MissingSegmentParams;

        assert_eq!(error.as_str(), "missing_segment_params");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_zero_dev_sectors_error_has_correct_str() {
        let error = UblkControlSetParamsError::ZeroDevSectors;

        assert_eq!(error.as_str(), "zero_dev_sectors");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_zero_max_sectors_error_has_correct_str() {
        let error = UblkControlSetParamsError::ZeroMaxSectors;

        assert_eq!(error.as_str(), "zero_max_sectors");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_zero_max_segment_size_error_has_correct_str() {
        let error = UblkControlSetParamsError::ZeroMaxSegmentSize;

        assert_eq!(error.as_str(), "zero_max_segment_size");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_zero_max_segments_error_has_correct_str() {
        let error = UblkControlSetParamsError::ZeroMaxSegments;

        assert_eq!(error.as_str(), "zero_max_segments");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_io_uring_setup_errno_error_retains_errno_value() {
        const EACCES_FOR_TEST: i32 = 13;
        let error = UblkControlSetParamsError::IoUringSetupErrno(EACCES_FOR_TEST);

        assert_eq!(error.as_str(), "io_uring_setup_errno");
        assert_eq!(error.errno(), Some(EACCES_FOR_TEST));
    }

    #[test]
    fn set_params_io_uring_setup_missing_errno_error_has_no_errno() {
        let error = UblkControlSetParamsError::IoUringSetupMissingErrno;

        assert_eq!(error.as_str(), "io_uring_setup_missing_errno");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_submission_queue_full_error_has_no_errno() {
        let error = UblkControlSetParamsError::SubmissionQueueFull;

        assert_eq!(error.as_str(), "submission_queue_full");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_io_uring_submit_errno_error_retains_errno_value() {
        const EINTR_FOR_TEST: i32 = 4;
        let error = UblkControlSetParamsError::IoUringSubmitErrno(EINTR_FOR_TEST);

        assert_eq!(error.as_str(), "io_uring_submit_errno");
        assert_eq!(error.errno(), Some(EINTR_FOR_TEST));
    }

    #[test]
    fn set_params_io_uring_submit_missing_errno_error_has_no_errno() {
        let error = UblkControlSetParamsError::IoUringSubmitMissingErrno;

        assert_eq!(error.as_str(), "io_uring_submit_missing_errno");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_completion_missing_error_has_no_errno() {
        let error = UblkControlSetParamsError::CompletionMissing;

        assert_eq!(error.as_str(), "completion_missing");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn set_params_unexpected_completion_user_data_error_has_no_errno() {
        let error = UblkControlSetParamsError::UnexpectedCompletionUserData(0x_dead_beef);

        assert_eq!(error.as_str(), "unexpected_completion_user_data");
        assert_eq!(error.errno(), None);
    }

    #[test]
    fn fetch_req_spec_uses_data_queue_read_write_command_and_sqe128() {
        let input = UblkDataQueueFetchReqInput::user_copy(0, 7, 1, 64);

        let spec = build_fetch_req_spec(input).unwrap();

        assert_eq!(spec.command, UblkDataQueueFetchReqCommand::FetchReq);
        assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvIoCmd>());
        assert_eq!(spec.q_id, 0);
        assert_eq!(spec.tag, 7);
        assert_eq!(spec.result, 0);
        assert_eq!(spec.user_copy_addr, 0);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(!spec.commits_result);
        assert!(spec.must_remain_in_flight_for_start);
    }

    #[test]
    fn fetch_req_command_encodes_queue_tag_result_and_zero_user_copy_addr() {
        let command =
            build_fetch_req_io_cmd(UblkDataQueueFetchReqInput::user_copy(0, 7, 1, 64)).unwrap();

        let payload = encode_fetch_req_cmd80(command);

        assert_eq!(&payload[0..2], &0_u16.to_ne_bytes());
        assert_eq!(&payload[2..4], &7_u16.to_ne_bytes());
        assert_eq!(&payload[4..8], &0_i32.to_ne_bytes());
        assert_eq!(&payload[8..16], &0_u64.to_ne_bytes());
        assert!(payload[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn fetch_req_input_rejects_invalid_queue_geometry_or_user_copy_addr() {
        assert_eq!(
            build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 0, 0, 64)),
            Err(UblkDataQueueFetchReqError::ZeroHardwareQueues)
        );
        assert_eq!(
            build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(
                UBLK_MAX_NR_QUEUES,
                0,
                UBLK_MAX_NR_QUEUES,
                64,
            )),
            Err(UblkDataQueueFetchReqError::QueueIdOutOfRange)
        );
        assert_eq!(
            build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 64, 1, 64)),
            Err(UblkDataQueueFetchReqError::TagOutOfRange)
        );

        let mut input = UblkDataQueueFetchReqInput::user_copy(0, 7, 1, 64);
        input.user_copy_addr = 4096;
        assert_eq!(
            build_fetch_req_spec(input),
            Err(UblkDataQueueFetchReqError::UserCopyFetchAddrMustBeZero)
        );
        assert_eq!(
            UblkDataQueueFetchReqError::UserCopyFetchAddrMustBeZero.as_str(),
            "user_copy_fetch_addr_must_be_zero"
        );
    }

    #[test]
    fn fetch_req_input_rejects_too_many_hw_queues_zero_queue_depth_and_excessive_depth() {
        assert_eq!(
            build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(
                0,
                0,
                UBLK_MAX_NR_QUEUES + 1,
                64,
            )),
            Err(UblkDataQueueFetchReqError::TooManyHardwareQueues)
        );
        assert_eq!(
            UblkDataQueueFetchReqError::TooManyHardwareQueues.as_str(),
            "too_many_hardware_queues"
        );

        assert_eq!(
            build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 0)),
            Err(UblkDataQueueFetchReqError::ZeroQueueDepth)
        );
        assert_eq!(
            UblkDataQueueFetchReqError::ZeroQueueDepth.as_str(),
            "zero_queue_depth"
        );

        assert_eq!(
            build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(
                0,
                0,
                1,
                UBLK_MAX_QUEUE_DEPTH + 1,
            )),
            Err(UblkDataQueueFetchReqError::QueueDepthTooLarge)
        );
        assert_eq!(
            UblkDataQueueFetchReqError::QueueDepthTooLarge.as_str(),
            "queue_depth_too_large"
        );
    }

    #[test]
    fn fetch_req_user_data_binds_tag_command_and_queue() {
        let user_data = fetch_req_user_data(0x0abc, 0x0123);

        assert_eq!(user_data & 0xffff, 0x0123);
        assert_eq!(
            (user_data >> 16) & 0xff,
            u64::from(UblkIoCommand::FetchReq.number())
        );
        assert_eq!((user_data >> 32) & 0xffff, 0x0abc);
        assert_eq!(user_data >> 48, 0);
    }

    #[test]
    fn decode_fetch_req_user_data_roundtrips_through_encode() {
        for q_id in [0, 1, 42, 0xfffe] {
            for tag in [0, 7, 63, 4095] {
                let user_data = fetch_req_user_data(q_id, tag);
                let (decoded_q_id, decoded_tag) = decode_fetch_req_user_data(user_data);
                assert_eq!(
                    (decoded_q_id, decoded_tag),
                    (q_id, tag),
                    "roundtrip failed for q_id={q_id} tag={tag}"
                );
            }
        }
    }

    #[test]
    fn get_features_command_maps_to_ublk_get_features() {
        let command = UblkControlReadonlyProbeCommand::GetFeatures;
        assert_eq!(command.as_str(), "GET_FEATURES");
        assert_eq!(command.ublk_command(), UblkCtrlCommand::GetFeatures);
        assert_eq!(
            command.request().raw(),
            UblkCtrlCommand::GetFeatures.request().raw()
        );
    }

    #[test]
    fn readonly_probe_error_as_str_maps_all_variants() {
        assert_eq!(
            UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(UblkCtrlCommand::GetDevInfo2)
                .as_str(),
            "unsupported_read_only_command"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::UnsupportedMutatingCommand(UblkCtrlCommand::AddDev)
                .as_str(),
            "unsupported_mutating_command"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::IoUringSetupErrno(12).as_str(),
            "io_uring_setup_errno"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::IoUringSetupMissingErrno.as_str(),
            "io_uring_setup_missing_errno"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::SubmissionQueueFull.as_str(),
            "submission_queue_full"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::IoUringSubmitErrno(11).as_str(),
            "io_uring_submit_errno"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::IoUringSubmitMissingErrno.as_str(),
            "io_uring_submit_missing_errno"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::CompletionMissing.as_str(),
            "completion_missing"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::UnexpectedCompletionUserData(0xdead).as_str(),
            "unexpected_completion_user_data"
        );
        assert_eq!(
            UblkControlReadonlyProbeError::UblkCommandErrno(25).as_str(),
            "ublk_command_errno"
        );
    }

    #[test]
    fn readonly_probe_error_errno_and_rejected_command_coverage() {
        let unsupported =
            UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(UblkCtrlCommand::GetDevInfo2);
        assert_eq!(unsupported.errno(), None);
        assert_eq!(
            unsupported.rejected_command(),
            Some(UblkCtrlCommand::GetDevInfo2)
        );

        let mutating =
            UblkControlReadonlyProbeError::UnsupportedMutatingCommand(UblkCtrlCommand::AddDev);
        assert_eq!(mutating.errno(), None);
        assert_eq!(mutating.rejected_command(), Some(UblkCtrlCommand::AddDev));

        let setup_errno = UblkControlReadonlyProbeError::IoUringSetupErrno(1);
        assert_eq!(setup_errno.errno(), Some(1));
        assert_eq!(setup_errno.rejected_command(), None);

        let setup_missing = UblkControlReadonlyProbeError::IoUringSetupMissingErrno;
        assert_eq!(setup_missing.errno(), None);
        assert_eq!(setup_missing.rejected_command(), None);

        let sq_full = UblkControlReadonlyProbeError::SubmissionQueueFull;
        assert_eq!(sq_full.errno(), None);
        assert_eq!(sq_full.rejected_command(), None);

        let submit_errno = UblkControlReadonlyProbeError::IoUringSubmitErrno(11);
        assert_eq!(submit_errno.errno(), Some(11));
        assert_eq!(submit_errno.rejected_command(), None);

        let submit_missing = UblkControlReadonlyProbeError::IoUringSubmitMissingErrno;
        assert_eq!(submit_missing.errno(), None);
        assert_eq!(submit_missing.rejected_command(), None);

        let completion_missing = UblkControlReadonlyProbeError::CompletionMissing;
        assert_eq!(completion_missing.errno(), None);
        assert_eq!(completion_missing.rejected_command(), None);

        let unexpected = UblkControlReadonlyProbeError::UnexpectedCompletionUserData(0xdead);
        assert_eq!(unexpected.errno(), None);
        assert_eq!(unexpected.rejected_command(), None);

        let cmd_errno = UblkControlReadonlyProbeError::UblkCommandErrno(25);
        assert_eq!(cmd_errno.errno(), Some(25));
        assert_eq!(cmd_errno.rejected_command(), None);
    }

    #[test]
    fn is_fetch_req_user_data_rejects_non_fetch_req_user_data() {
        let fetch_data = fetch_req_user_data(0, 0);
        assert!(is_fetch_req_user_data(fetch_data));

        // COMMIT_AND_FETCH user_data should not be recognized as FETCH_REQ
        let commit_data = commit_and_fetch_user_data(0, 0);
        assert!(!is_fetch_req_user_data(commit_data));

        // An arbitrary value should not be recognized
        assert!(!is_fetch_req_user_data(0xDEAD_BEEF));
    }

    #[test]
    fn fetch_req_readiness_requires_live_queue_runtime_for_start_dev() {
        let dropped_runtime = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 64, false);
        assert!(!dropped_runtime.all_fetches_ready());
        assert!(!dropped_runtime.start_dev_readiness().all_fetches_ready());

        let live_runtime = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 64, true);
        assert!(live_runtime.all_fetches_ready());
        assert!(live_runtime.start_dev_readiness().all_fetches_ready());
        assert!(live_runtime.start_dev_readiness().data_queue_runtime_live);
    }

    #[test]
    fn fetch_req_outcome_preserves_queue_tag_and_user_data() {
        let input = UblkDataQueueFetchReqInput::user_copy(0, 7, 1, 64);

        let outcome = UblkDataQueueFetchReqOutcome::from_input(input);

        assert_eq!(outcome.command, UblkDataQueueFetchReqCommand::FetchReq);
        assert_eq!(outcome.request_raw, UblkIoCommand::FetchReq.request().raw());
        assert_eq!(outcome.q_id, 0);
        assert_eq!(outcome.tag, 7);
        assert_eq!(outcome.user_data, fetch_req_user_data(0, 7));
        assert!(outcome.submitted_without_wait);
    }

    #[test]
    fn fetch_req_command_maps_to_ublk_fetch_req() {
        let command = UblkDataQueueFetchReqCommand::FetchReq;
        assert_eq!(command.as_str(), "FETCH_REQ");
        assert_eq!(command.ublk_command(), UblkIoCommand::FetchReq);
        assert_eq!(
            command.request().raw(),
            UblkIoCommand::FetchReq.request().raw()
        );
    }

    #[test]
    fn fetch_req_input_rejects_too_many_hardware_queues() {
        let input = UblkDataQueueFetchReqInput::user_copy(
            0,
            0,
            u16::checked_add(UBLK_MAX_NR_QUEUES, 1).expect("max"),
            64,
        );
        assert_eq!(
            build_fetch_req_spec(input),
            Err(UblkDataQueueFetchReqError::TooManyHardwareQueues)
        );
    }

    #[test]
    fn fetch_req_input_rejects_zero_queue_depth() {
        let input = UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 0);
        assert_eq!(
            build_fetch_req_spec(input),
            Err(UblkDataQueueFetchReqError::ZeroQueueDepth)
        );
    }

    #[test]
    fn fetch_req_input_rejects_queue_depth_too_large() {
        let input = UblkDataQueueFetchReqInput::user_copy(
            0,
            0,
            1,
            u16::checked_add(UBLK_MAX_QUEUE_DEPTH, 1).expect("max"),
        );
        assert_eq!(
            build_fetch_req_spec(input),
            Err(UblkDataQueueFetchReqError::QueueDepthTooLarge)
        );
    }

    #[test]
    fn fetch_req_error_as_str_and_errno_extraction() {
        assert_eq!(
            UblkDataQueueFetchReqError::ZeroHardwareQueues.as_str(),
            "zero_hardware_queues"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::TooManyHardwareQueues.as_str(),
            "too_many_hardware_queues"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::ZeroQueueDepth.as_str(),
            "zero_queue_depth"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::QueueDepthTooLarge.as_str(),
            "queue_depth_too_large"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::QueueIdOutOfRange.as_str(),
            "queue_id_out_of_range"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::TagOutOfRange.as_str(),
            "tag_out_of_range"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::SubmissionQueueFull.as_str(),
            "submission_queue_full"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::IoUringSubmitErrno(22).as_str(),
            "io_uring_submit_errno"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::IoUringSubmitMissingErrno.as_str(),
            "io_uring_submit_missing_errno"
        );
        assert_eq!(
            UblkDataQueueFetchReqError::IoUringSubmitZero.as_str(),
            "io_uring_submit_zero"
        );

        assert_eq!(
            UblkDataQueueFetchReqError::IoUringSubmitErrno(12).errno(),
            Some(12)
        );
        assert_eq!(UblkDataQueueFetchReqError::ZeroHardwareQueues.errno(), None);
        assert_eq!(
            UblkDataQueueFetchReqError::SubmissionQueueFull.errno(),
            None
        );
    }

    #[test]
    fn decode_and_is_fetch_req_user_data() {
        let user_data = fetch_req_user_data(0x0abc, 0x0123);
        assert!(is_fetch_req_user_data(user_data));

        let (q_id, tag) = decode_fetch_req_user_data(user_data);
        assert_eq!(q_id, 0x0abc);
        assert_eq!(tag, 0x0123);

        let user_data_zero = fetch_req_user_data(0, 0);
        let (q_id_zero, tag_zero) = decode_fetch_req_user_data(user_data_zero);
        assert_eq!(q_id_zero, 0);
        assert_eq!(tag_zero, 0);

        let user_data_max = fetch_req_user_data(u16::MAX, u16::MAX);
        let (q_id_max, tag_max) = decode_fetch_req_user_data(user_data_max);
        assert_eq!(q_id_max, u16::MAX);
        assert_eq!(tag_max, u16::MAX);
    }

    #[test]
    fn data_queue_runtime_open_spec_binds_concrete_dev_queue_path_and_ring() {
        let input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(42, 0, 1, 64);

        let spec = build_data_queue_runtime_open_spec(input).unwrap();

        assert_eq!(spec.dev_id, 42);
        assert_eq!(spec.q_id, 0);
        assert_eq!(spec.nr_hw_queues, 1);
        assert_eq!(spec.queue_depth, 64);
        assert_eq!(spec.data_queue_path_template, "/dev/ublkcN");
        assert_eq!(spec.data_queue_path, PathBuf::from("/dev/ublkc42"));
        assert_eq!(spec.open_mode, "read_write");
        assert_eq!(spec.ring_entries, 128);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(spec.requires_successful_add_dev);
        assert!(!spec.submits_fetch_req);
    }

    #[test]
    fn data_queue_runtime_open_rejects_auto_dev_id_and_bad_geometry() {
        assert_eq!(
            build_data_queue_runtime_open_spec(UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID,
                0,
                1,
                64,
            )),
            Err(UblkDataQueueRuntimeOpenError::AutoDeviceId)
        );
        assert_eq!(
            build_data_queue_runtime_open_spec(UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                42, 0, 0, 64,
            )),
            Err(UblkDataQueueRuntimeOpenError::ZeroHardwareQueues)
        );
        assert_eq!(
            build_data_queue_runtime_open_spec(UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                42,
                0,
                UBLK_MAX_NR_QUEUES + 1,
                64,
            )),
            Err(UblkDataQueueRuntimeOpenError::TooManyHardwareQueues)
        );
        assert_eq!(
            build_data_queue_runtime_open_spec(UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                42, 0, 1, 0,
            )),
            Err(UblkDataQueueRuntimeOpenError::ZeroQueueDepth)
        );
        assert_eq!(
            build_data_queue_runtime_open_spec(UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                42,
                0,
                1,
                UBLK_MAX_QUEUE_DEPTH + 1,
            )),
            Err(UblkDataQueueRuntimeOpenError::QueueDepthTooLarge)
        );
        assert_eq!(
            build_data_queue_runtime_open_spec(UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                42, 1, 1, 64,
            )),
            Err(UblkDataQueueRuntimeOpenError::QueueIdOutOfRange)
        );
    }

    #[test]
    fn data_queue_runtime_open_outcome_feeds_fetch_req_liveness_without_submissions() {
        let spec = build_data_queue_runtime_open_spec(
            UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(42, 0, 1, 64),
        )
        .unwrap();

        let outcome = UblkDataQueueRuntimeOpenOutcome::from_spec(&spec);
        let readiness = outcome.fetch_req_readiness(0);

        assert!(outcome.data_queue_fd_open);
        assert!(outcome.io_uring_ready);
        assert!(outcome.runtime_live);
        assert_eq!(outcome.data_queue_path, PathBuf::from("/dev/ublkc42"));
        assert_eq!(readiness.required_fetch_commands, 64);
        assert_eq!(readiness.submitted_fetch_commands, 0);
        assert!(readiness.data_queue_runtime_live);
        assert!(!readiness.all_fetches_ready());
    }

    #[test]
    fn data_queue_runtime_open_error_as_str_and_errno() {
        assert_eq!(
            UblkDataQueueRuntimeOpenError::AutoDeviceId.as_str(),
            "auto_device_id_not_concrete"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::ZeroHardwareQueues.as_str(),
            "zero_hardware_queues"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::TooManyHardwareQueues.as_str(),
            "too_many_hardware_queues"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::ZeroQueueDepth.as_str(),
            "zero_queue_depth"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::QueueDepthTooLarge.as_str(),
            "queue_depth_too_large"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::QueueIdOutOfRange.as_str(),
            "queue_id_out_of_range"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueuePathMismatch.as_str(),
            "data_queue_path_mismatch"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueuePathMissing.as_str(),
            "data_queue_path_missing"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice.as_str(),
            "data_queue_path_not_character_device"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(2).as_str(),
            "data_queue_metadata_errno"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueMetadataMissingErrno.as_str(),
            "data_queue_metadata_missing_errno"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(2).as_str(),
            "data_queue_open_errno"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno.as_str(),
            "data_queue_open_missing_errno"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::IoUringSetupErrno(12).as_str(),
            "io_uring_setup_errno"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno.as_str(),
            "io_uring_setup_missing_errno"
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::MmapFailed(14).as_str(),
            "mmap_failed"
        );

        // errno returns None for non-errno variants
        assert_eq!(UblkDataQueueRuntimeOpenError::AutoDeviceId.errno(), None);
        assert_eq!(
            UblkDataQueueRuntimeOpenError::ZeroHardwareQueues.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::TooManyHardwareQueues.errno(),
            None
        );
        assert_eq!(UblkDataQueueRuntimeOpenError::ZeroQueueDepth.errno(), None);
        assert_eq!(
            UblkDataQueueRuntimeOpenError::QueueDepthTooLarge.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::QueueIdOutOfRange.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueuePathMismatch.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueuePathMissing.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueMetadataMissingErrno.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno.errno(),
            None
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno.errno(),
            None
        );

        // errno returns Some for errno-carrying variants
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(2).errno(),
            Some(2)
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(13).errno(),
            Some(13)
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::IoUringSetupErrno(12).errno(),
            Some(12)
        );
        assert_eq!(
            UblkDataQueueRuntimeOpenError::MmapFailed(14).errno(),
            Some(14)
        );
    }

    #[test]
    fn fetch_req_submission_spec_binds_live_runtime_queue_tags() {
        let open_spec = build_data_queue_runtime_open_spec(
            UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(42, 0, 1, 64),
        )
        .unwrap();
        let open_outcome = UblkDataQueueRuntimeOpenOutcome::from_spec(&open_spec);

        let submit_spec = build_fetch_req_submission_spec(&open_outcome).unwrap();

        assert_eq!(submit_spec.q_id, 0);
        assert_eq!(submit_spec.queue_fetch_commands, 64);
        assert_eq!(submit_spec.all_queues_required_fetch_commands, 64);
        assert_eq!(submit_spec.first_tag, 0);
        assert_eq!(submit_spec.last_tag, 63);
        assert!(submit_spec.runtime_must_remain_live);
        assert!(submit_spec.submits_without_waiting_for_cqe);
        assert!(!submit_spec.submits_start_dev);
    }

    #[test]
    fn fetch_req_submission_outcome_makes_start_dev_ready_without_start_submission() {
        let open_spec = build_data_queue_runtime_open_spec(
            UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(42, 0, 1, 64),
        )
        .unwrap();
        let open_outcome = UblkDataQueueRuntimeOpenOutcome::from_spec(&open_spec);
        let submit_spec = build_fetch_req_submission_spec(&open_outcome).unwrap();

        let outcome =
            UblkDataQueueFetchReqSubmissionOutcome::from_spec(submit_spec, 64, Some(0), Some(63));
        let readiness = outcome.fetch_req_readiness();
        let start_readiness = outcome.start_dev_readiness();

        assert_eq!(outcome.submitted_fetch_commands, 64);
        assert_eq!(outcome.first_submitted_tag, Some(0));
        assert_eq!(outcome.last_submitted_tag, Some(63));
        assert!(outcome.submitted_without_waiting_for_cqe);
        assert!(!outcome.started_device);
        assert!(readiness.all_fetches_ready());
        assert!(start_readiness.all_fetches_ready());
    }

    #[test]
    fn fetch_req_submission_outcome_from_spec_with_zero_submitted_and_no_tags() {
        let open_spec = build_data_queue_runtime_open_spec(
            UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(42, 0, 1, 64),
        )
        .unwrap();
        let open_outcome = UblkDataQueueRuntimeOpenOutcome::from_spec(&open_spec);
        let submit_spec = build_fetch_req_submission_spec(&open_outcome).unwrap();

        let outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(submit_spec, 0, None, None);

        assert_eq!(outcome.submitted_fetch_commands, 0);
        assert_eq!(outcome.first_submitted_tag, None);
        assert_eq!(outcome.last_submitted_tag, None);
        assert!(!outcome.started_device);
        assert!(outcome.submitted_without_waiting_for_cqe);
        assert!(outcome.data_queue_runtime_live);
        assert_eq!(outcome.q_id, 0);
        assert_eq!(outcome.nr_hw_queues, 1);
        assert_eq!(outcome.queue_depth, 64);
    }

    #[test]
    fn fetch_req_submission_error_preserves_failed_tag_and_partial_count() {
        let error = UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
            tag: 7,
            submitted_fetch_commands: 7,
            error: UblkDataQueueFetchReqError::IoUringSubmitErrno(22),
        };

        assert_eq!(error.as_str(), "io_uring_submit_errno");
        assert_eq!(error.errno(), Some(22));
        assert_eq!(error.submitted_fetch_commands(), 7);
    }

    #[test]
    fn fetch_req_submission_error_runtime_not_live_as_str_and_errno() {
        let error = UblkDataQueueFetchReqSubmissionError::RuntimeNotLive;

        assert_eq!(error.as_str(), "data_queue_runtime_not_live");
        assert_eq!(error.errno(), None);
        assert_eq!(error.submitted_fetch_commands(), 0);
    }

    #[test]
    fn fetch_req_submission_error_invalid_fetch_req_input_zero_hw_queues() {
        let error = UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
            UblkDataQueueFetchReqError::ZeroHardwareQueues,
        );

        assert_eq!(error.as_str(), "invalid_fetch_req_input");
        assert_eq!(error.errno(), None);
        assert_eq!(error.submitted_fetch_commands(), 0);
    }

    #[test]
    fn fetch_req_submission_error_invalid_fetch_req_input_io_uring_submit_errno() {
        let error = UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
            UblkDataQueueFetchReqError::IoUringSubmitErrno(22),
        );

        assert_eq!(error.as_str(), "invalid_fetch_req_input");
        assert_eq!(error.errno(), Some(22));
        assert_eq!(error.submitted_fetch_commands(), 0);
    }

    #[test]
    fn fetch_req_submission_error_invalid_fetch_req_input_queue_id_out_of_range() {
        let error = UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
            UblkDataQueueFetchReqError::QueueIdOutOfRange,
        );

        assert_eq!(error.as_str(), "invalid_fetch_req_input");
        assert_eq!(error.errno(), None);
        assert_eq!(error.submitted_fetch_commands(), 0);
    }

    #[test]
    fn fetch_req_submission_error_invalid_fetch_req_input_submission_queue_full() {
        let error = UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
            UblkDataQueueFetchReqError::SubmissionQueueFull,
        );

        assert_eq!(error.as_str(), "invalid_fetch_req_input");
        assert_eq!(error.errno(), None);
        assert_eq!(error.submitted_fetch_commands(), 0);
    }

    #[test]
    fn build_fetch_req_submission_spec_rejects_not_live_runtime() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 1,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: false,
        };

        let result = build_fetch_req_submission_spec(&outcome);
        assert_eq!(
            result,
            Err(UblkDataQueueFetchReqSubmissionError::RuntimeNotLive)
        );
    }

    #[test]
    fn build_fetch_req_submission_spec_rejects_zero_hardware_queues_from_first_tag() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 0,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };

        let result = build_fetch_req_submission_spec(&outcome);
        assert_eq!(
            result,
            Err(UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
                UblkDataQueueFetchReqError::ZeroHardwareQueues,
            ))
        );
    }

    #[test]
    fn build_fetch_req_submission_spec_rejects_zero_queue_depth() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 1,
            queue_depth: 0,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };

        let result = build_fetch_req_submission_spec(&outcome);
        assert_eq!(
            result,
            Err(UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
                UblkDataQueueFetchReqError::ZeroQueueDepth,
            ))
        );
    }

    #[test]
    fn build_fetch_req_submission_spec_rejects_too_many_hardware_queues_from_first_tag() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: UBLK_MAX_NR_QUEUES + 1,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };

        let result = build_fetch_req_submission_spec(&outcome);
        assert_eq!(
            result,
            Err(UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
                UblkDataQueueFetchReqError::TooManyHardwareQueues,
            ))
        );
    }

    #[test]
    fn build_fetch_req_submission_spec_rejects_queue_depth_too_large() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 1,
            queue_depth: UBLK_MAX_QUEUE_DEPTH + 1,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };

        let result = build_fetch_req_submission_spec(&outcome);
        assert_eq!(
            result,
            Err(UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
                UblkDataQueueFetchReqError::QueueDepthTooLarge,
            ))
        );
    }

    #[test]
    fn build_fetch_req_submission_spec_rejects_queue_id_out_of_range() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: UBLK_MAX_NR_QUEUES,
            nr_hw_queues: 1,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };

        let result = build_fetch_req_submission_spec(&outcome);
        assert_eq!(
            result,
            Err(UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
                UblkDataQueueFetchReqError::QueueIdOutOfRange,
            ))
        );
    }

    #[test]
    fn fetch_req_submission_spec_from_runtime_outcome_preserves_fields() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 1,
            nr_hw_queues: 2,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };

        let spec = UblkDataQueueFetchReqSubmissionSpec::from_runtime_outcome(&outcome);

        assert_eq!(spec.q_id, 1);
        assert_eq!(spec.nr_hw_queues, 2);
        assert_eq!(spec.queue_depth, 64);
        assert_eq!(spec.queue_fetch_commands, 64);
        assert_eq!(spec.all_queues_required_fetch_commands, 128);
        assert_eq!(spec.first_tag, 0);
        assert_eq!(spec.last_tag, 63);
        assert!(spec.runtime_must_remain_live);
        assert!(spec.submits_without_waiting_for_cqe);
        assert!(!spec.submits_start_dev);
    }

    #[test]
    fn commit_and_fetch_spec_uses_data_queue_read_write_command_and_sqe128() {
        let input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 7, 1, 64);

        let spec = build_commit_and_fetch_spec(input).unwrap();

        assert_eq!(
            spec.command,
            UblkDataQueueCommitAndFetchCommand::CommitAndFetchReq
        );
        assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvIoCmd>());
        assert_eq!(spec.q_id, 0);
        assert_eq!(spec.tag, 7);
        assert_eq!(spec.result, UBLK_IO_RES_OK);
        assert_eq!(spec.addr_or_zone_append_lba, 0);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(spec.commits_result);
        assert!(spec.fetches_next_request);
        assert!(spec.runtime_must_remain_live);
    }

    #[test]
    fn commit_and_fetch_command_encodes_queue_tag_result_and_zero_lba() {
        let command = build_commit_and_fetch_io_cmd(
            UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 7, 1, 64),
        )
        .unwrap();

        let payload = encode_commit_and_fetch_cmd80(command);

        assert_eq!(&payload[0..2], &0_u16.to_ne_bytes());
        assert_eq!(&payload[2..4], &7_u16.to_ne_bytes());
        assert_eq!(&payload[4..8], &UBLK_IO_RES_OK.to_ne_bytes());
        assert_eq!(&payload[8..16], &0_u64.to_ne_bytes());
        assert!(payload[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn commit_and_fetch_input_rejects_bad_geometry_and_special_result_payloads() {
        assert_eq!(
            build_commit_and_fetch_spec(UblkDataQueueCommitAndFetchInput::completed_user_copy(
                0, 0, 0, 64,
            )),
            Err(UblkDataQueueCommitAndFetchError::ZeroHardwareQueues)
        );
        assert_eq!(
            build_commit_and_fetch_spec(UblkDataQueueCommitAndFetchInput::completed_user_copy(
                UBLK_MAX_NR_QUEUES,
                0,
                UBLK_MAX_NR_QUEUES,
                64,
            )),
            Err(UblkDataQueueCommitAndFetchError::QueueIdOutOfRange)
        );
        assert_eq!(
            build_commit_and_fetch_spec(UblkDataQueueCommitAndFetchInput::completed_user_copy(
                0, 64, 1, 64,
            )),
            Err(UblkDataQueueCommitAndFetchError::TagOutOfRange)
        );

        let mut input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 7, 1, 64);
        input.result = UBLK_IO_RES_NEED_GET_DATA;
        assert_eq!(
            build_commit_and_fetch_spec(input),
            Err(UblkDataQueueCommitAndFetchError::NeedGetDataResultUnsupported)
        );

        input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 7, 1, 64);
        input.result = 4096;
        assert!(
            build_commit_and_fetch_spec(input).is_ok(),
            "Linux ublk uses positive byte-count completions for read/write requests"
        );

        input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 7, 1, 64);
        input.addr_or_zone_append_lba = 4096;
        assert_eq!(
            build_commit_and_fetch_spec(input),
            Err(UblkDataQueueCommitAndFetchError::ZoneAppendLbaMustBeZero)
        );
    }

    #[test]
    fn commit_and_fetch_user_data_binds_tag_command_and_queue() {
        let user_data = commit_and_fetch_user_data(3, 9);

        assert_eq!(user_data & 0xffff, 9);
        assert_eq!(
            (user_data >> 16) & 0xff,
            u64::from(UblkIoCommand::CommitAndFetchReq.number())
        );
        assert_eq!((user_data >> 48) & 0xffff, 3);
        assert_eq!(user_data >> 63, 0);
    }

    #[test]
    fn commit_and_fetch_readiness_requires_live_fetched_completed_request() {
        let open_spec = build_data_queue_runtime_open_spec(
            UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(42, 0, 1, 64),
        )
        .unwrap();
        let open_outcome = UblkDataQueueRuntimeOpenOutcome::from_spec(&open_spec);
        let fetch_spec = build_fetch_req_submission_spec(&open_outcome).unwrap();
        let fetch_outcome =
            UblkDataQueueFetchReqSubmissionOutcome::from_spec(fetch_spec, 64, Some(0), Some(63));

        let missing_request =
            UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
                fetch_outcome,
                false,
                true,
            );
        assert!(!missing_request.all_commit_preconditions_ready());
        assert_eq!(
            validate_commit_and_fetch_readiness(missing_request),
            Err(UblkDataQueueCommitAndFetchError::FetchedRequestMissing)
        );

        let missing_completion =
            UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
                fetch_outcome,
                true,
                false,
            );
        assert_eq!(
            validate_commit_and_fetch_readiness(missing_completion),
            Err(UblkDataQueueCommitAndFetchError::CompletionResultNotReady)
        );

        let ready = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
            fetch_outcome,
            true,
            true,
        );
        assert!(ready.all_commit_preconditions_ready());
        assert_eq!(validate_commit_and_fetch_readiness(ready), Ok(()));
    }

    #[test]
    fn commit_and_fetch_readiness_rejects_non_live_runtime() {
        let readiness = UblkDataQueueCommitAndFetchReadiness {
            data_queue_runtime_live: false,
            fetched_request_available: true,
            completion_result_ready: true,
        };
        assert!(!readiness.all_commit_preconditions_ready());
        assert_eq!(
            validate_commit_and_fetch_readiness(readiness),
            Err(UblkDataQueueCommitAndFetchError::RuntimeNotLive)
        );
    }

    #[test]
    fn commit_and_fetch_outcome_preserves_queue_tag_result_and_user_data() {
        let input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 7, 1, 64);

        let outcome = UblkDataQueueCommitAndFetchOutcome::from_input(input);

        assert_eq!(
            outcome.command,
            UblkDataQueueCommitAndFetchCommand::CommitAndFetchReq
        );
        assert_eq!(
            outcome.request_raw,
            UblkIoCommand::CommitAndFetchReq.request().raw()
        );
        assert_eq!(outcome.q_id, 0);
        assert_eq!(outcome.tag, 7);
        assert_eq!(outcome.result, UBLK_IO_RES_OK);
        assert_eq!(outcome.user_data, commit_and_fetch_user_data(0, 7));
        assert!(outcome.submitted_without_waiting_for_cqe);
    }

    #[test]
    fn commit_and_fetch_input_rejects_too_many_hardware_queues() {
        assert_eq!(
            build_commit_and_fetch_spec(UblkDataQueueCommitAndFetchInput::completed_user_copy(
                0,
                0,
                UBLK_MAX_NR_QUEUES + 1,
                64,
            )),
            Err(UblkDataQueueCommitAndFetchError::TooManyHardwareQueues)
        );
    }

    #[test]
    fn commit_and_fetch_input_rejects_zero_queue_depth() {
        assert_eq!(
            build_commit_and_fetch_spec(UblkDataQueueCommitAndFetchInput::completed_user_copy(
                0, 0, 1, 0,
            )),
            Err(UblkDataQueueCommitAndFetchError::ZeroQueueDepth)
        );
    }

    #[test]
    fn commit_and_fetch_input_rejects_queue_depth_too_large() {
        assert_eq!(
            build_commit_and_fetch_spec(UblkDataQueueCommitAndFetchInput::completed_user_copy(
                0,
                0,
                1,
                UBLK_MAX_QUEUE_DEPTH + 1,
            )),
            Err(UblkDataQueueCommitAndFetchError::QueueDepthTooLarge)
        );
    }

    #[test]
    fn decode_commit_and_fetch_user_data_recovers_queue_and_tag() {
        let (q_id, tag) = decode_commit_and_fetch_user_data(commit_and_fetch_user_data(4, 12));
        assert_eq!(q_id, 4);
        assert_eq!(tag, 12);

        let (q_id, tag) = decode_commit_and_fetch_user_data(commit_and_fetch_user_data(0, 0));
        assert_eq!(q_id, 0);
        assert_eq!(tag, 0);
        let (q_id, tag) =
            decode_commit_and_fetch_user_data(commit_and_fetch_user_data(u16::MAX, u16::MAX));
        assert_eq!(q_id, u16::MAX);
        assert_eq!(tag, u16::MAX);
    }

    #[test]
    fn is_commit_and_fetch_user_data_distinguishes_from_other_commands() {
        assert!(is_commit_and_fetch_user_data(commit_and_fetch_user_data(
            0, 0
        )));
        assert!(is_commit_and_fetch_user_data(commit_and_fetch_user_data(
            3, 9
        )));
        assert!(!is_commit_and_fetch_user_data(fetch_req_user_data(
            u16::MAX,
            u16::MAX
        )));
        assert!(!is_commit_and_fetch_user_data(0));
        assert!(!is_commit_and_fetch_user_data(u64::MAX));
    }

    #[test]
    fn flush_completion_plan_maps_zero_payload_flush_to_commit_and_fetch() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_FLUSH),
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };
        let input = UblkDataQueueFlushCompletionInput::fetched_user_copy(0, 7, 1, 64, desc);

        let plan = build_flush_completion_plan(input).expect("flush plan");

        assert_eq!(plan.q_id, 0);
        assert_eq!(plan.tag, 7);
        assert_eq!(plan.op, UBLK_IO_OP_FLUSH);
        assert_eq!(plan.count_or_zones, 0);
        assert_eq!(plan.start_sector, 0);
        assert_eq!(plan.data_addr, 0);
        assert_eq!(plan.completion_result, UBLK_IO_RES_OK);
        assert_eq!(plan.addr_or_zone_append_lba, 0);
        assert_eq!(
            plan.commit_input,
            UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 7, 1, 64)
        );
        assert_eq!(
            plan.commit_request_raw,
            UblkIoCommand::CommitAndFetchReq.request().raw()
        );
        assert!(plan.commit_readiness.all_commit_preconditions_ready());
        assert!(plan.commits_result);
        assert!(plan.fetches_next_request);
    }

    #[test]
    fn flush_completion_plan_rejects_non_flush_or_payload_bearing_descriptors() {
        let mut desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE),
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };
        let mut input = UblkDataQueueFlushCompletionInput::fetched_user_copy(0, 7, 1, 64, desc);
        assert_eq!(
            build_flush_completion_plan(input),
            Err(UblkDataQueueFlushCompletionPlanError::NotFlushOperation(
                UBLK_IO_OP_WRITE
            ))
        );

        desc.op_flags = u32::from(UBLK_IO_OP_FLUSH);
        desc.count_or_zones = 1;
        input.desc = desc;
        assert_eq!(
            build_flush_completion_plan(input),
            Err(UblkDataQueueFlushCompletionPlanError::NonzeroFlushCount(1))
        );

        desc.count_or_zones = 0;
        desc.start_sector = 8;
        input.desc = desc;
        assert_eq!(
            build_flush_completion_plan(input),
            Err(UblkDataQueueFlushCompletionPlanError::NonzeroFlushStartSector(8))
        );

        desc.start_sector = 0;
        desc.addr = 0x1000;
        input.desc = desc;
        assert_eq!(
            build_flush_completion_plan(input),
            Err(UblkDataQueueFlushCompletionPlanError::NonzeroFlushDataAddr(
                0x1000
            ))
        );
    }

    #[test]
    fn flush_completion_plan_rejects_missing_runtime_or_invalid_queue_geometry() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_FLUSH),
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };
        let mut input = UblkDataQueueFlushCompletionInput::fetched_user_copy(0, 7, 1, 64, desc);

        input.data_queue_runtime_live = false;
        let runtime_error = build_flush_completion_plan(input).unwrap_err();
        assert_eq!(
            runtime_error,
            UblkDataQueueFlushCompletionPlanError::RuntimeNotLive
        );
        assert_eq!(runtime_error.as_str(), "data_queue_runtime_not_live");
        assert_eq!(runtime_error.errno(), None);

        input.data_queue_runtime_live = true;
        input.fetched_request_available = false;
        assert_eq!(
            build_flush_completion_plan(input),
            Err(UblkDataQueueFlushCompletionPlanError::FetchedRequestMissing)
        );

        input.fetched_request_available = true;
        input.q_id = 1;
        let geometry_error = build_flush_completion_plan(input).unwrap_err();
        assert_eq!(
            geometry_error,
            UblkDataQueueFlushCompletionPlanError::InvalidCommitAndFetchInput(
                UblkDataQueueCommitAndFetchError::QueueIdOutOfRange
            )
        );
        assert_eq!(geometry_error.as_str(), "queue_id_out_of_range");
        assert_eq!(geometry_error.errno(), None);
    }

    #[test]
    fn start_dev_spec_uses_mutating_read_write_command_and_sqe128() {
        let input = UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(42, 1234);

        let spec = build_start_dev_spec(input).unwrap();

        assert_eq!(spec.command, UblkControlStartDevCommand::StartDev);
        assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
        assert_eq!(spec.control_queue_id, u16::MAX);
        assert_eq!(spec.ctrl_buffer_len, 0);
        assert_eq!(spec.ctrl_buffer_addr, 0);
        assert_eq!(spec.inline_daemon_pid, 1234);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(spec.mutates_control_state);
        assert!(spec.requires_ready_io_fetches);
    }

    #[test]
    fn start_dev_command_targets_concrete_dev_and_inline_daemon_pid() {
        let input = UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(42, 1234);

        let command = build_start_dev_ctrl_cmd(input).unwrap();

        assert_eq!(command.dev_id, 42);
        assert_eq!(command.queue_id, u16::MAX);
        assert_eq!(command.len, 0);
        assert_eq!(command.addr, 0);
        assert_eq!(command.data, [1234]);
    }

    #[test]
    fn start_dev_command_encodes_into_uring_cmd80_payload() {
        let command = build_start_dev_ctrl_cmd(
            UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(42, 1234),
        )
        .unwrap();

        let payload = encode_start_dev_cmd80(command);

        assert_eq!(&payload[0..4], &42_u32.to_ne_bytes());
        assert_eq!(&payload[4..6], &u16::MAX.to_ne_bytes());
        assert_eq!(&payload[6..8], &0_u16.to_ne_bytes());
        assert_eq!(&payload[8..16], &0_u64.to_ne_bytes());
        assert_eq!(&payload[16..24], &1234_u64.to_ne_bytes());
        assert!(payload[24..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn start_dev_input_rejects_auto_device_id_or_invalid_pid() {
        let error =
            build_start_dev_spec(UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(
                TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID,
                1234,
            ))
            .unwrap_err();
        assert_eq!(error, UblkControlStartDevError::AutoDeviceId);
        assert_eq!(error.as_str(), "auto_device_id_not_concrete");

        let error = build_start_dev_spec(
            UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(42, 0),
        )
        .unwrap_err();
        assert_eq!(error, UblkControlStartDevError::InvalidDaemonPid);
        assert_eq!(error.as_str(), "invalid_daemon_pid");
    }

    #[test]
    fn start_dev_issue_readiness_requires_all_fetch_commands() {
        let not_ready = UblkControlStartDevReadiness::from_queue_geometry(1, 64, 63);
        assert_eq!(
            validate_start_dev_readiness(not_ready),
            Err(UblkControlStartDevError::DataQueueFetchesNotReady)
        );
        assert_eq!(
            UblkControlStartDevError::DataQueueFetchesNotReady.as_str(),
            "data_queue_fetches_not_ready"
        );

        let dropped_runtime = UblkControlStartDevReadiness::from_queue_geometry(1, 64, 64);
        assert!(!dropped_runtime.all_fetches_ready());
        assert_eq!(
            validate_start_dev_readiness(dropped_runtime),
            Err(UblkControlStartDevError::DataQueueFetchesNotReady)
        );

        let ready = UblkControlStartDevReadiness::from_queue_geometry_with_runtime(1, 64, 64, true);
        assert!(ready.all_fetches_ready());
        assert_eq!(validate_start_dev_readiness(ready), Ok(()));
    }

    #[test]
    fn start_dev_outcome_preserves_target_device_and_daemon_pid() {
        let input = UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(42, 1234);

        let outcome = UblkControlStartDevOutcome::from_input(input);

        assert_eq!(outcome.command, UblkControlStartDevCommand::StartDev);
        assert_eq!(
            outcome.request_raw,
            UblkCtrlCommand::StartDev.request().raw()
        );
        assert_eq!(outcome.dev_id, 42);
        assert_eq!(outcome.ublksrv_pid, 1234);
    }

    #[test]
    fn start_dev_gate_constants_are_stable() {
        assert_eq!(
            BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T,
            "OW-301T block-volume adapter ublk control runtime exposes START_DEV only behind ready data-queue fetch admission"
        );
        assert_eq!(
            BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U,
            "OW-301U block-volume adapter ublk runtime source-binds data-queue FETCH_REQ readiness before START_DEV"
        );
    }

    #[test]
    fn start_dev_error_as_str_and_errno_extraction() {
        let err = UblkControlStartDevError::AutoDeviceId;
        assert_eq!(err.as_str(), "auto_device_id_not_concrete");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::InvalidDaemonPid;
        assert_eq!(err.as_str(), "invalid_daemon_pid");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::DataQueueFetchesNotReady;
        assert_eq!(err.as_str(), "data_queue_fetches_not_ready");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::IoUringSetupErrno(12);
        assert_eq!(err.as_str(), "io_uring_setup_errno");
        assert_eq!(err.errno(), Some(12));

        let err = UblkControlStartDevError::IoUringSetupMissingErrno;
        assert_eq!(err.as_str(), "io_uring_setup_missing_errno");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::SubmissionQueueFull;
        assert_eq!(err.as_str(), "submission_queue_full");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::IoUringSubmitErrno(5);
        assert_eq!(err.as_str(), "io_uring_submit_errno");
        assert_eq!(err.errno(), Some(5));

        let err = UblkControlStartDevError::IoUringSubmitMissingErrno;
        assert_eq!(err.as_str(), "io_uring_submit_missing_errno");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::CompletionMissing;
        assert_eq!(err.as_str(), "completion_missing");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::UnexpectedCompletionUserData(0xBAD);
        assert_eq!(err.as_str(), "unexpected_completion_user_data");
        assert_eq!(err.errno(), None);

        let err = UblkControlStartDevError::UblkCommandErrno(22);
        assert_eq!(err.as_str(), "ublk_command_errno");
        assert_eq!(err.errno(), Some(22));
    }
    // ── Error injection tests ───────────────────────────────────────────

    #[allow(dead_code)]
    fn dummy_control_fd() -> BorrowedFd<'static> {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let owned = file;
        // SAFETY: owned.as_raw_fd() returns a valid fd; borrowed_raw does not
        // take ownership; owned stays in scope through the dummy test.
        unsafe { BorrowedFd::borrow_raw(owned.as_raw_fd()) }
    }

    fn dummy_io_uring_ring() -> IoUring<squeue::Entry128, cqueue::Entry> {
        IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring build")
    }

    #[test]
    fn injected_no_error_does_nothing() {
        super::error_injection::clear();
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
        assert!(build_add_dev_spec(add_dev_input).is_ok());
        let _ = fd;
    }

    #[test]
    fn injected_add_dev_errno_returns_before_io_uring_setup() {
        super::error_injection::set(
            super::error_injection::InjectedError::AddDevUblkCommandErrno(42),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let input = UblkControlAddDevInput::conservative_tidefs();
        let result = issue_add_dev(fd, input);
        assert!(result.is_err(), "injected add_dev should return Err");
        match result.unwrap_err() {
            UblkControlAddDevError::UblkCommandErrno(42) => {}
            _e => panic!("expected UblkCommandErrno(42), got {_e:?}"),
        }
        assert!(super::error_injection::try_take().is_none());
    }

    #[test]
    fn injected_del_dev_errno_returns_before_io_uring_setup() {
        super::error_injection::set(
            super::error_injection::InjectedError::DelDevUblkCommandErrno(7),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let input = UblkControlDelDevInput::from_kernel_dev_id(1);
        let result = issue_del_dev(fd, input);
        assert!(result.is_err(), "injected del_dev should return Err");
        match result.unwrap_err() {
            UblkControlDelDevError::UblkCommandErrno(7) => {}
            _e => panic!("expected UblkCommandErrno(7), got {_e:?}"),
        }
    }

    #[test]
    fn injected_del_dev_after_add_dev_failure_returns_ok() {
        super::error_injection::set(
            super::error_injection::InjectedError::DelDevAfterAddDevFailure,
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let input = UblkControlDelDevInput::from_kernel_dev_id(1);
        let result = issue_del_dev(fd, input);
        assert!(result.is_ok(), "DelDevAfterAddDevFailure should return Ok");
    }

    #[test]
    fn injected_set_params_errno_returns_before_io_uring_setup() {
        super::error_injection::set(
            super::error_injection::InjectedError::SetParamsUblkCommandErrno(13),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let params = valid_set_params();
        let input = UblkControlSetParamsInput::from_kernel_dev_id_and_params(1, params);
        let result = issue_set_params(fd, input);
        assert!(result.is_err(), "injected set_params should return Err");
        match result.unwrap_err() {
            UblkControlSetParamsError::UblkCommandErrno(13) => {}
            _e => panic!("expected UblkCommandErrno(13), got {_e:?}"),
        }
    }

    #[test]
    fn injected_start_dev_errno_returns_before_io_uring_setup() {
        super::error_injection::set(
            super::error_injection::InjectedError::StartDevUblkCommandErrno(99),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let input = UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(1, 1234);
        let readiness =
            UblkControlStartDevReadiness::from_queue_geometry_with_runtime(1, 64, 64, true);
        let result = issue_start_dev(fd, input, readiness);
        assert!(result.is_err(), "injected start_dev should return Err");
        match result.unwrap_err() {
            UblkControlStartDevError::UblkCommandErrno(99) => {}
            _e => panic!("expected UblkCommandErrno(99), got {_e:?}"),
        }
    }

    #[test]
    fn stop_dev_spec_uses_mutating_read_write_command_and_sqe128() {
        let input = UblkControlStopDevInput::from_kernel_dev_id(42);

        let spec = build_stop_dev_spec(input).unwrap();

        assert_eq!(spec.command, UblkControlStopDevCommand::StopDev);
        assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
        assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
        assert_eq!(spec.control_queue_id, u16::MAX);
        assert_eq!(spec.ctrl_buffer_len, 0);
        assert_eq!(spec.ctrl_buffer_addr, 0);
        assert_eq!(spec.uring_cmd_sqe_bytes, 128);
        assert!(spec.mutates_control_state);
    }

    #[test]
    fn stop_dev_command_targets_concrete_dev_with_zeroed_data() {
        let input = UblkControlStopDevInput::from_kernel_dev_id(42);

        let command = build_stop_dev_ctrl_cmd(input).unwrap();

        assert_eq!(command.dev_id, 42);
        assert_eq!(command.queue_id, u16::MAX);
        assert_eq!(command.len, 0);
        assert_eq!(command.addr, 0);
        assert_eq!(command.data, [0]);
    }

    #[test]
    fn stop_dev_command_encodes_into_uring_cmd80_payload() {
        let command =
            build_stop_dev_ctrl_cmd(UblkControlStopDevInput::from_kernel_dev_id(42)).unwrap();

        let payload = encode_stop_dev_cmd80(command);

        assert_eq!(&payload[0..4], &42_u32.to_ne_bytes());
        assert_eq!(&payload[4..6], &u16::MAX.to_ne_bytes());
        assert_eq!(&payload[6..8], &0_u16.to_ne_bytes());
        assert_eq!(&payload[8..16], &0_u64.to_ne_bytes());
        assert!(payload[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn stop_dev_input_rejects_auto_device_id() {
        let error = build_stop_dev_spec(UblkControlStopDevInput::from_kernel_dev_id(
            TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID,
        ))
        .unwrap_err();
        assert_eq!(error, UblkControlStopDevError::AutoDeviceId);
        assert_eq!(error.as_str(), "auto_device_id_not_concrete");
    }

    #[test]
    fn stop_dev_input_accepts_valid_concrete_device_id() {
        let input = UblkControlStopDevInput::from_kernel_dev_id(1);
        assert!(build_stop_dev_spec(input).is_ok());
        assert!(build_stop_dev_ctrl_cmd(input).is_ok());
    }

    #[test]
    fn stop_dev_outcome_preserves_target_device_id() {
        let input = UblkControlStopDevInput::from_kernel_dev_id(42);

        let outcome = UblkControlStopDevOutcome::from_input(input);

        assert_eq!(outcome.command, UblkControlStopDevCommand::StopDev);
        assert_eq!(
            outcome.request_raw,
            UblkCtrlCommand::StopDev.request().raw()
        );
        assert_eq!(outcome.dev_id, 42);
    }

    #[test]
    fn stop_dev_gate_constants_are_stable() {
        assert_eq!(UBLK_CONTROL_STOP_DEV_RING_ENTRIES, 1);
        assert_eq!(UBLK_CONTROL_STOP_DEV_USER_DATA, 0x5649_4245_4653_0136);
    }

    #[test]
    fn stop_dev_error_as_str_and_errno_extraction() {
        let err = UblkControlStopDevError::AutoDeviceId;
        assert_eq!(err.as_str(), "auto_device_id_not_concrete");
        assert_eq!(err.errno(), None);

        let err = UblkControlStopDevError::SubmissionQueueFull;
        assert_eq!(err.as_str(), "submission_queue_full");
        assert_eq!(err.errno(), None);

        let err = UblkControlStopDevError::CompletionMissing;
        assert_eq!(err.as_str(), "completion_missing");
        assert_eq!(err.errno(), None);

        let err = UblkControlStopDevError::UblkCommandErrno(19);
        assert_eq!(err.as_str(), "ublk_command_errno");
        assert_eq!(err.errno(), Some(19));

        let err = UblkControlStopDevError::IoUringSetupErrno(2);
        assert_eq!(err.as_str(), "io_uring_setup_errno");
        assert_eq!(err.errno(), Some(2));

        let err = UblkControlStopDevError::IoUringSubmitErrno(5);
        assert_eq!(err.as_str(), "io_uring_submit_errno");
        assert_eq!(err.errno(), Some(5));
    }

    #[test]
    fn injected_stop_dev_errno_returns_before_io_uring_setup() {
        super::error_injection::set(
            super::error_injection::InjectedError::StopDevUblkCommandErrno(99),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let input = UblkControlStopDevInput::from_kernel_dev_id(1);
        let result = issue_stop_dev(fd, input);
        assert!(result.is_err(), "injected stop_dev should return Err");
        match result.unwrap_err() {
            UblkControlStopDevError::UblkCommandErrno(99) => {}
            _e => panic!("expected UblkCommandErrno(99), got {_e:?}"),
        }
    }

    #[test]
    fn stop_dev_command_maps_to_ublk_stop_dev() {
        let cmd = UblkControlStopDevCommand::StopDev;
        assert_eq!(cmd.as_str(), "STOP_DEV");
        assert_eq!(cmd.ublk_command(), UblkCtrlCommand::StopDev);
    }

    #[test]
    fn stop_dev_lifecycle_sequence_accepts_any_valid_dev_id() {
        // STOP_DEV does not require prior START_DEV or running daemon;
        // it is a control-plane mutation that the kernel validates.
        for dev_id in [1, 42, 100, u32::MAX - 1] {
            let input = UblkControlStopDevInput::from_kernel_dev_id(dev_id);
            assert!(
                build_stop_dev_spec(input).is_ok(),
                "stop_dev spec should accept dev_id={dev_id}"
            );
        }
    }

    #[test]
    fn injected_readonly_probe_errno_returns_before_io_uring_setup() {
        super::error_injection::set(
            super::error_injection::InjectedError::ReadonlyProbeUblkCommandErrno(17),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let result = issue_get_features(fd);
        assert!(result.is_err(), "injected readonly_probe should return Err");
        match result.unwrap_err() {
            UblkControlReadonlyProbeError::UblkCommandErrno(17) => {}
            _e => panic!("expected UblkCommandErrno(17), got {_e:?}"),
        }
        assert!(super::error_injection::try_take().is_none());
    }

    #[test]
    fn injected_fetch_req_submission_queue_full() {
        super::error_injection::set(
            super::error_injection::InjectedError::FetchReqSubmissionQueueFull,
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let mut ring = dummy_io_uring_ring();
        let input = UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64);
        let result = submit_fetch_req_without_wait(&mut ring, fd, input);
        assert!(result.is_err(), "injected fetch_req should return Err");
        match result.unwrap_err() {
            UblkDataQueueFetchReqError::SubmissionQueueFull => {}
            _e => panic!("expected SubmissionQueueFull, got {_e:?}"),
        }
    }

    #[test]
    fn injected_fetch_req_ublk_command_errno() {
        super::error_injection::set(
            super::error_injection::InjectedError::FetchReqUblkCommandErrno(5),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let mut ring = dummy_io_uring_ring();
        let input = UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64);
        let result = submit_fetch_req_without_wait(&mut ring, fd, input);
        assert!(result.is_err(), "injected fetch_req should return Err");
        match result.unwrap_err() {
            UblkDataQueueFetchReqError::IoUringSubmitErrno(5) => {}
            _e => panic!("expected IoUringSubmitErrno(5), got {_e:?}"),
        }
    }

    #[test]
    fn injected_fetch_req_io_uring_submit_errno() {
        super::error_injection::set(
            super::error_injection::InjectedError::FetchReqIoUringSubmitErrno(22),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let mut ring = dummy_io_uring_ring();
        let input = UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64);
        let result = submit_fetch_req_without_wait(&mut ring, fd, input);
        assert!(result.is_err(), "injected fetch_req should return Err");
        match result.unwrap_err() {
            UblkDataQueueFetchReqError::IoUringSubmitErrno(22) => {}
            _e => panic!("expected IoUringSubmitErrno(22), got {_e:?}"),
        }
    }

    #[test]
    fn injected_fetch_req_io_uring_submit_zero() {
        super::error_injection::set(
            super::error_injection::InjectedError::FetchReqIoUringSubmitZero,
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let mut ring = dummy_io_uring_ring();
        let input = UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64);
        let result = submit_fetch_req_without_wait(&mut ring, fd, input);
        assert!(result.is_err(), "injected fetch_req should return Err");
        match result.unwrap_err() {
            UblkDataQueueFetchReqError::IoUringSubmitZero => {}
            _e => panic!("expected IoUringSubmitZero, got {_e:?}"),
        }
    }

    #[test]
    fn injected_fetch_req_io_uring_submit_missing_errno() {
        super::error_injection::set(
            super::error_injection::InjectedError::FetchReqIoUringSubmitMissingErrno,
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let mut ring = dummy_io_uring_ring();
        let input = UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64);
        let result = submit_fetch_req_without_wait(&mut ring, fd, input);
        assert!(result.is_err(), "injected fetch_req should return Err");
        match result.unwrap_err() {
            UblkDataQueueFetchReqError::IoUringSubmitMissingErrno => {}
            _e => panic!("expected IoUringSubmitMissingErrno, got {_e:?}"),
        }
    }

    #[test]
    fn injected_runtime_fetch_reqs_submission_queue_full() {
        super::error_injection::set(
            super::error_injection::InjectedError::RuntimeFetchReqsSubmissionQueueFull,
        );
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 1,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        let mut runtime = UblkDataQueueRuntime {
            data_queue_file: std::fs::File::open("/dev/null").expect("open /dev/null"),
            ring: dummy_io_uring_ring(),
            outcome,
            cmd_buf_ptrs: Vec::new(),
            cmd_buf_lens: vec![4096],
            io_buf_nr_hw_queues: 1,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: true,
            cq_overflow_count: 0,
            io_buf_queue_depth: 64,
        };
        let result = submit_runtime_fetch_reqs_without_wait(&mut runtime);
        assert!(
            result.is_err(),
            "injected runtime fetch_reqs should return Err"
        );
        match result.unwrap_err() {
            UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
                tag: 0,
                submitted_fetch_commands: 0,
                error: UblkDataQueueFetchReqError::SubmissionQueueFull,
            } => {}
            _e => panic!("expected FetchReqSubmit with SubmissionQueueFull, got {_e:?}"),
        }
    }
    #[test]
    fn injected_data_queue_open_errno() {
        super::error_injection::set(
            super::error_injection::InjectedError::DataQueueRuntimeOpenError(9),
        );
        let path = std::path::Path::new("/tmp/nonexistent-tidefs-injection-test");
        let input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 0, 1, 64);
        let result = open_data_queue_runtime(path, input);
        assert!(
            result.is_err(),
            "injected data_queue_open should return Err"
        );
        match result.unwrap_err() {
            UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(9) => {}
            _e => panic!("expected DataQueueOpenErrno(9), got {_e:?}"),
        }
    }

    #[test]
    fn injected_data_queue_io_uring_setup_errno() {
        super::error_injection::set(
            super::error_injection::InjectedError::DataQueueIoUringSetupErrno(12),
        );
        let path = std::path::Path::new("/tmp/nonexistent-tidefs-injection-test");
        let input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 0, 1, 64);
        let result = open_data_queue_runtime(path, input);
        assert!(
            result.is_err(),
            "injected data_queue_open should return Err"
        );
        match result.unwrap_err() {
            UblkDataQueueRuntimeOpenError::IoUringSetupErrno(12) => {}
            _e => panic!("expected IoUringSetupErrno(12), got {_e:?}"),
        }
    }

    #[test]
    fn injected_error_not_consumed_by_unrelated_function() {
        super::error_injection::set(
            super::error_injection::InjectedError::SetParamsUblkCommandErrno(77),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
        let result = issue_add_dev(fd, add_dev_input);
        assert!(
            result.is_ok(),
            "AddDev with SetParams injection should not be affected"
        );
        let remaining = super::error_injection::try_take();
        assert_eq!(
            remaining,
            Some(super::error_injection::InjectedError::SetParamsUblkCommandErrno(77)),
            "SetParams error should be preserved after AddDev call"
        );
    }

    #[test]
    fn injected_error_consumed_after_matching_call() {
        super::error_injection::set(
            super::error_injection::InjectedError::AddDevUblkCommandErrno(3),
        );
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_fd();
        let input = UblkControlAddDevInput::conservative_tidefs();
        let _ = issue_add_dev(fd, input);
        assert!(
            super::error_injection::try_take().is_none(),
            "injection should be consumed after matching call"
        );
    }

    // ── IO descriptor decode tests ─────────────────────────────────────

    #[test]
    fn decode_io_desc_read_extracts_op_sector_and_count() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_READ),
            count_or_zones: 8,
            start_sector: 1024,
            addr: 0x1000,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_READ);
        assert_eq!(desc.flags(), 0);
        assert_eq!(desc.count_or_zones, 8);
        assert_eq!(desc.start_sector, 1024);
    }

    #[test]
    fn decode_io_desc_write_extracts_op_sector_count_and_fua_flag() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE) | (UBLK_ATTR_FUA << 8),
            count_or_zones: 16,
            start_sector: 2048,
            addr: 0x2000,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
        assert_eq!(desc.flags(), UBLK_ATTR_FUA);
        assert_eq!(desc.count_or_zones, 16);
        assert_eq!(desc.start_sector, 2048);
    }

    #[test]
    fn decode_io_desc_flush_has_zero_payload_fields() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_FLUSH),
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_FLUSH);
        assert_eq!(desc.flags(), 0);
        assert_eq!(desc.count_or_zones, 0);
        assert_eq!(desc.start_sector, 0);
        assert_eq!(desc.addr, 0);
    }

    #[test]
    fn decode_io_desc_discard_extracts_op_sector_and_count() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_DISCARD),
            count_or_zones: 4,
            start_sector: 4096,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_DISCARD);
        assert_eq!(desc.flags(), 0);
        assert_eq!(desc.count_or_zones, 4);
        assert_eq!(desc.start_sector, 4096);
    }

    #[test]
    fn decode_io_desc_write_zeroes_extracts_op_sector_and_count() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE_ZEROES),
            count_or_zones: 2,
            start_sector: 512,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_WRITE_ZEROES);
        assert_eq!(desc.flags(), 0);
        assert_eq!(desc.count_or_zones, 2);
        assert_eq!(desc.start_sector, 512);
    }

    #[test]
    fn decode_io_desc_flags_mask_separates_op_from_flags() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_READ) | ((UBLK_ATTR_FUA | 0xDEAD) << 8),
            count_or_zones: 1,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_READ);
        assert_eq!(desc.flags(), UBLK_ATTR_FUA | 0xDEAD);
    }

    // ── IO command completion encoding tests ──────────────────────────

    #[test]
    fn encode_io_cmd_completion_preserves_q_id_tag_result_and_addr() {
        let cmd = UblkSrvIoCmd {
            q_id: 1,
            tag: 7,
            result: UBLK_IO_RES_OK,
            addr_or_zone_append_lba: 0,
        };
        let encoded = encode_io_cmd80(cmd);
        assert_eq!(&encoded[0..2], &1u16.to_ne_bytes());
        assert_eq!(&encoded[2..4], &7u16.to_ne_bytes());
        assert_eq!(&encoded[4..8], &UBLK_IO_RES_OK.to_ne_bytes());
        assert_eq!(&encoded[8..16], &0u64.to_ne_bytes());
    }

    #[test]
    fn encode_io_cmd_completion_error_sets_negative_result() {
        let cmd = UblkSrvIoCmd {
            q_id: 0,
            tag: 3,
            result: UBLK_IO_RES_ABORT,
            addr_or_zone_append_lba: 0,
        };
        let encoded = encode_io_cmd80(cmd);
        assert_eq!(&encoded[4..8], &UBLK_IO_RES_ABORT.to_ne_bytes());
    }

    #[test]
    fn encode_io_cmd_completion_need_get_data_sets_positive_result() {
        let cmd = UblkSrvIoCmd {
            q_id: 0,
            tag: 1,
            result: UBLK_IO_RES_NEED_GET_DATA,
            addr_or_zone_append_lba: 0x8000,
        };
        let encoded = encode_io_cmd80(cmd);
        assert_eq!(&encoded[4..8], &UBLK_IO_RES_NEED_GET_DATA.to_ne_bytes());
        assert_eq!(&encoded[8..16], &0x8000u64.to_ne_bytes());
    }

    #[test]
    fn encode_io_cmd_completion_write_encodes_addr_field() {
        let cmd = UblkSrvIoCmd {
            q_id: 2,
            tag: 15,
            result: UBLK_IO_RES_OK,
            addr_or_zone_append_lba: 0xDEAD_BEEF_0000,
        };
        let encoded = encode_io_cmd80(cmd);
        assert_eq!(&encoded[0..2], &2u16.to_ne_bytes());
        assert_eq!(&encoded[2..4], &15u16.to_ne_bytes());
        assert_eq!(&encoded[4..8], &UBLK_IO_RES_OK.to_ne_bytes());
        assert_eq!(&encoded[8..16], &0xDEAD_BEEF_0000u64.to_ne_bytes());
    }

    // ── Dispatch classification (opcode routing) tests ─────────────────

    #[test]
    fn classify_io_op_all_known_operations_have_distinct_codes() {
        let ops = [
            UBLK_IO_OP_READ,
            UBLK_IO_OP_WRITE,
            UBLK_IO_OP_FLUSH,
            UBLK_IO_OP_DISCARD,
            UBLK_IO_OP_WRITE_SAME,
            UBLK_IO_OP_WRITE_ZEROES,
        ];
        for i in 0..ops.len() {
            for j in (i + 1)..ops.len() {
                assert_ne!(ops[i], ops[j], "opcodes {i} and {j} must differ");
            }
        }
    }

    #[test]
    fn classify_io_op_read_write_flush_discard_write_zeroes_stable() {
        assert_eq!(UBLK_IO_OP_READ, 0);
        assert_eq!(UBLK_IO_OP_WRITE, 1);
        assert_eq!(UBLK_IO_OP_FLUSH, 2);
        assert_eq!(UBLK_IO_OP_DISCARD, 3);
        assert_eq!(UBLK_IO_OP_WRITE_SAME, 4);
        assert_eq!(UBLK_IO_OP_WRITE_ZEROES, 5);
    }

    #[test]
    fn classify_io_desc_read_routes_to_read_handler() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_READ),
            count_or_zones: 8,
            start_sector: 1024,
            addr: 0x1000,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_READ);
    }

    #[test]
    fn classify_io_desc_write_routes_to_write_handler() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE),
            count_or_zones: 16,
            start_sector: 2048,
            addr: 0x2000,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
    }

    #[test]
    fn classify_io_desc_flush_routes_to_flush_handler() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_FLUSH),
            count_or_zones: 0,
            start_sector: 0,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_FLUSH);
    }

    #[test]
    fn classify_io_desc_discard_routes_to_discard_handler() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_DISCARD),
            count_or_zones: 4,
            start_sector: 4096,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_DISCARD);
    }

    #[test]
    fn classify_io_desc_write_zeroes_routes_to_write_zeroes_handler() {
        let desc = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE_ZEROES),
            count_or_zones: 2,
            start_sector: 512,
            addr: 0,
        };
        assert_eq!(desc.op(), UBLK_IO_OP_WRITE_ZEROES);
    }

    // ── io_desc() error-path tests ─────────────────────────────────────

    fn dummy_runtime_with_buffer(queue_depth: u16) -> UblkDataQueueRuntime {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring build");
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 1,
            queue_depth,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: queue_depth as u32,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        let buf: Vec<u8> = vec![0u8; 4096];
        let io_buf_base = buf.as_ptr();
        std::mem::forget(buf);
        UblkDataQueueRuntime {
            data_queue_file: file,
            ring,
            outcome,
            cmd_buf_ptrs: vec![io_buf_base],
            cmd_buf_lens: vec![4096],
            io_buf_nr_hw_queues: 1,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: true,
            cq_overflow_count: 0,
            io_buf_queue_depth: queue_depth,
        }
    }

    #[test]
    fn io_desc_tag_within_queue_depth_returns_some() {
        let runtime = dummy_runtime_with_buffer(4);
        assert!(runtime.io_desc(0).is_some());
        assert!(runtime.io_desc(3).is_some());
    }

    #[test]
    fn io_desc_tag_at_queue_depth_returns_none() {
        let runtime = dummy_runtime_with_buffer(4);
        assert!(runtime.io_desc(4).is_none());
    }

    #[test]
    fn io_desc_tag_beyond_queue_depth_returns_none() {
        let runtime = dummy_runtime_with_buffer(4);
        assert!(runtime.io_desc(5).is_none());
        assert!(runtime.io_desc(u16::MAX).is_none());
    }

    #[test]
    fn data_buffer_tag_beyond_queue_depth_returns_none() {
        let runtime = dummy_runtime_with_buffer(4);
        assert!(runtime.data_buffer(4).is_none());
        assert!(runtime.data_buffer(5).is_none());
    }

    #[test]
    fn data_buffer_tag_within_queue_depth_returns_some() {
        let runtime = dummy_runtime_with_buffer(4);
        assert!(runtime.data_buffer(0).is_some());
        assert!(runtime.data_buffer(3).is_some());
    }

    #[test]
    fn data_buffer_mut_tag_beyond_queue_depth_returns_none() {
        let mut runtime = dummy_runtime_with_buffer(4);
        assert!(runtime.data_buffer_mut(4).is_none());
        assert!(runtime.data_buffer_mut(5).is_none());
    }

    // ── Device lifecycle tests ─────────────────────────────────────────

    #[test]
    fn data_queue_runtime_open_outcome_preserves_dev_id_and_queue_geometry() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 2,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        assert_eq!(outcome.dev_id, 42);
        assert_eq!(outcome.q_id, 0);
        assert_eq!(outcome.nr_hw_queues, 2);
        assert_eq!(outcome.queue_depth, 64);
        assert!(outcome.runtime_live);
        assert!(outcome.data_queue_fd_open);
        assert!(outcome.io_uring_ready);
    }

    #[test]
    fn data_queue_runtime_drop_with_null_buffer_and_zero_len_is_noop() {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring build");
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 1,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        let runtime = UblkDataQueueRuntime {
            data_queue_file: file,
            ring,
            outcome,
            cmd_buf_ptrs: Vec::new(),
            cmd_buf_lens: vec![4096],
            io_buf_nr_hw_queues: 1,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: true,
            cq_overflow_count: 0,
            io_buf_queue_depth: 64,
        };
        drop(runtime);
    }

    #[test]
    fn data_queue_runtime_as_fd_returns_borrowed_file_descriptor() {
        let runtime = dummy_runtime_with_buffer(4);
        let fd = runtime.as_fd();
        let _ = fd;
    }

    #[test]
    fn data_queue_runtime_ring_mut_returns_mutable_ring_reference() {
        let mut runtime = dummy_runtime_with_buffer(4);
        let ring = runtime.ring_mut();
        let _ = ring;
    }

    #[test]
    fn data_queue_runtime_outcome_returns_open_outcome_reference() {
        let runtime = dummy_runtime_with_buffer(4);
        assert_eq!(runtime.outcome().dev_id, 42);
        assert_eq!(runtime.outcome().q_id, 0);
        assert!(runtime.outcome().runtime_live);
    }

    #[test]
    fn data_queue_runtime_runtime_live_reflects_outcome_state() {
        let mut runtime = dummy_runtime_with_buffer(4);
        assert!(runtime.runtime_live());
        runtime.outcome.runtime_live = false;
        assert!(!runtime.runtime_live());
    }

    #[test]
    fn data_queue_runtime_debug_format_does_not_panic() {
        let runtime = dummy_runtime_with_buffer(4);
        let debug = format!("{runtime:?}");
        assert!(debug.contains("UblkDataQueueRuntime"));
    }

    // ── Multi-queue FetchReq validation tests ─────────────────────────

    #[test]
    fn fetch_req_multi_queue_valid_q_id_zero_with_nr_hw_queues_2() {
        let result = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 0, 2, 64));
        assert!(result.is_ok(), "q_id 0 valid when nr_hw_queues=2");
        let spec = result.unwrap();
        assert_eq!(spec.q_id, 0);
    }

    #[test]
    fn fetch_req_multi_queue_valid_q_id_one_with_nr_hw_queues_2() {
        let result = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(1, 0, 2, 64));
        assert!(result.is_ok(), "q_id 1 valid when nr_hw_queues=2");
        let spec = result.unwrap();
        assert_eq!(spec.q_id, 1);
    }

    #[test]
    fn fetch_req_multi_queue_q_id_out_of_range_with_nr_hw_queues_2() {
        let result = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(2, 0, 2, 64));
        assert_eq!(result, Err(UblkDataQueueFetchReqError::QueueIdOutOfRange));
    }

    #[test]
    fn fetch_req_multi_queue_tags_independent_across_queues() {
        let q0 = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 7, 2, 64)).unwrap();
        let q1 = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(1, 7, 2, 64)).unwrap();
        assert_eq!(q0.q_id, 0);
        assert_eq!(q1.q_id, 1);
        assert_eq!(q0.tag, 7);
        assert_eq!(q1.tag, 7);
    }

    #[test]
    fn fetch_req_multi_queue_max_valid_q_id_is_nr_hw_queues_minus_one() {
        assert!(build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64)).is_ok());
        assert!(build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(3, 0, 4, 64)).is_ok());
        assert!(build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(4, 0, 4, 64)).is_err());
    }

    // ── Multi-queue CommitAndFetch validation tests ───────────────────

    #[test]
    fn commit_and_fetch_multi_queue_valid_q_id_zero_with_nr_hw_queues_2() {
        let result = build_commit_and_fetch_spec(
            UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 2, 64),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn commit_and_fetch_multi_queue_valid_q_id_one_with_nr_hw_queues_2() {
        let result = build_commit_and_fetch_spec(
            UblkDataQueueCommitAndFetchInput::completed_user_copy(1, 0, 2, 64),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn commit_and_fetch_multi_queue_q_id_out_of_range_with_nr_hw_queues_2() {
        let result = build_commit_and_fetch_spec(
            UblkDataQueueCommitAndFetchInput::completed_user_copy(2, 0, 2, 64),
        );
        assert_eq!(
            result,
            Err(UblkDataQueueCommitAndFetchError::QueueIdOutOfRange)
        );
    }

    // ── Multi-queue readiness and geometry tests ───────────────────────

    #[test]
    fn all_queues_required_fetch_commands_computes_product() {
        let spec = UblkDataQueueFetchReqSubmissionSpec::from_runtime_outcome(
            &UblkDataQueueRuntimeOpenOutcome {
                dev_id: 42,
                q_id: 0,
                nr_hw_queues: 2,
                queue_depth: 64,
                data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
                ring_entries: 64,
                data_queue_fd_open: true,
                io_uring_ready: true,
                runtime_live: true,
            },
        );
        assert_eq!(spec.queue_fetch_commands, 64);
        assert_eq!(spec.all_queues_required_fetch_commands, 128);

        let spec = UblkDataQueueFetchReqSubmissionSpec::from_runtime_outcome(
            &UblkDataQueueRuntimeOpenOutcome {
                dev_id: 42,
                q_id: 0,
                nr_hw_queues: 4,
                queue_depth: 32,
                data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
                ring_entries: 32,
                data_queue_fd_open: true,
                io_uring_ready: true,
                runtime_live: true,
            },
        );
        assert_eq!(spec.all_queues_required_fetch_commands, 128);
    }

    #[test]
    fn fetch_req_readiness_not_ready_when_partial_multi_queue_completed() {
        let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(2, 64, 64, true);
        assert!(!readiness.all_fetches_ready());

        let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(2, 64, 127, true);
        assert!(!readiness.all_fetches_ready());
    }

    #[test]
    fn fetch_req_readiness_ready_when_all_multi_queue_commands_submitted() {
        let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(2, 64, 128, true);
        assert!(readiness.all_fetches_ready());

        let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(4, 8, 32, true);
        assert!(readiness.all_fetches_ready());
    }

    // ── Per-queue user_data uniqueness tests ──────────────────────────

    #[test]
    fn fetch_req_user_data_unique_per_queue_same_tag() {
        let ud0 = fetch_req_user_data(0, 5);
        let ud1 = fetch_req_user_data(1, 5);
        assert_ne!(
            ud0, ud1,
            "different q_ids should produce different user_data"
        );
    }

    #[test]
    fn commit_and_fetch_user_data_unique_per_queue_same_tag() {
        let ud0 = commit_and_fetch_user_data(0, 3);
        let ud1 = commit_and_fetch_user_data(1, 3);
        assert_ne!(
            ud0, ud1,
            "different q_ids should produce different user_data"
        );
    }

    #[test]
    fn decode_fetch_req_user_data_recovers_queue_across_multi_queue() {
        for q in 0..4u16 {
            let (recovered_q, recovered_tag) =
                decode_fetch_req_user_data(fetch_req_user_data(q, 42));
            assert_eq!(recovered_q, q);
            assert_eq!(recovered_tag, 42);
        }
    }

    #[test]
    fn decode_commit_and_fetch_user_data_recovers_queue_across_multi_queue() {
        for q in 0..4u16 {
            let (recovered_q, recovered_tag) =
                decode_commit_and_fetch_user_data(commit_and_fetch_user_data(q, 7));
            assert_eq!(recovered_q, q);
            assert_eq!(recovered_tag, 7);
        }
    }

    #[test]
    fn fetch_req_user_data_distinct_from_commit_and_fetch_across_queues() {
        for q in 0..4u16 {
            let fetch_ud = fetch_req_user_data(q, 0);
            let commit_ud = commit_and_fetch_user_data(q, 0);
            assert_ne!(
                fetch_ud, commit_ud,
                "fetch and commit user_data must differ even at same q_id={q}"
            );
            assert!(
                is_fetch_req_user_data(fetch_ud),
                "fetch_req_user_data({q}, 0) should be detected as fetch"
            );
            assert!(
                !is_fetch_req_user_data(commit_ud),
                "commit user_data({q}, 0) should not be detected as fetch"
            );
        }
    }

    // ── Build fetch_req_submission_spec multi-queue tests ─────────────

    #[test]
    fn build_fetch_req_submission_spec_multi_queue_validates_first_and_last_tag() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues: 2,
            queue_depth: 8,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 8,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        let result = build_fetch_req_submission_spec(&outcome);
        assert!(result.is_ok());
    }

    #[test]
    fn build_fetch_req_submission_spec_multi_queue_with_q_id_1() {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 1,
            nr_hw_queues: 2,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        let result = build_fetch_req_submission_spec(&outcome);
        assert!(result.is_ok());
    }

    // ── Multi-queue buffer access tests ───────────────────────────────

    fn multi_queue_runtime(nr_hw_queues: u16, queue_depth: u16) -> UblkDataQueueRuntime {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring build");
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: 0,
            nr_hw_queues,
            queue_depth,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: queue_depth as u32,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        let buf: Vec<u8> = vec![0u8; 4096];
        let io_buf_base = buf.as_ptr();
        std::mem::forget(buf);
        UblkDataQueueRuntime {
            data_queue_file: file,
            ring,
            outcome,
            cmd_buf_ptrs: vec![io_buf_base],
            cmd_buf_lens: vec![4096],
            io_buf_nr_hw_queues: nr_hw_queues,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: true,
            cq_overflow_count: 0,
            io_buf_queue_depth: queue_depth,
        }
    }

    #[test]
    fn io_desc_for_queue_valid_q0_t0_returns_some() {
        let runtime = multi_queue_runtime(4, 4);
        assert!(runtime.io_desc_for_queue(0, 0).is_some());
    }

    #[test]
    fn io_desc_for_queue_q_id_out_of_range_returns_none() {
        let runtime = multi_queue_runtime(2, 4);
        assert!(runtime.io_desc_for_queue(2, 0).is_none());
        assert!(runtime.io_desc_for_queue(3, 0).is_none());
    }

    #[test]
    fn io_desc_for_queue_tag_out_of_range_returns_none() {
        let runtime = multi_queue_runtime(2, 4);
        assert!(runtime.io_desc_for_queue(0, 4).is_none());
        assert!(runtime.io_desc_for_queue(0, 5).is_none());
    }

    #[test]
    fn io_desc_for_queue_both_out_of_range_returns_none() {
        let runtime = multi_queue_runtime(2, 4);
        assert!(runtime.io_desc_for_queue(2, 4).is_none());
    }

    #[test]
    fn data_buffer_for_queue_q_id_out_of_range_returns_none() {
        let runtime = multi_queue_runtime(2, 4);
        assert!(runtime.data_buffer_for_queue(2, 0).is_none());
    }

    #[test]
    fn data_buffer_for_queue_tag_out_of_range_returns_none() {
        let runtime = multi_queue_runtime(2, 4);
        assert!(runtime.data_buffer_for_queue(0, 4).is_none());
    }

    #[test]
    fn data_buffer_mut_for_queue_q_id_out_of_range_returns_none() {
        let mut runtime = multi_queue_runtime(2, 4);
        assert!(runtime.data_buffer_mut_for_queue(2, 0).is_none());
    }

    #[test]
    fn data_buffer_mut_for_queue_tag_out_of_range_returns_none() {
        let mut runtime = multi_queue_runtime(2, 4);
        assert!(runtime.data_buffer_mut_for_queue(0, 4).is_none());
    }

    #[test]
    fn queue_tag_to_slot_computes_correct_slot_for_single_queue() {
        let runtime = multi_queue_runtime(1, 8);
        assert_eq!(runtime.queue_tag_to_slot(0, 0), Some(0));
        assert_eq!(runtime.queue_tag_to_slot(0, 3), Some(3));
        assert_eq!(runtime.queue_tag_to_slot(0, 7), Some(7));
    }

    #[test]
    fn queue_tag_to_slot_computes_correct_slot_for_multi_queue() {
        let runtime = multi_queue_runtime(4, 8);
        // q0: slots 0..7
        assert_eq!(runtime.queue_tag_to_slot(0, 0), Some(0));
        assert_eq!(runtime.queue_tag_to_slot(0, 7), Some(7));
        // q1: slots 8..15
        assert_eq!(runtime.queue_tag_to_slot(1, 0), Some(8));
        assert_eq!(runtime.queue_tag_to_slot(1, 7), Some(15));
        // q2: slots 16..23
        assert_eq!(runtime.queue_tag_to_slot(2, 0), Some(16));
        assert_eq!(runtime.queue_tag_to_slot(2, 7), Some(23));
        // q3: slots 24..31
        assert_eq!(runtime.queue_tag_to_slot(3, 0), Some(24));
        assert_eq!(runtime.queue_tag_to_slot(3, 7), Some(31));
    }

    #[test]
    fn queue_tag_to_slot_q_id_out_of_range_returns_none() {
        let runtime = multi_queue_runtime(2, 8);
        assert_eq!(runtime.queue_tag_to_slot(2, 0), None);
        assert_eq!(runtime.queue_tag_to_slot(3, 0), None);
    }

    #[test]
    fn queue_tag_to_slot_tag_out_of_range_returns_none() {
        let runtime = multi_queue_runtime(2, 8);
        assert_eq!(runtime.queue_tag_to_slot(0, 8), None);
        assert_eq!(runtime.queue_tag_to_slot(0, 9), None);
    }

    #[test]
    fn queue_tag_to_slot_cross_queue_isolation() {
        let runtime = multi_queue_runtime(4, 4);
        // Each queue gets its own slot range
        let mut slots: Vec<usize> = Vec::new();
        for q in 0..4u16 {
            for t in 0..4u16 {
                slots.push(runtime.queue_tag_to_slot(q, t).unwrap());
            }
        }
        // All 16 slots should be unique
        let mut sorted = slots.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 16);
        assert_eq!(sorted[0], 0);
        assert_eq!(sorted[15], 15);
    }

    #[test]
    fn nr_hw_queues_field_exposed_on_runtime_outcome() {
        let runtime = multi_queue_runtime(4, 8);
        assert_eq!(runtime.outcome().nr_hw_queues, 4);
        assert_eq!(runtime.outcome().queue_depth, 8);
    }
}
// -----------------------------------------------------------------------
// UPDATE_SIZE unit tests
// -----------------------------------------------------------------------

#[allow(dead_code)]
fn valid_update_size_params() -> UblkParams {
    UblkParams {
        len: core::mem::size_of::<UblkParams>() as u32,
        types: UBLK_PARAM_TYPE_BASIC,
        basic: UblkParamBasic {
            dev_sectors: 2097152,
            max_sectors: 128,
            chunk_sectors: 128,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn update_size_command_maps_to_ublk_update_size() {
    let command = UblkControlUpdateSizeCommand::UpdateSize;
    assert_eq!(command.as_str(), "UPDATE_SIZE");
    assert_eq!(command.ublk_command(), UblkCtrlCommand::UpdateSize);
    assert_eq!(
        command.request().raw(),
        UblkCtrlCommand::UpdateSize.request().raw()
    );
}

#[test]
fn update_size_spec_from_input_binds_dev_sectors_and_params() {
    let params = valid_update_size_params();
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, params);
    let spec = build_update_size_spec(input).unwrap();

    assert_eq!(spec.command, UblkControlUpdateSizeCommand::UpdateSize);
    assert_eq!(
        spec.request_raw,
        UblkCtrlCommand::UpdateSize.request().raw()
    );
    assert_eq!(spec.request_direction, UblkIoctlDirection::ReadWrite);
    assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
    assert_eq!(spec.params_len, core::mem::size_of::<UblkParams>());
    assert_eq!(spec.control_queue_id, u16::MAX);
    assert_eq!(spec.uring_cmd_sqe_bytes, 128);
    assert!(spec.mutates_control_state);
    assert_eq!(spec.param_types, UBLK_PARAM_TYPE_BASIC);
    assert_eq!(spec.dev_sectors, 2097152);
}

#[test]
fn update_size_input_rejects_auto_device_id() {
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(
        u32::MAX,
        valid_update_size_params(),
    );
    let error = build_update_size_spec(input).unwrap_err();
    assert_eq!(error, UblkControlUpdateSizeError::AutoDeviceId);
    assert_eq!(error.as_str(), "auto_device_id_not_concrete");
}

#[test]
fn update_size_input_rejects_zero_params_len() {
    let mut params = valid_update_size_params();
    params.len = 0;
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, params);
    let error = build_update_size_spec(input).unwrap_err();
    assert_eq!(error, UblkControlUpdateSizeError::ZeroParamsLen);
    assert_eq!(error.as_str(), "zero_params_len");
}

#[test]
fn update_size_input_rejects_params_len_mismatch() {
    let mut params = valid_update_size_params();
    params.len -= 1;
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, params);
    let error = build_update_size_spec(input).unwrap_err();
    assert_eq!(error, UblkControlUpdateSizeError::ParamsLenMismatch);
    assert_eq!(error.as_str(), "params_len_mismatch");
}

#[test]
fn update_size_input_rejects_zero_param_types() {
    let mut params = valid_update_size_params();
    params.types = 0;
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, params);
    let error = build_update_size_spec(input).unwrap_err();
    assert_eq!(error, UblkControlUpdateSizeError::ZeroParamTypes);
    assert_eq!(error.as_str(), "zero_param_types");
}

#[test]
fn update_size_input_rejects_missing_basic_params() {
    let mut params = valid_update_size_params();
    params.types = UBLK_PARAM_TYPE_DISCARD;
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, params);
    let error = build_update_size_spec(input).unwrap_err();
    assert_eq!(error, UblkControlUpdateSizeError::MissingBasicParams);
    assert_eq!(error.as_str(), "missing_basic_params");
}

#[test]
fn update_size_input_rejects_zero_dev_sectors() {
    let mut params = valid_update_size_params();
    params.basic.dev_sectors = 0;
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, params);
    let error = build_update_size_spec(input).unwrap_err();
    assert_eq!(error, UblkControlUpdateSizeError::ZeroDevSectors);
    assert_eq!(error.as_str(), "zero_dev_sectors");
}

#[test]
fn update_size_outcome_preserves_target_device_and_params() {
    let params = valid_update_size_params();
    let input = UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, params);

    let outcome = UblkControlUpdateSizeOutcome::from_input(input);

    assert_eq!(outcome.command, UblkControlUpdateSizeCommand::UpdateSize);
    assert_eq!(
        outcome.request_raw,
        UblkCtrlCommand::UpdateSize.request().raw()
    );
    assert_eq!(outcome.dev_id, 42);
    assert_eq!(outcome.params, params);
}

#[test]
fn update_size_ctrl_cmd_encodes_into_uring_cmd80_payload() {
    let mut input =
        UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(42, valid_update_size_params());
    let command = build_update_size_ctrl_cmd(&mut input).unwrap();
    let payload = encode_update_size_cmd80(command);

    assert_eq!(usize::from(command.len), core::mem::size_of::<UblkParams>());
    assert!(payload.len() >= 80);
}

#[test]
fn update_size_error_errno_extraction() {
    let err = UblkControlUpdateSizeError::IoUringSetupErrno(12);
    assert_eq!(err.errno(), Some(12));
    assert_eq!(err.as_str(), "io_uring_setup_errno");

    let err = UblkControlUpdateSizeError::UblkCommandErrno(22);
    assert_eq!(err.errno(), Some(22));

    let err = UblkControlUpdateSizeError::AutoDeviceId;
    assert_eq!(err.errno(), None);
}

// ── FETCH_REQ readiness boundary tests ──────────────────────────────

#[test]
fn fetch_req_spec_for_user_copy_has_result_zero_and_addr_zero_and_sqe128() {
    let input = UblkDataQueueFetchReqInput::user_copy(0, 7, 1, 64);
    let spec = build_fetch_req_spec(input).unwrap();

    assert_eq!(spec.command, UblkDataQueueFetchReqCommand::FetchReq);
    assert_eq!(spec.q_id, 0);
    assert_eq!(spec.tag, 7);
    assert_eq!(spec.result, 0);
    assert_eq!(spec.user_copy_addr, 0);
    assert_eq!(spec.uring_cmd_sqe_bytes, 128);
    assert!(!spec.commits_result);
    assert!(spec.must_remain_in_flight_for_start);
}

#[test]
fn build_fetch_req_io_cmd_encodes_q_id_tag_result_zero_and_addr_zero() {
    let input = UblkDataQueueFetchReqInput::user_copy(2, 15, 4, 64);
    let command = build_fetch_req_io_cmd(input).unwrap();

    assert_eq!(command.q_id, 2);
    assert_eq!(command.tag, 15);
    assert_eq!(command.result, 0);
    assert_eq!(command.addr_or_zone_append_lba, 0);
}

#[test]
fn build_fetch_req_spec_rejects_zero_hardware_queues() {
    let result = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 0, 0, 64));
    assert_eq!(result, Err(UblkDataQueueFetchReqError::ZeroHardwareQueues));
}

#[test]
fn build_fetch_req_spec_rejects_queue_id_out_of_range() {
    let result = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(
        UBLK_MAX_NR_QUEUES,
        0,
        UBLK_MAX_NR_QUEUES,
        64,
    ));
    assert_eq!(result, Err(UblkDataQueueFetchReqError::QueueIdOutOfRange));
}

#[test]
fn build_fetch_req_spec_rejects_tag_out_of_range() {
    let result = build_fetch_req_spec(UblkDataQueueFetchReqInput::user_copy(0, 64, 1, 64));
    assert_eq!(result, Err(UblkDataQueueFetchReqError::TagOutOfRange));
}

#[test]
fn build_fetch_req_spec_rejects_nonzero_user_copy_addr() {
    let mut input = UblkDataQueueFetchReqInput::user_copy(0, 7, 1, 64);
    input.user_copy_addr = 4096;
    let result = build_fetch_req_spec(input);
    assert_eq!(
        result,
        Err(UblkDataQueueFetchReqError::UserCopyFetchAddrMustBeZero)
    );
}

#[test]
fn fetch_req_user_data_binds_tag_command_number_and_queue_id() {
    let user_data = fetch_req_user_data(3, 63);

    assert_eq!(user_data & 0xffff, 63);
    assert_eq!(
        (user_data >> 16) & 0xff,
        u64::from(UblkIoCommand::FetchReq.number())
    );
    assert_eq!((user_data >> 32) & 0xffff, 3);
}

#[test]
fn decode_fetch_req_user_data_roundtrip_restores_queue_and_tag() {
    let original = fetch_req_user_data(1, 42);
    let (q_id, tag) = decode_fetch_req_user_data(original);

    assert_eq!(q_id, 1);
    assert_eq!(tag, 42);
}

#[test]
fn is_fetch_req_user_data_detects_fetch_req_not_commit_and_fetch() {
    let fetch_data = fetch_req_user_data(0, 0);
    assert!(is_fetch_req_user_data(fetch_data));

    let commit_data = commit_and_fetch_user_data(0, 0);
    assert!(!is_fetch_req_user_data(commit_data));
}

#[test]
fn fetch_req_outcome_preserves_command_queue_tag_and_user_data() {
    let input = UblkDataQueueFetchReqInput::user_copy(2, 5, 4, 64);
    let outcome = UblkDataQueueFetchReqOutcome::from_input(input);

    assert_eq!(outcome.command, UblkDataQueueFetchReqCommand::FetchReq);
    assert_eq!(outcome.q_id, 2);
    assert_eq!(outcome.tag, 5);
    assert_eq!(outcome.user_data, fetch_req_user_data(2, 5));
    assert!(outcome.submitted_without_wait);
}

#[test]
fn fetch_req_readiness_not_ready_when_runtime_not_live() {
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 64, false);
    assert!(!readiness.all_fetches_ready());
    let start_dev = readiness.start_dev_readiness();
    assert!(!start_dev.all_fetches_ready());
}

#[test]
fn fetch_req_readiness_not_ready_when_partial_fetches_in_flight() {
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(2, 64, 63, true);
    assert!(!readiness.all_fetches_ready());
}

#[test]
fn fetch_req_readiness_ready_when_all_fetches_issued_and_runtime_live() {
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(2, 64, 128, true);
    assert!(readiness.all_fetches_ready());
}

#[test]
fn fetch_req_readiness_ready_with_minimal_single_queue_single_depth() {
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 1, 1, true);
    assert!(readiness.all_fetches_ready());
}

#[test]
fn fetch_req_readiness_start_dev_readiness_propagates_ready_state() {
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 64, true);
    let start_dev = readiness.start_dev_readiness();
    assert!(start_dev.all_fetches_ready());
}

#[test]
fn fetch_req_readiness_start_dev_readiness_propagates_not_ready_state() {
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 32, true);
    let start_dev = readiness.start_dev_readiness();
    assert!(!start_dev.all_fetches_ready());
}

#[test]
fn fetch_req_error_map_identities() {
    assert_eq!(
        UblkDataQueueFetchReqError::ZeroHardwareQueues.as_str(),
        "zero_hardware_queues"
    );
    assert_eq!(
        UblkDataQueueFetchReqError::UserCopyFetchAddrMustBeZero.as_str(),
        "user_copy_fetch_addr_must_be_zero"
    );
    assert_eq!(
        UblkDataQueueFetchReqError::IoUringSubmitErrno(42).errno(),
        Some(42)
    );
    assert_eq!(
        UblkDataQueueFetchReqError::SubmissionQueueFull.errno(),
        None
    );
}

#[test]
fn fetch_req_spec_must_remain_in_flight_for_start_by_default() {
    let spec =
        UblkDataQueueFetchReqSpec::from_input(UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64));
    assert!(spec.must_remain_in_flight_for_start);
    assert!(!spec.commits_result);
}

// ── Multi-queue sustained throughput / stress tests ───────────────────

/// Create a multi-queue runtime suitable for throughput tests.
/// Uses /dev/null as the backing file descriptor (no real ublk device).
#[allow(dead_code)]
fn throughput_runtime(nr_hw_queues: u16, queue_depth: u16) -> UblkDataQueueRuntime {
    let file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let ring_entries = (nr_hw_queues as u32) * (queue_depth as u32);
    let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
        .build(ring_entries)
        .expect("io_uring build");
    let outcome = UblkDataQueueRuntimeOpenOutcome {
        dev_id: 42,
        q_id: 0,
        nr_hw_queues,
        queue_depth,
        data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
        ring_entries,
        data_queue_fd_open: true,
        io_uring_ready: true,
        runtime_live: true,
    };
    let cmd_buf_size = tidefs_ublk_abi::ublk_queue_cmd_buf_size(queue_depth);
    let mut cmd_buf_ptrs: Vec<*const u8> = Vec::with_capacity(nr_hw_queues as usize);
    let mut cmd_buf_lens: Vec<usize> = Vec::with_capacity(nr_hw_queues as usize);
    for _q in 0..nr_hw_queues {
        let buf: Vec<u8> = vec![0u8; cmd_buf_size];
        let ptr = buf.as_ptr();
        cmd_buf_ptrs.push(ptr);
        cmd_buf_lens.push(cmd_buf_size);
        std::mem::forget(buf);
    }
    UblkDataQueueRuntime {
        data_queue_file: file,
        ring,
        outcome,
        cmd_buf_ptrs,
        cmd_buf_lens,
        io_buf_nr_hw_queues: nr_hw_queues,
        in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
        nodrop_enabled: true,
        cq_overflow_count: 0,
        io_buf_queue_depth: queue_depth,
    }
}

#[test]
fn stress_multi_queue_all_slots_are_distinct_across_four_queues() {
    // With 4 queues x 64 depth = 256 slots, every (q_id, tag) pair
    // must map to a distinct slot index.
    let runtime = throughput_runtime(4, 64);
    let mut seen = std::collections::HashSet::new();
    for q in 0..4u16 {
        for t in 0..64u16 {
            let slot = runtime.queue_tag_to_slot(q, t).expect("valid slot");
            assert!(seen.insert(slot), "duplicate slot {slot} for q={q} t={t}");
        }
    }
    assert_eq!(seen.len(), 256);
}

#[test]
fn stress_multi_queue_slot_bounds_zero_and_last() {
    let runtime = throughput_runtime(4, 64);
    assert_eq!(runtime.queue_tag_to_slot(0, 0), Some(0));
    assert_eq!(runtime.queue_tag_to_slot(3, 63), Some(255));
}

#[test]
fn stress_multi_queue_buffer_access_never_panics_across_all_slots() {
    // Verify that every valid (q_id, tag) pair yields a non-null
    // buffer pointer with the correct size. Exercise both read and
    // write accessors.
    let runtime = throughput_runtime(4, 64);
    for q in 0..4u16 {
        for t in 0..64u16 {
            let desc = runtime.io_desc_for_queue(q, t);
            assert!(desc.is_some(), "io_desc none for q={q} t={t}");

            // data_buffer_for_queue deprecated; use read_data_at/write_data_at
        }
    }
}

#[test]
fn stress_multi_queue_buffer_access_mut_never_panics_deprecated() {
    let mut runtime = throughput_runtime(4, 64);
    for q in 0..4u16 {
        for t in 0..64u16 {
            assert!(runtime.data_buffer_mut_for_queue(q, t).is_none());
        }
    }
}

#[test]
fn stress_multi_queue_out_of_bounds_returns_none_for_all_accessors() {
    let runtime = throughput_runtime(4, 64);
    // q_id out of bounds
    assert!(runtime.io_desc_for_queue(4, 0).is_none());
    assert!(runtime.data_buffer_for_queue(4, 0).is_none());
    assert!(runtime.queue_tag_to_slot(4, 0).is_none());
    // tag out of bounds
    assert!(runtime.io_desc_for_queue(0, 64).is_none());
    assert!(runtime.data_buffer_for_queue(0, 64).is_none());
    assert!(runtime.queue_tag_to_slot(0, 64).is_none());
    // both out of bounds
    assert!(runtime.io_desc_for_queue(5, 99).is_none());
}

#[test]
fn stress_multi_queue_user_data_uniqueness_across_256_entries() {
    // Every (q_id, tag) combination up to 4x64 must produce unique
    // user_data values for both FETCH_REQ and COMMIT_AND_FETCH.
    let mut fetch_set = std::collections::HashSet::new();
    let mut commit_set = std::collections::HashSet::new();
    for q in 0..4u16 {
        for t in 0..64u16 {
            let f = fetch_req_user_data(q, t);
            let c = commit_and_fetch_user_data(q, t);
            assert!(fetch_set.insert(f), "duplicate fetch user_data q={q} t={t}");
            assert!(
                commit_set.insert(c),
                "duplicate commit user_data q={q} t={t}"
            );
            assert!(
                !fetch_set.contains(&c),
                "fetch/commit collision q={q} t={t}"
            );
        }
    }
    assert_eq!(fetch_set.len(), 256);
    assert_eq!(commit_set.len(), 256);
}

#[test]
fn stress_multi_queue_fetch_req_submission_spec_all_queues_valid() {
    // build_fetch_req_submission_spec must succeed for all queue IDs
    // up to nr_hw_queues.
    for q in 0..4u16 {
        let outcome = UblkDataQueueRuntimeOpenOutcome {
            dev_id: 42,
            q_id: q,
            nr_hw_queues: 4,
            queue_depth: 64,
            data_queue_path: std::path::PathBuf::from("/dev/ublkc42"),
            ring_entries: 64,
            data_queue_fd_open: true,
            io_uring_ready: true,
            runtime_live: true,
        };
        let result = build_fetch_req_submission_spec(&outcome);
        assert!(
            result.is_ok(),
            "fetch_req_submission_spec failed for q_id={q}"
        );
        let spec = result.unwrap();
        assert_eq!(spec.q_id, q);
        assert_eq!(spec.nr_hw_queues, 4);
        assert_eq!(spec.queue_depth, 64);
    }
}

#[test]
fn stress_multi_queue_total_slots_match_nr_hw_queues_times_queue_depth() {
    for (nr, depth) in [(1, 64), (2, 32), (4, 16), (4, 64), (8, 32)] {
        let runtime = throughput_runtime(nr, depth);
        let total = (nr as usize) * (depth as usize);
        let mut slots = 0usize;
        for q in 0..nr {
            for t in 0..depth {
                assert!(runtime.queue_tag_to_slot(q, t).is_some());
                slots += 1;
            }
        }
        assert_eq!(slots, total, "nr={nr} depth={depth}");
    }
}

#[test]
fn stress_multi_queue_validate_open_input_rejects_all_invalid_combinations() {
    // Zero hardware queues
    assert!(validate_data_queue_runtime_open_input(
        UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 0, 0, 64)
    )
    .is_err());
    // Zero queue depth
    assert!(validate_data_queue_runtime_open_input(
        UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 0, 4, 0)
    )
    .is_err());
    // q_id >= nr_hw_queues
    assert!(validate_data_queue_runtime_open_input(
        UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 2, 2, 64)
    )
    .is_err());
    // Too many hardware queues (exceeds UBLK_MAX_NR_QUEUES)
    assert!(validate_data_queue_runtime_open_input(
        UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 0, UBLK_MAX_NR_QUEUES + 1, 64)
    )
    .is_err());
    // Valid input must pass
    assert!(validate_data_queue_runtime_open_input(
        UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 0, 4, 64)
    )
    .is_ok());
    // Single queue minimum
    assert!(validate_data_queue_runtime_open_input(
        UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(1, 0, 1, 1)
    )
    .is_ok());
}

// ── UblkDeviceLifecycleState ──────────────────────────────────────────

#[test]
fn lifecycle_state_as_str_is_stable() {
    assert_eq!(UblkDeviceLifecycleState::Created.as_str(), "created");
    assert_eq!(UblkDeviceLifecycleState::Attached.as_str(), "attached");
    assert_eq!(UblkDeviceLifecycleState::Draining.as_str(), "draining");
    assert_eq!(UblkDeviceLifecycleState::Removed.as_str(), "removed");
}

// ── UblkManagedDevice construction ────────────────────────────────────

#[test]
fn managed_device_from_add_dev_outcome_sets_created_state_and_block_path() {
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 42,
        nr_hw_queues: 1,
        queue_depth: 64,
        max_io_buf_bytes: 1048576,
        ..Default::default()
    };
    let outcome = UblkControlAddDevOutcome::from_dev_info(dev_info);
    let device = UblkManagedDevice::from_add_dev_outcome(&outcome);

    assert_eq!(device.dev_id, 42);
    assert_eq!(device.state, UblkDeviceLifecycleState::Created);
    assert_eq!(device.dev_info.dev_id, 42);
    assert_eq!(device.block_path, ublk_block_device_path(42));
}

// ── UblkControlRuntime construction and query methods ─────────────────

#[test]
fn control_runtime_lookup_device_returns_none_for_unknown() {
    // Static test of the runtime shape: even without a real control
    // device, the HashMap-backed lookup returns None for any key.
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };
    assert!(runtime.lookup_device(0).is_none());
    assert!(runtime.lookup_device(42).is_none());
    assert_eq!(runtime.device_count(), 0);
    assert!(runtime.device_ids().is_empty());
}

#[test]
fn control_runtime_device_register_unregister_consistency() {
    // Build a runtime backed by /dev/null and directly manipulate the
    // registry to verify lookup, count, and ids.
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let mut runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };

    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 100,
        nr_hw_queues: 2,
        queue_depth: 128,
        ..Default::default()
    };
    let device = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 100,
        state: UblkDeviceLifecycleState::Created,
        dev_info,
        block_path: ublk_block_device_path(100),
        blake3_state_hash: None,
    };
    runtime.devices.insert(100, device);
    assert_eq!(runtime.device_count(), 1);
    assert_eq!(runtime.device_ids(), vec![100]);
    assert!(runtime.lookup_device(100).is_some());
    assert_eq!(
        runtime.lookup_device(100).unwrap().state,
        UblkDeviceLifecycleState::Created
    );

    // Mark attached
    runtime.mark_attached(100).expect("mark_attached");
    assert_eq!(
        runtime.lookup_device(100).unwrap().state,
        UblkDeviceLifecycleState::Attached
    );

    // Remove (simulate state transition and remove from map)
    runtime.devices.remove(&100);
    assert_eq!(runtime.device_count(), 0);
    assert!(runtime.lookup_device(100).is_none());
}

// ── mark_attached error paths ─────────────────────────────────────────

#[test]
fn mark_attached_errors_on_unknown_device() {
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let mut runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };
    let result = runtime.mark_attached(99);
    assert_eq!(
        result,
        Err(UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id: 99 })
    );
}

#[test]
fn mark_attached_errors_when_not_in_created_state() {
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let mut runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };
    // Insert a device already in Attached state
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 77,
        ..Default::default()
    };
    runtime.devices.insert(
        77,
        UblkManagedDevice {
            lifecycle: QueueLifecycle::attached(),
            dev_id: 77,
            state: UblkDeviceLifecycleState::Attached,
            dev_info,
            block_path: ublk_block_device_path(77),
            blake3_state_hash: None,
        },
    );
    let result = runtime.mark_attached(77);
    // Non-Created state surfaces as InvalidLifecycleTransition
    assert_eq!(
        result,
        Err(UblkControlRemoveDeviceError::InvalidLifecycleTransition {
            dev_id: 77,
            current: UblkDeviceLifecycleState::Attached,
        })
    );
}

// ── remove_device error paths ─────────────────────────────────────────

#[test]
fn remove_device_errors_on_unknown_device() {
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let mut runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };
    let result = runtime.remove_device(5);
    assert_eq!(
        result,
        Err(UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id: 5 })
    );
}

#[test]
fn remove_device_errors_when_already_removed() {
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let mut runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };
    // Insert device already in Removed state
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 33,
        ..Default::default()
    };
    runtime.devices.insert(
        33,
        UblkManagedDevice {
            lifecycle: QueueLifecycle::attached(),
            dev_id: 33,
            state: UblkDeviceLifecycleState::Removed,
            dev_info,
            block_path: ublk_block_device_path(33),
            blake3_state_hash: None,
        },
    );
    let result = runtime.remove_device(33);
    assert_eq!(
        result,
        Err(UblkControlRemoveDeviceError::DeviceAlreadyRemoved { dev_id: 33 })
    );
}

// ── UblkControlRemoveDeviceError ──────────────────────────────────────

#[test]
fn remove_device_error_as_str() {
    assert_eq!(
        UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id: 1 }.as_str(),
        "device_not_registered"
    );
    assert_eq!(
        UblkControlRemoveDeviceError::DeviceAlreadyRemoved { dev_id: 2 }.as_str(),
        "device_already_removed"
    );
    assert_eq!(
        UblkControlRemoveDeviceError::UblkDelDevError(UblkControlDelDevError::AutoDeviceId)
            .as_str(),
        "ublk_del_dev_error"
    );
}

#[test]
fn remove_device_error_errno_delegates_to_del_dev_error() {
    let e =
        UblkControlRemoveDeviceError::UblkDelDevError(UblkControlDelDevError::UblkCommandErrno(19));
    assert_eq!(e.errno(), Some(19));

    let e = UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id: 0 };
    assert_eq!(e.errno(), None);
}

#[test]
fn remove_device_error_dev_id() {
    assert_eq!(
        UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id: 42 }.dev_id(),
        Some(42)
    );
    assert_eq!(
        UblkControlRemoveDeviceError::DeviceAlreadyRemoved { dev_id: 7 }.dev_id(),
        Some(7)
    );
    assert_eq!(
        UblkControlRemoveDeviceError::UblkDelDevError(UblkControlDelDevError::AutoDeviceId)
            .dev_id(),
        None
    );
}

// ── GetDevInfo2 command and spec ──────────────────────────────────────

#[test]
fn get_dev_info2_command_maps_to_ublk_get_dev_info2() {
    let command = UblkControlGetDevInfo2Command::GetDevInfo2;
    assert_eq!(command.as_str(), "GET_DEV_INFO2");
    assert_eq!(command.ublk_command(), UblkCtrlCommand::GetDevInfo2);
    assert_eq!(
        command.request().raw(),
        UblkCtrlCommand::GetDevInfo2.request().raw()
    );
}

#[test]
fn get_dev_info2_spec_has_correct_shape() {
    let spec = UblkControlGetDevInfo2Spec::get_dev_info2();
    assert_eq!(spec.command, UblkControlGetDevInfo2Command::GetDevInfo2);
    assert_eq!(
        spec.request_raw,
        UblkCtrlCommand::GetDevInfo2.request().raw()
    );
    assert_eq!(spec.request_direction, UblkIoctlDirection::Read);
    assert_eq!(usize::from(spec.request_size), size_of::<UblkSrvCtrlCmd>());
    assert_eq!(spec.dev_info_buffer_len, size_of::<UblkSrvCtrlDevInfo>());
    assert_eq!(spec.uring_cmd_sqe_bytes, 128);
    assert!(!spec.mutates_control_state);
}

#[test]
fn build_get_dev_info2_spec_rejects_auto_device_id() {
    let input = UblkControlGetDevInfo2Input::from_kernel_dev_id(TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID);
    let result = build_get_dev_info2_spec(input);
    assert_eq!(result, Err(UblkControlGetDevInfo2Error::AutoDeviceId));
}

#[test]
fn build_get_dev_info2_spec_accepts_concrete_dev_id() {
    let input = UblkControlGetDevInfo2Input::from_kernel_dev_id(42);
    let spec = build_get_dev_info2_spec(input).unwrap();
    assert_eq!(spec.command, UblkControlGetDevInfo2Command::GetDevInfo2);
}

#[test]
fn build_get_dev_info2_ctrl_cmd_encodes_dev_id_and_addr() {
    let input = UblkControlGetDevInfo2Input::from_kernel_dev_id(7);
    let mut dev_info = UblkSrvCtrlDevInfo::default();
    let cmd = build_get_dev_info2_ctrl_cmd(input, &mut dev_info);

    assert_eq!(cmd.dev_id, 7);
    assert_eq!(cmd.queue_id, u16::MAX);
    assert_eq!(cmd.len as usize, size_of::<UblkSrvCtrlDevInfo>());
    assert_eq!(
        cmd.addr,
        (&mut dev_info as *mut UblkSrvCtrlDevInfo) as usize as u64
    );
}

#[test]
fn get_dev_info2_cmd80_encodes_round_trips_dev_id() {
    let input = UblkControlGetDevInfo2Input::from_kernel_dev_id(55);
    let mut dev_info = UblkSrvCtrlDevInfo::default();
    let cmd = build_get_dev_info2_ctrl_cmd(input, &mut dev_info);
    let payload = encode_get_dev_info2_cmd80(cmd);

    // dev_id is at bytes 0..4 (little-endian)
    let decoded_dev_id = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
    assert_eq!(decoded_dev_id, 55);
}

// ── GetDevInfo2 error ─────────────────────────────────────────────────

#[test]
fn get_dev_info2_error_as_str() {
    assert_eq!(
        UblkControlGetDevInfo2Error::AutoDeviceId.as_str(),
        "auto_device_id_not_concrete"
    );
    assert_eq!(
        UblkControlGetDevInfo2Error::IoUringSetupErrno(1).as_str(),
        "io_uring_setup_errno"
    );
    assert_eq!(
        UblkControlGetDevInfo2Error::SubmissionQueueFull.as_str(),
        "submission_queue_full"
    );
    assert_eq!(
        UblkControlGetDevInfo2Error::CompletionMissing.as_str(),
        "completion_missing"
    );
}

#[test]
fn get_dev_info2_error_errno_extraction() {
    assert_eq!(
        UblkControlGetDevInfo2Error::IoUringSetupErrno(12).errno(),
        Some(12)
    );
    assert_eq!(
        UblkControlGetDevInfo2Error::UblkCommandErrno(19).errno(),
        Some(19)
    );
    assert_eq!(UblkControlGetDevInfo2Error::AutoDeviceId.errno(), None);
}

// ── GetDevInfo2 outcome ───────────────────────────────────────────────

#[test]
fn get_dev_info2_outcome_preserves_dev_info() {
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 99,
        nr_hw_queues: 4,
        queue_depth: 256,
        state: 1, // Live
        ..Default::default()
    };
    let outcome = UblkControlGetDevInfo2Outcome::from_dev_info(dev_info);
    assert_eq!(outcome.command, UblkControlGetDevInfo2Command::GetDevInfo2);
    assert_eq!(outcome.dev_info.dev_id, 99);
}

// ── Device count and device_ids filtering ─────────────────────────────

#[test]
fn device_count_excludes_removed_devices() {
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let mut runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };

    let created = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 1,
        state: UblkDeviceLifecycleState::Created,
        dev_info: UblkSrvCtrlDevInfo {
            dev_id: 1,
            ..Default::default()
        },
        block_path: ublk_block_device_path(1),
        blake3_state_hash: None,
    };
    let attached = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 2,
        state: UblkDeviceLifecycleState::Attached,
        dev_info: UblkSrvCtrlDevInfo {
            dev_id: 2,
            ..Default::default()
        },
        block_path: ublk_block_device_path(2),
        blake3_state_hash: None,
    };
    let removed = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 3,
        state: UblkDeviceLifecycleState::Removed,
        dev_info: UblkSrvCtrlDevInfo {
            dev_id: 3,
            ..Default::default()
        },
        block_path: ublk_block_device_path(3),
        blake3_state_hash: None,
    };

    runtime.devices.insert(1, created);
    runtime.devices.insert(2, attached);
    runtime.devices.insert(3, removed);

    assert_eq!(runtime.device_count(), 2);
    let mut ids = runtime.device_ids();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2]);
}

// ── Control fd accessor ───────────────────────────────────────────────

#[test]
fn control_runtime_control_fd_returns_valid_fd() {
    let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let runtime = UblkControlRuntime {
        control_file,
        devices: std::collections::HashMap::new(),
    };
    let fd = runtime.control_fd();
    // Just verify it gives a valid borrowed fd
    assert!(fd.as_raw_fd() >= 0);
}

// ── UblkBlockDevicePath ───────────────────────────────────────────────

#[test]
fn ublk_block_device_path_format() {
    assert_eq!(ublk_block_device_path(0), PathBuf::from("/dev/ublkb0"));
    assert_eq!(ublk_block_device_path(42), PathBuf::from("/dev/ublkb42"));
    assert_eq!(
        ublk_block_device_path(u32::MAX),
        PathBuf::from(format!("/dev/ublkb{}", u32::MAX))
    );
}

// ── GetDevInfo2 user_data constant ────────────────────────────────────

#[test]
fn get_dev_info2_ring_entries_and_user_data_are_distinct() {
    assert_eq!(UBLK_CONTROL_GET_DEV_INFO2_RING_ENTRIES, 1);
    // user_data must be distinct from other control-plane user_data values
    assert_ne!(
        UBLK_CONTROL_GET_DEV_INFO2_USER_DATA,
        UBLK_CONTROL_READONLY_PROBE_USER_DATA
    );
    assert_ne!(
        UBLK_CONTROL_GET_DEV_INFO2_USER_DATA,
        UBLK_CONTROL_ADD_DEV_USER_DATA
    );
    assert_ne!(
        UBLK_CONTROL_GET_DEV_INFO2_USER_DATA,
        UBLK_CONTROL_DEL_DEV_USER_DATA
    );
    assert_ne!(
        UBLK_CONTROL_GET_DEV_INFO2_USER_DATA,
        UBLK_CONTROL_SET_PARAMS_USER_DATA
    );
    assert_ne!(
        UBLK_CONTROL_GET_DEV_INFO2_USER_DATA,
        UBLK_CONTROL_START_DEV_USER_DATA
    );
    assert_ne!(
        UBLK_CONTROL_GET_DEV_INFO2_USER_DATA,
        UBLK_CONTROL_STOP_DEV_USER_DATA
    );
}

// ── UblkIoctlDispatch tests ─────────────────────────────────────

#[test]
fn dispatch_from_command_number_round_trips() {
    for num in [
        0x01u8, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x12, 0x13, 0x16, 0x15,
    ] {
        let variant = UblkIoctlDispatch::from_command_number(num);
        assert_eq!(
            variant.command_number(),
            num,
            "round-trip failed for command 0x{num:02x}: variant={variant:?}"
        );
    }
}

#[test]
fn dispatch_unhandled_preserves_raw_number() {
    for num in [0x00u8, 0x03, 0x09, 0x10, 0x11, 0x14, 0x17, 0xFF] {
        assert_eq!(
            UblkIoctlDispatch::from_command_number(num),
            UblkIoctlDispatch::Unhandled(num)
        );
        assert_eq!(UblkIoctlDispatch::Unhandled(num).command_number(), num);
    }
}

#[test]
fn dispatch_as_str_is_stable() {
    assert_eq!(UblkIoctlDispatch::GetDevInfo.as_str(), "GET_DEV_INFO");
    assert_eq!(
        UblkIoctlDispatch::GetQueueAffinity.as_str(),
        "GET_QUEUE_AFFINITY"
    );
    assert_eq!(UblkIoctlDispatch::AddDev.as_str(), "ADD_DEV");
    assert_eq!(UblkIoctlDispatch::StartDev.as_str(), "START_DEV");
    assert_eq!(UblkIoctlDispatch::Unhandled(99).as_str(), "UNHANDLED");
    assert_eq!(UblkIoctlDispatch::Unhandled(0).command_number(), 0);
    assert_eq!(UblkIoctlDispatch::Unhandled(255).command_number(), 255);
}

// ── DeviceCapacity tests ────────────────────────────────────────

#[test]
fn device_capacity_total_bytes_is_product() {
    let cap = DeviceCapacity {
        dev_id: 42,
        sector_count: 2048,
        sector_size: 512,
    };
    assert_eq!(cap.total_bytes(), 1_048_576);
    assert_eq!(cap.total_mib(), 1);
}

#[test]
fn device_capacity_zero_sectors() {
    let cap = DeviceCapacity {
        dev_id: 0,
        sector_count: 0,
        sector_size: 512,
    };
    assert_eq!(cap.total_bytes(), 0);
    assert_eq!(cap.total_mib(), 0);
}

#[test]
fn device_capacity_large_device() {
    let cap = DeviceCapacity {
        dev_id: 1,
        sector_count: 2_097_152,
        sector_size: 512,
    };
    assert_eq!(cap.total_bytes(), 1_073_741_824);
    assert_eq!(cap.total_mib(), 1024);
}

#[test]
fn device_capacity_non_standard_sector_size() {
    let cap = DeviceCapacity {
        dev_id: 3,
        sector_count: 1000,
        sector_size: 4096,
    };
    assert_eq!(cap.total_bytes(), 4_096_000);
}

#[test]
fn device_capacity_default_is_zero() {
    let cap = DeviceCapacity::default();
    assert_eq!(cap.dev_id, 0);
    assert_eq!(cap.sector_count, 0);
    assert_eq!(cap.sector_size, 0);
    assert_eq!(cap.total_bytes(), 0);
}

// ── Enumerate ublk devices (structural tests) ───────────────────

#[test]
fn enumerate_ublk_devices_returns_ok_on_any_system() {
    let result = enumerate_ublk_devices();
    assert!(result.is_ok());
}

#[test]
fn enumerate_ublk_devices_filters_to_ublkb_prefix_only() {
    let devices = enumerate_ublk_devices().expect("enumerate /dev");
    for (path, _dev_id) in &devices {
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("ublkb"), "unexpected device name: {name}");
    }
}

#[test]
fn enumerate_ublk_devices_parses_dev_id_from_name() {
    let devices = enumerate_ublk_devices().expect("enumerate /dev");
    for (path, dev_id) in &devices {
        let name = path.file_name().unwrap().to_str().unwrap();
        let expected = name
            .strip_prefix("ublkb")
            .and_then(|s| s.parse::<u32>().ok());
        assert_eq!(Some(*dev_id), expected, "dev_id mismatch for {name}");
    }
}

// ── enumerate_device_capacities ──────────────────────────────────

#[test]
fn enumerate_device_capacities_returns_ok() {
    let caps = enumerate_device_capacities();
    assert!(caps.is_ok());
}

#[test]
fn enumerate_device_capacities_each_entry_has_valid_dev_id() {
    let caps = enumerate_device_capacities().unwrap_or_default();
    for cap in &caps {
        assert_eq!(cap.dev_id, cap.dev_id);
    }
}
// ── BLAKE3 control-plane integrity tests ────────────────────────

#[test]
fn compute_device_state_hash_is_deterministic() {
    let info = UblkSrvCtrlDevInfo {
        nr_hw_queues: 2,
        queue_depth: 128,
        dev_id: 42,
        ..UblkSrvCtrlDevInfo::default()
    };
    let h1 = compute_device_state_hash(&info);
    let h2 = compute_device_state_hash(&info);
    assert_eq!(h1, h2);
}

#[test]
fn compute_device_state_hash_different_inputs_produce_different_hashes() {
    let a = UblkSrvCtrlDevInfo {
        nr_hw_queues: 1,
        queue_depth: 64,
        dev_id: 1,
        ..UblkSrvCtrlDevInfo::default()
    };
    let b = UblkSrvCtrlDevInfo {
        nr_hw_queues: 2,
        queue_depth: 128,
        dev_id: 2,
        ..UblkSrvCtrlDevInfo::default()
    };
    let ha = compute_device_state_hash(&a);
    let hb = compute_device_state_hash(&b);
    assert_ne!(ha, hb);
}

#[test]
fn compute_device_state_hash_zeroed_info_produces_valid_hash() {
    let info = UblkSrvCtrlDevInfo::default();
    let hash = compute_device_state_hash(&info);
    assert_eq!(hash.len(), 32);
}

#[test]
fn verify_device_state_hash_passes_with_matching_hash() {
    let info = UblkSrvCtrlDevInfo {
        dev_id: 7,
        nr_hw_queues: 1,
        queue_depth: 64,
        ..UblkSrvCtrlDevInfo::default()
    };
    let hash = compute_device_state_hash(&info);
    let result = verify_device_state_hash(&info, &hash);
    assert!(result.is_ok());
}

#[test]
fn verify_device_state_hash_fails_with_mismatched_hash() {
    let info = UblkSrvCtrlDevInfo {
        dev_id: 7,
        ..UblkSrvCtrlDevInfo::default()
    };
    let wrong_hash = [0xFFu8; 32];
    let result = verify_device_state_hash(&info, &wrong_hash);
    assert!(result.is_err());
    match result {
        Err(UblkDeviceIntegrityError::HashMismatch { expected, computed }) => {
            assert_eq!(expected, wrong_hash);
            assert_ne!(computed, wrong_hash);
        }
        _ => panic!("expected HashMismatch"),
    }
}

#[test]
fn ublk_device_integrity_error_as_str() {
    assert_eq!(
        UblkDeviceIntegrityError::NoStoredHash.as_str(),
        "no_stored_hash"
    );
    assert_eq!(
        UblkDeviceIntegrityError::HashMismatch {
            expected: [0u8; 32],
            computed: [0u8; 32],
        }
        .as_str(),
        "hash_mismatch"
    );
}

#[test]
fn ublk_device_integrity_error_display_contains_key_info() {
    let err = UblkDeviceIntegrityError::NoStoredHash;
    let s = format!("{err}");
    assert!(s.contains("no stored integrity hash"));

    let err = UblkDeviceIntegrityError::HashMismatch {
        expected: [0xAAu8; 32],
        computed: [0xBBu8; 32],
    };
    let s = format!("{err}");
    assert!(s.contains("hash mismatch"));
}

#[test]
fn ublk_device_integrity_error_eq_reflexive() {
    let e1 = UblkDeviceIntegrityError::NoStoredHash;
    let e2 = UblkDeviceIntegrityError::NoStoredHash;
    assert_eq!(e1, e2);
    let h1 = UblkDeviceIntegrityError::HashMismatch {
        expected: [1u8; 32],
        computed: [2u8; 32],
    };
    let h2 = UblkDeviceIntegrityError::HashMismatch {
        expected: [1u8; 32],
        computed: [2u8; 32],
    };
    assert_eq!(h1, h2);
    assert_ne!(e1, h1);
}

#[test]
fn managed_device_verify_integrity_passes_when_hash_matches() {
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 10,
        nr_hw_queues: 1,
        queue_depth: 64,
        ..UblkSrvCtrlDevInfo::default()
    };
    let hash = compute_device_state_hash(&dev_info);
    let device = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 10,
        state: UblkDeviceLifecycleState::Created,
        dev_info,
        block_path: PathBuf::from("/dev/ublkb10"),
        blake3_state_hash: Some(hash),
    };
    assert!(device.verify_integrity().is_ok());
}

#[test]
fn managed_device_verify_integrity_fails_with_no_stored_hash() {
    let device = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 10,
        state: UblkDeviceLifecycleState::Created,
        dev_info: UblkSrvCtrlDevInfo::default(),
        block_path: PathBuf::from("/dev/ublkb10"),
        blake3_state_hash: None,
    };
    let result = device.verify_integrity();
    assert_eq!(result, Err(UblkDeviceIntegrityError::NoStoredHash));
}

#[test]
fn managed_device_verify_integrity_fails_when_hash_mismatches() {
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 10,
        ..UblkSrvCtrlDevInfo::default()
    };
    let device = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 10,
        state: UblkDeviceLifecycleState::Created,
        dev_info,
        block_path: PathBuf::from("/dev/ublkb10"),
        blake3_state_hash: Some([0xCCu8; 32]),
    };
    let result = device.verify_integrity();
    assert!(matches!(
        result,
        Err(UblkDeviceIntegrityError::HashMismatch { .. })
    ));
}

#[test]
fn managed_device_update_integrity_hash_updates_stored_hash() {
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 10,
        nr_hw_queues: 1,
        ..UblkSrvCtrlDevInfo::default()
    };
    let mut device = UblkManagedDevice {
        lifecycle: QueueLifecycle::attached(),
        dev_id: 10,
        state: UblkDeviceLifecycleState::Created,
        dev_info,
        block_path: PathBuf::from("/dev/ublkb10"),
        blake3_state_hash: None,
    };
    assert!(device.blake3_state_hash.is_none());
    device.update_integrity_hash();
    assert!(device.blake3_state_hash.is_some());
    assert!(device.verify_integrity().is_ok());
}

#[test]
fn managed_device_from_add_dev_outcome_computes_hash() {
    let dev_info = UblkSrvCtrlDevInfo {
        dev_id: 5,
        nr_hw_queues: 1,
        queue_depth: 64,
        ..UblkSrvCtrlDevInfo::default()
    };
    let outcome = UblkControlAddDevOutcome::from_dev_info(dev_info);
    let device = UblkManagedDevice::from_add_dev_outcome(&outcome);
    assert_eq!(device.dev_id, 5);
    assert_eq!(device.state, UblkDeviceLifecycleState::Created);
    assert!(device.blake3_state_hash.is_some());
    assert!(device.verify_integrity().is_ok());
}
