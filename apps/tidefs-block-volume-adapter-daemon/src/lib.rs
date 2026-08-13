// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Library target for tidefs-block-volume-adapter-daemon.
// Exposes the daemon's product module graph to integration tests and library
// consumers. The binary target at main.rs has its own root; the library
// target duplicates the necessary crate-level items without publishing
// fake ublk-device simulators as product API.

#![deny(clippy::all)]
// clippy::pedantic is allowed for now; future chunks should whittle down this
// allow list by fixing one pedantic lint group at a time.
#![allow(clippy::pedantic)]
#![deny(unsafe_code)]
#![allow(dead_code, unused_imports)]
use std::error::Error;
use std::fmt;

use tidefs_types_package_profile_catalog::BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE;
pub mod kernel_check;
pub mod signal_shutdown;

// Re-export modules for integration tests
mod block_device_validation;
pub mod shutdown;
pub mod storage_backend;
pub mod ublk_completion;
pub mod ublk_control_open;
pub mod ublk_io;
pub mod ublk_io_handler;
pub mod ublk_io_uring;
mod ublk_parameter_spec;

// Re-export key integration-test types that are defined in private
// sub-modules of ublk_control_open.
pub use ublk_control_open::data_queue_worker::{
    DataQueueWorker, DataQueueWorkerError, DataQueueWorkerReport, DataQueueWorkerResultEntry,
};
pub(crate) use ublk_parameter_spec::{
    build_ublk_parameter_spec_report, build_ublk_parameter_spec_report_with_geometry,
};
#[cfg(test)]
pub(crate) use ublk_parameter_spec::{build_ublk_parameters, UblkParameterSpecError};

// ── Crate-level constants ─────────────────────────────────────────────

// ── barrier_audit: ublk barrier tracing audit log ──────────────────
// Emits structured JSON-line audit entries for every flush and
// FUA-write barrier processed by the ublk I/O handler.

use std::time::{SystemTime, UNIX_EPOCH};

/// Distinctive prefix for barrier audit lines in stderr.
pub const BARRIER_AUDIT_PREFIX: &str = "UBLK_BARRIER_AUDIT";

/// Identifies the kind of barrier that triggered the audit entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarrierType {
    Flush,
    FuaWrite,
}

impl BarrierType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Flush => "FLUSH",
            Self::FuaWrite => "FUA_WRITE",
        }
    }
}

/// Outcome of a barrier operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarrierResult {
    Completed,
    Failed,
}

impl BarrierResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
        }
    }
}

/// Monotonic barrier audit log for the ublk I/O serving path.
///
/// Records structured JSON-line entries on stderr for each barrier
/// (flush or FUA write) processed by the ublk data-queue I/O loop.
/// The `committed_root` field captures the txg committed-root pointer
/// (if available from the backend) to tie guest barriers directly to
/// committed-root publication validation.
#[derive(Debug)]
pub struct BarrierAuditLog {
    next_seq: u64,
    /// Count of flush barriers recorded.
    pub flush_count: u64,
    /// Count of FUA-write barriers recorded.
    pub fua_write_count: u64,
    /// Count of barrier operations that failed.
    pub failed_count: u64,
}

impl BarrierAuditLog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            flush_count: 0,
            fua_write_count: 0,
            failed_count: 0,
        }
    }

    pub fn record(&mut self, barrier_type: BarrierType, result: BarrierResult) {
        self.record_with_root(barrier_type, result, None);
    }

    /// Record a barrier event with an optional committed-root anchor.
    ///
    /// `committed_root_opt` encodes the txg committed-root pointer as a hex
    /// string when the backend exposes it. File-image backends produce `None`.
    pub fn record_with_root(
        &mut self,
        barrier_type: BarrierType,
        result: BarrierResult,
        committed_root_opt: Option<u64>,
    ) {
        match barrier_type {
            BarrierType::Flush => self.flush_count += 1,
            BarrierType::FuaWrite => self.fua_write_count += 1,
        };
        if result == BarrierResult::Failed {
            self.failed_count += 1;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root_part = if let Some(cr) = committed_root_opt {
            format!(",\"committed_root\":\"0x{cr:016x}\"")
        } else {
            String::new()
        };
        eprintln!(
            "{BARRIER_AUDIT_PREFIX} {{\"seq\":{seq},\"type\":\"{}\",\"ts_ns\":{now},\"result\":\"{}\"{root_part}}}",
            barrier_type.as_str(),
            result.as_str(),
        );
    }

    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Total barrier entries recorded.
    #[must_use]
    pub fn total_entries(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }
}

impl Default for BarrierAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

pub const LINUX_SECTOR_SIZE_BYTES: usize = 512;

pub(crate) const NON_CLAIMS: &[&str] = &[
    "no_dev_ublk_control",
    "no_fio_validation",
    "no_mkfs_mount_or_guest_filesystem",
    "no_production_resize_failover_runtime",
    "parent_ow_301_pc_005_pc_012_remain_open",
];

// ── AppError (shared with main.rs) ────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppError {
    message: String,
}

impl AppError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block-volume adapter app surface failed: {}",
            self.message
        )
    }
}

impl Error for AppError {}

// ── Shared functions (duplicated from main.rs for library target) ─────

pub(crate) fn print_plan_step(step: tidefs_ublk_abi::UblkControlPlanStep) {
    let request = step.request();
    println!("plan.{}.command={}", step.ordinal, step.command.as_str());
    println!(
        "plan.{}.command_nr=0x{:02x}",
        step.ordinal,
        step.command.number()
    );
    println!("plan.{}.ioctl_raw=0x{:08x}", step.ordinal, request.raw());
    println!(
        "plan.{}.ioctl_direction={}",
        step.ordinal,
        request.direction().as_str()
    );
    println!("plan.{}.ioctl_type=u", step.ordinal);
    println!("plan.{}.ioctl_size={}", step.ordinal, request.size());
    println!(
        "plan.{}.mutation_class={}",
        step.ordinal,
        step.mutation_class.as_str()
    );
    println!(
        "plan.{}.mutates_control_state={}",
        step.ordinal,
        step.mutates_control_state()
    );
}
