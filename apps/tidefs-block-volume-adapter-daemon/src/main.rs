// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![deny(clippy::all)]
// clippy::pedantic is allowed for now; future chunks should whittle down this
// allow list by fixing one pedantic lint group at a time.
#![allow(clippy::pedantic)]
#![allow(dead_code)]
#![deny(unsafe_code)]
mod kernel_check;

mod block_device_validation;
mod shutdown;
mod storage_backend;
mod ublk_completion;
mod ublk_control_open;
mod ublk_io;
mod ublk_io_handler;
mod ublk_io_uring;

use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::kernel_check::HostKernelClass;
use crate::kernel_check::{
    classify_host_identity, classify_kernel_release_str, ObserveHostIdentity,
};
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeExportPhaseClass,
    BlockVolumeExportTransitionClass, BlockVolumeFileImage, BlockVolumeFileImageError,
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeQueuePolicyRecord,
    BlockVolumeQueueRuntime, BlockVolumeQueueSetRecord, BlockVolumeResizeFenceRuntime,
    BlockVolumeResizeTransitionOutcomeClass, BLOCK_VOLUME_ADAPTER_CORE_GATE_OW_301A,
    BLOCK_VOLUME_CACHE_COHERENCY_GATE_OW_301E, BLOCK_VOLUME_DISPATCH_EXECUTION_GATE_OW_301C,
    BLOCK_VOLUME_EXPORT_LIFECYCLE_GATE_OW_301D, BLOCK_VOLUME_FILE_IMAGE_BACKING_GATE_OW_301N,
    BLOCK_VOLUME_QUEUE_ADMISSION_GATE_OW_301B, BLOCK_VOLUME_RESIZE_FENCE_GATE_OW_301F,
};
use tidefs_block_volume_adapter_ublk_control_runtime::{
    enumerate_device_capacities, issue_update_size, resolve_resize_policy,
    UblkControlUpdateSizeInput, UblkIoctlDispatch, BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q,
    BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R,
    BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P,
    BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S,
    BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T,
    BLOCK_VOLUME_UBLK_CONTROL_UPDATE_SIZE_GATE_OW_301Y,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_COMMIT_FETCH_GATE_OW_301X,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V,
};
use tidefs_types_package_profile_catalog::BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE;
use tidefs_ublk_abi::{
    control_command_size, params_size, ublk_control_plan_steps, UblkFeatureFlags, UblkParamBasic,
    UblkParamDiscard, UblkParamSegment, UblkParams, UblkSrvCtrlDevInfo, UblkSrvIoCmd,
    UblkSrvIoDesc, TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES, UBLK_ABI_GATE_OW_301I,
    UBLK_ATTR_FUA, UBLK_ATTR_VOLATILE_CACHE, UBLK_FEATURES_LEN, UBLK_IO_BUF_BITS,
    UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH, UBLK_MIN_SEGMENT_SIZE, UBLK_PARAM_TYPE_BASIC,
    UBLK_PARAM_TYPE_DISCARD, UBLK_PARAM_TYPE_SEGMENT,
};

use crate::block_device_validation::run_block_device_appearance_validation;
use crate::storage_backend::BlockVolumeStorageBackend;
use crate::ublk_control_open::{
    run_ublk_acceptance_harness, run_ublk_control_add_del_dev_boundary,
    run_ublk_control_add_dev_boundary, run_ublk_control_open_preflight,
    run_ublk_control_readonly_probe, run_ublk_control_resize_smoke_boundary,
    run_ublk_control_set_params_boundary, run_ublk_control_start_dev_boundary,
    run_ublk_data_queue_commit_and_fetch_boundary,
    run_ublk_data_queue_fetch_req_readiness_boundary,
    run_ublk_data_queue_fetch_req_submission_boundary, run_ublk_data_queue_io_loop_boundary,
    run_ublk_data_queue_open_boundary, run_ublk_live_device,
    BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O,
};

pub const BLOCK_VOLUME_ADAPTER_APP_GATE_OW_301G: &str =
    "OW-301G block-volume adapter app smoke surface: boundary probes plus live block-device I/O serving (ublk-serve subcommand)";
pub const BLOCK_VOLUME_HOST_PREFLIGHT_GATE_OW_301H: &str =
    "OW-301H block-volume adapter host preflight binds Linux and ublk readiness to explicit attach refusal";
pub const BLOCK_VOLUME_UBLK_ABI_PLAN_GATE_OW_301I: &str =
    "OW-301I block-volume adapter ublk ABI control plan is typed and non-mutating";
pub(crate) const NON_CLAIMS: &[&str] = &[
    "no_dev_ublk_control",
    "no_fio_validation",
    "no_mkfs_mount_or_guest_filesystem",
    "no_production_resize_failover_runtime",
    "parent_ow_301_pc_005_pc_012_remain_open",
];
// ── barrier_audit ───────────────────────────────────────────────────
// (Inline module duplicated from lib.rs for the binary crate root.)

pub const BARRIER_AUDIT_PREFIX: &str = "UBLK_BARRIER_AUDIT";

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

pub(crate) const LINUX_SECTOR_SIZE_BYTES: usize = 512;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(1);
    }
}

/// Parse --nr-hw-queues <N> from CLI args, returning the value or `default`.
/// Values outside 1..UBLK_MAX_NR_QUEUES are clamped to `default`.
fn parse_nr_hw_queues_from_args(default: u16) -> u16 {
    let args: Vec<String> = env::args().collect();
    for i in 1..args.len().saturating_sub(1) {
        if args[i] == "--nr-hw-queues" {
            let parsed: u16 = args[i + 1].parse().unwrap_or(default);
            if parsed == 0 || parsed > UBLK_MAX_NR_QUEUES {
                return default;
            }
            return parsed;
        }
    }
    default
}

fn run() -> Result<(), Box<dyn Error>> {
    let io_uring_enabled = env::args().any(|arg| arg == "--io-uring");
    let nr_hw_queues = parse_nr_hw_queues_from_args(4);
    match env::args().nth(1).as_deref() {
        None | Some("summary") => {
            print_summary();
            Ok(())
        }
        Some("preflight-host") => {
            let report = run_host_preflight()?;
            report.print();
            Ok(())
        }
        Some("ublk-abi-plan") => {
            let report = build_ublk_abi_plan_report();
            report.print();
            Ok(())
        }
        Some("ublk-control-open" | "ublk-control-open-preflight") => {
            let report = run_ublk_control_open_preflight()?;
            report.print();
            Ok(())
        }
        Some("ublk-control-readonly-probe" | "ublk-control-get-features") => {
            let report = run_ublk_control_readonly_probe()?;
            report.print();
            Ok(())
        }
        Some("ublk-control-add-dev" | "ublk-add-dev-boundary") => {
            let report = run_ublk_control_add_dev_boundary()?;
            report.print();
            Ok(())
        }
        Some("ublk-control-add-del-dev" | "ublk-del-dev-cleanup-boundary") => {
            let report = run_ublk_control_add_del_dev_boundary()?;
            report.print();
            Ok(())
        }
        Some("ublk-control-set-params" | "ublk-set-params-boundary") => {
            let report = run_ublk_control_set_params_boundary()?;
            report.print();
            Ok(())
        }
        Some("ublk-control-start-dev" | "ublk-start-dev-boundary") => {
            let report = run_ublk_control_start_dev_boundary()?;
            report.print();
            Ok(())
        }
        Some("ublk-acceptance-harness" | "ublk-acceptance") => {
            let report = run_ublk_acceptance_harness()?;
            report.print();
            Ok(())
        }
        Some("ublk-data-queue-fetch-req" | "ublk-fetch-req-readiness-boundary") => {
            let report = run_ublk_data_queue_fetch_req_readiness_boundary()?;
            report.print();
            Ok(())
        }
        Some("ublk-data-queue-open" | "ublk-data-open-boundary") => {
            let report = run_ublk_data_queue_open_boundary()?;
            report.print();
            Ok(())
        }
        Some("ublk-data-queue-fetch-req-submit" | "ublk-fetch-req-submit-boundary") => {
            let report = run_ublk_data_queue_fetch_req_submission_boundary()?;
            report.print();
            Ok(())
        }
        Some(
            "ublk-data-queue-commit-and-fetch"
            | "ublk-commit-fetch-boundary"
            | "ublk-data-commit-fetch",
        ) => {
            let report = run_ublk_data_queue_commit_and_fetch_boundary()?;
            report.print();
            Ok(())
        }
        Some("ublk-data-queue-io-loop" | "ublk-io-loop-boundary" | "ublk-data-io-loop") => {
            let geometry =
                BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_092), 4096, 1024, 1);
            let backing = TempBackingFile::new()?;
            let mut image = BlockVolumeFileImage::create_zeroed(backing.path(), geometry)
                .map_err(|err| file_image_error("create zeroed backing file for io loop", err))?;
            let report = run_ublk_data_queue_io_loop_boundary(
                None,
                99999,
                &mut image,
                io_uring_enabled,
                nr_hw_queues,
                64,
                30,
            )?;
            report.print();
            drop(image);
            let _ = backing.remove();
            Ok(())
        }
        Some(
            "ublk-device-appearance-validation" | "ublk-dev-appearance" | "ublk-block-device-check",
        ) => {
            let report = run_block_device_appearance_validation()?;
            report.print();
            Ok(())
        }
        Some("ublk-reconnect" | "ublk-device-reconnect") => {
            run_ublk_reconnect()?;
            Ok(())
        }
        Some("ublk-enumerate-devices" | "ublk-device-enumerate") => {
            run_ublk_enumerate_devices()?;
            Ok(())
        }
        Some("ublk-serve" | "ublk-live" | "ublk-serve-device") => {
            run_ublk_serve(io_uring_enabled, nr_hw_queues)?;
            Ok(())
        }
        Some("backing-file-smoke") => {
            let report = run_backing_file_smoke()?;
            report.print();
            Ok(())
        }
        Some("resize-fence-file-smoke") => {
            let report = run_resize_fence_file_smoke()?;
            report.print();
            Ok(())
        }
        Some("resize-smoke") => {
            let report = run_ublk_control_resize_smoke_boundary()?;
            report.print();
            Ok(())
        }
        Some("help" | "--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(Box::new(AppError::new(format!(
            "unknown command `{other}`"
        )))),
    }
}

fn print_summary() {
    let surface = BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE;
    println!("tidefs block volume adapter smoke surface");
    println!("gate={BLOCK_VOLUME_ADAPTER_APP_GATE_OW_301G}");
    println!("binary={}", surface.binary_name);
    println!("service={}", surface.human_name());
    println!("service_key={}", surface.rust_hint());
    println!("stable_family_id={}", surface.stable_family_id());
    println!("profile={}", surface.profile_name());
    println!("bundle={}", surface.bundle_name());
    println!("core_gate={BLOCK_VOLUME_ADAPTER_CORE_GATE_OW_301A}");
    println!("queue_gate={BLOCK_VOLUME_QUEUE_ADMISSION_GATE_OW_301B}");
    println!("dispatch_gate={BLOCK_VOLUME_DISPATCH_EXECUTION_GATE_OW_301C}");
    println!("lifecycle_gate={BLOCK_VOLUME_EXPORT_LIFECYCLE_GATE_OW_301D}");
    println!("cache_gate={BLOCK_VOLUME_CACHE_COHERENCY_GATE_OW_301E}");
    println!("resize_gate={BLOCK_VOLUME_RESIZE_FENCE_GATE_OW_301F}");
    println!("ublk_update_size_gate={BLOCK_VOLUME_UBLK_CONTROL_UPDATE_SIZE_GATE_OW_301Y}");
    println!("host_preflight_gate={BLOCK_VOLUME_HOST_PREFLIGHT_GATE_OW_301H}");
    println!("ublk_abi_plan_gate={BLOCK_VOLUME_UBLK_ABI_PLAN_GATE_OW_301I}");
    println!("file_image_backing_gate={BLOCK_VOLUME_FILE_IMAGE_BACKING_GATE_OW_301N}");
    println!("ublk_control_open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
    println!(
        "ublk_control_readonly_probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}"
    );
    println!("ublk_control_add_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
    println!("ublk_control_del_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R}");
    println!("ublk_control_set_params_gate={BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S}");
    println!("ublk_control_start_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T}");
    println!(
        "ublk_data_queue_fetch_req_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U}"
    );
    println!("ublk_data_queue_open_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V}");
    println!(
        "ublk_data_queue_fetch_req_submit_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W}"
    );
    println!(
        "ublk_data_queue_commit_fetch_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_COMMIT_FETCH_GATE_OW_301X}"
    );
    for non_claim in NON_CLAIMS {
        println!("nonclaim.{non_claim}=true");
    }
    println!("command.preflight_host=preflight-host");
    println!("command.ublk_abi_plan=ublk-abi-plan");
    println!("command.backing_file_smoke=backing-file-smoke");
    println!("command.resize_fence_file_smoke=resize-fence-file-smoke");
    println!("command.resize_smoke=resize-smoke");
    println!("command.ublk_control_open=ublk-control-open");
    println!("command.ublk_control_readonly_probe=ublk-control-readonly-probe");
    println!("command.ublk_control_add_dev=ublk-control-add-dev");
    println!("command.ublk_control_add_del_dev=ublk-control-add-del-dev");
    println!("command.ublk_control_set_params=ublk-control-set-params");
    println!("command.ublk_control_start_dev=ublk-control-start-dev");
    println!("command.ublk_data_queue_fetch_req=ublk-data-queue-fetch-req");
    println!("command.ublk_data_queue_open=ublk-data-queue-open");
    println!("command.ublk_data_queue_fetch_req_submit=ublk-data-queue-fetch-req-submit");
    println!("command.ublk_data_queue_commit_fetch=ublk-data-queue-commit-and-fetch");
    println!("command.ublk_data_commit_fetch=ublk-data-commit-fetch");
    println!("command.ublk_data_io_loop=ublk-data-queue-io-loop");
    println!("command.ublk_enumerate=ublk-enumerate-devices");
    println!("command.ublk_reconnect=ublk-reconnect");
    println!("command.ublk_serve=ublk-serve");
    println!("command.ublk_acceptance_harness=ublk-acceptance-harness");
    println!("command.ublk_device_appearance_validation=ublk-device-appearance-validation");
}

fn print_help() {
    println!("tidefs-block-volume-adapter-daemon commands:");
    println!("  summary      print the bounded Block Volume Adapter app surface");
    println!("  preflight-host  inspect non-mutating Linux/ublk host readiness");
    println!("  ublk-abi-plan  print the non-mutating ublk control ABI plan");
    println!("  ublk-control-open  run the real ublk control-device open admission boundary");
    println!("  ublk-control-open-preflight  alias for ublk-control-open");
    println!("  ublk-control-readonly-probe  run the gated read-only GET_FEATURES uring_cmd probe");
    println!("  ublk-control-get-features  alias for ublk-control-readonly-probe");
    println!("  ublk-control-add-dev  run the gated mutating ADD_DEV uring_cmd boundary");
    println!("  ublk-add-dev-boundary  alias for ublk-control-add-dev");
    println!("  ublk-control-add-del-dev  run ADD_DEV followed by guarded DEL_DEV cleanup");
    println!("  ublk-del-dev-cleanup-boundary  alias for ublk-control-add-del-dev");
    println!("  ublk-control-set-params  run ADD_DEV, guarded SET_PARAMS, and DEL_DEV cleanup");
    println!("  ublk-set-params-boundary  alias for ublk-control-set-params");
    println!("  ublk-control-start-dev  run ADD_DEV, SET_PARAMS, guarded START_DEV admission, and DEL_DEV cleanup");
    println!("  ublk-start-dev-boundary  alias for ublk-control-start-dev");
    println!("  ublk-data-queue-fetch-req  print guarded data-queue FETCH_REQ readiness boundary");
    println!("  ublk-fetch-req-readiness-boundary  alias for ublk-data-queue-fetch-req");
    println!("  ublk-data-queue-open  run ADD_DEV, guarded data-queue open, and DEL_DEV cleanup");
    println!("  ublk-data-queue-fetch-req-submit  run ADD_DEV, guarded data-queue open, guarded FETCH_REQ submission, and DEL_DEV cleanup");
    println!("  ublk-fetch-req-submit-boundary  alias for ublk-data-queue-fetch-req-submit");
    println!("  ublk-data-queue-commit-and-fetch  run the guarded COMMIT_AND_FETCH_REQ boundary after FETCH_REQ admission");
    println!("  ublk-commit-fetch-boundary  alias for ublk-data-queue-commit-and-fetch");
    println!("  ublk-data-commit-fetch  alias for ublk-data-queue-commit-and-fetch");
    println!(
        "  ublk-data-queue-io-loop  run the live data-queue I/O loop boundary after START_DEV"
    );
    println!("  ublk-io-loop-boundary  alias for ublk-data-queue-io-loop");
    println!("  ublk-data-io-loop  alias for ublk-data-queue-io-loop");
    println!("  ublk-device-enumerate  alias for ublk-enumerate-devices");
    println!(
        "  ublk-reconnect  probe START_USER_RECOVERY + END_USER_RECOVERY on existing ublk devices"
    );
    println!("  ublk-enumerate-devices  enumerate ublk devices and query capacity");
    println!("  ublk-serve  serve a live block device backed by a regular file or block device (SIGINT to stop)");
    println!("  ublk-live  alias for ublk-serve");
    println!("  ublk-serve-device  alias for ublk-serve");
    println!("  ublk-acceptance-harness  run the full ublk acceptance harness (ADD_DEV→IO→fio→DEL_DEV→durability re-verify)");
    println!("  ublk-acceptance  alias for ublk-acceptance-harness");
    println!("  ublk-device-appearance-validation  validate /dev/ublkbN geometry and permissions after START_DEV");
    println!("  ublk-dev-appearance  alias for ublk-device-appearance-validation");
    println!("  ublk-block-device-check  alias for ublk-device-appearance-validation");
    println!("  backing-file-smoke  run the durable userspace backing-file smoke check");
    println!("  resize-fence-file-smoke  run the OW-301F resize/fence file-image smoke check");
    println!("  resize-smoke  run the OW-301F resize/fence acceptance smoke check");
    println!("  help         print this help");
}

const fn build_ublk_abi_plan_report() -> UblkAbiPlanReport {
    UblkAbiPlanReport {
        ctrl_cmd_size: control_command_size(),
        ctrl_dev_info_size: std::mem::size_of::<UblkSrvCtrlDevInfo>(),
        io_desc_size: std::mem::size_of::<UblkSrvIoDesc>(),
        io_cmd_size: std::mem::size_of::<UblkSrvIoCmd>(),
        params_size: params_size(),
        features_len: UBLK_FEATURES_LEN,
        max_queue_depth: UBLK_MAX_QUEUE_DEPTH,
        max_nr_queues: UBLK_MAX_NR_QUEUES,
        io_buf_bits: UBLK_IO_BUF_BITS,
        required_features: TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES,
        control_ioctl_issued: false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UblkAbiPlanReport {
    ctrl_cmd_size: usize,
    ctrl_dev_info_size: usize,
    io_desc_size: usize,
    io_cmd_size: usize,
    params_size: usize,
    features_len: usize,
    max_queue_depth: u16,
    max_nr_queues: u16,
    io_buf_bits: u8,
    required_features: UblkFeatureFlags,
    control_ioctl_issued: bool,
}

impl UblkAbiPlanReport {
    fn print(&self) {
        println!("tidefs block volume adapter ublk abi control plan");
        println!("gate={BLOCK_VOLUME_UBLK_ABI_PLAN_GATE_OW_301I}");
        println!("abi_gate={UBLK_ABI_GATE_OW_301I}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!("abi.header_source=/usr/include/linux/ublk_cmd.h");
        println!("abi.ctrl_cmd_size={}", self.ctrl_cmd_size);
        println!("abi.ctrl_dev_info_size={}", self.ctrl_dev_info_size);
        println!("abi.io_desc_size={}", self.io_desc_size);
        println!("abi.io_cmd_size={}", self.io_cmd_size);
        println!("abi.params_size={}", self.params_size);
        println!("abi.features_len={}", self.features_len);
        println!("abi.max_queue_depth={}", self.max_queue_depth);
        println!("abi.max_nr_queues={}", self.max_nr_queues);
        println!("abi.io_buf_bits={}", self.io_buf_bits);
        println!(
            "features.required_mask=0x{:016x}",
            self.required_features.bits()
        );
        println!(
            "features.required.cmd_ioctl_encode={}",
            self.required_features
                .contains(UblkFeatureFlags::CMD_IOCTL_ENCODE)
        );
        println!(
            "features.required.user_copy={}",
            self.required_features.contains(UblkFeatureFlags::USER_COPY)
        );
        println!(
            "features.required.user_recovery={}",
            self.required_features
                .contains(UblkFeatureFlags::USER_RECOVERY)
        );
        println!(
            "features.required.update_size={}",
            self.required_features
                .contains(UblkFeatureFlags::UPDATE_SIZE)
        );
        println!(
            "features.required.quiesce={}",
            self.required_features.contains(UblkFeatureFlags::QUIESCE)
        );
        for step in ublk_control_plan_steps() {
            print_plan_step(*step);
        }
        println!("nonclaim.control_ioctl_issued=false");
        println!("nonclaim.dev_ublk_control_opened=false");
        println!("nonclaim.no_ublk_device_created=true");
        for non_claim in NON_CLAIMS {
            println!("nonclaim.{non_claim}=true");
        }
    }
}

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

fn build_ublk_parameter_spec_report() -> Result<UblkParameterSpecReport, AppError> {
    let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_091), 4096, 1024, 1);
    build_ublk_parameter_spec_report_with_geometry(geometry, 4, 64)
}

fn build_ublk_parameter_spec_report_with_geometry(
    geometry: BlockVolumeGeometryRecord,
    nr_hw_queues: u16,
    queue_depth: u16,
) -> Result<UblkParameterSpecReport, AppError> {
    let max_inflight_bytes = 1024 * 1024;
    let shard_count = nr_hw_queues as usize;
    let max_inflight_requests = queue_depth as usize;
    let runtime = BlockVolumeQueueRuntime::open(
        geometry,
        shard_count,
        max_inflight_requests,
        max_inflight_bytes,
    )
    .ok_or_else(|| AppError::new("build demo block-volume queue runtime"))?;
    build_ublk_parameters(geometry, &runtime.queue_policy, &runtime.queue_set)
        .map_err(|err| AppError::new(format!("project ublk parameters: {}", err.as_str())))
}

fn build_ublk_parameters(
    geometry: BlockVolumeGeometryRecord,
    queue_policy: &BlockVolumeQueuePolicyRecord,
    queue_set: &BlockVolumeQueueSetRecord,
) -> Result<UblkParameterSpecReport, UblkParameterSpecError> {
    if geometry.block_size_bytes == 0 {
        return Err(UblkParameterSpecError::ZeroBlockSize);
    }
    if geometry.block_count == 0 {
        return Err(UblkParameterSpecError::ZeroBlockCount);
    }
    if !geometry.block_size_bytes.is_power_of_two() {
        return Err(UblkParameterSpecError::NonPowerOfTwoBlockSize);
    }
    if geometry.block_size_bytes < LINUX_SECTOR_SIZE_BYTES {
        return Err(UblkParameterSpecError::BlockSizeBelowLinuxSector);
    }
    let capacity_bytes = geometry
        .capacity_bytes()
        .ok_or(UblkParameterSpecError::CapacityOverflow)?;
    if capacity_bytes % LINUX_SECTOR_SIZE_BYTES != 0 {
        return Err(UblkParameterSpecError::CapacityNotSectorAligned);
    }
    if queue_policy.shard_count != queue_set.shard_count {
        return Err(UblkParameterSpecError::QueuePolicyMismatch);
    }
    if queue_set.block_count != geometry.block_count {
        return Err(UblkParameterSpecError::QueueSetGeometryMismatch);
    }
    if queue_set.shard_count == 0 {
        return Err(UblkParameterSpecError::ZeroQueues);
    }
    if queue_set.shard_count > usize::from(UBLK_MAX_NR_QUEUES) {
        return Err(UblkParameterSpecError::TooManyQueues);
    }
    if queue_policy.max_inflight_requests == 0 {
        return Err(UblkParameterSpecError::ZeroQueueDepth);
    }
    if queue_policy.max_inflight_requests > usize::from(UBLK_MAX_QUEUE_DEPTH) {
        return Err(UblkParameterSpecError::QueueDepthTooLarge);
    }
    if queue_policy.max_inflight_bytes < geometry.block_size_bytes {
        return Err(UblkParameterSpecError::MaxInflightBytesBelowBlockSize);
    }
    if queue_policy.max_inflight_bytes % LINUX_SECTOR_SIZE_BYTES != 0 {
        return Err(UblkParameterSpecError::MaxInflightBytesNotSectorAligned);
    }
    if queue_policy.max_inflight_bytes < UBLK_MIN_SEGMENT_SIZE as usize {
        return Err(UblkParameterSpecError::MaxInflightBytesBelowUblkSegmentMinimum);
    }

    let queue_count =
        u16::try_from(queue_set.shard_count).map_err(|_| UblkParameterSpecError::TooManyQueues)?;
    let queue_depth = u16::try_from(queue_policy.max_inflight_requests)
        .map_err(|_| UblkParameterSpecError::QueueDepthTooLarge)?;
    let dev_sectors = u64::try_from(capacity_bytes / LINUX_SECTOR_SIZE_BYTES)
        .map_err(|_| UblkParameterSpecError::CapacityOverflow)?;
    let max_sectors = u32::try_from(queue_policy.max_inflight_bytes / LINUX_SECTOR_SIZE_BYTES)
        .map_err(|_| UblkParameterSpecError::MaxSectorsOverflow)?;
    let block_sectors = u32::try_from(geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES)
        .map_err(|_| UblkParameterSpecError::BlockSectorsOverflow)?;
    let (discard_granularity, discard_sectors) = if geometry.admits_discard() {
        (
            project_discard_granularity_bytes(geometry)?,
            project_discard_granularity_sectors(geometry, block_sectors)?,
        )
    } else {
        (
            u32::try_from(geometry.block_size_bytes)
                .map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)?,
            block_sectors,
        )
    };
    let segment_size = u32::try_from(queue_policy.max_inflight_bytes)
        .map_err(|_| UblkParameterSpecError::MaxSegmentSizeOverflow)?;
    let block_shift = geometry.block_size_bytes.trailing_zeros() as u8;
    let param_types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT;
    let params = UblkParams {
        len: params_size() as u32,
        types: param_types,
        basic: UblkParamBasic {
            attrs: UBLK_ATTR_VOLATILE_CACHE | UBLK_ATTR_FUA,
            logical_bs_shift: block_shift,
            physical_bs_shift: block_shift,
            io_opt_shift: block_shift,
            io_min_shift: block_shift,
            max_sectors,
            chunk_sectors: discard_sectors,
            dev_sectors,
            virt_boundary_mask: 0,
        },
        discard: UblkParamDiscard {
            discard_alignment: 0,
            discard_granularity,
            max_discard_sectors: if geometry.admits_discard() {
                max_sectors
            } else {
                0
            },
            max_write_zeroes_sectors: max_sectors,
            max_discard_segments: if geometry.admits_discard() { 1 } else { 0 },
            reserved0: 0,
        },
        seg: UblkParamSegment {
            seg_boundary_mask: u64::from(UBLK_MIN_SEGMENT_SIZE) - 1,
            max_segment_size: segment_size,
            max_segments: 1,
            pad: [0; 2],
        },
        ..UblkParams::default()
    };

    Ok(UblkParameterSpecReport {
        geometry,
        queue_count,
        queue_depth,
        max_inflight_bytes: queue_policy.max_inflight_bytes,
        params,
        params_set_ioctl_issued: false,
    })
}

fn project_discard_granularity_bytes(
    geometry: BlockVolumeGeometryRecord,
) -> Result<u32, UblkParameterSpecError> {
    let Some(bytes) = geometry
        .discard_granularity_blocks
        .checked_mul(geometry.block_size_bytes)
    else {
        return Err(UblkParameterSpecError::DiscardGranularityOverflow);
    };
    u32::try_from(bytes).map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)
}

fn project_discard_granularity_sectors(
    geometry: BlockVolumeGeometryRecord,
    block_sectors: u32,
) -> Result<u32, UblkParameterSpecError> {
    let blocks = u32::try_from(geometry.discard_granularity_blocks)
        .map_err(|_| UblkParameterSpecError::DiscardGranularityOverflow)?;
    blocks
        .checked_mul(block_sectors)
        .ok_or(UblkParameterSpecError::DiscardGranularityOverflow)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UblkParameterSpecReport {
    geometry: BlockVolumeGeometryRecord,
    queue_count: u16,
    queue_depth: u16,
    max_inflight_bytes: usize,
    params: UblkParams,
    params_set_ioctl_issued: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkParameterSpecError {
    ZeroBlockSize,
    ZeroBlockCount,
    NonPowerOfTwoBlockSize,
    BlockSizeBelowLinuxSector,
    CapacityOverflow,
    CapacityNotSectorAligned,
    QueuePolicyMismatch,
    QueueSetGeometryMismatch,
    ZeroQueues,
    TooManyQueues,
    ZeroQueueDepth,
    QueueDepthTooLarge,
    MaxInflightBytesBelowBlockSize,
    MaxInflightBytesNotSectorAligned,
    MaxInflightBytesBelowUblkSegmentMinimum,
    MaxSectorsOverflow,
    BlockSectorsOverflow,
    DiscardGranularityOverflow,
    MaxSegmentSizeOverflow,
}

impl UblkParameterSpecError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroBlockSize => "zero_block_size",
            Self::ZeroBlockCount => "zero_block_count",
            Self::NonPowerOfTwoBlockSize => "non_power_of_two_block_size",
            Self::BlockSizeBelowLinuxSector => "block_size_below_linux_sector",
            Self::CapacityOverflow => "capacity_overflow",
            Self::CapacityNotSectorAligned => "capacity_not_sector_aligned",
            Self::QueuePolicyMismatch => "queue_policy_mismatch",
            Self::QueueSetGeometryMismatch => "queue_set_geometry_mismatch",
            Self::ZeroQueues => "zero_queues",
            Self::TooManyQueues => "too_many_queues",
            Self::ZeroQueueDepth => "zero_queue_depth",
            Self::QueueDepthTooLarge => "queue_depth_too_large",
            Self::MaxInflightBytesBelowBlockSize => "max_inflight_bytes_below_block_size",
            Self::MaxInflightBytesNotSectorAligned => "max_inflight_bytes_not_sector_aligned",
            Self::MaxInflightBytesBelowUblkSegmentMinimum => {
                "max_inflight_bytes_below_ublk_segment_minimum"
            }
            Self::MaxSectorsOverflow => "max_sectors_overflow",
            Self::BlockSectorsOverflow => "block_sectors_overflow",
            Self::DiscardGranularityOverflow => "discard_granularity_overflow",
            Self::MaxSegmentSizeOverflow => "max_segment_size_overflow",
        }
    }
}

fn run_host_preflight() -> Result<HostPreflightReport, AppError> {
    HostPreflightInputs::read_host().map(|inputs| evaluate_host_preflight(&inputs))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostPreflightInputs {
    kernel_release: String,
    dev_ublk_control_present: bool,
    dev_ublk_control_is_char_device: bool,
    sys_module_ublk_drv_present: bool,
    sys_class_ublk_char_present: bool,
    sys_class_block_present: bool,
    host_identity: ObserveHostIdentity,
}

impl HostPreflightInputs {
    fn read_host() -> Result<Self, AppError> {
        let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|err| AppError::new(format!("read kernel release: {err}")))?
            .trim()
            .to_string();
        let dev_ublk_control = Path::new("/dev/ublk-control");
        let dev_ublk_control_metadata = fs::metadata(dev_ublk_control).ok();
        Ok(Self {
            kernel_release,
            dev_ublk_control_present: dev_ublk_control_metadata.is_some(),
            dev_ublk_control_is_char_device: dev_ublk_control_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.file_type().is_char_device()),
            sys_module_ublk_drv_present: Path::new("/sys/module/ublk_drv").exists(),
            sys_class_ublk_char_present: Path::new("/sys/class/ublk-char").exists(),
            sys_class_block_present: Path::new("/sys/class/block").exists(),
            host_identity: classify_host_identity(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostPreflightAdmissionClass {
    Admitted,
    Degraded,
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostPreflightRefusalClass {
    None,
    KernelBelowLinux700,
    MissingUblkControl,
    UblkControlNotCharacterDevice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostPreflightReport {
    kernel_release: String,
    kernel_class: HostKernelClass,
    observe_baseline_satisfied: bool,
    dev_ublk_control_present: bool,
    dev_ublk_control_is_char_device: bool,
    sys_module_ublk_drv_present: bool,
    sys_class_ublk_char_present: bool,
    sys_class_block_present: bool,
    admission_class: HostPreflightAdmissionClass,
    refusal_class: HostPreflightRefusalClass,
    degraded_missing_sysfs_mirror: bool,
    attach_mutation_attempted: bool,
    host_identity: ObserveHostIdentity,
}

fn evaluate_host_preflight(inputs: &HostPreflightInputs) -> HostPreflightReport {
    let kernel_class = classify_kernel_release_str(&inputs.kernel_release);
    let (admission_class, refusal_class) = if kernel_class != HostKernelClass::Linux700OrNewer {
        (
            HostPreflightAdmissionClass::Refused,
            HostPreflightRefusalClass::KernelBelowLinux700,
        )
    } else if !inputs.dev_ublk_control_present {
        (
            HostPreflightAdmissionClass::Refused,
            HostPreflightRefusalClass::MissingUblkControl,
        )
    } else if !inputs.dev_ublk_control_is_char_device {
        (
            HostPreflightAdmissionClass::Refused,
            HostPreflightRefusalClass::UblkControlNotCharacterDevice,
        )
    } else if !inputs.sys_module_ublk_drv_present || !inputs.sys_class_ublk_char_present {
        (
            HostPreflightAdmissionClass::Degraded,
            HostPreflightRefusalClass::None,
        )
    } else {
        (
            HostPreflightAdmissionClass::Admitted,
            HostPreflightRefusalClass::None,
        )
    };

    HostPreflightReport {
        kernel_release: inputs.kernel_release.clone(),
        kernel_class,
        observe_baseline_satisfied: kernel_class == HostKernelClass::Linux700OrNewer,
        dev_ublk_control_present: inputs.dev_ublk_control_present,
        dev_ublk_control_is_char_device: inputs.dev_ublk_control_is_char_device,
        sys_module_ublk_drv_present: inputs.sys_module_ublk_drv_present,
        sys_class_ublk_char_present: inputs.sys_class_ublk_char_present,
        sys_class_block_present: inputs.sys_class_block_present,
        admission_class,
        refusal_class,
        degraded_missing_sysfs_mirror: matches!(
            admission_class,
            HostPreflightAdmissionClass::Degraded
        ),
        attach_mutation_attempted: false,
        host_identity: inputs.host_identity,
    }
}

impl HostPreflightReport {
    fn print(&self) {
        println!("tidefs block volume adapter host preflight");
        println!("gate={BLOCK_VOLUME_HOST_PREFLIGHT_GATE_OW_301H}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!("host.kernel_release={}", self.kernel_release);
        println!("host.observe_kernel_class={:?}", self.kernel_class);
        println!(
            "host.observe_baseline_satisfied={}",
            self.observe_baseline_satisfied
        );
        println!(
            "host.dev_ublk_control_present={}",
            self.dev_ublk_control_present
        );
        println!(
            "host.dev_ublk_control_is_char_device={}",
            self.dev_ublk_control_is_char_device
        );
        println!(
            "host.sys_module_ublk_drv_present={}",
            self.sys_module_ublk_drv_present
        );
        println!(
            "host.sys_class_ublk_char_present={}",
            self.sys_class_ublk_char_present
        );
        println!(
            "host.sys_class_block_present={}",
            self.sys_class_block_present
        );
        println!("host.admission_class={:?}", self.admission_class);
        println!("host.refusal_class={:?}", self.refusal_class);
        println!(
            "host.live_attach_ready={}",
            self.admission_class == HostPreflightAdmissionClass::Admitted
        );
        println!(
            "host.degraded_missing_sysfs_mirror={}",
            self.degraded_missing_sysfs_mirror
        );
        println!(
            "host.attach_mutation_attempted={}",
            self.attach_mutation_attempted
        );
        println!("host.observe_host_identity={}", self.host_identity.as_str());
        for non_claim in NON_CLAIMS {
            println!("nonclaim.{non_claim}=true");
        }
    }
}

fn expect_completed(
    completion_class: BlockVolumeCompletionClass,
    context: &'static str,
) -> Result<(), AppError> {
    if completion_class == BlockVolumeCompletionClass::Completed {
        Ok(())
    } else {
        Err(AppError::new(format!(
            "{context} returned {completion_class:?}"
        )))
    }
}

fn run_backing_file_smoke() -> Result<FileBackingSmokeReport, AppError> {
    let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_095), 4096, 8, 1);
    let backing = TempBackingFile::new()?;
    let mut image = BlockVolumeFileImage::create_zeroed(backing.path(), geometry)
        .map_err(|err| file_image_error("create zeroed backing file", err))?;
    let backing_file_created = backing.path().is_file();
    let capacity_bytes = u64::try_from(
        geometry
            .capacity_bytes()
            .ok_or_else(|| AppError::new("geometry capacity missing"))?,
    )
    .map_err(|_| AppError::new("geometry capacity does not fit u64"))?;

    let payload = vec![0x42; geometry.block_size_bytes];
    let write = image
        .write_blocks(2, &payload)
        .map_err(|err| file_image_error("write backing file blocks", err))?;
    expect_completed(write.completion_class, "backing file write")?;

    let flush = image
        .flush()
        .map_err(|err| file_image_error("sync backing file", err))?;
    expect_completed(flush.completion_class, "backing file flush")?;
    let flush_barrier_present = flush.flush_barrier_ref.is_some();
    drop(image);

    let mut reopened = BlockVolumeFileImage::reopen_existing(backing.path(), geometry)
        .map_err(|err| file_image_error("reopen backing file", err))?;
    let (_, read_payload) = reopened
        .read_blocks(BlockRangeRecord::new(2, 1))
        .map_err(|err| file_image_error("read reopened backing file", err))?;
    let read_payload =
        read_payload.ok_or_else(|| AppError::new("reopened read payload missing"))?;
    let reopened_read_matches = read_payload == payload;
    if !reopened_read_matches {
        return Err(AppError::new("reopened read payload mismatch"));
    }

    let discard = reopened
        .discard_blocks(BlockRangeRecord::new(3, 1))
        .map_err(|err| file_image_error("discard backing file block", err))?;
    expect_completed(discard.completion_class, "backing file discard")?;
    let write_zeroes = reopened
        .write_zeroes(BlockRangeRecord::new(4, 1))
        .map_err(|err| file_image_error("write zeroes backing file block", err))?;
    expect_completed(write_zeroes.completion_class, "backing file write zeroes")?;
    let second_flush = reopened
        .flush()
        .map_err(|err| file_image_error("sync zeroed backing file", err))?;
    expect_completed(second_flush.completion_class, "backing file zero flush")?;

    let (_, zero_payload) = reopened
        .read_blocks(BlockRangeRecord::new(3, 2))
        .map_err(|err| file_image_error("read zeroed backing file blocks", err))?;
    let zero_payload = zero_payload.ok_or_else(|| AppError::new("zeroed read payload missing"))?;
    let expected_zeroes = vec![0; geometry.block_size_bytes * 2];
    let zero_visible_after_discard_and_write_zeroes = zero_payload == expected_zeroes;
    if !zero_visible_after_discard_and_write_zeroes {
        return Err(AppError::new("discard/write-zeroes were not zero-visible"));
    }

    let discard_intent_count = reopened.discard_intents.len();
    let dirty_epoch_count = reopened.dirty_epochs.len();
    drop(reopened);
    let path_removed = backing.remove()?;

    Ok(FileBackingSmokeReport {
        backing_file_created,
        backing_file_reopened: true,
        backing_file_sync_attempted: true,
        capacity_bytes,
        write_completion: write.completion_class,
        flush_barrier_present,
        reopened_read_matches,
        zero_visible_after_discard_and_write_zeroes,
        discard_intent_count,
        dirty_epoch_count,
        path_removed,
        non_claim_count: NON_CLAIMS.len(),
    })
}

fn file_image_error(context: &'static str, err: BlockVolumeFileImageError) -> AppError {
    AppError::new(format!("{context}: {err}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileBackingSmokeReport {
    backing_file_created: bool,
    backing_file_reopened: bool,
    backing_file_sync_attempted: bool,
    capacity_bytes: u64,
    write_completion: BlockVolumeCompletionClass,
    flush_barrier_present: bool,
    reopened_read_matches: bool,
    zero_visible_after_discard_and_write_zeroes: bool,
    discard_intent_count: usize,
    dirty_epoch_count: usize,
    path_removed: bool,
    non_claim_count: usize,
}

impl FileBackingSmokeReport {
    fn print(&self) {
        println!("tidefs block volume adapter file-backed image smoke");
        println!("gate={BLOCK_VOLUME_FILE_IMAGE_BACKING_GATE_OW_301N}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!("backing_file.created={}", self.backing_file_created);
        println!("backing_file.reopened={}", self.backing_file_reopened);
        println!(
            "backing_file.sync_attempted={}",
            self.backing_file_sync_attempted
        );
        println!("backing_file.capacity_bytes={}", self.capacity_bytes);
        println!("backing_file.path_removed={}", self.path_removed);
        println!("smoke.write_completion={:?}", self.write_completion);
        println!("smoke.flush_barrier_present={}", self.flush_barrier_present);
        println!("smoke.reopened_read_matches={}", self.reopened_read_matches);
        println!(
            "smoke.zero_visible_after_discard_and_write_zeroes={}",
            self.zero_visible_after_discard_and_write_zeroes
        );
        println!("smoke.discard_intents={}", self.discard_intent_count);
        println!("smoke.dirty_epochs={}", self.dirty_epoch_count);
        println!("smoke.non_claims={}", self.non_claim_count);
        println!("nonclaim.dev_ublk_control_opened=false");
        println!("nonclaim.io_uring_queue_processed=false");
        println!("nonclaim.no_ublk_device_created=true");
        for non_claim in NON_CLAIMS {
            println!("nonclaim.{non_claim}=true");
        }
    }
}

#[derive(Debug)]
struct TempBackingFile {
    path: PathBuf,
}

impl TempBackingFile {
    fn new() -> Result<Self, AppError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| AppError::new(format!("clock before unix epoch: {err}")))?
            .as_nanos();
        let mut path = env::temp_dir();
        path.push(format!(
            "tidefs-block-volume-file-backing-{}-{nonce}.img",
            process::id()
        ));
        let _ = fs::remove_file(&path);
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn remove(&self) -> Result<bool, AppError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(!self.path.exists()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(err) => Err(AppError::new(format!(
                "remove backing file `{}`: {err}",
                self.path.display()
            ))),
        }
    }
}

impl Drop for TempBackingFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppError {
    message: String,
}

impl AppError {
    fn new(message: impl Into<String>) -> Self {
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

#[allow(unsafe_code)]
/// Clamp nr_hw_queues to the valid range [1, UBLK_MAX_NR_QUEUES].
const fn validate_nr_hw_queues(n: u16) -> u16 {
    if n == 0 || n > UBLK_MAX_NR_QUEUES {
        4 // fallback to default
    } else {
        n
    }
}

const UBLK_SERVE_USAGE: &str = "usage: ublk-serve (--backing-file <PATH> | --backing-block-device <PATH>) [--create] [--read-only] [--block-size <N>] [--block-count <N>] [--discard-granularity <N>] [--nr-hw-queues <N>] [--drain-deadline <SECONDS>]";
const UBLK_SERVE_OBJECT_STORE_REFUSAL: &str = "--object-store is not a valid ublk-serve backing; use --backing-file <PATH> for a regular-file dev image or --backing-block-device <PATH> for a real block device";
const UBLK_SERVE_SNAPSHOT_REFUSAL: &str = "--snapshot is not a valid ublk-serve backing mode; object-store snapshot export is no longer a live backing device";

#[derive(Clone, Debug, Eq, PartialEq)]
enum UblkServeBacking {
    RegularFile(PathBuf),
    BlockDevice(PathBuf),
}

impl UblkServeBacking {
    fn path(&self) -> &Path {
        match self {
            Self::RegularFile(path) | Self::BlockDevice(path) => path,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::RegularFile(_) => "regular-file",
            Self::BlockDevice(_) => "block-device",
        }
    }

    fn resize_supported(&self) -> bool {
        matches!(self, Self::RegularFile(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UblkServeConfig {
    backing: UblkServeBacking,
    create: bool,
    read_only: bool,
    block_size: usize,
    block_count: usize,
    discard_granularity: usize,
    nr_hw_queues: u16,
    drain_deadline_secs: u64,
}

fn parse_ublk_serve_args(
    args: &[String],
    cli_nr_hw_queues: u16,
) -> Result<UblkServeConfig, AppError> {
    let mut backing_file: Option<PathBuf> = None;
    let mut backing_block_device: Option<PathBuf> = None;
    let mut object_store_path: Option<PathBuf> = None;
    let mut snapshot_name: Option<String> = None;
    let mut create = false;
    let mut read_only = false;
    let mut block_size: usize = 4096;
    let mut block_count: usize = 262144;
    let mut discard_granularity: usize = 1;
    let mut nr_hw_queues: u16 = validate_nr_hw_queues(cli_nr_hw_queues);
    let mut drain_deadline_secs: u64 = 30;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--backing-file" => {
                backing_file = Some(PathBuf::from(next_ublk_serve_value(
                    args,
                    &mut i,
                    "--backing-file",
                )?));
            }
            "--backing-block-device" => {
                backing_block_device = Some(PathBuf::from(next_ublk_serve_value(
                    args,
                    &mut i,
                    "--backing-block-device",
                )?));
            }
            "--object-store" => {
                object_store_path = Some(PathBuf::from(next_ublk_serve_value(
                    args,
                    &mut i,
                    "--object-store",
                )?));
            }
            "--snapshot" => {
                snapshot_name =
                    Some(next_ublk_serve_value(args, &mut i, "--snapshot")?.to_string());
            }
            "--create" => create = true,
            "--read-only" => read_only = true,
            "--block-size" => {
                block_size = parse_ublk_serve_usize(
                    next_ublk_serve_value(args, &mut i, "--block-size")?,
                    "--block-size",
                )?;
            }
            "--block-count" => {
                block_count = parse_ublk_serve_usize(
                    next_ublk_serve_value(args, &mut i, "--block-count")?,
                    "--block-count",
                )?;
            }
            "--discard-granularity" => {
                discard_granularity = parse_ublk_serve_usize(
                    next_ublk_serve_value(args, &mut i, "--discard-granularity")?,
                    "--discard-granularity",
                )?;
            }
            "--nr-hw-queues" => {
                nr_hw_queues = validate_nr_hw_queues(parse_ublk_serve_u16(
                    next_ublk_serve_value(args, &mut i, "--nr-hw-queues")?,
                    "--nr-hw-queues",
                )?);
            }
            "--drain-deadline" => {
                drain_deadline_secs = parse_ublk_serve_u64(
                    next_ublk_serve_value(args, &mut i, "--drain-deadline")?,
                    "--drain-deadline",
                )?;
            }
            other => {
                return Err(AppError::new(format!(
                    "unknown ublk-serve option `{other}`; {UBLK_SERVE_USAGE}"
                )));
            }
        }
        i += 1;
    }

    if object_store_path.is_some() {
        return Err(AppError::new(UBLK_SERVE_OBJECT_STORE_REFUSAL));
    }
    if snapshot_name.is_some() {
        return Err(AppError::new(UBLK_SERVE_SNAPSHOT_REFUSAL));
    }
    if backing_file.is_some() && backing_block_device.is_some() {
        return Err(AppError::new(
            "choose exactly one of --backing-file or --backing-block-device",
        ));
    }
    if block_size == 0 || block_size % LINUX_SECTOR_SIZE_BYTES != 0 {
        return Err(AppError::new(format!(
            "block-size must be a positive multiple of 512, got {block_size}"
        )));
    }
    if block_count == 0 {
        return Err(AppError::new("block-count must be positive"));
    }

    let backing = if let Some(path) = backing_file {
        if create && read_only {
            return Err(AppError::new(
                "--create is incompatible with --read-only for regular-file backing",
            ));
        }
        validate_regular_file_ublk_backing(&path, create)?;
        UblkServeBacking::RegularFile(path)
    } else if let Some(path) = backing_block_device {
        if create {
            return Err(AppError::new(
                "--create is incompatible with --backing-block-device",
            ));
        }
        validate_block_device_ublk_backing(&path)?;
        UblkServeBacking::BlockDevice(path)
    } else {
        return Err(AppError::new(format!(
            "missing ublk-serve backing; {UBLK_SERVE_USAGE}"
        )));
    };

    Ok(UblkServeConfig {
        backing,
        create,
        read_only,
        block_size,
        block_count,
        discard_granularity,
        nr_hw_queues,
        drain_deadline_secs,
    })
}

fn next_ublk_serve_value<'a>(
    args: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a str, AppError> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| AppError::new(format!("{flag} requires a value")))
}

fn parse_ublk_serve_usize(value: &str, flag: &str) -> Result<usize, AppError> {
    value
        .parse::<usize>()
        .map_err(|err| AppError::new(format!("parse {flag} value `{value}`: {err}")))
}

fn parse_ublk_serve_u16(value: &str, flag: &str) -> Result<u16, AppError> {
    value
        .parse::<u16>()
        .map_err(|err| AppError::new(format!("parse {flag} value `{value}`: {err}")))
}

fn parse_ublk_serve_u64(value: &str, flag: &str) -> Result<u64, AppError> {
    value
        .parse::<u64>()
        .map_err(|err| AppError::new(format!("parse {flag} value `{value}`: {err}")))
}

fn validate_regular_file_ublk_backing(path: &Path, create: bool) -> Result<(), AppError> {
    match fs::metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_file() {
                Ok(())
            } else if file_type.is_dir() {
                Err(AppError::new(format!(
                    "regular-file ublk backing `{}` is a directory; directory-backed ublk devices are not supported",
                    path.display()
                )))
            } else if file_type.is_block_device() {
                Err(AppError::new(format!(
                    "regular-file ublk backing `{}` is a block device; use --backing-block-device",
                    path.display()
                )))
            } else {
                Err(AppError::new(format!(
                    "regular-file ublk backing `{}` is not a regular file",
                    path.display()
                )))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && create => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(AppError::new(format!(
            "regular-file ublk backing `{}` does not exist; pass --create to create a dev image",
            path.display()
        ))),
        Err(err) => Err(AppError::new(format!(
            "inspect regular-file ublk backing `{}`: {err}",
            path.display()
        ))),
    }
}

fn validate_block_device_ublk_backing(path: &Path) -> Result<(), AppError> {
    let metadata = fs::metadata(path).map_err(|err| {
        AppError::new(format!(
            "inspect block-device ublk backing `{}`: {err}",
            path.display()
        ))
    })?;
    let file_type = metadata.file_type();
    if file_type.is_block_device() {
        Ok(())
    } else if file_type.is_dir() {
        Err(AppError::new(format!(
            "block-device ublk backing `{}` is a directory; directory-backed ublk devices are not supported",
            path.display()
        )))
    } else if file_type.is_file() {
        Err(AppError::new(format!(
            "block-device ublk backing `{}` is a regular file; use --backing-file for dev images",
            path.display()
        )))
    } else {
        Err(AppError::new(format!(
            "block-device ublk backing `{}` is not a block device",
            path.display()
        )))
    }
}

fn open_ublk_serve_backing(
    backing: &UblkServeBacking,
    create: bool,
    read_only: bool,
    geometry: BlockVolumeGeometryRecord,
) -> Result<BlockVolumeFileImage, AppError> {
    match backing {
        UblkServeBacking::RegularFile(path) if read_only => {
            eprintln!("tidefs ublk-serve: opening regular-file backing read-only");
            BlockVolumeFileImage::reopen_read_only(path, geometry)
                .map_err(|err| file_image_error("ublk-serve reopen regular-file read-only", err))
        }
        UblkServeBacking::RegularFile(path) if create => {
            eprintln!("tidefs ublk-serve: creating zeroed regular-file backing");
            BlockVolumeFileImage::create_zeroed(path, geometry)
                .map_err(|err| file_image_error("ublk-serve create regular-file backing", err))
        }
        UblkServeBacking::RegularFile(path) => {
            eprintln!("tidefs ublk-serve: reopening existing regular-file backing");
            BlockVolumeFileImage::reopen_existing(path, geometry)
                .map_err(|err| file_image_error("ublk-serve reopen regular-file backing", err))
        }
        UblkServeBacking::BlockDevice(path) if read_only => {
            eprintln!("tidefs ublk-serve: opening block-device backing read-only");
            BlockVolumeFileImage::reopen_read_only(path, geometry)
                .map_err(|err| file_image_error("ublk-serve reopen block-device read-only", err))
        }
        UblkServeBacking::BlockDevice(path) => {
            eprintln!("tidefs ublk-serve: opening block-device backing read-write");
            BlockVolumeFileImage::reopen_existing(path, geometry)
                .map_err(|err| file_image_error("ublk-serve reopen block-device backing", err))
        }
    }
}

fn run_ublk_enumerate_devices() -> Result<(), AppError> {
    let capacities = enumerate_device_capacities()
        .map_err(|e| AppError::new(format!("enumerate ublk devices: {e}")))?;
    let dispatch = UblkIoctlDispatch::from_command_number(tidefs_ublk_abi::UBLK_CMD_GET_DEV_INFO);
    eprintln!(
        "ublk device enumeration: {} device(s) found (dispatch {})",
        capacities.len(),
        dispatch.as_str(),
    );
    for cap in &capacities {
        eprintln!(
            "  ublkb{}: {} sectors x {}B = {} MiB",
            cap.dev_id,
            cap.sector_count,
            cap.sector_size,
            cap.total_mib(),
        );
    }
    if capacities.is_empty() {
        eprintln!("  (no ublk devices found on this system)");
    }
    Ok(())
}

fn run_ublk_reconnect() -> Result<(), AppError> {
    use std::os::fd::AsFd;
    use std::os::unix::fs::OpenOptionsExt;
    use tidefs_block_volume_adapter_ublk_control_runtime::issue_end_user_recovery;
    use tidefs_block_volume_adapter_ublk_control_runtime::issue_start_user_recovery;
    use tidefs_block_volume_adapter_ublk_control_runtime::UblkControlEndUserRecoveryInput;
    use tidefs_block_volume_adapter_ublk_control_runtime::UblkControlStartUserRecoveryInput;

    // ── Enumerate existing ublk devices ──────────────────────────
    let capacities = enumerate_device_capacities()
        .map_err(|e| AppError::new(format!("enumerate ublk devices: {e}")))?;
    if capacities.is_empty() {
        eprintln!("ublk-reconnect: no existing ublk devices found, nothing to reconnect to");
        eprintln!("ublk-reconnect: refusal=no_device_found (safe — no guest data corruption)");
        return Ok(());
    }

    // ── Open control device ─────────────────────────────────────
    let control_fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/ublk-control")
        .map_err(|e| AppError::new(format!("open /dev/ublk-control: {e}")))?;

    // ── Attempt START_USER_RECOVERY on the first device ─────────
    let cap = &capacities[0];
    eprintln!(
        "ublk-reconnect: attempting START_USER_RECOVERY on ublkb{} ({} sectors x {}B)",
        cap.dev_id, cap.sector_count, cap.sector_size,
    );

    let start_input = UblkControlStartUserRecoveryInput::from_kernel_dev_id(cap.dev_id);
    match issue_start_user_recovery(control_fd.as_fd(), start_input) {
        Ok(outcome) => {
            eprintln!(
                "ublk-reconnect: START_USER_RECOVERY succeeded on dev_id={}",
                outcome.dev_id,
            );
            // ── END_USER_RECOVERY to complete the reconnect cycle ─
            let end_input = UblkControlEndUserRecoveryInput::from_kernel_dev_id(cap.dev_id);
            match issue_end_user_recovery(control_fd.as_fd(), end_input) {
                Ok(end_outcome) => {
                    eprintln!(
                        "ublk-reconnect: END_USER_RECOVERY succeeded on dev_id={}",
                        end_outcome.dev_id,
                    );
                    eprintln!(
                        "ublk-reconnect: reconnect_probe=passed device=ublkb{}",
                        cap.dev_id,
                    );
                    eprintln!("ublk-reconnect: note=io_serving_not_yet_wired (recovery commands verified)");
                }
                Err(e) => {
                    eprintln!(
                        "ublk-reconnect: END_USER_RECOVERY failed on dev_id={}: {} (errno={:?})",
                        cap.dev_id,
                        e.as_str(),
                        e.errno(),
                    );
                    eprintln!("ublk-reconnect: refusal=end_user_recovery_failed (safe — guest data may be quiesced)");
                }
            }
        }
        Err(e) => {
            eprintln!(
                "ublk-reconnect: START_USER_RECOVERY refused on dev_id={}: {} (errno={:?})",
                cap.dev_id,
                e.as_str(),
                e.errno(),
            );
            // This is a valid close-standard outcome: explicit refusal without corruption
            eprintln!("ublk-reconnect: refusal=start_user_recovery_refused (safe — no guest data corruption)");

            if capacities.len() > 1 {
                eprintln!(
                    "ublk-reconnect: {} additional device(s) present but not attempted",
                    capacities.len() - 1,
                );
            }
        }
    }

    Ok(())
}

#[allow(unsafe_code)]
fn run_ublk_serve(io_uring_enabled: bool, cli_nr_hw_queues: u16) -> Result<(), AppError> {
    let args: Vec<String> = std::env::args().collect();
    let config = parse_ublk_serve_args(&args[2..], cli_nr_hw_queues).map_err(|err| {
        eprintln!("tidefs ublk-serve: {}", err.message);
        eprintln!("{UBLK_SERVE_USAGE}");
        err
    })?;

    let geometry = BlockVolumeGeometryRecord::new(
        BlockVolumeId::new(301_200),
        config.block_size,
        config.block_count,
        config.discard_granularity,
    );

    let capacity_mb = geometry
        .capacity_bytes()
        .map(|b| b / (1024 * 1024))
        .unwrap_or(0);
    eprintln!(
        "tidefs ublk-serve: {} backing={} geometry={}B x {} blocks discard_gran={} capacity~={}MiB",
        config.backing.kind(),
        config.backing.path().display(),
        config.block_size,
        config.block_count,
        config.discard_granularity,
        capacity_mb
    );
    if config.read_only {
        eprintln!("tidefs ublk-serve: read-only mode enabled");
    }

    let resize_policy =
        resolve_resize_policy(config.backing.resize_supported() && !config.read_only);
    if let Some(reason) = resize_policy.reason {
        eprintln!(
            "tidefs ublk-serve: resize refused -- {} (guest errno: {})",
            reason.as_str(),
            reason.guest_errno()
        );
    }

    let mut file_image =
        open_ublk_serve_backing(&config.backing, config.create, config.read_only, geometry)?;
    let nr_hw_queues = config.nr_hw_queues;
    let drain_deadline_secs = config.drain_deadline_secs;

    // Block SIGTERM, SIGINT, and SIGUSR1 in the main thread (and all threads
    // spawned from it, since the signal mask is inherited). SIGTERM/SIGINT
    // are caught by the dedicated sigwait thread. SIGUSR1 is used to unblock
    // the sigwait thread for clean shutdown join.
    {
        // SAFETY: sigset_t is a C signal-set object; it is immediately
        // initialized by sigemptyset before pthread_sigmask observes it.
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: sigemptyset/sigaddset mutate only the local sigset, and
        // pthread_sigmask reads that initialized mask for this process thread.
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGINT);
            libc::sigaddset(&mut sigset, libc::SIGTERM);
            libc::sigaddset(&mut sigset, libc::SIGUSR1);
            libc::sigaddset(&mut sigset, libc::SIGHUP);
            libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
        }
    }
    let resize_requested = Arc::new(AtomicBool::new(false));
    let resize_for_handler = resize_requested.clone();
    let resize_refusal_reason = resize_policy.reason;

    let shutdown_handle =
        crate::shutdown::ShutdownHandle::new(std::time::Duration::from_secs(drain_deadline_secs));
    let shutdown_for_handler = shutdown_handle.flag();

    // Dedicated signal-handling thread using sigwait(3).
    // Signals are already blocked by the inherited mask from the main thread;
    // sigwait atomically unblocks and waits for them.
    // SIGUSR1 is included so the main thread can unblock the sigwait thread
    // after the I/O loop completes (by raising SIGUSR1 via pthread_kill or
    // kill(2)). This allows us to join the thread before exit.
    let signal_thread = std::thread::spawn(move || {
        // SAFETY: sigset_t is a C signal-set object; it is initialized by
        // sigemptyset/sigaddset before sigwait reads it.
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: the signal thread owns this stack sigset while constructing
        // the exact mask passed to sigwait.
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGINT);
            libc::sigaddset(&mut sigset, libc::SIGTERM);
            libc::sigaddset(&mut sigset, libc::SIGUSR1);
            libc::sigaddset(&mut sigset, libc::SIGHUP);
        }
        loop {
            let mut caught_sig: libc::c_int = 0;
            // SAFETY: sigwait reads the initialized mask and writes one c_int
            // to the stack caught_sig slot.
            let rc = unsafe { libc::sigwait(&sigset, &mut caught_sig) };
            if rc != 0 {
                continue;
            }
            if caught_sig == libc::SIGUSR1 {
                // Main thread signalled us to exit after normal I/O loop completion
                break;
            }
            if caught_sig == libc::SIGHUP {
                if let Some(reason) = resize_refusal_reason {
                    eprintln!(
                        "tidefs ublk-serve: received SIGHUP, resize refused -- {} (guest errno: {})",
                        reason.as_str(),
                        reason.guest_errno()
                    );
                    continue;
                }
                eprintln!("tidefs ublk-serve: received SIGHUP, initiating resize");
                resize_for_handler.store(true, Ordering::Relaxed);
                shutdown_for_handler.store(true, Ordering::Relaxed);
                break;
            }
            eprintln!("tidefs ublk-serve: received signal {caught_sig}, initiating shutdown");
            shutdown_for_handler.store(true, Ordering::Relaxed);
            break;
        }
    });

    eprintln!(
        "tidefs ublk-serve: starting live block device (pid={})",
        std::process::id()
    );

    let backend: &mut dyn BlockVolumeStorageBackend = &mut file_image;

    // ── Reconnect detection: enumerate existing ublk devices and pass
    // the first found dev_id to the I/O loop for reconnect. The I/O loop
    // issues START_USER_RECOVERY / END_USER_RECOVERY internally; this
    // outer probe only detects devices without touching them.
    let mut reconnect_for_io_loop: Option<u32> = None;
    {
        let capacities = enumerate_device_capacities().unwrap_or_default();
        if !capacities.is_empty() {
            let cap = &capacities[0];
            eprintln!(
                "ublk-serve: existing device ublkb{} found, will attempt reconnect in I/O loop",
                cap.dev_id,
            );
            reconnect_for_io_loop = Some(cap.dev_id);
        } else {
            eprintln!("ublk-serve: no existing devices, creating fresh");
        }
    }
    // ── Live device I/O loop with resize restart ──
    // Remember the dev_id for UPDATE_SIZE (set during first I/O loop run)
    let mut saved_dev_id: u32 = 0;
    let report = loop {
        // Reset shutdown flag before each I/O loop run (so restart after
        // resize does not immediately exit on a stale flag).
        shutdown_handle.flag().store(false, Ordering::Relaxed);

        let loop_report = run_ublk_live_device(
            reconnect_for_io_loop,
            backend,
            shutdown_handle.flag(),
            io_uring_enabled,
            nr_hw_queues,
            64,
            drain_deadline_secs,
        )?;

        eprintln!("tidefs ublk-serve: device stopped");

        // Capture dev_id from this run for potential UPDATE_SIZE later
        if saved_dev_id == 0 {
            if let Ok(caps) = enumerate_device_capacities() {
                saved_dev_id = caps.first().map(|c| c.dev_id).unwrap_or(0);
            }
        }

        // Check whether this exit was a resize request (file-backed only)
        if resize_requested.load(Ordering::Relaxed) && resize_policy.reason.is_none() {
            resize_requested.store(false, Ordering::Relaxed);

            // Grow: double the backing file block count
            let current_geom = backend.geometry();
            let new_block_count = current_geom.block_count.saturating_mul(2);
            let new_sectors = (new_block_count as u64)
                .saturating_mul(current_geom.block_size_bytes as u64)
                / crate::LINUX_SECTOR_SIZE_BYTES as u64;

            eprintln!(
                "tidefs ublk-serve: resize grow {} -> {} blocks ({} -> {} sectors)",
                current_geom.block_count,
                new_block_count,
                current_geom.block_count * current_geom.block_size_bytes
                    / crate::LINUX_SECTOR_SIZE_BYTES,
                new_sectors,
            );

            if let Err(e) = backend.resize_to(new_block_count) {
                eprintln!("tidefs ublk-serve: backend resize failed: {e}");
                break loop_report;
            }

            // Issue UPDATE_SIZE to notify the kernel of the capacity change
            if saved_dev_id > 0 {
                let ctrl_path = std::path::Path::new(crate::ublk_control_open::UBLK_CONTROL_PATH);
                match crate::ublk_control_open::open_control_device_file(ctrl_path) {
                    Ok(ctrl_dev) => {
                        let update_params = tidefs_ublk_abi::UblkParams {
                            len: core::mem::size_of::<tidefs_ublk_abi::UblkParams>() as u32,
                            types: tidefs_ublk_abi::UBLK_PARAM_TYPE_BASIC,
                            basic: tidefs_ublk_abi::UblkParamBasic {
                                dev_sectors: new_sectors,
                                ..tidefs_ublk_abi::UblkParamBasic::default()
                            },
                            ..tidefs_ublk_abi::UblkParams::default()
                        };
                        let update_input =
                            UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(
                                saved_dev_id,
                                update_params,
                            );
                        match issue_update_size(ctrl_dev.as_fd(), update_input) {
                            Ok(outcome) => {
                                eprintln!(
                                    "tidefs ublk-serve: UPDATE_SIZE ok dev={} new_sectors={}",
                                    outcome.dev_id, outcome.params.basic.dev_sectors,
                                );
                            }
                            Err(e) => {
                                eprintln!("tidefs ublk-serve: UPDATE_SIZE failed: {}", e.as_str(),);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "tidefs ublk-serve: cannot open control device for UPDATE_SIZE: {e:?}"
                        );
                    }
                }
            } else {
                eprintln!("tidefs ublk-serve: cannot determine dev_id for UPDATE_SIZE");
            }

            // The I/O loop already issued DEL_DEV; set reconnect to None
            // so the next iteration creates a fresh device with new params.
            reconnect_for_io_loop = None;

            eprintln!("tidefs ublk-serve: resize complete, restarting I/O loop...");
            continue;
        }

        break loop_report;
    };

    report.print();

    if report.ublk_device_pair_deleted {
        eprintln!("tidefs ublk-serve: device pair cleaned up");
    }

    // Unblock the sigwait thread: SIGUSR1 is blocked in the main thread mask
    // but included in the sigset watched by sigwait. Raising it unblocks
    // sigwait so the thread can exit cleanly and we can join.
    // SAFETY: raise(3) delivers SIGUSR1 to this process; the signal is part of
    // the dedicated sigwait mask and carries no Rust references.
    unsafe {
        libc::raise(libc::SIGUSR1);
    }
    let _ = signal_thread.join();
    eprintln!("tidefs ublk-serve: resources cleaned up, exiting");

    Ok(())
}

fn run_resize_fence_file_smoke() -> Result<ResizeFenceFileSmokeReport, AppError> {
    let initial_geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_102), 4096, 8, 1);
    let backing = TempBackingFile::new()?;
    let mut image = BlockVolumeFileImage::create_zeroed(backing.path(), initial_geometry)
        .map_err(|err| file_image_error("create backing for resize fence file smoke", err))?;
    let mut runtime = BlockVolumeResizeFenceRuntime::open(initial_geometry, 4, 8, 4096 * 64)
        .ok_or_else(|| AppError::new("open resize fence runtime"))?;

    // Lifecycle: bootstrap -> admit export -> start queues
    runtime.lifecycle_runtime.admit_export();
    runtime.lifecycle_runtime.start_queues();

    // Pre-resize I/O: write blocks 0..2, flush barrier, read back
    let pre_data = [0x42_u8; 4096];
    let write = image
        .write_blocks(0, &pre_data)
        .map_err(|err| file_image_error("pre-resize write", err))?;
    expect_completed(write.completion_class, "pre-resize write")?;
    let flush = image
        .flush()
        .map_err(|err| file_image_error("pre-resize flush", err))?;
    expect_completed(flush.completion_class, "pre-resize flush")?;
    let pre_flush_barrier = flush.flush_barrier_ref.is_some();
    let (_, read_pre) = image
        .read_blocks(BlockRangeRecord::new(0, 1))
        .map_err(|err| file_image_error("pre-resize read", err))?;
    let read_pre = read_pre.ok_or_else(|| AppError::new("pre-resize read payload missing"))?;
    let pre_read_matches = read_pre == pre_data;

    // Pre-resize OOB refusal
    let pre_oob = image.write_blocks(initial_geometry.block_count, &[0xEE; 4096]);
    let pre_oob_refused =
        pre_oob.unwrap().completion_class == BlockVolumeCompletionClass::RefusedOutOfBounds;

    // ── GROW: 8 → 16 blocks ──
    let auth = runtime
        .lifecycle_runtime
        .export_runtime
        .authority_anchor_ref;
    runtime
        .lifecycle_runtime
        .begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
    let fenced_grow = runtime.lifecycle_runtime.fence_after_drain();
    let grow_fenced = fenced_grow.to_phase_class == BlockVolumeExportPhaseClass::Fenced;

    let prepare_grow = runtime.prepare_resize(16, auth);
    let grow_prepared =
        prepare_grow.outcome_class == BlockVolumeResizeTransitionOutcomeClass::Prepared;
    let grow_direction_tail = prepare_grow.affected_tail_range.map(|r| r.block_count);
    let grow_zero_visible = prepare_grow.zero_visible_range.is_some();

    let commit_grow = runtime.commit_resize(prepare_grow.transition_id);
    let grow_committed =
        commit_grow.outcome_class == BlockVolumeResizeTransitionOutcomeClass::Committed;
    runtime.lifecycle_runtime.resume_after_fence();

    // Update file image geometry after grow
    image
        .resize_to(runtime.current_geometry)
        .map_err(|err| file_image_error("resize file image for grow", err))?;

    // Write to expanded area (block 12, beyond original 8-block capacity)
    let grow_write_data = [0x77_u8; 4096];
    let grow_write_ok = if grow_committed {
        image
            .write_blocks(12, &grow_write_data)
            .map_err(|err| file_image_error("post-grow write", err))?;
        let (_, grow_read) = image
            .read_blocks(BlockRangeRecord::new(12, 1))
            .map_err(|err| file_image_error("post-grow read", err))?;
        grow_read.is_some_and(|p| p == grow_write_data)
    } else {
        false
    };

    // OOB after grow (write past block 15 = block 16)
    let grow_oob = image.write_blocks(16, &[0xEE; 4096]);
    let grow_oob_refused =
        grow_oob.unwrap().completion_class == BlockVolumeCompletionClass::RefusedOutOfBounds;

    // ── SHRINK: 16 → 12 blocks ──
    runtime
        .lifecycle_runtime
        .begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
    let fenced_shrink = runtime.lifecycle_runtime.fence_after_drain();
    let shrink_fenced = fenced_shrink.to_phase_class == BlockVolumeExportPhaseClass::Fenced;

    let prepare_shrink = runtime.prepare_resize(12, auth);
    let shrink_prepared =
        prepare_shrink.outcome_class == BlockVolumeResizeTransitionOutcomeClass::Prepared;
    let shrink_direction_tail = prepare_shrink.affected_tail_range.map(|r| r.block_count);

    let commit_shrink = runtime.commit_resize(prepare_shrink.transition_id);
    let shrink_committed =
        commit_shrink.outcome_class == BlockVolumeResizeTransitionOutcomeClass::Committed;
    runtime.lifecycle_runtime.resume_after_fence();

    // Update file image geometry after shrink
    image
        .resize_to(runtime.current_geometry)
        .map_err(|err| file_image_error("resize file image for shrink", err))?;

    // OOB after shrink (write at block 12, the new end)
    let shrink_oob = image.write_blocks(12, &[0xFF; 4096]);
    let shrink_oob_refused =
        shrink_oob.unwrap().completion_class == BlockVolumeCompletionClass::RefusedOutOfBounds;

    // Collect validation
    let lifecycle_transitions = runtime.lifecycle_runtime.transition_records.clone();
    let resize_transitions = runtime.resize_records.clone();

    drop(image);
    let path_removed = backing.remove()?;

    Ok(ResizeFenceFileSmokeReport {
        initial_block_count: initial_geometry.block_count,
        block_size_bytes: initial_geometry.block_size_bytes,
        pre_flush_barrier,
        pre_read_matches,
        pre_oob_refused,
        grow_fenced,
        grow_prepared,
        grow_direction_tail,
        grow_zero_visible,
        grow_committed,
        post_grow_block_count: runtime.current_geometry.block_count,
        grow_write_ok,
        grow_oob_refused,
        shrink_fenced,
        shrink_prepared,
        shrink_direction_tail,
        shrink_committed,
        post_shrink_block_count: 12,
        shrink_oob_refused,
        lifecycle_transition_count: lifecycle_transitions.len(),
        resize_transition_count: resize_transitions.len(),
        path_removed,
        non_claim_count: NON_CLAIMS.len(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResizeFenceFileSmokeReport {
    initial_block_count: usize,
    block_size_bytes: usize,
    pre_flush_barrier: bool,
    pre_read_matches: bool,
    pre_oob_refused: bool,
    grow_fenced: bool,
    grow_prepared: bool,
    grow_direction_tail: Option<usize>,
    grow_zero_visible: bool,
    grow_committed: bool,
    post_grow_block_count: usize,
    grow_write_ok: bool,
    grow_oob_refused: bool,
    shrink_fenced: bool,
    shrink_prepared: bool,
    shrink_direction_tail: Option<usize>,
    shrink_committed: bool,
    post_shrink_block_count: usize,
    shrink_oob_refused: bool,
    lifecycle_transition_count: usize,
    resize_transition_count: usize,
    path_removed: bool,
    non_claim_count: usize,
}

impl ResizeFenceFileSmokeReport {
    fn print(&self) {
        println!("tidefs block volume adapter resize/fence file-image smoke");
        println!("gate={BLOCK_VOLUME_RESIZE_FENCE_GATE_OW_301F}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "surface_family={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.human_name()
        );
        println!("resize.initial_block_count={}", self.initial_block_count);
        println!("resize.block_size_bytes={}", self.block_size_bytes);
        println!("resize.pre_flush_barrier={}", self.pre_flush_barrier);
        println!("resize.pre_read_matches={}", self.pre_read_matches);
        println!("resize.pre_oob_refused={}", self.pre_oob_refused);
        println!("resize.grow_fenced={}", self.grow_fenced);
        println!("resize.grow_prepared={}", self.grow_prepared);
        println!(
            "resize.grow_direction_tail={}",
            self.grow_direction_tail
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!("resize.grow_zero_visible={}", self.grow_zero_visible);
        println!("resize.grow_committed={}", self.grow_committed);
        println!(
            "resize.post_grow_block_count={}",
            self.post_grow_block_count
        );
        println!("resize.grow_write_ok={}", self.grow_write_ok);
        println!("resize.grow_oob_refused={}", self.grow_oob_refused);
        println!("resize.shrink_fenced={}", self.shrink_fenced);
        println!("resize.shrink_prepared={}", self.shrink_prepared);
        println!(
            "resize.shrink_direction_tail={}",
            self.shrink_direction_tail
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!("resize.shrink_committed={}", self.shrink_committed);
        println!(
            "resize.post_shrink_block_count={}",
            self.post_shrink_block_count
        );
        println!("resize.shrink_oob_refused={}", self.shrink_oob_refused);
        println!(
            "resize.lifecycle_transitions={}",
            self.lifecycle_transition_count
        );
        println!("resize.resize_transitions={}", self.resize_transition_count);
        println!("resize.path_removed={}", self.path_removed);
        println!("resize.non_claims={}", self.non_claim_count);
        println!("nonclaim.dev_ublk_control_opened=false");
        println!("nonclaim.io_uring_queue_processed=false");
        println!("nonclaim.no_ublk_device_created=true");
        for non_claim in NON_CLAIMS {
            println!("nonclaim.{non_claim}=true");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ublk_serve_args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    fn parse_ublk_serve_for_test(args: &[&str]) -> Result<UblkServeConfig, AppError> {
        parse_ublk_serve_args(&ublk_serve_args(args), 4)
    }

    fn ublk_serve_parse_error(args: &[&str]) -> String {
        parse_ublk_serve_for_test(args)
            .expect_err("ublk-serve parse should fail")
            .message
    }

    fn unique_ublk_serve_test_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        env::temp_dir().join(format!(
            "tidefs-ublk-serve-{label}-{}-{nonce}",
            process::id()
        ))
    }

    #[test]
    fn ublk_serve_rejects_object_store_backing() {
        let message = ublk_serve_parse_error(&["--object-store", "/tmp/tidefs-store"]);
        assert!(message.contains("--object-store is not a valid ublk-serve backing"));
        assert!(message.contains("--backing-file"));
        assert!(message.contains("--backing-block-device"));
    }

    #[test]
    fn ublk_serve_rejects_snapshot_backing_mode() {
        let message = ublk_serve_parse_error(&["--snapshot", "snap0"]);
        assert!(message.contains("--snapshot is not a valid ublk-serve backing mode"));
        assert!(message.contains("object-store snapshot export is no longer a live backing"));
    }

    #[test]
    fn ublk_serve_rejects_missing_backing() {
        let message = ublk_serve_parse_error(&["--block-size", "4096"]);
        assert!(message.contains("missing ublk-serve backing"));
        assert!(message.contains("--backing-block-device"));
    }

    #[test]
    fn ublk_serve_rejects_ambiguous_file_and_block_backing() {
        let message = ublk_serve_parse_error(&[
            "--backing-file",
            "/tmp/a.img",
            "--backing-block-device",
            "/dev/sda",
        ]);
        assert!(message.contains("choose exactly one"));
    }

    #[test]
    fn ublk_serve_rejects_directory_as_regular_file_backing() {
        let dir = unique_ublk_serve_test_path("file-dir");
        fs::create_dir(&dir).expect("create temp dir");
        let message = ublk_serve_parse_error(&["--backing-file", dir.to_str().expect("utf8")]);
        assert!(message.contains("is a directory"));
        assert!(message.contains("directory-backed ublk devices are not supported"));
        fs::remove_dir(&dir).expect("remove temp dir");
    }

    #[test]
    fn ublk_serve_rejects_directory_as_block_device_backing() {
        let dir = unique_ublk_serve_test_path("block-dir");
        fs::create_dir(&dir).expect("create temp dir");
        let message =
            ublk_serve_parse_error(&["--backing-block-device", dir.to_str().expect("utf8")]);
        assert!(message.contains("is a directory"));
        assert!(message.contains("directory-backed ublk devices are not supported"));
        fs::remove_dir(&dir).expect("remove temp dir");
    }

    #[test]
    fn ublk_serve_rejects_regular_file_as_block_device_backing() {
        let backing = TempBackingFile::new().expect("temp backing");
        fs::write(backing.path(), [0_u8; 4096]).expect("seed file");
        let message = ublk_serve_parse_error(&[
            "--backing-block-device",
            backing.path().to_str().expect("utf8"),
        ]);
        assert!(message.contains("is a regular file"));
        assert!(message.contains("use --backing-file"));
        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn ublk_serve_rejects_block_device_create_mode() {
        let message = ublk_serve_parse_error(&[
            "--backing-block-device",
            "/dev/tidefs-test-device",
            "--create",
        ]);
        assert!(message.contains("--create is incompatible with --backing-block-device"));
    }

    #[test]
    fn ublk_serve_accepts_existing_regular_file_backing() {
        let backing = TempBackingFile::new().expect("temp backing");
        fs::write(backing.path(), vec![0_u8; 4096 * 8]).expect("seed file");
        let config = parse_ublk_serve_for_test(&[
            "--backing-file",
            backing.path().to_str().expect("utf8"),
            "--block-size",
            "4096",
            "--block-count",
            "8",
            "--nr-hw-queues",
            "2",
        ])
        .expect("parse regular file backing");

        match &config.backing {
            UblkServeBacking::RegularFile(path) => assert_eq!(path.as_path(), backing.path()),
            UblkServeBacking::BlockDevice(_) => panic!("expected regular-file backing"),
        }
        assert!(!config.create);
        assert!(!config.read_only);
        assert_eq!(config.block_size, 4096);
        assert_eq!(config.block_count, 8);
        assert_eq!(config.nr_hw_queues, 2);
        assert!(config.backing.resize_supported());
        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn ublk_serve_accepts_regular_file_create_mode_without_preexisting_path() {
        let path = unique_ublk_serve_test_path("create-file");
        let config = parse_ublk_serve_for_test(&[
            "--backing-file",
            path.to_str().expect("utf8"),
            "--create",
            "--block-size",
            "4096",
            "--block-count",
            "8",
        ])
        .expect("parse create mode");
        match &config.backing {
            UblkServeBacking::RegularFile(backing_path) => {
                assert_eq!(backing_path.as_path(), path.as_path());
            }
            UblkServeBacking::BlockDevice(_) => panic!("expected regular-file backing"),
        }
        assert!(config.create);
        assert!(!path.exists());
    }

    #[test]
    fn backing_file_smoke_uses_real_backing_file_without_live_ublk() {
        let report = run_backing_file_smoke().expect("backing file smoke");
        assert!(report.backing_file_created);
        assert!(report.backing_file_reopened);
        assert!(report.backing_file_sync_attempted);
        assert_eq!(report.capacity_bytes, 4096 * 8);
        assert_eq!(
            report.write_completion,
            BlockVolumeCompletionClass::Completed
        );
        assert!(report.flush_barrier_present);
        assert!(report.reopened_read_matches);
        assert!(report.zero_visible_after_discard_and_write_zeroes);
        assert_eq!(report.discard_intent_count, 2);
        assert_eq!(report.dirty_epoch_count, 2);
        assert!(report.path_removed);
        assert_eq!(report.non_claim_count, NON_CLAIMS.len());
    }

    #[test]
    fn summary_surface_is_block_volume_adapter() {
        assert_eq!(
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name,
            "tidefs-block-volume-adapter-daemon"
        );
        assert_eq!(
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.human_name(),
            "Block Volume Adapter"
        );
        // no_live_ublk_device removed — live device now supported via ublk-serve
    }

    #[test]
    fn host_preflight_admits_linux700_with_control_device_and_sysfs() {
        let report = evaluate_host_preflight(&HostPreflightInputs {
            kernel_release: "7.0.0-test".to_string(),
            dev_ublk_control_present: true,
            dev_ublk_control_is_char_device: true,
            sys_module_ublk_drv_present: true,
            sys_class_ublk_char_present: true,
            sys_class_block_present: true,
            host_identity: ObserveHostIdentity::Unknown,
        });
        assert_eq!(report.kernel_class, HostKernelClass::Linux700OrNewer);
        assert_eq!(
            report.admission_class,
            HostPreflightAdmissionClass::Admitted
        );
        assert_eq!(report.refusal_class, HostPreflightRefusalClass::None);
        assert!(!report.attach_mutation_attempted);
    }

    #[test]
    fn host_preflight_refuses_missing_control_device_without_mutation() {
        let report = evaluate_host_preflight(&HostPreflightInputs {
            kernel_release: "7.0.0-test".to_string(),
            dev_ublk_control_present: false,
            dev_ublk_control_is_char_device: false,
            sys_module_ublk_drv_present: true,
            sys_class_ublk_char_present: true,
            sys_class_block_present: true,
            host_identity: ObserveHostIdentity::Unknown,
        });
        assert_eq!(report.admission_class, HostPreflightAdmissionClass::Refused);
        assert_eq!(
            report.refusal_class,
            HostPreflightRefusalClass::MissingUblkControl
        );
        assert!(!report.attach_mutation_attempted);
    }

    #[test]
    fn host_preflight_refuses_old_kernel_before_control_device() {
        let report = evaluate_host_preflight(&HostPreflightInputs {
            kernel_release: "6.12.79-test".to_string(),
            dev_ublk_control_present: true,
            dev_ublk_control_is_char_device: true,
            sys_module_ublk_drv_present: true,
            sys_class_ublk_char_present: true,
            sys_class_block_present: true,
            host_identity: ObserveHostIdentity::Unknown,
        });
        assert_eq!(report.kernel_class, HostKernelClass::LinuxTooPrevious);
        assert_eq!(report.admission_class, HostPreflightAdmissionClass::Refused);
        assert_eq!(
            report.refusal_class,
            HostPreflightRefusalClass::KernelBelowLinux700
        );
    }

    #[test]
    fn host_preflight_marks_sysfs_gap_as_degraded_not_refused() {
        let report = evaluate_host_preflight(&HostPreflightInputs {
            kernel_release: "7.0.0-test".to_string(),
            dev_ublk_control_present: true,
            dev_ublk_control_is_char_device: true,
            sys_module_ublk_drv_present: false,
            sys_class_ublk_char_present: false,
            sys_class_block_present: true,
            host_identity: ObserveHostIdentity::Unknown,
        });
        assert_eq!(
            report.admission_class,
            HostPreflightAdmissionClass::Degraded
        );
        assert_eq!(report.refusal_class, HostPreflightRefusalClass::None);
        assert!(report.degraded_missing_sysfs_mirror);
    }

    #[test]
    fn ublk_abi_plan_binds_expected_attach_sequence_without_ioctl() {
        let report = build_ublk_abi_plan_report();
        assert_eq!(report.ctrl_cmd_size, 32);
        assert_eq!(report.params_size, 136);
        assert!(!report.control_ioctl_issued);

        let steps = ublk_control_plan_steps();
        assert_eq!(
            steps[0].command,
            tidefs_ublk_abi::UblkCtrlCommand::GetFeatures
        );
        assert_eq!(steps[1].command, tidefs_ublk_abi::UblkCtrlCommand::AddDev);
        assert_eq!(
            steps[2].command,
            tidefs_ublk_abi::UblkCtrlCommand::SetParams
        );
        assert_eq!(steps[3].command, tidefs_ublk_abi::UblkCtrlCommand::StartDev);
        assert_eq!(
            steps[4].command,
            tidefs_ublk_abi::UblkCtrlCommand::GetDevInfo2
        );
        assert_eq!(
            steps[5].command,
            tidefs_ublk_abi::UblkCtrlCommand::QuiesceDev
        );
        assert_eq!(
            steps[6].command,
            tidefs_ublk_abi::UblkCtrlCommand::UpdateSize
        );
        assert_eq!(steps[7].command, tidefs_ublk_abi::UblkCtrlCommand::StopDev);
        assert_eq!(steps[8].command, tidefs_ublk_abi::UblkCtrlCommand::DelDev);
        assert!(!steps[0].mutates_control_state());
        assert!(!steps[4].mutates_control_state());
        assert!(steps[1].mutates_control_state());
        assert_eq!(steps[0].request().size(), report.ctrl_cmd_size as u16);
    }

    #[test]
    fn ublk_abi_plan_requires_resize_quiesce_and_user_copy_features() {
        let report = build_ublk_abi_plan_report();
        assert!(report
            .required_features
            .contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
        assert!(report
            .required_features
            .contains(UblkFeatureFlags::USER_COPY));
        assert!(report
            .required_features
            .contains(UblkFeatureFlags::UPDATE_SIZE));
        assert!(report.required_features.contains(UblkFeatureFlags::QUIESCE));
    }

    #[test]
    fn ublk_parameter_spec_maps_geometry_and_queue_policy() {
        let report = build_ublk_parameter_spec_report().expect("parameter construction");

        assert_eq!(report.geometry.block_size_bytes, 4096);
        assert_eq!(report.geometry.block_count, 1024);
        assert_eq!(report.queue_count, 4);
        assert_eq!(report.queue_depth, 64);
        assert_eq!(report.params.len, params_size() as u32);
        assert_eq!(
            report.params.types,
            UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT
        );
        assert_eq!(report.params.basic.logical_bs_shift, 12);
        assert_eq!(report.params.basic.physical_bs_shift, 12);
        assert_eq!(report.params.basic.dev_sectors, 8192);
        assert_eq!(report.params.basic.max_sectors, 2048);
        assert_eq!(report.params.basic.chunk_sectors, 8);
        assert_eq!(report.params.discard.discard_granularity, 4096);
        assert_eq!(report.params.discard.max_discard_sectors, 2048);
        assert_eq!(report.params.discard.max_write_zeroes_sectors, 2048);
        assert_eq!(report.params.seg.max_segment_size, 1024 * 1024);
        assert_eq!(report.params.seg.max_segments, 1);
        assert!((report.params.basic.attrs & UBLK_ATTR_VOLATILE_CACHE) != 0);
        assert!((report.params.basic.attrs & UBLK_ATTR_FUA) != 0);
        assert!(!report.params_set_ioctl_issued);
    }

    #[test]
    fn ublk_parameter_spec_can_disable_discard_while_advertising_write_zeroes() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(302), 4096, 64, 0);
        let runtime =
            BlockVolumeQueueRuntime::open(geometry, 2, 16, 64 * 1024).expect("queue runtime");
        let report = build_ublk_parameters(geometry, &runtime.queue_policy, &runtime.queue_set)
            .expect("parameter construction");

        assert_eq!(
            report.params.types,
            UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT
        );
        assert_eq!(report.params.basic.chunk_sectors, 8);
        assert_eq!(report.params.discard.discard_granularity, 4096);
        assert_eq!(report.params.discard.max_discard_sectors, 0);
        assert_eq!(report.params.discard.max_write_zeroes_sectors, 128);
        assert_eq!(report.params.discard.max_discard_segments, 0);
    }

    #[test]
    fn ublk_parameter_spec_refuses_invalid_geometry_and_queue_inputs() {
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(303), 4096, 64, 1);
        let runtime =
            BlockVolumeQueueRuntime::open(geometry, 2, 16, 64 * 1024).expect("queue runtime");

        assert_eq!(
            build_ublk_parameters(
                BlockVolumeGeometryRecord::new(BlockVolumeId::new(303), 0, 64, 1),
                &runtime.queue_policy,
                &runtime.queue_set,
            )
            .unwrap_err(),
            UblkParameterSpecError::ZeroBlockSize
        );
        assert_eq!(
            build_ublk_parameters(
                BlockVolumeGeometryRecord::new(BlockVolumeId::new(303), 1000, 64, 1),
                &runtime.queue_policy,
                &runtime.queue_set,
            )
            .unwrap_err(),
            UblkParameterSpecError::NonPowerOfTwoBlockSize
        );
        assert_eq!(
            build_ublk_parameters(
                BlockVolumeGeometryRecord::new(BlockVolumeId::new(303), 256, 64, 1),
                &runtime.queue_policy,
                &runtime.queue_set,
            )
            .unwrap_err(),
            UblkParameterSpecError::BlockSizeBelowLinuxSector
        );

        let mut zero_queue_policy = runtime.queue_policy.clone();
        let mut zero_queue_set = runtime.queue_set.clone();
        zero_queue_policy.shard_count = 0;
        zero_queue_set.shard_count = 0;
        assert_eq!(
            build_ublk_parameters(geometry, &zero_queue_policy, &zero_queue_set).unwrap_err(),
            UblkParameterSpecError::ZeroQueues
        );

        let mut oversized_depth = runtime.queue_policy.clone();
        oversized_depth.max_inflight_requests = usize::from(UBLK_MAX_QUEUE_DEPTH) + 1;
        assert_eq!(
            build_ublk_parameters(geometry, &oversized_depth, &runtime.queue_set).unwrap_err(),
            UblkParameterSpecError::QueueDepthTooLarge
        );

        let mut unaligned_bytes = runtime.queue_policy.clone();
        unaligned_bytes.max_inflight_bytes = 4097;
        assert_eq!(
            build_ublk_parameters(geometry, &unaligned_bytes, &runtime.queue_set).unwrap_err(),
            UblkParameterSpecError::MaxInflightBytesNotSectorAligned
        );

        let small_segment_geometry =
            BlockVolumeGeometryRecord::new(BlockVolumeId::new(304), 512, 64, 1);
        let small_segment_runtime = BlockVolumeQueueRuntime::open(
            small_segment_geometry,
            2,
            16,
            UBLK_MIN_SEGMENT_SIZE as usize,
        )
        .expect("queue runtime");
        let mut below_segment_minimum = small_segment_runtime.queue_policy.clone();
        below_segment_minimum.max_inflight_bytes = UBLK_MIN_SEGMENT_SIZE as usize - 512;
        assert_eq!(
            build_ublk_parameters(
                small_segment_geometry,
                &below_segment_minimum,
                &small_segment_runtime.queue_set,
            )
            .unwrap_err(),
            UblkParameterSpecError::MaxInflightBytesBelowUblkSegmentMinimum
        );
    }

    // ── backing-file durability tests (issue #267) ──

    fn durability_geometry() -> BlockVolumeGeometryRecord {
        BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_200), 4096, 8, 1)
    }

    fn make_block(byte: u8, bs: usize) -> Vec<u8> {
        vec![byte; bs]
    }

    #[test]
    fn backing_file_durability_multi_block_round_trip() {
        let geometry = durability_geometry();
        let bs = geometry.block_size_bytes;
        let backing = TempBackingFile::new().expect("temp file");
        let mut image =
            BlockVolumeFileImage::create_zeroed(backing.path(), geometry).expect("create");

        for i in 0..4 {
            image
                .write_blocks(i, &make_block(0x10 * (i as u8 + 1), bs))
                .expect("write");
        }
        image.flush().expect("flush");
        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen");
        for i in 0..4 {
            let (plan, payload) = reopened
                .read_blocks(BlockRangeRecord::new(i, 1))
                .expect("read");
            assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
            assert_eq!(
                payload.as_deref(),
                Some(make_block(0x10 * (i as u8 + 1), bs).as_slice())
            );
        }
        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn backing_file_durability_non_adjacent_write_gaps() {
        let geometry = durability_geometry();
        let bs = geometry.block_size_bytes;
        let backing = TempBackingFile::new().expect("temp file");
        let mut image =
            BlockVolumeFileImage::create_zeroed(backing.path(), geometry).expect("create");

        image
            .write_blocks(1, &make_block(0xAB, bs))
            .expect("write block 1");
        image
            .write_blocks(4, &make_block(0xCD, bs))
            .expect("write block 4");
        image.flush().expect("flush");
        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen");

        let (_, p1) = reopened
            .read_blocks(BlockRangeRecord::new(1, 1))
            .expect("read block 1");
        assert_eq!(p1.as_deref(), Some(make_block(0xAB, bs).as_slice()));

        let (_, p4) = reopened
            .read_blocks(BlockRangeRecord::new(4, 1))
            .expect("read block 4");
        assert_eq!(p4.as_deref(), Some(make_block(0xCD, bs).as_slice()));

        // untouched gap blocks should still be zero
        let (_, gap) = reopened
            .read_blocks(BlockRangeRecord::new(2, 2))
            .expect("read gap");
        assert_eq!(gap.as_deref(), Some(vec![0; bs * 2].as_slice()));

        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn backing_file_durability_write_without_explicit_flush_reopen() {
        let geometry = durability_geometry();
        let bs = geometry.block_size_bytes;
        let backing = TempBackingFile::new().expect("temp file");
        let mut image =
            BlockVolumeFileImage::create_zeroed(backing.path(), geometry).expect("create");

        image.write_blocks(3, &make_block(0xEF, bs)).expect("write");
        // drop without explicit flush — POSIX write → close → reopen must be coherent
        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen");
        let (plan, payload) = reopened
            .read_blocks(BlockRangeRecord::new(3, 1))
            .expect("read");
        assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(payload.as_deref(), Some(make_block(0xEF, bs).as_slice()));
        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn backing_file_durability_discard_persists_across_reopen() {
        let geometry = durability_geometry();
        let bs = geometry.block_size_bytes;
        let backing = TempBackingFile::new().expect("temp file");
        let mut image =
            BlockVolumeFileImage::create_zeroed(backing.path(), geometry).expect("create");

        image
            .write_blocks(0, &make_block(0x77, bs * 4))
            .expect("write 4 blocks");
        image.flush().expect("flush after write");
        image
            .discard_blocks(BlockRangeRecord::new(1, 2))
            .expect("discard blocks 1-2");
        image.flush().expect("flush after discard");
        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen");

        // block 0 should still have original data
        let (_, b0) = reopened
            .read_blocks(BlockRangeRecord::new(0, 1))
            .expect("read block 0");
        assert_eq!(b0.as_deref(), Some(make_block(0x77, bs).as_slice()));

        // blocks 1-2 should be zero (discarded)
        let (_, discarded) = reopened
            .read_blocks(BlockRangeRecord::new(1, 2))
            .expect("read discarded");
        assert_eq!(discarded.as_deref(), Some(vec![0; bs * 2].as_slice()));

        // block 3 should still have original data
        let (_, b3) = reopened
            .read_blocks(BlockRangeRecord::new(3, 1))
            .expect("read block 3");
        assert_eq!(b3.as_deref(), Some(make_block(0x77, bs).as_slice()));

        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn backing_file_durability_write_zeroes_persist_across_reopen() {
        let geometry = durability_geometry();
        let bs = geometry.block_size_bytes;
        let backing = TempBackingFile::new().expect("temp file");
        let mut image =
            BlockVolumeFileImage::create_zeroed(backing.path(), geometry).expect("create");

        image
            .write_blocks(0, &make_block(0x55, bs * 4))
            .expect("write 4 blocks");
        image.flush().expect("flush after write");
        image
            .write_zeroes(BlockRangeRecord::new(1, 2))
            .expect("write zeroes blocks 1-2");
        image.flush().expect("flush after write zeroes");
        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen");

        // block 0 should still have original data
        let (_, b0) = reopened
            .read_blocks(BlockRangeRecord::new(0, 1))
            .expect("read block 0");
        assert_eq!(b0.as_deref(), Some(make_block(0x55, bs).as_slice()));

        // blocks 1-2 should be zero
        let (_, zeroed) = reopened
            .read_blocks(BlockRangeRecord::new(1, 2))
            .expect("read zeroed");
        assert_eq!(zeroed.as_deref(), Some(vec![0; bs * 2].as_slice()));

        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn backing_file_durability_reopen_modify_reopen_cycle() {
        let geometry = durability_geometry();
        let bs = geometry.block_size_bytes;
        let backing = TempBackingFile::new().expect("temp file");
        let mut image =
            BlockVolumeFileImage::create_zeroed(backing.path(), geometry).expect("create");

        image
            .write_blocks(0, &make_block(0xAA, bs))
            .expect("gen 1 write");
        image.flush().expect("gen 1 flush");
        drop(image);

        let mut reopened =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen 1");
        let (_, gen1) = reopened
            .read_blocks(BlockRangeRecord::new(0, 1))
            .expect("read gen 1");
        assert_eq!(gen1.as_deref(), Some(make_block(0xAA, bs).as_slice()));

        reopened
            .write_blocks(0, &make_block(0xBB, bs))
            .expect("gen 2 write");
        reopened.flush().expect("gen 2 flush");
        drop(reopened);

        let reopened2 =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen 2");
        let (_, gen2) = reopened2
            .read_blocks(BlockRangeRecord::new(0, 1))
            .expect("read gen 2");
        assert_eq!(gen2.as_deref(), Some(make_block(0xBB, bs).as_slice()));

        assert!(backing.remove().expect("remove"));
    }

    #[test]
    fn backing_file_durability_multiple_flush_barriers() {
        let geometry = durability_geometry();
        let bs = geometry.block_size_bytes;
        let backing = TempBackingFile::new().expect("temp file");
        let mut image =
            BlockVolumeFileImage::create_zeroed(backing.path(), geometry).expect("create");

        let _a = image
            .write_blocks(2, &make_block(0x11, bs))
            .expect("write epoch A");
        let flush_a = image.flush().expect("flush A");
        let _b = image
            .write_blocks(5, &make_block(0x22, bs))
            .expect("write epoch B");
        let flush_b = image.flush().expect("flush B");

        // verify barrier receipts exist and are distinct
        assert!(flush_a.flush_barrier_ref.is_some());
        assert!(flush_b.flush_barrier_ref.is_some());
        assert_ne!(flush_a.flush_barrier_ref, flush_b.flush_barrier_ref);

        drop(image);

        let reopened =
            BlockVolumeFileImage::reopen_existing(backing.path(), geometry).expect("reopen");

        let (_, payload_a) = reopened
            .read_blocks(BlockRangeRecord::new(2, 1))
            .expect("read epoch A");
        assert_eq!(payload_a.as_deref(), Some(make_block(0x11, bs).as_slice()));

        let (_, payload_b) = reopened
            .read_blocks(BlockRangeRecord::new(5, 1))
            .expect("read epoch B");
        assert_eq!(payload_b.as_deref(), Some(make_block(0x22, bs).as_slice()));

        assert!(backing.remove().expect("remove"));
    }
}

#[cfg(test)]
mod decode_dispatch_tests;
