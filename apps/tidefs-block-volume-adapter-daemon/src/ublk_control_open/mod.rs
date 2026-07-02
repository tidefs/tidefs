// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(unused_imports)]
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use crate::kernel_check::HostKernelClass;
use crate::kernel_check::{
    classify_host_identity, classify_kernel_release_str, ObserveHostIdentity,
};
use tidefs_block_volume_adapter_ublk_control_runtime::{
    build_commit_and_fetch_spec, build_fetch_req_spec, build_fetch_req_submission_spec,
    commit_and_fetch_user_data, decode_commit_and_fetch_user_data, decode_fetch_req_user_data,
    fetch_req_user_data, is_commit_and_fetch_user_data, is_fetch_req_user_data, issue_add_dev,
    issue_del_dev, issue_end_user_recovery, issue_get_features, issue_set_params, issue_start_dev,
    issue_start_user_recovery, issue_stop_dev, issue_update_size, open_data_queue_runtime,
    resolve_resize_policy, submit_runtime_all_queues_fetch_reqs_without_wait,
    submit_runtime_commit_and_fetch_without_wait, submit_runtime_fetch_reqs_without_wait,
    ublk_data_queue_device_path, UblkControlAddDevCommand, UblkControlAddDevError,
    UblkControlAddDevInput, UblkControlAddDevOutcome, UblkControlAddDevSpec,
    UblkControlDelDevError, UblkControlDelDevInput, UblkControlDelDevOutcome,
    UblkControlDelDevSpec, UblkControlEndUserRecoveryCommand, UblkControlEndUserRecoveryError,
    UblkControlEndUserRecoveryInput, UblkControlEndUserRecoveryOutcome,
    UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError, UblkControlReadonlyProbeSpec,
    UblkControlSetParamsError, UblkControlSetParamsInput, UblkControlSetParamsOutcome,
    UblkControlSetParamsSpec, UblkControlStartDevError, UblkControlStartDevInput,
    UblkControlStartDevOutcome, UblkControlStartDevReadiness, UblkControlStartDevSpec,
    UblkControlStartUserRecoveryCommand, UblkControlStartUserRecoveryError,
    UblkControlStartUserRecoveryInput, UblkControlStartUserRecoveryOutcome,
    UblkControlStopDevError, UblkControlStopDevInput, UblkControlStopDevOutcome,
    UblkControlStopDevSpec, UblkControlUpdateSizeError, UblkControlUpdateSizeInput,
    UblkControlUpdateSizeOutcome, UblkDataQueueCommitAndFetchError,
    UblkDataQueueCommitAndFetchInput, UblkDataQueueCommitAndFetchOutcome,
    UblkDataQueueCommitAndFetchReadiness, UblkDataQueueCommitAndFetchSpec,
    UblkDataQueueFetchReqError, UblkDataQueueFetchReqInput, UblkDataQueueFetchReqReadiness,
    UblkDataQueueFetchReqSpec, UblkDataQueueFetchReqSubmissionError,
    UblkDataQueueFetchReqSubmissionOutcome, UblkDataQueueFetchReqSubmissionSpec,
    UblkDataQueueRuntimeOpenError, UblkDataQueueRuntimeOpenInput, UblkDataQueueRuntimeOpenOutcome,
    UblkDataQueueRuntimeOpenSpec, BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q,
    BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R,
    BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P,
    BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S,
    BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T,
    BLOCK_VOLUME_UBLK_CONTROL_STOP_DEV_GATE_OW_301ZC,
    BLOCK_VOLUME_UBLK_CONTROL_UPDATE_SIZE_GATE_OW_301Y,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_COMMIT_FETCH_GATE_OW_301X,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V, TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
};
use tidefs_types_package_profile_catalog::BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE;
use tidefs_ublk_abi::{
    ublk_control_plan_steps, UblkFeatureFlags, UblkParams,
    TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES,
};

use crate::{
    build_ublk_parameter_spec_report, build_ublk_parameter_spec_report_with_geometry,
    print_plan_step, AppError,
};

mod acceptance_harness;
mod add_del_dev;
mod add_dev;
mod commit_and_fetch;
mod data_queue_io_loop;
mod data_queue_open;
pub mod data_queue_worker;
mod fetch_req;
mod fetch_req_submission;
mod preflight;
mod readonly_probe;
mod resize_smoke;
mod set_params;
mod start_dev;
mod started_export_admission;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum UblkDataQueueIoLoopFailureClass {
    None,
    HostNotAdmitted,
    ControlOpenFailed,
    FeatureProbeFailed,
    RequiredFeaturesMissing,
    AddDevFailed,
    AddDevDidNotReturnDeviceId,
    ParameterBuildFailed,
    SetParamsFailed,
    DataQueueOpenFailed,
    FetchReqSubmissionFailed,
    StartDevFailed,
    IoLoopErrno,
    IoLoopPrematureExit,
}

impl UblkDataQueueIoLoopFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::FeatureProbeFailed => "feature_probe_failed",
            Self::RequiredFeaturesMissing => "required_features_missing",
            Self::AddDevFailed => "add_dev_failed",
            Self::AddDevDidNotReturnDeviceId => "add_dev_did_not_return_device_id",
            Self::ParameterBuildFailed => "parameter_build_failed",
            Self::SetParamsFailed => "set_params_failed",
            Self::DataQueueOpenFailed => "data_queue_open_failed",
            Self::FetchReqSubmissionFailed => "fetch_req_submission_failed",
            Self::StartDevFailed => "start_dev_failed",
            Self::IoLoopErrno => "io_loop_errno",
            Self::IoLoopPrematureExit => "io_loop_premature_exit",
        }
    }
}

#[derive(Clone, Debug)]
pub struct UblkDataQueueIoLoopReport {
    pub(crate) start_dev_uring_cmd_completed: bool,
    ublk_device_pair_created: bool,
    pub(crate) ublk_device_pair_deleted: bool,
    io_loop_attempted: bool,
    pub(crate) io_loop_completed_iterations: u64,
    pub(crate) io_loop_cqes_processed: u64,
    pub(crate) io_loop_commit_and_fetch_submitted: u64,
    io_loop_failure_class: UblkDataQueueIoLoopFailureClass,
    io_loop_errno: Option<i32>,
    pub(crate) image_bytes_read: u64,
    pub(crate) image_bytes_written: u64,
    pub(crate) image_read_ops_completed: u64,
    pub(crate) image_write_ops_completed: u64,
    pub(crate) image_flush_ops: u64,
    pub(crate) image_discard_ops: u64,
    pub(crate) image_write_zeroes_ops: u64,
    pub(crate) io_uring_queue_processed: bool,
    pub(crate) shutdown_graceful: bool,
    pub(crate) drain_cqes_processed: u64,
    pub(crate) drain_iterations: u64,
    pub(crate) drain_timed_out: bool,
    pub(crate) drain_hung_io_count: u64,
    pub(crate) data_queue_open_errno: Option<i32>,
    pub(crate) data_queue_open_error_str: Option<String>,
    pub(crate) final_flush_completed: bool,
    pub(crate) stop_dev_uring_cmd_completed: bool,
    pub(crate) set_params_errno: Option<i32>,
    /// Aggregate flush-barrier audit entries from all workers.
    pub(crate) barrier_audit_flush_count: u64,
    /// Aggregate FUA-write-barrier audit entries from all workers.
    pub(crate) barrier_audit_fua_write_count: u64,
    /// Aggregate failed barrier entries from all workers.
    pub(crate) barrier_audit_failed_count: u64,
    /// Total barrier audit entries across all workers.
    pub(crate) barrier_audit_total_entries: u64,
    pub(crate) started_export_admission_artifact_path: Option<PathBuf>,
    pub(crate) started_export_admission_artifact_written: bool,
}

impl UblkDataQueueIoLoopReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk data-queue I/O loop boundary");
        println!("gate={}", tidefs_block_volume_adapter_ublk_control_runtime::BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U);
        println!("io_loop.attempted={}", self.io_loop_attempted);
        println!(
            "io_loop.completed_iterations={}",
            self.io_loop_completed_iterations
        );
        println!("io_loop.cqes_processed={}", self.io_loop_cqes_processed);
        println!(
            "io_loop.commit_and_fetch_submitted={}",
            self.io_loop_commit_and_fetch_submitted
        );
        println!(
            "io_loop.failure_class={}",
            self.io_loop_failure_class.as_str()
        );
        if let Some(errno) = self.io_loop_errno {
            println!("io_loop.errno={errno}");
        }
        println!(
            "start_dev.uring_cmd_completed={}",
            self.start_dev_uring_cmd_completed
        );
        println!("ublk_device_pair_created={}", self.ublk_device_pair_created);
        println!("ublk_device_pair_deleted={}", self.ublk_device_pair_deleted);
        println!(
            "ublk_block_device_started={}",
            self.start_dev_uring_cmd_completed
        );
        println!("image_bytes_read={}", self.image_bytes_read);
        println!("image_bytes_written={}", self.image_bytes_written);
        println!("image_read_ops_completed={}", self.image_read_ops_completed);
        println!(
            "image_write_ops_completed={}",
            self.image_write_ops_completed
        );
        println!("image_flush_ops={}", self.image_flush_ops);
        println!("image_discard_ops={}", self.image_discard_ops);
        println!("image_write_zeroes_ops={}", self.image_write_zeroes_ops);
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.io_uring_queue_processed
        );
        println!(
            "stop_dev.uring_cmd_completed={}",
            self.stop_dev_uring_cmd_completed
        );
        println!("shutdown.graceful={}", self.shutdown_graceful);
        println!(
            "shutdown.drain_cqes_processed={}",
            self.drain_cqes_processed
        );
        println!("shutdown.drain_iterations={}", self.drain_iterations);
        println!("shutdown.drain_timed_out={}", self.drain_timed_out);
        println!("shutdown.drain_hung_io_count={}", self.drain_hung_io_count);
        println!(
            "shutdown.final_flush_completed={}",
            self.final_flush_completed
        );
        println!("set_params.errno={:?}", self.set_params_errno);
        println!("data_queue_open.errno={:?}", self.data_queue_open_errno);
        if let Some(ref s) = self.data_queue_open_error_str {
            println!("data_queue_open.error={s}");
        }
        println!(
            "started_export_admission_artifact.written={}",
            self.started_export_admission_artifact_written
        );
        if let Some(path) = &self.started_export_admission_artifact_path {
            println!("started_export_admission_artifact.path={}", path.display());
        }
    }
}

mod tests;

#[allow(unused_imports)]
pub(crate) use preflight::evaluate_ublk_control_open_preflight;

pub(crate) use readonly_probe::evaluate_ublk_control_readonly_probe;

pub(crate) use add_dev::evaluate_ublk_control_add_dev_boundary;

pub(crate) use add_del_dev::evaluate_ublk_control_add_del_dev_boundary;

pub(crate) use set_params::evaluate_ublk_control_set_params_boundary;

pub(crate) use start_dev::evaluate_ublk_control_start_dev_boundary;

pub(crate) use fetch_req::evaluate_ublk_data_queue_fetch_req_readiness_boundary;

pub(crate) use data_queue_open::evaluate_ublk_data_queue_open_boundary;

pub(crate) use fetch_req_submission::evaluate_ublk_data_queue_fetch_req_submission_boundary;

pub(crate) use commit_and_fetch::evaluate_ublk_data_queue_commit_and_fetch_boundary;

pub(crate) use started_export_admission::UblkStartedExportAdmissionArtifact;

pub use acceptance_harness::run_ublk_acceptance_harness;
pub use add_del_dev::run_ublk_control_add_del_dev_boundary;
pub use add_dev::run_ublk_control_add_dev_boundary;
pub use commit_and_fetch::run_ublk_data_queue_commit_and_fetch_boundary;
pub use data_queue_io_loop::{run_ublk_data_queue_io_loop_boundary, run_ublk_live_device};
pub use data_queue_open::run_ublk_data_queue_open_boundary;
pub use data_queue_worker::{
    DataQueueWorker, DataQueueWorkerError, DataQueueWorkerReport, DataQueueWorkerResultEntry,
    BLOCK_VOLUME_UBLK_DATA_QUEUE_WORKER_GATE_OW_301Z,
};
pub use fetch_req::run_ublk_data_queue_fetch_req_readiness_boundary;
pub use fetch_req_submission::run_ublk_data_queue_fetch_req_submission_boundary;
pub use preflight::run_ublk_control_open_preflight;
pub use readonly_probe::run_ublk_control_readonly_probe;
pub use resize_smoke::run_ublk_control_resize_smoke_boundary;
pub use set_params::run_ublk_control_set_params_boundary;
pub use start_dev::run_ublk_control_start_dev_boundary;

pub const BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O: &str =
    "OW-301O block-volume adapter ublk control open boundary admits only real host control devices";

pub(crate) const UBLK_CONTROL_PATH: &str = "/dev/ublk-control";

pub(crate) fn open_control_device(path: &Path) -> Result<(), UblkControlOpenErrorClass> {
    open_control_device_file(path).map(|_| ())
}

pub(crate) fn open_control_device_file(path: &Path) -> Result<fs::File, UblkControlOpenErrorClass> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(UblkControlOpenErrorClass::from_io_error)
}

#[allow(clippy::collection_is_never_read)]
#[allow(clippy::collection_is_never_read)]
#[allow(clippy::collection_is_never_read)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UblkControlOpenInputs {
    kernel_release: String,
    control_path: PathBuf,
    control_path_present: bool,
    control_path_is_char_device: bool,
    sys_module_ublk_drv_present: bool,
    sys_class_ublk_char_present: bool,
    sys_class_block_present: bool,
    control_open_result: Option<Result<(), UblkControlOpenErrorClass>>,
    host_identity: ObserveHostIdentity,
}

impl UblkControlOpenInputs {
    fn read_host() -> Result<Self, AppError> {
        let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|err| AppError::new(format!("read kernel release: {err}")))?
            .trim()
            .to_string();
        let control_path = PathBuf::from(UBLK_CONTROL_PATH);
        let control_metadata = fs::metadata(&control_path).ok();
        Ok(Self {
            kernel_release,
            control_path,
            control_path_present: control_metadata.is_some(),
            control_path_is_char_device: control_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.file_type().is_char_device()),
            sys_module_ublk_drv_present: Path::new("/sys/module/ublk_drv").exists(),
            sys_class_ublk_char_present: Path::new("/sys/class/ublk-char").exists(),
            sys_class_block_present: Path::new("/sys/class/block").exists(),
            host_identity: classify_host_identity(),
            control_open_result: None,
        })
    }

    fn kernel_below_baseline_allowed() -> bool {
        matches!(
            std::env::var("TIDEFS_ALLOW_KERNEL_BELOW_BASELINE"),
            Ok(ref v) if !v.is_empty()
        )
    }

    fn should_attempt_control_open(&self) -> bool {
        let kernel_class = classify_kernel_release_str(&self.kernel_release);
        let kernel_ok = kernel_class == HostKernelClass::Linux700OrNewer;
        if !kernel_ok && !Self::kernel_below_baseline_allowed() {
            return false;
        }
        if !kernel_ok {
            eprintln!(
                "tidefs: TIDEFS_ALLOW_KERNEL_BELOW_BASELINE override active \
                 -- kernel baseline check bypassed"
            );
        }
        self.control_path_present && self.control_path_is_char_device
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UblkControlOpenAdmissionClass {
    Admitted,
    Degraded,
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UblkControlOpenRefusalClass {
    None,
    KernelBelowLinux700,
    MissingUblkControl,
    UblkControlNotCharacterDevice,
    ControlOpenNotAttempted,
    ControlOpenFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UblkControlOpenErrorClass {
    NotFound,
    PermissionDenied,
    Interrupted,
    WouldBlock,
    OtherIo,
}

impl UblkControlOpenErrorClass {
    fn from_io_error(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            _ => Self::OtherIo,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::Interrupted => "interrupted",
            Self::WouldBlock => "would_block",
            Self::OtherIo => "other_io",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkControlOpenReport {
    pub(crate) kernel_release: String,
    pub(crate) kernel_class: HostKernelClass,
    observe_baseline_satisfied: bool,
    control_path: PathBuf,
    control_path_present: bool,
    control_path_is_char_device: bool,
    sys_module_ublk_drv_present: bool,
    sys_class_ublk_char_present: bool,
    sys_class_block_present: bool,
    degraded_missing_sysfs_mirror: bool,
    admission_class: UblkControlOpenAdmissionClass,
    refusal_class: UblkControlOpenRefusalClass,
    control_open_attempted: bool,
    control_opened: bool,
    control_open_error_class: Option<UblkControlOpenErrorClass>,
    read_only_probe_ioctl_issued: bool,
    mutating_ioctl_issued: bool,
    ublk_device_created: bool,
    pub(crate) host_identity: ObserveHostIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkControlReadonlyProbeFailureClass {
    None,
    HostNotAdmitted,
    ControlOpenFailed,
    ProbeNotAttemptedAfterOpen,
    IoUringSetupErrno,
    IoUringSetupMissingErrno,
    SubmissionQueueFull,
    IoUringSubmitErrno,
    IoUringSubmitMissingErrno,
    CompletionMissing,
    UnexpectedCompletionUserData,
    UblkCommandErrno,
    UnsupportedReadOnlyCommand,
    UnsupportedMutatingCommand,
}

impl UblkControlReadonlyProbeFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::ProbeNotAttemptedAfterOpen => "probe_not_attempted_after_open",
            Self::IoUringSetupErrno => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData => "unexpected_completion_user_data",
            Self::UblkCommandErrno => "ublk_command_errno",
            Self::UnsupportedReadOnlyCommand => "unsupported_read_only_command",
            Self::UnsupportedMutatingCommand => "unsupported_mutating_command",
        }
    }

    const fn from_runtime_error(error: UblkControlReadonlyProbeError) -> Self {
        match error {
            UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(_) => {
                Self::UnsupportedReadOnlyCommand
            }
            UblkControlReadonlyProbeError::UnsupportedMutatingCommand(_) => {
                Self::UnsupportedMutatingCommand
            }
            UblkControlReadonlyProbeError::IoUringSetupErrno(_) => Self::IoUringSetupErrno,
            UblkControlReadonlyProbeError::IoUringSetupMissingErrno => {
                Self::IoUringSetupMissingErrno
            }
            UblkControlReadonlyProbeError::SubmissionQueueFull => Self::SubmissionQueueFull,
            UblkControlReadonlyProbeError::IoUringSubmitErrno(_) => Self::IoUringSubmitErrno,
            UblkControlReadonlyProbeError::IoUringSubmitMissingErrno => {
                Self::IoUringSubmitMissingErrno
            }
            UblkControlReadonlyProbeError::CompletionMissing => Self::CompletionMissing,
            UblkControlReadonlyProbeError::UnexpectedCompletionUserData(_) => {
                Self::UnexpectedCompletionUserData
            }
            UblkControlReadonlyProbeError::UblkCommandErrno(_) => Self::UblkCommandErrno,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkControlReadonlyProbeReport {
    pub(crate) open_report: UblkControlOpenReport,
    probe_spec: UblkControlReadonlyProbeSpec,
    probe_uring_cmd_attempted: bool,
    probe_uring_cmd_completed: bool,
    probe_failure_class: UblkControlReadonlyProbeFailureClass,
    probe_errno: Option<i32>,
    probe_features: Option<UblkFeatureFlags>,
    probe_error: Option<UblkControlReadonlyProbeError>,
    mutating_ioctl_issued: bool,
    io_uring_queue_processed: bool,
    ublk_device_created: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkControlAddDevFailureClass {
    None,
    HostNotAdmitted,
    ControlOpenFailed,
    FeatureProbeFailed,
    RequiredFeaturesMissing,
    AddDevNotAttemptedAfterFeatureProbe,
    InvalidAddDevInput,
    IoUringSetupErrno,
    IoUringSetupMissingErrno,
    SubmissionQueueFull,
    IoUringSubmitErrno,
    IoUringSubmitMissingErrno,
    CompletionMissing,
    UnexpectedCompletionUserData,
    UblkCommandErrno,
}

impl UblkControlAddDevFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::FeatureProbeFailed => "feature_probe_failed",
            Self::RequiredFeaturesMissing => "required_features_missing",
            Self::AddDevNotAttemptedAfterFeatureProbe => {
                "add_dev_not_attempted_after_feature_probe"
            }
            Self::InvalidAddDevInput => "invalid_add_dev_input",
            Self::IoUringSetupErrno => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData => "unexpected_completion_user_data",
            Self::UblkCommandErrno => "ublk_command_errno",
        }
    }

    const fn from_runtime_error(error: UblkControlAddDevError) -> Self {
        match error {
            UblkControlAddDevError::UnsupportedCommand(_)
            | UblkControlAddDevError::ZeroHardwareQueues
            | UblkControlAddDevError::TooManyHardwareQueues
            | UblkControlAddDevError::ZeroQueueDepth
            | UblkControlAddDevError::QueueDepthTooLarge
            | UblkControlAddDevError::ZeroMaxIoBufferBytes
            | UblkControlAddDevError::MissingRequiredFeatureFlag(_) => Self::InvalidAddDevInput,
            UblkControlAddDevError::IoUringSetupErrno(_) => Self::IoUringSetupErrno,
            UblkControlAddDevError::IoUringSetupMissingErrno => Self::IoUringSetupMissingErrno,
            UblkControlAddDevError::SubmissionQueueFull => Self::SubmissionQueueFull,
            UblkControlAddDevError::IoUringSubmitErrno(_) => Self::IoUringSubmitErrno,
            UblkControlAddDevError::IoUringSubmitMissingErrno => Self::IoUringSubmitMissingErrno,
            UblkControlAddDevError::CompletionMissing => Self::CompletionMissing,
            UblkControlAddDevError::UnexpectedCompletionUserData(_) => {
                Self::UnexpectedCompletionUserData
            }
            UblkControlAddDevError::UblkCommandErrno(_) => Self::UblkCommandErrno,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkControlDelDevFailureClass {
    None,
    HostNotAdmitted,
    ControlOpenFailed,
    FeatureProbeFailed,
    RequiredFeaturesMissing,
    AddDevFailed,
    AddDevDidNotReturnDeviceId,
    DelDevNotAttemptedAfterAddDev,
    InvalidDelDevInput,
    IoUringSetupErrno,
    IoUringSetupMissingErrno,
    SubmissionQueueFull,
    IoUringSubmitErrno,
    IoUringSubmitMissingErrno,
    CompletionMissing,
    UnexpectedCompletionUserData,
    UblkCommandErrno,
}

impl UblkControlDelDevFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::FeatureProbeFailed => "feature_probe_failed",
            Self::RequiredFeaturesMissing => "required_features_missing",
            Self::AddDevFailed => "add_dev_failed",
            Self::AddDevDidNotReturnDeviceId => "add_dev_did_not_return_device_id",
            Self::DelDevNotAttemptedAfterAddDev => "del_dev_not_attempted_after_add_dev",
            Self::InvalidDelDevInput => "invalid_del_dev_input",
            Self::IoUringSetupErrno => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData => "unexpected_completion_user_data",
            Self::UblkCommandErrno => "ublk_command_errno",
        }
    }

    const fn from_runtime_error(error: UblkControlDelDevError) -> Self {
        match error {
            UblkControlDelDevError::AutoDeviceId => Self::InvalidDelDevInput,
            UblkControlDelDevError::IoUringSetupErrno(_) => Self::IoUringSetupErrno,
            UblkControlDelDevError::IoUringSetupMissingErrno => Self::IoUringSetupMissingErrno,
            UblkControlDelDevError::SubmissionQueueFull => Self::SubmissionQueueFull,
            UblkControlDelDevError::IoUringSubmitErrno(_) => Self::IoUringSubmitErrno,
            UblkControlDelDevError::IoUringSubmitMissingErrno => Self::IoUringSubmitMissingErrno,
            UblkControlDelDevError::CompletionMissing => Self::CompletionMissing,
            UblkControlDelDevError::UnexpectedCompletionUserData(_) => {
                Self::UnexpectedCompletionUserData
            }
            UblkControlDelDevError::UblkCommandErrno(_) => Self::UblkCommandErrno,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkControlSetParamsFailureClass {
    None,
    HostNotAdmitted,
    ControlOpenFailed,
    FeatureProbeFailed,
    RequiredFeaturesMissing,
    AddDevFailed,
    AddDevDidNotReturnDeviceId,
    ParameterBuildFailed,
    SetParamsNotAttemptedAfterAddDev,
    InvalidSetParamsInput,
    IoUringSetupErrno,
    IoUringSetupMissingErrno,
    SubmissionQueueFull,
    IoUringSubmitErrno,
    IoUringSubmitMissingErrno,
    CompletionMissing,
    UnexpectedCompletionUserData,
    UblkCommandErrno,
}

impl UblkControlSetParamsFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::FeatureProbeFailed => "feature_probe_failed",
            Self::RequiredFeaturesMissing => "required_features_missing",
            Self::AddDevFailed => "add_dev_failed",
            Self::AddDevDidNotReturnDeviceId => "add_dev_did_not_return_device_id",
            Self::ParameterBuildFailed => "parameter_build_failed",
            Self::SetParamsNotAttemptedAfterAddDev => "set_params_not_attempted_after_add_dev",
            Self::InvalidSetParamsInput => "invalid_set_params_input",
            Self::IoUringSetupErrno => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData => "unexpected_completion_user_data",
            Self::UblkCommandErrno => "ublk_command_errno",
        }
    }

    const fn from_runtime_error(error: UblkControlSetParamsError) -> Self {
        match error {
            UblkControlSetParamsError::AutoDeviceId
            | UblkControlSetParamsError::ZeroParamsLen
            | UblkControlSetParamsError::ParamsLenMismatch
            | UblkControlSetParamsError::ZeroParamTypes
            | UblkControlSetParamsError::MissingBasicParams
            | UblkControlSetParamsError::MissingDiscardParams
            | UblkControlSetParamsError::MissingSegmentParams
            | UblkControlSetParamsError::ZeroDevSectors
            | UblkControlSetParamsError::ZeroMaxSectors
            | UblkControlSetParamsError::ZeroMaxSegmentSize
            | UblkControlSetParamsError::ZeroMaxSegments => Self::InvalidSetParamsInput,
            UblkControlSetParamsError::IoUringSetupErrno(_) => Self::IoUringSetupErrno,
            UblkControlSetParamsError::IoUringSetupMissingErrno => Self::IoUringSetupMissingErrno,
            UblkControlSetParamsError::SubmissionQueueFull => Self::SubmissionQueueFull,
            UblkControlSetParamsError::IoUringSubmitErrno(_) => Self::IoUringSubmitErrno,
            UblkControlSetParamsError::IoUringSubmitMissingErrno => Self::IoUringSubmitMissingErrno,
            UblkControlSetParamsError::CompletionMissing => Self::CompletionMissing,
            UblkControlSetParamsError::UnexpectedCompletionUserData(_) => {
                Self::UnexpectedCompletionUserData
            }
            UblkControlSetParamsError::UblkCommandErrno(_) => Self::UblkCommandErrno,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkControlStartDevFailureClass {
    None,
    HostNotAdmitted,
    ControlOpenFailed,
    FeatureProbeFailed,
    RequiredFeaturesMissing,
    AddDevFailed,
    AddDevDidNotReturnDeviceId,
    ParameterBuildFailed,
    SetParamsFailed,
    DataQueueFetchesNotReady,
    StartDevNotAttemptedAfterSetParams,
    InvalidStartDevInput,
    IoUringSetupErrno,
    IoUringSetupMissingErrno,
    SubmissionQueueFull,
    IoUringSubmitErrno,
    IoUringSubmitMissingErrno,
    CompletionMissing,
    UnexpectedCompletionUserData,
    UblkCommandErrno,
}

impl UblkControlStartDevFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::FeatureProbeFailed => "feature_probe_failed",
            Self::RequiredFeaturesMissing => "required_features_missing",
            Self::AddDevFailed => "add_dev_failed",
            Self::AddDevDidNotReturnDeviceId => "add_dev_did_not_return_device_id",
            Self::ParameterBuildFailed => "parameter_build_failed",
            Self::SetParamsFailed => "set_params_failed",
            Self::DataQueueFetchesNotReady => "data_queue_fetches_not_ready",
            Self::StartDevNotAttemptedAfterSetParams => "start_dev_not_attempted_after_set_params",
            Self::InvalidStartDevInput => "invalid_start_dev_input",
            Self::IoUringSetupErrno => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::CompletionMissing => "completion_missing",
            Self::UnexpectedCompletionUserData => "unexpected_completion_user_data",
            Self::UblkCommandErrno => "ublk_command_errno",
        }
    }

    const fn from_runtime_error(error: UblkControlStartDevError) -> Self {
        match error {
            UblkControlStartDevError::AutoDeviceId | UblkControlStartDevError::InvalidDaemonPid => {
                Self::InvalidStartDevInput
            }
            UblkControlStartDevError::DataQueueFetchesNotReady => Self::DataQueueFetchesNotReady,
            UblkControlStartDevError::IoUringSetupErrno(_) => Self::IoUringSetupErrno,
            UblkControlStartDevError::IoUringSetupMissingErrno => Self::IoUringSetupMissingErrno,
            UblkControlStartDevError::SubmissionQueueFull => Self::SubmissionQueueFull,
            UblkControlStartDevError::IoUringSubmitErrno(_) => Self::IoUringSubmitErrno,
            UblkControlStartDevError::IoUringSubmitMissingErrno => Self::IoUringSubmitMissingErrno,
            UblkControlStartDevError::CompletionMissing => Self::CompletionMissing,
            UblkControlStartDevError::UnexpectedCompletionUserData(_) => {
                Self::UnexpectedCompletionUserData
            }
            UblkControlStartDevError::UblkCommandErrno(_) => Self::UblkCommandErrno,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkDataQueueOpenFailureClass {
    None,
    HostNotAdmitted,
    ControlOpenFailed,
    FeatureProbeFailed,
    RequiredFeaturesMissing,
    AddDevFailed,
    AddDevDidNotReturnDeviceId,
    DataQueueOpenNotAttemptedAfterAddDev,
    InvalidDataQueueRuntimeInput,
    DataQueuePathMismatch,
    DataQueuePathMissing,
    DataQueuePathNotCharacterDevice,
    DataQueueMetadataErrno,
    DataQueueMetadataMissingErrno,
    DataQueueOpenErrno,
    DataQueueOpenMissingErrno,
    IoUringSetupErrno,
    IoUringSetupMissingErrno,
}

impl UblkDataQueueOpenFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::FeatureProbeFailed => "feature_probe_failed",
            Self::RequiredFeaturesMissing => "required_features_missing",
            Self::AddDevFailed => "add_dev_failed",
            Self::AddDevDidNotReturnDeviceId => "add_dev_did_not_return_device_id",
            Self::DataQueueOpenNotAttemptedAfterAddDev => {
                "data_queue_open_not_attempted_after_add_dev"
            }
            Self::InvalidDataQueueRuntimeInput => "invalid_data_queue_runtime_input",
            Self::DataQueuePathMismatch => "data_queue_path_mismatch",
            Self::DataQueuePathMissing => "data_queue_path_missing",
            Self::DataQueuePathNotCharacterDevice => "data_queue_path_not_character_device",
            Self::DataQueueMetadataErrno => "data_queue_metadata_errno",
            Self::DataQueueMetadataMissingErrno => "data_queue_metadata_missing_errno",
            Self::DataQueueOpenErrno => "data_queue_open_errno",
            Self::DataQueueOpenMissingErrno => "data_queue_open_missing_errno",
            Self::IoUringSetupErrno => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
        }
    }

    const fn from_runtime_error(error: UblkDataQueueRuntimeOpenError) -> Self {
        match error {
            UblkDataQueueRuntimeOpenError::AutoDeviceId
            | UblkDataQueueRuntimeOpenError::ZeroHardwareQueues
            | UblkDataQueueRuntimeOpenError::TooManyHardwareQueues
            | UblkDataQueueRuntimeOpenError::ZeroQueueDepth
            | UblkDataQueueRuntimeOpenError::QueueDepthTooLarge
            | UblkDataQueueRuntimeOpenError::QueueIdOutOfRange => {
                Self::InvalidDataQueueRuntimeInput
            }
            UblkDataQueueRuntimeOpenError::DataQueuePathMismatch => Self::DataQueuePathMismatch,
            UblkDataQueueRuntimeOpenError::DataQueuePathMissing => Self::DataQueuePathMissing,
            UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice => {
                Self::DataQueuePathNotCharacterDevice
            }
            UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(_) => {
                Self::DataQueueMetadataErrno
            }
            UblkDataQueueRuntimeOpenError::DataQueueMetadataMissingErrno => {
                Self::DataQueueMetadataMissingErrno
            }
            UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(_) => Self::DataQueueOpenErrno,
            UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno => {
                Self::DataQueueOpenMissingErrno
            }
            UblkDataQueueRuntimeOpenError::IoUringSetupErrno(_) => Self::IoUringSetupErrno,
            UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno => {
                Self::IoUringSetupMissingErrno
            }
            UblkDataQueueRuntimeOpenError::MmapFailed(_) => Self::DataQueueOpenErrno,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkDataQueueFetchReqSubmissionFailureClass {
    None,
    DataQueueNotOpen,
    FetchReqSubmissionNotAttemptedAfterOpen,
    DataQueueRuntimeNotLive,
    InvalidFetchReqInput,
    SubmissionQueueFull,
    IoUringSubmitErrno,
    IoUringSubmitMissingErrno,
    IoUringSubmitZero,
}

impl UblkDataQueueFetchReqSubmissionFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DataQueueNotOpen => "data_queue_not_open",
            Self::FetchReqSubmissionNotAttemptedAfterOpen => {
                "fetch_req_submission_not_attempted_after_open"
            }
            Self::DataQueueRuntimeNotLive => "data_queue_runtime_not_live",
            Self::InvalidFetchReqInput => "invalid_fetch_req_input",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::IoUringSubmitZero => "io_uring_submit_zero",
        }
    }

    const fn from_fetch_req_error(error: UblkDataQueueFetchReqError) -> Self {
        match error {
            UblkDataQueueFetchReqError::ZeroHardwareQueues
            | UblkDataQueueFetchReqError::TooManyHardwareQueues
            | UblkDataQueueFetchReqError::ZeroQueueDepth
            | UblkDataQueueFetchReqError::QueueDepthTooLarge
            | UblkDataQueueFetchReqError::QueueIdOutOfRange
            | UblkDataQueueFetchReqError::TagOutOfRange
            | UblkDataQueueFetchReqError::UserCopyFetchAddrMustBeZero => Self::InvalidFetchReqInput,
            UblkDataQueueFetchReqError::SubmissionQueueFull => Self::SubmissionQueueFull,
            UblkDataQueueFetchReqError::IoUringSubmitErrno(_) => Self::IoUringSubmitErrno,
            UblkDataQueueFetchReqError::IoUringSubmitMissingErrno => {
                Self::IoUringSubmitMissingErrno
            }
            UblkDataQueueFetchReqError::IoUringSubmitZero => Self::IoUringSubmitZero,
        }
    }

    const fn from_runtime_error(error: UblkDataQueueFetchReqSubmissionError) -> Self {
        match error {
            UblkDataQueueFetchReqSubmissionError::RuntimeNotLive => Self::DataQueueRuntimeNotLive,
            UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(fetch_error)
            | UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
                error: fetch_error, ..
            } => Self::from_fetch_req_error(fetch_error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UblkDataQueueCommitAndFetchFailureClass {
    None,
    FetchReqNotReady,
    CommitAndFetchNotAttemptedAfterFetch,
    DataQueueRuntimeNotLive,
    FetchedRequestMissing,
    CompletionResultNotReady,
    InvalidCommitAndFetchInput,
    SubmissionQueueFull,
    IoUringSubmitErrno,
    IoUringSubmitMissingErrno,
    IoUringSubmitZero,
}

impl UblkDataQueueCommitAndFetchFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FetchReqNotReady => "fetch_req_not_ready",
            Self::CommitAndFetchNotAttemptedAfterFetch => {
                "commit_and_fetch_not_attempted_after_fetch"
            }
            Self::DataQueueRuntimeNotLive => "data_queue_runtime_not_live",
            Self::FetchedRequestMissing => "fetched_request_missing",
            Self::CompletionResultNotReady => "completion_result_not_ready",
            Self::InvalidCommitAndFetchInput => "invalid_commit_and_fetch_input",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::IoUringSubmitErrno => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::IoUringSubmitZero => "io_uring_submit_zero",
        }
    }

    const fn from_runtime_error(error: UblkDataQueueCommitAndFetchError) -> Self {
        match error {
            UblkDataQueueCommitAndFetchError::RuntimeNotLive => Self::DataQueueRuntimeNotLive,
            UblkDataQueueCommitAndFetchError::FetchedRequestMissing => Self::FetchedRequestMissing,
            UblkDataQueueCommitAndFetchError::CompletionResultNotReady => {
                Self::CompletionResultNotReady
            }
            UblkDataQueueCommitAndFetchError::ZeroHardwareQueues
            | UblkDataQueueCommitAndFetchError::TooManyHardwareQueues
            | UblkDataQueueCommitAndFetchError::ZeroQueueDepth
            | UblkDataQueueCommitAndFetchError::QueueDepthTooLarge
            | UblkDataQueueCommitAndFetchError::QueueIdOutOfRange
            | UblkDataQueueCommitAndFetchError::TagOutOfRange
            | UblkDataQueueCommitAndFetchError::NeedGetDataResultUnsupported
            | UblkDataQueueCommitAndFetchError::PositiveResultUnsupported
            | UblkDataQueueCommitAndFetchError::ZoneAppendLbaMustBeZero => {
                Self::InvalidCommitAndFetchInput
            }
            UblkDataQueueCommitAndFetchError::SubmissionQueueFull => Self::SubmissionQueueFull,
            UblkDataQueueCommitAndFetchError::IoUringSubmitErrno(_) => Self::IoUringSubmitErrno,
            UblkDataQueueCommitAndFetchError::IoUringSubmitMissingErrno => {
                Self::IoUringSubmitMissingErrno
            }
            UblkDataQueueCommitAndFetchError::IoUringSubmitZero => Self::IoUringSubmitZero,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkControlAddDevReport {
    pub(crate) readonly_report: UblkControlReadonlyProbeReport,
    add_dev_spec: UblkControlAddDevSpec,
    add_dev_input: UblkControlAddDevInput,
    add_dev_uring_cmd_attempted: bool,
    add_dev_uring_cmd_completed: bool,
    add_dev_failure_class: UblkControlAddDevFailureClass,
    add_dev_errno: Option<i32>,
    add_dev_outcome: Option<UblkControlAddDevOutcome>,
    add_dev_error: Option<UblkControlAddDevError>,
    add_dev_required_features: UblkFeatureFlags,
    add_dev_required_features_available: bool,
    ublk_device_pair_created: bool,
    io_uring_queue_processed: bool,
    ublk_block_device_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkControlAddDelDevReport {
    add_dev_report: UblkControlAddDevReport,
    del_dev_spec: UblkControlDelDevSpec,
    del_dev_target_dev_id: Option<u32>,
    del_dev_uring_cmd_attempted: bool,
    del_dev_uring_cmd_completed: bool,
    del_dev_failure_class: UblkControlDelDevFailureClass,
    del_dev_errno: Option<i32>,
    del_dev_outcome: Option<UblkControlDelDevOutcome>,
    del_dev_error: Option<UblkControlDelDevError>,
    cleanup_attempted_after_add_dev: bool,
    cleanup_failed_after_add_dev: bool,
    ublk_device_pair_created: bool,
    ublk_device_pair_deleted: bool,
    io_uring_queue_processed: bool,
    ublk_block_device_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkControlSetParamsReport {
    add_dev_report: UblkControlAddDevReport,
    set_params_spec: UblkControlSetParamsSpec,
    set_params_target_dev_id: Option<u32>,
    set_params_projected: bool,
    set_params_uring_cmd_attempted: bool,
    set_params_uring_cmd_completed: bool,
    set_params_failure_class: UblkControlSetParamsFailureClass,
    set_params_errno: Option<i32>,
    set_params_outcome: Option<UblkControlSetParamsOutcome>,
    set_params_error: Option<UblkControlSetParamsError>,
    del_dev_spec: UblkControlDelDevSpec,
    del_dev_target_dev_id: Option<u32>,
    del_dev_uring_cmd_attempted: bool,
    del_dev_uring_cmd_completed: bool,
    del_dev_failure_class: UblkControlDelDevFailureClass,
    del_dev_errno: Option<i32>,
    del_dev_outcome: Option<UblkControlDelDevOutcome>,
    del_dev_error: Option<UblkControlDelDevError>,
    cleanup_attempted_after_add_dev: bool,
    cleanup_failed_after_add_dev: bool,
    ublk_device_pair_created: bool,
    ublk_device_pair_deleted: bool,
    io_uring_queue_processed: bool,
    ublk_block_device_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkControlStartDevReport {
    set_params_report: UblkControlSetParamsReport,
    start_dev_spec: UblkControlStartDevSpec,
    pub(crate) start_dev_target_dev_id: Option<u32>,
    start_dev_daemon_pid: Option<i32>,
    start_dev_readiness: UblkControlStartDevReadiness,
    start_dev_uring_cmd_attempted: bool,
    pub(crate) start_dev_uring_cmd_completed: bool,
    start_dev_failure_class: UblkControlStartDevFailureClass,
    start_dev_errno: Option<i32>,
    start_dev_outcome: Option<UblkControlStartDevOutcome>,
    start_dev_error: Option<UblkControlStartDevError>,
    ublk_device_pair_created: bool,
    ublk_device_pair_deleted: bool,
    io_uring_queue_processed: bool,
    ublk_block_device_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqReport {
    pub(crate) open_report: UblkControlOpenReport,
    add_dev_input: UblkControlAddDevInput,
    fetch_req_spec: UblkDataQueueFetchReqSpec,
    fetch_req_readiness: UblkDataQueueFetchReqReadiness,
    start_dev_readiness: UblkControlStartDevReadiness,
    data_queue_path: PathBuf,
    data_queue_open_attempted: bool,
    data_queue_opened: bool,
    fetch_req_submission_attempted: bool,
    fetch_req_submitted: bool,
    data_queue_runtime_live: bool,
    ublk_block_device_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkDataQueueOpenReport {
    add_dev_report: UblkControlAddDevReport,
    data_queue_spec: UblkDataQueueRuntimeOpenSpec,
    data_queue_target_dev_id: Option<u32>,
    data_queue_open_attempted: bool,
    data_queue_opened: bool,
    data_queue_failure_class: UblkDataQueueOpenFailureClass,
    data_queue_errno: Option<i32>,
    data_queue_outcome: Option<UblkDataQueueRuntimeOpenOutcome>,
    data_queue_error: Option<UblkDataQueueRuntimeOpenError>,
    fetch_req_readiness: UblkDataQueueFetchReqReadiness,
    start_dev_readiness: UblkControlStartDevReadiness,
    del_dev_spec: UblkControlDelDevSpec,
    del_dev_target_dev_id: Option<u32>,
    del_dev_uring_cmd_attempted: bool,
    del_dev_uring_cmd_completed: bool,
    del_dev_failure_class: UblkControlDelDevFailureClass,
    del_dev_errno: Option<i32>,
    del_dev_outcome: Option<UblkControlDelDevOutcome>,
    del_dev_error: Option<UblkControlDelDevError>,
    cleanup_attempted_after_add_dev: bool,
    cleanup_failed_after_add_dev: bool,
    ublk_device_pair_created: bool,
    ublk_device_pair_deleted: bool,
    fetch_req_submitted: bool,
    start_dev_uring_cmd_attempted: bool,
    io_uring_queue_processed: bool,
    ublk_block_device_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkDataQueueFetchReqSubmissionReport {
    data_queue_open_report: UblkDataQueueOpenReport,
    fetch_req_submission_spec: UblkDataQueueFetchReqSubmissionSpec,
    fetch_req_submission_attempted: bool,
    fetch_req_submission_completed: bool,
    fetch_req_submitted: bool,
    fetch_req_failure_class: UblkDataQueueFetchReqSubmissionFailureClass,
    fetch_req_errno: Option<i32>,
    fetch_req_outcome: Option<UblkDataQueueFetchReqSubmissionOutcome>,
    fetch_req_error: Option<UblkDataQueueFetchReqSubmissionError>,
    fetch_req_readiness: UblkDataQueueFetchReqReadiness,
    start_dev_readiness: UblkControlStartDevReadiness,
    start_dev_uring_cmd_attempted: bool,
    io_uring_queue_processed: bool,
    ublk_block_device_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkDataQueueCommitAndFetchReport {
    fetch_req_report: UblkDataQueueFetchReqSubmissionReport,
    commit_and_fetch_spec: UblkDataQueueCommitAndFetchSpec,
    commit_and_fetch_readiness: UblkDataQueueCommitAndFetchReadiness,
    commit_and_fetch_attempted: bool,
    commit_and_fetch_completed: bool,
    commit_and_fetch_submitted: bool,
    commit_and_fetch_failure_class: UblkDataQueueCommitAndFetchFailureClass,
    commit_and_fetch_errno: Option<i32>,
    commit_and_fetch_outcome: Option<UblkDataQueueCommitAndFetchOutcome>,
    commit_and_fetch_error: Option<UblkDataQueueCommitAndFetchError>,
    start_dev_uring_cmd_attempted: bool,
    io_uring_queue_processed: bool,
    ublk_block_device_started: bool,
}
#[allow(clippy::option_if_let_else)]
/// Named input shape for `evaluate_ublk_control_start_dev_boundary`.
#[derive(Clone, Debug)]
pub(crate) struct UblkControlStartDevBoundaryInput<'a> {
    pub inputs: &'a UblkControlOpenInputs,
    pub probe_result: Option<Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError>>,
    pub add_dev_input: UblkControlAddDevInput,
    pub add_dev_result: Option<Result<UblkControlAddDevOutcome, UblkControlAddDevError>>,
    pub set_params_input: Option<UblkControlSetParamsInput>,
    pub set_params_result: Option<Result<UblkControlSetParamsOutcome, UblkControlSetParamsError>>,
    pub start_dev_input: Option<UblkControlStartDevInput>,
    pub start_dev_result: Option<Result<UblkControlStartDevOutcome, UblkControlStartDevError>>,
    pub start_dev_readiness: UblkControlStartDevReadiness,
    pub del_dev_result: Option<Result<UblkControlDelDevOutcome, UblkControlDelDevError>>,
}

/// Named input shape for `evaluate_ublk_data_queue_open_boundary`.
#[derive(Clone, Debug)]
pub(crate) struct UblkDataQueueOpenBoundaryInput<'a> {
    pub inputs: &'a UblkControlOpenInputs,
    pub probe_result: Option<Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError>>,
    pub add_dev_input: UblkControlAddDevInput,
    pub add_dev_result: Option<Result<UblkControlAddDevOutcome, UblkControlAddDevError>>,
    pub data_queue_input: Option<UblkDataQueueRuntimeOpenInput>,
    pub data_queue_open_result:
        Option<Result<UblkDataQueueRuntimeOpenOutcome, UblkDataQueueRuntimeOpenError>>,
    pub del_dev_result: Option<Result<UblkControlDelDevOutcome, UblkControlDelDevError>>,
}

/// Named input shape for `evaluate_ublk_data_queue_fetch_req_submission_boundary`.
#[derive(Clone, Debug)]
pub(crate) struct UblkDataQueueFetchReqSubmissionBoundaryInput<'a> {
    pub inputs: &'a UblkControlOpenInputs,
    pub probe_result: Option<Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError>>,
    pub add_dev_input: UblkControlAddDevInput,
    pub add_dev_result: Option<Result<UblkControlAddDevOutcome, UblkControlAddDevError>>,
    pub data_queue_input: Option<UblkDataQueueRuntimeOpenInput>,
    pub data_queue_open_result:
        Option<Result<UblkDataQueueRuntimeOpenOutcome, UblkDataQueueRuntimeOpenError>>,
    pub fetch_req_submission_result: Option<
        Result<UblkDataQueueFetchReqSubmissionOutcome, UblkDataQueueFetchReqSubmissionError>,
    >,
    pub del_dev_result: Option<Result<UblkControlDelDevOutcome, UblkControlDelDevError>>,
}

pub(crate) struct UblkDataQueueCommitAndFetchEvaluation<'a> {
    inputs: &'a UblkControlOpenInputs,
    probe_result: Option<Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError>>,
    add_dev_input: UblkControlAddDevInput,
    add_dev_result: Option<Result<UblkControlAddDevOutcome, UblkControlAddDevError>>,
    data_queue_input: Option<UblkDataQueueRuntimeOpenInput>,
    data_queue_open_result:
        Option<Result<UblkDataQueueRuntimeOpenOutcome, UblkDataQueueRuntimeOpenError>>,
    fetch_req_submission_result: Option<
        Result<UblkDataQueueFetchReqSubmissionOutcome, UblkDataQueueFetchReqSubmissionError>,
    >,
    commit_and_fetch_input: Option<UblkDataQueueCommitAndFetchInput>,
    commit_and_fetch_readiness: Option<UblkDataQueueCommitAndFetchReadiness>,
    commit_and_fetch_result:
        Option<Result<UblkDataQueueCommitAndFetchOutcome, UblkDataQueueCommitAndFetchError>>,
    del_dev_result: Option<Result<UblkControlDelDevOutcome, UblkControlDelDevError>>,
}

const fn is_pre_submit_set_params_error(error: UblkControlSetParamsError) -> bool {
    matches!(
        error,
        UblkControlSetParamsError::AutoDeviceId
            | UblkControlSetParamsError::ZeroParamsLen
            | UblkControlSetParamsError::ParamsLenMismatch
            | UblkControlSetParamsError::ZeroParamTypes
            | UblkControlSetParamsError::MissingBasicParams
            | UblkControlSetParamsError::MissingDiscardParams
            | UblkControlSetParamsError::MissingSegmentParams
            | UblkControlSetParamsError::ZeroDevSectors
            | UblkControlSetParamsError::ZeroMaxSectors
            | UblkControlSetParamsError::ZeroMaxSegmentSize
            | UblkControlSetParamsError::ZeroMaxSegments
    )
}

const fn is_pre_submit_start_dev_error(error: UblkControlStartDevError) -> bool {
    matches!(
        error,
        UblkControlStartDevError::AutoDeviceId
            | UblkControlStartDevError::InvalidDaemonPid
            | UblkControlStartDevError::DataQueueFetchesNotReady
    )
}

const fn is_pre_submit_commit_and_fetch_error(error: UblkDataQueueCommitAndFetchError) -> bool {
    matches!(
        error,
        UblkDataQueueCommitAndFetchError::RuntimeNotLive
            | UblkDataQueueCommitAndFetchError::FetchedRequestMissing
            | UblkDataQueueCommitAndFetchError::CompletionResultNotReady
            | UblkDataQueueCommitAndFetchError::ZeroHardwareQueues
            | UblkDataQueueCommitAndFetchError::TooManyHardwareQueues
            | UblkDataQueueCommitAndFetchError::ZeroQueueDepth
            | UblkDataQueueCommitAndFetchError::QueueDepthTooLarge
            | UblkDataQueueCommitAndFetchError::QueueIdOutOfRange
            | UblkDataQueueCommitAndFetchError::TagOutOfRange
            | UblkDataQueueCommitAndFetchError::NeedGetDataResultUnsupported
            | UblkDataQueueCommitAndFetchError::PositiveResultUnsupported
            | UblkDataQueueCommitAndFetchError::ZoneAppendLbaMustBeZero
    )
}

const fn data_queue_open_attempted_for_error(error: UblkDataQueueRuntimeOpenError) -> bool {
    matches!(
        error,
        UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(_)
            | UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno
            | UblkDataQueueRuntimeOpenError::IoUringSetupErrno(_)
            | UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno
    )
}

const fn data_queue_opened_before_error(error: UblkDataQueueRuntimeOpenError) -> bool {
    matches!(
        error,
        UblkDataQueueRuntimeOpenError::IoUringSetupErrno(_)
            | UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno
    )
}

impl UblkControlOpenReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk control open preflight");
        println!("gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
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
        println!(
            "host.degraded_missing_sysfs_mirror={}",
            self.degraded_missing_sysfs_mirror
        );
        println!("host.observe_host_identity={}", self.host_identity.as_str());
        println!("control.path={}", self.control_path.display());
        println!("control.open_mode=read_write");
        println!("control.path_present={}", self.control_path_present);
        println!(
            "control.path_is_char_device={}",
            self.control_path_is_char_device
        );
        println!("control.open_attempted={}", self.control_open_attempted);
        println!("control.opened={}", self.control_opened);
        println!(
            "control.open_error_class={}",
            self.control_open_error_class
                .map(UblkControlOpenErrorClass::as_str)
                .unwrap_or("none")
        );
        println!("control.admission_class={:?}", self.admission_class);
        println!("control.refusal_class={:?}", self.refusal_class);
        println!(
            "control.open_ready={}",
            matches!(
                self.admission_class,
                UblkControlOpenAdmissionClass::Admitted | UblkControlOpenAdmissionClass::Degraded
            ) && self.control_opened
        );
        println!("control.typed_ioctl_requests_bound=true");
        println!(
            "control.read_only_probe_ioctl_issued={}",
            self.read_only_probe_ioctl_issued
        );
        println!(
            "control.mutating_ioctl_issued={}",
            self.mutating_ioctl_issued
        );
        println!("control.ublk_device_created={}", self.ublk_device_created);
        for step in ublk_control_plan_steps() {
            print_plan_step(*step);
        }
        println!(
            "nonclaim.no_read_only_probe_ioctl_issued={}",
            !self.read_only_probe_ioctl_issued
        );
        println!(
            "nonclaim.no_control_mutating_ioctl_issued={}",
            !self.mutating_ioctl_issued
        );
        println!(
            "nonclaim.no_ublk_device_created={}",
            !self.ublk_device_created
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
}

impl UblkControlReadonlyProbeReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk control read-only probe");
        println!("gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!("host.kernel_release={}", self.open_report.kernel_release);
        println!(
            "host.observe_kernel_class={:?}",
            self.open_report.kernel_class
        );
        println!(
            "host.observe_baseline_satisfied={}",
            self.open_report.observe_baseline_satisfied
        );
        println!(
            "host.sys_module_ublk_drv_present={}",
            self.open_report.sys_module_ublk_drv_present
        );
        println!(
            "host.sys_class_ublk_char_present={}",
            self.open_report.sys_class_ublk_char_present
        );
        println!(
            "host.sys_class_block_present={}",
            self.open_report.sys_class_block_present
        );
        println!(
            "host.degraded_missing_sysfs_mirror={}",
            self.open_report.degraded_missing_sysfs_mirror
        );
        println!(
            "host.observe_host_identity={}",
            self.open_report.host_identity.as_str()
        );
        println!("control.path={}", self.open_report.control_path.display());
        println!("control.open_mode=read_write");
        println!(
            "control.path_present={}",
            self.open_report.control_path_present
        );
        println!(
            "control.path_is_char_device={}",
            self.open_report.control_path_is_char_device
        );
        println!(
            "control.open_attempted={}",
            self.open_report.control_open_attempted
        );
        println!("control.opened={}", self.open_report.control_opened);
        println!(
            "control.open_error_class={}",
            self.open_report
                .control_open_error_class
                .map(UblkControlOpenErrorClass::as_str)
                .unwrap_or("none")
        );
        println!(
            "control.admission_class={:?}",
            self.open_report.admission_class
        );
        println!("control.refusal_class={:?}", self.open_report.refusal_class);
        println!("probe.command={}", self.probe_spec.command.as_str());
        println!("probe.command_op_raw=0x{:08x}", self.probe_spec.request_raw);
        println!(
            "probe.command_op_direction={}",
            self.probe_spec.request_direction.as_str()
        );
        println!("probe.command_op_size={}", self.probe_spec.request_size);
        println!(
            "probe.feature_buffer_len={}",
            self.probe_spec.feature_buffer_len
        );
        println!(
            "probe.uring_cmd_sqe_bytes={}",
            self.probe_spec.uring_cmd_sqe_bytes
        );
        println!(
            "probe.mutates_control_state={}",
            self.probe_spec.mutates_control_state
        );
        println!(
            "probe.uring_cmd_attempted={}",
            self.probe_uring_cmd_attempted
        );
        println!(
            "probe.uring_cmd_completed={}",
            self.probe_uring_cmd_completed
        );
        println!("probe.failure_class={}", self.probe_failure_class.as_str());
        println!(
            "probe.errno={}",
            self.probe_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "probe.runtime_error={}",
            self.probe_error
                .map(UblkControlReadonlyProbeError::as_str)
                .unwrap_or("none")
        );
        match self.probe_features {
            Some(features) => println!("features.mask=0x{:016x}", features.bits()),
            None => println!("features.mask=none"),
        }
        println!(
            "features.required_mask=0x{:016x}",
            TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES.bits()
        );
        println!(
            "features.required_available={}",
            self.probe_features.is_some_and(
                |features| features.contains(TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES)
            )
        );
        println!(
            "features.user_copy={}",
            self.probe_features
                .is_some_and(|features| features.contains(UblkFeatureFlags::USER_COPY))
        );
        println!(
            "features.cmd_ioctl_encode={}",
            self.probe_features
                .is_some_and(|features| features.contains(UblkFeatureFlags::CMD_IOCTL_ENCODE))
        );
        println!(
            "features.user_recovery={}",
            self.probe_features
                .is_some_and(|features| features.contains(UblkFeatureFlags::USER_RECOVERY))
        );
        println!(
            "features.update_size={}",
            self.probe_features
                .is_some_and(|features| features.contains(UblkFeatureFlags::UPDATE_SIZE))
        );
        println!(
            "control.read_only_probe_uring_cmd_issued={}",
            self.probe_uring_cmd_attempted
        );
        println!(
            "control.mutating_ioctl_issued={}",
            self.mutating_ioctl_issued
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!("control.ublk_device_created={}", self.ublk_device_created);
        for step in ublk_control_plan_steps() {
            print_plan_step(*step);
        }
        println!(
            "nonclaim.no_control_mutating_ioctl_issued={}",
            !self.mutating_ioctl_issued
        );
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.io_uring_queue_processed
        );
        println!(
            "nonclaim.no_ublk_device_created={}",
            !self.ublk_device_created
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
}

impl UblkControlAddDevReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk ADD_DEV boundary");
        println!("gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "host.kernel_release={}",
            self.readonly_report.open_report.kernel_release
        );
        println!(
            "host.observe_kernel_class={:?}",
            self.readonly_report.open_report.kernel_class
        );
        println!(
            "host.observe_baseline_satisfied={}",
            self.readonly_report.open_report.observe_baseline_satisfied
        );
        println!(
            "control.path={}",
            self.readonly_report.open_report.control_path.display()
        );
        println!("control.open_mode=read_write");
        println!(
            "control.path_present={}",
            self.readonly_report.open_report.control_path_present
        );
        println!(
            "control.path_is_char_device={}",
            self.readonly_report.open_report.control_path_is_char_device
        );
        println!(
            "control.open_attempted={}",
            self.readonly_report.open_report.control_open_attempted
        );
        println!(
            "control.opened={}",
            self.readonly_report.open_report.control_opened
        );
        println!(
            "control.open_error_class={}",
            self.readonly_report
                .open_report
                .control_open_error_class
                .map(UblkControlOpenErrorClass::as_str)
                .unwrap_or("none")
        );
        println!(
            "control.admission_class={:?}",
            self.readonly_report.open_report.admission_class
        );
        println!(
            "control.refusal_class={:?}",
            self.readonly_report.open_report.refusal_class
        );
        println!(
            "probe.command={}",
            self.readonly_report.probe_spec.command.as_str()
        );
        println!(
            "probe.uring_cmd_attempted={}",
            self.readonly_report.probe_uring_cmd_attempted
        );
        println!(
            "probe.uring_cmd_completed={}",
            self.readonly_report.probe_uring_cmd_completed
        );
        println!(
            "probe.failure_class={}",
            self.readonly_report.probe_failure_class.as_str()
        );
        match self.readonly_report.probe_features {
            Some(features) => println!("features.mask=0x{:016x}", features.bits()),
            None => println!("features.mask=none"),
        }
        println!(
            "add_dev.required_features_mask=0x{:016x}",
            self.add_dev_required_features.bits()
        );
        println!(
            "add_dev.required_features_available={}",
            self.add_dev_required_features_available
        );
        println!("add_dev.command={}", self.add_dev_spec.command.as_str());
        println!(
            "add_dev.command_op_raw=0x{:08x}",
            self.add_dev_spec.request_raw
        );
        println!(
            "add_dev.command_op_direction={}",
            self.add_dev_spec.request_direction.as_str()
        );
        println!("add_dev.command_op_size={}", self.add_dev_spec.request_size);
        println!(
            "add_dev.ctrl_dev_info_len={}",
            self.add_dev_spec.ctrl_dev_info_len
        );
        println!("add_dev.queue_id={}", self.add_dev_spec.control_queue_id);
        println!(
            "add_dev.uring_cmd_sqe_bytes={}",
            self.add_dev_spec.uring_cmd_sqe_bytes
        );
        println!(
            "add_dev.mutates_control_state={}",
            self.add_dev_spec.mutates_control_state
        );
        println!("add_dev.nr_hw_queues={}", self.add_dev_input.nr_hw_queues);
        println!("add_dev.queue_depth={}", self.add_dev_input.queue_depth);
        println!(
            "add_dev.max_io_buf_bytes={}",
            self.add_dev_input.max_io_buf_bytes
        );
        println!(
            "add_dev.input_flags=0x{:016x}",
            self.add_dev_input.flags.bits()
        );
        println!(
            "add_dev.uring_cmd_attempted={}",
            self.add_dev_uring_cmd_attempted
        );
        println!(
            "add_dev.uring_cmd_completed={}",
            self.add_dev_uring_cmd_completed
        );
        println!(
            "add_dev.failure_class={}",
            self.add_dev_failure_class.as_str()
        );
        println!(
            "add_dev.errno={}",
            self.add_dev_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "add_dev.runtime_error={}",
            self.add_dev_error
                .map(UblkControlAddDevError::as_str)
                .unwrap_or("none")
        );
        match self.add_dev_outcome {
            Some(outcome) => {
                println!("add_dev.returned_dev_id={}", outcome.dev_info.dev_id);
                println!("add_dev.returned_state={}", outcome.dev_info.state);
                println!(
                    "add_dev.returned_max_io_buf_bytes={}",
                    outcome.dev_info.max_io_buf_bytes
                );
                println!("add_dev.returned_flags=0x{:016x}", outcome.dev_info.flags);
                println!("add_dev.owner_uid={}", outcome.dev_info.owner_uid);
                println!("add_dev.owner_gid={}", outcome.dev_info.owner_gid);
            }
            None => {
                println!("add_dev.returned_dev_id=none");
                println!("add_dev.returned_state=none");
                println!("add_dev.returned_max_io_buf_bytes=none");
                println!("add_dev.returned_flags=none");
                println!("add_dev.owner_uid=none");
                println!("add_dev.owner_gid=none");
            }
        }
        println!(
            "control.read_only_probe_uring_cmd_issued={}",
            self.readonly_report.probe_uring_cmd_attempted
        );
        println!(
            "control.mutating_add_dev_uring_cmd_issued={}",
            self.add_dev_uring_cmd_attempted
        );
        println!(
            "control.ublk_device_pair_created={}",
            self.ublk_device_pair_created
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        for step in ublk_control_plan_steps() {
            print_plan_step(*step);
        }
        println!("nonclaim.no_set_params_uring_cmd_issued=true");
        println!("nonclaim.no_start_dev_uring_cmd_issued=true");
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.io_uring_queue_processed
        );
        println!(
            "nonclaim.no_ublk_block_device_started={}",
            !self.ublk_block_device_started
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// True when the ADD_DEV io_uring command completed successfully.
    pub fn add_dev_uring_cmd_completed(&self) -> bool {
        self.add_dev_uring_cmd_completed
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// True when the ublk device pair was created in the kernel.
    pub fn ublk_device_pair_created(&self) -> bool {
        self.ublk_device_pair_created
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// The errno if ADD_DEV failed, or None.
    pub fn add_dev_errno(&self) -> Option<i32> {
        self.add_dev_errno
    }
}

impl UblkControlAddDelDevReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk ADD_DEV/DEL_DEV cleanup boundary");
        println!("gate={BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!("add_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "host.kernel_release={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .kernel_release
        );
        println!(
            "host.observe_kernel_class={:?}",
            self.add_dev_report.readonly_report.open_report.kernel_class
        );
        println!(
            "host.observe_baseline_satisfied={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .observe_baseline_satisfied
        );
        println!(
            "control.path={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_path
                .display()
        );
        println!("control.open_mode=read_write");
        println!(
            "control.open_attempted={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_open_attempted
        );
        println!(
            "control.opened={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_opened
        );
        println!(
            "control.open_error_class={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_open_error_class
                .map(UblkControlOpenErrorClass::as_str)
                .unwrap_or("none")
        );
        println!(
            "control.admission_class={:?}",
            self.add_dev_report
                .readonly_report
                .open_report
                .admission_class
        );
        println!(
            "control.refusal_class={:?}",
            self.add_dev_report
                .readonly_report
                .open_report
                .refusal_class
        );
        println!(
            "probe.command={}",
            self.add_dev_report
                .readonly_report
                .probe_spec
                .command
                .as_str()
        );
        println!(
            "probe.uring_cmd_attempted={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "probe.uring_cmd_completed={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_completed
        );
        println!(
            "probe.failure_class={}",
            self.add_dev_report
                .readonly_report
                .probe_failure_class
                .as_str()
        );
        match self.add_dev_report.readonly_report.probe_features {
            Some(features) => println!("features.mask=0x{:016x}", features.bits()),
            None => println!("features.mask=none"),
        }
        println!(
            "add_dev.required_features_mask=0x{:016x}",
            self.add_dev_report.add_dev_required_features.bits()
        );
        println!(
            "add_dev.required_features_available={}",
            self.add_dev_report.add_dev_required_features_available
        );
        println!(
            "add_dev.command={}",
            self.add_dev_report.add_dev_spec.command.as_str()
        );
        println!(
            "add_dev.command_op_raw=0x{:08x}",
            self.add_dev_report.add_dev_spec.request_raw
        );
        println!(
            "add_dev.command_op_direction={}",
            self.add_dev_report.add_dev_spec.request_direction.as_str()
        );
        println!(
            "add_dev.command_op_size={}",
            self.add_dev_report.add_dev_spec.request_size
        );
        println!(
            "add_dev.uring_cmd_attempted={}",
            self.add_dev_report.add_dev_uring_cmd_attempted
        );
        println!(
            "add_dev.uring_cmd_completed={}",
            self.add_dev_report.add_dev_uring_cmd_completed
        );
        println!(
            "add_dev.failure_class={}",
            self.add_dev_report.add_dev_failure_class.as_str()
        );
        println!(
            "add_dev.returned_dev_id={}",
            self.add_dev_report
                .add_dev_outcome
                .map(|outcome| outcome.dev_info.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!("del_dev.command={}", self.del_dev_spec.command.as_str());
        println!(
            "del_dev.command_op_raw=0x{:08x}",
            self.del_dev_spec.request_raw
        );
        println!(
            "del_dev.command_op_direction={}",
            self.del_dev_spec.request_direction.as_str()
        );
        println!("del_dev.command_op_size={}", self.del_dev_spec.request_size);
        println!("del_dev.queue_id={}", self.del_dev_spec.control_queue_id);
        println!(
            "del_dev.ctrl_buffer_len={}",
            self.del_dev_spec.ctrl_buffer_len
        );
        println!(
            "del_dev.ctrl_buffer_addr={}",
            self.del_dev_spec.ctrl_buffer_addr
        );
        println!(
            "del_dev.uring_cmd_sqe_bytes={}",
            self.del_dev_spec.uring_cmd_sqe_bytes
        );
        println!(
            "del_dev.mutates_control_state={}",
            self.del_dev_spec.mutates_control_state
        );
        println!(
            "del_dev.target_dev_id={}",
            self.del_dev_target_dev_id
                .map(|dev_id| dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.uring_cmd_attempted={}",
            self.del_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.uring_cmd_completed={}",
            self.del_dev_uring_cmd_completed
        );
        println!(
            "del_dev.failure_class={}",
            self.del_dev_failure_class.as_str()
        );
        println!(
            "del_dev.errno={}",
            self.del_dev_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.runtime_error={}",
            self.del_dev_error
                .map(UblkControlDelDevError::as_str)
                .unwrap_or("none")
        );
        println!(
            "del_dev.deleted_dev_id={}",
            self.del_dev_outcome
                .map(|outcome| outcome.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "control.read_only_probe_uring_cmd_issued={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "control.mutating_add_dev_uring_cmd_issued={}",
            self.add_dev_report.add_dev_uring_cmd_attempted
        );
        println!(
            "control.mutating_del_dev_uring_cmd_issued={}",
            self.del_dev_uring_cmd_attempted
        );
        println!(
            "control.cleanup_attempted_after_add_dev={}",
            self.cleanup_attempted_after_add_dev
        );
        println!(
            "control.cleanup_failed_after_add_dev={}",
            self.cleanup_failed_after_add_dev
        );
        println!(
            "control.ublk_device_pair_created={}",
            self.ublk_device_pair_created
        );
        println!(
            "control.ublk_device_pair_deleted={}",
            self.ublk_device_pair_deleted
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        for step in ublk_control_plan_steps() {
            print_plan_step(*step);
        }
        println!("nonclaim.no_set_params_uring_cmd_issued=true");
        println!("nonclaim.no_start_dev_uring_cmd_issued=true");
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.io_uring_queue_processed
        );
        println!(
            "nonclaim.no_ublk_block_device_started={}",
            !self.ublk_block_device_started
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// True when the DEL_DEV io_uring command completed successfully.
    pub fn del_dev_uring_cmd_completed(&self) -> bool {
        self.del_dev_uring_cmd_completed
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// True when the ublk device pair was deleted from the kernel.
    pub fn ublk_device_pair_deleted(&self) -> bool {
        self.ublk_device_pair_deleted
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// The errno if DEL_DEV failed, or None.
    pub fn del_dev_errno(&self) -> Option<i32> {
        self.del_dev_errno
    }
}

impl UblkControlSetParamsReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk SET_PARAMS boundary");
        println!("gate={BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!("add_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
        println!("del_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "host.kernel_release={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .kernel_release
        );
        println!(
            "host.observe_kernel_class={:?}",
            self.add_dev_report.readonly_report.open_report.kernel_class
        );
        println!(
            "host.observe_baseline_satisfied={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .observe_baseline_satisfied
        );
        println!(
            "control.path={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_path
                .display()
        );
        println!("control.open_mode=read_write");
        println!(
            "control.open_attempted={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_open_attempted
        );
        println!(
            "control.opened={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_opened
        );
        println!(
            "control.open_error_class={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_open_error_class
                .map(UblkControlOpenErrorClass::as_str)
                .unwrap_or("none")
        );
        println!(
            "control.admission_class={:?}",
            self.add_dev_report
                .readonly_report
                .open_report
                .admission_class
        );
        println!(
            "control.refusal_class={:?}",
            self.add_dev_report
                .readonly_report
                .open_report
                .refusal_class
        );
        println!(
            "probe.command={}",
            self.add_dev_report
                .readonly_report
                .probe_spec
                .command
                .as_str()
        );
        println!(
            "probe.uring_cmd_attempted={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "probe.uring_cmd_completed={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_completed
        );
        println!(
            "probe.failure_class={}",
            self.add_dev_report
                .readonly_report
                .probe_failure_class
                .as_str()
        );
        match self.add_dev_report.readonly_report.probe_features {
            Some(features) => println!("features.mask=0x{:016x}", features.bits()),
            None => println!("features.mask=none"),
        }
        println!(
            "add_dev.required_features_mask=0x{:016x}",
            self.add_dev_report.add_dev_required_features.bits()
        );
        println!(
            "add_dev.required_features_available={}",
            self.add_dev_report.add_dev_required_features_available
        );
        println!(
            "add_dev.command={}",
            self.add_dev_report.add_dev_spec.command.as_str()
        );
        println!(
            "add_dev.uring_cmd_attempted={}",
            self.add_dev_report.add_dev_uring_cmd_attempted
        );
        println!(
            "add_dev.uring_cmd_completed={}",
            self.add_dev_report.add_dev_uring_cmd_completed
        );
        println!(
            "add_dev.failure_class={}",
            self.add_dev_report.add_dev_failure_class.as_str()
        );
        println!(
            "add_dev.returned_dev_id={}",
            self.add_dev_report
                .add_dev_outcome
                .map(|outcome| outcome.dev_info.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "set_params.command={}",
            self.set_params_spec.command.as_str()
        );
        println!(
            "set_params.command_op_raw=0x{:08x}",
            self.set_params_spec.request_raw
        );
        println!(
            "set_params.command_op_direction={}",
            self.set_params_spec.request_direction.as_str()
        );
        println!(
            "set_params.command_op_size={}",
            self.set_params_spec.request_size
        );
        println!("set_params.params_len={}", self.set_params_spec.params_len);
        println!(
            "set_params.queue_id={}",
            self.set_params_spec.control_queue_id
        );
        println!(
            "set_params.uring_cmd_sqe_bytes={}",
            self.set_params_spec.uring_cmd_sqe_bytes
        );
        println!(
            "set_params.mutates_control_state={}",
            self.set_params_spec.mutates_control_state
        );
        println!(
            "set_params.target_dev_id={}",
            self.set_params_target_dev_id
                .map(|dev_id| dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!("set_params.projected={}", self.set_params_projected);
        println!(
            "set_params.param_types=0x{:08x}",
            self.set_params_spec.param_types
        );
        println!(
            "set_params.dev_sectors={}",
            self.set_params_spec.dev_sectors
        );
        println!(
            "set_params.max_sectors={}",
            self.set_params_spec.max_sectors
        );
        println!(
            "set_params.max_segment_size={}",
            self.set_params_spec.max_segment_size
        );
        println!(
            "set_params.max_segments={}",
            self.set_params_spec.max_segments
        );
        println!(
            "set_params.uring_cmd_attempted={}",
            self.set_params_uring_cmd_attempted
        );
        println!(
            "set_params.uring_cmd_completed={}",
            self.set_params_uring_cmd_completed
        );
        println!(
            "set_params.failure_class={}",
            self.set_params_failure_class.as_str()
        );
        println!(
            "set_params.errno={}",
            self.set_params_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "set_params.runtime_error={}",
            self.set_params_error
                .map(UblkControlSetParamsError::as_str)
                .unwrap_or("none")
        );
        println!("del_dev.command={}", self.del_dev_spec.command.as_str());
        println!(
            "del_dev.target_dev_id={}",
            self.del_dev_target_dev_id
                .map(|dev_id| dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.uring_cmd_attempted={}",
            self.del_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.uring_cmd_completed={}",
            self.del_dev_uring_cmd_completed
        );
        println!(
            "del_dev.failure_class={}",
            self.del_dev_failure_class.as_str()
        );
        println!(
            "del_dev.errno={}",
            self.del_dev_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.runtime_error={}",
            self.del_dev_error
                .map(UblkControlDelDevError::as_str)
                .unwrap_or("none")
        );
        println!(
            "del_dev.deleted_dev_id={}",
            self.del_dev_outcome
                .map(|outcome| outcome.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "control.read_only_probe_uring_cmd_issued={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "control.mutating_add_dev_uring_cmd_issued={}",
            self.add_dev_report.add_dev_uring_cmd_attempted
        );
        println!(
            "control.mutating_set_params_uring_cmd_issued={}",
            self.set_params_uring_cmd_attempted
        );
        println!(
            "control.mutating_del_dev_uring_cmd_issued={}",
            self.del_dev_uring_cmd_attempted
        );
        println!(
            "control.cleanup_attempted_after_add_dev={}",
            self.cleanup_attempted_after_add_dev
        );
        println!(
            "control.cleanup_failed_after_add_dev={}",
            self.cleanup_failed_after_add_dev
        );
        println!(
            "control.ublk_device_pair_created={}",
            self.ublk_device_pair_created
        );
        println!(
            "control.ublk_device_pair_deleted={}",
            self.ublk_device_pair_deleted
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        for step in ublk_control_plan_steps() {
            print_plan_step(*step);
        }
        println!("nonclaim.no_start_dev_uring_cmd_issued=true");
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.io_uring_queue_processed
        );
        println!(
            "nonclaim.no_ublk_block_device_started={}",
            !self.ublk_block_device_started
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// True when the SET_PARAMS io_uring command completed successfully.
    pub fn set_params_uring_cmd_completed(&self) -> bool {
        self.set_params_uring_cmd_completed
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// The errno if SET_PARAMS failed, or None.
    pub fn set_params_errno(&self) -> Option<i32> {
        self.set_params_errno
    }
}

impl UblkControlStartDevReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk START_DEV boundary");
        println!("gate={BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!("add_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
        println!("set_params_gate={BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S}");
        println!("del_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "host.kernel_release={}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .open_report
                .kernel_release
        );
        println!(
            "host.observe_kernel_class={:?}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .open_report
                .kernel_class
        );
        println!(
            "control.path={}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .open_report
                .control_path
                .display()
        );
        println!("control.open_mode=read_write");
        println!(
            "control.open_attempted={}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .open_report
                .control_open_attempted
        );
        println!(
            "control.opened={}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .open_report
                .control_opened
        );
        println!(
            "control.admission_class={:?}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .open_report
                .admission_class
        );
        println!(
            "control.refusal_class={:?}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .open_report
                .refusal_class
        );
        println!(
            "probe.uring_cmd_attempted={}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "probe.uring_cmd_completed={}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .probe_uring_cmd_completed
        );
        match self
            .set_params_report
            .add_dev_report
            .readonly_report
            .probe_features
        {
            Some(features) => println!("features.mask=0x{:016x}", features.bits()),
            None => println!("features.mask=none"),
        }
        println!(
            "add_dev.required_features_available={}",
            self.set_params_report
                .add_dev_report
                .add_dev_required_features_available
        );
        println!(
            "add_dev.uring_cmd_attempted={}",
            self.set_params_report
                .add_dev_report
                .add_dev_uring_cmd_attempted
        );
        println!(
            "add_dev.uring_cmd_completed={}",
            self.set_params_report
                .add_dev_report
                .add_dev_uring_cmd_completed
        );
        println!(
            "add_dev.failure_class={}",
            self.set_params_report
                .add_dev_report
                .add_dev_failure_class
                .as_str()
        );
        println!(
            "add_dev.returned_dev_id={}",
            self.set_params_report
                .add_dev_report
                .add_dev_outcome
                .map(|outcome| outcome.dev_info.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "set_params.uring_cmd_attempted={}",
            self.set_params_report.set_params_uring_cmd_attempted
        );
        println!(
            "set_params.uring_cmd_completed={}",
            self.set_params_report.set_params_uring_cmd_completed
        );
        println!(
            "set_params.failure_class={}",
            self.set_params_report.set_params_failure_class.as_str()
        );
        println!(
            "set_params.projected={}",
            self.set_params_report.set_params_projected
        );
        println!("start_dev.command={}", self.start_dev_spec.command.as_str());
        println!(
            "start_dev.command_op_raw=0x{:08x}",
            self.start_dev_spec.request_raw
        );
        println!(
            "start_dev.command_op_direction={}",
            self.start_dev_spec.request_direction.as_str()
        );
        println!(
            "start_dev.command_op_size={}",
            self.start_dev_spec.request_size
        );
        println!(
            "start_dev.queue_id={}",
            self.start_dev_spec.control_queue_id
        );
        println!(
            "start_dev.ctrl_buffer_len={}",
            self.start_dev_spec.ctrl_buffer_len
        );
        println!(
            "start_dev.ctrl_buffer_addr={}",
            self.start_dev_spec.ctrl_buffer_addr
        );
        println!(
            "start_dev.inline_daemon_pid={}",
            self.start_dev_spec.inline_daemon_pid
        );
        println!(
            "start_dev.uring_cmd_sqe_bytes={}",
            self.start_dev_spec.uring_cmd_sqe_bytes
        );
        println!(
            "start_dev.mutates_control_state={}",
            self.start_dev_spec.mutates_control_state
        );
        println!(
            "start_dev.requires_ready_io_fetches={}",
            self.start_dev_spec.requires_ready_io_fetches
        );
        println!(
            "start_dev.target_dev_id={}",
            self.start_dev_target_dev_id
                .map(|dev_id| dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "start_dev.daemon_pid={}",
            self.start_dev_daemon_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "start_dev.io_queue_fetches_ready={}",
            self.start_dev_readiness.all_fetches_ready()
        );
        println!(
            "start_dev.data_queue_runtime_live={}",
            self.start_dev_readiness.data_queue_runtime_live
        );
        println!(
            "start_dev.required_fetch_commands={}",
            self.start_dev_readiness.required_fetch_commands
        );
        println!(
            "start_dev.submitted_fetch_commands={}",
            self.start_dev_readiness.submitted_fetch_commands
        );
        println!(
            "start_dev.uring_cmd_attempted={}",
            self.start_dev_uring_cmd_attempted
        );
        println!(
            "start_dev.uring_cmd_completed={}",
            self.start_dev_uring_cmd_completed
        );
        println!(
            "start_dev.failure_class={}",
            self.start_dev_failure_class.as_str()
        );
        println!(
            "start_dev.errno={}",
            self.start_dev_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "start_dev.runtime_error={}",
            self.start_dev_error
                .map(UblkControlStartDevError::as_str)
                .unwrap_or("none")
        );
        println!(
            "start_dev.started_dev_id={}",
            self.start_dev_outcome
                .map(|outcome| outcome.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.target_dev_id={}",
            self.set_params_report
                .del_dev_target_dev_id
                .map(|dev_id| dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.uring_cmd_attempted={}",
            self.set_params_report.del_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.uring_cmd_completed={}",
            self.set_params_report.del_dev_uring_cmd_completed
        );
        println!(
            "del_dev.failure_class={}",
            self.set_params_report.del_dev_failure_class.as_str()
        );
        println!(
            "control.read_only_probe_uring_cmd_issued={}",
            self.set_params_report
                .add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "control.mutating_add_dev_uring_cmd_issued={}",
            self.set_params_report
                .add_dev_report
                .add_dev_uring_cmd_attempted
        );
        println!(
            "control.mutating_set_params_uring_cmd_issued={}",
            self.set_params_report.set_params_uring_cmd_attempted
        );
        println!(
            "control.mutating_start_dev_uring_cmd_issued={}",
            self.start_dev_uring_cmd_attempted
        );
        println!(
            "control.mutating_del_dev_uring_cmd_issued={}",
            self.set_params_report.del_dev_uring_cmd_attempted
        );
        println!(
            "control.cleanup_attempted_after_add_dev={}",
            self.set_params_report.cleanup_attempted_after_add_dev
        );
        println!(
            "control.cleanup_failed_after_add_dev={}",
            self.set_params_report.cleanup_failed_after_add_dev
        );
        println!(
            "control.ublk_device_pair_created={}",
            self.ublk_device_pair_created
        );
        println!(
            "control.ublk_device_pair_deleted={}",
            self.ublk_device_pair_deleted
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        for step in ublk_control_plan_steps() {
            print_plan_step(*step);
        }
        println!("nonclaim.no_data_queue_fetches_submitted=true");
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.io_uring_queue_processed
        );
        println!(
            "nonclaim.no_ublk_block_device_started={}",
            !self.ublk_block_device_started
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// True when the START_DEV io_uring command completed successfully.
    pub fn start_dev_uring_cmd_completed(&self) -> bool {
        self.start_dev_uring_cmd_completed
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// True when the ublk block device was started.
    pub fn ublk_block_device_started(&self) -> bool {
        self.ublk_block_device_started
    }
    #[cfg(feature = "ublk-host")]
    #[allow(dead_code)]
    /// The errno if START_DEV failed, or None.
    pub fn start_dev_errno(&self) -> Option<i32> {
        self.start_dev_errno
    }
}

impl UblkDataQueueFetchReqReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk data-queue FETCH_REQ readiness boundary");
        println!("gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("start_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!("host.kernel_release={}", self.open_report.kernel_release);
        println!(
            "host.observe_kernel_class={:?}",
            self.open_report.kernel_class
        );
        println!(
            "host.observe_baseline_satisfied={}",
            self.open_report.observe_baseline_satisfied
        );
        println!("control.path={}", self.open_report.control_path.display());
        println!("control.open_mode=read_write");
        println!(
            "control.open_attempted={}",
            self.open_report.control_open_attempted
        );
        println!("control.opened={}", self.open_report.control_opened);
        println!(
            "control.admission_class={:?}",
            self.open_report.admission_class
        );
        println!("control.refusal_class={:?}", self.open_report.refusal_class);
        println!("add_dev.nr_hw_queues={}", self.add_dev_input.nr_hw_queues);
        println!("add_dev.queue_depth={}", self.add_dev_input.queue_depth);
        println!("fetch_req.command={}", self.fetch_req_spec.command.as_str());
        println!(
            "fetch_req.command_op_raw=0x{:08x}",
            self.fetch_req_spec.request_raw
        );
        println!(
            "fetch_req.command_op_direction={}",
            self.fetch_req_spec.request_direction.as_str()
        );
        println!(
            "fetch_req.command_op_size={}",
            self.fetch_req_spec.request_size
        );
        println!("fetch_req.queue_id={}", self.fetch_req_spec.q_id);
        println!("fetch_req.q_id={}", self.fetch_req_spec.q_id);
        println!("fetch_req.tag={}", self.fetch_req_spec.tag);
        println!("fetch_req.result={}", self.fetch_req_spec.result);
        println!(
            "fetch_req.user_copy_addr={}",
            self.fetch_req_spec.user_copy_addr
        );
        println!(
            "fetch_req.user_data=0x{:016x}",
            fetch_req_user_data(self.fetch_req_spec.q_id, self.fetch_req_spec.tag)
        );
        println!(
            "fetch_req.uring_cmd_sqe_bytes={}",
            self.fetch_req_spec.uring_cmd_sqe_bytes
        );
        println!(
            "fetch_req.commits_result={}",
            self.fetch_req_spec.commits_result
        );
        println!(
            "fetch_req.must_remain_in_flight_for_start={}",
            self.fetch_req_spec.must_remain_in_flight_for_start
        );
        println!("data_queue.path_template=/dev/ublkcN");
        println!("data_queue.path={}", self.data_queue_path.display());
        println!(
            "data_queue.open_attempted={}",
            self.data_queue_open_attempted
        );
        println!("data_queue.opened={}", self.data_queue_opened);
        println!("data_queue.runtime_live={}", self.data_queue_runtime_live);
        println!(
            "fetch_req.data_queue_runtime_live={}",
            self.data_queue_runtime_live
        );
        println!(
            "fetch_req.required_fetch_commands={}",
            self.fetch_req_readiness.required_fetch_commands
        );
        println!(
            "fetch_req.submitted_fetch_commands={}",
            self.fetch_req_readiness.submitted_fetch_commands
        );
        println!(
            "fetch_req.submission_attempted={}",
            self.fetch_req_submission_attempted
        );
        println!("fetch_req.submitted={}", self.fetch_req_submitted);
        println!(
            "fetch_req.all_fetches_ready={}",
            self.fetch_req_readiness.all_fetches_ready()
        );
        println!(
            "start_dev.required_fetch_commands={}",
            self.start_dev_readiness.required_fetch_commands
        );
        println!(
            "start_dev.submitted_fetch_commands={}",
            self.start_dev_readiness.submitted_fetch_commands
        );
        println!(
            "start_dev.data_queue_runtime_live={}",
            self.start_dev_readiness.data_queue_runtime_live
        );
        println!(
            "start_dev.io_queue_fetches_ready={}",
            self.start_dev_readiness.all_fetches_ready()
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.fetch_req_submitted
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        println!("nonclaim.no_start_dev_uring_cmd_issued=true");
        println!("nonclaim.no_fetch_req_submitted_without_live_queue_runtime=true");
        println!(
            "nonclaim.no_data_queue_fetches_submitted={}",
            !self.fetch_req_submitted
        );
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.fetch_req_submitted
        );
        println!(
            "nonclaim.no_ublk_block_device_started={}",
            !self.ublk_block_device_started
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
}

impl UblkDataQueueOpenReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk data-queue open boundary");
        println!("gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!("add_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
        println!("fetch_req_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U}");
        println!("del_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "host.kernel_release={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .kernel_release
        );
        println!(
            "host.observe_kernel_class={:?}",
            self.add_dev_report.readonly_report.open_report.kernel_class
        );
        println!(
            "control.path={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_path
                .display()
        );
        println!("control.open_mode=read_write");
        println!(
            "control.open_attempted={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_open_attempted
        );
        println!(
            "control.opened={}",
            self.add_dev_report
                .readonly_report
                .open_report
                .control_opened
        );
        println!(
            "control.admission_class={:?}",
            self.add_dev_report
                .readonly_report
                .open_report
                .admission_class
        );
        println!(
            "control.refusal_class={:?}",
            self.add_dev_report
                .readonly_report
                .open_report
                .refusal_class
        );
        println!(
            "probe.uring_cmd_attempted={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "probe.uring_cmd_completed={}",
            self.add_dev_report
                .readonly_report
                .probe_uring_cmd_completed
        );
        match self.add_dev_report.readonly_report.probe_features {
            Some(features) => println!("features.mask=0x{:016x}", features.bits()),
            None => println!("features.mask=none"),
        }
        println!(
            "add_dev.required_features_available={}",
            self.add_dev_report.add_dev_required_features_available
        );
        println!(
            "add_dev.uring_cmd_attempted={}",
            self.add_dev_report.add_dev_uring_cmd_attempted
        );
        println!(
            "add_dev.uring_cmd_completed={}",
            self.add_dev_report.add_dev_uring_cmd_completed
        );
        println!(
            "add_dev.failure_class={}",
            self.add_dev_report.add_dev_failure_class.as_str()
        );
        println!(
            "add_dev.returned_dev_id={}",
            self.add_dev_report
                .add_dev_outcome
                .map(|outcome| outcome.dev_info.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "data_queue.path_template={}",
            self.data_queue_spec.data_queue_path_template
        );
        println!(
            "data_queue.path={}",
            self.data_queue_spec.data_queue_path.display()
        );
        println!("data_queue.open_mode={}", self.data_queue_spec.open_mode);
        println!("data_queue.dev_id={}", self.data_queue_spec.dev_id);
        println!("data_queue.q_id={}", self.data_queue_spec.q_id);
        println!(
            "data_queue.nr_hw_queues={}",
            self.data_queue_spec.nr_hw_queues
        );
        println!(
            "data_queue.queue_depth={}",
            self.data_queue_spec.queue_depth
        );
        println!(
            "data_queue.ring_entries={}",
            self.data_queue_spec.ring_entries
        );
        println!(
            "data_queue.uring_cmd_sqe_bytes={}",
            self.data_queue_spec.uring_cmd_sqe_bytes
        );
        println!(
            "data_queue.requires_successful_add_dev={}",
            self.data_queue_spec.requires_successful_add_dev
        );
        println!(
            "data_queue.submits_fetch_req={}",
            self.data_queue_spec.submits_fetch_req
        );
        println!(
            "data_queue.target_dev_id={}",
            self.data_queue_target_dev_id
                .map(|dev_id| dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "data_queue.open_attempted={}",
            self.data_queue_open_attempted
        );
        println!("data_queue.opened={}", self.data_queue_opened);
        println!(
            "data_queue.runtime_live={}",
            self.fetch_req_readiness.data_queue_runtime_live
        );
        println!(
            "data_queue.failure_class={}",
            self.data_queue_failure_class.as_str()
        );
        println!(
            "data_queue.errno={}",
            self.data_queue_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "data_queue.runtime_error={}",
            self.data_queue_error
                .map(UblkDataQueueRuntimeOpenError::as_str)
                .unwrap_or("none")
        );
        println!(
            "data_queue.opened_path={}",
            self.data_queue_outcome
                .as_ref()
                .map(|outcome| outcome.data_queue_path.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "fetch_req.required_fetch_commands={}",
            self.fetch_req_readiness.required_fetch_commands
        );
        println!(
            "fetch_req.submitted_fetch_commands={}",
            self.fetch_req_readiness.submitted_fetch_commands
        );
        println!(
            "fetch_req.data_queue_runtime_live={}",
            self.fetch_req_readiness.data_queue_runtime_live
        );
        println!(
            "fetch_req.all_fetches_ready={}",
            self.fetch_req_readiness.all_fetches_ready()
        );
        println!("fetch_req.submitted={}", self.fetch_req_submitted);
        println!(
            "start_dev.data_queue_runtime_live={}",
            self.start_dev_readiness.data_queue_runtime_live
        );
        println!(
            "start_dev.io_queue_fetches_ready={}",
            self.start_dev_readiness.all_fetches_ready()
        );
        println!(
            "start_dev.uring_cmd_attempted={}",
            self.start_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.target_dev_id={}",
            self.del_dev_target_dev_id
                .map(|dev_id| dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.uring_cmd_attempted={}",
            self.del_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.uring_cmd_completed={}",
            self.del_dev_uring_cmd_completed
        );
        println!(
            "del_dev.failure_class={}",
            self.del_dev_failure_class.as_str()
        );
        println!(
            "del_dev.errno={}",
            self.del_dev_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "del_dev.runtime_error={}",
            self.del_dev_error
                .map(UblkControlDelDevError::as_str)
                .unwrap_or("none")
        );
        println!(
            "del_dev.deleted_dev_id={}",
            self.del_dev_outcome
                .map(|outcome| outcome.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "control.mutating_add_dev_uring_cmd_issued={}",
            self.add_dev_report.add_dev_uring_cmd_attempted
        );
        println!(
            "control.mutating_del_dev_uring_cmd_issued={}",
            self.del_dev_uring_cmd_attempted
        );
        println!(
            "control.cleanup_attempted_after_add_dev={}",
            self.cleanup_attempted_after_add_dev
        );
        println!(
            "control.cleanup_failed_after_add_dev={}",
            self.cleanup_failed_after_add_dev
        );
        println!(
            "control.ublk_device_pair_created={}",
            self.ublk_device_pair_created
        );
        println!(
            "control.ublk_device_pair_deleted={}",
            self.ublk_device_pair_deleted
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        println!("nonclaim.no_fetch_req_submitted=true");
        println!("nonclaim.no_start_dev_uring_cmd_issued=true");
        println!(
            "nonclaim.no_io_uring_queue_processed={}",
            !self.io_uring_queue_processed
        );
        println!(
            "nonclaim.no_ublk_block_device_started={}",
            !self.ublk_block_device_started
        );
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
}

impl UblkDataQueueFetchReqSubmissionReport {
    pub fn print(&self) {
        let first_submitted_tag = self
            .fetch_req_outcome
            .and_then(|outcome| outcome.first_submitted_tag)
            .or_else(|| {
                let submitted = self.fetch_req_readiness.submitted_fetch_commands;
                (submitted > 0).then_some(0)
            });
        let last_submitted_tag = self
            .fetch_req_outcome
            .and_then(|outcome| outcome.last_submitted_tag)
            .or_else(|| {
                let submitted = self.fetch_req_readiness.submitted_fetch_commands;
                (submitted > 0).then(|| (submitted - 1) as u16)
            });

        println!("tidefs block volume adapter ublk data-queue FETCH_REQ submission boundary");
        println!("gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!("add_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
        println!("data_queue_open_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V}");
        println!("fetch_req_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U}");
        println!("del_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "host.kernel_release={}",
            self.data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .kernel_release
        );
        println!(
            "host.observe_kernel_class={:?}",
            self.data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .kernel_class
        );
        println!(
            "control.path={}",
            self.data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .control_path
                .display()
        );
        println!("control.open_mode=read_write");
        println!(
            "control.open_attempted={}",
            self.data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .control_open_attempted
        );
        println!(
            "control.opened={}",
            self.data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .control_opened
        );
        println!(
            "probe.uring_cmd_attempted={}",
            self.data_queue_open_report
                .add_dev_report
                .readonly_report
                .probe_uring_cmd_attempted
        );
        println!(
            "probe.uring_cmd_completed={}",
            self.data_queue_open_report
                .add_dev_report
                .readonly_report
                .probe_uring_cmd_completed
        );
        println!(
            "add_dev.required_features_available={}",
            self.data_queue_open_report
                .add_dev_report
                .add_dev_required_features_available
        );
        println!(
            "add_dev.uring_cmd_attempted={}",
            self.data_queue_open_report
                .add_dev_report
                .add_dev_uring_cmd_attempted
        );
        println!(
            "add_dev.uring_cmd_completed={}",
            self.data_queue_open_report
                .add_dev_report
                .add_dev_uring_cmd_completed
        );
        println!(
            "add_dev.returned_dev_id={}",
            self.data_queue_open_report
                .add_dev_report
                .add_dev_outcome
                .map(|outcome| outcome.dev_info.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "data_queue.path={}",
            self.data_queue_open_report
                .data_queue_spec
                .data_queue_path
                .display()
        );
        println!(
            "data_queue.open_attempted={}",
            self.data_queue_open_report.data_queue_open_attempted
        );
        println!(
            "data_queue.opened={}",
            self.data_queue_open_report.data_queue_opened
        );
        println!(
            "data_queue.runtime_live={}",
            self.fetch_req_readiness.data_queue_runtime_live
        );
        println!("fetch_req.q_id={}", self.fetch_req_submission_spec.q_id);
        println!(
            "fetch_req.queue_depth={}",
            self.fetch_req_submission_spec.queue_depth
        );
        println!(
            "fetch_req.queue_fetch_commands={}",
            self.fetch_req_submission_spec.queue_fetch_commands
        );
        println!(
            "fetch_req.all_queues_required_fetch_commands={}",
            self.fetch_req_submission_spec
                .all_queues_required_fetch_commands
        );
        println!(
            "fetch_req.first_tag={}",
            self.fetch_req_submission_spec.first_tag
        );
        println!(
            "fetch_req.last_tag={}",
            self.fetch_req_submission_spec.last_tag
        );
        println!(
            "fetch_req.runtime_must_remain_live={}",
            self.fetch_req_submission_spec.runtime_must_remain_live
        );
        println!(
            "fetch_req.submits_without_waiting_for_cqe={}",
            self.fetch_req_submission_spec
                .submits_without_waiting_for_cqe
        );
        println!(
            "fetch_req.submission_attempted={}",
            self.fetch_req_submission_attempted
        );
        println!(
            "fetch_req.submission_completed={}",
            self.fetch_req_submission_completed
        );
        println!("fetch_req.submitted={}", self.fetch_req_submitted);
        println!(
            "fetch_req.submitted_fetch_commands={}",
            self.fetch_req_readiness.submitted_fetch_commands
        );
        println!(
            "fetch_req.first_submitted_tag={}",
            first_submitted_tag
                .map(|tag| tag.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "fetch_req.last_submitted_tag={}",
            last_submitted_tag
                .map(|tag| tag.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "fetch_req.failure_class={}",
            self.fetch_req_failure_class.as_str()
        );
        println!(
            "fetch_req.errno={}",
            self.fetch_req_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "fetch_req.runtime_error={}",
            self.fetch_req_error
                .map(UblkDataQueueFetchReqSubmissionError::as_str)
                .unwrap_or("none")
        );
        println!(
            "fetch_req.all_fetches_ready={}",
            self.fetch_req_readiness.all_fetches_ready()
        );
        println!(
            "start_dev.required_fetch_commands={}",
            self.start_dev_readiness.required_fetch_commands
        );
        println!(
            "start_dev.submitted_fetch_commands={}",
            self.start_dev_readiness.submitted_fetch_commands
        );
        println!(
            "start_dev.io_queue_fetches_ready={}",
            self.start_dev_readiness.all_fetches_ready()
        );
        println!(
            "start_dev.uring_cmd_attempted={}",
            self.start_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.uring_cmd_attempted={}",
            self.data_queue_open_report.del_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.uring_cmd_completed={}",
            self.data_queue_open_report.del_dev_uring_cmd_completed
        );
        println!(
            "control.cleanup_attempted_after_add_dev={}",
            self.data_queue_open_report.cleanup_attempted_after_add_dev
        );
        println!(
            "control.cleanup_failed_after_add_dev={}",
            self.data_queue_open_report.cleanup_failed_after_add_dev
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        println!("nonclaim.no_start_dev_uring_cmd_issued=true");
        println!("nonclaim.no_ublk_block_device_started=true");
        println!("nonclaim.no_block_io_processed=true");
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
}

impl UblkDataQueueCommitAndFetchReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk data-queue COMMIT_AND_FETCH_REQ boundary");
        println!("gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_COMMIT_FETCH_GATE_OW_301X}");
        println!("open_gate={BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O}");
        println!("probe_gate={BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P}");
        println!("add_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q}");
        println!("data_queue_open_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V}");
        println!(
            "fetch_req_submit_gate={BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W}"
        );
        println!("del_dev_gate={BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R}");
        println!(
            "surface_binary={}",
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name
        );
        println!(
            "host.kernel_release={}",
            self.fetch_req_report
                .data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .kernel_release
        );
        println!(
            "host.observe_kernel_class={:?}",
            self.fetch_req_report
                .data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .kernel_class
        );
        println!(
            "control.opened={}",
            self.fetch_req_report
                .data_queue_open_report
                .add_dev_report
                .readonly_report
                .open_report
                .control_opened
        );
        println!(
            "add_dev.uring_cmd_completed={}",
            self.fetch_req_report
                .data_queue_open_report
                .add_dev_report
                .add_dev_uring_cmd_completed
        );
        println!(
            "data_queue.opened={}",
            self.fetch_req_report
                .data_queue_open_report
                .data_queue_opened
        );
        println!(
            "fetch_req.submission_completed={}",
            self.fetch_req_report.fetch_req_submission_completed
        );
        println!(
            "fetch_req.submitted_fetch_commands={}",
            self.fetch_req_report
                .fetch_req_readiness
                .submitted_fetch_commands
        );
        println!(
            "commit_and_fetch.command={}",
            self.commit_and_fetch_spec.command.as_str()
        );
        println!(
            "commit_and_fetch.command_op_raw=0x{:08x}",
            self.commit_and_fetch_spec.request_raw
        );
        println!(
            "commit_and_fetch.command_op_direction={}",
            self.commit_and_fetch_spec.request_direction.as_str()
        );
        println!(
            "commit_and_fetch.command_op_size={}",
            self.commit_and_fetch_spec.request_size
        );
        println!("commit_and_fetch.q_id={}", self.commit_and_fetch_spec.q_id);
        println!("commit_and_fetch.tag={}", self.commit_and_fetch_spec.tag);
        println!(
            "commit_and_fetch.result={}",
            self.commit_and_fetch_spec.result
        );
        println!(
            "commit_and_fetch.user_data=0x{:016x}",
            commit_and_fetch_user_data(
                self.commit_and_fetch_spec.q_id,
                self.commit_and_fetch_spec.tag
            )
        );
        println!(
            "commit_and_fetch.commits_result={}",
            self.commit_and_fetch_spec.commits_result
        );
        println!(
            "commit_and_fetch.fetches_next_request={}",
            self.commit_and_fetch_spec.fetches_next_request
        );
        println!(
            "commit_and_fetch.data_queue_runtime_live={}",
            self.commit_and_fetch_readiness.data_queue_runtime_live
        );
        println!(
            "commit_and_fetch.fetched_request_available={}",
            self.commit_and_fetch_readiness.fetched_request_available
        );
        println!(
            "commit_and_fetch.completion_result_ready={}",
            self.commit_and_fetch_readiness.completion_result_ready
        );
        println!(
            "commit_and_fetch.ready={}",
            self.commit_and_fetch_readiness
                .all_commit_preconditions_ready()
        );
        println!(
            "commit_and_fetch.uring_cmd_attempted={}",
            self.commit_and_fetch_attempted
        );
        println!(
            "commit_and_fetch.uring_cmd_completed={}",
            self.commit_and_fetch_completed
        );
        println!(
            "commit_and_fetch.submitted={}",
            self.commit_and_fetch_submitted
        );
        println!(
            "commit_and_fetch.failure_class={}",
            self.commit_and_fetch_failure_class.as_str()
        );
        println!(
            "commit_and_fetch.errno={}",
            self.commit_and_fetch_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "commit_and_fetch.runtime_error={}",
            self.commit_and_fetch_error
                .map(UblkDataQueueCommitAndFetchError::as_str)
                .unwrap_or("none")
        );
        println!(
            "del_dev.uring_cmd_attempted={}",
            self.fetch_req_report
                .data_queue_open_report
                .del_dev_uring_cmd_attempted
        );
        println!(
            "del_dev.uring_cmd_completed={}",
            self.fetch_req_report
                .data_queue_open_report
                .del_dev_uring_cmd_completed
        );
        println!(
            "start_dev.uring_cmd_attempted={}",
            self.start_dev_uring_cmd_attempted
        );
        println!(
            "control.io_uring_queue_processed={}",
            self.io_uring_queue_processed
        );
        println!(
            "control.ublk_block_device_started={}",
            self.ublk_block_device_started
        );
        println!("nonclaim.no_start_dev_uring_cmd_issued=true");
        println!("nonclaim.no_ublk_block_device_started=true");
        println!("nonclaim.no_block_io_processed=true");
        println!("nonclaim.no_fio_validation=true");
        println!("nonclaim.no_mkfs_mount_or_guest_filesystem=true");
        let _resize_policy = resolve_resize_policy(false);
        println!("resize.supported=false");
        println!("resize.refusal_reason=pool_capacity_fixed_at_create");
        println!("nonclaim.parent_ow_301_pc_005_pc_012_remain_open=true");
    }
}
