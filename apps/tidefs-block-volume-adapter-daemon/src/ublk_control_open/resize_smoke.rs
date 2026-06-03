#![allow(unused_assignments)]
use super::*;
use tidefs_block_volume_adapter_ublk_control_runtime::{
    issue_update_size, resolve_resize_policy, UblkControlUpdateSizeCommand,
    UblkControlUpdateSizeError, UblkControlUpdateSizeInput, UblkControlUpdateSizeOutcome,
    UblkControlUpdateSizeSpec, UblkResizeRefusalReason,
    BLOCK_VOLUME_UBLK_CONTROL_UPDATE_SIZE_GATE_OW_301Y, TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkControlResizeSmokeFailureClass {
    HostNotAdmitted,
    ControlOpenFailed,
    FeatureProbeFailed,
    RequiredFeaturesMissing,
    AddDevFailed,
    AddDevDidNotReturnDeviceId,
    ParameterBuildFailed,
    SetParamsFailed,
    DataQueueFetchesNotReady,
    StartDevFailed,
    UpdateSizeFailed,
    UpdateSizeUringCmdCompleted,
    ResizeExplicitlyRefused,
}

impl UblkControlResizeSmokeFailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostNotAdmitted => "host_not_admitted",
            Self::ControlOpenFailed => "control_open_failed",
            Self::FeatureProbeFailed => "feature_probe_failed",
            Self::RequiredFeaturesMissing => "required_features_missing",
            Self::AddDevFailed => "add_dev_failed",
            Self::AddDevDidNotReturnDeviceId => "add_dev_did_not_return_device_id",
            Self::ParameterBuildFailed => "parameter_build_failed",
            Self::SetParamsFailed => "set_params_failed",
            Self::DataQueueFetchesNotReady => "data_queue_fetches_not_ready",
            Self::StartDevFailed => "start_dev_failed",
            Self::UpdateSizeFailed => "update_size_failed",
            Self::UpdateSizeUringCmdCompleted => "update_size_uring_cmd_completed",
            Self::ResizeExplicitlyRefused => "resize_explicitly_refused",
        }
    }
}

#[derive(Clone, Debug)]
pub struct UblkControlResizeSmokeReport {
    pub gate: &'static str,
    pub failure_class: UblkControlResizeSmokeFailureClass,
    pub start_dev_target_dev_id: Option<u32>,
    pub start_dev_uring_cmd_completed: bool,
    pub update_size_attempted: bool,
    pub update_size_completed: bool,
    pub update_size_errno: Option<i32>,
    pub update_size_error: Option<UblkControlUpdateSizeError>,
    pub update_size_outcome: Option<UblkControlUpdateSizeOutcome>,
    pub original_dev_sectors: u64,
    pub resized_dev_sectors: u64,
    pub ublk_device_pair_deleted: bool,
    pub resize_supported: bool,
    pub resize_refusal_reason: Option<UblkResizeRefusalReason>,
    pub resize_refusal_guest_errno: Option<i32>,
}

impl UblkControlResizeSmokeReport {
    pub fn print(&self) {
        println!("gate={}", self.gate);
        println!("failure_class={}", self.failure_class.as_str());
        println!(
            "start_dev.target_dev_id={}",
            self.start_dev_target_dev_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "start_dev.uring_cmd_completed={}",
            self.start_dev_uring_cmd_completed
        );
        println!("update_size.attempted={}", self.update_size_attempted);
        println!("update_size.completed={}", self.update_size_completed);
        println!(
            "update_size.errno={}",
            self.update_size_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "update_size.runtime_error={}",
            self.update_size_error
                .map(UblkControlUpdateSizeError::as_str)
                .unwrap_or("none")
        );
        println!(
            "update_size.outcome_dev_id={}",
            self.update_size_outcome
                .as_ref()
                .map(|o| o.dev_id.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "update_size.outcome_dev_sectors={}",
            self.update_size_outcome
                .as_ref()
                .map(|o| o.params.basic.dev_sectors.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "update_size.original_dev_sectors={}",
            self.original_dev_sectors
        );
        println!(
            "update_size.resized_dev_sectors={}",
            self.resized_dev_sectors
        );
        println!("ublk_device_pair_deleted={}", self.ublk_device_pair_deleted);
        println!("resize_policy.supported={}", self.resize_supported);
        println!(
            "resize_policy.refusal_reason={}",
            self.resize_refusal_reason
                .map(UblkResizeRefusalReason::as_str)
                .unwrap_or("none")
        );
        println!(
            "resize_policy.guest_errno={}",
            self.resize_refusal_guest_errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
    }
}

pub fn run_ublk_control_resize_smoke_boundary() -> Result<UblkControlResizeSmokeReport, AppError> {
    let resize_policy = resolve_resize_policy(true);
    if let Some(reason) = resize_policy.reason {
        return Ok(UblkControlResizeSmokeReport {
            gate: BLOCK_VOLUME_UBLK_CONTROL_UPDATE_SIZE_GATE_OW_301Y,
            failure_class: UblkControlResizeSmokeFailureClass::ResizeExplicitlyRefused,
            start_dev_target_dev_id: None,
            start_dev_uring_cmd_completed: false,
            update_size_attempted: false,
            update_size_completed: false,
            update_size_errno: None,
            update_size_error: None,
            update_size_outcome: None,
            original_dev_sectors: 0,
            resized_dev_sectors: 0,
            ublk_device_pair_deleted: false,
            resize_supported: false,
            resize_refusal_reason: Some(reason),
            resize_refusal_guest_errno: Some(reason.guest_errno()),
        });
    }

    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    let mut add_dev_result = None;
    let mut _set_params_input = None;
    let mut set_params_result = None;
    let mut _start_dev_input = None;
    let mut start_dev_result = None;
    let mut del_dev_result = None;
    let mut update_size_result: Option<
        Result<UblkControlUpdateSizeOutcome, UblkControlUpdateSizeError>,
    > = None;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let mut start_dev_readiness = UblkControlStartDevReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
    );

    let mut original_dev_sectors: u64 = 0;
    let mut resized_dev_sectors: u64 = 0;
    let mut dev_id_for_update: Option<u32> = None;
    let mut params_for_update = UblkParams::default();

    if inputs.should_attempt_control_open() {
        match open_control_device_file(&inputs.control_path) {
            Ok(control_device) => {
                inputs.control_open_result = Some(Ok(()));
                let current_probe_result = issue_get_features(control_device.as_fd());
                if current_probe_result.as_ref().is_ok_and(|outcome| {
                    outcome
                        .features
                        .contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES)
                }) {
                    let current_add_dev_result =
                        issue_add_dev(control_device.as_fd(), add_dev_input);
                    if let Ok(outcome) = &current_add_dev_result {
                        dev_id_for_update = Some(outcome.dev_info.dev_id);
                        if let Ok(parameter_report) = build_ublk_parameter_spec_report() {
                            original_dev_sectors = parameter_report.params.basic.dev_sectors;
                            params_for_update = parameter_report.params;
                            resized_dev_sectors = original_dev_sectors.saturating_mul(2);
                            let set_params =
                                UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                                    outcome.dev_info.dev_id,
                                    parameter_report.params,
                                );
                            let current_set_params_result =
                                issue_set_params(control_device.as_fd(), set_params);
                            if current_set_params_result.is_ok() {
                                let data_queue_input =
                                    UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                                        outcome.dev_info.dev_id,
                                        0,
                                        add_dev_input.nr_hw_queues,
                                        add_dev_input.queue_depth,
                                    );
                                let data_queue_path =
                                    ublk_data_queue_device_path(data_queue_input.dev_id);
                                if let Ok(mut data_queue_runtime) =
                                    open_data_queue_runtime(&data_queue_path, data_queue_input)
                                {
                                    if let Ok(fetch_outcome) =
                                        submit_runtime_fetch_reqs_without_wait(
                                            &mut data_queue_runtime,
                                        )
                                    {
                                        start_dev_readiness = fetch_outcome.start_dev_readiness();
                                        let _ = start_dev_readiness.all_fetches_ready();
                                    }
                                }
                                let daemon_pid =
                                    i32::try_from(std::process::id()).unwrap_or(i32::MAX);
                                let current_start_dev_input =
                                    UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(
                                        outcome.dev_info.dev_id,
                                        daemon_pid,
                                    );
                                if start_dev_readiness.all_fetches_ready() {
                                    start_dev_result = Some(issue_start_dev(
                                        control_device.as_fd(),
                                        current_start_dev_input,
                                        start_dev_readiness,
                                    ));
                                }
                                _start_dev_input = Some(current_start_dev_input);

                                if start_dev_result.as_ref().is_some_and(|r| r.is_ok()) {
                                    let mut resized_params = params_for_update;
                                    resized_params.basic.dev_sectors = resized_dev_sectors;
                                    let update_input =
                                        UblkControlUpdateSizeInput::from_kernel_dev_id_and_params(
                                            outcome.dev_info.dev_id,
                                            resized_params,
                                        );
                                    update_size_result = Some(issue_update_size(
                                        control_device.as_fd(),
                                        update_input,
                                    ));
                                }
                            }
                            set_params_result = Some(current_set_params_result);
                            _set_params_input = Some(set_params);
                        }

                        let del_input =
                            UblkControlDelDevInput::from_kernel_dev_id(outcome.dev_info.dev_id);
                        del_dev_result = Some(issue_del_dev(control_device.as_fd(), del_input));
                    }
                    add_dev_result = Some(current_add_dev_result);
                }
                probe_result = Some(current_probe_result);
            }
            Err(error_class) => {
                inputs.control_open_result = Some(Err(error_class));
            }
        }
    }

    let mut failure_class = UblkControlResizeSmokeFailureClass::HostNotAdmitted;
    let mut start_dev_target_dev_id = None;
    let mut start_dev_uring_cmd_completed = false;
    let mut update_size_attempted = false;
    let mut update_size_completed = false;
    let mut update_size_errno = None;
    let mut update_size_error = None;
    let mut update_size_outcome = None;
    let mut ublk_device_pair_deleted = false;

    if inputs.control_open_result.is_none() {
        failure_class = UblkControlResizeSmokeFailureClass::HostNotAdmitted;
    } else if inputs
        .control_open_result
        .as_ref()
        .is_some_and(|r| r.is_err())
    {
        failure_class = UblkControlResizeSmokeFailureClass::ControlOpenFailed;
    } else if probe_result.as_ref().is_none_or(|r| r.is_err()) {
        failure_class = UblkControlResizeSmokeFailureClass::FeatureProbeFailed;
    } else if add_dev_result.is_none() {
        failure_class = UblkControlResizeSmokeFailureClass::RequiredFeaturesMissing;
    } else if add_dev_result.as_ref().is_some_and(|r| r.is_err()) {
        failure_class = UblkControlResizeSmokeFailureClass::AddDevFailed;
    } else if dev_id_for_update.is_none()
        || dev_id_for_update == Some(TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID)
    {
        failure_class = UblkControlResizeSmokeFailureClass::AddDevDidNotReturnDeviceId;
    } else if set_params_result.is_none() {
        failure_class = UblkControlResizeSmokeFailureClass::ParameterBuildFailed;
    } else if set_params_result.as_ref().is_some_and(|r| r.is_err()) {
        failure_class = UblkControlResizeSmokeFailureClass::SetParamsFailed;
    } else if !start_dev_readiness.all_fetches_ready() {
        failure_class = UblkControlResizeSmokeFailureClass::DataQueueFetchesNotReady;
    } else {
        match start_dev_result {
            Some(Ok(outcome)) => {
                start_dev_target_dev_id = Some(outcome.dev_id);
                start_dev_uring_cmd_completed = true;
                match update_size_result {
                    Some(Ok(outcome)) => {
                        update_size_attempted = true;
                        update_size_completed = true;
                        update_size_outcome = Some(outcome);
                        failure_class =
                            UblkControlResizeSmokeFailureClass::UpdateSizeUringCmdCompleted;
                    }
                    Some(Err(error)) => {
                        update_size_attempted = true;
                        update_size_errno = error.errno();
                        update_size_error = Some(error);
                        failure_class = UblkControlResizeSmokeFailureClass::UpdateSizeFailed;
                    }
                    None => {
                        failure_class = UblkControlResizeSmokeFailureClass::UpdateSizeFailed;
                    }
                }
            }
            Some(Err(_)) => {
                failure_class = UblkControlResizeSmokeFailureClass::StartDevFailed;
            }
            None => {
                failure_class = UblkControlResizeSmokeFailureClass::StartDevFailed;
            }
        }
    }

    ublk_device_pair_deleted = del_dev_result.as_ref().is_some_and(|r| r.is_ok());

    Ok(UblkControlResizeSmokeReport {
        gate: BLOCK_VOLUME_UBLK_CONTROL_UPDATE_SIZE_GATE_OW_301Y,
        failure_class,
        start_dev_target_dev_id,
        start_dev_uring_cmd_completed,
        update_size_attempted,
        update_size_completed,
        update_size_errno,
        update_size_error,
        update_size_outcome,
        original_dev_sectors,
        resized_dev_sectors,
        ublk_device_pair_deleted,
        resize_supported: true,
        resize_refusal_reason: None,
        resize_refusal_guest_errno: None,
    })
}
