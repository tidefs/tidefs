// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(unused_assignments)]
use super::*;

#[allow(clippy::let_unit_value)]
pub fn run_ublk_control_start_dev_boundary() -> Result<UblkControlStartDevReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    let mut add_dev_result = None;
    let mut set_params_input = None;
    let mut set_params_result = None;
    let mut start_dev_input = None;
    let mut start_dev_result = None;
    let mut del_dev_result = None;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let mut start_dev_readiness = UblkControlStartDevReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
    );

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
                        if let Ok(parameter_report) = build_ublk_parameter_spec_report() {
                            let current_set_params_input =
                                UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                                    outcome.dev_info.dev_id,
                                    parameter_report.params,
                                );
                            let current_set_params_result =
                                issue_set_params(control_device.as_fd(), current_set_params_input);
                            if current_set_params_result.is_ok() {
                                // Open the data-queue runtime and submit FETCH_REQs
                                // so the kernel can deliver I/O descriptors after START_DEV.
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
                                start_dev_input = Some(current_start_dev_input);
                            }
                            set_params_result = Some(current_set_params_result);
                            set_params_input = Some(current_set_params_input);
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

    Ok(evaluate_ublk_control_start_dev_boundary(
        UblkControlStartDevBoundaryInput {
            inputs: &inputs,
            probe_result,
            add_dev_input,
            add_dev_result,
            set_params_input,
            set_params_result,
            start_dev_input,
            start_dev_result,
            start_dev_readiness,
            del_dev_result,
        },
    ))
}
pub(crate) fn evaluate_ublk_control_start_dev_boundary(
    input: UblkControlStartDevBoundaryInput<'_>,
) -> UblkControlStartDevReport {
    let UblkControlStartDevBoundaryInput {
        inputs,
        probe_result,
        add_dev_input,
        add_dev_result,
        set_params_input,
        set_params_result,
        start_dev_input,
        start_dev_result,
        start_dev_readiness,
        del_dev_result,
    } = input;
    let set_params_report = evaluate_ublk_control_set_params_boundary(
        inputs,
        probe_result,
        add_dev_input,
        add_dev_result,
        set_params_input,
        set_params_result,
        del_dev_result,
    );
    let start_dev_spec = UblkControlStartDevSpec::from_input(
        start_dev_input
            .unwrap_or_else(|| UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(0, 1)),
    );
    let mut start_dev_target_dev_id = start_dev_input
        .map(|input| input.dev_id)
        .or_else(|| {
            set_params_report
                .set_params_outcome
                .map(|outcome| outcome.dev_id)
        })
        .or(set_params_report.set_params_target_dev_id)
        .filter(|&id| id != u32::MAX);
    let mut start_dev_daemon_pid = start_dev_input.map(|input| input.ublksrv_pid);
    let mut start_dev_uring_cmd_attempted = false;
    let mut start_dev_uring_cmd_completed = false;
    let mut start_dev_failure_class = UblkControlStartDevFailureClass::HostNotAdmitted;
    let mut start_dev_errno = None;
    let mut start_dev_outcome = None;
    let mut start_dev_error = None;

    if !set_params_report
        .add_dev_report
        .readonly_report
        .open_report
        .control_opened
    {
        if set_params_report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
        {
            start_dev_failure_class = UblkControlStartDevFailureClass::ControlOpenFailed;
        }
    } else if !set_params_report
        .add_dev_report
        .readonly_report
        .probe_uring_cmd_completed
    {
        start_dev_failure_class = UblkControlStartDevFailureClass::FeatureProbeFailed;
    } else if !set_params_report
        .add_dev_report
        .add_dev_required_features_available
    {
        start_dev_failure_class = UblkControlStartDevFailureClass::RequiredFeaturesMissing;
    } else if !set_params_report.add_dev_report.add_dev_uring_cmd_completed {
        start_dev_failure_class = UblkControlStartDevFailureClass::AddDevFailed;
    } else if start_dev_target_dev_id.is_none() {
        start_dev_failure_class = UblkControlStartDevFailureClass::AddDevDidNotReturnDeviceId;
    } else if !set_params_report.set_params_projected {
        start_dev_failure_class = UblkControlStartDevFailureClass::ParameterBuildFailed;
    } else if !set_params_report.set_params_uring_cmd_completed {
        start_dev_failure_class = UblkControlStartDevFailureClass::SetParamsFailed;
    } else if !start_dev_readiness.all_fetches_ready() {
        start_dev_failure_class = UblkControlStartDevFailureClass::DataQueueFetchesNotReady;
    } else {
        match start_dev_result {
            Some(Ok(outcome)) => {
                start_dev_target_dev_id = Some(outcome.dev_id);
                start_dev_daemon_pid = Some(outcome.ublksrv_pid);
                start_dev_uring_cmd_attempted = true;
                start_dev_uring_cmd_completed = true;
                start_dev_failure_class = UblkControlStartDevFailureClass::None;
                start_dev_outcome = Some(outcome);
            }
            Some(Err(error)) => {
                start_dev_uring_cmd_attempted = !is_pre_submit_start_dev_error(error);
                start_dev_failure_class =
                    UblkControlStartDevFailureClass::from_runtime_error(error);
                start_dev_errno = error.errno();
                start_dev_error = Some(error);
            }
            None => {
                start_dev_failure_class =
                    UblkControlStartDevFailureClass::StartDevNotAttemptedAfterSetParams;
            }
        }
    }

    UblkControlStartDevReport {
        ublk_device_pair_created: set_params_report.ublk_device_pair_created,
        ublk_device_pair_deleted: set_params_report.ublk_device_pair_deleted,
        set_params_report,
        start_dev_spec,
        start_dev_target_dev_id,
        start_dev_daemon_pid,
        start_dev_readiness,
        start_dev_uring_cmd_attempted,
        start_dev_uring_cmd_completed,
        start_dev_failure_class,
        start_dev_errno,
        start_dev_outcome,
        start_dev_error,
        io_uring_queue_processed: false,
        ublk_block_device_started: start_dev_uring_cmd_completed,
    }
}
