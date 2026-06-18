// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::*;

pub fn run_ublk_data_queue_open_boundary() -> Result<UblkDataQueueOpenReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    let mut add_dev_result = None;
    let mut data_queue_input = None;
    let mut data_queue_open_result = None;
    let mut del_dev_result = None;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

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
                        let current_data_queue_input =
                            UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                                outcome.dev_info.dev_id,
                                0,
                                add_dev_input.nr_hw_queues,
                                add_dev_input.queue_depth,
                            );
                        let data_queue_path =
                            ublk_data_queue_device_path(current_data_queue_input.dev_id);
                        let mut _data_queue_runtime = None;
                        match open_data_queue_runtime(&data_queue_path, current_data_queue_input) {
                            Ok(runtime) => {
                                data_queue_open_result = Some(Ok(runtime.outcome().clone()));
                                _data_queue_runtime = Some(runtime);
                            }
                            Err(error) => {
                                data_queue_open_result = Some(Err(error));
                            }
                        }
                        data_queue_input = Some(current_data_queue_input);

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

    Ok(evaluate_ublk_data_queue_open_boundary(
        UblkDataQueueOpenBoundaryInput {
            inputs: &inputs,
            probe_result,
            add_dev_input,
            add_dev_result,
            data_queue_input,
            data_queue_open_result,
            del_dev_result,
        },
    ))
}
pub(crate) fn evaluate_ublk_data_queue_open_boundary(
    input: UblkDataQueueOpenBoundaryInput<'_>,
) -> UblkDataQueueOpenReport {
    let UblkDataQueueOpenBoundaryInput {
        inputs,
        probe_result,
        add_dev_input,
        add_dev_result,
        data_queue_input,
        data_queue_open_result,
        del_dev_result,
    } = input;
    let add_dev_report =
        evaluate_ublk_control_add_dev_boundary(inputs, probe_result, add_dev_input, add_dev_result);
    let fallback_data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        add_dev_report
            .add_dev_outcome
            .map(|outcome| outcome.dev_info.dev_id)
            .unwrap_or(0),
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let data_queue_spec = UblkDataQueueRuntimeOpenSpec::from_input(
        data_queue_input.unwrap_or(fallback_data_queue_input),
    );
    let mut data_queue_target_dev_id = data_queue_input.map(|input| input.dev_id).or_else(|| {
        add_dev_report
            .add_dev_outcome
            .map(|outcome| outcome.dev_info.dev_id)
    });
    let mut data_queue_open_attempted = false;
    let mut data_queue_opened = false;
    let mut data_queue_failure_class = UblkDataQueueOpenFailureClass::HostNotAdmitted;
    let mut data_queue_errno = None;
    let mut data_queue_outcome = None;
    let mut data_queue_error = None;

    if !add_dev_report.readonly_report.open_report.control_opened {
        if add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
        {
            data_queue_failure_class = UblkDataQueueOpenFailureClass::ControlOpenFailed;
        }
    } else if !add_dev_report.readonly_report.probe_uring_cmd_completed {
        data_queue_failure_class = UblkDataQueueOpenFailureClass::FeatureProbeFailed;
    } else if !add_dev_report.add_dev_required_features_available {
        data_queue_failure_class = UblkDataQueueOpenFailureClass::RequiredFeaturesMissing;
    } else if !add_dev_report.add_dev_uring_cmd_completed {
        data_queue_failure_class = UblkDataQueueOpenFailureClass::AddDevFailed;
    } else if data_queue_target_dev_id.is_none() {
        data_queue_failure_class = UblkDataQueueOpenFailureClass::AddDevDidNotReturnDeviceId;
    } else if data_queue_input.is_none() {
        data_queue_failure_class =
            UblkDataQueueOpenFailureClass::DataQueueOpenNotAttemptedAfterAddDev;
    } else {
        match data_queue_open_result {
            Some(Ok(outcome)) => {
                data_queue_target_dev_id = Some(outcome.dev_id);
                data_queue_open_attempted = true;
                data_queue_opened = true;
                data_queue_failure_class = UblkDataQueueOpenFailureClass::None;
                data_queue_outcome = Some(outcome);
            }
            Some(Err(error)) => {
                data_queue_open_attempted = data_queue_open_attempted_for_error(error);
                data_queue_opened = data_queue_opened_before_error(error);
                data_queue_failure_class = UblkDataQueueOpenFailureClass::from_runtime_error(error);
                data_queue_errno = error.errno();
                data_queue_error = Some(error);
            }
            None => {
                data_queue_failure_class =
                    UblkDataQueueOpenFailureClass::DataQueueOpenNotAttemptedAfterAddDev;
            }
        }
    }

    let fetch_req_readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(
        input.add_dev_input.nr_hw_queues,
        input.add_dev_input.queue_depth,
        0,
        data_queue_opened,
    );
    let start_dev_readiness = fetch_req_readiness.start_dev_readiness();
    let del_dev_spec = UblkControlDelDevSpec::del_dev();
    let mut del_dev_target_dev_id = add_dev_report
        .add_dev_outcome
        .map(|outcome| outcome.dev_info.dev_id);
    let mut del_dev_uring_cmd_attempted = false;
    let mut del_dev_uring_cmd_completed = false;
    let mut del_dev_failure_class = UblkControlDelDevFailureClass::HostNotAdmitted;
    let mut del_dev_errno = None;
    let mut del_dev_outcome = None;
    let mut del_dev_error = None;

    if !add_dev_report.readonly_report.open_report.control_opened {
        if add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
        {
            del_dev_failure_class = UblkControlDelDevFailureClass::ControlOpenFailed;
        }
    } else if !add_dev_report.readonly_report.probe_uring_cmd_completed {
        del_dev_failure_class = UblkControlDelDevFailureClass::FeatureProbeFailed;
    } else if !add_dev_report.add_dev_required_features_available {
        del_dev_failure_class = UblkControlDelDevFailureClass::RequiredFeaturesMissing;
    } else if !add_dev_report.add_dev_uring_cmd_completed {
        del_dev_failure_class = UblkControlDelDevFailureClass::AddDevFailed;
    } else if del_dev_target_dev_id.is_none() {
        del_dev_failure_class = UblkControlDelDevFailureClass::AddDevDidNotReturnDeviceId;
    } else {
        match del_dev_result {
            Some(Ok(outcome)) => {
                del_dev_target_dev_id = Some(outcome.dev_id);
                del_dev_uring_cmd_attempted = true;
                del_dev_uring_cmd_completed = true;
                del_dev_failure_class = UblkControlDelDevFailureClass::None;
                del_dev_outcome = Some(outcome);
            }
            Some(Err(error)) => {
                del_dev_uring_cmd_attempted =
                    !matches!(error, UblkControlDelDevError::AutoDeviceId);
                del_dev_failure_class = UblkControlDelDevFailureClass::from_runtime_error(error);
                del_dev_errno = error.errno();
                del_dev_error = Some(error);
            }
            None => {
                del_dev_failure_class =
                    UblkControlDelDevFailureClass::DelDevNotAttemptedAfterAddDev;
            }
        }
    }

    let cleanup_attempted_after_add_dev =
        add_dev_report.add_dev_uring_cmd_completed && del_dev_uring_cmd_attempted;
    let cleanup_failed_after_add_dev =
        add_dev_report.add_dev_uring_cmd_completed && !del_dev_uring_cmd_completed;

    UblkDataQueueOpenReport {
        ublk_device_pair_created: add_dev_report.ublk_device_pair_created,
        add_dev_report,
        data_queue_spec,
        data_queue_target_dev_id,
        data_queue_open_attempted,
        data_queue_opened,
        data_queue_failure_class,
        data_queue_errno,
        data_queue_outcome,
        data_queue_error,
        fetch_req_readiness,
        start_dev_readiness,
        del_dev_spec,
        del_dev_target_dev_id,
        del_dev_uring_cmd_attempted,
        del_dev_uring_cmd_completed,
        del_dev_failure_class,
        del_dev_errno,
        del_dev_outcome,
        del_dev_error,
        cleanup_attempted_after_add_dev,
        cleanup_failed_after_add_dev,
        ublk_device_pair_deleted: del_dev_uring_cmd_completed,
        fetch_req_submitted: false,
        start_dev_uring_cmd_attempted: false,
        io_uring_queue_processed: false,
        ublk_block_device_started: false,
    }
}
