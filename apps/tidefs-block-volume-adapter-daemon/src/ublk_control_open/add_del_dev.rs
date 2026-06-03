use super::*;

pub fn run_ublk_control_add_del_dev_boundary() -> Result<UblkControlAddDelDevReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    let mut add_dev_result = None;
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

    Ok(evaluate_ublk_control_add_del_dev_boundary(
        &inputs,
        probe_result,
        add_dev_input,
        add_dev_result,
        del_dev_result,
    ))
}
pub(crate) fn evaluate_ublk_control_add_del_dev_boundary(
    inputs: &UblkControlOpenInputs,
    probe_result: Option<Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError>>,
    add_dev_input: UblkControlAddDevInput,
    add_dev_result: Option<Result<UblkControlAddDevOutcome, UblkControlAddDevError>>,
    del_dev_result: Option<Result<UblkControlDelDevOutcome, UblkControlDelDevError>>,
) -> UblkControlAddDelDevReport {
    let add_dev_report =
        evaluate_ublk_control_add_dev_boundary(inputs, probe_result, add_dev_input, add_dev_result);
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

    UblkControlAddDelDevReport {
        ublk_device_pair_created: add_dev_report.ublk_device_pair_created,
        add_dev_report,
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
        io_uring_queue_processed: false,
        ublk_block_device_started: false,
    }
}
