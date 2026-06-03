use super::*;

pub fn run_ublk_control_add_dev_boundary() -> Result<UblkControlAddDevReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    let mut add_dev_result = None;
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
                    add_dev_result = Some(issue_add_dev(control_device.as_fd(), add_dev_input));
                }
                probe_result = Some(current_probe_result);
            }
            Err(error_class) => {
                inputs.control_open_result = Some(Err(error_class));
            }
        }
    }

    Ok(evaluate_ublk_control_add_dev_boundary(
        &inputs,
        probe_result,
        add_dev_input,
        add_dev_result,
    ))
}
pub(crate) fn evaluate_ublk_control_add_dev_boundary(
    inputs: &UblkControlOpenInputs,
    probe_result: Option<Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError>>,
    add_dev_input: UblkControlAddDevInput,
    add_dev_result: Option<Result<UblkControlAddDevOutcome, UblkControlAddDevError>>,
) -> UblkControlAddDevReport {
    let readonly_report = evaluate_ublk_control_readonly_probe(inputs, probe_result);
    let add_dev_spec = UblkControlAddDevSpec::from_input(add_dev_input);
    let mut add_dev_uring_cmd_attempted = false;
    let mut add_dev_uring_cmd_completed = false;
    let mut add_dev_failure_class = UblkControlAddDevFailureClass::HostNotAdmitted;
    let mut add_dev_errno = None;
    let mut add_dev_outcome = None;
    let mut add_dev_error = None;
    let add_dev_required_features = TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES;
    let add_dev_required_features_available = readonly_report
        .probe_features
        .is_some_and(|features| features.contains(add_dev_required_features));

    if !readonly_report.open_report.control_opened {
        if readonly_report.open_report.control_open_attempted {
            add_dev_failure_class = UblkControlAddDevFailureClass::ControlOpenFailed;
        }
    } else if !readonly_report.probe_uring_cmd_completed {
        add_dev_failure_class = UblkControlAddDevFailureClass::FeatureProbeFailed;
    } else if !add_dev_required_features_available {
        add_dev_failure_class = UblkControlAddDevFailureClass::RequiredFeaturesMissing;
    } else {
        match add_dev_result {
            Some(Ok(outcome)) => {
                add_dev_uring_cmd_attempted = true;
                add_dev_uring_cmd_completed = true;
                add_dev_failure_class = UblkControlAddDevFailureClass::None;
                add_dev_outcome = Some(outcome);
            }
            Some(Err(error)) => {
                add_dev_uring_cmd_attempted = true;
                add_dev_failure_class = UblkControlAddDevFailureClass::from_runtime_error(error);
                add_dev_errno = error.errno();
                add_dev_error = Some(error);
            }
            None => {
                add_dev_failure_class =
                    UblkControlAddDevFailureClass::AddDevNotAttemptedAfterFeatureProbe;
            }
        }
    }

    UblkControlAddDevReport {
        readonly_report,
        add_dev_spec,
        add_dev_input,
        add_dev_uring_cmd_attempted,
        add_dev_uring_cmd_completed,
        add_dev_failure_class,
        add_dev_errno,
        add_dev_outcome,
        add_dev_error,
        add_dev_required_features,
        add_dev_required_features_available,
        ublk_device_pair_created: add_dev_uring_cmd_completed,
        io_uring_queue_processed: false,
        ublk_block_device_started: false,
    }
}
