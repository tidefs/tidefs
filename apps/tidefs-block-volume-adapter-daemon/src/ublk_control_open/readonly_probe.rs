use super::*;

pub fn run_ublk_control_readonly_probe() -> Result<UblkControlReadonlyProbeReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    if inputs.should_attempt_control_open() {
        match open_control_device_file(&inputs.control_path) {
            Ok(control_device) => {
                inputs.control_open_result = Some(Ok(()));
                probe_result = Some(issue_get_features(control_device.as_fd()));
            }
            Err(error_class) => {
                inputs.control_open_result = Some(Err(error_class));
            }
        }
    }
    Ok(evaluate_ublk_control_readonly_probe(&inputs, probe_result))
}
pub(crate) fn evaluate_ublk_control_readonly_probe(
    inputs: &UblkControlOpenInputs,
    probe_result: Option<Result<UblkControlGetFeaturesOutcome, UblkControlReadonlyProbeError>>,
) -> UblkControlReadonlyProbeReport {
    let open_report = evaluate_ublk_control_open_preflight(inputs);
    let probe_spec = UblkControlReadonlyProbeSpec::get_features();
    let mut probe_uring_cmd_attempted = false;
    let mut probe_uring_cmd_completed = false;
    let mut probe_failure_class = UblkControlReadonlyProbeFailureClass::HostNotAdmitted;
    let mut probe_errno = None;
    let mut probe_features = None;
    let mut probe_error = None;

    if open_report.control_opened {
        match probe_result {
            Some(Ok(outcome)) => {
                probe_uring_cmd_attempted = true;
                probe_uring_cmd_completed = true;
                probe_failure_class = UblkControlReadonlyProbeFailureClass::None;
                probe_features = Some(outcome.features);
            }
            Some(Err(error)) => {
                probe_uring_cmd_attempted = true;
                probe_failure_class =
                    UblkControlReadonlyProbeFailureClass::from_runtime_error(error);
                probe_errno = error.errno();
                probe_error = Some(error);
            }
            None => {
                probe_failure_class =
                    UblkControlReadonlyProbeFailureClass::ProbeNotAttemptedAfterOpen;
            }
        }
    } else if open_report.control_open_attempted {
        probe_failure_class = UblkControlReadonlyProbeFailureClass::ControlOpenFailed;
    }

    UblkControlReadonlyProbeReport {
        open_report,
        probe_spec,
        probe_uring_cmd_attempted,
        probe_uring_cmd_completed,
        probe_failure_class,
        probe_errno,
        probe_features,
        probe_error,
        mutating_ioctl_issued: false,
        io_uring_queue_processed: false,
        ublk_device_created: false,
    }
}
