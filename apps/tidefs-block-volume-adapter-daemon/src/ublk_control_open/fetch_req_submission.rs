use super::*;

pub fn run_ublk_data_queue_fetch_req_submission_boundary(
) -> Result<UblkDataQueueFetchReqSubmissionReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    let mut add_dev_result = None;
    let mut data_queue_input = None;
    let mut data_queue_open_result = None;
    let mut fetch_req_submission_result = None;
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
                            Ok(mut runtime) => {
                                data_queue_open_result = Some(Ok(runtime.outcome().clone()));
                                fetch_req_submission_result =
                                    Some(submit_runtime_fetch_reqs_without_wait(&mut runtime));
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

    Ok(evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &inputs,
            probe_result,
            add_dev_input,
            add_dev_result,
            data_queue_input,
            data_queue_open_result,
            fetch_req_submission_result,
            del_dev_result,
        },
    ))
}
pub(crate) fn evaluate_ublk_data_queue_fetch_req_submission_boundary(
    input: UblkDataQueueFetchReqSubmissionBoundaryInput<'_>,
) -> UblkDataQueueFetchReqSubmissionReport {
    let data_queue_open_report =
        evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
            inputs: input.inputs,
            probe_result: input.probe_result,
            add_dev_input: input.add_dev_input,
            add_dev_result: input.add_dev_result,
            data_queue_input: input.data_queue_input,
            data_queue_open_result: input.data_queue_open_result,
            del_dev_result: input.del_dev_result,
        });
    let fallback_open_outcome = data_queue_open_report
        .data_queue_outcome
        .clone()
        .unwrap_or_else(|| {
            UblkDataQueueRuntimeOpenOutcome::from_spec(&data_queue_open_report.data_queue_spec)
        });
    let fetch_req_submission_spec = build_fetch_req_submission_spec(&fallback_open_outcome)
        .unwrap_or_else(|_| {
            UblkDataQueueFetchReqSubmissionSpec::from_runtime_outcome(&fallback_open_outcome)
        });
    let mut fetch_req_submission_attempted = false;
    let mut fetch_req_submission_completed = false;
    let mut fetch_req_submitted = false;
    let fetch_req_failure_class;
    let mut fetch_req_errno = None;
    let mut fetch_req_outcome = None;
    let mut fetch_req_error = None;
    let mut submitted_fetch_commands = 0;
    let mut data_queue_runtime_live = data_queue_open_report.data_queue_opened;

    if !data_queue_open_report.data_queue_opened {
        fetch_req_failure_class = UblkDataQueueFetchReqSubmissionFailureClass::DataQueueNotOpen;
    } else {
        match input.fetch_req_submission_result {
            Some(Ok(outcome)) => {
                fetch_req_submission_attempted = true;
                fetch_req_submission_completed = true;
                fetch_req_submitted = outcome.submitted_fetch_commands > 0;
                fetch_req_failure_class = UblkDataQueueFetchReqSubmissionFailureClass::None;
                submitted_fetch_commands = outcome.submitted_fetch_commands;
                data_queue_runtime_live = outcome.data_queue_runtime_live;
                fetch_req_outcome = Some(outcome);
            }
            Some(Err(error)) => {
                fetch_req_submission_attempted = true;
                fetch_req_submitted = error.submitted_fetch_commands() > 0;
                fetch_req_failure_class =
                    UblkDataQueueFetchReqSubmissionFailureClass::from_runtime_error(error);
                fetch_req_errno = error.errno();
                submitted_fetch_commands = error.submitted_fetch_commands();
                data_queue_runtime_live =
                    !matches!(error, UblkDataQueueFetchReqSubmissionError::RuntimeNotLive);
                fetch_req_error = Some(error);
            }
            None => {
                fetch_req_failure_class =
                    UblkDataQueueFetchReqSubmissionFailureClass::FetchReqSubmissionNotAttemptedAfterOpen;
            }
        }
    }

    let fetch_req_readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(
        input.add_dev_input.nr_hw_queues,
        input.add_dev_input.queue_depth,
        submitted_fetch_commands,
        data_queue_runtime_live,
    );
    let start_dev_readiness = fetch_req_readiness.start_dev_readiness();

    UblkDataQueueFetchReqSubmissionReport {
        data_queue_open_report,
        fetch_req_submission_spec,
        fetch_req_submission_attempted,
        fetch_req_submission_completed,
        fetch_req_submitted,
        fetch_req_failure_class,
        fetch_req_errno,
        fetch_req_outcome,
        fetch_req_error,
        fetch_req_readiness,
        start_dev_readiness,
        start_dev_uring_cmd_attempted: false,
        io_uring_queue_processed: false,
        ublk_block_device_started: false,
    }
}
