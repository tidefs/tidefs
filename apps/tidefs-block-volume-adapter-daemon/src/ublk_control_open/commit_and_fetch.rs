// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::*;

pub fn run_ublk_data_queue_commit_and_fetch_boundary(
) -> Result<UblkDataQueueCommitAndFetchReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let mut probe_result = None;
    let mut add_dev_result = None;
    let mut data_queue_input = None;
    let mut data_queue_open_result = None;
    let mut fetch_req_submission_result = None;
    let mut commit_and_fetch_input = None;
    let mut commit_and_fetch_readiness = None;
    let mut commit_and_fetch_result = None;
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
                                let current_fetch_result =
                                    submit_runtime_fetch_reqs_without_wait(&mut runtime);
                                match current_fetch_result {
                                    Ok(fetch_outcome) => {
                                        let input =
                                            UblkDataQueueCommitAndFetchInput::completed_user_copy(
                                                fetch_outcome.q_id,
                                                fetch_outcome.first_submitted_tag.unwrap_or(0),
                                                fetch_outcome.nr_hw_queues,
                                                fetch_outcome.queue_depth,
                                            );
                                        let readiness =
                                            UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
                                            fetch_outcome,
                                            false,
                                            true,
                                        );
                                        commit_and_fetch_result =
                                            Some(submit_runtime_commit_and_fetch_without_wait(
                                                &mut runtime,
                                                input,
                                                readiness,
                                            ));
                                        commit_and_fetch_input = Some(input);
                                        commit_and_fetch_readiness = Some(readiness);
                                        fetch_req_submission_result = Some(Ok(fetch_outcome));
                                    }
                                    Err(error) => {
                                        fetch_req_submission_result = Some(Err(error));
                                    }
                                }
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

    Ok(evaluate_ublk_data_queue_commit_and_fetch_boundary(
        UblkDataQueueCommitAndFetchEvaluation {
            inputs: &inputs,
            probe_result,
            add_dev_input,
            add_dev_result,
            data_queue_input,
            data_queue_open_result,
            fetch_req_submission_result,
            commit_and_fetch_input,
            commit_and_fetch_readiness,
            commit_and_fetch_result,
            del_dev_result,
        },
    ))
}
pub(crate) fn evaluate_ublk_data_queue_commit_and_fetch_boundary(
    evaluation: UblkDataQueueCommitAndFetchEvaluation<'_>,
) -> UblkDataQueueCommitAndFetchReport {
    let fetch_req_report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: evaluation.inputs,
            probe_result: evaluation.probe_result,
            add_dev_input: evaluation.add_dev_input,
            add_dev_result: evaluation.add_dev_result,
            data_queue_input: evaluation.data_queue_input,
            data_queue_open_result: evaluation.data_queue_open_result,
            fetch_req_submission_result: evaluation.fetch_req_submission_result,
            del_dev_result: evaluation.del_dev_result,
        },
    );
    let fallback_commit_input = fetch_req_report
        .fetch_req_outcome
        .map(|outcome| {
            UblkDataQueueCommitAndFetchInput::completed_user_copy(
                outcome.q_id,
                outcome.first_submitted_tag.unwrap_or(0),
                outcome.nr_hw_queues,
                outcome.queue_depth,
            )
        })
        .unwrap_or_else(|| {
            UblkDataQueueCommitAndFetchInput::completed_user_copy(
                fetch_req_report.fetch_req_submission_spec.q_id,
                fetch_req_report.fetch_req_submission_spec.first_tag,
                fetch_req_report.fetch_req_submission_spec.nr_hw_queues,
                fetch_req_report.fetch_req_submission_spec.queue_depth,
            )
        });
    let commit_and_fetch_input = evaluation
        .commit_and_fetch_input
        .unwrap_or(fallback_commit_input);
    let commit_and_fetch_spec = build_commit_and_fetch_spec(commit_and_fetch_input)
        .unwrap_or_else(|_| UblkDataQueueCommitAndFetchSpec::from_input(commit_and_fetch_input));
    let fallback_readiness = fetch_req_report
        .fetch_req_outcome
        .map(|outcome| {
            UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
                outcome, false, true,
            )
        })
        .unwrap_or(UblkDataQueueCommitAndFetchReadiness {
            data_queue_runtime_live: fetch_req_report.fetch_req_readiness.data_queue_runtime_live,
            fetched_request_available: false,
            completion_result_ready: false,
        });
    let commit_and_fetch_readiness = evaluation
        .commit_and_fetch_readiness
        .unwrap_or(fallback_readiness);
    let mut commit_and_fetch_attempted = false;
    let mut commit_and_fetch_completed = false;
    let mut commit_and_fetch_submitted = false;
    let commit_and_fetch_failure_class;
    let mut commit_and_fetch_errno = None;
    let mut commit_and_fetch_outcome = None;
    let mut commit_and_fetch_error = None;

    if !fetch_req_report.fetch_req_submission_completed {
        commit_and_fetch_failure_class = UblkDataQueueCommitAndFetchFailureClass::FetchReqNotReady;
    } else {
        match evaluation.commit_and_fetch_result {
            Some(Ok(outcome)) => {
                commit_and_fetch_attempted = true;
                commit_and_fetch_completed = true;
                commit_and_fetch_submitted = true;
                commit_and_fetch_failure_class = UblkDataQueueCommitAndFetchFailureClass::None;
                commit_and_fetch_outcome = Some(outcome);
            }
            Some(Err(error)) => {
                commit_and_fetch_attempted = !is_pre_submit_commit_and_fetch_error(error);
                commit_and_fetch_failure_class =
                    UblkDataQueueCommitAndFetchFailureClass::from_runtime_error(error);
                commit_and_fetch_errno = error.errno();
                commit_and_fetch_error = Some(error);
            }
            None => {
                commit_and_fetch_failure_class =
                    UblkDataQueueCommitAndFetchFailureClass::CommitAndFetchNotAttemptedAfterFetch;
            }
        }
    }

    UblkDataQueueCommitAndFetchReport {
        fetch_req_report,
        commit_and_fetch_spec,
        commit_and_fetch_readiness,
        commit_and_fetch_attempted,
        commit_and_fetch_completed,
        commit_and_fetch_submitted,
        commit_and_fetch_failure_class,
        commit_and_fetch_errno,
        commit_and_fetch_outcome,
        commit_and_fetch_error,
        start_dev_uring_cmd_attempted: false,
        io_uring_queue_processed: false,
        ublk_block_device_started: false,
    }
}
