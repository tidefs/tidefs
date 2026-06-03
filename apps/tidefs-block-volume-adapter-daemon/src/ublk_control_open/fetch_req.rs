use super::*;

pub fn run_ublk_data_queue_fetch_req_readiness_boundary(
) -> Result<UblkDataQueueFetchReqReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_req_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_req_spec = build_fetch_req_spec(fetch_req_input).map_err(|error| {
        AppError::new(format!(
            "build ublk FETCH_REQ readiness boundary: {}",
            error.as_str()
        ))
    })?;
    let fetch_req_readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
        false,
    );

    if inputs.should_attempt_control_open() {
        inputs.control_open_result = Some(open_control_device(&inputs.control_path));
    }

    Ok(evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &inputs,
        add_dev_input,
        fetch_req_spec,
        fetch_req_readiness,
    ))
}
pub(crate) fn evaluate_ublk_data_queue_fetch_req_readiness_boundary(
    inputs: &UblkControlOpenInputs,
    add_dev_input: UblkControlAddDevInput,
    fetch_req_spec: UblkDataQueueFetchReqSpec,
    fetch_req_readiness: UblkDataQueueFetchReqReadiness,
) -> UblkDataQueueFetchReqReport {
    let open_report = evaluate_ublk_control_open_preflight(inputs);
    let start_dev_readiness = fetch_req_readiness.start_dev_readiness();

    UblkDataQueueFetchReqReport {
        open_report,
        add_dev_input,
        fetch_req_spec,
        fetch_req_readiness,
        start_dev_readiness,
        data_queue_path: PathBuf::from("/dev/ublkc0"),
        data_queue_open_attempted: false,
        data_queue_opened: false,
        fetch_req_submission_attempted: false,
        fetch_req_submitted: false,
        data_queue_runtime_live: fetch_req_readiness.data_queue_runtime_live,
        ublk_block_device_started: false,
    }
}
