// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::*;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::storage_backend::BlockVolumeStorageBackend;
use crate::ublk_completion::{UblkCompletionOperationKind, UblkCompletionTrace};
use crate::ublk_io_uring::UblkIoUringDispatcher;
use crate::LINUX_SECTOR_SIZE_BYTES;
use tidefs_block_volume_adapter_core::{
    BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeFileImageError,
    BlockVolumeGeometryRecord,
};
use tidefs_ublk_abi::{
    UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE,
    UBLK_IO_OP_WRITE_ZEROES, UBLK_IO_RES_OK,
};

struct UblkDataQueueIoLoopConfig {
    reconnect_dev_id: Option<u32>,
    max_iterations: Option<u32>,
    shutdown: Option<Arc<AtomicBool>>,
    io_uring_enabled: bool,
    nr_hw_queues: u16,
    queue_depth: u16,
    drain_deadline_secs: u64,
}

fn completed_read_payload<'a>(
    read_buf: &'a [u8],
    entry: &DataQueueWorkerResultEntry,
) -> Result<&'a [u8], DataQueueWorkerError> {
    if entry.byte_count > read_buf.len() {
        return Err(DataQueueWorkerError::PayloadBufferTooShort);
    }
    Ok(&read_buf[..entry.byte_count])
}

fn complete_read_data_queue_write(
    data_queue_runtime: &tidefs_block_volume_adapter_ublk_control_runtime::UblkDataQueueRuntime,
    q_id: u16,
    tag: u16,
    read_buf: &[u8],
    entry: DataQueueWorkerResultEntry,
) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
    let payload = completed_read_payload(read_buf, &entry)?;
    match data_queue_runtime.write_data_at(q_id, tag, payload) {
        Ok(written) if written == payload.len() => Ok(entry),
        Ok(_) | Err(_) => Err(DataQueueWorkerError::BackingStoreError(-libc::EIO)),
    }
}

const UBLK_DATA_QUEUE_SHUTDOWN_POLL: Duration = Duration::from_millis(100);

fn submit_data_queue_and_wait(
    data_queue_runtime: &mut tidefs_block_volume_adapter_ublk_control_runtime::UblkDataQueueRuntime,
    timeout: Option<Duration>,
) -> io::Result<usize> {
    if let Some(timeout) = timeout {
        let timeout = io_uring::types::Timespec::from(timeout);
        let args = io_uring::types::SubmitArgs::new().timespec(&timeout);
        match data_queue_runtime
            .ring_mut()
            .submitter()
            .submit_with_args(1, &args)
        {
            Ok(completions) => Ok(completions),
            Err(error) if error.raw_os_error() == Some(libc::ETIME) => Ok(0),
            Err(error) => Err(error),
        }
    } else {
        data_queue_runtime.ring_mut().submit_and_wait(1)
    }
}

pub fn run_ublk_live_device(
    reconnect_dev_id: Option<u32>,
    backend: &mut dyn BlockVolumeStorageBackend,
    shutdown: Arc<AtomicBool>,
    io_uring_enabled: bool,
    nr_hw_queues: u16,
    queue_depth: u16,
    drain_deadline_secs: u64,
) -> Result<UblkDataQueueIoLoopReport, AppError> {
    run_ublk_data_queue_io_loop_impl(
        backend,
        UblkDataQueueIoLoopConfig {
            reconnect_dev_id,
            max_iterations: None,
            shutdown: Some(shutdown),
            io_uring_enabled,
            nr_hw_queues,
            queue_depth,
            drain_deadline_secs,
        },
    )
}

pub fn run_ublk_data_queue_io_loop_boundary(
    reconnect_dev_id: Option<u32>,
    max_iterations: u32,
    backend: &mut dyn BlockVolumeStorageBackend,
    io_uring_enabled: bool,
    nr_hw_queues: u16,
    queue_depth: u16,
    drain_deadline_secs: u64,
) -> Result<UblkDataQueueIoLoopReport, AppError> {
    run_ublk_data_queue_io_loop_impl(
        backend,
        UblkDataQueueIoLoopConfig {
            reconnect_dev_id,
            max_iterations: Some(max_iterations),
            shutdown: None,
            io_uring_enabled,
            nr_hw_queues,
            queue_depth,
            drain_deadline_secs,
        },
    )
}

fn run_ublk_data_queue_io_loop_impl(
    backend: &mut dyn BlockVolumeStorageBackend,
    config: UblkDataQueueIoLoopConfig,
) -> Result<UblkDataQueueIoLoopReport, AppError> {
    let UblkDataQueueIoLoopConfig {
        reconnect_dev_id,
        max_iterations,
        shutdown,
        io_uring_enabled,
        nr_hw_queues,
        queue_depth,
        drain_deadline_secs,
    } = config;

    let mut inputs = UblkControlOpenInputs::read_host()?;
    let add_dev_input =
        UblkControlAddDevInput::from_nr_hw_queues_and_depth(nr_hw_queues, queue_depth);
    let mut completion_trace =
        UblkCompletionTrace::from_env(add_dev_input.nr_hw_queues, add_dev_input.queue_depth);
    #[allow(unused_assignments)]
    let mut start_dev_readiness = UblkControlStartDevReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
    );
    let mut start_dev_uring_cmd_completed = false;
    let mut ublk_device_pair_created = false;
    let mut ublk_device_pair_deleted = false;
    let mut io_loop_attempted = false;
    let mut io_loop_completed_iterations = 0u64;
    let mut io_loop_cqes_processed = 0u64;
    let mut io_loop_commit_and_fetch_submitted = 0u64;
    let mut io_loop_failure_class = UblkDataQueueIoLoopFailureClass::HostNotAdmitted;
    let mut io_loop_errno = None;
    let mut shutdown_graceful = false;
    let mut drain_cqes_processed: u64 = 0;
    let mut drain_iterations: u64 = 0;
    let mut drain_timed_out = false;
    let mut drain_hung_io_count: u64 = 0;
    let mut final_flush_completed = false;
    let mut stop_dev_uring_cmd_completed = false;
    let mut image_bytes_read: u64 = 0;
    let mut image_bytes_written: u64 = 0;
    let mut image_read_ops_completed: u64 = 0;
    let mut image_write_ops_completed: u64 = 0;
    let mut image_flush_ops: u64 = 0;
    let mut image_discard_ops: u64 = 0;
    let mut image_write_zeroes_ops: u64 = 0;
    let mut barrier_audit_flush_count: u64 = 0;
    let mut barrier_audit_fua_write_count: u64 = 0;
    let mut barrier_audit_failed_count: u64 = 0;
    let mut barrier_audit_total_entries: u64 = 0;
    let mut io_uring_queue_processed = false;
    let mut set_params_errno: Option<i32> = None;
    let mut data_queue_open_errno: Option<i32> = None;
    let mut data_queue_open_error_str: Option<String> = None;
    let mut feature_probe_attempted = false;
    let mut feature_probe_completed = false;
    let mut feature_mask = None;
    let mut required_features_available = false;
    let mut add_dev_attempted = false;
    let mut add_dev_completed = false;
    let mut add_dev_dev_id = None;
    let mut set_params_attempted = false;
    let mut set_params_completed = false;
    let mut set_params_block_size_bytes = None;
    let mut set_params_block_count = None;
    let mut set_params_dev_sectors = None;
    let mut data_queue_open_attempted = false;
    let mut data_queue_opened = false;
    let mut data_queue_path_for_artifact = None;
    let mut data_queue_runtime_live_at_start = false;
    let mut fetch_req_submission_attempted = false;
    let mut fetch_req_submission_completed = false;
    let mut fetch_req_required_commands = 0;
    let mut fetch_req_submitted_commands = 0;
    let mut fetch_req_first_qid = None;
    let mut fetch_req_first_tag = None;
    let mut fetch_req_last_qid = None;
    let mut fetch_req_last_tag = None;
    let mut start_dev_uring_cmd_attempted = false;
    let mut start_dev_refusal_class = Some("host_not_admitted".to_string());
    let mut start_dev_errno = None;
    let mut stop_dev_attempted = false;
    let mut del_dev_attempted = false;
    let mut del_dev_errno = None;

    // ── Device ID tracking: supports reconnect to existing devices ──
    let mut resolved_dev_id: Option<u32> = None;
    let mut from_reconnect = false;

    // Try reconnect first if a device ID was given
    if let Some(reconnect_id) = reconnect_dev_id {
        if inputs.should_attempt_control_open() {
            match open_control_device_file(&inputs.control_path) {
                Ok(ctrl_dev) => {
                    inputs.control_open_result = Some(Ok(()));
                    let start_input = tidefs_block_volume_adapter_ublk_control_runtime::UblkControlStartUserRecoveryInput::from_kernel_dev_id(reconnect_id);
                    match tidefs_block_volume_adapter_ublk_control_runtime::issue_start_user_recovery(ctrl_dev.as_fd(), start_input) {
                        Ok(outcome) => {
                            eprintln!("ublk-serve: reconnect START_USER_RECOVERY ok dev={}", outcome.dev_id);
                            resolved_dev_id = Some(outcome.dev_id);
                            from_reconnect = true;
                        }
                        Err(e) => {
                            eprintln!("ublk-serve: START_USER_RECOVERY refused ({}), falling back", e.as_str());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("ublk-serve: open control failed ({e:?}), falling back");
                }
            }
        }
    }

    if inputs.should_attempt_control_open() {
        match open_control_device_file(&inputs.control_path) {
            Ok(control_device) => {
                inputs.control_open_result = Some(Ok(()));
                feature_probe_attempted = true;
                let current_probe_result = issue_get_features(control_device.as_fd());
                match &current_probe_result {
                    Ok(outcome) => {
                        feature_probe_completed = true;
                        feature_mask = Some(outcome.features.bits());
                        required_features_available = outcome
                            .features
                            .contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES);
                    }
                    Err(error) => {
                        io_loop_failure_class = UblkDataQueueIoLoopFailureClass::FeatureProbeFailed;
                        start_dev_refusal_class = Some(error.as_str().to_string());
                    }
                }
                if current_probe_result.as_ref().is_ok_and(|outcome| {
                    outcome
                        .features
                        .contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES)
                }) {
                    add_dev_attempted = !from_reconnect;
                    let current_add_dev_result = if from_reconnect {
                        // Already have dev_id from reconnect, skip ADD_DEV
                        Ok(tidefs_block_volume_adapter_ublk_control_runtime::UblkControlAddDevOutcome::from_dev_info(
                            tidefs_ublk_abi::UblkSrvCtrlDevInfo {
                                dev_id: resolved_dev_id.unwrap_or(0),
                                nr_hw_queues: add_dev_input.nr_hw_queues,
                                queue_depth: add_dev_input.queue_depth,
                                max_io_buf_bytes: add_dev_input.max_io_buf_bytes,
                                ..Default::default()
                            }
                        ))
                    } else {
                        issue_add_dev(control_device.as_fd(), add_dev_input)
                    };
                    if let Ok(add_outcome) = &current_add_dev_result {
                        add_dev_completed = true;
                        add_dev_dev_id = Some(add_outcome.dev_info.dev_id);
                        ublk_device_pair_created = true;
                        let geometry = backend.geometry();
                        if let Ok(parameter_report) = build_ublk_parameter_spec_report_with_geometry(
                            geometry,
                            nr_hw_queues,
                            queue_depth,
                        ) {
                            set_params_block_size_bytes =
                                u64::try_from(geometry.block_size_bytes).ok();
                            set_params_block_count = u64::try_from(geometry.block_count).ok();
                            set_params_dev_sectors =
                                Some(parameter_report.params.basic.dev_sectors);
                            let set_params_input =
                                UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                                    add_outcome.dev_info.dev_id,
                                    parameter_report.params,
                                );
                            set_params_attempted = true;
                            let set_params_result =
                                issue_set_params(control_device.as_fd(), set_params_input);
                            if set_params_result.is_ok() {
                                set_params_completed = true;
                                // Open data queue runtime
                                let data_queue_input =
                                    UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                                        add_outcome.dev_info.dev_id,
                                        0,
                                        add_dev_input.nr_hw_queues,
                                        add_dev_input.queue_depth,
                                    );
                                let data_queue_path =
                                    ublk_data_queue_device_path(data_queue_input.dev_id);
                                data_queue_open_attempted = true;
                                data_queue_path_for_artifact = Some(data_queue_path.clone());
                                let data_queue_open_result =
                                    open_data_queue_runtime(&data_queue_path, data_queue_input);
                                if let Ok(mut data_queue_runtime) = data_queue_open_result {
                                    data_queue_opened = true;
                                    // Submit FETCH_REQs
                                    fetch_req_submission_attempted = true;
                                    fetch_req_required_commands =
                                        u32::from(add_dev_input.nr_hw_queues)
                                            * u32::from(add_dev_input.queue_depth);
                                    let fetch_submission_result =
                                        submit_runtime_all_queues_fetch_reqs_without_wait(
                                            &mut data_queue_runtime,
                                        );
                                    if let Ok(fetch_outcome) = &fetch_submission_result {
                                        fetch_req_submission_completed = true;
                                        fetch_req_required_commands =
                                            fetch_outcome.all_queues_required_fetch_commands;
                                        fetch_req_submitted_commands =
                                            fetch_outcome.submitted_fetch_commands;
                                        data_queue_runtime_live_at_start =
                                            fetch_outcome.data_queue_runtime_live;
                                        if fetch_outcome.submitted_fetch_commands
                                            >= fetch_outcome.all_queues_required_fetch_commands
                                            && fetch_outcome.all_queues_required_fetch_commands > 0
                                        {
                                            fetch_req_first_qid = Some(0);
                                            fetch_req_last_qid =
                                                Some(add_dev_input.nr_hw_queues - 1);
                                            fetch_req_first_tag = fetch_outcome.first_submitted_tag;
                                            fetch_req_last_tag = fetch_outcome.last_submitted_tag;
                                        }
                                        for qid in 0..add_dev_input.nr_hw_queues {
                                            for tag in 0..add_dev_input.queue_depth {
                                                completion_trace.record_fetch_submitted(qid, tag);
                                            }
                                        }
                                        start_dev_readiness = fetch_outcome.start_dev_readiness();
                                        if start_dev_readiness.all_fetches_ready() {
                                            // Submit START_DEV
                                            let daemon_pid = i32::try_from(std::process::id())
                                                .unwrap_or(i32::MAX);
                                            let start_dev_input =
                                                UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(
                                                    add_outcome.dev_info.dev_id,
                                                    daemon_pid,
                                                );
                                            start_dev_uring_cmd_attempted = true;
                                            let sd_result = if from_reconnect {
                                                let end_input = tidefs_block_volume_adapter_ublk_control_runtime::UblkControlEndUserRecoveryInput::from_kernel_dev_id(resolved_dev_id.unwrap_or(0));
                                                match tidefs_block_volume_adapter_ublk_control_runtime::issue_end_user_recovery(control_device.as_fd(), end_input) {
                                                    Ok(outcome) => {
                                                        eprintln!("ublk-serve: reconnect END_USER_RECOVERY ok dev={}", outcome.dev_id);
                                                        Ok(tidefs_block_volume_adapter_ublk_control_runtime::UblkControlStartDevOutcome::from_input(start_dev_input))
                                                    }
                                                    Err(e) => {
                                                        eprintln!("ublk-serve: END_USER_RECOVERY failed: {}", e.as_str());
                                                        Err(tidefs_block_volume_adapter_ublk_control_runtime::UblkControlStartDevError::UblkCommandErrno(e.errno().unwrap_or(-libc::EIO)))
                                                    }
                                                }
                                            } else {
                                                issue_start_dev(
                                                    control_device.as_fd(),
                                                    start_dev_input,
                                                    start_dev_readiness,
                                                )
                                            };
                                            if sd_result.is_ok() {
                                                start_dev_uring_cmd_completed = true;
                                                start_dev_refusal_class = None;
                                                io_loop_failure_class =
                                                    UblkDataQueueIoLoopFailureClass::None;
                                                // Live I/O loop: process CQEs and
                                                // submit COMMIT_AND_FETCH for each
                                                // incoming I/O request.
                                                io_loop_attempted = true;
                                                // Force io_uring task-work processing on the
                                                // data-queue ring before the I/O loop blocks in
                                                // submit_and_wait.  The partition-scan work
                                                // scheduled during START_DEV may already have
                                                // submitted I/O whose CQEs can be reaped now.
                                                // Any task-work callback (ublk_cmd_tw_cb) that
                                                // the kernel deferred will run inside submit().
                                                let _ = data_queue_runtime.ring_mut().submit();
                                                let mut data_workers: Vec<DataQueueWorker> = (0
                                                    ..add_dev_input.nr_hw_queues)
                                                    .map(|queue_id| {
                                                        DataQueueWorker::new(
                                                            queue_id,
                                                            backend.geometry(),
                                                        )
                                                    })
                                                    .collect();
                                                let mut io_uring_dispatcher: Option<
                                                    UblkIoUringDispatcher,
                                                > = if io_uring_enabled {
                                                    backend.as_raw_fd().and_then(|fd| {
                                                        UblkIoUringDispatcher::new(fd).ok()
                                                    })
                                                } else {
                                                    None
                                                };
                                                let mut iteration = 0u32;
                                                'io_loop: loop {
                                                    if let Some(ref shutdown_flag) = shutdown {
                                                        if shutdown_flag.load(Ordering::Relaxed) {
                                                            eprintln!("tidefs ublk-serve: shutdown signal received, draining I/O loop");
                                                            io_loop_failure_class =
                                                                UblkDataQueueIoLoopFailureClass::None;
                                                            shutdown_graceful = true;
                                                            break 'io_loop;
                                                        }
                                                    }
                                                    if let Some(max) = max_iterations {
                                                        if iteration >= max {
                                                            break 'io_loop;
                                                        }
                                                    }
                                                    iteration += 1;
                                                    io_loop_completed_iterations =
                                                        u64::from(iteration);
                                                    match submit_data_queue_and_wait(
                                                        &mut data_queue_runtime,
                                                        shutdown
                                                            .as_ref()
                                                            .map(|_| UBLK_DATA_QUEUE_SHUTDOWN_POLL),
                                                    ) {
                                                        Ok(_) => {}
                                                        Err(e) => {
                                                            io_loop_failure_class =
                                                                UblkDataQueueIoLoopFailureClass::IoLoopErrno;
                                                            io_loop_errno = e.raw_os_error();
                                                            break 'io_loop;
                                                        }
                                                    }
                                                    let mut pending_fetch_tags: Vec<(
                                                        u16,
                                                        u16,
                                                        bool,
                                                    )> = Vec::new();
                                                    {
                                                        while let Some(cqe) = data_queue_runtime
                                                            .ring_mut()
                                                            .completion()
                                                            .next()
                                                        {
                                                            io_loop_cqes_processed += 1;
                                                            let user_data = cqe.user_data();
                                                            if is_fetch_req_user_data(user_data) {
                                                                let (q_id, tag) =
                                                                    decode_fetch_req_user_data(
                                                                        user_data,
                                                                    );
                                                                if cqe.result() < 0 {
                                                                    completion_trace
                                                                        .record_fetch_cqe_error(
                                                                            q_id,
                                                                            tag,
                                                                            false,
                                                                            cqe.result(),
                                                                        );
                                                                    continue;
                                                                }
                                                                pending_fetch_tags
                                                                    .push((q_id, tag, false));
                                                            } else if is_commit_and_fetch_user_data(
                                                                user_data,
                                                            ) {
                                                                let (q_id, tag) =
                                                                    decode_commit_and_fetch_user_data(
                                                                        user_data,
                                                                    );
                                                                if cqe.result() < 0 {
                                                                    completion_trace
                                                                        .record_fetch_cqe_error(
                                                                            q_id,
                                                                            tag,
                                                                            true,
                                                                            cqe.result(),
                                                                        );
                                                                    continue;
                                                                }
                                                                completion_trace
                                                                    .record_completion_cqe(
                                                                        q_id, tag,
                                                                    );
                                                                pending_fetch_tags
                                                                    .push((q_id, tag, true));
                                                            }
                                                        }
                                                    }
                                                    for (q_id, tag, is_reissued_fetch) in
                                                        pending_fetch_tags
                                                    {
                                                        let result: i32;
                                                        if let Some(worker) =
                                                            data_workers.get_mut(usize::from(q_id))
                                                        {
                                                            if let Some(io_desc) =
                                                                data_queue_runtime
                                                                    .io_desc_for_queue(q_id, tag)
                                                                    .copied()
                                                            {
                                                                completion_trace
                                                                    .record_request_fetched(
                                                                        q_id,
                                                                        tag,
                                                                        UblkCompletionOperationKind::from_ublk_op(io_desc.op()),
                                                                        is_reissued_fetch,
                                                                    );
                                                                let before_bytes_read =
                                                                    worker.bytes_read;
                                                                let before_bytes_written =
                                                                    worker.bytes_written;
                                                                let before_read_ops =
                                                                    worker.read_ops;
                                                                let before_write_ops =
                                                                    worker.write_ops;
                                                                let before_flush_ops =
                                                                    worker.flush_ops;
                                                                let before_discard_ops =
                                                                    worker.discard_ops;
                                                                let before_write_zeroes_ops =
                                                                    worker.write_zeroes_ops;

                                                                let worker_result = if let Some(
                                                                    ref mut dispatcher,
                                                                ) =
                                                                    io_uring_dispatcher
                                                                {
                                                                    io_uring_queue_processed = true;
                                                                    match io_desc.op() {
                                                                        UBLK_IO_OP_READ => {
                                                                            let byte_count = worker.read_buffer_size(&io_desc); // rounds to block boundary
                                                                            let mut read_buf = vec![0u8; byte_count];
                                                                            let mut result = worker.process_one_io_uring(dispatcher, tag, &io_desc, Some(&mut read_buf), None);
                                                                            result = match result {
                                                                                Ok(entry) if entry.completion_class == BlockVolumeCompletionClass::Completed => complete_read_data_queue_write(&data_queue_runtime, q_id, tag, &read_buf, entry),
                                                                                other => other,
                                                                            };
                                                                        result
                                                                        }
                                                                        UBLK_IO_OP_WRITE => {
                                                                            let byte_count = worker.read_buffer_size(&io_desc); // rounds to block boundary
                                                                            let mut write_buf = vec![0u8; byte_count];
                                                                            match data_queue_runtime.read_data_at(q_id, tag, &mut write_buf) {
                                                                                Ok(_) => worker.process_one_io_uring(dispatcher, tag, &io_desc, None, Some(&write_buf)),
                                                                                Err(_) => Err(DataQueueWorkerError::BackingStoreError(-libc::EIO)),
                                                                            }
                                                                        }
                                                                        UBLK_IO_OP_FLUSH => worker
                                                                            .process_one_io_uring(
                                                                                dispatcher, tag, &io_desc,
                                                                                None, None,
                                                                            ),
                                                                        UBLK_IO_OP_DISCARD => worker
                                                                            .process_one_io_uring(
                                                                                dispatcher, tag, &io_desc,
                                                                                None, None,
                                                                            ),
                                                                        UBLK_IO_OP_WRITE_ZEROES => worker
                                                                            .process_one_io_uring(
                                                                                dispatcher, tag, &io_desc,
                                                                                None, None,
                                                                            ),
                                                                        // Unsupported io_uring ops fall back to sync
                                                                        _ => worker.process_one_with_buffers(
                                                                            backend, tag, &io_desc,
                                                                            None, None,
                                                                        ),
                                                                    }
                                                                } else {
                                                                    match io_desc
                                                                        .op()
                                                                    {
                                                                        UBLK_IO_OP_READ => {
                                                                            let byte_count = worker.read_buffer_size(&io_desc); // rounds to block boundary
                                                                            let mut read_buf = vec![0u8; byte_count];
                                                                            let mut result = worker.process_one_with_buffers(backend, tag, &io_desc, Some(&mut read_buf), None);
                                                                            result = match result {
                                                                                Ok(entry) if entry.completion_class == BlockVolumeCompletionClass::Completed => complete_read_data_queue_write(&data_queue_runtime, q_id, tag, &read_buf, entry),
                                                                                other => other,
                                                                            };
                                                                        result
                                                                        }
                                                                        UBLK_IO_OP_WRITE => {
                                                                            let byte_count = worker.read_buffer_size(&io_desc); // rounds to block boundary
                                                                            let mut write_buf = vec![0u8; byte_count];
                                                                            match data_queue_runtime.read_data_at(q_id, tag, &mut write_buf) {
                                                                                Ok(_) => worker.process_one_with_buffers(backend, tag, &io_desc, None, Some(&write_buf)),
                                                                                Err(_) => Err(DataQueueWorkerError::BackingStoreError(-libc::EIO)),
                                                                            }
                                                                        }
                                                                        _ => worker
                                                                            .process_one_with_buffers(
                                                                                backend, tag, &io_desc,
                                                                                None, None,
                                                                            ),
                                                                    }
                                                                };

                                                                result = match worker_result {
                                                                    Ok(entry) => {
                                                                        entry.io_cmd.result
                                                                    }
                                                                    Err(error) => {
                                                                        error.linux_errno()
                                                                    }
                                                                };

                                                                image_bytes_read += worker
                                                                    .bytes_read
                                                                    .saturating_sub(
                                                                        before_bytes_read,
                                                                    );
                                                                image_bytes_written += worker
                                                                    .bytes_written
                                                                    .saturating_sub(
                                                                        before_bytes_written,
                                                                    );
                                                                image_read_ops_completed +=
                                                                    worker.read_ops.saturating_sub(
                                                                        before_read_ops,
                                                                    );
                                                                image_write_ops_completed += worker
                                                                    .write_ops
                                                                    .saturating_sub(
                                                                        before_write_ops,
                                                                    );
                                                                image_flush_ops += worker
                                                                    .flush_ops
                                                                    .saturating_sub(
                                                                        before_flush_ops,
                                                                    );
                                                                image_discard_ops += worker
                                                                    .discard_ops
                                                                    .saturating_sub(
                                                                        before_discard_ops,
                                                                    );
                                                                image_write_zeroes_ops += worker
                                                                    .write_zeroes_ops
                                                                    .saturating_sub(
                                                                        before_write_zeroes_ops,
                                                                    );
                                                            } else {
                                                                result = -libc::EINVAL;
                                                            }
                                                        } else {
                                                            result = -libc::EINVAL;
                                                        }

                                                        let commit_input =
                                                            UblkDataQueueCommitAndFetchInput {
                                                                q_id,
                                                                tag,
                                                                nr_hw_queues: add_dev_input
                                                                    .nr_hw_queues,
                                                                queue_depth: add_dev_input
                                                                    .queue_depth,
                                                                result,
                                                                addr_or_zone_append_lba: 0,
                                                            };
                                                        let readiness =
                                                            UblkDataQueueCommitAndFetchReadiness {
                                                                data_queue_runtime_live: true,
                                                                fetched_request_available: true,
                                                                completion_result_ready: true,
                                                            };
                                                        match submit_runtime_commit_and_fetch_without_wait(
                                                            &mut data_queue_runtime,
                                                            commit_input,
                                                            readiness,
                                                        ) {
                                                            Ok(_) => {
                                                                completion_trace
                                                                    .record_completion_submitted(
                                                                        q_id, tag, result,
                                                                    );
                                                                io_loop_commit_and_fetch_submitted += 1;
                                                            }
                                                            Err(_) => {
                                                                completion_trace
                                                                    .record_completion_submit_failed(
                                                                        q_id, tag, result,
                                                                    );
                                                                break 'io_loop;
                                                            }
                                                        }
                                                    }
                                                    if !data_queue_path.exists() {
                                                        break 'io_loop;
                                                    }
                                                }

                                                // ── Shutdown drain and final flush ──────────
                                                if shutdown_graceful
                                                    && start_dev_uring_cmd_completed
                                                {
                                                    let drain_deadline = std::time::Instant::now()
                                                        + std::time::Duration::from_secs(
                                                            drain_deadline_secs,
                                                        );
                                                    eprintln!("tidefs ublk-serve: shutdown phase: draining in-flight I/O (deadline {drain_deadline_secs}s)");
                                                    'drain: loop {
                                                        if std::time::Instant::now()
                                                            >= drain_deadline
                                                        {
                                                            drain_timed_out = true;
                                                            eprintln!(
                                                                "tidefs ublk-serve: shutdown drain deadline expired"
                                                            );
                                                            break 'drain;
                                                        }
                                                        match submit_data_queue_and_wait(
                                                            &mut data_queue_runtime,
                                                            Some(UBLK_DATA_QUEUE_SHUTDOWN_POLL),
                                                        ) {
                                                            Ok(_) => {
                                                                drain_iterations += 1;
                                                            }
                                                            Err(_) => {
                                                                break 'drain;
                                                            }
                                                        }
                                                        let mut pending_tags: Vec<(
                                                            u16,
                                                            u16,
                                                            bool,
                                                        )> = Vec::new();
                                                        {
                                                            while let Some(cqe) = data_queue_runtime
                                                                .ring_mut()
                                                                .completion()
                                                                .next()
                                                            {
                                                                drain_cqes_processed += 1;
                                                                let user_data = cqe.user_data();
                                                                if is_fetch_req_user_data(user_data)
                                                                {
                                                                    let (q_id, tag) =
                                                                        decode_fetch_req_user_data(
                                                                            user_data,
                                                                        );
                                                                    if cqe.result() < 0 {
                                                                        completion_trace
                                                                            .record_fetch_cqe_error(
                                                                                q_id,
                                                                                tag,
                                                                                false,
                                                                                cqe.result(),
                                                                            );
                                                                        continue;
                                                                    }
                                                                    pending_tags
                                                                        .push((q_id, tag, false));
                                                                } else if is_commit_and_fetch_user_data(user_data)
                                                                {
                                                                    let (q_id, tag) =
                                                                        decode_commit_and_fetch_user_data(
                                                                            user_data,
                                                                        );
                                                                    if cqe.result() < 0 {
                                                                        completion_trace
                                                                            .record_fetch_cqe_error(
                                                                                q_id,
                                                                                tag,
                                                                                true,
                                                                                cqe.result(),
                                                                            );
                                                                        continue;
                                                                    }
                                                                    completion_trace
                                                                        .record_completion_cqe(
                                                                            q_id, tag,
                                                                        );
                                                                    pending_tags
                                                                        .push((q_id, tag, true));
                                                                }
                                                            }
                                                        }
                                                        if pending_tags.is_empty() {
                                                            break 'drain;
                                                        }
                                                        for (q_id, tag, is_reissued_fetch) in
                                                            pending_tags
                                                        {
                                                            let result: i32;
                                                            if let Some(ref mut worker) =
                                                                data_workers
                                                                    .get_mut(usize::from(q_id))
                                                            {
                                                                if let Some(io_desc) =
                                                                    data_queue_runtime
                                                                        .io_desc_for_queue(
                                                                            q_id, tag,
                                                                        )
                                                                        .copied()
                                                                {
                                                                    completion_trace
                                                                        .record_request_fetched(
                                                                            q_id,
                                                                            tag,
                                                                            UblkCompletionOperationKind::from_ublk_op(io_desc.op()),
                                                                            is_reissued_fetch,
                                                                        );
                                                                    let worker_result =
                                                                        if let Some(
                                                                            ref mut dispatcher,
                                                                        ) = io_uring_dispatcher
                                                                        {
                                                                            io_uring_queue_processed = true;
                                                                            match io_desc.op() {
                                                                            UBLK_IO_OP_READ => {
                                                                                let geometry = backend.geometry();
                                                                                let sectors_per_block = geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
                                                                                let sector_count = io_desc.count_or_zones as usize;
                                                                                let block_count = sector_count.div_ceil(sectors_per_block);
                                                                                let byte_count = block_count * geometry.block_size_bytes;
                                                                                let mut read_buf = vec![0u8; byte_count];
                                                                                let mut result = worker.process_one_io_uring(dispatcher, tag, &io_desc, Some(&mut read_buf), None);
                                                                                result = match result {
                                                                                    Ok(entry) if entry.completion_class == BlockVolumeCompletionClass::Completed => complete_read_data_queue_write(&data_queue_runtime, q_id, tag, &read_buf, entry),
                                                                                    other => other,
                                                                                };
                                                                            result
                                                                            }
                                                                            UBLK_IO_OP_WRITE => {
                                                                                let geometry = backend.geometry();
                                                                                let sectors_per_block = geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
                                                                                let sector_count = io_desc.count_or_zones as usize;
                                                                                let block_count = sector_count.div_ceil(sectors_per_block);
                                                                                let byte_count = block_count * geometry.block_size_bytes;
                                                                                let mut write_buf = vec![0u8; byte_count];
                                                                                match data_queue_runtime.read_data_at(q_id, tag, &mut write_buf) {
                                                                                    Ok(_) => worker.process_one_io_uring(dispatcher, tag, &io_desc, None, Some(&write_buf)),
                                                                                    Err(_) => Err(DataQueueWorkerError::BackingStoreError(-libc::EIO)),
                                                                                }
                                                                            }
                                                                            UBLK_IO_OP_FLUSH => worker.process_one_io_uring(dispatcher, tag, &io_desc, None, None),
                                                                            UBLK_IO_OP_DISCARD => worker.process_one_io_uring(dispatcher, tag, &io_desc, None, None),
                                                                            UBLK_IO_OP_WRITE_ZEROES => worker.process_one_io_uring(dispatcher, tag, &io_desc, None, None),
                                                                            _ => worker.process_one_with_buffers(backend, tag, &io_desc, None, None),
                                                                        }
                                                                        } else {
                                                                            // Non-io_uring path: use fd-backed read_data_at/write_data_at
                                                                            // for ublk I/O buffer data transfer (Linux 7.0 mmap is PROT_READ only).
                                                                            match io_desc.op() {
                                                                                UBLK_IO_OP_READ => {
                                                                                    let geometry = backend.geometry();
                                                                                    let sectors_per_block = geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
                                                                                    let sector_count = io_desc.count_or_zones as usize;
                                                                                    let block_count = sector_count.div_ceil(sectors_per_block);
                                                                                    let byte_count = block_count * geometry.block_size_bytes;
                                                                                    let mut read_buf = vec![0u8; byte_count];
                                                                                    let result = worker.process_one_with_buffers(backend, tag, &io_desc, Some(&mut read_buf), None);
                                                                                    match result {
                                                                                        Ok(entry) if entry.completion_class == BlockVolumeCompletionClass::Completed => complete_read_data_queue_write(&data_queue_runtime, q_id, tag, &read_buf, entry),
                                                                                        other => other,
                                                                                    }
                                                                                }
                                                                                UBLK_IO_OP_WRITE => {
                                                                                    let geometry = backend.geometry();
                                                                                    let sectors_per_block = geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
                                                                                    let sector_count = io_desc.count_or_zones as usize;
                                                                                    let block_count = sector_count.div_ceil(sectors_per_block);
                                                                                    let byte_count = block_count * geometry.block_size_bytes;
                                                                                    let mut write_buf = vec![0u8; byte_count];
                                                                                    match data_queue_runtime.read_data_at(q_id, tag, &mut write_buf) {
                                                                                        Ok(_) => worker.process_one_with_buffers(backend, tag, &io_desc, None, Some(&write_buf)),
                                                                                        Err(_) => Err(DataQueueWorkerError::BackingStoreError(-libc::EIO)),
                                                                                    }
                                                                                }
                                                                                UBLK_IO_OP_FLUSH => worker.process_one_with_buffers(backend, tag, &io_desc, None, None),
                                                                                UBLK_IO_OP_DISCARD => worker.process_one_with_buffers(backend, tag, &io_desc, None, None),
                                                                                UBLK_IO_OP_WRITE_ZEROES => worker.process_one_with_buffers(backend, tag, &io_desc, None, None),
                                                                                _ => worker.process_one_with_buffers(backend, tag, &io_desc, None, None),
                                                                            }
                                                                        };
                                                                    result = match worker_result {
                                                                        Ok(entry) => {
                                                                            entry.io_cmd.result
                                                                        }
                                                                        Err(error) => {
                                                                            error.linux_errno()
                                                                        }
                                                                    };
                                                                } else {
                                                                    result = -libc::EINVAL;
                                                                }
                                                            } else {
                                                                result = -libc::EINVAL;
                                                            }
                                                            let commit_input =
                                                                UblkDataQueueCommitAndFetchInput {
                                                                    q_id,
                                                                    tag,
                                                                    nr_hw_queues: add_dev_input
                                                                        .nr_hw_queues,
                                                                    queue_depth: add_dev_input
                                                                        .queue_depth,
                                                                    result,
                                                                    addr_or_zone_append_lba: 0,
                                                                };
                                                            let readiness = UblkDataQueueCommitAndFetchReadiness {
                                                                data_queue_runtime_live: true,
                                                                fetched_request_available: true,
                                                                completion_result_ready: true,
                                                            };
                                                            match submit_runtime_commit_and_fetch_without_wait(
                                                                &mut data_queue_runtime,
                                                                commit_input,
                                                                readiness,
                                                            ) {
                                                                Ok(_) => {
                                                                    completion_trace
                                                                        .record_completion_submitted(
                                                                            q_id, tag, result,
                                                                        );
                                                                }
                                                                Err(_) => {
                                                                    completion_trace
                                                                        .record_completion_submit_failed(
                                                                            q_id, tag, result,
                                                                        );
                                                                    break 'drain;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    // Final drain sweep via TargetResetGuard.
                                                    // Drain any remaining CQEs and verify in-flight reaches zero.
                                                    // Aggregate barrier audit counters from all workers.
                                                    for worker in &data_workers {
                                                        barrier_audit_flush_count +=
                                                            worker.barrier_audit.flush_count;
                                                        barrier_audit_fua_write_count +=
                                                            worker.barrier_audit.fua_write_count;
                                                        barrier_audit_failed_count +=
                                                            worker.barrier_audit.failed_count;
                                                        barrier_audit_total_entries +=
                                                            worker.barrier_audit.total_entries();
                                                    }
                                                    let remaining = drain_deadline
                                                        .checked_duration_since(
                                                            std::time::Instant::now(),
                                                        )
                                                        .unwrap_or(
                                                            std::time::Duration::from_millis(100),
                                                        );
                                                    data_queue_runtime.drain_completions(remaining);
                                                    let residual = data_queue_runtime
                                                        .in_flight_counter()
                                                        .load();
                                                    if residual > 0 {
                                                        drain_hung_io_count = residual as u64;
                                                    }

                                                    if drain_timed_out || residual > 0 {
                                                        eprintln!(
                                                            "tidefs ublk-serve: WARNING shutdown drain timed out, {drain_hung_io_count} hung I/O request(s) uncleared"
                                                        );
                                                    } else {
                                                        eprintln!("tidefs ublk-serve: shutdown phase: drain complete ({drain_iterations} iterations, {drain_cqes_processed} CQEs processed, in-flight counter verified zero)");
                                                    }

                                                    eprintln!("tidefs ublk-serve: shutdown phase: issuing final backend flush");
                                                    match backend.flush() {
                                                        Ok(()) => {
                                                            final_flush_completed = true;
                                                            eprintln!("tidefs ublk-serve: shutdown phase: backend flush complete");
                                                        }
                                                        Err(e) => {
                                                            eprintln!("tidefs ublk-serve: shutdown phase: final flush failed ({e})");
                                                        }
                                                    }
                                                }
                                            } else {
                                                if let Err(error) = sd_result {
                                                    start_dev_refusal_class =
                                                        Some(error.as_str().to_string());
                                                    start_dev_errno = error.errno();
                                                }
                                                io_loop_failure_class =
                                                    UblkDataQueueIoLoopFailureClass::StartDevFailed;
                                            }
                                        } else {
                                            start_dev_refusal_class =
                                                Some("data_queue_fetches_not_ready".to_string());
                                            io_loop_failure_class =
                                                UblkDataQueueIoLoopFailureClass::StartDevFailed;
                                        }
                                    } else {
                                        if let Err(error) = fetch_submission_result {
                                            fetch_req_submitted_commands =
                                                error.submitted_fetch_commands();
                                            start_dev_refusal_class =
                                                Some(error.as_str().to_string());
                                        }
                                        io_loop_failure_class =
                                            UblkDataQueueIoLoopFailureClass::FetchReqSubmissionFailed;
                                    }
                                } else {
                                    io_loop_failure_class =
                                        UblkDataQueueIoLoopFailureClass::DataQueueOpenFailed;
                                    if let Err(ref e) = data_queue_open_result {
                                        data_queue_open_errno = e.errno();
                                        data_queue_open_error_str = Some(e.as_str().to_string());
                                        start_dev_refusal_class = Some(e.as_str().to_string());
                                    }
                                }
                            } else {
                                io_loop_failure_class =
                                    UblkDataQueueIoLoopFailureClass::SetParamsFailed;
                                if let Err(ref e) = set_params_result {
                                    set_params_errno = e.errno();
                                    start_dev_refusal_class = Some(e.as_str().to_string());
                                }
                            }
                        } else {
                            io_loop_failure_class =
                                UblkDataQueueIoLoopFailureClass::ParameterBuildFailed;
                            start_dev_refusal_class = Some("parameter_build_failed".to_string());
                        }

                        // Cleanup: STOP_DEV then DEL_DEV after I/O loop or on error
                        let stop_input = UblkControlStopDevInput::from_kernel_dev_id(
                            add_outcome.dev_info.dev_id,
                        );
                        stop_dev_attempted = true;
                        match issue_stop_dev(control_device.as_fd(), stop_input) {
                            Ok(_outcome) => {
                                stop_dev_uring_cmd_completed = true;
                                eprintln!(
                                    "ublk-serve: STOP_DEV ok dev={}",
                                    add_outcome.dev_info.dev_id
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "ublk-serve: STOP_DEV failed ({}), continuing with DEL_DEV",
                                    e.as_str()
                                );
                            }
                        }
                        let del_input =
                            UblkControlDelDevInput::from_kernel_dev_id(add_outcome.dev_info.dev_id);
                        del_dev_attempted = true;
                        let del_result = issue_del_dev(control_device.as_fd(), del_input);
                        ublk_device_pair_deleted = del_result.is_ok();
                        if let Err(error) = del_result {
                            del_dev_errno = error.errno();
                        }
                    } else if let Err(error) = &current_add_dev_result {
                        io_loop_failure_class = UblkDataQueueIoLoopFailureClass::AddDevFailed;
                        start_dev_refusal_class = Some(error.as_str().to_string());
                    }
                } else if current_probe_result.is_ok() {
                    io_loop_failure_class =
                        UblkDataQueueIoLoopFailureClass::RequiredFeaturesMissing;
                    start_dev_refusal_class = Some("required_features_missing".to_string());
                }
            }
            Err(error_class) => {
                inputs.control_open_result = Some(Err(error_class));
                io_loop_failure_class = UblkDataQueueIoLoopFailureClass::ControlOpenFailed;
                start_dev_refusal_class = Some("control_open_failed".to_string());
            }
        }
    }

    completion_trace.record_releases();
    completion_trace.write_if_enabled().map_err(|error| {
        AppError::new(format!("write ublk completion runtime artifact: {error}"))
    })?;
    let open_report = evaluate_ublk_control_open_preflight(&inputs);
    let fetch_req_all_queue_tag_slots_covered = fetch_req_submission_completed
        && fetch_req_required_commands > 0
        && fetch_req_submitted_commands == fetch_req_required_commands
        && fetch_req_required_commands
            == u32::from(add_dev_input.nr_hw_queues) * u32::from(add_dev_input.queue_depth)
        && fetch_req_first_qid == Some(0)
        && fetch_req_first_tag == Some(0)
        && fetch_req_last_qid == Some(add_dev_input.nr_hw_queues.saturating_sub(1))
        && fetch_req_last_tag == Some(add_dev_input.queue_depth.saturating_sub(1))
        && data_queue_runtime_live_at_start;
    let first_request_serviced = io_loop_commit_and_fetch_submitted > 0;
    let bounded_no_request_observed = start_dev_uring_cmd_completed
        && io_loop_attempted
        && max_iterations.is_some()
        && io_loop_commit_and_fetch_submitted == 0
        && io_loop_errno.is_none();
    let first_request_observation = if first_request_serviced {
        "serviced_request"
    } else if bounded_no_request_observed {
        "bounded_no_request"
    } else if start_dev_uring_cmd_completed {
        "no_request_observation_missing"
    } else if start_dev_uring_cmd_attempted {
        "refused"
    } else {
        "not_started"
    }
    .to_string();
    let start_dev_state = if start_dev_uring_cmd_completed {
        "succeeded"
    } else if start_dev_uring_cmd_attempted {
        "refused"
    } else {
        "not_attempted"
    }
    .to_string();
    let started_export_admission_artifact = UblkStartedExportAdmissionArtifact {
        nr_hw_queues: add_dev_input.nr_hw_queues,
        queue_depth: add_dev_input.queue_depth,
        kernel_release: open_report.kernel_release,
        host_preflight_admitted: open_report.admission_class
            != UblkControlOpenAdmissionClass::Refused,
        control_open_attempted: open_report.control_open_attempted,
        control_opened: open_report.control_opened,
        control_open_error_class: open_report
            .control_open_error_class
            .map(|error_class| error_class.as_str().to_string()),
        feature_probe_attempted,
        feature_probe_completed,
        feature_mask,
        required_features_available,
        add_dev_attempted,
        add_dev_completed,
        add_dev_dev_id,
        set_params_attempted,
        set_params_completed,
        set_params_block_size_bytes,
        set_params_block_count,
        set_params_dev_sectors,
        set_params_errno,
        data_queue_open_attempted,
        data_queue_opened,
        data_queue_path: data_queue_path_for_artifact,
        data_queue_runtime_live_at_start,
        data_queue_open_errno,
        fetch_req_submission_attempted,
        fetch_req_submission_completed,
        fetch_req_required_commands,
        fetch_req_submitted_commands,
        fetch_req_all_queue_tag_slots_covered,
        fetch_req_first_qid,
        fetch_req_first_tag,
        fetch_req_last_qid,
        fetch_req_last_tag,
        start_dev_attempted: start_dev_uring_cmd_attempted,
        start_dev_succeeded: start_dev_uring_cmd_completed,
        start_dev_state,
        start_dev_refusal_class,
        start_dev_errno,
        service_loop_owned: start_dev_uring_cmd_completed
            && data_queue_runtime_live_at_start
            && fetch_req_all_queue_tag_slots_covered,
        service_loop_attempted: io_loop_attempted,
        service_loop_completed_iterations: io_loop_completed_iterations,
        service_loop_cqes_processed: io_loop_cqes_processed,
        first_request_observation,
        first_request_serviced,
        bounded_no_request_observed,
        commit_and_fetch_submitted: io_loop_commit_and_fetch_submitted,
        shutdown_graceful,
        drain_cqes_processed,
        drain_iterations,
        drain_timed_out,
        drain_hung_io_count,
        final_flush_completed,
        stop_dev_attempted,
        stop_dev_succeeded: stop_dev_uring_cmd_completed,
        del_dev_attempted,
        del_dev_succeeded: ublk_device_pair_deleted,
        del_dev_errno,
        ..UblkStartedExportAdmissionArtifact::default()
    };
    let started_export_admission_artifact_path = started_export_admission_artifact
        .write_if_enabled()
        .map_err(|error| {
            AppError::new(format!(
                "write ublk started-export admission runtime artifact: {error}"
            ))
        })?;
    let started_export_admission_artifact_written =
        started_export_admission_artifact_path.is_some();

    Ok(UblkDataQueueIoLoopReport {
        start_dev_uring_cmd_completed,
        ublk_device_pair_created,
        ublk_device_pair_deleted,
        io_loop_attempted,
        io_loop_completed_iterations,
        io_loop_cqes_processed,
        io_loop_commit_and_fetch_submitted,
        io_loop_failure_class,
        io_loop_errno,
        image_bytes_read,
        image_bytes_written,
        image_read_ops_completed,
        image_write_ops_completed,
        image_flush_ops,
        image_discard_ops,
        image_write_zeroes_ops,
        io_uring_queue_processed,
        shutdown_graceful,
        drain_cqes_processed,
        drain_iterations,
        drain_timed_out,
        drain_hung_io_count,
        final_flush_completed,
        stop_dev_uring_cmd_completed,
        set_params_errno,
        data_queue_open_errno,
        data_queue_open_error_str,
        barrier_audit_flush_count,
        barrier_audit_fua_write_count,
        barrier_audit_failed_count,
        barrier_audit_total_entries,
        started_export_admission_artifact_path,
        started_export_admission_artifact_written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_backend::BlockVolumeStorageBackend;
    use crate::ublk_control_open::UblkDataQueueIoLoopReport;
    use crate::LINUX_SECTOR_SIZE_BYTES;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tidefs_block_volume_adapter_core::{
        BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeGeometryRecord, BlockVolumeId,
        BlockVolumeRequestClass,
    };
    use tidefs_ublk_abi::UblkSrvIoCmd;

    fn test_geometry() -> BlockVolumeGeometryRecord {
        BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_900), 4096, 64, 1)
    }

    fn test_image() -> (tempfile::TempDir, BlockVolumeFileImage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.img");
        let image =
            BlockVolumeFileImage::create_zeroed(&path, test_geometry()).expect("create test image");
        (dir, image)
    }

    fn completed_read_entry(byte_count: usize) -> DataQueueWorkerResultEntry {
        DataQueueWorkerResultEntry {
            tag: 7,
            request_class: BlockVolumeRequestClass::Read,
            completion_class: BlockVolumeCompletionClass::Completed,
            io_cmd: UblkSrvIoCmd {
                q_id: 0,
                tag: 7,
                result: i32::try_from(byte_count).unwrap_or(i32::MAX),
                addr_or_zone_append_lba: 0,
            },
            byte_count,
        }
    }

    #[test]
    fn completed_read_payload_uses_kernel_request_length() {
        let read_buf = vec![0x5a; 4096];
        let entry = completed_read_entry(512);
        let payload = completed_read_payload(&read_buf, &entry).expect("read payload");
        assert_eq!(payload.len(), 512);
        assert!(payload.iter().all(|byte| *byte == 0x5a));
    }

    #[test]
    fn completed_read_payload_rejects_short_internal_buffer() {
        let read_buf = vec![0; 512];
        let entry = completed_read_entry(4096);
        let err = completed_read_payload(&read_buf, &entry).expect_err("short payload");
        assert_eq!(err, DataQueueWorkerError::PayloadBufferTooShort);
    }

    /// Verify that the shutdown flag gated by the live I/O loop causes
    /// gracefule exit (the boundary function with max_iterations doesn't use
    /// the shutdown flag; this test documents that contract).
    #[test]
    fn bounded_loop_runs_without_shutdown_flag_side_effects() {
        let (dir, mut image) = test_image();
        let _report = run_ublk_data_queue_io_loop_boundary(None, 1, &mut image, false, 1, 16, 30)
            .expect("io loop boundary");
        // The boundary function passes None for shutdown internally;
        // the report should show no shutdown activity.
        let _ = dir.close();
    }

    /// Verify that the live-device path passes the shutdown flag through
    /// to the I/O loop. On a host without a real ublk control device the
    /// call will fail early (HostNotAdmitted), which is fine: the test
    /// ensures the code path compiles and links the flag.
    #[test]
    fn live_device_path_passes_shutdown_flag_to_io_loop() {
        let (dir, mut image) = test_image();
        let shutdown = Arc::new(AtomicBool::new(false));
        let _report = run_ublk_live_device(None, &mut image, shutdown, false, 1, 16, 30);
        // On hosts without /dev/ublk-control this returns Err; on real
        // ublk hosts it returns Ok. Either is acceptable.
        let _ = dir.close();
    }

    /// Verify that a non-shutdown I/O loop (bounded iteration) correctly
    /// reports shutdown_graceful as false and drain fields at zero.
    #[test]
    fn bounded_loop_without_shutdown_reports_no_shutdown_fields() {
        let (dir, mut image) = test_image();
        let report = run_ublk_data_queue_io_loop_boundary(None, 10, &mut image, false, 1, 16, 30)
            .expect("io loop boundary");

        // In bounded mode, shutdown is None internally, so no shutdown occurs
        assert!(!report.shutdown_graceful);
        assert_eq!(report.drain_cqes_processed, 0);
        assert_eq!(report.drain_iterations, 0);
        assert!(!report.drain_timed_out);
        assert_eq!(report.drain_hung_io_count, 0);
        assert!(!report.final_flush_completed);

        drop(image);
        let _ = dir.close();
    }

    #[test]
    fn shutdown_fields_default_to_false_in_non_shutdown_report() {
        // Verify that the report struct defaults work for non-shutdown scenarios
        let report = UblkDataQueueIoLoopReport {
            start_dev_uring_cmd_completed: false,
            ublk_device_pair_created: false,
            ublk_device_pair_deleted: false,
            io_loop_attempted: false,
            io_loop_completed_iterations: 0,
            io_loop_cqes_processed: 0,
            io_loop_commit_and_fetch_submitted: 0,
            io_loop_failure_class:
                crate::ublk_control_open::UblkDataQueueIoLoopFailureClass::HostNotAdmitted,
            io_loop_errno: None,
            image_bytes_read: 0,
            image_bytes_written: 0,
            image_read_ops_completed: 0,
            image_write_ops_completed: 0,
            image_flush_ops: 0,
            image_discard_ops: 0,
            image_write_zeroes_ops: 0,
            io_uring_queue_processed: false,
            shutdown_graceful: false,
            drain_cqes_processed: 0,
            drain_iterations: 0,
            drain_timed_out: false,
            drain_hung_io_count: 0,
            final_flush_completed: false,
            stop_dev_uring_cmd_completed: false,
            set_params_errno: None,
            data_queue_open_errno: None,
            data_queue_open_error_str: None,
            barrier_audit_flush_count: 0,
            barrier_audit_fua_write_count: 0,
            barrier_audit_failed_count: 0,
            barrier_audit_total_entries: 0,
            started_export_admission_artifact_path: None,
            started_export_admission_artifact_written: false,
        };
        assert!(!report.shutdown_graceful);
        assert!(!report.drain_timed_out);
        assert!(!report.final_flush_completed);
    }

    #[test]
    fn shutdown_report_fields_track_graceful_shutdown_state() {
        let report = UblkDataQueueIoLoopReport {
            start_dev_uring_cmd_completed: true,
            ublk_device_pair_created: true,
            ublk_device_pair_deleted: true,
            io_loop_attempted: true,
            io_loop_completed_iterations: 42,
            io_loop_cqes_processed: 84,
            io_loop_commit_and_fetch_submitted: 42,
            io_loop_failure_class: crate::ublk_control_open::UblkDataQueueIoLoopFailureClass::None,
            io_loop_errno: None,
            image_bytes_read: 1024,
            image_bytes_written: 2048,
            image_read_ops_completed: 5,
            image_write_ops_completed: 10,
            image_flush_ops: 1,
            image_discard_ops: 0,
            image_write_zeroes_ops: 0,
            io_uring_queue_processed: false,
            shutdown_graceful: true,
            drain_cqes_processed: 4,
            drain_iterations: 2,
            drain_timed_out: false,
            drain_hung_io_count: 0,
            final_flush_completed: true,
            stop_dev_uring_cmd_completed: true,
            set_params_errno: None,
            data_queue_open_errno: None,
            data_queue_open_error_str: None,
            barrier_audit_flush_count: 0,
            barrier_audit_fua_write_count: 0,
            barrier_audit_failed_count: 0,
            barrier_audit_total_entries: 0,
            started_export_admission_artifact_path: None,
            started_export_admission_artifact_written: false,
        };
        assert!(report.shutdown_graceful);
        assert_eq!(report.drain_cqes_processed, 4);
        assert_eq!(report.drain_iterations, 2);
        assert!(!report.drain_timed_out);
        assert!(report.final_flush_completed);
    }

    #[test]
    fn shutdown_report_handles_drain_timeout_state() {
        let report = UblkDataQueueIoLoopReport {
            start_dev_uring_cmd_completed: true,
            ublk_device_pair_created: true,
            ublk_device_pair_deleted: true,
            io_loop_attempted: true,
            io_loop_completed_iterations: 100,
            io_loop_cqes_processed: 200,
            io_loop_commit_and_fetch_submitted: 100,
            io_loop_failure_class: crate::ublk_control_open::UblkDataQueueIoLoopFailureClass::None,
            io_loop_errno: None,
            image_bytes_read: 0,
            image_bytes_written: 4096,
            image_read_ops_completed: 0,
            image_write_ops_completed: 1,
            image_flush_ops: 0,
            image_discard_ops: 0,
            image_write_zeroes_ops: 0,
            io_uring_queue_processed: false,
            shutdown_graceful: true,
            drain_cqes_processed: 8,
            drain_iterations: 3,
            drain_timed_out: true,
            drain_hung_io_count: 2,
            final_flush_completed: false,
            stop_dev_uring_cmd_completed: false,
            set_params_errno: None,
            data_queue_open_errno: None,
            data_queue_open_error_str: None,
            barrier_audit_flush_count: 0,
            barrier_audit_fua_write_count: 0,
            barrier_audit_failed_count: 0,
            barrier_audit_total_entries: 0,
            started_export_admission_artifact_path: None,
            started_export_admission_artifact_written: false,
        };
        assert!(report.shutdown_graceful);
        assert!(report.drain_timed_out);
        assert_eq!(report.drain_hung_io_count, 2);
        assert!(!report.final_flush_completed);
        assert!(report.ublk_device_pair_deleted); // DEL_DEV still happens after timeout
    }
}
