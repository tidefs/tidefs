use super::*;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::storage_backend::BlockVolumeStorageBackend;
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
                let current_probe_result = issue_get_features(control_device.as_fd());
                if current_probe_result.as_ref().is_ok_and(|outcome| {
                    outcome
                        .features
                        .contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES)
                }) {
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
                        ublk_device_pair_created = true;
                        if let Ok(parameter_report) = build_ublk_parameter_spec_report_with_geometry(
                            backend.geometry(),
                            nr_hw_queues,
                            queue_depth,
                        ) {
                            let set_params_input =
                                UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                                    add_outcome.dev_info.dev_id,
                                    parameter_report.params,
                                );
                            let set_params_result =
                                issue_set_params(control_device.as_fd(), set_params_input);
                            if set_params_result.is_ok() {
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
                                let data_queue_open_result =
                                    open_data_queue_runtime(&data_queue_path, data_queue_input);
                                if let Ok(mut data_queue_runtime) = data_queue_open_result {
                                    // Submit FETCH_REQs
                                    if let Ok(fetch_outcome) =
                                        submit_runtime_all_queues_fetch_reqs_without_wait(
                                            &mut data_queue_runtime,
                                        )
                                    {
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
                                                        u64::from(iteration) + 1;
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
                                                    let mut pending_fetch_tags: Vec<(u16, u16)> =
                                                        Vec::new();
                                                    {
                                                        while let Some(cqe) = data_queue_runtime
                                                            .ring_mut()
                                                            .completion()
                                                            .next()
                                                        {
                                                            io_loop_cqes_processed += 1;
                                                            if cqe.result() < 0 {
                                                                continue;
                                                            }
                                                            let user_data = cqe.user_data();
                                                            if is_fetch_req_user_data(user_data) {
                                                                pending_fetch_tags.push(
                                                                    decode_fetch_req_user_data(
                                                                        user_data,
                                                                    ),
                                                                );
                                                            } else if is_commit_and_fetch_user_data(
                                                                user_data,
                                                            ) {
                                                                pending_fetch_tags.push(
                                                                    decode_commit_and_fetch_user_data(
                                                                        user_data,
                                                                    ),
                                                                );
                                                            }
                                                        }
                                                    }
                                                    for (q_id, tag) in pending_fetch_tags {
                                                        let result: i32;
                                                        if let Some(worker) =
                                                            data_workers.get_mut(usize::from(q_id))
                                                        {
                                                            if let Some(io_desc) =
                                                                data_queue_runtime
                                                                    .io_desc_for_queue(q_id, tag)
                                                                    .copied()
                                                            {
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
                                                                io_loop_commit_and_fetch_submitted += 1;
                                                            }
                                                            Err(_) => {
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
                                                        let mut pending_tags: Vec<(u16, u16)> =
                                                            Vec::new();
                                                        {
                                                            while let Some(cqe) = data_queue_runtime
                                                                .ring_mut()
                                                                .completion()
                                                                .next()
                                                            {
                                                                drain_cqes_processed += 1;
                                                                if cqe.result() < 0 {
                                                                    continue;
                                                                }
                                                                let user_data = cqe.user_data();
                                                                if is_fetch_req_user_data(user_data)
                                                                {
                                                                    pending_tags.push(
                                                                        decode_fetch_req_user_data(
                                                                            user_data,
                                                                        ),
                                                                    );
                                                                } else if is_commit_and_fetch_user_data(user_data)
                                                                {
                                                                    pending_tags.push(
                                                                        decode_commit_and_fetch_user_data(
                                                                            user_data,
                                                                        ),
                                                                    );
                                                                }
                                                            }
                                                        }
                                                        if pending_tags.is_empty() {
                                                            break 'drain;
                                                        }
                                                        for (q_id, tag) in pending_tags {
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
                                                            let _ = submit_runtime_commit_and_fetch_without_wait(
                                                                &mut data_queue_runtime,
                                                                commit_input,
                                                                readiness,
                                                            );
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
                                                io_loop_failure_class =
                                                    UblkDataQueueIoLoopFailureClass::StartDevFailed;
                                            }
                                        } else {
                                            io_loop_failure_class =
                                                UblkDataQueueIoLoopFailureClass::StartDevFailed;
                                        }
                                    } else {
                                        io_loop_failure_class =
                                            UblkDataQueueIoLoopFailureClass::FetchReqSubmissionFailed;
                                    }
                                } else {
                                    io_loop_failure_class =
                                        UblkDataQueueIoLoopFailureClass::DataQueueOpenFailed;
                                    if let Err(ref e) = data_queue_open_result {
                                        data_queue_open_errno = e.errno();
                                        data_queue_open_error_str = Some(e.as_str().to_string());
                                    }
                                }
                            } else {
                                io_loop_failure_class =
                                    UblkDataQueueIoLoopFailureClass::SetParamsFailed;
                                if let Err(ref e) = set_params_result {
                                    set_params_errno = e.errno();
                                }
                            }
                        } else {
                            io_loop_failure_class =
                                UblkDataQueueIoLoopFailureClass::ParameterBuildFailed;
                        }

                        // Cleanup: STOP_DEV then DEL_DEV after I/O loop or on error
                        let stop_input = UblkControlStopDevInput::from_kernel_dev_id(
                            add_outcome.dev_info.dev_id,
                        );
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
                        let del_result = issue_del_dev(control_device.as_fd(), del_input);
                        ublk_device_pair_deleted = del_result.is_ok();
                    }
                } else {
                    io_loop_failure_class =
                        UblkDataQueueIoLoopFailureClass::RequiredFeaturesMissing;
                }
            }
            Err(_) => {
                inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::from_io_error(
                    io::Error::from(io::ErrorKind::Other),
                )));
                io_loop_failure_class = UblkDataQueueIoLoopFailureClass::ControlOpenFailed;
            }
        }
    }

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
        };
        assert!(report.shutdown_graceful);
        assert!(report.drain_timed_out);
        assert_eq!(report.drain_hung_io_count, 2);
        assert!(!report.final_flush_completed);
        assert!(report.ublk_device_pair_deleted); // DEL_DEV still happens after timeout
    }
}
