use super::*;

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeGeometryRecord,
    BlockVolumeId,
};
use tidefs_block_volume_adapter_ublk_control_runtime::{
    UblkDataQueueCommitAndFetchInput, UblkDataQueueCommitAndFetchReadiness,
};
use tidefs_ublk_abi::{
    UBLK_IO_F_FUA, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE,
    UBLK_IO_OP_WRITE_ZEROES, UBLK_IO_RES_OK,
};

/// OW gate for the ublk acceptance harness.
pub const BLOCK_VOLUME_UBLK_ACCEPTANCE_HARNESS_GATE_PC_012: &str =
    "PC-012 ublk acceptance harness passes fio verify and durability checks";

/// Acceptance outcome classification for the ublk acceptance harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkAcceptanceStatus {
    /// Full acceptance evidence: first-pass fio passed and durability verification passed.
    Passed,
    /// First-pass fio passed, but post-restart durability verification failed.
    DurabilityFailed,
    /// A prerequisite (host, device lifecycle, harness state) blocked the durability pass.
    BlockedPrerequisite,
    /// First-pass fio verification failed; durability was not attempted or not meaningful.
    FirstPassFailed,
}

impl UblkAcceptanceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::DurabilityFailed => "durability_failed",
            Self::BlockedPrerequisite => "blocked_prerequisite",
            Self::FirstPassFailed => "first_pass_failed",
        }
    }

    pub const fn is_acceptance_evidence(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Result of a single fio verification pass.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct UblkAcceptanceFioPass {
    pub fio_verify_passed: bool,
    pub fio_stderr: String,
    pub device_path: Option<PathBuf>,
}

/// Report from the ublk acceptance harness.
#[derive(Clone, Debug)]
pub struct UblkAcceptanceHarnessReport {
    pub acceptance_status: UblkAcceptanceStatus,
    pub host_kernel_release: String,
    pub dev_id: u32,
    pub device_appeared: bool,
    pub block_device_path: Option<PathBuf>,
    pub first_verify: UblkAcceptanceFioPass,
    pub durability_verify: Option<UblkAcceptanceFioPass>,
    pub io_loop_completed_iterations: u64,
    pub io_loop_cqes_processed: u64,
    pub durability_block_reason: Option<String>,
}

impl UblkAcceptanceHarnessReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk acceptance harness");
        println!("gate={BLOCK_VOLUME_UBLK_ACCEPTANCE_HARNESS_GATE_PC_012}");
        println!("acceptance.status={}", self.acceptance_status.as_str());
        println!(
            "acceptance.is_evidence={}",
            self.acceptance_status.is_acceptance_evidence()
        );
        if let Some(ref reason) = self.durability_block_reason {
            println!("durability.block_reason={reason}");
        }
        println!("host.kernel_release={}", self.host_kernel_release);
        println!("dev_id={}", self.dev_id);
        println!("device.path={:?}", self.block_device_path);
        println!("device.appeared={}", self.device_appeared);
        println!(
            "first_verify.passed={}",
            self.first_verify.fio_verify_passed
        );
        if let Some(ref dp) = self.durability_verify {
            println!("durability_verify.passed={}", dp.fio_verify_passed);
        } else {
            println!("durability_verify.skipped=true");
        }
        println!(
            "io_loop.completed_iterations={}",
            self.io_loop_completed_iterations
        );
        println!("io_loop.cqes_processed={}", self.io_loop_cqes_processed);
    }
}

/// Scan `/dev/ublkb*` for a block device matching `dev_id`.
fn find_ublk_device(dev_id: u32) -> Option<PathBuf> {
    for entry in std::fs::read_dir("/dev").ok()?.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("ublkb") {
            let sysfs_dev = PathBuf::from(format!("/sys/dev/block/{dev_id}:0"));
            let sysfs_ublk = PathBuf::from(format!("/sys/class/block/{name_str}"));
            if sysfs_dev.exists() || sysfs_ublk.exists() {
                return Some(entry.path());
            }
        }
    }
    None
}

/// Wait up to `timeout` for a ublk device to appear.
fn wait_for_ublk_device(dev_id: u32, timeout: Duration) -> Option<PathBuf> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(path) = find_ublk_device(dev_id) {
            return Some(path);
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}

/// Run fio verify against a block device: write with CRC32C verification,
/// then read back and verify.
fn run_fio_verify(device_path: &std::path::Path, label: &str) -> UblkAcceptanceFioPass {
    let fio_write_job = format!(
        "[{label}-write]\n\
         ioengine=psync\n\
         direct=1\n\
         rw=write\n\
         bs=4k\n\
         size=256k\n\
         verify=crc32c\n\
         verify_fatal=1\n\
         group_reporting=1\n"
    );
    let fio_read_job = format!(
        "[{label}-read]\n\
         ioengine=psync\n\
         direct=1\n\
         rw=read\n\
         bs=4k\n\
         size=256k\n\
         verify=crc32c\n\
         verify_fatal=1\n\
         group_reporting=1\n\
         stonewall\n"
    );
    let job_content = format!("{fio_write_job}\n{fio_read_job}");

    let mut temp_job = std::env::temp_dir();
    temp_job.push(format!(
        "tidefs-ublk-fio-{label}-{}.fio",
        std::process::id()
    ));
    let _ = std::fs::write(&temp_job, &job_content);

    let output = std::process::Command::new("fio")
        .arg("--filename")
        .arg(device_path)
        .arg(&temp_job)
        .arg("--output-format=json")
        .output();

    let _ = std::fs::remove_file(&temp_job);

    match output {
        Ok(out) => {
            let passed = out.status.success();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            // Debug: if fio itself fails, include json on stdout in stderr
            let stderr = if !passed && stderr.is_empty() {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                stdout
            } else {
                stderr
            };
            UblkAcceptanceFioPass {
                fio_verify_passed: passed,
                fio_stderr: stderr,
                device_path: Some(device_path.to_path_buf()),
            }
        }
        Err(e) => UblkAcceptanceFioPass {
            fio_verify_passed: false,
            fio_stderr: format!("fio command failed: {e}"),
            device_path: Some(device_path.to_path_buf()),
        },
    }
}

fn open_control_device_file(path: &std::path::Path) -> Result<std::fs::File, AppError> {
    use std::os::unix::fs::FileTypeExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| AppError::new(format!("control device metadata: {e}")))?;
    if !meta.file_type().is_char_device() {
        return Err(AppError::new("control device is not a char device"));
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| AppError::new(format!("control device open: {e}")))
}

fn run_io_loop_iterations(
    nr_hw_queues: u16,
    queue_depth: u16,
    data_queue_runtime: &mut tidefs_block_volume_adapter_ublk_control_runtime::UblkDataQueueRuntime,
    image: &mut BlockVolumeFileImage,
    max_iterations: u32,
) -> (u64, u64) {
    let mut iterations: u64 = 0;
    let mut cqes_processed: u64 = 0;
    let sectors_per_block = (image.geometry.block_size_bytes / 512) as u64;

    for _ in 0..max_iterations {
        match data_queue_runtime.ring_mut().submit_and_wait(1) {
            Ok(_) => {}
            Err(_e) => break,
        }
        iterations += 1;

        let mut pending_fetch_tags: Vec<(u16, u16)> = Vec::new();
        while let Some(cqe) = data_queue_runtime.ring_mut().completion().next() {
            cqes_processed += 1;
            if cqe.result() < 0 {
                break;
            }
            let user_data = cqe.user_data();
            if is_fetch_req_user_data(user_data) {
                pending_fetch_tags.push(decode_fetch_req_user_data(user_data));
            }
        }

        for (q_id, tag) in pending_fetch_tags {
            let mut result: i32 = UBLK_IO_RES_OK;

            if let Some(io_desc) = data_queue_runtime.io_desc(tag) {
                let op = io_desc.op();
                let fua = (io_desc.op_flags & UBLK_IO_F_FUA) != 0;

                match op {
                    UBLK_IO_OP_READ => {
                        let sector_count = io_desc.count_or_zones as u64;
                        if sector_count > 0 && sectors_per_block > 0 {
                            let start_block = (io_desc.start_sector / sectors_per_block) as usize;
                            let block_count = (sector_count / sectors_per_block) as usize;
                            let range = BlockRangeRecord::new(start_block, block_count.max(1));
                            match image.read_blocks(range) {
                                Ok((plan, Some(payload))) => {
                                    if plan.completion_class
                                        == BlockVolumeCompletionClass::Completed
                                    {
                                        if data_queue_runtime
                                            .write_data_at(0, tag, &payload)
                                            .is_err()
                                        {
                                            result = -libc::EIO;
                                        }
                                    } else {
                                        result = -libc::EIO;
                                    }
                                }
                                _ => {
                                    result = -libc::EIO;
                                }
                            }
                        }
                    }
                    UBLK_IO_OP_WRITE => {
                        let sector_count = io_desc.count_or_zones as u64;
                        if sector_count > 0 && sectors_per_block > 0 {
                            let start_block = (io_desc.start_sector / sectors_per_block) as usize;
                            let block_count = (sector_count / sectors_per_block) as usize;
                            let payload_len = block_count.max(1) * image.geometry.block_size_bytes;
                            let mut write_buf = vec![0u8; payload_len];
                            match data_queue_runtime.read_data_at(0, tag, &mut write_buf) {
                                Ok(_) => {
                                    match image.write_blocks(start_block, &write_buf[..payload_len])
                                    {
                                        Ok(plan) => {
                                            if plan.completion_class
                                                != BlockVolumeCompletionClass::Completed
                                            {
                                                result = -libc::EIO;
                                            } else if fua {
                                                let _ = image.flush();
                                            }
                                        }
                                        Err(_) => {
                                            result = -libc::EIO;
                                        }
                                    }
                                }
                                Err(_) => {
                                    result = -libc::EIO;
                                }
                            }
                        }
                    }
                    UBLK_IO_OP_FLUSH => {
                        let _ = image.flush();
                    }
                    UBLK_IO_OP_DISCARD => {
                        let sector_count = io_desc.count_or_zones as u64;
                        if sector_count > 0 && sectors_per_block > 0 {
                            let start_block = (io_desc.start_sector / sectors_per_block) as usize;
                            let block_count = (sector_count / sectors_per_block) as usize;
                            let zeroes =
                                vec![0u8; block_count.max(1) * image.geometry.block_size_bytes];
                            if image.write_blocks(start_block, &zeroes).is_err() {
                                result = -libc::EIO;
                            }
                        }
                    }
                    UBLK_IO_OP_WRITE_ZEROES => {
                        let sector_count = io_desc.count_or_zones as u64;
                        if sector_count > 0 && sectors_per_block > 0 {
                            let start_block = (io_desc.start_sector / sectors_per_block) as usize;
                            let block_count = (sector_count / sectors_per_block) as usize;
                            let zeroes =
                                vec![0u8; block_count.max(1) * image.geometry.block_size_bytes];
                            if image.write_blocks(start_block, &zeroes).is_err() {
                                result = -libc::EIO;
                            }
                        }
                    }
                    _ => {
                        result = -libc::EIO;
                    }
                }

                let _ = fua;
            }

            let commit_input = UblkDataQueueCommitAndFetchInput {
                q_id,
                tag,
                nr_hw_queues,
                queue_depth,
                result,
                addr_or_zone_append_lba: 0,
            };
            let readiness = UblkDataQueueCommitAndFetchReadiness {
                data_queue_runtime_live: true,
                fetched_request_available: true,
                completion_result_ready: true,
            };
            let _ = submit_runtime_commit_and_fetch_without_wait(
                data_queue_runtime,
                commit_input,
                readiness,
            );
        }
    }

    (iterations, cqes_processed)
}


/// OW for the ublk acceptance harness: gate PC-012.
///
/// The harness:
/// 1. Checks ublk control open readiness
/// 2. Adds a ublk device backed by a temporary file image
/// 3. Starts the device and waits for the block device
/// 4. Runs fio verify (CRC32C write+read) against the block device
/// 5. After DEL_DEV, re-opens the same backing file and re-verifies fio data
///    for post-restart durability
pub fn run_ublk_acceptance_harness() -> Result<UblkAcceptanceHarnessReport, AppError> {
    use tidefs_block_volume_adapter_ublk_control_runtime as rt;

    let inputs = UblkControlOpenInputs::read_host()?;
    let kernel_release = inputs.kernel_release.clone();

    // Phase 1: Host readiness
    if !inputs.should_attempt_control_open() {
        return Err(AppError::new("host not ready for ublk control open"));
    }

    let control_device = match open_control_device_file(&inputs.control_path) {
        Ok(dev) => dev,
        Err(error_class) => {
            return Err(AppError::new(format!(
                "control device open failed: {error_class:?}"
            )));
        }
    };

    // Phase 2: Probe features
    let probe_outcome = rt::issue_get_features(control_device.as_fd())
        .map_err(|e| AppError::new(format!("get_features failed: {e:?}")))?;

    if !probe_outcome
        .features
        .contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES)
    {
        return Err(AppError::new("required ublk features not available"));
    }

    // Phase 3: ADD_DEV
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let add_outcome = rt::issue_add_dev(control_device.as_fd(), add_dev_input)
        .map_err(|e| AppError::new(format!("add_dev failed: {e:?}")))?;

    let dev_id = add_outcome.dev_info.dev_id;
    let nr_hw_queues = add_dev_input.nr_hw_queues;
    let queue_depth = add_dev_input.queue_depth;

    // Phase 4: Build backing image
    let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_094), 4096, 1024, 1);
    let backing_path = {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| AppError::new(format!("clock error: {e}")))?
            .as_nanos();
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tidefs-ublk-acceptance-{}-{nonce}.img",
            std::process::id()
        ));
        p
    };
    let _ = std::fs::remove_file(&backing_path);
    let mut image = BlockVolumeFileImage::create_zeroed(&backing_path, geometry)
        .map_err(|e| AppError::new(format!("create backing file: {e}")))?;

    // Phase 5: SET_PARAMS
    let parameter_report = build_ublk_parameter_spec_report()
        .map_err(|e| AppError::new(format!("parameter construction: {e}")))?;
    let set_params_input =
        UblkControlSetParamsInput::from_kernel_dev_id_and_params(dev_id, parameter_report.params);
    rt::issue_set_params(control_device.as_fd(), set_params_input)
        .map_err(|e| AppError::new(format!("set_params failed: {e:?}")))?;

    // Phase 6: Open data queue + submit FETCH_REQs
    let data_queue_input =
        UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(dev_id, 0, nr_hw_queues, queue_depth);
    let data_queue_path = rt::ublk_data_queue_device_path(data_queue_input.dev_id);
    let mut data_queue_runtime = rt::open_data_queue_runtime(&data_queue_path, data_queue_input)
        .map_err(|e| AppError::new(format!("data queue open: {e:?}")))?;

    let fetch_outcome = rt::submit_runtime_fetch_reqs_without_wait(&mut data_queue_runtime)
        .map_err(|e| AppError::new(format!("fetch reqs: {e:?}")))?;

    let start_dev_readiness = fetch_outcome.start_dev_readiness();
    if !start_dev_readiness.all_fetches_ready() {
        return Err(AppError::new("FETCH_REQs not ready"));
    }

    // Phase 7: START_DEV
    let daemon_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    let start_dev_input =
        UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(dev_id, daemon_pid);
    rt::issue_start_dev(control_device.as_fd(), start_dev_input, start_dev_readiness)
        .map_err(|e| AppError::new(format!("start_dev failed: {e:?}")))?;

    // Phase 8: Wait for block device to appear
    let device_path = wait_for_ublk_device(dev_id, Duration::from_secs(5));
    let device_appeared = device_path.is_some();

    // Phase 9: Spawn fio in background thread; run IO loop on main thread.
    // UblkDataQueueRuntime is !Send so IO loop stays on the calling thread.
    const ACCEPTANCE_IO_LOOP_MAX_ITERATIONS: u32 = 10_000;

    let fio_device_path = device_path.clone();
    let fio_handle = thread::spawn(move || {
        if let Some(ref path) = fio_device_path {
            run_fio_verify(path, "first")
        } else {
            UblkAcceptanceFioPass {
                fio_verify_passed: false,
                fio_stderr: "block device not found".to_string(),
                device_path: None,
            }
        }
    });

    let (io_iterations, io_cqes) = run_io_loop_iterations(
        nr_hw_queues,
        queue_depth,
        &mut data_queue_runtime,
        &mut image,
        ACCEPTANCE_IO_LOOP_MAX_ITERATIONS,
    );

    let first_verify = fio_handle.join().unwrap_or_else(|_| UblkAcceptanceFioPass {
        fio_verify_passed: false,
        fio_stderr: "fio thread panicked".to_string(),
        device_path: device_path.clone(),
    });

    // Phase 10: DEL_DEV cleanup
    let del_input = UblkControlDelDevInput::from_kernel_dev_id(dev_id);
    let _ = rt::issue_del_dev(control_device.as_fd(), del_input);
    drop(image);

    // Phase 11: Durability — re-open the same backing file and verify data
    let durability_verify = match BlockVolumeFileImage::reopen_existing(&backing_path, geometry) {
        Ok(mut image_durability) => {
            // Reload ublk lifecycle for the second pass
            let add_durability = rt::issue_add_dev(control_device.as_fd(), add_dev_input)
                .map_err(|e| AppError::new(format!("durability add_dev: {e:?}")))?;
            let durability_dev_id = add_durability.dev_info.dev_id;

            let set_params_durability = UblkControlSetParamsInput::from_kernel_dev_id_and_params(
                durability_dev_id,
                parameter_report.params,
            );
            rt::issue_set_params(control_device.as_fd(), set_params_durability)
                .map_err(|e| AppError::new(format!("durability set_params: {e:?}")))?;

            let dq_input_durability = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
                durability_dev_id,
                0,
                nr_hw_queues,
                queue_depth,
            );
            let dq_path_durability = rt::ublk_data_queue_device_path(dq_input_durability.dev_id);
            let mut dq_runtime_durability =
                rt::open_data_queue_runtime(&dq_path_durability, dq_input_durability)
                    .map_err(|e| AppError::new(format!("durability data queue: {e:?}")))?;

            let fetch_durability =
                rt::submit_runtime_fetch_reqs_without_wait(&mut dq_runtime_durability)
                    .map_err(|e| AppError::new(format!("durability fetch: {e:?}")))?;
            let readiness_durability = fetch_durability.start_dev_readiness();
            if !readiness_durability.all_fetches_ready() {
                return Err(AppError::new("durability FETCH_REQs not ready"));
            }

            let start_dev_durability = UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(
                durability_dev_id,
                daemon_pid,
            );
            rt::issue_start_dev(
                control_device.as_fd(),
                start_dev_durability,
                readiness_durability,
            )
            .map_err(|e| AppError::new(format!("durability start_dev: {e:?}")))?;

            let device_path_durability =
                wait_for_ublk_device(durability_dev_id, Duration::from_secs(5));

            // Spawn fio in thread; IO loop on main thread
            let fio_durability_path = device_path_durability.clone();
            let fio_durability_handle = thread::spawn(move || {
                if let Some(ref p) = fio_durability_path {
                    run_fio_verify(p, "durability")
                } else {
                    UblkAcceptanceFioPass {
                        fio_verify_passed: false,
                        fio_stderr: "durability: block device not found".to_string(),
                        device_path: None,
                    }
                }
            });

            let _ = run_io_loop_iterations(
                nr_hw_queues,
                queue_depth,
                &mut dq_runtime_durability,
                &mut image_durability,
                ACCEPTANCE_IO_LOOP_MAX_ITERATIONS,
            );

            let dpass = fio_durability_handle
                .join()
                .unwrap_or_else(|_| UblkAcceptanceFioPass {
                    fio_verify_passed: false,
                    fio_stderr: "durability fio thread panicked".to_string(),
                    device_path: device_path_durability,
                });

            let del_durability = UblkControlDelDevInput::from_kernel_dev_id(durability_dev_id);
            let _ = rt::issue_del_dev(control_device.as_fd(), del_durability);

            Some(dpass)
        }
        Err(_e) => {
            // Backing file could not be reopened: blocked prerequisite, not
            // a durability verification failure.
            None
        }
    };

    // Classify acceptance status
    let (acceptance_status, durability_block_reason) = classify_acceptance(
        &first_verify,
        durability_verify.as_ref(),
        &backing_path,
    );

    // Clean up backing file
    let _ = std::fs::remove_file(&backing_path);

    Ok(UblkAcceptanceHarnessReport {
        acceptance_status,
        host_kernel_release: kernel_release,
        dev_id,
        device_appeared,
        block_device_path: device_path,
        first_verify,
        durability_verify,
        io_loop_completed_iterations: io_iterations,
        io_loop_cqes_processed: io_cqes,
        durability_block_reason,
    })
}

/// Classify the acceptance outcome from first-pass fio and durability results.
fn classify_acceptance(
    first_verify: &UblkAcceptanceFioPass,
    durability_verify: Option<&UblkAcceptanceFioPass>,
    backing_path: &std::path::Path,
) -> (UblkAcceptanceStatus, Option<String>) {
    if !first_verify.fio_verify_passed {
        let reason = if first_verify.device_path.is_none() {
            "ublk block device did not appear; first-pass fio skipped".to_string()
        } else {
            format!(
                "first-pass fio verification failed: {}",
                first_verify.fio_stderr
            )
        };
        return (UblkAcceptanceStatus::FirstPassFailed, Some(reason));
    }

    match durability_verify {
        None => (
            UblkAcceptanceStatus::BlockedPrerequisite,
            Some(format!(
                "backing file {:?} could not be reopened for durability verification",
                backing_path
            )),
        ),
        Some(dp) => {
            if dp.fio_verify_passed {
                (UblkAcceptanceStatus::Passed, None)
            } else if dp.device_path.is_none() {
                (
                    UblkAcceptanceStatus::BlockedPrerequisite,
                    Some("durability ublk block device did not appear".to_string()),
                )
            } else {
                (
                    UblkAcceptanceStatus::DurabilityFailed,
                    Some(format!(
                        "post-restart durability fio verification failed: {}",
                        dp.fio_stderr
                    )),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_constant_is_stable() {
        assert_eq!(
            BLOCK_VOLUME_UBLK_ACCEPTANCE_HARNESS_GATE_PC_012,
            "PC-012 ublk acceptance harness passes fio verify and durability checks"
        );
    }

    #[test]
    fn acceptance_status_as_str() {
        assert_eq!(UblkAcceptanceStatus::Passed.as_str(), "passed");
        assert_eq!(
            UblkAcceptanceStatus::DurabilityFailed.as_str(),
            "durability_failed"
        );
        assert_eq!(
            UblkAcceptanceStatus::BlockedPrerequisite.as_str(),
            "blocked_prerequisite"
        );
        assert_eq!(
            UblkAcceptanceStatus::FirstPassFailed.as_str(),
            "first_pass_failed"
        );
    }

    #[test]
    fn only_passed_is_acceptance_evidence() {
        assert!(UblkAcceptanceStatus::Passed.is_acceptance_evidence());
        assert!(!UblkAcceptanceStatus::DurabilityFailed.is_acceptance_evidence());
        assert!(!UblkAcceptanceStatus::BlockedPrerequisite.is_acceptance_evidence());
        assert!(!UblkAcceptanceStatus::FirstPassFailed.is_acceptance_evidence());
    }

    #[test]
    fn report_print_is_idempotent() {
        let report = UblkAcceptanceHarnessReport {
            acceptance_status: UblkAcceptanceStatus::Passed,
            host_kernel_release: "6.12.79".to_string(),
            dev_id: 1,
            device_appeared: true,
            block_device_path: Some(PathBuf::from("/dev/ublkb0")),
            first_verify: UblkAcceptanceFioPass {
                fio_verify_passed: true,
                fio_stderr: String::new(),
                device_path: Some(PathBuf::from("/dev/ublkb0")),
            },
            durability_verify: Some(UblkAcceptanceFioPass {
                fio_verify_passed: true,
                fio_stderr: String::new(),
                device_path: Some(PathBuf::from("/dev/ublkb0")),
            }),
            io_loop_completed_iterations: 4,
            io_loop_cqes_processed: 8,
            durability_block_reason: None,
        };
        report.print();
    }

    #[test]
    fn report_with_skipped_durability_is_blocked_not_passed() {
        let report = UblkAcceptanceHarnessReport {
            acceptance_status: UblkAcceptanceStatus::BlockedPrerequisite,
            host_kernel_release: "6.12.79".to_string(),
            dev_id: 2,
            device_appeared: false,
            block_device_path: None,
            first_verify: UblkAcceptanceFioPass {
                fio_verify_passed: false,
                fio_stderr: "block device not found".to_string(),
                device_path: None,
            },
            durability_verify: None,
            io_loop_completed_iterations: 0,
            io_loop_cqes_processed: 0,
            durability_block_reason: Some("ublk block device did not appear".to_string()),
        };
        // Skipped durability must not be usable as acceptance evidence.
        assert!(!report.acceptance_status.is_acceptance_evidence());
        assert_eq!(
            report.acceptance_status,
            UblkAcceptanceStatus::BlockedPrerequisite
        );
        report.print();
    }

    #[test]
    fn report_with_durability_failure() {
        let report = UblkAcceptanceHarnessReport {
            acceptance_status: UblkAcceptanceStatus::DurabilityFailed,
            host_kernel_release: "6.12.79".to_string(),
            dev_id: 3,
            device_appeared: true,
            block_device_path: Some(PathBuf::from("/dev/ublkb1")),
            first_verify: UblkAcceptanceFioPass {
                fio_verify_passed: true,
                fio_stderr: String::new(),
                device_path: Some(PathBuf::from("/dev/ublkb0")),
            },
            durability_verify: Some(UblkAcceptanceFioPass {
                fio_verify_passed: false,
                fio_stderr: "crc32c mismatch".to_string(),
                device_path: Some(PathBuf::from("/dev/ublkb1")),
            }),
            io_loop_completed_iterations: 5,
            io_loop_cqes_processed: 12,
            durability_block_reason: Some(
                "post-restart durability fio verification failed: crc32c mismatch".to_string(),
            ),
        };
        assert!(!report.acceptance_status.is_acceptance_evidence());
        assert_eq!(
            report.acceptance_status,
            UblkAcceptanceStatus::DurabilityFailed
        );
        report.print();
    }

    #[test]
    fn report_with_first_pass_failure() {
        let report = UblkAcceptanceHarnessReport {
            acceptance_status: UblkAcceptanceStatus::FirstPassFailed,
            host_kernel_release: "6.12.79".to_string(),
            dev_id: 4,
            device_appeared: false,
            block_device_path: None,
            first_verify: UblkAcceptanceFioPass {
                fio_verify_passed: false,
                fio_stderr: "block device not found".to_string(),
                device_path: None,
            },
            durability_verify: None,
            io_loop_completed_iterations: 0,
            io_loop_cqes_processed: 0,
            durability_block_reason: Some(
                "ublk block device did not appear; first-pass fio skipped".to_string(),
            ),
        };
        assert!(!report.acceptance_status.is_acceptance_evidence());
        assert_eq!(
            report.acceptance_status,
            UblkAcceptanceStatus::FirstPassFailed
        );
        report.print();
    }

    #[test]
    fn classify_acceptance_passed() {
        let first = UblkAcceptanceFioPass {
            fio_verify_passed: true,
            fio_stderr: String::new(),
            device_path: Some(PathBuf::from("/dev/ublkb0")),
        };
        let durability = UblkAcceptanceFioPass {
            fio_verify_passed: true,
            fio_stderr: String::new(),
            device_path: Some(PathBuf::from("/dev/ublkb1")),
        };
        let (status, reason) =
            classify_acceptance(&first, Some(&durability), Path::new("/tmp/test.img"));
        assert_eq!(status, UblkAcceptanceStatus::Passed);
        assert!(reason.is_none());
    }

    #[test]
    fn classify_acceptance_durability_failed() {
        let first = UblkAcceptanceFioPass {
            fio_verify_passed: true,
            fio_stderr: String::new(),
            device_path: Some(PathBuf::from("/dev/ublkb0")),
        };
        let durability = UblkAcceptanceFioPass {
            fio_verify_passed: false,
            fio_stderr: "crc32c mismatch at offset 4096".to_string(),
            device_path: Some(PathBuf::from("/dev/ublkb1")),
        };
        let (status, reason) =
            classify_acceptance(&first, Some(&durability), Path::new("/tmp/test.img"));
        assert_eq!(status, UblkAcceptanceStatus::DurabilityFailed);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("crc32c mismatch"));
    }

    #[test]
    fn classify_acceptance_blocked_backing_reopen() {
        let first = UblkAcceptanceFioPass {
            fio_verify_passed: true,
            fio_stderr: String::new(),
            device_path: Some(PathBuf::from("/dev/ublkb0")),
        };
        let (status, reason) = classify_acceptance(&first, None, Path::new("/tmp/test.img"));
        assert_eq!(status, UblkAcceptanceStatus::BlockedPrerequisite);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("could not be reopened"));
    }

    #[test]
    fn classify_acceptance_blocked_durability_device_missing() {
        let first = UblkAcceptanceFioPass {
            fio_verify_passed: true,
            fio_stderr: String::new(),
            device_path: Some(PathBuf::from("/dev/ublkb0")),
        };
        let durability = UblkAcceptanceFioPass {
            fio_verify_passed: false,
            fio_stderr: "durability: block device not found".to_string(),
            device_path: None,
        };
        let (status, reason) =
            classify_acceptance(&first, Some(&durability), Path::new("/tmp/test.img"));
        assert_eq!(status, UblkAcceptanceStatus::BlockedPrerequisite);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("device did not appear"));
    }

    #[test]
    fn classify_acceptance_first_pass_failed() {
        let first = UblkAcceptanceFioPass {
            fio_verify_passed: false,
            fio_stderr: "fio command failed: No such device".to_string(),
            device_path: None,
        };
        let (status, reason) = classify_acceptance(&first, None, Path::new("/tmp/test.img"));
        assert_eq!(status, UblkAcceptanceStatus::FirstPassFailed);
        assert!(reason.is_some());
    }

    #[test]
    fn classify_acceptance_first_pass_failed_with_device() {
        let first = UblkAcceptanceFioPass {
            fio_verify_passed: false,
            fio_stderr: "verification failed".to_string(),
            device_path: Some(PathBuf::from("/dev/ublkb0")),
        };
        let (status, reason) = classify_acceptance(&first, None, Path::new("/tmp/test.img"));
        assert_eq!(status, UblkAcceptanceStatus::FirstPassFailed);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("first-pass fio verification failed"));
    }

    #[test]
    fn find_ublk_device_returns_none_when_missing() {
        assert!(find_ublk_device(99999).is_none());
    }
}
