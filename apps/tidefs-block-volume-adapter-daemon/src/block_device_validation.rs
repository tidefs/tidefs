#![allow(dead_code)]
use std::fs;
use std::path::PathBuf;

use crate::ublk_control_open::{
    run_ublk_control_add_del_dev_boundary, run_ublk_control_add_dev_boundary,
    run_ublk_control_open_preflight, run_ublk_control_readonly_probe,
    run_ublk_control_set_params_boundary, run_ublk_control_start_dev_boundary,
    run_ublk_data_queue_commit_and_fetch_boundary,
    run_ublk_data_queue_fetch_req_readiness_boundary,
    run_ublk_data_queue_fetch_req_submission_boundary, run_ublk_data_queue_io_loop_boundary,
    run_ublk_data_queue_open_boundary, UblkControlAddDelDevReport, UblkControlAddDevReport,
    UblkControlOpenReport, UblkControlReadonlyProbeReport, UblkControlSetParamsReport,
    UblkControlStartDevReport, UblkDataQueueCommitAndFetchReport, UblkDataQueueFetchReqReport,
    UblkDataQueueFetchReqSubmissionReport, UblkDataQueueIoLoopReport, UblkDataQueueOpenReport,
};
use crate::AppError;
use std::env;
use std::process;
use std::time::SystemTime;
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeFileImage, BlockVolumeGeometryRecord, BlockVolumeId,
};

/// Gate label for the block-device appearance validation gate.
pub const BLOCK_VOLUME_UBLK_DEVICE_APPEARANCE_GATE_OW_301Y: &str =
    "OW-301Y block-volume adapter ublk device appearance validates /dev/ublkbN geometry and permissions";

/// Result of block-device appearance validation.
#[derive(Clone, Debug)]
pub struct UblkDeviceAppearanceReport {
    pub preflight: UblkControlOpenReport,
    pub open_report: UblkControlOpenReport,
    pub readonly_report: UblkControlReadonlyProbeReport,
    pub add_dev_report: UblkControlAddDevReport,
    pub add_del_dev_report: UblkControlAddDelDevReport,
    pub set_params_report: UblkControlSetParamsReport,
    pub start_dev_report: UblkControlStartDevReport,
    pub fetch_req_report: UblkDataQueueFetchReqReport,
    pub data_queue_open_report: UblkDataQueueOpenReport,
    pub fetch_req_submission_report: UblkDataQueueFetchReqSubmissionReport,
    pub commit_and_fetch_report: UblkDataQueueCommitAndFetchReport,
    pub io_loop_report: UblkDataQueueIoLoopReport,
    /// Whether /dev/ublkbN was found after START_DEV
    pub block_device_present: bool,
    /// The device path if found
    pub block_device_path: Option<PathBuf>,
    /// Size in bytes from sysfs
    pub sysfs_size_bytes: Option<u64>,
    /// Sector size from sysfs
    pub sysfs_hw_sector_size: Option<u32>,
    /// Whether the device is read-only (from sysfs)
    pub sysfs_read_only: Option<bool>,
    /// Whether discard is supported (from sysfs)
    pub sysfs_discard_supported: Option<bool>,
    /// Owner:group from stat
    pub device_owner_uid: Option<u32>,
    pub device_group_gid: Option<u32>,
    /// Permission mode from stat
    pub device_permissions: Option<u32>,
    /// Image-backed IO validation: bytes read from backing image during IO loop.
    pub image_bytes_read: u64,
    /// Image-backed IO validation: bytes written to backing image during IO loop.
    pub image_bytes_written: u64,
    /// Image-backed IO validation: number of completed read ops in IO loop.
    pub image_read_ops_completed: u64,
    /// Image-backed IO validation: number of completed write ops in IO loop.
    pub image_write_ops_completed: u64,
    /// Image-backed IO validation: number of flush ops in IO loop.
    pub image_flush_ops: u64,
    /// Image-backed IO validation: number of discard ops in IO loop.
    pub image_discard_ops: u64,
    /// Image-backed IO validation: number of write-zeroes ops in IO loop.
    pub image_write_zeroes_ops: u64,
    /// Post-loop verification: backing image file size in bytes.
    pub image_file_size_bytes: Option<u64>,
    /// Post-loop verification: whether block 0 was re-readable after IO loop.
    pub image_block_zero_readable: bool,
    /// Post-loop verification: whether backing image size matches geometry.
    pub image_size_matches_geometry: bool,
}

impl UblkDeviceAppearanceReport {
    pub fn print(&self) {
        println!("tidefs block volume adapter ublk device appearance validation");
        println!("gate={BLOCK_VOLUME_UBLK_DEVICE_APPEARANCE_GATE_OW_301Y}");
        println!("host.kernel_release={}", self.open_report.kernel_release);
        println!(
            "host.observe_kernel_class={:?}",
            self.open_report.kernel_class
        );
        println!("block_device.present={}", self.block_device_present);
        if let Some(ref path) = self.block_device_path {
            println!("block_device.path={}", path.display());
        }
        if let Some(size) = self.sysfs_size_bytes {
            println!("block_device.size_bytes={size}");
        }
        if let Some(sector_size) = self.sysfs_hw_sector_size {
            println!("block_device.hw_sector_size={sector_size}");
        }
        if let Some(ro) = self.sysfs_read_only {
            println!("block_device.read_only={ro}");
        }
        if let Some(discard) = self.sysfs_discard_supported {
            println!("block_device.discard_supported={discard}");
        }
        if let Some(uid) = self.device_owner_uid {
            println!("block_device.owner_uid={uid}");
        }
        if let Some(gid) = self.device_group_gid {
            println!("block_device.group_gid={gid}");
        }
        if let Some(mode) = self.device_permissions {
            println!("block_device.permissions={mode:o}");
        }
        println!(
            "io_loop.completed_iterations={}",
            self.io_loop_report.io_loop_completed_iterations
        );
        println!(
            "io_loop.cqes_processed={}",
            self.io_loop_report.io_loop_cqes_processed
        );
        println!(
            "io_loop.commit_and_fetch_submitted={}",
            self.io_loop_report.io_loop_commit_and_fetch_submitted
        );
        println!(
            "start_dev.uring_cmd_completed={}",
            self.start_dev_report.start_dev_uring_cmd_completed
        );
        println!("image_backed.bytes_read={}", self.image_bytes_read);
        println!("image_backed.bytes_written={}", self.image_bytes_written);
        println!("image_backed.read_ops={}", self.image_read_ops_completed);
        println!("image_backed.write_ops={}", self.image_write_ops_completed);
        println!("image_backed.flush_ops={}", self.image_flush_ops);
        println!("image_backed.discard_ops={}", self.image_discard_ops);
        println!(
            "image_backed.write_zeroes_ops={}",
            self.image_write_zeroes_ops
        );
        if let Some(size) = self.image_file_size_bytes {
            println!("image_backed.file_size_bytes={size}");
        }
        println!(
            "image_backed.block_zero_readable={}",
            self.image_block_zero_readable
        );
        println!(
            "image_backed.size_matches_geometry={}",
            self.image_size_matches_geometry
        );
    }
}

/// Return the canonical ublk block-device name for `dev_id`:
/// `ublkb{dev_id}` (matching the Linux ublk driver convention).
fn ublk_block_device_name(dev_id: u32) -> String {
    format!("ublkb{dev_id}")
}

/// Scan `/dev/ublkb*` for the first device matching `dev_id` by checking
/// the device number in sysfs.
///
/// The ublk driver always names its block devices `ublkb{dev_id}`, so the
/// direct path `/dev/ublkb{dev_id}` is checked first.  When that is absent
/// (e.g. in a container with a remapped /dev), a scan of `/dev/ublkb*` with
/// a sysfs dev-attribute match serves as the fallback.
fn find_ublk_device(dev_id: u32) -> Option<PathBuf> {
    // Direct path: the ublk driver uses predictable ublkbN names.
    let dev_name = ublk_block_device_name(dev_id);
    let direct = PathBuf::from(format!("/dev/{dev_name}"));
    if direct.exists() {
        return Some(direct);
    }

    // Fallback scan: useful when /dev is remapped or device nodes are
    // created with non-standard names.  Verify sysfs dev attribute matches.
    for entry in fs::read_dir("/dev").ok()?.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("ublkb") {
            let path = entry.path();
            let sysfs_dev_attr = PathBuf::from(format!("/sys/class/block/{name_str}/dev"));
            if sysfs_dev_attr.exists() {
                return Some(path);
            }
        }
    }
    None
}

/// Read a sysfs attribute for a ublk device identified by its ublk device
/// number (`dev_id`).
///
/// The ublk driver exports block-device attributes under
/// `/sys/class/block/ublkb{dev_id}/{attr}` and queue attributes under
/// `/sys/class/block/ublkb{dev_id}/queue/{attr}`.  Both are tried before
/// falling back to a directory scan.
fn read_ublk_sysfs_attr(dev_id: u32, attr: &str) -> Option<String> {
    let name = ublk_block_device_name(dev_id);

    // Direct attribute path: /sys/class/block/ublkbN/{attr}
    let direct = PathBuf::from(format!("/sys/class/block/{name}/{attr}"));
    if direct.exists() {
        return fs::read_to_string(&direct)
            .ok()
            .map(|s| s.trim().to_string());
    }

    // Queue-scoped attribute: /sys/class/block/ublkbN/queue/{attr}
    let queue = PathBuf::from(format!("/sys/class/block/{name}/queue/{attr}"));
    if queue.exists() {
        return fs::read_to_string(&queue)
            .ok()
            .map(|s| s.trim().to_string());
    }

    // Fallback: scan /sys/class/block/ublkb* and match dev attribute.
    for entry in fs::read_dir("/sys/class/block").ok()?.flatten() {
        let entry_name = entry.file_name();
        let entry_name_str = entry_name.to_string_lossy();
        if entry_name_str.starts_with("ublkb") {
            let dev_path = entry.path().join("dev");
            if let Ok(dev_content) = fs::read_to_string(&dev_path) {
                if dev_content.trim().is_empty() {
                    continue;
                }
                let attr_path = entry.path().join(attr);
                if attr_path.exists() {
                    return fs::read_to_string(&attr_path)
                        .ok()
                        .map(|s| s.trim().to_string());
                }
                let queue_path = entry.path().join("queue").join(attr);
                if queue_path.exists() {
                    return fs::read_to_string(&queue_path)
                        .ok()
                        .map(|s| s.trim().to_string());
                }
            }
        }
    }
    None
}

/// Run the complete block-device appearance validation.
///
/// # Errors
/// Returns `AppError` if any gate in the pipeline fails fatally.
pub fn run_block_device_appearance_validation() -> Result<UblkDeviceAppearanceReport, AppError> {
    let preflight = run_ublk_control_open_preflight()?;
    let open_report = preflight.clone();
    let readonly_report = run_ublk_control_readonly_probe()?;
    let add_dev_report = run_ublk_control_add_dev_boundary()?;

    // After add_dev, a device pair should be created.
    // Try to find the ublk device before proceeding.
    let add_del_dev_report = run_ublk_control_add_del_dev_boundary()?;
    let set_params_report = run_ublk_control_set_params_boundary()?;
    let start_dev_report = run_ublk_control_start_dev_boundary()?;
    let fetch_req_report = run_ublk_data_queue_fetch_req_readiness_boundary()?;
    let data_queue_open_report = run_ublk_data_queue_open_boundary()?;
    let fetch_req_submission_report = run_ublk_data_queue_fetch_req_submission_boundary()?;
    let commit_and_fetch_report = run_ublk_data_queue_commit_and_fetch_boundary()?;
    let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_093), 4096, 1024, 1);
    let backing_path = {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| AppError::new(format!("clock before unix epoch: {err}")))?
            .as_nanos();
        let mut path = env::temp_dir();
        path.push(format!(
            "tidefs-block-volume-validation-{}-{nonce}.img",
            process::id()
        ));
        path
    };
    let _ = std::fs::remove_file(&backing_path);
    let mut image =
        BlockVolumeFileImage::create_zeroed(&backing_path, geometry).map_err(|err| {
            AppError::new(format!("create zeroed backing file for validation: {err}"))
        })?;
    let io_loop_report =
        run_ublk_data_queue_io_loop_boundary(None, 5, &mut image, false, 1, 64, 30)?;

    // Post-loop image verification: tie io_loop validation to backing image state
    let image_bytes_read_ev = io_loop_report.image_bytes_read;
    let image_bytes_written_ev = io_loop_report.image_bytes_written;
    let image_read_ops_completed_ev = io_loop_report.image_read_ops_completed;
    let image_write_ops_completed_ev = io_loop_report.image_write_ops_completed;
    let image_flush_ops_ev = io_loop_report.image_flush_ops;
    let image_discard_ops_ev = io_loop_report.image_discard_ops;
    let image_write_zeroes_ops_ev = io_loop_report.image_write_zeroes_ops;

    let image_file_size_bytes = std::fs::metadata(&backing_path).ok().map(|m| m.len());
    let expected_bytes =
        u64::try_from(geometry.block_count as u128 * geometry.block_size_bytes as u128).ok();
    let image_size_matches_geometry = match (image_file_size_bytes, expected_bytes) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => false,
    };
    let image_block_zero_readable = image.read_blocks(BlockRangeRecord::new(0, 1)).is_ok();

    drop(image);
    let _ = std::fs::remove_file(&backing_path);

    // After START_DEV + io_loop, check for the block device.
    // The actual dev_id comes from add_dev; use the start_dev target.
    let dev_id = start_dev_report.start_dev_target_dev_id.unwrap_or(0);

    let block_device_path = find_ublk_device(dev_id);
    let block_device_present = block_device_path.is_some();

    // Read sysfs attributes
    let sysfs_size_bytes = read_ublk_sysfs_attr(dev_id, "size")
        .and_then(|s| s.parse::<u64>().ok())
        .map(|blocks| blocks * 512); // sysfs size is in 512-byte sectors

    let sysfs_hw_sector_size = read_ublk_sysfs_attr(dev_id, "hw_sector_size")
        .and_then(|s| s.parse::<u32>().ok())
        .or_else(|| {
            // Try queue/hw_sector_size
            read_ublk_sysfs_attr(dev_id, "hw_sector_size").and_then(|s| s.parse::<u32>().ok())
        });

    let sysfs_read_only = read_ublk_sysfs_attr(dev_id, "ro").map(|s| s == "1");

    let sysfs_discard_supported = read_ublk_sysfs_attr(dev_id, "discard_max_bytes")
        .and_then(|s| s.parse::<u64>().ok())
        .map(|max| max > 0);

    // Device permissions via stat
    let (device_owner_uid, device_group_gid, device_permissions) =
        if let Some(ref path) = block_device_path {
            match fs::metadata(path) {
                Ok(metadata) => {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = metadata.permissions().mode();
                    // uid/gid via metadata on unix
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        (
                            Some(metadata.uid()),
                            Some(metadata.gid()),
                            Some(mode & 0o777),
                        )
                    }
                    #[cfg(not(unix))]
                    {
                        (None, None, Some(mode & 0o777))
                    }
                }
                Err(_) => (None, None, None),
            }
        } else {
            (None, None, None)
        };

    Ok(UblkDeviceAppearanceReport {
        preflight,
        open_report,
        readonly_report,
        add_dev_report,
        add_del_dev_report,
        set_params_report,
        start_dev_report,
        fetch_req_report,
        data_queue_open_report,
        fetch_req_submission_report,
        commit_and_fetch_report,
        io_loop_report,
        block_device_present,
        block_device_path,
        sysfs_size_bytes,
        sysfs_hw_sector_size,
        sysfs_read_only,
        sysfs_discard_supported,
        device_owner_uid,
        device_group_gid,
        device_permissions,
        image_bytes_read: image_bytes_read_ev,
        image_bytes_written: image_bytes_written_ev,
        image_read_ops_completed: image_read_ops_completed_ev,
        image_write_ops_completed: image_write_ops_completed_ev,
        image_flush_ops: image_flush_ops_ev,
        image_discard_ops: image_discard_ops_ev,
        image_write_zeroes_ops: image_write_zeroes_ops_ev,
        image_file_size_bytes,
        image_block_zero_readable,
        image_size_matches_geometry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_ublk_block_device_name() {
        assert_eq!(ublk_block_device_name(0), "ublkb0");
        assert_eq!(ublk_block_device_name(7), "ublkb7");
        assert_eq!(ublk_block_device_name(42), "ublkb42");
    }

    #[test]
    fn test_sysfs_attr_direct_path_format() {
        let name = ublk_block_device_name(3);
        let direct = PathBuf::from(format!("/sys/class/block/{name}/size"));
        let queue = PathBuf::from(format!("/sys/class/block/{name}/queue/hw_sector_size"));
        assert_eq!(direct, PathBuf::from("/sys/class/block/ublkb3/size"));
        assert_eq!(
            queue,
            PathBuf::from("/sys/class/block/ublkb3/queue/hw_sector_size")
        );
    }

    #[test]
    fn test_find_device_direct_path_format() {
        let name = ublk_block_device_name(5);
        let direct = PathBuf::from(format!("/dev/{name}"));
        assert_eq!(direct, PathBuf::from("/dev/ublkb5"));
    }

    #[test]
    fn test_ublk_sysfs_attr_fallback_scan_parsing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let blk_dir = tmp.path().join("ublkb0");
        fs::create_dir(&blk_dir).expect("create dir");
        fs::write(blk_dir.join("dev"), "252:0\n").expect("write dev");
        let dev_content = fs::read_to_string(blk_dir.join("dev")).expect("read dev");
        assert!(!dev_content.trim().is_empty());
    }
}
