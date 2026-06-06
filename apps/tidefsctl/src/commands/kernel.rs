//! Kernel-resident TideFS operator probes.
//!
//! This module reports whether the declared kernel control endpoint exists.
//! It intentionally does not open the endpoint or issue ioctls; until the
//! production kernel UAPI is wired, `tidefsctl` must stay an honest observer.

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use clap::Subcommand;

const DEFAULT_KERNEL_CONTROL_DEVICE: &str = "/dev/tidefs-control";

#[derive(Subcommand, Debug)]
pub enum KernelCommand {
    /// Report kernel control endpoint availability without issuing ioctls
    Status {
        /// Declared TideFS kernel control character device path
        #[arg(
            long = "control-dev",
            value_name = "PATH",
            default_value = DEFAULT_KERNEL_CONTROL_DEVICE
        )]
        control_dev: PathBuf,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn handle_kernel(cmd: KernelCommand) {
    match cmd {
        KernelCommand::Status { control_dev, json } => handle_status(&control_dev, json),
    }
}

fn handle_status(control_dev: &Path, json: bool) {
    let report = KernelControlStatus::probe(control_dev);
    if json {
        println!("{}", report.to_json());
    } else {
        print_plain(&report);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelControlStatus {
    control_device: PathBuf,
    device_state: DeviceState,
    production_uapi_wired: bool,
    mutating_ioctls_issued: bool,
    owner_manifest_authority: bool,
}

impl KernelControlStatus {
    fn probe(control_device: &Path) -> Self {
        Self {
            control_device: control_device.to_path_buf(),
            device_state: DeviceState::probe(control_device),
            production_uapi_wired: false,
            mutating_ioctls_issued: false,
            owner_manifest_authority: false,
        }
    }

    fn to_json(&self) -> String {
        let value = serde_json::json!({
            "probe_completed": true,
            "control_device": self.control_device.display().to_string(),
            "device_state": self.device_state.label(),
            "device_kind": self.device_state.kind_label(),
            "control_device_present": self.control_device_present(),
            "control_device_character": self.control_device_character(),
            "production_uapi_wired": self.production_uapi_wired,
            "control_uapi_usable": self.control_uapi_usable(),
            "mutating_ioctls_issued": self.mutating_ioctls_issued,
            "owner_manifest_authority": self.owner_manifest_authority,
            "message": self.message(),
        });
        serde_json::to_string_pretty(&value).expect("kernel status JSON should format")
    }

    fn control_device_present(&self) -> bool {
        !matches!(self.device_state, DeviceState::Missing)
    }

    fn control_device_character(&self) -> bool {
        matches!(self.device_state, DeviceState::CharacterDevice)
    }

    fn control_uapi_usable(&self) -> bool {
        self.production_uapi_wired && self.control_device_character()
    }

    fn message(&self) -> &'static str {
        match self.device_state {
            DeviceState::Missing => {
                "declared TideFS kernel control device is absent; production kernel UAPI is not wired"
            }
            DeviceState::CharacterDevice => {
                "declared TideFS kernel control device is present, but production UAPI wiring is not implemented"
            }
            DeviceState::WrongType(_) => {
                "declared TideFS kernel control path exists but is not a character device"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeviceState {
    Missing,
    CharacterDevice,
    WrongType(DeviceKind),
}

impl DeviceState {
    fn probe(path: &Path) -> Self {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return Self::Missing;
        };
        let file_type = metadata.file_type();
        if file_type.is_char_device() {
            Self::CharacterDevice
        } else {
            Self::WrongType(DeviceKind::from_file_type(file_type))
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::CharacterDevice => "character-device-present",
            Self::WrongType(_) => "wrong-type",
        }
    }

    fn kind_label(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::CharacterDevice => "character-device",
            Self::WrongType(kind) => kind.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    Socket,
    Fifo,
    Other,
}

impl DeviceKind {
    fn from_file_type(file_type: std::fs::FileType) -> Self {
        if file_type.is_file() {
            Self::RegularFile
        } else if file_type.is_dir() {
            Self::Directory
        } else if file_type.is_symlink() {
            Self::Symlink
        } else if file_type.is_block_device() {
            Self::BlockDevice
        } else if file_type.is_socket() {
            Self::Socket
        } else if file_type.is_fifo() {
            Self::Fifo
        } else {
            Self::Other
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::RegularFile => "regular-file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::BlockDevice => "block-device",
            Self::Socket => "socket",
            Self::Fifo => "fifo",
            Self::Other => "other",
        }
    }
}

fn print_plain(report: &KernelControlStatus) {
    println!("kernel_control_device: {}", report.control_device.display());
    println!("device_state: {}", report.device_state.label());
    println!("device_kind: {}", report.device_state.kind_label());
    println!(
        "control_device_present: {}",
        report.control_device_present()
    );
    println!(
        "control_device_character: {}",
        report.control_device_character()
    );
    println!("production_uapi_wired: {}", report.production_uapi_wired);
    println!("control_uapi_usable: {}", report.control_uapi_usable());
    println!("mutating_ioctls_issued: {}", report.mutating_ioctls_issued);
    println!(
        "owner_manifest_authority: {}",
        report.owner_manifest_authority
    );
    println!("message: {}", report.message());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_status_reports_missing_control_device() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("missing-control");

        let report = KernelControlStatus::probe(&missing);

        assert_eq!(report.device_state, DeviceState::Missing);
        assert!(!report.production_uapi_wired);
        assert!(!report.mutating_ioctls_issued);
        assert!(!report.owner_manifest_authority);
        assert!(!report.control_device_present());
        assert!(!report.control_device_character());
        assert!(!report.control_uapi_usable());
    }

    #[test]
    fn kernel_status_json_exposes_honest_uapi_boundary() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("missing-control");
        let report = KernelControlStatus::probe(&missing);

        let json: serde_json::Value =
            serde_json::from_str(&report.to_json()).expect("status JSON parses");

        assert_eq!(json["probe_completed"], true);
        assert_eq!(json["control_device"], missing.display().to_string());
        assert_eq!(json["device_state"], "missing");
        assert_eq!(json["control_device_present"], false);
        assert_eq!(json["control_device_character"], false);
        assert_eq!(json["production_uapi_wired"], false);
        assert_eq!(json["control_uapi_usable"], false);
        assert_eq!(json["mutating_ioctls_issued"], false);
        assert_eq!(json["owner_manifest_authority"], false);
    }

    #[test]
    fn kernel_status_reports_regular_file_as_wrong_type() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let regular = tmp.path().join("regular-control");
        std::fs::write(&regular, b"not a control device").expect("write regular file");

        let report = KernelControlStatus::probe(&regular);

        assert_eq!(
            report.device_state,
            DeviceState::WrongType(DeviceKind::RegularFile)
        );
        assert_eq!(report.device_state.label(), "wrong-type");
        assert_eq!(report.device_state.kind_label(), "regular-file");
        assert!(report.control_device_present());
        assert!(!report.control_device_character());
        assert!(!report.control_uapi_usable());
    }

    #[test]
    fn kernel_status_reports_dev_null_as_character_device_when_available() {
        let dev_null = Path::new("/dev/null");
        if !dev_null.exists() {
            return;
        }

        let report = KernelControlStatus::probe(dev_null);

        assert_eq!(report.device_state, DeviceState::CharacterDevice);
        assert_eq!(report.device_state.label(), "character-device-present");
        assert!(!report.production_uapi_wired);
        assert!(report.control_device_present());
        assert!(report.control_device_character());
        assert!(!report.control_uapi_usable());
    }
}
