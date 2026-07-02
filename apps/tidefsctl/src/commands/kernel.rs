// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-resident TideFS operator probes.
//!
//! This module reports whether the declared kernel control endpoint exists and
//! inventories the current kernel runtime surfaces. It intentionally does not
//! open the endpoint or issue ioctls; until the production kernel UAPI is
//! wired, `tidefsctl` must stay an honest observer.

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use clap::Subcommand;

use super::classification::StatusSource;

const DEFAULT_KERNEL_CONTROL_DEVICE: &str = "/dev/tidefs-control";
const CONTROL_DEVICE_SOURCE: &str = StatusSource::CommandLineParse.label();
const DEVICE_PROBE_SOURCE: &str = StatusSource::CachedLocalMetadata.label();
const PASSIVE_BOUNDARY_SOURCE: &str = StatusSource::UnsupportedOrOffline.label();
const RUNTIME_INVENTORY: &str = "static-source-inventory";
const RUNTIME_INVENTORY_SOURCE: &str = StatusSource::StaticConfiguration.label();
const CONTROL_CONTRACT_SOURCE: &str = StatusSource::StaticConfiguration.label();
const PRODUCTION_CONTROL_CONTRACT: &str = "minimum-production-control-uapi-required-not-wired";
const CONTROL_ENDPOINT_IDENTITY: &str = "declared-character-device";
const CONTROL_UAPI_VERSIONING: &str = "versioned-handshake-required";
const REQUIRED_READONLY_STATUS_CALLS: &[&str] = &["version", "status", "capabilities"];
const ABI_COMPATIBILITY_BOUNDARY: &str = "pre-alpha-no-production-abi-freeze";
const OWNER_AUTHORITY_PROOF: &str = "kernel-uapi-owner-proof-required-not-wired";

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
    runtime_inventory: &'static str,
    control_endpoint_opened: bool,
    readonly_status_calls_issued: bool,
    production_uapi_wired: bool,
    mutating_ioctls_issued: bool,
    mutating_operation_admission: MutatingOperationAdmission,
    owner_manifest_authority: bool,
    tidefs_owned_kthreads: RuntimeSurfaceState,
    tidefs_owned_workqueues: RuntimeSurfaceState,
}

impl KernelControlStatus {
    fn probe(control_device: &Path) -> Self {
        let device_state = DeviceState::probe(control_device);
        let mutating_operation_admission =
            MutatingOperationAdmission::from_device_state(&device_state);

        Self {
            control_device: control_device.to_path_buf(),
            device_state,
            runtime_inventory: RUNTIME_INVENTORY,
            control_endpoint_opened: false,
            readonly_status_calls_issued: false,
            production_uapi_wired: false,
            mutating_ioctls_issued: false,
            mutating_operation_admission,
            owner_manifest_authority: false,
            tidefs_owned_kthreads: RuntimeSurfaceState::NotWired,
            tidefs_owned_workqueues: RuntimeSurfaceState::NotWired,
        }
    }

    fn to_json(&self) -> String {
        let mut value = serde_json::json!({
            "probe_completed": true,
            "control_device": self.control_device.display().to_string(),
            "control_device_source": CONTROL_DEVICE_SOURCE,
            "device_state": self.device_state.label(),
            "device_state_source": DEVICE_PROBE_SOURCE,
            "device_kind": self.device_state.kind_label(),
            "device_kind_source": DEVICE_PROBE_SOURCE,
            "runtime_inventory": self.runtime_inventory,
            "runtime_inventory_source": RUNTIME_INVENTORY_SOURCE,
            "production_control_contract": PRODUCTION_CONTROL_CONTRACT,
            "production_control_contract_source": CONTROL_CONTRACT_SOURCE,
            "control_endpoint_identity": CONTROL_ENDPOINT_IDENTITY,
            "control_endpoint_identity_source": CONTROL_CONTRACT_SOURCE,
            "control_uapi_versioning": CONTROL_UAPI_VERSIONING,
            "control_uapi_versioning_source": CONTROL_CONTRACT_SOURCE,
            "required_readonly_status_calls": REQUIRED_READONLY_STATUS_CALLS,
            "required_readonly_status_calls_source": CONTROL_CONTRACT_SOURCE,
        });
        extend_json_object(
            &mut value,
            serde_json::json!({
                "status_is_passive": self.status_is_passive(),
                "status_is_passive_source": PASSIVE_BOUNDARY_SOURCE,
                "control_endpoint_opened": self.control_endpoint_opened,
                "control_endpoint_opened_source": PASSIVE_BOUNDARY_SOURCE,
                "readonly_status_calls_issued": self.readonly_status_calls_issued,
                "readonly_status_calls_issued_source": PASSIVE_BOUNDARY_SOURCE,
                "control_device_present": self.control_device_present(),
                "control_device_present_source": DEVICE_PROBE_SOURCE,
                "control_device_character": self.control_device_character(),
                "control_device_character_source": DEVICE_PROBE_SOURCE,
                "production_uapi_wired": self.production_uapi_wired,
                "production_uapi_wired_source": PASSIVE_BOUNDARY_SOURCE,
                "control_uapi_usable": self.control_uapi_usable(),
                "control_uapi_usable_source": PASSIVE_BOUNDARY_SOURCE,
                "mutating_ioctls_issued": self.mutating_ioctls_issued,
                "mutating_ioctls_issued_source": PASSIVE_BOUNDARY_SOURCE,
                "mutating_operation_admission": self.mutating_operation_admission.label(),
                "mutating_operation_admission_source": self.mutating_operation_admission.source_label(),
            }),
        );
        extend_json_object(
            &mut value,
            serde_json::json!({
                "abi_compatibility_boundary": ABI_COMPATIBILITY_BOUNDARY,
                "abi_compatibility_boundary_source": CONTROL_CONTRACT_SOURCE,
                "owner_manifest_authority": self.owner_manifest_authority,
                "owner_manifest_authority_source": PASSIVE_BOUNDARY_SOURCE,
                "owner_authority_proof": OWNER_AUTHORITY_PROOF,
                "owner_authority_proof_source": PASSIVE_BOUNDARY_SOURCE,
                "tidefs_owned_kthreads": self.tidefs_owned_kthreads.label(),
                "tidefs_owned_kthreads_source": self.tidefs_owned_kthreads.source_label(),
                "tidefs_owned_kthreads_wired": self.tidefs_owned_kthreads.is_wired(),
                "tidefs_owned_workqueues": self.tidefs_owned_workqueues.label(),
                "tidefs_owned_workqueues_source": self.tidefs_owned_workqueues.source_label(),
                "tidefs_owned_workqueues_wired": self.tidefs_owned_workqueues.is_wired(),
                "message": self.message(),
            }),
        );
        serde_json::to_string_pretty(&value).expect("kernel status JSON should format")
    }

    fn status_is_passive(&self) -> bool {
        !self.control_endpoint_opened
            && !self.readonly_status_calls_issued
            && !self.mutating_ioctls_issued
            && !self.owner_manifest_authority
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
                "declared TideFS kernel control device is absent; production kernel UAPI is not wired and all control operations are refused"
            }
            DeviceState::CharacterDevice => {
                "declared TideFS kernel control device is present, but production UAPI wiring is not implemented and all control operations are refused"
            }
            DeviceState::WrongType(_) => {
                "declared TideFS kernel control path exists but is not a character device; all control operations are refused"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutatingOperationAdmission {
    RefusedMissingControlDevice,
    RefusedWrongTypeControlPath,
    RefusedProductionUapiUnwired,
}

impl MutatingOperationAdmission {
    fn from_device_state(device_state: &DeviceState) -> Self {
        match device_state {
            DeviceState::Missing => Self::RefusedMissingControlDevice,
            DeviceState::CharacterDevice => Self::RefusedProductionUapiUnwired,
            DeviceState::WrongType(_) => Self::RefusedWrongTypeControlPath,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::RefusedMissingControlDevice => "refused-control-device-missing",
            Self::RefusedWrongTypeControlPath => "refused-control-path-wrong-type",
            Self::RefusedProductionUapiUnwired => "refused-production-uapi-unwired",
        }
    }

    fn source_label(self) -> &'static str {
        PASSIVE_BOUNDARY_SOURCE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeSurfaceState {
    NotWired,
}

impl RuntimeSurfaceState {
    fn label(self) -> &'static str {
        match self {
            Self::NotWired => "not-wired",
        }
    }

    fn is_wired(self) -> bool {
        match self {
            Self::NotWired => false,
        }
    }

    fn source_label(self) -> &'static str {
        match self {
            Self::NotWired => PASSIVE_BOUNDARY_SOURCE,
        }
    }
}

fn extend_json_object(value: &mut serde_json::Value, fields: serde_json::Value) {
    let target = value
        .as_object_mut()
        .expect("kernel status JSON root should be an object");
    let fields = fields
        .as_object()
        .expect("kernel status JSON extension should be an object");

    target.extend(
        fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
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
    for line in plain_lines(report) {
        println!("{line}");
    }
}

fn plain_lines(report: &KernelControlStatus) -> Vec<String> {
    vec![
        format!("kernel_control_device: {}", report.control_device.display()),
        format!("kernel_control_device_source: {CONTROL_DEVICE_SOURCE}"),
        format!("device_state: {}", report.device_state.label()),
        format!("device_state_source: {DEVICE_PROBE_SOURCE}"),
        format!("device_kind: {}", report.device_state.kind_label()),
        format!("device_kind_source: {DEVICE_PROBE_SOURCE}"),
        format!("runtime_inventory: {}", report.runtime_inventory),
        format!("runtime_inventory_source: {RUNTIME_INVENTORY_SOURCE}"),
        format!("production_control_contract: {PRODUCTION_CONTROL_CONTRACT}"),
        format!("production_control_contract_source: {CONTROL_CONTRACT_SOURCE}"),
        format!("control_endpoint_identity: {CONTROL_ENDPOINT_IDENTITY}"),
        format!("control_endpoint_identity_source: {CONTROL_CONTRACT_SOURCE}"),
        format!("control_uapi_versioning: {CONTROL_UAPI_VERSIONING}"),
        format!("control_uapi_versioning_source: {CONTROL_CONTRACT_SOURCE}"),
        format!(
            "required_readonly_status_calls: {}",
            REQUIRED_READONLY_STATUS_CALLS.join(",")
        ),
        format!("required_readonly_status_calls_source: {CONTROL_CONTRACT_SOURCE}"),
        format!("status_is_passive: {}", report.status_is_passive()),
        format!("status_is_passive_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!(
            "control_endpoint_opened: {}",
            report.control_endpoint_opened
        ),
        format!("control_endpoint_opened_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!(
            "readonly_status_calls_issued: {}",
            report.readonly_status_calls_issued
        ),
        format!("readonly_status_calls_issued_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!(
            "control_device_present: {}",
            report.control_device_present()
        ),
        format!("control_device_present_source: {DEVICE_PROBE_SOURCE}"),
        format!(
            "control_device_character: {}",
            report.control_device_character()
        ),
        format!("control_device_character_source: {DEVICE_PROBE_SOURCE}"),
        format!("production_uapi_wired: {}", report.production_uapi_wired),
        format!("production_uapi_wired_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!("control_uapi_usable: {}", report.control_uapi_usable()),
        format!("control_uapi_usable_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!("mutating_ioctls_issued: {}", report.mutating_ioctls_issued),
        format!("mutating_ioctls_issued_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!(
            "mutating_operation_admission: {}",
            report.mutating_operation_admission.label()
        ),
        format!(
            "mutating_operation_admission_source: {}",
            report.mutating_operation_admission.source_label()
        ),
        format!("abi_compatibility_boundary: {ABI_COMPATIBILITY_BOUNDARY}"),
        format!("abi_compatibility_boundary_source: {CONTROL_CONTRACT_SOURCE}"),
        format!(
            "owner_manifest_authority: {}",
            report.owner_manifest_authority
        ),
        format!("owner_manifest_authority_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!("owner_authority_proof: {OWNER_AUTHORITY_PROOF}"),
        format!("owner_authority_proof_source: {PASSIVE_BOUNDARY_SOURCE}"),
        format!(
            "tidefs_owned_kthreads: {}",
            report.tidefs_owned_kthreads.label()
        ),
        format!(
            "tidefs_owned_kthreads_source: {}",
            report.tidefs_owned_kthreads.source_label()
        ),
        format!(
            "tidefs_owned_kthreads_wired: {}",
            report.tidefs_owned_kthreads.is_wired()
        ),
        format!(
            "tidefs_owned_workqueues: {}",
            report.tidefs_owned_workqueues.label()
        ),
        format!(
            "tidefs_owned_workqueues_source: {}",
            report.tidefs_owned_workqueues.source_label()
        ),
        format!(
            "tidefs_owned_workqueues_wired: {}",
            report.tidefs_owned_workqueues.is_wired()
        ),
        format!("message: {}", report.message()),
    ]
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
        assert_eq!(report.runtime_inventory, RUNTIME_INVENTORY);
        assert!(report.status_is_passive());
        assert!(!report.control_endpoint_opened);
        assert!(!report.readonly_status_calls_issued);
        assert!(!report.production_uapi_wired);
        assert!(!report.mutating_ioctls_issued);
        assert_eq!(
            report.mutating_operation_admission,
            MutatingOperationAdmission::RefusedMissingControlDevice
        );
        assert!(!report.owner_manifest_authority);
        assert_eq!(report.tidefs_owned_kthreads, RuntimeSurfaceState::NotWired);
        assert_eq!(
            report.tidefs_owned_workqueues,
            RuntimeSurfaceState::NotWired
        );
        assert!(!report.tidefs_owned_kthreads.is_wired());
        assert!(!report.tidefs_owned_workqueues.is_wired());
        assert!(!report.control_device_present());
        assert!(!report.control_device_character());
        assert!(!report.control_uapi_usable());

        let json = status_json(&report);
        assert_json_sources(&json);
        assert_passive_boundary_json(&json);
        assert_eq!(json["device_state"], "missing");
        assert_eq!(json["device_kind"], "missing");
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
        assert_eq!(json["control_device_source"], CONTROL_DEVICE_SOURCE);
        assert_eq!(json["device_state"], "missing");
        assert_eq!(json["device_state_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(json["device_kind_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(json["runtime_inventory"], RUNTIME_INVENTORY);
        assert_eq!(json["runtime_inventory_source"], RUNTIME_INVENTORY_SOURCE);
        assert_production_contract_json(&json);
        assert_eq!(json["status_is_passive"], true);
        assert_eq!(json["status_is_passive_source"], PASSIVE_BOUNDARY_SOURCE);
        assert_eq!(json["control_endpoint_opened"], false);
        assert_eq!(
            json["control_endpoint_opened_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["readonly_status_calls_issued"], false);
        assert_eq!(
            json["readonly_status_calls_issued_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["control_device_present"], false);
        assert_eq!(json["control_device_present_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(json["control_device_character"], false);
        assert_eq!(json["control_device_character_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(json["production_uapi_wired"], false);
        assert_eq!(
            json["production_uapi_wired_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["control_uapi_usable"], false);
        assert_eq!(json["control_uapi_usable_source"], PASSIVE_BOUNDARY_SOURCE);
        assert_eq!(json["mutating_ioctls_issued"], false);
        assert_eq!(
            json["mutating_ioctls_issued_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(
            json["mutating_operation_admission"],
            "refused-control-device-missing"
        );
        assert_eq!(
            json["mutating_operation_admission_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(
            json["abi_compatibility_boundary"],
            ABI_COMPATIBILITY_BOUNDARY
        );
        assert_eq!(
            json["abi_compatibility_boundary_source"],
            CONTROL_CONTRACT_SOURCE
        );
        assert_eq!(json["owner_manifest_authority"], false);
        assert_eq!(
            json["owner_manifest_authority_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["owner_authority_proof"], OWNER_AUTHORITY_PROOF);
        assert_eq!(
            json["owner_authority_proof_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["tidefs_owned_kthreads"], "not-wired");
        assert_eq!(
            json["tidefs_owned_kthreads_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["tidefs_owned_kthreads_wired"], false);
        assert_eq!(json["tidefs_owned_workqueues"], "not-wired");
        assert_eq!(
            json["tidefs_owned_workqueues_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["tidefs_owned_workqueues_wired"], false);
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
        assert!(report.status_is_passive());
        assert!(!report.readonly_status_calls_issued);
        assert_eq!(
            report.mutating_operation_admission,
            MutatingOperationAdmission::RefusedWrongTypeControlPath
        );
        assert!(!report.tidefs_owned_kthreads.is_wired());
        assert!(!report.tidefs_owned_workqueues.is_wired());

        let json = status_json(&report);
        assert_json_sources(&json);
        assert_passive_boundary_json(&json);
        assert_eq!(json["device_state"], "wrong-type");
        assert_eq!(json["device_kind"], "regular-file");
        assert_eq!(json["control_device_present"], true);
        assert_eq!(json["control_device_character"], false);
        assert_eq!(json["control_uapi_usable"], false);
        assert_eq!(
            json["mutating_operation_admission"],
            "refused-control-path-wrong-type"
        );
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
        assert!(report.status_is_passive());
        assert!(!report.control_endpoint_opened);
        assert!(!report.readonly_status_calls_issued);
        assert_eq!(
            report.mutating_operation_admission,
            MutatingOperationAdmission::RefusedProductionUapiUnwired
        );
        assert!(!report.tidefs_owned_kthreads.is_wired());
        assert!(!report.tidefs_owned_workqueues.is_wired());

        let json = status_json(&report);
        assert_json_sources(&json);
        assert_passive_boundary_json(&json);
        assert_eq!(json["device_state"], "character-device-present");
        assert_eq!(json["device_kind"], "character-device");
        assert_eq!(json["control_device_present"], true);
        assert_eq!(json["control_device_character"], true);
        assert_eq!(json["control_uapi_usable"], false);
        assert_eq!(
            json["mutating_operation_admission"],
            "refused-production-uapi-unwired"
        );
    }

    #[test]
    fn kernel_status_plain_output_includes_source_classifications() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("missing-control");
        let report = KernelControlStatus::probe(&missing);
        let lines = plain_lines(&report);

        assert!(lines.contains(&format!(
            "kernel_control_device_source: {CONTROL_DEVICE_SOURCE}"
        )));
        assert!(lines.contains(&format!("device_state_source: {DEVICE_PROBE_SOURCE}")));
        assert!(lines.contains(&format!("device_kind_source: {DEVICE_PROBE_SOURCE}")));
        assert!(lines.contains(&format!(
            "control_device_present_source: {DEVICE_PROBE_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "control_device_character_source: {DEVICE_PROBE_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "runtime_inventory_source: {RUNTIME_INVENTORY_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "production_control_contract_source: {CONTROL_CONTRACT_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "required_readonly_status_calls_source: {CONTROL_CONTRACT_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "readonly_status_calls_issued_source: {PASSIVE_BOUNDARY_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "mutating_operation_admission_source: {PASSIVE_BOUNDARY_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "owner_authority_proof_source: {PASSIVE_BOUNDARY_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "tidefs_owned_kthreads_source: {PASSIVE_BOUNDARY_SOURCE}"
        )));
        assert!(lines.contains(&format!(
            "tidefs_owned_workqueues_source: {PASSIVE_BOUNDARY_SOURCE}"
        )));
    }

    fn status_json(report: &KernelControlStatus) -> serde_json::Value {
        serde_json::from_str(&report.to_json()).expect("status JSON parses")
    }

    fn assert_json_sources(json: &serde_json::Value) {
        assert_eq!(json["control_device_source"], CONTROL_DEVICE_SOURCE);
        assert_eq!(json["device_state_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(json["device_kind_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(json["runtime_inventory"], RUNTIME_INVENTORY);
        assert_eq!(json["runtime_inventory_source"], RUNTIME_INVENTORY_SOURCE);
        assert_production_contract_json(json);
        assert_eq!(json["control_device_present_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(json["control_device_character_source"], DEVICE_PROBE_SOURCE);
        assert_eq!(
            json["tidefs_owned_kthreads_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(
            json["tidefs_owned_workqueues_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
    }

    fn assert_passive_boundary_json(json: &serde_json::Value) {
        assert_eq!(json["status_is_passive"], true);
        assert_eq!(json["status_is_passive_source"], PASSIVE_BOUNDARY_SOURCE);
        assert_eq!(json["control_endpoint_opened"], false);
        assert_eq!(
            json["control_endpoint_opened_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["readonly_status_calls_issued"], false);
        assert_eq!(
            json["readonly_status_calls_issued_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["production_uapi_wired"], false);
        assert_eq!(
            json["production_uapi_wired_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["control_uapi_usable"], false);
        assert_eq!(json["control_uapi_usable_source"], PASSIVE_BOUNDARY_SOURCE);
        assert_eq!(json["mutating_ioctls_issued"], false);
        assert_eq!(
            json["mutating_ioctls_issued_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(
            json["mutating_operation_admission_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(
            json["abi_compatibility_boundary"],
            ABI_COMPATIBILITY_BOUNDARY
        );
        assert_eq!(
            json["abi_compatibility_boundary_source"],
            CONTROL_CONTRACT_SOURCE
        );
        assert_eq!(json["owner_manifest_authority"], false);
        assert_eq!(
            json["owner_manifest_authority_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["owner_authority_proof"], OWNER_AUTHORITY_PROOF);
        assert_eq!(
            json["owner_authority_proof_source"],
            PASSIVE_BOUNDARY_SOURCE
        );
        assert_eq!(json["tidefs_owned_kthreads"], "not-wired");
        assert_eq!(json["tidefs_owned_kthreads_wired"], false);
        assert_eq!(json["tidefs_owned_workqueues"], "not-wired");
        assert_eq!(json["tidefs_owned_workqueues_wired"], false);
    }

    fn assert_production_contract_json(json: &serde_json::Value) {
        assert_eq!(
            json["production_control_contract"],
            PRODUCTION_CONTROL_CONTRACT
        );
        assert_eq!(
            json["production_control_contract_source"],
            CONTROL_CONTRACT_SOURCE
        );
        assert_eq!(json["control_endpoint_identity"], CONTROL_ENDPOINT_IDENTITY);
        assert_eq!(
            json["control_endpoint_identity_source"],
            CONTROL_CONTRACT_SOURCE
        );
        assert_eq!(json["control_uapi_versioning"], CONTROL_UAPI_VERSIONING);
        assert_eq!(
            json["control_uapi_versioning_source"],
            CONTROL_CONTRACT_SOURCE
        );
        assert_eq!(
            json["required_readonly_status_calls"],
            serde_json::json!(REQUIRED_READONLY_STATUS_CALLS)
        );
        assert_eq!(
            json["required_readonly_status_calls_source"],
            CONTROL_CONTRACT_SOURCE
        );
    }
}
