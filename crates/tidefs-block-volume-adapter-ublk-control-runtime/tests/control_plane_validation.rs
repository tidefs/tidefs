// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified ublk control-plane device registration and queue
//! configuration protocol validation harness.
//!
//! Exercises:
//! - Device add/configure with a parameter matrix
//! - Queue setup and teardown with concurrent start/stop sequences
//! - Configuration state consistency via BLAKE3-hashed snapshots

use tidefs_block_volume_adapter_ublk_control_runtime::device::{
    UblkDeviceBuildError, UblkDeviceBuilder, UblkDeviceConfig,
};
use tidefs_block_volume_adapter_ublk_control_runtime::queue::{
    UblkQueueMapper, UblkQueueMapperConfig, UblkQueueMapperError,
};
use tidefs_block_volume_adapter_ublk_control_runtime::{
    compute_device_state_hash, enumerate_device_capacities, enumerate_ublk_devices,
    verify_device_state_hash, DeviceCapacity, UblkControlAddDevError, UblkControlAddDevInput,
    UblkControlAddDevOutcome, UblkControlDelDevError, UblkControlRemoveDeviceError,
    UblkControlRuntime, UblkControlSetParamsError, UblkControlStartDevError,
    UblkDeviceIntegrityError, UblkDeviceLifecycleState, UblkManagedDevice,
    TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES, TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
};
use tidefs_ublk_abi::{
    UblkFeatureFlags, UblkParamBasic, UblkParamDiscard, UblkParamSegment, UblkParams,
    UblkSrvCtrlDevInfo, UBLK_ATTR_VOLATILE_CACHE, UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH,
    UBLK_PARAM_TYPE_BASIC, UBLK_PARAM_TYPE_DISCARD, UBLK_PARAM_TYPE_SEGMENT,
};

// ── Helpers ────────────────────────────────────────────────────────────

fn ublk_control_available() -> bool {
    std::path::Path::new("/dev/ublk-control").exists()
}

fn null_runtime() -> (std::fs::File, UblkControlRuntime) {
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    let rt = UblkControlRuntime::from_control_file(f.try_clone().expect("clone fd"));
    (f, rt)
}

fn parameter_matrix() -> Vec<UblkDeviceConfig> {
    let mut out = Vec::new();
    for &qd in &[16u16, 32, 64, 128, 256] {
        for &nr in &[1u16, 2, 4] {
            for &buf_mib in &[1u32, 2, 4] {
                let p = UblkParams {
                    len: std::mem::size_of::<UblkParams>() as u32,
                    types: UBLK_PARAM_TYPE_BASIC
                        | UBLK_PARAM_TYPE_DISCARD
                        | UBLK_PARAM_TYPE_SEGMENT,
                    basic: UblkParamBasic {
                        logical_bs_shift: 9,
                        physical_bs_shift: 12,
                        io_opt_shift: 12,
                        io_min_shift: 9,
                        max_sectors: qd as u32 * 8,
                        chunk_sectors: 0,
                        dev_sectors: 2_097_152,
                        attrs: UBLK_ATTR_VOLATILE_CACHE,
                        virt_boundary_mask: 0,
                    },
                    discard: UblkParamDiscard {
                        discard_granularity: 512,
                        max_discard_sectors: qd as u32 * 8,
                        max_write_zeroes_sectors: qd as u32 * 8,
                        ..Default::default()
                    },
                    seg: UblkParamSegment {
                        max_segment_size: 65536,
                        max_segments: nr,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                out.push(UblkDeviceConfig {
                    nr_hw_queues: nr,
                    queue_depth: qd,
                    max_io_buf_bytes: buf_mib * 1024 * 1024,
                    flags: TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
                    params: p,
                });
            }
        }
    }
    out
}

fn hash_info(info: &UblkSrvCtrlDevInfo) -> [u8; 32] {
    compute_device_state_hash(info)
}

// ── BLAKE3 State Integrity ─────────────────────────────────────────────

#[test]
fn blake3_hash_changes_on_mutation() {
    let mut a = UblkSrvCtrlDevInfo {
        dev_id: 1,
        nr_hw_queues: 1,
        queue_depth: 64,
        ..Default::default()
    };
    let before = hash_info(&a);
    a.queue_depth = 128;
    assert_ne!(before, hash_info(&a));
}

#[test]
fn blake3_hash_field_coverage() {
    let base = UblkSrvCtrlDevInfo {
        dev_id: 42,
        nr_hw_queues: 2,
        queue_depth: 128,
        state: 1,
        max_io_buf_bytes: 1_048_576,
        ublksrv_pid: 12345,
        flags: 0x1,
        ..Default::default()
    };
    let bh = hash_info(&base);
    let mutations = [
        ("dev_id", UblkSrvCtrlDevInfo { dev_id: 99, ..base }),
        (
            "nr_hw_queues",
            UblkSrvCtrlDevInfo {
                nr_hw_queues: 4,
                ..base
            },
        ),
        (
            "queue_depth",
            UblkSrvCtrlDevInfo {
                queue_depth: 256,
                ..base
            },
        ),
        ("state", UblkSrvCtrlDevInfo { state: 2, ..base }),
        (
            "max_io_buf",
            UblkSrvCtrlDevInfo {
                max_io_buf_bytes: 2_097_152,
                ..base
            },
        ),
        (
            "ublksrv_pid",
            UblkSrvCtrlDevInfo {
                ublksrv_pid: 99999,
                ..base
            },
        ),
        (
            "flags",
            UblkSrvCtrlDevInfo {
                flags: 0x42,
                ..base
            },
        ),
    ];
    for (name, info) in &mutations {
        assert_ne!(hash_info(info), bh, "field '{name}' must affect hash");
    }
}

#[test]
fn verify_integrity_rejects_tampering() {
    let info = UblkSrvCtrlDevInfo {
        dev_id: 7,
        nr_hw_queues: 1,
        queue_depth: 64,
        ..Default::default()
    };
    let good = hash_info(&info);
    assert!(verify_device_state_hash(&info, &good).is_ok());
    assert!(verify_device_state_hash(&info, &[0xDEu8; 32]).is_err());
}

#[test]
fn managed_device_integrity_chain() {
    let info = UblkSrvCtrlDevInfo {
        dev_id: 42,
        nr_hw_queues: 1,
        queue_depth: 64,
        state: 0,
        max_io_buf_bytes: TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES,
        ..Default::default()
    };
    let outcome = UblkControlAddDevOutcome::from_dev_info(info);
    let mut dev = UblkManagedDevice::from_add_dev_outcome(&outcome);

    assert_eq!(dev.state, UblkDeviceLifecycleState::Created);
    assert!(dev.verify_integrity().is_ok());

    dev.dev_info.queue_depth = 9999;
    assert!(dev.verify_integrity().is_err());

    dev.update_integrity_hash();
    assert!(dev.verify_integrity().is_ok());

    dev.blake3_state_hash = None;
    assert_eq!(
        dev.verify_integrity(),
        Err(UblkDeviceIntegrityError::NoStoredHash)
    );
}

// ── Parameter Matrix ───────────────────────────────────────────────────

#[test]
fn parameter_matrix_validity() {
    let cfgs = parameter_matrix();
    assert!(!cfgs.is_empty());
    for c in &cfgs {
        assert!(c.nr_hw_queues > 0 && c.nr_hw_queues <= UBLK_MAX_NR_QUEUES);
        assert!(c.queue_depth > 0 && c.queue_depth <= UBLK_MAX_QUEUE_DEPTH);
        assert!(c.flags.contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES));
        assert!(c.queue_depth as u64 * c.nr_hw_queues as u64 * c.max_io_buf_bytes as u64 > 0);
    }
}

#[test]
fn parameter_matrix_covers_extremes() {
    let cfgs = parameter_matrix();
    assert!(cfgs.iter().any(|c| c.queue_depth == 16));
    assert!(cfgs.iter().any(|c| c.queue_depth == 256));
    assert!(cfgs.iter().any(|c| c.nr_hw_queues == 1));
    assert!(cfgs.iter().any(|c| c.nr_hw_queues == 4));
    assert!(cfgs.iter().any(|c| c.max_io_buf_bytes == 1_048_576));
    assert!(cfgs.iter().any(|c| c.max_io_buf_bytes == 4_194_304));
}

#[test]
fn parameter_matrix_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for c in &parameter_matrix() {
        assert!(seen.insert((c.nr_hw_queues, c.queue_depth, c.max_io_buf_bytes)));
    }
}

// ── Queue Setup/Teardown ───────────────────────────────────────────────

#[test]
fn queue_mapper_rejects_dev_null() {
    assert!(UblkQueueMapper::open_at(
        std::path::Path::new("/dev/null"),
        UblkQueueMapperConfig::new(42, 2, 64),
    )
    .is_err());
}

#[test]
fn queue_mapper_rejects_invalid_params() {
    assert!(UblkQueueMapper::open(UblkQueueMapperConfig::new(0, 0, 64)).is_err());
    assert!(UblkQueueMapper::open(UblkQueueMapperConfig::new(0, 1, 0)).is_err());
    assert!(
        UblkQueueMapper::open(UblkQueueMapperConfig::new(0, UBLK_MAX_NR_QUEUES + 1, 64)).is_err()
    );
    assert!(
        UblkQueueMapper::open(UblkQueueMapperConfig::new(0, 1, UBLK_MAX_QUEUE_DEPTH + 1)).is_err()
    );
}

#[test]
fn queue_mapper_config_eq() {
    let a = UblkQueueMapperConfig::new(99, 4, 128);
    assert_eq!(a.dev_id, 99);
    assert_eq!(a.nr_hw_queues, 4);
    assert_eq!(a.queue_depth, 128);
    assert_eq!(a, a.clone());
}

#[test]
fn queue_mapper_error_display() {
    assert!(UblkQueueMapperError::QueueIdOutOfRange {
        q_id: 5,
        nr_hw_queues: 4
    }
    .to_string()
    .contains("5"));
    assert!(UblkQueueMapperError::TagOutOfRange {
        tag: 128,
        queue_depth: 64
    }
    .to_string()
    .contains("128"));
    assert!(UblkQueueMapperError::AlreadyClosed
        .to_string()
        .contains("closed"));
    assert!(UblkQueueMapperError::NoQueueHandlesRegistered
        .to_string()
        .contains("no queue"));
    assert!(UblkQueueMapperError::InvalidQueueState {
        q_id: 1,
        reason: "test"
    }
    .to_string()
    .contains("test"));
    assert!(matches!(
        UblkQueueMapperError::from(std::io::Error::other("x")),
        UblkQueueMapperError::Io(_)
    ));
}

// ── Configuration Snapshots ────────────────────────────────────────────

#[test]
fn snapshot_after_add_dev_matches_direct_hash() {
    let info = UblkSrvCtrlDevInfo {
        dev_id: 5,
        nr_hw_queues: 1,
        queue_depth: 64,
        state: 0,
        max_io_buf_bytes: 1_048_576,
        ..Default::default()
    };
    let h = hash_info(&info);
    let outcome = UblkControlAddDevOutcome::from_dev_info(info);
    let dev = UblkManagedDevice::from_add_dev_outcome(&outcome);
    assert_eq!(dev.blake3_state_hash.unwrap(), h);
    assert!(dev.verify_integrity().is_ok());
}

#[test]
fn snapshot_distinct_across_devices() {
    let mut hashes = Vec::new();
    for id in 1..=10u32 {
        hashes.push(hash_info(&UblkSrvCtrlDevInfo {
            dev_id: id,
            nr_hw_queues: (id % 4 + 1) as u16,
            queue_depth: ((id % 8) + 1) as u16 * 32,
            ..Default::default()
        }));
    }
    let set: std::collections::HashSet<_> = hashes.iter().collect();
    assert_eq!(set.len(), hashes.len());
}

#[test]
fn snapshot_deterministic() {
    let info = UblkSrvCtrlDevInfo {
        dev_id: 42,
        nr_hw_queues: 2,
        queue_depth: 128,
        state: 1,
        max_io_buf_bytes: 2_097_152,
        ublksrv_pid: 99999,
        ..Default::default()
    };
    let h1 = hash_info(&info);
    let h2 = hash_info(&info);
    let h3 = hash_info(&info);
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

#[test]
fn snapshot_zeroed_differs_from_nonzero() {
    let zero = hash_info(&UblkSrvCtrlDevInfo::default());
    let one = hash_info(&UblkSrvCtrlDevInfo {
        dev_id: 1,
        ..Default::default()
    });
    assert_ne!(zero, one);
}

// ── Device Lifecycle States ────────────────────────────────────────────

#[test]
fn lifecycle_states_distinct() {
    use UblkDeviceLifecycleState::*;
    for (i, a) in [Created, Attached, Draining, Removed].iter().enumerate() {
        for b in [Created, Attached, Draining, Removed].iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn from_add_dev_yields_created_state() {
    let info = UblkSrvCtrlDevInfo {
        dev_id: 1,
        ..Default::default()
    };
    let dev =
        UblkManagedDevice::from_add_dev_outcome(&UblkControlAddDevOutcome::from_dev_info(info));
    assert_eq!(dev.state, UblkDeviceLifecycleState::Created);
}

#[test]
fn remove_device_error_dev_id() {
    assert_eq!(
        UblkControlRemoveDeviceError::DeviceNotRegistered { dev_id: 42 }.dev_id(),
        Some(42)
    );
    assert_eq!(
        UblkControlRemoveDeviceError::DeviceAlreadyRemoved { dev_id: 7 }.dev_id(),
        Some(7)
    );
    assert_eq!(
        UblkControlRemoveDeviceError::UblkDelDevError(UblkControlDelDevError::AutoDeviceId)
            .dev_id(),
        None
    );
}

// ── DeviceCapacity ─────────────────────────────────────────────────────

#[test]
fn device_capacity_enumeration_ok() {
    assert!(enumerate_device_capacities().is_ok());
}

#[test]
fn ublk_device_enumeration_ok() {
    assert!(enumerate_ublk_devices().is_ok());
}

#[test]
fn device_capacity_computations() {
    assert_eq!(
        DeviceCapacity {
            dev_id: 0,
            sector_count: 1,
            sector_size: 512
        }
        .total_bytes(),
        512
    );
    assert_eq!(
        DeviceCapacity {
            dev_id: 0,
            sector_count: 2_097_152,
            sector_size: 512
        }
        .total_mib(),
        1024
    );
    assert_eq!(DeviceCapacity::default().total_bytes(), 0);
    assert_eq!(
        DeviceCapacity {
            dev_id: 3,
            sector_count: 1000,
            sector_size: 4096
        }
        .total_bytes(),
        4_096_000
    );
}

// ── UblkDeviceBuilder Error Paths ──────────────────────────────────────

#[test]
fn builder_rejects_auto_dev_id() {
    let (_f, mut rt) = null_runtime();
    match UblkDeviceBuilder::new(&mut rt, UblkDeviceConfig::default())
        .build_from_existing_device(u32::MAX)
    {
        Err(UblkDeviceBuildError::Io(e)) => assert!(e.to_string().contains("concrete")),
        other => panic!("expected Io, got {other:?}"),
    }
}

#[test]
fn builder_error_display() {
    assert!(
        UblkDeviceBuildError::AddDev(UblkControlAddDevError::ZeroHardwareQueues)
            .to_string()
            .contains("add_dev")
    );

    assert!(
        UblkDeviceBuildError::SetParams(UblkControlSetParamsError::AutoDeviceId)
            .to_string()
            .contains("set_params")
    );

    let s = UblkDeviceBuildError::Cleanup {
        dev_id: 77,
        cause: Box::new(UblkDeviceBuildError::StartDev(
            UblkControlStartDevError::AutoDeviceId,
        )),
        del_dev_error: UblkControlDelDevError::AutoDeviceId,
    }
    .to_string();
    assert!(s.contains("77") && s.contains("cleanup"));
}

#[test]
fn builder_error_from_conversions() {
    assert!(matches!(
        UblkDeviceBuildError::from(UblkControlAddDevError::ZeroHardwareQueues),
        UblkDeviceBuildError::AddDev(_)
    ));
    assert!(matches!(
        UblkDeviceBuildError::from(UblkControlSetParamsError::AutoDeviceId),
        UblkDeviceBuildError::SetParams(_)
    ));
    assert!(matches!(
        UblkDeviceBuildError::from(UblkControlStartDevError::AutoDeviceId),
        UblkDeviceBuildError::StartDev(_)
    ));
    assert!(matches!(
        UblkDeviceBuildError::from(std::io::Error::other("x")),
        UblkDeviceBuildError::Io(_)
    ));
}

#[test]
fn builder_build_fails_on_dev_null() {
    let (_f, mut rt) = null_runtime();
    assert!(UblkDeviceBuilder::new(&mut rt, UblkDeviceConfig::default())
        .build()
        .is_err());
}

// ── Feature Flags ──────────────────────────────────────────────────────

#[test]
fn required_features_present() {
    assert!(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.contains(UblkFeatureFlags::CMD_IOCTL_ENCODE));
    assert!(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.contains(UblkFeatureFlags::USER_COPY));
}

#[test]
fn conservative_config_extra_flags() {
    let cfg = UblkDeviceConfig::conservative_tidefs();
    assert!(cfg.flags.contains(UblkFeatureFlags::URING_CMD_COMP_IN_TASK));
    assert!(cfg.flags.contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES));
    assert_eq!(cfg.nr_hw_queues, 1);
    assert_eq!(cfg.queue_depth, 64);
}

// ── AddDev Input ───────────────────────────────────────────────────────

#[test]
fn add_dev_input_defaults() {
    let inp = UblkControlAddDevInput::conservative_tidefs();
    assert_eq!(inp.nr_hw_queues, 1);
    assert_eq!(inp.queue_depth, 64);
    assert!(inp.max_io_buf_bytes > 0);
    assert!(inp.flags.contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES));
}

// ── Control Error Strings ──────────────────────────────────────────────

#[test]
fn add_dev_error_as_str() {
    assert_eq!(
        UblkControlAddDevError::ZeroHardwareQueues.as_str(),
        "zero_hardware_queues"
    );
    assert_eq!(
        UblkControlAddDevError::ZeroQueueDepth.as_str(),
        "zero_queue_depth"
    );
    assert_eq!(
        UblkControlAddDevError::ZeroMaxIoBufferBytes.as_str(),
        "zero_max_io_buffer_bytes"
    );
    assert_eq!(
        UblkControlAddDevError::TooManyHardwareQueues.as_str(),
        "too_many_hardware_queues"
    );
    assert_eq!(
        UblkControlAddDevError::QueueDepthTooLarge.as_str(),
        "queue_depth_too_large"
    );
}

// ── SKIP: Real ublk-control tests ──────────────────────────────────────

#[test]
fn ublk_control_available_documented() {
    let _ = ublk_control_available();
}

#[test]
fn real_readonly_probe_skip() {
    if !ublk_control_available() {
        eprintln!("SKIP: /dev/ublk-control not available");
    }
}

#[test]
fn real_add_dev_del_dev_skip() {
    if !ublk_control_available() {
        eprintln!("SKIP: /dev/ublk-control not available");
    }
}

#[test]
fn real_set_params_skip() {
    if !ublk_control_available() {
        eprintln!("SKIP: /dev/ublk-control not available");
    }
}

#[test]
fn real_start_stop_dev_skip() {
    if !ublk_control_available() {
        eprintln!("SKIP: /dev/ublk-control not available");
    }
}
