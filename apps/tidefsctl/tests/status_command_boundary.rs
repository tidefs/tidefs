// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId, SyncGuarantee};
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RecoveryPolicy, RootAuthenticationKey,
};
use tidefs_local_object_store::pool::{PoolHealth, PoolRedundancyPolicy};
use tidefs_posix_filesystem_adapter_daemon::{
    fuse_vfs_adapter::FuseVfsAdapter,
    live_owner::{start_fuse_owner, LiveOwnerConfig},
};

static NEXT_POOL_ID: AtomicU64 = AtomicU64::new(0);
const STATUS_COMMANDS: &[&str] = &[
    #[cfg(feature = "cluster")]
    "cluster",
    "device",
];

fn prepare_volume_lifecycle_graph(
    filesystem: &mut LocalFileSystem,
    dataset_id_byte: u8,
    committed_byte: u8,
    clone_byte: u8,
    staged_byte: u8,
) -> tidefs_pool_runtime::PoolVolume {
    filesystem
        .create_volume_dataset(
            "volume",
            DatasetId::from_bytes([dataset_id_byte; 16]),
            2 * 1024 * 1024,
            Vec::new(),
            DatasetFlags::default_create(),
            SyncGuarantee::Local,
        )
        .expect("create Pool-owned volume for device lifecycle");
    let mut volume = filesystem
        .open_volume_dataset("volume")
        .expect("open Pool-owned volume");
    filesystem
        .write_volume_blocks(&mut volume, 0, &vec![committed_byte; 4096])
        .expect("stage committed source volume block");
    filesystem
        .flush_volume(&mut volume)
        .expect("commit source volume block");
    filesystem
        .create_volume_snapshot_dataset("volume@before")
        .expect("create Pool-owned volume snapshot");
    filesystem
        .create_volume_clone_dataset("clone", "volume@before")
        .expect("create Pool-owned volume clone");
    let mut clone = filesystem
        .open_volume_dataset("clone")
        .expect("open Pool-owned volume clone");
    filesystem
        .write_volume_blocks(&mut clone, 0, &vec![clone_byte; 4096])
        .expect("stage clone block");
    filesystem
        .flush_volume(&mut clone)
        .expect("commit clone block");

    let mut active = filesystem
        .open_volume_dataset("volume")
        .expect("open active volume handle");
    filesystem
        .write_volume_blocks(&mut active, 1, &vec![staged_byte; 4096])
        .expect("stage private block across topology mutation");
    active
}

fn assert_and_flush_live_volume_graph(
    filesystem: &mut LocalFileSystem,
    active: &mut tidefs_pool_runtime::PoolVolume,
    committed_byte: u8,
    clone_byte: u8,
    staged_byte: u8,
) {
    let mut expected_source = vec![committed_byte; 4096];
    expected_source.extend(vec![staged_byte; 4096]);
    assert_eq!(
        filesystem
            .read_volume_blocks(active, 0, 2)
            .expect("read active volume after topology mutation"),
        expected_source,
        "active handle must retain committed and private staged blocks"
    );
    filesystem
        .flush_volume(active)
        .expect("flush staged block through the new topology");

    let clone = filesystem
        .open_volume_dataset("clone")
        .expect("open clone after topology mutation");
    assert_eq!(
        filesystem
            .read_volume_blocks(&clone, 0, 1)
            .expect("read clone after topology mutation"),
        vec![clone_byte; 4096]
    );
    let snapshots = filesystem
        .list_volume_snapshot_datasets()
        .expect("validate volume snapshots after topology mutation");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].path, "volume@before");
}

fn assert_reimported_volume_graph(
    filesystem: &mut LocalFileSystem,
    committed_byte: u8,
    clone_byte: u8,
    staged_byte: u8,
) {
    let source = filesystem
        .open_volume_dataset("volume")
        .expect("open source volume after reimport");
    let mut expected_source = vec![committed_byte; 4096];
    expected_source.extend(vec![staged_byte; 4096]);
    assert_eq!(
        filesystem
            .read_volume_blocks(&source, 0, 2)
            .expect("read source volume after reimport"),
        expected_source
    );

    let clone = filesystem
        .open_volume_dataset("clone")
        .expect("open clone after reimport");
    assert_eq!(
        filesystem
            .read_volume_blocks(&clone, 0, 1)
            .expect("read clone after reimport"),
        vec![clone_byte; 4096]
    );
    let snapshots = filesystem
        .list_volume_snapshot_datasets()
        .expect("validate volume snapshot after reimport");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].path, "volume@before");

    filesystem
        .create_volume_clone_dataset("snapshot-check", "volume@before")
        .expect("clone retained snapshot after reimport");
    let snapshot_check = filesystem
        .open_volume_dataset("snapshot-check")
        .expect("open verification clone after reimport");
    let mut expected_snapshot = vec![committed_byte; 4096];
    expected_snapshot.extend(vec![0; 4096]);
    assert_eq!(
        filesystem
            .read_volume_blocks(&snapshot_check, 0, 2)
            .expect("read exact retained snapshot bytes after reimport"),
        expected_snapshot
    );
}

fn open_named_filesystem(
    metadata_dir: &std::path::Path,
    devices: &[PathBuf],
    pool_name: &str,
    redundancy_policy: PoolRedundancyPolicy,
    dataset_path: &str,
) -> LocalFileSystem {
    LocalFileSystem::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
        metadata_dir,
        pool_name,
        redundancy_policy,
        dataset_path,
        tidefs_local_filesystem::LocalFileSystemOpenConfig {
            options: StoreOptions::default(),
            allocator_policy: tidefs_local_filesystem::LocalStorageAllocatorPolicy::default(),
            root_authentication_key: RootAuthenticationKey::demo_key(),
            encryption: None,
            compression: None,
            log_device_device_path: None,
            recovery_policy: RecoveryPolicy::default(),
            block_devices: Some(devices),
        },
    )
    .expect("open independently rooted filesystem")
}

fn prepare_independent_filesystem_lifecycle_graph(
    mut filesystem: LocalFileSystem,
    metadata_dir: &std::path::Path,
    devices: &[PathBuf],
    pool_name: &str,
    redundancy_policy: PoolRedundancyPolicy,
    dataset_id_byte: u8,
    payload_byte: u8,
) -> (LocalFileSystem, Vec<u8>) {
    filesystem
        .create_filesystem_dataset(
            "other",
            DatasetId::from_bytes([dataset_id_byte; 16]),
            Vec::new(),
            DatasetFlags::default_create(),
            SyncGuarantee::Local,
        )
        .expect("create independently rooted filesystem");
    filesystem
        .sync_all()
        .expect("commit root catalog before independent filesystem open");
    drop(filesystem);

    let payload = vec![payload_byte; 8193];
    let mut independent =
        open_named_filesystem(metadata_dir, devices, pool_name, redundancy_policy, "other");
    independent
        .create_file("/independent.bin", 0o600)
        .expect("create independent lifecycle file");
    independent
        .write_file("/independent.bin", 0, &payload)
        .expect("write independent lifecycle bytes");
    independent
        .sync_all()
        .expect("commit independent lifecycle bytes");
    drop(independent);

    let root = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        metadata_dir,
        devices,
        pool_name,
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("reopen root filesystem as sole Pool lifecycle owner");
    (root, payload)
}

fn assert_reimported_independent_filesystem(
    metadata_dir: &std::path::Path,
    devices: &[PathBuf],
    pool_name: &str,
    redundancy_policy: PoolRedundancyPolicy,
    expected: &[u8],
) {
    let independent =
        open_named_filesystem(metadata_dir, devices, pool_name, redundancy_policy, "other");
    assert_eq!(
        independent
            .read_file("/independent.bin")
            .expect("read independent filesystem after topology reimport"),
        expected
    );
}

fn assert_reimported_filesystem_snapshot(
    filesystem: &mut LocalFileSystem,
    snapshot_name: &str,
    expected_files: &[(String, Vec<u8>)],
) {
    filesystem
        .snapshot_summary(snapshot_name)
        .expect("retained filesystem snapshot after topology reimport");
    filesystem
        .rollback_to_snapshot(snapshot_name)
        .expect("rollback retained filesystem snapshot after topology reimport");
    for (path, expected) in expected_files {
        assert_eq!(
            filesystem
                .read_file(path)
                .expect("read rolled-back filesystem snapshot bytes"),
            *expected,
            "snapshot rollback mismatch for {path}"
        );
    }
}

fn remove_legacy_device_lifecycle_files(metadata_dir: &std::path::Path) {
    for name in [
        ".tidefs_device_removal_pending",
        ".tidefs_device_removal_pending.tmp",
        ".tidefs_device_replacement_evidence",
        ".tidefs_device_replacement_evidence.tmp",
    ] {
        match fs::remove_file(metadata_dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove obsolete lifecycle side file {name}: {error}"),
        }
    }
}

fn assert_legacy_device_lifecycle_files_absent(metadata_dir: &std::path::Path) {
    for name in [
        ".tidefs_device_removal_pending",
        ".tidefs_device_removal_pending.tmp",
        ".tidefs_device_replacement_evidence",
        ".tidefs_device_replacement_evidence.tmp",
    ] {
        assert!(
            !metadata_dir.join(name).exists(),
            "obsolete lifecycle side file {name} must not be recovery authority"
        );
    }
}

fn run_status(command: &str, json: bool) -> (String, Output) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let pool_name = format!(
        "status-boundary-{}-{now}-{}-{command}",
        std::process::id(),
        NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed)
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_tidefsctl"));
    process.args([command, "status", &pool_name]);
    if json {
        process.arg("--json");
    }
    let output = process.output().expect("run tidefsctl status command");
    (pool_name, output)
}

#[test]
fn no_owner_status_is_an_operator_refusal() {
    for &command in STATUS_COMMANDS {
        let (pool_name, output) = run_status(command, false);
        assert_eq!(output.status.code(), Some(1), "{command} status");
        assert!(output.stdout.is_empty(), "{command} status wrote stdout");

        let stderr = String::from_utf8(output.stderr).expect("human refusal is UTF-8");
        for expected in [
            format!("tidefsctl {command} status"),
            pool_name,
            "[source:unavailable-live-owner]".to_string(),
            "[source:unsupported-local-mode]".to_string(),
            "cached local metadata".to_string(),
            "non-authoritative".to_string(),
        ] {
            assert!(
                stderr.contains(&expected),
                "{command} status stderr omitted {expected:?}:\n{stderr}"
            );
        }
    }
}

#[test]
fn no_owner_status_json_is_a_machine_refusal() {
    for &command in STATUS_COMMANDS {
        let (pool_name, output) = run_status(command, true);
        assert_eq!(output.status.code(), Some(1), "{command} status --json");
        assert!(
            output.stderr.is_empty(),
            "{command} status --json wrote stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON refusal is parseable");
        assert_eq!(value["ok"], false, "{command} status --json");
        assert_eq!(value["command"], command, "{command} status --json");
        assert_eq!(value["operation"], "status", "{command} status --json");
        assert_eq!(value["pool_name"], pool_name, "{command} status --json");
        assert_eq!(
            value["source_classification"], "source:unavailable-live-owner",
            "{command} status --json"
        );
        assert_eq!(
            value["source:status"], "source:unavailable-live-owner",
            "{command} status --json"
        );
        assert_eq!(
            value["local_mode_classification"], "source:unsupported-local-mode",
            "{command} status --json"
        );
        assert!(
            value["error"].as_str().is_some_and(|error| {
                error.contains("no live status evidence obtained")
                    && error.contains("cached local metadata is non-authoritative")
            }),
            "{command} status --json omitted the refusal error: {value}"
        );
        assert!(
            value["recovery"]
                .as_str()
                .is_some_and(|recovery| recovery.contains("start or repair")),
            "{command} status --json omitted recovery guidance: {value}"
        );
    }
}

#[test]
fn no_owner_device_replace_json_refuses_without_touching_paths() {
    let pool_name = format!(
        "replace-no-owner-{}-{}",
        std::process::id(),
        NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args([
            "device",
            "replace",
            &pool_name,
            "/definitely/missing/tidefs-old-device",
            "/definitely/missing/tidefs-new-device",
            "--json",
        ])
        .output()
        .expect("run no-owner device replace");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let refusal: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse replacement refusal JSON");
    assert_eq!(refusal["ok"], false);
    assert_eq!(refusal["command"], "device");
    assert_eq!(refusal["operation"], "replace");
    assert_eq!(refusal["pool_name"], pool_name);
    assert_eq!(refusal["owner_required"], true);
    assert_eq!(refusal["source:status"], "source:unsupported-or-offline");
}

fn hex_guid(guid: &[u8; 16]) -> String {
    guid.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[test]
fn live_degraded_pool_status_reports_durable_member_identity() {
    let fixture = tempfile::tempdir().expect("create degraded status fixture");
    let metadata_dir = fixture.path().join("metadata");
    let devices = [
        fixture.path().join("member-0.img"),
        fixture.path().join("member-1.img"),
    ];
    fs::create_dir_all(&metadata_dir).expect("create Pool metadata directory");
    for device in &devices {
        File::create(device)
            .expect("create regular-file Pool member")
            .set_len(16 * 1024 * 1024)
            .expect("size regular-file Pool member");
    }

    let pool_name = format!(
        "status-degraded-{}-{}",
        std::process::id(),
        NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed)
    );
    let redundancy_policy = PoolRedundancyPolicy::replicated(2);
    let mut filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        &devices,
        &pool_name,
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("create two-member filesystem");
    filesystem.sync_all().expect("sync two-member filesystem");
    let initial_topology = filesystem.pool_topology_status();
    assert_eq!(initial_topology.health, PoolHealth::Online);
    assert_eq!(initial_topology.members.len(), 2);
    let missing_guid = initial_topology.members[0].device_guid;
    let present_guid = initial_topology.members[1].device_guid;
    drop(filesystem);
    let scanned = tidefs_pool_scan::scan_labels(&devices).expect("scan created Pool labels");
    let pool_uuid = scanned[0].pool_guid.expect("created label has a Pool UUID");
    assert_eq!(scanned[1].pool_guid, Some(pool_uuid));

    let offline_member = fixture.path().join("offline-member-0.img");
    fs::rename(&devices[0], &offline_member).expect("make member zero physically absent");
    let surviving_devices = [devices[1].clone()];
    let filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        &surviving_devices,
        &pool_name,
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::ReadOnly,
    )
    .expect("import surviving member read-only");
    let topology = filesystem.pool_topology_status();
    assert_eq!(topology.health, PoolHealth::Degraded);
    assert!(topology.read_only);
    assert_eq!(topology.members[0].device_guid, missing_guid);
    assert!(!topology.members[0].present);
    assert_eq!(topology.members[1].device_guid, present_guid);
    assert!(topology.members[1].present);

    let engine = VfsLocalFileSystem::new(filesystem).with_read_only();
    let shared_filesystem = engine.shared_filesystem();
    let adapter = FuseVfsAdapter::new(Box::new(engine))
        .expect("create live-owner adapter")
        .with_read_only();
    let runtime_dir = PathBuf::from("/run/tidefs/pools").join(hex_guid(&pool_uuid));
    assert!(
        !runtime_dir.exists(),
        "unique test Pool runtime directory unexpectedly exists: {}",
        runtime_dir.display()
    );
    let shutdown = Arc::new(AtomicBool::new(false));
    let owner = start_fuse_owner(
        LiveOwnerConfig {
            pool_name: pool_name.clone(),
            pool_uuid,
            backing_dir: metadata_dir.clone(),
            mountpoint: fixture.path().join("not-mounted"),
            runtime_dir: runtime_dir.clone(),
            read_only: true,
        },
        adapter.engine_handle(),
        adapter.dataset_replacement_handle(),
        shared_filesystem,
        Arc::clone(&shutdown),
    )
    .expect("start live owner for degraded Pool");

    let json_output = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args(["pool", "status", &pool_name, "--json"])
        .output()
        .expect("run live degraded pool status --json");
    let human_output = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args(["pool", "status", &pool_name])
        .output()
        .expect("run live degraded pool status");

    owner.stop();
    fs::remove_dir(&runtime_dir).expect("remove empty test Pool runtime directory");

    assert!(json_output.status.success(), "{json_output:?}");
    assert!(json_output.stderr.is_empty(), "{json_output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("parse live Pool status JSON");
    assert_eq!(value["source_classification"], "source:live-owner");
    assert_eq!(value["health"], "Degraded");
    assert_eq!(value["access"], "ReadOnly");
    assert_eq!(value["members_expected"], 2);
    assert_eq!(value["members_present"], 1);
    assert_eq!(value["members_missing"], 1);
    assert_eq!(value["members"][0]["index"], 0);
    assert_eq!(value["members"][0]["guid"], hex_guid(&missing_guid));
    assert_eq!(value["members"][0]["presence"], "Missing");
    assert_eq!(value["members"][1]["index"], 1);
    assert_eq!(value["members"][1]["guid"], hex_guid(&present_guid));
    assert_eq!(value["members"][1]["presence"], "Present");

    assert!(human_output.status.success(), "{human_output:?}");
    assert!(human_output.stderr.is_empty(), "{human_output:?}");
    let human = String::from_utf8(human_output.stdout).expect("human status is UTF-8");
    assert!(human.contains("health:      Degraded"), "{human}");
    assert!(human.contains("access:      ReadOnly"), "{human}");
    assert!(
        human.contains("members:     expected=2 present=1 missing=1"),
        "{human}"
    );
    assert!(
        human.contains(&format!("member 0:   {} Missing", hex_guid(&missing_guid))),
        "{human}"
    );
    assert!(
        human.contains(&format!("member 1:   {} Present", hex_guid(&present_guid))),
        "{human}"
    );
}

#[test]
fn pool_destroy_zero_superblock_retires_redundant_labels() {
    let fixture = tempfile::tempdir().expect("create pool destroy fixture");
    let device = fixture.path().join("member-0.img");
    File::create(&device)
        .expect("create regular-file Pool member")
        .set_len(16 * 1024 * 1024)
        .expect("size regular-file Pool member");
    let pool_name = format!(
        "pool-destroy-{}-{}",
        std::process::id(),
        NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed)
    );

    let create = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args([
            "pool",
            "create",
            &pool_name,
            "--file-devices",
            "--devices",
            device.to_str().expect("UTF-8 device path"),
            "--json",
        ])
        .output()
        .expect("create exported Pool through tidefsctl");
    assert!(create.status.success(), "{create:?}");

    let device_size = device.metadata().expect("stat Pool member").len();
    let label_size = tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64;
    let label_offsets = [0, device_size - label_size];
    assert_ne!(label_offsets[0], label_offsets[1]);
    let mut file = File::open(&device).expect("open created Pool member");
    for offset in label_offsets {
        let mut magic = [0u8; 4];
        file.seek(SeekFrom::Start(offset))
            .expect("seek created label copy");
        file.read_exact(&mut magic)
            .expect("read created label magic");
        assert_eq!(magic, tidefs_types_pool_label_core::POOL_LABEL_MAGIC);
    }
    drop(file);

    let destroy = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args([
            "pool",
            "destroy",
            &pool_name,
            "--zero-superblock",
            "--json",
            "--devices",
            device.to_str().expect("UTF-8 device path"),
        ])
        .output()
        .expect("destroy exported Pool through tidefsctl");
    assert!(destroy.status.success(), "{destroy:?}");
    assert!(destroy.stderr.is_empty(), "{destroy:?}");
    let result: serde_json::Value =
        serde_json::from_slice(&destroy.stdout).expect("parse pool destroy JSON");
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["zero_superblock"], true, "{result}");
    assert_eq!(result["redundant_label_areas_zeroed"], true, "{result}");
    assert_eq!(result["media_privacy_claimed"], false, "{result}");
    assert_eq!(result["secure_erase_claimed"], false, "{result}");
    assert_eq!(result["sanitization_claimed"], false, "{result}");
    assert_eq!(result["decommissioning_claimed"], false, "{result}");

    let mut file = File::open(&device).expect("reopen destroyed Pool member");
    for offset in label_offsets {
        let mut label_area = vec![0u8; label_size as usize];
        file.seek(SeekFrom::Start(offset))
            .expect("seek destroyed label copy");
        file.read_exact(&mut label_area)
            .expect("read destroyed label area");
        assert!(
            label_area.iter().all(|byte| *byte == 0),
            "label copy at {offset} was not zeroed"
        );
    }
    let entries = tidefs_pool_scan::scan_labels(std::slice::from_ref(&device))
        .expect("scan zeroed Pool member");
    assert!(!entries[0].has_tidefs_label);
}

#[test]
fn live_device_remove_cli_commits_survivor_topology() {
    let fixture = tempfile::tempdir().expect("create live removal fixture");
    let metadata_dir = fixture.path().join("metadata");
    let devices = [
        fixture.path().join("member-0.img"),
        fixture.path().join("member-1.img"),
    ];
    fs::create_dir_all(&metadata_dir).expect("create Pool metadata directory");
    for device in &devices {
        File::create(device)
            .expect("create regular-file Pool member")
            .set_len(16 * 1024 * 1024)
            .expect("size regular-file Pool member");
    }

    let pool_name = format!(
        "device-remove-{}-{}",
        std::process::id(),
        NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed)
    );
    let redundancy_policy = PoolRedundancyPolicy::replicated(1);
    let mut filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        &devices,
        &pool_name,
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("create two-member filesystem");

    let mut expected_files = Vec::new();
    for index in 0..4u8 {
        let path = format!("/remove-{index:02}.bin");
        let payload = vec![index.wrapping_add(1); 4096 + index as usize];
        filesystem
            .create_file(&path, 0o600)
            .expect("create receipt-backed mounted file");
        filesystem
            .write_file(&path, 0, &payload)
            .expect("write receipt-backed mounted file");
        expected_files.push((path, payload));
    }
    filesystem
        .sync_all()
        .expect("sync mounted files before removal");
    let snapshot_name = "before-remove-overwrite";
    let snapshot_files = expected_files.clone();
    filesystem
        .create_snapshot(snapshot_name)
        .expect("create mounted filesystem snapshot before removal");
    expected_files[0].1 = vec![0xa1; expected_files[0].1.len()];
    filesystem
        .write_file(&expected_files[0].0, 0, &expected_files[0].1)
        .expect("overwrite current mounted bytes after snapshot");
    filesystem
        .sync_all()
        .expect("sync post-snapshot current bytes before removal");
    let (mut filesystem, independent_payload) = prepare_independent_filesystem_lifecycle_graph(
        filesystem,
        &metadata_dir,
        &devices,
        &pool_name,
        redundancy_policy,
        0x81,
        0x61,
    );
    let mut active_volume = prepare_volume_lifecycle_graph(&mut filesystem, 0x71, 0x31, 0x41, 0x51);

    let scanned = tidefs_pool_scan::scan_labels(&devices).expect("scan created Pool labels");
    let pool_uuid = scanned[0].pool_guid.expect("created label has a Pool UUID");
    assert_eq!(scanned[1].pool_guid, Some(pool_uuid));

    let engine = VfsLocalFileSystem::new(filesystem);
    let shared_filesystem = engine.shared_filesystem();
    let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create live-owner adapter");
    let runtime_dir = PathBuf::from("/run/tidefs/pools").join(hex_guid(&pool_uuid));
    assert!(
        !runtime_dir.exists(),
        "unique test Pool runtime directory unexpectedly exists: {}",
        runtime_dir.display()
    );
    let shutdown = Arc::new(AtomicBool::new(false));
    let owner = start_fuse_owner(
        LiveOwnerConfig {
            pool_name: pool_name.clone(),
            pool_uuid,
            backing_dir: metadata_dir.clone(),
            mountpoint: fixture.path().join("not-mounted"),
            runtime_dir: runtime_dir.clone(),
            read_only: false,
        },
        adapter.engine_handle(),
        adapter.dataset_replacement_handle(),
        shared_filesystem.clone(),
        Arc::clone(&shutdown),
    )
    .expect("start live owner for device removal");

    let output = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args([
            "device",
            "remove",
            &pool_name,
            devices[1].to_str().expect("UTF-8 device path"),
        ])
        .output()
        .expect("run tidefsctl device remove");

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("device remove output is UTF-8");
    for expected in [
        "receipt-backed evacuation",
        "durable survivor topology commit",
        "remaining_devices=1",
        "does not establish secure erase",
        "media-remanence",
        "decommissioning guarantees",
    ] {
        assert!(
            stdout.contains(expected),
            "output omitted {expected:?}: {stdout}"
        );
    }
    assert!(
        stdout.contains("objects_evacuated=") && !stdout.contains("objects_evacuated=0"),
        "test data must exercise actual target evacuation: {stdout}"
    );
    assert_legacy_device_lifecycle_files_absent(&metadata_dir);

    {
        let mut filesystem = shared_filesystem.borrow_mut();
        assert_eq!(filesystem.pool_topology_status().members.len(), 1);
        for (path, expected) in &expected_files {
            assert_eq!(
                filesystem
                    .read_file(path)
                    .expect("read file through live owner after removal"),
                *expected,
                "live owner read mismatch for {path}"
            );
        }
        assert_and_flush_live_volume_graph(&mut filesystem, &mut active_volume, 0x31, 0x41, 0x51);
    }

    owner.stop();
    drop(shared_filesystem);
    drop(adapter);
    fs::remove_dir(&runtime_dir).expect("remove empty test Pool runtime directory");
    remove_legacy_device_lifecycle_files(&metadata_dir);
    assert_legacy_device_lifecycle_files_absent(&metadata_dir);

    let survivor = [devices[0].clone()];
    let mut reopened = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        &survivor,
        &pool_name,
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("reimport survivor-only committed topology");
    assert_eq!(reopened.pool_topology_status().members.len(), 1);
    for (path, expected) in &expected_files {
        assert_eq!(
            reopened
                .read_file(path)
                .expect("read file after survivor-only reimport"),
            *expected,
            "survivor-only read mismatch for {path}"
        );
    }
    assert_reimported_volume_graph(&mut reopened, 0x31, 0x41, 0x51);
    assert_reimported_filesystem_snapshot(&mut reopened, snapshot_name, &snapshot_files);
    drop(reopened);
    assert_reimported_independent_filesystem(
        &metadata_dir,
        &survivor,
        &pool_name,
        redundancy_policy,
        &independent_payload,
    );
}

#[test]
fn live_device_replace_cli_rebuilds_and_reimports() {
    let fixture = tempfile::tempdir().expect("create live replacement fixture");
    let metadata_dir = fixture.path().join("metadata");
    let devices = [
        fixture.path().join("member-0.img"),
        fixture.path().join("member-1.img"),
    ];
    let replacement = fixture.path().join("replacement.img");
    fs::create_dir_all(&metadata_dir).expect("create Pool metadata directory");
    for device in devices.iter().chain(std::iter::once(&replacement)) {
        File::create(device)
            .expect("create regular-file Pool member")
            .set_len(16 * 1024 * 1024)
            .expect("size regular-file Pool member");
    }

    let pool_name = format!(
        "device-replace-{}-{}",
        std::process::id(),
        NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed)
    );
    let redundancy_policy = PoolRedundancyPolicy::replicated(2);
    let mut filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        &devices,
        &pool_name,
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("create two-member replicated filesystem");

    let mut expected_files = vec![
        ("/replace-a.bin".to_string(), vec![0x2a; 8193]),
        (
            "/replace-b.bin".to_string(),
            (0..=255).cycle().take(12289).collect(),
        ),
    ];
    for (path, payload) in &expected_files {
        filesystem
            .create_file(path, 0o600)
            .expect("create committed replacement file");
        filesystem
            .write_file(path, 0, payload)
            .expect("write committed replacement bytes");
    }
    filesystem
        .sync_all()
        .expect("sync mounted files before replacement");
    let snapshot_name = "before-replace-overwrite";
    let snapshot_files = expected_files.clone();
    filesystem
        .create_snapshot(snapshot_name)
        .expect("create mounted filesystem snapshot before replacement");
    expected_files[0].1 = vec![0xb2; expected_files[0].1.len()];
    filesystem
        .write_file(&expected_files[0].0, 0, &expected_files[0].1)
        .expect("overwrite current mounted bytes after snapshot");
    filesystem
        .sync_all()
        .expect("sync post-snapshot current bytes before replacement");
    let (mut filesystem, independent_payload) = prepare_independent_filesystem_lifecycle_graph(
        filesystem,
        &metadata_dir,
        &devices,
        &pool_name,
        redundancy_policy,
        0x82,
        0x62,
    );
    let mut active_volume = prepare_volume_lifecycle_graph(&mut filesystem, 0x72, 0x32, 0x42, 0x52);

    let scanned = tidefs_pool_scan::scan_labels(&devices).expect("scan created Pool labels");
    let pool_uuid = scanned[0].pool_guid.expect("created label has a Pool UUID");
    assert_eq!(scanned[1].pool_guid, Some(pool_uuid));

    let engine = VfsLocalFileSystem::new(filesystem);
    let shared_filesystem = engine.shared_filesystem();
    let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create live-owner adapter");
    let runtime_dir = PathBuf::from("/run/tidefs/pools").join(hex_guid(&pool_uuid));
    assert!(
        !runtime_dir.exists(),
        "unique test Pool runtime directory unexpectedly exists: {}",
        runtime_dir.display()
    );
    let shutdown = Arc::new(AtomicBool::new(false));
    let owner = start_fuse_owner(
        LiveOwnerConfig {
            pool_name: pool_name.clone(),
            pool_uuid,
            backing_dir: metadata_dir.clone(),
            mountpoint: fixture.path().join("not-mounted"),
            runtime_dir: runtime_dir.clone(),
            read_only: false,
        },
        adapter.engine_handle(),
        adapter.dataset_replacement_handle(),
        shared_filesystem.clone(),
        Arc::clone(&shutdown),
    )
    .expect("start live owner for device replacement");

    let output = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args([
            "device",
            "replace",
            &pool_name,
            devices[0].to_str().expect("UTF-8 old device path"),
            replacement.to_str().expect("UTF-8 replacement device path"),
            "--json",
        ])
        .output()
        .expect("run tidefsctl device replace");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse replacement result JSON");
    assert_eq!(result["status"], "completed", "{result}");
    assert_eq!(result["topology_committed"], true, "{result}");
    assert_eq!(result["objects_failed"], 0, "{result}");
    assert_eq!(result["old_device_detach_allowed"], true, "{result}");
    assert_eq!(result["media_privacy_claimed"], false, "{result}");
    assert_eq!(result["secure_erase_claimed"], false, "{result}");
    assert_eq!(result["sanitization_claimed"], false, "{result}");
    assert_eq!(result["decommissioning_claimed"], false, "{result}");
    assert_legacy_device_lifecycle_files_absent(&metadata_dir);

    let status_output = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args(["device", "status", &pool_name, "--json"])
        .output()
        .expect("run live device status after replacement");
    assert!(status_output.status.success(), "{status_output:?}");
    let status: serde_json::Value = serde_json::from_slice(&status_output.stdout)
        .expect("parse replacement device status JSON");
    assert_eq!(status["source_classification"], "source:live-owner");
    assert_eq!(status["replacement"]["state"], "completed");
    assert_eq!(status["replacement"]["complete"], true);
    assert_eq!(status["replacement"]["old_device_detach_allowed"], true);

    {
        let mut filesystem = shared_filesystem.borrow_mut();
        assert_eq!(filesystem.pool_topology_status().members.len(), 2);
        for (path, expected) in &expected_files {
            assert_eq!(
                filesystem
                    .read_file(path)
                    .expect("read file through live owner after replacement"),
                *expected,
                "live owner read mismatch for {path}"
            );
        }
        assert_and_flush_live_volume_graph(&mut filesystem, &mut active_volume, 0x32, 0x42, 0x52);
    }

    owner.stop();
    drop(shared_filesystem);
    drop(adapter);
    fs::remove_dir(&runtime_dir).expect("remove empty test Pool runtime directory");
    remove_legacy_device_lifecycle_files(&metadata_dir);
    assert_legacy_device_lifecycle_files_absent(&metadata_dir);

    let replacement_topology = [replacement.clone(), devices[1].clone()];
    let mut reopened = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        &replacement_topology,
        &pool_name,
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("reimport replacement plus survivor topology");
    assert_eq!(reopened.pool_topology_status().members.len(), 2);
    for (path, expected) in &expected_files {
        assert_eq!(
            reopened
                .read_file(path)
                .expect("read exact bytes after replacement reimport"),
            *expected,
            "replacement reimport read mismatch for {path}"
        );
    }
    assert_reimported_volume_graph(&mut reopened, 0x32, 0x42, 0x52);
    assert_reimported_filesystem_snapshot(&mut reopened, snapshot_name, &snapshot_files);
    drop(reopened);
    assert_reimported_independent_filesystem(
        &metadata_dir,
        &replacement_topology,
        &pool_name,
        redundancy_policy,
        &independent_payload,
    );
}
