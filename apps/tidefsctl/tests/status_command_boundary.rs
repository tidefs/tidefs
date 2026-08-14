// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::fs::{self, File};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{SystemTime, UNIX_EPOCH};

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
