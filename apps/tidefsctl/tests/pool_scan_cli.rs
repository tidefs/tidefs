// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::process::Command;

use tidefs_local_object_store::pool_label::{
    encode_label, LabelPoolState, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
};

#[test]
fn pool_scan_json_refusal_exits_nonzero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pool_guid = [0x55; 16];
    let mut devices = Vec::new();

    for (index, generation, guid_byte) in [(0, 7, 0x61), (1, 8, 0x62)] {
        let path = dir.path().join(format!("device-{index}.img"));
        let mut label = PoolLabelV1::new(pool_guid, [guid_byte; 16], "scan-refusal");
        label.pool_state = LabelPoolState::Exported;
        label.device_index = index;
        label.device_count = 2;
        label.topology_generation = generation;
        label.device_capacity_bytes = 4096;

        let mut encoded = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut encoded).expect("encode pool label");
        std::fs::write(&path, encoded).expect("write pool label");
        devices.push(path);
    }

    let output = Command::new(env!("CARGO_BIN_EXE_tidefsctl"))
        .args(["pool", "scan", "--json", "--devices"])
        .args(&devices)
        .output()
        .expect("run tidefsctl pool scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("structured scan refusal JSON");
    let evidence = document["lifecycle_evidence"]
        .as_array()
        .expect("lifecycle evidence array");
    let row = evidence.first().expect("structured refusal evidence");

    assert_eq!(evidence.len(), 1);
    assert!(document["lifecycle_evidence_error"]
        .as_str()
        .expect("scan refusal error")
        .contains("topology_generation"));
    assert_eq!(row["schema"], "tidefs.pool-lifecycle-evidence.v1");
    assert_eq!(row["action"], "scan");
    assert_eq!(row["outcome"], "refused");
    assert_eq!(row["pool_guid"], "55555555-5555-5555-5555-555555555555");
    assert_eq!(row["topology_complete"], false);
    assert_eq!(row["owner_authorized"], false);
    assert_eq!(row["fail_closed"], true);
    assert!(row["reason"]
        .as_str()
        .expect("string reason")
        .contains("topology_generation"));
}
