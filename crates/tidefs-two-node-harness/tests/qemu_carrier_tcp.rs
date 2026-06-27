// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "qemu")]

use tidefs_two_node_harness::qemu_carrier::run_qemu_tcp_state_transfer;
use tidefs_two_node_harness::{blake3_hash, StateObject};

#[test]
fn qemu_tcp_carrier_state_transfer() {
    let seed = 42;
    let objects = vec![
        StateObject {
            object_key: 1,
            payload: b"qemu tcp carrier control object".to_vec(),
        },
        StateObject {
            object_key: 2,
            payload: vec![0xA5; 12 * 1024],
        },
    ];
    let expected_digest = {
        let mut payloads = Vec::new();
        for object in &objects {
            payloads.extend_from_slice(&object.payload);
        }
        blake3_hash(&payloads)
    };

    let report = run_qemu_tcp_state_transfer(seed, objects).expect("live TCP carrier transfer");

    assert_eq!(report.carrier, "tcp");
    assert_eq!(report.transfer.object_count, 2);
    assert_eq!(report.transfer.total_bytes, 12 * 1024 + 31);
    assert_eq!(report.transfer.chunk_count, 4);
    assert_eq!(report.transfer.transfer_digest, expected_digest);

    println!("QEMU_TCP_CARRIER_REPORT_BEGIN");
    println!(
        "{}",
        serde_json::json!({
            "carrier": report.carrier,
            "qemu_guest_detected": report.qemu_guest_detected,
            "object_count": report.transfer.object_count,
            "total_bytes": report.transfer.total_bytes,
            "chunk_count": report.transfer.chunk_count,
            "receiver_addr": report.receiver_addr,
        })
    );
    println!("QEMU_TCP_CARRIER_REPORT_END");
}
