// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "qemu")]

use tidefs_two_node_harness::qemu_carrier::{run_qemu_tcp_state_transfer, QemuTcpCarrierReport};
use tidefs_two_node_harness::{blake3_hash, StateObject};

fn main() {
    if let Err(err) = run() {
        eprintln!("tidefs-two-node-qemu-carrier-validation: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let seed = 42;
    let objects = validation_objects();
    let expected_digest = expected_transfer_digest(&objects);

    let report = run_qemu_tcp_state_transfer(seed, objects)?;
    if report.transfer.transfer_digest != expected_digest {
        return Err(
            "live TCP carrier transfer digest did not match expected payload digest".into(),
        );
    }

    println!("QEMU_TCP_CARRIER_REPORT_BEGIN");
    println!("{}", report_json(&report));
    println!("QEMU_TCP_CARRIER_REPORT_END");
    Ok(())
}

fn validation_objects() -> Vec<StateObject> {
    vec![
        StateObject {
            object_key: 1,
            payload: b"qemu tcp carrier control object".to_vec(),
        },
        StateObject {
            object_key: 2,
            payload: vec![0xA5; 12 * 1024],
        },
    ]
}

fn expected_transfer_digest(objects: &[StateObject]) -> [u8; 32] {
    let mut payloads = Vec::new();
    for object in objects {
        payloads.extend_from_slice(&object.payload);
    }
    blake3_hash(&payloads)
}

fn report_json(report: &QemuTcpCarrierReport) -> String {
    format!(
        "{{\"test\":\"tidefs-two-node-qemu-carrier-validation\",\
         \"validation_tier\":\"Tier 8 QEMU carrier validation\",\
         \"carrier\":{},\
         \"qemu_guest_detected\":{},\
         \"sender_node_id\":{},\
         \"receiver_node_id\":{},\
         \"receiver_addr\":{},\
         \"object_count\":{},\
         \"total_bytes\":{},\
         \"chunk_count\":{},\
         \"transfer_digest\":\"{}\"}}",
        json_string(report.carrier),
        report.qemu_guest_detected,
        report.sender_node_id,
        report.receiver_node_id,
        json_string(&report.receiver_addr),
        report.transfer.object_count,
        report.transfer.total_bytes,
        report.transfer.chunk_count,
        hex_digest(&report.transfer.transfer_digest),
    )
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
