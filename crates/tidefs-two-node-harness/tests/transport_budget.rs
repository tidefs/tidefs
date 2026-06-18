// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport budget measurement for REL-MN-011 multi-node performance gate.
//!
//! Runs a deterministic two-node state transfer round-trip at multiple payload
//! sizes, measures wall-clock latency and effective throughput, and outputs
//! parseable JSON KPIs with carrier mode disclosure.

use std::time::Instant;
use tidefs_two_node_harness::{StateObject, TwoNodeHarness};

const PAYLOAD_SIZES: &[usize] = &[256, 1024, 4096, 16384, 65536, 262144];
const WARMUP_RTPS: u32 = 3;
const MEASURE_RTPS: u32 = 10;

#[test]
#[ignore = "timed budget measurement; run with --ignored"]
fn transport_budget_measure() {
    let mut results: Vec<serde_json::Value> = Vec::new();

    for &size in PAYLOAD_SIZES {
        for _ in 0..WARMUP_RTPS {
            run_round_trip(size);
        }

        let mut latencies_us = Vec::with_capacity(MEASURE_RTPS as usize);
        let mut total_bytes: u64 = 0;
        for _ in 0..MEASURE_RTPS {
            let (lat_us, bytes) = run_round_trip(size);
            latencies_us.push(lat_us);
            total_bytes = bytes;
        }

        let avg_lat_us: f64 = latencies_us.iter().sum::<u64>() as f64 / latencies_us.len() as f64;
        let throughput_mb_s = if avg_lat_us > 0.0 {
            (total_bytes as f64 / (1024.0 * 1024.0)) / (avg_lat_us / 1_000_000.0)
        } else {
            0.0
        };

        results.push(serde_json::json!({
            "payload_size_bytes": size,
            "round_trips": MEASURE_RTPS,
            "avg_latency_us": avg_lat_us,
            "total_bytes_per_rt": total_bytes,
            "throughput_mb_s": throughput_mb_s,
        }));
    }

    let output = serde_json::json!({
        "harness": "tidefs-two-node-harness",
        "carrier": "loopback-deterministic",
        "carrier_disclosure": {
            "mode": "loopback",
            "tcp_available": false,
            "rdma_available": false,
            "note": "Deterministic in-memory loopback; TCP/RDMA require QEMU or live carrier"
        },
        "measurements": results,
        "kpi_version": 1,
    });

    println!("TRANSPORT_BUDGET_JSON_BEGIN");
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    println!("TRANSPORT_BUDGET_JSON_END");
}

fn run_round_trip(payload_size: usize) -> (u64, u64) {
    let mut harness = TwoNodeHarness::new(42);
    harness.establish_session().expect("session establishment");

    let payload_a = vec![0xABu8; payload_size];
    let payload_b = vec![0xCDu8; payload_size];

    let obj_a = StateObject {
        object_key: 1,
        payload: payload_a.clone(),
    };
    let obj_b = StateObject {
        object_key: 2,
        payload: payload_b.clone(),
    };

    let start = Instant::now();

    harness
        .state_transfer_a_to_b(&[obj_a])
        .expect("state transfer A->B");
    harness
        .state_transfer_b_to_a(&[obj_b])
        .expect("state transfer B->A");

    let elapsed_us = start.elapsed().as_micros() as u64;
    let total_bytes = (payload_a.len() + payload_b.len()) as u64;

    harness.teardown();
    (elapsed_us, total_bytes)
}

#[test]
fn transport_budget_smoke() {
    let (lat_us, bytes) = run_round_trip(256);
    assert!(lat_us > 0, "latency should be positive");
    assert_eq!(bytes, 512, "two 256-byte payloads = 512 bytes total");
}
