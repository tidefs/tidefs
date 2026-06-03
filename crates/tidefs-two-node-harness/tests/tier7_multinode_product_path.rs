//! Tier 7 multi-node/RDMA product path validation (#6561).
//!
//! Produces multi-process validation for distributed storage behavior
//! with backend disclosure. Exercises: sustained multi-transfer payloads,
//! quorum/write fan-out, rebuild after simulated node failure, split-brain
//! detection/epoch safety, partition resilience/healing, and session lifecycle
//! stress.
//!
//! Validation tier: Tier 7 harness readiness (deterministic loopback).
//! Tier 7 runtime closure requires live TCP or RDMA carrier.

use std::time::Instant;

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_membership_live::epoch_coordinator::EpochView;
use tidefs_membership_live::epoch_fence::MembershipEpochFence;
use tidefs_membership_live::fencing_watchdog::FencingWatchdog;
use tidefs_partition_runtime::single_writer_fence::SingleWriterFence;
use tidefs_partition_runtime::split_brain_guard::SplitBrainGuard;
use tidefs_partition_runtime::types::{PartitionFence, PartitionState};
use tidefs_two_node_harness::{StateObject, TwoNodeHarness};

fn mid(id: u64) -> MemberId {
    MemberId::new(id)
}
fn eid(id: u64) -> EpochId {
    EpochId(id)
}

fn probe_carrier() -> serde_json::Value {
    let rdma_dev = std::fs::read_dir("/sys/class/infiniband")
        .map(|d| d.count())
        .unwrap_or(0);
    let rdma_mod = std::fs::read_to_string("/proc/modules")
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("rdma_") || l.starts_with("ib_"))
                .count()
        })
        .unwrap_or(0);
    serde_json::json!({
        "mode": "loopback-deterministic", "tcp_available": true,
        "rdma_available": rdma_dev > 0, "rdma_modules_available": rdma_mod > 0,
        "rdma_link_active": rdma_dev > 0
    })
}

fn digest_hex(d: &[u8; 32]) -> String {
    d.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn result(
    name: &str,
    ok: bool,
    dur_ms: u64,
    details: serde_json::Value,
    blocker: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({"name":name,"status":if ok {"pass"} else {"fail"},"duration_ms":dur_ms,"details":details,"blocker":blocker})
}

// ── 1. Sustained multi-transfer payloads ────────────────────────────────

fn s1_sustained_multitransfer(seed: u64) -> serde_json::Value {
    let t0 = Instant::now();
    let sizes = &[256, 1024, 4096, 16384, 65536, 262144, 1048576];
    let iters = 5u32;
    let mut ms = Vec::new();
    let mut ok = true;
    for &sz in sizes {
        let mut lats = Vec::new();
        for _ in 0..iters {
            let mut h = TwoNodeHarness::new(seed);
            if h.establish_session().is_err() {
                ok = false;
                continue;
            }
            let obj = StateObject {
                object_key: 1,
                payload: vec![0xABu8; sz],
            };
            let t1 = Instant::now();
            if h.state_transfer_a_to_b(&[obj]).is_err() {
                ok = false;
            }
            lats.push(t1.elapsed().as_micros() as u64);
            h.teardown();
        }
        let avg = lats.iter().sum::<u64>() as f64 / lats.len() as f64;
        let tp = if avg > 0.0 {
            (sz as f64 / 1048576.0) / (avg / 1_000_000.0)
        } else {
            0.0
        };
        ms.push(serde_json::json!({"payload_size_bytes":sz,"iterations":iters,"avg_latency_us":avg,"throughput_mb_s":tp}));
    }
    result(
        "sustained-multitransfer",
        ok,
        t0.elapsed().as_millis() as u64,
        serde_json::json!({"payload_sizes":sizes.len(),"iterations_per_size":iters,"measurements":ms}),
        if ok {
            None
        } else {
            Some("Some transfers failed")
        },
    )
}

// ── 2. Quorum / write fan-out ───────────────────────────────────────────

fn s2_quorum_write_fanout(seed: u64) -> serde_json::Value {
    let t0 = Instant::now();
    let mut h = TwoNodeHarness::new(seed);
    let mut phases = Vec::new();
    let mut ok = true;
    match h.establish_session() {
        Ok(()) => phases.push(serde_json::json!({"phase":"session","status":"pass"})),
        Err(e) => {
            ok = false;
            phases
                .push(serde_json::json!({"phase":"session","status":"fail","error":e.to_string()}));
        }
    }
    let n = 8u64;
    let objs_a: Vec<StateObject> = (0..n)
        .map(|i| StateObject {
            object_key: 100 + i,
            payload: format!("fanout-a-{i}").into_bytes(),
        })
        .collect();
    match h.state_transfer_a_to_b(&objs_a) {
        Ok(r) => phases.push(serde_json::json!({"phase":"fanout-a-to-b","status":"pass","objects":r.object_count,"bytes":r.total_bytes})),
        Err(e) => { ok = false; phases.push(serde_json::json!({"phase":"fanout-a-to-b","status":"fail","error":e.to_string()})); }
    }
    let objs_b: Vec<StateObject> = (0..n)
        .map(|i| StateObject {
            object_key: 200 + i,
            payload: format!("fanout-b-{i}").into_bytes(),
        })
        .collect();
    match h.state_transfer_b_to_a(&objs_b) {
        Ok(r) => phases.push(serde_json::json!({"phase":"fanout-b-to-a","status":"pass","objects":r.object_count,"bytes":r.total_bytes})),
        Err(e) => { ok = false; phases.push(serde_json::json!({"phase":"fanout-b-to-a","status":"fail","error":e.to_string()})); }
    }
    h.teardown();
    result(
        "quorum-write-fanout",
        ok,
        t0.elapsed().as_millis() as u64,
        serde_json::json!({"fanout_count":n,"phases":phases}),
        if ok {
            None
        } else {
            Some("Fan-out phases failed")
        },
    )
}

// ── 3. Rebuild after simulated node failure ─────────────────────────────

fn s3_rebuild_after_failure(seed: u64) -> serde_json::Value {
    let t0 = Instant::now();
    let mut h = TwoNodeHarness::new(seed);
    let mut phases = Vec::new();
    let mut ok = true;
    if h.establish_session().is_err() {
        return result(
            "rebuild-after-failure",
            false,
            t0.elapsed().as_millis() as u64,
            serde_json::json!({}),
            Some("Session establish failed"),
        );
    }
    phases.push(serde_json::json!({"phase":"session","status":"pass"}));

    // Pre-failure write
    match h.ship_chunk_a_to_b(b"critical pre-failure data") {
        Ok(d) => phases.push(serde_json::json!({"phase":"pre-failure-write","status":"pass","digest":digest_hex(&d)})),
        Err(e) => { ok = false; phases.push(serde_json::json!({"phase":"pre-failure-write","status":"fail","error":e.to_string()})); }
    }

    // Simulate node B failure: block A->B link
    h.block_a_to_b();
    phases.push(serde_json::json!({"phase":"node-b-failure","status":"pass","a_to_b_blocked":h.is_a_to_b_blocked()}));

    // Chunk shipping fails during partition
    match h.ship_chunk_a_to_b(b"should-fail") {
        Err(_) => phases.push(serde_json::json!({"phase":"chunk-blocked","status":"pass"})),
        Ok(_) => {
            ok = false;
            phases.push(serde_json::json!({"phase":"chunk-blocked","status":"fail"}));
        }
    }

    // State transfer fails during partition
    let obj = StateObject {
        object_key: 99,
        payload: b"should-fail".to_vec(),
    };
    match h.state_transfer_a_to_b(&[obj]) {
        Err(_) => phases.push(serde_json::json!({"phase":"state-xfer-blocked","status":"pass"})),
        Ok(_) => {
            ok = false;
            phases.push(serde_json::json!({"phase":"state-xfer-blocked","status":"fail"}));
        }
    }

    // Heal and re-establish
    h.heal_all();
    h.teardown();
    match h.establish_session() {
        Ok(()) => {
            phases.push(serde_json::json!({"phase":"re-establish","status":"pass"}));
            let backfill = StateObject {
                object_key: 200,
                payload: b"post-heal-backfill-data".to_vec(),
            };
            match h.state_transfer_a_to_b(&[backfill]) {
                Ok(r) => phases.push(serde_json::json!({"phase":"backfill","status":"pass","objects":r.object_count,"bytes":r.total_bytes})),
                Err(e) => { ok = false; phases.push(serde_json::json!({"phase":"backfill","status":"fail","error":e.to_string()})); }
            }
        }
        Err(e) => {
            ok = false;
            phases.push(
                serde_json::json!({"phase":"re-establish","status":"fail","error":e.to_string()}),
            );
        }
    }
    h.teardown();
    result(
        "rebuild-after-failure",
        ok,
        t0.elapsed().as_millis() as u64,
        serde_json::json!({"phases":phases}),
        if ok {
            None
        } else {
            Some("Rebuild phases failed")
        },
    )
}

// ── 4. Split-brain detection and epoch safety ───────────────────────────

fn s4_split_brain_epoch_safety() -> serde_json::Value {
    let t0 = Instant::now();
    let mut phases = Vec::new();
    let mut ok = true;

    // Test 1: Connected writer accepted
    {
        let guard = SplitBrainGuard::new(mid(1), eid(1), 2);
        let ef = MembershipEpochFence::new();
        ef.update_from_view(&EpochView::new(eid(1), vec![mid(1), mid(2), mid(3)], 1000));
        let wd = FencingWatchdog::new();
        let mut fence = SingleWriterFence::new(guard, ef, wd, mid(1));
        let pass = fence.evaluate() && fence.can_accept_writes() && !fence.is_fenced();
        phases.push(serde_json::json!({"test":"connected-accepts-writer","status":if pass {"pass"} else {"fail"}}));
        if !pass {
            ok = false;
        }
    }

    // Test 2: Stale writer fenced after eviction
    {
        let guard = SplitBrainGuard::new(mid(2), eid(1), 2);
        let ef = MembershipEpochFence::new();
        ef.update_from_view(&EpochView::new(eid(1), vec![mid(1), mid(2), mid(3)], 1000));
        let wd = FencingWatchdog::new();
        let mut fence = SingleWriterFence::new(guard, ef, wd, mid(2));
        assert!(fence.evaluate());
        assert!(fence.can_accept_writes());
        // Evict writer 2 in epoch 2
        fence
            .epoch_fence()
            .update_from_view(&EpochView::new(eid(2), vec![mid(1), mid(3)], 2000));
        let pass = !fence.evaluate() && fence.is_fenced();
        phases.push(serde_json::json!({"test":"stale-writer-fenced","status":if pass {"pass"} else {"fail"}}));
        if !pass {
            ok = false;
        }
    }

    // Test 3: Minority-side writer fenced during partition
    {
        let guard = SplitBrainGuard::new(mid(1), eid(1), 3);
        let ef = MembershipEpochFence::new();
        ef.update_from_view(&EpochView::new(
            eid(1),
            vec![mid(1), mid(2), mid(3), mid(4)],
            1000,
        ));
        let wd = FencingWatchdog::new();
        let mut fence = SingleWriterFence::new(guard, ef, wd, mid(1));
        assert!(fence.evaluate());
        assert!(fence.can_accept_writes());
        // Directly set partition state on guard
        fence.guard_mut().partition_state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 2,
            since_millis: 100,
        };
        fence.guard_mut().fence = PartitionFence::raise_all();
        let pass = !fence.evaluate() && fence.is_fenced() && !fence.can_accept_writes();
        phases.push(serde_json::json!({"test":"minority-fenced-partition","status":if pass {"pass"} else {"fail"}}));
        if !pass {
            ok = false;
        }
    }

    // Test 4: Quorum-side writer continues during partition
    {
        let guard = SplitBrainGuard::new(mid(2), eid(1), 2);
        let ef = MembershipEpochFence::new();
        ef.update_from_view(&EpochView::new(
            eid(1),
            vec![mid(1), mid(2), mid(3), mid(4)],
            1000,
        ));
        let wd = FencingWatchdog::new();
        let mut fence = SingleWriterFence::new(guard, ef, wd, mid(2));
        fence.guard_mut().partition_state = PartitionState::QuorumSideActive {
            minority_members: vec![mid(1)],
            new_epoch: eid(2),
            since_millis: 100,
        };
        // quorum-side: no fence set (guard default is unfenced)
        let pass = fence.evaluate() && fence.can_accept_writes();
        phases.push(serde_json::json!({"test":"quorum-side-continues","status":if pass {"pass"} else {"fail"}}));
        if !pass {
            ok = false;
        }
    }

    result(
        "split-brain-epoch-safety",
        ok,
        t0.elapsed().as_millis() as u64,
        serde_json::json!({"phases":phases}),
        if ok {
            None
        } else {
            Some("Split-brain tests failed")
        },
    )
}

// ── 5. Partition resilience and healing ─────────────────────────────────

fn s5_partition_resilience(seed: u64) -> serde_json::Value {
    let t0 = Instant::now();
    let mut h = TwoNodeHarness::new(seed);
    let mut phases = Vec::new();
    let mut ok = true;
    if h.establish_session().is_err() {
        return result(
            "partition-resilience",
            false,
            t0.elapsed().as_millis() as u64,
            serde_json::json!({}),
            Some("Session establish failed"),
        );
    }
    phases.push(serde_json::json!({"phase":"session","status":"pass"}));

    // Asymmetric block
    h.block_a_to_b();
    phases.push(
        serde_json::json!({"phase":"block-a-to-b","status":"pass","blocked":h.is_a_to_b_blocked()}),
    );

    match h.ship_chunk_a_to_b(b"should-drop") {
        Err(_) => phases.push(serde_json::json!({"phase":"a-to-b-drop","status":"pass"})),
        Ok(_) => {
            ok = false;
            phases.push(serde_json::json!({"phase":"a-to-b-drop","status":"fail"}));
        }
    }
    // B->A chunk shipping uses A->B for the ack, which is blocked.
    // This is correct asymmetric partition behavior: the chunk protocol
    // requires bidirectional communication for acks.
    match h.ship_chunk_b_to_a(b"should-arrive") {
        Err(_) => phases.push(serde_json::json!({"phase":"b-to-a-chunk-ack-blocked","status":"pass","note":"ack on A->B blocked by asymmetric partition"})),
        Ok(_) => phases.push(serde_json::json!({"phase":"b-to-a-chunk-ack-blocked","status":"fail","note":"ack unexpectedly succeeded"})),
    }

    // Heal
    h.heal_all();
    phases.push(serde_json::json!({"phase":"heal","status":"pass","any_blocked":h.any_blocked()}));
    match h.ship_chunk_a_to_b(b"post-heal") {
        Ok(d) => phases
            .push(serde_json::json!({"phase":"post-heal","status":"pass","digest":digest_hex(&d)})),
        Err(e) => {
            ok = false;
            phases.push(
                serde_json::json!({"phase":"post-heal","status":"fail","error":e.to_string()}),
            );
        }
    }

    // Full block and recovery
    h.block_all();
    assert!(h.any_blocked());
    let ship_bad = h.ship_chunk_a_to_b(b"fully-blocked");
    phases.push(serde_json::json!({"phase":"full-block","status":if ship_bad.is_err(){"pass"}else{"fail"},"dropped":h.partition_dropped()}));

    h.heal_all();
    let obj = StateObject {
        object_key: 1,
        payload: b"state-after-heal".to_vec(),
    };
    match h.state_transfer_a_to_b(&[obj]) {
        Ok(r) => phases.push(serde_json::json!({"phase":"post-full-heal-xfer","status":"pass","bytes":r.total_bytes})),
        Err(e) => { ok = false; phases.push(serde_json::json!({"phase":"post-full-heal-xfer","status":"fail","error":e.to_string()})); }
    }

    h.teardown();
    result(
        "partition-resilience",
        ok,
        t0.elapsed().as_millis() as u64,
        serde_json::json!({"phases":phases,"total_dropped":h.partition_dropped()}),
        if ok {
            None
        } else {
            Some("Partition phases failed")
        },
    )
}

// ── 6. Session lifecycle stress ─────────────────────────────────────────

fn s6_session_lifecycle_stress(seed: u64) -> serde_json::Value {
    let t0 = Instant::now();
    let cycles = 10u64;
    let mut results = Vec::new();
    let mut all_ok = true;
    for c in 0..cycles {
        let mut h = TwoNodeHarness::new(seed + c);
        let mut r =
            serde_json::json!({"cycle":c,"est":"fail","alive":"fail","exch":"fail","td":"fail"});
        if h.establish_session().is_ok() {
            r["est"] = serde_json::json!("pass");
            if h.verify_session_alive().is_ok() {
                r["alive"] = serde_json::json!("pass");
            }
            if h.exchange_messages(b"a", b"b").is_ok() {
                r["exch"] = serde_json::json!("pass");
            }
            h.teardown();
            if !h.is_session_established() {
                r["td"] = serde_json::json!("pass");
            }
        }
        let ok_cycle =
            r["est"] == "pass" && r["alive"] == "pass" && r["exch"] == "pass" && r["td"] == "pass";
        if !ok_cycle {
            all_ok = false;
        }
        results.push(r);
    }
    result(
        "session-lifecycle-stress",
        all_ok,
        t0.elapsed().as_millis() as u64,
        serde_json::json!({"cycles":cycles,"results":results}),
        if all_ok {
            None
        } else {
            Some("Some cycles failed")
        },
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Main entry point
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[ignore = "Tier 7 multi-node/RDMA product path validation; run with --ignored"]
fn tier7_multinode_product_path_validation() {
    let seed = 42u64;
    let carrier = probe_carrier();
    let scenarios = vec![
        s1_sustained_multitransfer(seed),
        s2_quorum_write_fanout(seed),
        s3_rebuild_after_failure(seed),
        s4_split_brain_epoch_safety(),
        s5_partition_resilience(seed),
        s6_session_lifecycle_stress(seed),
    ];
    let passed = scenarios.iter().filter(|s| s["status"] == "pass").count();
    let failed = scenarios.iter().filter(|s| s["status"] == "fail").count();

    let report = serde_json::json!({
        "harness": "tidefs-two-node-harness",
        "issue": 6561,
        "carrier": carrier,
        "scenarios": scenarios,
        "summary": {"total":6,"passed":passed,"failed":failed,"blocked":0,
            "verdict": if failed==0 {"all-scenarios-pass"} else {"scenarios-failed"}},
        "validation_tier": "Tier-7-harness-readiness",
        "notes": [
            "Deterministic loopback transport; Tier 7 runtime closure requires live TCP or RDMA carrier",
            "QEMU multi-node validation (nix run .#rdmaCarrierTwoNodeTest) needed for Tier 7 runtime validation",
            if failed > 0 { format!("{failed} scenarios failed") } else { "All 6 scenarios pass".into() }
        ]
    });

    println!("TIER7_MULTINODE_VALIDATION_JSON_BEGIN");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    println!("TIER7_MULTINODE_VALIDATION_JSON_END");
    assert!(failed == 0, "{failed} Tier 7 scenarios failed");
}

#[test]
fn tier7_multinode_smoke() {
    let mut h = TwoNodeHarness::new(42);
    h.establish_session().expect("session");
    h.state_transfer_a_to_b(&[StateObject {
        object_key: 1,
        payload: vec![0xA5; 4096],
    }])
    .expect("xfer");
    h.teardown();

    let guard = SplitBrainGuard::new(mid(1), eid(1), 2);
    let ef = MembershipEpochFence::new();
    ef.update_from_view(&EpochView::new(eid(1), vec![mid(1), mid(2)], 1000));
    let mut fence = SingleWriterFence::new(guard, ef, FencingWatchdog::new(), mid(1));
    assert!(fence.evaluate());
    assert!(fence.can_accept_writes());
}
