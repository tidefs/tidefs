//! Deterministic two-node transport message dispatch round-trip validation.
//!
//! Exercises end-to-end message dispatch across the two-node deterministic
//! loopback transport harness, covering:
//!
//! 1. Basic single-message round-trip dispatch
//! 2. Ordered multi-message sequence
//! 3. Interleaved bidirectional dispatch
//! 4. Connection drain-and-reconnect message continuity
//! 5. Send-queue backpressure with bounded capacity
//!
//! Each scenario produces a PASS/FAIL verdict. Validation is recorded in
//! validation-output format for the multi-process distributed tier.

use std::collections::{HashMap, VecDeque};

use tidefs_membership_epoch::NodeIdentity as EpochNodeId;
use tidefs_two_node_harness::TwoNodeHarness;

// ── Inline dispatch types (mirrors tidefs_transport::dispatch without
//    depending directly on that crate, since Cargo.toml is owned by s2) ──

/// Message family discriminant for typed dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum MsgFamily {
    /// Bootstrap / control messages.
    Control = 0,
    /// Membership messages.
    Membership = 1,
    /// Lease messages.
    Lease = 2,
    /// Data transfer messages.
    Data = 3,
    /// Keepalive / liveness messages.
    Keepalive = 4,
    /// Placement messages.
    Placement = 5,
    /// Recovery messages.
    Recovery = 6,
    /// Shadow / validation messages.
    Shadow = 7,
    /// Reserved family 8.
    Reserved8 = 8,
    /// Reserved family 9.
    Reserved9 = 9,
}

impl MsgFamily {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Control),
            1 => Some(Self::Membership),
            2 => Some(Self::Lease),
            3 => Some(Self::Data),
            4 => Some(Self::Keepalive),
            5 => Some(Self::Placement),
            6 => Some(Self::Recovery),
            7 => Some(Self::Shadow),
            8 => Some(Self::Reserved8),
            9 => Some(Self::Reserved9),
            _ => None,
        }
    }
}

/// A tagged message carrying a [`MsgFamily`] discriminant and payload.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TaggedMessage {
    family: MsgFamily,
    payload: Vec<u8>,
}

impl TaggedMessage {
    fn new(family: MsgFamily, payload: Vec<u8>) -> Self {
        Self { family, payload }
    }

    /// Encode into a wire-ready byte vector: [family_byte] ++ payload.
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + self.payload.len());
        v.push(self.family as u8);
        v.extend_from_slice(&self.payload);
        v
    }

    /// Decode from wire bytes: first byte is family, remainder is payload.
    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }
        let family = MsgFamily::from_u8(raw[0])?;
        let payload = raw[1..].to_vec();
        Some(Self { family, payload })
    }
}

// ── Inline dispatch registry ──────────────────────────────────────────────

/// Records dispatched messages per family for validation.
struct DispatchRecorder {
    /// Map from family to ordered list of received payloads.
    received: HashMap<MsgFamily, Vec<Vec<u8>>>,
}

impl DispatchRecorder {
    fn new() -> Self {
        Self {
            received: HashMap::new(),
        }
    }

    /// Dispatch a decoded message: record it under its family.
    fn dispatch(&mut self, msg: TaggedMessage) {
        self.received
            .entry(msg.family)
            .or_default()
            .push(msg.payload);
    }

    /// Return payloads received for a given family (clone for assertions).
    fn payloads_for(&self, family: MsgFamily) -> &[Vec<u8>] {
        self.received
            .get(&family)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total messages dispatched.
    fn total_dispatched(&self) -> usize {
        self.received.values().map(|v| v.len()).sum()
    }

    /// Families that received at least one message.
    fn active_families(&self) -> Vec<MsgFamily> {
        let mut families: Vec<_> = self
            .received
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, _)| *k)
            .collect();
        families.sort_by_key(|f| *f as u8);
        families
    }

    /// Clear all recorded messages.
    fn clear(&mut self) {
        self.received.clear();
    }
}

// ── Bounded send queue ────────────────────────────────────────────────────

/// A simple bounded FIFO send queue for demonstrating backpressure.
struct BoundedSendQueue {
    queue: VecDeque<TaggedMessage>,
    capacity: usize,
    /// Count of messages dropped due to full queue.
    dropped: u64,
    /// Count of messages enqueued successfully.
    enqueued: u64,
}

impl BoundedSendQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity.min(64)),
            capacity,
            dropped: 0,
            enqueued: 0,
        }
    }

    /// Enqueue a message. On full queue, oldest is evicted (DropOldest).
    fn enqueue(&mut self, msg: TaggedMessage) {
        if self.queue.len() >= self.capacity {
            self.queue.pop_front();
            self.dropped += 1;
        }
        self.queue.push_back(msg);
        self.enqueued += 1;
    }

    /// Dequeue the next message for sending.
    fn dequeue(&mut self) -> Option<TaggedMessage> {
        self.queue.pop_front()
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.queue.len()
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn stats(&self) -> (usize, u64, u64) {
        (self.queue.len(), self.enqueued, self.dropped)
    }
}

// ── Connection lifecycle tracker ──────────────────────────────────────────

/// Connection state mirroring the transport connection lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnState {
    Disconnected,
    Connected,
    Draining,
}

/// Tracks connection state for a peer pair.
struct ConnectionTracker {
    a_to_b: ConnState,
    b_to_a: ConnState,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            a_to_b: ConnState::Disconnected,
            b_to_a: ConnState::Disconnected,
        }
    }

    fn connect(&mut self) {
        self.a_to_b = ConnState::Connected;
        self.b_to_a = ConnState::Connected;
    }

    fn drain(&mut self) {
        self.a_to_b = ConnState::Draining;
        self.b_to_a = ConnState::Draining;
    }

    #[allow(dead_code)]
    fn disconnect(&mut self) {
        self.a_to_b = ConnState::Disconnected;
        self.b_to_a = ConnState::Disconnected;
    }

    #[allow(dead_code)]
    fn can_send(&self) -> bool {
        matches!(self.a_to_b, ConnState::Connected)
    }
}

// ── Validation node wrapper ───────────────────────────────────────────────

/// Wraps a TwoNodeHarness with dispatch recorders and send queues per node.
struct ValidationHarness {
    harness: TwoNodeHarness,
    recorder_a: DispatchRecorder,
    recorder_b: DispatchRecorder,
    send_queue_a: BoundedSendQueue,
    send_queue_b: BoundedSendQueue,
    connection: ConnectionTracker,
    validation: Vec<ValidationEntry>,
}

#[derive(Clone, Debug)]
struct ValidationEntry {
    scenario: &'static str,
    verdict: &'static str,
    detail: String,
}

impl ValidationHarness {
    fn new(seed: u64) -> Self {
        Self {
            harness: TwoNodeHarness::new(seed),
            recorder_a: DispatchRecorder::new(),
            recorder_b: DispatchRecorder::new(),
            send_queue_a: BoundedSendQueue::new(256),
            send_queue_b: BoundedSendQueue::new(256),
            connection: ConnectionTracker::new(),
            validation: Vec::new(),
        }
    }

    fn record(&mut self, scenario: &'static str, verdict: &'static str, detail: String) {
        self.validation.push(ValidationEntry {
            scenario,
            verdict,
            detail,
        });
    }

    /// Establish transport session via the harness and mark connected.
    fn establish(&mut self) -> Result<(), String> {
        self.harness.establish_session()?;
        self.connection.connect();
        Ok(())
    }

    /// Drain all messages from node A, decode and dispatch to recorder_a.
    fn drain_and_dispatch_a(&mut self) -> usize {
        let mut count = 0;
        while let Some(sim_msg) = self.harness.node_a.transport.recv() {
            if let Some(tagged) = TaggedMessage::decode(&sim_msg.payload) {
                self.recorder_a.dispatch(tagged);
                count += 1;
            }
        }
        count
    }

    /// Drain all messages from node B, decode and dispatch to recorder_b.
    fn drain_and_dispatch_b(&mut self) -> usize {
        let mut count = 0;
        while let Some(sim_msg) = self.harness.node_b.transport.recv() {
            if let Some(tagged) = TaggedMessage::decode(&sim_msg.payload) {
                self.recorder_b.dispatch(tagged);
                count += 1;
            }
        }
        count
    }

    /// Enqueue a tagged message into A's send queue, then flush to B.
    fn send_a_to_b(&mut self, msg: TaggedMessage) -> Option<u64> {
        self.send_queue_a.enqueue(msg);
        self.flush_queue_a_to_b()
    }

    /// Flush A's send queue through the harness to B.
    fn flush_queue_a_to_b(&mut self) -> Option<u64> {
        let mut last_seq = None;
        while let Some(msg) = self.send_queue_a.dequeue() {
            let encoded = msg.encode();
            let to_id = EpochNodeId::new(self.harness.node_b.id);
            last_seq = self.harness.node_a.transport.send(to_id, 0, encoded);
        }
        last_seq
    }

    /// Enqueue a tagged message into B's send queue and flush to A.
    #[allow(dead_code)]
    fn send_b_to_a(&mut self, msg: TaggedMessage) -> Option<u64> {
        self.send_queue_b.enqueue(msg);
        self.flush_queue_b_to_a()
    }

    fn flush_queue_b_to_a(&mut self) -> Option<u64> {
        let mut last_seq = None;
        while let Some(msg) = self.send_queue_b.dequeue() {
            let encoded = msg.encode();
            let to_id = EpochNodeId::new(self.harness.node_a.id);
            last_seq = self.harness.node_b.transport.send(to_id, 0, encoded);
        }
        last_seq
    }

    /// Advance scheduler by one tick and dispatch any delivered messages.
    fn tick_and_dispatch(&mut self) -> (usize, usize) {
        self.harness.tick();
        let a = self.drain_and_dispatch_a();
        let b = self.drain_and_dispatch_b();
        (a, b)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Build seeded data of `len` bytes.
fn patterned_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

/// Emit validation output for a scenario to stdout (captured by test runner).
fn emit_validation(label: &str, entries: &[ValidationEntry]) {
    println!("── {label} ──────────────────────────────────────────");
    for e in entries {
        println!("  [{:4}] {} | {}", e.verdict, e.scenario, e.detail);
    }
    println!();
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 1: Basic single-message round-trip dispatch
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_01_single_message_roundtrip() {
    let mut vh = ValidationHarness::new(100);
    vh.establish().expect("establish session");

    let payload = b"hello transport dispatch".to_vec();
    let msg = TaggedMessage::new(MsgFamily::Control, payload.clone());

    let seq = vh.send_a_to_b(msg);
    assert!(seq.is_some(), "send should succeed");

    vh.tick_and_dispatch();

    let control_msgs = vh.recorder_b.payloads_for(MsgFamily::Control);
    assert_eq!(
        control_msgs.len(),
        1,
        "B should receive one Control message"
    );
    assert_eq!(control_msgs[0], payload, "payload should match");
    assert_eq!(
        vh.recorder_a.total_dispatched(),
        0,
        "A received no messages"
    );

    vh.record(
        "single-message-roundtrip",
        "PASS",
        format!(
            "A->B Control message delivered: seq={:?}, payload_len={}",
            seq,
            payload.len()
        ),
    );

    emit_validation("scenario_01", &vh.validation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 2: Ordered multi-message sequence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_02_ordered_multi_message() {
    let mut vh = ValidationHarness::new(200);
    vh.establish().expect("establish session");

    let msgs = vec![
        TaggedMessage::new(MsgFamily::Control, b"ctrl-0".to_vec()),
        TaggedMessage::new(MsgFamily::Data, b"data-0".to_vec()),
        TaggedMessage::new(MsgFamily::Membership, b"memb-0".to_vec()),
        TaggedMessage::new(MsgFamily::Data, b"data-1".to_vec()),
        TaggedMessage::new(MsgFamily::Control, b"ctrl-1".to_vec()),
    ];

    for msg in &msgs {
        vh.send_queue_a.enqueue(msg.clone());
    }
    vh.flush_queue_a_to_b();
    vh.tick_and_dispatch();

    assert_eq!(
        vh.recorder_b.total_dispatched(),
        5,
        "B should receive all 5 messages"
    );

    let control = vh.recorder_b.payloads_for(MsgFamily::Control);
    assert_eq!(control.len(), 2, "2 Control messages");
    assert_eq!(control[0], b"ctrl-0");
    assert_eq!(control[1], b"ctrl-1");

    let data = vh.recorder_b.payloads_for(MsgFamily::Data);
    assert_eq!(data.len(), 2, "2 Data messages");
    assert_eq!(data[0], b"data-0");
    assert_eq!(data[1], b"data-1");

    let memb = vh.recorder_b.payloads_for(MsgFamily::Membership);
    assert_eq!(memb.len(), 1, "1 Membership message");
    assert_eq!(memb[0], b"memb-0");

    let families = vh.recorder_b.active_families();
    assert_eq!(families.len(), 3, "3 distinct families active");

    vh.record(
        "ordered-multi-message",
        "PASS",
        format!("5 messages across 3 families delivered in order: {families:?}"),
    );

    emit_validation("scenario_02", &vh.validation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 3: Interleaved bidirectional dispatch
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_03_bidirectional_dispatch() {
    let mut vh = ValidationHarness::new(300);
    vh.establish().expect("establish session");

    // Round 1: A->B (Control), B->A (Lease)
    vh.send_queue_a.enqueue(TaggedMessage::new(
        MsgFamily::Control,
        b"a-to-b-r1".to_vec(),
    ));
    vh.send_queue_b
        .enqueue(TaggedMessage::new(MsgFamily::Lease, b"b-to-a-r1".to_vec()));
    vh.flush_queue_a_to_b();
    vh.flush_queue_b_to_a();
    vh.tick_and_dispatch();

    // Round 2: A->B (Data), B->A (Membership)
    vh.send_queue_a
        .enqueue(TaggedMessage::new(MsgFamily::Data, b"a-to-b-r2".to_vec()));
    vh.send_queue_b.enqueue(TaggedMessage::new(
        MsgFamily::Membership,
        b"b-to-a-r2".to_vec(),
    ));
    vh.flush_queue_a_to_b();
    vh.flush_queue_b_to_a();
    vh.tick_and_dispatch();

    // Round 3: simultaneous exchange
    vh.send_queue_a
        .enqueue(TaggedMessage::new(MsgFamily::Keepalive, b"a-ping".to_vec()));
    vh.send_queue_b
        .enqueue(TaggedMessage::new(MsgFamily::Keepalive, b"b-pong".to_vec()));
    vh.flush_queue_a_to_b();
    vh.flush_queue_b_to_a();
    vh.tick_and_dispatch();

    // Verify Node B received all A->B messages
    assert_eq!(
        vh.recorder_b.total_dispatched(),
        3,
        "B should receive 3 messages from A"
    );
    assert_eq!(vh.recorder_b.payloads_for(MsgFamily::Control).len(), 1);
    assert_eq!(vh.recorder_b.payloads_for(MsgFamily::Data).len(), 1);
    assert_eq!(vh.recorder_b.payloads_for(MsgFamily::Keepalive).len(), 1);

    // Verify Node A received all B->A messages
    assert_eq!(
        vh.recorder_a.total_dispatched(),
        3,
        "A should receive 3 messages from B"
    );
    assert_eq!(vh.recorder_a.payloads_for(MsgFamily::Lease).len(), 1);
    assert_eq!(vh.recorder_a.payloads_for(MsgFamily::Membership).len(), 1);
    assert_eq!(vh.recorder_a.payloads_for(MsgFamily::Keepalive).len(), 1);

    assert_eq!(
        vh.recorder_b.payloads_for(MsgFamily::Control)[0],
        b"a-to-b-r1"
    );
    assert_eq!(
        vh.recorder_a.payloads_for(MsgFamily::Lease)[0],
        b"b-to-a-r1"
    );

    vh.record(
        "bidirectional-dispatch",
        "PASS",
        format!(
            "bidirectional: A->B={} msgs, B->A={} msgs",
            vh.recorder_b.total_dispatched(),
            vh.recorder_a.total_dispatched()
        ),
    );

    emit_validation("scenario_03", &vh.validation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 4: Connection drain-and-reconnect message continuity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_04_drain_reconnect_continuity() {
    let mut vh = ValidationHarness::new(400);
    vh.establish().expect("establish session");

    // Phase 1: Send messages while connected
    vh.send_a_to_b(TaggedMessage::new(
        MsgFamily::Control,
        b"pre-drain-1".to_vec(),
    ));
    vh.send_a_to_b(TaggedMessage::new(MsgFamily::Data, b"pre-drain-2".to_vec()));
    vh.tick_and_dispatch();

    assert_eq!(
        vh.recorder_b.total_dispatched(),
        2,
        "pre-drain messages delivered"
    );
    let pre_count = vh.recorder_b.total_dispatched();

    // Phase 2: Drain the connection
    vh.connection.drain();
    vh.send_queue_a.enqueue(TaggedMessage::new(
        MsgFamily::Control,
        b"during-drain".to_vec(),
    ));
    vh.flush_queue_a_to_b();
    vh.tick_and_dispatch();

    // Phase 3: Teardown and reconnect
    vh.harness.teardown();
    vh.recorder_a.clear();
    vh.recorder_b.clear();
    vh.send_queue_a = BoundedSendQueue::new(256);
    vh.send_queue_b = BoundedSendQueue::new(256);

    vh.establish().expect("re-establish session");

    // Phase 4: Send messages after reconnect
    vh.send_a_to_b(TaggedMessage::new(
        MsgFamily::Membership,
        b"post-reconnect-1".to_vec(),
    ));
    vh.send_a_to_b(TaggedMessage::new(
        MsgFamily::Data,
        b"post-reconnect-2".to_vec(),
    ));
    vh.tick_and_dispatch();

    assert_eq!(
        vh.recorder_b.total_dispatched(),
        2,
        "post-reconnect messages delivered"
    );
    assert_eq!(
        vh.recorder_b.payloads_for(MsgFamily::Membership)[0],
        b"post-reconnect-1"
    );
    assert_eq!(
        vh.recorder_b.payloads_for(MsgFamily::Data)[0],
        b"post-reconnect-2"
    );

    vh.record(
        "drain-reconnect-continuity",
        "PASS",
        format!(
            "pre-drain={} msgs, post-reconnect={} msgs, connection re-established",
            pre_count,
            vh.recorder_b.total_dispatched()
        ),
    );

    emit_validation("scenario_04", &vh.validation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 5: Send-queue backpressure with bounded capacity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_05_backpressure_bounded_capacity() {
    let mut vh = ValidationHarness::new(500);
    vh.establish().expect("establish session");

    // Use a small capacity (8) to trigger backpressure quickly
    let mut small_queue = BoundedSendQueue::new(8);

    // Enqueue 20 messages — 8 will fit, 12 will evict oldest (DropOldest)
    for i in 0u64..20 {
        let payload = format!("msg-{i:02}").into_bytes();
        small_queue.enqueue(TaggedMessage::new(MsgFamily::Data, payload));
    }

    let (depth, enqueued, dropped) = small_queue.stats();
    assert_eq!(depth, 8, "queue should be at capacity (8)");
    assert_eq!(enqueued, 20, "all 20 messages attempted enqueue");
    assert_eq!(dropped, 12, "12 oldest messages evicted");

    // The remaining 8 messages should be the last 8 (msg-12 through msg-19)
    let mut drained: Vec<TaggedMessage> = Vec::new();
    while let Some(msg) = small_queue.dequeue() {
        drained.push(msg);
    }
    assert_eq!(drained.len(), 8);

    // Last message should be msg-19
    assert_eq!(String::from_utf8_lossy(&drained[7].payload), "msg-19");

    // Now send the drained messages through the harness
    for msg in drained {
        vh.send_queue_a.enqueue(msg);
    }
    vh.flush_queue_a_to_b();
    vh.tick_and_dispatch();

    assert_eq!(
        vh.recorder_b.total_dispatched(),
        8,
        "8 messages delivered after backpressure drain"
    );

    vh.record(
        "backpressure-bounded-capacity",
        "PASS",
        "capacity=8, enqueued=20, dropped=12 (oldest evicted), delivered=8".to_string(),
    );

    emit_validation("scenario_05", &vh.validation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 6: Large payload round-trip (multi-kB payloads)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_06_large_payload_roundtrip() {
    let mut vh = ValidationHarness::new(600);
    vh.establish().expect("establish session");

    let payload_sizes = [64, 256, 1024, 4096, 8192, 16384];
    for (i, &size) in payload_sizes.iter().enumerate() {
        let payload = patterned_payload(700 + i as u64, size);
        let msg = TaggedMessage::new(MsgFamily::Data, payload.clone());
        vh.send_a_to_b(msg);
        vh.tick_and_dispatch();

        let data_msgs = vh.recorder_b.payloads_for(MsgFamily::Data);
        assert_eq!(
            data_msgs.len(),
            i + 1,
            "after round {i}: B should have {expect} Data messages",
            i = i,
            expect = i + 1
        );
        assert_eq!(data_msgs[i].len(), size, "payload size match for {size}B");
        assert_eq!(data_msgs[i], payload, "payload content match for {size}B");
    }

    vh.record(
        "large-payload-roundtrip",
        "PASS",
        format!(
            "{} payloads from 64B to 16kB delivered with byte-level fidelity",
            payload_sizes.len()
        ),
    );

    emit_validation("scenario_06", &vh.validation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 7: Unknown family handling (no-handler fallback)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_07_unknown_family_handling() {
    let mut vh = ValidationHarness::new(700);
    vh.establish().expect("establish session");

    // Send a message with a family byte that doesn't map to MsgFamily
    let raw_payload = vec![
        0xFF, // invalid family byte
        0xDE, 0xAD, 0xBE, 0xEF,
    ];

    let to_id = EpochNodeId::new(vh.harness.node_b.id);
    vh.harness.node_a.transport.send(to_id, 0, raw_payload);
    vh.tick_and_dispatch();

    // The invalid message should be ignored by dispatch (not crash)
    assert_eq!(
        vh.recorder_b.total_dispatched(),
        0,
        "unknown family message should be skipped by dispatch"
    );

    // Send a valid message after to confirm dispatch still works
    vh.send_a_to_b(TaggedMessage::new(
        MsgFamily::Control,
        b"after-unknown".to_vec(),
    ));
    vh.tick_and_dispatch();

    assert_eq!(
        vh.recorder_b.payloads_for(MsgFamily::Control).len(),
        1,
        "dispatch still functional after unknown family"
    );

    vh.record(
        "unknown-family-handling",
        "PASS",
        "Invalid family byte 0xFF gracefully skipped; dispatch still operational".to_string(),
    );

    emit_validation("scenario_07", &vh.validation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 8: Deterministic replay — same seed, same outcome
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_08_deterministic_replay() {
    fn run_scenario(seed: u64) -> (usize, Vec<Vec<u8>>) {
        let mut vh = ValidationHarness::new(seed);
        vh.establish().expect("establish session");

        let msgs = vec![
            TaggedMessage::new(MsgFamily::Control, b"det-ctrl".to_vec()),
            TaggedMessage::new(MsgFamily::Data, b"det-data-0".to_vec()),
            TaggedMessage::new(MsgFamily::Membership, b"det-memb".to_vec()),
            TaggedMessage::new(MsgFamily::Data, b"det-data-1".to_vec()),
        ];

        for msg in &msgs {
            vh.send_queue_a.enqueue(msg.clone());
        }
        vh.flush_queue_a_to_b();
        vh.tick_and_dispatch();

        let total = vh.recorder_b.total_dispatched();
        let data_payloads = vh.recorder_b.payloads_for(MsgFamily::Data).to_vec();
        (total, data_payloads)
    }

    let (count1, data1) = run_scenario(800);
    let (count2, data2) = run_scenario(800);

    assert_eq!(count1, count2, "same total dispatched on replay");
    assert_eq!(data1, data2, "same Data payloads on replay");

    // Different seed produces different harness identity
    let h1 = tidefs_two_node_harness::TwoNodeHarness::new(800);
    let h2 = tidefs_two_node_harness::TwoNodeHarness::new(801);
    assert_ne!(
        h1.seed, h2.seed,
        "different seeds produce harnesses with different seed values"
    );
}
