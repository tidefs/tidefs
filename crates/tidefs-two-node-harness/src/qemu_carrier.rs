// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! QEMU-feature carrier validation over the live TideFS TCP transport.
//!
//! The deterministic harness remains the default validation surface. This
//! module is compiled only with the `qemu` feature and replays the harness
//! state-transfer framing over `tidefs-transport::Transport` using a real TCP
//! session. When the test is dispatched from a QEMU workflow, the same code
//! runs inside the guest and records whether QEMU/KVM was visible from the
//! guest environment.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use blake3::Hasher;
use tidefs_transport::{
    NodeInfo, SessionCloseReason, SessionId, Transport, TransportAddr, TransportError,
};

use crate::{blake3_hash, StateObject, StateTransferResult, TwoNodeHarness};

const NODE_A: u64 = 1;
const NODE_B: u64 = 2;
const ACCEPT_RETRIES: usize = 100;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const LISTENER_READY_TIMEOUT: Duration = Duration::from_secs(5);
const ACK_PREFIX: &[u8] = b"state_transfer_ack";
const QEMU_VALIDATION_CMDLINE_MARKER: &str = "tidefs.qemu_carrier_validation=1";

/// Report emitted by a live TCP carrier state-transfer run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTcpCarrierReport {
    /// PRNG seed matching the deterministic harness API shape.
    pub seed: u64,
    /// Carrier name exercised by this scenario.
    pub carrier: &'static str,
    /// Sender node id.
    pub sender_node_id: u64,
    /// Receiver node id.
    pub receiver_node_id: u64,
    /// Receiver TCP address used by the sender.
    pub receiver_addr: String,
    /// Whether this process appears to be running in a QEMU/KVM guest.
    pub qemu_guest_detected: bool,
    /// Completed transfer result from the sender perspective.
    pub transfer: StateTransferResult,
}

/// Run one state-transfer scenario over a live TCP carrier.
///
/// This is intentionally small and synchronous: it uses the production
/// transport handshake, sends the same state-transfer frames as
/// [`TwoNodeHarness::state_transfer_a_to_b`], verifies per-chunk BLAKE3
/// digests at the receiver, and verifies the aggregate digest ack at the
/// sender.
pub fn run_qemu_tcp_state_transfer(
    seed: u64,
    objects: Vec<StateObject>,
) -> Result<QemuTcpCarrierReport, String> {
    verify_unique_object_keys(&objects)?;

    let qemu_guest_detected = detect_qemu_guest();
    let (addr_tx, addr_rx) = mpsc::channel();
    let receiver_objects = objects.len();

    let receiver = thread::spawn(move || -> Result<ReceiverReport, String> {
        let mut node_b = Transport::new(NODE_B);
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        node_b
            .bind(TransportAddr::Tcp(bind_addr))
            .map_err(|e| format_transport_error("bind receiver TCP listener", e))?;
        let local_addr = node_b
            .bind_addr
            .clone()
            .ok_or_else(|| "receiver bind did not expose local address".to_string())?;
        addr_tx
            .send(local_addr.clone())
            .map_err(|e| format!("publish receiver address: {e}"))?;

        let session = blocking_accept(&mut node_b)?;
        node_b
            .perform_handshake(session)
            .map_err(|e| format_transport_error("receiver handshake", e))?;

        let transfer = receive_state_transfer(&mut node_b, session)?;
        if transfer.object_count != receiver_objects {
            return Err(format!(
                "receiver object count mismatch: expected {receiver_objects}, got {}",
                transfer.object_count
            ));
        }
        node_b
            .close_session(session, SessionCloseReason::LocalShutdown)
            .map_err(|e| format_transport_error("receiver close", e))?;

        Ok(ReceiverReport {
            addr: local_addr.to_string(),
            transfer,
        })
    });

    let receiver_addr = addr_rx
        .recv_timeout(LISTENER_READY_TIMEOUT)
        .map_err(|e| format!("receiver listener was not ready: {e}"))?;

    let mut node_a = Transport::new(NODE_A);
    node_a.add_node(NodeInfo::new(NODE_B, vec![receiver_addr], 0));
    let session = node_a
        .connect(NODE_B)
        .map_err(|e| format_transport_error("sender connect", e))?;
    node_a
        .perform_handshake(session)
        .map_err(|e| format_transport_error("sender handshake", e))?;

    let sender_transfer = send_state_transfer(&mut node_a, session, &objects)?;
    node_a
        .close_session(session, SessionCloseReason::LocalShutdown)
        .map_err(|e| format_transport_error("sender close", e))?;

    let receiver_report = receiver
        .join()
        .map_err(|_| "receiver thread panicked".to_string())??;

    if receiver_report.transfer != sender_transfer {
        return Err(format!(
            "receiver transfer result mismatch: sender={sender_transfer:?}, receiver={:?}",
            receiver_report.transfer
        ));
    }

    Ok(QemuTcpCarrierReport {
        seed,
        carrier: "tcp",
        sender_node_id: NODE_A,
        receiver_node_id: NODE_B,
        receiver_addr: receiver_report.addr,
        qemu_guest_detected,
        transfer: sender_transfer,
    })
}

#[derive(Clone, Debug)]
struct ReceiverReport {
    addr: String,
    transfer: StateTransferResult,
}

fn verify_unique_object_keys(objects: &[StateObject]) -> Result<(), String> {
    let mut keys = BTreeSet::new();
    for object in objects {
        if !keys.insert(object.object_key) {
            return Err(format!(
                "qemu TCP carrier state transfer requires unique object keys; duplicate key {}",
                object.object_key
            ));
        }
    }
    Ok(())
}

fn blocking_accept(transport: &mut Transport) -> Result<SessionId, String> {
    let started = Instant::now();
    for _ in 0..ACCEPT_RETRIES {
        match transport.accept_incoming() {
            Ok(session) => return Ok(session),
            Err(TransportError::Generic(ref e)) if e.contains("no pending connections") => {
                thread::sleep(ACCEPT_RETRY_DELAY);
            }
            Err(e) => return Err(format_transport_error("receiver accept", e)),
        }
    }

    Err(format!(
        "timeout waiting for live TCP connection after {} ms",
        started.elapsed().as_millis()
    ))
}

fn send_state_transfer(
    transport: &mut Transport,
    session: SessionId,
    objects: &[StateObject],
) -> Result<StateTransferResult, String> {
    let mut total_bytes = 0u64;
    let mut chunk_count = 0usize;
    let mut aggregate_hasher = Hasher::new();

    send_frame(transport, session, &(objects.len() as u32).to_be_bytes())?;

    for object in objects {
        let chunks = chunk_payload(&object.payload);
        let total_chunks = chunks.len() as u64;

        for (idx, chunk_data) in chunks.iter().enumerate() {
            let digest = blake3_hash(chunk_data);
            let mut frame = Vec::with_capacity(8 + 8 + 8 + 32 + 4 + chunk_data.len());
            frame.extend_from_slice(&object.object_key.to_be_bytes());
            frame.extend_from_slice(&(idx as u64).to_be_bytes());
            frame.extend_from_slice(&total_chunks.to_be_bytes());
            frame.extend_from_slice(&digest);
            frame.extend_from_slice(&(chunk_data.len() as u32).to_be_bytes());
            frame.extend_from_slice(chunk_data);
            send_frame(transport, session, &frame)?;

            chunk_count += 1;
            total_bytes += chunk_data.len() as u64;
            aggregate_hasher.update(chunk_data);
        }
    }

    let transfer_digest = finalize_hasher(aggregate_hasher);
    let ack = transport
        .recv_message(session)
        .map_err(|e| format_transport_error("sender receive transfer ack", e))?;
    if !ack.starts_with(ACK_PREFIX) {
        return Err("sender received malformed state-transfer ack prefix".to_string());
    }
    let ack_digest: [u8; 32] = ack[ACK_PREFIX.len()..]
        .try_into()
        .map_err(|_| "sender received malformed state-transfer ack digest".to_string())?;
    if ack_digest != transfer_digest {
        return Err("sender received mismatched state-transfer ack digest".to_string());
    }

    Ok(StateTransferResult {
        object_count: objects.len(),
        total_bytes,
        chunk_count,
        transfer_digest,
    })
}

fn receive_state_transfer(
    transport: &mut Transport,
    session: SessionId,
) -> Result<StateTransferResult, String> {
    let header = transport
        .recv_message(session)
        .map_err(|e| format_transport_error("receiver read state-transfer header", e))?;
    let object_count = u32::from_be_bytes(
        header
            .as_slice()
            .try_into()
            .map_err(|_| "receiver state-transfer header was not 4 bytes".to_string())?,
    ) as usize;

    let mut total_bytes = 0u64;
    let mut chunk_count = 0usize;
    let mut aggregate_hasher = Hasher::new();
    let mut received_objects: BTreeMap<u64, BTreeMap<u64, Vec<u8>>> = BTreeMap::new();
    let mut received_total_chunks: BTreeMap<u64, u64> = BTreeMap::new();
    let mut completed_objects: BTreeSet<u64> = BTreeSet::new();

    while completed_objects.len() < object_count {
        let frame = transport
            .recv_message(session)
            .map_err(|e| format_transport_error("receiver read state-transfer chunk", e))?;
        let parsed = parse_chunk_frame(&frame)?;

        let actual_digest = blake3_hash(parsed.payload);
        if actual_digest != parsed.digest {
            return Err(format!(
                "receiver BLAKE3 digest mismatch for object {} chunk {}",
                parsed.object_key, parsed.chunk_idx
            ));
        }

        aggregate_hasher.update(parsed.payload);
        total_bytes += parsed.payload.len() as u64;
        chunk_count += 1;

        received_total_chunks.insert(parsed.object_key, parsed.total_chunks);
        let object_chunks = received_objects.entry(parsed.object_key).or_default();
        object_chunks.insert(parsed.chunk_idx, parsed.payload.to_vec());
        if parsed.total_chunks > 0 && object_chunks.len() as u64 == parsed.total_chunks {
            completed_objects.insert(parsed.object_key);
        }
    }

    verify_complete_objects(&received_objects, &received_total_chunks)?;

    let transfer_digest = finalize_hasher(aggregate_hasher);
    let ack_frame = [ACK_PREFIX, &transfer_digest].concat();
    send_frame(transport, session, &ack_frame)?;

    Ok(StateTransferResult {
        object_count,
        total_bytes,
        chunk_count,
        transfer_digest,
    })
}

fn send_frame(transport: &mut Transport, session: SessionId, frame: &[u8]) -> Result<(), String> {
    transport
        .send_message(session, frame)
        .map_err(|e| format_transport_error("send TCP carrier frame", e))
}

struct ParsedChunkFrame<'a> {
    object_key: u64,
    chunk_idx: u64,
    total_chunks: u64,
    digest: [u8; 32],
    payload: &'a [u8],
}

fn parse_chunk_frame(frame: &[u8]) -> Result<ParsedChunkFrame<'_>, String> {
    if frame.len() < 8 + 8 + 8 + 32 + 4 {
        return Err(format!(
            "receiver chunk frame too short: {} bytes",
            frame.len()
        ));
    }

    let object_key = u64_from_slice(&frame[0..8], "object key")?;
    let chunk_idx = u64_from_slice(&frame[8..16], "chunk index")?;
    let total_chunks = u64_from_slice(&frame[16..24], "total chunks")?;
    let digest: [u8; 32] = frame[24..56]
        .try_into()
        .map_err(|_| "chunk digest was not 32 bytes".to_string())?;
    let payload_len = u32::from_be_bytes(
        frame[56..60]
            .try_into()
            .map_err(|_| "chunk payload length was not 4 bytes".to_string())?,
    ) as usize;
    let payload = &frame[60..];
    if payload.len() != payload_len {
        return Err(format!(
            "receiver chunk payload length mismatch: header says {payload_len}, got {}",
            payload.len()
        ));
    }

    Ok(ParsedChunkFrame {
        object_key,
        chunk_idx,
        total_chunks,
        digest,
        payload,
    })
}

fn verify_complete_objects(
    received_objects: &BTreeMap<u64, BTreeMap<u64, Vec<u8>>>,
    received_total_chunks: &BTreeMap<u64, u64>,
) -> Result<(), String> {
    for (&object_key, &total_chunks) in received_total_chunks {
        let chunks = received_objects
            .get(&object_key)
            .ok_or_else(|| format!("receiver missing object {object_key}"))?;
        if chunks.len() as u64 != total_chunks {
            return Err(format!(
                "receiver object {object_key}: expected {total_chunks} chunks, got {}",
                chunks.len()
            ));
        }
        for chunk_idx in 0..total_chunks {
            if !chunks.contains_key(&chunk_idx) {
                return Err(format!(
                    "receiver object {object_key}: missing chunk {chunk_idx}"
                ));
            }
        }
    }
    Ok(())
}

fn chunk_payload(payload: &[u8]) -> Vec<&[u8]> {
    if payload.is_empty() {
        return vec![payload];
    }
    payload
        .chunks(TwoNodeHarness::MAX_CHUNK_PAYLOAD)
        .collect::<Vec<_>>()
}

fn finalize_hasher(hasher: Hasher) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

fn u64_from_slice(bytes: &[u8], label: &str) -> Result<u64, String> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| format!("{label} was not 8 bytes"))?;
    Ok(u64::from_be_bytes(array))
}

fn format_transport_error(context: &str, error: TransportError) -> String {
    format!("{context}: {error}")
}

fn detect_qemu_guest() -> bool {
    const SIGNAL_PATHS: &[&str] = &[
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/proc/cpuinfo",
        "/proc/cmdline",
    ];

    // Minimal initramfs guests may not expose DMI or hypervisor CPU strings.
    // The QEMU launcher adds a validation cmdline marker for that path.
    for path in SIGNAL_PATHS {
        if file_contains_qemu_signal(path) {
            return true;
        }
    }
    false
}

fn file_contains_qemu_signal(path: &str) -> bool {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let lower = contents.to_ascii_lowercase();
    lower.contains("qemu")
        || lower.contains("kvm")
        || lower.contains("bochs")
        || lower.contains("standard pc")
        || lower.contains(QEMU_VALIDATION_CMDLINE_MARKER)
}
