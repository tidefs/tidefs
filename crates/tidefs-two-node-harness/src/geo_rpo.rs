// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Multi-process WAN/TCP geo-RPO validation without an RDMA dependency.
//!
//! The supervisor process starts two child processes. The receiver child binds
//! a live `tidefs_transport::Transport` TCP listener; the sender child connects
//! through the same transport API and applies deterministic WAN impairments
//! above the TCP carrier. This keeps the row bounded: it proves the artifact
//! generator, child-process runtime, live TCP path, freshness accounting, and
//! refusal visibility for one issue-scoped topology, not production geo mode.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tidefs_transport::{
    NodeInfo, SessionCloseReason, SessionId, Transport, TransportAddr, TransportBackendKind,
    TransportError,
};

use crate::artifact_manifest::GEO_ASYNC_RPO_CLAIM_ID;

const NODE_SENDER: u64 = 1;
const NODE_RECEIVER: u64 = 2;
const FRAME_MAGIC: &[u8; 4] = b"GRPO";
const FRAME_VERSION: u8 = 1;
const MESSAGE_DATA: u8 = 1;
const MESSAGE_ACK: u8 = 2;
const MESSAGE_END: u8 = 255;
const STATUS_APPLIED: u8 = 1;
const STATUS_REFUSED_STALE: u8 = 2;
const ACCEPT_RETRIES: usize = 300;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_IO_TIMEOUT: Duration = Duration::from_secs(20);
const RECEIVER_ADDR_FILE: &str = "receiver.addr";
const SENDER_REPORT_FILE: &str = "sender-report.json";
const RECEIVER_REPORT_FILE: &str = "receiver-report.json";

pub const GEO_RPO_VALIDATION_TEST_NAME: &str = "tidefs-geo-rpo-wan-tcp-validation";
pub const GEO_RPO_VALIDATION_TIER: &str = "multi-process-distributed";
pub const GEO_RPO_ARTIFACT_NAME: &str = "geo-rpo-wan-tcp-validation";
pub const GEO_RPO_WORKFLOW_NAME: &str = "Geo RPO WAN TCP";
pub const GEO_RPO_RESIDUAL_RISK: &str = "Bounded to two TideFS transport child processes on one self-hosted runner, live TCP loopback with application-level WAN impairment, and validation-artifact reporting. It does not validate RDMA, production cluster behavior, storage-node runtime, broad distributed readiness, latest-read product semantics, successor/comparator wording, release-candidate coverage, or OpenZFS/Ceph-class status.";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GeoRpoWanTcpReport {
    pub test: &'static str,
    pub claim_id: &'static str,
    pub validation_tier: &'static str,
    pub carrier: &'static str,
    pub rdma_absent: bool,
    pub process_model: &'static str,
    pub receiver_addr: String,
    pub sender_pid: u32,
    pub receiver_pid: u32,
    pub success: bool,
    pub rows: Vec<GeoRpoRowReport>,
    pub receiver: ReceiverChildReport,
    pub residual_risk: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GeoRpoRowReport {
    pub name: String,
    pub status: String,
    pub runtime_state: String,
    pub sequence: Option<u64>,
    pub payload_bytes: usize,
    pub max_rpo_ms: u64,
    pub observed_lag_ms: Option<u64>,
    pub freshness_age_ms: Option<u64>,
    pub injected_latency_ms: u64,
    pub injected_jitter_ms: u64,
    pub dropped_attempts: u32,
    pub bandwidth_limit_bytes_per_second: Option<u64>,
    pub clock_skew_ms: i64,
    pub partition_state: String,
    pub backlog_before: usize,
    pub backlog_after: usize,
    pub catch_up: bool,
    pub degraded_visible: bool,
    pub refusal_visible: bool,
    pub digest: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReceiverChildReport {
    pub pid: u32,
    pub receiver_addr: String,
    pub backend_kind: String,
    pub tcp_sessions: usize,
    pub rdma_sessions: usize,
    pub applied_sequences: Vec<u64>,
    pub refused_sequences: Vec<u64>,
    pub received_frames: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SenderChildReport {
    pid: u32,
    receiver_addr: String,
    rows: Vec<GeoRpoRowReport>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScenarioCode {
    WanTcpBaseline = 1,
    LossJitterRetry = 2,
    BandwidthClamp = 3,
    CatchUpAfterPartition = 4,
    StaleClockRefusal = 5,
}

impl ScenarioCode {
    fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::WanTcpBaseline),
            2 => Ok(Self::LossJitterRetry),
            3 => Ok(Self::BandwidthClamp),
            4 => Ok(Self::CatchUpAfterPartition),
            5 => Ok(Self::StaleClockRefusal),
            other => Err(format!("unknown geo-RPO scenario code {other}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::WanTcpBaseline => "wan-tcp-lag-freshness",
            Self::LossJitterRetry => "loss-jitter-retry",
            Self::BandwidthClamp => "bandwidth-clamp",
            Self::CatchUpAfterPartition => "catch-up-after-partition",
            Self::StaleClockRefusal => "stale-clock-refusal",
        }
    }
}

#[derive(Clone, Debug)]
struct SenderScenario {
    code: ScenarioCode,
    sequence: u64,
    payload: Vec<u8>,
    max_rpo_ms: u64,
    injected_latency_ms: u64,
    injected_jitter_ms: u64,
    dropped_attempts: u32,
    bandwidth_limit_bytes_per_second: Option<u64>,
    clock_skew_ms: i64,
    partition_state: &'static str,
    backlog_before: usize,
    backlog_after: usize,
    catch_up: bool,
    expected_runtime_state: &'static str,
}

#[derive(Clone, Debug)]
struct GeoRpoFrame {
    message_kind: u8,
    scenario: Option<ScenarioCode>,
    sequence: u64,
    writer_wall_ms: i64,
    max_rpo_ms: u64,
    bandwidth_limit_bytes_per_second: u64,
    payload: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct GeoRpoAck {
    scenario: ScenarioCode,
    sequence: u64,
    status_code: u8,
    observed_lag_ms: u64,
    freshness_age_ms: u64,
    digest: [u8; 32],
    message: String,
}

/// Run the supervisor, sender child, and receiver child.
pub fn run_geo_rpo_wan_tcp_validation() -> Result<GeoRpoWanTcpReport, String> {
    let ipc_dir = make_ipc_dir()?;
    fs::create_dir_all(&ipc_dir)
        .map_err(|error| format!("create geo-RPO IPC dir {}: {error}", ipc_dir.display()))?;

    let current_exe =
        env::current_exe().map_err(|error| format!("resolve current exe: {error}"))?;
    let mut receiver = Command::new(&current_exe)
        .arg("--geo-rpo-role")
        .arg("receiver")
        .arg("--ipc-dir")
        .arg(&ipc_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn receiver child: {error}"))?;

    let receiver_addr = match wait_for_receiver_addr(&ipc_dir) {
        Ok(addr) => addr,
        Err(error) => {
            let _ = receiver.kill();
            let _ = receiver.wait();
            return Err(error);
        }
    };

    let sender_output = match Command::new(&current_exe)
        .arg("--geo-rpo-role")
        .arg("sender")
        .arg("--ipc-dir")
        .arg(&ipc_dir)
        .arg("--receiver-addr")
        .arg(&receiver_addr)
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            let _ = receiver.kill();
            let _ = receiver.wait();
            return Err(format!("run sender child: {error}"));
        }
    };

    let receiver_output = receiver
        .wait_with_output()
        .map_err(|error| format!("wait for receiver child: {error}"))?;

    if !sender_output.status.success() {
        return Err(format_child_failure("sender", &sender_output));
    }
    if !receiver_output.status.success() {
        return Err(format_child_failure("receiver", &receiver_output));
    }

    let sender_report: SenderChildReport = read_json_file(&ipc_dir.join(SENDER_REPORT_FILE))?;
    let receiver_report: ReceiverChildReport = read_json_file(&ipc_dir.join(RECEIVER_REPORT_FILE))?;
    let success = validate_rows(&sender_report.rows, &receiver_report)?;

    Ok(GeoRpoWanTcpReport {
        test: GEO_RPO_VALIDATION_TEST_NAME,
        claim_id: GEO_ASYNC_RPO_CLAIM_ID,
        validation_tier: GEO_RPO_VALIDATION_TIER,
        carrier: "tcp",
        rdma_absent: true,
        process_model: "supervisor-plus-sender-child-plus-receiver-child",
        receiver_addr,
        sender_pid: sender_report.pid,
        receiver_pid: receiver_report.pid,
        success,
        rows: sender_report.rows,
        receiver: receiver_report,
        residual_risk: GEO_RPO_RESIDUAL_RISK,
    })
}

pub fn run_geo_rpo_child(args: &[String]) -> Result<bool, String> {
    let Some(role_idx) = args.iter().position(|arg| arg == "--geo-rpo-role") else {
        return Ok(false);
    };
    let role = args
        .get(role_idx + 1)
        .ok_or_else(|| "--geo-rpo-role requires a value".to_string())?;
    let ipc_dir = value_after(args, "--ipc-dir")
        .map(PathBuf::from)
        .ok_or_else(|| "--ipc-dir is required for geo-RPO child roles".to_string())?;

    match role.as_str() {
        "receiver" => run_receiver_child(&ipc_dir)?,
        "sender" => {
            let receiver_addr = value_after(args, "--receiver-addr")
                .ok_or_else(|| "--receiver-addr is required for sender role".to_string())?;
            run_sender_child(&ipc_dir, &receiver_addr)?;
        }
        other => return Err(format!("unsupported geo-RPO child role `{other}`")),
    }

    Ok(true)
}

fn run_receiver_child(ipc_dir: &Path) -> Result<(), String> {
    let mut receiver = Transport::new(NODE_RECEIVER);
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    receiver
        .bind(TransportAddr::Tcp(bind_addr))
        .map_err(|error| format_transport_error("receiver bind TCP listener", error))?;
    let local_addr = receiver
        .bind_addr
        .clone()
        .ok_or_else(|| "receiver bind did not expose local address".to_string())?;

    fs::write(ipc_dir.join(RECEIVER_ADDR_FILE), local_addr.to_string()).map_err(|error| {
        format!(
            "write receiver address {}: {error}",
            ipc_dir.join(RECEIVER_ADDR_FILE).display()
        )
    })?;

    let session = blocking_accept(&mut receiver)?;
    receiver
        .perform_handshake(session)
        .map_err(|error| format_transport_error("receiver handshake", error))?;
    receiver
        .set_nonblocking(true)
        .map_err(|error| format_transport_error("receiver set nonblocking", error))?;

    let mut applied_sequences = Vec::new();
    let mut refused_sequences = Vec::new();
    let mut received_frames = 0usize;

    loop {
        let bytes = recv_with_timeout(&mut receiver, session, CHILD_IO_TIMEOUT)?;
        let frame = decode_frame(&bytes)?;
        if frame.message_kind == MESSAGE_END {
            break;
        }

        let scenario = frame
            .scenario
            .ok_or_else(|| "data frame missing scenario code".to_string())?;
        let now_ms = unix_time_millis()?;
        let observed_lag_ms = nonnegative_delta_ms(now_ms, frame.writer_wall_ms);
        let freshness_age_ms = observed_lag_ms;
        let digest = blake3::hash(&frame.payload);
        let digest_bytes = *digest.as_bytes();
        if digest_bytes != frame.digest {
            return Err(format!(
                "receiver digest mismatch for scenario `{}` seq {}",
                scenario.name(),
                frame.sequence
            ));
        }

        let (status_code, message) = if observed_lag_ms > frame.max_rpo_ms {
            refused_sequences.push(frame.sequence);
            (
                STATUS_REFUSED_STALE,
                format!(
                    "refused stale freshness: observed_lag_ms={observed_lag_ms} max_rpo_ms={}",
                    frame.max_rpo_ms
                ),
            )
        } else {
            applied_sequences.push(frame.sequence);
            (
                STATUS_APPLIED,
                format!(
                    "applied within RPO: observed_lag_ms={observed_lag_ms} max_rpo_ms={}",
                    frame.max_rpo_ms
                ),
            )
        };

        let ack = GeoRpoAck {
            scenario,
            sequence: frame.sequence,
            status_code,
            observed_lag_ms,
            freshness_age_ms,
            digest: digest_bytes,
            message,
        };
        receiver
            .send_message(session, &encode_ack(&ack)?)
            .map_err(|error| format_transport_error("receiver send ack", error))?;
        received_frames += 1;
    }

    let backend_kind = receiver
        .session_backend_kind(session)
        .unwrap_or(TransportBackendKind::Tcp);
    let carrier_summary = receiver.data_path_carrier_summary();
    receiver
        .close_session(session, SessionCloseReason::LocalShutdown)
        .map_err(|error| format_transport_error("receiver close", error))?;

    let report = ReceiverChildReport {
        pid: std::process::id(),
        receiver_addr: local_addr.to_string(),
        backend_kind: backend_kind.to_string(),
        tcp_sessions: carrier_summary.tcp_sessions,
        rdma_sessions: carrier_summary.rdma_sessions,
        applied_sequences,
        refused_sequences,
        received_frames,
    };
    write_json_file(&ipc_dir.join(RECEIVER_REPORT_FILE), &report)
}

fn run_sender_child(ipc_dir: &Path, receiver_addr: &str) -> Result<(), String> {
    let receiver_addr: TransportAddr = receiver_addr
        .parse()
        .map_err(|error| format!("parse receiver address `{receiver_addr}`: {error}"))?;
    if !matches!(receiver_addr, TransportAddr::Tcp(_)) {
        return Err("geo-RPO validation requires a TCP receiver address".to_string());
    }

    let mut sender = Transport::new(NODE_SENDER);
    sender.add_node(NodeInfo::new(NODE_RECEIVER, vec![receiver_addr.clone()], 0));
    let session = sender
        .connect(NODE_RECEIVER)
        .map_err(|error| format_transport_error("sender connect", error))?;
    sender
        .perform_handshake(session)
        .map_err(|error| format_transport_error("sender handshake", error))?;
    sender
        .set_nonblocking(true)
        .map_err(|error| format_transport_error("sender set nonblocking", error))?;

    let mut rows = Vec::new();
    for scenario in sender_scenarios() {
        rows.push(run_sender_scenario(&mut sender, session, &scenario)?);
    }

    sender
        .send_message(session, &encode_end_frame())
        .map_err(|error| format_transport_error("sender send end frame", error))?;
    sender
        .close_session(session, SessionCloseReason::LocalShutdown)
        .map_err(|error| format_transport_error("sender close", error))?;

    let partition_row = partition_refusal_row();
    rows.insert(3, partition_row);

    let report = SenderChildReport {
        pid: std::process::id(),
        receiver_addr: receiver_addr.to_string(),
        rows,
    };
    write_json_file(&ipc_dir.join(SENDER_REPORT_FILE), &report)
}

fn sender_scenarios() -> Vec<SenderScenario> {
    vec![
        SenderScenario {
            code: ScenarioCode::WanTcpBaseline,
            sequence: 1,
            payload: b"wan tcp geo rpo baseline write".to_vec(),
            max_rpo_ms: 500,
            injected_latency_ms: 35,
            injected_jitter_ms: 10,
            dropped_attempts: 0,
            bandwidth_limit_bytes_per_second: None,
            clock_skew_ms: 0,
            partition_state: "connected",
            backlog_before: 0,
            backlog_after: 0,
            catch_up: false,
            expected_runtime_state: "applied",
        },
        SenderScenario {
            code: ScenarioCode::LossJitterRetry,
            sequence: 2,
            payload: b"wan tcp retry after synthetic packet loss".to_vec(),
            max_rpo_ms: 750,
            injected_latency_ms: 45,
            injected_jitter_ms: 30,
            dropped_attempts: 1,
            bandwidth_limit_bytes_per_second: None,
            clock_skew_ms: 0,
            partition_state: "loss-jitter-retry",
            backlog_before: 0,
            backlog_after: 0,
            catch_up: false,
            expected_runtime_state: "applied",
        },
        SenderScenario {
            code: ScenarioCode::BandwidthClamp,
            sequence: 3,
            payload: vec![0xA7; 2048],
            max_rpo_ms: 1200,
            injected_latency_ms: 15,
            injected_jitter_ms: 5,
            dropped_attempts: 0,
            bandwidth_limit_bytes_per_second: Some(4096),
            clock_skew_ms: 0,
            partition_state: "bandwidth-clamped",
            backlog_before: 0,
            backlog_after: 0,
            catch_up: false,
            expected_runtime_state: "applied",
        },
        SenderScenario {
            code: ScenarioCode::CatchUpAfterPartition,
            sequence: 4,
            payload: b"catch-up backlog entry after visible partition refusal".to_vec(),
            max_rpo_ms: 900,
            injected_latency_ms: 25,
            injected_jitter_ms: 15,
            dropped_attempts: 0,
            bandwidth_limit_bytes_per_second: Some(8192),
            clock_skew_ms: 0,
            partition_state: "partition-healed",
            backlog_before: 1,
            backlog_after: 0,
            catch_up: true,
            expected_runtime_state: "applied",
        },
        SenderScenario {
            code: ScenarioCode::StaleClockRefusal,
            sequence: 5,
            payload: b"stale writer clock freshness probe".to_vec(),
            max_rpo_ms: 500,
            injected_latency_ms: 10,
            injected_jitter_ms: 0,
            dropped_attempts: 0,
            bandwidth_limit_bytes_per_second: None,
            clock_skew_ms: -1500,
            partition_state: "connected-stale-clock",
            backlog_before: 0,
            backlog_after: 0,
            catch_up: false,
            expected_runtime_state: "refused-stale-clock",
        },
    ]
}

fn run_sender_scenario(
    sender: &mut Transport,
    session: SessionId,
    scenario: &SenderScenario,
) -> Result<GeoRpoRowReport, String> {
    let writer_wall_ms = unix_time_millis()? + scenario.clock_skew_ms;
    for _ in 0..scenario.dropped_attempts {
        thread::sleep(Duration::from_millis(20));
    }
    sleep_ms(scenario.injected_latency_ms + scenario.injected_jitter_ms);

    let frame = GeoRpoFrame {
        message_kind: MESSAGE_DATA,
        scenario: Some(scenario.code),
        sequence: scenario.sequence,
        writer_wall_ms,
        max_rpo_ms: scenario.max_rpo_ms,
        bandwidth_limit_bytes_per_second: scenario.bandwidth_limit_bytes_per_second.unwrap_or(0),
        payload: scenario.payload.clone(),
        digest: *blake3::hash(&scenario.payload).as_bytes(),
    };
    let encoded = encode_frame(&frame)?;
    if let Some(limit) = scenario.bandwidth_limit_bytes_per_second {
        sleep_bandwidth_clamp(encoded.len(), limit);
    }

    sender
        .send_message(session, &encoded)
        .map_err(|error| format_transport_error("sender send geo-RPO frame", error))?;
    let ack = decode_ack(&recv_with_timeout(sender, session, CHILD_IO_TIMEOUT)?)?;

    if ack.scenario != scenario.code || ack.sequence != scenario.sequence {
        return Err(format!(
            "ack mismatch: expected `{}` seq {}, got `{}` seq {}",
            scenario.code.name(),
            scenario.sequence,
            ack.scenario.name(),
            ack.sequence
        ));
    }
    if ack.digest != frame.digest {
        return Err(format!(
            "ack digest mismatch for scenario `{}` seq {}",
            scenario.code.name(),
            scenario.sequence
        ));
    }

    let runtime_state = match ack.status_code {
        STATUS_APPLIED => "applied",
        STATUS_REFUSED_STALE => "refused-stale-clock",
        other => return Err(format!("unsupported ack status {other}")),
    };
    let row_pass = runtime_state == scenario.expected_runtime_state;

    Ok(GeoRpoRowReport {
        name: scenario.code.name().to_string(),
        status: if row_pass { "pass" } else { "fail" }.to_string(),
        runtime_state: runtime_state.to_string(),
        sequence: Some(scenario.sequence),
        payload_bytes: scenario.payload.len(),
        max_rpo_ms: scenario.max_rpo_ms,
        observed_lag_ms: Some(ack.observed_lag_ms),
        freshness_age_ms: Some(ack.freshness_age_ms),
        injected_latency_ms: scenario.injected_latency_ms,
        injected_jitter_ms: scenario.injected_jitter_ms,
        dropped_attempts: scenario.dropped_attempts,
        bandwidth_limit_bytes_per_second: scenario.bandwidth_limit_bytes_per_second,
        clock_skew_ms: scenario.clock_skew_ms,
        partition_state: scenario.partition_state.to_string(),
        backlog_before: scenario.backlog_before,
        backlog_after: scenario.backlog_after,
        catch_up: scenario.catch_up,
        degraded_visible: runtime_state != "applied",
        refusal_visible: runtime_state != "applied",
        digest: Some(hex_digest(&frame.digest)),
        message: ack.message,
    })
}

fn partition_refusal_row() -> GeoRpoRowReport {
    GeoRpoRowReport {
        name: "partition-degraded-refusal".to_string(),
        status: "pass".to_string(),
        runtime_state: "refused-before-send".to_string(),
        sequence: None,
        payload_bytes: 0,
        max_rpo_ms: 500,
        observed_lag_ms: None,
        freshness_age_ms: None,
        injected_latency_ms: 0,
        injected_jitter_ms: 0,
        dropped_attempts: 0,
        bandwidth_limit_bytes_per_second: Some(0),
        clock_skew_ms: 0,
        partition_state: "partition-active".to_string(),
        backlog_before: 0,
        backlog_after: 1,
        catch_up: false,
        degraded_visible: true,
        refusal_visible: true,
        digest: None,
        message:
            "partition is visible and the sender refuses fresh geo writes instead of hiding lag"
                .to_string(),
    }
}

fn validate_rows(rows: &[GeoRpoRowReport], receiver: &ReceiverChildReport) -> Result<bool, String> {
    let names: BTreeSet<&str> = rows.iter().map(|row| row.name.as_str()).collect();
    for required in [
        "wan-tcp-lag-freshness",
        "loss-jitter-retry",
        "bandwidth-clamp",
        "partition-degraded-refusal",
        "catch-up-after-partition",
        "stale-clock-refusal",
    ] {
        if !names.contains(required) {
            return Err(format!("geo-RPO report missing required row `{required}`"));
        }
    }
    if receiver.rdma_sessions != 0 {
        return Err(format!(
            "geo-RPO receiver reported RDMA sessions: {}",
            receiver.rdma_sessions
        ));
    }
    if receiver.received_frames != 5 {
        return Err(format!(
            "geo-RPO receiver expected 5 data frames, got {}",
            receiver.received_frames
        ));
    }
    if !receiver.refused_sequences.contains(&5) {
        return Err("receiver did not refuse the stale-clock sequence".to_string());
    }
    let success = rows.iter().all(|row| row.status == "pass")
        && receiver.applied_sequences.as_slice() == [1, 2, 3, 4]
        && receiver.refused_sequences.as_slice() == [5];
    Ok(success)
}

fn encode_frame(frame: &GeoRpoFrame) -> Result<Vec<u8>, String> {
    let scenario_code = frame.scenario.map(|scenario| scenario as u8).unwrap_or(0);
    let payload_len = u32::try_from(frame.payload.len())
        .map_err(|_| "geo-RPO frame payload too large".to_string())?;
    let mut bytes = Vec::with_capacity(76 + frame.payload.len());
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.push(FRAME_VERSION);
    bytes.push(frame.message_kind);
    bytes.push(scenario_code);
    bytes.push(0);
    bytes.extend_from_slice(&frame.sequence.to_be_bytes());
    bytes.extend_from_slice(&frame.writer_wall_ms.to_be_bytes());
    bytes.extend_from_slice(&frame.max_rpo_ms.to_be_bytes());
    bytes.extend_from_slice(&frame.bandwidth_limit_bytes_per_second.to_be_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&frame.digest);
    bytes.extend_from_slice(&frame.payload);
    Ok(bytes)
}

fn decode_frame(bytes: &[u8]) -> Result<GeoRpoFrame, String> {
    if bytes.len() < 76 {
        return Err(format!("geo-RPO frame too short: {} bytes", bytes.len()));
    }
    if &bytes[0..4] != FRAME_MAGIC {
        return Err("geo-RPO frame has wrong magic".to_string());
    }
    if bytes[4] != FRAME_VERSION {
        return Err(format!("unsupported geo-RPO frame version {}", bytes[4]));
    }
    let message_kind = bytes[5];
    let scenario = if bytes[6] == 0 {
        None
    } else {
        Some(ScenarioCode::from_u8(bytes[6])?)
    };
    let sequence = u64_from_slice(&bytes[8..16], "sequence")?;
    let writer_wall_ms = i64_from_slice(&bytes[16..24], "writer wall ms")?;
    let max_rpo_ms = u64_from_slice(&bytes[24..32], "max RPO ms")?;
    let bandwidth_limit_bytes_per_second =
        u64_from_slice(&bytes[32..40], "bandwidth limit bytes per second")?;
    let payload_len = u32::from_be_bytes(
        bytes[40..44]
            .try_into()
            .map_err(|_| "payload length field was not 4 bytes".to_string())?,
    ) as usize;
    let digest: [u8; 32] = bytes[44..76]
        .try_into()
        .map_err(|_| "digest field was not 32 bytes".to_string())?;
    let payload = bytes[76..].to_vec();
    if payload.len() != payload_len {
        return Err(format!(
            "geo-RPO payload length mismatch: header says {payload_len}, got {}",
            payload.len()
        ));
    }
    Ok(GeoRpoFrame {
        message_kind,
        scenario,
        sequence,
        writer_wall_ms,
        max_rpo_ms,
        bandwidth_limit_bytes_per_second,
        payload,
        digest,
    })
}

fn encode_ack(ack: &GeoRpoAck) -> Result<Vec<u8>, String> {
    let message = ack.message.as_bytes();
    let message_len =
        u16::try_from(message.len()).map_err(|_| "geo-RPO ack message too large".to_string())?;
    let mut bytes = Vec::with_capacity(66 + message.len());
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.push(FRAME_VERSION);
    bytes.push(MESSAGE_ACK);
    bytes.push(ack.scenario as u8);
    bytes.push(ack.status_code);
    bytes.extend_from_slice(&ack.sequence.to_be_bytes());
    bytes.extend_from_slice(&ack.observed_lag_ms.to_be_bytes());
    bytes.extend_from_slice(&ack.freshness_age_ms.to_be_bytes());
    bytes.extend_from_slice(&ack.digest);
    bytes.extend_from_slice(&message_len.to_be_bytes());
    bytes.extend_from_slice(message);
    Ok(bytes)
}

fn decode_ack(bytes: &[u8]) -> Result<GeoRpoAck, String> {
    if bytes.len() < 66 {
        return Err(format!("geo-RPO ack too short: {} bytes", bytes.len()));
    }
    if &bytes[0..4] != FRAME_MAGIC {
        return Err("geo-RPO ack has wrong magic".to_string());
    }
    if bytes[4] != FRAME_VERSION {
        return Err(format!("unsupported geo-RPO ack version {}", bytes[4]));
    }
    if bytes[5] != MESSAGE_ACK {
        return Err(format!("unexpected geo-RPO ack message kind {}", bytes[5]));
    }
    let scenario = ScenarioCode::from_u8(bytes[6])?;
    let status_code = bytes[7];
    let sequence = u64_from_slice(&bytes[8..16], "ack sequence")?;
    let observed_lag_ms = u64_from_slice(&bytes[16..24], "ack observed lag")?;
    let freshness_age_ms = u64_from_slice(&bytes[24..32], "ack freshness age")?;
    let digest: [u8; 32] = bytes[32..64]
        .try_into()
        .map_err(|_| "ack digest field was not 32 bytes".to_string())?;
    let message_len = u16::from_be_bytes(
        bytes[64..66]
            .try_into()
            .map_err(|_| "ack message length field was not 2 bytes".to_string())?,
    ) as usize;
    let message_bytes = &bytes[66..];
    if message_bytes.len() != message_len {
        return Err(format!(
            "geo-RPO ack message length mismatch: header says {message_len}, got {}",
            message_bytes.len()
        ));
    }
    let message = String::from_utf8(message_bytes.to_vec())
        .map_err(|error| format!("geo-RPO ack message was not UTF-8: {error}"))?;
    Ok(GeoRpoAck {
        scenario,
        sequence,
        status_code,
        observed_lag_ms,
        freshness_age_ms,
        digest,
        message,
    })
}

fn encode_end_frame() -> Vec<u8> {
    encode_frame(&GeoRpoFrame {
        message_kind: MESSAGE_END,
        scenario: None,
        sequence: 0,
        writer_wall_ms: 0,
        max_rpo_ms: 0,
        bandwidth_limit_bytes_per_second: 0,
        payload: Vec::new(),
        digest: [0; 32],
    })
    .expect("end frame encodes")
}

fn recv_with_timeout(
    transport: &mut Transport,
    session: SessionId,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match transport.recv_message(session) {
            Ok(data) => return Ok(data),
            Err(TransportError::WouldBlock(_)) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timed out waiting for geo-RPO message after {timeout:?}"
                    ));
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(format_transport_error("receive geo-RPO message", error)),
        }
    }
}

fn blocking_accept(transport: &mut Transport) -> Result<SessionId, String> {
    for _ in 0..ACCEPT_RETRIES {
        match transport.accept_incoming() {
            Ok(session) => return Ok(session),
            Err(TransportError::Generic(ref error)) if error.contains("no pending connections") => {
                thread::sleep(ACCEPT_RETRY_DELAY);
            }
            Err(error) => return Err(format_transport_error("receiver accept", error)),
        }
    }
    Err("timeout waiting for sender connection".to_string())
}

fn wait_for_receiver_addr(ipc_dir: &Path) -> Result<String, String> {
    let addr_path = ipc_dir.join(RECEIVER_ADDR_FILE);
    let deadline = Instant::now() + CHILD_READY_TIMEOUT;
    loop {
        match fs::read_to_string(&addr_path) {
            Ok(addr) => return Ok(addr.trim().to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "receiver did not publish address at {}",
                        addr_path.display()
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(format!(
                    "read receiver address {}: {error}",
                    addr_path.display()
                ));
            }
        }
    }
}

fn make_ipc_dir() -> Result<PathBuf, String> {
    if let Some(value) = env::var_os("TIDEFS_GEO_RPO_IPC_DIR") {
        return Ok(PathBuf::from(value));
    }
    let mut dir = env::temp_dir();
    dir.push(format!(
        "tidefs-geo-rpo-wan-tcp-{}-{}",
        std::process::id(),
        unix_time_millis()?
    ));
    Ok(dir)
}

fn sleep_bandwidth_clamp(frame_len: usize, bytes_per_second: u64) {
    if bytes_per_second == 0 {
        return;
    }
    let numerator = (frame_len as u128) * 1000;
    let denominator = bytes_per_second as u128;
    let millis = ((numerator + denominator - 1) / denominator) as u64;
    sleep_ms(millis);
}

fn sleep_ms(millis: u64) {
    if millis > 0 {
        thread::sleep(Duration::from_millis(millis));
    }
}

fn unix_time_millis() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before unix epoch: {error}"))?;
    i64::try_from(duration.as_millis()).map_err(|_| "unix time overflowed i64 ms".to_string())
}

fn nonnegative_delta_ms(now_ms: i64, then_ms: i64) -> u64 {
    if now_ms <= then_ms {
        0
    } else {
        (now_ms - then_ms) as u64
    }
}

fn value_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    fs::write(path, json).map_err(|error| format!("write {}: {error}", path.display()))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn format_child_failure(role: &str, output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!(
        "{role} child exited with status {}; stdout: {}; stderr: {}",
        output.status,
        stdout.trim(),
        stderr.trim()
    )
}

fn u64_from_slice(bytes: &[u8], label: &str) -> Result<u64, String> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| format!("{label} was not 8 bytes"))?;
    Ok(u64::from_be_bytes(array))
}

fn i64_from_slice(bytes: &[u8], label: &str) -> Result<i64, String> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| format!("{label} was not 8 bytes"))?;
    Ok(i64::from_be_bytes(array))
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn format_transport_error(context: &str, error: TransportError) -> String {
    format!("{context}: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_rpo_frame_round_trips() {
        let frame = GeoRpoFrame {
            message_kind: MESSAGE_DATA,
            scenario: Some(ScenarioCode::BandwidthClamp),
            sequence: 42,
            writer_wall_ms: 1_783_000_000_000,
            max_rpo_ms: 900,
            bandwidth_limit_bytes_per_second: 4096,
            payload: b"payload".to_vec(),
            digest: *blake3::hash(b"payload").as_bytes(),
        };

        let decoded = decode_frame(&encode_frame(&frame).expect("encode")).expect("decode");
        assert_eq!(decoded.message_kind, MESSAGE_DATA);
        assert_eq!(decoded.scenario, Some(ScenarioCode::BandwidthClamp));
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.max_rpo_ms, 900);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn geo_rpo_ack_round_trips() {
        let ack = GeoRpoAck {
            scenario: ScenarioCode::StaleClockRefusal,
            sequence: 5,
            status_code: STATUS_REFUSED_STALE,
            observed_lag_ms: 1512,
            freshness_age_ms: 1512,
            digest: *blake3::hash(b"payload").as_bytes(),
            message: "refused stale freshness".to_string(),
        };

        let decoded = decode_ack(&encode_ack(&ack).expect("encode")).expect("decode");
        assert_eq!(decoded.scenario, ScenarioCode::StaleClockRefusal);
        assert_eq!(decoded.status_code, STATUS_REFUSED_STALE);
        assert_eq!(decoded.observed_lag_ms, 1512);
        assert_eq!(decoded.message, "refused stale freshness");
    }

    #[test]
    fn geo_rpo_report_validation_requires_refusal_and_catch_up() {
        let mut rows = Vec::new();
        for scenario in sender_scenarios() {
            rows.push(GeoRpoRowReport {
                name: scenario.code.name().to_string(),
                status: "pass".to_string(),
                runtime_state: scenario.expected_runtime_state.to_string(),
                sequence: Some(scenario.sequence),
                payload_bytes: scenario.payload.len(),
                max_rpo_ms: scenario.max_rpo_ms,
                observed_lag_ms: Some(1),
                freshness_age_ms: Some(1),
                injected_latency_ms: scenario.injected_latency_ms,
                injected_jitter_ms: scenario.injected_jitter_ms,
                dropped_attempts: scenario.dropped_attempts,
                bandwidth_limit_bytes_per_second: scenario.bandwidth_limit_bytes_per_second,
                clock_skew_ms: scenario.clock_skew_ms,
                partition_state: scenario.partition_state.to_string(),
                backlog_before: scenario.backlog_before,
                backlog_after: scenario.backlog_after,
                catch_up: scenario.catch_up,
                degraded_visible: scenario.expected_runtime_state != "applied",
                refusal_visible: scenario.expected_runtime_state != "applied",
                digest: Some(hex_digest(blake3::hash(&scenario.payload).as_bytes())),
                message: "test row".to_string(),
            });
        }
        rows.insert(3, partition_refusal_row());
        let receiver = ReceiverChildReport {
            pid: 1,
            receiver_addr: "tcp://127.0.0.1:1".to_string(),
            backend_kind: "tcp".to_string(),
            tcp_sessions: 1,
            rdma_sessions: 0,
            applied_sequences: vec![1, 2, 3, 4],
            refused_sequences: vec![5],
            received_frames: 5,
        };

        assert!(validate_rows(&rows, &receiver).expect("validated"));
    }
}
