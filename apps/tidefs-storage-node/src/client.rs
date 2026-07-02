// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Storage node client: connect and issue put/get/delete/list/stats/send/receive commands.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tidefs_transport::{NodeInfo, SessionCloseReason, Transport, TransportError};

use crate::protocol::{self, Frame};

/// Connect to a storage node, issue a single request, and return the response.
pub fn request(
    node_id: u64,
    server_node_id: u64,
    server_addr: SocketAddr,
    request: Frame,
    rdma: bool,
) -> Result<Frame, String> {
    let mut transport = if rdma {
        Transport::with_rdma_or_tcp(node_id, std::time::Duration::from_secs(5))
    } else {
        Transport::new(node_id)
    };

    transport.add_node(NodeInfo::new(
        server_node_id,
        vec![tidefs_transport::TransportAddr::Tcp(server_addr)],
        0,
    ));

    let session_id = transport
        .connect(server_node_id)
        .map_err(|e| format!("connect failed: {e:?}"))?;

    transport
        .perform_handshake(session_id)
        .map_err(|e| format!("handshake failed: {e:?}"))?;

    if let Err(e) = transport.send_message(session_id, &protocol::encode(&request)) {
        let _ = transport.close_session(session_id, SessionCloseReason::LocalShutdown);
        return Err(format!("send failed: {e:?}"));
    }

    let raw = match transport.recv_message(session_id) {
        Ok(raw) => raw,
        Err(e) => {
            let _ = transport.close_session(session_id, SessionCloseReason::LocalShutdown);
            return Err(format!("recv failed: {e:?}"));
        }
    };

    let decoded = protocol::decode(&raw)
        .ok_or_else(|| format!("failed to decode response: {} bytes", raw.len()));
    close_request_session(&mut transport, session_id);

    decoded
}

fn close_request_session(transport: &mut Transport, session_id: tidefs_transport::SessionId) {
    let _ = transport.send_message(session_id, &protocol::encode(&Frame::Bye));
    let _ = transport.set_nonblocking(true);

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match transport.recv_message(session_id) {
            Ok(raw) => {
                if matches!(protocol::decode(&raw), Some(Frame::Bye)) {
                    break;
                }
            }
            Err(TransportError::WouldBlock(_)) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }

    let _ = transport.close_session(session_id, SessionCloseReason::LocalShutdown);
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn render_optional_u64(out: &mut String, label: &str, value: Option<u64>) {
    if let Some(value) = value {
        let _ = writeln!(out, "{label}: {value}");
    }
}

fn render_u64_list(values: &[u64]) -> String {
    if values.is_empty() {
        return "none".into();
    }

    let mut rendered = String::new();
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            rendered.push_str(", ");
        }
        let _ = write!(rendered, "{value}");
    }
    rendered
}

pub(crate) fn render_stats_response(report: &protocol::StatsReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "backend: {}", report.backend);
    let _ = writeln!(out, "object_count: {}", report.object_count);
    let _ = writeln!(out, "bytes_written: {}", report.bytes_written);
    render_optional_u64(&mut out, "committed_writes", report.committed_writes);
    render_optional_u64(&mut out, "degraded_writes", report.degraded_writes);
    render_optional_u64(&mut out, "refused_writes", report.refused_writes);
    render_optional_u64(&mut out, "failed_writes", report.failed_writes);
    render_optional_u64(&mut out, "degraded_reads", report.degraded_reads);
    if let Some(replica_healthy) = &report.replica_healthy {
        let healthy = replica_healthy.iter().filter(|healthy| **healthy).count();
        let _ = writeln!(out, "replica_healthy: {healthy}/{}", replica_healthy.len());
    }
    render_optional_u64(
        &mut out,
        "total_capacity_bytes",
        report.total_capacity_bytes,
    );
    render_optional_u64(&mut out, "used_bytes", report.used_bytes);
    render_optional_u64(&mut out, "available_bytes", report.available_bytes);
    render_optional_u64(
        &mut out,
        "placement_receipt_ref_count",
        report.placement_receipt_ref_count,
    );
    out
}

pub(crate) fn render_receive_response(report: &protocol::ReceiveImportReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "spec: {}", report.spec);
    let _ = writeln!(out, "imported_roots: {}", report.imported_roots);
    let _ = writeln!(out, "imported_records: {}", report.imported_records);
    let _ = writeln!(
        out,
        "imported_payload_bytes: {}",
        report.imported_payload_bytes
    );
    let _ = writeln!(out, "selected_generation: {}", report.selected_generation);
    let _ = writeln!(
        out,
        "selected_transaction_id: {}",
        report.selected_transaction_id
    );
    let _ = writeln!(
        out,
        "snapshot_catalog_entries: {}",
        report.snapshot_catalog_entries
    );
    let _ = writeln!(out, "stream_version: {}", report.stream_version);
    let _ = writeln!(
        out,
        "staging_validated_before_publish: {}",
        yes_no(report.staging_validated_before_publish)
    );
    let _ = writeln!(
        out,
        "destination_root_reauthentication: {}",
        yes_no(report.destination_root_reauthentication)
    );
    let _ = writeln!(
        out,
        "production_fsck_required: {}",
        yes_no(report.production_fsck_required)
    );
    match report.placement_epoch {
        Some(epoch) => {
            let _ = writeln!(out, "placement_epoch: {epoch}");
        }
        None => out.push_str("placement_epoch: none\n"),
    }
    let _ = writeln!(
        out,
        "placement_verified_stable: {}",
        yes_no(report.placement_verified_stable)
    );
    out
}

pub(crate) fn render_scrub_response(report: &protocol::ScrubReport) -> String {
    let mut out = String::new();
    if let Some(backend) = &report.backend {
        let _ = writeln!(out, "backend: {backend}");
    }
    let _ = writeln!(out, "completed: {}", yes_no(report.completed));
    let _ = writeln!(out, "findings_count: {}", report.findings_count);
    let _ = writeln!(out, "segments_scanned: {}", report.segments_scanned);
    let _ = writeln!(out, "records_verified: {}", report.records_verified);
    let _ = writeln!(out, "bytes_scanned: {}", report.bytes_scanned);
    let _ = writeln!(
        out,
        "chain_breaks_detected: {}",
        report.chain_breaks_detected
    );
    let _ = writeln!(
        out,
        "placement_receipt_ref_count: {}",
        report.placement_receipt_ref_count
    );
    if let Some(error) = &report.error {
        let _ = writeln!(out, "error: {error}");
    }
    out
}

pub(crate) fn render_health_response(
    node_identity: &str,
    pool_state: &str,
    uptime_secs: u64,
    backend: &str,
    report: &protocol::HealthReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "node_identity: {node_identity}");
    let _ = writeln!(out, "pool_state: {pool_state}");
    let _ = writeln!(out, "uptime_secs: {uptime_secs}");
    let _ = writeln!(out, "backend: {backend}");
    let _ = writeln!(out, "node_id: {}", report.node_id);
    if let Some(member_class) = &report.node_member_class {
        let _ = writeln!(out, "node_member_class: {member_class}");
    }
    render_optional_u64(&mut out, "node_failure_domain", report.node_failure_domain);
    let _ = writeln!(out, "carrier: {}", report.carrier);
    let _ = writeln!(out, "carrier_live: {}", yes_no(report.carrier_is_live));
    let _ = writeln!(out, "replication_factor: {}", report.replication_factor);
    let _ = writeln!(out, "placement_version: {}", report.placement_version);
    let _ = writeln!(out, "peer_count: {}", report.peer_count);
    let _ = writeln!(
        out,
        "alive_voters: {}",
        render_u64_list(&report.alive_voters)
    );
    let _ = writeln!(out, "quorum_lost: {}", yes_no(report.quorum_lost));
    let _ = writeln!(
        out,
        "roster: active={} suspected={} failed={} left={}",
        report.roster_state_summary.active,
        report.roster_state_summary.suspected,
        report.roster_state_summary.failed,
        report.roster_state_summary.left
    );
    let _ = writeln!(
        out,
        "health: healthy={} suspect={} down={}",
        report.health_summary.healthy, report.health_summary.suspect, report.health_summary.down
    );
    if report.degraded_peers.is_empty() {
        out.push_str("degraded_peers: none\n");
    } else {
        out.push_str("degraded_peers:\n");
        for peer in &report.degraded_peers {
            let _ = writeln!(
                out,
                "  member={} health={} failed_pings={}",
                peer.member_id, peer.health, peer.failed_pings
            );
        }
    }
    if report.transport_backends.is_empty() {
        out.push_str("transport_backends: none\n");
    } else {
        out.push_str("transport_backends:\n");
        for backend in &report.transport_backends {
            let peer = backend
                .peer_node
                .map(|peer| peer.to_string())
                .unwrap_or_else(|| "unknown".into());
            let disclosure = backend.disclosure.as_deref().unwrap_or("none");
            let _ = writeln!(
                out,
                "  session={} peer={} backend={} disclosure={}",
                backend.session_id, peer, backend.backend_kind, disclosure
            );
        }
    }
    out
}

pub(crate) fn render_snapshot_summary(report: &protocol::SnapshotSummaryReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "snapshot: {}", report.name);
    let _ = writeln!(
        out,
        "source_transaction_id: {}",
        report.source_transaction_id
    );
    let _ = writeln!(out, "source_generation: {}", report.source_generation);
    let _ = writeln!(
        out,
        "created_at_generation: {}",
        report.created_at_generation
    );
    out
}

pub(crate) fn render_snapshot_rollback(report: &protocol::SnapshotRollbackReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "spec: {}", report.spec);
    out.push_str(&render_snapshot_summary(&report.snapshot));
    let _ = writeln!(out, "generation_before: {}", report.generation_before);
    let _ = writeln!(
        out,
        "restored_source_generation: {}",
        report.restored_source_generation
    );
    let _ = writeln!(out, "published_generation: {}", report.published_generation);
    let _ = writeln!(
        out,
        "snapshot_catalog_entries: {}",
        report.snapshot_catalog_entries
    );
    let _ = writeln!(
        out,
        "production_fsck_required: {}",
        yes_no(report.production_fsck_required)
    );
    out
}

pub(crate) fn render_snapshot_clone(report: &protocol::SnapshotCloneSummaryReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "clone: {}", report.name);
    let _ = writeln!(out, "origin: {}", report.origin);
    let _ = writeln!(
        out,
        "source_transaction_id: {}",
        report.source_transaction_id
    );
    let _ = writeln!(out, "source_generation: {}", report.source_generation);
    let _ = writeln!(
        out,
        "created_at_generation: {}",
        report.created_at_generation
    );
    out
}

/// Run client commands interactively or as one-shot.
pub fn run_client(
    node_id: u64,
    server_node_id: u64,
    server_addr: SocketAddr,
    cmd: &str,
    args: &[String],
    rdma: bool,
) -> Result<(), String> {
    match cmd {
        "put" => {
            let (key, value) = if args.first().map(|s| s.as_str()) == Some("--file") {
                let path = args.get(1).ok_or("usage: put --file <path> <key>")?;
                let key = args.get(2).ok_or("usage: put --file <path> <key>")?;
                let value = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
                (key.as_bytes().to_vec(), value)
            } else {
                let key = args.first().ok_or("usage: put <key> <value>")?;
                let value = args.get(1).ok_or("usage: put <key> <value>")?;
                (key.as_bytes().to_vec(), value.as_bytes().to_vec())
            };
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::Put { key, value },
                rdma,
            )?;
            match resp {
                Frame::Ok | Frame::PutWithReceiptResponse { .. } => println!("ok"),
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "get" => {
            let key = args.first().ok_or("usage: get <key>")?.as_bytes();
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::Get { key: key.to_vec() },
                rdma,
            )?;
            match resp {
                Frame::GetResponse { value } => {
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), &value);
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "del" => {
            let key = args.first().ok_or("usage: del <key>")?.as_bytes();
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::Delete { key: key.to_vec() },
                rdma,
            )?;
            match resp {
                Frame::DeleteResponse { existed } => {
                    println!("{}", if existed { "deleted" } else { "not found" });
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "list" => {
            let resp = request(node_id, server_node_id, server_addr, Frame::List, rdma)?;
            match resp {
                Frame::ListResponse { keys } => {
                    for k in &keys {
                        if let Ok(s) = String::from_utf8(k.clone()) {
                            println!("{s}");
                        } else {
                            println!("{k:?}");
                        }
                    }
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "stats" => {
            let resp = request(node_id, server_node_id, server_addr, Frame::Stats, rdma)?;
            match resp {
                Frame::StatsResponse { report } => print!("{}", render_stats_response(&report)),
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "scrub" => {
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::ScrubRequest,
                rdma,
            )?;
            match resp {
                Frame::ScrubResponse { report } => print!("{}", render_scrub_response(&report)),
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "repair" => {
            let _ = args;
            return Err(
                "repair requires placement-receipt-bound authority; key+payload repair is refused"
                    .into(),
            );
        }
        "send" => {
            let key = if args.first().map(|s| s.as_str()) == Some("--incremental") {
                let hex = args
                    .get(1)
                    .ok_or("usage: send [--incremental <hex-key-48-chars>]")?;
                if hex.len() != 48 {
                    return Err("--incremental key must be 48 hex characters (24 bytes)".into());
                }
                hex::decode(hex).map_err(|e| format!("invalid hex key: {e}"))?
            } else {
                vec![]
            };
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::Send { key },
                rdma,
            )?;
            match resp {
                Frame::SendResponse { export } => {
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), &export);
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "receive" => {
            let (export, hex_key) = if args.first().map(|s| s.as_str()) == Some("--file") {
                let path = args
                    .get(1)
                    .ok_or("usage: receive [--file <path>] <root-auth-key-hex-64-chars>")?;
                let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
                let key = args
                    .get(2)
                    .ok_or("usage: receive [--file <path>] <root-auth-key-hex-64-chars>")?;
                (data, key.as_str())
            } else {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
                    .map_err(|e| format!("read stdin: {e}"))?;
                let key = args
                    .first()
                    .map(|s| s.as_str())
                    .ok_or("usage: receive [--file <path>] <root-auth-key-hex-64-chars>")?;
                if key.len() != 64 {
                    return Err("root auth key must be 64 hex characters (32 bytes)".into());
                }
                (buf, key)
            };
            if hex_key.len() != 64 {
                return Err("root auth key must be 64 hex characters (32 bytes)".into());
            }
            let root_authentication_key =
                hex::decode(hex_key).map_err(|e| format!("invalid hex key: {e}"))?;
            if root_authentication_key.len() != 32 {
                return Err("root auth key must decode to 32 bytes".into());
            }
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::Receive {
                    export,
                    root_authentication_key,
                },
                rdma,
            )?;
            match resp {
                Frame::ReceiveResponse { report } => print!("{}", render_receive_response(&report)),
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "health" => {
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::HealthCheck,
                rdma,
            )?;
            match resp {
                Frame::HealthCheckResponse {
                    node_identity,
                    pool_state,
                    uptime_secs,
                    backend,
                    report,
                } => {
                    print!(
                        "{}",
                        render_health_response(
                            &node_identity,
                            &pool_state,
                            uptime_secs,
                            &backend,
                            &report
                        )
                    );
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "snapshot-create" => {
            let name = args
                .first()
                .cloned()
                .ok_or("usage: snapshot-create <snapshot-name>")?;
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::SnapshotCreate {
                    snapshot_name: name,
                },
                rdma,
            )?;
            match resp {
                Frame::SnapshotCreateResponse { summary } => {
                    print!("{}", render_snapshot_summary(&summary));
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "snapshot-destroy" => {
            let name = args
                .first()
                .cloned()
                .ok_or("usage: snapshot-destroy <snapshot-name>")?;
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::SnapshotDestroy {
                    snapshot_name: name,
                },
                rdma,
            )?;
            match resp {
                Frame::SnapshotDestroyResponse { summary } => {
                    print!("{}", render_snapshot_summary(&summary));
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "snapshot-rollback" => {
            let name = args
                .first()
                .cloned()
                .ok_or("usage: snapshot-rollback <snapshot-name>")?;
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::SnapshotRollback {
                    snapshot_name: name,
                },
                rdma,
            )?;
            match resp {
                Frame::SnapshotRollbackResponse { report } => {
                    print!("{}", render_snapshot_rollback(&report));
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "send-chunked" => {
            let key = if args.first().map(|s| s.as_str()) == Some("--incremental") {
                let hex = args
                    .get(1)
                    .ok_or("usage: send-chunked [--incremental <hex-key-48-chars>]")?;
                if hex.len() != 48 {
                    return Err("--incremental key must be 48 hex characters (24 bytes)".into());
                }
                hex::decode(hex).map_err(|e| format!("invalid hex key: {e}"))?
            } else {
                vec![]
            };
            let mut all_chunks = Vec::new();
            let mut cursor: Option<Vec<u8>> = None;
            loop {
                let frame = if let Some(ref c) = cursor {
                    Frame::SendResume { cursor: c.clone() }
                } else {
                    Frame::SendChunked { key: key.clone() }
                };
                let resp = request(node_id, server_node_id, server_addr, frame, rdma)?;
                match resp {
                    Frame::SendChunkedResponse {
                        chunk,
                        cursor: c,
                        more,
                    } => {
                        all_chunks.extend_from_slice(&chunk);
                        cursor = Some(c);
                        if !more {
                            let _ = std::io::Write::write_all(&mut std::io::stdout(), &all_chunks);
                            break;
                        }
                    }
                    Frame::SendResumeResponse {
                        chunk,
                        cursor: c,
                        more,
                    } => {
                        all_chunks.extend_from_slice(&chunk);
                        cursor = Some(c);
                        if !more {
                            let _ = std::io::Write::write_all(&mut std::io::stdout(), &all_chunks);
                            break;
                        }
                    }
                    Frame::Error { message } => return Err(format!("server error: {message}")),
                    other => return Err(format!("unexpected response: {other:?}")),
                }
            }
        }
        "send-resume" => {
            let cursor_hex = args
                .first()
                .cloned()
                .ok_or("usage: send-resume <cursor-hex>")?;
            let cursor =
                hex::decode(&cursor_hex).map_err(|e| format!("invalid cursor hex: {e}"))?;
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::SendResume { cursor },
                rdma,
            )?;
            match resp {
                Frame::SendResumeResponse {
                    chunk,
                    cursor: _c,
                    more: _,
                } => {
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), &chunk);
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        "snapshot-clone" => {
            let clone_name = args
                .first()
                .cloned()
                .ok_or("usage: snapshot-clone <clone-name> <source-snapshot>")?;
            let source = args
                .get(1)
                .cloned()
                .ok_or("usage: snapshot-clone <clone-name> <source-snapshot>")?;
            let resp = request(
                node_id,
                server_node_id,
                server_addr,
                Frame::SnapshotClone {
                    clone_name,
                    source_snapshot: source,
                },
                rdma,
            )?;
            match resp {
                Frame::SnapshotCloneResponse { summary } => {
                    print!("{}", render_snapshot_clone(&summary));
                }
                Frame::Error { message } => return Err(format!("server error: {message}")),
                other => return Err(format!("unexpected response: {other:?}")),
            }
        }
        _ => {
            return Err(format!(
                "unknown command: {cmd}; commands: put <key> <value> | put --file <path> <key> | get <key> | del <key> | list | stats | health | snapshot-create <name> | snapshot-destroy <name> | snapshot-rollback <name> | snapshot-clone <clone-name> <source-snapshot> | send-chunked [--incremental <key>] | send-resume <cursor-hex>"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_report() -> protocol::StatsReport {
        protocol::StatsReport {
            backend: "tcp".into(),
            object_count: 3,
            bytes_written: 4096,
            committed_writes: Some(2),
            degraded_writes: Some(1),
            refused_writes: Some(0),
            failed_writes: None,
            degraded_reads: None,
            replica_healthy: Some(vec![true, false]),
            total_capacity_bytes: None,
            used_bytes: None,
            available_bytes: None,
            placement_receipt_ref_count: None,
        }
    }

    fn receive_report() -> protocol::ReceiveImportReport {
        protocol::ReceiveImportReport {
            spec: "VFSSEND2".into(),
            imported_roots: 1,
            imported_records: 42,
            imported_payload_bytes: 8192,
            selected_generation: 5,
            selected_transaction_id: 6,
            snapshot_catalog_entries: 2,
            stream_version: 2,
            staging_validated_before_publish: true,
            destination_root_reauthentication: true,
            production_fsck_required: false,
            placement_epoch: Some(7),
            placement_verified_stable: true,
        }
    }

    #[test]
    fn stats_renderer_is_human_oriented_by_default() {
        let report = stats_report();
        let rendered = render_stats_response(&report);

        assert!(rendered.contains("backend: tcp"));
        assert!(rendered.contains("object_count: 3"));
        assert!(rendered.contains("replica_healthy: 1/2"));
        assert!(
            !rendered.contains('{'),
            "default renderer should not emit JSON: {rendered}"
        );

        let diagnostic: serde_json::Value =
            serde_json::from_str(&report.diagnostic_json()).unwrap();
        assert_eq!(diagnostic["object_count"], 3);
    }

    #[test]
    fn receive_renderer_is_human_oriented_by_default() {
        let report = receive_report();
        let rendered = render_receive_response(&report);

        assert!(rendered.contains("spec: VFSSEND2"));
        assert!(rendered.contains("imported_records: 42"));
        assert!(rendered.contains("placement_verified_stable: yes"));
        assert!(
            !rendered.contains('{'),
            "default renderer should not emit JSON: {rendered}"
        );

        let diagnostic: serde_json::Value =
            serde_json::from_str(&report.diagnostic_json()).unwrap();
        assert_eq!(diagnostic["imported_records"], 42);
    }
}
