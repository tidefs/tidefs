//! Storage node client: connect and issue put/get/delete/list/stats/send/receive commands.

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
                Frame::Ok => println!("ok"),
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
                Frame::StatsResponse { json } => println!("{json}"),
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
                Frame::ScrubResponse {
                    report_json,
                    findings_count,
                } => {
                    println!("findings_count: {findings_count}");
                    println!("{report_json}");
                }
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
                Frame::ReceiveResponse { report_json } => println!("{report_json}"),
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
                    report_json,
                } => {
                    println!("node_identity: {node_identity}");
                    println!("pool_state:    {pool_state}");
                    println!("uptime_secs:   {uptime_secs}");
                    println!("backend:       {backend}");
                    if !report_json.is_empty() {
                        println!("report:");
                        println!("{report_json}");
                    }
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
                Frame::SnapshotCreateResponse { summary_json } => {
                    let _ =
                        std::io::Write::write_all(&mut std::io::stdout(), summary_json.as_bytes());
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
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
                Frame::SnapshotDestroyResponse { summary_json } => {
                    let _ =
                        std::io::Write::write_all(&mut std::io::stdout(), summary_json.as_bytes());
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
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
                Frame::SnapshotRollbackResponse { report_json } => {
                    let _ =
                        std::io::Write::write_all(&mut std::io::stdout(), report_json.as_bytes());
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
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
                Frame::SnapshotCloneResponse { summary_json } => {
                    let _ =
                        std::io::Write::write_all(&mut std::io::stdout(), summary_json.as_bytes());
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
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
