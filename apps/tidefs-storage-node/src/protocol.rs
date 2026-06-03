//! Binary request/response protocol for tidefs-storage-node.
//!
//! Frames are self-describing binary messages carried over
//! `tidefs-transport` send/recv_message.
//!
//! Every frame starts with a 4-byte ASCII tag followed by
//! tag-specific payload encoded as little-endian.

/// Protocol frame tags (4 bytes, ASCII).
pub mod tag {
    /// Put object: key_len(u32) + key + value_len(u32) + value
    pub const PUT: &[u8; 4] = b"PUT\0";
    /// Get object: key_len(u32) + key; response: ok(u8) + value_len(u32) + value
    pub const GET: &[u8; 4] = b"GET\0";
    /// Delete object: key_len(u32) + key; response: deleted(u8)
    pub const DEL: &[u8; 4] = b"DEL\0";
    /// List keys: no payload; response: count(u32) + [key_len(u16) + key]...
    pub const LST: &[u8; 4] = b"LST\0";
    /// Stats: no payload; response: JSON object
    pub const STA: &[u8; 4] = b"STA\0";
    /// Close session: no payload, no response
    pub const BYE: &[u8; 4] = b"BYE\0";
    /// Error response: error_len(u16) + error_message
    pub const ERR: &[u8; 4] = b"ERR\0";
    /// Send (export): key_len(u16 LE) + key; response: ok(u8=1) + export_len(u64 LE) + export
    pub const SND: &[u8; 4] = b"SND\0";
    /// Receive (import): export_len(u64 LE) + export + key_len(u8) + root_auth_key\[key_len\]
    pub const RCV: &[u8; 4] = b"RCV\0";
    /// Ok response (for PUT, DEL): 1 byte ok
    pub const OK_: &[u8; 4] = b"OK \0";
    /// Health check request/response: request: no payload.
    /// Response: node_identity_len(u8) + node_identity +
    ///   pool_state_len(u16) + pool_state + uptime_secs(u64 LE)
    pub const HLTH: &[u8; 4] = b"HLTH";
    /// Snapshot barrier: coordinator requests all peers to sync and
    /// report their committed-root state before a snapshot is cut.
    /// Request: barrier_id(u64 LE) + name_len(u8) + snapshot_name
    /// Response: barrier_id(u64 LE) + committed_root_txg(u64 LE) +
    ///   committed_root_generation(u64 LE) + object_count(u64 LE)
    pub const SNP: &[u8; 4] = b"SNP\0";
    /// Scrub request: no payload.
    /// Response: report_json_len(u32 LE) + report_json + findings_count(u64 LE)
    pub const SCRB: &[u8; 4] = b"SCRB";
    /// Repair object: key_len(u32 LE) + key + payload_len(u32 LE) + authoritative_payload
    /// Response: ok(u8) + success(u8) + key_len(u32 LE) + key
    pub const RPRR: &[u8; 4] = b"RPRR";

    /// Snapshot lifecycle operations dispatched through the clustered path.
    /// Snapshot create: name_len(u8) + snapshot_name
    pub const SNPC: &[u8; 4] = b"SNPC";
    /// Snapshot destroy: name_len(u8) + snapshot_name
    pub const SNPD: &[u8; 4] = b"SNPD";
    /// Snapshot rollback: name_len(u8) + snapshot_name
    /// Response: ok(u8) + report_json_len(u32 LE) + report_json
    pub const SNPR: &[u8; 4] = b"SNPR";
    /// Snapshot clone: create a writable clone from a snapshot.
    /// Request: clone_name_len(u8) + clone_name + source_snapshot_len(u8) + source_snapshot
    /// Response: ok(u8) + summary_json_len(u32 LE) + summary_json
    pub const SNPCL: &[u8; 4] = b"SNCL";

    // ── Chunked send/receive with resume support ──
    /// Send chunked: request a chunked export (full or incremental) with cursor tracking.
    /// Request: key_len(u16 LE) + key
    /// Response: ok(u8) + chunk_len(u32 LE) + chunk + cursor_len(u8) + cursor + more(u8)
    pub const SNDC: &[u8; 4] = b"SNDC";
    /// Send resume: resume chunked export from a saved cursor.
    /// Request: cursor_len(u8) + cursor
    /// Response: same shape as SendChunk response
    pub const SNDR: &[u8; 4] = b"SNDR";
}

/// An owned protocol frame.
#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Get {
        key: Vec<u8>,
    },
    Delete {
        key: Vec<u8>,
    },
    List,
    Stats,
    Bye,
    Send {
        key: Vec<u8>,
    },
    Receive {
        export: Vec<u8>,
        root_authentication_key: Vec<u8>,
    },
    /// Health check: liveness probe.
    HealthCheck,
    /// Health check response: node identity, pool state, uptime, backend.
    /// The report_json field carries the multi-node operator health and topology
    /// report as a JSON string (empty for compatibility with pre-MN-028 nodes).
    HealthCheckResponse {
        node_identity: String,
        pool_state: String,
        uptime_secs: u64,
        backend: String,
        report_json: String,
    },
    // Responses
    Ok,
    /// Snapshot barrier request: coordinator asks a peer to drain
    /// pending writes and report its committed-root state.
    SnapshotBarrier {
        barrier_id: u64,
        snapshot_name: String,
    },
    /// Snapshot barrier response: peer reports its committed-root
    /// transaction-group id, generation, and object count so the
    /// coordinator can verify cross-node consistency before cutting
    /// a multi-node snapshot.
    SnapshotBarrierResponse {
        barrier_id: u64,
        /// Transaction-group id of the peer's committed root.
        committed_root_txg: u64,
        /// Monotonic generation counter at the peer.
        committed_root_generation: u64,
        /// Number of objects in the peer's store at the barrier
        /// point (diagnostic).
        object_count: u64,
    },
    GetResponse {
        value: Vec<u8>,
    },
    DeleteResponse {
        existed: bool,
    },
    ListResponse {
        keys: Vec<Vec<u8>>,
    },
    SendResponse {
        export: Vec<u8>,
    },
    ReceiveResponse {
        report_json: String,
    },
    StatsResponse {
        json: String,
    },
    Error {
        message: String,
    },

    // ── Multi-node scrub and repair fanout ──
    /// Request the server to run a full segment integrity scrub
    /// on its local object store and return a JSON report.
    ScrubRequest,
    /// Scrub report: JSON-serialized findings.
    ScrubResponse {
        /// JSON report with segments_scanned, records_verified,
        /// bytes_scanned, chain_breaks_detected, completed, findings_count.
        report_json: String,
        /// Number of findings (non-clean outcomes).
        findings_count: u64,
    },
    /// Repair a named object with an authoritative payload.
    RepairObject {
        key: Vec<u8>,
        authoritative_payload: Vec<u8>,
    },
    /// Acknowledge a repair operation.
    RepairObjectAck {
        key: Vec<u8>,
        success: bool,
    },

    // ── Snapshot lifecycle operations through the clustered storage-node path ──
    /// Create a named snapshot of the current dataset root.
    /// The storage node opens its configured fs_root LocalFileSystem,
    /// calls create_snapshot, and returns the summary.
    SnapshotCreate {
        snapshot_name: String,
    },
    /// Response to SnapshotCreate: JSON summary of the created snapshot.
    SnapshotCreateResponse {
        summary_json: String,
    },
    /// Destroy a named snapshot, unpinning its object graph from GC.
    SnapshotDestroy {
        snapshot_name: String,
    },
    /// Response to SnapshotDestroy: JSON summary of the destroyed snapshot.
    SnapshotDestroyResponse {
        summary_json: String,
    },
    /// Rollback the dataset to a named snapshot state.
    SnapshotRollback {
        snapshot_name: String,
    },
    /// Response to SnapshotRollback: JSON report of the rollback operation.
    SnapshotRollbackResponse { report_json: String },
    /// Create a writable clone from a named snapshot.
    SnapshotClone {
        clone_name: String,
        source_snapshot: String,
    },
    /// Response to SnapshotClone: JSON summary of the created clone.
    SnapshotCloneResponse {
        summary_json: String,
    },

    // ── Chunked send/receive with cursor-based resume ──
    /// Request a chunked export (full or incremental) with cursor tracking.
    /// Each chunk includes a cursor that the receiver saves for resume.
    SendChunked {
        key: Vec<u8>,
    },
    /// A chunk of exported data with a resume cursor.
    /// `more` is true when additional chunks follow after this one.
    SendChunkedResponse {
        chunk: Vec<u8>,
        cursor: Vec<u8>,
        more: bool,
    },
    /// Resume a chunked send from a previously saved cursor.
    SendResume {
        cursor: Vec<u8>,
    },
    /// Response to SendResume: the next chunk from the given cursor.
    SendResumeResponse {
        chunk: Vec<u8>,
        cursor: Vec<u8>,
        more: bool,
    },
}

/// Encode a frame into a byte vector suitable for transport send.
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut buf = Vec::new();
    match frame {
        Frame::Put { key, value } => {
            buf.extend_from_slice(tag::PUT);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
            buf.extend_from_slice(value);
        }
        Frame::Get { key } => {
            buf.extend_from_slice(tag::GET);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
        }
        Frame::Delete { key } => {
            buf.extend_from_slice(tag::DEL);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
        }
        Frame::List => {
            buf.extend_from_slice(tag::LST);
        }
        Frame::Stats => {
            buf.extend_from_slice(tag::STA);
        }
        Frame::Bye => {
            buf.extend_from_slice(tag::BYE);
        }
        Frame::Send { key } => {
            buf.extend_from_slice(tag::SND);
            buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
            buf.extend_from_slice(key);
        }
        Frame::Receive {
            export,
            root_authentication_key,
        } => {
            buf.extend_from_slice(tag::RCV);
            buf.extend_from_slice(&(export.len() as u64).to_le_bytes());
            buf.extend_from_slice(export);
            buf.push(root_authentication_key.len() as u8);
            buf.extend_from_slice(root_authentication_key);
        }
        Frame::HealthCheck => {
            buf.extend_from_slice(tag::HLTH);
        }
        Frame::HealthCheckResponse {
            node_identity,
            pool_state,
            uptime_secs,
            backend,
            report_json,
        } => {
            buf.extend_from_slice(tag::HLTH);
            let id_bytes = node_identity.as_bytes();
            buf.push(id_bytes.len() as u8);
            buf.extend_from_slice(id_bytes);
            let ps_bytes = pool_state.as_bytes();
            buf.extend_from_slice(&(ps_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(ps_bytes);
            buf.extend_from_slice(&uptime_secs.to_le_bytes());
            let bk_bytes = backend.as_bytes();
            buf.push(bk_bytes.len() as u8);
            buf.extend_from_slice(bk_bytes);
            let rj_bytes = report_json.as_bytes();
            buf.extend_from_slice(&(rj_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(rj_bytes);
        }
        Frame::SnapshotBarrier {
            barrier_id,
            snapshot_name,
        } => {
            buf.extend_from_slice(tag::SNP);
            buf.extend_from_slice(&barrier_id.to_le_bytes());
            let name_bytes = snapshot_name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        Frame::SnapshotBarrierResponse {
            barrier_id,
            committed_root_txg,
            committed_root_generation,
            object_count,
        } => {
            buf.extend_from_slice(tag::SNP);
            buf.extend_from_slice(&barrier_id.to_le_bytes());
            buf.extend_from_slice(&committed_root_txg.to_le_bytes());
            buf.extend_from_slice(&committed_root_generation.to_le_bytes());
            buf.extend_from_slice(&object_count.to_le_bytes());
        }
        Frame::Ok => {
            buf.extend_from_slice(tag::OK_);
            buf.push(1u8);
        }
        Frame::GetResponse { value } => {
            buf.extend_from_slice(tag::GET);
            buf.push(1u8);
            buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
            buf.extend_from_slice(value);
        }
        Frame::DeleteResponse { existed } => {
            buf.extend_from_slice(tag::DEL);
            buf.push(u8::from(*existed));
        }
        Frame::SendResponse { export } => {
            buf.extend_from_slice(tag::SND);
            buf.push(1u8);
            buf.extend_from_slice(&(export.len() as u64).to_le_bytes());
            buf.extend_from_slice(export);
        }
        Frame::ReceiveResponse { report_json } => {
            buf.extend_from_slice(tag::RCV);
            buf.push(1u8);
            let bytes = report_json.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        Frame::ListResponse { keys } => {
            buf.extend_from_slice(tag::LST);
            buf.extend_from_slice(&(keys.len() as u32).to_le_bytes());
            for k in keys {
                buf.extend_from_slice(&(k.len() as u16).to_le_bytes());
                buf.extend_from_slice(k);
            }
        }
        Frame::StatsResponse { json } => {
            buf.extend_from_slice(tag::STA);
            let bytes = json.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        // ── Scrub/repair fanout ──
        Frame::ScrubRequest => {
            buf.extend_from_slice(tag::SCRB);
        }
        Frame::ScrubResponse {
            report_json,
            findings_count,
        } => {
            buf.extend_from_slice(tag::SCRB);
            buf.push(1u8);
            let bytes = report_json.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&findings_count.to_le_bytes());
        }
        Frame::RepairObject {
            key,
            authoritative_payload,
        } => {
            buf.extend_from_slice(tag::RPRR);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(authoritative_payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(authoritative_payload);
        }
        Frame::RepairObjectAck { key, success } => {
            buf.extend_from_slice(tag::RPRR);
            buf.push(1u8);
            buf.push(u8::from(*success));
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
        }
        // ── Snapshot lifecycle encode ──
        Frame::SnapshotCreate { snapshot_name } => {
            buf.extend_from_slice(tag::SNPC);
            let name_bytes = snapshot_name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        Frame::SnapshotCreateResponse { summary_json } => {
            buf.extend_from_slice(tag::SNPC);
            buf.push(1u8);
            let bytes = summary_json.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        Frame::SnapshotDestroy { snapshot_name } => {
            buf.extend_from_slice(tag::SNPD);
            let name_bytes = snapshot_name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        Frame::SnapshotDestroyResponse { summary_json } => {
            buf.extend_from_slice(tag::SNPD);
            buf.push(1u8);
            let bytes = summary_json.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        Frame::SnapshotRollback { snapshot_name } => {
            buf.extend_from_slice(tag::SNPR);
            let name_bytes = snapshot_name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        Frame::SnapshotRollbackResponse { report_json } => {
            buf.extend_from_slice(tag::SNPR);
            buf.push(1u8);
            let bytes = report_json.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        Frame::SnapshotClone { clone_name, source_snapshot } => {
            buf.extend_from_slice(tag::SNPCL);
            let cn_bytes = clone_name.as_bytes();
            buf.push(cn_bytes.len() as u8);
            buf.extend_from_slice(cn_bytes);
            let ss_bytes = source_snapshot.as_bytes();
            buf.push(ss_bytes.len() as u8);
            buf.extend_from_slice(ss_bytes);
        }
        Frame::SnapshotCloneResponse { summary_json } => {
            buf.extend_from_slice(tag::SNPCL);
            buf.push(1u8);
            let bytes = summary_json.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        // ── Chunked send/receive encode ──
        Frame::SendChunked { key } => {
            buf.extend_from_slice(tag::SNDC);
            buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
            buf.extend_from_slice(key);
        }
        Frame::SendChunkedResponse { chunk, cursor, more } => {
            buf.extend_from_slice(tag::SNDC);
            buf.push(1u8); // ok marker
            buf.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            buf.extend_from_slice(chunk);
            buf.push(cursor.len() as u8);
            buf.extend_from_slice(cursor);
            buf.push(u8::from(*more));
        }
        Frame::SendResume { cursor } => {
            buf.extend_from_slice(tag::SNDR);
            buf.push(cursor.len() as u8);
            buf.extend_from_slice(cursor);
        }
        Frame::SendResumeResponse { chunk, cursor, more } => {
            buf.extend_from_slice(tag::SNDR);
            buf.push(1u8);
            buf.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            buf.extend_from_slice(chunk);
            buf.push(cursor.len() as u8);
            buf.extend_from_slice(cursor);
            buf.push(u8::from(*more));
        }
        Frame::Error { message } => {
            buf.extend_from_slice(tag::ERR);
            let bytes = message.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
    }
    buf
}

/// Decode a frame from raw bytes.
///
/// Returns `None` if the frame is incomplete or malformed.
pub fn decode(data: &[u8]) -> Option<Frame> {
    if data.len() < 4 {
        return None;
    }
    let tag = &data[0..4];
    let payload = &data[4..];

    // Helper to decode request/response pairs sharing the same tag.
    match tag {
        t if t == tag::PUT => {
            if payload.len() < 4 {
                return None;
            }
            let key_len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
            let key_start = 4;
            if payload.len() < key_start + key_len + 4 {
                return None;
            }
            let key = payload[key_start..key_start + key_len].to_vec();
            let val_start = key_start + key_len;
            let val_len =
                u32::from_le_bytes(payload[val_start..val_start + 4].try_into().ok()?) as usize;
            if payload.len() < val_start + 4 + val_len {
                return None;
            }
            let value = payload[val_start + 4..val_start + 4 + val_len].to_vec();
            Some(Frame::Put { key, value })
        }
        t if t == tag::GET => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 5 {
                // Response: ok(u8=1) + value_len(u32) + value
                let val_len = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + val_len {
                    return None;
                }
                let value = payload[5..5 + val_len].to_vec();
                Some(Frame::GetResponse { value })
            } else if payload.len() >= 4 {
                // Request: key_len(u32) + key
                let key_len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                if payload.len() < 4 + key_len {
                    return None;
                }
                let key = payload[4..4 + key_len].to_vec();
                Some(Frame::Get { key })
            } else {
                None
            }
        }
        t if t == tag::DEL => {
            if payload.is_empty() {
                return None;
            }
            if payload.len() == 1 && (payload[0] == 0 || payload[0] == 1) {
                // Response: ok(u8)
                Some(Frame::DeleteResponse {
                    existed: payload[0] == 1,
                })
            } else if payload.len() >= 4 {
                // Request: key_len(u32) + key
                let key_len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                if payload.len() < 4 + key_len {
                    return None;
                }
                let key = payload[4..4 + key_len].to_vec();
                Some(Frame::Delete { key })
            } else {
                None
            }
        }
        t if t == tag::SND => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 9 {
                // Response: ok(u8=1) + export_len(u64) + export
                let elen = u64::from_le_bytes(payload[1..9].try_into().ok()?) as usize;
                if payload.len() < 9 + elen {
                    return None;
                }
                Some(Frame::SendResponse {
                    export: payload[9..9 + elen].to_vec(),
                })
            } else if payload.len() >= 2 {
                // Request: key_len(u16) + key
                let klen = u16::from_le_bytes(payload[0..2].try_into().ok()?) as usize;
                if payload.len() < 2 + klen {
                    return None;
                }
                Some(Frame::Send {
                    key: payload[2..2 + klen].to_vec(),
                })
            } else {
                None
            }
        }
        t if t == tag::RCV => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 5 {
                // Response: ok(u8=1) + json_len(u32) + json
                let jlen = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + jlen {
                    return None;
                }
                let json = String::from_utf8(payload[5..5 + jlen].to_vec()).ok()?;
                Some(Frame::ReceiveResponse { report_json: json })
            } else if payload.len() >= 8 {
                // Request: export_len(u64) + export + key_len(u8) + root_auth_key[key_len]
                let elen = u64::from_le_bytes(payload[0..8].try_into().ok()?) as usize;
                if payload.len() < 8 + elen + 1 {
                    return None;
                }
                let exp = payload[8..8 + elen].to_vec();
                let kp = 8 + elen;
                let klen = payload[kp] as usize;
                if payload.len() < kp + 1 + klen {
                    return None;
                }
                let rk = payload[kp + 1..kp + 1 + klen].to_vec();
                Some(Frame::Receive {
                    export: exp,
                    root_authentication_key: rk,
                })
            } else {
                None
            }
        }
        t if t == tag::LST => {
            if payload.is_empty() {
                Some(Frame::List)
            } else if payload.len() >= 4 {
                let count = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                let mut pos = 4;
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    if payload.len() < pos + 2 {
                        return None;
                    }
                    let klen = u16::from_le_bytes(payload[pos..pos + 2].try_into().ok()?) as usize;
                    pos += 2;
                    if payload.len() < pos + klen {
                        return None;
                    }
                    keys.push(payload[pos..pos + klen].to_vec());
                    pos += klen;
                }
                Some(Frame::ListResponse { keys })
            } else {
                None
            }
        }
        t if t == tag::STA => {
            if payload.is_empty() {
                Some(Frame::Stats)
            } else if payload.len() >= 4 {
                let len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                if payload.len() < 4 + len {
                    return None;
                }
                let json = String::from_utf8(payload[4..4 + len].to_vec()).ok()?;
                Some(Frame::StatsResponse { json })
            } else {
                None
            }
        }
        t if t == tag::BYE => Some(Frame::Bye),
        t if t == tag::OK_ => {
            if payload.is_empty() {
                return None;
            }
            Some(if payload[0] == 1 {
                Frame::Ok
            } else {
                Frame::Error {
                    message: "unknown error".into(),
                }
            })
        }
        t if t == tag::HLTH => {
            if payload.is_empty() {
                Some(Frame::HealthCheck)
            } else if payload.len() >= 12 {
                let id_len = payload[0] as usize;
                if payload.len() < 1 + id_len + 2 {
                    return None;
                }
                let node_identity = String::from_utf8(payload[1..1 + id_len].to_vec()).ok()?;
                let ps_start = 1 + id_len;
                let ps_len =
                    u16::from_le_bytes(payload[ps_start..ps_start + 2].try_into().ok()?) as usize;
                if payload.len() < ps_start + 2 + ps_len + 8 {
                    return None;
                }
                let pool_state =
                    String::from_utf8(payload[ps_start + 2..ps_start + 2 + ps_len].to_vec())
                        .ok()?;
                let uptime_secs = u64::from_le_bytes(
                    payload[ps_start + 2 + ps_len..ps_start + 2 + ps_len + 8]
                        .try_into()
                        .ok()?,
                );
                // Backend disclosure field (optional, added after uptime_secs)
                let backend = if payload.len() > ps_start + 2 + ps_len + 8 {
                    let bk_start = ps_start + 2 + ps_len + 8;
                    let bk_len = payload[bk_start] as usize;
                    if payload.len() >= bk_start + 1 + bk_len {
                        String::from_utf8(payload[bk_start + 1..bk_start + 1 + bk_len].to_vec())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                // report_json: optional field after backend (added MN-028).
                // Format: report_json_len(u32 LE) + report_json bytes.
                let report_json = {
                    let bk_start = ps_start + 2 + ps_len + 8;
                    let bk_len = payload.get(bk_start).copied().unwrap_or(0) as usize;
                    let rj_start = bk_start + 1 + bk_len;
                    if payload.len() >= rj_start + 4 {
                        let rj_len =
                            u32::from_le_bytes(payload[rj_start..rj_start + 4].try_into().ok()?)
                                as usize;
                        if payload.len() >= rj_start + 4 + rj_len {
                            String::from_utf8(payload[rj_start + 4..rj_start + 4 + rj_len].to_vec())
                                .unwrap_or_default()
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                };
                Some(Frame::HealthCheckResponse {
                    node_identity,
                    pool_state,
                    uptime_secs,
                    backend,
                    report_json,
                })
            } else {
                Some(Frame::HealthCheck)
            }
        }
        t if t == tag::SNP => {
            // Distinguish request vs response by payload layout.
            // Request: barrier_id(u64 LE) + name_len(u8) + name
            // Response: barrier_id(u64 LE) + txg(u64 LE) + gen(u64 LE) + count(u64 LE)
            if payload.len() < 8 {
                return None;
            }
            let barrier_id = u64::from_le_bytes(payload[0..8].try_into().ok()?);
            // Response payload has 3 additional u64 fields (txg, gen, count) = 24 bytes
            if payload.len() == 8 + 24 {
                let committed_root_txg = u64::from_le_bytes(payload[8..16].try_into().ok()?);
                let committed_root_generation =
                    u64::from_le_bytes(payload[16..24].try_into().ok()?);
                let object_count = u64::from_le_bytes(payload[24..32].try_into().ok()?);
                Some(Frame::SnapshotBarrierResponse {
                    barrier_id,
                    committed_root_txg,
                    committed_root_generation,
                    object_count,
                })
            } else if payload.len() >= 9 {
                // Request: name_len(u8) followed by name bytes
                let name_len = payload[8] as usize;
                if payload.len() < 9 + name_len {
                    return None;
                }
                let snapshot_name = String::from_utf8(payload[9..9 + name_len].to_vec()).ok()?;
                Some(Frame::SnapshotBarrier {
                    barrier_id,
                    snapshot_name,
                })
            } else {
                // Exactly 8 bytes: barrier_id only. Treat as a
                // no-name barrier (internal flush-only request).
                Some(Frame::SnapshotBarrier {
                    barrier_id,
                    snapshot_name: String::new(),
                })
            }
        }
        // ── Scrub request/response ──
        t if t == tag::SCRB => {
            if payload.is_empty() {
                Some(Frame::ScrubRequest)
            } else if payload.len() >= 13 && payload[0] == 1 {
                // Response: ok(u8=1) + report_json_len(u32 LE) + report_json + findings_count(u64 LE)
                let rj_len = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + rj_len + 8 {
                    return None;
                }
                let report_json = String::from_utf8(payload[5..5 + rj_len].to_vec()).ok()?;
                let findings_count =
                    u64::from_le_bytes(payload[5 + rj_len..5 + rj_len + 8].try_into().ok()?);
                Some(Frame::ScrubResponse {
                    report_json,
                    findings_count,
                })
            } else {
                // Empty or malformed: treat as ScrubRequest
                Some(Frame::ScrubRequest)
            }
        }
        // ── Repair object request/ack ──
        t if t == tag::RPRR => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 6 {
                // Response: ok(u8=1) + success(u8) + key_len(u32 LE) + key.
                // A request with a one-byte key also starts with 1 because its
                // key_len is u32(1), so only accept the ack shape when the frame
                // length matches exactly; otherwise fall through to request
                // decoding.
                let key_len = u32::from_le_bytes(payload[2..6].try_into().ok()?) as usize;
                if payload.len() == 6 + key_len {
                    let success = payload[1] != 0;
                    let key = payload[6..6 + key_len].to_vec();
                    return Some(Frame::RepairObjectAck { key, success });
                }
            }
            if payload.len() >= 4 {
                // Request: key_len(u32 LE) + key + payload_len(u32 LE) + authoritative_payload
                let key_len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                if payload.len() < 4 + key_len + 4 {
                    return None;
                }
                let key = payload[4..4 + key_len].to_vec();
                let pl_start = 4 + key_len;
                let pl_len =
                    u32::from_le_bytes(payload[pl_start..pl_start + 4].try_into().ok()?) as usize;
                if payload.len() < pl_start + 4 + pl_len {
                    return None;
                }
                let authoritative_payload = payload[pl_start + 4..pl_start + 4 + pl_len].to_vec();
                Some(Frame::RepairObject {
                    key,
                    authoritative_payload,
                })
            } else {
                None
            }
        }
        // ── Snapshot lifecycle tag decoders ──
        t if t == tag::SNPC => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 5 {
                // Response: ok(u8=1) + json_len(u32 LE) + json
                let jlen = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + jlen {
                    return None;
                }
                let summary_json = String::from_utf8(payload[5..5 + jlen].to_vec()).ok()?;
                Some(Frame::SnapshotCreateResponse { summary_json })
            } else if payload.len() >= 1 {
                // Request: name_len(u8) + snapshot_name
                let name_len = payload[0] as usize;
                if payload.len() < 1 + name_len {
                    return None;
                }
                let snapshot_name = String::from_utf8(payload[1..1 + name_len].to_vec()).ok()?;
                Some(Frame::SnapshotCreate { snapshot_name })
            } else {
                None
            }
        }
        t if t == tag::SNPD => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 5 {
                // Response: ok(u8=1) + json_len(u32 LE) + json
                let jlen = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + jlen {
                    return None;
                }
                let summary_json = String::from_utf8(payload[5..5 + jlen].to_vec()).ok()?;
                Some(Frame::SnapshotDestroyResponse { summary_json })
            } else if payload.len() >= 1 {
                // Request: name_len(u8) + snapshot_name
                let name_len = payload[0] as usize;
                if payload.len() < 1 + name_len {
                    return None;
                }
                let snapshot_name = String::from_utf8(payload[1..1 + name_len].to_vec()).ok()?;
                Some(Frame::SnapshotDestroy { snapshot_name })
            } else {
                None
            }
        }
        t if t == tag::SNPCL => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 5 {
                // Response: ok(u8=1) + json_len(u32 LE) + json
                let jlen = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + jlen {
                    return None;
                }
                let summary_json = String::from_utf8(payload[5..5 + jlen].to_vec()).ok()?;
                Some(Frame::SnapshotCloneResponse { summary_json })
            } else if payload.len() >= 2 {
                // Request: clone_name_len(u8) + clone_name + source_snapshot_len(u8) + source_snapshot
                let cn_len = payload[0] as usize;
                if payload.len() < 1 + cn_len + 1 {
                    return None;
                }
                let clone_name = String::from_utf8(payload[1..1 + cn_len].to_vec()).ok()?;
                let ss_off = 1 + cn_len;
                let ss_len = payload[ss_off] as usize;
                if payload.len() < ss_off + 1 + ss_len {
                    return None;
                }
                let source_snapshot = String::from_utf8(payload[ss_off + 1..ss_off + 1 + ss_len].to_vec()).ok()?;
                Some(Frame::SnapshotClone { clone_name, source_snapshot })
            } else {
                None
            }
        }
        // ── Chunked send/receive tag decoders ──
        t if t == tag::SNDC => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 7 {
                // Response: ok(u8=1) + chunk_len(u32 LE) + chunk + cursor_len(u8) + cursor + more(u8)
                let clen = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + clen + 1 {
                    return None;
                }
                let chunk = payload[5..5 + clen].to_vec();
                let co = 5 + clen;
                let cl = payload[co] as usize;
                if payload.len() < co + 1 + cl + 1 {
                    return None;
                }
                let cursor = payload[co + 1..co + 1 + cl].to_vec();
                let more = payload[co + 1 + cl] != 0;
                Some(Frame::SendChunkedResponse { chunk, cursor, more })
            } else if payload.len() >= 2 {
                // Request: key_len(u16 LE) + key
                let klen = u16::from_le_bytes(payload[0..2].try_into().ok()?) as usize;
                if payload.len() < 2 + klen {
                    return None;
                }
                Some(Frame::SendChunked {
                    key: payload[2..2 + klen].to_vec(),
                })
            } else {
                None
            }
        }
        t if t == tag::SNDR => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 7 {
                // Response: ok(u8=1) + chunk_len(u32 LE) + chunk + cursor_len(u8) + cursor + more(u8)
                let clen = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + clen + 1 {
                    return None;
                }
                let chunk = payload[5..5 + clen].to_vec();
                let co = 5 + clen;
                let cl = payload[co] as usize;
                if payload.len() < co + 1 + cl + 1 {
                    return None;
                }
                let cursor = payload[co + 1..co + 1 + cl].to_vec();
                let more = payload[co + 1 + cl] != 0;
                Some(Frame::SendResumeResponse { chunk, cursor, more })
            } else if payload.len() >= 1 {
                // Request: cursor_len(u8) + cursor
                let cl = payload[0] as usize;
                if payload.len() < 1 + cl {
                    return None;
                }
                let cursor = payload[1..1 + cl].to_vec();
                Some(Frame::SendResume { cursor })
            } else {
                None
            }
        }
        t if t == tag::SNPR => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 5 {
                // Response: ok(u8=1) + json_len(u32 LE) + json
                let jlen = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() < 5 + jlen {
                    return None;
                }
                let report_json = String::from_utf8(payload[5..5 + jlen].to_vec()).ok()?;
                Some(Frame::SnapshotRollbackResponse { report_json })
            } else if payload.len() >= 1 {
                // Request: name_len(u8) + snapshot_name
                let name_len = payload[0] as usize;
                if payload.len() < 1 + name_len {
                    return None;
                }
                let snapshot_name = String::from_utf8(payload[1..1 + name_len].to_vec()).ok()?;
                Some(Frame::SnapshotRollback { snapshot_name })
            } else {
                None
            }
        }
        t if t == tag::ERR => {
            if payload.len() < 2 {
                return None;
            }
            let len = u16::from_le_bytes(payload[0..2].try_into().ok()?) as usize;
            if payload.len() < 2 + len {
                return None;
            }
            let message = String::from_utf8(payload[2..2 + len].to_vec()).ok()?;
            Some(Frame::Error { message })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_put() {
        let f = Frame::Put {
            key: b"hello".to_vec(),
            value: b"world".to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_get_request() {
        let f = Frame::Get {
            key: b"mykey".to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_get_response() {
        let f = Frame::GetResponse {
            value: b"some data".to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_delete_request() {
        let f = Frame::Delete {
            key: b"oldkey".to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_delete_response() {
        let f = Frame::DeleteResponse { existed: true };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_list_response() {
        let f = Frame::ListResponse {
            keys: vec![b"a".to_vec(), b"bb".to_vec()],
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_stats_response() {
        let f = Frame::StatsResponse {
            json: "{\"ok\":true}".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_error() {
        let f = Frame::Error {
            message: "not found".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_list_request() {
        let f = Frame::List;
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_stats_request() {
        let f = Frame::Stats;
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn decode_empty_returns_none() {
        assert_eq!(decode(&[]), None);
    }
    #[test]
    fn decode_short_returns_none() {
        assert_eq!(decode(b"PU"), None);
    }
    #[test]
    fn roundtrip_bye() {
        let f = Frame::Bye;
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_ok() {
        let f = Frame::Ok;
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_send_request_full() {
        let f = Frame::Send { key: vec![] };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_send_request_incremental() {
        let f = Frame::Send { key: vec![0u8; 24] };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_send_response() {
        let f = Frame::SendResponse {
            export: vec![0xAA; 1024],
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_receive_request() {
        let f = Frame::Receive {
            export: vec![0xBB; 512],
            root_authentication_key: vec![0x41; 32],
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
    #[test]
    fn roundtrip_receive_response() {
        let f = Frame::ReceiveResponse {
            report_json: "{\"imported_records\":42}".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_health_check_request() {
        let f = Frame::HealthCheck;
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_health_check_response() {
        let f = Frame::HealthCheckResponse {
            node_identity: "node-7.rack-3".into(),
            pool_state: "imported".into(),
            uptime_secs: 42,
            backend: "tcp:10.0.0.1:9090".into(),
            report_json: String::new(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_health_check_response_degraded() {
        let f = Frame::HealthCheckResponse {
            node_identity: "node-1".into(),
            pool_state: "degraded".into(),
            uptime_secs: 3600,
            backend: "loopback".into(),
            report_json: String::new(),
        };
        let encoded = encode(&f);
        let decoded = decode(&encoded);
        assert!(matches!(decoded, Some(Frame::HealthCheckResponse { .. })));
    }
    // ── Scrub/repair frame roundtrip tests ──

    #[test]
    fn roundtrip_scrub_request() {
        let f = Frame::ScrubRequest;
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_scrub_response() {
        let f = Frame::ScrubResponse {
            report_json: r#"{"segments_scanned":5,"findings_count":0}"#.into(),
            findings_count: 0,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_scrub_response_with_findings() {
        let f = Frame::ScrubResponse {
            report_json: r#"{"segments_scanned":3,"records_verified":42,"findings_count":2}"#
                .into(),
            findings_count: 2,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object() {
        let f = Frame::RepairObject {
            key: b"corrupted-obj".to_vec(),
            authoritative_payload: b"fixed-data".to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object_one_byte_key() {
        let f = Frame::RepairObject {
            key: b"k".to_vec(),
            authoritative_payload: b"fixed-data".to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object_ack_success() {
        let f = Frame::RepairObjectAck {
            key: b"fixed-obj".to_vec(),
            success: true,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object_ack_failure() {
        let f = Frame::RepairObjectAck {
            key: b"still-broken".to_vec(),
            success: false,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_receive_large_export() {
        let f = Frame::Receive {
            export: vec![0xCC; 65536],
            root_authentication_key: vec![0x41; 32],
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    // ── Snapshot lifecycle roundtrip tests ──
    #[test]
    fn roundtrip_snapshot_create_request() {
        let f = Frame::SnapshotCreate {
            snapshot_name: "before-upgrade".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_create_response() {
        let f = Frame::SnapshotCreateResponse {
            summary_json: r#"{"name":"before-upgrade","generation":42}"#.into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_destroy_request() {
        let f = Frame::SnapshotDestroy {
            snapshot_name: "old-snap".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_destroy_response() {
        let f = Frame::SnapshotDestroyResponse {
            summary_json: r#"{"name":"old-snap","destroyed":true}"#.into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_rollback_request() {
        let f = Frame::SnapshotRollback {
            snapshot_name: "safe-point".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_rollback_response() {
        let f = Frame::SnapshotRollbackResponse {
            report_json: r#"{"generation_before":100,"published_generation":101}"#.into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_rollback_long_name() {
        let f = Frame::SnapshotRollback {
            snapshot_name: "tidefs-autosnap-2026-05-28T14-30-00Z".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    // ── Snapshot clone roundtrip tests ──
    #[test]
    fn roundtrip_snapshot_clone_request() {
        let f = Frame::SnapshotClone {
            clone_name: "myclone".into(),
            source_snapshot: "origin-snap".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_clone_response() {
        let f = Frame::SnapshotCloneResponse {
            summary_json: r#"{"name":"myclone","origin":"origin-snap","source_generation":42}"#.into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_snapshot_clone_long_names() {
        let f = Frame::SnapshotClone {
            clone_name: "writable-clone-of-before-major-upgrade-v2".into(),
            source_snapshot: "autosnap-2026-05-28T14-30-00Z-pre-upgrade".into(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    // ── Chunked send/receive roundtrip tests ──
    #[test]
    fn roundtrip_send_chunked_request_full() {
        let f = Frame::SendChunked { key: vec![] };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_send_chunked_request_incremental() {
        let f = Frame::SendChunked { key: vec![0u8; 24] };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_send_chunked_response_more() {
        let f = Frame::SendChunkedResponse {
            chunk: vec![0xAA; 8192],
            cursor: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            more: true,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_send_chunked_response_last() {
        let f = Frame::SendChunkedResponse {
            chunk: vec![0xBB; 1024],
            cursor: vec![0xFF; 16],
            more: false,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_send_resume_request() {
        let f = Frame::SendResume {
            cursor: vec![0x01, 0x02, 0x03, 0x04],
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_send_resume_response() {
        let f = Frame::SendResumeResponse {
            chunk: vec![0xCC; 4096],
            cursor: vec![0x10, 0x20, 0x30, 0x40],
            more: true,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }
}
