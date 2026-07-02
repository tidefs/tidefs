// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Binary request/response protocol for tidefs-storage-node.
//!
//! Frames are self-describing binary messages carried over
//! `tidefs-transport` send/recv_message.
//!
//! Every frame starts with a 4-byte ASCII tag followed by
//! tag-specific payload encoded as little-endian.

use tidefs_membership_epoch::EpochId;
use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy};

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
    /// Stats: no payload; response: versioned typed stats report
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
    /// Response: versioned typed node and topology health report.
    pub const HLTH: &[u8; 4] = b"HLTH";
    /// Snapshot barrier: coordinator requests all peers to sync and
    /// report their committed-root state before a snapshot is cut.
    /// Request: barrier_id(u64 LE) + name_len(u8) + snapshot_name
    /// Response: barrier_id(u64 LE) + committed_root_txg(u64 LE) +
    ///   committed_root_generation(u64 LE) + object_count(u64 LE)
    pub const SNP: &[u8; 4] = b"SNP\0";
    /// Scrub request: no payload.
    /// Response: versioned typed scrub summary and findings count.
    pub const SCRB: &[u8; 4] = b"SCRB";
    /// Repair object:
    /// key_len(u32 LE) + key + placement_receipt_ref + payload_len(u32 LE) + authoritative_payload
    /// Response: ok(u8) + success(u8) + key_len(u32 LE) + key
    ///           + optional has_repaired_receipt(u8) + placement_receipt_ref
    pub const RPRR: &[u8; 4] = b"RPRR";

    /// Put object with placement receipt authority:
    /// key_len(u32 LE) + key + placement_receipt_ref + value_len(u32 LE) + value
    /// Response: ok(u8=1) + key_len(u32 LE) + key
    ///           + has_recorded_receipt(u8) + placement_receipt_ref
    pub const PUTW: &[u8; 4] = b"PUTW";

    /// Snapshot lifecycle operations dispatched through the clustered path.
    /// Snapshot create: name_len(u8) + snapshot_name
    pub const SNPC: &[u8; 4] = b"SNPC";
    /// Snapshot destroy: name_len(u8) + snapshot_name
    pub const SNPD: &[u8; 4] = b"SNPD";
    /// Snapshot rollback: name_len(u8) + snapshot_name
    /// Response: ok(u8) + versioned typed rollback report
    pub const SNPR: &[u8; 4] = b"SNPR";
    /// Snapshot clone: create a writable clone from a snapshot.
    /// Request: clone_name_len(u8) + clone_name + source_snapshot_len(u8) + source_snapshot
    /// Response: ok(u8) + versioned typed clone summary
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

const RECEIPT_POLICY_REPLICATED: u8 = 0;
const RECEIPT_POLICY_ERASURE: u8 = 1;
const PLACEMENT_RECEIPT_REF_WIRE_LEN: usize = 8 + 32 + 8 + 8 + 4 + 8 + 32 + 2;
const RESPONSE_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatsReport {
    pub backend: String,
    pub object_count: u64,
    pub bytes_written: u64,
    pub committed_writes: Option<u64>,
    pub degraded_writes: Option<u64>,
    pub refused_writes: Option<u64>,
    pub failed_writes: Option<u64>,
    pub degraded_reads: Option<u64>,
    pub replica_healthy: Option<Vec<bool>>,
    pub total_capacity_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub placement_receipt_ref_count: Option<u64>,
}

impl StatsReport {
    pub fn diagnostic_json(&self) -> String {
        let mut object = serde_json::Map::new();
        object.insert("backend".into(), serde_json::json!(self.backend));
        object.insert("object_count".into(), serde_json::json!(self.object_count));
        object.insert(
            "bytes_written".into(),
            serde_json::json!(self.bytes_written),
        );
        insert_optional_u64(&mut object, "committed_writes", self.committed_writes);
        insert_optional_u64(&mut object, "degraded_writes", self.degraded_writes);
        insert_optional_u64(&mut object, "refused_writes", self.refused_writes);
        insert_optional_u64(&mut object, "failed_writes", self.failed_writes);
        insert_optional_u64(&mut object, "degraded_reads", self.degraded_reads);
        if let Some(replica_healthy) = &self.replica_healthy {
            object.insert("replica_healthy".into(), serde_json::json!(replica_healthy));
        }
        insert_optional_u64(
            &mut object,
            "total_capacity_bytes",
            self.total_capacity_bytes,
        );
        insert_optional_u64(&mut object, "used_bytes", self.used_bytes);
        insert_optional_u64(&mut object, "available_bytes", self.available_bytes);
        insert_optional_u64(
            &mut object,
            "placement_receipt_ref_count",
            self.placement_receipt_ref_count,
        );
        serde_json::Value::Object(object).to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthPeerReport {
    pub member_id: u64,
    pub member_class: String,
    pub health: String,
    pub failure_domain: u64,
    pub failed_pings: u32,
    pub joining: bool,
    pub draining: bool,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DegradedPeerReport {
    pub member_id: u64,
    pub health: String,
    pub failed_pings: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HealthSummary {
    pub healthy: u64,
    pub suspect: u64,
    pub down: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RosterStateSummary {
    pub active: u64,
    pub suspected: u64,
    pub failed: u64,
    pub left: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureDomainReport {
    pub failure_domain: u64,
    pub member_count: u64,
    pub members: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportBackendReport {
    pub session_id: u64,
    pub peer_node: Option<u64>,
    pub backend_kind: String,
    pub disclosure: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthReport {
    pub node_id: u64,
    pub node_member_class: Option<String>,
    pub node_failure_domain: Option<u64>,
    pub carrier: String,
    pub carrier_is_live: bool,
    pub replication_factor: u8,
    pub placement_version: u64,
    pub peers: Vec<HealthPeerReport>,
    pub peer_count: u64,
    pub alive_voters: Vec<u64>,
    pub quorum_lost: bool,
    pub roster_size: u64,
    pub roster_state_summary: RosterStateSummary,
    pub health_summary: HealthSummary,
    pub degraded_peers: Vec<DegradedPeerReport>,
    pub failure_domains: Vec<FailureDomainReport>,
    pub transport_backends: Vec<TransportBackendReport>,
}

impl HealthReport {
    pub fn diagnostic_json(&self) -> String {
        serde_json::json!({
            "node_id": self.node_id,
            "node_member_class": self.node_member_class,
            "node_failure_domain": self.node_failure_domain,
            "carrier": self.carrier,
            "carrier_is_live": self.carrier_is_live,
            "replication_factor": self.replication_factor,
            "placement_version": self.placement_version,
            "peers": self.peers.iter().map(|p| serde_json::json!({
                "member_id": p.member_id,
                "member_class": p.member_class,
                "health": p.health,
                "failure_domain": p.failure_domain,
                "failed_pings": p.failed_pings,
                "joining": p.joining,
                "draining": p.draining,
                "epoch": p.epoch,
            })).collect::<Vec<_>>(),
            "peer_count": self.peer_count,
            "alive_voters": self.alive_voters,
            "quorum_lost": self.quorum_lost,
            "roster_size": self.roster_size,
            "roster_state_summary": {
                "active": self.roster_state_summary.active,
                "suspected": self.roster_state_summary.suspected,
                "failed": self.roster_state_summary.failed,
                "left": self.roster_state_summary.left,
            },
            "health_summary": {
                "healthy": self.health_summary.healthy,
                "suspect": self.health_summary.suspect,
                "down": self.health_summary.down,
            },
            "degraded_peers": self.degraded_peers.iter().map(|p| serde_json::json!({
                "member_id": p.member_id,
                "health": p.health,
                "failed_pings": p.failed_pings,
            })).collect::<Vec<_>>(),
            "failure_domains": self.failure_domains.iter().map(|d| serde_json::json!({
                "failure_domain": d.failure_domain,
                "member_count": d.member_count,
                "members": d.members,
            })).collect::<Vec<_>>(),
            "transport_backends": self.transport_backends.iter().map(|b| serde_json::json!({
                "session_id": b.session_id,
                "peer_node": b.peer_node,
                "backend_kind": b.backend_kind,
                "disclosure": b.disclosure,
            })).collect::<Vec<_>>(),
        })
        .to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveImportReport {
    pub spec: String,
    pub imported_roots: u64,
    pub imported_records: u64,
    pub imported_payload_bytes: u64,
    pub selected_generation: u64,
    pub selected_transaction_id: u64,
    pub snapshot_catalog_entries: u64,
    pub stream_version: u16,
    pub staging_validated_before_publish: bool,
    pub destination_root_reauthentication: bool,
    pub production_fsck_required: bool,
    pub placement_epoch: Option<u64>,
    pub placement_verified_stable: bool,
}

impl ReceiveImportReport {
    pub fn diagnostic_json(&self) -> String {
        serde_json::json!({
            "spec": self.spec,
            "imported_roots": self.imported_roots,
            "imported_records": self.imported_records,
            "imported_payload_bytes": self.imported_payload_bytes,
            "selected_generation": self.selected_generation,
            "selected_transaction_id": self.selected_transaction_id,
            "snapshot_catalog_entries": self.snapshot_catalog_entries,
            "stream_version": self.stream_version,
            "staging_validated_before_publish": self.staging_validated_before_publish,
            "destination_root_reauthentication": self.destination_root_reauthentication,
            "production_fsck_required": self.production_fsck_required,
            "placement_epoch": self.placement_epoch,
            "placement_verified_stable": self.placement_verified_stable,
        })
        .to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubReport {
    pub backend: Option<String>,
    pub segments_scanned: u64,
    pub records_verified: u64,
    pub bytes_scanned: u64,
    pub chain_breaks_detected: u64,
    pub completed: bool,
    pub findings_count: u64,
    pub placement_receipt_ref_count: u64,
    pub error: Option<String>,
}

impl ScrubReport {
    pub fn diagnostic_json(&self) -> String {
        let mut object = serde_json::Map::new();
        if let Some(backend) = &self.backend {
            object.insert("backend".into(), serde_json::json!(backend));
        }
        object.insert(
            "segments_scanned".into(),
            serde_json::json!(self.segments_scanned),
        );
        object.insert(
            "records_verified".into(),
            serde_json::json!(self.records_verified),
        );
        object.insert(
            "bytes_scanned".into(),
            serde_json::json!(self.bytes_scanned),
        );
        object.insert(
            "chain_breaks_detected".into(),
            serde_json::json!(self.chain_breaks_detected),
        );
        object.insert("completed".into(), serde_json::json!(self.completed));
        object.insert(
            "findings_count".into(),
            serde_json::json!(self.findings_count),
        );
        object.insert(
            "placement_receipt_ref_count".into(),
            serde_json::json!(self.placement_receipt_ref_count),
        );
        if let Some(error) = &self.error {
            object.insert("error".into(), serde_json::json!(error));
        }
        serde_json::Value::Object(object).to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotSummaryReport {
    pub name: String,
    pub source_transaction_id: u64,
    pub source_generation: u64,
    pub created_at_generation: u64,
}

impl SnapshotSummaryReport {
    pub fn diagnostic_json(&self) -> String {
        serde_json::json!({
            "name": self.name,
            "source_transaction_id": self.source_transaction_id,
            "source_generation": self.source_generation,
            "created_at_generation": self.created_at_generation,
        })
        .to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRollbackReport {
    pub spec: String,
    pub snapshot: SnapshotSummaryReport,
    pub generation_before: u64,
    pub restored_source_generation: u64,
    pub published_generation: u64,
    pub snapshot_catalog_entries: u64,
    pub production_fsck_required: bool,
}

impl SnapshotRollbackReport {
    pub fn diagnostic_json(&self) -> String {
        serde_json::json!({
            "spec": self.spec,
            "snapshot": {
                "name": self.snapshot.name,
                "source_transaction_id": self.snapshot.source_transaction_id,
                "source_generation": self.snapshot.source_generation,
                "created_at_generation": self.snapshot.created_at_generation,
            },
            "generation_before": self.generation_before,
            "restored_source_generation": self.restored_source_generation,
            "published_generation": self.published_generation,
            "snapshot_catalog_entries": self.snapshot_catalog_entries,
            "production_fsck_required": self.production_fsck_required,
        })
        .to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotCloneSummaryReport {
    pub name: String,
    pub origin: String,
    pub source_transaction_id: u64,
    pub source_generation: u64,
    pub created_at_generation: u64,
}

impl SnapshotCloneSummaryReport {
    pub fn diagnostic_json(&self) -> String {
        serde_json::json!({
            "name": self.name,
            "origin": self.origin,
            "source_transaction_id": self.source_transaction_id,
            "source_generation": self.source_generation,
            "created_at_generation": self.created_at_generation,
        })
        .to_string()
    }
}

fn insert_optional_u64(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<u64>,
) {
    if let Some(value) = value {
        map.insert(key.into(), serde_json::json!(value));
    }
}

fn put_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

fn put_string(buf: &mut Vec<u8>, value: &str) {
    put_u32(buf, value.len() as u32);
    buf.extend_from_slice(value.as_bytes());
}

fn put_option_string(buf: &mut Vec<u8>, value: &Option<String>) {
    put_bool(buf, value.is_some());
    if let Some(value) = value {
        put_string(buf, value);
    }
}

fn put_option_u64(buf: &mut Vec<u8>, value: Option<u64>) {
    put_bool(buf, value.is_some());
    if let Some(value) = value {
        put_u64(buf, value);
    }
}

fn put_vec_u64(buf: &mut Vec<u8>, values: &[u64]) {
    put_u32(buf, values.len() as u32);
    for value in values {
        put_u64(buf, *value);
    }
}

fn put_option_vec_bool(buf: &mut Vec<u8>, values: &Option<Vec<bool>>) {
    put_bool(buf, values.is_some());
    if let Some(values) = values {
        put_u32(buf, values.len() as u32);
        for value in values {
            put_bool(buf, *value);
        }
    }
}

fn take_u8(payload: &[u8], pos: &mut usize) -> Option<u8> {
    let value = *payload.get(*pos)?;
    *pos += 1;
    Some(value)
}

fn take_u16(payload: &[u8], pos: &mut usize) -> Option<u16> {
    let end = *pos + 2;
    let value = u16::from_le_bytes(payload.get(*pos..end)?.try_into().ok()?);
    *pos = end;
    Some(value)
}

fn take_u32(payload: &[u8], pos: &mut usize) -> Option<u32> {
    let end = *pos + 4;
    let value = u32::from_le_bytes(payload.get(*pos..end)?.try_into().ok()?);
    *pos = end;
    Some(value)
}

fn take_u64(payload: &[u8], pos: &mut usize) -> Option<u64> {
    let end = *pos + 8;
    let value = u64::from_le_bytes(payload.get(*pos..end)?.try_into().ok()?);
    *pos = end;
    Some(value)
}

fn take_bool(payload: &[u8], pos: &mut usize) -> Option<bool> {
    Some(take_u8(payload, pos)? != 0)
}

fn take_string(payload: &[u8], pos: &mut usize) -> Option<String> {
    let len = take_u32(payload, pos)? as usize;
    let end = *pos + len;
    let value = String::from_utf8(payload.get(*pos..end)?.to_vec()).ok()?;
    *pos = end;
    Some(value)
}

fn take_option_string(payload: &[u8], pos: &mut usize) -> Option<Option<String>> {
    if take_bool(payload, pos)? {
        Some(Some(take_string(payload, pos)?))
    } else {
        Some(None)
    }
}

fn take_option_u64(payload: &[u8], pos: &mut usize) -> Option<Option<u64>> {
    if take_bool(payload, pos)? {
        Some(Some(take_u64(payload, pos)?))
    } else {
        Some(None)
    }
}

fn take_vec_u64(payload: &[u8], pos: &mut usize) -> Option<Vec<u64>> {
    let len = take_u32(payload, pos)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(take_u64(payload, pos)?);
    }
    Some(values)
}

fn take_option_vec_bool(payload: &[u8], pos: &mut usize) -> Option<Option<Vec<bool>>> {
    if !take_bool(payload, pos)? {
        return Some(None);
    }
    let len = take_u32(payload, pos)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(take_bool(payload, pos)?);
    }
    Some(Some(values))
}

fn put_stats_report(buf: &mut Vec<u8>, report: &StatsReport) {
    put_string(buf, &report.backend);
    put_u64(buf, report.object_count);
    put_u64(buf, report.bytes_written);
    put_option_u64(buf, report.committed_writes);
    put_option_u64(buf, report.degraded_writes);
    put_option_u64(buf, report.refused_writes);
    put_option_u64(buf, report.failed_writes);
    put_option_u64(buf, report.degraded_reads);
    put_option_vec_bool(buf, &report.replica_healthy);
    put_option_u64(buf, report.total_capacity_bytes);
    put_option_u64(buf, report.used_bytes);
    put_option_u64(buf, report.available_bytes);
    put_option_u64(buf, report.placement_receipt_ref_count);
}

fn take_stats_report(payload: &[u8], pos: &mut usize) -> Option<StatsReport> {
    Some(StatsReport {
        backend: take_string(payload, pos)?,
        object_count: take_u64(payload, pos)?,
        bytes_written: take_u64(payload, pos)?,
        committed_writes: take_option_u64(payload, pos)?,
        degraded_writes: take_option_u64(payload, pos)?,
        refused_writes: take_option_u64(payload, pos)?,
        failed_writes: take_option_u64(payload, pos)?,
        degraded_reads: take_option_u64(payload, pos)?,
        replica_healthy: take_option_vec_bool(payload, pos)?,
        total_capacity_bytes: take_option_u64(payload, pos)?,
        used_bytes: take_option_u64(payload, pos)?,
        available_bytes: take_option_u64(payload, pos)?,
        placement_receipt_ref_count: take_option_u64(payload, pos)?,
    })
}

fn put_health_summary(buf: &mut Vec<u8>, summary: &HealthSummary) {
    put_u64(buf, summary.healthy);
    put_u64(buf, summary.suspect);
    put_u64(buf, summary.down);
}

fn take_health_summary(payload: &[u8], pos: &mut usize) -> Option<HealthSummary> {
    Some(HealthSummary {
        healthy: take_u64(payload, pos)?,
        suspect: take_u64(payload, pos)?,
        down: take_u64(payload, pos)?,
    })
}

fn put_roster_state_summary(buf: &mut Vec<u8>, summary: &RosterStateSummary) {
    put_u64(buf, summary.active);
    put_u64(buf, summary.suspected);
    put_u64(buf, summary.failed);
    put_u64(buf, summary.left);
}

fn take_roster_state_summary(payload: &[u8], pos: &mut usize) -> Option<RosterStateSummary> {
    Some(RosterStateSummary {
        active: take_u64(payload, pos)?,
        suspected: take_u64(payload, pos)?,
        failed: take_u64(payload, pos)?,
        left: take_u64(payload, pos)?,
    })
}

fn put_health_report(buf: &mut Vec<u8>, report: &HealthReport) {
    put_u64(buf, report.node_id);
    put_option_string(buf, &report.node_member_class);
    put_option_u64(buf, report.node_failure_domain);
    put_string(buf, &report.carrier);
    put_bool(buf, report.carrier_is_live);
    buf.push(report.replication_factor);
    put_u64(buf, report.placement_version);
    put_u32(buf, report.peers.len() as u32);
    for peer in &report.peers {
        put_u64(buf, peer.member_id);
        put_string(buf, &peer.member_class);
        put_string(buf, &peer.health);
        put_u64(buf, peer.failure_domain);
        put_u32(buf, peer.failed_pings);
        put_bool(buf, peer.joining);
        put_bool(buf, peer.draining);
        put_u64(buf, peer.epoch);
    }
    put_u64(buf, report.peer_count);
    put_vec_u64(buf, &report.alive_voters);
    put_bool(buf, report.quorum_lost);
    put_u64(buf, report.roster_size);
    put_roster_state_summary(buf, &report.roster_state_summary);
    put_health_summary(buf, &report.health_summary);
    put_u32(buf, report.degraded_peers.len() as u32);
    for peer in &report.degraded_peers {
        put_u64(buf, peer.member_id);
        put_string(buf, &peer.health);
        put_u32(buf, peer.failed_pings);
    }
    put_u32(buf, report.failure_domains.len() as u32);
    for domain in &report.failure_domains {
        put_u64(buf, domain.failure_domain);
        put_u64(buf, domain.member_count);
        put_vec_u64(buf, &domain.members);
    }
    put_u32(buf, report.transport_backends.len() as u32);
    for backend in &report.transport_backends {
        put_u64(buf, backend.session_id);
        put_option_u64(buf, backend.peer_node);
        put_string(buf, &backend.backend_kind);
        put_option_string(buf, &backend.disclosure);
    }
}

fn take_health_report(payload: &[u8], pos: &mut usize) -> Option<HealthReport> {
    let node_id = take_u64(payload, pos)?;
    let node_member_class = take_option_string(payload, pos)?;
    let node_failure_domain = take_option_u64(payload, pos)?;
    let carrier = take_string(payload, pos)?;
    let carrier_is_live = take_bool(payload, pos)?;
    let replication_factor = take_u8(payload, pos)?;
    let placement_version = take_u64(payload, pos)?;
    let peer_len = take_u32(payload, pos)? as usize;
    let mut peers = Vec::with_capacity(peer_len);
    for _ in 0..peer_len {
        peers.push(HealthPeerReport {
            member_id: take_u64(payload, pos)?,
            member_class: take_string(payload, pos)?,
            health: take_string(payload, pos)?,
            failure_domain: take_u64(payload, pos)?,
            failed_pings: take_u32(payload, pos)?,
            joining: take_bool(payload, pos)?,
            draining: take_bool(payload, pos)?,
            epoch: take_u64(payload, pos)?,
        });
    }
    let peer_count = take_u64(payload, pos)?;
    let alive_voters = take_vec_u64(payload, pos)?;
    let quorum_lost = take_bool(payload, pos)?;
    let roster_size = take_u64(payload, pos)?;
    let roster_state_summary = take_roster_state_summary(payload, pos)?;
    let health_summary = take_health_summary(payload, pos)?;
    let degraded_len = take_u32(payload, pos)? as usize;
    let mut degraded_peers = Vec::with_capacity(degraded_len);
    for _ in 0..degraded_len {
        degraded_peers.push(DegradedPeerReport {
            member_id: take_u64(payload, pos)?,
            health: take_string(payload, pos)?,
            failed_pings: take_u32(payload, pos)?,
        });
    }
    let domain_len = take_u32(payload, pos)? as usize;
    let mut failure_domains = Vec::with_capacity(domain_len);
    for _ in 0..domain_len {
        failure_domains.push(FailureDomainReport {
            failure_domain: take_u64(payload, pos)?,
            member_count: take_u64(payload, pos)?,
            members: take_vec_u64(payload, pos)?,
        });
    }
    let backend_len = take_u32(payload, pos)? as usize;
    let mut transport_backends = Vec::with_capacity(backend_len);
    for _ in 0..backend_len {
        transport_backends.push(TransportBackendReport {
            session_id: take_u64(payload, pos)?,
            peer_node: take_option_u64(payload, pos)?,
            backend_kind: take_string(payload, pos)?,
            disclosure: take_option_string(payload, pos)?,
        });
    }
    Some(HealthReport {
        node_id,
        node_member_class,
        node_failure_domain,
        carrier,
        carrier_is_live,
        replication_factor,
        placement_version,
        peers,
        peer_count,
        alive_voters,
        quorum_lost,
        roster_size,
        roster_state_summary,
        health_summary,
        degraded_peers,
        failure_domains,
        transport_backends,
    })
}

fn put_receive_import_report(buf: &mut Vec<u8>, report: &ReceiveImportReport) {
    put_string(buf, &report.spec);
    put_u64(buf, report.imported_roots);
    put_u64(buf, report.imported_records);
    put_u64(buf, report.imported_payload_bytes);
    put_u64(buf, report.selected_generation);
    put_u64(buf, report.selected_transaction_id);
    put_u64(buf, report.snapshot_catalog_entries);
    put_u16(buf, report.stream_version);
    put_bool(buf, report.staging_validated_before_publish);
    put_bool(buf, report.destination_root_reauthentication);
    put_bool(buf, report.production_fsck_required);
    put_option_u64(buf, report.placement_epoch);
    put_bool(buf, report.placement_verified_stable);
}

fn take_receive_import_report(payload: &[u8], pos: &mut usize) -> Option<ReceiveImportReport> {
    Some(ReceiveImportReport {
        spec: take_string(payload, pos)?,
        imported_roots: take_u64(payload, pos)?,
        imported_records: take_u64(payload, pos)?,
        imported_payload_bytes: take_u64(payload, pos)?,
        selected_generation: take_u64(payload, pos)?,
        selected_transaction_id: take_u64(payload, pos)?,
        snapshot_catalog_entries: take_u64(payload, pos)?,
        stream_version: take_u16(payload, pos)?,
        staging_validated_before_publish: take_bool(payload, pos)?,
        destination_root_reauthentication: take_bool(payload, pos)?,
        production_fsck_required: take_bool(payload, pos)?,
        placement_epoch: take_option_u64(payload, pos)?,
        placement_verified_stable: take_bool(payload, pos)?,
    })
}

fn put_scrub_report(buf: &mut Vec<u8>, report: &ScrubReport) {
    put_option_string(buf, &report.backend);
    put_u64(buf, report.segments_scanned);
    put_u64(buf, report.records_verified);
    put_u64(buf, report.bytes_scanned);
    put_u64(buf, report.chain_breaks_detected);
    put_bool(buf, report.completed);
    put_u64(buf, report.findings_count);
    put_u64(buf, report.placement_receipt_ref_count);
    put_option_string(buf, &report.error);
}

fn take_scrub_report(payload: &[u8], pos: &mut usize) -> Option<ScrubReport> {
    Some(ScrubReport {
        backend: take_option_string(payload, pos)?,
        segments_scanned: take_u64(payload, pos)?,
        records_verified: take_u64(payload, pos)?,
        bytes_scanned: take_u64(payload, pos)?,
        chain_breaks_detected: take_u64(payload, pos)?,
        completed: take_bool(payload, pos)?,
        findings_count: take_u64(payload, pos)?,
        placement_receipt_ref_count: take_u64(payload, pos)?,
        error: take_option_string(payload, pos)?,
    })
}

fn put_snapshot_summary_report(buf: &mut Vec<u8>, report: &SnapshotSummaryReport) {
    put_string(buf, &report.name);
    put_u64(buf, report.source_transaction_id);
    put_u64(buf, report.source_generation);
    put_u64(buf, report.created_at_generation);
}

fn take_snapshot_summary_report(payload: &[u8], pos: &mut usize) -> Option<SnapshotSummaryReport> {
    Some(SnapshotSummaryReport {
        name: take_string(payload, pos)?,
        source_transaction_id: take_u64(payload, pos)?,
        source_generation: take_u64(payload, pos)?,
        created_at_generation: take_u64(payload, pos)?,
    })
}

fn put_snapshot_rollback_report(buf: &mut Vec<u8>, report: &SnapshotRollbackReport) {
    put_string(buf, &report.spec);
    put_snapshot_summary_report(buf, &report.snapshot);
    put_u64(buf, report.generation_before);
    put_u64(buf, report.restored_source_generation);
    put_u64(buf, report.published_generation);
    put_u64(buf, report.snapshot_catalog_entries);
    put_bool(buf, report.production_fsck_required);
}

fn take_snapshot_rollback_report(
    payload: &[u8],
    pos: &mut usize,
) -> Option<SnapshotRollbackReport> {
    Some(SnapshotRollbackReport {
        spec: take_string(payload, pos)?,
        snapshot: take_snapshot_summary_report(payload, pos)?,
        generation_before: take_u64(payload, pos)?,
        restored_source_generation: take_u64(payload, pos)?,
        published_generation: take_u64(payload, pos)?,
        snapshot_catalog_entries: take_u64(payload, pos)?,
        production_fsck_required: take_bool(payload, pos)?,
    })
}

fn put_snapshot_clone_summary_report(buf: &mut Vec<u8>, report: &SnapshotCloneSummaryReport) {
    put_string(buf, &report.name);
    put_string(buf, &report.origin);
    put_u64(buf, report.source_transaction_id);
    put_u64(buf, report.source_generation);
    put_u64(buf, report.created_at_generation);
}

fn take_snapshot_clone_summary_report(
    payload: &[u8],
    pos: &mut usize,
) -> Option<SnapshotCloneSummaryReport> {
    Some(SnapshotCloneSummaryReport {
        name: take_string(payload, pos)?,
        origin: take_string(payload, pos)?,
        source_transaction_id: take_u64(payload, pos)?,
        source_generation: take_u64(payload, pos)?,
        created_at_generation: take_u64(payload, pos)?,
    })
}

fn encode_placement_receipt_ref(buf: &mut Vec<u8>, receipt: &PlacementReceiptRef) {
    buf.extend_from_slice(&receipt.object_id.to_le_bytes());
    buf.extend_from_slice(&receipt.object_key);
    buf.extend_from_slice(&receipt.receipt_epoch.0.to_le_bytes());
    buf.extend_from_slice(&receipt.receipt_generation.to_le_bytes());
    match receipt.redundancy_policy {
        ReceiptRedundancyPolicy::Replicated { copies } => {
            buf.push(RECEIPT_POLICY_REPLICATED);
            buf.push(copies);
            buf.push(0);
            buf.push(0);
        }
        ReceiptRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } => {
            buf.push(RECEIPT_POLICY_ERASURE);
            buf.push(data_shards);
            buf.push(parity_shards);
            buf.push(0);
        }
    }
    buf.extend_from_slice(&receipt.payload_len.to_le_bytes());
    buf.extend_from_slice(&receipt.payload_digest);
    buf.extend_from_slice(&receipt.target_count.to_le_bytes());
}

fn decode_placement_receipt_ref(payload: &[u8]) -> Option<(PlacementReceiptRef, usize)> {
    if payload.len() < PLACEMENT_RECEIPT_REF_WIRE_LEN {
        return None;
    }
    let object_id = u64::from_le_bytes(payload[0..8].try_into().ok()?);
    let mut object_key = [0u8; 32];
    object_key.copy_from_slice(&payload[8..40]);
    let receipt_epoch = EpochId::new(u64::from_le_bytes(payload[40..48].try_into().ok()?));
    let receipt_generation = u64::from_le_bytes(payload[48..56].try_into().ok()?);
    let redundancy_policy = match payload[56] {
        RECEIPT_POLICY_REPLICATED => {
            if payload[58] != 0 || payload[59] != 0 {
                return None;
            }
            ReceiptRedundancyPolicy::Replicated {
                copies: payload[57],
            }
        }
        RECEIPT_POLICY_ERASURE => {
            if payload[59] != 0 {
                return None;
            }
            ReceiptRedundancyPolicy::Erasure {
                data_shards: payload[57],
                parity_shards: payload[58],
            }
        }
        _ => return None,
    };
    let payload_len = u64::from_le_bytes(payload[60..68].try_into().ok()?);
    let mut payload_digest = [0u8; 32];
    payload_digest.copy_from_slice(&payload[68..100]);
    let target_count = u16::from_le_bytes(payload[100..102].try_into().ok()?);
    Some((
        PlacementReceiptRef::new(
            object_id,
            object_key,
            receipt_epoch,
            receipt_generation,
            redundancy_policy,
            payload_len,
            payload_digest,
            target_count,
        ),
        PLACEMENT_RECEIPT_REF_WIRE_LEN,
    ))
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
    /// Health check response: node identity, pool state, uptime, backend,
    /// and versioned topology report.
    HealthCheckResponse {
        node_identity: String,
        pool_state: String,
        uptime_secs: u64,
        backend: String,
        report: HealthReport,
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
        report: ReceiveImportReport,
    },
    StatsResponse {
        report: StatsReport,
    },
    Error {
        message: String,
    },

    // ── Multi-node scrub and repair fanout ──
    /// Request the server to run a full segment integrity scrub
    /// on its local object store and return a typed report.
    ScrubRequest,
    /// Scrub report.
    ScrubResponse {
        report: ScrubReport,
    },
    /// Repair a named object with placement-receipt-bound authoritative payload.
    RepairObject {
        key: Vec<u8>,
        placement_receipt_ref: PlacementReceiptRef,
        authoritative_payload: Vec<u8>,
    },
    /// Acknowledge a repair operation.
    RepairObjectAck {
        key: Vec<u8>,
        success: bool,
        repaired_placement_receipt_ref: Option<PlacementReceiptRef>,
    },

    /// Put object with placement receipt authority.
    /// The caller carries a PlacementReceiptRef that binds the write
    /// to a specific redundancy policy, epoch, and target set.
    PutWithReceipt {
        key: Vec<u8>,
        placement_receipt_ref: PlacementReceiptRef,
        value: Vec<u8>,
    },
    /// Response to a receipt-authorized put.
    /// Carries the pool-recorded placement receipt so the caller
    /// can validate durable placement authority.
    PutWithReceiptResponse {
        key: Vec<u8>,
        recorded_receipt_ref: Option<PlacementReceiptRef>,
    },

    // ── Snapshot lifecycle operations through the clustered storage-node path ──
    /// Create a named snapshot of the current dataset root.
    /// The storage node opens its configured fs_root LocalFileSystem,
    /// calls create_snapshot, and returns the summary.
    SnapshotCreate {
        snapshot_name: String,
    },
    /// Response to SnapshotCreate: typed summary of the created snapshot.
    SnapshotCreateResponse {
        summary: SnapshotSummaryReport,
    },
    /// Destroy a named snapshot, unpinning its object graph from GC.
    SnapshotDestroy {
        snapshot_name: String,
    },
    /// Response to SnapshotDestroy: typed summary of the destroyed snapshot.
    SnapshotDestroyResponse {
        summary: SnapshotSummaryReport,
    },
    /// Rollback the dataset to a named snapshot state.
    SnapshotRollback {
        snapshot_name: String,
    },
    /// Response to SnapshotRollback: typed report of the rollback operation.
    SnapshotRollbackResponse {
        report: SnapshotRollbackReport,
    },
    /// Create a writable clone from a named snapshot.
    SnapshotClone {
        clone_name: String,
        source_snapshot: String,
    },
    /// Response to SnapshotClone: typed summary of the created clone.
    SnapshotCloneResponse {
        summary: SnapshotCloneSummaryReport,
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
            report,
        } => {
            buf.extend_from_slice(tag::HLTH);
            buf.push(RESPONSE_VERSION);
            put_string(&mut buf, node_identity);
            put_string(&mut buf, pool_state);
            put_u64(&mut buf, *uptime_secs);
            put_string(&mut buf, backend);
            put_health_report(&mut buf, report);
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
        Frame::ReceiveResponse { report } => {
            buf.extend_from_slice(tag::RCV);
            buf.push(1u8);
            buf.push(RESPONSE_VERSION);
            put_receive_import_report(&mut buf, report);
        }
        Frame::ListResponse { keys } => {
            buf.extend_from_slice(tag::LST);
            buf.extend_from_slice(&(keys.len() as u32).to_le_bytes());
            for k in keys {
                buf.extend_from_slice(&(k.len() as u16).to_le_bytes());
                buf.extend_from_slice(k);
            }
        }
        Frame::StatsResponse { report } => {
            buf.extend_from_slice(tag::STA);
            buf.push(RESPONSE_VERSION);
            put_stats_report(&mut buf, report);
        }
        // ── Scrub/repair fanout ──
        Frame::ScrubRequest => {
            buf.extend_from_slice(tag::SCRB);
        }
        Frame::ScrubResponse { report } => {
            buf.extend_from_slice(tag::SCRB);
            buf.push(1u8);
            buf.push(RESPONSE_VERSION);
            put_scrub_report(&mut buf, report);
        }
        Frame::RepairObject {
            key,
            placement_receipt_ref,
            authoritative_payload,
        } => {
            buf.extend_from_slice(tag::RPRR);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            encode_placement_receipt_ref(&mut buf, placement_receipt_ref);
            buf.extend_from_slice(&(authoritative_payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(authoritative_payload);
        }
        Frame::RepairObjectAck {
            key,
            success,
            repaired_placement_receipt_ref,
        } => {
            buf.extend_from_slice(tag::RPRR);
            buf.push(1u8);
            buf.push(u8::from(*success));
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            if let Some(receipt) = repaired_placement_receipt_ref {
                buf.push(1);
                encode_placement_receipt_ref(&mut buf, receipt);
            }
        }
        Frame::PutWithReceipt {
            key,
            placement_receipt_ref,
            value,
        } => {
            buf.extend_from_slice(tag::PUTW);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            encode_placement_receipt_ref(&mut buf, placement_receipt_ref);
            buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
            buf.extend_from_slice(value);
        }
        Frame::PutWithReceiptResponse {
            key,
            recorded_receipt_ref,
        } => {
            buf.extend_from_slice(tag::PUTW);
            buf.push(1u8);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            if let Some(receipt) = recorded_receipt_ref {
                buf.push(1);
                encode_placement_receipt_ref(&mut buf, receipt);
            } else {
                buf.push(0);
            }
        }
        // ── Snapshot lifecycle encode ──
        Frame::SnapshotCreate { snapshot_name } => {
            buf.extend_from_slice(tag::SNPC);
            let name_bytes = snapshot_name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        Frame::SnapshotCreateResponse { summary } => {
            buf.extend_from_slice(tag::SNPC);
            buf.push(1u8);
            buf.push(RESPONSE_VERSION);
            put_snapshot_summary_report(&mut buf, summary);
        }
        Frame::SnapshotDestroy { snapshot_name } => {
            buf.extend_from_slice(tag::SNPD);
            let name_bytes = snapshot_name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        Frame::SnapshotDestroyResponse { summary } => {
            buf.extend_from_slice(tag::SNPD);
            buf.push(1u8);
            buf.push(RESPONSE_VERSION);
            put_snapshot_summary_report(&mut buf, summary);
        }
        Frame::SnapshotRollback { snapshot_name } => {
            buf.extend_from_slice(tag::SNPR);
            let name_bytes = snapshot_name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        Frame::SnapshotRollbackResponse { report } => {
            buf.extend_from_slice(tag::SNPR);
            buf.push(1u8);
            buf.push(RESPONSE_VERSION);
            put_snapshot_rollback_report(&mut buf, report);
        }
        Frame::SnapshotClone {
            clone_name,
            source_snapshot,
        } => {
            buf.extend_from_slice(tag::SNPCL);
            let cn_bytes = clone_name.as_bytes();
            buf.push(cn_bytes.len() as u8);
            buf.extend_from_slice(cn_bytes);
            let ss_bytes = source_snapshot.as_bytes();
            buf.push(ss_bytes.len() as u8);
            buf.extend_from_slice(ss_bytes);
        }
        Frame::SnapshotCloneResponse { summary } => {
            buf.extend_from_slice(tag::SNPCL);
            buf.push(1u8);
            buf.push(RESPONSE_VERSION);
            put_snapshot_clone_summary_report(&mut buf, summary);
        }
        // ── Chunked send/receive encode ──
        Frame::SendChunked { key } => {
            buf.extend_from_slice(tag::SNDC);
            buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
            buf.extend_from_slice(key);
        }
        Frame::SendChunkedResponse {
            chunk,
            cursor,
            more,
        } => {
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
        Frame::SendResumeResponse {
            chunk,
            cursor,
            more,
        } => {
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
            if payload[0] == 1 && payload.len() >= 2 && payload[1] == RESPONSE_VERSION {
                let mut pos = 2;
                Some(Frame::ReceiveResponse {
                    report: take_receive_import_report(payload, &mut pos)?,
                })
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
            } else if payload.len() >= 2 && payload[0] == RESPONSE_VERSION {
                let mut pos = 1;
                Some(Frame::StatsResponse {
                    report: take_stats_report(payload, &mut pos)?,
                })
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
            } else if payload[0] == RESPONSE_VERSION {
                let mut pos = 1;
                let node_identity = take_string(payload, &mut pos)?;
                let pool_state = take_string(payload, &mut pos)?;
                let uptime_secs = take_u64(payload, &mut pos)?;
                let backend = take_string(payload, &mut pos)?;
                let report = take_health_report(payload, &mut pos)?;
                Some(Frame::HealthCheckResponse {
                    node_identity,
                    pool_state,
                    uptime_secs,
                    backend,
                    report,
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
            } else if payload.len() >= 2 && payload[0] == 1 && payload[1] == RESPONSE_VERSION {
                let mut pos = 2;
                Some(Frame::ScrubResponse {
                    report: take_scrub_report(payload, &mut pos)?,
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
                // Response: ok(u8=1) + success(u8) + key_len(u32 LE) + key
                // + optional has_repaired_receipt(u8) + placement_receipt_ref.
                // A request with a one-byte key also starts with 1 because its
                // key_len is u32(1), so only accept the ack shape when the frame
                // length matches an ack shape; otherwise fall through to
                // request decoding.
                let key_len = u32::from_le_bytes(payload[2..6].try_into().ok()?) as usize;
                if payload.len() == 6 + key_len {
                    let success = payload[1] != 0;
                    let key = payload[6..6 + key_len].to_vec();
                    return Some(Frame::RepairObjectAck {
                        key,
                        success,
                        repaired_placement_receipt_ref: None,
                    });
                }
                if payload.len() == 7 + key_len {
                    let success = payload[1] != 0;
                    let key = payload[6..6 + key_len].to_vec();
                    if payload[6 + key_len] == 0 {
                        return Some(Frame::RepairObjectAck {
                            key,
                            success,
                            repaired_placement_receipt_ref: None,
                        });
                    }
                }
                if payload.len() == 7 + key_len + PLACEMENT_RECEIPT_REF_WIRE_LEN
                    && payload[6 + key_len] == 1
                {
                    let success = payload[1] != 0;
                    let key = payload[6..6 + key_len].to_vec();
                    let (receipt, receipt_len) =
                        decode_placement_receipt_ref(&payload[7 + key_len..])?;
                    if receipt_len == PLACEMENT_RECEIPT_REF_WIRE_LEN {
                        return Some(Frame::RepairObjectAck {
                            key,
                            success,
                            repaired_placement_receipt_ref: Some(receipt),
                        });
                    }
                }
            }
            if payload.len() >= 4 {
                // Request: key_len(u32 LE) + key + placement_receipt_ref
                // + payload_len(u32 LE) + authoritative_payload. Receiptless
                // key+payload repair frames no longer decode as repair
                // requests because repair must be placement-receipt-bound.
                let key_len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                if payload.len() < 4 + key_len + PLACEMENT_RECEIPT_REF_WIRE_LEN + 4 {
                    return None;
                }
                let key = payload[4..4 + key_len].to_vec();
                let (placement_receipt_ref, receipt_len) =
                    decode_placement_receipt_ref(&payload[4 + key_len..])?;
                let pl_start = 4 + key_len + receipt_len;
                let pl_len =
                    u32::from_le_bytes(payload[pl_start..pl_start + 4].try_into().ok()?) as usize;
                if payload.len() < pl_start + 4 + pl_len {
                    return None;
                }
                let authoritative_payload = payload[pl_start + 4..pl_start + 4 + pl_len].to_vec();
                Some(Frame::RepairObject {
                    key,
                    placement_receipt_ref,
                    authoritative_payload,
                })
            } else {
                None
            }
        }
        t if t == tag::PUTW => {
            if payload.is_empty() {
                return None;
            }
            if payload[0] == 1 && payload.len() >= 6 {
                // Response: ok(u8=1) + key_len(u32 LE) + key
                // + has_recorded_receipt(u8) + optional placement_receipt_ref.
                // A request with a one-byte key also starts with 1 because its
                // key_len is u32(1), so only accept the response shape when the
                // frame length matches exactly; otherwise fall through to
                // request decoding.
                let key_len = u32::from_le_bytes(payload[1..5].try_into().ok()?) as usize;
                if payload.len() == 6 + key_len && payload[5 + key_len] == 0 {
                    let key = payload[5..5 + key_len].to_vec();
                    return Some(Frame::PutWithReceiptResponse {
                        key,
                        recorded_receipt_ref: None,
                    });
                }
                if payload.len() == 6 + key_len + PLACEMENT_RECEIPT_REF_WIRE_LEN
                    && payload[5 + key_len] == 1
                {
                    let receipt_start = 6 + key_len;
                    let key = payload[5..5 + key_len].to_vec();
                    let (receipt, receipt_len) =
                        decode_placement_receipt_ref(&payload[receipt_start..])?;
                    if receipt_len == PLACEMENT_RECEIPT_REF_WIRE_LEN {
                        return Some(Frame::PutWithReceiptResponse {
                            key,
                            recorded_receipt_ref: Some(receipt),
                        });
                    }
                    return None;
                }
            }
            if payload.len() >= 4 {
                // Request: key_len(u32 LE) + key + placement_receipt_ref
                // + value_len(u32 LE) + value.
                let key_len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                if payload.len() < 4 + key_len + PLACEMENT_RECEIPT_REF_WIRE_LEN + 4 {
                    return None;
                }
                let key = payload[4..4 + key_len].to_vec();
                let (placement_receipt_ref, receipt_len) =
                    decode_placement_receipt_ref(&payload[4 + key_len..])?;
                if receipt_len != PLACEMENT_RECEIPT_REF_WIRE_LEN {
                    return None;
                }
                let val_start = 4 + key_len + receipt_len;
                let val_len =
                    u32::from_le_bytes(payload[val_start..val_start + 4].try_into().ok()?) as usize;
                if payload.len() < val_start + 4 + val_len {
                    return None;
                }
                let value = payload[val_start + 4..val_start + 4 + val_len].to_vec();
                Some(Frame::PutWithReceipt {
                    key,
                    placement_receipt_ref,
                    value,
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
            if payload[0] == 1 && payload.len() >= 2 && payload[1] == RESPONSE_VERSION {
                let mut pos = 2;
                Some(Frame::SnapshotCreateResponse {
                    summary: take_snapshot_summary_report(payload, &mut pos)?,
                })
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
            if payload[0] == 1 && payload.len() >= 2 && payload[1] == RESPONSE_VERSION {
                let mut pos = 2;
                Some(Frame::SnapshotDestroyResponse {
                    summary: take_snapshot_summary_report(payload, &mut pos)?,
                })
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
            if payload[0] == 1 && payload.len() >= 2 && payload[1] == RESPONSE_VERSION {
                let mut pos = 2;
                Some(Frame::SnapshotCloneResponse {
                    summary: take_snapshot_clone_summary_report(payload, &mut pos)?,
                })
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
                let source_snapshot =
                    String::from_utf8(payload[ss_off + 1..ss_off + 1 + ss_len].to_vec()).ok()?;
                Some(Frame::SnapshotClone {
                    clone_name,
                    source_snapshot,
                })
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
                Some(Frame::SendChunkedResponse {
                    chunk,
                    cursor,
                    more,
                })
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
                Some(Frame::SendResumeResponse {
                    chunk,
                    cursor,
                    more,
                })
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
            if payload[0] == 1 && payload.len() >= 2 && payload[1] == RESPONSE_VERSION {
                let mut pos = 2;
                Some(Frame::SnapshotRollbackResponse {
                    report: take_snapshot_rollback_report(payload, &mut pos)?,
                })
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

    fn receipt_ref(key: &[u8], payload: &[u8], generation: u64) -> PlacementReceiptRef {
        let object_key = tidefs_local_object_store::ObjectKey::from_name(key).as_bytes32();
        PlacementReceiptRef::new(
            77,
            object_key,
            EpochId::new(9),
            generation,
            ReceiptRedundancyPolicy::Replicated { copies: 2 },
            payload.len() as u64,
            blake3::hash(payload).into(),
            2,
        )
    }

    fn sample_stats_report() -> StatsReport {
        StatsReport {
            backend: "tcp".into(),
            object_count: 3,
            bytes_written: 4096,
            committed_writes: Some(2),
            degraded_writes: Some(0),
            refused_writes: Some(1),
            failed_writes: None,
            degraded_reads: None,
            replica_healthy: Some(vec![true, false]),
            total_capacity_bytes: None,
            used_bytes: None,
            available_bytes: None,
            placement_receipt_ref_count: None,
        }
    }

    fn sample_health_report() -> HealthReport {
        HealthReport {
            node_id: 7,
            node_member_class: Some("Voter".into()),
            node_failure_domain: Some(3),
            carrier: "tcp".into(),
            carrier_is_live: true,
            replication_factor: 2,
            placement_version: 9,
            peers: vec![HealthPeerReport {
                member_id: 7,
                member_class: "Voter".into(),
                health: "Healthy".into(),
                failure_domain: 3,
                failed_pings: 0,
                joining: false,
                draining: false,
                epoch: 1,
            }],
            peer_count: 1,
            alive_voters: vec![7],
            quorum_lost: false,
            roster_size: 1,
            roster_state_summary: RosterStateSummary {
                active: 1,
                suspected: 0,
                failed: 0,
                left: 0,
            },
            health_summary: HealthSummary {
                healthy: 1,
                suspect: 0,
                down: 0,
            },
            degraded_peers: Vec::new(),
            failure_domains: vec![FailureDomainReport {
                failure_domain: 3,
                member_count: 1,
                members: vec![7],
            }],
            transport_backends: vec![TransportBackendReport {
                session_id: 11,
                peer_node: Some(7),
                backend_kind: "tcp".into(),
                disclosure: Some("tcp:10.0.0.1:9090".into()),
            }],
        }
    }

    fn sample_receive_report() -> ReceiveImportReport {
        ReceiveImportReport {
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
            placement_epoch: Some(12),
            placement_verified_stable: true,
        }
    }

    fn sample_scrub_report(findings_count: u64) -> ScrubReport {
        ScrubReport {
            backend: Some("local".into()),
            segments_scanned: 5,
            records_verified: 42,
            bytes_scanned: 4096,
            chain_breaks_detected: findings_count,
            completed: findings_count == 0,
            findings_count,
            placement_receipt_ref_count: 1,
            error: None,
        }
    }

    fn sample_snapshot_summary(name: &str) -> SnapshotSummaryReport {
        SnapshotSummaryReport {
            name: name.into(),
            source_transaction_id: 100,
            source_generation: 42,
            created_at_generation: 43,
        }
    }

    fn sample_rollback_report() -> SnapshotRollbackReport {
        SnapshotRollbackReport {
            spec: "snapshot-rollback".into(),
            snapshot: sample_snapshot_summary("safe-point"),
            generation_before: 100,
            restored_source_generation: 42,
            published_generation: 101,
            snapshot_catalog_entries: 3,
            production_fsck_required: false,
        }
    }

    fn sample_clone_summary() -> SnapshotCloneSummaryReport {
        SnapshotCloneSummaryReport {
            name: "myclone".into(),
            origin: "origin-snap".into(),
            source_transaction_id: 100,
            source_generation: 42,
            created_at_generation: 43,
        }
    }

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
            report: sample_stats_report(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn response_reports_keep_explicit_diagnostic_json_projection() {
        let stats: serde_json::Value =
            serde_json::from_str(&sample_stats_report().diagnostic_json()).unwrap();
        assert_eq!(stats["object_count"], 3);
        assert_eq!(stats["committed_writes"], 2);

        let receive: serde_json::Value =
            serde_json::from_str(&sample_receive_report().diagnostic_json()).unwrap();
        assert_eq!(receive["spec"], "VFSSEND2");
        assert_eq!(receive["imported_records"], 42);

        let scrub: serde_json::Value =
            serde_json::from_str(&sample_scrub_report(2).diagnostic_json()).unwrap();
        assert_eq!(scrub["findings_count"], 2);
        assert_eq!(scrub["completed"], false);

        let rollback: serde_json::Value =
            serde_json::from_str(&sample_rollback_report().diagnostic_json()).unwrap();
        assert_eq!(rollback["snapshot"]["name"], "safe-point");
        assert_eq!(rollback["published_generation"], 101);
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
            report: sample_receive_report(),
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
            report: sample_health_report(),
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
            report: HealthReport {
                carrier_is_live: false,
                degraded_peers: vec![DegradedPeerReport {
                    member_id: 1,
                    health: "Suspect".into(),
                    failed_pings: 3,
                }],
                health_summary: HealthSummary {
                    healthy: 0,
                    suspect: 1,
                    down: 0,
                },
                ..sample_health_report()
            },
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
            report: sample_scrub_report(0),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_scrub_response_with_findings() {
        let f = Frame::ScrubResponse {
            report: sample_scrub_report(2),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object() {
        let key = b"corrupted-obj".to_vec();
        let payload = b"fixed-data".to_vec();
        let f = Frame::RepairObject {
            placement_receipt_ref: receipt_ref(&key, &payload, 17),
            key,
            authoritative_payload: payload,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object_one_byte_key() {
        let key = b"k".to_vec();
        let payload = b"fixed-data".to_vec();
        let f = Frame::RepairObject {
            placement_receipt_ref: receipt_ref(&key, &payload, 18),
            key,
            authoritative_payload: payload,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn receiptless_repair_without_receipt_does_not_decode() {
        let key = b"receiptless-key";
        let payload = b"fixed-data";
        let mut raw = Vec::new();
        raw.extend_from_slice(tag::RPRR);
        raw.extend_from_slice(&(key.len() as u32).to_le_bytes());
        raw.extend_from_slice(key);
        raw.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        raw.extend_from_slice(payload);
        assert_eq!(decode(&raw), None);
    }

    #[test]
    fn roundtrip_repair_object_ack_success() {
        let f = Frame::RepairObjectAck {
            key: b"fixed-obj".to_vec(),
            success: true,
            repaired_placement_receipt_ref: None,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object_ack_failure() {
        let f = Frame::RepairObjectAck {
            key: b"still-broken".to_vec(),
            success: false,
            repaired_placement_receipt_ref: None,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_repair_object_ack_with_repaired_receipt() {
        let key = b"fixed-obj".to_vec();
        let payload = b"fixed-data";
        let f = Frame::RepairObjectAck {
            repaired_placement_receipt_ref: Some(receipt_ref(&key, payload, 19)),
            key,
            success: true,
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

    // ── PutWithReceipt roundtrip tests ──
    #[test]
    fn roundtrip_put_with_receipt_request() {
        let key = b"object-1".to_vec();
        let payload = b"example-data";
        let receipt = receipt_ref(&key, payload, 7);
        let f = Frame::PutWithReceipt {
            key,
            placement_receipt_ref: receipt,
            value: payload.to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_put_with_receipt_one_byte_key_request() {
        let key = b"k".to_vec();
        let payload = b"example-data";
        let receipt = receipt_ref(&key, payload, 8);
        let f = Frame::PutWithReceipt {
            key,
            placement_receipt_ref: receipt,
            value: payload.to_vec(),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_put_with_receipt_response_with_receipt() {
        let key = b"obj".to_vec();
        let payload = b"data";
        let receipt = receipt_ref(&key, payload, 42);
        let f = Frame::PutWithReceiptResponse {
            key,
            recorded_receipt_ref: Some(receipt),
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_put_with_receipt_response_without_receipt() {
        let key = b"obj".to_vec();
        let f = Frame::PutWithReceiptResponse {
            key,
            recorded_receipt_ref: None,
        };
        assert_eq!(decode(&encode(&f)), Some(f));
    }

    #[test]
    fn roundtrip_put_with_receipt_erasure_policy() {
        let key = b"erasure-obj".to_vec();
        let payload = b"erasure-data";
        let mut obj_key = [0u8; 32];
        let len = key.len().min(32);
        obj_key[..len].copy_from_slice(&key[..len]);
        let receipt = PlacementReceiptRef {
            object_id: 99,
            object_key: obj_key,
            receipt_epoch: tidefs_membership_epoch::EpochId(3),
            receipt_generation: 100,
            redundancy_policy: ReceiptRedundancyPolicy::Erasure {
                data_shards: 4,
                parity_shards: 2,
            },
            payload_len: payload.len() as u64,
            payload_digest: [0xAA; 32],
            target_count: 6,
        };
        let f = Frame::PutWithReceipt {
            key,
            placement_receipt_ref: receipt,
            value: payload.to_vec(),
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
            summary: sample_snapshot_summary("before-upgrade"),
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
            summary: sample_snapshot_summary("old-snap"),
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
            report: sample_rollback_report(),
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
            summary: sample_clone_summary(),
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
