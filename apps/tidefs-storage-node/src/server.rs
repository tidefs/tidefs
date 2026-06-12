//! Storage node server: accept transport connections and serve
//! put/get/delete/list/stats operations backed by a ReplicatedObjectStore,
//! plus send/receive backed by a LocalFileSystem at a configured fs_root.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tidefs_cluster::placement_heal::RelocationFlowCommitPlacementPublication;
use tidefs_cluster::pool_protocol::{
    CatalogEntryRow, ClusterPoolCatalogDeltaResponse, ClusterPoolCatalogQueryResponse,
    ClusterPoolCreateResponse, ClusterPoolImportResponse, ClusterPoolLeaseResponse,
    ClusterPoolMessage,
};
use tidefs_cluster::{
    ClusterLeaseConfig, ClusterLeaseRuntime, FenceAuthority, FenceValidator, PlacementMap,
    RebuildFlowCommitPlacementPublication,
};
use tidefs_cluster::{ClusterPlacementPolicy, ClusterRedundancy};
use tidefs_durability_layout::DurabilityLayoutV1;
use tidefs_local_filesystem::{self as vfs, ChangedRecordExport, RootAuthenticationKey};
use tidefs_local_object_store::device_layout::DeviceMediaClass;
use tidefs_local_object_store::pool::{
    Pool, PoolConfig as ObjectPoolConfig, PoolProperties,
    PoolRedundancyPolicy as ObjectPoolRedundancyPolicy,
};
use tidefs_local_object_store::{
    DeviceBacking, DeviceClass as ObjectDeviceClass, DeviceConfig as ObjectDeviceConfig,
    DeviceIoClass as ObjectIoClass, DeviceKind as ObjectDeviceKind, ObjectKey, StoreOptions,
};
use tidefs_membership_epoch::session_binding::{RosterSessionRegistry, SessionAcceptor};
use tidefs_membership_epoch::EpochId;
use tidefs_membership_epoch::{DomainId, HealthClass, MemberClass, MemberId};
use tidefs_membership_live::connection_acceptance::ConnectionAcceptor;
use tidefs_membership_live::peer_eviction::EvictionAction;
use tidefs_membership_live::peer_join::PeerJoinHandshake;
use tidefs_membership_live::reconnect_handshake::PeerReconnectOutcome;
use tidefs_membership_live::session_binding::SessionBindingTable;
use tidefs_membership_live::{
    recv_membership_msg, send_membership_msg, MembershipConfig, MembershipRuntime,
    MembershipTransport, MembershipView, MembershipWireMessage, SwimAck,
};
use tidefs_membership_types::MemberIdentity;
use tidefs_node_join::{JoinPipeline, JoinPipelinePhase};
use tidefs_partition_runtime::split_brain_guard::SplitBrainGuard;
use tidefs_partition_runtime::types::PartitionFence;
use tidefs_pool_import::create::{PoolCreateConfig, PoolCreator, RedundancyPolicy};
use tidefs_pool_import::{pool_import, ImportedPool};
use tidefs_pool_scan::PoolDeviceBacking;
use tidefs_rebuild_planner::plan::{ReconstructionTask, ReconstructionTaskReceiptError};
use tidefs_rebuild_planner::planner::{
    plan_reconstruction, ReceiptBackedObjectPlacement, ReconstructionInput,
    ReconstructionPlanningError,
};
use tidefs_rebuild_runtime::admission::{LossRecord, RebuildAdmission, ReceiptIngestionError};
use tidefs_rebuild_runtime::scheduler::BackfillScheduler;
use tidefs_rebuild_runtime::task::BackfillTask;
use tidefs_replicated_object_store::{
    ReceiptRepairFlowCommitPublication, ReplicatedObjectStore, ReplicatedStoreConfig,
    TransportReplicatedStore, TransportReplicatedStoreConfig,
};
#[cfg(test)]
use tidefs_replication_model::ReplicatedReadClass;
use tidefs_replication_model::{
    FlowCommitResult, ObjectDigest, PlacementReceiptRef, ReceiptRedundancyPolicy,
    ReplicaMovementClass, ReplicatedReadPlan,
};
use tidefs_transport::connection_registry::ConnectionRegistry;
use tidefs_transport::{
    send_replication_msg, send_segment_fetch_response, PlacementVersionTracker, ReplicationMessage,
    SegmentFetchRequest, SegmentFetchResponse, SessionCloseReason, SyncEntry, Transport,
    TransportError, SEGMENT_FETCH_REQUEST_MAGIC,
};
use tidefs_types_pool_label_core::PoolRedundancyPolicy as LabelPoolRedundancyPolicy;

use crate::authority_spine::RuntimeAuthority;
use crate::protocol::{self, Frame};
use crate::snapshot_barrier::{SnapshotBarrierConfig, SnapshotCoordinator};

/// Magic prefix for cluster pool protocol messages (CP01 = Cluster Pool v1).
const CLUSTER_POOL_MESSAGE_MAGIC: &[u8; 4] = b"CP01";

/// Active store backend, selected by the runtime authority spine.
///
/// When `RuntimeAuthority::is_live()` is true, the storage node uses the
/// transport-backed [`TransportReplicatedStore`]; otherwise it falls back
/// to the local path-backed [`ReplicatedObjectStore`] for single-node or
/// harness use.
enum StoreBackend {
    /// Local path-backed replicated store (single-node/harness path).
    Local(Box<ReplicatedObjectStore>),
    /// Transport-backed replicated store (live multi-node path).
    TransportBacked(Box<TransportReplicatedStore>),
    /// Imported pool-backed byte-addressable media path.
    PoolBacked(Box<Pool>),
}

/// Storage-node summary for publishing a repair flow result into placement state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNodeRepairPlacementPublication {
    /// Repair execution, rebuild-runtime completion, and flow-commit evidence.
    pub repair_flow_publication: ReceiptRepairFlowCommitPublication,
    /// Placement-map state publication derived from the flow-commit result.
    pub placement_publication: RebuildFlowCommitPlacementPublication,
}

/// Storage-node summary for publishing a relocation flow result into placement state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNodeRelocationPlacementPublication {
    /// Caller-named source member retired by the publication.
    pub source_member: u64,
    /// Relocation flow-commit evidence accepted by the cluster placement API.
    pub flow_commit_result: FlowCommitResult,
    /// Placement-map state publication derived from the flow-commit result.
    pub placement_publication: RelocationFlowCommitPlacementPublication,
}

/// Publish storage-node repair flow-commit evidence into a local placement map.
///
/// This composes already-validated repair/flow evidence with local placement
/// state. It does not perform cluster-wide propagation, degraded-read routing,
/// replacement-node orchestration, or reclaim.
pub fn publish_repair_flow_commit_into_placement_map(
    placement_map: &mut PlacementMap,
    publication: &ReceiptRepairFlowCommitPublication,
) -> Result<StorageNodeRepairPlacementPublication, String> {
    validate_repair_flow_commit_publication(publication)?;

    let placement_publication = placement_map
        .publish_rebuild_flow_commit_result(&publication.flow_commit_result)
        .map_err(|err| format!("storage-node placement-map publication failed: {err}"))?;

    Ok(StorageNodeRepairPlacementPublication {
        repair_flow_publication: publication.clone(),
        placement_publication,
    })
}

/// Publish storage-node repair flow-commit evidence through cluster runtime.
///
/// This keeps the same repair/flow evidence checks as placement-map
/// publication, then delegates to the cluster runtime's owned placement state.
/// It does not perform cluster-wide propagation, degraded-read routing,
/// replacement-node orchestration, or reclaim.
pub fn publish_repair_flow_commit_into_cluster_runtime(
    runtime: &mut ClusterLeaseRuntime,
    publication: &ReceiptRepairFlowCommitPublication,
) -> Result<StorageNodeRepairPlacementPublication, String> {
    validate_repair_flow_commit_publication(publication)?;

    let placement_publication = runtime
        .publish_rebuild_flow_commit_result(&publication.flow_commit_result)
        .map_err(|err| format!("storage-node cluster-runtime publication failed: {err}"))?;

    Ok(StorageNodeRepairPlacementPublication {
        repair_flow_publication: publication.clone(),
        placement_publication,
    })
}

/// Publish storage-node relocation flow-commit evidence into a local placement map.
///
/// This composes completed relocation flow evidence with local placement state.
/// It records the replacement receipt and retires only `source_member` through
/// the cluster placement API. It does not perform cluster-wide propagation,
/// degraded-read routing, relocation execution, or reclaim.
pub fn publish_relocation_flow_commit_into_placement_map(
    placement_map: &mut PlacementMap,
    source_member: u64,
    result: &FlowCommitResult,
) -> Result<StorageNodeRelocationPlacementPublication, String> {
    let placement_publication = placement_map
        .publish_relocation_flow_commit_result(source_member, result)
        .map_err(|err| {
            format!("storage-node placement-map relocation publication failed: {err}")
        })?;

    Ok(StorageNodeRelocationPlacementPublication {
        source_member,
        flow_commit_result: result.clone(),
        placement_publication,
    })
}

/// Publish storage-node relocation flow-commit evidence through cluster runtime.
///
/// This delegates to the cluster runtime's owned placement state so the same
/// source-retirement and replacement-receipt checks gate local runtime
/// publication. It does not perform cluster-wide propagation, degraded-read
/// routing, relocation execution, or reclaim.
pub fn publish_relocation_flow_commit_into_cluster_runtime(
    runtime: &mut ClusterLeaseRuntime,
    source_member: u64,
    result: &FlowCommitResult,
) -> Result<StorageNodeRelocationPlacementPublication, String> {
    let placement_publication = runtime
        .publish_relocation_flow_commit_result(source_member, result)
        .map_err(|err| {
            format!("storage-node cluster-runtime relocation publication failed: {err}")
        })?;

    Ok(StorageNodeRelocationPlacementPublication {
        source_member,
        flow_commit_result: result.clone(),
        placement_publication,
    })
}

fn validate_repair_flow_commit_publication(
    publication: &ReceiptRepairFlowCommitPublication,
) -> Result<(), String> {
    let repair = &publication.repair_completion;
    let verified = repair.verified_receipt_completion;
    if repair.repaired_placement_receipt_ref != verified.repaired_placement_receipt_ref {
        return Err(format!(
            "repair evidence repaired placement receipt mismatch for subject {:?}",
            verified.subject_ref
        ));
    }

    let result = &publication.flow_commit_result;
    if result.updated_copy.subject_ref != verified.subject_ref {
        return Err(format!(
            "flow-commit subject {:?} does not match repair completion subject {:?}",
            result.updated_copy.subject_ref, verified.subject_ref
        ));
    }
    if result.updated_copy.member_ref != verified.target_member {
        return Err(format!(
            "flow-commit target {:?} does not match repair completion target {:?}",
            result.updated_copy.member_ref, verified.target_member
        ));
    }
    if let [published_receipt] = result.placement_receipt.placement_receipt_refs.as_slice() {
        if *published_receipt != verified.repaired_placement_receipt_ref {
            return Err(format!(
                "flow-commit repaired placement receipt for subject {:?} does not match repair completion",
                verified.subject_ref
            ));
        }
    }

    Ok(())
}

fn pool_name_key(name: impl AsRef<[u8]>) -> ObjectKey {
    ObjectKey::from_name(name)
}

fn pool_put_named(pool: &mut Pool, name: impl AsRef<[u8]>, payload: &[u8]) -> Result<(), String> {
    pool.put(ObjectIoClass::Data, pool_name_key(name), payload)
        .map(|_| ())
        .map_err(|e| format!("pool put: {e}"))
}

fn pool_put_key(pool: &mut Pool, key: ObjectKey, payload: &[u8]) -> Result<(), String> {
    pool.put(ObjectIoClass::Data, key, payload)
        .map(|_| ())
        .map_err(|e| format!("pool key put: {e}"))
}

fn pool_placement_receipt_ref_for_key(
    pool: &Pool,
    key: ObjectKey,
    object_id: u64,
) -> Result<PlacementReceiptRef, String> {
    let receipt = pool
        .placement_receipt_for_key(ObjectIoClass::Data, key)
        .map_err(|e| format!("pool key placement receipt lookup: {e}"))?
        .ok_or_else(|| {
            "pool key repair succeeded without a durable placement receipt".to_string()
        })?;
    receipt
        .shared_receipt_ref_for_subject(object_id)
        .map_err(|e| format!("pool key placement receipt projection: {e}"))
}

fn pool_get_named(pool: &Pool, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, String> {
    pool.get(ObjectIoClass::Data, pool_name_key(name))
        .map_err(|e| format!("pool get: {e}"))
}

fn pool_get_key(pool: &Pool, key: ObjectKey) -> Result<Option<Vec<u8>>, String> {
    pool.get(ObjectIoClass::Data, key)
        .map_err(|e| format!("pool key get: {e}"))
}

fn pool_delete_named(pool: &mut Pool, name: impl AsRef<[u8]>) -> Result<bool, String> {
    pool.delete(ObjectIoClass::Data, pool_name_key(name))
        .map_err(|e| format!("pool delete: {e}"))
}

fn pool_list_logical_keys(pool: &Pool) -> Result<Vec<ObjectKey>, String> {
    pool.placement_receipt_refs(ObjectIoClass::Data)
        .map(|refs| {
            refs.into_iter()
                .map(|receipt| ObjectKey::from_bytes32(receipt.object_key))
                .collect()
        })
        .map_err(|e| format!("pool receipt inventory: {e}"))
}

fn sync_entries_from_store(store: &StoreBackend) -> Vec<SyncEntry> {
    match store {
        StoreBackend::Local(rs) => rs
            .list_keys_local()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|key| {
                rs.get_key_local(key)
                    .ok()
                    .flatten()
                    .map(|payload| SyncEntry::receiptless(key.as_bytes32(), payload))
            })
            .collect(),
        StoreBackend::TransportBacked(ts) => ts
            .list_keys_local()
            .into_iter()
            .filter_map(|key| {
                ts.get_key_local(key)
                    .ok()
                    .flatten()
                    .map(|payload| SyncEntry::receiptless(key.as_bytes32(), payload))
            })
            .collect(),
        StoreBackend::PoolBacked(pool) => pool
            .placement_receipt_refs(ObjectIoClass::Data)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|receipt| {
                let key = ObjectKey::from_bytes32(receipt.object_key);
                pool_get_key(pool, key)
                    .ok()
                    .flatten()
                    .map(|payload| SyncEntry::with_receipt(key.as_bytes32(), payload, receipt))
            })
            .collect(),
    }
}

fn read_plan_object_name(plan: &ReplicatedReadPlan) -> String {
    format!("obj-{:016x}", plan.subject_ref.0)
}

fn validate_read_plan_response_receipt(
    plan: &ReplicatedReadPlan,
    payload: &[u8],
    receipt: PlacementReceiptRef,
) -> Result<(), String> {
    if receipt.is_synthetic() {
        return Err(format!(
            "read plan for subject {} would return synthetic placement receipt",
            plan.subject_ref.0
        ));
    }
    if !receipt.redundancy_policy.is_well_formed() {
        return Err(format!(
            "read plan for subject {} would return malformed receipt policy",
            plan.subject_ref.0
        ));
    }
    let required_targets = receipt.redundancy_policy.target_width();
    if receipt.target_count < required_targets {
        return Err(format!(
            "read plan for subject {} would return under-width receipt: targets={} required={}",
            plan.subject_ref.0, receipt.target_count, required_targets
        ));
    }
    if receipt.object_id != plan.subject_ref.0 {
        return Err(format!(
            "read plan subject mismatch: plan={} receipt={}",
            plan.subject_ref.0, receipt.object_id
        ));
    }
    if receipt.payload_len != payload.len() as u64 {
        return Err(format!(
            "read plan receipt length mismatch for subject {}: receipt={} actual={}",
            plan.subject_ref.0,
            receipt.payload_len,
            payload.len()
        ));
    }
    let actual_digest: [u8; 32] = blake3::hash(payload).into();
    if receipt.payload_digest != actual_digest {
        return Err(format!(
            "read plan receipt digest mismatch for subject {}",
            plan.subject_ref.0
        ));
    }
    Ok(())
}

fn read_plan_payload_from_store(
    store: &StoreBackend,
    plan: &ReplicatedReadPlan,
) -> Result<Option<(Vec<u8>, Option<PlacementReceiptRef>)>, String> {
    if !plan.read_class.permits_payload_response() {
        return Ok(None);
    }

    let name = read_plan_object_name(plan);
    match store {
        StoreBackend::Local(rs) => rs
            .get_local(&name)
            .map(|payload| payload.map(|payload| (payload, None))),
        StoreBackend::TransportBacked(ts) => ts
            .get_local(&name)
            .map(|payload| payload.map(|payload| (payload, None))),
        StoreBackend::PoolBacked(pool) => {
            let key = pool_name_key(name.as_bytes());
            let Some(payload) = pool_get_key(pool, key)? else {
                return Ok(None);
            };
            let receipt = pool_placement_receipt_ref_for_key(pool, key, plan.subject_ref.0)?;
            validate_read_plan_response_receipt(plan, &payload, receipt)?;
            Ok(Some((payload, Some(receipt))))
        }
    }
}

fn read_plan_response_from_store(
    store: &StoreBackend,
    plan_bytes: &[u8],
    source_member_id: u64,
) -> ReplicationMessage {
    let plan = match bincode::deserialize::<ReplicatedReadPlan>(plan_bytes) {
        Ok(plan) => plan,
        Err(e) => {
            return ReplicationMessage::ReadPlanResponse {
                found: false,
                payload: format!("read plan decode: {e}").into_bytes(),
                source_member_id,
                placement_receipt_ref: None,
            };
        }
    };

    match read_plan_payload_from_store(store, &plan) {
        Ok(Some((payload, placement_receipt_ref))) => ReplicationMessage::ReadPlanResponse {
            found: true,
            payload,
            source_member_id,
            placement_receipt_ref,
        },
        Ok(None) => ReplicationMessage::ReadPlanResponse {
            found: false,
            payload: Vec::new(),
            source_member_id,
            placement_receipt_ref: None,
        },
        Err(e) => ReplicationMessage::ReadPlanResponse {
            found: false,
            payload: e.into_bytes(),
            source_member_id,
            placement_receipt_ref: None,
        },
    }
}

#[cfg(test)]
fn validate_repair_receipt_for_name(
    name: &[u8],
    payload: &[u8],
    placement_receipt_ref: PlacementReceiptRef,
) -> Result<(), String> {
    let expected_key = tidefs_local_object_store::ObjectKey::from_name(name).as_bytes32();
    validate_repair_receipt(expected_key, payload, placement_receipt_ref)
}

fn validate_repair_receipt_for_object_key(
    object_key: ObjectKey,
    payload: &[u8],
    placement_receipt_ref: PlacementReceiptRef,
) -> Result<(), String> {
    validate_repair_receipt(object_key.as_bytes32(), payload, placement_receipt_ref)
}

fn exact_repair_object_key(key: &[u8]) -> Result<ObjectKey, String> {
    let bytes: [u8; 32] = key.try_into().map_err(|_| {
        format!(
            "repair object key must be exactly 32 bytes for exact-key repair, got {}",
            key.len()
        )
    })?;
    Ok(ObjectKey::from_bytes32(bytes))
}

fn validate_repair_receipt(
    expected_key: [u8; 32],
    payload: &[u8],
    placement_receipt_ref: PlacementReceiptRef,
) -> Result<(), String> {
    if placement_receipt_ref.is_synthetic() {
        return Err(format!(
            "repair refused: placement receipt for object {} is synthetic",
            placement_receipt_ref.object_id
        ));
    }
    if !placement_receipt_ref.redundancy_policy.is_well_formed() {
        return Err(format!(
            "repair refused: placement receipt for object {} has malformed redundancy policy",
            placement_receipt_ref.object_id
        ));
    }
    let required_targets = placement_receipt_ref.redundancy_policy.target_width();
    if placement_receipt_ref.target_count < required_targets {
        return Err(format!(
            "repair refused: placement receipt for object {} has {} targets, needs {}",
            placement_receipt_ref.object_id, placement_receipt_ref.target_count, required_targets
        ));
    }
    if placement_receipt_ref.object_key != expected_key {
        return Err(format!(
            "repair refused: placement receipt object key does not match repair key for object {}",
            placement_receipt_ref.object_id
        ));
    }
    if placement_receipt_ref.payload_len != payload.len() as u64 {
        return Err(format!(
            "repair refused: placement receipt payload length {} does not match repair payload length {} for object {}",
            placement_receipt_ref.payload_len,
            payload.len(),
            placement_receipt_ref.object_id
        ));
    }
    let digest: [u8; 32] = blake3::hash(payload).into();
    if placement_receipt_ref.payload_digest != digest {
        return Err(format!(
            "repair refused: placement receipt payload digest does not match repair payload for object {}",
            placement_receipt_ref.object_id
        ));
    }
    Ok(())
}

#[cfg(test)]
fn apply_receipt_bound_name_repair(
    store: &mut StoreBackend,
    name: &[u8],
    payload: &[u8],
    placement_receipt_ref: PlacementReceiptRef,
) -> Result<(), String> {
    validate_repair_receipt_for_name(name, payload, placement_receipt_ref)?;
    match store {
        StoreBackend::Local(rs) => rs.put_local(name, payload),
        StoreBackend::TransportBacked(ts) => ts.put_local(name, payload),
        StoreBackend::PoolBacked(pool) => pool_put_named(pool, name, payload),
    }
}

fn apply_receipt_bound_key_repair(
    store: &mut StoreBackend,
    object_key: ObjectKey,
    payload: &[u8],
    placement_receipt_ref: PlacementReceiptRef,
) -> Result<Option<PlacementReceiptRef>, String> {
    validate_repair_receipt_for_object_key(object_key, payload, placement_receipt_ref)?;
    let repaired_object_id = placement_receipt_ref.object_id;
    match store {
        StoreBackend::Local(rs) => rs.put_key_local(object_key, payload).map(|_| None),
        StoreBackend::TransportBacked(ts) => ts.put_key_local(object_key, payload).map(|_| None),
        StoreBackend::PoolBacked(pool) => {
            pool_put_key(pool, object_key, payload)?;
            pool_placement_receipt_ref_for_key(pool, object_key, repaired_object_id).map(Some)
        }
    }
}

fn classify_peer_scrub_response(report_json: &str, findings_count: u64) -> Result<(), String> {
    if findings_count > 0 {
        return Err(format!("peer scrub reported {findings_count} finding(s)"));
    }

    let report: serde_json::Value = serde_json::from_str(report_json)
        .map_err(|e| format!("peer scrub report JSON is malformed: {e}"))?;

    if let Some(error) = report.get("error") {
        return Err(format!("peer scrub reported error: {error}"));
    }

    match report.get("completed").and_then(serde_json::Value::as_bool) {
        Some(true) => Ok(()),
        Some(false) => Err("peer scrub did not complete".into()),
        None => Err("peer scrub report missing completed=true".into()),
    }
}

fn scrub_response_ack(report_json: &str, findings_count: u64) -> ReplicationMessage {
    let success = match classify_peer_scrub_response(report_json, findings_count) {
        Ok(()) => true,
        Err(reason) => {
            eprintln!("[storage-node] peer scrub response classified failed: {reason}");
            false
        }
    };
    ReplicationMessage::Ack {
        key_hash: "scrub-ack".into(),
        success,
    }
}

fn placement_receipt_inventory_json(store: &StoreBackend) -> serde_json::Value {
    match store {
        StoreBackend::PoolBacked(pool) => match pool.placement_receipt_refs(ObjectIoClass::Data) {
            Ok(refs) => serde_json::json!({
                "available": true,
                "count": refs.len(),
                "refs": refs,
            }),
            Err(e) => serde_json::json!({
                "available": false,
                "count": 0,
                "refs": [],
                "reason": format!("pool placement receipt scan failed: {e}"),
            }),
        },
        StoreBackend::Local(_) | StoreBackend::TransportBacked(_) => {
            serde_json::json!({
                "available": false,
                "count": 0,
                "refs": [],
                "reason": "compatibility object-store backend does not expose pool placement receipts; receipt-bound repair requests must carry PlacementReceiptRef explicitly",
            })
        }
    }
}

fn configured_rebuild_target_members(config: &StorageNodeConfig) -> Vec<MemberId> {
    let local = MemberId::new(config.node_id);
    let mut targets = BTreeSet::new();
    for peer in config
        .replica_peers
        .iter()
        .chain(config.membership_peers.iter())
    {
        let member = MemberId::new(peer.node_id);
        if member != local {
            targets.insert(member);
        }
    }
    targets.into_iter().collect()
}

fn local_failure_domain(config: &StorageNodeConfig) -> DomainId {
    DomainId::new(config.failure_domain.unwrap_or(config.node_id))
}

fn configured_rebuild_target_failure_domains(
    config: &StorageNodeConfig,
) -> BTreeMap<MemberId, DomainId> {
    let local = MemberId::new(config.node_id);
    let mut domains = BTreeMap::new();
    for peer in config
        .replica_peers
        .iter()
        .chain(config.membership_peers.iter())
    {
        let member = MemberId::new(peer.node_id);
        if member != local {
            domains
                .entry(member)
                .or_insert_with(|| DomainId::new(peer.failure_domain));
        }
    }
    domains
}

fn receipt_ingestion_error_json(error: ReceiptIngestionError) -> serde_json::Value {
    match error {
        ReceiptIngestionError::SyntheticReceiptRef { object_id } => serde_json::json!({
            "class": "synthetic-receipt-ref",
            "object_id": object_id,
        }),
        ReceiptIngestionError::MalformedReceiptPolicy { object_id } => serde_json::json!({
            "class": "malformed-receipt-policy",
            "object_id": object_id,
        }),
        ReceiptIngestionError::InsufficientReceiptTargets {
            object_id,
            required,
            actual,
        } => serde_json::json!({
            "class": "insufficient-receipt-targets",
            "object_id": object_id,
            "required": required,
            "actual": actual,
        }),
    }
}

fn placement_receipt_error_json(
    object_id: u64,
    reason: ReconstructionTaskReceiptError,
) -> serde_json::Value {
    match reason {
        ReconstructionTaskReceiptError::SyntheticReceipt => serde_json::json!({
            "class": "synthetic-receipt-ref",
            "object_id": object_id,
        }),
        ReconstructionTaskReceiptError::MalformedRedundancyPolicy => serde_json::json!({
            "class": "malformed-receipt-policy",
            "object_id": object_id,
        }),
        ReconstructionTaskReceiptError::UnderWidthReceipt {
            target_count,
            required_count,
        } => serde_json::json!({
            "class": "insufficient-receipt-targets",
            "object_id": object_id,
            "required": required_count,
            "actual": target_count,
        }),
    }
}

fn reconstruction_planning_error_json(error: ReconstructionPlanningError) -> serde_json::Value {
    match error {
        ReconstructionPlanningError::ReceiptObjectIdMismatch {
            object_id,
            receipt_object_id,
        } => serde_json::json!({
            "class": "receipt-object-id-mismatch",
            "object_id": object_id,
            "receipt_object_id": receipt_object_id,
        }),
        ReconstructionPlanningError::InvalidPlacementReceipt { object_id, reason } => {
            placement_receipt_error_json(object_id, reason)
        }
    }
}

fn durability_layout_from_receipt_policy(
    policy: ReceiptRedundancyPolicy,
) -> Result<DurabilityLayoutV1, String> {
    match policy {
        ReceiptRedundancyPolicy::Replicated { copies } => {
            DurabilityLayoutV1::mirror(copies).map_err(|err| format!("{err:?}"))
        }
        ReceiptRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } => DurabilityLayoutV1::erasure(data_shards, parity_shards)
            .map_err(|err| format!("{err:?}")),
    }
}

fn receipt_backed_rebuild_admission_json(
    config: &StorageNodeConfig,
    store: &StoreBackend,
) -> serde_json::Value {
    let StoreBackend::PoolBacked(pool) = store else {
        return serde_json::json!({
            "available": false,
            "preview": false,
            "receipt_ref_count": 0,
            "scheduled_task_count": 0,
            "reason": "compatibility object-store backend does not expose pool placement receipts; rebuild admission requires Pool::placement_receipt_refs authority",
        });
    };

    let receipt_refs = match pool.placement_receipt_refs(ObjectIoClass::Data) {
        Ok(refs) => refs,
        Err(e) => {
            return serde_json::json!({
                "available": false,
                "preview": true,
                "receipt_ref_count": 0,
                "scheduled_task_count": 0,
                "reason": format!("pool placement receipt scan failed: {e}"),
            });
        }
    };

    receipt_backed_rebuild_admission_from_refs_json(config, receipt_refs)
}

fn receipt_backed_rebuild_admission_from_refs_json(
    config: &StorageNodeConfig,
    receipt_refs: Vec<PlacementReceiptRef>,
) -> serde_json::Value {
    match receipt_backed_rebuild_admission_from_refs(config, receipt_refs) {
        Ok(preview) => preview.to_json(),
        Err(error) => error,
    }
}

fn receipt_backed_rebuild_planner_json(
    config: &StorageNodeConfig,
    store: &StoreBackend,
) -> serde_json::Value {
    let StoreBackend::PoolBacked(pool) = store else {
        return serde_json::json!({
            "available": false,
            "preview": false,
            "receipt_ref_count": 0,
            "task_count": 0,
            "reason": "compatibility object-store backend does not expose pool placement receipts; rebuild planner preview requires Pool::placement_receipt_refs authority",
        });
    };

    let receipt_refs = match pool.placement_receipt_refs(ObjectIoClass::Data) {
        Ok(refs) => refs,
        Err(e) => {
            return serde_json::json!({
                "available": false,
                "preview": true,
                "receipt_ref_count": 0,
                "task_count": 0,
                "reason": format!("pool placement receipt scan failed: {e}"),
            });
        }
    };

    receipt_backed_rebuild_planner_from_refs_json(config, receipt_refs)
}

fn receipt_backed_rebuild_planner_from_refs_json(
    config: &StorageNodeConfig,
    receipt_refs: Vec<PlacementReceiptRef>,
) -> serde_json::Value {
    match receipt_backed_rebuild_planner_from_refs(config, receipt_refs) {
        Ok(preview) => preview.to_json(),
        Err(error) => error,
    }
}

#[derive(Clone, Debug)]
struct ReceiptBackedAdmissionPreview {
    receipt_ref_count: usize,
    detected_epoch: u64,
    healthy_sources: Vec<MemberId>,
    lost_members: Vec<MemberId>,
    admitted_members: Vec<MemberId>,
    refused_members: Vec<serde_json::Value>,
    report_count: usize,
    intent_count: usize,
    tasks: Vec<BackfillTask>,
}

impl ReceiptBackedAdmissionPreview {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "available": true,
            "preview": true,
            "receipt_ref_count": self.receipt_ref_count,
            "detected_epoch": self.detected_epoch,
            "healthy_sources": self.healthy_sources,
            "lost_members": self.lost_members,
            "admitted_members": self.admitted_members,
            "refused_members": self.refused_members,
            "report_count": self.report_count,
            "intent_count": self.intent_count,
            "scheduled_task_count": self.tasks.len(),
            "scheduled_tasks": self.tasks,
        })
    }
}

fn receipt_backed_rebuild_admission_from_refs(
    config: &StorageNodeConfig,
    receipt_refs: Vec<PlacementReceiptRef>,
) -> Result<ReceiptBackedAdmissionPreview, serde_json::Value> {
    let receipt_ref_count = receipt_refs.len();
    let detected_epoch = receipt_refs
        .iter()
        .map(|receipt| receipt.receipt_epoch.0)
        .max()
        .unwrap_or(0);

    let healthy_sources = vec![MemberId::new(config.node_id)];
    let lost_members = configured_rebuild_target_members(config);
    if lost_members.is_empty() {
        return Err(serde_json::json!({
            "available": false,
            "preview": true,
            "receipt_ref_count": receipt_ref_count,
            "scheduled_task_count": 0,
            "detected_epoch": detected_epoch,
            "healthy_sources": healthy_sources,
            "lost_members": [],
            "reason": "pool placement receipts are present but no remote membership or replica peer is configured as a rebuild target",
        }));
    }

    let loss = LossRecord::from_placement_receipt_refs(
        lost_members.clone(),
        healthy_sources.clone(),
        receipt_refs,
        ReplicaMovementClass::RebuildLostOrSuspectCopy,
        detected_epoch,
        0,
    )
    .map_err(|error| {
        serde_json::json!({
            "available": false,
            "preview": true,
            "receipt_ref_count": receipt_ref_count,
            "scheduled_task_count": 0,
            "detected_epoch": detected_epoch,
            "healthy_sources": healthy_sources,
            "lost_members": lost_members,
            "receipt_ingestion_error": receipt_ingestion_error_json(error),
        })
    })?;

    let mut admission = RebuildAdmission::with_epoch(detected_epoch);
    let mut scheduler = BackfillScheduler::new();
    let outcome = admission.admit(&loss, &mut scheduler);
    let tasks = scheduler.drain_eligible();
    let refused_members = outcome
        .refused
        .into_iter()
        .map(|(member, reason)| {
            serde_json::json!({
                "member": member,
                "reason": format!("{reason:?}"),
            })
        })
        .collect();

    Ok(ReceiptBackedAdmissionPreview {
        receipt_ref_count,
        detected_epoch,
        healthy_sources,
        lost_members,
        admitted_members: outcome.admitted,
        refused_members,
        report_count: outcome.report_count,
        intent_count: outcome.intent_count,
        tasks,
    })
}

#[derive(Clone, Debug)]
struct ReceiptBackedPlannerPreview {
    receipt_ref_count: usize,
    detected_epoch: u64,
    local_member: MemberId,
    target_members: Vec<MemberId>,
    plan_id: u64,
    total_target_replicas: usize,
    tasks: Vec<ReconstructionTask>,
    reason: Option<&'static str>,
}

impl ReceiptBackedPlannerPreview {
    fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "available": true,
            "preview": true,
            "boundary": "storage-node-scrub-rebuild-planner-preview",
            "receipt_ref_count": self.receipt_ref_count,
            "detected_epoch": self.detected_epoch,
            "healthy_sources": [self.local_member],
            "candidate_targets": self.target_members,
            "failed_nodes": [],
            "plan_id": self.plan_id,
            "task_count": self.tasks.len(),
            "total_target_replicas": self.total_target_replicas,
            "tasks": self.tasks
                .iter()
                .map(reconstruction_task_json)
                .collect::<Vec<_>>(),
        });
        if let Some(reason) = self.reason {
            json["reason"] = serde_json::json!(reason);
        }
        json
    }
}

fn receipt_backed_rebuild_planner_from_refs(
    config: &StorageNodeConfig,
    receipt_refs: Vec<PlacementReceiptRef>,
) -> Result<ReceiptBackedPlannerPreview, serde_json::Value> {
    let receipt_ref_count = receipt_refs.len();
    let detected_epoch = receipt_refs
        .iter()
        .map(|receipt| receipt.receipt_epoch.0)
        .max()
        .unwrap_or(0);
    let local_member = MemberId::new(config.node_id);
    let target_members = configured_rebuild_target_members(config);
    if target_members.is_empty() {
        return Err(serde_json::json!({
            "available": false,
            "preview": true,
            "receipt_ref_count": receipt_ref_count,
            "task_count": 0,
            "detected_epoch": detected_epoch,
            "healthy_sources": [local_member],
            "candidate_targets": [],
            "reason": "pool placement receipts are present but no remote membership or replica peer is configured as a rebuild target",
        }));
    }

    if receipt_refs.is_empty() {
        return Ok(ReceiptBackedPlannerPreview {
            receipt_ref_count: 0,
            detected_epoch,
            local_member,
            target_members,
            plan_id: detected_epoch,
            total_target_replicas: 0,
            tasks: Vec::new(),
            reason: Some("pool placement receipt inventory is empty"),
        });
    }

    let policy = receipt_refs[0].redundancy_policy;
    let mut placement_members = BTreeSet::new();
    placement_members.insert(local_member);
    let mut object_placement = BTreeMap::new();
    for receipt in receipt_refs {
        if receipt.redundancy_policy != policy {
            return Err(serde_json::json!({
                "available": false,
                "preview": true,
                "receipt_ref_count": receipt_ref_count,
                "task_count": 0,
                "detected_epoch": detected_epoch,
                "planner_error": {
                    "class": "mixed-receipt-redundancy-policy",
                    "object_id": receipt.object_id,
                    "expected": policy,
                    "actual": receipt.redundancy_policy,
                },
            }));
        }
        let placement = match ReceiptBackedObjectPlacement::new(receipt, placement_members.clone())
        {
            Ok(placement) => placement,
            Err(reason) => {
                return Err(serde_json::json!({
                    "available": false,
                    "preview": true,
                    "receipt_ref_count": receipt_ref_count,
                    "task_count": 0,
                    "detected_epoch": detected_epoch,
                    "planner_error": placement_receipt_error_json(receipt.object_id, reason),
                }));
            }
        };
        if object_placement
            .insert(receipt.object_id, placement)
            .is_some()
        {
            return Err(serde_json::json!({
                "available": false,
                "preview": true,
                "receipt_ref_count": receipt_ref_count,
                "task_count": 0,
                "detected_epoch": detected_epoch,
                "planner_error": {
                    "class": "duplicate-placement-receipt-object",
                    "object_id": receipt.object_id,
                },
            }));
        }
    }

    let layout = match durability_layout_from_receipt_policy(policy) {
        Ok(layout) => layout,
        Err(reason) => {
            return Err(serde_json::json!({
                "available": false,
                "preview": true,
                "receipt_ref_count": receipt_ref_count,
                "task_count": 0,
                "detected_epoch": detected_epoch,
                "layout_error": {
                    "class": "invalid-receipt-redundancy-policy",
                    "reason": reason,
                },
            }));
        }
    };

    let mut member_health = BTreeMap::new();
    member_health.insert(local_member, HealthClass::Healthy);
    for member in &target_members {
        member_health.insert(*member, HealthClass::Healthy);
    }

    let mut failure_domains = configured_rebuild_target_failure_domains(config);
    failure_domains.insert(local_member, local_failure_domain(config));
    let input = ReconstructionInput {
        layout,
        member_health,
        failed_nodes: BTreeSet::new(),
        failed_device_count: 0,
        object_placement,
        in_flight_objects: BTreeSet::new(),
        failure_domains,
        plan_id: detected_epoch,
        now_ns: 0,
    };

    let plan = match plan_reconstruction(&input) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(serde_json::json!({
                "available": false,
                "preview": true,
                "receipt_ref_count": receipt_ref_count,
                "task_count": 0,
                "detected_epoch": detected_epoch,
                "planner_error": reconstruction_planning_error_json(error),
            }));
        }
    };

    let task_count = plan.task_count();
    let total_target_replicas = plan.total_target_replicas();

    Ok(ReceiptBackedPlannerPreview {
        receipt_ref_count,
        detected_epoch,
        local_member,
        target_members,
        plan_id: plan.plan_id,
        total_target_replicas,
        tasks: plan.tasks,
        reason: (task_count == 0).then_some("reconstruction planner produced no work"),
    })
}

fn reconstruction_task_json(task: &ReconstructionTask) -> serde_json::Value {
    serde_json::json!({
        "object_id": task.object_id(),
        "placement_receipt_ref": task.placement_receipt_ref,
        "source_nodes": &task.source_nodes,
        "target_nodes": &task.target_nodes,
        "data_range": task.data_range,
        "priority": task.priority,
    })
}

fn receipt_digest_to_object_digest(payload_digest: [u8; 32]) -> ObjectDigest {
    ObjectDigest::new(u64::from_le_bytes(
        payload_digest[..8]
            .try_into()
            .expect("digest prefix has 8 bytes"),
    ))
}

fn receipt_backed_rebuild_execution_candidates_json(
    config: &StorageNodeConfig,
    store: &StoreBackend,
) -> serde_json::Value {
    let StoreBackend::PoolBacked(pool) = store else {
        return serde_json::json!({
            "available": false,
            "preview": false,
            "receipt_ref_count": 0,
            "execution_candidate_count": 0,
            "reason": "compatibility object-store backend does not expose pool placement receipts; rebuild execution candidates require admission and planner receipt authority",
        });
    };

    let receipt_refs = match pool.placement_receipt_refs(ObjectIoClass::Data) {
        Ok(refs) => refs,
        Err(e) => {
            return serde_json::json!({
                "available": false,
                "preview": true,
                "receipt_ref_count": 0,
                "execution_candidate_count": 0,
                "reason": format!("pool placement receipt scan failed: {e}"),
            });
        }
    };

    receipt_backed_rebuild_execution_candidates_from_refs_json(config, receipt_refs)
}

fn receipt_backed_rebuild_execution_candidates_from_refs_json(
    config: &StorageNodeConfig,
    receipt_refs: Vec<PlacementReceiptRef>,
) -> serde_json::Value {
    let receipt_ref_count = receipt_refs.len();
    let detected_epoch = receipt_refs
        .iter()
        .map(|receipt| receipt.receipt_epoch.0)
        .max()
        .unwrap_or(0);

    if receipt_refs.is_empty() {
        return serde_json::json!({
            "available": true,
            "preview": true,
            "boundary": "storage-node-scrub-rebuild-execution-candidate-preview",
            "receipt_ref_count": 0,
            "detected_epoch": detected_epoch,
            "admission_task_count": 0,
            "planner_task_count": 0,
            "execution_candidate_count": 0,
            "candidates": [],
            "reason": "pool placement receipt inventory is empty",
        });
    }

    let admission = match receipt_backed_rebuild_admission_from_refs(config, receipt_refs.clone()) {
        Ok(admission) => admission,
        Err(error) => {
            return serde_json::json!({
                "available": false,
                "preview": true,
                "boundary": "storage-node-scrub-rebuild-execution-candidate-preview",
                "receipt_ref_count": receipt_ref_count,
                "detected_epoch": detected_epoch,
                "execution_candidate_count": 0,
                "reason": "rebuild admission preview is unavailable",
                "admission": error,
            });
        }
    };

    let planner = match receipt_backed_rebuild_planner_from_refs(config, receipt_refs) {
        Ok(planner) => planner,
        Err(error) => {
            return serde_json::json!({
                "available": false,
                "preview": true,
                "boundary": "storage-node-scrub-rebuild-execution-candidate-preview",
                "receipt_ref_count": receipt_ref_count,
                "detected_epoch": detected_epoch,
                "admission_task_count": admission.tasks.len(),
                "execution_candidate_count": 0,
                "reason": "rebuild planner preview is unavailable",
                "planner": error,
            });
        }
    };

    match cross_check_rebuild_execution_candidates(&admission, &planner) {
        Ok(candidates) => serde_json::json!({
            "available": true,
            "preview": true,
            "boundary": "storage-node-scrub-rebuild-execution-candidate-preview",
            "receipt_ref_count": receipt_ref_count,
            "detected_epoch": detected_epoch,
            "admission_task_count": admission.tasks.len(),
            "planner_task_count": planner.tasks.len(),
            "execution_candidate_count": candidates.len(),
            "candidates": candidates,
        }),
        Err(error) => serde_json::json!({
            "available": false,
            "preview": true,
            "boundary": "storage-node-scrub-rebuild-execution-candidate-preview",
            "receipt_ref_count": receipt_ref_count,
            "detected_epoch": detected_epoch,
            "admission_task_count": admission.tasks.len(),
            "planner_task_count": planner.tasks.len(),
            "execution_candidate_count": 0,
            "execution_candidate_error": error,
        }),
    }
}

fn cross_check_rebuild_execution_candidates(
    admission: &ReceiptBackedAdmissionPreview,
    planner: &ReceiptBackedPlannerPreview,
) -> Result<Vec<serde_json::Value>, serde_json::Value> {
    let admission_pairs = admission
        .tasks
        .iter()
        .map(|task| (task.placement_receipt_ref, task.target_member))
        .collect::<BTreeSet<_>>();
    let planner_pairs = planner
        .tasks
        .iter()
        .flat_map(|task| {
            task.target_nodes
                .iter()
                .map(move |target| (task.placement_receipt_ref, MemberId::new(*target)))
        })
        .collect::<BTreeSet<_>>();

    if admission_pairs != planner_pairs {
        let missing_in_planner = admission_pairs
            .difference(&planner_pairs)
            .map(|(receipt, target)| {
                serde_json::json!({
                    "placement_receipt_ref": receipt,
                    "target_member": target,
                })
            })
            .collect::<Vec<_>>();
        let extra_planner_targets = planner_pairs
            .difference(&admission_pairs)
            .map(|(receipt, target)| {
                serde_json::json!({
                    "placement_receipt_ref": receipt,
                    "target_member": target,
                })
            })
            .collect::<Vec<_>>();

        return Err(serde_json::json!({
            "class": "planner-admission-target-mismatch",
            "missing_in_planner": missing_in_planner,
            "extra_planner_targets": extra_planner_targets,
        }));
    }

    admission
        .tasks
        .iter()
        .map(|admission_task| {
            let planner_task = planner
                .tasks
                .iter()
                .find(|task| {
                    task.placement_receipt_ref == admission_task.placement_receipt_ref
                        && task.source_nodes.contains(&admission_task.source_member.0)
                        && task.target_nodes.contains(&admission_task.target_member.0)
                })
                .ok_or_else(|| {
                    serde_json::json!({
                        "class": "planner-admission-source-mismatch",
                        "placement_receipt_ref": admission_task.placement_receipt_ref,
                        "source_member": admission_task.source_member,
                        "target_member": admission_task.target_member,
                    })
                })?;

            let receipt = planner_task.placement_receipt_ref;
            let receipt_digest = receipt_digest_to_object_digest(receipt.payload_digest);
            if admission_task.payload_len != receipt.payload_len {
                return Err(serde_json::json!({
                    "class": "admission-payload-length-mismatch",
                    "placement_receipt_ref": receipt,
                    "admission_payload_len": admission_task.payload_len,
                    "receipt_payload_len": receipt.payload_len,
                }));
            }
            if admission_task.payload_digest != receipt_digest {
                return Err(serde_json::json!({
                    "class": "admission-payload-digest-mismatch",
                    "placement_receipt_ref": receipt,
                    "admission_payload_digest": admission_task.payload_digest,
                    "receipt_payload_digest": receipt.payload_digest,
                }));
            }

            Ok(serde_json::json!({
                "placement_receipt_ref": receipt,
                "source_member": admission_task.source_member,
                "target_member": admission_task.target_member,
                "movement_class": admission_task.movement_class,
                "payload_len": admission_task.payload_len,
                "payload_digest": admission_task.payload_digest,
                "planner_priority": planner_task.priority,
                "data_range": planner_task.data_range,
            }))
        })
        .collect()
}

fn local_scrub_report_json(config: &StorageNodeConfig, store: &StoreBackend) -> (String, u64) {
    let placement_receipt_refs = placement_receipt_inventory_json(store);
    let placement_receipt_ref_count = placement_receipt_refs["count"].as_u64().unwrap_or(0);
    let rebuild_admission = receipt_backed_rebuild_admission_json(config, store);
    let rebuild_planner = receipt_backed_rebuild_planner_json(config, store);
    let rebuild_execution_candidates =
        receipt_backed_rebuild_execution_candidates_json(config, store);
    if matches!(store, StoreBackend::PoolBacked(_)) {
        let json = serde_json::json!({
            "backend": "pool",
            "segments_scanned": 0,
            "records_verified": 0,
            "bytes_scanned": 0,
            "chain_breaks_detected": 0,
            "completed": true,
            "findings_count": 0,
            "placement_receipt_ref_count": placement_receipt_ref_count,
            "placement_receipt_refs": placement_receipt_refs,
            "rebuild_admission": rebuild_admission,
            "rebuild_planner": rebuild_planner,
            "rebuild_execution_candidates": rebuild_execution_candidates,
        });
        return (json.to_string(), 0);
    }

    let store_dir = &config.store_paths[0];
    let segments_dir = store_dir.join(tidefs_local_object_store::STORE_DIR_NAME);
    let scrubber = tidefs_local_object_store::SegmentIntegrityScrubber::new(&segments_dir);
    let mut suspect_log = tidefs_local_object_store::SuspectLog::new();
    match scrubber.scrub_full(&mut suspect_log) {
        Ok(report) => {
            let findings = report.outcomes.len() as u64;
            let json = serde_json::json!({
                "segments_scanned": report.segments_scanned,
                "records_verified": report.records_verified,
                "bytes_scanned": report.bytes_scanned,
                "chain_breaks_detected": report.chain_breaks_detected,
                "completed": report.completed,
                "findings_count": findings,
                "placement_receipt_ref_count": placement_receipt_ref_count,
                "placement_receipt_refs": placement_receipt_refs,
                "rebuild_admission": rebuild_admission,
                "rebuild_planner": rebuild_planner,
                "rebuild_execution_candidates": rebuild_execution_candidates,
            });
            (json.to_string(), findings)
        }
        Err(e) => {
            let json = serde_json::json!({
                "error": format!("{e}"),
                "placement_receipt_ref_count": placement_receipt_ref_count,
                "placement_receipt_refs": placement_receipt_refs,
                "rebuild_admission": rebuild_admission,
                "rebuild_planner": rebuild_planner,
                "rebuild_execution_candidates": rebuild_execution_candidates,
            });
            (json.to_string(), 0)
        }
    }
}

fn build_segment_fetch_response(
    store: &StoreBackend,
    request: &SegmentFetchRequest,
) -> Result<SegmentFetchResponse, String> {
    let receipt_ref = request.non_synthetic_receipt_ref();
    let obj_id = receipt_ref.map_or(request.object_id, |receipt| receipt.object_id);
    let receipt_key = receipt_ref.map(|receipt| ObjectKey::from_bytes32(receipt.object_key));

    let full_payload = match (store, receipt_key) {
        (StoreBackend::Local(rs), Some(object_key)) => require_receipt_key_payload(
            "local",
            obj_id,
            object_key,
            rs.get_key_local(object_key)
                .map_err(|e| format!("local receipt-key get for object {obj_id}: {e}"))?,
        )?,
        (StoreBackend::TransportBacked(ts), Some(object_key)) => require_receipt_key_payload(
            "transport",
            obj_id,
            object_key,
            ts.get_key_local(object_key)
                .map_err(|e| format!("transport receipt-key get for object {obj_id}: {e}"))?,
        )?,
        (StoreBackend::PoolBacked(pool), Some(object_key)) => require_receipt_key_payload(
            "pool",
            obj_id,
            object_key,
            pool_get_key(pool, object_key)
                .map_err(|e| format!("pool receipt-key get for object {obj_id}: {e}"))?,
        )?,
        (StoreBackend::Local(rs), None) => rs
            .get_local(request.object_id.to_le_bytes())
            .map_err(|e| format!("primary get for object {}: {e}", request.object_id))?
            .unwrap_or_default(),
        (StoreBackend::TransportBacked(ts), None) => ts
            .get_local(request.object_id.to_le_bytes())
            .map_err(|e| format!("primary get for object {}: {e}", request.object_id))?
            .unwrap_or_default(),
        (StoreBackend::PoolBacked(pool), None) => {
            pool_get_named(pool, request.object_id.to_le_bytes())
                .map_err(|e| format!("pool get for object {}: {e}", request.object_id))?
                .unwrap_or_default()
        }
    };

    let start = request.segment_offset as usize;
    let end = start.saturating_add(request.segment_length as usize);
    let segment_payload = if start < full_payload.len() {
        let slice_end = end.min(full_payload.len());
        full_payload[start..slice_end].to_vec()
    } else {
        Vec::new()
    };

    let actual_length = segment_payload.len() as u64;
    Ok(SegmentFetchResponse::new(
        obj_id,
        request.segment_offset,
        actual_length,
        segment_payload,
    ))
}

fn require_receipt_key_payload(
    backend: &str,
    object_id: u64,
    object_key: ObjectKey,
    payload: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    payload.ok_or_else(|| {
        format!(
            "{backend} receipt-key get for object {object_id}: exact placement receipt key {} not found",
            object_key_hex(object_key),
        )
    })
}

fn object_key_hex(object_key: ObjectKey) -> String {
    let mut out = String::with_capacity(64);
    for byte in object_key.as_bytes32() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Configuration for a storage node server.
#[derive(Clone)]
pub struct StorageNodeConfig {
    /// Address to bind the TCP listener on.
    pub bind_addr: SocketAddr,
    /// Local node ID for the transport layer.
    pub node_id: u64,
    /// Paths for the replicated object store.
    pub store_paths: Vec<PathBuf>,
    /// Pool device paths for pool import at startup.
    /// When set, the daemon imports these byte-addressable pool members
    /// before opening the store and uses them as the live backend.
    pub pool_device_paths: Vec<PathBuf>,
    /// Directory for pool import lock files. Defaults to /dev/tidefs/import.
    pub pool_lock_dir: Option<PathBuf>,
    /// Human-readable node identity string (e.g. "node-7.rack-3").
    pub node_identity: Option<String>,
    /// Runtime authority spine disclosing the active transport backend.
    /// When set, membership, transport, and replication subsystems
    /// consume this rather than raw CLI flags.
    pub authority: Option<RuntimeAuthority>,
    /// Filesystem root for send/receive operations.
    /// When set, the server can export and import changed-record streams.
    pub fs_root: Option<PathBuf>,
    /// Root authentication key for opening the filesystem (send path).
    pub root_auth_key: Option<RootAuthenticationKey>,
    /// Member class for this node: Voter, Learner, DataOnly, etc.
    /// Defaults to Voter if not set.
    pub member_class: Option<MemberClass>,
    /// Failure domain identifier for this node (e.g. rack id).
    /// Defaults to the node_id when not set.
    pub failure_domain: Option<u64>,
    /// Optional bind address for the membership control transport.
    pub membership_bind_addr: Option<SocketAddr>,
    /// Membership peers to register and dial during startup.
    pub membership_peers: Vec<MembershipPeerConfig>,
    /// Storage replica data endpoints to connect during startup.
    pub replica_peers: Vec<MembershipPeerConfig>,
    /// Use RDMA transport backend when available, falling back to TCP.
    /// When false (default), uses TCP transport.
    pub rdma: bool,
    /// Carrier policy for fail-closed RDMA enforcement (#6672).
    /// "prefer" (default) allows silent fallback to TCP; "enforce" fails
    /// closed when an RDMA claim cannot be satisfied.
    pub carrier_policy: Option<String>,
    /// Optional path to a ready-marker file created after startup completes.
    pub ready_file: Option<std::path::PathBuf>,
    /// Drain timeout in seconds for graceful node-drain on shutdown.
    pub drain_timeout_secs: u64,

    /// Optional directory for membership checkpoint persistence.
    /// When set, the runtime loads the latest epoch checkpoint on startup
    /// and creates new checkpoints after each epoch advancement,
    /// enabling cold-start cluster recovery without manual repair.
    pub membership_checkpoint_dir: Option<PathBuf>,

    /// Optional cluster lease configuration. When set, the node acquires
    /// and renews a membership lease for clustered pool import, and the
    /// write fence validator is activated for transport dispatch gating.
    pub cluster_lease_config: Option<ClusterLeaseConfig>,
}

/// Bootstrap configuration for one membership peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipPeerConfig {
    pub node_id: u64,
    pub addr: SocketAddr,
    pub member_class: MemberClass,
    pub failure_domain: u64,
}

/// Cloned/shared state passed to each session handler thread.
#[allow(dead_code)]
struct SessionContext {
    transport: Arc<Mutex<Transport>>,
    store: Arc<Mutex<StoreBackend>>,
    membership: Arc<Mutex<MembershipRuntime>>,
    membership_transport: Option<Arc<Mutex<MembershipTransport>>>,
    authority: Option<RuntimeAuthority>,
    config: StorageNodeConfig,
    imported_pool: Option<ImportedPool>,
    start_time: Instant,
    /// Pending evictions queued by the eviction callback for processing.
    pending_evictions: Arc<Mutex<Vec<(SocketAddr, EvictionAction)>>>,
    /// Roster-to-session registry shared between PeerJoinHandshake and ConnectionAcceptor.
    roster_session_registry: Arc<std::sync::RwLock<RosterSessionRegistry>>,
    /// Session acceptor wrapping the roster registry for roster-verified bindings.
    session_acceptor: Arc<std::sync::RwLock<SessionAcceptor>>,
    /// First-time peer-join handshake for unknown peers.
    peer_join_handshake: Arc<PeerJoinHandshake>,
    /// Known-peer reconnect acceptor: delivers ReconnectStatePushMessage on reconnect.
    connection_acceptor: Arc<ConnectionAcceptor>,
    /// Placement version tracker for consistent rebalance across nodes.
    placement_version_tracker: Arc<PlacementVersionTracker>,
    active_barrier: Arc<Mutex<Option<SnapshotCoordinator>>>,
    /// Write-fence validator from the cluster lease runtime.
    /// When set, transport-layer write dispatch must validate the write
    /// fence token against this validator before committing writes.
    fence_validator: Option<FenceValidator>,
    /// Cluster lease runtime for granting pool lease tokens to clients.
    /// When None (not yet wired), lease requests are refused with a
    /// "not configured" error.
    lease_runtime: Option<std::sync::Arc<std::sync::Mutex<ClusterLeaseRuntime>>>,
    /// Split-brain guard for partition-based fencing of write operations.
    /// When set and the node is on the minority side of a partition,
    /// write-gating operations (import, catalog mutations, lease grants)
    /// are refused with a typed MinorityFenced error before they hit storage.
    split_brain_guard: Option<Arc<Mutex<SplitBrainGuard>>>,
}
/// Bridges an Arc<ConnectionAcceptor> into a Box<dyn EpochCommitSubscriber>
/// for registration with the EpochAdvanceCoordinator.
///
/// ConnectionAcceptor already implements the local epoch_coordinator::EpochCommitSubscriber,
/// but it's held behind Arc for shared ownership. This thin wrapper delegates
/// on_epoch_committed to the inner acceptor.
struct AcceptorCoordinatorBridge {
    acceptor: Arc<ConnectionAcceptor>,
}

impl tidefs_membership_live::epoch_coordinator::EpochCommitSubscriber
    for AcceptorCoordinatorBridge
{
    fn on_epoch_committed(&self, view: &tidefs_membership_live::epoch_coordinator::EpochView) {
        tidefs_membership_live::epoch_coordinator::EpochCommitSubscriber::on_epoch_committed(
            self.acceptor.as_ref(),
            view,
        );
    }
}

/// A running storage node server.
pub struct StorageNode {
    transport: Arc<Mutex<Transport>>,
    store: Arc<Mutex<StoreBackend>>,
    membership: Arc<Mutex<MembershipRuntime>>,
    membership_transport: Option<Arc<Mutex<MembershipTransport>>>,
    _membership_service: Option<MembershipServiceHandle>,
    config: StorageNodeConfig,
    /// Runtime authority spine constructed at startup.
    authority: Option<RuntimeAuthority>,
    /// Result of pool import at startup, if pool_device_paths was set.
    imported_pool: Option<ImportedPool>,
    /// Daemon start time for uptime calculation.
    /// Cluster lease runtime for clustered pool import ownership.
    /// When configured, the node acquires a membership lease and
    /// issues write fences through the associated FenceAuthority.
    /// Wrapped in Arc<Mutex<>> so it can be shared into SessionContext
    /// for per-session lease token grants.
    cluster_lease_runtime: Option<Arc<Mutex<ClusterLeaseRuntime>>>,
    /// Write-fence validator for transport-layer write gating.
    /// Extracted from the FenceAuthority in ClusterLeaseRuntime.
    fence_validator: Option<FenceValidator>,
    /// Split-brain guard for partition-based fencing.
    /// Shared into SessionContext for per-session write gating.
    split_brain_guard: Option<Arc<Mutex<SplitBrainGuard>>>,
    start_time: Instant,
    /// Node-join pipeline tracking the staged join through ShadowOnly→VoterSpread→ReplicaTarget.
    join_pipeline: JoinPipeline,
    /// Stop flag for graceful shutdown.
    stop: Arc<AtomicBool>,
    /// Connection registry for eviction executor: maps peer IDs to endpoint addrs.
    /// Populated after transport handshake in serve_one.
    connection_registry: Arc<ConnectionRegistry>,
    /// Session binding table for eviction executor: released on peer departure.
    /// Populated after transport handshake in serve_one.
    session_bindings: Arc<Mutex<SessionBindingTable>>,
    /// Pending evictions queued by the eviction callback for processing.
    pending_evictions: Arc<Mutex<Vec<(SocketAddr, EvictionAction)>>>,
    /// Roster-to-session registry shared between PeerJoinHandshake and ConnectionAcceptor.
    roster_session_registry: Arc<std::sync::RwLock<RosterSessionRegistry>>,
    /// Session acceptor wrapping the roster registry for roster-verified bindings.
    session_acceptor: Arc<std::sync::RwLock<SessionAcceptor>>,
    /// First-time peer-join handshake for unknown peers.
    peer_join_handshake: Arc<PeerJoinHandshake>,
    /// Known-peer reconnect acceptor: delivers ReconnectStatePushMessage on reconnect.
    connection_acceptor: Arc<ConnectionAcceptor>,
    /// Placement version tracker for consistent rebalance across nodes.
    placement_version_tracker: Arc<PlacementVersionTracker>,
    active_barrier: Arc<Mutex<Option<SnapshotCoordinator>>>,
}

/// Build a ReachabilityMatrix from the membership failure detector and
/// evaluate the split-brain guard. Called after each membership tick to
/// keep the partition fence in sync with live peer health.
fn sync_partition_state_from_membership(
    membership: &MembershipRuntime,
    split_brain_guard: &std::sync::Mutex<SplitBrainGuard>,
    my_id: MemberId,
) {
    use tidefs_partition_runtime::types::ReachabilityEntry;

    let peers: Vec<_> = membership.detector.all_peers().collect();
    let my_reachable: Vec<MemberId> = peers
        .iter()
        .filter(|p| p.is_alive())
        .map(|p| p.member_id)
        .collect();

    let entry = ReachabilityEntry {
        observer: my_id,
        reachable: my_reachable,
        observed_at_millis: 0,
        epoch: tidefs_membership_epoch::EpochId::new(1),
    };

    let matrix = tidefs_partition_runtime::types::ReachabilityMatrix {
        entries: vec![entry],
        computed_at_millis: 0,
    };

    let mut guard = split_brain_guard.lock().unwrap();
    let members: Vec<_> = peers
        .iter()
        .map(|p| tidefs_membership_epoch::ClusterMemberRecord {
            member_id: p.member_id,
            member_class: p.member_class,
            current_membership_epoch_ref: p.epoch,
            log_frontier: 0,
            health: p.health,
            failure_domain_vector: tidefs_membership_epoch::FailureDomainVector::new(
                tidefs_membership_epoch::DomainId::new(p.failure_domain),
                tidefs_membership_epoch::DomainId::ZERO,
                tidefs_membership_epoch::DomainId::ZERO,
                tidefs_membership_epoch::DomainId::ZERO,
                tidefs_membership_epoch::DomainId::ZERO,
                tidefs_membership_epoch::DomainId::ZERO,
            ),
            digest: 0,
        })
        .collect();

    let (_state, _hazard) = guard.evaluate(&matrix, &membership.detector, &members);
}

struct MembershipServiceHandle {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MembershipServiceHandle {
    fn spawn(
        membership: Arc<Mutex<MembershipRuntime>>,
        membership_transport: Arc<Mutex<MembershipTransport>>,
        placement_version_tracker: Arc<PlacementVersionTracker>,
        period: Duration,
        split_brain_guard: Option<Arc<Mutex<SplitBrainGuard>>>,
        my_id: MemberId,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stop);
        // Poll interval for inbound message dispatch. Much tighter than the
        // tick period so membership protocol messages (Ack, Proposal, etc.)
        // are dispatched without multi-tick latency.
        let poll_interval = Duration::from_millis(10);
        let handle = thread::spawn(move || {
            let mut last_tick = Instant::now();
            while !stop_worker.load(Ordering::Relaxed) {
                // Continuously receive and dispatch inbound membership
                // messages on all connected peer sessions.
                recv_and_dispatch_membership_msgs(&membership, &membership_transport);

                // Sync placement version from the tracker into the
                // membership runtime so views carry the current version.
                {
                    let version = placement_version_tracker.current_version();
                    if version > 0 {
                        let mut runtime = membership.lock().unwrap();
                        runtime.set_placement_version(version);
                    }
                }

                // Tick the runtime (accept peers, send pings, broadcast
                // views) only at the configured period.
                if last_tick.elapsed() >= period {
                    run_membership_service_once(&membership, &membership_transport);

                    if let Some(ref guard) = split_brain_guard {
                        let runtime = membership.lock().unwrap();
                        sync_partition_state_from_membership(&runtime, guard, my_id);
                    }

                    last_tick = Instant::now();
                }

                thread::sleep(poll_interval);
            }
        });

        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MembershipServiceHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_membership_service_once(
    membership: &Arc<Mutex<MembershipRuntime>>,
    membership_transport: &Arc<Mutex<MembershipTransport>>,
) {
    let mut accepted_peers = Vec::new();

    {
        let mut transport = membership_transport.lock().unwrap();
        loop {
            match transport.try_accept_peer() {
                Ok(Some((peer_id, _))) => accepted_peers.push(peer_id),
                Ok(None) => break,
                Err(e) => {
                    if !is_optional_accept_poll(&e) {
                        eprintln!("[storage-node] membership accept error: {e:?}");
                    }
                    break;
                }
            }
        }
    }

    if !accepted_peers.is_empty() {
        let mut runtime = membership.lock().unwrap();
        for peer_id in accepted_peers {
            let member_id = MemberId::new(peer_id);
            if !runtime.detector.has_peer(member_id) {
                runtime.add_peer(member_id, MemberClass::Voter, peer_id);
            }
        }
    }

    let view = {
        let mut runtime = membership.lock().unwrap();
        let mut transport = membership_transport.lock().unwrap();
        let _ = transport.tick_runtime(&mut runtime);
        runtime.view()
    };

    {
        let mut transport = membership_transport.lock().unwrap();
        transport.broadcast_view(&view);
    }
}

/// Receive and dispatch inbound membership protocol messages on all connected
/// peer sessions. Sets non-blocking I/O so the membership service loop never
/// stalls on an idle session.
fn recv_and_dispatch_membership_msgs(
    membership: &Arc<Mutex<MembershipRuntime>>,
    membership_transport: &Arc<Mutex<MembershipTransport>>,
) {
    // Collect messages under the transport lock, then dispatch outside it
    // so handlers (Ping->Ack, etc.) can safely re-acquire the lock.
    let messages: Vec<(tidefs_transport::SessionId, MembershipWireMessage)> = {
        let mut transport = membership_transport.lock().unwrap();
        let session_ids: Vec<tidefs_transport::SessionId> =
            transport.peer_sessions.values().copied().collect();
        let _ = transport.transport.set_nonblocking(true);

        let mut msgs = Vec::new();
        for sid in session_ids {
            match recv_membership_msg(&mut transport.transport, sid) {
                Ok(wire_msg) => msgs.push((sid, wire_msg)),
                Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                    // No data available on this session.
                }
                Err(e) => {
                    eprintln!("[storage-node] membership recv error on session {sid}: {e:?}");
                }
            }
        }
        msgs
    };

    for (sid, wire_msg) in messages {
        dispatch_inbound_membership_msg(membership, membership_transport, sid, wire_msg);
    }
}

/// Dispatch a single inbound membership wire message to the runtime and
/// transport. Handles Ping→Ack response generation, Ack processing,
/// and epoch-transition message routing.
fn dispatch_inbound_membership_msg(
    membership: &Arc<Mutex<MembershipRuntime>>,
    membership_transport: &Arc<Mutex<MembershipTransport>>,
    sid: tidefs_transport::SessionId,
    wire_msg: MembershipWireMessage,
) {
    match wire_msg {
        MembershipWireMessage::Ping(ping) => {
            // Build an Ack and send it back on the same session.
            let ack = {
                let runtime = membership.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                SwimAck {
                    ping_seq_no: ping.seq_no,
                    acker: runtime.my_id,
                    acker_epoch: runtime.current_epoch(),
                    acker_epoch_receipt: 0,
                    suspicion_list: vec![],
                    membership_delta: vec![],
                    acked_at_millis: now,
                    signature: vec![],
                }
            };
            let mut transport = membership_transport.lock().unwrap();
            let ack_msg = MembershipWireMessage::Ack(ack);
            if let Err(e) = send_membership_msg(&mut transport.transport, sid, &ack_msg) {
                eprintln!("[storage-node] failed to send ack on session {sid}: {e:?}");
            }
        }
        MembershipWireMessage::Ack(ack) => {
            let mut runtime = membership.lock().unwrap();
            if let Err(e) = runtime.process_ack(&ack) {
                eprintln!("[storage-node] process_ack error: {e:?}");
            }
        }
        MembershipWireMessage::Proposal(proposal) => {
            let mut runtime = membership.lock().unwrap();
            if let Err(e) = runtime.receive_proposal(&proposal) {
                eprintln!("[storage-node] receive_proposal error: {e:?}");
            }
        }
        MembershipWireMessage::Accept(accept) => {
            let mut runtime = membership.lock().unwrap();
            if let Err(e) = runtime.receive_accept(accept) {
                eprintln!("[storage-node] receive_accept error: {e:?}");
            }
        }
        MembershipWireMessage::Commit(commit) => {
            let mut runtime = membership.lock().unwrap();
            if let Err(e) = runtime.receive_commit(&commit) {
                eprintln!("[storage-node] receive_commit error: {e:?}");
            }
        }
        MembershipWireMessage::View(view) => {
            // Inbound view snapshots are informational; the runtime's own
            // view is authoritative. No-op for now.
            let _ = view;
        }
        MembershipWireMessage::IndirectPingRequest(req) => {
            // Processed via FailureDetector when full indirect-ping relay
            // is wired through the runtime. No-op for now.
            let _ = req;
        }
        MembershipWireMessage::IndirectPingResponse(resp) => {
            // Requires verifying_key routing through the runtime.
            let _ = resp;
        }
        MembershipWireMessage::GossipBroadcast(gossip) => {
            // Requires full gossip engine wiring.
            let _ = gossip;
        }
    }
}

/// Derive a [`TransportReplicatedStoreConfig`] from the runtime authority's
/// replication factor. Uses majority quorum: write_quorum = (rf / 2) + 1.
fn transport_store_config_from_authority(
    a: &RuntimeAuthority,
    rdma: bool,
) -> TransportReplicatedStoreConfig {
    let rf = a.replication_factor() as usize;
    let write_quorum = if rf <= 1 { 1 } else { rf / 2 + 1 };
    TransportReplicatedStoreConfig {
        write_quorum,
        total_replicas: rf,
        enable_degraded_reads: true,
        rdma,
        store_options: tidefs_local_object_store::StoreOptions::default(),
    }
}

fn import_lock_dir(config: &StorageNodeConfig) -> PathBuf {
    config
        .pool_lock_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("/dev/tidefs/import"))
}

fn import_epoch_anchor_path(lock_dir: &Path) -> PathBuf {
    lock_dir.join("epoch_anchor")
}

fn pool_guid_hex(guid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in guid {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn object_pool_redundancy_policy(policy: LabelPoolRedundancyPolicy) -> ObjectPoolRedundancyPolicy {
    match policy {
        LabelPoolRedundancyPolicy::Replicated { copies } => {
            ObjectPoolRedundancyPolicy::replicated(copies)
        }
        LabelPoolRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } => ObjectPoolRedundancyPolicy::erasure(data_shards, parity_shards),
    }
}

fn object_pool_device_backing(path: &Path) -> Result<DeviceBacking, String> {
    match tidefs_pool_scan::classify_pool_device_backing(path)
        .map_err(|e| format!("pool device backing {}: {e}", path.display()))?
    {
        PoolDeviceBacking::BlockDevice => Ok(DeviceBacking::BlockDevice),
        PoolDeviceBacking::RegularFileDev => Ok(DeviceBacking::RegularFileDev),
    }
}

fn validate_cluster_create_device_media(
    device_paths: &[PathBuf],
    allow_file_devices: bool,
) -> Result<(), String> {
    for path in device_paths {
        match tidefs_pool_scan::classify_pool_device_backing(path)
            .map_err(|e| format!("cluster pool create device {}: {e}", path.display()))?
        {
            PoolDeviceBacking::BlockDevice => {}
            PoolDeviceBacking::RegularFileDev if allow_file_devices => {}
            PoolDeviceBacking::RegularFileDev => {
                return Err(format!(
                    "{} is a regular file; cluster pool create requires explicit --file-devices for development file media",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn pool_create_redundancy_from_cluster(policy: ClusterRedundancy) -> RedundancyPolicy {
    match policy {
        ClusterRedundancy::None => RedundancyPolicy::replicated(1),
        ClusterRedundancy::MirrorAcrossNodes { copies } => RedundancyPolicy::replicated(copies),
        ClusterRedundancy::ErasureCoded {
            data_shards,
            parity_shards,
        } => RedundancyPolicy::erasure(data_shards, parity_shards),
    }
}

fn cluster_create_redundancy_authority(
    redundancy: ClusterRedundancy,
    placement: ClusterPlacementPolicy,
) -> Result<RedundancyPolicy, String> {
    let expected = ClusterPlacementPolicy::from_redundancy(redundancy);
    if placement != expected {
        return Err(format!(
            "cluster pool create redundancy/placement mismatch: canonical redundancy {redundancy:?} derives {expected:?}, request carried {placement:?}"
        ));
    }
    Ok(pool_create_redundancy_from_cluster(redundancy))
}

fn object_pool_device_config(path: PathBuf) -> Result<ObjectDeviceConfig, String> {
    let backing = object_pool_device_backing(&path)?;
    Ok(ObjectDeviceConfig {
        media_class: DeviceMediaClass::default(),
        path: path.clone(),
        backing,
        class: ObjectDeviceClass::Data,
        kind: ObjectDeviceKind::Block { path },
        compression: None,
        encryption: None,
    })
}

fn object_pool_config_from_import(
    imported: &ImportedPool,
    lock_dir: &Path,
) -> Result<ObjectPoolConfig, String> {
    let device_paths = imported.config.device_tree.all_leaf_paths();
    if device_paths.is_empty() {
        return Err("pool import produced no leaf devices".into());
    }
    let devices = device_paths
        .into_iter()
        .map(object_pool_device_config)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ObjectPoolConfig {
        name: imported.config.pool_name.clone(),
        root_path: lock_dir.join(format!(
            "storage-node-pool-{}",
            pool_guid_hex(&imported.config.pool_uuid)
        )),
        devices,
    })
}

fn object_pool_properties_from_import(imported: &ImportedPool) -> PoolProperties {
    PoolProperties {
        redundancy_policy: object_pool_redundancy_policy(imported.config.redundancy_policy),
        ..PoolProperties::default()
    }
}

fn open_imported_pool_backend(imported: &ImportedPool, lock_dir: &Path) -> Result<Pool, String> {
    let config = object_pool_config_from_import(imported, lock_dir)?;
    std::fs::create_dir_all(&config.root_path).map_err(|e| {
        format!(
            "create storage-node pool metadata root {}: {e}",
            config.root_path.display()
        )
    })?;
    let properties = object_pool_properties_from_import(imported);
    Pool::open(config, properties, &StoreOptions::default())
        .map_err(|e| format!("open pool-backed storage-node backend: {e}"))
}

impl StorageNode {
    /// Create and start a storage node.
    pub fn start(config: StorageNodeConfig) -> Result<Self, String> {
        // ── Extract the runtime authority spine ──────────────────────
        let authority = config.authority.clone();

        // Pool import: if pool device paths are configured, import the pool
        // to verify label consistency and activate the byte-addressable media.
        //
        // Split-brain prevention: read the persisted epoch anchor to
        // reject stale committed roots from partitioned writers.
        let lock_dir = import_lock_dir(&config);
        let imported_pool = if !config.pool_device_paths.is_empty() {
            let epoch_anchor_path = import_epoch_anchor_path(&lock_dir);
            let min_epoch = read_epoch_anchor(&epoch_anchor_path);
            let imported =
                pool_import(&config.pool_device_paths, &lock_dir, false, None, min_epoch).map_err(
                    |e| {
                        let paths = config
                            .pool_device_paths
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("pool import failed for [{paths}]: {e}")
                    },
                )?;
            // Persist the committed-root epoch for the next import.
            if let Some(epoch) = imported.stats.committed_root_epoch {
                write_epoch_anchor(&epoch_anchor_path, epoch);
            }
            Some(imported)
        } else {
            None
        };

        let store_backend = if let Some(ref imported) = imported_pool {
            StoreBackend::PoolBacked(Box::new(open_imported_pool_backend(imported, &lock_dir)?))
        } else if let Some(ref a) = authority {
            if a.is_live() {
                // Transport-backed live path: use TransportReplicatedStore
                let primary_path = config
                    .store_paths
                    .first()
                    .ok_or_else(|| "store_paths must not be empty for live backend".to_string())?;
                let ts_cfg = transport_store_config_from_authority(a, config.rdma);
                let mut ts = TransportReplicatedStore::open(primary_path, a.node_id(), ts_cfg)?;
                // Connect to explicit replica peers as the storage data path.
                // Fall back to membership peers for older configurations.
                let replica_peers = if config.replica_peers.is_empty() {
                    &config.membership_peers
                } else {
                    &config.replica_peers
                };
                if replica_peers.is_empty() {
                    eprintln!(
                        "[storage-node] WARNING: live backend {:?} with zero replica peers;                          TransportReplicatedStore will have no remote replicas",
                        a.backend(),
                    );
                }
                for peer in replica_peers {
                    ts.connect_replica(peer.node_id, peer.addr)
                        .map_err(|e| format!("connect replica {}: {e}", peer.node_id))?;
                }
                StoreBackend::TransportBacked(Box::new(ts))
            } else {
                // Local/harness path: use path-backed ReplicatedObjectStore
                let store_cfg = ReplicatedStoreConfig {
                    replica_count: a.replication_factor() as usize,
                    ..Default::default()
                };
                let store = ReplicatedObjectStore::open(&config.store_paths, store_cfg)
                    .map_err(|e| format!("failed to open replicated store: {e}"))?;
                StoreBackend::Local(Box::new(store))
            }
        } else {
            // No authority: default to local path-backed
            let store_cfg = ReplicatedStoreConfig::default();
            let store = ReplicatedObjectStore::open(&config.store_paths, store_cfg)
                .map_err(|e| format!("failed to open replicated store: {e}"))?;
            StoreBackend::Local(Box::new(store))
        };

        let mut transport = if config.rdma {
            Transport::with_rdma_or_tcp(config.node_id, Duration::from_secs(5))
        } else {
            Transport::new(config.node_id)
        };
        // Apply carrier policy from config (defaults to Prefer when unset).
        match config.carrier_policy.as_deref() {
            Some("enforce") => {
                transport = transport.with_carrier_policy(
                    tidefs_transport::carrier_selection::CarrierPolicy::Enforce,
                );
                eprintln!("[storage-node] carrier_policy=enforce: RDMA claim will fail closed on silent TCP fallback");
            }
            _ => {
                transport = transport.with_carrier_policy(
                    tidefs_transport::carrier_selection::CarrierPolicy::Prefer,
                );
            }
        }
        transport
            .configure_generated_attestation(true)
            .map_err(|e| format!("transport attestation setup failed: {e}"))?;

        // Gate outbound sends with a concurrency limit to prevent a fast
        // sender from exhausting transport memory when the receiver or
        // network is slow (B5: Transport Flow Control Not Wired).
        // Default 256 in-flight sends; configurable via future config field.
        transport.set_send_concurrency_limit(256);

        transport
            .bind(tidefs_transport::TransportAddr::Tcp(config.bind_addr))
            .map_err(|e| format!("transport bind failed: {e:?}"))?;

        if let Some(ref a) = authority {
            eprintln!(
                "[storage-node] authority spine: backend={} live={} rf={}",
                a.backend(),
                a.is_live(),
                a.replication_factor(),
            );
        }

        let member_class = authority
            .as_ref()
            .and_then(|a| a.member_class())
            .or(config.member_class)
            .unwrap_or(MemberClass::Voter);
        let failure_domain = authority
            .as_ref()
            .and_then(|a| a.failure_domain())
            .or(config.failure_domain)
            .unwrap_or(config.node_id);
        let membership_config = MembershipConfig::default();
        let membership_period =
            Duration::from_millis((membership_config.ping_interval_ms / 4).max(1));
        let mut membership = if let Some(ref checkpoint_dir) = config.membership_checkpoint_dir {
            // Cold-start recovery: open checkpoint persistence and load latest
            // epoch snapshot plus transition journal so the runtime recovers
            // roster, epoch, and incarnation without manual repair.
            let checkpoint_store = tidefs_membership_live::CheckpointPersistence::open(
                checkpoint_dir,
            )
            .map_err(|e| {
                format!(
                    "membership checkpoint persistence open at {}: {e}",
                    checkpoint_dir.display()
                )
            })?;
            let journal =
                tidefs_membership_epoch::transition_journal::MembershipTransitionJournal::new();
            MembershipRuntime::load_from_checkpoint_store(
                Box::new(checkpoint_store),
                journal,
                membership_config,
                MemberId::new(config.node_id),
                member_class,
                failure_domain,
            )
        } else {
            MembershipRuntime::new(
                membership_config,
                MemberId::new(config.node_id),
                member_class,
                failure_domain,
            )
        };
        for peer in &config.membership_peers {
            membership.add_peer(
                MemberId::new(peer.node_id),
                peer.member_class,
                peer.failure_domain,
            );
        }

        let membership_transport =
            if config.membership_bind_addr.is_some() || !config.membership_peers.is_empty() {
                let mut transport = MembershipTransport::new(config.node_id);
                if let Some(addr) = config.membership_bind_addr {
                    transport
                        .bind(addr)
                        .map_err(|e| format!("membership transport bind failed: {e:?}"))?;
                }
                for peer in &config.membership_peers {
                    transport
                        .connect_to_peer(peer.node_id, peer.addr)
                        .map_err(|e| {
                            format!(
                                "membership transport connect to node {} at {} failed: {e:?}",
                                peer.node_id, peer.addr
                            )
                        })?;
                }
                Some(Arc::new(Mutex::new(transport)))
            } else {
                None
            };

        let membership = Arc::new(Mutex::new(membership));

        // Wire eviction executor into the membership runtime.
        let connection_registry = Arc::new(ConnectionRegistry::new());
        let session_bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let pending_evictions: Arc<Mutex<Vec<(SocketAddr, EvictionAction)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Roster-session bridge: shared registry + session acceptor used by
        // both PeerJoinHandshake (first-time joins) and ConnectionAcceptor
        // (known-peer reconnects).
        let roster_session_registry =
            Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let session_acceptor = Arc::new(std::sync::RwLock::new(SessionAcceptor::new(Arc::clone(
            &roster_session_registry,
        ))));

        // First-time peer-join handshake: accepts unknown peers, pushes
        // epoch state, and queues them for roster inclusion.
        let peer_join_handshake =
            Arc::new(PeerJoinHandshake::new(Arc::clone(&roster_session_registry)));

        // Known-peer reconnect acceptor: delivers ReconnectStatePushMessage
        // to peers that are already in the committed roster.
        let connection_acceptor = Arc::new(ConnectionAcceptor::new(Arc::clone(&session_acceptor)));
        {
            let pending = Arc::clone(&pending_evictions);
            let mut rt = membership.lock().unwrap();
            rt.wire_eviction_executor(
                Arc::clone(&connection_registry),
                Arc::clone(&session_bindings),
                Box::new(move |addr, action| {
                    pending.lock().unwrap().push((addr, action));
                }),
            );

            // Subscribe ConnectionAcceptor to the EpochAdvanceCoordinator so the
            // cached roster stays synchronized across epoch transitions. Both the
            // known-peer reconnect path and first-time join path consult this
            // roster to distinguish reconnects from new joins.
            if let Some(ref mut coordinator) = rt.epoch_coordinator {
                // ConnectionAcceptor implements both EpochCommitSubscriber traits,
                // so it can be registered directly with the coordinator.
                coordinator.subscribe(Box::new(AcceptorCoordinatorBridge {
                    acceptor: Arc::clone(&connection_acceptor),
                }));
            }
        }

        // Wire roster-update bridge: when the ConnectionAcceptor receives a
        // new roster from any source (EpochCommitBus or EpochAdvanceCoordinator),
        // also forward it to PeerJoinHandshake so first-time joins see the
        // current committed roster.
        {
            let pjh: Arc<PeerJoinHandshake> = Arc::clone(&peer_join_handshake);
            connection_acceptor.set_roster_update_hook(move |roster| {
                pjh.update_roster(roster.clone());
            });
        }

        // ── Placement version tracker ──────────────────────────────
        let placement_version_tracker = Arc::new(PlacementVersionTracker::new());

        // ── Split-brain guard for partition-based fencing ─────
        let split_brain_guard: Option<Arc<Mutex<SplitBrainGuard>>> =
            if config.cluster_lease_config.is_some() {
                let guard = Arc::new(Mutex::new(SplitBrainGuard::new(
                    tidefs_membership_epoch::MemberId::new(config.node_id),
                    EpochId::new(1),
                    2,
                )));
                Some(Arc::clone(&guard))
            } else {
                None
            };

        let membership_service = membership_transport.as_ref().map(|transport| {
            MembershipServiceHandle::spawn(
                Arc::clone(&membership),
                Arc::clone(transport),
                Arc::clone(&placement_version_tracker),
                membership_period,
                split_brain_guard.clone(),
                tidefs_membership_epoch::MemberId::new(config.node_id),
            )
        });

        // ── Cluster lease runtime for pool import ownership ─────
        let (cluster_lease_runtime, fence_validator) =
            if let Some(ref lease_config) = config.cluster_lease_config {
                use tokio::sync::mpsc;
                let (outgoing_tx, _outgoing_rx) = mpsc::unbounded_channel();
                let fence_authority = FenceAuthority::new();
                let fence_validator = fence_authority.validator();
                let rt = ClusterLeaseRuntime::new(
                    config.node_id,
                    tidefs_membership_epoch::EpochId(1),
                    lease_config.clone(),
                    outgoing_tx,
                )
                .with_fence_authority(fence_authority);
                (Some(Arc::new(Mutex::new(rt))), Some(fence_validator))
            } else {
                (None, None)
            };

        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
            store: Arc::new(Mutex::new(store_backend)),
            membership,
            membership_transport,
            _membership_service: membership_service,
            config,
            authority,
            imported_pool,
            start_time: Instant::now(),
            connection_registry: Arc::clone(&connection_registry),
            session_bindings: Arc::clone(&session_bindings),
            pending_evictions,
            roster_session_registry: Arc::clone(&roster_session_registry),
            session_acceptor: Arc::clone(&session_acceptor),
            peer_join_handshake: Arc::clone(&peer_join_handshake),
            connection_acceptor: Arc::clone(&connection_acceptor),
            placement_version_tracker,
            active_barrier: Arc::new(Mutex::new(None)),
            join_pipeline: JoinPipeline::new(),
            stop: Arc::new(AtomicBool::new(false)),
            cluster_lease_runtime,
            fence_validator,
            split_brain_guard,
        })
    }

    /// Initiate a multi-node snapshot barrier.
    ///
    /// Collects the current peer set from active transport sessions,
    /// creates a [`SnapshotCoordinator`], fans out
    /// [`Frame::SnapshotBarrier`] requests to every peer, and stores the
    /// coordinator in [`active_barrier`] for asynchronous response
    /// collection by [`serve_session`].
    ///
    /// Returns the encoded barrier request bytes for diagnostics.
    pub fn initiate_snapshot_barrier(
        &self,
        barrier_id: u64,
        snapshot_name: String,
        config: SnapshotBarrierConfig,
    ) -> Result<Vec<u8>, String> {
        use tidefs_transport::SessionId;
        // Collect peer ids and session bindings from live transport sessions.
        let mut t = self.transport.lock().unwrap();
        let stats = t.all_stats();
        let mut peer_ids: Vec<u64> = Vec::new();
        let mut peer_sessions: Vec<(u64, SessionId)> = Vec::new();
        for sid in stats.sessions.keys() {
            if let Some(peer_id) = t.peer_node(*sid) {
                if !peer_ids.contains(&peer_id) {
                    peer_ids.push(peer_id);
                }
                peer_sessions.push((peer_id, *sid));
            }
        }
        // Build the coordinator and encode the barrier request.
        let coord =
            SnapshotCoordinator::new(barrier_id, snapshot_name.clone(), peer_ids.clone(), config);
        let request_bytes = coord.request_bytes();
        // Fan out the barrier request to every peer session.
        let mut send_errors = 0usize;
        for (peer_id, session_id) in &peer_sessions {
            if let Err(e) = t.send_message(*session_id, &request_bytes) {
                eprintln!(
                    "[storage-node] barrier {barrier_id}: send to peer {peer_id} failed: {e:?}"
                );
                send_errors += 1;
            }
        }
        drop(t); // release transport lock before locking active_barrier
                 // Store the coordinator for asynchronous response collection.
        *self.active_barrier.lock().unwrap() = Some(coord);
        if send_errors > 0 {
            eprintln!(
                "[storage-node] barrier {barrier_id}: {send_errors}/{total} sends failed",
                total = peer_sessions.len(),
            );
        }
        eprintln!(
            "[storage-node] barrier {barrier_id} initiated: {count} peers",
            count = peer_ids.len(),
        );
        Ok(request_bytes)
    }

    /// Accept one incoming connection, complete handshake, then spawn a
    /// session handler thread and return immediately so the next connection
    /// can be accepted. This enables multi-session protocols (e.g.,
    /// TransportReplicatedStore's Control/Data/Shadow session families) to
    /// complete handshake against this storage-node peer.
    /// Set the split-brain guard to minority-fenced state, causing all
    /// write-gating operations (create, import, lease, catalog delta)
    /// to be refused with a typed minority-fenced error.
    ///
    /// This is a test/diagnostic injection point for partition campaign
    /// validation; the production path uses the full partition runtime.
    pub fn set_partition_fenced(&mut self) {
        if let Some(ref guard) = self.split_brain_guard {
            let mut g = guard.lock().unwrap();
            g.partition_state = tidefs_partition_runtime::types::PartitionState::MinorityFenced {
                quorum_side_voter_count: 3,
                since_millis: 0,
            };
            g.fence = PartitionFence::raise_all();
        }
    }

    /// Clear the partition fence, restoring write capability.
    pub fn clear_partition_fence(&mut self) {
        if let Some(ref guard) = self.split_brain_guard {
            let mut g = guard.lock().unwrap();
            g.partition_state = tidefs_partition_runtime::types::PartitionState::Connected;
            g.fence = PartitionFence::default();
        }
    }

    pub fn serve_one(&mut self) -> Result<(), String> {
        let accept_result = {
            let mut t = self.transport.lock().unwrap();
            t.accept_incoming()
        };
        let session_id = match accept_result {
            Ok(sid) => sid,
            Err(e) => {
                std::thread::sleep(std::time::Duration::from_millis(5));
                if is_accept_poll(&e) {
                    return Ok(());
                }
                return Err(format!("accept failed: {e:?}"));
            }
        };

        eprintln!("[storage-node] accepted session {session_id}");

        {
            let mut t = self.transport.lock().unwrap();
            t.perform_handshake(session_id)
                .map_err(|e| format!("handshake failed: {e:?}"))?;
        }

        eprintln!("[storage-node] session {session_id} established");

        // Log the transport backend actually negotiated for this session.
        // This closes the "silent TCP fallback" gap (B9): when --rdma is
        // requested but the session falls back to TCP, the operator can
        // see the actual backend in the logs.
        {
            let t = self.transport.lock().unwrap();
            if let Some(backend_kind) = t.session_backend_kind(session_id) {
                let peer_info = t
                    .peer_node(session_id)
                    .map(|p| format!(" peer={p}"))
                    .unwrap_or_default();
                eprintln!(
                    "[storage-node] session {session_id}{peer_info} transport_backend={backend_kind}"
                );
                if let Some(peer_node) = t.peer_node(session_id) {
                    if let Some(disclosure) = t.carrier_disclosure(peer_node) {
                        eprintln!(
                            "[storage-node] session {session_id} peer={peer_node} carrier_disclosure: {disclosure}"
                        );
                    }
                }
            }
        }
        // --- Join/reconnect dispatch: determine whether this is a known-peer
        //     reconnect or a first-time peer join, and deliver the appropriate
        //     epoch state push message.
        if let Some(peer_node) = {
            let t = self.transport.lock().unwrap();
            t.peer_node(session_id)
        } {
            // Build identity for join/reconnect dispatch.
            let identity = MemberIdentity::new(peer_node, 1);

            // Try known-peer reconnect first.
            let reconnect_outcome =
                self.connection_acceptor
                    .accept_connection(peer_node, session_id.0, identity);

            match reconnect_outcome {
                Ok(outcome) => match outcome {
                    PeerReconnectOutcome::Known { push_message, .. } => {
                        eprintln!(
                            "[storage-node] session {session_id}: known peer {peer_node} reconnecting, pushing epoch state"
                        );
                        placement_version_bump_on_reconnect(
                            &self.placement_version_tracker,
                            peer_node,
                        );
                        let encoded = push_message.encode();
                        if let Err(e) = {
                            let mut t = self.transport.lock().unwrap();
                            t.send_message(session_id, &encoded)
                        } {
                            eprintln!("[storage-node] session {session_id}: failed to send reconnect push: {e:?}");
                            return Err(format!("reconnect push send failed: {e:?}"));
                        }
                    }
                    PeerReconnectOutcome::AlreadyBound { .. } => {
                        eprintln!(
                            "[storage-node] session {session_id}: duplicate session for known peer {peer_node}, rejecting"
                        );
                        return Err(format!(
                            "duplicate session {session_id} for peer {peer_node}"
                        ));
                    }
                    PeerReconnectOutcome::Unknown => {
                        // Peer not in committed roster — skip join dispatch.
                        // Unknown peers (e.g. simple Frame clients) do not
                        // need a membership epoch push. They connect for
                        // Frame protocol only. Membership join happens
                        // through the explicit join protocol when needed.
                        eprintln!(
                            "[storage-node] session {session_id}: unknown peer {peer_node}, proceeding without membership push"
                        );
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[storage-node] session {session_id}: reconnect error for peer {peer_node}: {e:?}"
                    );
                    return Err(format!("reconnect error: {e:?}"));
                }
            }
        }

        // Register peer in eviction tracking tables so the eviction
        // executor can tear down connections and release bindings when
        // the peer is removed from the membership roster.
        let peer_node = { self.transport.lock().unwrap().peer_node(session_id) };
        if let Some(peer_node) = peer_node {
            let addr = { self.transport.lock().unwrap().session_addr(session_id) };
            if let Some(addr) = addr {
                use tidefs_membership_live::session_binding::{PeerSessionBinding, SessionId};
                use tidefs_transport::connection_registry::ConnectionId;
                use tidefs_transport::peer_admission::AdmittedPeer;

                let admitted = AdmittedPeer::new(peer_node, 1);
                let _ =
                    self.connection_registry
                        .insert(&admitted, ConnectionId::new(peer_node), addr);

                let binding = PeerSessionBinding::new(
                    peer_node,
                    tidefs_membership_epoch::MemberId::new(peer_node),
                    SessionId::new(session_id.0),
                    tidefs_membership_epoch::EpochId::new(1),
                );
                self.session_bindings.lock().unwrap().insert(binding);
            }
        }

        // Build the session context, cloning shared state for the handler thread.
        let ctx = SessionContext {
            transport: Arc::clone(&self.transport),
            store: Arc::clone(&self.store),
            membership: Arc::clone(&self.membership),
            membership_transport: self.membership_transport.as_ref().map(Arc::clone),
            split_brain_guard: self.split_brain_guard.clone(),
            authority: self.authority.clone(),
            config: self.config.clone(),
            imported_pool: self.imported_pool.clone(),
            start_time: self.start_time,
            pending_evictions: Arc::clone(&self.pending_evictions),
            roster_session_registry: Arc::clone(&self.roster_session_registry),
            session_acceptor: Arc::clone(&self.session_acceptor),
            peer_join_handshake: Arc::clone(&self.peer_join_handshake),
            connection_acceptor: Arc::clone(&self.connection_acceptor),
            placement_version_tracker: Arc::clone(&self.placement_version_tracker),
            active_barrier: Arc::clone(&self.active_barrier),
            fence_validator: self.fence_validator.clone(),
            lease_runtime: self.cluster_lease_runtime.as_ref().map(Arc::clone),
        };

        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _guard = rt.enter();
            serve_session(session_id, ctx);
        });

        Ok(())
    }
}

/// Handle all messages on an established session until the client
/// disconnects or sends Bye. Runs on a dedicated thread spawned by
/// [`StorageNode::serve_one`].
fn serve_session(session_id: tidefs_transport::SessionId, ctx: SessionContext) {
    loop {
        let raw = match recv_session_frame_unlocked(&ctx, session_id) {
            Ok(r) => r,
            Err(e) => {
                if is_read_poll(&e) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                eprintln!("[storage-node] session {session_id}: recv error: {e:?}");
                let peer_node = ctx.transport.lock().unwrap().peer_node(session_id);
                if let Some(peer_node) = peer_node {
                    eprintln!(
                        "[storage-node] session {session_id}: marking peer {peer_node} dead on store"
                    );
                    placement_version_bump_on_disconnect(&ctx.placement_version_tracker, peer_node);
                }
                break;
            }
        };

        // Tick membership
        {
            let mut m = ctx.membership.lock().unwrap();
            if let Some(ref mt) = ctx.membership_transport {
                let mut transport = mt.lock().unwrap();
                let _ = transport.tick_runtime(&mut m);
            } else {
                m.tick();
            }
        }

        // Process pending peer evictions from membership epoch commits.
        process_evictions(&ctx);

        // Try Frame protocol first (4-byte ASCII tag prefix)
        if let Some(frame) = protocol::decode(&raw) {
            let store = Arc::clone(&ctx.store);
            let response = handle_frame_ctx(session_id, &frame, &store, &ctx);

            // Route snapshot barrier responses to the active coordinator.
            if matches!(&frame, Frame::SnapshotBarrierResponse { .. }) {
                let peer_id = {
                    let t = ctx.transport.lock().unwrap();
                    t.peer_node(session_id).unwrap_or(0)
                };
                if let Some(ref mut coord) = *ctx.active_barrier.lock().unwrap() {
                    if coord.record_response(peer_id, &frame) {
                        eprintln!("[storage-node] barrier: recorded response from peer {peer_id}");
                    }
                }
            }

            if let Some(resp) = response {
                if matches!(resp, Frame::Bye) {
                    let mut t = ctx.transport.lock().unwrap();
                    t.send_message(session_id, &protocol::encode(&resp)).ok();
                    eprintln!("[storage-node] session {session_id} closing");
                    t.close_session(session_id, SessionCloseReason::LocalShutdown)
                        .ok();
                    return;
                }
                let mut t = ctx.transport.lock().unwrap();
                t.send_message(session_id, &protocol::encode(&resp))
                    .map_err(|e| {
                        eprintln!("[storage-node] session {session_id}: send error: {e:?}");
                    })
                    .ok();
            }

            if let Frame::Bye = frame {
                return;
            }
            continue;
        }

        // ── VSNP: TideFS Snapshot Network Protocol push/pull handler ──
        // Client sends raw VSNP messages (magic b"VSNP") for dataset
        // send/receive over the transport layer. This handler processes
        // push (receive export into local pool) and pull-request (export
        // from local pool and return).
        if raw.len() >= 4 && raw[..4] == *b"VSNP" {
            match handle_vsnp_message(session_id, &raw, &ctx) {
                Ok(Some(response)) => {
                    let mut t = ctx.transport.lock().unwrap();
                    t.send_message(session_id, &response)
                        .map_err(|e| {
                            eprintln!(
                                "[storage-node] session {session_id}: vsnp send error: {e:?}"
                            );
                        })
                        .ok();
                }
                Ok(None) => {
                    // No response needed (e.g., internal processing).
                }
                Err(e) => {
                    eprintln!("[storage-node] session {session_id}: vsnp error: {e}");
                    // Send error response back to client.
                    let error_bytes = build_vsnp_error(&format!("vsnp handler error: {e}"));
                    let mut t = ctx.transport.lock().unwrap();
                    t.send_message(session_id, &error_bytes).ok();
                }
            }
            continue;
        }

        // SegmentFetchRequest: 4-byte SF01 magic prefix
        if raw.len() >= 4 && raw[..4] == SEGMENT_FETCH_REQUEST_MAGIC {
            let request = match SegmentFetchRequest::decode(&raw) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "[storage-node] session {session_id}: segment fetch decode error: {e}"
                    );
                    continue;
                }
            };
            match handle_segment_fetch_ctx(session_id, request, &ctx) {
                Ok(obj_id) => {
                    eprintln!(
                        "[storage-node] session {session_id}: served segment fetch for object {obj_id}"
                    );
                }
                Err(e) => {
                    eprintln!("[storage-node] session {session_id}: segment fetch error: {e}");
                }
            }
            continue;
        }

        // ── ReplicationMessage handler: peer replication receive ────
        // Inbound replication messages from peer storage nodes MUST
        // use *_local methods on TransportBacked to avoid
        // re-replication loops. Never use *_named fan-out methods
        // here — client fan-out is handled exclusively by
        // handle_frame_ctx. See LOCAL-ONLY boundary.
        if let Ok(msg) = bincode::deserialize::<ReplicationMessage>(&raw) {
            let response = match &msg {
                ReplicationMessage::Put { name, payload } => {
                    let mut s = ctx.store.lock().unwrap();
                    let result = match &mut *s {
                        StoreBackend::Local(rs) => {
                            rs.put_local(name, payload).map_err(|e| e.to_string())
                        }
                        StoreBackend::TransportBacked(ts) => ts.put_local(name, payload),
                        StoreBackend::PoolBacked(pool) => pool_put_named(pool, name, payload),
                    };
                    match result {
                        Ok(()) => ReplicationMessage::Ack {
                            key_hash: name.clone(),
                            success: true,
                        },
                        Err(_e) => ReplicationMessage::Ack {
                            key_hash: name.clone(),
                            success: false,
                        },
                    }
                }
                ReplicationMessage::Get { name } => {
                    let mut s = ctx.store.lock().unwrap();
                    let result = match &mut *s {
                        StoreBackend::Local(rs) => rs.get_local(name),
                        StoreBackend::TransportBacked(ts) => ts.get_local(name),
                        StoreBackend::PoolBacked(pool) => pool_get_named(pool, name),
                    };
                    match result {
                        Ok(Some(payload)) => ReplicationMessage::GetResponse {
                            found: true,
                            payload,
                        },
                        Ok(None) => ReplicationMessage::GetResponse {
                            found: false,
                            payload: vec![],
                        },
                        Err(e) => ReplicationMessage::GetResponse {
                            found: false,
                            payload: e.into_bytes(),
                        },
                    }
                }
                ReplicationMessage::Delete { name, generation } => {
                    let mut s = ctx.store.lock().unwrap();
                    let result = match &mut *s {
                        StoreBackend::Local(rs) => rs.delete_local(name),
                        StoreBackend::TransportBacked(ts) => ts.delete_local(name),
                        StoreBackend::PoolBacked(pool) => pool_delete_named(pool, name),
                    };
                    match result {
                        Ok(deleted) => ReplicationMessage::DeleteAck {
                            deleted,
                            generation: *generation,
                        },
                        Err(_e) => ReplicationMessage::DeleteAck {
                            deleted: false,
                            generation: *generation,
                        },
                    }
                }
                ReplicationMessage::SyncRequest => {
                    let s = ctx.store.lock().unwrap();
                    let entries = sync_entries_from_store(&s);
                    ReplicationMessage::SyncResponse { entries }
                }
                ReplicationMessage::ReadPlan { plan_bytes } => {
                    let s = ctx.store.lock().unwrap();
                    read_plan_response_from_store(&s, plan_bytes, ctx.config.node_id)
                }
                ReplicationMessage::ScrubRequest => {
                    let s = ctx.store.lock().unwrap();
                    let (report_json, findings_count) = local_scrub_report_json(&ctx.config, &s);
                    ReplicationMessage::ScrubResponse {
                        report_json,
                        findings_count,
                    }
                }
                ReplicationMessage::RepairObject {
                    key,
                    placement_receipt_ref,
                    authoritative_payload,
                } => {
                    let (success, repaired_placement_receipt_ref) = {
                        let mut s = ctx.store.lock().unwrap();
                        match exact_repair_object_key(key) {
                            Ok(object_key) => match apply_receipt_bound_key_repair(
                                &mut *s,
                                object_key,
                                authoritative_payload,
                                *placement_receipt_ref,
                            ) {
                                Ok(repaired_placement_receipt_ref) => {
                                    (true, repaired_placement_receipt_ref)
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[storage-node] session {session_id}: repair object refused: {e}"
                                    );
                                    (false, None)
                                }
                            },
                            Err(e) => {
                                eprintln!(
                                    "[storage-node] session {session_id}: repair object key invalid: {e}"
                                );
                                (false, None)
                            }
                        }
                    };
                    ReplicationMessage::RepairObjectAck {
                        key: key.clone(),
                        success,
                        repaired_placement_receipt_ref,
                    }
                }
                ReplicationMessage::ScrubResponse {
                    report_json,
                    findings_count,
                } => {
                    eprintln!(
                        "[storage-node] session {session_id}: received scrub response from peer findings_count={findings_count}"
                    );
                    scrub_response_ack(report_json, *findings_count)
                }
                ReplicationMessage::RepairObjectAck { .. } => {
                    eprintln!("[storage-node] session {session_id}: received repair ack from peer");
                    ReplicationMessage::Ack {
                        key_hash: "repair-ack".into(),
                        success: true,
                    }
                }
                _ => ReplicationMessage::Ack {
                    key_hash: String::new(),
                    success: false,
                },
            };
            let mut t = ctx.transport.lock().unwrap();
            send_replication_msg(&mut t, session_id, &response)
                .map_err(|e| {
                    eprintln!(
                        "[storage-node] session {session_id}: send replication response: {e:?}"
                    );
                })
                .ok();
            continue;
        }

        // -- ClusterPoolMessage handler: cluster pool create/import dispatch --
        if raw.len() >= 4 && raw[..4] == *CLUSTER_POOL_MESSAGE_MAGIC {
            let msg_bytes = &raw[4..];
            match ClusterPoolMessage::decode(msg_bytes) {
                Ok(msg) => {
                    let peer_node_id = {
                        let t = ctx.transport.lock().unwrap();
                        t.peer_node(session_id)
                    };
                    let response =
                        handle_cluster_pool_message(session_id, peer_node_id, &msg, &ctx);
                    if let Some(resp) = response {
                        if let Ok(encoded) = resp.encode() {
                            let mut wire = Vec::with_capacity(4 + encoded.len());
                            wire.extend_from_slice(CLUSTER_POOL_MESSAGE_MAGIC);
                            wire.extend_from_slice(&encoded);
                            let mut t = ctx.transport.lock().unwrap();
                            t.send_message(session_id, &wire)
                                .map_err(|e| {
                                    eprintln!("[storage-node] session {session_id}: send cluster pool response: {e:?}");
                                })
                                .ok();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[storage-node] session {session_id}: cluster pool message decode error: {e:?}");
                }
            }
            continue;
        }

        eprintln!(
            "[storage-node] session {session_id}: failed to decode message: {} bytes starting with {:02x?}",
            raw.len(),
            &raw[..raw.len().min(8)]
        );
        // Don't close the session on unrecognized messages — keep
        // accepting in case this is a protocol we don't handle yet.
    }

    let mut t = ctx.transport.lock().unwrap();
    let _ = t.close_session(session_id, SessionCloseReason::TransportError);
}

/// Handle a cluster pool protocol message received from a peer node.
/// Dispatches to real pool create/import code and returns the response.
/// Check whether the partition guard allows write-gating operations.
///
/// Returns `Ok(())` when writes are allowed or no guard is active.
/// Returns `Err(error_message)` with a typed MinorityFenced error when
/// the node is on the minority side of a network partition.
fn check_partition_fence(ctx: &SessionContext) -> Result<(), String> {
    if let Some(ref guard) = ctx.split_brain_guard {
        let guard = guard.lock().unwrap();
        if !guard.can_accept_writes() {
            let state = format!("{:?}", guard.partition_state);
            return Err(format!(
                "minority-fenced: node is on the minority side of a partition (state: {state}); \
                 writes, imports, catalog mutations, and lease grants are refused"
            ));
        }
    }
    Ok(())
}

fn handle_cluster_pool_message(
    session_id: tidefs_transport::SessionId,
    peer_node_id: Option<u64>,
    msg: &ClusterPoolMessage,
    ctx: &SessionContext,
) -> Option<ClusterPoolMessage> {
    match msg {
        ClusterPoolMessage::CreateRequest(req) => {
            eprintln!(
                "[storage-node] session {session_id}: cluster pool create request pool={} node={}",
                req.pool_name, req.target_node_id
            );
            if let Err(fence_err) = check_partition_fence(ctx) {
                eprintln!("[storage-node] session {session_id}: create refused: {fence_err}");
                return Some(ClusterPoolMessage::CreateResponse(
                    ClusterPoolCreateResponse {
                        request_id: req.request_id,
                        node_id: req.target_node_id,
                        pool_guid: req.pool_guid,
                        success: false,
                        device_guids: vec![],
                        error: Some(fence_err),
                    },
                ));
            }
            let device_paths: Vec<std::path::PathBuf> = req
                .node_devices
                .iter()
                .map(|d| std::path::PathBuf::from(&d.device_path))
                .collect();
            if let Err(media_err) =
                validate_cluster_create_device_media(&device_paths, req.allow_file_devices)
            {
                eprintln!("[storage-node] session {session_id}: create refused: {media_err}");
                return Some(ClusterPoolMessage::CreateResponse(
                    ClusterPoolCreateResponse {
                        request_id: req.request_id,
                        node_id: req.target_node_id,
                        pool_guid: req.pool_guid,
                        success: false,
                        device_guids: vec![],
                        error: Some(media_err),
                    },
                ));
            }
            let redundancy =
                match cluster_create_redundancy_authority(req.redundancy, req.placement) {
                    Ok(redundancy) => redundancy,
                    Err(redundancy_err) => {
                        eprintln!(
                            "[storage-node] session {session_id}: create refused: {redundancy_err}"
                        );
                        return Some(ClusterPoolMessage::CreateResponse(
                            ClusterPoolCreateResponse {
                                request_id: req.request_id,
                                node_id: req.target_node_id,
                                pool_guid: req.pool_guid,
                                success: false,
                                device_guids: vec![],
                                error: Some(redundancy_err),
                            },
                        ));
                    }
                };
            let config = PoolCreateConfig {
                pool_name: req.pool_name.clone(),
                pool_guid: Some(req.pool_guid),
                redundancy,
                encryption_key: None,
                clustered: true,
            };
            let (success, device_guids, error) =
                match PoolCreator::create_pool(&device_paths, &config) {
                    Ok(outcome) => (true, outcome.device_guids, None),
                    Err(e) => (false, vec![], Some(format!("{e:?}"))),
                };
            Some(ClusterPoolMessage::CreateResponse(
                ClusterPoolCreateResponse {
                    request_id: req.request_id,
                    node_id: req.target_node_id,
                    pool_guid: req.pool_guid,
                    success,
                    device_guids,
                    error,
                },
            ))
        }
        ClusterPoolMessage::ImportRequest(req) => {
            eprintln!(
                "[storage-node] session {session_id}: cluster pool import request pool_guid={:02x?} node={} peer={:?}",
                &req.pool_guid[..4], req.target_node_id, peer_node_id
            );

            // ── Partition fence check ──────────────────────────
            if let Err(fence_err) = check_partition_fence(ctx) {
                eprintln!("[storage-node] session {session_id}: import refused: {fence_err}");
                return Some(ClusterPoolMessage::ImportResponse(
                    ClusterPoolImportResponse {
                        request_id: req.request_id,
                        node_id: req.target_node_id,
                        pool_guid: req.pool_guid,
                        success: false,
                        committed_root_epoch: None,
                        intent_log_replayed: None,
                        error: Some(fence_err),
                    },
                ));
            }

            // ── Membership verification ──────────────────────────
            // The requesting peer's authenticated node ID must match the
            // target_node_id in the import request.  A mismatch indicates
            // a misrouted message or an unauthorized node attempting to
            // import devices it does not own.
            if let Some(actual_peer) = peer_node_id {
                if actual_peer != req.target_node_id {
                    eprintln!(
                        "[storage-node] session {session_id}: import request node mismatch:                          peer={actual_peer} != target={}",
                        req.target_node_id
                    );
                    return Some(ClusterPoolMessage::ImportResponse(
                        ClusterPoolImportResponse {
                            request_id: req.request_id,
                            node_id: req.target_node_id,
                            pool_guid: req.pool_guid,
                            success: false,
                            committed_root_epoch: None,
                            intent_log_replayed: None,
                            error: Some(format!(
                                "node mismatch: authenticated peer {actual_peer} != target {}",
                                req.target_node_id
                            )),
                        },
                    ));
                }
            }

            // ── Lease/fence verification ─────────────────────────
            // When a FenceValidator is active (cluster lease runtime
            // configured), the importing node must hold a valid write
            // fence.  Absence of an active fence means no cluster
            // lease has been acquired, so clustered import is refused.
            if let Some(ref validator) = ctx.fence_validator {
                if validator.active_fence().is_none() {
                    eprintln!(
                        "[storage-node] session {session_id}: import refused:                          no active write fence (cluster lease not held)"
                    );
                    return Some(ClusterPoolMessage::ImportResponse(
                        ClusterPoolImportResponse {
                            request_id: req.request_id,
                            node_id: req.target_node_id,
                            pool_guid: req.pool_guid,
                            success: false,
                            committed_root_epoch: None,
                            intent_log_replayed: None,
                            error: Some(
                                "cluster lease not held; acquire a pool lease before import"
                                    .to_string(),
                            ),
                        },
                    ));
                }
            }
            let device_paths: Vec<std::path::PathBuf> = req
                .device_paths
                .iter()
                .map(|p| std::path::PathBuf::from(p))
                .collect();
            let lock_dir = ctx
                .config
                .pool_lock_dir
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp/tidefs-import-locks"));
            let (success, committed_root_epoch, intent_log_replayed, error) =
                match pool_import(&device_paths, &lock_dir, req.read_only, None, None) {
                    Ok(imported) => (true, imported.stats.committed_root_epoch, Some(0), None),
                    Err(e) => (false, None, None, Some(format!("{e:?}"))),
                };
            Some(ClusterPoolMessage::ImportResponse(
                ClusterPoolImportResponse {
                    request_id: req.request_id,
                    node_id: req.target_node_id,
                    pool_guid: req.pool_guid,
                    success,
                    committed_root_epoch,
                    intent_log_replayed,
                    error,
                },
            ))
        }
        ClusterPoolMessage::LeaseRequest(req) => {
            eprintln!(
                "[storage-node] session {session_id}: cluster pool lease request pool_guid={:02x?} requesting_node={}",
                &req.pool_guid[..4], req.requesting_node_id
            );

            if let Err(fence_err) = check_partition_fence(ctx) {
                eprintln!("[storage-node] session {session_id}: lease refused: {fence_err}");
                return Some(ClusterPoolMessage::LeaseResponse(
                    ClusterPoolLeaseResponse {
                        request_id: req.request_id,
                        node_id: req.requesting_node_id,
                        pool_guid: req.pool_guid,
                        success: false,
                        lease_token_bytes: None,
                        lease_expiration_ms: None,
                        error: Some(fence_err),
                    },
                ));
            }

            let (success, lease_token_bytes, lease_expiration_ms, error) =
                if let Some(ref lease_rt) = ctx.lease_runtime {
                    let mut rt = lease_rt.lock().unwrap();
                    match rt.try_get_pool_lease_token(req.pool_guid) {
                        Some(token) => {
                            if token.authorizes_pool(&req.pool_guid) {
                                let token_bytes = bincode::serialize(&token).unwrap_or_default();
                                // Track this remote client in the active-client mode tracker.
                                // Derive a dataset_id from the pool_guid for per-pool tracking.
                                let dataset_id = u64::from_le_bytes([
                                    req.pool_guid[0],
                                    req.pool_guid[1],
                                    req.pool_guid[2],
                                    req.pool_guid[3],
                                    req.pool_guid[4],
                                    req.pool_guid[5],
                                    req.pool_guid[6],
                                    req.pool_guid[7],
                                ]);
                                let _ =
                                    rt.remote_client_mounted(dataset_id, req.requesting_node_id);
                                (
                                    true,
                                    Some(token_bytes),
                                    Some(token.expiration_deadline_ms),
                                    None,
                                )
                            } else {
                                (
                                    false,
                                    None,
                                    None,
                                    Some("lease token pool GUID mismatch".to_string()),
                                )
                            }
                        }
                        None => (
                            false,
                            None,
                            None,
                            Some(
                                "no active lease for this pool; acquire cluster membership first"
                                    .to_string(),
                            ),
                        ),
                    }
                } else {
                    (
                        false,
                        None,
                        None,
                        Some("cluster lease runtime not configured on this node".to_string()),
                    )
                };

            Some(ClusterPoolMessage::LeaseResponse(
                ClusterPoolLeaseResponse {
                    request_id: req.request_id,
                    node_id: req.requesting_node_id,
                    pool_guid: req.pool_guid,
                    success,
                    lease_token_bytes,
                    lease_expiration_ms,
                    error,
                },
            ))
        }
        ClusterPoolMessage::CatalogDeltaRequest(req) => {
            eprintln!(
                "[storage-node] session {session_id}: catalog delta request pool_guid={:02x?} requesting_node={}",
                &req.pool_guid[..4], req.requesting_node_id
            );

            if let Err(fence_err) = check_partition_fence(ctx) {
                eprintln!(
                    "[storage-node] session {session_id}: catalog delta refused: {fence_err}"
                );
                return Some(ClusterPoolMessage::CatalogDeltaResponse(
                    ClusterPoolCatalogDeltaResponse {
                        request_id: req.request_id,
                        node_id: req.requesting_node_id,
                        pool_guid: req.pool_guid,
                        success: false,
                        catalog_version: None,
                        error: Some(fence_err),
                    },
                ));
            }

            let (success, catalog_version, error) = if let Some(ref lease_rt) = ctx.lease_runtime {
                let mut rt = lease_rt.lock().unwrap();
                match rt.apply_committed_catalog_delta(&req.delta_bytes) {
                    Some(Ok(version)) => (true, Some(version), None),
                    Some(Err(e)) => (false, None, Some(format!("{e}"))),
                    None => (
                        false,
                        None,
                        Some("no pool catalog configured on this node".to_string()),
                    ),
                }
            } else {
                (
                    false,
                    None,
                    Some("cluster lease runtime not configured on this node".to_string()),
                )
            };

            Some(ClusterPoolMessage::CatalogDeltaResponse(
                ClusterPoolCatalogDeltaResponse {
                    request_id: req.request_id,
                    node_id: req.requesting_node_id,
                    pool_guid: req.pool_guid,
                    success,
                    catalog_version,
                    error,
                },
            ))
        }

        ClusterPoolMessage::CatalogQueryRequest(req) => {
            eprintln!(
                "[storage-node] session {session_id}: catalog query request pool_guid={:02x?} requesting_node={} query_type={}",
                &req.pool_guid[..4], req.requesting_node_id, req.query_type_u8
            );

            let (success, entries, catalog_version, error) =
                if let Some(ref lease_rt) = ctx.lease_runtime {
                    let rt = lease_rt.lock().unwrap();
                    match rt.pool_catalog() {
                        Some(pool_cat) => {
                            let entries: Vec<CatalogEntryRow> = pool_cat
                                .catalog()
                                .catalog()
                                .list_all()
                                .into_iter()
                                .map(|(path, id, dtype, txg, flags, lc_state)| CatalogEntryRow {
                                    path,
                                    dataset_id_bytes: id.as_bytes().to_vec(),
                                    dataset_type_u8: dtype.to_u8(),
                                    creation_txg: txg,
                                    lifecycle_state_u8: lc_state.to_u8(),
                                    flags_u16: flags.bits(),
                                })
                                .collect();
                            let version = pool_cat.version();
                            (true, entries, version, None)
                        }
                        None => (
                            false,
                            vec![],
                            0,
                            Some("no pool catalog configured on this node".to_string()),
                        ),
                    }
                } else {
                    (
                        false,
                        vec![],
                        0,
                        Some("cluster lease runtime not configured on this node".to_string()),
                    )
                };

            Some(ClusterPoolMessage::CatalogQueryResponse(
                ClusterPoolCatalogQueryResponse {
                    request_id: req.request_id,
                    node_id: req.requesting_node_id,
                    pool_guid: req.pool_guid,
                    success,
                    entries,
                    catalog_version,
                    error,
                },
            ))
        }

        ClusterPoolMessage::CreateResponse(_)
        | ClusterPoolMessage::ImportResponse(_)
        | ClusterPoolMessage::LeaseResponse(_)
        | ClusterPoolMessage::CatalogDeltaResponse(_)
        | ClusterPoolMessage::CatalogQueryResponse(_) => {
            eprintln!(
                "[storage-node] session {session_id}: unexpected cluster pool response; ignoring"
            );
            None
        }
    }
}

/// Drain pending peer evictions and close the associated transport
/// sessions. Called from `serve_session` after tick_membership.
fn process_evictions(ctx: &SessionContext) {
    let mut pending = ctx.pending_evictions.lock().unwrap();
    let drained: Vec<(SocketAddr, EvictionAction)> = std::mem::take(&mut *pending);
    drop(pending);
    for (addr, action) in &drained {
        let reason = match action {
            EvictionAction::Close => SessionCloseReason::PeerRemoved,
            EvictionAction::Drain => SessionCloseReason::LocalShutdown,
        };
        let mut t = ctx.transport.lock().unwrap();
        match t.close_session_by_addr(*addr, reason) {
            Ok(()) => {
                eprintln!("[storage-node] evicted peer session at {addr}: {action:?}");
            }
            Err(e) => {
                eprintln!("[storage-node] eviction close for {addr} failed: {e:?}");
            }
        }
    }
}

fn recv_session_frame_unlocked(
    ctx: &SessionContext,
    session_id: tidefs_transport::SessionId,
) -> Result<Vec<u8>, TransportError> {
    loop {
        let mut conn = {
            let mut t = ctx.transport.lock().unwrap();
            t.active_connections.remove(&session_id).ok_or_else(|| {
                TransportError::Generic(format!("no active connection for session {session_id}"))
            })?
        };

        let raw_frame = conn.read_frame();

        let mut t = ctx.transport.lock().unwrap();
        t.active_connections.insert(session_id, conn);
        let raw_frame = raw_frame?;

        if let Some(payload) = t.decode_received_frame(session_id, raw_frame)? {
            return Ok(payload);
        }
    }
}

fn is_accept_poll(error: &TransportError) -> bool {
    match error {
        TransportError::WouldBlock(_) => true,
        TransportError::Generic(msg) => msg.contains("no pending connections"),
        _ => false,
    }
}

fn is_optional_accept_poll(error: &TransportError) -> bool {
    match error {
        TransportError::Generic(msg) if msg.contains("listener not bound") => true,
        _ => is_accept_poll(error),
    }
}

fn is_read_poll(error: &TransportError) -> bool {
    match error {
        TransportError::WouldBlock(_) => true,
        TransportError::Generic(msg) => {
            msg.contains("WouldBlock")
                || msg.contains("Resource temporarily unavailable")
                || msg.contains("os error 11")
        }
        _ => false,
    }
}

/// Record a placement version change when a peer disconnects.
/// Bumps the placement version tracker so membership views reflect
/// the updated peer set for rebalance consistency.
fn placement_version_bump_on_disconnect(tracker: &PlacementVersionTracker, node_id: u64) {
    let next_version = tracker.current_version().saturating_add(1);
    tracker.update(next_version);
    eprintln!(
        "[storage-node] placement version bumped to {next_version} after peer {node_id} disconnect"
    );
}

/// Record a placement version change when a peer reconnects.
fn placement_version_bump_on_reconnect(tracker: &PlacementVersionTracker, node_id: u64) {
    let next_version = tracker.current_version().saturating_add(1);
    tracker.update(next_version);
    eprintln!(
        "[storage-node] placement version bumped to {next_version} after peer {node_id} reconnect"
    );
}

impl StorageNode {
    /// Run the accept loop: continuously accept and serve clients.
    pub fn run(&mut self) -> Result<(), String> {
        eprintln!(
            "[storage-node] listening on {}, node_id={}",
            self.config.bind_addr, self.config.node_id
        );
        while !self.stop.load(Ordering::Relaxed) {
            match self.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !self.stop.load(Ordering::Relaxed) {
                        eprintln!("[storage-node] session error: {e}");
                    }
                }
            }
        }
        // Release the cluster lease and clear the write fence before exit.
        // This prevents split-brain writes from a zombie node and allows
        // another cluster member to immediately acquire the pool lease.
        if let Some(ref rt) = self.cluster_lease_runtime {
            let _ = rt.lock().unwrap().release_lease(0); // lease_authority_peer=0 for local-only release
            eprintln!(
                "[storage-node] cluster lease released for node {}",
                self.config.node_id,
            );
        }

        eprintln!("[storage-node] graceful shutdown complete");
        Ok(())
    }

    /// Signal the daemon to stop accepting new connections.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Run the staged node-join protocol, advancing through ShadowOnly → VoterSpread → ReplicaTarget.
    /// This is called after startup to onboard this node into the cluster.
    pub fn begin_join_protocol(&mut self) {
        self.join_pipeline.begin_discovery();
        eprintln!(
            "[storage-node] node-join protocol started: phase={:?}",
            self.join_pipeline.phase
        );
    }

    /// Return the current join phase from the pipeline.
    pub fn join_phase(&self) -> JoinPipelinePhase {
        self.join_pipeline.phase
    }

    /// Write the ready-marker file if configured, signaling to operators/harnesses
    /// that the daemon has completed startup.
    pub fn write_ready_marker(&self) {
        if let Some(ref ready_path) = self.config.ready_file {
            match std::fs::write(ready_path, b"ready\n") {
                Ok(()) => {
                    eprintln!(
                        "[storage-node] ready marker written: {}",
                        ready_path.display()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[storage-node] failed to write ready marker {}: {e}",
                        ready_path.display()
                    );
                }
            }
        }
    }

    /// Initiate graceful node drain, then shutdown.
    ///
    /// When membership peers are configured, the daemon transitions through the
    /// node-drain stages (leases → data → cache → admin → done) before stopping.
    /// Falls back to immediate shutdown when no membership is active or drain
    /// is not supported on this platform.
    /// Initiate graceful shutdown with node-drain intent.
    ///
    /// When membership peers are configured, the daemon signals its intent to
    /// drain before stopping. The full drain pipeline (leases → data → cache →
    /// admin → done) is driven by the []
    /// orchestrator with trait implementations provided by the caller.
    /// For the daemon, the drain is initiated externally via operator command
    /// before SIGTERM; here we log and proceed to immediate shutdown.
    pub fn shutdown_with_drain(&mut self) {
        if self.membership_transport.is_some() || !self.config.membership_peers.is_empty() {
            eprintln!(
                "[storage-node] drain intent signaled for node {} (timeout={}s).",
                self.config.node_id, self.config.drain_timeout_secs
            );
            eprintln!(
                "[storage-node] run 'tidefsctl drain --node {}' before shutdown for graceful drain.",
                self.config.node_id
            );
        } else {
            eprintln!("[storage-node] no membership peers configured, skipping drain");
        }

        self.shutdown();
    }

    /// Return a clone of the stop flag for use by signal handlers.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Returns the runtime authority spine, if constructed.
    #[must_use]
    pub fn authority(&self) -> Option<&RuntimeAuthority> {
        self.authority.as_ref()
    }
}
// ── Frame handler: client-facing public API ──────────────────
// Client Frame operations route through the full replication
// authority (put_named / get_named / delete_named) for fan-out
// to remote replicas when the backend is TransportBacked.
// Never use *_local methods here — those are for peer
// ReplicationMessage receive only (see serve_session).

/// Frame-protocol handler for session handler threads. Uses SessionContext
/// can access shared state without holding `&mut self` on the node.
fn handle_frame_ctx(
    session_id: tidefs_transport::SessionId,
    frame: &Frame,
    store: &Arc<Mutex<StoreBackend>>,
    ctx: &SessionContext,
) -> Option<Frame> {
    match frame {
        Frame::Put { key, value } => {
            let mut s = store.lock().unwrap();
            let result = match &mut *s {
                StoreBackend::Local(rs) => rs
                    .put_named(key, value)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                StoreBackend::TransportBacked(ts) => ts.put_named(key, value).and_then(|outcome| {
                    if outcome.quorum_reached {
                        Ok(())
                    } else {
                        Err(format!(
                            "write quorum not reached: {}/{} acknowledgements (need {})",
                            outcome.acks, outcome.total_targets, outcome.quorum_size
                        ))
                    }
                }),
                StoreBackend::PoolBacked(pool) => pool_put_named(pool, key, value),
            };
            match result {
                Ok(()) => Some(Frame::Ok),
                Err(e) => Some(Frame::Error { message: e }),
            }
        }
        Frame::Get { key } => {
            let mut s = store.lock().unwrap();
            let result = match &mut *s {
                StoreBackend::Local(rs) => rs.get_named(key).map_err(|e| e.to_string()),
                StoreBackend::TransportBacked(ts) => ts.get_named(key),
                StoreBackend::PoolBacked(pool) => pool_get_named(pool, key),
            };
            match result {
                Ok(Some(value)) => Some(Frame::GetResponse { value }),
                Ok(None) => Some(Frame::Error {
                    message: "not found".into(),
                }),
                Err(e) => Some(Frame::Error { message: e }),
            }
        }
        Frame::Delete { key } => {
            let mut s = store.lock().unwrap();
            let result = match &mut *s {
                StoreBackend::Local(rs) => rs.delete_named(key).map_err(|e| e.to_string()),
                StoreBackend::TransportBacked(ts) => ts.delete_named(key),
                StoreBackend::PoolBacked(pool) => pool_delete_named(pool, key),
            };
            match result {
                Ok(existed) => Some(Frame::DeleteResponse { existed }),
                Err(e) => Some(Frame::Error { message: e }),
            }
        }
        Frame::List => {
            let s = store.lock().unwrap();
            let keys: Vec<Vec<u8>> = match &*s {
                StoreBackend::Local(rs) => match rs.list_keys() {
                    Ok(keys) => keys.into_iter().map(|k| k.as_bytes32().to_vec()).collect(),
                    Err(e) => return Some(Frame::Error { message: e }),
                },
                StoreBackend::TransportBacked(ts) => ts
                    .list_keys_local()
                    .into_iter()
                    .map(|k| k.as_bytes32().to_vec())
                    .collect(),
                StoreBackend::PoolBacked(pool) => match pool_list_logical_keys(pool) {
                    Ok(keys) => keys.into_iter().map(|k| k.as_bytes32().to_vec()).collect(),
                    Err(e) => return Some(Frame::Error { message: e }),
                },
            };
            Some(Frame::ListResponse { keys })
        }
        Frame::Stats => {
            let s = store.lock().unwrap();
            let backend_disclosure = ctx
                .authority
                .as_ref()
                .map(|a| format!("{}", a.backend()))
                .unwrap_or_else(|| "not-run".to_string());
            let json = match &*s {
                StoreBackend::Local(rs) => {
                    let stats = rs.stats();
                    serde_json::json!({
                        "backend": backend_disclosure,
                        "object_count": stats.object_count,
                        "committed_writes": stats.committed_writes,
                        "degraded_writes": stats.degraded_writes,
                        "refused_writes": stats.refused_writes,
                        "bytes_written": stats.bytes_written,
                        "replica_healthy": stats.replica_healthy,
                    })
                }
                StoreBackend::TransportBacked(ts) => {
                    let stats = ts.stats();
                    serde_json::json!({
                        "backend": backend_disclosure,
                        "object_count": stats.object_count,
                        "committed_writes": stats.committed_writes,
                        "degraded_writes": stats.degraded_writes,
                        "failed_writes": stats.failed_writes,
                        "degraded_reads": stats.degraded_reads,
                        "bytes_written": stats.bytes_written,
                    })
                }
                StoreBackend::PoolBacked(pool) => {
                    let stats = pool.pool_stats();
                    let op_stats = pool.stats();
                    let placement_receipt_ref_count = pool
                        .placement_receipt_refs(ObjectIoClass::Data)
                        .map(|refs| refs.len())
                        .unwrap_or(0);
                    serde_json::json!({
                        "backend": "pool",
                        "object_count": stats.object_count,
                        "total_capacity_bytes": stats.total_capacity_bytes,
                        "used_bytes": stats.used_bytes,
                        "available_bytes": stats.available_bytes,
                        "bytes_written": op_stats.total_bytes,
                        "placement_receipt_ref_count": placement_receipt_ref_count,
                    })
                }
            };
            Some(Frame::StatsResponse {
                json: json.to_string(),
            })
        }
        Frame::Bye => Some(Frame::Bye),
        Frame::HealthCheck => {
            let node_identity = ctx
                .config
                .node_identity
                .clone()
                .unwrap_or_else(|| format!("node-{}", ctx.config.node_id));
            let pool_state = match &ctx.imported_pool {
                Some(pool) => {
                    if pool.config.health.is_operational() {
                        "imported".to_string()
                    } else {
                        "degraded".to_string()
                    }
                }
                None => "not-imported".to_string(),
            };
            let uptime_secs = ctx.start_time.elapsed().as_secs();
            let backend = ctx
                .authority
                .as_ref()
                .map(|a| format!("{}", a.backend()))
                .unwrap_or_else(|| "not-run".to_string());

            // Build multi-node operator health and topology report (MN-028).
            // Uses the membership runtime's failure detector for per-peer liveness,
            // the roster for topology/carrier state, placement version, and the
            // authority spine for node-level carrier/placement metadata.
            let carrier = ctx
                .authority
                .as_ref()
                .map(|a| a.backend().name())
                .unwrap_or("not-run");
            let carrier_is_live = ctx.authority.as_ref().map(|a| a.is_live()).unwrap_or(false);
            let node_id = ctx
                .authority
                .as_ref()
                .map(|a| a.node_id())
                .unwrap_or(ctx.config.node_id);
            let node_member_class = ctx
                .authority
                .as_ref()
                .and_then(|a| a.member_class())
                .map(|mc| format!("{mc:?}"));
            let node_failure_domain = ctx.authority.as_ref().and_then(|a| a.failure_domain());
            let replication_factor = ctx
                .authority
                .as_ref()
                .map(|a| a.replication_factor())
                .unwrap_or(0);
            // Collect per-session transport backend info for operator
            // observability. This closes the "silent TCP fallback" gap (B9):
            // even when --rdma is requested, the actual negotiated backend
            // per connected peer is disclosed here.
            let transport_backends: Vec<serde_json::Value> = {
                let t = ctx.transport.lock().unwrap();
                let mut backends = Vec::new();
                for sid in t.sessions.keys() {
                    if let Some(backend_kind) = t.session_backend_kind(*sid) {
                        let peer = t.peer_node(*sid);
                        let disclosure = peer.and_then(|p| t.carrier_disclosure(p).cloned());
                        backends.push(serde_json::json!({
                            "session_id": sid.0,
                            "peer_node": peer,
                            "backend_kind": backend_kind.to_string(),
                            "disclosure": disclosure.map(|d| d.to_string()),
                        }));
                    }
                }
                backends
            };

            let report_json = {
                let membership = ctx.membership.lock().unwrap();
                let detector = &membership.detector;
                let placement_version = membership.placement_version();
                let peers: Vec<serde_json::Value> = detector
                    .all_peers()
                    .map(|p| {
                        serde_json::json!({
                            "member_id": p.member_id.0,
                            "member_class": format!("{:?}", p.member_class),
                            "health": format!("{:?}", p.health),
                            "failure_domain": p.failure_domain,
                            "failed_pings": p.failed_ping_count,
                            "joining": p.joining,
                            "draining": p.draining,
                            "epoch": p.epoch.0,
                        })
                    })
                    .collect();
                let alive_voters: Vec<u64> =
                    detector.alive_voters().into_iter().map(|m| m.0).collect();
                let degraded_peers: Vec<serde_json::Value> = detector
                    .all_peers()
                    .filter(|p| {
                        matches!(
                            p.health,
                            tidefs_membership_epoch::HealthClass::Suspect
                                | tidefs_membership_epoch::HealthClass::Down
                        )
                    })
                    .map(|p| {
                        serde_json::json!({
                            "member_id": p.member_id.0,
                            "health": format!("{:?}", p.health),
                            "failed_pings": p.failed_ping_count,
                        })
                    })
                    .collect();
                let health_counts = {
                    let mut healthy = 0u64;
                    let mut suspect = 0u64;
                    let mut down = 0u64;
                    for p in detector.all_peers() {
                        match p.health {
                            tidefs_membership_epoch::HealthClass::Healthy => healthy += 1,
                            tidefs_membership_epoch::HealthClass::Suspect => suspect += 1,
                            tidefs_membership_epoch::HealthClass::Down => down += 1,
                        }
                    }
                    serde_json::json!({
                        "healthy": healthy,
                        "suspect": suspect,
                        "down": down,
                    })
                };
                let failure_domains: Vec<serde_json::Value> = {
                    let mut domains: std::collections::BTreeMap<u64, Vec<u64>> =
                        std::collections::BTreeMap::new();
                    for p in detector.all_peers() {
                        domains
                            .entry(p.failure_domain)
                            .or_default()
                            .push(p.member_id.0);
                    }
                    domains
                        .into_iter()
                        .map(|(fd, members)| {
                            serde_json::json!({
                                "failure_domain": fd,
                                "member_count": members.len(),
                                "members": members,
                            })
                        })
                        .collect()
                };
                let quorum_lost = detector.quorum_lost();
                // Roster state snapshot: count members in each lifecycle state.
                let roster_snapshot = membership.roster.snapshot();
                let mut roster_active = 0u64;
                let mut roster_suspected = 0u64;
                let mut roster_failed = 0u64;
                let mut roster_left = 0u64;
                for (_, state) in roster_snapshot.iter() {
                    match state {
                        tidefs_membership_live::roster::RosterState::Active => roster_active += 1,
                        tidefs_membership_live::roster::RosterState::Suspected => {
                            roster_suspected += 1
                        }
                        tidefs_membership_live::roster::RosterState::Failed => roster_failed += 1,
                        tidefs_membership_live::roster::RosterState::Left => roster_left += 1,
                    }
                }
                serde_json::json!({
                    "node_id": node_id,
                    "node_member_class": node_member_class,
                    "node_failure_domain": node_failure_domain,
                    "carrier": carrier,
                    "carrier_is_live": carrier_is_live,
                    "replication_factor": replication_factor,
                    "placement_version": placement_version,
                    "peers": peers,
                    "peer_count": detector.peer_count(),
                    "alive_voters": alive_voters,
                    "quorum_lost": quorum_lost,
                    "roster_size": roster_snapshot.len(),
                    "roster_state_summary": {
                        "active": roster_active,
                        "suspected": roster_suspected,
                        "failed": roster_failed,
                        "left": roster_left,
                    },
                    "health_summary": health_counts,
                    "degraded_peers": degraded_peers,
                    "failure_domains": failure_domains,
                    "transport_backends": transport_backends,
                })
                .to_string()
            };

            Some(Frame::HealthCheckResponse {
                node_identity,
                pool_state,
                uptime_secs,
                backend,
                report_json,
            })
        }
        Frame::Send { key } => {
            let fs_root = ctx.config.fs_root.as_ref()?;
            let auth_key = ctx.config.root_auth_key?;
            let mut fs = match vfs::LocalFileSystem::open_with_root_authentication_key(
                fs_root,
                StoreOptions::default(),
                auth_key,
            ) {
                Ok(fs) => fs,
                Err(e) => {
                    return Some(Frame::Error {
                        message: format!("open fs for send: {e}"),
                    })
                }
            };
            if key.is_empty() {
                match fs.export_changed_records() {
                    Ok(export) => Some(Frame::SendResponse {
                        export: export.encode(),
                    }),
                    Err(e) => Some(Frame::Error {
                        message: format!("export: {e}"),
                    }),
                }
            } else if key.len() == 24 {
                let tid = u64::from_le_bytes(key[0..8].try_into().unwrap());
                let gen = u64::from_le_bytes(key[8..16].try_into().unwrap());
                let csum = u64::from_le_bytes(key[16..24].try_into().unwrap());
                let audit = match vfs::audit_recovery_with_root_authentication_key(
                    fs_root,
                    StoreOptions::default(),
                    auth_key,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        return Some(Frame::Error {
                            message: format!("audit: {e}"),
                        })
                    }
                };
                let from_root = match audit.valid_committed_roots.iter().find(|r| {
                    r.transaction_id == tid
                        && r.generation == gen
                        && r.superblock_checksum.0 == csum
                }) {
                    Some(r) => r.clone(),
                    None => {
                        return Some(Frame::Error {
                            message: format!(
                                "from_root not found: tid={tid} gen={gen} csum={csum:#016x}"
                            ),
                        })
                    }
                };
                match fs.export_incremental_changed_records(&from_root) {
                    Ok(export) => Some(Frame::SendResponse {
                        export: export.encode(),
                    }),
                    Err(e) => Some(Frame::Error {
                        message: format!("incremental export: {e}"),
                    }),
                }
            } else {
                Some(Frame::Error {
                    message: format!("send key must be 0 or 24 bytes, got {}", key.len()),
                })
            }
        }
        Frame::Receive {
            export,
            root_authentication_key,
        } => {
            let fs_root = ctx.config.fs_root.as_ref()?;
            if root_authentication_key.len() != 32 {
                return Some(Frame::Error {
                    message: format!(
                        "root auth key must be 32 bytes, got {}",
                        root_authentication_key.len()
                    ),
                });
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(root_authentication_key);
            let auth_key = RootAuthenticationKey::from_bytes32(key_bytes);
            let decoded = match ChangedRecordExport::decode(export) {
                Ok(d) => d,
                Err(e) => {
                    return Some(Frame::Error {
                        message: format!("decode export: {e}"),
                    })
                }
            };
            let report = if decoded.incremental {
                vfs::LocalFileSystem::receive_incremental_changed_records_with_root_authentication_key(
                    fs_root, StoreOptions::default(), &decoded, auth_key,
                )
            } else {
                vfs::LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
                    fs_root, StoreOptions::default(), &decoded, auth_key,
                )
            };
            match report {
                Ok(r) => {
                    let json = serde_json::json!({
                        "spec": r.spec,
                        "imported_roots": r.imported_roots,
                        "imported_records": r.imported_records,
                        "imported_payload_bytes": r.imported_payload_bytes,
                        "selected_generation": r.selected_generation,
                        "selected_transaction_id": r.selected_transaction_id,
                        "snapshot_catalog_entries": r.snapshot_catalog_entries,
                        "stream_version": r.stream_version,
                        "staging_validated_before_publish": r.staging_validated_before_publish,
                        "destination_root_reauthentication": r.destination_root_reauthentication,
                        "production_fsck_required": r.production_fsck_required,
                    });
                    Some(Frame::ReceiveResponse {
                        report_json: json.to_string(),
                    })
                }
                Err(e) => Some(Frame::Error {
                    message: format!("receive: {e}"),
                }),
            }
        }
        Frame::SnapshotBarrier {
            barrier_id,
            snapshot_name,
        } => {
            let _snap_name = snapshot_name.clone();
            let mut s = store.lock().unwrap();
            let (committed_root_txg, committed_root_generation, object_count) = match &mut *s {
                StoreBackend::Local(rs) => {
                    let _ = rs.sync_all();
                    let txg = rs.committed_root_txg();
                    let gen = rs.committed_root_generation();
                    let count = rs.stats().object_count;
                    (txg, gen, count)
                }
                StoreBackend::TransportBacked(ts) => {
                    let _ = ts.sync_all();
                    let txg = ts.committed_root_txg();
                    let gen = ts.committed_root_generation();
                    let count = ts.stats().object_count;
                    (txg, gen, count)
                }
                StoreBackend::PoolBacked(pool) => {
                    let _ = pool.sync_all();
                    let count = pool.pool_stats().object_count;
                    (0, 0, count)
                }
            };
            Some(Frame::SnapshotBarrierResponse {
                barrier_id: *barrier_id,
                committed_root_txg,
                committed_root_generation,
                object_count,
            })
        }
        // ── Multi-node scrub fanout ──
        Frame::ScrubRequest => {
            let s = store.lock().unwrap();
            let (report_json, findings_count) = local_scrub_report_json(&ctx.config, &s);
            eprintln!(
                "[storage-node] session {session_id}: scrub request completed findings_count={findings_count}"
            );
            Some(Frame::ScrubResponse {
                report_json,
                findings_count,
            })
        }
        Frame::RepairObject {
            key,
            placement_receipt_ref,
            authoritative_payload,
        } => {
            let mut s = store.lock().unwrap();
            let object_key = match exact_repair_object_key(key) {
                Ok(object_key) => object_key,
                Err(message) => return Some(Frame::Error { message }),
            };
            let result = apply_receipt_bound_key_repair(
                &mut *s,
                object_key,
                authoritative_payload,
                *placement_receipt_ref,
            );
            let repaired_placement_receipt_ref = match result {
                Ok(repaired_placement_receipt_ref) => repaired_placement_receipt_ref,
                Err(message) => return Some(Frame::Error { message }),
            };
            let success = true;
            eprintln!(
                "[storage-node] session {session_id}: repair object key={} success={success}",
                String::from_utf8_lossy(key)
            );
            Some(Frame::RepairObjectAck {
                key: key.clone(),
                success,
                repaired_placement_receipt_ref,
            })
        }
        // ── Snapshot lifecycle operations (clustered dataset path) ──
        Frame::SnapshotCreate { snapshot_name } => {
            let fs_root = ctx.config.fs_root.as_ref()?;
            let auth_key = ctx.config.root_auth_key?;
            let mut fs = match vfs::LocalFileSystem::open_with_root_authentication_key(
                fs_root,
                StoreOptions::default(),
                auth_key,
            ) {
                Ok(fs) => fs,
                Err(e) => {
                    return Some(Frame::Error {
                        message: format!("open fs for snapshot create: {e}"),
                    })
                }
            };
            match fs.create_snapshot(snapshot_name) {
                Ok(summary) => {
                    let json = serde_json::json!({
                        "name": summary.name,
                        "source_transaction_id": summary.source_transaction_id,
                        "source_generation": summary.source_generation,
                        "created_at_generation": summary.created_at_generation,
                    });
                    Some(Frame::SnapshotCreateResponse {
                        summary_json: json.to_string(),
                    })
                }
                Err(e) => Some(Frame::Error {
                    message: format!("create snapshot: {e}"),
                }),
            }
        }
        Frame::SnapshotDestroy { snapshot_name } => {
            let fs_root = ctx.config.fs_root.as_ref()?;
            let auth_key = ctx.config.root_auth_key?;
            let mut fs = match vfs::LocalFileSystem::open_with_root_authentication_key(
                fs_root,
                StoreOptions::default(),
                auth_key,
            ) {
                Ok(fs) => fs,
                Err(e) => {
                    return Some(Frame::Error {
                        message: format!("open fs for snapshot destroy: {e}"),
                    })
                }
            };
            match fs.delete_snapshot(snapshot_name) {
                Ok(summary) => {
                    let json = serde_json::json!({
                        "name": summary.name,
                        "source_transaction_id": summary.source_transaction_id,
                        "source_generation": summary.source_generation,
                        "created_at_generation": summary.created_at_generation,
                    });
                    Some(Frame::SnapshotDestroyResponse {
                        summary_json: json.to_string(),
                    })
                }
                Err(e) => Some(Frame::Error {
                    message: format!("destroy snapshot: {e}"),
                }),
            }
        }
        Frame::SnapshotRollback { snapshot_name } => {
            let fs_root = ctx.config.fs_root.as_ref()?;
            let auth_key = ctx.config.root_auth_key?;
            let mut fs = match vfs::LocalFileSystem::open_with_root_authentication_key(
                fs_root,
                StoreOptions::default(),
                auth_key,
            ) {
                Ok(fs) => fs,
                Err(e) => {
                    return Some(Frame::Error {
                        message: format!("open fs for snapshot rollback: {e}"),
                    })
                }
            };
            match fs.rollback_to_snapshot(snapshot_name) {
                Ok(report) => {
                    let json = serde_json::json!({
                        "spec": report.spec,
                        "snapshot": {
                            "name": report.snapshot.name,
                            "source_transaction_id": report.snapshot.source_transaction_id,
                            "source_generation": report.snapshot.source_generation,
                            "created_at_generation": report.snapshot.created_at_generation,
                        },
                        "generation_before": report.generation_before,
                        "restored_source_generation": report.restored_source_generation,
                        "published_generation": report.published_generation,
                        "snapshot_catalog_entries": report.snapshot_catalog_entries,
                        "production_fsck_required": report.production_fsck_required,
                    });
                    Some(Frame::SnapshotRollbackResponse {
                        report_json: json.to_string(),
                    })
                }
                Err(e) => Some(Frame::Error {
                    message: format!("rollback to snapshot: {e}"),
                }),
            }
        }
        // ── Snapshot clone operation ──
        // ── Chunked send/receive with cursor-based resume ──
        Frame::SendChunked { key } => {
            let fs_root = ctx.config.fs_root.as_ref()?;
            let auth_key = ctx.config.root_auth_key?;
            let mut fs = match vfs::LocalFileSystem::open_with_root_authentication_key(
                fs_root,
                StoreOptions::default(),
                auth_key,
            ) {
                Ok(fs) => fs,
                Err(e) => {
                    return Some(Frame::Error {
                        message: format!("open fs for chunked send: {e}"),
                    })
                }
            };
            let export = if key.is_empty() {
                match fs.export_changed_records() {
                    Ok(e) => e.encode(),
                    Err(e) => {
                        return Some(Frame::Error {
                            message: format!("export: {e}"),
                        })
                    }
                }
            } else if key.len() == 24 {
                let tid = u64::from_le_bytes(key[0..8].try_into().unwrap());
                let gen = u64::from_le_bytes(key[8..16].try_into().unwrap());
                let csum = u64::from_le_bytes(key[16..24].try_into().unwrap());
                let audit = match vfs::audit_recovery_with_root_authentication_key(
                    fs_root,
                    StoreOptions::default(),
                    auth_key,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        return Some(Frame::Error {
                            message: format!("audit: {e}"),
                        })
                    }
                };
                let from_root = match audit.valid_committed_roots.iter().find(|r| {
                    r.transaction_id == tid
                        && r.generation == gen
                        && r.superblock_checksum.0 == csum
                }) {
                    Some(r) => r.clone(),
                    None => {
                        return Some(Frame::Error {
                            message: format!("from_root not found: tid={tid} gen={gen}"),
                        })
                    }
                };
                match fs.export_incremental_changed_records(&from_root) {
                    Ok(e) => e.encode(),
                    Err(e) => {
                        return Some(Frame::Error {
                            message: format!("incremental export: {e}"),
                        })
                    }
                }
            } else {
                return Some(Frame::Error {
                    message: format!("send key must be 0 or 24 bytes, got {}", key.len()),
                });
            };
            let cursor: Vec<u8> = if export.len() >= 8 {
                let mut c = vec![0u8; 16];
                c[0..8].copy_from_slice(&0u64.to_le_bytes());
                c[8..16].copy_from_slice(&export[..8]);
                c
            } else {
                vec![0u8; 16]
            };
            Some(Frame::SendChunkedResponse {
                chunk: export,
                cursor,
                more: false,
            })
        }
        Frame::SendResume { cursor: _cursor } => Some(Frame::Error {
            message:
                "send resume: re-send with incremental key (tid+gen+csum) from last received root"
                    .into(),
        }),

        Frame::SnapshotClone {
            clone_name,
            source_snapshot,
        } => {
            let fs_root = ctx.config.fs_root.as_ref()?;
            let auth_key = ctx.config.root_auth_key?;
            let mut fs = match vfs::LocalFileSystem::open_with_root_authentication_key(
                fs_root,
                StoreOptions::default(),
                auth_key,
            ) {
                Ok(fs) => fs,
                Err(e) => {
                    return Some(Frame::Error {
                        message: format!("open fs for snapshot clone: {e}"),
                    })
                }
            };
            match fs.create_clone(&clone_name, &source_snapshot) {
                Ok(summary) => {
                    let json = serde_json::json!({
                        "name": summary.name,
                        "origin": summary.origin,
                        "source_transaction_id": summary.source_transaction_id,
                        "source_generation": summary.source_generation,
                        "created_at_generation": summary.created_at_generation,
                    });
                    Some(Frame::SnapshotCloneResponse {
                        summary_json: json.to_string(),
                    })
                }
                Err(e) => Some(Frame::Error {
                    message: format!("create clone: {e}"),
                }),
            }
        }
        Frame::Ok
        | Frame::GetResponse { .. }
        | Frame::DeleteResponse { .. }
        | Frame::ListResponse { .. }
        | Frame::StatsResponse { .. }
        | Frame::SendResponse { .. }
        | Frame::ReceiveResponse { .. }
        | Frame::SnapshotBarrierResponse { .. }
        | Frame::HealthCheckResponse { .. }
        | Frame::Error { .. }
        | Frame::ScrubResponse { .. }
        | Frame::RepairObjectAck { .. }
        | Frame::SnapshotCreateResponse { .. }
        | Frame::SnapshotDestroyResponse { .. }
        | Frame::SnapshotRollbackResponse { .. }
        | Frame::SnapshotCloneResponse { .. }
        | Frame::SendChunkedResponse { .. }
        | Frame::SendResumeResponse { .. } => None,
    }
}

/// Segment-fetch handler for session handler threads.
fn handle_segment_fetch_ctx(
    session_id: tidefs_transport::SessionId,
    request: SegmentFetchRequest,
    ctx: &SessionContext,
) -> Result<u64, String> {
    let response = {
        let store_guard = ctx.store.lock().map_err(|e| format!("lock: {e}"))?;
        build_segment_fetch_response(&store_guard, &request)?
    };
    let obj_id = response.object_id;

    let mut t = ctx.transport.lock().map_err(|e| format!("lock: {e}"))?;
    send_segment_fetch_response(&mut t, session_id, &response)
        .map_err(|e| format!("send segment fetch response: {e}"))?;

    Ok(obj_id)
}
impl StorageNode {
    /// Return a clone of the `Arc<Mutex<MembershipRuntime>>` handle,
    /// usable by other daemon subsystems that need the membership view.
    pub fn membership_handle(&self) -> Arc<Mutex<MembershipRuntime>> {
        Arc::clone(&self.membership)
    }

    /// Return a clone of the membership transport handle when configured.
    pub fn membership_transport_handle(&self) -> Option<Arc<Mutex<MembershipTransport>>> {
        self.membership_transport.as_ref().map(Arc::clone)
    }

    /// Return the current membership view snapshot.
    pub fn membership_view(&self) -> MembershipView {
        self.membership.lock().unwrap().view()
    }

    /// Tick the membership runtime to advance failure detection and epoch state.
    pub fn tick_membership(&self) {
        let mut m = self.membership.lock().unwrap();
        if let Some(transport) = &self.membership_transport {
            let mut transport = transport.lock().unwrap();
            let _ = transport.tick_runtime(&mut m);
        } else {
            m.tick();
        }
    }
}

// ---------------------------------------------------------------------------
// Epoch anchor helpers — split-brain prevention
// ---------------------------------------------------------------------------

/// Read the persisted committed-root epoch anchor file.
///
/// Returns `Some(epoch)` if the file exists and contains a valid u64,
/// or `None` if the file is absent or unreadable (first import, no anchor).
fn read_epoch_anchor(path: &std::path::Path) -> Option<u64> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    text.trim().parse::<u64>().ok()
}

/// Persist the committed-root epoch as an anchor for future imports.
///
/// The anchor file records the last known good committed-root epoch so
/// that subsequent pool imports can reject stale roots from partitioned
/// writers (split-brain prevention gate).
fn write_epoch_anchor(path: &std::path::Path, epoch: u64) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, format!("{epoch}\n"));
}

// ---------------------------------------------------------------------------
// VSNP (TideFS Snapshot Network Protocol) handler
// ---------------------------------------------------------------------------

const VSNP_KIND_ERROR: u8 = 0;
const VSNP_KIND_PUSH: u8 = 1;
const VSNP_KIND_PULL_REQUEST: u8 = 2;
const VSNP_KIND_PULL_RESPONSE: u8 = 3;
const VSNP_KIND_ACK: u8 = 4;
const VSNP_KIND_BLOCK_PUSH: u8 = 5;
const VSNP_KIND_BLOCK_PULL_REQUEST: u8 = 6;
const VSNP_KIND_BLOCK_PULL_RESPONSE: u8 = 7;

fn build_vsnp_ack(message: &str) -> Vec<u8> {
    let b = message.as_bytes();
    let mut msg = Vec::with_capacity(4 + 1 + 4 + b.len());
    msg.extend_from_slice(b"VSNP");
    msg.push(VSNP_KIND_ACK);
    msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
    msg.extend_from_slice(b);
    msg
}

fn build_vsnp_block_pull_response(block_data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 1 + 4 + block_data.len());
    msg.extend_from_slice(b"VSNP");
    msg.push(VSNP_KIND_BLOCK_PULL_RESPONSE);
    msg.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
    msg.extend_from_slice(block_data);
    msg
}

fn build_vsnp_error(message: &str) -> Vec<u8> {
    let b = message.as_bytes();
    let mut msg = Vec::with_capacity(4 + 1 + 4 + b.len());
    msg.extend_from_slice(b"VSNP");
    msg.push(VSNP_KIND_ERROR);
    msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
    msg.extend_from_slice(b);
    msg
}

fn build_vsnp_pull_response(export: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 1 + 4 + export.len());
    msg.extend_from_slice(b"VSNP");
    msg.push(VSNP_KIND_PULL_RESPONSE);
    msg.extend_from_slice(&(export.len() as u32).to_le_bytes());
    msg.extend_from_slice(export);
    msg
}

fn handle_vsnp_message(
    session_id: tidefs_transport::SessionId,
    raw: &[u8],
    ctx: &SessionContext,
) -> Result<Option<Vec<u8>>, String> {
    if raw.len() < 5 {
        return Err("VSNP message too short".into());
    }
    let kind = raw[4];

    match kind {
        VSNP_KIND_PUSH => {
            if raw.len() < 9 + 4 {
                return Err("VSNP push: too short for key_len".into());
            }
            let key_len = u32::from_le_bytes(raw[5..9].try_into().unwrap()) as usize;
            if key_len != 32 {
                return Err(format!("VSNP push: expected key_len=32, got {key_len}"));
            }
            if raw.len() < 9 + 32 + 4 {
                return Err("VSNP push: too short for auth key + export_len".into());
            }
            let mut auth_key = [0u8; 32];
            auth_key.copy_from_slice(&raw[9..9 + 32]);
            let export_len = u32::from_le_bytes(raw[9 + 32..13 + 32].try_into().unwrap()) as usize;
            let export_start = 13 + 32;
            if raw.len() < export_start + export_len {
                return Err(format!(
                    "VSNP push: need {} bytes, got {}",
                    export_start + export_len,
                    raw.len()
                ));
            }
            let export_bytes = &raw[export_start..export_start + export_len];
            handle_vsnp_push(session_id, export_bytes, auth_key, ctx)
        }
        VSNP_KIND_PULL_REQUEST => {
            if raw.len() < 9 + 4 {
                return Err("VSNP pull_request: too short".into());
            }
            let key_len = u32::from_le_bytes(raw[5..9].try_into().unwrap()) as usize;
            if key_len != 32 {
                return Err(format!(
                    "VSNP pull_request: expected key_len=32, got {key_len}"
                ));
            }
            if raw.len() < 9 + 32 {
                return Err("VSNP pull_request: too short for auth key".into());
            }
            let mut auth_key = [0u8; 32];
            auth_key.copy_from_slice(&raw[9..9 + 32]);
            handle_vsnp_pull_request(session_id, auth_key, ctx)
        }
        VSNP_KIND_BLOCK_PUSH => {
            // Parse block push: [magic(4)][kind(1)][key_len(4)][key(32)][name_len(4)][name][data_len(4)][data]
            if raw.len() < 9 + 4 {
                return Err("VSNP block_push: too short".into());
            }
            let key_len = u32::from_le_bytes(raw[5..9].try_into().unwrap()) as usize;
            if key_len != 32 {
                return Err(format!("VSNP block_push: key_len={key_len}"));
            }
            if raw.len() < 9 + 32 + 4 {
                return Err("VSNP block_push: too short for name_len".into());
            }
            let mut auth_key = [0u8; 32];
            auth_key.copy_from_slice(&raw[9..9 + 32]);
            let name_len = u32::from_le_bytes(raw[9 + 32..13 + 32].try_into().unwrap()) as usize;
            let name_start = 13 + 32;
            if raw.len() < name_start + name_len + 4 {
                return Err("VSNP block_push: too short for data_len".into());
            }
            let _device_name =
                String::from_utf8_lossy(&raw[name_start..name_start + name_len]).into_owned();
            let data_len = u32::from_le_bytes(
                raw[name_start + name_len..name_start + name_len + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let data_start = name_start + name_len + 4;
            if raw.len() < data_start + data_len {
                return Err(format!(
                    "VSNP block_push: need {} bytes, got {}",
                    data_start + data_len,
                    raw.len()
                ));
            }
            let block_data = &raw[data_start..data_start + data_len];
            handle_vsnp_block_push(session_id, block_data, auth_key, ctx)
        }
        VSNP_KIND_BLOCK_PULL_REQUEST => {
            if raw.len() < 9 + 4 {
                return Err("VSNP block_pull_request: too short".into());
            }
            let key_len = u32::from_le_bytes(raw[5..9].try_into().unwrap()) as usize;
            if key_len != 32 {
                return Err(format!("VSNP block_pull_request: key_len={key_len}"));
            }
            if raw.len() < 9 + 32 + 4 {
                return Err("VSNP block_pull_request: too short for name_len".into());
            }
            let mut auth_key = [0u8; 32];
            auth_key.copy_from_slice(&raw[9..9 + 32]);
            let name_len = u32::from_le_bytes(raw[9 + 32..13 + 32].try_into().unwrap()) as usize;
            let name_start = 13 + 32;
            if raw.len() < name_start + name_len {
                return Err("VSNP block_pull_request: too short".into());
            }
            let _device_name =
                String::from_utf8_lossy(&raw[name_start..name_start + name_len]).into_owned();
            handle_vsnp_block_pull_request(session_id, auth_key, ctx)
        }
        other => Err(format!("unknown VSNP kind: {other}")),
    }
}

fn handle_vsnp_push(
    _session_id: tidefs_transport::SessionId,
    export_bytes: &[u8],
    auth_key_bytes: [u8; 32],
    ctx: &SessionContext,
) -> Result<Option<Vec<u8>>, String> {
    let fs_root = ctx.config.fs_root.as_ref().ok_or("no fs_root configured")?;
    let auth_key = RootAuthenticationKey::from_bytes32(auth_key_bytes);

    let export = vfs::vfssend2_bridge::decode_any_stream_to_changed_records(export_bytes)
        .map_err(|e| format!("decode stream: {e}"))?;

    let report = if export.incremental {
        vfs::LocalFileSystem::receive_incremental_changed_records_with_root_authentication_key(
            fs_root,
            tidefs_local_object_store::StoreOptions::default(),
            &export,
            auth_key,
        )
    } else {
        vfs::LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            fs_root,
            tidefs_local_object_store::StoreOptions::default(),
            &export,
            auth_key,
        )
    };

    match report {
        Ok(r) => {
            let ack = format!(
                "received stream (roots={}, records={}, payload={}, snapshots={}, tx={})",
                r.imported_roots,
                r.imported_records,
                r.imported_payload_bytes,
                r.snapshot_catalog_entries,
                r.selected_transaction_id,
            );
            Ok(Some(build_vsnp_ack(&ack)))
        }
        Err(e) => Err(format!("receive: {e}")),
    }
}

fn handle_vsnp_pull_request(
    _session_id: tidefs_transport::SessionId,
    auth_key_bytes: [u8; 32],
    ctx: &SessionContext,
) -> Result<Option<Vec<u8>>, String> {
    let fs_root = ctx.config.fs_root.as_ref().ok_or("no fs_root configured")?;
    let auth_key = RootAuthenticationKey::from_bytes32(auth_key_bytes);

    let mut fs = vfs::LocalFileSystem::open_with_root_authentication_key(
        fs_root,
        tidefs_local_object_store::StoreOptions::default(),
        auth_key,
    )
    .map_err(|e| format!("open fs for send: {e}"))?;

    let export = fs
        .export_changed_records()
        .map_err(|e| format!("export: {e}"))?;
    let encoded = export.encode();

    Ok(Some(build_vsnp_pull_response(&encoded)))
}

fn handle_vsnp_block_push(
    _session_id: tidefs_transport::SessionId,
    block_data: &[u8],
    _auth_key_bytes: [u8; 32],
    ctx: &SessionContext,
) -> Result<Option<Vec<u8>>, String> {
    let fs_root = ctx.config.fs_root.as_ref().ok_or("no fs_root configured")?;
    let block_file = std::path::Path::new(fs_root).join("block-volume-data");

    std::fs::write(&block_file, block_data).map_err(|e| format!("write block data: {e}"))?;

    let ack = format!("received block volume ({} bytes)", block_data.len());
    Ok(Some(build_vsnp_ack(&ack)))
}

fn handle_vsnp_block_pull_request(
    _session_id: tidefs_transport::SessionId,
    _auth_key_bytes: [u8; 32],
    ctx: &SessionContext,
) -> Result<Option<Vec<u8>>, String> {
    let fs_root = ctx.config.fs_root.as_ref().ok_or("no fs_root configured")?;
    let block_file = std::path::Path::new(fs_root).join("block-volume-data");

    let block_data = std::fs::read(&block_file).map_err(|e| format!("read block data: {e}"))?;

    if block_data.is_empty() {
        return Err("no block data found".into());
    }

    Ok(Some(build_vsnp_block_pull_response(&block_data)))
}

#[cfg(test)]
mod cluster_pool_handler_tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tidefs_cluster::pool_protocol::{ClusterPoolCreateResponse, ClusterPoolImportResponse};
    use tidefs_local_object_store::ObjectKey;
    use tidefs_pool_import::create::{PoolCreateConfig, PoolCreator, RedundancyPolicy};
    use tidefs_rebuild_runtime::completion::VerifiedReceiptCompletionRecord;
    use tidefs_replicated_object_store::ReceiptRepairCompletionEvidence;
    use tidefs_replication_model::{
        FlowCommitClass, FlowCommitResult, FlowState, ReceiptRedundancyPolicy, ReplicaCopyRecord,
        ReplicaPlacementReceipt, ReplicatedReceiptId, ReplicatedSubjectId,
    };

    /// Minimum device size for pool creation: 2 * 256KB labels + 8KB offset + 256KB commit region.
    const DEVICE_BYTES: u64 = 2_000_000;

    fn make_device(dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.set_len(DEVICE_BYTES).unwrap();
        f.flush().unwrap();
        path
    }

    fn minimal_config() -> StorageNodeConfig {
        StorageNodeConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: 1,
            store_paths: vec![PathBuf::from("/tmp/tidefs-store-test")],
            pool_device_paths: Vec::new(),
            pool_lock_dir: None,
            node_identity: None,
            authority: None,
            fs_root: None,
            root_auth_key: None,
            member_class: None,
            failure_domain: None,
            membership_bind_addr: None,
            membership_peers: Vec::new(),
            replica_peers: Vec::new(),
            rdma: false,
            carrier_policy: None,
            ready_file: None,
            drain_timeout_secs: 30,
            membership_checkpoint_dir: None,
            cluster_lease_config: None,
        }
    }

    fn config_with_rebuild_peer() -> StorageNodeConfig {
        let mut config = minimal_config();
        config.replica_peers.push(MembershipPeerConfig {
            node_id: 2,
            addr: "127.0.0.1:12002".parse().unwrap(),
            member_class: MemberClass::Voter,
            failure_domain: 2,
        });
        config
    }

    fn imported_regular_file_pool(
        dir: &tempfile::TempDir,
        names: &[&str],
        redundancy: RedundancyPolicy,
    ) -> (ImportedPool, PathBuf, Vec<PathBuf>) {
        let devices = names
            .iter()
            .map(|name| make_device(dir, name))
            .collect::<Vec<_>>();
        let create_config = PoolCreateConfig {
            pool_name: "storage-node-pool".into(),
            pool_guid: Some([0xC4; 16]),
            redundancy,
            encryption_key: None,
            clustered: false,
        };
        PoolCreator::create_pool(&devices, &create_config).unwrap();
        let lock_dir = dir.path().join("locks");
        let imported = pool_import(&devices, &lock_dir, false, None, None).unwrap();
        (imported, lock_dir, devices)
    }

    fn receipt_ref_for_key(
        object_key: ObjectKey,
        payload: &[u8],
        generation: u64,
    ) -> PlacementReceiptRef {
        PlacementReceiptRef::new(
            88,
            object_key.as_bytes32(),
            EpochId::new(11),
            generation,
            ReceiptRedundancyPolicy::Replicated { copies: 2 },
            payload.len() as u64,
            blake3::hash(payload).into(),
            2,
        )
    }

    fn receipt_ref(name: &[u8], payload: &[u8], generation: u64) -> PlacementReceiptRef {
        receipt_ref_for_key(ObjectKey::from_name(name), payload, generation)
    }

    fn repair_flow_commit_publication(
        source_receipt: PlacementReceiptRef,
        repaired_receipt: PlacementReceiptRef,
        target_member_id: u64,
        epoch: u64,
    ) -> ReceiptRepairFlowCommitPublication {
        let subject_ref = ReplicatedSubjectId::new(repaired_receipt.object_id);
        let target_member = MemberId::new(target_member_id);
        let verified_receipt_completion = VerifiedReceiptCompletionRecord {
            target_member,
            subject_ref,
            source_placement_receipt_ref: source_receipt,
            repaired_placement_receipt_ref: repaired_receipt,
        };
        ReceiptRepairFlowCommitPublication {
            repair_completion: ReceiptRepairCompletionEvidence {
                repaired_placement_receipt_ref: repaired_receipt,
                verified_receipt_completion,
                completion_event: None,
            },
            flow_commit_result: FlowCommitResult {
                placement_receipt: ReplicaPlacementReceipt {
                    receipt_id: ReplicatedReceiptId(10_000 + repaired_receipt.object_id),
                    verification_ref: ReplicatedReceiptId(20_000 + repaired_receipt.object_id),
                    transfer_ref: ReplicatedReceiptId(30_000 + repaired_receipt.object_id),
                    subject_refs: vec![subject_ref],
                    placed_on: target_member,
                    placement_epoch: EpochId::new(epoch),
                    subjects_placed: 1,
                    placement_receipt_refs: vec![repaired_receipt],
                },
                updated_copy: ReplicaCopyRecord::verified(
                    subject_ref,
                    target_member,
                    DomainId::new(target_member_id * 10 + 1),
                    receipt_digest_to_object_digest(repaired_receipt.payload_digest),
                    epoch,
                ),
                final_flow_state: FlowState::Complete,
                flow_class: FlowCommitClass::Rebuild,
                commit_epoch: EpochId::new(epoch),
            },
        }
    }

    fn relocation_flow_commit_result(
        relocated_receipt: PlacementReceiptRef,
        target_member_id: u64,
        epoch: u64,
    ) -> FlowCommitResult {
        let subject_ref = ReplicatedSubjectId::new(relocated_receipt.object_id);
        let target_member = MemberId::new(target_member_id);
        FlowCommitResult {
            placement_receipt: ReplicaPlacementReceipt {
                receipt_id: ReplicatedReceiptId(40_000 + relocated_receipt.object_id),
                verification_ref: ReplicatedReceiptId(50_000 + relocated_receipt.object_id),
                transfer_ref: ReplicatedReceiptId(60_000 + relocated_receipt.object_id),
                subject_refs: vec![subject_ref],
                placed_on: target_member,
                placement_epoch: EpochId::new(epoch),
                subjects_placed: 1,
                placement_receipt_refs: vec![relocated_receipt],
            },
            updated_copy: ReplicaCopyRecord::verified(
                subject_ref,
                target_member,
                DomainId::new(target_member_id * 10 + 1),
                receipt_digest_to_object_digest(relocated_receipt.payload_digest),
                epoch,
            ),
            final_flow_state: FlowState::Complete,
            flow_class: FlowCommitClass::Relocation,
            commit_epoch: EpochId::new(epoch),
        }
    }

    fn placement_map_with_old_receipt(old_receipt: PlacementReceiptRef) -> PlacementMap {
        let mut placement_map = PlacementMap::new(5);
        placement_map.insert(old_receipt.object_id, 1);
        placement_map.record_placement_receipt_ref(old_receipt.object_id, old_receipt);
        placement_map
    }

    fn cluster_runtime_with_old_receipt(old_receipt: PlacementReceiptRef) -> ClusterLeaseRuntime {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut runtime =
            ClusterLeaseRuntime::new(1, EpochId::new(1), ClusterLeaseConfig::default(), tx);
        let seed = repair_flow_commit_publication(old_receipt, old_receipt, 1, 5);
        runtime
            .publish_rebuild_flow_commit_result(&seed.flow_commit_result)
            .expect("seed runtime placement state");
        runtime
    }

    fn assert_repair_flow_publication_refused_without_mutation(
        publication: ReceiptRepairFlowCommitPublication,
        old_receipt: PlacementReceiptRef,
        expected: &str,
    ) {
        let mut placement_map = placement_map_with_old_receipt(old_receipt);

        let err = publish_repair_flow_commit_into_placement_map(&mut placement_map, &publication)
            .unwrap_err();

        assert!(err.contains(expected), "{err}");
        assert_eq!(placement_map.epoch(), 5);
        assert_eq!(
            placement_map.placement_receipt_ref(old_receipt.object_id),
            Some(old_receipt)
        );
        assert_eq!(
            placement_map
                .replicas_of(old_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [1].into_iter().collect()
        );
    }

    fn assert_repair_flow_runtime_publication_refused_without_mutation(
        publication: ReceiptRepairFlowCommitPublication,
        old_receipt: PlacementReceiptRef,
        expected: &str,
    ) {
        let mut runtime = cluster_runtime_with_old_receipt(old_receipt);

        let err = publish_repair_flow_commit_into_cluster_runtime(&mut runtime, &publication)
            .unwrap_err();

        assert!(err.contains(expected), "{err}");
        assert_eq!(runtime.placement_map().epoch(), 5);
        assert_eq!(
            runtime
                .placement_map()
                .placement_receipt_ref(old_receipt.object_id),
            Some(old_receipt)
        );
        assert_eq!(
            runtime
                .placement_map()
                .replicas_of(old_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [1].into_iter().collect()
        );
    }

    fn assert_relocation_flow_publication_refused_without_mutation(
        source_member: u64,
        result: FlowCommitResult,
        old_receipt: PlacementReceiptRef,
        expected: &str,
    ) {
        let mut placement_map = placement_map_with_old_receipt(old_receipt);

        let err = publish_relocation_flow_commit_into_placement_map(
            &mut placement_map,
            source_member,
            &result,
        )
        .unwrap_err();

        assert!(err.contains(expected), "{err}");
        assert_eq!(placement_map.epoch(), 5);
        assert_eq!(
            placement_map.placement_receipt_ref(old_receipt.object_id),
            Some(old_receipt)
        );
        assert_eq!(
            placement_map
                .replicas_of(old_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [1].into_iter().collect()
        );
    }

    fn assert_relocation_flow_runtime_publication_refused_without_mutation(
        source_member: u64,
        result: FlowCommitResult,
        old_receipt: PlacementReceiptRef,
        expected: &str,
    ) {
        let mut runtime = cluster_runtime_with_old_receipt(old_receipt);

        let err = publish_relocation_flow_commit_into_cluster_runtime(
            &mut runtime,
            source_member,
            &result,
        )
        .unwrap_err();

        assert!(err.contains(expected), "{err}");
        assert_eq!(runtime.placement_map().epoch(), 5);
        assert_eq!(
            runtime
                .placement_map()
                .placement_receipt_ref(old_receipt.object_id),
            Some(old_receipt)
        );
        assert_eq!(
            runtime
                .placement_map()
                .replicas_of(old_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [1].into_iter().collect()
        );
    }

    fn read_plan(subject_id: u64) -> ReplicatedReadPlan {
        ReplicatedReadPlan {
            subject_ref: tidefs_replication_model::ReplicatedSubjectId::new(subject_id),
            source_member_ref: Some(MemberId::new(1)),
            verified_member_refs: vec![MemberId::new(1)],
            unavailable_member_refs: Vec::new(),
            missing_replica_count: 0,
            read_class: ReplicatedReadClass::Exact,
            rebuild_required: false,
            read_receipt_ref: tidefs_replication_model::ReplicatedReceiptId(1),
        }
    }

    fn encode_read_plan(plan: &ReplicatedReadPlan) -> Vec<u8> {
        bincode::serialize(plan).unwrap()
    }

    #[test]
    fn sync_entries_preserve_object_key_identity() {
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("store")];
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
        store.put_named("alpha", b"payload").unwrap();
        let backend = StoreBackend::Local(Box::new(store));

        let entries = sync_entries_from_store(&backend);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].object_key,
            ObjectKey::from_name("alpha").as_bytes32()
        );
        assert_eq!(entries[0].payload, b"payload".to_vec());
        assert_eq!(entries[0].placement_receipt_ref, None);
    }

    #[test]
    fn local_backend_read_plan_response_is_receiptless() {
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("store")];
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
        let plan = read_plan(88);
        let object_name = read_plan_object_name(&plan);
        store.put_named(&object_name, b"planned-payload").unwrap();
        let backend = StoreBackend::Local(Box::new(store));

        let response = read_plan_response_from_store(&backend, &encode_read_plan(&plan), 1);

        match response {
            ReplicationMessage::ReadPlanResponse {
                found,
                payload,
                source_member_id,
                placement_receipt_ref,
            } => {
                assert!(found);
                assert_eq!(payload, b"planned-payload".to_vec());
                assert_eq!(source_member_id, 1);
                assert_eq!(placement_receipt_ref, None);
            }
            other => panic!("expected ReadPlanResponse, got {other:?}"),
        }
    }

    #[test]
    fn local_backend_degraded_valid_read_plan_response_is_receiptless() {
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("store")];
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
        let mut plan = read_plan(89);
        plan.read_class = ReplicatedReadClass::DegradedButValid;
        plan.missing_replica_count = 1;
        plan.rebuild_required = true;
        let object_name = read_plan_object_name(&plan);
        store
            .put_named(&object_name, b"degraded-planned-payload")
            .unwrap();
        let backend = StoreBackend::Local(Box::new(store));

        let response = read_plan_response_from_store(&backend, &encode_read_plan(&plan), 1);

        match response {
            ReplicationMessage::ReadPlanResponse {
                found,
                payload,
                source_member_id,
                placement_receipt_ref,
            } => {
                assert!(found);
                assert_eq!(payload, b"degraded-planned-payload".to_vec());
                assert_eq!(source_member_id, 1);
                assert_eq!(placement_receipt_ref, None);
            }
            other => panic!("expected ReadPlanResponse, got {other:?}"),
        }
    }

    #[test]
    fn local_backend_unreadable_read_plans_return_empty_response() {
        for read_class in [
            ReplicatedReadClass::RepairRequired,
            ReplicatedReadClass::Unavailable,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let paths = vec![dir.path().join("store")];
            let mut store =
                ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
            let mut plan = read_plan(90);
            plan.read_class = read_class;
            plan.rebuild_required = true;
            let object_name = read_plan_object_name(&plan);
            store
                .put_named(&object_name, b"must-not-be-served")
                .unwrap();
            let backend = StoreBackend::Local(Box::new(store));

            let response = read_plan_response_from_store(&backend, &encode_read_plan(&plan), 1);

            match response {
                ReplicationMessage::ReadPlanResponse {
                    found,
                    payload,
                    source_member_id,
                    placement_receipt_ref,
                } => {
                    assert!(!found, "{read_class:?} should fail closed");
                    assert!(payload.is_empty(), "{read_class:?} returned payload");
                    assert_eq!(source_member_id, 1);
                    assert_eq!(placement_receipt_ref, None);
                }
                other => panic!("expected ReadPlanResponse, got {other:?}"),
            }
        }
    }

    #[test]
    fn pool_backend_read_plan_response_carries_receipt_authority() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let mut backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));
        let plan = read_plan(88);
        let object_name = read_plan_object_name(&plan);
        let object_key = ObjectKey::from_name(object_name.as_bytes());

        if let StoreBackend::PoolBacked(pool) = &mut backend {
            pool_put_named(pool, object_name.as_bytes(), b"pool-planned-payload").unwrap();
        }

        let response = read_plan_response_from_store(&backend, &encode_read_plan(&plan), 1);

        match response {
            ReplicationMessage::ReadPlanResponse {
                found,
                payload,
                source_member_id,
                placement_receipt_ref,
            } => {
                assert!(found);
                assert_eq!(payload, b"pool-planned-payload".to_vec());
                assert_eq!(source_member_id, 1);
                let receipt = placement_receipt_ref.expect("pool read plan carries receipt");
                assert!(!receipt.is_synthetic());
                assert_eq!(receipt.object_id, plan.subject_ref.0);
                assert_eq!(receipt.object_key, object_key.as_bytes32());
                assert_eq!(receipt.payload_len, payload.len() as u64);
                let expected_digest: [u8; 32] = blake3::hash(&payload).into();
                assert_eq!(receipt.payload_digest, expected_digest);
                assert_eq!(receipt.target_count, 2);
            }
            other => panic!("expected ReadPlanResponse, got {other:?}"),
        }
    }

    fn assert_scrub_ack(report_json: String, findings_count: u64, expected_success: bool) {
        assert_eq!(
            scrub_response_ack(&report_json, findings_count),
            ReplicationMessage::Ack {
                key_hash: "scrub-ack".into(),
                success: expected_success,
            }
        );
    }

    #[test]
    fn peer_scrub_ack_succeeds_for_clean_completed_report() {
        let report_json = serde_json::json!({
            "segments_scanned": 1,
            "records_verified": 2,
            "bytes_scanned": 3,
            "chain_breaks_detected": 0,
            "completed": true,
            "findings_count": 0,
        })
        .to_string();

        assert_scrub_ack(report_json, 0, true);
    }

    #[test]
    fn peer_scrub_ack_fails_when_findings_are_reported() {
        let report_json = serde_json::json!({
            "completed": true,
            "findings_count": 1,
        })
        .to_string();

        assert_scrub_ack(report_json, 1, false);
    }

    #[test]
    fn peer_scrub_ack_fails_when_peer_reports_error() {
        let report_json = serde_json::json!({
            "error": "segment digest mismatch",
        })
        .to_string();

        assert_scrub_ack(report_json, 0, false);
    }

    #[test]
    fn peer_scrub_ack_fails_when_scrub_did_not_complete() {
        let report_json = serde_json::json!({
            "completed": false,
            "findings_count": 0,
        })
        .to_string();

        assert_scrub_ack(report_json, 0, false);
    }

    #[test]
    fn peer_scrub_ack_fails_on_malformed_report_json() {
        assert_scrub_ack("{not-json".into(), 0, false);
    }

    #[test]
    fn receipt_bound_name_repair_writes_matching_payload() {
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("store")];
        let store = ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
        let mut backend = StoreBackend::Local(Box::new(store));
        let name = b"repair-target";
        let payload = b"authoritative";
        let receipt = receipt_ref(name, payload, 3);

        apply_receipt_bound_name_repair(&mut backend, name, payload, receipt).unwrap();

        let entries = sync_entries_from_store(&backend);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].object_key,
            ObjectKey::from_name(name).as_bytes32()
        );
        assert_eq!(entries[0].payload, payload.to_vec());
        assert_eq!(entries[0].placement_receipt_ref, None);
    }

    #[test]
    fn receipt_bound_exact_key_repair_writes_matching_payload() {
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("store")];
        let store = ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
        let mut backend = StoreBackend::Local(Box::new(store));
        let object_key = ObjectKey::from_bytes32([0xAB; 32]);
        let payload = b"authoritative";
        let receipt = receipt_ref_for_key(object_key, payload, 6);

        let repaired_receipt_ref =
            apply_receipt_bound_key_repair(&mut backend, object_key, payload, receipt).unwrap();
        assert_eq!(repaired_receipt_ref, None);

        let entries = sync_entries_from_store(&backend);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].object_key, object_key.as_bytes32());
        assert_eq!(entries[0].payload, payload.to_vec());
        assert_eq!(entries[0].placement_receipt_ref, None);
    }

    #[test]
    fn exact_key_repair_rejects_non_32_byte_operand() {
        let err = exact_repair_object_key(b"not-a-32-byte-object-key").unwrap_err();
        assert!(err.contains("exactly 32 bytes"));
    }

    #[test]
    fn receipt_bound_repair_rejects_synthetic_receipt() {
        let name = b"repair-target";
        let payload = b"authoritative";
        let receipt = PlacementReceiptRef::synthetic_for_subject(
            tidefs_replication_model::ReplicatedSubjectId::new(88),
        );
        let err = validate_repair_receipt_for_name(name, payload, receipt).unwrap_err();
        assert!(err.contains("synthetic"));
    }

    #[test]
    fn receipt_bound_repair_rejects_key_mismatch() {
        let payload = b"authoritative";
        let receipt = receipt_ref(b"other-key", payload, 4);
        let err = validate_repair_receipt_for_name(b"repair-target", payload, receipt).unwrap_err();
        assert!(err.contains("object key does not match"));
    }

    #[test]
    fn receipt_bound_repair_rejects_payload_digest_mismatch() {
        let name = b"repair-target";
        let mut receipt = receipt_ref(name, b"authoritative", 5);
        receipt.payload_digest = blake3::hash(b"different").into();
        let err = validate_repair_receipt_for_name(name, b"authoritative", receipt).unwrap_err();
        assert!(err.contains("payload digest"));
    }

    #[test]
    fn receipt_inventory_discloses_storage_node_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("store")];
        let store = ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
        let backend = StoreBackend::Local(Box::new(store));
        let inventory = placement_receipt_inventory_json(&backend);
        assert_eq!(inventory["available"], false);
        assert_eq!(inventory["count"], 0);
        assert!(inventory["reason"]
            .as_str()
            .unwrap()
            .contains("compatibility object-store backend"));

        let admission = receipt_backed_rebuild_admission_json(&minimal_config(), &backend);
        assert_eq!(admission["available"], false);
        assert_eq!(admission["scheduled_task_count"], 0);
        assert!(admission["reason"]
            .as_str()
            .unwrap()
            .contains("does not expose pool placement receipts"));

        let planner = receipt_backed_rebuild_planner_json(&minimal_config(), &backend);
        assert_eq!(planner["available"], false);
        assert_eq!(planner["task_count"], 0);
        assert!(planner["reason"]
            .as_str()
            .unwrap()
            .contains("does not expose pool placement receipts"));

        let execution =
            receipt_backed_rebuild_execution_candidates_json(&minimal_config(), &backend);
        assert_eq!(execution["available"], false);
        assert_eq!(execution["execution_candidate_count"], 0);
        assert!(execution["reason"]
            .as_str()
            .unwrap()
            .contains("does not expose pool placement receipts"));
    }

    #[test]
    fn repair_flow_commit_publication_updates_placement_map() {
        let source_receipt = receipt_ref(b"storage-node-repair-source", b"old-payload", 1);
        let repaired_receipt = receipt_ref(b"storage-node-repair-source", b"new-payload", 2);
        let publication = repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        let mut placement_map = placement_map_with_old_receipt(source_receipt);

        let summary =
            publish_repair_flow_commit_into_placement_map(&mut placement_map, &publication)
                .expect("repair flow publication updates placement map");

        assert_eq!(summary.repair_flow_publication, publication);
        assert_eq!(
            summary.placement_publication.object_id,
            repaired_receipt.object_id
        );
        assert_eq!(summary.placement_publication.target_member, 2);
        assert_eq!(
            summary.placement_publication.placement_receipt_ref,
            repaired_receipt
        );
        assert_eq!(summary.placement_publication.map_epoch, 9);
        assert_eq!(placement_map.epoch(), 9);
        assert_eq!(
            placement_map.placement_receipt_ref(repaired_receipt.object_id),
            Some(repaired_receipt)
        );
        assert_eq!(
            placement_map
                .replicas_of(repaired_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [1, 2].into_iter().collect()
        );
    }

    #[test]
    fn repair_flow_commit_publication_updates_cluster_runtime() {
        let source_receipt = receipt_ref(b"storage-node-repair-source", b"old-payload", 1);
        let repaired_receipt = receipt_ref(b"storage-node-repair-source", b"new-payload", 2);
        let publication = repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        let mut runtime = cluster_runtime_with_old_receipt(source_receipt);

        let summary = publish_repair_flow_commit_into_cluster_runtime(&mut runtime, &publication)
            .expect("repair flow publication updates cluster runtime");

        assert_eq!(summary.repair_flow_publication, publication);
        assert_eq!(
            summary.placement_publication.object_id,
            repaired_receipt.object_id
        );
        assert_eq!(summary.placement_publication.target_member, 2);
        assert_eq!(
            summary.placement_publication.placement_receipt_ref,
            repaired_receipt
        );
        assert_eq!(summary.placement_publication.map_epoch, 9);
        assert_eq!(runtime.placement_map().epoch(), 9);
        assert_eq!(
            runtime
                .placement_map()
                .placement_receipt_ref(repaired_receipt.object_id),
            Some(repaired_receipt)
        );
        assert_eq!(
            runtime
                .placement_map()
                .replicas_of(repaired_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [1, 2].into_iter().collect()
        );
    }

    #[test]
    fn relocation_flow_commit_publication_updates_placement_map() {
        let source_receipt = receipt_ref(b"storage-node-relocation-source", b"old-payload", 1);
        let relocated_receipt = receipt_ref(b"storage-node-relocation-source", b"new-payload", 2);
        let result = relocation_flow_commit_result(relocated_receipt, 2, 9);
        let mut placement_map = placement_map_with_old_receipt(source_receipt);

        let summary =
            publish_relocation_flow_commit_into_placement_map(&mut placement_map, 1, &result)
                .expect("relocation flow publication updates placement map");

        assert_eq!(summary.source_member, 1);
        assert_eq!(summary.flow_commit_result, result);
        assert_eq!(
            summary.placement_publication.object_id,
            relocated_receipt.object_id
        );
        assert_eq!(summary.placement_publication.retired_source_member, 1);
        assert_eq!(summary.placement_publication.target_member, 2);
        assert_eq!(
            summary.placement_publication.placement_receipt_ref,
            relocated_receipt
        );
        assert_eq!(summary.placement_publication.map_epoch, 9);
        assert_eq!(placement_map.epoch(), 9);
        assert_eq!(
            placement_map.placement_receipt_ref(relocated_receipt.object_id),
            Some(relocated_receipt)
        );
        assert_eq!(
            placement_map
                .replicas_of(relocated_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [2].into_iter().collect()
        );
        assert!(!placement_map
            .objects_of(1)
            .is_some_and(|objects| objects.contains(&relocated_receipt.object_id)));
    }

    #[test]
    fn relocation_flow_commit_publication_updates_cluster_runtime() {
        let source_receipt = receipt_ref(b"storage-node-relocation-source", b"old-payload", 1);
        let relocated_receipt = receipt_ref(b"storage-node-relocation-source", b"new-payload", 2);
        let result = relocation_flow_commit_result(relocated_receipt, 2, 9);
        let mut runtime = cluster_runtime_with_old_receipt(source_receipt);

        let summary = publish_relocation_flow_commit_into_cluster_runtime(&mut runtime, 1, &result)
            .expect("relocation flow publication updates cluster runtime");

        assert_eq!(summary.source_member, 1);
        assert_eq!(summary.flow_commit_result, result);
        assert_eq!(
            summary.placement_publication.object_id,
            relocated_receipt.object_id
        );
        assert_eq!(summary.placement_publication.retired_source_member, 1);
        assert_eq!(summary.placement_publication.target_member, 2);
        assert_eq!(
            summary.placement_publication.placement_receipt_ref,
            relocated_receipt
        );
        assert_eq!(summary.placement_publication.map_epoch, 9);
        assert_eq!(runtime.placement_map().epoch(), 9);
        assert_eq!(
            runtime
                .placement_map()
                .placement_receipt_ref(relocated_receipt.object_id),
            Some(relocated_receipt)
        );
        assert_eq!(
            runtime
                .placement_map()
                .replicas_of(relocated_receipt.object_id)
                .cloned()
                .unwrap_or_default(),
            [2].into_iter().collect()
        );
        assert!(!runtime
            .placement_map()
            .objects_of(1)
            .is_some_and(|objects| objects.contains(&relocated_receipt.object_id)));
    }

    #[test]
    fn repair_flow_commit_publication_rejects_mismatches_without_mutation() {
        let source_receipt = receipt_ref(b"storage-node-repair-source", b"old-payload", 1);
        let repaired_receipt = receipt_ref(b"storage-node-repair-source", b"new-payload", 2);

        let mut mismatched_repair_record =
            repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        mismatched_repair_record
            .repair_completion
            .repaired_placement_receipt_ref = source_receipt;
        assert_repair_flow_publication_refused_without_mutation(
            mismatched_repair_record,
            source_receipt,
            "repair evidence repaired placement receipt mismatch",
        );

        let mut mismatched_subject =
            repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        mismatched_subject
            .flow_commit_result
            .updated_copy
            .subject_ref = ReplicatedSubjectId::new(repaired_receipt.object_id + 1);
        assert_repair_flow_publication_refused_without_mutation(
            mismatched_subject,
            source_receipt,
            "does not match repair completion subject",
        );

        let mut mismatched_target =
            repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        mismatched_target.flow_commit_result.updated_copy.member_ref = MemberId::new(3);
        assert_repair_flow_publication_refused_without_mutation(
            mismatched_target,
            source_receipt,
            "does not match repair completion target",
        );

        let mut mismatched_flow_receipt =
            repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        mismatched_flow_receipt
            .flow_commit_result
            .placement_receipt
            .placement_receipt_refs[0] = source_receipt;
        assert_repair_flow_publication_refused_without_mutation(
            mismatched_flow_receipt,
            source_receipt,
            "flow-commit repaired placement receipt",
        );
    }

    #[test]
    fn repair_flow_commit_publication_rejects_runtime_inputs_without_mutation() {
        let source_receipt = receipt_ref(b"storage-node-repair-source", b"old-payload", 1);
        let repaired_receipt = receipt_ref(b"storage-node-repair-source", b"new-payload", 2);

        let mut mismatched_target =
            repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        mismatched_target.flow_commit_result.updated_copy.member_ref = MemberId::new(3);
        assert_repair_flow_runtime_publication_refused_without_mutation(
            mismatched_target,
            source_receipt,
            "does not match repair completion target",
        );

        let mut stale = repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 4);
        stale.flow_commit_result.placement_receipt.placement_epoch = EpochId::new(4);
        assert_repair_flow_runtime_publication_refused_without_mutation(
            stale,
            source_receipt,
            "stale",
        );

        let mut receiptless =
            repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        receiptless
            .flow_commit_result
            .placement_receipt
            .placement_receipt_refs
            .clear();
        assert_repair_flow_runtime_publication_refused_without_mutation(
            receiptless,
            source_receipt,
            "exactly one placement receipt",
        );
    }

    #[test]
    fn repair_flow_commit_publication_rejects_bad_flow_result_without_mutation() {
        let source_receipt = receipt_ref(b"storage-node-repair-source", b"old-payload", 1);
        let repaired_receipt = receipt_ref(b"storage-node-repair-source", b"new-payload", 2);

        let mut stale = repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 4);
        stale.flow_commit_result.placement_receipt.placement_epoch = EpochId::new(4);
        assert_repair_flow_publication_refused_without_mutation(stale, source_receipt, "stale");

        let mut receiptless =
            repair_flow_commit_publication(source_receipt, repaired_receipt, 2, 9);
        receiptless
            .flow_commit_result
            .placement_receipt
            .placement_receipt_refs
            .clear();
        assert_repair_flow_publication_refused_without_mutation(
            receiptless,
            source_receipt,
            "exactly one placement receipt",
        );
    }

    #[test]
    fn relocation_flow_commit_publication_rejects_bad_inputs_without_mutation() {
        let source_receipt = receipt_ref(b"storage-node-relocation-source", b"old-payload", 1);
        let relocated_receipt = receipt_ref(b"storage-node-relocation-source", b"new-payload", 2);

        let mut wrong_class = relocation_flow_commit_result(relocated_receipt, 2, 9);
        wrong_class.flow_class = FlowCommitClass::Rebuild;
        assert_relocation_flow_publication_refused_without_mutation(
            1,
            wrong_class,
            source_receipt,
            "not relocation",
        );

        let mut incomplete = relocation_flow_commit_result(relocated_receipt, 2, 9);
        incomplete.final_flow_state = FlowState::Verified;
        assert_relocation_flow_publication_refused_without_mutation(
            1,
            incomplete,
            source_receipt,
            "not complete",
        );

        let mut receiptless = relocation_flow_commit_result(relocated_receipt, 2, 9);
        receiptless.placement_receipt.placement_receipt_refs.clear();
        assert_relocation_flow_publication_refused_without_mutation(
            1,
            receiptless,
            source_receipt,
            "exactly one placement receipt",
        );

        let wrong_source = relocation_flow_commit_result(relocated_receipt, 2, 9);
        assert_relocation_flow_publication_refused_without_mutation(
            3,
            wrong_source,
            source_receipt,
            "does not hold object",
        );

        let source_is_target = relocation_flow_commit_result(relocated_receipt, 1, 9);
        assert_relocation_flow_publication_refused_without_mutation(
            1,
            source_is_target,
            source_receipt,
            "matches target member",
        );
    }

    #[test]
    fn relocation_flow_commit_publication_rejects_runtime_inputs_without_mutation() {
        let source_receipt = receipt_ref(b"storage-node-relocation-source", b"old-payload", 1);
        let relocated_receipt = receipt_ref(b"storage-node-relocation-source", b"new-payload", 2);

        let mut stale = relocation_flow_commit_result(relocated_receipt, 2, 4);
        stale.placement_receipt.placement_epoch = EpochId::new(4);
        assert_relocation_flow_runtime_publication_refused_without_mutation(
            1,
            stale,
            source_receipt,
            "stale",
        );

        let mut mismatched_subject = relocation_flow_commit_result(relocated_receipt, 2, 9);
        mismatched_subject.updated_copy.subject_ref =
            ReplicatedSubjectId::new(relocated_receipt.object_id + 1);
        assert_relocation_flow_runtime_publication_refused_without_mutation(
            1,
            mismatched_subject,
            source_receipt,
            "does not match updated copy",
        );

        let mut mismatched_target = relocation_flow_commit_result(relocated_receipt, 2, 9);
        mismatched_target.placement_receipt.placed_on = MemberId::new(3);
        assert_relocation_flow_runtime_publication_refused_without_mutation(
            1,
            mismatched_target,
            source_receipt,
            "does not match updated copy",
        );
    }

    #[test]
    fn receipt_backed_rebuild_previews_reject_invalid_receipt_refs() {
        let payload = b"invalid-receipt-payload";
        let object_key = ObjectKey::from_bytes32([0xE4; 32]);
        let mut under_width = receipt_ref_for_key(object_key, payload, 1);
        under_width.target_count = 1;

        let admission = receipt_backed_rebuild_admission_from_refs_json(
            &config_with_rebuild_peer(),
            vec![under_width],
        );
        assert_eq!(admission["available"], false);
        assert_eq!(admission["receipt_ref_count"], 1);
        assert_eq!(
            admission["receipt_ingestion_error"]["class"],
            "insufficient-receipt-targets"
        );
        assert_eq!(admission["receipt_ingestion_error"]["required"], 2);
        assert_eq!(admission["receipt_ingestion_error"]["actual"], 1);

        let planner = receipt_backed_rebuild_planner_from_refs_json(
            &config_with_rebuild_peer(),
            vec![under_width],
        );
        assert_eq!(planner["available"], false);
        assert_eq!(planner["receipt_ref_count"], 1);
        assert_eq!(
            planner["planner_error"]["class"],
            "insufficient-receipt-targets"
        );
        assert_eq!(planner["planner_error"]["required"], 2);
        assert_eq!(planner["planner_error"]["actual"], 1);

        let mut malformed = receipt_ref_for_key(object_key, payload, 2);
        malformed.redundancy_policy = ReceiptRedundancyPolicy::Replicated { copies: 0 };
        malformed.target_count = 0;
        let planner = receipt_backed_rebuild_planner_from_refs_json(
            &config_with_rebuild_peer(),
            vec![malformed],
        );
        assert_eq!(planner["available"], false);
        assert_eq!(
            planner["planner_error"]["class"],
            "malformed-receipt-policy"
        );

        let synthetic = PlacementReceiptRef::synthetic_for_subject(
            tidefs_replication_model::ReplicatedSubjectId::new(99),
        );
        let admission = receipt_backed_rebuild_admission_from_refs_json(
            &config_with_rebuild_peer(),
            vec![synthetic],
        );
        assert_eq!(admission["available"], false);
        assert_eq!(
            admission["receipt_ingestion_error"]["class"],
            "synthetic-receipt-ref"
        );

        let planner = receipt_backed_rebuild_planner_from_refs_json(
            &config_with_rebuild_peer(),
            vec![synthetic],
        );
        assert_eq!(planner["available"], false);
        assert_eq!(planner["planner_error"]["class"], "synthetic-receipt-ref");

        let execution = receipt_backed_rebuild_execution_candidates_from_refs_json(
            &config_with_rebuild_peer(),
            vec![synthetic],
        );
        assert_eq!(execution["available"], false);
        assert_eq!(execution["execution_candidate_count"], 0);
        assert_eq!(
            execution["admission"]["receipt_ingestion_error"]["class"],
            "synthetic-receipt-ref"
        );
    }

    #[test]
    fn rebuild_execution_candidates_refuse_planner_admission_mismatch() {
        let payload = b"execution-candidate-payload";
        let object_key = ObjectKey::from_bytes32([0xD1; 32]);
        let receipt = receipt_ref_for_key(object_key, payload, 7);
        let admission =
            receipt_backed_rebuild_admission_from_refs(&config_with_rebuild_peer(), vec![receipt])
                .unwrap();
        let mut planner =
            receipt_backed_rebuild_planner_from_refs(&config_with_rebuild_peer(), vec![receipt])
                .unwrap();
        planner.tasks[0].target_nodes = vec![3];

        let err = cross_check_rebuild_execution_candidates(&admission, &planner).unwrap_err();
        assert_eq!(err["class"], "planner-admission-target-mismatch");
        assert_eq!(err["missing_in_planner"].as_array().unwrap().len(), 1);
        assert_eq!(err["extra_planner_targets"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn pool_backend_rejects_directory_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let err = object_pool_device_config(dir.path().to_path_buf()).unwrap_err();
        assert!(err.contains("pool device path is a directory"));
    }

    #[test]
    fn pool_backend_maps_regular_file_pool_policy_and_devices() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let config = object_pool_config_from_import(&imported, &lock_dir).unwrap();
        assert_eq!(config.devices.len(), 2);
        assert_eq!(
            config
                .devices
                .iter()
                .map(|device| device.path.clone())
                .collect::<Vec<_>>(),
            devices
        );
        assert!(config
            .devices
            .iter()
            .all(|device| device.backing == DeviceBacking::RegularFileDev));
        let properties = object_pool_properties_from_import(&imported);
        assert_eq!(
            properties.redundancy_policy,
            ObjectPoolRedundancyPolicy::replicated(2)
        );
    }

    #[test]
    fn pool_backend_put_get_delete_list_uses_receipt_authority() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let mut backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));

        let name = b"pool-backed-object";
        if let StoreBackend::PoolBacked(pool) = &mut backend {
            pool_put_named(pool, name, b"payload").unwrap();
            assert_eq!(
                pool_get_named(pool, name).unwrap(),
                Some(b"payload".to_vec())
            );
        }

        let entries = sync_entries_from_store(&backend);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].object_key,
            ObjectKey::from_name(name).as_bytes32()
        );
        assert_eq!(entries[0].payload, b"payload".to_vec());
        let sync_receipt = entries[0]
            .placement_receipt_ref
            .expect("pool-backed sync entry carries receipt authority");
        assert!(!sync_receipt.is_synthetic());
        assert_eq!(sync_receipt.object_key, entries[0].object_key);
        assert_eq!(sync_receipt.payload_len, entries[0].payload.len() as u64);
        let expected_digest: [u8; 32] = blake3::hash(&entries[0].payload).into();
        assert_eq!(sync_receipt.payload_digest, expected_digest);
        assert_eq!(sync_receipt.target_count, 2);
        assert_eq!(
            sync_receipt.redundancy_policy,
            tidefs_replication_model::ReceiptRedundancyPolicy::Replicated { copies: 2 }
        );

        let inventory = placement_receipt_inventory_json(&backend);
        assert_eq!(inventory["available"], true);
        assert_eq!(inventory["count"], 1);
        assert_eq!(inventory["refs"][0]["target_count"], 2);

        if let StoreBackend::PoolBacked(pool) = &mut backend {
            assert!(pool_delete_named(pool, name).unwrap());
            assert!(pool_get_named(pool, name).unwrap().is_none());
            assert!(pool_list_logical_keys(pool).unwrap().is_empty());
        }
    }

    #[test]
    fn pool_backend_exact_key_repair_uses_receipt_object_key() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let object_key = ObjectKey::from_bytes32([0xC7; 32]);
        let payload = b"pool-authoritative";
        let receipt = receipt_ref_for_key(object_key, payload, 7);
        let mut backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));

        let stale_generation = if let StoreBackend::PoolBacked(pool) = &mut backend {
            pool_put_key(pool, object_key, b"stale-local-payload").unwrap();
            pool_placement_receipt_ref_for_key(pool, object_key, receipt.object_id)
                .unwrap()
                .receipt_generation
        } else {
            unreachable!()
        };

        let repaired_receipt_ref =
            apply_receipt_bound_key_repair(&mut backend, object_key, payload, receipt)
                .unwrap()
                .unwrap();

        if let StoreBackend::PoolBacked(pool) = &mut backend {
            assert_eq!(
                pool_get_key(pool, object_key).unwrap(),
                Some(payload.to_vec())
            );
            assert!(pool_get_named(pool, object_key.as_bytes32())
                .unwrap()
                .is_none());
        }
        assert_eq!(repaired_receipt_ref.object_id, receipt.object_id);
        assert_eq!(repaired_receipt_ref.object_key, object_key.as_bytes32());
        assert_eq!(repaired_receipt_ref.payload_len, payload.len() as u64);
        let expected_digest: [u8; 32] = blake3::hash(payload).into();
        assert_eq!(repaired_receipt_ref.payload_digest, expected_digest);
        assert_eq!(repaired_receipt_ref.target_count, 2);
        assert!(repaired_receipt_ref.receipt_generation > stale_generation);
        assert!(!repaired_receipt_ref.is_synthetic());
        let entries = sync_entries_from_store(&backend);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].object_key, object_key.as_bytes32());
        assert_eq!(entries[0].payload, payload.to_vec());
        let sync_receipt = entries[0]
            .placement_receipt_ref
            .expect("pool-backed repaired key carries receipt authority");
        assert_eq!(sync_receipt.object_key, object_key.as_bytes32());
        assert_eq!(sync_receipt.payload_len, payload.len() as u64);
        assert_eq!(sync_receipt.payload_digest, expected_digest);
        assert_eq!(sync_receipt.target_count, 2);
        assert_eq!(
            sync_receipt.redundancy_policy,
            tidefs_replication_model::ReceiptRedundancyPolicy::Replicated { copies: 2 }
        );
        assert!(!sync_receipt.is_synthetic());
    }

    #[test]
    fn pool_backend_segment_fetch_uses_receipt_object_key() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let mut backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));

        let legacy_object_id: u64 = 44;
        let receipt_key = ObjectKey::from_bytes32([0x5A; 32]);
        let receipt_payload = b"receipt-authoritative-payload";
        let legacy_payload = b"legacy-object-id-payload";
        let receipt = receipt_ref_for_key(receipt_key, receipt_payload, 8);

        if let StoreBackend::PoolBacked(pool) = &mut backend {
            pool_put_named(pool, legacy_object_id.to_le_bytes(), legacy_payload).unwrap();
            pool_put_key(pool, receipt_key, receipt_payload).unwrap();
        }

        let request = SegmentFetchRequest {
            object_id: legacy_object_id,
            placement_receipt_ref: Some(receipt),
            segment_offset: 8,
            segment_length: 13,
        };

        let response = build_segment_fetch_response(&backend, &request).unwrap();

        assert_eq!(response.object_id, receipt.object_id);
        assert_eq!(response.payload, b"authoritative".to_vec());
        assert_eq!(response.segment_offset, 8);
        assert_eq!(response.segment_length, 13);
    }

    #[test]
    fn pool_backend_segment_fetch_refuses_missing_receipt_object_key() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let mut backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));

        let legacy_object_id: u64 = 45;
        let receipt_key = ObjectKey::from_bytes32([0x6A; 32]);
        let receipt_payload = b"missing-receipt-authoritative-payload";
        let receipt = receipt_ref_for_key(receipt_key, receipt_payload, 9);

        if let StoreBackend::PoolBacked(pool) = &mut backend {
            pool_put_named(pool, legacy_object_id.to_le_bytes(), b"legacy payload").unwrap();
        }

        let request = SegmentFetchRequest {
            object_id: legacy_object_id,
            placement_receipt_ref: Some(receipt),
            segment_offset: 0,
            segment_length: receipt.payload_len,
        };

        let err = build_segment_fetch_response(&backend, &request).unwrap_err();

        assert!(err.contains("pool receipt-key get for object 88"));
        assert!(err.contains("exact placement receipt key"));
        assert!(err.contains("6a6a6a6a"));
        assert!(err.contains("not found"));
    }

    #[test]
    fn pool_backend_segment_fetch_keeps_legacy_missing_fetch_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));

        let request = SegmentFetchRequest {
            object_id: 46,
            placement_receipt_ref: None,
            segment_offset: 0,
            segment_length: 32,
        };

        let response = build_segment_fetch_response(&backend, &request).unwrap();

        assert_eq!(response.object_id, 46);
        assert_eq!(response.segment_offset, 0);
        assert_eq!(response.segment_length, 0);
        assert!(response.payload.is_empty());
    }

    #[test]
    fn pool_backend_segment_fetch_keeps_synthetic_missing_fetch_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));
        let synthetic = PlacementReceiptRef::synthetic_for_subject(
            tidefs_replication_model::ReplicatedSubjectId::new(47),
        );

        let request = SegmentFetchRequest {
            object_id: 47,
            placement_receipt_ref: Some(synthetic),
            segment_offset: 0,
            segment_length: 32,
        };

        let response = build_segment_fetch_response(&backend, &request).unwrap();

        assert_eq!(response.object_id, 47);
        assert_eq!(response.segment_offset, 0);
        assert_eq!(response.segment_length, 0);
        assert!(response.payload.is_empty());
    }

    #[test]
    fn pool_backend_scrub_reports_real_receipt_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let (imported, lock_dir, _devices) = imported_regular_file_pool(
            &dir,
            &["dev0.img", "dev1.img"],
            RedundancyPolicy::replicated(2),
        );
        let mut backend = StoreBackend::PoolBacked(Box::new(
            open_imported_pool_backend(&imported, &lock_dir).unwrap(),
        ));
        if let StoreBackend::PoolBacked(pool) = &mut backend {
            pool_put_named(pool, b"scrubbed", b"payload").unwrap();
        }

        let (report_json, findings_count) =
            local_scrub_report_json(&config_with_rebuild_peer(), &backend);
        let report: serde_json::Value = serde_json::from_str(&report_json).unwrap();
        assert_eq!(findings_count, 0);
        assert_eq!(report["backend"], "pool");
        assert_eq!(report["placement_receipt_refs"]["available"], true);
        assert_eq!(report["placement_receipt_ref_count"], 1);
        assert_eq!(report["rebuild_admission"]["available"], true);
        assert_eq!(report["rebuild_admission"]["preview"], true);
        assert_eq!(report["rebuild_admission"]["receipt_ref_count"], 1);
        assert_eq!(
            report["rebuild_admission"]["healthy_sources"],
            serde_json::json!([1])
        );
        assert_eq!(
            report["rebuild_admission"]["lost_members"],
            serde_json::json!([2])
        );
        assert_eq!(
            report["rebuild_admission"]["admitted_members"],
            serde_json::json!([2])
        );
        assert_eq!(report["rebuild_admission"]["report_count"], 1);
        assert_eq!(report["rebuild_admission"]["intent_count"], 1);
        assert_eq!(report["rebuild_admission"]["scheduled_task_count"], 1);
        assert_eq!(report["rebuild_planner"]["available"], true);
        assert_eq!(report["rebuild_planner"]["preview"], true);
        assert_eq!(
            report["rebuild_planner"]["boundary"],
            "storage-node-scrub-rebuild-planner-preview"
        );
        assert_eq!(report["rebuild_planner"]["receipt_ref_count"], 1);
        assert_eq!(
            report["rebuild_planner"]["healthy_sources"],
            serde_json::json!([1])
        );
        assert_eq!(
            report["rebuild_planner"]["candidate_targets"],
            serde_json::json!([2])
        );
        assert_eq!(
            report["rebuild_planner"]["failed_nodes"],
            serde_json::json!([])
        );
        assert_eq!(report["rebuild_planner"]["task_count"], 1);
        assert_eq!(report["rebuild_planner"]["total_target_replicas"], 1);
        assert_eq!(report["rebuild_execution_candidates"]["available"], true);
        assert_eq!(
            report["rebuild_execution_candidates"]["boundary"],
            "storage-node-scrub-rebuild-execution-candidate-preview"
        );
        assert_eq!(
            report["rebuild_execution_candidates"]["receipt_ref_count"],
            1
        );
        assert_eq!(
            report["rebuild_execution_candidates"]["admission_task_count"],
            1
        );
        assert_eq!(
            report["rebuild_execution_candidates"]["planner_task_count"],
            1
        );
        assert_eq!(
            report["rebuild_execution_candidates"]["execution_candidate_count"],
            1
        );

        let receipt_ref = &report["placement_receipt_refs"]["refs"][0];
        let admission_task = &report["rebuild_admission"]["scheduled_tasks"][0];
        assert_eq!(admission_task["source_member"], 1);
        assert_eq!(admission_task["target_member"], 2);
        assert_eq!(admission_task["subject_ref"], receipt_ref["object_id"]);
        assert_eq!(admission_task["payload_len"], receipt_ref["payload_len"]);
        assert_eq!(admission_task["placement_receipt_ref"], *receipt_ref);
        assert_eq!(
            admission_task["placement_receipt_ref"]["target_count"],
            receipt_ref["target_count"]
        );
        let planner_task = &report["rebuild_planner"]["tasks"][0];
        assert_eq!(planner_task["object_id"], receipt_ref["object_id"]);
        assert_eq!(planner_task["source_nodes"], serde_json::json!([1]));
        assert_eq!(planner_task["target_nodes"], serde_json::json!([2]));
        assert_eq!(planner_task["placement_receipt_ref"], *receipt_ref);
        assert_eq!(
            planner_task["placement_receipt_ref"]["payload_digest"],
            receipt_ref["payload_digest"]
        );
        let candidate = &report["rebuild_execution_candidates"]["candidates"][0];
        assert_eq!(candidate["source_member"], 1);
        assert_eq!(candidate["target_member"], 2);
        assert_eq!(candidate["payload_len"], receipt_ref["payload_len"]);
        assert_eq!(candidate["placement_receipt_ref"], *receipt_ref);
        assert_eq!(
            candidate["placement_receipt_ref"]["payload_digest"],
            receipt_ref["payload_digest"]
        );
    }

    #[test]
    fn handler_create_request_calls_real_pool_api_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let dev = make_device(&dir, "dev0");

        let device_paths: Vec<std::path::PathBuf> = vec![dev.clone()];
        let config = PoolCreateConfig {
            pool_name: "test-pool".into(),
            pool_guid: Some([0xA1; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let outcome = PoolCreator::create_pool(&device_paths, &config).unwrap();
        assert_eq!(outcome.pool_guid, [0xA1; 16]);
        assert_eq!(outcome.pool_name, "test-pool");
        assert_eq!(outcome.device_count, 1);
    }

    #[test]
    fn handler_create_request_fails_on_invalid_device() {
        let device_paths: Vec<std::path::PathBuf> =
            vec![std::path::PathBuf::from("/nonexistent/device/path")];
        let config = PoolCreateConfig {
            pool_name: "bad-pool".into(),
            pool_guid: Some([0xB2; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let result = PoolCreator::create_pool(&device_paths, &config);
        assert!(result.is_err(), "expected error on nonexistent device");
    }

    #[test]
    fn cluster_create_media_rejects_regular_files_without_dev_flag() {
        let dir = tempfile::tempdir().unwrap();
        let dev = make_device(&dir, "dev0");
        let err = validate_cluster_create_device_media(&[dev], false).unwrap_err();
        assert!(err.contains("regular file"));
        assert!(err.contains("--file-devices"));
    }

    #[test]
    fn cluster_create_media_allows_regular_files_with_dev_flag() {
        let dir = tempfile::tempdir().unwrap();
        let dev = make_device(&dir, "dev0");
        validate_cluster_create_device_media(&[dev], true).unwrap();
    }

    #[test]
    fn cluster_create_media_rejects_directories() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            validate_cluster_create_device_media(&[dir.path().to_path_buf()], true).unwrap_err();
        assert!(err.contains("cluster pool create device"));
    }

    #[test]
    fn cluster_create_redundancy_authority_maps_replicated() {
        let redundancy = cluster_create_redundancy_authority(
            ClusterRedundancy::MirrorAcrossNodes { copies: 2 },
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
        )
        .unwrap();

        assert_eq!(redundancy, RedundancyPolicy::replicated(2));
    }

    #[test]
    fn cluster_create_redundancy_authority_maps_erasure() {
        let redundancy = cluster_create_redundancy_authority(
            ClusterRedundancy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
            },
            ClusterPlacementPolicy::ErasureCoded { data: 4, parity: 2 },
        )
        .unwrap();

        assert_eq!(redundancy, RedundancyPolicy::erasure(4, 2));
    }

    #[test]
    fn cluster_create_redundancy_authority_rejects_placement_mismatch() {
        let err = cluster_create_redundancy_authority(
            ClusterRedundancy::MirrorAcrossNodes { copies: 2 },
            ClusterPlacementPolicy::Stripe,
        )
        .unwrap_err();

        assert!(err.contains("redundancy/placement mismatch"));
        assert!(err.contains("MirrorAcrossNodes"));
        assert!(err.contains("Stripe"));
    }

    #[test]
    fn handler_create_and_import_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let dev = make_device(&dir, "dev0");
        let device_paths = vec![dev.clone()];

        // Create the pool.
        let create_config = PoolCreateConfig {
            pool_name: "roundtrip".into(),
            pool_guid: Some([0xC3; 16]),
            redundancy: RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        let outcome = PoolCreator::create_pool(&device_paths, &create_config).unwrap();
        assert_eq!(outcome.device_count, 1);

        // Import the pool.
        let lock_dir = dir.path().join("locks");
        let imported = pool_import(&device_paths, &lock_dir, false, None, None).unwrap();
        assert!(imported.stats.committed_root_epoch.is_some());
    }

    #[test]
    fn handler_import_fails_on_unlabeled_device() {
        let dir = tempfile::tempdir().unwrap();
        let dev = make_device(&dir, "dev0");
        let device_paths = vec![dev];
        let lock_dir = dir.path().join("locks");
        let result = pool_import(&device_paths, &lock_dir, false, None, None);
        assert!(result.is_err(), "expected error importing unlabeled device");
    }

    #[test]
    fn handler_create_response_encoding_roundtrip() {
        let resp = ClusterPoolCreateResponse {
            request_id: 42,
            node_id: 7,
            pool_guid: [0xDD; 16],
            success: true,
            device_guids: vec![[0x01; 16], [0x02; 16]],
            error: None,
        };
        let msg = ClusterPoolMessage::CreateResponse(resp.clone());
        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn handler_import_response_encoding_roundtrip() {
        let resp = ClusterPoolImportResponse {
            request_id: 1,
            node_id: 5,
            pool_guid: [0xEE; 16],
            success: true,
            committed_root_epoch: Some(3),
            intent_log_replayed: Some(10),
            error: None,
        };
        let msg = ClusterPoolMessage::ImportResponse(resp.clone());
        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn handler_error_response_encoding_roundtrip() {
        let resp = ClusterPoolCreateResponse {
            request_id: 99,
            node_id: 3,
            pool_guid: [0xFF; 16],
            success: false,
            device_guids: vec![],
            error: Some("device too small".into()),
        };
        let msg = ClusterPoolMessage::CreateResponse(resp.clone());
        let encoded = msg.encode().unwrap();
        let decoded = ClusterPoolMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }
}
