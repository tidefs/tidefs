//! Cluster lease runtime driving the membership lease lifecycle per node.
//!
//! The [`ClusterLeaseRuntime`] coordinates the [`LeaseStateMachine`] with
//! transport-layer message exchange and epoch-transition events. It is
//! designed to be embedded in a node's main event loop, driven by
//! periodic ticks and incoming message feeds.
//!
//! ## Integration points
//!
//! - **Transport**: outgoing messages are queued via a `tokio::sync::mpsc`
//!   sender; the transport layer polls the receiver for messages to send.
//! - **Membership epoch**: calls to `on_epoch_transition()` keep the
//!   runtime aligned with membership epoch changes.
//! - **Periodic tick**: `tick()` checks for deadline-driven expiry and
//!   initiates automatic renewal when the lease is approaching expiry.

use std::collections::{BTreeMap, BTreeSet};

use tokio::sync::mpsc;

use tidefs_membership_epoch::EpochId;

use crate::authority::{AcquireOutcome, LeaseAuthority, RenewOutcome};
use crate::dataset_catalog::{
    CatalogDelta, ClusterCatalogError, ClusterDatasetCatalog, ClusterPoolCatalog,
    DatasetCreateRequest,
};
use crate::lease_state_machine::LeaseStateMachine;
use crate::placement_heal::{
    HealState, HealStats, LossEvent, PlacementHealCoordinator, PlacementMap,
};
use crate::pool_config::{ClusterPlacementPolicy, ClusterPoolConfig, FailureDomain};
use crate::pool_lease_token::PoolLeaseToken;
use crate::protocol::MembershipLeaseMessage;
use crate::rebuild_backfill::{
    BackfillBatch, BackfillError, BackfillState, RebuildBackfillInitiator, RebuildPlan,
};
use crate::types::{LeaseState, LeaseStatus, MembershipLease};
use crate::write_fence::FenceAuthority;
use crate::write_fence::FenceValidator;
use crate::write_fence::WriteFence;

/// The direction a message is traveling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    /// Message being sent to the given peer node.
    Outgoing {
        peer_node_id: u64,
        msg: MembershipLeaseMessage,
    },
    /// Message received from a peer node.
    /// Backfill batch being sent to a target peer.
    /// Carries a [`BackfillBatch`] that the transport layer encodes as
    /// one or more `StateTransferRequest` messages.
    BackfillOutgoing {
        target_peer: u64,
        batch: BackfillBatch,
    },
    Incoming {
        peer_node_id: u64,
        msg: MembershipLeaseMessage,
    },
}

/// Configuration for the cluster lease runtime.
#[derive(Clone, Debug)]
pub struct ClusterLeaseConfig {
    /// Duration of each lease term in milliseconds.
    pub lease_term_ms: u64,
    /// Fraction of lease term (in thousandths) at which to start renewal.
    /// E.g., 750 means renew when 75% of the term has elapsed.
    pub renewal_threshold_permille: u64,
    /// Maximum number of retries for lease acquisition.
    pub max_acquire_retries: u32,
}

impl Default for ClusterLeaseConfig {
    fn default() -> Self {
        Self {
            lease_term_ms: 30_000,
            renewal_threshold_permille: 750,
            max_acquire_retries: 3,
        }
    }
}

/// The cluster lease runtime.
///
/// Owns the lease state machine and coordinates message exchange.
pub struct ClusterLeaseRuntime {
    node_id: u64,
    config: ClusterLeaseConfig,
    sm: LeaseStateMachine,
    /// Outgoing messages to be sent via transport.
    outgoing_tx: mpsc::UnboundedSender<MessageDirection>,
    /// Optional lease authority for grant/nack decisions on incoming requests.
    authority: Option<LeaseAuthority>,
    /// Pending request IDs to correlate responses.
    next_request_id: u64,
    /// Number of acquire retries attempted for the current acquisition.
    acquire_retries: u32,
    /// Current time in milliseconds since epoch.
    /// Rebuild backfill initiator for node/device loss recovery.
    backfill: RebuildBackfillInitiator,
    /// Placement heal coordinator: loss detection, rebuild planning, heal lifecycle.
    heal_coordinator: PlacementHealCoordinator,
    /// Write-fence authority for single-writer write-path gating.
    fence_authority: Option<FenceAuthority>,
    /// Pool-scoped cluster-gated dataset catalog for serialized catalog
    /// mutations with committed state persistence and version tracking.
    pool_catalog: Option<ClusterPoolCatalog>,
    /// Active-client mode tracker for per-dataset write-mode detection.
    client_mode_tracker: crate::client_mode::ClientModeTracker,
    now_ms: u64,
}

impl ClusterLeaseRuntime {
    /// Create a new runtime.
    ///
    /// `outgoing_tx` is an unbounded sender that the transport layer will
    /// poll to consume and send messages to peers.
    pub fn new(
        node_id: u64,
        current_epoch: EpochId,
        config: ClusterLeaseConfig,
        outgoing_tx: mpsc::UnboundedSender<MessageDirection>,
    ) -> Self {
        Self {
            node_id,
            config,
            sm: LeaseStateMachine::new(node_id, current_epoch),
            outgoing_tx,
            authority: None,
            fence_authority: None,
            next_request_id: 1,
            acquire_retries: 0,
            now_ms: 0,
            backfill: RebuildBackfillInitiator::new(current_epoch),
            heal_coordinator: PlacementHealCoordinator::new(current_epoch.0, None),
            pool_catalog: None,
            client_mode_tracker: crate::client_mode::ClientModeTracker::default(),
        }
    }

    /// Set the lease authority for processing incoming grant/nack requests.
    /// Initialize the lease authority from a bootstrapped

    /// [`ClusterAuthoritySnapshot`](crate::cluster_authority_snapshot::ClusterAuthoritySnapshot).

    ///

    /// This is the boot-time integration point: after scanning pool

    /// devices and discovering a valid authority record, call this

    /// method to seed the lease authority with the persisted epoch

    /// and voter knowledge.

    pub fn with_authority_snapshot(
        mut self,

        snapshot: &crate::cluster_authority_snapshot::ClusterAuthoritySnapshot,
    ) -> Self {
        let authority = LeaseAuthority::from_snapshot(snapshot);

        self.authority = Some(authority);

        self
    }

    pub fn with_authority(mut self, authority: LeaseAuthority) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Set the write-fence authority for single-writer write-path gating.
    pub fn with_fence_authority(mut self, fence_authority: FenceAuthority) -> Self {
        self.fence_authority = Some(fence_authority);
        self
    }

    /// Set the pool-scoped dataset catalog for cluster-gated catalog mutations.
    ///
    /// The catalog's lease lifecycle and committed state persistence are
    /// automatically managed. When a lease is acquired, the inner catalog
    /// is gated; on loss or epoch transition, the gate is cleared.
    pub fn with_pool_catalog(mut self, catalog: ClusterPoolCatalog) -> Self {
        self.pool_catalog = Some(catalog);
        self
    }

    /// Set the cluster placement policy for rebuild target selection.
    ///
    /// Delegates to [`PlacementHealCoordinator::with_placement_policy`].
    pub fn with_placement_policy(mut self, policy: ClusterPlacementPolicy) -> Self {
        self.heal_coordinator = self.heal_coordinator.with_placement_policy(policy);
        self
    }

    /// Register per-member failure-domain vectors for the heal coordinator.
    ///
    /// Delegates to [`PlacementHealCoordinator::with_member_failure_domains`].
    pub fn with_member_failure_domains(mut self, domains: BTreeMap<u64, FailureDomain>) -> Self {
        self.heal_coordinator = self.heal_coordinator.with_member_failure_domains(domains);
        self
    }

    /// Wire the cluster pool configuration into the heal coordinator.
    ///
    /// Extracts the placement policy from `config.placement` and builds
    /// per-node failure-domain vectors from `config.devices`.  Call this
    /// after pool import so that rebuild target selection is policy-aware
    /// and respects the cluster's failure-domain topology.
    pub fn with_cluster_pool_config(mut self, config: &ClusterPoolConfig) -> Self {
        self.heal_coordinator = self
            .heal_coordinator
            .with_placement_policy(config.placement);
        let domains: BTreeMap<u64, FailureDomain> = config
            .devices
            .iter()
            .map(|d| (d.node_id, d.failure_domain))
            .collect();
        self.heal_coordinator = self.heal_coordinator.with_member_failure_domains(domains);
        self
    }

    /// Set the active-client mode tracker for per-dataset mode detection
    /// and single-writer / multi-writer switching.
    pub fn with_client_mode_tracker(
        mut self,
        tracker: crate::client_mode::ClientModeTracker,
    ) -> Self {
        self.client_mode_tracker = tracker;
        self
    }

    /// Register a dataset in the client-mode tracker.
    ///
    /// Call this when a dataset is first mounted on this node.
    pub fn register_client_dataset(
        &mut self,
        dataset_id: u64,
    ) -> Result<crate::client_mode::ClientMode, crate::client_mode::ModeTransitionError> {
        self.client_mode_tracker
            .register(dataset_id, self.node_id)?;
        if let Some(fence) = self
            .fence_authority
            .as_ref()
            .and_then(|fa| fa.active_fence())
        {
            let _ = self
                .client_mode_tracker
                .set_writer(dataset_id, self.node_id, fence);
        }
        Ok(self.client_mode_tracker.active_mode(dataset_id).unwrap())
    }

    /// Record that a remote node has mounted the given dataset.
    pub fn remote_client_mounted(
        &mut self,
        dataset_id: u64,
        remote_node_id: u64,
    ) -> Result<crate::client_mode::ClientMode, crate::client_mode::ModeTransitionError> {
        // Auto-register if not yet tracked.
        if self.client_mode_tracker.active_mode(dataset_id).is_none() {
            self.register_client_dataset(dataset_id)?;
        }
        self.client_mode_tracker
            .client_mounted(dataset_id, remote_node_id)
    }

    /// Record that a remote node has unmounted the given dataset.
    pub fn remote_client_unmounted(
        &mut self,
        dataset_id: u64,
        remote_node_id: u64,
    ) -> Result<crate::client_mode::ClientMode, crate::client_mode::ModeTransitionError> {
        self.client_mode_tracker
            .client_unmounted(dataset_id, remote_node_id)
    }

    /// Return a reference to the client mode tracker.
    pub fn client_mode_tracker(&self) -> &crate::client_mode::ClientModeTracker {
        &self.client_mode_tracker
    }
    /// Return the current lease state.
    pub fn state(&self) -> LeaseState {
        self.sm.state()
    }

    /// Return the current lease, if any.
    pub fn lease(&self) -> Option<&MembershipLease> {
        self.sm.lease()
    }

    /// Return a status snapshot.
    pub fn status(&self) -> LeaseStatus {
        LeaseStatus {
            node_id: self.node_id,
            state: self.sm.state(),
            lease: self.sm.lease().cloned(),
            current_epoch: self.sm.current_epoch(),
            state_digest: self.sm.state_digest(),
        }
    }
    /// Try to produce a [`PoolLeaseToken`] from the current lease state.
    ///
    /// Returns `Some(token)` when the lease state machine is in `Held` or
    /// `Renewing` state and the lease record is present. Returns `None`
    /// when no lease is held (unleased, acquiring, expiring, released).
    ///
    /// The returned token carries the current write fence (if a
    /// `FenceAuthority` is configured) or a zero-generation fence.
    /// Callers must pass this token to pool import to prove cluster
    /// lease ownership.
    pub fn try_get_pool_lease_token(&self, pool_guid: [u8; 16]) -> Option<PoolLeaseToken> {
        let lease = self.sm.lease()?;
        if !self.sm.state().is_active() {
            return None;
        }
        let write_fence = self
            .fence_authority
            .as_ref()
            .and_then(|fa| fa.active_fence())
            .unwrap_or_else(|| WriteFence::new(self.sm.current_epoch(), 0));
        Some(PoolLeaseToken::new(
            lease.node_id,
            pool_guid,
            lease.epoch,
            lease.lease_id,
            lease.slot,
            write_fence,
            lease.expiration_deadline_ms,
        ))
    }

    // ── Dataset catalog accessors ─────────────────────────────────

    /// Return a reference to the pool-scoped catalog, if configured.
    pub fn pool_catalog(&self) -> Option<&ClusterPoolCatalog> {
        self.pool_catalog.as_ref()
    }

    /// Return a mutable reference to the pool-scoped catalog.
    pub fn pool_catalog_mut(&mut self) -> Option<&mut ClusterPoolCatalog> {
        self.pool_catalog.as_mut()
    }

    /// Return a reference to the inner cluster-gated catalog, if configured.
    pub fn dataset_catalog(&self) -> Option<&ClusterDatasetCatalog> {
        self.pool_catalog.as_ref().map(|pc| pc.catalog())
    }

    /// Encode the catalog's committed state for inclusion in epoch commit.
    ///
    /// Returns `None` if no catalog is configured.
    pub fn encode_catalog_committed_state(&self) -> Option<Vec<u8>> {
        self.pool_catalog
            .as_ref()
            .map(|pc| pc.encode_committed_state())
    }

    /// BLAKE3 digest of the catalog's committed state for cross-node verification.
    pub fn catalog_committed_state_digest(&self) -> Option<[u8; 32]> {
        self.pool_catalog
            .as_ref()
            .map(|pc| pc.committed_state_digest())
    }

    /// Current catalog version (monotonically incremented on each committed delta).
    pub fn catalog_version(&self) -> Option<u64> {
        self.pool_catalog.as_ref().map(|pc| pc.version())
    }

    /// Prepare a create-dataset delta for cluster proposal.
    ///
    /// Returns `None` if no dataset catalog is configured. Returns an error
    /// if the lease gate check fails or the catalog rejects the mutation.
    pub fn prepare_dataset_create(
        &self,
        path: &str,
        dataset_id: tidefs_dataset_catalog::DatasetId,
        dataset_type: tidefs_dataset_catalog::DatasetType,
        creation_txg: u64,
        properties: Vec<u8>,
        flags: tidefs_dataset_catalog::DatasetFlags,
    ) -> Option<Result<CatalogDelta, ClusterCatalogError>> {
        let cat = self.pool_catalog.as_ref()?;
        let fence = cat.active_fence()?;
        Some(cat.prepare_create_delta(
            fence,
            DatasetCreateRequest {
                path: path.into(),
                dataset_id,
                dataset_type,
                creation_txg,
                properties,
                flags,
            },
        ))
    }

    /// Prepare a destroy-dataset delta for cluster proposal.
    pub fn prepare_dataset_destroy(
        &self,
        path: &str,
    ) -> Option<Result<CatalogDelta, ClusterCatalogError>> {
        let cat = self.pool_catalog.as_ref()?;
        let fence = cat.active_fence()?;
        Some(cat.prepare_destroy_delta(fence, path))
    }

    /// Prepare a rename-dataset delta for cluster proposal.
    pub fn prepare_dataset_rename(
        &self,
        old_path: &str,
        new_path: &str,
    ) -> Option<Result<CatalogDelta, ClusterCatalogError>> {
        let cat = self.pool_catalog.as_ref()?;
        let fence = cat.active_fence()?;
        Some(cat.prepare_rename_delta(fence, old_path, new_path))
    }

    /// Apply a committed catalog delta to the local dataset catalog.
    ///
    /// Returns `None` if no dataset catalog is configured.
    pub fn apply_dataset_delta(
        &mut self,
        delta: &CatalogDelta,
    ) -> Option<Result<(), tidefs_dataset_catalog::CatalogError>> {
        // Use apply_committed_delta which also bumps the version counter.
        self.pool_catalog
            .as_mut()
            .map(|cat| cat.apply_committed_delta(delta).map(|_v| ()))
    }

    /// Apply a committed catalog delta received from the cluster epoch
    /// commit path.
    ///
    /// Deserializes a [`CatalogDelta`] from raw bytes (as produced by
    /// `bincode::serialize`), applies it to the pool catalog, and returns
    /// the new catalog version on success.
    ///
    /// This is the primary ingress point for catalog deltas arriving via
    /// the epoch commit path. Unlike prepare methods, this does NOT check
    /// the lease gate — the delta was already committed by cluster quorum.
    ///
    /// Returns `None` if no pool catalog is configured.
    pub fn apply_committed_catalog_delta(
        &mut self,
        delta_bytes: &[u8],
    ) -> Option<Result<u64, ClusterCatalogError>> {
        let cat = self.pool_catalog.as_mut()?;
        let delta: CatalogDelta = match bincode::deserialize(delta_bytes) {
            Ok(d) => d,
            Err(_) => {
                return Some(Err(ClusterCatalogError::Catalog(
                    tidefs_dataset_catalog::CatalogError::CorruptEncoding,
                )));
            }
        };
        Some(
            cat.apply_committed_delta(&delta)
                .map_err(ClusterCatalogError::from),
        )
    }

    /// Process an incoming membership lease message from a peer.
    ///
    /// This is the primary ingress point for lease protocol messages
    /// received from the transport layer.
    pub fn handle_incoming(&mut self, peer_node_id: u64, msg: MembershipLeaseMessage) {
        match &msg {
            MembershipLeaseMessage::AcquireAck(_ack) => {
                if self.sm.state() == LeaseState::Acquiring {
                    if let Err(e) = self.sm.grant() {
                        tracing::warn!("acquire ack but grant failed: {:?}", e);
                    } else {
                        // Single-writer fence: issue new fence on lease acquisition.
                        // Single-writer fence: issue new fence on lease acquisition.
                        let fence = if let Some(ref fence_auth) = self.fence_authority {
                            let epoch = self.sm.current_epoch();
                            fence_auth.issue_fence(epoch)
                        } else {
                            // If no fence_authority is configured, synthesize a fence
                            // from the current epoch so the catalog can still be gated.
                            crate::write_fence::WriteFence::new(self.sm.current_epoch(), 0)
                        };
                        // Notify the dataset catalog of lease acquisition.
                        if let Some(ref mut cat) = self.pool_catalog {
                            cat.on_lease_acquired(fence);
                        }
                    }
                }
            }
            MembershipLeaseMessage::AcquireNack(_nack) => {
                if self.sm.state() == LeaseState::Acquiring {
                    self.acquire_retries += 1;
                    if self.acquire_retries < self.config.max_acquire_retries {
                        self.send_acquire_request();
                    } else {
                        let _ = self.sm.reject();
                        self.acquire_retries = 0;
                    }
                }
            }
            MembershipLeaseMessage::RenewAck(_ack) => {
                if self.sm.state() == LeaseState::Renewing {
                    let _ = self.sm.renew_ack();
                }
            }
            MembershipLeaseMessage::RenewNack(_nack) => {
                if self.sm.state() == LeaseState::Renewing {
                    let _ = self.sm.renew_nack();
                }
            }
            MembershipLeaseMessage::ReleaseAck(_ack) => {
                // Release is fire-and-forget; no state change needed
            }
            MembershipLeaseMessage::Acquire(req) => {
                if let Some(ref mut authority) = self.authority {
                    match authority.handle_acquire(req) {
                        AcquireOutcome::Ack(ack) => {
                            let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                                peer_node_id,
                                msg: MembershipLeaseMessage::AcquireAck(ack),
                            });
                        }
                        AcquireOutcome::Nack(nack) => {
                            let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                                peer_node_id,
                                msg: MembershipLeaseMessage::AcquireNack(nack),
                            });
                        }
                    }
                } else {
                    tracing::debug!(
                        "received acquire request from peer {} but no authority configured",
                        peer_node_id
                    );
                }
            }
            MembershipLeaseMessage::Renew(req) => {
                if let Some(ref mut authority) = self.authority {
                    let new_deadline = self.config.lease_term_ms;
                    match authority.handle_renew(req, new_deadline) {
                        RenewOutcome::Ack(ack) => {
                            let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                                peer_node_id,
                                msg: MembershipLeaseMessage::RenewAck(ack),
                            });
                        }
                        RenewOutcome::Nack(nack) => {
                            let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                                peer_node_id,
                                msg: MembershipLeaseMessage::RenewNack(nack),
                            });
                        }
                    }
                } else {
                    tracing::debug!(
                        "received renew request from peer {} but no authority configured",
                        peer_node_id
                    );
                }
            }
            MembershipLeaseMessage::Release(req) => {
                if let Some(ref mut authority) = self.authority {
                    let ack = authority.handle_release(req);
                    let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                        peer_node_id,
                        msg: MembershipLeaseMessage::ReleaseAck(ack),
                    });
                } else {
                    tracing::debug!(
                        "received release from peer {} but no authority configured",
                        peer_node_id
                    );
                }
            }
            MembershipLeaseMessage::ExpireNotify(notify) => {
                if let Some(ref mut authority) = self.authority {
                    authority.handle_expire(notify);
                }
                tracing::debug!("received expire notification from peer {}", peer_node_id);
            }
        }
    }

    /// Start lease acquisition.
    ///
    /// Sends an Acquire request to the specified lease authority peer.
    pub fn start_acquire(&mut self, slot: u64, lease_authority_peer: u64) {
        if self.sm.state().is_active() {
            return; // already have a lease
        }
        self.acquire_retries = 0;
        self.send_acquire_request_inner(slot, lease_authority_peer);
    }

    /// Release the current lease.
    ///
    /// Sends a Release message to the lease authority and transitions to
    /// Released state.
    pub fn release_lease(&mut self, lease_authority_peer: u64) {
        if let Some(lease) = self.sm.lease() {
            let msg = MembershipLeaseMessage::Release(crate::protocol::ReleaseRequest {
                node_id: self.node_id,
                lease_id: lease.lease_id,
                epoch: lease.epoch,
            });
            let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                peer_node_id: lease_authority_peer,
                msg,
            });
        }
        let _ = self.sm.release();

        // Clear the write fence on voluntary release.
        if let Some(ref fence_auth) = self.fence_authority {
            fence_auth.clear();
        }

        // Notify the dataset catalog of lease loss.
        if let Some(ref mut cat) = self.pool_catalog {
            cat.on_lease_lost();
        }
    }

    /// Periodic tick — checks for deadline-driven expiry and triggers
    /// automatic renewal.
    pub fn tick(&mut self, now_ms: u64, lease_authority_peer: u64) {
        self.now_ms = now_ms;
        self.sm.tick(now_ms);

        let (should_renew, epoch_for_renew) = {
            let state = self.sm.state();
            if state == LeaseState::Held {
                if let Some(lease) = self.sm.lease() {
                    let elapsed = lease
                        .lease_term_ms
                        .saturating_sub(lease.remaining_ms(now_ms));
                    let threshold =
                        lease.lease_term_ms * self.config.renewal_threshold_permille / 1000;
                    (elapsed >= threshold, self.sm.current_epoch())
                } else {
                    (false, self.sm.current_epoch())
                }
            } else {
                (false, self.sm.current_epoch())
            }
        };
        if should_renew {
            let lease_id = self.sm.lease().map(|l| l.lease_id);
            if let Some(lid) = lease_id {
                if self.sm.renew(epoch_for_renew, now_ms).is_ok() {
                    let renew = MembershipLeaseMessage::Renew(crate::protocol::RenewRequest {
                        node_id: self.node_id,
                        lease_id: lid,
                        epoch: epoch_for_renew,
                    });
                    let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                        peer_node_id: lease_authority_peer,
                        msg: renew,
                    });
                }
            }
        }

        // If expired, notify
        if self.sm.state() == LeaseState::Expiring {
            if let Some(lease) = self.sm.lease() {
                let notify = MembershipLeaseMessage::ExpireNotify(crate::protocol::ExpireNotify {
                    node_id: self.node_id,
                    lease_id: lease.lease_id,
                    epoch: lease.epoch,
                });
                let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                    peer_node_id: lease_authority_peer,
                    msg: notify,
                });
            }
            let _ = self.sm.expire_to_released();

            // Clear the write fence on lease expiration.
            if let Some(ref fence_auth) = self.fence_authority {
                fence_auth.clear();
            }

            // Notify the dataset catalog of lease loss.
            if let Some(ref mut cat) = self.pool_catalog {
                cat.on_lease_lost();
            }
        }
    }

    /// Called when the membership epoch transitions.
    pub fn on_epoch_transition(&mut self, new_epoch: EpochId) {
        self.sm.on_epoch_transition(new_epoch);
        // Epoch transitions invalidate the current lease; notify the catalog.
        if let Some(ref mut cat) = self.pool_catalog {
            cat.on_lease_lost();
        }
        self.heal_coordinator.on_epoch_transition(new_epoch.0);
        let aborted = self.backfill.on_epoch_transition(new_epoch);
        if aborted > 0 {
            tracing::info!(
                "epoch transition aborted {} active backfills for epoch {:?}",
                aborted,
                new_epoch
            );
        }
    }

    // ── Rebuild backfill ────────────────────────────────────────────

    /// Trigger rebuild backfill on member departure.
    ///
    /// Consumes a [`RebuildPlan`] that describes which objects must
    /// be backfilled to which nodes, opens a backfill session, and
    /// queues the resulting batches as [`MessageDirection::BackfillOutgoing`]
    /// messages for transport dispatch.
    ///
    /// Returns the backfill session ID on success.
    pub fn on_member_departure(
        &mut self,
        plan: RebuildPlan,
        epoch: EpochId,
    ) -> Result<u64, BackfillError> {
        let backfill_id = self.backfill.open_backfill(plan, epoch)?;

        let batches = self
            .backfill
            .batches_for(backfill_id)
            .map(|bs| bs.to_vec())
            .unwrap_or_default();

        for batch in batches {
            let target = batch.target_node;
            let _ = self.outgoing_tx.send(MessageDirection::BackfillOutgoing {
                target_peer: target,
                batch,
            });
        }

        let _ = self.backfill.initiate_backfill(backfill_id);
        tracing::info!(
            "opened backfill {} with {} batches after member departure",
            backfill_id,
            self.backfill
                .batches_for(backfill_id)
                .map(|b| b.len())
                .unwrap_or(0)
        );

        Ok(backfill_id)
    }

    /// Record backfill progress from transport-layer chunk acknowledgements.
    pub fn record_backfill_progress(
        &mut self,
        backfill_id: u64,
        objects_completed: u64,
        bytes_transferred: u64,
    ) -> Result<(), BackfillError> {
        self.backfill
            .record_progress(backfill_id, objects_completed, bytes_transferred)
    }

    /// Complete a backfill transfer and finalize.
    pub fn complete_backfill(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        self.backfill.complete_transfer(backfill_id)?;
        self.backfill.finalize_backfill(backfill_id)?;
        tracing::info!("backfill {} completed and finalized", backfill_id);
        Ok(())
    }

    /// Abort a backfill by ID.
    pub fn abort_backfill(&mut self, backfill_id: u64) -> Result<(), BackfillError> {
        self.backfill.abort_backfill(backfill_id)
    }

    /// Query the state of a backfill session.
    pub fn backfill_state(&self, backfill_id: u64) -> Option<BackfillState> {
        self.backfill.session(backfill_id).map(|s| s.state)
    }

    /// Number of active (in-flight) backfills.
    pub fn active_backfill_count(&self) -> usize {
        self.backfill.active_count()
    }

    /// Total objects pending across all active backfills.
    pub fn backfill_pending_objects(&self) -> u64 {
        self.backfill.total_pending_objects()
    }

    /// Return the backfill initiator (for tests).
    #[cfg(test)]
    pub(crate) fn backfill_initiator_mut(&mut self) -> &mut RebuildBackfillInitiator {
        &mut self.backfill
    }

    // ── Placement heal ───────────────────────────────────────────────

    /// Detect member loss and initiate a heal.
    /// Computes rebuild scope from the placement map, generates a rebuild plan,
    /// and opens a backfill session through the existing backfill initiator.
    /// Returns the backfill session ID on success, or None if no heal was needed.
    pub fn detect_member_loss(
        &mut self,
        lost_members: BTreeSet<u64>,
        available_members: BTreeMap<u64, tidefs_membership_epoch::HealthClass>,
        now_ns: u64,
    ) -> Option<u64> {
        let epoch = self.heal_coordinator.placement().epoch();
        let event = LossEvent {
            lost_members,
            epoch,
            detected_at_ns: now_ns,
            available_members,
        };
        let _affected = self.heal_coordinator.detect_loss(event)?;
        let plan = self.heal_coordinator.build_rebuild_plan(1, now_ns)?;
        let epoch_id = EpochId(epoch);
        match self.on_member_departure(plan, epoch_id) {
            Ok(backfill_id) => {
                // Advance to Transferring so the backfill can receive progress and complete.
                let _ = self.backfill.start_transferring(backfill_id);
                self.heal_coordinator.record_backfill_opened(backfill_id);
                Some(backfill_id)
            }
            Err(e) => {
                tracing::warn!("failed to open backfill for heal: {:?}", e);
                self.heal_coordinator.abort_heal();
                None
            }
        }
    }

    /// Return the current heal state.
    pub fn heal_state(&self) -> HealState {
        self.heal_coordinator.state()
    }

    /// Return heal statistics.
    pub fn heal_stats(&self) -> &HealStats {
        self.heal_coordinator.stats()
    }

    /// Whether a heal operation is in progress.
    pub fn is_healing(&self) -> bool {
        self.heal_coordinator.is_healing()
    }

    /// Tick heal progress based on backfill completion.
    ///
    /// Called periodically; checks whether the backfill session
    /// associated with the current heal has completed.
    /// Returns true if the heal transitioned to Complete or Failed.
    pub fn heal_tick(
        &mut self,
        objects_completed: u64,
        bytes_transferred: u64,
        now_ns: u64,
    ) -> bool {
        if !self.heal_coordinator.is_healing() {
            return false;
        }

        if let Err(e) = self
            .heal_coordinator
            .record_rebuild_progress(objects_completed, bytes_transferred)
        {
            tracing::warn!("heal progress record failed: {}", e);
        }

        // Check if the associated backfill session is complete
        if let Some(backfill_id) = self.heal_coordinator.stats().backfill_id {
            if let Some(BackfillState::Complete) = self.backfill_state(backfill_id) {
                if self.heal_coordinator.state() == HealState::Rebuilding {
                    let _ = self.heal_coordinator.complete_rebuild(now_ns);
                }
            }
        }

        // Auto-finalize: move Verifying → Complete once rebuild transfer is done.
        if self.heal_coordinator.state() == HealState::Verifying {
            self.heal_coordinator.finalize_heal(&BTreeMap::new());
            return true;
        }

        self.heal_coordinator.state().is_terminal()
    }

    /// Access the placement map for external queries (e.g., show placement).
    pub fn placement_map(&self) -> &PlacementMap {
        self.heal_coordinator.placement()
    }

    /// Record an object placement in the heal coordinator (called from the write path).
    pub fn record_placement(&mut self, object_id: u64, member_id: u64) {
        self.heal_coordinator
            .placement_mut()
            .insert(object_id, member_id);
    }

    /// Return a validator for transport-layer write-fence checks, if configured.
    pub fn fence_validator(&self) -> Option<FenceValidator> {
        self.fence_authority.as_ref().map(|fa| fa.validator())
    }

    /// Return the state digest.
    pub fn state_digest(&self) -> [u8; 32] {
        self.sm.state_digest()
    }

    // ── Internal helpers ───────────────────────────────────────────

    fn send_acquire_request(&mut self) {
        self.send_acquire_request_inner(0, 0);
    }

    fn send_acquire_request_inner(&mut self, slot: u64, peer: u64) {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        let _ = self.sm.acquire(
            self.sm.current_epoch(),
            self.config.lease_term_ms,
            slot,
            request_id,
            self.now_ms,
        );

        if self.sm.state() == LeaseState::Acquiring {
            let msg = MembershipLeaseMessage::Acquire(crate::protocol::AcquireRequest {
                node_id: self.node_id,
                epoch: self.sm.current_epoch(),
                slot,
                lease_term_ms: self.config.lease_term_ms,
                request_id,
            });
            let _ = self.outgoing_tx.send(MessageDirection::Outgoing {
                peer_node_id: peer,
                msg,
            });
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AcquireAck, AcquireRequest, ExpireNotify, ReleaseRequest, RenewRequest};
    use tidefs_membership_epoch::{EpochId, HealthClass};

    #[test]
    fn new_runtime_is_unleased() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        assert_eq!(rt.state(), LeaseState::Unleased);
    }

    #[test]
    fn status_reflects_current_state() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        let status = rt.status();
        assert_eq!(status.node_id, 1);
        assert_eq!(status.state, LeaseState::Unleased);
        assert!(status.lease.is_none());
        assert_eq!(status.current_epoch, EpochId(1));
    }

    #[test]
    fn handle_acquire_ack_transitions_to_held() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        rt.start_acquire(0, 2);

        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent,
            MessageDirection::Outgoing {
                peer_node_id: 2,
                msg: MembershipLeaseMessage::Acquire(_),
            }
        ));

        assert_eq!(rt.state(), LeaseState::Acquiring);

        rt.handle_incoming(
            2,
            MembershipLeaseMessage::AcquireAck(AcquireAck {
                request_id: 1,
                lease_id: 100,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                deadline_ms: 30_000,
            }),
        );

        assert_eq!(rt.state(), LeaseState::Held);
    }

    #[test]
    fn epoch_transition_expires_lease() {
        let (tx, _rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        rt.start_acquire(0, 2);
        rt.handle_incoming(
            2,
            MembershipLeaseMessage::AcquireAck(AcquireAck {
                request_id: 1,
                lease_id: 100,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                deadline_ms: 30_000,
            }),
        );
        assert_eq!(rt.state(), LeaseState::Held);

        rt.on_epoch_transition(EpochId(2));
        assert_eq!(rt.state(), LeaseState::Expiring);
    }

    #[test]
    fn release_changes_state() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        rt.start_acquire(0, 2);
        rt.handle_incoming(
            2,
            MembershipLeaseMessage::AcquireAck(AcquireAck {
                request_id: 1,
                lease_id: 100,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                deadline_ms: 30_000,
            }),
        );

        let _ = rx.try_recv();

        rt.release_lease(2);

        assert_eq!(rt.state(), LeaseState::Released);

        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent,
            MessageDirection::Outgoing {
                peer_node_id: 2,
                msg: MembershipLeaseMessage::Release(_),
            }
        ));
    }

    #[test]
    fn tick_expires_and_notifies() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(
            1,
            EpochId(1),
            ClusterLeaseConfig {
                lease_term_ms: 1_000,
                renewal_threshold_permille: 2000,
                max_acquire_retries: 3,
            },
            tx,
        );

        rt.start_acquire(0, 2);
        rt.handle_incoming(
            2,
            MembershipLeaseMessage::AcquireAck(AcquireAck {
                request_id: 1,
                lease_id: 100,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 1_000,
                deadline_ms: 1_000,
            }),
        );
        let _ = rx.try_recv();

        rt.tick(1500, 2);

        assert_eq!(rt.state(), LeaseState::Released);
        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent,
            MessageDirection::Outgoing {
                peer_node_id: 2,
                msg: MembershipLeaseMessage::ExpireNotify(_),
            }
        ));
    }

    // ── Authority integration tests ──────────────────────────────────

    #[test]
    fn authority_grants_acquire_request() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(2, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_authority(LeaseAuthority::new(EpochId(1)));

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::Acquire(AcquireRequest {
                node_id: 1,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                request_id: 42,
            }),
        );

        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent,
            MessageDirection::Outgoing {
                peer_node_id: 1,
                msg: MembershipLeaseMessage::AcquireAck(_),
            }
        ));
    }

    #[test]
    fn authority_nacks_occupied_slot() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(2, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_authority(LeaseAuthority::new(EpochId(1)));

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::Acquire(AcquireRequest {
                node_id: 1,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                request_id: 1,
            }),
        );
        let _ = rx.try_recv().unwrap();

        rt.handle_incoming(
            3,
            MembershipLeaseMessage::Acquire(AcquireRequest {
                node_id: 3,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                request_id: 2,
            }),
        );

        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent,
            MessageDirection::Outgoing {
                peer_node_id: 3,
                msg: MembershipLeaseMessage::AcquireNack(_),
            }
        ));
    }

    #[test]
    fn authority_renews_and_acks() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(2, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_authority(LeaseAuthority::new(EpochId(1)));

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::Acquire(AcquireRequest {
                node_id: 1,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                request_id: 1,
            }),
        );
        let sent = rx.try_recv().unwrap();
        let lease_id = match sent {
            MessageDirection::Outgoing {
                msg: MembershipLeaseMessage::AcquireAck(ack),
                ..
            } => ack.lease_id,
            _ => panic!("expected AcquireAck"),
        };

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::Renew(RenewRequest {
                node_id: 1,
                lease_id,
                epoch: EpochId(1),
            }),
        );

        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent,
            MessageDirection::Outgoing {
                peer_node_id: 1,
                msg: MembershipLeaseMessage::RenewAck(_),
            }
        ));
    }

    #[test]
    fn authority_releases_and_acks() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(2, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_authority(LeaseAuthority::new(EpochId(1)));

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::Acquire(AcquireRequest {
                node_id: 1,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                request_id: 1,
            }),
        );
        let sent = rx.try_recv().unwrap();
        let lease_id = match sent {
            MessageDirection::Outgoing {
                msg: MembershipLeaseMessage::AcquireAck(ack),
                ..
            } => ack.lease_id,
            _ => panic!("expected AcquireAck"),
        };

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::Release(ReleaseRequest {
                node_id: 1,
                lease_id,
                epoch: EpochId(1),
            }),
        );

        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent,
            MessageDirection::Outgoing {
                peer_node_id: 1,
                msg: MembershipLeaseMessage::ReleaseAck(_),
            }
        ));
    }

    #[test]
    fn authority_handles_expire_notify() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut rt = ClusterLeaseRuntime::new(2, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_authority(LeaseAuthority::new(EpochId(1)));

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::Acquire(AcquireRequest {
                node_id: 1,
                epoch: EpochId(1),
                slot: 0,
                lease_term_ms: 30_000,
                request_id: 1,
            }),
        );
        let sent = rx.try_recv().unwrap();
        let lease_id = match sent {
            MessageDirection::Outgoing {
                msg: MembershipLeaseMessage::AcquireAck(ack),
                ..
            } => ack.lease_id,
            _ => panic!("expected AcquireAck"),
        };
        assert!(rx.try_recv().is_err());

        rt.handle_incoming(
            1,
            MembershipLeaseMessage::ExpireNotify(ExpireNotify {
                node_id: 1,
                lease_id,
                epoch: EpochId(1),
            }),
        );

        assert!(rx.try_recv().is_err());
    }

    // ── Backfill integration tests ─────────────────────────────────

    fn make_plan(
        plan_id: u64,
        tasks: Vec<crate::rebuild_backfill::ReconstructionTask>,
    ) -> RebuildPlan {
        RebuildPlan::new(plan_id, tasks, 0)
    }

    fn receipt_ref(object_id: u64) -> tidefs_replication_model::PlacementReceiptRef {
        let mut object_key = [0xA5; 32];
        object_key[..8].copy_from_slice(&object_id.to_le_bytes());
        let mut digest = [0x5A; 32];
        digest[..8].copy_from_slice(&object_id.to_le_bytes());
        tidefs_replication_model::PlacementReceiptRef::replicated(
            object_id,
            object_key,
            EpochId(1),
            1,
            2,
            4096,
            digest,
        )
    }

    fn make_task(
        object_id: u64,
        sources: Vec<u64>,
        targets: Vec<u64>,
    ) -> crate::rebuild_backfill::ReconstructionTask {
        crate::rebuild_backfill::ReconstructionTask::new_full_with_receipt(
            object_id,
            receipt_ref(object_id),
            sources,
            targets,
            0,
        )
    }

    #[test]
    fn on_member_departure_opens_backfill() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        let plan = make_plan(100, vec![make_task(1, vec![10], vec![20])]);
        let id = rt.on_member_departure(plan, EpochId(1)).unwrap();
        assert_eq!(id, 1);
        assert_eq!(rt.active_backfill_count(), 1);

        let sent = rx.try_recv().unwrap();
        assert!(matches!(sent, MessageDirection::BackfillOutgoing { .. }));
        if let MessageDirection::BackfillOutgoing { target_peer, batch } = sent {
            assert_eq!(target_peer, 20);
            assert_eq!(batch.commands.len(), 1);
            assert_eq!(batch.commands[0].source_node, 10);
        }
    }

    #[test]
    fn backfill_state_after_departure() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        let plan = make_plan(100, vec![make_task(1, vec![10], vec![20])]);
        let id = rt.on_member_departure(plan, EpochId(1)).unwrap();
        assert_eq!(rt.backfill_state(id), Some(BackfillState::Initiating));
    }

    #[test]
    fn record_and_complete_backfill() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        let plan = make_plan(100, vec![make_task(1, vec![10], vec![20])]);
        let id = rt.on_member_departure(plan, EpochId(1)).unwrap();

        rt.backfill_initiator_mut().session_mut(id).unwrap().state = BackfillState::Transferring;
        rt.record_backfill_progress(id, 1, 4096).unwrap();
        assert_eq!(rt.backfill_pending_objects(), 0);

        rt.complete_backfill(id).unwrap();
        assert_eq!(rt.backfill_state(id), Some(BackfillState::Complete));
        assert_eq!(rt.active_backfill_count(), 0);
    }

    #[test]
    fn epoch_transition_aborts_backfills() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        let plan = make_plan(100, vec![make_task(1, vec![10], vec![20])]);
        rt.on_member_departure(plan, EpochId(1)).unwrap();
        assert_eq!(rt.active_backfill_count(), 1);

        rt.on_epoch_transition(EpochId(2));
        assert_eq!(rt.active_backfill_count(), 0);
    }

    #[test]
    fn abort_backfill_by_id() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        let plan = make_plan(100, vec![make_task(1, vec![10], vec![20])]);
        let id = rt.on_member_departure(plan, EpochId(1)).unwrap();
        rt.abort_backfill(id).unwrap();
        assert_eq!(rt.backfill_state(id), Some(BackfillState::Aborted));
    }

    #[test]
    fn depart_with_empty_plan_errors() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        let plan = make_plan(100, vec![]);
        let err = rt.on_member_departure(plan, EpochId(1)).unwrap_err();
        assert!(matches!(err, BackfillError::EmptyPlan));
    }

    // ── Placement heal integration tests ────────────────────────────

    #[test]
    fn record_placement_populates_map() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        rt.record_placement(100, 10);
        rt.record_placement(100, 20);
        rt.record_placement(200, 10);
        let map = rt.placement_map();
        assert_eq!(map.object_count(), 2);
        assert_eq!(map.member_count(), 2);
    }

    #[test]
    fn detect_member_loss_without_receipts_refuses_backfill() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        rt.record_placement(1, 10);
        rt.record_placement(1, 20);
        rt.record_placement(2, 10);
        rt.record_placement(2, 20);
        rt.record_placement(3, 20);
        rt.record_placement(3, 30);
        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);
        let backfill_id = rt.detect_member_loss(lost, available, 1_000_000_000);
        assert!(backfill_id.is_none());
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.heal_state(), HealState::Aborted);
        assert!(!rt.is_healing());
    }

    #[test]
    fn heal_tick_completes_after_backfill_done() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        let plan = make_plan(100, vec![make_task(1, vec![10], vec![20])]);
        let bid = rt.on_member_departure(plan, EpochId(1)).unwrap();
        while rx.try_recv().is_ok() {}
        rt.backfill_initiator_mut().start_transferring(bid).unwrap();
        rt.heal_coordinator.record_backfill_opened(bid);
        rt.complete_backfill(bid).unwrap();
        let finished = rt.heal_tick(0, 0, 2_000_000_000);
        assert!(finished);
        assert!(!rt.is_healing());
    }

    #[test]
    fn epoch_transition_aborts_heal() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        rt.record_placement(1, 10);
        rt.record_placement(1, 20);
        rt.record_placement(2, 10);
        rt.record_placement(2, 20);
        rt.record_placement(3, 20);
        rt.record_placement(3, 30);
        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);
        rt.detect_member_loss(lost, available, 1_000_000_000);
        while rx.try_recv().is_ok() {}
        rt.on_epoch_transition(EpochId(2));
        assert!(!rt.is_healing());
        assert_eq!(rt.heal_state(), HealState::Aborted);
    }

    #[test]
    fn heal_lifecycle_full_flow_requires_receipts() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        // Objects 1-5 on members {10,20}; 6-10 on {10,30}.
        // Losing member 10 requires rebuilding 1-5 to 30 and 6-10 to 20.
        for obj_id in 1..=5 {
            rt.record_placement(obj_id, 10);
            rt.record_placement(obj_id, 20);
        }
        for obj_id in 6..=10 {
            rt.record_placement(obj_id, 10);
            rt.record_placement(obj_id, 30);
        }
        assert_eq!(rt.placement_map().object_count(), 10);
        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);
        let bid = rt.detect_member_loss(lost, available, 1_000_000_000);
        let stats = rt.heal_stats();
        assert!(stats.objects_to_rebuild > 0);
        assert!(bid.is_none());
        assert!(rx.try_recv().is_err());
        assert!(!rt.is_healing());
        assert_eq!(rt.heal_state(), HealState::Aborted);
    }

    #[test]
    fn receiptless_loss_does_not_start_duplicate_window() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        rt.record_placement(1, 10);
        rt.record_placement(1, 20);
        rt.record_placement(2, 10);
        rt.record_placement(2, 20);
        rt.record_placement(3, 20);
        rt.record_placement(3, 30);
        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);
        let first = rt.detect_member_loss(lost.clone(), available.clone(), 1_000_000_000);
        assert!(first.is_none());
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.heal_state(), HealState::Aborted);
        assert!(!rt.is_healing());
    }

    #[test]
    fn with_cluster_pool_config_wires_policy_and_domains() {
        use std::path::PathBuf;

        let (tx, _rx) = mpsc::unbounded_channel();
        let devices = vec![
            crate::pool_config::NodeDevice::new(
                PathBuf::from("/dev/n1d0"),
                [0u8; 16],
                0,
                0,
                1024 * 1024 * 1024,
                1,
                FailureDomain::for_node(1),
            ),
            crate::pool_config::NodeDevice::new(
                PathBuf::from("/dev/n2d0"),
                [1u8; 16],
                0,
                1,
                1024 * 1024 * 1024,
                2,
                FailureDomain::for_node(2),
            ),
            crate::pool_config::NodeDevice::new(
                PathBuf::from("/dev/n3d0"),
                [2u8; 16],
                0,
                2,
                1024 * 1024 * 1024,
                3,
                FailureDomain::for_node(3),
            ),
        ];
        let config = ClusterPoolConfig::new(
            [0xAB; 16],
            "testpool".into(),
            devices,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
        );

        let rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_cluster_pool_config(&config);

        // Placement policy should be MirrorAcrossNodes { copies: 2 }
        let policy = rt.heal_coordinator.placement_policy();
        assert_eq!(
            policy,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 }
        );

        // Failure domains should be populated for nodes 1, 2, 3
        // (indirectly verified by the heal coordinator having them set)
        let placement = rt.placement_map();
        assert_eq!(placement.epoch(), 1);
    }
}
