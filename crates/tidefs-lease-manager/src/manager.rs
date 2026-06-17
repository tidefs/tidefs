use std::collections::BTreeMap;
use std::sync::Arc;
use tidefs_cache_coherency::CoherencyEventBus;
use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseError, LeaseGrant, LeaseLifecycle};
use tidefs_lease::{LeaseMessage, LeaseMessageCodec, LeaseProtocolError};
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

/// Configuration for the distributed lease manager.
#[derive(Clone, Debug)]
pub struct LeaseManagerConfig {
    pub default_term_millis: u64,
    pub grace_period_millis: u64,
    pub witness_quorum: usize,
    pub witness_total: usize,
    pub max_leases_per_holder: usize,
    pub renewal_advance_fraction: u8,
    pub priority_inheritance_enabled: bool,
    pub current_mount_identity: DatasetMountIdentity,
}

impl Default for LeaseManagerConfig {
    fn default() -> Self {
        Self {
            default_term_millis: 30_000,
            grace_period_millis: 5_000,
            witness_quorum: 3,
            witness_total: 5,
            max_leases_per_holder: 4096,
            renewal_advance_fraction: 4,
            priority_inheritance_enabled: true,
            current_mount_identity: DatasetMountIdentity::ZERO,
        }
    }
}

/// Errors returned by the lease manager.
#[derive(Debug, thiserror::Error)]
pub enum LeaseManagerError {
    #[error("lease {0} not found")]
    NotFound(u64),
    #[error("lease {0} already exists")]
    Duplicate(u64),
    #[error("lease {0} is in terminal state {1:?}")]
    Terminal(u64, LeaseLifecycle),
    #[error("lease {0} has expired")]
    Expired(u64),
    #[error("insufficient witness confirmations: {0}/{1}")]
    InsufficientWitnesses(usize, usize),
    #[error("holder {0:?} has exceeded max lease count {1}")]
    HolderAtCapacity(MemberId, usize),
    #[error("conflict with existing lease {0}")]
    Conflict(u64),
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

/// Operational statistics for the lease manager.
#[derive(Clone, Copy, Debug, Default)]
pub struct ManagerStats {
    pub grants_total: u64,
    pub grants_active: u64,
    pub revocations_total: u64,
    pub renewals_total: u64,
    pub expirations_total: u64,
    pub node_failure_revocations: u64,
    pub conflicts_detected: u64,
}

/// Distributed lease manager with GRANT/REVOKE/RENEW lifecycle.
#[derive(Debug)]
pub struct LeaseManager {
    config: LeaseManagerConfig,
    grants: BTreeMap<u64, LeaseGrant>,
    holder_index: BTreeMap<MemberId, Vec<u64>>,
    domain_index: BTreeMap<DomainKey, u64>,
    next_lease_id: u64,
    current_epoch: EpochId,
    current_mount_identity: DatasetMountIdentity,
    stats: ManagerStats,
    /// Optional coherency event bus for dispatching cache invalidation
    /// when leases are revoked (mmap coherency integration).
    coherency_bus: Option<Arc<CoherencyEventBus>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DomainKey {
    Subtree {
        dataset_id: u64,
        prefix: String,
    },
    Inode {
        dataset_id: u64,
        ino: u64,
    },
    ByteRange {
        dataset_id: u64,
        ino: u64,
        start: u64,
        end: u64,
    },
    Other(u64),
}

impl From<&LeaseDomain> for DomainKey {
    fn from(d: &LeaseDomain) -> Self {
        match d {
            LeaseDomain::Subtree { dataset_id, prefix } => Self::Subtree {
                dataset_id: *dataset_id,
                prefix: prefix.clone(),
            },
            LeaseDomain::Inode { dataset_id, ino } => Self::Inode {
                dataset_id: *dataset_id,
                ino: *ino,
            },
            LeaseDomain::ByteRange {
                dataset_id,
                ino,
                start,
                end,
            } => Self::ByteRange {
                dataset_id: *dataset_id,
                ino: *ino,
                start: *start,
                end: *end,
            },
            _ => Self::Other(0),
        }
    }
}

impl LeaseManager {
    pub fn new(config: LeaseManagerConfig, current_epoch: EpochId) -> Self {
        let mount = config.current_mount_identity;
        Self {
            config,
            grants: BTreeMap::new(),
            holder_index: BTreeMap::new(),
            domain_index: BTreeMap::new(),
            next_lease_id: 1,
            current_epoch,
            current_mount_identity: mount,
            stats: ManagerStats::default(),
            coherency_bus: None,
        }
    }

    /// Set the coherency event bus for dispatching cache invalidation
    /// when leases are revoked (mmap coherency integration).
    pub fn set_coherency_bus(&mut self, bus: Arc<CoherencyEventBus>) {
        self.coherency_bus = Some(bus);
    }

    pub fn config(&self) -> &LeaseManagerConfig {
        &self.config
    }
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Return the current dataset mount identity.
    pub fn current_mount_identity(&self) -> DatasetMountIdentity {
        self.current_mount_identity
    }
    pub fn stats(&self) -> &ManagerStats {
        &self.stats
    }
    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    pub fn get_grant(&self, lease_id: u64) -> Option<&LeaseGrant> {
        self.grants.get(&lease_id)
    }

    pub fn holder_leases(&self, holder: MemberId) -> Vec<u64> {
        self.holder_index.get(&holder).cloned().unwrap_or_default()
    }

    pub fn holder_lease_count(&self, holder: MemberId) -> usize {
        self.holder_index.get(&holder).map(|v| v.len()).unwrap_or(0)
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_lease_id;
        self.next_lease_id = self.next_lease_id.wrapping_add(1);
        id
    }

    /// Grant a new lease with quorum-acknowledged acquisition.
    pub fn grant(
        &mut self,
        lease_class: LeaseClass,
        domain: LeaseDomain,
        holder_id: MemberId,
        witness_confirmations: usize,
        now_millis: u64,
    ) -> Result<LeaseGrant, LeaseManagerError> {
        if self.holder_lease_count(holder_id) >= self.config.max_leases_per_holder {
            return Err(LeaseManagerError::HolderAtCapacity(
                holder_id,
                self.config.max_leases_per_holder,
            ));
        }

        if witness_confirmations < self.config.witness_quorum {
            return Err(LeaseManagerError::InsufficientWitnesses(
                witness_confirmations,
                self.config.witness_quorum,
            ));
        }

        // Check domain conflict
        let domain_key = DomainKey::from(&domain);
        if let Some(&existing_id) = self.domain_index.get(&domain_key) {
            if let Some(existing) = self.grants.get(&existing_id) {
                if !existing.lifecycle.is_terminal()
                    && (existing.lease_class.is_exclusive() || lease_class.is_exclusive())
                {
                    self.stats.conflicts_detected += 1;
                    return Err(LeaseManagerError::Conflict(existing_id));
                }
            }
        }

        let lease_id = self.next_id();
        let grant = LeaseGrant::request(
            lease_id,
            lease_class,
            domain,
            holder_id,
            0u64,
            self.config.default_term_millis,
            now_millis,
            self.current_epoch,
            self.current_mount_identity,
            0,
            witness_confirmations,
            self.config.witness_total,
        );

        self.insert_grant(grant.clone());
        self.stats.grants_total += 1;
        self.stats.grants_active += 1;
        Ok(grant)
    }

    /// Grant with explicit ID for Raft replay / snapshot restore.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_with_id(
        &mut self,
        lease_id: u64,
        lease_class: LeaseClass,
        domain: LeaseDomain,
        holder_id: MemberId,
        term_millis: u64,
        witness_confirmations: usize,
        now_millis: u64,
    ) -> Result<LeaseGrant, LeaseManagerError> {
        if self.grants.contains_key(&lease_id) {
            return Err(LeaseManagerError::Duplicate(lease_id));
        }
        if witness_confirmations < self.config.witness_quorum {
            return Err(LeaseManagerError::InsufficientWitnesses(
                witness_confirmations,
                self.config.witness_quorum,
            ));
        }

        let grant = LeaseGrant::request(
            lease_id,
            lease_class,
            domain,
            holder_id,
            0u64,
            term_millis,
            now_millis,
            self.current_epoch,
            self.current_mount_identity,
            0,
            witness_confirmations,
            self.config.witness_total,
        );

        self.insert_grant(grant.clone());
        self.stats.grants_total += 1;
        self.stats.grants_active += 1;
        Ok(grant)
    }

    /// Renew an active lease, extending its expiry.
    pub fn renew(
        &mut self,
        lease_id: u64,
        holder_id: MemberId,
        now_millis: u64,
    ) -> Result<LeaseGrant, LeaseManagerError> {
        let grant = self
            .grants
            .get_mut(&lease_id)
            .ok_or(LeaseManagerError::NotFound(lease_id))?;

        if grant.holder_id != holder_id {
            return Err(LeaseError::HolderMismatch {
                holder_id: holder_id.0,
                lease_holder_id: grant.holder_id.0,
            })?;
        }

        if grant.lifecycle.is_terminal() {
            return Err(LeaseManagerError::Terminal(lease_id, grant.lifecycle));
        }

        let full_expiry = grant
            .expires_at_millis
            .saturating_add(grant.grace_period_millis);
        if now_millis >= full_expiry {
            return Err(LeaseManagerError::Expired(lease_id));
        }

        grant.renew(now_millis)?;
        self.stats.renewals_total += 1;
        Ok(grant.clone())
    }

    /// Release a lease held by `holder_id`.
    pub fn release(&mut self, lease_id: u64, holder_id: MemberId) -> Result<(), LeaseManagerError> {
        let grant = self
            .grants
            .get(&lease_id)
            .ok_or(LeaseManagerError::NotFound(lease_id))?;

        if grant.holder_id != holder_id {
            return Err(LeaseError::HolderMismatch {
                holder_id: holder_id.0,
                lease_holder_id: grant.holder_id.0,
            })?;
        }

        self.remove_grant(lease_id);
        Ok(())
    }

    /// Revoke a lease (authoritative action, not holder-initiated).

    /// Dispatch cache invalidation for a revoked lease's domain.
    ///
    /// When a lease is revoked (due to conflict, node failure, expiry, or
    /// epoch advancement), any cached pages in the lease's byte range must
    /// be invalidated so that subsequent accesses fault and fetch
    /// authoritative data from the new lease holder.
    fn dispatch_invalidation_for_grant(&self, grant: &LeaseGrant) {
        if let Some(ref bus) = self.coherency_bus {
            match &grant.domain {
                LeaseDomain::ByteRange {
                    dataset_id: _,
                    ino,
                    start,
                    end,
                } => {
                    bus.dispatch_range_invalidation(*ino, *start, *end);
                }
                LeaseDomain::Inode { dataset_id: _, ino } => {
                    bus.dispatch_inode_invalidation(*ino);
                }
                // Subtree and EpochTransition leases don't map to
                // byte-range cache invalidation; skip them.
                _ => {}
            }
        }
    }

    /// Revoke an active lease, fencing it and dispatching cache invalidation
    /// for the affected byte range if a coherency bus is configured.
    pub fn revoke(&mut self, lease_id: u64) -> Result<(), LeaseManagerError> {
        let grant_clone = {
            let grant = self
                .grants
                .get_mut(&lease_id)
                .ok_or(LeaseManagerError::NotFound(lease_id))?;

            if grant.lifecycle.is_terminal() {
                return Err(LeaseManagerError::Terminal(lease_id, grant.lifecycle));
            }

            grant.fence()?;
            self.stats.revocations_total += 1;
            self.stats.grants_active = self.stats.grants_active.saturating_sub(1);
            grant.clone()
        }; // mutable borrow of self.grants ends here
        self.dispatch_invalidation_for_grant(&grant_clone);
        Ok(())
    }

    /// Handle node failure: revoke all active leases of the failed node.
    pub fn handle_node_failure(&mut self, failed_node: MemberId) -> Vec<u64> {
        let lease_ids = self
            .holder_index
            .get(&failed_node)
            .cloned()
            .unwrap_or_default();
        let mut revoked = Vec::new();

        for &lease_id in &lease_ids {
            if self.revoke(lease_id).is_ok() {
                revoked.push(lease_id);
                self.stats.node_failure_revocations += 1;
            }
        }
        // dispatch already handled inside revoke()

        for &lid in &revoked {
            self.remove_from_holder_index(failed_node, lid);
        }

        revoked
    }

    /// Sweep and release all stale leases (past term + grace).
    pub fn sweep_expired(&mut self, now_millis: u64) -> Vec<u64> {
        let mut expired = Vec::new();
        let all_ids: Vec<u64> = self.grants.keys().copied().collect();

        for lease_id in all_ids {
            if let Some(grant) = self.grants.get(&lease_id) {
                if !grant.lifecycle.is_terminal() && grant.is_stale(now_millis) {
                    expired.push(lease_id);
                }
            }
        }

        for &lease_id in &expired {
            // Collect grant before removal for invalidation dispatch
            if let Some(grant) = self.grants.get(&lease_id) {
                let g = grant.clone();
                self.dispatch_invalidation_for_grant(&g);
            }
            self.remove_grant(lease_id);
            self.stats.expirations_total += 1;
            self.stats.grants_active = self.stats.grants_active.saturating_sub(1);
        }

        expired
    }

    /// Return IDs of active leases due for renewal.
    pub fn due_for_renewal(&self, now_millis: u64) -> Vec<u64> {
        self.grants
            .values()
            .filter(|g| !g.lifecycle.is_terminal() && g.should_renew(now_millis))
            .map(|g| g.lease_id)
            .collect()
    }

    /// Advance epoch: fence all active leases from prior epochs.
    pub fn advance_epoch(&mut self, new_epoch: EpochId) -> Vec<u64> {
        let mut fenced = Vec::new();
        if new_epoch <= self.current_epoch {
            return fenced;
        }

        let all_ids: Vec<u64> = self.grants.keys().copied().collect();
        for lease_id in all_ids {
            let grant_clone = {
                let grant = match self.grants.get_mut(&lease_id) {
                    Some(g) => g,
                    None => continue,
                };
                if grant.epoch < new_epoch
                    && !grant.lifecycle.is_terminal()
                    && grant.fence().is_ok()
                {
                    fenced.push(lease_id);
                    self.stats.revocations_total += 1;
                    self.stats.grants_active = self.stats.grants_active.saturating_sub(1);
                    Some(grant.clone())
                } else {
                    None
                }
            };
            if let Some(g) = grant_clone {
                self.dispatch_invalidation_for_grant(&g);
            }
        }

        self.current_epoch = new_epoch;
        fenced
    }

    /// Process an incoming lease protocol message and return a response.
    ///
    /// Dispatches Grant (re-grant via id), Renew, and Revoke messages
    /// to the appropriate manager methods and returns a BLAKE3-verified
    /// protocol response.
    pub fn process_message(
        &mut self,
        msg: &LeaseMessage,
        now_millis: u64,
    ) -> Result<LeaseMessage, LeaseProtocolError> {
        match msg {
            LeaseMessage::Grant(grant) => {
                // Re-grant with explicit ID (idempotent replay from Raft).
                match self.grant_with_id(
                    grant.lease_id,
                    grant.lease_class,
                    grant.domain.clone(),
                    grant.holder_id,
                    grant.term_millis,
                    grant.witness_confirmations,
                    now_millis,
                ) {
                    Ok(new_grant) => Ok(LeaseMessage::Grant(new_grant)),
                    Err(LeaseManagerError::Duplicate(id)) => Err(LeaseProtocolError::NotFound(id)),
                    Err(e) => self.map_manager_error(e),
                }
            }
            LeaseMessage::Renew {
                lease_id,
                holder_id,
                ..
            } => {
                // Renew: the epoch in the message is informational;
                // the manager validates via current_epoch internally.
                match self.renew(*lease_id, *holder_id, now_millis) {
                    Ok(renewed) => Ok(LeaseMessage::Grant(renewed)),
                    Err(e) => self.map_manager_error(e),
                }
            }
            LeaseMessage::Revoke { lease_id, .. } => match self.revoke(*lease_id) {
                Ok(()) => Ok(LeaseMessage::Acknowledge {
                    lease_id: *lease_id,
                    success: true,
                    detail: "revoked".into(),
                }),
                Err(e) => self.map_manager_error(e),
            },
            LeaseMessage::Acknowledge { .. } => {
                // Server does not process acknowledgements.
                Err(LeaseProtocolError::NotFound(0))
            }
        }
    }

    /// Encode a lease protocol message to BLAKE3-verified wire format.
    pub fn encode_message(msg: &LeaseMessage) -> Result<Vec<u8>, LeaseProtocolError> {
        LeaseMessageCodec::encode(msg).map_err(LeaseProtocolError::Codec)
    }

    /// Decode and verify a BLAKE3-authenticated lease protocol message.
    pub fn decode_message(bytes: &[u8]) -> Result<LeaseMessage, LeaseProtocolError> {
        LeaseMessageCodec::decode(bytes).map_err(LeaseProtocolError::Codec)
    }

    // Map LeaseManagerError to LeaseProtocolError.
    fn map_manager_error(&self, e: LeaseManagerError) -> Result<LeaseMessage, LeaseProtocolError> {
        Err(match e {
            LeaseManagerError::NotFound(id) => LeaseProtocolError::NotFound(id),
            LeaseManagerError::Duplicate(id) => LeaseProtocolError::NotFound(id),
            LeaseManagerError::Terminal(id, state) => LeaseProtocolError::Terminal(id, state),
            LeaseManagerError::Expired(id) => LeaseProtocolError::Expired(id),
            LeaseManagerError::InsufficientWitnesses(..) => LeaseProtocolError::NotFound(0),
            LeaseManagerError::HolderAtCapacity(..) => LeaseProtocolError::NotFound(0),
            LeaseManagerError::Conflict(id) => LeaseProtocolError::NotFound(id),
            LeaseManagerError::Lease(le) => match le {
                LeaseError::NotFound { lease_id } => LeaseProtocolError::NotFound(lease_id),
                LeaseError::AlreadyTerminal { lease_id, state } => {
                    LeaseProtocolError::Terminal(lease_id, state)
                }
                LeaseError::Expired { lease_id } => LeaseProtocolError::Expired(lease_id),
                LeaseError::HolderMismatch {
                    holder_id,
                    lease_holder_id,
                } => LeaseProtocolError::HolderMismatch(
                    tidefs_membership_epoch::MemberId::new(holder_id),
                    lease_holder_id,
                ),
                _ => LeaseProtocolError::NotFound(0),
            },
        })
    }
    // ── Internal ────────────────────────────────────────────────────

    fn insert_grant(&mut self, grant: LeaseGrant) {
        let lease_id = grant.lease_id;
        let holder = grant.holder_id;
        let domain_key = DomainKey::from(&grant.domain);

        self.domain_index.insert(domain_key, lease_id);
        self.holder_index.entry(holder).or_default().push(lease_id);
        self.grants.insert(lease_id, grant);
    }

    fn remove_grant(&mut self, lease_id: u64) {
        if let Some(grant) = self.grants.remove(&lease_id) {
            let holder = grant.holder_id;
            let key = DomainKey::from(&grant.domain);
            self.domain_index.remove(&key);
            self.remove_from_holder_index(holder, lease_id);
        }
    }

    fn remove_from_holder_index(&mut self, holder: MemberId, lease_id: u64) {
        if let Some(v) = self.holder_index.get_mut(&holder) {
            v.retain(|&id| id != lease_id);
            if v.is_empty() {
                self.holder_index.remove(&holder);
            }
        }
    }
}

// ── MembershipObserver impl ────────────────────────────────────────────

impl crate::membership::MembershipObserver for LeaseManager {
    fn on_membership_event(&mut self, event: &crate::membership::MembershipEvent) -> Vec<u64> {
        match event {
            crate::membership::MembershipEvent::NodeFailed { node_id }
            | crate::membership::MembershipEvent::NodeRemoved { node_id }
            | crate::membership::MembershipEvent::NodeDeparted { node_id } => {
                self.handle_node_failure(*node_id)
            }
            crate::membership::MembershipEvent::EpochAdvanced { new_epoch, .. } => {
                self.advance_epoch(*new_epoch)
            }
        }
    }
}
