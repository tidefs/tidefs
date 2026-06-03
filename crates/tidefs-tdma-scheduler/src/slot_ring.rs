//! SlotRing: circular buffer of epoch-bound time slots with deterministic
//! round-robin allocation and node-ID-to-slot mapping.
//!
//! The ring divides an epoch into `slots_per_epoch` equal-duration slots,
//! each of which may be claimed by exactly one node. Claims are BLAKE3-
//! authenticated via [`SlotGrant`](super::slot_grant::SlotGrant) tokens.

use std::collections::HashMap;

use tidefs_membership_epoch::EpochId;

use super::slot_grant::{SlotGrant, SlotGrantError};

// ---------------------------------------------------------------------------
// Slot ring configuration
// ---------------------------------------------------------------------------

/// Configuration for a [`SlotRing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRingConfig {
    /// Duration of each slot within an epoch (milliseconds).
    pub slot_duration_ms: u64,
    /// Number of slots in one epoch.
    pub slots_per_epoch: u32,
    /// Maximum grace period after slot expiry during which a late claim
    /// may still be accepted (milliseconds).
    pub max_grace_period_ms: u64,
}

impl Default for SlotRingConfig {
    fn default() -> Self {
        Self {
            slot_duration_ms: 10,
            slots_per_epoch: 1024,
            max_grace_period_ms: 2,
        }
    }
}

impl SlotRingConfig {
    /// Validate the configuration, returning the first error encountered.
    pub fn validate(&self) -> Result<(), SlotRingConfigError> {
        if self.slot_duration_ms == 0 {
            return Err(SlotRingConfigError::SlotDurationZero);
        }
        if self.slots_per_epoch == 0 {
            return Err(SlotRingConfigError::SlotsPerEpochZero);
        }
        Ok(())
    }

    /// Duration of the entire epoch in milliseconds.
    pub fn epoch_duration_ms(&self) -> u64 {
        self.slot_duration_ms * self.slots_per_epoch as u64
    }
}

// ---------------------------------------------------------------------------
// Configuration errors
// ---------------------------------------------------------------------------

/// Errors returned when a [`SlotRingConfig`] is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SlotRingConfigError {
    #[error("slot_duration_ms must be positive")]
    SlotDurationZero,
    #[error("slots_per_epoch must be positive")]
    SlotsPerEpochZero,
}

// ---------------------------------------------------------------------------
// Slot state
// ---------------------------------------------------------------------------

/// State of a single slot within the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    /// Slot has been claimed by the given node.
    Claimed { node_id: u64 },
    /// Slot was claimed but the node released it before expiry.
    Released,
    /// Slot expired without being released.
    Expired,
}

// ---------------------------------------------------------------------------
// Slot ring errors
// ---------------------------------------------------------------------------

/// Errors returned by [`SlotRing`] operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlotRingError {
    #[error("slot {0} is already claimed")]
    SlotAlreadyClaimed(u32),

    #[error("slot {0} is not claimed by node {1}")]
    NotSlotHolder(u32, u64),

    #[error("slot {0} is not in a claimable state")]
    SlotNotClaimable(u32),

    #[error("epoch mismatch: ring at epoch {ring_epoch:?}, operation at {op_epoch:?}")]
    EpochMismatch {
        ring_epoch: EpochId,
        op_epoch: EpochId,
    },

    #[error("no node registered for the ring")]
    NoNodes,

    #[error("node {0} is not registered")]
    NodeNotRegistered(u64),

    #[error("grant validation failed: {0}")]
    GrantValidationFailed(#[from] SlotGrantError),
}

// ---------------------------------------------------------------------------
// Slot ring
// ---------------------------------------------------------------------------

/// A circular buffer of epoch-bound TDMA time slots.
///
/// The ring divides the current epoch into `slots_per_epoch` equal-duration
/// slots. Registered nodes rotate through the ring in deterministic round-
/// robin order. Each slot claim produces a [`SlotGrant`] token that can be
/// BLAKE3-verified by peers to prevent forgery.
///
/// # Epoch binding
///
/// The ring is bound to a specific epoch. When the epoch advances, all
/// in-flight claims are invalidated and the ring resets. An optional grace
/// period allows late claims just past the slot boundary.
#[derive(Debug)]
pub struct SlotRing {
    config: SlotRingConfig,
    epoch: EpochId,
    /// All registered node IDs in insertion order (defines round-robin order).
    nodes: Vec<u64>,
    /// Slot index -> slot state.
    slots: HashMap<u32, SlotState>,
    /// Current round-robin cursor (index into `nodes`).
    cursor: usize,
    /// Monotonic txg counter incremented on every claim/release.
    txg: u64,
}

impl SlotRing {
    /// Create a new slot ring for the given epoch.
    pub fn new(config: SlotRingConfig, epoch: EpochId) -> Result<Self, SlotRingConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            epoch,
            nodes: Vec::new(),
            slots: HashMap::new(),
            cursor: 0,
            txg: 0,
        })
    }

    /// Return a reference to the ring configuration.
    pub fn config(&self) -> &SlotRingConfig {
        &self.config
    }

    /// Return the current epoch.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of currently claimed slots.
    pub fn claimed_slot_count(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, SlotState::Claimed { .. }))
            .count()
    }

    /// Current transaction counter value.
    pub fn txg(&self) -> u64 {
        self.txg
    }

    // ------------------------------------------------------------------
    // Node registration
    // ------------------------------------------------------------------

    /// Register a node for slot allocation.
    ///
    /// Idempotent: if the node is already registered, the call succeeds
    /// without changing round-robin order.
    pub fn register_node(&mut self, node_id: u64) {
        if !self.nodes.contains(&node_id) {
            self.nodes.push(node_id);
        }
    }

    /// Unregister a node. Any slots it currently holds are released.
    pub fn unregister_node(&mut self, node_id: u64) {
        self.nodes.retain(|&id| id != node_id);
        // Release all slots held by this node.
        for (_slot_idx, state) in self.slots.iter_mut() {
            if let SlotState::Claimed { node_id: holder } = state {
                if *holder == node_id {
                    *state = SlotState::Released;
                    self.txg += 1;
                }
            }
        }
        // Adjust cursor if it now points past the end.
        if self.cursor >= self.nodes.len() && !self.nodes.is_empty() {
            self.cursor %= self.nodes.len();
        }
    }

    /// Check whether a node is registered.
    pub fn is_registered(&self, node_id: u64) -> bool {
        self.nodes.contains(&node_id)
    }

    // ------------------------------------------------------------------
    // Slot allocation
    // ------------------------------------------------------------------

    /// Determine the next available slot index and claim it for a node.
    ///
    /// Uses round-robin: picks the next node in `nodes` order, then
    /// finds the next unclaimed slot in the ring. Returns a [`SlotGrant`]
    /// token for BLAKE3-authenticated peer verification.
    ///
    /// Returns `None` when no nodes are registered or all slots are claimed.
    pub fn next_slot(&mut self) -> Option<(u32, SlotGrant)> {
        if self.nodes.is_empty() {
            return None;
        }

        // Find the next node in round-robin order.
        let node_id = self.nodes[self.cursor % self.nodes.len()];
        self.cursor = (self.cursor + 1) % self.nodes.len();

        // Find the next unclaimed slot.
        self.claim_slot_inner(node_id)
    }

    /// Claim a specific slot for a node.
    ///
    /// Returns a [`SlotGrant`] token on success.
    pub fn claim_slot(
        &mut self,
        node_id: u64,
        slot_index: u32,
    ) -> Result<SlotGrant, SlotRingError> {
        if !self.nodes.contains(&node_id) {
            return Err(SlotRingError::NodeNotRegistered(node_id));
        }

        if slot_index >= self.config.slots_per_epoch {
            return Err(SlotRingError::SlotNotClaimable(slot_index));
        }

        match self.slots.get(&slot_index) {
            Some(SlotState::Claimed { .. }) => {
                return Err(SlotRingError::SlotAlreadyClaimed(slot_index));
            }
            Some(SlotState::Expired) | Some(SlotState::Released) => {
                // Allow reclaim of expired/released slots.
            }
            _ => {}
        }

        self.txg += 1;
        self.slots
            .insert(slot_index, SlotState::Claimed { node_id });

        Ok(SlotGrant::new(slot_index, self.epoch, node_id, self.txg))
    }

    /// Internal: allocate the next unclaimed slot for `node_id`.
    fn claim_slot_inner(&mut self, node_id: u64) -> Option<(u32, SlotGrant)> {
        for slot_index in 0..self.config.slots_per_epoch {
            let state = self.slots.get(&slot_index);
            match state {
                None | Some(SlotState::Released) | Some(SlotState::Expired) => {
                    self.txg += 1;
                    self.slots
                        .insert(slot_index, SlotState::Claimed { node_id });
                    let grant = SlotGrant::new(slot_index, self.epoch, node_id, self.txg);
                    return Some((slot_index, grant));
                }
                Some(SlotState::Claimed { .. }) => {
                    continue;
                }
            }
        }
        // All slots are claimed. Try reclaiming an expired slot.
        for slot_index in 0..self.config.slots_per_epoch {
            if let Some(SlotState::Expired) = self.slots.get(&slot_index) {
                self.txg += 1;
                self.slots
                    .insert(slot_index, SlotState::Claimed { node_id });
                let grant = SlotGrant::new(slot_index, self.epoch, node_id, self.txg);
                return Some((slot_index, grant));
            }
        }
        None
    }

    /// Release a slot held by a node.
    ///
    /// The slot becomes available for future claims (state: [`SlotState::Released`]).
    pub fn release_slot(&mut self, node_id: u64, slot_index: u32) -> Result<(), SlotRingError> {
        match self.slots.get(&slot_index) {
            Some(SlotState::Claimed { node_id: holder }) if *holder == node_id => {
                self.slots.insert(slot_index, SlotState::Released);
                self.txg += 1;
                Ok(())
            }
            Some(SlotState::Claimed { .. }) => {
                Err(SlotRingError::NotSlotHolder(slot_index, node_id))
            }
            _ => Err(SlotRingError::SlotNotClaimable(slot_index)),
        }
    }

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    /// Check if a specific node holds a specific slot.
    pub fn is_my_slot(&self, node_id: u64, slot_index: u32) -> bool {
        matches!(
            self.slots.get(&slot_index),
            Some(SlotState::Claimed { node_id: holder }) if *holder == node_id
        )
    }

    /// Return the node that holds a given slot, if claimed.
    pub fn slot_holder(&self, slot_index: u32) -> Option<u64> {
        match self.slots.get(&slot_index) {
            Some(SlotState::Claimed { node_id }) => Some(*node_id),
            _ => None,
        }
    }

    /// Return the slot index assigned to a given node, if any.
    pub fn node_slot(&self, node_id: u64) -> Option<u32> {
        self.slots
            .iter()
            .find(|(_, state)| matches!(state, SlotState::Claimed { node_id: holder } if *holder == node_id))
            .map(|(&idx, _)| idx)
    }

    /// List all claimed slots with their holders.
    pub fn claimed_slots(&self) -> Vec<(u32, u64)> {
        self.slots
            .iter()
            .filter_map(|(&idx, state)| match state {
                SlotState::Claimed { node_id } => Some((idx, *node_id)),
                _ => None,
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Epoch management
    // ------------------------------------------------------------------

    /// Advance to a new epoch, resetting all slot state.
    ///
    /// All in-flight claims are expired. The round-robin cursor is reset.
    /// Returns the number of slots that were drained.
    pub fn advance_epoch(&mut self, new_epoch: EpochId) -> usize {
        let drained = self.claimed_slot_count();
        self.slots.clear();
        self.cursor = 0;
        self.txg = 0;
        self.epoch = new_epoch;
        drained
    }

    /// Expire all slots whose slot-end time is past `now_ms` + grace period.
    ///
    /// Returns the indices of expired slots.
    pub fn expire_stale_slots(&mut self, now_ms: u64) -> Vec<u32> {
        // In a real implementation, this would use wall-clock timing.
        // For now, expire all claimed slots whose slot-end has passed.
        let mut expired = Vec::new();
        let slot_duration = self.config.slot_duration_ms;
        let grace = self.config.max_grace_period_ms;

        for (&slot_index, state) in self.slots.iter_mut() {
            let slot_end_ms = slot_index as u64 * slot_duration + slot_duration;
            if now_ms > slot_end_ms + grace {
                if let SlotState::Claimed { .. } = state {
                    *state = SlotState::Expired;
                    self.txg += 1;
                    expired.push(slot_index);
                }
            }
        }
        expired
    }

    // ------------------------------------------------------------------
    // Grant validation
    // ------------------------------------------------------------------

    /// Validate a [`SlotGrant`] token received from a peer.
    ///
    /// Checks that:
    /// - The BLAKE3 grant token is valid (tamper-proof).
    /// - The grant epoch matches the ring's current epoch.
    /// - The slot is actually claimed by the grantee.
    ///
    /// Returns `Ok(())` if the grant is valid.
    pub fn validate_slot_grant(&self, grant: &SlotGrant) -> Result<(), SlotRingError> {
        // 1. Verify the BLAKE3 token.
        grant.validate()?;

        // 2. Check epoch binding.
        if grant.epoch != self.epoch {
            return Err(SlotRingError::EpochMismatch {
                ring_epoch: self.epoch,
                op_epoch: grant.epoch,
            });
        }

        // 3. Check that the slot is actually held by the grantee.
        match self.slots.get(&grant.slot_index) {
            Some(SlotState::Claimed { node_id }) if *node_id == grant.grantee_node_id => {}
            Some(SlotState::Claimed { .. }) => {
                return Err(SlotRingError::NotSlotHolder(
                    grant.slot_index,
                    grant.grantee_node_id,
                ));
            }
            _ => {
                return Err(SlotRingError::SlotNotClaimable(grant.slot_index));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SlotRingConfig {
        SlotRingConfig {
            slot_duration_ms: 10,
            slots_per_epoch: 16,
            max_grace_period_ms: 2,
        }
    }

    fn test_epoch() -> EpochId {
        EpochId(1)
    }

    fn ring_with_nodes(node_ids: &[u64]) -> SlotRing {
        let mut ring = SlotRing::new(test_config(), test_epoch()).unwrap();
        for &id in node_ids {
            ring.register_node(id);
        }
        ring
    }

    // --- Construction ---

    #[test]
    fn new_ring_empty() {
        let ring = SlotRing::new(test_config(), test_epoch()).unwrap();
        assert_eq!(ring.node_count(), 0);
        assert_eq!(ring.claimed_slot_count(), 0);
        assert_eq!(ring.epoch(), EpochId(1));
    }

    #[test]
    fn zero_slot_duration_rejected() {
        let cfg = SlotRingConfig {
            slot_duration_ms: 0,
            ..test_config()
        };
        assert!(matches!(
            SlotRing::new(cfg, test_epoch()).unwrap_err(),
            SlotRingConfigError::SlotDurationZero
        ));
    }

    #[test]
    fn zero_slots_per_epoch_rejected() {
        let cfg = SlotRingConfig {
            slots_per_epoch: 0,
            ..test_config()
        };
        assert!(matches!(
            SlotRing::new(cfg, test_epoch()).unwrap_err(),
            SlotRingConfigError::SlotsPerEpochZero
        ));
    }

    // --- Node registration ---

    #[test]
    fn register_node_increases_count() {
        let mut ring = SlotRing::new(test_config(), test_epoch()).unwrap();
        ring.register_node(10);
        assert_eq!(ring.node_count(), 1);
        assert!(ring.is_registered(10));
    }

    #[test]
    fn register_node_idempotent() {
        let mut ring = SlotRing::new(test_config(), test_epoch()).unwrap();
        ring.register_node(10);
        ring.register_node(10);
        ring.register_node(10);
        assert_eq!(ring.node_count(), 1);
    }

    #[test]
    fn unregister_node_removes_and_releases_slots() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(10, 0).unwrap();
        assert_eq!(ring.claimed_slot_count(), 1);

        ring.unregister_node(10);
        assert_eq!(ring.node_count(), 1);
        assert!(!ring.is_registered(10));
        assert!(ring.is_registered(20));
        // Slot 0 should be released since holder was unregistered.
        assert_eq!(ring.claimed_slot_count(), 0);
    }

    #[test]
    fn unregister_last_node() {
        let mut ring = ring_with_nodes(&[10]);
        ring.unregister_node(10);
        assert_eq!(ring.node_count(), 0);
        // next_slot should return None when no nodes registered.
        assert!(ring.next_slot().is_none());
    }

    // --- next_slot round-robin ---

    #[test]
    fn next_slot_round_robins_nodes() {
        let mut ring = ring_with_nodes(&[10, 20, 30]);

        let (idx1, grant1) = ring.next_slot().unwrap();
        assert_eq!(grant1.grantee_node_id, 10);
        assert_eq!(idx1, 0);

        let (idx2, grant2) = ring.next_slot().unwrap();
        assert_eq!(grant2.grantee_node_id, 20);
        assert_eq!(idx2, 1);

        let (idx3, grant3) = ring.next_slot().unwrap();
        assert_eq!(grant3.grantee_node_id, 30);
        assert_eq!(idx3, 2);

        // Wraps back to node 10.
        let (_idx4, grant4) = ring.next_slot().unwrap();
        assert_eq!(grant4.grantee_node_id, 10);
    }

    #[test]
    fn next_slot_no_nodes_returns_none() {
        let mut ring = SlotRing::new(test_config(), test_epoch()).unwrap();
        assert!(ring.next_slot().is_none());
    }

    // --- claim_slot ---

    #[test]
    fn claim_specific_slot() {
        let mut ring = ring_with_nodes(&[10, 20]);
        let grant = ring.claim_slot(20, 5).unwrap();
        assert_eq!(grant.slot_index, 5);
        assert_eq!(grant.grantee_node_id, 20);
        assert_eq!(grant.epoch, EpochId(1));
    }

    #[test]
    fn claim_already_claimed_fails() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(10, 3).unwrap();
        let err = ring.claim_slot(20, 3).unwrap_err();
        assert!(matches!(err, SlotRingError::SlotAlreadyClaimed(3)));
    }

    #[test]
    fn claim_unregistered_node_fails() {
        let mut ring = ring_with_nodes(&[10]);
        let err = ring.claim_slot(99, 0).unwrap_err();
        assert!(matches!(err, SlotRingError::NodeNotRegistered(99)));
    }

    #[test]
    fn claim_out_of_bounds_fails() {
        let mut ring = ring_with_nodes(&[10]);
        let err = ring.claim_slot(10, 16).unwrap_err(); // max is 15
        assert!(matches!(err, SlotRingError::SlotNotClaimable(16)));
    }

    // --- release_slot ---

    #[test]
    fn release_claimed_slot() {
        let mut ring = ring_with_nodes(&[10]);
        ring.claim_slot(10, 7).unwrap();
        assert!(ring.is_my_slot(10, 7));

        ring.release_slot(10, 7).unwrap();
        assert!(!ring.is_my_slot(10, 7));
    }

    #[test]
    fn release_slot_wrong_holder_fails() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(10, 4).unwrap();
        let err = ring.release_slot(20, 4).unwrap_err();
        assert!(matches!(err, SlotRingError::NotSlotHolder(4, 20)));
    }

    #[test]
    fn release_unclaimed_slot_fails() {
        let mut ring = ring_with_nodes(&[10]);
        let err = ring.release_slot(10, 9).unwrap_err();
        assert!(matches!(err, SlotRingError::SlotNotClaimable(9)));
    }

    // --- is_my_slot ---

    #[test]
    fn is_my_slot_positive_and_negative() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(10, 2).unwrap();
        ring.claim_slot(20, 5).unwrap();

        assert!(ring.is_my_slot(10, 2));
        assert!(!ring.is_my_slot(10, 5));
        assert!(!ring.is_my_slot(20, 2));
        assert!(ring.is_my_slot(20, 5));
        assert!(!ring.is_my_slot(10, 99));
    }

    // --- Query helpers ---

    #[test]
    fn slot_holder_returns_correct_node() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(10, 0).unwrap();
        assert_eq!(ring.slot_holder(0), Some(10));
        assert_eq!(ring.slot_holder(1), None);
    }

    #[test]
    fn node_slot_finds_assigned_slot() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(20, 12).unwrap();
        assert_eq!(ring.node_slot(20), Some(12));
        assert_eq!(ring.node_slot(10), None);
    }

    #[test]
    fn claimed_slots_lists_all() {
        let mut ring = ring_with_nodes(&[10, 20, 30]);
        ring.claim_slot(10, 0).unwrap();
        ring.claim_slot(20, 3).unwrap();
        ring.claim_slot(30, 7).unwrap();

        let mut claimed = ring.claimed_slots();
        claimed.sort_by_key(|(idx, _)| *idx);
        assert_eq!(claimed, vec![(0, 10), (3, 20), (7, 30)]);
    }

    // --- Epoch transitions ---

    #[test]
    fn advance_epoch_drains_all_slots() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(10, 0).unwrap();
        ring.claim_slot(20, 1).unwrap();
        assert_eq!(ring.claimed_slot_count(), 2);

        let drained = ring.advance_epoch(EpochId(2));
        assert_eq!(drained, 2);
        assert_eq!(ring.claimed_slot_count(), 0);
        assert_eq!(ring.epoch(), EpochId(2));
        assert_eq!(ring.txg(), 0);

        // Round-robin cursor should reset.
        let (_idx, grant) = ring.next_slot().unwrap();
        assert_eq!(grant.grantee_node_id, 10);
    }

    #[test]
    fn epoch_boundary_ring_can_be_claimed_after_advance() {
        let mut ring = ring_with_nodes(&[10, 20]);
        // Fill all 16 slots in epoch 1.
        for i in 0..16 {
            ring.claim_slot(10, i).unwrap();
        }
        // Advance epoch.
        ring.advance_epoch(EpochId(2));
        // All slots should be free again.
        let grant = ring.claim_slot(20, 0).unwrap();
        assert_eq!(grant.epoch, EpochId(2));
    }

    // --- Grant validation ---

    #[test]
    fn validate_valid_grant_succeeds() {
        let mut ring = ring_with_nodes(&[10]);
        let grant = ring.claim_slot(10, 3).unwrap();
        assert!(ring.validate_slot_grant(&grant).is_ok());
    }

    #[test]
    fn validate_epoch_mismatch_rejected() {
        let mut ring = ring_with_nodes(&[10]);
        let mut grant = ring.claim_slot(10, 3).unwrap();
        // Tamper with the epoch.
        grant.epoch = EpochId(99);
        let err = ring.validate_slot_grant(&grant).unwrap_err();
        assert!(matches!(err, SlotRingError::EpochMismatch { .. }));
    }

    #[test]

    fn validate_wrong_holder_rejected() {
        let mut ring = ring_with_nodes(&[10, 20]);
        ring.claim_slot(10, 3).unwrap();
        // Re-claiming an already-claimed slot should fail.
        ring.claim_slot(20, 3).unwrap_err();
        assert!(matches!(
            ring.claim_slot(20, 3).unwrap_err(),
            SlotRingError::SlotAlreadyClaimed(3)
        ));

        // Create a forged grant: claim slot 3 with node 10, then try to
        // validate a grant saying node 20 holds it.
        let mut ring2 = ring_with_nodes(&[10, 20]);
        ring2.claim_slot(10, 3).unwrap();
        // Build a fake grant for node 20 on slot 3.
        let fake_grant = SlotGrant::new(3, test_epoch(), 20, 5);
        let err = ring2.validate_slot_grant(&fake_grant).unwrap_err();
        assert!(matches!(err, SlotRingError::NotSlotHolder(3, 20)));
    }

    #[test]
    fn validate_unclaimed_slot_rejected() {
        let ring = ring_with_nodes(&[10]);
        let grant = SlotGrant::new(7, test_epoch(), 10, 1);
        let err = ring.validate_slot_grant(&grant).unwrap_err();
        assert!(matches!(err, SlotRingError::SlotNotClaimable(7)));
    }

    // --- Stale slot expiry ---

    #[test]
    fn expire_stale_slots_reclaims_past_slots() {
        let mut ring = ring_with_nodes(&[10]);
        ring.claim_slot(10, 0).unwrap(); // slot 0: duration 10ms, end at +10ms
        ring.claim_slot(10, 5).unwrap(); // slot 5: duration 10ms, end at +60ms

        // At time 15ms, slot 0 should be expired (10ms + 2ms grace = 12ms).
        let expired = ring.expire_stale_slots(15);
        assert!(expired.contains(&0));
        assert!(!expired.contains(&5));
        assert_eq!(ring.claimed_slot_count(), 1); // slot 5 still claimed
    }

    #[test]
    fn expire_grace_period_keeps_slot_alive() {
        let mut ring = ring_with_nodes(&[10]);
        ring.claim_slot(10, 0).unwrap(); // slot 0 ends at 10ms, grace 2ms

        // At time 11ms, within grace period, slot 0 still alive.
        let expired = ring.expire_stale_slots(11);
        assert!(expired.is_empty());
        assert_eq!(ring.claimed_slot_count(), 1);
    }

    // --- Determism: same inputs produce same slot ring ---

    #[test]
    fn deterministic_slot_allocation() {
        let run = || {
            let mut ring = ring_with_nodes(&[5, 10, 15]);
            let mut results = Vec::new();
            for _ in 0..16 {
                if let Some((idx, grant)) = ring.next_slot() {
                    results.push((idx, grant.grantee_node_id));
                }
            }
            results
        };

        let r1 = run();
        let r2 = run();
        assert_eq!(r1, r2);
    }

    // --- Slot ring wrap-around fills all slots ---

    #[test]
    fn fills_all_slots_then_stops() {
        let mut ring = ring_with_nodes(&[10]);
        let mut count = 0;
        while let Some((_idx, _grant)) = ring.next_slot() {
            count += 1;
        }
        // Should fill all 16 slots.
        assert_eq!(count, 16);
        // One more attempt returns None.
        assert!(ring.next_slot().is_none());
    }

    // --- Release then reclaim ---

    #[test]
    fn release_allows_reclaim() {
        let mut ring = ring_with_nodes(&[10]);
        ring.claim_slot(10, 3).unwrap();
        ring.release_slot(10, 3).unwrap();

        // Reclaim the released slot.
        let grant = ring.claim_slot(10, 3).unwrap();
        assert_eq!(grant.slot_index, 3);
    }
}
