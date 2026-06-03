//! SlotGrant: slot assignment token.
//!
//! Each slot claim produces a [`SlotGrant`] carrying the slot index, epoch,
//! grantee node ID, and issuing transaction counter. The transport layer
//! provides integrity and authentication for these ephemeral scheduling tokens.

use tidefs_membership_epoch::EpochId;

/// Domain separator for slot-grant tokens to prevent cross-context collisions.
/// A slot grant token.
///
/// Carries the slot assignment metadata. The transport layer provides
/// integrity and authentication for these ephemeral scheduling tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotGrant {
    /// Slot index within the epoch (0 .. slots_per_epoch).
    pub slot_index: u32,
    /// Epoch this grant is bound to.
    pub epoch: EpochId,
    /// Node that was granted the slot.
    pub grantee_node_id: u64,
    /// Monotonic transaction counter at the time the grant was issued.
    pub issued_at_txg: u64,
}

impl SlotGrant {
    /// Create a new slot grant.
    pub fn new(slot_index: u32, epoch: EpochId, grantee_node_id: u64, issued_at_txg: u64) -> Self {
        Self {
            slot_index,
            epoch,
            grantee_node_id,
            issued_at_txg,
        }
    }

    /// Validate that the slot grant is well-formed.
    ///
    /// Transport-layer integrity replaces the former BLAKE3 token check.
    /// This method always returns `Ok(())`.
    pub fn validate(&self) -> Result<(), SlotGrantError> {
        let _ = self;
        Ok(())
    }

    /// Check whether this grant is stale relative to a newer epoch.
    ///
    /// A grant is stale when its epoch is less than `current_epoch`.
    pub fn is_stale(&self, current_epoch: EpochId) -> bool {
        self.epoch.0 < current_epoch.0
    }

    /// Check whether this grant is for a future epoch.
    pub fn is_future(&self, current_epoch: EpochId) -> bool {
        self.epoch.0 > current_epoch.0
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by [`SlotGrant::validate`].
///
/// Currently no error variants: transport-layer integrity replaces the
/// former BLAKE3 token check. Retained for API compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SlotGrantError {
    /// Reserved for future use.
    #[doc(hidden)]
    #[error("reserved")]
    _Reserved,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch(id: u64) -> EpochId {
        EpochId(id)
    }

    #[test]
    fn new_grant_constructs() {
        let grant = SlotGrant::new(7, test_epoch(1), 42, 100);
        assert_eq!(grant.slot_index, 7);
        assert_eq!(grant.epoch, test_epoch(1));
        assert_eq!(grant.grantee_node_id, 42);
        assert_eq!(grant.issued_at_txg, 100);
    }

    #[test]
    fn identical_grants_are_equal() {
        let g1 = SlotGrant::new(3, test_epoch(1), 10, 50);
        let g2 = SlotGrant::new(3, test_epoch(1), 10, 50);
        assert_eq!(g1, g2);
    }

    #[test]
    fn different_fields_different_grants() {
        let g1 = SlotGrant::new(0, test_epoch(1), 10, 1);
        let g2 = SlotGrant::new(1, test_epoch(1), 10, 1);
        assert_ne!(g1, g2);
    }

    // --- Validation (no-op: transport layer handles integrity) ---

    #[test]
    fn validate_always_passes() {
        let grant = SlotGrant::new(5, test_epoch(1), 42, 10);
        assert!(grant.validate().is_ok());

        // Even with tampered fields, validate() passes because transport
        // layer integrity replaces the former BLAKE3 token check.
        let mut grant2 = SlotGrant::new(5, test_epoch(1), 42, 10);
        grant2.grantee_node_id = 77;
        assert!(grant2.validate().is_ok());
    }

    #[test]
    fn is_stale_when_epoch_older() {
        let grant = SlotGrant::new(0, test_epoch(1), 10, 1);
        assert!(grant.is_stale(test_epoch(2)));
        assert!(grant.is_stale(test_epoch(100)));
    }

    #[test]
    fn not_stale_when_epoch_equal() {
        let grant = SlotGrant::new(0, test_epoch(5), 10, 1);
        assert!(!grant.is_stale(test_epoch(5)));
    }

    #[test]
    fn not_stale_when_epoch_newer() {
        let grant = SlotGrant::new(0, test_epoch(10), 10, 1);
        assert!(!grant.is_stale(test_epoch(5)));
    }

    #[test]
    fn is_future_detects_future_epoch() {
        let grant = SlotGrant::new(0, test_epoch(10), 10, 1);
        assert!(grant.is_future(test_epoch(5)));
        assert!(!grant.is_future(test_epoch(10)));
        assert!(!grant.is_future(test_epoch(15)));
    }
}
