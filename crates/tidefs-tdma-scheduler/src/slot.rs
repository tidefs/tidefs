//! TDMA slot types: state machine, slot descriptor, and allocation result.

use serde::{Deserialize, Serialize};

/// The state of a TDMA time slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotState {
    /// Allocated but not yet active (clock hasn't reached `slot_start`).
    Pending,
    /// Currently active; holder may perform writes.
    Active,
    /// Holder released the slot before expiry.
    Complete,
    /// Slot expired without being released; holder timed out.
    Expired,
}

impl SlotState {
    /// Returns true if this state is terminal (Complete or Expired).
    pub fn is_terminal(self) -> bool {
        matches!(self, SlotState::Complete | SlotState::Expired)
    }
}

/// A single TDMA time slot allocated to a node for a specific object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdmaSlot {
    /// The node that holds this slot (MemberId).
    pub node_id: u64,
    /// The object this slot covers (inode, block, or generic object id).
    pub object_id: u64,
    /// Slot start wall-clock time in milliseconds.
    pub slot_start: u64,
    /// Slot end wall-clock time in milliseconds.
    pub slot_end: u64,
    /// Current slot state.
    pub state: SlotState,
}

impl TdmaSlot {
    /// Create a new pending slot.
    pub fn new_pending(node_id: u64, object_id: u64, slot_start: u64, slot_end: u64) -> Self {
        Self {
            node_id,
            object_id,
            slot_start,
            slot_end,
            state: SlotState::Pending,
        }
    }

    /// Check if the slot is stale (expired) at the given time.
    pub fn is_stale(&self, now_millis: u64) -> bool {
        now_millis >= self.slot_end && !self.state.is_terminal()
    }

    /// Check if the slot is currently active at the given time.
    pub fn is_active_at(&self, now_millis: u64) -> bool {
        !self.state.is_terminal() && now_millis >= self.slot_start && now_millis < self.slot_end
    }

    /// Duration of the slot in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.slot_end.saturating_sub(self.slot_start)
    }
}

/// Result of a slot allocation request.
#[derive(Debug, Clone)]
pub struct SlotAllocation {
    /// The allocated slot.
    pub slot: TdmaSlot,
    /// When the next slot for this object begins (0 if no queued requests).
    pub next_slot_at: u64,
}

// ---------------------------------------------------------------------------
// Transport-level TDMA slot FSM
// ---------------------------------------------------------------------------

/// Transport-level bandwidth-slot lifecycle state.
///
/// The canonical FSM for a transport TDMA slot:
///
/// ```text
/// Free ──allocate()──▶ Allocated ──activate()──▶ Active
///   ▲                                              │
///   │                    ┌─────────────────────────┘
///   │                    ▼
///   ◀──────────free()── Draining ◀────drain()
/// ```
///
/// Valid transitions:
/// - `Free → Allocated` (allocate)
/// - `Allocated → Active` (activate)
/// - `Active → Draining` (drain)
/// - `Draining → Free` (free)
/// - `Free → Free` (free is idempotent on Free)
///
/// All other transitions return [`TransportSlotError::InvalidTransition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSlotState {
    /// Slot is available for allocation.
    Free,
    /// Slot has been assigned to a transport session but is not yet active.
    Allocated {
        /// Transport session that owns this slot.
        session_id: u64,
    },
    /// Slot is actively carrying data for its session.
    Active {
        /// Transport session that owns this slot.
        session_id: u64,
    },
    /// Slot is draining in-flight data before release.
    Draining {
        /// Transport session that owns this slot.
        session_id: u64,
    },
}

impl TransportSlotState {
    /// Returns `true` if the slot is available for allocation.
    pub fn is_free(self) -> bool {
        matches!(self, TransportSlotState::Free)
    }

    /// Returns `true` if the slot is currently active (carrying data).
    pub fn is_active(self) -> bool {
        matches!(self, TransportSlotState::Active { .. })
    }

    /// Returns the session ID assigned to this slot, if any.
    pub fn session_id(self) -> Option<u64> {
        match self {
            TransportSlotState::Free => None,
            TransportSlotState::Allocated { session_id }
            | TransportSlotState::Active { session_id }
            | TransportSlotState::Draining { session_id } => Some(session_id),
        }
    }
}

/// Errors from transport-slot FSM transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSlotError {
    /// An invalid FSM transition was attempted.
    InvalidTransition {
        /// The state before the transition was attempted.
        from: TransportSlotState,
        /// The target state name.
        to: &'static str,
    },
    /// The slot is not in the expected state for the operation.
    WrongState {
        expected: &'static str,
        actual: TransportSlotState,
    },
}

impl core::fmt::Display for TransportSlotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportSlotError::InvalidTransition { from, to } => {
                write!(f, "invalid transport slot FSM transition: {from:?} → {to}")
            }
            TransportSlotError::WrongState { expected, actual } => {
                write!(
                    f,
                    "transport slot in wrong state: expected {expected}, got {actual:?}"
                )
            }
        }
    }
}

/// A transport-bandwidth TDMA slot with lifecycle FSM.
///
/// Each slot represents a fixed-size time quantum (offset + duration) with a
/// byte capacity (`max_bytes`). The slot progresses through a lifecycle:
/// `Free → Allocated → Active → Draining → Free`, driven by the transport
/// scheduler.
#[derive(Debug, Clone)]
pub struct TransportSlot {
    /// Monotonic slot index within the epoch.
    pub slot_index: u64,
    /// Current FSM state.
    pub state: TransportSlotState,
    /// Maximum bytes that may be transmitted in this slot.
    pub max_bytes: u64,
    /// Nanosecond offset from the start of the epoch.
    pub offset_ns: u64,
    /// Duration of this slot in nanoseconds.
    pub duration_ns: u64,
}

impl TransportSlot {
    /// Create a new free transport slot.
    pub fn new(slot_index: u64, max_bytes: u64, offset_ns: u64, duration_ns: u64) -> Self {
        Self {
            slot_index,
            state: TransportSlotState::Free,
            max_bytes,
            offset_ns,
            duration_ns,
        }
    }

    /// Allocate this slot to a transport session.
    ///
    /// Valid only from [`TransportSlotState::Free`].
    pub fn allocate(&mut self, session_id: u64) -> Result<(), TransportSlotError> {
        if !self.state.is_free() {
            return Err(TransportSlotError::InvalidTransition {
                from: self.state,
                to: "Allocated",
            });
        }
        self.state = TransportSlotState::Allocated { session_id };
        Ok(())
    }

    /// Activate the slot so data may begin flowing.
    ///
    /// Valid only from [`TransportSlotState::Allocated`].
    pub fn activate(&mut self) -> Result<(), TransportSlotError> {
        match self.state {
            TransportSlotState::Allocated { session_id } => {
                self.state = TransportSlotState::Active { session_id };
                Ok(())
            }
            _ => Err(TransportSlotError::InvalidTransition {
                from: self.state,
                to: "Active",
            }),
        }
    }

    /// Begin draining the slot (in-flight data may complete).
    ///
    /// Valid only from [`TransportSlotState::Active`].
    pub fn drain(&mut self) -> Result<(), TransportSlotError> {
        match self.state {
            TransportSlotState::Active { session_id } => {
                self.state = TransportSlotState::Draining { session_id };
                Ok(())
            }
            _ => Err(TransportSlotError::InvalidTransition {
                from: self.state,
                to: "Draining",
            }),
        }
    }

    /// Release the slot back to the free pool.
    ///
    /// Valid from [`TransportSlotState::Draining`] or [`TransportSlotState::Free`]
    /// (idempotent on Free).
    pub fn free(&mut self) -> Result<(), TransportSlotError> {
        match self.state {
            TransportSlotState::Draining { .. } | TransportSlotState::Free => {
                self.state = TransportSlotState::Free;
                Ok(())
            }
            _ => Err(TransportSlotError::InvalidTransition {
                from: self.state,
                to: "Free",
            }),
        }
    }

    /// Return the session ID assigned to this slot, if any.
    pub fn session_id(&self) -> Option<u64> {
        self.state.session_id()
    }
}

// ---------------------------------------------------------------------------
// Transport-slot table for epoch-level slot lookup
// ---------------------------------------------------------------------------

/// A table of transport slots, indexed by slot position for O(log n) lookup.
#[derive(Debug, Clone, Default)]
pub struct TransportSlotTable {
    slots: std::collections::BTreeMap<u64, TransportSlot>,
}

impl TransportSlotTable {
    /// Create an empty slot table.
    pub fn new() -> Self {
        Self {
            slots: std::collections::BTreeMap::new(),
        }
    }

    /// Insert a slot into the table.
    pub fn insert(&mut self, slot: TransportSlot) {
        self.slots.insert(slot.slot_index, slot);
    }

    /// Look up a slot by its index.
    pub fn get(&self, slot_index: u64) -> Option<&TransportSlot> {
        self.slots.get(&slot_index)
    }

    /// Look up a slot mutably by its index.
    pub fn get_mut(&mut self, slot_index: u64) -> Option<&mut TransportSlot> {
        self.slots.get_mut(&slot_index)
    }

    /// Return the number of slots in the table.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Return true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Iterate over all slots in index order.
    pub fn iter(&self) -> impl Iterator<Item = &TransportSlot> {
        self.slots.values()
    }
}

#[cfg(test)]
mod transport_slot_tests {
    use super::*;

    // --- TransportSlotState ---

    #[test]
    fn free_state_is_free() {
        assert!(TransportSlotState::Free.is_free());
    }

    #[test]
    fn allocated_state_is_not_free() {
        assert!(!TransportSlotState::Allocated { session_id: 1 }.is_free());
    }

    #[test]
    fn active_state_is_active() {
        assert!(TransportSlotState::Active { session_id: 5 }.is_active());
    }

    #[test]
    fn free_state_is_not_active() {
        assert!(!TransportSlotState::Free.is_active());
    }

    #[test]
    fn session_id_returns_none_for_free() {
        assert_eq!(TransportSlotState::Free.session_id(), None);
    }

    #[test]
    fn session_id_returns_some_for_allocated() {
        assert_eq!(
            TransportSlotState::Allocated { session_id: 42 }.session_id(),
            Some(42)
        );
    }

    #[test]
    fn session_id_returns_some_for_draining() {
        assert_eq!(
            TransportSlotState::Draining { session_id: 99 }.session_id(),
            Some(99)
        );
    }

    // --- TransportSlot FSM: valid transitions ---

    fn test_slot() -> TransportSlot {
        TransportSlot::new(0, 1024, 0, 1000)
    }

    #[test]
    fn fsm_free_to_allocated() {
        let mut s = test_slot();
        s.allocate(10).unwrap();
        assert_eq!(s.state, TransportSlotState::Allocated { session_id: 10 });
        assert_eq!(s.session_id(), Some(10));
    }

    #[test]
    fn fsm_allocated_to_active() {
        let mut s = test_slot();
        s.allocate(10).unwrap();
        s.activate().unwrap();
        assert_eq!(s.state, TransportSlotState::Active { session_id: 10 });
    }

    #[test]
    fn fsm_active_to_draining() {
        let mut s = test_slot();
        s.allocate(10).unwrap();
        s.activate().unwrap();
        s.drain().unwrap();
        assert_eq!(s.state, TransportSlotState::Draining { session_id: 10 });
    }

    #[test]
    fn fsm_draining_to_free() {
        let mut s = test_slot();
        s.allocate(10).unwrap();
        s.activate().unwrap();
        s.drain().unwrap();
        s.free().unwrap();
        assert_eq!(s.state, TransportSlotState::Free);
        assert_eq!(s.session_id(), None);
    }

    #[test]
    fn fsm_free_to_free_is_idempotent() {
        let mut s = test_slot();
        s.free().unwrap();
        assert_eq!(s.state, TransportSlotState::Free);
    }

    // --- TransportSlot FSM: invalid transitions ---

    #[test]
    fn fsm_free_to_draining_invalid() {
        let mut s = test_slot();
        let err = s.drain().unwrap_err();
        assert!(matches!(err, TransportSlotError::InvalidTransition { .. }));
    }

    #[test]
    fn fsm_free_to_activate_invalid() {
        let mut s = test_slot();
        let err = s.activate().unwrap_err();
        assert!(matches!(err, TransportSlotError::InvalidTransition { .. }));
    }

    #[test]
    fn fsm_active_to_free_invalid() {
        let mut s = test_slot();
        s.allocate(10).unwrap();
        s.activate().unwrap();
        let err = s.free().unwrap_err();
        assert!(matches!(err, TransportSlotError::InvalidTransition { .. }));
    }

    #[test]
    fn fsm_active_to_allocated_invalid() {
        let mut s = test_slot();
        s.allocate(10).unwrap();
        s.activate().unwrap();
        let err = s.allocate(20).unwrap_err();
        assert!(matches!(err, TransportSlotError::InvalidTransition { .. }));
    }

    #[test]
    fn fsm_allocated_to_free_invalid() {
        let mut s = test_slot();
        s.allocate(10).unwrap();
        let err = s.free().unwrap_err();
        assert!(matches!(err, TransportSlotError::InvalidTransition { .. }));
    }

    #[test]
    fn session_id_preserved_through_full_lifecycle() {
        let mut s = test_slot();
        s.allocate(77).unwrap();
        assert_eq!(s.session_id(), Some(77));
        s.activate().unwrap();
        assert_eq!(s.session_id(), Some(77));
        s.drain().unwrap();
        assert_eq!(s.session_id(), Some(77));
        s.free().unwrap();
        assert_eq!(s.session_id(), None);
    }

    // --- TransportSlotTable ---

    #[test]
    fn table_insert_and_get() {
        let mut t = TransportSlotTable::new();
        let slot = TransportSlot::new(3, 512, 3000, 1000);
        t.insert(slot);
        assert!(t.get(3).is_some());
        assert_eq!(t.get(3).unwrap().max_bytes, 512);
        assert_eq!(t.get(3).unwrap().slot_index, 3);
    }

    #[test]
    fn table_get_nonexistent() {
        let t = TransportSlotTable::new();
        assert!(t.get(999).is_none());
    }

    #[test]
    fn table_get_mut_allows_fsm_transition() {
        let mut t = TransportSlotTable::new();
        t.insert(TransportSlot::new(0, 1024, 0, 1000));

        let slot = t.get_mut(0).unwrap();
        slot.allocate(42).unwrap();
        assert_eq!(slot.session_id(), Some(42));
    }

    #[test]
    fn table_len_and_is_empty() {
        let mut t = TransportSlotTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        t.insert(TransportSlot::new(0, 100, 0, 1000));
        assert!(!t.is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn table_iter_yields_all_slots() {
        let mut t = TransportSlotTable::new();
        t.insert(TransportSlot::new(1, 100, 1000, 500));
        t.insert(TransportSlot::new(0, 200, 0, 500));
        t.insert(TransportSlot::new(2, 300, 2000, 500));
        let indices: Vec<u64> = t.iter().map(|s| s.slot_index).collect();
        assert_eq!(indices, vec![0, 1, 2]);
    }
}
