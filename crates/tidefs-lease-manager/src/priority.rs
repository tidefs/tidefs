use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

/// Priority level for lease scheduling and inheritance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeasePriority {
    Background = 0,
    Normal = 1,
    Elevated = 2,
    High = 3,
    Critical = 4,
}

impl Default for LeasePriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Priority inheritance state for lock chains.
///
/// When a high-priority waiter is blocked on a lock held by a low-priority
/// holder, the holder's priority is temporarily boosted to the waiter's level.
/// This prevents priority inversion in the lease system.
#[derive(Clone, Debug, Default)]
pub struct PriorityInheritance {
    base_priorities: BTreeMap<MemberId, LeasePriority>,
    effective_priorities: BTreeMap<MemberId, LeasePriority>,
    /// Per-lease: highest priority waiter blocked on this lease.
    lease_max_waiter_prio: BTreeMap<u64, LeasePriority>,
    /// Per-lease: the holder of this lease (for boost propagation).
    lease_holder: BTreeMap<u64, MemberId>,
}

impl PriorityInheritance {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the base priority for a holder.
    pub fn set_base_priority(&mut self, holder: MemberId, priority: LeasePriority) {
        self.base_priorities.insert(holder, priority);
        self.recompute_effective(holder);
    }

    /// Get the effective priority for a holder (base + inherited boost).
    pub fn effective_priority(&self, holder: MemberId) -> LeasePriority {
        self.effective_priorities
            .get(&holder)
            .copied()
            .unwrap_or(LeasePriority::Normal)
    }

    /// Register a lease as held by `holder`.
    pub fn register_lease(&mut self, lease_id: u64, holder: MemberId) {
        self.lease_holder.insert(lease_id, holder);
    }

    /// Unregister a lease (e.g. on release/revoke).
    pub fn unregister_lease(&mut self, lease_id: u64) {
        if let Some(holder) = self.lease_holder.remove(&lease_id) {
            self.lease_max_waiter_prio.remove(&lease_id);
            self.recompute_effective(holder);
        }
    }

    /// Register a waiter blocked on `blocked_lease_id`.
    ///
    /// The holder of `blocked_lease_id` gets its effective priority boosted
    /// to at least `waiter_priority` (priority inheritance).
    pub fn register_waiter(&mut self, blocked_lease_id: u64, waiter_priority: LeasePriority) {
        let current = self
            .lease_max_waiter_prio
            .get(&blocked_lease_id)
            .copied()
            .unwrap_or(LeasePriority::Background);

        if waiter_priority > current {
            self.lease_max_waiter_prio
                .insert(blocked_lease_id, waiter_priority);
        }

        // Boost the lease holder
        if let Some(&holder) = self.lease_holder.get(&blocked_lease_id) {
            self.recompute_effective(holder);
        }
    }

    /// Unregister a waiter from a lease.
    pub fn unregister_waiter(&mut self, blocked_lease_id: u64) {
        // Recompute max waiter priority for remaining waiters
        // (simplified: just remove; full impl would track individual waiters)
        self.lease_max_waiter_prio.remove(&blocked_lease_id);

        if let Some(&holder) = self.lease_holder.get(&blocked_lease_id) {
            self.recompute_effective(holder);
        }
    }

    /// Clear all state for a holder (e.g. on node failure).
    pub fn clear_holder(&mut self, holder: MemberId) {
        self.base_priorities.remove(&holder);
        self.effective_priorities.remove(&holder);

        // Remove all leases held by this holder
        let dead_leases: Vec<u64> = self
            .lease_holder
            .iter()
            .filter(|(_, &h)| h == holder)
            .map(|(&lid, _)| lid)
            .collect();
        for lid in dead_leases {
            self.lease_holder.remove(&lid);
            self.lease_max_waiter_prio.remove(&lid);
        }
    }

    /// Reset all inheritance state.
    pub fn reset(&mut self) {
        self.base_priorities.clear();
        self.effective_priorities.clear();
        self.lease_max_waiter_prio.clear();
        self.lease_holder.clear();
    }

    // ── Internal ────────────────────────────────────────────────────

    fn recompute_effective(&mut self, holder: MemberId) {
        let base = self
            .base_priorities
            .get(&holder)
            .copied()
            .unwrap_or(LeasePriority::Normal);

        // Find max waiter priority across all leases held by this holder
        let mut inherited = LeasePriority::Background;
        for (&lease_id, &prio) in &self.lease_max_waiter_prio {
            if self.lease_holder.get(&lease_id) == Some(&holder) {
                inherited = inherited.max(prio);
            }
        }

        self.effective_priorities
            .insert(holder, base.max(inherited));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // ── LeasePriority ordering ──────────────────────────────────────

    #[test]
    fn test_lease_priority_ordering() {
        assert!(LeasePriority::Background < LeasePriority::Normal);
        assert!(LeasePriority::Normal < LeasePriority::Elevated);
        assert!(LeasePriority::Elevated < LeasePriority::High);
        assert!(LeasePriority::High < LeasePriority::Critical);
    }

    #[test]
    fn test_lease_priority_default_is_normal() {
        assert_eq!(LeasePriority::default(), LeasePriority::Normal);
    }

    #[test]
    fn test_lease_priority_max() {
        assert_eq!(
            LeasePriority::Background.max(LeasePriority::Critical),
            LeasePriority::Critical
        );
        assert_eq!(
            LeasePriority::High.max(LeasePriority::Normal),
            LeasePriority::High
        );
    }

    // ── PriorityInheritance basic ───────────────────────────────────

    #[test]
    fn test_priority_inheritance_basic() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Normal);
        pi.set_base_priority(m(2), LeasePriority::High);

        // Holder 1 holds lease 10
        pi.register_lease(10, m(1));

        // Waiter at High priority blocks on lease 10
        pi.register_waiter(10, LeasePriority::High);

        // Holder 1 should be boosted to High
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);
    }

    #[test]
    fn test_priority_inheritance_unregister() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Background);
        pi.register_lease(10, m(1));

        pi.register_waiter(10, LeasePriority::Critical);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Critical);

        pi.unregister_waiter(10);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Background);
    }

    #[test]
    fn test_priority_inheritance_clear_holder() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Normal);
        pi.set_base_priority(m(2), LeasePriority::High);
        pi.register_lease(10, m(1));

        pi.register_waiter(10, LeasePriority::High);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);

        pi.clear_holder(m(2));
        // Holder 2 cleared, but holder 1 still boosted by remaining waiter
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);

        pi.clear_holder(m(1));
        // Holder 1 cleared entirely
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Normal);
    }

    #[test]
    fn test_priority_multiple_waiters_max_wins() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Background);
        pi.register_lease(10, m(1));

        pi.register_waiter(10, LeasePriority::Normal);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Normal);

        pi.register_waiter(10, LeasePriority::Critical);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Critical);
    }

    #[test]
    fn test_default_priority() {
        let pi = PriorityInheritance::new();
        assert_eq!(pi.effective_priority(m(99)), LeasePriority::Normal);
    }

    #[test]
    fn test_unregister_lease_drops_boost() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Background);
        pi.register_lease(10, m(1));
        pi.register_waiter(10, LeasePriority::Critical);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Critical);

        pi.unregister_lease(10);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Background);
    }

    // ── PriorityInheritance: multi-holder, multi-lease ──────────────

    #[test]
    fn test_multiple_holders_independent_boosting() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Background);
        pi.set_base_priority(m(2), LeasePriority::Background);

        pi.register_lease(10, m(1));
        pi.register_lease(20, m(2));

        // Boost holder 1 only
        pi.register_waiter(10, LeasePriority::Critical);

        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Critical);
        assert_eq!(pi.effective_priority(m(2)), LeasePriority::Background);
    }

    #[test]
    fn test_multi_lease_holder_boosted_by_any_held_lease() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Background);
        pi.register_lease(10, m(1));
        pi.register_lease(20, m(1));

        // Waiter on lease 10 — both leases held by m(1), so m(1) boosted
        pi.register_waiter(10, LeasePriority::High);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);
    }

    #[test]
    fn test_unregister_one_lease_preserves_other_boost() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Background);
        pi.register_lease(10, m(1));
        pi.register_lease(20, m(1));

        pi.register_waiter(10, LeasePriority::High);
        pi.register_waiter(20, LeasePriority::Critical);

        // Holder boosted to Critical (max across both leases)
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Critical);

        // Unregister lease 20 (drops Critical boost) but lease 10 still High
        pi.unregister_lease(20);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);

        // Unregister lease 10, back to base
        pi.unregister_lease(10);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Background);
    }

    #[test]
    fn test_waiter_cannot_lower_boost() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Normal);
        pi.register_lease(10, m(1));

        // Boost to High
        pi.register_waiter(10, LeasePriority::High);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);

        // Lower-priority waiter does not reduce the boost
        pi.register_waiter(10, LeasePriority::Normal);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);
    }

    #[test]
    fn test_clear_holder_on_unknown_holder_is_noop() {
        let mut pi = PriorityInheritance::new();
        // Should not panic
        pi.clear_holder(m(999));
    }

    #[test]
    fn test_reset_clears_all_state() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Critical);
        pi.set_base_priority(m(2), LeasePriority::High);
        pi.register_lease(10, m(1));
        pi.register_waiter(10, LeasePriority::Critical);

        pi.reset();

        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Normal);
        assert_eq!(pi.effective_priority(m(2)), LeasePriority::Normal);
    }

    #[test]
    fn test_set_base_priority_overwrites_previous() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Normal);

        // Overwrite with different priority
        pi.set_base_priority(m(1), LeasePriority::Critical);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Critical);
    }

    #[test]
    fn test_base_priority_persists_after_waiter_unregistered() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::Elevated);
        pi.register_lease(10, m(1));
        pi.register_waiter(10, LeasePriority::Critical);

        // Boosted to Critical
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Critical);

        pi.unregister_waiter(10);
        // Should return to Elevated (base), not Normal (default)
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::Elevated);
    }

    #[test]
    fn test_effective_priority_at_least_base() {
        let mut pi = PriorityInheritance::new();
        pi.set_base_priority(m(1), LeasePriority::High);
        pi.register_lease(10, m(1));

        // Even with Background waiter, effective stays at base (High)
        pi.register_waiter(10, LeasePriority::Background);
        assert_eq!(pi.effective_priority(m(1)), LeasePriority::High);
    }
}
