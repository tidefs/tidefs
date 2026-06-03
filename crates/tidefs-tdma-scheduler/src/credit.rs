//! Credit-based transmit scheduling with weighted fair queuing.
//!
//! Every node has a [`CreditAccount`] that tracks available bandwidth credits
//! via a token-bucket model. The [`CreditScheduler`] allocates slots within an
//! epoch proportionally to configured node weights, producing a deterministic
//! [`SlotTable`] of [`BandwidthSlot`] entries.

use std::collections::HashMap;

use crate::config::TdmaConfig;

// ---------------------------------------------------------------------------
// Bandwidth slot
// ---------------------------------------------------------------------------

/// A single transmit slot within an epoch, owned by one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandwidthSlot {
    /// Node that may transmit during this slot.
    pub node_id: u64,
    /// Nanosecond offset from the start of the epoch.
    pub offset_ns: u64,
    /// Duration of this slot in nanoseconds.
    pub duration_ns: u64,
    /// Maximum bytes the holder may transmit in this slot.
    pub max_bytes: u64,
}

// ---------------------------------------------------------------------------
// Slot table
// ---------------------------------------------------------------------------

/// An ordered ring of bandwidth slots covering one full epoch.
#[derive(Debug, Clone)]
pub struct SlotTable {
    /// Monotonically increasing epoch identifier.
    pub epoch_id: u64,
    /// Slots in time order (ascending `offset_ns`).
    pub slots: Vec<BandwidthSlot>,
}

impl SlotTable {
    /// Create an empty slot table for the given epoch.
    pub fn new(epoch_id: u64) -> Self {
        Self {
            epoch_id,
            slots: Vec::new(),
        }
    }

    /// Number of slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// True when no slots are allocated.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Total bytes allocated across all slots.
    pub fn total_bytes(&self) -> u64 {
        self.slots.iter().map(|s| s.max_bytes).sum()
    }

    /// Total duration covered by this table in nanoseconds.
    pub fn total_duration_ns(&self) -> u64 {
        self.slots.iter().map(|s| s.duration_ns).sum()
    }
}

// ---------------------------------------------------------------------------
// Credit account
// ---------------------------------------------------------------------------

/// Per-node token-bucket credit account.
///
/// Credits are refilled proportionally to the node's weight at each epoch
/// boundary and consumed as slots are allocated.
#[derive(Debug, Clone)]
pub struct CreditAccount {
    /// Node identifier.
    pub node_id: u64,
    /// Configured scheduling weight (higher = more bandwidth).
    pub weight: u32,
    /// Current credit balance in bytes (may be negative for debt).
    pub credits: i64,
    /// Maximum credits this account may accumulate (prevents hoarding).
    pub max_credits: i64,
}

impl CreditAccount {
    /// Create a new credit account with the given weight and zero balance.
    pub fn new(node_id: u64, weight: u32, max_credits: i64) -> Self {
        Self {
            node_id,
            weight,
            credits: 0,
            max_credits,
        }
    }

    /// Refill credits at epoch start proportional to weight.
    ///
    /// `total_weight` is the sum of all node weights; `total_bytes` is the
    /// total bandwidth budget for the epoch.
    pub fn refill(&mut self, total_weight: u32, total_bytes: u64) {
        if total_weight == 0 {
            return;
        }
        let share = (self.weight as u64)
            .saturating_mul(total_bytes)
            .checked_div(total_weight as u64)
            .unwrap_or(0);
        self.credits = self
            .credits
            .saturating_add_unsigned(share)
            .min(self.max_credits);
    }

    /// Try to consume `bytes` of credit. Returns true if sufficient.
    pub fn consume(&mut self, bytes: u64) -> bool {
        let b = bytes as i64;
        if self.credits >= b {
            self.credits -= b;
            true
        } else {
            false
        }
    }

    /// Force-consume bytes even if credits go negative (debt).
    pub fn consume_forced(&mut self, bytes: u64) {
        self.credits = self.credits.saturating_sub_unsigned(bytes);
    }

    /// Check whether the account can afford `bytes`.
    pub fn can_afford(&self, bytes: u64) -> bool {
        self.credits >= bytes as i64
    }

    // ── Transport debit/credit operations ──────────────────────────────

    /// Debit credits on send (transport-level bandwidth enforcement).
    ///
    /// Returns `false` if the debit would push the account past the
    /// overdraft limit, rejecting the send.
    #[must_use]
    pub fn debit_on_send(&mut self, bytes: u64, overdraft_limit: i64) -> bool {
        if overdraft_limit >= 0 {
            // No overdraft allowed: must have sufficient credits.
            return self.consume(bytes);
        }
        let after = self.credits.saturating_sub_unsigned(bytes);
        if after < overdraft_limit {
            return false;
        }
        self.credits = after;
        true
    }

    /// Credit account on acknowledgment from the peer.
    ///
    /// Replenishes credits up to [`Self::max_credits`].
    pub fn credit_on_ack(&mut self, bytes: u64) {
        self.credits = self
            .credits
            .saturating_add_unsigned(bytes)
            .min(self.max_credits);
    }

    /// Check whether the account is currently in overdraft (credits < 0).
    #[must_use]
    pub fn is_overdraft(&self) -> bool {
        self.credits < 0
    }

    /// Run a periodic credit-replenishment tick.
    ///
    /// Adds `bytes_per_tick` credits, capped at [`Self::max_credits`].
    pub fn replenish_tick(&mut self, bytes_per_tick: u64) {
        self.credits = self
            .credits
            .saturating_add_unsigned(bytes_per_tick)
            .min(self.max_credits);
    }
}

// ---------------------------------------------------------------------------
// Credit scheduler
// ---------------------------------------------------------------------------

/// Holds per-node credit state and drives weighted-fair-queuing slot
/// allocation.
pub struct CreditScheduler {
    config: TdmaConfig,
    accounts: HashMap<u64, CreditAccount>,
}

/// Errors from credit scheduler operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreditSchedulerError {
    #[error("no nodes registered for scheduling")]
    NoNodes,

    #[error("node {0} not found in credit state")]
    NodeNotFound(u64),
}

impl CreditScheduler {
    /// Create a new credit scheduler with the given configuration.
    pub fn new(config: TdmaConfig) -> Self {
        Self {
            config,
            accounts: HashMap::new(),
        }
    }

    /// Return a reference to the configuration.
    pub fn config(&self) -> &TdmaConfig {
        &self.config
    }

    /// Register or update a node's weight.
    pub fn set_node_weight(&mut self, node_id: u64, weight: u32) {
        let max_credits = (self.config.total_bandwidth_bytes_per_epoch as i64).saturating_mul(2);
        self.accounts
            .entry(node_id)
            .and_modify(|a| a.weight = weight)
            .or_insert_with(|| CreditAccount::new(node_id, weight, max_credits));
    }

    /// Remove a node from the scheduler.
    pub fn remove_node(&mut self, node_id: u64) {
        self.accounts.remove(&node_id);
    }

    /// Return the number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.accounts.len()
    }

    /// Get a reference to a node's credit account.
    pub fn account(&self, node_id: u64) -> Option<&CreditAccount> {
        self.accounts.get(&node_id)
    }

    /// Refill all accounts for the start of an epoch.
    pub fn refill_all(&mut self) {
        let total_weight: u32 = self.accounts.values().map(|a| a.weight).sum();
        for account in self.accounts.values_mut() {
            account.refill(total_weight, self.config.total_bandwidth_bytes_per_epoch);
        }
    }

    /// Allocate a full epoch's slot table using deterministic weighted fair
    /// queuing.
    ///
    /// Each slot consumes `bytes_per_slot` credits from the assigned node.
    /// Allocation proceeds in rounds: each node's deficit is incremented by
    /// its weight each round; when deficit exceeds the quantum (total weight),
    /// the node receives a slot and deficit decreases. When a node exhausts
    /// credits or the epoch is full, allocation stops.
    ///
    /// Returns a [`SlotTable`] with slots ordered by time offset.
    pub fn allocate_epoch(&mut self, epoch_id: u64) -> Result<SlotTable, CreditSchedulerError> {
        if self.accounts.is_empty() {
            return Err(CreditSchedulerError::NoNodes);
        }

        let bytes_per_slot = self.config.bytes_per_slot();
        let slots_per_epoch = self.config.slots_per_epoch() as usize;
        let duration_per_slot = self.config.slot_granularity_ns;

        if slots_per_epoch == 0 {
            return Ok(SlotTable::new(epoch_id));
        }

        // Refill credits at epoch start.
        self.refill_all();

        // Collect node ids sorted for deterministic output.
        let mut node_ids: Vec<u64> = self.accounts.keys().copied().collect();
        node_ids.sort_unstable();

        let mut slot_table = SlotTable::new(epoch_id);

        let total_weight: u32 = self.accounts.values().map(|a| a.weight).sum();
        let quantum = total_weight;

        // Per-node deficit for WFQ.
        let mut deficits: HashMap<u64, u32> = node_ids.iter().map(|&id| (id, 0u32)).collect();

        let mut allocated = 0usize;
        // Node is exhausted when its credits fall below one slot's cost.
        let mut exhausted: HashMap<u64, bool> = node_ids.iter().map(|&id| (id, false)).collect();

        // WFQ main loop: each iteration is one round. Deficit increases by
        // weight, and any node whose deficit reaches or exceeds the quantum
        // drains as many slots as credits permit.
        loop {
            if allocated >= slots_per_epoch {
                break;
            }

            let mut any_viable = false;

            for &node_id in &node_ids {
                if allocated >= slots_per_epoch {
                    break;
                }
                if *exhausted.get(&node_id).unwrap_or(&false) {
                    continue;
                }

                // Increment deficit by this node's weight.
                let weight = self.accounts[&node_id].weight;
                *deficits.get_mut(&node_id).unwrap() += weight;

                // Drain deficit: allocate one slot per quantum of deficit
                // while credits remain sufficient.
                while allocated < slots_per_epoch && deficits[&node_id] >= quantum {
                    let account = self.accounts.get_mut(&node_id).unwrap();
                    if bytes_per_slot > 0 && account.credits < bytes_per_slot as i64 {
                        exhausted.insert(node_id, true);
                        break;
                    }

                    *deficits.get_mut(&node_id).unwrap() -= quantum;
                    if bytes_per_slot > 0 {
                        account.credits -= bytes_per_slot as i64;
                    }

                    let offset_ns = allocated as u64 * duration_per_slot;
                    slot_table.slots.push(BandwidthSlot {
                        node_id,
                        offset_ns,
                        duration_ns: duration_per_slot,
                        max_bytes: bytes_per_slot,
                    });
                    allocated += 1;
                }

                if !*exhausted.get(&node_id).unwrap_or(&false) {
                    any_viable = true;
                }
            }

            // Only fall back to round-robin debt distribution when every
            // node has exhausted its credits and cannot afford another slot.
            if !any_viable {
                let mut idx = 0usize;
                while allocated < slots_per_epoch && !node_ids.is_empty() {
                    let node_id = node_ids[idx % node_ids.len()];
                    let account = self.accounts.get_mut(&node_id).unwrap();
                    if bytes_per_slot > 0 {
                        account.credits = account.credits.saturating_sub_unsigned(bytes_per_slot);
                    }

                    let offset_ns = allocated as u64 * duration_per_slot;
                    slot_table.slots.push(BandwidthSlot {
                        node_id,
                        offset_ns,
                        duration_ns: duration_per_slot,
                        max_bytes: bytes_per_slot,
                    });
                    allocated += 1;
                    idx += 1;
                }
                break;
            }
        }

        Ok(slot_table)
    }

    /// Access the raw accounts map (for inspection/testing).
    pub fn accounts(&self) -> &HashMap<u64, CreditAccount> {
        &self.accounts
    }
}

// ---------------------------------------------------------------------------
// SlotAllocator (convenience wrapper)
// ---------------------------------------------------------------------------

/// High-level slot allocator that produces a [`SlotTable`] for a full epoch.
///
/// Thin wrapper around [`CreditScheduler`] exposed as the primary entry point
/// for callers that only need epoch-level allocation.
pub struct SlotAllocator {
    scheduler: CreditScheduler,
}

impl SlotAllocator {
    /// Create a new allocator with the given config.
    pub fn new(config: TdmaConfig) -> Self {
        Self {
            scheduler: CreditScheduler::new(config),
        }
    }

    /// Register a node with the given weight.
    pub fn register_node(&mut self, node_id: u64, weight: u32) {
        self.scheduler.set_node_weight(node_id, weight);
    }

    /// Allocate slots for one epoch. The returned [`SlotTable`] is
    /// deterministic: given the same config, weights, and epoch boundary
    /// state, repeated calls produce identical results.
    pub fn allocate_epoch(&mut self, epoch_id: u64) -> Result<SlotTable, CreditSchedulerError> {
        self.scheduler.allocate_epoch(epoch_id)
    }

    /// Return a reference to the inner scheduler.
    pub fn scheduler(&self) -> &CreditScheduler {
        &self.scheduler
    }

    /// Return a mutable reference to the inner scheduler.
    pub fn scheduler_mut(&mut self) -> &mut CreditScheduler {
        &mut self.scheduler
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TdmaConfig {
        TdmaConfig {
            epoch_duration_us: 1000,   // 1_000_000 ns
            slot_granularity_ns: 1000, // 1000 slots
            default_weight: 100,
            total_bandwidth_bytes_per_epoch: 1_000_000, // 1 MB
        }
    }

    // --- CreditAccount ---

    #[test]
    fn credit_account_new_zero_balance() {
        let a = CreditAccount::new(1, 100, 1000);
        assert_eq!(a.node_id, 1);
        assert_eq!(a.weight, 100);
        assert_eq!(a.credits, 0);
        assert_eq!(a.max_credits, 1000);
    }

    #[test]
    fn refill_proportional() {
        let mut a = CreditAccount::new(1, 100, 1_000_000);
        a.refill(400, 1_000_000); // 100/400 * 1M = 250K
        assert_eq!(a.credits, 250_000);
    }

    #[test]
    fn refill_capped_at_max() {
        let mut a = CreditAccount::new(1, 100, 100);
        a.refill(100, 1_000_000); // 100% * 1M = 1M, capped at 100
        assert_eq!(a.credits, 100);
    }

    #[test]
    fn refill_zero_total_weight_noop() {
        let mut a = CreditAccount::new(1, 100, 1000);
        a.credits = 50;
        a.refill(0, 1_000_000);
        assert_eq!(a.credits, 50);
    }

    #[test]
    fn consume_sufficient() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 500;
        assert!(a.consume(400));
        assert_eq!(a.credits, 100);
    }

    #[test]
    fn consume_insufficient() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 300;
        assert!(!a.consume(500));
        assert_eq!(a.credits, 300);
    }

    #[test]
    fn consume_forced_goes_negative() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 100;
        a.consume_forced(500);
        assert_eq!(a.credits, -400);
    }

    #[test]
    fn can_afford_boundary() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 500;
        assert!(a.can_afford(500));
        assert!(!a.can_afford(501));
    }

    // --- SlotTable ---

    #[test]
    fn slot_table_empty() {
        let t = SlotTable::new(7);
        assert_eq!(t.epoch_id, 7);
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.total_bytes(), 0);
        assert_eq!(t.total_duration_ns(), 0);
    }

    #[test]
    fn slot_table_with_slots() {
        let mut t = SlotTable::new(1);
        t.slots.push(BandwidthSlot {
            node_id: 10,
            offset_ns: 0,
            duration_ns: 1000,
            max_bytes: 500,
        });
        t.slots.push(BandwidthSlot {
            node_id: 20,
            offset_ns: 1000,
            duration_ns: 1000,
            max_bytes: 500,
        });
        assert_eq!(t.len(), 2);
        assert_eq!(t.total_bytes(), 1000);
        assert_eq!(t.total_duration_ns(), 2000);
    }

    // --- CreditScheduler ---

    #[test]
    fn empty_no_nodes_errors() {
        let mut s = CreditScheduler::new(test_config());
        let err = s.allocate_epoch(1).unwrap_err();
        assert!(matches!(err, CreditSchedulerError::NoNodes));
    }

    #[test]
    fn single_node_full_bandwidth() {
        let mut s = CreditScheduler::new(test_config());
        s.set_node_weight(10, 100);
        let table = s.allocate_epoch(1).unwrap();
        assert_eq!(table.len(), 1000);
        for slot in &table.slots {
            assert_eq!(slot.node_id, 10);
            assert_eq!(slot.duration_ns, 1000);
            assert_eq!(slot.max_bytes, 1000);
        }
        for (i, slot) in table.slots.iter().enumerate() {
            assert_eq!(slot.offset_ns, i as u64 * 1000);
        }
    }

    #[test]
    fn two_node_equal_split() {
        let mut s = CreditScheduler::new(test_config());
        s.set_node_weight(10, 100);
        s.set_node_weight(20, 100);
        let table = s.allocate_epoch(1).unwrap();
        assert_eq!(table.slots.len(), 1000);
        let n10 = table.slots.iter().filter(|s| s.node_id == 10).count();
        let n20 = table.slots.iter().filter(|s| s.node_id == 20).count();
        assert_eq!(n10, 500);
        assert_eq!(n20, 500);
    }

    #[test]
    fn weighted_unequal_split() {
        let mut s = CreditScheduler::new(test_config());
        s.set_node_weight(10, 300);
        s.set_node_weight(20, 100); // 75/25
        let table = s.allocate_epoch(1).unwrap();
        let n10 = table.slots.iter().filter(|s| s.node_id == 10).count();
        let n20 = table.slots.iter().filter(|s| s.node_id == 20).count();
        assert_eq!(n10, 750);
        assert_eq!(n20, 250);
    }

    #[test]
    fn deterministic_output() {
        let mut s1 = CreditScheduler::new(test_config());
        s1.set_node_weight(10, 100);
        s1.set_node_weight(20, 200);
        let t1 = s1.allocate_epoch(1).unwrap();

        let mut s2 = CreditScheduler::new(test_config());
        s2.set_node_weight(10, 100);
        s2.set_node_weight(20, 200);
        let t2 = s2.allocate_epoch(1).unwrap();

        assert_eq!(t1.slots.len(), t2.slots.len());
        for (a, b) in t1.slots.iter().zip(t2.slots.iter()) {
            assert_eq!(a.node_id, b.node_id);
            assert_eq!(a.offset_ns, b.offset_ns);
        }
    }

    #[test]
    fn node_removal() {
        let mut s = CreditScheduler::new(test_config());
        s.set_node_weight(10, 100);
        s.set_node_weight(20, 100);
        assert_eq!(s.node_count(), 2);
        s.remove_node(20);
        assert_eq!(s.node_count(), 1);
        let table = s.allocate_epoch(1).unwrap();
        assert!(table.slots.iter().all(|s| s.node_id == 10));
    }

    #[test]
    fn refill_all_respects_max() {
        let config = TdmaConfig {
            total_bandwidth_bytes_per_epoch: 1_000_000,
            ..test_config()
        };
        let mut s = CreditScheduler::new(config);
        s.set_node_weight(10, 100);
        s.refill_all();
        assert_eq!(s.account(10).unwrap().credits, 1_000_000);
        s.refill_all();
        // capped at 2x total_bandwidth
        assert_eq!(s.account(10).unwrap().credits, 2_000_000);
    }

    // --- SlotAllocator ---

    #[test]
    fn allocator_roundtrip() {
        let mut alloc = SlotAllocator::new(test_config());
        alloc.register_node(10, 100);
        alloc.register_node(20, 100);
        let table = alloc.allocate_epoch(1).unwrap();
        assert_eq!(table.slots.len(), 1000);
        assert_eq!(table.epoch_id, 1);
        let n10 = table.slots.iter().filter(|s| s.node_id == 10).count();
        let n20 = table.slots.iter().filter(|s| s.node_id == 20).count();
        assert!(n10 > 0);
        assert!(n20 > 0);
        assert_eq!(n10 + n20, 1000);
    }

    #[test]
    fn allocator_no_nodes_errors() {
        let mut alloc = SlotAllocator::new(test_config());
        let err = alloc.allocate_epoch(1).unwrap_err();
        assert!(matches!(err, CreditSchedulerError::NoNodes));
    }

    #[test]
    fn zero_bytes_per_slot_allocation() {
        // When bandwidth is smaller than slots, bytes_per_slot = 0.
        let config = TdmaConfig {
            total_bandwidth_bytes_per_epoch: 500,
            epoch_duration_us: 1000,
            slot_granularity_ns: 1000,
            ..Default::default()
        };
        let mut alloc = SlotAllocator::new(config);
        alloc.register_node(10, 100);
        let table = alloc.allocate_epoch(1).unwrap();
        assert_eq!(table.slots.len(), 1000);
        // Every slot has 0 max_bytes since 500 / 1000 = 0.
        for slot in &table.slots {
            assert_eq!(slot.max_bytes, 0);
        }
    }

    #[test]
    fn credit_exhaustion_fallback_distributes_remaining() {
        // Give a tiny budget so both nodes exhaust credits quickly.
        let config = TdmaConfig {
            epoch_duration_us: 1000,
            slot_granularity_ns: 1000,
            total_bandwidth_bytes_per_epoch: 5000, // 5 bytes/slot * 1000 slots
            ..Default::default()
        };
        let mut alloc = SlotAllocator::new(config);
        alloc.register_node(10, 100);
        alloc.register_node(20, 100);
        let table = alloc.allocate_epoch(1).unwrap();
        // Should still fill all 1000 slots (fallback round-robin after exhaustion).
        assert_eq!(table.slots.len(), 1000);
        // Credits should be negative or zero.
        let credits_10 = alloc.scheduler().account(10).unwrap().credits;
        let credits_20 = alloc.scheduler().account(20).unwrap().credits;
        // 5000 total / 2 nodes = 2500 each, minus 1000 * 5 = -2500 each
        assert!(credits_10 <= 0);
        assert!(credits_20 <= 0);
    }

    #[test]
    fn epoch_wrap_around_second_epoch() {
        let mut alloc = SlotAllocator::new(test_config());
        alloc.register_node(10, 100);
        alloc.register_node(20, 100);

        let t1 = alloc.allocate_epoch(1).unwrap();
        let t2 = alloc.allocate_epoch(2).unwrap();

        // Both epochs should be full and identical (deterministic).
        assert_eq!(t1.slots.len(), 1000);
        assert_eq!(t2.slots.len(), 1000);
        for (a, b) in t1.slots.iter().zip(t2.slots.iter()) {
            assert_eq!(a.node_id, b.node_id);
            assert_eq!(a.offset_ns, b.offset_ns);
        }
    }

    #[test]
    fn node_weight_update_between_epochs() {
        let mut alloc = SlotAllocator::new(test_config());
        alloc.register_node(10, 100);
        alloc.register_node(20, 100);

        let t1 = alloc.allocate_epoch(1).unwrap();
        let n10_epoch1 = t1.slots.iter().filter(|s| s.node_id == 10).count();
        assert_eq!(n10_epoch1, 500);

        // Change weight: 10 gets 3x bandwidth of 20.
        alloc.scheduler_mut().set_node_weight(10, 300);
        alloc.scheduler_mut().set_node_weight(20, 100);

        let t2 = alloc.allocate_epoch(2).unwrap();
        let n10_epoch2 = t2.slots.iter().filter(|s| s.node_id == 10).count();
        assert_eq!(n10_epoch2, 750);
    }

    // --- debit_on_send / credit_on_ack / overdraft ---

    #[test]
    fn debit_on_send_with_sufficient_credits() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 500;
        assert!(a.debit_on_send(300, -1000));
        assert_eq!(a.credits, 200);
    }

    #[test]
    fn debit_on_send_with_overdraft_limit_rejects_excessive() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 500;
        // overdraft_limit = -200: max debit = 500 + 200 = 700, but 800 > 700
        assert!(!a.debit_on_send(800, -200));
        assert_eq!(a.credits, 500); // unchanged
    }

    #[test]
    fn debit_on_send_with_overdraft_limit_allows_within_bound() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 500;
        // overdraft_limit = -200: max debit = 700
        assert!(a.debit_on_send(700, -200));
        assert_eq!(a.credits, -200);
    }

    #[test]
    fn debit_on_send_no_overdraft_allowed() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 500;
        // overdraft_limit = 0 means no overdraft ever
        assert!(a.debit_on_send(500, 0));
        assert!(!a.debit_on_send(1, 0));
    }

    #[test]
    fn credit_on_ack_replenishes() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 300;
        a.credit_on_ack(200);
        assert_eq!(a.credits, 500);
    }

    #[test]
    fn credit_on_ack_capped_at_max() {
        let mut a = CreditAccount::new(1, 100, 100);
        a.credits = 80;
        a.credit_on_ack(50);
        assert_eq!(a.credits, 100);
    }

    #[test]
    fn is_overdraft_detects_negative() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = -1;
        assert!(a.is_overdraft());
        a.credits = 0;
        assert!(!a.is_overdraft());
        a.credits = 100;
        assert!(!a.is_overdraft());
    }

    #[test]
    fn replenish_tick_adds_bytes() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 200;
        a.replenish_tick(100);
        assert_eq!(a.credits, 300);
    }

    #[test]
    fn replenish_tick_capped_at_max() {
        let mut a = CreditAccount::new(1, 100, 1000);
        a.credits = 950;
        a.replenish_tick(200);
        assert_eq!(a.credits, 1000);
    }

    #[test]
    fn debit_then_credit_cycle_consistency() {
        let mut a = CreditAccount::new(1, 100, 10000);
        a.credits = 1000;

        // Send 400 bytes
        assert!(a.debit_on_send(400, -500));
        assert_eq!(a.credits, 600);

        // Ack 400 bytes
        a.credit_on_ack(400);
        assert_eq!(a.credits, 1000);

        // Multiple debit/credit cycles
        for _ in 0..5 {
            assert!(a.debit_on_send(200, -500));
            assert!(!a.is_overdraft());
            a.credit_on_ack(200);
        }
        assert_eq!(a.credits, 1000);
    }
}
