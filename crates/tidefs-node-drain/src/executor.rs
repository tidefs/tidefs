// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::drain::{DrainError, DrainProgress, DrainStage, NodeDrain};
use tidefs_lease::lock_table::LockTable;
use tidefs_lease::types::LockOwner;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// DrainOps trait — abstraction over cluster services a drain needs
// ---------------------------------------------------------------------------

/// Operations that the [`DrainExecutor`] calls to interact with live cluster
/// services. Production implementations wire these to placement, cache, and
/// admin services. Test implementations use mocks.
pub trait DrainOps {
    /// Return the set of lease IDs owned by a node.
    fn lease_ids_for_node(&self, node_id: MemberId) -> Vec<u64>;

    /// Release a specific lease by ID.
    fn release_lease(&mut self, lease_id: u64) -> Result<(), String>;

    /// Number of objects (primary replicas) stored on a node.
    fn object_count_for_node(&self, node_id: MemberId) -> u64;

    /// Number of cache bytes held by a node.
    fn cache_bytes_for_node(&self, node_id: MemberId) -> u64;

    /// Migrate one object off the node. Returns true if more objects remain.
    fn migrate_one_object(&mut self, node_id: MemberId) -> Result<bool, String>;

    /// Invalidate a chunk of cache, up to max_bytes. Returns (bytes_invalidated, bytes_remaining).
    fn invalidate_cache_chunk(
        &mut self,
        node_id: MemberId,
        max_bytes: u64,
    ) -> Result<(u64, u64), String>;

    /// Transfer admin responsibility from one node to another.
    fn transfer_admin(&mut self, from: MemberId, to: MemberId) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// LockTableDrainOps — production implementation backed by LockTable
// ---------------------------------------------------------------------------

/// Production [`DrainOps`] backed by a [`LockTable`].
///
/// Lease enumeration and release delegate to the lock table. Data, cache, and
/// admin operations are stubbed — they return "not yet wired" until the
/// placement-runtime and cache services are integrated.
pub struct LockTableDrainOps<'a> {
    lock_table: &'a mut LockTable,
    /// Target node to receive migrated admin roles.
    admin_target: MemberId,
}

impl<'a> LockTableDrainOps<'a> {
    #[must_use]
    pub fn admin_target(&self) -> MemberId {
        self.admin_target
    }
    pub fn new(lock_table: &'a mut LockTable, admin_target: MemberId) -> Self {
        Self {
            lock_table,
            admin_target,
        }
    }
}

impl DrainOps for LockTableDrainOps<'_> {
    fn lease_ids_for_node(&self, node_id: MemberId) -> Vec<u64> {
        let owner = LockOwner {
            node_id,
            pid: 0,
            owner_key: 0,
        };
        self.lock_table.owner_lease_ids(&owner)
    }

    fn release_lease(&mut self, lease_id: u64) -> Result<(), String> {
        // Check if the lease exists
        if self.lock_table.get_grant(lease_id).is_none() {
            return Err(format!("lease {lease_id} not found"));
        }
        self.lock_table
            .apply(&tidefs_lease::types::RaftCommand::Release { lease_id });
        Ok(())
    }

    fn object_count_for_node(&self, _node_id: MemberId) -> u64 {
        // Stub: placement-runtime integration not yet wired.
        0
    }

    fn cache_bytes_for_node(&self, _node_id: MemberId) -> u64 {
        // Stub: cache service integration not yet wired.
        0
    }

    fn migrate_one_object(&mut self, _node_id: MemberId) -> Result<bool, String> {
        // Stub: placement-runtime rebuild integration not yet wired.
        Ok(false)
    }

    fn invalidate_cache_chunk(
        &mut self,
        _node_id: MemberId,
        _max_bytes: u64,
    ) -> Result<(u64, u64), String> {
        // Stub: cache invalidation integration not yet wired.
        Ok((0, 0))
    }

    fn transfer_admin(&mut self, _from: MemberId, _to: MemberId) -> Result<(), String> {
        // Stub: admin role transfer not yet wired.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DrainExecutor — orchestrates a drain through all stages
// ---------------------------------------------------------------------------

/// The drain executor drives a [`NodeDrain`] through each stage by calling
/// [`DrainOps`] trait methods. It handles incremental progress updates,
/// cancellation, and timeout enforcement.
pub struct DrainExecutor {
    drain: NodeDrain,
}

impl DrainExecutor {
    /// Create a new executor wrapping a drain state machine.
    #[must_use]
    pub fn new(drain: NodeDrain) -> Self {
        Self { drain }
    }

    /// Start draining a node. Returns the executor and a monitoring handle.
    #[must_use]
    pub fn start(node_id: MemberId) -> (Self, crate::DrainHandle) {
        let (drain, handle) = NodeDrain::drain(node_id);
        (Self { drain }, handle)
    }

    // Accessors

    #[must_use]
    pub fn drain(&self) -> &NodeDrain {
        &self.drain
    }

    #[must_use]
    pub fn handle(&self) -> crate::DrainHandle {
        self.drain.handle()
    }

    /// Run a single tick of the executor.
    ///
    /// Returns the current stage after processing. If the drain has timed out,
    /// returns an error.
    pub fn tick(
        &mut self,
        _ops: &mut dyn DrainOps,
        delta_ms: u64,
    ) -> Result<DrainStage, DrainError> {
        self.drain.tick(delta_ms);

        if self.drain.is_timed_out() {
            return Err(DrainError::Timeout {
                node_id: self.drain.node_id(),
                timeout_ms: self.drain.timeout_ms(),
            });
        }

        // Nothing to do if terminal
        if self.drain.stage().is_terminal() {
            return Ok(self.drain.stage());
        }

        Ok(self.drain.stage())
    }

    /// Execute the drain through all stages to completion.
    ///
    /// Returns the final stage (Drained) or an error if something goes wrong.
    pub fn execute(&mut self, ops: &mut dyn DrainOps) -> Result<DrainStage, DrainError> {
        loop {
            match self.drain.stage() {
                DrainStage::DrainRequested => {
                    self.drain.advance_stage()?;
                }
                DrainStage::DrainingLeases => {
                    self.execute_lease_stage(ops)?;
                }
                DrainStage::DrainingData => {
                    self.execute_data_stage(ops)?;
                }
                DrainStage::DrainingCache => {
                    self.execute_cache_stage(ops)?;
                }
                DrainStage::DrainingAdmin => {
                    self.execute_admin_stage(ops)?;
                }
                DrainStage::Drained => return Ok(self.drain.stage()),
                DrainStage::Cancelled => return Ok(self.drain.stage()),
            }
        }
    }

    /// Execute only the lease drain stage. Returns the current progress.
    pub fn execute_lease_stage(
        &mut self,
        ops: &mut dyn DrainOps,
    ) -> Result<DrainProgress, DrainError> {
        let node = self.drain.node_id();

        // Advance into DrainingLeases if not already past it
        while self.drain.stage() == DrainStage::DrainRequested {
            self.drain.advance_stage()?;
        }

        if self.drain.stage() != DrainStage::DrainingLeases {
            return Ok(self.drain.progress());
        }

        let lease_ids = ops.lease_ids_for_node(node);

        if lease_ids.is_empty() {
            self.drain.update_progress(DrainProgress::ZERO);
            self.drain.advance_stage()?;
            return Ok(self.drain.progress());
        }

        // Release leases one at a time
        let remaining: u64 = lease_ids.len() as u64;
        let mut released = 0u64;
        let mut errors = Vec::new();

        for &lease_id in &lease_ids {
            match ops.release_lease(lease_id) {
                Ok(()) => released += 1,
                Err(e) => errors.push(e),
            }
        }

        self.drain.update_progress(DrainProgress {
            leases_remaining: remaining.saturating_sub(released),
            ..DrainProgress::ZERO
        });

        if !errors.is_empty() {
            return Err(DrainError::StageNotComplete {
                node_id: node,
                stage: DrainStage::DrainingLeases,
                progress: self.drain.progress(),
            });
        }

        self.drain.advance_stage()?;
        Ok(self.drain.progress())
    }

    /// Execute only the data migration stage.
    pub fn execute_data_stage(
        &mut self,
        ops: &mut dyn DrainOps,
    ) -> Result<DrainProgress, DrainError> {
        let node = self.drain.node_id();

        // Advance into DrainingData if not already past it
        while self.drain.stage() < DrainStage::DrainingData {
            self.drain.advance_stage()?;
        }
        if self.drain.stage() != DrainStage::DrainingData {
            return Ok(self.drain.progress());
        }

        let mut remaining = ops.object_count_for_node(node);

        self.drain.update_progress(DrainProgress {
            objects_remaining: remaining,
            ..DrainProgress::ZERO
        });

        while remaining > 0 {
            match ops.migrate_one_object(node) {
                Ok(more) => {
                    remaining = remaining.saturating_sub(1);
                    self.drain.update_progress(DrainProgress {
                        objects_remaining: remaining,
                        ..DrainProgress::ZERO
                    });
                    if !more {
                        break;
                    }
                }
                Err(_e) => {
                    return Err(DrainError::StageNotComplete {
                        node_id: node,
                        stage: DrainStage::DrainingData,
                        progress: self.drain.progress(),
                    });
                }
            }
        }

        self.drain.advance_stage()?;
        Ok(self.drain.progress())
    }

    /// Execute only the cache invalidation stage.
    pub fn execute_cache_stage(
        &mut self,
        ops: &mut dyn DrainOps,
    ) -> Result<DrainProgress, DrainError> {
        let node = self.drain.node_id();

        // Advance into DrainingCache if not already past it
        while self.drain.stage() < DrainStage::DrainingCache {
            self.drain.advance_stage()?;
        }
        if self.drain.stage() != DrainStage::DrainingCache {
            return Ok(self.drain.progress());
        }

        let mut remaining = ops.cache_bytes_for_node(node);
        const CHUNK_SIZE: u64 = 64 * 1024 * 1024; // 64 MiB chunks

        self.drain.update_progress(DrainProgress {
            bytes_remaining: remaining,
            ..DrainProgress::ZERO
        });

        while remaining > 0 {
            match ops.invalidate_cache_chunk(node, CHUNK_SIZE) {
                Ok((invalidated, rem)) => {
                    remaining = rem;
                    self.drain.update_progress(DrainProgress {
                        bytes_remaining: remaining,
                        ..DrainProgress::ZERO
                    });
                    if invalidated == 0 {
                        break;
                    }
                }
                Err(_e) => {
                    // Non-fatal: cache invalidation can be retried or skipped
                    break;
                }
            }
        }

        self.drain.advance_stage()?;
        Ok(self.drain.progress())
    }

    /// Execute only the admin transfer stage.
    pub fn execute_admin_stage(
        &mut self,
        ops: &mut dyn DrainOps,
    ) -> Result<DrainProgress, DrainError> {
        let node = self.drain.node_id();

        // Advance into DrainingAdmin if not already past it
        while self.drain.stage() < DrainStage::DrainingAdmin {
            self.drain.advance_stage()?;
        }
        if self.drain.stage() != DrainStage::DrainingAdmin {
            return Ok(self.drain.progress());
        }

        ops.transfer_admin(node, MemberId::new(0))?;
        self.drain.update_progress(DrainProgress::ZERO);
        self.drain.advance_stage()?;
        Ok(self.drain.progress())
    }
    /// Cancel the drain, returning the node to Active.
    pub fn cancel(&mut self) -> Result<DrainStage, DrainError> {
        self.drain.cancel()
    }

    /// Mark the drained node as decommissioned.
    pub fn decommission(&mut self) {
        self.drain.mark_decommissioned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain::NodeState;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn node_id(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // -----------------------------------------------------------------------
    // MockDrainOps
    // -----------------------------------------------------------------------

    struct MockDrainOps {
        leases: BTreeMap<u64, Vec<u64>>, // node_id -> lease_ids
        objects: BTreeMap<u64, u64>,     // node_id -> object count
        cache_bytes: BTreeMap<u64, u64>, // node_id -> cache bytes
        admin_transfer_called: Arc<AtomicBool>,
        released_leases: Vec<u64>,
    }

    impl MockDrainOps {
        fn new() -> Self {
            Self {
                leases: BTreeMap::new(),
                objects: BTreeMap::new(),
                cache_bytes: BTreeMap::new(),
                admin_transfer_called: Arc::new(AtomicBool::new(false)),
                released_leases: Vec::new(),
            }
        }

        fn with_leases(mut self, node: u64, lease_ids: Vec<u64>) -> Self {
            self.leases.insert(node, lease_ids);
            self
        }

        fn with_objects(mut self, node: u64, count: u64) -> Self {
            self.objects.insert(node, count);
            self
        }

        fn with_cache_bytes(mut self, node: u64, bytes: u64) -> Self {
            self.cache_bytes.insert(node, bytes);
            self
        }
    }

    impl DrainOps for MockDrainOps {
        fn lease_ids_for_node(&self, node_id: MemberId) -> Vec<u64> {
            self.leases.get(&node_id.0).cloned().unwrap_or_default()
        }

        fn release_lease(&mut self, lease_id: u64) -> Result<(), String> {
            self.released_leases.push(lease_id);
            Ok(())
        }

        fn object_count_for_node(&self, node_id: MemberId) -> u64 {
            self.objects.get(&node_id.0).copied().unwrap_or(0)
        }

        fn cache_bytes_for_node(&self, node_id: MemberId) -> u64 {
            self.cache_bytes.get(&node_id.0).copied().unwrap_or(0)
        }

        fn migrate_one_object(&mut self, node_id: MemberId) -> Result<bool, String> {
            if let Some(count) = self.objects.get_mut(&node_id.0) {
                if *count > 0 {
                    *count -= 1;
                }
                Ok(*count > 0)
            } else {
                Ok(false)
            }
        }

        fn invalidate_cache_chunk(
            &mut self,
            node_id: MemberId,
            max_bytes: u64,
        ) -> Result<(u64, u64), String> {
            if let Some(bytes) = self.cache_bytes.get_mut(&node_id.0) {
                let chunk = (*bytes).min(max_bytes);
                *bytes -= chunk;
                Ok((chunk, *bytes))
            } else {
                Ok((0, 0))
            }
        }

        fn transfer_admin(&mut self, _from: MemberId, _to: MemberId) -> Result<(), String> {
            self.admin_transfer_called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn executor_full_drain_with_leases() {
        let mut ops = MockDrainOps::new().with_leases(1, vec![100, 101, 102]);
        let (mut exec, _handle) = DrainExecutor::start(node_id(1));

        let result = exec.execute(&mut ops);
        assert!(result.is_ok());
        assert_eq!(exec.drain().stage(), DrainStage::Drained);
        assert_eq!(exec.drain().state(), NodeState::Drained);
        // All 3 leases should have been released
        assert_eq!(ops.released_leases.len(), 3);
    }

    #[test]
    fn executor_drain_no_data() {
        let mut ops = MockDrainOps::new(); // no leases, no objects, no cache
        let (mut exec, _handle) = DrainExecutor::start(node_id(2));

        let result = exec.execute(&mut ops);
        assert!(result.is_ok());
        assert_eq!(exec.drain().stage(), DrainStage::Drained);
    }

    #[test]
    fn executor_drain_with_objects() {
        let mut ops = MockDrainOps::new().with_objects(3, 5);
        let (mut exec, _handle) = DrainExecutor::start(node_id(3));

        let result = exec.execute(&mut ops);
        assert!(result.is_ok());
        assert_eq!(exec.drain().stage(), DrainStage::Drained);
        assert_eq!(ops.objects.get(&3), Some(&0));
    }

    #[test]
    fn executor_drain_with_cache() {
        let mut ops = MockDrainOps::new().with_cache_bytes(4, 200 * 1024 * 1024); // 200 MiB
        let (mut exec, _handle) = DrainExecutor::start(node_id(4));

        let result = exec.execute(&mut ops);
        assert!(result.is_ok());
        assert_eq!(ops.cache_bytes.get(&4), Some(&0));
    }

    #[test]
    fn executor_cancel_mid_drain() {
        let mut ops = MockDrainOps::new()
            .with_leases(5, vec![200, 201])
            .with_objects(5, 10);
        let (mut exec, _handle) = DrainExecutor::start(node_id(5));

        // Execute leases stage
        exec.execute_lease_stage(&mut ops).unwrap();
        assert_eq!(exec.drain().stage(), DrainStage::DrainingData);

        // Cancel before data migration
        let stage = exec.cancel().unwrap();
        assert_eq!(stage, DrainStage::Cancelled);
        assert_eq!(exec.drain().state(), NodeState::Active);
    }

    #[test]
    fn executor_lease_stage_only() {
        let mut ops = MockDrainOps::new().with_leases(6, vec![300]);
        let (mut exec, _handle) = DrainExecutor::start(node_id(6));

        let _progress = exec.execute_lease_stage(&mut ops).unwrap();
        assert_eq!(exec.drain().stage(), DrainStage::DrainingData);
        assert_eq!(ops.released_leases, vec![300]);
    }

    #[test]
    fn executor_data_stage_progress_tracks_remaining() {
        let mut ops = MockDrainOps::new().with_objects(7, 3);
        let (mut exec, _handle) = DrainExecutor::start(node_id(7));

        // Advance through lease stage (no leases)
        exec.execute_lease_stage(&mut ops).unwrap();
        // Now in data stage
        let progress = exec.execute_data_stage(&mut ops).unwrap();
        assert_eq!(progress.objects_remaining, 0);
    }

    #[test]
    fn executor_admin_transfer_called() {
        let mut ops = MockDrainOps::new();
        let (mut exec, _handle) = DrainExecutor::start(node_id(8));

        // Skip to admin stage by advancing through all prior stages
        for _ in 0..4 {
            exec.drain.update_progress(DrainProgress::ZERO);
            exec.drain.advance_stage().unwrap();
        }
        assert_eq!(exec.drain().stage(), DrainStage::DrainingAdmin);

        let result = exec.execute_admin_stage(&mut ops);
        assert!(result.is_ok());
        assert_eq!(exec.drain().stage(), DrainStage::Drained);
        assert!(ops.admin_transfer_called.load(Ordering::SeqCst));
    }

    #[test]
    fn executor_tick_delta() {
        let mut ops = MockDrainOps::new();
        let (mut exec, _handle) = DrainExecutor::start(node_id(9));
        exec.drain.set_timeout(5000);

        let stage = exec.tick(&mut ops, 100).unwrap();
        assert_eq!(exec.drain.elapsed_ms(), 100);
        assert_eq!(stage, DrainStage::DrainRequested);
    }

    #[test]
    fn executor_timeout_error() {
        let mut ops = MockDrainOps::new();
        let (mut exec, _handle) = DrainExecutor::start(node_id(10));
        exec.drain.set_timeout(1000);

        let err = exec.tick(&mut ops, 1001).unwrap_err();
        assert!(matches!(err, DrainError::Timeout { .. }));
    }
}
