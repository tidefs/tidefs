// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Placement/receipt authority model for the distributed model checker.
//!
//! Tracks placement receipts and enforces that rebuild/reclaim operations
//! require prior durable placement receipts.  This is a self-contained
//! model that mirrors the TideFS placement protocol without depending on
//! live runtime crates.

use std::collections::BTreeMap;

/// Per-node placement receipt state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementReceiptState {
    pub receipt_id: u64,
    pub object_key: String,
    pub node_id: u64,
    pub epoch: u64,
    pub durable: bool,
}

/// Policy controlling when rebuild or reclaim is permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebuildPolicy {
    /// Require a durable placement receipt before rebuild.
    RequireDurableReceipt,
    /// Permit rebuild without a receipt (unsafe, for testing).
    PermitWithoutReceipt,
}

/// Placement model — tracks placement receipts and rebuild eligibility.
#[derive(Clone, Debug)]
pub struct PlacementModel {
    /// All known placement receipts, keyed by receipt_id.
    pub receipts: BTreeMap<u64, PlacementReceiptState>,
    /// For each object, the set of nodes with a durable receipt.
    pub object_placements: BTreeMap<String, Vec<u64>>,
    /// Rebuild operations that have been attempted.
    pub rebuild_attempts: Vec<RebuildAttempt>,
    /// Policy for rebuild/reclaim eligibility.
    pub policy: RebuildPolicy,
}

/// Record of a rebuild or reclaim attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildAttempt {
    pub object_key: String,
    pub target_node: u64,
    pub epoch: u64,
    pub had_durable_receipt: bool,
    pub allowed: bool,
}

impl PlacementModel {
    #[must_use]
    pub fn new(_node_count: usize) -> Self {
        Self {
            receipts: BTreeMap::new(),
            object_placements: BTreeMap::new(),
            rebuild_attempts: Vec::new(),
            policy: RebuildPolicy::RequireDurableReceipt,
        }
    }

    /// Record a placement receipt as durable.
    pub fn record_receipt(&mut self, receipt: PlacementReceiptState) {
        self.object_placements
            .entry(receipt.object_key.clone())
            .or_default()
            .push(receipt.node_id);
        self.receipts.insert(receipt.receipt_id, receipt);
    }

    /// Check whether an object has a durable placement receipt.
    #[must_use]
    pub fn has_durable_receipt(&self, object_key: &str) -> bool {
        self.object_placements.get(object_key)
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
    }

    /// Attempt a rebuild or reclaim operation.  Returns true if permitted.
    pub fn try_rebuild(
        &mut self,
        object_key: &str,
        target_node: u64,
        epoch: u64,
    ) -> bool {
        let has_receipt = self.has_durable_receipt(object_key);
        let allowed = match self.policy {
            RebuildPolicy::RequireDurableReceipt => has_receipt,
            RebuildPolicy::PermitWithoutReceipt => true,
        };
        self.rebuild_attempts.push(RebuildAttempt {
            object_key: object_key.to_string(),
            target_node,
            epoch,
            had_durable_receipt: has_receipt,
            allowed,
        });
        allowed
    }
}
