// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Placement/receipt authority model for the distributed model checker.
//!
//! Tracks placement receipts and enforces that rebuild/reclaim operations
//! require prior durable placement receipts.  Uses the settled receipt
//! identity and locator types from `tidefs-replication-model` instead of
//! inventing parallel types.

use std::collections::BTreeMap;
use tidefs_membership_epoch::EpochId;
pub use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy};

/// Per-node placement receipt state tracked by the model.
///
/// Wraps the real [`PlacementReceiptRef`] identity with model-level
/// durability tracking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementReceiptState {
    /// The settled receipt identity from `tidefs-replication-model`.
    pub receipt_ref: PlacementReceiptRef,
    /// Node that recorded this receipt.
    pub node_id: u64,
    /// Whether the receipt has been durably recorded.
    pub durable: bool,
}

impl PlacementReceiptState {
    /// Create a placement receipt state for a model-check scenario.
    #[must_use]
    pub fn for_model(
        object_id: u64,
        object_key_str: &str,
        node_id: u64,
        epoch: u64,
        durable: bool,
    ) -> Self {
        let receipt_ref = model_placement_receipt_ref(object_id, object_key_str, epoch);
        Self {
            receipt_ref,
            node_id,
            durable,
        }
    }

    /// The epoch of this receipt.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.receipt_ref.receipt_epoch.0
    }
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
    /// All known placement receipt states, keyed by receipt ref identity.
    pub receipts: BTreeMap<PlacementReceiptRef, PlacementReceiptState>,
    /// For each object (by model object key string), the set of nodes
    /// with a durable receipt.
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
    pub fn record_receipt(&mut self, state: PlacementReceiptState) {
        let object_key = object_key_from_receipt_ref(&state.receipt_ref);
        if state.durable {
            self.object_placements
                .entry(object_key)
                .or_default()
                .push(state.node_id);
        }
        self.receipts.insert(state.receipt_ref, state);
    }

    /// Check whether an object has a durable placement receipt.
    #[must_use]
    pub fn has_durable_receipt(&self, object_key: &str) -> bool {
        self.object_placements
            .get(object_key)
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
    }

    /// Attempt a rebuild or reclaim operation.  Returns true if permitted.
    pub fn try_rebuild(&mut self, object_key: &str, target_node: u64, epoch: u64) -> bool {
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

// ── helpers ───────────────────────────────────────────────────────────

/// Build a minimal [`PlacementReceiptRef`] for model-check scenarios.
/// The model only exercises epoch and object identity; remaining fields
/// are set to zero/default values that satisfy the type contract.
#[must_use]
pub fn model_placement_receipt_ref(
    object_id: u64,
    object_key_str: &str,
    epoch: u64,
) -> PlacementReceiptRef {
    let mut key = [0u8; 32];
    let bytes = object_key_str.as_bytes();
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    PlacementReceiptRef::new(
        object_id,
        key,
        EpochId::new(epoch),
        0, // receipt_generation
        ReceiptRedundancyPolicy::Replicated { copies: 1 },
        0,         // payload_len
        [0u8; 32], // payload_digest
        1,         // target_count
    )
}

/// Extract a model-level object key string from a receipt ref.
fn object_key_from_receipt_ref(r: &PlacementReceiptRef) -> String {
    // Find the first nul or take the whole 32 bytes as UTF-8 lossy.
    let len = r.object_key.iter().position(|&b| b == 0).unwrap_or(32);
    String::from_utf8_lossy(&r.object_key[..len]).into_owned()
}

/// Create a model object key string from a receipt ref, zero-padded.
#[must_use]
pub fn receipt_ref_to_model_key(r: &PlacementReceiptRef) -> String {
    object_key_from_receipt_ref(r)
}
