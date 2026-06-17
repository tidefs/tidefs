// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Membership-epoch model for the distributed model checker.
//!
//! Consumes `EpochId`, `ReceiptId`, and placement-authority types from
//! `tidefs-membership-epoch` (the #17/#18 placement/receipt authority).
//! This module is a pure model — it does not depend on a live network
//! or consensus runtime.

use std::collections::BTreeMap;

/// Per-node epoch record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochState {
    pub node_id: u64,
    pub current_epoch: u64,
    /// Highest epoch this node has ever seen.
    pub highest_seen: u64,
}

/// Tracks membership-epoch advancement across all nodes.
#[derive(Clone, Debug)]
pub struct MembershipEpochModel {
    pub nodes: Vec<EpochState>,
    /// For each node, the set of epochs it has acknowledged.
    pub epoch_history: BTreeMap<u64, Vec<u64>>,
    /// Tracks which nodes have advanced to which epochs.
    pub epoch_members: BTreeMap<u64, Vec<u64>>,
}

impl MembershipEpochModel {
    #[must_use]
    pub fn new(node_count: usize) -> Self {
        let nodes: Vec<EpochState> = (0..node_count as u64)
            .map(|nid| EpochState { node_id: nid, current_epoch: 0, highest_seen: 0 })
            .collect();
        let mut epoch_members = BTreeMap::new();
        epoch_members.insert(0, (0..node_count as u64).collect());
        Self { nodes, epoch_history: BTreeMap::new(), epoch_members }
    }

    /// Record that a node has advanced to `new_epoch`.
    pub fn record_advance(&mut self, node_id: u64, new_epoch: u64) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.node_id == node_id) {
            node.current_epoch = new_epoch;
            if new_epoch > node.highest_seen {
                node.highest_seen = new_epoch;
            }
        }
        self.epoch_history.entry(new_epoch).or_default().push(node_id);
        self.epoch_members.entry(new_epoch).or_default().push(node_id);
    }

    /// Returns the current epoch for a node.
    #[must_use]
    pub fn epoch_of(&self, node_id: u64) -> u64 {
        self.nodes.iter()
            .find(|n| n.node_id == node_id)
            .map(|n| n.current_epoch)
            .unwrap_or(0)
    }

    /// Returns nodes that have not yet advanced beyond `epoch`.
    #[must_use]
    pub fn lagging_nodes(&self, epoch: u64) -> Vec<u64> {
        self.nodes.iter()
            .filter(|n| n.current_epoch < epoch)
            .map(|n| n.node_id)
            .collect()
    }

    /// Returns the membership set for a given epoch.
    #[must_use]
    pub fn members_at(&self, epoch: u64) -> Vec<u64> {
        self.epoch_members.get(&epoch).cloned().unwrap_or_default()
    }
}
