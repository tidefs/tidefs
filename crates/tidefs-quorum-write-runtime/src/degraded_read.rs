// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Degraded read protocol: health-aware candidate selection, cascading
//! fallback, and DemandRead escalation to the transfer orchestrator (#901).
//!
//! Tries candidates in strict order:
//! 1. Local replica
//! 2. Healthy replicas
//! 3. Lagged-but-usable replicas
//! 4. Any remaining replica
//! 5. Escalate to DemandRead transfer ticket

use std::collections::BTreeMap;
use std::path::PathBuf;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_membership_epoch::MemberId;
use tidefs_quorum_write::ReadClass;

// ── Candidate health classification for ordering ─────────────────────

/// Health-aware candidate for degraded reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CandidateHealthClass {
    /// Best: local replica (lowest latency).
    Local = 0,
    /// Healthy remote replicas at the latest frontier.
    Healthy = 1,
    /// Lagged but with verified data (degraded_but_valid visibility).
    LaggedButUsable = 2,
    /// Any replica (last resort before DemandRead).
    AnyReplica = 3,
}

/// A single candidate replica with health classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegradedReadCandidate {
    pub member_id: MemberId,
    pub health_class: CandidateHealthClass,
    pub is_local: bool,
    pub lag_bytes_behind: u64,
}

// ── DemandRead ticket ─────────────────────────────────────────────────

/// Escalation ticket: when all degraded read candidates fail,
/// request a DemandRead transfer from the orchestrator (#901).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemandReadTicket {
    pub ticket_id: u64,
    pub object_key: ObjectKey,
    pub candidate_count_tried: usize,
    pub priority: u8,
    pub epoch: u64,
}

impl DemandReadTicket {
    /// Maximum priority for DemandRead tickets.
    pub const MAX_PRIORITY: u8 = 255;

    #[must_use]
    pub fn with_max_priority(mut self) -> Self {
        self.priority = Self::MAX_PRIORITY;
        self
    }
}

// ── Degraded read visibility ──────────────────────────────────────────

/// Visibility class returned to readers when serving degraded data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedReadVisibility {
    /// Exact: read from the latest frontier.
    Exact,
    /// Degraded but valid: served from a lagged replica with verified data.
    DegradedButValid,
    /// Repair required: data was served but the replica needs repair.
    RepairRequired,
    /// Unavailable: no replica could serve the data.
    Unavailable,
}

impl DegradedReadVisibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::DegradedButValid => "degraded_but_valid",
            Self::RepairRequired => "repair_required",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether the data is readable (even if stale).
    #[must_use]
    pub const fn is_readable(self) -> bool {
        matches!(
            self,
            Self::Exact | Self::DegradedButValid | Self::RepairRequired
        )
    }

    /// Whether the read was degraded (not from the latest frontier).
    #[must_use]
    pub const fn is_degraded(self) -> bool {
        matches!(self, Self::DegradedButValid | Self::RepairRequired)
    }
}

// ── DegradedReadProtocol ──────────────────────────────────────────────

/// Production degraded read protocol with health-aware candidate selection.
///
/// Tries candidates in strict priority order:
/// 1. Local replica (fastest path)
/// 2. Healthy replicas at the frontier
/// 3. Lagged-but-usable replicas
/// 4. Any remaining replica
/// 5. Escalate to DemandRead transfer when all fail
pub struct DegradedReadProtocol {
    replica_paths: Vec<PathBuf>,
    replicas: BTreeMap<usize, LocalObjectStore>,
    candidates: Vec<DegradedReadCandidate>,
    local_member_id: Option<MemberId>,
    /// Whether to escalate to DemandRead on all-fail.
    escalate_to_demand_read: bool,
}

impl DegradedReadProtocol {
    #[must_use]
    pub fn new(replica_paths: Vec<PathBuf>) -> Self {
        Self {
            replica_paths,
            replicas: BTreeMap::new(),
            candidates: Vec::new(),
            local_member_id: None,
            escalate_to_demand_read: true,
        }
    }

    /// Set the local member id for candidate prioritization.
    pub fn set_local_member(&mut self, member_id: MemberId) {
        self.local_member_id = Some(member_id);
    }

    /// Enable or disable DemandRead escalation.
    pub fn set_escalation(&mut self, escalate: bool) {
        self.escalate_to_demand_read = escalate;
    }

    /// Update candidate ordering from health/lag state.
    ///
    /// Called before each read to ensure ordering reflects current health.
    pub fn refresh_candidates(&mut self, health_state: &[(MemberId, CandidateHealthClass, u64)]) {
        self.candidates.clear();
        for (member_id, health_class, lag_bytes) in health_state.iter() {
            let is_local = self.local_member_id == Some(*member_id);
            // Override health class for local replica
            let effective_class = if is_local {
                CandidateHealthClass::Local
            } else {
                *health_class
            };
            self.candidates.push(DegradedReadCandidate {
                member_id: *member_id,
                health_class: effective_class,
                is_local,
                lag_bytes_behind: *lag_bytes,
            });
        }
        // Sort: Local < Healthy < LaggedButUsable < AnyReplica
        self.candidates.sort_by_key(|c| c.health_class as u8);
    }

    /// Open all replica stores.
    pub fn open_replicas(&mut self) -> Result<(), String> {
        for (i, path) in self.replica_paths.iter().enumerate() {
            let store =
                LocalObjectStore::open_read_only_with_options(path, StoreOptions::default())
                    .map_err(|e| format!("replica {i} at {path:?}: {e}"))?
                    .ok_or_else(|| format!("replica {path:?} does not exist"))?;
            self.replicas.insert(i, store);
        }
        Ok(())
    }

    /// Try to resolve a read using health-aware candidate ordering.
    ///
    /// Returns the data, visibility class, and which candidate served it.
    pub fn resolve(
        &self,
        key: &ObjectKey,
    ) -> Result<(Vec<u8>, DegradedReadVisibility, Option<MemberId>), String> {
        // Try candidates in sorted health order
        for candidate in &self.candidates {
            let idx = self
                .candidates
                .iter()
                .position(|c| c.member_id == candidate.member_id);
            if let Some(idx) = idx {
                if let Some(replica) = self.replicas.get(&idx) {
                    match replica.get(*key) {
                        Ok(Some(data)) => {
                            let visibility = if candidate.lag_bytes_behind == 0 {
                                DegradedReadVisibility::Exact
                            } else {
                                DegradedReadVisibility::DegradedButValid
                            };
                            return Ok((data, visibility, Some(candidate.member_id)));
                        }
                        Ok(None) => continue,
                        Err(_) => continue,
                    }
                }
            }
        }

        // All candidates exhausted — escalate to DemandRead
        if self.escalate_to_demand_read {
            Ok((Vec::new(), DegradedReadVisibility::Unavailable, None))
        } else {
            Err(format!(
                "degraded read: object {} not in any replica",
                key.short_hex()
            ))
        }
    }

    /// Build a DemandRead escalation ticket when all candidates fail.
    #[must_use]
    pub fn build_demand_read_ticket(&self, key: &ObjectKey) -> DemandReadTicket {
        DemandReadTicket {
            ticket_id: 0,
            object_key: *key,
            candidate_count_tried: self.candidates.len(),
            priority: DemandReadTicket::MAX_PRIORITY,
            epoch: 0,
        }
        .with_max_priority()
    }

    #[must_use]
    pub fn can_degrade(&self) -> bool {
        !self.replicas.is_empty()
    }

    #[must_use]
    pub fn replica_count(&self) -> usize {
        self.replicas.len()
    }

    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Categorize candidates by health class.
    #[must_use]
    pub fn candidates_by_class(&self) -> BTreeMap<CandidateHealthClass, Vec<MemberId>> {
        let mut map: BTreeMap<CandidateHealthClass, Vec<MemberId>> = BTreeMap::new();
        for c in &self.candidates {
            map.entry(c.health_class).or_default().push(c.member_id);
        }
        map
    }
}

// Keep the original DegradedReadResolver for backward compatibility
pub struct DegradedReadResolver {
    replica_paths: Vec<PathBuf>,
    replicas: BTreeMap<usize, LocalObjectStore>,
}

impl DegradedReadResolver {
    #[must_use]
    pub fn new(replica_paths: Vec<PathBuf>) -> Self {
        Self {
            replica_paths,
            replicas: BTreeMap::new(),
        }
    }

    pub fn open_replicas(&mut self) -> Result<(), String> {
        for (i, path) in self.replica_paths.iter().enumerate() {
            let store =
                LocalObjectStore::open_read_only_with_options(path, StoreOptions::default())
                    .map_err(|e| format!("replica {i} at {path:?}: {e}"))?
                    .ok_or_else(|| format!("replica {path:?} does not exist"))?;
            self.replicas.insert(i, store);
        }
        Ok(())
    }

    pub fn resolve(&self, key: &ObjectKey) -> Result<(Vec<u8>, ReadClass), String> {
        for (i, replica) in &self.replicas {
            match replica.get(*key) {
                Ok(Some(data)) => {
                    let class = if i == &0 {
                        ReadClass::Exact
                    } else {
                        ReadClass::DegradedButValid
                    };
                    return Ok((data, class));
                }
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
        Err(format!(
            "degraded read: object {} not in any replica",
            key.short_hex()
        ))
    }

    #[must_use]
    pub fn can_degrade(&self) -> bool {
        !self.replicas.is_empty()
    }

    #[must_use]
    pub fn replica_count(&self) -> usize {
        self.replicas.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_class_ordering() {
        assert!(CandidateHealthClass::Local < CandidateHealthClass::Healthy);
        assert!(CandidateHealthClass::Healthy < CandidateHealthClass::LaggedButUsable);
        assert!(CandidateHealthClass::LaggedButUsable < CandidateHealthClass::AnyReplica);
    }

    #[test]
    fn empty_protocol_cannot_degrade() {
        let p = DegradedReadProtocol::new(Vec::new());
        assert!(!p.can_degrade());
        assert_eq!(p.replica_count(), 0);
        assert_eq!(p.candidate_count(), 0);
    }

    #[test]
    fn refresh_candidates_orders_by_health() {
        let mut p = DegradedReadProtocol::new(Vec::new());
        p.set_local_member(MemberId::new(2));

        let health = vec![
            (MemberId::new(1), CandidateHealthClass::Healthy, 0),
            (MemberId::new(2), CandidateHealthClass::Healthy, 0), // local → overridden to Local
            (MemberId::new(3), CandidateHealthClass::LaggedButUsable, 100),
        ];
        p.refresh_candidates(&health);

        let by_class = p.candidates_by_class();
        assert_eq!(by_class.get(&CandidateHealthClass::Local).unwrap().len(), 1);
        assert_eq!(
            by_class.get(&CandidateHealthClass::Healthy).unwrap().len(),
            1
        );
        assert_eq!(
            by_class
                .get(&CandidateHealthClass::LaggedButUsable)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn demand_read_ticket_max_priority() {
        let p = DegradedReadProtocol::new(Vec::new());
        let key = ObjectKey::default();
        let ticket = p.build_demand_read_ticket(&key);
        assert_eq!(ticket.priority, 255);
    }

    #[test]
    fn degraded_visibility_is_readable() {
        assert!(DegradedReadVisibility::Exact.is_readable());
        assert!(DegradedReadVisibility::DegradedButValid.is_readable());
        assert!(DegradedReadVisibility::RepairRequired.is_readable());
        assert!(!DegradedReadVisibility::Unavailable.is_readable());
    }

    #[test]
    fn degraded_visibility_is_degraded() {
        assert!(!DegradedReadVisibility::Exact.is_degraded());
        assert!(DegradedReadVisibility::DegradedButValid.is_degraded());
        assert!(DegradedReadVisibility::RepairRequired.is_degraded());
        assert!(!DegradedReadVisibility::Unavailable.is_degraded());
    }

    #[test]
    fn backward_compat_resolver() {
        let r = DegradedReadResolver::new(Vec::new());
        assert!(!r.can_degrade());
        assert_eq!(r.replica_count(), 0);
    }

    // ── Receipt-aware degraded read tests ───────────────────────────

    #[test]
    fn receipt_aware_candidate_fallback_after_loss() {
        // Simulate a receipt-addressed replicated object (2 copies).
        // When the local replica is lost, candidates fall back to
        // the remaining healthy replica. The degraded read ordering
        // is driven by candidate health, not replica store state.
        let mut p = DegradedReadProtocol::new(Vec::new());
        p.set_local_member(MemberId::new(1));

        // Two replicas: local (node 1) and remote (node 2), both healthy
        let health = vec![
            (MemberId::new(1), CandidateHealthClass::Healthy, 0),
            (MemberId::new(2), CandidateHealthClass::Healthy, 0),
        ];
        p.refresh_candidates(&health);

        assert_eq!(p.candidate_count(), 2);

        // Local candidate should be promoted to Local class
        let by_class = p.candidates_by_class();
        let locals = by_class.get(&CandidateHealthClass::Local).unwrap();
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0], MemberId::new(1));
        let healthy = by_class.get(&CandidateHealthClass::Healthy).unwrap();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0], MemberId::new(2));

        // Simulate loss of the local replica (node 1 goes down)
        let degraded_health = vec![
            (MemberId::new(2), CandidateHealthClass::Healthy, 0),
        ];
        p.refresh_candidates(&degraded_health);

        assert_eq!(p.candidate_count(), 1);
        // The remaining candidate is on node 2, now the only healthy
        let by_class = p.candidates_by_class();
        assert!(by_class.get(&CandidateHealthClass::Local).is_none());
        let remaining = by_class.get(&CandidateHealthClass::Healthy).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], MemberId::new(2));

        // After loss of all replicas, no candidates remain
        let empty_health: Vec<(MemberId, CandidateHealthClass, u64)> = vec![];
        p.refresh_candidates(&empty_health);
        assert_eq!(p.candidate_count(), 0);
        assert!(p.candidates_by_class().is_empty());
    }

    #[test]
    fn receipt_aware_lagged_replica_fallback() {
        // Verify that lagged-but-usable replicas are ordered after healthy ones.
        let mut p = DegradedReadProtocol::new(Vec::new());
        p.set_local_member(MemberId::new(10));

        let health = vec![
            (MemberId::new(10), CandidateHealthClass::LaggedButUsable, 500),
            (MemberId::new(20), CandidateHealthClass::Healthy, 0),
            (MemberId::new(30), CandidateHealthClass::LaggedButUsable, 100),
        ];
        p.refresh_candidates(&health);

        assert_eq!(p.candidate_count(), 3);

        let by_class = p.candidates_by_class();
        // Local is always promoted to Local class regardless of input
        assert_eq!(by_class.get(&CandidateHealthClass::Local).unwrap().len(), 1);
        assert_eq!(by_class.get(&CandidateHealthClass::Healthy).unwrap().len(), 1);
        assert_eq!(by_class.get(&CandidateHealthClass::LaggedButUsable).unwrap().len(), 1);

        // Candidates should be ordered: Local first, then Healthy, then Lagged
        let by_class = p.candidates_by_class();
        let locals = by_class.get(&CandidateHealthClass::Local).unwrap();
        let healthy = by_class.get(&CandidateHealthClass::Healthy).unwrap();
        let lagged = by_class.get(&CandidateHealthClass::LaggedButUsable).unwrap();
        assert_eq!(locals.len(), 1);
        assert_eq!(healthy.len(), 1);
        assert_eq!(lagged.len(), 1);
        assert_eq!(locals[0], MemberId::new(10));
        assert_eq!(healthy[0], MemberId::new(20));
        assert_eq!(lagged[0], MemberId::new(30));
    }
}
