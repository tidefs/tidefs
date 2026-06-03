//! Placement health tracker.
//!
//! Monitors replica health with lag/degraded/stale/verified states per chunk.
//! Tracks which replicas are healthy, degraded, or need attention, and
//! feeds health information into the placement evaluation loop.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use tidefs_membership_epoch::{EpochId, HealthClass, MemberId};
use tidefs_replication_model::ReplicatedSubjectId;

/// Replica health state per chunk.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReplicaHealthState {
    Verified = 0,
    Lagging = 1,
    Degraded = 2,
    Stale = 3,
    Unknown = 4,
}

impl ReplicaHealthState {
    #[must_use]
    pub const fn admits_placement(self) -> bool {
        matches!(self, Self::Verified | Self::Lagging)
    }
}

/// Health record for a replica on a specific member.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReplicaHealthRecord {
    pub subject_ref: ReplicatedSubjectId,
    pub member_id: MemberId,
    pub health_state: ReplicaHealthState,
    pub epoch: EpochId,
    pub lag_millis: u64,
    pub last_verified_at_millis: u64,
    pub member_health: HealthClass,
}

/// PlacementHealthTracker monitors replica health across the cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PlacementHealthTracker {
    pub replica_health: BTreeMap<(ReplicatedSubjectId, MemberId), ReplicaHealthRecord>,
    pub epoch: EpochId,
}

impl PlacementHealthTracker {
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            replica_health: BTreeMap::new(),
            epoch,
        }
    }

    pub fn record_health(
        &mut self,
        subject_ref: ReplicatedSubjectId,
        member_id: MemberId,
        health_state: ReplicaHealthState,
        lag_millis: u64,
        member_health: HealthClass,
    ) {
        let now = now_millis();
        let record = ReplicaHealthRecord {
            subject_ref,
            member_id,
            health_state,
            epoch: self.epoch,
            lag_millis,
            last_verified_at_millis: if health_state == ReplicaHealthState::Verified {
                now
            } else {
                0
            },
            member_health,
        };
        self.replica_health.insert((subject_ref, member_id), record);
    }

    #[must_use]
    pub fn get_health(
        &self,
        subject_ref: ReplicatedSubjectId,
        member_id: MemberId,
    ) -> Option<&ReplicaHealthRecord> {
        self.replica_health.get(&(subject_ref, member_id))
    }

    #[must_use]
    pub fn is_healthy(&self, subject_ref: ReplicatedSubjectId, member_id: MemberId) -> bool {
        self.get_health(subject_ref, member_id)
            .is_some_and(|r| r.health_state.admits_placement())
    }

    #[must_use]
    pub fn healthy_replicas(&self, subject_ref: ReplicatedSubjectId) -> Vec<MemberId> {
        let mut replicas: Vec<(ReplicaHealthState, MemberId)> = self
            .replica_health
            .iter()
            .filter(|((s, _), r)| *s == subject_ref && r.health_state.admits_placement())
            .map(|((_, m), r)| (r.health_state, *m))
            .collect();
        replicas.sort_by_key(|(state, _)| *state);
        replicas.into_iter().map(|(_, m)| m).collect()
    }

    #[must_use]
    pub fn degraded_replicas(&self, subject_ref: ReplicatedSubjectId) -> Vec<MemberId> {
        let mut replicas: Vec<MemberId> = self
            .replica_health
            .iter()
            .filter(|((s, _), r)| {
                *s == subject_ref
                    && matches!(
                        r.health_state,
                        ReplicaHealthState::Degraded | ReplicaHealthState::Stale
                    )
            })
            .map(|((_, m), _)| *m)
            .collect();
        replicas.sort();
        replicas
    }

    pub fn mark_verified(&mut self, subject_ref: ReplicatedSubjectId, member_id: MemberId) {
        if let Some(record) = self.replica_health.get_mut(&(subject_ref, member_id)) {
            record.health_state = ReplicaHealthState::Verified;
            record.last_verified_at_millis = now_millis();
            record.lag_millis = 0;
        } else {
            self.record_health(
                subject_ref,
                member_id,
                ReplicaHealthState::Verified,
                0,
                HealthClass::Healthy,
            );
        }
    }

    pub fn retire_replica(&mut self, subject_ref: ReplicatedSubjectId, member_id: MemberId) {
        self.replica_health.remove(&(subject_ref, member_id));
    }

    pub fn advance_epoch(&mut self, new_epoch: EpochId) {
        self.epoch = new_epoch;
        for record in self.replica_health.values_mut() {
            if record.epoch != new_epoch && record.health_state == ReplicaHealthState::Unknown {
                record.health_state = ReplicaHealthState::Stale;
            }
            record.epoch = new_epoch;
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tracker_lifecycle() {
        let mut ht = PlacementHealthTracker::new(EpochId::new(1));
        let subject = ReplicatedSubjectId::new(100);
        let member = MemberId::new(1);
        assert!(!ht.is_healthy(subject, member));
        ht.record_health(
            subject,
            member,
            ReplicaHealthState::Verified,
            0,
            HealthClass::Healthy,
        );
        assert!(ht.is_healthy(subject, member));
        let healthy = ht.healthy_replicas(subject);
        assert_eq!(healthy, vec![member]);
    }

    #[test]
    fn test_degraded_detection() {
        let mut ht = PlacementHealthTracker::new(EpochId::new(1));
        let subject = ReplicatedSubjectId::new(100);
        let m1 = MemberId::new(1);
        let m2 = MemberId::new(2);
        ht.record_health(
            subject,
            m1,
            ReplicaHealthState::Verified,
            0,
            HealthClass::Healthy,
        );
        ht.record_health(
            subject,
            m2,
            ReplicaHealthState::Degraded,
            5000,
            HealthClass::Healthy,
        );
        let degraded = ht.degraded_replicas(subject);
        assert_eq!(degraded, vec![m2]);
        let healthy = ht.healthy_replicas(subject);
        assert_eq!(healthy, vec![m1]);
    }

    #[test]
    fn test_mark_verified() {
        let mut ht = PlacementHealthTracker::new(EpochId::new(1));
        let subject = ReplicatedSubjectId::new(100);
        let member = MemberId::new(1);
        ht.record_health(
            subject,
            member,
            ReplicaHealthState::Lagging,
            100,
            HealthClass::Healthy,
        );
        ht.mark_verified(subject, member);
        let record = ht.get_health(subject, member).unwrap();
        assert_eq!(record.health_state, ReplicaHealthState::Verified);
        assert_eq!(record.lag_millis, 0);
    }

    #[test]
    fn test_retire_replica() {
        let mut ht = PlacementHealthTracker::new(EpochId::new(1));
        let subject = ReplicatedSubjectId::new(100);
        let member = MemberId::new(1);
        ht.record_health(
            subject,
            member,
            ReplicaHealthState::Verified,
            0,
            HealthClass::Healthy,
        );
        ht.retire_replica(subject, member);
        assert!(ht.get_health(subject, member).is_none());
    }

    #[test]
    fn test_health_state_ordering() {
        assert!(ReplicaHealthState::Verified < ReplicaHealthState::Degraded);
        assert!(ReplicaHealthState::Lagging < ReplicaHealthState::Stale);
    }
}
