// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::types::*;
use rand::seq::SliceRandom;
use rand::thread_rng;
use tidefs_membership_epoch::{ClusterMemberRecord, HealthClass, MemberClass, MemberId};

/// Select witnesses from the current epoch's Voters.
///
/// Rules:
/// - Only Voters that are Healthy are eligible.
/// - Excluded members (quarantined, drained) are filtered out.
/// - Failure-domain separation: prefer witnesses in different domains from
///   authority homes and replica locations.
/// - If insufficient distinct domains exist, fill from best available.
pub fn select_witnesses(ctx: &WitnessSelectionContext) -> Result<Vec<MemberId>, WitnessError> {
    // Filter eligible voters.
    let eligible: Vec<&ClusterMemberRecord> = ctx
        .voters
        .iter()
        .filter(|m| {
            m.member_class == MemberClass::Voter
                && m.health == HealthClass::Healthy
                && !ctx.excluded.contains(&m.member_id)
        })
        .collect();

    if eligible.len() < ctx.min_witnesses {
        return Err(WitnessError::InsufficientVoters {
            have: eligible.len(),
            need: ctx.min_witnesses,
        });
    }

    // Score each candidate by failure-domain separation from authority/replica homes.
    let domain_ids: Vec<tidefs_membership_epoch::DomainId> = ctx
        .authority_homes
        .iter()
        .chain(ctx.replica_locations.iter())
        .flat_map(|fdv| [fdv.node, fdv.rack, fdv.zone, fdv.region].into_iter())
        .collect();

    let mut scored: Vec<(MemberId, usize)> = eligible
        .iter()
        .map(|m| {
            let fdv = &m.failure_domain_vector;
            // Count how many of this member's domains overlap with subject domains.
            // Lower overlap = better separation = higher score.
            let overlap = [fdv.node, fdv.rack, fdv.zone, fdv.region]
                .iter()
                .filter(|d| domain_ids.contains(d))
                .count();
            // Inverse: 0 overlap = score 4, 4 overlap = score 0.
            (m.member_id, 4usize.saturating_sub(overlap))
        })
        .collect();

    // Sort by score descending (best separation first) then shuffle within score bands.
    scored.sort_by(|(_, a), (_, b)| b.cmp(a));

    // Select top N, but shuffle within equal-score groups for load balancing.
    let mut rng = thread_rng();
    let mut selected: Vec<MemberId> = Vec::with_capacity(ctx.max_witnesses.min(eligible.len()));

    let mut i = 0;
    while selected.len() < ctx.max_witnesses && i < scored.len() {
        // Find the group with the same score.
        let score = scored[i].1;
        let group_end = scored[i..]
            .iter()
            .position(|(_, s)| *s != score)
            .map(|p| i + p)
            .unwrap_or(scored.len());

        let mut group: Vec<MemberId> = scored[i..group_end].iter().map(|(id, _)| *id).collect();
        group.shuffle(&mut rng);

        for id in group {
            if selected.len() >= ctx.max_witnesses {
                break;
            }
            selected.push(id);
        }

        i = group_end;
    }

    // Must have at least min_witnesses.
    if selected.len() < ctx.min_witnesses {
        return Err(WitnessError::InsufficientVoters {
            have: selected.len(),
            need: ctx.min_witnesses,
        });
    }

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;

    fn make_voter(id: u64, node: u64, rack: u64, zone: u64, region: u64) -> ClusterMemberRecord {
        use tidefs_membership_epoch::{DomainId, FailureDomainVector};
        ClusterMemberRecord {
            member_id: MemberId::new(id),
            member_class: MemberClass::Voter,
            current_membership_epoch_ref: EpochId::new(1),
            log_frontier: 0,
            health: HealthClass::Healthy,
            failure_domain_vector: FailureDomainVector::new(
                DomainId::new(node),
                DomainId::new(node),
                DomainId::new(rack),
                DomainId::new(rack),
                DomainId::new(zone),
                DomainId::new(region),
            ),
            digest: 0,
        }
    }

    #[test]
    fn test_selects_enough_witnesses() {
        let voters: Vec<ClusterMemberRecord> = (1..=6).map(|i| make_voter(i, i, i, i, 1)).collect();

        let ctx = WitnessSelectionContext {
            voters,
            excluded: vec![],
            authority_homes: vec![],
            replica_locations: vec![],
            max_witnesses: 3,
            min_witnesses: 2,
            current_epoch: EpochId::new(1),
        };

        let selected = select_witnesses(&ctx).unwrap();
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn test_rejects_quarantined() {
        let mut voters: Vec<ClusterMemberRecord> =
            (1..=3).map(|i| make_voter(i, i, i, i, 1)).collect();
        voters[1].health = HealthClass::Down;

        let ctx = WitnessSelectionContext {
            voters,
            excluded: vec![],
            authority_homes: vec![],
            replica_locations: vec![],
            max_witnesses: 3,
            min_witnesses: 2,
            current_epoch: EpochId::new(1),
        };

        // Only 2 healthy voters — min is 2, should succeed.
        let selected = select_witnesses(&ctx).unwrap();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_insufficient_voters() {
        let voters: Vec<ClusterMemberRecord> = vec![make_voter(1, 1, 1, 1, 1)];

        let ctx = WitnessSelectionContext {
            voters,
            excluded: vec![],
            authority_homes: vec![],
            replica_locations: vec![],
            max_witnesses: 3,
            min_witnesses: 2,
            current_epoch: EpochId::new(1),
        };

        let result = select_witnesses(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_excludes_marked_members() {
        let voters: Vec<ClusterMemberRecord> = (1..=5).map(|i| make_voter(i, i, i, i, 1)).collect();

        let ctx = WitnessSelectionContext {
            voters,
            excluded: vec![MemberId::new(2), MemberId::new(4)],
            authority_homes: vec![],
            replica_locations: vec![],
            max_witnesses: 3,
            min_witnesses: 2,
            current_epoch: EpochId::new(1),
        };

        let selected = select_witnesses(&ctx).unwrap();
        assert!(!selected.contains(&MemberId::new(2)));
        assert!(!selected.contains(&MemberId::new(4)));
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn test_failure_domain_separation() {
        // 6 voters across 2 zones.
        let voters: Vec<ClusterMemberRecord> = vec![
            make_voter(1, 1, 1, 1, 1), // zone 1
            make_voter(2, 2, 1, 1, 1), // zone 1
            make_voter(3, 3, 2, 2, 1), // zone 2
            make_voter(4, 4, 2, 2, 1), // zone 2
            make_voter(5, 5, 3, 3, 1), // zone 3
            make_voter(6, 6, 3, 3, 1), // zone 3
        ];

        // Authority home is in zone 1, zone 1 witnesses should be deprioritized.
        let ctx = WitnessSelectionContext {
            voters,
            excluded: vec![],
            authority_homes: vec![tidefs_membership_epoch::FailureDomainVector::new(
                tidefs_membership_epoch::DomainId::new(1),
                tidefs_membership_epoch::DomainId::new(1),
                tidefs_membership_epoch::DomainId::new(1),
                tidefs_membership_epoch::DomainId::new(1),
                tidefs_membership_epoch::DomainId::new(1),
                tidefs_membership_epoch::DomainId::new(1),
            )],
            replica_locations: vec![],
            max_witnesses: 4,
            min_witnesses: 2,
            current_epoch: EpochId::new(1),
        };

        let selected = select_witnesses(&ctx).unwrap();
        // Should prefer zone 2 and zone 3 over zone 1
        // Total selected: 4, with bias toward different zones.
        assert_eq!(selected.len(), 4);
    }
}
