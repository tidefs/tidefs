#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_lease::{
    issuance::{LeaseAuthority, LeaseAuthorityConfig, LeaseIssuanceResult, LeaseRequest},
    LeaseClass, LeaseDomain,
};
use tidefs_membership_epoch::{
    ClusterMemberRecord, DomainId, EpochId, FailureDomainVector,
    HealthClass, MemberClass, MemberId,
};

fn make_domain(seed: u64) -> FailureDomainVector {
    FailureDomainVector::new(
        DomainId::new(seed * 10 + 1),
        DomainId::new(seed * 10 + 2),
        DomainId::new(seed * 10 + 3),
        DomainId::new(seed),
        DomainId::new(seed + 1),
        DomainId::new(1),
    )
}

fn build_voters(count: u8) -> Vec<ClusterMemberRecord> {
    (0..(count.min(16).max(1)))
        .map(|i| ClusterMemberRecord {
            member_id: MemberId::new(i as u64),
            member_class: MemberClass::Voter,
            current_membership_epoch_ref: EpochId::new(1),
            log_frontier: 0,
            health: HealthClass::Healthy,
            failure_domain_vector: make_domain(i as u64),
            digest: 0,
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let voter_count = (data[0] % 15).max(3) as usize;
    let config = LeaseAuthorityConfig {
        min_witnesses: 2,
        max_witnesses: voter_count,
        default_term_millis: 10_000,
        grace_period_denominator: 8,
        current_epoch: EpochId::new(1),
        voters: build_voters(voter_count as u8),
        witness_pubkeys: std::collections::BTreeMap::new(),
        ..LeaseAuthorityConfig::default()
    };

    let mut authority = LeaseAuthority::new(config);

    let op_count = (data[1] % 20).max(1) as usize;
    let mut next_id: u64 = 1;
    let classes = [LeaseClass::Exclusive, LeaseClass::Shared, LeaseClass::Staging];

    for i in 0..op_count {
        let offset = 8 + (i * 4).min(data.len().saturating_sub(4));
        if offset + 4 > data.len() {
            break;
        }

        let op_byte = data[offset];
        let param_byte = data[offset + 1];

        match op_byte % 5 {
            0 => {
                let class = classes[(param_byte as usize) % 3];
                let requester = MemberId::new((param_byte as u64 % voter_count as u64) + 1);
                let request = LeaseRequest {
                    lease_id: next_id,
                    lease_class: class,
                    domain: LeaseDomain::ChunkRange {
                        replica_set_id: 1,
                        start_chunk: 0,
                        end_chunk: 100,
                    },
                    requester_id: requester,
                    term_millis: Some(5_000 + (param_byte as u64 * 1_000)),
                };
                let result = authority.request_lease(request);
                if matches!(result, LeaseIssuanceResult::Granted { .. }) {
                    next_id += 1;
                }
            }
            1 => {
                let lease_id = ((param_byte as u64) % next_id).max(1);
                let _ = authority.release_lease(lease_id, MemberId::new(1));
            }
            2 => {
                let lease_id = ((param_byte as u64) % next_id).max(1);
                let _ = authority.renew_lease(lease_id, MemberId::new(1));
            }
            3 => {
                let lease_id = ((param_byte as u64) % next_id).max(1);
                let _ = authority.fence_lease(lease_id);
            }
            _ => {
                let _ = authority.evaluate_expiry();
            }
        }
    }

    // Expired leases should be terminal
    let expired = authority.evaluate_expiry();
    for id in &expired {
        if let Some(grant) = authority.get_lease(*id) {
            assert!(grant.lifecycle.is_terminal(),
                "expired lease should be terminal");
        }
    }

    // Receipts should not exceed bounds
    assert!(authority.receipts().len() <= op_count + 1,
        "receipts should not exceed operation count");
});
