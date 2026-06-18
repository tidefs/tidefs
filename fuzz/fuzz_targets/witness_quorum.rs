// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_witness_set::{
    WitnessQuorumClass, WitnessSet, WitnessAnchor, WitnessRecord, WitnessLifecycle,
};
use tidefs_membership_epoch::{MemberId, EpochId};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Fuzz WitnessQuorumClass invariants
    let total = ((data[0] as usize) % 16).max(1);
    let required = ((data[1] as usize) % total).max(1);

    // Strict majority
    let sm = WitnessQuorumClass::StrictMajority;
    let sm_required = sm.required_count(total);
    assert!(sm_required >= 1, "strict majority requires >= 1");
    assert!(sm_required <= total, "strict majority <= total");
    assert!(sm.is_satisfied(sm_required, total), "quorum satisfied at min");
    if sm_required > 0 {
        assert!(!sm.is_satisfied(sm_required.saturating_sub(1), total),
            "below minimum not satisfied");
    }

    // Flexible
    let flex = WitnessQuorumClass::Flexible { required, total };
    let flex_required = flex.required_count(total);
    assert!(flex_required <= total, "flexible required <= total");
    assert!(flex.is_satisfied(flex_required, total),
        "flexible quorum satisfied at min");
    if flex_required > 0 {
        assert!(!flex.is_satisfied(flex_required.saturating_sub(1), total),
            "below flexible min not satisfied");
    }

    // Fuzz WitnessSet construction and lifecycle
    let anchor = if data[2] % 2 == 0 {
        WitnessAnchor::Chunk {
            chunk_key: data[..16.min(data.len())].to_vec(),
            expected_digest: data[..32.min(data.len())].to_vec(),
        }
    } else {
        WitnessAnchor::Epoch {
            epoch_id: EpochId::new(data[2] as u64),
        }
    };

    let quorum_class = if data[3] % 2 == 0 {
        WitnessQuorumClass::StrictMajority
    } else {
        WitnessQuorumClass::Flexible { required, total }
    };

    let q_required = quorum_class.required_count(total);

    // Build witness records
    let mut collected = Vec::new();
    let selected = (0..total as u64)
        .map(|i| MemberId::new(i + 1))
        .collect::<Vec<_>>();

    let witness_count = (data[5] as usize % total).max(1);
    for i in 0..witness_count {
        collected.push(WitnessRecord {
            witness_id: MemberId::new(i as u64 + 1),
            anchor: anchor.clone(),
            claim_digest: vec![0u8; 32],
            witnessed_at_millis: data[4] as u64,
            quorum_class,
            signature: vec![],
        });
    }

    let lifecycle = if witness_count >= q_required && q_required > 0 {
        WitnessLifecycle::QuorumReached
    } else {
        WitnessLifecycle::Collecting
    };

    let set = WitnessSet {
        set_id: data[2] as u64,
        anchor,
        quorum_class,
        selected_witnesses: selected,
        collected,
        lifecycle,
        created_at_millis: data[4] as u64,
        deadline_millis: 0,
        epoch: EpochId::new(1),
            verification_receipt: None,
    };

    // QuorumReached should satisfy quorum
    if matches!(set.lifecycle, WitnessLifecycle::QuorumReached) {
        assert!(quorum_class.is_satisfied(set.collected.len(), total),
            "QuorumReached must satisfy quorum");
    }

    // Collecting should not satisfy quorum (unless zero witnesses required)
    if matches!(set.lifecycle, WitnessLifecycle::Collecting) && witness_count > 0 {
        if witness_count < q_required || q_required == 0 {
            // expected
        } else {
            assert!(!quorum_class.is_satisfied(set.collected.len(), total),
                "Collecting should not satisfy quorum");
        }
    }
});
