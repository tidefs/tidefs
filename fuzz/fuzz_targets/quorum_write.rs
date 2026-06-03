#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_quorum_write::{
    DurabilityMode, DigestBytes, EpochId, NodeId, PhaseKind,
    QuorumWriteId, QuorumWriteProtocol, TransferTicketId,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Derive parameters from fuzz input
    let target_count = ((data[0] as usize) % 7).max(1);
    let mode_idx = (data[1] as usize) % 3;
    let mode = match mode_idx {
        0 => DurabilityMode::QuorumFull,
        1 => DurabilityMode::QuorumWitness,
        _ => DurabilityMode::QuorumChain,
    };
    let byte_count = u64::from_le_bytes(
        data.get(2..10).unwrap_or(&[0u8; 8]).try_into().unwrap_or([0u8; 8])
    ).max(1);

    let mut digest = DigestBytes::default();
    let copy_len = 32.min(data.len().saturating_sub(10));
    digest[..copy_len].copy_from_slice(&data[10..10 + copy_len]);

    let targets: Vec<NodeId> = (0..target_count)
        .map(|i| NodeId::new(i as u64 + 1))
        .collect();

    // Build protocol state
    let protocol = QuorumWriteProtocol::new(
        QuorumWriteId::new(data[0] as u64 + 1),
        TransferTicketId::new(data[4] as u64),
        format!("fuzz_object_{}", data[3]),
        mode,
        NodeId::new(0),
        targets.clone(),
        byte_count,
        digest,
        EpochId::new(1),
    );

    // Verify min_quorum invariant
    let min_q = protocol.min_quorum();
    match mode {
        DurabilityMode::QuorumFull => {
            assert_eq!(min_q, target_count,
                "QuorumFull requires all targets");
        }
        DurabilityMode::QuorumWitness | DurabilityMode::QuorumChain => {
            let expected = target_count / 2 + 1;
            assert_eq!(min_q, expected,
                "witness/chain quorum must be N/2+1");
        }
    }

    // Phase starts at Prepare
    assert_eq!(protocol.current_phase, PhaseKind::Prepare);

    // Verify serde roundtrip
    let serialized = serde_json::to_vec(&protocol).expect("serialize");
    let deserialized: QuorumWriteProtocol = serde_json::from_slice(&serialized).expect("deserialize");
    assert_eq!(protocol, deserialized, "serde roundtrip mismatch");

    // Verify DurabilityMode min_quorum directly
    for n in 1..=16 {
        let q = mode.min_quorum(n);
        match mode {
            DurabilityMode::QuorumFull => assert_eq!(q, n),
            DurabilityMode::QuorumWitness | DurabilityMode::QuorumChain => {
                assert_eq!(q, n / 2 + 1);
            }
        }
    }
});
