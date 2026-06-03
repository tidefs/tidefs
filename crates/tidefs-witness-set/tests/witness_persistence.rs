// Integration tests: WitnessSet persistence and reload across simulated
// crash/restart cycles, codec fidelity for wire transfer, and
// WitnessSetConfig BLAKE3-verified integrity verification.

use tidefs_witness_set::witness_set::{QuorumThreshold, WitnessSet};
use tidefs_witness_set::{
    MembershipQuorum, PersistError, WitnessMember, WitnessSetCodec, WitnessSetConfig,
};

// -- Helper ---------------------------------------------------------------

fn sample_config() -> WitnessSetConfig {
    WitnessSetConfig::new(
        vec![
            WitnessMember::new(1, 1),
            WitnessMember::new(2, 2),
            WitnessMember::new(3, 1),
            WitnessMember::new(4, 2),
            WitnessMember::new(5, 1),
        ],
        MembershipQuorum::StrictMajority,
    )
    .with_min_healthy_fraction(0.6)
}

// -- WitnessSetConfig persistence round-trip -------------------------------

#[test]
fn test_config_persist_and_restore() {
    let cfg = sample_config();
    let wire = cfg.to_persistent().unwrap();
    let restored = WitnessSetConfig::from_persistent(&wire).unwrap();

    assert_eq!(restored.len(), cfg.len());
    assert_eq!(restored.total_weight(), cfg.total_weight());
    assert_eq!(restored.threshold, cfg.threshold);
    assert_eq!(restored.min_healthy_fraction, cfg.min_healthy_fraction);
    for i in 0..cfg.len() {
        assert_eq!(restored.members[i].node_id, cfg.members[i].node_id);
        assert_eq!(restored.members[i].weight, cfg.members[i].weight);
    }
}

#[test]
fn test_config_tamper_detection() {
    let cfg = sample_config();
    let wire = cfg.to_persistent().unwrap();

    let tamper_positions = [4, wire.len() / 2, wire.len() - 10];
    for pos in &tamper_positions {
        let mut corrupted = wire.clone();
        corrupted[*pos] ^= 0x01;
        let result = WitnessSetConfig::from_persistent(&corrupted);
        assert!(
            matches!(result, Err(PersistError::IntegrityMismatch { .. })),
            "tamper at position {pos} should be detected"
        );
    }
}

#[test]
fn test_config_persisted_struct_verify() {
    let cfg = sample_config();
    let persisted = cfg.to_persisted().unwrap();

    let verified = WitnessSetConfig::verify_persisted(&persisted).unwrap();
    assert_eq!(verified, &cfg);

    let mut tampered = persisted.clone();
    tampered.config.members[0].weight = 999;
    let result = WitnessSetConfig::verify_persisted(&tampered);
    assert!(matches!(
        result,
        Err(PersistError::IntegrityMismatch { .. })
    ));

    let mut tampered_hash = persisted.clone();
    tampered_hash.blake3_hash[0] ^= 0xFF;
    let result = WitnessSetConfig::verify_persisted(&tampered_hash);
    assert!(matches!(
        result,
        Err(PersistError::IntegrityMismatch { .. })
    ));
}

// -- WitnessSet codec round-trip for wire transfer -------------------------

#[test]
fn test_witness_set_encode_decode_full_cycle() {
    let mut ws = WitnessSet::with_epoch(QuorumThreshold::SuperMajority, 7);
    for id in 1..=10u64 {
        ws.add_witness(id);
    }
    ws.ack(1, 100);
    ws.ack(3, 100);
    ws.ack(5, 100);
    ws.ack(7, 100);
    ws.ack(2, 200);
    ws.ack(4, 200);
    ws.ack(6, 200);
    ws.ack(8, 200);
    ws.ack(10, 200);

    let encoded = WitnessSetCodec::encode_to_vec(&ws);
    let decoded = WitnessSetCodec::decode(&encoded).unwrap();

    assert_eq!(decoded.epoch(), 7);
    assert_eq!(decoded.len(), 10);
    assert_eq!(decoded.threshold(), QuorumThreshold::SuperMajority);
    assert_eq!(decoded.ack_count(100), 4);
    assert_eq!(decoded.ack_count(200), 5);
    assert_eq!(decoded.operation_count(), 2);
}

#[test]
fn test_witness_set_codec_empty_to_full_to_empty() {
    let mut ws = WitnessSet::new(QuorumThreshold::Exact(3));
    let enc1 = WitnessSetCodec::encode_to_vec(&ws);
    let dec1 = WitnessSetCodec::decode(&enc1).unwrap();
    assert!(dec1.is_empty());

    for id in 1..=5u64 {
        ws.add_witness(id);
    }
    ws.ack(1, 10);
    ws.ack(2, 10);
    ws.ack(3, 10);
    let enc2 = WitnessSetCodec::encode_to_vec(&ws);
    let dec2 = WitnessSetCodec::decode(&enc2).unwrap();
    assert_eq!(dec2.len(), 5);
    assert!(dec2.has_quorum(10));

    ws.advance_epoch(1);
    let enc3 = WitnessSetCodec::encode_to_vec(&ws);
    let dec3 = WitnessSetCodec::decode(&enc3).unwrap();
    assert_eq!(dec3.len(), 5);
    assert_eq!(dec3.epoch(), 1);
    assert_eq!(dec3.operation_count(), 0);
}

#[test]
fn test_codec_buffer_underrun_variants() {
    let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
    for id in 1..=20u64 {
        ws.add_witness(id);
    }
    ws.ack(1, 100);
    ws.ack(2, 100);
    ws.ack(3, 100);

    let full = WitnessSetCodec::encode_to_vec(&ws);
    for len in [0, 1, 2, 5, 10, full.len() / 4, full.len() / 2] {
        let truncated = &full[..len.min(full.len())];
        if len < full.len() {
            assert!(WitnessSetCodec::decode(truncated).is_err());
        }
    }
    assert!(WitnessSetCodec::decode(&full).is_ok());
}

// -- Crash/restart simulation -----------------------------------------------

#[test]
fn test_simulated_crash_restart_witness_state() {
    let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 0);
    for id in 1..=5u64 {
        ws.add_witness(id);
    }
    ws.ack(1, 42);
    ws.ack(2, 42);
    ws.ack(3, 42);

    let snapshot = WitnessSetCodec::encode_to_vec(&ws);
    let recovered = WitnessSetCodec::decode(&snapshot).unwrap();

    assert_eq!(recovered.epoch(), 0);
    assert_eq!(recovered.len(), 5);
    assert!(recovered.has_quorum(42));
    assert_eq!(recovered.ack_count(42), 3);

    let mut ws2 = recovered;
    ws2.ack(4, 42);
    ws2.ack(5, 42);
    assert_eq!(ws2.ack_count(42), 5);
    assert!(ws2.has_quorum(42));
}

#[test]
fn test_crash_restart_mid_epoch() {
    let mut ws = WitnessSet::with_epoch(QuorumThreshold::SuperMajority, 3);
    for id in 1..=7u64 {
        ws.add_witness(id);
    }
    ws.ack(1, 100);
    ws.ack(2, 100);
    ws.ack(3, 100);
    ws.ack(4, 100);
    ws.ack(1, 200);
    ws.ack(2, 200);
    ws.ack(3, 200);
    ws.ack(4, 200);
    ws.ack(5, 200);

    let snapshot = WitnessSetCodec::encode_to_vec(&ws);
    let recovered = WitnessSetCodec::decode(&snapshot).unwrap();

    assert_eq!(recovered.epoch(), 3);
    assert_eq!(recovered.len(), 7);
    assert!(!recovered.has_quorum(100));
    assert!(recovered.has_quorum(200));
    assert_eq!(recovered.operation_count(), 2);

    let mut ws2 = recovered;
    ws2.ack(5, 100);
    assert!(ws2.has_quorum(100));
}

#[test]
fn test_crash_restart_epoch_advances_then_restart() {
    let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 10);
    for id in 1..=3u64 {
        ws.add_witness(id);
    }
    ws.ack(1, 100);
    ws.ack(2, 100);
    ws.ack(3, 100);

    ws.advance_epoch(11);

    let snapshot = WitnessSetCodec::encode_to_vec(&ws);
    let recovered = WitnessSetCodec::decode(&snapshot).unwrap();

    assert_eq!(recovered.epoch(), 11);
    assert_eq!(recovered.len(), 3);
    assert_eq!(recovered.operation_count(), 0);
    assert!(!recovered.has_quorum(100));
}

// -- Membership changes across persistence cycles --------------------------

#[test]
fn test_add_remove_persist_cycle() {
    let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
    ws.add_witness(10);
    ws.add_witness(20);
    ws.add_witness(30);
    ws.ack(10, 1);
    ws.ack(20, 1);
    ws.ack(30, 1);

    ws.remove_witness(20);
    ws.add_witness(40);
    ws.ack(40, 1);

    let snapshot = WitnessSetCodec::encode_to_vec(&ws);
    let recovered = WitnessSetCodec::decode(&snapshot).unwrap();

    assert_eq!(recovered.len(), 3);
    assert!(!recovered.contains(20));
    assert!(recovered.contains(40));
    assert!(recovered.has_quorum(1));
}

// -- Different threshold types across persistence ---------------------------

#[test]
fn test_all_threshold_types_survive_persist_cycle() {
    for threshold in [
        QuorumThreshold::StrictMajority,
        QuorumThreshold::SuperMajority,
        QuorumThreshold::Exact(5),
    ] {
        let mut ws = WitnessSet::new(threshold);
        for id in 1..=10u64 {
            ws.add_witness(id);
        }
        ws.ack(1, 100);
        ws.ack(2, 100);

        let snapshot = WitnessSetCodec::encode_to_vec(&ws);
        let recovered = WitnessSetCodec::decode(&snapshot).unwrap();

        assert_eq!(recovered.threshold(), threshold);
        assert_eq!(recovered.ack_count(100), 2);
        assert_eq!(recovered.len(), 10);
    }
}

// -- Empty set edge cases ---------------------------------------------------

#[test]
fn test_empty_set_persist_restore() {
    let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
    let snapshot = WitnessSetCodec::encode_to_vec(&ws);
    let recovered = WitnessSetCodec::decode(&snapshot).unwrap();

    assert!(recovered.is_empty());
    assert_eq!(recovered.epoch(), 0);
    assert_eq!(recovered.operation_count(), 0);
}

#[test]
fn test_empty_config_persist_roundtrip() {
    let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::SuperMajority);
    let wire = cfg.to_persistent().unwrap();
    let restored = WitnessSetConfig::from_persistent(&wire).unwrap();
    assert!(restored.is_empty());
    assert_eq!(restored.threshold, MembershipQuorum::SuperMajority);

    let persisted = cfg.to_persisted().unwrap();
    let verified = WitnessSetConfig::verify_persisted(&persisted).unwrap();
    assert!(verified.is_empty());
}
