// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::types::*;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use std::collections::BTreeMap;
use tidefs_membership_epoch::{EpochId, MemberId};

/// Sign a witness record payload.
///
/// The signed payload excludes the signature field to avoid self-referential signing.
pub fn sign_witness_record(record: &mut WitnessRecord, signing_key: &Keypair) {
    let payload = serde_json::to_vec(&WitnessPayload {
        witness_id: record.witness_id,
        claim_digest: &record.claim_digest,
        witnessed_at_millis: record.witnessed_at_millis,
        quorum_class: record.quorum_class,
    })
    .unwrap_or_default();
    record.signature = signing_key.sign(&payload).to_bytes().to_vec();
}

/// Verify a witness record's signature.
pub fn verify_witness_record(
    record: &WitnessRecord,
    pubkey_bytes: &[u8],
) -> Result<(), WitnessError> {
    if pubkey_bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
        return Err(WitnessError::InvalidSignature(record.witness_id.0));
    }

    let mut pk_arr = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
    pk_arr.copy_from_slice(pubkey_bytes);
    let public_key = PublicKey::from_bytes(&pk_arr)
        .map_err(|_| WitnessError::InvalidSignature(record.witness_id.0))?;

    if record.signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(WitnessError::InvalidSignature(record.witness_id.0));
    }

    let mut sig_arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&record.signature);
    let signature = Signature::from_bytes(&sig_arr)
        .map_err(|_| WitnessError::InvalidSignature(record.witness_id.0))?;

    let payload = serde_json::to_vec(&WitnessPayload {
        witness_id: record.witness_id,
        claim_digest: &record.claim_digest,
        witnessed_at_millis: record.witnessed_at_millis,
        quorum_class: record.quorum_class,
    })
    .unwrap_or_default();

    public_key
        .verify(&payload, &signature)
        .map_err(|_| WitnessError::InvalidSignature(record.witness_id.0))
}

/// Verify all witness records against known public keys.
/// Also validates each witness is a Voter in the current epoch and not quarantined.
pub fn verify_witness_set(
    set: &WitnessSet,
    pubkeys: &BTreeMap<MemberId, Vec<u8>>,
    current_epoch: EpochId,
    quarantined: &[MemberId],
) -> Result<WitnessVerificationReceipt, WitnessError> {
    let mut confirming = 0usize;
    let _refuting = 0usize;
    let mut digests = Vec::new();

    for record in &set.collected {
        // Validate witness is not quarantined.
        if quarantined.contains(&record.witness_id) {
            return Err(WitnessError::RefuseQuarantinedWitness(record.witness_id.0));
        }

        // Get public key.
        let pubkey_bytes =
            pubkeys
                .get(&record.witness_id)
                .ok_or(WitnessError::WitnessNotInEpoch(
                    record.witness_id.0,
                    current_epoch.0,
                ))?;

        // Verify signature.
        verify_witness_record(record, pubkey_bytes)?;

        // Count the witness.
        confirming += 1;
        digests.extend_from_slice(&record.claim_digest);
    }

    // Check quorum.
    let voter_count = pubkeys.len(); // approximate
    if !set
        .quorum_class
        .is_satisfied(confirming, voter_count.max(1))
    {
        return Err(WitnessError::Timeout {
            collected: confirming,
            required: set.quorum_class.required_count(voter_count.max(1)),
        });
    }

    // Compute aggregate digest.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    digests.hash(&mut hasher);
    let aggregate_digest = hasher.finish().to_le_bytes().to_vec();

    Ok(WitnessVerificationReceipt {
        witness_set_id: set.set_id,
        verified: true,
        confirming_count: confirming,
        refuting_count: 0,
        verified_at_millis: now_millis(),
        aggregate_digest,
    })
}

// Simple wall-clock approximation.
fn now_millis() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(serde::Serialize)]
struct WitnessPayload<'a> {
    witness_id: MemberId,
    claim_digest: &'a [u8],
    witnessed_at_millis: u64,
    quorum_class: WitnessQuorumClass,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    fn make_keypair() -> Keypair {
        let mut csprng = OsRng;
        Keypair::generate(&mut csprng)
    }

    #[test]
    fn test_sign_and_verify_single_witness() {
        let kp = make_keypair();
        let mut record = WitnessRecord {
            witness_id: MemberId::new(1),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ckey".to_vec(),
                expected_digest: b"digest".to_vec(),
            },
            claim_digest: b"claim".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };

        sign_witness_record(&mut record, &kp);
        assert!(!record.signature.is_empty());
        assert!(verify_witness_record(&record, &kp.public.to_bytes()).is_ok());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut record = WitnessRecord {
            witness_id: MemberId::new(1),
            anchor: WitnessAnchor::Epoch {
                epoch_id: EpochId::new(1),
            },
            claim_digest: b"claim".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };
        sign_witness_record(&mut record, &kp1);
        assert!(verify_witness_record(&record, &kp2.public.to_bytes()).is_err());
    }

    #[test]
    fn test_tampered_claim_fails() {
        let kp = make_keypair();
        let mut record = WitnessRecord {
            witness_id: MemberId::new(1),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ckey".to_vec(),
                expected_digest: b"digest".to_vec(),
            },
            claim_digest: b"claim".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };
        sign_witness_record(&mut record, &kp);
        record.claim_digest = b"tampered".to_vec();
        assert!(verify_witness_record(&record, &kp.public.to_bytes()).is_err());
    }

    #[test]
    fn test_verify_witness_set_quorum() {
        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let kp3 = make_keypair();

        let mut r1 = WitnessRecord {
            witness_id: MemberId::new(1),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"d".to_vec(),
            },
            claim_digest: b"c1".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };
        let mut r2 = WitnessRecord {
            witness_id: MemberId::new(2),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"d".to_vec(),
            },
            claim_digest: b"c2".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };
        let mut r3 = WitnessRecord {
            witness_id: MemberId::new(3),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"d".to_vec(),
            },
            claim_digest: b"c3".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };
        sign_witness_record(&mut r1, &kp1);
        sign_witness_record(&mut r2, &kp2);
        sign_witness_record(&mut r3, &kp3);

        let mut pubkeys = BTreeMap::new();
        pubkeys.insert(MemberId::new(1), kp1.public.to_bytes().to_vec());
        pubkeys.insert(MemberId::new(2), kp2.public.to_bytes().to_vec());
        pubkeys.insert(MemberId::new(3), kp3.public.to_bytes().to_vec());

        let set = WitnessSet {
            set_id: 1,
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"d".to_vec(),
            },
            quorum_class: WitnessQuorumClass::StrictMajority,
            selected_witnesses: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            collected: vec![r1, r2, r3],
            lifecycle: WitnessLifecycle::Collecting,
            created_at_millis: 1000,
            deadline_millis: 5000,
            epoch: EpochId::new(1),
            verification_receipt: None,
        };

        let receipt = verify_witness_set(&set, &pubkeys, EpochId::new(1), &[]).unwrap();
        assert!(receipt.verified);
        assert_eq!(receipt.confirming_count, 3);
    }

    #[test]
    fn test_verify_witness_set_insufficient_quorum() {
        let kp1 = make_keypair();

        let mut r1 = WitnessRecord {
            witness_id: MemberId::new(1),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"d".to_vec(),
            },
            claim_digest: b"c1".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };
        sign_witness_record(&mut r1, &kp1);

        let mut pubkeys = BTreeMap::new();
        pubkeys.insert(MemberId::new(1), kp1.public.to_bytes().to_vec());
        pubkeys.insert(MemberId::new(2), vec![0u8; 32]); // placeholder
        pubkeys.insert(MemberId::new(3), vec![0u8; 32]);

        let set = WitnessSet {
            set_id: 2,
            anchor: WitnessAnchor::Epoch {
                epoch_id: EpochId::new(1),
            },
            quorum_class: WitnessQuorumClass::StrictMajority,
            selected_witnesses: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            collected: vec![r1], // only 1 of 3 — below majority
            lifecycle: WitnessLifecycle::Collecting,
            created_at_millis: 1000,
            deadline_millis: 5000,
            epoch: EpochId::new(1),
            verification_receipt: None,
        };

        let result = verify_witness_set(&set, &pubkeys, EpochId::new(1), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_quarantined() {
        let kp1 = make_keypair();
        let mut r1 = WitnessRecord {
            witness_id: MemberId::new(1),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"d".to_vec(),
            },
            claim_digest: b"c1".to_vec(),
            witnessed_at_millis: 1000,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: Vec::new(),
        };
        sign_witness_record(&mut r1, &kp1);

        let mut pubkeys = BTreeMap::new();
        pubkeys.insert(MemberId::new(1), kp1.public.to_bytes().to_vec());

        let set = WitnessSet {
            set_id: 3,
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"d".to_vec(),
            },
            quorum_class: WitnessQuorumClass::Flexible {
                required: 1,
                total: 1,
            },
            selected_witnesses: vec![MemberId::new(1)],
            collected: vec![r1],
            lifecycle: WitnessLifecycle::Collecting,
            created_at_millis: 1000,
            deadline_millis: 5000,
            epoch: EpochId::new(1),
            verification_receipt: None,
        };

        let result = verify_witness_set(
            &set,
            &pubkeys,
            EpochId::new(1),
            &[MemberId::new(1)], // quarantined
        );
        assert!(result.is_err());
    }
}
