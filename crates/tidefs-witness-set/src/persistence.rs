// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// BLAKE3-verified persistence for WitnessSetConfig.
//
// Witness configurations are serialized to a deterministic JSON form,
// hashed with BLAKE3, and stored alongside the hash for integrity
// verification on load. Consumers (tidefs-local-filesystem, quorum-write
// runtime) store the resulting byte blobs in the local-object-store or
// committed-root slots.
//
// The wire format is:
//   [4 bytes LE: payload_len] [payload_len bytes: JSON config] [32 bytes: BLAKE3 hash]

use crate::config::WitnessSetConfig;
use serde::{Deserialize, Serialize};

/// A persisted witness configuration with BLAKE3 integrity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersistedWitnessConfig {
    /// The witness set configuration.
    pub config: WitnessSetConfig,
    /// BLAKE3-256 hash of the canonical serialized form.
    pub blake3_hash: [u8; 32],
}

/// Errors that can occur during persistence operations.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PersistError {
    #[error("serialization failed: {0}")]
    Serialize(String),
    #[error("deserialization failed: {0}")]
    Deserialize(String),
    #[error("BLAKE3 integrity check failed: expected {expected:?}, got {actual:?}")]
    IntegrityMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("payload too short: {0} bytes")]
    PayloadTooShort(usize),
    #[error("invalid payload length prefix: {0}")]
    InvalidLengthPrefix(u32),
}

impl WitnessSetConfig {
    /// Serialize the config and append a BLAKE3-256 integrity hash.
    ///
    /// Returns the wire-format bytes: 4-byte LE payload length, the JSON
    /// serialization of the config, and a 32-byte BLAKE3-256 hash of the
    /// config bytes.
    pub fn to_persistent(&self) -> Result<Vec<u8>, PersistError> {
        let payload =
            serde_json::to_vec(self).map_err(|e| PersistError::Serialize(e.to_string()))?;
        let hash = blake3::hash(&payload);
        let mut out = Vec::with_capacity(4 + payload.len() + 32);
        let len_u32: u32 = payload
            .len()
            .try_into()
            .map_err(|_| PersistError::Serialize("payload too large".into()))?;
        out.extend_from_slice(&len_u32.to_le_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(hash.as_bytes());
        Ok(out)
    }

    /// Deserialize from wire-format bytes and verify the BLAKE3 hash.
    ///
    /// Returns `Err(PersistError::IntegrityMismatch)` if the hash does
    /// not match the payload.
    pub fn from_persistent(data: &[u8]) -> Result<Self, PersistError> {
        if data.len() < 36 {
            return Err(PersistError::PayloadTooShort(data.len()));
        }
        let payload_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if payload_len == 0 || payload_len > data.len().saturating_sub(36) {
            return Err(PersistError::InvalidLengthPrefix(payload_len as u32));
        }
        let payload = &data[4..4 + payload_len];
        let expected_hash: [u8; 32] = data[4 + payload_len..4 + payload_len + 32]
            .try_into()
            .map_err(|_| PersistError::PayloadTooShort(data.len()))?;
        let actual_hash = blake3::hash(payload);
        if actual_hash.as_bytes() != &expected_hash {
            return Err(PersistError::IntegrityMismatch {
                expected: expected_hash,
                actual: *actual_hash.as_bytes(),
            });
        }
        let config: WitnessSetConfig = serde_json::from_slice(payload)
            .map_err(|e| PersistError::Deserialize(e.to_string()))?;
        Ok(config)
    }

    /// Build a `PersistedWitnessConfig` holding the config and its hash.
    pub fn to_persisted(&self) -> Result<PersistedWitnessConfig, PersistError> {
        let payload =
            serde_json::to_vec(self).map_err(|e| PersistError::Serialize(e.to_string()))?;
        let hash = blake3::hash(&payload);
        Ok(PersistedWitnessConfig {
            config: self.clone(),
            blake3_hash: *hash.as_bytes(),
        })
    }

    /// Verify that a `PersistedWitnessConfig` matches its stored hash.
    ///
    /// Re-serializes the contained config and checks the BLAKE3 hash.
    /// Returns `Ok(&config)` on success.
    pub fn verify_persisted(
        persisted: &PersistedWitnessConfig,
    ) -> Result<&WitnessSetConfig, PersistError> {
        let payload = serde_json::to_vec(&persisted.config)
            .map_err(|e| PersistError::Serialize(e.to_string()))?;
        let actual = blake3::hash(&payload);
        if actual.as_bytes() != &persisted.blake3_hash {
            return Err(PersistError::IntegrityMismatch {
                expected: persisted.blake3_hash,
                actual: *actual.as_bytes(),
            });
        }
        Ok(&persisted.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MembershipQuorum, WitnessMember};

    fn sample_config() -> WitnessSetConfig {
        WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 2),
                WitnessMember::new(3, 1),
            ],
            MembershipQuorum::StrictMajority,
        )
        .with_min_healthy_fraction(0.6)
    }

    // -- Round-trip through wire format ------------------------------------

    #[test]
    fn test_round_trip_wire_format() {
        let cfg = sample_config();
        let wire = cfg.to_persistent().unwrap();
        assert!(wire.len() > 36);
        let restored = WitnessSetConfig::from_persistent(&wire).unwrap();
        assert_eq!(restored.len(), cfg.len());
        assert_eq!(restored.total_weight(), cfg.total_weight());
        assert_eq!(restored.threshold, cfg.threshold);
        assert_eq!(restored.min_healthy_fraction, cfg.min_healthy_fraction);
    }

    #[test]
    fn test_round_trip_empty_config() {
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::SuperMajority);
        let wire = cfg.to_persistent().unwrap();
        let restored = WitnessSetConfig::from_persistent(&wire).unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.threshold, MembershipQuorum::SuperMajority);
    }

    #[test]
    fn test_round_trip_absolute_weight() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(10, 5)],
            MembershipQuorum::AbsoluteWeight(3),
        );
        let wire = cfg.to_persistent().unwrap();
        let restored = WitnessSetConfig::from_persistent(&wire).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.threshold, MembershipQuorum::AbsoluteWeight(3));
    }

    // -- Integrity: tampered payload ---------------------------------------

    #[test]
    fn test_tampered_payload_detected() {
        let cfg = sample_config();
        let mut wire = cfg.to_persistent().unwrap();
        // Flip a bit in the payload.
        wire[6] ^= 0x01;
        let result = WitnessSetConfig::from_persistent(&wire);
        assert!(matches!(
            result,
            Err(PersistError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn test_tampered_hash_detected() {
        let cfg = sample_config();
        let mut wire = cfg.to_persistent().unwrap();
        // Corrupt the hash bytes at the end.
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;
        let result = WitnessSetConfig::from_persistent(&wire);
        assert!(matches!(
            result,
            Err(PersistError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn test_truncated_payload_detected() {
        let cfg = sample_config();
        let wire = cfg.to_persistent().unwrap();
        // Truncate mid-payload.
        let truncated = &wire[..wire.len() - 33];
        let result = WitnessSetConfig::from_persistent(truncated);
        assert!(result.is_err(), "expected error from truncated payload");
    }

    #[test]
    fn test_too_short_data() {
        let result = WitnessSetConfig::from_persistent(&[0u8; 4]);
        assert!(result.is_err(), "expected error from truncated payload");
    }

    #[test]
    fn test_invalid_length_prefix() {
        let cfg = sample_config();
        let mut wire = cfg.to_persistent().unwrap();
        // Corrupt the length prefix.
        wire[0] = 0xFF;
        wire[1] = 0xFF;
        wire[2] = 0xFF;
        wire[3] = 0xFF;
        let result = WitnessSetConfig::from_persistent(&wire);
        assert!(matches!(result, Err(PersistError::InvalidLengthPrefix(_))));
    }

    // -- PersistedWitnessConfig round-trip --------------------------------

    #[test]
    fn test_persisted_struct_round_trip() {
        let cfg = sample_config();
        let persisted = cfg.to_persisted().unwrap();
        assert_eq!(persisted.config, cfg);
        assert_eq!(persisted.blake3_hash.len(), 32);

        // Verify
        let verified = WitnessSetConfig::verify_persisted(&persisted).unwrap();
        assert_eq!(verified, &cfg);
    }

    #[test]
    fn test_persisted_tampered_config_detected() {
        let cfg = sample_config();
        let mut persisted = cfg.to_persisted().unwrap();
        // Tamper with a member weight.
        persisted.config.members[0].weight = 999;
        let result = WitnessSetConfig::verify_persisted(&persisted);
        assert!(matches!(
            result,
            Err(PersistError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn test_persisted_tampered_hash_detected() {
        let cfg = sample_config();
        let mut persisted = cfg.to_persisted().unwrap();
        persisted.blake3_hash[0] ^= 0xFF;
        let result = WitnessSetConfig::verify_persisted(&persisted);
        assert!(matches!(
            result,
            Err(PersistError::IntegrityMismatch { .. })
        ));
    }

    // -- Deterministic output ----------------------------------------------

    #[test]
    fn test_deterministic_persistence_output() {
        let cfg = sample_config();
        let wire1 = cfg.to_persistent().unwrap();
        let wire2 = cfg.to_persistent().unwrap();
        assert_eq!(wire1, wire2);

        let hash1 = cfg.to_persisted().unwrap().blake3_hash;
        let hash2 = cfg.to_persisted().unwrap().blake3_hash;
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_configs_have_different_hashes() {
        let cfg1 = sample_config();
        let cfg2 = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 1)],
            MembershipQuorum::StrictMajority,
        );
        let hash1 = cfg1.to_persisted().unwrap().blake3_hash;
        let hash2 = cfg2.to_persisted().unwrap().blake3_hash;
        assert_ne!(hash1, hash2);
    }
}
