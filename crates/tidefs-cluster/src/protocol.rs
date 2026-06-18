// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Membership lease wire protocol: acquire, renew, release, and expire
//! message types with BLAKE3-256 integrity per frame.
//!
//! Each message is serialized with `bincode` and carries a domain-separated
//! BLAKE3-256 digest (domain `tidefs-cluster-membership-lease-protocol-v1`)
//! computed over the canonical bincode encoding of the message payload.
//!
//! ## Wire format
//!
//! ```text
//! [1-byte discriminant][bincode payload][32-byte BLAKE3 digest]
//! ```

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::EpochId;

/// Domain separation for protocol message integrity.
const PROTOCOL_DOMAIN: &str = "tidefs-cluster-membership-lease-protocol-v1";

/// Encode/decode errors for the lease protocol.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("bincode serialize error: {0}")]
    Serialize(String),
    #[error("bincode deserialize error: {0}")]
    Deserialize(String),
    #[error("BLAKE3 digest mismatch: expected {expected:?}, got {got:?}")]
    DigestMismatch { expected: [u8; 32], got: [u8; 32] },
    #[error("unknown message discriminant: {0:#x}")]
    UnknownDiscriminant(u8),
    #[error("payload too short: {0} bytes")]
    PayloadTooShort(usize),
}

// ── Message discriminants ──────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Discriminant {
    Acquire = 0x01,
    AcquireAck = 0x02,
    AcquireNack = 0x03,
    Renew = 0x04,
    RenewAck = 0x05,
    RenewNack = 0x06,
    Release = 0x07,
    ReleaseAck = 0x08,
    ExpireNotify = 0x09,
}

impl Discriminant {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Acquire),
            0x02 => Some(Self::AcquireAck),
            0x03 => Some(Self::AcquireNack),
            0x04 => Some(Self::Renew),
            0x05 => Some(Self::RenewAck),
            0x06 => Some(Self::RenewNack),
            0x07 => Some(Self::Release),
            0x08 => Some(Self::ReleaseAck),
            0x09 => Some(Self::ExpireNotify),
            _ => None,
        }
    }
}

// ── Message types ──────────────────────────────────────────────────

/// Acquire a membership lease slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireRequest {
    pub node_id: u64,
    pub epoch: EpochId,
    pub slot: u64,
    pub lease_term_ms: u64,
    pub request_id: u64,
}

/// Ack an acquisition — lease slot granted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireAck {
    pub request_id: u64,
    pub lease_id: u64,
    pub epoch: EpochId,
    pub slot: u64,
    pub lease_term_ms: u64,
    pub deadline_ms: u64,
}

/// Nack an acquisition — request denied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireNack {
    pub request_id: u64,
    pub reason: String,
}

/// Renew an existing lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewRequest {
    pub node_id: u64,
    pub lease_id: u64,
    pub epoch: EpochId,
}

/// Ack a renewal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewAck {
    pub lease_id: u64,
    pub new_deadline_ms: u64,
}

/// Nack a renewal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewNack {
    pub lease_id: u64,
    pub reason: String,
}

/// Release a held lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub node_id: u64,
    pub lease_id: u64,
    pub epoch: EpochId,
}

/// Ack a release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAck {
    pub lease_id: u64,
}

/// Notify that a lease has expired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpireNotify {
    pub node_id: u64,
    pub lease_id: u64,
    pub epoch: EpochId,
}

/// All membership lease protocol messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipLeaseMessage {
    Acquire(AcquireRequest),
    AcquireAck(AcquireAck),
    AcquireNack(AcquireNack),
    Renew(RenewRequest),
    RenewAck(RenewAck),
    RenewNack(RenewNack),
    Release(ReleaseRequest),
    ReleaseAck(ReleaseAck),
    ExpireNotify(ExpireNotify),
}

impl MembershipLeaseMessage {
    /// Encode this message to wire format bytes.
    ///
    /// Returns bincode-serialized payload preceded by discriminant byte
    /// and followed by 32-byte BLAKE3 digest.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let payload = self.serialize_payload()?;
        let digest = compute_digest(&payload);
        let mut bytes = Vec::with_capacity(1 + payload.len() + 32);
        bytes.push(self.discriminant());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    /// Decode a membership lease message from wire format bytes.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 33 {
            return Err(ProtocolError::PayloadTooShort(data.len()));
        }

        let discriminant = data[0];
        let payload_end = data.len() - 32;
        let payload = &data[1..payload_end];
        let received_digest: [u8; 32] = data[payload_end..]
            .try_into()
            .map_err(|_| ProtocolError::PayloadTooShort(data.len()))?;

        let expected_digest = compute_digest(payload);
        if received_digest != expected_digest {
            return Err(ProtocolError::DigestMismatch {
                expected: expected_digest,
                got: received_digest,
            });
        }

        Self::deserialize_payload(discriminant, payload)
    }

    fn discriminant(&self) -> u8 {
        match self {
            Self::Acquire(_) => Discriminant::Acquire as u8,
            Self::AcquireAck(_) => Discriminant::AcquireAck as u8,
            Self::AcquireNack(_) => Discriminant::AcquireNack as u8,
            Self::Renew(_) => Discriminant::Renew as u8,
            Self::RenewAck(_) => Discriminant::RenewAck as u8,
            Self::RenewNack(_) => Discriminant::RenewNack as u8,
            Self::Release(_) => Discriminant::Release as u8,
            Self::ReleaseAck(_) => Discriminant::ReleaseAck as u8,
            Self::ExpireNotify(_) => Discriminant::ExpireNotify as u8,
        }
    }

    fn serialize_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        let bytes = match self {
            Self::Acquire(v) => bincode::serialize(v),
            Self::AcquireAck(v) => bincode::serialize(v),
            Self::AcquireNack(v) => bincode::serialize(v),
            Self::Renew(v) => bincode::serialize(v),
            Self::RenewAck(v) => bincode::serialize(v),
            Self::RenewNack(v) => bincode::serialize(v),
            Self::Release(v) => bincode::serialize(v),
            Self::ReleaseAck(v) => bincode::serialize(v),
            Self::ExpireNotify(v) => bincode::serialize(v),
        };
        bytes.map_err(|e| ProtocolError::Serialize(e.to_string()))
    }

    fn deserialize_payload(discriminant: u8, payload: &[u8]) -> Result<Self, ProtocolError> {
        let disc = Discriminant::from_u8(discriminant)
            .ok_or(ProtocolError::UnknownDiscriminant(discriminant))?;

        let msg = match disc {
            Discriminant::Acquire => Self::Acquire(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::AcquireAck => Self::AcquireAck(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::AcquireNack => Self::AcquireNack(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::Renew => Self::Renew(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::RenewAck => Self::RenewAck(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::RenewNack => Self::RenewNack(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::Release => Self::Release(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::ReleaseAck => Self::ReleaseAck(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
            Discriminant::ExpireNotify => Self::ExpireNotify(
                bincode::deserialize(payload)
                    .map_err(|e| ProtocolError::Deserialize(e.to_string()))?,
            ),
        };
        Ok(msg)
    }
}

/// Compute BLAKE3-256 digest over payload bytes with domain separation.
fn compute_digest(payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_derive_key(PROTOCOL_DOMAIN);
    h.update(payload);
    h.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;

    #[test]
    fn roundtrip_acquire() {
        let msg = MembershipLeaseMessage::Acquire(AcquireRequest {
            node_id: 1,
            epoch: EpochId(5),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 42,
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_acquire_ack() {
        let msg = MembershipLeaseMessage::AcquireAck(AcquireAck {
            request_id: 42,
            lease_id: 100,
            epoch: EpochId(5),
            slot: 0,
            lease_term_ms: 30_000,
            deadline_ms: 30_000,
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_acquire_nack() {
        let msg = MembershipLeaseMessage::AcquireNack(AcquireNack {
            request_id: 42,
            reason: "slot occupied".into(),
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_renew() {
        let msg = MembershipLeaseMessage::Renew(RenewRequest {
            node_id: 1,
            lease_id: 100,
            epoch: EpochId(5),
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_renew_ack() {
        let msg = MembershipLeaseMessage::RenewAck(RenewAck {
            lease_id: 100,
            new_deadline_ms: 60_000,
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_renew_nack() {
        let msg = MembershipLeaseMessage::RenewNack(RenewNack {
            lease_id: 100,
            reason: "epoch changed".into(),
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_release() {
        let msg = MembershipLeaseMessage::Release(ReleaseRequest {
            node_id: 1,
            lease_id: 100,
            epoch: EpochId(5),
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_release_ack() {
        let msg = MembershipLeaseMessage::ReleaseAck(ReleaseAck { lease_id: 100 });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_expire_notify() {
        let msg = MembershipLeaseMessage::ExpireNotify(ExpireNotify {
            node_id: 1,
            lease_id: 100,
            epoch: EpochId(5),
        });
        let encoded = msg.encode().unwrap();
        let decoded = MembershipLeaseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_rejects_garbage() {
        let garbage = vec![0xFFu8; 100];
        assert!(MembershipLeaseMessage::decode(&garbage).is_err());
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(MembershipLeaseMessage::decode(&[]).is_err());
    }

    #[test]
    fn decode_rejects_short() {
        assert!(MembershipLeaseMessage::decode(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_discriminant() {
        // Valid digest but unknown discriminant 0xFE
        let payload = bincode::serialize(&AcquireRequest {
            node_id: 1,
            epoch: EpochId(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        })
        .unwrap();
        let digest = compute_digest(&payload);
        let mut bytes = Vec::new();
        bytes.push(0xFE); // unknown discriminant
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&digest);
        assert!(MembershipLeaseMessage::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_digest_mismatch() {
        let msg = MembershipLeaseMessage::Acquire(AcquireRequest {
            node_id: 1,
            epoch: EpochId(5),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 42,
        });
        let encoded = msg.encode().unwrap();

        // Tamper with the payload
        let mut tampered = encoded.clone();
        tampered[1] ^= 0xFF; // flip bits in payload
        assert!(MembershipLeaseMessage::decode(&tampered).is_err());
    }

    #[test]
    fn deterministic_encoding() {
        let msg1 = MembershipLeaseMessage::Acquire(AcquireRequest {
            node_id: 1,
            epoch: EpochId(5),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 42,
        });
        let msg2 = msg1.clone();

        let encoded1 = msg1.encode().unwrap();
        let encoded2 = msg2.encode().unwrap();
        assert_eq!(encoded1, encoded2);
    }
}
