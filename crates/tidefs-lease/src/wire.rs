//! Lease service wire protocol message types and codec.
//!
//! Implements the cluster lock service wire protocol so that TideFS nodes
//! can exchange lease requests, grants, revocations, renewals, and releases
//! over established transport sessions.
//!
//! ## Wire format
//!
//! Each lease wire message is serialized with `bincode`, protected by a
//! domain-separated BLAKE3-256 digest, and framed with a binary-schema
//! envelope header per P2-03 §2.1:
//!
//! ```text
//! [64-byte EnvelopeHeader][bincode payload][32-byte BLAKE3 digest]
//! ```
//!
//! The envelope carries LE family=9 type=1 version=1.0 with CRC32C header
//! protection and BLAKE3-256 strong digest profile. The trailing 32-byte
//! digest covers the bincode payload.

use serde::{Deserialize, Serialize};
use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{
    BinarySchemaError, ChecksumProfile, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};
use tidefs_binary_schema_framing::EnvelopeBuilder;
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

use crate::types::{LeaseClass, LeaseDomain, LeaseGrant};

// ---------------------------------------------------------------------------
// Schema identity constants
// ---------------------------------------------------------------------------

/// Schema family for lease wire protocol messages.
const LEASE_FAMILY: SchemaFamilyId = SchemaFamilyId(9);

/// Schema type for the LeaseWireMessage enum.
const LEASE_TYPE: SchemaTypeId = SchemaTypeId(1);

/// Schema version for lease wire protocol v1.0.
const LEASE_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Domain tag for lease message BLAKE3 domain separation.
const LEASE_DOMAIN_TAG: DomainTag = DomainTag::ReceiptBody;

/// Number of bytes in the trailing BLAKE3-256 digest.
const DIGEST_BYTES: usize = 32;

/// Number of bytes in the binary-schema envelope header.
const HEADER_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Wire message discriminant
// ---------------------------------------------------------------------------

/// Internal discriminant for the LeaseWireMessage enum, serialized as the
/// first byte of the bincode payload so the decoder can select the correct
/// variant before full deserialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
enum LeaseWireDiscriminant {
    Request = 0x01,
    Grant = 0x02,
    Revoke = 0x03,
    Renew = 0x04,
    Release = 0x05,
    Error = 0x06,
}

impl LeaseWireDiscriminant {
    #[allow(dead_code)]
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Request),
            0x02 => Some(Self::Grant),
            0x03 => Some(Self::Revoke),
            0x04 => Some(Self::Renew),
            0x05 => Some(Self::Release),
            0x06 => Some(Self::Error),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire payload types
// ---------------------------------------------------------------------------

/// Request a new lease for a domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequestPayload {
    /// Opaque request identifier for correlating response.
    pub request_id: u64,
    /// The lease class being requested (exclusive, shared, staging).
    pub lease_class: LeaseClass,
    /// The domain to lease.
    pub domain: LeaseDomain,
    /// The node requesting the lease.
    pub holder_id: MemberId,
    /// Requested lease term in milliseconds.
    pub term_millis: u64,
    /// Membership epoch for epoch-gated lease issuance.
    pub epoch: EpochId,
    /// Committed dataset mount identity for fencing on remount / epoch change.
    pub mount_identity: DatasetMountIdentity,
}

/// A granted lease, wrapping the domain LeaseGrant with a request correlation id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrantPayload {
    /// Correlates to the LeaseRequestPayload::request_id.
    pub request_id: u64,
    /// The granted lease.
    pub grant: LeaseGrant,
}

/// Revoke an active lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRevokePayload {
    /// The lease being revoked.
    pub lease_id: u64,
    /// Membership epoch at time of revocation.
    pub epoch: EpochId,
    /// Reason for revocation.
    pub reason: RevokeReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeReason {
    Admin,
    Conflict,
    Fencing,
    EpochAdvance,
    HolderUnreachable,
    PolicyViolation,
}

/// Renew an existing lease to extend its term.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRenewPayload {
    /// The lease being renewed.
    pub lease_id: u64,
    /// The holder requesting renewal.
    pub holder_id: MemberId,
    /// Membership epoch at time of renewal.
    pub epoch: EpochId,
}

/// Release a lease voluntarily.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseReleasePayload {
    /// The lease being released.
    pub lease_id: u64,
    /// The holder releasing the lease.
    pub holder_id: MemberId,
    /// Membership epoch at time of release.
    pub epoch: EpochId,
}

/// Wire-level error codes returned in response to lease operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseWireErrorCode {
    UnknownLease = 1,
    StaleEpoch = 2,
    UnauthorizedPeer = 3,
    LeaseExpired = 4,
    LeaseFenced = 5,
    HolderMismatch = 6,
    WitnessInsufficient = 7,
    InternalError = 8,
}

/// Error response for a lease operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseErrorPayload {
    /// Correlates to the originating request_id.
    pub request_id: u64,
    /// Wire-level error code.
    pub code: LeaseWireErrorCode,
    /// Human-readable error detail (limited to 256 bytes on wire).
    pub detail: String,
}

// ---------------------------------------------------------------------------
// LeaseWireMessage enum
// ---------------------------------------------------------------------------

/// Top-level lease wire protocol message.
///
/// Serialized with bincode using a leading discriminant byte so the decoder
/// can select the correct variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseWireMessage {
    Request(LeaseRequestPayload),
    Grant(LeaseGrantPayload),
    Revoke(LeaseRevokePayload),
    Renew(LeaseRenewPayload),
    Release(LeaseReleasePayload),
    Error(LeaseErrorPayload),
}

impl LeaseWireMessage {
    /// Return the discriminant for this message variant.
    #[allow(dead_code)]
    fn discriminant(&self) -> LeaseWireDiscriminant {
        match self {
            Self::Request(_) => LeaseWireDiscriminant::Request,
            Self::Grant(_) => LeaseWireDiscriminant::Grant,
            Self::Revoke(_) => LeaseWireDiscriminant::Revoke,
            Self::Renew(_) => LeaseWireDiscriminant::Renew,
            Self::Release(_) => LeaseWireDiscriminant::Release,
            Self::Error(_) => LeaseWireDiscriminant::Error,
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseWireCodec
// ---------------------------------------------------------------------------

/// Encodes and decodes [`LeaseWireMessage`] values into BLAKE3-authenticated,
/// binary-schema-framed wire format.
pub struct LeaseWireCodec;

impl LeaseWireCodec {
    /// Encode a [`LeaseWireMessage`] to the wire format.
    ///
    /// Returns a `Vec<u8>` containing the 64-byte envelope header, the
    /// bincode-serialized payload, and a trailing 32-byte BLAKE3-256
    /// domain digest of the payload.
    ///
    /// # Errors
    ///
    /// Returns `BinarySchemaError` if bincode serialization fails.
    pub fn encode(msg: &LeaseWireMessage) -> Result<Vec<u8>, BinarySchemaError> {
        let payload =
            bincode::serialize(msg).map_err(|_e| BinarySchemaError::InvalidPayloadClass)?;

        // Domain-separated BLAKE3-256 digest over the payload.
        let digest = blake3_domain_digest(
            &payload,
            LEASE_FAMILY,
            LEASE_TYPE,
            LEASE_VERSION,
            LEASE_DOMAIN_TAG,
        );

        let total_body = (payload.len() + DIGEST_BYTES) as u64;

        let header = EnvelopeBuilder::new(LEASE_FAMILY, LEASE_TYPE, LEASE_VERSION)
            .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
            .build(0, total_body);

        let mut out = Vec::with_capacity(HEADER_BYTES + payload.len() + DIGEST_BYTES);
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// Decode a wire-format byte slice into a [`LeaseWireMessage`].
    ///
    /// Validates the envelope header CRC32C, verifies the BLAKE3-256
    /// payload digest, and deserializes the bincode payload.
    ///
    /// # Errors
    ///
    /// Returns `BinarySchemaError` if the header is invalid, the digest
    /// is missing or mismatched, or bincode deserialization fails.
    pub fn decode(bytes: &[u8]) -> Result<LeaseWireMessage, BinarySchemaError> {
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES {
            return Err(BinarySchemaError::BoundsViolation);
        }

        // Decode envelope header (validates magic, CRC32C).
        let header_buf: &[u8; HEADER_BYTES] = bytes[..HEADER_BYTES]
            .try_into()
            .map_err(|_| BinarySchemaError::BoundsViolation)?;
        let header = tidefs_binary_schema_framing::EnvelopeHeader::decode(header_buf)?;

        // Validate header metadata.
        if header.family_id != LEASE_FAMILY {
            return Err(BinarySchemaError::InvalidPayloadClass);
        }
        if header.type_id != LEASE_TYPE {
            return Err(BinarySchemaError::InvalidPayloadClass);
        }

        let total_body = header.total_body_bytes as usize;
        if total_body < DIGEST_BYTES {
            return Err(BinarySchemaError::BoundsViolation);
        }
        let body_end = HEADER_BYTES + total_body;
        if bytes.len() < body_end {
            return Err(BinarySchemaError::BoundsViolation);
        }

        let payload_len = total_body - DIGEST_BYTES;
        let payload = &bytes[HEADER_BYTES..HEADER_BYTES + payload_len];
        let digest: &[u8; DIGEST_BYTES] = bytes[HEADER_BYTES + payload_len..body_end]
            .try_into()
            .map_err(|_| BinarySchemaError::BoundsViolation)?;

        // Verify BLAKE3-256 digest.
        let expected = blake3_domain_digest(
            payload,
            LEASE_FAMILY,
            LEASE_TYPE,
            LEASE_VERSION,
            LEASE_DOMAIN_TAG,
        );
        if *digest != expected {
            return Err(BinarySchemaError::DigestMismatch);
        }

        // Deserialize payload.
        let msg: LeaseWireMessage =
            bincode::deserialize(payload).map_err(|_| BinarySchemaError::InvalidPayloadClass)?;

        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tidefs_membership_epoch::DatasetMountIdentity;
    use super::*;

    // ── helpers ────────────────────────────────────────────────────────

    fn make_test_request() -> LeaseWireMessage {
        LeaseWireMessage::Request(LeaseRequestPayload {
            request_id: 1,
            lease_class: LeaseClass::Exclusive,
            domain: LeaseDomain::Inode {
                dataset_id: 42,
                ino: 100,
            },
            holder_id: MemberId(7),
            term_millis: 30_000,
            epoch: EpochId(5),
            mount_identity: DatasetMountIdentity::new(1, 1, 1),
        })
    }

    fn make_test_grant() -> LeaseWireMessage {
        let grant = LeaseGrant::request(
            99,
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 42,
                ino: 100,
            },
            MemberId(7),
            0u64,
            30_000,
            1_000_000,
            EpochId(5),
            DatasetMountIdentity::new(1, 1, 1),
            1,
            3,
            5,
        );
        LeaseWireMessage::Grant(LeaseGrantPayload {
            request_id: 1,
            grant,
        })
    }

    fn make_test_revoke() -> LeaseWireMessage {
        LeaseWireMessage::Revoke(LeaseRevokePayload {
            lease_id: 99,
            epoch: EpochId(5),
            reason: RevokeReason::Admin,
        })
    }

    fn make_test_renew() -> LeaseWireMessage {
        LeaseWireMessage::Renew(LeaseRenewPayload {
            lease_id: 99,
            holder_id: MemberId(7),
            epoch: EpochId(5),
        })
    }

    fn make_test_release() -> LeaseWireMessage {
        LeaseWireMessage::Release(LeaseReleasePayload {
            lease_id: 99,
            holder_id: MemberId(7),
            epoch: EpochId(5),
        })
    }

    fn make_test_error() -> LeaseWireMessage {
        LeaseWireMessage::Error(LeaseErrorPayload {
            request_id: 42,
            code: LeaseWireErrorCode::UnknownLease,
            detail: "no such lease".into(),
        })
    }

    // ── round-trip tests ───────────────────────────────────────────────

    #[test]
    fn roundtrip_request() {
        let msg = make_test_request();
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_grant() {
        let msg = make_test_grant();
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_revoke() {
        let msg = make_test_revoke();
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_renew() {
        let msg = make_test_renew();
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_release() {
        let msg = make_test_release();
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_error() {
        let msg = make_test_error();
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // ── encode produces non-empty bytes ────────────────────────────────

    #[test]
    fn encode_produces_non_empty_bytes() {
        for msg in &[
            make_test_request(),
            make_test_grant(),
            make_test_revoke(),
            make_test_renew(),
            make_test_release(),
            make_test_error(),
        ] {
            let encoded = LeaseWireCodec::encode(msg).unwrap();
            assert!(
                !encoded.is_empty(),
                "encoded bytes should not be empty for {msg:?}"
            );
            assert!(
                encoded.len() > HEADER_BYTES + DIGEST_BYTES,
                "encoded should have header+body+digest"
            );
        }
    }

    // ── decode error paths ─────────────────────────────────────────────

    #[test]
    fn decode_rejects_too_short() {
        let short = [0u8; 10];
        assert!(matches!(
            LeaseWireCodec::decode(&short),
            Err(BinarySchemaError::BoundsViolation)
        ));
    }

    #[test]
    fn decode_rejects_header_only() {
        let short = [0u8; HEADER_BYTES];
        assert!(matches!(
            LeaseWireCodec::decode(&short),
            Err(BinarySchemaError::BoundsViolation)
        ));
    }

    #[test]
    fn decode_rejects_tampered_payload() {
        let msg = make_test_request();
        let mut encoded = LeaseWireCodec::encode(&msg).unwrap();
        // Tamper with a byte in the payload section
        let tamper_idx = HEADER_BYTES + 1;
        encoded[tamper_idx] ^= 0xFF;
        let result = LeaseWireCodec::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_tampered_digest() {
        let msg = make_test_request();
        let mut encoded = LeaseWireCodec::encode(&msg).unwrap();
        // Tamper with the digest
        let digest_start = encoded.len() - DIGEST_BYTES;
        encoded[digest_start] ^= 0xFF;
        let result = LeaseWireCodec::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_wrong_family() {
        let msg = make_test_request();
        let mut encoded = LeaseWireCodec::encode(&msg).unwrap();
        // Corrupt family_id bytes in the header (offset 4..12)
        encoded[4] ^= 0xFF;
        let result = LeaseWireCodec::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn encode_is_deterministic() {
        let msg = make_test_request();
        let e1 = LeaseWireCodec::encode(&msg).unwrap();
        let e2 = LeaseWireCodec::encode(&msg).unwrap();
        assert_eq!(e1, e2);
    }

    // ── empty domain variants ──────────────────────────────────────────

    #[test]
    fn roundtrip_request_epoch_transition_domain() {
        let msg = LeaseWireMessage::Request(LeaseRequestPayload {
            request_id: 2,
            lease_class: LeaseClass::Staging,
            domain: LeaseDomain::EpochTransition {
                epoch_id: EpochId(10),
            },
            holder_id: MemberId(3),
            term_millis: 10_000,
            epoch: EpochId(10),
            mount_identity: DatasetMountIdentity::new(1, 1, 1),
        });
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_grant_with_shared_class() {
        let grant = LeaseGrant::request(
            200,
            LeaseClass::Shared,
            LeaseDomain::Snapshot { snapshot_id: 1 },
            MemberId(8),
            0u64,
            60_000,
            2_000_000,
            EpochId(7),
            DatasetMountIdentity::new(1, 1, 1),
            2,
            4,
            7,
        );
        let msg = LeaseWireMessage::Grant(LeaseGrantPayload {
            request_id: 5,
            grant,
        });
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_all_revoke_reasons() {
        for reason in &[
            RevokeReason::Admin,
            RevokeReason::Conflict,
            RevokeReason::Fencing,
            RevokeReason::EpochAdvance,
            RevokeReason::HolderUnreachable,
            RevokeReason::PolicyViolation,
        ] {
            let msg = LeaseWireMessage::Revoke(LeaseRevokePayload {
                lease_id: 1,
                epoch: EpochId(1),
                reason: *reason,
            });
            let encoded = LeaseWireCodec::encode(&msg).unwrap();
            let decoded = LeaseWireCodec::decode(&encoded).unwrap();
            assert_eq!(decoded, msg, "roundtrip failed for {reason:?}");
        }
    }

    #[test]
    fn roundtrip_all_error_codes() {
        for code in &[
            LeaseWireErrorCode::UnknownLease,
            LeaseWireErrorCode::StaleEpoch,
            LeaseWireErrorCode::UnauthorizedPeer,
            LeaseWireErrorCode::LeaseExpired,
            LeaseWireErrorCode::LeaseFenced,
            LeaseWireErrorCode::HolderMismatch,
            LeaseWireErrorCode::WitnessInsufficient,
            LeaseWireErrorCode::InternalError,
        ] {
            let msg = LeaseWireMessage::Error(LeaseErrorPayload {
                request_id: 1,
                code: *code,
                detail: format!("error {code:?}"),
            });
            let encoded = LeaseWireCodec::encode(&msg).unwrap();
            let decoded = LeaseWireCodec::decode(&encoded).unwrap();
            assert_eq!(decoded, msg, "roundtrip failed for {code:?}");
        }
    }
}
