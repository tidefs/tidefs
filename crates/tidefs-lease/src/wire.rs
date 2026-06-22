// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lease service wire protocol message types and codec.
//!
//! Implements the cluster lock service wire protocol so that TideFS nodes
//! can exchange lease requests, grants, revocations, renewals, releases,
//! and cache invalidation messages over established transport sessions.
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
use tidefs_cache_coherency::{
    CacheInvalidationMessage, CacheInvalidationReason, CacheInvalidationScope,
    InvalidationWaitPolicy,
};
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
    Invalidate = 0x07,
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
            0x07 => Some(Self::Invalidate),
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
    InvalidationRejected = 9,
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
// Cache invalidation wire payload (issue #754)
// ---------------------------------------------------------------------------

/// Wire-level serializable mirror of [`CacheInvalidationReason`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireInvalidationReason {
    ConflictingWriteLease,
    LeaseRevoked,
    EpochTransition,
    MountIdentityChanged,
    DestructiveMutation,
    InodeOrphaned,
    AdminDrain,
    HolderUnreachable,
    PolicyEviction,
}

impl From<CacheInvalidationReason> for WireInvalidationReason {
    fn from(r: CacheInvalidationReason) -> Self {
        match r {
            CacheInvalidationReason::ConflictingWriteLease => Self::ConflictingWriteLease,
            CacheInvalidationReason::LeaseRevoked => Self::LeaseRevoked,
            CacheInvalidationReason::EpochTransition => Self::EpochTransition,
            CacheInvalidationReason::MountIdentityChanged => Self::MountIdentityChanged,
            CacheInvalidationReason::DestructiveMutation => Self::DestructiveMutation,
            CacheInvalidationReason::InodeOrphaned => Self::InodeOrphaned,
            CacheInvalidationReason::AdminDrain => Self::AdminDrain,
            CacheInvalidationReason::HolderUnreachable => Self::HolderUnreachable,
            CacheInvalidationReason::PolicyEviction => Self::PolicyEviction,
        }
    }
}

impl From<WireInvalidationReason> for CacheInvalidationReason {
    fn from(r: WireInvalidationReason) -> Self {
        match r {
            WireInvalidationReason::ConflictingWriteLease => Self::ConflictingWriteLease,
            WireInvalidationReason::LeaseRevoked => Self::LeaseRevoked,
            WireInvalidationReason::EpochTransition => Self::EpochTransition,
            WireInvalidationReason::MountIdentityChanged => Self::MountIdentityChanged,
            WireInvalidationReason::DestructiveMutation => Self::DestructiveMutation,
            WireInvalidationReason::InodeOrphaned => Self::InodeOrphaned,
            WireInvalidationReason::AdminDrain => Self::AdminDrain,
            WireInvalidationReason::HolderUnreachable => Self::HolderUnreachable,
            WireInvalidationReason::PolicyEviction => Self::PolicyEviction,
        }
    }
}

/// Wire-level serializable mirror of [`InvalidationWaitPolicy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireWaitPolicy {
    Advisory,
    WaitForCleanEviction,
    WaitForDirtyDrain,
    FenceAndError,
}

impl From<InvalidationWaitPolicy> for WireWaitPolicy {
    fn from(p: InvalidationWaitPolicy) -> Self {
        match p {
            InvalidationWaitPolicy::Advisory => Self::Advisory,
            InvalidationWaitPolicy::WaitForCleanEviction => Self::WaitForCleanEviction,
            InvalidationWaitPolicy::WaitForDirtyDrain => Self::WaitForDirtyDrain,
            InvalidationWaitPolicy::FenceAndError => Self::FenceAndError,
        }
    }
}

impl From<WireWaitPolicy> for InvalidationWaitPolicy {
    fn from(p: WireWaitPolicy) -> Self {
        match p {
            WireWaitPolicy::Advisory => Self::Advisory,
            WireWaitPolicy::WaitForCleanEviction => Self::WaitForCleanEviction,
            WireWaitPolicy::WaitForDirtyDrain => Self::WaitForDirtyDrain,
            WireWaitPolicy::FenceAndError => Self::FenceAndError,
        }
    }
}

/// Wire-level serializable mirror of [`CacheInvalidationScope`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireInvalidationScope {
    Range { start: u64, end: u64 },
    Inode,
    Dataset,
}

impl From<CacheInvalidationScope> for WireInvalidationScope {
    fn from(s: CacheInvalidationScope) -> Self {
        match s {
            CacheInvalidationScope::Range { start, end } => Self::Range { start, end },
            CacheInvalidationScope::Inode => Self::Inode,
            CacheInvalidationScope::Dataset => Self::Dataset,
        }
    }
}

impl From<WireInvalidationScope> for CacheInvalidationScope {
    fn from(s: WireInvalidationScope) -> Self {
        match s {
            WireInvalidationScope::Range { start, end } => Self::Range { start, end },
            WireInvalidationScope::Inode => Self::Inode,
            WireInvalidationScope::Dataset => Self::Dataset,
        }
    }
}

/// Cache invalidation payload sent over the lease wire protocol.
///
/// Carries the full authority metadata for cross-node cache coherency
/// as defined by `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheInvalidationPayload {
    pub dataset_id: u64,
    pub mount_session_id: u64,
    pub inode_id: u64,
    pub inode_generation: u64,
    pub scope: WireInvalidationScope,
    pub old_range_generation: u64,
    pub new_range_generation: u64,
    pub lease_epoch: u64,
    pub membership_epoch: u64,
    pub reason: WireInvalidationReason,
    pub wait_policy: WireWaitPolicy,
}

impl CacheInvalidationPayload {
    /// Create a payload from a [`CacheInvalidationMessage`] (coherency crate).
    pub fn from_coherency(msg: &CacheInvalidationMessage) -> Self {
        Self {
            dataset_id: msg.dataset_id,
            mount_session_id: msg.mount_session_id,
            inode_id: msg.inode_id,
            inode_generation: msg.inode_generation,
            scope: msg.scope.into(),
            old_range_generation: msg.old_range_generation,
            new_range_generation: msg.new_range_generation,
            lease_epoch: msg.lease_epoch,
            membership_epoch: msg.membership_epoch,
            reason: msg.reason.into(),
            wait_policy: msg.wait_policy.into(),
        }
    }

    /// Convert back to a [`CacheInvalidationMessage`] for the coherency crate.
    pub fn into_coherency(self) -> CacheInvalidationMessage {
        CacheInvalidationMessage {
            dataset_id: self.dataset_id,
            mount_session_id: self.mount_session_id,
            inode_id: self.inode_id,
            inode_generation: self.inode_generation,
            scope: self.scope.into(),
            old_range_generation: self.old_range_generation,
            new_range_generation: self.new_range_generation,
            lease_epoch: self.lease_epoch,
            membership_epoch: self.membership_epoch,
            reason: self.reason.into(),
            wait_policy: self.wait_policy.into(),
        }
    }
}

/// Acknowledgment of a cache invalidation message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationAckPayload {
    /// The dataset id from the invalidation message.
    pub dataset_id: u64,
    /// The inode id from the invalidation message (0 for dataset scope).
    pub inode_id: u64,
    /// Number of clean entries evicted.
    pub clean_evicted: u64,
    /// Number of dirty entries still pending.
    pub dirty_remaining: u64,
    /// Whether all dirty entries have been drained.
    pub dirty_drained: bool,
    /// Whether the subscriber needs more time.
    pub needs_retry: bool,
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
    /// Cache invalidation message for cross-node coherency (issue #754).
    Invalidate(CacheInvalidationPayload),
    /// Acknowledgment of a cache invalidation message.
    InvalidateAck(InvalidationAckPayload),
}

// ---------------------------------------------------------------------------
// LeaseWireCodec
// ---------------------------------------------------------------------------

/// Encodes and decodes [LeaseWireMessage] values into BLAKE3-authenticated,
/// binary-schema-framed wire format.
pub struct LeaseWireCodec;

impl LeaseWireCodec {
    /// Encode a [LeaseWireMessage] to the wire format.
    ///
    /// Returns a `Vec<u8>` containing the 64-byte envelope header, the
    /// bincode-serialized payload, and a trailing 32-byte BLAKE3-256
    /// domain digest of the payload.
    ///
    /// # Errors
    ///
    /// Returns [`BinarySchemaError`] if bincode serialization fails.
    pub fn encode(msg: &LeaseWireMessage) -> Result<Vec<u8>, BinarySchemaError> {
        let payload =
            bincode::serialize(msg).map_err(|_e| BinarySchemaError::InvalidPayloadClass)?;

        let digest = blake3_domain_digest(
            &payload,
            LEASE_FAMILY,
            LEASE_TYPE,
            LEASE_VERSION,
            LEASE_DOMAIN_TAG,
        );

        let total_body = (payload.len() + DIGEST_BYTES) as u64;

        let header =
            EnvelopeBuilder::new(LEASE_FAMILY, LEASE_TYPE, LEASE_VERSION)
                .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
                .build(0, total_body);

        let mut out = Vec::with_capacity(HEADER_BYTES + payload.len() + DIGEST_BYTES);
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// Decode a framed lease wire message from transport payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BinarySchemaError`] if the payload is invalid.
    pub fn decode(framed: &[u8]) -> Result<LeaseWireMessage, BinarySchemaError> {
        if framed.len() < HEADER_BYTES + DIGEST_BYTES {
            return Err(BinarySchemaError::InvalidPayloadLength {
                got: framed.len(),
                min_expected: HEADER_BYTES + DIGEST_BYTES,
            });
        }

        let header = tidefs_binary_schema_framing::EnvelopeHeader::decode(
            &framed[..HEADER_BYTES],
        )?;

        if header.family() != LEASE_FAMILY
            || header.schema_type() != LEASE_TYPE
        {
            return Err(BinarySchemaError::InvalidSchemaClass {
                family: header.family().0,
                typ: header.schema_type().0,
            });
        }

        let payload_len = (header.body_length() as usize).saturating_sub(DIGEST_BYTES);
        let payload = &framed[HEADER_BYTES..HEADER_BYTES + payload_len];
        let digest = &framed[HEADER_BYTES + payload_len..HEADER_BYTES + payload_len + DIGEST_BYTES];

        let expected = blake3_domain_digest(
            payload,
            LEASE_FAMILY,
            LEASE_TYPE,
            LEASE_VERSION,
            LEASE_DOMAIN_TAG,
        );

        if expected != digest {
            return Err(BinarySchemaError::DigestMismatch);
        }

        bincode::deserialize(payload).map_err(|_e| BinarySchemaError::InvalidPayloadEncoding)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_revoke_roundtrip() {
        let msg = LeaseWireMessage::Revoke(LeaseRevokePayload {
            lease_id: 42,
            epoch: EpochId(1),
            reason: RevokeReason::Conflict,
        });
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_grant_roundtrip() {
        let mount = DatasetMountIdentity::ZERO;
        let grant = LeaseGrant::request(
            1,
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 100,
            },
            MemberId(10),
            0,
            30000,
            1000,
            EpochId(1),
            mount,
            0,
            3,
            5,
        );
        let msg = LeaseWireMessage::Grant(LeaseGrantPayload {
            request_id: 1,
            grant,
        });
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // ── Cache invalidation wire tests ────────────────────────────────

    #[test]
    fn wire_invalidate_range_roundtrip() {
        let payload = CacheInvalidationPayload {
            dataset_id: 1,
            mount_session_id: 100,
            inode_id: 42,
            inode_generation: 5,
            scope: WireInvalidationScope::Range {
                start: 0,
                end: 4096,
            },
            old_range_generation: 1,
            new_range_generation: 2,
            lease_epoch: 10,
            membership_epoch: 20,
            reason: WireInvalidationReason::ConflictingWriteLease,
            wait_policy: WireWaitPolicy::WaitForCleanEviction,
        };
        let msg = LeaseWireMessage::Invalidate(payload);
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_invalidate_inode_roundtrip() {
        let payload = CacheInvalidationPayload {
            dataset_id: 2,
            mount_session_id: 200,
            inode_id: 99,
            inode_generation: 3,
            scope: WireInvalidationScope::Inode,
            old_range_generation: 5,
            new_range_generation: 6,
            lease_epoch: 15,
            membership_epoch: 25,
            reason: WireInvalidationReason::EpochTransition,
            wait_policy: WireWaitPolicy::WaitForDirtyDrain,
        };
        let msg = LeaseWireMessage::Invalidate(payload);
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_invalidate_ack_roundtrip() {
        let ack = InvalidationAckPayload {
            dataset_id: 1,
            inode_id: 42,
            clean_evicted: 5,
            dirty_remaining: 0,
            dirty_drained: true,
            needs_retry: false,
        };
        let msg = LeaseWireMessage::InvalidateAck(ack);
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn coherency_to_wire_roundtrip() {
        let coh = CacheInvalidationMessage::range(
            1, 100, 42, 5, 0, 4096, 1, 2, 10, 20,
            CacheInvalidationReason::ConflictingWriteLease,
            InvalidationWaitPolicy::WaitForCleanEviction,
        );
        let wire = CacheInvalidationPayload::from_coherency(&coh);
        let back = wire.into_coherency();
        assert_eq!(back, coh);
    }

    #[test]
    fn invalidate_wire_ack_preserves_fields() {
        let ack = InvalidationAckPayload {
            dataset_id: 3,
            inode_id: 77,
            clean_evicted: 10,
            dirty_remaining: 2,
            dirty_drained: false,
            needs_retry: true,
        };
        let msg = LeaseWireMessage::InvalidateAck(ack.clone());
        let encoded = LeaseWireCodec::encode(&msg).unwrap();
        let decoded = LeaseWireCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_wait_policy_conversion() {
        let policies = [
            InvalidationWaitPolicy::Advisory,
            InvalidationWaitPolicy::WaitForCleanEviction,
            InvalidationWaitPolicy::WaitForDirtyDrain,
            InvalidationWaitPolicy::FenceAndError,
        ];
        for p in &policies {
            let w: WireWaitPolicy = (*p).into();
            let back: InvalidationWaitPolicy = w.into();
            assert_eq!(*p, back);
        }
    }

    #[test]
    fn wire_invalidation_reason_conversion() {
        let reasons = [
            CacheInvalidationReason::ConflictingWriteLease,
            CacheInvalidationReason::LeaseRevoked,
            CacheInvalidationReason::EpochTransition,
            CacheInvalidationReason::DestructiveMutation,
            CacheInvalidationReason::PolicyEviction,
        ];
        for r in &reasons {
            let w: WireInvalidationReason = (*r).into();
            let back: CacheInvalidationReason = w.into();
            assert_eq!(*r, back);
        }
    }
}
