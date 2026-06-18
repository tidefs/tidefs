// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lease protocol service: grant, renewal, revocation, and acknowledgement
//! with BLAKE3-verified message integrity and epoch-bound state machines.
//!
//! Provides the LeaseProtocol service that manages multiple leases through
//! their lifecycle, enforcing epoch-bound invalidation and BLAKE3-verified
//! message exchange for the single-writer fast path in multi-node TideFS.
//!
//! # Epoch-bound invalidation
//!
//! When advance_epoch(new_epoch) is called with a strictly greater epoch,
//! all active leases are revoked. This ensures no split-brain writes can
//! occur across epoch boundaries -- a holder with a lease from epoch N cannot
//! mutate data after the cluster has advanced to epoch N+1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{
    BinarySchemaError, ChecksumProfile, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};
use tidefs_binary_schema_framing::EnvelopeBuilder;
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

use crate::lease_state_machine::{LeaseHolder, LeaseStateMachine, TransitionError};
use crate::types::{LeaseClass, LeaseDomain, LeaseError, LeaseGrant, LeaseLifecycle};
use crate::wire::RevokeReason;

// ---------------------------------------------------------------------------
// Schema identity constants
// ---------------------------------------------------------------------------

/// Schema family for lease protocol messages (distinct from wire-level family 9).
const LEASE_PROTO_FAMILY: SchemaFamilyId = SchemaFamilyId(10);

/// Schema type for the LeaseMessage enum.
const LEASE_PROTO_TYPE: SchemaTypeId = SchemaTypeId(1);

/// Schema version for lease protocol v1.0.
const LEASE_PROTO_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Domain tag for lease protocol BLAKE3 domain separation.
const LEASE_PROTO_DOMAIN_TAG: DomainTag = DomainTag::ReceiptBody;

/// Number of bytes in the trailing BLAKE3-256 digest.
const DIGEST_BYTES: usize = 32;

/// Number of bytes in the binary-schema envelope header.
const HEADER_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// LeaseMessage
// ---------------------------------------------------------------------------

/// Protocol-level lease message for grant/renew/revoke/acknowledge exchange.
///
/// This is the higher-level protocol message type; for wire-level framing
/// with richer request/error variants see [crate::wire::LeaseWireMessage].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseMessage {
    /// A lease has been granted, carrying the full grant payload.
    Grant(LeaseGrant),
    /// Request to renew an existing lease.
    Renew {
        lease_id: u64,
        holder_id: MemberId,
        epoch: EpochId,
    },
    /// Request to revoke an active lease.
    Revoke {
        lease_id: u64,
        epoch: EpochId,
        reason: RevokeReason,
    },
    /// Acknowledgment of a lease operation (grant, renewal, or revocation).
    Acknowledge {
        /// The lease this acknowledgment pertains to.
        lease_id: u64,
        /// Whether the operation succeeded.
        success: bool,
        /// Human-readable detail (max 256 bytes on wire).
        detail: String,
    },
}

impl LeaseMessage {
    /// Return the lease_id associated with this message, if any.
    pub fn lease_id(&self) -> Option<u64> {
        match self {
            Self::Grant(g) => Some(g.lease_id),
            Self::Renew { lease_id, .. }
            | Self::Revoke { lease_id, .. }
            | Self::Acknowledge { lease_id, .. } => Some(*lease_id),
        }
    }

    /// Return the epoch associated with this message, if any.
    pub fn epoch(&self) -> Option<EpochId> {
        match self {
            Self::Grant(g) => Some(g.epoch),
            Self::Renew { epoch, .. } | Self::Revoke { epoch, .. } => Some(*epoch),
            Self::Acknowledge { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseMessageCodec
// ---------------------------------------------------------------------------

/// Encodes and decodes [LeaseMessage] values into BLAKE3-authenticated,
/// binary-schema-framed wire format.
///
/// Uses schema family 10 (distinct from the wire-level lease protocol family 9)
/// to avoid ambiguity between protocol-level and wire-level messages.
pub struct LeaseMessageCodec;

impl LeaseMessageCodec {
    /// Encode a [LeaseMessage] to the wire format.
    ///
    /// Returns a Vec<u8> containing the 64-byte envelope header, the
    /// bincode-serialized payload, and a trailing 32-byte BLAKE3-256
    /// domain digest of the payload.
    ///
    /// # Errors
    ///
    /// Returns BinarySchemaError if bincode serialization fails.
    pub fn encode(msg: &LeaseMessage) -> Result<Vec<u8>, BinarySchemaError> {
        let payload =
            bincode::serialize(msg).map_err(|_e| BinarySchemaError::InvalidPayloadClass)?;

        let digest = blake3_domain_digest(
            &payload,
            LEASE_PROTO_FAMILY,
            LEASE_PROTO_TYPE,
            LEASE_PROTO_VERSION,
            LEASE_PROTO_DOMAIN_TAG,
        );

        let total_body = (payload.len() + DIGEST_BYTES) as u64;

        let header =
            EnvelopeBuilder::new(LEASE_PROTO_FAMILY, LEASE_PROTO_TYPE, LEASE_PROTO_VERSION)
                .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
                .build(0, total_body);

        let mut out = Vec::with_capacity(HEADER_BYTES + payload.len() + DIGEST_BYTES);
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// Decode a wire-format byte slice into a [LeaseMessage].
    ///
    /// Validates the envelope header CRC32C, verifies the BLAKE3-256
    /// payload digest, and deserializes the bincode payload.
    ///
    /// # Errors
    ///
    /// Returns BinarySchemaError if the header is invalid, the digest
    /// is missing or mismatched, or bincode deserialization fails.
    pub fn decode(bytes: &[u8]) -> Result<LeaseMessage, BinarySchemaError> {
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES {
            return Err(BinarySchemaError::BoundsViolation);
        }

        let header_buf: &[u8; HEADER_BYTES] = bytes[..HEADER_BYTES]
            .try_into()
            .map_err(|_| BinarySchemaError::BoundsViolation)?;
        let header = tidefs_binary_schema_framing::EnvelopeHeader::decode(header_buf)?;

        if header.family_id != LEASE_PROTO_FAMILY {
            return Err(BinarySchemaError::InvalidPayloadClass);
        }
        if header.type_id != LEASE_PROTO_TYPE {
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

        let expected = blake3_domain_digest(
            payload,
            LEASE_PROTO_FAMILY,
            LEASE_PROTO_TYPE,
            LEASE_PROTO_VERSION,
            LEASE_PROTO_DOMAIN_TAG,
        );
        if *digest != expected {
            return Err(BinarySchemaError::DigestMismatch);
        }

        let msg: LeaseMessage =
            bincode::deserialize(payload).map_err(|_| BinarySchemaError::InvalidPayloadClass)?;

        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// LeaseProtocolError
// ---------------------------------------------------------------------------

/// Errors returned by the [LeaseProtocol] service.
#[derive(Debug, thiserror::Error)]
pub enum LeaseProtocolError {
    #[error("lease {0} not found")]
    NotFound(u64),
    #[error("lease {0} is in terminal state {1:?}")]
    Terminal(u64, LeaseLifecycle),
    #[error("lease {0} has expired")]
    Expired(u64),
    #[error("holder {0:?} does not match lease {1} holder")]
    HolderMismatch(MemberId, u64),
    #[error("epoch must advance: {0:?} <= {1:?}")]
    EpochNotAdvanced(EpochId, EpochId),
    #[error("state machine transition error: {0:?}")]
    Transition(TransitionError),
    #[error("lease {0} epoch {1:?} does not match current {2:?}")]
    EpochMismatch(u64, EpochId, EpochId),
    #[error("mount identity {0:?} does not match current {1:?}")]
    MountIdentityMismatch(DatasetMountIdentity, DatasetMountIdentity),
    #[error("codec error: {0:?}")]
    Codec(BinarySchemaError),
}

impl From<BinarySchemaError> for LeaseProtocolError {
    fn from(e: BinarySchemaError) -> Self {
        Self::Codec(e)
    }
}

// ---------------------------------------------------------------------------
// LeaseProtocol
// ---------------------------------------------------------------------------

/// Protocol-level lease service with epoch-bound state machines and
/// BLAKE3-verified message exchange.
///
/// Manages the lifecycle of multiple leases: grant, renewal, and revocation.
/// All active leases are invalidated when the membership epoch advances,
/// preventing split-brain writes across epoch boundaries.
pub struct LeaseProtocol {
    current_epoch: EpochId,
    current_mount_identity: DatasetMountIdentity,
    machines: BTreeMap<u64, LeaseStateMachine>,
    grants: BTreeMap<u64, LeaseGrant>,
    next_lease_id: u64,
}

impl LeaseProtocol {
    /// Create a new protocol instance at the given epoch.
    pub fn new(current_epoch: EpochId, mount_identity: DatasetMountIdentity) -> Self {
        Self {
            current_epoch,
            current_mount_identity: mount_identity,
            machines: BTreeMap::new(),
            grants: BTreeMap::new(),
            next_lease_id: 1,
        }
    }

    /// Return the current membership epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Return the current dataset mount identity.
    pub fn current_mount_identity(&self) -> DatasetMountIdentity {
        self.current_mount_identity
    }

    /// Return the number of tracked active leases.
    pub fn active_count(&self) -> usize {
        self.grants
            .values()
            .filter(|g| g.lifecycle.is_active())
            .count()
    }

    /// Return total tracked leases (including terminal).
    pub fn total_count(&self) -> usize {
        self.grants.len()
    }

    /// Look up a grant by lease id.
    pub fn get_grant(&self, lease_id: u64) -> Option<&LeaseGrant> {
        self.grants.get(&lease_id)
    }

    /// Returns true if the lease is active (granted and not terminal).
    pub fn is_active(&self, lease_id: u64) -> bool {
        self.grants
            .get(&lease_id)
            .map(|g| g.lifecycle.is_active())
            .unwrap_or(false)
    }

    /// Grant a new lease.
    ///
    /// Creates a fresh LeaseStateMachine for the lease, transitions it to
    /// Granted, and records the grant.
    pub fn grant_lease(
        &mut self,
        lease_class: LeaseClass,
        domain: LeaseDomain,
        holder_id: MemberId,
        term_millis: u64,
        mount_identity: DatasetMountIdentity,
    ) -> Result<LeaseGrant, LeaseProtocolError> {
        if mount_identity != self.current_mount_identity {
            return Err(LeaseProtocolError::MountIdentityMismatch(
                mount_identity,
                self.current_mount_identity,
            ));
        }

        let lease_id = self.next_id();
        let now_millis = now_millis();

        let grant = LeaseGrant::request(
            lease_id,
            lease_class,
            domain,
            holder_id,
            0u64,
            term_millis,
            now_millis,
            self.current_epoch,
            mount_identity,
            0,
            0,
            0,
        );

        let holder = LeaseHolder::new(holder_id);
        let ttl = std::time::Duration::from_millis(term_millis);

        let mut sm = LeaseStateMachine::new();
        sm.grant(holder, ttl)
            .map_err(LeaseProtocolError::Transition)?;

        self.machines.insert(lease_id, sm);
        self.grants.insert(lease_id, grant.clone());
        Ok(grant)
    }

    /// Renew an active lease, extending its term.
    ///
    /// The holder must match the original grant holder, and the lease must
    /// be active (not expired, revoked, or otherwise terminal).
    pub fn renew_lease(
        &mut self,
        lease_id: u64,
        holder_id: MemberId,
        term_millis: u64,
    ) -> Result<LeaseGrant, LeaseProtocolError> {
        // Reject renewal if the lease epoch or mount identity do not match.
        {
            let grant = self
                .grants
                .get(&lease_id)
                .ok_or(LeaseProtocolError::NotFound(lease_id))?;
            if grant.epoch != self.current_epoch {
                return Err(LeaseProtocolError::EpochMismatch(
                    lease_id,
                    grant.epoch,
                    self.current_epoch,
                ));
            }
            if grant.mount_identity != self.current_mount_identity {
                return Err(LeaseProtocolError::MountIdentityMismatch(
                    grant.mount_identity,
                    self.current_mount_identity,
                ));
            }
        }

        let sm = self
            .machines
            .get_mut(&lease_id)
            .ok_or(LeaseProtocolError::NotFound(lease_id))?;

        let holder = LeaseHolder::new(holder_id);
        let ttl = std::time::Duration::from_millis(term_millis);

        sm.renew(&holder, ttl).map_err(|e| match e {
            TransitionError::AlreadyExpired => LeaseProtocolError::Expired(lease_id),
            TransitionError::NotGranted => {
                LeaseProtocolError::Terminal(lease_id, LeaseLifecycle::Revoked)
            }
            TransitionError::HolderMismatch => {
                LeaseProtocolError::HolderMismatch(holder_id, lease_id)
            }
            _ => LeaseProtocolError::Transition(e),
        })?;

        let now_millis = now_millis();
        let grant = self
            .grants
            .get_mut(&lease_id)
            .expect("grant must exist if machine exists");
        grant.renew(now_millis).map_err(|e| match e {
            LeaseError::AlreadyTerminal { lease_id, state } => {
                LeaseProtocolError::Terminal(lease_id, state)
            }
            LeaseError::Expired { lease_id } => LeaseProtocolError::Expired(lease_id),
            _ => LeaseProtocolError::NotFound(lease_id),
        })?;

        Ok(grant.clone())
    }

    /// Revoke an active lease.
    ///
    /// Transitions the lease to Revoked state and fences the grant.
    pub fn revoke_lease(&mut self, lease_id: u64) -> Result<(), LeaseProtocolError> {
        let sm = self
            .machines
            .get_mut(&lease_id)
            .ok_or(LeaseProtocolError::NotFound(lease_id))?;

        sm.revoke().map_err(|e| match e {
            TransitionError::AlreadyExpired => LeaseProtocolError::Expired(lease_id),
            TransitionError::NotGranted => {
                LeaseProtocolError::Terminal(lease_id, LeaseLifecycle::Revoked)
            }
            _ => LeaseProtocolError::Transition(e),
        })?;

        let grant = self
            .grants
            .get_mut(&lease_id)
            .expect("grant must exist if machine exists");
        grant.fence().map_err(|e| match e {
            LeaseError::AlreadyTerminal { lease_id, state } => {
                LeaseProtocolError::Terminal(lease_id, state)
            }
            _ => LeaseProtocolError::NotFound(lease_id),
        })?;

        Ok(())
    }

    /// Advance the membership epoch.
    ///
    /// Revokes all active leases whose epoch is older than new_epoch.
    /// Returns the IDs of revoked leases. This is the epoch-bound
    /// invalidation guarantee: no lease from an old epoch survives.
    /// Invalidate all leases that were granted under a different mount identity.
    ///
    /// Called after a dataset remount to fence any leases from the previous mount,
    /// even if their time interval has not expired.
    pub fn remount_invalidate(&mut self, new_mount_identity: DatasetMountIdentity) -> Vec<u64> {
        let mut revoked = Vec::new();
        for (lease_id, grant) in &mut self.grants {
            if grant.mount_identity != new_mount_identity && !grant.lifecycle.is_terminal() {
                grant.lifecycle = LeaseLifecycle::Fenced;
                revoked.push(*lease_id);
                if let Some(sm) = self.machines.get_mut(lease_id) {
                    let _ = sm.fence();
                }
            }
        }
        self.current_mount_identity = new_mount_identity;
        revoked
    }

    pub fn advance_epoch(&mut self, new_epoch: EpochId) -> Result<Vec<u64>, LeaseProtocolError> {
        if new_epoch <= self.current_epoch {
            return Err(LeaseProtocolError::EpochNotAdvanced(
                new_epoch,
                self.current_epoch,
            ));
        }

        let mut revoked = Vec::new();
        let all_ids: Vec<u64> = self.grants.keys().copied().collect();

        for lease_id in all_ids {
            if let Some(grant) = self.grants.get_mut(&lease_id) {
                if grant.epoch < new_epoch && grant.lifecycle.is_active() {
                    if let Some(sm) = self.machines.get_mut(&lease_id) {
                        let _ = sm.fence();
                    }
                    let _ = grant.fence();
                    revoked.push(lease_id);
                }
            }
        }

        self.current_epoch = new_epoch;
        Ok(revoked)
    }

    /// Tick all state machines to check for TTL expiry.
    ///
    /// Returns the IDs of leases that expired during this tick.
    pub fn tick_all(&mut self) -> Vec<u64> {
        let mut expired = Vec::new();
        for (lease_id, sm) in &mut self.machines {
            sm.tick();
            if !sm.is_active() {
                if let Some(grant) = self.grants.get_mut(lease_id) {
                    if grant.lifecycle.is_active() {
                        grant.lifecycle = LeaseLifecycle::Expired;
                        expired.push(*lease_id);
                    }
                }
            }
        }
        expired
    }

    /// Encode a lease operation result as a BLAKE3-verified message.
    pub fn encode_message(msg: &LeaseMessage) -> Result<Vec<u8>, BinarySchemaError> {
        LeaseMessageCodec::encode(msg)
    }

    /// Decode and verify a BLAKE3-authenticated lease message.
    pub fn decode_message(bytes: &[u8]) -> Result<LeaseMessage, BinarySchemaError> {
        LeaseMessageCodec::decode(bytes)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn next_id(&mut self) -> u64 {
        let id = self.next_lease_id;
        self.next_lease_id = self.next_lease_id.wrapping_add(1);
        id
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tidefs_membership_epoch::EpochId;

    fn m(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn inode_domain(ds: u64, ino: u64) -> LeaseDomain {
        LeaseDomain::Inode {
            dataset_id: ds,
            ino,
        }
    }

    fn make_test_grant_msg() -> LeaseMessage {
        let grant = LeaseGrant::request(
            1,
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(7),
            0u64,
            30_000,
            1_000_000,
            epoch(1),
            DatasetMountIdentity::new(1, 1, 1),
            0,
            0,
            0,
        );
        LeaseMessage::Grant(grant)
    }

    // -- LeaseMessage accessors ------------------------------------------

    #[test]
    fn test_lease_message_lease_id() {
        assert_eq!(make_test_grant_msg().lease_id(), Some(1));

        let renew = LeaseMessage::Renew {
            lease_id: 42,
            holder_id: m(1),
            epoch: epoch(1),
        };
        assert_eq!(renew.lease_id(), Some(42));

        let revoke = LeaseMessage::Revoke {
            lease_id: 99,
            epoch: epoch(1),
            reason: RevokeReason::Admin,
        };
        assert_eq!(revoke.lease_id(), Some(99));

        let ack = LeaseMessage::Acknowledge {
            lease_id: 7,
            success: true,
            detail: "ok".into(),
        };
        assert_eq!(ack.lease_id(), Some(7));
    }

    #[test]
    fn test_lease_message_epoch() {
        assert_eq!(make_test_grant_msg().epoch(), Some(epoch(1)));

        let renew = LeaseMessage::Renew {
            lease_id: 1,
            holder_id: m(7),
            epoch: epoch(3),
        };
        assert_eq!(renew.epoch(), Some(epoch(3)));

        let revoke = LeaseMessage::Revoke {
            lease_id: 1,
            epoch: epoch(5),
            reason: RevokeReason::EpochAdvance,
        };
        assert_eq!(revoke.epoch(), Some(epoch(5)));

        let ack = LeaseMessage::Acknowledge {
            lease_id: 1,
            success: true,
            detail: "ok".into(),
        };
        assert_eq!(ack.epoch(), None);
    }

    // -- LeaseMessageCodec round-trip ------------------------------------

    #[test]
    fn roundtrip_grant() {
        let msg = make_test_grant_msg();
        let encoded = LeaseMessageCodec::encode(&msg).unwrap();
        let decoded = LeaseMessageCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_renew() {
        let msg = LeaseMessage::Renew {
            lease_id: 1,
            holder_id: m(7),
            epoch: epoch(1),
        };
        let encoded = LeaseMessageCodec::encode(&msg).unwrap();
        let decoded = LeaseMessageCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_revoke() {
        let msg = LeaseMessage::Revoke {
            lease_id: 1,
            epoch: epoch(1),
            reason: RevokeReason::Fencing,
        };
        let encoded = LeaseMessageCodec::encode(&msg).unwrap();
        let decoded = LeaseMessageCodec::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_acknowledge() {
        let msg = LeaseMessage::Acknowledge {
            lease_id: 1,
            success: true,
            detail: "granted".into(),
        };
        let encoded = LeaseMessageCodec::encode(&msg).unwrap();
        let decoded = LeaseMessageCodec::decode(&encoded).unwrap();
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
            let msg = LeaseMessage::Revoke {
                lease_id: 1,
                epoch: epoch(1),
                reason: *reason,
            };
            let encoded = LeaseMessageCodec::encode(&msg).unwrap();
            let decoded = LeaseMessageCodec::decode(&encoded).unwrap();
            assert_eq!(decoded, msg, "roundtrip failed for {reason:?}");
        }
    }

    // -- Codec error paths ----------------------------------------------

    #[test]
    fn decode_rejects_too_short() {
        assert!(matches!(
            LeaseMessageCodec::decode(&[0u8; 10]),
            Err(BinarySchemaError::BoundsViolation)
        ));
    }

    #[test]
    fn decode_rejects_tampered_payload() {
        let msg = make_test_grant_msg();
        let mut encoded = LeaseMessageCodec::encode(&msg).unwrap();
        encoded[HEADER_BYTES + 1] ^= 0xFF;
        assert!(LeaseMessageCodec::decode(&encoded).is_err());
    }

    #[test]
    fn decode_rejects_tampered_digest() {
        let msg = make_test_grant_msg();
        let mut encoded = LeaseMessageCodec::encode(&msg).unwrap();
        let digest_start = encoded.len() - DIGEST_BYTES;
        encoded[digest_start] ^= 0xFF;
        assert!(LeaseMessageCodec::decode(&encoded).is_err());
    }

    #[test]
    fn encode_is_deterministic() {
        let msg = make_test_grant_msg();
        let e1 = LeaseMessageCodec::encode(&msg).unwrap();
        let e2 = LeaseMessageCodec::encode(&msg).unwrap();
        assert_eq!(e1, e2);
    }

    // -- LeaseProtocol grant --------------------------------------------

    #[test]
    fn test_grant_lease_basic() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let grant = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        assert_eq!(grant.lease_id, 1);
        assert_eq!(grant.holder_id, m(7));
        assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
        assert_eq!(proto.active_count(), 1);
        assert!(proto.is_active(1));
    }

    #[test]
    fn test_grant_lease_multiple() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 1),
                m(10),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        proto
            .grant_lease(
                LeaseClass::Shared,
                inode_domain(1, 2),
                m(20),
                15_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        assert_eq!(proto.active_count(), 2);
        assert!(proto.is_active(1));
        assert!(proto.is_active(2));
    }

    // -- LeaseProtocol renew --------------------------------------------

    #[test]
    fn test_renew_basic() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let g = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let renewed = proto.renew_lease(g.lease_id, m(7), 60_000).unwrap();
        assert_eq!(renewed.version, 2);
        assert!(renewed.expires_at_millis > g.expires_at_millis);
        assert!(proto.is_active(g.lease_id));
    }

    #[test]
    fn test_renew_wrong_holder() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let g = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        let result = proto.renew_lease(g.lease_id, m(99), 30_000);
        assert!(matches!(
            result,
            Err(LeaseProtocolError::HolderMismatch(_, _))
        ));
    }

    #[test]
    fn test_renew_not_found() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let result = proto.renew_lease(999, m(1), 30_000);
        assert!(matches!(result, Err(LeaseProtocolError::NotFound(999))));
    }

    // -- LeaseProtocol revoke -------------------------------------------

    #[test]
    fn test_revoke_basic() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let g = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        proto.revoke_lease(g.lease_id).unwrap();
        assert!(!proto.is_active(g.lease_id));
        assert_eq!(
            proto.get_grant(g.lease_id).unwrap().lifecycle,
            LeaseLifecycle::Fenced
        );
    }

    #[test]
    fn test_revoke_not_found() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        assert!(matches!(
            proto.revoke_lease(999),
            Err(LeaseProtocolError::NotFound(999))
        ));
    }

    #[test]
    fn test_revoke_twice_fails() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let g = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        proto.revoke_lease(g.lease_id).unwrap();
        let result = proto.revoke_lease(g.lease_id);
        assert!(matches!(result, Err(LeaseProtocolError::Terminal(_, _))));
    }

    // -- Epoch-bound invalidation ---------------------------------------

    #[test]
    fn test_advance_epoch_revokes_all_active() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let g1 = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 1),
                m(10),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        let g2 = proto
            .grant_lease(
                LeaseClass::Shared,
                inode_domain(1, 2),
                m(20),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();

        let revoked = proto.advance_epoch(epoch(2)).unwrap();
        assert_eq!(revoked.len(), 2);
        assert!(revoked.contains(&g1.lease_id));
        assert!(revoked.contains(&g2.lease_id));
        assert_eq!(proto.current_epoch(), epoch(2));
        assert_eq!(proto.active_count(), 0);
    }

    #[test]
    fn test_advance_epoch_new_leases_survive() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 1),
                m(10),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        proto.advance_epoch(epoch(2)).unwrap();
        assert_eq!(proto.active_count(), 0);

        let g = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 2),
                m(10),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        assert_eq!(g.epoch, epoch(2));
        assert_eq!(proto.active_count(), 1);
    }

    #[test]
    fn test_advance_epoch_same_or_backward_fails() {
        let mut proto = LeaseProtocol::new(epoch(5), DatasetMountIdentity::new(1, 1, 5));
        assert!(proto.advance_epoch(epoch(5)).is_err());
        assert!(proto.advance_epoch(epoch(3)).is_err());
    }

    // -- TTL expiry via tick_all ----------------------------------------

    #[test]
    fn test_tick_all_expires_stale() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                1, // 1ms
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let expired = proto.tick_all();
        assert_eq!(expired.len(), 1);
        assert_eq!(proto.active_count(), 0);
    }

    #[test]
    fn test_tick_all_noop_on_active() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                60_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        assert!(proto.tick_all().is_empty());
        assert_eq!(proto.active_count(), 1);
    }

    // -- Protocol-level encode/decode -----------------------------------

    #[test]
    fn test_protocol_encode_decode_roundtrip() {
        let mut proto = LeaseProtocol::new(epoch(1), DatasetMountIdentity::new(1, 1, 1));
        let grant = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                30_000,
                DatasetMountIdentity::new(1, 1, 1),
            )
            .unwrap();
        let msg = LeaseMessage::Grant(grant);
        let encoded = LeaseProtocol::encode_message(&msg).unwrap();
        let decoded = LeaseProtocol::decode_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_acknowledge_variant() {
        let ok = LeaseMessage::Acknowledge {
            lease_id: 1,
            success: true,
            detail: "granted".into(),
        };
        let fail = LeaseMessage::Acknowledge {
            lease_id: 2,
            success: false,
            detail: "conflict".into(),
        };
        assert!(matches!(
            &ok,
            LeaseMessage::Acknowledge { success: true, .. }
        ));
        assert!(matches!(
            &fail,
            LeaseMessage::Acknowledge { success: false, .. }
        ));

        for msg in &[ok, fail] {
            let encoded = LeaseMessageCodec::encode(msg).unwrap();
            let decoded = LeaseMessageCodec::decode(&encoded).unwrap();
            assert_eq!(&decoded, msg);
        }
    }
    // ── Issue #469: mount-identity and epoch binding ──────────────────

    fn mount_id(dataset_id: u64, mount_id: u64, committed_epoch: u64) -> DatasetMountIdentity {
        DatasetMountIdentity::new(dataset_id, mount_id, committed_epoch)
    }

    /// AC1: Lease acquisition requires a committed dataset mount identity token.
    #[test]
    fn test_lease_acquisition_with_correct_mount_identity() {
        let mi = mount_id(1, 1, 1);
        let mut proto = LeaseProtocol::new(epoch(1), mi);
        let grant = proto
            .grant_lease(LeaseClass::Exclusive, inode_domain(1, 42), m(7), 30_000, mi)
            .expect("grant should succeed with matching mount identity");
        assert_eq!(grant.mount_identity, mi);
        assert_eq!(grant.epoch, epoch(1));
        assert!(proto.is_active(grant.lease_id));
    }

    /// AC1: stale mount identities are rejected before a lease is granted.
    #[test]
    fn test_lease_acquisition_rejects_wrong_mount_identity() {
        let current = mount_id(1, 2, 1);
        let stale = mount_id(1, 1, 1);
        let mut proto = LeaseProtocol::new(epoch(1), current);

        let result = proto.grant_lease(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(7),
            30_000,
            stale,
        );

        assert!(matches!(
            result,
            Err(LeaseProtocolError::MountIdentityMismatch(got, expected))
                if got == stale && expected == current
        ));
        assert_eq!(proto.active_count(), 0);
    }

    /// AC2: Lease renewal is rejected if the current membership epoch
    /// does not match the lease epoch.
    #[test]
    fn test_lease_rejection_after_epoch_change() {
        let mi = mount_id(1, 1, 1);
        let mut proto = LeaseProtocol::new(epoch(1), mi);
        let grant = proto
            .grant_lease(LeaseClass::Exclusive, inode_domain(1, 42), m(7), 30_000, mi)
            .unwrap();
        // Advance the epoch — all old leases are revoked.
        proto.advance_epoch(epoch(2)).unwrap();
        // The lease should no longer be active.
        assert!(!proto.is_active(grant.lease_id));
        // A new lease with the new epoch should succeed.
        let g2 = proto
            .grant_lease(LeaseClass::Exclusive, inode_domain(1, 99), m(7), 30_000, mi)
            .unwrap();
        assert_eq!(g2.epoch, epoch(2));
        assert!(proto.is_active(g2.lease_id));
    }

    /// AC2 (renewal rejection): renewing a lease from an old epoch fails.
    #[test]
    fn test_renewal_rejected_on_epoch_mismatch() {
        let mi = mount_id(1, 1, 1);
        let mut proto = LeaseProtocol::new(epoch(1), mi);
        let grant = proto
            .grant_lease(LeaseClass::Exclusive, inode_domain(1, 42), m(7), 30_000, mi)
            .unwrap();
        // Advance epoch — should fence all old leases.
        proto.advance_epoch(epoch(2)).unwrap();
        // Attempting to renew the old lease should fail.
        let result = proto.renew_lease(grant.lease_id, m(7), 30_000);
        assert!(
            result.is_err(),
            "renewal should be rejected after epoch change"
        );
    }

    /// AC3: A lease from a previous mount is invalid after remount,
    /// even if the lease interval has not expired.
    #[test]
    fn test_lease_invalidation_after_remount() {
        let mi1 = mount_id(1, 1, 1);
        let mut proto = LeaseProtocol::new(epoch(1), mi1);
        let grant = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                60_000,
                mi1,
            )
            .unwrap();
        assert!(proto.is_active(grant.lease_id));
        // Remount with a new mount identity (same epoch, different mount_id).
        let mi2 = mount_id(1, 2, 1);
        let revoked = proto.remount_invalidate(mi2);
        assert!(revoked.contains(&grant.lease_id));
        assert!(!proto.is_active(grant.lease_id));
        assert_eq!(proto.current_mount_identity(), mi2);
    }

    /// AC3 (continued): after remount, new leases use the new mount identity.
    #[test]
    fn test_new_leases_use_current_mount_after_remount() {
        let mi1 = mount_id(1, 1, 1);
        let mi2 = mount_id(1, 2, 1);
        let mut proto = LeaseProtocol::new(epoch(1), mi1);
        proto.remount_invalidate(mi2);
        let g = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                30_000,
                mi2,
            )
            .expect("grant should succeed with current mount identity");
        assert_eq!(g.mount_identity, mi2);
    }

    /// AC4: Leases are persisted with mount-identity and epoch binding
    /// (verified through encode/decode round-trip maintaining both fields).
    #[test]
    fn test_lease_persistence_with_identity_binding() {
        let mi = mount_id(1, 42, 7);
        let mut proto = LeaseProtocol::new(epoch(7), mi);
        let grant = proto
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 100),
                m(7),
                30_000,
                mi,
            )
            .unwrap();
        // Encode and decode the grant message.
        let msg = LeaseMessage::Grant(grant.clone());
        let encoded = LeaseProtocol::encode_message(&msg).unwrap();
        let decoded = LeaseProtocol::decode_message(&encoded).unwrap();
        match decoded {
            LeaseMessage::Grant(decoded_grant) => {
                assert_eq!(decoded_grant.mount_identity, mi);
                assert_eq!(decoded_grant.epoch, epoch(7));
                assert_eq!(decoded_grant.lease_id, grant.lease_id);
            }
            other => panic!("expected Grant, got {other:?}"),
        }
    }

    /// AC4 (continued): a lease decoded from persistence is still invalid
    /// after remount, even though it was encoded correctly.
    #[test]
    fn test_persisted_lease_invalid_after_remount() {
        let mi1 = mount_id(1, 1, 1);
        let mi2 = mount_id(1, 2, 1);
        // Create and encode a lease under mi1.
        let mut proto1 = LeaseProtocol::new(epoch(1), mi1);
        let grant = proto1
            .grant_lease(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(7),
                60_000,
                mi1,
            )
            .unwrap();
        let encoded = LeaseProtocol::encode_message(&LeaseMessage::Grant(grant.clone())).unwrap();
        // A new protocol instance with mi2 should recognize the persisted lease as stale.
        let proto2 = LeaseProtocol::new(epoch(1), mi2);
        let decoded = LeaseProtocol::decode_message(&encoded).unwrap();
        if let LeaseMessage::Grant(decoded_grant) = decoded {
            assert_eq!(decoded_grant.mount_identity, mi1);
            assert_ne!(
                decoded_grant.mount_identity,
                proto2.current_mount_identity()
            );
        }
    }
}
