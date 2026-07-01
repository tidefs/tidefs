// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::{Deserialize, Serialize};
use std::fmt;
pub use tidefs_auth::NodeIdentity;
pub use tidefs_auth::NodeIdentity as NodeIdentityPublic;
use tidefs_clock_timing::types::HlcValue;
use tidefs_storage_intent_core::{StorageIntentEvidenceKind, StorageIntentEvidenceRef};
use tidefs_storage_intent_remote_media_capability::RemoteTargetIdentityFacts;

// ---------------------------------------------------------------------------
// Core identifiers
// ---------------------------------------------------------------------------

/// Unique session identifier between two nodes.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct SessionId(pub u64);

impl SessionId {
    #[must_use]
    /// Create a new SessionId from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s{}", self.0)
    }
}

/// Locally-unique transfer identifier for chunk shipping.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ChunkTransferId(pub u64);

impl ChunkTransferId {
    #[must_use]
    /// Create a new ChunkTransferId from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for ChunkTransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ct{}", self.0)
    }
}

/// Content-addressable chunk identifier.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ChunkId(pub u64);

impl ChunkId {
    #[must_use]
    /// Create a new ChunkId from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chunk:{}", self.0)
    }
}

/// SHA-256 hash digest.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    #[must_use]
    /// Create a new Hash from a 32-byte array.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

mod hex {
    /// Hex-encode raw bytes into a string.
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

// ---------------------------------------------------------------------------
// HLC timestamp (source-owned timing model, backed by tidefs-clock-timing)
// ---------------------------------------------------------------------------

/// Hybrid Logical Clock timestamp backed by a real HlcValue.
///
/// Wraps HlcValue from tidefs-clock-timing. The outer wrapper keeps the
/// transport crate's API stable while the inner value carries the full HLC
/// physical time (nanoseconds) and logical counter.
///
/// Historical new(wall_millis, logical) constructor remains available as a
/// convenience (interprets wall_millis as milliseconds and converts to ns).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct HlcTimestamp(HlcValue);

impl HlcTimestamp {
    /// Create an HlcTimestamp from wall-clock milliseconds + logical.
    ///
    /// The millisecond value is converted to nanoseconds for storage.
    #[must_use]
    pub fn new(wall_millis: u64, logical: u32) -> Self {
        Self(HlcValue::new(
            wall_millis.saturating_mul(1_000_000),
            logical as u64,
        ))
    }

    /// Create directly from an HlcValue.
    #[must_use]
    pub fn from_hlc_value(value: HlcValue) -> Self {
        Self(value)
    }

    /// Return the inner HlcValue.
    #[must_use]
    pub fn as_hlc_value(&self) -> &HlcValue {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Protocol versioning
// ---------------------------------------------------------------------------

/// A (message family, version) pair for protocol negotiation during handshake.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct FamilyVersion {
    pub family_id: u16,
    pub version_major: u16,
    pub version_minor: u16,
}

impl FamilyVersion {
    #[must_use]
    /// Create a new FamilyVersion with the given family and version numbers.
    pub const fn new(family_id: u16, version_major: u16, version_minor: u16) -> Self {
        Self {
            family_id,
            version_major,
            version_minor,
        }
    }
}

/// Monotonic version for freshness fencing on chunk transfers.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct FenceVersion(pub u64);

impl FenceVersion {
    #[must_use]
    /// Create a new FenceVersion from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------

/// Cohort membership info exchanged during session handshake.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct CohortMembership {
    pub domain_ids: Vec<u64>,
    pub epoch: u64,
}

impl CohortMembership {
    #[must_use]
    /// Create a new CohortMembership with the given domain IDs and epoch.
    pub fn new(domain_ids: Vec<u64>, epoch: u64) -> Self {
        Self { domain_ids, epoch }
    }
}

/// Bounded transport-session identity sample for #961 remote media inputs.
///
/// The sample is read-only: it records session, node identity, HLC, fence, and
/// cohort facts already owned by transport/membership/auth layers. It does not
/// originate placement, durability, trust-domain, or endpoint-measurement
/// authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteMediaTransportIdentitySample {
    pub session_id: SessionId,
    pub local_node_id: u64,
    pub remote_node_id: u64,
    pub observed_at: HlcTimestamp,
    pub fence_version: FenceVersion,
    pub cohort_epoch: u64,
    pub cohort_member_count: u16,
    pub remote_identity_version: u64,
    pub stable_identity_ref: StorageIntentEvidenceRef,
    pub namespace_identity_ref: StorageIntentEvidenceRef,
}

fn evidence_ref_has_kind(
    evidence_ref: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence_ref.is_bound() && evidence_ref.kind == kind
}

impl RemoteMediaTransportIdentitySample {
    #[must_use]
    pub fn from_authenticated_session(
        session_id: SessionId,
        local_identity: &NodeIdentity,
        remote_identity: &NodeIdentity,
        observed_at: HlcTimestamp,
        fence_version: FenceVersion,
        cohort: &CohortMembership,
        stable_identity_ref: StorageIntentEvidenceRef,
        namespace_identity_ref: StorageIntentEvidenceRef,
    ) -> Self {
        let cohort_member_count = cohort.domain_ids.len().min(u16::MAX as usize) as u16;
        Self {
            session_id,
            local_node_id: local_identity.node_id,
            remote_node_id: remote_identity.node_id,
            observed_at,
            fence_version,
            cohort_epoch: cohort.epoch,
            cohort_member_count,
            remote_identity_version: remote_identity.identity_version,
            stable_identity_ref,
            namespace_identity_ref,
        }
    }

    #[must_use]
    pub fn to_remote_target_identity_facts(self) -> RemoteTargetIdentityFacts {
        let observed_hlc = self.observed_at.as_hlc_value();
        if self.session_id.0 == 0
            || self.local_node_id == 0
            || self.remote_node_id == 0
            || self.local_node_id == self.remote_node_id
            || self.fence_version.0 == 0
            || self.cohort_epoch == 0
            || self.cohort_member_count == 0
            || self.remote_identity_version == 0
            || observed_hlc.physical_ns() == 0
            || !evidence_ref_has_kind(
                self.stable_identity_ref,
                StorageIntentEvidenceKind::TrustDomainEvidence,
            )
            || !evidence_ref_has_kind(
                self.namespace_identity_ref,
                StorageIntentEvidenceKind::MetadataNamespaceEvidence,
            )
        {
            return RemoteTargetIdentityFacts::default();
        }

        RemoteTargetIdentityFacts {
            stable_target_identity: true,
            stable_namespace_identity: true,
            pool_member_binding: true,
            endpoint_generation_proven: true,
            credential_key_epoch_proven: true,
            identity_generation: self.remote_identity_version,
            namespace_generation: self.cohort_epoch,
            endpoint_generation: self.session_id.0,
            credential_key_epoch: self.remote_identity_version,
            pool_member_generation: self.fence_version.0,
            stable_identity_ref: self.stable_identity_ref,
            namespace_identity_ref: self.namespace_identity_ref,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::StorageIntentEvidenceId;

    fn evidence_ref(kind: StorageIntentEvidenceKind, seed: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            kind,
            StorageIntentEvidenceId([seed; 32]),
            u64::from(seed),
            1,
        )
    }

    fn node_identity(node_id: u64, identity_version: u64) -> NodeIdentity {
        NodeIdentity {
            node_id,
            verifying_key_bytes: [node_id as u8; 32],
            attested_at_millis: 1,
            identity_version,
            self_signature: vec![identity_version as u8; 64],
        }
    }

    #[test]
    fn authenticated_session_projects_remote_identity_facts() {
        let local = node_identity(11, 1);
        let remote = node_identity(22, 7);
        let cohort = CohortMembership::new(vec![11, 22, 33], 5);
        let stable_ref = evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 41);
        let namespace_ref = evidence_ref(StorageIntentEvidenceKind::MetadataNamespaceEvidence, 42);

        let sample = RemoteMediaTransportIdentitySample::from_authenticated_session(
            SessionId::new(99),
            &local,
            &remote,
            HlcTimestamp::new(1_700_000_000, 3),
            FenceVersion::new(13),
            &cohort,
            stable_ref,
            namespace_ref,
        );
        let facts = sample.to_remote_target_identity_facts();

        assert!(facts.stable_target_identity);
        assert!(facts.stable_namespace_identity);
        assert!(facts.pool_member_binding);
        assert!(facts.endpoint_generation_proven);
        assert!(facts.credential_key_epoch_proven);
        assert_eq!(facts.identity_generation, 7);
        assert_eq!(facts.namespace_generation, 5);
        assert_eq!(facts.endpoint_generation, 99);
        assert_eq!(facts.credential_key_epoch, 7);
        assert_eq!(facts.pool_member_generation, 13);
        assert_eq!(facts.stable_identity_ref, stable_ref);
        assert_eq!(facts.namespace_identity_ref, namespace_ref);
    }

    #[test]
    fn endpoint_name_only_identity_sample_rejects() {
        let local = node_identity(11, 1);
        let remote = node_identity(22, 7);
        let cohort = CohortMembership::new(vec![11, 22], 5);

        let sample = RemoteMediaTransportIdentitySample::from_authenticated_session(
            SessionId::new(99),
            &local,
            &remote,
            HlcTimestamp::new(1_700_000_000, 3),
            FenceVersion::new(13),
            &cohort,
            StorageIntentEvidenceRef::default(),
            StorageIntentEvidenceRef::default(),
        );

        assert_eq!(
            sample.to_remote_target_identity_facts(),
            RemoteTargetIdentityFacts::default()
        );
    }

    #[test]
    fn wrong_identity_ref_kind_rejects() {
        let local = node_identity(11, 1);
        let remote = node_identity(22, 7);
        let cohort = CohortMembership::new(vec![11, 22], 5);

        let sample = RemoteMediaTransportIdentitySample::from_authenticated_session(
            SessionId::new(99),
            &local,
            &remote,
            HlcTimestamp::new(1_700_000_000, 3),
            FenceVersion::new(13),
            &cohort,
            evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 43),
            evidence_ref(StorageIntentEvidenceKind::MetadataNamespaceEvidence, 44),
        );

        assert_eq!(
            sample.to_remote_target_identity_facts(),
            RemoteTargetIdentityFacts::default()
        );
    }
}
