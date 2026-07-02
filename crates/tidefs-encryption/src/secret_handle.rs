// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Secret-handle/key-lease boundary for pool encryption keys (REL-SEC-003).
//!
//! This module implements the operator-visible secret-handle/key-lease
//! boundary for encrypted pool mount/import, following the P9-04
//! secret-key-policy law:
//!
//! - [`PoolEncryptionSecretHandle`]: opaque, stable identifier for a pool
//!   encryption key. Operators reference the key by handle, not by file
//!   path or raw bytes.
//! - [`PoolEncryptionKeyLease`]: short-lived plaintext access to the pool
//!   encryption key. The lease is time-bounded and the key material is
//!   zeroized on drop.
//!
//! ## Integration with durable envelope
//!
//! The handle sits above the [`SealedPoolKeyEnvelope`](tidefs_local_object_store::encrypt::SealedPoolKeyEnvelope)
//! (VEKF v1 format) durable sealed-key storage:
//!
//! ```text
//! operator -> secret handle ID -> handle record -> sealed envelope
//!                                                     |
//!                                     wrapping key --> unseal
//!                                                     |
//!                                                     v
//!                                               plaintext lease
//! ```
//!
//! The handle ID is stable across key rotations; the envelope version
//! changes when the key is rotated or rewrapped.

use std::fmt;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::key_hierarchy::PoolWrappingKey;
use crate::{EncryptionError, Result, StoreKey, KEY_LEN};

// ── Constants ─────────────────────────────────────────────────────────────

/// Handle ID length in bytes (16 bytes = 128 bits of entropy).
pub const SECRET_HANDLE_ID_LEN: usize = 16;

/// Dataset mount authority key length in bytes.
pub const DATASET_MOUNT_AUTHORITY_KEY_LEN: usize = 32;

/// Committed dataset mount token length in bytes.
pub const DATASET_MOUNT_COMMITMENT_LEN: usize = 32;

const DATASET_MOUNT_COMMITMENT_DOMAIN: &[u8] =
    b"tidefs-encryption committed dataset mount token v1";

/// Maximum lease duration for a pool encryption key.
pub const MAX_LEASE_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// Default lease duration for mount-time use.
pub const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(300); // 5 minutes

// ── Handle identifier ─────────────────────────────────────────────────────

/// A stable, opaque 128-bit identifier for a pool encryption secret handle.
///
/// Generated randomly at handle creation; stable across key rotations.
/// The operator references the handle by this ID; the ID never exposes
/// key material (P9-04 handle-not-bytes law §3.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretHandleId {
    bytes: [u8; SECRET_HANDLE_ID_LEN],
}

impl SecretHandleId {
    /// Generate a fresh random handle ID using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_HANDLE_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Restore a handle ID from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SECRET_HANDLE_ID_LEN {
            return None;
        }
        let mut arr = [0u8; SECRET_HANDLE_ID_LEN];
        arr.copy_from_slice(bytes);
        Some(Self { bytes: arr })
    }

    /// Raw handle ID bytes.
    pub fn as_bytes(&self) -> &[u8; SECRET_HANDLE_ID_LEN] {
        &self.bytes
    }

    /// Hex-encode the handle ID for display (32 hex chars).
    pub fn hex(&self) -> String {
        self.bytes
            .iter()
            .fold(String::with_capacity(32), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

impl fmt::Debug for SecretHandleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretHandleId({})", self.hex())
    }
}

impl fmt::Display for SecretHandleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

// ── Lifecycle state ───────────────────────────────────────────────────────

/// Lifecycle state for a pool encryption secret handle (P9-04 §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretHandleLifecycle {
    /// Handle created, key sealed, not yet activated for mount use.
    SealedInactive,
    /// Handle is active; leases can be issued.
    Active,
    /// Key is being rotated; both old and new envelopes are valid.
    RotatingDualValid,
    /// Handle revoked; no new leases allowed.
    Revoked,
    /// Handle in quarantine (material may be compromised).
    Quarantined,
    /// Handle retired (terminal state).
    Retired,
}

impl SecretHandleLifecycle {
    /// Whether this state blocks lease issuance.
    pub fn blocks_lease(&self) -> bool {
        matches!(self, Self::Revoked | Self::Quarantined | Self::Retired)
    }

    /// Whether this state allows mount/import.
    pub fn allows_mount(&self) -> bool {
        matches!(self, Self::Active | Self::RotatingDualValid)
    }
}

/// Mounted pool key lifecycle state used by fail-closed access reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountedPoolKeyAccessState {
    Active,
    Rotating,
    Revoked,
    Quarantined,
    Retired,
    Missing,
    Stale,
    RecoveryAfterCrash,
}

impl MountedPoolKeyAccessState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::RecoveryAfterCrash => "recovery_after_crash",
        }
    }
}

impl fmt::Display for MountedPoolKeyAccessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Crash-recovery evidence available before issuing a mounted pool key lease.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MountedPoolKeyRecoveryEvidence {
    /// Normal active mount path with no recovery replay required.
    #[default]
    CurrentMount,
    /// Recovery replay completed and restored the committed key binding.
    ReplayedAfterCrash,
    /// Recovery replay is required but missing or incomplete.
    ReplayMissing,
}

/// Explicit refusal reason for mounted pool key access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountedPoolKeyAccessRefusal {
    MissingHandleRecord,
    MissingCommittedMountToken,
    StaleCommittedMountToken,
    HandleNotActive,
    HandleRevoked,
    HandleQuarantined,
    HandleRetired,
    RecoveryReplayMissing,
}

impl MountedPoolKeyAccessRefusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingHandleRecord => "missing handle record",
            Self::MissingCommittedMountToken => "missing committed mount token",
            Self::StaleCommittedMountToken => "stale committed mount token",
            Self::HandleNotActive => "handle is not active",
            Self::HandleRevoked => "handle is revoked",
            Self::HandleQuarantined => "handle is quarantined",
            Self::HandleRetired => "handle is retired",
            Self::RecoveryReplayMissing => "recovery replay is missing",
        }
    }
}

impl fmt::Display for MountedPoolKeyAccessRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountedPoolKeyAccessDecision {
    AllowLease,
    RefuseMountAccess,
}

/// Mounted pool key access assessment with operator-visible refusal detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountedPoolKeyAccessAssessment {
    pub state: MountedPoolKeyAccessState,
    pub decision: MountedPoolKeyAccessDecision,
    pub refusal: Option<MountedPoolKeyAccessRefusal>,
}

impl MountedPoolKeyAccessAssessment {
    pub fn allow(state: MountedPoolKeyAccessState) -> Self {
        Self {
            state,
            decision: MountedPoolKeyAccessDecision::AllowLease,
            refusal: None,
        }
    }

    pub fn refuse(state: MountedPoolKeyAccessState, refusal: MountedPoolKeyAccessRefusal) -> Self {
        Self {
            state,
            decision: MountedPoolKeyAccessDecision::RefuseMountAccess,
            refusal: Some(refusal),
        }
    }

    pub fn allows_lease(&self) -> bool {
        self.decision == MountedPoolKeyAccessDecision::AllowLease
    }

    pub fn refusal_reason(&self) -> Option<MountedPoolKeyAccessRefusal> {
        self.refusal
    }
}

/// Payload class covered by a cryptographic-erase boundary assessment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformPayloadClass {
    FullyTransformedEncrypted,
    Plaintext,
    CompressedOnly,
    Unencrypted,
    PartiallyTransformed,
    RawStoreBypassed,
    PreviouslyExposedMedia,
}

/// Evidence required before revocation/destruction can enter claim review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptographicEraseEvidence {
    pub payload_class: TransformPayloadClass,
    pub transform_metadata_persisted: bool,
    pub stored_frame_reachability_proven: bool,
    pub media_remanence_limits_documented: bool,
}

impl CryptographicEraseEvidence {
    pub fn encrypted_with_full_proof() -> Self {
        Self {
            payload_class: TransformPayloadClass::FullyTransformedEncrypted,
            transform_metadata_persisted: true,
            stored_frame_reachability_proven: true,
            media_remanence_limits_documented: true,
        }
    }
}

/// Explicit refusal reason for cryptographic erase claim review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptographicEraseRefusal {
    KeyLifecycleNotDestroyedOrRevoked,
    MissingTransformMetadata,
    StoredFrameReachabilityUnproven,
    MediaRemanenceLimitsUnproven,
    PayloadPlaintext,
    PayloadCompressedOnly,
    PayloadUnencrypted,
    PayloadPartiallyTransformed,
    PayloadRawStoreBypassed,
    PayloadPreviouslyExposed,
}

impl CryptographicEraseRefusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KeyLifecycleNotDestroyedOrRevoked => "key lifecycle is not destroyed or revoked",
            Self::MissingTransformMetadata => "transform metadata is missing",
            Self::StoredFrameReachabilityUnproven => "stored-frame reachability is unproven",
            Self::MediaRemanenceLimitsUnproven => "media remanence limits are unproven",
            Self::PayloadPlaintext => "payload is plaintext",
            Self::PayloadCompressedOnly => "payload is compressed-only",
            Self::PayloadUnencrypted => "payload is unencrypted",
            Self::PayloadPartiallyTransformed => "payload is partially transformed",
            Self::PayloadRawStoreBypassed => "payload bypassed the raw-store transform authority",
            Self::PayloadPreviouslyExposed => "payload was previously exposed on media",
        }
    }
}

impl fmt::Display for CryptographicEraseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptographicEraseVerdict {
    Refused,
    PrerequisitesSatisfiedForClaimReview,
}

/// Cryptographic erase boundary assessment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptographicEraseAssessment {
    pub verdict: CryptographicEraseVerdict,
    pub refusal: Option<CryptographicEraseRefusal>,
    pub non_claim: &'static str,
}

impl CryptographicEraseAssessment {
    pub fn refused(refusal: CryptographicEraseRefusal) -> Self {
        Self {
            verdict: CryptographicEraseVerdict::Refused,
            refusal: Some(refusal),
            non_claim: CRYPTOGRAPHIC_ERASE_NON_CLAIM,
        }
    }

    pub fn prerequisites_satisfied_for_claim_review() -> Self {
        Self {
            verdict: CryptographicEraseVerdict::PrerequisitesSatisfiedForClaimReview,
            refusal: None,
            non_claim: CRYPTOGRAPHIC_ERASE_NON_CLAIM,
        }
    }

    pub fn can_present_as_secure_erase(&self) -> bool {
        false
    }

    pub fn eligible_for_claim_review(&self) -> bool {
        self.verdict == CryptographicEraseVerdict::PrerequisitesSatisfiedForClaimReview
    }
}

pub const CRYPTOGRAPHIC_ERASE_NON_CLAIM: &str =
    "key revocation or destruction alone is not secure erase, sanitization, decommissioning, or remanence proof";

impl fmt::Display for SecretHandleLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealedInactive => write!(f, "sealed_inactive"),
            Self::Active => write!(f, "active"),
            Self::RotatingDualValid => write!(f, "rotating_dual_valid"),
            Self::Revoked => write!(f, "revoked"),
            Self::Quarantined => write!(f, "quarantined"),
            Self::Retired => write!(f, "retired"),
        }
    }
}

// ── Dataset mount identity ─────────────────────────────────────────────────

/// A dataset mount identity.
///
/// Binds encryption key access to a specific dataset mount instance.
/// When a dataset is unmounted and remounted, the mount generation
/// increments, invalidating any key handles bound to the previous
/// mount. This prevents decryption under a stale or foreign dataset
/// identity.
///
/// The identity is the pair `(dataset_id, mount_generation)` where
/// `mount_generation` is a monotonically increasing counter assigned
/// at each mount of the dataset. It is not sufficient authorization by
/// itself; key-handle lease issuance requires a
/// [`CommittedDatasetMountToken`] minted by the current mount authority.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DatasetMountIdentity {
    /// Dataset identifier (e.g., "pool/dataset").
    pub dataset_id: String,
    /// Monotonic mount generation for this dataset.
    /// Incremented on each remount; resets to 0 only on pool create.
    pub mount_generation: u64,
}

impl DatasetMountIdentity {
    /// Create a new mount identity for a dataset at a given generation.
    pub fn new(dataset_id: String, mount_generation: u64) -> Self {
        Self {
            dataset_id,
            mount_generation,
        }
    }

    /// Returns true when `other` matches this identity (same dataset
    /// and same mount generation).
    pub fn matches(&self, other: &Self) -> bool {
        self.dataset_id == other.dataset_id && self.mount_generation == other.mount_generation
    }
}

impl std::fmt::Display for DatasetMountIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@gen{}", self.dataset_id, self.mount_generation)
    }
}

/// Secret authority material used to mint committed dataset mount tokens.
///
/// The mount authority owns this material. Encryption key-handle callers carry
/// a [`CommittedDatasetMountToken`], not this key.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DatasetMountAuthorityKey {
    bytes: [u8; DATASET_MOUNT_AUTHORITY_KEY_LEN],
}

impl DatasetMountAuthorityKey {
    /// Generate fresh mount-authority key material using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; DATASET_MOUNT_AUTHORITY_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Restore mount-authority key material from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DATASET_MOUNT_AUTHORITY_KEY_LEN {
            return Err(EncryptionError::InvalidKeyLength {
                expected: DATASET_MOUNT_AUTHORITY_KEY_LEN,
                got: bytes.len(),
            });
        }

        let mut arr = [0u8; DATASET_MOUNT_AUTHORITY_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Raw authority key bytes.
    pub fn as_bytes(&self) -> &[u8; DATASET_MOUNT_AUTHORITY_KEY_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for DatasetMountAuthorityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatasetMountAuthorityKey")
            .finish_non_exhaustive()
    }
}

/// Committed evidence for one dataset mount identity.
///
/// The token is a keyed BLAKE3 commitment over the dataset id and mount
/// generation, minted by the current mount authority. A bare
/// [`DatasetMountIdentity`] does not authorize key-handle minting or lease
/// issuance.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CommittedDatasetMountToken {
    dataset_mount_identity: DatasetMountIdentity,
    commitment: [u8; DATASET_MOUNT_COMMITMENT_LEN],
}

impl CommittedDatasetMountToken {
    /// Mint a committed token for `dataset_mount_identity`.
    pub fn mint(
        dataset_mount_identity: DatasetMountIdentity,
        authority_key: &DatasetMountAuthorityKey,
    ) -> Self {
        let commitment = commit_dataset_mount_identity(&dataset_mount_identity, authority_key);
        Self {
            dataset_mount_identity,
            commitment,
        }
    }

    /// The dataset mount identity committed by this token.
    pub fn dataset_mount_identity(&self) -> &DatasetMountIdentity {
        &self.dataset_mount_identity
    }

    /// The committed digest minted for this token.
    pub fn commitment(&self) -> &[u8; DATASET_MOUNT_COMMITMENT_LEN] {
        &self.commitment
    }

    fn matches_record(
        &self,
        dataset_mount_identity: &DatasetMountIdentity,
        commitment: &[u8; DATASET_MOUNT_COMMITMENT_LEN],
    ) -> bool {
        self.dataset_mount_identity.matches(dataset_mount_identity)
            && constant_time_eq(&self.commitment, commitment)
    }
}

impl fmt::Debug for CommittedDatasetMountToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommittedDatasetMountToken")
            .field("dataset_mount_identity", &self.dataset_mount_identity)
            .finish_non_exhaustive()
    }
}

fn commit_dataset_mount_identity(
    dataset_mount_identity: &DatasetMountIdentity,
    authority_key: &DatasetMountAuthorityKey,
) -> [u8; DATASET_MOUNT_COMMITMENT_LEN] {
    let dataset_id = dataset_mount_identity.dataset_id.as_bytes();
    let mut hasher = blake3::Hasher::new_keyed(authority_key.as_bytes());
    hasher.update(DATASET_MOUNT_COMMITMENT_DOMAIN);
    hasher.update(&(dataset_id.len() as u64).to_le_bytes());
    hasher.update(dataset_id);
    hasher.update(&dataset_mount_identity.mount_generation.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn constant_time_eq(
    left: &[u8; DATASET_MOUNT_COMMITMENT_LEN],
    right: &[u8; DATASET_MOUNT_COMMITMENT_LEN],
) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ── Handle record ─────────────────────────────────────────────────────────

/// Durable record for a pool encryption secret handle.
///
/// Stored alongside the sealed envelope. Contains handle identity,
/// lifecycle state, creation timestamp, and rotation lineage.
/// Never contains plaintext key material (P9-04 handle-not-bytes §3.3).
#[derive(Clone, Debug)]
pub struct PoolEncryptionSecretHandleRecord {
    /// Stable handle identifier.
    pub handle_id: SecretHandleId,
    /// Human-readable pool name.
    pub pool_name: String,
    /// Current lifecycle state.
    pub lifecycle: SecretHandleLifecycle,
    /// Unix timestamp (seconds) when the handle was created.
    pub created_at: u64,
    /// Committed dataset mount identity this handle is bound to.
    ///
    /// Lease issuance requires a committed token for this identity.
    pub dataset_mount_identity: DatasetMountIdentity,
    /// Commitment minted by the current mount authority for this handle.
    dataset_mount_commitment: [u8; DATASET_MOUNT_COMMITMENT_LEN],
    /// Unix timestamp (seconds) when lifecycle last changed.
    pub state_changed_at: u64,
    /// Key generation counter (0 = original, increments on rotation).
    pub key_generation: u32,
    /// SHA-256 digest of the sealed envelope bytes for integrity.
    pub sealed_envelope_sha256: [u8; 32],
    /// Wrapping-key generation used to seal this version.
    pub wrapping_key_generation: u32,
}

impl PoolEncryptionSecretHandleRecord {
    /// Create a new handle record for a freshly generated key.
    pub fn new(
        handle_id: SecretHandleId,
        pool_name: String,
        sealed_envelope_sha256: [u8; 32],
        wrapping_key_generation: u32,
        created_at: u64,
        dataset_mount_token: CommittedDatasetMountToken,
    ) -> Self {
        Self {
            handle_id,
            pool_name,
            lifecycle: SecretHandleLifecycle::SealedInactive,
            created_at,
            state_changed_at: created_at,
            key_generation: 0,
            sealed_envelope_sha256,
            wrapping_key_generation,
            dataset_mount_identity: dataset_mount_token.dataset_mount_identity,
            dataset_mount_commitment: dataset_mount_token.commitment,
        }
    }

    /// Activate the handle for mount use (leases become issuable).
    pub fn activate(&mut self, now: u64) {
        self.lifecycle = SecretHandleLifecycle::Active;
        self.state_changed_at = now;
    }

    /// Mark the handle as rotating with dual-valid key material.
    pub fn begin_rotation(&mut self, now: u64) {
        self.lifecycle = SecretHandleLifecycle::RotatingDualValid;
        self.state_changed_at = now;
    }

    /// Revoke the handle, blocking all future leases.
    pub fn revoke(&mut self, now: u64) {
        self.lifecycle = SecretHandleLifecycle::Revoked;
        self.state_changed_at = now;
    }

    /// Quarantine the handle, blocking leases while compromise is investigated.
    pub fn quarantine(&mut self, now: u64) {
        self.lifecycle = SecretHandleLifecycle::Quarantined;
        self.state_changed_at = now;
    }

    /// Retire the handle, blocking leases as a terminal lifecycle state.
    pub fn retire(&mut self, now: u64) {
        self.lifecycle = SecretHandleLifecycle::Retired;
        self.state_changed_at = now;
    }

    /// Whether a lease can be issued.
    pub fn can_issue_lease(&self) -> bool {
        self.lifecycle.allows_mount()
    }

    /// Whether this handle can be used for mount/import.
    pub fn can_mount(&self) -> bool {
        self.lifecycle.allows_mount()
    }

    /// Whether `token` is the committed mount evidence bound to this handle.
    pub fn accepts_dataset_mount_token(&self, token: &CommittedDatasetMountToken) -> bool {
        token.matches_record(&self.dataset_mount_identity, &self.dataset_mount_commitment)
    }

    /// Commitment minted by the current mount authority for this handle.
    pub fn dataset_mount_commitment(&self) -> &[u8; DATASET_MOUNT_COMMITMENT_LEN] {
        &self.dataset_mount_commitment
    }

    fn bind_dataset_mount_token(
        &mut self,
        dataset_mount_token: CommittedDatasetMountToken,
        now: u64,
    ) {
        self.dataset_mount_identity = dataset_mount_token.dataset_mount_identity;
        self.dataset_mount_commitment = dataset_mount_token.commitment;
        self.state_changed_at = now;
    }
}

pub fn assess_mounted_pool_key_access(
    record: Option<&PoolEncryptionSecretHandleRecord>,
    dataset_mount_token: Option<&CommittedDatasetMountToken>,
    recovery: MountedPoolKeyRecoveryEvidence,
) -> MountedPoolKeyAccessAssessment {
    if recovery == MountedPoolKeyRecoveryEvidence::ReplayMissing {
        return MountedPoolKeyAccessAssessment::refuse(
            MountedPoolKeyAccessState::RecoveryAfterCrash,
            MountedPoolKeyAccessRefusal::RecoveryReplayMissing,
        );
    }

    let Some(record) = record else {
        return MountedPoolKeyAccessAssessment::refuse(
            MountedPoolKeyAccessState::Missing,
            MountedPoolKeyAccessRefusal::MissingHandleRecord,
        );
    };

    let state = match record.lifecycle {
        SecretHandleLifecycle::SealedInactive => {
            return MountedPoolKeyAccessAssessment::refuse(
                MountedPoolKeyAccessState::Missing,
                MountedPoolKeyAccessRefusal::HandleNotActive,
            );
        }
        SecretHandleLifecycle::Active => MountedPoolKeyAccessState::Active,
        SecretHandleLifecycle::RotatingDualValid => MountedPoolKeyAccessState::Rotating,
        SecretHandleLifecycle::Revoked => {
            return MountedPoolKeyAccessAssessment::refuse(
                MountedPoolKeyAccessState::Revoked,
                MountedPoolKeyAccessRefusal::HandleRevoked,
            );
        }
        SecretHandleLifecycle::Quarantined => {
            return MountedPoolKeyAccessAssessment::refuse(
                MountedPoolKeyAccessState::Quarantined,
                MountedPoolKeyAccessRefusal::HandleQuarantined,
            );
        }
        SecretHandleLifecycle::Retired => {
            return MountedPoolKeyAccessAssessment::refuse(
                MountedPoolKeyAccessState::Retired,
                MountedPoolKeyAccessRefusal::HandleRetired,
            );
        }
    };

    let Some(token) = dataset_mount_token else {
        return MountedPoolKeyAccessAssessment::refuse(
            MountedPoolKeyAccessState::Missing,
            MountedPoolKeyAccessRefusal::MissingCommittedMountToken,
        );
    };

    if !record.accepts_dataset_mount_token(token) {
        return MountedPoolKeyAccessAssessment::refuse(
            MountedPoolKeyAccessState::Stale,
            MountedPoolKeyAccessRefusal::StaleCommittedMountToken,
        );
    }

    if recovery == MountedPoolKeyRecoveryEvidence::ReplayedAfterCrash {
        MountedPoolKeyAccessAssessment::allow(MountedPoolKeyAccessState::RecoveryAfterCrash)
    } else {
        MountedPoolKeyAccessAssessment::allow(state)
    }
}

pub fn assess_cryptographic_erase_boundary(
    key_state: MountedPoolKeyAccessState,
    evidence: CryptographicEraseEvidence,
) -> CryptographicEraseAssessment {
    if !matches!(
        key_state,
        MountedPoolKeyAccessState::Revoked | MountedPoolKeyAccessState::Retired
    ) {
        return CryptographicEraseAssessment::refused(
            CryptographicEraseRefusal::KeyLifecycleNotDestroyedOrRevoked,
        );
    }

    match evidence.payload_class {
        TransformPayloadClass::FullyTransformedEncrypted => {}
        TransformPayloadClass::Plaintext => {
            return CryptographicEraseAssessment::refused(
                CryptographicEraseRefusal::PayloadPlaintext,
            );
        }
        TransformPayloadClass::CompressedOnly => {
            return CryptographicEraseAssessment::refused(
                CryptographicEraseRefusal::PayloadCompressedOnly,
            );
        }
        TransformPayloadClass::Unencrypted => {
            return CryptographicEraseAssessment::refused(
                CryptographicEraseRefusal::PayloadUnencrypted,
            );
        }
        TransformPayloadClass::PartiallyTransformed => {
            return CryptographicEraseAssessment::refused(
                CryptographicEraseRefusal::PayloadPartiallyTransformed,
            );
        }
        TransformPayloadClass::RawStoreBypassed => {
            return CryptographicEraseAssessment::refused(
                CryptographicEraseRefusal::PayloadRawStoreBypassed,
            );
        }
        TransformPayloadClass::PreviouslyExposedMedia => {
            return CryptographicEraseAssessment::refused(
                CryptographicEraseRefusal::PayloadPreviouslyExposed,
            );
        }
    }

    if !evidence.transform_metadata_persisted {
        return CryptographicEraseAssessment::refused(
            CryptographicEraseRefusal::MissingTransformMetadata,
        );
    }

    if !evidence.stored_frame_reachability_proven {
        return CryptographicEraseAssessment::refused(
            CryptographicEraseRefusal::StoredFrameReachabilityUnproven,
        );
    }

    if !evidence.media_remanence_limits_documented {
        return CryptographicEraseAssessment::refused(
            CryptographicEraseRefusal::MediaRemanenceLimitsUnproven,
        );
    }

    CryptographicEraseAssessment::prerequisites_satisfied_for_claim_review()
}

// ── Key lease ─────────────────────────────────────────────────────────────

/// A short-lived lease granting plaintext access to a pool encryption key.
///
/// Wraps a [`StoreKey`] valid only until expiry. The key is zeroized on
/// drop. Per P9-04 §5.1: no long-lived secret as ambient capability;
/// runtime access flows through a short-lived lease.
pub struct PoolEncryptionKeyLease {
    handle_id: SecretHandleId,
    /// The committed dataset mount token bound to this lease.
    dataset_mount_token: CommittedDatasetMountToken,
    key: StoreKey,
    expires_at: Instant,
    usage: LeaseUsageClass,
}

impl fmt::Debug for PoolEncryptionKeyLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolEncryptionKeyLease")
            .field("handle_id", &self.handle_id)
            .field("expires_at", &self.expires_at)
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// What the lease is used for (P9-04 usage classes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseUsageClass {
    /// Mount or import a pool for filesystem access.
    PoolMount,
    /// Pool-level maintenance (scrub, rebuild, rekey).
    PoolMaintenance,
    /// Dataset-level operations within an encrypted pool.
    DatasetAccess,
}

impl LeaseUsageClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PoolMount => "pool_mount",
            Self::PoolMaintenance => "pool_maintenance",
            Self::DatasetAccess => "dataset_access",
        }
    }
}

impl PoolEncryptionKeyLease {
    fn new(
        handle_id: SecretHandleId,
        key: StoreKey,
        duration: Duration,
        dataset_mount_token: CommittedDatasetMountToken,
        usage: LeaseUsageClass,
    ) -> Self {
        Self {
            handle_id,
            key,
            expires_at: Instant::now() + duration,
            usage,
            dataset_mount_token,
        }
    }

    /// The handle this lease belongs to.
    pub fn handle_id(&self) -> SecretHandleId {
        self.handle_id
    }

    /// Whether the lease is still valid.
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Time remaining, or zero if expired.
    pub fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// Usage class for this lease.
    pub fn usage(&self) -> LeaseUsageClass {
        self.usage
    }

    /// Access the plaintext key bytes. Returns `None` if expired.
    pub fn key_bytes(&self) -> Option<&[u8; KEY_LEN]> {
        if self.is_valid() {
            Some(self.key.as_bytes())
        } else {
            None
        }
    }

    /// The dataset mount identity this lease is bound to.
    pub fn dataset_mount_identity(&self) -> &DatasetMountIdentity {
        self.dataset_mount_token.dataset_mount_identity()
    }

    /// The committed dataset mount token this lease is bound to.
    pub fn committed_dataset_mount_token(&self) -> &CommittedDatasetMountToken {
        &self.dataset_mount_token
    }

    /// Consume the lease and return a copy of the [`StoreKey`] if still valid.
    /// The original key material is zeroized on drop via [`StoreKey`] own Drop impl.
    pub fn into_key(self) -> Option<StoreKey> {
        if self.is_valid() {
            Some(self.key.clone())
        } else {
            None
        }
    }
}

// ── Secret handle ─────────────────────────────────────────────────────────

/// The operator-visible secret handle for a pool encryption key.
///
/// Bundles the handle identifier, durable record, and sealed envelope.
/// Operators use the handle ID to reference the key; the runtime uses
/// the handle to issue time-bounded leases.
///
/// This replaces the pattern of passing raw `--encryption-envelope`
/// file paths with a handle-based model.
#[derive(Clone, Debug)]
pub struct PoolEncryptionSecretHandle {
    /// Handle record (identity, lifecycle, lineage).
    pub record: PoolEncryptionSecretHandleRecord,
    /// Sealed envelope containing the encrypted key material.
    pub envelope: tidefs_local_object_store::encrypt::SealedPoolKeyEnvelope,
}

impl PoolEncryptionSecretHandle {
    /// Mint a new secret handle: generate a pool key, seal it in a
    /// VEKF envelope under the wrapping key, and create a handle record.
    ///
    /// Returns the handle and the original [`StoreKey`] so the caller
    /// can use it immediately (e.g., for the first mount). The caller
    /// should activate the handle with [`activate`](Self::activate)
    /// before issuing leases to other consumers.
    pub fn mint(
        pool_name: String,
        dataset_mount_token: CommittedDatasetMountToken,
        wrapping_key: &PoolWrappingKey,
        now: u64,
    ) -> Result<(Self, StoreKey)> {
        let handle_id = SecretHandleId::generate();
        let store_key = StoreKey::generate();
        let (envelope, digest) = seal_store_key_for_handle(&store_key, wrapping_key)?;

        let record = PoolEncryptionSecretHandleRecord::new(
            handle_id,
            pool_name,
            digest,
            0,
            now,
            dataset_mount_token,
        );

        Ok((Self { record, envelope }, store_key))
    }

    /// Rotate the sealed pool key and rebind the handle to a remounted dataset.
    ///
    /// The current mount authority supplies the committed token for the new
    /// mount generation. After this returns, the old committed token no longer
    /// authorizes leases for this handle.
    pub fn rotate_key_for_remount(
        &mut self,
        dataset_mount_token: CommittedDatasetMountToken,
        wrapping_key: &PoolWrappingKey,
        now: u64,
    ) -> Result<StoreKey> {
        if !self.record.lifecycle.allows_mount() {
            let assessment = assess_mounted_pool_key_access(
                Some(&self.record),
                None,
                MountedPoolKeyRecoveryEvidence::CurrentMount,
            );
            return Err(EncryptionError::KeyLifecycleAccessRefused {
                state: assessment.state,
                reason: assessment
                    .refusal_reason()
                    .unwrap_or(MountedPoolKeyAccessRefusal::HandleNotActive),
            });
        }

        let store_key = StoreKey::generate();
        let (envelope, digest) = seal_store_key_for_handle(&store_key, wrapping_key)?;
        self.envelope = envelope;
        self.record.sealed_envelope_sha256 = digest;
        self.record.key_generation = self.record.key_generation.saturating_add(1);
        self.record
            .bind_dataset_mount_token(dataset_mount_token, now);

        Ok(store_key)
    }

    /// Issue a short-lived lease for the pool encryption key.
    ///
    /// Unseals the envelope using the wrapping key and returns a
    /// time-bounded [`PoolEncryptionKeyLease`]. The lease duration
    /// is clamped to [`MAX_LEASE_DURATION`].
    ///
    /// Returns an error if the handle is revoked/quarantined/retired,
    /// or if the envelope cannot be unsealed (wrong wrapping key or
    /// corruption).
    pub fn issue_lease(
        &self,
        dataset_mount_token: &CommittedDatasetMountToken,
        wrapping_key: &PoolWrappingKey,
        duration: Duration,
        usage: LeaseUsageClass,
    ) -> Result<PoolEncryptionKeyLease> {
        let assessment = assess_mounted_pool_key_access(
            Some(&self.record),
            Some(dataset_mount_token),
            MountedPoolKeyRecoveryEvidence::CurrentMount,
        );
        if !assessment.allows_lease() {
            return Err(EncryptionError::KeyLifecycleAccessRefused {
                state: assessment.state,
                reason: assessment
                    .refusal_reason()
                    .unwrap_or(MountedPoolKeyAccessRefusal::HandleNotActive),
            });
        }

        let dataset_mount_token =
            self.authorize_committed_mount_token(Some(dataset_mount_token))?;

        let actual_duration = duration.min(MAX_LEASE_DURATION);

        let pool_key = tidefs_local_object_store::encrypt::PoolEncryptionKey::unseal(
            &self.envelope,
            wrapping_key.as_bytes(),
        )
        .ok_or(EncryptionError::DecryptionFailed)?;

        let store_key = StoreKey::from_bytes(pool_key.as_bytes()).map_err(|_| {
            EncryptionError::InvalidKeyLength {
                expected: KEY_LEN,
                got: pool_key.as_bytes().len(),
            }
        })?;

        Ok(PoolEncryptionKeyLease::new(
            self.record.handle_id,
            store_key,
            actual_duration,
            dataset_mount_token.clone(),
            usage,
        ))
    }

    fn authorize_committed_mount_token<'a>(
        &self,
        dataset_mount_token: Option<&'a CommittedDatasetMountToken>,
    ) -> Result<&'a CommittedDatasetMountToken> {
        let token = dataset_mount_token.ok_or(EncryptionError::KeyDerivationRejected)?;

        if self.record.accepts_dataset_mount_token(token) {
            Ok(token)
        } else {
            Err(EncryptionError::KeyDerivationRejected)
        }
    }

    /// Activate the handle, allowing leases and mounts.
    pub fn activate(&mut self, now: u64) {
        self.record.activate(now);
    }

    /// Revoke the handle, blocking all future leases.
    pub fn revoke(&mut self, now: u64) {
        self.record.revoke(now);
    }

    /// Mark the handle as rotating with dual-valid key material.
    pub fn begin_rotation(&mut self, now: u64) {
        self.record.begin_rotation(now);
    }

    /// Quarantine the handle, blocking leases while compromise is investigated.
    pub fn quarantine(&mut self, now: u64) {
        self.record.quarantine(now);
    }

    /// Retire the handle, blocking leases as a terminal lifecycle state.
    pub fn retire(&mut self, now: u64) {
        self.record.retire(now);
    }

    /// The handle ID for operator display/logging.
    pub fn handle_id(&self) -> SecretHandleId {
        self.record.handle_id
    }

    /// Whether this handle allows mount/import.
    pub fn can_mount(&self) -> bool {
        self.record.can_mount()
    }
}

fn seal_store_key_for_handle(
    store_key: &StoreKey,
    wrapping_key: &PoolWrappingKey,
) -> Result<(
    tidefs_local_object_store::encrypt::SealedPoolKeyEnvelope,
    [u8; 32],
)> {
    use sha2::{Digest, Sha256};

    let pool_key =
        tidefs_local_object_store::encrypt::PoolEncryptionKey::from_bytes(store_key.as_bytes())
            .ok_or(EncryptionError::InvalidKeyLength {
                expected: KEY_LEN,
                got: store_key.as_bytes().len(),
            })?;
    let envelope = pool_key.seal(wrapping_key.as_bytes());

    let envelope_bytes = envelope.to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(envelope_bytes);
    let digest: [u8; 32] = hasher.finalize().into();

    Ok((envelope, digest))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_hierarchy::PoolWrappingKey;

    fn dummy_wrapping_key() -> PoolWrappingKey {
        let salt = PoolWrappingKey::generate_salt();
        PoolWrappingKey::derive("test passphrase for secret handle", &salt).unwrap()
    }

    fn now() -> u64 {
        1700000000u64
    }

    fn dummy_mount_identity() -> DatasetMountIdentity {
        DatasetMountIdentity::new("pool/ds1".into(), 1)
    }

    fn dummy_mount_authority_key() -> DatasetMountAuthorityKey {
        DatasetMountAuthorityKey::from_bytes(&[0x5a; DATASET_MOUNT_AUTHORITY_KEY_LEN]).unwrap()
    }

    fn mount_token(identity: DatasetMountIdentity) -> CommittedDatasetMountToken {
        CommittedDatasetMountToken::mint(identity, &dummy_mount_authority_key())
    }

    fn dummy_mount_token() -> CommittedDatasetMountToken {
        mount_token(dummy_mount_identity())
    }

    #[test]
    fn mint_handle_and_issue_lease_roundtrip() {
        let wk = dummy_wrapping_key();
        let mount_id = dummy_mount_identity();
        let token = mount_token(mount_id.clone());
        let (mut handle, original_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();

        assert_eq!(
            handle.record.lifecycle,
            SecretHandleLifecycle::SealedInactive
        );
        assert!(!handle.can_mount());

        handle.activate(now());
        assert!(handle.can_mount());

        let lease = handle
            .issue_lease(
                &token,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease.is_valid());
        assert_eq!(lease.key_bytes().unwrap(), original_key.as_bytes());
    }

    #[test]
    fn revoked_handle_blocks_lease() {
        let wk = dummy_wrapping_key();
        let token = dummy_mount_token();
        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();
        handle.activate(now());
        handle.revoke(now());

        assert!(handle.record.lifecycle.blocks_lease());
        let result = handle.issue_lease(
            &token,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(matches!(
            result,
            Err(EncryptionError::KeyLifecycleAccessRefused {
                state: MountedPoolKeyAccessState::Revoked,
                reason: MountedPoolKeyAccessRefusal::HandleRevoked,
            })
        ));
    }

    #[test]
    fn quarantined_and_retired_handles_block_lease_with_explicit_refusal() {
        let wk = dummy_wrapping_key();
        let token = dummy_mount_token();

        let (mut quarantined, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();
        quarantined.activate(now());
        quarantined.quarantine(now() + 1);
        let result = quarantined.issue_lease(
            &token,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(matches!(
            result,
            Err(EncryptionError::KeyLifecycleAccessRefused {
                state: MountedPoolKeyAccessState::Quarantined,
                reason: MountedPoolKeyAccessRefusal::HandleQuarantined,
            })
        ));

        let (mut retired, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();
        retired.activate(now());
        retired.retire(now() + 1);
        let result = retired.issue_lease(
            &token,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(matches!(
            result,
            Err(EncryptionError::KeyLifecycleAccessRefused {
                state: MountedPoolKeyAccessState::Retired,
                reason: MountedPoolKeyAccessRefusal::HandleRetired,
            })
        ));
    }

    #[test]
    fn active_rotating_missing_stale_and_recovery_states_are_reported() {
        let wk = dummy_wrapping_key();
        let token = dummy_mount_token();
        let stale_token = mount_token(DatasetMountIdentity::new("pool/ds1".into(), 2));
        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();

        let missing = assess_mounted_pool_key_access(
            None,
            Some(&token),
            MountedPoolKeyRecoveryEvidence::CurrentMount,
        );
        assert_eq!(missing.state, MountedPoolKeyAccessState::Missing);
        assert_eq!(
            missing.refusal_reason(),
            Some(MountedPoolKeyAccessRefusal::MissingHandleRecord)
        );

        handle.activate(now());
        let active = assess_mounted_pool_key_access(
            Some(&handle.record),
            Some(&token),
            MountedPoolKeyRecoveryEvidence::CurrentMount,
        );
        assert_eq!(active.state, MountedPoolKeyAccessState::Active);
        assert!(active.allows_lease());

        handle.begin_rotation(now() + 10);
        let rotating = assess_mounted_pool_key_access(
            Some(&handle.record),
            Some(&token),
            MountedPoolKeyRecoveryEvidence::CurrentMount,
        );
        assert_eq!(rotating.state, MountedPoolKeyAccessState::Rotating);
        assert!(rotating.allows_lease());

        let missing_token = assess_mounted_pool_key_access(
            Some(&handle.record),
            None,
            MountedPoolKeyRecoveryEvidence::CurrentMount,
        );
        assert_eq!(missing_token.state, MountedPoolKeyAccessState::Missing);
        assert_eq!(
            missing_token.refusal_reason(),
            Some(MountedPoolKeyAccessRefusal::MissingCommittedMountToken)
        );

        let stale = assess_mounted_pool_key_access(
            Some(&handle.record),
            Some(&stale_token),
            MountedPoolKeyRecoveryEvidence::CurrentMount,
        );
        assert_eq!(stale.state, MountedPoolKeyAccessState::Stale);
        assert_eq!(
            stale.refusal_reason(),
            Some(MountedPoolKeyAccessRefusal::StaleCommittedMountToken)
        );

        let replay_missing = assess_mounted_pool_key_access(
            Some(&handle.record),
            Some(&token),
            MountedPoolKeyRecoveryEvidence::ReplayMissing,
        );
        assert_eq!(
            replay_missing.state,
            MountedPoolKeyAccessState::RecoveryAfterCrash
        );
        assert_eq!(
            replay_missing.refusal_reason(),
            Some(MountedPoolKeyAccessRefusal::RecoveryReplayMissing)
        );

        let replayed = assess_mounted_pool_key_access(
            Some(&handle.record),
            Some(&token),
            MountedPoolKeyRecoveryEvidence::ReplayedAfterCrash,
        );
        assert_eq!(
            replayed.state,
            MountedPoolKeyAccessState::RecoveryAfterCrash
        );
        assert!(replayed.allows_lease());
    }

    #[test]
    fn cryptographic_erase_refuses_without_full_transform_and_media_proof() {
        let full = CryptographicEraseEvidence::encrypted_with_full_proof();
        let active = assess_cryptographic_erase_boundary(MountedPoolKeyAccessState::Active, full);
        assert_eq!(
            active.refusal,
            Some(CryptographicEraseRefusal::KeyLifecycleNotDestroyedOrRevoked)
        );
        assert!(!active.can_present_as_secure_erase());

        let missing_metadata = assess_cryptographic_erase_boundary(
            MountedPoolKeyAccessState::Revoked,
            CryptographicEraseEvidence {
                transform_metadata_persisted: false,
                ..full
            },
        );
        assert_eq!(
            missing_metadata.refusal,
            Some(CryptographicEraseRefusal::MissingTransformMetadata)
        );

        let payload_refusals = [
            (
                TransformPayloadClass::Plaintext,
                CryptographicEraseRefusal::PayloadPlaintext,
            ),
            (
                TransformPayloadClass::CompressedOnly,
                CryptographicEraseRefusal::PayloadCompressedOnly,
            ),
            (
                TransformPayloadClass::Unencrypted,
                CryptographicEraseRefusal::PayloadUnencrypted,
            ),
            (
                TransformPayloadClass::PartiallyTransformed,
                CryptographicEraseRefusal::PayloadPartiallyTransformed,
            ),
            (
                TransformPayloadClass::RawStoreBypassed,
                CryptographicEraseRefusal::PayloadRawStoreBypassed,
            ),
            (
                TransformPayloadClass::PreviouslyExposedMedia,
                CryptographicEraseRefusal::PayloadPreviouslyExposed,
            ),
        ];

        for (payload_class, expected) in payload_refusals {
            let result = assess_cryptographic_erase_boundary(
                MountedPoolKeyAccessState::Revoked,
                CryptographicEraseEvidence {
                    payload_class,
                    ..full
                },
            );
            assert_eq!(result.refusal, Some(expected));
            assert!(!result.can_present_as_secure_erase());
        }
    }

    #[test]
    fn cryptographic_erase_prerequisites_do_not_widen_secure_erase_claims() {
        let result = assess_cryptographic_erase_boundary(
            MountedPoolKeyAccessState::Retired,
            CryptographicEraseEvidence::encrypted_with_full_proof(),
        );

        assert!(result.eligible_for_claim_review());
        assert!(!result.can_present_as_secure_erase());
        assert_eq!(result.non_claim, CRYPTOGRAPHIC_ERASE_NON_CLAIM);
    }

    #[test]
    fn wrong_wrapping_key_fails_lease() {
        let wk1 = dummy_wrapping_key();
        let mount_id = dummy_mount_identity();
        let token = mount_token(mount_id);
        let salt = PoolWrappingKey::generate_salt();
        let wk2 = PoolWrappingKey::derive("different passphrase", &salt).unwrap();

        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk1, now())
                .unwrap();
        handle.activate(now());

        let result = handle.issue_lease(
            &token,
            &wk2,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());
    }

    #[test]
    fn lease_clamped_to_max_duration() {
        let wk = dummy_wrapping_key();
        let token = dummy_mount_token();
        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();
        handle.activate(now());

        let lease = handle
            .issue_lease(
                &token,
                &wk,
                Duration::from_secs(7200),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease.remaining() <= MAX_LEASE_DURATION);
    }

    #[test]
    fn lease_into_key_consumes() {
        let wk = dummy_wrapping_key();
        let token = dummy_mount_token();
        let (mut handle, original_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();
        handle.activate(now());

        let lease = handle
            .issue_lease(
                &token,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        let consumed = lease.into_key().unwrap();
        assert_eq!(consumed.as_bytes(), original_key.as_bytes());
    }

    #[test]
    fn handle_id_hex_roundtrip() {
        let id = SecretHandleId::generate();
        let hex = id.hex();
        assert_eq!(hex.len(), 32);

        let parsed: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let restored = SecretHandleId::from_bytes(&parsed).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn handle_ids_are_unique() {
        let id1 = SecretHandleId::generate();
        let id2 = SecretHandleId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn lifecycle_transitions_track_state_changed_at() {
        let wk = dummy_wrapping_key();
        let (mut handle, _) = PoolEncryptionSecretHandle::mint(
            "test-pool".into(),
            dummy_mount_token(),
            &wk,
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(handle.record.state_changed_at, 1_700_000_000);

        handle.activate(1_700_000_100);
        assert_eq!(handle.record.state_changed_at, 1_700_000_100);

        handle.revoke(1_700_000_200);
        assert_eq!(handle.record.state_changed_at, 1_700_000_200);
    }

    #[test]
    fn envelope_integrity_digest_is_stable() {
        let wk = dummy_wrapping_key();
        let (handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), dummy_mount_token(), &wk, now())
                .unwrap();

        // Recompute and verify
        use sha2::{Digest, Sha256};
        let envelope_bytes = handle.envelope.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(envelope_bytes);
        let digest: [u8; 32] = hasher.finalize().into();

        assert_eq!(handle.record.sealed_envelope_sha256, digest);
    }

    // ── Mount identity binding tests ───────────────────────────────────

    #[test]
    fn mount_identity_bound_to_correct_identity() {
        let wk = dummy_wrapping_key();
        let mount_id = DatasetMountIdentity::new("pool/ds1".into(), 5);
        let token = mount_token(mount_id.clone());

        let (mut handle, original_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();

        assert_eq!(&handle.record.dataset_mount_identity, &mount_id);

        handle.activate(now());

        // Lease with correct mount identity succeeds
        let lease = handle
            .issue_lease(
                &token,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease.is_valid());
        assert_eq!(lease.key_bytes().unwrap(), original_key.as_bytes());
        assert_eq!(lease.dataset_mount_identity(), &mount_id);
        assert_eq!(lease.committed_dataset_mount_token(), &token);
    }

    #[test]
    fn committed_mount_token_rejects_missing_evidence() {
        let wk = dummy_wrapping_key();
        let token = dummy_mount_token();

        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token, &wk, now()).unwrap();
        handle.activate(now());

        let result = handle.authorize_committed_mount_token(None);
        assert!(result.is_err());
    }

    #[test]
    fn committed_mount_token_rejects_tampered_commitment() {
        let wk = dummy_wrapping_key();
        let mount_id = DatasetMountIdentity::new("pool/ds1".into(), 5);
        let token = mount_token(mount_id);
        let mut forged = token.clone();
        forged.commitment[0] ^= 0x80;

        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token, &wk, now()).unwrap();
        handle.activate(now());

        let result = handle.issue_lease(
            &forged,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());
    }

    #[test]
    fn committed_mount_token_rejected_with_wrong_identity() {
        let wk = dummy_wrapping_key();
        let mount_id = DatasetMountIdentity::new("pool/ds1".into(), 5);
        let token = mount_token(mount_id);
        let wrong_token = mount_token(DatasetMountIdentity::new("pool/ds1".into(), 6));
        let foreign_token = mount_token(DatasetMountIdentity::new("pool/ds2".into(), 5));

        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token, &wk, now()).unwrap();
        handle.activate(now());

        let result = handle.issue_lease(
            &wrong_token,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());

        let result = handle.issue_lease(
            &foreign_token,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());
    }

    #[test]
    fn encryption_roundtrip_with_mount_identity_gate() {
        // Full encryption round-trip: mount-identity-bound key handle
        // drives object encryption and decryption through the lease.
        let wk = dummy_wrapping_key();
        let mount_id = DatasetMountIdentity::new("pool/ds1".into(), 1);
        let token = mount_token(mount_id);

        let (mut handle, _store_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), token.clone(), &wk, now())
                .unwrap();
        handle.activate(now());

        let lease = handle
            .issue_lease(
                &token,
                &wk,
                Duration::from_secs(300),
                LeaseUsageClass::DatasetAccess,
            )
            .unwrap();

        // Use the lease to derive object keys and encrypt/decrypt
        let store_key = lease.into_key().unwrap();
        let deriver = crate::ObjectKeyDeriver::new(store_key);

        let obj_key_a = deriver.derive("tidefs-object-encryption-v1", b"obj-a");
        let obj_key_b = deriver.derive("tidefs-object-encryption-v1", b"obj-b");

        // Different objects get different keys
        assert_ne!(obj_key_a.as_bytes(), obj_key_b.as_bytes());

        // Same object with same master produces same key (deterministic)
        let obj_key_a2 = deriver.derive("tidefs-object-encryption-v1", b"obj-a");
        assert_eq!(obj_key_a.as_bytes(), obj_key_a2.as_bytes());

        // Encrypt/decrypt round-trip using extent helpers
        use crate::key_hierarchy::{decrypt_extent, encrypt_extent, DatasetDEK, ExtentNonce};
        let dek = DatasetDEK::from_bytes(obj_key_a.as_bytes());
        let nonce = ExtentNonce::derive(1, 0, &dek);
        let plaintext = b"mount-identity-gated encryption round-trip data";

        let encrypted = encrypt_extent(plaintext, &dek, &nonce).unwrap();
        let decrypted = decrypt_extent(&encrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn key_rotation_across_remount() {
        // After a remount, the mount generation increments.
        // The existing handle is rotated onto the new committed token.
        let wk = dummy_wrapping_key();
        let old_mount_id = DatasetMountIdentity::new("pool/ds1".into(), 3);
        let new_mount_id = DatasetMountIdentity::new("pool/ds1".into(), 4);
        let old_token = mount_token(old_mount_id);
        let new_token = mount_token(new_mount_id);

        // First mount: mint handle with generation 3
        let (mut handle_old, key_old) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), old_token.clone(), &wk, now())
                .unwrap();
        handle_old.activate(now());

        let lease_old = handle_old
            .issue_lease(
                &old_token,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease_old.is_valid());

        let key_new = handle_old
            .rotate_key_for_remount(new_token.clone(), &wk, now() + 100)
            .unwrap();

        // The rotated handle rejects the old stale committed token.
        let result = handle_old.issue_lease(
            &old_token,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());

        let lease_new = handle_old
            .issue_lease(
                &new_token,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease_new.is_valid());

        // Keys differ across remount (new DEK generated)
        assert_ne!(key_old.as_bytes(), key_new.as_bytes());

        assert_eq!(
            &handle_old.record.dataset_mount_identity,
            new_token.dataset_mount_identity()
        );
        assert_eq!(handle_old.record.key_generation, 1);
    }

    #[test]
    fn mount_identity_display_format() {
        let id = DatasetMountIdentity::new("pool/tank".into(), 42);
        assert_eq!(format!("{id}"), "pool/tank@gen42");
    }

    #[test]
    fn mount_identity_matches_same_identity() {
        let a = DatasetMountIdentity::new("pool/ds".into(), 1);
        let b = DatasetMountIdentity::new("pool/ds".into(), 1);
        assert!(a.matches(&b));
        assert!(b.matches(&a));
    }

    #[test]
    fn mount_identity_rejects_different_generation() {
        let a = DatasetMountIdentity::new("pool/ds".into(), 1);
        let b = DatasetMountIdentity::new("pool/ds".into(), 2);
        assert!(!a.matches(&b));
    }

    #[test]
    fn mount_identity_rejects_different_dataset() {
        let a = DatasetMountIdentity::new("pool/ds1".into(), 1);
        let b = DatasetMountIdentity::new("pool/ds2".into(), 1);
        assert!(!a.matches(&b));
    }
}
