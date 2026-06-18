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

/// A committed dataset mount identity token.
///
/// Binds encryption key access to a specific dataset mount instance.
/// When a dataset is unmounted and remounted, the mount generation
/// increments, invalidating any key handles bound to the previous
/// mount. This prevents decryption under a stale or foreign dataset
/// identity.
///
/// The token is the pair `(dataset_id, mount_generation)` where
/// `mount_generation` is a monotonically increasing counter assigned
/// at each mount of the dataset. A key handle bound to
/// `DatasetMountIdentity { dataset_id: "pool/ds1", mount_generation: 5 }`
/// cannot be used after a remount that produces generation 6.
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
    /// Lease issuance requires a matching mount identity.
    pub dataset_mount_identity: DatasetMountIdentity,
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
        dataset_mount_identity: DatasetMountIdentity,
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
            dataset_mount_identity,
        }
    }

    /// Activate the handle for mount use (leases become issuable).
    pub fn activate(&mut self, now: u64) {
        self.lifecycle = SecretHandleLifecycle::Active;
        self.state_changed_at = now;
    }

    /// Revoke the handle, blocking all future leases.
    pub fn revoke(&mut self, now: u64) {
        self.lifecycle = SecretHandleLifecycle::Revoked;
        self.state_changed_at = now;
    }

    /// Whether a lease can be issued.
    pub fn can_issue_lease(&self) -> bool {
        !self.lifecycle.blocks_lease()
    }

    /// Whether this handle can be used for mount/import.
    pub fn can_mount(&self) -> bool {
        self.lifecycle.allows_mount()
    }
}

// ── Key lease ─────────────────────────────────────────────────────────────

/// A short-lived lease granting plaintext access to a pool encryption key.
///
/// Wraps a [`StoreKey`] valid only until expiry. The key is zeroized on
/// drop. Per P9-04 §5.1: no long-lived secret as ambient capability;
/// runtime access flows through a short-lived lease.
pub struct PoolEncryptionKeyLease {
    handle_id: SecretHandleId,
    /// The dataset mount identity bound to this lease.
    dataset_mount_identity: DatasetMountIdentity,
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
        dataset_mount_identity: DatasetMountIdentity,
        usage: LeaseUsageClass,
    ) -> Self {
        Self {
            handle_id,
            key,
            expires_at: Instant::now() + duration,
            usage,
            dataset_mount_identity,
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
        &self.dataset_mount_identity
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
        dataset_mount_identity: DatasetMountIdentity,
        wrapping_key: &PoolWrappingKey,
        now: u64,
    ) -> Result<(Self, StoreKey)> {
        use sha2::{Digest, Sha256};

        let handle_id = SecretHandleId::generate();
        let store_key = StoreKey::generate();

        // Bridge StoreKey -> PoolEncryptionKey -> SealedPoolKeyEnvelope
        let pool_key =
            tidefs_local_object_store::encrypt::PoolEncryptionKey::from_bytes(store_key.as_bytes())
                .ok_or(EncryptionError::InvalidKeyLength {
                    expected: KEY_LEN,
                    got: store_key.as_bytes().len(),
                })?;
        let envelope = pool_key.seal(wrapping_key.as_bytes());

        // Compute SHA-256 digest of the envelope for integrity tracking
        let envelope_bytes = envelope.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(envelope_bytes);
        let digest: [u8; 32] = hasher.finalize().into();

        let record = PoolEncryptionSecretHandleRecord::new(
            handle_id,
            pool_name,
            digest,
            0,
            now,
            dataset_mount_identity,
        );

        Ok((Self { record, envelope }, store_key))
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
        dataset_mount_identity: &DatasetMountIdentity,
        wrapping_key: &PoolWrappingKey,
        duration: Duration,
        usage: LeaseUsageClass,
    ) -> Result<PoolEncryptionKeyLease> {
        if self.record.lifecycle.blocks_lease() {
            return Err(EncryptionError::KeyDerivationRejected);
        }

        // Gate on dataset mount identity. Every handle is bound to the
        // committed dataset mount that minted it, and lease issuance requires
        // the caller to present that exact identity.
        if !self
            .record
            .dataset_mount_identity
            .matches(dataset_mount_identity)
        {
            return Err(EncryptionError::KeyDerivationRejected);
        }

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
            self.record.dataset_mount_identity.clone(),
            usage,
        ))
    }

    /// Activate the handle, allowing leases and mounts.
    pub fn activate(&mut self, now: u64) {
        self.record.activate(now);
    }

    /// Revoke the handle, blocking all future leases.
    pub fn revoke(&mut self, now: u64) {
        self.record.revoke(now);
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

    #[test]
    fn mint_handle_and_issue_lease_roundtrip() {
        let wk = dummy_wrapping_key();
        let mount_id = dummy_mount_identity();
        let (mut handle, original_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id.clone(), &wk, now())
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
                &mount_id,
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
        let mount_id = dummy_mount_identity();
        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id.clone(), &wk, now())
                .unwrap();
        handle.activate(now());
        handle.revoke(now());

        assert!(handle.record.lifecycle.blocks_lease());
        let result = handle.issue_lease(
            &mount_id,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_wrapping_key_fails_lease() {
        let wk1 = dummy_wrapping_key();
        let mount_id = dummy_mount_identity();
        let salt = PoolWrappingKey::generate_salt();
        let wk2 = PoolWrappingKey::derive("different passphrase", &salt).unwrap();

        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id.clone(), &wk1, now())
                .unwrap();
        handle.activate(now());

        let result = handle.issue_lease(
            &mount_id,
            &wk2,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());
    }

    #[test]
    fn lease_clamped_to_max_duration() {
        let wk = dummy_wrapping_key();
        let mount_id = dummy_mount_identity();
        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id.clone(), &wk, now())
                .unwrap();
        handle.activate(now());

        let lease = handle
            .issue_lease(
                &mount_id,
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
        let mount_id = dummy_mount_identity();
        let (mut handle, original_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id.clone(), &wk, now())
                .unwrap();
        handle.activate(now());

        let lease = handle
            .issue_lease(
                &mount_id,
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
            dummy_mount_identity(),
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
        let (handle, _) = PoolEncryptionSecretHandle::mint(
            "test-pool".into(),
            dummy_mount_identity(),
            &wk,
            now(),
        )
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

        let (mut handle, original_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id.clone(), &wk, now())
                .unwrap();

        assert_eq!(&handle.record.dataset_mount_identity, &mount_id);

        handle.activate(now());

        // Lease with correct mount identity succeeds
        let lease = handle
            .issue_lease(
                &mount_id,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease.is_valid());
        assert_eq!(lease.key_bytes().unwrap(), original_key.as_bytes());
        assert_eq!(lease.dataset_mount_identity(), &mount_id);
    }

    #[test]
    fn mount_identity_rejected_with_wrong_identity() {
        let wk = dummy_wrapping_key();
        let mount_id = DatasetMountIdentity::new("pool/ds1".into(), 5);
        let wrong_id = DatasetMountIdentity::new("pool/ds1".into(), 6);
        let foreign_id = DatasetMountIdentity::new("pool/ds2".into(), 5);

        let (mut handle, _) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id, &wk, now()).unwrap();
        handle.activate(now());

        // Wrong mount generation
        let result = handle.issue_lease(
            &wrong_id,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());

        // Foreign dataset
        let result = handle.issue_lease(
            &foreign_id,
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

        let (mut handle, _store_key) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), mount_id.clone(), &wk, now())
                .unwrap();
        handle.activate(now());

        let lease = handle
            .issue_lease(
                &mount_id,
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
        // The old mount identity should be rejected; a new handle
        // with the new mount identity must be minted.
        let wk = dummy_wrapping_key();
        let old_mount_id = DatasetMountIdentity::new("pool/ds1".into(), 3);
        let new_mount_id = DatasetMountIdentity::new("pool/ds1".into(), 4);

        // First mount: mint handle with generation 3
        let (mut handle_old, key_old) =
            PoolEncryptionSecretHandle::mint("test-pool".into(), old_mount_id.clone(), &wk, now())
                .unwrap();
        handle_old.activate(now());

        let lease_old = handle_old
            .issue_lease(
                &old_mount_id,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease_old.is_valid());

        // Remount: mount generation advances to 4
        // The old handle must reject the new mount identity
        let result = handle_old.issue_lease(
            &new_mount_id,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());

        // Old handle still works with old mount identity (until revoked)
        let lease_old_again = handle_old
            .issue_lease(
                &old_mount_id,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease_old_again.is_valid());

        // New mount: mint a fresh handle with generation 4
        let (mut handle_new, key_new) = PoolEncryptionSecretHandle::mint(
            "test-pool".into(),
            new_mount_id.clone(),
            &wk,
            now() + 100,
        )
        .unwrap();
        handle_new.activate(now() + 100);

        let lease_new = handle_new
            .issue_lease(
                &new_mount_id,
                &wk,
                Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        assert!(lease_new.is_valid());

        // Keys differ across remount (new DEK generated)
        assert_ne!(key_old.as_bytes(), key_new.as_bytes());

        // New handle rejects the old (stale) mount identity
        let result = handle_new.issue_lease(
            &old_mount_id,
            &wk,
            Duration::from_secs(60),
            LeaseUsageClass::PoolMount,
        );
        assert!(result.is_err());
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
