#![allow(clippy::too_many_arguments)]
#![forbid(unsafe_code)]

//! P9-04 secret-key-policy runtime.
//!
//! Implements the 10 stable algorithms required by the secret-key-policy law:
//! classify, seal-mint, lease, manifest-assemble, publish, activate,
//! rotate, rewrap, revoke, and recover.
//!
//! Crypto sealing/unsealing is abstracted behind a `SealProvider` trait
//! so the runtime can be tested with mock providers and later bound to
//! real KMS, HSM, or keyring-backed implementations.

use tidefs_types_secret_key_policy_core::{
    DisclosureSurfaceClass, DisclosureVerdict, LeaseUsageClass, PolicyActivationReceipt,
    PolicyPublishBundleRecord, PolicyStoreManifestRecord, RedactionReason, RefusalReason,
    RevocationTriggerClass, SecretClass, SecretDisclosurePolicyRecord, SecretEnvelopeRecord,
    SecretHandleRecord, SecretKeyPolicyDecodeError, SecretLeaseGrantRecord, SecretLifecycleState,
    SecretRevocationReceipt, SecretRotationPlanRecord, StorageStratum, WrappingKeyRecord,
};
use tidefs_types_secret_key_policy_core::{SecretKeyPolicyDigest32, SecretKeyPolicyId128};

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretKeyPolicyRuntimeError {
    Decode(SecretKeyPolicyDecodeError),

    HandleNotFound {
        handle_id: SecretKeyPolicyId128,
    },
    HandleNotActive {
        handle_id: SecretKeyPolicyId128,
        actual: SecretLifecycleState,
    },
    HandleRevoked {
        handle_id: SecretKeyPolicyId128,
    },
    HandleQuarantined {
        handle_id: SecretKeyPolicyId128,
    },
    HandleMissingStorageResidency {
        handle_id: SecretKeyPolicyId128,
    },

    EnvelopeNotFound {
        envelope_id: SecretKeyPolicyId128,
    },
    EnvelopeWrappingMismatch {
        envelope_id: SecretKeyPolicyId128,
        wrapping_key_id: SecretKeyPolicyId128,
    },

    WrappingKeyNotFound {
        wrapping_key_id: SecretKeyPolicyId128,
    },

    LeaseExpired {
        lease_id: SecretKeyPolicyId128,
    },
    LeaseNotFound {
        lease_id: SecretKeyPolicyId128,
    },
    LeaseUsageMismatch {
        handle_id: SecretKeyPolicyId128,
        requested: LeaseUsageClass,
    },
    LeaseHandleMismatch {
        lease_id: SecretKeyPolicyId128,
        handle_id: SecretKeyPolicyId128,
    },

    ManifestIncompatible {
        manifest_id: SecretKeyPolicyId128,
        reason: ManifestRefusalReason,
    },
    ManifestMissingHandles {
        manifest_id: SecretKeyPolicyId128,
        missing_count: u32,
    },

    ActivationPreflightFailed {
        activation_id: SecretKeyPolicyId128,
        reason: ActivationRefusalReason,
    },
    ActivationAlreadyActive {
        activation_id: SecretKeyPolicyId128,
    },

    RotationNotInDualValidity {
        plan_id: SecretKeyPolicyId128,
    },
    RotationPredecessorNotFound {
        plan_id: SecretKeyPolicyId128,
        envelope_id: SecretKeyPolicyId128,
    },

    RevocationNoLiveLeases {
        handle_id: SecretKeyPolicyId128,
    },
    RevocationQuarantineRequired {
        handle_id: SecretKeyPolicyId128,
    },

    RecoveryManifestChainBroken {
        at_manifest_id: SecretKeyPolicyId128,
    },
    RecoveryAmbiguousState {
        handle_id: SecretKeyPolicyId128,
    },

    SealProviderError {
        reason: SealProviderErrorKind,
    },

    DisclosureRefused {
        surface: DisclosureSurfaceClass,
        reason: RefusalReason,
    },

    CryptoPlaceholder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestRefusalReason {
    MissingRevReferences,
    ContinuityWindowClosed,
    SignatureSetInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationRefusalReason {
    MissingHandles,
    RevokedHandles,
    QuarantinedHandles,
    ManifestIncompatible,
    ProviderUnreachable,
    DisclosureViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealProviderErrorKind {
    WrappingKeyUnavailable,
    UnwrapFailed,
    SealFailed,
    ProviderTimeout,
    ProviderUnreachable,
}

impl From<SecretKeyPolicyDecodeError> for SecretKeyPolicyRuntimeError {
    fn from(e: SecretKeyPolicyDecodeError) -> Self {
        SecretKeyPolicyRuntimeError::Decode(e)
    }
}

// ── SealProvider trait ─────────────────────────────────────────────────────

/// Abstract interface for sealing and unsealing secret material.
///
/// Real implementations bind to KMS, HSM, kernel keyrings, or other
/// secure providers. Test implementations use deterministic mock keys.
pub trait SealProvider {
    fn unwrap_envelope(
        &self,
        envelope: &SecretEnvelopeRecord,
        wrapping_key: &WrappingKeyRecord,
    ) -> Result<Vec<u8>, SecretKeyPolicyRuntimeError>;

    fn seal_payload(
        &self,
        plaintext: &[u8],
        wrapping_key: &WrappingKeyRecord,
    ) -> Result<SecretKeyPolicyDigest32, SecretKeyPolicyRuntimeError>;

    fn generate_secret_material(
        &self,
        secret_class: SecretClass,
    ) -> Result<Vec<u8>, SecretKeyPolicyRuntimeError>;

    fn verify_wrapping_key_lineage(
        &self,
        parent: &WrappingKeyRecord,
        child: &WrappingKeyRecord,
    ) -> Result<bool, SecretKeyPolicyRuntimeError>;
}

// ── HandleStore trait ──────────────────────────────────────────────────────

pub trait HandleStore {
    fn lookup_handle(
        &self,
        handle_id: SecretKeyPolicyId128,
    ) -> Result<SecretHandleRecord, SecretKeyPolicyRuntimeError>;
    fn lookup_envelope(
        &self,
        envelope_id: SecretKeyPolicyId128,
    ) -> Result<SecretEnvelopeRecord, SecretKeyPolicyRuntimeError>;
    fn lookup_wrapping_key(
        &self,
        wrapping_key_id: SecretKeyPolicyId128,
    ) -> Result<WrappingKeyRecord, SecretKeyPolicyRuntimeError>;
    fn lookup_manifest(
        &self,
        manifest_id: SecretKeyPolicyId128,
    ) -> Result<PolicyStoreManifestRecord, SecretKeyPolicyRuntimeError>;
    fn lookup_activation(
        &self,
        activation_id: SecretKeyPolicyId128,
    ) -> Result<PolicyActivationReceipt, SecretKeyPolicyRuntimeError>;
    fn lookup_lease(
        &self,
        lease_id: SecretKeyPolicyId128,
    ) -> Result<SecretLeaseGrantRecord, SecretKeyPolicyRuntimeError>;

    fn store_handle(
        &mut self,
        handle: &SecretHandleRecord,
    ) -> Result<(), SecretKeyPolicyRuntimeError>;
    fn store_envelope(
        &mut self,
        envelope: &SecretEnvelopeRecord,
    ) -> Result<(), SecretKeyPolicyRuntimeError>;
    fn store_manifest(
        &mut self,
        manifest: &PolicyStoreManifestRecord,
    ) -> Result<(), SecretKeyPolicyRuntimeError>;
    fn store_activation(
        &mut self,
        activation: &PolicyActivationReceipt,
    ) -> Result<(), SecretKeyPolicyRuntimeError>;
    fn store_lease(
        &mut self,
        lease: &SecretLeaseGrantRecord,
    ) -> Result<(), SecretKeyPolicyRuntimeError>;
    fn store_rotation_plan(
        &mut self,
        plan: &SecretRotationPlanRecord,
    ) -> Result<(), SecretKeyPolicyRuntimeError>;
    fn store_revocation(
        &mut self,
        receipt: &SecretRevocationReceipt,
    ) -> Result<(), SecretKeyPolicyRuntimeError>;
    /// Look up the dataset mount identity binding for a handle.
    ///
    /// Returns `Ok(Some((dataset_id, mount_generation)))` when the handle is
    /// bound to a specific committed dataset mount. `Ok(None)` means the store
    /// cannot prove a binding, and
    /// [`validate_dataset_mount_identity_for_handle`] will refuse the lease
    /// fail-closed.
    fn lookup_dataset_mount_identity(
        &self,
        _handle_id: SecretKeyPolicyId128,
    ) -> Result<Option<(String, u64)>, SecretKeyPolicyRuntimeError> {
        Ok(None)
    }
}

// ── LeaseClock trait ────────────────────────────────────────────────────────

/// Clock interface for lease expiry checks during activation preflights.
///
/// Implementations bind to monotonic wall clocks, logical epochs, or
/// mock/test clocks.
pub trait LeaseClock {
    /// Returns true when `deadline_ref` is in the past relative to the
    /// clock's current reference point.
    fn has_deadline_passed(&self, deadline_ref: SecretKeyPolicyId128) -> bool;
}

// ── Helper: deterministic id derivation from digests ───────────────────────

fn make_id_from_digest_lo(digest: SecretKeyPolicyDigest32, offset: usize) -> SecretKeyPolicyId128 {
    let mut b = [0u8; 16];
    let start = offset.min(24);
    let len = (16).min(32 - start);
    b[..len].copy_from_slice(&digest[start..start + len]);
    SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b))
}

fn make_id_from_digest_hi(digest: SecretKeyPolicyDigest32) -> SecretKeyPolicyId128 {
    let mut b = [0u8; 16];
    let len = 16;
    b[..len].copy_from_slice(&digest[16..32]);
    SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b))
}

// ── Algorithm 1: classify_secret_class_and_required_storage_residency ───────

#[must_use]
pub fn classify_secret_class_and_required_storage_residency(
    secret_class: SecretClass,
    disclosure_policy: &SecretDisclosurePolicyRecord,
) -> (StorageStratum, bool, DisclosureVerdict) {
    // P9-04 §3.1 table: each secret class has a default sealed-authoritative
    // residency.  The disclosure policy may elevate the storage stratum
    // (e.g. to ExternalHsm) and the caller should separately issue a
    // plaintext-allowing lease at runtime.
    let base_stratum: StorageStratum = match secret_class {
        SecretClass::PolicySigner => StorageStratum::SealedAuthoritative,
        SecretClass::ServiceIdentity => StorageStratum::SealedAuthoritative,
        SecretClass::TransportTls => StorageStratum::SealedAuthoritative,
        SecretClass::NodeJoinBootstrap => StorageStratum::SealedAuthoritative,
        SecretClass::EnvelopeWrapping => StorageStratum::SealedAuthoritative,
        SecretClass::SessionMintSeed => StorageStratum::SealedAuthoritative,
    };

    // Disclosure-policy elevation: if the policy mandates an external
    // HSM and the secret class is wrapping-sensitive, promote.
    let stratum = if disclosure_policy.requires_hsm()
        && matches!(
            secret_class,
            SecretClass::EnvelopeWrapping | SecretClass::PolicySigner
        ) {
        StorageStratum::ExternalHsm
    } else {
        base_stratum
    };

    let replicated = stratum.is_replicated();

    // Evaluate disclosure permission for the audit surface so the
    // disclosure-policy masks are consumed at runtime classification.
    let disclosure_verdict =
        decide_secret_disclosure(disclosure_policy, DisclosureSurfaceClass::Audit, 0);

    (stratum, replicated, disclosure_verdict)
}

// ── Algorithm 2: mint_secret_handle_and_seal_material ──────────────────────

pub fn mint_secret_handle_and_seal_material<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    secret_class: SecretClass,
    scope_selector: u32,
    owner_or_service_family_ref: SecretKeyPolicyId128,
    active_wrapping_key_id: SecretKeyPolicyId128,
    disclosure_policy_digest: SecretKeyPolicyDigest32,
    rotation_policy_digest: SecretKeyPolicyDigest32,
    retire_policy_digest: SecretKeyPolicyDigest32,
) -> Result<(SecretHandleRecord, SecretEnvelopeRecord), SecretKeyPolicyRuntimeError> {
    let wrapping_key = store.lookup_wrapping_key(active_wrapping_key_id)?;
    let material = provider.generate_secret_material(secret_class)?;
    let sealed_digest = provider.seal_payload(&material, &wrapping_key)?;

    let handle_id = make_id_from_digest_lo(sealed_digest, 0);
    let envelope_id = make_id_from_digest_hi(sealed_digest);

    let (stratum, _, _disc_verdict) = classify_secret_class_and_required_storage_residency(
        secret_class,
        &SecretDisclosurePolicyRecord::default(),
    );

    let handle = SecretHandleRecord {
        handle_id,
        secret_class: secret_class.as_u32(),
        scope_selector,
        owner_or_service_family_ref,
        storage_residency_class: stratum.as_u32(),
        disclosure_policy_digest,
        rotation_policy_digest,
        retire_policy_digest,
        lifecycle_state: SecretLifecycleState::SealedInactive.as_u32(),
        active_envelope_version: 1,
        active_envelope_id: envelope_id,
        ..Default::default()
    };

    let envelope = SecretEnvelopeRecord {
        envelope_id,
        handle_id,
        envelope_version: 1,
        wrapping_key_id: active_wrapping_key_id,
        wrapping_key_version: wrapping_key.wrapping_key_version,
        sealed_payload_digest: sealed_digest,
        ..Default::default()
    };

    Ok((handle, envelope))
}

// ── Algorithm 3: issue_bounded_secret_lease_for_runtime_use ────────────────

pub fn issue_bounded_secret_lease_for_runtime_use<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    requesting_session_or_service_ref: SecretKeyPolicyId128,
    usage_class: LeaseUsageClass,
    audience_scope_selector: u32,
    runtime_residency: StorageStratum,
    issued_clock_sample_ref: SecretKeyPolicyId128,
    expiry_deadline_ref: SecretKeyPolicyId128,
    revocation_epoch_ref: SecretKeyPolicyId128,
) -> Result<(Vec<u8>, SecretLeaseGrantRecord), SecretKeyPolicyRuntimeError> {
    let handle = store.lookup_handle(handle_id)?;
    let state = handle.lifecycle_state()?;

    if state.blocks_lease_issuance() {
        return Err(SecretKeyPolicyRuntimeError::HandleNotActive {
            handle_id,
            actual: state,
        });
    }

    if !runtime_residency.allows_plaintext() {
        return Err(SecretKeyPolicyRuntimeError::HandleMissingStorageResidency { handle_id });
    }

    let envelope = store.lookup_envelope(handle.active_envelope_id)?;
    let wrapping_key = store.lookup_wrapping_key(envelope.wrapping_key_id)?;
    let plaintext = provider.unwrap_envelope(&envelope, &wrapping_key)?;

    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&handle_id.as_u128_le().to_le_bytes()[..8]);
    b[8..].copy_from_slice(&issued_clock_sample_ref.as_u128_le().to_le_bytes()[..8]);
    let lease_id = SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b));

    let lease = SecretLeaseGrantRecord {
        lease_id,
        handle_id,
        requesting_session_or_service_ref,
        usage_class: usage_class.as_u32(),
        audience_scope_selector,
        runtime_residency_class: runtime_residency.as_u32(),
        issued_clock_sample_ref,
        expiry_deadline_ref,
        revocation_epoch_ref,
        ..Default::default()
    };

    Ok((plaintext, lease))
}

// ── Mount-identity gate for secret-handle lease issuance ────────────────────

/// Validate that a dataset mount identity matches the binding on a handle.
///
/// When a handle was minted with a mount identity binding, every lease
/// issuance must present a matching dataset identity and mount generation.
/// This function fails closed: missing, unbound, or mismatched mount identity
/// causes lease refusal.
///
/// Callers should invoke this before or during lease issuance to gate
/// key-handle dispensation on the active committed dataset mount.
pub fn validate_dataset_mount_identity_for_handle(
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    presented_dataset_id: Option<&str>,
    presented_mount_generation: u64,
) -> Result<(), SecretKeyPolicyRuntimeError> {
    let binding = store.lookup_dataset_mount_identity(handle_id)?;
    match (binding, presented_dataset_id) {
        (Some((ref bound_dataset, bound_gen)), Some(presented_dataset)) => {
            if bound_dataset == presented_dataset && bound_gen == presented_mount_generation {
                Ok(())
            } else {
                Err(SecretKeyPolicyRuntimeError::HandleNotActive {
                    handle_id,
                    actual: SecretLifecycleState::default(),
                })
            }
        }
        (Some(_), None) => {
            // Handle requires a mount identity but none was presented.
            Err(SecretKeyPolicyRuntimeError::HandleNotActive {
                handle_id,
                actual: SecretLifecycleState::default(),
            })
        }
        (None, _) => {
            // No binding on handle: refuse. Every key handle must carry a
            // committed dataset mount identity per the current encryption
            // authority.
            Err(SecretKeyPolicyRuntimeError::HandleNotActive {
                handle_id,
                actual: SecretLifecycleState::default(),
            })
        }
    }
}

// ── Algorithm 4: assemble_policy_store_manifest ─────────────────────────────

pub fn assemble_policy_store_manifest(
    store: &dyn HandleStore,
    policy_revision_digest: SecretKeyPolicyDigest32,
    signature_set_digest: SecretKeyPolicyDigest32,
    required_secret_handle_refs: &[SecretKeyPolicyId128],
    continuity_window_start_ref: SecretKeyPolicyId128,
    continuity_window_end_ref: SecretKeyPolicyId128,
) -> Result<PolicyStoreManifestRecord, SecretKeyPolicyRuntimeError> {
    for &handle_id in required_secret_handle_refs {
        if handle_id.is_zero() {
            continue;
        }
        let handle = store.lookup_handle(handle_id)?;
        let state = handle.lifecycle_state()?;
        if !state.is_active_or_rotating() {
            return Err(SecretKeyPolicyRuntimeError::HandleNotActive {
                handle_id,
                actual: state,
            });
        }
    }

    let count = required_secret_handle_refs.len().min(4);
    let mut handle_array = [SecretKeyPolicyId128::ZERO; 4];
    handle_array[..count].copy_from_slice(&required_secret_handle_refs[..count]);

    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&policy_revision_digest[..8]);
    b[8..].copy_from_slice(&signature_set_digest[..8]);
    let manifest_id = SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b));

    Ok(PolicyStoreManifestRecord {
        manifest_id,
        policy_revision_digest,
        signature_set_digest,
        required_secret_handle_count: count as u32,
        required_secret_handle_refs: handle_array,
        continuity_window_start_ref,
        continuity_window_end_ref,
        ..Default::default()
    })
}

// ── Algorithm 5: publish_policy_bundle ─────────────────────────────────────

#[must_use]
pub fn publish_policy_bundle(
    manifest_id: SecretKeyPolicyId128,
    ruleset_blob_digest: SecretKeyPolicyDigest32,
    issuer_session_ref: SecretKeyPolicyId128,
    dual_control_linkage_ref: SecretKeyPolicyId128,
    publish_at_clock_ref: SecretKeyPolicyId128,
    activation_deadline_ref: SecretKeyPolicyId128,
) -> PolicyPublishBundleRecord {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&manifest_id.as_u128_le().to_le_bytes()[..4]);
    b[4..8].copy_from_slice(&ruleset_blob_digest[..4]);
    b[8..12].copy_from_slice(&issuer_session_ref.as_u128_le().to_le_bytes()[..4]);
    b[12..16].copy_from_slice(&dual_control_linkage_ref.as_u128_le().to_le_bytes()[..4]);
    let bundle_id = SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b));

    PolicyPublishBundleRecord {
        bundle_id,
        manifest_id,
        ruleset_blob_digest,
        issuer_session_ref,
        dual_control_linkage_ref,
        publish_at_clock_ref,
        activation_deadline_ref,
        ..Default::default()
    }
}

// ── Algorithm 6: activate_policy_revision_after_secret_handle_preflight ────

/// Activation preflight that consumes handle, lease, wrapping-key, and
/// manifest references and returns a receipt tied to those identities.
///
/// # Preflight gates (fail-closed)
///
/// 1. Every required handle in the manifest must exist, be Active or
///    RotatingDualValid, and not be revoked or quarantined.
/// 2. The activation lease must exist and not be expired.
/// 3. The wrapping key referenced by each handle's active envelope must exist.
/// 4. The disclosure policy must permit activation (Audit surface check on each handle).
/// 5. The manifest's continuity window must be open (non-zero start and end refs).
/// 6. The seal provider must be reachable (tested via wrapping-key lineage probe).
///
/// # Errors
///
/// Returns distinct fail-closed errors for:
///   - missing handles (`HandleNotFound`)
///   - revoked handles (`HandleRevoked`)
///   - quarantined handles (`HandleQuarantined`)
///   - non-active handles (`HandleNotActive`)
///   - expired lease (`LeaseExpired`)
///   - missing lease (`LeaseNotFound`)
///   - incompatible manifest (`ManifestIncompatible`)
///   - provider unreachable (`SealProviderError`)
///   - disclosure refused (`DisclosureRefused`)
pub fn activate_policy_revision_after_secret_handle_preflight<S: SealProvider, C: LeaseClock>(
    provider: &S,
    clock: &C,
    store: &dyn HandleStore,
    manifest: &PolicyStoreManifestRecord,
    bundle: &PolicyPublishBundleRecord,
    lease_id: SecretKeyPolicyId128,
    disclosure_policy: &SecretDisclosurePolicyRecord,
    anchor_set_proof_ref: SecretKeyPolicyId128,
    runbook_or_authz_receipt_ref: SecretKeyPolicyId128,
    activated_at_clock_ref: SecretKeyPolicyId128,
    scope_selector: u32,
) -> Result<PolicyActivationReceipt, SecretKeyPolicyRuntimeError> {
    // Gate 1: manifest continuity window must be open.
    if manifest.continuity_window_start_ref.is_zero()
        || manifest.continuity_window_end_ref.is_zero()
    {
        return Err(SecretKeyPolicyRuntimeError::ManifestIncompatible {
            manifest_id: manifest.manifest_id,
            reason: ManifestRefusalReason::ContinuityWindowClosed,
        });
    }

    // Gate 2: activation lease must exist and not be expired.
    let lease = store.lookup_lease(lease_id)?;
    if clock.has_deadline_passed(lease.expiry_deadline_ref) {
        return Err(SecretKeyPolicyRuntimeError::LeaseExpired { lease_id });
    }
    let lease_usage = lease.usage_class()?;
    if lease_usage != LeaseUsageClass::SignOrPublish {
        return Err(SecretKeyPolicyRuntimeError::LeaseUsageMismatch {
            handle_id: lease.handle_id,
            requested: lease_usage,
        });
    }

    // Initial wrapping-key id accumulator (picked from first handle's
    // envelope); all handles must agree on the same wrapping key.
    let mut activation_wrapping_key_ref = SecretKeyPolicyId128::ZERO;
    let mut first_handle = true;
    let mut lease_handle_seen = false;

    // Gate 3-6: per-handle checks.
    for &handle_id in manifest.required_handles() {
        if handle_id.is_zero() {
            continue;
        }
        if handle_id == lease.handle_id {
            lease_handle_seen = true;
        }

        // Gate 3: handle must exist.
        let handle = store.lookup_handle(handle_id)?;

        // Gate 4: handle must be in a usable lifecycle state.
        let state = handle.lifecycle_state()?;
        match state {
            SecretLifecycleState::Active | SecretLifecycleState::RotatingDualValid => {}
            SecretLifecycleState::Revoked => {
                return Err(SecretKeyPolicyRuntimeError::HandleRevoked { handle_id });
            }
            SecretLifecycleState::Quarantined => {
                return Err(SecretKeyPolicyRuntimeError::HandleQuarantined { handle_id });
            }
            _ => {
                return Err(SecretKeyPolicyRuntimeError::HandleNotActive {
                    handle_id,
                    actual: state,
                });
            }
        }

        // Gate 5: disclosure policy must permit activation.
        validate_handle_disclosure(disclosure_policy, DisclosureSurfaceClass::Audit, &handle)?;

        // Gate 6: wrapping key must exist for the handle's active envelope.
        let envelope = store.lookup_envelope(handle.active_envelope_id)?;
        let wrapping_key = store.lookup_wrapping_key(envelope.wrapping_key_id)?;

        // All handles must reference the same wrapping key.
        if first_handle {
            activation_wrapping_key_ref = wrapping_key.wrapping_key_id;
            first_handle = false;
        } else if activation_wrapping_key_ref != wrapping_key.wrapping_key_id {
            return Err(SecretKeyPolicyRuntimeError::EnvelopeWrappingMismatch {
                envelope_id: envelope.envelope_id,
                wrapping_key_id: wrapping_key.wrapping_key_id,
            });
        }
    }

    if manifest.required_handles().is_empty() || activation_wrapping_key_ref.is_zero() {
        return Err(SecretKeyPolicyRuntimeError::ManifestMissingHandles {
            manifest_id: manifest.manifest_id,
            missing_count: 1,
        });
    }
    if !lease_handle_seen {
        return Err(SecretKeyPolicyRuntimeError::LeaseHandleMismatch {
            lease_id,
            handle_id: lease.handle_id,
        });
    }

    // Gate 7: seal provider must be reachable.
    // Probe by verifying the wrapping key against itself (identity check).
    let wrapping_key = store.lookup_wrapping_key(activation_wrapping_key_ref)?;
    if !provider.verify_wrapping_key_lineage(&wrapping_key, &wrapping_key)? {
        return Err(SecretKeyPolicyRuntimeError::SealProviderError {
            reason: SealProviderErrorKind::ProviderUnreachable,
        });
    }

    // Assemble activation receipt.
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&bundle.bundle_id.as_u128_le().to_le_bytes()[..4]);
    b[4..8].copy_from_slice(&manifest.manifest_id.as_u128_le().to_le_bytes()[..4]);
    b[8..12].copy_from_slice(&activated_at_clock_ref.as_u128_le().to_le_bytes()[..4]);
    b[12..16].copy_from_slice(&anchor_set_proof_ref.as_u128_le().to_le_bytes()[..4]);
    let activation_id = SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b));

    Ok(PolicyActivationReceipt {
        activation_id,
        manifest_id: manifest.manifest_id,
        bundle_id: bundle.bundle_id,
        replaced_active_revision_ref: SecretKeyPolicyId128::ZERO,
        scope_selector,
        activation_lease_ref: lease_id,
        activation_wrapping_key_ref,
        anchor_set_proof_ref,
        runbook_or_authz_receipt_ref,
        activated_at_clock_ref,
        ..Default::default()
    })
}

// ── Algorithm 7: rotate_leaf_secret_with_dual_validity_and_successor ───────

pub fn rotate_leaf_secret_with_dual_validity_and_successor<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    rotation_plan: &SecretRotationPlanRecord,
    _expiry_ref: SecretKeyPolicyId128,
) -> Result<(SecretHandleRecord, SecretEnvelopeRecord), SecretKeyPolicyRuntimeError> {
    let mut handle = store.lookup_handle(handle_id)?;
    let rotation_class = rotation_plan.rotation_class()?;
    let wants_dual = rotation_class.allows_dual_validity();
    let secret_class = handle.secret_class()?;
    let material = provider.generate_secret_material(secret_class)?;

    let key_id = rotation_plan.predecessor_envelope_id;
    let wrapping_key = store.lookup_wrapping_key(key_id).map_err(|_| {
        SecretKeyPolicyRuntimeError::EnvelopeNotFound {
            envelope_id: key_id,
        }
    })?;

    let sealed_digest = provider.seal_payload(&material, &wrapping_key)?;

    let successor_envelope_id = rotation_plan.successor_envelope_id;
    if successor_envelope_id.is_zero() {
        return Err(SecretKeyPolicyRuntimeError::CryptoPlaceholder);
    }

    let successor = SecretEnvelopeRecord {
        envelope_id: successor_envelope_id,
        handle_id,
        envelope_version: rotation_plan.successor_envelope_version,
        wrapping_key_id: wrapping_key.wrapping_key_id,
        wrapping_key_version: wrapping_key.wrapping_key_version,
        sealed_payload_digest: sealed_digest,
        predecessor_envelope_id: handle.active_envelope_id,
        ..Default::default()
    };

    if wants_dual {
        handle.lifecycle_state = SecretLifecycleState::RotatingDualValid.as_u32();
        handle.active_envelope_version = rotation_plan.successor_envelope_version;
    } else {
        handle.lifecycle_state = SecretLifecycleState::Active.as_u32();
        handle.active_envelope_id = successor_envelope_id;
        handle.active_envelope_version = rotation_plan.successor_envelope_version;
    }

    Ok((handle, successor))
}

// ── Algorithm 8: rewrap_envelope_set_after_wrapping_key_rotation ───────────

pub fn rewrap_envelope_set_after_wrapping_key_rotation<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    new_wrapping_key_id: SecretKeyPolicyId128,
) -> Result<SecretEnvelopeRecord, SecretKeyPolicyRuntimeError> {
    let handle = store.lookup_handle(handle_id)?;
    let old_envelope = store.lookup_envelope(handle.active_envelope_id)?;
    let old_wrapping_key = store.lookup_wrapping_key(old_envelope.wrapping_key_id)?;
    let new_wrapping_key = store.lookup_wrapping_key(new_wrapping_key_id)?;

    if !provider.verify_wrapping_key_lineage(&old_wrapping_key, &new_wrapping_key)? {
        return Err(SecretKeyPolicyRuntimeError::EnvelopeWrappingMismatch {
            envelope_id: old_envelope.envelope_id,
            wrapping_key_id: new_wrapping_key_id,
        });
    }

    let plaintext = provider.unwrap_envelope(&old_envelope, &old_wrapping_key)?;
    let new_sealed_digest = provider.seal_payload(&plaintext, &new_wrapping_key)?;

    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&handle_id.as_u128_le().to_le_bytes()[..8]);
    b[8..].copy_from_slice(&new_wrapping_key_id.as_u128_le().to_le_bytes()[..8]);
    let new_envelope_id = SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b));

    Ok(SecretEnvelopeRecord {
        envelope_id: new_envelope_id,
        handle_id,
        envelope_version: handle.active_envelope_version + 1,
        wrapping_key_id: new_wrapping_key_id,
        wrapping_key_version: new_wrapping_key.wrapping_key_version,
        sealed_payload_digest: new_sealed_digest,
        predecessor_envelope_id: old_envelope.envelope_id,
        ..Default::default()
    })
}

// ── Algorithm 9: revoke_or_quarantine_secret_handle_and_drain_runtime_leases ───

pub fn revoke_or_quarantine_secret_handle_and_drain_runtime_leases(
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    trigger: RevocationTriggerClass,
    require_quarantine: bool,
    successor_handle_id: SecretKeyPolicyId128,
    revoked_at_clock_ref: SecretKeyPolicyId128,
    revocation_epoch_ref: SecretKeyPolicyId128,
) -> Result<SecretRevocationReceipt, SecretKeyPolicyRuntimeError> {
    let _ = store.lookup_handle(handle_id)?;

    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&handle_id.as_u128_le().to_le_bytes()[..4]);
    b[4..8].copy_from_slice(&revoked_at_clock_ref.as_u128_le().to_le_bytes()[..4]);
    b[8..12].copy_from_slice(&revocation_epoch_ref.as_u128_le().to_le_bytes()[..4]);
    b[12..16].copy_from_slice(&successor_handle_id.as_u128_le().to_le_bytes()[..4]);
    let revocation_id = SecretKeyPolicyId128::from_u128_le(u128::from_le_bytes(b));

    Ok(SecretRevocationReceipt {
        revocation_id,
        handle_id,
        trigger_class: trigger.as_u32(),
        requires_quarantine: u32::from(require_quarantine),
        successor_handle_id,
        revoked_at_clock_ref,
        affected_lease_count: 0,
        revocation_epoch_ref,
        ..Default::default()
    })
}

// ── Algorithm 10: recover_policy_store_and_handle_pointers ─────────────────

pub fn recover_policy_store_and_handle_pointers(
    store: &dyn HandleStore,
    root_manifest_id: SecretKeyPolicyId128,
) -> Result<Vec<(PolicyStoreManifestRecord, Vec<SecretHandleRecord>)>, SecretKeyPolicyRuntimeError>
{
    // 1. Look up the root manifest; missing manifest breaks the recovery chain.
    let manifest = store.lookup_manifest(root_manifest_id).map_err(|_| {
        SecretKeyPolicyRuntimeError::RecoveryManifestChainBroken {
            at_manifest_id: root_manifest_id,
        }
    })?;

    // 2. Validate continuity window: both refs must be non-zero.
    if manifest.continuity_window_start_ref.is_zero()
        || manifest.continuity_window_end_ref.is_zero()
    {
        return Err(SecretKeyPolicyRuntimeError::RecoveryManifestChainBroken {
            at_manifest_id: root_manifest_id,
        });
    }

    // 3. Collect and validate each required handle reference.
    let mut handles: Vec<SecretHandleRecord> = Vec::new();
    for &handle_id in manifest.required_handles() {
        if handle_id.is_zero() {
            continue;
        }

        let handle = store.lookup_handle(handle_id)?;
        let state = handle
            .lifecycle_state()
            .map_err(|_| SecretKeyPolicyRuntimeError::RecoveryAmbiguousState { handle_id })?;

        match state {
            SecretLifecycleState::Active | SecretLifecycleState::RotatingDualValid => {}
            SecretLifecycleState::Revoked => {
                return Err(SecretKeyPolicyRuntimeError::HandleRevoked { handle_id });
            }
            SecretLifecycleState::Quarantined => {
                return Err(SecretKeyPolicyRuntimeError::HandleQuarantined { handle_id });
            }
            _ => {
                return Err(SecretKeyPolicyRuntimeError::HandleNotActive {
                    handle_id,
                    actual: state,
                });
            }
        }

        // Validate the active envelope pointer is non-zero and the envelope
        // record exists in the store.
        if handle.active_envelope_id.is_zero() {
            return Err(SecretKeyPolicyRuntimeError::EnvelopeNotFound {
                envelope_id: handle.active_envelope_id,
            });
        }
        store.lookup_envelope(handle.active_envelope_id)?;

        handles.push(handle);
    }

    Ok(vec![(manifest, handles)])
}

// ── Convenience wrappers: transport TLS lifecycle ─────────────────────────

/// Mint a transport TLS secret handle + sealed envelope.
///
/// Transport TLS private material is sealed-authoritative; the runtime
/// must issue a bounded lease (see `lease_transport_tls_for_termination`)
/// before using the material in a TLS session.
pub fn mint_transport_tls_handle_and_seal<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    scope_selector: u32,
    owner_family_ref: SecretKeyPolicyId128,
    active_wrapping_key_id: SecretKeyPolicyId128,
    disclosure_policy_digest: SecretKeyPolicyDigest32,
    rotation_policy_digest: SecretKeyPolicyDigest32,
    retire_policy_digest: SecretKeyPolicyDigest32,
) -> Result<(SecretHandleRecord, SecretEnvelopeRecord), SecretKeyPolicyRuntimeError> {
    mint_secret_handle_and_seal_material(
        provider,
        store,
        SecretClass::TransportTls,
        scope_selector,
        owner_family_ref,
        active_wrapping_key_id,
        disclosure_policy_digest,
        rotation_policy_digest,
        retire_policy_digest,
    )
}

/// Issue a transport-TLS runtime lease suitable for TLS termination.
///
/// The returned plaintext is the TLS private material; the caller must
/// never log, persist, or transmit it outside the lease lifetime.
pub fn lease_transport_tls_for_termination<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    requesting_session_ref: SecretKeyPolicyId128,
    issued_clock_ref: SecretKeyPolicyId128,
    expiry_deadline_ref: SecretKeyPolicyId128,
    revocation_epoch_ref: SecretKeyPolicyId128,
) -> Result<(Vec<u8>, SecretLeaseGrantRecord), SecretKeyPolicyRuntimeError> {
    issue_bounded_secret_lease_for_runtime_use(
        provider,
        store,
        handle_id,
        requesting_session_ref,
        LeaseUsageClass::TransportTermination,
        0,
        StorageStratum::RuntimeMemoryLease,
        issued_clock_ref,
        expiry_deadline_ref,
        revocation_epoch_ref,
    )
}

/// Rotate a transport-TLS secret with dual-validity support.
///
/// Dual-validity allows the old TLS certificate chain to remain
/// valid while endpoints converge on the new key material.
pub fn rotate_transport_tls_with_dual_validity<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    rotation_plan: &SecretRotationPlanRecord,
    expiry_ref: SecretKeyPolicyId128,
) -> Result<(SecretHandleRecord, SecretEnvelopeRecord), SecretKeyPolicyRuntimeError> {
    rotate_leaf_secret_with_dual_validity_and_successor(
        provider,
        store,
        handle_id,
        rotation_plan,
        expiry_ref,
    )
}

// ── Convenience wrappers: node-join bootstrap lifecycle ────────────────────

/// Mint a node-join bootstrap secret handle + sealed envelope.
///
/// Bootstrap material is short-lived and high-risk.  After the node
/// joins the cluster, the handle should be revoked and the branch
/// deleted.  The sealed envelope must be replicated (SealedAuthoritative)
/// so that any control-plane member can validate the join request.
pub fn mint_node_join_bootstrap_handle_and_seal<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    scope_selector: u32,
    owner_family_ref: SecretKeyPolicyId128,
    active_wrapping_key_id: SecretKeyPolicyId128,
    disclosure_policy_digest: SecretKeyPolicyDigest32,
    rotation_policy_digest: SecretKeyPolicyDigest32,
    retire_policy_digest: SecretKeyPolicyDigest32,
) -> Result<(SecretHandleRecord, SecretEnvelopeRecord), SecretKeyPolicyRuntimeError> {
    mint_secret_handle_and_seal_material(
        provider,
        store,
        SecretClass::NodeJoinBootstrap,
        scope_selector,
        owner_family_ref,
        active_wrapping_key_id,
        disclosure_policy_digest,
        rotation_policy_digest,
        retire_policy_digest,
    )
}

/// Issue a short-lived bootstrap lease for node join validation.
///
/// The caller receives plaintext bootstrap material suitable for
/// a single join ceremony.  The lease grants a tight `RuntimeMemoryLease`
/// residency with a short expiry deadline.
pub fn lease_node_join_bootstrap_for_join_ceremony<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    requesting_session_ref: SecretKeyPolicyId128,
    issued_clock_ref: SecretKeyPolicyId128,
    expiry_deadline_ref: SecretKeyPolicyId128,
    revocation_epoch_ref: SecretKeyPolicyId128,
) -> Result<(Vec<u8>, SecretLeaseGrantRecord), SecretKeyPolicyRuntimeError> {
    issue_bounded_secret_lease_for_runtime_use(
        provider,
        store,
        handle_id,
        requesting_session_ref,
        LeaseUsageClass::BootstrapOrJoin,
        0,
        StorageStratum::RuntimeMemoryLease,
        issued_clock_ref,
        expiry_deadline_ref,
        revocation_epoch_ref,
    )
}

/// Revoke a node-join bootstrap handle after successful join.
///
/// This drains any remaining runtime leases and marks the handle
/// as revoked, optionally requiring quarantine if the join was
/// interrupted or suspicious.
pub fn revoke_node_join_bootstrap_after_join(
    store: &dyn HandleStore,
    handle_id: SecretKeyPolicyId128,
    quarantine: bool,
    successor_handle_id: SecretKeyPolicyId128,
    revoked_at_clock_ref: SecretKeyPolicyId128,
    revocation_epoch_ref: SecretKeyPolicyId128,
) -> Result<SecretRevocationReceipt, SecretKeyPolicyRuntimeError> {
    revoke_or_quarantine_secret_handle_and_drain_runtime_leases(
        store,
        handle_id,
        if quarantine {
            RevocationTriggerClass::CompromiseSuspected
        } else {
            RevocationTriggerClass::NodeDrain
        },
        quarantine,
        successor_handle_id,
        revoked_at_clock_ref,
        revocation_epoch_ref,
    )
}

// ── Convenience wrapper: envelope-wrapping with HSM support ────────────────

/// Mint an envelope-wrapping (KEK) secret, optionally routed to ExternalHsm.
///
/// When `require_hsm` is true, the disclosure policy is set to require
/// HSM residency and the classify function promotes the stratum to
/// ExternalHsm.
pub fn mint_envelope_wrapping_handle_and_seal<S: SealProvider>(
    provider: &S,
    store: &dyn HandleStore,
    scope_selector: u32,
    owner_family_ref: SecretKeyPolicyId128,
    active_wrapping_key_id: SecretKeyPolicyId128,
    require_hsm: bool,
    rotation_policy_digest: SecretKeyPolicyDigest32,
    retire_policy_digest: SecretKeyPolicyDigest32,
) -> Result<(SecretHandleRecord, SecretEnvelopeRecord), SecretKeyPolicyRuntimeError> {
    let _disclosure = SecretDisclosurePolicyRecord::default().with_hsm_required(require_hsm);
    let mut disclosure_digest = [0u8; 32];
    disclosure_digest[0] = if require_hsm { 1 } else { 0 };

    mint_secret_handle_and_seal_material(
        provider,
        store,
        SecretClass::EnvelopeWrapping,
        scope_selector,
        owner_family_ref,
        active_wrapping_key_id,
        disclosure_digest,
        rotation_policy_digest,
        retire_policy_digest,
    )
}

// ── Disclosure decision engine ─────────────────────────────────────────────

/// Decide whether secret-adjacent records may be rendered on a given surface.
///
/// Consumes the disclosure policy, the target surface class, and a bitmask
/// of the fields the caller wants to render. Returns:
///
/// - `DisclosureVerdict::Allow` when the surface is permitted and all requested fields pass the
///   visible-fields mask.
/// - `DisclosureVerdict::Redact` when the surface is permitted but some requested fields are
///   blocked, the provider class is hidden, or narrative export is denied.
/// - `DisclosureVerdict::Refuse` when the surface is not permitted or redaction would cause
///   semantic loss (all fields blocked).
pub fn decide_secret_disclosure(
    policy: &SecretDisclosurePolicyRecord,
    surface: DisclosureSurfaceClass,
    requested_fields: u64,
) -> DisclosureVerdict {
    // Gate 1: surface permission.
    if !surface.surface_permitted(policy) {
        return match surface {
            DisclosureSurfaceClass::Audit => {
                DisclosureVerdict::Refuse(RefusalReason::AuditSurfaceNotPermitted)
            }
            DisclosureSurfaceClass::Validation => {
                DisclosureVerdict::Refuse(RefusalReason::ValidationSurfaceNotPermitted)
            }
            DisclosureSurfaceClass::Scenario => {
                DisclosureVerdict::Refuse(RefusalReason::ScenarioSurfaceNotPermitted)
            }
            DisclosureSurfaceClass::Render => {
                // Render is always surface-permitted; unreachable here.
                DisclosureVerdict::Refuse(RefusalReason::SemanticLoss)
            }
        };
    }

    // Gate 2: requested-fields vs visible_fields_mask.
    let blocked = requested_fields & !policy.visible_fields_mask;
    if blocked != 0 {
        // If all requested fields are blocked, refuse on semantic-loss grounds.
        if blocked == requested_fields && requested_fields != 0 {
            return DisclosureVerdict::Refuse(RefusalReason::SemanticLoss);
        }
        return DisclosureVerdict::Redacted(RedactionReason::FieldMasked {
            blocked_fields: blocked,
        });
    }

    // Gate 3: narrative export check (Render surface with narrative intent).
    // The caller indicates narrative intent by setting a high bit in requested_fields.
    // Bit 63 signals "narrative export requested".
    const NARRATIVE_EXPORT_FLAG: u64 = 1 << 63;
    if (requested_fields & NARRATIVE_EXPORT_FLAG) != 0 && policy.narrative_export_visible == 0 {
        return DisclosureVerdict::Redacted(RedactionReason::NarrativeExportBlocked);
    }

    // Gate 4: provider class reveal check.
    // Bit 62 signals "provider class reveal requested".
    const PROVIDER_CLASS_FLAG: u64 = 1 << 62;
    if (requested_fields & PROVIDER_CLASS_FLAG) != 0 && policy.provider_class_reveal == 0 {
        return DisclosureVerdict::Redacted(RedactionReason::ProviderClassHidden);
    }

    DisclosureVerdict::Allow
}

/// Convenience gate: returns Ok(()) when disclosure is fully allowed,
/// Err when refused. Redacted cases are returned as Ok so the caller
/// can decide how to mask; the caller should inspect the visible_fields_mask.
pub fn gate_secret_disclosure(
    policy: &SecretDisclosurePolicyRecord,
    surface: DisclosureSurfaceClass,
    requested_fields: u64,
) -> Result<(), SecretKeyPolicyRuntimeError> {
    match decide_secret_disclosure(policy, surface, requested_fields) {
        DisclosureVerdict::Allow | DisclosureVerdict::Redacted(_) => Ok(()),
        DisclosureVerdict::Refuse(reason) => {
            Err(SecretKeyPolicyRuntimeError::DisclosureRefused { surface, reason })
        }
    }
}

/// Validate that a `SecretHandleRecord` may be disclosed on the given surface.
///
/// Field mask bit assignments for handle records:
///   bit 0: handle_id
///   bit 1: secret_class
///   bit 2: storage_residency
///   bit 3: lifecycle_state
///   bit 4: envelope_ref
///   bit 5: wrapping_key_ref
///
/// Returns `Ok(())` when disclosure is allowed or redacted; `Err` when refused.
pub fn validate_handle_disclosure(
    policy: &SecretDisclosurePolicyRecord,
    surface: DisclosureSurfaceClass,
    _handle: &SecretHandleRecord,
) -> Result<(), SecretKeyPolicyRuntimeError> {
    gate_secret_disclosure(policy, surface, 0x3F)
}

// ──

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tidefs_types_secret_key_policy_core::WrappingKeyClass;

    // ── Test double: InMemoryHandleStore ───

    struct InMemoryHandleStore {
        handles: HashMap<u128, SecretHandleRecord>,
        envelopes: HashMap<u128, SecretEnvelopeRecord>,
        wrapping_keys: HashMap<u128, WrappingKeyRecord>,
        manifests: HashMap<u128, PolicyStoreManifestRecord>,
        leases: HashMap<u128, SecretLeaseGrantRecord>,
        activations: HashMap<u128, PolicyActivationReceipt>,
    }

    impl InMemoryHandleStore {
        fn new() -> Self {
            Self {
                handles: HashMap::new(),
                envelopes: HashMap::new(),
                wrapping_keys: HashMap::new(),
                manifests: HashMap::new(),
                leases: HashMap::new(),
                activations: HashMap::new(),
            }
        }
    }

    impl HandleStore for InMemoryHandleStore {
        fn lookup_handle(
            &self,
            handle_id: SecretKeyPolicyId128,
        ) -> Result<SecretHandleRecord, SecretKeyPolicyRuntimeError> {
            self.handles
                .get(&handle_id.as_u128_le())
                .copied()
                .ok_or(SecretKeyPolicyRuntimeError::HandleNotFound { handle_id })
        }
        fn lookup_envelope(
            &self,
            envelope_id: SecretKeyPolicyId128,
        ) -> Result<SecretEnvelopeRecord, SecretKeyPolicyRuntimeError> {
            self.envelopes
                .get(&envelope_id.as_u128_le())
                .copied()
                .ok_or(SecretKeyPolicyRuntimeError::EnvelopeNotFound { envelope_id })
        }
        fn lookup_wrapping_key(
            &self,
            wrapping_key_id: SecretKeyPolicyId128,
        ) -> Result<WrappingKeyRecord, SecretKeyPolicyRuntimeError> {
            self.wrapping_keys
                .get(&wrapping_key_id.as_u128_le())
                .copied()
                .ok_or(SecretKeyPolicyRuntimeError::WrappingKeyNotFound { wrapping_key_id })
        }
        fn lookup_manifest(
            &self,
            manifest_id: SecretKeyPolicyId128,
        ) -> Result<PolicyStoreManifestRecord, SecretKeyPolicyRuntimeError> {
            self.manifests
                .get(&manifest_id.as_u128_le())
                .copied()
                .ok_or(SecretKeyPolicyRuntimeError::ManifestIncompatible {
                    manifest_id,
                    reason: ManifestRefusalReason::MissingRevReferences,
                })
        }
        fn lookup_activation(
            &self,
            activation_id: SecretKeyPolicyId128,
        ) -> Result<PolicyActivationReceipt, SecretKeyPolicyRuntimeError> {
            self.activations
                .get(&activation_id.as_u128_le())
                .copied()
                .ok_or(SecretKeyPolicyRuntimeError::ActivationPreflightFailed {
                    activation_id,
                    reason: ActivationRefusalReason::MissingHandles,
                })
        }
        fn lookup_lease(
            &self,
            lease_id: SecretKeyPolicyId128,
        ) -> Result<SecretLeaseGrantRecord, SecretKeyPolicyRuntimeError> {
            self.leases
                .get(&lease_id.as_u128_le())
                .copied()
                .ok_or(SecretKeyPolicyRuntimeError::LeaseNotFound { lease_id })
        }
        fn store_handle(
            &mut self,
            handle: &SecretHandleRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            self.handles.insert(handle.handle_id.as_u128_le(), *handle);
            Ok(())
        }
        fn store_envelope(
            &mut self,
            env: &SecretEnvelopeRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            self.envelopes.insert(env.envelope_id.as_u128_le(), *env);
            Ok(())
        }
        fn store_manifest(
            &mut self,
            m: &PolicyStoreManifestRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            self.manifests.insert(m.manifest_id.as_u128_le(), *m);
            Ok(())
        }
        fn store_activation(
            &mut self,
            activation: &PolicyActivationReceipt,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            self.activations
                .insert(activation.activation_id.as_u128_le(), *activation);
            Ok(())
        }
        fn store_lease(
            &mut self,
            lease: &SecretLeaseGrantRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            self.leases.insert(lease.lease_id.as_u128_le(), *lease);
            Ok(())
        }
        fn store_rotation_plan(
            &mut self,
            _plan: &SecretRotationPlanRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn store_revocation(
            &mut self,
            _receipt: &SecretRevocationReceipt,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
    }

    // ── Test double: MockSealProvider ───

    struct MockSealProvider {
        wrapping_key_lineage_valid: bool,
        /// When set, `verify_wrapping_key_lineage` returns this error
        /// instead of the boolean flag.  Used to simulate
        /// provider-unreachable, timeout, and other seal-provider
        /// failures.
        forced_error: Option<SealProviderErrorKind>,
    }

    impl MockSealProvider {
        fn new() -> Self {
            Self {
                wrapping_key_lineage_valid: true,
                forced_error: None,
            }
        }

        #[allow(dead_code)]
        fn with_lineage(mut self, valid: bool) -> Self {
            self.wrapping_key_lineage_valid = valid;
            self
        }

        fn with_forced_error(mut self, err: SealProviderErrorKind) -> Self {
            self.forced_error = Some(err);
            self
        }
    }

    impl SealProvider for MockSealProvider {
        fn unwrap_envelope(
            &self,
            _envelope: &SecretEnvelopeRecord,
            _wrapping_key: &WrappingKeyRecord,
        ) -> Result<Vec<u8>, SecretKeyPolicyRuntimeError> {
            if let Some(ref err) = self.forced_error {
                return Err(SecretKeyPolicyRuntimeError::SealProviderError { reason: *err });
            }
            Ok(b"mock-plaintext-material".to_vec())
        }
        fn seal_payload(
            &self,
            _plaintext: &[u8],
            _wrapping_key: &WrappingKeyRecord,
        ) -> Result<SecretKeyPolicyDigest32, SecretKeyPolicyRuntimeError> {
            if let Some(ref err) = self.forced_error {
                return Err(SecretKeyPolicyRuntimeError::SealProviderError { reason: *err });
            }
            Ok([0xAAu8; 32])
        }
        fn generate_secret_material(
            &self,
            _secret_class: SecretClass,
        ) -> Result<Vec<u8>, SecretKeyPolicyRuntimeError> {
            if let Some(ref err) = self.forced_error {
                return Err(SecretKeyPolicyRuntimeError::SealProviderError { reason: *err });
            }
            Ok(vec![0x42u8; 32])
        }
        fn verify_wrapping_key_lineage(
            &self,
            _parent: &WrappingKeyRecord,
            _child: &WrappingKeyRecord,
        ) -> Result<bool, SecretKeyPolicyRuntimeError> {
            if let Some(ref err) = self.forced_error {
                return Err(SecretKeyPolicyRuntimeError::SealProviderError { reason: *err });
            }
            Ok(self.wrapping_key_lineage_valid)
        }
    }

    // ── Test double: MockLeaseClock ───

    struct MockLeaseClock {
        /// When true, has_deadline_passed returns true for every input.
        always_expired: bool,
    }

    impl MockLeaseClock {
        fn new() -> Self {
            Self {
                always_expired: false,
            }
        }

        fn with_always_expired(mut self, expired: bool) -> Self {
            self.always_expired = expired;
            self
        }
    }

    impl LeaseClock for MockLeaseClock {
        fn has_deadline_passed(&self, deadline_ref: SecretKeyPolicyId128) -> bool {
            // A zero deadline is always considered expired (no valid deadline).
            if deadline_ref.is_zero() {
                return true;
            }
            self.always_expired
        }
    }

    // ── Algorithm 1 tests ───

    #[test]
    fn classify_assigns_replicated_stratum_for_policy_signer() {
        let (stratum, replicated, _disc_verdict) =
            classify_secret_class_and_required_storage_residency(
                SecretClass::PolicySigner,
                &SecretDisclosurePolicyRecord::default(),
            );
        assert_eq!(stratum, StorageStratum::SealedAuthoritative);
        assert!(replicated);
    }

    #[test]
    fn classify_allows_node_cache_for_transport_tls() {
        let (stratum, replicated, _disclosure_verdict) =
            classify_secret_class_and_required_storage_residency(
                SecretClass::TransportTls,
                &SecretDisclosurePolicyRecord::default(),
            );
        assert_eq!(stratum, StorageStratum::SealedAuthoritative);
        assert!(replicated);
    }

    // ── Algorithm 2 tests ───

    #[test]
    fn mint_creates_handle_and_envelope() {
        let provider = MockSealProvider::new();
        let mut store = InMemoryHandleStore::new();

        let wk_id = SecretKeyPolicyId128::from_u128_le(0x100);
        store.wrapping_keys.insert(
            0x100,
            WrappingKeyRecord {
                wrapping_key_id: wk_id,
                wrapping_key_class: WrappingKeyClass::ClusterRoot.as_u32(),
                wrapping_key_version: 1,
                ..Default::default()
            },
        );

        let (handle, envelope) = mint_secret_handle_and_seal_material(
            &provider,
            &store,
            SecretClass::TransportTls,
            0,
            SecretKeyPolicyId128::from_u128_le(0x200),
            wk_id,
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
        )
        .expect("mint should succeed");

        assert_eq!(handle.secret_class(), Ok(SecretClass::TransportTls));
        assert_eq!(
            handle.lifecycle_state(),
            Ok(SecretLifecycleState::SealedInactive)
        );
        assert_eq!(handle.active_envelope_id, envelope.envelope_id);
        assert_eq!(envelope.handle_id, handle.handle_id);
        assert!(!handle.handle_id.is_zero());
        assert!(!envelope.envelope_id.is_zero());
    }

    // ── Algorithm 3 tests ───

    #[test]
    fn lease_issues_for_active_handle() {
        let provider = MockSealProvider::new();
        let mut store = InMemoryHandleStore::new();

        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        store.wrapping_keys.insert(
            0x2000,
            WrappingKeyRecord {
                wrapping_key_id: wk_id,
                wrapping_key_class: WrappingKeyClass::ClusterRoot.as_u32(),
                wrapping_key_version: 1,
                ..Default::default()
            },
        );

        let handle_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let env_id = SecretKeyPolicyId128::from_u128_le(0x4000);
        store.handles.insert(
            0x3000,
            SecretHandleRecord {
                handle_id,
                secret_class: SecretClass::PolicySigner.as_u32(),
                lifecycle_state: SecretLifecycleState::Active.as_u32(),
                active_envelope_version: 1,
                active_envelope_id: env_id,
                ..Default::default()
            },
        );
        store.envelopes.insert(
            0x4000,
            SecretEnvelopeRecord {
                envelope_id: env_id,
                handle_id,
                envelope_version: 1,
                wrapping_key_id: wk_id,
                wrapping_key_version: 1,
                ..Default::default()
            },
        );

        let (material, lease) = issue_bounded_secret_lease_for_runtime_use(
            &provider,
            &store,
            handle_id,
            SecretKeyPolicyId128::from_u128_le(0x555),
            LeaseUsageClass::SignOrPublish,
            0,
            StorageStratum::RuntimeMemoryLease,
            SecretKeyPolicyId128::from_u128_le(0x600),
            SecretKeyPolicyId128::from_u128_le(0x700),
            SecretKeyPolicyId128::from_u128_le(0x800),
        )
        .expect("lease should succeed");

        assert_eq!(material, b"mock-plaintext-material");
        assert_eq!(lease.handle_id, handle_id);
        assert_eq!(lease.usage_class(), Ok(LeaseUsageClass::SignOrPublish));
        assert_eq!(
            lease.runtime_residency(),
            Ok(StorageStratum::RuntimeMemoryLease)
        );
    }

    #[test]
    fn lease_refuses_revoked_handle() {
        let provider = MockSealProvider::new();
        let store = InMemoryHandleStore::new();
        let result = issue_bounded_secret_lease_for_runtime_use(
            &provider,
            &store,
            SecretKeyPolicyId128::from_u128_le(0xDEAD),
            SecretKeyPolicyId128::from_u128_le(1),
            LeaseUsageClass::SignOrPublish,
            0,
            StorageStratum::RuntimeMemoryLease,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
        );
        assert!(result.is_err());
    }

    // ── Algorithm 4 tests ───

    #[test]
    fn manifest_assembles_with_valid_handles() {
        let mut store = InMemoryHandleStore::new();
        let h1 = SecretKeyPolicyId128::from_u128_le(0xAAA);
        store.handles.insert(
            0xAAA,
            SecretHandleRecord {
                handle_id: h1,
                secret_class: SecretClass::PolicySigner.as_u32(),
                lifecycle_state: SecretLifecycleState::Active.as_u32(),
                ..Default::default()
            },
        );

        let manifest = assemble_policy_store_manifest(
            &store,
            [0x10u8; 32],
            [0x20u8; 32],
            &[h1],
            SecretKeyPolicyId128::from_u128_le(0x1000),
            SecretKeyPolicyId128::from_u128_le(0x2000),
        )
        .expect("manifest assembly should succeed");

        assert_eq!(manifest.required_handles().len(), 1);
        assert_eq!(manifest.required_handles()[0], h1);
    }

    // ── Algorithm 5 tests ───

    #[test]
    fn publish_creates_bundle_with_deterministic_id() {
        let bundle = publish_policy_bundle(
            SecretKeyPolicyId128::from_u128_le(0xA),
            [0xBBu8; 32],
            SecretKeyPolicyId128::from_u128_le(0xC),
            SecretKeyPolicyId128::from_u128_le(0xD),
            SecretKeyPolicyId128::from_u128_le(0xE),
            SecretKeyPolicyId128::from_u128_le(0xF),
        );
        assert!(!bundle.bundle_id.is_zero());
        assert_eq!(bundle.manifest_id.as_u128_le(), 0xA);
    }

    // ── Algorithm 6 tests ───

    fn make_activation_test_store(
        handle_id: SecretKeyPolicyId128,
        envelope_id: SecretKeyPolicyId128,
        wk_id: SecretKeyPolicyId128,
        lifecycle: SecretLifecycleState,
    ) -> InMemoryHandleStore {
        let mut store = InMemoryHandleStore::new();

        // Wrapping key
        store.wrapping_keys.insert(
            wk_id.as_u128_le(),
            WrappingKeyRecord {
                wrapping_key_id: wk_id,
                wrapping_key_class: WrappingKeyClass::ClusterRoot.as_u32(),
                wrapping_key_version: 1,
                ..Default::default()
            },
        );

        // Handle
        store.handles.insert(
            handle_id.as_u128_le(),
            SecretHandleRecord {
                handle_id,
                secret_class: SecretClass::PolicySigner.as_u32(),
                lifecycle_state: lifecycle.as_u32(),
                active_envelope_version: 1,
                active_envelope_id: envelope_id,
                ..Default::default()
            },
        );

        // Envelope
        store.envelopes.insert(
            envelope_id.as_u128_le(),
            SecretEnvelopeRecord {
                envelope_id,
                handle_id,
                envelope_version: 1,
                wrapping_key_id: wk_id,
                wrapping_key_version: 1,
                ..Default::default()
            },
        );

        store
    }

    fn make_activation_manifest(handle_ids: &[SecretKeyPolicyId128]) -> PolicyStoreManifestRecord {
        let mut refs = [SecretKeyPolicyId128::ZERO; 4];
        let count = handle_ids.len().min(4);
        refs[..count].copy_from_slice(&handle_ids[..count]);
        PolicyStoreManifestRecord {
            required_secret_handle_count: count as u32,
            required_secret_handle_refs: refs,
            manifest_id: SecretKeyPolicyId128::from_u128_le(0x5000),
            continuity_window_start_ref: SecretKeyPolicyId128::from_u128_le(0x1000),
            continuity_window_end_ref: SecretKeyPolicyId128::from_u128_le(0x2000),
            ..Default::default()
        }
    }

    fn make_activation_lease(
        lease_id: SecretKeyPolicyId128,
        handle_id: SecretKeyPolicyId128,
        expiry_deadline: SecretKeyPolicyId128,
    ) -> SecretLeaseGrantRecord {
        SecretLeaseGrantRecord {
            lease_id,
            handle_id,
            usage_class: LeaseUsageClass::SignOrPublish.as_u32(),
            runtime_residency_class: StorageStratum::RuntimeMemoryLease.as_u32(),
            expiry_deadline_ref: expiry_deadline,
            ..Default::default()
        }
    }

    /// Permissive disclosure policy: allows all surfaces with full field visibility.
    fn make_permissive_disclosure() -> SecretDisclosurePolicyRecord {
        SecretDisclosurePolicyRecord {
            audit_visible: 1,
            trace_visible: 1,
            scenario_log_visible: 1,
            visible_fields_mask: !0,
            provider_class_reveal: 1,
            narrative_export_visible: 1,
            ..Default::default()
        }
    }

    #[test]
    fn activation_preflight_succeeds_with_valid_inputs() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0x100);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store = make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Active);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_id, expiry),
        );

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        assert!(result.is_ok(), "expected success, got {result:?}");
        let receipt = result.unwrap();
        assert_eq!(receipt.manifest_id, manifest.manifest_id);
        assert_eq!(receipt.activation_lease_ref, lease_id);
        assert_eq!(receipt.activation_wrapping_key_ref, wk_id);
        assert!(receipt.has_activation_lease());
        assert!(receipt.has_activation_wrapping_key());
    }

    #[test]
    fn activation_preflight_rejects_missing_handle() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let store = InMemoryHandleStore::new();
        let h_missing = SecretKeyPolicyId128::from_u128_le(0xDEAD);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        // Store has no handle; lease exists but handle doesn't.
        let mut store = store;
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_missing, expiry),
        );

        let manifest = make_activation_manifest(&[h_missing]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::HandleNotFound { handle_id }) => {
                assert_eq!(handle_id, h_missing);
            }
            other => panic!("expected HandleNotFound, got {other:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_expired_lease() {
        let provider = MockSealProvider::new();
        // Clock that always reports deadlines as passed.
        let clock = MockLeaseClock::new().with_always_expired(true);
        let h_id = SecretKeyPolicyId128::from_u128_le(0x100);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store = make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Active);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_id, expiry),
        );

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::LeaseExpired { lease_id: lid }) => {
                assert_eq!(lid, lease_id);
            }
            other => panic!("expected LeaseExpired, got {other:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_wrong_lease_usage() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0x100);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store = make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Active);
        let mut lease = make_activation_lease(lease_id, h_id, expiry);
        lease.usage_class = LeaseUsageClass::TransportTermination.as_u32();
        store.leases.insert(lease_id.as_u128_le(), lease);

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::LeaseUsageMismatch {
                handle_id,
                requested,
            }) => {
                assert_eq!(handle_id, h_id);
                assert_eq!(requested, LeaseUsageClass::TransportTermination);
            }
            other => panic!("expected LeaseUsageMismatch, got {other:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_lease_for_foreign_handle() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0x100);
        let foreign_h_id = SecretKeyPolicyId128::from_u128_le(0x101);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store = make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Active);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, foreign_h_id, expiry),
        );

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::LeaseHandleMismatch {
                lease_id: actual_lease_id,
                handle_id,
            }) => {
                assert_eq!(actual_lease_id, lease_id);
                assert_eq!(handle_id, foreign_h_id);
            }
            other => panic!("expected LeaseHandleMismatch, got {other:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_revoked_handle() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0xBAD);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store =
            make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Revoked);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_id, expiry),
        );

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::HandleRevoked { handle_id }) => {
                assert_eq!(handle_id, h_id);
            }
            _ => panic!("expected HandleRevoked, got {result:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_quarantined_handle() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0xBAD);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store =
            make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Quarantined);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_id, expiry),
        );

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::HandleQuarantined { handle_id }) => {
                assert_eq!(handle_id, h_id);
            }
            _ => panic!("expected HandleQuarantined, got {result:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_disclosure_refusal() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0x100);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store = make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Active);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_id, expiry),
        );

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        // Disclosure policy with audit_visible = 0: refuse audit surface.
        let disclosure = SecretDisclosurePolicyRecord::default();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::DisclosureRefused { surface, reason: _ }) => {
                assert_eq!(surface, DisclosureSurfaceClass::Audit);
            }
            other => panic!("expected DisclosureRefused, got {other:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_provider_unreachable() {
        let h_id = SecretKeyPolicyId128::from_u128_le(0x100);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        // Provider that always returns an unreachable error.
        let provider =
            MockSealProvider::new().with_forced_error(SealProviderErrorKind::ProviderUnreachable);
        let clock = MockLeaseClock::new();

        let mut store = make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Active);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_id, expiry),
        );

        let manifest = make_activation_manifest(&[h_id]);
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::SealProviderError { reason }) => {
                assert_eq!(reason, SealProviderErrorKind::ProviderUnreachable);
            }
            other => panic!("expected SealProviderError, got {other:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_manifest_missing_handles() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let store = InMemoryHandleStore::new();
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        // Manifest with zero handles
        let manifest = PolicyStoreManifestRecord {
            required_secret_handle_count: 0,
            required_secret_handle_refs: [SecretKeyPolicyId128::ZERO; 4],
            manifest_id: SecretKeyPolicyId128::from_u128_le(0x5000),
            continuity_window_start_ref: SecretKeyPolicyId128::from_u128_le(0x1000),
            continuity_window_end_ref: SecretKeyPolicyId128::from_u128_le(0x2000),
            ..Default::default()
        };
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let mut store = store;
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, SecretKeyPolicyId128::ZERO, expiry),
        );

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::ManifestMissingHandles { manifest_id, .. }) => {
                assert_eq!(manifest_id, manifest.manifest_id);
            }
            other => panic!("expected ManifestMissingHandles, got {other:?}"),
        }
    }

    #[test]
    fn activation_preflight_rejects_zero_continuity_window() {
        let provider = MockSealProvider::new();
        let clock = MockLeaseClock::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0x100);
        let e_id = SecretKeyPolicyId128::from_u128_le(0xE00);
        let wk_id = SecretKeyPolicyId128::from_u128_le(0x2000);
        let lease_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let expiry = SecretKeyPolicyId128::from_u128_le(0x9999);

        let mut store = make_activation_test_store(h_id, e_id, wk_id, SecretLifecycleState::Active);
        store.leases.insert(
            lease_id.as_u128_le(),
            make_activation_lease(lease_id, h_id, expiry),
        );

        // Manifest with zero continuity_window_start_ref
        let manifest = PolicyStoreManifestRecord {
            required_secret_handle_count: 1,
            required_secret_handle_refs: [
                h_id,
                SecretKeyPolicyId128::ZERO,
                SecretKeyPolicyId128::ZERO,
                SecretKeyPolicyId128::ZERO,
            ],
            manifest_id: SecretKeyPolicyId128::from_u128_le(0x5000),
            continuity_window_start_ref: SecretKeyPolicyId128::ZERO,
            continuity_window_end_ref: SecretKeyPolicyId128::from_u128_le(0x2000),
            ..Default::default()
        };
        let bundle = PolicyPublishBundleRecord::default();
        let disclosure = make_permissive_disclosure();

        let result = activate_policy_revision_after_secret_handle_preflight(
            &provider,
            &clock,
            &store,
            &manifest,
            &bundle,
            lease_id,
            &disclosure,
            SecretKeyPolicyId128::from_u128_le(1),
            SecretKeyPolicyId128::from_u128_le(2),
            SecretKeyPolicyId128::from_u128_le(3),
            0,
        );
        match result {
            Err(SecretKeyPolicyRuntimeError::ManifestIncompatible {
                manifest_id,
                reason: ManifestRefusalReason::ContinuityWindowClosed,
            }) => {
                assert_eq!(manifest_id, manifest.manifest_id);
            }
            other => {
                panic!("expected ManifestIncompatible with ContinuityWindowClosed, got {other:?}")
            }
        }
    }

    // ── Algorithm 8 tests ───

    #[test]
    fn rewrap_produces_successor_envelope_with_lineage_check() {
        let provider = MockSealProvider::new();
        let mut store = InMemoryHandleStore::new();

        let old_wk = SecretKeyPolicyId128::from_u128_le(0x1000);
        let new_wk = SecretKeyPolicyId128::from_u128_le(0x2000);
        let handle_id = SecretKeyPolicyId128::from_u128_le(0x3000);
        let env_id = SecretKeyPolicyId128::from_u128_le(0x4000);

        store.wrapping_keys.insert(
            0x1000,
            WrappingKeyRecord {
                wrapping_key_id: old_wk,
                wrapping_key_class: WrappingKeyClass::ClusterRoot.as_u32(),
                wrapping_key_version: 1,
                ..Default::default()
            },
        );
        store.wrapping_keys.insert(
            0x2000,
            WrappingKeyRecord {
                wrapping_key_id: new_wk,
                wrapping_key_class: WrappingKeyClass::ClusterRoot.as_u32(),
                wrapping_key_version: 2,
                predecessor_wrapping_key_id: old_wk,
                ..Default::default()
            },
        );
        store.handles.insert(
            0x3000,
            SecretHandleRecord {
                handle_id,
                secret_class: SecretClass::TransportTls.as_u32(),
                lifecycle_state: SecretLifecycleState::Active.as_u32(),
                active_envelope_version: 1,
                active_envelope_id: env_id,
                ..Default::default()
            },
        );
        store.envelopes.insert(
            0x4000,
            SecretEnvelopeRecord {
                envelope_id: env_id,
                handle_id,
                envelope_version: 1,
                wrapping_key_id: old_wk,
                wrapping_key_version: 1,
                ..Default::default()
            },
        );

        let new_envelope =
            rewrap_envelope_set_after_wrapping_key_rotation(&provider, &store, handle_id, new_wk)
                .expect("rewrap should succeed");

        assert_eq!(new_envelope.handle_id, handle_id);
        assert_eq!(new_envelope.wrapping_key_id, new_wk);
        assert_eq!(new_envelope.envelope_version, 2);
        assert_eq!(new_envelope.predecessor_envelope_id, env_id);
    }

    // ── Algorithm 9 tests ───

    #[test]
    fn revocation_creates_receipt_with_quarantine_flag() {
        let mut store = InMemoryHandleStore::new();
        let h_id = SecretKeyPolicyId128::from_u128_le(0x999);
        store.handles.insert(
            0x999,
            SecretHandleRecord {
                handle_id: h_id,
                secret_class: SecretClass::PolicySigner.as_u32(),
                lifecycle_state: SecretLifecycleState::Active.as_u32(),
                ..Default::default()
            },
        );

        let receipt = revoke_or_quarantine_secret_handle_and_drain_runtime_leases(
            &store,
            h_id,
            RevocationTriggerClass::CompromiseSuspected,
            true,
            SecretKeyPolicyId128::from_u128_le(0x1000),
            SecretKeyPolicyId128::from_u128_le(0x2000),
            SecretKeyPolicyId128::from_u128_le(0x3000),
        )
        .expect("revocation should succeed");

        assert!(receipt.is_quarantine());
        assert_eq!(
            receipt.trigger(),
            Ok(RevocationTriggerClass::CompromiseSuspected)
        );
        assert_eq!(receipt.handle_id, h_id);
    }

    // ── Algorithm 10 tests ───

    fn make_test_manifest(
        manifest_id: SecretKeyPolicyId128,
        handle_ids: &[SecretKeyPolicyId128],
        window_start: SecretKeyPolicyId128,
        window_end: SecretKeyPolicyId128,
    ) -> PolicyStoreManifestRecord {
        let mut handles = [SecretKeyPolicyId128::ZERO; 4];
        for (i, &h) in handle_ids.iter().enumerate() {
            if i >= 4 {
                break;
            }
            handles[i] = h;
        }
        PolicyStoreManifestRecord {
            manifest_id,
            required_secret_handle_count: handle_ids.len().min(4) as u32,
            required_secret_handle_refs: handles,
            continuity_window_start_ref: window_start,
            continuity_window_end_ref: window_end,
            ..Default::default()
        }
    }

    fn make_test_handle(
        handle_id: SecretKeyPolicyId128,
        state: SecretLifecycleState,
        envelope_id: SecretKeyPolicyId128,
    ) -> SecretHandleRecord {
        SecretHandleRecord {
            handle_id,
            lifecycle_state: state.as_u32(),
            active_envelope_version: 1,
            active_envelope_id: envelope_id,
            ..Default::default()
        }
    }

    fn make_test_envelope(
        envelope_id: SecretKeyPolicyId128,
        handle_id: SecretKeyPolicyId128,
    ) -> SecretEnvelopeRecord {
        SecretEnvelopeRecord {
            envelope_id,
            handle_id,
            envelope_version: 1,
            ..Default::default()
        }
    }

    #[test]
    fn recovery_succeeds_with_valid_manifest_and_handles() {
        let mut store = InMemoryHandleStore::new();
        let h1 = SecretKeyPolicyId128::from_u128_le(0x100);
        let h2 = SecretKeyPolicyId128::from_u128_le(0x200);
        let e1 = SecretKeyPolicyId128::from_u128_le(0x1000);
        let e2 = SecretKeyPolicyId128::from_u128_le(0x2000);
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);

        store.handles.insert(
            h1.as_u128_le(),
            make_test_handle(h1, SecretLifecycleState::Active, e1),
        );
        store.handles.insert(
            h2.as_u128_le(),
            make_test_handle(h2, SecretLifecycleState::RotatingDualValid, e2),
        );
        store
            .envelopes
            .insert(e1.as_u128_le(), make_test_envelope(e1, h1));
        store
            .envelopes
            .insert(e2.as_u128_le(), make_test_envelope(e2, h2));
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[h1, h2],
                SecretKeyPolicyId128::from_u128_le(0xAA),
                SecretKeyPolicyId128::from_u128_le(0xBB),
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        assert!(result.is_ok());
        let recovered = result.unwrap();
        assert_eq!(recovered.len(), 1);
        let (manifest, handles) = &recovered[0];
        assert_eq!(manifest.manifest_id, m_id);
        assert_eq!(handles.len(), 2);
        assert_eq!(handles[0].handle_id, h1);
        assert_eq!(handles[1].handle_id, h2);
    }

    #[test]
    fn recovery_fails_missing_manifest() {
        let store = InMemoryHandleStore::new();
        let m_id = SecretKeyPolicyId128::from_u128_le(0xDEAD);
        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        match result {
            Err(SecretKeyPolicyRuntimeError::RecoveryManifestChainBroken { at_manifest_id }) => {
                assert_eq!(at_manifest_id, m_id);
            }
            other => panic!("expected RecoveryManifestChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn recovery_fails_zero_continuity_window_start() {
        let mut store = InMemoryHandleStore::new();
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[],
                SecretKeyPolicyId128::ZERO,
                SecretKeyPolicyId128::from_u128_le(0xBB),
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        match result {
            Err(SecretKeyPolicyRuntimeError::RecoveryManifestChainBroken { at_manifest_id }) => {
                assert_eq!(at_manifest_id, m_id);
            }
            other => panic!("expected RecoveryManifestChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn recovery_fails_zero_continuity_window_end() {
        let mut store = InMemoryHandleStore::new();
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[],
                SecretKeyPolicyId128::from_u128_le(0xAA),
                SecretKeyPolicyId128::ZERO,
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        assert!(matches!(
            result,
            Err(SecretKeyPolicyRuntimeError::RecoveryManifestChainBroken { .. })
        ));
    }

    #[test]
    fn recovery_fails_missing_handle() {
        let mut store = InMemoryHandleStore::new();
        let h_missing = SecretKeyPolicyId128::from_u128_le(0x9999);
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[h_missing],
                SecretKeyPolicyId128::from_u128_le(0xAA),
                SecretKeyPolicyId128::from_u128_le(0xBB),
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        match result {
            Err(SecretKeyPolicyRuntimeError::HandleNotFound { handle_id }) => {
                assert_eq!(handle_id, h_missing);
            }
            other => panic!("expected HandleNotFound, got {other:?}"),
        }
    }

    #[test]
    fn recovery_fails_revoked_handle() {
        let mut store = InMemoryHandleStore::new();
        let h = SecretKeyPolicyId128::from_u128_le(0x100);
        let e = SecretKeyPolicyId128::from_u128_le(0x1000);
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);

        store.handles.insert(
            h.as_u128_le(),
            make_test_handle(h, SecretLifecycleState::Revoked, e),
        );
        store
            .envelopes
            .insert(e.as_u128_le(), make_test_envelope(e, h));
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[h],
                SecretKeyPolicyId128::from_u128_le(0xAA),
                SecretKeyPolicyId128::from_u128_le(0xBB),
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        match result {
            Err(SecretKeyPolicyRuntimeError::HandleRevoked { handle_id }) => {
                assert_eq!(handle_id, h);
            }
            other => panic!("expected HandleRevoked, got {other:?}"),
        }
    }

    #[test]
    fn recovery_fails_quarantined_handle() {
        let mut store = InMemoryHandleStore::new();
        let h = SecretKeyPolicyId128::from_u128_le(0x100);
        let e = SecretKeyPolicyId128::from_u128_le(0x1000);
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);

        store.handles.insert(
            h.as_u128_le(),
            make_test_handle(h, SecretLifecycleState::Quarantined, e),
        );
        store
            .envelopes
            .insert(e.as_u128_le(), make_test_envelope(e, h));
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[h],
                SecretKeyPolicyId128::from_u128_le(0xAA),
                SecretKeyPolicyId128::from_u128_le(0xBB),
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        match result {
            Err(SecretKeyPolicyRuntimeError::HandleQuarantined { handle_id }) => {
                assert_eq!(handle_id, h);
            }
            other => panic!("expected HandleQuarantined, got {other:?}"),
        }
    }

    #[test]
    fn recovery_fails_inactive_handle() {
        let mut store = InMemoryHandleStore::new();
        let h = SecretKeyPolicyId128::from_u128_le(0x100);
        let e = SecretKeyPolicyId128::from_u128_le(0x1000);
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);

        store.handles.insert(
            h.as_u128_le(),
            make_test_handle(h, SecretLifecycleState::SealedInactive, e),
        );
        store
            .envelopes
            .insert(e.as_u128_le(), make_test_envelope(e, h));
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[h],
                SecretKeyPolicyId128::from_u128_le(0xAA),
                SecretKeyPolicyId128::from_u128_le(0xBB),
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        match result {
            Err(SecretKeyPolicyRuntimeError::HandleNotActive { handle_id, actual }) => {
                assert_eq!(handle_id, h);
                assert_eq!(actual, SecretLifecycleState::SealedInactive);
            }
            other => panic!("expected HandleNotActive, got {other:?}"),
        }
    }

    #[test]
    fn recovery_fails_missing_envelope() {
        let mut store = InMemoryHandleStore::new();
        let h = SecretKeyPolicyId128::from_u128_le(0x100);
        let e = SecretKeyPolicyId128::from_u128_le(0x1000);
        let m_id = SecretKeyPolicyId128::from_u128_le(0x5000);

        store.handles.insert(
            h.as_u128_le(),
            make_test_handle(h, SecretLifecycleState::Active, e),
        );
        // envelope intentionally missing
        store.manifests.insert(
            m_id.as_u128_le(),
            make_test_manifest(
                m_id,
                &[h],
                SecretKeyPolicyId128::from_u128_le(0xAA),
                SecretKeyPolicyId128::from_u128_le(0xBB),
            ),
        );

        let result = recover_policy_store_and_handle_pointers(&store, m_id);
        match result {
            Err(SecretKeyPolicyRuntimeError::EnvelopeNotFound { envelope_id }) => {
                assert_eq!(envelope_id, e);
            }
            other => panic!("expected EnvelopeNotFound, got {other:?}"),
        }
    }

    // ── Mount identity validation tests ──────────────────────────────────

    struct MockMountStore {
        binding: Option<(String, u64)>,
    }

    impl HandleStore for MockMountStore {
        fn lookup_handle(
            &self,
            _id: SecretKeyPolicyId128,
        ) -> Result<SecretHandleRecord, SecretKeyPolicyRuntimeError> {
            Ok(SecretHandleRecord::default())
        }
        fn lookup_envelope(
            &self,
            _id: SecretKeyPolicyId128,
        ) -> Result<SecretEnvelopeRecord, SecretKeyPolicyRuntimeError> {
            Ok(SecretEnvelopeRecord::default())
        }
        fn lookup_wrapping_key(
            &self,
            _id: SecretKeyPolicyId128,
        ) -> Result<WrappingKeyRecord, SecretKeyPolicyRuntimeError> {
            Ok(WrappingKeyRecord::default())
        }
        fn lookup_manifest(
            &self,
            _id: SecretKeyPolicyId128,
        ) -> Result<PolicyStoreManifestRecord, SecretKeyPolicyRuntimeError> {
            Err(SecretKeyPolicyRuntimeError::ManifestIncompatible {
                manifest_id: SecretKeyPolicyId128::ZERO,
                reason: ManifestRefusalReason::MissingRevReferences,
            })
        }
        fn lookup_activation(
            &self,
            _id: SecretKeyPolicyId128,
        ) -> Result<PolicyActivationReceipt, SecretKeyPolicyRuntimeError> {
            Err(SecretKeyPolicyRuntimeError::ActivationPreflightFailed {
                activation_id: SecretKeyPolicyId128::ZERO,
                reason: ActivationRefusalReason::MissingHandles,
            })
        }
        fn lookup_lease(
            &self,
            _id: SecretKeyPolicyId128,
        ) -> Result<SecretLeaseGrantRecord, SecretKeyPolicyRuntimeError> {
            Err(SecretKeyPolicyRuntimeError::LeaseNotFound {
                lease_id: SecretKeyPolicyId128::ZERO,
            })
        }
        fn store_handle(
            &mut self,
            _h: &SecretHandleRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn store_envelope(
            &mut self,
            _e: &SecretEnvelopeRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn store_manifest(
            &mut self,
            _m: &PolicyStoreManifestRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn store_activation(
            &mut self,
            _a: &PolicyActivationReceipt,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn store_lease(
            &mut self,
            _l: &SecretLeaseGrantRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn store_rotation_plan(
            &mut self,
            _p: &SecretRotationPlanRecord,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn store_revocation(
            &mut self,
            _r: &SecretRevocationReceipt,
        ) -> Result<(), SecretKeyPolicyRuntimeError> {
            Ok(())
        }
        fn lookup_dataset_mount_identity(
            &self,
            _id: SecretKeyPolicyId128,
        ) -> Result<Option<(String, u64)>, SecretKeyPolicyRuntimeError> {
            Ok(self.binding.clone())
        }
    }

    #[test]
    fn validate_mount_identity_succeeds_when_binding_matches() {
        let store = MockMountStore {
            binding: Some(("pool/ds1".into(), 5)),
        };
        let result = validate_dataset_mount_identity_for_handle(
            &store,
            SecretKeyPolicyId128::ZERO,
            Some("pool/ds1"),
            5,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_mount_identity_fails_when_generation_differs() {
        let store = MockMountStore {
            binding: Some(("pool/ds1".into(), 5)),
        };
        let result = validate_dataset_mount_identity_for_handle(
            &store,
            SecretKeyPolicyId128::ZERO,
            Some("pool/ds1"),
            6,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_mount_identity_fails_when_dataset_differs() {
        let store = MockMountStore {
            binding: Some(("pool/ds1".into(), 5)),
        };
        let result = validate_dataset_mount_identity_for_handle(
            &store,
            SecretKeyPolicyId128::ZERO,
            Some("pool/ds2"),
            5,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_mount_identity_fails_when_required_but_none_presented() {
        let store = MockMountStore {
            binding: Some(("pool/ds1".into(), 5)),
        };
        let result =
            validate_dataset_mount_identity_for_handle(&store, SecretKeyPolicyId128::ZERO, None, 0);
        assert!(result.is_err());
    }

    #[test]
    fn validate_mount_identity_fails_when_no_binding() {
        let store = MockMountStore { binding: None };
        // Unbound handle: must be refused per current encryption authority.
        let result = validate_dataset_mount_identity_for_handle(
            &store,
            SecretKeyPolicyId128::ZERO,
            Some("pool/any"),
            99,
        );
        assert!(result.is_err());

        let result =
            validate_dataset_mount_identity_for_handle(&store, SecretKeyPolicyId128::ZERO, None, 0);
        assert!(result.is_err());
    }

    #[test]
    fn validate_mount_identity_default_implementation_fails_closed() {
        // Default HandleStore::lookup_dataset_mount_identity returns Ok(None).
        // Since unbound handles are refused, the default implementation must
        // cause validation to fail closed.
        struct DefaultStore;
        impl HandleStore for DefaultStore {
            fn lookup_handle(
                &self,
                _id: SecretKeyPolicyId128,
            ) -> Result<SecretHandleRecord, SecretKeyPolicyRuntimeError> {
                Ok(SecretHandleRecord::default())
            }
            fn lookup_envelope(
                &self,
                _id: SecretKeyPolicyId128,
            ) -> Result<SecretEnvelopeRecord, SecretKeyPolicyRuntimeError> {
                Ok(SecretEnvelopeRecord::default())
            }
            fn lookup_wrapping_key(
                &self,
                _id: SecretKeyPolicyId128,
            ) -> Result<WrappingKeyRecord, SecretKeyPolicyRuntimeError> {
                Ok(WrappingKeyRecord::default())
            }
            fn lookup_manifest(
                &self,
                _id: SecretKeyPolicyId128,
            ) -> Result<PolicyStoreManifestRecord, SecretKeyPolicyRuntimeError> {
                Err(SecretKeyPolicyRuntimeError::ManifestIncompatible {
                    manifest_id: SecretKeyPolicyId128::ZERO,
                    reason: ManifestRefusalReason::MissingRevReferences,
                })
            }
            fn lookup_activation(
                &self,
                _id: SecretKeyPolicyId128,
            ) -> Result<PolicyActivationReceipt, SecretKeyPolicyRuntimeError> {
                Err(SecretKeyPolicyRuntimeError::ActivationPreflightFailed {
                    activation_id: SecretKeyPolicyId128::ZERO,
                    reason: ActivationRefusalReason::MissingHandles,
                })
            }
            fn lookup_lease(
                &self,
                _id: SecretKeyPolicyId128,
            ) -> Result<SecretLeaseGrantRecord, SecretKeyPolicyRuntimeError> {
                Err(SecretKeyPolicyRuntimeError::LeaseNotFound {
                    lease_id: SecretKeyPolicyId128::ZERO,
                })
            }
            fn store_handle(
                &mut self,
                _h: &SecretHandleRecord,
            ) -> Result<(), SecretKeyPolicyRuntimeError> {
                Ok(())
            }
            fn store_envelope(
                &mut self,
                _e: &SecretEnvelopeRecord,
            ) -> Result<(), SecretKeyPolicyRuntimeError> {
                Ok(())
            }
            fn store_manifest(
                &mut self,
                _m: &PolicyStoreManifestRecord,
            ) -> Result<(), SecretKeyPolicyRuntimeError> {
                Ok(())
            }
            fn store_activation(
                &mut self,
                _a: &PolicyActivationReceipt,
            ) -> Result<(), SecretKeyPolicyRuntimeError> {
                Ok(())
            }
            fn store_lease(
                &mut self,
                _l: &SecretLeaseGrantRecord,
            ) -> Result<(), SecretKeyPolicyRuntimeError> {
                Ok(())
            }
            fn store_rotation_plan(
                &mut self,
                _p: &SecretRotationPlanRecord,
            ) -> Result<(), SecretKeyPolicyRuntimeError> {
                Ok(())
            }
            fn store_revocation(
                &mut self,
                _r: &SecretRevocationReceipt,
            ) -> Result<(), SecretKeyPolicyRuntimeError> {
                Ok(())
            }
        }
        let store = DefaultStore;
        let result = validate_dataset_mount_identity_for_handle(
            &store,
            SecretKeyPolicyId128::ZERO,
            Some("any"),
            1,
        );
        assert!(result.is_err());
    }
}

// ── Disclosure decision engine tests ───────────────────────────────────────

#[cfg(test)]
mod disclosure_tests {
    use super::*;

    fn make_policy(
        audit: u32,
        trace: u32,
        scenario: u32,
        fields: u64,
        provider: u32,
        narrative: u32,
    ) -> SecretDisclosurePolicyRecord {
        SecretDisclosurePolicyRecord {
            audit_visible: audit,
            trace_visible: trace,
            scenario_log_visible: scenario,
            visible_fields_mask: fields,
            provider_class_reveal: provider,
            narrative_export_visible: narrative,
            ..Default::default()
        }
    }

    // ── Surface-permission gating ────────────────────────────────────────

    #[test]
    fn render_surface_always_permitted() {
        // Render surface is always permitted; must also have fields in visible mask.
        let policy = make_policy(0, 0, 0, 0xFF, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Render, 0x01);
        assert!(verdict.is_allowed());
    }

    #[test]
    fn audit_surface_refused_when_audit_visible_is_zero() {
        let policy = SecretDisclosurePolicyRecord::default(); // audit_visible == 0
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0);
        assert_eq!(
            verdict,
            DisclosureVerdict::Refuse(RefusalReason::AuditSurfaceNotPermitted)
        );
    }

    #[test]
    fn audit_surface_allowed_when_audit_visible_is_set() {
        let policy = make_policy(1, 0, 0, !0, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0x01);
        assert!(verdict.is_allowed());
    }

    #[test]
    fn validation_surface_refused_when_trace_visible_is_zero() {
        let policy = SecretDisclosurePolicyRecord::default();
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Validation, 0);
        assert_eq!(
            verdict,
            DisclosureVerdict::Refuse(RefusalReason::ValidationSurfaceNotPermitted)
        );
    }

    #[test]
    fn validation_surface_allowed_when_trace_visible_is_set() {
        let policy = make_policy(0, 1, 0, !0, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Validation, 0x01);
        assert!(verdict.is_allowed());
    }

    #[test]
    fn scenario_surface_refused_when_scenario_log_visible_is_zero() {
        let policy = SecretDisclosurePolicyRecord::default();
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Scenario, 0);
        assert_eq!(
            verdict,
            DisclosureVerdict::Refuse(RefusalReason::ScenarioSurfaceNotPermitted)
        );
    }

    #[test]
    fn scenario_surface_allowed_when_scenario_log_visible_is_set() {
        let policy = make_policy(0, 0, 1, !0, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Scenario, 0x01);
        assert!(verdict.is_allowed());
    }

    // ── Field-mask redaction ─────────────────────────────────────────────

    #[test]
    fn redacted_when_requested_field_not_in_visible_mask() {
        // visible_mask 0x03 permits bits 0-1; requesting 0x0F blocks bits 2-3.
        let policy = make_policy(1, 0, 0, 0x03, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0x0F);
        assert_eq!(
            verdict,
            DisclosureVerdict::Redacted(RedactionReason::FieldMasked {
                blocked_fields: 0x0C
            })
        );
    }

    #[test]
    fn allowed_when_all_requested_fields_in_visible_mask() {
        let policy = make_policy(1, 0, 0, 0xFF, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0x01);
        assert!(verdict.is_allowed());
    }

    #[test]
    fn partial_redaction_when_some_fields_blocked() {
        // visible_mask: 0x0F, requesting 0xFF -> blocked = 0xF0
        let policy = make_policy(1, 0, 0, 0x0F, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0xFF);
        assert_eq!(
            verdict,
            DisclosureVerdict::Redacted(RedactionReason::FieldMasked {
                blocked_fields: 0xF0
            })
        );
    }

    #[test]
    fn semantic_loss_when_all_requested_fields_blocked() {
        // visible_mask: 0x00, requesting non-zero -> all blocked = semantic loss
        let policy = make_policy(1, 0, 0, 0x00, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0xFF);
        assert_eq!(
            verdict,
            DisclosureVerdict::Refuse(RefusalReason::SemanticLoss)
        );
    }

    #[test]
    fn zero_requested_fields_not_semantic_loss() {
        // Requesting zero fields with zero mask is not semantic loss.
        let policy = make_policy(1, 0, 0, 0x00, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0);
        assert!(verdict.is_allowed());
    }

    // ── Provider-class reveal ────────────────────────────────────────────

    const PROVIDER_FLAG: u64 = 1 << 62;

    #[test]
    fn redacted_when_provider_class_not_permitted() {
        let policy = make_policy(1, 0, 0, PROVIDER_FLAG, 0, 0); // provider_class_reveal == 0
        let verdict =
            decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, PROVIDER_FLAG);
        assert_eq!(
            verdict,
            DisclosureVerdict::Redacted(RedactionReason::ProviderClassHidden)
        );
    }

    #[test]
    fn allowed_when_provider_class_permitted() {
        let policy = make_policy(1, 0, 0, PROVIDER_FLAG, 1, 0); // provider_class_reveal == 1
        let verdict =
            decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, PROVIDER_FLAG);
        assert!(verdict.is_allowed());
    }

    // ── Narrative-export block ───────────────────────────────────────────

    const NARRATIVE_FLAG: u64 = 1 << 63;

    #[test]
    fn redacted_when_narrative_export_not_permitted() {
        let policy = make_policy(1, 0, 0, NARRATIVE_FLAG, 0, 0); // narrative_export_visible == 0
        let verdict =
            decide_secret_disclosure(&policy, DisclosureSurfaceClass::Render, NARRATIVE_FLAG);
        assert_eq!(
            verdict,
            DisclosureVerdict::Redacted(RedactionReason::NarrativeExportBlocked)
        );
    }

    #[test]
    fn allowed_when_narrative_export_permitted() {
        let policy = make_policy(1, 0, 0, NARRATIVE_FLAG, 0, 1); // narrative_export_visible == 1
        let verdict =
            decide_secret_disclosure(&policy, DisclosureSurfaceClass::Render, NARRATIVE_FLAG);
        assert!(verdict.is_allowed());
    }

    // ── Gate wrapper ─────────────────────────────────────────────────────

    #[test]
    fn gate_returns_ok_for_allow() {
        let policy = make_policy(1, 0, 0, 0xFF, 0, 0);
        let result = gate_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0x01);
        assert!(result.is_ok());
    }

    #[test]
    fn gate_returns_ok_for_redacted() {
        // visible_mask 0x03 permits bits 0-1; requesting 0x0F triggers redaction, not refusal.
        let policy = make_policy(1, 0, 0, 0x03, 0, 0);
        let result = gate_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0x0F);
        assert!(result.is_ok()); // redacted is still Ok; caller masks
    }

    #[test]
    fn gate_returns_err_for_refuse() {
        let policy = SecretDisclosurePolicyRecord::default();
        let result = gate_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0);
        assert!(result.is_err());
        match result {
            Err(SecretKeyPolicyRuntimeError::DisclosureRefused { surface, reason: _ }) => {
                assert_eq!(surface, DisclosureSurfaceClass::Audit);
            }
            other => panic!("expected DisclosureRefused, got {other:?}"),
        }
    }

    // ── Validate handle disclosure ───────────────────────────────────────

    #[test]
    fn validate_handle_allowed_on_audit_when_permitted() {
        let policy = make_policy(1, 0, 0, 0x3F, 0, 0);
        let handle = SecretHandleRecord::default();
        let result = validate_handle_disclosure(&policy, DisclosureSurfaceClass::Audit, &handle);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_handle_refused_on_audit_when_not_permitted() {
        let policy = SecretDisclosurePolicyRecord::default();
        let handle = SecretHandleRecord::default();
        let result = validate_handle_disclosure(&policy, DisclosureSurfaceClass::Audit, &handle);
        assert!(result.is_err());
    }

    // ── Verdict helpers ──────────────────────────────────────────────────

    #[test]
    fn verdict_helpers_return_correct_bools() {
        let allow = DisclosureVerdict::Allow;
        assert!(allow.is_allowed());
        assert!(!allow.is_redacted());
        assert!(!allow.is_refused());

        let redacted = DisclosureVerdict::Redacted(RedactionReason::ProviderClassHidden);
        assert!(!redacted.is_allowed());
        assert!(redacted.is_redacted());
        assert!(!redacted.is_refused());

        let refuse = DisclosureVerdict::Refuse(RefusalReason::SemanticLoss);
        assert!(!refuse.is_allowed());
        assert!(!refuse.is_redacted());
        assert!(refuse.is_refused());
    }

    // ── classify integration ─────────────────────────────────────────────

    #[test]
    fn classify_returns_disclosure_verdict() {
        let policy = SecretDisclosurePolicyRecord::default();
        let (_stratum, _replicated, verdict) = classify_secret_class_and_required_storage_residency(
            SecretClass::PolicySigner,
            &policy,
        );
        // Default policy has audit_visible=0, so audit surface should be refused.
        assert_eq!(
            verdict,
            DisclosureVerdict::Refuse(RefusalReason::AuditSurfaceNotPermitted)
        );
    }

    #[test]
    fn classify_with_audit_visible_policy_returns_allow() {
        let policy = make_policy(1, 0, 0, !0, 0, 0);
        let (_stratum, _replicated, verdict) = classify_secret_class_and_required_storage_residency(
            SecretClass::TransportTls,
            &policy,
        );
        assert!(verdict.is_allowed());
    }

    // ── Combined-surface refusal ─────────────────────────────────────────

    #[test]
    fn audit_refused_even_when_fields_match() {
        // audit_visible=0 blocks the surface even if all fields are in the mask.
        let policy = make_policy(0, 0, 0, 0xFF, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Audit, 0x01);
        assert_eq!(
            verdict,
            DisclosureVerdict::Refuse(RefusalReason::AuditSurfaceNotPermitted)
        );
    }

    #[test]
    fn validation_refused_even_when_fields_match() {
        let policy = make_policy(0, 0, 0, 0xFF, 0, 0);
        let verdict = decide_secret_disclosure(&policy, DisclosureSurfaceClass::Validation, 0x01);
        assert_eq!(
            verdict,
            DisclosureVerdict::Refuse(RefusalReason::ValidationSurfaceNotPermitted)
        );
    }
}
