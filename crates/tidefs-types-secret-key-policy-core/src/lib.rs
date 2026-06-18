// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Portable `no_std` `secret_key_policy_0` enums and fixed-width record types.
//!
//! This crate owns the stable enums, lifecycle states, and fixed-width records
//! for the P9-04 secret-key-policy law: 6 secret classes, 4 storage strata,
//! 7 lifecycle states, handle-not-bytes, lease/rotation/revocation, and
//! policy-store chain.

use core::convert::TryFrom;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecretKeyPolicyId128(pub [u8; 16]);

impl SecretKeyPolicyId128 {
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn from_u128_le(value: u128) -> Self {
        Self(value.to_le_bytes())
    }

    #[must_use]
    pub const fn as_u128_le(self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

pub type SecretKeyPolicyDigest32 = [u8; 32];

// ── Secret class ───────────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SecretClass {
    PolicySigner = 0,
    ServiceIdentity = 1,
    TransportTls = 2,
    NodeJoinBootstrap = 3,
    EnvelopeWrapping = 4,
    SessionMintSeed = 5,
}

impl SecretClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicySigner => "secret.secret_key_policy_0.policy_signer",
            Self::ServiceIdentity => "secret.secret_key_policy_0.service_identity",
            Self::TransportTls => "secret.secret_key_policy_0.transport_tls",
            Self::NodeJoinBootstrap => "secret.secret_key_policy_0.node_join_bootstrap",
            Self::EnvelopeWrapping => "secret.secret_key_policy_0.envelope_wrapping",
            Self::SessionMintSeed => "secret.secret_key_policy_0.session_mint_seed",
        }
    }
}

impl Default for SecretClass {
    fn default() -> Self {
        Self::PolicySigner
    }
}

impl TryFrom<u32> for SecretClass {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PolicySigner),
            1 => Ok(Self::ServiceIdentity),
            2 => Ok(Self::TransportTls),
            3 => Ok(Self::NodeJoinBootstrap),
            4 => Ok(Self::EnvelopeWrapping),
            5 => Ok(Self::SessionMintSeed),
            _ => Err(SecretKeyPolicyDecodeError::InvalidSecretClass(value)),
        }
    }
}

// ── Storage stratum ────────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StorageStratum {
    SealedAuthoritative = 0,
    NodeSealedCache = 1,
    RuntimeMemoryLease = 2,
    RuntimeKeyringLease = 3,

    /// P9-04 stratum s4: external hardware security module.
    /// Plaintext lives inside the HSM boundary; the HSM drives
    /// sealing/unsealing operations through a provider adapter.
    ExternalHsm = 4,
}

impl StorageStratum {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SealedAuthoritative => "store.secret_key_policy_0.sealed_authoritative.s0",
            Self::NodeSealedCache => "store.secret_key_policy_0.node_sealed_cache.s1",
            Self::RuntimeMemoryLease => "store.secret_key_policy_0.runtime_memory_lease.s2",
            Self::RuntimeKeyringLease => "store.secret_key_policy_0.runtime_keyring_lease.s3",
            Self::ExternalHsm => "store.secret_key_policy_0.external_hsm.s4",
        }
    }

    #[must_use]
    pub const fn allows_plaintext(self) -> bool {
        matches!(
            self,
            Self::RuntimeMemoryLease | Self::RuntimeKeyringLease | Self::ExternalHsm
        )
    }

    #[must_use]
    pub const fn is_external_provider(self) -> bool {
        matches!(self, Self::ExternalHsm)
    }

    #[must_use]
    pub const fn is_replicated(self) -> bool {
        matches!(self, Self::SealedAuthoritative)
    }
}

impl Default for StorageStratum {
    fn default() -> Self {
        Self::SealedAuthoritative
    }
}

impl TryFrom<u32> for StorageStratum {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SealedAuthoritative),
            1 => Ok(Self::NodeSealedCache),
            2 => Ok(Self::RuntimeMemoryLease),
            3 => Ok(Self::RuntimeKeyringLease),
            4 => Ok(Self::ExternalHsm),
            _ => Err(SecretKeyPolicyDecodeError::InvalidStorageStratum(value)),
        }
    }
}

// ── Secret lifecycle state ─────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SecretLifecycleState {
    SealedInactive = 0,
    Active = 1,
    RotatingDualValid = 2,
    Revoked = 3,
    Quarantined = 4,
    Retired = 5,
}

impl SecretLifecycleState {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SealedInactive => "state.secret_key_policy_0.sealed_inactive",
            Self::Active => "state.secret_key_policy_0.active",
            Self::RotatingDualValid => "state.secret_key_policy_0.rotating_dual_valid",
            Self::Revoked => "state.secret_key_policy_0.revoked",
            Self::Quarantined => "state.secret_key_policy_0.quarantined",
            Self::Retired => "state.secret_key_policy_0.retired",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Retired)
    }

    #[must_use]
    pub const fn blocks_lease_issuance(self) -> bool {
        matches!(self, Self::Revoked | Self::Quarantined | Self::Retired)
    }

    #[must_use]
    pub const fn is_active_or_rotating(self) -> bool {
        matches!(self, Self::Active | Self::RotatingDualValid)
    }
}

impl Default for SecretLifecycleState {
    fn default() -> Self {
        Self::SealedInactive
    }
}

impl TryFrom<u32> for SecretLifecycleState {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SealedInactive),
            1 => Ok(Self::Active),
            2 => Ok(Self::RotatingDualValid),
            3 => Ok(Self::Revoked),
            4 => Ok(Self::Quarantined),
            5 => Ok(Self::Retired),
            _ => Err(SecretKeyPolicyDecodeError::InvalidLifecycleState(value)),
        }
    }
}

// ── Lease usage class ──────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LeaseUsageClass {
    SignOrPublish = 0,
    TransportTermination = 1,
    MutualAuth = 2,
    EnvelopeUnwrap = 3,
    SessionMint = 4,
    BootstrapOrJoin = 5,
}

impl LeaseUsageClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignOrPublish => "usage.secret_key_policy_0.sign_or_publish.u0",
            Self::TransportTermination => "usage.secret_key_policy_0.transport_termination.u1",
            Self::MutualAuth => "usage.secret_key_policy_0.mutual_auth.u2",
            Self::EnvelopeUnwrap => "usage.secret_key_policy_0.envelope_unwrap.u3",
            Self::SessionMint => "usage.secret_key_policy_0.session_mint.u4",
            Self::BootstrapOrJoin => "usage.secret_key_policy_0.bootstrap_or_join.u5",
        }
    }
}

impl Default for LeaseUsageClass {
    fn default() -> Self {
        Self::SignOrPublish
    }
}

impl TryFrom<u32> for LeaseUsageClass {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SignOrPublish),
            1 => Ok(Self::TransportTermination),
            2 => Ok(Self::MutualAuth),
            3 => Ok(Self::EnvelopeUnwrap),
            4 => Ok(Self::SessionMint),
            5 => Ok(Self::BootstrapOrJoin),
            _ => Err(SecretKeyPolicyDecodeError::InvalidLeaseUsageClass(value)),
        }
    }
}

// ── Refusal class ──────────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SecretKeyPolicyRefusalClass {
    MissingHandle = 0,
    RevokedHandle = 1,
    QuarantinedHandle = 2,
    ProviderUnreachable = 3,
    ManifestIncompatible = 4,
    DisclosureViolation = 5,
}

impl SecretKeyPolicyRefusalClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingHandle => "refusal.secret_key_policy_0.missing_handle",
            Self::RevokedHandle => "refusal.secret_key_policy_0.revoked_handle",
            Self::QuarantinedHandle => "refusal.secret_key_policy_0.quarantined_handle",
            Self::ProviderUnreachable => "refusal.secret_key_policy_0.provider_unreachable",
            Self::ManifestIncompatible => "refusal.secret_key_policy_0.manifest_incompatible",
            Self::DisclosureViolation => "refusal.secret_key_policy_0.disclosure_violation",
        }
    }
}

impl Default for SecretKeyPolicyRefusalClass {
    fn default() -> Self {
        Self::MissingHandle
    }
}

impl TryFrom<u32> for SecretKeyPolicyRefusalClass {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MissingHandle),
            1 => Ok(Self::RevokedHandle),
            2 => Ok(Self::QuarantinedHandle),
            3 => Ok(Self::ProviderUnreachable),
            4 => Ok(Self::ManifestIncompatible),
            5 => Ok(Self::DisclosureViolation),
            _ => Err(SecretKeyPolicyDecodeError::InvalidRefusalClass(value)),
        }
    }
}

// ── Wrapping key class ─────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WrappingKeyClass {
    ClusterRoot = 0,
    ScopeDomain = 1,
    LeafEnvelope = 2,
}

impl WrappingKeyClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClusterRoot => "wrapping.secret_key_policy_0.cluster_root.w0",
            Self::ScopeDomain => "wrapping.secret_key_policy_0.scope_domain.w1",
            Self::LeafEnvelope => "wrapping.secret_key_policy_0.leaf_envelope.w2",
        }
    }
}

impl Default for WrappingKeyClass {
    fn default() -> Self {
        Self::ClusterRoot
    }
}

impl TryFrom<u32> for WrappingKeyClass {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ClusterRoot),
            1 => Ok(Self::ScopeDomain),
            2 => Ok(Self::LeafEnvelope),
            _ => Err(SecretKeyPolicyDecodeError::InvalidWrappingKeyClass(value)),
        }
    }
}

// ── Rotation class ─────────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RotationClass {
    Standard = 0,
    DualValidity = 1,
    Emergency = 2,
}

impl RotationClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "rotation.secret_key_policy_0.standard.r0",
            Self::DualValidity => "rotation.secret_key_policy_0.dual_validity.r1",
            Self::Emergency => "rotation.secret_key_policy_0.emergency.r2",
        }
    }

    #[must_use]
    pub const fn allows_dual_validity(self) -> bool {
        matches!(self, Self::DualValidity)
    }
}

impl Default for RotationClass {
    fn default() -> Self {
        Self::Standard
    }
}

impl TryFrom<u32> for RotationClass {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Standard),
            1 => Ok(Self::DualValidity),
            2 => Ok(Self::Emergency),
            _ => Err(SecretKeyPolicyDecodeError::InvalidRotationClass(value)),
        }
    }
}

// ── Revocation trigger class ───────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RevocationTriggerClass {
    OperatorRequested = 0,
    CompromiseSuspected = 1,
    RotationFailure = 2,
    NodeDrain = 3,
    AuditEscalation = 4,
}

impl RevocationTriggerClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorRequested => "trigger.secret_key_policy_0.operator_requested.t0",
            Self::CompromiseSuspected => "trigger.secret_key_policy_0.compromise_suspected.t1",
            Self::RotationFailure => "trigger.secret_key_policy_0.rotation_failure.t2",
            Self::NodeDrain => "trigger.secret_key_policy_0.node_drain.t3",
            Self::AuditEscalation => "trigger.secret_key_policy_0.audit_escalation.t4",
        }
    }
}

impl Default for RevocationTriggerClass {
    fn default() -> Self {
        Self::OperatorRequested
    }
}

impl TryFrom<u32> for RevocationTriggerClass {
    type Error = SecretKeyPolicyDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::OperatorRequested),
            1 => Ok(Self::CompromiseSuspected),
            2 => Ok(Self::RotationFailure),
            3 => Ok(Self::NodeDrain),
            4 => Ok(Self::AuditEscalation),
            _ => Err(SecretKeyPolicyDecodeError::InvalidRevocationTrigger(value)),
        }
    }
}

// ── Decode error ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SecretKeyPolicyDecodeError {
    InvalidSecretClass(u32),
    InvalidStorageStratum(u32),
    InvalidLifecycleState(u32),
    InvalidLeaseUsageClass(u32),
    InvalidRefusalClass(u32),
    InvalidWrappingKeyClass(u32),
    InvalidRotationClass(u32),
    InvalidRevocationTrigger(u32),
}

// ── WrappingKeyRecord (48 bytes) ───────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WrappingKeyRecord {
    pub wrapping_key_id: SecretKeyPolicyId128,
    pub wrapping_key_class: u32,
    pub provider_class: u32,
    pub wrapping_key_version: u32,
    pub _reserved0: u32,
    pub predecessor_wrapping_key_id: SecretKeyPolicyId128,
}

impl WrappingKeyRecord {
    #[must_use = "return value must be used"]
    pub fn wrapping_key_class(self) -> Result<WrappingKeyClass, SecretKeyPolicyDecodeError> {
        WrappingKeyClass::try_from(self.wrapping_key_class)
    }
}

// ── SecretHandleRecord (112 bytes) ─────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretHandleRecord {
    pub handle_id: SecretKeyPolicyId128,
    pub secret_class: u32,
    pub scope_selector: u32,
    pub owner_or_service_family_ref: SecretKeyPolicyId128,
    pub storage_residency_class: u32,
    pub _reserved0: u32,
    pub disclosure_policy_digest: SecretKeyPolicyDigest32,
    pub rotation_policy_digest: SecretKeyPolicyDigest32,
    pub retire_policy_digest: SecretKeyPolicyDigest32,
    pub lifecycle_state: u32,
    pub active_envelope_version: u32,
    pub active_envelope_id: SecretKeyPolicyId128,
    pub _reserved1: u64,
}

impl SecretHandleRecord {
    #[must_use = "return value must be used"]
    pub fn secret_class(self) -> Result<SecretClass, SecretKeyPolicyDecodeError> {
        SecretClass::try_from(self.secret_class)
    }

    #[must_use = "return value must be used"]
    pub fn storage_residency(self) -> Result<StorageStratum, SecretKeyPolicyDecodeError> {
        StorageStratum::try_from(self.storage_residency_class)
    }

    #[must_use = "return value must be used"]
    pub fn lifecycle_state(self) -> Result<SecretLifecycleState, SecretKeyPolicyDecodeError> {
        SecretLifecycleState::try_from(self.lifecycle_state)
    }
}

// ── SecretEnvelopeRecord (80 bytes) ────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretEnvelopeRecord {
    pub envelope_id: SecretKeyPolicyId128,
    pub handle_id: SecretKeyPolicyId128,
    pub envelope_version: u32,
    pub _reserved0: u32,
    pub wrapping_key_id: SecretKeyPolicyId128,
    pub wrapping_key_version: u32,
    pub _reserved1: u32,
    pub sealed_payload_digest: SecretKeyPolicyDigest32,
    pub predecessor_envelope_id: SecretKeyPolicyId128,
    pub _reserved2: u64,
}

impl SecretEnvelopeRecord {
    #[must_use]
    pub const fn has_predecessor(self) -> bool {
        !self.predecessor_envelope_id.is_zero()
    }
}

// ── SecretLeaseGrantRecord (96 bytes) ──────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretLeaseGrantRecord {
    pub lease_id: SecretKeyPolicyId128,
    pub handle_id: SecretKeyPolicyId128,
    pub requesting_session_or_service_ref: SecretKeyPolicyId128,
    pub usage_class: u32,
    pub audience_scope_selector: u32,
    pub runtime_residency_class: u32,
    pub _reserved0: u32,
    pub issued_clock_sample_ref: SecretKeyPolicyId128,
    pub expiry_deadline_ref: SecretKeyPolicyId128,
    pub revocation_epoch_ref: SecretKeyPolicyId128,
    pub _reserved1: u64,
}

impl SecretLeaseGrantRecord {
    #[must_use = "return value must be used"]
    pub fn usage_class(self) -> Result<LeaseUsageClass, SecretKeyPolicyDecodeError> {
        LeaseUsageClass::try_from(self.usage_class)
    }

    #[must_use = "return value must be used"]
    pub fn runtime_residency(self) -> Result<StorageStratum, SecretKeyPolicyDecodeError> {
        StorageStratum::try_from(self.runtime_residency_class)
    }
}

// ── SecretRotationPlanRecord (96 bytes) ────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretRotationPlanRecord {
    pub rotation_plan_id: SecretKeyPolicyId128,
    pub handle_id: SecretKeyPolicyId128,
    pub rotation_class: u32,
    pub _reserved0: u32,
    pub predecessor_envelope_id: SecretKeyPolicyId128,
    pub successor_envelope_id: SecretKeyPolicyId128,
    pub predecessor_envelope_version: u32,
    pub successor_envelope_version: u32,
    pub dual_validity_max_epochs: u32,
    pub _reserved1: u32,
    pub required_runbook_class: u32,
    pub _reserved2: u32,
    pub required_follow_up_receipt_refs: SecretKeyPolicyId128,
    pub dual_validity_expiry_ref: SecretKeyPolicyId128,
    pub _reserved3: u64,
}

impl SecretRotationPlanRecord {
    #[must_use = "return value must be used"]
    pub fn rotation_class(self) -> Result<RotationClass, SecretKeyPolicyDecodeError> {
        RotationClass::try_from(self.rotation_class)
    }

    #[must_use]
    pub fn is_dual_validity(self) -> bool {
        matches!(self.rotation_class(), Ok(RotationClass::DualValidity))
    }
}

// ── SecretRevocationReceipt (96 bytes) ─────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretRevocationReceipt {
    pub revocation_id: SecretKeyPolicyId128,
    pub handle_id: SecretKeyPolicyId128,
    pub trigger_class: u32,
    pub revocation_class: u32,
    pub requires_quarantine: u32,
    pub _reserved0: u32,
    pub successor_handle_id: SecretKeyPolicyId128,
    pub revoked_at_clock_ref: SecretKeyPolicyId128,
    pub affected_lease_count: u32,
    pub _reserved1: u32,
    pub revocation_epoch_ref: SecretKeyPolicyId128,
    pub _reserved2: u64,
}

impl SecretRevocationReceipt {
    #[must_use = "return value must be used"]
    pub fn trigger(self) -> Result<RevocationTriggerClass, SecretKeyPolicyDecodeError> {
        RevocationTriggerClass::try_from(self.trigger_class)
    }

    #[must_use]
    pub const fn is_quarantine(self) -> bool {
        self.requires_quarantine != 0
    }

    #[must_use]
    pub const fn has_successor(self) -> bool {
        !self.successor_handle_id.is_zero()
    }
}

// ── SecretDisclosurePolicyRecord (48 bytes) ────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretDisclosurePolicyRecord {
    pub disclosure_policy_id: SecretKeyPolicyId128,
    pub handle_id: SecretKeyPolicyId128,
    pub visible_fields_mask: u64,
    pub provider_class_reveal: u32,
    pub audit_visible: u32,
    pub trace_visible: u32,
    pub scenario_log_visible: u32,
    pub narrative_export_visible: u32,
    pub _reserved0: u64,
}

impl SecretDisclosurePolicyRecord {
    #[must_use]
    pub const fn is_audit_visible(self) -> bool {
        self.audit_visible != 0
    }

    #[must_use]
    pub const fn is_trace_visible(self) -> bool {
        self.trace_visible != 0
    }

    /// Returns true when the disclosure policy mandates an external HSM
    /// for sealing/unsealing operations on the associated secret class.
    #[must_use]
    pub const fn requires_hsm(self) -> bool {
        // Low 32 bits of _reserved0 carry the HSM-required flag.
        (self._reserved0 as u32) != 0
    }

    /// Set the HSM-required flag on a disclosure policy record.
    #[must_use]
    pub const fn with_hsm_required(mut self, required: bool) -> Self {
        let flag: u64 = if required { 1 } else { 0 };
        self._reserved0 = (self._reserved0 & 0xFFFF_FFFF_0000_0000) | flag;
        self
    }
}

// ── PolicyStoreManifestRecord (128 bytes) ──────────────────────────────────

// ── Disclosure surface classes ───────────────────────────────────────────────────

/// Surfaces on which secret-adjacent records may be rendered or exported.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DisclosureSurfaceClass {
    Render = 0,
    Audit = 1,
    Validation = 2,
    Scenario = 3,
}

impl DisclosureSurfaceClass {
    /// Returns true when the disclosure policy permits this surface class.
    #[must_use]
    pub const fn surface_permitted(self, policy: &SecretDisclosurePolicyRecord) -> bool {
        match self {
            Self::Render => true,
            Self::Audit => policy.audit_visible != 0,
            Self::Validation => policy.trace_visible != 0,
            Self::Scenario => policy.scenario_log_visible != 0,
        }
    }
}

// ── Disclosure decision types ──────────────────────────────────────────────────────

/// Why a disclosure decision mandated redaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionReason {
    /// visible_fields_mask blocks at least one field in the requested field set.
    /// blocked_fields: which bits were denied.
    FieldMasked { blocked_fields: u64 },
    /// provider_class_reveal is not set; provider-class disclosure blocked.
    ProviderClassHidden,
    /// narrative_export_visible is false; narrative export blocked.
    NarrativeExportBlocked,
}

/// Why a disclosure decision mandated outright refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalReason {
    /// audit_visible is false; audit surface not permitted.
    AuditSurfaceNotPermitted,
    /// trace_visible is false; validation surface not permitted.
    ValidationSurfaceNotPermitted,
    /// scenario_log_visible is false; scenario surface not permitted.
    ScenarioSurfaceNotPermitted,
    /// Redaction would change the verdict meaning: semantic loss.
    SemanticLoss,
}

/// Outcome of a disclosure-surface decision for secret-adjacent records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisclosureVerdict {
    /// Full rendering permitted; all requested fields visible.
    Allow,
    /// Rendering permitted with field-level masking.
    Redacted(RedactionReason),
    /// Rendering must be refused entirely.
    Refuse(RefusalReason),
}

impl DisclosureVerdict {
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    #[must_use]
    pub const fn is_redacted(self) -> bool {
        matches!(self, Self::Redacted(_))
    }

    #[must_use]
    pub const fn is_refused(self) -> bool {
        matches!(self, Self::Refuse(_))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyStoreManifestRecord {
    pub manifest_id: SecretKeyPolicyId128,
    pub policy_revision_digest: SecretKeyPolicyDigest32,
    pub signature_set_digest: SecretKeyPolicyDigest32,
    pub required_secret_handle_count: u32,
    pub _reserved0: u32,
    pub required_secret_handle_refs: [SecretKeyPolicyId128; 4],
    pub continuity_window_start_ref: SecretKeyPolicyId128,
    pub continuity_window_end_ref: SecretKeyPolicyId128,
    pub _reserved1: u64,
}

impl PolicyStoreManifestRecord {
    #[must_use]
    pub fn required_handles(&self) -> &[SecretKeyPolicyId128] {
        let count = (self.required_secret_handle_count as usize).min(4);
        &self.required_secret_handle_refs[..count]
    }
}

// ── PolicyPublishBundleRecord (112 bytes) ──────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyPublishBundleRecord {
    pub bundle_id: SecretKeyPolicyId128,
    pub manifest_id: SecretKeyPolicyId128,
    pub ruleset_blob_digest: SecretKeyPolicyDigest32,
    pub issuer_session_ref: SecretKeyPolicyId128,
    pub dual_control_linkage_ref: SecretKeyPolicyId128,
    pub publish_at_clock_ref: SecretKeyPolicyId128,
    pub activation_deadline_ref: SecretKeyPolicyId128,
    pub _reserved0: u64,
}

// ── PolicyActivationReceipt (216 bytes) ────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyActivationReceipt {
    pub activation_id: SecretKeyPolicyId128,
    pub manifest_id: SecretKeyPolicyId128,
    pub bundle_id: SecretKeyPolicyId128,
    pub replaced_active_revision_ref: SecretKeyPolicyId128,
    pub rollback_eligible_predecessor_count: u32,
    pub scope_selector: u32,
    pub rollback_eligible_predecessors: [SecretKeyPolicyId128; 4],
    pub anchor_set_proof_ref: SecretKeyPolicyId128,
    pub runbook_or_authz_receipt_ref: SecretKeyPolicyId128,
    pub activated_at_clock_ref: SecretKeyPolicyId128,
    pub activation_lease_ref: SecretKeyPolicyId128,
    pub activation_wrapping_key_ref: SecretKeyPolicyId128,
}

impl PolicyActivationReceipt {
    #[must_use]
    pub const fn replaces_prior(self) -> bool {
        !self.replaced_active_revision_ref.is_zero()
    }

    #[must_use]
    pub fn rollback_predecessors(&self) -> &[SecretKeyPolicyId128] {
        let count = (self.rollback_eligible_predecessor_count as usize).min(4);
        &self.rollback_eligible_predecessors[..count]
    }

    #[must_use]
    pub const fn has_activation_lease(self) -> bool {
        !self.activation_lease_ref.is_zero()
    }

    #[must_use]
    pub const fn has_activation_wrapping_key(self) -> bool {
        !self.activation_wrapping_key_ref.is_zero()
    }
}

// ── Size assertions ────────────────────────────────────────────────────────

const _: [(); 48] = [(); core::mem::size_of::<WrappingKeyRecord>()];
const _: [(); 176] = [(); core::mem::size_of::<SecretHandleRecord>()];
const _: [(); 120] = [(); core::mem::size_of::<SecretEnvelopeRecord>()];
const _: [(); 120] = [(); core::mem::size_of::<SecretLeaseGrantRecord>()];
const _: [(); 136] = [(); core::mem::size_of::<SecretRotationPlanRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<SecretRevocationReceipt>()];
const _: [(); 72] = [(); core::mem::size_of::<SecretDisclosurePolicyRecord>()];
const _: [(); 192] = [(); core::mem::size_of::<PolicyStoreManifestRecord>()];
const _: [(); 136] = [(); core::mem::size_of::<PolicyPublishBundleRecord>()];
const _: [(); 216] = [(); core::mem::size_of::<PolicyActivationReceipt>()];

// ── Human-aliases module ───────────────────────────────────────────────────

pub mod secret_key_policy {
    pub const FAMILY_NAME: &str = "Secret Key Policy (P9-04)";
    pub const STABLE_SOURCE_LOCATOR: &str = "secret_key_policy_0";
    pub const CANONICAL_CHAIN: &str =
        "wrapping-key lineage → secret handle → sealed envelope → manifest/binding → activation/lease → rotation/revocation receipt";

    pub use super::{
        LeaseUsageClass, PolicyActivationReceipt, PolicyPublishBundleRecord,
        PolicyStoreManifestRecord, RevocationTriggerClass, RotationClass, SecretClass,
        SecretDisclosurePolicyRecord, SecretEnvelopeRecord, SecretHandleRecord,
        SecretKeyPolicyDecodeError, SecretKeyPolicyDigest32, SecretKeyPolicyId128,
        SecretKeyPolicyRefusalClass as RefusalClass, SecretLeaseGrantRecord, SecretLifecycleState,
        SecretRevocationReceipt, SecretRotationPlanRecord, StorageStratum, WrappingKeyClass,
        WrappingKeyRecord,
    };
}

pub mod human {
    pub mod secret_key_policy {
        pub use crate::secret_key_policy::*;
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_classes_round_trip() {
        for c in [
            SecretClass::PolicySigner,
            SecretClass::ServiceIdentity,
            SecretClass::TransportTls,
            SecretClass::NodeJoinBootstrap,
            SecretClass::EnvelopeWrapping,
            SecretClass::SessionMintSeed,
        ] {
            assert_eq!(SecretClass::try_from(c.as_u32()), Ok(c));
        }
    }

    #[test]
    fn invalid_secret_class_reports_error() {
        assert_eq!(
            SecretClass::try_from(99),
            Err(SecretKeyPolicyDecodeError::InvalidSecretClass(99))
        );
    }

    #[test]
    fn storage_strata_round_trip() {
        for s in [
            StorageStratum::SealedAuthoritative,
            StorageStratum::NodeSealedCache,
            StorageStratum::RuntimeMemoryLease,
            StorageStratum::RuntimeKeyringLease,
        ] {
            assert_eq!(StorageStratum::try_from(s.as_u32()), Ok(s));
        }
    }

    #[test]
    fn plaintext_only_in_lease_strata() {
        assert!(!StorageStratum::SealedAuthoritative.allows_plaintext());
        assert!(!StorageStratum::NodeSealedCache.allows_plaintext());
        assert!(StorageStratum::RuntimeMemoryLease.allows_plaintext());
        assert!(StorageStratum::RuntimeKeyringLease.allows_plaintext());
    }

    #[test]
    fn only_authoritative_is_replicated() {
        assert!(StorageStratum::SealedAuthoritative.is_replicated());
        assert!(!StorageStratum::NodeSealedCache.is_replicated());
    }

    #[test]
    fn lifecycle_states_round_trip() {
        for s in [
            SecretLifecycleState::SealedInactive,
            SecretLifecycleState::Active,
            SecretLifecycleState::RotatingDualValid,
            SecretLifecycleState::Revoked,
            SecretLifecycleState::Quarantined,
            SecretLifecycleState::Retired,
        ] {
            assert_eq!(SecretLifecycleState::try_from(s.as_u32()), Ok(s));
        }
    }

    #[test]
    fn terminal_state_is_only_retired() {
        assert!(!SecretLifecycleState::Active.is_terminal());
        assert!(!SecretLifecycleState::Revoked.is_terminal());
        assert!(SecretLifecycleState::Retired.is_terminal());
    }

    #[test]
    fn revoked_and_quarantined_block_leases() {
        assert!(!SecretLifecycleState::Active.blocks_lease_issuance());
        assert!(SecretLifecycleState::Revoked.blocks_lease_issuance());
        assert!(SecretLifecycleState::Quarantined.blocks_lease_issuance());
        assert!(SecretLifecycleState::Retired.blocks_lease_issuance());
    }

    #[test]
    fn is_active_or_rotating() {
        assert!(SecretLifecycleState::Active.is_active_or_rotating());
        assert!(SecretLifecycleState::RotatingDualValid.is_active_or_rotating());
        assert!(!SecretLifecycleState::Revoked.is_active_or_rotating());
    }

    #[test]
    fn only_dual_validity_allows_dual() {
        assert!(!RotationClass::Standard.allows_dual_validity());
        assert!(RotationClass::DualValidity.allows_dual_validity());
        assert!(!RotationClass::Emergency.allows_dual_validity());
    }

    #[test]
    fn handle_record_accessors() {
        let handle = SecretHandleRecord {
            secret_class: SecretClass::TransportTls.as_u32(),
            storage_residency_class: StorageStratum::RuntimeMemoryLease.as_u32(),
            lifecycle_state: SecretLifecycleState::Active.as_u32(),
            ..Default::default()
        };
        assert_eq!(handle.secret_class(), Ok(SecretClass::TransportTls));
        assert_eq!(
            handle.storage_residency(),
            Ok(StorageStratum::RuntimeMemoryLease)
        );
        assert_eq!(handle.lifecycle_state(), Ok(SecretLifecycleState::Active));
    }

    #[test]
    fn envelope_predecessor_detection() {
        let without = SecretEnvelopeRecord::default();
        assert!(!without.has_predecessor());
        let with = SecretEnvelopeRecord {
            predecessor_envelope_id: SecretKeyPolicyId128::from_u128_le(0x42),
            ..Default::default()
        };
        assert!(with.has_predecessor());
    }

    #[test]
    fn lease_grant_accessors() {
        let lease = SecretLeaseGrantRecord {
            usage_class: LeaseUsageClass::TransportTermination.as_u32(),
            runtime_residency_class: StorageStratum::RuntimeMemoryLease.as_u32(),
            ..Default::default()
        };
        assert_eq!(
            lease.usage_class(),
            Ok(LeaseUsageClass::TransportTermination)
        );
        assert_eq!(
            lease.runtime_residency(),
            Ok(StorageStratum::RuntimeMemoryLease)
        );
    }

    #[test]
    fn rotation_plan_dual_validity_detection() {
        let standard = SecretRotationPlanRecord {
            rotation_class: RotationClass::Standard.as_u32(),
            ..Default::default()
        };
        assert!(!standard.is_dual_validity());
        let dual = SecretRotationPlanRecord {
            rotation_class: RotationClass::DualValidity.as_u32(),
            ..Default::default()
        };
        assert!(dual.is_dual_validity());
    }

    #[test]
    fn revocation_receipt_accessors() {
        let rev = SecretRevocationReceipt {
            trigger_class: RevocationTriggerClass::CompromiseSuspected.as_u32(),
            requires_quarantine: 1,
            successor_handle_id: SecretKeyPolicyId128::from_u128_le(0x77),
            ..Default::default()
        };
        assert_eq!(
            rev.trigger(),
            Ok(RevocationTriggerClass::CompromiseSuspected)
        );
        assert!(rev.is_quarantine());
        assert!(rev.has_successor());
    }

    #[test]
    fn disclosure_policy_visibility() {
        let vis = SecretDisclosurePolicyRecord {
            audit_visible: 1,
            trace_visible: 1,
            ..Default::default()
        };
        assert!(vis.is_audit_visible());
        assert!(vis.is_trace_visible());
        let hidden = SecretDisclosurePolicyRecord::default();
        assert!(!hidden.is_audit_visible());
    }

    #[test]
    fn manifest_required_handles_slice() {
        let manifest = PolicyStoreManifestRecord {
            required_secret_handle_count: 2,
            required_secret_handle_refs: [
                SecretKeyPolicyId128::from_u128_le(0xA1),
                SecretKeyPolicyId128::from_u128_le(0xA2),
                SecretKeyPolicyId128::ZERO,
                SecretKeyPolicyId128::ZERO,
            ],
            ..Default::default()
        };
        let handles = manifest.required_handles();
        assert_eq!(handles.len(), 2);
        assert_eq!(handles[0].as_u128_le(), 0xA1);
    }

    #[test]
    fn activation_rollback_predecessors() {
        let receipt = PolicyActivationReceipt {
            rollback_eligible_predecessor_count: 2,
            rollback_eligible_predecessors: [
                SecretKeyPolicyId128::from_u128_le(1),
                SecretKeyPolicyId128::from_u128_le(2),
                SecretKeyPolicyId128::ZERO,
                SecretKeyPolicyId128::ZERO,
            ],
            ..Default::default()
        };
        let preds = receipt.rollback_predecessors();
        assert_eq!(preds.len(), 2);
    }

    #[test]
    fn default_records_have_zero_ids() {
        assert_eq!(
            SecretHandleRecord::default().handle_id,
            SecretKeyPolicyId128::ZERO
        );
        assert_eq!(
            SecretEnvelopeRecord::default().envelope_id,
            SecretKeyPolicyId128::ZERO
        );
        assert_eq!(
            PolicyActivationReceipt::default().activation_id,
            SecretKeyPolicyId128::ZERO
        );
    }
}
