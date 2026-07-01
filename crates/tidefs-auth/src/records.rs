// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::{Keypair, Signer};
use serde::{Deserialize, Serialize};

use crate::authorization::{ActionClass, AuthorizationDecision};
use crate::principal::{PrincipalId, ScopeSelector};

// ---------------------------------------------------------------------------
// CredentialBindingRecord.
// Resolves a presented credential to exactly one named principal.
// ---------------------------------------------------------------------------

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct CredentialBindingId(pub u64);

impl CredentialBindingId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CredentialType {
    Ed25519Key,
    SessionBearerToken,
    TlsClientCertificate,
    SignedAssertion,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519Key => write!(f, "ed25519_key"),
            Self::SessionBearerToken => write!(f, "session_bearer_token"),
            Self::TlsClientCertificate => write!(f, "tls_client_certificate"),
            Self::SignedAssertion => write!(f, "signed_assertion"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CredentialBindingRecord {
    pub binding_id: CredentialBindingId,
    pub principal_id: PrincipalId,
    pub credential_type: CredentialType,
    pub credential_hash: [u8; 32],
    pub bound_at_millis: u64,
    pub expires_at_millis: Option<u64>,
    pub binding_signature: Vec<u8>,
}

impl CredentialBindingRecord {
    pub fn new(
        binding_id: CredentialBindingId,
        principal_id: PrincipalId,
        credential_type: CredentialType,
        credential_material: &[u8],
        signing_key: &Keypair,
    ) -> Self {
        let now = crate::identity::current_time_utils();
        let mut binding = Self {
            binding_id,
            principal_id,
            credential_type,
            credential_hash: sha256_hash(credential_material),
            bound_at_millis: now,
            expires_at_millis: None,
            binding_signature: Vec::new(),
        };

        let preimage = binding.preimage_for_signing();
        binding.binding_signature = signing_key.sign(&preimage).to_bytes().to_vec();

        binding
    }

    pub fn with_ttl(mut self, ttl_millis: u64) -> Self {
        self.expires_at_millis = Some(self.bound_at_millis + ttl_millis);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at_millis {
            crate::identity::current_time_utils() > exp
        } else {
            false
        }
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.binding_id.0.to_le_bytes());
        buf.extend_from_slice(&self.principal_id.0.to_le_bytes());
        buf.extend_from_slice(self.credential_type.to_string().as_bytes());
        buf.extend_from_slice(&self.credential_hash);
        buf.extend_from_slice(&self.bound_at_millis.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// SessionGrantRecord.
// ---------------------------------------------------------------------------

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct SessionGrantId(pub u64);

impl SessionGrantId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AssuranceClass {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AssuranceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SessionGrantRecord {
    pub grant_id: SessionGrantId,
    pub session_id: u64,
    pub principal_id: PrincipalId,
    pub token_bytes: [u8; 32],
    pub issued_at_millis: u64,
    pub expires_at_millis: u64,
    pub audience: Vec<u64>,
    pub assurance_class: AssuranceClass,
    pub scope_ceiling: ScopeSelector,
    pub revocation_epoch: u64,
    pub grant_signature: Vec<u8>,
}

impl SessionGrantRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        grant_id: SessionGrantId,
        session_id: u64,
        principal_id: PrincipalId,
        token_bytes: [u8; 32],
        ttl_millis: u64,
        audience: Vec<u64>,
        assurance_class: AssuranceClass,
        scope_ceiling: ScopeSelector,
        revocation_epoch: u64,
        signing_key: &Keypair,
    ) -> Self {
        let now = crate::identity::current_time_utils();
        let mut grant = Self {
            grant_id,
            session_id,
            principal_id,
            token_bytes,
            issued_at_millis: now,
            expires_at_millis: now + ttl_millis,
            audience,
            assurance_class,
            scope_ceiling,
            revocation_epoch,
            grant_signature: Vec::new(),
        };

        let preimage = grant.preimage_for_signing();
        grant.grant_signature = signing_key.sign(&preimage).to_bytes().to_vec();

        grant
    }

    pub fn is_expired(&self) -> bool {
        crate::identity::current_time_utils() > self.expires_at_millis
    }

    pub fn is_revoked(&self, current_epoch: u64) -> bool {
        self.revocation_epoch < current_epoch
    }

    pub fn is_for_audience(&self, node_id: u64) -> bool {
        self.audience.is_empty() || self.audience.contains(&node_id)
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.grant_id.0.to_le_bytes());
        buf.extend_from_slice(&self.session_id.to_le_bytes());
        buf.extend_from_slice(&self.principal_id.0.to_le_bytes());
        buf.extend_from_slice(&self.token_bytes);
        buf.extend_from_slice(&self.issued_at_millis.to_le_bytes());
        buf.extend_from_slice(&self.expires_at_millis.to_le_bytes());
        for node in &self.audience {
            buf.extend_from_slice(&node.to_le_bytes());
        }
        buf.extend_from_slice(self.assurance_class.to_string().as_bytes());
        buf.extend_from_slice(self.scope_ceiling.to_string().as_bytes());
        buf.extend_from_slice(&self.revocation_epoch.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// OverrideConstraintProfileRecord.
// ---------------------------------------------------------------------------

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct OverrideProfileId(pub u64);

impl OverrideProfileId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OverrideConstraintProfileRecord {
    pub profile_id: OverrideProfileId,
    pub allowed_action_classes: Vec<ActionClass>,
    pub max_scope: ScopeSelector,
    pub max_duration_millis: u64,
    pub max_use_count: u32,
    pub dual_control_required: bool,
    pub created_at_millis: u64,
}

impl OverrideConstraintProfileRecord {
    pub fn new(
        profile_id: OverrideProfileId,
        allowed_action_classes: Vec<ActionClass>,
        max_scope: ScopeSelector,
        max_duration_millis: u64,
        max_use_count: u32,
        dual_control_required: bool,
    ) -> Self {
        Self {
            profile_id,
            allowed_action_classes,
            max_scope,
            max_duration_millis,
            max_use_count,
            dual_control_required,
            created_at_millis: crate::identity::current_time_utils(),
        }
    }

    pub fn allows_action(&self, action: ActionClass) -> bool {
        self.allowed_action_classes.is_empty() || self.allowed_action_classes.contains(&action)
    }
}

// ---------------------------------------------------------------------------
// OverrideConsumptionRecord.
// ---------------------------------------------------------------------------

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct OverrideConsumptionId(pub u64);

impl OverrideConsumptionId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OverrideConsumptionRecord {
    pub consumption_id: OverrideConsumptionId,
    pub ticket_id: u64,
    pub decision: AuthorizationDecision,
    pub action_receipt: Vec<u8>,
    pub consumed_at_millis: u64,
    pub audit_event_id: crate::audit::AuditEventId,
}

impl OverrideConsumptionRecord {
    pub fn new(
        consumption_id: OverrideConsumptionId,
        ticket_id: u64,
        decision: AuthorizationDecision,
        action_receipt: Vec<u8>,
        audit_event_id: crate::audit::AuditEventId,
    ) -> Self {
        Self {
            consumption_id,
            ticket_id,
            decision,
            action_receipt,
            consumed_at_millis: crate::identity::current_time_utils(),
            audit_event_id,
        }
    }
}

// ---------------------------------------------------------------------------
// AuditChainAnchorRecord.
// ---------------------------------------------------------------------------

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct AuditChainAnchorId(pub u64);

impl AuditChainAnchorId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuditChainAnchorRecord {
    pub anchor_id: AuditChainAnchorId,
    pub event_range_start: crate::audit::AuditEventId,
    pub event_range_end: crate::audit::AuditEventId,
    pub event_count: u64,
    pub sealed_at_millis: u64,
    pub seal_hash: [u8; 32],
    pub prior_anchor_hash: Option<[u8; 32]>,
    pub signature: Vec<u8>,
}

impl AuditChainAnchorRecord {
    pub fn new(
        anchor_id: AuditChainAnchorId,
        event_range_start: crate::audit::AuditEventId,
        event_range_end: crate::audit::AuditEventId,
        event_count: u64,
        seal_hash: [u8; 32],
        prior_anchor_hash: Option<[u8; 32]>,
        signing_key: &Keypair,
    ) -> Self {
        let now = crate::identity::current_time_utils();
        let mut anchor = Self {
            anchor_id,
            event_range_start,
            event_range_end,
            event_count,
            sealed_at_millis: now,
            seal_hash,
            prior_anchor_hash,
            signature: Vec::new(),
        };

        let preimage = anchor.preimage_for_signing();
        anchor.signature = signing_key.sign(&preimage).to_bytes().to_vec();

        anchor
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.anchor_id.0.to_le_bytes());
        buf.extend_from_slice(&self.event_range_start.0.to_le_bytes());
        buf.extend_from_slice(&self.event_range_end.0.to_le_bytes());
        buf.extend_from_slice(&self.event_count.to_le_bytes());
        buf.extend_from_slice(&self.sealed_at_millis.to_le_bytes());
        buf.extend_from_slice(&self.seal_hash);
        if let Some(ref prior) = self.prior_anchor_hash {
            buf.extend_from_slice(prior);
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Utility: SHA-256 hash helpers
// ---------------------------------------------------------------------------

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Hash a set of ordered audit events into a seal hash.
pub fn hash_audit_events(events: &[crate::audit::AuditEvent]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for event in events {
        if let Ok(serialized) = serde_json::to_vec(event) {
            hasher.update(&serialized);
        }
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::ActionClass;

    // --- Newtype roundtrips ---

    #[test]
    fn credential_binding_id_new_roundtrip() {
        let id = CredentialBindingId::new(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn session_grant_id_new_roundtrip() {
        let id = SessionGrantId::new(7);
        assert_eq!(id.0, 7);
    }

    #[test]
    fn override_consumption_id_new_roundtrip() {
        let id = OverrideConsumptionId::new(99);
        assert_eq!(id.0, 99);
    }

    #[test]
    fn audit_chain_anchor_id_new_roundtrip() {
        let id = AuditChainAnchorId::new(1);
        assert_eq!(id.0, 1);
    }

    // --- Display impls ---

    #[test]
    fn credential_type_display() {
        assert_eq!(CredentialType::Ed25519Key.to_string(), "ed25519_key");
        assert_eq!(
            CredentialType::SessionBearerToken.to_string(),
            "session_bearer_token"
        );
        assert_eq!(
            CredentialType::TlsClientCertificate.to_string(),
            "tls_client_certificate"
        );
        assert_eq!(
            CredentialType::SignedAssertion.to_string(),
            "signed_assertion"
        );
    }

    #[test]
    fn assurance_class_display() {
        assert_eq!(AssuranceClass::Low.to_string(), "low");
        assert_eq!(AssuranceClass::Medium.to_string(), "medium");
        assert_eq!(AssuranceClass::High.to_string(), "high");
        assert_eq!(AssuranceClass::Critical.to_string(), "critical");
    }

    // --- sha256_hash ---

    #[test]
    fn sha256_hash_deterministic() {
        let h1 = sha256_hash(b"hello");
        let h2 = sha256_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_hash_different_inputs_different_outputs() {
        let h1 = sha256_hash(b"hello");
        let h2 = sha256_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_hash_empty_input() {
        let h = sha256_hash(b"");
        // SHA-256 of empty string
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn sha256_hash_known_vector() {
        let h = sha256_hash(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(h, expected);
    }

    // --- OverrideProfile::allows_action ---

    fn make_profile(allowed: Vec<ActionClass>) -> OverrideConstraintProfileRecord {
        OverrideConstraintProfileRecord {
            profile_id: OverrideProfileId::new(1),
            allowed_action_classes: allowed,
            max_scope: ScopeSelector::All,
            max_duration_millis: 3_600_000,
            max_use_count: 10,
            dual_control_required: false,
            created_at_millis: 1000,
        }
    }

    #[test]
    fn override_profile_allows_listed_action() {
        let profile = make_profile(vec![ActionClass::Observe, ActionClass::Stage]);
        assert!(profile.allows_action(ActionClass::Observe));
        assert!(profile.allows_action(ActionClass::Stage));
        assert!(!profile.allows_action(ActionClass::Publish));
    }

    #[test]
    fn override_profile_empty_allowed_allows_all() {
        let profile = make_profile(vec![]);
        assert!(profile.allows_action(ActionClass::Observe));
        assert!(profile.allows_action(ActionClass::Stage));
        assert!(profile.allows_action(ActionClass::Publish));
    }

    #[test]
    fn override_profile_single_action() {
        let profile = make_profile(vec![ActionClass::Observe]);
        assert!(profile.allows_action(ActionClass::Observe));
        assert!(!profile.allows_action(ActionClass::Stage));
    }
}
