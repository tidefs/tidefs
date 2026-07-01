// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Authentication/authorization/audit model for TideFS.
//!
//! This crate implements:
//! - [NodeIdentity]: Ed25519-based node identity with self-signing and key rotation
//! - [HelloMessage]/[HelloResponse]: mutual attestation handshake (P8-01 message family m0)
//! - [verify_mutual_attestation]: full 7-step mutual attestation verification
//! - [Principal]: 5-class principal model (HumanOperator, Service, ClusterNode, Auditor, Breakglass)
//! - [RoleBinding]: capability grants with scope and expiry
//! - [AuthorizationRequest]/[AuthorizationDecision]: authorization pipeline
//! - [AuditLog]: append-only audit trail with chain seals for every authorization decision
//! - [OverrideTicket]: typed override machinery with dual-control support
//! - [SecurityResponseEnvelope]: typed security response classes
//!
//! Every distributed session, every control-plane operation, and every
//! secret lease operation routes through this model for identity proof
//! and authorization enforcement.

pub mod attestation;
pub mod audit;
pub mod authorization;
pub mod capability;
pub mod envelope;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod local_only;
pub mod override_mechanism;
pub mod persistence;
pub mod principal;
pub mod records;
pub mod security;
pub mod session_security;

// Re-exports
pub use attestation::{
    check_nonce_replay, mint_session_grant_for_authenticated_subject, verify_mutual_attestation,
    AttestationResult, HelloMessage, HelloResponse, NonceCache, SessionClass, SessionToken,
};
pub use audit::{
    append_audit_event_and_seal_chain_if_needed, AuditEvent, AuditEventId, AuditEventKind, AuditLog,
};
pub use authorization::{
    consume_capability_grant_for_request, derive_authorization_decision_for_request,
    derive_capability_grant_or_denial_from_policy, evaluate_authorization,
    evaluate_role_bindings_for_action_scope_and_visibility, required_capability, required_class,
    scope_covers, ActionClass, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    CapabilityGrantAuthorization,
};
pub use capability::{
    CapabilityGrant, CapabilityGrantConsumeResult, CapabilityGrantDenial,
    CapabilityGrantDenialReason, CapabilityGrantId, CapabilityGrantUse,
};
pub use envelope::{SecurityResponseClass, SecurityResponseEnvelope};
pub use error::{AttestationError, AuthorizationError, IdentityError};
pub use handshake::{
    derive_session_keys, HandshakeState, HelloHandshake, HelloHandshakeResult, SessionKeys,
    VerifyMessage, HANDSHAKE_TIMEOUT,
};
pub use identity::{
    check_revocation_status, check_revocation_status_with_grace, current_time_utils,
    resolve_principal_from_presented_credential_chain, revoke_identity_with_grace,
    validate_credential_binding_and_time_health, CompromiseRecoveryRecord,
    GracePeriodRevocationRecord, GracePeriodRevocationSet, IdentityRevocationRecord,
    KeyLifecycleStats, KeyRotationRecord, NodeIdentity, NodeKeyStore, RevocationReason,
    RevocationSet,
};
pub use override_mechanism::{
    consume_override_ticket_and_bind_it_to_action, determine_override_requirement_or_sufficiency,
    issue_typed_override_ticket_under_dual_control, OverrideClass, OverrideTicket,
    OverrideTicketId,
};
pub use principal::{
    Principal, PrincipalClass, PrincipalId, RoleBinding, RoleBindingId, ScopeSelector,
};
pub use records::{
    hash_audit_events, AssuranceClass, AuditChainAnchorId, AuditChainAnchorRecord,
    CredentialBindingId, CredentialBindingRecord, CredentialType, OverrideConstraintProfileRecord,
    OverrideConsumptionId, OverrideConsumptionRecord, OverrideProfileId, SessionGrantId,
    SessionGrantRecord,
};

// Re-exports from security module (cluster security and identity model)
pub use security::{
    admin_access_check, dedup_key, generate_psk_proof, generate_psk_proof_ack, negotiate_mode,
    rdma_bulk_gate, tlv_tag, verify_hello_security, verify_psk_proof, verify_psk_proof_ack,
    AdminProxyHeader, AuthenticatedPeer, ClusterSecurityConfig, DedupEntry, DedupResult,
    DedupWindow, HelloTlv, NodeSecurityConfig, PskStore, SecurityMode,
};

// Re-exports from session_security module
pub use session_security::{SessionSecurity, SessionSecurityError, SessionSecurityStats};

// Re-exports from local_only module (operator authorization boundary)
pub use local_only::{LocalOnlyError, LocalOnlyGuard};
