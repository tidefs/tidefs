// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::{Keypair, Signer};
use serde::{Deserialize, Serialize};

use crate::audit::AuditLog;
use crate::authorization::{ActionClass, AuthorizationDecision, AuthorizationRequest};
use crate::error::AuthorizationError;
use crate::principal::{Principal, PrincipalClass};
use crate::records::{
    OverrideConstraintProfileRecord, OverrideConsumptionId, OverrideConsumptionRecord,
    OverrideProfileId,
};

// ---------------------------------------------------------------------------
// OverrideClass.
// Six typed override classes.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OverrideClass {
    /// Relax reserve or floor constraints (e.g., allow allocation below safety floor)
    ReserveFloorRelaxation,
    /// Bypass product admission gate (e.g., force-admit a degraded volume)
    ProductAdmissionBypass,
    /// Force admission through an expensive/costly path
    ExpensivePathAdmission,
    /// Allow repair publication without normal quorum
    RepairPublication,
    /// Accelerate failover or cutover beyond normal pace
    FailoverCutoverAcceleration,
    /// Disclose sensitive visibility data normally redacted
    SensitiveVisibilityDisclosure,
}

impl std::fmt::Display for OverrideClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReserveFloorRelaxation => write!(f, "reserve_floor_relaxation"),
            Self::ProductAdmissionBypass => write!(f, "product_admission_bypass"),
            Self::ExpensivePathAdmission => write!(f, "expensive_path_admission"),
            Self::RepairPublication => write!(f, "repair_publication"),
            Self::FailoverCutoverAcceleration => write!(f, "failover_cutover_acceleration"),
            Self::SensitiveVisibilityDisclosure => write!(f, "sensitive_visibility_disclosure"),
        }
    }
}

// ---------------------------------------------------------------------------
// OverrideTicket.
// Typed override ticket supporting dual-control authorization.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OverrideTicketId(pub u64);

impl OverrideTicketId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OverrideTicket {
    pub ticket_id: OverrideTicketId,
    pub override_class: OverrideClass,
    pub constraint_profile_id: OverrideProfileId,
    pub issued_by_principal: crate::principal::PrincipalId,
    pub issued_at_millis: u64,
    pub expires_at_millis: u64,
    pub max_use_count: u32,
    pub use_count: u32,
    /// Signatures for dual-control: must have at least one;
    /// if constraint profile requires dual-control, must have ≥ 2.
    pub authorization_signatures: Vec<Vec<u8>>,
}

impl OverrideTicket {
    pub fn new(
        ticket_id: OverrideTicketId,
        override_class: OverrideClass,
        constraint_profile_id: OverrideProfileId,
        issued_by_principal: crate::principal::PrincipalId,
        ttl_millis: u64,
        max_use_count: u32,
        signing_key: &Keypair,
    ) -> Self {
        let now = crate::identity::current_time_utils();
        let mut ticket = Self {
            ticket_id,
            override_class,
            constraint_profile_id,
            issued_by_principal,
            issued_at_millis: now,
            expires_at_millis: now + ttl_millis,
            max_use_count,
            use_count: 0,
            authorization_signatures: Vec::new(),
        };

        let preimage = ticket.preimage_for_signing();
        ticket
            .authorization_signatures
            .push(signing_key.sign(&preimage).to_bytes().to_vec());

        ticket
    }

    /// Add a second authorization signature for dual-control.
    pub fn add_dual_signature(&mut self, signing_key: &Keypair) {
        let preimage = self.preimage_for_signing();
        self.authorization_signatures
            .push(signing_key.sign(&preimage).to_bytes().to_vec());
    }

    pub fn is_expired(&self) -> bool {
        crate::identity::current_time_utils() > self.expires_at_millis
    }

    pub fn is_exhausted(&self) -> bool {
        self.use_count >= self.max_use_count
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_exhausted()
    }

    pub fn has_dual_control(&self) -> bool {
        self.authorization_signatures.len() >= 2
    }

    pub fn record_use(&mut self) {
        self.use_count += 1;
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.ticket_id.0.to_le_bytes());
        buf.extend_from_slice(self.override_class.to_string().as_bytes());
        buf.extend_from_slice(&self.constraint_profile_id.0.to_le_bytes());
        buf.extend_from_slice(&self.issued_by_principal.0.to_le_bytes());
        buf.extend_from_slice(&self.issued_at_millis.to_le_bytes());
        buf.extend_from_slice(&self.expires_at_millis.to_le_bytes());
        buf.extend_from_slice(&self.max_use_count.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Override algorithms.
// ---------------------------------------------------------------------------

/// Determine whether an override is required for the given request,
/// or whether the principal already has sufficient authority.
///
/// Returns Ok(None) if no override is needed,
/// Ok(Some(class)) if an override of the given class is required,
/// or Err if the request is impossible even with override.
pub fn determine_override_requirement_or_sufficiency(
    request: &AuthorizationRequest,
) -> Result<Option<OverrideClass>, AuthorizationError> {
    // Actions that always require override:
    // - OverrideIssue → needs audit-facing override
    // - RepairPublish → may need RepairPublication
    // - FailoverStage → may need FailoverCutoverAcceleration
    match request.action {
        ActionClass::OverrideIssue => {
            // Always requires override — this is a meta-action
            Ok(Some(OverrideClass::ReserveFloorRelaxation))
        }
        ActionClass::RepairPublish => {
            if request.principal.has_class(PrincipalClass::HumanOperator) {
                Ok(None)
            } else {
                Ok(Some(OverrideClass::RepairPublication))
            }
        }
        ActionClass::FailoverStage => {
            if request.principal.has_capability("failover") {
                Ok(None)
            } else {
                Ok(Some(OverrideClass::FailoverCutoverAcceleration))
            }
        }
        ActionClass::Stage => {
            if request.principal.has_capability("stage") {
                Ok(None)
            } else {
                Ok(Some(OverrideClass::ProductAdmissionBypass))
            }
        }
        ActionClass::Publish => {
            if request.principal.has_capability("publish") {
                Ok(None)
            } else {
                Ok(Some(OverrideClass::ProductAdmissionBypass))
            }
        }
        _ => {
            // Observe, RotateKey, GrantRole, RevokeRole, ReadAuditLog
            // generally do not use override
            Ok(None)
        }
    }
}

/// Issue a typed override ticket, optionally under dual control.
///
/// Override ticket issuance.
#[allow(clippy::too_many_arguments)]
pub fn issue_typed_override_ticket_under_dual_control(
    ticket_id: OverrideTicketId,
    override_class: OverrideClass,
    constraint_profile: &OverrideConstraintProfileRecord,
    issued_by_principal: crate::principal::PrincipalId,
    ttl_millis: u64,
    max_use_count: u32,
    primary_key: &Keypair,
    secondary_key: Option<&Keypair>,
) -> Result<OverrideTicket, AuthorizationError> {
    // Ensure TTL does not exceed profile max
    let effective_ttl = std::cmp::min(ttl_millis, constraint_profile.max_duration_millis);

    // Ensure use count does not exceed profile max
    let effective_use_count = std::cmp::min(max_use_count, constraint_profile.max_use_count);

    let mut ticket = OverrideTicket::new(
        ticket_id,
        override_class,
        constraint_profile.profile_id,
        issued_by_principal,
        effective_ttl,
        effective_use_count,
        primary_key,
    );

    if constraint_profile.dual_control_required {
        if let Some(secondary) = secondary_key {
            ticket.add_dual_signature(secondary);
        } else {
            return Err(AuthorizationError::OverrideTicketInvalid {
                ticket_id: ticket_id.0,
            });
        }
    }

    Ok(ticket)
}

/// Consume an override ticket and bind it to an action.
///
/// Validates the ticket, records the use, and produces
/// a consumption record linked to the authorization decision and audit event.
pub fn consume_override_ticket_and_bind_it_to_action(
    ticket: &mut OverrideTicket,
    decision: &AuthorizationDecision,
    audit_log: &mut AuditLog,
    principal: &Principal,
    session_id: u64,
    constraint_profile: &OverrideConstraintProfileRecord,
) -> Result<OverrideConsumptionRecord, AuthorizationError> {
    // Validate ticket
    if !ticket.is_valid() {
        return Err(AuthorizationError::OverrideTicketInvalid {
            ticket_id: ticket.ticket_id.0,
        });
    }

    if constraint_profile.dual_control_required && !ticket.has_dual_control() {
        return Err(AuthorizationError::OverrideTicketInvalid {
            ticket_id: ticket.ticket_id.0,
        });
    }

    // Record use
    ticket.record_use();

    // Build action receipt
    let mut receipt = Vec::new();
    receipt.extend_from_slice(&ticket.ticket_id.0.to_le_bytes());
    receipt.extend_from_slice(&principal.principal_id.0.to_le_bytes());
    receipt.extend_from_slice(&session_id.to_le_bytes());
    receipt.extend_from_slice(&crate::identity::current_time_utils().to_le_bytes());

    // Record audit event
    let audit_event_id = audit_log.record_decision(decision, principal.principal_id, session_id);

    let consumption_id = OverrideConsumptionId::new(ticket.ticket_id.0);

    Ok(OverrideConsumptionRecord::new(
        consumption_id,
        ticket.ticket_id.0,
        decision.clone(),
        receipt,
        audit_event_id,
    ))
}
