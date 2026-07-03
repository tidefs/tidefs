// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};

use crate::audit::{append_audit_event_and_seal_chain_if_needed, AuditEventId, AuditLog};
use crate::capability::{CapabilityGrant, CapabilityGrantConsumeResult};
use crate::error::AuthorizationError;
use crate::principal::{Principal, PrincipalClass, ScopeSelector};
use crate::records::AuditChainAnchorRecord;

// ---------------------------------------------------------------------------
// Action classes: what operation is being requested
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionClass {
    Observe,
    Stage,
    Publish,
    OverrideIssue,
    RepairPublish,
    FailoverStage,
    RotateKey,
    GrantRole,
    RevokeRole,
    ReadAuditLog,
}

impl std::fmt::Display for ActionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Stage => write!(f, "stage"),
            Self::Publish => write!(f, "publish"),
            Self::OverrideIssue => write!(f, "override_issue"),
            Self::RepairPublish => write!(f, "repair_publish"),
            Self::FailoverStage => write!(f, "failover_stage"),
            Self::RotateKey => write!(f, "rotate_key"),
            Self::GrantRole => write!(f, "grant_role"),
            Self::RevokeRole => write!(f, "revoke_role"),
            Self::ReadAuditLog => write!(f, "read_audit_log"),
        }
    }
}

// ---------------------------------------------------------------------------
// Authorization request and decision
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub principal: Principal,
    pub session_id: u64,
    pub action: ActionClass,
    pub resource: ScopeSelector,
    pub override_ticket_id: Option<u64>,
}

impl AuthorizationRequest {
    pub fn new(
        principal: Principal,
        session_id: u64,
        action: ActionClass,
        resource: ScopeSelector,
    ) -> Self {
        Self {
            principal,
            session_id,
            action,
            resource,
            override_ticket_id: None,
        }
    }

    pub fn with_override(mut self, ticket_id: u64) -> Self {
        self.override_ticket_id = Some(ticket_id);
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub request: AuthorizationRequest,
    pub outcome: AuthorizationOutcome,
    pub matched_roles: Vec<String>,
    pub decided_at_millis: u64,
    pub decider_node_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    Allowed,
    AllowedWithOverride { ticket_id: u64 },
    Denied(String),
}

// ---------------------------------------------------------------------------
// Remote privileged action admission
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemotePrivilegedAction {
    pub command: String,
    pub action: ActionClass,
    pub resource: ScopeSelector,
}

impl RemotePrivilegedAction {
    #[must_use]
    pub fn new(command: impl Into<String>, action: ActionClass, resource: ScopeSelector) -> Self {
        Self {
            command: command.into(),
            action,
            resource,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemotePrivilegedAuthorizationContext {
    pub principal: Option<Principal>,
    pub session_id: Option<u64>,
    pub policy_state: RemotePrivilegedPolicyState,
    pub cluster_owner_state: ClusterOwnerAuthorizationState,
    pub override_ticket_id: Option<u64>,
    pub valid_override_ticket_ids: Vec<u64>,
}

impl RemotePrivilegedAuthorizationContext {
    #[must_use]
    pub fn available(principal: Principal, session_id: u64, decider_node_id: u64) -> Self {
        Self {
            principal: Some(principal),
            session_id: Some(session_id),
            policy_state: RemotePrivilegedPolicyState::Current,
            cluster_owner_state: ClusterOwnerAuthorizationState::Available { decider_node_id },
            override_ticket_id: None,
            valid_override_ticket_ids: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_override(mut self, ticket_id: u64) -> Self {
        self.override_ticket_id = Some(ticket_id);
        self.valid_override_ticket_ids.push(ticket_id);
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RemotePrivilegedPolicyState {
    Current,
    Missing,
    Stale { reason: String },
    Invalid { reason: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ClusterOwnerAuthorizationState {
    Available { decider_node_id: u64 },
    Unavailable { reason: String },
    Refused { reason: String },
}

impl ClusterOwnerAuthorizationState {
    const fn decider_node_id(&self) -> u64 {
        match self {
            Self::Available { decider_node_id } => *decider_node_id,
            Self::Unavailable { .. } | Self::Refused { .. } => 0,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RemotePrivilegedRefusalReason {
    MissingIdentity,
    MissingSession,
    MissingPolicy,
    StalePolicy { reason: String },
    InvalidPolicy { reason: String },
    ClusterOwnerUnavailable { reason: String },
    ClusterOwnerRefused { reason: String },
    MissingCapability { capability: String },
    AuthorizationDenied { reason: String },
}

impl std::fmt::Display for RemotePrivilegedRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingIdentity => write!(f, "missing authenticated identity"),
            Self::MissingSession => write!(f, "missing authenticated session"),
            Self::MissingPolicy => write!(f, "missing remote authorization policy"),
            Self::StalePolicy { reason } => {
                write!(f, "stale remote authorization policy: {reason}")
            }
            Self::InvalidPolicy { reason } => {
                write!(f, "invalid remote authorization policy: {reason}")
            }
            Self::ClusterOwnerUnavailable { reason } => {
                write!(f, "cluster owner unavailable for authorization: {reason}")
            }
            Self::ClusterOwnerRefused { reason } => {
                write!(f, "cluster owner refused authorization: {reason}")
            }
            Self::MissingCapability { capability } => {
                write!(f, "missing capability '{capability}'")
            }
            Self::AuthorizationDenied { reason } => write!(f, "authorization denied: {reason}"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemotePrivilegedAuthorizationEvidence {
    pub command: String,
    pub decision: AuthorizationDecision,
    pub audit_event_id: AuditEventId,
    pub chain_anchor: Option<AuditChainAnchorRecord>,
    pub refusal: Option<RemotePrivilegedRefusalReason>,
}

impl RemotePrivilegedAuthorizationEvidence {
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.refusal.is_none()
            && matches!(
                self.decision.outcome,
                AuthorizationOutcome::Allowed | AuthorizationOutcome::AllowedWithOverride { .. }
            )
            && self.audit_event_id.0 != 0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGrantAuthorization {
    pub decision: AuthorizationDecision,
    pub consume_result: CapabilityGrantConsumeResult,
}

// ---------------------------------------------------------------------------
// Authorization engine
// ---------------------------------------------------------------------------

/// Default capability-to-action mapping.
/// Maps each ActionClass to the capability string required.
pub fn required_capability(action: ActionClass) -> &'static str {
    match action {
        ActionClass::Observe => "observe",
        ActionClass::Stage => "stage",
        ActionClass::Publish => "publish",
        ActionClass::OverrideIssue => "override",
        ActionClass::RepairPublish => "repair",
        ActionClass::FailoverStage => "failover",
        ActionClass::RotateKey => "rotate_key",
        ActionClass::GrantRole => "grant_role",
        ActionClass::RevokeRole => "revoke_role",
        ActionClass::ReadAuditLog => "read_audit_log",
    }
}

/// Required principal class for each action.
pub fn required_class(action: ActionClass) -> PrincipalClass {
    match action {
        ActionClass::Observe => PrincipalClass::Auditor,
        ActionClass::Stage => PrincipalClass::HumanOperator,
        ActionClass::Publish => PrincipalClass::HumanOperator,
        ActionClass::OverrideIssue => PrincipalClass::HumanOperator,
        ActionClass::RepairPublish => PrincipalClass::Service,
        ActionClass::FailoverStage => PrincipalClass::HumanOperator,
        ActionClass::RotateKey => PrincipalClass::Service,
        ActionClass::GrantRole => PrincipalClass::HumanOperator,
        ActionClass::RevokeRole => PrincipalClass::HumanOperator,
        ActionClass::ReadAuditLog => PrincipalClass::Auditor,
    }
}

pub fn consume_capability_grant_for_request(
    grant: &mut CapabilityGrant,
    request: &AuthorizationRequest,
    decider_node_id: u64,
) -> CapabilityGrantAuthorization {
    let matched_role = format!("capability_grant:{}", grant.grant_id.0);
    let consume_result = grant.consume(
        request.principal.principal_id,
        &request.resource,
        required_capability(request.action),
    );
    let (outcome, matched_roles) = match &consume_result {
        Ok(_) => (AuthorizationOutcome::Allowed, vec![matched_role]),
        Err(denial) => (
            AuthorizationOutcome::Denied(denial.reason.to_string()),
            Vec::new(),
        ),
    };

    CapabilityGrantAuthorization {
        decision: AuthorizationDecision {
            request: request.clone(),
            outcome,
            matched_roles,
            decided_at_millis: crate::identity::current_time_utils(),
            decider_node_id,
        },
        consume_result,
    }
}

/// Evaluate an authorization request against a principal.
///
/// Steps:
/// 1. Check principal class requirement
/// 2. Check capability requirement via role bindings
/// 3. Check scope match
/// 4. Check override ticket if present
/// 5. Produce decision
pub fn evaluate_authorization(
    request: &AuthorizationRequest,
    decider_node_id: u64,
) -> AuthorizationDecision {
    let action = request.action;
    let principal = &request.principal;
    let capability = required_capability(action);
    let class = required_class(action);

    let mut matched_roles = Vec::new();

    // Check principal class
    if !principal.has_class(class) && class != PrincipalClass::ClusterNode {
        // HumanOperator can do anything that Auditor can do
        let is_auditor_escalation =
            class == PrincipalClass::Auditor && principal.has_class(PrincipalClass::HumanOperator);
        if !is_auditor_escalation {
            return AuthorizationDecision {
                request: request.clone(),
                outcome: AuthorizationOutcome::Denied(format!(
                    "principal class {:?} does not match required class {:?}",
                    principal.class, class
                )),
                matched_roles,
                decided_at_millis: crate::identity::current_time_utils(),
                decider_node_id,
            };
        }
    }

    // Check capability via roles
    if !principal.has_capability(capability) {
        // Check for override ticket
        if let Some(ticket_id) = request.override_ticket_id {
            if principal.has_capability("override") {
                return AuthorizationDecision {
                    request: request.clone(),
                    outcome: AuthorizationOutcome::AllowedWithOverride { ticket_id },
                    matched_roles: vec!["override".into()],
                    decided_at_millis: crate::identity::current_time_utils(),
                    decider_node_id,
                };
            }
        }

        return AuthorizationDecision {
            request: request.clone(),
            outcome: AuthorizationOutcome::Denied(format!(
                "principal {:?} lacks capability '{}'",
                principal.principal_id, capability
            )),
            matched_roles,
            decided_at_millis: crate::identity::current_time_utils(),
            decider_node_id,
        };
    }

    // Collect matching role names
    matched_roles = principal
        .roles
        .iter()
        .filter(|role| role.capabilities.contains(&capability.to_string()))
        .map(|role| role.role_name.clone())
        .collect();

    AuthorizationDecision {
        request: request.clone(),
        outcome: AuthorizationOutcome::Allowed,
        matched_roles,
        decided_at_millis: crate::identity::current_time_utils(),
        decider_node_id,
    }
}

// ---------------------------------------------------------------------------
// Algorithm: evaluate_role_bindings_for_action_scope_and_visibility
// Role-binding evaluation.
// ---------------------------------------------------------------------------

/// Evaluate whether the principal's role bindings cover the requested
/// action, scope, and visibility.
///
/// Returns the list of matching role names and whether the principal has
/// adequate scope coverage.
pub fn evaluate_role_bindings_for_action_scope_and_visibility(
    principal: &Principal,
    action: ActionClass,
    resource: &ScopeSelector,
) -> (Vec<String>, bool) {
    let capability = required_capability(action);

    let matching: Vec<&crate::principal::RoleBinding> = principal
        .roles
        .iter()
        .filter(|role| {
            // Check capability
            role.capabilities.contains(&capability.to_string()) && !role.is_expired()
        })
        .collect();

    let role_names: Vec<String> = matching.iter().map(|r| r.role_name.clone()).collect();

    // Check scope coverage: at least one role must cover the resource
    let has_scope = matching
        .iter()
        .any(|role| scope_covers(&role.scope, resource));

    (role_names, has_scope)
}

/// Determine whether `parent_scope` covers `target`.
pub fn scope_covers(parent: &ScopeSelector, target: &ScopeSelector) -> bool {
    match parent {
        ScopeSelector::All => true,
        ScopeSelector::Path(p) => match target {
            ScopeSelector::Path(t) => t.starts_with(p.as_str()),
            _ => false,
        },
        _ => parent == target,
    }
}

// ---------------------------------------------------------------------------
// Algorithm: derive_capability_grant_or_denial_from_policy.
// ---------------------------------------------------------------------------

/// Derive a capability decision from policy.
///
/// Returns `true` if the principal has the required capability through
/// valid (non-expired) role bindings that cover the requested scope.
pub fn derive_capability_grant_or_denial_from_policy(
    principal: &Principal,
    action: ActionClass,
    resource: &ScopeSelector,
) -> bool {
    let capability = required_capability(action);

    principal.roles.iter().any(|role| {
        role.capabilities.contains(&capability.to_string())
            && !role.is_expired()
            && scope_covers(&role.scope, resource)
    })
}

// ---------------------------------------------------------------------------
// Algorithm: derive_authorization_decision_for_request.
// ---------------------------------------------------------------------------

/// Full authorization decision pipeline.
///
/// Chains all prior steps into one typed decision:
/// 1. Check principal class
/// 2. Evaluate role bindings
/// 3. Derive capability from policy
/// 4. Consider override if applicable
/// 5. Produce final decision
pub fn derive_authorization_decision_for_request(
    request: &AuthorizationRequest,
    decider_node_id: u64,
    valid_override_ticket_ids: &[u64],
) -> AuthorizationDecision {
    let principal = &request.principal;
    let action = request.action;
    let resource = &request.resource;
    let class = required_class(action);

    let mut matched_roles = Vec::new();

    // Step 1: Check principal class
    let has_class = principal.has_class(class)
        || (class == PrincipalClass::Auditor && principal.has_class(PrincipalClass::HumanOperator));

    if !has_class && class != PrincipalClass::ClusterNode {
        return AuthorizationDecision {
            request: request.clone(),
            outcome: AuthorizationOutcome::Denied(format!(
                "principal class {:?} does not match required class {:?}",
                principal.class, class
            )),
            matched_roles,
            decided_at_millis: crate::identity::current_time_utils(),
            decider_node_id,
        };
    }

    // Step 2: Evaluate role bindings
    let (role_names, has_scope) =
        evaluate_role_bindings_for_action_scope_and_visibility(principal, action, resource);
    matched_roles = role_names;

    if !has_scope {
        return AuthorizationDecision {
            request: request.clone(),
            outcome: AuthorizationOutcome::Denied(format!(
                "no role covers resource scope {resource:?}"
            )),
            matched_roles,
            decided_at_millis: crate::identity::current_time_utils(),
            decider_node_id,
        };
    }

    // Step 3: Derive capability from policy
    let has_capability = derive_capability_grant_or_denial_from_policy(principal, action, resource);

    // Step 4: Consider override
    if !has_capability {
        if let Some(ticket_id) = request.override_ticket_id {
            if principal.has_capability("override")
                && valid_override_ticket_ids.contains(&ticket_id)
            {
                return AuthorizationDecision {
                    request: request.clone(),
                    outcome: AuthorizationOutcome::AllowedWithOverride { ticket_id },
                    matched_roles: vec!["override".into()],
                    decided_at_millis: crate::identity::current_time_utils(),
                    decider_node_id,
                };
            }
        }
    }

    // Step 5: Final decision
    if has_capability {
        AuthorizationDecision {
            request: request.clone(),
            outcome: AuthorizationOutcome::Allowed,
            matched_roles,
            decided_at_millis: crate::identity::current_time_utils(),
            decider_node_id,
        }
    } else {
        AuthorizationDecision {
            request: request.clone(),
            outcome: AuthorizationOutcome::Denied(format!(
                "principal {:?} lacks capability {:?} for action {:?}",
                principal.principal_id,
                required_capability(action),
                action,
            )),
            matched_roles: Vec::new(),
            decided_at_millis: crate::identity::current_time_utils(),
            decider_node_id,
        }
    }
}

/// Evaluate and audit one remote privileged operator action.
///
/// This is the fail-closed source-owned admission path for cluster-routed
/// privileged work. It does not transport a request or make any CLI command
/// remote-capable by itself: callers must supply an authenticated principal,
/// session, fresh policy state, reachable owner state, and an audit log.
pub fn authorize_remote_privileged_action(
    action: RemotePrivilegedAction,
    context: RemotePrivilegedAuthorizationContext,
    audit_log: &mut AuditLog,
    sealing_key: &Keypair,
    batch_size_threshold: usize,
) -> Result<RemotePrivilegedAuthorizationEvidence, AuthorizationError> {
    let decider_node_id = context.cluster_owner_state.decider_node_id();

    let (decision, principal_id, session_id, refusal) =
        remote_privileged_decision(action.clone(), context, decider_node_id);

    let (audit_event_id, chain_anchor) = append_audit_event_and_seal_chain_if_needed(
        audit_log,
        &decision,
        principal_id,
        session_id,
        sealing_key,
        batch_size_threshold,
    )?;

    Ok(RemotePrivilegedAuthorizationEvidence {
        command: action.command,
        decision,
        audit_event_id,
        chain_anchor,
        refusal,
    })
}

fn remote_privileged_decision(
    action: RemotePrivilegedAction,
    context: RemotePrivilegedAuthorizationContext,
    decider_node_id: u64,
) -> (
    AuthorizationDecision,
    crate::principal::PrincipalId,
    u64,
    Option<RemotePrivilegedRefusalReason>,
) {
    let principal = match context.principal {
        Some(principal) => principal,
        None => anonymous_remote_principal(),
    };
    let principal_id = principal.principal_id;
    let session_id = context.session_id.unwrap_or(0);

    if principal_id.0 == 0 {
        return denied_remote_privileged_decision(
            &action,
            principal,
            session_id,
            decider_node_id,
            RemotePrivilegedRefusalReason::MissingIdentity,
        );
    }

    if session_id == 0 {
        return denied_remote_privileged_decision(
            &action,
            principal,
            session_id,
            decider_node_id,
            RemotePrivilegedRefusalReason::MissingSession,
        );
    }

    match context.policy_state {
        RemotePrivilegedPolicyState::Current => {}
        RemotePrivilegedPolicyState::Missing => {
            return denied_remote_privileged_decision(
                &action,
                principal,
                session_id,
                decider_node_id,
                RemotePrivilegedRefusalReason::MissingPolicy,
            );
        }
        RemotePrivilegedPolicyState::Stale { reason } => {
            return denied_remote_privileged_decision(
                &action,
                principal,
                session_id,
                decider_node_id,
                RemotePrivilegedRefusalReason::StalePolicy { reason },
            );
        }
        RemotePrivilegedPolicyState::Invalid { reason } => {
            return denied_remote_privileged_decision(
                &action,
                principal,
                session_id,
                decider_node_id,
                RemotePrivilegedRefusalReason::InvalidPolicy { reason },
            );
        }
    }

    match context.cluster_owner_state {
        ClusterOwnerAuthorizationState::Available { decider_node_id } => {
            let mut request = AuthorizationRequest::new(
                principal.clone(),
                session_id,
                action.action,
                action.resource.clone(),
            );
            if let Some(ticket_id) = context.override_ticket_id {
                request = request.with_override(ticket_id);
            }

            let mut decision = derive_authorization_decision_for_request(
                &request,
                decider_node_id,
                &context.valid_override_ticket_ids,
            );
            let refusal = remote_privileged_refusal_for_decision(&decision);
            if let Some(ref refusal) = refusal {
                decision.outcome = AuthorizationOutcome::Denied(refusal.to_string());
            }

            (decision, principal_id, session_id, refusal)
        }
        ClusterOwnerAuthorizationState::Unavailable { reason } => {
            denied_remote_privileged_decision(
                &action,
                principal,
                session_id,
                decider_node_id,
                RemotePrivilegedRefusalReason::ClusterOwnerUnavailable { reason },
            )
        }
        ClusterOwnerAuthorizationState::Refused { reason } => denied_remote_privileged_decision(
            &action,
            principal,
            session_id,
            decider_node_id,
            RemotePrivilegedRefusalReason::ClusterOwnerRefused { reason },
        ),
    }
}

fn remote_privileged_refusal_for_decision(
    decision: &AuthorizationDecision,
) -> Option<RemotePrivilegedRefusalReason> {
    match &decision.outcome {
        AuthorizationOutcome::Allowed | AuthorizationOutcome::AllowedWithOverride { .. } => None,
        AuthorizationOutcome::Denied(reason) => {
            let capability = required_capability(decision.request.action);
            let has_capability =
                principal_has_unexpired_capability(&decision.request.principal, capability);
            if has_capability {
                Some(RemotePrivilegedRefusalReason::AuthorizationDenied {
                    reason: reason.clone(),
                })
            } else {
                Some(RemotePrivilegedRefusalReason::MissingCapability {
                    capability: capability.to_string(),
                })
            }
        }
    }
}

fn principal_has_unexpired_capability(principal: &Principal, capability: &str) -> bool {
    principal
        .roles
        .iter()
        .any(|role| role.capabilities.iter().any(|cap| cap == capability) && !role.is_expired())
}

fn denied_remote_privileged_decision(
    action: &RemotePrivilegedAction,
    principal: Principal,
    session_id: u64,
    decider_node_id: u64,
    refusal: RemotePrivilegedRefusalReason,
) -> (
    AuthorizationDecision,
    crate::principal::PrincipalId,
    u64,
    Option<RemotePrivilegedRefusalReason>,
) {
    let principal_id = principal.principal_id;
    let decision = AuthorizationDecision {
        request: AuthorizationRequest {
            principal,
            session_id,
            action: action.action,
            resource: action.resource.clone(),
            override_ticket_id: None,
        },
        outcome: AuthorizationOutcome::Denied(refusal.to_string()),
        matched_roles: Vec::new(),
        decided_at_millis: crate::identity::current_time_utils(),
        decider_node_id,
    };

    (decision, principal_id, session_id, Some(refusal))
}

fn anonymous_remote_principal() -> Principal {
    Principal::new(
        crate::principal::PrincipalId::new(0),
        PrincipalClass::ClusterNode,
        0,
        Vec::new(),
    )
}
