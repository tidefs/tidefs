use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityGrant, CapabilityGrantConsumeResult};
use crate::principal::{Principal, PrincipalClass, ScopeSelector};

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
// P9-02 §5.3 step 2
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
// Algorithm: derive_capability_grant_or_denial_from_policy — P9-02 §5.3 step 3
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
// Algorithm: derive_authorization_decision_for_request — P9-02 §5.3 step 5
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
