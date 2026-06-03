use serde::{Deserialize, Serialize};

use crate::authorization::{AuthorizationDecision, AuthorizationRequest};
use crate::principal::PrincipalId;

// ---------------------------------------------------------------------------
// Security response envelope classes — P9-02 §8
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SecurityResponseClass {
    /// Authentication failed: credential not recognized or expired
    AuthnFailed {
        principal_id: Option<PrincipalId>,
        reason: String,
    },
    /// Session has expired (beyond TTL, or revoked)
    SessionExpired {
        session_id: u64,
        expired_at_millis: u64,
    },
    /// Authorization denied: principal lacks capability or class
    AuthzDenied {
        principal_id: PrincipalId,
        reason: String,
    },
    /// Override is required to proceed with this action
    OverrideRequired {
        principal_id: PrincipalId,
        action: String,
        override_class: String,
    },
    /// The provided override ticket is invalid, expired, or exhausted
    OverrideInvalid { ticket_id: u64, reason: String },
    /// Visibility redacted: principal cannot view this resource
    VisibilityRedacted {
        principal_id: PrincipalId,
        resource: String,
    },
}

impl SecurityResponseClass {
    /// Construct from an authorization denial decision.
    pub fn from_denied(principal_id: PrincipalId, decision: &AuthorizationDecision) -> Self {
        let reason = match &decision.outcome {
            crate::authorization::AuthorizationOutcome::Denied(reason) => reason.clone(),
            _ => "unknown denial".to_string(),
        };
        Self::AuthzDenied {
            principal_id,
            reason,
        }
    }

    /// Construct from authn failure.
    pub fn authn_failed(reason: String) -> Self {
        Self::AuthnFailed {
            principal_id: None,
            reason,
        }
    }

    /// Construct from session expiry.
    pub fn session_expired(session_id: u64, expired_at_millis: u64) -> Self {
        Self::SessionExpired {
            session_id,
            expired_at_millis,
        }
    }

    /// Construct from override requirement.
    pub fn override_required(
        principal_id: PrincipalId,
        action: &str,
        override_class: &str,
    ) -> Self {
        Self::OverrideRequired {
            principal_id,
            action: action.to_string(),
            override_class: override_class.to_string(),
        }
    }

    /// Construct from invalid override.
    pub fn override_invalid(ticket_id: u64, reason: String) -> Self {
        Self::OverrideInvalid { ticket_id, reason }
    }

    /// Construct from visibility redaction.
    pub fn visibility_redacted(principal_id: PrincipalId, resource: &str) -> Self {
        Self::VisibilityRedacted {
            principal_id,
            resource: resource.to_string(),
        }
    }
}

impl std::fmt::Display for SecurityResponseClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthnFailed { reason, .. } => write!(f, "authn_failed: {reason}"),
            Self::SessionExpired { session_id, .. } => {
                write!(f, "session_expired: session {session_id}")
            }
            Self::AuthzDenied {
                principal_id,
                reason,
            } => {
                write!(f, "authz_denied: principal {principal_id:?} — {reason}")
            }
            Self::OverrideRequired {
                principal_id,
                action,
                override_class,
            } => {
                write!(
                    f,
                    "override_required: principal {principal_id:?} needs {override_class} for {action}"
                )
            }
            Self::OverrideInvalid {
                ticket_id, reason, ..
            } => {
                write!(f, "override_invalid: ticket {ticket_id} — {reason}")
            }
            Self::VisibilityRedacted {
                principal_id,
                resource,
            } => {
                write!(
                    f,
                    "visibility_redacted: principal {principal_id:?} on {resource}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Full security response envelope
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SecurityResponseEnvelope {
    pub response_class: SecurityResponseClass,
    pub request: Option<AuthorizationRequest>,
    pub decision: Option<AuthorizationDecision>,
    pub issued_at_millis: u64,
}

impl SecurityResponseEnvelope {
    pub fn new(
        response_class: SecurityResponseClass,
        request: Option<AuthorizationRequest>,
        decision: Option<AuthorizationDecision>,
    ) -> Self {
        Self {
            response_class,
            request,
            decision,
            issued_at_millis: crate::identity::current_time_utils(),
        }
    }
}
