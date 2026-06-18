// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use thiserror::Error;

// ---------------------------------------------------------------------------
// Attestation errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    #[error("nonce mismatch: client nonce not echoed correctly")]
    NonceMismatch,

    #[error("identity not found in epoch: node {node_id}")]
    IdentityNotInEpoch { node_id: u64 },

    #[error("epoch mismatch: client epoch {client_epoch} != server epoch {server_epoch}")]
    EpochMismatch {
        client_epoch: u64,
        server_epoch: u64,
    },

    #[error("protocol version not supported: offered {offered:?}, accepted {accepted}")]
    ProtocolVersionNotSupported { offered: Vec<u16>, accepted: u16 },

    #[error("signature verification failed for node {node_id}: {reason}")]
    SignatureVerificationFailed { node_id: u64, reason: String },

    #[error("invalid session class negotiation: offered {offered:?}, accepted {accepted:?}")]
    SessionClassMismatch { offered: String, accepted: String },

    #[error("attestation challenge failed: {reason}")]
    ChallengeFailed { reason: String },

    #[error("nonce replay detected for node {node_id}")]
    NonceReplay { node_id: u64 },
}

// ---------------------------------------------------------------------------
// Identity errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("identity version rollback: attempted {attempted}, current {current}")]
    VersionRollback { attempted: u64, current: u64 },

    #[error("identity expired at version {version}")]
    Expired { version: u64 },

    #[error("identity revoked: {reason}")]
    Revoked { reason: String },

    #[error("credential binding not found for credential hash {hash:?}")]
    CredentialBindingNotFound { hash: [u8; 32] },

    #[error("credential binding expired for principal {principal_id}")]
    CredentialBindingExpired { principal_id: String },

    #[error("key rotation failed: {reason}")]
    KeyRotationFailed { reason: String },

    #[error("compromise recovery failed: {reason}")]
    CompromiseRecoveryFailed { reason: String },

    #[error("revocation grace period active: {reason}")]
    RevocationGracePeriod { reason: String },
}

// ---------------------------------------------------------------------------
// Authorization errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("principal {principal_id} not found")]
    PrincipalNotFound { principal_id: u64 },

    #[error("session {session_id} not found or expired")]
    SessionNotFound { session_id: u64 },

    #[error("session {session_id} expired at {expired_at:?}")]
    SessionExpired { session_id: u64, expired_at: String },

    #[error("insufficient capability: needed {needed:?}, have {have:?}")]
    InsufficientCapability { needed: String, have: Vec<String> },

    #[error("action {action:?} denied on resource {resource}: {reason}")]
    Denied {
        action: String,
        resource: String,
        reason: String,
    },

    #[error("override ticket {ticket_id} is invalid or expired")]
    OverrideTicketInvalid { ticket_id: u64 },

    #[error("override ticket {ticket_id} exhausted: used {used}/{max_uses}")]
    OverrideTicketExhausted {
        ticket_id: u64,
        used: u32,
        max_uses: u32,
    },

    #[error("dual-control required for override ticket {ticket_id} but only {sig_count} signatures present")]
    DualControlRequired { ticket_id: u64, sig_count: usize },

    #[error("audit trail broken: {reason}")]
    AuditTrailBroken { reason: String },

    #[error("role binding conflict: {reason}")]
    RoleBindingConflict { reason: String },

    #[error("session grant error: {reason}")]
    SessionGrantError { reason: String },

    #[error("time health check failed: clock skew {skew_ms}ms exceeds threshold {threshold_ms}ms")]
    TimeHealthFailed { skew_ms: i64, threshold_ms: i64 },

    #[error("audit log persistence failed: {reason}")]
    AuditLogPersistenceFailed { reason: String },
}

// ---------------------------------------------------------------------------
// Security errors — cluster security and identity model
// ---------------------------------------------------------------------------

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    #[error("auth mode unsupported: requested {requested:?}, supported {supported:?}")]
    AuthModeUnsupported {
        requested: String,
        supported: Vec<String>,
    },

    #[error("unknown PSK identity: {identity}")]
    UnknownPskIdentity { identity: String },

    #[error("PSK proof mismatch")]
    PskProofMismatch,

    #[error("PSK proof ACK mismatch")]
    PskProofAckMismatch,

    #[error("TLS certificate hash mismatch")]
    TlsCertHashMismatch,

    #[error("security mode mismatch: local {local:?} vs remote {remote:?}: {reason}")]
    ModeMismatch {
        local: String,
        remote: String,
        reason: String,
    },

    #[error("ADMIN access denied: {0}")]
    AdminAccessDenied(String),

    #[error("RDMA bulk denied: {0}")]
    RdmaBulkDenied(String),

    #[error("invalid PSK proof TLV")]
    InvalidPskProof,

    #[error("invalid PSK identity encoding")]
    InvalidPskIdentity,

    #[error("unsupported security mode: {mode}")]
    UnsupportedMode { mode: u8 },

    #[error(
        "TLS peer identity missing: tcp_mtls requires a transport-provided peer certificate DN"
    )]
    TlsPeerIdentityMissing,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AdminAccessDenied {
    #[error("not authenticated")]
    NotAuthenticated,

    #[error("peer not in admin set: {peer:?}")]
    NotInAdminSet { peer: String },
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RdmaBulkDenied {
    #[error("RDMA bulk not supported in dev_insecure mode")]
    DevInsecureNotSupported,

    #[error("RDMA bulk over authenticated mode requires operator acknowledgment")]
    OperatorAckRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_error_display() {
        let e = AttestationError::NonceMismatch;
        assert_eq!(
            e.to_string(),
            "nonce mismatch: client nonce not echoed correctly"
        );

        let e = AttestationError::IdentityNotInEpoch { node_id: 42 };
        assert_eq!(e.to_string(), "identity not found in epoch: node 42");

        let e = AttestationError::EpochMismatch {
            client_epoch: 5,
            server_epoch: 10,
        };
        assert_eq!(
            e.to_string(),
            "epoch mismatch: client epoch 5 != server epoch 10"
        );
    }

    #[test]
    fn identity_error_display() {
        let e = IdentityError::KeyGenerationFailed {
            reason: "bad seed".into(),
        };
        assert_eq!(e.to_string(), "key generation failed: bad seed");

        let e = IdentityError::VersionRollback {
            attempted: 1,
            current: 5,
        };
        assert_eq!(
            e.to_string(),
            "identity version rollback: attempted 1, current 5"
        );

        let e = IdentityError::Expired { version: 3 };
        assert_eq!(e.to_string(), "identity expired at version 3");

        let e = IdentityError::Revoked {
            reason: "compromised".into(),
        };
        assert_eq!(e.to_string(), "identity revoked: compromised");
    }

    #[test]
    fn authorization_error_display() {
        let e = AuthorizationError::PrincipalNotFound { principal_id: 7 };
        assert_eq!(e.to_string(), "principal 7 not found");

        let e = AuthorizationError::SessionNotFound { session_id: 99 };
        assert_eq!(e.to_string(), "session 99 not found or expired");

        let e = AuthorizationError::Denied {
            action: "read".into(),
            resource: "/vol/1".into(),
            reason: "no capability".into(),
        };
        assert!(e.to_string().contains("read"));
        assert!(e.to_string().contains("/vol/1"));
        assert!(e.to_string().contains("no capability"));
    }

    #[test]
    fn authorization_error_override_ticket() {
        let e = AuthorizationError::OverrideTicketInvalid { ticket_id: 5 };
        assert!(e.to_string().contains("5"));
        assert!(e.to_string().contains("invalid"));

        let e = AuthorizationError::OverrideTicketExhausted {
            ticket_id: 3,
            used: 10,
            max_uses: 10,
        };
        assert!(e.to_string().contains("3"));
        assert!(e.to_string().contains("10"));
    }

    #[test]
    fn security_error_display() {
        let e = SecurityError::AdminAccessDenied("not authorized".into());
        assert_eq!(e.to_string(), "ADMIN access denied: not authorized");

        let e = SecurityError::UnknownPskIdentity {
            identity: "node7".into(),
        };
        assert_eq!(e.to_string(), "unknown PSK identity: node7");
    }
}
