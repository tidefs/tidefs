use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit::{AuditEvent, AuditEventId, AuditLog};
use crate::error::AuthorizationError;
use crate::records::AuditChainAnchorRecord;

// ---------------------------------------------------------------------------
// Audit log durability: JSON snapshot with atomic file persistence
// ---------------------------------------------------------------------------

/// Current on-disk format version.
const AUDIT_LOG_VERSION: u32 = 1;

/// Serializable snapshot of the full audit log state.
///
/// This is the on-disk representation.  On load, chain integrity is
/// verified before the log is returned to the caller, providing tamper
/// validation: any modification of the persisted file will cause the
/// integrity check to fail and the load to be refused.
#[derive(Serialize, Deserialize, Debug)]
struct AuditLogSnapshot {
    version: u32,
    events: Vec<AuditEvent>,
    anchors: Vec<AuditChainAnchorRecord>,
    next_event_id: u64,
    next_anchor_id: u64,
    sealed_up_to: Option<AuditEventId>,
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

impl AuditLog {
    /// Serialize the full audit log state to a JSON byte vector.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let snapshot = AuditLogSnapshot {
            version: AUDIT_LOG_VERSION,
            events: self.events.clone(),
            anchors: self.anchors.clone(),
            next_event_id: self.next_event_id,
            next_anchor_id: self.next_anchor_id,
            sealed_up_to: self.sealed_up_to,
        };
        serde_json::to_vec(&snapshot)
    }

    /// Deserialize audit log state from JSON bytes, then verify chain
    /// integrity before returning.  Tampered files are rejected.
    pub fn from_json_bytes(json: &[u8]) -> Result<Self, AuthorizationError> {
        let snapshot: AuditLogSnapshot = serde_json::from_slice(json).map_err(|e| {
            AuthorizationError::AuditLogPersistenceFailed {
                reason: format!("failed to deserialize audit log: {e}"),
            }
        })?;

        if snapshot.version != AUDIT_LOG_VERSION {
            return Err(AuthorizationError::AuditLogPersistenceFailed {
                reason: format!(
                    "unsupported audit log version {} (expected {AUDIT_LOG_VERSION})",
                    snapshot.version
                ),
            });
        }

        let log = AuditLog {
            events: snapshot.events,
            anchors: snapshot.anchors,
            next_event_id: snapshot.next_event_id,
            next_anchor_id: snapshot.next_anchor_id,
            sealed_up_to: snapshot.sealed_up_to,
        };

        // Verify chain integrity — this is the tamper-validation gate.
        log.verify_chain_integrity().map_err(|e| {
            AuthorizationError::AuditLogPersistenceFailed {
                reason: format!("audit log integrity check failed on load: {e}"),
            }
        })?;

        Ok(log)
    }
}

// ---------------------------------------------------------------------------
// File I/O — atomic writes via temp+rename
// ---------------------------------------------------------------------------

impl AuditLog {
    /// Atomically persist the audit log to `path`.
    ///
    /// Writes to a temporary file first, then atomically renames it over
    /// the target path.  This prevents corruption from partial writes
    /// (e.g. crash mid-write, out-of-disk-space).
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), AuthorizationError> {
        let path = path.as_ref();
        let json =
            self.to_json_bytes()
                .map_err(|e| AuthorizationError::AuditLogPersistenceFailed {
                    reason: format!("serialization failed: {e}"),
                })?;

        // Atomic write: write to .tmp, then rename.
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &json).map_err(|e| AuthorizationError::AuditLogPersistenceFailed {
            reason: format!("write to {} failed: {e}", tmp_path.display()),
        })?;
        fs::rename(&tmp_path, path).map_err(|e| AuthorizationError::AuditLogPersistenceFailed {
            reason: format!("rename to {} failed: {e}", path.display()),
        })?;

        Ok(())
    }

    /// Load an audit log from `path`, verifying chain integrity.
    ///
    /// Returns `AuditLogPersistenceFailed` if the file does not exist,
    /// is malformed, has an unsupported version, or fails integrity
    /// verification.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, AuthorizationError> {
        let path = path.as_ref();
        let json = fs::read(path).map_err(|e| AuthorizationError::AuditLogPersistenceFailed {
            reason: match e.kind() {
                io::ErrorKind::NotFound => {
                    format!("audit log file not found: {}", path.display())
                }
                _ => format!("failed to read {}: {e}", path.display()),
            },
        })?;

        Self::from_json_bytes(&json)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{ActionClass, AuthorizationDecision, AuthorizationOutcome};
    use crate::principal::{Principal, PrincipalClass, PrincipalId, ScopeSelector};
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    fn make_decision(allowed: bool) -> AuthorizationDecision {
        let outcome = if allowed {
            AuthorizationOutcome::Allowed
        } else {
            AuthorizationOutcome::Denied("test denial".into())
        };
        AuthorizationDecision {
            request: crate::authorization::AuthorizationRequest {
                principal: Principal::new(
                    PrincipalId::new(1),
                    PrincipalClass::ClusterNode,
                    0,
                    Vec::new(),
                ),
                session_id: 1,
                action: ActionClass::Observe,
                resource: ScopeSelector::All,
                override_ticket_id: None,
            },
            outcome,
            matched_roles: Vec::new(),
            decided_at_millis: 1000,
            decider_node_id: 0,
        }
    }

    fn make_keypair() -> Keypair {
        let mut csprng = OsRng;
        Keypair::generate(&mut csprng)
    }

    fn populate_log(log: &mut AuditLog, n: usize) {
        for i in 0..n {
            let d = make_decision(i % 3 == 0);
            log.record_decision(&d, PrincipalId::new((i as u64) % 5), i as u64);
        }
    }

    // ------------------------------------------------------------------
    // Round-trip through bytes
    // ------------------------------------------------------------------

    #[test]
    fn empty_log_roundtrip() {
        let log = AuditLog::new();
        let json = log.to_json_bytes().expect("serialize");
        let restored = AuditLog::from_json_bytes(&json).expect("deserialize+verify");
        assert!(restored.events.is_empty());
        assert!(restored.anchors.is_empty());
        assert_eq!(restored.next_event_id, 1);
        assert_eq!(restored.next_anchor_id, 1);
    }

    #[test]
    fn populated_log_roundtrip_no_seals() {
        let mut log = AuditLog::new();
        populate_log(&mut log, 5);
        let json = log.to_json_bytes().expect("serialize");
        let restored = AuditLog::from_json_bytes(&json).expect("deserialize+verify");
        assert_eq!(restored.events.len(), 5);
        assert_eq!(restored.next_event_id, 6);
    }

    #[test]
    fn populated_log_with_seals_roundtrip() {
        let mut log = AuditLog::new();
        let key = make_keypair();
        populate_log(&mut log, 6);

        log.seal_events(AuditEventId::new(1), AuditEventId::new(3), &key)
            .expect("first seal");
        log.seal_events(AuditEventId::new(4), AuditEventId::new(6), &key)
            .expect("second seal");

        let json = log.to_json_bytes().expect("serialize");
        let restored = AuditLog::from_json_bytes(&json).expect("deserialize+verify");

        assert_eq!(restored.events.len(), 6);
        assert_eq!(restored.anchors.len(), 2);
        assert_eq!(restored.next_event_id, 7);
        assert_eq!(restored.next_anchor_id, 3);

        // Verify seal data survived round-trip.
        assert_eq!(restored.anchors[0].event_range_start, AuditEventId::new(1));
        assert_eq!(restored.anchors[0].event_range_end, AuditEventId::new(3));
        assert_eq!(restored.anchors[1].event_range_start, AuditEventId::new(4));
        assert_eq!(restored.anchors[1].event_range_end, AuditEventId::new(6));
    }

    // ------------------------------------------------------------------
    // Tamper validation
    // ------------------------------------------------------------------

    #[test]
    fn tampered_json_rejected() {
        let mut log = AuditLog::new();
        let key = make_keypair();
        populate_log(&mut log, 3);
        log.seal_events(AuditEventId::new(1), AuditEventId::new(3), &key)
            .expect("seal");

        let mut json = log.to_json_bytes().expect("serialize");

        // Flip a byte in the serialized payload — simulate tampering.
        json[10] ^= 0xFF;

        let result = AuditLog::from_json_bytes(&json);
        assert!(result.is_err(), "tampered JSON must be rejected");
    }

    #[test]
    fn tampered_event_data_rejected() {
        let mut log = AuditLog::new();
        let key = make_keypair();
        populate_log(&mut log, 4);
        log.seal_events(AuditEventId::new(1), AuditEventId::new(4), &key)
            .expect("seal");

        let json = log.to_json_bytes().expect("serialize");

        // Deserialize, modify event data, re-serialize — the seal hash
        // won't match the re-computed hash during verify_chain_integrity.
        let mut snapshot: AuditLogSnapshot =
            serde_json::from_slice(&json).expect("deserialize snapshot");
        // Change the last event's principal_id.
        snapshot.events.last_mut().unwrap().principal_id = PrincipalId::new(999);
        let tampered_json = serde_json::to_vec(&snapshot).expect("re-serialize");

        let result = AuditLog::from_json_bytes(&tampered_json);
        assert!(
            result.is_err(),
            "tampered event data must be rejected by integrity check"
        );
    }

    #[test]
    fn wrong_version_rejected() {
        let log = AuditLog::new();
        let json = log.to_json_bytes().expect("serialize");

        // Patch version to 99.
        let json_str = String::from_utf8(json).expect("utf8");
        let tampered = json_str.replace("\"version\":1", "\"version\":99");

        let result = AuditLog::from_json_bytes(tampered.as_bytes());
        assert!(result.is_err(), "unsupported version must be rejected");
    }

    // ------------------------------------------------------------------
    // File I/O round-trip
    // ------------------------------------------------------------------

    #[test]
    fn save_load_file_roundtrip() {
        let mut log = AuditLog::new();
        let key = make_keypair();
        populate_log(&mut log, 5);
        log.seal_events(AuditEventId::new(1), AuditEventId::new(5), &key)
            .expect("seal");

        let dir = std::env::temp_dir();
        let path = dir.join("tidefs_audit_test_persistence.json");

        log.save_to_file(&path).expect("save");
        let restored = AuditLog::load_from_file(&path).expect("load+verify");

        assert_eq!(restored.events.len(), log.events.len());
        assert_eq!(restored.anchors.len(), log.anchors.len());
        assert_eq!(restored.next_event_id, log.next_event_id);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_nonexistent_file_fails() {
        let result = AuditLog::load_from_file("/nonexistent/tidefs_audit_log.json");
        assert!(result.is_err(), "nonexistent file must fail");
    }

    #[test]
    fn save_load_empty_log() {
        let log = AuditLog::new();
        let dir = std::env::temp_dir();
        let path = dir.join("tidefs_audit_test_empty.json");

        log.save_to_file(&path).expect("save empty");
        let restored = AuditLog::load_from_file(&path).expect("load empty");
        assert!(restored.events.is_empty());
        let _ = fs::remove_file(&path);
    }
}
