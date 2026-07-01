// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};

use crate::authorization::AuthorizationDecision;
use crate::principal::PrincipalId;
use crate::records::AuditChainAnchorRecord;

// ---------------------------------------------------------------------------
// Audit trail: receipts for every authorization decision
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuditEventId(pub u64);

impl AuditEventId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: AuditEventId,
    pub decision: AuthorizationDecision,
    pub principal_id: PrincipalId,
    pub session_id: u64,
    pub event_kind: AuditEventKind,
    pub recorded_at_millis: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AuditEventKind {
    AccessGranted,
    AccessDenied {
        reason: String,
    },
    OverrideUsed {
        ticket_id: u64,
    },
    RoleGranted {
        role: String,
        granted_by: PrincipalId,
    },
    RoleRevoked {
        role: String,
        revoked_by: PrincipalId,
    },
    KeyRotated {
        node_id: u64,
        old_version: u64,
        new_version: u64,
    },
    SessionEstablished {
        peer_node_id: u64,
    },
    SessionTerminated {
        peer_node_id: u64,
        reason: String,
    },
    ChainSealed {
        anchor_id: crate::records::AuditChainAnchorId,
    },
    OverrideConsumed {
        ticket_id: u64,
        consumption_id: crate::records::OverrideConsumptionId,
    },
    OverrideTicketIssued {
        ticket_id: u64,
        override_class: String,
    },
}

// ---------------------------------------------------------------------------
// Audit log: append-only event store with sealable chain
// ---------------------------------------------------------------------------

pub struct AuditLog {
    pub events: Vec<AuditEvent>,
    pub anchors: Vec<AuditChainAnchorRecord>,
    pub(crate) next_event_id: u64,
    pub(crate) next_anchor_id: u64,
    /// Events that have been sealed; all events up to this ID are in anchors.
    pub(crate) sealed_up_to: Option<AuditEventId>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            anchors: Vec::new(),
            next_event_id: 1,
            next_anchor_id: 1,
            sealed_up_to: None,
        }
    }

    /// Record an authorization decision as an audit event.
    pub fn record_decision(
        &mut self,
        decision: &AuthorizationDecision,
        principal_id: PrincipalId,
        session_id: u64,
    ) -> AuditEventId {
        let event_kind = match &decision.outcome {
            crate::authorization::AuthorizationOutcome::Allowed => AuditEventKind::AccessGranted,
            crate::authorization::AuthorizationOutcome::AllowedWithOverride { ticket_id } => {
                AuditEventKind::OverrideUsed {
                    ticket_id: *ticket_id,
                }
            }
            crate::authorization::AuthorizationOutcome::Denied(reason) => {
                AuditEventKind::AccessDenied {
                    reason: reason.clone(),
                }
            }
        };

        let event_id = AuditEventId::new(self.next_event_id);
        self.next_event_id += 1;

        let event = AuditEvent {
            event_id,
            decision: decision.clone(),
            principal_id,
            session_id,
            event_kind,
            recorded_at_millis: crate::identity::current_time_utils(),
        };

        self.events.push(event);
        event_id
    }

    /// Record a session lifecycle event.
    pub fn record_session(
        &mut self,
        kind: AuditEventKind,
        principal_id: PrincipalId,
        session_id: u64,
    ) -> AuditEventId {
        let event_id = AuditEventId::new(self.next_event_id);
        self.next_event_id += 1;

        // Create a minimal decision for session events
        let decision = AuthorizationDecision {
            request: crate::authorization::AuthorizationRequest {
                principal: crate::principal::Principal::new(
                    crate::principal::PrincipalId::new(0),
                    crate::principal::PrincipalClass::ClusterNode,
                    0,
                    Vec::new(),
                ),
                session_id,
                action: crate::authorization::ActionClass::Observe,
                resource: crate::principal::ScopeSelector::All,
                override_ticket_id: None,
            },
            outcome: crate::authorization::AuthorizationOutcome::Allowed,
            matched_roles: Vec::new(),
            decided_at_millis: crate::identity::current_time_utils(),
            decider_node_id: 0,
        };

        let event = AuditEvent {
            event_id,
            decision,
            principal_id,
            session_id,
            event_kind: kind,
            recorded_at_millis: crate::identity::current_time_utils(),
        };

        self.events.push(event);
        event_id
    }

    /// Retrieve events for a principal.
    pub fn events_for_principal(&self, principal_id: PrincipalId) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.principal_id == principal_id)
            .collect()
    }

    /// Retrieve events for a session.
    pub fn events_for_session(&self, session_id: u64) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.session_id == session_id)
            .collect()
    }

    /// Get unsealed events (those after the last seal or all if never sealed).
    pub fn unsealed_events(&self) -> &[AuditEvent] {
        match self.sealed_up_to {
            Some(last_sealed) => {
                let pos = self
                    .events
                    .iter()
                    .position(|e| e.event_id.0 > last_sealed.0);
                match pos {
                    Some(idx) => &self.events[idx..],
                    None => &[],
                }
            }
            None => &self.events,
        }
    }

    /// Get the number of unsealed events.
    pub fn unsealed_event_count(&self) -> usize {
        self.unsealed_events().len()
    }
}

// ---------------------------------------------------------------------------
// Chain sealing.
// ---------------------------------------------------------------------------

impl AuditLog {
    /// Seal a range of events into a chain anchor.
    ///
    /// All events from `start` through `end` (inclusive) are hashed together
    /// and sealed into an `AuditChainAnchorRecord` that also references the
    /// prior anchor's hash, providing tamper-evident ordering.
    ///
    /// Returns the new anchor record.
    pub fn seal_events(
        &mut self,
        start_id: AuditEventId,
        end_id: AuditEventId,
        signing_key: &Keypair,
    ) -> Result<AuditChainAnchorRecord, crate::error::AuthorizationError> {
        let events: Vec<&AuditEvent> = self
            .events
            .iter()
            .filter(|e| e.event_id.0 >= start_id.0 && e.event_id.0 <= end_id.0)
            .collect();

        if events.is_empty() {
            return Err(crate::error::AuthorizationError::AuditTrailBroken {
                reason: format!("no events in range {}-{}", start_id.0, end_id.0),
            });
        }

        let event_count = events.len() as u64;
        let seal_hash = crate::records::hash_audit_events(
            &events.iter().map(|e| (*e).clone()).collect::<Vec<_>>(),
        );

        let prior_anchor_hash = self.anchors.last().map(|a| a.seal_hash);

        let anchor_id = crate::records::AuditChainAnchorId::new(self.next_anchor_id);
        self.next_anchor_id += 1;

        let anchor = AuditChainAnchorRecord::new(
            anchor_id,
            start_id,
            end_id,
            event_count,
            seal_hash,
            prior_anchor_hash,
            signing_key,
        );

        self.anchors.push(anchor.clone());
        self.sealed_up_to = Some(end_id);

        Ok(anchor)
    }

    /// Validate the chain integrity by verifying each anchor's seal and linkage.
    pub fn verify_chain_integrity(&self) -> Result<(), crate::error::AuthorizationError> {
        for (i, anchor) in self.anchors.iter().enumerate() {
            // Recompute seal hash from the events in range
            let events: Vec<AuditEvent> = self
                .events
                .iter()
                .filter(|e| {
                    e.event_id.0 >= anchor.event_range_start.0
                        && e.event_id.0 <= anchor.event_range_end.0
                })
                .cloned()
                .collect();

            let recomputed_hash = crate::records::hash_audit_events(&events);

            if recomputed_hash != anchor.seal_hash {
                return Err(crate::error::AuthorizationError::AuditTrailBroken {
                    reason: format!(
                        "seal hash mismatch at anchor {}: expected {:?}, got {:?}",
                        anchor.anchor_id.0, anchor.seal_hash, recomputed_hash
                    ),
                });
            }

            // Validate prior anchor linkage
            if i > 0 {
                let prior = &self.anchors[i - 1];
                match anchor.prior_anchor_hash {
                    Some(ref hash) if hash == &prior.seal_hash => {}
                    _ => {
                        return Err(crate::error::AuthorizationError::AuditTrailBroken {
                            reason: format!(
                                "chain link broken at anchor {}: prior hash mismatch",
                                anchor.anchor_id.0
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Algorithm: append_audit_event_and_seal_chain_if_needed.
// ---------------------------------------------------------------------------

/// Append an audit event for a decision, and automatically seal the chain
/// if the unsealed event count exceeds the batch threshold.
pub fn append_audit_event_and_seal_chain_if_needed(
    audit_log: &mut AuditLog,
    decision: &AuthorizationDecision,
    principal_id: PrincipalId,
    session_id: u64,
    sealing_key: &Keypair,
    batch_size_threshold: usize,
) -> Result<(AuditEventId, Option<AuditChainAnchorRecord>), crate::error::AuthorizationError> {
    let event_id = audit_log.record_decision(decision, principal_id, session_id);

    let anchor = if audit_log.unsealed_event_count() >= batch_size_threshold {
        let unsealed = audit_log.unsealed_events();
        if unsealed.is_empty() {
            None
        } else {
            let start_id = unsealed[0].event_id;
            let end_id = unsealed[unsealed.len() - 1].event_id;
            Some(audit_log.seal_events(start_id, end_id, sealing_key)?)
        }
    } else {
        None
    };

    Ok((event_id, anchor))
}
