// auth_state_machine.rs — override ticket lifecycle (issue, consume,
// dual-control, expiry, exhaustion), audit chain sealing and
// integrity verification, session grant state transitions, and
// security response envelope classes.

use tidefs_auth::*;

// ---------------------------------------------------------------------------
// OverrideTicket: creation, validity, expiry, exhaustion, dual-control
// ---------------------------------------------------------------------------

#[test]
fn override_ticket_new_is_valid() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let ticket = OverrideTicket::new(
        OverrideTicketId::new(1),
        OverrideClass::ReserveFloorRelaxation,
        OverrideProfileId::new(1),
        PrincipalId::new(10),
        3_600_000,
        5,
        &key,
    );
    assert_eq!(ticket.ticket_id, OverrideTicketId::new(1));
    assert_eq!(ticket.use_count, 0);
    assert_eq!(ticket.max_use_count, 5);
    assert!(ticket.is_valid());
    assert!(!ticket.is_expired());
    assert!(!ticket.is_exhausted());
    assert!(!ticket.has_dual_control()); // only 1 signature
    assert_eq!(ticket.authorization_signatures.len(), 1);
}

#[test]
fn override_ticket_expires_with_zero_ttl() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let ticket = OverrideTicket::new(
        OverrideTicketId::new(1),
        OverrideClass::ProductAdmissionBypass,
        OverrideProfileId::new(1),
        PrincipalId::new(10),
        0,
        1,
        &key,
    );
    assert_eq!(ticket.expires_at_millis, ticket.issued_at_millis);
}

#[test]
fn override_ticket_not_expired_with_future_ttl() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let ticket = OverrideTicket::new(
        OverrideTicketId::new(1),
        OverrideClass::ExpensivePathAdmission,
        OverrideProfileId::new(1),
        PrincipalId::new(10),
        86_400_000, // 1 day
        100,
        &key,
    );
    assert!(!ticket.is_expired());
}

#[test]
fn override_ticket_becomes_exhausted_after_max_uses() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut ticket = OverrideTicket::new(
        OverrideTicketId::new(1),
        OverrideClass::RepairPublication,
        OverrideProfileId::new(1),
        PrincipalId::new(10),
        3_600_000,
        3,
        &key,
    );
    assert!(ticket.is_valid());
    ticket.record_use();
    assert!(ticket.is_valid());
    assert_eq!(ticket.use_count, 1);
    ticket.record_use();
    ticket.record_use();
    assert_eq!(ticket.use_count, 3);
    assert!(ticket.is_exhausted());
    assert!(!ticket.is_valid());
}

#[test]
fn override_ticket_dual_control_with_second_signature() {
    let (_, key1) = NodeIdentity::generate(1).expect("generate");
    let (_, key2) = NodeIdentity::generate(2).expect("generate");
    let mut ticket = OverrideTicket::new(
        OverrideTicketId::new(1),
        OverrideClass::SensitiveVisibilityDisclosure,
        OverrideProfileId::new(1),
        PrincipalId::new(10),
        3_600_000,
        1,
        &key1,
    );
    assert!(!ticket.has_dual_control());
    ticket.add_dual_signature(&key2);
    assert!(ticket.has_dual_control());
    assert_eq!(ticket.authorization_signatures.len(), 2);
}

// ---------------------------------------------------------------------------
// OverrideClass Display
// ---------------------------------------------------------------------------

#[test]
fn override_class_display() {
    assert_eq!(
        OverrideClass::ReserveFloorRelaxation.to_string(),
        "reserve_floor_relaxation"
    );
    assert_eq!(
        OverrideClass::ProductAdmissionBypass.to_string(),
        "product_admission_bypass"
    );
    assert_eq!(
        OverrideClass::ExpensivePathAdmission.to_string(),
        "expensive_path_admission"
    );
    assert_eq!(
        OverrideClass::RepairPublication.to_string(),
        "repair_publication"
    );
    assert_eq!(
        OverrideClass::FailoverCutoverAcceleration.to_string(),
        "failover_cutover_acceleration"
    );
    assert_eq!(
        OverrideClass::SensitiveVisibilityDisclosure.to_string(),
        "sensitive_visibility_disclosure"
    );
}

// ---------------------------------------------------------------------------
// determine_override_requirement_or_sufficiency
// ---------------------------------------------------------------------------

fn mk_principal(class: PrincipalClass, caps: &[&str]) -> Principal {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let role = if caps.is_empty() {
        None
    } else {
        Some(RoleBinding::new(
            RoleBindingId(1),
            "test".into(),
            caps.iter().map(|c| c.to_string()).collect(),
            ScopeSelector::All,
            &key,
        ))
    };
    Principal::new(PrincipalId::new(1), class, 10, role.into_iter().collect())
}

#[test]
fn determine_override_override_issue_always_requires_override() {
    let principal = mk_principal(PrincipalClass::HumanOperator, &["override"]);
    let request =
        AuthorizationRequest::new(principal, 1, ActionClass::OverrideIssue, ScopeSelector::All);
    let result = determine_override_requirement_or_sufficiency(&request);
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[test]
fn determine_override_repair_publish_by_operator_ok() {
    let principal = mk_principal(PrincipalClass::HumanOperator, &["repair"]);
    let request =
        AuthorizationRequest::new(principal, 1, ActionClass::RepairPublish, ScopeSelector::All);
    let result = determine_override_requirement_or_sufficiency(&request);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none()); // operator doesn't need override
}

#[test]
fn determine_override_repair_publish_by_service_needs_override() {
    let principal = mk_principal(PrincipalClass::Service, &["repair"]);
    let request =
        AuthorizationRequest::new(principal, 1, ActionClass::RepairPublish, ScopeSelector::All);
    let result = determine_override_requirement_or_sufficiency(&request);
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[test]
fn determine_override_failover_with_capability_ok() {
    let principal = mk_principal(PrincipalClass::HumanOperator, &["failover"]);
    let request =
        AuthorizationRequest::new(principal, 1, ActionClass::FailoverStage, ScopeSelector::All);
    let result = determine_override_requirement_or_sufficiency(&request);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn determine_override_failover_without_capability_needs_override() {
    let principal = mk_principal(PrincipalClass::HumanOperator, &[]);
    let request =
        AuthorizationRequest::new(principal, 1, ActionClass::FailoverStage, ScopeSelector::All);
    let result = determine_override_requirement_or_sufficiency(&request);
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[test]
fn determine_override_observe_no_override_needed() {
    let principal = mk_principal(PrincipalClass::Auditor, &["observe"]);
    let request = AuthorizationRequest::new(principal, 1, ActionClass::Observe, ScopeSelector::All);
    let result = determine_override_requirement_or_sufficiency(&request);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// issue_typed_override_ticket_under_dual_control
// ---------------------------------------------------------------------------

#[test]
fn issue_override_ticket_respects_constraint_profile() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let profile = OverrideConstraintProfileRecord::new(
        OverrideProfileId::new(1),
        vec![],
        ScopeSelector::All,
        60000, // max 1 minute
        3,     // max 3 uses
        false, // no dual control
    );
    let ticket = issue_typed_override_ticket_under_dual_control(
        OverrideTicketId::new(1),
        OverrideClass::ReserveFloorRelaxation,
        &profile,
        PrincipalId::new(1),
        3_600_000, // requested 1 hour → capped to 60s
        10,        // requested 10 uses → capped to 3
        &key,
        None,
    )
    .expect("should issue");
    assert_eq!(ticket.max_use_count, 3);
    // TTL should be clipped to 60s
    let ttl = ticket.expires_at_millis - ticket.issued_at_millis;
    assert!(ttl <= 60000);
}

#[test]
fn issue_override_ticket_dual_control_fails_without_secondary() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let profile = OverrideConstraintProfileRecord::new(
        OverrideProfileId::new(1),
        vec![],
        ScopeSelector::All,
        3_600_000,
        5,
        true, // dual control required
    );
    let result = issue_typed_override_ticket_under_dual_control(
        OverrideTicketId::new(1),
        OverrideClass::SensitiveVisibilityDisclosure,
        &profile,
        PrincipalId::new(1),
        3_600_000,
        5,
        &key,
        None, // no secondary key
    );
    assert!(result.is_err());
}

#[test]
fn issue_override_ticket_dual_control_succeeds_with_secondary() {
    let (_, key1) = NodeIdentity::generate(1).expect("generate");
    let (_, key2) = NodeIdentity::generate(2).expect("generate");
    let profile = OverrideConstraintProfileRecord::new(
        OverrideProfileId::new(1),
        vec![],
        ScopeSelector::All,
        3_600_000,
        5,
        true,
    );
    let ticket = issue_typed_override_ticket_under_dual_control(
        OverrideTicketId::new(1),
        OverrideClass::SensitiveVisibilityDisclosure,
        &profile,
        PrincipalId::new(1),
        3_600_000,
        5,
        &key1,
        Some(&key2),
    )
    .expect("should issue");
    assert!(ticket.has_dual_control());
}

// ---------------------------------------------------------------------------
// consume_override_ticket_and_bind_it_to_action
// ---------------------------------------------------------------------------

#[test]
fn consume_override_ticket_produces_consumption_record() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut ticket = OverrideTicket::new(
        OverrideTicketId::new(1),
        OverrideClass::RepairPublication,
        OverrideProfileId::new(1),
        PrincipalId::new(10),
        3_600_000,
        5,
        &key,
    );
    let profile = OverrideConstraintProfileRecord::new(
        OverrideProfileId::new(1),
        vec![],
        ScopeSelector::All,
        3_600_000,
        10,
        false,
    );
    let principal = Principal::new(PrincipalId::new(1), PrincipalClass::Service, 10, vec![]);
    let decision = evaluate_authorization(
        &AuthorizationRequest::new(
            principal.clone(),
            42,
            ActionClass::RepairPublish,
            ScopeSelector::All,
        ),
        10,
    );
    let mut audit_log = AuditLog::new();

    let record = consume_override_ticket_and_bind_it_to_action(
        &mut ticket,
        &decision,
        &mut audit_log,
        &principal,
        42,
        &profile,
    )
    .expect("consume should succeed");

    assert_eq!(record.ticket_id, 1);
    assert_eq!(ticket.use_count, 1);
    assert!(!record.action_receipt.is_empty());
    // Audit log should have an event
    assert_eq!(audit_log.events.len(), 1);
}

#[test]
fn consume_override_ticket_fails_when_exhausted() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut ticket = OverrideTicket::new(
        OverrideTicketId::new(1),
        OverrideClass::RepairPublication,
        OverrideProfileId::new(1),
        PrincipalId::new(10),
        3_600_000,
        1,
        &key,
    );
    let profile = OverrideConstraintProfileRecord::new(
        OverrideProfileId::new(1),
        vec![],
        ScopeSelector::All,
        3_600_000,
        10,
        false,
    );
    let principal = Principal::new(PrincipalId::new(1), PrincipalClass::Service, 10, vec![]);
    let decision = evaluate_authorization(
        &AuthorizationRequest::new(
            principal.clone(),
            42,
            ActionClass::RepairPublish,
            ScopeSelector::All,
        ),
        10,
    );
    let mut audit_log = AuditLog::new();

    // First use succeeds
    assert!(consume_override_ticket_and_bind_it_to_action(
        &mut ticket,
        &decision,
        &mut audit_log,
        &principal,
        42,
        &profile,
    )
    .is_ok());

    // Second use fails (ticket exhausted)
    let result = consume_override_ticket_and_bind_it_to_action(
        &mut ticket,
        &decision,
        &mut audit_log,
        &principal,
        42,
        &profile,
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthorizationError::OverrideTicketInvalid { .. }
    ));
}

// ---------------------------------------------------------------------------
// AuditLog: chain sealing and integrity verification
// ---------------------------------------------------------------------------

#[test]
fn audit_log_seal_and_verify_chain() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut log = AuditLog::new();

    // Add some events
    let principal_id = PrincipalId::new(1);
    let session_id: u64 = 42;

    let decision = AuthorizationDecision {
        request: AuthorizationRequest::new(
            Principal::new(principal_id, PrincipalClass::HumanOperator, 10, vec![]),
            session_id,
            ActionClass::Stage,
            ScopeSelector::All,
        ),
        outcome: AuthorizationOutcome::Allowed,
        matched_roles: vec![],
        decided_at_millis: 1000,
        decider_node_id: 1,
    };

    log.record_decision(&decision, principal_id, session_id);
    log.record_decision(&decision, principal_id, session_id);

    // Seal
    let anchor = log
        .seal_events(log.events[0].event_id, log.events[1].event_id, &key)
        .expect("seal should succeed");
    assert_eq!(anchor.event_count, 2);
    assert!(!anchor.seal_hash.iter().all(|&b| b == 0));

    // Verify chain integrity
    assert!(log.verify_chain_integrity().is_ok());
}

#[test]
fn audit_log_seal_empty_range_fails() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut log = AuditLog::new();
    let result = log.seal_events(
        crate::audit::AuditEventId::new(1),
        crate::audit::AuditEventId::new(10),
        &key,
    );
    assert!(result.is_err());
}

#[test]
fn audit_log_chain_link_verified() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut log = AuditLog::new();
    let principal_id = PrincipalId::new(1);

    let decision = AuthorizationDecision {
        request: AuthorizationRequest::new(
            Principal::new(principal_id, PrincipalClass::Auditor, 10, vec![]),
            1,
            ActionClass::Observe,
            ScopeSelector::All,
        ),
        outcome: AuthorizationOutcome::Allowed,
        matched_roles: vec![],
        decided_at_millis: 1000,
        decider_node_id: 0,
    };

    // First batch of 2 events
    log.record_decision(&decision, principal_id, 1);
    log.record_decision(&decision, principal_id, 1);
    log.seal_events(log.events[0].event_id, log.events[1].event_id, &key)
        .expect("first seal");

    // Second batch of 1 event
    log.record_decision(&decision, principal_id, 1);
    log.seal_events(log.events[2].event_id, log.events[2].event_id, &key)
        .expect("second seal");

    // Chain should verify (prior anchor hash linkage)
    assert!(log.verify_chain_integrity().is_ok());
}

#[test]
fn audit_log_record_session_event() {
    let mut log = AuditLog::new();
    let event_id = log.record_session(
        AuditEventKind::SessionEstablished { peer_node_id: 42 },
        PrincipalId::new(1),
        100,
    );
    assert!(event_id.0 > 0);
    assert_eq!(log.events.len(), 1);
}

#[test]
fn audit_log_events_for_principal_filtering() {
    let mut log = AuditLog::new();
    let d = AuthorizationDecision {
        request: AuthorizationRequest::new(
            Principal::new(PrincipalId::new(1), PrincipalClass::Auditor, 10, vec![]),
            1,
            ActionClass::Observe,
            ScopeSelector::All,
        ),
        outcome: AuthorizationOutcome::Allowed,
        matched_roles: vec![],
        decided_at_millis: 1000,
        decider_node_id: 0,
    };
    log.record_decision(&d, PrincipalId::new(1), 1);
    log.record_decision(&d, PrincipalId::new(2), 1);
    log.record_decision(&d, PrincipalId::new(1), 1);

    assert_eq!(log.events_for_principal(PrincipalId::new(1)).len(), 2);
    assert_eq!(log.events_for_principal(PrincipalId::new(2)).len(), 1);
    assert_eq!(log.events_for_principal(PrincipalId::new(99)).len(), 0);
}

#[test]
fn audit_log_events_for_session_filtering() {
    let mut log = AuditLog::new();
    let d = AuthorizationDecision {
        request: AuthorizationRequest::new(
            Principal::new(PrincipalId::new(1), PrincipalClass::Auditor, 10, vec![]),
            1,
            ActionClass::Observe,
            ScopeSelector::All,
        ),
        outcome: AuthorizationOutcome::Allowed,
        matched_roles: vec![],
        decided_at_millis: 1000,
        decider_node_id: 0,
    };
    log.record_decision(&d, PrincipalId::new(1), 100);
    log.record_decision(&d, PrincipalId::new(1), 200);
    log.record_decision(&d, PrincipalId::new(1), 100);

    assert_eq!(log.events_for_session(100).len(), 2);
    assert_eq!(log.events_for_session(200).len(), 1);
}

#[test]
fn audit_log_unsealed_events_after_seal() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut log = AuditLog::new();
    let d = AuthorizationDecision {
        request: AuthorizationRequest::new(
            Principal::new(PrincipalId::new(1), PrincipalClass::Auditor, 10, vec![]),
            1,
            ActionClass::Observe,
            ScopeSelector::All,
        ),
        outcome: AuthorizationOutcome::Allowed,
        matched_roles: vec![],
        decided_at_millis: 1000,
        decider_node_id: 0,
    };

    log.record_decision(&d, PrincipalId::new(1), 1);
    log.record_decision(&d, PrincipalId::new(1), 1);
    log.record_decision(&d, PrincipalId::new(1), 1);

    // Unsealed: all 3
    assert_eq!(log.unsealed_event_count(), 3);

    // Seal first 2
    log.seal_events(log.events[0].event_id, log.events[1].event_id, &key)
        .expect("seal");

    // Unsealed: last 1
    assert_eq!(log.unsealed_event_count(), 1);
}

// ---------------------------------------------------------------------------
// append_audit_event_and_seal_chain_if_needed
// ---------------------------------------------------------------------------

#[test]
fn append_and_seal_chains_when_threshold_exceeded() {
    let (_, key) = NodeIdentity::generate(1).expect("generate");
    let mut log = AuditLog::new();
    let d = AuthorizationDecision {
        request: AuthorizationRequest::new(
            Principal::new(PrincipalId::new(1), PrincipalClass::Auditor, 10, vec![]),
            1,
            ActionClass::Observe,
            ScopeSelector::All,
        ),
        outcome: AuthorizationOutcome::Allowed,
        matched_roles: vec![],
        decided_at_millis: 1000,
        decider_node_id: 0,
    };

    // Add 3 events with threshold=2 (triggers seal at 2, then again at 4)
    let (_eid, anchor) =
        append_audit_event_and_seal_chain_if_needed(&mut log, &d, PrincipalId::new(1), 1, &key, 2)
            .expect("append");
    assert_eq!(log.events.len(), 1);
    assert!(anchor.is_none()); // 1 < 2 threshold

    let (_eid, anchor) =
        append_audit_event_and_seal_chain_if_needed(&mut log, &d, PrincipalId::new(1), 1, &key, 2)
            .expect("append");
    assert_eq!(log.events.len(), 2);
    assert!(anchor.is_some()); // 2 >= 2 threshold, seals

    // After sealing a new event, unsealed count resets
    let (_eid, anchor) =
        append_audit_event_and_seal_chain_if_needed(&mut log, &d, PrincipalId::new(1), 1, &key, 2)
            .expect("append");
    assert_eq!(log.events.len(), 3);
    assert!(anchor.is_none()); // only 1 unsealed after seal
}

// ---------------------------------------------------------------------------
// SecurityResponseEnvelope: constructors and classes
// ---------------------------------------------------------------------------

#[test]
fn security_response_envelope_new_sets_timestamp() {
    let envelope = SecurityResponseEnvelope::new(
        SecurityResponseClass::AuthnFailed {
            principal_id: None,
            reason: "bad credentials".into(),
        },
        None,
        None,
    );
    assert!(envelope.issued_at_millis > 0);
}

#[test]
fn security_response_class_authn_failed() {
    let class = SecurityResponseClass::authn_failed("token expired".into());
    assert!(matches!(class, SecurityResponseClass::AuthnFailed { .. }));
    assert!(class.to_string().contains("token expired"));
}

#[test]
fn security_response_class_session_expired() {
    let class = SecurityResponseClass::session_expired(42, 5000);
    assert!(matches!(
        class,
        SecurityResponseClass::SessionExpired { .. }
    ));
    assert!(class.to_string().contains("session 42"));
}

#[test]
fn security_response_class_authz_denied() {
    let class = SecurityResponseClass::AuthzDenied {
        principal_id: PrincipalId::new(1),
        reason: "no capability".into(),
    };
    assert!(matches!(class, SecurityResponseClass::AuthzDenied { .. }));
    assert!(class.to_string().contains("no capability"));
}

#[test]
fn security_response_class_override_required() {
    let class = SecurityResponseClass::override_required(
        PrincipalId::new(1),
        "publish",
        "reserve_floor_relaxation",
    );
    assert!(matches!(
        class,
        SecurityResponseClass::OverrideRequired { .. }
    ));
}

#[test]
fn security_response_class_override_invalid() {
    let class = SecurityResponseClass::override_invalid(5, "expired".into());
    assert!(matches!(
        class,
        SecurityResponseClass::OverrideInvalid { .. }
    ));
}

#[test]
fn security_response_class_visibility_redacted() {
    let class = SecurityResponseClass::visibility_redacted(PrincipalId::new(1), "/secret");
    assert!(matches!(
        class,
        SecurityResponseClass::VisibilityRedacted { .. }
    ));
    assert!(class.to_string().contains("/secret"));
}

#[test]
fn security_response_class_from_denied() {
    let decision = AuthorizationDecision {
        request: AuthorizationRequest::new(
            Principal::new(PrincipalId::new(1), PrincipalClass::Auditor, 10, vec![]),
            1,
            ActionClass::Observe,
            ScopeSelector::All,
        ),
        outcome: AuthorizationOutcome::Denied("access denied".into()),
        matched_roles: vec![],
        decided_at_millis: 1000,
        decider_node_id: 0,
    };
    let class = SecurityResponseClass::from_denied(PrincipalId::new(1), &decision);
    assert!(matches!(class, SecurityResponseClass::AuthzDenied { .. }));
}

// ---------------------------------------------------------------------------
// Error variant coverage: untested error types
// ---------------------------------------------------------------------------

#[test]
fn attestation_error_nonce_replay() {
    let e = AttestationError::NonceReplay { node_id: 7 };
    assert!(e.to_string().contains("node 7"));
}

#[test]
fn attestation_error_challenge_failed() {
    let e = AttestationError::ChallengeFailed {
        reason: "bad sig".into(),
    };
    assert!(e.to_string().contains("bad sig"));
}

#[test]
fn attestation_error_session_class_mismatch() {
    let e = AttestationError::SessionClassMismatch {
        offered: "full_mesh".into(),
        accepted: "ring".into(),
    };
    assert!(e.to_string().contains("full_mesh"));
    assert!(e.to_string().contains("ring"));
}

#[test]
fn attestation_error_protocol_version_not_supported() {
    let e = AttestationError::ProtocolVersionNotSupported {
        offered: vec![1, 2],
        accepted: 3,
    };
    assert!(e.to_string().contains("[1, 2]"));
}

#[test]
fn authorization_error_dual_control_required() {
    let e = AuthorizationError::DualControlRequired {
        ticket_id: 5,
        sig_count: 1,
    };
    assert!(e.to_string().contains("5"));
    assert!(e.to_string().contains("1"));
}

#[test]
fn authorization_error_session_grant_error() {
    let e = AuthorizationError::SessionGrantError {
        reason: "revoked at epoch 5 (current: 10)".into(),
    };
    assert!(e.to_string().contains("session grant error"));
    assert!(e.to_string().contains("revoked at epoch 5"));
}

#[test]
fn authorization_error_role_binding_conflict() {
    let e = AuthorizationError::RoleBindingConflict {
        reason: "duplicate".into(),
    };
    assert!(e.to_string().contains("duplicate"));
}

#[test]
fn identity_error_credential_binding_not_found() {
    let e = IdentityError::CredentialBindingNotFound { hash: [0xAAu8; 32] };
    assert!(e.to_string().contains("credential binding not found"));
}

#[test]
fn identity_error_credential_binding_expired() {
    let e = IdentityError::CredentialBindingExpired {
        principal_id: "p-42".into(),
    };
    assert!(e.to_string().contains("credential binding expired"));
    assert!(e.to_string().contains("p-42"));
}

// ---------------------------------------------------------------------------
// error type equality
// ---------------------------------------------------------------------------

#[test]
fn attestation_error_equality() {
    let e1 = AttestationError::NonceMismatch;
    let e2 = AttestationError::NonceMismatch;
    assert_eq!(e1, e2);
}

#[test]
fn identity_error_equality() {
    let e1 = IdentityError::Expired { version: 1 };
    let e2 = IdentityError::Expired { version: 1 };
    assert_eq!(e1, e2);
    let e3 = IdentityError::Expired { version: 2 };
    assert_ne!(e1, e3);
}

#[test]
fn security_error_equality() {
    let e1 = tidefs_auth::error::SecurityError::AdminAccessDenied("no".into());
    let e2 = tidefs_auth::error::SecurityError::AdminAccessDenied("no".into());
    assert_eq!(e1, e2);
}
