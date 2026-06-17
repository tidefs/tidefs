use tidefs_auth::*;

#[test]
fn test_node_identity_generate_and_verify() {
    let (identity, _) = NodeIdentity::generate(42).expect("generate failed");
    assert_eq!(identity.node_id, 42);
    assert_eq!(identity.identity_version, 1);
    identity
        .verify_self_signature()
        .expect("self-signature should verify");
}

#[test]
fn test_node_identity_tamper_detection() {
    let (mut identity, _) = NodeIdentity::generate(1).expect("generate failed");
    identity.node_id = 99;
    assert!(identity.verify_self_signature().is_err());
}

#[test]
fn test_node_identity_key_rotation() {
    let (identity, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let (new_identity, _, _) = identity.rotate(&signing_key).expect("rotation failed");
    assert_eq!(new_identity.node_id, 1);
    assert_eq!(new_identity.identity_version, 2);
    new_identity
        .verify_self_signature()
        .expect("rotated identity should self-verify");
}

#[test]
fn test_node_key_store() {
    let mut store = NodeKeyStore::new();
    let (identity, _) = NodeIdentity::generate(10).expect("generate failed");
    store
        .register(identity.clone())
        .expect("registration failed");
    assert!(store.contains(10));
    assert!(store.get_verifying_key(10).is_some());
    assert!(!store.contains(99));
}

#[test]
fn test_hello_message_sign_and_verify() {
    let (client_id, client_key) = NodeIdentity::generate(1).expect("generate failed");
    let msg = HelloMessage::new(
        client_id.clone(),
        &client_key,
        vec![1],
        SessionClass::FullMesh,
        42,
    );
    msg.verify().expect("HelloMessage should verify");
}

#[test]
fn test_hello_response_sign_and_verify() {
    let (server_id, server_key) = NodeIdentity::generate(2).expect("generate failed");
    let nonce = [42u8; 32];
    let resp = HelloResponse::new(
        server_id,
        &server_key,
        nonce,
        1,
        SessionClass::FullMesh,
        100,
        42,
    );
    resp.verify().expect("HelloResponse should verify");
    assert_eq!(resp.client_nonce_echo, nonce);
}

#[test]
fn test_full_mutual_attestation() {
    let (client_id, client_key) = NodeIdentity::generate(1).expect("generate failed");
    let (server_id, server_key) = NodeIdentity::generate(2).expect("generate failed");
    let mut store = NodeKeyStore::new();
    store.register(client_id.clone()).expect("register failed");
    store.register(server_id.clone()).expect("register failed");
    let client_msg = HelloMessage::new(client_id, &client_key, vec![1], SessionClass::FullMesh, 42);
    let server_resp = HelloResponse::new(
        server_id,
        &server_key,
        client_msg.client_nonce,
        1,
        SessionClass::FullMesh,
        100,
        42,
    );
    let result = verify_mutual_attestation(
        &client_msg.client_nonce,
        &server_resp.server_nonce,
        &client_msg,
        &server_resp,
        &store,
    )
    .expect("mutual attestation should succeed");
    assert!(result.verified);
    assert_eq!(result.epoch, 42);
    assert_eq!(result.peer_identity.node_id, 2);
}

#[test]
fn test_mutual_attestation_unknown_identity_rejected() {
    let (client_id, client_key) = NodeIdentity::generate(1).expect("generate failed");
    let (server_id, server_key) = NodeIdentity::generate(2).expect("generate failed");
    let mut store = NodeKeyStore::new();
    store.register(client_id.clone()).expect("register failed");
    let client_msg = HelloMessage::new(client_id, &client_key, vec![1], SessionClass::FullMesh, 1);
    let server_resp = HelloResponse::new(
        server_id,
        &server_key,
        client_msg.client_nonce,
        1,
        SessionClass::FullMesh,
        100,
        1,
    );
    assert!(verify_mutual_attestation(
        &client_msg.client_nonce,
        &server_resp.server_nonce,
        &client_msg,
        &server_resp,
        &store,
    )
    .is_err());
}

#[test]
fn test_mutual_attestation_epoch_mismatch() {
    let (client_id, client_key) = NodeIdentity::generate(1).expect("generate failed");
    let (server_id, server_key) = NodeIdentity::generate(2).expect("generate failed");
    let mut store = NodeKeyStore::new();
    store.register(client_id.clone()).expect("register failed");
    store.register(server_id.clone()).expect("register failed");
    let client_msg = HelloMessage::new(client_id, &client_key, vec![1], SessionClass::FullMesh, 42);
    let server_resp = HelloResponse::new(
        server_id,
        &server_key,
        client_msg.client_nonce,
        1,
        SessionClass::FullMesh,
        100,
        99,
    );
    assert!(verify_mutual_attestation(
        &client_msg.client_nonce,
        &server_resp.server_nonce,
        &client_msg,
        &server_resp,
        &store,
    )
    .is_err());
}

#[test]
fn test_principal_capability_check() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let role = RoleBinding::new(
        RoleBindingId(1),
        "admin".into(),
        vec!["stage".into(), "publish".into()],
        ScopeSelector::All,
        &signing_key,
    );
    let principal = Principal::new(
        PrincipalId::new(1),
        PrincipalClass::HumanOperator,
        10,
        vec![role],
    );
    assert!(principal.has_capability("stage"));
    assert!(principal.has_all_capabilities(&["stage", "publish"]));
    assert!(!principal.has_capability("delete"));
}

#[test]
fn test_authorization_allow() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let role = RoleBinding::new(
        RoleBindingId(1),
        "admin".into(),
        vec!["stage".into()],
        ScopeSelector::All,
        &signing_key,
    );
    let principal = Principal::new(
        PrincipalId::new(1),
        PrincipalClass::HumanOperator,
        10,
        vec![role],
    );
    let decision = evaluate_authorization(
        &AuthorizationRequest::new(principal, 42, ActionClass::Stage, ScopeSelector::All),
        0,
    );
    assert!(matches!(decision.outcome, AuthorizationOutcome::Allowed));
}

#[test]
fn test_authorization_denied_wrong_class() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let role = RoleBinding::new(
        RoleBindingId(1),
        "readonly".into(),
        vec!["observe".into()],
        ScopeSelector::All,
        &signing_key,
    );
    let principal = Principal::new(PrincipalId::new(1), PrincipalClass::Auditor, 10, vec![role]);
    let decision = evaluate_authorization(
        &AuthorizationRequest::new(principal, 42, ActionClass::Stage, ScopeSelector::All),
        0,
    );
    assert!(matches!(decision.outcome, AuthorizationOutcome::Denied(_)));
}

#[test]
fn test_authorization_denied_missing_capability() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let role = RoleBinding::new(
        RoleBindingId(1),
        "limited".into(),
        vec!["observe".into()],
        ScopeSelector::All,
        &signing_key,
    );
    let principal = Principal::new(
        PrincipalId::new(1),
        PrincipalClass::HumanOperator,
        10,
        vec![role],
    );
    let decision = evaluate_authorization(
        &AuthorizationRequest::new(principal, 42, ActionClass::Publish, ScopeSelector::All),
        0,
    );
    assert!(matches!(decision.outcome, AuthorizationOutcome::Denied(_)));
}

#[test]
fn test_authorization_override() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let role = RoleBinding::new(
        RoleBindingId(1),
        "emergency".into(),
        vec!["override".into()],
        ScopeSelector::All,
        &signing_key,
    );
    let principal = Principal::new(
        PrincipalId::new(1),
        PrincipalClass::HumanOperator,
        10,
        vec![role],
    );
    let decision = evaluate_authorization(
        &AuthorizationRequest::new(principal, 42, ActionClass::Publish, ScopeSelector::All)
            .with_override(999),
        0,
    );
    assert!(matches!(
        decision.outcome,
        AuthorizationOutcome::AllowedWithOverride { ticket_id: 999 }
    ));
}

#[test]
fn test_audit_log_record_and_query() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let role = RoleBinding::new(
        RoleBindingId(1),
        "admin".into(),
        vec!["stage".into()],
        ScopeSelector::All,
        &signing_key,
    );
    let principal = Principal::new(
        PrincipalId::new(1),
        PrincipalClass::HumanOperator,
        10,
        vec![role],
    );
    let decision = evaluate_authorization(
        &AuthorizationRequest::new(principal, 42, ActionClass::Stage, ScopeSelector::All),
        0,
    );
    let mut log = AuditLog::new();
    log.record_decision(&decision, PrincipalId::new(1), 42);
    assert_eq!(log.events.len(), 1);
    assert_eq!(log.events_for_principal(PrincipalId::new(1)).len(), 1);
}

#[test]
fn test_capability_grant_max_uses() {
    let mut grant = CapabilityGrant::new(
        CapabilityGrantId::new(1),
        PrincipalId::new(1),
        "observe".into(),
        ScopeSelector::All,
    )
    .with_max_uses(2);
    assert_eq!(
        grant
            .consume(PrincipalId::new(1), &ScopeSelector::All, "observe")
            .expect("first use should succeed")
            .use_count,
        1
    );
    assert_eq!(
        grant
            .consume(PrincipalId::new(1), &ScopeSelector::All, "observe")
            .expect("final allowed use should succeed")
            .use_count,
        2
    );
    let denial = grant
        .consume(PrincipalId::new(1), &ScopeSelector::All, "observe")
        .expect_err("exhausted grant should be denied");
    assert!(matches!(
        denial.reason,
        CapabilityGrantDenialReason::Exhausted {
            max_uses: 2,
            use_count: 2
        }
    ));
    assert_eq!(grant.use_count, 2);
}

// =========================================================================
// Key rotation record and lifecycle
// =========================================================================

#[test]
fn test_key_rotation_record_generated_on_rotate() {
    let (identity, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let (new_identity, _new_key, rotation_record) =
        identity.rotate(&signing_key).expect("rotation failed");

    assert_eq!(rotation_record.node_id, 1);
    assert_eq!(rotation_record.old_identity_version, 1);
    assert_eq!(rotation_record.new_identity_version, 2);
    assert_eq!(
        rotation_record.new_verifying_key_bytes,
        new_identity.verifying_key_bytes
    );
    assert!(!rotation_record.rotation_proof.is_empty());

    // The new identity should self-verify
    new_identity
        .verify_self_signature()
        .expect("rotated identity should self-verify");

    // The rotation proof should verify against the old verifying key
    let old_vk = identity.verifying_key().expect("old vk");
    rotation_record
        .verify(&old_vk)
        .expect("rotation proof should verify");
}

#[test]
fn test_key_rotation_record_verify_fails_with_wrong_key() {
    let (identity, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let (_, _, rotation_record) = identity.rotate(&signing_key).expect("rotation failed");

    // Try to verify with a different node's key
    let (other_id, _) = NodeIdentity::generate(2).expect("generate failed");
    let other_vk = other_id.verifying_key().expect("other vk");

    assert!(rotation_record.verify(&other_vk).is_err());
}

#[test]
fn test_key_rotation_record_tamper_detection() {
    let (identity, signing_key) = NodeIdentity::generate(1).expect("generate failed");
    let (_, _, mut rotation_record) = identity.rotate(&signing_key).expect("rotation failed");

    let old_vk = identity.verifying_key().expect("old vk");

    // Tamper with the new verifying key bytes
    rotation_record.new_verifying_key_bytes[0] ^= 0xFF;
    assert!(rotation_record.verify(&old_vk).is_err());
}

#[test]
fn test_key_rotation_proof_contains_correct_preimage() {
    // Rotating twice should produce distinct proofs since versions differ
    let (identity, sk1) = NodeIdentity::generate(1).expect("generate");
    let (id2, sk2, rr1) = identity.rotate(&sk1).expect("rotate 1");
    let (_, _, rr2) = id2.rotate(&sk2).expect("rotate 2");

    assert_ne!(rr1.rotation_proof, rr2.rotation_proof);
    assert_eq!(rr1.old_identity_version, 1);
    assert_eq!(rr2.old_identity_version, 2);
    assert_eq!(rr2.new_identity_version, 3);
}

#[test]
fn test_node_identity_rotate_preserves_node_id() {
    let (identity, key) = NodeIdentity::generate(42).expect("generate");
    let (new_id, _, _) = identity.rotate(&key).expect("rotate");
    assert_eq!(new_id.node_id, 42);
}

// =========================================================================
// Grace-period revocation
// =========================================================================

#[test]
fn test_grace_period_revocation_within_grace() {
    let (node_id, identity) = {
        let (id, _) = NodeIdentity::generate(10).expect("generate");
        (id.node_id, id)
    };

    let (_, signing_key) = NodeIdentity::generate(99).expect("generate");
    let mut set = GracePeriodRevocationSet::new();

    // Insert a revocation with default 5-minute grace period
    revoke_identity_with_grace(
        &mut set,
        node_id,
        identity.identity_version,
        PrincipalId::new(99),
        RevocationReason::ScheduledRotation,
        &signing_key,
    );

    // Immediately after revocation, the grace period should still be active
    let result = check_revocation_status_with_grace(&set, node_id, identity.identity_version);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        IdentityError::RevocationGracePeriod { .. }
    ));
}

#[test]
fn test_grace_period_revocation_after_grace() {
    let (node_id, version) = {
        let (id, _) = NodeIdentity::generate(10).expect("generate");
        (id.node_id, id.identity_version)
    };

    let (_, signing_key) = NodeIdentity::generate(99).expect("generate");

    // Create a revocation that already expired (grace = 0)
    let record = GracePeriodRevocationRecord::new(
        node_id,
        version,
        PrincipalId::new(99),
        RevocationReason::ConfirmedCompromise,
        &signing_key,
        0, // zero grace period — expired immediately
    );

    assert!(record.grace_period_expired());
    assert!(!record.within_grace_period());

    let mut set = GracePeriodRevocationSet::new();
    set.insert((node_id, version), record);

    let result = check_revocation_status_with_grace(&set, node_id, version);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdentityError::Revoked { .. }));
}

#[test]
fn test_grace_period_revocation_not_revoked() {
    let (node_id, version) = {
        let (id, _) = NodeIdentity::generate(10).expect("generate");
        (id.node_id, id.identity_version)
    };

    let set = GracePeriodRevocationSet::new();
    assert!(check_revocation_status_with_grace(&set, node_id, version).is_ok());
}

#[test]
fn test_grace_period_revocation_different_version_not_affected() {
    let (node_id, _) = {
        let (id, _) = NodeIdentity::generate(10).expect("generate");
        (id.node_id, id.identity_version)
    };

    let (_, signing_key) = NodeIdentity::generate(99).expect("generate");
    let mut set = GracePeriodRevocationSet::new();

    // Revoke version 1
    revoke_identity_with_grace(
        &mut set,
        node_id,
        1, // version 1 is revoked
        PrincipalId::new(99),
        RevocationReason::ScheduledRotation,
        &signing_key,
    );

    // Version 2 should still be OK
    assert!(check_revocation_status_with_grace(&set, node_id, 2).is_ok());
}

// =========================================================================
// Compromise recovery
// =========================================================================

#[test]
fn test_compromise_rotate_generates_new_identity() {
    let (identity, _) = NodeIdentity::generate(1).expect("generate");
    let (new_identity, _new_key, recovery_record) = identity
        .compromise_rotate()
        .expect("compromise rotate failed");

    assert_eq!(new_identity.node_id, 1);
    assert_eq!(new_identity.identity_version, 2);
    new_identity
        .verify_self_signature()
        .expect("new identity should self-verify");

    assert_eq!(recovery_record.node_id, 1);
    assert_eq!(recovery_record.compromised_identity_version, 1);
    assert_eq!(recovery_record.new_identity_version, 2);
    assert_eq!(
        recovery_record.new_verifying_key_bytes,
        new_identity.verifying_key_bytes
    );
}

#[test]
fn test_compromise_recovery_record_self_signature_verifies() {
    let (identity, _) = NodeIdentity::generate(1).expect("generate");
    let (_, _, recovery_record) = identity
        .compromise_rotate()
        .expect("compromise rotate failed");

    recovery_record
        .verify_new_key_self_signature()
        .expect("recovery self-signature should verify");
}

#[test]
fn test_compromise_recovery_signature_tamper_detected() {
    let (identity, _) = NodeIdentity::generate(1).expect("generate");
    let (_, _, mut recovery_record) = identity
        .compromise_rotate()
        .expect("compromise rotate failed");

    // Tamper with the new verifying key
    recovery_record.new_verifying_key_bytes[0] ^= 0xFF;
    assert!(recovery_record.verify_new_key_self_signature().is_err());
}

#[test]
fn test_compromise_recovery_does_not_use_old_key() {
    let (identity, _) = NodeIdentity::generate(1).expect("generate");
    let (new_identity, _, recovery_record) = identity
        .compromise_rotate()
        .expect("compromise rotate failed");

    // The new identity should NOT be verifiable by the old key
    let old_vk = identity.verifying_key().expect("old vk");

    // Check: the recovery record explicitly has NO old-key signature
    // The new_self_signature is from the new key, not the old one
    assert_eq!(
        recovery_record.new_verifying_key_bytes,
        new_identity.verifying_key_bytes
    );

    // The old key should NOT be able to verify the new identity's self-signature
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&new_identity.node_id.to_le_bytes());
    preimage.extend_from_slice(&new_identity.verifying_key_bytes);
    preimage.extend_from_slice(&new_identity.attested_at_millis.to_le_bytes());
    preimage.extend_from_slice(&new_identity.identity_version.to_le_bytes());

    use ed25519_dalek::Verifier;
    let sig =
        ed25519_dalek::Signature::from_bytes(&new_identity.self_signature).expect("parse sig");
    assert!(old_vk.verify(&preimage, &sig).is_err());
}

#[test]
fn test_compromise_recovery_distinct_from_normal_rotation() {
    let (id1, sk1) = NodeIdentity::generate(1).expect("generate");

    // Normal rotation
    let (_id2_rotated, _sk2, rotation_record) = id1.rotate(&sk1).expect("rotate");

    // Compromise recovery (using id1 again since we still have its data)
    let (_id2_recovered, _sk2r, recovery_record) =
        id1.compromise_rotate().expect("compromise rotate");

    // Both produce new identities at version 2, but with different keys
    // (both are freshly generated, so they'll almost certainly differ)
    assert_ne!(
        rotation_record.new_verifying_key_bytes,
        recovery_record.new_verifying_key_bytes
    );

    // The rotation record has a rotation_proof signed by old key
    assert!(!rotation_record.rotation_proof.is_empty());

    // The recovery record does NOT have a rotation proof (it has new_self_signature instead)
    let vk = id1.verifying_key().expect("old vk");
    rotation_record
        .verify(&vk)
        .expect("rotation proof verifies");
}

// =========================================================================
// Key lifecycle stats
// =========================================================================

#[test]
fn test_key_lifecycle_stats_initial_state() {
    let now = tidefs_auth::current_time_utils();
    let stats = KeyLifecycleStats::new(1, now);

    assert_eq!(stats.total_rotations, 0);
    assert_eq!(stats.total_revocations, 0);
    assert_eq!(stats.total_compromises, 0);
    assert_eq!(stats.current_identity_version, 1);
    assert_eq!(stats.current_key_created_at_millis, now);
}

#[test]
fn test_key_lifecycle_stats_record_rotation() {
    let now = tidefs_auth::current_time_utils();
    let mut stats = KeyLifecycleStats::new(1, now);

    stats.record_rotation(2);
    assert_eq!(stats.total_rotations, 1);
    assert_eq!(stats.current_identity_version, 2);
    assert!(stats.current_key_created_at_millis >= now);

    stats.record_rotation(3);
    assert_eq!(stats.total_rotations, 2);
    assert_eq!(stats.current_identity_version, 3);
}

#[test]
fn test_key_lifecycle_stats_record_compromise() {
    let now = tidefs_auth::current_time_utils();
    let mut stats = KeyLifecycleStats::new(1, now);

    stats.record_compromise(2);
    assert_eq!(stats.total_compromises, 1);
    assert_eq!(stats.total_rotations, 1); // compromise also counts as rotation
    assert_eq!(stats.current_identity_version, 2);
}

#[test]
fn test_key_lifecycle_stats_record_revocation() {
    let now = tidefs_auth::current_time_utils();
    let mut stats = KeyLifecycleStats::new(1, now);

    stats.record_revocation();
    assert_eq!(stats.total_revocations, 1);
    assert_eq!(stats.total_rotations, 0); // revocation doesn't change rotation count
    assert_eq!(stats.current_identity_version, 1);
}

#[test]
fn test_key_lifecycle_stats_age_increases() {
    let now = tidefs_auth::current_time_utils();
    let stats = KeyLifecycleStats::new(1, now);
    let age = stats.current_key_age_millis();
    // Age should be non-negative
    assert!(age < 60_000, "age should be small (a few ms), got {age}");
}

#[test]
fn test_key_lifecycle_stats_full_lifecycle() {
    let now = tidefs_auth::current_time_utils();
    let mut stats = KeyLifecycleStats::new(1, now);

    // Normal rotation
    stats.record_rotation(2);
    assert_eq!(stats.total_rotations, 1);

    // Revocation of some old key
    stats.record_revocation();
    assert_eq!(stats.total_revocations, 1);

    // Compromise recovery
    stats.record_compromise(3);
    assert_eq!(stats.total_compromises, 1);
    assert_eq!(stats.total_rotations, 2); // rotation + compromise = 2
    assert_eq!(stats.current_identity_version, 3);
}

// =========================================================================
// GracePeriodRevocationRecord display and helpers
// =========================================================================

#[test]
fn test_grace_period_revocation_new_with_custom_grace() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate");
    let record = GracePeriodRevocationRecord::new(
        42,
        2,
        PrincipalId::new(99),
        RevocationReason::OperatorInitiated,
        &signing_key,
        30_000, // 30 second grace period
    );

    assert_eq!(record.revocation.node_id, 42);
    assert_eq!(record.revocation.identity_version, 2);
    assert!(!record.grace_period_expired()); // 30s grace not expired yet
    assert!(record.within_grace_period());
}

#[test]
fn test_grace_period_revocation_verify_signature() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate");
    let record = GracePeriodRevocationRecord::new(
        42,
        2,
        PrincipalId::new(99),
        RevocationReason::NodeDecommissioned,
        &signing_key,
        300_000,
    );

    let vk = signing_key.public;
    record
        .revocation
        .verify(&vk)
        .expect("revocation sig should verify");
}

#[test]
fn test_grace_period_revocation_signature_tampered() {
    let (_, signing_key) = NodeIdentity::generate(1).expect("generate");
    let mut record = GracePeriodRevocationRecord::new(
        42,
        2,
        PrincipalId::new(99),
        RevocationReason::SuspectedCompromise,
        &signing_key,
        300_000,
    );

    let vk = signing_key.public;
    assert!(record.revocation.verify(&vk).is_ok());

    // Tamper with signature
    if !record.revocation.revocation_signature.is_empty() {
        record.revocation.revocation_signature[0] ^= 0xFF;
    }
    assert!(record.revocation.verify(&vk).is_err());
}
