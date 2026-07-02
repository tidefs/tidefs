// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use tidefs_auth::*;

fn keypair() -> Keypair {
    let mut rng = OsRng;
    Keypair::generate(&mut rng)
}

fn action() -> RemotePrivilegedAction {
    RemotePrivilegedAction::new("pool destroy", ActionClass::Publish, ScopeSelector::All)
}

fn operator_with_capabilities(capabilities: &[&str]) -> Principal {
    let signing_key = keypair();
    let role = RoleBinding::new(
        RoleBindingId(1),
        "operator".into(),
        capabilities
            .iter()
            .map(|capability| (*capability).into())
            .collect(),
        ScopeSelector::All,
        &signing_key,
    );
    Principal::new(
        PrincipalId::new(7),
        PrincipalClass::HumanOperator,
        11,
        vec![role],
    )
}

fn available_context(principal: Principal) -> RemotePrivilegedAuthorizationContext {
    RemotePrivilegedAuthorizationContext::available(principal, 44, 99)
}

#[test]
fn remote_privileged_action_allows_and_seals_audited_decision() {
    let sealing_key = keypair();
    let mut audit_log = AuditLog::new();
    let context = available_context(operator_with_capabilities(&["publish"]));

    let evidence =
        authorize_remote_privileged_action(action(), context, &mut audit_log, &sealing_key, 1)
            .expect("remote privileged authorization");

    assert!(evidence.is_allowed());
    assert_eq!(evidence.command, "pool destroy");
    assert_eq!(evidence.audit_event_id, AuditEventId::new(1));
    assert!(evidence.chain_anchor.is_some());
    assert_eq!(audit_log.events.len(), 1);
    assert_eq!(
        audit_log.events[0].event_kind,
        AuditEventKind::AccessGranted
    );
    audit_log.verify_chain_integrity().expect("sealed chain");
}

#[test]
fn remote_privileged_action_denials_are_audited() {
    let cases = vec![
        (
            "missing identity",
            RemotePrivilegedAuthorizationContext {
                principal: None,
                session_id: Some(44),
                policy_state: RemotePrivilegedPolicyState::Current,
                cluster_owner_state: ClusterOwnerAuthorizationState::Available {
                    decider_node_id: 99,
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::MissingIdentity,
        ),
        (
            "missing session",
            RemotePrivilegedAuthorizationContext {
                principal: Some(operator_with_capabilities(&["publish"])),
                session_id: None,
                policy_state: RemotePrivilegedPolicyState::Current,
                cluster_owner_state: ClusterOwnerAuthorizationState::Available {
                    decider_node_id: 99,
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::MissingSession,
        ),
        (
            "zero session",
            RemotePrivilegedAuthorizationContext {
                principal: Some(operator_with_capabilities(&["publish"])),
                session_id: Some(0),
                policy_state: RemotePrivilegedPolicyState::Current,
                cluster_owner_state: ClusterOwnerAuthorizationState::Available {
                    decider_node_id: 99,
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::MissingSession,
        ),
        (
            "missing capability",
            available_context(operator_with_capabilities(&["observe"])),
            RemotePrivilegedRefusalReason::MissingCapability {
                capability: "publish".into(),
            },
        ),
        (
            "missing policy",
            RemotePrivilegedAuthorizationContext {
                principal: Some(operator_with_capabilities(&["publish"])),
                session_id: Some(44),
                policy_state: RemotePrivilegedPolicyState::Missing,
                cluster_owner_state: ClusterOwnerAuthorizationState::Available {
                    decider_node_id: 99,
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::MissingPolicy,
        ),
        (
            "stale policy",
            RemotePrivilegedAuthorizationContext {
                principal: Some(operator_with_capabilities(&["publish"])),
                session_id: Some(44),
                policy_state: RemotePrivilegedPolicyState::Stale {
                    reason: "policy epoch 8 is older than owner epoch 9".into(),
                },
                cluster_owner_state: ClusterOwnerAuthorizationState::Available {
                    decider_node_id: 99,
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::StalePolicy {
                reason: "policy epoch 8 is older than owner epoch 9".into(),
            },
        ),
        (
            "invalid policy",
            RemotePrivilegedAuthorizationContext {
                principal: Some(operator_with_capabilities(&["publish"])),
                session_id: Some(44),
                policy_state: RemotePrivilegedPolicyState::Invalid {
                    reason: "policy signature failed".into(),
                },
                cluster_owner_state: ClusterOwnerAuthorizationState::Available {
                    decider_node_id: 99,
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::InvalidPolicy {
                reason: "policy signature failed".into(),
            },
        ),
        (
            "owner unavailable",
            RemotePrivilegedAuthorizationContext {
                principal: Some(operator_with_capabilities(&["publish"])),
                session_id: Some(44),
                policy_state: RemotePrivilegedPolicyState::Current,
                cluster_owner_state: ClusterOwnerAuthorizationState::Unavailable {
                    reason: "no reachable owner endpoint".into(),
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::ClusterOwnerUnavailable {
                reason: "no reachable owner endpoint".into(),
            },
        ),
        (
            "owner refused",
            RemotePrivilegedAuthorizationContext {
                principal: Some(operator_with_capabilities(&["publish"])),
                session_id: Some(44),
                policy_state: RemotePrivilegedPolicyState::Current,
                cluster_owner_state: ClusterOwnerAuthorizationState::Refused {
                    reason: "owner fencing in progress".into(),
                },
                override_ticket_id: None,
                valid_override_ticket_ids: Vec::new(),
            },
            RemotePrivilegedRefusalReason::ClusterOwnerRefused {
                reason: "owner fencing in progress".into(),
            },
        ),
    ];

    for (case, context, expected_refusal) in cases {
        let sealing_key = keypair();
        let mut audit_log = AuditLog::new();
        let evidence =
            authorize_remote_privileged_action(action(), context, &mut audit_log, &sealing_key, 32)
                .unwrap_or_else(|err| panic!("{case}: authorization failed: {err}"));

        assert_eq!(
            evidence.refusal,
            Some(expected_refusal.clone()),
            "{case}: refusal"
        );
        assert!(!evidence.is_allowed(), "{case}: allowed unexpectedly");
        assert_eq!(evidence.audit_event_id, AuditEventId::new(1), "{case}");
        assert_eq!(audit_log.events.len(), 1, "{case}");
        assert!(
            matches!(
                &audit_log.events[0].event_kind,
                AuditEventKind::AccessDenied { reason }
                    if reason == &expected_refusal.to_string()
            ),
            "{case}: audit event did not preserve refusal"
        );
        assert!(audit_log.unsealed_event_count() == 1, "{case}");
    }
}
