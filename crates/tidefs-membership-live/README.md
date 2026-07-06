# tidefs-membership-live

`tidefs-membership-live` contains source-owned runtime helpers that connect the
deterministic membership model to live process and transport plumbing.

This crate is product code, but this README is not a product-admission proof,
roadmap, release note, or distributed-availability claim. Product wording,
successor/comparator wording, and distributed product-mode admission remain
governed by the repository claim registry, membership authority docs, current
source, validation evidence, and live GitHub issues.

## Authority Boundary

- `docs/MEMBERSHIP_AUTHORITY.md` names `tidefs-membership-epoch` as the single
  membership authority owner and describes how the live runtime fits at the
  membership/transport boundary.
- `validation/claims.toml` and the generated claim registry own claim status,
  blockers, and evidence requirements.
- `docs/workspace-package-classification.md` classifies this crate as current
  product code, so README prose must stay narrower than source and claim
  evidence.
- Source modules and tests are the durable API and behavior reference for this
  crate. Git history keeps removed historical lineage.

## Current Shape

Use this crate when working on live membership plumbing around:

- `runtime`: `MembershipRuntime`, transition observations, and tick results.
- `types`: membership wire and runtime data types shared across modules.
- `transport_wiring`, `transport_bridge`, and `transport_session_manager`:
  adapters between membership messages and transport sessions.
- `membership_inbound_dispatch`, `membership_outbound_dispatch`, and
  `dispatch_router`: typed routing for inbound and outbound membership
  messages.
- `failure_detector`, `indirect_ping`, `heartbeat`, `liveness`,
  `peer_unreachable`, `peer_health`, and `peer_health_scorer`: peer observation
  and liveness helper state.
- `gossip`, `gossip_batcher`, and `roster_gossip`: roster and peer-state
  dissemination helpers.
- `epoch_transition`, `epoch_state_machine`, `epoch_coordinator`,
  `epoch_catch_up`, `epoch_push`, `epoch_fence`, `proposal_commit`,
  `membership_vote_handler`, and `commit_coordinator_bridge`: live wiring
  around membership epoch transitions.
- `roster`, `session_binding`, `roster_session_bridge`, `roster_sync`,
  `roster_notify`, and `roster_leave_notify`: roster state and session-facing
  membership bindings.
- `join_request`, `join_response`, `join_handler`, `join_initiator`,
  `peer_join`, `peer_add_connector`, `departure_initiator`, `drain`, and
  `drain_verifier`: join, leave, and drain coordination helpers.
- `coordinator_lease`, `cluster_lease_wiring`, and `lease_messages`:
  coordinator lease message construction and wiring.
- `event_bridge`, `deterministic_transport`, `deterministic_replay`,
  `transport_event_recorder`, and `harness`: event publication and deterministic
  testing support.
- `checkpoint_persistence`, `backend_disclosure`, `capability_view`,
  `connection_acceptance`, `connection_establishment`, `connection_teardown`,
  `peer_eviction`, `reconnect_handshake`, `seed_discovery`,
  `suspicion_accumulator`, `incarnation_validator`, `journal_sync_trigger`, and
  `send_gate`: focused runtime integration helpers.

Prefer the module docs, public types re-exported from `src/lib.rs`, and nearby
tests for API details. Keep this README as navigation, not as a protocol spec.

## Contributor Guidance

- Before changing distributed membership behavior, read
  `docs/MEMBERSHIP_AUTHORITY.md`, `docs/CLAIMS_GATE_POLICY.md`,
  `validation/claims.toml`, and the live issue or PR that owns the behavior.
- Keep runtime behavior changes out of README-only work. If a source scan finds
  a missing runtime path, retarget it to the existing owning issue or propose a
  focused follow-up with a disjoint write set.
- Do not add product-readiness, release-readiness, RDMA-readiness,
  OpenZFS/Ceph-class, production-availability, or broad failure-detection
  claims here. Those claims require the repository claim gate and current
  evidence.
- Avoid historical issue-number lineage in this README. Closed issue and PR
  history belongs in GitHub and git history unless a current authority document
  explicitly needs it.
- Keep examples and guidance tied to current source names. When a module
  changes, update this file only if contributors would lose useful navigation.
