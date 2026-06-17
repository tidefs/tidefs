# Policy Authority runtime surface (POLICY_AUTHORITY pre-preview continuity)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This is the active human-named authority document.


This document is the source-of-truth for the production-depth `policy_authority` runtime
trait and service surface.

The active production reading is now requirement-aligned: steady-state production
`policy_authority` residency is kernel-hosted, while any userspace `policy_authority` daemon remains a

It answers the question:

**How does tidefs run one lawful `policy_authority` authority surface - with one authority
host family, one ingress grammar, one domain-shard law, one trait split, one
publication bridge, and one refusal/stop language - without letting `control_plane`,
`posix_filesystem_adapter`, `explanation_query`, `block_volume_adapter`, cluster peers, shadow pilots, or helper tools become
hidden policy/budget/product authority?**

See also:
- `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`
- `docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`
- `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`
- `docs/SHADOW_PILOT_RUNTIME_HOOKS_DIVERGENCE_SINKS_P3-04.md`
- `docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md`
- `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`
- `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`
- `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`
- `docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md`
- `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now fixes one explicit `governance_surface_0` law for live `policy_authority`
authority surface:

- one production authority-host family:
  - **`service.policy_authority.authority.kernel_resident.k0`**
- one bounded non-production userspace mirror family:
  - **`service.policy_authority.authority.lab_mirror.tidefs-policy-authority-daemon.l0`**
- six stable ingress-surface classes:
  - **`surface.policy_authority.control_plane_local.s0`**
  - **`surface.policy_authority.client_posix_filesystem_adapter.s1`**
  - **`surface.policy_authority.client_explanation_query.s2`**
  - **`surface.policy_authority.client_block_volume_adapter.s3`**
  - **`surface.policy_authority.cluster_runtime.s4`**
  - **`surface.policy_authority.shadow_replay.s5`**
- six stable domain-shard classes:
  - **`shard.policy_authority.policy.d0`**
  - **`shard.policy_authority.override.d1`**
  - **`shard.policy_authority.budget.d2`**
  - **`shard.policy_authority.recipe.d3`**
  - **`shard.policy_authority.product_admission.d4`**
  - **`shard.policy_authority.product_reclaim.d5`**
- eight stable runtime-component classes:
  - **`comp.policy_authority.ingress_bind.c0`**
  - **`comp.policy_authority.request_canon.c1`**
  - **`comp.policy_authority.idempotency.c2`**
  - **`comp.policy_authority.anchor_freeze.c3`**
  - **`comp.policy_authority.domain_router.c4`**
  - **`comp.policy_authority.policy_budget_eval.c5`**
  - **`comp.policy_authority.product_eval.c6`**
  - **`comp.policy_authority.publication_receipt_bridge.c7`**
- ten stable trait families:
  - **`PolicyAuthorityIngressSurface`**
  - **`PolicyAuthorityRequestCanonicalizer`**
  - **`PolicyAuthorityIdempotencyJournal`**
  - **`PolicyAuthorityAnchorFreezer`**
  - **`PolicyAuthorityDomainShardRouter`**
  - **`PolicyAuthorityPolicySnapshotResolver`**
  - **`PolicyAuthorityOverrideLeaseResolver`**
  - **`PolicyAuthorityBudgetDecisionEngine`**
  - **`PolicyAuthorityProductDecisionEngine`**
  - **`PolicyAuthorityPublicationReceiptBridge`**
- eight stable stage classes:
  - **`stage.policy_authority.ingress_bind.h0`**
  - **`stage.policy_authority.canonicalize_request.h1`**
  - **`stage.policy_authority.freeze_anchor_set.h2`**
  - **`stage.policy_authority.bind_domain_shard.h3`**
  - **`stage.policy_authority.resolve_policy_override_budget.h4`**
  - **`stage.policy_authority.evaluate_product_decision.h5`**
  - **`stage.policy_authority.issue_successor_or_answer_plan.h6`**
  - **`stage.policy_authority.bridge_publication_pipeline_schema_codec_response_registry.h7`**
- seven stable refusal / stop classes:
  - **`refusal.policy_authority.authz_or_session.r0`**
  - **`refusal.policy_authority.anchor_stale.r1`**
  - **`refusal.policy_authority.idempotency_conflict.r2`**
  - **`refusal.policy_authority.policy_or_secret_missing.r3`**
  - **`refusal.policy_authority.override_invalid.r4`**
  - **`refusal.policy_authority.budget_or_product_denied.r5`**
  - **`refusal.policy_authority.stop_or_quarantine.r6`**
- one canonical authority-surface chain:
  - **ingress surface -> canonical request/batch -> idempotency bind -> anchor freeze -> domain-shard bind -> policy/override/budget/product evaluation -> successor or answer plan -> `publication_pipeline` / `schema_codec` / `response_registry` bridge**

This means tidefs is no longer allowed to say only:
- "`policy_authority` is some future Rust service,"
- "the exact trait surface can wait until code exists,"
- "`control_plane`, `posix_filesystem_adapter`, and `explanation_query` can each grow the adapter they need,"
- "cluster/failover traffic can use a separate internal path for now,"
- or "production can just keep the userspace mirror if it works well enough."

It must instead say:
- which production family owns live authority evaluation,
- which userspace mirror is explicitly non-production,
- which ingress surfaces may reach authoritative truth,
- which domain shards exist and how request capsules bind to them,
- which runtime components own canonicalization, anchor freeze, evaluation, and
  bridge work,
- which trait families are legal and which truth scopes they may not own,
- and how every mutating or read-like `policy_authority` request reaches `publication_pipeline`, `schema_codec`, and
  `response_registry` without surface-local reinterpretation.

The anti-regression rule is explicit:

**No `tidefsctl` command, `control_plane` helper route, `posix_filesystem_adapter` request worker,
`explanation_query` query path, future `block_volume_adapter` gate, cluster peer helper, shadow compare tool,
or package-local sidecar may decide policy, override, budget, recipe,
admission, or reclaim truth except by entering the declared `governance_surface_0` authority
surface. Any surviving `tidefs-policy-authority-daemon` mirror is non-production by declaration
and may not silently become the steady-state production host.**

## 2. Scope and boundaries

This document governs:

- the one lawful kernel-resident production `policy_authority` authority family,
- the one bounded non-production userspace mirror family,
- the ingress surfaces that may submit canonical `policy_authority` work,
- the domain-shard law for policy, override, budget, recipe, admission, and
  reclaim decisions,
- the runtime-component and trait-family split inside the production host and the bounded mirror,
- request-capsule admission, idempotency, anchor freeze, and evaluation-plan
  shaping,
- the service-local budget, stop, and quarantine grammar,
- and the only legal bridge from `policy_authority` work into `publication_pipeline` publication, `schema_codec`
  receipt emission, and `response_registry` visible-answer rendering.

This document now consumes the explicit `control_plane` route/carrier law in
`docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`, the explicit `publication_pipeline`
publication-runtime law in
`docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`, the explicit `response_registry`
receipt/response law in `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`,
the explicit `shadow_pilot_0` shadow-hook law in
`docs/SHADOW_PILOT_RUNTIME_HOOKS_DIVERGENCE_SINKS_P3-04.md`, the explicit
`identity_access_audit_0` principal/session/grant/override/audit law in
`docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md`, the explicit `secret_key_policy_0`
secret/policy-storage law in
`docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`, the explicit `transport_session_0`
transport/session/cohort graph in `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`,
the explicit `membership_placement_0` membership/placement/failure-domain law in
`docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`, the explicit `memory_arena_0`
memory-domain / arena / ownership-token law in
`docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md`, the
explicit `package_profile_catalog` build / packaging / activation law in
`docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`, and the explicit `posix_filesystem_adapter`
daemon/process topology law in `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`.

That boundary is deliberate.
`P3-01` closes the last open runtime-surface ambiguity inside the `P3`
workstream.
The design rule-family to Rust-type map is now explicit in
`docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`, so Rust ids, owned structs,
borrowed views, builders, collection wrappers, bridge mirrors, and `type_map` row
ids are no longer allowed to drift from the declared design rule families. It
now also consumes the explicit `workspace_layout` workspace-family / crate-service-
boundary law in
`docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`, so crate
roots, service roots, dependency edges, and test/observe boundaries are no
longer allowed to drift from the declared design rule and runtime laws. It now
also consumes the explicit `linux_baseline` Linux 7.0 baseline contract in
`docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`, so admitted
host assumptions, subsystem floors, and explicit non-baseline cuts are no
longer allowed to drift from the declared package/stage bindings. It now also consumes the explicit `product_variant` product-variant matrix in
`docs/PRODUCT_VARIANT_MATRIX_P0-02.md`, so declared bring-up-only,
mixed-client-kernel, and kernel-self-sufficient authority rows
are no longer allowed to drift from the declared host/package/stage bindings.
It now also consumes the explicit `vfs_boundary_mirror` UAPI / FFI / canonical-schema boundary law in `docs/UAPI_FFI_CANONICAL_SCHEMA_BOUNDARY_RULES_P1-03.md`, so boundary mirrors, wire layouts, kernel-visible structs, `repr(C)` call frames, and conversion exactness are no longer allowed to drift from the declared design rule families. It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary. They may **not** invent a
second authority service family, a second request family beyond `W8-01`/`request_queue_0`,
a surface-local policy store, a queue-local publication dialect, or a
render-local refusal dialect outside `governance_surface_0`.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future
prose:

  canonical `PolicyAuthorityRequestRecord`, `PolicyAuthorityRequestBatchRecord`, `PolicyAuthorityRequestReceipt`,
  and `PolicyAuthorityAdapterShimBindingRecord` families.
  downstream client bands that must enter `policy_authority` through canonical request
  capture instead of local sovereignty.
  prove that the repo has a stable human-facing control surface that must later
  become a lawful `control_plane -> policy_authority` path rather than a direct local mutator.
  stable semantic op names instead of scattering literals.
  mutating and leader-only classification instead of adapter-local guesses.
  lease/fence behavior, and persisted restart state strongly enough to prove
  where `policy_authority` cluster-runtime hooks must later bind.
  derived-budget enforcement and proves that budget state cannot remain hidden
  in ad hoc cache code.
  `W8-01..W8-06`, `13` cluster tests, and `1` CLI smoke test.

Production `governance_surface_0` extends those anchors by fixing the live authority-surface
runtime they must eventually share.
The current reference still proves feasibility, but any `tidefs-policy-authority-daemon`-style path now counts only as a bounded userspace mirror rather than the final production residency.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Authority service families | 1 |
| Stable ingress-surface classes | 6 |
| Stable domain-shard classes | 6 |
| Stable runtime-component classes | 8 |
| Stable trait families | 10 |
| Stable stage classes | 8 |
| Stable refusal / stop classes | 7 |
| Required record families | 10 |
| Required algorithms | 10 |

## 5. One authority service family and ingress-surface law

### 5.1 One service family

The production design now fixes exactly one live production authority family:

- **`service.policy_authority.authority.kernel_resident.k0`**

It may scale by shard or instance only under the declared membership/placement
law.
It remains **one** authority family.

The bounded non-production mirror family is:

- **`service.policy_authority.authority.lab_mirror.tidefs-policy-authority-daemon.l0`**

It may not redefine sovereignty.

Tidefs is not allowed to grow:
- one local writer helper for `control_plane`,
- one private product-admission helper for `posix_filesystem_adapter`,
- one query-only truth daemon for `explanation_query`,
- one migration-only cluster agent that bypasses the same request,
  anchor-freeze, and refusal chain,
- or one userspace mirror that silently becomes the production host by packaging convention.

### 5.2 Stable ingress surfaces

| Surface class | Meaning | May be user-facing? | Typical client band |
|---|---|---:|---|
| `surface.policy_authority.control_plane_local.s0` | admitted `control_plane` writer and read-like control routes | yes, through `control_plane` only | `band.client.control_plane.local.b0` |
| `surface.policy_authority.client_posix_filesystem_adapter.s1` | internal `posix_filesystem_adapter` governance/product gate traffic | no | `band.client.posix_filesystem_adapter.internal.b1` |
| `surface.policy_authority.client_explanation_query.s2` | internal `explanation_query` explanation/query traffic | no | `band.client.explanation_query.internal.b2` |
| `surface.policy_authority.client_block_volume_adapter.s3` | future `block_volume_adapter` governance/product gate traffic | no | `band.client.block_volume_adapter.internal.b3` |
| `surface.policy_authority.cluster_runtime.s4` | lease/failover/runbook/membership/runtime traffic | no | `band.client.cluster.runtime.b4` |

### 5.3 Surface invariants

1. `s0.control_plane_local` is the only operator-facing route into live `policy_authority`.
2. `s1`, `s2`, and `s3` are client-band surfaces only.
3. `s4.cluster_runtime` is the only lawful ingress for distributed-runtime
   authority work.
   Cluster helpers may not grow a second write dialect.
   migration work, but it may not turn shadow state into authority without the
   same `publication_pipeline` and `schema_codec` chain.
5. Every ingress surface binds one declared session/grant model, one allowed
   request-capsule subset, one idempotency scope, and one refusal language.

## 6. Runtime-component and trait-family law

### 6.1 Stable runtime-component classes

| Component class | Primary role | May directly issue `publication_pipeline` work? |
|---|---|---:|
| `comp.policy_authority.ingress_bind.c0` | bind surface, session/grant, and admitted client band | no |
| `comp.policy_authority.request_canon.c1` | canonicalize or rehydrate `W8-01` request/batch records | no |
| `comp.policy_authority.idempotency.c2` | bind idempotency key and dedupe/replay scope | no |
| `comp.policy_authority.anchor_freeze.c3` | freeze policy, lease, membership, and budget anchors | no |
| `comp.policy_authority.domain_router.c4` | bind one request capsule to one primary shard | no |
| `comp.policy_authority.policy_budget_eval.c5` | resolve policy, override, secret, and budget inputs | no |
| `comp.policy_authority.product_eval.c6` | evaluate recipe/admission/reclaim plans and typed refusals | no |
| `comp.policy_authority.publication_receipt_bridge.c7` | issue `publication_pipeline` intents, join `schema_codec`, and hand tickets to `response_registry` | yes |

### 6.2 Stable trait families

| Trait family | Owned by component class | Purpose |
|---|---|---|
| `PolicyAuthorityIngressSurface` | `c0` | decode one admitted surface into a canonical service ingress frame |
| `PolicyAuthorityIdempotencyJournal` | `c2` | dedupe or replay one request capsule under one declared scope |
| `PolicyAuthorityAnchorFreezer` | `c3` | freeze required anchor sets before evaluation begins |
| `PolicyAuthorityDomainShardRouter` | `c4` | map one request capsule to one primary `d0..d5` shard |
| `PolicyAuthorityPolicySnapshotResolver` | `c5` | resolve live policy manifests and activation snapshots |
| `PolicyAuthorityOverrideLeaseResolver` | `c5` | resolve override validity, session grants, and runtime leases |
| `PolicyAuthorityBudgetDecisionEngine` | `c5` | resolve budget-domain publish/adjust/quote decisions |
| `PolicyAuthorityProductDecisionEngine` | `c6` | resolve recipe, admission, and reclaim decisions |
| `PolicyAuthorityPublicationReceiptBridge` | `c7` | bridge mutation or read plans into `publication_pipeline`, `schema_codec`, and `response_registry` |

### 6.3 Trait invariants

1. No trait family may mutate authority directly.
   Only `c7` may submit a declared plan to `publication_pipeline`, and `publication_pipeline` alone performs the
   authoritative cut.
2. `c5` and `c6` may produce evaluation plans and typed refusals, but they may
   not emit user-visible truth by themselves.
3. `c1` may not invent new request nouns or surface-local payload variants.
   Canonical request truth still lives in the `W8-01` families.
4. `c3` must freeze anchors before any product or budget decision is admitted.
5. `c7` is the only component allowed to bind all three downstream bridges:
   publication, receipt, and visible-answer rendering.

## 7. Domain-shard and request-capsule law

### 7.1 Stable domain shards

| Shard class | Owned decision families |
|---|---|
| `shard.policy_authority.policy.d0` | policy publish and policy lookup |
| `shard.policy_authority.budget.d2` | budget publish, quote, and adjust |
| `shard.policy_authority.recipe.d3` | product recipe publication |
| `shard.policy_authority.product_admission.d4` | manual or advisory product admission |
| `shard.policy_authority.product_reclaim.d5` | manual or advisory product reclaim |

### 7.2 Stable request-capsule classes

| Capsule class | Canonical request nouns | Primary shard | Mutating? |
|---|---|---|---:|
| `capsule.policy_authority.policy.write.k0` | `req.policy.publish.r0` | `d0` | yes |
| `capsule.policy_authority.policy.read.k1` | `req.policy.lookup.r0` | `d0` | no |
| `capsule.policy_authority.override.write.k2` | `req.override.issue.r0`, `req.override.revoke.r0` | `d1` | yes |
| `capsule.policy_authority.budget.write.k4` | `req.budget_domain.publish.r0`, `req.budget_domain.adjust.r0` | `d2` | yes |
| `capsule.policy_authority.budget.read.k5` | `req.budget_domain.quote.r0` | `d2` | no |
| `capsule.policy_authority.recipe.write.k6` | `req.product_recipe.publish.r0` | `d3` | yes |
| `capsule.policy_authority.product_admission.k7` | `req.product_admission.ask.r0`, `req.product_admission.manual.r0` | `d4` | mixed |
| `capsule.policy_authority.product_reclaim.k8` | `req.product_reclaim.ask.r0`, `req.product_reclaim.manual.r0` | `d5` | mixed |

### 7.3 Capsule invariants

1. Every admitted `policy_authority` request or batch binds exactly one primary capsule class
   and exactly one primary shard.
2. Rare multi-shard intent must use the already-declared `PolicyAuthorityRequestBatchRecord`
   family rather than inventing cross-shard helper code.
3. The first implementation subset `request_queue_0.p0` remains the narrow implementation start.
   This document widens the runtime law, not the first implementation scope.
4. `posix_filesystem_adapter`, `explanation_query`, and future `block_volume_adapter` surfaces may only use the capsule classes
   admitted to their binding record.
5. Read-like capsules still emit canonical `PolicyAuthorityRequestReceipt` linkage and one
   declared `response_registry` answer plan.

## 8. Canonical authority-service stage chain

| Stage class | Meaning |
|---|---|
| `stage.policy_authority.ingress_bind.h0` | bind one admitted ingress surface plus one session/grant and client band |
| `stage.policy_authority.canonicalize_request.h1` | canonicalize or rehydrate one `W8-01` request or request batch |
| `stage.policy_authority.freeze_anchor_set.h2` | freeze policy, membership, lease, budget, and secret anchor refs |
| `stage.policy_authority.bind_domain_shard.h3` | attach one primary shard and serialization key |
| `stage.policy_authority.resolve_policy_override_budget.h4` | resolve policy snapshots, override validity, secret leases, and budget inputs |
| `stage.policy_authority.evaluate_product_decision.h5` | compute recipe/admission/reclaim result or typed refusal |
| `stage.policy_authority.issue_successor_or_answer_plan.h6` | compose mutation-successor plan, read-answer plan, or refusal plan |
| `stage.policy_authority.bridge_publication_pipeline_schema_codec_response_registry.h7` | send mutation plans into `publication_pipeline`, join `schema_codec`, and issue `response_registry` render tickets |

The chain has three hard boundaries:

- canonical request truth exists before `h2` and stays in the `W8-01` family,
- authority moves only when `h7` submits a mutation plan into `publication_pipeline` and `publication_pipeline`
  performs the later cut,
- and visible answers exist only after `h7` has a canonical `response_registry` ticket.

That means:
- `control_plane` may not render a successful control-plane mutation before `publication_pipeline` and
  `schema_codec` join,
  truths,
- and cluster/runbook/shadow paths may not invent a second evaluation or refusal
  chain outside `governance_surface_0`.

## 9. Budget, stop, and refusal law

### 9.1 Service-budget scopes

The production service uses these minimum budget scopes:

- `budget.policy_authority.global.b0` - total authority-service in-flight load
- `budget.policy_authority.surface.b1` - per-surface in-flight limits
- `budget.policy_authority.shard.b2` - per-shard queued work limits
- `budget.policy_authority.shadow.b3` - shadow/replay compare budget

### 9.2 Refusal and stop classes

| Refusal class | Meaning |
|---|---|
| `r0.authz_or_session` | session/grant/authz proof missing or expired |
| `r1.anchor_stale` | required anchor freeze cannot be proven or is stale |
| `r2.idempotency_conflict` | same idempotency scope collides with incompatible prior request |
| `r3.policy_or_secret_missing` | required policy manifest or secret lease is unavailable |
| `r4.override_invalid` | override missing, expired, spent, or scope-incompatible |
| `r5.budget_or_product_denied` | budget/admission/reclaim/recipe policy denies progress |
| `r6.stop_or_quarantine` | stop ticket, shadow hazard, failover hold, or quarantine blocks work |

### 9.3 Refusal invariants

1. Every refusal class must be expressible through one shared `response_registry` render path.
2. `posix_filesystem_adapter`, `explanation_query`, `control_plane`, and future `block_volume_adapter` surfaces may compress or translate the
   answer, but they may not invent a different refusal taxonomy.
3. `r6.stop_or_quarantine` is the only class that may absorb `shadow_pilot_0`, `membership_placement_0`,
   `operator_runbook_0`, `userspace`, or `kernel_gateway` stop-state linkage.
4. Budget pressure never silently drops work.
   It must emit `PolicyAuthorityStopOrRefusalRecord` plus one renderable refusal.

## 10. New authoritative records

This design introduces **10 new record families**.

| Record | Purpose |
|---|---|
| `PolicyAuthorityServiceTopologyRecord` | authoritative declaration of the production kernel-resident `policy_authority` family plus any bounded non-production userspace mirror, together with admitted surfaces, traits, and activation binding |
| `PolicyAuthorityIngressSurfaceBindingRecord` | one admitted ingress-surface binding from `control_plane`, `posix_filesystem_adapter`, `explanation_query`, `block_volume_adapter`, cluster runtime, or shadow replay |
| `PolicyAuthorityRuntimeComponentRecord` | one declared runtime component class and its allowed truth scope |
| `PolicyAuthorityRequestCapsuleRecord` | one admitted runtime request capsule around canonical `W8-01` request or batch refs |
| `PolicyAuthorityAnchorFreezeRecord` | one frozen anchor set bound to a request capsule |
| `PolicyAuthorityDomainShardBindingRecord` | one binding from a request capsule to one primary `d0..d5` shard |
| `PolicyAuthorityEvaluationPlanRecord` | one policy/override/budget/product evaluation plan before answer or mutation emission |
| `PolicyAuthoritySuccessorOrAnswerPlanRecord` | one mutation-successor plan, read-answer plan, or refusal plan issued by `policy_authority` |
| `PolicyAuthorityServiceBudgetStateRecord` | one global, surface, shard, or shadow budget/backpressure mirror |
| `PolicyAuthorityStopOrRefusalRecord` | one typed refusal or stop/quarantine record linked to rendering and recovery |

## 11. New algorithms

This design introduces **10 new algorithms / protocol families**.

| Algorithm | Purpose |
|---|---|
| `declare_policy_authority_service_topology_and_trait_families()` | emit one authoritative `policy_authority` service topology and trait set |
| `bind_ingress_surface_to_policy_authority_runtime()` | admit one surface/carrier/session/grant combination into live `policy_authority` |
| `canonicalize_or_rehydrate_policy_authority_request_capsule()` | turn surface-local input into one canonical request capsule |
| `bind_policy_authority_idempotency_and_freeze_anchor_set()` | attach idempotency scope and frozen anchors before evaluation |
| `route_policy_authority_request_capsule_to_domain_shard()` | select one primary shard and serialization key |
| `resolve_policy_override_budget_inputs_for_policy_authority()` | resolve policy, secret, override, lease, and budget prerequisites |
| `evaluate_policy_authority_product_decision_or_prepare_refusal()` | compute admission/reclaim/recipe result or typed refusal |
| `compose_policy_authority_successor_or_read_answer_plan()` | produce mutation-successor plan, read-answer plan, or refusal plan |
| `bridge_policy_authority_plan_into_publication_pipeline_schema_codec_and_response_registry()` | pass the plan into publication, receipt, and visible-answer handling |
| `emit_policy_authority_stop_quarantine_or_backpressure_refusal()` | surface pressure, hold, stop, or quarantine as one canonical refusal record |

## 12. Whole-system operational paths added by this law

1. local `tidefsctl` mutation request -> `surface.policy_authority.control_plane_local.s0` binding ->
   canonical `PolicyAuthorityRequestCapsuleRecord` -> `d0`/`d1`/`d2`/`d3` evaluation ->
   mutation-successor plan enters `publication_pipeline` -> `schema_codec` + `response_registry` finish one visible
   answer instead of `control_plane` keeping a local write dialect
2. `posix_filesystem_adapter` growth, override, or product-backed access edge ->
   capsule enters `d1`/`d2`/`d4`/`d5` -> read-answer or refusal plan joins
   `response_registry` -> Linux-facing errno/flag/render stays client-only instead of hiding
   local product authority
3. `explanation_query` explanation query -> `surface.policy_authority.client_explanation_query.s2` binding -> policy,
   override, budget, admission, or reclaim capsule enters the right shard ->
   canonical answer plan joins `PolicyAuthorityRequestReceipt` plus `response_registry` provenance /
   exactness badges -> explanation truth stops being query-local folklore
4. failover/runbook/shadow stage trigger -> `surface.policy_authority.cluster_runtime.s4` or
   `surface.policy_authority.shadow_replay.s5` binding -> frozen anchors, membership epoch,
   and stop/quarantine state are resolved before evaluation -> work either enters
   `publication_pipeline` lawfully or emits one typed refusal instead of migration-only helper
   behavior
5. overload, stale anchors, or explicit stop ticket -> one
   `PolicyAuthorityServiceBudgetStateRecord` opens backpressure or stop state -> one
   `PolicyAuthorityStopOrRefusalRecord` emits `r1`, `r2`, `r5`, or `r6` -> `control_plane`, `posix_filesystem_adapter`,
   `explanation_query`, dashboards, and recall readers all see one refusal grammar instead of
   surface-specific timeout or retry folklore

## 13. Acceptance effect on the design pack

With this law settled:

- `P3-01` becomes detailed enough for later implementation planning,
- the full `P3` authority-runtime workstream is now at `L3`,
- the repo now has one explicit answer to how live `policy_authority` runs, where request
  truth begins, where evaluation happens, and where publication/receipt/answer
  bridges may exist,
- `control_plane`, `posix_filesystem_adapter`, `explanation_query`, `publication_pipeline`, `response_registry`, `shadow_pilot_0`, `package_profile_catalog`, `memory_arena_0`, `transport_session_0`, and `membership_placement_0`
  now share one `policy_authority` runtime grammar instead of adapter-local helper paths,
- there are still **no** `L0` or `L1` production-design items,
- and the full production design ledger is now closed at `L3`, and later work is no longer missing shared seam/deletion law.
