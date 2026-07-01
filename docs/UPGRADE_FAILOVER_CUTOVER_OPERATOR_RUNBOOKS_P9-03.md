# upgrade / failover / cutover operator runbooks (P9-03) (v0.422)

This document is the source-of-truth for the production-depth operator-execution law.

It answers the question:

**How does tidefs execute live upgrades, failovers, and cutovers as typed, auditable runbooks instead of wiki prose, shell folklore, or one-off human judgment?**

See also:
- `docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md`
- `crates/tidefs-local-object-store/src/fault_catalog.rs`
- `crates/tidefs-validation/src/fault_injection_scenario_catalog.rs`
- `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md`
- `docs/FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS_P8-04.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270)
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for live operator execution:

- one coordinating family: **`family.operator_runbook.operator_runbook_0`**
- one execution law: **`law.intent_dryrun_stage_commit_verify_rollback.operator_runbook_0`**
- one canonical chain for every substantive live move:
  - **runbook template -> runbook intent -> authz/override binding -> preflight anchor snapshot -> dry-run receipt -> stage fence -> domain-specific commit receipt -> postchange verification record -> closure or rollback receipt**

This means tidefs is no longer allowed to treat any of these as the real production runbook:
- a wiki page,
- a shell transcript,
- a maintenance-window announcement,
- or “the operator knows the order.”

Those may still exist as convenience narrative.
They are not legal truth.
The legal truth is the bound runbook class plus the receipts, anchors, and verification artifacts it emits.

The anti-regression rule is explicit:

**A rollout or failover is never “successful” merely because traffic kept flowing. It is successful only when the bound gate receipts, bound domain-specific commit receipts, and postchange verification record all close under one named runbook class.**

## 2. Scope and boundaries

This document governs:
- operator-executed upgrades across declared continuity windows,
- failover and handoff of live authority or serving responsibility,
- cutover between archived, Rust userspace, and future kernel-hosted surfaces,
- rollback / re-entry after a blocked or failed move,
- and the minimum artifact and refusal grammar for those operations.

This document does **not** yet fully settle:
- the exact automation engine that will drive these runbooks in production.

The final secret/key storage mechanics are now explicit in `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`, and the operator truth-surface law is now explicit in `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270).
That boundary is deliberate.
`P9-03` fixes the legal runbook grammar.
Later items may refine budget tuning, retention, and automation, but they may not invent a second rollout/failover language.

## 3. Runbook family law

### 3.1 Mandatory runbook classes

The production system now requires at least these stable runbook classes:

1. **`runbook.operator_runbook_0.upgrade.variant_window.r0`**
   - rolling or staged upgrade inside one declared `feature_window` continuity window
   - includes format bridge use, mixed-version admission, and explicit downgrade fences

2. **`runbook.operator_runbook_0.failover.authority_domain.r1`**
   - authority handoff or emergency failover for one domain / cohort / service holder
   - includes witness quorum, reserve escrow, fence/drain, and replay-cursor sealing

3. **`runbook.operator_runbook_0.cutover.userspace_staircase.r2`**
   - `userspace` stage cutovers, especially narrow Rust authority, `posix_filesystem_adapter`/`explanation_query`/`block_volume_adapter` promotion, and final `control_plane` surface movement

4. **`runbook.operator_runbook_0.cutover.kernel_family.r3`**
   - future kernel-family promotions after `stage.userspace.mixed_soak_archive_ready.s7`
   - includes first `posix_filesystem_adapter` clean-read seam and later `block_volume_adapter` / optional `policy_authority` family moves

5. **`runbook.operator_runbook_0.rollback.reentry.r4`**
   - explicit return from any blocked or failed upgrade/failover/cutover path
   - includes re-entry after rollback only through the same row/profile/gate grammar

No production rollout, failover, or cutover may proceed outside one of those classes until a new class is explicitly declared in `operator_runbook_0`.

### 3.2 Stable step grammar

Every runbook class must use the same seven stable step classes:

1. **`step.operator_runbook_0.intent.s0`**
   - declare the subject, source state, target state, operator authority, and rollback class

2. **`step.operator_runbook_0.preflight_snapshot.s1`**

3. **`step.operator_runbook_0.dry_run_gate.s2`**
   - simulate admissibility and emit explicit refusal, continuation obligations, or stage admission

4. **`step.operator_runbook_0.stage_fence_prepare.s3`**
   - acquire freeze/quiesce/fence objects, drain intents, upgrade windows, or failover handoff state

5. **`step.operator_runbook_0.commit_transition.s4`**
   - execute the domain-specific transition through the already-settled subsystem receipt families

6. **`step.operator_runbook_0.verify_truth.s5`**
   - confirm gates, receipts, truth surfaces, anchors, and cutover/failover effects match the runbook claim

7. **`step.operator_runbook_0.close_or_reenter.s6`**
   - emit clean closure or a rollback/re-entry receipt; never leave the move as narrative limbo

The step ids are fixed.
Future tooling may automate them differently, but it may not change their legal order or hide them.

### 3.3 Mandatory runbook fields

Every concrete runbook intent must declare at least:
- `runbook_class_ref`
- `subject_scope_selector`
- `source_state_ref`
- `target_state_ref`
- `required_row_refs[]`
- `required_gate_refs[]`
- `required_profile_refs[]`
- `required_anchor_refs[]`
- `required_secret_handle_refs[]` (handle refs only; storage law is now `secret_key_policy_0` in `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`)
- `authz_decision_ref`
- `override_ticket_refs[]`
- `rollback_class_ref`
- `disclosure_policy_ref`

If one of those fields is absent, the runbook is incomplete and may not admit staging.

## 4. Authorization, preflight, and dry-run law

### 4.1 Actor / session / override binding

Every runbook intent must bind to the `identity_access_audit_0` law from `docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md`:
- one authenticated principal/session pair,
- one authorization decision,
- and, when required, one or more valid override consumptions.

The production rule is explicit:
- normal upgrade/cutover/failover paths must succeed under published role/capability law,
- emergency or exceptional paths may use typed overrides only where the constraint profile allows them,
- and no runbook step may smuggle authority through shell privilege, host-local root, or undocumented environment variables.

Dual control remains mandatory where `P9-02` already requires it.
`P9-03` does not weaken that law; it only says how those already-legal powers are exercised.

### 4.2 Preflight anchor snapshot law

Before any runbook may stage, it must seal one preflight snapshot that binds the move to current truth.
That snapshot must include the relevant subset of:
- current policy revision,
- current continuity window / upgrade bridge refs,
- checkpoint anchors,
- immutable snapshot anchors if the move depends on them,
- replay-cursor anchors and seal receipts,
- failover intents / quorum refs / handoff fence refs when applicable,
- and the current operator-visible summary that the move claims it will change.

This snapshot is not optional bookkeeping.

### 4.3 Dry-run and refusal law

Every runbook class must support a dry-run result before commit.
The dry-run may be:
- normal and complete,
- emergency and best-effort,
- or explicit refusal.

Refusal is a legal and often correct outcome.
A dry-run must therefore say which of these is true:
- **admissible** — stage may begin,
- **blocked** — named continuation obligations remain,
- **override_required** — ordinary admission failed but a still-legal override path exists,

No operator or automation engine may translate those into “just try it and see.”

## 5. Stage, commit, verify, and rollback law

### 5.1 Stage-fence law

`step.operator_runbook_0.stage_fence_prepare.s3` is where the system becomes ready for change.
It may:
- close admission for new conflicting work,
- freeze or quiesce selected surfaces,
- stage failover handoff fences,
- seal replay cursors,
- pin one upgrade continuity window,
- and hold the checkpoint/snapshot anchors the move depends on.

But it may **not** itself claim success.
Staging is preparation, not final truth.

### 5.2 Domain-specific commit mapping

`P9-03` does not replace the subsystem receipts that already own the real move.
It orchestrates them.
The mapping is fixed:

- **upgrade runbooks** must commit through `feature_window` artifacts such as:
  - `UpgradeIntentRecord`
  - `UpgradeBatchRecord`
  - `UpgradeCutoverReceipt`

- **failover runbooks** must commit through distributed/runtime artifacts such as:
  - `FailoverIntentRecord`
  - `WitnessQuorumRecord`
  - `HandoffFenceRecord`
  - relevant freshness or placement receipts

- **userspace cutover runbooks** must commit through `userspace` artifacts such as:
  - `UserspaceCutoverPlanRecord`
  - `UserspaceAuthorityCutoverReceipt`
  - `UserspaceRollbackReentryReceipt` when needed

- **kernel-family cutover runbooks** must commit through artifacts such as:
  - `KernelFamilyPromotionPlanRecord`
  - `KernelFamilyCutoverReceipt`
  - `KernelFamilyRollbackReceipt` when needed

The anti-regression rule is explicit:

**`operator_runbook_0` may coordinate those subsystem receipts, but it may not invent a second notion of commit that bypasses them.**

### 5.3 Postchange verification law

After commit, the runbook must prove the new state from canonical truth surfaces.
Verification must check the relevant subset of:
- required gate receipts,
- postchange checkpoint/snapshot/cursor anchor health,
- expected variant or lease ownership,
- expected policy revision and continuity-window state,
- expected control_plane/explanation_query operator-visible truth,
- expected shadow/cutover parity state,
- and any repair/rebuild/failover side effects the move should have triggered.

If those checks do not close, the result is not “partial success.”
It is one of:
- a stop ticket,
- a rollback trigger,
- or a closure with mandatory continuation class.

### 5.4 Rollback / re-entry law

Every runbook class must declare one rollback class before commit starts.
Rollback is therefore never improvised after the fact.

Rollback must:
- restore or explicitly supersede the prior state through receipts,
- carry forward the relevant anchors and replay cursors,
- and reopen admission only through `gate.rollback.reentry` where that gate exists.

Rollback may not:
- rewrite already-published receipts,
- silently restore hidden archived or userspace authority,
- or claim that a blocked move “never happened.”

## 6. Runbook-class specializations

### 6.1 Upgrade runbooks

`runbook.operator_runbook_0.upgrade.variant_window.r0` must consume `feature_window` and `canonical_schema` together.
The move is illegal unless:
- one continuity window is declared,
- any required bridge class is declared,
- required checkpoint/snapshot/cursor anchors are sealed,
- and downgrade fences or quarantine rules are already known.

This runbook class is where mixed-version or reencode/replay complexity is made honest to operators.
It may not hide a bridge, hide a continuity miss, or imply that replay of unknown-future artifacts is okay because the new binary happened to parse them.

### 6.2 Failover runbooks

`runbook.operator_runbook_0.failover.authority_domain.r1` must consume the already-settled failover/handoff law from `P8-03`, `P8-04`, `P6-03`, and `P2-05`.
The move is illegal unless:
- the required failover intent and quorum classes exist,
- reserve escrow and service-floor effects are known,
- replay cursors are sealed at the failover frontier,
- and post-failover verification can still prove exactness/freshness truth to operators.

This matters most for emergency paths.
The design rule does not forbid emergency failover.
It forbids emergency failover that becomes unqueryable folklore afterward.

### 6.3 Userspace-staircase cutover runbooks

`runbook.operator_runbook_0.cutover.userspace_staircase.r2` is the executable operator form of `userspace`.
It must therefore bind directly to:
- the named `userspace` stage id,
- the inherited `type_map` row ids,
- the inherited `cutover_control_0` campaign rows,
- the inherited gate classes,
- and the rollback class declared by the `userspace` stage.

This is especially important for `stage.userspace.control_plane_full_surface.s6` and `stage.userspace.mixed_soak_archive_ready.s7`.
Those stages are no longer allowed to rely on “we know how to cut traffic over later.”
They now have one declared runbook grammar.

### 6.4 Kernel-family cutover runbooks

`runbook.operator_runbook_0.cutover.kernel_family.r3` is the operator form of
future kernel-family promotion.
It inherits the fixed family order and first-seam law.
That means:
- no kernel-family runbook may begin before `stage.userspace.mixed_soak_archive_ready.s7`,
- the first legal product-family runbook is for `kmod.posix_filesystem_adapter.vfs.k0`,
- the runbook must preserve the userspace fallback surfaces declared by the seam,
- and later `block_volume_adapter` / optional `policy_authority` moves must reuse the same row/profile/gate/rollback grammar.

Kernel execution may change mechanics.
It may not change the meaning of operator success, refusal, rollback, or proof.

## 7. Artifact and failure-bucket law

### 7.1 Mandatory runbook artifact classes

Every substantive runbook execution must emit at least:
1. one runbook intent artifact,
2. one preflight snapshot artifact,
3. one dry-run receipt,
4. one stage-fence artifact or explicit stage refusal,
5. the domain-specific commit receipt set,
6. one postchange verification artifact,
7. one closure or rollback receipt,
8. and one operator-readable summary artifact that links back to the canonical receipts.

The last item may be narrative or dashboard-oriented later.
It is not the source of truth.
It is a projection over the canonical artifacts above.

### 7.2 Normalized runbook failure buckets

`operator_runbook_0` now requires these stable failure/refusal buckets:
- **`bucket.operator_runbook_0.auth_policy_refusal`**
- **`bucket.operator_runbook_0.anchor_or_window_invalid`**
- **`bucket.operator_runbook_0.quorum_or_fence_blocked`**
- **`bucket.operator_runbook_0.secret_or_channel_unavailable`**
- **`bucket.operator_runbook_0.postcommit_verification_failed`**
- **`bucket.operator_runbook_0.rollback_or_reentry_blocked`**

Those buckets do not replace `type_map`, `cutover_control_0`, `userspace`, or kernel-family buckets.
They are the stable operator-execution projection that maps those deeper findings into runbook-visible truth.

## 8. Current-tree grounding rule

- and `start.sh` / `stop.sh` as the current session entry wrappers.

Those are not yet the final production automation product.
But the grounding rule is now explicit:


## 9. Boundary with remaining unresolved production items

The adjacent `P9-04` secret and policy-storage law is now explicit in `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`, source-backed performance-gate behavior lives under `crates/tidefs-validation/src/performance_gate/`, and the operator truth-surface law is now explicit in `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270).
The boundary is deliberate:
- `P9-03` fixes how operators execute a move,
- `P9-04` now fixes where long-lived secret material lives, how runtime leases work, and how secret material rotates or revokes,
- source-backed performance-gate rows add numeric floors to the same gates,
- `P10-04` is now explicit in `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270) and renders these results through shared `truth_view` truth surfaces and render receipts,
- future kernel-side runbook helpers must obey the current kernel residency and
  preview UAPI boundaries,

## 10. Records required by this law

The central data-structures map now requires:
- `OperatorRunbookTemplateRecord`
- `OperatorRunbookIntentRecord`
- `OperatorRunbookStepBindingRecord`
- `OperatorRunbookPreflightSnapshotRecord`
- `OperatorRunbookDryRunReceipt`
- `OperatorRunbookStageFenceRecord`
- `OperatorRunbookExecutionReceipt`
- `OperatorRunbookCommitReceipt`
- `OperatorRunbookVerificationRecord`
- `OperatorRunbookRollbackReceipt`

## 11. Algorithms required by this law

The central algorithms map now requires:
- `declare_operator_runbook_template_and_required_steps()`
- `issue_operator_runbook_intent_from_authorized_request()`
- `bind_runbook_steps_to_rows_artifacts_anchors_and_secret_handles()`
- `snapshot_preflight_policy_gates_and_persistence_anchors()`
- `evaluate_runbook_dry_run_and_emit_admission_or_refusal()`
- `acquire_stage_fences_quiesce_and_transition_windows()`
- `execute_runbook_step_and_emit_linked_receipts()`
- `seal_runbook_commit_with_domain_receipts_and_gate_refs()`
- `verify_postchange_truth_surfaces_and_open_stop_ticket_if_needed()`
- `execute_runbook_rollback_or_reentry_with_anchor_preservation()`

## 12. Acceptance effect on the design pack

With this law settled:
- `P9-03` becomes detailed enough for later implementation planning,
- operator execution is no longer allowed to hide behind wiki prose or shell folklore,
- upgrade/failover/cutover paths now share one runbook grammar across userspace, clustered failover, and future kernel promotions,
- and the next unresolved production items are no longer live-runbook ambiguity but the build/packaging matrix and later distributed session/placement detail that must consume the fixed `shadow_pilot_0` runbook-shadow law and the now-explicit `archive_control` retirement law.
