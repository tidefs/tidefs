# publication pipeline runtime decomposition (P3-02) (v0.357)

This document is the source-of-truth for the production-depth publication
pipeline runtime decomposition for tidefs.

It answers the question:

**How does tidefs move an admitted mutation, policy change, failover cut,
repair publish, or checkpoint/cursor boundary through one explicit runtime queue,
batch, commit, progress, and wake chain instead of vague “commit_group sync somewhere”,
per-daemon worker folklore, or cluster-local commit magic?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md`
- `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`
- `docs/SHADOW_PILOT_RUNTIME_HOOKS_DIVERGENCE_SINKS_P3-04.md`
- `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`
- `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`
- `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for publication-runtime truth:

- one coordinating family: **`family.publication_pipeline_runtime.publication_pipeline`**
- one graph law: **`law.intent_prepare_batch_commit_progress_ticket.publication_pipeline`**
- **8 stable queue classes**
- **6 stable batch classes**
- **7 stable seal-trigger classes**
- **10 stable persistence task classes**
- one canonical chain:
  - **intent normalize -> anchor freeze -> prepare work item -> batch join ->
    seal trigger -> commit cut -> progress cursor -> wake tasks -> emission
    ticket -> recovery or retirement**

This means tidefs is no longer allowed to say only:

- “the pool commit_group logic will cover it,”
- “cluster commit is whatever the leader log already does,”
- “fsync/syncfs just force some sync path,”
- “policy and failover publish through their own helpers,”
- or “response emission can decide what was committed after the fact.”

It must instead say:

- which normalized publication-intent class entered the runtime,
- which frozen anchor set and shard key bound that intent,
- which queue class owns the work at each stage,
- which batch class and seal trigger admitted the commit cut,
- which persistence task classes must survive restart or failover,
- which progress cursor proves replica or follower visibility,
- which post-publish wake tasks are required for products, fences,
  checkpoints, and truth surfaces,
- and which emission ticket is handed to the explicit `response_registry`
  response/receipt path without letting later renderers redefine what actually
  committed.

The anti-regression rule is explicit:

**No daemon thread, helper task, cluster follower, runbook stage, cache worker,
policy path, or future kernel bridge may become legal publication authority
unless it uses the declared `publication_pipeline` queue classes, batch classes, seal triggers,
persistence tasks, and commit/progress/ticket law fixed here.**

## 2. Scope and boundaries

This document governs:

- how publication-capable work from `policy_authority`, `control_plane`, `posix_filesystem_adapter`, `block_volume_adapter`, failover,
  repair, and checkpoint/cursor maintenance is normalized into one intent
  grammar,
- how intents are sharded by frozen authority-domain anchors,
- how prepare work, batch assembly, commit cuts, progress tracking, and
  post-publish wake tasks are separated,
- how local commit_group thresholds and distributed cluster-commit movement map into one
  publication law,
- and how restart/failover recovery scans decide whether in-flight work is
  resumable, quarantined, or retired.

This document now consumes the explicit `governance_surface_0` authority-service law in `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`.

That boundary is deliberate.
`P3-02` fixes **how authority advances through runtime and where later laws
must plug in**.
It now consumes the explicit `memory_arena_0` memory-domain / arena / ownership-token law in `docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md`, the explicit `transport_session_0` transport / session / cohort graph in
`docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`, the explicit `membership_placement_0`
membership / placement / failure-domain law in
`docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`, the explicit `control_plane`
route/carrier law in `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`, the
explicit `shadow_pilot_0` shadow-hook law in
`docs/SHADOW_PILOT_RUNTIME_HOOKS_DIVERGENCE_SINKS_P3-04.md`, the explicit
`response_registry` receipt/response emission law in
`docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`, and the explicit `canonical_schema`
checkpoint/snapshot/cursor law in
`docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md`.
It now also consumes the explicit `posix_filesystem_adapter` daemon / process topology law in `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`, so mount-helper/bootstrap state, per-mount session processes, and restart verdicts are no longer allowed to create a second publication engine or a helper-local commit story around `posix_filesystem_adapter`. The design rule-family to Rust-type map is now explicit in `docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`, so Rust ids, owned structs, borrowed views, builders, collection wrappers, bridge mirrors, and `type_map` row ids are no longer allowed to drift from the declared design rule families. It now also consumes the explicit `workspace_layout` workspace-family / crate-service-boundary law in `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`, so crate roots, service roots, dependency edges, and test/observe boundaries are no longer allowed to drift from the declared design rule and runtime laws. It now also consumes the explicit `linux_baseline` Linux 7.0 baseline contract in `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`, so admitted host assumptions, subsystem floors, and explicit non-baseline cuts are no longer allowed to drift from the declared package/stage bindings. It now also consumes the explicit `product_variant` product-variant matrix in `docs/PRODUCT_VARIANT_MATRIX_P0-02.md`, so declared userspace-only, mixed-client-kernel, and optional later selected-domain kernel-authority rows are no longer allowed to drift from the declared host/package/stage bindings. It now also consumes the explicit `vfs_boundary_mirror` UAPI / FFI / canonical-schema boundary law in `docs/UAPI_FFI_CANONICAL_SCHEMA_BOUNDARY_RULES_P1-03.md`, so boundary mirrors, wire layouts, kernel-visible structs, `repr(C)` call frames, and conversion exactness are no longer allowed to drift from the declared design rule families. It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary. They may **not** invent a second publication engine, a queue-local commit dialect, or a second authority-advance chain outside `publication_pipeline`.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future
prose:

  exposes `commit_group_sync()` and `commit_group_tick()`, and seals local commits on
  op-count/time/byte thresholds.
  maintenance tick and reports `commit_group_synced` plus the threshold reason.
  mutating ops into one replicated log entry and can wait for all up voters.
  acknowledgement, commit-index advancement, resend, and log-sync behavior.
  `replication_state.json` for restart and catch-up recovery.

Production `publication_pipeline` extends those anchors by fixing the runtime decomposition they
must eventually share.
The current reference still proves feasibility, but it does not yet embody the
full queue/shard/ticket law described here.

## 4. Queue-class law

Every publication-capable path must move through one of the declared queue
classes.

| Queue class | Purpose |
|---|---|
| `queue.publication_pipeline.ingress.q0` | normalized publication intents from `policy_authority`, `control_plane`, `posix_filesystem_adapter`, `block_volume_adapter`, failover, repair, or checkpoint/cursor triggers |
| `queue.publication_pipeline.batch.q2` | per-domain batch assembly and seal arbitration |
| `queue.publication_pipeline.commit.q3` | exclusive execution of the narrow authoritative commit cut |
| `queue.publication_pipeline.progress.q4` | follower/replica progress, commit cursors, and post-cut convergence state |
| `queue.publication_pipeline.product_wake.q5` | product/cache/view/fence/checkpoint wake tasks caused by a committed cut |
| `queue.publication_pipeline.emit_ticket.q6` | handoff of committed facts to the explicit `response_registry` response/receipt emission path |
| `queue.publication_pipeline.recovery.q7` | restart/failover scan, resume, quarantine, or retirement of in-flight publication work |

The queue law is strict:

1. Only `q3.commit` may move authoritative heads, projection roots, epochs,
   or linked ledgers.
2. `q0`, `q1`, and `q2` may prepare or seal, but they may not claim that
   publication is visible yet.
3. `q4`, `q5`, and `q6` are downstream of a committed cut; they may lag, but
   they may not reinterpret what the cut means.
4. `q6.emit_ticket` carries only canonical emission tickets. It may not render
   wire replies, explanation fields, or operator bundles by itself.
5. `q7.recovery` may resume, quarantine, or retire in-flight work, but it may
   not invent a new commit result that lacks a `q3` cut record.

## 5. Batch classes and seal-trigger law

### 5.1 Stable batch classes

| Batch class | Meaning |
|---|---|
| `batch.publication_pipeline.single_domain.b0` | default one-domain publication cut over one authority shard |
| `batch.publication_pipeline.sync_forced.b1` | explicit barrier cut for `fsync`/`syncfs`/operator sync or equivalent synchronous visibility contract |
| `batch.publication_pipeline.cluster_commit_group.b2` | one replicated semantic batch whose commit proof spans leader/follower progress |
| `batch.publication_pipeline.policy_or_governance.b3` | control-plane policy, budget, override, or recipe publication under `control_plane` |
| `batch.publication_pipeline.failover_or_stage.b4` | failover, handoff, rollback, or cutover stage publication tied to `operator_runbook_0`, `userspace`, or `kernel_gateway` |
| `batch.publication_pipeline.multi_domain_expensive.b5` | rare, explicit cross-domain coordinated publish; never an incidental coalescing side effect |

### 5.2 Stable seal-trigger classes

| Seal trigger | Meaning |
|---|---|
| `seal.publication_pipeline.target_ops.s0` | op-count threshold reached |
| `seal.publication_pipeline.target_seconds.s1` | time threshold reached |
| `seal.publication_pipeline.target_bytes.s2` | soft dirty-bytes threshold reached |
| `seal.publication_pipeline.dirty_max_bytes.s3` | hard dirty-bytes cap reached |
| `seal.publication_pipeline.caller_barrier.s4` | explicit caller barrier such as `fsync`, `syncfs`, or route-level synchronous publish |
| `seal.publication_pipeline.runbook_or_failover.s5` | runbook stage fence, failover commit window, rollback point, or explicit migration boundary |
| `seal.publication_pipeline.checkpoint_or_cursor.s6` | checkpoint/snapshot/cursor persistence or recovery boundary forces a seal |

The seal law is strict:

1. `s0-s3` mirror the real pool-side commit_group thresholds already present in the
2. `s4-s6` are semantic barriers, not scheduler convenience flags.
3. A batch class is chosen before sealing. A queue may refuse or split a batch,
   but it may not silently upgrade to `b5.multi_domain_expensive`.
4. `b5.multi_domain_expensive` always requires explicit charter/runbook intent,
   audit linkage, and recovery markers.
5. No queue-local worker may seal a batch on private heuristics that survive
   nowhere in manifests, receipts, or progress cursors.

## 6. Canonical publication chain

The production runtime now fixes one stage chain for publication-capable work:

| Stage | Meaning |
|---|---|
| `stage.publication_pipeline.h0.normalize_intent` | normalize incoming request or runtime trigger into one publication intent |
| `stage.publication_pipeline.h1.freeze_anchor_set` | freeze authority-domain, policy, lease, membership, and cursor anchors |
| `stage.publication_pipeline.h2.prepare_work_item` | prepare immutable successors, witness/refcount/reserve deltas, and required prerequisites |
| `stage.publication_pipeline.h3.join_batch` | admit the work item into one sharded batch builder |
| `stage.publication_pipeline.h4.seal_batch` | seal the batch under one declared trigger and batch class |
| `stage.publication_pipeline.h5.commit_cut` | execute the narrow authoritative cut and persist the cut record |
| `stage.publication_pipeline.h6.persist_progress_cursor` | advance replica/follower/progress cursor state and convergence markers |
| `stage.publication_pipeline.h7.emit_wake_tasks` | create product, fence, cache, checkpoint, and archive/retention wake tasks |
| `stage.publication_pipeline.h8.issue_emission_ticket` | hand off canonical committed facts to explicit `response_registry` handling without rendering them yet |
| `stage.publication_pipeline.h9.recover_or_retire` | on restart/failover, resume, quarantine, or retire in-flight work |

The chain has two hard boundaries:

- authority moves **only** at `h5.commit_cut`,
- and external response/receipt rendering begins **only after** `h8`, under the
  explicit `response_registry` law in `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`.

That means:

- background views, caches, and observer products may lag after `h5`, but they
  may not redefine the cut,
- cluster progress may continue after `h5`, but it is a progress question, not a
  second commit dialect,
- and the explicit `response_registry` law now decides storage/index/render policy for
  receipts and responses, but it does not get to decide whether the cut
  happened.

## 7. Persistence-task and distributed-binding law

Every batch class must materialize the required persistence tasks.
The minimum stable task classes are:

| Task class | Purpose |
|---|---|
| `task.publication_pipeline.intent_journal.t0` | durable admission of the normalized publication intent |
| `task.publication_pipeline.anchor_seal.t1` | frozen anchor-set persistence and shard-key proof |
| `task.publication_pipeline.prepare_materialization.t2` | prepared immutable successor and prerequisite bundle tracking |
| `task.publication_pipeline.batch_manifest.t3` | one sealed batch manifest with class, members, and trigger refs |
| `task.publication_pipeline.commit_cut.t4` | authoritative cut record and successor/epoch move proof |
| `task.publication_pipeline.progress_cursor.t5` | follower/replica/progress cursor state and quorum or degradation result |
| `task.publication_pipeline.product_wake.t6` | post-publish wake tasks for caches, views, fences, and mirrors |
| `task.publication_pipeline.checkpoint_cursor.t7` | checkpoint/snapshot/cursor persistence tasks linked to the cut |
| `task.publication_pipeline.emission_ticket.t8` | canonical ticket for explicit `response_registry` receipt/response emission |
| `task.publication_pipeline.recovery_scan.t9` | restart/failover recovery, quarantine, or retirement proof |

Distributed binding is explicit:

- `t5.progress_cursor` must project onto the declared `transport_session_0` control and
  replication-metadata sessions, not a publication-private socket grammar.
- `membership_placement_0` membership epoch and placement verdicts freeze at `h1` and become inputs
  to `t5`; they may not be recomputed post-commit by queue-local heuristics.
  same publication chain that authority and response paths see.
- `canonical_schema` checkpoint/snapshot/cursor tasks consume `t7`, not a separate checkpoint
  mini-pipeline.
- single-node variants still emit the same task classes even when `t5` collapses
  to local progress and durability proof.

## 8. Stop-trigger and anti-regression law

The production runtime now requires these stop-trigger classes:

| Stop trigger | Meaning | Required action |
|---|---|---|
| `stop.publication_pipeline.missing_anchor` | required authority, policy, lease, membership, or cursor anchor missing or contradictory | refuse admission or quarantine the intent |
| `stop.publication_pipeline.prepare_over_budget` | prepare work exceeds admitted reserve, latency, or pressure window | throttle or refuse before seal |
| `stop.publication_pipeline.shard_conflict` | incompatible work tries to share one shard/batch without an explicit expensive-path class | split or refuse; never silently merge |
| `stop.publication_pipeline.commit_conflict` | predecessor pointer, epoch, or cut precondition changed before `h5` | abort batch and reopen from fresh anchors |
| `stop.publication_pipeline.progress_uncertain` | commit cut happened but follower/replica/progress state is ambiguous or contradictory | hold stage/result and preserve recovery markers |
| `stop.publication_pipeline.emission_ticket_gap` | committed cut lacks the required emission ticket for explicit `response_registry` handling | block external success rendering |

No later law may demote one of these triggers into a dashboard warning,
queue-local metric, or best-effort comment.
If one fires, the result is a typed refusal, hold, rollback marker, or recovery
quarantine state under `operator_runbook_0`, `userspace`, or `kernel_gateway` when those domains are active.

## 9. Records required by this law

The central data-structures map now requires:

- `PublicationIngressIntentRecord`
- `PublicationAnchorFreezeRecord`
- `PublicationPrepareWorkItemRecord`
- `PublicationBatchRecord`
- `PublicationSealTriggerRecord`
- `PublicationCommitCutRecord`
- `PublicationProgressCursorRecord`
- `PublicationWakeTaskRecord`
- `PublicationEmissionTicketRecord`
- `PublicationRecoveryScanRecord`

These records sit above raw commit_group/log internals and below later response or truth
rendering.
They are the typed runtime proof objects that `control_plane`, `posix_filesystem_adapter`, `block_volume_adapter`, `shadow_pilot_0`,

## 10. Algorithms required by this law

The central algorithm map now requires:

- `normalize_request_or_runtime_trigger_to_publication_intent()`
- `freeze_publication_anchor_set_and_shard_key()`
- `admit_publication_intent_into_prepare_queue()`
- `prepare_successor_work_item_and_admit_to_batch()`
- `seal_publication_batch_from_threshold_or_semantic_barrier()`
- `execute_atomic_publication_commit_cut()`
- `persist_commit_progress_and_replica_cursor_state()`
- `emit_postpublish_wake_tasks_for_products_fences_and_checkpoints()`
- `issue_publication_emission_ticket_for_p3_03_path()`
- `recover_or_quarantine_inflight_publication_after_restart_or_failover()`

## 11. Whole-system operational paths added by this law

1. `control_plane` policy or override route normalizes to one `publication_pipeline` ingress intent ->
   anchors freeze under `control_plane`/`identity_access_audit_0`/`secret_key_policy_0` -> one governance batch seals -> one
   authoritative cut occurs -> later receipt/response rendering consumes an
   emission ticket instead of re-deciding what committed
2. `posix_filesystem_adapter` buffered mutation or synchronous durability request joins one domain
   shard -> `seal.publication_pipeline.caller_barrier.s4` forces a `b1.sync_forced` cut ->
   progress cursor and wake tasks carry the committed fact to views/caches
   instead of “commit_group synced” folklore
3. replicated semantic batch in the cluster harness enters as
   `batch.publication_pipeline.cluster_commit_group.b2` -> leader/follower progress moves under `transport_session_0`
   control and metadata sessions -> committed cut and progress cursor remain one
   chain instead of one local commit_group story plus one separate cluster story
4. failover, rollback point, or stage fence under `operator_runbook_0`/`userspace`/`kernel_gateway` forces
   `seal.publication_pipeline.runbook_or_failover.s5` -> the cut, progress cursor,
   checkpoint/cursor task, and emission ticket all bind to the same stage proof
   instead of separate maintenance scripts
   explicit `response_registry` response emission all consume the same `h0 -> h9` publication
   chain instead of inventing compare-local, dashboard-local, archive-local, or
   render-local commit dialects

## 12. Acceptance effect on the design pack

With this law settled:

- `P3-02` becomes detailed enough for later implementation planning,
- the repo now has one explicit answer to how admitted work becomes a shard,
  batch, cut, progress cursor, wake task, and emission ticket,
- `control_plane`, `transport_session_0`, `membership_placement_0`, `shadow_pilot_0`, `canonical_schema`, `operator_runbook_0`, `package_profile_catalog`, and `archive_control` now share one
  publication-runtime grammar instead of reusing “commit_group” as a catch-all story,
- future `posix_filesystem_adapter`, `block_volume_adapter`, and kernel bridge paths must now enter the same
  publication chain rather than attaching commit truth to queue-local workers,
- and the full production design ledger is now at `L3`, so later work is user-directed refinement or implementation discipline rather than missing seam/deletion law.
