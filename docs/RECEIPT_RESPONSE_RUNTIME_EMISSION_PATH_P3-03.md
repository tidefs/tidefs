# receipt / response runtime emission path (P3-03) (v0.357)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the source-of-truth for the production-depth receipt /
response runtime emission path for tidefs.

It answers the question:

**How does tidefs turn one committed cut, exact read verdict, degraded-but-legal
answer, stop/refusal result, or archive recall into one explicit runtime chain
for `schema_codec` receipt joins, `response_envelope` response envelopes, carrier/surface compression,
delivery commit, indexing, and later recall instead of letting each surface
invent its own “success/failure” story?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`
- `docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`
- `docs/SHADOW_PILOT_RUNTIME_HOOKS_DIVERGENCE_SINKS_P3-04.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270)
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for receipt/response runtime
truth:

- one coordinating family: **`family.receipt_response_runtime.response_registry`**
- one runtime/render owner family: **`service.response_normalizer.response_normalizer`**
- one graph law: **`law.ingress_cut_join_envelope_render_index_recall.response_registry`**
- **8 stable emission scope classes**
- **5 stable truth-cut classes**
- **8 stable render classes**
- **7 stable refusal classes**
- one canonical chain:
  - **emission ingress -> truth cut -> receipt join -> response envelope ->
    compression plan -> render bundle -> delivery commit -> index write ->
    recall binding -> recovery or redelivery**

This means tidefs is no longer allowed to say only:

- “the FUSE adapter can decide which errno means success,”
- “the control-plane route will return whatever JSON feels natural,”
- “dashboards, archive recall, and scenario summaries can each keep their own
  render grammar,”
- “read answers do not need durable linkage because only mutations emit
  receipts,”
- or “the response path can rediscover what committed after the fact.”

It must instead say:

- which `response_registry` scope class admitted the answer,
- which truth-cut class the answer is allowed to claim,
- which `schema_codec` receipts, tickets, findings, or stop triggers are required for
  that claim,
- which canonical `response_envelope` / `response_normalizer` response envelope was materialized,
  or test/campaign surfaces,
- which delivery commit proves the rendered answer actually left the runtime,
- which index rows and recall bindings survive for later operator, archive, or
- and which recovery path is required if delivery or indexing is interrupted by
  restart or failover.

The anti-regression rule is explicit:

**No adapter, CLI, dashboard, archive reader, scenario harness, xfstests tool,
future kernel leaf, or future Rust service may become legal response authority
unless it consumes the declared `response_registry` scope classes, truth-cut classes,
receipt-join law, response-envelope law, render classes, delivery commits,
indexes, and recall bindings fixed here.**

## 2. Scope and boundaries

This document governs:

- how `publication_pipeline` emission tickets, exact read verdicts, degraded/stale-but-legal read
  verdicts, stop/refusal results, archive recalls, and test/campaign summaries
  enter one response runtime,
- how `schema_codec` receipts, tickets, findings, and stop markers are joined to a
  response claim,
- how one canonical `response_envelope` / `response_normalizer` response envelope is materialized before any
  surface-specific compression occurs,
- how carrier-specific and surface-specific rendering is derived for `posix_filesystem_adapter`,
- and how restart/failover recovery classifies in-flight response work.

This document now consumes the explicit `governance_surface_0` authority-service law in `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`.

That boundary is deliberate.
`P3-03` fixes **how committed or refused truth becomes a visible answer and a
later recallable artifact**.
It now consumes the explicit `memory_arena_0` memory-domain / arena / ownership-token law in `docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md`, the explicit `posix_filesystem_adapter` daemon / process topology law in `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`, the explicit `publication_pipeline` publication-runtime law in
`docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`, the explicit `control_plane`
route/carrier law in `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`, the
explicit `shadow_pilot_0` shadow-runtime law in
`docs/SHADOW_PILOT_RUNTIME_HOOKS_DIVERGENCE_SINKS_P3-04.md`, the explicit `truth_view`
truth-surface law in `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270),
The design rule-family to Rust-type map is now explicit in `docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`, so Rust ids, owned structs, borrowed views, builders, collection wrappers, bridge mirrors, and `type_map` row ids are no longer allowed to drift from the declared design rule families. It now also consumes the explicit `workspace_layout` workspace-family / crate-service-boundary law in `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`, so crate roots, service roots, dependency edges, and test/observe boundaries are no longer allowed to drift from the declared design rule and runtime laws. It now also consumes the explicit `linux_baseline` Linux 7.0 baseline contract in `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`, so admitted host assumptions, subsystem floors, and explicit non-baseline cuts are no longer allowed to drift from the declared package/stage bindings. It now also consumes the explicit `product_variant` product-variant matrix in `docs/PRODUCT_VARIANT_MATRIX_P0-02.md`, so declared userspace-only, mixed-client-kernel, and optional later selected-domain kernel-authority rows are no longer allowed to drift from the declared host/package/stage bindings. It now also consumes the explicit `vfs_boundary_mirror` UAPI / FFI / canonical-schema boundary law in `docs/UAPI_FFI_CANONICAL_SCHEMA_BOUNDARY_RULES_P1-03.md`, so boundary mirrors, wire layouts, kernel-visible structs, `repr(C)` call frames, and conversion exactness are no longer allowed to drift from the declared design rule families. It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary. They may **not** invent a second response authority, adapter-local status family, archive-local truth story, or render-time commit reinterpretation outside `response_registry`.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future
prose:

  `Ok`/`Err` result ADT for pure verdict propagation.
  bounded FUSE reply encoder pair, `ok_reply()` and `err_reply()`, proving that
  Linux-wire delivery is a distinct runtime step.
  service, stats, debug, and fingerprint bundles for operator-facing userspace
  surfaces.
  raw `check` stdout into stable `TestLine`, `Counts`, and `SummaryLine`
  structures rather than shell-local text scraping.
  JSON-serializable `ScenarioReport`, `ScenarioEvaluation`, and
  `ScenarioSuiteReport` objects.

Production `response_registry` extends those anchors by fixing the lineage, cut, envelope,
compression, index, and recall law that all of those surfaces must eventually
share.
The current reference still proves feasibility, but it does not yet embody the
full response-runtime chain described here.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Stable emission scope classes | 8 |
| Stable truth-cut classes | 5 |
| Stable render classes | 8 |
| Stable refusal classes | 7 |
| Required record families | 10 |
| Required algorithms | 10 |

## 5. Emission scope, truth-cut, render, and refusal law

### 5.1 Stable emission scope classes

| Scope class | Meaning |
|---|---|
| `scope.response_registry.charter.read.s0` | direct read/stat/query answer tied to frozen read anchors |
| `scope.response_registry.charter.mutation.s1` | visible charter mutation result tied to a committed publication cut |
| `scope.response_registry.control.write.s2` | `control_plane` policy/override/admission/secret-control write route result |
| `scope.response_registry.control.read.s3` | `control_plane` truth, state, or bounded diagnostic read |
| `scope.response_registry.runbook.stage.s4` | operator stage, failover, rollback, or cutover result |
| `scope.response_registry.shadow_or_gate.s6` | shadow, performance, chaos, or stop/gate-derived refusal or advisory result |
| `scope.response_registry.test_or_campaign.s7` | xfstests, scenario, benchmark, or campaign summary result |

### 5.2 Stable truth-cut classes

| Truth cut | Meaning |
|---|---|
| `cut.response_registry.committed_authority.c0` | answer is justified by one committed authority move or committed stage result |
| `cut.response_registry.read_anchor_exact.c1` | answer is an exact read under one frozen anchor set |
| `cut.response_registry.read_anchor_degraded.c2` | answer is legal but degraded/stale-bounded under explicit charter allowance |
| `cut.response_registry.stop_or_refusal.c3` | answer is a refusal, hold, or stop condition that must remain visible as such |
| `cut.response_registry.recall_archive.c4` | answer is a later recall or archive-backed projection over already-sealed truth |

The cut law is strict:

1. `c0.committed_authority` requires a committed publication/stage receipt set.
   A prepare-only artifact may never claim it.
2. `c1.read_anchor_exact` and `c2.read_anchor_degraded` require frozen read
   anchors. They may not silently inherit “latest enough” from cache or route
   locality.
3. `c3.stop_or_refusal` must preserve denial/hold cause. No renderer may fprevious it
   into generic I/O failure, “unknown,” or “not ready.”
4. `c4.recall_archive` may project preserved artifacts, but it may not become a
   second live authority.
5. No render class may upgrade, blur, or erase the cut class selected upstream.

### 5.3 Stable render classes

| Render class | Meaning |
|---|---|
| `render.response_registry.posix_filesystem_adapter_wire.r0` | Linux-facing `posix_filesystem_adapter` errno/attr/bytes/flag compression |
| `render.response_registry.block_volume_adapter_completion.r1` | block/export completion status and byte-count compression |
| `render.response_registry.control_plane_json_rpc.r2` | structured `control_plane` API/CLI reply bundle |
| `render.response_registry.explanation_query_fieldset.r3` | explanation/query field projection with lineage refs |
| `render.response_registry.truth_view_bundle.r4` | operator truth-surface render bundle |
| `render.response_registry.test_campaign_report.r6` | stable scenario / xfstests / perf / chaos summary bundle |
| `render.response_registry.refusal_only.r7` | refusal-only or hold-only bundle with no success payload |

### 5.4 Stable refusal classes

| Refusal class | Meaning |
|---|---|
| `refusal.response_registry.auth_or_policy.f0` | authn/authz/policy or override refusal |
| `refusal.response_registry.reserve_or_budget.f1` | reserve, budget, or pressure refusal |
| `refusal.response_registry.prepared_not_published.f2` | work prepared but not yet lawfully visible |
| `refusal.response_registry.stale_or_degraded_not_admitted.f3` | stale/degraded answer exists but charter or route forbids surfacing it |
| `refusal.response_registry.unsupported_cut_or_surface.f4` | unsupported-by-charter-cut or unsupported-by-surface refusal |
| `refusal.response_registry.stop_ticket_or_hazard.f5` | stop ticket, split-brain hold, or cutover blocker is open |
| `refusal.response_registry.delivery_or_recall_blocked.f6` | delivery/index/recall cannot be completed lawfully |

Refusal compression is also strict:

- `posix_filesystem_adapter` and `block_volume_adapter` may compress refusals to Linux-visible status, but only after
  the canonical refusal class exists.
  refusal class explicitly.
- a local renderer may add hints, but it may not invent a new refusal family.

## 6. Canonical emission chain

The production runtime now fixes one stage chain for response work:

| Stage | Meaning |
|---|---|
| `stage.response_registry.e0.admit_ingress` | admit one emission ingress from `publication_pipeline`, a read verdict, a gate result, or a recall/test source |
| `stage.response_registry.e1.derive_truth_cut` | derive the allowed truth-cut class from committed anchors, read anchors, or stop state |
| `stage.response_registry.e2.join_receipt_lineage` | join required `schema_codec` receipts, tickets, findings, and stop markers |
| `stage.response_registry.e3.materialize_response_envelope` | materialize one canonical `response_envelope` / `response_normalizer` response envelope |
| `stage.response_registry.e4.compile_compression_plan` | choose the legal render class, field mask, redaction set, and visible status compression |
| `stage.response_registry.e5.assemble_render_bundle` | assemble one structured bundle or binary reply payload candidate |
| `stage.response_registry.e6.commit_delivery` | commit the visible answer to its carrier or surface under one idempotent delivery record |
| `stage.response_registry.e7.write_indexes` | persist request, receipt, subject, stage, artifact, and refusal indexes as required |
| `stage.response_registry.e9.recover_or_redeliver` | on restart/failover, recover, redeliver, or terminally refuse incomplete response work |

The chain has three hard boundaries:

- truth is selected **before** render compression,
- delivery becomes externally visible **only** at `e6.commit_delivery`,
- and recall or archive projection happens **only after** `e7`/`e8`, never by
  re-running authority logic.

That means:

- adapters may compress but they may not reinterpret truth,
- dashboards and recall readers may project but they may not promote raw logs to
  authority,
- and retries or reconnects may redeliver a committed answer, but they may not
  fabricate a different response story for the same request token.

## 7. Storage, indexing, retention, and idempotent-delivery law

The production response runtime now requires four retention classes:

| Retention class | Meaning |
|---|---|
| `retain.response_registry.ephemeral.r0` | bounded non-mutating reply with no later recall obligation |
| `retain.response_registry.indexed_hot.r1` | indexed live reply needed for request/subject/stage lookup |
| `record.response_registry.stop_hold.r3` | refusal/hold/stop artifact recorded until cleared or superseded |

The index law is also explicit.
At minimum the runtime must be able to index by:

- request or idempotency token,
- subject scope and authority anchor,
- receipt / response reference,
- route or runbook/stage identity,
- and artifact / bundle / refusal locator.

Indexing rules:

1. mutating success (`s1`, `s2`, `s4`) always requires indexed-hot storage.
2. truth/recall and campaign/report scopes (`s5`, `s6`, `s7`) always require
   indexed or recallable storage.
3. pure exact reads (`s0`) may use `r0.ephemeral` only if no stop, no recall
   contract, and no later operator lookup requirement applies.
4. a response that cites archive-only material may not be emitted as live truth
   without a visible `c4.recall_archive` cut.
5. idempotent replay returns the same delivery digest or a typed delivery
   conflict; it never creates a second success narrative.

xfstests summaries therefore become projections over the same indexed response
runtime, not independent stores of truth.

## 8. Stop-trigger and anti-regression law

The production runtime now requires these stop-trigger classes:

| Stop trigger | Meaning | Required action |
|---|---|---|
| `stop.response_registry.ingress_lineage_missing` | ingress lacks required emission ticket, read anchor, or stop-marker lineage | refuse admission or quarantine the ingress |
| `stop.response_registry.required_receipt_gap` | required `schema_codec` receipt/ticket/finding set is incomplete for the chosen cut | refuse visible success or hold until complete |
| `stop.response_registry.envelope_cut_mismatch` | materialized response envelope disagrees with the selected truth cut or receipt lineage | quarantine and require operator-visible action |
| `stop.response_registry.illegal_compression_loss` | render plan would erase exactness, freshness, refusal class, or prepared-vs-published distinction | refuse that render class and surface a typed refusal |
| `stop.response_registry.duplicate_delivery_conflict` | retry or redelivery would emit a different digest for the same request/delivery token | block redelivery and preserve both candidates for audit |
| `stop.response_registry.index_or_recall_gap` | required index rows or recall bindings are missing for a surface that promises them | block completion and preserve recovery markers |
| `stop.response_registry.live_archive_boundary_breach` | archive-backed material is being surfaced as live authority or live truth without the declared cut class | refuse or quarantine and emit a visible boundary violation |

No later law may demote one of these triggers into a dashboard warning,
adapter-local string, or best-effort comment.
If one fires, the result is a typed refusal, hold, rollback marker, or recovery
domains are active.

## 9. Records required by this law

The central data-structures map now requires:

- `ResponseEmissionIngressRecord`
- `ResponseScopeClassRecord`
- `ResponseTruthCutRecord`
- `ResponseReceiptJoinRecord`
- `ResponseCompressionPlanRecord`
- `ResponseRenderBundleRecord`
- `ResponseDeliveryCommitRecord`
- `ResponseIndexEntryRecord`
- `ResponseRecallBindingRecord`
- `ResponseEmissionRecoveryRecord`

These records sit beside the existing `schema_codec` receipt family and the existing
`ResponseEnvelopeRecord` canonical response language.
They are the typed runtime proof objects that `posix_filesystem_adapter`, `block_volume_adapter`, `control_plane`, `explanation_query`,
archived-era readers must consume.

## 10. Algorithms required by this law

The central algorithm map now requires:

- `declare_response_scope_and_render_classes()`
- `admit_response_emission_ingress_from_ticket_read_or_gate()`
- `derive_response_truth_cut_from_anchor_commit_or_refusal_state()`
- `join_required_schema_codec_receipts_findings_and_stop_markers()`
- `materialize_response_envelope_from_truth_cut_and_scope()`
- `compile_surface_or_carrier_compression_plan()`
- `assemble_render_bundle_or_binary_reply_candidate()`
- `commit_delivery_and_idempotent_request_completion()`
- `write_response_indexes_and_recall_bindings()`
- `recover_or_redeliver_inflight_response_emission()`

## 11. Whole-system operational paths added by this law

1. `control_plane` write or runbook route -> `publication_pipeline` emission ticket -> `response_registry` joins the
   required `schema_codec` receipts and one canonical response envelope ->
   `render.response_registry.control_plane_json_rpc.r2` plus indexed delivery commit -> `tidefsctl` or
   API caller receives one stable answer without local JSON folklore
2. `posix_filesystem_adapter` lookup/read or mutation result -> frozen read anchors or committed cut
   select `c1`, `c2`, or `c0` -> `response_registry` compiles `render.response_registry.posix_filesystem_adapter_wire.r0` ->
   Linux-facing errno/attrs/bytes are delivered without erasing exactness,
   freshness, refusal cause, or prepared-vs-published truth
   recall binding are reused -> one operator or archive bundle is rendered from
   the preserved `response_registry` chain instead of log scraping or tarball archaeology
4. xfstests run, scenario suite, perf run, or chaos campaign completes ->
   stable report structures enter `scope.response_registry.test_or_campaign.s7` -> `response_registry`
   binds the report to gate receipts, stop tickets, and artifact locators ->
   release/cutover surfaces consume one lawful summary grammar instead of tool-
   local summaries
5. shadow divergence, performance regression, chaos refusal, or cutover stop
   ticket fires -> `scope.response_registry.shadow_or_gate.s6` plus `c3.stop_or_refusal`
   materializes one refusal bundle and index chain -> `control_plane`, `truth_view`, and later
   recall surfaces all see the same blocker truth instead of local strings,
   dashboard-only state, or retry folklore

## 12. Acceptance effect on the design pack

With this law settled:

- `P3-03` becomes detailed enough for later implementation planning,
- the repo now has one explicit answer to how receipts, response envelopes,
  refusal classes, binary replies, structured bundles, indexes, and archive
  recall bindings are derived from committed or refused truth,
  share one response-runtime grammar instead of surface-local status stories,
- future adapter, dashboard, archive, and campaign work must now consume the
  explicit `response_registry` law rather than rediscovering truth after the fact,
- and the full production design ledger is now at `L3`, so later work is user-directed refinement or implementation discipline rather than missing seam/deletion law.
