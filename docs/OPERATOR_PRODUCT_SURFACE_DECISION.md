# Operator Product Surface Decision

Issue: #1267
Date: 2026-06-24
Status: design decision for follow-up issue mapping

This decision records the current runtime-fed operator product-surface
boundary after the OW-307D blocker map. It does not implement a product
surface, widen publishing claims, or preselect a runtime carrier.

## Evidence Reviewed

- `README.md`: TideFS is pre-alpha; the OpenZFS/Ceph-class target is
  aspirational, not a present-tense capability claim.
- `AGENTS.md`: Product bar says claims must stay behind implementation
  reality.
- `docs/CLAIMS_GATE_POLICY.md`: Publishing-facing docs must not present
  future capability as current product fact. The claims gate enforces
  this through `check-claims-gate`.
- `validation/claims.toml`: No claim for operator product surface exists.
  Registered claims are filesystem-scoped (crash safety, rename atomicity,
  page-cache writeback, kernel teardown, distributed combined safety
  model). The combined safety claim is bounded model-check evidence only.
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`:
  `docs/DISTRIBUTED_OPERATOR_PRODUCT_SURFACE_BLOCKER_MAP_OW307D.md` is
  classified as Historical input. The register states the parent OW-307
  gate remains open and a runtime-fed operator product surface is not yet
  present.
- `docs/DISTRIBUTED_OPERATOR_PRODUCT_SURFACE_BLOCKER_MAP_OW307D.md`:
  Records typed distributed operator truth rows (OW-307A), deterministic
  demo rows (OW-307B), summary rows (OW-307C), and source/cut/provenance/
  exactness/freshness headers (OW-307E) as implementation-tracked
  non-release building blocks. Explicitly states that deterministic demo
  output is not a production operator product. Lists six required product
  properties (runtime source data, source/cut headers,
  provenance/exactness/freshness, product carrier, render proof, refusal
  behavior) and records that none are satisfied.
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`: **Does not
  exist in the repository.** Referenced by OW-307D as the production truth
  grammar and by at least ten other documents as the truth-surface law
  defining mandatory surface classes, provenance/exactness/freshness
  rendering, carrier verification, and the `truth_view` concept. The
  missing file is a critical gap: the production truth grammar the
  OW-307D blocker map depends on is undefined.
- `docs/OPERATOR_UAPI_AUTHORITY.md`: Design decision #656 records the
  pre-alpha operator UAPI boundary. Cluster pool creation is prototype-only.
  Cluster placement/heal exercises are development diagnostics. Explicit
  non-claims preserve that the decision is not a production ioctl/statx/
  ublk/FUSE ABI freeze, not kernelspace readiness evidence, not distributed
  operator maturity evidence, and does not wire runtime-fed remote policy
  authority. Issue #1278 later closed the current pre-alpha command-boundary
  follow-up map without selecting a runtime-fed product carrier.
- `docs/USER_MANUAL.md`: Describes the pre-alpha userspace filesystem.
  Lists known limitations including no mmap, no online device replacement,
  no network transport for send/receive, no automated self-healing. No
  operator dashboard or product surface described.
- `docs/REVIEW_TODO_REGISTER.md`: the operator/UAPI closeout notes are closed
  for the current pre-alpha command boundary. TFR-017 (Transport/cluster
  authority) remains open and still blocks runtime-fed distributed product
  surfaces.
- `docs/WHOLE_REPO_REVIEW.md`: Reports that the OW-307D blocker map says
  deterministic demo rows do not prove a production operator surface.
- Bounded `rg` inspection for `DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES`,
  `truth_view`, runtime-fed operator surfaces, render receipts, and
  product carriers: The P10-04 document is referenced by
  deleted P3 receipt/response production-depth lineage,
  `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`,
  deleted performance/fault production-depth lineage,
  deleted kernel-boundary production-depth lineage,
  `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`,
  `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`, deleted
  operator-manual lineage docs, and deleted scrub/repair/resilver historical
  lineage docs.
  All references treat it as an existing law document; none of them
  reproduce its content. The `truth_view` glyph appears as the OW-307
  identifier across these documents.

## Compared Alternatives

### Alternative A: Restore a missing/current P10-04 truth-surface law

The P10-04 document does not exist and its intended content is unknown
beyond the OW-307D property table and cross-reference descriptions.
Creating a substitute would invent product policy the repository has
not previously defined. The document is referenced as law-level
authority by surviving historical P-series lineage and deleted
fault/performance roots. Restoring it would
require reconstructing the truth-surface grammar, mandatory surface
classes, carrier verification rules, and `truth_view` rendering
contract from secondary descriptions alone. This exceeds the scope of
a decision boundary and would create fake authority.

**Rejected**: The document cannot be restored without access to its
original content. Recording its absence is the correct first step.

### Alternative B: Create a successor operator-product-surface decision

This decision document serves as the successor. It records the current
boundary, preserves OW-307D as historical input, maps follow-up work,
and records explicit non-claims. This is the chosen alternative.

### Alternative C: Keep OW-307D historical while mapping new work elsewhere

OW-307D is already classified as Historical input in the documentation
authority register. This decision preserves that classification while
creating a forward path through follow-up issues. The OW-307A/B/C/E
building blocks (typed rows, deterministic demo rows, summaries,
headers) remain implementation-tracked non-release; they are not
reclassified by this decision.

### Alternative D: Stop and split because the surface is premature

The evidence confirms the surface is premature for any product carrier
implementation. No live distributed storage runtime feeds operator rows.
No runtime mirrors or receipt-backed source classes exist. TFR-017 remains
open. However, recording the decision boundary and
follow-up map is useful even without implementation: it prevents future
work from treating deterministic demo output as a production operator
product and defines the prerequisites that must close before any carrier
work begins. This document records that split.

## Decision

The runtime-fed operator product surface boundary is:

1. **No runtime-fed operator product surface exists.** The OW-307A/B/C/E
   building blocks provide typed truth rows, deterministic demo rows,
   summaries, and source/cut/provenance/exactness/freshness headers, but
   no live distributed storage runtime or admitted runtime mirror feeds
   them. The control-plane daemon prints bounded demo output only.

2. **The production truth grammar is undefined.** The P10-04 document
   (`docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`) referenced
   by OW-307D and ten other documents as the truth-surface law does not
   exist in the repository. Until this gap is resolved, no carrier can
   claim to render truth-surface-compliant operator data.

3. **No product carrier class is selectable now.** The current pre-alpha
   operator/UAPI command boundary is closed, but it is not a product carrier.
   TFR-017 transport/cluster authority and the missing P10-04 truth grammar
   must close before any carrier (CLI, API, dashboard, archive-reader) can be
   selected or implemented.

4. **OW-307D remains Historical input.** Its classification in
   `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` is preserved. The OW-307
   parent gate remains open.

5. **The next feasible carrier class is CLI/status**, but only after the
   prerequisite closure described in the follow-up issue map. A CLI
   carrier can consume the existing typed rows and summary helper, render
   source-classified status with explicit non-live framing, and fail
   closed when no live owner is reachable. Dashboard, API, and
   archive-reader carriers require additional runtime infrastructure
   (live mirrors, receipt-backed sources, render pipelines) that does not
   exist.

## Carrier Class Assessment

| Carrier class | Plausible next? | Prerequisites |
| --- | --- | --- |
| CLI/status | Plausible after prerequisite closure | TFR-017 decision, P10-04 disposition, live-owner routing audit, and proof that the command boundary has a runtime-fed carrier |
| API | Not plausible | Requires live runtime mirrors, receipt-backed source classes, and transport authority that do not exist |
| Dashboard | Not plausible | Requires API carrier or equivalent backend, render pipeline, and refusal behavior paths |
| Archive-reader | Not plausible | Requires runtime-fed receipts, render bundles, and archive format authority |
| No product carrier | Current state | Deterministic demo output is the only visible surface; it is not a product carrier |

## Non-Claims

- Deterministic demo rows, source markers, screenshots, raw stdout, and
  historical blocker maps are not runtime-fed product evidence.
- The existing OW-307A/B/C/E building blocks are implementation-tracked
  non-release; they do not become production operator truth by being
  referenced from this decision.
- This decision does not implement a dashboard server, long-running
  operator CLI, API product surface, runtime placement/health/rebuild/risk
  mirrors, or any distributed storage behavior.
- This decision does not close TFR-017, TFR-019, or parent OW-307.
- This decision does not reclassify OW-307D or any other historical-input
  document as current policy or current spec.
- This decision is not a publishing-facing capability claim and does not
  change `validation/claims.toml` or the generated claim registry.

## Follow-Up Issue Map

Each follow-up is intentionally non-overlapping. Each should cite this
decision and keep its expected write set within the listed paths unless
the issue body is updated before work starts.

| Topic | Expected write set | Scope |
| --- | --- | --- |
| P10-04 disposition: classify the missing truth-surface law reference and update cross-referencing documents | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, cross-reference notes in the ten documents that reference P10-04, `docs/REVIEW_TODO_REGISTER.md` | Record that `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` is missing; either create a placeholder recording its absence or add a register row explaining the gap. Update cross-references so future readers are not misled into treating a missing document as existing authority. |
| TFR-017 transport/cluster authority decision | `docs/TRANSPORT_CLUSTER_AUTHORITY.md` or successor, `docs/REVIEW_TODO_REGISTER.md` | Define transport authority, cross-replica comparison, dispatch, and backpressure semantics before any carrier can consume runtime cluster data. |
| Documentation authority register: classify this decision | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, `docs/REVIEW_TODO_REGISTER.md` | Add a row classifying `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md` as current policy and updating operator/UAPI and TFR-019 notes. |
| INDEX.md: add this decision | `docs/INDEX.md` | Add this decision document to the documentation index. |

## Implementation Boundary

This document does not edit FUSE, POSIX adapter, snapshot send/receive,
storage-node runtime, GitHub workflow, `validation/claims.toml`, or
generated claim registry files. If the evidence shows those paths must
change, the follow-up issue map above names the expected write sets.

## Validation For This Slice

Documentation/design/source-inspection only:

- Bounded source/doc inspection with `rg` for the evidence terms and
  referenced docs named above.
- `git diff --check` on the resulting documentation diff.

No local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, xfstests, or
broad GitHub Actions validation is required for this design slice.
