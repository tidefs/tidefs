# Release Readiness Verdict Contract

Issue: #1279
Date: 2026-06-24
Status: design decision; completed follow-up map recorded below

This document defines the release-readiness verdict boundary for TideFS.
It does not declare TideFS release-ready. It records where the verdict
authority lives, what evidence families it consumes, what remains explicitly
non-claimed, and how gate-local readiness receipts are distinguished from
whole-product admission.

## Purpose

TideFS has guardrails around release and product claims (`docs/CLAIMS_GATE_POLICY.md`,
`docs/UNRELEASED_AUTHORITY_POLICY.md`), a release-candidate evidence index
(`docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md`), and a performance-gate receipt
with a source-backed `perf_gate_ready` field in
`crates/tidefs-validation/src/performance_gate/`.
None of these documents is a whole-product release-readiness verdict. This
contract:

- names the verdict owner (who decides that TideFS is ready for a release),
- lists the evidence families a verdict must consume,
- draws the line between gate-local readiness receipts and whole-product admission,
- records explicit non-claims so no reader treats a gate receipt or evidence
  index as a release declaration, and
- maps the follow-up issues needed before any product admission claim can be made.

## Evidence Reviewed

- `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md` (2026-06-23): Explicitly states the
  release-candidate evidence index is a **gate input, not a gate verdict**. Records
  lane job results, artifact names, and path patterns without making a product-readiness
  claim. Follow-up notes document profile design decisions and artifact retention
  asymmetry.
- `docs/UNRELEASED_AUTHORITY_POLICY.md` (current policy guardrail): Requires current
  authority instead of preserving pre-release compatibility leftovers. Pre-release
  paths must not be named "legacy" and must not imply a product compatibility contract.
- `docs/CLAIMS_GATE_POLICY.md` (current policy guardrail): Publishing-facing docs must
  not present future capability as current product fact. Scans specific surfaces through
  `xtask check-claims-gate`. Claims are individually validated; no single claim or
  summary row acts as a product admission verdict.
- `crates/tidefs-validation/src/performance_gate/runner.rs`: Defines
  `GateReceipt.perf_gate_ready` as a gate-local receipt requiring subject
  completeness, at least one runtime validation row, zero artifact gap, and
  zero budget gap for the `performance_budget_0` matrix rows. It renders as
  `Performance gate: READY` or `Performance gate: NOT READY`, not as a
  whole-product release-readiness verdict.
- `docs/GITHUB_CI.md` (current): Describes the Release Candidate workflow as a
  manual-only self-hosted composition of Rust, Nix, QEMU smoke, xfstests, and RDMA
  lanes. The workflow uploads a `release-candidate-evidence-index` JSON artifact
  and does not make a product-readiness claim.
- `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md` (#1267): Records that no runtime-fed
  operator product surface exists, the P10-04 truth-surface law is missing, and no
  product carrier class is selectable until transport/cluster authority and the
  P10-04 gap close.
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` (TFR-019): Classifies existing
  release-facing documents and records the P10-04 missing-doc gap.
- `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`: Records the six required
  runtime-fed product-surface properties (runtime source data, source/cut
  headers, provenance/exactness/freshness, product carrier, render proof, and
  refusal behavior) and states none are satisfied.
- `README.md` and `AGENTS.md`: TideFS is pre-alpha. Claims must stay behind
  implementation reality. OpenZFS/Ceph-class target is aspirational.
- Bounded inspection of `crates/tidefs-validation/src/performance_gate/runner.rs`:
  `GateReceipt.perf_gate_ready` is computed as
  `m.has_runtime_validation() && invariant_holds && artifact_gap == 0 && budget_gap == 0`.
  The rendered report uses the scope-qualified `Performance gate:` label, so the
  receipt remains an input to this verdict boundary rather than a product
  admission signal.

## Compared Alternatives

### Alternative A: Extend the release-candidate evidence contract

Extend `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md` to also define the verdict
boundary.

**Assessment: Rejected.** That document's purpose is to describe how the Release
Candidate workflow produces and indexes evidence. It already states it is a
"gate input, not a gate verdict." Adding verdict language would blur that
boundary and confuse readers who need to distinguish evidence collection from
the decision that consumes it. The evidence index should remain an input
document, consumed by the verdict process defined elsewhere.

### Alternative B: Create a separate release-readiness verdict contract (selected)

Create `docs/RELEASE_READINESS_VERDICT_CONTRACT.md` as a focused policy
document that names the verdict owner, required evidence families, refusal
language, and the distinction between gate-local receipts and whole-product
admission.

**Assessment: Selected.** This is the cleanest separation. Each document keeps
one responsibility: the evidence contract describes the input, this verdict
contract describes the decision boundary. Gate-local receipts
(`perf_gate_ready`, claims-gate claim status, CI lane results) remain local
signals; the verdict contract is the only place that combines them into a
product admission decision. The document can be updated as evidence families
mature without rewiring the input documents.

### Alternative C: Keep verdict authority out of repo docs until a later milestone

Defer the verdict contract until more evidence families are implemented and the
product is closer to a real release decision.

**Assessment: Rejected.** Multiple documents already have readiness-adjacent
concepts. The `perf_gate_ready` field is in live source and rendered in
markdown with the scope-qualified `Performance gate: READY` or `Performance
gate: NOT READY` label. The claims gate scans for publishing-facing capability
statements. The release-candidate workflow produces an evidence index. Without
a verdict contract, a reader could reasonably interpret any of these as a
whole-product signal. Defining the boundary now costs little and prevents
misinterpretation during the pre-release period when the most evidence gaps
exist.

## Decision

### Verdict owner

The release-readiness verdict is not a single gate receipt, CI run, or claim
status row. It is a human-integrated decision that must consume the evidence
families listed below and must be recorded in a tracked GitHub issue or
equivalent artifact whose body names the consumed evidence runs, open gaps,
and explicit non-claims.

Until a release authority (maintainer, release engineer, or product owner) is
named, the verdict is **not claimed**. No automated gate, CI workflow, or
generated artifact may render "TideFS is release-ready" without that authority's
explicit recorded decision.

### Required evidence families

A release-readiness verdict must consume evidence from each active family.
Families that do not yet exist or are intentionally deferred must be recorded
as open gaps in the verdict artifact.

| Evidence family | Current input documents | Status as of 2026-06-24 |
|---|---|---|
| Release-candidate evidence index | `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md`, `release-candidate-evidence-index` artifact | Defined; smoke and full profiles exist; lane-local manifests (issues 643-646) are still absent |
| Claims gate | `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, `xtask check-claims-gate` | Enforced; individual claims validated; no product-admission claim exists |
| Performance budget gate | `crates/tidefs-validation/src/performance_gate/`, `GateReceipt` | Gate-local `perf_gate_ready` implemented; minimum suite families remain incomplete |
| Standing CI gate | `docs/GITHUB_CI.md`, Rust Fast, Nix Checks, Clippy, Secret Policy | Active on self-hosted runners; path-filtered for docs-only PRs |
| Operator truth surfaces | `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing), `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md` | P10-04 document does not exist; the current decision record keeps the six runtime-fed product-surface properties unsatisfied |
| Operator UAPI authority | `docs/OPERATOR_UAPI_AUTHORITY.md` | Pre-alpha command boundary is closed, but it does not create a runtime-fed product carrier |
| Transport/cluster authority | TFR-017 | Open; no current transport authority document |
| Unreleased authority | `docs/UNRELEASED_AUTHORITY_POLICY.md` | Current policy; enforced in review |
| Kernel residency evidence | `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`, QEMU smoke, kernel teardown | Narrow QEMU smoke exists; full-kernel, daemonless, crash/replay not yet covered |

### Gate-local vs whole-product admission

A gate-local readiness receipt is a signal scoped to one evidence family. A
whole-product admission verdict consumes all active families and records open
gaps explicitly.

| Concept | Scope | Example |
|---|---|---|
| Gate-local receipt | One evidence family or matrix | `GateReceipt.perf_gate_ready = true` means the performance budget rows pass; it does not mean TideFS is release-ready |
| Gate-local receipt | One evidence family or matrix | `validate-claim <id>` passing means that claim's evidence artifacts are present and valid; it does not validate other claims |
| Gate-local receipt | One evidence family or matrix | Release Candidate `smoke` profile passing means the narrow compose succeeded; it does not validate xfstests, RDMA, or distributed behavior |
| Whole-product admission | All active families, with open gaps recorded | A verdict artifact (GitHub issue or equivalent) consuming all evidence families, naming consumed runs and artifacts, and recording explicit non-claims |

### Refusal and non-claim language

The verdict contract requires that any document, artifact, or generated output
that could be read as a release-readiness signal must include refusal language.
The following terms are forbidden in any context that could imply whole-product
readiness unless accompanied by the verdict owner's recorded decision:

- "TideFS is release-ready"
- "release-ready" (unqualified; gate-local receipts must qualify with their
  scope, e.g., "performance-gate release-ready")
- "production-ready"
- "GA-ready"
- "stable release"

Gate-local receipts must use a scope-qualified field name or a scope-qualified
rendered label, for example `perf_gate_ready` and `Performance gate: READY`.
They must not render an unqualified "READY" / "NOT READY" string that can be
misread as a whole-product verdict.

### What is explicitly not claimed

This contract records that as of 2026-06-24:

- TideFS is **not** release-ready. No release-readiness verdict exists.
- The `GateReceipt.perf_gate_ready` field is a **performance-gate-local**
  receipt, not a whole-product admission claim.
- The Release Candidate workflow produces an **evidence index**, not a verdict.
- The claims gate validates individual claims; no claim or summary row acts as
  a product admission signal.
- The missing P10-04 truth-surface law means the production truth grammar is
  undefined (see #1270 for P10-04 disposition).
- No runtime-fed operator product surface exists (see #1267).
- TFR-017 (transport/cluster authority) remains open, and the closed pre-alpha
  operator/UAPI command boundary does not create a runtime-fed product carrier.

## Completed Follow-Up Issue Map

The original follow-up issues were intentionally non-overlapping. They are
recorded here as closure evidence, not as remaining work. Cross-reference
additions for the release candidate evidence contract, performance gate,
GITHUB_CI.md,
and INDEX.md were completed by #1279 and are not listed separately.

| Issue | Expected write set | Scope |
|---|---|---|
| #1283 | `crates/tidefs-validation/src/performance_gate/runner.rs`, `crates/tidefs-validation/src/performance_gate/consolidation.rs`, `xtask/tidefs-xtask/src/main.rs` | Completed the performance-gate rename from `release_ready` to `perf_gate_ready` and updated `GateReceipt::render_markdown()` so the rendered label is gate-local. |
| #1284 | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` | Completed rows for the release-facing evidence-input documents named by this contract. |

## Non-Overlap with #1270

Issue #1270 owns the P10-04 truth-surface law disposition: classifying the
missing `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` reference
in the documentation authority register and updating cross-references in the
~10 documents that cite P10-04. This contract references P10-04 only as an
evidence-family gap in the required-evidence table and in the explicit
non-claims section. It does not classify P10-04, update P10-04 cross-references
in other documents, or resolve the missing-truth-grammar gap.

## Implementation Boundary

This document does not edit FUSE, POSIX adapter, snapshot send/receive,
storage-node runtime, GitHub workflow, `validation/claims.toml`, generated
claim registry files, or Rust source code. The follow-up issue map above names
the expected write sets for implementation slices.

## Validation For This Slice

Documentation/design validation only:

- Bounded source/doc inspection across the evidence documents listed above.
- `git diff --check` on the resulting documentation diff.
- No local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, xfstests, or
  broad GitHub Actions validation is required for this design slice.
