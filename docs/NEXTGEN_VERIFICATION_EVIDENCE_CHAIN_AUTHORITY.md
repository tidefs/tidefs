# Nextgen Verification Evidence Chain Authority

Maturity: current design authority for issue #751 and the TFR-021 evidence
chain decision.

This document decides how the request contract, trace oracle, crash oracle,
performance contract, adapter environment models, distributed model checks,
and offload evidence feed one claims-gate evidence chain. It is a
documentation authority slice only. It does not validate new claims, change
runtime behavior, or close crash, performance, adapter, kernel, distributed,
RDMA, or offload evidence gaps by itself.

## Decision

The single evidence-chain owner is the claims gate:

- `validation/claims.toml` is the editable claim registry and evidence
  requirement spine.
- `xtask validate-claim <id>` is the command authority that decides whether a
  registered claim is validated, blocked, planned, or invalid for the current
  evidence set.
- `docs/CLAIMS_GATE_POLICY.md` remains the policy authority for claim wording,
  validation tiers, and fail-closed behavior.

`docs/CLAIM_REGISTRY.md` is not the editable evidence-chain spine. It is a
generated projection from `validation/claims.toml` and must remain generated
output.

TideFS should not create a second unified claim registry. The unified format
must extend the existing reusable evidence-manifest and receipt path:

- `crates/tidefs-validation/src/evidence_artifact_manifest.rs` owns the common
  evidence artifact manifest schema and validation.
- `crates/tidefs-validation/src/validation_schema.rs` and
  `validation_status.rs` own the shared tier and outcome vocabulary.
- `crates/tidefs-claim-ledger` may record append-only receipt integrity for
  stored evidence, but receipt integrity does not decide claim status.

## Evidence Chain

Every nextgen evidence producer feeds this chain:

1. `validation/claims.toml` declares the claim id, scope, required evidence
   classes, required validation tiers, artifact paths, and blocking issues.
2. A producer creates a reviewable artifact plus a common evidence manifest.
3. Optional receipt plumbing records append-only integrity for the manifest or
   artifact digest.
4. `xtask validate-claim <id>` verifies that every required evidence class is
   present, fresh, tier-compatible, and non-blocking.
5. `docs/CLAIM_REGISTRY.md` is regenerated from the registry. It reports the
   result; it is not edited by hand.

Any missing, stale, malformed, lower-tier, mismatched, unresolved-blocker, or
non-pass evidence fails closed. Lower-tier evidence may diagnose a claim but
cannot close a higher-tier claim.

## Common Evidence Format

Each claim evidence record must use `EvidenceArtifactManifest`
`manifest_version = 2` and carry these fields:

| Field | Authority rule |
| --- | --- |
| `claim_id` | Must match a claim in `validation/claims.toml`. |
| `evidence_class` | Must match one required evidence class for that claim. |
| `validation_tier` | Must use the canonical `ValidationTier` vocabulary. |
| `scope` | Must name the bounded behavior, workload, model, or runtime path covered. |
| `artifact_path` and `content_digest` | Must identify the workspace-relative artifact path and machine-checkable BLAKE3 digest. |
| `run_id` | Must name the GitHub Actions run id/attempt or deterministic fixture/model run id. |
| `source_ref` | Must name the commit SHA or source ref that produced the artifact. |
| `outcome` | Must use the shared validation outcome vocabulary: pass, product fail, harness fail, environment refusal, or skip. |
| `residual_risk` | Must state the limits that remain after the evidence, especially model-only or harness-only boundaries. |
| `source` | Must name the crate, workflow, or tool that emitted the artifact. |
| `generated_at` | Must be a reviewable generated timestamp. |
| `blocking_issues` | Must explicitly list unresolved issues that keep the evidence from closing the claim, or an empty list when none are known. |

Version-1 manifests are retired pre-standardization input: they may remain
useful for review or historical comparison, but `validate-evidence-manifest`
must reject them for future claim closure because they can hide run identity,
source ref, outcome, residual risk, or blocking issue state in ad hoc strings.
Producers that still emit version-1 manifests must regenerate version-2
records before their artifacts can satisfy claim evidence.

## Producer Rules

| Surface | How it feeds the chain | Boundary |
| --- | --- | --- |
| Request contract | Names the semantic request/completion vocabulary and contract version used by evidence. | It is contract-shape authority, not runtime proof. |
| Trace oracle | `crates/tidefs-trace-oracle` emits trace replay/comparison artifacts and manifests through issue #731. | Model-only or harness-only traces do not close runtime crash claims. |
| Crash oracle | `crates/tidefs-crash-oracle` emits model crash matrices and runtime crash reports. | Model matrices and runtime crash artifacts remain distinct evidence classes. |
| Performance contract | `crates/tidefs-performance-contract`, no-hidden-queue checks, and workflow artifacts emit workload, budget, baseline, and outcome evidence. | Performance claims require workload envelope, environment profile, comparator or baseline policy, measurement vector, budget decision, and receipt. |
| Adapter environment models | FUSE and uBLK models emit model-tier manifests through issue #811. | Adapter models prove translation/lifecycle constraints only; adapters do not own filesystem semantics. |
| Distributed model check | `crates/tidefs-distributed-model-check` emits bounded model manifests through issue #811. | Model receipts do not prove storage-node, transport, multi-process, production cluster, RDMA, or runtime behavior. |
| Offload boundary | Offload descriptors, CPU reference checks, and completion validation feed non-authoritative performance evidence. | Offload can improve cost only; storage correctness must pass when offload is absent. |
| Claim ledger | `ValidationReceiptLedger` proves stored receipt order and mutation resistance. | Receipt integrity is evidence integrity only; it is not claim-status authority. |

No producer may define a parallel claim status, a parallel trace/crash registry,
or a separate adapter-specific evidence system. Producers emit artifacts and
manifests; the claims gate decides.

## Follow-up Issue Map

These implementation issues close the TFR-021 integration gap without
overlapping producer lanes:

| Issue | Purpose | Expected write set |
| --- | --- | --- |
| #809 `evidence-chain-format: standardize common claim evidence fields` | Extend the reusable evidence manifest with explicit run id, source ref, outcome, and residual risk fields. | `crates/tidefs-validation/src/evidence_artifact_manifest.rs`, focused `xtask` validator plumbing, one reference producer if needed, narrow docs. |
| #810 `claims-gate-spine: consume unified evidence manifests for claim closure` | Make `validate-claim` consume the unified manifests and optional receipt integrity when deciding claim closure. | `xtask/tidefs-xtask/src/**`, `crates/tidefs-validation/**` helper APIs, `crates/tidefs-claim-ledger/**` receipt helpers, `validation/claims.toml`, narrow docs. |
| #811 `adapter-model-evidence-chain: emit unified model evidence manifests` | Feed FUSE, uBLK, and distributed model evidence into the common manifest format without claiming runtime proof. | `crates/tidefs-env-fuse-model/**`, `crates/tidefs-env-ublk-model/**`, `crates/tidefs-distributed-model-check/**`, `validation/artifacts/{fuse,ublk,distributed}/**`, claim references only for real model evidence. |
| #731 `trace-oracle-artifacts: emit schema manifests for replay outputs` | Feed trace replay and comparison outputs into the common trace artifact manifest path. | `crates/tidefs-trace-oracle/**`, `xtask/tidefs-xtask/src/trace_oracle.rs`, narrow trace docs. |
| #596 `verification-runtime: record rename crash runtime artifact` | Provide a real runtime crash artifact for the rename claim. | `crates/tidefs-crash-oracle/**`, `validation/artifacts/crash-oracle/**`, claim status only if all evidence is fresh. |
| #720 `perf/no-hidden-queues: gate active rename and orphan-index metadata mutations` | Provide the performance/admission evidence needed by affected rename claims. | `crates/tidefs-local-filesystem/**`, `crates/tidefs-orphan-index/**`, `crates/tidefs-performance-contract/**`, `validation/performance/no-hidden-queues.toml`, `validation/artifacts/performance/**`. |
| #643, #644, #646 | Feed xfstests, kernel fsync, and RDMA workflow artifacts into evidence manifests. | Their workflow-specific expected write sets only; shared schema work belongs to #809. |
| #671 | Publish a release-candidate evidence index that consumes lane-local manifests. | `.github/workflows/release-candidate.yml` and user-facing CI docs only if needed. |

TFR-021 remains an implementation program until these lanes land. This document
closes the owner and format decision: the claims gate is the single evidence
owner, `validation/claims.toml` is the spine, and common evidence manifests are
the producer format.
