# Nextgen Verification, Performance, and Offload Pointer

Maturity: bounded historical consolidation pointer, not live program
authority.

This document used to carry the integrated next-generation verification,
performance, offload, and follow-up issue map for closed issues #483, #1066,
and #1274. That roadmap state is now historical lineage. Current TideFS
verification authority lives in source, the claim registry, evidence artifact
schemas, validation policy, CI workflow documentation, and live GitHub issues
and pull requests.

Do not use this file as a roadmap, status register, issue-creation protocol,
claim closure record, release-readiness proof, or product-successor claim. Use
the smallest current authority below.

## Current Authority Surface

| Scope | Current authority |
| --- | --- |
| Claim publication and evidence gates | `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, and `cargo run -p tidefs-xtask -- check-claims-gate` |
| Documentation classification and stale-authority cleanup | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, `docs/REVIEW_TODO_POLICY.md`, and `docs/REVIEW_TODO_REGISTER.md` |
| Request/completion contract shape | `docs/REQUEST_CONTRACT.md`, `crates/tidefs-types-vfs-core`, and `crates/tidefs-schema-codec-vfs` |
| Trace artifact manifests | `docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md` and `crates/tidefs-trace-oracle/src/artifact_manifest.rs` |
| Generic evidence artifact manifests | `crates/tidefs-validation/src/evidence_artifact_manifest.rs`, `validation/claims.toml`, and the artifact manifests under `validation/artifacts/` |
| Validation tier labels | `crates/tidefs-validation/src/validation_schema.rs` and `docs/CLAIMS_GATE_POLICY.md` |
| Trace oracle behavior | `crates/tidefs-trace-oracle/README.md`, `crates/tidefs-trace-oracle/src/protocol.rs`, `crates/tidefs-trace-oracle/src/backend.rs`, and `crates/tidefs-trace-oracle/src/manifest.rs` |
| Crash-oracle, performance, offload, adapter, distributed, and two-node evidence | The owning crate sources, `validation/claims.toml`, current evidence manifests, and live issue/PR state for the exact slice |
| No-hidden-queue review | `validation/performance/no-hidden-queues.toml` and `cargo run -p tidefs-xtask -- check-no-hidden-queues` |
| CI validation workflow authority | `docs/GITHUB_CI.md` and the workflow files under `.github/workflows/` |

## Preserved Boundaries

The old nextgen map recorded conservative verification boundaries that remain
valid only through the current authority surfaces above:

- model-only evidence may diagnose source/model behavior, but it does not prove
  mounted runtime, crash, distributed, kernel, RDMA, or production behavior;
- harness-only evidence may diagnose harness behavior, but it does not close a
  higher-tier product claim unless the claim registry asks for that exact
  evidence class;
- runtime, kernel, distributed, performance, offload, and successor/comparator
  claims remain blocked until `validation/claims.toml` names the required
  evidence and `validate-claim` or the relevant gate records matching current
  artifacts;
- offload results are never storage semantics authority;
- publishing-facing docs must stay behind `docs/CLAIMS_GATE_POLICY.md` and the
  current claim registry.

Historical design decisions, rejected alternatives, child-issue maps, and PR
checklists from the retired roadmap remain available through git history and
closed GitHub issue/PR history. They are not active process authority.
