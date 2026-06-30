# Successor Lockdown And Documentation Consolidation

Issue: #1580
Date: 2026-06-30
Status: current policy guardrail and TFR-019 consolidation map

TideFS is pre-alpha. OpenZFS/Ceph-class reliability and scale remain product
targets, not current capabilities.

This document binds two related controls:

1. Successor, superiority, and comparator wording must route through the
   registered claim system.
2. Documentation cleanup must route through TFR-019 classification instead of
   creating another status surface.

## Authority Boundary

The publishing-facing successor boundary is
`storage.intent.successor_comparator.v1` in `validation/claims.toml`.

Until that claim validates with fresh evidence manifests, TideFS documents,
release notes, generated claim text, operator output, issue closeouts, and PR
summaries must not say or imply that TideFS is a successor, replacement, or
superior alternative to OpenZFS, Ceph, DRBD, or local filesystems.

Allowed wording may describe:

- ambition and target class;
- blocked claim ids and missing evidence;
- historical design inputs from incumbent systems;
- bounded local claims that already validate under their own claim ids.

Disallowed wording includes:

- unqualified OpenZFS/Ceph-class fulfillment;
- average benchmark wins used as superiority permission;
- storage-intent row labels treated as product admission;
- release-ready, production-ready, GA-ready, or stable-release statements
  without a verdict artifact owned by
  `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.

## Successor Claim Gate

The successor comparator claim remains blocked until these evidence classes are
present and current:

- `storage-intent-comparator-equivalence-evidence`;
- `storage-intent-successor-performance-fault-set`;
- `storage-intent-successor-claim-boundary-review`;
- `storage-intent-operator-explanation-evidence`;
- `claims-gate-review`.

Normal implementation PRs do not have to prove this whole claim. They need the
focused validation named by their issue. Product-facing comparator evidence is
collected only at named product gates such as:

- `cargo run -p tidefs-xtask -- validate-claim <claim-id>`;
- proof-train packets under `docs/PRODUCT_ADMISSION_PROOF_TRAINS.md`;
- release-readiness verdict review under
  `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`;
- performance, fault, attribution, evidence-query, and service-objective
  matrices that are explicitly consumed by the claim registry;
- claim-boundary review manifests under `validation/artifacts/`.

If a PR touches product claims, successor wording, comparator baselines,
release-readiness wording, or evidence manifests, it must run the relevant
claim gate and preserve blocked status unless real evidence was added by the
same issue.

## Storage Intent Spine

`docs/STORAGE_INTENT_POLICY_AUTHORITY.md` is the design spine for successor
work. The key rule is that each successful acknowledgment must carry a named
guarantee receipt, and optimization must improve the path that earns that
receipt.

Labels are not authority. Media names, cache tiers, RAM-fast paths, remote
placement, prefetch success, RDMA availability, latency rows, and background
reclaim state do not upgrade an operation into a durability, availability,
freshness, or successor claim.

The successor claim may consume storage-intent work only after the consumed
surface records its own boundary, non-claims, evidence, and refusal behavior.

## Documentation Consolidation Law

Documentation consolidation is first-class product work because stale imported
material was the root cause of claim drift and low-value proof churn recorded
in `docs/WHOLE_REPO_REVIEW.md`.

The TFR-019 classification state remains the authority state from
`docs/DOCUMENTATION_AUTHORITY_REGISTER.md`:

- Current policy;
- Current spec;
- Historical input;
- Missing;
- Delete candidate.

Classification notes may also record a document handling role:

- Evidence-only: records authority evidence, old paths, retired crates,
  issue closeouts, or generated-state inputs without becoming a current status
  surface.
- Generated or derived: produced from registry/source data and not hand-edited
  as independent policy.

Evidence-only and generated/derived are roles, not extra authority states. A
document still needs exactly one TFR-019 state before it can be relied on.

## Consolidation Order

Use this order for documentation cleanup:

1. Keep the active entry path small: `README.md`, `AGENTS.md`, `docs/INDEX.md`,
   `docs/REVIEW_TODO_REGISTER.md`,
   `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, this document, and the specific
   policy/spec documents named by the active issue.
2. Classify before deleting. Promote only after checking live source behavior,
   `validation/claims.toml`, and the claims gate.
3. Collapse duplicate truth surfaces. Old status matrices, Forgejo-era
   coordination packets, closeout snapshots, and issue-era implementation
   plans should become historical input or delete candidates after useful
   content moves to current authority.
4. Keep generated outputs generated. `docs/CLAIM_REGISTRY.md` follows
   `validation/claims.toml`; it must not become hand-authored policy.
5. Treat broad design docs as review inputs until a focused issue classifies
   their exact scope.
6. Delete only after classification shows that useful content has moved or the
   file is obsolete scaffold/closeout material.

## Implementation Work Rhythm

TideFS work should move by focused product slices, not by asking each small PR
to prove the whole product.

For ordinary issue work:

- name the behavior, acceptance criteria, expected write set, and validation
  tier in the GitHub issue;
- run focused validation for the touched behavior;
- preserve non-claim language when the slice feeds a larger authority chain;
- avoid broad runtime or release-candidate gates unless the issue is a product
  gate.

For product gates:

- consume a named proof-train packet, claim id, verdict artifact, or validation
  manifest;
- list open gaps and residual non-claims;
- fail closed when evidence is missing, stale, malformed, or outside scope.

## Current Non-Claims

This document does not:

- validate `storage.intent.successor_comparator.v1`;
- declare TideFS release-ready, production-ready, or stable;
- close TFR-019;
- classify every imported document;
- prove OpenZFS, Ceph, DRBD, or local-filesystem successor behavior;
- prove RDMA, distributed availability, kernel-resident storage authority, or
  full mounted crash recovery.

It is a guardrail for how to finish that work without multiplying truth
surfaces or turning every implementation PR into a whole-product proof demand.
