# Operator UAPI Authority

Issue: #656
Date: 2026-06-20
Status: design decision for follow-up implementation and documentation slices

This document records the operator-facing UAPI boundary for the current
TideFS pre-alpha command surface. It decides how `tidefsctl` command classes,
live-owner routing, admission, diagnostics, prototype cluster commands, and
preview kernel/FUSE/ublk surfaces relate. It does not implement command
behavior, reclassify imported documents, edit the preview UAPI document, or
claim release readiness.

## Evidence Reviewed

- `docs/REVIEW_TODO_REGISTER.md` TFR-011 records that CLI, FUSE, ublk,
  kernel UAPI, and docs can describe different truths. The current notes say
  issue #239 added a `tidefsctl` local-only admission table, issue #243 moved
  FUSE cluster admission to typed mount authority, and issue #278 checked the
  preview UAPI doc, book chapter, operator-authz boundary, and claims gate
  against the command classification/admission table. TFR-011 remains open
  until operator surface, live-owner routing, cluster diagnostics/
  authorization, and kernel UAPI authority are one reviewed boundary.
- `docs/REVIEW_TODO_REGISTER.md` TFR-019 records that imported documents are
  not release truth until classified as current policy, current spec,
  historical input, or delete candidate. The #337 note classifies the preview
  UAPI doc only for the checked `tidefsctl` table and current non-release VFS
  codec hooks; it explicitly does not close full-kernel, broader operator
  UAPI, kernel residency, storage authority, block-volume, xfstests,
  crash-recovery, distributed, or documentation drift debt.
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` makes the authority rule explicit:
  imported documents are review inputs until classified. It classifies
  `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md` as current spec only for the
  checked `tidefsctl` command classification/admission table and current
  non-release VFS fixed-width codec hook description.
- `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md` declares marker
  `tidefsctl-command-classification-v1`, points at
  `apps/tidefsctl/src/commands/classification.rs` as the command
  classification source, and states that the preview boundary is not a
  production Linux ioctl, statx, or ublk ABI freeze and is not kernelspace
  readiness evidence.
- `apps/README.md` classifies `apps/tidefsctl`, the FUSE adapter daemon, the
  block-volume adapter daemon, scrub, and storage-node as bounded userspace
  entrypoints. It states that FUSE, ublk, storage-node, scrub, and CLI behavior
  still require issue-scoped validation before release-facing wording can rely
  on them.
- `apps/tidefsctl/src/commands/classification.rs` is the current command
  class, routing, help-visibility, and summary registry for public operator,
  userspace harness, operator diagnostic, prototype, development diagnostic,
  and removed command classes. `root_long_about()` renders help from this
  registry.
- `apps/tidefsctl/src/commands/authz.rs` is the current privileged-admission
  registry. It maps command paths to `local-only`, `local-only-when-mutating`,
  or `unguarded`, checks that admission entries point at registered command
  surfaces, and checks the operator authz boundary table against the registry.
- `apps/tidefsctl/src/commands/live_owner.rs` is the current live-owner routing
  helper. It treats a pool name as an imported-pool identity, refuses to reopen
  cached imported state behind an unreachable owner, and source-classifies
  status refusals when no live evidence is available.
- Current operator entrypoints show the boundary split in code:
  `tidefsctl pool`, `device`, `block`, `dataset`, and `snapshot` route live
  imported state through the owner or require explicit offline/exported inputs;
  `tidefsctl diag` emits source-qualified support evidence; `tidefsctl kernel
  status` is a passive probe that does not issue ioctls; `cluster status`
  fails closed without a live owner; `cluster pool create` is a prototype; and
  `cluster placement/heal exercise` are development diagnostics.
- `apps/tidefs-storage-node/README.md` records a runtime authority spine for
  storage-node internals, but still says several repair, convergence,
  orchestration, degraded-read, and reclaim publications are separate work.
  This is implementation evidence, not final distributed operator maturity.
- `xtask/tidefs-xtask/src/claims.rs`, `docs/CLAIMS_GATE_POLICY.md`,
  `docs/book/chapters/10-tidefsctl.adoc`, and
  `docs/security/operator-authz-boundary.md` already consume the command
  classification/admission table and reject unframed claims that cluster
  prototypes or development exercises are final distributed operator UAPI.

## Compared Authority Models

### Model A: code registry as the command authority

`apps/tidefsctl/src/commands/classification.rs` owns command class, routing,
help visibility, and summary text. `apps/tidefsctl/src/commands/authz.rs` owns
privileged admission. Docs, book text, support bundles, and claims checks
consume or check those registries.

Strengths:

- Matches current source and tests.
- Keeps help text, diagnostics, book text, preview UAPI table, and claims-gate
  policy from drifting into separate command lists.
- Makes command changes visible in code review at the same point where parser
  and handler behavior changes.

Limits:

- The code registry is command-surface authority only. It does not promote
  preview VFS codecs, FUSE behavior, ublk behavior, kernel ioctls, or
  distributed operation into production ABI authority.
- The registry cannot by itself classify imported design documents. TFR-019
  document classification remains a separate docs authority process.

### Model B: docs/spec as the command authority checked by code

A doc or spec table would be the primary command surface. Code would be
generated from, or checked against, that document.

Strengths:

- Good fit for a future release ABI freeze after the command contract is
  stable and the production operator protocol exists.
- Makes human-facing design review naturally primary.

Limits:

- Not a safe current authority because TFR-019 still says imported docs are
  review inputs until classified.
- The preview UAPI document is deliberately scoped to the existing checked
  table and non-release VFS codec hooks. Making it primary would give a
  preview doc more authority than it claims.
- It would make command behavior depend on a broader documentation surface
  before live-owner routing, remote authorization, kernel UAPI, and cluster
  operator maturity are complete.

### Model C: separate registries for public, diagnostic, harness, and prototype
classes

Each command class would have a separate registry and possibly separate
generated docs.

Strengths:

- Gives each audience a smaller table.
- Could support future independent release gates for public operator commands,
  diagnostics, harnesses, and prototypes.

Limits:

- High drift risk today because routing and admission semantics cross class
  boundaries.
- Would duplicate checks already centralized by `COMMAND_SURFACES` and
  `command_admission`.
- Separate registries would make it easier for prototypes or diagnostics to
  inherit public operator wording accidentally.

## Decision

Use Model A now: the `tidefsctl` code registry is the current command-surface
authority, checked by documentation and claims-gate consumers. Preserve Model C
as a class split inside the one registry rather than as separate source files.
Do not use Model B until a future release/freeze issue creates a production
operator protocol or ABI source and updates code generation or checks around
that source.

This decision defines the current operator boundary as follows.

| Boundary | Decision |
| --- | --- |
| Command class | Every `tidefsctl` surface must be in `COMMAND_SURFACES` with exactly one of `public-operator`, `userspace-harness`, `operator-diagnostic`, `prototype`, `development-diagnostic`, or `removed-or-unsupported`. |
| Routing | `live-owner` means the command must use the reachable owner endpoint for imported live state and fail closed when no live evidence exists. `live-owner-or-offline-input` allows explicit exported/not-yet-imported device inputs, but cached imported metadata is not live truth. |
| Admission | Mutating public operator commands remain `local-only` or `local-only-when-mutating` until remote principal/session/authz wiring is product-grade. Read-only commands, diagnostics, prototypes, development exercises, and removed hidden surfaces may be `unguarded` only when their class and summary preserve the weaker claim. |
| Visibility | Root help is generated from the registry. Removed or unsupported surfaces are hidden and fail closed. Prototype and development-diagnostic surfaces may remain visible only when their class, routing, and summary say they are not final operator UAPI. |
| Diagnostics | Diagnostics are evidence collection, not storage authority. `diag` must preserve source labels such as command classification registry, passive probe, offline device scan, live owner, and unavailable. `kernel status` remains passive until a production kernel UAPI issue wires real control operations. |
| Live-owner status | `cluster status` and `device status` are public operator status commands only when a live owner is reachable. Without one, they must source-classify the refusal instead of presenting cached or static data as live status. |
| Cluster prototypes | `cluster pool create` remains `prototype` and `prototype-only`. `cluster placement exercise` and `cluster heal exercise` remain `development-diagnostic` and `development-exercise`. Storage-node runtime authority spine work may inform follow-ups, but it is not final distributed operator UAPI. |
| Kernel/FUSE/ublk preview surfaces | The current preview UAPI doc remains current spec only for the checked `tidefsctl` table and non-release VFS codec hooks. FUSE and ublk adapter entrypoints remain operator/harness surfaces that need issue-scoped runtime evidence before any release-facing claim can rely on them. |
| Documentation authority | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` remains the authority for document classification. A command appearing in current code does not make an unclassified imported doc current policy or current spec. |

## Non-Claims Preserved

- This decision is not a production Linux ioctl, statx, ublk, FUSE, or
  kernel-module ABI freeze.
- This decision is not kernelspace readiness evidence and does not claim
  full-kernel operation.
- This decision is not distributed operator maturity evidence and does not
  make cluster pool prototypes or placement/heal exercises final distributed
  operator UAPI.
- This decision does not wire runtime-fed remote policy authority. Privileged
  operator mutation remains local-only until a separate issue wires principal,
  session, authorization decision, audit, and live-owner routing into each
  privileged handler.
- This decision does not close TFR-011, TFR-017, TFR-019, block-volume
  runtime validation, FUSE runtime validation, xfstests, crash-recovery, RDMA,
  or release claims.

## Follow-Up Issue Map

These follow-ups are intentionally non-overlapping. Each should cite this
decision and keep its expected write set within the listed paths unless the
issue body is updated before work starts.

| Topic | Follow-up issue | Expected write set | Scope |
| --- | --- | --- | --- |
| Command-registry enforcement | [#657](https://github.com/tidefs/tidefs/issues/657) | `apps/tidefsctl/src/commands/classification.rs`, `apps/tidefsctl/src/commands/authz.rs`, `apps/tidefsctl/src/main.rs` | Strengthen registry/admission invariants and help rendering checks without changing command behavior. |
| Doc and claims-gate coverage | [#658](https://github.com/tidefs/tidefs/issues/658) | `xtask/tidefs-xtask/src/claims.rs`, `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, `docs/CLAIM_REGISTRY.md` | Decide whether this decision artifact should be scanned by the claims gate and update generated claim text if needed. |
| Live-owner routing | [#659](https://github.com/tidefs/tidefs/issues/659) | `apps/tidefsctl/src/commands/live_owner.rs`, `apps/tidefsctl/src/commands/pool.rs`, `apps/tidefsctl/src/commands/device.rs`, `apps/tidefsctl/src/commands/block.rs`, `apps/tidefsctl/src/commands/dataset.rs`, `apps/tidefsctl/src/commands/snapshot.rs` | Audit live-owner routing and source-classified refusals for public operator commands. |
| Preview-UAPI cross-references | [#660](https://github.com/tidefs/tidefs/issues/660) | `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`, `docs/book/chapters/10-tidefsctl.adoc`, `docs/security/operator-authz-boundary.md` | Cross-reference this decision from the checked preview UAPI, book, and authz docs without widening the preview UAPI scope. |
| Documentation-authority classification | [#661](https://github.com/tidefs/tidefs/issues/661) | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, `docs/REVIEW_TODO_REGISTER.md`, `docs/INDEX.md` | Classify this decision artifact and update TFR-011/TFR-019 notes after the decision lands. |
| Cluster diagnostic/prototype separation | [#662](https://github.com/tidefs/tidefs/issues/662) | `apps/tidefsctl/src/commands/cluster.rs`, `crates/tidefs-cluster/src/pool_orchestrator.rs`, `apps/tidefs-storage-node/README.md`, `apps/tidefs-storage-node/src/authority_spine.rs` | Keep cluster pool prototype and placement/heal development diagnostics separate from public live-owner cluster status. |

## Validation For This Slice

This issue is documentation/design only. Validation is bounded to:

- source inspection of the evidence listed above;
- `git diff --check`.

No local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, or xfstests
validation is required for this decision. Because this slice does not add a
structured policy check, it does not require a Focused Rust dispatch for
`tidefs-xtask`.
