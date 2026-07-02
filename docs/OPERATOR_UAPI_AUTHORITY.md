# Operator UAPI Authority

Issue: #656
Date: 2026-06-20
Status: current pre-alpha boundary; operator/UAPI one-boundary closeout complete

This document records the operator-facing UAPI boundary for the current
TideFS pre-alpha command surface. It decides how `tidefsctl` command classes,
live-owner routing, admission, diagnostics, prototype cluster commands, and
preview kernel/FUSE/ublk surfaces relate. It does not implement command
behavior, reclassify imported documents, edit the preview UAPI document, or
claim release readiness.

## Evidence Reviewed

- `docs/REVIEW_TODO_REGISTER.md` previously recorded that CLI, FUSE, ublk,
  kernel UAPI, and docs can describe different truths. The current notes say
  issue #239 added a `tidefsctl` local-only admission table, issue #243 moved
  FUSE cluster admission to typed mount authority, issue #278 checked the
  preview UAPI doc, book chapter, operator-authz boundary, and claims gate
  against the command classification/admission table, and issue #1278 closes
  the current pre-alpha one-boundary decision after rechecking the #656
  through #662 follow-up map.
- `docs/REVIEW_TODO_REGISTER.md` TFR-019 records that imported documents are
  not release truth until classified as current policy, current spec,
  historical input, or delete candidate. The #337 note classifies the preview
  UAPI doc only for the checked `tidefsctl` table and current non-release VFS
  codec hooks; it explicitly does not close full-kernel, broader operator
  UAPI, kernel residency, storage authority, block-volume, xfstests,
  crash-recovery, distributed, or documentation drift debt.
- Issue #1278 re-reviewed the live #656 through #662 follow-up state, the
  #1267 product-surface decision, the checked preview-UAPI table, the
  operator/UAPI and TFR-019 register notes, and the current command
  classification, admission, live-owner, and cluster sources. It closes the
  one-boundary decision for the current pre-alpha operator surface because the
  #657 through #662 follow-ups are closed and the live source/docs now share
  the same boundary. Residual production ABI, distributed operator maturity,
  runtime-fed remote policy authority, product-carrier, and broad
  documentation-drift work remain outside that closeout and are mapped below.
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
- `docs/workspace-package-classification.md` classifies `apps/tidefsctl`, the
  FUSE adapter daemon, the block-volume adapter daemon, scrub, and storage-node
  as bounded userspace entrypoints. `apps/README.md` is only a navigation
  pointer to that checked authority and the issue-scoped validation boundary.
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

## Operator/UAPI Closeout Review

Issue #1278 performed the closeout review on 2026-06-28. The live GitHub
states were:

| Issue | State | Closeout significance |
| --- | --- | --- |
| [#656](https://github.com/tidefs/tidefs/issues/656) | Closed 2026-06-20 | Chose the code registry/admission/live-owner model for the current pre-alpha operator boundary. |
| [#657](https://github.com/tidefs/tidefs/issues/657) | Closed 2026-06-21 | Enforced command registry and privileged-admission invariants. |
| [#658](https://github.com/tidefs/tidefs/issues/658) | Closed 2026-06-21 | Decided claims-gate coverage; this decision artifact remains a non-publishing design record while scanned docs consume the command table. |
| [#659](https://github.com/tidefs/tidefs/issues/659) | Closed 2026-06-21 | Audited live-owner routing and source-classified refusals. |
| [#660](https://github.com/tidefs/tidefs/issues/660) | Closed 2026-06-21 | Cross-referenced this decision from the checked preview UAPI, book, and authz docs. |
| [#661](https://github.com/tidefs/tidefs/issues/661) | Closed 2026-06-20 | Classified this decision in the documentation authority register and updated operator/UAPI and TFR-019 notes. |
| [#662](https://github.com/tidefs/tidefs/issues/662) | Closed 2026-06-21 | Kept cluster pool prototypes and placement/heal exercises separate from public live-owner cluster status. |
| [#1267](https://github.com/tidefs/tidefs/issues/1267) | Closed 2026-06-24 | Recorded that no runtime-fed operator product surface exists and mapped prerequisite follow-ups before any product carrier can be selected. |
| [#1270](https://github.com/tidefs/tidefs/issues/1270) | Closed 2026-06-28 | Classified the missing P10-04 truth-surface law reference so product-surface citations cannot treat it as existing authority. |

The current repo evidence matches those live states:

- `COMMAND_SURFACES` in `apps/tidefsctl/src/commands/classification.rs`
  remains the command class, routing, visibility, and summary authority.
- `command_admission` in `apps/tidefsctl/src/commands/authz.rs` remains the
  privileged-admission authority and checks that public operator mutations are
  not silently unguarded.
- `apps/tidefsctl/src/commands/live_owner.rs` routes imported-pool status to
  the live owner when reachable and otherwise emits source-classified
  fail-closed refusals instead of treating cached metadata as live truth.
- `apps/tidefsctl/src/commands/cluster.rs` keeps `cluster pool create` as a
  prototype, `cluster placement/heal exercise` as development diagnostics, and
  `cluster status` as live-owner status that fails closed without live
  evidence.
- `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`,
  `docs/book/chapters/10-tidefsctl.adoc`, and
  `docs/security/operator-authz-boundary.md` consume the same checked command
  classification/admission boundary without widening it into a production ABI
  or final distributed operator UAPI.

Decision: the one public operator/UAPI boundary is complete for the
current pre-alpha surface. The boundary is the checked `tidefsctl` command
registry plus the privileged-admission registry, live-owner routing/refusal
rules, source-classified diagnostics, explicit prototype/development classes,
and the preview kernel/FUSE/ublk non-release framing recorded here.

Residual work does not reopen that boundary:

| Residual area | Mapping | Boundary |
| --- | --- | --- |
| Production Linux ioctl/statx/ublk/FUSE/kernel ABI freeze | Future issue-scoped ABI freeze decision and implementation proof | Not selected by the operator/UAPI closeout; this document remains pre-alpha and non-release. |
| Distributed transport/cluster maturity | TFR-017, `docs/TRANSPORT_CLUSTER_AUTHORITY.md`, and focused follow-ups such as [#1282](https://github.com/tidefs/tidefs/issues/1282), [#1285](https://github.com/tidefs/tidefs/issues/1285), and [#1293](https://github.com/tidefs/tidefs/issues/1293) | Blocks multi-node/product claims and runtime-fed carriers, but not the current command boundary. |
| Runtime-fed product carrier selection | [#1267](https://github.com/tidefs/tidefs/issues/1267), `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`, and the P10-04 disposition closed by [#1270](https://github.com/tidefs/tidefs/issues/1270) | No CLI/API/dashboard/archive-reader carrier is selected here. |
| Broad documentation authority drift | TFR-019 and `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` | Imported docs still need classification before they can become current policy/spec. |

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

### Model B: documentation table as the command authority checked by code

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

## Minimal Kernel-Control UAPI Contract

Issue #1768 records the minimum production kernel-control boundary that a
future implementation must satisfy before `tidefsctl kernel status` can stop
being passive. The current source records this contract as
`minimum-production-control-uapi-required-not-wired`, and the command still
opens no device and issues no ioctls.

The future endpoint identity is the declared TideFS control character device:
`/dev/tidefs-control` by default, or an explicit `--control-dev` path for
diagnostic probing. A production client must first prove the opened endpoint is
the TideFS control device, not merely any present character device.

The first readonly operation must be a versioned handshake that returns at
least version, status, and capabilities facts. Unknown versions, missing
capabilities, wrong-type paths, or absent devices must fail closed. This
versioning rule is not an ABI freeze; it is the minimum shape that future ABI
review must validate before production wording can strengthen.

Mutating kernel-control operations remain refused until the version/capability
handshake proves production UAPI support, privileged admission is satisfied,
and owner authority is proven through kernel UAPI evidence. The current live
owner manifests under `/run/tidefs/pools/.../owner.json` are userspace routing
evidence only; they are not kernel owner authority.

This contract preserves the current ABI compatibility boundary:
`pre-alpha-no-production-abi-freeze`. It does not claim kernelspace readiness,
no-daemon product mode, mounted-kernel POSIX parity, release readiness, or
successor/comparator status.

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
- This closeout closes only the current pre-alpha operator/UAPI one-boundary
  decision. It does not close TFR-017, TFR-019, block-volume runtime
  validation, FUSE runtime validation, xfstests, crash-recovery, RDMA, release
  claims, or future production UAPI/ABI freeze work.

## Closed Operator/UAPI Follow-Up Map

The original follow-ups were intentionally non-overlapping. As of the #1278
closeout review, all #656-mapped operator/UAPI follow-ups are closed:

| Topic | Follow-up issue | Closed state | Scope closed |
| --- | --- | --- | --- |
| Command-registry enforcement | [#657](https://github.com/tidefs/tidefs/issues/657) | Closed 2026-06-21 | Registry/admission invariants and help rendering checks. |
| Doc and claims-gate coverage | [#658](https://github.com/tidefs/tidefs/issues/658) | Closed 2026-06-21 | Claims-gate coverage decision for this design artifact and generated claim text. |
| Live-owner routing | [#659](https://github.com/tidefs/tidefs/issues/659) | Closed 2026-06-21 | Live-owner routing and source-classified refusals for public operator commands. |
| Preview-UAPI cross-references | [#660](https://github.com/tidefs/tidefs/issues/660) | Closed 2026-06-21 | Preview UAPI, book, and authz cross-references without widening preview scope. |
| Documentation-authority classification | [#661](https://github.com/tidefs/tidefs/issues/661) | Closed 2026-06-20 | Documentation authority classification for this decision. |
| Cluster diagnostic/prototype separation | [#662](https://github.com/tidefs/tidefs/issues/662) | Closed 2026-06-21 | Cluster prototype and development-diagnostic separation from public live-owner status. |

## Validation For This Slice

This issue is documentation/design only. Validation is bounded to:

- source inspection of the evidence listed above;
- `git diff --check`.

No local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, or xfstests
validation is required for this decision. Because this slice does not add a
structured policy check, it does not require a Focused Rust dispatch for
`tidefs-xtask`.
