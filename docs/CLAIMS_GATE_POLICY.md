# Claims Gate Policy

Maturity: current policy guardrail.

TideFS may describe ambition and future direction, but publishing-facing docs
must not present future capability as current product fact.

## Required command

Run this before publishing a tarball, tag, external summary, or handoff that a
reader could treat as a capability statement:

```text
cargo run -p tidefs-xtask -- check-claims-gate
```

This command checks publishing-facing capability wording. It does not validate
active work ownership. Foreground Codex work is coordinated through GitHub
issues and pull requests in `tidefs/tidefs`; use the separate worktree/claim
diagnostic commands when checking local worker ownership.

## Claim Registry Authority

Stable claim ids live in `validation/claims.toml`. That registry records the
claim status, scope, required evidence classes, current blockers, and the text
that may appear in generated claim documentation.

The generated claim document is `docs/CLAIM_REGISTRY.md`. It is checked by
`cargo run -p tidefs-xtask -- check-claims-gate`; manual edits to that document
must fail unless they match the registry-derived output exactly.

Use `cargo run -p tidefs-xtask -- validate-claim <id>` before treating a
registered claim as validated evidence. Planned, blocked, and invalid claims
fail closed; validated claims also fail closed when required evidence artifacts
are missing or older than `validation/claims.toml`.

When a claim evidence requirement names a `manifest_path`,
`validate-claim <id>` treats that unified evidence manifest as the evidence
record for the requirement. The manifest must be version 2, workspace-relative,
schema-valid, digest-matched to its artifact, current for the checked source,
and must match the claim id, evidence class, validation tier, artifact path,
run id, source ref, pass outcome, residual risk, source, scope, and blocking
issue state expected by the registry. Missing, stale, malformed, mismatched,
non-pass, or blocked manifests fail closed; receipt integrity may support
evidence integrity, but it does not replace the registry or `validate-claim`
as claim-status authority.

## Successor And Comparator Wording

The publishing-facing successor and comparator boundary is
`storage.intent.successor_comparator.v1` in `validation/claims.toml`. Until
that claim validates with current evidence manifests, TideFS docs, release
notes, generated claim text, operator output, issue closeouts, and PR summaries
must not say or imply that TideFS is a successor, replacement, superior
alternative, or comparator-performance winner against OpenZFS, Ceph, DRBD, or
local filesystems.

Allowed wording may describe ambition and target class, blocked claim ids and
missing evidence, historical design inputs from incumbent systems, or bounded
local claims that already validate under their own claim ids.

Disallowed wording includes:

- unqualified OpenZFS/Ceph-class fulfillment;
- average benchmark wins used as superiority permission;
- storage-intent row labels treated as product admission;
- blocked release-ready, production-ready, GA-ready, or stable-release
  statements without a verdict artifact owned by
  `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.

The successor comparator claim remains blocked until the registry-required
evidence classes are present and current, including:

- `storage-intent-comparator-equivalence-evidence`;
- `storage-intent-successor-performance-fault-set`;
- `storage-intent-successor-claim-boundary-review`;
- `storage-intent-operator-explanation-evidence`;
- `claims-gate-review`.

Normal implementation PRs need the focused validation named by their GitHub
issue; they do not prove the whole successor claim. Product-facing comparator
evidence is collected only at named product gates such as `validate-claim`,
proof-train packets, release-readiness verdict review, explicit
performance/fault/attribution/evidence-query/service-objective matrices, or
claim-boundary manifests under `validation/artifacts/`.

If a PR touches product claims, successor wording, comparator baselines,
release-readiness wording, or evidence manifests, it must run the relevant
claim gate and preserve blocked status unless the same issue adds matching
evidence for the exact claimed scope.

## Validation Tier Evidence Map

The nextgen program authority is
`docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`. This policy document
is the claims-facing reference for mapping the validation tiers implemented by
`tidefs-validation` to the evidence classes required by
`validation/claims.toml`.

The rule is intentionally conservative: the claim registry names the required
evidence classes, while the validation tier describes where the artifact came
from. A tier does not substitute for a missing evidence class. Lower-tier
evidence may diagnose, reproduce, narrow, or motivate a higher-tier claim, but
it cannot validate that higher-tier claim. For example, a `source-model`
crash matrix may satisfy `model-crash-matrix`, but it cannot satisfy
`runtime-crash-oracle`; a `qemu-guest` uBLK smoke artifact may diagnose block
runtime behavior, but it cannot close distributed or RDMA evidence classes.

Use the smallest tier whose artifact source and scope match the claim:

| Tier labels | Artifact source and examples | Evidence classes this tier can satisfy |
| --- | --- | --- |
| `source-model` | Deterministic models, schemas, static manifests, and bounded proof outputs. Examples include `validation/artifacts/crash-oracle/model-crash-matrices.json`, `validation/artifacts/ublk/qid-tag-state-model.json`, and model-scoped teardown artifacts. | Model-only or source-model classes such as `model-crash-matrix`, `qid-tag-state-model`, `kernel-context-token-model`, or other registry classes whose scope is explicitly model-only. |
| `cargo-unit` | Focused crate tests, parser/schema/golden-vector checks, registry loaders, and source/registry review helpers run without a mounted product path. | Source, registry, codec, manifest, and helper-tool evidence classes whose required scope is source review or unit-level behavior. |
| `harness-only` | Offline harnesses and simulations that do not mount FUSE, start a uBLK export, load a TideFS kernel module, or run a distributed transport. | Harness/model evidence classes such as admission-budget or isolation-model artifacts when the claim explicitly asks for harness-level evidence. |
| `mounted-userspace` | A live mounted userspace path, normally a FUSE or userspace owner harness artifact with command, commit, backend, and output. | Runtime evidence classes for mounted local userspace behavior, such as `runtime-crash-oracle`, `runtime-namespace-crash-artifact`, or mounted performance artifacts when the artifact scope matches the claim. |
| `qemu-guest` | Runtime evidence collected inside a QEMU guest, including focused uBLK or mounted userspace rows. | QEMU-scoped runtime evidence classes. For uBLK claims, examples include `runtime-ublk-completion-artifact` and `runtime-ublk-started-export-admission-artifact` when the artifact came from the relevant qemu-ublk workflow and verifier. |
| `kbuild` | Kernel build evidence only. | Kernel source/build classes and review evidence that require compilation, but not mounted kernel runtime behavior. |
| `qemu-module-load` | QEMU evidence that the kernel module can load and expose the expected control surface. | Module-load evidence classes. This tier does not satisfy mounted kernel VFS, block I/O, or full-kernel no-daemon classes by itself. |
| `mounted-kernel-vfs` | Mounted kernel VFS runtime rows, usually from QEMU/kernel workflows with artifact output. | Runtime kernel VFS evidence classes whose claim scope is the mounted kernel filesystem path. |
| `kernel-block-io` | Kernel block-device I/O runtime rows, including uBLK/kernel block interaction when the artifact scope names that path. | Runtime kernel block I/O evidence classes whose claim scope is block-device behavior. |
| `full-kernel-no-daemon` | Mounted operation through the kernel-resident no-daemon path. | Not yet full-kernel no-daemon evidence; applies only when the artifact proves the specific claim scope. |
| `multi-process-distributed` | Multi-process transport, cluster, or RDMA runtime rows with captured commands, topology, backend, and outputs. | Distributed or RDMA runtime evidence classes when the claim explicitly requires that class and the artifact scope matches the topology and transport. |

`claims-gate-review` is an evidence class, not a runtime tier. A
claims-gate review artifact may be produced by source/registry review and
should document which model, source, runtime, or distributed artifacts were
reviewed, which claim ids are covered, and which stronger classes remain
missing. It can satisfy a `claims-gate-review` requirement, but it cannot
replace the other required classes in `validation/claims.toml`.

When choosing GitHub Actions validation, dispatch the smallest workflow that
can produce the missing evidence class. Source and registry slices normally
need only `git diff --check`, docs review, and a focused Rust workflow when a
crate/tool changed. Mounted userspace, QEMU, kernel, uBLK, xfstests,
distributed, and RDMA claims need the corresponding runtime workflow artifact.
Model-only evidence must remain model-only in claim receipts and product
wording until the required runtime class and claims-gate review both exist.

## Claims rule

Current capability wording is blocked for these claim families unless the same
line clearly frames the capability as absent today, future work, or a goal:

- must not publish an OpenZFS/Ceph successor claim;
- must not claim production-ready status;
- must not claim POSIX-complete behavior;
- must not claim distributed storage capability;
- must not claim kernelspace-ready or full-kernel operation;
- must not claim an RDMA data path.
- must not claim mounted device-level compression or mounted device-level
  encryption while the TFR-006 raw-store inventory has blocked production
  rows.
- must not claim final distributed operator UAPI status for prototype or
  development-exercise `tidefsctl` commands.

A line may mention one of those topics only when it is clearly framed as one of:

- not true today;
- future or aspirational work;
- a goal or ambition rather than current product state.

## Proof Before Stronger Claims

Stronger wording requires all of the following:

1. a tracked GitHub issue naming the claim;
2. recorded proof that covers the full claimed behavior;
3. an updated current-status or review-register row;
4. an updated claims gate rule that allows the specific stronger claim.

## Crash Evidence Scope

Crash-oracle model matrices are model-only evidence. A
`runtime-crash-oracle` or `runtime-namespace-crash-artifact` evidence entry
must point at runtime evidence whose declared source and scope are runtime,
not model-only. Crash-safety and rename-crash claims must keep planned,
blocked, or fail-closed wording until the registry records fresh model
evidence, runtime evidence for the required runtime class, and a
`claims-gate-review` artifact that reviews the model/runtime evidence
boundary.

## Mounted Transform Authority

The mounted local-filesystem compression/encryption claim is blocked behind
`docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`. The lower
object-store compression and encryption wrappers may be discussed as helper
or library-tier surfaces, but publishing-facing text must not present them as
end-to-end mounted filesystem support until the transform authority records no
blocked production raw-store paths.

## Operator Command Classification

The `tidefsctl` command classification authority is
`apps/tidefsctl/src/commands/classification.rs`, marker
`tidefsctl-command-classification-v1`; privileged admission is recorded in
`apps/tidefsctl/src/commands/authz.rs`. Publishing-facing docs must preserve
the distinction between `public-operator`, `userspace-harness`,
`operator-diagnostic`, `prototype`, `development-diagnostic`, and
`removed-or-unsupported` command surfaces, including their routing, admission,
help visibility, and summary text. In particular, `cluster placement exercise`,
`cluster heal exercise`, and `cluster pool create` are not final distributed
operator UAPI.

The claims gate checks the exact registry/admission table below against
`COMMAND_SURFACES` and `command_admission`:

| Command | Class | Routing | Admission | Help | Summary |
|---|---|---|---|---|---|
| `pool create` | `public-operator` | `offline-discovery-or-import-input` | `local-only` | `visible` | create an exported pool from explicit byte-addressable devices |
| `pool scan` | `public-operator` | `offline-discovery-or-import-input` | `unguarded` | `visible` | scan explicit devices for pool labels |
| `pool status` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | query the live owner by pool name, or scan explicit offline devices |
| `pool import` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | request owner-mediated import; explicit devices are import inputs |
| `pool export` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | export through the live owner, or operate on exported explicit devices |
| `pool destroy` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | destroy through the live owner, or operate on exported explicit devices |
| `pool get` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | read pool properties through owner authority or explicit offline devices |
| `pool set` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | set pool properties through owner authority or explicit offline devices |
| `pool list-props` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list pool property definitions and effective values |
| `snapshot create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create snapshots through the live owner or explicit offline devices |
| `snapshot list` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list local snapshot catalog entries with kind, origin, hold, and generation metadata |
| `snapshot clone create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create local snapshot clones through the live owner or explicit offline devices |
| `snapshot clone delete` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | delete local snapshot clones through the live owner or explicit offline devices |
| `snapshot clone promote` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | promote local snapshot clones through the live owner or explicit offline devices |
| `snapshot bookmark create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create local snapshot bookmarks through the live owner or explicit offline devices |
| `snapshot bookmark delete` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | delete local snapshot bookmarks through the live owner or explicit offline devices |
| `snapshot hold` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | place local deletion-prevention holds on snapshots or clones |
| `snapshot release` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | release local deletion-prevention holds on snapshots or clones |
| `snapshot holds` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | inspect local snapshot and clone hold counts |
| `snapshot prune` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | prune regular local snapshots by retention policy while excluding clones and bookmarks |
| `snapshot destroy` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | destroy snapshots through the live owner or explicit offline devices |
| `snapshot export` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | register runtime-pending read-only snapshot export mount surface |
| `snapshot extract` | `public-operator` | `live-owner` | `local-only` | `visible` | extract one regular file from a snapshot through the live owner |
| `snapshot rollback` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | roll back through the live owner or explicit offline devices |
| `snapshot send` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | export snapshot streams through owner authority or explicit offline devices |
| `snapshot receive` | `public-operator` | `live-owner` | `local-only` | `visible` | receive snapshot streams through the live owner; offline receive is unsupported |
| `device remove` | `public-operator` | `live-owner` | `local-only` | `visible` | route device evacuation/removal through live placement and refcount authority |
| `device status` | `public-operator` | `live-owner` | `unguarded` | `visible` | query live device status through the live owner; fail closed when no live owner is reachable |
| `defrag` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | request online extent-map defragmentation for a path |
| `block attach` | `public-operator` | `live-owner` | `local-only` | `visible` | attach an imported pool as a ublk block device through owner authority |
| `block detach` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | detach an existing ublk device by numeric id |
| `block list` | `public-operator` | `no-live-pool-state` | `unguarded` | `visible` | list attached ublk devices |
| `block send` | `public-operator` | `live-owner` | `local-only` | `visible` | send block-volume state through live owner and transport authority |
| `block receive` | `public-operator` | `live-owner` | `local-only` | `visible` | receive block-volume state through live owner and transport authority |
| `dataset create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create catalog-backed datasets through owner authority or explicit devices |
| `dataset list` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list catalog-backed datasets through owner authority or explicit devices |
| `dataset destroy` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | destroy catalog entries through owner authority or explicit devices |
| `dataset rename` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | rename catalog entries through owner authority or explicit devices |
| `dataset set-strategy` | `public-operator` | `live-owner-or-offline-input` | `local-only-when-mutating` | `visible` | set dataset feature strategy through owner authority or explicit devices |
| `dataset seal-key` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | seal dataset keys through owner authority or explicit devices |
| `dataset rotate-key` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | rotate dataset wrapping keys through owner authority or explicit devices |
| `dataset upgrade` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | enable supported dataset features through owner authority or explicit devices |
| `dataset get` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | read dataset properties through owner authority or explicit devices |
| `dataset set` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | set dataset properties through owner authority or explicit devices |
| `dataset list-props` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list dataset property definitions and effective values |
| `storage-intent explain` | `public-operator` | `passive-diagnostic` | `unguarded` | `visible` | render supplied storage-intent policy, receipt, and evidence-query records read-only |
| `storage-intent policy set` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | stage dataset prefetch/residency policy source through #855 without activation |
| `storage-intent policy clear` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | stage dataset prefetch/residency policy clears through #855 without activation |
| `storage-intent policy show` | `public-operator` | `passive-diagnostic` | `unguarded` | `visible` | render staged dataset prefetch/residency policy source documents |
| `storage-intent policy dry-run` | `public-operator` | `passive-diagnostic` | `unguarded` | `visible` | compile staged dataset prefetch/residency policy source and render blocked support |
| `mount` | `userspace-harness` | `userspace-harness` | `unguarded` | `visible` | launch the current direct FUSE development harness |
| `pool mount` | `userspace-harness` | `userspace-harness` | `unguarded` | `visible` | import explicit devices and launch the current FUSE owner harness |
| `pool integrity-check` | `operator-diagnostic` | `live-owner-or-offline-input` | `unguarded` | `visible` | run live-owner or explicit-device integrity diagnostics |
| `kernel status` | `operator-diagnostic` | `passive-diagnostic` | `unguarded` | `visible` | passively inspect the declared kernel control endpoint |
| `diag` | `operator-diagnostic` | `passive-diagnostic` | `unguarded` | `visible` | collect a redacted diagnostic support bundle |
| `cluster pool create` | `prototype` | `prototype-only` | `unguarded` | `visible` | prototype clustered pool creation; not final distributed operator UAPI |
| `cluster placement exercise` | `development-diagnostic` | `development-exercise` | `unguarded` | `visible` | development diagnostic exercise for placement-map code |
| `cluster heal exercise` | `development-diagnostic` | `development-exercise` | `unguarded` | `visible` | development diagnostic exercise for placement-heal code |
| `cluster status` | `public-operator` | `live-owner` | `unguarded` | `visible` | query live cluster status through the live owner; fail closed when no live owner is reachable |
| `pool list` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | no authoritative pool registry exists; use pool scan --devices or pool status <pool> |
| `device rebuild` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | offline directory object-store rebuild is retired; use live pool repair authority |
| `directory-backed pool media` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store pool media is retired for operator pool commands |
| `pool integrity-check --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store integrity scan mode is retired; use --devices or live owner |
| `snapshot --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store snapshot mode is retired |
| `block --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store block-volume mode is retired |
| `device remove --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | offline directory device removal is retired |
| `device remove --surviving-dirs` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | offline directory survivor-device removal is retired |

## Unreleased Authority Boundary

TideFS has not had a public release. Publishing-facing docs must not describe
old internal TideFS paths as legacy product compatibility, migration, downgrade,
or fallback promises unless a tracked GitHub issue names the released external
boundary or operator-owned data set being preserved. Current design wording
should choose current authority, retire the stale pre-release path, or mark the
material as historical input.

## Scanned surfaces

`tidefs-xtask check-claims-gate` scans the top-level README,
`apps/README.md`, `crates/README.md`,
`docs/workspace-package-classification.md`, current policy docs, preview
handoff docs that remain in the tree, the review register, and the whole-repo
review. It also verifies that the source rule table in
`xtask/tidefs-xtask/src/claims.rs` and this policy document remain present.

The top-level app and crate indexes are checked publishing surfaces. They may
summarize maturity only with explicit limitation framing: app summaries must
remain inventory text rather than production-readiness claims, and crate
package counts, area tables, and capability summaries must defer to the
checked workspace package classification rather than acting as separate
package authority or release proof.


`docs/OPERATOR_UAPI_AUTHORITY.md` is not in the direct claims-gate scanned
set (issue #658). It is a design-decision artifact that defines operator
UAPI authority boundaries; it is not a publishing-facing capability
statement. The command classification/admission table it defines as source
of truth is already consumed by this policy document and by
`docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`, both of which remain scanned.
The authority document records blocked operator-boundary topics for UAPI/ABI
stability, kernel residency, distributed command scope, and runtime-fed policy
authority that the claims gate enforces.

## Work-State Boundary

GitHub issue and pull request state is the active work-state authority for
foreground Codex development. Forgejo helper commands remain available for
historical/local diagnostics, but stale Forgejo ownership assumptions must not
block `check-claims-gate` from scanning publishing claims in a valid
GitHub/Codex worktree.
