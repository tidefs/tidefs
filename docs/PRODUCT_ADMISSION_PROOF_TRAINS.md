# Product Admission Proof Trains

Issue: #1298
Date: 2026-06-24
Status: design map; planning and review overlay only

This document maps existing TideFS whole-product admission evidence into a
small set of proof trains. It is not a release-readiness verdict, it does not
rename the verdict owner from `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`, and
it does not change any implementation, validation workflow, product surface, or
claim registry.

## Non-Claims And Refusals

TideFS remains pre-alpha. No release-readiness verdict exists. OpenZFS/Ceph-class
status is a target rather than a present TideFS capability.

The proof trains below are planning containers for evidence review. A train can
collect gate-local receipts, issue closeouts, CI runs, or design decisions, but
none of those local receipts becomes whole-product admission by itself. A future
verdict artifact must still consume all active evidence families, name open
gaps, and record explicit non-claims as required by
`docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.

This document refuses the following interpretations:

- A passing CI workflow, claims-gate row, release-candidate evidence index, or
  performance-gate receipt is not a whole-product admission verdict.
- A proof train map is not a promise that the train is complete.
- This map does not claim TideFS is release-ready, production-ready, GA-ready,
  stable-release material, or an OpenZFS/Ceph-class implementation.

## Evidence Reviewed

Repository evidence reviewed for this map:

- `README.md`: TideFS is aimed at OpenZFS/Ceph-class reliability and scale, but
  the repository is pre-alpha and the claim is not currently fulfilled.
- `AGENTS.md`: product claims must stay behind implementation reality; storage
  authority, recovery, capacity, snapshots, device lifecycle, kernel residency,
  and distributed behavior must close before OpenZFS/Ceph-class status is
  claimed.
- `docs/00_user_requirements.md`: the original ambition is a safe,
  human-understandable storage system that can eventually beat the combined
  practical value of OpenZFS and Ceph; the current judgement says the ambition
  is not met and names broad authority debt.
- `docs/WHOLE_REPO_REVIEW.md`: the active review snapshot names fail-closed
  incumbent comparisons, priority TFR families, and the next review order that
  must precede honest product claims.
- `docs/REVIEW_TODO_REGISTER.md`: the durable blocker register records the
  current review/debt families that block OpenZFS/Ceph-class claims.
- `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`: the verdict owner is a tracked
  human-integrated decision artifact, not a single CI run or gate receipt; the
  contract lists required evidence families and preserves the gate-local versus
  whole-product boundary.
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`: #1284 has added current authority
  rows for release-facing evidence inputs while preserving the rule that those
  inputs are not a product-admission verdict.
- `docs/GITHUB_CI.md`, `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md`,
  `docs/CLAIMS_GATE_POLICY.md`, and
  `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md` as evidence-family
  inputs already referenced by the verdict contract.
- `/root/ai/docs/projects/tidefs/state/final-product-shape-review-2026-05-24.md`
  as historical context for the phrase "proof trains." That note is useful as
  a planning instinct but predates the current verdict contract and is not used
  as release authority.

Live GitHub evidence reviewed at 2026-06-24T10:52:08Z:

- Source issue #1298 was open, unassigned, and had no comments.
- No same-issue local worktree, local branch, remote branch, active process, or
  open pull request existed before this branch was created.
- Open draft PR #1132 (`gpt0/issue-929-fuse-generic013-fsstress-cpu`) touched
  local-filesystem Rust files and one Nix validation file only.
- Open draft PR #1144 (`gpt4/issue-1127-adapter-lib-failures`) touched POSIX
  adapter and local-filesystem Rust files only.
- #1270, #1278, #1283, #1286, #1288, #1289, and #1293 were open and are
  intentionally left to their own expected write sets.
- #1284 was closed and is treated as completed context for authority-register
  coverage of release-facing evidence inputs.

## Decision

Use five product-admission proof trains as a review overlay:

1. Verdict and evidence-control proof.
2. Local storage integrity and lifecycle proof.
3. POSIX, block, and kernel runtime proof.
4. Operator truth and distributed cluster proof.
5. Documentation, provenance, and claim-hygiene proof.

The trains are deliberately broader than individual TFR rows and narrower than
"make TideFS done." Each train is a place to assemble evidence for the future
verdict owner. None may close whole-product admission alone.

## Proof Train Map

| Proof train | Current evidence families | Repo review/debt families | Live issue families or follow-up gaps |
|---|---|---|---|
| Verdict and evidence-control proof | Release-candidate evidence index, claims gate, performance budget gate, standing CI gate, unreleased authority policy, documentation-authority rows for release-facing inputs | TFR-001 claim drift, TFR-015 runtime output doctrine, TFR-020 test signal authority | #1283 remains open for the P10-03 readiness-field scope fix. #1284 is closed for authority-register release-input rows. The verdict contract still records absent lane-local manifests and incomplete performance-suite families as open gaps. |
| Local storage integrity and lifecycle proof | Storage authority designs and receipts for inode identity, timestamp/generation, transforms, capacity, recovery, writeback, mmap, snapshots, send/receive, deadlists, device lifecycle, trim, and remanence | TFR-004, TFR-005, TFR-006, TFR-007, TFR-008, TFR-010, TFR-012 | The register maps this train through existing authority docs and follow-up slices such as the inode namespace map, transform pipeline map, capacity map, page-cache/writeback maps, snapshot/deadlist map, and device lifecycle/remanence work. The open gap is integrated proof that these local storage families work as one product contract. |
| POSIX, block, and kernel runtime proof | QEMU smoke, mounted-kernel evidence, FUSE and ublk behavior, xfstests/fsx/fsstress rows, kernel residency evidence, no-daemon kernel cutover evidence | TFR-008, TFR-009, TFR-018 | #1288 remains open for the TFR-009 kernel-residency authority decision. Existing kernel/POSIX work remains train-local evidence until mounted runtime, crash/replay, page-cache, block, and no-daemon behavior are proven together. |
| Operator truth and distributed cluster proof | Operator truth surfaces, operator UAPI authority, transport/cluster authority, RDMA/TCP carrier evidence, membership/fencing, placement, scrub/repair, product carrier refusal behavior | TFR-011, TFR-017, TFR-019 | #1270 remains open for the missing P10-04 truth-surface law disposition. #1278 remains open for the TFR-011 operator-UAPI closeout. Transport/cluster authority remains open under TFR-017, including carrier binding, cross-replica comparison, repair dispatch, partition recovery, and operator product-surface evidence. |
| Documentation, provenance, and claim-hygiene proof | Claims-gate policy, unreleased-authority policy, documentation-authority register, licensing/provenance docs, dependency-license evidence, test-signal policy, review register hygiene | TFR-002, TFR-003, TFR-013, TFR-014, TFR-016, TFR-019, TFR-020 | #1286 remains open for model-only evidence boundary cross-references. #1289 remains open for TFR-014 licensing/provenance closeout. #1293 remains open for one TFR-019 coordination-design classification. Documentation cleanup and provenance evidence stay supporting proof, not whole-product admission. |

## Local Storage Integrity And Lifecycle Packet

This is the bounded packet shape for proof train 2. It is a train-local
review packet, not a train-completion claim, release-readiness verdict,
product-admission decision, or change to the verdict owner named by
`docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.

A worker or reviewer assembling this packet must consume the claim-boundary
inputs first: `README.md`, `AGENTS.md`, `docs/00_user_requirements.md`,
`docs/WHOLE_REPO_REVIEW.md`, `docs/REVIEW_TODO_REGISTER.md`, and
`docs/RELEASE_READINESS_VERDICT_CONTRACT.md`. Those inputs keep the packet
inside the current pre-alpha boundary and require every train-local receipt,
closed issue, CI artifact, and storage review note to remain evidence for the
future verdict owner rather than whole-product admission.

The train-local packet must then cover these local storage evidence families:

| Evidence family | Current authority inputs to consume | Open gap category to carry forward |
|---|---|---|
| Dataset and inode authority | `docs/INODE_NAMESPACE_AUTHORITY.md`, TFR-004 rows in `docs/REVIEW_TODO_REGISTER.md`, and the non-overlapping follow-up map for allocator ownership, FUSE lookup-reference projection, old-catalog policy, and special-node replay. | Dataset-scoped allocation, persisted inode identity, FUSE lookup/forget state, inode-table projection, old pre-release catalog refusal, recovery seeding, and namespace replay are not yet one proven runtime contract. |
| Timestamp, generation, and on-disk format | `docs/TIMESTAMP_GENERATION_AUTHORITY.md`, `docs/ON_DISK_FORMAT_VERSIONING_AND_COMPATIBILITY_POLICY.md`, and `docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md` as historical/reconciled review input only. | POSIX time, generation, txg, object-version identity, scrub identity, replay ticks, rename stamps, and internal format refusal rules still need the delegated runtime and evidence rows recorded by TFR-005 before the family can support a closure claim. |
| Transform authority | `docs/TRANSFORM_PIPELINE_AUTHORITY.md`, `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`, and the TFR-006 register rows. | Mounted-content compression, lower device compression/encryption, dedup fingerprinting, checksums, raw-store escape hatches, reclaim identity, and key handling are not yet one validated transform path. Mounted device-level compression and encryption remain blocked until the follow-up map proves conformance. |
| Capacity and accounting | `docs/CAPACITY_ACCOUNTING_AUTHORITY.md`, `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`, `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md`, `docs/LOCAL_SNAPSHOTS_OW108.md`, and TFR-007 rows. | Mounted write admission, quota input, POSIX/FUSE `statfs`, physical placement, snapshot-pinned bytes, dedup savings, reclaim deltas, inode-count projection, and operator reporting still need one authority-backed accounting lifecycle. |
| Recovery, fsync, writeback, mmap, and page-cache coherency | `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`, `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`, `docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md`, TFR-008 rows, and TFR-018 rows where mounted runtime evidence is the consumer. | Dirty/writeback lifecycle, `fsync`/`syncfs`/`msync` barriers, mmap faults, direct-I/O reconciliation, stale-generation fences, FUSE/kernel notifications, crash replay, and no-production-fsck failure classes are not yet proven end to end across mounted local runtime paths. |
| Snapshot, clone, send/receive, and deadlist lifecycle | `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`, `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md`, `docs/design/distributed-snapshot-shipping.md`, and TFR-010 rows. | Snapshot state, catalog entries, lifecycle pins, clone lineage, send/receive base-root authority, released-root deadlist derivation, receipt-bound reclaim, receive triggers, and distributed shipping remain split across local authority and open implementation/follow-up rows. |
| Device lifecycle, discard, zeroing, and remanence | `docs/DEVICE_LIFECYCLE_REMANENCE_AUTHORITY.md`, `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`, transform/capacity authority inputs where they affect discard or reclaim, and TFR-012 rows. | Byte-device admission, discard capability reporting, trim/free semantics, online removal, replacement/rebuild, durable label/topology updates, zero-visible data, secure erase, and media privacy policy are still open product boundaries. |

The packet may cite focused runtime tests, source inspections, issue closeouts,
or CI artifacts for one row only when their scope is named. It must also name
any stale, historical, or superseded inputs it consumes. A local storage receipt
does not graduate into a whole-product verdict unless the verdict owner later
consumes it together with every active evidence family, records open gaps, and
states the remaining non-claims.

## Train Completion Shape

A proof train is review-complete only when it can hand the verdict owner a
bounded packet containing:

- the source commit or PR range reviewed;
- the repo documents and live issues consumed;
- the CI runs, workflow artifacts, or gate-local receipts consumed;
- a list of open gaps, explicitly scoped non-claims, and superseded/stale
  evidence;
- any remaining follow-up issues with non-overlapping expected write sets; and
- a statement that train-local receipts are not whole-product admission.

This completion shape is intentionally descriptive. It does not create a new
automated gate and does not override the verdict contract.

## Alternatives Considered

### Alternative A: Change the verdict contract directly

Rejected. `docs/RELEASE_READINESS_VERDICT_CONTRACT.md` owns the verdict
boundary: verdict owner, required evidence families, gate-local versus
whole-product distinction, refusal language, and follow-up map. Issue #1298's
expected write set excludes that file. Changing the contract would blur a
decision boundary that already exists and would exceed this slice.

### Alternative B: Put proof trains in the release-candidate evidence contract

Rejected. `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md` describes one evidence
input: how the release-candidate workflow produces and indexes artifacts. Proof
trains also include live issue ownership, documentation authority, claims-gate
policy, operator truth surfaces, local storage authority, kernel residency, and
distributed behavior. Putting the map there would make an evidence input look
like a product-planning or verdict document.

### Alternative C: Reuse the historical proof-train note as current authority

Rejected. The 2026-05-24 state note correctly points toward proof-train
planning, but it predates the current GitHub issue/PR workflow, the verdict
contract, the release-candidate evidence contract, and the latest register
updates. It is reviewed as historical context only.

### Alternative D: Do not add a separate map

Rejected. The verdict contract lists evidence families, and the review register
lists TFR debt, but neither gives reviewers a compact planning overlay that
connects evidence families to live issue families without changing the verdict
boundary. A separate document satisfies that planning need while leaving the
contract and implementation surfaces untouched.

## Non-Overlapping Follow-Up Map

No new GitHub issue is required by this slice. The current non-overlapping map
is:

| Follow-up lane | Current owner or gap | Write-set boundary |
|---|---|---|
| P10-04 truth-surface disposition | #1270 open | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, `docs/REVIEW_TODO_REGISTER.md`, and the named P10-04 cross-reference docs only |
| Operator UAPI closeout | #1278 open | `docs/OPERATOR_UAPI_AUTHORITY.md`, `docs/REVIEW_TODO_REGISTER.md`, and possible `docs/INDEX.md` only if evidence requires |
| Performance-gate scoped readiness receipt | #1283 open | P10-03 performance-gate source/doc surfaces named by that issue; not this map |
| Model-only test-signal claim cross-references | #1286 open | Documentation claim-boundary cross-references named by that issue |
| Kernel residency authority | #1288 open | Kernel-residency authority docs and narrow cross-references named by that issue |
| Licensing/provenance closeout | #1289 open | `docs/REVIEW_TODO_REGISTER.md` and possible `docs/LICENSING.md` clarification only |
| Coordination design completion authority | #1293 open | `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, the exact coordination-design completion doc, and possible register residual note only |

The proof-train map itself owns only `docs/PRODUCT_ADMISSION_PROOF_TRAINS.md`.
Future implementation or validation issues should select one proof train, name
the exact evidence family and write set, and preserve the verdict contract's
rule that gate-local receipts are not whole-product admission.

## Validation Boundary

Validation for this document is documentation/design/source inspection only:

- `git diff --check` on this issue branch.
- Source inspection against `README.md`, `AGENTS.md`,
  `docs/00_user_requirements.md`, `docs/WHOLE_REPO_REVIEW.md`,
  `docs/REVIEW_TODO_REGISTER.md`, and
  `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.
- A bounded claim-wording scan for unqualified release-ready, production-ready,
  GA-ready, stable-release, or OpenZFS/Ceph-class capability claims introduced
  by this file.

No local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, xfstests, or broad
GitHub Actions validation is required for this docs-only map.
