# Receive-stream merge and checkpoint boundary

Maturity: current source-backed boundary for the local changed-record receive
path. This document is a narrow citation target for receive target handling,
merge-plan gate relaxation, and retryable receive checkpoint cleanup. It is not
a product-admission claim for snapshot/send/receive/reclaim or distributed
receive behavior.

Current authority:

- `crates/tidefs-local-filesystem/src/send_receive.rs` owns the local
  changed-record receive execution path, including staging, checkpoints,
  sender-authority validation, base-root protection, omitted-content
  validation, merge-plan use, and publish ordering.
- `crates/tidefs-local-filesystem/src/receive_persistence.rs` owns the
  execution hooks that let a supplied merge plan relax the default fail-closed
  incremental receive gate and apply per-object import decisions.
- `validation/claims.toml` keeps the
  `snapshot-clone-send-receive-reclaim` product-admission gate blocked until
  lifecycle/capacity, action-execution, local/distributed successor boundary,
  and claims-gate evidence validate for the exact mode.
- Issue #1743 owns the open snapshot/clone/send/receive/reclaim product gap.
  Issue #1813 owns cleanup of the adjacent receive merge-planner and
  cross-pool authorization design records. Issue #1874 owns local OW-era
  send/receive note cleanup. Issue #1258 and PR #1563 own the distributed
  SnapshotBarrier/VFSSEND2 production slice and its runtime-evidence gate.

## 1. Receive target classification

Every receive target is classified before imported roots are published.

### 1.1 Empty target

The target root path does not exist or contains no TideFS pool state. Full
changed-record streams may create a fresh local pool at that path. Incremental
streams are refused because they require an existing protected base root.

Current source enforces this through
`receive_changed_records_into_empty_root`.

### 1.2 Compatible non-empty target

The target root path exists, contains a live TideFS pool, and the incremental
stream's `from_root` is present and protected by a data-retaining snapshot or
clone record with consistent catalog and lifecycle-pin authority.

Incremental receive may proceed after the local receive path verifies sender
authority, stream shape, the base root, omitted content, checksums, namespace
invariants, and publish ordering. Full streams are refused for non-empty
targets because a full receive is the empty-target creation path.

### 1.3 Conflicting non-empty target

Without an explicit merge plan, a conflicting non-empty target fails closed:
the local receive path requires the stream's base root to be present on the
target and protected by local snapshot/catalog/lifecycle authority. It does not
silently merge divergent histories, discard target changes, or stitch together
unproven dataset state.

When a `ReceiveMergePlan` is supplied, current source deliberately relaxes that
base-root gate for the local incremental receive execution path. The receive
then proceeds under per-object decisions from the merge plan:

- `KeepLocal` skips the stream object so the target copy remains authoritative.
- `KeepRemote` imports the stream object.
- `AutoMerge` and objects not named by the plan import from the stream.

That merge-plan integration is current source behavior, not future roadmap
status. It remains bounded to the local changed-record receive path and does
not by itself validate distributed receive, cross-pool reclaim, placement
receipt, OpenZFS/Ceph successor, or product-ready snapshot/send/receive
claims. Those wider gaps remain blocked by #1743 and the claims registry.

## 2. Resume checkpoint authority

### 2.1 Staging-based checkpoint resume

Empty-target receive writes object payloads into a staging store before
publishing the received root. During that import, the receiver persists a
`ReceiveCheckpoint` containing:

- a stable export identity derived from the stream spec, stream version,
  transform contract, and source root identities;
- the expected changed-object record count;
- the object keys already persisted into staging.

On retry, if the staging directory exists and contains a checkpoint matching
the current export identity, the receiver skips completed keys and resumes. If
there is no usable checkpoint or the checkpoint belongs to a different export,
the receiver removes the stale staging directory and starts fresh.

This is local staging resume. It is not cross-host distributed replication
resume, and it only survives while the staging directory remains available.

### 2.2 Retryable receive errors preserve staging

Current source preserves the staging directory and receive checkpoint when an
empty-target receive fails with a retryable error. Retryable errors are the
cases where a later attempt can plausibly make forward progress with the same
export and staged objects, such as transient store I/O, local no-space or
pressure refusal, and uncertain publish outcome.

Current source removes staging only for non-retryable failures that make the
checkpoint unsafe or inapplicable, including malformed streams, unsupported
stream shapes, deterministic store/refusal errors, or target state corruption.
The original receive error is returned unchanged; cleanup policy only decides
whether a later retry can resume from the checkpoint.

No follow-up issue is recorded here for retryable-error checkpoint
preservation because the current receive source and tests already implement
that behavior.

## 3. Base-root protection

Incremental receive continues to require a data-retaining base-root authority
unless a merge plan explicitly relaxes the gate under section 1.3.

- A retaining snapshot or clone can protect the base root.
- A bookmark is not sufficient because it does not retain data.
- A present base root with inconsistent catalog or lifecycle-pin authority
  fails before object import.

These are local correctness requirements, not product-admission evidence for
the blocked snapshot/clone/send/receive/reclaim gate.

## 4. Omitted-content and snapshot anchors

Incremental receive and snapshot import also keep these source-backed local
rules:

- Omitted unchanged content records must already be present and checksum-valid
  in the target store before the received root is published.
- Snapshot and clone catalog entries are transported as changed records that
  preserve `SnapshotRecord` kind; import rewrites root summaries without
  converting clone/bookmark semantics into broader authority.

These rules do not validate distributed receive, reclaim, or successor claims.

## 5. Distributed and cross-pool non-claims

The integrated changed-record receive path validates sender authority through
its explicit receive authorization inputs. That local check is not a broad
distributed receive product claim. This document does not validate:

- storage-node runtime coordination;
- multi-host stream scheduling or barrier evidence;
- cross-pool deadlist/reclaim accounting;
- placement-receipt-gated receive;
- distributed conflict resolution;
- OpenZFS/Ceph successor or production-ready wording.

Adjacent design cleanup belongs to #1813. Product admission remains blocked by
#1743, `validation/claims.toml`, and the generated claim registry until the
required evidence classes validate for the exact scope.

## 6. Validation boundary

For documentation cleanup that only retargets or narrows this boundary, use:

- `git diff --check`;
- a focused reference scan for this file, receive checkpoints, retryable
  receive wording, and stale implementation-status wording;
- `cargo run -p tidefs-xtask -- check-doc-authority-drift`;
- `cargo run -p tidefs-xtask -- check-claims-gate` when product-facing wording
  changes.

Runtime send/receive, merge-planner execution, storage-node, distributed,
QEMU, xfstests, RDMA, release-candidate, and product-admission validation
belong to the focused issues that change those behaviors or evidence paths.
