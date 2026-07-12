# TideFS

TideFS is a Rust filesystem and storage stack aimed at OpenZFS/Ceph-class
reliability and scale. It is not there yet. The repo is a pre-alpha
implementation with serious architectural debt tracked in
`docs/REVIEW_TODO_REGISTER.md`.
TideFS does not currently fulfill the OpenZFS/Ceph-class narrative; that is
the target, not a present-tense capability claim.

This repository is the fresh TideFS tree on `master`; source paths, crates,
binaries, and docs should use TideFS names.

The primary remote is the public repository `tidefs/tidefs` on GitHub; the
operator approved making that main repository public on 2026-06-21. Public
visibility is a read boundary only, not a product release: outsider interaction
remains restricted by the documented public-read controls in `docs/GITHUB_CI.md`,
and TideFS infrastructure, runner credentials, deployment keys, API tokens, TLS
keys, and other secrets remain outside this repository. The companion
`tidefs/tidefs-infra-configuration` repository remains private.

## Product Contract

This section is the canonical product shape for TideFS. It is a product
contract, not a roadmap and not a status report. It defines the final target
shape; current capability remains controlled by the claim registry, review
register, and live issues/PRs.

No other document, issue, prototype, crate, daemon, command, test, or
automation path may add a user-facing TideFS product mode or public product
surface by implication. If the final product shape changes, this section must
change in the same reviewable path.

### Canonical Shape

TideFS is installable host storage software. The finished product manages
operator-selected local storage devices as TideFS pools, then exposes storage
from those pools as mounted filesystems or block volumes. It is local-first:
single-node local operation is a final product mode, not a temporary bring-up
shortcut. Clustered operation is an additional final product mode, not a
replacement for local operation.

The final product object model is limited to:

- Device: a local storage device admitted to, removed from, or rejected by a
  TideFS pool.
- Pool: an imported or importable ownership boundary over one or more devices.
- Filesystem: a mountable namespace allocated from one pool.
- Volume: a block-volume object allocated from one pool.
- Snapshot: a read-only point-in-time state of a filesystem or volume.
- Clone: a writable object derived from a snapshot, if and only if the relevant
  mode admits clone support.

Objects outside that list are not product objects unless this contract is
updated.

The finished product has exactly these user-facing storage modes:

- Local mounted filesystem: one node owns local devices, imports a local pool,
  and exposes a mounted filesystem path.
- Local block-volume export: one node owns local devices, imports a local pool,
  and exposes block volumes.
- Clustered mounted filesystem: two or more nodes use explicit membership,
  ownership, fencing, and recovery rules to expose mounted filesystem access.
- Clustered block-volume export: two or more nodes use explicit membership,
  ownership, fencing, and recovery rules to expose block volumes.

For this contract, local means no peer is required for correct operation.
Clustered means peer membership, ownership transfer, loss handling, and fencing
are part of the product behavior. Mounted filesystem means a path mounted on a
host. Block-volume export means a block device or export endpoint with
documented read, write, flush, barrier, resize, discard, and fencing behavior.

### Product Surfaces

The finished product exposes storage behavior only through these public
surfaces:

- `tidefsctl` for operator inspection and control.
- Mounted filesystem paths for advertised filesystem modes.
- Block device or block export paths for advertised block-volume modes.
- Runtime state for the current owner, peer membership, devices, pools,
  filesystems, volumes, snapshots, clones, and recovery state.
- Validation evidence packets tied to the claim registry for publishable
  capability claims.
- Repository documentation and generated claim registers as the publication
  authority for what is promised, proven, blocked, or intentionally excluded.

Internal crates, helper binaries, test fixtures, validation harnesses, service
protocols, on-disk implementation details, and automation endpoints are not
public product surfaces merely because they exist. A daemon, kernel module, or
background worker may be required implementation machinery, but it is not an
operator product interface unless this contract or a current repo-local
authority document names that interface as public.

### Required Final Behavior

Every finished mode above must define its supported, refused, and failure
behavior before that mode can be treated as part of the product. Silent
best-effort behavior is not a product contract. Each mode must have explicit
answers for:

- Device admission, rejection, identity, ownership, loss, replacement, rebuild,
  removal, and offline handling.
- Pool create, import, export, destroy, device membership, degraded import, and
  refused import behavior.
- Filesystem create, mount, unmount, destroy, capacity limit, reserve, snapshot,
  restore, and reclaim behavior for mounted filesystem modes.
- Volume create, open/export, close/unexport, destroy, capacity limit, resize,
  snapshot, restore, and reclaim behavior for block-volume modes.
- Clone behavior, either as supported behavior with validation evidence or as an
  explicit refusal in each mode.
- Crash recovery to the last committed root, or an explicit integrity or media
  failure when recovery cannot be completed.
- Integrity verification using checksums or equivalent end-to-end protection,
  plus operator-visible scrub and repair outcomes.
- Mounted filesystem durability boundaries for writeback, page cache, `fsync`,
  `fdatasync`, `mmap`, rename, link, unlink, truncate, and directory updates.
- Block-volume durability boundaries for flush, FUA or equivalent barriers,
  resize, discard, fencing, and ownership transfer.
- Local and clustered accounting from live state, not stale declarations.
- Operator-visible truth for current ownership, peer health, offline devices,
  rebuild progress, scrub findings, blocked operations, refused operations, and
  recovery state.
- Kernel-resident data paths where the product claims kernel-resident behavior;
  user-space shims do not satisfy those claims.
- Repeatable validation that records the tested build, configuration, devices,
  commands, results, and claim identifiers.

### Exclusions

The product contract also excludes interpretations that would make the target
ambiguous:

- TideFS is not defined as a cloud service, hosted control plane, or appliance.
- TideFS is not cluster-only; local operation remains a first-class product
  mode.
- TideFS is not a generic object store, key-value store, database, backup
  product, orchestration platform, or Kubernetes storage product.
- TideFS does not include a browser UI, REST API, multi-tenant control plane,
  remote management service, package repository, installer appliance, or hosted
  telemetry service as final product surface.
- TideFS is not production-ready.
- TideFS does not claim matching OpenZFS or Ceph behavior.
- TideFS is not POSIX-complete.
- TideFS does not claim a final distributed operator UAPI.
- Unreleased data formats and control surfaces do not carry compatibility
  promises unless a repo-local authority document says so explicitly.
- Separate requirements, roadmap, status, or vision Markdown roots must not be
  created for this same product story.

Current implementation status and blockers belong in
`docs/CLAIMS_GATE_POLICY.md`, generated `docs/CLAIM_REGISTRY.md`,
`docs/REVIEW_TODO_REGISTER.md`, and live GitHub issues and pull requests.

## Current Policy

- License: `GPL-2.0-only WITH Linux-syscall-note`.
- Durable review debt belongs in `docs/REVIEW_TODO_REGISTER.md`; inline notes
  are only short pointers to register entries.
- Test changes must follow `docs/TEST_SIGNAL_POLICY.md`: prefer product and
  invariant signal over test-count growth, marker checks, and stale fixtures.
- Unreleased internal surfaces must follow
  `docs/UNRELEASED_AUTHORITY_POLICY.md`: choose current authority instead of
  preserving pre-release paths as legacy compatibility or migration debt.
- Control formats and JSON usage must follow
  `docs/CONTROL_FORMAT_AND_JSON_POLICY.md`: JSON is acceptable for explicit
  evidence, diagnostics, support, trace, and expert export surfaces, not as the
  default operator UX, hot-path protocol, or durable product format.
- Mounted device-level compression and encryption are blocked behind
  `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`; lower object-store
  wrappers are not an end-to-end mounted filesystem claim.
- Publishing-facing capability wording must pass
  `cargo run -p tidefs-xtask -- check-claims-gate`.
- Commits should be clean, scoped, and bisectable in the same spirit as Linux
  kernel development.

## Layout

```text
apps/        runnable daemons, demos, and operator tools
crates/      storage core, adapters, kernel-facing crates, and shared types
docs/        design docs, review policy, and debt register
kmod/        Rust-for-Linux bridge substrate
xtask/       repo checks and developer commands
```

## Build

Keep Cargo output outside the repository:

```sh
export CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target
cargo check --workspace --locked
```

## Start Here

Use this repo-local reading order before changing behavior or documentation:

1. `README.md` - repository overview and current policy summary
2. `AGENTS.md` - agent and managed-worker contract
3. `CONTRIBUTING.md` - contribution, local build, and PR guidance
4. `docs/GITHUB_CI.md` - CI workflow, validation lanes, and secret boundary
5. `docs/CLAIMS_GATE_POLICY.md` - publishing-facing claim guardrails
6. `docs/REVIEW_TODO_POLICY.md` - durable review-debt policy
7. `docs/REVIEW_TODO_REGISTER.md` - current review-debt register
8. `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` - document authority and classification
9. `docs/INDEX.md` - documentation index and authority-family map

Read `docs/LICENSING.md`, `docs/TEST_SIGNAL_POLICY.md`,
`docs/UNRELEASED_AUTHORITY_POLICY.md`, and
`docs/CONTROL_FORMAT_AND_JSON_POLICY.md` when a change touches those surfaces.
