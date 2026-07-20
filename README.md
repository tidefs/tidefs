# TideFS

TideFS is a pre-alpha Rust filesystem and storage stack pursuing
OpenZFS/Ceph-class reliability and scale. It does not currently fulfill that
target and is not production-ready.

The public `tidefs/tidefs` repository is not a product release. Outsider
interaction remains restricted by `docs/GITHUB_CI.md`; infrastructure and
secrets remain outside it, and `tidefs/tidefs-infra-configuration` remains
private.

## Product Contract

This is TideFS's sole authority for product modes and public surfaces. It
defines the final target, not present support. No mode below is currently
supported. Source plus focused tests through the relevant product surface
establish current behavior. Issues and pull requests select work and record
blockers. Claims, evidence packets, generated registers, and release verdicts
belong only to publication decisions; they neither establish capability nor
complete ordinary development.

No other document, issue, prototype, crate, daemon, command, test, or automation
may imply a user-facing mode or surface. Changes to the final shape must update
this section in the same review.

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

These surfaces are product carriers only when they exercise the real
implementation path. Internal crates, helpers, fixtures, harnesses, protocols,
on-disk details, daemons, kernel modules, background workers, and automation
endpoints are not public interfaces merely because they exist.

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
- Clone behavior, either supported and tested or explicitly refused in each
  mode.
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
- Repeatable tests through the relevant product surface for each supported,
  refused, and high-risk failure behavior.

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
  promises except for a named, tested external ABI, protocol, or operator-owned
  data set.
- Separate requirements, roadmap, status, or vision Markdown roots must not be
  created for this same product story.

## Current Development Direction

The first pilot targets one local, single-node mounted-filesystem carrier:
`tidefsctl` creates or imports a pool and creates one filesystem; the actual
POSIX/FUSE path mounts it; real file and directory I/O exercises storage;
`fsync`/`fdatasync` and rename durability are observed; the process stops or
crashes; the pool reopens; data and metadata are read back through the mount
with integrity verification; truthful status is inspected; the filesystem
unmounts; and the pool exports and reimports.

This sequence is an acceptance target, not present support. The mounted path
remains a development harness until the full lifecycle passes focused boundary
tests. Block-volume, kernel-resident, and clustered modes follow unless a
demonstrated safety prerequisite requires earlier work.

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
- Until its aggregate-check wiring is removed, the existing
  `cargo run -p tidefs-xtask -- check-claims-gate` command remains a
  compatibility check for publication metadata. It neither establishes
  capability nor completes ordinary work.
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

The complete baseline for ordinary work is:

1. `README.md` — product contract and current development direction;
2. `AGENTS.md` — repository development rules; and
3. `CONTRIBUTING.md` — contribution path and ordinary definition of done.

Load specialized references only when the touched surface needs them.
`CONTRIBUTING.md` routes to testing, CI and secrets, licensing, review debt,
unreleased compatibility, and control-format policy. `docs/INDEX.md` is
optional navigation for those references and for claims/publication,
architecture, and operator documents; it is not baseline authority.
