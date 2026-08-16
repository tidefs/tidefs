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

For this pilot, the selected carrier is `tidefsctl pool mount` calling the
library `tidefs_posix_filesystem_adapter_daemon::run_mount` path. Mounted
validation creates regular-file device pools through `tidefsctl pool create`
and exercises that same carrier; the daemon binary has no separate local mount
or smoke carrier. Ordinary development is selected by this contract, current
source, and live issues and pull requests; publication claims do not select or
block that work.

The default `tidefsctl` build is this local pool, mount, device, dataset,
snapshot, defrag, live-owner, and status carrier. Block-volume commands,
cluster authority, remote snapshot transport, kernel/validation diagnostics,
receive-merge inspection, optional data policy, and storage-intent policy
inspection remain in the same CLI source behind the explicit `block-volume`,
`cluster`, `remote-snapshot`, `diagnostics`, `receive-merge`, `data-policy`, and
`storage-intent` features. Packaging that needs every retained development
surface selects the `full` feature explicitly; the default does not carry
unavailable commands in its parser, help, or command-classification registry.

The default `tidefs-local-filesystem` package is the standalone Pool-backed
mounted core. Replication I/O, quorum writes, distributed repair and erasure,
policy observation, and optional data policy are source-owned Cargo features;
`full` restores the retained development subsystems without changing the
default mount authority.

The current source also implements one bounded pilot lifecycle operation:
`tidefsctl device remove` can route to the reachable mounted local owner of a
Pool with one mounted filesystem, its data-retaining snapshot-table snapshots
and clones, and active unmounted independent filesystem datasets with their own
data-retaining snapshot-table roots; evacuate receipt-backed objects; reconcile
embedded content receipt generations through copy-on-write manifests; refresh
every affected authenticated filesystem and snapshot root; and publish a
redundant survivor-only topology before reporting success. Before evacuation
the owner authenticates every current filesystem root plus each retained
snapshot record, matching catalog entry, typed Pool snapshot root, exact
captured filesystem root, and complete captured content graph through the
shared Pool runtime. Mounted records also require their live lifecycle pins;
opening an independent successor reconstructs its pins from the authenticated
records. The owner durably queues predecessor manifests and publishes each
filesystem state plus all of its changed typed snapshot roots before topology
publication.
Before mutation, redundant member labels record a versioned, checksummed
removal intent bound to the Pool GUID, target member index and GUID, and
successor topology generation; paths are descriptive runtime locators only.
Reopen selects exact lifecycle agreement from the highest complete label
topology before receipt recovery and resumes without a host-side marker file or
runtime directory. Co-owned Pool-runtime volumes, volume snapshots, and volume
clones survive because their immutable typed roots carry keys and digests while
Pool lifecycle relocates their complete receipt-backed object graphs. Removal
still refuses before evacuation for independently mountable filesystem dataset
clones, non-active filesystem datasets, or simultaneous multi-mounted
ownership. This is current implementation behavior, not a production-readiness,
failed-device, replacement, rebuild, secure-erase, media-remanence,
sanitization, or decommissioning claim.

The same carrier implements one bounded present-member replacement row:
`tidefsctl device replace` routes only to the reachable mounted local owner of
an exact writable two-member `Replicated { copies: 2 }` Pool. Redundant labels
persist checksummed old/new GUID identity, member index, successor topology
generation, rebuild progress, and terminal state before mutation; no host-side
evidence file is recovery authority. The owner keeps the readable old member
attached and allocation-fenced, rewrites current receipt-backed objects onto
the survivor plus replacement, copy-on-writes mounted content manifests,
refreshes the authenticated root ring, and only then publishes redundant
same-cardinality labels. Replacement requires a distinct blank same-backing
candidate with sufficient capacity. It preserves co-owned Pool-runtime
volumes, volume snapshots, volume clones, and active unmounted independent
filesystem roots through the same preflight, copy-on-write reconciliation, and
typed-root publication order. Data-retaining snapshot-table snapshots and
clones of the mounted filesystem and every admitted active independent
filesystem also survive through exact captured-root authentication,
captured-manifest copy-on-write, and one canonical publication of each owning
filesystem state plus its changed typed snapshot roots. It still refuses
independently mountable filesystem dataset clones and non-active filesystem
datasets. This row does not claim failed-member rebuild, writable degraded
operation, simultaneous multi-mounted filesystem atomicity, secure erase,
media remanence, sanitization, decommissioning, or production readiness.

The offline local carrier implements one bounded Pool-destroy row for an exact
exported Pool supplied with all member paths. `tidefsctl pool destroy` writes
and rereads a complete `Destroyed` trailing-label family before promoting and
rereading the primary family. With `--zero-superblock`, it then zeroes and
verifies each full trailing label area before each primary label area, so
success leaves no redundant label copy discoverable or importable. The command
reports this as label-area hygiene and explicitly makes no media-privacy,
secure-erase, sanitization, or decommissioning claim. It does not erase Pool
data regions, destroy an imported/live owner, or establish general
production-ready Pool destruction.

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
