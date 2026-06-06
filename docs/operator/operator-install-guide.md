# TideFS Operator Install and Upgrade Guide

This guide covers installing TideFS on a clean Linux machine, creating a
upgrading to a new version, and rolling back.

TideFS is pre-alpha. Do not use it for real data. This guide documents the
current operator workflow from a clean host. Read
[docs/REVIEW_TODO_REGISTER.md](../REVIEW_TODO_REGISTER.md) and

---

## 1. Prerequisites

- x86_64 Linux host (kernel 5.15 or later for FUSE; 7.0 for full-kernel
  mode)
- Nix package manager with flakes enabled
- FUSE kernel module loaded (`/dev/fuse` accessible)
- 500 MB free disk space for a minimal pool

**Enable Nix flakes.** If Nix is not already installed:

```sh
curl -L https://nixos.org/nix/install | sh
```

Add this to `~/.config/nix/nix.conf` or `/etc/nix/nix.conf`:

```
experimental-features = nix-command flakes
```

**Verify FUSE** is available:

```sh
ls -l /dev/fuse
# If missing: modprobe fuse (as root)
```

TideFS uses Nix to provide a pinned Rust toolchain and build dependencies.
No host-global Rust or cargo installation is needed.

---

## 2. Obtaining TideFS

Clone the repository and build:

```sh
git clone http://172.16.106.12/forgejo/tidefs/tidefs.git
cd tidefs
nix build .#packages.x86_64-linux.default
```

This produces `./result/bin/` containing the seven workspace binaries:

| Binary | Purpose |
|---|---|
| `tidefs-posix-filesystem-adapter-daemon` | FUSE daemon for POSIX filesystem access |
| `tidefs-block-volume-adapter-daemon` | ublk daemon for block device export |
| `tidefs-storage-node` | Multi-node storage daemon |
| `tidefsctl` | Operator CLI (pool, dataset, snapshot, device, block) |
| `tidefs-filesystem-demo` | Local filesystem demo |
| `tidefs-store-demo` | Object store demo |
| `tidefs-xtask` | Development task runner |

For operator workflows, `tidefsctl` is the primary interface. The FUSE and
ublk daemons are launched by it.

**Install to profile** (optional, for permanent `PATH` availability):

```sh
nix profile install ./result
```


```sh
tidefsctl --version
tidefs-posix-filesystem-adapter-daemon --version
```

---

## 3. Creating a Storage Pool

A TideFS pool is a collection of block devices or regular files (development
mode) that store all data, metadata, and committed roots.

### 3.1 Create a pool on block devices

```sh
tidefsctl pool create mypool --devices /dev/sdb /dev/sdc
```

This writes dual-copy pool labels and an initial committed root (epoch 1).
The pool is left in **exported** state.

**Redundancy options:**

| Flag | Behavior |
|---|---|
| `--redundancy single` | One full copy on one eligible device (default) |
| `--redundancy replicated=N` | `N` full copies on distinct eligible devices |
| `--redundancy erasure=D+P` | Erasure placement with `D` data shards and `P` parity shards on distinct eligible devices |

The selected policy is pool-wide and is persisted in every pool member label.
It does not pre-create fixed RAIDZ-like or vdev-like groups; placement receipts
record the exact devices selected for each allocation.

**Encryption (optional):**

```sh
tidefsctl pool create mypool --devices /dev/sdb \
  --feature-flags encryption \
  --encryption-envelope ./mypool.key
```

Keep `./mypool.key` safe. It is required for every subsequent import.

### 3.2 Create a pool on regular files (development only)

```sh
truncate -s 2G /tmp/pool1.img
truncate -s 2G /tmp/pool2.img
tidefsctl pool create mypool --devices /tmp/pool1.img /tmp/pool2.img --file-devices
```

The `--file-devices` flag is hidden and intended for development. Directory
object-store paths are compatibility/offline storage only, not pool members.

### 3.3 Import the pool into a live owner

A newly created pool is exported. In the current userspace path, importing for
use means starting the runtime that owns the live state:

```sh
tidefsctl pool mount mypool /mnt/tidefs --devices /dev/sdb /dev/sdc
# or with file devices:
tidefsctl pool mount mypool /mnt/tidefs --devices /tmp/pool1.img /tmp/pool2.img
```

With encryption:

```sh
tidefsctl pool mount mypool /mnt/tidefs \
  --devices /dev/sdb /dev/sdc \
  --encryption-envelope ./mypool.key
```

Plain `tidefsctl pool import mypool` is an owner-mediated request, not a
live-state owner by itself. Do not use it as a substitute for the kernel UAPI
or a userspace daemon endpoint.

### 3.4 Check pool status

```sh
tidefsctl pool status mypool --devices /dev/sdb /dev/sdc
tidefsctl pool status mypool --json  # machine-readable
```

Use `--devices` only for exported/offline status or discovery. Once the pool is
imported, `tidefsctl pool status mypool` routes to the live owner instead of
opening the devices. A stale `/run/tidefs/pools/.../owner.json` file is not
itself a live owner interface. For userspace owners the socket must be
reachable; for kernel owners the kernel UAPI client must be wired and usable.
If labels still show an imported pool and no supported owner interface responds,
repair or restart the kernel UAPI or userspace daemon owner before running
live-state commands. Do not open the cached imported state directly.

`tidefsctl kernel status` is the passive kernel-runtime inventory for the
current pre-alpha kernel surface. It checks the declared control endpoint path
and reports source-visible runtime surfaces such as TideFS-owned kthreads and
workqueues, but it does not open `/dev/tidefs-control`, issue ioctls, or make a
kernel owner manifest authoritative.

---

## 4. Mounting the Filesystem

Once the pool is imported, mount it through the FUSE adapter.

### 4.1 Direct FUSE mount (daemon launch)

```sh
tidefsctl mount /tmp/tidefs-store /mnt/tidefs
```

This starts the FUSE daemon in the foreground, mounting the pool at
`/mnt/tidefs`. Use `Ctrl-C` or `fusermount3 -u /mnt/tidefs` to stop.

### 4.2 Pool-aware mount (import + live owner in one step)

```sh
tidefsctl pool mount mypool /mnt/tidefs --devices /tmp/pool1.img /tmp/pool2.img
```

The `--devices` form imports exported storage and starts the userspace FUSE
owner. If the pool is already imported, omit `--devices`; the command talks to
the runtime owner instead of reopening the devices. The current userspace FUSE
owner fails closed for additional mount requests until owner-side secondary
mount/session creation is implemented.

For a specific dataset:

```sh
tidefsctl pool mount mypool /mnt/tidefs \
  --devices /dev/sdb /dev/sdc \
  --dataset mydataset
```

Read-only mount:

```sh
tidefsctl pool mount mypool /mnt/tidefs \
  --devices /dev/sdb /dev/sdc \
  --read-only
```

### 4.3 Daemon-only mount (low-level FUSE launch)

The daemon binary can also be invoked directly:

```sh
tidefs-posix-filesystem-adapter-daemon mount-vfs \
  --store /tmp/tidefs-store \
  --mount /mnt/tidefs \
  --root-auth-key-hex "$(openssl rand -hex 32)"
```

### 4.4 Verify the mount

```sh
mountpoint /mnt/tidefs
ls -la /mnt/tidefs
df -h /mnt/tidefs
stat /mnt/tidefs
```

---


### 5.1 Operator demo script

operations, and persistence across remount:

```sh
scripts/tidefs-operator-demo.sh \
  --daemon-bin ./result/bin/tidefs-posix-filesystem-adapter-daemon
```

This runs 16 operations (pool create, mount, file create/write/read/stat,
mkdir, rmdir, rename, hard link, symlink, truncate, append, unmount,

Exit codes:
- `0` — all operations passed
- `1` — at least one operation failed
- `2` — environment refusal (no FUSE, no daemon binary)

### 5.2 Smoke mount

```sh
tidefs-posix-filesystem-adapter-daemon smoke-mount
```

This creates a temporary store and mountpoint, exercises the first-current
operations, then cleans up.


```sh
```

mounted-kernel, kernel block-I/O, and xfstests behavior. Nix builds artifacts
only; the `qemu-system-*` process and runtime tests must launch outside the Nix
build sandbox. Host-kernel FUSE/ublk/mount tests are not autonomous development
outside-sandbox runners.

---

## 6. Daily Operations

### 6.1 Managing datasets

```sh
# Create a dataset
tidefsctl dataset create mypool mydataset

# List datasets
tidefsctl dataset list mypool

# Rename
tidefsctl dataset rename mypool mydataset newname

# Destroy (requires empty dataset)
tidefsctl dataset destroy mypool mydataset
```

### 6.2 Managing snapshots

```sh
# Create a snapshot
tidefsctl snapshot create mypool mysnap

# List snapshots
tidefsctl snapshot list mypool

# Destroy
tidefsctl snapshot destroy mypool mysnap

# Export and receive a changed-record snapshot stream
tidefsctl snapshot send mypool --output /tmp/mypool.vfssend1
tidefsctl snapshot receive --backing-dir /tmp/received-pool --input /tmp/mypool.vfssend1
```

For an imported pool, the full `snapshot send --output` form asks the live
owner to export from its mounted state and write the stream. Live network push
and live incremental send are not owner-side paths yet, so those forms fail
closed instead of opening storage behind the owner. Snapshot receive remains an
explicit target-store operation.

For exported/offline pools, the same dataset and snapshot commands may take
`--devices`. That direct-device form stays offline; it does not import the pool
or create `/run/tidefs/pools/<uuid>` runtime ownership as a side effect. If the
live-owner registry already names that pool UUID, the CLI routes to that exact
owner. An on-disk `ACTIVE` label is cached recovery evidence rather than the
owner interface itself, but it is not ordinary exported storage. Without a
reachable owner interface, live-state commands fail closed; repair or restart
the kernel UAPI or userspace daemon owner, then operate through that owner.

### 6.3 Block device export

```sh
# Request a ublk block export from the imported pool owner
tidefsctl block attach mypool

# Development/exported object-store attach path
tidefsctl block attach mypool --backing-dir /var/lib/tidefs/mypool

# List exported block devices
tidefsctl block list

# Detach
tidefsctl block detach <dev-name>
```

The pool-name form routes to the live owner. If the FUSE, ublk, or kernel
owner does not implement block export yet, it fails closed instead of opening
storage behind that owner. The `--backing-dir` form is only for exported or
offline object-store development paths. If a reachable owner manifest names
both that pool and the same backing directory, the command routes to that exact
owner; it must not route by pool name alone. If any imported-pool owner
manifest names the backing directory for a different pool, the command refuses
instead of opening that cached imported state as offline storage.
`tidefsctl block send` and
`tidefsctl block receive` follow the same split: pool-name form through the
owner, explicit `--backing-dir` for exported/offline object-store work.
Snapshot `--backing-dir` commands have no pool operand, so they route by the
reachable owner manifest for that backing directory before opening or writing
the object store directly.

### 6.4 Device management

```sh
# Request live owner-mediated removal from an imported pool
tidefsctl device remove mypool /dev/sdc

# Exported/offline removal spells its storage handles explicitly
tidefsctl device remove mypool /dev/sdc --backing-dir /var/lib/tidefs/device-sdc --surviving-dirs /var/lib/tidefs/device-sdb

# Trigger rebuild after device replacement
tidefsctl device rebuild
```

The pool name is the live-owner identity. If `mypool` is imported, device
removal routes to that owner. The current userspace FUSE owner executes
mounted-pool evacuation through its live `Pool` state and refuses `--force`;
kernel-owner removal and active-label topology persistence remain bounded
follow-up work. The backing-directory form is only for exported/offline
storage.
The offline form probes existing labels without creating or opening the store
writable. Those labels provide topology and recovery evidence. If they identify
`ACTIVE` imported state, the request routes to the owner interface or fails
closed; it does not evacuate through direct storage access.
`--surviving-dirs`, `device rebuild --surviving-dir`, and
`device rebuild --replacement-dir` are offline object-store paths as well. They
must not point into `/run/tidefs/pools` or any backing directory named by an
imported-pool owner manifest.

`tidefsctl pool integrity-check mypool` uses the same boundary. Pool-name
checks route to the kernel UAPI or userspace daemon owner for imported state.
Direct storage scans are only for exported/offline or not-yet-imported storage
named explicitly with `--devices` and/or `--backing-dir`; if those inputs name
runtime state or an imported-pool owner manifest, the command routes to that
owner interface or fails closed.

### 6.5 Pool export (deactivate)

```sh
tidefsctl pool export mypool
tidefsctl pool export mypool --force
```

Export makes the pool inactive. Use it before system shutdown, device
maintenance, or when moving devices between hosts.

---

## 7. Upgrade

Upgrading TideFS has two parts: updating the software binaries, and
upgrading on-disk dataset feature flags.

### 7.1 Upgrade the software

```sh
cd tidefs
git pull origin master
nix build .#packages.x86_64-linux.default

# If installed to profile:
nix profile upgrade tidefs-workspace
# Or re-install:
nix profile install ./result
```

### 7.2 Unmount and re-export before upgrade

```sh
fusermount3 -u /mnt/tidefs
tidefsctl pool export mypool
```

### 7.3 Import and mount with the new version

```sh
tidefsctl pool mount mypool /mnt/tidefs --devices /dev/sdb /dev/sdc
```

### 7.4 Upgrade dataset feature flags

After the software is updated, upgrade on-disk datasets to enable new
features supported by the new version:

```sh
tidefsctl dataset upgrade mypool mydataset
```

This uses the upgrade table (`SupportedFeaturesV1`) to enumerate every
feature the current software version supports, then enables each
supported-but-not-yet-enabled feature on the dataset with prerequisite
checking.

Output shows:
```
dataset 'mydataset' upgrade complete: 3 enabled, 0 skipped, 0 failed
```

Run this for each dataset in the pool. The `root` dataset is typically
upgraded first.

### 7.5 Verify after upgrade

```sh
scripts/tidefs-operator-demo.sh \
  --daemon-bin ./result/bin/tidefs-posix-filesystem-adapter-daemon
```

Check pool status and verify existing data is accessible:

```sh
tidefsctl pool status mypool --json
ls -la /mnt/tidefs
```

---

## 8. Rollback

If an upgrade causes problems, roll back to the previous version.

### 8.1 Stop all mounts

```sh
fusermount3 -u /mnt/tidefs
tidefsctl pool export mypool
```

### 8.2 Roll back the software

If using `nix profile`:

```sh
# List generations
nix profile history

# Roll back to previous generation
nix profile rollback --to <generation-number>
```

If building directly:

```sh
cd tidefs
git checkout <previous-commit>
nix build .#packages.x86_64-linux.default
```

### 8.3 Re-import and mount

```sh
tidefsctl pool mount mypool /mnt/tidefs --devices /dev/sdb /dev/sdc
```

### 8.4 Verify recovery

```sh
scripts/tidefs-operator-demo.sh \
  --daemon-bin ./result/bin/tidefs-posix-filesystem-adapter-daemon
```

**Note**: Dataset feature flags enabled by the newer version are not
automatically downgraded. TideFS forward-compatibility is not yet guaranteed
for all feature combinations. If rollback fails due to feature-flag
incompatibility, contact the TideFS development team with the pool status
output and the version you are rolling back from and to.

---

## 9. Pool Destruction

To completely remove a pool and its data:

```sh
# Ensure the pool is exported first
tidefsctl pool export mypool --force

# Destroy the pool (zeroes pool labels on each device)
tidefsctl pool destroy mypool --devices /dev/sdb /dev/sdc --force --zero-superblock
```

For an imported pool, `tidefsctl pool destroy mypool` asks the live owner. The
current userspace owner fails that request closed; export or unmount first,
then use the explicit `--devices` form on exported storage.

Without `--zero-superblock`, only the label headers are removed. With it,
the superblock regions on each device are also zeroed.

---

## 10. Uninstalling TideFS

Remove the Nix profile installation:

```sh
nix profile remove tidefs-workspace
```

Remove the cloned repository and build artifacts:

```sh
rm -rf ~/tidefs /tmp/tidefs-workers
```

---

## 11. Troubleshooting

### FUSE device not found

```
fuse: device not found
```

Load the kernel module:

```sh
modprobe fuse
ls -l /dev/fuse
```


```sh
nix run .#qemu-smoke
```

### Permission denied on /dev/fuse

Add your user to the `fuse` group or adjust permissions:

```sh
usermod -a -G fuse $USER
# Log out and back in, or:
chmod 666 /dev/fuse
```

### Mountpoint not empty

```
fuse: mountpoint is not empty
```

Choose an empty directory or clear the mountpoint:

```sh
rm -rf /mnt/tidefs/*
# or use a different path
```

### Devices busy on export

```
pool export failed: device busy
```

Ensure all mounts are unmounted and no process is using the pool:

```sh
fusermount3 -u /mnt/tidefs
lsof /dev/sdb  # check for open handles
tidefsctl pool export mypool --force
```

### Dataset upgrade failed

```
dataset upgrade: feature 'compression' requires prerequisite 'encryption'
```

Some features have prerequisites. Enable prerequisites first, or check the
upgrade table for the correct ordering. The upgrade output lists which
features were skipped and why.

### Daemon exited before mount

Check the daemon log. When using operator demo:

```sh
```

Common causes: store path not writable, key mismatch, or corrupted pool
state.

---

## 12. Reference

- [Clustered Pool Workflow](clustered-pool-workflow.md) — multi-node cluster pool operation
- [Getting Started](../GETTING_STARTED.md) — developer workflow
- [User Manual](../USER_MANUAL.md) — supported POSIX operations
- [FUSE Mount](../FUSE_MOUNT.md) — FUSE adapter details
- [Review TODO Register](../REVIEW_TODO_REGISTER.md) — current capability blockers
- [Cutover and Rollback Playbook](../release/cutover-fallback-rollback-playbook.md) — kernel-mode transitions
- [Upgrade Failover Cutover Runbooks](../UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md) — design-level operator law
