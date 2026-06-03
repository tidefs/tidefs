# xfstests harness

Practical guide for running xfstests against the TideFS FUSE implementation.

## Quick start


```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-fuse-xfstests"
  --tests "generic/001" \
  --output "$OUT"
```

Run the #6582 smoke tranche:

```bash
TESTS="generic/001 generic/002 generic/003 generic/004 generic/005 generic/006 generic/007 generic/008 generic/009 generic/010 generic/011 generic/012 generic/013"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-fuse-xfstests-001"
  --tests "$TESTS" \
  --output "$OUT"
```

For local diagnostics inside an environment that already has usable FUSE and
xfstests support, run specific tests through the scoreboard wrapper:

```bash
TIDEFS_XFSTESTS_TESTS="generic/001 generic/002 generic/035" \
TIDEFS_XFSTESTS_CHECK_ARGS="-fuse" \
```

Local host `/dev/fuse` runs are diagnostic only. Autonomous closure for FUSE
the `qemu-system-*` process launches outside the Nix build sandbox.

## Nix app entrypoints

  `--keep-tmp`.
- `nix run .#xfstests-runner` - convenience wrapper for xfstests-only
  scoreboard runs in a prepared mounted-userspace environment. Supports
  `--quick`, `--auto`, `--tests`, `--per-test`, and `--out`.
- `nix run .#posix-scoreboard` - full POSIX scoreboard (fio, fsx, fsstress,
  pjdfstest, xfstests). Set `TIDEFS_XFSTESTS_NIX_PACKAGE=1` to enable the
  xfstests lane.

## Mount helper

The FUSE mount helper (`tidefs-xfstests-mount`, symlinked as `tidefs-preview`) is what xfstests calls via `mount.fuse`. It:

1. Creates a per-mount backing store under `$TIDEFS_XFSTESTS_STORE_ROOT` (default: `/tmp/tidefs-xfstests-store`)
2. Launches `tidefs-posix-filesystem-adapter-daemon mount --store <dir> --mount <mountpoint>` in background
3. Waits for the daemon's ready/refusal receipt, then exits without owning
   live mount state

`tidefs-preview` helper. That helper derives the backing store from the
xfstests device name, so `_test_cycle_mount` remounts see the same test
filesystem contents while per-row cleanup still resets the store before the
next row. The generated guest `umount` wrapper waits for the matching daemon
to exit before remounting the same store, so short scratch mount cycles do not
race a previous writer.
The generated helper mounts with the daemon's `writeback` coherency profile
without enabling the FUSE kernel writeback-cache flag; ordinary opens therefore
remain mmap-capable instead of advertising `FOPEN_DIRECT_IO`, while explicit
`O_DIRECT` opens still use the direct-I/O path. It also provisions a 2 GiB
content-capacity ceiling for each per-row TideFS store, so sparse/truncate
xfstests rows that require 256 MiB scratch files do not fail against the
daemon's smaller default 64 MiB local-filesystem capacity. The guest backs
`/store` with a host-created ext4 raw image attached as a virtio disk
(`TIDEFS_FUSE_XFSTESTS_STORE_IMAGE_MB`, default 8192 MiB), so large mmap and
rewrite-heavy rows exercise real guest storage instead of filling the initrd
root filesystem.
The QEMU guest defaults to 2048 MiB of RAM because mmap-heavy rows such as
`generic/344` simultaneously exercise the kernel page cache, the test process,
and the userspace daemon; override with
`TIDEFS_FUSE_XFSTESTS_QEMU_MEMORY_MB` only when deliberately testing tighter
memory pressure.

Debug with `TIDEFS_XFSTESTS_DEBUG=1`.

## Exclude list

`scripts/tidefs-xfstests-exclude` contains 45 tests excluded because they require features not yet in the TideFS FUSE adapter:

| Feature area          | Tests excluded |
|-----------------------|---------------|
| ACLs                  | generic/099, 237, 307, 318, 319, 375, 444 |
| Capabilities          | generic/694 |
| Encryption (fscrypt)  | generic/397, 398, 399, 400, 401 |
| Immutable/append-only | generic/079 |
| FS_IOC ioctls         | generic/009 |
| Kernel-specific       | generic/048, 054, 058, 062 |
| Mmap coherency        | generic/091, 215, 216, 223, 224, 225, 226, 228, 229, 230, 231, 235, 239, 247, 248, 252, 255, 263 |
| Mknod device/fifo     | generic/184 |
| Quota                 | generic/244, 245, 383 |
| Swap                  | generic/472, 493, 494 |
| Sub-second timestamps | generic/258 |

Delivered (no longer excluded): O_DIRECT (#876), POSIX file locks (#491/#791),
FIEMAP (#500), fallocate modes (#515), RENAME_EXCHANGE (#532).

The exclude file is passed to xfstests-check via `-E` when `TIDEFS_XFSTESTS_EXCLUDE` is set. Override with:

```bash
TIDEFS_XFSTESTS_EXCLUDE=/path/to/custom-exclude nix run .#xfstests-runner -- --quick
```

## Interpreting the scoreboard

Results land in `<out_dir>/scoreboard.md` and `<out_dir>/scoreboard.tsv`.

- **Passed**: test exited 0 and xfstests `.out.bad` was empty or matched `.out`
- **Failed**: test exited non-zero or output mismatch
- **Skipped**: test was excluded or xfstests could not run it (e.g. missing helper binary)


## Environment variables

| Variable                       | Default              | Description |
|-------------------------------|----------------------|-------------|
| `TIDEFS_XFSTESTS_TESTS`       | `generic/001`        | Space-separated test list |
| `TIDEFS_XFSTESTS_CHECK_ARGS`  | `-fuse`              | Arguments for xfstests-check |
| `TIDEFS_XFSTESTS_EXCLUDE`     | `scripts/tidefs-xfstests-exclude` | Path to exclude file |
| `TIDEFS_XFSTESTS_STORE_ROOT`  | `/tmp/tidefs-xfstests-store` | Backing store root |
| `TIDEFS_XFSTESTS_DEBUG`       | `0`                  | Enable mount helper debug output |
| `TIDEFS_RUN_ID`               | `<date>-xfstests`    | Run identifier |
| `TIDEFS_FUSE_XFSTESTS_QEMU_MEMORY_MB` | `2048` | QEMU guest RAM for the FUSE xfstests runner |
| `TIDEFS_FUSE_XFSTESTS_STORE_IMAGE_MB` | `8192` | Size of the virtio-backed guest `/store` image |

## Baseline

The current smoke baseline starts with the #6582 tranche,
`generic/001` through `generic/013`, the #6584 tranche,
`generic/014` through `generic/050`, and the #6586 tranche,
`generic/051` through `generic/100`, plus the #6588 tranche,
`generic/101` through `generic/150`, the #6590 tranche,
`generic/151` through `generic/200`, and the #6592 tranche,
`generic/201` through `generic/250`, plus the #6594 tranche,
`generic/251` through `generic/300`, plus the #6596 tranche,
`generic/301` through `generic/350`, plus the #6598 tranche,
`generic/351` through `generic/418`, on the current TideFS FUSE adapter inside
the QEMU guest runner. There is no pass-rate gate inherited from a deleted
publishing checklist: each attempted row must be recorded as pass, fail,
unsupported, environment refusal, or deferred product scope with a concrete
reason.

outputs are
for `generic/001` and
for `generic/002` through `generic/013`. The combined result covers
`generic/001` through `generic/013` as PASS with no failed, blocked, or

On commit `302164e2`, an outside-sandbox QEMU/KVM run against Linux 7.0.0
for `generic/014` through `generic/050`. The result covers all requested rows

On commit `a59fbb8a`, an outside-sandbox QEMU/KVM run against Linux 7.0.0
for `generic/051` through `generic/100`. The JSON contains one structured row
for every requested xfstests test: `generic/084` and `generic/086` passed; 16
rows failed as product defects (`generic/053`, `062`, `069`, `070`, `071`,
`074`, `075`, `080`, `087`, `088`, `091`, `095`, `097`, `098`, `099`,
`100`); 15 rows are unsupported feature/precondition rows; and 17 rows are
FUSE mount/sanity/teardown rows, are `passed=12`, `failed=16`, `blocked=0`,
`unsupported=15`, and `skipped=17`.

On commit `b26233d4`, after per-row scratch/result cleanup landed, an
outside-sandbox QEMU/KVM run against Linux 7.0.0 classified the #6588 smoke
for `generic/101` through `generic/150`. The JSON contains one structured row
for every requested xfstests test: `generic/103`, `generic/117`, and
`generic/141` passed; 14 rows failed as product defects (`generic/105`,
`109`, `112`, `113`, `120`, `124`, `126`, `127`, `129`, `130`, `131`, `132`,
`133`, `135`); 24 rows are unsupported feature/precondition rows; and 9 rows
FUSE mount/sanity/teardown rows, are `passed=12`, `failed=15`, `blocked=0`,
`unsupported=24`, and `skipped=9`; the extra failed row is the `unmount`
teardown check reporting `Device or resource busy`. This is classification

On commit `57481d43`, an outside-sandbox QEMU/KVM run against Linux 7.0.0
for `generic/151` through `generic/200`. The JSON contains one structured row
for every requested xfstests test: zero xfstests rows passed; 4 rows failed as
product defects (`generic/169`, `184`, `192`, `198`); 43 rows are unsupported
feature/precondition rows; and 3 rows are environment or feature skips. The
`passed=10`, `failed=4`, `blocked=0`, `unsupported=43`, and `skipped=3`; all
infrastructure rows, including `unmount` and `daemon_stop`, passed. The failed
rows currently expose `FS_IOC_FSGETXATTR`/remount visibility issues
(`generic/169`), special-node `mknod` runtime failure (`generic/184`),
post-sleep timestamp/stat file visibility failure (`generic/192`), and AIO
sparse-file `Bus error` behavior (`generic/198`). This is classification

On commit `2bb253a6`, after the FUSE xfstests guest started using the
coreutils `mv` binary instead of the BusyBox applet, an outside-sandbox
QEMU/KVM run against Linux 7.0.0 classified the #6592 smoke tranche. The
for `generic/201` through `generic/250`. The JSON contains one structured row
for every requested xfstests test: `generic/208`, `210`, `211`, `212`, `221`,
`246`, and `248` passed; 9 rows failed as product or exact-output defects
(`generic/207`, `209`, `214`, `215`, `237`, `239`, `245`, `247`, `249`); 19
rows are unsupported feature/precondition rows; and 15 rows are environment or
mount/sanity/teardown rows, are `passed=16`, `failed=10`, `blocked=0`,
`unsupported=19`, and `skipped=15`; the extra failed row is the `unmount`
teardown check reporting `Device or resource busy`, while `daemon_stop`
passed. The failed rows currently expose timeout hangs (`generic/207`, `209`,
`215`, `249`), fallocate/truncate EIO behavior (`generic/214`), ACL errno
drift (`generic/237`), ENOSPC/truncate output (`generic/239`), a remaining
coreutils `mv` expected-output mismatch (`generic/245`), and missing expected
a pass claim.

On commit `a47833f2`, an outside-sandbox QEMU/KVM run against Linux 7.0.0
for `generic/251` through `generic/300`. The JSON contains one structured row
for every requested xfstests test: zero xfstests rows passed; 6 rows failed as
product or exact-output defects (`generic/257`, `258`, `263`, `285`, `286`,
`294`); 34 rows are unsupported feature/precondition rows; and 10 rows are
FUSE mount/sanity/teardown rows, are `passed=9`, `failed=7`, `blocked=0`,
`unsupported=34`, and `skipped=10`; the extra failed row is the `unmount`
teardown check reporting `Device or resource busy`, while `daemon_stop`
passed. The failed rows currently expose readdir/inode-number drift
(`generic/257`), negative timestamp wrapping (`generic/258`), fsx truncate
EIO (`generic/263`), SEEK_DATA/SEEK_HOLE sanity failure with cleanup EIO
(`generic/285`), a sparse seek timeout (`generic/286`), and special-node or
read-only expected-output drift (`generic/294`). This is classification

On commit `01648bd0`, an outside-sandbox QEMU/KVM run against Linux 7.0.0
output is
for `generic/301` through `generic/350`. That run produced one structured
xfstests row for `generic/301` through `generic/345`, then `generic/346`
wedged in the mmap/write `holetest` path after exceeding the 600s per-test
timeout; the owned guest was terminated and the rescued primary JSON marked
`generic/346` through `generic/350` blocked because no parsed rows appeared
output under
and classified `generic/347`, `generic/348`, `generic/349`, and
`generic/350` as skipped preconditions. Commit `efe90d25` then copied
scratch output under
passed `generic/315`, replacing the primary run's missing-guest-command
failure. The combined xfstests row classification for the #6596 tranche is:
`generic/308`, `generic/315`, `generic/337`, and `generic/339` pass; 11 rows
fail as product or exact-output defects (`generic/306`, `307`, `309`, `310`,
`313`, `318`, `319`, `323`, `340`, `344`, `345`); `generic/346` remains a
blocked hard-hang row; 18 rows are unsupported feature/precondition rows; and
16 rows are environment or feature skips. The failures currently expose
read-only/special-node expected-output drift, ACL and timestamp update drift,
600s timeout hangs, truncate-down timestamp drift, ACL inheritance/userns
errno drift, and ENOSPC/ftruncate/file-exists behavior. This is classification

On commit `8f1e2a71`, an outside-sandbox QEMU/KVM run against Linux 7.0.0
output is
for `generic/351` through `generic/418`. That run produced structured rows
through `generic/395`; `generic/391` timed out after the 600s per-test bound,
and the owned guest was terminated after the wrapper failed to recover cleanly.
The rescued primary JSON marked `generic/396` through `generic/418` blocked
because no parsed rows appeared after the stop. Commit `4c3b6044` then copied
scratch output under
reclassified `generic/360` from a missing guest command to a product or
exact-output failure: the row still emits a missing temporary-file cleanup
line. A committed-head tail run under
classified `generic/396` through `generic/418` without blocked rows. The final
#6598 xfstests row classification is: `generic/377` and `generic/403` pass; 8
rows fail as product or exact-output defects (`generic/354`, `360`, `375`,
`391`, `393`, `394`, `401`, `412`); 20 rows are unsupported
feature/precondition rows; and 38 rows are environment or feature skips. The
failures currently expose ENOSPC/ftruncate/file-exists behavior, missing temp
cleanup after checksum, ACL/SGID permission drift, a direct-I/O timeout hang,
ftruncate EIO/ENOSPC behavior, special-node/find-by-type setup drift, and
pass claim.

The #6587 kernel VFS tranche (`generic/051` through `generic/100`) ran through
the Linux 7.0.0 mounted-kernel VFS runner with the Nix-built
`tidefs_posix_vfs.ko` matching the guest kernel. The accepted row matrix uses
for `generic/061` through `generic/069`,
for `generic/070`,
for `generic/071` through `generic/074`,
for `generic/075` and `generic/077` through `generic/080`,
for `generic/076`,
and
The deferred `generic/070` row from the shared `061-070` run, deferred
`generic/075` through `generic/080` rows from the shared `071-080` run, and
the first isolated `generic/076` harness-timeout row are not used as final row
classification. The final #6587 xfstests row classification is:
`generic/056`, `generic/058`, `generic/059`, `generic/060`, `generic/061`,
`generic/062`, `generic/063`, `generic/064`, `generic/065`, `generic/066`,
`generic/067`, `generic/070`, `generic/071`, `generic/072`, `generic/075`,
`generic/076`, `generic/080`, `generic/088`, `generic/089`, `generic/090`,
`generic/096`, `generic/097`, and `generic/098` pass; 11 rows fail as
product defects (`generic/057`, `generic/069`, `generic/073`, `generic/074`,
`generic/083`, `generic/084`, `generic/085`, `generic/086`, `generic/087`,
`generic/092`, `generic/100`); 12 rows are unsupported feature/precondition
rows; and 4 rows are environment or feature skips. The failures currently
expose silent data loss, timeout hangs, generic xfstests output failure, and
EIO on a valid operation. There are no deferred, harness-fail, or
environment-refusal rows in the accepted matrix. This is mounted-kernel
closure.

The #6589 kernel VFS tranche (`generic/101` through `generic/150`) ran through
the Linux 7.0.0 mounted-kernel VFS runner with the Nix-built
`tidefs_posix_vfs.ko` matching the guest kernel. The accepted row matrix uses
for `generic/101` and `generic/102`,
for `generic/103` through `generic/110`,
for `generic/121` through `generic/127`,
for `generic/128` through `generic/130`,
and
Rows after `generic/102` from the first shared `101-110` run are not used as
final row classification, and deferred `generic/128` through `generic/130`
rows after the `generic/127` timeout are superseded by the isolated
replacement run. The final #6589 xfstests row classification is:
`generic/101`, `generic/103`, `generic/104`, `generic/106`, `generic/107`,
`generic/109`, `generic/112`, `generic/117`, `generic/120`, `generic/124`,
`generic/126`, `generic/131`, `generic/132`, and `generic/141` pass; 3 rows
fail as product defects (`generic/102`, `generic/127`, `generic/129`); 29
rows are unsupported feature/precondition rows; and 4 rows are environment or
feature skips. The failures currently expose repeated clean remount/replay
expected-output drift (`generic/102`) and timeout hangs in `generic/127` and
`generic/129`. There are no deferred, harness-fail, or environment-refusal
for a no-go tranche, not a pass claim or TFR-018 closure.

The #6591 kernel VFS tranche (`generic/151` through `generic/200`) ran through
the Linux 7.0.0 mounted-kernel VFS runner with the Nix-built
`tidefs_posix_vfs.ko` matching the guest kernel. The accepted row matrix uses
and
The wedged shared `161-170` run is not used as final row classification; the
isolated `161-163` and tail `164-170` runs supersede it. The final #6591
xfstests row classification is: `generic/169`, `generic/177`, `generic/184`,
and `generic/192` pass; no rows fail as product defects; 43 rows are
unsupported feature/precondition rows; and 3 rows are environment or feature
skips. There are no deferred, harness-fail, or environment-refusal rows in the
tranche, not a pass claim or TFR-018 closure.

The #6593 kernel VFS tranche (`generic/201` through `generic/250`) ran through
the Linux 7.0.0 mounted-kernel VFS runner with the Nix-built
`tidefs_posix_vfs.ko` matching the guest kernel. The accepted row matrix uses
for `generic/201` through `generic/204`,
for `generic/205` through `generic/210`,
for `generic/241` through `generic/247`, and
for `generic/248` through `generic/250`. Deferred `generic/205` through
`generic/210` rows after the `generic/204` timeout and deferred
`generic/248` through `generic/250` rows after the `generic/247` timeout are
not used as final row classification. The final #6593 xfstests row
classification is: `generic/215`, `generic/221`, `generic/236`,
`generic/246`, and `generic/248` pass; 7 rows fail as product defects
(`generic/204`, `213`, `224`, `228`, `245`, `247`, `249`); 36 rows are
unsupported feature/precondition rows; and 2 rows are environment or feature
skips. There are no deferred, harness-fail, or environment-refusal rows in the
tranche, not a pass claim or TFR-018 closure.

The #6595 kernel VFS tranche (`generic/251` through `generic/300`) ran through
the Linux 7.0.0 mounted-kernel VFS runner with the Nix-built
`tidefs_posix_vfs.ko` matching the guest kernel. The accepted row matrix uses
for `generic/251` through `generic/260`,
for `generic/261` through `generic/270`,
for `generic/271` through `generic/273`,
for `generic/274`,
for `generic/275`,
for `generic/276` through `generic/280`,
and
Deferred `generic/274` through `generic/280` rows from the first shared
`271-280` run are not used as final row classification. The final #6595
xfstests row classification is: `generic/255`, `generic/286`, and
`generic/294` pass; 7 rows fail as product defects (`generic/257`, `258`,
`269`, `273`, `274`, `275`, `285`); 38 rows are unsupported
feature/precondition rows; and 2 rows are environment or feature skips. There
are no deferred, harness-fail, or environment-refusal rows in the accepted
not a pass claim or TFR-018 closure.

The #6599 kernel VFS tranche (`generic/351` through `generic/418`) ran through
the Linux 7.0.0 mounted-kernel VFS runner with the Nix-built
`tidefs_posix_vfs.ko` matching the guest kernel. The helper-built external
guest load with an `Invalid module format`/vermagic mismatch. The accepted row
through `generic/361`,
through `generic/371`,
through `generic/387`,
through `generic/403`, and
for `generic/404` through `generic/418`. Earlier post-timeout deferred rows,
post-`generic/361` blanket mount failures, and the shared-run no-space
`generic/404` through `generic/418` tail are not used as final row
classification. The final #6599 xfstests row classification is: `generic/354`,
`generic/360`, `generic/376`, `generic/377`, `generic/393`, `generic/394`,
`generic/403`, and `generic/404` pass; 8 rows fail as product defects
(`generic/361`, `371`, `387`, `401`, `409`, `410`, `411`, `416`); 32 rows are
unsupported feature/precondition rows; and 20 rows are environment or feature
skips. There are no deferred, harness-fail, or environment-refusal rows in the
tranche, not a pass claim or TFR-018 closure.

The #6597 kernel VFS tranche (`generic/301` through `generic/350`) ran through
the same Linux 7.0.0 mounted-kernel VFS runner with the Nix-built
`tidefs_posix_vfs.ko` matching the guest kernel. The accepted row matrix uses
through `generic/316`,
for isolated replacement rows `generic/317` through `generic/320`,
and
The shared-run no-space `generic/317` through `generic/320` rows are not used
as final row classification. The final #6597 xfstests row classification is:
`generic/308`, `generic/309`, `generic/310`, `generic/315`, `generic/316`,
`generic/321`, `generic/325`, `generic/335`, `generic/337`, `generic/338`,
`generic/341`, `generic/343`, and `generic/348` pass; 11 rows fail as product
defects (`generic/306`, `313`, `320`, `322`, `336`, `339`, `340`, `342`,
`344`, `345`, `346`); 21 rows are unsupported feature/precondition rows; and
5 rows are environment or feature skips. There are no deferred, harness-fail,
or environment-refusal rows in the accepted matrix. This is mounted-kernel
closure.

Run with:

```bash
TESTS="generic/001 generic/002 generic/003 generic/004 generic/005 generic/006 generic/007 generic/008 generic/009 generic/010 generic/011 generic/012 generic/013"
```

## Tiering policy

a bounded acceptance scope. Tests that are exercised but expected to fail
are cataloged as expected failures with concrete reasons. There is no hidden
release PASS — every test outcome must be explicitly classified.

|-------|--------------|---------|
| quick | mounted userspace | FUSE in guest or prepared local diagnostic environment |
| auto  | mounted userspace | FUSE in guest or prepared local diagnostic environment |
| lock  | mounted userspace | FUSE in guest or prepared local diagnostic environment |
| all   | mounted/kernel as claimed | Requires the matching QEMU or mounted-kernel runner |

and provides:

- `XfstestsTieringPolicy` — group-to-tier mapping and expected-failure catalog
  detection

### Expected-failure catalog

Tests that are expected to fail are cataloged in `XfstestsTieringPolicy::default_policy()`.
Each entry names the test, feature area, reason, applicable groups, and target
tier where the failure is expected to become a pass.

When a cataloged test starts passing, remove it from the catalog rather than
reclassifying it as an expected pass. An unexpected pass for a catalog entry
is always an improvement.

### Policy conformance

A scoreboard run is policy-conformant when:

- No unexpected failures (product defects not in the catalog)
- No unclassified skips (every skipped test must have a reason)

Environment refusals, expected failures, and documented skips are all
policy-conformant outcomes.
