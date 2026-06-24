# Preview UAPI/ABI Boundary (OW-202)

> TFR-019 authority note: this document is current spec only for the checked
> preview command classification table and current non-release VFS codec hooks
> named below. It is not a production Linux ioctl/statx/ublk ABI freeze and
> not kernelspace-readiness evidence.

See `docs/OPERATOR_UAPI_AUTHORITY.md` for the operator UAPI decision that
relates this checked table to live-owner routing, local-only admission,
diagnostics, prototype cluster commands, and the non-release VFS/ublk/kernel
preview boundary. That decision does not widen this document's current-spec
scope.

This document describes historical tracker item 202 by documenting the
vfs_boundary_mirror terminology and preview UAPI/ABI surfaces. It is not a
production Linux ioctl/statx/ublk ABI freeze and does not claim TideFS is
kernelspace-ready.

## Purpose

This document tracks the current preview VFS fixed-width codec hooks and the
userspace-to-kernel classification surfaces used during development. These are
implementation-tracked non-release surfaces.

## vfs_boundary_mirror

The `vfs_boundary_mirror` name is the stable terminology for fixed-width VFS
boundary records between owned engine values and ABI-safe scalar encodings.
The current source surface is the `tidefs-schema-codec-vfs` crate, which owns
the fixed-width VFS handle, inode id, generation, node-kind, and errno codec
hooks used by adapters and kernel-facing paths during development.

Layout and round-trip tests live in `crates/tidefs-schema-codec-vfs/` and are
exercised by `cargo test -p tidefs-schema-codec-vfs --all-targets`.

## Non-Claims

This document is not proof that TideFS is kernelspace-ready. It does not freeze
a production Linux ioctl, statx, or ublk ABI, and it is not a kernel-module ABI
freeze. The preview boundary mirrors are development scaffolding that will
change before any production release. Cluster prototypes and development
diagnostics are not final distributed operator UAPI and remain non-release
surfaces. Production UAPI/ABI freeze requires a separate tracked GitHub issue
with implementation proof and an explicit freeze decision.

## tidefsctl command classification contract

Authority marker: `tidefsctl-command-classification-v1`.

The source of truth is
`apps/tidefsctl/src/commands/classification.rs`. `tidefsctl --help` consumes
that registry for its long classification text, and focused tests check this
document against the same marker and the exact registry/admission table below.
Command groups must not claim stronger stability than the class recorded here:

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

## Current Status

The vfs_boundary_mirror is an implementation-tracked non-release surface.
TideFS does not currently have kernelspace-ready capability.
