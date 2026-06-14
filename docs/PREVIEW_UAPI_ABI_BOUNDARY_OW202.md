# Preview UAPI/ABI Boundary (OW-202)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 202 by documenting the
vfs_boundary_mirror and preview UAPI/ABI surfaces. It is not a production
Linux ioctl/statx/ublk ABI freeze and does not claim TideFS is kernelspace-ready.

## Purpose

This document tracks the current preview VFS boundary mirror layout and the
userspace-to-kernel data structures used during development. These are
implementation-tracked non-release surfaces.

## vfs_boundary_mirror

The `vfs_boundary_mirror` records are fixed-size preview structures that map
userspace VFS state (inode attributes, extent metadata, directory entries) to
the kernel boundary. They exist so the kernel VFS module can consume
committed-root state without a userspace daemon during the bootstrap path.

Layout tests live in `crates/tidefs-schema-codec-vfs-boundary/` and are
exercised by `cargo test -p tidefs-schema-codec-vfs-boundary --all-targets`.

## Non-Claims

This document is not proof that TideFS is kernelspace-ready. It does not freeze
a production Linux ioctl, statx, or ublk ABI. The preview boundary mirrors are
development scaffolding that will change before any production release.
Production UAPI/ABI freeze requires a separate tracked GitHub issue with
implementation proof and an explicit freeze decision.

## tidefsctl command classification contract

Authority marker: `tidefsctl-command-classification-v1`.

The source of truth is
`apps/tidefsctl/src/commands/classification.rs`. `tidefsctl --help` consumes
that registry for its long classification text, and focused tests check this
document against the same marker. Command groups must not claim stronger
stability than the class recorded there:

| Class | Current surfaces | Contract |
|---|---|---|
| `public-operator` | `pool create`, `pool scan`, `pool status`, `pool import`, `pool export`, `pool destroy`, `pool get`, `pool set`, `pool list-props`, `snapshot create`, `snapshot list`, `snapshot clone create`, `snapshot clone delete`, `snapshot clone promote`, `snapshot bookmark create`, `snapshot bookmark delete`, `snapshot hold`, `snapshot release`, `snapshot holds`, `snapshot prune`, `snapshot destroy`, `snapshot rollback`, `snapshot send`, `snapshot receive`, `device remove`, `defrag`, `block attach`, `block detach`, `block list`, `block send`, `block receive`, `dataset create`, `dataset list`, `dataset destroy`, `dataset rename`, `dataset set-strategy`, `dataset seal-key`, `dataset rotate-key`, `dataset upgrade`, `dataset get`, `dataset set`, `dataset list-props` | Pool-name live state routes through the declared kernel/userspace live owner. Explicit `--devices` inputs are offline, discovery, import, or not-yet-imported inputs, not live-state overrides. |
| `userspace-harness` | `mount`, `pool mount` | Current FUSE harness surfaces. They do not change mount default backing media, and they are not a production kernel runtime claim. |
| `operator-diagnostic` | `pool integrity-check`, `kernel status`, `diag` | Diagnostic and support-bundle surfaces. `kernel status` is passive inventory while production kernel UAPI wiring is absent. |
| `prototype` | `cluster pool create` | Prototype cluster operator surface. It is not final distributed operator UAPI and remains behind TFR-017 authority work. |
| `development-diagnostic` | `cluster placement exercise`, `cluster heal exercise` | Development exercises for placement/heal code. They are not accepted as final distributed operator UAPI or proof of clustered product behavior. |
| `removed-or-unsupported` | `pool list`, `device rebuild`, `directory-backed pool media`, `pool integrity-check --backing-dir`, `snapshot --backing-dir`, `block --backing-dir`, `device remove --backing-dir`, `device remove --surviving-dirs` | Hidden or retired surfaces must fail closed with clear errors. They must not appear as supported help entries or placeholder success paths. |

## Current Status

The vfs_boundary_mirror is an implementation-tracked non-release surface.
TideFS does not currently have kernelspace-ready capability.
