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
Production UAPI/ABI freeze requires a separate tracked Forgejo issue with

## Current Status

The vfs_boundary_mirror is an implementation-tracked non-release surface.
TideFS does not currently have kernelspace-ready capability.
