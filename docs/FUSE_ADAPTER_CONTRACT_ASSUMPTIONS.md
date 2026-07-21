# FUSE Adapter Contract Assumptions

> TFR-019 authority classification: Current policy (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

Maturity: current userspace-carrier boundary.

The FUSE adapter is a userspace carrier boundary. It parses kernel requests and
dispatches registered-handle operations through the VFS engine. Filesystem
semantics, persisted content, and placement-receipt authority remain in the
filesystem and Pool layers; the adapter is not a second storage authority.

Every readable open, create, and temporary-file handle forces
`FOPEN_DIRECT_IO`, and the adapter masks `FOPEN_KEEP_CACHE`. Both command-line
spellings that request kernel writeback cache are refused. Kernel page-cache
reads therefore cannot bypass daemon-side receipt-authoritative reads, and no
kernel-writeback compatibility path is part of the current carrier.

Ordinary registered-handle dirty tracking remains in the adapter. Flush,
`fsync`, `fdatasync`, `syncfs`, and release dispatch durability work through
the VFS engine rather than an adapter-owned byte cache.

Focused adapter tests cover the open flags and dispatch boundary. The mounted
receipt-authority test in
`apps/tidefs-posix-filesystem-adapter-daemon/tests/receipt_authority_mount.rs`
is the product-boundary check that a read through the same open file descriptor
fails closed when its persisted placement receipt is no longer authoritative.

This document does not claim broader FUSE/POSIX completeness, kernel-resident
behavior, or production readiness. Current source and mounted tests, not a
standalone lifecycle model or generated evidence artifact, establish carrier
behavior.
