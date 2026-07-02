# Kernel And Transport Unsafe Boundary Pointer

This file is a narrow provenance pointer for the older security/RDMA crate set.
The live whole-tree unsafe inventory is `docs/UNSAFE_AUDIT.md`; use that file,
the source, and the active unsafe-audit issues for current unsafe-code status.

## Current Boundary

- `crates/tidefs-auth/`, `crates/tidefs-encryption/`,
  `crates/tidefs-local-filesystem/`, `crates/tidefs-local-object-store/`, and
  `crates/tidefs-scrub-core/` forbid unsafe code at their crate or module
  boundaries.
- `crates/tidefs-transport/src/lib.rs` denies unsafe code at the crate root.
  The RDMA transport submodule is the relevant exception because it wraps
  libibverbs through FFI resource-owner types.
- `crates/tidefs-transport/src/rdma/ffi.rs` declares the libibverbs ABI.
  `crates/tidefs-transport/src/rdma/verbs.rs` owns the resource wrappers,
  pointer lifetimes, queue-pair state transitions, memory registration, and
  drop cleanup around those declarations.
- `crates/tidefs-transport/src/rdma.rs` adapts the RDMA backend to TideFS
  transport frames. It does not own storage media, pool labels, committed
  roots, allocation, recovery, placement, or policy decisions.

## Non-Claims

- This pointer is not the whole-tree unsafe inventory and must not be cited as
  product-wide unsafe-code status.
- RDMA FFI wrappers do not create a second storage authority. They are a
  transport boundary over OS/library resources.
- Safe-Rust crate-level `forbid(unsafe_code)` or `deny(unsafe_code)` settings
  do not prove kernel safety, release readiness, product hardening, or absence
  of unsafe behavior elsewhere in the repository.
- Unsafe-audit closure depends on the live inventory and follow-up issues.
  Issue #1077 remains the broad audit parent, #1158 owns POSIX/FUSE syscall
  harness comments, and #1909 owns retirement of static unsafe audit surfaces
  after the focused splits close.

## Review Rule

When an unsafe-code claim, FFI boundary, kernel boundary, or RDMA safety
statement needs updating, read `docs/UNSAFE_AUDIT.md`, inspect the source at
the exact path, and update the owning unsafe-audit issue or PR. Do not expand
this file into a second inventory.
