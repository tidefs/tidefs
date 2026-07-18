# Kernel And Transport Unsafe Boundary Pointer

This file is a narrow provenance pointer for the older security/RDMA crate set.
Unsafe-code provenance lives with source-local safety documentation and lint
policy. A hand-maintained whole-tree line inventory is not current authority.

## Current Boundary

- Non-vendored unsafe blocks, unsafe functions, unsafe implementations, and
  unsafe foreign interfaces must carry a nearby `SAFETY:` comment or a
  `# Safety` section that states the local invariant or caller obligation.
- Root workspace policy denies `unsafe_op_in_unsafe_fn` and
  `missing_safety_doc`, and denies Clippy `unsafe_code` by default. Crates and
  modules that deliberately own an unsafe boundary keep any exception scoped
  to that boundary; an exception does not replace local safety documentation.
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
- Source-local safety comments and lint policy record review boundaries; they
  do not establish a current whole-tree site count.

## Review Rule

When an unsafe-code claim, FFI boundary, kernel boundary, or RDMA safety
statement needs updating, inspect the source at the exact path, verify its
local `SAFETY:` or `# Safety` contract, confirm that any unsafe-code allowance
is narrowly scoped, and update the owning live issue or PR. Do not add a
hand-maintained whole-tree inventory or line-number ledger.
