# Kernel Unsafe Boundary Consolidated Inventory

Issue: [#6492] [NEXT-SEC-013]
Review date: 2026-05-23
Head (origin/master at review): `27403b998`
Branch: `agent-s6` (Nexus worktree)

## Summary

This inventory covers every `unsafe` block, `extern "C"` FFI declaration, and
C shim surface in the crate set owned by this issue:

- `crates/tidefs-auth/`
- `crates/tidefs-encryption/`
- `crates/tidefs-transport/`
- `crates/tidefs-local-filesystem/`
- `crates/tidefs-local-object-store/`
- `crates/tidefs-scrub-core/`

## Verdict

**Five of seven owned crates forbid `unsafe_code` entirely.**
The only unsafe surface is the RDMA verbs transport binding in
`crates/tidefs-transport/src/rdma/`, which wraps the OS-level `libibverbs`
library. This surface is a narrow, OS-library FFI wrapper. It contains no
duplicate TideFS storage authority, no userspace local-object-store substitute,
no FFI persistence layer, and no policy engine.

Every unsafe block has a documented safety invariant. Every type with
`unsafe impl Send/Sync` carries a rationale. Every FFI function call is
wrapped through the `verbs` module's resource-ownership types with `Drop`
cleanup. Production tests exercising RDMA device enumeration, PD/CQ/QP
lifecycle, and loopback send/recv roundtrip exist in-tree.

## Per-Crate Inventory

### tidefs-auth

`#![forbid(unsafe_code)]` -- zero unsafe blocks, zero `extern "C"` shims.

### tidefs-encryption

`#![forbid(unsafe_code)]` -- zero unsafe blocks, zero `extern "C"` shims.

### tidefs-local-filesystem

`#![forbid(unsafe_code)]` -- zero unsafe blocks, zero `extern "C"` shims.
No kernel or FFI dependencies.

### tidefs-local-object-store

`#![forbid(unsafe_code)]` -- zero unsafe blocks, zero `extern "C"` shims.
The doc comment explicitly states "This crate forbids unsafe code."

### tidefs-scrub-core

`#![forbid(unsafe_code)]` in `lib.rs`, `repair_scheduling.rs`, and
`scrub_repair.rs` -- each module independently forbids unsafe. Zero unsafe
blocks, zero `extern "C"` shims.


Zero unsafe blocks in production source code
(`src/mount_harness.rs`, `src/concurrent_ops.rs`, etc. use only safe Rust).
Test modules under `tests/` use `unsafe` only for test infrastructure
(e.g., harness setup). Not a production code concern.

### tidefs-transport

`#![deny(unsafe_code)]` at the crate root (`lib.rs`). The RDMA submodule
overrides this with `#![allow(unsafe_code)]` because it wraps a C library.
The three RDMA files are the **only** unsafe surface in the entire owned set.

## RDMA Unsafe Surface Detail

### 1. ffi.rs (FFI declarations)

Role: Rust-side type and function declarations matching the libibverbs
C ABI. Contains zero executable code.

| Element | Safety Invariant |
|---|---|
| Opaque structs (ibv_device, ibv_context, ibv_pd, ibv_mr, ibv_cq, ibv_qp) | Zero-sized markers never instantiated in Rust. Library allocates instances; Rust only holds raw pointers. |
| extern "C" function declarations (23 functions) | Each matches libibverbs 1.x ABI. Called only from verbs.rs wrapper methods that own pointer arguments through Drop-guarded resource types. |
| repr(C) structs (ibv_sge, ibv_wc, ibv_send_wr, etc.) | Layout matches C struct per libibverbs header. Union fields zeroed before use and never read as unions. |

**Storage authority:** None. Pure ABI declarations for an OS-level network
transport library.

### 2. verbs.rs (Safe-ish wrappers, 705 lines)

Role: Resource-owning wrapper types with Drop cleanup, QP state-machine

| Wrapper Type | Unsafe Elements | Safety Rationale |
|---|---|---|
| RdmaDevice | Send/Sync impls, 5 FFI calls | ibv_context is thread-safe per spec. ibv_get_device_list, ibv_open_device, ibv_close_device, ibv_get_device_name, ibv_free_device_list are called with ownership discipline. |
| ProtectionDomain | Send/Sync impls, 2 FFI calls | ibv_pd is thread-safe per spec. ibv_alloc_pd/dealloc_pd paired through Drop. |
| MemoryRegion | Send/Sync impls, 2 FFI calls, offset-based field access | ibv_mr is thread-safe per spec. register() is marked unsafe -- caller guarantees buffer lifetime. lkey() reads first u32 per ABI layout. |
| CompletionQueue | Send/Sync impls, 2 FFI calls | ibv_cq is thread-safe per spec. ibv_create_cq/destroy_cq paired through Drop. Poll uses zeroed stack array for WC batch. |
| ibv_mr::lkey() | Pointer cast to u32 | ABI guarantees lkey at offset 0. |
| ibv_qp::qp_num() | Pointer cast to u32 | ABI guarantees qp_num at offset 0. |

**Storage authority:** None. Verbs wrappers are a resource-management layer
for RDMA transport primitives.

### 3. rdma.rs (RDMA transport backend, ~900 lines)

Role: Implements TransportBackend and ConnectionLike over RDMA queue pairs.

| Unsafe Site | Safety Invariant |
|---|---|
| MemoryRegion::register() for buffer pools | Owned Vec<u8> allocation, pointer valid for MR lifetime. |
| ptr_at() / mut_ptr_at() offset arithmetic | Offset bounded by buffer pool construction (idx * buf_size within capacity). |
| MemoryRegion::register() in test helpers | Test-only; buf is live Vec allocation. |

**Storage authority:** None. Moves opaque transport frames between nodes.

## C Shim Surface

The only `extern "C"` declarations in owned crates are the 23 libibverbs
function declarations in `ffi.rs`. There are **no** custom C source files,
no `cc::Build` invocations, and no hand-written C shim code anywhere in the
owned crates.

## Test Coverage

All non-opt-in tests pass on hosts without RDMA hardware:

| Test | Location | What It Proves |
|---|---|---|
| test_rdma_device_enumeration | verbs.rs:615 | Device detection or clean error |
| test_protection_domain_create_destroy | verbs.rs:626 | PD alloc + Drop cleanup |
| test_completion_queue_create_destroy | verbs.rs:639 | CQ create + empty poll |
| test_qp_create_and_state_transition | verbs.rs:650 | QP RESET->INIT; duplicate rejected |
| test_post_recv_and_send_completes | verbs.rs:675 | Post-recv API with buffer/lkey |
| test_qp_info_encode_decode_roundtrip | rdma.rs:581 | Wire format deterministic |
| test_rdma_transport_new_returns_not_available_when_no_device | rdma.rs:595 | Graceful missing-device handling |
| test_send_free_bitmap_all_free_at_init | rdma.rs:618 | Buffer pool bitmap (16 buffers) |
| test_send_free_bitmap_mark_and_release | rdma.rs:629 | Busy/free transitions |
| test_qp_info_zero_values_roundtrip | rdma.rs:639 | Null QP info survives |
| test_rdma_connection_lifecycle_with_device | rdma.rs:649 | Full connection construction |
| test_wr_id_passed_to_post_send_and_post_recv | rdma.rs:684 | wr_id reaches verbs layer |
| test_rdma_loopback_send_recv_roundtrip | rdma.rs:779 | E2E loopback (opt-in) |
| test_rdma_loopback_large_payload | rdma.rs:806 | 256 KiB roundtrip (opt-in) |
| test_rdma_loopback_multiple_messages | rdma.rs:824 | Buffer-pool reuse (opt-in) |
| test_rdma_transport_bind_connect_accept_loopback | rdma.rs:851 | TransportBackend trait (opt-in) |

Opt-in tests require TIDEFS_RUN_RDMA_LOOPBACK=1 or TIDEFS_RUN_QEMU_RDMA_SMOKE=1.

## Storage Authority Non-Duplication

The RDMA transport surface:
- Does not read/write TideFS pool labels, superblocks, or committed roots
- Does not allocate or free pool space
- Does not interpret TideFS object/extent/inode content
- Does not participate in txg, intent logging, or crash recovery
- Does not select, replicate, or place storage objects
- Does not implement any TideFS storage policy

TideFS storage authority resides in tidefs-local-object-store,
tidefs-local-filesystem, tidefs-commit-group, tidefs-intent-log,
and related storage crates -- all of which forbid(unsafe_code).

## A-Register Findings Addressed

**A2** (Workspace Shape, C shim policy): The kernel-review policy says C shims
must expose narrow unsafe Linux mechanics and must not become a second TideFS
storage authority. The RDMA FFI complies: it wraps libibverbs (an OS library)
for transport only, touches no storage, and can be compiled out by removing
the `rdma` module without affecting the rest of tidefs-transport.

**A4** (Proof-Marker Pattern): This inventory uses concrete source locations
and safety invariants, not generic proof-marker language.

**No other A-register findings are directly addressed by this inventory.**
