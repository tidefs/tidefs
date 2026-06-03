# TideFS Security Audit — Pre-Release Hardening

**Date**: 2026-04-30
**Scope**: Full codebase (`master` at `bbbfd90`)
**Issue**: [#621](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/621)

## 1. Unsafe Code Enumeration

### 1.1 Summary

| Metric | Count |
|---|---|
| Crates with `#![forbid(unsafe_code)]` | 41 |
| Crates without `#![forbid(unsafe_code)]` | 1 |
| Total `unsafe` blocks in codebase | 14 |
| Total `unsafe` blocks outside ublk-control-runtime | 0 |
| Files with "unsafe" in comments/strings (false positives) | 3 |

### 1.2 The Single Unsafe Crate

**`crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs`** (4542 lines, 14 unsafe blocks)

This crate has `#![deny(unsafe_op_in_unsafe_fn)]` but does not forbid unsafe code, because it must interact with the Linux io_uring and mmap interfaces. Every other production crate forbids unsafe code entirely.

### 1.3 Unsafe Block Inventory

#### Category A: io_uring Submission Queue Pushes (8 blocks)

| Line | Command | SAFETY Invariant |
|---|---|---|
| 688 | ADD_DEV | Buffer (`dev_info`) stays live until CQE consumed; private ring |
| 898 | DEL_DEV | No userspace buffer; private ring, no other SQEs |
| 1141 | SET_PARAMS | Buffer (`input.params`) stays live until CQE consumed |
| 1406 | UPDATE_SIZE | Private ring, no other SQEs |
| 1823 | FETCH_REQ (data queue) | USER_COPY mode; caller owns ring and fd |
| 2189 | COMMIT_AND_FETCH_REQ | Queue/tag request already fetched and completed |
| 2789 | START_DEV | Inline daemon pid data; private ring |
| 3035 | GET_FEATURES (probe) | Buffer (`features_bits`) stays live until CQE consumed |

All io_uring pushes follow a consistent pattern: create entry, push to a private ring, `submit_and_wait` for CQE, then consume result. The private ring guarantee (no concurrent submissions from other threads) is maintained by the API design — each function creates its own `IoUring`.

**Assessment**: Well-structured. 7/8 blocks have explicit SAFETY comments. The UPDATE_SIZE block (line 1406) is the only one without — a documentation gap.

#### Category B: mmap Buffer Access (3 blocks)

| Line | Function | Safety Mechanism |
|---|---|---|
| 2422 | `io_desc(&self, tag)` | Bounds check: `tag < self.io_buf_queue_depth` |
| 2437 | `data_buffer(&self, tag)` | Bounds check: `tag < self.io_buf_queue_depth` |
| 2452 | `data_buffer_mut(&self, tag)` | Bounds check: `tag < self.io_buf_queue_depth` |

These access the ublk shared memory buffer (`UBLKSRV_IO_BUF_OFFSET`), mmap'd from the kernel. Each performs a bounds check before pointer arithmetic. The `data_buffer_mut` function creates a `&mut [u8]` from a raw pointer — this requires exclusive ownership of the buffer region. The ublk protocol ensures each tag is exclusively owned by a single in-flight request.

**Assessment**: Sound. Bounds checks are correct. The exclusive ownership model for data queue tags is enforced by the ublk protocol.

#### Category C: mmap/munmap Lifecycle (2 blocks)

| Line | Context |
|---|---|
| 2462 | `Drop` impl: `libc::munmap(self.io_buf_base, self.io_buf_len)` |
| 2521 | `open_data_queue_runtime()`: `libc::mmap(...)` for io_buf_base |

The mmap is created when the data queue runtime is opened and freed on drop. The `Drop` checks `!self.io_buf_base.is_null() && self.io_buf_len > 0` before calling munmap.

**Assessment**: Sound. The lifecycle is correctly managed with RAII.

#### Category D: Test Helper (1 block)

| Line | Context |
|---|---|
| 4153 | `dummy_control_fd()`: `BorrowedFd::borrow_raw(owned.as_raw_fd())` |

Creates a `BorrowedFd<'static>` with a fake lifetime. The `owned` `File` variable is intentionally leaked (not dropped), so the fd stays valid for the test duration. Acceptable for test code but under-documented.

**Assessment**: Low risk (test only).

### 1.4 False Positives

Three files mention "unsafe" in strings or comments but contain no unsafe blocks:

- `xtask/tidefs-xtask/src/block.rs` — in assertion messages about "unsafe control-only starts"
- `crates/tidefs-local-filesystem/src/tests.rs` — string "unsafe retention policy"

### 1.5 `forbid(unsafe_code)` Coverage

41 crates and apps use `#![forbid(unsafe_code)]`, including all FUSE filesystem crates, core type crates, daemon apps, schema codec crates, local filesystem and object store, ublk-abi (no_std), and xtask.

**Assessment**: Exceptional. The unsafe surface is minimized to exactly one crate that genuinely requires it.

---

## 2. Privilege Boundary Audit

### 2.1 Block Volume Adapter Daemon

The ublk daemon (`apps/tidefs-block-volume-adapter-daemon`) interacts with:
- `/dev/ublk-control` — requires `CAP_SYS_ADMIN` or root
- `/dev/ublkcN` (data queue) — opened by daemon after ADD_DEV
- `/dev/ublkbN` (block device) — created by kernel after START_DEV
- io_uring — may need `CAP_SYS_NICE` for SQPOLL

**Privilege requirement**: The daemon must run as root or with `CAP_SYS_ADMIN`.


### 2.2 FUSE Daemon

The FUSE daemon (`apps/tidefs-posix-filesystem-adapter-daemon`) uses the `fuser` crate. Mount options include `NoSuid` (good).

**Privilege requirement**: FUSE mounting typically requires membership in the `fuse` group, not root.


### 2.3 Missing Hardening

The codebase does not contain:
- `prctl` calls for capability bounding sets
- seccomp filter setup
- Namespace isolation

These are typical for production daemons with elevated privileges. For a pre-release audit focusing on correctness, this is expected scope.

---

## 3. Vulnerability Pattern Scan

### 3.1 Integer Casts

**ublk-control-runtime** (~26 `as` casts):

- **Size calculations**: `(tag as usize) << UBLK_IO_BUF_BITS` — bounds-checked before use.
- **User data encoding**: `tag as u64 | ((cmd as u64) << 16)` — bit packing within known ranges (tag: u16, q_id < 64).


### 3.2 TOCTOU Races

**No TOCTOU patterns found**. The filesystem model is session-based:
- FUSE operations use inode numbers, not paths (after lookup/getattr)
- The LocalFileSystem layer uses internal inode IDs
- Path-based operations resolve through a single snapshot-consistent view

The FUSE kernel layer handles path resolution and passes resolved inodes to the daemon, which eliminates the classic path-based TOCTOU window.

### 3.3 Buffer Over-reads

**from_raw_parts / from_raw_parts_mut**: Only in ublk-control-runtime (lines 2439, 2454). Both bounded by `buf_size = (1 << UBLK_IO_BUF_BITS) - size_of::<UblkSrvIoDesc>()` with tag bounds check.

**FUSE layer**: Uses safe Rust Vec/slices. Buffer sizes are kernel-provided. No raw pointer buffer access.

### 3.4 Panic on Input

**ublk-control-runtime**: 7 `unreachable!()` calls in test-only error injection functions (lines 80-236). These are exhaustive matches on the `InjectedError` enum — the unreachable branches are truly unreachable and only compiled in test builds. No runtime panic risk.

**FUSE layer**: `unwrap`/`expect` primarily in tests (400+) and initialization paths where failure is fatal. No attacker-controllable unwrap in the hot path.

---

## 4. Error Injection Coverage

The ublk-control-runtime has a `thread_local!` error injection facility for testing error paths:

- `AddDevUblkCommandErrno`
- `DelDevUblkCommandErrno` + `DelDevAfterAddDevFailure`
- `SetParamsUblkCommandErrno`
- `StartDevUblkCommandErrno`
- `FetchReqSubmissionQueueFull` / `FetchReqUblkCommandErrno` / `FetchReqIoUringSubmitErrno` / `FetchReqIoUringSubmitZero`

This is comprehensive for the ublk control runtime but does not extend to the FUSE or object-store layers.

---

## 5. Findings

### 5.1 By Severity

| # | Severity | Finding |
|---|---|---|
| F1 | Low | Missing SAFETY comment on UPDATE_SIZE submission push (line 1406) |
| F2 | Low | `unreachable!()` on unknown ublk command codes — should return error (7 instances) |
| F3 | Low | `dummy_control_fd()` intentionally leaks fd in test code without comment (line 4153) |
| F4 | Info | No fuzzing targets exist for FUSE or object-store inputs |
| F5 | Info | No capability dropping after block device initialization |
| F6 | Info | ublk-control-runtime is the only crate without `#[forbid(unsafe_code)]` (documented, intentional) |

### 5.2 Verified Safe

- All 14 unsafe blocks have adequate justification
- No exploitable integer overflow or truncation
- No TOCTOU vulnerabilities (session-based inode model)
- No buffer over-reads (both `from_raw_parts` calls are bounds-checked)

### 5.3 Strengths

1. 41/42 crates forbid unsafe code — exceptional for a Rust storage system
2. Centralized unsafe surface — all unsafe in one well-documented crate
3. Error injection framework for ublk error paths
4. Consistent SAFETY documentation (13/14 blocks)
5. Session-based filesystem model — inherently TOCTOU-resistant

---

## 6. Recommendations

### Quick Wins

1. Add SAFETY comment to UPDATE_SIZE submission push (`lib.rs:1406`)
2. Consider adding a `#[track_caller]` note to error injection helpers for better test diagnostics
3. Add comment to `dummy_control_fd()` explaining the intentional fd leak

### Medium Term

4. Scaffold `cargo-fuzz` target for FUSE request deserialization
5. Scaffold `cargo-fuzz` target for object-store record decode

### Long Term

6. Implement capability dropping in the block-volume-adapter daemon
7. Consider seccomp filter for the FUSE daemon
