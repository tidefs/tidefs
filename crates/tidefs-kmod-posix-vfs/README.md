# tidefs-kmod-posix-vfs

`tidefs-kmod-posix-vfs` contains the Rust source model for the TideFS Linux
POSIX VFS adapter. It maps Linux VFS callback families onto the kmod bridge
types and the shared `VfsEngine` trait without owning product claims,
validation status, or release readiness.

## Authority Boundary

This README is only crate-local orientation for kernel contributors. Use the
repository authorities below for product and proof questions:

- `docs/KERNEL_RESIDENCY_AUTHORITY.md` owns the kernel-residency boundary.
- `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md` owns the resident pool
  engine architecture.
- `validation/claims.toml` and generated `docs/CLAIM_REGISTRY.md` own admitted
  claims and required evidence.
- `docs/GITHUB_CI.md` owns GitHub Actions validation flow.
- `crates/tidefs-kmod-posix-vfs/VFS-OPS-GAP-ANALYSIS.md` is a separate
  gap-analysis snapshot; do not duplicate or update that snapshot here.

Do not use this README as evidence for no-daemon operation, full-kernel
readiness, mounted proof, production status, release readiness, or successor
comparisons.

## Source Map

- `tidefs_posix_vfs_main.rs` is the Rust-for-Linux module entry point used by
  the kernel build.
- `tidefs_posix_vfs_shim.c` provides the mounted C shim used by the kernel
  module path.
- `Kbuild` and `Makefile` describe the kernel build integration.
- `src/lib.rs` declares the crate-level safety and callback registration
  contract, exports the operation modules, and defines `KmodPosixVfs`.
- `src/mount.rs`, `src/kernel_mount.rs`, `src/mount_lifecycle.rs`, and
  `src/mount_options.rs` cover superblock setup, mount admission, lifecycle
  handling, and option parsing.
- `src/superblock.rs` and `src/super_operations.rs` cover superblock state and
  super-operation dispatch.
- `src/dir.rs`, `src/dir_cursor.rs`, `src/dir_ops_bridge.rs`,
  `src/readdir.rs`, and `src/inode.rs` cover directory state, cursor handling,
  lookup, and readdir flow.
- File, inode, and namespace operation families live in one module per VFS
  concern, including `create.rs`, `open_release.rs`, `read.rs`, `write.rs`,
  `rename.rs`, `unlink.rs`, `link.rs`, `mkdir.rs`, `rmdir.rs`, `mknod.rs`,
  `symlink.rs`, `tmpfile.rs`, `getattr.rs`, `setattr.rs`, `permission.rs`,
  `statfs.rs`, `statx.rs`, `xattr.rs`, `fsync.rs`, `flush.rs`, `syncfs.rs`,
  `llseek.rs`, `fadvise.rs`, `fallocate.rs`, `copy_file_range.rs`, and
  `update_time.rs`.
- Page-cache and extent-adjacent source models live in
  `address_space_ops.rs`, `mmap.rs`, `readahead.rs`, `writeback.rs`,
  `page_authority.rs`, `extent_ops.rs`, and `extent_ops_bridge.rs`.
- `src/no_daemon_residency.rs`, `src/intent_record.rs`,
  `src/intent_replay.rs`, `src/replay_integration.rs`, and
  `src/live_data_allocator.rs` provide source-local helpers used by the VFS
  model. Product-level residency claims still belong to the authority docs and
  claim registry.
- `src/blake3_guard.rs` contains crate-local BLAKE3 guard helpers used by the
  repository guard tooling.
- `src/kernel_env_model.rs` and `src/test_util.rs` are cargo-side support code;
  they are not mounted kernel callback registration.

## Contributor Notes

The crate is `#![cfg_attr(not(CONFIG_RUST), no_std)]` and uses `core`, `alloc`,
and kmod-bridge aliases so the same Rust sources can be checked under Cargo and
integrated by Rust-for-Linux builds. Keep kernel-only facts close to the
callback or bridge code that enforces them, especially pointer lifetime,
callback ABI, lock ordering, and sleepability constraints.

Cargo checks exercise the Rust source model and bridge facades. They do not
replace Kbuild registration, mounted Linux validation, or claim-gate evidence.
When changing behavior, update the source or the appropriate authority doc
rather than expanding this README into a runbook.

Unsupported or intentionally fail-closed operations should be documented in the
module that implements the decision. If a gap affects product behavior or claim
admission, update the owning issue, claim registry, or kernel authority doc
instead of adding a status table here.
