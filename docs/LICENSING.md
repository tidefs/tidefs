# TideFS Licensing

TideFS is licensed as:

```text
GPL-2.0-only WITH Linux-syscall-note
```

This follows the Linux-kernel model: the implementation is GPLv2-only, and
applications that use TideFS through clear syscall-like public interfaces are
not treated as derived works merely for using those interfaces.

For TideFS, the clear public boundary includes POSIX syscall behavior,
kernel UAPI/ioctl-style interfaces, FUSE and ublk protocol entry points,
stable command-line tools, and documented wire protocols. Linking to internal
TideFS Rust crates or embedding implementation code is not the same as using
that boundary.

License texts are stored in `COPYING`,
`LICENSES/preferred/GPL-2.0`, and
`LICENSES/exceptions/Linux-syscall-note`.

`cargo run -p tidefs-xtask -- check-workspace-policy` verifies workspace
package metadata, excluded fuzz harness manifests, and registered file-local
license/provenance markers.

## Third-Party Code

Vendored or imported third-party code keeps its own file-local license notices.
Do not rewrite those notices to the project license.

The current workspace license exceptions are:

| Path | Package | License | Provenance |
| --- | --- | --- | --- |
| `crates/tidefs-fuser` | `fuser` | `MIT` | Patched vendored FUSE protocol crate from upstream `fuser`; license text is `crates/tidefs-fuser/LICENSE.md`. |
| `crates/tidefs-fuser/examples/notify_inval_entry.rs` | `fuser` example | `GPLv2` | Vendored upstream example translated from libfuse `example/notify_inval_entry.c`; the file-local notice is preserved. |
| `crates/tidefs-fuser/examples/notify_inval_inode.rs` | `fuser` example | `GPLv2` | Vendored upstream example translated from libfuse `example/notify_{inval_inode,store_retrieve}.c`; the file-local notice is preserved. |
| `crates/tidefs-fuser/examples/poll.rs` | `fuser` example | `GPLv2` | Vendored upstream example translated from libfuse `example/poll.c`; the file-local notice is preserved. |
| `crates/tidefs-fuser/examples/poll_client.rs` | `fuser` example | `GPLv2` | Vendored upstream example translated from libfuse `example/poll_client.c`; the file-local notice is preserved. |

## Kernel Module Notices

Linux loadable module sources use Linux kernel-style file-local SPDX/module
license markers. These are TideFS-owned kernel integration files, not
third-party imports, and they are tracked explicitly because the kernel build
surface expects `GPL-2.0` SPDX text and `license: "GPL"` module metadata rather
than the workspace package license string.

| Path | File-local marker | Provenance |
| --- | --- | --- |
| `crates/tidefs-block-kmod/tidefs_block_kmod.rs` | `GPL-2.0` / `GPL` | TideFS block-volume Rust-for-Linux module entry point. |
| `crates/tidefs-kmod-posix-vfs/src/kernel_intent_writer.rs` | `GPL-2.0` | TideFS Kbuild-only POSIX VFS intent-log writer. |
| `crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs` | `GPL-2.0` / `GPL` | TideFS POSIX VFS Rust-for-Linux module entry point. |
| `crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_shim.c` | `GPL-2.0` | TideFS POSIX VFS C registration shim. |
| `kmod/smoke_module/rust_tidefs_smoke.rs` | `GPL-2.0` / `GPL` | TideFS Rust-for-Linux smoke fixture. |

All other packages reported by root `cargo metadata --no-deps --locked` use
`GPL-2.0-only WITH Linux-syscall-note` through workspace package metadata.
The five excluded cargo-fuzz harness manifests are standalone non-published
packages and now declare the same
`GPL-2.0-only WITH Linux-syscall-note` license explicitly:

- `fuzz/Cargo.toml`
- `crates/tidefs-binary_schema-core/fuzz/Cargo.toml`
- `crates/tidefs-local-filesystem/fuzz/Cargo.toml`
- `crates/tidefs-local-object-store/fuzz/Cargo.toml`
- `crates/tidefs-validation/fuzz/Cargo.toml`

`cargo run -p tidefs-xtask -- check-workspace-policy` verifies these excluded
fuzz manifests keep explicit TideFS license declarations and rejects
undocumented file-local third-party notices or stale license strings.
