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

## Third-Party Code

Vendored or imported third-party code keeps its own file-local license notices.
Do not rewrite those notices to the project license.

The current workspace license exception is:

| Path | Package | License | Provenance |
| --- | --- | --- | --- |
| `crates/tidefs-fuser` | `fuser` | `MIT` | Patched vendored FUSE protocol crate from upstream `fuser`; license text is `crates/tidefs-fuser/LICENSE.md`. |

All other packages reported by root `cargo metadata --no-deps --locked` use
`GPL-2.0-only WITH Linux-syscall-note` through workspace package metadata.
The five excluded cargo-fuzz harness manifests are standalone non-published
packages and now declare the same
`GPL-2.0-only WITH Linux-syscall-note` license explicitly:

- `fuzz/Cargo.toml`
- `crates/tidefs-binary_schema-core/fuzz/Cargo.toml`
- `crates/tidefs-local-filesystem/fuzz/Cargo.toml`
- `crates/tidefs-local-object-store/fuzz/Cargo.toml`

`cargo run -p tidefs-xtask -- check-workspace-policy` verifies these excluded
fuzz manifests keep explicit TideFS license declarations.
