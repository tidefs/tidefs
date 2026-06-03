# Troubleshooting common build failures (v0.423)

Maturity: **implemented-source** developer guide for diagnosing and fixing common build failures.

This document covers build failures that affect the TideFS Rust workspace or the Nix development

## 1. Quick health check

If the build fails, start with the minimal diagnostic:

    nix develop
    cargo check --workspace

If `nix develop` fails, jump to §2 (Nix). If `cargo check` fails, jump to §3 (Cargo).

## 2. Nix shell failures

### 2.1 Flakes not enabled

Symptom: `error: experimental Nix feature 'flakes' is disabled`.

Fix: enable flakes in `~/.config/nix/nix.conf` or `/etc/nix/nix.conf`:

    experimental-features = nix-command flakes

Alternatively pass `--extra-experimental-features 'nix-command flakes'` to every `nix` invocation.

### 2.2 rust-overlay fetch failure

Symptom: `error: … while fetching the input 'github:oxalica/rust-overlay'`.

Fix: ensure network access to GitHub. If behind a proxy, set `https_proxy` and retry:

    export https_proxy=http://proxy.example.com:8080
    nix develop

### 2.3 Nix build user sandbox denied

Symptom: `error: a 'x86_64-linux' with features {} is required to build …`.

Fix: this is a host/platform mismatch. TideFS requires an `x86_64-linux` host. Check:

    uname -m   # must print x86_64

### 2.4 Missing FUSE support at runtime

Symptom: builds succeed but FUSE-based commands fail at runtime with `fusermount3: … fuse device not found`.

kernel's `/dev/fuse`; host-kernel FUSE checks are convenience diagnostics only,
module and ensure `/dev/fuse` exists:

    sudo modprobe fuse
    ls -l /dev/fuse   # must exist with crw-rw-rw- permissions

### 2.5 `pkg-config` not found during Nix evaluation

Symptom: `error: builder for … failed with exit code 1` mentioning `pkg-config`.

Fix: the flake already includes `pkg-config` as a native build input. If this surfaces inside
`nix develop`, the dev shell may have been entered from a stale evaluation. Re-enter:

    exit            # leave current shell
    nix develop     # fresh evaluation

## 3. Cargo / Rust build failures

### 3.1 Wrong Rust toolchain version

Symptom: `error: package … requires rustc 1.88.0 but the active toolchain is …`.

Fix: TideFS pins Rust 1.88.0 in `rust-toolchain.toml`. Inside `nix develop`, this is automatically
honoured. Outside Nix, ensure `rustup` has the matching toolchain:

    rustup toolchain install 1.88.0
    rustup component add clippy rustfmt --toolchain 1.88.0
    rustup override set 1.88.0

Verify:

    rustc --version   # rustc 1.88.0 (…)

### 3.2 Missing `libfuse3` system headers

Symptom: linker errors mentioning `fuse`, or cargo errors about missing `fuse3` when building
`tidefs-posix-filesystem-adapter-*` crates.

Fix: install the FUSE3 development package:

    # Debian / Ubuntu
    sudo apt-get install libfuse3-dev

    # Fedora
    sudo dnf install fuse3-devel

    # Arch
    sudo pacman -S fuse3

Then rebuild. Inside `nix develop` this is provided automatically.

### 3.3 Workspace resolver errors

Symptom: `error: failed to select a version for …` or dependency resolution failures.

Fix: TideFS requires Cargo resolver v2 (set in the workspace `Cargo.toml`). Ensure you are using
a recent enough Cargo (1.88.0 includes a compatible version). If dependency resolution fails
after pulling new changes, update the lockfile:

    cargo update

If a specific crate fails, isolate it:

    cargo check -p <crate-name>

### 3.4 Compiler internal errors or OOM

Symptom: `rustc exited with signal: 9 (SIGKILL)` or `error: could not compile … (signal: 9, SIGKILL: kill)`.

Fix: the Rust compiler ran out of memory. Limit parallel compilation:

    CARGO_BUILD_JOBS=2 cargo check --workspace

For large workspaces like TideFS, a machine with at least 8 GB RAM is recommended.

### 3.5 Linker failures (`cc` / `ld` not found)

Symptom: `error: linker 'cc' not found`.

Fix: install a C compiler toolchain:

    # Debian / Ubuntu
    sudo apt-get install build-essential

    # Fedora
    sudo dnf groupinstall "Development Tools"

In `nix develop`, `gcc` and `binutils` are provided by the shell.

### 3.6 Missing `io_uring` headers

Symptom: build errors in `tidefs-block-volume-adapter-*` crates referencing `io_uring` symbols.

Fix: install kernel headers:

    sudo apt-get install linux-headers-$(uname -r)

Inside `nix develop`, these are provided through `pkgs.io-uring-headers`.

### 3.7 `cargo check` passes but `cargo build` fails

Symptom: `cargo check` succeeds but `cargo build` fails with linker errors.

Fix: `cargo check` skips code generation. The failure is likely a linking issue (see §3.2 or §3.5).
Check the linker error message for the missing library and install the corresponding `-dev` package:

    cargo build --workspace 2>&1 | tail -40

### 3.8 Feature flag mismatch between crates

Symptom: errors like `cannot find type … in crate …` when a workspace crate depends on a feature
that is not enabled.

Fix: check that the downstream crate's `Cargo.toml` enables the required feature. Run the targeted check:

    cargo check -p tidefs-posix-filesystem-adapter-daemon

## 4. Formatting and lint failures

### 4.1 `cargo fmt --check` fails


Fix: run `cargo fmt` to auto-format:

    cargo fmt

If `rustfmt` is not in PATH, install the component:

    rustup component add rustfmt

### 4.2 `cargo clippy` warnings treated as errors

Symptom: `cargo clippy` exits with non-zero status on warnings.

Fix: review the output:

    cargo clippy --workspace --all-targets 2>&1 | head -60

Common clippy lints and their fixes:

- `clippy::needless_return` — remove redundant `return` keyword.
- `clippy::redundant_clone` — remove unnecessary `.clone()` calls.
- `clippy::uninlined_format_args` — use inline format arguments (`format!("{x}")`).

To apply auto-fixable clippy suggestions:

    cargo clippy --fix --allow-dirty --allow-staged

### 4.3 Dead-code or unused-import warnings

Symptom: `warning: unused import: …` or `warning: function is never used`.

Fix: remove the unused item. To list all:

    cargo check --workspace 2>&1 | grep -E 'warning:.*unused'

## 5. xtask failures

### 5.1 `tidefs-xtask` panics or returns non-zero

Symptom: `cargo run -p tidefs-xtask -- check-group <group>` fails.

is self-documenting — read the error message and correct the violating source. Run a single group:

    cargo run -p tidefs-xtask -- check-group policy

### 5.2 xtask build failure (itself fails to compile)

Symptom: `cargo run -p tidefs-xtask` fails to build.

Fix: this usually means the xtask crate references a type or path that changed. Fix the
offending references in `crates/tidefs-xtask/` so that xtask compiles.

## 6. Test failures

### 6.1 `cargo test --workspace` fails

Symptom: a test panics or asserts false.

Fix: isolate the failing test:

    RUST_BACKTRACE=1 cargo test -p <crate> --lib -- <test_name>

See `docs/DEBUGGING_WORKFLOWS.md` for test isolation and tracing workflows.

### 6.2 Tests pass locally but fail in CI

Symptom: tests that pass on one machine fail on another.

Fix: common causes include:

- **Different kernel version** — some tests depend on kernel FUSE or io_uring behaviour.
  Verify with `uname -r`.
- **Missing `/dev/fuse`** — ensure the FUSE kernel module is loaded (§2.4).
- **Resource limits** — CI containers often have low file-descriptor or memory limits.
  Check `ulimit -n` and `ulimit -m`.

Run the exact CI command:


## 7. Block-volume adapter failures

### 7.1 ublk kernel module not loaded

Symptom: `cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-open` fails with
`device or resource busy` or `no such device`.

Fix: load the `ublk_drv` kernel module:

    sudo modprobe ublk_drv

Verify:

    ls /dev/ublk-control   # must exist (character device)

### 7.2 Permission denied on `/dev/ublk-control`

Symptom: `Permission denied (os error 13)` when opening ublk control.

Fix: add your user to the appropriate group or run with `sudo`.

## 8. Cache and incremental build issues

### 8.1 Stale incremental compilation artifacts

Symptom: build errors that reference types or modules that no longer exist.

Fix: clean and rebuild:

    cargo clean
    cargo check --workspace

For a targeted clean of a single crate:

    cargo clean -p <crate-name>
    cargo check -p <crate-name>

### 8.2 Cargo.lock out of sync

Symptom: `error: the lock file … needs to be updated but --locked was passed`.

Fix: regenerate the lockfile:

    cargo update
    cargo check --workspace

## 9. Disk space and I/O issues

### 9.1 Disk full during build

Symptom: `error: could not write … No space left on device`.

Fix: the TideFS workspace with debug builds can consume several GB. Ensure at least 10 GB free:

    df -h .

Clean unused artifacts:

    cargo clean

### 9.2 Read-only filesystem in Nix store

Symptom: `error: failed to write … Read-only file system` during a Nix build.

Fix: this is expected — Nix derivations write to a separate output path. Run `cargo` from
the repository checkout, not from a Nix store path.

## 10. Quick reference of common commands

| Failure class | Diagnostic command |
|---|---|
| Can Nix shell open? | `nix develop` |
| Does the workspace type-check? | `cargo check --workspace` |
| Does formatting pass? | `cargo fmt --check` |
| Does clippy pass? | `cargo clippy --workspace --all-targets` |
| Do tests pass? | `cargo test --workspace --all-targets` |
| One crate check | `cargo check -p <crate>` |
| One test | `cargo test -p <crate> --lib -- <name>` |
| Clean rebuild | `cargo clean && cargo check --workspace` |
| xtask policy check | `cargo run -p tidefs-xtask -- check-group policy` |

## 11. Still stuck?

- Check `docs/DEBUGGING_WORKFLOWS.md` for tracing, FUSE-debug, and test isolation.
- File an issue on the TideFS Forgejo tracker with the `build` or `bug` label and attach the
  full output of `cargo check --workspace 2>&1` and `uname -a`.
