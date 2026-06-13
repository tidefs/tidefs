# Getting Started with TideFS

## Prerequisites

- Linux x86_64 host
- Nix with flakes enabled

The repo provides a pinned Rust toolchain through Nix. No host-global Rust
installation is needed.

**Important**: The Nix build sandbox does not provide `/dev/kvm`, `/dev/fuse`,
or the runtime device substrate. Nix builds artifacts only; autonomous runtime

## Quick Start

    nix develop
    cargo check --workspace
    cargo build --workspace
    cargo test --workspace --all-targets

## Key Demos

    cargo run -p tidefs-store-demo          # Object store
    cargo run -p tidefs-filesystem-demo     # Local filesystem
    cargo run -p tidefs-block-volume-adapter-daemon -- summary

## Mounting the Filesystem

Mounted device-level compression and encryption are blocked behind the TFR-006
transform authority raw-store inventory; the preview mount command below does
not enable those transforms.

    mkdir -p /tmp/tidefs-store /tmp/tidefs-mnt
    export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="$(openssl rand -hex 32)"
    cargo run -p tidefs-posix-filesystem-adapter-daemon -- \
      mount --store /tmp/tidefs-store --mount /tmp/tidefs-mnt

Use `/tmp/tidefs-mnt` with standard POSIX operations. Unmount:

    fusermount3 -u /tmp/tidefs-mnt

Smoke mount:

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- smoke-mount


    nix run .#qemu-smoke            # FUSE smoke in QEMU guest (Linux 7.0)
    nix run .#posix-scoreboard      # FUSE POSIX scoreboard (requires /dev/fuse; use QEMU)
    nix run .#xfstests-runner       # diagnostic xfstests scoreboard wrapper

kernel.** Nix builds artifacts only. QEMU and tests that touch `/dev/fuse`,
ublk, mounts, RDMA, xfstests, fsstress, or fio filesystem semantics must launch
outside the Nix build sandbox and run inside a guest.

Legacy `qemu-smoke`, `qemu-ublk-*`, and `fuse-vm-test` app entrypoints are
to outside-sandbox runners before relying on them.

## Where to Go Next

- `docs/ARCHITECTURE.md` — system architecture and layer model
- `docs/REVIEW_TODO_REGISTER.md` — current review debt and capability blockers
- `docs/PREVIEW_USER_MANUAL.md` — preview-only operation notes
- `docs/INDEX.md` — full documentation index
