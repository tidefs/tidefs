# TideFS Preview User Manual

Maturity: **preview** -- this document describes development preview surfaces,
not production capability. TideFS does not currently fulfill production-ready
capability, and does not currently have POSIX-complete or full-kernel capability.

## Overview

TideFS is a pre-alpha storage stack. This manual covers the current preview
surface for developers and early testers who understand the project is not
release-ready.

## Quick Start (Preview Only)

```sh
nix develop
export CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target
cargo check --workspace --locked
```

## Preview Daemons

### FUSE Mount (Development Preview)

filesystem:

```sh
mkdir -p /tmp/tidefs-store /tmp/tidefs-mnt
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="$(openssl rand -hex 32)"
cargo run -p tidefs-posix-filesystem-adapter-daemon -- \
  mount --store /tmp/tidefs-store --mount /tmp/tidefs-mnt
fusermount3 -u /tmp/tidefs-mnt
```

### ublk Block Volume (Development Preview)


```sh
cargo run -p tidefs-block-volume-adapter-daemon -- summary
```

## Important Limitations

This is a preview. TideFS is not production-ready, not POSIX-complete, and does
not yet have full-kernel capability. Do not use it for real data. All claims
are governed by the project Claims gate
(`cargo run -p tidefs-xtask -- check-claims-gate`).

For current status see [docs/REVIEW_TODO_REGISTER.md](REVIEW_TODO_REGISTER.md)
and [docs/WHOLE_REPO_REVIEW.md](WHOLE_REPO_REVIEW.md). The old status,
feature-matrix, and release-focus docs are not current TideFS authority unless
they are recreated through the review register.
