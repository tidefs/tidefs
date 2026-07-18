# tidefs-block-kmod

Crate-local orientation for the TideFS kernel block-volume module.

This README is not product, release, successor/comparator, or kernel-residency
authority. Use `docs/KERNEL_RESIDENCY_AUTHORITY.md`,
`docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`, `validation/claims.toml`,
and the generated claim registry for those boundaries.

## Source Map

- `tidefs_block_kmod.rs` is the Linux Kbuild entrypoint. It registers the
  block device and wires Linux request callbacks to the Rust dispatch path.
- `src/device.rs` models the block-device lifecycle and the cargo-side
  request path used by tests.
- `src/dispatch.rs` classifies block operations and sends read, write, flush,
  discard, write-zeroes, and zero-range requests to a `BlockBackend`.
- `src/pool_core_backend.rs` adapts block-kmod dispatch to pool-core logical
  volume operations and contains the self-stacking rejection hook.
- `src/raw_block_file.rs` provides the current file-backed bring-up adapter for
  `/dev/tidefs_pool_member`.
- `src/backend_mode.rs`, `src/ioctl.rs`, `src/lifecycle.rs`,
  `src/open_release.rs`, `src/request_completion.rs`, and `src/timeout.rs`
  hold local policy and lifecycle helpers.

## Kernel Request Path

The Linux module dispatches I/O through the blk-mq `queue_rq` callback used by
the Linux 7.0 Rust-for-Linux block bindings. The supported baseline does not
provide a Rust `submit_bio` operation for `kernel::block::mq::Operations`.

Bio fields, bio segment walking, and page mapping still cross unsafe C binding
boundaries in the Kbuild entrypoint because the supported Rust-for-Linux
baseline does not expose safe Rust wrappers for all of those kernel APIs. Keep
changes to that code close to the local safety comments and scoped unsafe-code
lint allowances.

## Backend Selection

The normal Kbuild path tries to open `/dev/tidefs_pool_member` and register a
pool-backed block device. Registration fails closed when that backend is not
available.

The in-memory `BlockExport` backend is an explicit bring-up and smoke-test
mode, enabled only with `--cfg=tidefs_block_kmod_bringup_backend`. It is useful
for exercising request dispatch, but it is not pool-backed storage evidence.

`PoolCoreBackend` is the source-local adapter for pool-core logical-volume I/O.
Follow the kernel authority docs before changing claim wording around shared
pool-core integration, production readiness, daemon independence, or exported
block-volume behavior.

## Developer Notes

- Keep queue-limit facts in source comments and tests unless a kernel-facing
  operator procedure needs to live in an authority doc.
- Keep runtime inspection recipes in workflow or validation docs, not here.
- Do not add product-claim evidence to this README; update the claim registry
  inputs and authority docs instead.
