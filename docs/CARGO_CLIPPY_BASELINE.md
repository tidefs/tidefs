# Cargo Clippy Baseline

Issue #1075 establishes the TideFS clippy warning baseline and CI gate.

The machine-readable snapshot is `docs/clippy-baseline.json`. It records the
current warning count per workspace crate for the command shape used by the
gate:

```sh
cargo clippy -p <crate> --locked --all-targets --message-format=json
```

The baseline gate is `scripts/clippy-baseline.sh`. On pull requests the
`Clippy` workflow runs the script in changed-crate mode. If a crate emits more
warnings than its recorded count, the workflow fails and uploads
`clippy-baseline-summary.json`.

Root lint policy is recorded in `Cargo.toml`:

- `unsafe_code = "deny"` is a Rust lint policy for non-kernel/non-FFI crates.
- `missing_safety_doc = "deny"` keeps public unsafe contracts documented.
- `cast_lossless = "warn"` flags avoidable casts without blocking existing
  warning-free crates.

Kernel, FFI, and capability-test crates may need explicit crate-local lint
policy when they inherit workspace lints. That exception path is deliberately
manifest-local so unsafe-code audit work remains separate from this clippy
baseline gate.
