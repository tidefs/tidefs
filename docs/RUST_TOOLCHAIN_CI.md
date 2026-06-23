# Rust Toolchain CI Gate

The `Rust Toolchain` workflow
([.github/workflows/rust-toolchain.yml](../.github/workflows/rust-toolchain.yml))
verifies that the pinned Rust toolchain in `rust-toolchain.toml` and its required
components remain coherent when toolchain or Nix inputs change. It is a
validation-only gate: it reports the observed versions and expected channel but
does not change the toolchain version or crate source.

## Authority

- `rust-toolchain.toml` — canonical toolchain channel, profile, and component
  list.
- `flake.nix` — consumes `rust-toolchain.toml` through
  `rust-bin.fromRustupToolchainFile` in the `.#ci` dev shell and all package
  derivations.

## Triggers

- **Push to `master`** that touches `rust-toolchain.toml`, `flake.nix`,
  `flake.lock`, the workflow file, or this documentation.
- **Pull request** that touches the same files.
- **Manual dispatch** (`workflow_dispatch`) for ad-hoc toolchain verification
  against any branch.

The workflow respects the draft-PR skip convention and uses the
`TIDEFS_SELF_HOSTED_READY` repository variable gate.

## Gate Outcome

The gate passes only when all of the following hold inside the `nix develop .#ci`
shell:

- `rustc --version` reports the channel pinned in `rust-toolchain.toml`.
- `cargo --version` reports a matching version.
- `cargo clippy --version` reports a matching version and clippy is available.
- `rustfmt --version` reports a matching version.
- `rust-src` is present in the sysroot (`$(rustc --print sysroot)/lib/rustlib/src/rust`).

The workflow is a fast coherence check that completes in seconds; it is not a
substitute for `Rust Fast` or `Focused Rust` build-and-test lanes.

## Job Summary

The workflow summary records:

- The expected channel parsed from `rust-toolchain.toml`.
- A table of each component with its observed version or availability status.
- A pass/fail verdict: all components verified, or a count of verification
  failures.

## Manual Run

```sh
gh workflow run rust-toolchain.yml --ref <branch>
```

## Toolchain Version Change Policy

This gate detects toolchain drift but does not change the pinned version. A
Rust version change must use a separate GitHub issue whose acceptance criteria
include the new version, the updated `rust-toolchain.toml`, a regenerated
`Cargo.lock`, compilation through `Rust Fast`, and any version-specific code
adjustments. This gate then provides evidence that the CI toolchain aligns with
the updated pin.

## Relationship to Other CI Lanes

- **Rust Toolchain** (this lane): fast toolchain component and channel
  coherence check only.
- **Rust Fast / Focused Rust**: build and test lanes; they use the toolchain
  verified by this gate but do not validate component availability.
- **Nix Checks**: builds pure Nix derivations including the toolchain itself,
  but does not run the toolchain components or verify version strings.
- **Dependency Advisory / License**: operate on Cargo dependency metadata and
  are unrelated to the Rust toolchain version.
