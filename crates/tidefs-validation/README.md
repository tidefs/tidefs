# tidefs-validation

This crate is validation support, not product acceptance by itself.

**Focused validation commands:** `docs/GITHUB_CI.md` and the workflow YAML in
`.github/workflows/` are the authoritative command map for narrow
source/validation work. Claims-specific validation is governed by
`docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, and the generated
`docs/CLAIM_REGISTRY.md`.

Production release validation must come from executed runs: FUSE, ublk, RDMA,
multi-node, Kbuild, Linux 7.0 QEMU, mounted-kernel VFS, kernel block-I/O, or
full-kernel no-daemon logs. Source/model rows, CargoUnit rows,
schema-only rows, generated scoreboards, and harness-presence checks are
non-closing validation.

## Active Roles

- Shared runtime artifact contracts such as `runtime_artifact_source`.
- Generic performance-gate machinery that requires measured artifacts for
  release PASS rows.
- Parsers and helpers for real workload output.
- Focused smoke checks for product crates when those checks exercise product
  behavior directly.

## Retired Roles

The crate no longer carries standalone validation bundles whose only
successful rows are SourceModel, CargoUnit, schema, or harness tiers. Retired
families include no-daemon residency matrices, current-head source matrices,
schema-only xfstests validation, simulated ublk crash/flush rows, and
source/cargo performance-budget rows.

New validation work should either run the real target path and write output
under `/root/ai/tmp/tidefs-validation/`, or report the exact product blocker
found while attempting that run.
