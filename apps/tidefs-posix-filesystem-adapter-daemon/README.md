# tidefs-posix-filesystem-adapter-daemon

FUSE adapter entrypoint for preview mounted TideFS runs. The daemon connects
Linux FUSE requests to the TideFS VFS engine and local filesystem stack; it is
an app-local operator entrypoint and validation harness, not a POSIX-complete,
production, release-readiness, or successor/comparator claim.

## Authority

Use this README for orientation only. Current behavior and status live in:

- source handlers under `src/` and mounted/runtime tests under `tests/`;
- FUSE boundary policy in `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md`;
- product-admission state in `validation/claims.toml` and generated
  `docs/CLAIM_REGISTRY.md`;
- publishing wording rules in `docs/CLAIMS_GATE_POLICY.md`;
- workflow and artifact authority in `docs/GITHUB_CI.md`;
- live GitHub issues, pull requests, and their validation evidence.

The `mounted-posix-operator-runtime` admission gate remains blocked. Do not use
this app README as an operation matrix, xfstests scorecard, errno table,
writeback/cache capability manual, or runtime proof.

## Developer Entry Points

Run the binary with `--help` for the current subcommands and flags. The common
developer entry points are mount, smoke-mount, VFS-backed mount, POSIX
scoreboard, coverage-gap diagnostics, charter rendering, and receipt-demo
diagnostics.

Current entry-point commands live in `docs/GETTING_STARTED.md`; CI lane and
artifact authority lives in `docs/GITHUB_CI.md`; xfstests scoreboard details
live in `docs/xfstests-harness.md`. Validation scope and required GitHub
Actions lanes belong in the issue or pull request that changes the adapter
behavior.
