# tidefs-posix-filesystem-adapter-daemon

Library carrier connecting Linux FUSE requests to the TideFS VFS engine and
Pool-backed local filesystem. Operators reach it through `tidefsctl pool
mount`; this package's binary is not a second mount entrypoint.

## Authority

Use this README for orientation only. Current behavior and status live in:

- source handlers under `src/` and mounted/runtime tests under `tests/`;
- FUSE boundary policy in `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md`;
- workflow and artifact authority in `docs/GITHUB_CI.md`;
- live GitHub issues and pull requests.

Do not use this app README as an operation matrix, xfstests scorecard, errno
table, writeback/cache capability manual, or runtime proof.

## Developer Entry Points

Use `tidefsctl pool create` and `tidefsctl pool mount --devices` for every
mounted lifecycle. The package binary retains only focused development
diagnostics; it does not create, import, or mount a filesystem.

Current entry-point commands live in `docs/GETTING_STARTED.md`; CI lane and
artifact authority lives in `docs/GITHUB_CI.md`; xfstests dispatch and artifact
details live in `docs/XFSTESTS_DISPATCH_CONTRACT.md`. Local scoreboard behavior
remains source-owned by the adapter and validation crates. Validation scope and
required GitHub Actions lanes belong in the issue or pull request that changes
the adapter behavior.
