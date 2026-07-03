# TideFS xfstests Dispatch Contract

This document records the concrete xfstests dispatch contract as observed in
`.github/workflows/xfstests.yml`, `docs/GITHUB_CI.md`, and the referenced Nix
flake validation commands. It is a documentation-only reference; it does not
change any workflow, source, flake, or runtime behaviour.

## Workflow Summary

- **Workflow name**: `xfstests`
- **Workflow file**: `.github/workflows/xfstests.yml`
- **Triggers**:
  - `workflow_dispatch` (manual) with `target` and optional `tests` inputs.
  - `schedule` at `17 1 * * *` (01:17 UTC daily).
- **Concurrency group**: `${{ github.workflow }}-${{ github.ref }}-${{ inputs.target || 'scheduled' }}`.
  `cancel-in-progress` is `false`.
- **Timeout**: 240 minutes per job.
- **Job condition**: Runs when the event is `workflow_dispatch`, or when the
  repository variable `TIDEFS_SELF_HOSTED_READY` is `1`.

## Targets

The workflow accepts one of four `target` values. Three are matrix jobs; the
fourth (`all`) dispatches every matrix job.

### Target: `all`

- **Input type**: `choice` (default).
- **Behaviour**: The workflow matrix iterates over `fuse`, `kmod-smoke`, and
  `k7-vfs`. Each matrix job runs only when the dispatch target is `all` or
  matches the matrix target name.
- **Evidence scope**: `broad` (no `tests` list supplied) or `focused` (when a
  non-empty `tests` list is supplied).
- **Artifact name pattern**: `xfstests-fuse`, `xfstests-kmod-smoke`,
  `xfstests-k7-vfs`.

### Target: `fuse`

- **Validation command**:
  ```
  nix run .#fuse-xfstests-validation -- [--tests "TEST1 TEST2 ..."] \
    --output "$ARTIFACT_ROOT/validation.json"
  ```
- **Environment variables**:
  - `TIDEFS_FUSE_XFSTESTS_TMPDIR` = `$WORK_ROOT/fuse`
- **Default tests** (when no `tests` input): `generic/001` through `generic/013`
  (13 smoke tests).
- **Guest VM**: Linux 7.0 QEMU guest, FUSE mount of TideFS userspace daemon.
- **Output artifact**: `xfstests-fuse`
- **Key artifact files**: `validation.json`, `xfstests-run-manifest.json`,
  `artifact-root.env`
- **Evidence scope**: `focused` when `tests` input is non-empty, otherwise
  `broad`.

### Target: `kmod-smoke`

- **Validation command**:
  ```
  nix run .#kmod-xfstests-smoke -- --timeout 3600 [--tests "TEST1 TEST2 ..."]
  ```
- **Environment variables**:
  - `TIDEFS_OUTPUT_ROOT` = `$ARTIFACT_ROOT`
- **Default tests** (when no `tests` input): `authority/missing-pool
  configured-pool-member` (two internal smoke labels, not upstream xfstests
  group/test names).
- **Supported focused `tests` labels**: `authority/missing-pool` and
  `configured-pool-member`. Unknown labels fail closed with exit code 2 before
  QEMU starts.
- **Guest VM**: Linux 7.0 QEMU guest, `tidefs_posix_vfs.ko` loaded, minimal
  authority and mount smoke checks.
- **Output artifact**: `xfstests-kmod-smoke`
- **Key artifact files**: `qemu.log` (copied into a timestamped subdirectory
  under the artifact root), `xfstests-run-manifest.json`, `artifact-root.env`
- **Evidence scope**: `focused` when a non-empty supported internal label list
  is supplied, otherwise `broad`. The run-level manifest records the resolved
  internal label set actually selected by the harness. Unsupported labels are
  recorded as a selection error, not focused smoke evidence.

### Target: `k7-vfs`

- **Validation command**:
  ```
  nix run .#k7-vfs-xfstests-validation -- [--tests "TEST1 TEST2 ..."] \
    --output "$ARTIFACT_ROOT/validation.json"
  ```
- **Environment variables**:
  - `TIDEFS_K7_TFS_XFSTESTS_TMPDIR` = `$WORK_ROOT/k7-vfs`
- **Default tests** (when no `tests` input): `generic/001` through `generic/013`
  (13 smoke tests).
- **Guest VM**: NixOS VM booted with Linux 7.0 and loaded `tidefs_posix_vfs.ko`.
  Real upstream `xfstests-check` inside the guest.
- **Output artifact**: `xfstests-k7-vfs`
- **Key artifact files**: `validation.json`, `xfstests-run-manifest.json`,
  `artifact-root.env`, `nix-vm-build.log` (when present).
- **Evidence scope**: `focused` when `tests` input is non-empty, otherwise
  `broad`.

## `tests` Input

- **Type**: `string` (optional, default empty).
- **Format**: Space-separated test names (e.g. `generic/001 generic/002`).
- **Effect on evidence scope**: A non-empty `tests` input after whitespace
  stripping sets the evidence manifest `evidence_scope` to `focused`; an empty
  or whitespace-only input sets it to `broad`.
- **How each target uses `tests`**:
  - `fuse`: Passed to `tidefs-fuse-xfstests-validation` as `--tests "..."`.
    Defaults to `generic/001`–`generic/013`.
  - `kmod-smoke`: Passed to `tidefs-kmod-xfstests-smoke` as `--tests "..."`.
    Defaults to `authority/missing-pool configured-pool-member` (internal smoke
    labels).
  - `k7-vfs`: Passed to `tidefs-k7-vfs-xfstests-validation` as `--tests "..."`.
    Defaults to `generic/001`–`generic/013`.

## Runner Labels

All xfstests jobs require:

```
self-hosted, linux, x64, tidefs, nix, kvm, xfstests
```

The `all` dispatch runs three concurrent matrix jobs, each matching one target,
on the same label set. The host must provide `/dev/kvm` and `/dev/fuse`.

## Artifact Name and Path Shape

| Target      | GitHub artifact name     | Artifact root path (on runner)                                                                  |
|-------------|--------------------------|-------------------------------------------------------------------------------------------------|
| `fuse`      | `xfstests-fuse`          | `${{ runner.temp }}/tidefs-xfstests-artifacts/${{ github.run_id }}-${{ github.run_attempt }}/fuse` |
| `kmod-smoke`| `xfstests-kmod-smoke`    | `${{ runner.temp }}/tidefs-xfstests-artifacts/${{ github.run_id }}-${{ github.run_attempt }}/kmod-smoke` |
| `k7-vfs`    | `xfstests-k7-vfs`        | `${{ runner.temp }}/tidefs-xfstests-artifacts/${{ github.run_id }}-${{ github.run_attempt }}/k7-vfs` |

All artifacts have `retention-days: 7`.

Each artifact contains an `xfstests-run-manifest.json` run-level manifest with
the following fields. This is the xfstests-specific schema validated by
`validate-xfstests-evidence-manifest`; it is not the generic claim
`EvidenceArtifactManifest` schema used by `evidence-manifest.json` files.

- `manifest_version` (number, currently `1`)
- `workflow` (e.g. `xfstests`)
- `run_id`, `run_attempt` (GitHub Actions run identifiers)
- `source_ref`, `source_sha` (the dispatched branch and commit)
- `target` (the matrix target name: `fuse`, `kmod-smoke`, or `k7-vfs`)
- `evidence_scope` (`broad` or `focused`)
- `tests` (array of requested test names, omitted when empty)
- `artifact_paths` (array of relative paths to all non-manifest files in the
  artifact root)
- `selection_error` (unsupported selector rejected before focused evidence was
  recorded, omitted when empty)
- `started_at` (UTC timestamp from `artifact-root.env` when available)
- `finished_at` (UTC timestamp written at manifest creation time)

## Evidence Scope Rules

- **Row-specific evidence**: A run with a non-empty `tests` list produces
  `evidence_scope: focused`. The `tests` array names exactly which xfstests
  rows or supported smoke labels were exercised. Only those rows'
  classifications are evidence for the dispatched ref. Unsupported `kmod-smoke`
  labels fail closed and are recorded as a selection error rather than focused
  evidence.
- **Target-wide evidence**: A run without a `tests` list (or with an empty
  `tests` input) produces `evidence_scope: broad`. The result covers the
  target's full default tranche.
- **Product claims**: The evidence manifest records classification counts
  (pass, fail, blocked, unsupported, skip, deferred) for the requested rows
  but does not itself make a product-readiness claim. Claim-registry entries
  and release-candidate evidence indexes are separate concerns governed by
  other workflows and docs (`Focused Claim Validation`, `Release Candidate`,
  `docs/CLAIM_REGISTRY.md`).

## Smallest-Row Rule

From `docs/GITHUB_CI.md`:

> Use the smallest known failing row set such as `generic/003` while debugging
> an isolated failure; reserve broad target dispatches such as `target=fuse` or
> `target=all` for acceptance gates, scheduled coverage, or when the failure
> set is not yet isolated.

In practice this means:

1. After a runtime failure is isolated to one or a few specific xfstests rows,
   dispatch only those rows: set `target` to the relevant target and `tests` to
   the space-separated row names (e.g. `generic/003`).
2. Reserve `target=fuse`, `target=k7-vfs`, or `target=all` with an empty
   `tests` input for:
   - PR or milestone acceptance gates,
   - scheduled daily coverage,
   - still-unisolated failures where the failing row set is unknown.
3. Do not dispatch broad targets as a debug-loop step; use the narrowest row
   set that reproduces the failure.

### Target-Specific Row Granularity

- **`fuse` and `k7-vfs`**: `tests` names are upstream xfstests group/test
  identifiers (e.g. `generic/003`, `generic/007`). These targets honour the
  smallest-row rule at the individual xfstests test granularity.
- **`kmod-smoke`**: `tests` names are internal smoke labels
  (`authority/missing-pool`, `configured-pool-member`), not upstream xfstests
  rows. The kmod-smoke target is a lightweight smoke harness, not a full
  xfstests runner; its `tests` input narrows the smoke check set rather than
  selecting upstream xfstests rows. Unsupported labels such as `generic/003`
  fail closed and must not be interpreted as focused `kmod-smoke` evidence.

## Scheduling and Manual-Only Behaviour

- **Scheduled runs** (`schedule` trigger): Run only when
  `TIDEFS_SELF_HOSTED_READY` is `1`. No `tests` input is available; all three
  matrix targets run with their default test sets and `evidence_scope: broad`.
- **Manual runs** (`workflow_dispatch` trigger): Always run regardless of
  `TIDEFS_SELF_HOSTED_READY`. The `target` and `tests` inputs are available.

## Follow-Up Notes

These observations record ambiguity or naming gaps between the referenced
sources. They are not addressed in this documentation slice.

1.  **`kmod-xfstests-smoke` vs `kmod-xfstests-validation`**: The workflow
    dispatches `.#kmod-xfstests-smoke`, but the flake also defines
    `.#kmod-xfstests-validation` (a separate app pointing at a different
    package, `kernelXfstestsValidation`). The `kmod-xfstests-validation` app is
    not wired into any workflow. Its relationship to the smoke harness and
    whether it should replace or supplement it is not documented.

2.  **`fuse-xfstests-vm` vs `fuse-xfstests-validation`**: The flake defines
    both `.#fuse-xfstests-vm` and `.#fuse-xfstests-validation`. They invoke the
    same binary with the same arguments. Only `.#fuse-xfstests-validation` is
    wired into the workflow. The `-vm` alias is unused and may be stale.

3.  **`qemu-k7-vfs-xfstests-validation`**: The flake defines
    `.#qemu-k7-vfs-xfstests-validation` as an alias for
    `.#k7-vfs-xfstests-validation`. It is not referenced by any workflow.
    Intentional alias or stale naming is not recorded.

4.  **`kmod-smoke` artifact paths**: Unlike `fuse` and `k7-vfs`, the
    `kmod-smoke` harness writes its `qemu.log` into a timestamped subdirectory
    under the artifact root. The `xfstests-run-manifest.json` `artifact_paths`
    array records these relative paths, but the shape differs from the flat
    `validation.json` output of the other targets.
