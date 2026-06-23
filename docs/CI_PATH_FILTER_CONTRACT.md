# CI Path Filter Contract

Audit of standing TideFS workflow path filters as of 2026-06-23, matching
`.github/workflows/*.yml` against the prose in `docs/GITHUB_CI.md`.

**Purpose**: Let workers determine which changes trigger which checks before
dispatching extra validation. No workflow, source, or CI behavior is changed
by this document.

## Standing Workflows

### PR Gate Workflows

These workflows run on pull-request events (`opened`, `synchronize`, `reopened`,
`ready_for_review`) targeting `master`. Draft PRs are skipped unless noted.

| Workflow | PR Filter | Push / Master | Manual Dispatch | Docs-Only Trigger? | Runner Labels |
|---|---|---|---|---|---|
| **Actionlint** | `paths`: `.github/workflows/**`, `.github/actionlint.yaml` | `paths` (same) | Yes | No | `self-hosted,linux,x64,tidefs,nix` |
| **Clippy** | `paths`: `.github/workflows/clippy.yml`, `Cargo.lock`, `Cargo.toml`, `apps/**`, `crates/**`, `kmod/**`, `xtask/**`, `scripts/clippy-baseline.sh`, `docs/CARGO_CLIPPY_BASELINE.md`, `docs/clippy-baseline.json` | None | Yes (scope input) | No (only clippy-specific docs) | `self-hosted,linux,x64,tidefs,nix` |
| **Rust Fast** | `paths-ignore`: `docs/**`, `*.md`, `COPYING` | No filter (always) | Yes | No (ignored) | `self-hosted,linux,x64,tidefs,nix` |
| **Nix Checks** | `paths-ignore`: `docs/**`, `*.md`, `COPYING` | No filter (always) | Yes | No (ignored) | `self-hosted,linux,x64,tidefs,nix` |
| **Secret Policy** | `paths`: `.github/workflows/**`, `docs/GITHUB_CI.md`, `AGENTS.md`, `xtask/tidefs-xtask/**`, `Cargo.toml`, `Cargo.lock`, `flake.nix`, `flake.lock` | No filter (always) | Yes | Only `docs/GITHUB_CI.md`; general docs do not trigger | `self-hosted,linux,x64,tidefs,nix` |
| **Rust Toolchain** | `paths`: `rust-toolchain.toml`, `flake.nix`, `flake.lock`, `.github/workflows/rust-toolchain.yml`, `docs/RUST_TOOLCHAIN_CI.md` | `paths` (same) | Yes | No (only toolchain-specific docs) | `self-hosted,linux,x64,tidefs,nix` |
| **Dependency License** | `paths`: `Cargo.toml`, `Cargo.lock`, `deny.toml`, `flake.nix`, `flake.lock`, `.github/workflows/dependency-license.yml`, `docs/adr/0006-license-compliance-cargo-deny.md`, `docs/DEPENDENCY_LICENSE_CI.md` | No filter (always) | Yes | Only license-specific docs; general docs do not trigger | `self-hosted,linux,x64,tidefs,nix` |
| **Dependency Advisory** | `paths`: `deny.toml`, `Cargo.lock`, `Cargo.toml`, `crates/*/Cargo.toml`, `.github/workflows/dependency-advisory.yml` | None | Yes | No | `self-hosted,linux,x64,tidefs,nix` |
| **Focused Rust** | `paths`: `.github/workflows/focused-rust.yml`, `scripts/ci-test-runner.sh`, `flake.nix`, `flake.lock` | None | Yes (crates, cargo_test_args) | No (self-test only) | `self-hosted,linux,x64,tidefs,nix` |

### Manual and Scheduled Workflows

These workflows do not respond to pull-request events and are never
path-filtered beyond their manual-dispatch or schedule triggers.

| Workflow | Trigger | Push / Master | Manual Dispatch | Docs-Only Trigger? | Runner Labels |
|---|---|---|---|---|---|
| **Focused Claim Validation** | `workflow_dispatch` only | No | Yes (mode, claim_id, artifact_path) | N/A (manual) | `self-hosted,linux,x64,tidefs,nix` |
| **QEMU Smoke** | `push` (kmod-xfstests-smoke only), `workflow_dispatch` (8 targets) | No filter (`kmod-xfstests-smoke` on every push) | Yes (target) | Triggers on master push (kmod-xfstests-smoke regardless of path) | `self-hosted,linux,x64,tidefs,nix,kvm` |
| **Kernel fsync/syncfs** | `workflow_dispatch` only | No | Yes (timeout, pool_size) | N/A (manual) | `self-hosted,linux,x64,tidefs,nix,kvm` |
| **Kernel mmap** | `workflow_dispatch` only | No | Yes (timeout) | N/A (manual) | `self-hosted,linux,x64,tidefs,nix,kvm` |
| **RDMA** | `schedule` (`43 2 * * *`), `workflow_dispatch` | No | Yes | N/A (manual/scheduled) | `self-hosted,linux,x64,tidefs,nix,kvm,rdma` |
| **Release Candidate** | `workflow_dispatch` only | No | Yes (profile: smoke/full) | N/A (manual) | Various (rust-smoke, nix, qemu, xfstests, rdma jobs) |
| **xfstests** | `schedule` (`17 1 * * *`), `workflow_dispatch` | No | Yes (target, tests) | N/A (manual/scheduled) | `self-hosted,linux,x64,tidefs,nix,kvm,xfstests` |

### Controller Telemetry

| Workflow | Trigger | Push / Master | Manual Dispatch | Docs-Only Trigger? | Runner Labels |
|---|---|---|---|---|---|
| **Codex Nexus Relay** | Issue events (all), PR events (all types including `converted_to_draft`), push to `master` | Every push | Yes | Triggers on every event (telemetry, not validation) | `self-hosted,linux,x64,tidefs` |

**Classification**: Codex Nexus Relay is controller telemetry, not TideFS
validation. It relays events to the local Nexus dashboard, signs payloads with
a host-local secret, and uses a global concurrency group. Draft PRs are
included so the controller can reconcile live GitHub state. Ignore relay check
runs when evaluating CI gates.

## Draft PR Behavior

All standing PR gate workflows skip draft pull requests via an explicit
`github.event.pull_request.draft == false` condition in the job-level `if:`
expression, except:

- **Focused Rust**: This workflow has a narrow PR self-test trigger (only when
  its own workflow file, `scripts/ci-test-runner.sh`, or flake files are
  modified). It does not include a draft check in its job condition, so it
  runs even on draft PRs that touch those specific paths. This is the
  intentional self-test behavior documented in `docs/GITHUB_CI.md`: "It also
  self-tests on pull requests that modify the focused workflow or its runner
  helper so workflow changes get Actions coverage before merge."

- **Codex Nexus Relay**: Controller telemetry; deliberately includes all PR
  events including drafts.

Manual workflow dispatch remains available for draft-branch evidence regardless
of draft status, as stated in `docs/GITHUB_CI.md`.

## Docs-Only Change Summary

A PR that only touches files under `docs/**`, root `*.md`, or `COPYING` will
trigger the following standing workflows on PR events:

| Workflow | Triggered? | Notes |
|---|---|---|
| Actionlint | No | Limited to `.github/workflows/**` and `.github/actionlint.yaml` |
| Clippy | Only for `docs/clippy-baseline.json` or `docs/CARGO_CLIPPY_BASELINE.md` | General docs are not in path list |
| Rust Fast | No | Explicitly ignored via `paths-ignore` |
| Nix Checks | No | Explicitly ignored via `paths-ignore` |
| Secret Policy | Only for `docs/GITHUB_CI.md` | General docs are not in path list |
| Rust Toolchain | Only for `docs/RUST_TOOLCHAIN_CI.md` | General docs are not in path list |
| Dependency License | Only for `docs/adr/0006-*.md` or `docs/DEPENDENCY_LICENSE_CI.md` | General docs are not in path list |
| Dependency Advisory | No | No doc paths in filter list |
| Focused Rust | No | Self-test trigger only |
| Codex Nexus Relay | Yes (all events) | Controller telemetry, not validation |

**Net effect**: A docs-only PR (e.g., editing `docs/some-design.md`) triggers
zero TideFS validation workflows on PR events. Only the Codex Nexus Relay
telemetry bridge fires. This matches the `docs/GITHUB_CI.md` design: "docs-only
design and authority PRs do not occupy scarce self-hosted runner slots."

**Master push**: `Rust Fast`, `Nix Checks`, `Secret Policy`, `Dependency
License`, `QEMU Smoke` (kmod-xfstests-smoke), and `Codex Nexus Relay` run on
every push to `master` without path filters. A docs-only commit merged to
`master` will consume self-hosted runner capacity for these push-triggered
jobs. This is the documented policy: "pushes to `master` and manual dispatches
still run them."

## Manual Dispatch Override

Every workflow supports `workflow_dispatch`. When an issue validation tier
calls for focused validation despite path filters, dispatch the relevant
workflow manually against the feature branch. Manual dispatch ignores
`TIDEFS_SELF_HOSTED_READY` and draft-PR gates.

Targeted dispatch recommendations:

- **Rust unit tests**: `Focused Rust` with comma-separated crate list
- **Claim/evidence validation**: `Focused Claim Validation` with mode + claim_id/artifact_path
- **Runtime smoke**: `QEMU Smoke` with a single target
- **Kernel durability**: `Kernel fsync/syncfs validation`, `Kernel mmap validation`
- **Filesystem**: `xfstests` with `tests` narrowed to the failing row set
- **Full gate**: `Release Candidate` with `smoke` or `full` profile

## GITHUB_CI.md vs Workflow YAML Review

Audit performed against `.github/workflows/*.yml` at `7832ef9c` and
`docs/GITHUB_CI.md` at the same revision.

### Matches

- `Rust Fast` and `Nix Checks` both use `paths-ignore: docs/**, *.md, COPYING`
  on PRs. Their push triggers have no path filter. Matches prose.
- `Secret Policy` PR runs are limited to workflow/policy files plus xtask and
  build inputs. Matches prose.
- Draft PRs are skipped by all standing PR gate workflows. Matches prose.
- Manual dispatch remains available for draft branches. Matches prose.
- Codex Nexus Relay uses global concurrency and cancels stale runs. Matches
  prose.

### Follow-Up Items

These items record observations that do not contradict `docs/GITHUB_CI.md`
prose but merit awareness. They are listed here so a future issue can decide
whether to align or document the behavior; this slice does not modify
workflows.

1. **Focused Rust draft-PR self-test**: The `Focused Rust` workflow
   (`focused-rust.yml`) does not include a draft-PR skip condition on its PR
   self-test trigger. The GITHUB_CI.md prose says "Draft pull requests are not
   integration candidates, so required self-hosted PR checks skip them."
   Focused Rust's self-test is narrow (only fires when its own workflow,
   runner script, or flake files change) and the omission is the documented
   self-test behavior, but the draft-skip absence is not explicitly called out
   in `docs/GITHUB_CI.md`. A follow-up issue could either add an explicit note
   to `docs/GITHUB_CI.md` about the self-test exception or add a draft gate to
   the workflow.

2. **Push-triggered workflows without path filters**: `Secret Policy`,
   `Dependency License`, and `QEMU Smoke` run on every push to `master`
   without path filters. `docs/GITHUB_CI.md` explicitly notes this behavior
   for `Rust Fast` and `Nix Checks` ("pushes to `master` and manual dispatches
   still run them") but does not enumerate the other push-triggered workflows.
   The behavior is correct and matches the workflow YAML; only the prose list
   in `docs/GITHUB_CI.md` is incomplete.

3. **`Actionlint` push path filter**: `actionlint.yml` applies a `paths`
   filter on push (only `.github/workflows/**` and `.github/actionlint.yaml`),
   so a push that does not touch workflow files skips actionlint. This is
   narrower than the other push-triggered workflows and is not mentioned in
   `docs/GITHUB_CI.md`. It is correct behavior (no reason to lint workflows
   that haven't changed) but worth noting for completeness.

None of these items are blockers; they are candidates for a separate
documentation or workflow refinement issue.

## Validation

Per issue #1102 validation tier:

- `git diff --check` clean.
- Table content compared against `.github/workflows/*.yml` revision `7832ef9c`
  and `docs/GITHUB_CI.md` same revision.
- No GitHub Actions dispatch, local Cargo/Nix build, QEMU, xfstests, RDMA, or
  release-candidate validation required.
