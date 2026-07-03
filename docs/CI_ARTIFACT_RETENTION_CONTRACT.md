# CI Artifact Retention Contract

**Last updated**: 2026-06-23
**Source**: bounded inspection of `.github/workflows/*.yml`

This document inventories every GitHub Actions artifact uploaded by TideFS
workflows, its retention window, upload path pattern, and whether the
artifact is TideFS validation evidence or relay/controller telemetry.
Workflows that intentionally write only job summaries and upload no
artifact are also recorded.

Terms used below:

- **Validation evidence**: an artifact produced by a TideFS CI workflow
  whose content can confirm or refute an acceptance criterion, gate a
  pull request, or serve as a claims-gate or release-candidate input.
- **Relay/controller telemetry**: an artifact or workflow run whose job
  is to relay GitHub events to the local `tidefs-codex-nexus` controller;
  it never runs tests or checks out source. These runs must not be
  treated as CI gates.
- **Summary only**: the workflow writes a job summary (Markdown rendered
  by GitHub Actions on the run page) but does not upload a downloadable
  artifact. The summary is the only evidence surface for that workflow.

---

## Artifact inventory

### Validation evidence with uploaded artifacts

| Workflow file | Artifact name pattern | Retention | Upload path pattern | Evidence surface |
|---|---|---|---|---|
| `rust-fast.yml` | `rust-fast-summary` | 7 days | `ci-test-summary.json` | Rust smoke summary JSON |
| `clippy.yml` | `clippy-baseline-summary` | 7 days | `clippy-baseline-summary.json` | Clippy baseline comparison JSON |
| `focused-rust.yml` | `focused-rust-summary` | 7 days | `ci-test-summary.json` + `ci-test-summary-evidence-manifest.json` | Focused crate test summary + evidence manifest |
| `qemu-smoke.yml` | `qemu-smoke-${{ matrix.name }}` (7 matrix targets) | 7 days | `${{ matrix.output_dir }}/**` | Runtime smoke output (logs, summary.env, evidence manifests for kernel-fsync target) |
| `kernel-mmap-validation.yml` | `kernel-mmap-validation` | 7 days | `/tmp/tidefs-validation/kernel-mmap-validation/**` | Kernel mmap/writeback row artifacts |
| `kernel-fsync-validation.yml` | `kernel-fsync-validation` | 7 days | `/tmp/tidefs-kmod-fsync-validation/**` + `/tmp/tidefs-validation/kernel-fsync-validation/**` | Kernel fsync/syncfs durability row artifacts + evidence manifest |
| `xfstests.yml` | `xfstests-${{ matrix.target }}` (3 targets: fuse, kmod-smoke, k7-vfs) | 7 days | `${{ runner.temp }}/tidefs-xfstests-artifacts/${{ run_id }}-${{ run_attempt }}/${{ matrix.target }}/` | xfstests output + evidence manifest per target |
| `rdma.yml` | `rdma-${{ matrix.name }}` (3 targets: static-carrier-check, host-probe, qemu-two-node) | 7 days | `/tmp/tidefs-rdma-two-node/**` + `/tmp/tidefs-validation/**` | RDMA row artifacts + evidence manifest per target |
| `dependency-advisory.yml` | `dependency-advisory-report` | 7 days | `advisories-report.json`, `advisories.json`, `advisories-stderr.txt` | cargo-deny advisory check JSON + stderr |
| `release-candidate.yml` | `release-candidate-rust-summary` | 14 days | `ci-test-summary.json` | Rust smoke summary for RC |
| `release-candidate.yml` | `release-candidate-qemu-${{ matrix.name }}` (1 target: kmod-xfstests-smoke) | 14 days | `/tmp/tidefs-validation/**` | QEMU smoke runtime output for RC |
| `release-candidate.yml` | `release-candidate-xfstests-${{ matrix.target }}` (3 targets: fuse, kmod-smoke, k7-vfs) | 14 days | `/tmp/tidefs-validation/**` | xfstests output for RC (full profile only) |
| `release-candidate.yml` | `release-candidate-rdma-${{ matrix.name }}` (3 targets: static-carrier-check, host-probe, qemu-two-node) | 14 days | `/tmp/tidefs-rdma-two-node/**` + `/tmp/tidefs-validation/**` | RDMA output for RC (full profile only) |
| `release-candidate.yml` | `release-candidate-evidence-index` | 14 days | `release-candidate-evidence-index/index.json` | Candidate evidence index JSON (required, `if-no-files-found: error`) |

### Validation evidence with job summary only (no uploaded artifact)

| Workflow file | Summary content | Evidence surface |
|---|---|---|
| `focused-claim-validation.yml` | Input validation report, command executed, status/result | Claim validation outcome rendered in step summary |
| `dependency-license.yml` | Ref, SHA, `cargo deny check licenses` outcome | License compliance gate rendered in step summary |
| `rust-toolchain.yml` | Expected channel, host triple, commit, per-component versions (rustc, cargo, clippy, rustfmt, rust-src) | Toolchain verification table rendered in step summary |
| `actionlint.yml` | actionlint version and lint report | Workflow lint results rendered in step summary |

### Validation evidence with pass/fail only (no uploaded artifact, no job summary)

| Workflow file | Evidence surface |
|---|---|
| `nix-checks.yml` | Pass/fail by exit code; builds `.#checks.x86_64-linux.rdmaCarrierTwoNode` and three core packages |
| `secret-policy.yml` | Pass/fail by exit code; runs seeded violation fixtures and forbidden-secret-surface scan |

### Relay/controller telemetry (not TideFS validation evidence)

| Workflow file | Evidence surface |
|---|---|
| `tidefs-codex-nexus-relay.yml` | Signs and POSTs the original GitHub event payload to the local `tidefs-codex-nexus` webhook endpoint. Never runs tests or checks out source. Pull-request relay runs allocate runners only for source-head and lifecycle wakeups; pending PR wakeups coalesce per PR while running deliveries finish, and issue, push, and manual-dispatch wakeups still coalesce globally. These workflow runs, checks, and statuses must not be treated as CI gates. |

---

## QEMU Smoke matrix targets

The `qemu-smoke.yml` workflow runs a matrix of seven targets from a single
workflow file. The per-target artifact names are:

| Target id | Artifact name | Output directory |
|---|---|---|
| `kmod-xfstests-smoke` | `qemu-smoke-kmod-xfstests-smoke` | `/tmp/tidefs-validation/kmod-xfstests-smoke` |
| `kernel-teardown-validation` | `qemu-smoke-kernel-teardown-validation` | `/tmp/tidefs-validation/kernel-teardown-validation` |
| `kernel-fsync-validation` | `qemu-smoke-kernel-fsync-validation` | `/tmp/tidefs-validation/kernel-fsync-validation` |
| `kernel-mmap-validation` | `qemu-smoke-kernel-mmap-validation` | `/tmp/tidefs-validation/kernel-mmap-validation` |
| `kernel-no-daemon-teardown-validation` | `qemu-smoke-kernel-no-daemon-teardown-validation` | `/tmp/tidefs-validation/kernel-no-daemon-teardown-validation` |
| `fuse-vm-test` | `qemu-smoke-fuse-vm-test` | `/tmp/tidefs-validation/fuse-vm-test` |
| `qemu-ublk-smoke` | `qemu-smoke-qemu-ublk-smoke` | `/tmp/tidefs-validation/ublk` |

Three of these targets also have standalone workflows with independent
artifact names and evidence manifests:

- `kernel-fsync-validation`: standalone `kernel-fsync-validation.yml` is
  the claims-gate authority; the QEMU Smoke sub-target is a smoke-level
  run that records a local evidence manifest but the claims gate defers to
  the standalone workflow.
- `kernel-mmap-validation`: standalone `kernel-mmap-validation.yml` is
  the independent validation lane.
- `kernel-teardown-validation` and `kernel-no-daemon-teardown-validation`:
  no standalone workflow exists; the QEMU Smoke sub-target is the only
  runtime lane for these rows.

---

## Release Candidate artifact naming convention

Release Candidate workflow artifacts follow a distinct naming pattern:
`release-candidate-<lane>-<target>`. All RC artifacts have 14-day retention
(versus the default 7-day) and the top-level evidence index uses
`if-no-files-found: error` (all other RC artifacts use `ignore`).

The `smoke` profile runs Rust, Nix, and QEMU lanes. The `full` profile
also runs xfstests and RDMA lanes. Lane-level artifacts are only uploaded
when their profile is active.

---

## Cross-cutting notes

- All artifact uploads use `actions/upload-artifact@v7`.
- Most validation workflows also write a job summary to `$GITHUB_STEP_SUMMARY`
  that duplicates or summarizes the artifact content. The job summary is the
  only evidence surface for summary-only workflows; for artifact-uploading
  workflows, the artifact is authoritative and the summary is a convenience
  rendering.
- `nix-checks.yml` and `secret-policy.yml` use exit-code-only pass/fail;
  the only artifact of a failure is the run log.
- The `Codex Nexus Relay` workflow is controller telemetry, not validation
  evidence. It must not be counted as pending, failing, or passing CI when
  evaluating PR readiness or merge gates. Pull-request relay runs skip
  metadata-only edits before allocating a runner and coalesce stale pending
  wakeups by PR because Nexus reconciles from live GitHub state. The Current
  queue summary in `tidefs-codex-nexus` already separates relay and non-relay
  check/run evidence.

---

## Follow-up notes

- The `kernel-teardown-validation` and `kernel-no-daemon-teardown-validation`
  QEMU Smoke sub-targets lack standalone workflows and do not produce
  evidence manifests in `qemu-smoke.yml`. Their sole evidence surface is
  the uploaded runtime output under their respective artifact names
  (`qemu-smoke-kernel-teardown-validation` and
  `qemu-smoke-kernel-no-daemon-teardown-validation`). If standalone
  claims-gate authority workflows are added for these rows, this contract
  should be updated.
- `release-candidate.yml` `qemu` job writes one fixed matrix target
  (`kmod-xfstests-smoke`), but the QEMU Smoke workflow (`qemu-smoke.yml`)
  runs seven. These are intentionally different scopes. The RC does not
  claim to cover all QEMU Smoke targets.
- `focused-claim-validation.yml` does not upload an artifact even though
  workflows such as `validate-evidence-manifest` and
  `validate-ublk-completion` accept an `artifact_path` input; the
  workflow's purpose is validation of an existing artifact, not production
  of a new one.
