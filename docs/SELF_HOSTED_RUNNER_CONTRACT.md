# Self-Hosted Runner Contract

This document inventories the GitHub Actions self-hosted runner label sets used
by each TideFS workflow, maps labels to required host capabilities, and records
the distinction between runner labels, repository variables, draft-PR skip
behavior, and manual-dispatch exceptions.

Source authority: workflow files under `.github/workflows/` plus the existing
CI documentation in `docs/GITHUB_CI.md`. This document is a snapshot of the
current codebase; it does not change runner labels, workflow scheduling, or
runner host configuration.

## Runner Label Inventory

Every TideFS workflow job uses a `runs-on` label list. Five distinct label sets
appear in the current workflow tree.

### Label set A: `[self-hosted, linux, x64, tidefs, nix]`

The most common set. Requires a self-hosted Linux x86-64 runner with Nix.

Workflows using this set:

| Workflow | Trigger | Draft skip? |
|---|---|---|
| `Rust Fast` | push, PR (ready), manual | yes |
| `Clippy` | PR (source paths), manual | yes |
| `Nix Checks` | push, PR (ready), manual | yes |
| `Focused Rust` | PR (workflow self-test), manual | no (manual-only gate) |
| `Secret Policy` | push, PR (source paths), manual | yes |
| `Dependency License` | push, PR (source paths), manual | yes |
| `Dependency Advisory` | PR (source paths), manual | yes |
| `Actionlint` | push, PR (source paths), manual | yes |
| `Rust Toolchain` | push, PR (source paths), manual | yes |
| `Release Candidate` (rust-smoke, nix, index) | manual only | N/A |
| `Focused Claim Validation` | manual only | N/A |

### Label set B: `[self-hosted, linux, x64, tidefs, nix, kvm]`

Adds KVM to the base Nix set. Requires `/dev/kvm` and virtualization
capabilities.

Workflows using this set:

| Workflow | Trigger | Draft skip? |
|---|---|---|
| `QEMU Smoke` | push, manual | N/A (no PR trigger) |
| `Release Candidate` (qemu) | manual only | N/A |
| `Kernel fsync/syncfs validation` | manual only | N/A |
| `Kernel mmap validation` | manual only | N/A |

### Label set C: `[self-hosted, linux, x64, tidefs, nix, kvm, xfstests]`

Adds xfstests to the KVM set. Requires the xfstests test suite binaries and
scratch space for xfstests work directories and VM-backed filesystem test
devices.

Workflows using this set:

| Workflow | Trigger | Draft skip? |
|---|---|---|
| `xfstests` | schedule, manual | N/A (no PR trigger) |
| `Release Candidate` (xfstests) | manual only | N/A |

### Label set D: `[self-hosted, linux, x64, tidefs, nix, kvm, rdma]`

Adds RDMA to the KVM set. Requires RDMA-capable hardware, kernel drivers,
userspace tools (libibverbs, rdma-core), and the ability to run two-QEMU-node
networked test topologies.

Workflows using this set:

| Workflow | Trigger | Draft skip? |
|---|---|---|
| `RDMA` | schedule, manual | N/A (no PR trigger) |
| `Release Candidate` (rdma) | manual only | N/A |

### Label set E: `[self-hosted, linux, x64, tidefs]`

The minimal set. Requires only a self-hosted Linux x86-64 runner registered in
the TideFS organization. No Nix, KVM, or other capability labels are demanded
because the job runs only standard Unix tools (curl, perl, bash).

| Workflow | Trigger | Draft skip? |
|---|---|---|
| `Codex Nexus Relay` | issue, PR, push, manual | N/A (not a PR check) |

## Label Capability Map

Each label implies a host capability the runner must provide. The following
table records the semantic contract for every label found in workflow
`runs-on` clauses.

| Label | Required capability |
|---|---|
| `self-hosted` | GitHub self-hosted Actions runner (not GitHub-hosted). All TideFS jobs use this label; no workflow uses `ubuntu-latest` or other hosted-runner labels. |
| `linux` | Linux kernel. All TideFS CI is Linux-only. |
| `x64` | x86-64 (amd64) architecture. |
| `tidefs` | Registered in the `tidefs-ci` runner group for the `tidefs/tidefs` repository. |
| `nix` | Nix package manager with the flake feature available. The `.#ci` development shell must evaluate and build. |
| `kvm` | `/dev/kvm` character device present and usable. Required for QEMU-based kernel-module and FUSE VM testing. |
| `xfstests` | xfstests test suite installed or available. Required for filesystem-level validation runs that exercise the xfstests harness against FUSE, kernel-module, or k7-vfs mount targets. |
| `rdma` | RDMA-capable network hardware with kernel drivers loaded and userspace libraries (libibverbs, rdma-core) installed. Required for the two-node QEMU RDMA transport validation. |

## Labels Documented But Not Used By Any Workflow

`docs/GITHUB_CI.md` states that each self-hosted runner should carry the full
label set:

```text
self-hosted linux x64 tidefs nix kvm fuse ublk rdma kernel xfstests
```

Three labels in that set do not appear in any current workflow `runs-on`
clause:

- `fuse` — FUSE kernel module availability. While QEMU Smoke and xfstests
  workflows run FUSE-backed tests, they gate on the `kvm` label and check
  `/dev/fuse` at runtime through a host-preflight step rather than requiring a
  dedicated `fuse` runner label.
- `ublk` — ublk (userspace block device) kernel support. QEMU Smoke includes a
  `qemu-ublk-smoke` target, but the runner label is not used. Host capability
  is exercised at runtime rather than through label matching.
- `kernel` — kernel development toolchain. Kernel-module build and Kbuild
  verification happen inside the Nix development shell without a distinct
  runner label.

These labels are present on the runner VMs but unused by the current workflow
tree. See the follow-up notes section below.

## Trigger And Skip Rules

Every non-relay, non-manual workflow job is gated by two conditions:

1. **`TIDEFS_SELF_HOSTED_READY` repository variable**: push-triggered and
   scheduled jobs require this variable to be set to `"1"`. Manual
   `workflow_dispatch` jobs ignore the variable so individual lanes can run
   during bring-up or maintenance.

2. **Draft pull request skip**: PR-triggered jobs skip draft pull requests.
   The `ready_for_review` event re-triggers standing checks on the current
   branch head. Manual dispatch remains available for draft branches that
   need early evidence without marking the PR ready.

The combined gate expression used by most workflows:

```yaml
if: ${{ (github.event_name == 'workflow_dispatch' || vars.TIDEFS_SELF_HOSTED_READY == '1')
        && (github.event_name != 'pull_request' || github.event.pull_request.draft == false) }}
```

The `Nix Checks` workflow uses a slightly different ordering (manual dispatch
checked before the variable) but applies the same logical gates.

`Focused Rust` uses a PR trigger limited to workflow self-test paths (the
workflow file itself, its runner helper script, and flake inputs). Its manual
dispatch has no draft-skip gate since it is not a standing PR check.

## Path Filtering For Docs-Only PRs

`Rust Fast` and `Nix Checks` ignore pull requests that only touch `docs/**`,
root Markdown policy files, or `COPYING`. This conserves self-hosted runner
capacity for source changes. Pushes to `master` and manual dispatches still run
these workflows regardless of paths.

If a documentation-only PR needs runtime or build validation, the issue
validation tier should record that requirement and the author should dispatch
the relevant workflow manually.

## Codex Nexus Relay

The `Codex Nexus Relay` workflow is controller telemetry, not TideFS
validation. It does not run tests, build code, or check out the repository
source tree. Its job:

- Reads the GitHub event payload from `$GITHUB_EVENT_PATH`.
- Signs the payload with the host-local webhook secret at
  `/etc/tidefs-codex-nexus/webhook-secret`.
- POSTs the signed event to the local Nexus dashboard at
  `http://172.16.106.12/tidefs-codex-nexus/webhook/github`.

It uses label set E (`[self-hosted, linux, x64, tidefs]`) and a global
concurrency group so any delivered relay wakeup causes Nexus to reconcile live
GitHub state. Stale relay jobs are cancelled.

Relay check/run status is not TideFS CI evidence. Queued, pending, cancelled,
or failed relay checks are controller infrastructure state and should be
ignored when evaluating PR validation, CI gates, or merge readiness.

## Concurrency Groups

Workflow concurrency groups are documented here for completeness, as they
affect runner scheduling but not the label contract itself.

- `Rust Fast`, `Nix Checks`, `Secret Policy`, `Dependency License`,
  `Dependency Advisory`, `Actionlint`, `Rust Toolchain`:
  `${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`
  with `cancel-in-progress: true`.

- `Clippy`:
  `${{ github.workflow }}-${{ github.ref }}-${{ github.event_name == 'workflow_dispatch' && inputs.scope || 'changed' }}`
  with `cancel-in-progress: true`.

- `Focused Rust`:
  `${{ github.workflow }}-${{ github.ref }}-${{ inputs.crates }}-${{ inputs.cargo_test_args }}`
  with `cancel-in-progress: true`. Newer identical dispatches cancel older ones;
  distinct crate selections remain independent.

- `Focused Claim Validation`:
  `focused-claim-validation-${{ github.ref }}-${{ inputs.mode }}-${{ inputs.claim_id }}-${{ inputs.artifact_path }}`
  with `cancel-in-progress: false`.

- `QEMU Smoke`, `Kernel fsync/syncfs validation`, `Kernel mmap validation`:
  `${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: true`
  (QEMU Smoke) or `false` (the kernel validations).

- `xfstests`:
  `${{ github.workflow }}-${{ github.ref }}-${{ inputs.target || 'scheduled' }}`
  with `cancel-in-progress: false`.

- `RDMA`:
  `${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: false`.

- `Release Candidate`:
  `${{ github.workflow }}-${{ github.ref }}-${{ inputs.profile }}`
  with `cancel-in-progress: true`. Newer dispatches for the same branch and
  profile cancel older ones.

- `Codex Nexus Relay`:
  `${{ github.workflow }}` (global) with `cancel-in-progress: true`.

## Follow-Up Notes

The following items are recorded for future investigation or improvement. They
are out of scope for this documentation slice.

1. **Unused runner labels** (`fuse`, `ublk`, `kernel`): `docs/GITHUB_CI.md`
   states these labels should be on every runner, but no workflow selects them.
   QEMU Smoke and xfstests workflows check `/dev/fuse` and `/dev/kvm` at
   runtime in host-preflight steps. Consider whether the unused labels should
   be removed from the runner VMs, added to workflow `runs-on` clauses where
   the capability is actually required, or kept as documentation of host
   capability for manual dispatch selection.

2. **`Focused Rust` draft-PR path**: The workflow triggers on PR source-path
   changes for self-testing (when the workflow itself, `ci-test-runner.sh`, or
   flake inputs change). This self-test trigger does not include a draft-skip
   gate in the PR path filtering, though combined with the path filter it only
   fires when workflow tooling files change.

3. **`Release Candidate` label granularity**: The release-candidate workflow
   uses four different label sets across its jobs (A, B, C, D). If a runner
   has labels A and B but not C or D, the xfstests and RDMA jobs would never
   be scheduled for that runner. The current fleet uses uniform runners with
   all labels, so this is not a live scheduling issue but is worth documenting
   for future heterogeneous runner pools.

4. **`Codex Nexus Relay` host requirements**: The relay workflow does not
   check for `/dev/fuse`, `/dev/kvm`, or other device nodes. This is correct
   because the relay does not use FUSE or KVM, but it means the relay can run
   on any runner with the `tidefs` label regardless of FUSE or KVM
   availability.
