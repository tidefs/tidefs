# RDMA Validation Contract

This document is the bounded, source-inspected contract for the TideFS RDMA
validation lane. It lists every RDMA workflow target, the runner labels each
target depends on, dispatch behavior, expected output/artifact path shapes,
and the validation command or probe each target represents. It distinguishes
static carrier/host checks from two-node runtime evidence and records what
each target can support as issue or PR validation.

This contract is derived from source inspection of:

- `docs/GITHUB_CI.md`
- `.github/workflows/rdma.yml`
- `flake.nix`
- `nix/tidefs-rdma-probe.sh`
- `nix/tidefs-qemu-rdma-two-node.sh`

It does not alter any of those files.

---

## Target Summary

The `RDMA` workflow ([.github/workflows/rdma.yml](/.github/workflows/rdma.yml))
defines a single job `rdma` with three matrix targets. All three run on the
same runner label set and share a common evidence-manifest step.

| Matrix target          | command class      | evidence class              | validation tier          | primary artifact        | flake invocation                                                 |
|------------------------|--------------------|-----------------------------|--------------------------|-------------------------|------------------------------------------------------------------|
| `static-carrier-check` | `static-carrier`   | `rdma-static-carrier-check` | `harness-only`           | `command-status.env`    | `nix build -L .#checks.x86_64-linux.rdmaCarrierTwoNode`          |
| `host-probe`           | `host-probe`       | `rdma-host-probe`           | `harness-only`           | `summary.env`           | `nix run .#rdma-probe -- --validation-dir <dir>`                 |
| `qemu-two-node`        | `qemu-two-node`     | `rdma-qemu-two-node`        | `multi-process-distributed` | `summary.env`        | `nix run .#qemu-rdma-two-node-nixos -- --validation-dir <dir>`   |

All three targets produce an `evidence-manifest.json` in their artifact root
recording `claim_id`, `evidence_class`, `validation_tier`, source ref/SHA,
matrix target, command class, result status, primary artifact path, and
b3sum digest.

---

## Target Details

### `static-carrier-check`

- **What it does.** A Nix check (`rdmaCarrierTwoNode` in `flake.nix` checks)
  that greps `flake.nix` for the presence of four required strings:
  `rdmaCarrierTwoNodeTest`, `nodes.server`, `nodes.client`, and
  `rping -c -a 192.168.77.10`. It is a static code-structure guard: it
  verifies the NixOS test definition exists and names the expected two-node
  topology and cross-node rping probe. It does **not** build any binary, boot
  any VM, load any kernel module, or touch any RDMA hardware.
- **Evidence class.** `rdma-static-carrier-check`.
- **Validation tier.** `harness-only`. Produces no runtime evidence.
- **Artifact root.** `/tmp/tidefs-validation/rdma/static-carrier-check`.
- **Primary artifact.** `command-status.env` (a shell-sourceable status file).
- **What it supports.** Validates that the Nix RDMA test harness definition
  is structurally intact after flake.nix refactors, renames, or code motion.
  Suitable as a CI gate for any change that touches `flake.nix`, Nix test
  definitions, or the Nix RDMA carrier script.
- **When it is not suitable.** It proves nothing about host RDMA hardware,
  kernel module availability, or live transport behavior.

### `host-probe`

- **What it does.** Runs `tidefs-rdma-probe` (`nix/tidefs-rdma-probe.sh`), a
  non-mutating host inspection script. It reports:
  - Presence of RDMA userspace tools (`rdma`, `ip`, `modprobe`, `lsmod`,
    `modinfo`, `ibv_devices`, `ibv_devinfo`, `rping`).
  - Availability and load state of software-RDMA kernel modules (`rdma_rxe`,
    `siw`, `ib_core`, `ib_uverbs`).
  - Visible RDMA link count and IB device count.
  - A readiness classification (`rdma_ready`: `yes`/`no`/`partial`) and a
    transport-session fallback classification.
- **Evidence class.** `rdma-host-probe`.
- **Validation tier.** `harness-only`. Inspects the host's installed tooling
  and kernel module state; does not create, modify, or tear down RDMA links
  unless explicitly requested with `TIDEFS_RDMA_ALLOW_MUTATION=1` and a
  mutation subcommand (`--enable-rxe`, `--enable-siw`, `--delete-link`).
- **Artifact root.** `/tmp/tidefs-validation/rdma/host-probe`.
- **Primary artifact.** `summary.env` (key-value shell-sourceable summary).
- **What it supports.** Verifies a CI runner or development host has the
  required RDMA toolchain and kernel modules installed. Useful as a runner
  health check or bring-up probe.
- **When it is not suitable.** It does not exercise a live RDMA connection
  between two nodes and cannot validate end-to-end transport behavior.

### `qemu-two-node`

- **What it does.** Boots two disposable QEMU VMs connected via socket
  networking, enables software RDMA (rxe) inside each guest, runs
  `tidefs-rdma-probe` in both, and writes node-pair carrier validation
  results. The guest kernel and initrd come from the
  `qemuRdmaGuestSystem` NixOS system closure, which bundles RDMA kernel
  modules and userspace tools (`rdma-core`, `rping`). This is the only
  target that exercises a live, multi-process, distributed RDMA path.
- **Evidence class.** `rdma-qemu-two-node`.
- **Validation tier.** `multi-process-distributed`. Produces runtime evidence
  from two cooperating QEMU guest nodes.
- **Artifact root.** `/tmp/tidefs-rdma-two-node`.
- **Primary artifact.** `summary.env`.
- **What it supports.** Validates that the full software-RDMA carrier
  stack—kernel modules, userspace verbs, cross-node rping—works in a
  controlled, disposable environment. Appropriate for transport-layer PR
  validation or scheduled carrier health checks.
- **When it is not suitable.** It runs entirely inside QEMU with software
  RDMA (rxe); it does not validate hardware RDMA (Infiniband, RoCE) or
  production network topologies.

---

## Runner Labels

All three targets require the runner label set:

```
self-hosted, linux, x64, tidefs, nix, kvm, rdma
```

The `kvm` label is required even for `static-carrier-check` and `host-probe`
because the RDMA job-level `runs-on` selects this label set once for the
entire matrix. A runner without KVM will fail to pick up any RDMA job,
including the static carrier check.

---

## Dispatch Behavior

- **Manual dispatch.** `workflow_dispatch` runs the full matrix (all three
  targets) against the selected branch.
- **Scheduled.** A daily cron trigger (`43 2 * * *`, 02:43 UTC) runs against
  the default branch (`master`).
- **Concurrency.** Grouped by `${{ github.workflow }}-${{ github.ref }}`;
  `cancel-in-progress: false`, so a scheduled run does not cancel a manual
  dispatch against the same ref, and vice versa.
- **TIDEFS_SELF_HOSTED_READY gate.** Scheduled runs are skipped when the
  repository variable `TIDEFS_SELF_HOSTED_READY` is not `1`. Manual
  dispatches ignore this gate.
- **Timeout.** Job timeout is 180 minutes. The per-command timeout is
  10500 seconds (175 minutes).
- **Artifact retention.** Uploaded artifacts are retained for 7 days.

---

## Artifact Path Shapes

Every target produces files under its `artifact_root`:

| Target                | artifact_root                                          | Uploaded as          |
|-----------------------|--------------------------------------------------------|----------------------|
| `static-carrier-check`| `/tmp/tidefs-validation/rdma/static-carrier-check`     | `rdma-static-carrier-check` |
| `host-probe`          | `/tmp/tidefs-validation/rdma/host-probe`               | `rdma-host-probe`    |
| `qemu-two-node`       | `/tmp/tidefs-rdma-two-node`                            | `rdma-qemu-two-node` |

Common files in every artifact root:

- `artifact-root.env` — workflow metadata (run ID, ref, SHA, UTC timestamp).
- `command-status.env` — command outcome (status code, started/finished at,
  result status: `pass`/`fail`/`timeout`).
- `command.stdout.log` / `command.stderr.log` — captured command output.
- `evidence-manifest.json` — structured evidence record with claim id,
  content digest, validation tier, and scope.

The workflow upload step uses `if: always()` and `if-no-files-found: ignore`,
so a runner failure before artifact creation does not fail the upload step.

---

## When RDMA Evidence Is Required

RDMA validation is **required** for changes that:

- Alter the RDMA transport code paths (crate `tidefs-transport`,
  transport-related kernel modules, or the RDMA carrier scripts/flake outputs).
- Modify the RDMA workflow itself (`.github/workflows/rdma.yml`).
- Refactor the RDMA guest system NixOS definition (`qemuRdmaGuestSystem` in
  `flake.nix`) or the two-node QEMU harness (`nix/tidefs-qemu-rdma-two-node.sh`).
- Introduce a new RDMA dependency or change how `rdma-core` is linked.

In these cases at minimum the `static-carrier-check` should pass; the
`host-probe` and `qemu-two-node` targets should pass before merge when the
change affects runtime transport behavior.

## When RDMA Evidence Is Explicitly Out of Scope

RDMA validation is **not required** for:

- Ordinary Rust crate changes that do not touch `tidefs-transport` or RDMA
  dependencies.
- Documentation-only PRs that do not alter the RDMA workflow, flake outputs,
  or transport scripts.
- Nix package bumps that do not change the RDMA guest system or RDMA tool
  dependency closure.
- CI path-filtered PRs that touch only `docs/**`, root Markdown policy text,
  or `COPYING` (these PRs already skip standing `Rust Fast` and `Nix Checks`;
  RDMA is a scheduled/manual lane and does not gate them).

When a PR does not meet any RDMA requirement trigger, do not dispatch an
RDMA run. Reserve the self-hosted RDMA runner slots for transport-touching
PRs and scheduled carrier health checks.

## Release-Candidate Validation

The `Release Candidate` workflow's `full` profile includes RDMA. When a
release candidate is dispatched, the `RDMA` workflow runs as part of the
full acceptance gate. Do not treat a passing `static-carrier-check` or
`host-probe` alone as a release-candidate RDMA gate; the `qemu-two-node`
target must also pass.

---

## Recorded Mismatches and Follow-Up Notes

These are source-inspection findings recorded for follow-up, not addressed
in this documentation slice.

1. **GITHUB_CI.md groups RDMA with xfstests as "scheduled/manual lanes for
   longer filesystem and transport work."** The `static-carrier-check` is a
   static flake analysis (no filesystem or transport work). The `host-probe`
   is a non-mutating host inspection. Only `qemu-two-node` matches the
   "transport work" description. The CI doc should distinguish the three
   targets or at least note that not all RDMA targets are transport-runtime.

2. **Flake output naming inconsistency.** The check is
   `checks.x86_64-linux.rdmaCarrierTwoNode` (camelCase suffix) while the
   apps are `rdma-probe` and `qemu-rdma-two-node-nixos` (kebab-case).
   This is cosmetic but may confuse discoverability.

3. **`kvm` label required for static checks.** The `static-carrier-check`
   target requires a runner with KVM because the job-level `runs-on` selects
   the full label set including `kvm`. A runner without KVM (but with RDMA
   userspace tools) could run `static-carrier-check` and `host-probe`. This
   is a workflow shape constraint, not a bug, but worth documenting.

4. **No `tidefs-storage-node` binary runtime evidence in qemu-two-node.**
   The `qemu-two-node` target boots the RDMA guest system and runs
   `rdma-probe` inside the guests, but does not start `tidefs-storage-node`
   or exercise the TideFS RDMA data path. According to a comment in
   `flake.nix`, the binary is included in the guest initrd, but the current
   harness script does not launch it. The `qemu-two-node` target is therefore
   a **carrier validation** (RDMA transport layer works), not a **data-path
   validation** (TideFS storage node uses RDMA successfully). Data-path RDMA
   validation is a separate future target.
