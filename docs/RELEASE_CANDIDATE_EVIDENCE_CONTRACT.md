# Release Candidate Evidence Contract

**Last updated**: 2026-06-23
**Source**: bounded inspection of `docs/GITHUB_CI.md`,
`.github/workflows/release-candidate.yml`, and the referenced lane workflows
(`rust-fast.yml`, `nix-checks.yml`, `qemu-smoke.yml`, `xfstests.yml`,
`rdma.yml`).

**Purpose**: This document records how the Release Candidate workflow produces
and indexes evidence across its `smoke` and `full` profiles so that workers,
PR authors, and gate auditors can interpret a `release-candidate-evidence-index`
artifact without tracing through YAML. It does not change any workflow,
source, flake, claim-registry, or runtime behavior.

---

## Profiles

The Release Candidate is a manual-only (`workflow_dispatch`) self-hosted
workflow. Every run selects one profile:

| Profile | Lanes executed | Primary use |
|---|---|---|
| `smoke` | Rust smoke, Nix build, QEMU smoke | Fast gate: confirms the branch compiles, basic Rust tests pass, Nix packages build, and the kernel module mounts the bootstrap VFS root under QEMU. |
| `full` | Rust smoke, Nix build, QEMU smoke, xfstests, RDMA | Broader checkout before a release decision: adds the filesystem (FUSE + kernel) xfstests targets and the RDMA transport two-node harness. |

Both profiles produce the same top-level evidence index artifact shape;
`smoke` records `xfstests` and `rdma` lanes as `skipped_by_profile`.

The workflow uses per-branch + per-profile concurrency with
`cancel-in-progress: true`, so a newer dispatch for the same branch and
profile cancels any queued or running older copy.

---

## Lane Jobs

### rust-smoke

Always runs for both profiles. No dependency.

| Attribute | Value |
|---|---|
| Runner labels | `self-hosted, linux, x64, tidefs, nix` |
| Timeout | 45 min |
| Commands | `cargo metadata --locked --format-version 1 --no-deps` |
|  | `scripts/ci-test-runner.sh --crates "$TIDEFS_RUST_FAST_CRATES" --json ci-test-summary.json` |
|  | `cargo test -p tidefs-transport --locked send_message_missing_session_fails` |
| Crates tested | `tidefs-xtask`, `tidefs-extent-map`, `tidefs-schema-codec-posix-filesystem-adapter`, `tidefs-secret-key-policy-runtime` |
| Uploaded artifact | `release-candidate-rust-summary` |
| Artifact path | `ci-test-summary.json` |
| Retention | 14 days |
| Lane-local manifest owner | Issue 645 (Focused Rust lane-local evidence manifest) |

### nix

Always runs for both profiles. Depends on `rust-smoke`.

| Attribute | Value |
|---|---|
| Runner labels | `self-hosted, linux, x64, tidefs, nix` |
| Timeout | 180 min |
| Commands | `nix build -L .#checks.x86_64-linux.rdmaCarrierTwoNode` |
|  | `nix build -L .#packages.x86_64-linux.default` |
|  | `nix build -L .#packages.x86_64-linux.tidefsFuseRuntime` |
|  | `nix build -L .#packages.x86_64-linux.tidefsUblkRuntime` |
|  | `nix build -L .#packages.x86_64-linux.tidefsPosixVfsKmod` |
| Uploaded artifact | *none* (evidence is pass/fail by exit code) |
| Lane-local manifest | `not_applicable` (no owner issue; the nix job result itself is the evidence) |

### qemu

Always runs for both profiles. Depends on `nix`. Single matrix entry.

| Attribute | Value |
|---|---|
| Runner labels | `self-hosted, linux, x64, tidefs, nix, kvm` |
| Timeout | 120 min |
| Matrix target | `kmod-xfstests-smoke` |
| Command | `nix run .#kmod-xfstests-smoke -- --timeout 1800` |
| Uploaded artifact | `release-candidate-qemu-kmod-xfstests-smoke` |
| Artifact path glob | `/tmp/tidefs-validation/**` |
| Retention | 14 days |
| Lane-local manifest owner | Issue 644 (Kernel fsync lane-local evidence manifest) |

### xfstests

Full profile only. Depends on `qemu`. Matrix of three targets.

| Attribute | Value |
|---|---|
| Runner labels | `self-hosted, linux, x64, tidefs, nix, kvm, xfstests` |
| Timeout | 240 min |
| Profile gate | `if: inputs.profile == 'full'` |

| Target | Command | Artifact name | Artifact path glob |
|---|---|---|---|
| `fuse` | `nix run .#fuse-xfstests-validation` | `release-candidate-xfstests-fuse` | `/tmp/tidefs-validation/**` |
| `kmod-smoke` | `nix run .#kmod-xfstests-smoke -- --timeout 3600` | `release-candidate-xfstests-kmod-smoke` | `/tmp/tidefs-validation/**` |
| `k7-vfs` | `nix run .#k7-vfs-xfstests-validation` | `release-candidate-xfstests-k7-vfs` | `/tmp/tidefs-validation/**` |

| Attribute | Value |
|---|---|
| Retention | 14 days |
| Lane-local manifest owner | Issue 643 (xfstests lane-local evidence manifest) |

### rdma

Full profile only. Depends on `qemu`. Matrix of three targets.

| Attribute | Value |
|---|---|
| Runner labels | `self-hosted, linux, x64, tidefs, nix, kvm, rdma` |
| Timeout | 180 min |
| Profile gate | `if: inputs.profile == 'full'` |

| Target | Command | Artifact name | Artifact path globs |
|---|---|---|---|
| `static-carrier-check` | `nix build -L .#checks.x86_64-linux.rdmaCarrierTwoNode` | `release-candidate-rdma-static-carrier-check` | `/tmp/tidefs-rdma-two-node/**`, `/tmp/tidefs-validation/**` |
| `host-probe` | `nix run .#rdma-probe -- --validation-dir /tmp/tidefs-validation/rdma/host-probe` | `release-candidate-rdma-host-probe` | `/tmp/tidefs-rdma-two-node/**`, `/tmp/tidefs-validation/**` |
| `qemu-two-node` | `nix run .#qemu-rdma-two-node-nixos -- --validation-dir /tmp/tidefs-rdma-two-node` | `release-candidate-rdma-qemu-two-node` | `/tmp/tidefs-rdma-two-node/**`, `/tmp/tidefs-validation/**` |

| Attribute | Value |
|---|---|
| Retention | 14 days |
| Lane-local manifest owner | Issue 646 (RDMA lane-local evidence manifest) |

### candidate-evidence-index

Always runs (`always() && !cancelled()`). Depends on all five lane jobs.
Produces the top-level evidence index.

| Attribute | Value |
|---|---|
| Runner labels | `self-hosted, linux, x64, tidefs, nix` |
| Timeout | 10 min |
| Uploaded artifact | `release-candidate-evidence-index` |
| Artifact path | `release-candidate-evidence-index/index.json` |
| Upload policy | `if-no-files-found: error` (a missing index is a workflow failure) |
| Retention | 14 days |

### Lane dependency graph

```
rust-smoke
  └─ nix
       └─ qemu
            ├─ xfstests  (full only)
            ├─ rdma      (full only)
            └─ candidate-evidence-index
```

The evidence index always depends on all five lane jobs. For `smoke` runs,
`xfstests` and `rdma` are skipped by their `if:` condition, so their `needs`
result is `skipped`. The index records them as `skipped_by_profile`.

---

## Evidence Index Structure

The index is a single JSON object (`schema_version: 1`) written by a `jq`
script inside a `nix develop .#ci` shell. Its top-level shape:

```json
{
  "schema_version": 1,
  "workflow": {
    "name": "Release Candidate",
    "run_id": "<GitHub Actions run ID>",
    "run_attempt": "<run attempt number>",
    "run_url": "<full URL to the Actions run>"
  },
  "source": {
    "repository": "tidefs/tidefs",
    "ref": "refs/heads/<branch>",
    "ref_name": "<branch name>",
    "sha": "<full commit SHA>"
  },
  "profile": "smoke | full",
  "candidate_evidence_index": {
    "artifact_name": "release-candidate-evidence-index",
    "path": "release-candidate-evidence-index/index.json",
    "scope": "top-level candidate evidence"
  },
  "claim_boundary": {
    "product_readiness": "not_claimed",
    "coverage_broadening": false,
    "lane_local_manifests_synthesized": false
  },
  "lane_local_manifest_boundaries": [
    {
      "status": "absent",
      "current_owner_issue": null,
      "evidence_class": "xfstests lane-local evidence manifest",
      "missing_input": "lane-local manifest is not produced by the release-candidate workflow",
      "historical_provenance": {
        "completed_issue": 643,
        "state": "closed",
        "role": "historical lane-local manifest producer lineage"
      }
    },
    {
      "status": "absent",
      "current_owner_issue": null,
      "evidence_class": "Kernel fsync lane-local evidence manifest",
      "missing_input": "lane-local manifest is not produced by the release-candidate workflow",
      "historical_provenance": {
        "completed_issue": 644,
        "state": "closed",
        "role": "historical lane-local manifest producer lineage"
      }
    },
    {
      "status": "absent",
      "current_owner_issue": null,
      "evidence_class": "Focused Rust lane-local evidence manifest",
      "missing_input": "lane-local manifest is not produced by the release-candidate workflow",
      "historical_provenance": {
        "completed_issue": 645,
        "state": "closed",
        "role": "historical lane-local manifest producer lineage"
      }
    },
    {
      "status": "absent",
      "current_owner_issue": null,
      "evidence_class": "RDMA lane-local evidence manifest",
      "missing_input": "lane-local manifest is not produced by the release-candidate workflow",
      "historical_provenance": {
        "completed_issue": 646,
        "state": "closed",
        "role": "historical lane-local manifest producer lineage"
      }
    }
  ],
  "lanes": [ /* per-lane entries, see below */ ]
}
```

### Per-lane entry

Each lane records its job result, artifacts, and lane-local manifest status:

```json
{
  "id": "rust-smoke | nix | qemu | xfstests | rdma",
  "job_id": "<matching GitHub Actions job id>",
  "job_name": "<human-readable job name>",
  "profiles": ["smoke", "full"] | ["full"],
  "github_needs_result": "success | failure | cancelled | skipped | timed_out",
  "status": "run | skipped_by_profile | failed | missing_evidence",
  "artifacts": [
    {
      "name": "<GitHub artifact name>",
      "expected_path_patterns": ["<glob>", ...]
    }
  ],
  "lane_local_manifest": {
    "status": "absent | not_applicable",
    "current_owner_issue": null,
    "evidence_class": "<description>",
    "missing_input": "<explanation when absent>",
    "historical_provenance": {
      "completed_issue": <historical issue number>,
      "state": "closed",
      "role": "historical lane-local manifest producer lineage"
    },
    "note": "<explanation when absent>"
  }
}
```

Matrix lanes (`qemu`, `xfstests`, `rdma`) also include a `matrix_jobs` array
with per-target details and expected artifact path patterns.

### Lane status classification

| `github_needs_result` | Profile match? | Derived `status` |
|---|---|---|
| `success` | yes | `run` |
| `failure`, `cancelled`, `timed_out` | yes | `failed` |
| any other | yes | `missing_evidence` |
| any | no | `skipped_by_profile` |

For `smoke`, `xfstests` and `rdma` are always `skipped_by_profile`. For
`full`, every lane must not be `skipped_by_profile`.

### Self-validation

The evidence-index job runs a `jq -e` assertion pass over the written index
before uploading it. The assertions verify:

- The profile field is `smoke` or `full`.
- The workflow name is `Release Candidate`.
- The source SHA is non-empty.
- The index artifact name is `release-candidate-evidence-index`.
- All five lane IDs (`nix`, `qemu`, `rdma`, `rust-smoke`, `xfstests`) are
  present and sorted.
- Every lane status is one of `run`, `skipped_by_profile`, `failed`,
  `missing_evidence`.
- On `smoke`: `xfstests` and `rdma` are `skipped_by_profile`; `rust-smoke`,
  `nix`, and `qemu` are not `skipped_by_profile`.
- Every lane-local manifest that is `absent` has no current owner issue,
  records the explicit missing input, and keeps any closed issue lineage under
  historical provenance.

If the assertions fail, the step exits non-zero and the evidence index is not
uploaded. An index that passes self-validation is structurally self-consistent
but does not assert lane-level correctness or product readiness.

---

## Lane-Local Manifest Handling

The evidence index explicitly records that four lane-local manifests are
`absent`. These manifests are outside the Release Candidate workflow slice; the
index does not synthesize pass claims from their absence. The
`claim_boundary.lane_local_manifests_synthesized` field is always `false`.

Closed issues 643, 644, 645, and 646 are retained only as historical completed
lineage under `historical_provenance`. They are not emitted as current owner
issues for absent lane-local manifests, and the index records
`current_owner_issue: null` for those absent inputs.

The `nix` lane has no associated lane-local manifest and is recorded as
`not_applicable`: its job exit code is the evidence.

When auditing a candidate run, treat an `absent` manifest as unreviewed scope
that a separate claims-gate or lane-local validation workflow must cover before
the candidate's lane evidence can be considered complete for a product
readiness decision. The candidate index itself makes no product-readiness
claim.

---

## Runner Labels Used

| Lane | Required labels |
|---|---|
| `rust-smoke` | `self-hosted`, `linux`, `x64`, `tidefs`, `nix` |
| `nix` | `self-hosted`, `linux`, `x64`, `tidefs`, `nix` |
| `qemu` | `self-hosted`, `linux`, `x64`, `tidefs`, `nix`, `kvm` |
| `xfstests` | `self-hosted`, `linux`, `x64`, `tidefs`, `nix`, `kvm`, `xfstests` |
| `rdma` | `self-hosted`, `linux`, `x64`, `tidefs`, `nix`, `kvm`, `rdma` |
| `candidate-evidence-index` | `self-hosted`, `linux`, `x64`, `tidefs`, `nix` |

All match the runner contract in `docs/GITHUB_CI.md`. The full runner label
set for the TideFS CI fleet is `self-hosted linux x64 tidefs nix kvm fuse ublk
rdma kernel xfstests`. The RC workflow does not use `fuse`, `ublk`, or
`kernel` labels directly; those labels appear on runners used by the
standalone lane workflows.

---

## Interpretation Guide

### What the index proves

- A named workflow ran against a specific commit SHA on a specific branch.
- Which profile was selected.
- Each lane job's GitHub Actions result (success, failure, skipped, etc.).
- Whether the lane's expected artifacts were declared and their expected
  path patterns.
- That lane-local manifests were not synthesized.
- That the index is structurally self-consistent (the self-validation `jq`
  assertions passed).

### What the index does not prove

- That a lane's artifact content is correct or complete. The index records
  artifact names and expected path patterns, not artifact hashes or content
  validation.
- That any lane-local manifest has been reviewed for the current release
  candidate.
- That the candidate is product-ready. The `claim_boundary.product_readiness`
  field is always `not_claimed`.
- That issue/PR-specific acceptance criteria are satisfied. Those criteria
  belong to issue validation tiers and focused workflows, not to the
  release-candidate gate.

### Reading a skipped lane

- `skipped_by_profile` means the job was not run because the selected profile
  excludes it. On `smoke`, `xfstests` and `rdma` are intentionally skipped.
  This is expected and not a failure.
- `skipped` (as a raw GitHub `needs` result) can also appear when a
  dependency fails and GitHub skips downstream jobs. The index maps this to
  `missing_evidence` because the lane never ran and its result is unknown.

### Reading a `missing_evidence` lane

- The lane job ran (or was supposed to run) but its GitHub Actions result is
  not `success`, `failure`, `cancelled`, or `timed_out`. This can indicate a
  runner infrastructure problem, a job that was skipped by a dependency
  failure, or an unexpected workflow event. Investigate the run page for the
  specific job status.

### Gate role

The release candidate evidence index is a **gate input**, not a gate verdict.
The verdict boundary that consumes this evidence index and the other inputs
listed below is defined in `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`. That
contract records required evidence families, explicit non-claims, and the
distinction between gate-local readiness receipts and whole-product admission.
A product readiness decision must combine the index with:

- Lane-local manifest review through current workflow/source state or live
  issue state. Historical completed issues 643-646 are provenance only, not
  current missing-input owners.
- Issue/PR-specific validation evidence (focused Rust, focused claim
  validation, targeted xfstests rows, etc.).
- Standing CI gate status (Rust Fast, Nix Checks, Clippy, Secret Policy).
- Other release-candidate runs against ancestor commits for trend comparison.

---

## Comparison with Standalone Lane Workflows

The Release Candidate workflow runs a composed subset of the standalone lane
workflows. Key differences:

| Aspect | Standalone | Release Candidate |
|---|---|---|
| **Rust Fast** (`rust-fast.yml`) | Uploads `rust-fast-summary` (7 day retention). PR-triggered; path-filtered to skip `docs/**`. | Uploads `release-candidate-rust-summary` (14 day retention). Same crates and transport test. Manual only. |
| **Nix Checks** (`nix-checks.yml`) | Builds `tidefsBlockKmod` in addition to the core packages. PR-triggered; path-filtered. | Does **not** build `tidefsBlockKmod`. Manual only. |
| **QEMU Smoke** (`qemu-smoke.yml`) | 7 matrix targets including `kernel-teardown-validation`, `kernel-no-daemon-teardown-validation`, `kernel-fsync-validation`, `kernel-mmap-validation`, `fuse-vm-test`, `qemu-ublk-smoke`. | 1 target: `kmod-xfstests-smoke`. |
| **xfstests** (`xfstests.yml`) | 3 targets (same). Scheduled daily + manual dispatch. 7 day retention. | 3 targets (same). Manual only, as part of `full` profile. 14 day retention. |
| **RDMA** (`rdma.yml`) | 3 targets (same). Scheduled daily + manual dispatch. 7 day retention. | 3 targets (same). Manual only, as part of `full` profile. 14 day retention. |

The RC workflow intentionally runs a narrower QEMU smoke surface than the
standalone workflow and omits `tidefsBlockKmod` from the Nix build. These are
profile design decisions, not oversights: the RC gate is a broad composition
check, not a replacement for focused lane validation.

---

## Follow-Up Notes

These observations are recorded as documentation follow-ups. No workflow,
source, or behavior changes are made by this contract.

1. **`docs/GITHUB_CI.md` description of RC nix job**: The prose says the RC
   runs "Nix ... lanes" without listing the exact derivations. The actual YAML
   builds `rdmaCarrierTwoNode` as a pure check derivation plus four core
   packages (`default`, `tidefsFuseRuntime`, `tidefsUblkRuntime`,
   `tidefsPosixVfsKmod`). The standalone `nix-checks.yml` also builds
   `tidefsBlockKmod`, which the RC omits. A reader relying only on
   `docs/GITHUB_CI.md` might assume parity between the two nix jobs.

2. **QEMU smoke scope mismatch**: `docs/GITHUB_CI.md` describes the QEMU
   Smoke workflow as having seven targets (including kernel-teardown and
   kernel-no-daemon-teardown), but the RC only runs `kmod-xfstests-smoke`.
   The RC QEMU job artifact name (`release-candidate-qemu-${{ matrix.name }}`)
   uses a matrix variable but the matrix has only one entry, so a reader
   inspecting the artifact list might expect more QEMU targets in the RC.
   The `docs/CI_ARTIFACT_RETENTION_CONTRACT.md` correctly notes this: "1
   target: kmod-xfstests-smoke".

3. **Artifact retention asymmetry**: All RC artifacts have 14-day retention
   while standalone lane artifacts have 7-day retention. This is intentional
   (RC runs are fewer and gating), but it means a stale RC run may have
   downloadable artifacts after the corresponding standalone lane artifacts
   have expired.

4. **Lane-local manifest historical lineage**: Issues 643-646 are closed
   historical producer-lineage issues for the four absent lane-local manifests.
   The evidence index keeps that lineage as provenance while representing the
   current missing inputs with `current_owner_issue: null`.
