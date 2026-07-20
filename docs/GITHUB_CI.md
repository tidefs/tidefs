# GitHub CI

TideFS uses GitHub as the primary remote for the main `tidefs/tidefs`
repository. The operator approved making that main repository public on
2026-06-21. This public repository status is a read-visibility boundary only:
TideFS remains pre-alpha, and the visibility change is not a product release,
release-readiness claim, or compatibility promise.

GitHub outsider interaction remains restricted by the documented public-read
controls: organization interaction limits stay at `collaborators_only`, pull
request (PR) creation remains collaborator-only, `tidefs-ci` self-hosted runner
access remains selected-repository access for the TideFS repositories, and
workflow-token permissions remain read-only. The secret boundary below still
keeps runner credentials, deployment keys, API tokens, TLS keys, and other
TideFS secrets outside GitHub and outside this repository.

## Secret Boundary

GitHub is not a TideFS secret store. Do not configure TideFS repository,
organization, or environment secrets in GitHub. Do not use GitHub deploy keys,
Actions secrets, `secrets.*` workflow expressions, or committed encrypted
secret payloads for TideFS operations.

Secrets such as runner registration tokens, website deployment keys, API
tokens, TLS private keys, and host credentials must live only in host-local or
operator-owned secret storage outside GitHub and outside this repository. CI
may use non-secret repository variables for scheduling gates, such as
`TIDEFS_SELF_HOSTED_READY`.

## Workflow Shape

- All TideFS development and release-candidate workflow jobs run on the
  self-hosted TideFS runner VMs. Do not add `ubuntu-latest`, other
  GitHub-hosted runner labels, or hosted-runner package-manager assumptions to
  TideFS workflows. The workflow YAML remains the exact trigger/input source;
  this document is the discoverable CI authority entry point.
- `Actionlint` runs `actionlint` against `.github/workflows/*.yml` with
  `.github/actionlint.yaml` as the runner-label configuration source. It runs
  on workflow/actionlint configuration changes and manual dispatch, records its
  version and report in the step summary, and uploads no long-lived artifacts.
- `Rust Fast` runs on the TideFS self-hosted runner VMs through the repo
  `.#ci` Nix development shell. It covers workspace metadata plus a focused
  Rust smoke set for changes to its direct inputs:
  `tidefs-extent-map`,
  `tidefs-schema-codec-posix-filesystem-adapter`, and
  `tidefs-secret-key-policy-runtime`, plus a targeted `tidefs-transport`
  session test. It does not run documentation-authority or publication checks.
- `Rust Toolchain` (`.github/workflows/rust-toolchain.yml`) runs on the
  TideFS self-hosted runner VMs through the repo `.#ci` Nix development shell
  when a pull request changes `rust-toolchain.toml`, `flake.nix`, or
  `flake.lock`, and on manual dispatch. It verifies that the
  `rust-toolchain.toml` channel matches `rustc -Vv`, records `cargo`,
  `clippy`, `rustfmt`, and `rust-src` availability in the job summary, and
  fails closed on missing components. It is a fast toolchain-coherence gate
  only: toolchain version changes require their own issue and validation
  through the build/test lanes that consume the updated pin.
- `Clippy` runs on the TideFS self-hosted runner VMs through the same repo
  `.#ci` Nix development shell. On pull requests it selects changed workspace
  crates from locked Cargo metadata and the merge-base diff, then runs direct
  `cargo clippy -p <crate> --locked --all-targets` checks. Cargo failures fail
  the job and ordinary diagnostics remain in the job log; no warning-count
  snapshot or result artifact is maintained. Root workspace, Cargo
  configuration, lockfile, and toolchain changes select the whole workspace.
  Manual dispatch can run either changed-crate or full-workspace checks
  against a feature branch. Root lint policy remains in `Cargo.toml`;
  kernel, FFI, and capability-test crates that cannot inherit those lints use
  explicit crate-local manifest policy instead of weakening workspace lint
  policy.
- `Dependency License` (`.github/workflows/dependency-license.yml`) runs
  `cargo deny check licenses` through the repo `.#ci` Nix development shell on
  pull requests that touch `Cargo.toml`, `Cargo.lock`, `deny.toml`, `flake.nix`,
  `flake.lock`, or ADR-0006, and on manual dispatch. `deny.toml` remains the
  accepted license allowlist and dependency rule source;
  `docs/adr/0006-license-compliance-cargo-deny.md` records the architectural
  decision to use `cargo-deny`. The workflow summary records the source ref,
  SHA, command, and pass/fail outcome. License allowlist changes must edit
  `deny.toml`, follow the ADR-0006 revision boundary, and pass this gate on
  the update branch.
- `Focused Rust` is a manual self-hosted workflow for issue-specific PR
  validation. Dispatch it against the feature branch with a comma-separated
  crate list and optional extra `cargo test` arguments when the acceptance
  criteria require touched-package Rust tests outside the standing smoke set.
  The `crates` input must name workspace packages, not paths, and the workflow
  rejects duplicate names, control characters, path-like entries, and shell
  metacharacters before running Cargo. Optional `cargo_test_args` are bounded
  to safe `cargo test` filters and flags.
  It uses the same repo `.#ci` Nix development shell, host-local Cargo scratch,
  JSON summary artifact, and per-run target cleanup as `Rust Fast`. Newer
  identical dispatches for the same ref, crate list, and extra cargo-test
  arguments cancel older queued or running copies so stale branch-head checks
  do not compete with current merge-gate validation on the self-hosted runner
  fleet. Distinct crate lists or extra arguments remain independent. It also
  self-tests on pull requests that modify the focused workflow or its runner
  helper so workflow changes get Actions coverage before merge.

- `Focused Claim Validation` is a manual-only self-hosted workflow for
  focused claim-receipt and evidence-artifact validation. Dispatch it
  against a feature branch with a `mode` input and, depending on mode,
  a `claim_id` or `artifact_path`. It uses the repo `.#ci` Nix development
  shell and runs only the smallest relevant xtask subcommand:
  `validate-claim`, `check-claims-gate`, `check-no-hidden-queues`,
  `validate-evidence-manifest`, `validate-ublk-completion`, or
  `validate-ublk-started-export`. Input validation rejects broad, mismatched,
  newline-bearing, or shell-like selections: `validate-claim` requires only
  `claim_id`, the evidence and uBLK artifact validators require only
  `artifact_path`, and the gate/no-hidden-queue modes accept neither. The
  workflow summary records the claim id,
  artifact path, command executed, result, and any artifact upload
  path. It does not expose or configure TideFS secrets and does not
  trigger broad xfstests, RDMA, kernel, or release-candidate validation.
- `Secret Policy` runs on the same self-hosted TideFS runner labels and keeps
  the GitHub secret boundary checked without spending hosted Actions minutes.
  Its pull-request trigger is limited to workflow, policy, xtask, dependency,
  build, and root configuration files; manual dispatch remains available for
  focused checks of feature branches.
- `Dependency Advisory` runs `cargo deny check advisories` against `deny.toml`
  and `Cargo.lock` for dependency-policy and lockfile changes. It is
  validation-only: the workflow reports RustSec/yanked dependency drift,
  uploads `dependency-advisory-report`, and leaves remediation to a separate
  issue/PR. Its job summary links `docs/DEPENDENCY_ADVISORY_CI.md`, which is
  retained as the narrow remediation guide for this workflow.
- Standing PR checks use explicit risk paths. `Rust Fast` runs only for its
  selected crates, transport smoke, and shared build inputs. `Nix Checks` runs
  only for Nix, Cargo, and toolchain inputs. Rustfmt, Secret Policy, and the
  dependency workflows likewise run only for files they inspect. These PR
  checks do not rerun automatically after the identical tree reaches `master`;
  manual dispatch remains available when a merge or milestone invalidates the
  existing result. If another change needs runtime or build coverage, name the
  risk in the issue and dispatch the focused workflow explicitly.
- `Nix Checks` runs on self-hosted TideFS runners and builds core Nix packages
  for Nix, Cargo, and toolchain input changes, or by manual dispatch. It is a
  compile/build gate only: a green run
  does not prove FUSE, uBLK, RDMA, mounted-kernel behavior, filesystem
  correctness, crash consistency, performance, or release readiness.
- `QEMU Smoke` runs outside-sandbox kernel runtime rows on self-hosted
  TideFS runners with KVM and FUSE access. Only `master` pushes that touch the
  explicit kernel-module, kernel package, smoke harness, toolchain, or direct
  `tidefsctl` setup paths run the standing `kmod-xfstests-smoke` target: load
  `tidefs_posix_vfs.ko`, mount the explicit bootstrap VFS root, exercise
  directory/symlink/readdir/statfs operations, and leave engine-backed storage
  checks to the longer filesystem lanes. Manual `workflow_dispatch` exposes a
  `target` choice for `kmod-xfstests-smoke`, `kernel-fsync-validation`,
  `kernel-mmap-validation`, `kernel-teardown-validation`,
  `kernel-no-daemon-teardown-validation`, `two-node-carrier-validation`,
  `fuse-vm-test`, `fuse-inode-metadata-validation`, `qemu-ublk-smoke`,
  `qemu-ublk-qid-tag-runtime`, `storage-intent-ack-fault-matrix`,
  `receipt-bound-reclaim-runtime`, `scrub-foreground-read-runtime`, and `all`;
  `.github/workflows/qemu-smoke.yml` remains the exact source for target
  commands, output directories, artifact upload names, and retention. The
  workflow constructs its matrix from the selected target before KVM runner
  allocation: one specific target creates one runtime job, while `all` creates
  the complete set. Except for the standing `master` smoke target, non-default
  targets and `all` are manual validation tiers; dispatch them only when the
  issue or pull request validation tier names the row set. QEMU Smoke
  artifacts are not xfstests, RDMA, release-candidate, broad filesystem
  correctness, product-readiness, performance-comparator, or
  successor/comparator evidence unless the relevant validation tier and
  dedicated evidence authority say so. The QEMU Smoke
  `kernel-fsync-validation` and `kernel-mmap-validation` rows are focused
  runtime evidence surfaces. Dedicated workflows with the same flake refs remain
  separate validation lanes when an issue tier requires standalone fsync/mmap
  evidence, serial concurrency, or richer manifests.
- `Two-node carrier validation` is a manual `QEMU Smoke` target for
  `tidefs-two-node-harness`. It runs `.#two-node-carrier-validation`, boots a
  Linux 7.0 QEMU guest, executes the `qemu`-gated live TCP carrier
  state-transfer scenario, and uploads `carrier-report.json`, `qemu.log`,
  `summary.json`, and environment metadata under
  `two-node-carrier-validation`.
- `Storage-intent acknowledgment fault matrix` is a manual `QEMU Smoke`
  target for the fault-only portion of
  `storage.intent.ack_receipt_honesty.v1`. It boots Linux 7.0 three times
  against one raw virtio-blk image, sends `SIGKILL` only to the exact QEMU
  processes started by the harness before and after acknowledgment
  publication, then verifies kill-before-ack, crash-after-ack, stale-media,
  under-quorum, and hidden durable-to-volatile downgrade rows. It emits the
  promotable fault-matrix JSON plus a version-2 evidence manifest. The
  under-quorum row is a receipt-gate injection, not multi-process distributed
  quorum execution; the target is not mounted-runtime evidence and does not
  validate product, release, successor, or comparator wording.
- `Geo RPO WAN TCP` is a manual self-hosted workflow for the bounded
  `storage.intent.geo_async_rpo.v1` runtime row. It runs
  `tidefs-geo-rpo-wan-tcp-validation` from `tidefs-two-node-harness`, starts
  sender and receiver child processes over live `tidefs-transport` TCP, applies
  application-level WAN impairment rows for lag, catch-up, freshness/RPO,
  degraded/refusal visibility, partitions, stale clocks, loss/jitter, and
  bandwidth clamps, and uploads the three registered
  `validation/artifacts/storage-intent/geo-*` evidence artifacts with
  manifests. This is RDMA-absent WAN/TCP row evidence, not production cluster
  readiness, storage-node runtime proof, successor/comparator permission, or a
  release-candidate gate.
- `Kernel fsync/syncfs validation` is a narrow manual self-hosted workflow for
  the fsync/fdatasync/syncfs durability row. It runs
  `.#kernel-fsync-validation` against the selected branch with
  `timeout_seconds` and `pool_size_mb` inputs, exercises a QEMU power-loss
  cycle with persistent virtio-blk backing storage, and uploads phase logs,
  `summary.env`, and a v2 claim evidence `evidence-manifest.json` under
  `kernel-fsync-validation`; missing summaries are recorded as non-pass
  harness evidence rather than placeholder pass artifacts.
- `Kernel mmap validation` is a narrow manual self-hosted workflow for the
  mounted mmap/writeback QEMU row. It runs `.#kernel-mmap-validation` against
  the selected branch with a `timeout_seconds` input and uploads `summary.env`
  and row artifacts under `kernel-mmap-validation`. This is mmap/page-cache row
  evidence, not xfstests, RDMA, performance, release-candidate, or broad
  crash-consistency evidence.
- `Kernel teardown validation` is a manual self-hosted QEMU Smoke target
  for the T5 mounted-kernel-vfs cutover and teardown runtime evidence row. It runs
  `.#kernel-teardown-validation` against the selected branch, creates a
  disposable configured pool member, exercises
  cutover intent, dry-run admission, fence staging, commit, mounted truth
  verification, close, teardown, unmount, and module-unload lifecycle with
  kernel-owned workqueue/callback trace evidence through tracefs/ftrace when
  available or TideFS lifecycle dmesg markers otherwise, and uploads
  `kernel-teardown-runtime.json` and `evidence-manifest.json` under
  `kernel-teardown-validation`. Its artifact validator fails closed when the
  mounted-kernel cutover phase, fence, truth, trace, refusal, cleanup, source,
  or dmesg-danger fields are malformed or missing. It does not cover T6
  full-kernel/no-daemon rows and does not update claim registry status.
- `Kernel no-daemon teardown validation` is a manual self-hosted QEMU Smoke
  target for the T6 full-kernel-no-daemon teardown and recovery runtime
  evidence row. It runs `.#kernel-no-daemon-teardown-validation` against the
  selected branch, exercises mount/write/sync/teardown/unmount/module-unload
  lifecycle with ftrace workqueue tracing, zero userspace daemons, post-final
  refusal probes, and no-daemon crash/recovery cycles, and uploads
  `kernel-teardown-runtime.json` and `evidence-manifest.json` under
  `kernel-no-daemon-teardown-validation`. It does not update claim registry
  status or generated claim docs.
- Kernel module CI builds use the Linux 7.0 Rust-for-Linux baseline, require
  Rust-enabled prepared kernel trees, use LLVM tooling, and compile module C and
  Rust paths with warnings treated as errors. Local build recipes are helper
  workflows only; the validation tier for a change must still name the runtime,
  kernel, xfstests, RDMA, or release-candidate lane that exercises the affected
  behavior.
- `xfstests` and `RDMA` are scheduled/manual lanes for longer filesystem and
  transport work. Manual `xfstests` dispatch accepts a `target` and an
  optional space-separated `tests` list. Use the smallest known failing row set
  such as `generic/003` for `fuse` or `k7-vfs` while debugging an isolated
  failure. The `kmod-smoke` target accepts only its internal smoke labels,
  `authority/missing-pool` and `configured-pool-member`, and fails closed for
  upstream xfstests row names. Reserve broad target dispatches such as
  `target=fuse` or `target=all` for acceptance gates, scheduled coverage, or
  when the failure set is not yet isolated. `RDMA` dispatch runs two matrix
  targets: `host-probe` for non-mutating runner capability inspection and
  `qemu-two-node` for multi-process distributed transport evidence. The host
  probe is harness/host evidence only; it does not prove live two-node transport
  behavior. xfstests uploads its run-level manifest as
  `xfstests-run-manifest.json`; RDMA claim-shaped rows use v2
  `evidence-manifest.json` records with explicit outcomes.
- `Release Candidate` is a manual-only self-hosted workflow. The `smoke`
  profile runs Rust, Nix, and QEMU smoke lanes; the `full` profile also runs
  xfstests and RDMA. Each run uploads a top-level
  `release-candidate-evidence-index` JSON artifact that records the selected
  profile, source SHA, lane job results, expected lane artifact names and path
  patterns, and absent lane-local manifests without making a product-readiness
  claim. Newer dispatches for the same branch and profile cancel older queued
  or running copies so superseded release-candidate runs do not leave stale
  self-hosted index jobs in the runner queue.
  The evidence index is consumed by the release-readiness verdict contract
  (`docs/RELEASE_READINESS_VERDICT_CONTRACT.md`), which defines the boundary
  between gate-local readiness receipts and whole-product admission.

## Runner Contract

Both 32-core development VMs are GitHub self-hosted runners in the
`tidefs-ci` runner group. Each runner should have these labels:

```text
self-hosted linux x64 tidefs nix kvm fuse ublk rdma kernel xfstests
```

The runners need Nix, KVM, FUSE, ublk, loop devices, QEMU, RDMA userspace
tools, and enough local scratch space for Nix builds and VM disks.
Individual workflows select narrower subsets of that label set: Rust, Nix,
Secret Policy, dependency, and actionlint lanes use the `nix` subset; QEMU and
kernel validation lanes add `kvm`; xfstests adds `xfstests`; and RDMA adds
`rdma`.

The path-gated QEMU push and scheduled self-hosted jobs stay skipped until the
repository variable `TIDEFS_SELF_HOSTED_READY` is set to `1`. Manual dispatch
ignores that gate so a specific lane can be run during bring-up.

Draft pull requests are not integration candidates, so required self-hosted PR
checks skip them until the PR is marked ready for review. The `ready_for_review`
event reruns the standing checks on the current head before integration.
Manual workflow dispatch remains available for draft branches that need early
evidence. Live GitHub state is authoritative for automation; issue, pull-request,
and push events do not allocate a self-hosted runner merely to wake a local
controller.

Runner host configuration and bring-up notes live in
`tidefs/tidefs-infra-configuration`.
