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
  TideFS workflows.
- `Rust Fast` runs on the TideFS self-hosted runner VMs through the repo
  `.#ci` Nix development shell. It covers workspace metadata plus a focused
  Rust smoke set:
  `tidefs-xtask`, `tidefs-extent-map`,
  `tidefs-schema-codec-posix-filesystem-adapter`, and
  `tidefs-secret-key-policy-runtime`, plus a targeted `tidefs-transport`
  session test.
- `Clippy` runs on the TideFS self-hosted runner VMs through the same repo
  `.#ci` Nix development shell. On pull requests it selects changed workspace
  crates, compares their clippy warning counts against
  `docs/clippy-baseline.json`, and fails when a crate introduces warnings
  above the recorded baseline. Manual dispatch can run either changed-crate or
  full-workspace clippy checks against a feature branch and uploads
  `clippy-baseline-summary`.
- `Focused Rust` is a manual self-hosted workflow for issue-specific PR
  validation. Dispatch it against the feature branch with a comma-separated
  crate list and optional extra `cargo test` arguments when the acceptance
  criteria require touched-package Rust tests outside the standing smoke set.
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
  `validate-ublk-started-export`. Input validation rejects broad or
  mismatched selections (for example, `claim_id` without
  `validate-claim` mode). The workflow summary records the claim id,
  artifact path, command executed, result, and any artifact upload
  path. It does not expose or configure TideFS secrets and does not
  trigger broad xfstests, RDMA, kernel, or release-candidate validation.
- `Secret Policy` runs on the same self-hosted TideFS runner labels and keeps
  the GitHub secret boundary checked without spending hosted Actions minutes.
- Standing PR validation is path-filtered so docs-only design and authority
  PRs do not occupy scarce self-hosted runner slots when their issue validation
  tier is documentation/design/source inspection. `Rust Fast` and `Nix Checks`
  ignore pull requests that only touch `docs/**`, root Markdown policy text, or
  `COPYING`; pushes to `master` and manual dispatches still run them.
  `Secret Policy` pull-request runs are limited to the workflow/policy files it
  scans plus the xtask and build inputs that can change the scanner itself. If
  a documentation-only PR needs runtime or build validation, record that in the
  issue validation tier and dispatch the focused workflow explicitly.
- `Codex Nexus Relay` is a self-hosted event bridge for the local
  `tidefs-codex-nexus` dashboard. It does not run tests or checkout source; it
  relays issue, pull-request, push, and manual-dispatch events by signing the
  original GitHub event payload with the host-local
  `/etc/tidefs-codex-nexus/webhook-secret` file on `ci1`/`ci2` and posting it
  to `http://172.16.106.12/tidefs-codex-nexus/webhook/github`. Comment and
  workflow-run events stay out of the relay to avoid recursive automation
  chatter; the Nexus safety poll still refreshes workflow state.
- `Nix Checks` runs on self-hosted TideFS runners and builds pure check
  derivations plus the core Nix packages.
- `QEMU Smoke` runs outside-sandbox kernel runtime rows on self-hosted
  TideFS runners with KVM and FUSE access. Pushes to `master` run the default
  `kmod-xfstests-smoke` target: load `tidefs_posix_vfs.ko`, mount the explicit
  bootstrap VFS root, exercise supported directory/symlink/readdir/statfs
  operations, and keep engine-backed storage checks in the longer filesystem
  lanes. Manual dispatch can select the default target, the mounted
  `kernel-mmap-validation` target, or both.
- `Two-node carrier validation` is a manual `QEMU Smoke` target for
  `tidefs-two-node-harness`. It runs `.#two-node-carrier-validation`, boots a
  Linux 7.0 QEMU guest, executes the `qemu`-gated live TCP carrier
  state-transfer scenario, and uploads `carrier-report.json`, `qemu.log`,
  `summary.json`, and environment metadata under
  `two-node-carrier-validation`.
- `Kernel mmap validation` is a narrow manual self-hosted workflow for the
  mounted mmap/writeback QEMU row. It runs `.#kernel-mmap-validation` against
  the selected branch and uploads row artifacts under
  `kernel-mmap-validation`.
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
- `xfstests` and `RDMA` are scheduled/manual lanes for longer filesystem and
  transport work. Manual `xfstests` dispatch accepts a `target` and an
  optional space-separated `tests` list. Use the smallest known failing row set
  such as `generic/003` while debugging an isolated failure; reserve broad
  target dispatches such as `target=fuse` or `target=all` for acceptance gates,
  scheduled coverage, or when the failure set is not yet isolated.
- `Release Candidate` is a manual-only self-hosted workflow. The `smoke`
  profile runs Rust, Nix, and QEMU smoke lanes; the `full` profile also runs
  xfstests and RDMA. Each run uploads a top-level
  `release-candidate-evidence-index` JSON artifact that records the selected
  profile, source SHA, lane job results, expected lane artifact names and path
  patterns, and absent lane-local manifests without making a product-readiness
  claim. Newer dispatches for the same branch and profile cancel older queued
  The evidence index is consumed by the release-readiness verdict contract
  (`docs/RELEASE_READINESS_VERDICT_CONTRACT.md`), which defines the boundary
  between gate-local readiness receipts and whole-product admission.
  or running copies so superseded release-candidate runs do not leave stale
  self-hosted index jobs in the runner queue.

## Runner Contract

Both 32-core development VMs are GitHub self-hosted runners in the
`tidefs-ci` runner group. Each runner should have these labels:

```text
self-hosted linux x64 tidefs nix kvm fuse ublk rdma kernel xfstests
```

The runners need Nix, KVM, FUSE, ublk, loop devices, QEMU, RDMA userspace
tools, and enough local scratch space for Nix builds and VM disks.

Push-triggered and scheduled self-hosted jobs stay skipped until the repository
variable `TIDEFS_SELF_HOSTED_READY` is set to `1`. Manual dispatch ignores that
gate so a specific lane can be run during bring-up.

Draft pull requests are not integration candidates, so required self-hosted PR
checks skip them until the PR is marked ready for review. The `ready_for_review`
event reruns the standing checks on the current head before integration.
Manual workflow dispatch remains available for draft branches that need early
evidence. Codex Nexus Relay jobs use one global concurrency group and may
cancel stale relay runs across issues, PRs, and refs because any delivered
relay wakeup causes Nexus to reconcile live GitHub state rather than treating
each queued relay job as durable work.

Runner host configuration and bring-up notes live in
`tidefs/tidefs-infra-configuration`.

## Codex Nexus Relay Recovery

The relay HMAC secret is intentionally host-local. It must be present on each
self-hosted runner VM as:

```text
/etc/tidefs-codex-nexus/webhook-secret
```

The file should be owned by `root:github-runner` with mode `0640`. To validate
the event bridge after runner maintenance, confirm that the NixOS system
profile still exposes the relay signer tools on each runner, dispatch the
`Codex Nexus Relay` workflow against the target branch, and confirm the local
dashboard event log records a signed `workflow_dispatch` event.

- `Kernel no-daemon teardown validation` is a manual self-hosted QEMU Smoke
  target for the T6 full-kernel-no-daemon teardown and recovery runtime
  evidence row. It runs `.#kernel-no-daemon-teardown-validation` against the
  selected branch, exercises mount/write/sync/teardown/unmount/module-unload
  lifecycle with ftrace workqueue tracing, zero userspace daemons, post-final
  refusal probes, and no-daemon crash/recovery cycles, and uploads
  `kernel-teardown-runtime.json` and `evidence-manifest.json` under
  `kernel-no-daemon-teardown-validation`. It does not update claim registry
  status or generated claim docs.
