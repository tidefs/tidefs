# GitHub CI

TideFS uses GitHub as the primary private remote. The repository remains
private until the operator gives an explicit public-release go-ahead.

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
- `Focused Rust` is a manual self-hosted workflow for issue-specific PR
  validation. Dispatch it against the feature branch with a comma-separated
  crate list and optional extra `cargo test` arguments when the acceptance
  criteria require touched-package Rust tests outside the standing smoke set.
  It uses the same repo `.#ci` Nix development shell, host-local Cargo scratch,
  JSON summary artifact, and per-run target cleanup as `Rust Fast`. It also
  self-tests on pull requests that modify the focused workflow or its runner
  helper so workflow changes get Actions coverage before merge.
- `Secret Policy` runs on the same self-hosted TideFS runner labels and keeps
  the GitHub secret boundary checked without spending hosted Actions minutes.
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
- `Kernel mmap validation` is a narrow manual self-hosted workflow for the
  mounted mmap/writeback QEMU row. It runs `.#kernel-mmap-validation` against
  the selected branch and uploads row artifacts under
  `kernel-mmap-validation`.
- `xfstests` and `RDMA` are scheduled/manual lanes for longer filesystem and
  transport work. Manual `xfstests` dispatch accepts a `target` and an
  optional space-separated `tests` list. Use the smallest known failing row set
  such as `generic/003` while debugging an isolated failure; reserve broad
  target dispatches such as `target=fuse` or `target=all` for acceptance gates,
  scheduled coverage, or when the failure set is not yet isolated.
- `Release Candidate` is a manual-only self-hosted workflow. The `smoke`
  profile runs Rust, Nix, and QEMU smoke lanes; the `full` profile also runs
  xfstests and RDMA.

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
