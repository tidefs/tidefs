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

- `Rust Fast` runs on GitHub-hosted Ubuntu and covers workspace metadata plus
  a focused Rust smoke set:
  `tidefs-xtask`, `tidefs-extent-map`,
  `tidefs-schema-codec-posix-filesystem-adapter`, and
  `tidefs-secret-key-policy-runtime`, plus a targeted `tidefs-transport`
  session test.
- `Nix Checks` runs on self-hosted TideFS runners and builds pure check
  derivations plus the core Nix packages.
- `QEMU Smoke` runs the outside-sandbox kernel bootstrap smoke on self-hosted
  TideFS runners with KVM and FUSE access: load `tidefs_posix_vfs.ko`, mount
  the explicit bootstrap VFS root, exercise supported directory/symlink/
  readdir/statfs operations, and keep engine-backed storage checks in the
  longer filesystem lanes. Legacy runNixOSTest QEMU apps stay out of Actions
  until they are ported to the outside-sandbox runner shape.
- `xfstests` and `RDMA` are scheduled/manual lanes for longer filesystem and
  transport work.
- `Release Candidate` is a manual-only workflow. The `smoke` profile runs Rust,
  Nix, and QEMU smoke lanes; the `full` profile also runs xfstests and RDMA.

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
