# apps/

This root hosts bounded userspace mirror binaries and operator/demo tools.

Current app roots are mixed operator, daemon, and demo surfaces. This is an
inventory, not a production-readiness claim:

- `tidefs-block-volume-adapter-daemon` — Block Volume Adapter userspace daemon
  and ublk tooling. Release validation must come from the live ublk path or an
  explicit host/runtime blocker.
- `tidefsctl` — operator CLI. Its public UAPI authority remains under
  `TFR-011`/`TFR-019` review until command maturity labels, docs, and handlers
  agree.
- `tidefs-filesystem-demo` — non-production Local Filesystem demo that creates
  a small persisted namespace over the Local Object Store.
- `tidefs-posix-filesystem-adapter-daemon` — userspace FUSE preview mount,
  smoke test, and POSIX validation harness surface.
- `tidefs-scrub` — scrub/repair CLI surface for the current scrub core.
- `tidefs-storage-node` — storage-node daemon and transport-backed object-store
  surface. The storage-node cluster authority remains under `TFR-017`;
  transport product authority is review-scoped there as well.
- `tidefs-store-demo` — non-production Local Object Store demo that writes,
  reopens, replays, and reads real bytes from disk.
