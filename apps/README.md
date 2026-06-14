# apps/

This root hosts bounded userspace entrypoints, operator tools, daemons, and demos.

The checked package-role authority is `docs/workspace-package-classification.md`; this file mirrors the current app-root inventory only for navigation.

| App root | Role | Disposition |
| --- | --- | --- |
| `apps/tidefs-block-volume-adapter-daemon` | `adapter-operator` | operator entrypoint for the ublk adapter; live runtime validation required before release claims. |
| `apps/tidefs-filesystem-demo` | `proof-harness` | demo entrypoint and proof harness; non-production Local Filesystem exercise only. |
| `apps/tidefs-posix-filesystem-adapter-daemon` | `adapter-operator` | operator entrypoint and FUSE validation harness; preview mount surface only. |
| `apps/tidefs-scrub` | `adapter-operator` | operator entrypoint for scrub/repair plumbing; not release proof by itself. |
| `apps/tidefs-storage-node` | `adapter-operator` | operator entrypoint for storage-node experiments; cluster authority remains TFR-017. |
| `apps/tidefs-store-demo` | `proof-harness` | demo entrypoint and proof harness; non-production Local Object Store exercise only. |
| `apps/tidefsctl` | `adapter-operator` | operator entrypoint for CLI/UAPI work; TFR-011 and TFR-019 remain open. |

These app roots are not production-readiness claims. FUSE, ublk, storage-node, scrub, and CLI behavior must still be validated through the relevant issue-scoped checks before release-facing wording can rely on them.
