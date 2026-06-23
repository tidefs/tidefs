# FUSE Adapter Contract Assumptions

> TFR-019 authority classification: Current policy (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

Maturity: current guardrail for GitHub issue #290.

The FUSE adapter is an environment boundary. It may parse kernel requests,
manage FUSE connection/request lifecycle state, classify unsupported kernel
capabilities, and schedule foreground/background work. It must not define the
filesystem semantics for acknowledged mutations.

Semantic adapter requests are translated into TideFS-owned request/completion
records at the adapter boundary. The current canonical seed lives in
`tidefs-types-vfs-core::contract`; operations not yet represented there may
use the temporary `tidefs-model-core::ModelRequest` vocabulary in pure
verification models, but runtime adapter code must continue through the
VfsEngine/contract executor path rather than calling storage mutation APIs
directly.

Unsupported FUSE capabilities are explicit model outcomes. Known examples
include `O_TMPFILE` and FIEMAP-class requests when the current mounted subset
does not implement them. These outcomes are classified as unsupported with a
stable errno and are not harness failures.

The guardrail for this assumption is
`cargo test -p tidefs-env-fuse-model adapter_boundary_guard_rejects_storage_bypass --locked`.
It scans production adapter-boundary source files for direct local-filesystem
or object-store mutation authority. Test fixtures and daemon backend assembly
remain allowed outside that scoped production request-handler set.

This document does not close any GitHub issue #254 xfstests rows and does not
claim broader FUSE/POSIX completeness. Runtime xfstests evidence stays owned
by the focused runtime issues that dispatch those rows.
