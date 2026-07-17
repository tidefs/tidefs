# Operator Authentication and Authorization Boundary

Current authority: `docs/OPERATOR_UAPI_AUTHORITY.md`, the checked
`tidefsctl` command classification/admission tables, and source-owned
`tidefs-auth` local-only admission helpers.

This boundary records the current local-only operator admission surface. It is
not a remote operator-authorization, production cluster, release-readiness, or
successor/comparator claim. Remote privileged-action authorization remains owned
by the live operator-authz follow-up work until transport/session/live-owner
evidence is product-grade and explicitly wired into privileged handlers.

## Posture

TideFS currently operates as a **local-only** storage system for privileged
operator actions. Every mutation of pool state, device topology, encryption
secrets, and dataset catalog requires direct local access to storage devices,
pool lock directories, and encryption secret handles. These operations refuse
to execute in a remote, proxied, or cluster-routed context.

`tidefs-auth` includes source-owned authorization and audit primitives for a
future remote privileged-action path, but current privileged CLI/API handlers do
not treat those primitives as remote admission by themselves. Until the
transport/session/live-owner path is product-grade and explicit remote context
is passed into handlers, `LocalOnlyGuard` keeps privileged mutation and data
movement local-only.

## Privileged Action Classification

The `tidefsctl` admission helper is the public CLI/UAPI boundary for command
authorization. The table is checked byte-for-byte against
`apps/tidefsctl/src/commands/classification.rs` and
`apps/tidefsctl/src/commands/authz.rs`.

`docs/OPERATOR_UAPI_AUTHORITY.md` records the operator UAPI authority decision
that relates this admission table to live-owner routing, diagnostics,
prototype cluster commands, and preview kernel/FUSE/ublk surfaces. That
decision does not freeze production Linux ioctl/statx/ublk ABI, kernel-module
ABI, kernelspace readiness, or final distributed operator UAPI; this document
keeps the current privileged-action boundary local-only until remote authz is
product-grade.

| Command | Class | Routing | Admission | Help | Summary |
|---|---|---|---|---|---|
| `pool create` | `public-operator` | `offline-discovery-or-import-input` | `local-only` | `visible` | create an exported pool from explicit byte-addressable devices |
| `pool scan` | `public-operator` | `offline-discovery-or-import-input` | `unguarded` | `visible` | scan explicit devices for pool labels |
| `pool status` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | query the live owner by pool name, or scan explicit offline devices |
| `pool import` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | request owner-mediated import; explicit devices are import inputs |
| `pool export` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | export through the live owner, or operate on exported explicit devices |
| `pool destroy` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | destroy through the live owner, or operate on exported explicit devices |
| `pool get` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | read pool properties through owner authority or explicit offline devices |
| `pool set` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | set pool properties through owner authority or explicit offline devices |
| `pool list-props` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list pool property definitions and effective values |
| `snapshot create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create snapshots through the live owner or explicit offline devices |
| `snapshot list` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list local snapshot catalog entries with kind, origin, hold, and generation metadata |
| `snapshot clone create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create local snapshot clones through the live owner or explicit offline devices |
| `snapshot clone delete` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | delete local snapshot clones through the live owner or explicit offline devices |
| `snapshot clone promote` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | promote local snapshot clones through the live owner or explicit offline devices |
| `snapshot bookmark create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create local snapshot bookmarks through the live owner or explicit offline devices |
| `snapshot bookmark delete` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | delete local snapshot bookmarks through the live owner or explicit offline devices |
| `snapshot hold` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | place local deletion-prevention holds on snapshots or clones |
| `snapshot release` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | release local deletion-prevention holds on snapshots or clones |
| `snapshot holds` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | inspect local snapshot and clone hold counts |
| `snapshot prune` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | prune regular local snapshots by retention policy while excluding clones and bookmarks |
| `snapshot prune-scheduled policy` | `public-operator` | `live-owner` | `unguarded` | `visible` | inspect live scheduled snapshot prune policy admission state |
| `snapshot prune-scheduled plan` | `public-operator` | `live-owner` | `unguarded` | `visible` | inspect live scheduled snapshot prune dry-run plans |
| `snapshot prune-scheduled enable` | `public-operator` | `live-owner` | `local-only` | `visible` | admit destructive scheduled snapshot prune execution through live authority |
| `snapshot prune-scheduled disable` | `public-operator` | `live-owner` | `local-only` | `visible` | disable destructive scheduled snapshot prune execution through live authority |
| `snapshot prune-scheduled status` | `public-operator` | `live-owner` | `unguarded` | `visible` | inspect live scheduled snapshot prune job status |
| `snapshot prune-scheduled refusals` | `public-operator` | `live-owner` | `unguarded` | `visible` | inspect live scheduled snapshot prune refusal reasons |
| `snapshot prune-scheduled results` | `public-operator` | `live-owner` | `unguarded` | `visible` | inspect live scheduled snapshot prune result summaries |
| `snapshot destroy` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | destroy snapshots through the live owner or explicit offline devices |
| `snapshot export` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | register runtime-pending read-only snapshot export mount surface |
| `snapshot extract` | `public-operator` | `live-owner` | `local-only` | `visible` | extract one regular file from a snapshot through the live owner |
| `snapshot rollback` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | roll back through the live owner or explicit offline devices |
| `snapshot send` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | export snapshot streams through owner authority or explicit offline devices |
| `snapshot receive` | `public-operator` | `live-owner` | `local-only` | `visible` | receive snapshot streams through the live owner; offline receive is unsupported |
| `device remove` | `public-operator` | `live-owner` | `local-only` | `visible` | require live-owner authority but refuse dispatch until evacuation receipts and topology/label updates are durable |
| `device status` | `public-operator` | `live-owner` | `unguarded` | `visible` | query live device status through the live owner; fail closed when no live owner is reachable |
| `defrag` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | request online extent-map defragmentation for a path |
| `block attach` | `public-operator` | `live-owner` | `local-only` | `visible` | attach an imported pool as a ublk block device through owner authority |
| `block detach` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | detach an existing ublk device by numeric id |
| `block list` | `public-operator` | `no-live-pool-state` | `unguarded` | `visible` | list attached ublk devices |
| `block send` | `public-operator` | `live-owner` | `local-only` | `visible` | send block-volume state through live owner and transport authority |
| `block receive` | `public-operator` | `live-owner` | `local-only` | `visible` | receive block-volume state through live owner and transport authority |
| `dataset create` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | create catalog-backed datasets through owner authority or explicit devices |
| `dataset list` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list catalog-backed datasets through owner authority or explicit devices |
| `dataset destroy` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | destroy catalog entries through owner authority or explicit devices |
| `dataset rename` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | rename catalog entries through owner authority or explicit devices |
| `dataset set-strategy` | `public-operator` | `live-owner-or-offline-input` | `local-only-when-mutating` | `visible` | set dataset feature strategy through owner authority or explicit devices |
| `dataset seal-key` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | seal dataset keys through owner authority or explicit devices |
| `dataset rotate-key` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | rotate dataset wrapping keys through owner authority or explicit devices |
| `dataset upgrade` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | enable supported dataset features through owner authority or explicit devices |
| `dataset get` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | read dataset properties through owner authority or explicit devices |
| `dataset set` | `public-operator` | `live-owner-or-offline-input` | `local-only` | `visible` | set dataset properties through owner authority or explicit devices |
| `dataset list-props` | `public-operator` | `live-owner-or-offline-input` | `unguarded` | `visible` | list dataset property definitions and effective values |
| `storage-intent explain` | `public-operator` | `passive-diagnostic` | `unguarded` | `visible` | render supplied storage-intent policy, receipt, and evidence-query records read-only |
| `storage-intent policy set` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | stage dataset prefetch/residency policy source through #855 without activation |
| `storage-intent policy clear` | `public-operator` | `no-live-pool-state` | `local-only` | `visible` | stage dataset prefetch/residency policy clears through #855 without activation |
| `storage-intent policy show` | `public-operator` | `passive-diagnostic` | `unguarded` | `visible` | render staged dataset prefetch/residency policy source documents |
| `storage-intent policy dry-run` | `public-operator` | `passive-diagnostic` | `unguarded` | `visible` | compile staged dataset prefetch/residency policy source and render blocked support |
| `mount` | `userspace-harness` | `userspace-harness` | `unguarded` | `visible` | launch the current direct FUSE development harness |
| `pool mount` | `userspace-harness` | `userspace-harness` | `unguarded` | `visible` | import explicit devices and launch the current FUSE owner harness |
| `pool integrity-check` | `operator-diagnostic` | `live-owner-or-offline-input` | `unguarded` | `visible` | run live-owner or explicit-device integrity diagnostics |
| `kernel status` | `operator-diagnostic` | `passive-diagnostic` | `unguarded` | `visible` | passively inspect the declared kernel control endpoint |
| `diag` | `operator-diagnostic` | `passive-diagnostic` | `unguarded` | `visible` | collect a redacted diagnostic support bundle |
| `cluster pool create` | `prototype` | `prototype-only` | `unguarded` | `visible` | prototype clustered pool creation; not final distributed operator UAPI |
| `cluster placement exercise` | `development-diagnostic` | `development-exercise` | `unguarded` | `visible` | development diagnostic exercise for placement-map code |
| `cluster heal exercise` | `development-diagnostic` | `development-exercise` | `unguarded` | `visible` | development diagnostic exercise for placement-heal code |
| `cluster status` | `public-operator` | `live-owner` | `unguarded` | `visible` | query live cluster status through the live owner; fail closed when no live owner is reachable |
| `pool list` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | no authoritative pool registry exists; use pool scan --devices or pool status <pool> |
| `device rebuild` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | offline directory object-store rebuild is retired; use live pool repair authority |
| `directory-backed pool media` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store pool media is retired for operator pool commands |
| `pool integrity-check --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store integrity scan mode is retired; use --devices or live owner |
| `snapshot --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store snapshot mode is retired |
| `block --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | directory object-store block-volume mode is retired |
| `device remove --backing-dir` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | offline directory device removal is retired |
| `device remove --surviving-dirs` | `removed-or-unsupported` | `removed` | `unguarded` | `hidden` | offline directory survivor-device removal is retired |

Rows with `local-only` map to `LocalOnlyGuard::new("<command>")` and emit a
consistent `tidefsctl <command>: ...` operator error if the guard cannot prove
a local process context. `local-only-when-mutating` is the same guard in the
mutating mode only. `unguarded` rows are consciously excluded from privileged
guarding until they mutate state or a future issue gives them a stronger
authorization class.

## Diagnostic Bundle Boundary

`tidefsctl diag` is an unguarded, read-only operator diagnostic. Its support
bundle is source-qualified evidence rather than authority. System, build, and
environment facts are labeled `passive-host-probe`; command-surface facts are
labeled `command-classification-registry`; explicit `--devices` facts are
labeled `offline-device-scan`; future reachable owner facts must be labeled
`live-owner`; and placeholders are labeled `unavailable`.

The diagnostic path must not reopen cached imported-pool state behind the
runtime owner. If explicit device labels show `ACTIVE` imported state, the
bundle may report label-only evidence and `live_owner_required`, but committed
roots, datasets, and claim-adjacent validation rows remain unavailable unless a
reachable live-owner or validation artifact source is actually consulted.

`mount` remains explicitly standalone/local: it constructs only standalone
daemon mount authority and cannot assert cluster admission. `pool mount
--cluster` is separate from remote operator authorization; it is admitted
only after clustered pool labels are validated, the pool GUID is read from the
labels, a non-empty `PoolLeaseToken` is acquired from the storage-node, and the
daemon receives one typed cluster lease authority. The daemon rejects missing,
corrupt, invalid, or pool-mismatched lease material before opening the mounted
filesystem, and it rejects cluster lease material on standalone authority
instead of ignoring it.

## LocalOnlyGuard

The `LocalOnlyGuard` struct in `tidefs-auth::local_only` provides a runtime
check that confirms the calling process is a local POSIX process with access
to `/proc/self/status`. It is a zero-sized token that documents the local-only
boundary at the call site.

```rust
use tidefs_auth::local_only::LocalOnlyGuard;

let _guard = LocalOnlyGuard::new("pool create")
    .expect("pool create must run locally");
```

- The process has a valid PID (not PID 0)
- `/proc/self/status` is accessible (confirming a local Linux process context)

When either check fails, the guard returns `LocalOnlyError`, blocking the
privileged operation.

## Source-Owned Authorization Pipeline

When cluster-routed operator access is product-grade, privileged handlers will
use the full `tidefs-auth` pipeline instead of bare `LocalOnlyGuard`:

1. **Principal resolution** — `resolve_principal_from_presented_credential_chain()`
   maps the caller's credentials to a `Principal` with class, roles, and
   node binding.
2. **Session binding** — authenticated session material such as a
   `SessionToken` binds the principal to a short-lived session id.
3. **Authorization request** — an `AuthorizationRequest` is constructed with
   the principal, session_id, ActionClass, and resource ScopeSelector.
4. **Decision** — `derive_authorization_decision_for_request()` evaluates
   the request against the principal's role bindings, capabilities, scope,
   and any override tickets.
5. **Audit** — `append_audit_event_and_seal_chain_if_needed()` records the
   decision in the audit log with chain sealing.

The record-level pipeline and remote privileged-action decision/audit helper are
source-owned in `tidefs-auth`, but they are not wired to any CLI/API privileged
action handler as a remote control path. Issue #1801 and PR #1982 own that
follow-up surface. Until that work lands with explicit transport, session,
admin-peer, live-owner, authorization, and audit evidence, handlers remain
local-only by default.

## Related Documents

- `docs/OPERATOR_UAPI_AUTHORITY.md` — operator UAPI authority decision and
  preserved non-claims for preview ABI/UAPI scope
- `docs/security/unified-storage-encryption-threat-model.md` — encryption claims
- `docs/CLAIMS_GATE_POLICY.md` — claim wording and evidence-gate alignment
- `docs/security/transport-security-boundary.md` — transport-level session
  security and ADMIN service gating
- `docs/security/pool-encryption-secret-handle-boundary.md` — encryption secret
  handle and key lease model
