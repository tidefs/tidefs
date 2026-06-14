# Operator Authentication and Authorization Boundary

Issue: #6489
Packet: NEXT-SEC-010
documented and the LocalOnlyGuard is source-integrated; runtime
enforcement of remote authz is deferred to cluster operator path
completion.

## Posture

TideFS currently operates as a **local-only** storage system for privileged
operator actions. Every mutation of pool state, device topology, encryption
secrets, and dataset catalog requires direct local access to storage devices,
pool lock directories, and encryption secret handles. These operations refuse
to execute in a remote, proxied, or cluster-routed context.

When TideFS gains full multi-node cluster operation with remote operator
access, privileged actions will be gated through the P9-02 authorization
pipeline (Principal, RoleBinding, AuthorizationRequest, AuthorizationDecision,
AuditLog). Until that path is product-grade, the local-only guard prevents
ambiguous operation.

## Privileged Action Classification

| Action | Authz Class | Current Gate | Future Gate |
|---|---|---|---|
| `pool create/import/export/destroy/set` | LocalOnly | `tidefsctl` admission helper and lower pool guards where present | `AuthorizationRequest(ActionClass::Publish/Stage)` |
| `device remove` | LocalOnly | `tidefsctl` admission helper | `AuthorizationRequest(ActionClass::RepairPublish)` |
| `dataset create/destroy/rename/set` | LocalOnly | `tidefsctl` admission helper | `AuthorizationRequest(ActionClass::Stage)` |
| `dataset set-strategy --enable/--disable` | LocalOnly | `tidefsctl` admission helper when mutating | `AuthorizationRequest(ActionClass::Stage)` |
| `dataset upgrade` | LocalOnly | `tidefsctl` admission helper | `AuthorizationRequest(ActionClass::Stage)` |
| `dataset seal-key/rotate-key` | LocalOnly | `tidefsctl` admission helper | `AuthorizationRequest(ActionClass::RotateKey)` |
| `snapshot create/destroy/rollback/send/receive`, `snapshot clone create/delete/promote`, `snapshot bookmark create/delete`, `snapshot hold/release/prune` | LocalOnly | `tidefsctl` admission helper | `AuthorizationRequest(ActionClass::Stage)` |
| `block attach/detach/send/receive` | LocalOnly | `tidefsctl` admission helper | `AuthorizationRequest(ActionClass::Stage)` |
| `defrag` | LocalOnly | `tidefsctl` admission helper | `AuthorizationRequest(ActionClass::RepairPublish)` |

The `tidefsctl` admission helper is the public CLI/UAPI boundary for these
commands. It maps each privileged command name to
`LocalOnlyGuard::new("<command>")` and emits a consistent `tidefsctl <command>:
...` operator error if the guard cannot prove a local process context.

The following surfaces are consciously excluded from the privileged guard
until they mutate state or a future issue gives them a stronger authorization
class: help text, `pool scan`, `pool status`, `pool get`, `pool list-props`,
`snapshot list`, `snapshot holds`, `block list`, `dataset list`, `dataset get`,
`dataset list-props`, `pool integrity-check`, `kernel status`, `diag`,
userspace harnesses (`mount`, `pool mount`), prototype/development cluster
commands, and removed directory-backed/offline surfaces that already fail
closed before opening retired media.

`mount` remains explicitly standalone/local: it constructs only standalone
daemon mount authority and cannot assert cluster admission. `pool mount
--cluster` is separate from P9-02 remote operator authorization; it is admitted
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

## P9-02 Authorization Pipeline (Future)

When cluster-routed operator access is product-grade, the current
`LocalOnlyGuard` will be replaced by the full P9-02 pipeline:

1. **Principal resolution** — `resolve_principal_from_presented_credential_chain()`
   maps the caller's credentials to a `Principal` with class, roles, and
   node binding.
   binds the principal to a short-lived session with a `SessionToken`.
3. **Authorization request** — an `AuthorizationRequest` is constructed with
   the principal, session_id, ActionClass, and resource ScopeSelector.
4. **Decision** — `derive_authorization_decision_for_request()` evaluates
   the request against the principal's role bindings, capabilities, scope,
   and any override tickets.
5. **Audit** — `append_audit_event_and_seal_chain_if_needed()` records the
   decision in the audit log with chain sealing.

This pipeline is already implemented in `tidefs-auth` but is not yet wired
to any CLI/API privileged action paths. Wiring it requires:
- A cluster transport path that can route operator requests to the pool owner
  node
- A session establishment path that provides `AuthenticatedPeer` identity
- An admin peer set configuration for `admin_access_check()`
- Integration of the authorization decision into each privileged handler

## Related Documents

- `docs/security/unified-storage-encryption-threat-model.md` — encryption claims
- `docs/security/security-release-matrix.md` — signoff verdict and threat-claim
  alignment
- `docs/security/transport-security-boundary.md` — transport-level session
  security and ADMIN service gating
- `docs/security/pool-encryption-secret-handle-boundary.md` — encryption secret
  handle and key lease model

## A-Register Relevance

- **A17** (Security/Auth/Encryption Design): advanced — this document and
  `LocalOnlyGuard` wire the operator authz boundary to an explicit, checkable
  call-site token instead of leaving auth/authz claims as record types alone.
  The remaining authz wiring (P9-02 pipeline to privileged handlers) is a
  deferred continuation gated on cluster operator path completion.
- **A20** (tidefsctl Operator Surface): advanced — `tidefsctl` now has an
  explicit local-only admission table for privileged public operator
  mutations and data-movement paths. This does not claim remote cluster
  operator authorization; it keeps the current live-owner routing model in
  place until the P9-02 path is product-grade.

## Implementation Status (2026-06-13)

### Done
- `LocalOnlyGuard` in `tidefs-auth::local_only` — zero-sized runtime token
  with `check_local_process()` verifying PID > 0 and `/proc/self/status`
  accessibility
- `LocalOnlyError` — typed error for non-local and no-process-identity cases
- `From<LocalOnlyError>` impls for `ExportError` and `ImportError`
- `PoolExporter::export_pool()` — wired with `LocalOnlyGuard::new("pool export")?`
- `PoolImporter::import_pool()` — wired with `LocalOnlyGuard::new("pool import")?`
- `ExportOrchestrator::run()` — wired with `LocalOnlyGuard::new("pool export orchestration")?`
- `ExportOrchestrator::export_labels_only()` — wired with `LocalOnlyGuard::new("pool export labels")?`
- `PoolCreator::create_pool()` — wired with `LocalOnlyGuard::new("pool create")?`
- `CreateError::NotLocal` variant with Display and From impls
- `ExportError::NotLocal` and `ImportError::NotLocal` variants with Display
  impls
  unchecked construction, copy semantics, and error display messages
- `apps/tidefsctl/src/commands/authz.rs` — shared command admission helper
  with guard/classification tests for privileged and unguarded command
  surfaces.
- `tidefsctl pool create/import/export/destroy/set`,
  `device remove`, `snapshot create/destroy/rollback/send/receive`,
  `snapshot clone create/delete/promote`,
  `snapshot bookmark create/delete`, `snapshot hold/release/prune`,
  `block attach/detach/send/receive`,
  `dataset create/destroy/rename/set-strategy` when mutating,
  `dataset seal-key/rotate-key/upgrade/set`, and `defrag` now acquire a
  `LocalOnlyGuard` at their CLI handler boundary before mutating state or
  initiating privileged data movement.
- `tidefsctl mount`, `tidefsctl pool mount --cluster`, and the POSIX adapter
  daemon mount config now use typed mount authority: standalone mounts carry no
  cluster lease material, while clustered pool mounts carry a validated
  `PoolLeaseToken` through daemon admission.

### Next
- Keep new `tidefsctl` public operator commands wired through
  `apps/tidefsctl/src/commands/authz.rs` so every command has an explicit
  guarded or unguarded admission decision.
- Replace the local-only guard with the full P9-02 authorization pipeline only
  after the cluster operator path has product-grade principal, session,
  transport, admin peer, authorization, and audit behavior.
