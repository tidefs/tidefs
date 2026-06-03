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
| `pool create` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::Publish)` |
| `pool import` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::Stage)` |
| `pool export` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::Stage)` |
| `pool destroy` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::Publish)` |
| `device remove` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::RepairPublish)` |
| `encryption key enroll` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::RotateKey)` |
| `dataset create/destroy` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::Stage)` |
| `snapshot create/destroy` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::Stage)` |
| `block attach/detach` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::Stage)` |
| `defrag` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::RepairPublish)` |
| `read audit log` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::ReadAuditLog)` |
| `grant/revoke role` | LocalOnly | `LocalOnlyGuard` | `AuthorizationRequest(ActionClass::GrantRole)` |

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
- **A20** (tidefsctl Operator Surface): not directly addressed — the
  `LocalOnlyGuard` is source-integrated in `tidefs-auth` and available for
  wiring into `tidefsctl` privileged commands. Wiring it into tidefsctl is
  deferred to the tidefsctl UAPI cleanup issue.

## Implementation Status (2026-05-23)

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

### Next
- Wire `LocalOnlyGuard` into remaining privileged entry points:
  `tidefsctl pool create`, `tidefsctl pool destroy`, `tidefsctl device remove`,
  `tidefsctl snapshot create/destroy`, `tidefsctl block attach/detach`
