# Pool Encryption Secret-Handle/Key-Lease Boundary (REL-SEC-003)

Status: implemented (type boundary + mount-identity unit evidence, 2026-06-18)
Crate: `tidefs-encryption` (`secret_handle` module)

## What this boundary is

The secret-handle/key-lease boundary replaces raw file-path-based encryption
key management with a handle-based model following P9-04 secret-key-policy law.
Operators reference the pool encryption key by a stable opaque `SecretHandleId`
rather than by a filesystem path to a `SealedPoolKeyEnvelope` file. Runtime
access to the plaintext key flows through a short-lived `PoolEncryptionKeyLease`,
not through an ambient long-lived key reference.

Every handle is also bound to a committed dataset mount identity:
`(dataset_id, mount_generation)`. Lease issuance requires the caller to
present that same identity, so stale remount generations and foreign datasets
fail closed before plaintext key access is granted.

## Key types

| Type | Location | Role |
|---|---|---|
| `SecretHandleId` | `tidefs_encryption::secret_handle` | Stable 128-bit opaque handle for the pool encryption key |
| `SecretHandleLifecycle` | `tidefs_encryption::secret_handle` | P9-04 lifecycle states: SealedInactive, Active, RotatingDualValid, Revoked, Quarantined, Retired |
| `DatasetMountIdentity` | `tidefs_encryption::secret_handle` | Committed `(dataset_id, mount_generation)` token for mount-scoped key access |
| `PoolEncryptionSecretHandleRecord` | `tidefs_encryption::secret_handle` | Durable record with handle identity, lifecycle, lineage, and mount identity binding |
| `PoolEncryptionSecretHandle` | `tidefs_encryption::secret_handle` | Top-level handle bundling record + sealed envelope |
| `PoolEncryptionKeyLease` | `tidefs_encryption::secret_handle` | Short-lived plaintext key access bound to the handle mount identity; zeroized on drop |
| `LeaseUsageClass` | `tidefs_encryption::secret_handle` | PoolMount, PoolMaintenance, DatasetAccess |

## Integration chain

```text
operator -> secret handle ID -> handle record + dataset mount identity
                                      |
present matching mount identity ------+
                                      v
                               sealed envelope
                                      |
                      wrapping key -> unseal
                                      |
                                      v
                         plaintext lease (time-bounded)
```

`PoolEncryptionSecretHandle::mint()` generates a pool key, seals it in a
VEKF-format `SealedPoolKeyEnvelope` under the `PoolWrappingKey`, and creates
a handle record bound to a `DatasetMountIdentity`. The operator activates the
handle before issuing leases.

`PoolEncryptionSecretHandle::issue_lease()` first requires the presented
`DatasetMountIdentity` to match the handle binding. Only then does it unseal
the envelope and return a time-bounded `PoolEncryptionKeyLease` carrying the
same mount identity. Leases are clamped to `MAX_LEASE_DURATION` (1 hour).
Wrong mount generation, foreign dataset, and revoked/quarantined/retired
handles refuse lease issuance.

## Durable storage

The sealed key envelope remains the existing `SealedPoolKeyEnvelope` (VEKF v1,
84 bytes). `PoolEncryptionSecretHandleRecord` carries the handle identity,
lifecycle state, committed dataset mount identity, SHA-256 envelope digest,
and rotation lineage.

## P9-04 compliance

- Handle-not-bytes (§3.3): `SecretHandleId` is an opaque 128-bit identifier;
  the key material is sealed inside the envelope and only exposed via lease.
- Lease bounded lifetime (§5.1): `PoolEncryptionKeyLease` is time-bounded
  and zeroized on drop.
- Mount-identity gate: every lease requires the committed dataset identity and
  mount generation that minted the handle. Missing, unbound, stale-generation,
  or foreign-dataset identity checks fail closed.
- Lifecycle states (§6.5): all six P9-04 states implemented.
- Handle stable across rotation: `key_generation` counter tracks rotation
  lineage.

## Current reachability

The boundary types are defined and tested. The P9-04 runtime helper
`validate_dataset_mount_identity_for_handle()` consumes policy-layer mount
identity bindings and defaults stores that cannot prove a binding to
fail-closed behavior. Mounted local-filesystem encryption remains blocked on
the broader transform authority work; this document is not an end-to-end
mounted encryption claim.

## A-register impact

This implements the type-boundary portion of A17 (Security/Auth/Encryption
Design Is Split Between Strong Laws And Weak Live Boundaries):
- Advances: "Resolve mounted at-rest encryption authority" by providing the
  P9-04 handle/lease types needed for product-path wiring.
- Does not yet close: product reachability (pool create/import/mount wiring)

## Tests

17 unit tests in `secret_handle::tests` covering: mint+lease roundtrip,
revoked-handle refusal, wrong wrapping key rejection, lease duration clamping,
lease consumption, handle ID hex roundtrip, uniqueness, lifecycle transitions,
envelope integrity digest stability, correct mount identity success, wrong
generation rejection, foreign dataset rejection, encryption round-trip through
the mount-identity gate, key rotation across remount, and mount identity
display/matching helpers.
