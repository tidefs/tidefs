# Pool Encryption Secret-Handle/Key-Lease Boundary (REL-SEC-003)

Status: implemented (type boundary, 2026-05-22)
Crate: `tidefs-encryption` (`secret_handle` module)

## What this boundary is

The secret-handle/key-lease boundary replaces raw file-path-based encryption
key management with a handle-based model following P9-04 secret-key-policy law.
Operators reference the pool encryption key by a stable opaque `SecretHandleId`
rather than by a filesystem path to a `SealedPoolKeyEnvelope` file. Runtime
access to the plaintext key flows through a short-lived `PoolEncryptionKeyLease`,
not through an ambient long-lived key reference.

## Key types

| Type | Location | Role |
|---|---|---|
| `SecretHandleId` | `tidefs_encryption::secret_handle` | Stable 128-bit opaque handle for the pool encryption key |
| `SecretHandleLifecycle` | `tidefs_encryption::secret_handle` | P9-04 lifecycle states: SealedInactive, Active, RotatingDualValid, Revoked, Quarantined, Retired |
| `PoolEncryptionSecretHandleRecord` | `tidefs_encryption::secret_handle` | Durable record with handle identity, lifecycle, lineage |
| `PoolEncryptionSecretHandle` | `tidefs_encryption::secret_handle` | Top-level handle bundling record + sealed envelope |
| `PoolEncryptionKeyLease` | `tidefs_encryption::secret_handle` | Short-lived plaintext key access; zeroized on drop |
| `LeaseUsageClass` | `tidefs_encryption::secret_handle` | PoolMount, PoolMaintenance, DatasetAccess |

## Integration chain

```text
operator -> secret handle ID -> handle record -> sealed envelope
                                                    |
                                    wrapping key --> unseal
                                                    |
                                                    v
                                              plaintext lease (time-bounded)
```

`PoolEncryptionSecretHandle::mint()` generates a pool key, seals it in a
VEKF-format `SealedPoolKeyEnvelope` under the `PoolWrappingKey`, and creates
a handle record. The operator activates the handle before issuing leases.

`PoolEncryptionSecretHandle::issue_lease()` unseals the envelope, returns a
time-bounded `PoolEncryptionKeyLease`. Leases are clamped to
`MAX_LEASE_DURATION` (1 hour). Revoked/quarantined/retired handles refuse
lease issuance.

## Durable storage

The sealed key envelope remains the existing `SealedPoolKeyEnvelope` (VEKF v1,
84 bytes). The new `PoolEncryptionSecretHandleRecord` carries the handle
identity, lifecycle state, SHA-256 envelope digest, and rotation lineage.

## P9-04 compliance

- Handle-not-bytes (§3.3): `SecretHandleId` is an opaque 128-bit identifier;
  the key material is sealed inside the envelope and only exposed via lease.
- Lease bounded lifetime (§5.1): `PoolEncryptionKeyLease` is time-bounded
  and zeroized on drop.
- Lifecycle states (§6.5): all six P9-04 states implemented.
- Handle stable across rotation: `key_generation` counter tracks rotation
  lineage.

## Current reachability

The boundary types are defined and tested. The pool create/import/mount CLI

## A-register impact

This implements the type-boundary portion of A17 (Security/Auth/Encryption
Design Is Split Between Strong Laws And Weak Live Boundaries):
- Advances: "Resolve mounted at-rest encryption authority" by providing the
  P9-04 handle/lease types needed for product-path wiring.
- Does not yet close: product reachability (pool create/import/mount wiring)

## Tests

9 unit tests in `secret_handle::tests` covering: mint+lease roundtrip,
revoked-handle refusal, wrong wrapping key rejection, lease duration clamping,
lease consumption, handle ID hex roundtrip, uniqueness, lifecycle transitions,
and envelope integrity digest stability.
