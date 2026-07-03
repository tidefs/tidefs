# Pool Encryption Secret-Handle/Key-Lease Boundary (REL-SEC-003)

Status: implemented (committed mount-token boundary + unit evidence, 2026-06-20)
Crate: `tidefs-encryption` (`secret_handle` module)

## What this boundary is

The secret-handle/key-lease boundary replaces raw file-path-based encryption
key management with a handle-based model following P9-04 secret-key-policy law.
Operators reference the pool encryption key by a stable opaque `SecretHandleId`
rather than by a filesystem path to a `SealedPoolKeyEnvelope` file. Runtime
access to the plaintext key flows through a short-lived `PoolEncryptionKeyLease`,
not through an ambient long-lived key reference.

Every handle is also bound to committed dataset mount evidence. The mount
authority mints a `CommittedDatasetMountToken` from
`DatasetMountIdentity { dataset_id, mount_generation }` and secret
`DatasetMountAuthorityKey` material. Lease issuance requires the caller to
present that committed token, not just the tuple, so missing evidence,
tampered commitments, stale remount generations, and foreign datasets fail
closed before plaintext key access is granted.

## Key types

| Type | Location | Role |
|---|---|---|
| `SecretHandleId` | `tidefs_encryption::secret_handle` | Stable 128-bit opaque handle for the pool encryption key |
| `SecretHandleLifecycle` | `tidefs_encryption::secret_handle` | P9-04 lifecycle states: SealedInactive, Active, RotatingDualValid, Revoked, Quarantined, Retired |
| `DatasetMountIdentity` | `tidefs_encryption::secret_handle` | Bare dataset/mount tuple; not sufficient authorization by itself |
| `DatasetMountAuthorityKey` | `tidefs_encryption::secret_handle` | Secret mount-authority key material used to mint committed tokens |
| `CommittedDatasetMountToken` | `tidefs_encryption::secret_handle` | Keyed BLAKE3 commitment over the dataset id and mount generation |
| `PoolEncryptionSecretHandleRecord` | `tidefs_encryption::secret_handle` | Durable record with handle identity, lifecycle, lineage, and mount identity binding |
| `PoolEncryptionSecretHandle` | `tidefs_encryption::secret_handle` | Top-level handle bundling record + sealed envelope |
| `PoolEncryptionKeyLease` | `tidefs_encryption::secret_handle` | Short-lived plaintext key access bound to the handle mount identity; zeroized on drop |
| `LeaseUsageClass` | `tidefs_encryption::secret_handle` | PoolMount, PoolMaintenance, DatasetAccess |
| `MountedPoolKeyAccessAssessment` | `tidefs_encryption::secret_handle` | Source-owned mounted-access state/refusal report for active, rotating, revoked, quarantined, retired, missing, stale, and recovery-after-crash key evidence |
| `CryptographicEraseAssessment` | `tidefs_encryption::secret_handle` | Non-claim assessment proving key revocation/destruction alone cannot be presented as secure erase without transform metadata, stored-frame reachability, and media-remanence evidence |

## Integration chain

```text
mount authority -> committed dataset mount token
                                      |
operator -> secret handle ID -> handle record + committed token digest
                                      |
present matching committed token -----+
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
a handle record bound to a `CommittedDatasetMountToken`. The operator
activates the handle before issuing leases.

`PoolEncryptionSecretHandle::issue_lease()` first requires the presented
`CommittedDatasetMountToken` to match the handle binding. Only then does it
unseal the envelope and return a time-bounded `PoolEncryptionKeyLease`
carrying the same committed token. Leases are clamped to `MAX_LEASE_DURATION`
(1 hour). The #1823 mounted access assessment now records fail-closed states
for active, rotating, revoked, quarantined, retired, missing, stale, and
recovery-after-crash evidence before any plaintext lease is issued. Missing
token evidence, tampered commitments, wrong mount generation, foreign dataset,
incomplete recovery replay, and revoked/quarantined/retired handles refuse
lease issuance with explicit refusal reasons.

## Durable storage

The sealed key envelope remains the existing `SealedPoolKeyEnvelope` (VEKF v1,
84 bytes). `PoolEncryptionSecretHandleRecord` carries the handle identity,
lifecycle state, committed dataset mount identity, committed token digest,
SHA-256 envelope digest, and rotation lineage.

## P9-04 compliance

- Handle-not-bytes (§3.3): `SecretHandleId` is an opaque 128-bit identifier;
  the key material is sealed inside the envelope and only exposed via lease.
- Lease bounded lifetime (§5.1): `PoolEncryptionKeyLease` is time-bounded
  and zeroized on drop.
- Mount-identity gate: every lease requires the committed dataset mount token
  that minted the handle. Missing token evidence, unbound handles, tampered
  commitments, stale generations, or foreign datasets fail closed.
- Lifecycle states (§6.5): all six P9-04 states implemented.
- Handle stable across rotation: `key_generation` counter tracks rotation
  lineage.

## Current reachability

The boundary types are defined and tested. The P9-04 runtime helper
`validate_committed_dataset_mount_token_for_handle()` consumes policy-layer
committed mount evidence and defaults stores that cannot prove a binding to
fail-closed behavior. Mounted local-filesystem encryption remains blocked on
the broader transform authority work; this document is not an end-to-end
mounted encryption claim.

Issue #1823 adds the source-owned lifecycle and cryptographic-erase boundary:
key access is allowed only for active or rotating handles with current
committed mount evidence, or after crash recovery has replayed the committed
binding. Revoked, quarantined, retired, missing, stale, and replay-missing
states fail closed. The cryptographic-erase assessment can make a branch
eligible for future claim review only when the key state is revoked or retired
and the caller also proves persisted transform metadata, stored-frame
reachability, and documented media/remanence limits for fully encrypted
payloads. That assessment is still a non-claim: key revocation or destruction
alone is not secure erase, sanitization, decommissioning, or remanence proof.

## A-register impact

This implements the type-boundary portion of A17 (Security/Auth/Encryption
Design Is Split Between Strong Laws And Weak Live Boundaries):
- Advances: "Resolve mounted at-rest encryption authority" by providing the
  P9-04 handle/lease types needed for product-path wiring.
- Does not yet close: product reachability (pool create/import/mount wiring)

## Tests

Unit tests in `secret_handle::tests` cover: mint+lease roundtrip,
revoked/quarantined/retired-handle refusal, wrong wrapping key rejection, lease
duration clamping, lease consumption, handle ID hex roundtrip, uniqueness,
lifecycle transitions, active/rotating/missing/stale/recovery-after-crash
assessment output, envelope integrity digest stability, correct
committed-token success, missing token rejection, tampered commitment
rejection, wrong generation rejection, foreign dataset rejection, encryption
round-trip through the mount-token gate, key rotation across remount,
cryptographic-erase non-claim/refusal output, and mount identity
display/matching helpers.
