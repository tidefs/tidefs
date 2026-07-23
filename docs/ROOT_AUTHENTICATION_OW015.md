# Root authentication

> TFR-019 authority note: this imported implementation note is review material;
> reconcile it with current source and `docs/REVIEW_TODO_REGISTER.md`.

This document describes historical tracker item 015 for committed local
filesystem roots. A root-slot candidate is selectable only after its keyed
BLAKE3-256 record authenticates the exact superblock and transaction manifest
named by that root.

## Contract

Each new committed root carries a `VFSRATH1` root-authentication trailer with:

- record version `1`;
- algorithm suite id `1`;
- policy epoch `1`;
- BLAKE3-256 digest of the canonical superblock object;
- BLAKE3-256 digest of the transaction manifest object;
- keyed BLAKE3-256 authentication code over root slot, transaction id,
  generation, next inode id, inode count, namespace/object checksums, entry
  count, object digests, suite id, and policy epoch.

The root authentication key is an external operator secret. Production callers
either pass `RootAuthenticationKey` explicitly or set
`TIDEFS_ROOT_AUTHENTICATION_KEY_HEX` to a 64-hex-character key. Raw
authentication keys are never stored inside segment records.

## Recovery behavior

Recovery treats a missing or invalid root-authentication record as an invalid
root candidate, not as a repair request. Newer unauthenticated, wrong-key, or
digest-mismatched roots are skipped so an older authenticated committed root can
still be selected. If no authenticated committed root is selectable, mounting
reports an explicit integrity/state error.

The authenticated root record is checked before the superblock becomes live.
Manifest entries are then validated against their exact object keys, roles, and
checksums before recovered state is selected.

## Retired Pre-Release Format

The unreleased v0.390 fixed-superblock path is not imported or migrated. If its
marker is present without a selectable authenticated committed root, mount
fails closed and does not publish a replacement root. Current data must be
selected through an authenticated transaction manifest and exact versioned
Pool placement receipts.

## Source surfaces

- `ROOT_AUTHENTICATION_SPEC`
- `ROOT_AUTHENTICATION_ENV_VAR`
- `RootAuthenticationDigest`
- `RootAuthenticationCode`
- `RootAuthenticationKey`
- `RootAuthenticationRecord`
- `sign_root_commit`
- `LocalFileSystem::open_with_root_authentication_key`
- `audit_recovery_with_root_authentication_key`
- `run_crash_recovery_matrix_with_root_authentication_key`


The source tests cover:

- root authentication requires the matching external key;
- an unauthenticated newer root candidate is skipped in favor of the latest
  authenticated root;
- recovery audit summaries expose root-authentication presence, suite, policy
  epoch, digest, and authentication-code fields.

The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-root-authentication
```

The stable implementation-tracked non-release command name is
`tidefs-xtask check-root-authentication`.

## Still open

This slice does not implement a key manager, sealed-key enrollment, key
rotation, transparent re-encryption, online scrub, distributed replica
authentication, or snapshot/rollback semantics.
