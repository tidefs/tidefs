# Root authentication

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 015 for committed Local
Filesystem roots. Root-slot candidates are mountable only after a keyed BLAKE3-256 authentication
objects named by that root.

## Contract

Each new committed root carries a `VFSRATH1` root-authentication trailer with:

- record version `1`;
- algorithm suite id `1`;
- policy epoch `1`;
- BLAKE3-256 digest of the canonical superblock object;
- BLAKE3-256 digest of the transaction manifest object, or all zeroes for the
  v0.390 fixed-superblock compatibility path;
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
manifest entries are trusted.

## Compatibility

Existing v0.390 fixed-superblock stores can still be imported. The import path
rewrites the current state through the normal root-slot publication path, which
creates a v0.415 root-authentication record. Tests use an explicit fixture key;
non-test defaults require `TIDEFS_ROOT_AUTHENTICATION_KEY_HEX`.

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
