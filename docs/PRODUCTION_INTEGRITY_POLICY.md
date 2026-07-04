# Production integrity policy

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source and
> `docs/REVIEW_TODO_REGISTER.md`.

Historical tracker wording: item 006.

This document describes the historical production-integrity design-contract
level. It replaces the development checksum/key policy with a production
integrity target and names the migration boundary for the data path. For the
Local Object Store record layer, new records are version `3` and carry
BLAKE3-256 production-integrity trailers. Committed-root authentication is
covered by the root-authentication note.

## Chosen algorithms

The production integrity target is:

| Surface | Algorithm |
|---|---|
| Object payload digest | `BLAKE3-256` |
| Record/header digest | `BLAKE3-256` |
| Manifest digest | `BLAKE3-256` |
| Root authentication | keyed `BLAKE3-256` root authentication code |
| Object-name derivation | `BLAKE3 derive_key` with TideFS integrity domains |

The source constants are:

```text
PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM
PRODUCTION_INTEGRITY_RECORD_DIGEST_ALGORITHM
PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM
PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM
PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION
```

The implementation-tracked non-release topic names are chosen algorithms, domain separation,
collision policy, authenticated root, migration plan, compatibility boundary,

## Domain separation

Every production digest input must be framed before hashing. The frame includes:

- TideFS integrity domain;
- format version;
- object family;
- record role;
- payload length;
- canonical bytes for the exact object being authenticated.

The production policy does not reuse one raw hash namespace for object names,
payloads, manifests, record headers, and root authentication. Cross-domain hash
matches have no meaning.

## Collision policy

A digest or derived-key collision inside one domain is an explicit
integrity/media error.

Replay, mount, and retention logic must not:

- choose an arbitrary winner;
- merge two colliding records;
- rename or repair namespace truth;
- continue as if the collision were a normal overwrite.

Collision handling follows the existing no-production-fsck design rule: previous
committed root, new committed root, or explicit integrity/media error.

## Authenticated root

A committed filesystem root is mountable only when its authenticated root record
covers:

- root slot;
- generation;
- transaction id;
- manifest digest;
- superblock digest;
- policy epoch;
- record format version;
- integrity algorithm suite id.

The root authentication key is an external operator secret or sealed local key.
Raw authentication keys are never stored inside segment records. A missing,
wrong, or unavailable root authentication key makes the root unmountable as

## Migration plan

Production integrity starts at record version 3. The object-store record layer
now writes v3 records with BLAKE3-256 payload and record digests.

The migration plan is:

1. Keep record versions 1 and 2 as v1/v2 compatibility inputs.
2. Add record version 3 with 32-byte production digest fields.
3. Open existing v1/v2 stores only in compatibility or upgrade mode.
4. Compute v3 object, manifest, and root authentication records from verified
   existing committed roots.
5. Publish the v3 root through the normal root-slot protocol.
6. Retain older committed roots until retention policy says they are no longer
   required.
7. Never rewrite v1/v2 records in place as part of migration.

The current writer emits v3 object-store records and root-slot commits with
`VFSRATH1` keyed BLAKE3-256 root-authentication records. v1/v2 replay remains



- `production_integrity_policy_covers_open_work_006_acceptance_gate`;
- `new_records_use_v3_production_integrity_trailer`;
- `production_integrity_trailer_mismatch_rejects_replay`;
- `root_authentication_requires_the_matching_external_key`;
- `unauthenticated_newer_root_candidate_is_skipped`;
- `tidefs-xtask check-production-integrity`;
- `tidefs-xtask check-production-integrity-v3`;
- `tidefs-xtask check-root-authentication`;
- store-demo output for `production_integrity.*` policy fields.

`tidefs-xtask check-production-integrity-v3`, and
`tidefs-xtask check-root-authentication`.

## Non-goals

This policy does not implement:

- online scrub or self-healing;
- key manager integration;
- transparent re-encryption;
- distributed replica authentication;
- FUSE or kernel mount behavior.

Those remain separate implementation work after the production integrity policy
is fixed.
