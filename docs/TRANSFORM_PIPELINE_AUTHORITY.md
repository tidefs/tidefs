# Transform Pipeline Authority

Maturity: design authority for TFR-006 and GitHub issue #712.

Mounted device-level compression remains blocked.
Mounted device-level encryption remains blocked.

This document is the single ordering authority for TideFS storage transforms.
It decides the order of compression, encryption, dedup fingerprinting,
checksum computation, and raw-store I/O. It does not claim that every current
runtime path already follows the decision. Runtime conformance is tracked by
the follow-up issues in "Implementation Map".

## Scope

This authority covers mounted content payloads and lower object-store payloads
that may be compressed, encrypted, deduplicated, checksummed, and written to
the raw local object store.

It does not make metadata/raw-only paths into mounted content transforms.
Committed-root slots, sealed key records, allocator counters, placement
receipts, and other storage metadata may use explicit raw-only authorities,
but those authorities must not be cited as proof of mounted file-content
compression or encryption.

## Decision

The mandatory write pipeline is:

```text
plaintext identity
  -> dedup fingerprint and planning
  -> compression decision/frame
  -> encryption decision/frame
  -> checksum over the stored frame
  -> raw-store I/O and placement receipt
```

The mandatory read pipeline is the reverse:

```text
raw-store read
  -> checksum verification of the stored frame
  -> decryption when an encryption frame is present
  -> decompression when a compression frame is present
  -> plaintext identity returned to the mounted caller
```

The shorter guardrail vocabulary remains valid:

```text
plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes
```

Dedup fingerprinting is a pre-transform planning step over plaintext identity.
It is not an in-transform stage after compression or encryption, and it is not
a deferred post-write reconciliation step for the foreground mounted write
path. A future background dedup scanner may propose rewrites, but any rewrite
must re-enter this pipeline as a new transaction and must not mutate raw media
bytes in place.

## Authority Owner

The pipeline dispatch owner is the lower pool I/O authority in
`crates/tidefs-local-object-store/src/pool/`.

The intended implementation owner is a named local-object-store module such as
`crates/tidefs-local-object-store/src/pool/transform_pipeline.rs`, surfaced
through `PoolStore` and `PoolStoreMut`. The helper crates remain helpers:

- `tidefs-compression` provides compression frame primitives and policy
  reports.
- `tidefs-encryption` provides encryption frame primitives and key handling.
- `tidefs-dedup` models plaintext dedup identity and reclaim consequences.
- `LocalObjectStore` stores and verifies raw media bytes.

Those helper crates do not own the mounted storage ordering contract by
themselves. Callers that need raw metadata access must use an explicit
metadata/raw-only authority, not an implicit `raw_primary_store()` bypass.

## Representations

Each stage sees exactly one representation:

| Stage | Input representation | Output representation |
|---|---|---|
| Dedup planning | Plaintext content identity | A write-new, redirect-to-canonical, or bypass decision |
| Compression | Plaintext payload chosen by the dedup plan | Compression frame, including an explicit uncompressed identity frame |
| Encryption | Compression frame | Encryption frame, or explicit plaintext/no-encryption frame |
| Checksum | Exact bytes that will be stored in raw media | Checksum evidence for those stored bytes |
| Raw-store I/O | Checksum-covered stored frame | Durable object location and placement receipt |

Checksums cover the exact stored frame. With encryption enabled, that is the
encryption frame. With encryption disabled, that is the compression frame or
explicit uncompressed frame. A mounted content checksum must not silently
switch to uncompressed plaintext while raw media stores encrypted or compressed
bytes.

Reclaim identity is not plaintext identity. Reclaim consumes the committed
object key, locator, placement receipt, or replacement receipt that authorizes
which physical storage can be retired.

Dedup redirects are transform payloads too. A redirect may select a canonical
object, but the redirect record itself must still be protected by whatever
checksum/encryption policy applies to that object class. Resolving a redirect
selects the canonical object; reading the canonical object then follows the
same reverse pipeline.

## Fallback And Skip Policy

Compression skip is allowed only as an explicit compression decision:

- compression disabled by policy;
- payload below the configured threshold;
- attempted compression fails or does not meet the minimum savings rule;
- policy validation fails and the caller falls back to the configured
  uncompressed identity mode.

All four cases produce an explicit uncompressed/identity compression frame or
equivalent typed decision. They do not bypass checksum, encryption, placement,
or receipt handling.

Encryption skip is allowed only when the effective encryption policy is
explicitly plaintext/no-encryption. If policy requires encryption and the key
is absent, locked, malformed, or unavailable, writes and reads fail closed.
Key-administration records may be metadata/raw-only records, but they do not
enable mounted content encryption claims.

Dedup bypass is allowed when dedup is disabled, the content class is not
dedup-eligible, a canonical object is missing or stale, a fingerprint collision
or verification failure is detected, receipt evidence is insufficient, or
policy selects write-new for isolation. The fallback is to write the payload as
a new object through the same compression/encryption/checksum/raw I/O pipeline.

Checksum skip is not a mounted product fallback. A raw-only metadata authority
may define its own integrity mechanism, but transformed mounted payloads need
stored-frame checksum evidence before mounted device transforms can be claimed.

## Current Evidence Review

The current tree already points in this direction but does not yet centralize
the authority:

- `docs/REVIEW_TODO_REGISTER.md` TFR-006 records that mounted-content
  compression, object-store device compression/encryption, helper crates,
  dedup, and raw-store bypasses still need one transform authority.
- `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md` defines the
  guardrail vocabulary and keeps mounted compression/encryption blocked while
  production raw-store rows remain.
- `docs/ARCHITECTURE.md` lists `tidefs-compression`, `tidefs-encryption`, and
  `tidefs-dedup` as separate product-layer crates rather than one dispatch
  owner.
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md` is historical input showing checksum
  framing concerns are interdependent with transform framing.
- `crates/tidefs-local-filesystem/src/content.rs` currently computes dedup
  fingerprints over plaintext chunks before `encode_content_chunk()`, then
  writes encoded chunk objects with `PoolStoreMut::put_with_receipt()`.
- `crates/tidefs-local-filesystem/src/encoding.rs` currently makes compression
  an explicit content-chunk encoding decision and stores incompressible data as
  uncompressed chunk payload.
- `crates/tidefs-local-object-store/src/device.rs` has transparent compressed
  and encrypted device wrappers, and `Device::is_encrypted()` recurses through
  the compression wrapper.
- `crates/tidefs-local-object-store/src/store.rs` computes and verifies
  per-object checksums over payload bytes at the local object-store layer.
- `crates/tidefs-dedup/src/lib.rs` already names plaintext identity as dedup
  identity and separates reclaim identity from plaintext hash identity.

Prior art supports the shape but does not define TideFS policy:

- OpenZFS uses a central ZIO pipeline with transform stages and transform
  buffers; TideFS adopts the central pipeline lesson, while keeping its own
  BLAKE3, receipt, and object-store model.
- Ceph `ObjectStore::Transaction` treats object mutations as sequenced,
  all-or-nothing transaction input to the object store; TideFS adopts the
  lesson that transformed bytes and placement evidence should cross one
  storage authority boundary rather than several hidden wrappers.

These prior-art references are not comparator evidence and do not authorize
OpenZFS/Ceph successor, performance, durability, transform, compression, or
encryption claims. Any product-facing comparison must route through #875 claim
ids and #928/#930 comparator evidence.

## Implementation Map

| Non-conforming surface | Follow-up owner | Expected write set |
|---|---|---|
| Lower pool transform dispatch is not yet one named authority. | #779 | `crates/tidefs-local-object-store/src/pool/mod.rs`, a new pool transform module, `crates/tidefs-local-object-store/src/device.rs`, and narrow helper-crate adapters if needed. |
| Mounted content scrub/read needs plaintext identity with checksum and receipt evidence. | #650 | `crates/tidefs-local-filesystem/src/content.rs` and focused local-filesystem helper/tests. |
| Local scrub still needs to consume the mounted content identity authority. | #651 | `crates/tidefs-local-filesystem/src/scrub.rs` and focused scrub tests. |
| Repair dispatch must require transform-aware scrub evidence before writeback. | #652 | `crates/tidefs-local-filesystem/src/scrub_repair_integration.rs`, `crates/tidefs-local-filesystem/src/repair.rs`, and scrub-core evidence types only if needed. |
| Crash-matrix raw staging must be isolated as validation-only. | #692 | `crates/tidefs-local-filesystem/src/crash_recovery.rs`, the mounted raw-store inventory, and TFR-006 register notes. |
| Placement, degraded read, scrub, repair, and rebuild consumers must use receipt authority rather than raw topology scans. | #18 and #675 | Receipt/locator/rebuild models plus the local-filesystem, scrub, and rebuild consumers named by those issues. |
| Distributed primary writes must not create a second placement authority beside local receipts. | #674 | `apps/tidefs-storage-node/src/`, `crates/tidefs-replicated-object-store/`, and `crates/tidefs-transport/`. |
| Reclaim and rebake must consume replacement/base receipt evidence before trimming physical storage. | #605 and #676 | `crates/tidefs-reclaim/`, `crates/tidefs-reclaim-queue-core/`, and local-object-store reclaim/replay surfaces. |
| Durable receive must validate receive contracts before persisting or promoting received objects. | #566 and PR #623 | `crates/tidefs-receive-stream/`, local receive integration, and two-node receive harness paths named there. |
| Scrub block identity needs a documentation-only data_version boundary. | #742 | `docs/SCRUB_IDENTITY_AUTHORITY.md` and narrow TFR-005 cross-references. |

If later source inspection finds a production raw-store path not covered by
the rows above, create or update a focused issue with a non-overlapping
expected write set before editing that path.

## Claim Boundary

This authority document is non-enabling. Mounted local-filesystem device-level
compression and encryption remain blocked until:

1. #779 provides the lower transform dispatcher.
2. The raw-store inventory has no production `blocked` mounted rows.
3. Every mounted content, repair, receipt, send/receive, reclaim, and recovery
   consumer either routes through the pipeline or is explicitly raw-only.
4. Validation evidence covers the transformed write/read/recovery rows that
   the product claim names.

Until those conditions are true, TideFS may describe the lower helper crates
and object-store wrappers, but it must not claim end-to-end mounted
device-level compression or encryption.

## References

- GitHub issue #712: transform ordering decision authority.
- GitHub issue #779: lower storage transform pipeline dispatcher.
- OpenZFS `zio.c`: https://github.com/openzfs/zfs/blob/master/module/zfs/zio.c
- OpenZFS `zio.h`: https://github.com/openzfs/zfs/blob/master/include/sys/zio.h
- Ceph `ObjectStore.h`: https://github.com/ceph/ceph/blob/main/src/os/ObjectStore.h
- Ceph `Transaction.h`: https://github.com/ceph/ceph/blob/main/src/os/Transaction.h
