# Transform Pipeline Authority

Maturity: design authority for TFR-006, GitHub issue #712, and the
GitHub issue #1063 evidence review.

Mounted device-level compression remains blocked.
Mounted device-level encryption remains blocked.

This document is the single ordering authority for TideFS storage transforms.
It decides the order of compression, encryption, dedup fingerprinting,
checksum computation, and raw-store I/O. It does not claim that every current
runtime path already follows the decision. Runtime conformance is tracked by
the follow-up issues in "Implementation Map".

Issue #712 recorded the initial ordering decision. Issue #1063 expands this
document into the transform-authority boundary survey, authority-model
comparison, non-claim list, and follow-up implementation map.

## Scope

This authority covers mounted content payloads and lower object-store payloads
that may be compressed, encrypted, deduplicated, checksummed, and written to
the raw local object store.

It does not make metadata/raw-only paths into mounted content transforms.
Committed-root slots, sealed key records, allocator counters, placement
receipts, and other storage metadata may use explicit raw-only authorities,
but those authorities must not be cited as proof of mounted file-content
compression or encryption.

## Surveyed Surfaces

Issue #1063 surveyed the following current surfaces before choosing the
authority boundary:

| Surface | Evidence found | Authority role |
|---|---|---|
| `crates/tidefs-compression/src/lib.rs` | Describes itself as the compression helper/library tier. Mounted writes currently resolve `ContentCompressionPolicy` and call `encode_content_chunk()` in the local-filesystem content path. | Compression primitive and policy-report helper, not canonical transform dispatch. |
| `crates/tidefs-compression/src/lib.rs` | Source-owned compression helper/library tier. | Primitive and policy-report helper, not canonical transform dispatch. |
| `crates/tidefs-encryption/src/lib.rs` and `crates/tidefs-encryption/src/secret_handle.rs` | Provide frame/key helpers and secret-handle helpers, while warning that lower object-store encryption is not an end-to-end mounted filesystem proof. | Encryption primitive and key-handle helper, not canonical dispatch. |
| `docs/security/pool-encryption-secret-handle-boundary.md` | Defines the secret-handle/key-lease boundary for pool encryption access. | Key access policy boundary; not ciphertext ordering authority. |
| `crates/tidefs-checksum-tree/src/lib.rs` | Provides BLAKE3 checksum trees, domain tags, `ChecksumTreeBuilder`, `ChecksumTreeVerifier`, and locator-bound verification helpers. | Checksum evidence primitive consumed by the pipeline. |
| `crates/tidefs-verification-engine/src/lib.rs` and `crates/tidefs-verification-engine/src/object_verify.rs` | Provide `VerificationPlan`, object verification, batch verification, transfer receipts, and quorum/reporting helpers. | Verification consumer/projection of stored-frame evidence, not transform dispatch. |
| `docs/BLAKE3_USAGE_POLICY.md` | Current BLAKE3 placement and review policy. | Digest-placement policy only, not proof that all runtime paths comply. |
| `crates/tidefs-local-object-store/src/pool/mod.rs` | `Pool`, `PoolStore`, and `PoolStoreMut` route normal pool I/O; `raw_primary_store()` and `raw_primary_store_mut()` are explicit raw-store escape hatches; encrypted pools fail closed when locked; `open_single_device()` currently wraps an encrypted inner device with an outer compressed device, so write flow compresses before encryption. | Chosen canonical dispatch boundary. |
| `crates/tidefs-local-object-store/src/device.rs` | `DeviceConfig` accepts optional compression and encryption; `CompressedDevice` and `EncryptedDevice` are transparent wrappers; `Device::is_encrypted()` recurses through compression wrappers. | Lower wrapper implementation surface; cannot be the sole authority because wrapper nesting hides policy and raw-store visibility. |
| `crates/tidefs-local-object-store/src/lib.rs` and `crates/tidefs-local-object-store/src/integrity.rs` | `LocalObjectStore` persists payload bytes with `IntegrityTrailerV2`; durable options can verify read checksums; `ChecksumProof` and `verify_object_read()` verify object data against checksum evidence. | Raw object persistence and stored-byte integrity surface. |
| `crates/tidefs-intent-log/README.md` and `crates/tidefs-intent-log/src/frame.rs` | Intent-log frames are BLAKE3-authenticated over encoded records, txg id, and record sequence. Kernel and user-space readers/writers verify real frames. | Metadata/raw-only transaction log authority; not mounted file-content transform dispatch. |
| `crates/tidefs-secret-key-policy-runtime/src/lib.rs` | Owns `SealProvider`, `HandleStore`, mount identity gates, activation, leases, rotation, revocation, and manifests. | Secret policy and lease authority; supplies/validates key handles but does not order compression, encryption, checksum, or raw writes. |
| `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md` | Defines the guardrail vocabulary `plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes`, classifies raw-store paths, and keeps mounted device-level transforms blocked while production raw-store bypass rows remain. | Current mounted guardrail and raw-store visibility inventory. |
| `crates/tidefs-dedup/src/lib.rs` and mounted content paths | Model plaintext dedup identity separately from reclaim identity; mounted content currently fingerprints plaintext before encoded writes. | Plaintext identity planning input before transforms, not a post-encryption or post-checksum stage. |

## Authority Model Comparison

| Model | Advantages | Problems | Decision |
|---|---|---|---|
| Device-wrapper plugin model: compression/encryption live only as `Device` wrappers below the object store. | Matches existing `CompressedDevice` and `EncryptedDevice` code; can be applied to lower pool devices without changing callers. | Ordering is implicit in wrapper nesting; checksums, key leases, placement receipts, and raw-store bypass visibility remain split; mounted callers can mistake helper wrappers for an end-to-end transform claim. | Rejected as the sole authority. Device wrappers remain implementation details used by the chosen dispatcher. |
| Standalone lower-pool transform stage: a named dispatcher under `crates/tidefs-local-object-store/src/pool/` owns ordered write/read execution. | Gives one entrypoint for `PoolStore` and `PoolStoreMut`; makes compression before encryption and checksum-over-stored-frame explicit; can label metadata/raw-only bypasses; can persist transform metadata with locators, trailers, or receipts. | Requires #779 and follow-up consumers to stop treating raw-store access as normal mounted content I/O. | Chosen boundary. |
| Mounted local-filesystem content transform authority: mounted content code owns compression/encryption/checksum ordering before calling the pool. | Sees plaintext content identity and current mounted compression policy directly. | Duplicates lower object-store authority, cannot fully own raw-store persistence, key leases, placement receipts, recovery, receive, reclaim, or degraded reads. | Projection/consumer only. Mounted content may choose policies and plaintext identity, then must enter the lower-pool dispatcher for storage transforms. |
| Verification-only authority: checksum-tree or verification-engine APIs define the boundary after writes. | Clear audit and receipt language; useful for scrub, transfer, and object verification. | Does not decide how bytes are transformed before they are stored and cannot prevent raw-store writes from bypassing transform order. | Consumer only. Verification checks evidence emitted by the storage authority. |

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
through `PoolStore` and `PoolStoreMut`. Those are the canonical storage
transform entrypoints for transformed payloads.

The helper crates remain helpers:

- `tidefs-compression` provides compression frame primitives and policy
  reports.
- `tidefs-encryption` provides encryption frame primitives and key handling.
- `tidefs-dedup` models plaintext dedup identity and reclaim consequences.
- `tidefs-checksum-tree` provides checksum tree and locator-binding
  primitives.
- `tidefs-verification-engine` consumes stored-frame evidence for object,
  batch, transfer, and quorum verification.
- `tidefs-secret-key-policy-runtime` owns secret policy, handle, lease,
  activation, rotation, and revocation state.
- `LocalObjectStore` stores and verifies raw media bytes.

Those helper crates do not own the mounted storage ordering contract by
themselves. Callers that need raw metadata access must use an explicit
metadata/raw-only authority, not an implicit `raw_primary_store()` bypass.
Intent-log records, sealed key records, allocator counters, and placement
receipts are examples of explicit raw-only or metadata authorities; they do
not prove mounted content transform support.

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

Transform metadata is part of the stored-frame authority. Runtime
implementations must persist enough typed metadata with the frame, object
locator, integrity trailer, or placement receipt to replay the reverse
pipeline: compression algorithm or explicit identity decision, encryption mode
or explicit plaintext decision, key-handle/lease epoch when encryption applies,
nonce/authentication material as required by the encryption frame, checksum
domain/root for the exact stored bytes, and the object key or locator covered
by the receipt. The document does not mandate one binary layout for that
metadata; it mandates that the metadata cross the same authority boundary as
the stored frame and cannot live only in caller-local state.

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
- `docs/BLAKE3_USAGE_POLICY.md` records the BLAKE3 placement and review
  boundary consumed by transform framing.
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

This is the follow-up map for issue #1063. The issue #1063 slice is
documentation-only and edits this file plus the TFR-006 register note. Runtime
changes belong to the non-overlapping follow-up rows below.

| Non-conforming surface | Follow-up owner | Expected write set |
|---|---|---|
| Lower pool transform dispatch is not yet one named authority. | #779 | `crates/tidefs-local-object-store/src/pool/mod.rs`, a new pool transform module, `crates/tidefs-local-object-store/src/device.rs`, and narrow helper-crate adapters if needed. |
| Transform metadata persistence needs one typed handoff from frame metadata to locator, integrity trailer, or placement receipt evidence. | #779 | Same lower-pool transform module, local-object-store receipt/trailer adapters, and narrow helper-crate adapters needed by that dispatcher. |
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

## Explicit Non-claims

This document records a boundary; it does not enable a product feature by
itself. In particular, it does not claim:

- end-to-end mounted local-filesystem device-level compression or encryption;
- offline re-key, re-compression, or transform-policy changes without rewriting
  the affected stored frames through the pipeline;
- compatibility migration for unreleased transform formats or wrapper layouts;
- OpenZFS-class, Ceph-class, or comparator-level transform, checksum,
  encryption, durability, or performance behavior;
- that `raw_primary_store()` or `raw_primary_store_mut()` are safe production
  mounted-content transform paths;
- that the secret-key policy runtime owns ciphertext dispatch or can replace
  the lower-pool transform dispatcher;
- that checksum evidence may cover plaintext while raw media stores ciphertext
  or compressed bytes;
- that verification-engine receipts decide transform order after a raw write
  has already bypassed the dispatcher.

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
- GitHub issue #1063: transform-authority boundary survey and follow-up map.
- GitHub issue #779: lower storage transform pipeline dispatcher.
- GitHub issue #218: mounted raw-store bypass inventory.
- OpenZFS `zio.c`: https://github.com/openzfs/zfs/blob/master/module/zfs/zio.c
- OpenZFS `zio.h`: https://github.com/openzfs/zfs/blob/master/include/sys/zio.h
- Ceph `ObjectStore.h`: https://github.com/ceph/ceph/blob/main/src/os/ObjectStore.h
- Ceph `Transaction.h`: https://github.com/ceph/ceph/blob/main/src/os/Transaction.h
