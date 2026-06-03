# BLAKE3 Usage Policy

Maturity: **design-policy** — binding on all current and future TideFS code.

This document defines where BLAKE3-256 cryptographic hashing belongs in the
TideFS codebase and where simpler integrity mechanisms must be used instead.

## 1. Design Principle

BLAKE3-256 is TideFS's canonical content-addressable hash and durable-integrity
digest. It is **not** the project's general-purpose hash function. The existing
checksum law (`docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`)
already defines two integrity classes:

- **CRC32C** — fast corruption detection for record framing, self-consistency
- **BLAKE3-256** — strong identity / transfer digest for content addressing and
  durable tamper detection

These are not substitutes for each other. Applying BLAKE3 where CRC32C or a
generation counter suffices wastes CPU on hot paths and dilutes the design
rationale without adding security value.

## 2. Where BLAKE3 Belongs

BLAKE3-256 is mandatory in these contexts:

### 2.1 Content Addressing

The object store uses BLAKE3-256 to derive storage keys from content. Two
identical payloads must produce the same key. This requires cryptographic
collision resistance.

Crates: `tidefs-local-object-store`, `tidefs-send-stream`, `tidefs-receive-stream`

### 2.2 Durable Integrity Trailers

Every on-disk record that persists across mounts, reboots, or host failures
carries a BLAKE3-256 payload digest in its integrity trailer. This is the
end-to-end guarantee that silent corruption will be detected on read.

Crates: `tidefs-local-object-store`, `tidefs-local-filesystem`,
`tidefs-inode-table`, `tidefs-extent-map`, `tidefs-intent-log`,
`tidefs-dataset-catalog`, `tidefs-space-accounting`

### 2.3 Committed-Root and Superblock Tamper Detection

The committed-root anchor and superblock carry keyed BLAKE3-256 digests to
detect tampering and provide crash-consistency guarantees across unclean
shutdown.

Crates: `tidefs-local-filesystem`, `tidefs-pool-scan`

### 2.4 Scrub Integrity Verification

The background scrub engine uses BLAKE3-256 to verify on-disk object integrity
against stored digests. This is the same end-to-end guarantee as SS2.2, applied
asynchronously.

Crates: `tidefs-scrub-core`, `tidefs-compaction`

### 2.5 Erasure-Coded Shard Verification

Erasure-coded shards carry BLAKE3-256 integrity envelopes binding the object
key, stripe index, shard index, and payload. Shards must be verified before
decode to prevent corrupt shards from contaminating reconstruction.

Crates: `tidefs-erasure-coded-store`

### 2.6 Transport Session Boundary Key Derivation and MAC

BLAKE3 may be used at the transport/session boundary for session key derivation
or a MAC only when that is the single configured session-authentication
primitive for a raw carrier. If TLS, AEAD, HMAC, or another session envelope is
already providing node-to-node authenticity and integrity, do not stack a
second message-local BLAKE3 layer.

Crates: `tidefs-transport` (`session/handshake.rs`, `reconnect.rs`, and any
explicit transport-security consolidation work around `message_auth.rs`)

### 2.7 Commit/Compaction/Rebuild Verification

When compaction rewrites object segments, it verifies rewritten data against
the original BLAKE3 digest. When rebuild reconstructs data from erasure-coded
shards, it verifies the result. These are the same content-addressing guarantee.

Crates: `tidefs-compaction`, `tidefs-rebuild`


### 2.8 Transport Epoch Bridge State Integrity

The transport epoch event bridge (`tidefs-transport/src/epoch_bridge.rs`)
maintains a BLAKE3-256 domain-separated digest covering the last-applied
epoch number, roster hash, and subscriber count (domain:
`tidefs-transport-epoch-bridge-v1`). This digest provides deterministic
subscribers with a specific roster. It is not a hot-path hash; it is
recomputed once per epoch transition.
## 3. Where BLAKE3 Does Not Belong

BLAKE3 must **not** be used in these contexts. Simpler mechanisms are correct
and cheaper.

### 3.1 Ephemeral Protocol Messages

Protocol messages that exist only on the wire and are already protected by the
transport layer's integrity and authentication do not need their own BLAKE3
digest. The transport provides integrity; adding another hash inside the
message is redundant.

Affected code:
- `tidefs-membership-live/src/types.rs` — `AckData`, `IndirectPingReq`,
  `IndirectPingResp` with domain-separated BLAKE3 digests
- `tidefs-node-drain/src/drain_state.rs` — `DrainRequest::blake3_digest` field
- `tidefs-tdma-scheduler/src/slot_grant.rs` — domain-separated BLAKE3 token
- `tidefs-membership-live/src/gossip_batcher.rs` — BLAKE3 for batch hashing

**Fix**: Remove the BLAKE3 digest from the message struct. If a protocol needs
integrity, the transport layer's message_auth provides it. If a protocol needs
a cheap integrity check for internal use, CRC32C suffices.

### 3.2 Hot I/O Paths Where Storage Already Hashes

Functions on the FUSE/ublk I/O hot path must not hash data with BLAKE3 when
the storage layer already computes and verifies the same digest on
commit/read. Doing it twice wastes CPU in the daemon's hottest loop.

Affected code:
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` —
  `blake3::hash(&data[..written])` in dispatch_write
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_write.rs` —
  `use blake3::Hasher`

**Fix**: Remove the BLAKE3 hash from the write path. The intent log and object
store already compute and verify BLAKE3 digests at persist time. If the write
path needs an intent-log record identifier, use a monotonic sequence number or
the object store key returned after commit.

### 3.3 Non-Durable Bookkeeping

Statistics, capacity snapshots, and in-memory bookkeeping that does not persist
across restarts must not carry BLAKE3 digests. A monotonic generation counter
provides the same stale-reader detection without cryptographic cost.

Former affected code:
- The consolidated POSIX capacity shard previously contained
  `CapacitySnapshot::content_hash` and `CapacityRefreshState::Committing`
  ("computing BLAKE3 hash"). That standalone shard is no longer present in the
  active workspace.

**Fix**: Do not reintroduce content hashes into capacity snapshots when
capacity/statfs handling is wired through the active adapter runtime. A
generation field provides monotonic detection of stale snapshots. Neither the
kernel's statfs interface nor the FUSE statfs handler needs cryptographic
collision resistance on capacity numbers.

### 3.4 Duplicate Integrity Layers in Transport

When the transport/session envelope already provides integrity and
authenticity, individual transport operations must not add a second BLAKE3
digest over the same payload. The selected session envelope can be TLS, AEAD,
HMAC, or a single consolidated MAC; the point is that operation-local BLAKE3
does not become a substitute security model.

Affected code:
- `tidefs-transport/src/envelope.rs` — `blake3::hash(&payload)` on envelope
- `tidefs-transport/src/segment_fetch.rs` — `blake3::hash(&combined)` on
  segment fetch
- `tidefs-transport/src/connection_pool.rs` — BLAKE3 for connection pool state
- `tidefs-transport/src/epoch_barrier.rs` — BLAKE3 for epoch barriers
- `tidefs-transport/src/message_dispatch.rs` — BLAKE3 for message type and
  envelope dispatch
- `tidefs-transport/src/compression.rs` — BLAKE3 for compressed frames

**Fix**: Remove the duplicate BLAKE3 hash. The transport MAC already covers the
payload. For compression frames, CRC32C on the compressed payload is sufficient
to detect framing errors before decompression.

### 3.5 Namespace In-Memory Hashing

Namespace entry hashing for in-memory lookup structures is a performance
optimization, not a durability guarantee. Use a non-cryptographic hash.

Affected code:
- `crates/tidefs-namespace/src/entry.rs` — `blake3::Hasher::new()` without
  domain separation

**Fix**: Replace with `fxhash` or `ahash`. If the entries are later persisted
through the local filesystem's BLAKE3-verified records, the storage layer
provides integrity.

## 4. Enforcement

New uses of `blake3::` outside the crates listed in SS2 must be justified in
the commit message and reviewed against this policy. Existing overfitted uses
(listed in SS3) must be refactored when the owning subsystem is next touched,
or via the specific refactor issues filed against this policy.

Changes to this policy require a PR that cites the specific design argument
for expanding or restricting BLAKE3 usage.
