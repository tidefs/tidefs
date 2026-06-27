# BLAKE3 Usage Policy

Maturity: **current policy** — binding for BLAKE3 placement and review. Current
implementation status remains governed by live source behavior,
`validation/claims.toml`, and the claims gate.

This document defines where BLAKE3-256 cryptographic hashing belongs in the
TideFS codebase and where simpler integrity mechanisms must be used instead.
It is not a production-readiness, end-to-end checksum, scrub self-heal,
erasure-coded repair, or tamper-proof committed-root claim.

Authority classification: TFR-019 / GitHub issue #332 promoted this file as
current policy after checking live source and the claim registry. The current
tree contains implemented BLAKE3 pieces such as binary-schema checksum profiles,
local-object-store `IntegrityTrailerV2` digests, segment-chain verification
helpers, read-only scrub reporting, and root-authentication helpers. The claim
registry does not yet validate the broader production behavior described by the
historical G3 checksum architecture docs.

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

BLAKE3-256 is the required choice when TideFS implements or reviews these
contexts. The lists below name current and planned surfaces for review; they do
not prove every listed path has production-ready mounted behavior today.

### 2.1 Content Addressing

The object store uses BLAKE3-256 to derive storage keys from content. Two
identical payloads must produce the same key. This requires cryptographic
collision resistance.

Relevant surfaces: `tidefs-local-object-store`, `tidefs-send-stream`,
`tidefs-receive-stream`.

### 2.2 Durable Integrity Trailers

Durable record formats that carry production integrity trailers use BLAKE3-256
payload and record digests. The current local object-store implementation
includes `IntegrityTrailerV2`; this policy does not by itself claim that every
metadata and data path has mounted, production-validated read verification.

Relevant surfaces: `tidefs-local-object-store`, `tidefs-local-filesystem`,
`tidefs-inode-table`, `tidefs-extent-map`, `tidefs-intent-log`,
`tidefs-dataset-catalog`, `tidefs-space-accounting`.

### 2.3 Committed-Root and Superblock Tamper Detection

Committed-root and superblock designs that authenticate root state use keyed
BLAKE3-256 digests. Current docs and code must not turn that design rule into a
tamper-proof committed-root or crash-consistency product claim without matching
claim-registry evidence.

Relevant surfaces: `tidefs-local-filesystem`, `tidefs-pool-scan`.

### 2.4 Scrub Integrity Verification

Scrub and verification paths use stored integrity data to report mismatches.
Where a scrub path verifies BLAKE3-256 production-integrity trailers, it must use
the same domain-separated digest rules as the write/read path. This is not a
scrub self-heal or repair guarantee.

Relevant surfaces: `apps/tidefs-scrub`, `tidefs-scrub-core`,
`tidefs-compaction`.

### 2.5 Erasure-Coded Shard Verification

When erasure-coded shard storage is implemented, shards must carry BLAKE3-256
integrity envelopes binding the object key, stripe index, shard index, and
payload. This is a design requirement for EC work, not a current production EC
integrity claim.

Relevant surfaces: `tidefs-erasure-coded-store`.

### 2.6 Transport Session Boundary Key Derivation and MAC

BLAKE3 may be used at the transport/session boundary for session key derivation
or a MAC only when that is the single configured session-authentication
primitive for a raw carrier. If TLS, AEAD, HMAC, or another session envelope is
already providing node-to-node authenticity and integrity, do not stack a
second message-local BLAKE3 layer.

Relevant surfaces: `tidefs-transport` (`session/handshake.rs`, `reconnect.rs`,
and any explicit transport-security consolidation work around
`message_auth.rs`).

### 2.7 Commit/Compaction/Rebuild Verification

When compaction rewrites object segments or rebuild reconstructs data from
erasure-coded shards, the implementation must verify rewritten or reconstructed
data against the relevant BLAKE3 digest before publishing it. This policy does
not claim that compaction or rebuild has production repair evidence today.

Relevant surfaces: `tidefs-compaction`, `tidefs-rebuild`.


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

**Fix**: Remove the duplicate BLAKE3 hash. The chosen transport/session
integrity envelope covers the payload. For compression frames, CRC32C on the
compressed payload is sufficient to detect framing errors before decompression.

### 3.5 Namespace In-Memory Hashing

Namespace entry hashing for in-memory lookup structures is a performance
optimization, not a durability guarantee. Use a non-cryptographic hash.

Affected code:
- `crates/tidefs-namespace/src/entry.rs` — `blake3::Hasher::new()` without
  domain separation

**Fix**: Replace with `rustc-hash` or `ahash`. If the entries are later
persisted through the local filesystem's BLAKE3-verified records, the storage
layer provides integrity.

## 4. Enforcement

New uses of `blake3::` outside the crates listed in SS2 must be justified in
the commit message and reviewed against this policy. Existing overfitted uses
(listed in SS3) must be refactored when the owning subsystem is next touched,
or via the specific refactor issues filed against this policy.

Changes to this policy require a PR that cites the specific design argument
for expanding or restricting BLAKE3 usage.
