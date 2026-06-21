# Receive cross-pool authorization

This document decides the authorization model for receive streams that carry
distributed sender-pool claims. It is the design artifact for issue #705.

**Status**: decided / not yet implemented.

**Last updated**: 2026-06-20.

**Authority dependency**: issue #705 cites
`docs/RECEIVE_STREAM_MERGE_POLICY.md` section 5 as design authority. That
document landed on `master` in PR #762 as commit `57c53360`; this document
depends on that merged policy.

**Authority inputs reviewed**:

- `docs/RECEIVE_STREAM_MERGE_POLICY.md` section 5, which records the
  distributed-replication non-claim and the fail-closed rule for future
  distributed fields.
- `docs/SEND_RECEIVE_OW109.md`, especially the local-only receive contract and
  still-open distributed replication, transport authorization, placement
  receipt, and conflict-resolution items.
- `docs/REVIEW_TODO_REGISTER.md` TFR-017, which keeps transport and cluster
  authority open until membership, dispatch, comparison, and recovery behavior
  are one product-grade contract.
- `crates/tidefs-local-filesystem/src/encoding.rs`, where the current
  changed-record stream encodes v1-v4 only: full/incremental streams with
  optional `from_root` and optional `placement_epoch`.
- `crates/tidefs-local-filesystem/src/send_receive.rs`, where current receive
  validation checks stream shape, root identity, incremental base-root
  authority, omitted content, checksums, namespace invariants, staging, and
  publish ordering.
- `crates/tidefs-send-stream/src/lib.rs` and
  `crates/tidefs-local-filesystem/src/vfssend2_bridge.rs`, where VFSSEND2 has
  source pool and dataset ids but does not yet bind those ids to sender epoch,
  membership generation, local pool identity, or operator cross-pool receive
  authorization.
- OpenZFS `zfs receive -o` and `-x` property override semantics as prior art
  (https://openzfs.github.io/openzfs-docs/man/master/8/zfs-receive.8.html):
  receive-time overrides are explicit, per invocation, and do not delete the
  stream's received property values.

## 1. Current boundary

The currently integrated local changed-record receive path is local authority.
It does not validate distributed sender identity because the integrated
changed-record stream has no distributed sender-pool fields today.

That absence is safe only while the stream makes no distributed claim. Once a
stream format carries sender pool, sender epoch, membership generation, or
equivalent distributed authority fields, accepting the stream without checking
those fields would silently turn remote cluster authority into local storage
authority. TideFS must fail closed instead.

VFSSEND2 is the intended canonical multi-node send/receive format and already
carries `source_pool_id` and `source_dataset_id`, but current receive-side
code treats those as stream lineage fields rather than a cross-pool
authorization gate. This decision therefore applies to both:

- future VFSSEND1 changed-record extensions, if that format is kept alive for
  distributed receive; and
- VFSSEND2 header, header-extension, lineage-manifest, and local-filesystem
  bridge receive paths.

## 2. Sender authority fields

A stream that claims distributed sender authority must carry one mandatory
sender authority block. The block identifies the sender pool and the cluster
membership context that made the stream valid at send time.

Required fields:

- `sender_pool_uuid`: stable 128-bit pool identity for the source pool. A zero
  value is invalid in distributed streams.
- `sender_pool_epoch`: monotonic identity epoch for the source pool. It changes
  when the pool identity is deliberately regenerated, imported under a new
  authority, or otherwise rekeyed so old streams must not be treated as fresh
  authority.
- `sender_membership_generation`: monotonic generation from the membership or
  fencing authority that permitted the sender to issue the stream. A zero
  value is invalid in distributed streams unless the stream is explicitly
  marked local-only.
- `sender_dataset_uuid`: stable source dataset identity. This is not a
  replacement for pool identity; it prevents a valid pool id from being reused
  across the wrong dataset lineage.
- `sender_root_identity`: the already existing full or incremental root
  identity evidence, represented by the current root plus optional
  `from_root`/lineage base fields. This keeps local root validation tied to
  the sender-pool envelope.

The block is not an authentication secret and not an authorization token. It is
evidence that the receiver validates against local pool identity, membership
state, and operator authorization. Transport authentication and encryption
remain separate TFR-017 work.

Legacy changed-record streams without this block remain local-only. They must
not be upgraded into distributed streams by external metadata. A future
receiver that is asked to perform distributed or cross-pool receive from a
legacy stream must refuse before staging object payloads.

## 3. Authorization surface

Cross-pool receive authorization is **per receive** and **exact sender
identity only**.

The operator surface must be exposed as a receive invocation option or the
equivalent API parameter:

```text
allow_cross_pool_from = {
  sender_pool_uuid,
  sender_pool_epoch,
  sender_membership_generation,
  sender_dataset_uuid
}
```

The surface may later appear as a CLI flag, a library option, or a receive
request field, but it must keep the same semantics:

- default is no cross-pool authorization;
- an authorization names exactly one sender identity tuple;
- wildcards, "allow any pool", and persistent inherited defaults are not valid
  for the first implementation;
- the authorization expires with the receive invocation;
- authorization only permits the receiver to continue to normal validation. It
  does not bypass stream digest, root-authentication, checksum,
  base-root, omitted-content, namespace, staging, or publish checks.

Rejected alternatives:

- **Per-pool property**: too broad for a trust-boundary override. A persistent
  pool property could authorize future receives that the operator did not
  inspect.
- **Global config key**: too easy to leave enabled and hard to reason about in
  multi-pool deployments.
- **Per-sender allowlist**: desirable later, but it depends on a product-grade
  transport and membership authority. Until TFR-017 is closed for that
  surface, an allowlist would look authoritative before TideFS can prove what
  the sender identity means.

This mirrors the useful part of OpenZFS receive-time property overrides:
operator intent is explicit on the receive command. TideFS diverges from ZFS
where needed because cross-pool authorization is a trust-boundary gate, not a
property-value override. Received sender authority evidence must be retained in
audit metadata even when the operator authorizes the receive.

## 4. Receiver validation sequence

The receiver validates sender authority before it writes payload objects to
staging or publishes a received root.

1. Decode the stream header and lineage records.
2. Classify sender authority:
   - no sender authority block in a legacy local-only stream: proceed only as
     local receive;
   - sender authority block present: validate field shape and reject zero or
     malformed mandatory values;
   - distributed receive requested but no sender authority block present:
     reject as missing distributed authority.
3. Load local target pool identity and local membership state, if available.
4. If `sender_pool_uuid`, `sender_pool_epoch`, and
   `sender_membership_generation` match local pool authority, treat the stream
   as same-pool and continue to existing receive validation.
5. If any sender pool authority field differs from local pool authority,
   classify the stream as cross-pool.
6. For a cross-pool stream, require per-receive authorization whose exact
   tuple matches the stream's `sender_pool_uuid`, `sender_pool_epoch`,
   `sender_membership_generation`, and `sender_dataset_uuid`. Reject on
   missing authorization, tuple mismatch, unknown sender fields, stale
   generation, or unsupported sender-authority version.
7. After authorization passes, run the existing local receive validation:
   stream version and totals, full versus incremental target class,
   `from_root` presence, base-root protection, omitted-content availability,
   root-authentication, object checksums, namespace invariants, staging fsync,
   and atomic publish.
8. Record audit metadata on success: sender authority tuple, whether the
   receive was same-pool or cross-pool, the explicit authorization tuple used
   for cross-pool receive, the selected local target pool identity, and the
   current/incremental root identities.

The fail-closed point is step 6. A cross-pool stream without exact
authorization is refused before payload staging. If a future implementation
must decode records before discovering sender authority, it must use a
bounded, non-persistent preflight decoder and still reject before writing
stream payloads to the target store.

## 5. Error taxonomy

Implementations must keep cross-pool refusal distinct from existing receive
failures so operators know which action is required.

Required classes:

- malformed sender authority: the stream's distributed fields are invalid;
- missing sender authority: distributed receive was requested but the stream is
  legacy/local-only;
- unknown sender pool: the sender identity does not match local pool identity
  and no exact authorization was supplied;
- authorization mismatch: an authorization was supplied, but it names a
  different sender tuple than the stream carries;
- stale sender generation: the sender membership generation or pool epoch is
  older than the receiver can accept;
- local receive validation failure: all existing base-root, omitted-content,
  checksum, namespace, staging, and publish errors remain separate.

## 6. Follow-up implementation map

The design work is complete in this issue. Implementation is split so the
schema and receive gate do not overlap.

- #777 `receive-stream-sender-authority-fields`
  - Purpose: add typed sender authority evidence to the stream schema.
  - Expected write set:
    - `crates/tidefs-send-stream/src/lib.rs`
    - `crates/tidefs-local-filesystem/src/types.rs`
    - `crates/tidefs-local-filesystem/src/encoding.rs`
    - `crates/tidefs-local-filesystem/src/vfssend2_bridge.rs`
    - focused send/receive stream tests under
      `crates/tidefs-local-filesystem/tests/` or
      `crates/tidefs-send-stream/tests/`
  - Validation tier: focused Rust validation for touched stream crates plus
    `git diff --check`.

- #778 `receive-cross-pool-authorization-validation`
  - Purpose: add the per-receive exact-sender authorization gate and
    fail-closed receive validation.
  - Expected write set:
    - `crates/tidefs-local-filesystem/src/send_receive.rs`
    - `crates/tidefs-local-filesystem/src/lib.rs`
    - `crates/tidefs-local-filesystem/src/error.rs`
    - focused receive tests under `crates/tidefs-local-filesystem/tests/` or
      `crates/tidefs-local-filesystem/src/tests.rs`
    - operator/API documentation updates if a receive CLI/API surface exists
      at implementation time
  - Validation tier: focused Rust validation for `tidefs-local-filesystem`
    send/receive tests plus `git diff --check`.

## 7. Non-claims

This document does not implement runtime behavior. It does not edit
send/receive source, changed-record encoding, active receive tests, transport
authentication, cluster membership, placement receipts, or persistent
operator policy. It only decides the receive authorization model that those
future implementation issues must satisfy.

OpenZFS references in this document are prior-art inputs for explicit operator
intent. They are not a send/receive maturity, compatibility, safety, or
superiority claim for TideFS.
