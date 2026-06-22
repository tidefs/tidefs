# Send/receive version authority

Maturity: design authority for issue #695; documentation-only slice.
Status: decided; source follow-ups mapped.

This document records the current authority boundary for timestamp and storage
version fields carried by TideFS changed-record send/receive streams. It
narrows the TFR-005 section 9.4 open item without changing runtime
send/receive source.

## Authority inputs

- `docs/TIMESTAMP_GENERATION_AUTHORITY.md`, especially section 9.4.
- `docs/UNRELEASED_AUTHORITY_POLICY.md`.
- `docs/LOCAL_SNAPSHOTS_OW108.md` and `docs/SEND_RECEIVE_OW109.md`.
- `docs/RECEIVE_STREAM_MERGE_POLICY.md`.
- `crates/tidefs-local-filesystem/src/encoding.rs`.
- `crates/tidefs-local-filesystem/src/send_receive.rs`.
- `crates/tidefs-local-filesystem/src/vfssend2_bridge.rs`.
- Issue #566 and PR #623. They were closed/merged before this document was
  written, but issue #695 still authorizes this slice as documentation/design
  only.

## Decision

Changed-record send/receive has two separate version authorities, and neither
one is a reconciliation authority:

1. The changed-record stream envelope version decides only which stream-level
   envelope fields exist.
2. Each local filesystem record payload's own format version decides how POSIX
   timestamps, `data_version`, and `metadata_version` are encoded.

The stream must not introduce a third pass that repairs, normalizes,
reconciles, or derives POSIX timestamps from storage versions, VFS
generations, transaction ids, or other commit ticks. For unreleased TideFS
formats, old pre-authority records fail closed unless a future issue names a
real external data boundary and satisfies `docs/UNRELEASED_AUTHORITY_POLICY.md`.

## Field projection rules

### POSIX timestamps

Full and incremental changed-record streams carry POSIX timestamp authority by
carrying local inode record payloads that contain explicit `PosixTimeRecord`
fields:

- `atime_ns`
- `mtime_ns`
- `ctime_ns`
- `btime_ns`

The local filesystem inode record format is the authority for those fields.
The stream envelope version is not allowed to reinterpret them. Import may
decode and validate the inode payload, but it must not fabricate missing
timestamps from `generation`, `data_version`, `metadata_version`,
`transaction_id`, committed-root generation, placement epoch, or wall-clock
time at the receiver.

Current local inode decode already rejects formats below 5 because those
formats lacked explicit POSIX timestamps. That fail-closed behavior is the
desired authority rule for changed-record import too.

### `data_version`

`data_version` remains the local filesystem content-object identity token
defined by `docs/TIMESTAMP_GENERATION_AUTHORITY.md` and
`docs/CONTENT_OBJECT_VERSION_AUTHORITY.md`. A changed-record stream carries it
inside local inode, content object, content manifest, and content chunk
payloads, and those values are part of object-key and checksum validation.

Full receive preserves the source payload's `data_version` values when
reconstructing the imported committed roots. Incremental receive does the same
for incoming records and verifies omitted unchanged content against the
receiver's protected base root. It must not allocate receiver-local
`data_version` values, compare them to POSIX timestamps, or rebuild equality
with inode generation.

### `metadata_version`

`metadata_version` remains the local filesystem metadata storage version field
defined by `docs/TIMESTAMP_GENERATION_AUTHORITY.md`. It is carried in local
inode payloads. Changed-record import may validate the payload and the root it
belongs to, but must not use `metadata_version` to create POSIX timestamps or
to repair namespace revision counters. The separate
`metadata_version` to `subtree_rev` / `dir_rev` coupling remains a TFR-005
runtime issue outside this send/receive stream decision.

## Stream version selection

### VFSSEND1 changed-record envelope

The current local changed-record envelope is `VFSSEND1`:

| Envelope version | Meaning |
| --- | --- |
| 1 | Full stream, no placement epoch |
| 2 | Incremental stream with `from_root`, no placement epoch |
| 3 | Full stream with placement epoch |
| 4 | Incremental stream with `from_root` and placement epoch |

The encoder should derive this value from the stream's full/incremental shape
and placement-epoch presence. It is not a caller-selected compatibility knob.
Adding a new envelope field requires a new envelope version and focused
decode/round-trip coverage. Changing local record payload layout requires the
appropriate local filesystem record format version change instead.

### Local record payloads

The local filesystem record format version, currently
`FILESYSTEM_FORMAT_VERSION`, owns local inode, content, manifest, directory,
snapshot, and extent payload layout. If POSIX timestamp fields,
`data_version`, or `metadata_version` layout changes, that change belongs to
the local record format family and its golden/codec validation, not to an
import-side reconciliation pass.

### VFSSEND2 bridge

`tidefs-send-stream` owns the VFSSEND2 envelope version for the canonical
send-stream crate. The current local bridge wraps changed-record payloads into
VFSSEND2 object records, but the local payload bytes still keep their local
record authority. VFSSEND2 lineage, sender identity, dataset identity, and
feature negotiation fields may decide whether a stream can be accepted; they
must not reinterpret local POSIX timestamp, `data_version`, or
`metadata_version` payload fields.

## Import reconciliation rule

Allowed import transformations are limited to authority-preserving receive
work:

- validate stream magic, envelope version, reserved fields, counts, object
  roles, checksums, root summaries, root authentication, base-root authority,
  omitted content, and placement-epoch evidence;
- stage objects before publish;
- re-sign imported committed roots with the destination root-authentication
  key;
- rewrite imported snapshot catalog root references to the destination-signed
  root summaries.

The following are not allowed:

- deriving POSIX timestamps from `generation`, transaction ids,
  `data_version`, or `metadata_version`;
- remapping `data_version` or `metadata_version` to receiver-local ticks;
- repairing equality among `generation`, `data_version`, and
  `metadata_version`;
- accepting pre-explicit-timestamp inode payloads through compatibility or
  downgrade fallback;
- treating VFSSEND2 lineage or sender identity metadata as an override for
  local record payload field authority.

## Follow-up implementation map

- #1002 (`send-receive-vfssend1-version-authority-guards`) is the focused
  VFSSEND1 guard issue. Its expected write set is limited to
  `crates/tidefs-local-filesystem/src/encoding.rs`, focused tests under
  `crates/tidefs-local-filesystem/tests/**` or an encoding-only adjacent test
  module, and `crates/tidefs-local-filesystem/src/types.rs` only if a narrow
  testable helper is needed. It must not edit
  `crates/tidefs-local-filesystem/src/send_receive.rs` or local receive tests
  while #703 has a live branch or PR touching those paths.
- #777 (`receive-stream-sender-authority-fields`) owns distributed sender
  authority fields and stream-header evidence. That issue should consume this
  document when deciding whether VFSSEND1 remains local-only or gains new
  sender evidence, and it must not use sender identity fields to reinterpret
  timestamp or local storage-version payloads.
- #703 (`receive-conflicting-target-error`) remains the receive merge-policy
  error-classification follow-up. It is not a timestamp/version projection
  issue and should not absorb #1002 unless live issue state records a deliberate
  handoff.

Runtime send/receive validation, Focused Rust runs, and any source changes
belong to those follow-up issues. Issue #695 remains complete as a design
slice when this document is reviewed with source inspection and
`git diff --check`.
