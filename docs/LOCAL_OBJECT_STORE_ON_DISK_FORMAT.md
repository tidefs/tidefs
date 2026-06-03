# Local Object Store on-disk format (OW-005/OW-014) (v0.414)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

Historical tracker wording: item 005.

This document describes the historical `OW-005` Local Object Store on-disk
format. v0.414 adds `OW-014`: the current writer now emits record version `3`
with a BLAKE3-256 production-integrity trailer. v1 and v2 records remain

## Scope

The format is an append-only segment log under a caller-provided store root:

```text
<store-root>/
  segments/
    segment-0000000000000000.vlos
    segment-0000000000000001.vlos
    ...
```

The format specifies:

- segment identity;
- segment gaps;
- record versions;
- header layout;
- footer semantics;
- tombstones;
- history;
- upgrade rules.

The source-level binding is:

```text
LOCAL_OBJECT_STORE_ON_DISK_FORMAT_SPEC
LocalObjectStoreFormatTopic
LocalObjectStoreFormatRule
LOCAL_OBJECT_STORE_ON_DISK_FORMAT_RULES
local_object_store_on_disk_format_rules()
```

`tidefs-xtask check-local-store-format` verifies that this document, the source
model, and demo output remain connected.

## Segment identity

All segment files live in `segments/`. A segment file is recognized only when
its basename exactly matches:

```text
segment-<16 lowercase hexadecimal u64>.vlos
```

Examples:

```text
segment-0000000000000000.vlos
segment-0000000000000001.vlos
segment-000000000000000a.vlos
```

Files with other names in `segments/` are ignored by segment discovery. Segment
ids are parsed as unsigned 64-bit integers, sorted, deduplicated, and replayed
in ascending id order.

## Segment gaps

The current format permits absent segment ids. If segment `0` and segment `2`
are present and segment `1` is absent, replay scans `0` then `2`.

That is a segment gap, not an in-file repair. The strictness boundary is:

- missing segment file id: tolerated by current discovery because it has no
  bytes to replay;
- corrupt bytes inside any discovered non-final segment: explicit error;
- torn bytes at the append tail of the final discovered segment: automatic tail
  truncation when `repair_torn_tail` is enabled.

Future compaction or archival rules may tighten segment-gap policy, but they may
not reinterpret corrupt bytes in a discovered non-final segment as safe.

## Record Versions

The current writer emits record format version `3`.

Replay accepts:

| Version | Shape | Write status |
|---:|---|---|
| `1` | 96-byte header + payload | v1 read-only compatibility |
| `2` | 96-byte header + payload + 16-byte footer | v2 read-only compatibility |
| `3` | 96-byte header + payload + 16-byte footer + 112-byte production-integrity trailer | current writer format |

Any other record version is an explicit unsupported-version error.

## Header layout

Every record begins with a 96-byte little-endian header:

| Byte range | Field | Type | Rule |
|---:|---|---|---|
| `0..8` | magic | 8 bytes | ASCII `VLOSREC1` |
| `8..10` | format version | `u16` | `1`, `2`, or `3` |
| `10..12` | record kind | `u16` | `1` put, `2` delete tombstone |
| `12..14` | header length | `u16` | must be `96` |
| `14..16` | reserved | `u16` | must be `0` |
| `16..24` | sequence | `u64` | local monotonically increasing record number |
| `24..32` | payload length | `u64` | number of payload bytes |
| `32..40` | payload checksum | `u64` | current development checksum over payload |
| `40..48` | header checksum | `u64` | checksum over the header with this field zeroed |
| `48..56` | commit marker | `u64` | marker derived from kind, sequence, payload length, checksum, and key |
| `56..88` | object key | 32 bytes | fixed object identifier |
| `88..96` | reserved | `u64` | must be `0` |

All reserved bytes are part of the compatibility contract. Non-zero reserved
fields are corruption, not forward-compatible extension.

## Payload

The payload immediately follows the header. The maximum payload size for current
v3 records is:

```text
max_segment_bytes - 96 - 16 - 112
```

For v2 footer compatibility records, replay allows:

```text
max_segment_bytes - 96 - 16
```

For v1 no-footer compatibility records, replay allows:

```text
max_segment_bytes - 96
```

Reads verify the payload bytes against the stored payload checksum. A mismatch
is an explicit integrity error, except for the v1 no-footer final-tail case where
the current replay code can truncate an interrupted final append.

## Footer Semantics

Version `2` and version `3` records include a 16-byte footer:

| Byte range | Field | Type | Rule |
|---:|---|---|---|
| `0..8` | footer magic | 8 bytes | ASCII `VLOSEND2` |
| `8..16` | footer marker | `u64` | marker derived from record header fields |

A v2/v3 footer-bearing record is replayable only when:

2. the full payload is present;
3. the payload checksum matches;
4. the footer magic is `VLOSEND2`;
5. the footer marker matches the record fields.

A missing or partial footer in the final discovered segment is a torn tail. It
may be truncated automatically. A missing, partial, or mismatched footer in a
non-final segment is corruption.

## Production-Integrity Trailer

Version `3` records end with a 112-byte production-integrity trailer after the
footer:

| Byte range | Field | Type | Rule |
|---:|---|---|---|
| `0..8` | trailer magic | 8 bytes | ASCII `VLOSINT4` |
| `8..10` | record version | `u16` | must match the header version |
| `10..12` | digest suite | `u16` | `1`, BLAKE3-256 |
| `12..14` | trailer length | `u16` | must be `112` |
| `14..16` | reserved | `u16` | must be `0` |
| `16..48` | payload digest | 32 bytes | BLAKE3-256 framed payload digest |
| `48..80` | record digest | 32 bytes | BLAKE3-256 framed record digest |
| `80` | shard count | `u8` | EC shard count (0 when unused) |
| `81` | shard index | `u8` | EC shard index (0 when unused) |
| `82` | ec_k | `u8` | EC data shards (0 when unused) |
| `83` | ec_m | `u8` | EC parity shards (0 when unused) |
| `84..112` | reserved | 28 bytes | must be zero |

The payload digest and record digest use separate TideFS production-integrity
domains. A mismatch is `StoreError::ProductionIntegrityMismatch`, not a repair
request.

## Tombstones

Record kind `2` is a delete tombstone.

Tombstone rules:

- payload length must be `0`;
- the payload checksum is the checksum of an empty payload;
- replay removes the key from the live index;
- tombstones do not erase older put-record history from disk;
- tombstones are counted separately in replay statistics.

A delete tombstone with payload bytes is corrupt.

## History

Replay maintains two views:

- the live latest-object index;
- per-key put-record history.

Every fully replayable put record is appended to the in-memory history for that
key. A later put becomes the live value. A later delete removes the key from the
live index, but it does not erase older put locations from history.

This is required by the Local Filesystem recovery layer: root-slot selection may
need to inspect an older fully written root candidate after a newer candidate is
logically invalid.

## Upgrade rules

The upgrade contract is intentionally conservative:

- current code writes only v3 records;
- current replay accepts v1 no-footer records for compatibility;
- current replay accepts v2 footer-committed records;
- current replay accepts v3 production-integrity records and verifies their
  BLAKE3-256 trailer digests;
- unsupported future versions are explicit errors;
- reserved header fields must remain zero;
- footer-bearing future formats must not be silently accepted unless replay has
  an explicit version rule for them;
- production integrity upgrades follow `docs/PRODUCTION_INTEGRITY_POLICY.md`
  and must migrate from the current development checksum/key policy.



- `local_object_store_on_disk_format_spec_covers_open_work_005_topics`
- `put_reopen_gets_bytes`
- `overwrite_replay_keeps_latest_payload`
- `delete_replay_hides_object`
- `version_history_preserves_superseded_put_locations`
- `truncated_tail_is_repaired_without_losing_committed_record`
- `invalid_final_footer_is_rejected_as_integrity_error`
- `checksum_mismatch_rejects_replay`
- `new_records_use_v3_production_integrity_trailer`
- `record_version_2_footer_record_replays_as_compatibility_input`
- `production_integrity_trailer_mismatch_rejects_replay`
- `segment_rollover_creates_multiple_segments`
- `tidefs-xtask check-local-store-format`
- `tidefs-xtask check-production-integrity-v3`

The store demo prints:

```text
on_disk_format_spec=...
on_disk_format.rules=...
on_disk_format.rule topic=...
```

## Non-goals

This spec does not complete:

- authenticated roots;
- collision policy;
- online scrub/repair;
- production allocator segment retirement;
- compaction and segment retirement;
- distributed replication or erasure coding.

Those remain separate historical tracker items.
