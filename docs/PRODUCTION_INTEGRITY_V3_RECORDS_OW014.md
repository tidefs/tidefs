# Production integrity v3 records (OW-014) (v0.414)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 014 for the Local Object Store
record layer. The implemented slice starts the production-integrity data path by making new
object-store records use record version 3 with a BLAKE3-256
production-integrity trailer.

## Record boundary

New records are written as:

```text
96-byte record header
payload bytes
16-byte footer commit marker
112-byte production-integrity trailer
```

The trailer carries:

- `VLOSINT4` trailer magic;
- record version `3`;
- digest suite id `1`;
- trailer length (112 bytes);
- BLAKE3-256 payload digest;
- BLAKE3-256 record digest.

The payload digest is framed with a TideFS production-integrity payload domain,
record version, record kind, sequence, payload length, development checksum, and
object key before hashing the payload bytes. The record digest is framed with a
separate TideFS production-integrity record domain and covers the record frame,
header bytes, payload bytes, footer bytes, and payload digest.

## Compatibility

Replay remains compatible with existing stores:

- record version 1 is still accepted as a no-footer compatibility input;
- record version 2 is still accepted as a footer-committed compatibility input;
- record version 3 is the only version written by current code;
- unsupported future versions are explicit errors.

v3 path is introduced.

## Error behavior

Trailer digest mismatch is an explicit integrity/media error through
`StoreError::ProductionIntegrityMismatch`. Replay does not repair, rewrite,
merge, or choose a winner for a production-integrity mismatch.

## Source surfaces

- `RECORD_FORMAT_VERSION_V2_FOOTER`
- `PRODUCTION_INTEGRITY_TRAILER_MAGIC_ASCII`
- `PRODUCTION_INTEGRITY_TRAILER_LEN`
- `ProductionIntegrityDigest`
- `ProductionIntegrityRecordDigests`
- `encode_integrity_trailer_v2`
- `decode_integrity_trailer_v2`
- `build_integrity_trailer_v2`
- `verify_integrity_trailer_v2`
- `record_has_production_integrity_trailer`
- `StoreError::ProductionIntegrityMismatch`
- `ReplayReport::v3_records_seen`
- `ReplayReport::production_integrity_records_seen`


The source tests cover:

- new records carry a valid v3 production-integrity trailer;
- v2 footer records still replay as compatibility inputs;
- corrupted production-integrity trailer digests are rejected.

The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-production-integrity-v3
```

The stable implementation-tracked non-release command name is
`tidefs-xtask check-production-integrity-v3`.

## Follow-on root authentication

root authentication is delivered by OW-015 in v0.415. This OW-014 slice does
not store raw root authentication keys, implement sealed-key handling, perform
