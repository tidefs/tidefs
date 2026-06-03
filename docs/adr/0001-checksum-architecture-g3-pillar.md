# ADR-0001: End-to-End Checksum Architecture (G3 Pillar)

Date: 2026-05-05
Status: Accepted

## Context

Data integrity is a non-negotiable requirement for any next-generation storage
system. ZFS defines the bar with end-to-end 256-bit checksums on every block
pointer and self-healing from redundant copies. Ceph offers optional per-object
checksums but silent corruption can persist when they are disabled.

TideFS needed a canonical checksum strategy that:
- Is mandatory (never optional)
- Covers every record payload
- Domain-separates by record type to prevent cross-type confusion
- Detects corruption synchronously on read and asynchronously via scrub
- Triggers repair or explicit error reporting on mismatch
- Integrates with the existing binary-schema framing and transport layers

## Decision

Adopt a G3-pillar checksum architecture with these core elements:

1. **BLAKE3-256** as the canonical cryptographic digest for all data payloads,
   domain-separated by record type via `blake3_domain_digest()`.

   record kind, format version, payload length) — not end-to-end integrity.

3. **IntegrityTrailerV2** (112 bytes, magic "VLOSINT4") attached to every
   object-store record, containing the BLAKE3-256 digest and EC shard fields.

4. **ChecksumProfile** four-tier system: framing (CRC32C), transport (BLAKE3
   + CRC32C frame), metadata (BLAKE3 domain-separated), data (BLAKE3-256).

5. **SuspectLog**: persistent, append-only log of detected corruption events.

6. **SegmentIntegrityFooter**: hash chain from segment root to each record,
   forming a verifiable integrity chain.

7. **Domain separation**: every checksum computation includes a `DomainTag`
   (e.g., `RECORD_PAYLOAD`, `MANIFEST_ROOT`, `INTENT_LOG_ENTRY`).

   only for non-cryptographic metadata-index purposes.

## Consequences

- Every read path incurs a BLAKE3-256 verification cost; acceptable given
  hardware-accelerated BLAKE3 on modern CPUs.
- `IntegrityTrailerV2` adds 112 bytes per record (up from 80-byte V3 trailer);
  space overhead is negligible for typical record sizes.
- The four-tier `ChecksumProfile` model provides a vocabulary for reasoning
  about integrity at every layer, reducing ad-hoc checksum placement.
- SuspectLog enables post-mortem analysis and proactive repair scheduling.
- Future-proofing: BLAKE3 domain separation ensures cryptographic agility if
  algorithm migration is ever needed.

Design spec: `docs/design/1683-checksum-architecture-g3-pillar-design-spec.md`
Issue: [#1683](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1683)
