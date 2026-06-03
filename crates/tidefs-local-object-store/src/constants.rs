//! On-disk format constants for the local object store.
//!
//! This module defines every magic byte sequence, format version, record
//! layout size, integrity trailer constant, checksum seed, domain-separation
//! context, and default configuration value used by the segment layer.
//!
//! # Record layout
//!
//! Each record on disk is: [`RECORD_HEADER_LEN`] (96 bytes) + payload
//! (variable) + [`INTEGRITY_TRAILER_V2_LEN`] (112 bytes) +
//! [`RECORD_FOOTER_LEN`] (16 bytes). The total per-record overhead is
//! [`RECORD_OVERHEAD_BYTES`] (224 bytes). [`PRODUCTION_INTEGRITY_TRAILER_LEN`] is an alias for [`INTEGRITY_TRAILER_V2_LEN`] and kept for public-API stability.
//!
//! # Production integrity (v3)
//!
//! The current production format (`RECORD_FORMAT_VERSION = 3`) uses
//! BLAKE3-256 digests with domain-separated key derivation contexts per
//! record type (`DOMAIN_CONTEXT_PUT_RECORD`, `DOMAIN_CONTEXT_DELETE_RECORD`).
//! Integrity trailers carry a magic marker, a digest suite identifier, and
//! separate payload and record digests.
//!
//! # Segment integrity chaining
//!
//! [`SEGMENT_INTEGRITY_FOOTER_LEN`] (192 bytes) provides per-segment hash
//! chaining for end-to-end integrity verification across segment boundaries.
//!

pub const STORE_DIR_NAME: &str = "segments";
pub const SEGMENT_FILE_EXTENSION: &str = "vlos";
pub const INDEX_BASE_FILE_NAME: &str = "index_base";
pub(crate) const SPACEMAP_BASE_FILE_NAME: &str = "spacemap_base";
pub(crate) const SCRUB_CURSOR_FILE_NAME: &str = "scrub_cursor";
pub const SUSPECT_LOG_FILE_NAME: &str = "suspect_log";
pub(crate) const INDEX_BASE_MAGIC: [u8; 8] = *b"VFSXBASE";
pub(crate) const INDEX_BASE_FORMAT_VERSION: u16 = 1;

pub const RECORD_HEADER_LEN: usize = 96;
pub const RECORD_HEADER_LEN_U64: u64 = RECORD_HEADER_LEN as u64;
pub const RECORD_FOOTER_LEN: usize = 16;
pub const RECORD_FOOTER_LEN_U64: u64 = RECORD_FOOTER_LEN as u64;
pub const RECORD_FORMAT_VERSION_V1_NO_FOOTER: u16 = 1;
pub const RECORD_FORMAT_VERSION_V2_FOOTER: u16 = 2;
pub const RECORD_FORMAT_VERSION: u16 = 3;
// PRODUCTION_INTEGRITY_TRAILER_* constants are the public-API surface.
// They alias the canonical INTEGRITY_TRAILER_V2_* values below; all
// three must stay in agreement with the live writer.
pub const PRODUCTION_INTEGRITY_TRAILER_LEN: usize = 112;
pub const PRODUCTION_INTEGRITY_DIGEST_LEN: usize = 32;
pub const PRODUCTION_INTEGRITY_TRAILER_MAGIC_ASCII: &str = "VLOSINT4";
pub const PRODUCTION_INTEGRITY_TRAILER_MAGIC_BYTES: [u8; 8] = *b"VLOSINT4";
pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_SEGMENT_BYTES: u64 = 256;
pub const RECORD_MAGIC_ASCII: &str = "VLOSREC1";
pub const RECORD_FOOTER_MAGIC_ASCII: &str = "VLOSEND2";
pub const RECORD_MAGIC_BYTES: [u8; 8] = *b"VLOSREC1";
pub const RECORD_FOOTER_MAGIC_BYTES: [u8; 8] = *b"VLOSEND2";
pub const LOCAL_OBJECT_STORE_ON_DISK_FORMAT_SPEC: &str = "TideFS storage item 005 Local Object Store on-disk format: segment identity, segment gaps, record versions, footer semantics, tombstones, history, and upgrade rules are specified for the current append-only segment log";
pub const PRODUCTION_INTEGRITY_POLICY_SPEC: &str = "TideFS storage item 006 production integrity policy: BLAKE3-256 digests, domain separation, collision rejection, authenticated roots, and v3 migration boundaries replace the development checksum/key policy as the target design";
pub const PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM: &str = "BLAKE3-256";
pub const PRODUCTION_INTEGRITY_RECORD_DIGEST_ALGORITHM: &str = "BLAKE3-256";
pub const PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM: &str =
    "keyed BLAKE3-256 root authentication code";
pub const PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM: &str =
    "BLAKE3 derive_key with TideFS integrity domains";
pub const PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION: u16 = 3;

pub(crate) const RECORD_MAGIC: [u8; 8] = RECORD_MAGIC_BYTES;
pub(crate) const RECORD_FOOTER_MAGIC: [u8; 8] = RECORD_FOOTER_MAGIC_BYTES;
pub(crate) const HEADER_CHECKSUM_SEED: u64 = 0x5649_4245_4653_4831;
pub(crate) const PAYLOAD_CHECKSUM_SEED: u64 = 0x5649_4245_4653_5031;
pub(crate) const FOOTER_CHECKSUM_SEED: u64 = 0x5649_4245_4653_4632;
pub(crate) const KEY_DERIVE_SEED: u64 = 0x5649_4245_4653_4b31;
pub(crate) const COMMIT_MARKER_BASE: u64 = 0xc0a1_f00d_d15c_a11d;
pub(crate) const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
pub(crate) const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub const DEFAULT_SEGMENT_ROTATION_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_SEGMENT_ROTATION_WRITE_LIMIT: u64 = 10_000;

pub const DEFAULT_BACKGROUND_SCRUB_INTERVAL_SECS: u64 = 0;

pub const DEFAULT_SEGMENT_COUNT: u64 = 65536;

/// Default free-segment low-watermark threshold for space-pressure signaling.
pub const DEFAULT_LOW_WATERMARK_SEGMENTS: u64 = 16;

// ---------------------------------------------------------------------------
// IntegrityTrailerV2 (G3 pillar: 112-byte trailer with EC shard fields)
// ---------------------------------------------------------------------------

pub const INTEGRITY_TRAILER_V2_LEN: usize = 112;
pub const INTEGRITY_TRAILER_V2_LEN_U64: u64 = INTEGRITY_TRAILER_V2_LEN as u64;
pub const INTEGRITY_TRAILER_V2_MAGIC_ASCII: &str = "VLOSINT4";
pub const INTEGRITY_TRAILER_V2_MAGIC_BYTES: [u8; 8] = *b"VLOSINT4";
pub const INTEGRITY_TRAILER_V2_DIGEST_SUITE_ID: u16 = 1; // BLAKE3-256

// ---------------------------------------------------------------------------
// SegmentIntegrityFooter (G3 pillar: 192-byte segment hash-chaining footer)
// ---------------------------------------------------------------------------

pub const SEGMENT_INTEGRITY_FOOTER_LEN: usize = 192;
pub const SEGMENT_INTEGRITY_FOOTER_LEN_U64: u64 = SEGMENT_INTEGRITY_FOOTER_LEN as u64;
pub const SEGMENT_INTEGRITY_FOOTER_MAGIC_ASCII: &str = "VLOSSEGF";
pub const SEGMENT_INTEGRITY_FOOTER_MAGIC_BYTES: [u8; 8] = *b"VLOSSEGF";

// ---------------------------------------------------------------------------
// SuspectLog (G3 pillar: persistent ring buffer for corruption tracking)
// ---------------------------------------------------------------------------

pub const SUSPECT_LOG_RING_CAPACITY: usize = 256;
pub const SUSPECT_LOG_ENTRY_LEN: usize = 128; // authoritative VSUS on-disk entry size; must match the encoder in store::encode_suspect_entry

// ---------------------------------------------------------------------------
// Checksum architecture specification marker
// ---------------------------------------------------------------------------

pub const CHECKSUM_ARCHITECTURE_SPEC: &str = "TideFS checksum architecture item 0ZA: mandatory non-optional two-tier checksums (CRC32C record-header sanity + BLAKE3-256 payload integrity), domain-separated per-record-type contexts, IntegrityTrailerV2 with EC shard fields, persistent SuspectLog corruption tracking, per-segment SegmentIntegrityFooter hash chaining, and PRODUCTION_INTEGRITY_POLICY_SPEC as policy anchor";

// ---------------------------------------------------------------------------
// Domain-separation contexts for BLAKE3 derive_key per record type
// ---------------------------------------------------------------------------

pub(crate) const DOMAIN_CONTEXT_PUT_RECORD: &str = "tidefs.put_record.v1";
pub(crate) const DOMAIN_CONTEXT_DELETE_RECORD: &str = "tidefs.delete_record.v1";

// ---------------------------------------------------------------------------
// Per-record overhead for the production format (RECORD_FORMAT_VERSION = 3).
// = RECORD_HEADER_LEN + RECORD_FOOTER_LEN + INTEGRITY_TRAILER_V2_LEN (96+16+112)
// ---------------------------------------------------------------------------

pub const RECORD_OVERHEAD_BYTES: u64 = 224;
