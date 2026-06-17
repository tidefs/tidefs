//! BLAKE3-256-hashed xattr value record for persistent storage.
//!
//! An [`XattrRecord`] is the on-disk representation of a single extended
//! attribute value. It carries the inode, namespace, name, value, and
//! creation transaction group, with a trailing BLAKE3-256 domain-separated
//! digest for integrity verification.
//!
//! # Wire format (V2)
//!
//! ```text
//! [u8; 4]   magic           "XATR"
//! u8        format_version  2
//! u64 LE    inode
//! u64 LE    inode_generation
//! u8        namespace       1=security 2=system 3=trusted 4=user
//! u16 LE    name_len
//! [u8; NL]  name
//! u32 LE    value_len
//! [u8; VL]  value
//! u64 LE    creation_txg
//! [u8; 32]  BLAKE3-256 digest over all preceding bytes
//! ```
//!
//! Enabled via the `persistence` feature flag (brings in std and the
//! binary-schema checksum stack).

#[cfg(not(any(test, feature = "persistence")))]
compile_error!("xattr_record requires the persistence feature or test");

use tidefs_binary_schema_checksum::{blake3_domain_digest, blake3_domain_verify};
use tidefs_binary_schema_core::{
    DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion, U16Le, U32Le,
};

// ---------------------------------------------------------------------------
// Magic and format constants
// ---------------------------------------------------------------------------

/// Magic bytes for xattr value record: `XATR`.
const XATTR_RECORD_MAGIC: [u8; 4] = [0x58, 0x41, 0x54, 0x52]; // "XATR"

/// Current xattr value record format version.
const XATTR_RECORD_FORMAT_VERSION: u8 = 2;

/// Schema type ID for xattr value records (201 = xattr value record).
const XATTR_RECORD_TYPE_ID: SchemaTypeId = SchemaTypeId(201);

/// Schema version for xattr value record format V2.
const XATTR_RECORD_VERSION: SchemaVersion = SchemaVersion::new(2, 0);

/// Minimum on-disk blob size: magic(4) + version(1) + inode(8)
/// + inode_generation(8) + ns(1) + name_len(2) + value_len(4)
/// + txg(8) + digest(32) = 68.
///
/// This is the size of a record with a zero-length name and value.
const XATTR_RECORD_MIN_BLOB_LEN: usize = 68;

// ---------------------------------------------------------------------------
// Namespace
// ---------------------------------------------------------------------------

/// Xattr namespace discriminant.
///
/// Values are compatible with [`tidefs_intent_log::record::XattrNamespace`]
/// byte encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum XattrNamespace {
    /// `security.*` — SELinux, SMACK, AppArmor.
    Security = 1,
    /// `system.*` — ACLs, capabilities.
    System = 2,
    /// `trusted.*` — restricted to CAP_SYS_ADMIN.
    Trusted = 3,
    /// `user.*` — unrestricted per-file attributes.
    User = 4,
}

impl XattrNamespace {
    /// Serialize as a single byte.
    #[inline]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Deserialize from a single byte.
    #[inline]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Security),
            2 => Some(Self::System),
            3 => Some(Self::Trusted),
            4 => Some(Self::User),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// XattrRecord
// ---------------------------------------------------------------------------

/// An on-disk xattr value record with BLAKE3-256 integrity verification.
///
/// Each record is a self-describing blob that can be sealed (serialized
/// and hashed) and verified (deserialized and checked against the
/// embedded digest). Records are keyed by their BLAKE3 content hash in
/// the local object store, referenced by intent-log [`XattrSet`] and
/// [`XattrRemove`] entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrRecord {
    /// Inode number this xattr belongs to.
    pub inode: u64,
    /// Inode generation/version this xattr belongs to.
    pub inode_generation: u64,
    /// Xattr namespace.
    pub namespace: XattrNamespace,
    /// The attribute name (without namespace prefix), e.g. `selinux`
    /// for `security.selinux`.
    pub name: Vec<u8>,
    /// The attribute value bytes.
    pub value: Vec<u8>,
    /// Transaction group in which this record was created.
    pub creation_txg: u64,
}

impl XattrRecord {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create a new xattr record with the given creation txg.
    #[must_use]
    pub fn new(
        inode: u64,
        inode_generation: u64,
        namespace: XattrNamespace,
        name: Vec<u8>,
        value: Vec<u8>,
        creation_txg: u64,
    ) -> Self {
        Self {
            inode,
            inode_generation,
            namespace,
            name,
            value,
            creation_txg,
        }
    }

    // ------------------------------------------------------------------
    // Seal (encode + hash)
    // ------------------------------------------------------------------

    /// Encode the record to bytes and append a BLAKE3-256
    /// domain-separated digest of the encoded header + payload.
    ///
    /// The returned blob can be stored in the object store and later
    /// verified with [`verify`](Self::verify).
    #[must_use]
    pub fn seal(&self) -> Vec<u8> {
        let header_payload = self.encode_header_and_payload();
        let digest = blake3_domain_digest(
            &header_payload,
            SchemaFamilyId::BINARY_SCHEMA,
            XATTR_RECORD_TYPE_ID,
            XATTR_RECORD_VERSION,
            DomainTag::SectionBody,
        );
        let mut blob = header_payload;
        blob.extend_from_slice(&digest);
        blob
    }

    /// Compute the BLAKE3-256 domain-separated content hash of this
    /// record (without the trailing digest field).
    ///
    /// This hash is a stable identifier for the record content and can
    /// be used as the object-store key or as the intent-log `value_hash`.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        let header_payload = self.encode_header_and_payload();
        blake3_domain_digest(
            &header_payload,
            SchemaFamilyId::BINARY_SCHEMA,
            XATTR_RECORD_TYPE_ID,
            XATTR_RECORD_VERSION,
            DomainTag::SectionBody,
        )
    }

    // ------------------------------------------------------------------
    // Verify (decode + check)
    // ------------------------------------------------------------------

    /// Decode a sealed blob and verify the BLAKE3-256 digest.
    ///
    /// Returns `Ok(Self)` if the digest matches, or an error on format
    /// or integrity failure.
    pub fn verify(data: &[u8]) -> Result<Self, XattrRecordError> {
        if data.len() < XATTR_RECORD_MIN_BLOB_LEN {
            return Err(XattrRecordError::Truncated);
        }
        if data[..4] != XATTR_RECORD_MAGIC {
            return Err(XattrRecordError::BadMagic);
        }
        if data[4] != XATTR_RECORD_FORMAT_VERSION {
            return Err(XattrRecordError::UnknownVersion { version: data[4] });
        }

        let content_end = data.len() - 32;
        let header_payload = &data[..content_end];
        let expected_digest: &[u8; 32] = data[content_end..]
            .try_into()
            .map_err(|_| XattrRecordError::Truncated)?;

        // Verify BLAKE3 domain-separated digest.
        blake3_domain_verify(
            header_payload,
            expected_digest,
            SchemaFamilyId::BINARY_SCHEMA,
            XATTR_RECORD_TYPE_ID,
            XATTR_RECORD_VERSION,
            DomainTag::SectionBody,
        )
        .map_err(|_| XattrRecordError::DigestMismatch)?;

        // Decode payload (skip magic + version = 5 bytes).
        Self::decode_payload(&data[5..content_end])
    }

    /// Decode a raw payload (without magic, version, or digest).
    fn decode_payload(data: &[u8]) -> Result<Self, XattrRecordError> {
        let mut pos = 0usize;

        // inode (8 bytes)
        ensure_len(data, pos, 8)?;
        let inode = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // inode_generation (8 bytes)
        ensure_len(data, pos, 8)?;
        let inode_generation = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // namespace (1 byte)
        ensure_len(data, pos, 1)?;
        let ns_byte = data[pos];
        pos += 1;
        let namespace = XattrNamespace::from_byte(ns_byte)
            .ok_or(XattrRecordError::BadNamespace { byte: ns_byte })?;

        // name_len (2 bytes)
        ensure_len(data, pos, 2)?;
        let name_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;

        // name (name_len bytes)
        ensure_len(data, pos, name_len)?;
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;

        // value_len (4 bytes)
        ensure_len(data, pos, 4)?;
        let value_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        // value (value_len bytes)
        ensure_len(data, pos, value_len)?;
        let value = data[pos..pos + value_len].to_vec();
        pos += value_len;

        // creation_txg (8 bytes)
        ensure_len(data, pos, 8)?;
        let creation_txg = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        // pos += 8; -- not needed, but kept for symmetry

        Ok(Self {
            inode,
            inode_generation,
            namespace,
            name,
            value,
            creation_txg,
        })
    }

    // ------------------------------------------------------------------
    // Encoding helpers
    // ------------------------------------------------------------------

    /// Encode magic, version, and payload fields (without the digest).
    fn encode_header_and_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            XATTR_RECORD_MAGIC.len()
                + 1  // version
                + 8  // inode
                + 8  // inode_generation
                + 1  // namespace
                + U16Le::BYTES + self.name.len()
                + U32Le::BYTES + self.value.len()
                + 8, // creation_txg
        );

        // Magic + version
        buf.extend_from_slice(&XATTR_RECORD_MAGIC);
        buf.push(XATTR_RECORD_FORMAT_VERSION);

        // inode
        buf.extend_from_slice(&self.inode.to_le_bytes());

        // inode_generation
        buf.extend_from_slice(&self.inode_generation.to_le_bytes());

        // namespace
        buf.push(self.namespace.to_byte());

        // name_len + name
        let name_len = U16Le::from_le(self.name.len() as u16);
        buf.extend_from_slice(&name_len.encode());
        buf.extend_from_slice(&self.name);

        // value_len + value
        let value_len = U32Le::from_le(self.value.len() as u32);
        buf.extend_from_slice(&value_len.encode());
        buf.extend_from_slice(&self.value);

        // creation_txg
        buf.extend_from_slice(&self.creation_txg.to_le_bytes());

        buf
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by xattr record seal/verify operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrRecordError {
    /// The blob is too short to contain a valid record.
    Truncated,
    /// The magic bytes do not match "XATR".
    BadMagic,
    /// The format version is not recognised.
    UnknownVersion {
        /// The version byte found in the blob.
        version: u8,
    },
    /// The namespace byte is not a recognised discriminant (1-4).
    BadNamespace {
        /// The byte found in the blob.
        byte: u8,
    },
    /// The BLAKE3-256 digest does not match the computed digest.
    DigestMismatch,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
fn ensure_len(data: &[u8], pos: usize, needed: usize) -> Result<(), XattrRecordError> {
    if pos + needed > data.len() {
        Err(XattrRecordError::Truncated)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record() -> XattrRecord {
        XattrRecord::new(
            42,
            9,
            XattrNamespace::User,
            b"mykey".to_vec(),
            b"myval".to_vec(),
            7,
        )
    }

    // ── Basic seal/verify round-trip ──────────────────────────────────

    #[test]
    fn seal_verify_roundtrip() {
        let rec = make_record();
        let blob = rec.seal();

        // Magic check
        assert_eq!(&blob[..4], &XATTR_RECORD_MAGIC);
        assert_eq!(blob[4], XATTR_RECORD_FORMAT_VERSION);

        let verified = XattrRecord::verify(&blob).expect("verify should succeed");
        assert_eq!(verified, rec);
    }

    #[test]
    fn empty_name_and_value_roundtrip() {
        let rec = XattrRecord::new(1, 1, XattrNamespace::Security, vec![], vec![], 0);
        let blob = rec.seal();
        let verified = XattrRecord::verify(&blob).expect("verify empty");
        assert_eq!(verified, rec);
    }

    #[test]
    fn large_value_roundtrip() {
        let big = vec![0xABu8; 8192];
        let rec = XattrRecord::new(
            99,
            3,
            XattrNamespace::System,
            b"large".to_vec(),
            big.clone(),
            3,
        );
        let blob = rec.seal();
        let verified = XattrRecord::verify(&blob).expect("verify large");
        assert_eq!(verified.name, b"large".to_vec());
        assert_eq!(verified.value, big);
    }

    #[test]
    fn binary_name_roundtrip() {
        let name = vec![0x00, 0xFF, 0x42, 0x99];
        let rec = XattrRecord::new(10, 4, XattrNamespace::User, name.clone(), b"v".to_vec(), 1);
        let blob = rec.seal();
        let verified = XattrRecord::verify(&blob).expect("verify binary name");
        assert_eq!(verified.name, name);
    }

    // ── All four namespaces ───────────────────────────────────────────

    #[test]
    fn all_namespaces_roundtrip() {
        let namespaces = [
            (XattrNamespace::Security, b"sec".to_vec(), b"sv".to_vec()),
            (XattrNamespace::System, b"sys".to_vec(), b"syv".to_vec()),
            (XattrNamespace::Trusted, b"tr".to_vec(), b"tv".to_vec()),
            (XattrNamespace::User, b"usr".to_vec(), b"uv".to_vec()),
        ];
        for (ns, name, value) in &namespaces {
            let rec = XattrRecord::new(1, 1, *ns, name.clone(), value.clone(), 0);
            let blob = rec.seal();
            let verified = XattrRecord::verify(&blob).expect("verify namespace");
            assert_eq!(verified.namespace, *ns);
            assert_eq!(verified.name, *name);
            assert_eq!(verified.value, *value);
        }
    }

    // ── Content hash stability ────────────────────────────────────────

    #[test]
    fn content_hash_is_deterministic() {
        let rec = make_record();
        let h1 = rec.content_hash();
        let h2 = rec.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_differs_per_value() {
        let r1 = XattrRecord::new(1, 1, XattrNamespace::User, b"a".to_vec(), b"v1".to_vec(), 0);
        let r2 = XattrRecord::new(1, 1, XattrNamespace::User, b"a".to_vec(), b"v2".to_vec(), 0);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn content_hash_differs_per_name() {
        let r1 = XattrRecord::new(1, 1, XattrNamespace::User, b"a".to_vec(), b"v".to_vec(), 0);
        let r2 = XattrRecord::new(1, 1, XattrNamespace::User, b"b".to_vec(), b"v".to_vec(), 0);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn content_hash_differs_per_inode() {
        let r1 = XattrRecord::new(1, 1, XattrNamespace::User, b"a".to_vec(), b"v".to_vec(), 0);
        let r2 = XattrRecord::new(2, 1, XattrNamespace::User, b"a".to_vec(), b"v".to_vec(), 0);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn content_hash_differs_per_inode_generation() {
        let r1 = XattrRecord::new(1, 1, XattrNamespace::User, b"a".to_vec(), b"v".to_vec(), 0);
        let r2 = XattrRecord::new(1, 2, XattrNamespace::User, b"a".to_vec(), b"v".to_vec(), 0);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn content_hash_differs_per_txg() {
        let r1 = XattrRecord::new(1, 1, XattrNamespace::User, b"a".to_vec(), b"v".to_vec(), 0);
        let r2 = XattrRecord::new(1, 1, XattrNamespace::User, b"a".to_vec(), b"v".to_vec(), 1);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    // ── Integrity: tampering detection ────────────────────────────────

    #[test]
    fn tampered_magic_rejected() {
        let rec = make_record();
        let mut blob = rec.seal();
        blob[0] ^= 0xFF;
        assert_eq!(XattrRecord::verify(&blob), Err(XattrRecordError::BadMagic));
    }

    #[test]
    fn tampered_value_rejected() {
        let rec = make_record();
        let mut blob = rec.seal();
        // Flip a byte in the value region after inode-generation evidence.
        // 4(magic) + 1(version) + 8(inode) + 8(generation) + 1(ns)
        // + 2(name_len) + 5(name) + 4(value_len) = 33
        blob[33] ^= 0xFF;
        assert_eq!(
            XattrRecord::verify(&blob),
            Err(XattrRecordError::DigestMismatch)
        );
    }

    #[test]
    fn tampered_digest_rejected() {
        let rec = make_record();
        let mut blob = rec.seal();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert_eq!(
            XattrRecord::verify(&blob),
            Err(XattrRecordError::DigestMismatch)
        );
    }

    #[test]
    fn truncated_blob_rejected() {
        let rec = make_record();
        let blob = rec.seal();
        // Truncate well below the minimum blob size so the length
        // check fires before digest verification.
        let truncated = &blob[..XATTR_RECORD_MIN_BLOB_LEN - 1];
        assert_eq!(
            XattrRecord::verify(truncated),
            Err(XattrRecordError::Truncated)
        );
    }
    #[test]
    fn empty_blob_rejected() {
        assert_eq!(XattrRecord::verify(&[]), Err(XattrRecordError::Truncated));
    }

    #[test]
    fn unknown_version_rejected() {
        let rec = make_record();
        let mut blob = rec.seal();
        blob[4] = 99; // unknown version
        assert_eq!(
            XattrRecord::verify(&blob),
            Err(XattrRecordError::UnknownVersion { version: 99 })
        );
    }

    // ── Namespace validation ──────────────────────────────────────────

    #[test]
    fn bad_namespace_caught_by_digest() {
        let rec = make_record();
        let mut blob = rec.seal();
        // Namespace byte is at offset 4(magic)+1(version)+8(inode)+8(generation) = 21
        blob[21] = 99; // invalid namespace
                       // Digest verification fires before structural decode; tampered data
                       // is always caught as DigestMismatch.
        assert_eq!(
            XattrRecord::verify(&blob),
            Err(XattrRecordError::DigestMismatch)
        );
    }

    #[test]
    fn valid_digest_bad_namespace_rejected() {
        // Construct a blob with a deliberately invalid namespace byte
        // and a recomputed digest — this tests the structural guard
        // when the digest is otherwise valid.
        let rec = make_record();
        let mut blob = rec.seal();
        blob[21] = 99; // invalid namespace
                       // Recompute digest over the now-modified header+payload.
        let content_end = blob.len() - 32;
        let new_digest = blake3_domain_digest(
            &blob[..content_end],
            SchemaFamilyId::BINARY_SCHEMA,
            XATTR_RECORD_TYPE_ID,
            XATTR_RECORD_VERSION,
            DomainTag::SectionBody,
        );
        blob[content_end..].copy_from_slice(&new_digest);
        assert_eq!(
            XattrRecord::verify(&blob),
            Err(XattrRecordError::BadNamespace { byte: 99 })
        );
    }
    #[test]
    fn namespace_from_byte_edge_cases() {
        assert_eq!(XattrNamespace::from_byte(0), None);
        assert_eq!(XattrNamespace::from_byte(5), None);
        assert_eq!(XattrNamespace::from_byte(255), None);
    }

    // ── Same-name different values produce different records ──────────

    #[test]
    fn upsert_replacement_yields_different_blob() {
        let r1 = XattrRecord::new(
            1,
            1,
            XattrNamespace::User,
            b"key".to_vec(),
            b"old".to_vec(),
            1,
        );
        let r2 = XattrRecord::new(
            1,
            1,
            XattrNamespace::User,
            b"key".to_vec(),
            b"new".to_vec(),
            2,
        );

        let blob1 = r1.seal();
        let blob2 = r2.seal();
        assert_ne!(blob1, blob2);

        // Both independently verify.
        XattrRecord::verify(&blob1).expect("r1 verify");
        XattrRecord::verify(&blob2).expect("r2 verify");
    }

    // ── Encoding is deterministic ─────────────────────────────────────

    #[test]
    fn encoding_is_deterministic() {
        let rec = make_record();
        let b1 = rec.seal();
        let b2 = rec.seal();
        assert_eq!(b1, b2);
    }
}
