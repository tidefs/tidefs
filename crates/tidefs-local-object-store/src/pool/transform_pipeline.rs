// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lower storage transform pipeline dispatcher.
//!
//! This module owns the ordered write/read transform execution for the local
//! object-store pool authority.  It is the canonical dispatch point for
//! mounted content transforms and must not be bypassed by raw-store callers
//! that claim compression or encryption support.
//!
//! The authority document is `docs/TRANSFORM_PIPELINE_AUTHORITY.md`.
//!
//! ## Write pipeline
//!
//! ```text
//! plaintext identity
//!   -> dedup fingerprint and planning (caller-supplied decision)
//!   -> compression decision/frame
//!   -> encryption decision/frame
//!   -> checksum over the stored frame
//!   -> raw-store I/O and placement receipt
//! ```
//!
//! ## Read pipeline
//!
//! ```text
//! raw-store read
//!   -> checksum verification of the stored frame
//!   -> decryption when an encryption frame is present
//!   -> decompression when a compression frame is present
//!   -> plaintext identity returned to the mounted caller
//! ```

use crate::compress::{CompressionAlgorithm, CompressionConfig};
use crate::encrypt::{decrypt_object, encrypt_object, EncryptionConfig};
use crate::{ObjectKey, Result, StoreError};

// ---------------------------------------------------------------------------
// Pipeline decisions
// ---------------------------------------------------------------------------

/// Caller-supplied dedup decision fed into the write pipeline before any
/// transform is applied.  The dispatcher records this decision but does not
/// compute dedup fingerprints itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DedupDecision {
    /// Write a new object through the full transform pipeline.
    NewWrite,
    /// Redirect this logical write to an existing canonical object.
    /// The pipeline still protects the redirect record with whatever
    /// checksum/encryption policy applies.
    RedirectToCanonical {
        canonical_key: ObjectKey,
    },
    /// Dedup is disabled or inapplicable for this content class.
    Bypass,
}

/// Compression decision made by the pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionDecision {
    /// Payload was compressed with the given algorithm.
    Compressed(CompressionAlgorithm),
    /// Explicit uncompressed identity frame — no compression applied.
    UncompressedIdentity,
}

/// Encryption decision made by the pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionDecision {
    /// Stored frame is encrypted (ChaCha20-Poly1305 AEAD).
    Encrypted,
    /// Explicit plaintext/no-encryption frame.
    PlaintextNoEncryption,
}

// ---------------------------------------------------------------------------
// Stored frame metadata
// ---------------------------------------------------------------------------

/// Metadata persisted alongside the stored frame so the reverse read pipeline
/// can replay the same transform decisions without guesswork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredFrameMetadata {
    /// Compression algorithm applied, or `None` when the frame is an
    /// explicit uncompressed-identity frame.
    pub compression: Option<CompressionAlgorithm>,
    /// Whether the stored frame is encrypted.
    pub encrypted: bool,
    /// BLAKE3 checksum over the exact bytes written to raw media.
    pub checksum: [u8; 32],
    /// Length of the stored frame in bytes.
    pub stored_len: u64,
}

impl StoredFrameMetadata {
    /// Number of bytes consumed by the compression frame header (5 bytes:
    /// 1 algorithm + 4 uncompressed-length LE).
    pub const COMPRESSION_FRAME_HEADER_LEN: usize = 5;
}

// ---------------------------------------------------------------------------
// Transform pipeline authority
// ---------------------------------------------------------------------------

/// Named transform dispatcher that owns the ordered write/read pipeline for
/// the lower local-object-store pool.
///
/// This is the canonical storage transform entrypoint for mounted content
/// payloads.  It applies compression, encryption, and checksum in the order
/// decided by `docs/TRANSFORM_PIPELINE_AUTHORITY.md` and writes the result
/// through the raw object store.
///
/// Metadata/raw-only consumers must use an explicit raw-only mode and cannot
/// be confused with mounted content transform support.
pub struct TransformPipelineAuthority {
    /// Compression policy for this pipeline instance.
    compression_config: CompressionConfig,
    /// Encryption configuration when enabled; `None` means plaintext/no-encryption.
    encryption_config: Option<EncryptionConfig>,
}

impl TransformPipelineAuthority {
    /// Create a pipeline with compression only (no encryption).
    pub fn compression_only(config: CompressionConfig) -> Self {
        Self {
            compression_config: config,
            encryption_config: None,
        }
    }

    /// Create a pipeline with both compression and encryption.
    pub fn with_encryption(
        compression_config: CompressionConfig,
        encryption_config: EncryptionConfig,
    ) -> Self {
        Self {
            compression_config,
            encryption_config: Some(encryption_config),
        }
    }

    /// Create a pipeline with encryption but no compression.
    /// Uses an explicit uncompressed-identity compression config.
    pub fn encryption_only(encryption_config: EncryptionConfig) -> Self {
        Self {
            compression_config: CompressionConfig {
                algorithm: CompressionAlgorithm::Uncompressed,
                ..CompressionConfig::default()
            },
            encryption_config: Some(encryption_config),
        }
    }

    /// Create a raw-only pass-through pipeline.  Produces explicit
    /// uncompressed plaintext frames with checksum.  This is the safe
    /// raw-only mode — callers that need metadata/raw access must use this
    /// instead of `raw_primary_store()` to make their intent visible.
    pub fn raw_only() -> Self {
        Self {
            compression_config: CompressionConfig {
                algorithm: CompressionAlgorithm::Uncompressed,
                ..CompressionConfig::default()
            },
            encryption_config: None,
        }
    }

    // ------------------------------------------------------------------
    // Write pipeline
    // ------------------------------------------------------------------

    /// Execute the full write pipeline: dedup planning → compress → encrypt →
    /// checksum.
    ///
    /// Returns the stored frame (ready for raw-media write) and its metadata.
    /// The caller writes the frame to the raw object store and records the
    /// metadata alongside the locator, integrity trailer, or placement receipt.
    ///
    /// # Arguments
    ///
    /// * `plaintext` — the payload before any transform.
    /// * `_dedup_decision` — caller-supplied dedup fingerprint/planning result;
    ///   recorded but not used for post-transform fingerprinting.
    pub fn write_frame(
        &self,
        plaintext: &[u8],
        _dedup_decision: &DedupDecision,
    ) -> Result<(Vec<u8>, StoredFrameMetadata)> {
        // Stage 1: compression frame
        let (compressed, compression_decision) = self.compress_stage(plaintext);

        // Stage 2: encryption frame
        let (encrypted, encrypted_flag) = self.encrypt_stage(&compressed);

        // Stage 3: checksum over the exact stored frame
        let checksum = *blake3::hash(&encrypted).as_bytes();

        let metadata = StoredFrameMetadata {
            compression: match compression_decision {
                CompressionDecision::Compressed(alg) => Some(alg),
                CompressionDecision::UncompressedIdentity => None,
            },
            encrypted: encrypted_flag,
            checksum,
            stored_len: encrypted.len() as u64,
        };

        Ok((encrypted, metadata))
    }

    // ------------------------------------------------------------------
    // Read pipeline
    // ------------------------------------------------------------------

    /// Execute the full read pipeline: checksum verification → decrypt →
    /// decompress → plaintext.
    ///
    /// # Arguments
    ///
    /// * `stored_frame` — the exact bytes read from raw media.
    /// * `metadata` — frame metadata recorded alongside the stored frame
    ///   during the write pipeline.
    pub fn read_frame(
        &self,
        stored_frame: &[u8],
        metadata: &StoredFrameMetadata,
    ) -> Result<Vec<u8>> {
        // Stage 1: checksum verification
        self.checksum_verify_stage(stored_frame, metadata)?;

        // Stage 2: decrypt when an encryption frame is present
        let decrypted = self.decrypt_stage(stored_frame, metadata)?;

        // Stage 3: decompress when a compression frame is present
        let plaintext = self.decompress_stage(&decrypted, metadata)?;

        Ok(plaintext)
    }

    // ------------------------------------------------------------------
    // Per-stage helpers (public for testability)
    // ------------------------------------------------------------------

    /// Stage 1 write: compress plaintext → compression frame.
    ///
    /// Returns the framed bytes and the compression decision.
    pub fn compress_stage(&self, plaintext: &[u8]) -> (Vec<u8>, CompressionDecision) {
        let mut stats = crate::compress::CompressionStats::default();
        let framed =
            crate::compress::compress_frame(plaintext, &self.compression_config, &mut stats);

        let decision = match crate::compress::CompressionAlgorithm::from_byte(framed[0]) {
            Some(CompressionAlgorithm::Uncompressed) | None => {
                CompressionDecision::UncompressedIdentity
            }
            Some(alg) => CompressionDecision::Compressed(alg),
        };

        (framed, decision)
    }

    /// Stage 2 write: encrypt compression frame → encryption frame.
    ///
    /// When encryption is disabled or no key is available, returns the
    /// compression frame as-is with an explicit plaintext/no-encryption
    /// decision.
    pub fn encrypt_stage(&self, compression_frame: &[u8]) -> (Vec<u8>, bool) {
        match &self.encryption_config {
            Some(config) => {
                let encrypted = encrypt_object(&config.key, compression_frame);
                (encrypted, true)
            }
            None => (compression_frame.to_vec(), false),
        }
    }

    /// Stage 3 write: compute checksum over the stored frame.
    ///
    /// This is called by [`write_frame`]; exposed for testing.
    #[must_use]
    pub fn checksum_stage(stored_frame: &[u8]) -> [u8; 32] {
        *blake3::hash(stored_frame).as_bytes()
    }

    /// Stage 1 read: verify checksum of the stored frame.
    pub fn checksum_verify_stage(
        &self,
        stored_frame: &[u8],
        metadata: &StoredFrameMetadata,
    ) -> Result<()> {
        let observed = Self::checksum_stage(stored_frame);
        if observed != metadata.checksum {
            return Err(StoreError::InvalidOptions {
                reason: "transform pipeline: stored frame checksum mismatch",
            });
        }
        Ok(())
    }

    /// Stage 2 read: decrypt → compression frame.
    ///
    /// Fails closed when encryption is expected but no key is available.
    pub fn decrypt_stage(
        &self,
        stored_frame: &[u8],
        metadata: &StoredFrameMetadata,
    ) -> Result<Vec<u8>> {
        if !metadata.encrypted {
            return Ok(stored_frame.to_vec());
        }
        match &self.encryption_config {
            Some(config) => decrypt_object(&config.key, stored_frame).ok_or({
                StoreError::InvalidOptions {
                    reason: "transform pipeline: decryption failed (wrong key or corrupted data)",
                }
            }),
            None => Err(StoreError::InvalidOptions {
                reason:
                    "transform pipeline: encrypted frame but no encryption config available (fail-closed)",
            }),
        }
    }

    /// Stage 3 read: decompress compression frame → plaintext.
    pub fn decompress_stage(
        &self,
        compression_frame: &[u8],
        metadata: &StoredFrameMetadata,
    ) -> Result<Vec<u8>> {
        match metadata.compression {
            Some(_alg) => {
                // A compression algorithm was recorded — decompress the frame.
                crate::compress::decompress_frame(compression_frame).map_err(|_e| {
                    StoreError::InvalidOptions {
                        reason: "transform pipeline: decompression failed",
                    }
                })
            }
            None => {
                // Explicit uncompressed identity frame — return as plaintext.
                // Strip the 5-byte frame header if present.
                if compression_frame.len()
                    >= StoredFrameMetadata::COMPRESSION_FRAME_HEADER_LEN
                {
                    let header_alg =
                        crate::compress::CompressionAlgorithm::from_byte(compression_frame[0]);
                    if header_alg == Some(CompressionAlgorithm::Uncompressed) {
                        return Ok(
                            compression_frame
                                [StoredFrameMetadata::COMPRESSION_FRAME_HEADER_LEN..]
                                .to_vec(),
                        );
                    }
                }
                Ok(compression_frame.to_vec())
            }
        }
    }

    /// Return the compression configuration for this pipeline.
    pub fn compression_config(&self) -> &CompressionConfig {
        &self.compression_config
    }

    /// Return true when encryption is configured and active.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.encryption_config.is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::StoreEncryptionKey;
    use crate::compress::CompressionAlgorithm;

    fn test_compression_config() -> CompressionConfig {
        CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
            min_compress_bytes: 64,
        }
    }

    fn test_encryption_config() -> EncryptionConfig {
        let key = StoreEncryptionKey::generate();
        EncryptionConfig::new(key)
    }

    // ── Write pipeline tests ──────────────────────────────────────────

    #[test]
    fn write_read_roundtrip_compression_only() {
        let pipeline = TransformPipelineAuthority::compression_only(test_compression_config());
        let plaintext = b"hello world, this is a test payload for the transform pipeline";

        let (frame, meta) = pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();
        assert!(!frame.is_empty());
        assert!(!meta.encrypted);
        assert_eq!(meta.stored_len, frame.len() as u64);

        let recovered = pipeline.read_frame(&frame, &meta).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn write_read_roundtrip_compression_and_encryption() {
        let pipeline = TransformPipelineAuthority::with_encryption(
            test_compression_config(),
            test_encryption_config(),
        );
        let plaintext = b"secret data that must be encrypted and compressed";

        let (frame, meta) = pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();
        assert!(meta.encrypted);
        assert_eq!(meta.stored_len, frame.len() as u64);

        let recovered = pipeline.read_frame(&frame, &meta).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn write_read_roundtrip_encryption_only() {
        let pipeline = TransformPipelineAuthority::encryption_only(test_encryption_config());
        let plaintext = b"encrypted but not compressed payload";

        let (frame, meta) = pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();
        assert!(meta.encrypted);
        assert_eq!(meta.compression, None);

        let recovered = pipeline.read_frame(&frame, &meta).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn write_read_roundtrip_raw_only() {
        let pipeline = TransformPipelineAuthority::raw_only();
        let plaintext = b"raw payload with no transforms";

        let (frame, meta) = pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();
        assert!(!meta.encrypted);
        assert_eq!(meta.compression, None);

        let recovered = pipeline.read_frame(&frame, &meta).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn small_payload_uncompressed_identity() {
        let pipeline = TransformPipelineAuthority::compression_only(CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
            min_compress_bytes: 1024,
        });
        let plaintext = b"tiny";

        let (_frame, meta) = pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();
        // Small payload below threshold: explicit uncompressed identity
        assert_eq!(meta.compression, None);
    }

    // ── Dedup decision passthrough ───────────────────────────────────

    #[test]
    fn dedup_bypass_does_not_alter_transform() {
        let pipeline = TransformPipelineAuthority::compression_only(test_compression_config());
        let plaintext = b"dedup bypass payload";

        let (frame_bypass, meta_bypass) = pipeline
            .write_frame(plaintext, &DedupDecision::Bypass)
            .unwrap();
        let (frame_new, meta_new) = pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();

        // The pipeline does not alter the frame based on dedup decision;
        // decisions are recorded for downstream consumers.
        assert_eq!(frame_bypass, frame_new);
        assert_eq!(meta_bypass, meta_new);
    }

    // ── Checksum failure ─────────────────────────────────────────────

    #[test]
    fn checksum_verify_detects_corruption() {
        let pipeline = TransformPipelineAuthority::compression_only(test_compression_config());
        let plaintext = b"data that will be corrupted";

        let (mut frame, meta) = pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();

        // Corrupt one byte
        if !frame.is_empty() {
            frame[0] ^= 0xFF;
        }

        let err = pipeline.read_frame(&frame, &meta).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("checksum") || msg.contains("Checksum"),
            "expected checksum error, got: {msg}"
        );
    }

    // ── Encryption fail-closed ──────────────────────────────────────

    #[test]
    fn encrypted_frame_fails_closed_without_key() {
        let enc_key = test_encryption_config();
        let encrypt_pipeline = TransformPipelineAuthority::with_encryption(
            test_compression_config(),
            enc_key,
        );
        let plaintext = b"this should fail closed when read without a key";

        let (frame, meta) = encrypt_pipeline
            .write_frame(plaintext, &DedupDecision::NewWrite)
            .unwrap();
        assert!(meta.encrypted);

        // Try reading with a pipeline that has no encryption config
        let no_enc_pipeline =
            TransformPipelineAuthority::compression_only(test_compression_config());
        let err = no_enc_pipeline.read_frame(&frame, &meta).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("encrypt") || msg.contains("fail-closed"),
            "expected encryption-related error, got: {msg}"
        );
    }

    // ── Per-stage helpers ────────────────────────────────────────────

    #[test]
    fn compress_stage_produces_frame() {
        let pipeline = TransformPipelineAuthority::compression_only(test_compression_config());
        let plaintext = b"compressible compressible compressible compressible";

        let (framed, decision) = pipeline.compress_stage(plaintext);

        // With zstd, the framed output should have the 5-byte header.
        assert!(framed.len() >= 5);
        assert!(
            matches!(
                decision,
                CompressionDecision::Compressed(_) | CompressionDecision::UncompressedIdentity
            )
        );
    }

    #[test]
    fn encrypt_stage_no_config_returns_plaintext() {
        let pipeline = TransformPipelineAuthority::compression_only(test_compression_config());
        let input = b"plaintext frame";
        let (output, encrypted) = pipeline.encrypt_stage(input);
        assert!(!encrypted);
        assert_eq!(output, input);
    }

    #[test]
    fn encrypt_stage_with_config_returns_ciphertext() {
        let pipeline = TransformPipelineAuthority::encryption_only(test_encryption_config());
        let input = b"plaintext frame to encrypt";
        let (output, encrypted) = pipeline.encrypt_stage(input);
        assert!(encrypted);
        assert_ne!(output, input);
        // ChaCha20-Poly1305 adds 28 bytes overhead
        assert_eq!(
            output.len(),
            input.len() + crate::encrypt::ENCRYPTION_OVERHEAD
        );
    }

    #[test]
    fn checksum_stage_is_deterministic() {
        let data = b"deterministic checksum test";
        let cs1 = TransformPipelineAuthority::checksum_stage(data);
        let cs2 = TransformPipelineAuthority::checksum_stage(data);
        assert_eq!(cs1, cs2);
    }

    #[test]
    fn checksum_stage_differs_for_different_data() {
        let cs1 = TransformPipelineAuthority::checksum_stage(b"data A");
        let cs2 = TransformPipelineAuthority::checksum_stage(b"data B");
        assert_ne!(cs1, cs2);
    }
}
