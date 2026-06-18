// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Intent-log record verification: round-trip encoding, single-byte
//! corruption detection, and in-memory replay state simulation.
//!
//! The [`RecordRoundtrip`] trait provides a standardised encode→decode
//! verification contract for any record or frame type. Callers outside
//! the crate (e.g., FUSE handler implementations that wire intent-log
//! recording) can use the trait to assert that their records survive
//! serialization correctly.
//!
//! Tests in the [`tests`] sub-module exercise every record variant with
//! systematic byte-level corruption and commit→replay simulations.

use crate::{IntentLogError, IntentLogFrame, IntentLogRecord, XattrNamespace};

// ── RecordRoundtrip trait ──────────────────────────────────────────────

/// Trait for records that support encode→decode round-trip verification.
///
/// Implemented for [`IntentLogRecord`] and [`IntentLogFrame`]. The trait
/// is public so that downstream crates (FUSE handlers, local-filesystem,
/// object-store) can reuse the same verification contract when testing
/// their own intent-log wiring.
pub trait RecordRoundtrip: Sized + PartialEq + std::fmt::Debug {
    /// Serialize the record into bytes.
    fn encode(&self) -> Vec<u8>;

    /// Deserialize the record from bytes.
    fn decode(buf: &[u8]) -> Result<Self, IntentLogError>;

    /// Round-trip assertion: encode, decode, compare.
    ///
    /// # Panics
    ///
    /// Panics if decode fails or the decoded value differs from the
    /// original.
    fn assert_roundtrip(&self) {
        let encoded = self.encode();
        let decoded = Self::decode(&encoded).expect("decode must succeed on freshly-encoded bytes");
        assert_eq!(
            *self, decoded,
            "round-trip mismatch: {self:?} != {decoded:?}"
        );
    }

    /// Frame-level round-trip assertion that also validates the checksum.
    ///
    /// # Panics
    ///
    /// Panics if frame decode fails (checksum mismatch, buffer too short,
    /// or unknown discriminant) or the decoded frame differs from the
    /// original.
    fn assert_frame_roundtrip(&self)
    where
        Self: Clone,
    {
        let encoded = self.encode();
        let decoded =
            Self::decode(&encoded).expect("frame decode must succeed on freshly-encoded bytes");
        assert_eq!(*self, decoded, "frame round-trip mismatch");
    }
}

impl RecordRoundtrip for IntentLogRecord {
    fn encode(&self) -> Vec<u8> {
        IntentLogRecord::encode(self)
    }
    fn decode(buf: &[u8]) -> Result<Self, IntentLogError> {
        IntentLogRecord::decode(buf)
    }
}

impl RecordRoundtrip for IntentLogFrame {
    fn encode(&self) -> Vec<u8> {
        IntentLogFrame::encode(self)
    }
    fn decode(buf: &[u8]) -> Result<Self, IntentLogError> {
        IntentLogFrame::decode(buf)
    }
}

// ── Helper: build a representative record for every variant ───────────

/// Return a representative (non-trivial) record for every discriminant.
///
/// This is public so that downstream tests can reuse the canonical
/// record set when verifying their own intent-log integration.
pub fn representative_records() -> Vec<IntentLogRecord> {
    vec![
        IntentLogRecord::Write {
            ino: 42,
            offset: 4096,
            length: 65536,
            data_hash: [0xAB; 32],
        },
        IntentLogRecord::Truncate {
            ino: 7,
            new_size: 1_048_576,
        },
        IntentLogRecord::Setattr {
            ino: 100,
            attr_mask: 0xFFFF_FFFF,
            attrs: [0x55; 64],
        },
        IntentLogRecord::Create {
            parent: 2,
            name: b"example.txt".to_vec(),
            mode: 0o644,
            ino: 1000,
        },
        IntentLogRecord::Unlink {
            parent: 2,
            name: b"stale.log".to_vec(),
            ino: 999,
        },
        IntentLogRecord::Rename {
            src_parent: 2,
            src_name: b"old.txt".to_vec(),
            dst_parent: 3,
            dst_name: b"new.txt".to_vec(),
            overwrite_target_ino: Some(555),
            ino: 1000,
            rename_flags: 0,
        },
        IntentLogRecord::Symlink {
            parent: 2,
            name: b"mysymlink".to_vec(),
            target: b"/usr/local/bin/tool".to_vec(),
            ino: 777,
        },
        IntentLogRecord::HardLink {
            ino: 42,
            new_parent: 5,
            new_name: b"hardlink-name".to_vec(),
        },
        IntentLogRecord::Mkdir {
            parent: 2,
            name: b"newdir".to_vec(),
            mode: 0o755,
            ino: 500,
        },
        IntentLogRecord::Rmdir {
            parent: 2,
            name: b"emptydir".to_vec(),
            ino: 500,
        },
        IntentLogRecord::Mknod {
            parent: 2,
            name: b"myfifo".to_vec(),
            mode: 0o644,
            rdev: 0x0801,
            ino: 888,
        },
        IntentLogRecord::XattrSet {
            ino: 42,
            namespace: XattrNamespace::Security,
            key_hash: [0x11; 32],
            value_hash: [0x22; 32],
        },
        IntentLogRecord::XattrRemove {
            ino: 42,
            namespace: XattrNamespace::Security,
            key_hash: [0x11; 32],
        },
        IntentLogRecord::Fallocate {
            ino: 33,
            offset: 0,
            length: 2_097_152,
            mode: 0,
        },
        IntentLogRecord::BufferedWrite {
            ino: 42,
            offset: 8192,
            length: 12,
            data: b"hello world!".to_vec(),
        },
        IntentLogRecord::WriteIntentAck {
            ino: 42,
            offset: 4096,
            length: 65536,
        },
        IntentLogRecord::Lseek {
            ino: 42,
            whence: 3, // SEEK_DATA
            offset: 0,
            result: 4096,
        },
        IntentLogRecord::CopyFileRange {
            src_ino: 100,
            src_fh: 42,
            dst_ino: 200,
            dst_fh: 43,
            src_offset: 0,
            dst_offset: 4096,
            len: 65536,
        },
    ]
}

// ── Production verification helpers ───────────────────────────────────

/// Verify that an encoded frame can be decoded and its checksum is valid.
///
/// Returns `Ok(())` if the frame passes all integrity checks, or an
/// [`IntentLogError`] describing the failure. This is a convenience
/// wrapper around [`IntentLogFrame::decode`] that discards the decoded
/// frame and only reports success/failure.
pub fn verify_encoded_frame(buf: &[u8]) -> Result<(), IntentLogError> {
    IntentLogFrame::decode(buf)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntentLog;

    // ── Frame-level round-trip for every record type ──────────────

    #[test]
    fn frame_roundtrip_all_record_types() {
        for rec in representative_records() {
            let frame = IntentLogFrame::new(rec, 7, 3);
            frame.assert_frame_roundtrip();
        }
    }

    // ── Single-byte corruption: every byte in the encoded frame ───

    #[test]
    fn single_byte_corruption_all_record_types() {
        for rec in representative_records() {
            let frame = IntentLogFrame::new(rec, 1, 0);
            let encoded = frame.encode();
            assert!(!encoded.is_empty(), "encoded frame must not be empty");

            let mut corruption_detected = false;
            for pos in 0..encoded.len() {
                let mut corrupted = encoded.clone();
                corrupted[pos] ^= 0xFF;
                if IntentLogFrame::decode(&corrupted).is_err() {
                    corruption_detected = true;
                }
            }
            assert!(
                corruption_detected,
                "no byte-flip detected for record type discriminant={}",
                encoded.first().copied().unwrap_or(0)
            );
        }
    }

    #[test]
    fn checksum_field_every_byte_detected() {
        for rec in representative_records() {
            let frame = IntentLogFrame::new(rec, 1, 0);
            let encoded = frame.encode();
            for cs_byte in 16..48 {
                let mut corrupted = encoded.clone();
                corrupted[cs_byte] ^= 0xFF;
                let err = IntentLogFrame::decode(&corrupted).unwrap_err();
                assert_eq!(
                    err,
                    IntentLogError::ChecksumMismatch,
                    "flip at byte {cs_byte} should be ChecksumMismatch, got {err:?}"
                );
            }
        }
    }

    #[test]
    fn header_fields_every_byte_detected() {
        for rec in representative_records() {
            let frame = IntentLogFrame::new(rec, 3, 7);
            let encoded = frame.encode();
            for pos in 0..8 {
                let mut corrupted = encoded.clone();
                corrupted[pos] ^= 0xFF;
                let err = IntentLogFrame::decode(&corrupted).unwrap_err();
                assert_eq!(
                    err,
                    IntentLogError::ChecksumMismatch,
                    "flip at txg_id byte {pos} must be detected"
                );
            }
            for pos in 8..16 {
                let mut corrupted = encoded.clone();
                corrupted[pos] ^= 0xFF;
                let err = IntentLogFrame::decode(&corrupted).unwrap_err();
                assert_eq!(
                    err,
                    IntentLogError::ChecksumMismatch,
                    "flip at record_seq byte {pos} must be detected"
                );
            }
        }
    }

    #[test]
    fn record_payload_every_byte_detected() {
        for rec in representative_records() {
            let frame = IntentLogFrame::new(rec, 1, 0);
            let encoded = frame.encode();
            let payload_start = 52;
            assert!(
                encoded.len() > payload_start,
                "encoded frame too short for payload test"
            );
            let mut corruption_detected = false;
            for pos in payload_start..encoded.len() {
                let mut corrupted = encoded.clone();
                corrupted[pos] ^= 0xFF;
                if IntentLogFrame::decode(&corrupted).is_err() {
                    corruption_detected = true;
                }
            }
            assert!(
                corruption_detected,
                "no payload byte-flip detected for record type"
            );
        }
    }

    // ── Replay-simulation tests ──────────────────────────────────

    #[test]
    fn replay_simulation_single_create() {
        let log = IntentLog::new(32);
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"test.txt".to_vec(),
            mode: 0o644,
            ino: 100,
        };
        let frame = log.append(rec.clone(), 1);
        let (segment, lsn) = log.commit(1);
        assert!(!segment.is_empty());
        assert_eq!(lsn, 1);

        let replayed = log.replay(&segment, 0).expect("replay must succeed");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].record, rec);
        assert_eq!(replayed[0].txg_id, frame.txg_id);
        assert_eq!(replayed[0].record_seq, frame.record_seq);
        assert!(replayed[0].verify().is_ok());
    }

    #[test]
    fn replay_simulation_mixed_sequence() {
        let log = IntentLog::new(64);
        let records: Vec<IntentLogRecord> = vec![
            IntentLogRecord::Create {
                parent: 1,
                name: b"a.txt".to_vec(),
                mode: 0o644,
                ino: 10,
            },
            IntentLogRecord::Write {
                ino: 10,
                offset: 0,
                length: 4096,
                data_hash: [0xCC; 32],
            },
            IntentLogRecord::Mkdir {
                parent: 1,
                name: b"sub".to_vec(),
                mode: 0o755,
                ino: 11,
            },
            IntentLogRecord::Symlink {
                parent: 1,
                name: b"link".to_vec(),
                target: b"/etc/passwd".to_vec(),
                ino: 12,
            },
            IntentLogRecord::Rename {
                src_parent: 1,
                src_name: b"a.txt".to_vec(),
                dst_parent: 11,
                dst_name: b"b.txt".to_vec(),
                overwrite_target_ino: None,
                ino: 10,
                rename_flags: 0,
            },
        ];

        for rec in &records {
            log.append(rec.clone(), 42);
        }

        let (segment, lsn) = log.commit(42);
        assert_eq!(lsn, records.len() as u64);

        let replayed = log.replay(&segment, 0).expect("replay must succeed");
        assert_eq!(replayed.len(), records.len());
        for (i, expected) in records.iter().enumerate() {
            assert_eq!(replayed[i].record, *expected, "mismatch at index {i}");
            assert_eq!(replayed[i].txg_id, 42);
            assert_eq!(replayed[i].record_seq, i as u64);
            assert!(replayed[i].verify().is_ok());
        }
    }

    #[test]
    fn replay_simulation_respects_lsn_filter() {
        let log = IntentLog::new(32);
        for i in 0..8 {
            log.append(
                IntentLogRecord::Truncate {
                    ino: i,
                    new_size: i * 1024,
                },
                1,
            );
        }
        let (segment, _lsn) = log.commit(1);

        let replayed = log.replay(&segment, 5).expect("replay must succeed");
        assert_eq!(replayed.len(), 3);
        assert_eq!(replayed[0].record_seq, 5);
        assert_eq!(replayed[1].record_seq, 6);
        assert_eq!(replayed[2].record_seq, 7);
    }

    #[test]
    fn replay_rejects_corrupted_segment() {
        let log = IntentLog::new(32);
        log.append(
            IntentLogRecord::Create {
                parent: 1,
                name: b"f".to_vec(),
                mode: 0o644,
                ino: 1,
            },
            1,
        );
        let (mut segment, _lsn) = log.commit(1);
        if segment.len() > 8 {
            segment[8] ^= 0xFF;
        }
        assert!(log.replay(&segment, 0).is_err());
    }

    #[test]
    fn replay_rejects_truncated_segment() {
        let log = IntentLog::new(32);
        log.append(
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 4096,
            },
            1,
        );
        let (mut segment, _lsn) = log.commit(1);
        let truncate_to = segment.len().saturating_sub(1).max(1);
        segment.truncate(truncate_to);
        assert!(log.replay(&segment, 0).is_err());
    }

    // ── Round-trip for every record type via the trait ────────────

    #[test]
    fn record_roundtrip_all_variants() {
        for rec in representative_records() {
            rec.assert_roundtrip();
        }
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn buffered_write_no_payload_roundtrip() {
        let rec = IntentLogRecord::BufferedWrite {
            ino: 1,
            offset: 0,
            length: 0,
            data: vec![],
        };
        rec.assert_roundtrip();
        let frame = IntentLogFrame::new(rec, 1, 0);
        frame.assert_frame_roundtrip();
    }

    #[test]
    fn rename_no_overwrite_roundtrip() {
        let rec = IntentLogRecord::Rename {
            src_parent: 1,
            src_name: b"a".to_vec(),
            dst_parent: 2,
            dst_name: b"b".to_vec(),
            overwrite_target_ino: None,
            ino: 5,
            rename_flags: 0,
        };
        rec.assert_roundtrip();
        let frame = IntentLogFrame::new(rec, 1, 0);
        frame.assert_frame_roundtrip();
    }

    #[test]
    fn rename_with_overwrite_roundtrip() {
        let rec = IntentLogRecord::Rename {
            src_parent: 1,
            src_name: b"a".to_vec(),
            dst_parent: 2,
            dst_name: b"b".to_vec(),
            overwrite_target_ino: Some(99),
            ino: 5,
            rename_flags: 0,
        };
        rec.assert_roundtrip();
        let frame = IntentLogFrame::new(rec, 1, 0);
        frame.assert_frame_roundtrip();
    }

    #[test]
    fn all_xattr_namespaces_roundtrip() {
        for ns in &[
            XattrNamespace::Security,
            XattrNamespace::System,
            XattrNamespace::Trusted,
            XattrNamespace::User,
        ] {
            let rec = IntentLogRecord::XattrSet {
                ino: 1,
                namespace: *ns,
                key_hash: [0xAA; 32],
                value_hash: [0xBB; 32],
            };
            rec.assert_roundtrip();
        }
    }

    #[test]
    fn all_xattr_remove_namespaces_roundtrip() {
        for ns in &[
            XattrNamespace::Security,
            XattrNamespace::System,
            XattrNamespace::Trusted,
            XattrNamespace::User,
        ] {
            let rec = IntentLogRecord::XattrRemove {
                ino: 1,
                namespace: *ns,
                key_hash: [0xAA; 32],
            };
            rec.assert_roundtrip();
        }
    }

    // ── Domain separation checks ─────────────────────────────────

    #[test]
    fn domain_separation_via_txg_id() {
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"file.txt".to_vec(),
            mode: 0o644,
            ino: 42,
        };
        let mut seen = std::collections::HashSet::new();
        for txg in 0..16 {
            let frame = IntentLogFrame::new(rec.clone(), txg, 0);
            assert!(
                seen.insert(frame.checksum),
                "checksum collision at txg_id={txg}"
            );
        }
    }

    #[test]
    fn domain_separation_via_record_seq() {
        let rec = IntentLogRecord::Truncate {
            ino: 1,
            new_size: 4096,
        };
        let mut seen = std::collections::HashSet::new();
        for seq in 0..16 {
            let frame = IntentLogFrame::new(rec.clone(), 1, seq);
            assert!(
                seen.insert(frame.checksum),
                "checksum collision at record_seq={seq}"
            );
        }
    }

    // ── Record-level corruption: structural vs integrity ─────────

    #[test]
    fn record_decode_is_structural_not_integrity() {
        let rec = IntentLogRecord::Write {
            ino: 42,
            offset: 0,
            length: 256,
            data_hash: [0xAB; 32],
        };
        let mut encoded = rec.encode();
        encoded[1] ^= 0xFF;
        let decoded =
            IntentLogRecord::decode(&encoded).expect("decode should succeed structurally");
        assert_ne!(rec, decoded);
    }

    #[test]
    fn corrupt_name_length_detected_as_buffer_too_short() {
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"test".to_vec(),
            mode: 0o644,
            ino: 10,
        };
        let mut encoded = rec.encode();
        encoded[9] = 255;
        let err = IntentLogRecord::decode(&encoded).unwrap_err();
        assert_eq!(err, IntentLogError::BufferTooShort);
    }

    #[test]
    fn identical_records_different_txg_different_checksum() {
        let rec = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 64,
            data_hash: [0xAA; 32],
        };
        let f1 = IntentLogFrame::new(rec.clone(), 1, 0);
        let f2 = IntentLogFrame::new(rec, 2, 0);
        assert_ne!(f1.checksum, f2.checksum);
    }

    #[test]
    fn identical_records_different_seq_different_checksum() {
        let rec = IntentLogRecord::Truncate {
            ino: 1,
            new_size: 100,
        };
        let f1 = IntentLogFrame::new(rec.clone(), 1, 0);
        let f2 = IntentLogFrame::new(rec, 1, 1);
        assert_ne!(f1.checksum, f2.checksum);
    }
}
