#![no_std]
#![forbid(unsafe_code)]

//! `schema_codec` fixed-width LE codecs for the first `posix_filesystem_adapter` wake-receipt surface.

use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterId128, PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
    PosixFilesystemAdapterProductWakeReceiptRecord,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub expected_len: usize,
    pub actual_len: usize,
}

pub trait CanonicalFixedWidth: Sized {
    const ENCODED_LEN: usize;

    fn encode_le(&self, out: &mut [u8]);
    /// Decode a fixed-width value from LE bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if `bytes.len()` does not match [`ENCODED_LEN`](Self::ENCODED_LEN).
    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// Validates that `bytes` has the expected length.
///
/// # Errors
///
/// Returns [`DecodeError`] if `bytes.len()` does not equal `expected_len`.
const fn expect_len(bytes: &[u8], expected_len: usize) -> Result<(), DecodeError> {
    if bytes.len() == expected_len {
        Ok(())
    } else {
        Err(DecodeError {
            expected_len,
            actual_len: bytes.len(),
        })
    }
}

fn write_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_bytes(out: &mut [u8], offset: usize, bytes: &[u8]) {
    out[offset..offset + bytes.len()].copy_from_slice(bytes);
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0_u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes[offset..offset + N]);
    out
}

impl CanonicalFixedWidth for PosixFilesystemAdapterId128 {
    const ENCODED_LEN: usize = 16;

    fn encode_le(&self, out: &mut [u8]) {
        out[..16].copy_from_slice(&self.0);
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self(read_array::<16>(bytes, 0)))
    }
}

impl CanonicalFixedWidth for PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs {
    const ENCODED_LEN: usize = 96;

    fn encode_le(&self, out: &mut [u8]) {
        write_bytes(out, 0, &self.witness_join_id.0);
        write_bytes(out, 16, &self.policy_witness_id.0);
        write_bytes(out, 32, &self.budget_witness_id.0);
        write_bytes(out, 48, &self.recipe_witness_id.0);
        write_bytes(out, 64, &self.witness_join_digest);
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self {
            witness_join_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 0)),
            policy_witness_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 16)),
            budget_witness_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 32)),
            recipe_witness_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 48)),
            witness_join_digest: read_array::<32>(bytes, 64),
        })
    }
}

impl CanonicalFixedWidth for PosixFilesystemAdapterProductWakeReceiptRecord {
    const ENCODED_LEN: usize = 256;

    fn encode_le(&self, out: &mut [u8]) {
        write_bytes(out, 0, &self.wake_receipt_id.0);
        write_bytes(out, 16, &self.request_id.0);
        write_bytes(out, 32, &self.journal_id.0);
        write_bytes(out, 48, &self.response_registry_receipt_id.0);
        write_bytes(out, 64, &self.publication_pipeline_ticket_id_or_zero.0);
        write_u32_le(out, 80, self.wake_class);
        write_u32_le(out, 84, self.visibility_class);
        write_u64_le(out, 88, self._reserved0);
        write_bytes(out, 96, &self.answer_digest);
        write_bytes(out, 128, &self.artifact_locator_digest);
        write_bytes(out, 160, &self.witness_refs.witness_join_id.0);
        write_bytes(out, 176, &self.witness_refs.policy_witness_id.0);
        write_bytes(out, 192, &self.witness_refs.budget_witness_id.0);
        write_bytes(out, 208, &self.witness_refs.recipe_witness_id.0);
        write_bytes(out, 224, &self.witness_refs.witness_join_digest);
    }

    fn decode_le(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, Self::ENCODED_LEN)?;
        Ok(Self {
            wake_receipt_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 0)),
            request_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 16)),
            journal_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 32)),
            response_registry_receipt_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 48)),
            publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128(read_array::<16>(
                bytes, 64,
            )),
            wake_class: read_u32_le(bytes, 80),
            visibility_class: read_u32_le(bytes, 84),
            _reserved0: read_u64_le(bytes, 88),
            answer_digest: read_array::<32>(bytes, 96),
            artifact_locator_digest: read_array::<32>(bytes, 128),
            witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs {
                witness_join_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 160)),
                policy_witness_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 176)),
                budget_witness_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 192)),
                recipe_witness_id: PosixFilesystemAdapterId128(read_array::<16>(bytes, 208)),
                witness_join_digest: read_array::<32>(bytes, 224),
            },
        })
    }
}

// TURN3_HUMAN_POSIX_FILESYSTEM_ADAPTER_SCHEMA_CODEC_ALIASES
/// Human-named module for Canonical Schema Codec helpers.
pub mod posix_filesystem_adapter_schema_codec {
    pub const FAMILY_NAME: &str = "Canonical Schema Codec";
    pub const STABLE_SOURCE_LOCATOR: &str = "schema_codec";
    pub const ROLE: &str = "fixed-width little-endian encode/decode records and packet codecs";

    pub use crate::{CanonicalFixedWidth, DecodeError};
}

/// Human alias namespace. Prefer `human::posix_filesystem_adapter_schema_codec::*` in new examples.
pub mod human {
    pub mod posix_filesystem_adapter_schema_codec {
        pub use crate::posix_filesystem_adapter_schema_codec::*;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use tidefs_types_posix_filesystem_adapter_core::{
        PosixFilesystemAdapterProductWakeReceiptDraft, PosixFilesystemAdapterVisibilityClass,
        PosixFilesystemAdapterWakeClass,
    };

    #[test]
    fn wake_receipt_round_trips() {
        let record = PosixFilesystemAdapterProductWakeReceiptRecord::new(
            PosixFilesystemAdapterProductWakeReceiptDraft {
                wake_receipt_id: PosixFilesystemAdapterId128::from_u128_le(0x11),
                request_id: PosixFilesystemAdapterId128::from_u128_le(0x22),
                journal_id: PosixFilesystemAdapterId128::from_u128_le(0x33),
                response_registry_receipt_id: PosixFilesystemAdapterId128::from_u128_le(0x44),
                publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128::from_u128_le(
                    0x55,
                ),
                wake_class: PosixFilesystemAdapterWakeClass::NamespaceProjection,
                visibility_class: PosixFilesystemAdapterVisibilityClass::CommittedVisible,
                answer_digest: [0xAA_u8; 32],
                artifact_locator_digest: [0xBB_u8; 32],
                witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                    PosixFilesystemAdapterId128::from_u128_le(0x66),
                    PosixFilesystemAdapterId128::from_u128_le(0x77),
                    PosixFilesystemAdapterId128::from_u128_le(0x88),
                    PosixFilesystemAdapterId128::from_u128_le(0x99),
                    [0xCC_u8; 32],
                ),
            },
        );
        let mut bytes = [0_u8; PosixFilesystemAdapterProductWakeReceiptRecord::ENCODED_LEN];
        record.encode_le(&mut bytes);
        let decoded =
            PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&bytes).expect("decode");
        assert_eq!(decoded, record);
        assert_eq!(
            decoded.wake_class(),
            Ok(PosixFilesystemAdapterWakeClass::NamespaceProjection)
        );
        assert_eq!(
            decoded.visibility(),
            Ok(PosixFilesystemAdapterVisibilityClass::CommittedVisible)
        );
        assert!(decoded.has_witness_join());
    }

    #[test]
    fn posix_adapter_id_round_trips() {
        let id = PosixFilesystemAdapterId128::from_u128_le(0xDEAD_BEEF_CAFE_BABE);
        let mut buf = [0_u8; PosixFilesystemAdapterId128::ENCODED_LEN];
        id.encode_le(&mut buf);
        let decoded = PosixFilesystemAdapterId128::decode_le(&buf).expect("decode");
        assert_eq!(decoded, id);
    }

    #[test]
    fn policy_budget_recipe_witness_refs_round_trips() {
        let refs = PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
            PosixFilesystemAdapterId128::from_u128_le(0x11),
            PosixFilesystemAdapterId128::from_u128_le(0x22),
            PosixFilesystemAdapterId128::from_u128_le(0x33),
            PosixFilesystemAdapterId128::from_u128_le(0x44),
            [0xAA_u8; 32],
        );
        let mut buf = [0_u8; PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::ENCODED_LEN];
        refs.encode_le(&mut buf);
        let decoded =
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::decode_le(&buf).expect("decode");
        assert_eq!(decoded, refs);
    }

    #[test]
    fn wrong_length_is_rejected_posix_adapter_id() {
        let err = PosixFilesystemAdapterId128::decode_le(&[0_u8; 8]).expect_err("must fail");
        assert_eq!(err.expected_len, 16);
        assert_eq!(err.actual_len, 8);
    }

    #[test]
    fn wrong_length_is_rejected_witness_refs() {
        let err = PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::decode_le(&[0_u8; 32])
            .expect_err("must fail");
        assert_eq!(err.expected_len, 96);
        assert_eq!(err.actual_len, 32);
    }

    #[test]
    fn wrong_length_is_rejected_wake_receipt() {
        let err = PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&[0_u8; 128])
            .expect_err("must fail");
        assert_eq!(err.expected_len, 256);
        assert_eq!(err.actual_len, 128);
    }

    #[test]
    fn empty_input_rejected_all_types() {
        assert!(PosixFilesystemAdapterId128::decode_le(&[]).is_err());
        assert!(PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::decode_le(&[]).is_err());
        assert!(PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&[]).is_err());
    }

    #[test]
    fn one_byte_input_rejected_all_types() {
        assert!(PosixFilesystemAdapterId128::decode_le(&[0_u8; 1]).is_err());
        assert!(
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::decode_le(&[0_u8; 1]).is_err()
        );
        assert!(PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&[0_u8; 1]).is_err());
    }

    #[test]
    fn one_byte_short_rejected_all_types() {
        assert!(PosixFilesystemAdapterId128::decode_le(&[0_u8; 15]).is_err());
        assert!(
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::decode_le(&[0_u8; 95]).is_err()
        );
        assert!(PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&[0_u8; 255]).is_err());
    }

    #[test]
    fn one_byte_over_rejected_all_types() {
        assert!(PosixFilesystemAdapterId128::decode_le(&[0_u8; 17]).is_err());
        assert!(
            PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::decode_le(&[0_u8; 97]).is_err()
        );
        assert!(PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&[0_u8; 257]).is_err());
    }

    #[test]
    fn oversized_input_rejected() {
        let big = [0xAA_u8; 1024];
        assert!(PosixFilesystemAdapterId128::decode_le(&big).is_err());
        assert!(PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::decode_le(&big).is_err());
        assert!(PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&big).is_err());
    }

    #[test]
    fn decode_error_equality() {
        let e1 = DecodeError {
            expected_len: 16,
            actual_len: 8,
        };
        let e2 = DecodeError {
            expected_len: 16,
            actual_len: 8,
        };
        let e3 = DecodeError {
            expected_len: 16,
            actual_len: 4,
        };
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn non_zero_ids_roundtrip() {
        let record = PosixFilesystemAdapterProductWakeReceiptRecord::new(
            PosixFilesystemAdapterProductWakeReceiptDraft {
                wake_receipt_id: PosixFilesystemAdapterId128::from_u128_le(0xFFFF_FFFF_FFFF_FFFF),
                request_id: PosixFilesystemAdapterId128::from_u128_le(0xEEEE_EEEE_EEEE_EEEE),
                journal_id: PosixFilesystemAdapterId128::from_u128_le(0xDDDD_DDDD_DDDD_DDDD),
                response_registry_receipt_id: PosixFilesystemAdapterId128::from_u128_le(
                    0xCCCC_CCCC_CCCC_CCCC,
                ),
                publication_pipeline_ticket_id_or_zero: PosixFilesystemAdapterId128::from_u128_le(
                    0xBBBB_BBBB_BBBB_BBBB,
                ),
                wake_class: PosixFilesystemAdapterWakeClass::NamespaceProjection,
                visibility_class: PosixFilesystemAdapterVisibilityClass::CommittedVisible,
                answer_digest: [0xFF_u8; 32],
                artifact_locator_digest: [0xFE_u8; 32],
                witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
                    PosixFilesystemAdapterId128::from_u128_le(0xAAAA_AAAA_AAAA_AAAA),
                    PosixFilesystemAdapterId128::from_u128_le(0xBBBB_BBBB_BBBB_BBBB),
                    PosixFilesystemAdapterId128::from_u128_le(0xCCCC_CCCC_CCCC_CCCC),
                    PosixFilesystemAdapterId128::from_u128_le(0xDDDD_DDDD_DDDD_DDDD),
                    [0xFF_u8; 32],
                ),
            },
        );
        let mut buf = [0_u8; PosixFilesystemAdapterProductWakeReceiptRecord::ENCODED_LEN];
        record.encode_le(&mut buf);
        let decoded =
            PosixFilesystemAdapterProductWakeReceiptRecord::decode_le(&buf).expect("decode");
        assert_eq!(decoded, record);
    }

    // ── golden vector decode tests ─────────────────────────────────────

    /// Decode golden binary → check canonical fields → re-encode must match.
    fn assert_golden_decode_roundtrip<T: CanonicalFixedWidth + core::fmt::Debug + PartialEq>(
        name: &str,
        golden: &[u8],
        check: impl FnOnce(&T),
    ) {
        let decoded = T::decode_le(golden).unwrap_or_else(|e| {
            panic!(
                "golden decode failed for {name}: expected_len={exp}, actual_len={act}",
                exp = e.expected_len,
                act = e.actual_len
            )
        });
        check(&decoded);
        let mut re_buf = std::vec![0_u8; golden.len()];
        decoded.encode_le(&mut re_buf);
        assert_eq!(
            re_buf, golden,
            "re-encode of {name} does not match golden binary"
        );
    }

    #[test]
    fn golden_decode_wake_receipt_record() {
        let golden = include_bytes!("../../../validation/format-golden/posix-filesystem-adapter_posixfilesystemadapterproductwakereceiptrecord.bin");
        assert_golden_decode_roundtrip::<PosixFilesystemAdapterProductWakeReceiptRecord>(
            "PosixFilesystemAdapterProductWakeReceiptRecord",
            golden,
            |v| {
                assert_eq!(
                    v.wake_receipt_id.as_u128_le(),
                    0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1u128
                );
            },
        );
    }
}
