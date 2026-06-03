//! Parity RAID stripe layout engine.
//!
//! `ParityRaid1` implements single-parity (XOR) striping: given N data blocks
//! of equal size, it produces one parity block as the bytewise XOR of all
//! data blocks. Any single missing block (data or parity) can be reconstructed
//! by XOR-ing all surviving blocks.

use std::fmt;

/// Errors from parity_raid layout operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParityRaidError {
    /// Fewer than the minimum number of data columns.
    TooFewDataColumns { got: usize, min: usize },
    /// Data blocks have inconsistent lengths.
    StripeLengthMismatch {
        expected: usize,
        got: usize,
        column: usize,
    },
    /// At least one surviving block is required for reconstruction.
    EmptySurvivors,
    /// Not enough surviving blocks to reconstruct (need N total, got fewer).
    TooFewSurvivors { have: usize, need: usize },
    /// Exactly one missing column required for single-parity reconstruction.
    WrongMissingCount { missing: usize, expected: usize },
    /// Input buffer is empty.
    EmptyInput,
    /// Device tree is not a ParityRaid variant.
    NotParityRaid,
    /// Only parity=1 is supported; got a higher parity count.
    ParityNotSupported { got: u8, max: u8 },
}

impl fmt::Display for ParityRaidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewDataColumns { got, min } => {
                write!(f, "need at least {min} data columns, got {got}")
            }
            Self::StripeLengthMismatch {
                expected,
                got,
                column,
            } => {
                write!(f, "column {column}: expected length {expected}, got {got}")
            }
            Self::EmptySurvivors => f.write_str("at least one surviving block required"),
            Self::TooFewSurvivors { have, need } => {
                write!(f, "need {need} surviving blocks, got {have}")
            }
            Self::WrongMissingCount { missing, expected } => {
                write!(f, "expected {expected} missing column, got {missing}")
            }
            Self::EmptyInput => f.write_str("input buffer is empty"),
            Self::NotParityRaid => f.write_str("device tree is not a ParityRaid topology"),
            Self::ParityNotSupported { got, max } => {
                write!(f, "parity count {got} not supported (max {max})")
            }
        }
    }
}

/// ParityRaid1: single-parity XOR stripe layout.
///
/// Computes one parity block per stripe by bytewise XOR across all data
/// blocks. Can reconstruct any single missing block from the surviving
/// blocks.
pub struct ParityRaid1;

impl ParityRaid1 {
    /// Minimum number of data columns for meaningful parity_raid1.
    pub const MIN_DATA_COLUMNS: usize = 2;

    /// Compute the parity block for a set of data blocks.
    ///
    /// All data blocks must be the same length. Returns a parity block of
    /// that length. An empty input slice returns an empty parity block.
    ///
    /// # Panics
    ///
    /// Panics if data blocks have different lengths.
    pub fn compute(data_blocks: &[&[u8]]) -> Vec<u8> {
        if data_blocks.is_empty() {
            return Vec::new();
        }
        let len = data_blocks[0].len();
        let mut parity = vec![0u8; len];
        for block in data_blocks {
            assert_eq!(
                block.len(),
                len,
                "All data blocks must have the same length"
            );
            for (p, &b) in parity.iter_mut().zip(block.iter()) {
                *p ^= b;
            }
        }
        parity
    }

    /// Split a buffer into `n_data` equal-sized data columns plus one XOR
    /// parity column.
    ///
    /// Returns `n_data + 1` columns: data columns at indices `0..n_data`,
    /// parity column at index `n_data`. All columns have the same length.
    ///
    /// The buffer is zero-padded at the end if not evenly divisible by
    /// `n_data`, so every data column has the same length.
    ///
    /// # Errors
    ///
    /// Returns [`ParityRaidError::TooFewDataColumns`] when `n_data < 2`.
    /// Returns [`ParityRaidError::EmptyInput`] when `buf` is empty.
    pub fn stripe_write(buf: &[u8], n_data: usize) -> Result<Vec<Vec<u8>>, ParityRaidError> {
        if n_data < Self::MIN_DATA_COLUMNS {
            return Err(ParityRaidError::TooFewDataColumns {
                got: n_data,
                min: Self::MIN_DATA_COLUMNS,
            });
        }
        if buf.is_empty() {
            return Err(ParityRaidError::EmptyInput);
        }

        let col_len = buf.len().div_ceil(n_data);

        let mut data: Vec<Vec<u8>> = Vec::with_capacity(n_data);
        for i in 0..n_data {
            let start = i * col_len;
            let end = (start + col_len).min(buf.len());
            let mut col = vec![0u8; col_len];
            col[..end - start].copy_from_slice(&buf[start..end]);
            data.push(col);
        }

        let mut parity = vec![0u8; col_len];
        for col in &data {
            xor_into(&mut parity, col);
        }
        data.push(parity);

        Ok(data)
    }

    /// Reconstruct a single missing block from the surviving blocks.
    ///
    /// The surviving blocks must include all data+parity blocks except one.
    /// All surviving blocks must have the same length. Returns the
    /// reconstructed block (same length). Since XOR is its own inverse, the
    /// reconstruction is simply the XOR of all surviving blocks.
    ///
    /// # Panics
    ///
    /// Panics if the survivors slice is empty or if survivors have different
    /// lengths.
    pub fn reconstruct_from_survivors(survivors: &[&[u8]]) -> Vec<u8> {
        assert!(
            !survivors.is_empty(),
            "At least one surviving block is required for reconstruction"
        );
        // For XOR parity, the missing block is the XOR of all survivors.
        Self::compute(survivors)
    }

    /// Reconstruct the data at a specific missing position within a stripe.
    ///
    /// `stripe_blocks` is the full stripe (data + parity), with `None` at
    /// the position of the missing block. For ParityRaid1, exactly one
    /// position must be `None` and all present blocks must be the same
    /// length.
    ///
    /// Returns the reconstructed block. Returns `None` if zero or more than
    /// one block is missing.
    pub fn reconstruct(stripe_blocks: &[Option<&[u8]>]) -> Option<Vec<u8>> {
        let missing_count = stripe_blocks.iter().filter(|b| b.is_none()).count();
        if missing_count != 1 {
            return None;
        }
        let survivors: Vec<&[u8]> = stripe_blocks.iter().filter_map(|b| *b).collect();
        if survivors.is_empty() {
            return None;
        }
        Some(Self::reconstruct_from_survivors(&survivors))
    }

    /// Reconstruct a single missing column from the surviving columns.
    ///
    /// `missing_idx` is the 0-based index of the missing column
    /// (0..n_data for a data column, n_data for the parity column).
    /// `survivors` must contain every column except the missing one,
    /// in their original order. All stripes must have the same length.
    ///
    /// # Errors
    ///
    /// Returns [`ParityRaidError::StripeLengthMismatch`] when survivors have
    /// inconsistent lengths.
    /// Returns [`ParityRaidError::EmptySurvivors`] when survivors is empty.
    pub fn stripe_reconstruct(
        missing_idx: usize,
        survivors: &[&[u8]],
        total_cols: usize,
    ) -> Result<Vec<u8>, ParityRaidError> {
        if missing_idx >= total_cols {
            return Err(ParityRaidError::TooFewSurvivors {
                have: 0,
                need: total_cols - 1,
            });
        }
        let need = total_cols - 1;
        if survivors.len() < need {
            return Err(ParityRaidError::TooFewSurvivors {
                have: survivors.len(),
                need,
            });
        }
        if survivors.is_empty() {
            return Err(ParityRaidError::EmptySurvivors);
        }

        let col_len = survivors[0].len();
        for (i, stripe) in survivors.iter().enumerate() {
            if stripe.len() != col_len {
                return Err(ParityRaidError::StripeLengthMismatch {
                    expected: col_len,
                    got: stripe.len(),
                    column: i,
                });
            }
        }

        let mut reconstructed = vec![0u8; col_len];
        for stripe in survivors {
            xor_into(&mut reconstructed, stripe);
        }
        Ok(reconstructed)
    }

    /// Verify the parity block against the data blocks.
    ///
    /// Returns `true` if XOR of all data blocks equals the provided parity.
    /// Returns `true` if data_blocks is empty (trivially consistent).
    pub fn verify_parity(data_blocks: &[&[u8]], parity: &[u8]) -> bool {
        if data_blocks.is_empty() {
            return true;
        }
        let col_len = data_blocks[0].len();
        if parity.len() != col_len {
            return false;
        }
        let computed = Self::compute(data_blocks);
        computed == parity
    }
}

// ── Internal: XOR src into dst in-place ──────────────────────────────

#[inline]
fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len(), "xor_into: length mismatch");
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compute ──────────────────────────────────────────────────────

    #[test]
    fn compute_two_data_blocks() {
        let d0: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let d1: &[u8] = &[0x10, 0x20, 0x30, 0x40];
        let parity = ParityRaid1::compute(&[d0, d1]);
        assert_eq!(parity[0], 0x11);
        assert_eq!(parity[1], 0x22);
        assert_eq!(parity[2], 0x33);
        assert_eq!(parity[3], 0x44);
    }

    #[test]
    fn compute_four_data_blocks() {
        let d0: &[u8] = &[0xAA, 0xBB, 0xCC];
        let d1: &[u8] = &[0x11, 0x22, 0x33];
        let d2: &[u8] = &[0x44, 0x55, 0x66];
        let d3: &[u8] = &[0x77, 0x88, 0x99];
        let parity = ParityRaid1::compute(&[d0, d1, d2, d3]);
        let expected: Vec<u8> = (0..3).map(|i| d0[i] ^ d1[i] ^ d2[i] ^ d3[i]).collect();
        assert_eq!(parity, expected);
    }

    #[test]
    fn compute_single_data_block_parity_equals_data() {
        let d0: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let parity = ParityRaid1::compute(&[d0]);
        assert_eq!(parity, d0);
    }

    #[test]
    fn compute_all_zero_data_stripe() {
        let d0: &[u8] = &[0u8; 64];
        let d1: &[u8] = &[0u8; 64];
        let d2: &[u8] = &[0u8; 64];
        let parity = ParityRaid1::compute(&[d0, d1, d2]);
        assert_eq!(parity, &[0u8; 64][..]);
    }

    #[test]
    fn compute_empty_input_returns_empty() {
        let parity = ParityRaid1::compute(&[]);
        assert!(parity.is_empty());
    }

    #[test]
    fn compute_empty_blocks_zero_length() {
        let d0: &[u8] = &[];
        let d1: &[u8] = &[];
        let parity = ParityRaid1::compute(&[d0, d1]);
        assert!(parity.is_empty());
    }

    #[test]
    fn compute_eight_data_blocks() {
        let blocks: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; 128]).collect();
        let refs: Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
        let parity = ParityRaid1::compute(&refs);
        // XOR of 0..7 across the bytes - each byte is the same value
        // 0^1^2^3^4^5^6^7 = 0
        assert_eq!(parity.len(), 128);
        assert!(parity.iter().all(|&b| b == 0));
    }

    // ── stripe_write ─────────────────────────────────────────────────

    #[test]
    fn stripe_write_even_split() {
        let data = b"abcdef"; // 6 bytes, 3 columns = 2 bytes each
        let stripes = ParityRaid1::stripe_write(data, 3).unwrap();
        assert_eq!(stripes.len(), 4); // 3 data + 1 parity
        assert_eq!(stripes[0], b"ab");
        assert_eq!(stripes[1], b"cd");
        assert_eq!(stripes[2], b"ef");
        // parity: ab XOR cd XOR ef
        let expected_parity = vec![b'a' ^ b'c' ^ b'e', b'b' ^ b'd' ^ b'f'];
        assert_eq!(stripes[3], expected_parity);
    }

    #[test]
    fn stripe_write_uneven_split_zero_pads() {
        let data = b"abcde"; // 5 bytes, 3 columns = 2 bytes each, last column zero-padded
        let stripes = ParityRaid1::stripe_write(data, 3).unwrap();
        assert_eq!(stripes.len(), 4);
        assert_eq!(stripes[0], b"ab");
        assert_eq!(stripes[1], b"cd");
        assert_eq!(&stripes[2][..1], b"e");
        assert_eq!(stripes[2][1], 0); // zero-padded
    }

    #[test]
    fn stripe_write_round_trip() {
        let original = b"hello parity_raid1 stripe write round trip test payload!";
        for n_data in 2..=8 {
            let stripes = ParityRaid1::stripe_write(original, n_data).unwrap();
            assert_eq!(stripes.len(), n_data + 1);
            // Reassemble data from first n_data columns, truncating to original length
            let mut reassembled = Vec::new();
            for stripe in stripes.iter().take(n_data) {
                reassembled.extend_from_slice(stripe);
            }
            reassembled.truncate(original.len());
            assert_eq!(
                reassembled, original,
                "round-trip failed for n_data={n_data}"
            );
        }
    }

    #[test]
    fn stripe_write_too_few_data_columns() {
        let result = ParityRaid1::stripe_write(b"data", 1);
        assert!(matches!(
            result,
            Err(ParityRaidError::TooFewDataColumns { got: 1, min: 2 })
        ));
    }

    #[test]
    fn stripe_write_empty_input() {
        let result = ParityRaid1::stripe_write(b"", 3);
        assert!(matches!(result, Err(ParityRaidError::EmptyInput)));
    }

    #[test]
    fn stripe_write_single_byte() {
        let stripes = ParityRaid1::stripe_write(&[0x42], 2).unwrap();
        assert_eq!(stripes.len(), 3);
        assert_eq!(stripes[0], vec![0x42]);
        assert_eq!(stripes[1], vec![0x00]);
        assert_eq!(stripes[2], vec![0x42]); // parity = 0x42 XOR 0x00 = 0x42
    }

    // ── reconstruct_from_survivors ───────────────────────────────────

    #[test]
    fn reconstruct_missing_data_block_2plus1() {
        let d0: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let d1: &[u8] = &[0x10, 0x20, 0x30, 0x40];
        let parity = ParityRaid1::compute(&[d0, d1]);

        let rebuilt = ParityRaid1::reconstruct_from_survivors(&[d0, &parity]);
        assert_eq!(rebuilt, d1);

        let rebuilt = ParityRaid1::reconstruct_from_survivors(&[d1, &parity]);
        assert_eq!(rebuilt, d0);
    }

    #[test]
    fn reconstruct_missing_data_block_4plus1() {
        let d0: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let d1: &[u8] = &[0x11, 0x22, 0x33, 0x44];
        let d2: &[u8] = &[0x55, 0x66, 0x77, 0x88];
        let d3: &[u8] = &[0x99, 0xAA, 0xBB, 0xCC];
        let parity = ParityRaid1::compute(&[d0, d1, d2, d3]);

        let rebuilt_d0 = ParityRaid1::reconstruct_from_survivors(&[d1, d2, d3, &parity]);
        assert_eq!(rebuilt_d0, d0);

        let rebuilt_d1 = ParityRaid1::reconstruct_from_survivors(&[d0, d2, d3, &parity]);
        assert_eq!(rebuilt_d1, d1);

        let rebuilt_d2 = ParityRaid1::reconstruct_from_survivors(&[d0, d1, d3, &parity]);
        assert_eq!(rebuilt_d2, d2);

        let rebuilt_d3 = ParityRaid1::reconstruct_from_survivors(&[d0, d1, d2, &parity]);
        assert_eq!(rebuilt_d3, d3);
    }

    #[test]
    fn reconstruct_missing_parity() {
        let d0: &[u8] = &[0xDE, 0xAD];
        let d1: &[u8] = &[0xBE, 0xEF];
        let d2: &[u8] = &[0xCA, 0xFE];
        let parity = ParityRaid1::compute(&[d0, d1, d2]);
        let rebuilt = ParityRaid1::reconstruct_from_survivors(&[d0, d1, d2]);
        assert_eq!(rebuilt, parity);
    }

    // ── reconstruct (position-aware) ─────────────────────────────────

    #[test]
    fn reconstruct_position_aware_data_loss() {
        let d0: &[u8] = &[0x01, 0x02];
        let d1: &[u8] = &[0x03, 0x04];
        let d2: &[u8] = &[0x05, 0x06];
        let parity = ParityRaid1::compute(&[d0, d1, d2]);
        let stripe: &[Option<&[u8]>] = &[Some(d0), None, Some(d2), Some(&parity)];
        let rebuilt = ParityRaid1::reconstruct(stripe).unwrap();
        assert_eq!(rebuilt, d1);
    }

    #[test]
    fn reconstruct_position_aware_parity_loss() {
        let d0: &[u8] = &[0x0A, 0x0B];
        let d1: &[u8] = &[0x0C, 0x0D];
        let parity = ParityRaid1::compute(&[d0, d1]);
        let stripe: &[Option<&[u8]>] = &[Some(d0), Some(d1), None];
        let rebuilt = ParityRaid1::reconstruct(stripe).unwrap();
        assert_eq!(rebuilt, parity);
    }

    #[test]
    fn reconstruct_refuses_zero_missing() {
        let d0: &[u8] = &[0x01, 0x02];
        let d1: &[u8] = &[0x03, 0x04];
        let parity = ParityRaid1::compute(&[d0, d1]);
        let stripe: &[Option<&[u8]>] = &[Some(d0), Some(d1), Some(&parity)];
        assert!(ParityRaid1::reconstruct(stripe).is_none());
    }

    #[test]
    fn reconstruct_refuses_two_missing() {
        let d0: &[u8] = &[0x01, 0x02];
        let d1: &[u8] = &[0x03, 0x04];
        let parity = ParityRaid1::compute(&[d0, d1]);
        let stripe: &[Option<&[u8]>] = &[None, None, Some(&parity)];
        assert!(ParityRaid1::reconstruct(stripe).is_none());
    }

    // ── stripe_reconstruct ───────────────────────────────────────────

    #[test]
    fn stripe_reconstruct_data_column() {
        let stripes = ParityRaid1::stripe_write(b"hello parity_raid world", 4).unwrap();
        // Reconstruct data column 2 using other data columns + parity
        let survivors: Vec<&[u8]> = vec![
            stripes[0].as_slice(),
            stripes[1].as_slice(),
            stripes[3].as_slice(),
            stripes[4].as_slice(),
        ];
        let rebuilt = ParityRaid1::stripe_reconstruct(2, &survivors, 5).unwrap();
        assert_eq!(rebuilt, stripes[2]);
    }

    #[test]
    fn stripe_reconstruct_parity_column() {
        let stripes = ParityRaid1::stripe_write(b"rebuild parity column", 3).unwrap();
        let survivors: Vec<&[u8]> = vec![
            stripes[0].as_slice(),
            stripes[1].as_slice(),
            stripes[2].as_slice(),
        ];
        let rebuilt = ParityRaid1::stripe_reconstruct(3, &survivors, 4).unwrap();
        assert_eq!(rebuilt, stripes[3]);
    }

    #[test]
    fn stripe_reconstruct_out_of_bounds_index() {
        let result = ParityRaid1::stripe_reconstruct(5, &[b"data"], 5);
        assert!(result.is_err());
    }

    #[test]
    fn stripe_reconstruct_length_mismatch() {
        let survivors: Vec<&[u8]> = vec![b"abc", b"de", b"fgh"];
        let result = ParityRaid1::stripe_reconstruct(0, &survivors, 4);
        assert!(matches!(
            result,
            Err(ParityRaidError::StripeLengthMismatch { .. })
        ));
    }

    // ── verify_parity ────────────────────────────────────────────────

    #[test]
    fn verify_parity_passes_on_correct_data() {
        let d0: &[u8] = &[0x01, 0x02, 0x03];
        let d1: &[u8] = &[0x10, 0x20, 0x30];
        let parity = ParityRaid1::compute(&[d0, d1]);
        assert!(ParityRaid1::verify_parity(&[d0, d1], &parity));
    }

    #[test]
    fn verify_parity_detects_corruption() {
        let d0: &[u8] = &[0x01, 0x02, 0x03];
        let d1: &[u8] = &[0x10, 0x20, 0x30];
        let parity = ParityRaid1::compute(&[d0, d1]);
        let mut bad_parity = parity.clone();
        bad_parity[0] ^= 0x01;
        assert!(!ParityRaid1::verify_parity(&[d0, d1], &bad_parity));
    }

    #[test]
    fn verify_parity_empty_data_is_ok() {
        assert!(ParityRaid1::verify_parity(&[], b"anything"));
    }

    #[test]
    fn verify_parity_length_mismatch() {
        let d0: &[u8] = &[0x01, 0x02];
        let d1: &[u8] = &[0x10, 0x20];
        assert!(!ParityRaid1::verify_parity(&[d0, d1], b"short"));
    }

    // ── property tests ───────────────────────────────────────────────

    #[test]
    fn property_round_trip_variable_widths_and_sizes() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let n_data: usize = rng.gen_range(2..=12);
            let block_size: usize = rng.gen_range(512..=131_072);
            let blocks: Vec<Vec<u8>> = (0..n_data)
                .map(|_| (0..block_size).map(|_| rng.gen::<u8>()).collect())
                .collect();
            let refs: Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
            let parity = ParityRaid1::compute(&refs);

            // Reconstruct each data block
            for (missing, _) in blocks.iter().enumerate().take(n_data) {
                let survivors: Vec<&[u8]> = refs
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| i != missing)
                    .map(|(_, b)| *b)
                    .chain(std::iter::once(parity.as_slice()))
                    .collect();
                let rebuilt = ParityRaid1::reconstruct_from_survivors(&survivors);
                assert_eq!(
                    rebuilt, blocks[missing],
                    "round-trip mismatch at missing={missing}"
                );
            }

            // Reconstruct parity
            let rebuilt_parity = ParityRaid1::reconstruct_from_survivors(&refs);
            assert_eq!(rebuilt_parity, parity);
        }
    }

    #[test]
    fn property_stripe_write_reconstruct_each_column() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            let n_data: usize = rng.gen_range(2..=8);
            let payload_len: usize = rng.gen_range(1..=4096);
            let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen::<u8>()).collect();
            let stripes = ParityRaid1::stripe_write(&payload, n_data).unwrap();
            let total_cols = n_data + 1;

            for missing_idx in 0..total_cols {
                let survivors: Vec<&[u8]> = stripes
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != missing_idx)
                    .map(|(_, s)| s.as_slice())
                    .collect();
                let rebuilt =
                    ParityRaid1::stripe_reconstruct(missing_idx, &survivors, total_cols).unwrap();
                assert_eq!(
                    rebuilt, stripes[missing_idx],
                    "reconstruct failed for column {missing_idx} with n_data={n_data}"
                );
            }
        }
    }

    // ── ParityRaidError Display ──────────────────────────────────────

    #[test]
    fn parity_raid_error_display() {
        let e = ParityRaidError::TooFewDataColumns { got: 1, min: 2 };
        assert!(e.to_string().contains("need at least 2"));

        let e = ParityRaidError::EmptyInput;
        assert!(e.to_string().contains("empty"));

        let e = ParityRaidError::StripeLengthMismatch {
            expected: 10,
            got: 7,
            column: 3,
        };
        let s = e.to_string();
        assert!(s.contains("column 3"));
        assert!(s.contains("expected length 10"));
        assert!(s.contains("got 7"));

        let e = ParityRaidError::TooFewSurvivors { have: 1, need: 3 };
        let s = e.to_string();
        assert!(s.contains("need 3"));
        assert!(s.contains("got 1"));
    }
}
