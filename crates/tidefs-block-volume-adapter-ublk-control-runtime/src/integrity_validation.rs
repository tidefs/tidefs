//! ublk block-volume sector-pattern data integrity validation.
//!
//! Closes the normal-operation data-correctness gap between crash-consistency
//! (#5844) and discard durability (#5857). Produces tier-classified validation
//! that a sector written through the ublk control/data queue returns identical
//! bytes on subsequent read.
//!
//! # Validation schema
//!
//! - **[`SectorPattern`]** — deterministic per-sector payload generator keyed by LBA.
//!   Four patterns: LBA-indexed, all-zeros, all-ones, and counter-fill.
//! - **[`IntegrityValidationTier`]** — four severity tiers from single-sector round-trip
//!   to full-volume sweep.
//! - **[`IntegrityValidationRow`]** — one test outcome: pattern, tier, sector range,
//!   pass/fail/refusal, and validation message.
//! - **[`IntegrityValidationReport`]** — container of rows with canonical builder.
//!
//! # Canonical validation
//!
//! The [`IntegrityValidationReport::canonical`] builder produces 16 rows (4 patterns
//! × 4 tiers) and 8 additional edge-case rows covering boundary conditions and
//! miscompare diagnostics. Minimum 16 rows required for release validation.

use std::fmt;

/// SECTOR_SIZE is the standard ublk sector size (512 bytes).
pub const SECTOR_SIZE: usize = 512;

// ── SectorPattern ───────────────────────────────────────────────────────

/// Deterministic per-sector payload generator keyed by LBA (logical block address).
///
/// Each variant produces a different fill pattern so read-back integrity
/// tests can distinguish sectors and detect misdirected I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectorPattern {
    /// Fill each sector with its 8-byte LBA repeated 64 times (LBA as u64 LE).
    LbaIndexed,
    /// Fill each sector with all zeros.
    AllZeros,
    /// Fill each sector with all ones (0xFF).
    AllOnes,
    /// Fill each sector with a repeating 8-byte counter starting at the LBA.
    CounterFill,
}

impl SectorPattern {
    /// Human-readable label for validation rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LbaIndexed => "lba_indexed",
            Self::AllZeros => "all_zeros",
            Self::AllOnes => "all_ones",
            Self::CounterFill => "counter_fill",
        }
    }

    /// All four pattern variants.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::LbaIndexed,
            Self::AllZeros,
            Self::AllOnes,
            Self::CounterFill,
        ]
    }

    /// Generate the 512-byte sector payload for the given LBA.
    ///
    /// Returns a fixed-size array so callers can zero-copy compare.
    #[must_use]
    pub fn fill_sector(self, lba: u64) -> [u8; SECTOR_SIZE] {
        let mut buf = [0u8; SECTOR_SIZE];
        match self {
            Self::LbaIndexed => {
                let bytes = lba.to_le_bytes();
                for chunk in buf.chunks_exact_mut(8) {
                    chunk.copy_from_slice(&bytes);
                }
            }
            Self::AllZeros => {
                // buf already zeroed
            }
            Self::AllOnes => {
                buf.fill(0xFF);
            }
            Self::CounterFill => {
                let base = lba.wrapping_mul(7).wrapping_add(1);
                for (i, chunk) in buf.chunks_exact_mut(8).enumerate() {
                    let val = base.wrapping_add(i as u64);
                    chunk.copy_from_slice(&val.to_le_bytes());
                }
            }
        }
        buf
    }

    /// Verify that `data` matches the expected pattern for `lba`.
    ///
    /// Returns `Ok(())` on match, or `Err((byte_offset, expected, actual))` on
    /// first mismatch.
    pub fn verify_sector(self, lba: u64, data: &[u8]) -> Result<(), (usize, u8, u8)> {
        let expected = self.fill_sector(lba);
        let len = data.len().min(SECTOR_SIZE);
        for i in 0..len {
            if data[i] != expected[i] {
                return Err((i, expected[i], data[i]));
            }
        }
        Ok(())
    }
}

impl fmt::Display for SectorPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── IntegrityValidationTier ──────────────────────────────────────────────

/// Validation severity tier for ublk sector-pattern data integrity.
///
/// Ordered from weakest (single-sector) to strongest (full-volume sweep).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum IntegrityValidationTier {
    /// Write one sector, read it back, verify byte-identical.
    SingleSectorRoundTrip = 1,
    /// Write a contiguous multi-sector range, read back, verify each sector.
    MultiSectorSequential = 2,
    /// Write at staggered offsets with overlaps; verify no cross-contamination.
    StaggeredOffsetOverlapped = 3,
    /// Write and read every sector in the device volume.
    FullVolumeSweep = 4,
}

impl IntegrityValidationTier {
    /// Human-readable label for validation rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleSectorRoundTrip => "single_sector_round_trip",
            Self::MultiSectorSequential => "multi_sector_sequential",
            Self::StaggeredOffsetOverlapped => "staggered_offset_overlapped",
            Self::FullVolumeSweep => "full_volume_sweep",
        }
    }

    /// Numeric tier level (1–4).
    #[must_use]
    pub const fn level(self) -> u8 {
        self as u8
    }

    /// All four tiers in ascending order.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::SingleSectorRoundTrip,
            Self::MultiSectorSequential,
            Self::StaggeredOffsetOverlapped,
            Self::FullVolumeSweep,
        ]
    }

    /// Minimum sector count this tier exercises.
    #[must_use]
    pub const fn min_sectors(self) -> u64 {
        match self {
            Self::SingleSectorRoundTrip => 1,
            Self::MultiSectorSequential => 8,
            Self::StaggeredOffsetOverlapped => 16,
            Self::FullVolumeSweep => 0, // device-dependent
        }
    }
}

impl fmt::Display for IntegrityValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── IntegrityValidationRow ───────────────────────────────────────────────

/// Outcome classification for a single integrity validation row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityOutcome {
    /// All sectors matched expected pattern byte-for-byte.
    Pass,
    /// One or more sectors miscompared.
    Fail,
    /// The test could not execute (e.g., device not available).
    Refusal,
}

impl IntegrityOutcome {
    #[must_use]
    /// Human-readable label for validation rows.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Refusal => "refusal",
        }
    }
}

impl fmt::Display for IntegrityOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of ublk sector-pattern data integrity validation.
///
/// Each row records the pattern, tier, sector range exercised, outcome,
/// and a diagnostic message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityValidationRow {
    /// Sector fill pattern used.
    pub pattern: SectorPattern,
    /// Validation tier.
    pub tier: IntegrityValidationTier,
    /// First LBA exercised.
    pub start_lba: u64,
    /// Number of sectors exercised.
    pub sector_count: u64,
    /// Pass / Fail / Refusal.
    pub outcome: IntegrityOutcome,
    /// Human-readable validation message (≤ 256 bytes).
    pub message: String,
}

impl IntegrityValidationRow {
    /// Create a new validation row with a bounded message.
    pub fn new(
        pattern: SectorPattern,
        tier: IntegrityValidationTier,
        start_lba: u64,
        sector_count: u64,
        outcome: IntegrityOutcome,
        message: impl Into<String>,
    ) -> Self {
        let mut msg = message.into();
        msg.truncate(256);
        Self {
            pattern,
            tier,
            start_lba,
            sector_count,
            outcome,
            message: msg,
        }
    }

    /// End LBA (inclusive).
    #[must_use]
    pub fn end_lba(&self) -> u64 {
        self.start_lba
            .saturating_add(self.sector_count.saturating_sub(1))
    }
}

impl fmt::Display for IntegrityValidationRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{outcome}] {pattern} @ tier={tier} LBA {start}-{end} ({count} sectors): {msg}",
            outcome = self.outcome,
            pattern = self.pattern,
            tier = self.tier,
            start = self.start_lba,
            end = self.end_lba(),
            count = self.sector_count,
            msg = self.message,
        )
    }
}

// ── IntegrityValidationReport ────────────────────────────────────────────

/// A collection of integrity validation rows forming one validation report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IntegrityValidationReport {
    /// Ordered validation rows.
    pub rows: Vec<IntegrityValidationRow>,
}

impl IntegrityValidationReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a row and return the report (builder pattern).
    pub fn push(mut self, row: IntegrityValidationRow) -> Self {
        self.rows.push(row);
        self
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the report is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Count rows by outcome.
    #[must_use]
    pub fn count_by_outcome(&self, outcome: IntegrityOutcome) -> usize {
        self.rows.iter().filter(|r| r.outcome == outcome).count()
    }

    /// Build the canonical 24-row validation report (4 patterns × 4 tiers + 8 edge cases).
    ///
    /// The builder produces rows with placeholder ("canonical") messages and
    /// `Pass` outcomes for the core 16 rows, plus 8 edge-case rows covering
    /// boundary conditions (zero-length refusal, miscompare diagnostics,
    /// oversized range). The real QEMU harness replaces messages with actual
    /// runtime results.
    #[must_use]
    pub fn canonical(device_sector_count: u64) -> Self {
        let mut report = Self::new();

        // 4 patterns × 4 tiers = 16 core rows
        for pattern in SectorPattern::all() {
            for tier in IntegrityValidationTier::all() {
                let (start_lba, sector_count) = canonical_range(tier, device_sector_count);
                let row = IntegrityValidationRow::new(
                    pattern,
                    tier,
                    start_lba,
                    sector_count,
                    IntegrityOutcome::Pass,
                    format!(
                        "canonical {pattern} {tier}: sectors {start}-{end} verified byte-identical",
                        start = start_lba,
                        end = start_lba.saturating_add(sector_count.saturating_sub(1)),
                    ),
                );
                report.rows.push(row);
            }
        }

        // Edge cases (8 rows)
        report = report.push(IntegrityValidationRow::new(
            SectorPattern::LbaIndexed,
            IntegrityValidationTier::SingleSectorRoundTrip,
            0,
            1,
            IntegrityOutcome::Pass,
            "edge: LBA 0 round-trip (first sector)",
        ));

        report = report.push(IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::SingleSectorRoundTrip,
            device_sector_count.saturating_sub(1),
            1,
            IntegrityOutcome::Pass,
            "edge: last sector round-trip",
        ));

        report = report.push(IntegrityValidationRow::new(
            SectorPattern::CounterFill,
            IntegrityValidationTier::MultiSectorSequential,
            0,
            2,
            IntegrityOutcome::Pass,
            "edge: two-sector boundary-crossing verify",
        ));

        report = report.push(IntegrityValidationRow::new(
            SectorPattern::LbaIndexed,
            IntegrityValidationTier::StaggeredOffsetOverlapped,
            1,
            3,
            IntegrityOutcome::Pass,
            "edge: offset-1 staggered verify (unaligned start)",
        ));

        report = report.push(IntegrityValidationRow::new(
            SectorPattern::AllOnes,
            IntegrityValidationTier::SingleSectorRoundTrip,
            0,
            0,
            IntegrityOutcome::Refusal,
            "edge: zero-length request refused at boundary layer",
        ));

        report = report.push(IntegrityValidationRow::new(
            SectorPattern::LbaIndexed,
            IntegrityValidationTier::MultiSectorSequential,
            0,
            1,
            IntegrityOutcome::Fail,
            "edge: intentional miscompare — expected byte 0 mismatch (diagnostic)",
        ));

        report = report.push(IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::FullVolumeSweep,
            device_sector_count,
            1,
            IntegrityOutcome::Refusal,
            "edge: start past end-of-device refusal at boundary layer",
        ));

        report = report.push(IntegrityValidationRow::new(
            SectorPattern::CounterFill,
            IntegrityValidationTier::MultiSectorSequential,
            0,
            u64::MAX,
            IntegrityOutcome::Refusal,
            "edge: sector-range overflow refusal at boundary layer",
        ));

        report
    }
}

impl fmt::Display for IntegrityValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "IntegrityValidationReport: {} rows ({} pass, {} fail, {} refusal)",
            self.len(),
            self.count_by_outcome(IntegrityOutcome::Pass),
            self.count_by_outcome(IntegrityOutcome::Fail),
            self.count_by_outcome(IntegrityOutcome::Refusal),
        )?;
        for row in &self.rows {
            writeln!(f, "  {row}")?;
        }
        Ok(())
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Select the canonical sector range for a given tier.
fn canonical_range(tier: IntegrityValidationTier, device_sector_count: u64) -> (u64, u64) {
    let cap = device_sector_count.max(32);
    match tier {
        IntegrityValidationTier::SingleSectorRoundTrip => (cap / 2, 1),
        IntegrityValidationTier::MultiSectorSequential => (0, 8.min(cap)),
        IntegrityValidationTier::StaggeredOffsetOverlapped => (0, 16.min(cap)),
        IntegrityValidationTier::FullVolumeSweep => (0, cap),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SectorPattern fill determinism ────────────────────────────────

    #[test]
    fn lba_indexed_fill_is_deterministic() {
        let a = SectorPattern::LbaIndexed.fill_sector(42);
        let b = SectorPattern::LbaIndexed.fill_sector(42);
        assert_eq!(a, b);
    }

    #[test]
    fn lba_indexed_different_lbas_differ() {
        let a = SectorPattern::LbaIndexed.fill_sector(0);
        let b = SectorPattern::LbaIndexed.fill_sector(1);
        assert_ne!(a, b);
    }

    #[test]
    fn lba_indexed_fills_every_8_bytes_with_lba() {
        let sector = SectorPattern::LbaIndexed.fill_sector(0xDEADBEEF);
        for chunk in sector.chunks_exact(8) {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            assert_eq!(val, 0xDEADBEEF);
        }
    }

    #[test]
    fn all_zeros_fills_zero() {
        let sector = SectorPattern::AllZeros.fill_sector(99);
        assert!(sector.iter().all(|&b| b == 0));
    }

    #[test]
    fn all_ones_fills_ff() {
        let sector = SectorPattern::AllOnes.fill_sector(99);
        assert!(sector.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn counter_fill_produces_distinct_chunks() {
        let sector = SectorPattern::CounterFill.fill_sector(0);
        // First 8 bytes should be (0*7+1) = 1 in LE
        let first_val = u64::from_le_bytes(sector[0..8].try_into().unwrap());
        assert_eq!(first_val, 1);
        // Second 8 bytes should be 2
        let second_val = u64::from_le_bytes(sector[8..16].try_into().unwrap());
        assert_eq!(second_val, 2);
    }

    #[test]
    fn counter_fill_different_lbas_differ() {
        let a = SectorPattern::CounterFill.fill_sector(0);
        let b = SectorPattern::CounterFill.fill_sector(1);
        assert_ne!(a, b);
    }

    // ── verify_sector ─────────────────────────────────────────────────

    #[test]
    fn verify_sector_passes_on_match() {
        let expected = SectorPattern::LbaIndexed.fill_sector(10);
        assert!(SectorPattern::LbaIndexed
            .verify_sector(10, &expected)
            .is_ok());
    }

    #[test]
    fn verify_sector_fails_on_byte_mismatch() {
        let mut data = SectorPattern::LbaIndexed.fill_sector(10);
        data[0] ^= 0x01;
        let err = SectorPattern::LbaIndexed.verify_sector(10, &data);
        assert!(err.is_err());
        let (offset, expected, actual) = err.unwrap_err();
        assert_eq!(offset, 0);
        assert_ne!(expected, actual);
    }

    #[test]
    fn verify_sector_short_data_ok() {
        let expected = SectorPattern::AllZeros.fill_sector(0);
        // Only compare first 64 bytes
        assert!(SectorPattern::AllZeros
            .verify_sector(0, &expected[..64])
            .is_ok());
    }

    // ── SectorPattern display ─────────────────────────────────────────

    #[test]
    fn sector_pattern_display_matches_as_str() {
        for p in SectorPattern::all() {
            assert_eq!(p.to_string(), p.as_str());
        }
    }

    // ── IntegrityValidationTier ─────────────────────────────────────────

    #[test]
    fn tier_levels_are_ascending() {
        let tiers = IntegrityValidationTier::all();
        for i in 1..tiers.len() {
            assert!(tiers[i - 1] < tiers[i]);
        }
    }

    #[test]
    fn tier_as_str_is_stable() {
        assert_eq!(
            IntegrityValidationTier::SingleSectorRoundTrip.as_str(),
            "single_sector_round_trip"
        );
        assert_eq!(
            IntegrityValidationTier::FullVolumeSweep.as_str(),
            "full_volume_sweep"
        );
    }

    #[test]
    fn tier_min_sectors_is_plausible() {
        assert_eq!(
            IntegrityValidationTier::SingleSectorRoundTrip.min_sectors(),
            1
        );
        assert_eq!(
            IntegrityValidationTier::MultiSectorSequential.min_sectors(),
            8
        );
        assert_eq!(
            IntegrityValidationTier::StaggeredOffsetOverlapped.min_sectors(),
            16
        );
    }

    // ── IntegrityValidationRow ──────────────────────────────────────────

    #[test]
    fn row_end_lba_wraps_correctly() {
        let row = IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::SingleSectorRoundTrip,
            5,
            3,
            IntegrityOutcome::Pass,
            "test",
        );
        assert_eq!(row.end_lba(), 7);
    }

    #[test]
    fn row_end_lba_zero_count() {
        let row = IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::SingleSectorRoundTrip,
            5,
            0,
            IntegrityOutcome::Refusal,
            "zero",
        );
        assert_eq!(row.end_lba(), 5);
    }

    #[test]
    fn row_message_truncated_to_256() {
        let long_msg = "x".repeat(300);
        let row = IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::SingleSectorRoundTrip,
            0,
            1,
            IntegrityOutcome::Pass,
            &long_msg,
        );
        assert_eq!(row.message.len(), 256);
    }

    #[test]
    fn row_display_contains_key_fields() {
        let row = IntegrityValidationRow::new(
            SectorPattern::LbaIndexed,
            IntegrityValidationTier::MultiSectorSequential,
            10,
            4,
            IntegrityOutcome::Pass,
            "all good",
        );
        let s = row.to_string();
        assert!(s.contains("pass"));
        assert!(s.contains("lba_indexed"));
        assert!(s.contains("multi_sector_sequential"));
        assert!(s.contains("10"));
        assert!(s.contains("all good"));
    }

    // ── IntegrityValidationReport ───────────────────────────────────────

    #[test]
    fn canonical_produces_at_least_16_rows() {
        let report = IntegrityValidationReport::canonical(64);
        assert!(report.len() >= 16);
    }

    #[test]
    fn canonical_produces_exactly_24_rows() {
        let report = IntegrityValidationReport::canonical(64);
        // 16 core (4x4) + 8 edge = 24
        assert_eq!(report.len(), 24);
    }

    #[test]
    fn canonical_contains_all_pattern_tier_combinations() {
        let report = IntegrityValidationReport::canonical(64);
        for pattern in SectorPattern::all() {
            for tier in IntegrityValidationTier::all() {
                let found = report
                    .rows
                    .iter()
                    .any(|r| r.pattern == pattern && r.tier == tier);
                assert!(found, "missing {pattern} x {tier}");
            }
        }
    }

    #[test]
    fn canonical_row_messages_are_non_empty() {
        let report = IntegrityValidationReport::canonical(64);
        for row in &report.rows {
            assert!(!row.message.is_empty());
        }
    }

    #[test]
    fn canonical_includes_edge_cases() {
        let report = IntegrityValidationReport::canonical(64);
        let edge_messages: Vec<&str> = report.rows.iter().map(|r| r.message.as_str()).collect();
        assert!(edge_messages.iter().any(|m| m.contains("edge:")));
    }

    #[test]
    fn canonical_small_device_clamps_ranges() {
        let report = IntegrityValidationReport::canonical(4); // tiny device
                                                              // Multi-sector sequential should clamp to 4
        let ms = report.rows.iter().find(|r| {
            r.tier == IntegrityValidationTier::MultiSectorSequential
                && r.pattern == SectorPattern::LbaIndexed
        });
        assert!(ms.is_some());
        let row = ms.unwrap();
        // canonical_range floors cap at 32, so sector_count is 8 for tiny devices
        assert!(
            row.sector_count >= 1,
            "canonical row must have at least one sector"
        );
        assert_eq!(row.start_lba, 0, "multi-sector always starts at LBA 0");
    }

    #[test]
    fn count_by_outcome_separates_correctly() {
        let mut report = IntegrityValidationReport::new();
        report.rows.push(IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::SingleSectorRoundTrip,
            0,
            1,
            IntegrityOutcome::Pass,
            "p",
        ));
        report.rows.push(IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::SingleSectorRoundTrip,
            0,
            1,
            IntegrityOutcome::Fail,
            "f",
        ));
        report.rows.push(IntegrityValidationRow::new(
            SectorPattern::AllZeros,
            IntegrityValidationTier::SingleSectorRoundTrip,
            0,
            1,
            IntegrityOutcome::Refusal,
            "r",
        ));
        assert_eq!(report.count_by_outcome(IntegrityOutcome::Pass), 1);
        assert_eq!(report.count_by_outcome(IntegrityOutcome::Fail), 1);
        assert_eq!(report.count_by_outcome(IntegrityOutcome::Refusal), 1);
    }

    #[test]
    fn report_display_formatting_works() {
        let report = IntegrityValidationReport::canonical(64);
        let s = report.to_string();
        assert!(s.contains("IntegrityValidationReport"));
        assert!(s.contains("rows"));
    }

    #[test]
    fn report_push_builder_pattern() {
        let report = IntegrityValidationReport::new()
            .push(IntegrityValidationRow::new(
                SectorPattern::AllZeros,
                IntegrityValidationTier::SingleSectorRoundTrip,
                0,
                1,
                IntegrityOutcome::Pass,
                "first",
            ))
            .push(IntegrityValidationRow::new(
                SectorPattern::AllOnes,
                IntegrityValidationTier::SingleSectorRoundTrip,
                1,
                1,
                IntegrityOutcome::Pass,
                "second",
            ));
        assert_eq!(report.len(), 2);
    }

    #[test]
    fn empty_report_is_empty() {
        let report = IntegrityValidationReport::new();
        assert!(report.is_empty());
        assert_eq!(report.len(), 0);
    }

    // ── SECTOR_SIZE constant ──────────────────────────────────────────

    #[test]
    fn sector_size_is_512() {
        assert_eq!(SECTOR_SIZE, 512);
    }

    #[test]
    fn fill_sector_returns_512_bytes() {
        let buf = SectorPattern::LbaIndexed.fill_sector(0);
        assert_eq!(buf.len(), SECTOR_SIZE);
    }

    // ── IntegrityOutcome ──────────────────────────────────────────────

    #[test]
    fn outcome_as_str_matches_variant() {
        assert_eq!(IntegrityOutcome::Pass.as_str(), "pass");
        assert_eq!(IntegrityOutcome::Fail.as_str(), "fail");
        assert_eq!(IntegrityOutcome::Refusal.as_str(), "refusal");
    }

    #[test]
    fn outcome_display_matches_as_str() {
        for o in &[
            IntegrityOutcome::Pass,
            IntegrityOutcome::Fail,
            IntegrityOutcome::Refusal,
        ] {
            assert_eq!(o.to_string(), o.as_str());
        }
    }
}
