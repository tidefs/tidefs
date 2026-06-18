// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;

/// Pool-wide unique extent identifier with generation counter.
///
/// Every allocated extent in the pool receives a unique `ExtentId`.
/// The lower 48 bits hold the monotonic allocation counter; the upper
/// 16 bits hold a generation counter that prevents ABA reuse: when an
/// extent is freed and its slot is later reused, the generation is
/// incremented so that stale lookups for the old `ExtentId` miss.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExtentId(pub u64);

/// Number of bits reserved for the generation counter.
const GEN_BITS: u32 = 16;
/// Mask for the id portion (lower 48 bits).
const ID_MASK: u64 = (1u64 << (64 - GEN_BITS)) - 1;
/// Maximum id value.
#[allow(dead_code)]
pub const MAX_EXTENT_ID: u64 = ID_MASK;

impl ExtentId {
    /// Sentinel for "no extent".
    pub const NONE: Self = Self(0);

    /// Create a new `ExtentId` with the given generation and id.
    #[must_use]
    pub const fn with_generation(id: u64, generation: u16) -> Self {
        Self(((generation as u64) << (64 - GEN_BITS)) | (id & ID_MASK))
    }

    /// Returns true when the id is `NONE`.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Returns true when the id is not `NONE`.
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }

    /// The raw 48-bit extent id (without generation).
    #[must_use]
    pub const fn id(self) -> u64 {
        self.0 & ID_MASK
    }

    /// The generation counter (upper 16 bits).
    #[must_use]
    pub const fn generation(self) -> u16 {
        ((self.0 >> (64 - GEN_BITS)) & 0xFFFF) as u16
    }

    /// Create an `ExtentId` from raw parts.
    ///
    /// This is equivalent to `with_generation` but uses separate args.
    #[must_use]
    pub const fn from_parts(id: u64, generation: u16) -> Self {
        Self::with_generation(id, generation)
    }

    /// Advance to the next generation, keeping the same id.
    #[must_use]
    pub const fn next_generation(self) -> Self {
        let gen = self.generation();
        Self::with_generation(self.id(), gen.wrapping_add(1))
    }
}

impl fmt::Display for ExtentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let gen = self.generation();
        let id = self.id();
        if gen != 0 {
            write!(f, "{id}:{gen}")
        } else {
            write!(f, "{id}")
        }
    }
}

impl From<u64> for ExtentId {
    /// Convert a raw u64 into an `ExtentId`.
    ///
    /// For new allocations prefer [`ExtentId::with_generation`] so the
    /// generation counter is set correctly.
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<ExtentId> for u64 {
    fn from(v: ExtentId) -> Self {
        v.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_zero() {
        assert_eq!(ExtentId::NONE, ExtentId(0));
        assert!(ExtentId::NONE.is_none());
    }

    #[test]
    fn with_generation_encodes_correctly() {
        let eid = ExtentId::with_generation(42, 3);
        assert_eq!(eid.id(), 42);
        assert_eq!(eid.generation(), 3);
    }

    #[test]
    fn generation_zero_display_omits_counter() {
        let eid = ExtentId::with_generation(42, 0);
        assert_eq!(format!("{eid}"), "42");
    }

    #[test]
    fn generation_nonzero_display_includes_counter() {
        let eid = ExtentId::with_generation(42, 5);
        assert_eq!(format!("{eid}"), "42:5");
    }

    #[test]
    fn different_generations_not_equal() {
        let a = ExtentId::with_generation(42, 0);
        let b = ExtentId::with_generation(42, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn id_preserved_across_generations() {
        let a = ExtentId::with_generation(99, 1);
        assert_eq!(a.id(), 99);
        let b = a.next_generation();
        assert_eq!(b.id(), 99);
        assert_eq!(b.generation(), 2);
        assert_ne!(a, b);
    }

    #[test]
    fn max_extent_id_fits_in_48_bits() {
        assert_eq!(MAX_EXTENT_ID, (1u64 << 48) - 1);
        let eid = ExtentId::with_generation(MAX_EXTENT_ID, 0xFFFF);
        assert_eq!(eid.id(), MAX_EXTENT_ID);
        assert_eq!(eid.generation(), 0xFFFF);
    }

    #[test]
    fn from_u64_roundtrips_raw() {
        let raw: u64 = 0x000300000000002A; // generation 3, id 42
        let eid = ExtentId::from(raw);
        assert_eq!(eid.id(), 42);
        assert_eq!(eid.generation(), 3);
        assert_eq!(u64::from(eid), raw);
    }
}
