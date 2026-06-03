//! Store abstraction for the commit_group subsystem.
//!
//! Defines `CommitGroupKey` (a wire-compatible 32-byte key) and the `CommitGroupStore` trait
//! that abstracts the minimal object-store operations needed by the commit
//! and recovery paths. Implementations live in `tidefs-local-object-store`
//! and test doubles.

use std::fmt;

// ---------------------------------------------------------------------------
// CommitGroupKey — wire-compatible 32-byte object key
// ---------------------------------------------------------------------------

/// A 32-byte object key used by the commit_group subsystem.
///
/// Wire-compatible with `tidefs_local_object_store::ObjectKey`: the same byte
/// layout so journal payloads round-trip between the two types.
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CommitGroupKey(pub [u8; 32]);

impl CommitGroupKey {
    /// The zero / nil key.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Construct from a 32-byte array.
    #[must_use]
    pub const fn from_bytes32(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes32(self) -> [u8; 32] {
        self.0
    }

    /// Return a reference to the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CommitGroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommitGroupKey({self})")
    }
}

impl fmt::Display for CommitGroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CommitGroupStore — minimal store trait for commit_group operations
// ---------------------------------------------------------------------------

/// Minimal object-store trait required by the commit_group subsystem.
///
/// Implementations persist named blobs (journal records, queued writes)
/// and retrieve them during recovery. The trait is deliberately narrow:
/// only `put_named` and `get_named` are needed.
pub trait CommitGroupStore {
    /// Store a named blob and return its key.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string on I/O failure.
    fn put_named(&mut self, name: &str, payload: &[u8]) -> Result<CommitGroupKey, String>;

    /// Retrieve a named blob by key name, returning `None` when absent.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string on I/O failure.
    fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txg_key_zero() {
        assert_eq!(CommitGroupKey::ZERO.as_bytes32(), [0u8; 32]);
    }

    #[test]
    fn txg_key_roundtrip() {
        let bytes = [0xAAu8; 32];
        let key = CommitGroupKey::from_bytes32(bytes);
        assert_eq!(key.as_bytes32(), bytes);
    }

    #[test]
    fn txg_key_display() {
        let key = CommitGroupKey::from_bytes32([0x01u8; 32]);
        let s = format!("{key}");
        assert_eq!(s.len(), 64);
    }
}

#[test]
fn txg_key_ordering() {
    let a = CommitGroupKey::from_bytes32([0x00u8; 32]);
    let b = CommitGroupKey::from_bytes32([0x01u8; 32]);
    let c = CommitGroupKey::from_bytes32([0x02u8; 32]);
    assert!(a < b);
    assert!(b < c);
    assert!(a < c);
}

#[test]
fn txg_key_ordering_lexicographic() {
    let mut high_first = [0x01u8; 32];
    high_first[31] = 0x00;
    let mut low_first = [0x00u8; 32];
    low_first[31] = 0xFF;
    let a = CommitGroupKey::from_bytes32(high_first);
    let b = CommitGroupKey::from_bytes32(low_first);
    assert!(a > b);
}

#[test]
fn txg_key_display_is_all_hex() {
    let key = CommitGroupKey::from_bytes32([0x12u8; 32]);
    let s = format!("{key}");
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn txg_key_debug_format() {
    let key = CommitGroupKey::from_bytes32([0x00u8; 32]);
    let s = format!("{key:?}");
    assert!(s.contains("CommitGroupKey"));
}

#[test]
fn txg_key_hash_consistent() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let a = CommitGroupKey::from_bytes32([1u8; 32]);
    let b = CommitGroupKey::from_bytes32([1u8; 32]);
    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    a.hash(&mut ha);
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn txg_key_hash_different() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let a = CommitGroupKey::from_bytes32([1u8; 32]);
    let b = CommitGroupKey::from_bytes32([2u8; 32]);
    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    a.hash(&mut ha);
    b.hash(&mut hb);
    assert_ne!(ha.finish(), hb.finish());
}

#[test]
fn txg_key_as_bytes() {
    let key = CommitGroupKey::from_bytes32([0x55u8; 32]);
    assert_eq!(key.as_bytes(), &[0x55u8; 32]);
}

#[test]
fn txg_key_partial_difference() {
    let a = CommitGroupKey::from_bytes32({
        let mut arr = [0x00u8; 32];
        arr[31] = 0x01;
        arr
    });
    let b = CommitGroupKey::from_bytes32([0x00u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn txg_key_nonzero_bytes() {
    let key = CommitGroupKey::from_bytes32([0xFFu8; 32]);
    assert_ne!(key, CommitGroupKey::ZERO);
}
