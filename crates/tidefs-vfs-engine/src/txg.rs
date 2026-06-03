//! Transaction-group lifecycle types for kernel-mode committed-root advancement.
//!
//! This module defines the types used by the [`VfsEngine`] transaction-group
//! trait methods ([`VfsEngine::txg_open`], [`VfsEngine::txg_commit_prepare`],
//! [`VfsEngine::txg_commit_finish`]) to batch kernel-mode writes into
//! crash-consistent transaction groups and advance the durable committed root
//! without userspace daemon mediation.

use core::fmt;

/// Transaction group identifier.
///
/// Zero (`TxgId(0)`) is the sentinel value representing "no transaction group".
/// Valid transaction groups use non-zero identifiers.
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TxgId(pub u64);

impl TxgId {
    /// Sentinel value representing no transaction group.
    pub const NO_TXG: Self = TxgId(0);

    /// Returns `true` if this is a valid (non-zero) transaction group id.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Debug for TxgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxgId({})", self.0)
    }
}

impl fmt::Display for TxgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Durable committed-root identifier.
///
/// A 32-byte content digest that identifies a specific committed filesystem
/// state. After a transaction group commits, the new committed root becomes
/// the authoritative recovery point for crash recovery.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct CommittedRoot(pub [u8; 32]);

impl CommittedRoot {
    /// Zero-filled sentinel root (not a valid committed state).
    pub const ZERO: Self = CommittedRoot([0u8; 32]);

    /// Create a committed root from a 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        CommittedRoot(bytes)
    }

    /// Returns the raw bytes of this committed root.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for CommittedRoot {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for CommittedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommittedRoot({:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...)",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        )
    }
}

impl fmt::Display for CommittedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Result of preparing a transaction group for commit.
///
/// Returned by [`VfsEngine::txg_commit_prepare`]. Contains the proposed
/// committed-root identifier after this txg commits and any quorum
/// requirements for multi-node operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxgPrepareResult {
    /// The proposed committed-root identifier after this txg commits.
    pub committed_root: CommittedRoot,
    /// Whether quorum acknowledgement from peer nodes is required before
    /// the commit can finish (multi-node mode only).
    pub quorum_needed: bool,
    /// Engine-specific flags for extended commit semantics.
    pub flags: u64,
}

impl TxgPrepareResult {
    /// Construct an immediate (non-quorum) prepare result with the given root.
    #[must_use]
    pub const fn immediate(root: CommittedRoot) -> Self {
        Self {
            committed_root: root,
            quorum_needed: false,
            flags: 0,
        }
    }
}

/// Opaque handle for an open transaction group.
///
/// Returned by [`VfsEngine::txg_open`]. The handle tracks the txg lifecycle:
/// it must be passed to [`VfsEngine::txg_commit_finish`] to successfully
/// close the transaction group.
///
/// # Abort on drop
///
/// If the handle is dropped before being consumed by `txg_commit_finish`
/// (e.g., due to an error unwind or early return), the transaction group
/// is implicitly aborted. Real engine implementations track aborted
/// transaction groups in their internal state and roll back uncommitted
/// mutations.
pub struct TxgHandle {
    txg_id: TxgId,
    consumed: bool,
}

impl TxgHandle {
    /// Create a no-op handle for engines that do not support transaction groups.
    ///
    /// The no-op handle carries [`TxgId::NO_TXG`] and its drop is a no-op.
    #[must_use]
    pub const fn noop() -> Self {
        Self {
            txg_id: TxgId::NO_TXG,
            consumed: false,
        }
    }

    /// Create a new handle for the given transaction group id.
    #[must_use]
    pub const fn new(txg_id: TxgId) -> Self {
        Self {
            txg_id,
            consumed: false,
        }
    }

    /// Return the transaction group id.
    #[must_use]
    pub const fn id(&self) -> TxgId {
        self.txg_id
    }

    /// Mark the handle as consumed.
    ///
    /// Called by [`VfsEngine::txg_commit_finish`] to signal that the
    /// transaction group was successfully committed. After this call,
    /// `is_consumed()` returns `true` and the drop handler becomes a no-op.
    pub fn mark_consumed(&mut self) {
        self.consumed = true;
    }

    /// Returns `true` if this handle has been consumed by `txg_commit_finish`.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }
}

impl fmt::Debug for TxgHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxgHandle")
            .field("txg_id", &self.txg_id)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl Drop for TxgHandle {
    fn drop(&mut self) {
        // When the handle is dropped without being consumed by
        // txg_commit_finish, the transaction group is implicitly aborted.
        // The default noop handle requires no action; real engine
        // implementations track aborted txgs in their internal state
        // and will roll back any uncommitted mutations.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txg_id_default_is_no_txg() {
        assert_eq!(TxgId::default(), TxgId::NO_TXG);
        assert!(!TxgId::default().is_valid());
    }

    #[test]
    fn txg_id_nonzero_is_valid() {
        assert!(TxgId(1).is_valid());
        assert!(TxgId(u64::MAX).is_valid());
    }

    #[test]
    fn txg_id_debug_display() {
        let id = TxgId(42);
        assert_eq!(alloc::format!("{id:?}"), "TxgId(42)");
        assert_eq!(alloc::format!("{id}"), "42");
    }

    #[test]
    fn committed_root_zero_is_default() {
        assert_eq!(CommittedRoot::default(), CommittedRoot::ZERO);
        assert_eq!(CommittedRoot::ZERO.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn committed_root_new_roundtrip() {
        let bytes: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
            0x70, 0x80, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0x00,
        ];
        let root = CommittedRoot::new(bytes);
        assert_eq!(root.as_bytes(), &bytes);
    }

    #[test]
    fn committed_root_debug_format() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        let root = CommittedRoot::new(bytes);
        let s = alloc::format!("{root:?}");
        assert!(s.starts_with("CommittedRoot(dead000000000000...)"));
    }

    #[test]
    fn txg_prepare_result_immediate() {
        let root = CommittedRoot::new([0x42u8; 32]);
        let result = TxgPrepareResult::immediate(root);
        assert_eq!(result.committed_root, root);
        assert!(!result.quorum_needed);
        assert_eq!(result.flags, 0);
    }

    #[test]
    fn txg_prepare_result_with_quorum() {
        let root = CommittedRoot::new([0xffu8; 32]);
        let result = TxgPrepareResult {
            committed_root: root,
            quorum_needed: true,
            flags: 3,
        };
        assert_eq!(result.committed_root, root);
        assert!(result.quorum_needed);
        assert_eq!(result.flags, 3);
    }

    #[test]
    fn txg_handle_noop() {
        let handle = TxgHandle::noop();
        assert_eq!(handle.id(), TxgId::NO_TXG);
        assert!(!handle.is_consumed());
    }

    #[test]
    fn txg_handle_new() {
        let handle = TxgHandle::new(TxgId(7));
        assert_eq!(handle.id(), TxgId(7));
        assert!(handle.id().is_valid());
        assert!(!handle.is_consumed());
    }

    #[test]
    fn txg_handle_mark_consumed() {
        let mut handle = TxgHandle::new(TxgId(99));
        assert!(!handle.is_consumed());
        handle.mark_consumed();
        assert!(handle.is_consumed());
    }

    #[test]
    fn txg_handle_debug_format() {
        let handle = TxgHandle::new(TxgId(1));
        let s = alloc::format!("{handle:?}");
        assert!(s.contains("TxgHandle"));
        assert!(s.contains("TxgId(1)"));
        assert!(s.contains("consumed"));
    }

    #[test]
    fn txg_handle_drop_without_consume_is_noop() {
        // The handle is created and dropped without being marked consumed.
        // This verifies no panic occurs.
        let handle = TxgHandle::new(TxgId(42));
        drop(handle);
    }
}
