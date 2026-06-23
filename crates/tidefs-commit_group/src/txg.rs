// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transaction group lifecycle: begin, commit, abort with intent-log barrier
//! integration and BLAKE3-verified state tracking.
//!
//! `TxGroupHandle` provides the operational lifecycle that FUSE durability
//! handlers (fsync, flush, fsyncdir) use to group intent-log records into
//! durable transaction groups. Each group is a crash-safety boundary:
//! either all operations in the group are committed atomically, or the
//! group is aborted and discarded.
//!
//! # Lifecycle
//!
//! ```text
//! begin_txg() -> Open -> commit_txg(data) -> Sealed -> Committing -> Committed -> Applied
//!   |                |                          |
//!   |                +-- abort_txg() ---------> Aborted
//!   |                                              |
//!   +----------------------------------------------+ (re-open with next txg id)
//! ```

use crate::state_machine::CommitGroupStateMachine;
use crate::sync::SyncGate;
use crate::types::{CommitGroupError, CommitGroupId};

// ---------------------------------------------------------------------------
// TxGroupState -- BLAKE3-verified crash-recovery record
// ---------------------------------------------------------------------------

/// Magic identifier for a serialized `TxGroupState` record.
pub const TX_GROUP_STATE_MAGIC: [u8; 4] = *b"VTGS";

/// Lifecycle state encoded in a persisted `TxGroupState`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxGroupLifecycle {
    /// Transaction group is open (accepting writes).
    Open = 1,
    /// Commit in progress (barrier record written to intent log).
    Committing = 2,
    /// Transaction group committed (root pointer advanced).
    Committed = 3,
    /// Transaction group aborted (all staged data discarded).
    Aborted = 4,
}

impl TxGroupLifecycle {
    /// Serialize to a single-byte discriminant.
    #[must_use]
    pub fn to_discriminant(self) -> u8 {
        self as u8
    }

    /// Deserialize from a single-byte discriminant.
    /// Unknown values default to `Aborted`.
    #[must_use]
    pub fn from_discriminant(d: u8) -> Self {
        match d {
            1 => Self::Open,
            2 => Self::Committing,
            3 => Self::Committed,
            _ => Self::Aborted,
        }
    }
}

/// BLAKE3-verified transaction group state record for crash recovery.
///
/// Persisted alongside the committed root so recovery can determine which
/// transaction groups were in-flight at crash time. The checksum covers
/// the magic, sequence number, and lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxGroupState {
    /// Magic bytes (`VTGS`).
    pub magic: [u8; 4],
    /// Transaction group sequence number.
    pub sequence: u64,
    /// Lifecycle state at persist time.
    pub state: TxGroupLifecycle,
    /// BLAKE3-256 checksum over magic, sequence, and state discriminator.
    pub checksum: [u8; 32],
}

impl TxGroupState {
    /// Create a new `TxGroupState`, automatically computing the checksum.
    #[must_use]
    pub fn new(sequence: u64, state: TxGroupLifecycle) -> Self {
        let mut record = Self {
            magic: TX_GROUP_STATE_MAGIC,
            sequence,
            state,
            checksum: [0u8; 32],
        };
        record.checksum = record.compute_checksum();
        record
    }

    /// Compute the BLAKE3-256 checksum over the record fields.
    #[must_use]
    pub fn compute_checksum(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&TX_GROUP_STATE_MAGIC);
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&[self.state.to_discriminant()]);
        *hasher.finalize().as_bytes()
    }

    /// Verify that the stored checksum matches the record content.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.checksum == self.compute_checksum()
    }

    /// Serialize to a 45-byte buffer: `[magic:4][sequence:8][state:1][checksum:32]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(45);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.push(self.state.to_discriminant());
        buf.extend_from_slice(&self.checksum);
        buf
    }

    /// Deserialize from bytes with magic and checksum verification.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if the buffer is too short,
    /// the magic doesn't match, or the checksum fails verification.
    pub fn decode(buf: &[u8]) -> Result<Self, CommitGroupError> {
        if buf.len() < 45 {
            return Err(CommitGroupError::PrepareFailed {
                reason: format!("TxGroupState decode: expected 45 bytes, got {}", buf.len()),
            });
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if magic != TX_GROUP_STATE_MAGIC {
            return Err(CommitGroupError::PrepareFailed {
                reason: "TxGroupState decode: magic mismatch".into(),
            });
        }

        let sequence = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        let state = TxGroupLifecycle::from_discriminant(buf[12]);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[13..45]);

        let record = Self {
            magic,
            sequence,
            state,
            checksum,
        };

        if !record.verify() {
            return Err(CommitGroupError::PrepareFailed {
                reason: "TxGroupState decode: checksum verification failed".into(),
            });
        }

        Ok(record)
    }
}

// ---------------------------------------------------------------------------
// TxGroupHandle -- begin / commit / abort lifecycle
// ---------------------------------------------------------------------------

/// Transaction group lifecycle handle: begin, commit, abort with intent-log
/// barrier integration.
///
/// Wraps a [`CommitGroupStateMachine`] for per-group lifecycle tracking and
/// a [`SyncGate`] for barrier coordination (waking fsync waiters on commit).
/// Each call to [`begin_txg`](Self::begin_txg) advances the transaction group
/// sequence number; [`commit_txg`](Self::commit_txg) drives the group through
/// seal -> commit -> apply and notifies the sync gate.
///
/// # Example (FUSE fsync path)
///
/// ```ignore
/// let mut txg = TxGroupHandle::new(CommitGroupId::FIRST);
///
/// // Open a new transaction group for write accumulation.
/// let txg_id = txg.begin_txg().unwrap();
///
/// // ... writes and metadata mutations accumulate ...
///
/// // Commit the group: all operations become durable.
/// let digest = txg.commit_txg(b"fsync barrier data").unwrap();
/// // sync_gate is notified; fsync waiters are woken.
/// ```
#[derive(Clone, Debug)]
pub struct TxGroupHandle {
    /// Per-group lifecycle state machine.
    state_machine: CommitGroupStateMachine,
    /// Sync gate for waking fsync / syncfs waiters on commit.
    sync_gate: SyncGate,
    /// The current transaction group sequence number.
    current_txg: CommitGroupId,
    /// BLAKE3-256 chain digest from the most recently committed group.
    chain_digest: [u8; 32],
}

impl TxGroupHandle {
    /// Create a new handle starting at the given transaction group id.
    #[must_use]
    pub fn new(starting_txg: CommitGroupId) -> Self {
        Self {
            state_machine: CommitGroupStateMachine::new(starting_txg, [0u8; 32]),
            sync_gate: SyncGate::new(),
            current_txg: starting_txg,
            chain_digest: [0u8; 32],
        }
    }

    /// Create a handle resuming from a recovered committed state.
    ///
    /// `prior_chain_digest` is the BLAKE3 chain digest from the most recent
    /// committed group, used to continue the hash chain across mounts.
    #[must_use]
    pub fn resume(starting_txg: CommitGroupId, prior_chain_digest: [u8; 32]) -> Self {
        Self {
            state_machine: CommitGroupStateMachine::new(starting_txg, prior_chain_digest),
            sync_gate: SyncGate::new(),
            current_txg: starting_txg,
            chain_digest: prior_chain_digest,
        }
    }

    // ---- accessors ----

    /// The current transaction group identifier.
    #[must_use]
    pub fn txg_id(&self) -> CommitGroupId {
        self.current_txg
    }

    /// The BLAKE3-256 chain digest from the most recently committed group.
    #[must_use]
    pub fn chain_digest(&self) -> [u8; 32] {
        self.chain_digest
    }

    /// Reference to the sync gate for fsync barrier coordination.
    #[must_use]
    pub fn sync_gate(&self) -> &SyncGate {
        &self.sync_gate
    }

    /// Returns `true` if a transaction group is currently open (accepting writes).
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state_machine.is_open()
    }

    /// Returns `true` if the state machine is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state_machine.is_terminal()
    }

    /// Current lifecycle state of the state machine.
    #[must_use]
    pub fn group_state(&self) -> crate::state_machine::CommitGroupState {
        self.state_machine.state()
    }

    // ---- lifecycle operations ----

    /// Begin a new transaction group.
    ///
    /// If a previous group terminated (committed+applied or aborted), this
    /// advances the sequence number and opens a fresh group. If a group is
    /// already open, an error is returned.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::PrepareFailed` if a txg is already open.
    pub fn begin_txg(&mut self) -> Result<CommitGroupId, CommitGroupError> {
        if self.state_machine.is_terminal() {
            // Advance to the next txg id and create a fresh state machine.
            self.current_txg = self.current_txg.next();
            self.state_machine = CommitGroupStateMachine::new(self.current_txg, self.chain_digest);
            Ok(self.current_txg)
        } else if self.state_machine.is_open() {
            Err(CommitGroupError::PrepareFailed {
                reason: "a transaction group is already open; commit or abort it first".into(),
            })
        } else {
            // Mid-lifecycle (e.g., Sealed, Committing) -- caller should
            // complete or abort before beginning a new group.
            Err(CommitGroupError::PrepareFailed {
                reason: format!(
                    "cannot begin a new txg while current group is in {:?} state",
                    self.state_machine.state()
                ),
            })
        }
    }

    /// Commit the current transaction group.
    ///
    /// Drives the group through the full commit lifecycle:
    ///
    /// 1. **Seal** -- no more writes accepted.
    /// 2. **Begin commit** -- intent-log barrier records are written during
    ///    this phase (callers drain the intent-log buffer and pass the
    ///    serialized barrier content as `commit_data`).
    /// 3. **Complete commit** -- BLAKE3 chain digest is computed over
    ///    `commit_data`, chaining this group to its predecessor.
    /// 4. **Apply** -- committed group becomes live (readers see the new
    ///    root pointer on the next lookup).
    /// 5. **Notify sync gate** -- all fsync / syncfs waiters whose data
    ///    was in this group are woken.
    ///
    /// Returns the BLAKE3-256 chain digest for this commit.
    ///
    /// `commit_data` should include the serialized intent-log barrier
    /// content (e.g., hashes of drained frames). This data is hashed
    /// into the chain digest, making the barrier tamper-evident.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if no group is open
    /// or if any phase transition fails.
    pub fn commit_txg(&mut self, commit_data: &[u8]) -> Result<[u8; 32], CommitGroupError> {
        if !self.state_machine.is_open() {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "cannot commit txg: state machine is {:?} (expected Open)",
                    self.state_machine.state()
                ),
            });
        }

        // 1. Seal
        self.state_machine.seal()?;

        // 2. Begin commit -- intent-log barrier insertion point
        self.state_machine.begin_commit()?;

        // 3. Complete commit -- chain digest computation
        self.state_machine.complete_commit(commit_data)?;

        // 4. Apply
        self.state_machine.apply()?;

        // 5. Update chain digest
        self.chain_digest = self.state_machine.chain_digest();

        // 6. Notify sync gate -- committed root has advanced
        self.sync_gate.notify_committed(self.current_txg);

        Ok(self.chain_digest)
    }

    /// Abort the current transaction group.
    ///
    /// Discards all staged writes and metadata mutations. The group can
    /// be re-opened with [`begin_txg`](Self::begin_txg), which will
    /// advance to the next sequence number.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is
    /// already committed (a committed group cannot be aborted).
    pub fn abort_txg(&mut self) -> Result<(), CommitGroupError> {
        self.state_machine.abort()
    }

    /// Produce a [`TxGroupState`] record reflecting the current state
    /// for crash-recovery persistence.
    ///
    /// The caller should persist this record alongside the committed root
    /// after each successful `commit_txg` or `abort_txg`.
    #[must_use]
    pub fn to_state_record(&self) -> TxGroupState {
        let lifecycle = match self.state_machine.state() {
            crate::state_machine::CommitGroupState::Open => TxGroupLifecycle::Open,
            crate::state_machine::CommitGroupState::Committing => TxGroupLifecycle::Committing,
            crate::state_machine::CommitGroupState::Committed
            | crate::state_machine::CommitGroupState::Applied => TxGroupLifecycle::Committed,
            crate::state_machine::CommitGroupState::Aborted => TxGroupLifecycle::Aborted,
            _ => TxGroupLifecycle::Open,
        };
        TxGroupState::new(self.current_txg.0, lifecycle)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::compute_chain_digest;
    use std::thread;

    // ==================================================================
    // TxGroupLifecycle
    // ==================================================================

    #[test]
    fn lifecycle_discriminants_are_distinct() {
        let states = [
            TxGroupLifecycle::Open,
            TxGroupLifecycle::Committing,
            TxGroupLifecycle::Committed,
            TxGroupLifecycle::Aborted,
        ];
        for i in 0..states.len() {
            for j in 0..states.len() {
                if i == j {
                    assert_eq!(states[i], states[j]);
                } else {
                    assert_ne!(states[i], states[j]);
                }
            }
        }
    }

    #[test]
    fn lifecycle_roundtrip_discriminant() {
        for state in [
            TxGroupLifecycle::Open,
            TxGroupLifecycle::Committing,
            TxGroupLifecycle::Committed,
            TxGroupLifecycle::Aborted,
        ] {
            let d = state.to_discriminant();
            let back = TxGroupLifecycle::from_discriminant(d);
            assert_eq!(back, state, "roundtrip failed for {state:?}");
        }
    }

    #[test]
    fn lifecycle_unknown_discriminant_defaults_to_aborted() {
        assert_eq!(
            TxGroupLifecycle::from_discriminant(0),
            TxGroupLifecycle::Aborted
        );
        assert_eq!(
            TxGroupLifecycle::from_discriminant(5),
            TxGroupLifecycle::Aborted
        );
        assert_eq!(
            TxGroupLifecycle::from_discriminant(255),
            TxGroupLifecycle::Aborted
        );
    }

    // ==================================================================
    // TxGroupState: encode / decode / verify
    // ==================================================================

    #[test]
    fn tx_group_state_new_is_verified() {
        let record = TxGroupState::new(42, TxGroupLifecycle::Open);
        assert!(record.verify());
        assert_eq!(record.magic, TX_GROUP_STATE_MAGIC);
        assert_eq!(record.sequence, 42);
        assert_eq!(record.state, TxGroupLifecycle::Open);
    }

    #[test]
    fn tx_group_state_encode_decode_roundtrip() {
        for (seq, state) in [
            (1, TxGroupLifecycle::Open),
            (2, TxGroupLifecycle::Committing),
            (3, TxGroupLifecycle::Committed),
            (4, TxGroupLifecycle::Aborted),
        ] {
            let record = TxGroupState::new(seq, state);
            let encoded = record.encode();
            assert_eq!(encoded.len(), 45);
            let decoded = TxGroupState::decode(&encoded).unwrap();
            assert_eq!(decoded, record, "roundtrip failed for seq={seq} {state:?}");
        }
    }

    #[test]
    fn tx_group_state_decode_rejects_short_buffer() {
        let result = TxGroupState::decode(&[0u8; 10]);
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::PrepareFailed { reason }) => {
                assert!(reason.contains("expected 45 bytes"));
            }
            other => panic!("expected PrepareFailed, got {other:?}"),
        }
    }

    #[test]
    fn tx_group_state_decode_rejects_wrong_magic() {
        let mut buf = vec![0u8; 45];
        buf[0..4].copy_from_slice(b"BADC");
        let result = TxGroupState::decode(&buf);
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::PrepareFailed { reason }) => {
                assert!(reason.contains("magic mismatch"));
            }
            other => panic!("expected PrepareFailed, got {other:?}"),
        }
    }

    #[test]
    fn tx_group_state_decode_rejects_corrupt_checksum() {
        let record = TxGroupState::new(1, TxGroupLifecycle::Open);
        let mut encoded = record.encode();
        // Flip a byte in the checksum region (bytes 13..45).
        encoded[20] ^= 0xFF;
        let result = TxGroupState::decode(&encoded);
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::PrepareFailed { reason }) => {
                assert!(reason.contains("checksum verification failed"));
            }
            other => panic!("expected PrepareFailed, got {other:?}"),
        }
    }

    #[test]
    fn tx_group_state_checksum_changes_with_sequence() {
        let r1 = TxGroupState::new(1, TxGroupLifecycle::Open);
        let r2 = TxGroupState::new(2, TxGroupLifecycle::Open);
        assert_ne!(r1.checksum, r2.checksum);
    }

    #[test]
    fn tx_group_state_checksum_changes_with_state() {
        let r1 = TxGroupState::new(1, TxGroupLifecycle::Open);
        let r2 = TxGroupState::new(1, TxGroupLifecycle::Committed);
        assert_ne!(r1.checksum, r2.checksum);
    }

    #[test]
    fn tx_group_state_compute_checksum_deterministic() {
        let r1 = TxGroupState::new(100, TxGroupLifecycle::Committed);
        let r2 = TxGroupState::new(100, TxGroupLifecycle::Committed);
        assert_eq!(r1.compute_checksum(), r2.compute_checksum());
        assert_eq!(r1.checksum, r2.checksum);
    }

    #[test]
    fn tx_group_state_verify_tampered_magic_does_not_affect_checksum() {
        let mut r = TxGroupState::new(1, TxGroupLifecycle::Open);
        r.magic = *b"BADC";
        // Magic is verified during decode (not via checksum),
        // so tampering the in-memory struct field does not break verify.
        // The checksum uses the constant TX_GROUP_STATE_MAGIC as a type tag.
        assert!(r.verify());
    }

    #[test]
    fn tx_group_state_verify_fails_on_tampered_sequence() {
        let mut r = TxGroupState::new(1, TxGroupLifecycle::Open);
        r.sequence = 999;
        assert!(!r.verify());
    }

    #[test]
    fn tx_group_state_max_sequence() {
        let r = TxGroupState::new(u64::MAX, TxGroupLifecycle::Committed);
        assert!(r.verify());
        let encoded = r.encode();
        assert_eq!(encoded.len(), 45);
        let decoded = TxGroupState::decode(&encoded).unwrap();
        assert_eq!(decoded.sequence, u64::MAX);
    }

    // ==================================================================
    // TxGroupHandle: construction and accessors
    // ==================================================================

    #[test]
    fn new_handle_is_open() {
        let handle = TxGroupHandle::new(CommitGroupId::FIRST);
        assert!(handle.is_open());
        assert!(!handle.is_terminal());
        assert_eq!(handle.txg_id(), CommitGroupId::FIRST);
        assert_eq!(handle.chain_digest(), [0u8; 32]);
    }

    #[test]
    fn resume_handle_preserves_digest() {
        let digest = [0xABu8; 32];
        let handle = TxGroupHandle::resume(CommitGroupId(5), digest);
        assert_eq!(handle.chain_digest(), digest);
        assert!(handle.is_open());
    }

    #[test]
    fn to_state_record_reflects_open_state() {
        let handle = TxGroupHandle::new(CommitGroupId(3));
        let record = handle.to_state_record();
        assert_eq!(record.sequence, 3);
        assert_eq!(record.state, TxGroupLifecycle::Open);
        assert!(record.verify());
    }

    // ==================================================================
    // TxGroupHandle: begin_txg / commit_txg / abort_txg lifecycle
    // ==================================================================

    #[test]
    fn begin_commit_full_lifecycle() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);

        // Commit the open txg
        let digest = handle.commit_txg(b"lifecycle test").unwrap();
        assert!(!handle.is_open());
        assert!(handle.is_terminal());
        assert_ne!(digest, [0u8; 32]);

        // Begin a new txg
        let new_id = handle.begin_txg().unwrap();
        assert_eq!(new_id, CommitGroupId(2));
        assert!(handle.is_open());

        // Commit the second txg
        let digest2 = handle.commit_txg(b"second commit").unwrap();
        assert_ne!(digest2, digest);

        // Begin a third
        let id3 = handle.begin_txg().unwrap();
        assert_eq!(id3, CommitGroupId(3));
        let digest3 = handle.commit_txg(b"third commit").unwrap();
        assert_ne!(digest3, digest2);

        // Chain digests are linked
        let expected2 = compute_chain_digest(&digest, b"second commit");
        assert_eq!(digest2, expected2);
        let expected3 = compute_chain_digest(&digest2, b"third commit");
        assert_eq!(digest3, expected3);
    }

    #[test]
    fn abort_then_reopen() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        assert!(handle.is_open());

        handle.abort_txg().unwrap();
        assert!(handle.is_terminal());
        assert!(!handle.is_open());

        // Re-open after abort advances the txg id
        let new_id = handle.begin_txg().unwrap();
        assert_eq!(new_id, CommitGroupId(2));
        assert!(handle.is_open());

        let digest = handle.commit_txg(b"after abort").unwrap();
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn begin_txg_rejected_when_already_open() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        assert!(handle.is_open());

        let result = handle.begin_txg();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::PrepareFailed { reason }) => {
                assert!(reason.contains("already open"));
            }
            other => panic!("expected PrepareFailed, got {other:?}"),
        }
    }

    #[test]
    fn commit_txg_rejected_when_not_open() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        handle.commit_txg(b"first").unwrap();
        // State is terminal (Applied) -- cannot commit again
        let result = handle.commit_txg(b"second");
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { reason }) => {
                assert!(reason.contains("expected Open"));
            }
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    #[test]
    fn abort_txg_rejected_after_commit() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        handle.commit_txg(b"committed").unwrap();

        let result = handle.abort_txg();
        assert!(result.is_err());
        match result {
            Err(CommitGroupError::CommitPhaseRejected { reason }) => {
                assert!(reason.contains("cannot abort a Committed group"));
            }
            other => panic!("expected CommitPhaseRejected, got {other:?}"),
        }
    }

    #[test]
    fn double_abort_is_idempotent() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        handle.abort_txg().unwrap();
        // Second abort is a no-op
        assert!(handle.abort_txg().is_ok());
    }

    // ==================================================================
    // TxGroupHandle: chain digest integrity
    // ==================================================================

    #[test]
    fn chain_digest_depends_on_prior_state() {
        let mut h1 = TxGroupHandle::new(CommitGroupId::FIRST);
        let d1 = h1.commit_txg(b"data").unwrap();

        let mut h2 = TxGroupHandle::new(CommitGroupId::FIRST);
        let d1_alt = h2.commit_txg(b"different").unwrap();
        assert_ne!(d1, d1_alt);

        // After both begin a second txg, digests are based on different priors
        h1.begin_txg().unwrap();
        h1.commit_txg(b"same second data").unwrap();
        let d1_chain = h1.chain_digest();

        h2.begin_txg().unwrap();
        h2.commit_txg(b"same second data").unwrap();
        let d2_chain = h2.chain_digest();

        // Same second data, different prior -> different chain digest
        assert_ne!(d1_chain, d2_chain);
    }

    #[test]
    fn chain_digest_over_empty_commit_data() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        let digest = handle.commit_txg(b"").unwrap();
        assert_ne!(digest, [0u8; 32]);
    }

    // ==================================================================
    // TxGroupHandle: sync gate barrier semantics
    // ==================================================================

    #[test]
    fn sync_gate_durable_advances_on_commit() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        assert_eq!(handle.sync_gate().durable_commit_group(), CommitGroupId(0));

        handle.commit_txg(b"barrier 1").unwrap();
        assert_eq!(handle.sync_gate().durable_commit_group(), CommitGroupId(1));

        handle.begin_txg().unwrap();
        handle.commit_txg(b"barrier 2").unwrap();
        assert_eq!(handle.sync_gate().durable_commit_group(), CommitGroupId(2));
    }

    #[test]
    fn sync_gate_wakes_fsync_waiters_on_commit() {
        let handle = TxGroupHandle::new(CommitGroupId::FIRST);
        let gate = handle.sync_gate().clone();
        let mut handle = handle;

        // Register an inode as dirty in this txg
        gate.register_dirty(42, CommitGroupId::FIRST);

        // Spawn a thread that polls for durable advance
        let gate_clone = gate.clone();
        let waiter = thread::spawn(move || {
            while gate_clone.durable_commit_group() == CommitGroupId(0) {
                thread::yield_now();
            }
            gate_clone.durable_commit_group()
        });

        // Commit wakes the waiter
        handle.commit_txg(b"wake test").unwrap();

        let durable = waiter.join().unwrap();
        assert_eq!(durable, CommitGroupId(1));
    }

    #[test]
    fn sync_gate_durable_does_not_regress() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        handle.commit_txg(b"txg 1").unwrap();
        assert_eq!(handle.sync_gate().durable_commit_group(), CommitGroupId(1));

        handle.begin_txg().unwrap();
        handle.commit_txg(b"txg 2").unwrap();
        assert_eq!(handle.sync_gate().durable_commit_group(), CommitGroupId(2));
    }

    // ==================================================================
    // TxGroupHandle: state record during lifecycle
    // ==================================================================

    #[test]
    fn state_record_after_commit() {
        let mut handle = TxGroupHandle::new(CommitGroupId(7));
        handle.commit_txg(b"test").unwrap();

        let record = handle.to_state_record();
        assert_eq!(record.sequence, 7);
        assert_eq!(record.state, TxGroupLifecycle::Committed);
        assert!(record.verify());
    }

    #[test]
    fn state_record_after_abort() {
        let mut handle = TxGroupHandle::new(CommitGroupId(3));
        handle.abort_txg().unwrap();

        let record = handle.to_state_record();
        assert_eq!(record.sequence, 3);
        assert_eq!(record.state, TxGroupLifecycle::Aborted);
        assert!(record.verify());
    }

    // ==================================================================
    // TxGroupHandle: monotonic txg id advancement
    // ==================================================================

    #[test]
    fn txg_id_advances_monotonically_across_cycles() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);

        for expected in 1..=5u64 {
            assert_eq!(handle.txg_id(), CommitGroupId(expected));
            handle.commit_txg(b"monotonic").unwrap();
            if expected < 5 {
                handle.begin_txg().unwrap();
            }
        }

        assert_eq!(handle.txg_id(), CommitGroupId(5));
    }

    #[test]
    fn txg_id_advances_after_abort() {
        let mut handle = TxGroupHandle::new(CommitGroupId(10));
        handle.abort_txg().unwrap();
        handle.begin_txg().unwrap();
        assert_eq!(handle.txg_id(), CommitGroupId(11));
    }

    // ==================================================================
    // TxGroupHandle: clone and independent operation
    // ==================================================================

    #[test]
    fn cloned_handles_share_sync_gate() {
        let mut h1 = TxGroupHandle::new(CommitGroupId::FIRST);
        let h2 = h1.clone();

        // h1 commits
        h1.commit_txg(b"h1").unwrap();

        // h2's sync gate sees the same durable pointer
        assert_eq!(h2.sync_gate().durable_commit_group(), CommitGroupId(1));
    }

    // ==================================================================
    // TxGroupHandle: large commit data
    // ==================================================================

    #[test]
    fn commit_with_large_data() {
        let mut handle = TxGroupHandle::new(CommitGroupId::FIRST);
        let large_data = vec![0xAAu8; 65536];
        let digest = handle.commit_txg(&large_data).unwrap();
        assert_ne!(digest, [0u8; 32]);
    }
}
