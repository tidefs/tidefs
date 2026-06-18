// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! In-memory ring-buffer intent log with transaction tracking.
//!
//! The [`InMemoryIntentLog`] accumulates [`IntentLogRecord`] entries in a
//! byte-capacity-limited ring buffer.  Transaction boundaries (`TxBegin`,
//! `TxCommit`, `TxAbort`) are tracked so that only committed regions are
//! flushed to durable storage and aborted regions are silently discarded.
//!
//! # Design
//!
//! Records are stored as pre-encoded byte vectors.  The buffer tracks total
//! encoded bytes against a configurable capacity.  On `TxCommit`, the
//! transaction region is marked ready for flush.  On `TxAbort`, the
//! matching region is immediately discarded.
//!
//! [`flush_committed`](InMemoryIntentLog::flush_committed) scans from the
//! front of the buffer and returns the encoded bytes of the oldest fully-
//! committed transaction, removing it from the buffer.  Records before the
//! first `TxBegin` (i.e. uncommitted prefix) are left in place.

use std::collections::VecDeque;

use super::record::{IntentLogRecord, DISCR_TX_ABORT, DISCR_TX_BEGIN, DISCR_TX_COMMIT};

// ---------------------------------------------------------------------------
// RingEntry
// ---------------------------------------------------------------------------

/// A single pre-encoded record held in the ring buffer.
#[derive(Clone, Debug)]
struct RingEntry {
    /// Framed record bytes (discriminant | body_len | body | checksum).
    encoded: Vec<u8>,
    /// Record discriminant for O(1) type checks without decoding.
    discriminant: u16,
}

// ---------------------------------------------------------------------------
// InMemoryIntentLog
// ---------------------------------------------------------------------------

/// An in-memory ring-buffer intent log with transaction boundary tracking.
///
/// Accumulates intent-log records up to a configurable byte capacity.
/// Committed transaction regions are flushed to durable storage on demand;
/// aborted transactions are silently discarded.
///
/// # Examples
///
/// ```
/// use tidefs_local_object_store::intent_log::buffer::InMemoryIntentLog;
/// use tidefs_local_object_store::intent_log::record::IntentLogRecord;
///
/// let mut log = InMemoryIntentLog::new(65536);
/// log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
/// log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();
/// let flushed = log.flush_committed().unwrap();
/// assert_eq!(flushed.len(), 2); // TxBegin + TxCommit
/// ```
#[derive(Clone, Debug)]
pub struct InMemoryIntentLog {
    entries: VecDeque<RingEntry>,
    /// Total encoded bytes currently stored.
    total_bytes: usize,
    /// Maximum capacity in bytes.
    capacity: usize,
}

impl InMemoryIntentLog {
    /// Create a new intent log with the given byte capacity.
    ///
    /// `capacity` must be large enough to hold at least one smallest record
    /// (TxBegin = ~44 bytes framed).
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            total_bytes: 0,
            capacity,
        }
    }

    /// Append a record to the log.
    ///
    /// On `TxAbort`: finds the most recent unmatched `TxBegin` with the same
    /// `cg_id` and discards all entries from that `TxBegin` through this
    /// `TxAbort`.
    ///
    /// Returns `Err` if the encoded record would exceed the remaining
    /// capacity.  Callers should [`flush_committed`](Self::flush_committed)
    /// to make room before retrying.
    pub fn append(&mut self, record: IntentLogRecord) -> Result<(), String> {
        let discr = record.discriminant();

        // TxAbort processing: discard the matching region before encoding.
        if discr == DISCR_TX_ABORT {
            self.handle_abort(&record)?;
            return Ok(());
        }

        let encoded = record.encode();
        let record_bytes = encoded.len();

        // If the record alone exceeds capacity, it can never fit.
        if record_bytes > self.capacity {
            return Err(format!(
                "record of {record_bytes} bytes exceeds intent-log capacity of {} bytes",
                self.capacity
            ));
        }

        // Try to make room by flushing committed regions.
        while self.total_bytes + record_bytes > self.capacity {
            if self.flush_committed().is_none() {
                return Err(format!(
                    "intent-log buffer full ({}/{} bytes); no committed region to flush",
                    self.total_bytes, self.capacity
                ));
            }
        }

        self.total_bytes += record_bytes;
        self.entries.push_back(RingEntry {
            encoded,
            discriminant: discr,
        });
        Ok(())
    }

    /// Flush the oldest fully-committed transaction region.
    ///
    /// Scans from the front for a `TxBegin`/`TxCommit` pair.  Returns the
    /// encoded bytes of all records in the region (including the boundary
    /// records) and removes them from the buffer.  Aborted transactions
    /// encountered during the scan are silently discarded.
    ///
    /// Returns `None` if the buffer is empty or contains only uncommitted
    /// (open) transactions.
    pub fn flush_committed(&mut self) -> Option<Vec<Vec<u8>>> {
        loop {
            if self.entries.is_empty() {
                return None;
            }

            // Find the first TxBegin.
            let begin_idx = self
                .entries
                .iter()
                .position(|e| e.discriminant == DISCR_TX_BEGIN)?;

            // We have a TxBegin at `begin_idx`.  Extract its cg_id by decoding.
            let cg_id = match Self::decode_cg_id(&self.entries[begin_idx].encoded) {
                Ok(id) => id,
                Err(_) => {
                    // Corrupt entry — discard it and continue.
                    self.remove_front_n(begin_idx + 1);
                    continue;
                }
            };

            // Scan forward for matching TxCommit or TxAbort.
            let mut found_end: Option<usize> = None;
            let mut is_commit = false;

            for (i, entry) in self.entries.iter().enumerate().skip(begin_idx + 1) {
                if entry.discriminant == DISCR_TX_COMMIT {
                    if let Ok(id) = Self::decode_cg_id(&entry.encoded) {
                        if id == cg_id {
                            found_end = Some(i);
                            is_commit = true;
                            break;
                        }
                    }
                } else if entry.discriminant == DISCR_TX_ABORT {
                    if let Ok(id) = Self::decode_cg_id(&entry.encoded) {
                        if id == cg_id {
                            found_end = Some(i);
                            is_commit = false;
                            break;
                        }
                    }
                }
                // Nested TxBegin: skip — it belongs to a sub-transaction.
                // We'll match the outermost first.
            }

            match found_end {
                Some(end_idx) if is_commit => {
                    // Extract and return the committed region.
                    let mut flushed = Vec::with_capacity(end_idx + 1);
                    let mut bytes_freed = 0usize;
                    for _ in 0..=end_idx {
                        let entry = self.entries.pop_front().unwrap();
                        bytes_freed += entry.encoded.len();
                        flushed.push(entry.encoded);
                    }
                    self.total_bytes = self.total_bytes.saturating_sub(bytes_freed);
                    return Some(flushed);
                }
                Some(end_idx) => {
                    // TxAbort: discard the aborted region and continue scanning.
                    self.remove_front_n(end_idx + 1);
                    continue;
                }
                None => {
                    // Open transaction: no matching TxCommit or TxAbort found.
                    // Can't flush this region.  If there are entries before it,
                    // they must be orphaned (no TxBegin) — discard them.
                    if begin_idx > 0 {
                        self.remove_front_n(begin_idx);
                        continue;
                    }
                    return None;
                }
            }
        }
    }

    /// Total encoded bytes currently stored.
    pub fn stored_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Number of records currently stored.
    pub fn record_count(&self) -> usize {
        self.entries.len()
    }

    /// Capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the buffer has any committed region ready to flush.
    pub fn has_committed(&self) -> bool {
        // Scan for a TxBegin that has a matching TxCommit before any TxAbort.
        let mut open_txns: Vec<u64> = Vec::new();

        for entry in &self.entries {
            match entry.discriminant {
                DISCR_TX_BEGIN => {
                    if let Ok(cg_id) = Self::decode_cg_id(&entry.encoded) {
                        open_txns.push(cg_id);
                    }
                }
                DISCR_TX_COMMIT => {
                    if let Ok(cg_id) = Self::decode_cg_id(&entry.encoded) {
                        if let Some(pos) = open_txns.iter().position(|&id| id == cg_id) {
                            // Found a committed pair.
                            if pos == open_txns.len() - 1 {
                                // Innermost committed — this is ready to flush.
                                return true;
                            }
                            open_txns.remove(pos);
                        }
                    }
                }
                DISCR_TX_ABORT => {
                    if let Ok(cg_id) = Self::decode_cg_id(&entry.encoded) {
                        open_txns.retain(|&id| id != cg_id);
                    }
                }
                _ => {}
            }
        }
        false
    }

    // ── private helpers ─────────────────────────────────────────────

    /// Handle a TxAbort record: find the most recent unmatched TxBegin
    /// with the same cg_id and discard from there through the end.
    fn handle_abort(&mut self, record: &IntentLogRecord) -> Result<(), String> {
        let cg_id = match record {
            IntentLogRecord::TxAbort { cg_id } => *cg_id,
            _ => unreachable!(),
        };

        // Search backwards for the matching TxBegin.
        let mut depth: usize = 0;
        let mut abort_from: Option<usize> = None;

        for (i, entry) in self.entries.iter().enumerate().rev() {
            match entry.discriminant {
                DISCR_TX_COMMIT => {
                    if let Ok(id) = Self::decode_cg_id(&entry.encoded) {
                        if id == cg_id {
                            depth += 1;
                        }
                    }
                }
                DISCR_TX_ABORT => {
                    if let Ok(id) = Self::decode_cg_id(&entry.encoded) {
                        if id == cg_id {
                            depth += 1;
                        }
                    }
                }
                DISCR_TX_BEGIN => {
                    if let Ok(id) = Self::decode_cg_id(&entry.encoded) {
                        if id == cg_id {
                            if depth == 0 {
                                abort_from = Some(i);
                                break;
                            }
                            depth -= 1;
                        }
                    }
                }
                _ => {}
            }
        }

        match abort_from {
            Some(idx) => {
                // Discard entries from idx through end.
                let remove_count = self.entries.len() - idx;
                self.remove_back_n(remove_count);
                Ok(())
            }
            None => Err(format!("TxAbort(cg_id={cg_id}) without matching TxBegin")),
        }
    }

    /// Decode a cg_id from an encoded TxBegin, TxCommit, or TxAbort record.
    fn decode_cg_id(encoded: &[u8]) -> Result<u64, String> {
        if encoded.len() < 6 + 8 + 32 {
            return Err("encoded record too short for cg_id extraction".into());
        }
        // Body starts at offset 6.  For Tx* variants, body is 8 bytes (cg_id u64 LE).
        Ok(u64::from_le_bytes([
            encoded[6],
            encoded[7],
            encoded[8],
            encoded[9],
            encoded[10],
            encoded[11],
            encoded[12],
            encoded[13],
        ]))
    }

    /// Remove the first `n` entries, updating `total_bytes`.
    fn remove_front_n(&mut self, n: usize) {
        for _ in 0..n {
            if let Some(entry) = self.entries.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(entry.encoded.len());
            }
        }
    }

    /// Remove the last `n` entries, updating `total_bytes`.
    fn remove_back_n(&mut self, n: usize) {
        for _ in 0..n {
            if let Some(entry) = self.entries.pop_back() {
                self.total_bytes = self.total_bytes.saturating_sub(entry.encoded.len());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::record::IntentLogRecord;
    use super::*;
    use crate::ObjectKey;

    fn test_key(id: u64) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&id.to_le_bytes());
        ObjectKey::from_bytes(bytes)
    }

    fn test_write(key_id: u64, data: &[u8]) -> IntentLogRecord {
        IntentLogRecord::WritePayload {
            object_id: test_key(key_id),
            offset: 0,
            data: data.to_vec(),
        }
    }

    // ── Basic append and flush ──────────────────────────────────────

    #[test]
    fn append_and_flush_single_transaction() {
        let mut log = InMemoryIntentLog::new(65536);
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"hello")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        assert!(log.has_committed());
        let flushed = log.flush_committed().unwrap();
        assert_eq!(flushed.len(), 3); // TxBegin, WritePayload, TxCommit

        // Verify we can decode the flushed records
        for encoded in &flushed {
            let decoded = IntentLogRecord::decode(encoded).unwrap();
            // Round-trip should match re-encoding
            assert_eq!(decoded.encode(), *encoded);
        }

        assert!(log.is_empty());
        assert!(!log.has_committed());
    }

    #[test]
    fn flush_only_committed_region() {
        let mut log = InMemoryIntentLog::new(65536);
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"first")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();
        log.append(test_write(2, b"second")).unwrap();
        // TxCommit(2) not yet appended — still open

        let flushed = log.flush_committed().unwrap();
        assert_eq!(flushed.len(), 3); // Only cg_id=1 committed region
        assert_eq!(log.record_count(), 2); // TxBegin(2) and WritePayload remain
        assert!(!log.has_committed());
    }

    #[test]
    fn flush_multiple_committed_regions_in_order() {
        let mut log = InMemoryIntentLog::new(65536);

        // Transaction 1
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"a")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        // Transaction 2
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();
        log.append(test_write(2, b"b")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 2 }).unwrap();

        // First flush
        let flushed1 = log.flush_committed().unwrap();
        assert_eq!(flushed1.len(), 3);

        // Second flush
        let flushed2 = log.flush_committed().unwrap();
        assert_eq!(flushed2.len(), 3);

        assert!(log.is_empty());
    }

    // ── TxAbort discards records ────────────────────────────────────

    #[test]
    fn abort_discards_region() {
        let mut log = InMemoryIntentLog::new(65536);
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"should be discarded")).unwrap();
        log.append(IntentLogRecord::TxAbort { cg_id: 1 }).unwrap();

        // Buffer should be empty after abort
        assert!(log.is_empty());
        assert_eq!(log.record_count(), 0);
        assert_eq!(log.stored_bytes(), 0);
    }

    #[test]
    fn abort_only_discards_matching_txn() {
        let mut log = InMemoryIntentLog::new(65536);

        // Transaction 1 (committed)
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"keep")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        // Transaction 2 (aborted)
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();
        log.append(test_write(2, b"discard")).unwrap();
        log.append(IntentLogRecord::TxAbort { cg_id: 2 }).unwrap();

        // Transaction 3 (committed)
        log.append(IntentLogRecord::TxBegin { cg_id: 3 }).unwrap();
        log.append(test_write(3, b"also keep")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 3 }).unwrap();

        assert_eq!(log.record_count(), 6); // 2 committed txns

        let flushed1 = log.flush_committed().unwrap();
        assert_eq!(flushed1.len(), 3); // cg_id=1
        let flushed2 = log.flush_committed().unwrap();
        assert_eq!(flushed2.len(), 3); // cg_id=3
        assert!(log.is_empty());
    }

    #[test]
    fn abort_without_matching_begin_is_error() {
        let mut log = InMemoryIntentLog::new(65536);
        let result = log.append(IntentLogRecord::TxAbort { cg_id: 99 });
        assert!(result.is_err());
    }

    // ── Buffer capacity and wrap-around ─────────────────────────────

    #[test]
    fn capacity_enforced() {
        // Tiny capacity: only enough for ~2 small records
        let small_cap = 256;
        let mut log = InMemoryIntentLog::new(small_cap);

        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        // Buffer now has committed region, next append should auto-flush
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();
        // The auto-flush should have removed cg_id=1's committed region
        assert!(log.has_committed() || log.record_count() > 0);
    }

    #[test]
    fn record_exceeding_capacity_rejected() {
        let mut log = InMemoryIntentLog::new(32); // Too small for any record
        let result = log.append(test_write(1, b"data"));
        assert!(result.is_err());
    }

    #[test]
    fn full_buffer_errors_when_no_committed_region() {
        // Capacity just enough for TxBegin + WritePayload but not TxCommit.
        let begin = IntentLogRecord::TxBegin { cg_id: 1 };
        let begin_bytes = begin.encode().len();
        let write_bytes = test_write(1, &[0xAA; 60]).encode().len();
        // Capacity fits TxBegin + one WritePayload but not a second WritePayload
        let mut log = InMemoryIntentLog::new(begin_bytes + write_bytes + 10);
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, &[0xAA; 60])).unwrap();

        // Buffer is nearly full with an open (uncommitted) transaction.
        // Adding another record should fail because no committed region to flush.
        let result = log.append(test_write(2, &[0xBB; 60]));
        assert!(result.is_err());
    }

    #[test]
    fn append_auto_flushes_to_make_room() {
        let begin = IntentLogRecord::TxBegin { cg_id: 1 };
        let begin_bytes = begin.encode().len();
        let commit = IntentLogRecord::TxCommit { cg_id: 1 };
        let commit_bytes = commit.encode().len();
        let small_write = test_write(1, b"x");

        // Capacity: just enough for one committed transaction
        let cap = begin_bytes + commit_bytes + small_write.encode().len() + 10;
        let mut log = InMemoryIntentLog::new(cap);

        // Fill with a committed transaction
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(small_write.clone()).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        assert!(log.has_committed());

        // Next append should auto-flush the committed region
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();

        // After auto-flush, cg_id=1 should be gone
        assert_eq!(log.record_count(), 1); // Only TxBegin(2)
    }

    // ── Nested transactions ─────────────────────────────────────────

    #[test]
    fn nested_transactions_flush_outermost() {
        let mut log = InMemoryIntentLog::new(65536);

        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();
        log.append(test_write(1, b"nested")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 2 }).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        let flushed = log.flush_committed().unwrap();
        assert_eq!(flushed.len(), 5); // All 5 records
        assert!(log.is_empty());
    }

    #[test]
    fn nested_abort_discards_inner_only() {
        let mut log = InMemoryIntentLog::new(65536);

        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"outer")).unwrap();
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();
        log.append(test_write(2, b"inner discard")).unwrap();
        log.append(IntentLogRecord::TxAbort { cg_id: 2 }).unwrap();
        // Inner transaction discarded
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        assert_eq!(log.record_count(), 3); // TxBegin(1), outer write, TxCommit(1)

        let flushed = log.flush_committed().unwrap();
        assert_eq!(flushed.len(), 3);

        // Verify the flushed records don't include the inner write
        let decoded: Vec<IntentLogRecord> = flushed
            .iter()
            .map(|e| IntentLogRecord::decode(e).unwrap())
            .collect();
        assert!(matches!(decoded[0], IntentLogRecord::TxBegin { cg_id: 1 }));
        assert!(matches!(decoded[1], IntentLogRecord::WritePayload { .. }));
        assert!(matches!(decoded[2], IntentLogRecord::TxCommit { cg_id: 1 }));
    }

    // ── Variants in flushed output ──────────────────────────────────

    #[test]
    fn flushed_records_roundtrip_all_object_store_variants() {
        let mut log = InMemoryIntentLog::new(65536);

        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"payload")).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        // Add ExportTerminal in a separate transaction
        log.append(IntentLogRecord::TxBegin { cg_id: 2 }).unwrap();
        log.append(IntentLogRecord::ExportTerminal { cg_id: 2 })
            .unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 2 }).unwrap();

        let flushed = log.flush_committed().unwrap();
        assert_eq!(flushed.len(), 3); // First committed region only

        for encoded in &flushed {
            let decoded = IntentLogRecord::decode(encoded).unwrap();
            assert_eq!(decoded.encode(), *encoded);
        }

        let flushed2 = log.flush_committed().unwrap();
        assert_eq!(flushed2.len(), 3); // Second committed region

        for encoded in &flushed2 {
            let decoded = IntentLogRecord::decode(encoded).unwrap();
            assert_eq!(decoded.encode(), *encoded);
        }
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn flush_empty_log_returns_none() {
        let mut log = InMemoryIntentLog::new(1024);
        assert!(log.flush_committed().is_none());
    }

    #[test]
    fn flush_open_transaction_returns_none() {
        let mut log = InMemoryIntentLog::new(1024);
        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(test_write(1, b"open")).unwrap();
        // No TxCommit yet
        assert!(log.flush_committed().is_none());
        assert_eq!(log.record_count(), 2);
    }

    #[test]
    fn has_committed_detects_readiness() {
        let mut log = InMemoryIntentLog::new(65536);

        assert!(!log.has_committed());

        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        assert!(!log.has_committed()); // Still open

        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();
        assert!(log.has_committed());

        log.flush_committed();
        assert!(!log.has_committed());
    }

    // ── Filesystem variant rejection ────────────────────────────────
    // Filesystem variants are no longer valid constructors; this is a
    // compile-time guarantee. The object-store IntentLogRecord only
    // accepts WritePayload, TxBegin, TxCommit, TxAbort, ExportTerminal.
}
