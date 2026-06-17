//! Dead-object reclaim queue with commit_group-anchored reclamation eligibility.
//!
//! Provides a persistent, crash-safe queue for objects whose storage space
//! is eligible for reclamation only after the stable committed commit_group advances
//! past the object's `death_commit_group`.  Receipt-bound drains also require
//! durable replacement/base receipt evidence before old physical placement is
//! retired. Enqueue is idempotent by object ID.
//!
//! # Integration
//!
//! - **Snapshot destroy** enqueues dead objects after catalog removal.
//! - **Segment cleaner** enqueues dead objects after live-block relocation.
//! - **Allocator** calls `ack_reclaimed` after space is freed.

use alloc::collections::BTreeMap as BTreeMapAlloc;
use alloc::vec::Vec;
use core::fmt;

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy};
use tidefs_types_reclaim_queue_core::{
    DeadObjectEntry, DeadObjectReceiptPolicy, DeadObjectReplacementReceipt, ObjectKey,
};

/// Reason a shared placement receipt reference cannot authorize dead-object reclaim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementReceiptRefReclaimError {
    /// Generation-zero compatibility receipts are not durable placement authority.
    SyntheticReceipt,
    /// The shared receipt describes a different object key than the retired object.
    ObjectKeyMismatch {
        expected: ObjectKey,
        found: ObjectKey,
    },
    /// The redundancy policy cannot describe usable replacement placement.
    MalformedPolicy,
    /// The receipt recorded fewer physical targets than its redundancy policy requires.
    UnderWidthReceipt {
        target_count: u16,
        required_count: u16,
    },
}

impl fmt::Display for PlacementReceiptRefReclaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyntheticReceipt => {
                f.write_str("synthetic placement receipt cannot authorize reclaim")
            }
            Self::ObjectKeyMismatch { expected, found } => write!(
                f,
                "placement receipt object key mismatch: expected {expected}, found {found}"
            ),
            Self::MalformedPolicy => {
                f.write_str("placement receipt redundancy policy is malformed")
            }
            Self::UnderWidthReceipt {
                target_count,
                required_count,
            } => write!(
                f,
                "placement receipt target count {target_count} is below required width {required_count}"
            ),
        }
    }
}

/// Convert the shared distributed receipt policy into the dead-object queue
/// policy projection without changing the persisted queue format.
#[must_use]
pub const fn dead_object_policy_from_placement_ref(
    policy: ReceiptRedundancyPolicy,
) -> DeadObjectReceiptPolicy {
    match policy {
        ReceiptRedundancyPolicy::Replicated { copies } => {
            DeadObjectReceiptPolicy::Replicated { copies }
        }
        ReceiptRedundancyPolicy::Erasure {
            data_shards,
            parity_shards,
        } => DeadObjectReceiptPolicy::Erasure {
            data_shards,
            parity_shards,
        },
    }
}

/// Build dead-object replacement evidence from the canonical distributed
/// placement receipt reference.
///
/// The returned receipt is still keyed by the retired object id carried in the
/// dead-object queue. This helper only admits exact-key, non-synthetic,
/// policy-satisfying refs so callers cannot accidentally make receipt-bound
/// reclaim looser than the queue's existing gate.
pub fn replacement_receipt_from_placement_ref(
    retired_object_key: ObjectKey,
    placement_ref: PlacementReceiptRef,
) -> Result<DeadObjectReplacementReceipt, PlacementReceiptRefReclaimError> {
    if placement_ref.is_synthetic() {
        return Err(PlacementReceiptRefReclaimError::SyntheticReceipt);
    }

    let found_key = ObjectKey(placement_ref.object_key);
    if found_key != retired_object_key {
        return Err(PlacementReceiptRefReclaimError::ObjectKeyMismatch {
            expected: retired_object_key,
            found: found_key,
        });
    }

    if !placement_ref.redundancy_policy.is_well_formed() {
        return Err(PlacementReceiptRefReclaimError::MalformedPolicy);
    }

    let required_count = placement_ref.redundancy_policy.target_width();
    if placement_ref.target_count < required_count {
        return Err(PlacementReceiptRefReclaimError::UnderWidthReceipt {
            target_count: placement_ref.target_count,
            required_count,
        });
    }

    Ok(DeadObjectReplacementReceipt::new(
        retired_object_key,
        placement_ref.receipt_epoch.0,
        placement_ref.receipt_generation,
        dead_object_policy_from_placement_ref(placement_ref.redundancy_policy),
        placement_ref.payload_len,
        placement_ref.payload_digest,
        placement_ref.target_count,
    ))
}

/// Attach canonical placement receipt evidence to a dead-object entry.
pub fn dead_object_entry_with_placement_ref(
    entry: DeadObjectEntry,
    placement_ref: PlacementReceiptRef,
) -> Result<DeadObjectEntry, PlacementReceiptRefReclaimError> {
    let replacement_receipt =
        replacement_receipt_from_placement_ref(entry.object_id, placement_ref)?;
    Ok(entry.with_replacement_receipt(replacement_receipt))
}

// ---------------------------------------------------------------------------
// DeadObjectReclaimQueue
// ---------------------------------------------------------------------------

/// Persistent dead-object reclaim queue backed by an ordered map.
///
/// Entries are keyed by [`ObjectKey`] for deterministic iteration order
/// and idempotent enqueue (duplicate object IDs are silently ignored).
///
/// # Crash safety
///
/// On startup, call [`decode`](Self::decode) from the persisted bytes
/// to recover the queue.  Enqueue during normal operation is idempotent,
/// so re-enqueuing the same object after replay is a no-op.
///
/// # Eligibility
///
/// [`dequeue_batch`](Self::dequeue_batch) returns only entries whose
/// `death_commit_group` is strictly less than the provided `stable_committed_txg`
/// and whose `eligible` flag is `true`.  [`dequeue_receipt_bound_batch`] adds
/// the release-facing replacement/base receipt evidence gate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeadObjectReclaimQueue {
    entries: BTreeMapAlloc<ObjectKey, DeadObjectEntry>,
}

impl DeadObjectReclaimQueue {
    /// Create an empty dead-object reclaim queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMapAlloc::new(),
        }
    }

    /// Number of entries in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Enqueue a dead object for eventual reclamation.
    ///
    /// Idempotent: if an entry with the same `object_id` already exists,
    /// returns `Ok(false)` without modifying the queue.  This allows
    /// replay-safe re-enqueue during crash recovery.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the entry was newly inserted.
    /// - `Ok(false)` if the entry was already present (duplicate).
    pub fn enqueue(&mut self, entry: DeadObjectEntry) -> bool {
        use alloc::collections::btree_map::Entry;
        match self.entries.entry(entry.object_id) {
            Entry::Vacant(v) => {
                v.insert(entry);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Dequeue up to `max_count` eligible entries.
    ///
    /// An entry is eligible when `eligible` is `true` and `death_commit_group` is
    /// strictly less than `stable_committed_txg`.  Entries are returned in
    /// object-key order for deterministic processing.
    ///
    /// The entries are *not* removed from the queue; call
    /// [`ack_reclaimed`](Self::ack_reclaimed) after the allocator has
    /// freed the space.
    #[must_use]
    pub fn dequeue_batch(
        &self,
        max_count: usize,
        stable_committed_txg: u64,
    ) -> Vec<DeadObjectEntry> {
        if max_count == 0 || self.is_empty() {
            return Vec::new();
        }
        self.entries
            .values()
            .filter(|e| e.is_reclaimable(stable_committed_txg))
            .take(max_count)
            .copied()
            .collect()
    }

    /// Dequeue up to `max_count` entries authorized by txg, eligibility, and
    /// replacement/base placement receipt evidence.
    ///
    /// Compatibility callers may still use [`Self::dequeue_batch`]. Release
    /// reclaim drains that retire obsolete/source placement should use this
    /// receipt-bound path so legacy or malformed entries stay queued until
    /// durable replacement placement authority is attached.
    #[must_use]
    pub fn dequeue_receipt_bound_batch(
        &self,
        max_count: usize,
        stable_committed_txg: u64,
    ) -> Vec<DeadObjectEntry> {
        if max_count == 0 || self.is_empty() {
            return Vec::new();
        }
        self.entries
            .values()
            .filter(|e| e.is_receipt_bound_reclaimable(stable_committed_txg))
            .take(max_count)
            .copied()
            .collect()
    }

    /// Dequeue up to `max_count` entries authorized by txg, eligibility,
    /// replacement receipt evidence, and generation stability.
    ///
    /// This is the strictest drain gate required by rebake/reclaim durability
    /// gating (#346). Entries are only dequeued when their replacement
    /// receipt generation is at or below `stable_committed_generation`,
    /// proving the receipt publication is stable and cannot be rolled back.
    #[must_use]
    pub fn dequeue_receipt_bound_batch_with_stable_generation(
        &self,
        max_count: usize,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
    ) -> Vec<DeadObjectEntry> {
        if max_count == 0 || self.is_empty() {
            return Vec::new();
        }
        self.entries
            .values()
            .filter(|e| {
                e.is_receipt_bound_reclaimable_with_stable_generation(
                    stable_committed_txg,
                    stable_committed_generation,
                )
            })
            .take(max_count)
            .copied()
            .collect()
    }

    /// Publish a replacement/base placement receipt for a dead-object entry
    /// already in the queue. This is the rebake pathway: after rebake converts
    /// ingest extents to base shards, it calls this to attach the durable
    /// replacement receipt so the queue can authorize obsolete-ingest trim.
    ///
    /// If the entry already has a replacement receipt, the new receipt is
    /// accepted only when its generation is strictly greater (monotonic
    /// progression). A lower or equal generation is silently ignored.
    ///
    /// Returns `true` if the receipt was attached or replaced.
    pub fn publish_replacement_receipt(
        &mut self,
        object_id: &ObjectKey,
        receipt: DeadObjectReplacementReceipt,
    ) -> bool {
        if let Some(entry) = self.entries.get_mut(object_id) {
            let accept = match entry.replacement_receipt {
                Some(existing) => receipt.receipt_generation > existing.receipt_generation,
                None => true,
            };
            if accept {
                entry.replacement_receipt = Some(receipt);
                return true;
            }
        }
        false
    }

    /// Remove successfully reclaimed entries from the queue.
    ///
    /// Call this after the allocator has freed the objects' space.
    /// Missing keys are silently ignored (the entry may have been removed
    /// by a concurrent operation or a prior ack).
    ///
    /// Returns the number of entries actually removed.
    pub fn ack_reclaimed(&mut self, object_ids: &[ObjectKey]) -> usize {
        let mut removed = 0;
        for id in object_ids {
            if self.entries.remove(id).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Mark an entry as ineligible for reclamation.
    ///
    /// Used when a snapshot or clone references a dead object, preventing
    /// its space from being reclaimed until the reference is dropped.
    ///
    /// Returns `true` if the entry was found and updated.
    pub fn mark_ineligible(&mut self, object_id: &ObjectKey) -> bool {
        if let Some(entry) = self.entries.get_mut(object_id) {
            entry.eligible = false;
            true
        } else {
            false
        }
    }

    /// Mark an entry as eligible for reclamation.
    ///
    /// Used when the last snapshot/clone reference to a dead object is
    /// dropped, allowing the object's space to be reclaimed.
    ///
    /// Returns `true` if the entry was found and updated.
    pub fn mark_eligible(&mut self, object_id: &ObjectKey) -> bool {
        if let Some(entry) = self.entries.get_mut(object_id) {
            entry.eligible = true;
            true
        } else {
            false
        }
    }

    /// Return all entries in object-key order.
    #[must_use]
    pub fn all_entries(&self) -> Vec<DeadObjectEntry> {
        self.entries.values().copied().collect()
    }

    /// Number of entries currently eligible for reclamation given a
    /// stable committed commit_group.
    #[must_use]
    pub fn eligible_count(&self, stable_committed_txg: u64) -> usize {
        self.entries
            .values()
            .filter(|e| e.is_reclaimable(stable_committed_txg))
            .count()
    }

    /// Number of entries currently eligible for receipt-bound reclamation.
    #[must_use]
    pub fn receipt_bound_eligible_count(&self, stable_committed_txg: u64) -> usize {
        self.entries
            .values()
            .filter(|e| e.is_receipt_bound_reclaimable(stable_committed_txg))
            .count()
    }

    /// Number of entries eligible for receipt-bound reclamation with
    /// generation-stability gating.
    #[must_use]
    pub fn receipt_bound_eligible_count_with_stable_generation(
        &self,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
    ) -> usize {
        self.entries
            .values()
            .filter(|e| {
                e.is_receipt_bound_reclaimable_with_stable_generation(
                    stable_committed_txg,
                    stable_committed_generation,
                )
            })
            .count()
    }

    /// Remove all entries from the queue.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    // ------------------------------------------------------------------
    // Binary encoding
    // ------------------------------------------------------------------

    /// Magic bytes identifying a dead-object reclaim-queue payload.
    const MAGIC: &'static [u8; 4] = b"DRCL";

    /// Legacy binary format version without replacement receipt evidence.
    const FORMAT_VERSION_V1: u32 = 1;

    /// Current binary format version.
    const FORMAT_VERSION: u32 = 2;

    /// Schema family identifier for dead-object-queue BLAKE3 domain context.
    const FAMILY_ID: SchemaFamilyId = SchemaFamilyId(0x4452_434C_0000_0001);

    /// Schema type identifier for dead-object-queue format v1.
    const TYPE_ID: SchemaTypeId = SchemaTypeId(1);

    /// Schema version for dead-object-queue format v1.0.
    const VERSION_V1: SchemaVersion = SchemaVersion::new(1, 0);

    /// Schema version for dead-object-queue format v2.0.
    const VERSION: SchemaVersion = SchemaVersion::new(2, 0);

    /// Domain tag for dead-object-queue payload integrity.
    const DOMAIN_TAG: DomainTag = DomainTag::SectionBody;

    /// Encode the entire queue to a byte vector with a BLAKE3 integrity footer.
    ///
    /// Format (little-endian):
    /// - 4 bytes: magic `DRCL`
    /// - 4 bytes: format version (u32)
    /// - 4 bytes: entry count (u32)
    /// - N * current-version per-entry encoded records
    /// - 32 bytes: BLAKE3 domain-separated digest over all preceding bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let entries = self.all_entries();
        let count = entries.len() as u32;

        let body_len = 12usize
            .checked_add(count as usize * DeadObjectEntry::ENCODED_SIZE)
            .expect("dead-object queue too large to encode");
        let mut buf = Vec::with_capacity(body_len + 32);

        // Header
        buf.extend_from_slice(Self::MAGIC);
        buf.extend_from_slice(&Self::FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());

        // Entries
        for entry in &entries {
            buf.extend_from_slice(&entry.encode());
        }

        // BLAKE3 integrity footer over all preceding bytes
        let digest = blake3_domain_digest(
            &buf,
            Self::FAMILY_ID,
            Self::TYPE_ID,
            Self::VERSION,
            Self::DOMAIN_TAG,
        );
        buf.extend_from_slice(&digest);

        buf
    }

    /// Decode a queue from bytes previously produced by [`encode`](Self::encode).
    ///
    /// # Errors
    ///
    /// Returns [`DeadObjectQueueDecodeError`] if the buffer is truncated,
    /// has an invalid magic, an unsupported version, a corrupt entry, or a
    /// BLAKE3 integrity footer mismatch.
    pub fn decode(data: &[u8]) -> Result<Self, DeadObjectQueueDecodeError> {
        // Minimum size: header (12) + footer (32) = 44 bytes
        if data.len() < 44 {
            return Err(DeadObjectQueueDecodeError::Truncated);
        }

        // Verify magic
        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(DeadObjectQueueDecodeError::InvalidMagic);
        }

        // Verify version
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let (entry_size, schema_version) = match version {
            Self::FORMAT_VERSION_V1 => (DeadObjectEntry::ENCODED_SIZE_V1, Self::VERSION_V1),
            Self::FORMAT_VERSION => (DeadObjectEntry::ENCODED_SIZE, Self::VERSION),
            found => {
                return Err(DeadObjectQueueDecodeError::UnsupportedVersion {
                    found,
                    expected: Self::FORMAT_VERSION,
                })
            }
        };

        // Verify BLAKE3 integrity footer
        let body_len = data.len() - 32;
        let expected_digest = blake3_domain_digest(
            &data[..body_len],
            Self::FAMILY_ID,
            Self::TYPE_ID,
            schema_version,
            Self::DOMAIN_TAG,
        );
        let actual_digest: [u8; 32] = data[body_len..].try_into().unwrap();
        if expected_digest != actual_digest {
            return Err(DeadObjectQueueDecodeError::IntegrityFooterMismatch);
        }

        // Parse entry count
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let expected_body_len = 12usize
            .checked_add(
                count
                    .checked_mul(entry_size)
                    .ok_or(DeadObjectQueueDecodeError::Truncated)?,
            )
            .ok_or(DeadObjectQueueDecodeError::Truncated)?;

        if body_len < expected_body_len {
            return Err(DeadObjectQueueDecodeError::Truncated);
        }
        if body_len > expected_body_len {
            return Err(DeadObjectQueueDecodeError::TrailingBytes {
                found: body_len,
                expected: expected_body_len,
            });
        }

        // Parse entries (enqueue is idempotent, so duplicates in data are harmless)
        let mut queue = Self::new();
        for i in 0..count {
            let offset = 12 + i * entry_size;
            let entry = if version == Self::FORMAT_VERSION_V1 {
                let entry_bytes: &[u8; DeadObjectEntry::ENCODED_SIZE_V1] = data
                    [offset..offset + DeadObjectEntry::ENCODED_SIZE_V1]
                    .try_into()
                    .map_err(|_| DeadObjectQueueDecodeError::Truncated)?;
                DeadObjectEntry::decode_v1(entry_bytes)
            } else {
                let entry_bytes: &[u8; DeadObjectEntry::ENCODED_SIZE] = data
                    [offset..offset + DeadObjectEntry::ENCODED_SIZE]
                    .try_into()
                    .map_err(|_| DeadObjectQueueDecodeError::Truncated)?;
                DeadObjectEntry::decode(entry_bytes)
            }
            .map_err(|e| DeadObjectQueueDecodeError::EntryDecode(alloc::format!("{e}")))?;
            queue.enqueue(entry);
        }

        Ok(queue)
    }

    /// Estimate the serialized byte size without allocating.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let count = self.len();
        12 + count * DeadObjectEntry::ENCODED_SIZE + 32
    }
}

// ---------------------------------------------------------------------------
// DeadObjectQueueDecodeError -- queue-level decode failure
// ---------------------------------------------------------------------------

/// Errors that can occur when decoding a [`DeadObjectReclaimQueue`] from
/// its wire-format encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeadObjectQueueDecodeError {
    /// Data is shorter than the minimum header + footer.
    Truncated,
    /// Magic bytes do not match the expected `DRCL`.
    InvalidMagic,
    /// Format version is not supported.
    UnsupportedVersion { found: u32, expected: u32 },
    /// A per-entry decode failed.
    EntryDecode(String),
    /// The body carried bytes beyond the declared entry count.
    TrailingBytes { found: usize, expected: usize },
    /// The BLAKE3 integrity footer did not verify.
    IntegrityFooterMismatch,
}

impl core::fmt::Display for DeadObjectQueueDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated dead-object-queue data"),
            Self::InvalidMagic => f.write_str("invalid dead-object-queue magic bytes"),
            Self::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported dead-object-queue version: found {found}, expected {expected}"
                )
            }
            Self::EntryDecode(msg) => {
                write!(f, "dead-object-queue entry decode error: {msg}")
            }
            Self::TrailingBytes { found, expected } => {
                write!(
                    f,
                    "dead-object-queue trailing bytes: found body length {found}, expected {expected}"
                )
            }
            Self::IntegrityFooterMismatch => {
                f.write_str("dead-object-queue BLAKE3 integrity footer mismatch")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_replication_model::{ReceiptRedundancyPolicy, ReplicatedSubjectId};

    fn oid(byte: u8) -> ObjectKey {
        let mut k = [0u8; 32];
        k[0] = byte;
        ObjectKey(k)
    }

    fn entry(id: u8, death_commit_group: u64, eligible: bool, enqueued_at: u64) -> DeadObjectEntry {
        DeadObjectEntry::new(
            oid(id),
            [0u8; 16],
            death_commit_group,
            eligible,
            enqueued_at,
        )
    }

    fn digest(byte: u8) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest[0] = byte;
        digest
    }

    fn receipt(id: u8) -> DeadObjectReplacementReceipt {
        DeadObjectReplacementReceipt::replicated(oid(id), 7, 1, 2, 4096, digest(id))
    }

    fn placement_ref(
        key: ObjectKey,
        generation: u64,
        redundancy_policy: ReceiptRedundancyPolicy,
        target_count: u16,
    ) -> PlacementReceiptRef {
        PlacementReceiptRef {
            object_id: u64::from(key.0[0]),
            object_key: key.0,
            receipt_epoch: Default::default(),
            receipt_generation: generation,
            redundancy_policy,
            payload_len: 4096,
            payload_digest: digest(key.0[0]),
            target_count,
        }
    }

    fn entry_with_receipt(
        id: u8,
        death_commit_group: u64,
        eligible: bool,
        enqueued_at: u64,
    ) -> DeadObjectEntry {
        entry(id, death_commit_group, eligible, enqueued_at).with_replacement_receipt(receipt(id))
    }

    fn encode_v1_entry(entry: DeadObjectEntry) -> [u8; DeadObjectEntry::ENCODED_SIZE_V1] {
        let mut buf = [0u8; DeadObjectEntry::ENCODED_SIZE_V1];
        buf[0..32].copy_from_slice(&entry.object_id.0);
        buf[32..48].copy_from_slice(&entry.dataset_uuid);
        buf[48..56].copy_from_slice(&entry.death_commit_group.to_le_bytes());
        buf[56] = u8::from(entry.eligible);
        buf[57..65].copy_from_slice(&entry.enqueued_at_txg.to_le_bytes());
        buf
    }

    // ── enqueue / idempotency ─────────────────────────────────────────

    #[test]
    fn enqueue_adds_entry() {
        let mut q = DeadObjectReclaimQueue::new();
        assert!(q.enqueue(entry(1, 10, true, 5)));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn enqueue_idempotent_duplicate_is_noop() {
        let mut q = DeadObjectReclaimQueue::new();
        assert!(q.enqueue(entry(1, 10, true, 5)));
        assert!(!q.enqueue(entry(1, 20, false, 6))); // different fields, same object_id
        assert_eq!(q.len(), 1);
        // Original entry is preserved (first-write-wins)
        let all = q.all_entries();
        assert_eq!(all[0].death_commit_group, 10);
        assert!(all[0].eligible);
    }

    #[test]
    fn enqueue_multiple_different_ids() {
        let mut q = DeadObjectReclaimQueue::new();
        for i in 1..=10u8 {
            assert!(q.enqueue(entry(i, i as u64 * 10, true, i as u64)));
        }
        assert_eq!(q.len(), 10);
    }

    // ── dequeue_batch eligibility ──────────────────────────────────────

    #[test]
    fn dequeue_batch_respects_max_count() {
        let mut q = DeadObjectReclaimQueue::new();
        for i in 1..=5u8 {
            q.enqueue(entry(i, i as u64, true, 0));
        }
        let batch = q.dequeue_batch(3, 100);
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn dequeue_batch_filters_by_death_txg() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 10, true, 0)); // death_commit_group=10, not eligible at stable=10
        q.enqueue(entry(2, 5, true, 0)); // death_commit_group=5, eligible at stable=10
        q.enqueue(entry(3, 10, true, 0)); // death_commit_group=10, not eligible at stable=10

        let batch = q.dequeue_batch(10, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(2));
    }

    #[test]
    fn dequeue_batch_respects_eligible_flag() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, false, 0)); // death_commit_group=5, eligible=false => NOT eligible
        q.enqueue(entry(2, 5, true, 0)); // death_commit_group=5, eligible=true => eligible

        let batch = q.dequeue_batch(10, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(2));
    }

    #[test]
    fn dequeue_batch_returns_deterministic_order() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(30, 1, true, 0));
        q.enqueue(entry(10, 1, true, 0));
        q.enqueue(entry(20, 1, true, 0));

        let batch = q.dequeue_batch(10, 100);
        let ids: Vec<u8> = batch.iter().map(|e| e.object_id.0[0]).collect();
        assert_eq!(ids, [10, 20, 30]); // sorted by ObjectKey
    }

    #[test]
    fn dequeue_batch_does_not_remove_entries() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        q.enqueue(entry(2, 5, true, 0));

        let batch = q.dequeue_batch(10, 10);
        assert_eq!(batch.len(), 2);
        assert_eq!(q.len(), 2); // entries still in queue

        // Same entries dequeued again
        let batch2 = q.dequeue_batch(10, 10);
        assert_eq!(batch2.len(), 2);
    }

    #[test]
    fn dequeue_batch_empty_queue() {
        let q = DeadObjectReclaimQueue::new();
        assert!(q.dequeue_batch(10, 100).is_empty());
    }

    #[test]
    fn dequeue_batch_max_count_zero() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        assert!(q.dequeue_batch(0, 100).is_empty());
    }

    #[test]
    fn receipt_bound_dequeue_requires_replacement_receipt() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        q.enqueue(entry_with_receipt(2, 5, true, 0));

        let compatibility_batch = q.dequeue_batch(10, 10);
        assert_eq!(compatibility_batch.len(), 2);

        let receipt_bound_batch = q.dequeue_receipt_bound_batch(10, 10);
        assert_eq!(receipt_bound_batch.len(), 1);
        assert_eq!(receipt_bound_batch[0].object_id, oid(2));
    }

    #[test]
    fn receipt_bound_dequeue_rejects_synthetic_malformed_and_under_width() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0).with_replacement_receipt(
            DeadObjectReplacementReceipt::replicated(oid(1), 7, 0, 2, 4096, digest(1)),
        ));
        q.enqueue(entry(2, 5, true, 0).with_replacement_receipt(
            DeadObjectReplacementReceipt::new(
                oid(2),
                7,
                1,
                DeadObjectReceiptPolicy::Replicated { copies: 0 },
                4096,
                digest(2),
                0,
            ),
        ));
        q.enqueue(entry(3, 5, true, 0).with_replacement_receipt(
            DeadObjectReplacementReceipt::new(
                oid(3),
                7,
                1,
                DeadObjectReceiptPolicy::Erasure {
                    data_shards: 2,
                    parity_shards: 1,
                },
                4096,
                digest(3),
                2,
            ),
        ));
        q.enqueue(entry_with_receipt(4, 5, true, 0));

        let batch = q.dequeue_receipt_bound_batch(10, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(4));
        assert_eq!(q.receipt_bound_eligible_count(10), 1);
    }

    #[test]
    fn receipt_bound_dequeue_still_respects_txg_and_eligible_flag() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry_with_receipt(1, 10, true, 0));
        q.enqueue(entry_with_receipt(2, 5, false, 0));
        q.enqueue(entry_with_receipt(3, 5, true, 0));

        let batch = q.dequeue_receipt_bound_batch(10, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(3));
        assert_eq!(q.eligible_count(10), 1);
        assert_eq!(q.receipt_bound_eligible_count(10), 1);
    }

    #[test]
    fn placement_ref_bridge_authorizes_receipt_bound_dequeue() {
        let key = oid(0x70);
        let entry = DeadObjectEntry::new(key, [0x70; 16], 5, true, 4);
        let placement_ref =
            placement_ref(key, 9, ReceiptRedundancyPolicy::Replicated { copies: 2 }, 2);

        let bridged =
            dead_object_entry_with_placement_ref(entry, placement_ref).expect("bridge receipt");
        assert_eq!(
            bridged.replacement_receipt.unwrap(),
            DeadObjectReplacementReceipt::replicated(key, 0, 9, 2, 4096, digest(0x70))
        );

        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(bridged);

        let batch = q.dequeue_receipt_bound_batch(10, 6);
        assert_eq!(batch, vec![bridged]);
    }

    #[test]
    fn placement_ref_bridge_rejects_synthetic_receipts() {
        let key = oid(0x71);
        let entry = DeadObjectEntry::new(key, [0x71; 16], 5, true, 4);
        let synthetic = PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(0x71));

        let err = dead_object_entry_with_placement_ref(entry, synthetic)
            .expect_err("synthetic ref must not authorize reclaim");
        assert_eq!(err, PlacementReceiptRefReclaimError::SyntheticReceipt);

        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry);
        assert!(q.dequeue_receipt_bound_batch(10, 6).is_empty());
    }

    #[test]
    fn placement_ref_bridge_rejects_object_key_mismatch() {
        let entry = DeadObjectEntry::new(oid(0x72), [0x72; 16], 5, true, 4);
        let placement_ref = placement_ref(
            oid(0x73),
            10,
            ReceiptRedundancyPolicy::Replicated { copies: 2 },
            2,
        );

        let err = dead_object_entry_with_placement_ref(entry, placement_ref)
            .expect_err("mismatched ref must fail");
        assert_eq!(
            err,
            PlacementReceiptRefReclaimError::ObjectKeyMismatch {
                expected: oid(0x72),
                found: oid(0x73),
            }
        );
    }

    #[test]
    fn placement_ref_bridge_rejects_malformed_policy() {
        let key = oid(0x74);
        let entry = DeadObjectEntry::new(key, [0x74; 16], 5, true, 4);
        let placement_ref = placement_ref(
            key,
            10,
            ReceiptRedundancyPolicy::Replicated { copies: 0 },
            0,
        );

        let err = dead_object_entry_with_placement_ref(entry, placement_ref)
            .expect_err("malformed policy must fail");
        assert_eq!(err, PlacementReceiptRefReclaimError::MalformedPolicy);
    }

    #[test]
    fn placement_ref_bridge_rejects_under_width_receipts() {
        let key = oid(0x75);
        let entry = DeadObjectEntry::new(key, [0x75; 16], 5, true, 4);
        let placement_ref = placement_ref(
            key,
            10,
            ReceiptRedundancyPolicy::Erasure {
                data_shards: 2,
                parity_shards: 1,
            },
            2,
        );

        let err = dead_object_entry_with_placement_ref(entry, placement_ref)
            .expect_err("under-width receipt must fail");
        assert_eq!(
            err,
            PlacementReceiptRefReclaimError::UnderWidthReceipt {
                target_count: 2,
                required_count: 3,
            }
        );
    }

    // ── ack_reclaimed ──────────────────────────────────────────────────

    #[test]
    fn ack_reclaimed_removes_entries() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        q.enqueue(entry(2, 5, true, 0));
        q.enqueue(entry(3, 5, true, 0));

        let removed = q.ack_reclaimed(&[oid(1), oid(3)]);
        assert_eq!(removed, 2);
        assert_eq!(q.len(), 1);
        assert_eq!(q.all_entries()[0].object_id, oid(2));
    }

    #[test]
    fn ack_reclaimed_missing_keys_silently_ignored() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));

        let removed = q.ack_reclaimed(&[oid(1), oid(99)]);
        assert_eq!(removed, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn ack_reclaimed_empty_ids_removes_none() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        assert_eq!(q.ack_reclaimed(&[]), 0);
        assert_eq!(q.len(), 1);
    }

    // ── mark_ineligible / mark_eligible ────────────────────────────────

    #[test]
    fn mark_ineligible_sets_flag() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        assert!(q.mark_ineligible(&oid(1)));
        // Now not eligible regardless of commit_group
        assert!(q.dequeue_batch(10, 100).is_empty());
    }

    #[test]
    fn mark_ineligible_missing_key_returns_false() {
        let mut q = DeadObjectReclaimQueue::new();
        assert!(!q.mark_ineligible(&oid(99)));
    }

    #[test]
    fn mark_eligible_restores_eligibility() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, false, 0));
        assert!(q.mark_eligible(&oid(1)));
        let batch = q.dequeue_batch(10, 10);
        assert_eq!(batch.len(), 1);
    }

    // ── eligible_count ─────────────────────────────────────────────────

    #[test]
    fn eligible_count_mixed() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0)); // eligible at stable=10
        q.enqueue(entry(2, 15, true, 0)); // NOT eligible at stable=10
        q.enqueue(entry(3, 5, false, 0)); // NOT eligible (flag)
        q.enqueue(entry(4, 8, true, 0)); // eligible at stable=10

        assert_eq!(q.eligible_count(10), 2);
    }

    // ── clear ──────────────────────────────────────────────────────────

    #[test]
    fn clear_empties_queue() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        q.enqueue(entry(2, 5, true, 0));
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    // ── encode / decode round-trip ─────────────────────────────────────

    #[test]
    fn encode_decode_empty_queue() {
        let q = DeadObjectReclaimQueue::new();
        let bytes = q.encode();
        let decoded = DeadObjectReclaimQueue::decode(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_decode_single_entry() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry_with_receipt(42, 10, true, 5));
        let bytes = q.encode();
        let decoded = DeadObjectReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.all_entries(), q.all_entries());
        assert_eq!(decoded.receipt_bound_eligible_count(11), 1);
    }

    #[test]
    fn decode_v1_queue_entries_lack_receipt_evidence() {
        let legacy_entry = entry(7, 5, true, 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DeadObjectReclaimQueue::MAGIC);
        bytes.extend_from_slice(&DeadObjectReclaimQueue::FORMAT_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&encode_v1_entry(legacy_entry));
        let digest = blake3_domain_digest(
            &bytes,
            DeadObjectReclaimQueue::FAMILY_ID,
            DeadObjectReclaimQueue::TYPE_ID,
            DeadObjectReclaimQueue::VERSION_V1,
            DeadObjectReclaimQueue::DOMAIN_TAG,
        );
        bytes.extend_from_slice(&digest);

        let decoded = DeadObjectReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.dequeue_batch(10, 10).len(), 1);
        assert!(decoded.dequeue_receipt_bound_batch(10, 10).is_empty());
        assert_eq!(decoded.all_entries()[0].replacement_receipt, None);
    }

    #[test]
    fn encode_decode_many_entries() {
        let mut q = DeadObjectReclaimQueue::new();
        for i in 0..100u8 {
            q.enqueue(entry(i, i as u64 + 1, i % 2 == 0, i as u64));
        }
        let bytes = q.encode();
        let decoded = DeadObjectReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), q.len());
        assert_eq!(decoded, q);
    }

    #[test]
    fn encode_decode_mixed_eligibility() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 1));
        q.enqueue(entry(2, 10, false, 2));
        q.enqueue(entry(3, 15, true, 3));

        let bytes = q.encode();
        let decoded = DeadObjectReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded, q);

        // Eligibility should survive round-trip
        let batch = decoded.dequeue_batch(10, 10);
        assert_eq!(batch.len(), 1); // only id=1 has death_commit_group(5) < 10 AND eligible=true
    }

    #[test]
    fn encode_decode_max_txg_values() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(DeadObjectEntry::new(
            oid(1),
            [0xFFu8; 16],
            u64::MAX,
            true,
            u64::MAX,
        ));
        let bytes = q.encode();
        let decoded = DeadObjectReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded, q);
    }

    #[test]
    fn encoded_len_matches_actual() {
        let mut q = DeadObjectReclaimQueue::new();
        assert_eq!(q.encode().len(), q.encoded_len());

        q.enqueue(entry(1, 5, true, 0));
        assert_eq!(q.encode().len(), q.encoded_len());

        for i in 2..=20u8 {
            q.enqueue(entry(i, i as u64, true, 0));
        }
        assert_eq!(q.encode().len(), q.encoded_len());
    }

    #[test]
    fn encoded_len_formula() {
        let n = 10;
        let mut q = DeadObjectReclaimQueue::new();
        for i in 0..n {
            q.enqueue(entry(i as u8, 1, true, 0));
        }
        // 12 header + current-version entries + 32 footer.
        assert_eq!(q.encoded_len(), 12 + n * DeadObjectEntry::ENCODED_SIZE + 32);
    }

    // ── decode error conditions ────────────────────────────────────────

    #[test]
    fn decode_rejects_truncated() {
        assert_eq!(
            DeadObjectReclaimQueue::decode(&[0u8; 8]),
            Err(DeadObjectQueueDecodeError::Truncated)
        );
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"XXXX");
        // Recompute footer over the bad body
        let body = &data[..12];
        let digest = blake3_domain_digest(
            body,
            DeadObjectReclaimQueue::FAMILY_ID,
            DeadObjectReclaimQueue::TYPE_ID,
            DeadObjectReclaimQueue::VERSION,
            DeadObjectReclaimQueue::DOMAIN_TAG,
        );
        data[12..44].copy_from_slice(&digest);
        assert_eq!(
            DeadObjectReclaimQueue::decode(&data),
            Err(DeadObjectQueueDecodeError::InvalidMagic)
        );
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"DRCL");
        header[4..8].copy_from_slice(&99u32.to_le_bytes());
        header[8..12].copy_from_slice(&0u32.to_le_bytes());
        let digest = blake3_domain_digest(
            &header,
            DeadObjectReclaimQueue::FAMILY_ID,
            DeadObjectReclaimQueue::TYPE_ID,
            DeadObjectReclaimQueue::VERSION,
            DeadObjectReclaimQueue::DOMAIN_TAG,
        );
        let mut data = header;
        data.extend_from_slice(&digest);
        assert_eq!(
            DeadObjectReclaimQueue::decode(&data),
            Err(DeadObjectQueueDecodeError::UnsupportedVersion {
                found: 99,
                expected: 2,
            })
        );
    }

    #[test]
    fn decode_rejects_corrupted_footer() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 5, true, 0));
        let mut bytes = q.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert_eq!(
            DeadObjectReclaimQueue::decode(&bytes),
            Err(DeadObjectQueueDecodeError::IntegrityFooterMismatch)
        );
    }

    #[test]
    fn decode_rejects_trailing_body_bytes() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry_with_receipt(1, 5, true, 0));
        let mut bytes = q.encode();
        let footer = bytes.split_off(bytes.len() - 32);
        bytes.push(0xA5);
        let digest = blake3_domain_digest(
            &bytes,
            DeadObjectReclaimQueue::FAMILY_ID,
            DeadObjectReclaimQueue::TYPE_ID,
            DeadObjectReclaimQueue::VERSION,
            DeadObjectReclaimQueue::DOMAIN_TAG,
        );
        assert_ne!(digest, footer.as_slice());
        bytes.extend_from_slice(&digest);

        assert_eq!(
            DeadObjectReclaimQueue::decode(&bytes),
            Err(DeadObjectQueueDecodeError::TrailingBytes {
                found: 12 + DeadObjectEntry::ENCODED_SIZE + 1,
                expected: 12 + DeadObjectEntry::ENCODED_SIZE,
            })
        );
    }

    #[test]
    fn decode_errors_display_non_empty() {
        let variants = [
            DeadObjectQueueDecodeError::Truncated,
            DeadObjectQueueDecodeError::InvalidMagic,
            DeadObjectQueueDecodeError::UnsupportedVersion {
                found: 2,
                expected: 1,
            },
            DeadObjectQueueDecodeError::EntryDecode("test".into()),
            DeadObjectQueueDecodeError::TrailingBytes {
                found: 1,
                expected: 0,
            },
            DeadObjectQueueDecodeError::IntegrityFooterMismatch,
        ];
        for err in &variants {
            let s = alloc::format!("{err}");
            assert!(!s.is_empty(), "Display output empty for {err:?}");
        }
    }

    // ── integration-style tests ────────────────────────────────────────

    #[test]
    fn full_lifecycle_enqueue_dequeue_ack() {
        let mut q = DeadObjectReclaimQueue::new();

        // Simulate: objects die at different txgs
        q.enqueue(entry(1, 100, true, 100)); // died at commit_group 100
        q.enqueue(entry(2, 200, true, 200)); // died at commit_group 200
        q.enqueue(entry(3, 300, true, 300)); // died at commit_group 300

        // At stable_txg=150, only object 1 is eligible
        let batch = q.dequeue_batch(10, 150);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(1));

        // Ack reclaimed object 1
        let removed = q.ack_reclaimed(&[oid(1)]);
        assert_eq!(removed, 1);
        assert_eq!(q.len(), 2);

        // At stable_txg=250, object 2 becomes eligible
        let batch = q.dequeue_batch(10, 250);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(2));

        // Ack reclaimed object 2
        q.ack_reclaimed(&[oid(2)]);
        assert_eq!(q.len(), 1);

        // At stable_txg=350, object 3 becomes eligible
        let batch = q.dequeue_batch(10, 350);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(3));
    }

    #[test]
    fn snapshot_reference_prevents_reclamation() {
        let mut q = DeadObjectReclaimQueue::new();

        // Object dies but a snapshot still references it
        q.enqueue(entry(1, 100, true, 100));

        // Snapshot exists -> mark ineligible
        assert!(q.mark_ineligible(&oid(1)));

        // Even though death_commit_group < stable_txg, eligible=false blocks reclamation
        let batch = q.dequeue_batch(10, 200);
        assert!(batch.is_empty());

        // Snapshot destroyed -> mark eligible
        assert!(q.mark_eligible(&oid(1)));
        let batch = q.dequeue_batch(10, 200);
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn crash_recovery_replay_is_idempotent() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(entry(1, 10, true, 5));
        q.enqueue(entry(2, 12, true, 6));
        q.enqueue(entry(3, 14, true, 7));

        // Persist
        let bytes = q.encode();

        // Simulate crash and reload
        let recovered = DeadObjectReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(recovered, q);

        // Re-enqueue same objects (replay) -- should be idempotent
        let mut q2 = recovered;
        assert!(!q2.enqueue(entry(1, 10, true, 5))); // duplicate
        assert!(!q2.enqueue(entry(2, 12, true, 6))); // duplicate
        assert!(q2.enqueue(entry(4, 16, true, 8))); // new entry

        assert_eq!(q2.len(), 4); // original 3 + new 1
    }

    #[test]
    fn large_queue_encode_decode_is_deterministic() {
        let mut q = DeadObjectReclaimQueue::new();
        for i in 0..500u16 {
            let byte = (i % 256) as u8;
            q.enqueue(entry(byte, i as u64, i % 2 == 0, i as u64));
        }
        let bytes1 = q.encode();
        let bytes2 = q.encode();
        assert_eq!(bytes1, bytes2, "encode must be deterministic");
        let decoded = DeadObjectReclaimQueue::decode(&bytes1).unwrap();
        assert_eq!(decoded.len(), q.len());
    }
    // ── receipt-bound reclaim tests for #346 ────────────────────────────

    fn erasure_entry(
        object_byte: u8,
        death_txg: u64,
        receipt_generation: u64,
        data_shards: u8,
        parity_shards: u8,
    ) -> DeadObjectEntry {
        let key = oid(object_byte);
        let receipt = DeadObjectReplacementReceipt::erasure_coded(
            key,
            7,
            receipt_generation,
            data_shards,
            parity_shards,
            4096,
            digest_for_key(key),
        );
        DeadObjectEntry::new(key, [object_byte; 16], death_txg, true, death_txg)
            .with_replacement_receipt(receipt)
    }

    fn digest_for_key(key: ObjectKey) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[0] = key.0[0];
        d
    }

    #[test]
    fn erasure_coded_replacement_receipt_authorizes_reclaim() {
        let key = oid(42);
        let receipt = DeadObjectReplacementReceipt::erasure_coded(
            key, 7, 1, 4, 2, 8192, digest_for_key(key),
        );
        assert!(!receipt.is_synthetic());
        assert!(receipt.authorizes_reclaim_for(key));
    }

    #[test]
    fn erasure_entry_passes_receipt_bound_dequeue() {
        let mut q = DeadObjectReclaimQueue::new();
        q.enqueue(erasure_entry(10, 5, 1, 4, 2));

        let batch = q.dequeue_receipt_bound_batch(10, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].object_id, oid(10));
    }

    #[test]
    fn stable_generation_gating_blocks_uncommitted_receipt() {
        let mut q = DeadObjectReclaimQueue::new();
        // Receipt generation 5, but stable committed generation is only 3
        q.enqueue(erasure_entry(20, 5, 5, 4, 2));

        // Receipt-bound batch (no generation check): should pass
        let batch = q.dequeue_receipt_bound_batch(10, 10);
        assert_eq!(batch.len(), 1);

        // Stable-generation batch: should block because gen 5 > stable 3
        let batch = q.dequeue_receipt_bound_batch_with_stable_generation(10, 10, 3);
        assert_eq!(batch.len(), 0);

        // Stable-generation batch at gen 5 or higher: should pass
        let batch = q.dequeue_receipt_bound_batch_with_stable_generation(10, 10, 5);
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn stable_generation_gating_rejects_zero_generation() {
        let mut q = DeadObjectReclaimQueue::new();
        let key = oid(30);
        let receipt = DeadObjectReplacementReceipt::replicated(
            key, 7, 0, 2, 4096, digest_for_key(key),
        );
        q.enqueue(
            DeadObjectEntry::new(key, [30; 16], 5, true, 5)
                .with_replacement_receipt(receipt),
        );

        // Synthetic receipt (gen 0): stable-generation batch rejects
        let batch = q.dequeue_receipt_bound_batch_with_stable_generation(10, 10, 5);
        assert_eq!(batch.len(), 0);

        // Even receipt-bound batch rejects synthetic
        let batch = q.dequeue_receipt_bound_batch(10, 10);
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn rebake_publishes_replacement_receipt() {
        let mut q = DeadObjectReclaimQueue::new();
        let key = oid(40);
        // Enqueue without replacement receipt (pre-rebake)
        q.enqueue(DeadObjectEntry::new(key, [40; 16], 5, true, 5));

        // Not yet reclaimable via receipt-bound path
        assert_eq!(q.receipt_bound_eligible_count(10), 0);

        // Rebake publishes replacement receipt
        let receipt = DeadObjectReplacementReceipt::replicated(
            key, 7, 1, 2, 4096, digest_for_key(key),
        );
        assert!(q.publish_replacement_receipt(&key, receipt));

        // Now reclaimable
        assert_eq!(q.receipt_bound_eligible_count(10), 1);
    }

    #[test]
    fn rebake_publish_rejects_lower_generation() {
        let mut q = DeadObjectReclaimQueue::new();
        let key = oid(50);
        let receipt_gen3 = DeadObjectReplacementReceipt::replicated(
            key, 7, 3, 2, 4096, digest_for_key(key),
        );
        q.enqueue(
            DeadObjectEntry::new(key, [50; 16], 5, true, 5)
                .with_replacement_receipt(receipt_gen3),
        );

        // Attempt to publish older generation: rejected
        let receipt_gen2 = DeadObjectReplacementReceipt::replicated(
            key, 7, 2, 2, 4096, digest_for_key(key),
        );
        assert!(!q.publish_replacement_receipt(&key, receipt_gen2));

        // Attempt to publish same generation: rejected
        let receipt_gen3b = DeadObjectReplacementReceipt::replicated(
            key, 7, 3, 2, 4096, digest_for_key(key),
        );
        assert!(!q.publish_replacement_receipt(&key, receipt_gen3b));

        // Publish higher generation: accepted
        let receipt_gen4 = DeadObjectReplacementReceipt::replicated(
            key, 7, 4, 2, 4096, digest_for_key(key),
        );
        assert!(q.publish_replacement_receipt(&key, receipt_gen4));
    }

    #[test]
    fn reclaim_does_not_race_receipt_publication() {
        let mut q = DeadObjectReclaimQueue::new();
        let key = oid(60);
        // Dead object enqueued, receipt published at gen 8
        let receipt = DeadObjectReplacementReceipt::erasure_coded(
            key, 7, 8, 4, 2, 8192, digest_for_key(key),
        );
        q.enqueue(
            DeadObjectEntry::new(key, [60; 16], 5, true, 5)
                .with_replacement_receipt(receipt),
        );

        // stable_committed_generation = 7 (behind the receipt gen 8)
        // Reclaim must NOT proceed because receipt generation is not yet stable
        let batch = q.dequeue_receipt_bound_batch_with_stable_generation(10, 10, 7);
        assert_eq!(batch.len(), 0, "reclaim must not race uncommitted receipt");

        // Once stable generation catches up to 8, reclaim proceeds
        let batch = q.dequeue_receipt_bound_batch_with_stable_generation(10, 10, 8);
        assert_eq!(batch.len(), 1);

        // After ack, entry is removed
        let removed = q.ack_reclaimed(&[key]);
        assert_eq!(removed, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn mixed_replicated_and_erasure_entries() {
        let mut q = DeadObjectReclaimQueue::new();
        let k1 = oid(70);
        let k2 = oid(71);

        let r1 = DeadObjectReplacementReceipt::replicated(
            k1, 7, 1, 3, 4096, digest_for_key(k1),
        );
        let r2 = DeadObjectReplacementReceipt::erasure_coded(
            k2, 7, 2, 8, 3, 16384, digest_for_key(k2),
        );

        q.enqueue(DeadObjectEntry::new(k1, [70; 16], 5, true, 5).with_replacement_receipt(r1));
        q.enqueue(DeadObjectEntry::new(k2, [71; 16], 5, true, 5).with_replacement_receipt(r2));

        assert_eq!(q.receipt_bound_eligible_count(10), 2);
        assert_eq!(q.receipt_bound_eligible_count_with_stable_generation(10, 5), 2);

        let batch = q.dequeue_receipt_bound_batch_with_stable_generation(10, 10, 5);
        assert_eq!(batch.len(), 2);
    }

}
