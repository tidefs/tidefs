// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Shard group lifecycle: ingest durability ladder.
//!
//! New writes land as ingest extents and climb a 5-state durability ladder:
//! `Ingest` → `Replicating` → `Replicated` → `Rebaking` → `Base`.
//!
//! Each extent tracks its current [`ReplicaLifecycle`] state, a wall-clock
//! deadline for each transition, and the system emits [`DurabilityWarning`]
//! when an extent is stuck too long in a vulnerable state.

use std::time::Duration;

// ── Timeout constants ──────────────────────────────────────────────────

/// If an extent stays in `Ingest` longer than this, escalate to `Warning`.
pub const INGEST_WARNING_TIMEOUT: Duration = Duration::from_secs(30);

/// If an extent stays in `Ingest` longer than this, escalate to `Critical`.
pub const INGEST_CRITICAL_TIMEOUT: Duration = Duration::from_secs(300);

/// If an extent stays in `Replicating` longer than this, escalate.
pub const REPLICATING_TIMEOUT: Duration = Duration::from_secs(120);

/// If an extent stays in `Rebaking` longer than this, escalate.
pub const REBAKING_TIMEOUT: Duration = Duration::from_secs(600);

// ── ReplicaLifecycle ───────────────────────────────────────────────────

/// 5-state durability ladder for an ingest extent within a shard group.
///
/// ```text
/// Ingest ──► Replicating ──► Replicated ──► Rebaking ──► Base
/// ```
///
/// `Ingest` is the entry point (write just landed, no redundancy).
/// `Base` is the terminal durable state (fully rebaked into a ShardGroupV1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReplicaLifecycle {
    /// Write just landed; not yet replicated. Single copy, no redundancy.
    Ingest,
    /// Replication in progress to target nodes.
    Replicating,
    /// N copies exist; durability satisfied through replication.
    Replicated,
    /// Converting ingest extents into erasure-coded shard groups.
    Rebaking,
    /// Fully rebaked into a `ShardGroupV1`; durable.
    Base,
}

impl ReplicaLifecycle {
    /// Returns `true` when the lifecycle has reached the terminal durable state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, ReplicaLifecycle::Base)
    }

    /// Returns `true` when the extent is durable (at least replicated).
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        matches!(
            self,
            ReplicaLifecycle::Replicated | ReplicaLifecycle::Rebaking | ReplicaLifecycle::Base
        )
    }

    /// Returns `true` when the extent is in a vulnerable state (no redundancy).
    #[must_use]
    pub const fn is_vulnerable(&self) -> bool {
        matches!(
            self,
            ReplicaLifecycle::Ingest | ReplicaLifecycle::Replicating
        )
    }

    /// Advance the lifecycle to `target`. Returns `Ok(new_state)` on valid
    /// forward progress. Returns `Err` with the current state when the
    /// transition is not allowed.
    pub fn advance(self, target: ReplicaLifecycle) -> Result<ReplicaLifecycle, ReplicaLifecycle> {
        match (self, target) {
            // Idempotent: same state is always valid.
            _ if self == target => Ok(self),

            // Forward transitions (the durability ladder).
            (ReplicaLifecycle::Ingest, ReplicaLifecycle::Replicating) => Ok(target),
            (ReplicaLifecycle::Replicating, ReplicaLifecycle::Replicated) => Ok(target),
            (ReplicaLifecycle::Replicated, ReplicaLifecycle::Rebaking) => Ok(target),
            (ReplicaLifecycle::Rebaking, ReplicaLifecycle::Base) => Ok(target),

            // Any other transition is invalid.
            _ => Err(self),
        }
    }

    /// Try to advance, returning the resulting state (same on invalid).
    #[must_use]
    pub fn try_advance(self, target: ReplicaLifecycle) -> ReplicaLifecycle {
        self.advance(target).unwrap_or(self)
    }

    /// Ordered sequence of states for iteration.
    #[must_use]
    pub const fn all_states() -> [ReplicaLifecycle; 5] {
        [
            ReplicaLifecycle::Ingest,
            ReplicaLifecycle::Replicating,
            ReplicaLifecycle::Replicated,
            ReplicaLifecycle::Rebaking,
            ReplicaLifecycle::Base,
        ]
    }

    /// Ordinal for ordering/comparison.
    #[must_use]
    pub const fn ordinal(&self) -> u8 {
        match self {
            ReplicaLifecycle::Ingest => 0,
            ReplicaLifecycle::Replicating => 1,
            ReplicaLifecycle::Replicated => 2,
            ReplicaLifecycle::Rebaking => 3,
            ReplicaLifecycle::Base => 4,
        }
    }

    /// Returns `true` if `self` < `other` in durability ladder order.
    #[must_use]
    pub const fn precedes(&self, other: ReplicaLifecycle) -> bool {
        self.ordinal() < other.ordinal()
    }
}

impl core::fmt::Display for ReplicaLifecycle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            ReplicaLifecycle::Ingest => "ingest",
            ReplicaLifecycle::Replicating => "replicating",
            ReplicaLifecycle::Replicated => "replicated",
            ReplicaLifecycle::Rebaking => "rebaking",
            ReplicaLifecycle::Base => "base",
        };
        write!(f, "{s}")
    }
}

// ── DurabilityWarning ──────────────────────────────────────────────────

/// Escalation level emitted when an extent is stuck in a non-durable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DurabilityWarning {
    /// No issue; extent is progressing normally.
    Ok,
    /// Extent stuck in Ingest or Replicating beyond the warning threshold.
    Warning,
    /// Extent stuck in Ingest beyond the critical threshold (data at risk).
    Critical,
}

impl DurabilityWarning {
    /// Evaluate the warning level for an extent given its current state and
    /// the time it has spent in that state.
    #[must_use]
    pub fn evaluate(state: ReplicaLifecycle, elapsed_in_state: Duration) -> Self {
        match state {
            ReplicaLifecycle::Ingest => {
                if elapsed_in_state >= INGEST_CRITICAL_TIMEOUT {
                    DurabilityWarning::Critical
                } else if elapsed_in_state >= INGEST_WARNING_TIMEOUT {
                    DurabilityWarning::Warning
                } else {
                    DurabilityWarning::Ok
                }
            }
            ReplicaLifecycle::Replicating => {
                if elapsed_in_state >= REPLICATING_TIMEOUT {
                    DurabilityWarning::Warning
                } else {
                    DurabilityWarning::Ok
                }
            }
            // Replicated, Rebaking, Base are durable enough.
            ReplicaLifecycle::Replicated | ReplicaLifecycle::Rebaking | ReplicaLifecycle::Base => {
                DurabilityWarning::Ok
            }
        }
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, DurabilityWarning::Ok)
    }

    #[must_use]
    pub const fn needs_escalation(&self) -> bool {
        matches!(
            self,
            DurabilityWarning::Warning | DurabilityWarning::Critical
        )
    }
}

impl core::fmt::Display for DurabilityWarning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            DurabilityWarning::Ok => "ok",
            DurabilityWarning::Warning => "warning",
            DurabilityWarning::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

// ── DurabilityLadder ───────────────────────────────────────────────────

/// Per-extent durability ladder tracking with wall-clock deadlines.
///
/// Each entry records the current [`ReplicaLifecycle`] state and the
/// instant at which it entered that state, enabling timeout-based
/// escalation via [`DurabilityWarning::evaluate`].
#[derive(Clone, Debug)]
pub struct DurabilityLadder {
    state: ReplicaLifecycle,
    /// Timestamp (seconds since an arbitrary epoch) when the current
    /// state was entered. Callers provide their own clock.
    entered_at_secs: u64,
}

impl DurabilityLadder {
    /// Create a new ladder entry at `Ingest`.
    #[must_use]
    pub fn new(now_secs: u64) -> Self {
        Self {
            state: ReplicaLifecycle::Ingest,
            entered_at_secs: now_secs,
        }
    }

    /// Create a ladder entry with an explicit initial state.
    #[must_use]
    pub fn with_state(state: ReplicaLifecycle, now_secs: u64) -> Self {
        Self {
            state,
            entered_at_secs: now_secs,
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ReplicaLifecycle {
        self.state
    }

    /// Timestamp when the current state was entered.
    #[must_use]
    pub const fn entered_at_secs(&self) -> u64 {
        self.entered_at_secs
    }

    /// Elapsed time in the current state.
    #[must_use]
    pub fn elapsed(&self, now_secs: u64) -> Duration {
        let delta = now_secs.saturating_sub(self.entered_at_secs);
        Duration::from_secs(delta)
    }

    /// Attempt to advance to `target`. On success, resets the entry clock.
    /// Returns the new state (same on invalid transition).
    #[must_use]
    pub fn try_advance(&mut self, target: ReplicaLifecycle, now_secs: u64) -> ReplicaLifecycle {
        match self.state.advance(target) {
            Ok(new_state) => {
                self.state = new_state;
                self.entered_at_secs = now_secs;
                new_state
            }
            Err(current) => current,
        }
    }

    /// Evaluate the current durability warning level.
    #[must_use]
    pub fn warning(&self, now_secs: u64) -> DurabilityWarning {
        DurabilityWarning::evaluate(self.state, self.elapsed(now_secs))
    }

    /// Returns `true` if the extent has reached the terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Returns `true` if the extent is durable (at least replicated).
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        self.state.is_durable()
    }

    /// Returns `true` if the extent is in a vulnerable state.
    #[must_use]
    pub const fn is_vulnerable(&self) -> bool {
        self.state.is_vulnerable()
    }
}

// ── Multi-extent tracking ──────────────────────────────────────────────

/// Summary statistics across a collection of durability ladders.
#[derive(Clone, Debug, Default)]
pub struct DurabilitySummary {
    pub ingest_count: usize,
    pub replicating_count: usize,
    pub replicated_count: usize,
    pub rebaking_count: usize,
    pub base_count: usize,
    pub total: usize,
}

impl DurabilitySummary {
    /// Aggregate counts from a slice of [`DurabilityLadder`] entries.
    #[must_use]
    pub fn from_ladders(ladders: &[DurabilityLadder]) -> Self {
        let mut s = Self::default();
        for ladder in ladders {
            s.total += 1;
            match ladder.state() {
                ReplicaLifecycle::Ingest => s.ingest_count += 1,
                ReplicaLifecycle::Replicating => s.replicating_count += 1,
                ReplicaLifecycle::Replicated => s.replicated_count += 1,
                ReplicaLifecycle::Rebaking => s.rebaking_count += 1,
                ReplicaLifecycle::Base => s.base_count += 1,
            }
        }
        s
    }

    /// Count of extents that are still vulnerable (Ingest + Replicating).
    #[must_use]
    pub const fn vulnerable_count(&self) -> usize {
        self.ingest_count + self.replicating_count
    }

    /// Count of extents that are fully durable (Replicated + Rebaking + Base).
    #[must_use]
    pub const fn durable_count(&self) -> usize {
        self.replicated_count + self.rebaking_count + self.base_count
    }

    /// Fraction of extents that are durable (0.0–1.0).
    #[must_use]
    pub fn durable_fraction(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.durable_count() as f64 / self.total as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ShardGroupV1 — on-media format for erasure-coded shard groups
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use tidefs_erasure_coding::{encode, reconstruct, ErasureShard, ShardKind, StripeConfig};
use tidefs_incremental_job_core::IncrementalJob;
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

/// On-media record for a k+m erasure-coded shard group.
///
/// Byte layout (little-endian, all multi-byte fields LE):
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 16   | shard_group_id: UUID |
/// | 16     | 1    | k: data shard count (1..255) |
/// | 17     | 1    | m: parity shard count (1..255) |
/// | 18     | 1    | shard_count: k + m |
/// | 19     | 1    | flags |
/// | 20     | 32   | original_digest: BLAKE3-256 over original payload |
/// | 52     | 4    | original_len: u32 LE, original payload length in bytes |
/// | 56     | 28   | reserved (zero-filled) |
/// | 84     | var  | per-shard descriptors: shard_count × 80 bytes |
/// | …      | 32   | self_checksum: BLAKE3-256 over bytes 0..(len-32) |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardGroupV1 {
    /// UUID uniquely identifying this shard group.
    pub shard_group_id: [u8; 16],
    /// Data shard count.
    pub k: u8,
    /// Parity shard count.
    pub m: u8,
    /// Total shard count (k + m).
    pub shard_count: u8,
    /// Flags (reserved for future use).
    pub flags: u8,
    /// BLAKE3-256 digest over the original (pre-encoding) payload.
    pub original_digest: [u8; 32],
    /// Original payload length in bytes.
    pub original_len: u32,
    /// Per-shard placement descriptors.
    pub shards: Vec<ShardDescriptor>,
    /// BLAKE3-256 self-checksum over the serialized header + descriptors.
    pub self_checksum: [u8; 32],
}

/// Per-shard descriptor in a `ShardGroupV1`.
///
/// Byte layout (80 bytes, little-endian):
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 8    | node_id: u64 LE |
/// | 8      | 32   | extent_key: BLAKE3-256 of shard data |
/// | 40     | 2    | shard_index: u16 LE |
/// | 42     | 6    | reserved (zero-filled) |
/// | 48     | 32   | shard_checksum: BLAKE3-256 over shard bytes |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardDescriptor {
    /// Node that hosts this shard.
    pub node_id: u64,
    /// BLAKE3-256 hash serving as the extent key for this shard.
    pub extent_key: [u8; 32],
    /// Index: 0..(k-1) for data, k..(k+m-1) for parity.
    pub shard_index: u16,
    /// BLAKE3-256 checksum over the shard payload bytes.
    pub shard_checksum: [u8; 32],
}

// ---- constants ----

impl ShardGroupV1 {
    /// Fixed header size (bytes 0..83, before shard descriptors).
    pub const HEADER_SIZE: usize = 84;
    /// Size of each per-shard descriptor on disk.
    pub const SHARD_DESC_SIZE: usize = 80;
    /// Size of the trailing self-checksum.
    pub const CHECKSUM_SIZE: usize = 32;

    /// Total encoded size in bytes.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        ShardGroupV1::HEADER_SIZE
            + (self.shard_count as usize) * ShardGroupV1::SHARD_DESC_SIZE
            + ShardGroupV1::CHECKSUM_SIZE
    }

    /// Returns true if this is a valid erasure-coded group (k >= 1, m >= 1).
    #[must_use]
    pub const fn is_erasure_coded(&self) -> bool {
        self.k >= 1 && self.m >= 1
    }

    /// Validate structural constraints.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.k == 0 {
            return Err("k must be >= 1");
        }
        if self.m == 0 {
            return Err("m must be >= 1");
        }
        let sum = self.k as u16 + self.m as u16;
        if sum > 255 {
            return Err("k + m must be <= 255");
        }
        if self.shard_count != self.k + self.m {
            return Err("shard_count must equal k + m");
        }
        if self.shards.len() != self.shard_count as usize {
            return Err("shards.len() must equal shard_count");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Encode / Decode (binary serialization)
// ---------------------------------------------------------------------------

/// Serialise a `ShardGroupV1` to bytes.
///
/// Returns `None` if validation fails.
pub fn encode_shard_group(sg: &ShardGroupV1) -> Option<Vec<u8>> {
    sg.validate().ok()?;
    let size = sg.encoded_size();
    let mut buf = vec![0u8; size];

    // Header (84 bytes)
    buf[0..16].copy_from_slice(&sg.shard_group_id);
    buf[16] = sg.k;
    buf[17] = sg.m;
    buf[18] = sg.shard_count;
    buf[19] = sg.flags;
    buf[20..52].copy_from_slice(&sg.original_digest);
    buf[52..56].copy_from_slice(&sg.original_len.to_le_bytes());
    // bytes 56..84 are reserved (already zero)

    // Shard descriptors
    for (i, sd) in sg.shards.iter().enumerate() {
        let off = ShardGroupV1::HEADER_SIZE + i * ShardGroupV1::SHARD_DESC_SIZE;
        buf[off..off + 8].copy_from_slice(&sd.node_id.to_le_bytes());
        buf[off + 8..off + 40].copy_from_slice(&sd.extent_key);
        buf[off + 40..off + 42].copy_from_slice(&sd.shard_index.to_le_bytes());
        // bytes 42..48 are reserved (already zero)
        buf[off + 48..off + 80].copy_from_slice(&sd.shard_checksum);
    }

    // Self-checksum: BLAKE3 over everything before the checksum field
    let csum_off = size - ShardGroupV1::CHECKSUM_SIZE;
    let checksum = blake3::hash(&buf[..csum_off]);
    buf[csum_off..].copy_from_slice(checksum.as_bytes());

    Some(buf)
}

/// Deserialise bytes into a `ShardGroupV1`.
///
/// Returns `None` if the buffer is too short, shard_count is inconsistent,
/// or the self-checksum fails.
pub fn decode_shard_group(bytes: &[u8]) -> Option<ShardGroupV1> {
    if bytes.len() < ShardGroupV1::HEADER_SIZE + ShardGroupV1::CHECKSUM_SIZE {
        return None;
    }

    let shard_group_id: [u8; 16] = bytes[0..16].try_into().ok()?;
    let k = bytes[16];
    let m = bytes[17];
    let shard_count = bytes[18];
    let flags = bytes[19];
    let original_digest: [u8; 32] = bytes[20..52].try_into().ok()?;
    let original_len = u32::from_le_bytes(bytes[52..56].try_into().ok()?);

    if shard_count != k + m {
        return None;
    }

    let expected_size = ShardGroupV1::HEADER_SIZE
        + (shard_count as usize) * ShardGroupV1::SHARD_DESC_SIZE
        + ShardGroupV1::CHECKSUM_SIZE;
    if bytes.len() < expected_size {
        return None;
    }

    // Verify self-checksum
    let csum_off = expected_size - ShardGroupV1::CHECKSUM_SIZE;
    let stored_checksum: [u8; 32] = bytes[csum_off..csum_off + 32].try_into().ok()?;
    let computed = blake3::hash(&bytes[..csum_off]);
    if stored_checksum != *computed.as_bytes() {
        return None;
    }

    // Decode shard descriptors
    let mut shards = Vec::with_capacity(shard_count as usize);
    for i in 0..shard_count as usize {
        let off = ShardGroupV1::HEADER_SIZE + i * ShardGroupV1::SHARD_DESC_SIZE;
        if off + ShardGroupV1::SHARD_DESC_SIZE > bytes.len() {
            return None;
        }
        let node_id = u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?);
        let extent_key: [u8; 32] = bytes[off + 8..off + 40].try_into().ok()?;
        let shard_index = u16::from_le_bytes(bytes[off + 40..off + 42].try_into().ok()?);
        let shard_checksum: [u8; 32] = bytes[off + 48..off + 80].try_into().ok()?;
        shards.push(ShardDescriptor {
            node_id,
            extent_key,
            shard_index,
            shard_checksum,
        });
    }

    let sg = ShardGroupV1 {
        shard_group_id,
        k,
        m,
        shard_count,
        flags,
        original_digest,
        original_len,
        shards,
        self_checksum: stored_checksum,
    };

    sg.validate().ok()?;
    Some(sg)
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Generate a random shard group id (UUIDv4-like).
fn new_shard_group_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = ((i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15u64)
            .wrapping_mul(0x9E37)
            >> 32) as u8;
    }
    id
}

/// Compute per-shard BLAKE3 checksums for data and parity shards.
fn checksum_shards(shards: &[Vec<u8>]) -> Vec<[u8; 32]> {
    shards
        .iter()
        .map(|s| {
            let h = blake3::hash(s);
            let mut csum = [0u8; 32];
            csum.copy_from_slice(h.as_bytes());
            csum
        })
        .collect()
}

// ---------------------------------------------------------------------------
// ShardGroupEncoder
// ---------------------------------------------------------------------------

/// Encodes raw payload into a `ShardGroupV1` using erasure coding.
///
/// Given `data`, `k` data shards, and `m` parity shards, the encoder:
/// 1. Splits data into k equal-sized shards (zero-pads the last if needed)
/// 2. Computes m parity shards via Reed-Solomon
/// 3. Computes BLAKE3 checksums for each shard
/// 4. Builds and returns the `ShardGroupV1` record
pub struct ShardGroupEncoder;

impl ShardGroupEncoder {
    /// Encode `data` into a k+m shard group.
    ///
    /// Returns `None` if k == 0, m == 0, k+m > 255, or m > 3 (current
    /// tidefs-erasure-coding limit).
    pub fn encode(data: &[u8], k: u8, m: u8) -> Option<(ShardGroupV1, Vec<Vec<u8>>)> {
        if k == 0 || m == 0 || (k as u16 + m as u16) > 255 {
            return None;
        }
        let k_usize = k as usize;

        // Determine shard_len: each data shard gets ceil(len / k) bytes
        let shard_len = if data.is_empty() {
            1 // minimum shard size for empty payload
        } else {
            data.len().div_ceil(k_usize)
        };

        let config = StripeConfig {
            data_shards: k_usize,
            parity_shards: m as usize,
            shard_len,
        };

        let encoded = encode(&config, data)?;

        // Collect data shards + parity shards
        let m_usize = m as usize;
        let mut all_shards: Vec<Vec<u8>> = Vec::with_capacity(k_usize + m_usize);
        for shard in &encoded.shards {
            all_shards.push(shard.bytes.clone());
        }

        // Per-shard checksums
        let checksums = checksum_shards(&all_shards);

        // Original digest
        let original_digest_hash = blake3::hash(data);
        let mut original_digest = [0u8; 32];
        original_digest.copy_from_slice(original_digest_hash.as_bytes());

        let shard_group_id = new_shard_group_id();
        let shard_count = k + m;

        // Build shard descriptors
        let mut shards = Vec::with_capacity(shard_count as usize);
        for (i, csum) in checksums.iter().enumerate() {
            shards.push(ShardDescriptor {
                node_id: 0, // caller fills in after placement
                extent_key: *csum,
                shard_index: i as u16,
                shard_checksum: *csum,
            });
        }

        let sg = ShardGroupV1 {
            shard_group_id,
            k,
            m,
            shard_count,
            flags: 0,
            original_digest,
            original_len: data.len() as u32,
            shards,
            self_checksum: [0u8; 32], // filled in by encode_shard_group
        };

        // Encode to bytes and back to get self-checksum populated
        let encoded_bytes = encode_shard_group(&sg)?;
        let sg_with_csum = decode_shard_group(&encoded_bytes)?;

        Some((sg_with_csum, all_shards))
    }

    /// Encode and return only the `ShardGroupV1` record (shard data
    /// is assumed to be written separately by the caller).
    pub fn encode_record(data: &[u8], k: u8, m: u8) -> Option<ShardGroupV1> {
        Self::encode(data, k, m).map(|(sg, _)| sg)
    }
}

// ---------------------------------------------------------------------------
// ShardGroupDecoder
// ---------------------------------------------------------------------------

/// Decodes a `ShardGroupV1` back to the original payload.
///
/// The decoder requires at least k shards (identified by `shard_index`)
/// to be provided.  It verifies per-shard BLAKE3 checksums before
/// reconstruction.
pub struct ShardGroupDecoder;

/// Error cases for shard group decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The ShardGroupV1 self-checksum is invalid.
    InvalidChecksum,
    /// A per-shard BLAKE3 checksum mismatch.
    ShardChecksumMismatch { shard_index: u16 },
    /// Not enough shards provided (need at least k).
    InsufficientShards { have: usize, need: usize },
    /// Reconstruction failed (e.g. linear dependence, internal error).
    ReconstructionFailed,
    /// ShardGroupV1 structural validation failed.
    ValidationFailed(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChecksum => write!(f, "ShardGroupV1 self-checksum invalid"),
            Self::ShardChecksumMismatch { shard_index } => {
                write!(f, "per-shard checksum mismatch at shard {shard_index}")
            }
            Self::InsufficientShards { have, need } => {
                write!(f, "insufficient shards: have {have}, need at least {need}")
            }
            Self::ReconstructionFailed => write!(f, "reconstruction failed"),
            Self::ValidationFailed(e) => write!(f, "validation failed: {e}"),
        }
    }
}

impl ShardGroupDecoder {
    /// Decode a `ShardGroupV1` back to the original payload.
    ///
    /// `shard_data` maps shard_index to shard bytes. At least `k` shards
    /// must be present and their BLAKE3 checksums must match the
    /// descriptors in the `ShardGroupV1`.
    ///
    /// The `ShardGroupV1` self-checksum is NOT verified here (it is
    /// verified during `decode_shard_group`).  If you constructed the
    /// `ShardGroupV1` manually, call `verify_self_checksum` first.
    pub fn decode(
        sg: &ShardGroupV1,
        shard_data: &std::collections::BTreeMap<u16, Vec<u8>>,
    ) -> Result<Vec<u8>, DecodeError> {
        sg.validate().map_err(DecodeError::ValidationFailed)?;

        let k_usize = sg.k as usize;
        let m_usize = sg.m as usize;
        let stripe_width = k_usize + m_usize;

        if shard_data.len() < k_usize {
            return Err(DecodeError::InsufficientShards {
                have: shard_data.len(),
                need: k_usize,
            });
        }

        // Verify per-shard checksums
        for sd in &sg.shards {
            if let Some(data) = shard_data.get(&sd.shard_index) {
                let hash = blake3::hash(data);
                if *hash.as_bytes() != sd.shard_checksum {
                    return Err(DecodeError::ShardChecksumMismatch {
                        shard_index: sd.shard_index,
                    });
                }
            }
        }

        // Determine shard_len from the first available data shard
        let shard_len = shard_data.values().next().map(|v| v.len()).unwrap_or(1);

        let config = StripeConfig {
            data_shards: k_usize,
            parity_shards: m_usize,
            shard_len,
        };

        // Build available shards array
        let mut available: Vec<Option<ErasureShard>> = vec![None; stripe_width];
        for (&idx, data) in shard_data {
            if (idx as usize) < stripe_width {
                let kind = if (idx as usize) < k_usize {
                    ShardKind::Data
                } else {
                    ShardKind::Parity
                };
                available[idx as usize] = Some(ErasureShard {
                    index: idx as usize,
                    kind,
                    bytes: data.clone(),
                });
            }
        }

        let reconstruction =
            reconstruct(&config, &available, None).ok_or(DecodeError::ReconstructionFailed)?;

        Ok(reconstruction.payload[..sg.original_len as usize].to_vec())
    }

    /// Verify the self-checksum of a `ShardGroupV1` by re-encoding and
    /// comparing the stored checksum against the computed one.
    pub fn verify_self_checksum(sg: &ShardGroupV1) -> Result<(), DecodeError> {
        let size = ShardGroupV1::HEADER_SIZE
            + (sg.shard_count as usize) * ShardGroupV1::SHARD_DESC_SIZE
            + ShardGroupV1::CHECKSUM_SIZE;
        let mut buf = vec![0u8; size];

        buf[0..16].copy_from_slice(&sg.shard_group_id);
        buf[16] = sg.k;
        buf[17] = sg.m;
        buf[18] = sg.shard_count;
        buf[19] = sg.flags;
        buf[20..52].copy_from_slice(&sg.original_digest);
        buf[52..56].copy_from_slice(&sg.original_len.to_le_bytes());

        for (i, sd) in sg.shards.iter().enumerate() {
            let off = ShardGroupV1::HEADER_SIZE + i * ShardGroupV1::SHARD_DESC_SIZE;
            buf[off..off + 8].copy_from_slice(&sd.node_id.to_le_bytes());
            buf[off + 8..off + 40].copy_from_slice(&sd.extent_key);
            buf[off + 40..off + 42].copy_from_slice(&sd.shard_index.to_le_bytes());
            buf[off + 48..off + 80].copy_from_slice(&sd.shard_checksum);
        }

        let csum_off = size - ShardGroupV1::CHECKSUM_SIZE;
        let computed = blake3::hash(&buf[..csum_off]);
        if *computed.as_bytes() != sg.self_checksum {
            return Err(DecodeError::InvalidChecksum);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Utility: verify per-shard checksums
// ---------------------------------------------------------------------------

/// Verify all per-shard BLAKE3 checksums in a `ShardGroupV1` against
/// the provided shard data.
///
/// Returns `Ok(())` if all shards in `shard_data` match their
/// descriptors.  Missing shards (not in the map) are skipped.
pub fn verify_shard_checksums(
    sg: &ShardGroupV1,
    shard_data: &std::collections::BTreeMap<u16, Vec<u8>>,
) -> Result<(), DecodeError> {
    for sd in &sg.shards {
        if let Some(data) = shard_data.get(&sd.shard_index) {
            let hash = blake3::hash(data);
            if *hash.as_bytes() != sd.shard_checksum {
                return Err(DecodeError::ShardChecksumMismatch {
                    shard_index: sd.shard_index,
                });
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// RebakeService -- budgeted ingest-to-base conversion
// ═══════════════════════════════════════════════════════════════════════

/// Per-dataset durability policy used by [`RebakeService`].
///
/// `None` leaves replicated ingest extents alone. `Replicated` writes full
/// copies without erasure coding. `ErasureCoded` encodes data through
/// [`ShardGroupEncoder`] and commits a `ShardGroupV1` target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RedundancyPolicy {
    /// No rebake work for this dataset.
    None,
    /// Write `copies` full replicas.
    Replicated { copies: u8 },
    /// Encode `data_shards + parity_shards` erasure-coded shards.
    ErasureCoded { data_shards: u8, parity_shards: u8 },
}

impl RedundancyPolicy {
    /// Default production policy until per-dataset policy wiring overrides it.
    pub const DEFAULT_REPLICATED_COPIES: u8 = 3;

    /// Number of physical shards or copies produced by this policy.
    #[must_use]
    pub const fn shard_count(self) -> u8 {
        match self {
            RedundancyPolicy::None => 1,
            RedundancyPolicy::Replicated { copies } => copies,
            RedundancyPolicy::ErasureCoded {
                data_shards,
                parity_shards,
            } => data_shards.saturating_add(parity_shards),
        }
    }

    /// Returns true when `step()` should do rebake work.
    #[must_use]
    pub const fn is_active(self) -> bool {
        !matches!(self, RedundancyPolicy::None)
    }

    /// Returns true when this policy produces `ShardGroupV1` metadata.
    #[must_use]
    pub const fn is_erasure_coded(self) -> bool {
        matches!(self, RedundancyPolicy::ErasureCoded { .. })
    }

    /// Human-readable policy label for logs and admin views.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            RedundancyPolicy::None => "none",
            RedundancyPolicy::Replicated { .. } => "replicated",
            RedundancyPolicy::ErasureCoded { .. } => "erasure_coded",
        }
    }

    /// Validate user-visible policy shape before using it for writes.
    pub fn validate(self) -> Result<(), &'static str> {
        match self {
            RedundancyPolicy::None => Ok(()),
            RedundancyPolicy::Replicated { copies } => {
                if copies == 0 {
                    Err("replicated policy requires at least one copy")
                } else {
                    Ok(())
                }
            }
            RedundancyPolicy::ErasureCoded {
                data_shards,
                parity_shards,
            } => {
                if data_shards == 0 {
                    return Err("erasure-coded policy requires data_shards > 0");
                }
                if parity_shards == 0 {
                    return Err("erasure-coded policy requires parity_shards > 0");
                }
                if data_shards as u16 + parity_shards as u16 > 255 {
                    return Err("erasure-coded policy requires data_shards + parity_shards <= 255");
                }
                Ok(())
            }
        }
    }
}

impl Default for RedundancyPolicy {
    fn default() -> Self {
        RedundancyPolicy::Replicated {
            copies: Self::DEFAULT_REPLICATED_COPIES,
        }
    }
}

/// Cumulative counters for one rebake job.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RebakeStats {
    /// Candidate extents examined by the job.
    pub extents_scanned: u64,
    /// Candidate extents atomically committed to a rebaked target.
    pub extents_rebaked: u64,
    /// Logical bytes successfully rebaked.
    pub bytes_rebaked: u64,
    /// Latest scanner snapshot of ingest bytes still awaiting rebake.
    pub ingest_bytes_remaining: u64,
}

impl RebakeStats {
    /// Zero-valued stats.
    pub const ZERO: Self = Self {
        extents_scanned: 0,
        extents_rebaked: 0,
        bytes_rebaked: 0,
        ingest_bytes_remaining: 0,
    };

    /// Add counters from another sample. Remaining bytes are a snapshot, so
    /// the newest value wins rather than accumulating.
    pub fn accumulate(&mut self, other: Self) {
        self.extents_scanned = self.extents_scanned.saturating_add(other.extents_scanned);
        self.extents_rebaked = self.extents_rebaked.saturating_add(other.extents_rebaked);
        self.bytes_rebaked = self.bytes_rebaked.saturating_add(other.bytes_rebaked);
        self.ingest_bytes_remaining = other.ingest_bytes_remaining;
    }
}

/// Stable cursor persisted in the incremental-job checkpoint.
///
/// The service commits one extent at a time. The cursor advances only after
/// [`ExtentCommitter::commit_rebake`] succeeds, so crash replay sees either
/// the original ingest extent or the fully committed rebaked target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RebakeCursor {
    candidate_index: u64,
}

impl RebakeCursor {
    const FRESH: Self = Self { candidate_index: 0 };

    fn encode(self) -> Vec<u8> {
        self.candidate_index.to_le_bytes().to_vec()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let raw: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
        Some(Self {
            candidate_index: u64::from_le_bytes(raw),
        })
    }

    fn advance(&mut self) {
        self.candidate_index = self.candidate_index.saturating_add(1);
    }
}

/// Candidate extent returned by the scanner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestExtent {
    /// Unique key for the ingest extent.
    pub extent_key: u64,
    /// Dataset that owns this extent.
    pub dataset_id: u64,
    /// Logical data length.
    pub data_size: u64,
    /// Current lifecycle state.
    pub lifecycle: ReplicaLifecycle,
}

/// Concrete payload prepared by `RebakeService` before the writer persists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebakeOutput {
    /// Full-copy rebake output.
    Replicated { copies: Vec<Vec<u8>> },
    /// Erasure-coded output with its durable `ShardGroupV1` record.
    ErasureCoded {
        shard_group: ShardGroupV1,
        shards: Vec<Vec<u8>>,
    },
}

impl RebakeOutput {
    /// Number of physical copies or shards carried by the output.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        match self {
            RebakeOutput::Replicated { copies } => copies.len(),
            RebakeOutput::ErasureCoded { shards, .. } => shards.len(),
        }
    }
}

/// Target committed into the extent map after writer persistence succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebakeTarget {
    /// Full-copy target generated by a replicated policy.
    Replicated { replica_group_id: u64, copies: u8 },
    /// Erasure-coded target generated by a `ShardGroupV1` policy.
    ShardGroupV1 {
        shard_group_id: [u8; 16],
        data_shards: u8,
        parity_shards: u8,
    },
}

/// Scans for ingest extents that are ready to rebake.
pub trait ExtentScan: Send {
    /// Return a stable, deterministic candidate list. Candidates should be in
    /// `ReplicaLifecycle::Replicated`; the service filters defensively.
    fn list_rebake_candidates(&self) -> Result<Vec<IngestExtent>, String>;

    /// Return current ingest bytes waiting for rebake.
    fn ingest_bytes_total(&self) -> Result<u64, String>;
}

/// Reads raw ingest extent data.
pub trait ExtentReader: Send {
    /// Return the full logical data for `extent_key`.
    fn read_extent_data(&self, extent_key: u64) -> Result<Vec<u8>, String>;
}

/// Persists prepared rebake output to the chosen placement backend.
pub trait ShardWriter: Send {
    /// Write the prepared output and return the target that can be committed
    /// into the extent map.
    fn write_rebake_output(
        &mut self,
        extent: &IngestExtent,
        output: &RebakeOutput,
    ) -> Result<RebakeTarget, String>;
}

/// Atomically swaps the ingest extent for the writer's committed target.
pub trait ExtentCommitter: Send {
    /// Commit the rebake in one TXG/extent-map operation.
    fn commit_rebake(&mut self, old_extent_key: u64, target: RebakeTarget) -> Result<(), String>;
}

/// Budgeted incremental job that converts replicated ingest extents into base
/// replicated or erasure-coded shard targets.
pub struct RebakeService {
    job_id: JobId,
    policy: RedundancyPolicy,
    cursor: RebakeCursor,
    stats: RebakeStats,
    scanner: Box<dyn ExtentScan>,
    reader: Box<dyn ExtentReader>,
    writer: Box<dyn ShardWriter>,
    committer: Box<dyn ExtentCommitter>,
    candidates: Vec<IngestExtent>,
}

impl RebakeService {
    /// Create a rebake job with concrete storage backends.
    #[must_use]
    pub fn new(
        scanner: Box<dyn ExtentScan>,
        reader: Box<dyn ExtentReader>,
        writer: Box<dyn ShardWriter>,
        committer: Box<dyn ExtentCommitter>,
        policy: RedundancyPolicy,
    ) -> Self {
        Self::with_job_id(JobId::NONE, scanner, reader, writer, committer, policy)
    }

    /// Create a rebake job with an explicit job id.
    #[must_use]
    pub fn with_job_id(
        job_id: JobId,
        scanner: Box<dyn ExtentScan>,
        reader: Box<dyn ExtentReader>,
        writer: Box<dyn ShardWriter>,
        committer: Box<dyn ExtentCommitter>,
        policy: RedundancyPolicy,
    ) -> Self {
        Self {
            job_id,
            policy,
            cursor: RebakeCursor::FRESH,
            stats: RebakeStats::ZERO,
            scanner,
            reader,
            writer,
            committer,
            candidates: Vec::new(),
        }
    }

    /// Current policy.
    #[must_use]
    pub const fn policy(&self) -> RedundancyPolicy {
        self.policy
    }

    /// Current cumulative stats.
    #[must_use]
    pub const fn stats(&self) -> RebakeStats {
        self.stats
    }

    fn checkpoint(&self, is_complete: bool) -> StepResult {
        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::Rebake,
            epoch: 1,
            cursor_state: CursorState(self.cursor.encode()),
            progress: JobProgress {
                items_processed: self.stats.extents_rebaked,
                items_total_estimate: self.candidates.len() as u64,
                bytes_processed: self.stats.bytes_rebaked,
                bytes_total_estimate: self.stats.ingest_bytes_remaining,
                elapsed_ms: 0,
            },
        };
        if is_complete {
            StepResult::complete(checkpoint)
        } else {
            StepResult::in_progress(checkpoint)
        }
    }

    fn refresh_candidates_if_needed(&mut self) -> Result<(), JobError> {
        if !self.candidates.is_empty() {
            return Ok(());
        }
        self.candidates = self
            .scanner
            .list_rebake_candidates()
            .map_err(|e| JobError::Other(format!("rebake candidate scan failed: {e}")))?;
        self.stats.ingest_bytes_remaining = self.scanner.ingest_bytes_total().unwrap_or(0);
        Ok(())
    }

    fn prepare_output(&self, data: &[u8]) -> Result<RebakeOutput, JobError> {
        self.policy
            .validate()
            .map_err(|e| JobError::Other(format!("invalid rebake policy: {e}")))?;
        match self.policy {
            RedundancyPolicy::None => {
                Err(JobError::Other("none policy has no rebake output".into()))
            }
            RedundancyPolicy::Replicated { copies } => Ok(RebakeOutput::Replicated {
                copies: vec![data.to_vec(); copies as usize],
            }),
            RedundancyPolicy::ErasureCoded {
                data_shards,
                parity_shards,
            } => {
                let (shard_group, shards) =
                    ShardGroupEncoder::encode(data, data_shards, parity_shards).ok_or_else(
                        || {
                            JobError::Other(format!(
                        "failed to encode ShardGroupV1 with k={data_shards} m={parity_shards}"
                    ))
                        },
                    )?;
                Ok(RebakeOutput::ErasureCoded {
                    shard_group,
                    shards,
                })
            }
        }
    }

    fn rebake_one_extent(&mut self, extent: &IngestExtent) -> Result<u64, JobError> {
        let data = self
            .reader
            .read_extent_data(extent.extent_key)
            .map_err(|e| {
                JobError::Other(format!("read extent {} failed: {e}", extent.extent_key))
            })?;
        let data_len = data.len() as u64;
        let output = self.prepare_output(&data)?;
        let target = self
            .writer
            .write_rebake_output(extent, &output)
            .map_err(|e| {
                JobError::Other(format!(
                    "write rebake output for extent {} failed: {e}",
                    extent.extent_key
                ))
            })?;
        self.committer
            .commit_rebake(extent.extent_key, target)
            .map_err(|e| {
                JobError::Other(format!(
                    "commit rebake for extent {} failed: {e}",
                    extent.extent_key
                ))
            })?;
        Ok(data_len)
    }
}

impl IncrementalJob for RebakeService {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        match state {
            Some(cp) => {
                if cp.job_kind != JobKind::Rebake {
                    return Err(JobError::CursorStateInvalid {
                        job_id: cp.job_id,
                        reason: "checkpoint job_kind is not Rebake",
                    });
                }
                let cursor = RebakeCursor::decode(cp.cursor_state.as_bytes()).ok_or(
                    JobError::CursorStateInvalid {
                        job_id: cp.job_id,
                        reason: "rebake cursor must be 8 bytes",
                    },
                )?;
                Ok(Self {
                    job_id: cp.job_id,
                    policy: RedundancyPolicy::default(),
                    cursor,
                    stats: RebakeStats {
                        extents_scanned: cp.progress.items_processed,
                        extents_rebaked: cp.progress.items_processed,
                        bytes_rebaked: cp.progress.bytes_processed,
                        ingest_bytes_remaining: cp.progress.bytes_total_estimate,
                    },
                    scanner: Box::new(NoopScanner),
                    reader: Box::new(NoopReader),
                    writer: Box::new(NoopWriter),
                    committer: Box::new(NoopCommitter),
                    candidates: Vec::new(),
                })
            }
            None => Ok(Self::new(
                Box::new(NoopScanner),
                Box::new(NoopReader),
                Box::new(NoopWriter),
                Box::new(NoopCommitter),
                RedundancyPolicy::default(),
            )),
        }
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        if !self.policy.is_active() {
            return Ok(self.checkpoint(true));
        }
        self.refresh_candidates_if_needed()?;
        if self.candidates.is_empty() {
            return Ok(self.checkpoint(true));
        }

        let mut items_this_step = 0u64;
        let mut bytes_this_step = 0u64;

        while (self.cursor.candidate_index as usize) < self.candidates.len() {
            if budget.max_items > 0 && items_this_step >= budget.max_items {
                break;
            }

            let extent = self.candidates[self.cursor.candidate_index as usize].clone();
            if budget.max_bytes > 0
                && bytes_this_step.saturating_add(extent.data_size) > budget.max_bytes
            {
                if items_this_step == 0 {
                    return Err(JobError::BudgetExceeded {
                        job_id: self.job_id,
                        budget,
                        actual_items: 1,
                        actual_bytes: extent.data_size,
                    });
                }
                break;
            }

            self.stats.extents_scanned = self.stats.extents_scanned.saturating_add(1);
            items_this_step = items_this_step.saturating_add(1);

            if extent.lifecycle != ReplicaLifecycle::Replicated {
                self.cursor.advance();
                continue;
            }

            let data_len = self.rebake_one_extent(&extent)?;
            bytes_this_step = bytes_this_step.saturating_add(data_len);
            self.stats.bytes_rebaked = self.stats.bytes_rebaked.saturating_add(data_len);
            self.stats.extents_rebaked = self.stats.extents_rebaked.saturating_add(1);
            self.cursor.advance();
        }

        self.stats.ingest_bytes_remaining = self.scanner.ingest_bytes_total().unwrap_or(0);
        let is_complete = self.cursor.candidate_index as usize >= self.candidates.len();
        Ok(self.checkpoint(is_complete))
    }

    fn persist_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), JobError> {
        if checkpoint.job_kind != JobKind::Rebake {
            return Err(JobError::CursorStateInvalid {
                job_id: self.job_id,
                reason: "checkpoint job_kind is not Rebake",
            });
        }
        if checkpoint.job_id != self.job_id {
            return Err(JobError::CursorStateInvalid {
                job_id: self.job_id,
                reason: "checkpoint job_id does not match service",
            });
        }
        if checkpoint.cursor_state.as_bytes() != self.cursor.encode().as_slice() {
            return Err(JobError::CursorStateInvalid {
                job_id: self.job_id,
                reason: "checkpoint cursor does not match service cursor",
            });
        }
        Ok(())
    }

    fn complete(self) -> Result<(), JobError> {
        Ok(())
    }

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::Rebake
    }
}

struct NoopScanner;

impl ExtentScan for NoopScanner {
    fn list_rebake_candidates(&self) -> Result<Vec<IngestExtent>, String> {
        Ok(Vec::new())
    }

    fn ingest_bytes_total(&self) -> Result<u64, String> {
        Ok(0)
    }
}

struct NoopReader;

impl ExtentReader for NoopReader {
    fn read_extent_data(&self, _extent_key: u64) -> Result<Vec<u8>, String> {
        Err("noop rebake reader is not configured".into())
    }
}

struct NoopWriter;

impl ShardWriter for NoopWriter {
    fn write_rebake_output(
        &mut self,
        _extent: &IngestExtent,
        _output: &RebakeOutput,
    ) -> Result<RebakeTarget, String> {
        Err("noop rebake writer is not configured".into())
    }
}

struct NoopCommitter;

impl ExtentCommitter for NoopCommitter {
    fn commit_rebake(&mut self, _old_extent_key: u64, _target: RebakeTarget) -> Result<(), String> {
        Err("noop rebake committer is not configured".into())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod rebake_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type RebakeWrites = Arc<Mutex<Vec<(u64, RebakeOutput)>>>;
    type RebakeCommits = Arc<Mutex<Vec<(u64, RebakeTarget)>>>;

    #[derive(Clone)]
    struct MockScanner {
        extents: Vec<IngestExtent>,
    }

    impl ExtentScan for MockScanner {
        fn list_rebake_candidates(&self) -> Result<Vec<IngestExtent>, String> {
            Ok(self.extents.clone())
        }

        fn ingest_bytes_total(&self) -> Result<u64, String> {
            Ok(self.extents.iter().map(|extent| extent.data_size).sum())
        }
    }

    struct MockReader {
        data: HashMap<u64, Vec<u8>>,
    }

    impl ExtentReader for MockReader {
        fn read_extent_data(&self, extent_key: u64) -> Result<Vec<u8>, String> {
            self.data
                .get(&extent_key)
                .cloned()
                .ok_or_else(|| format!("missing data for extent {extent_key}"))
        }
    }

    struct MockWriter {
        writes: Arc<Mutex<Vec<(u64, RebakeOutput)>>>,
        next_replica_group_id: u64,
    }

    impl ShardWriter for MockWriter {
        fn write_rebake_output(
            &mut self,
            extent: &IngestExtent,
            output: &RebakeOutput,
        ) -> Result<RebakeTarget, String> {
            self.writes
                .lock()
                .expect("write log lock")
                .push((extent.extent_key, output.clone()));
            match output {
                RebakeOutput::Replicated { copies } => {
                    let replica_group_id = self.next_replica_group_id;
                    self.next_replica_group_id = self.next_replica_group_id.saturating_add(1);
                    Ok(RebakeTarget::Replicated {
                        replica_group_id,
                        copies: copies.len() as u8,
                    })
                }
                RebakeOutput::ErasureCoded { shard_group, .. } => Ok(RebakeTarget::ShardGroupV1 {
                    shard_group_id: shard_group.shard_group_id,
                    data_shards: shard_group.k,
                    parity_shards: shard_group.m,
                }),
            }
        }
    }

    struct MockCommitter {
        commits: Arc<Mutex<Vec<(u64, RebakeTarget)>>>,
    }

    impl ExtentCommitter for MockCommitter {
        fn commit_rebake(
            &mut self,
            old_extent_key: u64,
            target: RebakeTarget,
        ) -> Result<(), String> {
            self.commits
                .lock()
                .expect("commit log lock")
                .push((old_extent_key, target));
            Ok(())
        }
    }

    fn extent(extent_key: u64, data_size: u64) -> IngestExtent {
        IngestExtent {
            extent_key,
            dataset_id: 7,
            data_size,
            lifecycle: ReplicaLifecycle::Replicated,
        }
    }

    fn make_service(
        extents: Vec<IngestExtent>,
        data: HashMap<u64, Vec<u8>>,
        policy: RedundancyPolicy,
    ) -> (RebakeService, RebakeWrites, RebakeCommits) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let commits = Arc::new(Mutex::new(Vec::new()));
        let service = RebakeService::with_job_id(
            JobId(3447),
            Box::new(MockScanner { extents }),
            Box::new(MockReader { data }),
            Box::new(MockWriter {
                writes: writes.clone(),
                next_replica_group_id: 100,
            }),
            Box::new(MockCommitter {
                commits: commits.clone(),
            }),
            policy,
        );
        (service, writes, commits)
    }

    #[test]
    fn redundancy_policy_validation_and_labels() {
        assert_eq!(RedundancyPolicy::None.label(), "none");
        assert!(!RedundancyPolicy::None.is_active());
        assert_eq!(RedundancyPolicy::Replicated { copies: 3 }.shard_count(), 3);
        assert_eq!(
            RedundancyPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2
            }
            .shard_count(),
            6
        );
        assert!(RedundancyPolicy::ErasureCoded {
            data_shards: 4,
            parity_shards: 2
        }
        .is_erasure_coded());
        assert!(RedundancyPolicy::Replicated { copies: 0 }
            .validate()
            .is_err());
    }

    #[test]
    fn rebake_stats_accumulate_uses_latest_remaining_snapshot() {
        let mut stats = RebakeStats::ZERO;
        stats.accumulate(RebakeStats {
            extents_scanned: 2,
            extents_rebaked: 1,
            bytes_rebaked: 4096,
            ingest_bytes_remaining: 8192,
        });
        stats.accumulate(RebakeStats {
            extents_scanned: 3,
            extents_rebaked: 2,
            bytes_rebaked: 2048,
            ingest_bytes_remaining: 1024,
        });
        assert_eq!(stats.extents_scanned, 5);
        assert_eq!(stats.extents_rebaked, 3);
        assert_eq!(stats.bytes_rebaked, 6144);
        assert_eq!(stats.ingest_bytes_remaining, 1024);
    }

    #[test]
    fn rebake_cursor_checkpoint_roundtrip() {
        let cursor = RebakeCursor {
            candidate_index: 42,
        };
        assert_eq!(RebakeCursor::decode(&cursor.encode()), Some(cursor));
        assert!(RebakeCursor::decode(&[1, 2, 3]).is_none());
    }

    #[test]
    fn none_policy_completes_without_io() {
        let (mut service, writes, commits) = make_service(
            vec![extent(1, 4)],
            HashMap::from([(1, vec![1, 2, 3, 4])]),
            RedundancyPolicy::None,
        );
        let step = service.step(WorkBudget::DEFAULT_TICK).expect("step");
        assert!(step.is_complete);
        assert_eq!(service.stats().extents_rebaked, 0);
        assert!(writes.lock().expect("writes").is_empty());
        assert!(commits.lock().expect("commits").is_empty());
    }

    #[test]
    fn rebake_with_replicated_policy_writes_full_copies_and_commits() {
        let (mut service, writes, commits) = make_service(
            vec![extent(1, 4), extent(2, 3)],
            HashMap::from([(1, vec![1, 2, 3, 4]), (2, vec![9, 8, 7])]),
            RedundancyPolicy::Replicated { copies: 3 },
        );
        let step = service.step(WorkBudget::UNBOUNDED).expect("step");
        assert!(step.is_complete);
        assert_eq!(service.stats().extents_scanned, 2);
        assert_eq!(service.stats().extents_rebaked, 2);
        assert_eq!(service.stats().bytes_rebaked, 7);

        let writes = writes.lock().expect("writes");
        assert_eq!(writes.len(), 2);
        match &writes[0].1 {
            RebakeOutput::Replicated { copies } => {
                assert_eq!(copies.len(), 3);
                assert!(copies.iter().all(|copy| copy == &[1, 2, 3, 4]));
            }
            other => panic!("expected replicated output, got {other:?}"),
        }

        let commits = commits.lock().expect("commits");
        assert_eq!(commits.len(), 2);
        assert_eq!(
            commits[0],
            (
                1,
                RebakeTarget::Replicated {
                    replica_group_id: 100,
                    copies: 3
                }
            )
        );
        assert_eq!(
            commits[1],
            (
                2,
                RebakeTarget::Replicated {
                    replica_group_id: 101,
                    copies: 3
                }
            )
        );
    }

    #[test]
    fn rebake_with_erasure_coded_policy_builds_shard_group_v1() {
        let data = b"payload rebaked into current ShardGroupV1".to_vec();
        let (mut service, writes, commits) = make_service(
            vec![extent(9, data.len() as u64)],
            HashMap::from([(9, data.clone())]),
            RedundancyPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
            },
        );

        let step = service.step(WorkBudget::UNBOUNDED).expect("step");
        assert!(step.is_complete);
        assert_eq!(service.stats().extents_rebaked, 1);
        assert_eq!(service.stats().bytes_rebaked, data.len() as u64);

        let writes = writes.lock().expect("writes");
        match &writes[0].1 {
            RebakeOutput::ErasureCoded {
                shard_group,
                shards,
            } => {
                assert_eq!(shard_group.k, 4);
                assert_eq!(shard_group.m, 2);
                assert_eq!(shards.len(), 6);
                ShardGroupDecoder::verify_self_checksum(shard_group).expect("self checksum");
            }
            other => panic!("expected erasure-coded output, got {other:?}"),
        }

        let commits = commits.lock().expect("commits");
        assert_eq!(commits.len(), 1);
        match commits[0].1 {
            RebakeTarget::ShardGroupV1 {
                data_shards,
                parity_shards,
                ..
            } => {
                assert_eq!(data_shards, 4);
                assert_eq!(parity_shards, 2);
            }
            other => panic!("expected ShardGroupV1 target, got {other:?}"),
        }
    }

    #[test]
    fn rebake_respects_max_items_budget() {
        let data = vec![0x42; 8];
        let (mut service, _writes, commits) = make_service(
            vec![extent(1, 8), extent(2, 8), extent(3, 8)],
            HashMap::from([(1, data.clone()), (2, data.clone()), (3, data)]),
            RedundancyPolicy::Replicated { copies: 2 },
        );
        let budget = WorkBudget {
            max_items: 1,
            max_bytes: 0,
            max_ms: 0,
        };

        assert!(!service.step(budget).expect("step 1").is_complete);
        assert_eq!(service.stats().extents_rebaked, 1);
        assert!(!service.step(budget).expect("step 2").is_complete);
        assert_eq!(service.stats().extents_rebaked, 2);
        assert!(service.step(budget).expect("step 3").is_complete);
        assert_eq!(commits.lock().expect("commits").len(), 3);
    }

    #[test]
    fn rebake_respects_max_bytes_budget() {
        let (mut service, _writes, _commits) = make_service(
            vec![extent(1, 4), extent(2, 4)],
            HashMap::from([(1, vec![1, 2, 3, 4]), (2, vec![5, 6, 7, 8])]),
            RedundancyPolicy::Replicated { copies: 2 },
        );
        let budget = WorkBudget {
            max_items: 0,
            max_bytes: 4,
            max_ms: 0,
        };

        assert!(!service.step(budget).expect("step 1").is_complete);
        assert_eq!(service.stats().extents_rebaked, 1);
        assert!(service.step(budget).expect("step 2").is_complete);
        assert_eq!(service.stats().extents_rebaked, 2);
    }

    #[test]
    fn rebake_too_small_byte_budget_fails_without_partial_commit() {
        let (mut service, _writes, commits) = make_service(
            vec![extent(1, 8)],
            HashMap::from([(1, vec![0xAA; 8])]),
            RedundancyPolicy::Replicated { copies: 2 },
        );
        let budget = WorkBudget {
            max_items: 0,
            max_bytes: 4,
            max_ms: 0,
        };

        let err = service.step(budget).expect_err("budget error");
        assert!(matches!(err, JobError::BudgetExceeded { .. }));
        assert!(commits.lock().expect("commits").is_empty());
        assert_eq!(service.stats().extents_rebaked, 0);
    }

    #[test]
    fn non_replicated_candidates_are_scanned_but_not_rebaked() {
        let mut pending = extent(1, 8);
        pending.lifecycle = ReplicaLifecycle::Replicating;
        let (mut service, writes, commits) = make_service(
            vec![pending, extent(2, 4)],
            HashMap::from([(1, vec![0x11; 8]), (2, vec![0x22; 4])]),
            RedundancyPolicy::Replicated { copies: 2 },
        );
        let step = service.step(WorkBudget::UNBOUNDED).expect("step");
        assert!(step.is_complete);
        assert_eq!(service.stats().extents_scanned, 2);
        assert_eq!(service.stats().extents_rebaked, 1);
        assert_eq!(writes.lock().expect("writes").len(), 1);
        assert_eq!(commits.lock().expect("commits").len(), 1);
    }

    #[test]
    fn checkpoint_persistence_and_resume_keep_cursor() {
        let (mut service, _writes, _commits) = make_service(
            vec![extent(1, 4), extent(2, 4)],
            HashMap::from([(1, vec![1, 2, 3, 4]), (2, vec![5, 6, 7, 8])]),
            RedundancyPolicy::Replicated { copies: 2 },
        );
        let budget = WorkBudget {
            max_items: 1,
            max_bytes: 0,
            max_ms: 0,
        };
        let step = service.step(budget).expect("step");
        assert!(!step.is_complete);
        service
            .persist_checkpoint(&step.checkpoint)
            .expect("persist checkpoint");

        let resumed = RebakeService::resume(Some(step.checkpoint)).expect("resume");
        assert_eq!(resumed.job_id(), JobId(3447));
        assert_eq!(resumed.job_kind(), JobKind::Rebake);
        assert_eq!(resumed.stats().extents_rebaked, 1);
    }

    #[test]
    fn resume_rejects_wrong_job_kind() {
        let checkpoint = Checkpoint::new_initial(JobId(1), JobKind::Scrub);
        let err = match RebakeService::resume(Some(checkpoint)) {
            Ok(_) => panic!("expected wrong-kind resume to fail"),
            Err(err) => err,
        };
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // ── ReplicaLifecycle tests ─────────────────────────────────────

    #[test]
    fn lifecycle_terminal_only_base() {
        assert!(!ReplicaLifecycle::Ingest.is_terminal());
        assert!(!ReplicaLifecycle::Replicating.is_terminal());
        assert!(!ReplicaLifecycle::Replicated.is_terminal());
        assert!(!ReplicaLifecycle::Rebaking.is_terminal());
        assert!(ReplicaLifecycle::Base.is_terminal());
    }

    #[test]
    fn lifecycle_durable_states() {
        assert!(!ReplicaLifecycle::Ingest.is_durable());
        assert!(!ReplicaLifecycle::Replicating.is_durable());
        assert!(ReplicaLifecycle::Replicated.is_durable());
        assert!(ReplicaLifecycle::Rebaking.is_durable());
        assert!(ReplicaLifecycle::Base.is_durable());
    }

    #[test]
    fn lifecycle_vulnerable_states() {
        assert!(ReplicaLifecycle::Ingest.is_vulnerable());
        assert!(ReplicaLifecycle::Replicating.is_vulnerable());
        assert!(!ReplicaLifecycle::Replicated.is_vulnerable());
        assert!(!ReplicaLifecycle::Rebaking.is_vulnerable());
        assert!(!ReplicaLifecycle::Base.is_vulnerable());
    }

    #[test]
    fn lifecycle_forward_transitions() {
        assert_eq!(
            ReplicaLifecycle::Ingest.advance(ReplicaLifecycle::Replicating),
            Ok(ReplicaLifecycle::Replicating)
        );
        assert_eq!(
            ReplicaLifecycle::Replicating.advance(ReplicaLifecycle::Replicated),
            Ok(ReplicaLifecycle::Replicated)
        );
        assert_eq!(
            ReplicaLifecycle::Replicated.advance(ReplicaLifecycle::Rebaking),
            Ok(ReplicaLifecycle::Rebaking)
        );
        assert_eq!(
            ReplicaLifecycle::Rebaking.advance(ReplicaLifecycle::Base),
            Ok(ReplicaLifecycle::Base)
        );
    }

    #[test]
    fn lifecycle_invalid_transitions() {
        // Cannot skip states
        assert_eq!(
            ReplicaLifecycle::Ingest.advance(ReplicaLifecycle::Replicated),
            Err(ReplicaLifecycle::Ingest)
        );
        assert_eq!(
            ReplicaLifecycle::Ingest.advance(ReplicaLifecycle::Base),
            Err(ReplicaLifecycle::Ingest)
        );
        // Cannot go backwards
        assert_eq!(
            ReplicaLifecycle::Replicated.advance(ReplicaLifecycle::Ingest),
            Err(ReplicaLifecycle::Replicated)
        );
        assert_eq!(
            ReplicaLifecycle::Base.advance(ReplicaLifecycle::Rebaking),
            Err(ReplicaLifecycle::Base)
        );
        // Base is terminal
        assert_eq!(
            ReplicaLifecycle::Base.advance(ReplicaLifecycle::Base),
            Ok(ReplicaLifecycle::Base)
        );
        assert_eq!(
            ReplicaLifecycle::Base.advance(ReplicaLifecycle::Ingest),
            Err(ReplicaLifecycle::Base)
        );
    }

    #[test]
    fn lifecycle_idempotent_transition() {
        for state in ReplicaLifecycle::all_states() {
            assert_eq!(state.advance(state), Ok(state));
        }
    }

    #[test]
    fn lifecycle_ordinal_ordering() {
        assert!(ReplicaLifecycle::Ingest.precedes(ReplicaLifecycle::Replicating));
        assert!(ReplicaLifecycle::Replicating.precedes(ReplicaLifecycle::Replicated));
        assert!(ReplicaLifecycle::Replicated.precedes(ReplicaLifecycle::Rebaking));
        assert!(ReplicaLifecycle::Rebaking.precedes(ReplicaLifecycle::Base));
        assert!(!ReplicaLifecycle::Base.precedes(ReplicaLifecycle::Ingest));
    }

    #[test]
    fn lifecycle_display() {
        assert_eq!(ReplicaLifecycle::Ingest.to_string(), "ingest");
        assert_eq!(ReplicaLifecycle::Replicating.to_string(), "replicating");
        assert_eq!(ReplicaLifecycle::Replicated.to_string(), "replicated");
        assert_eq!(ReplicaLifecycle::Rebaking.to_string(), "rebaking");
        assert_eq!(ReplicaLifecycle::Base.to_string(), "base");
    }

    // ── DurabilityWarning tests ────────────────────────────────────

    #[test]
    fn warning_ingest_ok_within_limit() {
        let w = DurabilityWarning::evaluate(ReplicaLifecycle::Ingest, Duration::from_secs(15));
        assert_eq!(w, DurabilityWarning::Ok);
    }

    #[test]
    fn warning_ingest_warning_after_30s() {
        let w = DurabilityWarning::evaluate(ReplicaLifecycle::Ingest, Duration::from_secs(30));
        assert_eq!(w, DurabilityWarning::Warning);
    }

    #[test]
    fn warning_ingest_critical_after_300s() {
        let w = DurabilityWarning::evaluate(ReplicaLifecycle::Ingest, Duration::from_secs(300));
        assert_eq!(w, DurabilityWarning::Critical);

        let w2 = DurabilityWarning::evaluate(ReplicaLifecycle::Ingest, Duration::from_secs(600));
        assert_eq!(w2, DurabilityWarning::Critical);
    }

    #[test]
    fn warning_replicating_ok_within_limit() {
        let w = DurabilityWarning::evaluate(ReplicaLifecycle::Replicating, Duration::from_secs(60));
        assert_eq!(w, DurabilityWarning::Ok);
    }

    #[test]
    fn warning_replicating_warning_after_120s() {
        let w =
            DurabilityWarning::evaluate(ReplicaLifecycle::Replicating, Duration::from_secs(120));
        assert_eq!(w, DurabilityWarning::Warning);
    }

    #[test]
    fn warning_durable_states_always_ok() {
        for state in &[
            ReplicaLifecycle::Replicated,
            ReplicaLifecycle::Rebaking,
            ReplicaLifecycle::Base,
        ] {
            let w = DurabilityWarning::evaluate(*state, Duration::from_secs(3600));
            assert_eq!(w, DurabilityWarning::Ok, "state {state:?} should be ok");
        }
    }

    // ── DurabilityLadder tests ─────────────────────────────────────

    #[test]
    fn ladder_starts_at_ingest() {
        let ladder = DurabilityLadder::new(100);
        assert_eq!(ladder.state(), ReplicaLifecycle::Ingest);
        assert_eq!(ladder.entered_at_secs(), 100);
    }

    #[test]
    fn ladder_full_cycle() {
        let mut ladder = DurabilityLadder::new(0);

        let s = ladder.try_advance(ReplicaLifecycle::Replicating, 10);
        assert_eq!(s, ReplicaLifecycle::Replicating);
        assert_eq!(ladder.entered_at_secs(), 10);

        let s = ladder.try_advance(ReplicaLifecycle::Replicated, 20);
        assert_eq!(s, ReplicaLifecycle::Replicated);
        assert_eq!(ladder.entered_at_secs(), 20);

        let s = ladder.try_advance(ReplicaLifecycle::Rebaking, 30);
        assert_eq!(s, ReplicaLifecycle::Rebaking);
        assert_eq!(ladder.entered_at_secs(), 30);

        let s = ladder.try_advance(ReplicaLifecycle::Base, 40);
        assert_eq!(s, ReplicaLifecycle::Base);
        assert_eq!(ladder.entered_at_secs(), 40);

        assert!(ladder.is_terminal());
    }

    #[test]
    fn ladder_rejects_skip() {
        let mut ladder = DurabilityLadder::new(0);
        // Skip from Ingest to Replicated
        let s = ladder.try_advance(ReplicaLifecycle::Replicated, 10);
        assert_eq!(s, ReplicaLifecycle::Ingest); // unchanged
        assert_eq!(ladder.entered_at_secs(), 0); // clock unchanged
    }

    #[test]
    fn ladder_rejects_backwards() {
        let mut ladder = DurabilityLadder::new(0);
        let _ = ladder.try_advance(ReplicaLifecycle::Replicating, 10);
        let _ = ladder.try_advance(ReplicaLifecycle::Replicated, 20);

        // Attempt to go back to Ingest
        let s = ladder.try_advance(ReplicaLifecycle::Ingest, 30);
        assert_eq!(s, ReplicaLifecycle::Replicated); // unchanged
        assert_eq!(ladder.entered_at_secs(), 20); // clock unchanged
    }

    #[test]
    fn ladder_elapsed() {
        let mut ladder = DurabilityLadder::new(100);
        assert_eq!(ladder.elapsed(115), Duration::from_secs(15));

        let _ = ladder.try_advance(ReplicaLifecycle::Replicating, 200);
        assert_eq!(ladder.elapsed(260), Duration::from_secs(60));
    }

    #[test]
    fn ladder_warning_escalation() {
        let mut ladder = DurabilityLadder::new(0);

        // 15s in Ingest: OK
        assert_eq!(ladder.warning(15), DurabilityWarning::Ok);

        // 30s in Ingest: Warning
        assert_eq!(ladder.warning(30), DurabilityWarning::Warning);

        // 300s in Ingest: Critical
        assert_eq!(ladder.warning(300), DurabilityWarning::Critical);

        // Transition to Replicating resets clock
        let _ = ladder.try_advance(ReplicaLifecycle::Replicating, 310);
        assert_eq!(ladder.warning(370), DurabilityWarning::Ok); // 60s in Replicating

        // 120s in Replicating: Warning
        assert_eq!(ladder.warning(430), DurabilityWarning::Warning);

        // Transition to Replicated: always OK
        let _ = ladder.try_advance(ReplicaLifecycle::Replicated, 440);
        assert_eq!(ladder.warning(5000), DurabilityWarning::Ok);
    }

    // ── Multi-extent tests ─────────────────────────────────────────

    #[test]
    fn multi_extent_concurrent_lifecycle() {
        let mut extents = vec![
            DurabilityLadder::new(0),
            DurabilityLadder::new(0),
            DurabilityLadder::new(0),
        ];

        // All start at Ingest
        let summary = DurabilitySummary::from_ladders(&extents);
        assert_eq!(summary.ingest_count, 3);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.vulnerable_count(), 3);
        assert_eq!(summary.durable_count(), 0);

        // Advance extent 0 to Replicating
        let _ = extents[0].try_advance(ReplicaLifecycle::Replicating, 10);
        let summary = DurabilitySummary::from_ladders(&extents);
        assert_eq!(summary.ingest_count, 2);
        assert_eq!(summary.replicating_count, 1);
        assert_eq!(summary.vulnerable_count(), 3);

        // Advance extent 1 to Replicated
        let _ = extents[1].try_advance(ReplicaLifecycle::Replicating, 10);
        let _ = extents[1].try_advance(ReplicaLifecycle::Replicated, 20);
        let summary = DurabilitySummary::from_ladders(&extents);
        assert_eq!(summary.ingest_count, 1);
        assert_eq!(summary.replicating_count, 1);
        assert_eq!(summary.replicated_count, 1);
        assert_eq!(summary.durable_count(), 1);

        // Advance extent 2 to Base
        let _ = extents[2].try_advance(ReplicaLifecycle::Replicating, 10);
        let _ = extents[2].try_advance(ReplicaLifecycle::Replicated, 20);
        let _ = extents[2].try_advance(ReplicaLifecycle::Rebaking, 30);
        let _ = extents[2].try_advance(ReplicaLifecycle::Base, 40);
        let summary = DurabilitySummary::from_ladders(&extents);
        assert_eq!(summary.base_count, 1);
        assert_eq!(summary.durable_count(), 2);
    }

    #[test]
    fn durability_summary_empty() {
        let summary = DurabilitySummary::from_ladders(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.vulnerable_count(), 0);
        assert_eq!(summary.durable_count(), 0);
        assert!((summary.durable_fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn durability_summary_fractions() {
        let extents = vec![
            DurabilityLadder::with_state(ReplicaLifecycle::Base, 0),
            DurabilityLadder::with_state(ReplicaLifecycle::Ingest, 0),
            DurabilityLadder::with_state(ReplicaLifecycle::Replicated, 0),
        ];
        let summary = DurabilitySummary::from_ladders(&extents);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.durable_count(), 2);
        assert!((summary.durable_fraction() - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn stuck_detection_multi_extent() {
        let mut extents = [
            DurabilityLadder::new(0),
            DurabilityLadder::new(10),
            DurabilityLadder::new(20),
        ];

        // At t=320: extent 0 stuck for 320s (Critical), extent 1 for 310s (Critical), extent 2 for 300s (Critical)
        let warnings: Vec<DurabilityWarning> = extents.iter().map(|e| e.warning(320)).collect();
        assert!(warnings.iter().all(|w| *w == DurabilityWarning::Critical));

        // Advance extent 0
        let _ = extents[0].try_advance(ReplicaLifecycle::Replicating, 330);
        assert_eq!(extents[0].warning(340), DurabilityWarning::Ok);

        // Extents 1 and 2 still critical
        assert_eq!(extents[1].warning(340), DurabilityWarning::Critical);
        assert_eq!(extents[2].warning(340), DurabilityWarning::Critical);
    }

    #[test]
    fn serde_roundtrip_lifecycle() {
        for state in ReplicaLifecycle::all_states() {
            let json = serde_json::to_string(&state).expect("serialize");
            let round: ReplicaLifecycle = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, round);
        }
    }

    // ── ShardGroupV1 tests ─────────────────────────────────────────

    fn make_test_sg(k: u8, m: u8) -> ShardGroupV1 {
        let data = b"hello world this is test data for shard group encoding!";
        ShardGroupEncoder::encode_record(data, k, m).expect("encode_record")
    }

    #[test]
    fn roundtrip_4_plus_2() {
        let data = b"The quick brown fox jumps over the lazy dog.  This is a test payload.";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        assert_eq!(sg.k, 4);
        assert_eq!(sg.m, 2);
        assert_eq!(sg.shard_count, 6);
        assert_eq!(sg.shards.len(), 6);
        assert_eq!(shards.len(), 6);

        ShardGroupDecoder::verify_self_checksum(&sg).expect("self-checksum");

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }

        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_4_plus_2_one_missing() {
        let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        // Drop shard 1, use remaining 5 (3 data + 2 parity = 5 >= k=4)
        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            if i != 1 {
                shard_map.insert(i as u16, s.clone());
            }
        }

        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode with 1 missing");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_4_plus_2_two_missing() {
        let data = b"Erasure coding test: tolerate up to m=2 losses with k=4 data shards.";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        // Drop data shards 0 and 2, keep 2 data + 2 parity = 4 >= k=4
        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            if i != 0 && i != 2 {
                shard_map.insert(i as u16, s.clone());
            }
        }

        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode with 2 missing");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_4_plus_2_three_missing_fails() {
        let data = b"This should fail because we drop 3 shards but only have m=2 parity.";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        // Keep only 1 data + 1 parity = 2 < k=4
        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        shard_map.insert(0, shards[0].clone());
        shard_map.insert(5, shards[5].clone());

        let result = ShardGroupDecoder::decode(&sg, &shard_map);
        assert!(result.is_err());
        match result {
            Err(DecodeError::InsufficientShards { .. })
            | Err(DecodeError::ReconstructionFailed) => {}
            other => {
                panic!("expected insufficient shards or reconstruction failure, got {other:?}")
            }
        }
    }

    #[test]
    fn per_shard_checksum_verification() {
        let data = b"checksum verification test payload";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }
        verify_shard_checksums(&sg, &shard_map).expect("all checksums OK");

        // Corrupt one shard
        let mut corrupted = shard_map.clone();
        if let Some(s) = corrupted.get_mut(&0) {
            s[0] ^= 0xFF;
        }
        let result = verify_shard_checksums(&sg, &corrupted);
        assert!(result.is_err());
        match result {
            Err(DecodeError::ShardChecksumMismatch { shard_index: 0 }) => {}
            other => panic!("expected checksum mismatch at shard 0, got {other:?}"),
        }
    }

    #[test]
    fn self_checksum_tamper_detection() {
        let data = b"self-checksum integrity test";
        let (sg, _shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        ShardGroupDecoder::verify_self_checksum(&sg).expect("valid self-checksum");

        let mut tampered = sg.clone();
        tampered.k = 3;
        let result = ShardGroupDecoder::verify_self_checksum(&tampered);
        assert!(result.is_err());
        match result {
            Err(DecodeError::InvalidChecksum) => {}
            other => panic!("expected InvalidChecksum, got {other:?}"),
        }
    }

    #[test]
    fn binary_roundtrip() {
        let data = b"binary encode/decode roundtrip check";
        let (sg, _shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        let bytes = encode_shard_group(&sg).expect("encode_shard_group");
        let decoded = decode_shard_group(&bytes).expect("decode_shard_group");

        assert_eq!(decoded.shard_group_id, sg.shard_group_id);
        assert_eq!(decoded.k, sg.k);
        assert_eq!(decoded.m, sg.m);
        assert_eq!(decoded.shard_count, sg.shard_count);
        assert_eq!(decoded.original_digest, sg.original_digest);
        assert_eq!(decoded.original_len, sg.original_len);
        assert_eq!(decoded.shards.len(), sg.shards.len());
        assert_eq!(decoded.self_checksum, sg.self_checksum);
    }

    #[test]
    fn binary_decode_rejects_truncated() {
        let data = b"truncation test";
        let (sg, _shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");
        let bytes = encode_shard_group(&sg).expect("encode_shard_group");

        assert!(decode_shard_group(&bytes[..bytes.len() - 10]).is_none());
        assert!(decode_shard_group(&bytes[..10]).is_none());
    }

    #[test]
    fn binary_decode_rejects_tampered_checksum() {
        let data = b"tampered checksum test";
        let (sg, _shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");
        let mut bytes = encode_shard_group(&sg).expect("encode_shard_group");

        bytes[18] ^= 1;

        assert!(decode_shard_group(&bytes).is_none());
    }

    #[test]
    fn encode_empty_payload() {
        let data = b"";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode empty");

        assert_eq!(sg.original_len, 0);

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }
        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode empty");
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_single_byte() {
        let data = b"X";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode single byte");

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }
        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode single byte");
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_exact_multiple_of_k() {
        let data = vec![0xABu8; 256];
        let (sg, shards) = ShardGroupEncoder::encode(&data, 4, 2).expect("encode exact");

        for (i, shard) in shards.iter().enumerate().take(4) {
            assert_eq!(shard.len(), 64, "data shard {i} wrong size");
        }

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }
        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode exact");
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_not_multiple_of_k() {
        let data = vec![0xCDu8; 100];
        let (sg, shards) = ShardGroupEncoder::encode(&data, 4, 2).expect("encode non-multiple");

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }
        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode non-multiple");
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_rejects_zero_k() {
        assert!(ShardGroupEncoder::encode(b"data", 0, 2).is_none());
    }

    #[test]
    fn encode_rejects_zero_m() {
        assert!(ShardGroupEncoder::encode(b"data", 4, 0).is_none());
    }

    #[test]
    fn encode_rejects_overflow() {
        assert!(ShardGroupEncoder::encode(b"data", 200, 56).is_none());
    }

    #[test]
    fn roundtrip_2_plus_1() {
        let data = b"minimal 2+1 config test data";
        let (sg, shards) = ShardGroupEncoder::encode(data, 2, 1).expect("encode 2+1");

        assert_eq!(sg.k, 2);
        assert_eq!(sg.m, 1);
        assert_eq!(sg.shard_count, 3);

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }

        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode 2+1");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_2_plus_1_one_data_missing() {
        let data = b"2+1 with one data shard missing";
        let (sg, shards) = ShardGroupEncoder::encode(data, 2, 1).expect("encode 2+1");

        // Drop data shard 0, keep shard 1 + parity = 2 >= k=2
        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        shard_map.insert(1, shards[1].clone());
        shard_map.insert(2, shards[2].clone());

        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode 2+1 missing 1");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_2_plus_1_two_missing_fails() {
        let data = b"2+1 with two missing should fail";
        let (sg, shards) = ShardGroupEncoder::encode(data, 2, 1).expect("encode 2+1");

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        shard_map.insert(2, shards[2].clone());

        let result = ShardGroupDecoder::decode(&sg, &shard_map);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_8_plus_3() {
        let data = b"larger 8+3 configuration with triple parity for extra durability";
        let (sg, shards) = ShardGroupEncoder::encode(data, 8, 3).expect("encode 8+3");

        assert_eq!(sg.k, 8);
        assert_eq!(sg.m, 3);
        assert_eq!(sg.shard_count, 11);

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_map.insert(i as u16, s.clone());
        }

        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode 8+3");
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_8_plus_3_three_missing() {
        let data = b"8+3 with max tolerable loss of 3 shards";
        let (sg, shards) = ShardGroupEncoder::encode(data, 8, 3).expect("encode 8+3");

        // Drop shards 0, 4, 7 (3 data shards), keep 5 data + 3 parity = 8 >= k=8
        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (i, s) in shards.iter().enumerate() {
            if i != 0 && i != 4 && i != 7 {
                shard_map.insert(i as u16, s.clone());
            }
        }

        let decoded =
            ShardGroupDecoder::decode(&sg, &shard_map).expect("decode 8+3 with 3 missing");
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_record_returns_valid_sg() {
        let data = b"encode_record test";
        let sg = ShardGroupEncoder::encode_record(data, 4, 2).expect("encode_record");
        assert!(sg.validate().is_ok());
        ShardGroupDecoder::verify_self_checksum(&sg).expect("self-checksum");
    }

    #[test]
    fn decode_from_parity_only() {
        let data = b"testing reconstruction from parity-only shards";
        let (sg, shards) = ShardGroupEncoder::encode(data, 4, 2).expect("encode");

        let mut shard_map: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        shard_map.insert(2, shards[2].clone());
        shard_map.insert(3, shards[3].clone());
        shard_map.insert(4, shards[4].clone());
        shard_map.insert(5, shards[5].clone());

        let decoded = ShardGroupDecoder::decode(&sg, &shard_map).expect("decode from parity");
        assert_eq!(decoded, data);
    }

    #[test]
    fn validate_ok() {
        let sg = make_test_sg(4, 2);
        assert!(sg.validate().is_ok());
    }

    #[test]
    fn validate_mismatched_shard_count() {
        let mut sg = make_test_sg(4, 2);
        sg.shard_count = 7;
        assert_eq!(sg.validate(), Err("shard_count must equal k + m"));
    }

    #[test]
    fn validate_mismatched_shards_len() {
        let mut sg = make_test_sg(4, 2);
        sg.shards.pop();
        assert_eq!(sg.validate(), Err("shards.len() must equal shard_count"));
    }

    #[test]
    fn decode_error_display() {
        assert_eq!(
            DecodeError::InvalidChecksum.to_string(),
            "ShardGroupV1 self-checksum invalid"
        );
        assert_eq!(
            DecodeError::ShardChecksumMismatch { shard_index: 3 }.to_string(),
            "per-shard checksum mismatch at shard 3"
        );
        assert_eq!(
            DecodeError::InsufficientShards { have: 2, need: 4 }.to_string(),
            "insufficient shards: have 2, need at least 4"
        );
    }
}
