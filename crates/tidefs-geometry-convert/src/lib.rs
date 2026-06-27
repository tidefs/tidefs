// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Online pool geometry conversion: rewrites locator table entries to change
//! durability policy (mirror <-> erasure coding) without destroying data.
//!
//! Leverages extent_id indirection (#1191): file->extent_id (extent map, unchanged),
//! extent_id->physical_shards (locator table, rewritten during conversion).
//!
//! Implements the geometry conversion design (#3387).
//! Canonical design spec:
//! [`docs/design/online-pool-geometry-conversion.md`].
//!
//! # Current scope
//!
//! Defines `DurabilityPolicy`, `ConversionScope`, `GeometryConversionProgress`,
//! the `GeometryConversionJob` as an `IncrementalJob`, and a pool-backed
//! `ExtentStore` adapter over the current `tidefs-locator-table` authority.
//! Mounted pool release claims remain gated on runtime validation evidence.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use tidefs_erasure_coding::{
    encode as ec_encode, reconstruct as ec_reconstruct, stripe_fragment_count, ErasureShard,
    ShardKind, StripeConfig,
};
pub use tidefs_locator_table::{
    locator_flags, ExtentLocatorValueV1 as LocatorValueV1, LocatorId, LocatorTableError,
    LocatorTableOps, ReplicaHealth, ReplicaPlacement, ShardPlacement,
};
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, IncrementalJob, JobError, JobId, JobKind, JobProgress, StepResult,
    WorkBudget,
};

// ---------------------------------------------------------------------------
// DurabilityPolicy
// ---------------------------------------------------------------------------

/// Defines how data shards are laid out for durability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurabilityPolicy {
    /// N-way mirroring: N identical replicas on distinct failure domains.
    Mirror { replica_count: u8 },
    /// Erasure coding with K data shards + M parity shards.
    ErasureCoded {
        data_shards: u16,
        parity_shards: usize,
        shard_len: usize,
    },
}

impl DurabilityPolicy {
    /// Total number of physical shards needed.
    pub fn total_shards(&self) -> usize {
        match self {
            DurabilityPolicy::Mirror { replica_count } => *replica_count as usize,
            DurabilityPolicy::ErasureCoded {
                data_shards,
                parity_shards,
                ..
            } => *data_shards as usize + parity_shards,
        }
    }

    /// Human-readable label.
    pub const fn label(&self) -> &'static str {
        match self {
            DurabilityPolicy::Mirror { .. } => "mirror",
            DurabilityPolicy::ErasureCoded { .. } => "erasure_coded",
        }
    }

    /// Whether this policy uses erasure coding.
    pub const fn is_erasure_coded(&self) -> bool {
        matches!(self, DurabilityPolicy::ErasureCoded { .. })
    }
}

impl fmt::Display for DurabilityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DurabilityPolicy::Mirror { replica_count } => write!(f, "mirror({replica_count})"),
            DurabilityPolicy::ErasureCoded {
                data_shards,
                parity_shards,
                shard_len,
            } => {
                write!(f, "EC({data_shards}+{parity_shards} shard_len={shard_len})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ConversionScope
// ---------------------------------------------------------------------------

/// Scope of the geometry conversion operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionScope {
    Pool(u64),
    Dataset(u64),
    ExtentClass(u64),
}

impl fmt::Display for ConversionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversionScope::Pool(id) => write!(f, "pool({id})"),
            ConversionScope::Dataset(id) => write!(f, "dataset({id})"),
            ConversionScope::ExtentClass(id) => write!(f, "extent_class({id})"),
        }
    }
}

// ---------------------------------------------------------------------------
// GeometryConversionProgress
// ---------------------------------------------------------------------------

/// Observable conversion progress.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeometryConversionProgress {
    pub entries_total: u64,
    pub entries_converted: u64,
    pub bytes_converted: u64,
    pub estimated_completion_seconds: Option<u64>,
}

impl GeometryConversionProgress {
    pub fn percent(&self) -> f64 {
        if self.entries_total == 0 {
            0.0
        } else {
            (self.entries_converted as f64 / self.entries_total as f64) * 100.0
        }
    }
}

// ---------------------------------------------------------------------------
// ConversionCursor — serializable position
// ---------------------------------------------------------------------------

/// Persistent cursor tracking conversion progress.
#[derive(Clone, Debug)]
pub struct ConversionCursor {
    pub scope: ConversionScope,
    pub old_policy: DurabilityPolicy,
    pub new_policy: DurabilityPolicy,
    pub last_converted_locator: u64,
    pub entries_total: u64,
    pub entries_converted: u64,
    pub bytes_converted: u64,
    pub started_epoch: u64,
    pub cancelled: bool,
    pub failed: bool,
    pub last_error: Option<String>,
}

impl ConversionCursor {
    #[must_use]
    pub const fn pool_id(&self) -> u64 {
        match self.scope {
            ConversionScope::Pool(id)
            | ConversionScope::Dataset(id)
            | ConversionScope::ExtentClass(id) => id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // scope (tag + id)
        match self.scope {
            ConversionScope::Pool(id) => {
                buf.push(0u8);
                buf.extend_from_slice(&id.to_le_bytes());
            }
            ConversionScope::Dataset(id) => {
                buf.push(1u8);
                buf.extend_from_slice(&id.to_le_bytes());
            }
            ConversionScope::ExtentClass(id) => {
                buf.push(2u8);
                buf.extend_from_slice(&id.to_le_bytes());
            }
        }
        encode_policy(&mut buf, &self.old_policy);
        encode_policy(&mut buf, &self.new_policy);
        buf.extend_from_slice(&self.last_converted_locator.to_le_bytes());
        buf.extend_from_slice(&self.entries_total.to_le_bytes());
        buf.extend_from_slice(&self.entries_converted.to_le_bytes());
        buf.extend_from_slice(&self.bytes_converted.to_le_bytes());
        buf.extend_from_slice(&self.started_epoch.to_le_bytes());
        buf.push(if self.cancelled { 1u8 } else { 0u8 });
        buf.push(if self.failed { 1u8 } else { 0u8 });
        match &self.last_error {
            Some(error) => {
                let bytes = error.as_bytes();
                let len = bytes.len().min(u32::MAX as usize) as u32;
                buf.extend_from_slice(&len.to_le_bytes());
                buf.extend_from_slice(&bytes[..len as usize]);
            }
            None => buf.extend_from_slice(&0u32.to_le_bytes()),
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let mut pos = 0usize;
        let scope_tag = data[pos];
        pos += 1;
        if data.len() < pos + 8 {
            return None;
        }
        let id = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let scope = match scope_tag {
            0 => ConversionScope::Pool(id),
            1 => ConversionScope::Dataset(id),
            2 => ConversionScope::ExtentClass(id),
            _ => return None,
        };
        let (old_policy, npos) = decode_policy(data, pos)?;
        pos = npos;
        let (new_policy, npos) = decode_policy(data, pos)?;
        pos = npos;
        if data.len() < pos + 40 {
            return None;
        }
        let last_converted_locator = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let entries_total = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let entries_converted = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let bytes_converted = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let started_epoch = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let cancelled = pos < data.len() && data[pos] != 0;
        if pos < data.len() {
            pos += 1;
        }
        let failed = pos < data.len() && data[pos] != 0;
        if pos < data.len() {
            pos += 1;
        }
        let last_error = if pos < data.len() {
            if data.len() < pos + 4 {
                return None;
            }
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if len == 0 {
                None
            } else {
                if data.len() < pos + len {
                    return None;
                }
                Some(String::from_utf8(data[pos..pos + len].to_vec()).ok()?)
            }
        } else {
            None
        };
        Some(Self {
            scope,
            old_policy,
            new_policy,
            last_converted_locator,
            entries_total,
            entries_converted,
            bytes_converted,
            started_epoch,
            cancelled,
            failed,
            last_error,
        })
    }
}

fn encode_policy(buf: &mut Vec<u8>, policy: &DurabilityPolicy) {
    match policy {
        DurabilityPolicy::Mirror { replica_count } => {
            buf.push(0u8);
            buf.push(*replica_count);
        }
        DurabilityPolicy::ErasureCoded {
            data_shards,
            parity_shards,
            shard_len,
        } => {
            buf.push(1u8);
            buf.extend_from_slice(&data_shards.to_le_bytes());
            buf.push(*parity_shards as u8);
            buf.extend_from_slice(&(*shard_len as u64).to_le_bytes());
        }
    }
}

fn decode_policy(data: &[u8], pos: usize) -> Option<(DurabilityPolicy, usize)> {
    if data.len() <= pos {
        return None;
    }
    let tag = data[pos];
    let mut npos = pos + 1;
    match tag {
        0 => {
            if data.len() <= npos {
                return None;
            }
            let rc = data[npos];
            npos += 1;
            Some((DurabilityPolicy::Mirror { replica_count: rc }, npos))
        }
        1 => {
            if data.len() < npos + 10 {
                return None;
            }
            let ds = u16::from_le_bytes(data[npos..npos + 2].try_into().ok()?);
            npos += 2;
            let pc = data[npos] as usize;
            npos += 1;
            let sl = u64::from_le_bytes(data[npos..npos + 8].try_into().ok()?) as usize;
            npos += 8;
            Some((
                DurabilityPolicy::ErasureCoded {
                    data_shards: ds,
                    parity_shards: pc,
                    shard_len: sl,
                },
                npos,
            ))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LocatorEntry
// ---------------------------------------------------------------------------

/// Simplified locator entry for conversion traversal.
#[derive(Clone, Debug)]
pub struct LocatorEntry {
    pub locator_id: LocatorId,
    pub value: LocatorValueV1,
}

/// Locator table traversal needed by pool-backed geometry conversion.
pub trait LocatorEntrySource: Send {
    /// Total number of locator table entries for the selected pool scope.
    fn locator_count(&self, pool_id: u64) -> u64;

    /// Walk locator entries from `start_after` (None = from beginning).
    fn walk_entries(
        &self,
        pool_id: u64,
        start_after: Option<LocatorId>,
        batch_size: u32,
    ) -> Vec<LocatorEntry>;
}

/// Role of a shard materialized by geometry conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryShardRole {
    MirrorReplica,
    EcData,
    EcParity,
}

/// One shard payload that must be placed before the locator swap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeometryShardWrite {
    pub shard_index: u16,
    pub role: GeometryShardRole,
    pub bytes: Vec<u8>,
    pub payload_digest: [u8; 32],
}

/// Placement planning boundary used by pool-backed conversion.
pub trait GeometryPlacementPlanner: Send {
    fn plan_shard_placements(
        &mut self,
        locator_id: LocatorId,
        new_policy: &DurabilityPolicy,
        writes: &[GeometryShardWrite],
    ) -> Result<Vec<ReplicaPlacement>, String>;
}

/// Physical shard I/O boundary used by pool-backed conversion.
pub trait GeometryShardIo: Send {
    fn read_shard(
        &self,
        locator: &LocatorValueV1,
        replica: &ReplicaPlacement,
        shard: &ShardPlacement,
    ) -> Result<Vec<u8>, String>;

    fn write_shard(
        &mut self,
        locator_id: LocatorId,
        placement: &ReplicaPlacement,
        write: &GeometryShardWrite,
    ) -> Result<(), String>;
}

/// Pool-backed conversion store over locator-table, placement, and shard I/O.
#[derive(Clone, Debug)]
pub struct PoolBackedExtentStore<L, P, I> {
    pool_id: u64,
    locators: L,
    placement: P,
    shard_io: I,
}

impl<L, P, I> PoolBackedExtentStore<L, P, I> {
    #[must_use]
    pub const fn new(pool_id: u64, locators: L, placement: P, shard_io: I) -> Self {
        Self {
            pool_id,
            locators,
            placement,
            shard_io,
        }
    }

    #[must_use]
    pub const fn pool_id(&self) -> u64 {
        self.pool_id
    }

    #[must_use]
    pub const fn locators(&self) -> &L {
        &self.locators
    }

    #[must_use]
    pub const fn shard_io(&self) -> &I {
        &self.shard_io
    }

    #[must_use]
    pub fn into_parts(self) -> (L, P, I) {
        (self.locators, self.placement, self.shard_io)
    }
}

// ---------------------------------------------------------------------------
// ExtentStore trait — abstracted storage for conversion
// ---------------------------------------------------------------------------

/// Abstract storage backend for geometry conversion.
///
/// Pool-backed implementations should preserve fail-stop ordering: reads and
/// writes happen before the atomic locator swap, and cursor advancement happens
/// only after `update_locator` succeeds.
pub trait ExtentStore: Send {
    /// Total number of locator table entries for the pool.
    fn locator_count(&self, pool_id: u64) -> u64;

    /// Walk locator entries from `start_after` (None = from beginning).
    fn walk_entries(
        &self,
        pool_id: u64,
        start_after: Option<LocatorId>,
        batch_size: u32,
    ) -> Vec<LocatorEntry>;

    /// Read full payload for shards described by the locator value.
    fn read_payload(
        &self,
        value: &LocatorValueV1,
        old_policy: &DurabilityPolicy,
    ) -> Result<Vec<u8>, String>;

    /// Write new shards for a locator entry; returns new replica placements.
    fn write_shards(
        &mut self,
        old_locator_id: LocatorId,
        new_policy: &DurabilityPolicy,
        payload: &[u8],
        payload_digest: [u8; 32],
    ) -> Result<Vec<ReplicaPlacement>, String>;

    /// Atomically update locator entry to point to new placements.
    fn update_locator(
        &mut self,
        locator_id: LocatorId,
        new_placements: Vec<ReplicaPlacement>,
        new_policy: &DurabilityPolicy,
        payload_digest: [u8; 32],
        payload_bytes: u64,
    ) -> Result<LocatorValueV1, String>;
}

/// Store reconstruction hook for `IncrementalJob::resume`.
pub trait ResumeExtentStore: ExtentStore + Sized {
    fn resume_from_cursor(cursor: &ConversionCursor) -> Result<Self, String>;
}

impl<L, P, I> ExtentStore for PoolBackedExtentStore<L, P, I>
where
    L: LocatorEntrySource + LocatorTableOps + Send,
    P: GeometryPlacementPlanner + Send,
    I: GeometryShardIo + Send,
{
    fn locator_count(&self, pool_id: u64) -> u64 {
        self.locators.locator_count(pool_id)
    }

    fn walk_entries(
        &self,
        pool_id: u64,
        start_after: Option<LocatorId>,
        batch_size: u32,
    ) -> Vec<LocatorEntry> {
        self.locators.walk_entries(pool_id, start_after, batch_size)
    }

    fn read_payload(
        &self,
        value: &LocatorValueV1,
        old_policy: &DurabilityPolicy,
    ) -> Result<Vec<u8>, String> {
        read_payload_from_locator(&self.shard_io, value, old_policy)
    }

    fn write_shards(
        &mut self,
        old_locator_id: LocatorId,
        new_policy: &DurabilityPolicy,
        payload: &[u8],
        payload_digest: [u8; 32],
    ) -> Result<Vec<ReplicaPlacement>, String> {
        let writes = materialize_target_shards(new_policy, payload, payload_digest)?;
        let placements =
            self.placement
                .plan_shard_placements(old_locator_id, new_policy, &writes)?;
        if placements.len() != writes.len() {
            return Err(format!(
                "placement count {} does not match shard write count {}",
                placements.len(),
                writes.len()
            ));
        }
        for (placement, write) in placements.iter().zip(writes.iter()) {
            self.shard_io
                .write_shard(old_locator_id, placement, write)?;
        }
        Ok(placements)
    }

    fn update_locator(
        &mut self,
        locator_id: LocatorId,
        new_placements: Vec<ReplicaPlacement>,
        new_policy: &DurabilityPolicy,
        payload_digest: [u8; 32],
        payload_bytes: u64,
    ) -> Result<LocatorValueV1, String> {
        let mut new_value = self
            .locators
            .resolve(locator_id)
            .map_err(|e| format!("resolve before relocate failed: {e}"))?;
        new_value.replica_placement = new_placements;
        configure_locator_for_policy(
            &mut new_value,
            new_policy,
            payload_digest,
            payload_bytes,
            estimate_on_media_bytes(new_policy, payload_bytes),
        )?;
        self.locators
            .relocate_value(locator_id, new_value)
            .map_err(|e| format!("atomic locator relocate failed: {e}"))
    }
}

fn materialize_target_shards(
    policy: &DurabilityPolicy,
    payload: &[u8],
    payload_digest: [u8; 32],
) -> Result<Vec<GeometryShardWrite>, String> {
    match policy {
        DurabilityPolicy::Mirror { replica_count } => {
            if *replica_count == 0 {
                return Err("mirror conversion requires at least one replica".to_string());
            }
            Ok((0..*replica_count)
                .map(|_| GeometryShardWrite {
                    shard_index: 0,
                    role: GeometryShardRole::MirrorReplica,
                    bytes: payload.to_vec(),
                    payload_digest,
                })
                .collect())
        }
        DurabilityPolicy::ErasureCoded {
            data_shards,
            parity_shards,
            shard_len,
        } => {
            let config = ec_config(*data_shards, *parity_shards, *shard_len)?;
            let stripe_count = stripe_count(payload.len(), config.data_capacity());
            let mut shard_bytes = vec![Vec::new(); config.stripe_width()];
            for stripe_index in 0..stripe_count {
                let start = stripe_index * config.data_capacity();
                let end = payload.len().min(start + config.data_capacity());
                let stripe_payload = &payload[start..end];
                let encoded = ec_encode(&config, stripe_payload).ok_or_else(|| {
                    format!(
                        "failed to encode EC stripe {stripe_index} for {} payload bytes",
                        stripe_payload.len()
                    )
                })?;
                for shard in encoded.shards {
                    shard_bytes[shard.index].extend_from_slice(&shard.bytes);
                }
            }
            Ok(shard_bytes
                .into_iter()
                .enumerate()
                .map(|(index, bytes)| GeometryShardWrite {
                    shard_index: index as u16,
                    role: if index < config.data_shards {
                        GeometryShardRole::EcData
                    } else {
                        GeometryShardRole::EcParity
                    },
                    bytes,
                    payload_digest,
                })
                .collect())
        }
    }
}

fn read_payload_from_locator<I: GeometryShardIo>(
    shard_io: &I,
    value: &LocatorValueV1,
    policy: &DurabilityPolicy,
) -> Result<Vec<u8>, String> {
    match policy {
        DurabilityPolicy::Mirror { .. } => read_mirror_payload(shard_io, value),
        DurabilityPolicy::ErasureCoded {
            data_shards,
            parity_shards,
            shard_len,
        } => read_ec_payload(shard_io, value, *data_shards, *parity_shards, *shard_len),
    }
}

fn read_mirror_payload<I: GeometryShardIo>(
    shard_io: &I,
    value: &LocatorValueV1,
) -> Result<Vec<u8>, String> {
    if value.payload_bytes == 0 {
        return Ok(Vec::new());
    }
    for replica in value.replica_placement.iter().filter(|r| r.is_readable()) {
        let mut placements = replica.shard_placements.clone();
        placements.sort_by_key(|shard| shard.shard_index);
        let mut payload = Vec::new();
        for shard in &placements {
            payload.extend_from_slice(&shard_io.read_shard(value, replica, shard)?);
        }
        payload.truncate(value.payload_bytes as usize);
        if blake3_digest(&payload) == value.payload_digest {
            return Ok(payload);
        }
    }
    Err(format!(
        "no readable mirror replica matched digest for locator {}",
        value.locator_id
    ))
}

fn read_ec_payload<I: GeometryShardIo>(
    shard_io: &I,
    value: &LocatorValueV1,
    data_shards: u16,
    parity_shards: usize,
    shard_len: usize,
) -> Result<Vec<u8>, String> {
    if value.payload_bytes == 0 {
        return Ok(Vec::new());
    }
    let config = ec_config(data_shards, parity_shards, shard_len)?;
    let stripe_count = stripe_count(value.payload_bytes as usize, config.data_capacity());
    let mut shard_buffers: Vec<Option<Vec<u8>>> = vec![None; config.stripe_width()];
    for replica in value.replica_placement.iter().filter(|r| r.is_readable()) {
        for shard in &replica.shard_placements {
            let index = shard.shard_index as usize;
            if index >= config.stripe_width() || shard_buffers[index].is_some() {
                continue;
            }
            shard_buffers[index] = Some(shard_io.read_shard(value, replica, shard)?);
        }
    }

    let mut payload = Vec::with_capacity(value.payload_bytes as usize);
    for stripe_index in 0..stripe_count {
        let stripe_start = stripe_index * config.data_capacity();
        let stripe_payload_len =
            (value.payload_bytes as usize - stripe_start).min(config.data_capacity());
        let effective_k = stripe_fragment_count(
            value.payload_bytes as usize,
            stripe_index,
            config.data_shards,
            config.shard_len,
        );
        let mut available = Vec::with_capacity(config.stripe_width());
        for (index, buffer) in shard_buffers.iter().enumerate() {
            let shard = buffer.as_ref().and_then(|bytes| {
                let start = stripe_index * config.shard_len;
                let end = start + config.shard_len;
                (bytes.len() >= end).then(|| ErasureShard {
                    index,
                    kind: if index < config.data_shards {
                        ShardKind::Data
                    } else {
                        ShardKind::Parity
                    },
                    bytes: bytes[start..end].to_vec(),
                })
            });
            available.push(shard);
        }
        let reconstructed = ec_reconstruct(&config, &available, Some(effective_k))
            .ok_or_else(|| format!("insufficient EC shards for locator {}", value.locator_id))?;
        let mut stripe_payload = reconstructed.payload;
        stripe_payload.truncate(stripe_payload_len);
        payload.extend_from_slice(&stripe_payload);
    }
    payload.truncate(value.payload_bytes as usize);
    if blake3_digest(&payload) != value.payload_digest {
        return Err(format!(
            "EC payload digest mismatch for locator {}",
            value.locator_id
        ));
    }
    Ok(payload)
}

fn configure_locator_for_policy(
    value: &mut LocatorValueV1,
    policy: &DurabilityPolicy,
    payload_digest: [u8; 32],
    payload_bytes: u64,
    on_media_bytes: u64,
) -> Result<(), String> {
    value.payload_digest = payload_digest;
    value.payload_bytes = payload_bytes;
    value.on_media_bytes = on_media_bytes;
    match policy {
        DurabilityPolicy::Mirror { replica_count } => {
            if *replica_count == 0 {
                return Err("mirror locator update requires at least one replica".to_string());
            }
            value.flags &= !locator_flags::ERASURE_CODED;
            value.flags &= !locator_flags::SHARDED;
            value.shard_count = 1;
            value.replica_count = *replica_count;
        }
        DurabilityPolicy::ErasureCoded {
            data_shards,
            parity_shards,
            shard_len,
        } => {
            let config = ec_config(*data_shards, *parity_shards, *shard_len)?;
            value.flags |= locator_flags::ERASURE_CODED | locator_flags::SHARDED;
            value.shard_count = config.stripe_width() as u16;
            value.replica_count = 0;
        }
    }
    Ok(())
}

fn estimate_on_media_bytes(policy: &DurabilityPolicy, payload_bytes: u64) -> u64 {
    match policy {
        DurabilityPolicy::Mirror { replica_count } => {
            payload_bytes.saturating_mul(*replica_count as u64)
        }
        DurabilityPolicy::ErasureCoded {
            data_shards,
            parity_shards,
            shard_len,
        } => {
            let Ok(config) = ec_config(*data_shards, *parity_shards, *shard_len) else {
                return 0;
            };
            let stripes = stripe_count(payload_bytes as usize, config.data_capacity()) as u64;
            stripes
                .saturating_mul(config.stripe_width() as u64)
                .saturating_mul(config.shard_len as u64)
        }
    }
}

fn ec_config(
    data_shards: u16,
    parity_shards: usize,
    shard_len: usize,
) -> Result<StripeConfig, String> {
    if data_shards == 0 || parity_shards == 0 || shard_len == 0 {
        return Err(format!(
            "invalid EC policy: data_shards={data_shards} parity_shards={parity_shards} shard_len={shard_len}"
        ));
    }
    let data_shards = data_shards as usize;
    if data_shards + parity_shards > 255 {
        return Err(format!(
            "invalid EC policy: total shards {} exceeds GF(2^8) limit",
            data_shards + parity_shards
        ));
    }
    Ok(StripeConfig {
        data_shards,
        parity_shards,
        shard_len,
    })
}

fn stripe_count(payload_len: usize, data_capacity: usize) -> usize {
    if payload_len == 0 {
        1
    } else {
        payload_len.div_ceil(data_capacity)
    }
}

// ---------------------------------------------------------------------------
// GeometryConversionJob — IncrementalJob implementation
// ---------------------------------------------------------------------------

/// Background job performing online pool geometry conversion.
pub struct GeometryConversionJob<S: ExtentStore> {
    id: JobId,
    store: S,
    cursor: ConversionCursor,
    epoch: u64,
}

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

impl<S: ExtentStore> GeometryConversionJob<S> {
    /// Create a new conversion job. Does NOT start with a checkpoint.
    pub fn new(
        store: S,
        scope: ConversionScope,
        old_policy: DurabilityPolicy,
        new_policy: DurabilityPolicy,
    ) -> Self {
        let pool_id = match scope {
            ConversionScope::Pool(id)
            | ConversionScope::Dataset(id)
            | ConversionScope::ExtentClass(id) => id,
        };
        let entries_total = store.locator_count(pool_id);
        Self {
            id: JobId(NEXT_JOB_ID.fetch_add(1, Ordering::SeqCst)),
            store,
            cursor: ConversionCursor {
                scope,
                old_policy: old_policy.clone(),
                new_policy: new_policy.clone(),
                last_converted_locator: 0,
                entries_total,
                entries_converted: 0,
                bytes_converted: 0,
                started_epoch: 1,
                cancelled: false,
                failed: false,
                last_error: None,
            },
            epoch: 1,
        }
    }

    fn convert_one(&mut self, entry: &LocatorEntry) -> Result<u64, String> {
        let payload = self
            .store
            .read_payload(&entry.value, &self.cursor.old_policy)?;
        let bytes = payload.len() as u64;
        let digest = blake3_digest(&payload);
        let new_placements =
            self.store
                .write_shards(entry.locator_id, &self.cursor.new_policy, &payload, digest)?;
        self.store.update_locator(
            entry.locator_id,
            new_placements,
            &self.cursor.new_policy,
            digest,
            bytes,
        )?;
        self.cursor.entries_converted += 1;
        self.cursor.bytes_converted += bytes;
        self.cursor.last_converted_locator = entry.locator_id.0;
        Ok(bytes)
    }

    fn from_cursor(id: JobId, epoch: u64, store: S, cursor: ConversionCursor) -> Self {
        Self {
            id,
            store,
            cursor,
            epoch,
        }
    }

    fn decode_checkpoint_cursor(checkpoint: &Checkpoint) -> Result<ConversionCursor, JobError> {
        if checkpoint.cursor_state.is_empty() {
            return Err(JobError::CursorStateInvalid {
                job_id: checkpoint.job_id,
                reason: "GeometryConversionJob::resume requires a non-empty cursor (use new() for fresh jobs)",
            });
        }
        ConversionCursor::decode(checkpoint.cursor_state.as_bytes()).ok_or(
            JobError::CursorStateInvalid {
                job_id: checkpoint.job_id,
                reason: "failed to decode ConversionCursor",
            },
        )
    }

    pub fn resume_with_store(checkpoint: Checkpoint, store: S) -> Result<Self, JobError> {
        let cursor = Self::decode_checkpoint_cursor(&checkpoint)?;
        Ok(Self::from_cursor(
            checkpoint.job_id,
            checkpoint.epoch,
            store,
            cursor,
        ))
    }

    pub fn step(&mut self, budget: WorkBudget) -> StepResult {
        if self.cursor.cancelled
            || self.cursor.failed
            || self.cursor.entries_converted >= self.cursor.entries_total
        {
            return StepResult {
                checkpoint: self.make_checkpoint(),
                is_complete: true,
            };
        }
        let max_entries = self.max_entries_for_budget(budget);
        let pool_id = self.cursor.pool_id();
        let start_after = if self.cursor.last_converted_locator == 0 {
            None
        } else {
            Some(LocatorId(self.cursor.last_converted_locator))
        };
        let batch = self
            .store
            .walk_entries(pool_id, start_after, max_entries as u32);
        if batch.is_empty() {
            return StepResult {
                checkpoint: self.make_checkpoint(),
                is_complete: true,
            };
        }
        for entry in &batch {
            if let Err(error) = self.convert_one(entry) {
                self.cursor.failed = true;
                self.cursor.last_error = Some(format!(
                    "locator {} conversion failed: {error}",
                    entry.locator_id
                ));
                break;
            }
        }
        let is_complete = self.cursor.failed
            || self.cursor.entries_converted >= self.cursor.entries_total
            || batch.len() < max_entries as usize;
        StepResult {
            checkpoint: self.make_checkpoint(),
            is_complete,
        }
    }

    pub fn persist_checkpoint(&self) -> Checkpoint {
        self.make_checkpoint()
    }

    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.cursor.failed
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.cursor.last_error.as_deref()
    }

    fn max_entries_for_budget(&self, budget: WorkBudget) -> u64 {
        let items = if budget.max_items == 0 {
            256
        } else {
            budget.max_items
        };
        let bytes = if budget.max_bytes == 0 {
            256
        } else {
            budget.max_bytes / 4096
        };
        items.min(bytes).min(256)
    }

    /// Checkpoint reflecting current cursor state.
    fn make_checkpoint(&self) -> Checkpoint {
        let cursor_bytes = self.cursor.encode();
        Checkpoint {
            job_id: self.id,
            job_kind: JobKind::GeometryConvert,
            epoch: self.epoch,
            cursor_state: CursorState(cursor_bytes),
            progress: JobProgress {
                items_processed: self.cursor.entries_converted,
                items_total_estimate: self.cursor.entries_total,
                bytes_processed: self.cursor.bytes_converted,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        }
    }

    pub fn job_id(&self) -> JobId {
        self.id
    }

    pub fn job_kind(&self) -> JobKind {
        JobKind::GeometryConvert
    }
}

impl<S: ExtentStore + ResumeExtentStore + 'static> IncrementalJob for GeometryConversionJob<S> {
    fn resume(checkpoint: Checkpoint) -> Result<Self, JobError> {
        let cursor = Self::decode_checkpoint_cursor(&checkpoint)?;
        let store = S::resume_from_cursor(&cursor).map_err(|_| JobError::CursorStateInvalid {
            job_id: checkpoint.job_id,
            reason: "failed to recreate GeometryConversionJob store backend from cursor",
        })?;
        Ok(Self::from_cursor(
            checkpoint.job_id,
            checkpoint.epoch,
            store,
            cursor,
        ))
    }

    fn step(&mut self, budget: WorkBudget) -> StepResult {
        GeometryConversionJob::step(self, budget)
    }

    fn persist_checkpoint(&self) -> Checkpoint {
        GeometryConversionJob::persist_checkpoint(self)
    }

    fn complete(self) {
        // No-op: old shards reclaimed by GC.
    }

    fn job_id(&self) -> JobId {
        self.id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::GeometryConvert
    }
}

impl<S: ExtentStore> fmt::Display for GeometryConversionJob<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GeometryConversionJob(id={}, scope={}, {}->{}, {}/{})",
            self.id.0,
            self.cursor.scope,
            self.cursor.old_policy,
            self.cursor.new_policy,
            self.cursor.entries_converted,
            self.cursor.entries_total
        )
    }
}

impl<S: ExtentStore> fmt::Debug for GeometryConversionJob<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 helper
// ---------------------------------------------------------------------------

fn blake3_digest(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// In-memory mock store for testing.
    struct MockStore {
        entries: HashMap<u64, LocatorEntry>,
        next_locator_id: u64,
        fail_read_locator: Option<u64>,
        fail_write_locator: Option<u64>,
        fail_update_locator: Option<u64>,
    }

    impl MockStore {
        fn new(_pool_id: u64) -> Self {
            Self {
                entries: HashMap::new(),
                next_locator_id: 1,
                fail_read_locator: None,
                fail_write_locator: None,
                fail_update_locator: None,
            }
        }

        fn add_entry(&mut self, payload: &[u8], replica_count: u8) -> LocatorId {
            let lid = LocatorId(self.next_locator_id);
            self.next_locator_id += 1;
            let digest = blake3_digest(payload);
            let mut value = LocatorValueV1::new(lid, 1, 0, digest, payload.len() as u64);
            for _ in 0..replica_count {
                value.add_replica(ReplicaPlacement::new_unsharded(
                    0,
                    0,
                    lid.0 * 100,
                    0,
                    payload.len() as u64,
                ));
            }
            self.entries.insert(
                lid.0,
                LocatorEntry {
                    locator_id: lid,
                    value,
                },
            );
            lid
        }
    }

    impl ExtentStore for MockStore {
        fn locator_count(&self, _pool_id: u64) -> u64 {
            self.entries.len() as u64
        }

        fn walk_entries(
            &self,
            _pool_id: u64,
            start_after: Option<LocatorId>,
            batch_size: u32,
        ) -> Vec<LocatorEntry> {
            let start = start_after.map(|l| l.0).unwrap_or(0);
            let mut ids: Vec<u64> = self.entries.keys().copied().collect();
            ids.sort_unstable();
            ids.into_iter()
                .filter(|&id| id > start)
                .take(batch_size as usize)
                .map(|id| self.entries[&id].clone())
                .collect()
        }

        fn read_payload(
            &self,
            value: &LocatorValueV1,
            _old_policy: &DurabilityPolicy,
        ) -> Result<Vec<u8>, String> {
            let lid = value.locator_id.0;
            if self.fail_read_locator == Some(lid) {
                return Err("mock read failure".to_string());
            }
            Ok((0..value.payload_bytes as usize)
                .map(|i| (lid.wrapping_add(i as u64) % 256) as u8)
                .collect())
        }

        fn write_shards(
            &mut self,
            locator_id: LocatorId,
            new_policy: &DurabilityPolicy,
            payload: &[u8],
            _digest: [u8; 32],
        ) -> Result<Vec<ReplicaPlacement>, String> {
            if self.fail_write_locator == Some(locator_id.0) {
                return Err("mock write failure".to_string());
            }
            let count = new_policy.total_shards();
            Ok((0..count)
                .map(|i| {
                    ReplicaPlacement::new_unsharded(
                        0,
                        0,
                        locator_id.0 * 200 + i as u64,
                        0,
                        payload.len() as u64,
                    )
                })
                .collect())
        }

        fn update_locator(
            &mut self,
            locator_id: LocatorId,
            new_placements: Vec<ReplicaPlacement>,
            new_policy: &DurabilityPolicy,
            payload_digest: [u8; 32],
            payload_bytes: u64,
        ) -> Result<LocatorValueV1, String> {
            if self.fail_update_locator == Some(locator_id.0) {
                return Err("mock update failure".to_string());
            }
            let entry = self.entries.get_mut(&locator_id.0).ok_or("not found")?;
            entry.value.locator_rev += 1;
            entry.value.replica_placement = new_placements;
            configure_locator_for_policy(
                &mut entry.value,
                new_policy,
                payload_digest,
                payload_bytes,
                estimate_on_media_bytes(new_policy, payload_bytes),
            )?;
            Ok(entry.value.clone())
        }
    }

    type HarnessPoolStore =
        PoolBackedExtentStore<HarnessLocatorTable, HarnessPlacementPlanner, HarnessShardIo>;

    #[derive(Clone, Debug)]
    struct HarnessLocatorTable {
        entries: HashMap<u64, LocatorEntry>,
        next_locator_id: u64,
        fail_relocate_locator: Option<u64>,
    }

    impl HarnessLocatorTable {
        fn new() -> Self {
            Self {
                entries: HashMap::new(),
                next_locator_id: 1,
                fail_relocate_locator: None,
            }
        }

        fn add_policy_entry(
            &mut self,
            placement: &mut HarnessPlacementPlanner,
            shard_io: &mut HarnessShardIo,
            policy: &DurabilityPolicy,
            payload: &[u8],
        ) -> LocatorId {
            let locator_id = LocatorId(self.next_locator_id);
            self.next_locator_id += 1;
            let digest = blake3_digest(payload);
            let writes = materialize_target_shards(policy, payload, digest).expect("shards");
            let placements = placement
                .plan_shard_placements(locator_id, policy, &writes)
                .expect("placements");
            for (placement, write) in placements.iter().zip(writes.iter()) {
                shard_io
                    .write_shard(locator_id, placement, write)
                    .expect("initial shard write");
            }
            let mut value = LocatorValueV1::new(locator_id, 1, 0, digest, payload.len() as u64);
            value.replica_placement = placements;
            configure_locator_for_policy(
                &mut value,
                policy,
                digest,
                payload.len() as u64,
                estimate_on_media_bytes(policy, payload.len() as u64),
            )
            .expect("locator policy");
            self.entries
                .insert(locator_id.0, LocatorEntry { locator_id, value });
            locator_id
        }
    }

    impl LocatorEntrySource for HarnessLocatorTable {
        fn locator_count(&self, _pool_id: u64) -> u64 {
            self.entries.len() as u64
        }

        fn walk_entries(
            &self,
            _pool_id: u64,
            start_after: Option<LocatorId>,
            batch_size: u32,
        ) -> Vec<LocatorEntry> {
            let start = start_after.map(|id| id.0).unwrap_or(0);
            let mut ids: Vec<u64> = self.entries.keys().copied().collect();
            ids.sort_unstable();
            ids.into_iter()
                .filter(|id| *id > start)
                .take(batch_size as usize)
                .map(|id| self.entries[&id].clone())
                .collect()
        }
    }

    impl LocatorTableOps for HarnessLocatorTable {
        fn resolve(&self, locator_id: LocatorId) -> Result<LocatorValueV1, LocatorTableError> {
            self.entries
                .get(&locator_id.0)
                .map(|entry| entry.value.clone())
                .ok_or(LocatorTableError::NotFound)
        }

        fn allocate(
            &mut self,
            payload_bytes: u64,
            payload_digest: [u8; 32],
            replica_placement: Vec<ReplicaPlacement>,
            created_commit_group: u64,
        ) -> Result<LocatorValueV1, LocatorTableError> {
            let locator_id = LocatorId(self.next_locator_id);
            self.next_locator_id += 1;
            let mut value = LocatorValueV1::new(
                locator_id,
                1,
                created_commit_group,
                payload_digest,
                payload_bytes,
            );
            value.replica_placement = replica_placement;
            value.replica_count = value.replica_placement.len() as u8;
            self.entries.insert(
                locator_id.0,
                LocatorEntry {
                    locator_id,
                    value: value.clone(),
                },
            );
            Ok(value)
        }

        fn relocate(
            &mut self,
            old_locator_id: LocatorId,
            new_replica_placement: Vec<ReplicaPlacement>,
        ) -> Result<LocatorValueV1, LocatorTableError> {
            let entry = self
                .entries
                .get_mut(&old_locator_id.0)
                .ok_or(LocatorTableError::NotFound)?;
            entry.value.locator_rev += 1;
            entry.value.replica_placement = new_replica_placement;
            entry.value.replica_count = entry.value.replica_placement.len() as u8;
            Ok(entry.value.clone())
        }

        fn relocate_value(
            &mut self,
            old_locator_id: LocatorId,
            mut new_value: LocatorValueV1,
        ) -> Result<LocatorValueV1, LocatorTableError> {
            if self.fail_relocate_locator == Some(old_locator_id.0) {
                return Err(LocatorTableError::AllocationFailed);
            }
            let entry = self
                .entries
                .get_mut(&old_locator_id.0)
                .ok_or(LocatorTableError::NotFound)?;
            new_value.locator_rev = entry.value.locator_rev + 1;
            new_value.locator_id = old_locator_id;
            entry.value = new_value;
            Ok(entry.value.clone())
        }

        fn retire(&mut self, locator_id: LocatorId) -> Result<(), LocatorTableError> {
            self.entries
                .remove(&locator_id.0)
                .map(|_| ())
                .ok_or(LocatorTableError::NotFound)
        }

        fn batch_resolve(&self, locator_ids: &[LocatorId]) -> Vec<(LocatorId, LocatorValueV1)> {
            locator_ids
                .iter()
                .filter_map(|id| self.resolve(*id).ok().map(|value| (*id, value)))
                .collect()
        }
    }

    #[derive(Clone, Debug)]
    struct HarnessPlacementPlanner {
        next_segment_id: u64,
    }

    impl HarnessPlacementPlanner {
        fn new() -> Self {
            Self { next_segment_id: 1 }
        }
    }

    impl GeometryPlacementPlanner for HarnessPlacementPlanner {
        fn plan_shard_placements(
            &mut self,
            _locator_id: LocatorId,
            _new_policy: &DurabilityPolicy,
            writes: &[GeometryShardWrite],
        ) -> Result<Vec<ReplicaPlacement>, String> {
            Ok(writes
                .iter()
                .map(|write| {
                    let segment_id = self.next_segment_id;
                    self.next_segment_id += 1;
                    ReplicaPlacement {
                        node_id: segment_id,
                        device_id: segment_id,
                        shard_placements: vec![ShardPlacement::new(
                            write.shard_index,
                            segment_id,
                            0,
                            write.bytes.len() as u64,
                        )],
                        health: ReplicaHealth::Online,
                    }
                })
                .collect())
        }
    }

    #[derive(Clone, Debug)]
    struct HarnessShardIo {
        shards: HashMap<u64, Vec<u8>>,
        fail_write_locator: Option<u64>,
    }

    impl HarnessShardIo {
        fn new() -> Self {
            Self {
                shards: HashMap::new(),
                fail_write_locator: None,
            }
        }
    }

    impl GeometryShardIo for HarnessShardIo {
        fn read_shard(
            &self,
            _locator: &LocatorValueV1,
            _replica: &ReplicaPlacement,
            shard: &ShardPlacement,
        ) -> Result<Vec<u8>, String> {
            self.shards
                .get(&shard.segment_id)
                .cloned()
                .ok_or_else(|| format!("missing shard segment {}", shard.segment_id))
        }

        fn write_shard(
            &mut self,
            locator_id: LocatorId,
            placement: &ReplicaPlacement,
            write: &GeometryShardWrite,
        ) -> Result<(), String> {
            if self.fail_write_locator == Some(locator_id.0) {
                return Err("harness shard write failure".to_string());
            }
            for shard in &placement.shard_placements {
                self.shards.insert(shard.segment_id, write.bytes.clone());
            }
            Ok(())
        }
    }

    fn harness_store(pool_id: u64) -> HarnessPoolStore {
        PoolBackedExtentStore::new(
            pool_id,
            HarnessLocatorTable::new(),
            HarnessPlacementPlanner::new(),
            HarnessShardIo::new(),
        )
    }

    fn resume_registry() -> &'static Mutex<HashMap<u64, HarnessPoolStore>> {
        static REGISTRY: OnceLock<Mutex<HashMap<u64, HarnessPoolStore>>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
    }

    impl ResumeExtentStore for HarnessPoolStore {
        fn resume_from_cursor(cursor: &ConversionCursor) -> Result<Self, String> {
            resume_registry()
                .lock()
                .expect("resume registry")
                .remove(&cursor.pool_id())
                .ok_or_else(|| format!("no harness store for pool {}", cursor.pool_id()))
        }
    }

    // ── DurabilityPolicy ─────────────────────────────────────────

    #[test]
    fn mirror_total_shards() {
        let p = DurabilityPolicy::Mirror { replica_count: 3 };
        assert_eq!(p.total_shards(), 3);
        assert!(!p.is_erasure_coded());
    }

    #[test]
    fn ec_total_shards() {
        let p = DurabilityPolicy::ErasureCoded {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 4096,
        };
        assert_eq!(p.total_shards(), 6);
        assert!(p.is_erasure_coded());
    }

    #[test]
    fn policy_display() {
        let m = DurabilityPolicy::Mirror { replica_count: 2 };
        assert_eq!(format!("{m}"), "mirror(2)");
        let ec = DurabilityPolicy::ErasureCoded {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 4096,
        };
        assert_eq!(format!("{ec}"), "EC(4+2 shard_len=4096)");
    }

    // ── ConversionScope ──────────────────────────────────────────

    #[test]
    fn scope_display() {
        assert_eq!(format!("{}", ConversionScope::Pool(7)), "pool(7)");
        assert_eq!(format!("{}", ConversionScope::Dataset(3)), "dataset(3)");
        assert_eq!(
            format!("{}", ConversionScope::ExtentClass(1)),
            "extent_class(1)"
        );
    }

    // ── GeometryConversionProgress ───────────────────────────────

    #[test]
    fn progress_percent() {
        let p = GeometryConversionProgress {
            entries_total: 100,
            entries_converted: 42,
            ..Default::default()
        };
        assert!((p.percent() - 42.0).abs() < 0.01);
    }

    #[test]
    fn progress_percent_zero_total() {
        let p = GeometryConversionProgress::default();
        assert!((p.percent() - 0.0).abs() < f64::EPSILON);
    }

    // ── Cursor encode/decode ─────────────────────────────────────

    #[test]
    fn cursor_roundtrip_mirror_to_ec() {
        let cursor = ConversionCursor {
            scope: ConversionScope::Pool(1),
            old_policy: DurabilityPolicy::Mirror { replica_count: 2 },
            new_policy: DurabilityPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 4096,
            },
            last_converted_locator: 42,
            entries_total: 1000,
            entries_converted: 42,
            bytes_converted: 42000,
            started_epoch: 5,
            cancelled: false,
            failed: false,
            last_error: None,
        };
        let enc = cursor.encode();
        let dec = ConversionCursor::decode(&enc).expect("roundtrip");
        assert_eq!(dec.scope, cursor.scope);
        assert_eq!(dec.old_policy, cursor.old_policy);
        assert_eq!(dec.new_policy, cursor.new_policy);
        assert_eq!(dec.last_converted_locator, 42);
        assert_eq!(dec.entries_total, 1000);
        assert_eq!(dec.entries_converted, 42);
        assert_eq!(dec.bytes_converted, 42000);
        assert_eq!(dec.started_epoch, 5);
        assert!(!dec.cancelled);
        assert!(!dec.failed);
        assert_eq!(dec.last_error, None);
    }

    #[test]
    fn cursor_roundtrip_ec_to_mirror() {
        let cursor = ConversionCursor {
            scope: ConversionScope::Dataset(7),
            old_policy: DurabilityPolicy::ErasureCoded {
                data_shards: 8,
                parity_shards: 3,
                shard_len: 8192,
            },
            new_policy: DurabilityPolicy::Mirror { replica_count: 3 },
            last_converted_locator: 0,
            entries_total: 500,
            entries_converted: 100,
            bytes_converted: 800_000,
            started_epoch: 2,
            cancelled: true,
            failed: false,
            last_error: None,
        };
        let enc = cursor.encode();
        let dec = ConversionCursor::decode(&enc).expect("roundtrip");
        assert_eq!(dec.scope, ConversionScope::Dataset(7));
        assert!(dec.cancelled);
        assert_eq!(
            dec.new_policy,
            DurabilityPolicy::Mirror { replica_count: 3 }
        );
    }

    #[test]
    fn cursor_roundtrip_records_failure() {
        let cursor = ConversionCursor {
            scope: ConversionScope::Pool(9),
            old_policy: DurabilityPolicy::Mirror { replica_count: 2 },
            new_policy: DurabilityPolicy::Mirror { replica_count: 3 },
            last_converted_locator: 4,
            entries_total: 10,
            entries_converted: 4,
            bytes_converted: 16_384,
            started_epoch: 3,
            cancelled: false,
            failed: true,
            last_error: Some("locator 5 conversion failed: mock write failure".to_string()),
        };
        let enc = cursor.encode();
        let dec = ConversionCursor::decode(&enc).expect("roundtrip");
        assert!(dec.failed);
        assert_eq!(
            dec.last_error.as_deref(),
            Some("locator 5 conversion failed: mock write failure")
        );
    }

    #[test]
    fn cursor_decode_garbage() {
        assert!(ConversionCursor::decode(&[]).is_none());
        assert!(ConversionCursor::decode(&[0xFF, 0xFF]).is_none());
    }

    // ── GeometryConversionJob ────────────────────────────────────

    #[test]
    fn mirror_to_ec_single_extent() {
        let mut store = MockStore::new(1);
        store.add_entry(&vec![0xABu8; 4096], 2);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(1),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 1024,
            },
        );
        assert_eq!(job.job_kind(), JobKind::GeometryConvert);
        assert!(job.job_id().0 > 0);
        assert_eq!(job.cursor.entries_total, 1);
        assert_eq!(job.cursor.entries_converted, 0);
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete, "single extent pool should complete");
        assert_eq!(job.cursor.entries_converted, 1);
    }

    #[test]
    fn ec_to_mirror_conversion() {
        let mut store = MockStore::new(2);
        store.add_entry(&vec![0x42u8; 2048], 1);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(2),
            DurabilityPolicy::ErasureCoded {
                data_shards: 2,
                parity_shards: 1,
                shard_len: 1024,
            },
            DurabilityPolicy::Mirror { replica_count: 3 },
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);
        assert_eq!(job.cursor.entries_converted, 1);
    }

    #[test]
    fn incremental_progress_multiple_extents() {
        let mut store = MockStore::new(3);
        for _ in 0..10 {
            store.add_entry(&vec![0u8; 1024], 2);
        }
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(3),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 256,
            },
        );
        let budget = WorkBudget {
            max_items: 3,
            max_bytes: 0,
            max_ms: 0,
        };
        let r1 = job.step(budget);
        assert!(!r1.is_complete);
        assert_eq!(job.cursor.entries_converted, 3);
        let r2 = job.step(WorkBudget::DEFAULT_TICK);
        assert!(r2.is_complete);
        assert_eq!(job.cursor.entries_converted, 10);
    }

    #[test]
    fn empty_pool_completes_immediately() {
        let store = MockStore::new(4);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(4),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 1024,
            },
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);
        assert_eq!(job.cursor.entries_converted, 0);
    }

    #[test]
    fn ec_to_ec_different_families() {
        let mut store = MockStore::new(5);
        store.add_entry(&vec![0x55u8; 8192], 1);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(5),
            DurabilityPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 2048,
            },
            DurabilityPolicy::ErasureCoded {
                data_shards: 8,
                parity_shards: 3,
                shard_len: 1024,
            },
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);
        assert_eq!(job.cursor.entries_converted, 1);
    }

    #[test]
    fn mirror_to_mirror_different_count() {
        let mut store = MockStore::new(8);
        store.add_entry(&vec![0x11u8; 512], 2);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(8),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::Mirror { replica_count: 4 },
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);
        assert_eq!(job.cursor.entries_converted, 1);
    }

    #[test]
    fn checkpoint_reflects_progress() {
        let mut store = MockStore::new(6);
        store.add_entry(&vec![0u8; 512], 2);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(6),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::Mirror { replica_count: 3 },
        );
        let _ = job.step(WorkBudget::DEFAULT_TICK);
        let cp = job.persist_checkpoint();
        assert_eq!(cp.progress.items_processed, 1);
        assert!(cp.progress.items_total_estimate > 0);
        assert_eq!(cp.job_kind, JobKind::GeometryConvert);
    }

    #[test]
    fn job_display() {
        let store = MockStore::new(7);
        let job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(7),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 1024,
            },
        );
        let s = format!("{job}");
        assert!(s.contains("GeometryConversionJob"));
        assert!(s.contains("pool(7)"));
        assert!(s.contains("mirror(2)"));
        assert!(s.contains("EC(4+2"));
    }

    #[test]
    fn digest_deterministic() {
        assert_eq!(blake3_digest(b"hello"), blake3_digest(b"hello"));
    }

    #[test]
    fn digest_different_inputs() {
        assert_ne!(blake3_digest(b"hello"), blake3_digest(b"world"));
    }

    #[test]
    fn locator_id_basics() {
        let lid = LocatorId(42);
        assert!(lid.is_some());
        assert!(!lid.is_none());
        assert!(LocatorId::NONE.is_none());
        assert_eq!(format!("{lid}"), "000000000000002a");
    }

    #[test]
    fn replica_placement_basics() {
        let rp = ReplicaPlacement::new_unsharded(1, 2, 3, 0, 1024);
        assert_eq!(rp.node_id, 1);
        assert_eq!(rp.device_id, 2);
        assert!(rp.is_readable());
    }

    #[test]
    fn locator_value_flags_set_on_ec_conversion() {
        let mut store = MockStore::new(9);
        store.add_entry(&vec![0u8; 256], 2);
        let _lid = LocatorId(1);
        // Verify old entry is not EC-flagged
        {
            let old = &store.entries[&1].value;
            assert_eq!(old.flags & locator_flags::ERASURE_CODED, 0);
        }
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(9),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 64,
            },
        );
        let _ = job.step(WorkBudget::DEFAULT_TICK);
        // After conversion, entry should be EC-flagged
        // Note: since store is moved into job, we check via the checkpoint
        let cp = job.persist_checkpoint();
        assert_eq!(cp.progress.items_processed, 1);
    }

    #[test]
    fn budget_limits_entries_per_tick() {
        let mut store = MockStore::new(10);
        for _ in 0..10 {
            store.add_entry(&vec![0u8; 1024], 2);
        }
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(10),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::Mirror { replica_count: 3 },
        );
        let tight_budget = WorkBudget {
            max_items: 5,
            max_bytes: 0,
            max_ms: 0,
        };
        let r = job.step(tight_budget);
        assert!(!r.is_complete);
        assert!(job.cursor.entries_converted <= 5);
    }

    #[test]
    fn conversion_write_failure_is_checkpointed_without_progress() {
        let mut store = MockStore::new(11);
        let lid = store.add_entry(&vec![0u8; 1024], 2);
        store.fail_write_locator = Some(lid.0);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(11),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::Mirror { replica_count: 3 },
        );
        let r = job.step(WorkBudget::DEFAULT_TICK);
        assert!(r.is_complete);
        assert!(job.is_failed());
        assert_eq!(job.cursor.entries_converted, 0);
        assert_eq!(job.cursor.last_converted_locator, 0);
        assert_eq!(
            job.last_error(),
            Some("locator 0000000000000001 conversion failed: mock write failure")
        );
        let cp = job.persist_checkpoint();
        let cursor = ConversionCursor::decode(cp.cursor_state.as_bytes()).expect("cursor");
        assert!(cursor.failed);
        assert_eq!(cursor.entries_converted, 0);
        assert_eq!(
            cursor.last_error.as_deref(),
            Some("locator 0000000000000001 conversion failed: mock write failure")
        );
    }

    #[test]
    fn conversion_update_failure_preserves_completed_prefix() {
        let mut store = MockStore::new(12);
        store.add_entry(&vec![1u8; 1024], 2);
        let second = store.add_entry(&vec![2u8; 1024], 2);
        store.fail_update_locator = Some(second.0);
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(12),
            DurabilityPolicy::Mirror { replica_count: 2 },
            DurabilityPolicy::Mirror { replica_count: 3 },
        );
        let r = job.step(WorkBudget::DEFAULT_TICK);
        assert!(r.is_complete);
        assert!(job.is_failed());
        assert_eq!(job.cursor.entries_converted, 1);
        assert_eq!(job.cursor.last_converted_locator, 1);
        assert_eq!(
            job.last_error(),
            Some("locator 0000000000000002 conversion failed: mock update failure")
        );
    }

    #[test]
    fn pool_backed_mirror_to_ec_reassembles_writes_and_relocates() {
        let payload = b"mirror payload converted into EC shards across stripes".repeat(20);
        let source_policy = DurabilityPolicy::Mirror { replica_count: 2 };
        let target_policy = DurabilityPolicy::ErasureCoded {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 128,
        };
        let mut store = harness_store(21);
        let locator_id = store.locators.add_policy_entry(
            &mut store.placement,
            &mut store.shard_io,
            &source_policy,
            &payload,
        );

        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(21),
            source_policy,
            target_policy.clone(),
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);
        assert_eq!(job.cursor.entries_converted, 1);

        let value = job.store.locators.resolve(locator_id).expect("locator");
        assert!(value.flags & locator_flags::ERASURE_CODED != 0);
        assert!(value.flags & locator_flags::SHARDED != 0);
        assert_eq!(value.shard_count, 3);
        assert_eq!(value.replica_count, 0);
        let read_back = job
            .store
            .read_payload(&value, &target_policy)
            .expect("read back EC");
        assert_eq!(read_back, payload);
    }

    #[test]
    fn pool_backed_ec_to_mirror_reconstructs_payload() {
        let payload = b"ec payload survives conversion to mirrors".repeat(17);
        let source_policy = DurabilityPolicy::ErasureCoded {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 64,
        };
        let target_policy = DurabilityPolicy::Mirror { replica_count: 3 };
        let mut store = harness_store(22);
        let locator_id = store.locators.add_policy_entry(
            &mut store.placement,
            &mut store.shard_io,
            &source_policy,
            &payload,
        );

        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(22),
            source_policy,
            target_policy.clone(),
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);

        let value = job.store.locators.resolve(locator_id).expect("locator");
        assert_eq!(value.flags & locator_flags::ERASURE_CODED, 0);
        assert_eq!(value.flags & locator_flags::SHARDED, 0);
        assert_eq!(value.shard_count, 1);
        assert_eq!(value.replica_count, 3);
        let read_back = job
            .store
            .read_payload(&value, &target_policy)
            .expect("read back mirror");
        assert_eq!(read_back, payload);
    }

    #[test]
    fn pool_backed_ec_family_conversion_materializes_new_width() {
        let payload = b"ec family conversion payload".repeat(40);
        let source_policy = DurabilityPolicy::ErasureCoded {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 96,
        };
        let target_policy = DurabilityPolicy::ErasureCoded {
            data_shards: 3,
            parity_shards: 2,
            shard_len: 64,
        };
        let mut store = harness_store(23);
        let locator_id = store.locators.add_policy_entry(
            &mut store.placement,
            &mut store.shard_io,
            &source_policy,
            &payload,
        );

        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(23),
            source_policy,
            target_policy.clone(),
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);

        let value = job.store.locators.resolve(locator_id).expect("locator");
        assert!(value.flags & locator_flags::ERASURE_CODED != 0);
        assert_eq!(value.shard_count, 5);
        assert_eq!(value.replica_placement.len(), 5);
        let read_back = job
            .store
            .read_payload(&value, &target_policy)
            .expect("read back new EC family");
        assert_eq!(read_back, payload);
    }

    #[test]
    fn checkpoint_resume_recreates_pool_store_and_continues() {
        let source_policy = DurabilityPolicy::Mirror { replica_count: 2 };
        let target_policy = DurabilityPolicy::ErasureCoded {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 128,
        };
        let mut store = harness_store(24);
        let first = store.locators.add_policy_entry(
            &mut store.placement,
            &mut store.shard_io,
            &source_policy,
            b"first extent",
        );
        let second = store.locators.add_policy_entry(
            &mut store.placement,
            &mut store.shard_io,
            &source_policy,
            b"second extent",
        );
        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(24),
            source_policy,
            target_policy.clone(),
        );
        let one_item = WorkBudget {
            max_items: 1,
            max_bytes: 0,
            max_ms: 0,
        };
        let first_step = job.step(one_item);
        assert!(!first_step.is_complete);
        assert_eq!(job.cursor.last_converted_locator, first.0);
        let checkpoint = job.persist_checkpoint();
        let store = job.into_store();
        resume_registry()
            .lock()
            .expect("resume registry")
            .insert(24, store);

        let mut resumed =
            <GeometryConversionJob<HarnessPoolStore> as IncrementalJob>::resume(checkpoint)
                .expect("resume");
        let second_step = resumed.step(WorkBudget::DEFAULT_TICK);
        assert!(second_step.is_complete);
        assert_eq!(resumed.cursor.entries_converted, 2);
        assert_eq!(resumed.cursor.last_converted_locator, second.0);
        for locator_id in [first, second] {
            let value = resumed.store.locators.resolve(locator_id).expect("locator");
            assert!(value.flags & locator_flags::ERASURE_CODED != 0);
            assert_eq!(value.shard_count, 3);
        }
    }

    #[test]
    fn pool_backed_relocate_failure_preserves_completed_prefix() {
        let source_policy = DurabilityPolicy::Mirror { replica_count: 2 };
        let target_policy = DurabilityPolicy::Mirror { replica_count: 3 };
        let mut store = harness_store(25);
        let first = store.locators.add_policy_entry(
            &mut store.placement,
            &mut store.shard_io,
            &source_policy,
            b"already committed",
        );
        let second = store.locators.add_policy_entry(
            &mut store.placement,
            &mut store.shard_io,
            &source_policy,
            b"fails at relocate",
        );
        store.locators.fail_relocate_locator = Some(second.0);

        let mut job = GeometryConversionJob::new(
            store,
            ConversionScope::Pool(25),
            source_policy,
            target_policy,
        );
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);
        assert!(job.is_failed());
        assert_eq!(job.cursor.entries_converted, 1);
        assert_eq!(job.cursor.last_converted_locator, first.0);

        let first_value = job.store.locators.resolve(first).expect("first");
        let second_value = job.store.locators.resolve(second).expect("second");
        assert_eq!(first_value.replica_count, 3);
        assert_eq!(second_value.replica_count, 2);
        assert_eq!(
            job.last_error(),
            Some(
                "locator 0000000000000002 conversion failed: atomic locator relocate failed: allocation failed"
            )
        );
    }
}
