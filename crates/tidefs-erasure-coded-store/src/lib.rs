// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]
#![forbid(unsafe_code)]

//! Erasure-coded object store: stripes data with parity across N
//! `LocalObjectStore` instances using GF(2^8) Reed-Solomon codes.
//!
//! Each object is split into `data_shards` data shards plus
//! `parity_shards` parity shards. Any `data_shards` surviving shards
//! are sufficient to reconstruct the original payload. This provides
//! space-efficient redundancy compared to full replication:
//!
//! | Config  | Overhead | Tolerates |
//! |---------|----------|-----------|
//! | 4+1     | 1.25x    | 1 loss    |
//! | 4+2     | 1.50x    | 2 losses  |
//! | 8+3     | 1.375x   | 3 losses  |
//!
//! Compared to ZFS PARITY_RAID and Ceph erasure-coded pools, this store
//! operates at the object level (not block/placement-group level),
//! avoiding PG state combinatorics and enabling fine-grained per-object
//! repair without full-PG rebuilds.
//!
//! Multi-stripe encoding: payloads larger than `data_capacity` are
//! split into multiple stripes, each independently encoded. This
//! allows arbitrarily large objects with consistent shard sizes.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::Arc,
};
use tidefs_durability_layout::FailureDomainV1;
use tidefs_erasure_coding::{encode, reconstruct, ErasureShard, ShardKind, StripeConfig};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_placement_planner::placement_plan::{DeviceCandidate, PlacementPlan};
use tokio::sync::Mutex;

pub mod write_path;

/// Configuration for an erasure-coded object store.
#[derive(Clone, Debug)]
pub struct ErasureCodedStoreConfig {
    /// Number of data shards per stripe. Must be >= 1.
    pub data_shards: usize,
    /// Number of parity shards (1-3).
    pub parity_shards: usize,
    /// Bytes per shard. Payload capacity per stripe = data_shards * shard_len.
    pub shard_len: usize,
    /// Store options applied to each shard store.
    pub store_options: StoreOptions,
    /// Optional failure domain descriptor for placement anti-affinity.
    /// When `None`, identity mapping (shard i → store i) is used.
    pub failure_domain: Option<FailureDomainV1>,
    /// Optional device candidates, one per store. Must be in the same order
    /// as the store paths. When `None`, identity mapping is used.
    pub device_candidates: Option<Vec<DeviceCandidate>>,
}

impl ErasureCodedStoreConfig {
    /// Total number of stores (data + parity).
    #[must_use]
    pub fn store_count(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Payload capacity per stripe in bytes.
    #[must_use]
    pub fn data_capacity(&self) -> usize {
        self.data_shards * self.shard_len
    }

    /// Convenience: 4+2 PARITY_RAID2 configuration with 64 KiB shards.
    #[must_use]
    pub fn four_plus_two() -> Self {
        Self {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 65536,
            store_options: StoreOptions::test_fast(),
            failure_domain: None,
            device_candidates: None,
        }
    }

    /// Convenience: 8+3 PARITY_RAID3 configuration with 64 KiB shards.
    #[must_use]
    pub fn eight_plus_three() -> Self {
        Self {
            data_shards: 8,
            parity_shards: 3,
            shard_len: 65536,
            store_options: StoreOptions::test_fast(),
            failure_domain: None,
            device_candidates: None,
        }
    }

    /// Convenience: 2+1 minimal configuration for testing.
    #[must_use]
    pub fn two_plus_one_test() -> Self {
        Self {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 256,
            store_options: StoreOptions::test_fast(),
            failure_domain: None,
            device_candidates: None,
        }
    }
}

/// Statistics for an erasure-coded store.
#[derive(Clone, Debug, Default)]
pub struct ErasureCodedStoreStats {
    /// Total objects stored.
    pub object_count: u64,
    /// Total stripes written across all objects.
    pub stripes_written: u64,
    /// Total bytes of original payload written.
    pub bytes_written: u64,
    /// Total bytes stored on disk (including parity).
    pub bytes_stored: u64,
    /// Number of shard records written with embedded digest envelopes.
    pub shards_written: u64,
    /// Number of reads that required reconstruction.
    pub degraded_reads: Cell<u64>,
    /// Number of reads that served from all data shards (no reconstruction).
    pub clean_reads: Cell<u64>,
    /// Number of reads that failed (insufficient shards).
    pub failed_reads: Cell<u64>,
    /// Number of shard records whose embedded digest was verified.
    pub shards_verified: Cell<u64>,
    /// Number of shard records rejected before decode because the embedded digest failed.
    pub shard_verification_failures: Cell<u64>,
    /// Per-store health: true if store is available.
    pub store_healthy: Vec<bool>,
    /// Number of encode operations performed.
    pub encodes: Cell<u64>,
    /// Number of decode operations performed.
    pub decodes: Cell<u64>,
    /// Number of repair operations performed.
    pub repairs: Cell<u64>,
    /// Number of individual shard reads.
    pub shards_read: Cell<u64>,
    /// Number of times a missing shard triggered a fallback read.
    pub missing_shard_fallbacks: Cell<u64>,
}

/// A pending erasure-coded shard repair queued during degraded reads.
///
/// When a read reconstructs data from surviving shards, the missing or corrupt
/// shards are queued here and written back on the next flush or write.
#[derive(Clone, Debug)]
struct PendingEcRepair {
    /// Index of the store that needs repair.
    store_index: usize,
    /// Object key for the shard being repaired.
    shard_key: tidefs_local_object_store::ObjectKey,
    /// Encoded shard record to write back (already wrapped with digest envelope).
    shard_record: Vec<u8>,
}

/// Erasure-coded object store.
///
/// Maintains N `LocalObjectStore` instances where N = data_shards + parity_count.
/// Objects are striped across data stores with parity shards distributed across
/// parity stores. Any data_shards surviving shards are sufficient to reconstruct.
pub struct ErasureCodedStore {
    pub stores: Vec<LocalObjectStore>,
    config: ErasureCodedStoreConfig,
    stats: ErasureCodedStoreStats,
    /// Maps shard index → store index, computed from the placement plan.
    /// Falls back to identity mapping when placement info is not provided.
    shard_to_store: HashMap<usize, usize>,
    /// Pending shard repairs queued during degraded reads.
    repair_queue: RefCell<Vec<PendingEcRepair>>,
}

impl ErasureCodedStore {
    /// Open an erasure-coded store.
    ///
    /// `paths` must contain exactly `config.store_count()` paths.
    /// The first `config.data_shards` paths are data stores;
    /// the remaining paths are parity stores.
    ///
    /// # Errors
    ///
    /// Returns an error if any store fails to open, if paths is empty,
    /// or if the path count does not match the store count.
    pub fn open(paths: &[PathBuf], config: ErasureCodedStoreConfig) -> Result<Self, String> {
        let expected = config.store_count();
        if paths.is_empty() {
            return Err("erasure-coded store requires at least 1 path".into());
        }
        if paths.len() != expected {
            return Err(format!(
                "path count ({}) does not match store count ({} data + {} parity = {})",
                paths.len(),
                config.data_shards,
                config.parity_shards,
                expected,
            ));
        }

        let mut stores = Vec::with_capacity(expected);
        for (i, path) in paths.iter().enumerate() {
            let store = LocalObjectStore::open_with_options(path, config.store_options.clone())
                .map_err(|e| format!("failed to open store {i} at {path:?}: {e}"))?;
            stores.push(store);
        }

        // Compute shard → store mapping from placement plan, or fall back to identity.
        let shard_to_store = compute_shard_to_store(&config);

        Ok(Self {
            stores,
            config,
            stats: ErasureCodedStoreStats {
                store_healthy: vec![true; expected],
                ..Default::default()
            },
            shard_to_store,
            repair_queue: RefCell::new(Vec::new()),
        })
    }

    /// Put an object identified by `name`.
    ///
    /// The payload is split into stripes of `data_capacity` bytes. Each stripe
    /// is encoded into data + parity shards and written to the corresponding
    /// stores. Shards are keyed as `{object_key}_stripe_{s}_shard_{i}`.
    pub fn put_named(&mut self, name: impl AsRef<[u8]>, payload: &[u8]) -> Result<(), String> {
        // Flush any pending shard repairs from degraded reads before writing.
        self.flush_repairs();
        let key = ObjectKey::from_name(&name);
        let cap = self.config.data_capacity();
        let sw = self.config.store_count();
        let original_len = payload.len();
        let num_stripes = if original_len == 0 {
            1
        } else {
            original_len.div_ceil(cap)
        };

        let stripe_config = StripeConfig {
            data_shards: self.config.data_shards,
            parity_shards: self.config.parity_shards,
            shard_len: self.config.shard_len,
        };

        // Store total original payload length as metadata on ALL stores
        // so it survives partial failures. Each store independently holds
        // the length; any surviving store can serve it on read.
        let len_key = len_object_key(key);
        let len_bytes = (original_len as u64).to_le_bytes().to_vec();
        for i in 0..sw {
            let _ = self.stores[i].put(len_key, &len_bytes);
        }

        let object_prefix = object_prefix(key);
        let mut bytes_stored: u64 = 0;
        let mut shards_written = 0u64;
        let mut store_healthy = vec![true; sw];

        for s in 0..num_stripes {
            let start = s * cap;
            let end = (original_len).min(start + cap);
            let chunk = if start < original_len {
                &payload[start..end]
            } else {
                &[]
            };

            let encoded = encode(&stripe_config, chunk)
                .ok_or_else(|| format!("encode failed for stripe {s}"))?;

            for shard in &encoded.shards {
                let shard_key = shard_object_key(key, s, shard.index);
                let shard_record =
                    encode_verified_shard(&object_prefix, s, shard.index, &shard.bytes)?;
                let store_idx = mapped_store_index(&self.shard_to_store, shard.index, sw);
                match self.stores[store_idx].put(shard_key, &shard_record) {
                    Ok(_) => {
                        bytes_stored += shard_record.len() as u64;
                        shards_written += 1;
                    }
                    Err(e) => {
                        store_healthy[store_idx] = false;
                        eprintln!(
                            "store {store_idx} write failed for stripe {s} shard {}: {e}",
                            shard.index,
                        );
                    }
                }
            }
        }

        self.stats.object_count += 1;
        self.stats.stripes_written += num_stripes as u64;
        self.stats.bytes_written += original_len as u64;
        self.stats.bytes_stored += bytes_stored;
        self.stats.shards_written += shards_written;
        self.stats.store_healthy = store_healthy;
        increment_cell(&self.stats.encodes);

        Ok(())
    }

    /// Get an object by name.
    ///
    /// Reads all shards for all stripes, reconstructs each stripe, and
    /// concatenates the results. If fewer than `data_shards` shards are
    /// available for any stripe, the read fails.
    pub fn get_named(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, String> {
        let key = ObjectKey::from_name(&name);
        let sw = self.config.store_count();
        let object_prefix = object_prefix(key);

        let stripe_config = StripeConfig {
            data_shards: self.config.data_shards,
            parity_shards: self.config.parity_shards,
            shard_len: self.config.shard_len,
        };

        // Probe all stores for stripe count. Returns 0 if no store has the object.
        let num_stripes = probe_stripe_count_all(&self.stores, key, sw, &self.shard_to_store);
        if num_stripes == 0 {
            return Ok(None);
        }

        // Read total original payload length metadata from any store.
        let len_key = len_object_key(key);
        let mut total_original_len: Option<usize> = None;
        for i in 0..sw {
            if let Ok(Some(bytes)) = self.stores[i].get(len_key) {
                if bytes.len() >= 8 {
                    total_original_len =
                        Some(u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize);
                    break;
                }
            }
        }

        let cap = self.config.data_capacity();
        let default_cap = match total_original_len {
            Some(len) => len.max(num_stripes * cap),
            None => num_stripes * cap,
        };
        let mut result = Vec::with_capacity(default_cap);
        let mut degraded = false;

        for s in 0..num_stripes {
            let mut available: Vec<Option<ErasureShard>> = Vec::with_capacity(sw);

            for i in 0..sw {
                let sk = shard_object_key(key, s, i);
                let store_idx = mapped_store_index(&self.shard_to_store, i, sw);
                match self.stores[store_idx].get(sk) {
                    Ok(Some(record)) => {
                        increment_cell(&self.stats.shards_read);
                        match decode_verified_shard(&object_prefix, s, i, &record) {
                            Ok(bytes) => {
                                increment_cell(&self.stats.shards_verified);
                                let kind = if i < self.config.data_shards {
                                    ShardKind::Data
                                } else {
                                    ShardKind::Parity
                                };
                                available.push(Some(ErasureShard {
                                    index: i,
                                    kind,
                                    bytes,
                                }));
                            }
                            Err(e) => {
                                increment_cell(&self.stats.shard_verification_failures);
                                eprintln!(
                                    "store {store_idx} shard {i} verify failed for stripe {s}: {e}"
                                );
                                available.push(None);
                                degraded = true;
                            }
                        }
                    }
                    Ok(None) => {
                        available.push(None);
                        degraded = true;
                        increment_cell(&self.stats.missing_shard_fallbacks);
                    }
                    Err(e) => {
                        eprintln!("store {store_idx} read failed for stripe {s} shard {i}: {e}");
                        available.push(None);
                        degraded = true;
                        increment_cell(&self.stats.missing_shard_fallbacks);
                    }
                }
            }

            let recon = reconstruct(&stripe_config, &available, None).ok_or_else(|| {
                increment_cell(&self.stats.failed_reads);
                format!(
                    "stripe {s}: insufficient verified shards available ({}/{} needed)",
                    available.iter().filter(|s| s.is_some()).count(),
                    self.config.data_shards,
                )
            })?;

            // Queue repairs for missing/corrupt shards to be written back later.
            if degraded {
                if let Some(encoded) = encode(&stripe_config, &recon.payload) {
                    for i in 0..sw {
                        if available[i].is_none() {
                            let shard_key = shard_object_key(key, s, i);
                            let store_index = mapped_store_index(&self.shard_to_store, i, sw);
                            if let Ok(shard_record) = encode_verified_shard(
                                &object_prefix,
                                s,
                                i,
                                &encoded.shards[i].bytes,
                            ) {
                                self.repair_queue.borrow_mut().push(PendingEcRepair {
                                    store_index,
                                    shard_key,
                                    shard_record,
                                });
                            }
                        }
                    }
                }
            }

            // Truncate each stripe to its original chunk length.
            let stripe_chunk_len = match total_original_len {
                Some(_len) if s + 1 < num_stripes => cap,
                Some(len) => len.saturating_sub(s * cap),
                None => recon.payload.len(),
            };
            let effective = stripe_chunk_len.min(recon.payload.len());

            result.extend_from_slice(&recon.payload[..effective]);
        }

        if degraded {
            self.stats
                .degraded_reads
                .set(self.stats.degraded_reads.get() + 1);
        } else {
            self.stats.clean_reads.set(self.stats.clean_reads.get() + 1);
        }
        increment_cell(&self.stats.decodes);

        Ok(Some(result))
    }

    /// Delete an object by name from all stores.
    pub fn delete_named(&mut self, name: impl AsRef<[u8]>) -> Result<bool, String> {
        let key = ObjectKey::from_name(&name);
        let sw = self.config.store_count();
        let num_stripes = probe_stripe_count_all(&self.stores, key, sw, &self.shard_to_store);
        if num_stripes == 0 {
            // Also try to clean up any orphaned length metadata from all stores.
            for i in 0..sw {
                let _ = self.stores[i].delete(len_object_key(key));
            }
            return Ok(false);
        }

        for s in 0..num_stripes {
            for i in 0..sw {
                let sk = shard_object_key(key, s, i);
                let store_idx = mapped_store_index(&self.shard_to_store, i, sw);
                let _ = self.stores[store_idx].delete(sk);
            }
        }

        // Delete length metadata from all stores.
        for i in 0..sw {
            let _ = self.stores[i].delete(len_object_key(key));
        }

        Ok(true)
    }

    /// Sync all stores to disk.
    pub fn sync_all(&mut self) -> Result<(), String> {
        for (i, store) in self.stores.iter_mut().enumerate() {
            store
                .sync_all()
                .map_err(|e| format!("store {i} sync failed: {e}"))?;
        }
        Ok(())
    }

    /// Return current statistics.
    #[must_use]
    pub fn stats(&self) -> &ErasureCodedStoreStats {
        &self.stats
    }

    /// Return the number of stores.
    #[must_use]
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    /// Return per-store health status.
    #[must_use]
    pub fn store_health(&self) -> &[bool] {
        &self.stats.store_healthy
    }

    /// Write back any pending shard repairs queued during degraded reads.
    ///
    /// Returns the number of shards successfully repaired.
    pub fn flush_repairs(&mut self) -> usize {
        let pending: Vec<PendingEcRepair> = std::mem::take(&mut *self.repair_queue.borrow_mut());
        let mut repaired = 0usize;
        for p in &pending {
            match self.stores[p.store_index].put(p.shard_key, &p.shard_record) {
                Ok(_) => {
                    repaired += 1;
                    increment_cell(&self.stats.repairs);
                }
                Err(e) => {
                    eprintln!(
                        "ec repair: failed to write shard to store {}: {e}",
                        p.store_index
                    );
                }
            }
        }
        repaired
    }

    /// Repair a specific store by reconstructing its shards from surviving
    /// stores. Iterates all stored objects and rebuilds missing shards.
    ///
    /// Returns the number of shards repaired.
    pub fn repair_store(&mut self, store_index: usize) -> Result<usize, String> {
        if store_index >= self.stores.len() {
            return Err(format!("store index {store_index} out of range"));
        }

        let all_prefixes = collect_base_keys(&self.stores, store_index);

        let sw = self.config.store_count();
        let stripe_config = StripeConfig {
            data_shards: self.config.data_shards,
            parity_shards: self.config.parity_shards,
            shard_len: self.config.shard_len,
        };

        let mut repaired = 0usize;

        for prefix in &all_prefixes {
            // Determine stripe count: probe all stores for stripe 0 of their own shard.
            let mut healthy_shard: Option<usize> = None;
            for i in 0..sw {
                let probe_key = shard_key_from_prefix(prefix, 0, i);
                let store_idx = mapped_store_index(&self.shard_to_store, i, sw);
                if let Ok(Some(_)) = self.stores[store_idx].get(probe_key) {
                    healthy_shard = Some(i);
                    break;
                }
            }
            let h = match healthy_shard {
                Some(i) => i,
                None => continue,
            };
            let healthy_store = mapped_store_index(&self.shard_to_store, h, sw);

            let mut num_stripes = 1usize;
            loop {
                let probe_key = shard_key_from_prefix(prefix, num_stripes, h);
                match self.stores[healthy_store].get(probe_key) {
                    Ok(Some(_)) => num_stripes += 1,
                    _ => break,
                }
            }

            for s in 0..num_stripes {
                // Read all shards from all stores
                let mut available: Vec<Option<ErasureShard>> = Vec::with_capacity(sw);
                for i in 0..sw {
                    let sk = shard_key_from_prefix(prefix, s, i);
                    let store_idx = mapped_store_index(&self.shard_to_store, i, sw);
                    match self.stores[store_idx].get(sk) {
                        Ok(Some(record)) => match decode_verified_shard(prefix, s, i, &record) {
                            Ok(bytes) => {
                                increment_cell(&self.stats.shards_verified);
                                let kind = if i < self.config.data_shards {
                                    ShardKind::Data
                                } else {
                                    ShardKind::Parity
                                };
                                available.push(Some(ErasureShard {
                                    index: i,
                                    kind,
                                    bytes,
                                }));
                            }
                            Err(e) => {
                                increment_cell(&self.stats.shard_verification_failures);
                                eprintln!(
                                    "store {store_idx} shard {i} verify failed for stripe {s}: {e}"
                                );
                                available.push(None);
                            }
                        },
                        _ => available.push(None),
                    }
                }

                if let Some(recon) = reconstruct(&stripe_config, &available, None) {
                    for rebuilt in &recon.rebuilt_shards {
                        let target_store =
                            mapped_store_index(&self.shard_to_store, rebuilt.index, sw);
                        if target_store == store_index {
                            let sk = shard_key_from_prefix(prefix, s, rebuilt.index);
                            let shard_record =
                                encode_verified_shard(prefix, s, rebuilt.index, &rebuilt.bytes)?;
                            self.stores[target_store]
                                .put(sk, &shard_record)
                                .map_err(|e| {
                                    format!("repair write failed for shard {}: {e}", rebuilt.index,)
                                })?;
                            repaired += 1;
                        }
                    }
                }
            }
        }

        // Mark store as healthy after repair
        if store_index < self.stats.store_healthy.len() {
            self.stats.store_healthy[store_index] = true;
        }
        increment_cell(&self.stats.repairs);

        Ok(repaired)
    }
}

// ── Async EC store runtime types ──────────────────────────────────────

/// Error type for async EC store operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcStoreError {
    /// Encoding failed.
    EncodeFailed(String),
    /// Decoding/reconstruction failed.
    DecodeFailed(String),
    /// Dispatch to a shard store failed.
    DispatchFailed { shard: usize, reason: String },
    /// Not enough shards available to reconstruct.
    InsufficientShards { available: usize, needed: usize },
    /// Repair operation failed.
    RepairFailed { store_index: usize, reason: String },
    /// Internal store error.
    Internal(String),
}

impl fmt::Display for EcStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodeFailed(msg) => write!(f, "encode failed: {msg}"),
            Self::DecodeFailed(msg) => write!(f, "decode failed: {msg}"),
            Self::DispatchFailed { shard, reason } => {
                write!(f, "dispatch to shard {shard} failed: {reason}")
            }
            Self::InsufficientShards { available, needed } => {
                write!(
                    f,
                    "insufficient shards: {available} available, {needed} needed"
                )
            }
            Self::RepairFailed {
                store_index,
                reason,
            } => {
                write!(f, "repair of store {store_index} failed: {reason}")
            }
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for EcStoreError {}

/// Result of an EC write path execution.
#[derive(Debug, Clone)]
pub struct EcWriteResult {
    /// Number of shards successfully dispatched.
    pub shards_dispatched: usize,
    /// Total number of shards in the stripe set.
    pub shards_total: usize,
    /// Total bytes encoded (original payload size).
    pub bytes_encoded: u64,
}

/// Result of an EC read path execution.
#[derive(Debug, Clone)]
pub struct EcReadResult {
    /// The reconstructed payload.
    pub payload: Vec<u8>,
    /// Number of individual shard reads performed.
    pub shards_read: usize,
    /// Number of times a missing shard triggered an alternative fetch.
    pub fallbacks_used: usize,
    /// Whether the read required reconstruction (degraded).
    pub degraded: bool,
}

// ── Shard integrity envelope helpers ──────────────────────────────────

const SHARD_RECORD_MAGIC: &[u8; 8] = b"VECSHV1\0";
const SHARD_RECORD_VERSION: u8 = 1;
const SHARD_RECORD_HEADER_LEN: usize = 60;
const SHARD_DIGEST_CONTEXT: &str = "TideFS erasure-coded-store shard digest v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardIntegrityError {
    MissingEnvelope,
    TruncatedRecord,
    UnsupportedVersion(u8),
    HeaderMismatch {
        expected_stripe: u64,
        got_stripe: u64,
        expected_shard: u16,
        got_shard: u16,
    },
    DigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    LengthOverflow(&'static str),
}

impl fmt::Display for ShardIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvelope => write!(f, "missing shard integrity envelope"),
            Self::TruncatedRecord => write!(f, "truncated shard integrity record"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported shard integrity version {version}")
            }
            Self::HeaderMismatch {
                expected_stripe,
                got_stripe,
                expected_shard,
                got_shard,
            } => write!(
                f,
                "shard header mismatch: expected stripe {expected_stripe} shard {expected_shard}, got stripe {got_stripe} shard {got_shard}"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "shard digest mismatch: expected {}, got {}",
                HexDigest(expected),
                HexDigest(actual)
            ),
            Self::LengthOverflow(field) => write!(f, "{field} length overflow"),
        }
    }
}

impl std::error::Error for ShardIntegrityError {}

fn object_prefix(base: ObjectKey) -> [u8; 16] {
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&base.as_bytes32()[..16]);
    prefix
}

fn encode_verified_shard(
    object_prefix: &[u8; 16],
    stripe: usize,
    shard_index: usize,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let stripe_u64 = u64::try_from(stripe).map_err(|_| "stripe index overflow".to_string())?;
    let shard_u16 = u16::try_from(shard_index).map_err(|_| "shard index overflow".to_string())?;
    let payload_len =
        u64::try_from(payload.len()).map_err(|_| "shard payload length overflow".to_string())?;
    let digest = compute_shard_digest(object_prefix, stripe_u64, shard_u16, payload);

    let mut out = Vec::with_capacity(SHARD_RECORD_HEADER_LEN + payload.len());
    out.extend_from_slice(SHARD_RECORD_MAGIC);
    out.push(SHARD_RECORD_VERSION);
    out.push(0);
    out.extend_from_slice(&shard_u16.to_le_bytes());
    out.extend_from_slice(&stripe_u64.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_verified_shard(
    object_prefix: &[u8; 16],
    stripe: usize,
    shard_index: usize,
    record: &[u8],
) -> Result<Vec<u8>, ShardIntegrityError> {
    if record.len() < SHARD_RECORD_HEADER_LEN {
        return Err(ShardIntegrityError::TruncatedRecord);
    }
    if &record[..SHARD_RECORD_MAGIC.len()] != SHARD_RECORD_MAGIC {
        return Err(ShardIntegrityError::MissingEnvelope);
    }
    let version = record[8];
    if version != SHARD_RECORD_VERSION {
        return Err(ShardIntegrityError::UnsupportedVersion(version));
    }
    let got_shard = u16::from_le_bytes(record[10..12].try_into().unwrap());
    let got_stripe = u64::from_le_bytes(record[12..20].try_into().unwrap());
    let payload_len = u64::from_le_bytes(record[20..28].try_into().unwrap());
    let expected_stripe =
        u64::try_from(stripe).map_err(|_| ShardIntegrityError::LengthOverflow("stripe index"))?;
    let expected_shard = u16::try_from(shard_index)
        .map_err(|_| ShardIntegrityError::LengthOverflow("shard index"))?;
    if got_stripe != expected_stripe || got_shard != expected_shard {
        return Err(ShardIntegrityError::HeaderMismatch {
            expected_stripe,
            got_stripe,
            expected_shard,
            got_shard,
        });
    }
    let payload_len = usize::try_from(payload_len)
        .map_err(|_| ShardIntegrityError::LengthOverflow("shard payload"))?;
    if record.len() != SHARD_RECORD_HEADER_LEN + payload_len {
        return Err(ShardIntegrityError::TruncatedRecord);
    }
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&record[28..60]);
    let payload = &record[SHARD_RECORD_HEADER_LEN..];
    let actual = compute_shard_digest(object_prefix, got_stripe, got_shard, payload);
    if expected != actual {
        return Err(ShardIntegrityError::DigestMismatch { expected, actual });
    }
    Ok(payload.to_vec())
}

fn compute_shard_digest(
    object_prefix: &[u8; 16],
    stripe: u64,
    shard_index: u16,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SHARD_DIGEST_CONTEXT);
    hasher.update(object_prefix);
    hasher.update(&stripe.to_le_bytes());
    hasher.update(&shard_index.to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn increment_cell(cell: &Cell<u64>) {
    cell.set(cell.get().saturating_add(1));
}

struct HexDigest<'a>(&'a [u8; 32]);

impl fmt::Display for HexDigest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ── Shard key helpers ──────────────────────────────────────────────────

/// Build a shard object key from a base object key, stripe index, and shard index.
fn shard_object_key(base: ObjectKey, stripe: usize, shard: usize) -> ObjectKey {
    let base_bytes = base.as_bytes32();
    let mut out = [0u8; 32];
    // First 16 bytes: base key prefix (enables grouping by object)
    out[..16].copy_from_slice(&base_bytes[..16]);
    // Bytes 16-23: stripe index as u64 LE
    out[16..24].copy_from_slice(&(stripe as u64).to_le_bytes());
    // Bytes 24-31: shard index as u64 LE
    out[24..32].copy_from_slice(&(shard as u64).to_le_bytes());
    ObjectKey::from_bytes(out)
}

/// Build a metadata key for storing original payload length.
fn len_object_key(base: ObjectKey) -> ObjectKey {
    let base_bytes = base.as_bytes32();
    let mut out = [0u8; 32];
    // First 16 bytes: same prefix as shard keys (object grouping)
    out[..16].copy_from_slice(&base_bytes[..16]);
    // Bytes 16-23: marker for length metadata (u64::MAX as sentinel)
    out[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    // Bytes 24-31: zero (distinguishes from shard keys)
    out[24..32].copy_from_slice(&0u64.to_le_bytes());
    ObjectKey::from_bytes(out)
}

/// Extract the base object key from a shard key. Returns None if the key
/// doesn't match the shard key pattern.
fn extract_base_key(key: ObjectKey) -> Option<[u8; 16]> {
    let bytes = key.as_bytes32();
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&bytes[..16]);
    // Reject obviously empty prefix (all zeros is extremely unlikely for a real key)
    if prefix == [0u8; 16] {
        return None;
    }
    // Filter out length metadata keys (stripe = u64::MAX marker)
    let stripe = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    if stripe == u64::MAX {
        return None;
    }
    Some(prefix)
}

/// Construct a shard key from an object prefix (16 bytes) instead of the full ObjectKey.
/// Used during repair when we only have the prefix from extract_base_key.
fn shard_key_from_prefix(prefix: &[u8; 16], stripe: usize, shard: usize) -> ObjectKey {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(prefix);
    out[16..24].copy_from_slice(&(stripe as u64).to_le_bytes());
    out[24..32].copy_from_slice(&(shard as u64).to_le_bytes());
    ObjectKey::from_bytes(out)
}

/// Probe all mapped stores for stripe 0. Returns stripe count, or 0 if
/// no store has one of the object's logical shards.
fn probe_stripe_count_all(
    stores: &[LocalObjectStore],
    key: ObjectKey,
    sw: usize,
    shard_to_store: &HashMap<usize, usize>,
) -> usize {
    let mut healthy: Option<usize> = None;
    for i in 0..sw {
        let store_idx = mapped_store_index(shard_to_store, i, sw);
        let probe_key = shard_object_key(key, 0, i);
        match stores[store_idx].get(probe_key) {
            Ok(Some(_)) => {
                healthy = Some(i);
                break;
            }
            _ => continue,
        }
    }
    let h = match healthy {
        Some(i) => i,
        None => return 0,
    };
    let healthy_store = mapped_store_index(shard_to_store, h, sw);

    // Count stripes from the found healthy store using its shard index.
    let mut n = 1usize;
    loop {
        let probe_key = shard_object_key(key, n, h);
        match stores[healthy_store].get(probe_key) {
            Ok(Some(_)) => n += 1,
            _ => break,
        }
    }
    n
}

/// Collect unique base object keys from all healthy stores (excluding store_index).
fn collect_base_keys(
    stores: &[LocalObjectStore],
    store_index: usize,
) -> std::collections::BTreeSet<[u8; 16]> {
    let mut keys = std::collections::BTreeSet::new();
    for (i, store) in stores.iter().enumerate() {
        if i == store_index {
            continue;
        }
        for obj_key in store.list_keys() {
            if let Some(prefix) = extract_base_key(obj_key) {
                keys.insert(prefix);
            }
        }
    }
    keys
}

fn mapped_store_index(
    shard_to_store: &HashMap<usize, usize>,
    shard_index: usize,
    store_count: usize,
) -> usize {
    let mapped = shard_to_store
        .get(&shard_index)
        .copied()
        .unwrap_or(shard_index);
    if mapped < store_count {
        mapped
    } else {
        shard_index
    }
}

/// Compute the shard_index → store_index mapping from placement config.
///
/// When `failure_domain` and `device_candidates` are both `Some`, uses
/// [`PlacementPlan::assign_devices`] to determine which device (and thus
/// which store) receives each shard. Falls back to identity mapping
/// (`shard i → store i`) when placement info is missing or incomplete.
fn compute_shard_to_store(config: &ErasureCodedStoreConfig) -> HashMap<usize, usize> {
    let total = config.store_count();
    let mut map: HashMap<usize, usize> = (0..total).map(|i| (i, i)).collect();

    if let (Some(ref fd), Some(ref candidates)) =
        (&config.failure_domain, &config.device_candidates)
    {
        if candidates.len() == total {
            let layout = tidefs_durability_layout::DurabilityLayoutV1::erasure(
                config.data_shards as u8,
                config.parity_shards as u8,
            );
            if let Ok(layout) = layout {
                let plan = PlacementPlan::from_layout(layout, *fd);
                if let Ok(assignments) = plan.assign_devices(candidates) {
                    let device_to_store: HashMap<u64, usize> = candidates
                        .iter()
                        .enumerate()
                        .map(|(idx, dc)| (dc.device_id, idx))
                        .collect();

                    let mut mapped = HashMap::with_capacity(total);
                    for a in &assignments {
                        let shard_idx = a.shard_index as usize;
                        if shard_idx < total {
                            if let Some(&store_idx) = device_to_store.get(&a.device_id) {
                                if store_idx < total {
                                    mapped.insert(shard_idx, store_idx);
                                }
                            }
                        }
                    }
                    if mapped.len() == total {
                        map = mapped;
                    }
                }
            }
        }
    }

    map
}

// ── Async runtime implementation ──────────────────────────────────────

/// Async erasure-coded store runtime.
///
/// Wraps an [`ErasureCodedStore`] behind an `Arc<Mutex<>>` to provide
/// async-safe access. Each operation type (`EcWritePath`, `EcReadPath`,
/// `EcRepairPath`) is a single-use executor produced by this runtime.
pub struct EcStoreRuntime {
    store: Arc<Mutex<ErasureCodedStore>>,
}

impl EcStoreRuntime {
    /// Wrap an existing `ErasureCodedStore` for async access.
    #[must_use]
    pub fn new(store: ErasureCodedStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// Create a write path executor.
    #[must_use]
    pub fn write_path(&self, name: impl AsRef<[u8]>, payload: Vec<u8>) -> EcWritePath {
        EcWritePath {
            store: Arc::clone(&self.store),
            name: name.as_ref().to_vec(),
            payload,
        }
    }

    /// Create a read path executor.
    #[must_use]
    pub fn read_path(&self, name: impl AsRef<[u8]>) -> EcReadPath {
        EcReadPath {
            store: Arc::clone(&self.store),
            name: name.as_ref().to_vec(),
        }
    }

    /// Create a repair path executor.
    #[must_use]
    pub fn repair_path(&self, store_index: usize) -> EcRepairPath {
        EcRepairPath {
            store: Arc::clone(&self.store),
            store_index,
        }
    }

    /// Access the underlying store reference count (for testing).
    #[must_use]
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.store)
    }
}

/// Single-use async executor for EC encode + dispatch.
///
/// Created by [`EcStoreRuntime::write_path`].
pub struct EcWritePath {
    store: Arc<Mutex<ErasureCodedStore>>,
    name: Vec<u8>,
    payload: Vec<u8>,
}

impl EcWritePath {
    /// Execute the write path: encode payload, dispatch shards to stores.
    ///
    /// Uses `tokio::task::spawn_blocking` for CPU-bound encode and
    /// synchronous store I/O.
    pub async fn execute(self) -> Result<EcWriteResult, EcStoreError> {
        let store = Arc::clone(&self.store);
        let name = self.name;
        let payload = self.payload;

        tokio::task::spawn_blocking(move || {
            let mut s = store.blocking_lock();
            let cap = s.config.data_capacity();
            let sw = s.config.store_count();
            let original_len = payload.len();
            let num_stripes = if original_len == 0 {
                1
            } else {
                original_len.div_ceil(cap)
            };

            let stripe_config = StripeConfig {
                data_shards: s.config.data_shards,
                parity_shards: s.config.parity_shards,
                shard_len: s.config.shard_len,
            };

            // Store total original payload length as metadata
            let key = ObjectKey::from_name(&name);
            let len_key = len_object_key(key);
            let len_bytes = (original_len as u64).to_le_bytes().to_vec();
            for i in 0..sw {
                let _ = s.stores[i].put(len_key, &len_bytes);
            }

            let object_prefix = object_prefix(key);
            let mut shards_dispatched: usize = 0;
            let shards_total = sw * num_stripes;
            let mut store_healthy = vec![true; sw];

            for stripe_idx in 0..num_stripes {
                let start = stripe_idx * cap;
                let end = (original_len).min(start + cap);
                let chunk = if start < original_len {
                    &payload[start..end]
                } else {
                    &[]
                };

                let encoded = encode(&stripe_config, chunk).ok_or_else(|| {
                    EcStoreError::EncodeFailed(format!("encode failed for stripe {stripe_idx}"))
                })?;

                for shard in &encoded.shards {
                    let shard_key = shard_object_key(key, stripe_idx, shard.index);
                    let shard_record = encode_verified_shard(
                        &object_prefix,
                        stripe_idx,
                        shard.index,
                        &shard.bytes,
                    )
                    .map_err(EcStoreError::Internal)?;

                    let store_idx = mapped_store_index(&s.shard_to_store, shard.index, sw);
                    match s.stores[store_idx].put(shard_key, &shard_record) {
                        Ok(_) => {
                            shards_dispatched += 1;
                            s.stats.bytes_stored += shard_record.len() as u64;
                        }
                        Err(e) => {
                            store_healthy[store_idx] = false;
                            return Err(EcStoreError::DispatchFailed {
                                shard: shard.index,
                                reason: e.to_string(),
                            });
                        }
                    }
                }
            }

            s.stats.object_count += 1;
            s.stats.stripes_written += num_stripes as u64;
            s.stats.bytes_written += original_len as u64;
            s.stats.shards_written += shards_dispatched as u64;
            s.stats.store_healthy = store_healthy;
            increment_cell(&s.stats.encodes);

            Ok(EcWriteResult {
                shards_dispatched,
                shards_total,
                bytes_encoded: original_len as u64,
            })
        })
        .await
        .map_err(|e| EcStoreError::Internal(format!("spawn_blocking join error: {e}")))?
    }
}

/// Single-use async executor for EC fetch + decode.
///
/// Created by [`EcStoreRuntime::read_path`].
pub struct EcReadPath {
    store: Arc<Mutex<ErasureCodedStore>>,
    name: Vec<u8>,
}

impl EcReadPath {
    /// Execute the read path: fetch shards, fallback on missing, decode.
    ///
    /// Tries to read all k+m shards. If a shard is missing or corrupt,
    /// skips it and relies on having >= k shards for reconstruction.
    pub async fn execute(self) -> Result<Option<EcReadResult>, EcStoreError> {
        let store = Arc::clone(&self.store);
        let name = self.name;

        tokio::task::spawn_blocking(move || {
            let s = store.blocking_lock();
            let key = ObjectKey::from_name(&name);
            let sw = s.config.store_count();
            let object_prefix = object_prefix(key);

            let stripe_config = StripeConfig {
                data_shards: s.config.data_shards,
                parity_shards: s.config.parity_shards,
                shard_len: s.config.shard_len,
            };

            // Probe stripe count from all stores
            let num_stripes = probe_stripe_count_all(&s.stores, key, sw, &s.shard_to_store);
            if num_stripes == 0 {
                return Ok(None);
            }

            // Read total original payload length metadata
            let len_key = len_object_key(key);
            let mut total_original_len: Option<usize> = None;
            for i in 0..sw {
                if let Ok(Some(bytes)) = s.stores[i].get(len_key) {
                    if bytes.len() >= 8 {
                        total_original_len =
                            Some(u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize);
                        break;
                    }
                }
            }

            let cap = s.config.data_capacity();
            let default_cap = match total_original_len {
                Some(len) => len.max(num_stripes * cap),
                None => num_stripes * cap,
            };
            let mut result = Vec::with_capacity(default_cap);
            let mut degraded = false;
            let mut shards_read: usize = 0;
            let mut fallbacks_used: usize = 0;

            for stripe_idx in 0..num_stripes {
                let mut available: Vec<Option<ErasureShard>> = Vec::with_capacity(sw);

                for i in 0..sw {
                    let sk = shard_object_key(key, stripe_idx, i);
                    let store_idx = mapped_store_index(&s.shard_to_store, i, sw);
                    match s.stores[store_idx].get(sk) {
                        Ok(Some(record)) => {
                            shards_read += 1;
                            match decode_verified_shard(&object_prefix, stripe_idx, i, &record) {
                                Ok(bytes) => {
                                    increment_cell(&s.stats.shards_verified);
                                    let kind = if i < s.config.data_shards {
                                        ShardKind::Data
                                    } else {
                                        ShardKind::Parity
                                    };
                                    available.push(Some(ErasureShard {
                                        index: i,
                                        kind,
                                        bytes,
                                    }));
                                }
                                Err(e) => {
                                    increment_cell(&s.stats.shard_verification_failures);
                                    eprintln!(
                                        "store {store_idx} shard {i} verify failed for stripe {stripe_idx}: {e}"
                                    );
                                    available.push(None);
                                    degraded = true;
                                    fallbacks_used += 1;
                                }
                            }
                        }
                        Ok(None) => {
                            available.push(None);
                            degraded = true;
                            fallbacks_used += 1;
                            increment_cell(&s.stats.missing_shard_fallbacks);
                        }
                        Err(e) => {
                            eprintln!(
                                "store {store_idx} read failed for stripe {stripe_idx} shard {i}: {e}"
                            );
                            available.push(None);
                            degraded = true;
                            fallbacks_used += 1;
                            increment_cell(&s.stats.missing_shard_fallbacks);
                        }
                    }
                }

                let recon = reconstruct(&stripe_config, &available, None).ok_or_else(|| {
                    increment_cell(&s.stats.failed_reads);
                    EcStoreError::InsufficientShards {
                        available: available.iter().filter(|s| s.is_some()).count(),
                        needed: s.config.data_shards,
                    }
                })?;

                let stripe_chunk_len = match total_original_len {
                    Some(_len) if stripe_idx + 1 < num_stripes => cap,
                    Some(len) => len.saturating_sub(stripe_idx * cap),
                    None => recon.payload.len(),
                };
                let effective = stripe_chunk_len.min(recon.payload.len());
                result.extend_from_slice(&recon.payload[..effective]);
            }

            if degraded {
                s.stats.degraded_reads.set(s.stats.degraded_reads.get() + 1);
            } else {
                s.stats.clean_reads.set(s.stats.clean_reads.get() + 1);
            }
            increment_cell(&s.stats.decodes);
            s.stats
                .shards_read
                .set(s.stats.shards_read.get().saturating_add(shards_read as u64));

            Ok(Some(EcReadResult {
                payload: result,
                shards_read,
                fallbacks_used,
                degraded,
            }))
        })
        .await
        .map_err(|e| EcStoreError::Internal(format!("spawn_blocking join error: {e}")))?
    }
}

/// Single-use async executor for EC repair.
///
/// Created by [`EcStoreRuntime::repair_path`].
pub struct EcRepairPath {
    store: Arc<Mutex<ErasureCodedStore>>,
    store_index: usize,
}

impl EcRepairPath {
    /// Execute the repair path: reconstruct missing shards for a store
    /// from surviving shards on other stores.
    ///
    /// Returns the number of shards repaired.
    pub async fn execute(self) -> Result<usize, EcStoreError> {
        let store = Arc::clone(&self.store);
        let store_index = self.store_index;

        tokio::task::spawn_blocking(move || {
            let mut s = store.blocking_lock();

            if store_index >= s.stores.len() {
                return Err(EcStoreError::RepairFailed {
                    store_index,
                    reason: "store index out of range".into(),
                });
            }

            let all_prefixes = collect_base_keys(&s.stores, store_index);
            let sw = s.config.store_count();
            let stripe_config = StripeConfig {
                data_shards: s.config.data_shards,
                parity_shards: s.config.parity_shards,
                shard_len: s.config.shard_len,
            };

            let mut repaired = 0usize;

            for prefix in &all_prefixes {
                let mut healthy_shard: Option<usize> = None;
                for i in 0..sw {
                    let probe_key = shard_key_from_prefix(prefix, 0, i);
                    let store_idx = mapped_store_index(&s.shard_to_store, i, sw);
                    if let Ok(Some(_)) = s.stores[store_idx].get(probe_key) {
                        healthy_shard = Some(i);
                        break;
                    }
                }
                let h = match healthy_shard {
                    Some(i) => i,
                    None => continue,
                };
                let healthy_store = mapped_store_index(&s.shard_to_store, h, sw);

                let mut num_stripes = 1usize;
                loop {
                    let probe_key = shard_key_from_prefix(prefix, num_stripes, h);
                    match s.stores[healthy_store].get(probe_key) {
                        Ok(Some(_)) => num_stripes += 1,
                        _ => break,
                    }
                }

                for stripe_idx in 0..num_stripes {
                    let mut available: Vec<Option<ErasureShard>> =
                        Vec::with_capacity(sw);
                    for i in 0..sw {
                        let sk = shard_key_from_prefix(prefix, stripe_idx, i);
                        let store_idx = mapped_store_index(&s.shard_to_store, i, sw);
                        match s.stores[store_idx].get(sk) {
                            Ok(Some(record)) => {
                                match decode_verified_shard(
                                    prefix,
                                    stripe_idx,
                                    i,
                                    &record,
                                ) {
                                    Ok(bytes) => {
                                        increment_cell(&s.stats.shards_verified);
                                        let kind = if i < s.config.data_shards {
                                            ShardKind::Data
                                        } else {
                                            ShardKind::Parity
                                        };
                                        available.push(Some(ErasureShard {
                                            index: i,
                                            kind,
                                            bytes,
                                        }));
                                    }
                                    Err(e) => {
                                        increment_cell(
                                            &s.stats.shard_verification_failures,
                                        );
                                        eprintln!(
                                            "store {store_idx} shard {i} verify failed for stripe {stripe_idx}: {e}"
                                        );
                                        available.push(None);
                                    }
                                }
                            }
                            _ => available.push(None),
                        }
                    }

                    if let Some(recon) = reconstruct(&stripe_config, &available, None) {
                        for rebuilt in &recon.rebuilt_shards {
                            let target_store =
                                mapped_store_index(&s.shard_to_store, rebuilt.index, sw);
                            if target_store == store_index {
                                let sk = shard_key_from_prefix(
                                    prefix,
                                    stripe_idx,
                                    rebuilt.index,
                                );
                                let shard_record = encode_verified_shard(
                                    prefix,
                                    stripe_idx,
                                    rebuilt.index,
                                    &rebuilt.bytes,
                                )
                                .map_err(EcStoreError::Internal)?;
                                s.stores[target_store]
                                    .put(sk, &shard_record)
                                    .map_err(|e| {
                                        EcStoreError::RepairFailed {
                                            store_index,
                                            reason: format!(
                                                "repair write failed for shard {}: {e}",
                                                rebuilt.index,
                                            ),
                                        }
                                    })?;
                                repaired += 1;
                            }
                        }
                    }
                }
            }

            if store_index < s.stats.store_healthy.len() {
                s.stats.store_healthy[store_index] = true;
            }
            increment_cell(&s.stats.repairs);

            Ok(repaired)
        })
        .await
        .map_err(|e| EcStoreError::Internal(format!("spawn_blocking join error: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tidefs_durability_layout::{FailureDomainLevel, FailureDomainV1};

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tidefs-ec-{label}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_dirs(dirs: &[PathBuf]) {
        for d in dirs {
            let _ = fs::remove_dir_all(d);
        }
    }

    fn make_paths(n: usize, label: &str) -> Vec<PathBuf> {
        (0..n).map(|i| temp_dir(&format!("{label}-r{i}"))).collect()
    }

    fn device_candidate(device_id: u64) -> DeviceCandidate {
        DeviceCandidate {
            device_id,
            node_id: None,
            rack_id: None,
            datacenter_id: None,
        }
    }

    // --- 2+1 basic put/get ---

    #[test]
    fn two_plus_one_put_get() {
        let paths = make_paths(3, "2p1");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        store.put_named("hello", b"world").unwrap();

        let data = store.get_named("hello").unwrap();
        assert_eq!(data, Some(b"world".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- 2+1 large payload (multi-stripe) ---

    #[test]
    fn two_plus_one_large_payload() {
        let paths = make_paths(3, "2p1big");
        let cfg = ErasureCodedStoreConfig::two_plus_one_test();
        let cap = cfg.data_capacity(); // 2 * 256 = 512
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        // Write 3x capacity to trigger multi-stripe
        let payload: Vec<u8> = (0..(cap * 3 + 100) as u16)
            .map(|i| (i % 251) as u8)
            .collect();
        store.put_named("big", &payload).unwrap();

        let data = store.get_named("big").unwrap();
        assert_eq!(data, Some(payload));

        // Check multi-stripe stats
        assert!(store.stats().stripes_written >= 4);

        cleanup_dirs(&paths);
    }

    // --- 2+1 delete ---

    #[test]
    fn two_plus_one_delete() {
        let paths = make_paths(3, "2p1del");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        store.put_named("x", b"data").unwrap();
        assert!(store.get_named("x").unwrap().is_some());

        let deleted = store.delete_named("x").unwrap();
        assert!(deleted);
        assert_eq!(store.get_named("x").unwrap(), None);

        cleanup_dirs(&paths);
    }

    // --- Nonexistent read ---

    #[test]
    fn get_nonexistent() {
        let paths = make_paths(3, "2p1none");
        let store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        assert_eq!(store.get_named("nope").unwrap(), None);

        cleanup_dirs(&paths);
    }

    // --- Degraded read: one shard missing, reconstruct from survivors ---

    #[test]
    fn degraded_read_reconstructs() {
        let paths = make_paths(3, "degraded");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        store.put_named("resilient", b"survives-loss").unwrap();

        // Simulate store 0 failure: delete all objects from store 0
        let all_keys: Vec<_> = store.stores[0].list_keys();
        for k in &all_keys {
            store.stores[0].delete(*k).unwrap();
        }

        // Read should still succeed via reconstruction
        let data = store.get_named("resilient").unwrap();
        assert_eq!(data, Some(b"survives-loss".to_vec()));

        // Should be tracked as degraded read
        assert!(store.stats().degraded_reads.get() >= 1);

        cleanup_dirs(&paths);
    }

    // --- Degraded read: two shards missing with single parity -> fail ---

    #[test]
    fn degraded_read_fails_with_too_many_losses() {
        let paths = make_paths(3, "fail");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        store.put_named("doomed", b"lost").unwrap();

        // Delete from stores 0 and 1 (2 data shards, only 1 parity survives)
        let k0: Vec<_> = store.stores[0].list_keys();
        for k in &k0 {
            store.stores[0].delete(*k).unwrap();
        }
        let k1: Vec<_> = store.stores[1].list_keys();
        for k in &k1 {
            store.stores[1].delete(*k).unwrap();
        }

        // Read should fail
        let result = store.get_named("doomed");
        assert!(result.is_err());

        cleanup_dirs(&paths);
    }

    // --- 4+2 put/get ---

    #[test]
    fn four_plus_two_put_get() {
        let paths = make_paths(6, "4p2");
        let mut store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 512,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();

        store.put_named("data", b"four-plus-two-test").unwrap();

        let data = store.get_named("data").unwrap();
        assert_eq!(data, Some(b"four-plus-two-test".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- Empty payload ---

    #[test]
    fn empty_payload() {
        let paths = make_paths(3, "empty");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        store.put_named("empty", b"").unwrap();

        let data = store.get_named("empty").unwrap();
        assert_eq!(data, Some(b"".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- Sync and reopen ---

    #[test]
    fn reopen_preserves_data() {
        let paths = make_paths(3, "reopen");

        {
            let mut store =
                ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test())
                    .unwrap();
            store.put_named("persist", b"survives-reopen").unwrap();
            store.sync_all().unwrap();
        }

        {
            let store =
                ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test())
                    .unwrap();
            let data = store.get_named("persist").unwrap();
            assert_eq!(data, Some(b"survives-reopen".to_vec()));
        }

        cleanup_dirs(&paths);
    }

    // --- Repair: rebuild missing shards ---

    #[test]
    fn repair_restores_missing_shards() {
        let paths = make_paths(3, "repair");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        store.put_named("r", b"repair-me").unwrap();

        // Wipe store 0
        let k0: Vec<_> = store.stores[0].list_keys();
        for k in &k0 {
            store.stores[0].delete(*k).unwrap();
        }

        // Repair store 0
        let repaired = store.repair_store(0).unwrap();
        assert!(repaired >= 1);

        // Verify store 0 has data again
        let k0_after = store.stores[0].list_keys();
        assert!(!k0_after.is_empty());

        // Read should now be clean
        let data = store.get_named("r").unwrap();
        assert_eq!(data, Some(b"repair-me".to_vec()));

        cleanup_dirs(&paths);
    }

    #[test]
    fn placement_mapping_routes_sync_read_repair_and_delete() {
        let paths = make_paths(3, "placed");
        let cfg = ErasureCodedStoreConfig {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 64,
            store_options: StoreOptions::test_fast(),
            failure_domain: Some(FailureDomainV1::new(FailureDomainLevel::Device, 3).unwrap()),
            device_candidates: Some(vec![
                device_candidate(30),
                device_candidate(20),
                device_candidate(10),
            ]),
        };
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        assert_eq!(store.shard_to_store.get(&0), Some(&2));
        assert_eq!(store.shard_to_store.get(&1), Some(&1));
        assert_eq!(store.shard_to_store.get(&2), Some(&0));

        let name = b"placed-object";
        let key = ObjectKey::from_name(name);
        let payload = b"placement-backed erasure coded payload".to_vec();
        store.put_named(name, &payload).unwrap();

        assert!(store.stores[2]
            .get(shard_object_key(key, 0, 0))
            .unwrap()
            .is_some());
        assert!(store.stores[0]
            .get(shard_object_key(key, 0, 2))
            .unwrap()
            .is_some());
        assert!(store.stores[0]
            .get(shard_object_key(key, 0, 0))
            .unwrap()
            .is_none());

        let physical_store_2_keys: Vec<_> = store.stores[2].list_keys();
        for key in &physical_store_2_keys {
            store.stores[2].delete(*key).unwrap();
        }

        assert_eq!(store.get_named(name).unwrap(), Some(payload.clone()));
        assert!(store.stats().degraded_reads.get() >= 1);

        let flushed = store.flush_repairs();
        assert!(flushed >= 1);
        assert!(store.stores[2]
            .get(shard_object_key(key, 0, 0))
            .unwrap()
            .is_some());

        let physical_store_2_keys: Vec<_> = store.stores[2].list_keys();
        for key in &physical_store_2_keys {
            store.stores[2].delete(*key).unwrap();
        }

        let repaired = store.repair_store(2).unwrap();
        assert!(repaired >= 1);
        assert!(store.stores[2]
            .get(shard_object_key(key, 0, 0))
            .unwrap()
            .is_some());
        assert_eq!(store.get_named(name).unwrap(), Some(payload));

        assert!(store.delete_named(name).unwrap());
        assert_eq!(store.get_named(name).unwrap(), None);
        assert!(store.stores[2]
            .get(shard_object_key(key, 0, 0))
            .unwrap()
            .is_none());
        assert!(store.stores[0]
            .get(shard_object_key(key, 0, 2))
            .unwrap()
            .is_none());

        cleanup_dirs(&paths);
    }

    // --- Multi-object storage ---

    #[test]
    fn multiple_objects() {
        let paths = make_paths(3, "multi");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        for i in 0..10 {
            let key = format!("obj-{i}");
            let val = format!("value-{i}");
            store.put_named(&key, val.as_bytes()).unwrap();
        }

        assert_eq!(store.stats().object_count, 10);

        for i in 0..10 {
            let key = format!("obj-{i}");
            let data = store.get_named(&key).unwrap();
            assert_eq!(data, Some(format!("value-{i}").into_bytes()));
        }

        cleanup_dirs(&paths);
    }

    // --- Error: path count mismatch ---

    #[test]
    fn path_count_mismatch_rejected() {
        let paths = make_paths(2, "mismatch");
        let result = ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test());
        assert!(result.is_err());
        cleanup_dirs(&paths);
    }

    // --- Error: empty paths ---

    #[test]
    fn empty_paths_rejected() {
        let cfg = ErasureCodedStoreConfig::two_plus_one_test();
        let result = ErasureCodedStore::open(&[], cfg);
        assert!(result.is_err());
    }

    // --- 4+2 survives 2 losses ---

    #[test]
    fn four_plus_two_survives_two_losses() {
        let paths = make_paths(6, "4p2loss");
        let mut store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 512,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();

        let payload: Vec<u8> = (0..2000u16).map(|i| (i % 251) as u8).collect();
        store.put_named("survivor", &payload).unwrap();

        // Delete shards from stores 0 and 1
        let k0: Vec<_> = store.stores[0].list_keys();
        for k in &k0 {
            store.stores[0].delete(*k).unwrap();
        }
        let k1: Vec<_> = store.stores[1].list_keys();
        for k in &k1 {
            store.stores[1].delete(*k).unwrap();
        }

        let data = store.get_named("survivor").unwrap();
        assert_eq!(data, Some(payload));

        cleanup_dirs(&paths);
    }

    // --- 8+3 survives 3 losses ---

    #[test]
    fn eight_plus_three_survives_three_losses() {
        let paths = make_paths(11, "8p3loss");
        let mut store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 8,
                parity_shards: 3,
                shard_len: 256,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();

        store.put_named("octo", b"eight-plus-three-data").unwrap();

        // Delete 3 stores
        for i in 0..3 {
            let keys: Vec<_> = store.stores[i].list_keys();
            for k in &keys {
                store.stores[i].delete(*k).unwrap();
            }
        }

        let data = store.get_named("octo").unwrap();
        assert_eq!(data, Some(b"eight-plus-three-data".to_vec()));

        cleanup_dirs(&paths);
    }

    // ── Async runtime tests ──────────────────────────────────────────

    #[tokio::test]
    async fn async_4p2_round_trip() {
        let paths = make_paths(6, "async4p2");
        let store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 512,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();
        let runtime = EcStoreRuntime::new(store);

        let payload: Vec<u8> = (0..2000u16).map(|i| (i % 251) as u8).collect();
        let wp = runtime.write_path("roundtrip", payload.clone());
        let result = wp.execute().await.unwrap();
        assert_eq!(result.shards_dispatched, result.shards_total);
        assert_eq!(result.bytes_encoded, payload.len() as u64);

        let rp = runtime.read_path("roundtrip");
        let read = rp.execute().await.unwrap().unwrap();
        assert_eq!(read.payload, payload);
        assert!(!read.degraded);
        assert!(read.fallbacks_used == 0);

        cleanup_dirs(&paths);
    }

    #[tokio::test]
    async fn async_4p2_one_missing_shard() {
        let paths = make_paths(6, "async4p2miss1");
        let mut store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 512,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();

        let payload: Vec<u8> = (0..1000u16).map(|i| (i % 199) as u8).collect();
        store.put_named("resilient", &payload).unwrap();

        // Delete store 0 shards
        let k0: Vec<_> = store.stores[0].list_keys();
        for k in &k0 {
            store.stores[0].delete(*k).unwrap();
        }

        let runtime = EcStoreRuntime::new(store);
        let rp = runtime.read_path("resilient");
        let read = rp.execute().await.unwrap().unwrap();
        assert_eq!(read.payload, payload);
        assert!(read.degraded);
        assert!(read.fallbacks_used >= 1);

        cleanup_dirs(&paths);
    }

    #[tokio::test]
    async fn async_4p2_two_missing_shards() {
        let paths = make_paths(6, "async4p2miss2");
        let mut store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 512,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();

        let payload: Vec<u8> = (0..1000u16).map(|i| (i % 199) as u8).collect();
        store.put_named("resilient2", &payload).unwrap();

        // Delete stores 0 and 1
        for i in 0..2 {
            let keys: Vec<_> = store.stores[i].list_keys();
            for k in &keys {
                store.stores[i].delete(*k).unwrap();
            }
        }

        let runtime = EcStoreRuntime::new(store);
        let rp = runtime.read_path("resilient2");
        let read = rp.execute().await.unwrap().unwrap();
        assert_eq!(read.payload, payload);
        assert!(read.degraded);

        cleanup_dirs(&paths);
    }

    #[tokio::test]
    async fn async_4p2_three_missing_shards_fails() {
        let paths = make_paths(6, "async4p2miss3");
        let mut store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 512,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();

        store.put_named("doomed", b"lost-data").unwrap();

        // Delete stores 0, 1, 2 (3 losses, but 4+2 can only survive 2)
        for i in 0..3 {
            let keys: Vec<_> = store.stores[i].list_keys();
            for k in &keys {
                store.stores[i].delete(*k).unwrap();
            }
        }

        let runtime = EcStoreRuntime::new(store);
        let rp = runtime.read_path("doomed");
        let result = rp.execute().await;
        assert!(result.is_err());
        // Verify it's the right error kind
        match result.unwrap_err() {
            EcStoreError::InsufficientShards { available, needed } => {
                assert!(available < needed);
            }
            _ => panic!("expected InsufficientShards"),
        }

        cleanup_dirs(&paths);
    }

    #[tokio::test]
    async fn async_repair_reconstructs_shard() {
        let paths = make_paths(3, "asyncrepair");
        let mut store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();

        store.put_named("r", b"repair-me-async").unwrap();

        // Wipe store 0
        let k0: Vec<_> = store.stores[0].list_keys();
        for k in &k0 {
            store.stores[0].delete(*k).unwrap();
        }

        let runtime = EcStoreRuntime::new(store);
        let repair = runtime.repair_path(0);
        let repaired = repair.execute().await.unwrap();
        assert!(repaired >= 1);

        // Verify clean read after repair
        let rp = runtime.read_path("r");
        let read = rp.execute().await.unwrap().unwrap();
        assert_eq!(read.payload, b"repair-me-async");
        assert!(!read.degraded);

        cleanup_dirs(&paths);
    }

    #[tokio::test]
    async fn async_concurrent_encode_decode() {
        let paths = make_paths(6, "asyncconcur");
        let store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 512,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();
        let runtime = std::sync::Arc::new(EcStoreRuntime::new(store));

        // Concurrent writes
        let mut handles = Vec::new();
        for i in 0..8 {
            let rt = runtime.clone();
            let payload: Vec<u8> = (0..256u16)
                .map(|j| (j as u8).wrapping_add(i as u8))
                .collect();
            handles.push(tokio::spawn(async move {
                let wp = rt.write_path(format!("obj-{i}"), payload.clone());
                wp.execute().await.unwrap();
                payload
            }));
        }

        let mut payloads = Vec::new();
        for h in handles {
            payloads.push(h.await.unwrap());
        }

        // Concurrent reads
        let mut read_handles = Vec::new();
        for i in 0..8 {
            let rt = runtime.clone();
            let expected = payloads[i].clone();
            read_handles.push(tokio::spawn(async move {
                let rp = rt.read_path(format!("obj-{i}"));
                let read = rp.execute().await.unwrap().unwrap();
                assert_eq!(read.payload, expected, "mismatch obj-{i}");
            }));
        }

        for h in read_handles {
            h.await.unwrap();
        }

        cleanup_dirs(&paths);
    }

    #[tokio::test]
    async fn async_large_data_multi_stripe() {
        // 256 KB payload with 256-byte shards, 4+2 config
        // 4 data shards * 256 bytes = 1 KB per stripe -> ~256 stripes
        let paths = make_paths(6, "asynclarge");
        let store = ErasureCodedStore::open(
            &paths,
            ErasureCodedStoreConfig {
                data_shards: 4,
                parity_shards: 2,
                shard_len: 256,
                store_options: StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            },
        )
        .unwrap();
        let runtime = EcStoreRuntime::new(store);

        let size: usize = 256 * 1024; // 256 KB
        let payload: Vec<u8> = (0..size)
            .map(|i| ((i as u64).wrapping_mul(0x9E3779B9).wrapping_add(i as u64)) as u8)
            .collect();

        let wp = runtime.write_path("large", payload.clone());
        let result = wp.execute().await.unwrap();
        assert_eq!(result.bytes_encoded, size as u64);
        // 4 data shards + 2 parity = 6 shards per stripe, ~256 stripes -> 1536 shards
        assert!(result.shards_dispatched >= 200 * 6);

        let rp = runtime.read_path("large");
        let read = rp.execute().await.unwrap().unwrap();
        assert_eq!(read.payload, payload);
        assert!(!read.degraded);
        assert!(read.shards_read >= result.shards_dispatched);

        cleanup_dirs(&paths);
    }
    #[tokio::test]
    async fn async_write_then_read_nonexistent_is_none() {
        let paths = make_paths(3, "asyncnone");
        let store =
            ErasureCodedStore::open(&paths, ErasureCodedStoreConfig::two_plus_one_test()).unwrap();
        let runtime = EcStoreRuntime::new(store);

        let rp = runtime.read_path("nope");
        let result = rp.execute().await.unwrap();
        assert!(result.is_none());

        cleanup_dirs(&paths);
    }

    #[tokio::test]
    async fn async_ec_store_error_display() {
        assert_eq!(
            EcStoreError::EncodeFailed("bad".into()).to_string(),
            "encode failed: bad"
        );
        assert_eq!(
            EcStoreError::InsufficientShards {
                available: 1,
                needed: 4
            }
            .to_string(),
            "insufficient shards: 1 available, 4 needed"
        );
        assert_eq!(
            EcStoreError::DispatchFailed {
                shard: 2,
                reason: "io".into()
            }
            .to_string(),
            "dispatch to shard 2 failed: io"
        );
        assert_eq!(
            EcStoreError::RepairFailed {
                store_index: 3,
                reason: "gone".into()
            }
            .to_string(),
            "repair of store 3 failed: gone"
        );
        assert_eq!(
            EcStoreError::Internal("boom".into()).to_string(),
            "internal error: boom"
        );
    }
    // --- Async placement-aware write path test -------------------------------

    /// Verify that the async write path honors placement-planner-determined
    /// shard-to-store mapping when placement config is provided.  Uses exactly
    /// N stores for N shards with each device in a distinct failure domain,
    /// exercising the placement code path through the async EcWritePath.
    #[tokio::test]
    async fn async_write_path_uses_placement_mapping() {
        use tidefs_durability_layout::FailureDomainLevel;
        use tidefs_placement_planner::placement_plan::DeviceCandidate;

        // 3 stores for a 2+1 layout — each in a distinct node-level domain.
        let paths = make_paths(3, "async-placement");
        let fd =
            tidefs_durability_layout::FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();

        let candidates: Vec<DeviceCandidate> = (0..3)
            .map(|i| DeviceCandidate {
                device_id: i as u64,
                node_id: Some(i as u64), // each device on its own node
                rack_id: None,
                datacenter_id: None,
            })
            .collect();

        let config = ErasureCodedStoreConfig {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 128,
            store_options: StoreOptions::test_fast(),
            failure_domain: Some(fd),
            device_candidates: Some(candidates),
        };

        let store = ErasureCodedStore::open(&paths, config).unwrap();
        let runtime = EcStoreRuntime::new(store);

        // Write a small payload (fits in one stripe).
        let payload = b"placement-async".to_vec();
        let wp = runtime.write_path("placement-async", payload.clone());
        let result = wp.execute().await.unwrap();
        assert!(result.shards_dispatched > 0);

        // Read back to verify correctness.
        let rp = runtime.read_path("placement-async");
        let read = rp.execute().await.unwrap().unwrap();
        assert_eq!(read.payload, payload);

        cleanup_dirs(&paths);
    }
}
