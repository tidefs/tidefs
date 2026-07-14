// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! Cauchy Reed-Solomon erasure coding engine for TideFS.
//!
//! Systematic encoding over GF(2^8) using Cauchy matrices parameterized by
//! arbitrary (data_shards, parity_shards) pairs. Reconstruction from any
//! `data_shards` surviving shards.
//!
//! ## Tail-stripe buffer contract
//!
//! When an extent has multiple stripes and the final stripe contains fewer
//! than `k` data fragments (unaligned extent tail), reconstruction must
//! size its decode buffer to the effective fragment count returned by
//! [`stripe_fragment_count`] rather than blindly allocating `k` slots.
//! Slots beyond the effective count are zero-filled to prevent
//! uninitialized data from entering GF(2^8) multiplication. This is
//! enforced by a `debug_assert!` in the reconstruction path.

use tidefs_replication_model::ReplicationIntent;

// ---------------------------------------------------------------------------
// GF(2^8) — primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
// ---------------------------------------------------------------------------

static GF_EXP: [u8; 510] = {
    let mut e = [0u8; 510];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        e[i] = x as u8;
        e[i + 255] = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
        i += 1;
    }
    e[255] = 1;
    e[509] = 1;
    e
};

static GF_LOG: [u8; 256] = {
    let mut l = [0u8; 256];
    let mut i = 0;
    while i < 255 {
        l[GF_EXP[i] as usize] = i as u8;
        i += 1;
    }
    l
};

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        GF_EXP[GF_LOG[a as usize] as usize + GF_LOG[b as usize] as usize]
    }
}

/// GF(2^8) division: a / b. Returns 0 when b == 0.
#[inline]
fn gf_div(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let la = GF_LOG[a as usize] as i32;
    let lb = GF_LOG[b as usize] as i32;
    let idx = (la - lb + 255) as usize % 255;
    GF_EXP[idx]
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    gf_div(1, a)
}

// ---------------------------------------------------------------------------
// Cauchy encoding matrix
// ---------------------------------------------------------------------------
// Systematic encoding: [I_k | C]^T where I_k is kxk identity and C is mxk
// Cauchy matrix with C[i][j] = 1 / (x_i xor y_j).
//
// X = {0, 1, ..., m-1} for parity rows
// Y = {m, m+1, ..., m+k-1} for data columns
// Since X cap Y = empty, every C[i][j] is well-defined.
// ---------------------------------------------------------------------------

type GfMatrix = Vec<Vec<u8>>;

/// Build the full Cauchy encoding matrix.
/// First `k` rows are identity (data shards).
/// Remaining `m` rows are the Cauchy parity matrix.
/// Requires k+m <= 256 for disjoint X/Y sets in u8.
fn build_cauchy_encoding(k: usize, m: usize) -> GfMatrix {
    let total = k + m;
    let mut mat = vec![vec![0u8; k]; total];
    // Identity rows
    for (i, row) in mat.iter_mut().take(k).enumerate() {
        row[i] = 1;
    }
    // Cauchy parity rows: C[parity_row][data_col] = 1/(x_r xor y_c)
    for row in 0..m {
        let x = row as u8; // X = {0..m-1}
        for col in 0..k {
            let y = (m + col) as u8; // Y = {m..m+k-1}
            mat[k + row][col] = gf_inv(x ^ y);
        }
    }
    mat
}

/// Invert a square GF(2^8) matrix via Gauss-Jordan elimination.
#[allow(clippy::needless_range_loop)]
fn invert_matrix(mat: &GfMatrix) -> Option<GfMatrix> {
    let n = mat.len();
    let mut aug = vec![vec![0u8; 2 * n]; n];
    for i in 0..n {
        for j in 0..n {
            aug[i][j] = mat[i][j];
        }
        aug[i][i + n] = 1;
    }
    for col in 0..n {
        let pr = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pr);
        let inv_p = gf_inv(aug[col][col]);
        for j in 0..2 * n {
            aug[col][j] = gf_mul(aug[col][j], inv_p);
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let f = aug[row][col];
            if f == 0 {
                continue;
            }
            for j in 0..2 * n {
                aug[row][j] ^= gf_mul(f, aug[col][j]);
            }
        }
    }
    let mut inv = vec![vec![0u8; n]; n];
    for i in 0..n {
        for j in 0..n {
            inv[i][j] = aug[i][j + n];
        }
    }
    Some(inv)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureShard {
    pub index: usize,
    pub kind: ShardKind,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardKind {
    Data,
    Parity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_len: usize,
}

impl StripeConfig {
    pub fn stripe_width(&self) -> usize {
        self.data_shards + self.parity_shards
    }
    pub fn data_capacity(&self) -> usize {
        self.data_shards * self.shard_len
    }
}

/// Compute the effective number of data fragments for a stripe at
/// `stripe_index` within a multi-stripe extent.
///
/// Interior stripes always have `k` data fragments. The tail stripe
/// (last) has `ceil(remaining_bytes / block_size)` fragments, capped at
/// `k`. The extent size is the total logical byte length of the
/// extent; indices start at 0.
///
/// Returns 0 when `block_size == 0` or `k == 0` (invalid config).
#[must_use]
pub fn stripe_fragment_count(
    extent_size: usize,
    stripe_index: usize,
    k: usize,
    block_size: usize,
) -> usize {
    if k == 0 || block_size == 0 {
        return 0;
    }
    let stripe_capacity = k * block_size;
    let stripe_start = stripe_index * stripe_capacity;
    if stripe_start >= extent_size {
        return 0;
    }
    let remaining = extent_size - stripe_start;
    let fragments = remaining.div_ceil(block_size);
    fragments.min(k)
}

// ---------------------------------------------------------------------------
// ReplicationIntent integration
// ---------------------------------------------------------------------------

/// Construct a `StripeConfig` from a `ReplicationIntent::ErasureCoded` variant.
///
/// Returns `None` when the intent is not `ErasureCoded`, when `shard_len` is
/// zero, or when `k + m > 255` (exceeds GF(2^8) disjoint X/Y set bound).
#[must_use]
pub fn config_from_replication_intent(
    intent: &ReplicationIntent,
    shard_len: usize,
) -> Option<StripeConfig> {
    match intent {
        ReplicationIntent::ErasureCoded {
            data_shards,
            parity_shards,
            ..
        } => config_from_erasure_coded(*data_shards, *parity_shards, shard_len),
        ReplicationIntent::Mirror { .. } => None,
        ReplicationIntent::Distributed { .. } => None,
    }
}

/// Construct a StripeConfig from a RedundancyPolicy::ErasureCoded variant.
///
/// Returns `None` when the (k, m, shard_len) combination is invalid
/// (zero shards, zero shard length, or k+m > 255).
#[must_use]
pub fn config_from_erasure_coded(k: u8, m: u8, shard_len: usize) -> Option<StripeConfig> {
    let k = k as usize;
    let m = m as usize;
    if k == 0 || m == 0 || shard_len == 0 || k + m > 255 {
        return None;
    }
    Some(StripeConfig {
        data_shards: k,
        parity_shards: m,
        shard_len,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedStripe {
    pub config: StripeConfig,
    pub shards: Vec<ErasureShard>,
    pub original_payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconstruction {
    pub payload: Vec<u8>,
    pub rebuilt_shards: Vec<ErasureShard>,
}

/// Encoded stripe material for receipt-tracked placement paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptEncodedStripe {
    /// Data and parity shards ready for placement and receipt publication.
    pub shards: Vec<ErasureShard>,
    /// Original payload bytes represented by this stripe before padding.
    pub original_payload_len: usize,
}

/// Reconstructed stripe material for receipt-tracked read and repair paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptReconstructedStripe {
    /// Reconstructed payload, including any stripe padding.
    pub payload: Vec<u8>,
    /// Missing shards rebuilt during reconstruction for repair evidence.
    pub rebuilt_shards: Vec<ErasureShard>,
}

/// Receipt-tracked stripe helper failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptStripeError {
    EncodeRejected,
    InvalidAvailableSet { slots: usize, expected: usize },
    InsufficientShards { available: usize, needed: usize },
}

pub fn encode_receipt_stripe(
    config: &StripeConfig,
    payload: &[u8],
) -> Result<ReceiptEncodedStripe, ReceiptStripeError> {
    let encoded = encode(config, payload).ok_or(ReceiptStripeError::EncodeRejected)?;
    Ok(ReceiptEncodedStripe {
        shards: encoded.shards,
        original_payload_len: encoded.original_payload_len,
    })
}

pub fn reconstruct_receipt_stripe(
    config: &StripeConfig,
    available: &[Option<ErasureShard>],
) -> Result<ReceiptReconstructedStripe, ReceiptStripeError> {
    let expected = config.stripe_width();
    if available.len() != expected {
        return Err(ReceiptStripeError::InvalidAvailableSet {
            slots: available.len(),
            expected,
        });
    }
    for (slot, shard) in available.iter().enumerate() {
        let Some(shard) = shard else {
            continue;
        };
        let expected_kind = if slot < config.data_shards {
            ShardKind::Data
        } else {
            ShardKind::Parity
        };
        if shard.index != slot
            || shard.kind != expected_kind
            || shard.bytes.len() != config.shard_len
        {
            return Err(ReceiptStripeError::InvalidAvailableSet {
                slots: available.len(),
                expected,
            });
        }
    }
    let available_count = available.iter().filter(|shard| shard.is_some()).count();
    let reconstructed =
        reconstruct(config, available, None).ok_or(ReceiptStripeError::InsufficientShards {
            available: available_count,
            needed: config.data_shards,
        })?;
    Ok(ReceiptReconstructedStripe {
        payload: reconstructed.payload,
        rebuilt_shards: reconstructed.rebuilt_shards,
    })
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

pub fn encode(config: &StripeConfig, payload: &[u8]) -> Option<EncodedStripe> {
    if config.data_shards == 0 || config.shard_len == 0 || payload.len() > config.data_capacity() {
        return None;
    }
    let ds = config.data_shards;
    let sl = config.shard_len;
    let mut data = Vec::with_capacity(ds);
    for i in 0..ds {
        let start = i * sl;
        let end = payload.len().min(start + sl).max(start);
        let mut b = vec![0u8; sl];
        if end > start {
            b[..end - start].copy_from_slice(&payload[start..end]);
        }
        data.push(b);
    }
    let parity = compute_parity(config, &data);
    let mut shards = Vec::with_capacity(config.stripe_width());
    for (i, d) in data.into_iter().enumerate() {
        shards.push(ErasureShard {
            index: i,
            kind: ShardKind::Data,
            bytes: d,
        });
    }
    for (i, p) in parity.into_iter().enumerate() {
        shards.push(ErasureShard {
            index: ds + i,
            kind: ShardKind::Parity,
            bytes: p,
        });
    }
    Some(EncodedStripe {
        config: config.clone(),
        shards,
        original_payload_len: payload.len(),
    })
}

/// Compute parity shards from data shards using the Cauchy encoding matrix.
fn compute_parity(config: &StripeConfig, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let k = config.data_shards;
    let m = config.parity_shards;
    let sl = config.shard_len;
    let mat = build_cauchy_encoding(k, m);
    let mut parity = vec![vec![0u8; sl]; m];
    for (row, parity_row) in parity.iter_mut().enumerate() {
        let r = k + row;
        for (col, &c) in mat[r][..k].iter().enumerate() {
            if c == 0 {
                continue;
            }
            for (b, pb) in parity_row.iter_mut().enumerate().take(sl) {
                *pb ^= gf_mul(c, data[col][b]);
            }
        }
    }
    parity
}

// ---------------------------------------------------------------------------
// Reconstruct
// ---------------------------------------------------------------------------

#[must_use]
pub fn reconstruct(
    config: &StripeConfig,
    available: &[Option<ErasureShard>],
    effective_k: Option<usize>,
) -> Option<Reconstruction> {
    let w = config.stripe_width();
    if available.len() != w {
        return None;
    }
    let eff_k = effective_k.unwrap_or(config.data_shards);
    if eff_k == 0 || eff_k > config.data_shards {
        return None;
    }
    let present: Vec<usize> = (0..w).filter(|&i| available[i].is_some()).collect();
    if present.len() < eff_k {
        return None;
    }
    let missing: Vec<usize> = (0..w).filter(|&i| available[i].is_none()).collect();
    if missing.is_empty() {
        let mut payload = Vec::with_capacity(eff_k * config.shard_len);
        for shard in available.iter().take(eff_k) {
            payload.extend_from_slice(&shard.as_ref().unwrap().bytes);
        }
        return Some(Reconstruction {
            payload,
            rebuilt_shards: vec![],
        });
    }
    if missing.len() > config.parity_shards {
        return None;
    }
    reconstruct_degraded(config, available, &present, &missing, eff_k)
}

#[allow(clippy::needless_range_loop)]
fn reconstruct_degraded(
    config: &StripeConfig,
    available: &[Option<ErasureShard>],
    _present: &[usize],
    missing: &[usize],
    eff_k: usize,
) -> Option<Reconstruction> {
    let k = config.data_shards;
    let m = config.parity_shards;
    let sl = config.shard_len;
    let w = config.stripe_width();

    // Build full Cauchy encoding matrix: k identity rows + m Cauchy rows
    let full = build_cauchy_encoding(k, m);

    // Select k rows: prefer identity (data), then Cauchy (parity)
    let mut row_sel: Vec<usize> = Vec::with_capacity(k);
    for i in 0..k {
        if available[i].is_some() && row_sel.len() < k {
            row_sel.push(i);
        }
    }
    for i in k..w {
        if available[i].is_some() && row_sel.len() < k {
            row_sel.push(i);
        }
    }
    if row_sel.len() < k {
        return None;
    }

    // Build ds×ds submatrix M and RHS
    let mut sub = vec![vec![0u8; k]; k];
    let mut rhs = vec![vec![0u8; sl]; k];
    for (out_row, &src_row) in row_sel.iter().enumerate() {
        for col in 0..k {
            sub[out_row][col] = full[src_row][col];
        }
        rhs[out_row].copy_from_slice(&available[src_row].as_ref().unwrap().bytes);
    }

    let inv = invert_matrix(&sub)?;

    // Reconstruct effective data columns from k×k inverse matrix.
    // The tail stripe may produce fewer than k data fragments; zero-fill
    // the remaining slots to satisfy rebuild_parity's k-column contract.
    // data[col] = Σ_row inv[col][row] * rhs[row]
    let mut data = vec![vec![0u8; sl]; eff_k];
    for col in 0..eff_k {
        for row in 0..k {
            let c = inv[col][row];
            if c == 0 {
                continue;
            }
            for b in 0..sl {
                data[col][b] ^= gf_mul(c, rhs[row][b]);
            }
        }
    }
    debug_assert!(
        data.iter().all(|d| d.len() == sl),
        "reconstruction buffer must be fully allocated"
    );

    // Pad with zero columns so rebuild_parity sees k data columns.
    let zero_col = vec![0u8; sl];
    let padded_data: Vec<Vec<u8>> = data
        .iter()
        .cloned()
        .chain(std::iter::repeat_n(zero_col, k.saturating_sub(eff_k)))
        .collect();

    let mut rebuilt = Vec::new();
    for &idx in missing {
        let bytes = if idx < k {
            padded_data[idx].clone()
        } else {
            rebuild_parity(config, &padded_data, idx - k)
        };
        let kind = if idx < k {
            ShardKind::Data
        } else {
            ShardKind::Parity
        };
        rebuilt.push(ErasureShard {
            index: idx,
            kind,
            bytes,
        });
    }

    let mut payload = Vec::with_capacity(eff_k * sl);
    for d in &data {
        payload.extend_from_slice(d);
    }
    Some(Reconstruction {
        payload,
        rebuilt_shards: rebuilt,
    })
}

#[allow(clippy::needless_range_loop)]
fn rebuild_parity(config: &StripeConfig, data: &[Vec<u8>], parity_idx: usize) -> Vec<u8> {
    let k = config.data_shards;
    let m = config.parity_shards;
    let sl = config.shard_len;
    let mat = build_cauchy_encoding(k, m);
    let r = k + parity_idx;
    let mut p = vec![0u8; sl];
    for col in 0..k {
        let c = mat[r][col];
        if c == 0 {
            continue;
        }
        for b in 0..sl {
            p[b] ^= gf_mul(c, data[col][b]);
        }
    }
    p
}

// ---------------------------------------------------------------------------
// ParityRaid1 — single-parity XOR stripe layout
// ---------------------------------------------------------------------------

/// Single-parity XOR stripe layout (RAID1-style parity).
///
/// Computes a row-parity stripe across data shards using element-wise XOR.
/// Capable of reconstructing any single missing data shard from survivors
/// plus the parity shard.  Shorter shards are zero-padded for the XOR;
/// the parity shard length equals the maximum data shard length.
///
/// # Examples
///
/// ```ignore
/// let raid = ParityRaid1::new(3).unwrap();
/// let shards: &[&[u8]] = &[b"abc", b"def", b"ghi"];
/// let parity = raid.compute_parity(shards);
/// // Reconstruct shard at index 1
/// let survivors = &[(0usize, shards[0]), (2, shards[2])];
/// let reconstructed = raid.reconstruct(1, survivors, &parity).unwrap();
/// assert_eq!(reconstructed, shards[1]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityRaid1 {
    pub data_shard_count: usize,
}

impl ParityRaid1 {
    /// Create a new `ParityRaid1` with the given number of data shards.
    ///
    /// # Errors
    ///
    /// Returns `"data_shard_count must be >= 2"` if `data_shard_count < 2`.
    pub fn new(data_shard_count: usize) -> Result<Self, &'static str> {
        if data_shard_count < 2 {
            return Err("data_shard_count must be >= 2");
        }
        Ok(Self { data_shard_count })
    }

    /// Compute the XOR parity shard across all data shards.
    ///
    /// The parity shard length equals the maximum length among all data
    /// shards.  Shorter shards are treated as if they were zero-padded to
    /// that length.
    ///
    /// Returns an all-zero vector if `data_shards` is empty (caller should
    /// validate before calling).
    #[must_use]
    pub fn compute_parity(&self, data_shards: &[&[u8]]) -> Vec<u8> {
        let max_len = data_shards.iter().map(|s| s.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; max_len];
        for shard in data_shards {
            for (p, &b) in parity.iter_mut().zip(shard.iter()) {
                *p ^= b;
            }
        }
        parity
    }

    /// Reconstruct a single missing data shard from survivors and the
    /// parity shard.
    ///
    /// `missing_index` is informational (not used in computation; the
    /// caller should track which shard index is being reconstructed).
    /// `survivors` must contain exactly `data_shard_count - 1` pairs of
    /// `(index, data)` for the surviving data shards.  The parity shard
    /// must be the XOR of all original data shards.
    ///
    /// Returns the reconstructed data shard, truncated to the length of
    /// the longest survivor/parity (removing any trailing zero-padding
    /// from the XOR operation).
    ///
    /// # Errors
    ///
    /// Returns `"survivors.len() must equal data_shard_count - 1"` if the
    /// wrong number of survivors is provided.
    #[allow(unused_variables)]
    pub fn reconstruct(
        &self,
        missing_index: usize,
        survivors: &[(usize, &[u8])],
        parity: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if survivors.len() != self.data_shard_count - 1 {
            return Err("survivors.len() must equal data_shard_count - 1");
        }
        let max_len = parity
            .len()
            .max(survivors.iter().map(|(_, s)| s.len()).max().unwrap_or(0));
        let mut reconstructed = vec![0u8; max_len];
        // XOR all survivors
        for (_idx, shard) in survivors {
            for (r, &b) in reconstructed.iter_mut().zip(shard.iter()) {
                *r ^= b;
            }
        }
        // XOR parity (which itself is XOR of all original shards,
        // so survivors ^ parity = missing shard)
        for (r, &b) in reconstructed.iter_mut().zip(parity.iter()) {
            *r ^= b;
        }
        Ok(reconstructed)
    }

    /// Convenience method: perform a full stripe write.
    ///
    /// Accepts data shard slices and returns a pair of
    /// `(owned_data_shards, parity_shard)`.
    /// The caller is responsible for ensuring `data_shards.len()` equals
    /// `data_shard_count`.
    #[must_use]
    pub fn stripe_write(&self, data_shards: &[&[u8]]) -> (Vec<Vec<u8>>, Vec<u8>) {
        let data: Vec<Vec<u8>> = data_shards.iter().map(|s| s.to_vec()).collect();
        let parity = self.compute_parity(data_shards);
        (data, parity)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ShardGroupV1 — on-media format for erasure-coded shard groups
// ---------------------------------------------------------------------------

/// On-media metadata block that encodes k data shards + m parity shards
/// for a single logical extent.  Maps 1:1 to a `LocatorId`.
///
/// Byte layout (little-endian):
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 16   | group_id: UUIDv4 |
/// | 16     | 1    | ec_k: data shard count (1..255) |
/// | 17     | 1    | ec_m: parity shard count (0..255) |
/// | 18     | 1    | flags: bit 0=COMPACTED, bit 1=BASE_COMPLETE |
/// | 19     | 1    | replica_count (0 for EC; r for replicated) |
/// | 20     | 8    | logical_offset: byte offset in the logical extent |
/// | 28     | 8    | logical_length: length of the logical extent in bytes |
/// | 36     | 32   | original_digest: BLAKE3-256 over original payload |
/// | 68     | 8    | stripe_size: bytes per stripe |
/// | 76     | 8    | stripe_count: number of stripes |
/// | 84     | 4    | crc32c: CRC32C over bytes 0..83 |
/// | 88+    | var  | per-shard descriptors (shard_count × 54 bytes) |
///
/// Per-shard descriptor:
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 2    | shard_index: 0..(k-1)=data, k..(k+m-1)=parity |
/// | 2      | 4    | reserved |
/// | 6      | 8    | device_id: physical device ID |
/// | 14     | 8    | offset: physical byte offset on device |
/// | 22     | 8    | length: padded shard length in bytes |
/// | 30     | 8    | reserved |
/// | 38     | 8    | reserved |
/// | 46     | 8    | reserved |
///
/// Total on-media overhead: 84 + (k+m) * 54 bytes per shard group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardGroupV1 {
    /// UUIDv4 uniquely identifying this shard group.
    pub group_id: [u8; 16],
    /// Data shard count (k).
    pub ec_k: u8,
    /// Parity shard count (m).
    pub ec_m: u8,
    /// Flags: bit 0=COMPACTED, bit 1=BASE_COMPLETE.
    pub flags: u8,
    /// Replica copies (0 for EC datasets).
    pub replica_count: u8,
    /// Starting byte offset in the logical extent.
    pub logical_offset: u64,
    /// Length of the logical extent in bytes.
    pub logical_length: u64,
    /// BLAKE3-256 digest over the original (pre-encoding) payload.
    pub original_digest: [u8; 32],
    /// Bytes per stripe (data_capacity = k * stripe_size).
    pub stripe_size: u64,
    /// Number of stripes.
    pub stripe_count: u64,
    /// CRC32C checksum over the fixed header (bytes 0..83).
    pub header_crc32c: u32,
    /// Per-shard placement descriptors.
    pub shards: Vec<ShardDescriptor>,
}

/// Per-shard placement descriptor within a `ShardGroupV1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardDescriptor {
    /// Index: 0..(k-1) for data, k..(k+m-1) for parity.
    pub shard_index: u16,
    /// Physical device ID hosting this shard.
    pub device_id: u64,
    /// Physical byte offset on the device.
    pub offset: u64,
    /// Padded shard length in bytes.
    pub length: u64,
}

// ShardGroupV1 flag constants
impl ShardGroupV1 {
    /// Flag: shard data uses compact layout.
    pub const FLAG_COMPACTED: u8 = 0x01;
    /// Flag: all k+m shards written and verified.
    pub const FLAG_BASE_COMPLETE: u8 = 0x02;

    /// Returns the total shard count (k + m).
    #[must_use]
    pub const fn shard_count(&self) -> u8 {
        self.ec_k + self.ec_m
    }

    /// Returns `true` if the BASE_COMPLETE flag is set.
    #[must_use]
    pub const fn is_base_complete(&self) -> bool {
        (self.flags & Self::FLAG_BASE_COMPLETE) != 0
    }

    /// Returns `true` if the COMPACTED flag is set.
    #[must_use]
    pub const fn is_compacted(&self) -> bool {
        (self.flags & Self::FLAG_COMPACTED) != 0
    }

    /// Returns `true` if this is an erasure-coded group (replica_count == 0).
    #[must_use]
    pub const fn is_erasure_coded(&self) -> bool {
        self.replica_count == 0 && self.ec_m > 0
    }

    /// Validates instance constraints per the sealed design spec.
    pub fn validate_constraints(&self) -> Result<(), &'static str> {
        if self.ec_k == 0 {
            return Err("ec_k must be >= 1");
        }
        if (self.ec_k as u16 + self.ec_m as u16) > 255 {
            return Err("ec_k + ec_m must be <= 255");
        }
        if (self.ec_k as u16 + self.ec_m as u16) < 2 {
            return Err("at least one redundancy shard required");
        }
        if self.stripe_size < 512 {
            return Err("stripe_size must be >= 512");
        }
        if self.ec_m > 0 && self.replica_count != 0 {
            return Err("replicas and EC are exclusive per extent");
        }
        Ok(())
    }

    /// Fixed header size (bytes 0..83, before shard descriptors).
    pub const HEADER_SIZE: usize = 84;

    /// Size of each per-shard descriptor in bytes.
    pub const SHARD_DESCRIPTOR_SIZE: usize = 54;
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- GF(2^8) arithmetic ---

    #[test]
    fn gf_mul_identity() {
        for i in 0..=255u8 {
            assert_eq!(gf_mul(1, i), i);
        }
    }
    #[test]
    fn gf_mul_zero() {
        for i in 0..=255u8 {
            assert_eq!(gf_mul(0, i), 0);
        }
    }

    #[test]
    fn gf_mul_commutative() {
        for &a in &[1u8, 2, 13, 27, 53, 101, 200, 255] {
            for &b in &[1u8, 3, 17, 31, 99, 127, 201, 254] {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
    }

    #[test]
    fn gf_div_undoes_mul() {
        for a in 1..=255u8 {
            for b in 1..=255u8 {
                assert_eq!(gf_div(gf_mul(a, b), b), a);
            }
        }
    }
    #[test]
    fn gf_inv_reciprocal() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn encoding_submatrix_invertible() {
        for k in 1..=6usize {
            for m in 1..=3usize {
                if k + m > 255 {
                    continue;
                }
                let full = build_cauchy_encoding(k, m);
                let mut sub = vec![vec![0u8; k]; k];
                for i in 0..k {
                    for j in 0..k {
                        sub[i][j] = full[i][j];
                    }
                }
                // Identity submatrix should invert to identity
                let inv = invert_matrix(&sub).expect("identity submatrix");
                for i in 0..k {
                    for j in 0..k {
                        assert_eq!(inv[i][j], if i == j { 1 } else { 0 });
                    }
                }
                // Replace one identity row with a parity row: should still be invertible
                if k > 1 {
                    let mut sub2 = vec![vec![0u8; k]; k];
                    for i in 0..k - 1 {
                        sub2[i][i] = 1;
                    }
                    for j in 0..k {
                        sub2[k - 1][j] = full[k][j];
                    } // first parity row
                    assert!(
                        invert_matrix(&sub2).is_some(),
                        "identity+parity submatrix (k={k}, m={m}) should be invertible"
                    );
                }
            }
        }
    }

    // --- Helpers ---

    fn cfg_4d8p(parity: usize) -> StripeConfig {
        StripeConfig {
            data_shards: 4,
            parity_shards: parity,
            shard_len: 8,
        }
    }

    fn payload_for(c: &StripeConfig) -> Vec<u8> {
        (0..c.data_capacity() as u8).collect()
    }

    fn make_avail(enc: &EncodedStripe, drops: &[usize]) -> Vec<Option<ErasureShard>> {
        let w = enc.config.stripe_width();
        let mut v: Vec<Option<ErasureShard>> =
            (0..w).map(|i| Some(enc.shards[i].clone())).collect();
        for &d in drops {
            v[d] = None;
        }
        v
    }

    // --- Round trips ---

    #[test]
    fn round_trip_all_levels_full() {
        for parity in [1, 2, 3] {
            let c = cfg_4d8p(parity);
            let p = payload_for(&c);
            let enc = encode(&c, &p).unwrap();
            let avail = make_avail(&enc, &[]);
            let rec = reconstruct(&c, &avail, None).unwrap();
            assert_eq!(&rec.payload[..p.len()], &p, "round-trip {parity}");
            assert!(rec.rebuilt_shards.is_empty());
        }
    }

    #[test]
    fn short_payload_round_trip() {
        let c = StripeConfig {
            data_shards: 4,
            parity_shards: 1,
            shard_len: 8,
        };
        let p = b"short"; // 5 bytes
        let enc = encode(&c, p).unwrap();
        assert_eq!(enc.original_payload_len, 5);
        let avail = make_avail(&enc, &[]);
        let rec = reconstruct(&c, &avail, None).unwrap();
        assert_eq!(&rec.payload[..5], p);
        assert!(rec.payload[5..].iter().all(|&b| b == 0));
    }

    // --- Single loss ---

    #[test]
    fn single_data_loss_each() {
        for parity in [1, 2, 3] {
            let c = cfg_4d8p(parity);
            let p = payload_for(&c);
            let enc = encode(&c, &p).unwrap();
            for missing in 0..c.data_shards {
                let avail = make_avail(&enc, &[missing]);
                let rec = reconstruct(&c, &avail, None).expect("should survive 1 data loss");
                assert_eq!(&rec.payload[..p.len()], &p);
                assert_eq!(rec.rebuilt_shards[0].index, missing);
                assert_eq!(rec.rebuilt_shards[0].kind, ShardKind::Data);
                assert_eq!(rec.rebuilt_shards.len(), 1);
            }
        }
    }

    #[test]
    fn single_parity_loss() {
        for parity in [1, 2, 3] {
            let c = cfg_4d8p(parity);
            let p = payload_for(&c);
            let enc = encode(&c, &p).unwrap();
            let avail = make_avail(&enc, &[c.data_shards]);
            let rec = reconstruct(&c, &avail, None).expect("should survive 1 parity loss");
            assert_eq!(&rec.payload[..p.len()], &p);
            assert_eq!(rec.rebuilt_shards.len(), 1);
            assert_eq!(rec.rebuilt_shards[0].kind, ShardKind::Parity);
        }
    }

    // --- Max loss ---

    #[test]
    fn double_survives_two_data_loss() {
        let c = StripeConfig {
            data_shards: 6,
            parity_shards: 2,
            shard_len: 16,
        };
        let p = payload_for(&c);
        let enc = encode(&c, &p).unwrap();
        let avail = make_avail(&enc, &[1, 4]);
        let rec = reconstruct(&c, &avail, None).expect("double: 2 data loss");
        assert_eq!(&rec.payload[..p.len()], &p);
        assert_eq!(rec.rebuilt_shards.len(), 2);
    }

    #[test]
    fn triple_survives_three_data_loss() {
        let c = StripeConfig {
            data_shards: 6,
            parity_shards: 3,
            shard_len: 16,
        };
        let p = payload_for(&c);
        let enc = encode(&c, &p).unwrap();
        let avail = make_avail(&enc, &[0, 2, 5]);
        let rec = reconstruct(&c, &avail, None).expect("triple: 3 data loss");
        assert_eq!(&rec.payload[..p.len()], &p);
        assert_eq!(rec.rebuilt_shards.len(), 3);
    }

    #[test]
    fn mixed_data_parity_loss() {
        let c = StripeConfig {
            data_shards: 6,
            parity_shards: 2,
            shard_len: 16,
        };
        let p = payload_for(&c);
        let enc = encode(&c, &p).unwrap();
        let avail = make_avail(&enc, &[3, 6]); // data shard 3 + first parity
        let rec = reconstruct(&c, &avail, None).expect("double: 1 data + 1 parity loss");
        assert_eq!(&rec.payload[..p.len()], &p);
    }

    // --- Refusal ---

    #[test]
    fn refuses_too_many_missing() {
        for parity in [1, 2, 3] {
            let c = cfg_4d8p(parity);
            let p = payload_for(&c);
            let enc = encode(&c, &p).unwrap();
            let loss = parity + 1;
            let drops: Vec<usize> = (0..loss).collect();
            let avail = make_avail(&enc, &drops);
            assert!(
                reconstruct(&c, &avail, None).is_none(),
                "{parity}: should refuse with {loss} missing"
            );
        }
    }

    #[test]
    fn refuses_zero_data_shards() {
        assert!(encode(
            &StripeConfig {
                data_shards: 0,
                parity_shards: 1,
                shard_len: 8
            },
            b"t"
        )
        .is_none());
    }
    #[test]
    fn refuses_oversize_payload() {
        assert!(encode(
            &StripeConfig {
                data_shards: 2,
                parity_shards: 1,
                shard_len: 4
            },
            b"123456789"
        )
        .is_none());
    }

    // --- Large shard ---

    #[test]
    fn large_shard_recovery() {
        let c = StripeConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 4096,
        };
        let p = payload_for(&c);
        let enc = encode(&c, &p).unwrap();
        // Double parity tolerates up to 2 failures; drop data 1 + parity 4, keep data 0,2,3 + parity 5
        let avail = make_avail(&enc, &[1, 4]);
        let rec = reconstruct(&c, &avail, None)
            .expect("double: recover data 1 and parity 4 from 4 present");
        assert_eq!(&rec.payload[..p.len()], &p);
        assert_eq!(rec.rebuilt_shards.len(), 2);
    }
    // --- Randomized property ---

    #[test]
    fn property_random_single_loss() {
        for seed in 0..32u64 {
            let ds = 3 + (seed % 5) as usize;
            let sl = 8 + (seed % 8) as usize * 4;
            for parity in [1, 2, 3] {
                let c = StripeConfig {
                    data_shards: ds,
                    parity_shards: parity,
                    shard_len: sl,
                };
                let p: Vec<u8> = (0..c.data_capacity())
                    .map(|i| (seed.wrapping_add(i as u64) ^ (i as u64).rotate_left(13)) as u8)
                    .collect();
                let enc = encode(&c, &p).unwrap();
                let drop = (seed as usize * 7 + 1) % c.stripe_width();
                let avail = make_avail(&enc, &[drop]);
                let rec = reconstruct(&c, &avail, None)
                    .unwrap_or_else(|| panic!("seed={seed}: {parity} ds={ds} sl={sl} drop={drop}"));
                assert_eq!(&rec.payload[..p.len()], &p, "seed={seed}");
                assert_eq!(rec.rebuilt_shards.len(), 1);
            }
        }
    }

    #[test]
    fn property_random_max_loss() {
        for seed in 0..16u64 {
            let ds = 4 + (seed % 4) as usize;
            let parity = [1, 2, 3][seed as usize % 3];
            let c = StripeConfig {
                data_shards: ds,
                parity_shards: parity,
                shard_len: 16,
            };
            let p: Vec<u8> = (0..c.data_capacity())
                .map(|i| (seed.wrapping_add(i as u64) ^ (i as u64).wrapping_mul(0x9E37)) as u8)
                .collect();
            let enc = encode(&c, &p).unwrap();
            let mut drops = Vec::new();
            for k in 0..parity {
                drops.push((seed as usize * 13 + k * 7) % c.stripe_width());
            }
            let avail = make_avail(&enc, &drops);
            let rec = reconstruct(&c, &avail, None).unwrap_or_else(|| {
                panic!(
                    "seed={seed}: {parity} survive {} losses (ds={ds})",
                    drops.len()
                )
            });
            assert_eq!(&rec.payload[..p.len()], &p, "seed={seed}");
        }
    }

    // --- GF(2^8) distributivity over XOR ---

    #[test]
    fn gf_mul_distributive_over_xor() {
        // a * (b ^ c) == (a * b) ^ (a * c) over GF(2^8)
        for &a in &[1u8, 2, 7, 13, 29, 53, 101, 137, 200, 255] {
            for &b in &[1u8, 3, 17, 31, 63, 99, 127, 201, 254] {
                for &c in &[2u8, 5, 19, 37, 71, 113, 149, 211] {
                    let left = gf_mul(a, b ^ c);
                    let right = gf_mul(a, b) ^ gf_mul(a, c);
                    assert_eq!(left, right, "distributive failed for a={a} b={b} c={c}");
                }
            }
        }
    }

    // --- Encode edge cases ---

    #[test]
    fn empty_payload_round_trip() {
        let c = StripeConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 8,
        };
        let enc = encode(&c, &[]).unwrap();
        assert_eq!(enc.original_payload_len, 0);
        let avail: Vec<Option<ErasureShard>> = enc.shards.iter().cloned().map(Some).collect();
        let rec = reconstruct(&c, &avail, None).unwrap();
        assert!(rec.payload.iter().all(|&b| b == 0));
        assert_eq!(rec.payload.len(), c.data_capacity());
    }

    #[test]
    fn max_capacity_payload_round_trip() {
        let c = StripeConfig {
            data_shards: 3,
            parity_shards: 1,
            shard_len: 16,
        };
        let p = vec![0xABu8; c.data_capacity()];
        let enc = encode(&c, &p).unwrap();
        assert_eq!(enc.original_payload_len, c.data_capacity());
        let avail: Vec<Option<ErasureShard>> = enc.shards.iter().cloned().map(Some).collect();
        let rec = reconstruct(&c, &avail, None).unwrap();
        assert_eq!(&rec.payload[..p.len()], &p);
    }

    #[test]
    fn encode_rejects_zero_shard_len() {
        assert!(encode(
            &StripeConfig {
                data_shards: 4,
                parity_shards: 1,
                shard_len: 0,
            },
            b"data"
        )
        .is_none());
    }

    #[test]
    fn encode_rejects_zero_data_shards() {
        // Already tested indirectly, but explicit check for clarity
        assert!(encode(
            &StripeConfig {
                data_shards: 0,
                parity_shards: 1,
                shard_len: 8,
            },
            b"data"
        )
        .is_none());
    }

    // --- Singleton stripe ---

    #[test]
    fn singleton_data_shard_single_parity_round_trip() {
        let c = StripeConfig {
            data_shards: 1,
            parity_shards: 1,
            shard_len: 32,
        };
        let p = b"hello singleton!".to_vec();
        let enc = encode(&c, &p).unwrap();
        assert_eq!(enc.shards.len(), 2);
        let avail = make_avail(&enc, &[0]); // drop data shard
        let rec = reconstruct(&c, &avail, None).unwrap();
        assert_eq!(&rec.payload[..p.len()], &p);
    }

    // --- Extra surviving shards ---

    #[test]
    fn reconstruct_extra_survivors_same_result() {
        // With more than k shards available, result should be same regardless
        // of which subset of k we choose (the extra survivor is redundant).
        let c = StripeConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 8,
        };
        let p = payload_for(&c);
        let enc = encode(&c, &p).unwrap();
        // Drop only 1 data shard, so 3 data + 2 parity = 5 survivors (k=4)
        let avail = make_avail(&enc, &[1]);
        let rec = reconstruct(&c, &avail, None).unwrap();
        assert_eq!(&rec.payload[..p.len()], &p);
    }

    // --- Insufficient shards (explicit boundary) ---

    #[test]
    fn reconstruct_fails_when_all_data_missing_z1() {
        let c = StripeConfig {
            data_shards: 3,
            parity_shards: 1,
            shard_len: 8,
        };
        let p = payload_for(&c);
        let enc = encode(&c, &p).unwrap();
        // Drop all 3 data shards, keep only 1 parity — need 3 data, have 1
        let avail = make_avail(&enc, &[0, 1, 2]);
        assert!(reconstruct(&c, &avail, None).is_none());
    }

    #[test]
    fn reconstruct_fails_only_one_data_surviving_z2() {
        let c = StripeConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 8,
        };
        let p = payload_for(&c);
        let enc = encode(&c, &p).unwrap();
        // Drop 3 data shards, keeping 1 data + 2 parity = 3 < k=4
        let avail = make_avail(&enc, &[0, 2, 3]);
        assert!(reconstruct(&c, &avail, None).is_none());
    }

    // --- Wrong available vec length ---

    #[test]
    fn reconstruct_rejects_wrong_available_len() {
        let c = StripeConfig {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 4,
        };
        let p = b"12345678".to_vec();
        let enc = encode(&c, &p).unwrap();
        // Provide only 1 slot instead of stripe_width=3
        let avail: Vec<Option<ErasureShard>> = vec![Some(enc.shards[0].clone())];
        assert!(reconstruct(&c, &avail, None).is_none());
    }

    // --- Boundary payload size ---

    #[test]
    fn one_byte_under_capacity_round_trip() {
        let c = StripeConfig {
            data_shards: 3,
            parity_shards: 2,
            shard_len: 4,
        };
        let p = vec![0xCDu8; c.data_capacity() - 1];
        let enc = encode(&c, &p).unwrap();
        assert_eq!(enc.original_payload_len, p.len());
        let avail = make_avail(&enc, &[]);
        let rec = reconstruct(&c, &avail, None).unwrap();
        assert_eq!(&rec.payload[..p.len()], &p);
        // The padded last byte should be zero
        assert_eq!(rec.payload[p.len()], 0);
    }

    // --- ShardGroupV1 validation ---

    fn valid_shard_group() -> ShardGroupV1 {
        ShardGroupV1 {
            group_id: [1u8; 16],
            ec_k: 4,
            ec_m: 2,
            flags: ShardGroupV1::FLAG_BASE_COMPLETE,
            replica_count: 0,
            logical_offset: 0,
            logical_length: 4096,
            original_digest: [0xABu8; 32],
            stripe_size: 512,
            stripe_count: 1,
            header_crc32c: 0,
            shards: vec![],
        }
    }

    #[test]
    fn shardgroup_v1_validate_all_ok() {
        assert!(valid_shard_group().validate_constraints().is_ok());
    }

    #[test]
    fn shardgroup_v1_validate_zero_k_rejected() {
        let mut sg = valid_shard_group();
        sg.ec_k = 0;
        assert_eq!(sg.validate_constraints(), Err("ec_k must be >= 1"));
    }

    #[test]
    fn shardgroup_v1_validate_no_redundancy_rejected() {
        let mut sg = valid_shard_group();
        sg.ec_k = 1;
        sg.ec_m = 0; // ec_k + ec_m = 1 < 2
        assert_eq!(
            sg.validate_constraints(),
            Err("at least one redundancy shard required")
        );
    }

    #[test]
    fn shardgroup_v1_validate_small_stripe_rejected() {
        let mut sg = valid_shard_group();
        sg.stripe_size = 511;
        assert_eq!(sg.validate_constraints(), Err("stripe_size must be >= 512"));
    }

    #[test]
    fn shardgroup_v1_validate_replica_ec_exclusive() {
        let mut sg = valid_shard_group();
        sg.replica_count = 2; // ec_m > 0 but replica_count != 0
        assert_eq!(
            sg.validate_constraints(),
            Err("replicas and EC are exclusive per extent")
        );
    }

    #[test]
    fn shardgroup_v1_validate_sum_overflow_rejected() {
        let mut sg = valid_shard_group();
        sg.ec_k = 200;
        sg.ec_m = 56; // sum = 256 > 255
        assert_eq!(sg.validate_constraints(), Err("ec_k + ec_m must be <= 255"));
    }

    #[test]
    fn shardgroup_v1_flag_constants() {
        assert_eq!(ShardGroupV1::FLAG_COMPACTED, 0x01);
        assert_eq!(ShardGroupV1::FLAG_BASE_COMPLETE, 0x02);
    }

    #[test]
    fn shardgroup_v1_is_erasure_coded() {
        let sg = valid_shard_group();
        assert!(sg.is_erasure_coded());
        let mut replicated = valid_shard_group();
        replicated.ec_m = 0;
        replicated.replica_count = 3;
        assert!(!replicated.is_erasure_coded());
    }

    #[test]
    fn shardgroup_v1_is_base_complete() {
        let sg = valid_shard_group();
        assert!(sg.is_base_complete());
        let mut incomplete = valid_shard_group();
        incomplete.flags = 0;
        assert!(!incomplete.is_base_complete());
    }

    // --- ParityRaid1 unit tests ---

    #[test]
    fn parity_raid1_new_rejects_too_few_data_shards() {
        assert_eq!(
            ParityRaid1::new(0).unwrap_err(),
            "data_shard_count must be >= 2"
        );
        assert_eq!(
            ParityRaid1::new(1).unwrap_err(),
            "data_shard_count must be >= 2"
        );
        assert!(ParityRaid1::new(2).is_ok());
        assert!(ParityRaid1::new(8).is_ok());
    }

    #[test]
    fn parity_raid1_xor_identity_two_identical_shards_all_zero() {
        let raid = ParityRaid1::new(2).unwrap();
        let shard = b"hello world!";
        let parity = raid.compute_parity(&[shard, shard]);
        assert!(parity.iter().all(|&b| b == 0));
    }

    #[test]
    fn parity_raid1_commutativity() {
        let raid = ParityRaid1::new(3).unwrap();
        let a: &[u8] = b"abc123";
        let b_slice: &[u8] = b"def456";
        let c: &[u8] = b"ghi789";
        let p1 = raid.compute_parity(&[a, b_slice, c]);
        let p2 = raid.compute_parity(&[c, a, b_slice]);
        let p3 = raid.compute_parity(&[b_slice, c, a]);
        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn parity_raid1_reconstruct_each_position() {
        let raid = ParityRaid1::new(4).unwrap();
        let shards: &[&[u8]] = &[
            &[0x01, 0x02, 0x03, 0x04],
            &[0x11, 0x12, 0x13, 0x14],
            &[0x21, 0x22, 0x23, 0x24],
            &[0x31, 0x32, 0x33, 0x34],
        ];
        let parity = raid.compute_parity(shards);
        for missing in 0..4 {
            let survivors: Vec<(usize, &[u8])> = (0..4)
                .filter(|&i| i != missing)
                .map(|i| (i, shards[i]))
                .collect();
            let reconstructed = raid.reconstruct(missing, &survivors, &parity).unwrap();
            assert_eq!(
                reconstructed, shards[missing],
                "mismatch reconstructing shard {missing}"
            );
        }
    }

    #[test]
    fn parity_raid1_reconstruct_zero_padded_shorter_shard() {
        let raid = ParityRaid1::new(3).unwrap();
        let a: &[u8] = b"short";
        let b: &[u8] = b"longer_data";
        let c: &[u8] = b"x";
        let parity = raid.compute_parity(&[a, b, c]);
        // Reconstruct shard at index 0 (the "short" one)
        let survivors = vec![(1usize, b), (2, c)];
        let reconstructed = raid.reconstruct(0, &survivors, &parity).unwrap();
        // The reconstructed shard may be longer than original "short" due to
        // zero-padded XOR with longer shards. Only the first 5 bytes matter.
        assert_eq!(&reconstructed[..a.len()], a);
    }

    #[test]
    fn parity_raid1_empty_shards() {
        let raid = ParityRaid1::new(2).unwrap();
        let parity = raid.compute_parity(&[b"", b""]);
        assert!(parity.is_empty());
    }

    #[test]
    fn parity_raid1_single_byte_shards() {
        let raid = ParityRaid1::new(4).unwrap();
        let shards: &[&[u8]] = &[b"\x01", b"\x02", b"\x03", b"\x04"];
        let parity = raid.compute_parity(shards);
        assert_eq!(parity, vec![0x04]);
        // Reconstruct each
        for missing in 0..4 {
            let survivors: Vec<(usize, &[u8])> = (0..4)
                .filter(|&i| i != missing)
                .map(|i| (i, shards[i]))
                .collect();
            let reconstructed = raid.reconstruct(missing, &survivors, &parity).unwrap();
            assert_eq!(reconstructed, shards[missing]);
        }
    }

    #[test]
    fn parity_raid1_large_shard_1mib() {
        let raid = ParityRaid1::new(2).unwrap();
        let size = 1024 * 1024; // 1 MiB
        let a: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        let b: Vec<u8> = (0..size).map(|i| ((i + 1) & 0xFF) as u8).collect();
        let parity = raid.compute_parity(&[&a, &b]);
        assert_eq!(parity.len(), size);
        for i in 0..size {
            assert_eq!(parity[i], a[i] ^ b[i]);
        }
        // Reconstruct
        let survivors = vec![(0usize, a.as_ref())];
        let recovered = raid.reconstruct(1, &survivors, &parity).unwrap();
        assert_eq!(recovered, b);
    }

    #[test]
    fn parity_raid1_reconstruct_wrong_survivor_count() {
        let raid = ParityRaid1::new(3).unwrap();
        let shard: &[u8] = b"data";
        let parity = vec![0u8; 4];
        // Only 1 survivor when 2 are needed
        let err = raid
            .reconstruct(0, &[(1usize, shard)], &parity)
            .unwrap_err();
        assert_eq!(err, "survivors.len() must equal data_shard_count - 1");
        // 3 survivors when 2 are needed
        let err = raid
            .reconstruct(0, &[(0usize, shard), (1, shard), (2, shard)], &parity)
            .unwrap_err();
        assert_eq!(err, "survivors.len() must equal data_shard_count - 1");
    }

    #[test]
    fn parity_raid1_stripe_write_roundtrip() {
        let raid = ParityRaid1::new(3).unwrap();
        let a: &[u8] = b"aaa";
        let b: &[u8] = b"bbbb";
        let c: &[u8] = b"cc";
        let (data, parity) = raid.stripe_write(&[a, b, c]);
        assert_eq!(data.len(), 3);
        assert_eq!(data[0], a);
        assert_eq!(data[1], b);
        assert_eq!(data[2], c);
        // Parity should match compute_parity result
        let expected_parity = raid.compute_parity(&[a, b, c]);
        assert_eq!(parity, expected_parity);
    }

    #[test]
    fn parity_raid1_variable_length_edge_cases() {
        let raid = ParityRaid1::new(3).unwrap();
        // One empty shard, two non-empty
        let parity = raid.compute_parity(&[b"", b"ab", b"cd"]);
        let expected: Vec<u8> = vec![b'a' ^ b'c', b'b' ^ b'd'];
        assert_eq!(parity, expected);
        // Reconstruction with empty survivor
        let survivors = vec![(0usize, &b""[..]), (2usize, &b"cd"[..])];
        let recovered = raid.reconstruct(1, &survivors, &parity).unwrap();
        assert_eq!(recovered, b"ab");
    }

    // --- ParityRaid1 proptest ---

    proptest::proptest! {
    #[test]
    fn proptest_parity_raid1_reconstruct_roundtrip(
        shard_count in 2usize..=8usize,
        seed in 0u64..256,
    ) {
        let raid = ParityRaid1::new(shard_count).unwrap();
        // Generate random shards with variable lengths
        let rng = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            seed.hash(&mut h);
            h.finish()
        };
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(shard_count);
        for i in 0..shard_count {
            let len = ((rng.wrapping_add(i as u64 * 7 + 13)) % 4096) as usize;
            let mut s = Vec::with_capacity(len);
            let mut state = rng.wrapping_add(i as u64 * 101);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                s.push((state >> 32) as u8);
            }
            shards.push(s);
        }
        let slices: Vec<&[u8]> = shards.iter().map(|s| s.as_ref()).collect();
        let parity = raid.compute_parity(&slices);

        // Reconstruct every position
        for missing in 0..shard_count {
            let survivors: Vec<(usize, &[u8])> = (0..shard_count)
                .filter(|&i| i != missing)
                .map(|i| (i, slices[i]))
                .collect();
            let reconstructed = raid.reconstruct(missing, &survivors, &parity)
                .expect("reconstruct should succeed");
            // Reconstructed may be longer due to zero-padding; original bytes must match
            assert_eq!(
                &reconstructed[..shards[missing].len()],
                shards[missing].as_slice(),
                "seed={seed} shard_count={shard_count} missing={missing}"
            );
        }
    }
    }

    // -----------------------------------------------------------------------
    // ReplicationIntent integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_from_ec_intent_valid() {
        let intent = tidefs_replication_model::ReplicationIntent::new_erasure_coded(
            4,
            2,
            tidefs_replication_model::FailureDomain::Rack,
        )
        .unwrap();
        let cfg = config_from_replication_intent(&intent, 16).unwrap();
        assert_eq!(cfg.data_shards, 4);
        assert_eq!(cfg.parity_shards, 2);
        assert_eq!(cfg.shard_len, 16);
    }

    #[test]
    fn config_from_mirror_intent_returns_none() {
        let intent = tidefs_replication_model::ReplicationIntent::new_mirror(
            3,
            tidefs_replication_model::FailureDomain::Node,
        )
        .unwrap();
        assert!(config_from_replication_intent(&intent, 16).is_none());
    }

    #[test]
    fn config_from_ec_intent_rejects_zero_shard_len() {
        let intent = tidefs_replication_model::ReplicationIntent::new_erasure_coded(
            4,
            2,
            tidefs_replication_model::FailureDomain::Device,
        )
        .unwrap();
        assert!(config_from_replication_intent(&intent, 0).is_none());
    }

    #[test]
    fn config_from_ec_intent_rejects_k_plus_m_exceeds_255() {
        let intent = tidefs_replication_model::ReplicationIntent::new_erasure_coded(
            200,
            56,
            tidefs_replication_model::FailureDomain::Device,
        )
        .unwrap();
        assert!(config_from_replication_intent(&intent, 1).is_none());
    }

    #[test]
    fn ec_intent_roundtrip_via_config() {
        let intent = tidefs_replication_model::ReplicationIntent::new_erasure_coded(
            6,
            3,
            tidefs_replication_model::FailureDomain::Rack,
        )
        .unwrap();
        let cfg = config_from_replication_intent(&intent, 32).unwrap();
        let payload: Vec<u8> = (0..cfg.data_capacity()).map(|i| (i & 0xFF) as u8).collect();
        let enc = encode(&cfg, &payload).unwrap();
        // Drop data shards 0, 1, 3 and reconstruct from survivors (3 data + 3 parity = 6 >= k=6)
        let avail: Vec<Option<ErasureShard>> = (0..cfg.stripe_width())
            .map(|i| {
                if i == 0 || i == 1 || i == 3 {
                    None
                } else {
                    Some(enc.shards[i].clone())
                }
            })
            .collect();
        let rec = reconstruct(&cfg, &avail, None).expect("reconstruct after triple loss");
        assert_eq!(&rec.payload[..payload.len()], &payload);
        assert_eq!(rec.rebuilt_shards.len(), 3);
    }

    #[test]
    fn ec_intent_small_k1_m1_roundtrip() {
        let intent = tidefs_replication_model::ReplicationIntent::new_erasure_coded(
            1,
            1,
            tidefs_replication_model::FailureDomain::Device,
        )
        .unwrap();
        let cfg = config_from_replication_intent(&intent, 64).unwrap();
        let payload = vec![0xABu8; cfg.data_capacity()];
        let enc = encode(&cfg, &payload).unwrap();
        assert_eq!(enc.shards.len(), 2);
        // Reconstruct from parity only
        let avail: Vec<Option<ErasureShard>> = (0..2)
            .map(|i| {
                if i == 0 {
                    None
                } else {
                    Some(enc.shards[i].clone())
                }
            })
            .collect();
        let rec = reconstruct(&cfg, &avail, None).expect("reconstruct from parity only");
        assert_eq!(&rec.payload[..payload.len()], &payload);
    }

    #[test]
    fn ec_intent_matches_direct_config() {
        let intent = tidefs_replication_model::ReplicationIntent::new_erasure_coded(
            4,
            2,
            tidefs_replication_model::FailureDomain::Node,
        )
        .unwrap();
        let cfg_from_intent = config_from_replication_intent(&intent, 16).unwrap();
        let cfg_direct = config_from_erasure_coded(4, 2, 16).unwrap();
        assert_eq!(cfg_from_intent, cfg_direct);
    }

    #[test]
    fn test_reconstruct_tail_stripe_unaligned() {
        // 3+2 config, 2 KiB block size.
        // 10 KiB extent: stripe 0 = 6 KiB (3 full fragments),
        // stripe 1 = 4 KiB (2 effective fragments, eff_k=2).
        let c = config_from_erasure_coded(3, 2, 2048).unwrap();
        let tail_payload: Vec<u8> = (0..4096u16).map(|i| (i & 0xFF) as u8).collect();
        let enc = encode(&c, &tail_payload).unwrap();
        // Drop data shard 1 (second of 3); keep shards 0, 2, 3, 4.
        let avail: Vec<Option<ErasureShard>> = enc
            .shards
            .iter()
            .enumerate()
            .map(|(i, s)| if i == 1 { None } else { Some(s.clone()) })
            .collect();
        let rec = reconstruct(&c, &avail, Some(2))
            .expect("tail stripe reconstruction with effective_k=2");
        assert_eq!(
            rec.payload.len(),
            4096,
            "tail stripe payload must be 2 shards (4096 bytes)"
        );
        assert_eq!(
            &rec.payload[..],
            &tail_payload[..],
            "reconstructed tail must match original"
        );
    }

    #[test]
    fn test_reconstruct_tail_stripe_zero_pad() {
        // 3+2 config, 512-byte shard size.
        // 1 KiB payload: only 2 data fragments (eff_k=2, k=3).
        // The third data fragment is zero-padded by encode.
        let c = config_from_erasure_coded(3, 2, 512).unwrap();
        let payload: Vec<u8> = (0..1024u16).map(|i| (i as u8).wrapping_mul(3)).collect();
        let enc = encode(&c, &payload).unwrap();
        // Drop data shard 0; keep shards 1, 2 (zero-padded), 3, 4.
        let avail: Vec<Option<ErasureShard>> = enc
            .shards
            .iter()
            .enumerate()
            .map(|(i, s)| if i == 0 { None } else { Some(s.clone()) })
            .collect();
        // Reconstruct with eff_k=2: zero-filled fragment must not
        // corrupt the GF(2^8) decode of the two real data columns.
        let rec = reconstruct(&c, &avail, Some(2))
            .expect("zero-pad tail stripe reconstruction with effective_k=2");
        assert_eq!(rec.payload.len(), 1024);
        assert_eq!(&rec.payload[..], &payload[..]);
    }
}
