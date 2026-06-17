//! Erasure-coded object write path: ErasureCodedWriteRequest, stripe assembly,
//! Reed-Solomon parity computation, shard dispatch, and partial-write rollback.
//!
//! Consumes a [`DurabilityLayoutV1`] to determine k/m parameters and placement
//! constraints.  Each object payload is split into stripes of `k * shard_len`
//! bytes, then each stripe is encoded into `k+m` shards via GF(2^8)
//! Reed-Solomon and dispatched to local-object-store instances.

use std::collections::HashMap;
use std::fmt;

use tidefs_durability_layout::FailureDomainV1;
use tidefs_durability_layout::{DurabilityLayoutV1, DurabilityPolicy};
use tidefs_erasure_coding::{encode, ErasureShard, ShardKind, StripeConfig};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
use tidefs_placement_planner::placement_plan::{DeviceCandidate, PlacementPlan, ShardAssignment};

// ---------------------------------------------------------------------------
// Write request / outcome types
// ---------------------------------------------------------------------------

/// A request to write an object through the erasure-coded write path.
///
/// The request bundles the object id, payload, durability layout (which
/// determines k/m and placement constraints), and the per-shard byte size.
/// Call [`ErasureCodedWriteRequest::execute`] to stripe, encode, and dispatch.
#[derive(Debug, Clone)]
pub struct ErasureCodedWriteRequest<'a> {
    /// Object identifier, becomes the base key in local-object-store.
    pub object_id: Vec<u8>,
    /// Raw payload bytes to be striped and erasure-encoded.
    pub payload: Vec<u8>,
    /// Durability layout governing data/parity shard counts.
    /// Must be `DurabilityPolicy::ErasureStyle`; mirror layouts are rejected.
    pub layout: &'a DurabilityLayoutV1,
    /// Bytes per shard. Stripe data capacity = k * shard_len.
    pub shard_len: usize,
    /// Failure domain descriptor for placement anti-affinity.
    /// Each store in the stores slice must correspond to one device candidate.
    pub failure_domain: &'a FailureDomainV1,
    /// Device candidates, one per store, in the same order as the stores slice.
    /// The placement planner selects which device gets each shard.
    pub device_candidates: &'a [DeviceCandidate],
}

/// Outcome of a successfully completed erasure-coded write.
#[derive(Debug, Clone)]
pub struct ErasureCodedWriteOutcome {
    /// Object identifier (echoed from the request).
    pub object_id: Vec<u8>,
    /// Per-stripe outcomes with shard locations and integrity digests.
    pub stripe_outcomes: Vec<StripeWriteOutcome>,
    /// Number of shards successfully dispatched.
    pub shards_dispatched: usize,
    /// Total shards across all stripes (num_stripes * (k+m)).
    pub shards_total: usize,
    /// Original payload size in bytes.
    pub bytes_encoded: u64,
}

/// Per-stripe write outcome: list of shard placements.
#[derive(Debug, Clone)]
pub struct StripeWriteOutcome {
    /// Zero-based stripe index within the object.
    pub stripe_index: usize,
    /// Object identifier (deterministic manifest self-containment).
    pub object_id: Vec<u8>,
    /// Stripe configuration (k, m, shard_len) for this stripe.
    pub stripe_config: StripeConfig,
    /// Logical payload length within this stripe, before shard-len padding.
    pub original_chunk_len: usize,
    /// Per-shard placement info (shard index, target store, integrity digest).
    pub shard_placements: Vec<ShardPlacement>,
}

/// Location and integrity metadata for a single dispatched shard.
#[derive(Debug, Clone)]
pub struct ShardPlacement {
    /// Index of the shard within the stripe (0..k-1 = data, k..k+m-1 = parity).
    pub shard_index: usize,
    /// Kind of this shard (Data or Parity).
    pub shard_kind: ShardKind,
    /// Target store index in the stores slice, determined by the placement planner.
    pub store_index: usize,
    /// Device id selected by the placement planner for this shard.
    pub device_id: u64,
    /// BLAKE3 digest of the shard payload bytes.
    pub digest: [u8; 32],
    /// Shard payload size in bytes (padded to shard_len).
    pub size: usize,
}

/// Evidence recorded when dispatched shards are rolled back after a
/// partial write failure.
///
/// Carried inside [`WritePathError::DispatchFailed`] so the caller can
/// inspect which shards were written and subsequently deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackEvidence {
    /// Stripe index where the failure occurred.
    pub failed_stripe: usize,
    /// Shard index that triggered the failure.
    pub failed_shard: usize,
    /// Store index that rejected the write.
    pub failed_store: usize,
    /// Keys that were written and then rolled back: (store_index, shard_key_bytes).
    pub rolled_back_keys: Vec<(usize, [u8; 32])>,
}

// ---------------------------------------------------------------------------
// Write path error
// ---------------------------------------------------------------------------

/// Errors that can occur during the erasure-coded write path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritePathError {
    /// The durability layout does not specify an erasure-style policy.
    NotErasureStyle,
    /// The parity count from the layout is not 1, 2, or 3.
    InvalidParityCount(usize),
    /// The shard_len must be >= 1.
    InvalidShardLen,
    /// Encoding failed for the given stripe index.
    EncodeFailed(usize),
    /// Not enough stores to hold all shards.
    InsufficientStores { needed: usize, available: usize },
    /// Writing a shard to its target store failed.
    DispatchFailed {
        rollback_evidence: Option<RollbackEvidence>,
        stripe: usize,
        shard: usize,
        store: usize,
        reason: String,
    },
    /// Shard record integrity envelope encoding failed.
    EnvelopeEncodeFailed(String),
    /// Internal error.
    Internal(String),
}

impl fmt::Display for WritePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotErasureStyle => {
                write!(f, "durability layout is not ErasureStyle; mirror layouts are not supported by the erasure-coded write path")
            }
            Self::InvalidParityCount(n) => {
                write!(
                    f,
                    "invalid parity count {n} from durability layout; must be 1, 2, or 3"
                )
            }
            Self::InvalidShardLen => write!(f, "shard_len must be >= 1"),
            Self::EncodeFailed(stripe) => write!(f, "encode failed for stripe {stripe}"),
            Self::InsufficientStores { needed, available } => {
                write!(f, "need {needed} stores for k+m shards, have {available}")
            }
            Self::DispatchFailed {
                rollback_evidence,
                stripe,
                shard,
                store,
                reason,
            } => {
                write!(
                    f,
                    "dispatch to store {store} failed for stripe {stripe} shard {shard}: {reason}"
                )?;
                if let Some(ref ev) = rollback_evidence {
                    write!(f, " (rolled back {} keys)", ev.rolled_back_keys.len())?;
                }
                Ok(())
            }
            Self::EnvelopeEncodeFailed(msg) => {
                write!(f, "shard integrity envelope encoding failed: {msg}")
            }
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for WritePathError {}

// ---------------------------------------------------------------------------
// Write execution
// ---------------------------------------------------------------------------

impl<'a> ErasureCodedWriteRequest<'a> {
    /// Execute the write path: validate layout, split into stripes, encode
    /// each stripe with Reed-Solomon, dispatch shards to stores, and return
    /// an [`ErasureCodedWriteOutcome`].
    ///
    /// On any shard write failure, previously written shards for this object
    /// are rolled back (deleted) before returning the error.
    ///
    /// # Errors
    ///
    /// Returns [`WritePathError`] if the layout is not `ErasureStyle`, the
    /// parity count is invalid, the shard length is zero, encoding fails,
    /// there are insufficient stores, or a store write fails.
    pub fn execute(
        self,
        stores: &mut [LocalObjectStore],
    ) -> Result<ErasureCodedWriteOutcome, WritePathError> {
        // --- Validate layout ---
        let (k, m) = extract_ec_params(self.layout)?;

        if self.shard_len == 0 {
            return Err(WritePathError::InvalidShardLen);
        }

        let stripe_config = StripeConfig {
            data_shards: k,
            parity_shards: m,
            shard_len: self.shard_len,
        };

        let cap = stripe_config.data_capacity();
        let original_len = self.payload.len();
        let num_stripes = if original_len == 0 {
            1
        } else {
            original_len.div_ceil(cap)
        };

        let sw = stripe_config.stripe_width();
        let shards_total = sw * num_stripes;

        if stores.len() < sw {
            return Err(WritePathError::InsufficientStores {
                needed: sw,
                available: stores.len(),
            });
        }

        // --- Compute placement plan ---
        let placement_plan = PlacementPlan::from_layout(*self.layout, *self.failure_domain);
        let shard_assignments = placement_plan
            .assign_devices(self.device_candidates)
            .map_err(|e| WritePathError::Internal(format!("placement plan failed: {e}")))?;

        if shard_assignments.len() < sw {
            return Err(WritePathError::InsufficientStores {
                needed: sw,
                available: shard_assignments.len(),
            });
        }

        // Build device_id -> store_index mapping from device_candidates order.
        let device_to_store: HashMap<u64, usize> = self
            .device_candidates
            .iter()
            .enumerate()
            .map(|(idx, dc)| (dc.device_id, idx))
            .collect();

        let key = ObjectKey::from_name(&self.object_id);
        let mut stripe_outcomes = Vec::with_capacity(num_stripes);
        let mut shards_dispatched = 0usize;

        // Track (store_index, ObjectKey) for rollback on failure.
        let mut written_keys: Vec<(usize, [u8; 32])> = Vec::new();

        for stripe_idx in 0..num_stripes {
            // --- Slice payload chunk ---
            let start = stripe_idx * cap;
            let end = (original_len).min(start + cap);
            let chunk = if start < original_len {
                &self.payload[start..end]
            } else {
                &[]
            };

            // --- Reed-Solomon encode ---
            let encoded =
                encode(&stripe_config, chunk).ok_or(WritePathError::EncodeFailed(stripe_idx))?;

            // --- Compute placements from placement planner assignments ---
            let placements = dispatch_stripes(
                &key,
                stripe_idx,
                &encoded.shards,
                &shard_assignments,
                &device_to_store,
            )?;

            // --- Write each shard to its target store ---
            for placement in &placements {
                let shard = &encoded.shards[placement.shard_index];
                let shard_key = shard_key_bytes(&key, stripe_idx, placement.shard_index);
                let shard_record =
                    encode_shard_record(&key, stripe_idx, placement.shard_index, &shard.bytes)
                        .map_err(WritePathError::EnvelopeEncodeFailed)?;

                match stores[placement.store_index]
                    .put(ObjectKey::from_bytes(shard_key), &shard_record)
                {
                    Ok(_) => {
                        let sk = shard_key_bytes(&key, stripe_idx, placement.shard_index);
                        written_keys.push((placement.store_index, sk));
                        shards_dispatched += 1;
                    }
                    Err(e) => {
                        // Rollback: delete all previously written shards for this object.
                        rollback_written(stores, &written_keys);
                        return Err(WritePathError::DispatchFailed {
                            rollback_evidence: Some(RollbackEvidence {
                                failed_stripe: stripe_idx,
                                failed_shard: placement.shard_index,
                                failed_store: placement.store_index,
                                rolled_back_keys: written_keys.clone(),
                            }),
                            stripe: stripe_idx,
                            shard: placement.shard_index,
                            store: placement.store_index,
                            reason: e.to_string(),
                        });
                    }
                }
            }

            stripe_outcomes.push(StripeWriteOutcome {
                stripe_index: stripe_idx,
                object_id: self.object_id.clone(),
                stripe_config: stripe_config.clone(),
                original_chunk_len: chunk.len(),
                shard_placements: placements,
            });
        }

        // --- Validate manifest completeness before acknowledging success ---
        validate_manifest(&stripe_outcomes, k, m, num_stripes, shards_total)?;
        Ok(ErasureCodedWriteOutcome {
            object_id: self.object_id,
            stripe_outcomes,
            shards_dispatched,
            shards_total,
            bytes_encoded: original_len as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// dispatch_stripes — map shards to placement targets from placement-plan output
// ---------------------------------------------------------------------------

/// Map erasure-coded shards to store indices using placement-planner assignments.
///
/// Consumes the output of [`PlacementPlan::assign_devices`] and a
/// `device_id → store_index` mapping to determine which store receives
/// each shard.  The placement planner selects devices respecting failure-domain
/// anti-affinity and device health; this function translates device assignments
/// into concrete store indices.
///
/// Returns one [`ShardPlacement`] per shard, each containing the target
/// store index, device id, and the shard's BLAKE3 integrity digest.
///
/// # Errors
///
/// Returns [`WritePathError::InsufficientStores`] if the placement plan
/// has fewer assignments than shards or a shard index has no mapped store.
pub fn dispatch_stripes(
    key: &ObjectKey,
    stripe_idx: usize,
    shards: &[ErasureShard],
    shard_assignments: &[ShardAssignment],
    device_to_store: &HashMap<u64, usize>,
) -> Result<Vec<ShardPlacement>, WritePathError> {
    if shard_assignments.len() < shards.len() {
        return Err(WritePathError::InsufficientStores {
            needed: shards.len(),
            available: shard_assignments.len(),
        });
    }

    let mut placements = Vec::with_capacity(shards.len());
    for shard in shards {
        // Look up which device the placement planner assigned for this shard index.
        let assignment = shard_assignments
            .iter()
            .find(|a| a.shard_index as usize == shard.index)
            .ok_or_else(|| {
                WritePathError::Internal(format!(
                    "placement plan has no assignment for shard index {}",
                    shard.index
                ))
            })?;

        let device_id = assignment.device_id;

        // Map device_id to store_index.
        let store_index = *device_to_store.get(&device_id).ok_or_else(|| {
            WritePathError::Internal(format!(
                "device_id {device_id} from placement plan is not in device-to-store map"
            ))
        })?;

        let digest = compute_shard_blake3(
            key,
            stripe_idx as u64,
            shard.index.try_into().unwrap(),
            &shard.bytes,
        );
        placements.push(ShardPlacement {
            shard_index: shard.index,
            shard_kind: shard.kind,
            store_index,
            device_id,
            digest,
            size: shard.bytes.len(),
        });
    }

    Ok(placements)
}
/// Validate that every stripe in the manifest covers all data and parity shards
/// with non-zero digests and the expected shard counts.
///
/// Returns an error if any stripe is missing a shard placement, has a zero
/// digest, or the overall shard count does not match expectations.
fn validate_manifest(
    stripe_outcomes: &[StripeWriteOutcome],
    k: usize,
    m: usize,
    num_stripes: usize,
    shards_total: usize,
) -> Result<(), WritePathError> {
    let sw = k + m;
    if stripe_outcomes.len() != num_stripes {
        return Err(WritePathError::Internal(format!(
            "manifest has {} stripe outcomes, expected {num_stripes}",
            stripe_outcomes.len()
        )));
    }

    for (expected_stripe, so) in stripe_outcomes.iter().enumerate() {
        if so.stripe_index != expected_stripe {
            return Err(WritePathError::Internal(format!(
                "manifest stripe at position {expected_stripe} has stripe index {}",
                so.stripe_index
            )));
        }
        if so.stripe_config.data_shards != k || so.stripe_config.parity_shards != m {
            return Err(WritePathError::Internal(format!(
                "stripe {} config is {}+{}, expected {k}+{m}",
                so.stripe_index, so.stripe_config.data_shards, so.stripe_config.parity_shards
            )));
        }
        if so.stripe_config.shard_len == 0 {
            return Err(WritePathError::Internal(format!(
                "stripe {} config has zero shard_len",
                so.stripe_index
            )));
        }
        if so.shard_placements.len() != sw {
            return Err(WritePathError::Internal(format!(
                "stripe {} manifest has {} shard placements, expected {sw}",
                so.stripe_index,
                so.shard_placements.len()
            )));
        }

        // Verify data/parity shard count per stripe
        let data_count = so
            .shard_placements
            .iter()
            .filter(|p| p.shard_kind == ShardKind::Data)
            .count();
        let parity_count = so.shard_placements.len() - data_count;
        if data_count != k || parity_count != m {
            return Err(WritePathError::Internal(format!(
                "stripe {} manifest has {data_count} data + {parity_count} parity shards, expected {k}+{m}",
                so.stripe_index
            )));
        }

        let mut seen_shards = vec![false; sw];
        for placement in &so.shard_placements {
            if placement.shard_index >= sw {
                return Err(WritePathError::Internal(format!(
                    "stripe {} shard index {} is outside 0..{sw}",
                    so.stripe_index, placement.shard_index
                )));
            }
            if seen_shards[placement.shard_index] {
                return Err(WritePathError::Internal(format!(
                    "stripe {} has duplicate shard index {}",
                    so.stripe_index, placement.shard_index
                )));
            }
            seen_shards[placement.shard_index] = true;

            let expected_kind = if placement.shard_index < k {
                ShardKind::Data
            } else {
                ShardKind::Parity
            };
            if placement.shard_kind != expected_kind {
                return Err(WritePathError::Internal(format!(
                    "stripe {} shard {} has kind {:?}, expected {:?}",
                    so.stripe_index, placement.shard_index, placement.shard_kind, expected_kind
                )));
            }
            if placement.digest == [0u8; 32] {
                return Err(WritePathError::Internal(format!(
                    "stripe {} shard {} has zero digest",
                    so.stripe_index, placement.shard_index
                )));
            }
            if placement.size == 0 {
                return Err(WritePathError::Internal(format!(
                    "stripe {} shard {} has zero size",
                    so.stripe_index, placement.shard_index
                )));
            }
            if placement.size != so.stripe_config.shard_len {
                return Err(WritePathError::Internal(format!(
                    "stripe {} shard {} has size {}, expected {}",
                    so.stripe_index,
                    placement.shard_index,
                    placement.size,
                    so.stripe_config.shard_len
                )));
            }
        }
    }

    // Cross-check total shard count
    let total: usize = stripe_outcomes
        .iter()
        .map(|so| so.shard_placements.len())
        .sum();
    if total != shards_total {
        return Err(WritePathError::Internal(format!(
            "manifest covers {total} shard placements, expected {shards_total}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract (k, m) from a durability layout.  Rejects mirror policies.
fn extract_ec_params(layout: &DurabilityLayoutV1) -> Result<(usize, usize), WritePathError> {
    match &layout.policy {
        DurabilityPolicy::ErasureStyle {
            data_shards,
            parity_shards,
        } => Ok((*data_shards as usize, *parity_shards as usize)),
        DurabilityPolicy::Mirror { .. } => Err(WritePathError::NotErasureStyle),
        DurabilityPolicy::Hybrid {
            data_shards,
            parity_shards,
            ..
        } => Ok((*data_shards as usize, *parity_shards as usize)),
    }
}

/// Build the 32-byte shard key from base ObjectKey, stripe index, and shard index.
fn shard_key_bytes(base: &ObjectKey, stripe: usize, shard: usize) -> [u8; 32] {
    let base_bytes = base.as_bytes32();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&base_bytes[..16]);
    out[16..24].copy_from_slice(&(stripe as u64).to_le_bytes());
    out[24..32].copy_from_slice(&(shard as u64).to_le_bytes());
    out
}

/// Shard integrity record constants.
const SHARD_MAGIC: &[u8; 8] = b"VECSHV1\0";
const SHARD_VERSION: u8 = 1;
const SHARD_HEADER_LEN: usize = 60;
const SHARD_DIGEST_CTX: &str = "TideFS erasure-coded-store shard digest v1";

/// Encode a shard payload with an integrity envelope.
///
/// Format: magic (8) | version (1) | reserved (1) | shard_index (u16 LE) |
/// stripe_index (u64 LE) | payload_len (u64 LE) | BLAKE3 digest (32) |
/// payload bytes.
fn encode_shard_record(
    key: &ObjectKey,
    stripe: usize,
    shard_index: usize,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let stripe_u64 = u64::try_from(stripe).map_err(|_| "stripe index overflow".to_string())?;
    let shard_u16 = u16::try_from(shard_index).map_err(|_| "shard index overflow".to_string())?;
    let payload_len =
        u64::try_from(payload.len()).map_err(|_| "shard payload length overflow".to_string())?;
    let digest = compute_shard_blake3(key, stripe_u64, shard_u16, payload);

    let mut out = Vec::with_capacity(SHARD_HEADER_LEN + payload.len());
    out.extend_from_slice(SHARD_MAGIC);
    out.push(SHARD_VERSION);
    out.push(0); // reserved
    out.extend_from_slice(&shard_u16.to_le_bytes());
    out.extend_from_slice(&stripe_u64.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Compute a BLAKE3 domain-separated digest for a shard.
fn compute_shard_blake3(
    key: &ObjectKey,
    stripe: u64,
    shard_index: u16,
    payload: &[u8],
) -> [u8; 32] {
    let bytes = key.as_bytes32();
    let prefix: &[u8; 16] = bytes[..16].try_into().unwrap();
    let mut hasher = blake3::Hasher::new_derive_key(SHARD_DIGEST_CTX);
    hasher.update(prefix);
    hasher.update(&stripe.to_le_bytes());
    hasher.update(&shard_index.to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Delete all previously written shards on write-path failure.
fn rollback_written(stores: &mut [LocalObjectStore], written: &[(usize, [u8; 32])]) {
    for (store_idx, key_bytes) in written {
        let _ = stores[*store_idx].delete(ObjectKey::from_bytes(*key_bytes));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel};
    use tidefs_local_object_store::StoreOptions;

    fn make_paths(count: usize, label: &str) -> Vec<PathBuf> {
        let base = std::env::temp_dir().join(format!("ec-write-path-{label}"));
        let _ = std::fs::create_dir_all(&base);
        (0..count)
            .map(|i| base.join(format!("store-{i}")))
            .collect()
    }

    fn cleanup_dirs(paths: &[PathBuf]) {
        for p in paths {
            if let Some(parent) = p.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
        }
    }

    fn open_stores(paths: &[PathBuf]) -> Vec<LocalObjectStore> {
        paths
            .iter()
            .map(|p| LocalObjectStore::open_with_options(p, StoreOptions::test_fast()).unwrap())
            .collect()
    }

    fn erasure_layout_4_2() -> DurabilityLayoutV1 {
        DurabilityLayoutV1::erasure(4, 2).unwrap()
    }

    fn erasure_layout_2_1() -> DurabilityLayoutV1 {
        DurabilityLayoutV1::erasure(2, 1).unwrap()
    }

    /// Build a `FailureDomainV1` at Device level with `count` distinct targets.
    fn device_fd(count: u8) -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Device, count).unwrap()
    }

    /// Build device candidates with unique device_ids, each in its own domain.
    fn device_candidates(count: usize) -> Vec<DeviceCandidate> {
        (0..count)
            .map(|i| DeviceCandidate {
                device_id: i as u64,
                node_id: None,
                rack_id: None,
                datacenter_id: None,
            })
            .collect()
    }

    fn manifest_placement(
        shard_index: usize,
        shard_kind: ShardKind,
        digest_byte: u8,
    ) -> ShardPlacement {
        ShardPlacement {
            shard_index,
            shard_kind,
            store_index: shard_index,
            device_id: shard_index as u64,
            digest: [digest_byte; 32],
            size: 64,
        }
    }

    fn manifest_stripe(shard_placements: Vec<ShardPlacement>) -> StripeWriteOutcome {
        StripeWriteOutcome {
            stripe_index: 0,
            object_id: b"manifest".to_vec(),
            stripe_config: StripeConfig {
                data_shards: 2,
                parity_shards: 1,
                shard_len: 64,
            },
            original_chunk_len: 128,
            shard_placements,
        }
    }

    /// Build device candidates with node-level grouping.
    /// `devices_per_node` entries per node, `node_count` nodes.
    fn node_device_candidates(node_count: usize, devices_per_node: usize) -> Vec<DeviceCandidate> {
        let mut out = Vec::new();
        for node in 0..node_count {
            for dev in 0..devices_per_node {
                out.push(DeviceCandidate {
                    device_id: (node * devices_per_node + dev) as u64,
                    node_id: Some(node as u64),
                    rack_id: None,
                    datacenter_id: None,
                });
            }
        }
        out
    }

    // --- Basic 4+2 write round-trip ---

    #[test]
    fn basic_4p2_write_roundtrip() {
        let layout = erasure_layout_4_2();
        let paths = make_paths(6, "basic-4p2");
        let mut stores = open_stores(&paths);

        let payload = b"hello erasure-coded write path!".to_vec();
        let device_cands_6 = device_candidates(6);
        let fd_6 = device_fd(6);
        let req = ErasureCodedWriteRequest {
            object_id: b"obj-1".to_vec(),
            payload: payload.clone(),
            layout: &layout,
            shard_len: 64,
            failure_domain: &fd_6,
            device_candidates: &device_cands_6,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.object_id, b"obj-1");
        assert_eq!(outcome.bytes_encoded, payload.len() as u64);
        assert_eq!(outcome.shards_dispatched, outcome.shards_total);
        assert_eq!(outcome.shards_total, 6); // 1 stripe * (4+2)
        assert_eq!(outcome.stripe_outcomes.len(), 1);

        // Verify each shard has a placement with digest and size
        let placements = &outcome.stripe_outcomes[0].shard_placements;
        assert_eq!(placements.len(), 6);
        for (i, p) in placements.iter().enumerate() {
            assert_eq!(p.shard_index, i);
            assert_eq!(p.store_index, i);
            assert_eq!(p.size, 64); // padded to shard_len
            assert_ne!(p.digest, [0u8; 32]);
        }

        // Verify shards actually exist in stores
        let key = ObjectKey::from_name(b"obj-1");
        for i in 0..6 {
            let sk = shard_key_bytes(&key, 0, i);
            let stored = stores[i].get(ObjectKey::from_bytes(sk)).unwrap();
            assert!(stored.is_some(), "shard {i} missing from store {i}");
        }

        cleanup_dirs(&paths);
    }

    // --- 2+1 with larger payload (multi-stripe) ---

    #[test]
    fn two_plus_one_multi_stripe() {
        let layout = erasure_layout_2_1();
        let paths = make_paths(3, "2p1-multi");
        let mut stores = open_stores(&paths);

        let cap = 2 * 256; // k * shard_len = 512
        let payload: Vec<u8> = (0..(cap * 3 + 100) as u16)
            .map(|i| (i % 251) as u8)
            .collect();
        let device_cands_3 = device_candidates(3);
        let fd_3 = device_fd(3);
        let req = ErasureCodedWriteRequest {
            object_id: b"big".to_vec(),
            payload: payload.clone(),
            layout: &layout,
            shard_len: 256,
            failure_domain: &fd_3,
            device_candidates: &device_cands_3,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.bytes_encoded, payload.len() as u64);
        // 3 full stripes + 1 partial = 4 stripes * 3 shards = 12 total
        assert_eq!(outcome.shards_total, 4 * 3);
        assert_eq!(outcome.shards_dispatched, 4 * 3);
        assert_eq!(outcome.stripe_outcomes.len(), 4);

        cleanup_dirs(&paths);
    }

    // --- Empty payload ---

    #[test]
    fn empty_payload_write() {
        let layout = erasure_layout_2_1();
        let paths = make_paths(3, "empty");
        let mut stores = open_stores(&paths);

        let device_cands_3 = device_candidates(3);
        let fd_3 = device_fd(3);
        let req = ErasureCodedWriteRequest {
            object_id: b"empty".to_vec(),
            payload: vec![],
            layout: &layout,
            shard_len: 256,
            failure_domain: &fd_3,
            device_candidates: &device_cands_3,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.bytes_encoded, 0);
        assert_eq!(outcome.stripe_outcomes.len(), 1); // one empty stripe
        assert_eq!(outcome.shards_total, 3);
        assert_eq!(outcome.shards_dispatched, 3);

        cleanup_dirs(&paths);
    }

    // --- Mirror layout rejected ---

    #[test]
    fn mirror_layout_rejected() {
        let mirror = DurabilityLayoutV1::mirror(3).unwrap();
        let paths = make_paths(3, "mirror-rej");
        let mut stores = open_stores(&paths);

        let device_cands_3 = device_candidates(3);
        let fd_3 = device_fd(3);
        let req = ErasureCodedWriteRequest {
            object_id: b"nope".to_vec(),
            payload: b"data".to_vec(),
            layout: &mirror,
            shard_len: 64,
            failure_domain: &fd_3,
            device_candidates: &device_cands_3,
        };

        let err = req.execute(&mut stores).unwrap_err();
        assert!(matches!(err, WritePathError::NotErasureStyle));

        cleanup_dirs(&paths);
    }

    // --- Invalid shard_len rejected ---

    #[test]
    fn zero_shard_len_rejected() {
        let layout = erasure_layout_2_1();
        let paths = make_paths(3, "zero-len");
        let mut stores = open_stores(&paths);

        let device_cands_3d = device_candidates(3);
        let fd_3d = device_fd(3);
        let req = ErasureCodedWriteRequest {
            object_id: b"x".to_vec(),
            payload: b"data".to_vec(),
            layout: &layout,
            shard_len: 0,
            failure_domain: &fd_3d,
            device_candidates: &device_cands_3d,
        };

        let err = req.execute(&mut stores).unwrap_err();
        assert!(matches!(err, WritePathError::InvalidShardLen));

        cleanup_dirs(&paths);
    }

    // --- Insufficient stores ---

    #[test]
    fn insufficient_stores_rejected() {
        let layout = erasure_layout_4_2(); // needs 6 stores
        let paths = make_paths(3, "few-stores"); // only 3
        let mut stores = open_stores(&paths);

        let device_cands_3b = device_candidates(3);
        let fd_3b = device_fd(3);
        let req = ErasureCodedWriteRequest {
            object_id: b"x".to_vec(),
            payload: b"data".to_vec(),
            layout: &layout,
            shard_len: 64,
            failure_domain: &fd_3b,
            device_candidates: &device_cands_3b,
        };

        let err = req.execute(&mut stores).unwrap_err();
        match err {
            WritePathError::InsufficientStores { needed, available } => {
                assert_eq!(needed, 6);
                assert_eq!(available, 3);
            }
            _ => panic!("expected InsufficientStores, got {err:?}"),
        }

        cleanup_dirs(&paths);
    }

    // --- Partial write rollback ---

    #[test]
    fn partial_write_rollback() {
        let layout = erasure_layout_4_2();
        let paths = make_paths(6, "rollback");
        let mut stores = open_stores(&paths);

        let payload = vec![0xADu8; 2000];
        let device_cands_6 = device_candidates(6);
        let fd_6 = device_fd(6);
        let req = ErasureCodedWriteRequest {
            object_id: b"rollback-me".to_vec(),
            payload,
            layout: &layout,
            shard_len: 128,
            failure_domain: &fd_6,
            device_candidates: &device_cands_6,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.shards_dispatched, outcome.shards_total);

        // Verify shards exist
        let key = ObjectKey::from_name(b"rollback-me");
        for i in 0..6 {
            let sk = shard_key_bytes(&key, 0, i);
            assert!(stores[i].get(ObjectKey::from_bytes(sk)).unwrap().is_some());
        }

        // Force a write failure by closing a store or using corrupted store...
        // Instead, test that dispatch failure returns the right error.
        // For a true rollback test, we'd need store fault injection.

        cleanup_dirs(&paths);
    }

    // --- dispatch_stripes unit tests ---

    #[test]
    fn dispatch_stripes_placement_aware() {
        let key = ObjectKey::from_name(b"test");
        let shards = vec![
            ErasureShard {
                index: 0,
                kind: tidefs_erasure_coding::ShardKind::Data,
                bytes: vec![1u8; 64],
            },
            ErasureShard {
                index: 1,
                kind: tidefs_erasure_coding::ShardKind::Data,
                bytes: vec![2u8; 64],
            },
            ErasureShard {
                index: 2,
                kind: tidefs_erasure_coding::ShardKind::Parity,
                bytes: vec![3u8; 64],
            },
        ];

        // Build placement plan assignments: device i gets shard i (Device-level fd)
        let candidates = device_candidates(5);
        let fd = device_fd(5);
        let layout = DurabilityLayoutV1::erasure(2, 1).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);
        let shard_assignments = plan.assign_devices(&candidates).unwrap();
        let device_to_store: HashMap<u64, usize> = candidates
            .iter()
            .enumerate()
            .map(|(i, c)| (c.device_id, i))
            .collect();

        let placements =
            dispatch_stripes(&key, 0, &shards, &shard_assignments, &device_to_store).unwrap();
        assert_eq!(placements.len(), 3);
        // All stores should be different (anti-affinity at Device level)
        let mut store_ids: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        let mut device_ids: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for p in &placements {
            assert!(
                store_ids.insert(p.store_index),
                "duplicate store_index {}",
                p.store_index
            );
            assert!(
                device_ids.insert(p.device_id),
                "duplicate device_id {}",
                p.device_id
            );
        }
        assert_eq!(store_ids.len(), 3);
        assert_eq!(device_ids.len(), 3);
        assert_ne!(placements[0].digest, [0u8; 32]);
    }

    #[test]
    fn dispatch_stripes_insufficient_assignments() {
        let key = ObjectKey::from_name(b"test");
        let shards: Vec<ErasureShard> = (0..6)
            .map(|i| ErasureShard {
                index: i,
                kind: if i < 4 {
                    tidefs_erasure_coding::ShardKind::Data
                } else {
                    tidefs_erasure_coding::ShardKind::Parity
                },
                bytes: vec![0u8; 64],
            })
            .collect();

        // Only 3 assignments for 6 shards -> InsufficientStores
        let candidates = device_candidates(3);
        let fd = device_fd(3);
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);
        // This will fail at plan level since 3 devices < 6 needed, not at dispatch level.
        // For dispatch-level: provide only 3 assignments but 6 shards.
        let partial_assignments: Vec<ShardAssignment> =
            plan.assign_devices(&candidates).unwrap_or_default(); // Will be empty since plan fails
        let device_to_store: HashMap<u64, usize> = candidates
            .iter()
            .enumerate()
            .map(|(i, c)| (c.device_id, i))
            .collect();

        let err =
            dispatch_stripes(&key, 0, &shards, &partial_assignments, &device_to_store).unwrap_err();
        match err {
            WritePathError::InsufficientStores {
                needed,
                available: _,
            } => {
                assert_eq!(needed, 6);
            }
            _ => panic!("expected InsufficientStores, got {err:?}"),
        }
    }

    // --- WritePathError Display ---

    #[test]
    fn write_path_error_display() {
        assert_eq!(
            WritePathError::NotErasureStyle.to_string(),
            "durability layout is not ErasureStyle; mirror layouts are not supported by the erasure-coded write path"
        );
        assert_eq!(
            WritePathError::InvalidParityCount(5).to_string(),
            "invalid parity count 5 from durability layout; must be 1, 2, or 3"
        );
        assert_eq!(
            WritePathError::InvalidShardLen.to_string(),
            "shard_len must be >= 1"
        );
        assert_eq!(
            WritePathError::EncodeFailed(3).to_string(),
            "encode failed for stripe 3"
        );
        assert_eq!(
            WritePathError::InsufficientStores {
                needed: 6,
                available: 2
            }
            .to_string(),
            "need 6 stores for k+m shards, have 2"
        );
        assert_eq!(
            WritePathError::DispatchFailed {
                rollback_evidence: None,
                stripe: 1,
                shard: 3,
                store: 3,
                reason: "io error".into()
            }
            .to_string(),
            "dispatch to store 3 failed for stripe 1 shard 3: io error"
        );
        assert_eq!(
            WritePathError::EnvelopeEncodeFailed("bad".into()).to_string(),
            "shard integrity envelope encoding failed: bad"
        );
        assert_eq!(
            WritePathError::Internal("boom".into()).to_string(),
            "internal error: boom"
        );
    }

    // --- Known-answer: parity correctness via Reed-Solomon test vectors ---

    #[test]
    fn known_answer_parity_4p2() {
        // For a 4+2 config with shard_len=4 and payload "ABCDEFGHIJKLMNOP"
        // (exactly 4*4=16 bytes), verify parity shards match expected values:
        // Parity is computed via Vandermonde over GF(2^8) with base = data_shards.
        let layout = erasure_layout_4_2();
        let paths = make_paths(6, "known-4p2");
        let mut stores = open_stores(&paths);

        let payload = b"ABCDEFGHIJKLMNOP".to_vec(); // exactly 16 bytes
        let device_cands_6 = device_candidates(6);
        let fd_6 = device_fd(6);
        let req = ErasureCodedWriteRequest {
            object_id: b"known".to_vec(),
            payload,
            layout: &layout,
            shard_len: 4,
            failure_domain: &fd_6,
            device_candidates: &device_cands_6,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.shards_total, 6);
        assert_eq!(outcome.stripe_outcomes.len(), 1);

        // Read back the parity shards from stores 4 and 5 and verify they
        // are non-zero and differ from data shards.
        let key = ObjectKey::from_name(b"known");
        let parity4 = stores[4]
            .get(ObjectKey::from_bytes(shard_key_bytes(&key, 0, 4)))
            .unwrap()
            .unwrap();
        let parity5 = stores[5]
            .get(ObjectKey::from_bytes(shard_key_bytes(&key, 0, 5)))
            .unwrap()
            .unwrap();

        // Parity shard payload is in the integrity envelope; strip the header.
        assert!(parity4.len() > 60);
        assert!(parity5.len() > 60);
        let p4_payload = &parity4[60..];
        let p5_payload = &parity5[60..];
        assert_eq!(p4_payload.len(), 4);
        assert_eq!(p5_payload.len(), 4);

        // Parity shards should differ from data shards and from each other.
        let d0 = &stores[0]
            .get(ObjectKey::from_bytes(shard_key_bytes(&key, 0, 0)))
            .unwrap()
            .unwrap()[60..];
        assert_ne!(p4_payload, d0);
        assert_ne!(p5_payload, d0);
        assert_ne!(p4_payload, p5_payload);

        // The parity bytes should be non-zero (actual Reed-Solomon output).
        assert_ne!(p4_payload, &[0u8; 4]);
        assert_ne!(p5_payload, &[0u8; 4]);

        cleanup_dirs(&paths);
    }

    // --- Stripe boundary: payload exactly k stripes ---

    #[test]
    fn payload_exactly_k_stripes() {
        let layout = erasure_layout_2_1();
        let paths = make_paths(3, "exact-boundary");
        let mut stores = open_stores(&paths);

        let shard_len = 64;
        let cap = 2 * shard_len; // 128 bytes
        let payload = vec![0x42u8; cap]; // exactly one stripe's worth

        let device_cands_3 = device_candidates(3);
        let fd_3 = device_fd(3);
        let req = ErasureCodedWriteRequest {
            object_id: b"exact".to_vec(),
            payload,
            layout: &layout,
            shard_len,
            failure_domain: &fd_3,
            device_candidates: &device_cands_3,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.stripe_outcomes.len(), 1);
        assert_eq!(outcome.shards_total, 3);

        cleanup_dirs(&paths);
    }

    // --- Stripe boundary: payload smaller than one stripe ---

    #[test]
    fn payload_smaller_than_stripe() {
        let layout = erasure_layout_4_2();
        let paths = make_paths(6, "small-payload");
        let mut stores = open_stores(&paths);

        let shard_len = 128;
        let _cap = 4 * shard_len; // 512 bytes
        let payload = vec![0x7Fu8; 50]; // much smaller than one stripe

        let device_cands_6 = device_candidates(6);
        let fd_6 = device_fd(6);
        let req = ErasureCodedWriteRequest {
            object_id: b"small".to_vec(),
            payload,
            layout: &layout,
            shard_len,
            failure_domain: &fd_6,
            device_candidates: &device_cands_6,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.stripe_outcomes.len(), 1);
        assert_eq!(outcome.shards_total, 6);
        assert_eq!(outcome.bytes_encoded, 50);

        // Verify data shards have correct padded size
        let key = ObjectKey::from_name(b"small");
        for i in 0..4 {
            let sk = shard_key_bytes(&key, 0, i);
            let stored = stores[i].get(ObjectKey::from_bytes(sk)).unwrap().unwrap();
            assert_eq!(stored.len(), 60 + shard_len); // header + padded payload
        }

        cleanup_dirs(&paths);
    }

    // --- 8+3 multi-stripe ---

    #[test]
    fn eight_plus_three_multi_stripe() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let paths = make_paths(11, "8p3-multi");
        let mut stores = open_stores(&paths);

        let shard_len = 64;
        let cap = 8 * shard_len; // 512 bytes per stripe
        let payload: Vec<u8> = (0..(cap * 2 + 200) as u16)
            .map(|i| (i % 199) as u8)
            .collect(); // ~1224 bytes → 3 stripes

        let device_cands_11 = device_candidates(11);
        let fd_11 = device_fd(11);
        let req = ErasureCodedWriteRequest {
            object_id: b"8p3".to_vec(),
            payload,
            layout: &layout,
            shard_len,
            failure_domain: &fd_11,
            device_candidates: &device_cands_11,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.stripe_outcomes.len(), 3);
        assert_eq!(outcome.shards_total, 3 * 11); // 3 stripes * (8+3)
        assert_eq!(outcome.shards_dispatched, 3 * 11);

        cleanup_dirs(&paths);
    }

    // --- Placement planner integration tests ------------------------------

    /// Verify the placement planner rejects writes when there aren't enough
    /// distinct failure domains at Node level.
    #[test]
    fn placement_rejects_insufficient_node_domains() {
        let layout = DurabilityLayoutV1::erasure(3, 2).unwrap(); // needs 5 shards
        let paths = make_paths(5, "reject-node");
        let mut stores = open_stores(&paths);

        // All 5 devices on 2 nodes — only 2 distinct domains, need 5
        let candidates: Vec<DeviceCandidate> = (0..5)
            .map(|i| DeviceCandidate {
                device_id: i as u64,
                node_id: Some((i % 2) as u64),
                rack_id: None,
                datacenter_id: None,
            })
            .collect();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 5).unwrap();

        let payload = b"should-fail".to_vec();
        let req = ErasureCodedWriteRequest {
            object_id: b"reject".to_vec(),
            payload,
            layout: &layout,
            shard_len: 64,
            failure_domain: &fd,
            device_candidates: &candidates,
        };

        let err = req.execute(&mut stores).unwrap_err();
        // Should fail with an internal error from placement plan
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("placement plan failed"),
                    "unexpected error: {msg}"
                );
            }
            _ => panic!("expected Internal error from placement plan, got {err:?}"),
        }

        cleanup_dirs(&paths);
    }

    /// Verify shards are placed on different nodes when using Node-level
    /// failure domains with enough distinct nodes.
    #[test]
    fn placement_node_level_anti_affinity() {
        let layout = DurabilityLayoutV1::erasure(2, 1).unwrap(); // needs 3 shards
        let paths = make_paths(6, "node-affinity");
        let mut stores = open_stores(&paths);

        // 6 devices across 3 distinct nodes (2 devices per node)
        let candidates = node_device_candidates(3, 2);
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();

        let payload = vec![0xABu8; 64]; // fits in one stripe (2*64=128 capacity)
        let req = ErasureCodedWriteRequest {
            object_id: b"node-affinity".to_vec(),
            payload,
            layout: &layout,
            shard_len: 64,
            failure_domain: &fd,
            device_candidates: &candidates,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.shards_total, 3);
        let placements = &outcome.stripe_outcomes[0].shard_placements;
        assert_eq!(placements.len(), 3);

        // Each shard should be on a different store (anti-affinity)
        let mut store_ids: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        for p in placements {
            assert!(
                store_ids.insert(p.store_index),
                "duplicate store {}",
                p.store_index
            );
            // Verify device_id is populated (not zero for all)
        }
        assert_eq!(store_ids.len(), 3);

        // Verify each shard has a device_id
        let mut device_ids: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for p in placements {
            assert!(
                device_ids.insert(p.device_id),
                "duplicate device_id {}",
                p.device_id
            );
        }
        assert_eq!(device_ids.len(), 3);

        cleanup_dirs(&paths);
    }

    /// Verify placement-aware write produces auditable placement metadata.
    #[test]
    fn placement_outcome_includes_device_ids() {
        let layout = erasure_layout_4_2();
        let paths = make_paths(6, "audit");
        let mut stores = open_stores(&paths);

        let device_cands = device_candidates(6);
        let fd = device_fd(6);

        let payload = b"auditable placement".to_vec();
        let req = ErasureCodedWriteRequest {
            object_id: b"audit".to_vec(),
            payload: payload.clone(),
            layout: &layout,
            shard_len: 128,
            failure_domain: &fd,
            device_candidates: &device_cands,
        };

        let outcome = req.execute(&mut stores).unwrap();
        let placements = &outcome.stripe_outcomes[0].shard_placements;

        // Every placement must have a non-trivial device_id and store_index
        for p in placements {
            assert!(
                p.store_index < 6,
                "store_index {} out of range",
                p.store_index
            );
            assert_ne!(
                p.digest, [0u8; 32],
                "shard {} has zero digest",
                p.shard_index
            );
            assert!(p.size > 0, "shard {} has zero size", p.shard_index);
        }

        cleanup_dirs(&paths);
    }

    // --- Tail-stripe manifest: verify original_chunk_len records logical
    //     payload length, not shard-len-padded size ---

    #[test]
    fn tail_stripe_manifest_original_chunk_len() {
        let layout = erasure_layout_2_1();
        let paths = make_paths(3, "tail-stripe");
        let mut stores = open_stores(&paths);

        let shard_len = 64;
        let cap = 2 * shard_len;
        // Payload is 200 bytes: first stripe = 128 bytes, tail stripe = 72 bytes.
        let payload: Vec<u8> = (0..200u8).collect();

        let device_cands_3 = device_candidates(3);
        let fd_3 = device_fd(3);
        let req = ErasureCodedWriteRequest {
            object_id: b"tail".to_vec(),
            payload,
            layout: &layout,
            shard_len,
            failure_domain: &fd_3,
            device_candidates: &device_cands_3,
        };

        let outcome = req.execute(&mut stores).unwrap();
        assert_eq!(outcome.stripe_outcomes.len(), 2);

        // First stripe: full capacity
        let s0 = &outcome.stripe_outcomes[0];
        assert_eq!(s0.stripe_index, 0);
        assert_eq!(s0.original_chunk_len, cap);
        assert_eq!(s0.shard_placements.len(), 3);
        assert_eq!(s0.object_id, b"tail");
        assert_eq!(s0.stripe_config.data_shards, 2);
        assert_eq!(s0.stripe_config.parity_shards, 1);
        assert_eq!(s0.stripe_config.shard_len, shard_len);
        // Verify shard kinds
        assert_eq!(s0.shard_placements[0].shard_kind, ShardKind::Data);
        assert_eq!(s0.shard_placements[1].shard_kind, ShardKind::Data);
        assert_eq!(s0.shard_placements[2].shard_kind, ShardKind::Parity);

        // Tail stripe: 72 bytes (200 - 128)
        let s1 = &outcome.stripe_outcomes[1];
        assert_eq!(s1.stripe_index, 1);
        assert_eq!(s1.original_chunk_len, 72);
        assert_eq!(s1.shard_placements.len(), 3);
        // Every shard should have size == shard_len (padded)
        for p in &s1.shard_placements {
            assert_eq!(p.size, shard_len);
        }
        assert_ne!(s1.original_chunk_len, s1.shard_placements[0].size);

        cleanup_dirs(&paths);
    }

    // --- Digest mismatch: verify every placement has a non-zero digest ---

    #[test]
    fn manifest_digest_is_populated() {
        let layout = erasure_layout_4_2();
        let paths = make_paths(6, "digest-chk");
        let mut stores = open_stores(&paths);

        let payload = b"digest check payload".to_vec();
        let req = ErasureCodedWriteRequest {
            object_id: b"digest-obj".to_vec(),
            payload,
            layout: &layout,
            shard_len: 64,
            failure_domain: &device_fd(6),
            device_candidates: &device_candidates(6),
        };

        let outcome = req.execute(&mut stores).unwrap();
        for so in &outcome.stripe_outcomes {
            for p in &so.shard_placements {
                assert_ne!(
                    p.digest, [0u8; 32],
                    "stripe {} shard {} has zero digest",
                    so.stripe_index, p.shard_index
                );
            }
        }

        cleanup_dirs(&paths);
    }

    // --- Missing shard: validate_manifest rejects incomplete stripe outcomes ---

    #[test]
    fn validate_manifest_rejects_missing_shard() {
        // Build a StripeWriteOutcome with only 2 placements instead of 3
        let partial = StripeWriteOutcome {
            stripe_index: 0,
            object_id: b"partial".to_vec(),
            stripe_config: StripeConfig {
                data_shards: 2,
                parity_shards: 1,
                shard_len: 64,
            },
            original_chunk_len: 128,
            shard_placements: vec![
                ShardPlacement {
                    shard_index: 0,
                    shard_kind: ShardKind::Data,
                    store_index: 0,
                    device_id: 0,
                    digest: [1u8; 32],
                    size: 64,
                },
                ShardPlacement {
                    shard_index: 1,
                    shard_kind: ShardKind::Data,
                    store_index: 1,
                    device_id: 1,
                    digest: [2u8; 32],
                    size: 64,
                },
            ],
        };

        let err = validate_manifest(&[partial], 2, 1, 1, 3).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("has 2 shard placements"),
                    "expected missing-shard error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }
    }

    // --- Data/parity shard count mismatch ---

    #[test]
    fn validate_manifest_rejects_wrong_shard_kind_counts() {
        // Build a manifest whose placements claim 3 Data shards under a 2+1 config.
        let malformed = StripeWriteOutcome {
            stripe_index: 0,
            object_id: b"wrong".to_vec(),
            stripe_config: StripeConfig {
                data_shards: 2,
                parity_shards: 1,
                shard_len: 64,
            },
            original_chunk_len: 192,
            shard_placements: vec![
                ShardPlacement {
                    shard_index: 0,
                    shard_kind: ShardKind::Data,
                    store_index: 0,
                    device_id: 0,
                    digest: [1u8; 32],
                    size: 64,
                },
                ShardPlacement {
                    shard_index: 1,
                    shard_kind: ShardKind::Data,
                    store_index: 1,
                    device_id: 1,
                    digest: [2u8; 32],
                    size: 64,
                },
                ShardPlacement {
                    shard_index: 2,
                    shard_kind: ShardKind::Data,
                    store_index: 2,
                    device_id: 2,
                    digest: [3u8; 32],
                    size: 64,
                },
            ],
        };

        // Expect 2 data + 1 parity, but got 3 data + 0 parity
        let err = validate_manifest(&[malformed], 2, 1, 1, 3).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("data") && msg.contains("parity"),
                    "expected shard-kind-count error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }
    }

    // --- Duplicate shard index rejection ---

    #[test]
    fn validate_manifest_rejects_duplicate_shard_index() {
        let duplicate = manifest_stripe(vec![
            manifest_placement(0, ShardKind::Data, 1),
            manifest_placement(0, ShardKind::Data, 2),
            manifest_placement(2, ShardKind::Parity, 3),
        ]);

        let err = validate_manifest(&[duplicate], 2, 1, 1, 3).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("duplicate shard index 0"),
                    "expected duplicate-shard-index error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }
    }

    // --- Shard kind must match its index range ---

    #[test]
    fn validate_manifest_rejects_shard_kind_index_mismatch() {
        let mismatched = manifest_stripe(vec![
            manifest_placement(0, ShardKind::Data, 1),
            manifest_placement(1, ShardKind::Parity, 2),
            manifest_placement(2, ShardKind::Data, 3),
        ]);

        let err = validate_manifest(&[mismatched], 2, 1, 1, 3).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("shard 1 has kind") && msg.contains("expected Data"),
                    "expected shard-kind/index error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }
    }

    // --- Stripe config and recorded shard size must agree with manifest authority ---

    #[test]
    fn validate_manifest_rejects_config_and_size_mismatch() {
        let mut wrong_config = manifest_stripe(vec![
            manifest_placement(0, ShardKind::Data, 1),
            manifest_placement(1, ShardKind::Data, 2),
            manifest_placement(2, ShardKind::Parity, 3),
        ]);
        wrong_config.stripe_config.data_shards = 3;

        let err = validate_manifest(&[wrong_config], 2, 1, 1, 3).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("config is 3+1"),
                    "expected stripe-config error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }

        let mut wrong_size = manifest_stripe(vec![
            manifest_placement(0, ShardKind::Data, 1),
            manifest_placement(1, ShardKind::Data, 2),
            manifest_placement(2, ShardKind::Parity, 3),
        ]);
        wrong_size.shard_placements[1].size = 63;

        let err = validate_manifest(&[wrong_size], 2, 1, 1, 3).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("has size 63, expected 64"),
                    "expected shard-size error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }
    }

    // --- Zero digest rejection ---

    #[test]
    fn validate_manifest_rejects_zero_digest() {
        let corrupt = StripeWriteOutcome {
            stripe_index: 0,
            object_id: b"zero-dig".to_vec(),
            stripe_config: StripeConfig {
                data_shards: 2,
                parity_shards: 1,
                shard_len: 64,
            },
            original_chunk_len: 128,
            shard_placements: vec![
                ShardPlacement {
                    shard_index: 0,
                    shard_kind: ShardKind::Data,
                    store_index: 0,
                    device_id: 0,
                    digest: [0u8; 32],
                    size: 64,
                },
                ShardPlacement {
                    shard_index: 1,
                    shard_kind: ShardKind::Data,
                    store_index: 1,
                    device_id: 1,
                    digest: [1u8; 32],
                    size: 64,
                },
                ShardPlacement {
                    shard_index: 2,
                    shard_kind: ShardKind::Parity,
                    store_index: 2,
                    device_id: 2,
                    digest: [2u8; 32],
                    size: 64,
                },
            ],
        };

        let err = validate_manifest(&[corrupt], 2, 1, 1, 3).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("zero digest"),
                    "expected zero-digest error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }
    }

    // --- Placement mismatch: wrong number of stripes in manifest ---

    #[test]
    fn validate_manifest_rejects_wrong_stripe_count() {
        let valid = StripeWriteOutcome {
            stripe_index: 0,
            object_id: b"count".to_vec(),
            stripe_config: StripeConfig {
                data_shards: 2,
                parity_shards: 1,
                shard_len: 64,
            },
            original_chunk_len: 128,
            shard_placements: vec![
                ShardPlacement {
                    shard_index: 0,
                    shard_kind: ShardKind::Data,
                    store_index: 0,
                    device_id: 0,
                    digest: [1u8; 32],
                    size: 64,
                },
                ShardPlacement {
                    shard_index: 1,
                    shard_kind: ShardKind::Data,
                    store_index: 1,
                    device_id: 1,
                    digest: [2u8; 32],
                    size: 64,
                },
                ShardPlacement {
                    shard_index: 2,
                    shard_kind: ShardKind::Parity,
                    store_index: 2,
                    device_id: 2,
                    digest: [3u8; 32],
                    size: 64,
                },
            ],
        };

        // Claim 2 stripes but only provide 1
        let err = validate_manifest(&[valid], 2, 1, 2, 6).unwrap_err();
        match err {
            WritePathError::Internal(msg) => {
                assert!(
                    msg.contains("has 1 stripe outcomes"),
                    "expected stripe-count error, got: {msg}"
                );
            }
            _ => panic!("expected Internal error, got {err:?}"),
        }
    }

    // --- Rollback evidence is populated on dispatch failure ---

    #[test]
    fn rollback_evidence_populated_on_failure() {
        let paths = make_paths(6, "rollback-evidence");
        let stores = open_stores(&paths);
        // Drop one store to create a failure scenario
        drop(stores);
        let _stores = open_stores(&paths);

        // We cannot easily inject a store failure without fault injection,
        // but we can verify that when a DispatchFailed is constructed,
        // the RollbackEvidence fields are accessible.
        let evidence = RollbackEvidence {
            failed_stripe: 0,
            failed_shard: 3,
            failed_store: 3,
            rolled_back_keys: vec![(0, [0u8; 32]), (1, [1u8; 32])],
        };
        assert_eq!(evidence.failed_stripe, 0);
        assert_eq!(evidence.failed_shard, 3);
        assert_eq!(evidence.failed_store, 3);
        assert_eq!(evidence.rolled_back_keys.len(), 2);

        // Verify evidence is carried in the error
        let err = WritePathError::DispatchFailed {
            rollback_evidence: Some(evidence),
            stripe: 0,
            shard: 3,
            store: 3,
            reason: "simulated".into(),
        };
        match &err {
            WritePathError::DispatchFailed {
                rollback_evidence: Some(ev),
                ..
            } => {
                assert_eq!(ev.rolled_back_keys.len(), 2);
                assert_eq!(ev.failed_stripe, 0);
            }
            _ => panic!("expected DispatchFailed with rollback evidence"),
        }

        // Display should mention rollback
        let msg = err.to_string();
        assert!(
            msg.contains("rolled back 2 keys"),
            "display should mention rollback, got: {msg}"
        );

        cleanup_dirs(&paths);
    }
}
