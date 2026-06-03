//! Directory-based space quotas and reservations (ZFS dataset parity).
//!
//! Per-directory hard/soft limits on bytes and inode counts, plus
//! guaranteed-minimum space reservations, modeled on ZFS quota/refquota/reservation.
//! Quotas apply to an entire directory subtree; nested quotas use the
//! most restrictive limit along the ancestor chain.

use std::collections::{BTreeMap, HashMap};

use tidefs_local_object_store::ObjectKey;
use tidefs_types_vfs_core::InodeId;

use crate::constants::content_chunk_size;
use crate::error::FileSystemError;
use crate::Result;

/// Per-directory space quota configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaConfig {
    pub hard_limit_bytes: u64,
    pub soft_limit_bytes: u64,
    pub hard_limit_inodes: u64,
    pub soft_limit_inodes: u64,
    pub reservation_bytes: u64,
}

impl QuotaConfig {
    #[allow(dead_code)] // INTENT: quota types for planned per-dataset space enforcement
    pub fn is_active(&self) -> bool {
        self.hard_limit_bytes > 0
            || self.soft_limit_bytes > 0
            || self.hard_limit_inodes > 0
            || self.soft_limit_inodes > 0
            || self.reservation_bytes > 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaUsage {
    pub bytes_used: u64,
    pub inodes_used: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaEntry {
    pub config: QuotaConfig,
    pub usage: QuotaUsage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaDecision {
    Allowed,
    HardBytesExceeded {
        limit_bytes: u64,
        current_bytes: u64,
        delta_bytes: u64,
    },
    HardInodesExceeded {
        limit_inodes: u64,
        current_inodes: u64,
    },
    SoftBytesExceeded {
        limit_bytes: u64,
        current_bytes: u64,
        delta_bytes: u64,
    },
    SoftInodesExceeded {
        limit_inodes: u64,
        current_inodes: u64,
    },
    ReservationViolation {
        reserved_bytes: u64,
        free_bytes: u64,
    },
}

impl QuotaDecision {
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            QuotaDecision::HardBytesExceeded { .. }
                | QuotaDecision::HardInodesExceeded { .. }
                | QuotaDecision::ReservationViolation { .. }
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QuotaTable {
    entries: BTreeMap<InodeId, QuotaEntry>,
}

impl QuotaTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    #[allow(dead_code)] // INTENT: quota types for planned per-dataset space enforcement
    pub fn set_quota(&mut self, dir_inode: InodeId, config: QuotaConfig) {
        if config.is_active() {
            let usage = self
                .entries
                .get(&dir_inode)
                .map(|e| e.usage)
                .unwrap_or_default();
            self.entries.insert(dir_inode, QuotaEntry { config, usage });
        } else {
            self.entries.remove(&dir_inode);
        }
    }
    #[allow(dead_code)] // INTENT: quota types for planned per-dataset space enforcement
    pub fn remove_quota(&mut self, dir_inode: InodeId) {
        self.entries.remove(&dir_inode);
    }
    #[allow(dead_code)] // INTENT: quota types for planned per-dataset space enforcement
    pub fn get(&self, dir_inode: InodeId) -> Option<&QuotaEntry> {
        self.entries.get(&dir_inode)
    }
    #[allow(dead_code)] // INTENT: quota types for planned per-dataset space enforcement
    pub fn quota_dirs(&self) -> impl Iterator<Item = InodeId> + '_ {
        self.entries.keys().copied()
    }
    pub fn total_reserved_bytes(&self) -> u64 {
        self.entries
            .values()
            .map(|e| e.config.reservation_bytes)
            .sum()
    }
    #[allow(dead_code)] // INTENT: quota types for planned per-dataset space enforcement
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn check_delta(
        &self,
        ancestors: &[InodeId],
        delta_bytes: u64,
        delta_inodes: u64,
        pool_free_bytes: u64,
    ) -> QuotaDecision {
        let mut decision = QuotaDecision::Allowed;
        for &ancestor in ancestors {
            if let Some(entry) = self.entries.get(&ancestor) {
                let cfg = &entry.config;
                if cfg.hard_limit_bytes > 0 {
                    let projected = entry.usage.bytes_used.saturating_add(delta_bytes);
                    if projected > cfg.hard_limit_bytes {
                        return QuotaDecision::HardBytesExceeded {
                            limit_bytes: cfg.hard_limit_bytes,
                            current_bytes: entry.usage.bytes_used,
                            delta_bytes,
                        };
                    }
                }
                if cfg.soft_limit_bytes > 0 && cfg.hard_limit_bytes == 0 {
                    let projected = entry.usage.bytes_used.saturating_add(delta_bytes);
                    if projected > cfg.soft_limit_bytes {
                        decision = QuotaDecision::SoftBytesExceeded {
                            limit_bytes: cfg.soft_limit_bytes,
                            current_bytes: entry.usage.bytes_used,
                            delta_bytes,
                        };
                    }
                }
                if cfg.hard_limit_inodes > 0 && delta_inodes > 0 {
                    let projected = entry.usage.inodes_used.saturating_add(delta_inodes);
                    if projected > cfg.hard_limit_inodes {
                        return QuotaDecision::HardInodesExceeded {
                            limit_inodes: cfg.hard_limit_inodes,
                            current_inodes: entry.usage.inodes_used,
                        };
                    }
                }
                if cfg.soft_limit_inodes > 0 && cfg.hard_limit_inodes == 0 && delta_inodes > 0 {
                    let projected = entry.usage.inodes_used.saturating_add(delta_inodes);
                    if projected > cfg.soft_limit_inodes {
                        decision = QuotaDecision::SoftInodesExceeded {
                            limit_inodes: cfg.soft_limit_inodes,
                            current_inodes: entry.usage.inodes_used,
                        };
                    }
                }
                if cfg.reservation_bytes > 0 {
                    let total_reserved = self.total_reserved_bytes();
                    let after_alloc = pool_free_bytes.saturating_sub(delta_bytes);
                    if after_alloc < total_reserved {
                        return QuotaDecision::ReservationViolation {
                            reserved_bytes: total_reserved,
                            free_bytes: pool_free_bytes,
                        };
                    }
                }
            }
        }
        decision
    }

    pub fn apply_delta(&mut self, ancestors: &[InodeId], delta_bytes: u64, delta_inodes: u64) {
        for &ancestor in ancestors {
            if let Some(entry) = self.entries.get_mut(&ancestor) {
                entry.usage.bytes_used = entry.usage.bytes_used.saturating_add(delta_bytes);
                entry.usage.inodes_used = entry.usage.inodes_used.saturating_add(delta_inodes);
            }
        }
    }
    #[allow(dead_code)] // INTENT: quota types for planned per-dataset space enforcement
    pub fn recompute_all(
        &mut self,
        parent_map: &HashMap<InodeId, InodeId>,
        size_map: &HashMap<InodeId, u64>,
    ) {
        for entry in self.entries.values_mut() {
            entry.usage = QuotaUsage::default();
        }
        let mut dir_children: HashMap<InodeId, Vec<InodeId>> = HashMap::new();
        for (&child, &parent) in parent_map {
            dir_children.entry(parent).or_default().push(child);
        }
        for quota_dir in self.entries.keys().copied().collect::<Vec<_>>() {
            let mut stack = dir_children.get(&quota_dir).cloned().unwrap_or_default();
            while let Some(child) = stack.pop() {
                if let Some(size) = size_map.get(&child) {
                    let grains = allocation_grains_for_len(*size);
                    self.entries.get_mut(&quota_dir).unwrap().usage.bytes_used = self.entries
                        [&quota_dir]
                        .usage
                        .bytes_used
                        .saturating_add(grains);
                }
                self.entries.get_mut(&quota_dir).unwrap().usage.inodes_used =
                    self.entries[&quota_dir].usage.inodes_used.saturating_add(1);
                if let Some(grandchildren) = dir_children.get(&child) {
                    stack.extend_from_slice(grandchildren);
                }
            }
            self.entries.get_mut(&quota_dir).unwrap().usage.inodes_used =
                self.entries[&quota_dir].usage.inodes_used.saturating_add(1);
        }
    }

    pub fn quota_limited_available(&self, ancestors: &[InodeId], pool_free_bytes: u64) -> u64 {
        let total_reserved = self.total_reserved_bytes();
        let after_reservation = pool_free_bytes.saturating_sub(total_reserved);
        let mut min_hard = u64::MAX;
        for &ancestor in ancestors {
            if let Some(entry) = self.entries.get(&ancestor) {
                if entry.config.hard_limit_bytes > 0 {
                    let remaining = entry
                        .config
                        .hard_limit_bytes
                        .saturating_sub(entry.usage.bytes_used);
                    min_hard = min_hard.min(remaining);
                }
            }
        }
        after_reservation.min(min_hard)
    }
}

// Binary encoding
const QUOTA_TABLE_MAGIC: &[u8; 6] = b"VQTA01";
const QUOTA_ENTRY_ENCODED_SIZE: usize = 64;

impl QuotaTable {
    pub fn encode(&self) -> Vec<u8> {
        let cap = 6 + 4 + self.entries.len() * QUOTA_ENTRY_ENCODED_SIZE;
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(QUOTA_TABLE_MAGIC);
        let count: u32 = self.entries.len() as u32;
        out.extend_from_slice(&count.to_le_bytes());
        for (&dir_inode, entry) in &self.entries {
            out.extend_from_slice(&dir_inode.get().to_le_bytes());
            out.extend_from_slice(&entry.config.hard_limit_bytes.to_le_bytes());
            out.extend_from_slice(&entry.config.soft_limit_bytes.to_le_bytes());
            out.extend_from_slice(&entry.config.hard_limit_inodes.to_le_bytes());
            out.extend_from_slice(&entry.config.soft_limit_inodes.to_le_bytes());
            out.extend_from_slice(&entry.config.reservation_bytes.to_le_bytes());
            out.extend_from_slice(&entry.usage.bytes_used.to_le_bytes());
            out.extend_from_slice(&entry.usage.inodes_used.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 {
            return Err(FileSystemError::Decode {
                object: "quota table",
                reason: "too short for header",
            });
        }
        if &bytes[..6] != QUOTA_TABLE_MAGIC {
            return Err(FileSystemError::Decode {
                object: "quota table",
                reason: "magic bytes do not match",
            });
        }
        let count = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        let expected_len = 10 + count * QUOTA_ENTRY_ENCODED_SIZE;
        if bytes.len() != expected_len {
            return Err(FileSystemError::Decode {
                object: "quota table",
                reason: "length does not match expected entry count",
            });
        }
        let mut entries = BTreeMap::new();
        for i in 0..count {
            let offset = 10 + i * QUOTA_ENTRY_ENCODED_SIZE;
            let slice = &bytes[offset..offset + QUOTA_ENTRY_ENCODED_SIZE];
            let inode_id = InodeId::new(u64::from_le_bytes(slice[0..8].try_into().unwrap()));
            let config = QuotaConfig {
                hard_limit_bytes: u64::from_le_bytes(slice[8..16].try_into().unwrap()),
                soft_limit_bytes: u64::from_le_bytes(slice[16..24].try_into().unwrap()),
                hard_limit_inodes: u64::from_le_bytes(slice[24..32].try_into().unwrap()),
                soft_limit_inodes: u64::from_le_bytes(slice[32..40].try_into().unwrap()),
                reservation_bytes: u64::from_le_bytes(slice[40..48].try_into().unwrap()),
            };
            let usage = QuotaUsage {
                bytes_used: u64::from_le_bytes(slice[48..56].try_into().unwrap()),
                inodes_used: u64::from_le_bytes(slice[56..64].try_into().unwrap()),
            };
            entries.insert(inode_id, QuotaEntry { config, usage });
        }
        Ok(Self { entries })
    }
}

pub fn quota_table_object_key() -> ObjectKey {
    ObjectKey::from_name("tidefs.local-filesystem.v1.quota-table")
}

pub(crate) fn allocation_grains_for_len(len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    len.saturating_add(content_chunk_size() as u64 - 1) / content_chunk_size() as u64
        * content_chunk_size() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inode(id: u64) -> InodeId {
        InodeId::new(id)
    }

    #[test]
    fn set_and_get_quota() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 1_000_000,
                hard_limit_inodes: 100,
                ..Default::default()
            },
        );
        let entry = table.get(inode(10)).unwrap();
        assert_eq!(entry.config.hard_limit_bytes, 1_000_000);
        assert_eq!(entry.config.hard_limit_inodes, 100);
    }

    #[test]
    fn remove_quota() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 100,
                ..Default::default()
            },
        );
        table.remove_quota(inode(10));
        assert!(table.get(inode(10)).is_none());
    }

    #[test]
    fn check_delta_hard_bytes_blocks_write() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        table.apply_delta(&[inode(10)], 800, 0);
        let decision = table.check_delta(&[inode(10)], 300, 0, u64::MAX);
        assert!(decision.is_refusal());
        assert!(matches!(decision, QuotaDecision::HardBytesExceeded { .. }));
    }

    #[test]
    fn check_delta_within_limits_allows_write() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        assert!(!table
            .check_delta(&[inode(10)], 500, 0, u64::MAX)
            .is_refusal());
    }

    #[test]
    fn nested_quota_most_restrictive_wins() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(5),
            QuotaConfig {
                hard_limit_bytes: 10_000,
                ..Default::default()
            },
        );
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 100,
                ..Default::default()
            },
        );
        assert!(table
            .check_delta(&[inode(5), inode(10)], 200, 0, u64::MAX)
            .is_refusal());
    }

    #[test]
    fn apply_delta_updates_ancestors() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(5),
            QuotaConfig {
                hard_limit_bytes: 10_000,
                ..Default::default()
            },
        );
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        table.apply_delta(&[inode(5), inode(10)], 400, 1);
        assert_eq!(table.get(inode(5)).unwrap().usage.bytes_used, 400);
        assert_eq!(table.get(inode(10)).unwrap().usage.bytes_used, 400);
    }

    #[test]
    fn reservation_violation_when_free_below_total_reserved() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(1),
            QuotaConfig {
                reservation_bytes: 500,
                ..Default::default()
            },
        );
        assert!(table.check_delta(&[inode(1)], 100, 0, 300).is_refusal());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 1_000_000,
                soft_limit_bytes: 500_000,
                hard_limit_inodes: 10_000,
                soft_limit_inodes: 5_000,
                reservation_bytes: 100_000,
            },
        );
        table.apply_delta(&[inode(10)], 200_000, 50);
        table.set_quota(
            inode(20),
            QuotaConfig {
                hard_limit_bytes: 5_000_000,
                ..Default::default()
            },
        );
        let decoded = QuotaTable::decode(&table.encode()).unwrap();
        assert_eq!(table, decoded);
    }

    #[test]
    fn quota_limited_available_accounts_for_limits_and_reservations() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 1000,
                reservation_bytes: 200,
                ..Default::default()
            },
        );
        table.apply_delta(&[inode(10)], 400, 0);
        assert_eq!(table.quota_limited_available(&[inode(10)], 1000), 600);
    }

    #[test]
    fn recompute_all_rebuilds_usage() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(1),
            QuotaConfig {
                hard_limit_bytes: 10_000,
                hard_limit_inodes: 100,
                ..Default::default()
            },
        );
        table.apply_delta(&[inode(1)], 9999, 99);
        let mut parent_map = HashMap::new();
        parent_map.insert(inode(2), inode(1));
        let mut size_map = HashMap::new();
        size_map.insert(inode(2), 100);
        table.recompute_all(&parent_map, &size_map);
        let entry = table.get(inode(1)).unwrap();
        assert_eq!(entry.usage.bytes_used, allocation_grains_for_len(100));
        assert_eq!(entry.usage.inodes_used, 2);
    }

    #[test]
    fn is_active_false_for_default_config() {
        assert!(!QuotaConfig::default().is_active());
    }
    #[test]
    fn is_active_true_when_any_field_set() {
        assert!(QuotaConfig {
            hard_limit_bytes: 1,
            ..Default::default()
        }
        .is_active());
    }
    #[test]
    fn encode_empty_table() {
        assert_eq!(
            QuotaTable::new(),
            QuotaTable::decode(&QuotaTable::new().encode()).unwrap()
        );
    }
    #[test]
    fn set_quota_with_zero_config_removes_entry() {
        let mut table = QuotaTable::new();
        table.set_quota(
            inode(10),
            QuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        assert!(table.get(inode(10)).is_some());
        table.set_quota(inode(10), QuotaConfig::default());
        assert!(table.get(inode(10)).is_none());
    }
}
