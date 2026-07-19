// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Capacity smoke: deterministic runtime checks for the production
//! [`tidefs_local_filesystem::capacity_authority::CapacityAuthority`].
//!
//! Replaces the retired CapacityFacade-based smoke path.
//! Covers construction, ENOSPC gating, allocation accounting,
//! statfs derivation, root-reserve visibility, and capacity
//! mutation.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_local_filesystem::capacity_authority::{CapacityAuthority, CapacityStatfs};
use tidefs_posix_filesystem_adapter_daemon::capacity::StatfsReply;
use tidefs_space_accounting::SpaceAccounting;
use tidefs_types_space_accounting_core::{
    DatasetSpaceCountersV1, PoolPhysicalCountersV1, SpaceDelta, SpaceDomainId,
};
use tidefs_types_vfs_core::Errno;

/// Run the full capacity smoke sequence and return the harness.
#[must_use]
pub fn run_capacity_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("capacity/smoke");
    smoke_authority_construction_and_accessors(&mut h);
    smoke_enospc_gating(&mut h);
    smoke_enospc_with_root_reserve(&mut h);
    smoke_enospc_after_allocation(&mut h);
    smoke_allocation_accounting(&mut h);
    smoke_record_free_accounting(&mut h);
    smoke_statfs_derivation(&mut h);
    smoke_statfs_derivation_after_allocation(&mut h);
    smoke_statfs_derivation_zero_block_size(&mut h);
    smoke_block_rounding_helpers(&mut h);
    smoke_setters_and_mutation(&mut h);
    smoke_statfs_reply_encoding(&mut h);
    h.scenario_end("capacity/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("capacity smoke trace should serialize");
    let decoded = deserialize_trace(&serialized).expect("capacity smoke trace should deserialize");
    h.assert_eq_ev(
        "capacity smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

// ── Construction and accessors ──────────────────────────────────────────

fn smoke_authority_construction_and_accessors(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 4096 * 8, 4096, 4096 * 4);
    record_capacity_op(
        h,
        "capacity.authority.new",
        0,
        b"total=262144 used=32768 bs=4096 root_reserve=16384",
    );

    h.assert_eq_ev("total_bytes", ca.total_bytes(), 4096 * 64);
    h.assert_eq_ev("used_bytes", ca.used_bytes(), 4096 * 8);
    h.assert_eq_ev("block_size", ca.block_size(), 4096);
    h.assert_eq_ev("root_reserve_bytes", ca.root_reserve_bytes(), 4096 * 4);
    h.assert_eq_ev("reserved_bytes initial", ca.reserved_bytes(), 0);
    h.assert_eq_ev("pending_bytes initial", ca.pending_bytes(), 0);

    // free = total - used = 64 - 8 = 56 blocks = 229376 bytes
    h.assert_eq_ev("free_bytes", ca.free_bytes(), 4096 * 56);
    // available = free - root_reserve = 56 - 4 = 52 blocks = 212992 bytes
    h.assert_eq_ev("available_bytes", ca.available_bytes(), 4096 * 52);

    record_capacity_op(
        h,
        "capacity.authority.from_pool_stats",
        0,
        b"total=4096*128 used=4096*16",
    );
    let ca2 = CapacityAuthority::from_pool_stats(4096 * 128, 4096 * 16, 4096, 4096 * 8);
    h.assert_eq_ev("from_pool_stats total", ca2.total_bytes(), 4096 * 128);
    h.assert_eq_ev("from_pool_stats used", ca2.used_bytes(), 4096 * 16);
    h.assert_eq_ev(
        "from_pool_stats root_reserve",
        ca2.root_reserve_bytes(),
        4096 * 8,
    );
}

// ── ENOSPC gating ───────────────────────────────────────────────────────

fn smoke_enospc_gating(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 0, 4096, 0);
    record_capacity_op(h, "capacity.check_enospc.zero", 0, b"zero byte request");

    // Zero-byte request always succeeds.
    h.assert_eq_ev("zero bytes passes enospc", ca.check_enospc(0), Ok(()));

    // Request within capacity.
    record_capacity_op(
        h,
        "capacity.check_enospc.small",
        0,
        b"4096 bytes within 64 blocks",
    );
    h.assert_eq_ev("small request passes", ca.check_enospc(4096), Ok(()));

    // Request at exact capacity.
    record_capacity_op(h, "capacity.check_enospc.exact", 0, b"all 64 blocks");
    h.assert_eq_ev("exact capacity passes", ca.check_enospc(4096 * 64), Ok(()));

    // Request exceeding total capacity.
    record_capacity_op(
        h,
        "capacity.check_enospc.overflow",
        0,
        b"65 blocks exceeds 64",
    );
    h.assert_eq_ev(
        "excess over total fails enospc",
        ca.check_enospc(4096 * 65),
        Err(Errno::ENOSPC),
    );
}

fn smoke_enospc_with_root_reserve(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 0, 4096, 4096 * 32);
    record_capacity_op(
        h,
        "capacity.check_enospc.root_reserve",
        0,
        b"32-block root reserve",
    );

    // 64 blocks total, 32 reserved for root. available = 32.
    h.assert_eq_ev(
        "root reserve reduces available",
        ca.available_bytes(),
        4096 * 32,
    );

    // Request within available succeeds.
    h.assert_eq_ev(
        "within available passes",
        ca.check_enospc(4096 * 32),
        Ok(()),
    );

    // One block over available fails.
    h.assert_eq_ev(
        "exceeds available fails enospc",
        ca.check_enospc(4096 * 33),
        Err(Errno::ENOSPC),
    );
}

fn smoke_enospc_after_allocation(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 8, 0, 4096, 0);
    record_capacity_op(
        h,
        "capacity.check_enospc.after_alloc",
        0,
        b"use 7 of 8 blocks",
    );

    ca.record_allocation(4096 * 7);
    h.assert_eq_ev("after 7 allocs: used", ca.used_bytes(), 4096 * 7);
    h.assert_eq_ev("after 7 allocs: free", ca.free_bytes(), 4096);
    h.assert_eq_ev("one block still ok", ca.check_enospc(4096), Ok(()));

    ca.record_allocation(4096);
    h.assert_eq_ev("after 8 allocs: used", ca.used_bytes(), 4096 * 8);
    h.assert_eq_ev("after 8 allocs: free", ca.free_bytes(), 0);
    h.assert_eq_ev(
        "full capacity fails enospc",
        ca.check_enospc(1),
        Err(Errno::ENOSPC),
    );
}

// ── Allocation accounting ───────────────────────────────────────────────

fn smoke_allocation_accounting(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 0, 4096, 0);

    record_capacity_op(h, "capacity.record_allocation", 0, b"4 blocks");
    ca.record_allocation(4096 * 4);
    h.assert_eq_ev(
        "record_allocation increases used",
        ca.used_bytes(),
        4096 * 4,
    );
    h.assert_eq_ev(
        "record_allocation decreases free",
        ca.free_bytes(),
        4096 * 60,
    );
    h.assert_eq_ev(
        "record_allocation decreases avail",
        ca.available_bytes(),
        4096 * 60,
    );

    record_capacity_op(h, "capacity.record_allocation.more", 0, b"10 more blocks");
    ca.record_allocation(4096 * 10);
    h.assert_eq_ev("cumulative used", ca.used_bytes(), 4096 * 14);
    h.assert_eq_ev("cumulative free", ca.free_bytes(), 4096 * 50);
}

fn smoke_record_free_accounting(h: &mut SmokeHarness) {
    let total_bytes = 4096 * 64;
    let initial_used_bytes = 4096 * 16;
    let freed_bytes = 4096 * 8;
    let initial_pool = PoolPhysicalCountersV1::mounted_authority_from_capacity(
        total_bytes,
        initial_used_bytes,
        4096,
    );
    let mut accounting = SpaceAccounting::new(
        DatasetSpaceCountersV1 {
            logical_used_bytes: initial_used_bytes,
            quota_bytes: total_bytes,
            ..DatasetSpaceCountersV1::default()
        },
        SpaceDomainId::NONE,
    );
    accounting.update_pool_counters(initial_pool);
    let ca = CapacityAuthority::from_committed_accounting(total_bytes, &accounting, 4096, 0);
    record_capacity_op(h, "capacity.record_free", 0, b"free 8 of 16 blocks");

    accounting.accumulate_delta(SpaceDelta::new_free(freed_bytes));
    ca.record_free(freed_bytes);
    h.assert_eq_ev("record_free decreases used", ca.used_bytes(), 4096 * 8);
    h.assert_eq_ev(
        "record_free keeps committed free before commit",
        ca.free_bytes(),
        4096 * 48,
    );
    h.assert_eq_ev(
        "record_free keeps committed avail before commit",
        ca.available_bytes(),
        4096 * 48,
    );

    record_capacity_op(
        h,
        "capacity.record_free.commit",
        0,
        b"commit 8-block free delta",
    );
    let committed_used_bytes = initial_used_bytes - freed_bytes;
    let committed_pool = PoolPhysicalCountersV1::mounted_authority_from_capacity(
        total_bytes,
        committed_used_bytes,
        4096,
    );
    accounting
        .commit_pending(committed_pool)
        .expect("free delta should commit");
    ca.refresh_committed_accounting_after_commit(&accounting, committed_pool);
    h.assert_eq_ev("committed free increases free", ca.free_bytes(), 4096 * 56);
    h.assert_eq_ev(
        "committed free increases avail",
        ca.available_bytes(),
        4096 * 56,
    );

    // Free beyond used: saturates at 0.
    record_capacity_op(
        h,
        "capacity.record_free.saturate",
        0,
        b"free 16 blocks from 8 used",
    );
    ca.record_free(4096 * 16);
    h.assert_eq_ev("record_free saturates used at 0", ca.used_bytes(), 0);
    h.assert_eq_ev(
        "total unchanged after free saturation",
        ca.total_bytes(),
        4096 * 64,
    );
}

// ── Statfs derivation ───────────────────────────────────────────────────

fn smoke_statfs_derivation(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 4096 * 8, 4096, 4096 * 4);
    record_capacity_op(
        h,
        "capacity.derive_statfs",
        0,
        b"used=8 root_reserve=4 inodes=1000/800",
    );

    let statfs = ca.derive_statfs(1000, 800, 255);
    h.assert_eq_ev("derive_statfs total_blocks", statfs.total_blocks, 64);
    h.assert_eq_ev("derive_statfs free_blocks", statfs.free_blocks, 56);
    h.assert_eq_ev("derive_statfs avail_blocks", statfs.avail_blocks, 52);
    h.assert_eq_ev("derive_statfs total_inodes", statfs.total_inodes, 1000);
    h.assert_eq_ev("derive_statfs free_inodes", statfs.free_inodes, 800);
    h.assert_eq_ev("derive_statfs block_size", statfs.block_size, 4096);
    h.assert_eq_ev("derive_statfs name_max", statfs.name_max, 255);
}

fn smoke_statfs_derivation_after_allocation(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 0, 4096, 0);
    record_capacity_op(
        h,
        "capacity.derive_statfs.after_alloc",
        0,
        b"allocate 10 blocks",
    );

    ca.record_allocation(4096 * 10);
    let statfs = ca.derive_statfs(500, 400, 255);
    h.assert_eq_ev("total_blocks unchanged", statfs.total_blocks, 64);
    h.assert_eq_ev("free_blocks after alloc", statfs.free_blocks, 54);
    h.assert_eq_ev("avail_blocks after alloc", statfs.avail_blocks, 54);
    h.assert_eq_ev("inode counts passed through", statfs.total_inodes, 500);
}

fn smoke_statfs_derivation_zero_block_size(h: &mut SmokeHarness) {
    // Zero block size is a degenerate case that returns zeros.
    // (Cannot construct via new() due to assert, but derive_statfs handles it
    // defensively; CapacityStatfs::default tests the zero-bs output shape.)
    let cs = CapacityStatfs::default();
    record_capacity_op(h, "capacity.statfs.default", 0, b"zero-value default");
    h.assert_eq_ev("default total_blocks zero", cs.total_blocks, 0);
    h.assert_eq_ev("default free_blocks zero", cs.free_blocks, 0);
    h.assert_eq_ev("default avail_blocks zero", cs.avail_blocks, 0);
    h.assert_eq_ev("default block_size zero", cs.block_size, 0);
    h.assert_eq_ev("default name_max zero", cs.name_max, 0);
}

// ── Setters and mutation ────────────────────────────────────────────────

// ── Block rounding helpers (production methods on CapacityAuthority) ──

// ── Block rounding helpers (production methods on CapacityAuthority) ──────

fn smoke_block_rounding_helpers(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 0, 4096, 0);

    record_capacity_op(h, "capacity.blocks_for_bytes", 0, b"byte-to-block rounding");
    h.assert_eq_ev("zero bytes → zero blocks", ca.blocks_for_bytes(0), Ok(0));
    h.assert_eq_ev("1 byte → 1 block", ca.blocks_for_bytes(1), Ok(1));
    h.assert_eq_ev("4096 bytes → 1 block", ca.blocks_for_bytes(4096), Ok(1));
    h.assert_eq_ev("4097 bytes → 2 blocks", ca.blocks_for_bytes(4097), Ok(2));

    record_capacity_op(
        h,
        "capacity.growth_blocks_for_size_change",
        0,
        b"growth rounding",
    );
    h.assert_eq_ev(
        "same size → zero growth",
        ca.growth_blocks_for_size_change(4096, 4096),
        Ok(0),
    );
    h.assert_eq_ev(
        "shrink → zero growth",
        ca.growth_blocks_for_size_change(8192, 0),
        Ok(0),
    );
    h.assert_eq_ev(
        "0→8192 needs 2 blocks",
        ca.growth_blocks_for_size_change(0, 8192),
        Ok(2),
    );
    h.assert_eq_ev(
        "partial second block rounds up",
        ca.growth_blocks_for_size_change(4096, 8193),
        Ok(2),
    );
}

fn smoke_setters_and_mutation(h: &mut SmokeHarness) {
    let ca = CapacityAuthority::new(4096 * 64, 4096 * 8, 4096, 4096 * 4);

    record_capacity_op(h, "capacity.set_total_bytes", 0, b"64->128 blocks");
    ca.set_total_bytes(4096 * 128);
    h.assert_eq_ev(
        "set_total_bytes updates total",
        ca.total_bytes(),
        4096 * 128,
    );
    h.assert_eq_ev("set_total_bytes expands free", ca.free_bytes(), 4096 * 120);
    h.assert_eq_ev(
        "set_total_bytes expands avail",
        ca.available_bytes(),
        4096 * 116,
    );

    record_capacity_op(
        h,
        "capacity.set_root_reserve_bytes",
        0,
        b"4->16 blocks reserve",
    );
    ca.set_root_reserve_bytes(4096 * 16);
    h.assert_eq_ev(
        "set_root_reserve updates value",
        ca.root_reserve_bytes(),
        4096 * 16,
    );
    h.assert_eq_ev(
        "set_root_reserve reduces avail",
        ca.available_bytes(),
        4096 * 104,
    );
    h.assert_eq_ev(
        "set_root_reserve preserves free",
        ca.free_bytes(),
        4096 * 120,
    );

    let accounting = SpaceAccounting::new(
        DatasetSpaceCountersV1 {
            logical_used_bytes: 4096 * 8,
            quota_bytes: 4096 * 48,
            ..DatasetSpaceCountersV1::default()
        },
        SpaceDomainId::NONE,
    );
    let quoted = CapacityAuthority::from_committed_accounting(4096 * 64, &accounting, 4096, 0);
    record_capacity_op(
        h,
        "capacity.set_total_bytes.quoted",
        0,
        b"64->128 blocks with 48-block dataset quota",
    );
    quoted.set_total_bytes(4096 * 128);
    let quoted_statfs = quoted.derive_statfs(1000, 900, 255);
    h.assert_eq_ev(
        "pool resize updates quoted physical total",
        quoted.total_bytes(),
        4096 * 128,
    );
    h.assert_eq_ev(
        "pool resize preserves dataset quota total",
        quoted_statfs.total_blocks,
        48,
    );
    h.assert_eq_ev(
        "pool resize preserves dataset quota free",
        quoted_statfs.free_blocks,
        40,
    );
    h.assert_eq_ev(
        "dataset quota boundary remains admissible",
        quoted.check_enospc(4096 * 40),
        Ok(()),
    );
    h.assert_eq_ev(
        "pool resize preserves dataset quota admission",
        quoted.check_enospc(4096 * 40 + 1),
        Err(Errno::ENOSPC),
    );
}

// ── StatfsReply encoding ────────────────────────────────────────────────

fn smoke_statfs_reply_encoding(h: &mut SmokeHarness) {
    record_capacity_op(h, "capacity.statfs_reply", 0, b"wire encoding checks");

    let minimal = StatfsReply::new(4096);
    h.assert_eq_ev("statfs reply constructor sets bsize", minimal.bsize, 4096);
    h.assert_eq_ev("statfs reply constructor sets frsize", minimal.frsize, 4096);

    let normalized = StatfsReply {
        blocks: 10,
        bfree: 12,
        bavail: 15,
        files: 7,
        ffree: 9,
        favail: 11,
        bsize: 4096,
        namemax: 255,
        frsize: 4096,
    }
    .normalized();
    h.assert_eq_ev("statfs normalization caps bfree", normalized.bfree, 10);
    h.assert_eq_ev("statfs normalization caps bavail", normalized.bavail, 10);
    h.assert_eq_ev("statfs normalization caps ffree", normalized.ffree, 7);
    h.assert_eq_ev("statfs normalization caps favail", normalized.favail, 7);

    let reply = StatfsReply {
        blocks: 128,
        bfree: 100,
        bavail: 80,
        files: 1000,
        ffree: 800,
        favail: 700,
        bsize: 4096,
        namemax: 255,
        frsize: 4096,
    };
    let bytes = reply.as_fuse_bytes();
    h.assert_eq_ev(
        "statfs reply encodes fixed wire length",
        bytes.len(),
        StatfsReply::ENCODED_LEN,
    );
    h.assert_eq_ev("statfs bytes encode total blocks", read_u64(&bytes, 0), 128);
    h.assert_eq_ev("statfs bytes encode bfree", read_u64(&bytes, 8), 100);
    h.assert_eq_ev("statfs bytes encode bavail", read_u64(&bytes, 16), 80);
    h.assert_eq_ev("statfs bytes encode bsize", read_u64(&bytes, 48), 4096);
    h.assert_eq_ev("statfs bytes encode frsize", read_u64(&bytes, 64), 4096);
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn record_capacity_op(h: &mut SmokeHarness, op_name: &str, inode_id: u64, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_capacity_passes() {
        let h = run_capacity_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
