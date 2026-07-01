// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P5-02 FUSE maintenance lane: forget drains, release finalizers, validation sink handoff.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.

use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterForgetBatchMirrorRecord, PosixFilesystemAdapterInterruptTokenRecord,
    PosixFilesystemAdapterRequestClass, PosixFilesystemAdapterRequestContextMirrorRecord,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Forget drain ────────────────────────────────────────────────────────────

/// FUSE opcode for a single lookup-reference drop.
pub const FUSE_FORGET_OPCODE: u32 = 2;

/// FUSE opcode for a batch of lookup-reference drops.
pub const FUSE_BATCH_FORGET_OPCODE: u32 = 42;

/// One inode lookup-reference decrement requested by the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetDrainDelta {
    /// Inode whose lookup reference count should be decremented.
    pub inode: u64,
    /// Number of lookup references to drop for `inode`.
    pub lookup_decrement: u64,
}

/// Aggregate summary for a validated FUSE forget batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetBatchDrainPlan {
    /// Number of forget entries in the validated batch.
    pub entry_count: u32,
    /// First inode in the batch, preserved for existing mirror records.
    pub first_inode: u64,
    /// Sum of all lookup-reference decrements in the batch.
    pub total_lookup_decrement: u64,
}

/// Aggregate delta plan for a validated FUSE forget batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetBatchDrainDeltasPlan {
    /// Number of raw forget entries in the validated batch.
    pub entry_count: u32,
    /// Number of unique inode deltas written to the caller's output buffer.
    pub unique_inode_count: u32,
    /// First inode in the batch, preserved for existing mirror records.
    pub first_inode: u64,
    /// Sum of all lookup-reference decrements in the batch.
    pub total_lookup_decrement: u64,
}

/// Current lookup-reference count tracked for one inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetLookupReferenceCounter {
    /// Inode whose lookup references are tracked.
    pub inode: u64,
    /// Current lookup-reference count for `inode`.
    pub lookup_count: u64,
}

/// One inode lookup-reference increment granted by an entry-producing response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupReferenceGrant {
    /// Inode whose lookup reference count should be incremented.
    pub inode: u64,
    /// Number of lookup references to add for `inode`.
    pub lookup_increment: u64,
}

/// Result of applying one lookup-reference grant to a tracked inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupReferenceGrantOutcome {
    /// Inode whose lookup-reference count changed.
    pub inode: u64,
    /// Lookup-reference count before the grant was applied.
    pub previous_lookup_count: u64,
    /// Lookup-reference increment that was applied.
    pub lookup_increment: u64,
    /// Lookup-reference count after the grant was applied.
    pub current_lookup_count: u64,
}

/// State reached after a lookup-reference drain is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgetLookupReferenceState {
    /// The inode still has at least one lookup reference.
    StillReferenced,
    /// The inode has no lookup references left and can be considered dropped.
    DroppedToZero,
}

/// Result of applying one validated forget drain to a tracked inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetLookupApplyOutcome {
    /// Inode whose lookup-reference count changed.
    pub inode: u64,
    /// Lookup-reference count before the drain was applied.
    pub previous_lookup_count: u64,
    /// Lookup-reference decrement that was applied.
    pub lookup_decrement: u64,
    /// Lookup-reference count after the drain was applied.
    pub remaining_lookup_count: u64,
    /// High-level state reached by the drain.
    pub state: ForgetLookupReferenceState,
}

/// Summary for applying a validated forget batch to tracked lookup references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetLookupBatchApplySummary {
    /// Number of forget entries in the validated batch.
    pub entry_count: u32,
    /// Sum of all lookup-reference decrements applied by the batch.
    pub total_lookup_decrement: u64,
    /// Number of tracked inodes that dropped exactly to zero.
    pub dropped_to_zero_count: u32,
    /// Number of tracked inodes that stayed referenced after the drain.
    pub still_referenced_count: u32,
}

/// Validation failure for forget drain planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgetDrainError {
    /// FUSE inode 0 is invalid.
    ZeroInode,
    /// A forget entry must drop at least one lookup reference.
    ZeroLookupDecrement,
    /// BATCH_FORGET payloads must contain at least one entry.
    EmptyBatch,
    /// The batch entry count cannot fit in the mirror record.
    TooManyBatchEntries,
    /// The caller-provided delta output buffer cannot hold all unique inodes.
    BatchDeltaOutputTooSmall {
        required_unique_inode_count: u32,
        provided_delta_capacity: u32,
    },
    /// The aggregate lookup-reference decrement overflowed `u64`.
    LookupDecrementOverflow,
}

/// Failure while applying validated forget drains to tracked lookup references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgetLookupApplyError {
    /// A raw drain entry failed the existing planner validation.
    InvalidDrain(ForgetDrainError),
    /// The drain referenced an inode that is not present in the tracked state.
    MissingTrackedInode { inode: u64 },
    /// The drain would make a tracked lookup-reference count negative.
    LookupReferenceUnderflow {
        inode: u64,
        current_lookup_count: u64,
        lookup_decrement: u64,
    },
    /// Aggregating duplicate entries for one inode overflowed `u64`.
    LookupDecrementOverflow { inode: u64 },
}

/// Validation failure while planning or applying lookup-reference grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupReferenceGrantError {
    /// FUSE inode 0 is invalid.
    ZeroInode,
    /// A lookup-reference grant must add at least one reference.
    ZeroLookupIncrement,
    /// The grant was applied to a counter for a different inode.
    TrackedInodeMismatch {
        tracked_inode: u64,
        grant_inode: u64,
    },
    /// The grant would overflow the tracked lookup-reference count.
    LookupReferenceOverflow {
        inode: u64,
        current_lookup_count: u64,
        lookup_increment: u64,
    },
}

/// Create a forget batch mirror for a BATCH_FORGET payload.
///
/// The daemon thread picks this up and drains the forget list
/// without entering heavy worker lanes.
#[must_use]
pub fn create_forget_batch_mirror(
    forget_count: u32,
    first_inode: u64,
    batch_length: u32,
) -> PosixFilesystemAdapterForgetBatchMirrorRecord {
    PosixFilesystemAdapterForgetBatchMirrorRecord {
        forget_count,
        first_inode,
        batch_length,
        _reserved: [0_u32; 1],
    }
}

/// Plan a single FUSE_FORGET lookup-reference decrement.
///
/// The maintenance drain treats zero inode or zero decrement values as malformed
/// input instead of silently losing lifetime-accounting signal.
pub const fn plan_forget_drain(
    inode: u64,
    lookup_decrement: u64,
) -> Result<ForgetDrainDelta, ForgetDrainError> {
    if inode == 0 {
        return Err(ForgetDrainError::ZeroInode);
    }
    if lookup_decrement == 0 {
        return Err(ForgetDrainError::ZeroLookupDecrement);
    }
    Ok(ForgetDrainDelta {
        inode,
        lookup_decrement,
    })
}

/// Plan an aggregate BATCH_FORGET drain from raw `(inode, nlookup)` entries.
///
/// The returned summary is enough for queue accounting and mirror emission; the
/// caller keeps the raw entries for per-inode application during daemon wiring.
pub fn plan_forget_batch_drain(
    entries: &[(u64, u64)],
) -> Result<ForgetBatchDrainPlan, ForgetDrainError> {
    if entries.is_empty() {
        return Err(ForgetDrainError::EmptyBatch);
    }
    if entries.len() > u32::MAX as usize {
        return Err(ForgetDrainError::TooManyBatchEntries);
    }

    let first_delta = plan_forget_drain(entries[0].0, entries[0].1)?;
    let mut total_lookup_decrement = 0_u64;

    for &(inode, lookup_decrement) in entries {
        let delta = plan_forget_drain(inode, lookup_decrement)?;
        total_lookup_decrement = match total_lookup_decrement.checked_add(delta.lookup_decrement) {
            Some(next_total) => next_total,
            None => return Err(ForgetDrainError::LookupDecrementOverflow),
        };
    }

    Ok(ForgetBatchDrainPlan {
        entry_count: entries.len() as u32,
        first_inode: first_delta.inode,
        total_lookup_decrement,
    })
}

fn count_unique_forget_inodes(entries: &[(u64, u64)]) -> u32 {
    let mut unique_inode_count = 0_u32;

    for (entry_index, &(inode, _)) in entries.iter().enumerate() {
        let mut seen_before = false;
        for &(previous_inode, _) in &entries[..entry_index] {
            if previous_inode == inode {
                seen_before = true;
                break;
            }
        }
        if !seen_before {
            unique_inode_count += 1;
        }
    }

    unique_inode_count
}

/// Plan aggregate per-inode lookup-reference decrements for a FUSE forget batch.
///
/// The caller provides storage so this crate can stay `no_std` and
/// allocation-free. Deltas are emitted in first-seen inode order, with duplicate
/// entries folded into the same output slot. The output buffer is not mutated
/// when validation fails or when it is too small.
pub fn plan_forget_batch_deltas(
    entries: &[(u64, u64)],
    output: &mut [ForgetDrainDelta],
) -> Result<ForgetBatchDrainDeltasPlan, ForgetDrainError> {
    let summary = plan_forget_batch_drain(entries)?;
    let unique_inode_count = count_unique_forget_inodes(entries);

    if output.len() < unique_inode_count as usize {
        return Err(ForgetDrainError::BatchDeltaOutputTooSmall {
            required_unique_inode_count: unique_inode_count,
            provided_delta_capacity: output.len() as u32,
        });
    }

    let mut written = 0_usize;
    for &(inode, lookup_decrement) in entries {
        let mut existing_index = None;
        for (delta_index, delta) in output[..written].iter().enumerate() {
            if delta.inode == inode {
                existing_index = Some(delta_index);
                break;
            }
        }

        if let Some(delta_index) = existing_index {
            output[delta_index].lookup_decrement = match output[delta_index]
                .lookup_decrement
                .checked_add(lookup_decrement)
            {
                Some(next_lookup_decrement) => next_lookup_decrement,
                None => return Err(ForgetDrainError::LookupDecrementOverflow),
            };
        } else {
            output[written] = ForgetDrainDelta {
                inode,
                lookup_decrement,
            };
            written += 1;
        }
    }

    Ok(ForgetBatchDrainDeltasPlan {
        entry_count: summary.entry_count,
        unique_inode_count,
        first_inode: summary.first_inode,
        total_lookup_decrement: summary.total_lookup_decrement,
    })
}

/// Plan one lookup-reference increment from a FUSE entry-producing response.
///
/// LOOKUP and other successful entry replies grant lookup references that must
/// later be balanced by FORGET/BATCH_FORGET drains.
pub const fn plan_lookup_reference_grant(
    inode: u64,
    lookup_increment: u64,
) -> Result<LookupReferenceGrant, LookupReferenceGrantError> {
    if inode == 0 {
        return Err(LookupReferenceGrantError::ZeroInode);
    }
    if lookup_increment == 0 {
        return Err(LookupReferenceGrantError::ZeroLookupIncrement);
    }
    Ok(LookupReferenceGrant {
        inode,
        lookup_increment,
    })
}

fn validate_forget_delta(
    delta: ForgetDrainDelta,
) -> Result<ForgetDrainDelta, ForgetLookupApplyError> {
    plan_forget_drain(delta.inode, delta.lookup_decrement)
        .map_err(ForgetLookupApplyError::InvalidDrain)
}

fn aggregate_lookup_decrement_for_inode(
    entries: &[(u64, u64)],
    inode: u64,
) -> Result<u64, ForgetLookupApplyError> {
    let mut total_lookup_decrement = 0_u64;

    for &(entry_inode, lookup_decrement) in entries {
        if entry_inode == inode {
            total_lookup_decrement = match total_lookup_decrement.checked_add(lookup_decrement) {
                Some(next_total) => next_total,
                None => return Err(ForgetLookupApplyError::LookupDecrementOverflow { inode }),
            };
        }
    }

    Ok(total_lookup_decrement)
}

fn validate_lookup_reference_grant(
    grant: LookupReferenceGrant,
) -> Result<LookupReferenceGrant, LookupReferenceGrantError> {
    plan_lookup_reference_grant(grant.inode, grant.lookup_increment)
}

/// Apply one validated lookup-reference grant to a tracked inode counter.
///
/// The caller owns counter storage and decides whether the first reference for
/// a previously unseen inode should allocate a new counter before calling this.
pub fn apply_lookup_reference_grant_to_counter(
    counter: &mut ForgetLookupReferenceCounter,
    grant: LookupReferenceGrant,
) -> Result<LookupReferenceGrantOutcome, LookupReferenceGrantError> {
    let grant = validate_lookup_reference_grant(grant)?;

    if counter.inode != grant.inode {
        return Err(LookupReferenceGrantError::TrackedInodeMismatch {
            tracked_inode: counter.inode,
            grant_inode: grant.inode,
        });
    }

    let previous_lookup_count = counter.lookup_count;
    let current_lookup_count = match previous_lookup_count.checked_add(grant.lookup_increment) {
        Some(current_lookup_count) => current_lookup_count,
        None => {
            return Err(LookupReferenceGrantError::LookupReferenceOverflow {
                inode: grant.inode,
                current_lookup_count: previous_lookup_count,
                lookup_increment: grant.lookup_increment,
            });
        }
    };
    counter.lookup_count = current_lookup_count;

    Ok(LookupReferenceGrantOutcome {
        inode: grant.inode,
        previous_lookup_count,
        lookup_increment: grant.lookup_increment,
        current_lookup_count,
    })
}

/// Apply one validated lookup-reference drain to a tracked inode counter.
///
/// The caller owns storage for counters; this crate stays allocation-free so it
/// can remain a small maintenance-lane planning helper.
pub fn apply_forget_drain_to_lookup_counter(
    counter: &mut ForgetLookupReferenceCounter,
    delta: ForgetDrainDelta,
) -> Result<ForgetLookupApplyOutcome, ForgetLookupApplyError> {
    let delta = validate_forget_delta(delta)?;

    if counter.inode != delta.inode {
        return Err(ForgetLookupApplyError::MissingTrackedInode { inode: delta.inode });
    }
    if counter.lookup_count < delta.lookup_decrement {
        return Err(ForgetLookupApplyError::LookupReferenceUnderflow {
            inode: delta.inode,
            current_lookup_count: counter.lookup_count,
            lookup_decrement: delta.lookup_decrement,
        });
    }

    let previous_lookup_count = counter.lookup_count;
    counter.lookup_count -= delta.lookup_decrement;
    let state = if counter.lookup_count == 0 {
        ForgetLookupReferenceState::DroppedToZero
    } else {
        ForgetLookupReferenceState::StillReferenced
    };

    Ok(ForgetLookupApplyOutcome {
        inode: delta.inode,
        previous_lookup_count,
        lookup_decrement: delta.lookup_decrement,
        remaining_lookup_count: counter.lookup_count,
        state,
    })
}

/// Apply a validated BATCH_FORGET payload to tracked lookup-reference counters.
///
/// Duplicate entries for one inode are aggregated before mutating state, so the
/// helper either applies a whole valid batch or leaves counters unchanged.
pub fn apply_forget_batch_to_lookup_counters(
    counters: &mut [ForgetLookupReferenceCounter],
    entries: &[(u64, u64)],
) -> Result<ForgetLookupBatchApplySummary, ForgetLookupApplyError> {
    let plan = plan_forget_batch_drain(entries).map_err(ForgetLookupApplyError::InvalidDrain)?;

    for &(inode, _) in entries {
        if !counters.iter().any(|counter| counter.inode == inode) {
            return Err(ForgetLookupApplyError::MissingTrackedInode { inode });
        }
    }

    for counter in counters.iter() {
        let lookup_decrement = aggregate_lookup_decrement_for_inode(entries, counter.inode)?;
        if lookup_decrement > counter.lookup_count {
            return Err(ForgetLookupApplyError::LookupReferenceUnderflow {
                inode: counter.inode,
                current_lookup_count: counter.lookup_count,
                lookup_decrement,
            });
        }
    }

    let mut dropped_to_zero_count = 0_u32;
    let mut still_referenced_count = 0_u32;

    for counter in counters.iter_mut() {
        let lookup_decrement = aggregate_lookup_decrement_for_inode(entries, counter.inode)?;
        if lookup_decrement == 0 {
            continue;
        }

        let outcome = apply_forget_drain_to_lookup_counter(
            counter,
            ForgetDrainDelta {
                inode: counter.inode,
                lookup_decrement,
            },
        )?;
        match outcome.state {
            ForgetLookupReferenceState::StillReferenced => still_referenced_count += 1,
            ForgetLookupReferenceState::DroppedToZero => dropped_to_zero_count += 1,
        }
    }

    Ok(ForgetLookupBatchApplySummary {
        entry_count: plan.entry_count,
        total_lookup_decrement: plan.total_lookup_decrement,
        dropped_to_zero_count,
        still_referenced_count,
    })
}

/// Validate that a request context belongs to the maintenance lane.
#[must_use]
pub fn is_maintenance_request(ctx: &PosixFilesystemAdapterRequestContextMirrorRecord) -> bool {
    ctx.request_class == PosixFilesystemAdapterRequestClass::Maintenance.as_u32()
}

/// Check if a request is a forget/batch-forget that must bypass heavy lanes.
#[must_use]
pub fn is_forget_opcode(opcode: u32) -> bool {
    opcode == FUSE_FORGET_OPCODE || opcode == FUSE_BATCH_FORGET_OPCODE
}

// ── Interrupt token ─────────────────────────────────────────────────────────

/// Create an interrupt token for a FUSE request.
///
/// Maps an INTERRUPT wire request to a cancel-pending marker.
/// §9: `INTERRUPT` must be handled in `queue_class_0.control_urgent`
/// via cancellation tokens.
#[must_use]
pub fn create_interrupt_token(
    unique_fuse_request: u64,
    cancel_requested: bool,
) -> PosixFilesystemAdapterInterruptTokenRecord {
    PosixFilesystemAdapterInterruptTokenRecord {
        unique_fuse_request,
        cancel_requested,
        _reserved: [0_u32; 2],
    }
}

/// Mark an interrupt token as having been canceled.
#[must_use]
pub fn cancel_interrupt_token(
    mut token: PosixFilesystemAdapterInterruptTokenRecord,
) -> PosixFilesystemAdapterInterruptTokenRecord {
    token.cancel_requested = true;
    token
}

/// Check if an interrupt token has been canceled.
#[must_use]
pub fn is_interrupt_canceled(token: &PosixFilesystemAdapterInterruptTokenRecord) -> bool {
    token.cancel_requested
}

// ── Release finalizer dispatch ──────────────────────────────────────────────

/// Dispatch a release-finalize request through the maintenance drain.
///
/// Release finalizers must not block worker lanes with long cleanup.
#[must_use]
pub fn dispatch_release_finalize(
    ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    debug_assert!(
        is_maintenance_request(&ctx)
            || ctx.request_class == PosixFilesystemAdapterRequestClass::FileWriteback.as_u32(),
        "dispatch_release_finalize called with unexpected request class"
    );
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forget_batch_mirror_preserves_fields() {
        let mirror = create_forget_batch_mirror(5, 100, 5);
        assert_eq!(mirror.forget_count, 5);
        assert_eq!(mirror.first_inode, 100);
        assert_eq!(mirror.batch_length, 5);
    }

    #[test]
    fn forget_opcode_detection() {
        assert!(is_forget_opcode(FUSE_FORGET_OPCODE));
        assert!(is_forget_opcode(FUSE_BATCH_FORGET_OPCODE));
        assert!(!is_forget_opcode(1)); // FUSE_LOOKUP
    }

    #[test]
    fn single_forget_plan_preserves_inode_and_lookup_drop() {
        let delta = plan_forget_drain(100, 3).expect("valid forget");

        assert_eq!(
            delta,
            ForgetDrainDelta {
                inode: 100,
                lookup_decrement: 3,
            }
        );
    }

    #[test]
    fn single_forget_plan_rejects_zero_inode_or_drop() {
        assert_eq!(plan_forget_drain(0, 1), Err(ForgetDrainError::ZeroInode));
        assert_eq!(
            plan_forget_drain(100, 0),
            Err(ForgetDrainError::ZeroLookupDecrement)
        );
    }

    #[test]
    fn batch_forget_plan_aggregates_entries() {
        let plan = plan_forget_batch_drain(&[(100, 1), (101, 3), (100, 2)]).expect("valid batch");

        assert_eq!(
            plan,
            ForgetBatchDrainPlan {
                entry_count: 3,
                first_inode: 100,
                total_lookup_decrement: 6,
            }
        );
    }

    #[test]
    fn batch_forget_plan_rejects_empty_or_zero_count_entries() {
        assert_eq!(
            plan_forget_batch_drain(&[]),
            Err(ForgetDrainError::EmptyBatch)
        );
        assert_eq!(
            plan_forget_batch_drain(&[(100, 1), (101, 0)]),
            Err(ForgetDrainError::ZeroLookupDecrement)
        );
    }

    #[test]
    fn batch_forget_plan_rejects_total_overflow() {
        assert_eq!(
            plan_forget_batch_drain(&[(100, u64::MAX), (101, 1)]),
            Err(ForgetDrainError::LookupDecrementOverflow)
        );
    }

    #[test]
    fn batch_forget_delta_plan_aggregates_in_first_seen_order() {
        let mut deltas = [
            ForgetDrainDelta {
                inode: 0,
                lookup_decrement: 0,
            },
            ForgetDrainDelta {
                inode: 0,
                lookup_decrement: 0,
            },
            ForgetDrainDelta {
                inode: 999,
                lookup_decrement: 999,
            },
        ];
        let plan = plan_forget_batch_deltas(&[(100, 1), (101, 3), (100, 2)], &mut deltas)
            .expect("valid delta plan");

        assert_eq!(
            plan,
            ForgetBatchDrainDeltasPlan {
                entry_count: 3,
                unique_inode_count: 2,
                first_inode: 100,
                total_lookup_decrement: 6,
            }
        );
        assert_eq!(
            &deltas[..2],
            &[
                ForgetDrainDelta {
                    inode: 100,
                    lookup_decrement: 3,
                },
                ForgetDrainDelta {
                    inode: 101,
                    lookup_decrement: 3,
                },
            ]
        );
        assert_eq!(
            deltas[2],
            ForgetDrainDelta {
                inode: 999,
                lookup_decrement: 999,
            }
        );
    }

    #[test]
    fn batch_forget_delta_plan_rejects_small_output_without_mutation() {
        let mut deltas = [ForgetDrainDelta {
            inode: 999,
            lookup_decrement: 999,
        }];
        let result = plan_forget_batch_deltas(&[(100, 1), (101, 1)], &mut deltas);

        assert_eq!(
            result,
            Err(ForgetDrainError::BatchDeltaOutputTooSmall {
                required_unique_inode_count: 2,
                provided_delta_capacity: 1,
            })
        );
        assert_eq!(
            deltas[0],
            ForgetDrainDelta {
                inode: 999,
                lookup_decrement: 999,
            }
        );
    }

    #[test]
    fn batch_forget_delta_plan_rejects_invalid_batch_without_mutation() {
        let mut deltas = [ForgetDrainDelta {
            inode: 999,
            lookup_decrement: 999,
        }];
        let result = plan_forget_batch_deltas(&[(100, 1), (101, 0)], &mut deltas);

        assert_eq!(result, Err(ForgetDrainError::ZeroLookupDecrement));
        assert_eq!(
            deltas[0],
            ForgetDrainDelta {
                inode: 999,
                lookup_decrement: 999,
            }
        );
    }

    #[test]
    fn lookup_grant_plan_preserves_inode_and_increment() {
        let grant = plan_lookup_reference_grant(100, 3).expect("valid lookup grant");

        assert_eq!(
            grant,
            LookupReferenceGrant {
                inode: 100,
                lookup_increment: 3,
            }
        );
    }

    #[test]
    fn lookup_grant_plan_rejects_zero_inode_or_increment() {
        assert_eq!(
            plan_lookup_reference_grant(0, 1),
            Err(LookupReferenceGrantError::ZeroInode)
        );
        assert_eq!(
            plan_lookup_reference_grant(100, 0),
            Err(LookupReferenceGrantError::ZeroLookupIncrement)
        );
    }

    #[test]
    fn lookup_grant_apply_increments_counter() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 2,
        };
        let outcome = apply_lookup_reference_grant_to_counter(
            &mut counter,
            LookupReferenceGrant {
                inode: 100,
                lookup_increment: 4,
            },
        )
        .expect("valid lookup grant apply");

        assert_eq!(
            outcome,
            LookupReferenceGrantOutcome {
                inode: 100,
                previous_lookup_count: 2,
                lookup_increment: 4,
                current_lookup_count: 6,
            }
        );
        assert_eq!(counter.lookup_count, 6);
    }

    #[test]
    fn lookup_grant_apply_rejects_mismatched_counter_without_mutation() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 2,
        };
        let result = apply_lookup_reference_grant_to_counter(
            &mut counter,
            LookupReferenceGrant {
                inode: 200,
                lookup_increment: 1,
            },
        );

        assert_eq!(
            result,
            Err(LookupReferenceGrantError::TrackedInodeMismatch {
                tracked_inode: 100,
                grant_inode: 200,
            })
        );
        assert_eq!(counter.lookup_count, 2);
    }

    #[test]
    fn lookup_grant_apply_rejects_overflow_without_mutation() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: u64::MAX,
        };
        let result = apply_lookup_reference_grant_to_counter(
            &mut counter,
            LookupReferenceGrant {
                inode: 100,
                lookup_increment: 1,
            },
        );

        assert_eq!(
            result,
            Err(LookupReferenceGrantError::LookupReferenceOverflow {
                inode: 100,
                current_lookup_count: u64::MAX,
                lookup_increment: 1,
            })
        );
        assert_eq!(counter.lookup_count, u64::MAX);
    }

    #[test]
    fn lookup_grant_can_be_balanced_by_forget_drain() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 1,
        };

        apply_lookup_reference_grant_to_counter(
            &mut counter,
            LookupReferenceGrant {
                inode: 100,
                lookup_increment: 2,
            },
        )
        .expect("valid lookup grant apply");
        let drain = apply_forget_drain_to_lookup_counter(
            &mut counter,
            ForgetDrainDelta {
                inode: 100,
                lookup_decrement: 3,
            },
        )
        .expect("valid matching forget drain");

        assert_eq!(drain.state, ForgetLookupReferenceState::DroppedToZero);
        assert_eq!(counter.lookup_count, 0);
    }

    #[test]
    fn lookup_counter_single_drain_stays_referenced() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 5,
        };
        let outcome = apply_forget_drain_to_lookup_counter(
            &mut counter,
            ForgetDrainDelta {
                inode: 100,
                lookup_decrement: 2,
            },
        )
        .expect("valid counter drain");

        assert_eq!(
            outcome,
            ForgetLookupApplyOutcome {
                inode: 100,
                previous_lookup_count: 5,
                lookup_decrement: 2,
                remaining_lookup_count: 3,
                state: ForgetLookupReferenceState::StillReferenced,
            }
        );
        assert_eq!(counter.lookup_count, 3);
    }

    #[test]
    fn lookup_counter_exact_drain_drops_to_zero() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 2,
        };
        let outcome = apply_forget_drain_to_lookup_counter(
            &mut counter,
            ForgetDrainDelta {
                inode: 100,
                lookup_decrement: 2,
            },
        )
        .expect("valid exact drain");

        assert_eq!(outcome.state, ForgetLookupReferenceState::DroppedToZero);
        assert_eq!(outcome.remaining_lookup_count, 0);
        assert_eq!(counter.lookup_count, 0);
    }

    #[test]
    fn lookup_counter_rejects_underflow_without_mutation() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 1,
        };
        let result = apply_forget_drain_to_lookup_counter(
            &mut counter,
            ForgetDrainDelta {
                inode: 100,
                lookup_decrement: 2,
            },
        );

        assert_eq!(
            result,
            Err(ForgetLookupApplyError::LookupReferenceUnderflow {
                inode: 100,
                current_lookup_count: 1,
                lookup_decrement: 2,
            })
        );
        assert_eq!(counter.lookup_count, 1);
    }

    #[test]
    fn lookup_batch_applies_multi_inode_drain() {
        let mut counters = [
            ForgetLookupReferenceCounter {
                inode: 100,
                lookup_count: 3,
            },
            ForgetLookupReferenceCounter {
                inode: 101,
                lookup_count: 2,
            },
        ];
        let summary = apply_forget_batch_to_lookup_counters(&mut counters, &[(100, 1), (101, 2)])
            .expect("valid batch apply");

        assert_eq!(
            summary,
            ForgetLookupBatchApplySummary {
                entry_count: 2,
                total_lookup_decrement: 3,
                dropped_to_zero_count: 1,
                still_referenced_count: 1,
            }
        );
        assert_eq!(counters[0].lookup_count, 2);
        assert_eq!(counters[1].lookup_count, 0);
    }

    #[test]
    fn lookup_batch_aggregates_duplicate_inode_entries() {
        let mut counters = [ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 5,
        }];
        let summary = apply_forget_batch_to_lookup_counters(&mut counters, &[(100, 1), (100, 3)])
            .expect("valid duplicate inode batch");

        assert_eq!(
            summary,
            ForgetLookupBatchApplySummary {
                entry_count: 2,
                total_lookup_decrement: 4,
                dropped_to_zero_count: 0,
                still_referenced_count: 1,
            }
        );
        assert_eq!(counters[0].lookup_count, 1);
    }

    #[test]
    fn lookup_batch_preserves_unrelated_counters() {
        let mut counters = [
            ForgetLookupReferenceCounter {
                inode: 100,
                lookup_count: 5,
            },
            ForgetLookupReferenceCounter {
                inode: 200,
                lookup_count: 7,
            },
        ];

        apply_forget_batch_to_lookup_counters(&mut counters, &[(100, 2)])
            .expect("valid partial batch");

        assert_eq!(counters[0].lookup_count, 3);
        assert_eq!(counters[1].lookup_count, 7);
    }

    #[test]
    fn lookup_batch_rejects_underflow_without_mutation() {
        let mut counters = [
            ForgetLookupReferenceCounter {
                inode: 100,
                lookup_count: 2,
            },
            ForgetLookupReferenceCounter {
                inode: 101,
                lookup_count: 4,
            },
        ];
        let result = apply_forget_batch_to_lookup_counters(&mut counters, &[(100, 3), (101, 1)]);

        assert_eq!(
            result,
            Err(ForgetLookupApplyError::LookupReferenceUnderflow {
                inode: 100,
                current_lookup_count: 2,
                lookup_decrement: 3,
            })
        );
        assert_eq!(counters[0].lookup_count, 2);
        assert_eq!(counters[1].lookup_count, 4);
    }

    #[test]
    fn interrupt_token_cancel() {
        let token = create_interrupt_token(42, false);
        assert!(!is_interrupt_canceled(&token));
        let canceled = cancel_interrupt_token(token);
        assert!(is_interrupt_canceled(&canceled));
        assert_eq!(canceled.unique_fuse_request, 42);
    }

    #[test]
    fn is_maintenance_detects_correct_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::Maintenance.as_u32(),
            ..Default::default()
        };
        assert!(is_maintenance_request(&ctx));
    }

    #[test]
    fn release_finalize_preserves_context() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 500,
            request_class: PosixFilesystemAdapterRequestClass::Maintenance.as_u32(),
            ..Default::default()
        };
        let dispatched = dispatch_release_finalize(ctx);
        assert_eq!(dispatched.unique, 500);
    }

    // ── Additional coverage: delta plans, lifecycle, error paths ───────────────

    #[test]
    fn batch_forget_plan_single_entry() {
        let plan = plan_forget_batch_drain(&[(42, 7)]).expect("single-entry batch");
        assert_eq!(
            plan,
            ForgetBatchDrainPlan {
                entry_count: 1,
                first_inode: 42,
                total_lookup_decrement: 7,
            }
        );
    }

    #[test]
    fn batch_forget_plan_rejects_zero_inode_after_valid_first() {
        assert_eq!(
            plan_forget_batch_drain(&[(100, 1), (0, 1)]),
            Err(ForgetDrainError::ZeroInode)
        );
    }

    #[test]
    fn batch_forget_delta_plan_all_unique_no_merge() {
        let mut deltas = [ForgetDrainDelta {
            inode: 0,
            lookup_decrement: 0,
        }; 4];
        let plan = plan_forget_batch_deltas(&[(10, 1), (20, 2), (30, 3), (40, 4)], &mut deltas)
            .expect("valid all-unique delta plan");

        assert_eq!(plan.entry_count, 4);
        assert_eq!(plan.unique_inode_count, 4);
        assert_eq!(plan.total_lookup_decrement, 10);
        assert_eq!(
            deltas[0],
            ForgetDrainDelta {
                inode: 10,
                lookup_decrement: 1
            }
        );
        assert_eq!(
            deltas[1],
            ForgetDrainDelta {
                inode: 20,
                lookup_decrement: 2
            }
        );
        assert_eq!(
            deltas[2],
            ForgetDrainDelta {
                inode: 30,
                lookup_decrement: 3
            }
        );
        assert_eq!(
            deltas[3],
            ForgetDrainDelta {
                inode: 40,
                lookup_decrement: 4
            }
        );
    }

    #[test]
    fn batch_forget_delta_plan_triple_duplicate_merge() {
        let mut deltas = [ForgetDrainDelta {
            inode: 0,
            lookup_decrement: 0,
        }; 1];
        let plan = plan_forget_batch_deltas(&[(77, 2), (77, 3), (77, 5)], &mut deltas)
            .expect("valid triple duplicate delta plan");

        assert_eq!(plan.entry_count, 3);
        assert_eq!(plan.unique_inode_count, 1);
        assert_eq!(plan.total_lookup_decrement, 10);
        assert_eq!(
            deltas[0],
            ForgetDrainDelta {
                inode: 77,
                lookup_decrement: 10
            }
        );
    }

    #[test]
    fn batch_forget_delta_plan_overflow_on_duplicate_merge() {
        let mut deltas = [ForgetDrainDelta {
            inode: 0,
            lookup_decrement: 0,
        }; 1];
        let result = plan_forget_batch_deltas(&[(99, u64::MAX), (99, 1)], &mut deltas);
        assert_eq!(result, Err(ForgetDrainError::LookupDecrementOverflow));
    }

    #[test]
    fn batch_apply_rejects_missing_tracked_inode() {
        let mut counters = [ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: 3,
        }];
        let result = apply_forget_batch_to_lookup_counters(&mut counters, &[(100, 1), (200, 1)]);
        assert_eq!(
            result,
            Err(ForgetLookupApplyError::MissingTrackedInode { inode: 200 })
        );
        assert_eq!(counters[0].lookup_count, 3);
    }

    #[test]
    fn batch_apply_overflow_on_duplicate_aggregation() {
        let mut counters = [ForgetLookupReferenceCounter {
            inode: 100,
            lookup_count: u64::MAX,
        }];
        let result =
            apply_forget_batch_to_lookup_counters(&mut counters, &[(100, u64::MAX), (100, 1)]);
        assert_eq!(
            result,
            Err(ForgetLookupApplyError::InvalidDrain(
                ForgetDrainError::LookupDecrementOverflow
            ))
        );
        assert_eq!(counters[0].lookup_count, u64::MAX);
    }

    #[test]
    fn lookup_grant_and_drain_full_lifecycle() {
        let mut counter = ForgetLookupReferenceCounter {
            inode: 200,
            lookup_count: 0,
        };

        // Grant twice
        apply_lookup_reference_grant_to_counter(
            &mut counter,
            LookupReferenceGrant {
                inode: 200,
                lookup_increment: 3,
            },
        )
        .expect("first grant");
        assert_eq!(counter.lookup_count, 3);

        apply_lookup_reference_grant_to_counter(
            &mut counter,
            LookupReferenceGrant {
                inode: 200,
                lookup_increment: 2,
            },
        )
        .expect("second grant");
        assert_eq!(counter.lookup_count, 5);

        // Drain partially
        let outcome1 = apply_forget_drain_to_lookup_counter(
            &mut counter,
            ForgetDrainDelta {
                inode: 200,
                lookup_decrement: 1,
            },
        )
        .expect("partial drain");
        assert_eq!(outcome1.state, ForgetLookupReferenceState::StillReferenced);
        assert_eq!(counter.lookup_count, 4);

        // Drain all remaining
        let outcome2 = apply_forget_drain_to_lookup_counter(
            &mut counter,
            ForgetDrainDelta {
                inode: 200,
                lookup_decrement: 4,
            },
        )
        .expect("final drain");
        assert_eq!(outcome2.state, ForgetLookupReferenceState::DroppedToZero);
        assert_eq!(counter.lookup_count, 0);
    }

    #[test]
    fn forget_opcode_rejects_common_fuse_opcodes() {
        assert!(!is_forget_opcode(1)); // FUSE_LOOKUP
        assert!(!is_forget_opcode(14)); // FUSE_MKNOD
        assert!(!is_forget_opcode(26)); // FUSE_READDIR
        assert!(!is_forget_opcode(0));
        assert!(!is_forget_opcode(u32::MAX));
    }

    #[test]
    fn dispatch_release_finalize_allows_writeback_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 600,
            request_class: PosixFilesystemAdapterRequestClass::FileWriteback.as_u32(),
            ..Default::default()
        };
        let dispatched = dispatch_release_finalize(ctx);
        assert_eq!(dispatched.unique, 600);
    }

    #[test]
    fn forget_batch_mirror_zero_values() {
        let mirror = create_forget_batch_mirror(0, 0, 0);
        assert_eq!(mirror.forget_count, 0);
        assert_eq!(mirror.first_inode, 0);
        assert_eq!(mirror.batch_length, 0);
    }

    #[test]
    fn drain_delta_derives() {
        let a = ForgetDrainDelta {
            inode: 10,
            lookup_decrement: 3,
        };
        let b = a;
        assert_eq!(a, b);
        assert_ne!(
            a,
            ForgetDrainDelta {
                inode: 10,
                lookup_decrement: 4
            }
        );
        assert_ne!(
            a,
            ForgetDrainDelta {
                inode: 20,
                lookup_decrement: 3
            }
        );
    }

    #[test]
    fn forget_lookup_reference_state_variants() {
        assert_ne!(
            ForgetLookupReferenceState::StillReferenced,
            ForgetLookupReferenceState::DroppedToZero,
        );
        assert_eq!(
            ForgetLookupReferenceState::StillReferenced,
            ForgetLookupReferenceState::StillReferenced,
        );
        assert_eq!(
            ForgetLookupReferenceState::DroppedToZero,
            ForgetLookupReferenceState::DroppedToZero,
        );
    }
}
