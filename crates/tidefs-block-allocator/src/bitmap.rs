//! Free-block bitmap with bit-level alloc/free primitives.
//!
//! The bitmap is a flat bit array backing `BlockAllocator`: bit `i`
//! corresponds to block `i` (1 = used, 0 = free). Blocks are numbered
//! `0..block_count-1`. Allocation scans forward from a hint position for
//! the first run of consecutive free bits meeting the requested count.
//!
//! This module is the lowest-level allocation primitive in the TideFS block
//! stack. It is called only through `BlockAllocator`'s write-locked path;
//! it is not safe for concurrent use on its own. The bitmap tracks a dirty
//! flag that is cleared by `BlockAllocator::flush` or
//! `BlockAllocator::mark_clean` after persistence.
//!
//! ## Allocation policy
//!
//! Two strategies plus a scattered fallback:
//! - **First-fit** (default, `FreeBlockBitmap::alloc_contiguous`): scans
//!   forward from a hint position for the first run of consecutive free bits
//!   meeting the requested count.
//! - **Best-fit** (`FreeBlockBitmap::alloc_contiguous_best_fit`): scans the
//!   entire bitmap and selects the smallest free run that satisfies the
//!   request, reducing long-term fragmentation.
//!
//! Both strategies fall back to scattered allocation via
//! `FreeBlockBitmap::alloc_any` when no contiguous run exists.

use crate::error::AllocError;
use crate::DeviceId;

/// Iterator over contiguous free runs in a [`FreeBlockBitmap`].
///
/// Yields `(start_block, length_in_blocks)` for each run of consecutive
/// free blocks. Runs are sorted by ascending start block.
pub struct FreeExtentIter<'a> {
    bitmap: &'a FreeBlockBitmap,
    position: u64,
}

impl<'a> FreeExtentIter<'a> {
    /// Create a new iterator over the free extents of `bitmap`.
    pub fn new(bitmap: &'a FreeBlockBitmap) -> Self {
        Self {
            bitmap,
            position: 0,
        }
    }
}

impl<'a> Iterator for FreeExtentIter<'a> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let total = self.bitmap.block_count();
        while self.position < total && !self.bitmap.is_free_inner(self.position) {
            self.position += 1;
        }
        if self.position >= total {
            return None;
        }
        let start = self.position;
        while self.position < total && self.bitmap.is_free_inner(self.position) {
            self.position += 1;
        }
        Some((start, self.position - start))
    }
}

/// A block address, 0-based.
pub type BlockId = u64;

/// Persistent free-block bitmap.
///
/// Stored as an array of `u64` words for efficient scanning.
/// On init the bitmap is read from a reserved on-disk region;
/// mutations set a dirty flag; callers must explicitly flush via
/// [`crate::BlockAllocator::flush`] or [`crate::BlockAllocator::flush_to`].
#[derive(Clone, Debug)]
pub struct FreeBlockBitmap {
    /// Total number of blocks tracked.
    block_count: u64,
    /// Bit array: word i covers bits (i*64)..(i*64+63).
    words: Vec<u64>,
    /// Hint for the next allocation scan start.
    hint: u64,
    /// Number of free blocks (cached to avoid full scans).
    free_count: u64,
    /// True when the in-memory state differs from on-disk.
    dirty: bool,
}

/// Check whether a block is on a fenced device, given allocation metadata.
pub(crate) fn is_block_fenced_inner(
    block_id: BlockId,
    block_size: u32,
    device_extents: &std::collections::BTreeMap<u64, (DeviceId, u64)>,
    fenced_devices: &std::collections::HashSet<DeviceId>,
) -> bool {
    let offset = block_id * u64::from(block_size);
    device_extents
        .range(..=offset)
        .next_back()
        .is_some_and(|(_start, (id, len))| offset < _start + len && fenced_devices.contains(id))
}

impl FreeBlockBitmap {
    /// Number of bits per word.
    const BITS_PER_WORD: u64 = 64;

    /// Number of `u64` bitmap words needed for `block_count` blocks.
    #[must_use]
    pub fn word_count_for(block_count: u64) -> usize {
        block_count.div_ceil(Self::BITS_PER_WORD) as usize
    }

    /// Number of bytes needed to persist a bitmap for `block_count` blocks.
    #[must_use]
    pub fn byte_len_for(block_count: u64) -> u64 {
        Self::word_count_for(block_count) as u64 * core::mem::size_of::<u64>() as u64
    }

    /// Create a new bitmap with all blocks initially free.
    #[must_use]
    pub fn new(block_count: u64) -> Self {
        let num_words = Self::word_count_for(block_count);
        let words = vec![0u64; num_words];
        // Mark bits beyond block_count as "used" so they never get allocated.
        let mut bm = Self {
            block_count,
            words,
            hint: 0,
            free_count: block_count,
            dirty: true,
        };
        bm.guard_tail_bits();
        bm
    }

    /// Create a bitmap from a pre-existing on-disk word array.
    ///
    /// `free_count` is computed by counting zero bits across all words,
    /// then subtracting guard bits beyond `block_count`.
    #[must_use]
    pub fn from_words(block_count: u64, mut words: Vec<u64>) -> Self {
        let expected = Self::word_count_for(block_count);
        words.truncate(expected);
        words.resize(expected, u64::MAX);
        let mut bm = Self {
            block_count,
            words,
            hint: 0,
            free_count: 0,
            dirty: false,
        };
        bm.guard_tail_bits();
        bm.free_count = bm.count_free_blocks();
        bm
    }

    /// Mark bits beyond block_count as permanently used so they never
    /// get allocated. These are guard bits, not real blocks, so free_count
    /// is not adjusted.
    fn guard_tail_bits(&mut self) {
        let rem = self.block_count % Self::BITS_PER_WORD;
        if rem == 0 {
            return;
        }
        if let Some(last) = self.words.last_mut() {
            let mask = !((1u64 << rem) - 1);
            *last |= mask;
        }
    }

    /// Count valid free blocks, excluding guard bits beyond `block_count`.
    fn count_free_blocks(&self) -> u64 {
        let full_words = (self.block_count / Self::BITS_PER_WORD) as usize;
        let rem = self.block_count % Self::BITS_PER_WORD;

        let mut free = self
            .words
            .iter()
            .take(full_words)
            .map(|word| (!word).count_ones() as u64)
            .sum();

        if rem != 0 {
            if let Some(word) = self.words.get(full_words) {
                let mask = (1u64 << rem) - 1;
                free += ((!word) & mask).count_ones() as u64;
            }
        }

        free
    }

    /// Total blocks tracked.
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    /// Number of currently free blocks.
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.free_count
    }

    /// Whether the bitmap has been modified since last flush.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag (caller has persisted).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Reference to the raw words for flush.
    #[must_use]
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// Test whether block `id` is free.
    #[must_use]
    pub fn is_free(&self, id: BlockId) -> bool {
        if id >= self.block_count {
            return false;
        }
        let (word_idx, bit) = Self::bit_pos(id);
        (self.words[word_idx] & (1u64 << bit)) == 0
    }

    /// Mark a single block as used.
    ///
    /// Idempotent: re-marking an already-used block is a no-op.
    pub fn mark_used(&mut self, id: BlockId) {
        if id >= self.block_count {
            return;
        }
        let (word_idx, bit) = Self::bit_pos(id);
        let mask = 1u64 << bit;
        if self.words[word_idx] & mask == 0 {
            self.words[word_idx] |= mask;
            self.free_count = self.free_count.saturating_sub(1);
            self.dirty = true;
        }
    }

    /// Mark a single block as free.
    ///
    /// Idempotent: re-freeing an already-free block is a no-op.
    pub fn mark_free(&mut self, id: BlockId) {
        if id >= self.block_count {
            return;
        }
        let (word_idx, bit) = Self::bit_pos(id);
        let mask = 1u64 << bit;
        if self.words[word_idx] & mask != 0 {
            self.words[word_idx] &= !mask;
            self.free_count += 1;
            self.dirty = true;
        }
    }

    /// Try to allocate `nblocks` consecutive free blocks.
    ///
    /// Returns a vector of block ids on success, or `Err(AllocError::NoSpace)`
    /// if no run of sufficient length exists.
    ///
    /// The search starts at `self.hint` (wrapping around to 0) to reduce
    /// fragmentation over the bitmap front.
    #[must_use = "allocation result must be consumed to track block usage"]
    pub fn alloc_contiguous(&mut self, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        let need = u64::from(nblocks);
        if need == 0 || need > self.block_count || need > self.free_count {
            return Err(AllocError::NoSpace);
        }

        let start_hint = self.hint;
        let total = self.block_count;

        // Two-pass: [hint, total), then [0, hint).
        // Carry run_start/run_len across passes so contiguous free runs
        // that wrap around the end of the bitmap are detected. Only
        // continue a run into pass 2 when the pass-1 run reaches the
        // end of the bitmap (i.e., adjacent to block 0).
        let mut run_start: Option<u64> = None;
        let mut run_len: u64 = 0;

        for pass in 0..2 {
            let range_start = if pass == 0 { start_hint } else { 0 };
            let range_end = if pass == 0 { total } else { start_hint };

            // When entering pass 2, only keep the pass-1 run if it
            // extends to the very end of the bitmap (wraps cleanly).
            if pass == 1 {
                if let Some(rs) = run_start {
                    if rs + run_len < total {
                        // Pass-1 run didn't reach the end; discard it.
                        run_start = None;
                        run_len = 0;
                    }
                }
            }

            for blk in range_start..range_end {
                if self.is_free_inner(blk) {
                    if run_start.is_none() {
                        run_start = Some(blk);
                    }
                    run_len += 1;
                    if run_len >= need {
                        let first = run_start.unwrap();
                        // Collect blocks, wrapping around when
                        // first + need exceeds total.
                        let mut ids = Vec::with_capacity(need as usize);
                        for off in 0..need {
                            let id = (first + off) % total;
                            ids.push(id);
                        }
                        for &id in &ids {
                            self.mark_used(id);
                        }
                        let hint = (first + need) % total;
                        self.hint = hint;
                        return Ok(ids);
                    }
                } else {
                    run_start = None;
                    run_len = 0;
                }
            }
        }

        // Wrap-around check: a contiguous run may span the hint boundary.
        // Count consecutive free blocks from the end and beginning of the
        // bitmap; if their combined length meets the request, allocate the
        // wrap-around run starting at (total - suffix_free).
        let suffix_free = (0..total)
            .rev()
            .take_while(|&blk| self.is_free_inner(blk))
            .count() as u64;
        let prefix_free = (0..total)
            .take_while(|&blk| self.is_free_inner(blk))
            .count() as u64;

        if suffix_free + prefix_free >= need {
            let first = total.saturating_sub(need.min(suffix_free));
            let ids: Vec<BlockId> = if suffix_free >= need {
                // Entire allocation fits within the suffix.
                (first..first + need).collect()
            } else {
                // Allocation wraps around: suffix + prefix head.
                (first..total).chain(0..(need - suffix_free)).collect()
            };
            for &id in &ids {
                self.mark_used(id);
            }
            self.hint = if suffix_free >= need {
                first + need
            } else {
                need - suffix_free
            };
            if self.hint >= total {
                self.hint = 0;
            }
            return Ok(ids);
        }

        Err(AllocError::NoSpace)
    }
    /// Allocate `nblocks` consecutive free blocks using best-fit selection.
    ///
    /// Scans the entire bitmap for free runs, selects the smallest run
    /// that satisfies the request, and allocates from it. This reduces
    /// long-term fragmentation compared to first-fit.
    #[must_use = "best-fit allocation result must be consumed"]
    pub fn alloc_contiguous_best_fit(&mut self, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        let need = u64::from(nblocks);
        if need == 0 || need > self.block_count || need > self.free_count {
            return Err(AllocError::NoSpace);
        }

        let total = self.block_count;
        let mut best_start: Option<u64> = None;
        let mut best_len: u64 = u64::MAX;
        let mut pos: u64 = 0;

        while pos < total {
            while pos < total && !self.is_free_inner(pos) {
                pos += 1;
            }
            if pos >= total {
                break;
            }
            let start = pos;
            while pos < total && self.is_free_inner(pos) {
                pos += 1;
            }
            let run_len = pos.saturating_sub(start);
            if run_len >= need && run_len < best_len {
                best_start = Some(start);
                best_len = run_len;
                if run_len == need {
                    break;
                }
            }
        }

        if let Some(first) = best_start {
            let ids: Vec<BlockId> = (first..first + need).collect();
            for &id in &ids {
                self.mark_used(id);
            }
            self.hint = first + need;
            return Ok(ids);
        }

        // Wrap-around check.
        let suffix_free = (0..total)
            .rev()
            .take_while(|&blk| self.is_free_inner(blk))
            .count() as u64;
        let prefix_free = (0..total)
            .take_while(|&blk| self.is_free_inner(blk))
            .count() as u64;

        if suffix_free + prefix_free >= need {
            let first = total.saturating_sub(need.min(suffix_free));
            let ids: Vec<BlockId> = if suffix_free >= need {
                (first..first + need).collect()
            } else {
                (first..total).chain(0..(need - suffix_free)).collect()
            };
            for &id in &ids {
                self.mark_used(id);
            }
            self.hint = if suffix_free >= need {
                first + need
            } else {
                need - suffix_free
            };
            if self.hint >= total {
                self.hint = 0;
            }
            return Ok(ids);
        }

        Err(AllocError::NoSpace)
    }

    /// Return the length (in blocks) of the largest contiguous free run.
    #[must_use]
    pub fn largest_contiguous_free(&self) -> u32 {
        let mut max_run: u64 = 0;
        let mut current_run: u64 = 0;
        let total = self.block_count;

        for blk in 0..total {
            if self.is_free_inner(blk) {
                current_run += 1;
                max_run = max_run.max(current_run);
            } else {
                current_run = 0;
            }
        }

        let suffix_free = (0..total)
            .rev()
            .take_while(|&blk| self.is_free_inner(blk))
            .count() as u64;
        let prefix_free = (0..total)
            .take_while(|&blk| self.is_free_inner(blk))
            .count() as u64;

        let wrap_run = if suffix_free > 0 && prefix_free > 0 {
            (suffix_free + prefix_free).min(total)
        } else {
            0
        };

        max_run.max(wrap_run) as u32
    }

    /// Validate internal consistency invariants.
    #[must_use]
    pub fn check_invariants(&self) -> bool {
        let actual_free = self.count_free_blocks();
        if actual_free != self.free_count {
            return false;
        }

        let rem = self.block_count % Self::BITS_PER_WORD;
        if rem != 0 {
            if let Some(last) = self.words.last() {
                let mask = !((1u64 << rem) - 1);
                if (*last & mask) != mask {
                    return false;
                }
            }
        }

        let expected_words = Self::word_count_for(self.block_count);
        if self.words.len() != expected_words {
            return false;
        }

        true
    }

    /// Return an iterator over contiguous free runs.
    pub fn free_extents(&self) -> FreeExtentIter<'_> {
        FreeExtentIter::new(self)
    }

    /// Count the number of contiguous free runs.
    #[must_use]
    pub fn free_run_count(&self) -> u64 {
        let mut count: u64 = 0;
        let total = self.block_count;
        let mut pos: u64 = 0;

        while pos < total {
            while pos < total && !self.is_free_inner(pos) {
                pos += 1;
            }
            if pos >= total {
                break;
            }
            count += 1;
            while pos < total && self.is_free_inner(pos) {
                pos += 1;
            }
        }

        count
    }

    /// Allocate `nblocks` contiguous blocks starting at `start_block`.
    ///
    /// Returns `Ok(Vec<BlockId>)` when the run `[start_block, start_block+nblocks)`
    /// is entirely free, or `Err(AllocError::NoSpace)` when any block in the
    /// range is already used or out of bounds.
    #[must_use = "allocation-at-offset result must be consumed to track block usage"]
    pub fn alloc_contiguous_at(
        &mut self,
        start_block: u64,
        nblocks: u32,
    ) -> Result<Vec<BlockId>, AllocError> {
        let need = u64::from(nblocks);
        if need == 0 || start_block + need > self.block_count {
            return Err(AllocError::NoSpace);
        }
        for blk in start_block..start_block + need {
            if !self.is_free_inner(blk) {
                return Err(AllocError::NoSpace);
            }
        }
        let ids: Vec<BlockId> = (start_block..start_block + need).collect();
        for &id in &ids {
            self.mark_used(id);
        }
        Ok(ids)
    }

    /// Allocate `nblocks` blocks, preferring one contiguous run and falling
    /// back to scattered allocation when the bitmap is fragmented.
    #[must_use = "allocation result must be consumed to track block usage"]
    pub fn alloc(&mut self, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        self.alloc_contiguous(nblocks)
            .or_else(|_| self.alloc_contiguous_best_fit(nblocks))
            .or_else(|_| self.alloc_any(nblocks))
    }

    /// Allocate any `nblocks` free blocks, not necessarily contiguous.
    ///
    /// This is a fallback when contiguity is not required. Scan from hint
    /// picking the first `nblocks` free blocks found.
    #[must_use = "scattered allocation result must be consumed to track block usage"]
    pub fn alloc_any(&mut self, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        let need = u64::from(nblocks);
        if need == 0 || need > self.free_count {
            return Err(AllocError::NoSpace);
        }

        let total = self.block_count;
        let mut result = Vec::with_capacity(need as usize);
        let start = self.hint;

        // Two-pass scan.
        for pass in 0..2 {
            let range_start = if pass == 0 { start } else { 0 };
            let range_end = if pass == 0 { total } else { start };

            for blk in range_start..range_end {
                if self.is_free_inner(blk) {
                    self.mark_used(blk);
                    result.push(blk);
                    if result.len() as u64 >= need {
                        self.hint = blk + 1;
                        if self.hint >= total {
                            self.hint = 0;
                        }
                        return Ok(result);
                    }
                }
            }
        }

        // Should not reach here; free_count check guards.
        Err(AllocError::NoSpace)
    }

    /// Allocate `nblocks` contiguous free blocks, skipping blocks on fenced devices.
    #[must_use = "filtered contiguous allocation result must be consumed"]
    pub fn alloc_contiguous_skip_devices(
        &mut self,
        nblocks: u32,
        block_size: u32,
        device_extents: &std::collections::BTreeMap<u64, (DeviceId, u64)>,
        fenced_devices: &std::collections::HashSet<DeviceId>,
    ) -> Result<Vec<BlockId>, AllocError> {
        let need = u64::from(nblocks);
        if need == 0 || need > self.block_count || need > self.free_count {
            return Err(AllocError::NoSpace);
        }

        let start_hint = self.hint;
        let total = self.block_count;

        let mut run_start: Option<u64> = None;
        let mut run_len: u64 = 0;

        for pass in 0..2 {
            let range_start = if pass == 0 { start_hint } else { 0 };
            let range_end = if pass == 0 { total } else { start_hint };

            if pass == 1 {
                if let Some(rs) = run_start {
                    if rs + run_len < total {
                        run_start = None;
                        run_len = 0;
                    }
                }
            }

            for blk in range_start..range_end {
                if self.is_free_inner(blk)
                    && !is_block_fenced_inner(blk, block_size, device_extents, fenced_devices)
                {
                    if run_start.is_none() {
                        run_start = Some(blk);
                    }
                    run_len += 1;
                    if run_len >= need {
                        let first = run_start.unwrap();
                        let mut ids = Vec::with_capacity(need as usize);
                        for off in 0..need {
                            let id = (first + off) % total;
                            ids.push(id);
                        }
                        for &id in &ids {
                            self.mark_used(id);
                        }
                        let hint = (first + need) % total;
                        self.hint = hint;
                        return Ok(ids);
                    }
                } else {
                    run_start = None;
                    run_len = 0;
                }
            }
        }

        // Wrap-around check.
        let suffix_free = (0..total)
            .rev()
            .take_while(|&blk| {
                self.is_free_inner(blk)
                    && !is_block_fenced_inner(blk, block_size, device_extents, fenced_devices)
            })
            .count() as u64;
        let prefix_free = (0..total)
            .take_while(|&blk| {
                self.is_free_inner(blk)
                    && !is_block_fenced_inner(blk, block_size, device_extents, fenced_devices)
            })
            .count() as u64;

        if suffix_free + prefix_free >= need {
            let first = total.saturating_sub(need.min(suffix_free));
            let ids: Vec<BlockId> = if suffix_free >= need {
                (first..first + need).collect()
            } else {
                (first..total).chain(0..(need - suffix_free)).collect()
            };
            for &id in &ids {
                self.mark_used(id);
            }
            self.hint = if suffix_free >= need {
                first + need
            } else {
                need - suffix_free
            };
            if self.hint >= total {
                self.hint = 0;
            }
            return Ok(ids);
        }

        Err(AllocError::NoSpace)
    }

    /// Allocate any `nblocks` free blocks, skipping blocks on fenced devices.
    #[must_use = "filtered scattered allocation result must be consumed"]
    pub fn alloc_any_skip_devices(
        &mut self,
        nblocks: u32,
        block_size: u32,
        device_extents: &std::collections::BTreeMap<u64, (DeviceId, u64)>,
        fenced_devices: &std::collections::HashSet<DeviceId>,
    ) -> Result<Vec<BlockId>, AllocError> {
        self.alloc_contiguous_skip_devices(nblocks, block_size, device_extents, fenced_devices)
            .or_else(|_| {
                self.alloc_scattered_skip_devices(
                    nblocks,
                    block_size,
                    device_extents,
                    fenced_devices,
                )
            })
    }

    /// Scattered fallback for skip-devices allocation.
    fn alloc_scattered_skip_devices(
        &mut self,
        nblocks: u32,
        block_size: u32,
        device_extents: &std::collections::BTreeMap<u64, (DeviceId, u64)>,
        fenced_devices: &std::collections::HashSet<DeviceId>,
    ) -> Result<Vec<BlockId>, AllocError> {
        let need = u64::from(nblocks);
        if need == 0 || need > self.free_count {
            return Err(AllocError::NoSpace);
        }

        let total = self.block_count;
        let mut result = Vec::with_capacity(need as usize);
        let start = self.hint;

        for pass in 0..2 {
            let range_start = if pass == 0 { start } else { 0 };
            let range_end = if pass == 0 { total } else { start };

            for blk in range_start..range_end {
                if self.is_free_inner(blk)
                    && !is_block_fenced_inner(blk, block_size, device_extents, fenced_devices)
                {
                    self.mark_used(blk);
                    result.push(blk);
                    if result.len() as u64 >= need {
                        self.hint = blk + 1;
                        if self.hint >= total {
                            self.hint = 0;
                        }
                        return Ok(result);
                    }
                }
            }
        }

        Err(AllocError::NoSpace)
    }

    /// Free a set of blocks.
    ///
    /// Idempotent: already-free blocks are silently ignored.
    pub fn free_blocks(&mut self, blocks: &[BlockId]) {
        for &id in blocks {
            self.mark_free(id);
        }
    }

    /// Reset the allocation scan hint.
    pub fn reset_hint(&mut self) {
        self.hint = 0;
    }

    /// Internal: test bit without bounds check (caller guarantees id < block_count).
    ///
    /// Visibility widened to `pub(crate)` for [`FreeExtentIter`].
    pub(crate) fn is_free_inner(&self, id: BlockId) -> bool {
        let word_idx = (id / Self::BITS_PER_WORD) as usize;
        let bit = (id % Self::BITS_PER_WORD) as u32;
        (self.words[word_idx] & (1u64 << bit)) == 0
    }

    /// Compute (word_idx, bit_in_word) for a block id.
    fn bit_pos(id: BlockId) -> (usize, u32) {
        let word_idx = (id / Self::BITS_PER_WORD) as usize;
        let bit = (id % Self::BITS_PER_WORD) as u32;
        (word_idx, bit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bitmap_all_free() {
        let bm = FreeBlockBitmap::new(1024);
        assert_eq!(bm.block_count(), 1024);
        assert_eq!(bm.free_count(), 1024);
        assert!(bm.is_dirty());
    }

    #[test]
    fn alloc_one_mark_used_free_returns() {
        let mut bm = FreeBlockBitmap::new(1024);
        let blocks = bm.alloc_contiguous(1).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(bm.free_count(), 1023);
        assert!(!bm.is_free(blocks[0]));

        bm.free_blocks(&blocks);
        assert_eq!(bm.free_count(), 1024);
        assert!(bm.is_free(blocks[0]));
    }

    #[test]
    fn alloc_all_then_one_more() {
        let mut bm = FreeBlockBitmap::new(128);
        bm.alloc_contiguous(128).unwrap();
        assert_eq!(bm.free_count(), 0);
        assert!(bm.alloc_contiguous(1).is_err());
    }

    #[test]
    fn free_already_free_is_noop() {
        let mut bm = FreeBlockBitmap::new(128);
        let initial_free = bm.free_count();
        bm.free_blocks(&[0, 1, 2]); // should be no-ops
        assert_eq!(bm.free_count(), initial_free);
    }

    #[test]
    fn alloc_contiguous_returns_consecutive_blocks() {
        let mut bm = FreeBlockBitmap::new(1024);
        let blocks = bm.alloc_contiguous(5).unwrap();
        assert_eq!(blocks.len(), 5);
        for i in 1..5 {
            assert_eq!(blocks[i], blocks[i - 1] + 1);
        }
    }

    #[test]
    fn alloc_contiguous_skips_used_regions() {
        let mut bm = FreeBlockBitmap::new(1024);
        // Manually mark blocks 3,4 as used.
        bm.mark_used(3);
        bm.mark_used(4);
        // alloc 3 blocks; should get 0,1,2 (since 3,4 are used).
        let blocks = bm.alloc_contiguous(3).unwrap();
        assert_eq!(blocks, &[0, 1, 2]);

        // Next alloc of 3 should get 5,6,7.
        let blocks2 = bm.alloc_contiguous(3).unwrap();
        assert_eq!(blocks2, &[5, 6, 7]);
    }

    #[test]
    fn alloc_any_collects_scattered() {
        let mut bm = FreeBlockBitmap::new(256);
        // Mark all even blocks as used.
        for i in (0..256).step_by(2) {
            bm.mark_used(i);
        }
        // alloc_any(3) should pick 3 odd blocks.
        let blocks = bm.alloc_any(3).unwrap();
        assert_eq!(blocks.len(), 3);
        for &b in &blocks {
            assert!(b % 2 == 1, "expected odd block, got {b}");
        }
    }

    #[test]
    fn alloc_falls_back_to_scattered_blocks() {
        let mut bm = FreeBlockBitmap::new(8);
        for block in [0, 2, 4, 6, 7] {
            bm.mark_used(block);
        }

        let blocks = bm.alloc(3).unwrap();

        assert_eq!(blocks, &[1, 3, 5]);
        assert_eq!(bm.free_count(), 0);
    }

    #[test]
    fn alloc_zero_blocks_err() {
        let mut bm = FreeBlockBitmap::new(256);
        assert!(bm.alloc_contiguous(0).is_err());
    }

    #[test]
    fn from_words_preserves_state() {
        let mut bm = FreeBlockBitmap::new(256);
        bm.mark_used(10);
        bm.mark_used(20);
        let words = bm.words().to_vec();
        let free = bm.free_count();

        let bm2 = FreeBlockBitmap::from_words(256, words);
        assert_eq!(bm2.free_count(), free);
        assert!(!bm2.is_free(10));
        assert!(!bm2.is_free(20));
        assert!(bm2.is_free(0));
    }

    #[test]
    fn from_words_short_input_treats_missing_words_as_used() {
        let bm = FreeBlockBitmap::from_words(128, vec![0]);

        assert_eq!(bm.free_count(), 64);
        assert!(bm.is_free(63));
        assert!(!bm.is_free(64));
    }

    #[test]
    fn dirty_flag_management() {
        let mut bm = FreeBlockBitmap::from_words(128, vec![0, 0]);
        assert!(!bm.is_dirty());

        bm.mark_used(5);
        assert!(bm.is_dirty());

        bm.mark_clean();
        assert!(!bm.is_dirty());

        bm.mark_free(5);
        assert!(bm.is_dirty());
    }

    #[test]
    fn mark_used_out_of_range_is_noop() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.mark_used(100); // out of range
        assert_eq!(bm.free_count(), 64);
    }

    #[test]
    fn hint_wraps_around() {
        let mut bm = FreeBlockBitmap::new(64);
        let _ = bm.alloc_contiguous(60).unwrap(); // leaves 4 free
        let blocks = bm.alloc_contiguous(4).unwrap();
        // Should have wrapped around or used remaining.
        assert_eq!(blocks.len(), 4);
        assert_eq!(bm.free_count(), 0);
    }

    /// Prove that freed blocks can be re-allocated at the same addresses
    /// when the scan hint is reset to start from zero.
    #[test]
    fn reuse_after_free_same_addresses_with_reset_hint() {
        let mut bm = FreeBlockBitmap::new(64);
        let blocks = bm.alloc_contiguous(5).unwrap();
        assert_eq!(&blocks, &[0, 1, 2, 3, 4]);
        assert_eq!(bm.free_count(), 59);
        bm.free_blocks(&blocks);
        assert_eq!(bm.free_count(), 64);
        bm.reset_hint();
        let blocks2 = bm.alloc_contiguous(5).unwrap();
        assert_eq!(&blocks2, &[0, 1, 2, 3, 4]);
    }

    /// Free adjacent extents and verify the combined space satisfies
    /// a larger contiguous allocation (bitmap analog of free-list merge).
    #[test]
    fn adjacent_free_extents_coalesce_for_larger_contiguous_alloc() {
        let mut bm = FreeBlockBitmap::new(64);
        let a = bm.alloc_contiguous(3).unwrap(); // 0..2
        let b = bm.alloc_contiguous(3).unwrap(); // 3..5
        assert_eq!(&a, &[0, 1, 2]);
        assert_eq!(&b, &[3, 4, 5]);
        bm.free_blocks(&a);
        bm.free_blocks(&b);
        bm.reset_hint();
        // 0..5 should now be a single 6-block contiguous free run.
        let c = bm.alloc_contiguous(6).unwrap();
        assert_eq!(&c, &[0, 1, 2, 3, 4, 5]);
    }

    /// Allocating a sub-range leaves the remainder available (split test).
    #[test]
    fn split_large_extent_remainder_still_allocatable() {
        let mut bm = FreeBlockBitmap::new(64);
        let a = bm.alloc_contiguous(3).unwrap(); // 0..2
        assert_eq!(&a, &[0, 1, 2]);
        // Remainder 3..63 (61 blocks) must still be allocatable.
        let b = bm.alloc_contiguous(61).unwrap();
        assert_eq!(b.len(), 61);
        assert_eq!(b.first(), Some(&3));
        assert_eq!(b.last(), Some(&63));
        assert_eq!(bm.free_count(), 0);
    }

    /// After interleaved alloc/free creates fragmentation, alloc_contiguous
    /// still finds the largest contiguous free run via the two-pass scan.
    /// Guards against FUSE write dispatch picking stale or fragmented extents.
    #[test]
    fn fragmentation_stress_finds_largest_contiguous_run() {
        let mut bm = FreeBlockBitmap::new(64);
        // Create alternating used/free in first 32 blocks.
        for i in (0..32).step_by(2) {
            bm.mark_used(i);
        }
        // Mark 32..35 used.
        for i in 32..36 {
            bm.mark_used(i);
        }
        // Mark 40..47 used.
        for i in 40..48 {
            bm.mark_used(i);
        }
        // Mark 50..63 used.
        for i in 50..64 {
            bm.mark_used(i);
        }
        // Free blocks: odd 1..31, 36..39 (4), 48..49 (2).
        // Largest contiguous free run = 36..39 = 4 blocks.
        bm.reset_hint();
        let blocks = bm.alloc_contiguous(4).unwrap();
        assert_eq!(&blocks, &[36, 37, 38, 39]);
    }

    // ─── FreeExtentIter ───

    #[test]
    fn free_extent_iter_empty_when_all_used() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.alloc_contiguous(64).unwrap();
        let extents: Vec<(u64, u64)> = bm.free_extents().collect();
        assert!(extents.is_empty());
    }

    #[test]
    fn free_extent_iter_all_free_single_run() {
        let bm = FreeBlockBitmap::new(64);
        let extents: Vec<(u64, u64)> = bm.free_extents().collect();
        assert_eq!(extents, vec![(0, 64)]);
    }

    #[test]
    fn free_extent_iter_fragmented() {
        let mut bm = FreeBlockBitmap::new(16);
        bm.mark_used(3);
        bm.mark_used(7);
        bm.mark_used(8);
        bm.mark_used(12);
        let extents: Vec<(u64, u64)> = bm.free_extents().collect();
        assert_eq!(extents, vec![(0, 3), (4, 3), (9, 3), (13, 3)]);
    }

    #[test]
    fn free_run_count_matches_iter() {
        let mut bm = FreeBlockBitmap::new(32);
        for i in (0..32).step_by(3) {
            bm.mark_used(i);
        }
        let iter_count = bm.free_extents().count() as u64;
        assert_eq!(bm.free_run_count(), iter_count);
    }

    #[test]
    fn free_run_count_fully_free_is_one() {
        let bm = FreeBlockBitmap::new(64);
        assert_eq!(bm.free_run_count(), 1);
    }

    #[test]
    fn free_run_count_fully_used_is_zero() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.alloc_contiguous(64).unwrap();
        assert_eq!(bm.free_run_count(), 0);
    }

    // ─── largest_contiguous_free ───

    #[test]
    fn largest_contiguous_free_fully_free() {
        let bm = FreeBlockBitmap::new(64);
        assert_eq!(bm.largest_contiguous_free(), 64);
    }

    #[test]
    fn largest_contiguous_free_checkerboard_is_one() {
        let mut bm = FreeBlockBitmap::new(64);
        for i in (0..64).step_by(2) {
            bm.mark_used(i);
        }
        assert_eq!(bm.largest_contiguous_free(), 1);
    }

    #[test]
    fn largest_contiguous_free_mid_range() {
        let mut bm = FreeBlockBitmap::new(64);
        for i in 0..20 {
            bm.mark_used(i);
        }
        for i in 40..64 {
            bm.mark_used(i);
        }
        assert_eq!(bm.largest_contiguous_free(), 20);
    }

    #[test]
    fn largest_contiguous_free_wrap_around() {
        let mut bm = FreeBlockBitmap::new(64);
        for i in 40..60 {
            bm.mark_used(i);
        }
        assert_eq!(bm.largest_contiguous_free(), 44);
    }

    #[test]
    fn largest_contiguous_free_fully_used_is_zero() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.alloc_contiguous(64).unwrap();
        assert_eq!(bm.largest_contiguous_free(), 0);
    }

    // ─── best-fit ───

    #[test]
    fn best_fit_selects_smallest_sufficient_run() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.mark_used(0);
        bm.mark_used(1);
        bm.mark_used(4);
        bm.mark_used(10);
        bm.mark_used(14);
        let blocks = bm.alloc_contiguous_best_fit(2).unwrap();
        assert_eq!(&blocks, &[2, 3]);
    }

    #[test]
    fn best_fit_exact_fit_short_circuits() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.mark_used(0);
        bm.mark_used(1);
        bm.mark_used(2);
        bm.mark_used(30);
        let blocks = bm.alloc_contiguous_best_fit(3).unwrap();
        assert_eq!(&blocks, &[3, 4, 5]);
    }

    #[test]
    fn best_fit_wrap_around() {
        let mut bm = FreeBlockBitmap::new(64);
        for i in 20..44 {
            bm.mark_used(i);
        }
        let blocks = bm.alloc_contiguous_best_fit(30).unwrap();
        assert_eq!(blocks.len(), 30);
        let first = *blocks.first().unwrap();
        let last = *blocks.last().unwrap();
        assert!(
            first >= 34 || last < 20,
            "expected wrap-around, first={first} last={last}"
        );
    }

    #[test]
    fn best_fit_no_space() {
        let mut bm = FreeBlockBitmap::new(64);
        for i in (0..64).step_by(4) {
            bm.mark_used(i);
        }
        assert!(bm.alloc_contiguous_best_fit(4).is_err());
    }

    #[test]
    fn best_fit_zero_blocks_err() {
        let mut bm = FreeBlockBitmap::new(64);
        assert!(bm.alloc_contiguous_best_fit(0).is_err());
    }

    // ─── check_invariants ───

    #[test]
    fn invariants_pass_on_new_bitmap() {
        let bm = FreeBlockBitmap::new(128);
        assert!(bm.check_invariants());
    }

    #[test]
    fn invariants_pass_after_alloc_free() {
        let mut bm = FreeBlockBitmap::new(128);
        let blocks = bm.alloc_contiguous(50).unwrap();
        assert!(bm.check_invariants());
        bm.free_blocks(&blocks);
        assert!(bm.check_invariants());
    }

    #[test]
    fn invariants_pass_after_exhaustion() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.alloc_contiguous(64).unwrap();
        assert!(bm.check_invariants());
    }

    #[test]
    fn invariants_pass_from_words() {
        let bm = FreeBlockBitmap::from_words(128, vec![0, 0]);
        assert!(bm.check_invariants());
    }

    #[test]
    fn invariants_pass_after_random_mutations() {
        let mut bm = FreeBlockBitmap::new(256);
        let mut seed: u64 = 42;
        for _ in 0..200 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let blk = seed % 256;
            if seed & 1 == 0 {
                bm.mark_used(blk);
            } else {
                bm.mark_free(blk);
            }
        }
        assert!(bm.check_invariants());
    }

    #[test]
    fn alloc_uses_best_fit_as_fallback() {
        let mut bm = FreeBlockBitmap::new(64);
        bm.mark_used(3);
        for i in 5..64 {
            bm.mark_used(i);
        }
        let blocks = bm.alloc(2).unwrap();
        assert_eq!(blocks.len(), 2);
    }

    /// After freeing blocks behind the hint, alloc_any finds them on the
    /// wrap pass when blocks past hint are all used.
    #[test]
    fn alloc_any_reuses_freed_blocks_on_wrap_pass() {
        let mut bm = FreeBlockBitmap::new(64);
        let a = bm.alloc_contiguous(10).unwrap(); // 0..9, hint=10
        bm.free_blocks(&a); // freed, but hint is at 10
                            // Mark all blocks past hint as used so the first pass finds nothing.
        for i in 10..64 {
            bm.mark_used(i);
        }
        // Only free blocks are 0..9.
        // alloc_any scans from hint=10 forward (all used), wraps to 0..10.
        let b = bm.alloc_any(10).unwrap();
        let mut sorted = b.clone();
        sorted.sort();
        assert_eq!(&sorted, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
