//! `Statfs` struct and accumulation helpers.
//!
//! Mirrors the Linux `struct statfs` / `statvfs` fields used by
//! the FUSE `statfs` operation. The block allocator fills block-related
//! fields (`f_blocks`, `f_bfree`, `f_bavail`, `f_bsize`,
//! `f_frsize`) from the free-block bitmap; inode-related fields
//! (`f_files`, `f_ffree`, `f_favail`, `f_namemax`) are zeroed.
//! The namespace layer is expected to merge inode-table counters into the
//! returned struct, and the FUSE layer fills `f_type` and `f_flags`.
//!
//! This module is read-only with respect to allocation state; callers
//! access it through `BlockAllocator::statfs` which holds only a read
//! lock on the inner state.

/// Filesystem statistics suitable for `statfs`/`statvfs`.
///
/// All fields are `u64` to match the Linux kernel `kstatfs` and FUSE wire format.
/// Inode fields (`f_files`, `f_ffree`, `f_favail`) are zeroed here;
/// the namespace layer is expected to merge inode-table counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statfs {
    /// Total number of blocks in the filesystem.
    pub f_blocks: u64,
    /// Number of free blocks.
    pub f_bfree: u64,
    /// Number of free blocks available to unprivileged users.
    /// Tracks `f_bfree` minus a root-reserve when one is configured.
    pub f_bavail: u64,
    /// Block size in bytes.
    pub f_bsize: u64,
    /// Total number of file slots (inodes). Zeroed here; filled by namespace.
    pub f_files: u64,
    /// Number of free file slots. Zeroed here.
    pub f_ffree: u64,
    /// Number of free file slots available to unprivileged users. Zeroed here.
    pub f_favail: u64,
    /// Maximum filename length. Zeroed here; filled by namespace.
    pub f_namemax: u32,
    /// Fragment size (unused by TideFS; set equal to f_bsize).
    pub f_frsize: u64,
    /// Filesystem type magic. Zeroed here; set by FUSE layer.
    pub f_type: u32,
    /// Mount flags. Zeroed here; set by FUSE layer.
    pub f_flags: u32,
}

impl Statfs {
    /// Create a blank statfs with only block size set.
    #[must_use]
    pub fn new(block_size: u64) -> Self {
        Self {
            f_bsize: block_size,
            f_frsize: block_size,
            ..Self::default()
        }
    }

    /// Fill block-related fields from the allocator state.
    pub fn set_blocks(&mut self, total: u64, free: u64, avail: u64) {
        self.f_blocks = total;
        self.f_bfree = free;
        self.f_bavail = avail;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_zero() {
        let s = Statfs::default();
        assert_eq!(s.f_blocks, 0);
        assert_eq!(s.f_bfree, 0);
        assert_eq!(s.f_bsize, 0);
    }

    #[test]
    fn new_sets_block_and_fragment_size() {
        let s = Statfs::new(4096);
        assert_eq!(s.f_bsize, 4096);
        assert_eq!(s.f_frsize, 4096);
    }

    #[test]
    fn set_blocks_updates_fields() {
        let mut s = Statfs::new(4096);
        s.set_blocks(1000, 500, 450);
        assert_eq!(s.f_blocks, 1000);
        assert_eq!(s.f_bfree, 500);
        assert_eq!(s.f_bavail, 450);
    }
}
