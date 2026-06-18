// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE `statfs_out` reply layout and serialization.
//!
//! Mirrors the Linux `struct fuse_statfs_out` wire format:
//! - 11 × u64 fields (blocks, bfree, bavail, files, ffree, favail, bsize, namelen, frsize, padding, spare)
//! - 88 bytes total.
//!
//! The reply struct holds the canonical field values; [`StatfsReply::as_fuse_bytes`]
//! serializes them to little-endian wire format.

/// A FUSE `statfs_out` reply with all fields populated.
///
/// All block/file counts are `u64`; `bsize`, `frsize`, and `namemax`
/// are `u32` in the wire format but held as `u64` for convenience.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatfsReply {
    /// Total number of blocks in the filesystem (`f_blocks`).
    pub blocks: u64,
    /// Number of free blocks (`f_bfree`).
    pub bfree: u64,
    /// Number of free blocks available to unprivileged users (`f_bavail`).
    pub bavail: u64,
    /// Total number of file slots / inodes (`f_files`).
    pub files: u64,
    /// Number of free file slots (`f_ffree`).
    pub ffree: u64,
    /// Number of free file slots available to unprivileged users (`f_favail`).
    pub favail: u64,
    /// Block size in bytes (`f_bsize`).
    pub bsize: u64,
    /// Maximum filename length (`f_namelen`).
    pub namemax: u32,
    /// Fragment size (`f_frsize`); TideFS sets equal to `f_bsize`.
    pub frsize: u64,
}

impl StatfsReply {
    /// Byte length of the serialized `statfs_out` on the wire.
    pub const ENCODED_LEN: usize = 88;

    /// Create a minimal reply with only block size and fragment size set.
    #[must_use]
    pub fn new(block_size: u64) -> Self {
        Self {
            bsize: block_size,
            frsize: block_size,
            ..Self::default()
        }
    }

    /// Return a POSIX-consistent view of the capacity counters.
    ///
    /// Free block counts are capped at total blocks, available blocks are capped
    /// at free blocks, and inode availability follows the same total/free
    /// relationship. This keeps impossible lower-layer or lifecycle accounting
    /// states from leaking into statfs replies.
    #[must_use]
    pub fn normalized(self) -> Self {
        let bfree = self.bfree.min(self.blocks);
        let bavail = self.bavail.min(bfree);
        let ffree = self.ffree.min(self.files);
        let favail = self.favail.min(ffree);

        Self {
            bfree,
            bavail,
            ffree,
            favail,
            ..self
        }
    }

    /// Serialize into the FUSE `statfs_out` wire format (little-endian).
    ///
    /// Returns an 88-byte array suitable for `fuse_out_header` + payload.
    #[must_use]
    pub fn as_fuse_bytes(self) -> [u8; Self::ENCODED_LEN] {
        let reply = self.normalized();
        let mut buf = [0_u8; Self::ENCODED_LEN];
        let mut pos = 0;

        let mut write_u64 = |v: u64| {
            buf[pos..pos + 8].copy_from_slice(&v.to_le_bytes());
            pos += 8;
        };

        write_u64(reply.blocks);
        write_u64(reply.bfree);
        write_u64(reply.bavail);
        write_u64(reply.files);
        write_u64(reply.ffree);
        write_u64(reply.favail);
        write_u64(reply.bsize);
        write_u64(u64::from(reply.namemax));
        write_u64(reply.frsize);
        // padding (8 bytes, zeroed)
        write_u64(0);
        // spare (8 bytes, zeroed — last field in fuse_statfs_out)
        write_u64(0);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_len_is_88() {
        assert_eq!(StatfsReply::ENCODED_LEN, 88);
    }

    #[test]
    fn new_sets_block_and_fragment_size() {
        let s = StatfsReply::new(4096);
        assert_eq!(s.bsize, 4096);
        assert_eq!(s.frsize, 4096);
        assert_eq!(s.blocks, 0);
    }

    #[test]
    fn roundtrip_fixed_values() {
        let reply = StatfsReply {
            blocks: 1000000,
            bfree: 500000,
            bavail: 450000,
            files: 2000000,
            ffree: 1500000,
            favail: 1400000,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
        };

        let bytes = reply.as_fuse_bytes();

        // Verify field positions (little-endian reads)
        let read_u64 = |offset: usize| -> u64 {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };

        assert_eq!(read_u64(0), 1000000); // blocks
        assert_eq!(read_u64(8), 500000); // bfree
        assert_eq!(read_u64(16), 450000); // bavail
        assert_eq!(read_u64(24), 2000000); // files
        assert_eq!(read_u64(32), 1500000); // ffree
        assert_eq!(read_u64(40), 1400000); // favail
        assert_eq!(read_u64(48), 4096); // bsize
        assert_eq!(read_u64(56), 255); // namemax (as u64)
        assert_eq!(read_u64(64), 4096); // frsize
        assert_eq!(read_u64(72), 0); // padding
        assert_eq!(read_u64(80), 0); // spare
    }

    #[test]
    fn normalized_clamps_inconsistent_capacity_counts() {
        let reply = StatfsReply {
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

        assert_eq!(reply.bfree, 10);
        assert_eq!(reply.bavail, 10);
        assert_eq!(reply.ffree, 7);
        assert_eq!(reply.favail, 7);
    }

    #[test]
    fn fuse_bytes_serialize_normalized_capacity_counts() {
        let reply = StatfsReply {
            blocks: 10,
            bfree: 8,
            bavail: 9,
            files: 7,
            ffree: 6,
            favail: 8,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
        };

        let bytes = reply.as_fuse_bytes();
        let read_u64 = |offset: usize| -> u64 {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };

        assert_eq!(read_u64(8), 8);
        assert_eq!(read_u64(16), 8);
        assert_eq!(read_u64(32), 6);
        assert_eq!(read_u64(40), 6);
    }

    #[test]
    fn zero_reply_is_all_zeros() {
        let reply = StatfsReply::default();
        let bytes = reply.as_fuse_bytes();
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn namemax_u32_max_serializes_correctly() {
        let reply = StatfsReply {
            blocks: 1,
            bfree: 1,
            bavail: 1,
            files: 1,
            ffree: 1,
            favail: 1,
            bsize: 512,
            namemax: u32::MAX,
            frsize: 512,
        };
        let bytes = reply.as_fuse_bytes();
        let namemax_from_wire = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        assert_eq!(namemax_from_wire, u64::from(u32::MAX));
    }

    #[test]
    fn extreme_block_counts_serialize_correctly() {
        let reply = StatfsReply {
            blocks: u64::MAX,
            bfree: u64::MAX / 2,
            bavail: u64::MAX / 4,
            files: u64::MAX,
            ffree: u64::MAX / 2,
            favail: u64::MAX / 4,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
        };
        let bytes = reply.as_fuse_bytes();
        let read_u64 = |offset: usize| -> u64 {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };
        assert_eq!(read_u64(0), u64::MAX);
        assert_eq!(read_u64(8), u64::MAX / 2);
        assert_eq!(read_u64(16), u64::MAX / 4);
        assert_eq!(read_u64(24), u64::MAX);
        assert_eq!(read_u64(32), u64::MAX / 2);
        assert_eq!(read_u64(40), u64::MAX / 4);
    }

    #[test]
    fn frsize_not_equal_to_bsize_preserved_in_wire() {
        let reply = StatfsReply {
            bsize: 4096,
            frsize: 8192,
            ..StatfsReply::default()
        };
        let bytes = reply.as_fuse_bytes();
        let read_u64 = |offset: usize| -> u64 {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };
        assert_eq!(read_u64(48), 4096);
        assert_eq!(read_u64(64), 8192);
        assert_ne!(read_u64(48), read_u64(64));
    }

    #[test]
    fn normalized_is_idempotent() {
        let reply = StatfsReply {
            blocks: 10,
            bfree: 12,
            bavail: 15,
            files: 7,
            ffree: 9,
            favail: 11,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
        };
        let once = reply.normalized();
        let twice = once.normalized();
        assert_eq!(once, twice);
    }

    #[test]
    fn debug_output_contains_field_values() {
        let reply = StatfsReply {
            blocks: 100,
            bfree: 50,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
            ..StatfsReply::default()
        };
        let debug = format!("{reply:?}");
        assert!(debug.contains("100"));
        assert!(debug.contains("50"));
        assert!(debug.contains("4096"));
        assert!(debug.contains("255"));
    }

    #[test]
    fn clone_equals_original() {
        let original = StatfsReply {
            blocks: 1000,
            bfree: 500,
            bavail: 400,
            files: 2000,
            ffree: 1500,
            favail: 1400,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
        };
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn statfs_reply_structural_equality() {
        let a = StatfsReply {
            blocks: 1,
            bfree: 2,
            bsize: 512,
            namemax: 64,
            frsize: 512,
            ..StatfsReply::default()
        };
        let b = StatfsReply {
            blocks: 1,
            bfree: 2,
            bsize: 512,
            namemax: 64,
            frsize: 512,
            ..StatfsReply::default()
        };
        assert_eq!(a, b);
        let c = StatfsReply { blocks: 2, ..a };
        assert_ne!(a, c);
    }

    #[test]
    fn new_with_block_size_zero_is_valid() {
        // block_size=0 is unusual but not rejected at construction;
        // correctness logic lives in callers and in normalized.
        let s = StatfsReply::new(0);
        assert_eq!(s.bsize, 0);
        assert_eq!(s.frsize, 0);
    }

    #[test]
    fn default_has_all_zero_fields() {
        let s = StatfsReply::default();
        assert_eq!(s.blocks, 0);
        assert_eq!(s.bfree, 0);
        assert_eq!(s.bavail, 0);
        assert_eq!(s.files, 0);
        assert_eq!(s.ffree, 0);
        assert_eq!(s.favail, 0);
        assert_eq!(s.bsize, 0);
        assert_eq!(s.namemax, 0);
        assert_eq!(s.frsize, 0);
    }
}
