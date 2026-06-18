// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Ioctl dispatch for the block-kmod kernel driver.
//!
//! Translates Linux block-layer ioctl command numbers into backend
//! operations. Handles BLKGETSIZE64, BLKFLSBUF, BLKROSET, BLKROGET,
//! BLKSSZGET, BLKPBSZGET, BLKIOMIN, BLKIOOPT, and BLKALIGNOFF, and
//! returns ENOTTY for unsupported commands.
//!
//! # Kernel binding (Linux 7.0)
//!
//! In the kernel build environment, the ioctl callback registered via
//! `block_device_operations::ioctl` calls [`dispatch_ioctl`] to translate
//! the command number and user-pointer argument. The kernel's `put_user` /
//! `get_user` primitives handle userspace memory access.
//!
//! # Userspace (feature OFF)
//!
//! The typed model provides [`IoctlCommand`] classification and a
//! [`dispatch_ioctl`] function returning structured [`IoctlOutcome`]
//! values suitable for unit testing without a running kernel.

use crate::dispatch::BlockBackend;

// ── Linux block ioctl command numbers ──────────────────────────────────

/// BLKGETSIZE64 — get device size in bytes (`u64 *`).
pub const BLKGETSIZE64: u32 = 0x8008_1272;

/// BLKFLSBUF — flush buffer cache.
pub const BLKFLSBUF: u32 = 0x0000_1261;

/// BLKROSET — set device read-only (`int *`).
pub const BLKROSET: u32 = 0x0000_125D;

/// BLKROGET — get device read-only status (`int *`).
pub const BLKROGET: u32 = 0x0000_125E;

/// BLKSSZGET — get logical block (sector) size (`int *`).
pub const BLKSSZGET: u32 = 0x0000_1268;

/// BLKPBSZGET — get physical block size (`int *`).
pub const BLKPBSZGET: u32 = 0x0000_127B;

/// BLKIOMIN — get minimum I/O size in bytes (`int *`).
pub const BLKIOMIN: u32 = 0x0000_1278;

/// BLKIOOPT — get optimal I/O size in bytes (`int *`).
pub const BLKIOOPT: u32 = 0x0000_1279;

/// BLKALIGNOFF — get alignment offset in bytes (`int *`).
pub const BLKALIGNOFF: u32 = 0x0000_127A;

/// TIDEFS_BLK_RESIZE_GROW — grow block device capacity (u64 new_sectors).
/// Private ioctl in the TideFS range.
pub const TIDEFS_BLK_RESIZE_GROW: u32 = 0x0000_7F01;

/// TIDEFS_BLK_DISCARD_STATS — read discard amplification budget counters.
/// Returns a packed DiscardStatsIoctlPayload to userspace.
pub const TIDEFS_BLK_DISCARD_STATS: u32 = 0x0000_7F02;

/// TIDEFS_BLK_DISCARD_SUBMIT — submit a discard request via ioctl.
/// arg encodes ((start_sector: u32) << 32) | (sector_count: u32).
pub const TIDEFS_BLK_DISCARD_SUBMIT: u32 = 0x0000_7F03;
// ── Errno constants ────────────────────────────────────────────────────

/// Returned for unsupported ioctl commands: "Inappropriate ioctl for device".
pub const ENOTTY: i32 = -25;

/// Returned for null/malformed user-space pointer arguments.
pub const EFAULT: i32 = -14;

/// Returned when a backend operation (e.g. flush) fails.
pub const EIO: i32 = -5;

/// Returned for invalid argument values (e.g. unknown flag in BLKROSET).
pub const EINVAL: i32 = -22;

// ── IoctlCommand ──────────────────────────────────────────────────────

/// Classified ioctl command for block device operations.
///
/// Maps the raw Linux `ioctl` command number to a typed variant.
/// Unrecognised commands are wrapped in [`IoctlCommand::Unsupported`],
/// which the dispatch path rejects with `-ENOTTY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlCommand {
    /// BLKGETSIZE64 — query device capacity in bytes.
    GetSize64,

    /// TIDEFS_BLK_RESIZE_GROW — grow device capacity to new sector count.
    ResizeGrow(u64),
    /// BLKFLSBUF — flush block device buffer cache.
    FlushBuf,
    /// BLKROSET — set device read-only.
    SetReadOnly,
    /// BLKROGET — get device read-only status.
    GetReadOnly,
    /// BLKSSZGET — get logical block (sector) size.
    GetSectorSize,
    /// BLKPBSZGET — get physical block size.
    GetPhysicalSectorSize,
    /// BLKIOMIN — get minimum I/O size in bytes.
    GetIoMin,
    /// BLKIOOPT — get optimal I/O size in bytes.
    GetIoOpt,
    /// BLKALIGNOFF — get alignment offset in bytes.
    GetAlignmentOffset,
    /// TIDEFS_BLK_DISCARD_STATS — read discard amplification budget counters.
    GetDiscardStats,

    /// TIDEFS_BLK_DISCARD_SUBMIT — submit a discard via ioctl.
    /// arg encodes ((start_sector: u32) << 32) | sector_count.
    SubmitDiscard(u64, u32),

    /// Unrecognised or unsupported ioctl command.
    Unsupported(u32),
}

impl IoctlCommand {
    /// Classify a raw ioctl command number.
    #[must_use]
    pub fn from_cmd(cmd: u32) -> Self {
        match cmd {
            BLKGETSIZE64 => Self::GetSize64,
            TIDEFS_BLK_RESIZE_GROW => Self::ResizeGrow(0),
            TIDEFS_BLK_DISCARD_STATS => Self::GetDiscardStats,
            TIDEFS_BLK_DISCARD_SUBMIT => Self::SubmitDiscard(0, 0),
            BLKFLSBUF => Self::FlushBuf,
            BLKROSET => Self::SetReadOnly,
            BLKROGET => Self::GetReadOnly,
            BLKSSZGET => Self::GetSectorSize,
            BLKPBSZGET => Self::GetPhysicalSectorSize,
            BLKIOMIN => Self::GetIoMin,
            BLKIOOPT => Self::GetIoOpt,
            BLKALIGNOFF => Self::GetAlignmentOffset,
            other => Self::Unsupported(other),
        }
    }

    /// Whether this command is recognised (not [`Unsupported`](IoctlCommand::Unsupported)).
    #[must_use]
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }
}

impl core::fmt::Display for IoctlCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GetSize64 => write!(f, "BLKGETSIZE64"),
            Self::ResizeGrow(s) => write!(f, "TIDEFS_BLK_RESIZE_GROW({s})"),
            Self::FlushBuf => write!(f, "BLKFLSBUF"),
            Self::SetReadOnly => write!(f, "BLKROSET"),
            Self::GetReadOnly => write!(f, "BLKROGET"),
            Self::GetSectorSize => write!(f, "BLKSSZGET"),
            Self::GetPhysicalSectorSize => write!(f, "BLKPBSZGET"),
            Self::GetIoMin => write!(f, "BLKIOMIN"),
            Self::GetIoOpt => write!(f, "BLKIOOPT"),
            Self::GetAlignmentOffset => write!(f, "BLKALIGNOFF"),
            Self::GetDiscardStats => write!(f, "TIDEFS_BLK_DISCARD_STATS"),
            Self::SubmitDiscard(s, c) => write!(f, "TIDEFS_BLK_DISCARD_SUBMIT({s},{c})"),
            Self::Unsupported(cmd) => write!(f, "Unsupported(0x{cmd:08X})"),
        }
    }
}

// ── IoctlOutcome ──────────────────────────────────────────────────────

/// Outcome of a successful ioctl dispatch.
///
/// Different ioctl commands return different types of data to userspace.
/// This enum captures the per-command return payload so the caller
/// (or the kernel binding's `put_user` path) knows what to copy to
/// the user-provided buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlOutcome {
    /// Command completed with no return value (BLKFLSBUF, BLKROSET).
    Ok,
    /// BLKGETSIZE64: device capacity in bytes.
    Capacity(u64),
    /// BLKROGET: read-only flag.
    ReadOnly(bool),
    /// BLKSSZGET: logical sector size in bytes.
    SectorSize(u32),
    /// BLKPBSZGET: physical block size in bytes.
    PhysicalSectorSize(u32),
    /// BLKIOMIN: minimum I/O size in bytes.
    IoMinSize(u32),
    /// BLKIOOPT: optimal I/O size in bytes.
    IoOptSize(u32),
    /// BLKALIGNOFF: alignment offset in bytes (always 0 for TideFS).
    AlignmentOffset(u32),

    /// TIDEFS_BLK_DISCARD_STATS: discard amplification budget counters.
    DiscardStats(DiscardStatsIoctlPayload),
}

/// Packed payload returned by TIDEFS_BLK_DISCARD_STATS ioctl.
///
/// All fields are u64 so the struct has a stable ABI across kernel/userspace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct DiscardStatsIoctlPayload {
    /// Total discard operations successfully dispatched.
    pub discard_count: u64,
    /// Total logical sectors discarded.
    pub discard_sectors_total: u64,
    /// Number of discards rejected because the amplification budget was exceeded.
    pub discard_budget_exceeded: u64,
    /// Whether discard is supported by this device.
    pub discard_supported: u64,
    /// Per-operation sector cap (0 = no cap).
    pub max_sectors_per_discard: u64,
    /// Lifetime operation cap (0 = unlimited).
    pub max_total_discard_ops: u64,
}

// ── dispatch_ioctl ────────────────────────────────────────────────────

/// Dispatch a block ioctl command against a backend.
///
/// `cmd` is the raw ioctl command number from the kernel (e.g.
/// [`BLKGETSIZE64`]). `arg` is the user-space argument cast to `usize`
/// — in kernel mode this is a pointer; in userspace mode a zero value
/// signals a null-pointer fault. `read_only` is a mutable reference to
/// the device's read-only flag (for BLKROSET/BLKROGET).
///
/// # Returns
///
/// * `Ok(IoctlOutcome)` — the command succeeded; the variant carries
///   any return payload.
/// * `Err(negative_errno)` — the command failed; the value is a
///   standard Linux errno constant (e.g. [`ENOTTY`], [`EFAULT`],
///   [`EIO`]).
///
/// # Errors
///
/// | Condition | Returns |
/// |-----------|---------|
/// | Unrecognised command | `ENOTTY` |
/// | Null pointer for pointer-requiring commands | `EFAULT` |
/// | Backend flush failure (BLKFLSBUF) | `EIO` |
pub fn dispatch_ioctl<B: BlockBackend>(
    backend: &mut B,
    cmd: u32,
    arg: usize,
    read_only: &mut bool,
) -> Result<IoctlOutcome, i32> {
    let command = IoctlCommand::from_cmd(cmd);

    match command {
        IoctlCommand::GetSize64 => {
            if arg == 0 {
                return Err(EFAULT);
            }
            Ok(IoctlOutcome::Capacity(backend.capacity()))
        }
        IoctlCommand::ResizeGrow(new_sectors) => {
            let sectors = if arg != 0 { arg as u64 } else { new_sectors };
            if sectors == 0 {
                return Err(EINVAL);
            }
            backend.resize_grow(sectors).map_err(|_| EINVAL)?;
            Ok(IoctlOutcome::Capacity(backend.capacity()))
        }
        IoctlCommand::FlushBuf => {
            backend.flush().map_err(|_| EIO)?;
            Ok(IoctlOutcome::Ok)
        }
        IoctlCommand::SetReadOnly => {
            // In kernel mode, arg is a pointer to an int obtained via get_user.
            // In userspace mode, arg encodes the flag directly: non-zero = read-only.
            // A null pointer (arg=0) is not checked here; kernel binding handles it.
            *read_only = arg != 0;
            Ok(IoctlOutcome::Ok)
        }
        IoctlCommand::GetReadOnly => {
            if arg == 0 {
                return Err(EFAULT);
            }
            Ok(IoctlOutcome::ReadOnly(*read_only))
        }
        IoctlCommand::GetSectorSize => {
            if arg == 0 {
                return Err(EFAULT);
            }
            Ok(IoctlOutcome::SectorSize(backend.sector_size()))
        }
        IoctlCommand::GetPhysicalSectorSize => {
            if arg == 0 {
                return Err(EFAULT);
            }
            // Physical block size matches logical for the in-memory backend;
            // kernel mode reads this from the request_queue limits.
            Ok(IoctlOutcome::PhysicalSectorSize(backend.sector_size()))
        }
        IoctlCommand::GetIoMin => {
            if arg == 0 {
                return Err(EFAULT);
            }
            Ok(IoctlOutcome::IoMinSize(backend.sector_size()))
        }
        IoctlCommand::GetIoOpt => {
            if arg == 0 {
                return Err(EFAULT);
            }
            // Optimal I/O size: in the kernel binding this is read from
            // the request_queue physical_block_size; the in-memory backend
            // uses sector_size() as a reasonable default.
            Ok(IoctlOutcome::IoOptSize(backend.sector_size()))
        }
        IoctlCommand::GetAlignmentOffset => Ok(IoctlOutcome::AlignmentOffset(0)),
        IoctlCommand::GetDiscardStats => {
            // Discard stats are handled at the device level before
            // reaching dispatch_ioctl. If we reach here, the backend
            // doesn't know about discard stats.
            Err(ENOTTY)
        }
        IoctlCommand::SubmitDiscard(_, _) => {
            // Discard submission is handled at the device level before
            // reaching dispatch_ioctl.
            Err(ENOTTY)
        }
        IoctlCommand::Unsupported(_) => Err(ENOTTY),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockExport;

    fn make_backend() -> BlockExport {
        BlockExport::new_fixed_capacity(1024).unwrap()
    }

    // ── Command classification tests ─────────────────────────────────

    #[test]
    fn classify_blkgetsize64() {
        assert_eq!(
            IoctlCommand::from_cmd(BLKGETSIZE64),
            IoctlCommand::GetSize64
        );
    }

    #[test]
    fn classify_blkflsbuf() {
        assert_eq!(IoctlCommand::from_cmd(BLKFLSBUF), IoctlCommand::FlushBuf);
    }

    #[test]
    fn classify_blkroset() {
        assert_eq!(IoctlCommand::from_cmd(BLKROSET), IoctlCommand::SetReadOnly);
    }

    #[test]
    fn classify_blkroget() {
        assert_eq!(IoctlCommand::from_cmd(BLKROGET), IoctlCommand::GetReadOnly);
    }

    #[test]
    fn classify_blksszget() {
        assert_eq!(
            IoctlCommand::from_cmd(BLKSSZGET),
            IoctlCommand::GetSectorSize
        );
    }

    #[test]
    fn classify_blkpbszget() {
        assert_eq!(
            IoctlCommand::from_cmd(BLKPBSZGET),
            IoctlCommand::GetPhysicalSectorSize
        );
    }

    #[test]
    fn classify_blkiomin() {
        assert_eq!(IoctlCommand::from_cmd(BLKIOMIN), IoctlCommand::GetIoMin);
    }

    #[test]
    fn classify_blkioopt() {
        assert_eq!(IoctlCommand::from_cmd(BLKIOOPT), IoctlCommand::GetIoOpt);
    }

    #[test]
    fn classify_blkalignoff() {
        assert_eq!(
            IoctlCommand::from_cmd(BLKALIGNOFF),
            IoctlCommand::GetAlignmentOffset
        );
    }

    #[test]
    fn classify_unknown_command() {
        let cmd = IoctlCommand::from_cmd(0xDEAD_BEEF);
        assert!(matches!(cmd, IoctlCommand::Unsupported(0xDEAD_BEEF)));
        assert!(!cmd.is_supported());
    }

    #[test]
    fn classify_zero_command() {
        let cmd = IoctlCommand::from_cmd(0);
        assert!(matches!(cmd, IoctlCommand::Unsupported(0)));
        assert!(!cmd.is_supported());
    }

    #[test]
    fn all_known_commands_are_supported() {
        for cmd_num in [
            BLKGETSIZE64,
            BLKFLSBUF,
            BLKROSET,
            BLKROGET,
            BLKSSZGET,
            BLKPBSZGET,
            BLKIOMIN,
            BLKIOOPT,
            BLKALIGNOFF,
        ] {
            let cmd = IoctlCommand::from_cmd(cmd_num);
            assert!(
                cmd.is_supported(),
                "command {cmd_num:08X} should be supported"
            );
        }
    }

    // ── IoctlCommand Display tests ──────────────────────────────────

    #[test]
    fn display_getsize64() {
        let cmd = IoctlCommand::GetSize64;
        assert_eq!(alloc::format!("{cmd}"), "BLKGETSIZE64");
    }

    #[test]
    fn display_flushbuf() {
        let cmd = IoctlCommand::FlushBuf;
        assert_eq!(alloc::format!("{cmd}"), "BLKFLSBUF");
    }

    #[test]
    fn display_blkiomin() {
        let cmd = IoctlCommand::GetIoMin;
        assert_eq!(alloc::format!("{cmd}"), "BLKIOMIN");
    }

    #[test]
    fn display_blkioopt() {
        let cmd = IoctlCommand::GetIoOpt;
        assert_eq!(alloc::format!("{cmd}"), "BLKIOOPT");
    }

    #[test]
    fn display_blkalignoff() {
        let cmd = IoctlCommand::GetAlignmentOffset;
        assert_eq!(alloc::format!("{cmd}"), "BLKALIGNOFF");
    }

    #[test]
    fn display_unsupported() {
        let cmd = IoctlCommand::Unsupported(0x1234_5678);
        let s = alloc::format!("{cmd}");
        assert!(s.contains("Unsupported"));
        assert!(s.contains("12345678"));
    }

    // ── dispatch_ioctl: BLKGETSIZE64 ────────────────────────────────

    #[test]
    fn get_size64_returns_capacity() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKGETSIZE64, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::Capacity(1024 * 512)));
    }

    #[test]
    fn get_size64_null_arg_returns_efault() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKGETSIZE64, 0, &mut ro);
        assert_eq!(result, Err(EFAULT));
    }

    // ── dispatch_ioctl: BLKFLSBUF ───────────────────────────────────

    #[test]
    fn flush_buf_ok() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKFLSBUF, 0, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::Ok));
    }

    // ── dispatch_ioctl: BLKROSET / BLKROGET ────────────────────────

    #[test]
    fn set_read_only_toggle() {
        let mut be = make_backend();
        let mut ro = false;

        // Set read-only (non-zero arg)
        let result = dispatch_ioctl(&mut be, BLKROSET, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::Ok));
        assert!(ro);

        // Verify via BLKROGET
        let result = dispatch_ioctl(&mut be, BLKROGET, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::ReadOnly(true)));
    }

    #[test]
    fn set_read_only_back_to_writable() {
        let mut be = make_backend();
        let mut ro = true;

        // Clear read-only (zero arg)
        let result = dispatch_ioctl(&mut be, BLKROSET, 0, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::Ok));
        assert!(!ro);

        // Verify via BLKROGET
        let result = dispatch_ioctl(&mut be, BLKROGET, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::ReadOnly(false)));
    }

    #[test]
    fn get_read_only_null_arg_returns_efault() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKROGET, 0, &mut ro);
        assert_eq!(result, Err(EFAULT));
    }

    #[test]
    fn set_read_only_null_arg_not_checked_by_dispatch() {
        // BLKROSET with arg=0 means "set writable" in userspace mode.
        // The null-pointer check for the arg pointer is handled by the
        // kernel binding, not by dispatch_ioctl.
        let mut be = make_backend();
        let mut ro = true;
        let result = dispatch_ioctl(&mut be, BLKROSET, 0, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::Ok));
        assert!(!ro);
    }

    // ── dispatch_ioctl: BLKSSZGET / BLKPBSZGET ─────────────────────

    #[test]
    fn get_sector_size() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKSSZGET, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::SectorSize(512)));
    }

    #[test]
    fn get_sector_size_null_arg_returns_efault() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKSSZGET, 0, &mut ro);
        assert_eq!(result, Err(EFAULT));
    }

    #[test]
    fn get_physical_sector_size() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKPBSZGET, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::PhysicalSectorSize(512)));
    }

    #[test]
    fn get_physical_sector_size_null_arg_returns_efault() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKPBSZGET, 0, &mut ro);
        assert_eq!(result, Err(EFAULT));
    }

    // ── dispatch_ioctl: BLKIOMIN ────────────────────────────────────

    #[test]
    fn get_io_min_returns_sector_size() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKIOMIN, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::IoMinSize(512)));
    }

    #[test]
    fn get_io_min_null_arg_returns_efault() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKIOMIN, 0, &mut ro);
        assert_eq!(result, Err(EFAULT));
    }

    // ── dispatch_ioctl: BLKIOOPT ────────────────────────────────────

    #[test]
    fn get_io_opt_returns_sector_size() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKIOOPT, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::IoOptSize(512)));
    }

    #[test]
    fn get_io_opt_null_arg_returns_efault() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKIOOPT, 0, &mut ro);
        assert_eq!(result, Err(EFAULT));
    }

    // ── dispatch_ioctl: BLKALIGNOFF ─────────────────────────────────

    #[test]
    fn get_alignment_offset_returns_zero() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKALIGNOFF, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::AlignmentOffset(0)));
    }

    #[test]
    fn get_alignment_offset_does_not_check_null_arg() {
        // BLKALIGNOFF doesn't need a pointer arg (always returns 0),
        // so a null arg (0) is accepted without EFAULT.
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKALIGNOFF, 0, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::AlignmentOffset(0)));
    }

    // ── dispatch_ioctl: ENOTTY ─────────────────────────────────────

    #[test]
    fn unsupported_command_returns_enotty() {
        let mut be = make_backend();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, 0xDEAD_BEEF, 1, &mut ro);
        assert_eq!(result, Err(ENOTTY));
    }

    // ── dispatch_ioctl: zero-capacity device ──────────────────────

    #[test]
    fn get_size64_zero_capacity() {
        let mut be = BlockExport::new_fixed_capacity(1).unwrap();
        let mut ro = false;
        let result = dispatch_ioctl(&mut be, BLKGETSIZE64, 1, &mut ro);
        assert_eq!(result, Ok(IoctlOutcome::Capacity(512)));
    }

    // ── IoctlOutcome / IoctlCommand trait impls ────────────────────

    #[test]
    fn ioctl_command_debug_and_clone() {
        let cmd = IoctlCommand::GetSize64;
        let dbg = alloc::format!("{cmd:?}");
        assert!(dbg.contains("GetSize64"));

        let cmd2 = cmd; // Copy
        assert_eq!(cmd2, cmd);

        let cmd3 = cmd;
        assert_eq!(cmd3, cmd);
    }

    #[test]
    fn ioctl_outcome_debug_and_clone() {
        let outcome = IoctlOutcome::Capacity(42);
        let dbg = alloc::format!("{outcome:?}");
        assert!(dbg.contains("Capacity"));
        assert!(dbg.contains("42"));

        let outcome2 = outcome; // Copy
        assert_eq!(outcome2, outcome);

        let outcome3 = outcome;
        assert_eq!(outcome3, outcome);
    }

    #[test]
    fn ioctl_command_unsupported_debug() {
        let cmd = IoctlCommand::Unsupported(0xABCD);
        let dbg = alloc::format!("{cmd:?}");
        assert!(dbg.contains("Unsupported"));
        // Derived Debug for u32 prints decimal, not hex.
        assert!(dbg.contains("43981"));
    }
}
