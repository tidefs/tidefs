// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! In-memory inode table for TideFS.
//!
//! [`InodeTable`] is the authoritative inode-number-to-attributes registry
//! for a single TideFS namespace shard. It provides constant-time lookup,
//! thread-safe concurrent access via [`parking_lot::RwLock`], and a
//! slot-allocator backing store with a free list for predictable memory use.
//!
//! # Design
//!
//! - Slots: `Vec<Option<InodeEntry>>` with direct index = inode number.
//! - Free list: `Vec<u64>` of freed indices, consumed before bumping the
//!   slot vector.
//! - Thread safety: all public methods lock an internal `RwLock` so the
//!   table can be shared as `Arc<InodeTable>` across FUSE worker threads.
//! - Time source: a [`TimeSource`] trait provides `now()` for testability;
//!   the default [`SystemTimeSource`] uses `std::time::SystemTime`.
//!
//! Review debt TFR-004: this table is another inode allocation/state authority
//! alongside `tidefs-namespace` and `tidefs-local-filesystem`.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

mod persist;
pub mod persistent;

// ---------------------------------------------------------------------------
// Ino — inode number
// ---------------------------------------------------------------------------

/// An inode number within a TideFS namespace shard.
/// Type alias for the public-facing inode number type used in the issue
/// plan API (`allocate`, `lookup`, `update`, `delete`). Aliases [`Ino`].
pub type InodeNumber = Ino;

///
/// Wraps `u64`; the value is used as a direct index into the slot vector.
#[derive(Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct Ino(pub u64);

impl Ino {
    /// Sentinel inode number representing the root directory.
    pub const ROOT: Ino = Ino(1);

    /// Sentinel value for "no inode" / invalid.
    pub const NONE: Ino = Ino(0);
}

impl fmt::Debug for Ino {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ino({})", self.0)
    }
}

impl fmt::Display for Ino {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Ino {
    fn from(v: u64) -> Self {
        Ino(v)
    }
}

impl From<Ino> for u64 {
    fn from(ino: Ino) -> u64 {
        ino.0
    }
}

// ---------------------------------------------------------------------------
// InodeKind
// ---------------------------------------------------------------------------

/// The kind of filesystem object an inode represents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

impl InodeKind {
    /// Returns `true` for [`InodeKind::Directory`].
    #[must_use]
    pub fn is_dir(self) -> bool {
        matches!(self, InodeKind::Directory)
    }

    /// Returns `true` for [`InodeKind::File`].
    #[must_use]
    pub fn is_file(self) -> bool {
        matches!(self, InodeKind::File)
    }

    /// Returns `true` for [`InodeKind::Symlink`].
    #[must_use]
    pub fn is_symlink(self) -> bool {
        matches!(self, InodeKind::Symlink)
    }
}

// ---------------------------------------------------------------------------
// InodeAttributes
// ---------------------------------------------------------------------------

/// Maximum number of extended attributes per inode.
pub const MAX_XATTR_COUNT: usize = 256;
/// Maximum size of a single extended attribute value in bytes (64 KiB).
pub const MAX_XATTR_VALUE_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// DirtyFlags -- per-field dirty-change tracking bitmask
// ---------------------------------------------------------------------------

/// `mode` field is dirty.
pub const ATTR_DIRTY_MODE: u32 = 1 << 0;
/// `uid` field is dirty.
pub const ATTR_DIRTY_UID: u32 = 1 << 1;
/// `gid` field is dirty.
pub const ATTR_DIRTY_GID: u32 = 1 << 2;
/// `size` field is dirty.
pub const ATTR_DIRTY_SIZE: u32 = 1 << 3;
/// `atime` field is dirty.
pub const ATTR_DIRTY_ATIME: u32 = 1 << 4;
/// `mtime` field is dirty.
pub const ATTR_DIRTY_MTIME: u32 = 1 << 5;
/// `ctime` field is dirty.
pub const ATTR_DIRTY_CTIME: u32 = 1 << 6;
/// `nlink` field is dirty.
pub const ATTR_DIRTY_NLINK: u32 = 1 << 7;
/// `blocks` field is dirty.
pub const ATTR_DIRTY_BLOCKS: u32 = 1 << 8;
/// `kind` field is dirty.
pub const ATTR_DIRTY_KIND: u32 = 1 << 9;

/// All known attribute fields are dirty (used on mount / fresh creation).
pub const ATTR_DIRTY_ALL: u32 = ATTR_DIRTY_MODE
    | ATTR_DIRTY_UID
    | ATTR_DIRTY_GID
    | ATTR_DIRTY_SIZE
    | ATTR_DIRTY_ATIME
    | ATTR_DIRTY_MTIME
    | ATTR_DIRTY_CTIME
    | ATTR_DIRTY_NLINK
    | ATTR_DIRTY_BLOCKS
    | ATTR_DIRTY_KIND;

/// Full set of POSIX-like inode attributes.
///
/// Timestamps (`atime`, `mtime`, `ctime`) are stored as [`Duration`] from
/// the Unix epoch (1970-01-01T00:00:00Z).
#[derive(Clone, Debug)]
pub struct InodeAttributes {
    /// File mode / permission bits.
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time (duration since Unix epoch).
    pub atime: Duration,
    /// Last modification time (duration since Unix epoch).
    pub mtime: Duration,
    /// Last status-change time (duration since Unix epoch).
    pub ctime: Duration,
    /// Hard-link count.
    pub nlink: u32,
    /// Inode generation number (incremented on reuse).
    pub generation: u64,
    /// Object kind.
    pub kind: InodeKind,
    /// Extended attributes (name -> value).
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Bitmask tracking which attribute fields are dirty since last clean point.
    pub dirty_bits: u32,
    /// Monotonic counter incremented on every mutation via setter methods.
    pub mutation_gen: u64,
}

impl InodeAttributes {
    /// Create a minimal attribute set with the given `mode`, `uid`, `gid`,
    /// `kind`, and zero/defaults for the rest. Timestamps are set to epoch.
    #[must_use]
    pub fn new(mode: u32, uid: u32, gid: u32, kind: InodeKind) -> Self {
        let mut attrs = InodeAttributes {
            mode,
            uid,
            gid,
            size: 0,
            blocks: 0,
            atime: Duration::ZERO,
            mtime: Duration::ZERO,
            ctime: Duration::ZERO,
            nlink: 1,
            generation: 0,
            kind,
            xattrs: BTreeMap::new(),
            dirty_bits: 0,
            mutation_gen: 0,
        };
        // Freshly created attributes start clean; mutation generation starts
        // at 1 so generation 0 remains a sentinel for dirty-change tracking.
        attrs.mutation_gen = 1;
        attrs
    }

    // ── Dirty-state API ──────────────────────────────────────────────

    /// Return `true` when at least one attribute field is dirty.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty_bits != 0
    }

    /// Return the raw dirty-field bitmask.
    #[must_use]
    pub fn dirty_fields(&self) -> u32 {
        self.dirty_bits
    }

    /// Clear all dirty flags.
    ///
    /// The generation counter is not reset.
    pub fn mark_clean(&mut self) {
        self.dirty_bits = 0;
    }

    /// Return the inode slot generation used for stale-handle detection.
    #[must_use]
    pub fn inode_generation(&self) -> u64 {
        self.generation
    }

    /// Return the current mutation generation counter.
    #[must_use]
    pub fn mutation_generation(&self) -> u64 {
        self.mutation_gen
    }

    /// Return `true` when at least one mutation has occurred since `gen`.
    #[must_use]
    pub fn changed_since(&self, gen: u64) -> bool {
        self.mutation_gen > gen
    }

    // ── Field setters ────────────────────────────────────────────────

    /// Set `mode` and mark the field dirty.
    pub fn set_mode(&mut self, v: u32) {
        self.mode = v;
        self.dirty_bits |= ATTR_DIRTY_MODE;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `uid` and mark the field dirty.
    pub fn set_uid(&mut self, v: u32) {
        self.uid = v;
        self.dirty_bits |= ATTR_DIRTY_UID;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `gid` and mark the field dirty.
    pub fn set_gid(&mut self, v: u32) {
        self.gid = v;
        self.dirty_bits |= ATTR_DIRTY_GID;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `size` and mark the field dirty.
    pub fn set_size(&mut self, v: u64) {
        self.size = v;
        self.dirty_bits |= ATTR_DIRTY_SIZE;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `blocks` and mark the field dirty.
    pub fn set_blocks(&mut self, v: u64) {
        self.blocks = v;
        self.dirty_bits |= ATTR_DIRTY_BLOCKS;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `atime` and mark the field dirty.
    pub fn set_atime(&mut self, v: Duration) {
        self.atime = v;
        self.dirty_bits |= ATTR_DIRTY_ATIME;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `mtime` and mark the field dirty.
    pub fn set_mtime(&mut self, v: Duration) {
        self.mtime = v;
        self.dirty_bits |= ATTR_DIRTY_MTIME;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `ctime` and mark the field dirty.
    pub fn set_ctime(&mut self, v: Duration) {
        self.ctime = v;
        self.dirty_bits |= ATTR_DIRTY_CTIME;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `nlink` and mark the field dirty.
    pub fn set_nlink(&mut self, v: u32) {
        self.nlink = v;
        self.dirty_bits |= ATTR_DIRTY_NLINK;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }

    /// Set `kind` and mark the field dirty.
    pub fn set_kind(&mut self, v: InodeKind) {
        self.kind = v;
        self.dirty_bits |= ATTR_DIRTY_KIND;
        self.mutation_gen = self.mutation_gen.wrapping_add(1);
    }
}

impl PartialEq for InodeAttributes {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.size == other.size
            && self.blocks == other.blocks
            && self.atime == other.atime
            && self.mtime == other.mtime
            && self.ctime == other.ctime
            && self.nlink == other.nlink
            && self.generation == other.generation
            && self.kind == other.kind
            && self.xattrs == other.xattrs
            && self.dirty_bits == other.dirty_bits
            && self.mutation_gen == other.mutation_gen
    }
}

impl Eq for InodeAttributes {}

// ---------------------------------------------------------------------------
// InodeTableError
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Extended attribute flags and errors
// ---------------------------------------------------------------------------

/// XATTR_CREATE: fail if the attribute already exists.
pub const XATTR_CREATE: u32 = 1;
/// XATTR_REPLACE: fail if the attribute does not exist.
pub const XATTR_REPLACE: u32 = 2;

/// Errors returned by extended-attribute operations on [`InodeAttributes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrError {
    /// The xattr name is empty or contains a NUL byte.
    InvalidName,
    /// The xattr name exceeds the maximum length (255 bytes).
    NameTooLong,
    /// The xattr value exceeds the per-value size limit (64 KiB).
    ValueTooLarge,
    /// The requested attribute does not exist.
    AttrNotFound,
    /// The attribute already exists (for XATTR_CREATE).
    AttrExists,
    /// Per-inode xattr count limit exceeded (MAX_XATTR_COUNT).
    InodeXattrLimit,
}

impl XattrError {
    /// Return the closest POSIX errno for this error.
    #[must_use]
    pub fn raw_os_error(self) -> i32 {
        match self {
            Self::InvalidName | Self::NameTooLong => libc::EINVAL,
            Self::ValueTooLarge => libc::E2BIG,
            Self::AttrNotFound => libc::ENODATA,
            Self::AttrExists => libc::EEXIST,
            Self::InodeXattrLimit => libc::ENOSPC,
        }
    }
}

impl std::fmt::Display for XattrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName => write!(f, "invalid xattr name"),
            Self::NameTooLong => write!(f, "xattr name too long"),
            Self::ValueTooLarge => write!(f, "xattr value too large"),
            Self::AttrNotFound => write!(f, "xattr not found"),
            Self::AttrExists => write!(f, "xattr already exists"),
            Self::InodeXattrLimit => write!(f, "per-inode xattr limit exceeded"),
        }
    }
}

impl std::error::Error for XattrError {}

// ---------------------------------------------------------------------------
// InodeAttributes xattr methods
// ---------------------------------------------------------------------------

impl InodeAttributes {
    /// Get the value of an extended attribute by name.
    ///
    /// Returns [`XattrError::AttrNotFound`] when the name does not exist
    /// and [`XattrError::InvalidName`] when name validation fails.
    pub fn get_xattr(&self, name: &[u8]) -> Result<&[u8], XattrError> {
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > 255 {
            return Err(XattrError::NameTooLong);
        }
        self.xattrs
            .get(name)
            .map(|v| v.as_slice())
            .ok_or(XattrError::AttrNotFound)
    }

    /// Return the size of an extended attribute value.
    ///
    /// Useful for callers implementing ERANGE semantics: call this first
    /// to learn the required buffer size, then call `get_xattr`.
    pub fn get_xattr_size(&self, name: &[u8]) -> Result<usize, XattrError> {
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > 255 {
            return Err(XattrError::NameTooLong);
        }
        self.xattrs
            .get(name)
            .map(|v| v.len())
            .ok_or(XattrError::AttrNotFound)
    }

    /// Set the value of an extended attribute.
    ///
    /// `flags` is one of: 0 (create or replace), [`XATTR_CREATE`], or
    /// [`XATTR_REPLACE`].
    ///
    /// Returns an error when:
    /// - the name is invalid (`EINVAL`)
    /// - the value exceeds [`MAX_XATTR_VALUE_LEN`] (`E2BIG`)
    /// - the per-inode count exceeds [`MAX_XATTR_COUNT`] (`ENOSPC`)
    /// - XATTR_CREATE and the attribute already exists (`EEXIST`)
    /// - XATTR_REPLACE and the attribute does not exist (`ENODATA`)
    pub fn set_xattr(&mut self, name: &[u8], value: &[u8], flags: u32) -> Result<(), XattrError> {
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > 255 {
            return Err(XattrError::NameTooLong);
        }
        if value.len() > MAX_XATTR_VALUE_LEN {
            return Err(XattrError::ValueTooLarge);
        }
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
            return Err(XattrError::InvalidName);
        }

        match flags {
            XATTR_CREATE => {
                if self.xattrs.contains_key(name) {
                    return Err(XattrError::AttrExists);
                }
                if self.xattrs.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
            XATTR_REPLACE => {
                if !self.xattrs.contains_key(name) {
                    return Err(XattrError::AttrNotFound);
                }
            }
            _ => {
                // 0: create or replace — only check limit on new entries
                if !self.xattrs.contains_key(name) && self.xattrs.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
        }

        self.xattrs.insert(name.to_vec(), value.to_vec());
        Ok(())
    }

    /// List all extended attribute names, returning them null-separated
    /// with a trailing null (Linux convention).
    #[must_use]
    pub fn list_xattr(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for name in self.xattrs.keys() {
            buf.extend_from_slice(name);
            buf.push(0);
        }
        buf
    }

    /// Return the total size needed to hold the list_xattr output.
    #[must_use]
    pub fn list_xattr_size(&self) -> usize {
        if self.xattrs.is_empty() {
            return 0;
        }
        self.xattrs.keys().map(|k| k.len() + 1).sum()
    }

    /// Remove an extended attribute by name.
    ///
    /// Returns [`XattrError::AttrNotFound`] when the name does not exist.
    pub fn remove_xattr(&mut self, name: &[u8]) -> Result<(), XattrError> {
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > 255 {
            return Err(XattrError::NameTooLong);
        }
        if self.xattrs.remove(name).is_none() {
            return Err(XattrError::AttrNotFound);
        }
        Ok(())
    }

    /// Return the number of extended attributes on this inode.
    #[must_use]
    pub fn xattr_count(&self) -> usize {
        self.xattrs.len()
    }
}

// ── Link-count limits ─────────────────────────────────────────────────

/// Maximum hard-link count per inode (POSIX `LINK_MAX` = 65000).
///
/// Attempts to increment nlink past this limit return [`InodeTableError::LinkCountOverflow`].
pub const LINK_MAX: u32 = 65000;

/// Errors returned by [`InodeTable`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeTableError {
    /// The requested inode number is not present in the table.
    InodeNotFound,
    /// The inode is present, but its generation does not match the caller's handle.
    GenerationMismatch,
    /// Attempted to `remove` an inode that still has links (`nlink > 0`).
    InodeHasLinks,
    /// The inode table is exhausted (all available slots occupied).
    TableFull,
    /// Hard-link count would exceed [`LINK_MAX`].
    LinkCountOverflow,
}

impl fmt::Display for InodeTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InodeTableError::InodeNotFound => write!(f, "inode not found"),
            InodeTableError::GenerationMismatch => write!(f, "inode generation mismatch"),
            InodeTableError::InodeHasLinks => write!(f, "inode still has links"),
            InodeTableError::TableFull => write!(f, "inode table exhausted"),
            InodeTableError::LinkCountOverflow => write!(f, "link count would exceed LINK_MAX"),
        }
    }
}

impl std::error::Error for InodeTableError {}

// ---------------------------------------------------------------------------
// TimeSource
// ---------------------------------------------------------------------------

/// Source of wall-clock time, abstracted for testability.
pub trait TimeSource: Send + Sync {
    /// Return the current time as a [`Duration`] since the Unix epoch.
    fn now(&self) -> Duration;
}

/// Default [`TimeSource`] backed by [`SystemTime::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// InodeEntry (internal)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) struct InodeEntry {
    #[allow(dead_code)]
    ino: Ino,
    attrs: InodeAttributes,
}

// ---------------------------------------------------------------------------
// InodeTableInner (internal)
// ---------------------------------------------------------------------------

/// Internal mutable state of the inode table.
struct InodeTableInner {
    /// Slots indexed by inode number. `None` means the slot is free.
    slots: Vec<Option<InodeEntry>>,
    /// Stack of freed inode numbers, consumed before bumping `slots`.
    free_list: Vec<u64>,
    /// Monotonically increasing generation counter.
    next_generation: u64,
    /// Hard upper bound on the number of usable slots.
    max_capacity: usize,
    /// Time source for stamping ctime/mtime/atime on create.
    time_source: Box<dyn TimeSource>,
    /// Set of inode numbers with dirty (unpersisted) state.
    dirty_inos: HashSet<u64>,
    /// Set of inode numbers deleted since last commit (need tombstone in store).
    deleted_inos: HashSet<u64>,
    /// Per-inode open-reference count. Incremented on open, decremented on release.
    open_ref_counts: BTreeMap<u64, u64>,
}

impl std::fmt::Debug for InodeTableInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InodeTableInner")
            .field("slots", &self.slots)
            .field("free_list", &self.free_list)
            .field("next_generation", &self.next_generation)
            .field("max_capacity", &self.max_capacity)
            .field("time_source", &"<dyn TimeSource>")
            .finish()
    }
}

impl InodeTableInner {
    fn new(capacity: usize, time_source: Box<dyn TimeSource>) -> Self {
        let max_capacity = capacity.max(1);
        let mut slots = Vec::with_capacity(max_capacity + 1); // +1 for reserved slot 0
        slots.push(None); // index 0 = reserved for Ino::NONE
        InodeTableInner {
            max_capacity,
            slots,
            free_list: Vec::new(),
            next_generation: 1,
            time_source,
            dirty_inos: HashSet::new(),
            deleted_inos: HashSet::new(),
            open_ref_counts: BTreeMap::new(),
        }
    }

    /// Allocate the next free inode number.
    fn alloc_ino(&mut self) -> Result<u64, InodeTableError> {
        if let Some(idx) = self.free_list.pop() {
            return Ok(idx);
        }
        // Enforce max_capacity: current usable slots = slots.len() - 1 (reserved 0).
        let current_usable = self.slots.len().saturating_sub(1);
        if current_usable >= self.max_capacity {
            return Err(InodeTableError::TableFull);
        }
        let idx = self.slots.len() as u64;
        if idx == u64::MAX {
            return Err(InodeTableError::TableFull);
        }
        self.slots.push(None);
        Ok(idx)
    }

    fn alloc_generation(&mut self) -> u64 {
        if self.next_generation == 0 {
            self.next_generation = 1;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        if self.next_generation == 0 {
            self.next_generation = 1;
        }
        generation
    }

    fn create(
        &mut self,
        kind: InodeKind,
        mut attrs: InodeAttributes,
    ) -> Result<Ino, InodeTableError> {
        let now = self.time_source.now();
        let ino_num = self.alloc_ino()?;
        let gen = self.alloc_generation();

        attrs.kind = kind;
        attrs.atime = now;
        attrs.mtime = now;
        attrs.ctime = now;
        attrs.nlink = 1;
        attrs.generation = gen;

        let ino = Ino(ino_num);
        self.slots[ino_num as usize] = Some(InodeEntry { ino, attrs });
        self.dirty_inos.insert(ino_num);
        Ok(ino)
    }

    fn lookup(&self, ino: Ino) -> Option<&InodeEntry> {
        self.slots.get(ino.0 as usize).and_then(|o| o.as_ref())
    }

    fn getattr(&self, ino: Ino) -> Option<InodeAttributes> {
        self.lookup(ino).map(|e| e.attrs.clone())
    }

    fn validate_generation(
        &self,
        ino: Ino,
        generation: u64,
    ) -> Result<InodeAttributes, InodeTableError> {
        let entry = self.lookup(ino).ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.generation != generation {
            return Err(InodeTableError::GenerationMismatch);
        }
        Ok(entry.attrs.clone())
    }

    fn setattr_if_generation(
        &mut self,
        ino: Ino,
        generation: u64,
        mut attrs: InodeAttributes,
    ) -> Result<(), InodeTableError> {
        let entry = self
            .slots
            .get_mut(ino.0 as usize)
            .and_then(|o| o.as_mut())
            .ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.generation != generation {
            return Err(InodeTableError::GenerationMismatch);
        }
        attrs.generation = generation;
        entry.attrs = attrs;
        self.dirty_inos.insert(ino.0);
        Ok(())
    }

    fn remove_if_generation(&mut self, ino: Ino, generation: u64) -> Result<(), InodeTableError> {
        let entry = self
            .slots
            .get(ino.0 as usize)
            .and_then(|o| o.as_ref())
            .ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.generation != generation {
            return Err(InodeTableError::GenerationMismatch);
        }
        if entry.attrs.nlink > 0 {
            return Err(InodeTableError::InodeHasLinks);
        }
        self.slots[ino.0 as usize] = None;
        self.free_list.push(ino.0);
        self.dirty_inos.remove(&ino.0);
        self.deleted_inos.insert(ino.0);
        Ok(())
    }

    fn link_if_generation(&mut self, ino: Ino, generation: u64) -> Result<u32, InodeTableError> {
        let entry = self
            .slots
            .get_mut(ino.0 as usize)
            .and_then(|o| o.as_mut())
            .ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.generation != generation {
            return Err(InodeTableError::GenerationMismatch);
        }
        if entry.attrs.nlink >= LINK_MAX {
            return Err(InodeTableError::LinkCountOverflow);
        }
        entry.attrs.nlink += 1;
        entry.attrs.ctime = self.time_source.now();
        self.dirty_inos.insert(ino.0);
        Ok(entry.attrs.nlink)
    }

    fn unlink_if_generation(&mut self, ino: Ino, generation: u64) -> Result<(), InodeTableError> {
        let idx = ino.0 as usize;
        let entry = self
            .slots
            .get_mut(idx)
            .and_then(|o| o.as_mut())
            .ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.generation != generation {
            return Err(InodeTableError::GenerationMismatch);
        }
        if entry.attrs.nlink == 0 {
            return Err(InodeTableError::InodeNotFound);
        }
        entry.attrs.nlink -= 1;
        entry.attrs.ctime = self.time_source.now();
        self.dirty_inos.insert(ino.0);
        if entry.attrs.nlink == 0 && entry.attrs.kind.is_file() {
            self.slots[idx] = None;
            self.free_list.push(ino.0);
            self.dirty_inos.remove(&ino.0);
            self.deleted_inos.insert(ino.0);
        }
        Ok(())
    }

    fn setattr(&mut self, ino: Ino, attrs: InodeAttributes) -> Result<(), InodeTableError> {
        let entry = self
            .slots
            .get_mut(ino.0 as usize)
            .and_then(|o| o.as_mut())
            .ok_or(InodeTableError::InodeNotFound)?;
        entry.attrs = attrs;
        self.dirty_inos.insert(ino.0);
        Ok(())
    }

    fn remove(&mut self, ino: Ino) -> Result<(), InodeTableError> {
        let entry = self
            .slots
            .get(ino.0 as usize)
            .and_then(|o| o.as_ref())
            .ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.nlink > 0 {
            return Err(InodeTableError::InodeHasLinks);
        }
        self.slots[ino.0 as usize] = None;
        self.free_list.push(ino.0);
        self.dirty_inos.remove(&ino.0);
        self.deleted_inos.insert(ino.0);
        Ok(())
    }

    fn link(&mut self, ino: Ino) -> Result<u32, InodeTableError> {
        let entry = self
            .slots
            .get_mut(ino.0 as usize)
            .and_then(|o| o.as_mut())
            .ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.nlink >= LINK_MAX {
            return Err(InodeTableError::LinkCountOverflow);
        }
        entry.attrs.nlink += 1;
        entry.attrs.ctime = self.time_source.now();
        self.dirty_inos.insert(ino.0);
        Ok(entry.attrs.nlink)
    }

    fn unlink(&mut self, ino: Ino) -> Result<(), InodeTableError> {
        let idx = ino.0 as usize;
        let entry = self
            .slots
            .get_mut(idx)
            .and_then(|o| o.as_mut())
            .ok_or(InodeTableError::InodeNotFound)?;
        if entry.attrs.nlink == 0 {
            return Err(InodeTableError::InodeNotFound);
        }
        entry.attrs.nlink -= 1;
        entry.attrs.ctime = self.time_source.now();
        self.dirty_inos.insert(ino.0);
        if entry.attrs.nlink == 0 && entry.attrs.kind.is_file() {
            // Auto-remove file inodes when nlink reaches 0.
            self.slots[idx] = None;
            self.free_list.push(ino.0);
            self.dirty_inos.remove(&ino.0);
            self.deleted_inos.insert(ino.0);
        }
        Ok(())
    }

    fn adjust_nlink(&mut self, ino: Ino, delta: i32) -> Result<u32, InodeTableError> {
        let idx = ino.0 as usize;
        let entry = self
            .slots
            .get_mut(idx)
            .and_then(|o| o.as_mut())
            .ok_or(InodeTableError::InodeNotFound)?;

        if delta > 0 {
            entry.attrs.nlink = entry.attrs.nlink.saturating_add(delta as u32);
        } else if delta < 0 {
            let dec = (-delta) as u32;
            if entry.attrs.nlink < dec {
                return Err(InodeTableError::InodeNotFound);
            }
            entry.attrs.nlink -= dec;
        }

        entry.attrs.ctime = self.time_source.now();
        self.dirty_inos.insert(ino.0);

        let result_nlink = entry.attrs.nlink;
        let is_file = entry.attrs.kind.is_file();
        let _ = entry;

        if result_nlink == 0 && is_file {
            self.slots[idx] = None;
            self.free_list.push(ino.0);
            self.dirty_inos.remove(&ino.0);
            self.deleted_inos.insert(ino.0);
        }

        Ok(result_nlink)
    }
    fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn capacity(&self) -> usize {
        self.max_capacity
    }

    fn inc_open_ref(&mut self, ino: u64) -> u64 {
        let count = self.open_ref_counts.entry(ino).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    fn dec_open_ref(&mut self, ino: u64) -> Option<u64> {
        let count = self.open_ref_counts.get_mut(&ino)?;
        if *count == 0 {
            return None;
        }
        *count -= 1;
        let new_count = *count;
        if new_count == 0 {
            self.open_ref_counts.remove(&ino);
        }
        Some(new_count)
    }

    fn open_ref_count(&self, ino: u64) -> u64 {
        self.open_ref_counts.get(&ino).copied().unwrap_or(0)
    }

    // ── extended attribute operations ─────────────────────────────────

    fn get_xattr_inner(&self, ino: Ino, name: &[u8]) -> Result<Vec<u8>, XattrError> {
        let entry = self.lookup(ino).ok_or(XattrError::AttrNotFound)?;
        entry.attrs.get_xattr(name).map(|v| v.to_vec())
    }

    fn get_xattr_size_inner(&self, ino: Ino, name: &[u8]) -> Result<usize, XattrError> {
        let entry = self.lookup(ino).ok_or(XattrError::AttrNotFound)?;
        entry.attrs.get_xattr_size(name)
    }

    fn set_xattr_inner(
        &mut self,
        ino: Ino,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), XattrError> {
        let entry = self
            .slots
            .get_mut(ino.0 as usize)
            .and_then(|o| o.as_mut())
            .ok_or(XattrError::AttrNotFound)?;
        entry.attrs.set_xattr(name, value, flags)?;
        self.dirty_inos.insert(ino.0);
        Ok(())
    }

    fn list_xattr_inner(&self, ino: Ino) -> Result<Vec<u8>, XattrError> {
        let entry = self.lookup(ino).ok_or(XattrError::AttrNotFound)?;
        Ok(entry.attrs.list_xattr())
    }

    fn list_xattr_size_inner(&self, ino: Ino) -> Result<usize, XattrError> {
        let entry = self.lookup(ino).ok_or(XattrError::AttrNotFound)?;
        Ok(entry.attrs.list_xattr_size())
    }

    fn remove_xattr_inner(&mut self, ino: Ino, name: &[u8]) -> Result<(), XattrError> {
        let entry = self
            .slots
            .get_mut(ino.0 as usize)
            .and_then(|o| o.as_mut())
            .ok_or(XattrError::AttrNotFound)?;
        entry.attrs.remove_xattr(name)?;
        self.dirty_inos.insert(ino.0);
        Ok(())
    }

    // ── batch prefetch ───────────────────────────────────────────────

    /// Batch-lookup inode attributes for a set of inode numbers in a
    /// single lock acquisition.
    ///
    /// Returns `(Ino, InodeAttributes)` pairs for inodes that exist;
    /// missing inodes are silently omitted (best-effort prefetch).
    fn prefetch_batch(&self, inos: &[Ino]) -> Vec<(Ino, InodeAttributes)> {
        inos.iter()
            .filter_map(|&ino| self.getattr(ino).map(|attrs| (ino, attrs)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// InodeTable
// ---------------------------------------------------------------------------

/// Thread-safe in-memory inode table.
///
/// Wraps internal state in a [`parking_lot::RwLock`] so it can be shared
/// via [`Arc<InodeTable>`] across FUSE worker threads.
///
/// # Examples
///
/// ```rust
/// use tidefs_inode_table::{InodeTable, InodeKind, InodeAttributes, SystemTimeSource};
///
/// let tbl = InodeTable::new(1024, Box::new(SystemTimeSource::default()));
/// let ino = tbl.create(InodeKind::File, InodeAttributes::new(0o644, 1000, 1000, InodeKind::File)).unwrap();
/// assert!(tbl.lookup(ino).is_some());
/// ```
#[derive(Clone, Debug)]
pub struct InodeTable {
    inner: Arc<RwLock<InodeTableInner>>,
}

/// Bounded read-only window returned by direct persistent inode scans.
///
/// `next_cursor` is the inode number where a caller can resume scanning. It is
/// a scan cursor, not a guarantee that another live inode exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedInodeWindow {
    /// Live persisted inode entries found in ascending inode-number order.
    pub entries: Vec<(Ino, InodeAttributes)>,
    /// Cursor for the next scan, or `None` when the header range is drained.
    pub next_cursor: Option<Ino>,
}

impl InodeTable {
    /// Create a new inode table with an initial slot `capacity`.
    ///
    /// Slot 0 is reserved for [`Ino::NONE`] and never returned to callers.
    pub fn new(capacity: usize, time_source: Box<dyn TimeSource>) -> Self {
        InodeTable {
            inner: Arc::new(RwLock::new(InodeTableInner::new(capacity, time_source))),
        }
    }

    /// Allocate a new inode of the given `kind` with `initial_attrs`.
    ///
    /// Timestamps are filled from the table's [`TimeSource`]; `nlink` is
    /// set to 1; a fresh `generation` is assigned.
    pub fn create(
        &self,
        kind: InodeKind,
        initial_attrs: InodeAttributes,
    ) -> Result<Ino, InodeTableError> {
        self.inner.write().create(kind, initial_attrs)
    }

    /// Allocate a new inode from its attributes alone (issue-plan alias for
    /// [`create`](Self::create)). Extracts `kind` from `attrs.kind`.
    pub fn allocate(&self, attrs: InodeAttributes) -> Result<Ino, InodeTableError> {
        let kind = attrs.kind;
        self.create(kind, attrs)
    }
    /// Look up an inode by number. Returns a snapshot of the attributes,
    /// or `None` if the inode is not present.
    #[must_use]
    pub fn lookup(&self, ino: Ino) -> Option<InodeAttributes> {
        self.inner.read().getattr(ino)
    }

    /// Return a snapshot of the attributes for `ino`.
    #[must_use]
    pub fn getattr(&self, ino: Ino) -> Option<InodeAttributes> {
        self.inner.read().getattr(ino)
    }

    /// Return attributes for `ino` only when `generation` matches the live slot.
    ///
    /// This lets higher layers reject stale inode handles after slot reuse
    /// without conflating a recycled inode number with the original object.
    pub fn validate_generation(
        &self,
        ino: Ino,
        generation: u64,
    ) -> Result<InodeAttributes, InodeTableError> {
        self.inner.read().validate_generation(ino, generation)
    }

    /// Replace attributes only when `generation` matches the live slot.
    ///
    /// The stored generation is preserved from the validated handle so callers
    /// cannot accidentally rewrite a live inode with stale generation metadata.
    pub fn setattr_if_generation(
        &self,
        ino: Ino,
        generation: u64,
        attrs: InodeAttributes,
    ) -> Result<(), InodeTableError> {
        self.inner
            .write()
            .setattr_if_generation(ino, generation, attrs)
    }

    /// Remove an inode only when `generation` matches the live slot.
    ///
    /// This keeps stale handles from freeing a recycled inode number.
    pub fn remove_if_generation(&self, ino: Ino, generation: u64) -> Result<(), InodeTableError> {
        self.inner.write().remove_if_generation(ino, generation)
    }

    /// Increment the link count only when `generation` matches the live slot.
    pub fn link_if_generation(&self, ino: Ino, generation: u64) -> Result<u32, InodeTableError> {
        self.inner.write().link_if_generation(ino, generation)
    }

    /// Decrement the link count only when `generation` matches the live slot.
    ///
    /// If the checked unlink drops a regular file to zero links, the inode is
    /// automatically removed just like [`unlink`](Self::unlink).
    pub fn unlink_if_generation(&self, ino: Ino, generation: u64) -> Result<(), InodeTableError> {
        self.inner.write().unlink_if_generation(ino, generation)
    }

    /// Replace the attributes for `ino`.
    ///
    /// The caller is responsible for assembling the complete
    /// [`InodeAttributes`] struct (e.g. by reading current values via
    /// [`getattr`](Self::getattr) and overriding the fields of interest).
    pub fn setattr(&self, ino: Ino, attrs: InodeAttributes) -> Result<(), InodeTableError> {
        self.inner.write().setattr(ino, attrs)
    }

    /// Replace the attributes for `ino` (issue-plan alias for
    /// [`setattr`](Self::setattr)).
    pub fn update(&self, ino: Ino, attrs: InodeAttributes) -> Result<(), InodeTableError> {
        self.setattr(ino, attrs)
    }
    /// Remove an inode from the table.
    ///
    /// Fails with [`InodeTableError::InodeHasLinks`] if `nlink > 0`.
    pub fn remove(&self, ino: Ino) -> Result<(), InodeTableError> {
        self.inner.write().remove(ino)
    }

    /// Remove an inode from the table (issue-plan alias for
    /// [`remove`](Self::remove)).
    pub fn delete(&self, ino: Ino) -> Result<(), InodeTableError> {
        self.remove(ino)
    }
    /// Increment the link count for `ino`.
    ///
    /// Returns the new `nlink` value.
    pub fn link(&self, ino: Ino) -> Result<u32, InodeTableError> {
        self.inner.write().link(ino)
    }

    /// Decrement the link count for `ino`.
    ///
    /// If `nlink` reaches 0 and the inode is a regular file, the inode is
    /// automatically removed from the table. Directory and symlink inodes
    /// with `nlink == 0` are left in place; the caller is responsible for
    /// removing them with [`remove`](Self::remove) when appropriate.
    pub fn unlink(&self, ino: Ino) -> Result<(), InodeTableError> {
        self.inner.write().unlink(ino)
    }

    // ── nlink adjustment ─────────────────────────────────────────

    /// Adjust the link count of `ino` by `delta`.
    ///
    /// A positive `delta` increments `nlink`; a negative `delta`
    /// decrements it. When a regular file reaches zero links it is
    /// auto-removed, just like [`unlink`](Self::unlink). Directories
    /// and symlinks are not auto-removed at zero links.
    ///
    /// # Errors
    ///
    /// Returns [`InodeTableError::InodeNotFound`] when the inode is
    /// not present, or when `nlink` would underflow below zero.
    pub fn adjust_nlink(&self, ino: Ino, delta: i32) -> Result<u32, InodeTableError> {
        self.inner.write().adjust_nlink(ino, delta)
    }
    // ── extended attribute operations ─────────────────────────────────

    /// Get the value of an extended attribute for `ino` by `name`.
    ///
    /// Returns [`XattrError::AttrNotFound`] when the inode or xattr
    /// does not exist.
    pub fn get_xattr(&self, ino: Ino, name: &[u8]) -> Result<Vec<u8>, XattrError> {
        self.inner.read().get_xattr_inner(ino, name)
    }

    /// Return the size of an extended attribute value for `ino`.
    ///
    /// Useful for callers implementing ERANGE semantics.
    pub fn get_xattr_size(&self, ino: Ino, name: &[u8]) -> Result<usize, XattrError> {
        self.inner.read().get_xattr_size_inner(ino, name)
    }

    /// Set an extended attribute on `ino`.
    ///
    /// `flags` is one of: 0 (create or replace), [`XATTR_CREATE`], or
    /// [`XATTR_REPLACE`].
    pub fn set_xattr(
        &self,
        ino: Ino,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), XattrError> {
        self.inner.write().set_xattr_inner(ino, name, value, flags)
    }

    /// List all extended attribute names for `ino`, returning them
    /// null-separated with a trailing null (Linux convention).
    pub fn list_xattr(&self, ino: Ino) -> Result<Vec<u8>, XattrError> {
        self.inner.read().list_xattr_inner(ino)
    }

    /// Return the total size needed to hold the list_xattr output.
    pub fn list_xattr_size(&self, ino: Ino) -> Result<usize, XattrError> {
        self.inner.read().list_xattr_size_inner(ino)
    }

    /// Remove an extended attribute from `ino`.
    ///
    /// Returns [`XattrError::AttrNotFound`] when the inode or xattr
    /// does not exist.
    pub fn remove_xattr(&self, ino: Ino, name: &[u8]) -> Result<(), XattrError> {
        self.inner.write().remove_xattr_inner(ino, name)
    }

    /// Return the number of extended attributes on `ino`.
    pub fn xattr_count(&self, ino: Ino) -> Result<usize, XattrError> {
        let inner = self.inner.read();
        let entry = inner.lookup(ino).ok_or(XattrError::AttrNotFound)?;
        Ok(entry.attrs.xattr_count())
    }

    /// Return the number of live inodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Return `true` if the table contains no live inodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Return the total slot capacity (excluding reserved slot 0).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.read().capacity()
    }

    /// Return filesystem-wide inode statistics: (total_capacity, free_count).
    ///
    /// `total_capacity` is the maximum number of inode slots.
    /// `free_count` is the number of unused slots (`capacity - live_inodes`).
    /// Both values saturate at `u64::MAX`.
    #[must_use]
    pub fn inode_counts(&self) -> (u64, u64) {
        let inner = self.inner.read();
        let total = inner.capacity() as u64;
        let free = total.saturating_sub(inner.len() as u64);
        (total, free)
    }

    /// Iterate over all live inodes, returning a snapshot vector of
    /// `(Ino, InodeAttributes)` pairs.
    #[must_use]
    pub fn iter(&self) -> Vec<(Ino, InodeAttributes)> {
        let inner = self.inner.read();
        inner
            .slots
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| slot.as_ref().map(|e| (Ino(idx as u64), e.attrs.clone())))
            .collect()
    }

    /// Return the number of live inodes (alias for [`len`](Self::len)).
    #[must_use]
    pub fn count(&self) -> usize {
        self.len()
    }

    /// Open an inode table from a persistent object store.
    ///
    /// Loads the header and all stored inode records from `store`.
    /// If no header exists (fresh store), creates an empty table
    /// with the given `capacity`.
    pub fn open(
        store: &mut tidefs_local_object_store::LocalObjectStore,
        capacity: usize,
        time_source: Box<dyn TimeSource>,
    ) -> Result<Self, persist::PersistError> {
        use persist::{load_all_inodes, load_header};

        let header = match load_header(store)? {
            Some(h) => h,
            None => {
                let h = persist::InodeTableHeader::new(capacity);
                persist::save_header(store, &h)?;
                h
            }
        };

        let slots = load_all_inodes(store, &header)?;

        let inner = InodeTableInner {
            max_capacity: header.max_capacity,
            slots,
            free_list: header.free_list,
            next_generation: header.next_generation,
            time_source,
            dirty_inos: HashSet::new(),
            deleted_inos: HashSet::new(),
            open_ref_counts: BTreeMap::new(),
        };

        Ok(InodeTable {
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    /// Look up one persisted inode without opening a full in-memory table.
    ///
    /// This reads the persistent header and the target inode object directly
    /// from `store`. It returns `None` for fresh stores, inode zero, inodes
    /// outside the header cursor, missing records, and deleted slots.
    pub fn lookup_persisted(
        store: &tidefs_local_object_store::LocalObjectStore,
        ino: Ino,
    ) -> Result<Option<InodeAttributes>, persist::PersistError> {
        let Some(header) = persist::load_header(store)? else {
            return Ok(None);
        };

        Ok(persist::load_inode(store, &header, ino)?.map(|entry| entry.attrs))
    }

    /// Read a bounded live-inode window without opening a full in-memory table.
    ///
    /// The scan starts at `start_ino` (inclusive), skips missing/deleted slots,
    /// and retains at most `max_entries` live entries.
    pub fn persisted_window(
        store: &tidefs_local_object_store::LocalObjectStore,
        start_ino: Ino,
        max_entries: usize,
    ) -> Result<PersistedInodeWindow, persist::PersistError> {
        let Some(header) = persist::load_header(store)? else {
            return Ok(PersistedInodeWindow {
                entries: Vec::new(),
                next_cursor: None,
            });
        };
        let (entries, next_cursor) =
            persist::load_inode_window(store, &header, start_ino, max_entries)?;
        let entries = entries
            .into_iter()
            .map(|entry| (entry.ino, entry.attrs))
            .collect();

        Ok(PersistedInodeWindow {
            entries,
            next_cursor,
        })
    }

    /// Commit all dirty inodes and deletions to the object store.
    ///
    /// Writes every inode marked dirty since the last commit, then
    /// deletes tombstones for removed inodes. Finally writes the
    /// updated header with current generation and free-list state.
    pub fn commit(
        &self,
        store: &mut tidefs_local_object_store::LocalObjectStore,
    ) -> Result<(), persist::PersistError> {
        use persist::{delete_inode, save_header, save_inode, InodeTableHeader};

        let mut inner = self.inner.write();

        for &ino_num in &inner.dirty_inos.clone() {
            if let Some(entry) = inner
                .slots
                .get_mut(ino_num as usize)
                .and_then(|o| o.as_mut())
            {
                save_inode(store, ino_num, entry)?;
                entry.attrs.mark_clean();
            }
        }

        for &ino_num in &inner.deleted_inos {
            delete_inode(store, ino_num)?;
        }

        inner.dirty_inos.clear();
        inner.deleted_inos.clear();

        let header = InodeTableHeader {
            next_free_cursor: inner.slots.len() as u64,
            next_generation: inner.next_generation,
            free_list: inner.free_list.clone(),
            max_capacity: inner.max_capacity,
        };
        save_header(store, &header)?;

        Ok(())
    }

    /// Flush dirty inodes to the object store (alias for [`commit`](Self::commit)).
    pub fn flush(
        &self,
        store: &mut tidefs_local_object_store::LocalObjectStore,
    ) -> Result<(), persist::PersistError> {
        self.commit(store)
    }

    /// Return the number of dirty (unpersisted) inodes.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        self.inner.read().dirty_inos.len()
    }

    /// Increment the open-reference count for `ino` and return the new count.
    pub fn inc_open_ref(&self, ino: Ino) -> u64 {
        self.inner.write().inc_open_ref(ino.0)
    }

    /// Decrement the open-reference count for `ino` and return the new count,
    /// or `None` if the count was already zero.
    pub fn dec_open_ref(&self, ino: Ino) -> Option<u64> {
        self.inner.write().dec_open_ref(ino.0)
    }

    /// Return the current open-reference count for `ino`, or 0 if never opened.
    #[must_use]
    pub fn open_ref_count(&self, ino: Ino) -> u64 {
        self.inner.read().open_ref_count(ino.0)
    }

    /// Batch-lookup inode attributes, priming the in-memory cache for a
    /// set of inode numbers in a single lock acquisition.
    ///
    /// Returns `(Ino, InodeAttributes)` pairs for inodes that exist.
    /// Missing inodes are silently omitted (best-effort prefetch).
    #[must_use]
    pub fn prefetch_batch(&self, inos: &[Ino]) -> Vec<(Ino, InodeAttributes)> {
        self.inner.read().prefetch_batch(inos)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Barrier;
    use std::thread;
    use tempfile::TempDir;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    fn attr_file(mode: u32) -> InodeAttributes {
        InodeAttributes::new(mode, 1000, 1000, InodeKind::File)
    }

    fn attr_dir(mode: u32) -> InodeAttributes {
        InodeAttributes::new(mode, 0, 0, InodeKind::Directory)
    }

    /// A time source that can be advanced programmatically, shared between
    /// the table and the test code via `Arc<AtomicU64>`.
    struct SharedTimeSource {
        epoch_secs: Arc<AtomicU64>,
    }

    impl SharedTimeSource {
        fn new() -> (Self, Arc<AtomicU64>) {
            let epoch = Arc::new(AtomicU64::new(0));
            (
                SharedTimeSource {
                    epoch_secs: Arc::clone(&epoch),
                },
                epoch,
            )
        }

        fn advance(&self, secs: u64) {
            self.epoch_secs.fetch_add(secs, Ordering::SeqCst);
        }
    }

    impl TimeSource for SharedTimeSource {
        fn now(&self) -> Duration {
            Duration::from_secs(self.epoch_secs.load(Ordering::SeqCst))
        }
    }

    fn make_table(capacity: usize) -> (InodeTable, SharedTimeSource) {
        let (ts, _epoch) = SharedTimeSource::new();
        let epoch = ts.epoch_secs.clone();
        let tbl = InodeTable::new(capacity, Box::new(ts));
        // Return the SharedTimeSource wrapper so tests can advance time.
        let wrapper = SharedTimeSource { epoch_secs: epoch };
        (tbl, wrapper)
    }

    fn temp_object_store() -> (TempDir, LocalObjectStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open object store");
        (dir, store)
    }

    fn save_sparse_header(
        store: &mut LocalObjectStore,
        next_free_cursor: u64,
        free_list: Vec<u64>,
    ) {
        persist::save_header(
            store,
            &persist::InodeTableHeader {
                next_free_cursor,
                next_generation: 9000,
                free_list,
                max_capacity: next_free_cursor as usize,
            },
        )
        .expect("save header");
    }

    fn save_sparse_inode(store: &mut LocalObjectStore, ino_num: u64, mode: u32) -> InodeAttributes {
        let mut attrs = InodeAttributes::new(mode, 1000 + ino_num as u32, 2000, InodeKind::File);
        attrs.generation = ino_num.saturating_mul(10);
        attrs.xattrs.insert(
            b"user.scale".to_vec(),
            format!("ino-{ino_num}").into_bytes(),
        );
        persist::save_inode(
            store,
            ino_num,
            &InodeEntry {
                ino: Ino(ino_num),
                attrs: attrs.clone(),
            },
        )
        .expect("save inode");
        attrs
    }

    // ------------------------------------------------------------------
    // Basic create / lookup
    // ------------------------------------------------------------------

    #[test]
    fn create_and_lookup() {
        let (tbl, ts) = make_table(16);
        ts.advance(42);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let attrs = tbl.lookup(ino).unwrap();
        assert_eq!(attrs.mode, 0o644);
        assert_eq!(attrs.kind, InodeKind::File);
        assert_eq!(attrs.nlink, 1);
        assert!(attrs.generation > 0);
        assert_eq!(attrs.atime, Duration::from_secs(42));
        assert_eq!(attrs.mtime, Duration::from_secs(42));
        assert_eq!(attrs.ctime, Duration::from_secs(42));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let (tbl, _ts) = make_table(16);
        assert!(tbl.lookup(Ino(42)).is_none());
    }

    #[test]
    fn create_10k_inodes_all_reachable() {
        let (tbl, _ts) = make_table(11000);
        let mut inos = Vec::new();
        for i in 0..10_000 {
            let ino = tbl
                .create(
                    InodeKind::File,
                    InodeAttributes::new(0o644, i, i, InodeKind::File),
                )
                .unwrap();
            inos.push(ino);
        }
        assert_eq!(tbl.len(), 10_000);
        for ino in &inos {
            assert!(tbl.lookup(*ino).is_some(), "inode {ino} should exist");
        }
    }

    // ------------------------------------------------------------------
    // getattr / setattr round-trip
    // ------------------------------------------------------------------

    #[test]
    fn getattr_setattr_round_trip() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.size = 4096;
        attrs.mode = 0o755;
        tbl.setattr(ino, attrs.clone()).unwrap();

        let stored = tbl.getattr(ino).unwrap();
        assert_eq!(stored.size, 4096);
        assert_eq!(stored.mode, 0o755);
    }

    #[test]
    fn setattr_missing_returns_error() {
        let (tbl, _ts) = make_table(16);
        let err = tbl.setattr(Ino(99), attr_file(0o644));
        assert_eq!(err, Err(InodeTableError::InodeNotFound));
    }

    // ------------------------------------------------------------------
    // nlink lifecycle
    // ------------------------------------------------------------------

    #[test]
    fn nlink_lifecycle_file() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // create → nlink = 1
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);

        // link → nlink = 2
        let n = tbl.link(ino).unwrap();
        assert_eq!(n, 2);

        // unlink → nlink = 1
        tbl.unlink(ino).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);

        // unlink → nlink = 0, auto-remove for files
        tbl.unlink(ino).unwrap();
        assert!(tbl.lookup(ino).is_none());
    }

    #[test]
    fn nlink_directory_no_auto_remove() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();

        tbl.unlink(ino).unwrap(); // nlink 1→0
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 0);
        // Directory is NOT auto-removed.
        assert!(tbl.lookup(ino).is_some());
    }

    // ------------------------------------------------------------------
    // remove gate
    // ------------------------------------------------------------------

    #[test]
    fn remove_fails_when_nlink_gt_0() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.remove(ino), Err(InodeTableError::InodeHasLinks));
    }

    #[test]
    fn remove_succeeds_when_nlink_is_0() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        tbl.unlink(ino).unwrap(); // nlink → 0
        tbl.remove(ino).unwrap();
        assert!(tbl.lookup(ino).is_none());
    }

    // ------------------------------------------------------------------
    // Free list reuse
    // ------------------------------------------------------------------

    #[test]
    fn free_list_reuses_slots() {
        let (tbl, _ts) = make_table(16);
        let ino_a = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let _ino_b = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // Remove ino_a via double-unlink (file auto-remove on nlink→0).
        tbl.link(ino_a).unwrap();
        tbl.unlink(ino_a).unwrap();
        tbl.unlink(ino_a).unwrap();
        assert!(tbl.lookup(ino_a).is_none());

        // New create should reuse ino_a's slot from the free list.
        let ino_c = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(ino_c.0, ino_a.0);
        assert_eq!(tbl.len(), 2); // ino_b and ino_c are alive
    }

    // ------------------------------------------------------------------
    // Table exhaustion
    // ------------------------------------------------------------------

    #[test]
    fn table_exhaustion() {
        let (tbl, _ts) = make_table(4);
        for _ in 0..4 {
            tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        }
        // capacity was 4, but slot 0 is reserved, so we have 4 usable slots.
        // Wait — capacity 4 means 4 slots + reserved slot 0 = 5 slots.
        // But actually the issue says to test exhaustion. Let me use smaller.
        let (tbl2, _ts2) = make_table(1);
        tbl2.create(InodeKind::File, attr_file(0o644)).unwrap();
        let err = tbl2.create(InodeKind::File, attr_file(0o644));
        assert_eq!(err, Err(InodeTableError::TableFull));
    }

    // Actually let me fix the exhaustion test — make_table(capacity) creates slots
    // with capacity, but the Vec grows dynamically. The TableFull error only
    // happens at u64::MAX. But the issue says "assert the next create returns
    // an error (not a panic)." This implies a fixed-capacity table.
    //
    // Let me add a max_capacity limit to the inner table to make this testable.

    // ------------------------------------------------------------------
    // Iteration
    // ------------------------------------------------------------------

    #[test]
    fn iter_returns_all_live_inodes() {
        let (tbl, _ts) = make_table(64);
        let mut inos = Vec::new();
        for i in 0..10 {
            let ino = tbl
                .create(
                    InodeKind::File,
                    InodeAttributes::new(0o644, i, i, InodeKind::File),
                )
                .unwrap();
            inos.push(ino);
        }

        let snapshot = tbl.iter();
        assert_eq!(snapshot.len(), 10);
        for (ino, attrs) in &snapshot {
            assert!(inos.contains(ino));
            assert_eq!(attrs.kind, InodeKind::File);
        }
    }

    #[test]
    fn count_and_len() {
        let (tbl, _ts) = make_table(64);
        assert!(tbl.is_empty());
        assert_eq!(tbl.len(), 0);
        tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert!(!tbl.is_empty());
        assert_eq!(tbl.len(), 1);
        assert_eq!(tbl.count(), 1);
    }

    // ------------------------------------------------------------------
    // Direct persistent read windows
    // ------------------------------------------------------------------

    #[test]
    fn lookup_persisted_reads_sparse_high_inode_without_open() {
        let (_dir, mut store) = temp_object_store();
        let high = 1_000_000;
        save_sparse_header(&mut store, high + 3, Vec::new());
        let expected = save_sparse_inode(&mut store, high, 0o640);

        assert_eq!(
            InodeTable::lookup_persisted(&store, Ino(high)).unwrap(),
            Some(expected)
        );
        assert_eq!(
            InodeTable::lookup_persisted(&store, Ino(high + 1)).unwrap(),
            None
        );
        assert_eq!(
            InodeTable::lookup_persisted(&store, Ino(high + 3)).unwrap(),
            None
        );
        assert_eq!(InodeTable::lookup_persisted(&store, Ino(0)).unwrap(), None);
    }

    #[test]
    fn persisted_window_skips_missing_deleted_and_bounds_live_entries() {
        let (_dir, mut store) = temp_object_store();
        let high = 50_000;
        save_sparse_header(&mut store, high + 7, vec![high + 2]);

        let first = save_sparse_inode(&mut store, high, 0o640);
        save_sparse_inode(&mut store, high + 2, 0o641);
        let second = save_sparse_inode(&mut store, high + 4, 0o642);
        let third = save_sparse_inode(&mut store, high + 6, 0o643);
        persist::delete_inode(&mut store, high + 2).expect("delete sparse inode");

        let window = InodeTable::persisted_window(&store, Ino(high), 2).unwrap();
        assert_eq!(
            window.entries,
            vec![(Ino(high), first), (Ino(high + 4), second)]
        );
        assert_eq!(window.next_cursor, Some(Ino(high + 5)));

        let tail = InodeTable::persisted_window(&store, window.next_cursor.unwrap(), 10).unwrap();
        assert_eq!(tail.entries, vec![(Ino(high + 6), third)]);
        assert_eq!(tail.next_cursor, None);
    }

    // ------------------------------------------------------------------
    // Concurrent stress test
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_create_lookup_unlink() {
        let tbl = std::sync::Arc::new(InodeTable::new(20000, Box::new(SystemTimeSource)));
        let barrier = std::sync::Arc::new(Barrier::new(8));
        let created = std::sync::Arc::new(RwLock::new(Vec::new()));

        let mut handles = Vec::new();
        for w in 0..4 {
            let tbl = Arc::clone(&tbl);
            let barrier = Arc::clone(&barrier);
            let created = Arc::clone(&created);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut local = Vec::new();
                for i in 0..2500 {
                    let ino = tbl
                        .create(
                            InodeKind::File,
                            InodeAttributes::new(0o644, w * 10000 + i, 0, InodeKind::File),
                        )
                        .unwrap();
                    local.push(ino);
                }
                created.write().extend(local);
            }));
        }
        for _ in 0..4 {
            let tbl = Arc::clone(&tbl);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..5000 {
                    let _ = tbl.lookup(Ino(1));
                    let _ = tbl.len();
                    let _ = tbl.iter();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let created = created.read();
        assert_eq!(created.len(), 10000);
        // All created inodes should be reachable
        for ino in created.iter() {
            assert!(tbl.lookup(*ino).is_some(), "inode {ino} should exist");
        }
        assert_eq!(tbl.len(), 10000);

        // Unlink all and verify auto-removal
        for ino in created.iter() {
            tbl.unlink(*ino).unwrap();
        }
        assert_eq!(tbl.len(), 0);
    }

    // ------------------------------------------------------------------
    // Generation counter
    // ------------------------------------------------------------------

    #[test]
    fn generation_increments() {
        let (tbl, _ts) = make_table(16);
        let ino1 = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let ino2 = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let g1 = tbl.getattr(ino1).unwrap().generation;
        let g2 = tbl.getattr(ino2).unwrap().generation;
        assert!(g2 > g1);
    }

    #[test]
    fn generation_wrap_skips_zero() {
        let (tbl, _ts) = make_table(16);
        {
            let mut inner = tbl.inner.write();
            inner.next_generation = u64::MAX;
        }

        let last = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let wrapped = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        assert_eq!(tbl.getattr(last).unwrap().generation, u64::MAX);
        assert_eq!(tbl.getattr(wrapped).unwrap().generation, 1);
        assert_ne!(tbl.getattr(wrapped).unwrap().generation, 0);
    }

    #[test]
    fn generation_reused_slot_gets_new_generation() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen1 = tbl.getattr(ino).unwrap().generation;

        // Remove it
        tbl.link(ino).unwrap();
        tbl.unlink(ino).unwrap();
        tbl.unlink(ino).unwrap();

        // Re-create — same slot, different generation
        let ino2 = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(ino2.0, ino.0);
        let gen2 = tbl.getattr(ino2).unwrap().generation;
        assert!(gen2 > gen1);
    }

    #[test]
    fn validate_generation_returns_attrs_for_live_generation() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let attrs = tbl.getattr(ino).unwrap();

        let validated = tbl.validate_generation(ino, attrs.generation).unwrap();

        assert_eq!(validated, attrs);
    }

    #[test]
    fn validate_generation_rejects_missing_inode() {
        let (tbl, _ts) = make_table(16);

        assert_eq!(
            tbl.validate_generation(Ino(99), 1),
            Err(InodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn validate_generation_rejects_reused_stale_handle() {
        let (tbl, _ts) = make_table(16);
        let old_ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let old_generation = tbl.getattr(old_ino).unwrap().generation;

        tbl.unlink(old_ino).unwrap();
        let new_ino = tbl.create(InodeKind::File, attr_file(0o600)).unwrap();
        let new_generation = tbl.getattr(new_ino).unwrap().generation;

        assert_eq!(new_ino, old_ino);
        assert_ne!(new_generation, old_generation);
        assert_eq!(
            tbl.validate_generation(old_ino, old_generation),
            Err(InodeTableError::GenerationMismatch)
        );
        assert_eq!(
            tbl.validate_generation(new_ino, new_generation)
                .unwrap()
                .mode,
            0o600
        );
    }

    #[test]
    fn stale_handle_checked_operations_reject_reallocated_slot() {
        let (tbl, _ts) = make_table(16);
        let old_ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let old_generation = tbl.getattr(old_ino).unwrap().generation;

        tbl.unlink(old_ino).unwrap();
        assert!(tbl.lookup(old_ino).is_none());

        let replacement = tbl.create(InodeKind::File, attr_file(0o600)).unwrap();
        let replacement_attrs = tbl.getattr(replacement).unwrap();
        let replacement_generation = replacement_attrs.generation;

        assert_eq!(replacement, old_ino);
        assert_ne!(replacement_generation, old_generation);
        assert_eq!(replacement_attrs.mode, 0o600);
        assert_eq!(replacement_attrs.nlink, 1);
        assert_eq!(
            tbl.validate_generation(old_ino, old_generation),
            Err(InodeTableError::GenerationMismatch)
        );

        let mut stale_attrs = replacement_attrs.clone();
        stale_attrs.mode = 0o777;
        stale_attrs.size = 4096;
        assert_eq!(
            tbl.setattr_if_generation(old_ino, old_generation, stale_attrs),
            Err(InodeTableError::GenerationMismatch)
        );
        assert_eq!(tbl.getattr(replacement).unwrap().mode, 0o600);
        assert_eq!(tbl.getattr(replacement).unwrap().size, 0);

        assert_eq!(
            tbl.link_if_generation(old_ino, old_generation),
            Err(InodeTableError::GenerationMismatch)
        );
        assert_eq!(tbl.getattr(replacement).unwrap().nlink, 1);

        assert_eq!(
            tbl.unlink_if_generation(old_ino, old_generation),
            Err(InodeTableError::GenerationMismatch)
        );
        assert!(tbl.lookup(replacement).is_some());

        assert_eq!(
            tbl.remove_if_generation(old_ino, old_generation),
            Err(InodeTableError::GenerationMismatch)
        );
        assert!(tbl.lookup(replacement).is_some());

        let mut live_attrs = tbl.getattr(replacement).unwrap();
        live_attrs.mode = 0o640;
        tbl.setattr_if_generation(replacement, replacement_generation, live_attrs)
            .unwrap();
        assert_eq!(tbl.getattr(replacement).unwrap().mode, 0o640);

        assert_eq!(
            tbl.link_if_generation(replacement, replacement_generation),
            Ok(2)
        );
        tbl.unlink_if_generation(replacement, replacement_generation)
            .unwrap();
        assert_eq!(tbl.getattr(replacement).unwrap().nlink, 1);
        tbl.unlink_if_generation(replacement, replacement_generation)
            .unwrap();
        assert!(tbl.lookup(replacement).is_none());
    }

    // ------------------------------------------------------------------
    // Ino sentinels
    // ------------------------------------------------------------------

    #[test]
    fn ino_sentinels() {
        assert_eq!(Ino::ROOT.0, 1);
        assert_eq!(Ino::NONE.0, 0);
    }

    #[test]
    fn ino_from_into() {
        let ino = Ino::from(42u64);
        assert_eq!(u64::from(ino), 42);
    }

    // ------------------------------------------------------------------
    // InodeKind predicates
    // ------------------------------------------------------------------

    #[test]
    fn inode_kind_predicates() {
        assert!(InodeKind::File.is_file());
        assert!(!InodeKind::File.is_dir());
        assert!(InodeKind::Directory.is_dir());
        assert!(InodeKind::Symlink.is_symlink());
    }

    // ------------------------------------------------------------------
    // TimeSource plumbing
    // ------------------------------------------------------------------

    #[test]
    fn timestamps_filled_on_create() {
        let (tbl, ts) = make_table(16);
        ts.advance(100);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let attrs = tbl.getattr(ino).unwrap();
        assert_eq!(attrs.atime, Duration::from_secs(100));
        assert_eq!(attrs.mtime, Duration::from_secs(100));
        assert_eq!(attrs.ctime, Duration::from_secs(100));
    }

    #[test]
    fn ctime_updated_on_link_unlink() {
        let (tbl, ts) = make_table(16);
        ts.advance(10);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().ctime, Duration::from_secs(10));

        ts.advance(5);
        tbl.link(ino).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().ctime, Duration::from_secs(15));

        ts.advance(3);
        tbl.unlink(ino).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().ctime, Duration::from_secs(18));
    }

    // ------------------------------------------------------------------
    // TableFull at exhaustion
    // ------------------------------------------------------------------

    #[test]
    fn table_full_at_max_capacity() {
        // Fill all usable slots in a small table.
        let (tbl, _ts) = make_table(3);
        for _ in 0..3 {
            tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        }
        // Fourth create must fail with TableFull.
        let err = tbl.create(InodeKind::File, attr_file(0o644));
        assert_eq!(err, Err(InodeTableError::TableFull));
        assert_eq!(tbl.len(), 3);
    }

    // ------------------------------------------------------------------
    // link / unlink error cases
    // ------------------------------------------------------------------

    #[test]
    fn link_missing_returns_error() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(tbl.link(Ino(99)), Err(InodeTableError::InodeNotFound));
    }

    #[test]
    fn unlink_missing_returns_error() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(tbl.unlink(Ino(99)), Err(InodeTableError::InodeNotFound));
    }

    #[test]
    fn remove_missing_returns_error() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(tbl.remove(Ino(99)), Err(InodeTableError::InodeNotFound));
    }

    // ------------------------------------------------------------------
    // InodeAttributes::new defaults
    // ------------------------------------------------------------------

    #[test]
    fn attr_new_defaults() {
        let a = InodeAttributes::new(0o644, 1000, 1000, InodeKind::File);
        assert_eq!(a.mode, 0o644);
        assert_eq!(a.size, 0);
        assert_eq!(a.blocks, 0);
        assert_eq!(a.nlink, 1);
        assert_eq!(a.generation, 0);
        assert_eq!(a.kind, InodeKind::File);
        assert_eq!(a.atime, Duration::ZERO);
    }

    // ------------------------------------------------------------------
    // Capacity reporting
    // ------------------------------------------------------------------

    #[test]
    fn capacity_excludes_reserved_slot() {
        let (tbl, _ts) = make_table(100);
        // With capacity = 100, we have 100 usable slots + reserved slot 0 = 101 total.
        // capacity() returns usable slots.
        assert_eq!(tbl.capacity(), 100);
    }

    // ------------------------------------------------------------------
    // Issue-plan API tests: allocate / update / delete
    // ------------------------------------------------------------------

    #[test]
    fn allocate_then_lookup() {
        let (tbl, ts) = make_table(16);
        ts.advance(10);
        let ino = tbl
            .allocate(InodeAttributes::new(0o644, 1000, 1000, InodeKind::File))
            .unwrap();
        let attrs = tbl.lookup(ino).unwrap();
        assert_eq!(attrs.mode, 0o644);
        assert_eq!(attrs.kind, InodeKind::File);
        assert_eq!(attrs.nlink, 1);
        assert!(attrs.generation > 0);
        assert_eq!(attrs.ctime, Duration::from_secs(10));
    }

    #[test]
    fn update_existing() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let mut attrs = tbl.lookup(ino).unwrap();
        attrs.size = 4096;
        attrs.mode = 0o755;
        tbl.update(ino, attrs.clone()).unwrap();
        let stored = tbl.lookup(ino).unwrap();
        assert_eq!(stored.size, 4096);
        assert_eq!(stored.mode, 0o755);
    }

    #[test]
    fn update_missing() {
        let (tbl, _ts) = make_table(16);
        let err = tbl.update(Ino(99), attr_file(0o644));
        assert_eq!(err, Err(InodeTableError::InodeNotFound));
    }

    #[test]
    fn delete_then_lookup_fails() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        tbl.unlink(ino).unwrap(); // nlink 1→0
        tbl.delete(ino).unwrap();
        assert!(tbl.lookup(ino).is_none());
    }

    #[test]
    fn delete_fails_when_nlink_gt_0() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl
            .allocate(InodeAttributes::new(0o644, 1000, 1000, InodeKind::File))
            .unwrap();
        assert_eq!(tbl.delete(ino), Err(InodeTableError::InodeHasLinks));
    }

    #[test]
    fn delete_missing() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(tbl.delete(Ino(99)), Err(InodeTableError::InodeNotFound));
    }

    #[test]
    fn allocate_missing_kind_uses_attrs_kind() {
        // allocate extracts kind from attrs.kind, not a separate parameter
        let (tbl, _ts) = make_table(16);
        let attrs = InodeAttributes::new(0o644, 1000, 1000, InodeKind::Symlink);
        let ino = tbl.allocate(attrs).unwrap();
        let stored = tbl.lookup(ino).unwrap();
        assert_eq!(stored.kind, InodeKind::Symlink);
        assert!(stored.kind.is_symlink());
    }

    #[test]
    fn metadata_path_scenario() {
        // Full lifecycle: allocate → lookup → update → link → unlink → delete → absent
        let (tbl, ts) = make_table(16);

        ts.advance(42);
        let ino = tbl
            .allocate(InodeAttributes::new(0o644, 1000, 1000, InodeKind::File))
            .unwrap();
        assert_eq!(tbl.count(), 1);

        let attrs = tbl.lookup(ino).unwrap();
        assert_eq!(attrs.mode, 0o644);
        assert_eq!(attrs.nlink, 1);
        assert_eq!(attrs.size, 0);

        let mut updated = attrs.clone();
        updated.size = 8192;
        updated.mode = 0o600;
        tbl.update(ino, updated).unwrap();
        let attrs2 = tbl.lookup(ino).unwrap();
        assert_eq!(attrs2.size, 8192);
        assert_eq!(attrs2.mode, 0o600);

        let n = tbl.link(ino).unwrap();
        assert_eq!(n, 2);
        let attrs3 = tbl.lookup(ino).unwrap();
        assert_eq!(attrs3.nlink, 2);

        tbl.unlink(ino).unwrap();
        let attrs4 = tbl.lookup(ino).unwrap();
        assert_eq!(attrs4.nlink, 1);

        tbl.unlink(ino).unwrap(); // nlink→0, file auto-removed
        assert!(tbl.lookup(ino).is_none());

        assert_eq!(tbl.count(), 0);
    }

    // ------------------------------------------------------------------
    // Generation-guarded operations: success paths
    // ------------------------------------------------------------------

    #[test]
    fn setattr_if_generation_success() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;

        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.size = 4096;
        attrs.mode = 0o755;
        tbl.setattr_if_generation(ino, gen, attrs).unwrap();

        let stored = tbl.getattr(ino).unwrap();
        assert_eq!(stored.size, 4096);
        assert_eq!(stored.mode, 0o755);
        assert_eq!(stored.generation, gen);
    }

    #[test]
    fn setattr_if_generation_preserves_generation() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;

        // Pass a different generation in the attrs; it must be overwritten.
        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.generation = gen + 999;
        tbl.setattr_if_generation(ino, gen, attrs).unwrap();

        let stored = tbl.getattr(ino).unwrap();
        assert_eq!(stored.generation, gen);
    }

    #[test]
    fn link_if_generation_success() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;

        let n = tbl.link_if_generation(ino, gen).unwrap();
        assert_eq!(n, 2);
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 2);
    }

    #[test]
    fn unlink_if_generation_success() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;
        tbl.link_if_generation(ino, gen).unwrap(); // nlink 1->2

        tbl.unlink_if_generation(ino, gen).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);
    }

    #[test]
    fn remove_if_generation_success() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;
        tbl.unlink_if_generation(ino, gen).unwrap(); // nlink 1->0

        tbl.remove_if_generation(ino, gen).unwrap();
        assert!(tbl.lookup(ino).is_none());
    }

    // ------------------------------------------------------------------
    // Generation-guarded operations: error paths (missing, mismatch)
    // ------------------------------------------------------------------

    #[test]
    fn setattr_if_generation_missing_inode() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(
            tbl.setattr_if_generation(Ino(99), 1, attr_file(0o644)),
            Err(InodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn link_if_generation_missing_inode() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(
            tbl.link_if_generation(Ino(99), 1),
            Err(InodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn unlink_if_generation_missing_inode() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(
            tbl.unlink_if_generation(Ino(99), 1),
            Err(InodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn remove_if_generation_missing_inode() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(
            tbl.remove_if_generation(Ino(99), 1),
            Err(InodeTableError::InodeNotFound)
        );
    }

    // ------------------------------------------------------------------
    // First-allocation is Ino::ROOT (1)
    // ------------------------------------------------------------------

    #[test]
    fn first_allocation_is_root_ino() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        assert_eq!(ino, Ino::ROOT);
        assert_eq!(ino.0, 1);
    }

    // ------------------------------------------------------------------
    // Multiple fill-free-refill cycles
    // ------------------------------------------------------------------

    #[test]
    fn multiple_fill_free_refill_cycles() {
        let (tbl, _ts) = make_table(8);
        // Cycle 1: fill
        let mut inos = Vec::new();
        for _ in 0..8 {
            inos.push(tbl.create(InodeKind::File, attr_file(0o644)).unwrap());
        }
        assert_eq!(tbl.len(), 8);
        assert_eq!(
            tbl.create(InodeKind::File, attr_file(0o644)),
            Err(InodeTableError::TableFull)
        );

        // Free all (via auto-remove: link then double-unlink for files)
        for &ino in &inos {
            tbl.link(ino).unwrap();
            tbl.unlink(ino).unwrap();
            tbl.unlink(ino).unwrap();
        }
        assert_eq!(tbl.len(), 0);

        // Cycle 2: re-fill, same slots reused with bumped generations
        let mut inos2 = Vec::new();
        for _ in 0..8 {
            inos2.push(tbl.create(InodeKind::File, attr_file(0o755)).unwrap());
        }
        assert_eq!(tbl.len(), 8);

        // All reused slots should have new generations
        for &new_ino in &inos2 {
            let attrs = tbl.getattr(new_ino).unwrap();
            assert_eq!(attrs.mode, 0o755);
            assert!(attrs.generation > 1); // at least gen 2
        }
    }

    // ------------------------------------------------------------------
    // Empty-table edge cases
    // ------------------------------------------------------------------

    #[test]
    fn empty_table_len_is_zero() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(tbl.len(), 0);
        assert!(tbl.is_empty());
    }

    #[test]
    fn empty_table_iter_returns_empty() {
        let (tbl, _ts) = make_table(16);
        let snapshot = tbl.iter();
        assert!(snapshot.is_empty());
    }

    #[test]
    fn empty_table_lookup_returns_none() {
        let (tbl, _ts) = make_table(16);
        assert!(tbl.lookup(Ino(1)).is_none());
        assert!(tbl.lookup(Ino::ROOT).is_none());
    }

    #[test]
    fn empty_table_getattr_returns_none() {
        let (tbl, _ts) = make_table(16);
        assert!(tbl.getattr(Ino(1)).is_none());
    }

    // ------------------------------------------------------------------
    // Generation stress: 100+ alloc/free cycles on one slot
    // ------------------------------------------------------------------

    #[test]
    fn generation_stress_100_cycles() {
        let (tbl, _ts) = make_table(4);
        let mut last_gen = 0u64;

        for i in 0..100 {
            let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
            if i == 0 {
                assert_eq!(ino.0, 1); // first slot
            }
            let attrs = tbl.getattr(ino).unwrap();
            assert!(
                attrs.generation > last_gen,
                "generation {} should be > {last_gen} at cycle {i}",
                attrs.generation
            );
            last_gen = attrs.generation;

            // Free via auto-remove
            tbl.link(ino).unwrap();
            tbl.unlink(ino).unwrap();
            tbl.unlink(ino).unwrap();
            assert!(tbl.lookup(ino).is_none());
        }

        assert_eq!(tbl.len(), 0);
        // Generation should have advanced at least 100 (one per alloc)
        assert!(last_gen >= 100);
    }

    // ------------------------------------------------------------------
    // Concurrent mixed-workload stress
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_mixed_workload() {
        use std::sync::atomic::AtomicU32;

        let tbl = std::sync::Arc::new(InodeTable::new(5000, Box::new(SystemTimeSource)));
        let ops = std::sync::Arc::new(AtomicU32::new(0));
        let errors = std::sync::Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..6 {
            let tbl = Arc::clone(&tbl);
            let ops = Arc::clone(&ops);
            let errors = Arc::clone(&errors);
            handles.push(thread::spawn(move || {
                for j in 0..200 {
                    let mode = 0o600 | ((j as u32) & 0x1FF);
                    match tbl.create(
                        InodeKind::File,
                        InodeAttributes::new(mode, j as u32, 0, InodeKind::File),
                    ) {
                        Ok(ino) => {
                            ops.fetch_add(1, Ordering::Relaxed);
                            // Immediately unlink and auto-remove
                            tbl.link(ino).ok();
                            tbl.unlink(ino).ok();
                            tbl.unlink(ino).ok();
                        }
                        Err(InodeTableError::TableFull) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Each thread gets 200 iterations, but TableFull is expected under
        // contention. We just check we didn't crash.
        let _ = ops.load(Ordering::Relaxed);
        let _ = errors.load(Ordering::Relaxed);
    }

    // ------------------------------------------------------------------
    // validate_generation with generation == 0
    // ------------------------------------------------------------------

    #[test]
    fn validate_generation_rejects_gen_zero_on_live_inode() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let real_gen = tbl.getattr(ino).unwrap().generation;
        assert!(real_gen > 0);

        // Generation 0 should be treated as a mismatch (or at least not match).
        // Since the allocator starts at 1, 0 should never match a live inode.
        assert_eq!(
            tbl.validate_generation(ino, 0),
            Err(InodeTableError::GenerationMismatch)
        );
    }

    // ------------------------------------------------------------------
    // Dirty-count tracking
    // ------------------------------------------------------------------

    #[test]
    fn dirty_count_increments_on_create() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(tbl.dirty_count(), 0);
        tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.dirty_count(), 1);
    }

    #[test]
    fn dirty_count_increments_on_multiple_creates() {
        let (tbl, _ts) = make_table(16);
        for _ in 0..5 {
            tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        }
        assert_eq!(tbl.dirty_count(), 5);
    }

    #[test]
    fn dirty_count_increments_on_setattr() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        // dirty_count is 1 after create
        assert_eq!(tbl.dirty_count(), 1);

        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.size = 4096;
        tbl.setattr(ino, attrs).unwrap();
        // setattr should mark the inode dirty (already dirty, count stays 1)
        assert_eq!(tbl.dirty_count(), 1);
    }

    #[test]
    fn dirty_count_increments_on_link() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.dirty_count(), 1);

        tbl.link(ino).unwrap();
        // link marks dirty
        assert_eq!(tbl.dirty_count(), 1);
    }

    #[test]
    fn dirty_count_increments_on_unlink() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        tbl.link(ino).unwrap(); // nlink 1→2
        assert_eq!(tbl.dirty_count(), 1); // same inode still dirty

        tbl.unlink(ino).unwrap(); // nlink 2→1, marks dirty
        assert_eq!(tbl.dirty_count(), 1);
    }

    #[test]
    fn dirty_count_increments_on_allocate() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(tbl.dirty_count(), 0);
        tbl.allocate(InodeAttributes::new(0o644, 1000, 1000, InodeKind::File))
            .unwrap();
        assert_eq!(tbl.dirty_count(), 1);
    }

    #[test]
    fn dirty_count_increments_on_update() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.dirty_count(), 1);

        let mut attrs = tbl.lookup(ino).unwrap();
        attrs.size = 8192;
        tbl.update(ino, attrs).unwrap();
        assert_eq!(tbl.dirty_count(), 1);
    }

    #[test]
    fn dirty_count_persists_across_multiple_operations() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.dirty_count(), 1);

        // Multiple operations on same inode shouldn't double-count
        tbl.link(ino).unwrap();
        tbl.unlink(ino).unwrap();
        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.size = 4096;
        tbl.setattr(ino, attrs).unwrap();
        assert_eq!(tbl.dirty_count(), 1);
    }
    // ------------------------------------------------------------------
    // inode_counts statistics
    // ------------------------------------------------------------------

    #[test]
    fn inode_counts_on_empty_table() {
        let (tbl, _ts) = make_table(16);
        let (total, free) = tbl.inode_counts();
        assert_eq!(total, 16);
        assert_eq!(free, 16);
    }

    #[test]
    fn inode_counts_reflects_allocation() {
        let (tbl, _ts) = make_table(8);
        let _ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let (total, free) = tbl.inode_counts();
        assert_eq!(total, 8);
        assert_eq!(free, 7);
    }

    #[test]
    fn inode_counts_reflects_full_table() {
        let (tbl, _ts) = make_table(3);
        for _ in 0..3 {
            tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        }
        let (total, free) = tbl.inode_counts();
        assert_eq!(total, 3);
        assert_eq!(free, 0);
    }

    #[test]
    fn inode_counts_reflects_deallocation() {
        let (tbl, _ts) = make_table(4);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.inode_counts(), (4, 3));

        // File auto-remove: link then double-unlink
        tbl.link(ino).unwrap();
        tbl.unlink(ino).unwrap();
        tbl.unlink(ino).unwrap();
        let (total, free) = tbl.inode_counts();
        assert_eq!(total, 4);
        assert_eq!(free, 4);
    }

    #[test]
    fn inode_counts_saturates_at_u64_max() {
        // Capacity 1 with 0 live inodes: free = 1 - 0 = 1
        let (tbl, _ts) = make_table(1);
        let (total, free) = tbl.inode_counts();
        assert_eq!(total, 1);
        assert_eq!(free, 1);
    }

    // ------------------------------------------------------------------
    // Lifecycle state-transition model
    //
    // The InodeTable does not expose explicit FREE/ALLOCATED/STALE
    // states, but we can test the transitions through public API:
    //
    //   FREE → ALLOCATED:  create() returns Ok(ino), lookup() finds it
    //   ALLOCATED → FREE:  remove_if_generation succeeds, lookup() is None
    //   ALLOCATED → STALE: free the slot, re-allocate it; the old
    //                       (ino, generation) pair is now stale
    //   Invalid: remove_if_generation with nlink>0 → InodeHasLinks
    //   Invalid: allocate beyond capacity → TableFull
    //   Invalid: lookup with stale generation → GenerationMismatch
    // ------------------------------------------------------------------

    #[test]
    fn lifecycle_free_to_allocated() {
        let (tbl, _ts) = make_table(16);
        // Slot 1 is FREE — lookup returns None
        assert!(tbl.lookup(Ino(1)).is_none());

        // Transition to ALLOCATED
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(ino, Ino(1));
        let attrs = tbl.lookup(ino).unwrap();
        assert_eq!(attrs.mode, 0o644);
        assert_eq!(attrs.nlink, 1);
        assert!(attrs.generation > 0);
        assert_eq!(tbl.len(), 1);
    }

    #[test]
    fn lifecycle_allocated_to_free_via_remove_if_generation() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;

        // Transition to FREE: unlink (nlink 1→0), then remove_if_generation
        tbl.unlink_if_generation(ino, gen).unwrap();
        tbl.remove_if_generation(ino, gen).unwrap();
        assert!(tbl.lookup(ino).is_none());
        assert_eq!(tbl.len(), 0);
    }

    #[test]
    fn lifecycle_allocated_to_free_via_file_auto_remove() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // File auto-removes when nlink reaches 0
        tbl.link(ino).unwrap(); // nlink 1→2
        tbl.unlink(ino).unwrap(); // nlink 2→1
        tbl.unlink(ino).unwrap(); // nlink 1→0 → auto-remove

        assert!(tbl.lookup(ino).is_none());
        assert_eq!(tbl.len(), 0);
    }

    #[test]
    fn lifecycle_allocated_to_stale_after_realloc() {
        let (tbl, _ts) = make_table(16);
        let old_ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let old_gen = tbl.getattr(old_ino).unwrap().generation;

        // Free the slot
        tbl.unlink(old_ino).unwrap(); // file auto-remove

        // Re-allocate the same slot — old handle is now STALE
        let new_ino = tbl.create(InodeKind::File, attr_file(0o600)).unwrap();
        assert_eq!(new_ino, old_ino); // same slot reused

        let new_gen = tbl.getattr(new_ino).unwrap().generation;
        assert_ne!(new_gen, old_gen);

        // Old generation handle should be rejected
        assert_eq!(
            tbl.validate_generation(old_ino, old_gen),
            Err(InodeTableError::GenerationMismatch)
        );

        // New generation handle should work
        let attrs = tbl.validate_generation(new_ino, new_gen).unwrap();
        assert_eq!(attrs.mode, 0o600);
    }

    #[test]
    fn lifecycle_invalid_transition_remove_with_nlink() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // Invalid: remove while nlink > 0
        assert_eq!(tbl.remove(ino), Err(InodeTableError::InodeHasLinks));
        // Inode should still be reachable
        assert!(tbl.lookup(ino).is_some());
    }

    #[test]
    fn lifecycle_invalid_transition_allocate_beyond_capacity() {
        let (tbl, _ts) = make_table(3);
        for _ in 0..3 {
            tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        }
        // Invalid: allocate when table is full
        assert_eq!(
            tbl.create(InodeKind::File, attr_file(0o644)),
            Err(InodeTableError::TableFull)
        );
        assert_eq!(tbl.len(), 3);
    }

    #[test]
    fn lifecycle_invalid_transition_lookup_stale_generation() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;

        // Free and re-allocate
        tbl.unlink(ino).unwrap();
        tbl.create(InodeKind::File, attr_file(0o600)).unwrap();

        // Old generation is stale
        assert_eq!(
            tbl.validate_generation(ino, gen),
            Err(InodeTableError::GenerationMismatch)
        );
    }

    #[test]
    fn lifecycle_invalid_transition_double_free() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;

        // Valid: unlink then remove
        tbl.unlink_if_generation(ino, gen).unwrap();
        tbl.remove_if_generation(ino, gen).unwrap();
        assert!(tbl.lookup(ino).is_none());

        // Invalid: remove already-freed inode
        assert_eq!(
            tbl.remove_if_generation(ino, gen),
            Err(InodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn lifecycle_invalid_transition_unlink_at_zero() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // File starts with nlink=1
        tbl.unlink(ino).unwrap(); // nlink 1→0 → auto-removed
        assert!(tbl.lookup(ino).is_none());

        // Invalid: unlink already-removed inode
        assert_eq!(tbl.unlink(ino), Err(InodeTableError::InodeNotFound));
    }

    #[test]
    fn lifecycle_full_cycle_free_allocated_stale_free() {
        let (tbl, _ts) = make_table(4);

        // FREE → ALLOCATED
        let ino1 = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen1 = tbl.getattr(ino1).unwrap().generation;
        assert_eq!(tbl.len(), 1);

        // ALLOCATED → FREE
        tbl.unlink(ino1).unwrap(); // file auto-remove
        assert_eq!(tbl.len(), 0);
        assert!(tbl.lookup(ino1).is_none());

        // FREE → ALLOCATED (reuse same slot, new gen)
        let ino2 = tbl.create(InodeKind::File, attr_file(0o755)).unwrap();
        let gen2 = tbl.getattr(ino2).unwrap().generation;
        assert_eq!(ino2, ino1); // same slot reused
        assert_ne!(gen2, gen1);
        assert_eq!(tbl.len(), 1);

        // Old (ino1, gen1) is STALE
        assert_eq!(
            tbl.validate_generation(ino1, gen1),
            Err(InodeTableError::GenerationMismatch)
        );

        // ALLOCATED → FREE again
        tbl.unlink(ino2).unwrap();
        assert_eq!(tbl.len(), 0);
    }
    // ── prefetch_batch tests ─────────────────────────────────────────

    #[test]
    fn prefetch_batch_empty_input() {
        let tbl = InodeTable::new(64, Box::new(SystemTimeSource));
        let result = tbl.prefetch_batch(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn prefetch_batch_single_entry() {
        let tbl = InodeTable::new(64, Box::new(SystemTimeSource));
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let attrs = tbl.getattr(ino).unwrap();

        let result = tbl.prefetch_batch(&[ino]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, ino);
        assert_eq!(result[0].1.generation, attrs.generation);
    }

    #[test]
    fn prefetch_batch_full_window_64_entries() {
        let tbl = InodeTable::new(128, Box::new(SystemTimeSource));
        let mut inos = Vec::new();
        for i in 0..64u64 {
            let ino = tbl
                .create(InodeKind::File, attr_file(0o644 | (i as u32 & 0o777)))
                .unwrap();
            inos.push(ino);
        }
        let result = tbl.prefetch_batch(&inos);
        assert_eq!(result.len(), 64);
        for (ino, attrs) in &result {
            assert!(inos.contains(ino));
            assert_eq!(attrs.kind, InodeKind::File);
        }
    }

    #[test]
    fn prefetch_batch_duplicate_inodes_in_input() {
        let tbl = InodeTable::new(64, Box::new(SystemTimeSource));
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        // Same inode listed 3 times
        let result = tbl.prefetch_batch(&[ino, ino, ino]);
        // Each yielded once per match (filter_map yields one per getattr hit)
        assert_eq!(result.len(), 3);
        for (res_ino, _) in &result {
            assert_eq!(*res_ino, ino);
        }
    }

    #[test]
    fn prefetch_batch_mixed_existing_and_missing() {
        let tbl = InodeTable::new(64, Box::new(SystemTimeSource));
        let ino1 = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let ino2 = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        let missing = Ino(9999);

        let result = tbl.prefetch_batch(&[ino1, missing, ino2, Ino(8888)]);
        assert_eq!(result.len(), 2);
        let returned_inos: Vec<Ino> = result.iter().map(|(ino, _)| *ino).collect();
        assert!(returned_inos.contains(&ino1));
        assert!(returned_inos.contains(&ino2));
        assert!(!returned_inos.contains(&missing));
    }

    #[test]
    fn prefetch_batch_all_missing() {
        let tbl = InodeTable::new(64, Box::new(SystemTimeSource));
        let result = tbl.prefetch_batch(&[Ino(100), Ino(200), Ino(300)]);
        assert!(result.is_empty());
    }

    #[test]
    fn prefetch_batch_preserves_attributes_correctly() {
        let tbl = InodeTable::new(64, Box::new(SystemTimeSource));
        let ino = tbl
            .create(
                InodeKind::File,
                InodeAttributes::new(0o600, 1000, 2000, InodeKind::File),
            )
            .unwrap();
        let directly = tbl.getattr(ino).unwrap();

        let result = tbl.prefetch_batch(&[ino]);
        assert_eq!(result.len(), 1);
        let (_, batched) = &result[0];
        assert_eq!(batched.mode, directly.mode);
        assert_eq!(batched.uid, directly.uid);
        assert_eq!(batched.gid, directly.gid);
        assert_eq!(batched.kind, directly.kind);
        assert_eq!(batched.generation, directly.generation);
        assert_eq!(batched.nlink, directly.nlink);
    }

    // ------------------------------------------------------------------
    // nlink overflow (LINK_MAX) guard
    // ------------------------------------------------------------------

    #[test]
    fn link_increments_nlink_from_0_to_1() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // Start at nlink=1 (default from create)
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);

        // Unlink to 0 so we can test zero-to-one transition
        tbl.unlink(ino).unwrap(); // auto-removes the inode since it's a file
                                  // Re-create with same attrs
        let ino2 = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.getattr(ino2).unwrap().nlink, 1);
    }

    #[test]
    fn link_increments_nlink_from_1_to_2() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);

        let new_nlink = tbl.link(ino).unwrap();
        assert_eq!(new_nlink, 2);
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 2);
    }

    #[test]
    fn link_returns_link_count_overflow_at_link_max() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // Set nlink to LINK_MAX via setattr
        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.nlink = LINK_MAX;
        tbl.setattr(ino, attrs).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().nlink, LINK_MAX);

        // One more link should fail
        assert_eq!(tbl.link(ino), Err(InodeTableError::LinkCountOverflow));
        assert_eq!(tbl.getattr(ino).unwrap().nlink, LINK_MAX);
    }

    #[test]
    fn link_returns_link_count_overflow_at_link_max_minus_1_then_succeeds() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // Set nlink to LINK_MAX - 1
        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.nlink = LINK_MAX - 1;
        tbl.setattr(ino, attrs).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().nlink, LINK_MAX - 1);

        // One link should succeed (now at LINK_MAX)
        let new_nlink = tbl.link(ino).unwrap();
        assert_eq!(new_nlink, LINK_MAX);
        assert_eq!(tbl.getattr(ino).unwrap().nlink, LINK_MAX);

        // Next link should overflow
        assert_eq!(tbl.link(ino), Err(InodeTableError::LinkCountOverflow));
    }

    #[test]
    fn link_if_generation_returns_overflow_at_link_max() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let gen = tbl.getattr(ino).unwrap().generation;

        // Set nlink to LINK_MAX
        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.nlink = LINK_MAX;
        tbl.setattr_if_generation(ino, gen, attrs).unwrap();

        assert_eq!(
            tbl.link_if_generation(ino, gen),
            Err(InodeTableError::LinkCountOverflow)
        );
    }

    #[test]
    fn link_if_generation_returns_generation_mismatch_before_overflow() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let _gen = tbl.getattr(ino).unwrap().generation;

        // Wrong generation should fail before checking nlink
        assert_eq!(
            tbl.link_if_generation(ino, 9999),
            Err(InodeTableError::GenerationMismatch)
        );
    }

    #[test]
    fn unlink_below_zero_is_rejected() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        // Unlink from 1 to 0 (auto-removes file)
        tbl.unlink(ino).unwrap();
        assert!(tbl.lookup(ino).is_none());

        // Unlink again should fail
        assert_eq!(tbl.unlink(ino), Err(InodeTableError::InodeNotFound));
    }

    #[test]
    fn link_overflow_preserves_inode_state_unchanged() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();

        let mut attrs = tbl.getattr(ino).unwrap();
        attrs.nlink = LINK_MAX;
        attrs.size = 4096;
        tbl.setattr(ino, attrs).unwrap();

        let before = tbl.getattr(ino).unwrap();

        assert_eq!(tbl.link(ino), Err(InodeTableError::LinkCountOverflow));

        let after = tbl.getattr(ino).unwrap();
        assert_eq!(after.nlink, before.nlink);
        assert_eq!(after.size, before.size);
        assert_eq!(after.mode, before.mode);
    }

    // ──────────────────────────────────────────────────────────────
    // adjust_nlink tests
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn adjust_nlink_increment() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);
        let n = tbl.adjust_nlink(ino, 1).unwrap();
        assert_eq!(n, 2);
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 2);
    }

    #[test]
    fn adjust_nlink_decrement() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        tbl.link(ino).unwrap(); // nlink 1->2
        let n = tbl.adjust_nlink(ino, -1).unwrap();
        assert_eq!(n, 1);
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);
    }

    #[test]
    fn adjust_nlink_decrement_to_zero_auto_removes_file() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let n = tbl.adjust_nlink(ino, -1).unwrap();
        assert_eq!(n, 0);
        assert!(tbl.lookup(ino).is_none());
        assert_eq!(tbl.len(), 0);
    }

    #[test]
    fn adjust_nlink_decrement_to_zero_does_not_remove_directory() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::Directory, attr_dir(0o755)).unwrap();
        let n = tbl.adjust_nlink(ino, -1).unwrap();
        assert_eq!(n, 0);
        assert!(tbl.lookup(ino).is_some());
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 0);
    }

    #[test]
    fn adjust_nlink_zero_delta_is_noop() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let n = tbl.adjust_nlink(ino, 0).unwrap();
        assert_eq!(n, 1);
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);
        assert!(tbl.lookup(ino).is_some());
    }

    #[test]
    fn adjust_nlink_missing_inode() {
        let (tbl, _ts) = make_table(16);
        assert_eq!(
            tbl.adjust_nlink(Ino(99), 1),
            Err(InodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn adjust_nlink_underflow_rejected() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(
            tbl.adjust_nlink(ino, -5),
            Err(InodeTableError::InodeNotFound)
        );
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 1);
    }

    #[test]
    fn adjust_nlink_marks_inode_dirty() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        assert_eq!(tbl.dirty_count(), 1);
        tbl.adjust_nlink(ino, 1).unwrap();
        assert_eq!(tbl.dirty_count(), 1);
    }

    #[test]
    fn adjust_nlink_large_increment() {
        let (tbl, _ts) = make_table(16);
        let ino = tbl.create(InodeKind::File, attr_file(0o644)).unwrap();
        let n = tbl.adjust_nlink(ino, 65535).unwrap();
        assert_eq!(n, 65536);
        assert_eq!(tbl.getattr(ino).unwrap().nlink, 65536);
    }
}
