#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Runtime inode-attribute store.
//!
//! Provides the [`InodeAttributeStore`] trait for POSIX attribute get/set
//! dispatch, link-count tracking, and stat translation. Ships with
//! [`MemInodeAttributeStore`], a default in-memory implementation backed
//! by `HashMap` + `RwLock`.
//!
//! The trait is designed so callers (inode-table, namespace, FUSE adapter)
//! can swap in a persistent store without changing the attribute contract.
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
pub use tidefs_types_vfs_core::{
    InodeAttr, InodeFlags, InodeId, NodeKind, PosixAttrs, PosixTimestampNs, SetAttr, FATTR_ATIME,
    FATTR_ATIME_NOW, FATTR_CTIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE,
    FATTR_UID, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, S_ISGID, S_ISUID, S_ISVTX,
};
pub mod obj_xattr_store;
pub mod posix_acl;
pub mod table_store;
pub mod timestamp;
pub mod xattr;
// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------
/// Errors returned by attribute-store operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttrError {
    /// The requested inode number does not exist in the store.
    InoNotFound,
    /// `drop_link` was called when nlink was already zero.
    LinkUnderflow,
    /// `bump_link` would exceed the maximum link count.
    LinkOverflow,
}
impl AttrError {
    /// Return the closest POSIX errno for this attribute-store error.
    #[must_use]
    pub fn raw_os_error(self) -> i32 {
        match self {
            Self::InoNotFound => libc::ENOENT,
            Self::LinkUnderflow => libc::ENOLINK,
            Self::LinkOverflow => libc::EMLINK,
        }
    }
}
impl std::fmt::Display for AttrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InoNotFound => write!(f, "inode not found"),
            Self::LinkUnderflow => write!(f, "link count underflow"),
            Self::LinkOverflow => write!(f, "link count overflow"),
        }
    }
}
impl std::error::Error for AttrError {}
// ---------------------------------------------------------------------------
// InodeAttributeStore trait
// ---------------------------------------------------------------------------
/// Trait for inode attribute storage and manipulation.
///
/// Implementations must be `Send + Sync` so they can be shared across
/// threads (e.g. behind an `Arc` in a FUSE daemon).
pub trait InodeAttributeStore: Send + Sync {
    /// Return the full [`InodeAttr`] for `ino`.
    fn getattr(&self, ino: u64) -> Result<InodeAttr, AttrError>;
    /// Apply a masked attribute update from `set`.
    ///
    /// The caller controls which fields change via `set.valid`. Unmasked
    /// fields retain their current values. The implementation must bump
    /// `ctime` whenever at least one field changes.
    fn setattr(&self, ino: u64, set: &SetAttr) -> Result<InodeAttr, AttrError>;
    /// Atomically increment `nlink` and return the **new** count.
    fn bump_link(&self, ino: u64) -> Result<u32, AttrError>;
    /// Atomically decrement `nlink` and return the **new** count.
    ///
    /// Must fail with [`AttrError::LinkUnderflow`] if nlink is already
    /// zero before the decrement.
    fn drop_link(&self, ino: u64) -> Result<u32, AttrError>;
    /// Get the value of an extended attribute for `ino` by `name`.
    fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, tidefs_inode_table::XattrError>;
    /// Return the size of an extended attribute value for `ino`.
    fn get_xattr_size(
        &self,
        ino: u64,
        name: &[u8],
    ) -> Result<usize, tidefs_inode_table::XattrError>;
    /// Set an extended attribute on `ino`.
    ///
    /// `flags` is one of: 0 (create or replace),
    /// [`tidefs_inode_table::XATTR_CREATE`], or
    /// [`tidefs_inode_table::XATTR_REPLACE`].
    fn set_xattr(
        &self,
        ino: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), tidefs_inode_table::XattrError>;
    /// List all extended attribute names for `ino`, returning them
    /// null-separated with a trailing null (Linux convention).
    fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, tidefs_inode_table::XattrError>;
    /// Return the total size needed to hold the list_xattr output.
    fn list_xattr_size(&self, ino: u64) -> Result<usize, tidefs_inode_table::XattrError>;
    /// Remove an extended attribute from `ino`.
    fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), tidefs_inode_table::XattrError>;
    /// Translate the stored attributes for `ino` into a POSIX `libc::stat`.
    fn to_stat(&self, ino: u64) -> Result<libc::stat, AttrError> {
        let attrs = self.getattr(ino)?;
        Ok(crate::to_stat(ino, &attrs.posix))
    }
}
// ---------------------------------------------------------------------------
// Helper: current time in nanoseconds since UNIX epoch
// ---------------------------------------------------------------------------
pub(crate) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(i64::MAX)
}
// ---------------------------------------------------------------------------
// Helper: setattr planning and logic (shared by all backends)
// ---------------------------------------------------------------------------
/// POSIX timestamp update selected by a setattr timestamp plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetattrTimestampUpdate {
    /// Leave the timestamp unchanged.
    Unchanged,
    /// Set the timestamp to the provided nanoseconds since the UNIX epoch.
    SetNs(PosixTimestampNs),
}
impl SetattrTimestampUpdate {
    /// Return `true` when this update writes a timestamp.
    #[must_use]
    pub const fn writes_timestamp(self) -> bool {
        matches!(self, Self::SetNs(_))
    }
}
/// POSIX atime/mtime update requested before resolving the current clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixTimestampAction {
    /// Leave the timestamp unchanged.
    Keep,
    /// Set the timestamp to explicit nanoseconds since the UNIX epoch.
    SetNs(PosixTimestampNs),
    /// Set the timestamp to the caller-supplied current clock value.
    SetToNow,
}
impl PosixTimestampAction {
    /// Return `true` when this action writes a timestamp.
    #[must_use]
    pub const fn writes_timestamp(self) -> bool {
        !matches!(self, Self::Keep)
    }
    /// Resolve this POSIX action into a concrete POSIX timestamp update.
    #[must_use]
    pub const fn resolve(self, now_ns: i64) -> SetattrTimestampUpdate {
        match self {
            Self::Keep => SetattrTimestampUpdate::Unchanged,
            Self::SetNs(timestamp_ns) => SetattrTimestampUpdate::SetNs(timestamp_ns),
            Self::SetToNow => {
                SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(now_ns))
            }
        }
    }
}
/// Pure POSIX utime-style timestamp plan for atime and mtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixUtimeTimestampPlan {
    /// Planned atime action.
    pub atime: PosixTimestampAction,
    /// Planned mtime action.
    pub mtime: PosixTimestampAction,
}
impl PosixUtimeTimestampPlan {
    /// Create a POSIX utime-style timestamp plan.
    #[must_use]
    pub const fn new(atime: PosixTimestampAction, mtime: PosixTimestampAction) -> Self {
        Self { atime, mtime }
    }
    /// Return `true` when at least one POSIX timestamp action writes a value.
    #[must_use]
    pub const fn writes_any_timestamp(self) -> bool {
        self.atime.writes_timestamp() || self.mtime.writes_timestamp()
    }
    /// Resolve this POSIX plan into the concrete POSIX timestamp plan.
    ///
    /// POSIX atime/mtime writes also advance ctime to the same resolved clock.
    #[must_use]
    pub const fn resolve(self, now_ns: i64) -> SetattrTimestampPlan {
        let ctime = if self.writes_any_timestamp() {
            SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(now_ns))
        } else {
            SetattrTimestampUpdate::Unchanged
        };
        SetattrTimestampPlan {
            atime: self.atime.resolve(now_ns),
            mtime: self.mtime.resolve(now_ns),
            ctime,
        }
    }
    /// Apply this POSIX plan to POSIX attributes using a resolved clock value.
    pub fn apply_to(self, posix: &mut PosixAttrs, now_ns: i64) -> bool {
        self.resolve(now_ns).apply_to(posix)
    }
    /// Apply this POSIX plan to full inode attributes using a resolved clock value.
    pub fn apply_to_inode(self, attrs: &mut InodeAttr, now_ns: i64) -> bool {
        self.apply_to(&mut attrs.posix, now_ns)
    }
}
/// Pure timestamp plan for an inode setattr request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetattrTimestampPlan {
    /// Planned atime update.
    pub atime: SetattrTimestampUpdate,
    /// Planned mtime update.
    pub mtime: SetattrTimestampUpdate,
    /// Planned ctime update.
    pub ctime: SetattrTimestampUpdate,
}
impl SetattrTimestampPlan {
    /// Return `true` when at least one timestamp will be written.
    #[must_use]
    pub const fn writes_any_timestamp(self) -> bool {
        self.atime.writes_timestamp()
            || self.mtime.writes_timestamp()
            || self.ctime.writes_timestamp()
    }
    /// Apply this timestamp plan to POSIX attributes.
    ///
    /// Returns `true` when at least one timestamp write was accepted.
    pub fn apply_to(self, posix: &mut PosixAttrs) -> bool {
        if let SetattrTimestampUpdate::SetNs(atime_ns) = self.atime {
            posix.atime_ns = atime_ns.as_unix_nanos();
        }
        if let SetattrTimestampUpdate::SetNs(mtime_ns) = self.mtime {
            posix.mtime_ns = mtime_ns.as_unix_nanos();
        }
        if let SetattrTimestampUpdate::SetNs(ctime_ns) = self.ctime {
            posix.ctime_ns = ctime_ns.as_unix_nanos();
        }
        self.writes_any_timestamp()
    }
}

/// Apply setattr timestamp fields to POSIX attributes.
///
/// Automatic ctime advancement is tied to an actual atime/mtime or prior
/// metadata change. Timestamp bits that resolve to the already-stored value are
/// accepted as no-ops and do not manufacture a ctime update.
pub fn apply_setattr_timestamps_to_posix(
    set: &SetAttr,
    posix: &mut PosixAttrs,
    now_ns: i64,
    advance_ctime: bool,
) -> bool {
    let utime_plan = plan_posix_utime_timestamps(set);
    let mut changed = false;
    let mut timestamp_changed = false;

    if let SetattrTimestampUpdate::SetNs(atime_ns) = utime_plan.atime.resolve(now_ns) {
        let atime_ns = atime_ns.as_unix_nanos();
        if posix.atime_ns != atime_ns {
            posix.atime_ns = atime_ns;
            changed = true;
            timestamp_changed = true;
        }
    }
    if let SetattrTimestampUpdate::SetNs(mtime_ns) = utime_plan.mtime.resolve(now_ns) {
        let mtime_ns = mtime_ns.as_unix_nanos();
        if posix.mtime_ns != mtime_ns {
            posix.mtime_ns = mtime_ns;
            changed = true;
            timestamp_changed = true;
        }
    }

    let ctime_update = if set.is_valid(FATTR_CTIME) {
        Some(set.ctime_ns)
    } else if advance_ctime || timestamp_changed {
        Some(now_ns)
    } else {
        None
    };
    if let Some(ctime_ns) = ctime_update {
        if posix.ctime_ns != ctime_ns {
            posix.ctime_ns = ctime_ns;
            changed = true;
        }
    }

    changed
}

/// Plan timestamp updates from a VFS setattr request without touching storage.
///
/// `now_ns` resolves `FATTR_ATIME_NOW`, `FATTR_MTIME_NOW`, and automatic ctime
/// advancement. `advance_ctime` must be true when a non-timestamp metadata
/// field has already been accepted for the same setattr operation.
#[must_use]
pub fn plan_setattr_timestamps(
    set: &SetAttr,
    now_ns: i64,
    advance_ctime: bool,
) -> SetattrTimestampPlan {
    let utime_plan = plan_posix_utime_timestamps(set);
    let atime = utime_plan.atime.resolve(now_ns);
    let mtime = utime_plan.mtime.resolve(now_ns);
    let has_timestamp_mutation = utime_plan.writes_any_timestamp() || set.is_valid(FATTR_CTIME);
    let ctime = if set.is_valid(FATTR_CTIME) {
        SetattrTimestampUpdate::SetNs(set.ctime_timestamp())
    } else if advance_ctime || has_timestamp_mutation {
        SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(now_ns))
    } else {
        SetattrTimestampUpdate::Unchanged
    };
    SetattrTimestampPlan {
        atime,
        mtime,
        ctime,
    }
}
/// Plan POSIX utime-style atime/mtime actions from a VFS setattr request.
///
/// `*_NOW` flags take precedence over explicit timestamp values, matching the
/// concrete setattr timestamp planner.
#[must_use]
pub fn plan_posix_utime_timestamps(set: &SetAttr) -> PosixUtimeTimestampPlan {
    let atime = if set.is_valid(FATTR_ATIME_NOW) {
        PosixTimestampAction::SetToNow
    } else if set.is_valid(FATTR_ATIME) {
        PosixTimestampAction::SetNs(set.atime_timestamp())
    } else {
        PosixTimestampAction::Keep
    };
    let mtime = if set.is_valid(FATTR_MTIME_NOW) {
        PosixTimestampAction::SetToNow
    } else if set.is_valid(FATTR_MTIME) {
        PosixTimestampAction::SetNs(set.mtime_timestamp())
    } else {
        PosixTimestampAction::Keep
    };
    PosixUtimeTimestampPlan { atime, mtime }
}
const POSIX_STAT_BLOCK_SIZE: u64 = 512;
pub(crate) const fn blocks_512_for_size(size: u64) -> u64 {
    let full_blocks = size / POSIX_STAT_BLOCK_SIZE;
    let partial_block = if size % POSIX_STAT_BLOCK_SIZE == 0 {
        0
    } else {
        1
    };
    full_blocks + partial_block
}
/// Apply `set` to `attrs.posix` in-place.
///
/// Returns `true` if at least one field was modified, including an automatic
/// ctime bump when a real metadata or atime/mtime change occurred.
pub fn apply_setattr(attrs: &mut InodeAttr, set: &SetAttr) -> bool {
    let mut changed = false;
    let p = &mut attrs.posix;
    let now = now_ns();
    if set.is_valid(FATTR_MODE) {
        let mode = (p.mode & S_IFMT) | (set.mode & !S_IFMT);
        if p.mode != mode {
            p.mode = mode;
            changed = true;
        }
    }
    if set.is_valid(FATTR_UID) {
        if p.uid != set.uid {
            p.uid = set.uid;
            changed = true;
        }
    }
    if set.is_valid(FATTR_GID) {
        if p.gid != set.gid {
            p.gid = set.gid;
            changed = true;
        }
    }
    if set.is_valid(FATTR_SIZE) {
        let blocks_512 = blocks_512_for_size(set.size);
        if p.size != set.size || p.blocks_512 != blocks_512 {
            p.size = set.size;
            p.blocks_512 = blocks_512;
            changed = true;
        }
    }
    changed |= apply_setattr_timestamps_to_posix(set, p, now, changed);
    changed
}
// ---------------------------------------------------------------------------
// Default in-memory implementation
// ---------------------------------------------------------------------------
type XattrMap = BTreeMap<Vec<u8>, Vec<u8>>;
type InodeXattrMap = BTreeMap<u64, XattrMap>;

/// Default in-memory attribute store backed by `HashMap<u64, InodeAttr>` +
/// `RwLock`.
///
/// Suitable for single-node use and testing. The trait boundary allows
/// replacement with a persistent store later.
#[derive(Debug, Default)]
pub struct MemInodeAttributeStore {
    inner: RwLock<HashMap<u64, InodeAttr>>,
    xattrs: RwLock<InodeXattrMap>,
}
impl MemInodeAttributeStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            xattrs: RwLock::new(BTreeMap::new()),
        }
    }
    /// Insert (or overwrite) an inode's attributes directly.
    ///
    /// This is a low-level entry-point for inode-table initialisation;
    /// callers that only need get/set/link should use the trait methods.
    pub fn insert(&self, ino: u64, attrs: InodeAttr) {
        self.inner
            .write()
            .expect("RwLock poisoned")
            .insert(ino, attrs);
    }
    /// Remove an inode from the store.
    pub fn remove(&self, ino: u64) -> Option<InodeAttr> {
        self.inner.write().expect("RwLock poisoned").remove(&ino)
    }
    /// Return the number of inodes tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().expect("RwLock poisoned").len()
    }
    /// Return `true` when the store has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().expect("RwLock poisoned").is_empty()
    }
}
impl InodeAttributeStore for MemInodeAttributeStore {
    fn getattr(&self, ino: u64) -> Result<InodeAttr, AttrError> {
        let map = self.inner.read().expect("RwLock poisoned");
        map.get(&ino).copied().ok_or(AttrError::InoNotFound)
    }
    fn setattr(&self, ino: u64, set: &SetAttr) -> Result<InodeAttr, AttrError> {
        let mut map = self.inner.write().expect("RwLock poisoned");
        let attrs = map.get_mut(&ino).ok_or(AttrError::InoNotFound)?;
        apply_setattr(attrs, set);
        Ok(*attrs)
    }
    fn bump_link(&self, ino: u64) -> Result<u32, AttrError> {
        let mut map = self.inner.write().expect("RwLock poisoned");
        let attrs = map.get_mut(&ino).ok_or(AttrError::InoNotFound)?;
        if attrs.posix.nlink >= tidefs_inode_table::LINK_MAX {
            return Err(AttrError::LinkOverflow);
        }
        attrs.posix.nlink += 1;
        attrs.posix.ctime_ns = now_ns();
        Ok(attrs.posix.nlink)
    }
    fn drop_link(&self, ino: u64) -> Result<u32, AttrError> {
        let mut map = self.inner.write().expect("RwLock poisoned");
        let attrs = map.get_mut(&ino).ok_or(AttrError::InoNotFound)?;
        if attrs.posix.nlink == 0 {
            return Err(AttrError::LinkUnderflow);
        }
        attrs.posix.nlink -= 1;
        attrs.posix.ctime_ns = now_ns();
        Ok(attrs.posix.nlink)
    }
    fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, tidefs_inode_table::XattrError> {
        use tidefs_inode_table::XattrError;
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > 255 {
            return Err(XattrError::NameTooLong);
        }
        let map = self.xattrs.read().expect("RwLock poisoned");
        let per_inode = map.get(&ino).ok_or(XattrError::AttrNotFound)?;
        per_inode.get(name).cloned().ok_or(XattrError::AttrNotFound)
    }
    fn get_xattr_size(
        &self,
        ino: u64,
        name: &[u8],
    ) -> Result<usize, tidefs_inode_table::XattrError> {
        use tidefs_inode_table::XattrError;
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > 255 {
            return Err(XattrError::NameTooLong);
        }
        let map = self.xattrs.read().expect("RwLock poisoned");
        let per_inode = map.get(&ino).ok_or(XattrError::AttrNotFound)?;
        per_inode
            .get(name)
            .map(|v| v.len())
            .ok_or(XattrError::AttrNotFound)
    }
    fn set_xattr(
        &self,
        ino: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), tidefs_inode_table::XattrError> {
        use tidefs_inode_table::{
            XattrError, MAX_XATTR_COUNT, MAX_XATTR_VALUE_LEN, XATTR_CREATE, XATTR_REPLACE,
        };
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
        // Verify the inode exists
        {
            let inner = self.inner.read().expect("RwLock poisoned");
            if !inner.contains_key(&ino) {
                return Err(XattrError::AttrNotFound);
            }
        }
        let mut map = self.xattrs.write().expect("RwLock poisoned");
        let per_inode = map.entry(ino).or_default();
        match flags {
            XATTR_CREATE => {
                if per_inode.contains_key(name) {
                    return Err(XattrError::AttrExists);
                }
                if per_inode.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
            XATTR_REPLACE => {
                if !per_inode.contains_key(name) {
                    return Err(XattrError::AttrNotFound);
                }
            }
            _ => {
                if !per_inode.contains_key(name) && per_inode.len() >= MAX_XATTR_COUNT {
                    return Err(XattrError::InodeXattrLimit);
                }
            }
        }
        per_inode.insert(name.to_vec(), value.to_vec());
        Ok(())
    }
    fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, tidefs_inode_table::XattrError> {
        let map = self.xattrs.read().expect("RwLock poisoned");
        let per_inode = match map.get(&ino) {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };
        let mut buf = Vec::new();
        for name in per_inode.keys() {
            buf.extend_from_slice(name);
            buf.push(0);
        }
        Ok(buf)
    }
    fn list_xattr_size(&self, ino: u64) -> Result<usize, tidefs_inode_table::XattrError> {
        let map = self.xattrs.read().expect("RwLock poisoned");
        let per_inode = match map.get(&ino) {
            Some(p) => p,
            None => return Ok(0),
        };
        if per_inode.is_empty() {
            return Ok(0);
        }
        Ok(per_inode.keys().map(|k| k.len() + 1).sum())
    }
    fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), tidefs_inode_table::XattrError> {
        use tidefs_inode_table::XattrError;
        if name.is_empty() || name.contains(&0) {
            return Err(XattrError::InvalidName);
        }
        if name.len() > 255 {
            return Err(XattrError::NameTooLong);
        }
        let mut map = self.xattrs.write().expect("RwLock poisoned");
        let per_inode = map.get_mut(&ino).ok_or(XattrError::AttrNotFound)?;
        if per_inode.remove(name).is_none() {
            return Err(XattrError::AttrNotFound);
        }
        Ok(())
    }
}
// ---------------------------------------------------------------------------
// to_stat: PosixAttrs → libc::stat
// ---------------------------------------------------------------------------
/// Convert a [`PosixAttrs`] slice and an inode number into a POSIX
/// `libc::stat`.
///
/// This is the translation layer consumable by the FUSE adapter.
#[must_use]
pub fn to_stat(ino: u64, posix: &PosixAttrs) -> libc::stat {
    // Safety: zero-initialize the C struct, then fill every field.
    // We never expose padding bytes to safe code; the struct is
    // consumed by the FUSE reply layer.
    #[allow(unsafe_code)]
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    st.st_dev = 0;
    st.st_ino = ino;
    st.st_mode = posix.mode;
    st.st_nlink = posix.nlink.into();
    st.st_uid = posix.uid;
    st.st_gid = posix.gid;
    st.st_rdev = posix.rdev as u64;
    st.st_size = posix.size as i64;
    st.st_blksize = posix.blksize as i64;
    st.st_blocks = posix.blocks_512 as i64;
    st.st_atime = posix.atime_ns.div_euclid(1_000_000_000) as libc::time_t;
    st.st_atime_nsec = posix.atime_ns.rem_euclid(1_000_000_000) as libc::c_long;
    st.st_mtime = posix.mtime_ns.div_euclid(1_000_000_000) as libc::time_t;
    st.st_mtime_nsec = posix.mtime_ns.rem_euclid(1_000_000_000) as libc::c_long;
    st.st_ctime = posix.ctime_ns.div_euclid(1_000_000_000) as libc::time_t;
    st.st_ctime_nsec = posix.ctime_ns.rem_euclid(1_000_000_000) as libc::c_long;
    st
}
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AttrDirty — dirty tracking bitmask
// ---------------------------------------------------------------------------
/// Bitmask tracking which attribute fields are dirty and need persistence.
///
/// Each bit corresponds to a field in [`InodeAttr`] / [`PosixAttrs`] that
/// has been modified in the cache but not yet written through to the backing
/// [`InodeAttributeStore`].  Callers build a mask on [`AttrCache::update`]
/// and the mask is cleared on [`AttrCache::flush_dirty`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AttrDirty(u32);
/// `mode` field is dirty.
pub const ATTR_DIRTY_MODE: u32 = 1 << 0;
/// `uid` field is dirty.
pub const ATTR_DIRTY_UID: u32 = 1 << 1;
/// `gid` field is dirty.
pub const ATTR_DIRTY_GID: u32 = 1 << 2;
/// `size` field is dirty.
pub const ATTR_DIRTY_SIZE: u32 = 1 << 3;
/// `atime_ns` field is dirty.
pub const ATTR_DIRTY_ATIME: u32 = 1 << 4;
/// `mtime_ns` field is dirty.
pub const ATTR_DIRTY_MTIME: u32 = 1 << 5;
/// `ctime_ns` field is dirty.
pub const ATTR_DIRTY_CTIME: u32 = 1 << 6;
/// `nlink` field is dirty.
pub const ATTR_DIRTY_NLINK: u32 = 1 << 7;
impl AttrDirty {
    /// Create an empty (clean) dirty mask.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }
    /// Return `true` when no dirty bits are set.
    #[must_use]
    pub const fn is_clean(self) -> bool {
        self.0 == 0
    }
    /// Return `true` when at least one dirty bit is set.
    #[must_use]
    pub const fn is_dirty(self) -> bool {
        self.0 != 0
    }
    /// Set one or more dirty bits (OR).
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }
    /// Clear all dirty bits.
    pub fn clear(&mut self) {
        self.0 = 0;
    }
    /// Return `true` when the given flag bit is set.
    #[must_use]
    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
    /// Return the raw bitmask value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}
// ---------------------------------------------------------------------------
// AttrCache — LRU attribute cache with dirty tracking
// ---------------------------------------------------------------------------
/// Map dirty mask flags to the corresponding [`SetAttr`] `valid` bits.
fn dirty_to_fattr_valid(dirty: AttrDirty) -> u32 {
    let mut valid = 0u32;
    if dirty.has(ATTR_DIRTY_MODE) {
        valid |= FATTR_MODE;
    }
    if dirty.has(ATTR_DIRTY_UID) {
        valid |= FATTR_UID;
    }
    if dirty.has(ATTR_DIRTY_GID) {
        valid |= FATTR_GID;
    }
    if dirty.has(ATTR_DIRTY_SIZE) {
        valid |= FATTR_SIZE;
    }
    if dirty.has(ATTR_DIRTY_ATIME) {
        valid |= FATTR_ATIME;
    }
    if dirty.has(ATTR_DIRTY_MTIME) {
        valid |= FATTR_MTIME;
    }
    if dirty.has(ATTR_DIRTY_CTIME) {
        valid |= FATTR_CTIME;
    }
    // ATTR_DIRTY_NLINK is not persisted via setattr; nlink changes go
    // through bump_link / drop_link on the store and the cache entry
    // for nlink is invalidated by those paths.
    valid
}
/// Build a [`SetAttr`] from an [`InodeAttr`] and dirty mask for flushing.
fn build_setattr_from_dirty(attrs: &InodeAttr, dirty: AttrDirty) -> SetAttr {
    let p = &attrs.posix;
    SetAttr {
        valid: dirty_to_fattr_valid(dirty),
        mode: p.mode,
        uid: p.uid,
        gid: p.gid,
        size: p.size,
        atime_ns: p.atime_ns,
        mtime_ns: p.mtime_ns,
        ctime_ns: p.ctime_ns,
    }
}
/// A single entry in the attribute cache.
#[derive(Clone, Debug)]
struct AttrCacheEntry {
    /// Cached inode attributes.
    attrs: InodeAttr,
    /// Dirty-field bitmask.
    dirty: AttrDirty,
    /// Monotonic generation for LRU ordering (higher = more recent).
    lru_gen: u64,
}
/// LRU attribute cache with dirty tracking, sitting between callers
/// (FUSE adapter, namespace, inode table) and a backing
/// [`InodeAttributeStore`].
///
/// The cache intercepts `getattr` requests (`get`, `get_or_load`) so that
/// repeated stat / getattr calls avoid hitting the backing store.
/// Writes go through `update` and are held dirty until `flush_dirty`
/// writes them through to the store.
///
/// LRU eviction (`evict_lru`) only removes *clean* entries; dirty
/// entries must be flushed first.
pub struct AttrCache<S: InodeAttributeStore> {
    /// Backing persistent store.
    store: S,
    /// Cached entries: inode_number → AttrCacheEntry.
    entries: RwLock<HashMap<u64, AttrCacheEntry>>,
    /// Maximum number of cached entries before eviction kicks in.
    max_entries: usize,
    /// Monotonic counter bumped on every access; used for LRU ordering.
    lru_counter: AtomicU64,
}
impl<S: InodeAttributeStore> AttrCache<S> {
    /// Create a new attribute cache backed by `store`.
    ///
    /// `max_entries` is the soft capacity; the cache may temporarily
    /// exceed it until the next eviction or insertion-triggered eviction.
    #[must_use]
    pub fn new(store: S, max_entries: usize) -> Self {
        Self {
            store,
            entries: RwLock::new(HashMap::new()),
            max_entries,
            lru_counter: AtomicU64::new(0),
        }
    }
    /// Return a reference to the backing store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }
    /// Return the number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().expect("RwLock poisoned").len()
    }
    /// Return `true` when the cache has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().expect("RwLock poisoned").is_empty()
    }
    /// Return the number of entries with at least one dirty field.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        self.entries
            .read()
            .expect("RwLock poisoned")
            .values()
            .filter(|e| e.dirty.is_dirty())
            .count()
    }
    /// Return the configured maximum entry count.
    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
    // ── core cache operations ────────────────────────────────────────
    /// Return cached attributes for `ino`, bumping its LRU generation.
    ///
    /// Returns `None` on cache miss.
    #[must_use]
    pub fn get(&self, ino: u64) -> Option<InodeAttr> {
        let mut map = self.entries.write().expect("RwLock poisoned");
        let entry = map.get_mut(&ino)?;
        entry.lru_gen = self.lru_counter.fetch_add(1, Ordering::Relaxed);
        Some(entry.attrs)
    }
    /// Return attributes for `ino`, loading from the backing store on
    /// cache miss.
    ///
    /// On miss the loaded attributes are inserted into the cache.  If the
    /// cache is at capacity a single clean LRU entry is evicted to make
    /// room.
    pub fn get_or_load(&self, ino: u64) -> Result<InodeAttr, AttrError> {
        // Fast path: cache hit
        {
            let mut map = self.entries.write().expect("RwLock poisoned");
            if let Some(entry) = map.get_mut(&ino) {
                entry.lru_gen = self.lru_counter.fetch_add(1, Ordering::Relaxed);
                return Ok(entry.attrs);
            }
        }
        // Slow path: load from store
        let attrs = self.store.getattr(ino)?;
        // Insert and possibly evict
        let mut map = self.entries.write().expect("RwLock poisoned");
        let gen = self.lru_counter.fetch_add(1, Ordering::Relaxed);
        map.insert(
            ino,
            AttrCacheEntry {
                attrs,
                dirty: AttrDirty::new(),
                lru_gen: gen,
            },
        );
        // Evict one clean LRU entry if over capacity
        if map.len() > self.max_entries {
            drop(map); // release lock before calling evict_lru_inner
            self.evict_lru(1);
        }
        Ok(attrs)
    }
    /// Update cached attributes for `ino`, merging `attrs` into the
    /// cache and marking `dirty_mask` fields as dirty.
    ///
    /// If `ino` is not in the cache it is inserted.  The dirty mask is
    /// OR-ed into any existing dirty bits for that entry — this allows
    /// callers to accumulate dirty flags across multiple updates before
    /// flushing.
    ///
    /// # Errors
    ///
    /// Returns [`AttrError::InoNotFound`] if `ino` does not exist in the
    /// backing store (the cache does not fabricate inodes).
    pub fn update(
        &self,
        ino: u64,
        attrs: InodeAttr,
        dirty_mask: AttrDirty,
    ) -> Result<(), AttrError> {
        // Verify the inode exists in the backing store.
        let _ = self.store.getattr(ino)?;
        let mut map = self.entries.write().expect("RwLock poisoned");
        let gen = self.lru_counter.fetch_add(1, Ordering::Relaxed);
        match map.get_mut(&ino) {
            Some(entry) => {
                entry.attrs = attrs;
                entry.dirty.set(dirty_mask.bits());
                entry.lru_gen = gen;
            }
            None => {
                let mut dirty = AttrDirty::new();
                dirty.set(dirty_mask.bits());
                map.insert(
                    ino,
                    AttrCacheEntry {
                        attrs,
                        dirty,
                        lru_gen: gen,
                    },
                );
                // Evict one clean LRU entry if over capacity
                if map.len() > self.max_entries {
                    drop(map);
                    self.evict_lru(1);
                }
            }
        }
        Ok(())
    }
    /// Persist all dirty entries to the backing store.
    ///
    /// `_commit_group` is a transaction-group tag reserved for future writeback
    /// integration; currently accepted but unused.
    ///
    /// Returns the number of entries flushed.  A partial flush is not
    /// attempted: the first store error aborts and remaining dirty
    /// entries stay dirty.
    pub fn flush_dirty(&self, _commit_group: u64) -> Result<usize, AttrError> {
        let map = self.entries.read().expect("RwLock poisoned");
        // Collect dirty inodes and their SetAttr representations.
        let dirty_snapshot: Vec<(u64, SetAttr)> = map
            .iter()
            .filter(|(_, e)| e.dirty.is_dirty())
            .map(|(&ino, e)| (ino, build_setattr_from_dirty(&e.attrs, e.dirty)))
            .collect();
        let count = dirty_snapshot.len();
        if count == 0 {
            return Ok(0);
        }
        // Flush each dirty entry through the store.
        // Drop the map lock before calling into the store to avoid
        // deadlocks if the store itself tries to interact with the cache.
        drop(map);
        for (ino, set) in &dirty_snapshot {
            self.store.setattr(*ino, set)?;
        }
        // Clear dirty flags on successfully flushed entries.
        let mut map = self.entries.write().expect("RwLock poisoned");
        for (ino, _) in &dirty_snapshot {
            if let Some(entry) = map.get_mut(ino) {
                entry.dirty.clear();
            }
        }
        Ok(count)
    }
    /// Evict up to `count` least-recently-used **clean** entries.
    ///
    /// Dirty entries are skipped (they must be flushed before eviction).
    /// Returns the number of entries actually evicted.
    pub fn evict_lru(&self, count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        let mut map = self.entries.write().expect("RwLock poisoned");
        // Collect clean entries sorted by lru_gen (ascending = oldest first).
        let mut clean: Vec<(u64, u64)> = map
            .iter()
            .filter(|(_, e)| e.dirty.is_clean())
            .map(|(&ino, e)| (ino, e.lru_gen))
            .collect();
        clean.sort_by_key(|(_, gen)| *gen);
        let to_remove = clean.iter().take(count).count();
        for (ino, _) in clean.iter().take(count) {
            map.remove(ino);
        }
        to_remove
    }
    /// Invalidate (remove) a cached entry for `ino`.
    ///
    /// Returns the evicted [`InodeAttr`] if it was cached.
    pub fn invalidate(&self, ino: u64) -> Option<InodeAttr> {
        self.entries
            .write()
            .expect("RwLock poisoned")
            .remove(&ino)
            .map(|e| e.attrs)
    }

    // ── batch prefetch ───────────────────────────────────────────────

    /// Prefetch a batch of inode attributes into the cache.
    ///
    /// For each `ino` that is not already cached, loads the attributes
    /// from the backing store and inserts them into the LRU cache.
    /// Already-cached entries have their LRU generation bumped.
    ///
    /// Missing inodes in the backing store are silently skipped
    /// (best-effort prefetch). If the cache exceeds capacity after the
    /// operation, clean LRU entries are evicted.
    ///
    /// Returns the number of newly cached entries (entries that were
    /// loaded from the store, not those that were already present).
    pub fn prefetch_batch(&self, inos: &[u64]) -> usize {
        use std::sync::atomic::Ordering;

        let mut newly_cached = 0usize;
        let mut map = self.entries.write().expect("RwLock poisoned");

        for &ino in inos {
            if let Some(entry) = map.get_mut(&ino) {
                // Already cached: bump LRU generation
                entry.lru_gen = self.lru_counter.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // Load from backing store
            if let Ok(attrs) = self.store.getattr(ino) {
                let gen = self.lru_counter.fetch_add(1, Ordering::Relaxed);
                map.insert(
                    ino,
                    AttrCacheEntry {
                        attrs,
                        dirty: AttrDirty::new(),
                        lru_gen: gen,
                    },
                );
                newly_cached += 1;
            }
        }

        // Evict clean LRU entries if over capacity
        if map.len() > self.max_entries {
            let excess = map.len() - self.max_entries;
            drop(map);
            self.evict_lru(excess);
        }

        newly_cached
    }
}
// ---------------------------------------------------------------------------
// AttrCache tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod attrcache_tests {
    use super::*;
    fn dummy_attrs(ino: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: tidefs_types_vfs_core::Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: S_IFREG | 0o644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 1_000_000_000,
                mtime_ns: 2_000_000_000,
                ctime_ns: 3_000_000_000,
                btime_ns: 4_000_000_000,
                size: 4096,
                blocks_512: 8,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }
    fn make_cache(max: usize) -> AttrCache<MemInodeAttributeStore> {
        let store = MemInodeAttributeStore::new();
        AttrCache::new(store, max)
    }
    fn make_cache_seeded(max: usize, inos: &[u64]) -> AttrCache<MemInodeAttributeStore> {
        let store = MemInodeAttributeStore::new();
        for &ino in inos {
            store.insert(ino, dummy_attrs(ino));
        }
        AttrCache::new(store, max)
    }
    // ── AttrDirty ─────────────────────────────────────────────────────
    #[test]
    fn dirty_new_is_clean() {
        let d = AttrDirty::new();
        assert!(d.is_clean());
        assert!(!d.is_dirty());
        assert_eq!(d.bits(), 0);
    }
    #[test]
    fn dirty_set_and_has() {
        let mut d = AttrDirty::new();
        d.set(ATTR_DIRTY_MODE);
        assert!(d.has(ATTR_DIRTY_MODE));
        assert!(!d.has(ATTR_DIRTY_UID));
        assert!(d.is_dirty());
    }
    #[test]
    fn dirty_set_accumulates() {
        let mut d = AttrDirty::new();
        d.set(ATTR_DIRTY_MODE);
        d.set(ATTR_DIRTY_UID | ATTR_DIRTY_SIZE);
        assert!(d.has(ATTR_DIRTY_MODE));
        assert!(d.has(ATTR_DIRTY_UID));
        assert!(d.has(ATTR_DIRTY_SIZE));
        assert!(!d.has(ATTR_DIRTY_GID));
    }
    #[test]
    fn dirty_clear_resets() {
        let mut d = AttrDirty::new();
        d.set(ATTR_DIRTY_MODE | ATTR_DIRTY_MTIME);
        assert!(d.is_dirty());
        d.clear();
        assert!(d.is_clean());
        assert_eq!(d.bits(), 0);
    }
    // ── AttrCache::new / basic properties ─────────────────────────────
    #[test]
    fn cache_new_is_empty() {
        let cache = make_cache(64);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.max_entries(), 64);
    }
    #[test]
    fn cache_store_access() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let cache = AttrCache::new(store, 64);
        let attrs = cache.store().getattr(1).unwrap();
        assert_eq!(attrs.posix.mode, S_IFREG | 0o644);
    }
    // ── get (cache hit) ───────────────────────────────────────────────
    #[test]
    fn get_miss_returns_none() {
        let cache = make_cache(64);
        assert_eq!(cache.get(1), None);
    }
    #[test]
    fn get_hit_after_load() {
        let cache = make_cache_seeded(64, &[1]);
        let _ = cache.get_or_load(1).unwrap();
        let hit = cache.get(1);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().inode_id.get(), 1);
    }
    #[test]
    fn get_updates_lru() {
        let cache = make_cache_seeded(64, &[1, 2, 3]);
        // Load all three
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        let _ = cache.get_or_load(3).unwrap();
        // Access 1 again — it becomes most recent
        let _ = cache.get(1).unwrap();
        // Evict 2 clean entries — should evict 2 and 3 (oldest), keep 1
        let evicted = cache.evict_lru(2);
        assert_eq!(evicted, 2);
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());
        assert!(cache.get(3).is_none());
    }
    // ── get_or_load ───────────────────────────────────────────────────
    #[test]
    fn get_or_load_miss_loads_from_store() {
        let cache = make_cache_seeded(64, &[1]);
        let attrs = cache.get_or_load(1).unwrap();
        assert_eq!(attrs.inode_id.get(), 1);
        assert_eq!(attrs.posix.mode, S_IFREG | 0o644);
    }
    #[test]
    fn get_or_load_hit_does_not_reload() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let cache = AttrCache::new(store, 64);
        // First call loads
        let _a1 = cache.get_or_load(1).unwrap();
        // Dirty the backing store directly (simulate external mutation)
        let mut changed = dummy_attrs(1);
        changed.posix.mode = S_IFREG | 0o700;
        cache
            .store()
            .setattr(
                1,
                &SetAttr {
                    valid: FATTR_MODE,
                    mode: S_IFREG | 0o700,
                    ..SetAttr::new()
                },
            )
            .unwrap();
        // Second call hits cache — returns stale (cached) value
        let a2 = cache.get_or_load(1).unwrap();
        assert_eq!(a2.posix.mode, S_IFREG | 0o644); // stale, not 0o700
    }
    #[test]
    fn get_or_load_not_found() {
        let cache = make_cache(64);
        assert_eq!(cache.get_or_load(99), Err(AttrError::InoNotFound));
    }
    // ── update ────────────────────────────────────────────────────────
    #[test]
    fn update_inserts_and_marks_dirty() {
        let cache = make_cache_seeded(64, &[1]);
        let mut attrs = cache.get_or_load(1).unwrap();
        attrs.posix.mode = S_IFREG | 0o600;
        let mut dirty = AttrDirty::new();
        dirty.set(ATTR_DIRTY_MODE);
        cache.update(1, attrs, dirty).unwrap();
        let cached = cache.get(1).unwrap();
        assert_eq!(cached.posix.mode, S_IFREG | 0o600);
        assert_eq!(cache.dirty_count(), 1);
    }
    #[test]
    fn update_accumulates_dirty() {
        let cache = make_cache_seeded(64, &[1]);
        let mut attrs = cache.get_or_load(1).unwrap();
        // First update: mode
        attrs.posix.mode = S_IFREG | 0o600;
        let mut d1 = AttrDirty::new();
        d1.set(ATTR_DIRTY_MODE);
        cache.update(1, attrs, d1).unwrap();
        // Second update: uid (mode still dirty from first update)
        let mut attrs = cache.get(1).unwrap();
        attrs.posix.uid = 2000;
        let mut d2 = AttrDirty::new();
        d2.set(ATTR_DIRTY_UID);
        cache.update(1, attrs, d2).unwrap();
        // Entry should have both mode and uid dirty
        let map = cache.entries.read().unwrap();
        let entry = map.get(&1).unwrap();
        assert!(entry.dirty.has(ATTR_DIRTY_MODE));
        assert!(entry.dirty.has(ATTR_DIRTY_UID));
    }
    #[test]
    fn update_not_found_in_store() {
        let cache = make_cache(64);
        let result = cache.update(99, dummy_attrs(99), AttrDirty::new());
        assert_eq!(result, Err(AttrError::InoNotFound));
    }
    // ── flush_dirty ───────────────────────────────────────────────────
    #[test]
    fn flush_dirty_empty_returns_zero() {
        let cache = make_cache_seeded(64, &[1]);
        let _ = cache.get_or_load(1).unwrap();
        assert_eq!(cache.flush_dirty(0).unwrap(), 0);
    }
    #[test]
    fn flush_dirty_persists_and_clears() {
        let cache = make_cache_seeded(64, &[1]);
        let mut attrs = cache.get_or_load(1).unwrap();
        attrs.posix.mode = S_IFREG | 0o600;
        let mut dirty = AttrDirty::new();
        dirty.set(ATTR_DIRTY_MODE);
        cache.update(1, attrs, dirty).unwrap();
        assert_eq!(cache.dirty_count(), 1);
        let flushed = cache.flush_dirty(1).unwrap();
        assert_eq!(flushed, 1);
        assert_eq!(cache.dirty_count(), 0);
        // Verify store has the new mode
        let stored = cache.store().getattr(1).unwrap();
        assert_eq!(stored.posix.mode, S_IFREG | 0o600);
    }
    #[test]
    fn flush_dirty_multiple_entries() {
        let cache = make_cache_seeded(64, &[1, 2, 3]);
        for ino in [1u64, 2, 3] {
            let mut attrs = cache.get_or_load(ino).unwrap();
            attrs.posix.mode = S_IFREG | (0o600 + ino as u32);
            let mut dirty = AttrDirty::new();
            dirty.set(ATTR_DIRTY_MODE);
            cache.update(ino, attrs, dirty).unwrap();
        }
        assert_eq!(cache.dirty_count(), 3);
        let flushed = cache.flush_dirty(0).unwrap();
        assert_eq!(flushed, 3);
        assert_eq!(cache.dirty_count(), 0);
        for ino in [1u64, 2, 3] {
            let stored = cache.store().getattr(ino).unwrap();
            assert_eq!(stored.posix.mode, S_IFREG | (0o600 + ino as u32));
        }
    }
    #[test]
    fn flush_dirty_preserves_clean_entries() {
        let cache = make_cache_seeded(64, &[1, 2]);
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        // Dirty only inode 1
        let mut attrs = cache.get(1).unwrap();
        attrs.posix.uid = 999;
        let mut dirty = AttrDirty::new();
        dirty.set(ATTR_DIRTY_UID);
        cache.update(1, attrs, dirty).unwrap();
        cache.flush_dirty(0).unwrap();
        // Inode 2 should still be cached (it was clean)
        assert!(cache.get(2).is_some());
    }
    #[test]
    fn flush_dirty_multi_field() {
        let cache = make_cache_seeded(64, &[1]);
        let mut attrs = cache.get_or_load(1).unwrap();
        attrs.posix.mode = S_IFREG | 0o700;
        attrs.posix.uid = 42;
        attrs.posix.gid = 99;
        attrs.posix.size = 16384;
        let mut dirty = AttrDirty::new();
        dirty.set(ATTR_DIRTY_MODE | ATTR_DIRTY_UID | ATTR_DIRTY_GID | ATTR_DIRTY_SIZE);
        cache.update(1, attrs, dirty).unwrap();
        cache.flush_dirty(0).unwrap();
        let stored = cache.store().getattr(1).unwrap();
        assert_eq!(stored.posix.mode, S_IFREG | 0o700);
        assert_eq!(stored.posix.uid, 42);
        assert_eq!(stored.posix.gid, 99);
        assert_eq!(stored.posix.size, 16384);
    }
    // ── evict_lru ─────────────────────────────────────────────────────
    #[test]
    fn evict_lru_zero_does_nothing() {
        let cache = make_cache_seeded(64, &[1, 2]);
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        assert_eq!(cache.evict_lru(0), 0);
        assert_eq!(cache.len(), 2);
    }
    #[test]
    fn evict_lru_removes_oldest_clean() {
        let cache = make_cache_seeded(64, &[1, 2, 3]);
        // Load in order: 1 (oldest), 2, 3 (newest)
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        let _ = cache.get_or_load(3).unwrap();
        let evicted = cache.evict_lru(1);
        assert_eq!(evicted, 1);
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
    }
    #[test]
    fn evict_lru_skips_dirty_entries() {
        let cache = make_cache_seeded(64, &[1, 2, 3]);
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        let _ = cache.get_or_load(3).unwrap();
        // Make inode 1 dirty (oldest, but dirty → cannot be evicted)
        let mut attrs = cache.get(1).unwrap();
        attrs.posix.mode = S_IFREG | 0o700;
        let mut dirty = AttrDirty::new();
        dirty.set(ATTR_DIRTY_MODE);
        cache.update(1, attrs, dirty).unwrap();
        // Evict 2 — should skip dirty inode 1, evict 2 and 3
        let evicted = cache.evict_lru(2);
        assert_eq!(evicted, 2);
        assert!(cache.get(1).is_some()); // dirty, preserved
        assert!(cache.get(2).is_none());
        assert!(cache.get(3).is_none());
    }
    #[test]
    fn evict_lru_more_than_clean() {
        let cache = make_cache_seeded(64, &[1]);
        let _ = cache.get_or_load(1).unwrap();
        let evicted = cache.evict_lru(5);
        assert_eq!(evicted, 1);
        assert!(cache.is_empty());
    }
    // ── capacity enforcement ──────────────────────────────────────────
    #[test]
    fn get_or_load_evicts_when_over_capacity() {
        let cache = make_cache_seeded(2, &[1, 2, 3]);
        // Load entries; max_entries=2, so third insert triggers eviction
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        let _ = cache.get_or_load(3).unwrap();
        // Should have evicted the oldest (1)
        assert!(cache.len() <= 2);
    }
    #[test]
    fn update_evicts_when_over_capacity() {
        let cache = make_cache_seeded(2, &[1, 2]);
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        // Insert a new entry via update (ino 3 must exist in store)
        cache.store().insert(3, dummy_attrs(3));
        cache.update(3, dummy_attrs(3), AttrDirty::new()).unwrap();
        assert!(cache.len() <= 2);
    }
    #[test]
    fn capacity_enforcement_does_not_evict_dirty() {
        let cache = make_cache_seeded(2, &[1, 2]);
        let _ = cache.get_or_load(1).unwrap();
        let _ = cache.get_or_load(2).unwrap();
        // Make both dirty
        for ino in [1u64, 2] {
            let mut attrs = cache.get(ino).unwrap();
            attrs.posix.uid = 999;
            let mut dirty = AttrDirty::new();
            dirty.set(ATTR_DIRTY_UID);
            cache.update(ino, attrs, dirty).unwrap();
        }
        // Try to insert a third — should succeed (len becomes > max)
        // because all entries are now dirty and cannot be evicted.
        cache.store().insert(3, dummy_attrs(3));
        let mut d3 = AttrDirty::new();
        d3.set(ATTR_DIRTY_UID);
        cache.update(3, dummy_attrs(3), d3).unwrap();
        assert_eq!(cache.len(), 3);
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
    }
    // ── invalidate ────────────────────────────────────────────────────
    #[test]
    fn invalidate_removes_cached_entry() {
        let cache = make_cache_seeded(64, &[1]);
        let _ = cache.get_or_load(1).unwrap();
        assert!(cache.get(1).is_some());
        let removed = cache.invalidate(1);
        assert!(removed.is_some());
        assert!(cache.get(1).is_none());
    }
    #[test]
    fn invalidate_miss_returns_none() {
        let cache = make_cache(64);
        assert_eq!(cache.invalidate(1), None);
    }
    // ── dirty_to_fattr_valid ──────────────────────────────────────────
    #[test]
    fn dirty_to_fattr_maps_all_fields() {
        let mut d = AttrDirty::new();
        d.set(
            ATTR_DIRTY_MODE
                | ATTR_DIRTY_UID
                | ATTR_DIRTY_GID
                | ATTR_DIRTY_SIZE
                | ATTR_DIRTY_ATIME
                | ATTR_DIRTY_MTIME
                | ATTR_DIRTY_CTIME,
        );
        let valid = dirty_to_fattr_valid(d);
        assert!(valid & FATTR_MODE != 0);
        assert!(valid & FATTR_UID != 0);
        assert!(valid & FATTR_GID != 0);
        assert!(valid & FATTR_SIZE != 0);
        assert!(valid & FATTR_ATIME != 0);
        assert!(valid & FATTR_MTIME != 0);
        assert!(valid & FATTR_CTIME != 0);
    }
    #[test]
    fn dirty_to_fattr_excludes_nlink() {
        let mut d = AttrDirty::new();
        d.set(ATTR_DIRTY_NLINK);
        let valid = dirty_to_fattr_valid(d);
        assert_eq!(valid, 0);
    }
    // ── concurrent get + update ───────────────────────────────────────
    #[test]
    fn concurrent_get_and_update() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        let store = MemInodeAttributeStore::new();
        for ino in 0..16u64 {
            store.insert(ino, dummy_attrs(ino));
        }
        let cache = Arc::new(AttrCache::new(store, 64));
        // Pre-load all inodes into cache
        for ino in 0..16u64 {
            cache.get_or_load(ino).unwrap();
        }
        const N_THREADS: usize = 8;
        const N_OPS: usize = 100;
        let barrier = Arc::new(Barrier::new(N_THREADS));
        let mut handles = Vec::new();
        for t in 0..N_THREADS {
            let c = Arc::clone(&cache);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                for i in 0..N_OPS {
                    let ino = ((t * N_OPS + i) % 16) as u64;
                    let mut attrs = c.get_or_load(ino).unwrap();
                    attrs.posix.uid = attrs.posix.uid.wrapping_add(1);
                    let mut dirty = AttrDirty::new();
                    dirty.set(ATTR_DIRTY_UID);
                    c.update(ino, attrs, dirty).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // All 16 inodes should still be in cache
        for ino in 0..16u64 {
            assert!(cache.get(ino).is_some(), "inode {ino} missing");
        }
        assert_eq!(cache.len(), 16);
    }
    // ── build_setattr_from_dirty ──────────────────────────────────────
    #[test]
    fn build_setattr_from_dirty_copies_fields() {
        let attrs = dummy_attrs(1);
        let mut dirty = AttrDirty::new();
        dirty.set(ATTR_DIRTY_MODE | ATTR_DIRTY_UID);
        let set = build_setattr_from_dirty(&attrs, dirty);
        assert!(set.is_valid(FATTR_MODE));
        assert!(set.is_valid(FATTR_UID));
        assert!(!set.is_valid(FATTR_GID));
        assert_eq!(set.mode, S_IFREG | 0o644);
        assert_eq!(set.uid, 1000);
    }
    // ── lru ordering across operations ────────────────────────────────
    #[test]
    fn lru_ordering_respected_after_mixed_operations() {
        let cache = make_cache_seeded(64, &[1, 2, 3, 4, 5]);
        // Load all
        for ino in [1u64, 2, 3, 4, 5] {
            let _ = cache.get_or_load(ino).unwrap();
        }
        // Access 3 (makes it newest), then 5, then 1
        let _ = cache.get(3);
        let _ = cache.get(5);
        let _ = cache.get(1);
        // Evict 2 — should evict 2 and 4 (oldest), keep 1, 3, 5
        let evicted = cache.evict_lru(2);
        assert_eq!(evicted, 2);
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());
        assert!(cache.get(3).is_some());
        assert!(cache.get(4).is_none());
        assert!(cache.get(5).is_some());
    }
}
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_vfs_core::{S_IFDIR, S_IFLNK};
    fn dummy_attrs(ino: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: tidefs_types_vfs_core::Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: S_IFREG | 0o644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 1_000_000_000,
                mtime_ns: 2_000_000_000,
                ctime_ns: 3_000_000_000,
                btime_ns: 4_000_000_000,
                size: 4096,
                blocks_512: 8,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }
    // ── getattr / setattr ────────────────────────────────────────────────
    #[test]
    fn getattr_not_found() {
        let store = MemInodeAttributeStore::new();
        assert_eq!(store.getattr(42), Err(AttrError::InoNotFound));
    }
    #[test]
    fn getattr_round_trip() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let got = store.getattr(1).unwrap();
        assert_eq!(got.inode_id.get(), 1);
        assert_eq!(got.posix.mode, S_IFREG | 0o644);
    }
    #[test]
    fn setattr_not_found() {
        let store = MemInodeAttributeStore::new();
        assert_eq!(
            store.setattr(99, &SetAttr::new()),
            Err(AttrError::InoNotFound)
        );
    }
    #[test]
    fn setattr_mode_only() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = S_IFREG | 0o600;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mode, S_IFREG | 0o600);
        assert_eq!(updated.posix.uid, 1000); // untouched
                                             // ctime must have moved forward
        assert!(updated.posix.ctime_ns > 3_000_000_000);
    }
    #[test]
    fn setattr_chmod_preserves_timestamps_and_inode_identity() {
        let store = MemInodeAttributeStore::new();
        let mut original = dummy_attrs(7);
        original.posix.mode = S_IFREG | 0o644;
        original.posix.nlink = 3;
        original.subtree_rev = 11;
        original.dir_rev = 17;
        store.insert(7, original);
        let before = now_ns();
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o600;
        let updated = store.setattr(7, &set).unwrap();
        assert_eq!(updated.posix.mode, S_IFREG | 0o600);
        assert_eq!(updated.posix.atime_ns, original.posix.atime_ns);
        assert_eq!(updated.posix.mtime_ns, original.posix.mtime_ns);
        assert!(updated.posix.ctime_ns >= before);
        assert!(updated.posix.ctime_ns > original.posix.ctime_ns);
        assert_eq!(updated.inode_id, original.inode_id);
        assert_eq!(updated.generation, original.generation);
        assert_eq!(updated.kind, original.kind);
        assert_eq!(updated.flags, original.flags);
        assert_eq!(updated.subtree_rev, original.subtree_rev);
        assert_eq!(updated.dir_rev, original.dir_rev);
        assert_eq!(updated.posix.uid, original.posix.uid);
        assert_eq!(updated.posix.gid, original.posix.gid);
        assert_eq!(updated.posix.nlink, original.posix.nlink);
        assert_eq!(updated.posix.rdev, original.posix.rdev);
        assert_eq!(updated.posix.btime_ns, original.posix.btime_ns);
        assert_eq!(updated.posix.size, original.posix.size);
        assert_eq!(updated.posix.blocks_512, original.posix.blocks_512);
        assert_eq!(updated.posix.blksize, original.posix.blksize);
    }
    #[test]
    fn setattr_chmod_preserves_existing_type_bits() {
        for (ino, kind, type_bits) in [
            (1, NodeKind::File, S_IFREG),
            (2, NodeKind::Dir, S_IFDIR),
            (3, NodeKind::Symlink, S_IFLNK),
        ] {
            let store = MemInodeAttributeStore::new();
            let mut attrs = dummy_attrs(ino);
            attrs.kind = kind;
            attrs.posix.mode = type_bits | 0o644;
            store.insert(ino, attrs);
            let mut set = SetAttr::new();
            set.valid = FATTR_MODE;
            set.mode = 0o4751;
            let updated = store.setattr(ino, &set).unwrap();
            assert_eq!(updated.posix.mode & S_IFMT, type_bits);
            assert_eq!(updated.posix.mode & !S_IFMT, 0o4751);
            assert_eq!(updated.kind, kind);
        }
    }
    #[test]
    fn setattr_chmod_ignores_incoming_type_bits() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.kind = NodeKind::Dir;
        attrs.posix.mode = S_IFDIR | 0o755;
        store.insert(1, attrs);
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = S_IFREG | 0o700;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mode, S_IFDIR | 0o700);
        assert_eq!(updated.kind, NodeKind::Dir);
    }
    #[test]
    fn setattr_size_recomputes_blocks() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 8192;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.size, 8192);
        assert_eq!(updated.posix.blocks_512, blocks_512_for_size(8192));
    }
    #[test]
    fn blocks_512_for_size_rounds_without_overflow() {
        assert_eq!(blocks_512_for_size(0), 0);
        assert_eq!(blocks_512_for_size(1), 1);
        assert_eq!(blocks_512_for_size(511), 1);
        assert_eq!(blocks_512_for_size(512), 1);
        assert_eq!(blocks_512_for_size(513), 2);
        assert_eq!(
            blocks_512_for_size(u64::MAX),
            (u64::MAX / POSIX_STAT_BLOCK_SIZE) + 1
        );
    }
    #[test]
    fn setattr_size_max_recomputes_blocks_without_overflow() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = u64::MAX;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.size, u64::MAX);
        assert_eq!(updated.posix.blocks_512, blocks_512_for_size(u64::MAX));
    }
    #[test]
    fn setattr_uid_gid() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = 2000;
        set.gid = 3000;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.uid, 2000);
        assert_eq!(updated.posix.gid, 3000);
    }
    #[test]
    fn setattr_atime_mtime_ctime() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME | FATTR_CTIME;
        set.atime_ns = 100;
        set.mtime_ns = 200;
        set.ctime_ns = 300;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, 100);
        assert_eq!(updated.posix.mtime_ns, 200);
        assert_eq!(updated.posix.ctime_ns, 300);
    }

    #[test]
    fn setattr_unchanged_atime_mtime_preserves_ctime() {
        let store = MemInodeAttributeStore::new();
        let original = dummy_attrs(1);
        store.insert(1, original);
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = original.posix.atime_ns;
        set.mtime_ns = original.posix.mtime_ns;

        let updated = store.setattr(1, &set).unwrap();

        assert_eq!(updated.posix.atime_ns, original.posix.atime_ns);
        assert_eq!(updated.posix.mtime_ns, original.posix.mtime_ns);
        assert_eq!(updated.posix.ctime_ns, original.posix.ctime_ns);
    }

    #[test]
    fn setattr_atime_only_preserves_mtime_and_metadata() {
        let store = MemInodeAttributeStore::new();
        let original = dummy_attrs(1);
        store.insert(1, original);
        let before = now_ns();
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME;
        set.atime_ns = 100;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, 100);
        assert_eq!(updated.posix.mtime_ns, original.posix.mtime_ns);
        assert!(updated.posix.ctime_ns >= before);
        assert_eq!(updated.posix.mode, original.posix.mode);
        assert_eq!(updated.posix.uid, original.posix.uid);
        assert_eq!(updated.posix.gid, original.posix.gid);
        assert_eq!(updated.posix.size, original.posix.size);
        assert_eq!(updated.posix.blocks_512, original.posix.blocks_512);
        assert_eq!(updated.kind, original.kind);
        assert_eq!(updated.inode_id, original.inode_id);
    }
    #[test]
    fn setattr_mtime_only_preserves_atime_and_metadata() {
        let store = MemInodeAttributeStore::new();
        let original = dummy_attrs(1);
        store.insert(1, original);
        let before = now_ns();
        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME;
        set.mtime_ns = 200;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, original.posix.atime_ns);
        assert_eq!(updated.posix.mtime_ns, 200);
        assert!(updated.posix.ctime_ns >= before);
        assert_eq!(updated.posix.mode, original.posix.mode);
        assert_eq!(updated.posix.uid, original.posix.uid);
        assert_eq!(updated.posix.gid, original.posix.gid);
        assert_eq!(updated.posix.size, original.posix.size);
        assert_eq!(updated.posix.blocks_512, original.posix.blocks_512);
        assert_eq!(updated.kind, original.kind);
        assert_eq!(updated.inode_id, original.inode_id);
    }
    #[test]
    fn setattr_atime_mtime_preserves_unrelated_metadata() {
        let store = MemInodeAttributeStore::new();
        let original = dummy_attrs(1);
        store.insert(1, original);
        let before = now_ns();
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = 111;
        set.mtime_ns = 222;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, 111);
        assert_eq!(updated.posix.mtime_ns, 222);
        assert!(updated.posix.ctime_ns >= before);
        assert_eq!(updated.posix.mode, original.posix.mode);
        assert_eq!(updated.posix.uid, original.posix.uid);
        assert_eq!(updated.posix.gid, original.posix.gid);
        assert_eq!(updated.posix.size, original.posix.size);
        assert_eq!(updated.posix.blocks_512, original.posix.blocks_512);
        assert_eq!(updated.kind, original.kind);
        assert_eq!(updated.inode_id, original.inode_id);
    }
    #[test]
    fn setattr_atime_now_mtime_now() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let before = now_ns();
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME_NOW | FATTR_MTIME_NOW;
        let updated = store.setattr(1, &set).unwrap();
        assert!(updated.posix.atime_ns >= before);
        assert!(updated.posix.mtime_ns >= before);
    }
    #[test]
    fn timestamp_plan_explicit_atime_mtime_advances_ctime() {
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = 11;
        set.mtime_ns = 22;
        let plan = plan_setattr_timestamps(&set, 99, false);
        assert_eq!(
            plan,
            SetattrTimestampPlan {
                atime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(11)),
                mtime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(22)),
                ctime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(99)),
            }
        );
    }
    #[test]
    fn timestamp_plan_now_flags_use_supplied_clock() {
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME_NOW | FATTR_MTIME_NOW;
        set.atime_ns = 11;
        set.mtime_ns = 22;
        let plan = plan_setattr_timestamps(&set, 1234, false);
        assert_eq!(
            plan,
            SetattrTimestampPlan {
                atime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(1234)),
                mtime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(1234)),
                ctime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(1234)),
            }
        );
    }
    #[test]
    fn timestamp_plan_unchanged_when_no_time_or_prior_metadata_change() {
        let set = SetAttr::new();
        let plan = plan_setattr_timestamps(&set, 1234, false);
        assert_eq!(
            plan,
            SetattrTimestampPlan {
                atime: SetattrTimestampUpdate::Unchanged,
                mtime: SetattrTimestampUpdate::Unchanged,
                ctime: SetattrTimestampUpdate::Unchanged,
            }
        );
        assert!(!plan.writes_any_timestamp());
    }
    #[test]
    fn timestamp_plan_advances_ctime_for_prior_metadata_change() {
        let set = SetAttr::new();
        let plan = plan_setattr_timestamps(&set, 5678, true);
        assert_eq!(
            plan,
            SetattrTimestampPlan {
                atime: SetattrTimestampUpdate::Unchanged,
                mtime: SetattrTimestampUpdate::Unchanged,
                ctime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(5678)),
            }
        );
    }
    #[test]
    fn timestamp_plan_explicit_ctime_overrides_auto_advance() {
        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME | FATTR_CTIME;
        set.mtime_ns = 22;
        set.ctime_ns = 33;
        let plan = plan_setattr_timestamps(&set, 5678, true);
        assert_eq!(
            plan,
            SetattrTimestampPlan {
                atime: SetattrTimestampUpdate::Unchanged,
                mtime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(22)),
                ctime: SetattrTimestampUpdate::SetNs(PosixTimestampNs::from_unix_nanos(33)),
            }
        );
    }
    #[test]
    fn posix_utime_plan_explicit_times_preserves_unrelated_inode_fields() {
        let mut attrs = dummy_attrs(1);
        let original = attrs;
        let plan = PosixUtimeTimestampPlan::new(
            PosixTimestampAction::SetNs(PosixTimestampNs::from_unix_nanos(111)),
            PosixTimestampAction::SetNs(PosixTimestampNs::from_unix_nanos(222)),
        );
        assert!(plan.apply_to_inode(&mut attrs, 999));
        assert_eq!(attrs.posix.atime_ns, 111);
        assert_eq!(attrs.posix.mtime_ns, 222);
        assert_eq!(attrs.posix.ctime_ns, 999);
        assert_eq!(attrs.posix.mode, original.posix.mode);
        assert_eq!(attrs.posix.uid, original.posix.uid);
        assert_eq!(attrs.posix.gid, original.posix.gid);
        assert_eq!(attrs.posix.nlink, original.posix.nlink);
        assert_eq!(attrs.posix.size, original.posix.size);
        assert_eq!(attrs.posix.blocks_512, original.posix.blocks_512);
        assert_eq!(attrs.inode_id, original.inode_id);
        assert_eq!(attrs.generation, original.generation);
        assert_eq!(attrs.kind, original.kind);
        assert_eq!(attrs.flags, original.flags);
        assert_eq!(attrs.subtree_rev, original.subtree_rev);
        assert_eq!(attrs.dir_rev, original.dir_rev);
    }
    #[test]
    fn posix_utime_plan_now_uses_supplied_clock_deterministically() {
        let mut attrs = dummy_attrs(1);
        let plan = PosixUtimeTimestampPlan::new(
            PosixTimestampAction::SetToNow,
            PosixTimestampAction::SetToNow,
        );
        assert!(plan.apply_to_inode(&mut attrs, 1234));
        assert_eq!(attrs.posix.atime_ns, 1234);
        assert_eq!(attrs.posix.mtime_ns, 1234);
        assert_eq!(attrs.posix.ctime_ns, 1234);
    }
    #[test]
    fn posix_utime_plan_keep_existing_does_not_touch_timestamps() {
        let mut attrs = dummy_attrs(1);
        let original = attrs;
        let plan =
            PosixUtimeTimestampPlan::new(PosixTimestampAction::Keep, PosixTimestampAction::Keep);
        assert!(!plan.apply_to_inode(&mut attrs, 1234));
        assert_eq!(attrs.posix.atime_ns, original.posix.atime_ns);
        assert_eq!(attrs.posix.mtime_ns, original.posix.mtime_ns);
        assert_eq!(attrs.posix.ctime_ns, original.posix.ctime_ns);
    }
    #[test]
    fn posix_utime_plan_mixed_keep_and_explicit_advances_ctime() {
        let mut attrs = dummy_attrs(1);
        let plan = PosixUtimeTimestampPlan::new(
            PosixTimestampAction::Keep,
            PosixTimestampAction::SetNs(PosixTimestampNs::from_unix_nanos(222)),
        );
        assert!(plan.apply_to_inode(&mut attrs, 777));
        assert_eq!(attrs.posix.atime_ns, 1_000_000_000);
        assert_eq!(attrs.posix.mtime_ns, 222);
        assert_eq!(attrs.posix.ctime_ns, 777);
    }
    #[test]
    fn posix_utime_plan_from_setattr_preserves_now_action() {
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME_NOW | FATTR_MTIME;
        set.atime_ns = 11;
        set.mtime_ns = 22;
        let plan = plan_posix_utime_timestamps(&set);
        assert_eq!(
            plan,
            PosixUtimeTimestampPlan {
                atime: PosixTimestampAction::SetToNow,
                mtime: PosixTimestampAction::SetNs(PosixTimestampNs::from_unix_nanos(22)),
            }
        );
    }
    #[test]
    fn setattr_no_fields_does_not_bump_ctime() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let orig = store.getattr(1).unwrap();
        let set = SetAttr::new(); // valid == 0
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.ctime_ns, orig.posix.ctime_ns);
    }
    // ── link-count operations ────────────────────────────────────────────
    #[test]
    fn bump_link_not_found() {
        let store = MemInodeAttributeStore::new();
        assert_eq!(store.bump_link(1), Err(AttrError::InoNotFound));
    }
    #[test]
    fn bump_link_increments() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        assert_eq!(store.bump_link(1).unwrap(), 2);
        assert_eq!(store.bump_link(1).unwrap(), 3);
        let attrs = store.getattr(1).unwrap();
        assert_eq!(attrs.posix.nlink, 3);
    }
    #[test]
    fn bump_link_zero_to_one() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.nlink = 0;
        store.insert(1, attrs);
        let n = store.bump_link(1).unwrap();
        assert_eq!(n, 1);
        assert_eq!(store.getattr(1).unwrap().posix.nlink, 1);
    }
    #[test]
    fn bump_link_overflow_at_link_max() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.nlink = tidefs_inode_table::LINK_MAX;
        store.insert(1, attrs);
        assert_eq!(store.bump_link(1), Err(AttrError::LinkOverflow));
        assert_eq!(
            store.getattr(1).unwrap().posix.nlink,
            tidefs_inode_table::LINK_MAX
        );
    }
    #[test]
    fn bump_link_succeeds_at_link_max_minus_1() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.nlink = tidefs_inode_table::LINK_MAX - 1;
        store.insert(1, attrs);
        let n = store.bump_link(1).unwrap();
        assert_eq!(n, tidefs_inode_table::LINK_MAX);
        assert_eq!(store.bump_link(1), Err(AttrError::LinkOverflow));
    }
    #[test]
    fn drop_link_decrements() {
        let store = MemInodeAttributeStore::new();
        let mut a = dummy_attrs(1);
        a.posix.nlink = 3;
        store.insert(1, a);
        assert_eq!(store.drop_link(1).unwrap(), 2);
        assert_eq!(store.drop_link(1).unwrap(), 1);
        assert_eq!(store.drop_link(1).unwrap(), 0);
    }
    #[test]
    fn drop_link_underflow() {
        let store = MemInodeAttributeStore::new();
        let mut a = dummy_attrs(1);
        a.posix.nlink = 0;
        store.insert(1, a);
        assert_eq!(store.drop_link(1), Err(AttrError::LinkUnderflow));
    }
    #[test]
    fn drop_link_not_found() {
        let store = MemInodeAttributeStore::new();
        assert_eq!(store.drop_link(1), Err(AttrError::InoNotFound));
    }
    #[test]
    fn attr_error_maps_to_posix_errno() {
        assert_eq!(AttrError::InoNotFound.raw_os_error(), libc::ENOENT);
        assert_eq!(AttrError::LinkUnderflow.raw_os_error(), libc::ENOLINK);
    }
    // ── to_stat ──────────────────────────────────────────────────────────
    #[test]
    fn to_stat_maps_fields() {
        let posix = PosixAttrs {
            mode: S_IFREG | 0o755,
            uid: 1000,
            gid: 100,
            nlink: 2,
            rdev: 0,
            atime_ns: 1_500_000_000,
            mtime_ns: 2_500_000_000,
            ctime_ns: 3_500_000_000,
            btime_ns: 4_500_000_000,
            size: 1024,
            blocks_512: 2,
            blksize: 4096,
        };
        let st = to_stat(42, &posix);
        assert_eq!(st.st_ino, 42);
        assert_eq!(st.st_mode, S_IFREG | 0o755);
        assert_eq!(st.st_nlink, 2);
        assert_eq!(st.st_uid, 1000);
        assert_eq!(st.st_gid, 100);
        assert_eq!(st.st_rdev, 0);
        assert_eq!(st.st_size, 1024);
        assert_eq!(st.st_blksize, 4096);
        assert_eq!(st.st_blocks, 2);
        // timestamp split
        assert_eq!(st.st_atime, 1);
        assert_eq!(st.st_atime_nsec, 500_000_000);
        assert_eq!(st.st_mtime, 2);
        assert_eq!(st.st_mtime_nsec, 500_000_000);
        assert_eq!(st.st_ctime, 3);
        assert_eq!(st.st_ctime_nsec, 500_000_000);
    }
    #[test]
    fn store_to_stat_reads_current_attrs() {
        let store = MemInodeAttributeStore::new();
        store.insert(7, dummy_attrs(7));
        let st = store.to_stat(7).unwrap();
        assert_eq!(st.st_ino, 7);
        assert_eq!(st.st_mode, S_IFREG | 0o644);
        assert_eq!(st.st_nlink, 1);
        assert_eq!(st.st_size, 4096);
        assert_eq!(st.st_blocks, 8);
    }
    #[test]
    fn store_to_stat_not_found() {
        let store = MemInodeAttributeStore::new();
        assert!(matches!(store.to_stat(7), Err(AttrError::InoNotFound)));
    }
    // ═══════════════════════════════════════════════════════════════════
    // Extended attribute tests (MemInodeAttributeStore)
    // ═══════════════════════════════════════════════════════════════════
    #[test]
    fn xattr_set_get_roundtrip() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.set_xattr(1, b"user.key1", b"val1", 0).unwrap();
        let val = store.get_xattr(1, b"user.key1").unwrap();
        assert_eq!(val, b"val1");
    }
    #[test]
    fn xattr_set_with_create_flag_succeeds_on_new() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        assert_eq!(
            store.set_xattr(1, b"user.newkey", b"val", 1), // XATTR_CREATE
            Ok(())
        );
    }
    #[test]
    fn xattr_set_with_create_flag_fails_on_existing() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.set_xattr(1, b"user.dup", b"first", 0).unwrap();
        let err = store.set_xattr(1, b"user.dup", b"second", 1).unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::AttrExists);
    }
    #[test]
    fn xattr_set_with_replace_flag_succeeds_on_existing() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.set_xattr(1, b"user.rep", b"old", 0).unwrap();
        assert_eq!(
            store.set_xattr(1, b"user.rep", b"new", 2), // XATTR_REPLACE
            Ok(())
        );
        assert_eq!(store.get_xattr(1, b"user.rep").unwrap(), b"new");
    }
    #[test]
    fn xattr_set_with_replace_flag_fails_on_missing() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let err = store.set_xattr(1, b"user.missing", b"val", 2).unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::AttrNotFound);
    }
    #[test]
    fn xattr_remove_existing() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.set_xattr(1, b"user.del", b"val", 0).unwrap();
        assert_eq!(store.remove_xattr(1, b"user.del"), Ok(()));
        assert_eq!(
            store.get_xattr(1, b"user.del"),
            Err(tidefs_inode_table::XattrError::AttrNotFound)
        );
    }
    #[test]
    fn xattr_remove_missing_returns_not_found() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let err = store.remove_xattr(1, b"user.missing").unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::AttrNotFound);
    }
    #[test]
    fn xattr_remove_missing_inode_returns_not_found() {
        let store = MemInodeAttributeStore::new();
        let err = store.remove_xattr(42, b"user.any").unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::AttrNotFound);
    }
    #[test]
    fn xattr_list_returns_all_keys() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.set_xattr(1, b"user.a", b"1", 0).unwrap();
        store.set_xattr(1, b"user.b", b"2", 0).unwrap();
        let list = store.list_xattr(1).unwrap();
        let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.a".as_slice()));
        assert!(names.contains(&b"user.b".as_slice()));
    }
    #[test]
    fn xattr_list_empty_for_inode_with_no_xattrs() {
        let store = MemInodeAttributeStore::new();
        store.insert(99, dummy_attrs(99));
        let list = store.list_xattr(99).unwrap();
        assert!(list.is_empty());
    }
    #[test]
    fn xattr_per_inode_count_limit_enforced() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        use tidefs_inode_table::MAX_XATTR_COUNT;
        // Fill up to the limit
        for i in 0..MAX_XATTR_COUNT {
            let name = format!("user.key{i}");
            store.set_xattr(1, name.as_bytes(), b"val", 0).unwrap();
        }
        // Next one should fail with InodeXattrLimit
        let err = store
            .set_xattr(1, b"user.overlimit", b"val", 0)
            .unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::InodeXattrLimit);
    }
    #[test]
    fn xattr_per_value_size_limit_enforced() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        use tidefs_inode_table::MAX_XATTR_VALUE_LEN;
        let big = vec![0xCC; MAX_XATTR_VALUE_LEN + 1];
        let err = store.set_xattr(1, b"user.big", &big, 0).unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::ValueTooLarge);
    }
    #[test]
    fn xattr_get_size_returns_correct_size() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store
            .set_xattr(1, b"user.sized", b"hello world", 0)
            .unwrap();
        let size = store.get_xattr_size(1, b"user.sized").unwrap();
        assert_eq!(size, 11);
    }
    #[test]
    fn xattr_get_missing_inode_returns_not_found() {
        let store = MemInodeAttributeStore::new();
        let err = store.get_xattr(42, b"user.any").unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::AttrNotFound);
    }
    #[test]
    fn xattr_invalid_name_rejected() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        assert_eq!(
            store.set_xattr(1, b"", b"val", 0).unwrap_err(),
            tidefs_inode_table::XattrError::InvalidName
        );
        // NUL in name rejected
        assert_eq!(
            store
                .set_xattr(1, b"user.bad\0byte", b"val", 0)
                .unwrap_err(),
            tidefs_inode_table::XattrError::InvalidName
        );
        // Arbitrary prefix is fine at this level; namespace filtering is done
        // at the FUSE dispatch boundary.
        assert!(store.set_xattr(1, b"custom.foo", b"val", 0).is_ok());
    }
    #[test]
    fn xattr_multiple_inodes_independent() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.insert(2, dummy_attrs(2));
        store.set_xattr(1, b"user.inode1", b"a", 0).unwrap();
        store.set_xattr(2, b"user.inode2", b"b", 0).unwrap();
        assert_eq!(store.get_xattr(1, b"user.inode1").unwrap(), b"a");
        assert_eq!(store.get_xattr(2, b"user.inode2").unwrap(), b"b");
        assert_eq!(
            store.get_xattr(1, b"user.inode2"),
            Err(tidefs_inode_table::XattrError::AttrNotFound)
        );
        assert_eq!(
            store.get_xattr(2, b"user.inode1"),
            Err(tidefs_inode_table::XattrError::AttrNotFound)
        );
    }
    #[test]
    fn xattr_get_with_size_then_get_implements_erange_pattern() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store
            .set_xattr(1, b"user.sized", b"hello world", 0)
            .unwrap();
        // Step 1: caller asks for size
        let size = store.get_xattr_size(1, b"user.sized").unwrap();
        assert_eq!(size, 11);
        // Step 2: caller allocates a buffer that's too small
        let small_buf_len = 5;
        assert!(
            small_buf_len < size,
            "buffer must be too small for ERANGE test"
        );
        // Step 3: if buffer is too small, caller returns ERANGE.
        // The store doesn't implement the buffer copy directly; the
        // dispatch layer at the FUSE/engine boundary handles ERANGE after
        // discovering the value is larger than the provided buffer.
        // This test verifies the size-report path works correctly so
        // that the dispatch layer can make the ERANGE decision.
        let val = store.get_xattr(1, b"user.sized").unwrap();
        assert!(val.len() > small_buf_len);
    }
    #[test]
    fn xattr_get_size_on_missing_returns_not_found() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let err = store.get_xattr_size(1, b"user.missing").unwrap_err();
        assert_eq!(err, tidefs_inode_table::XattrError::AttrNotFound);
    }
    #[test]
    fn xattr_list_xattr_size_matches_list_xattr_len() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.set_xattr(1, b"user.a", b"x", 0).unwrap();
        store.set_xattr(1, b"user.b", b"y", 0).unwrap();
        let list = store.list_xattr(1).unwrap();
        let size = store.list_xattr_size(1).unwrap();
        assert_eq!(list.len(), size);
    }
    #[test]
    fn xattr_overwrite_with_flag_zero() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        store.set_xattr(1, b"user.key", b"first", 0).unwrap();
        store.set_xattr(1, b"user.key", b"second", 0).unwrap();
        assert_eq!(store.get_xattr(1, b"user.key").unwrap(), b"second");
    }
    // ── MemInodeAttributeStore helpers ───────────────────────────────────
    #[test]
    fn mem_store_len_and_is_empty() {
        let store = MemInodeAttributeStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        store.insert(1, dummy_attrs(1));
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }
    #[test]
    fn mem_store_remove() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        assert!(store.remove(1).is_some());
        assert!(store.remove(1).is_none());
        assert!(store.is_empty());
    }
    // ── concurrent link / unlink stress ─────────────────────────────────
    #[test]
    fn concurrent_link_unlink_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        let store = Arc::new(MemInodeAttributeStore::new());
        let mut attrs = dummy_attrs(1);
        attrs.posix.nlink = 0;
        store.insert(1, attrs);
        const N_THREADS: usize = 16;
        const N_OPS: usize = 200;
        // Phase 1: all threads bump concurrently
        let barrier = Arc::new(Barrier::new(N_THREADS));
        let mut handles = Vec::new();
        for _ in 0..N_THREADS {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                for _ in 0..N_OPS {
                    s.bump_link(1).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let after_bumps = store.getattr(1).unwrap().posix.nlink;
        assert_eq!(after_bumps, (N_THREADS * N_OPS) as u32);
        // Phase 2: all threads drop concurrently
        let barrier = Arc::new(Barrier::new(N_THREADS));
        let mut handles = Vec::new();
        for _ in 0..N_THREADS {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                for _ in 0..N_OPS {
                    s.drop_link(1).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let after_drops = store.getattr(1).unwrap().posix.nlink;
        assert_eq!(after_drops, 0);
        // nlink returned to zero: no underflows, no lost updates.
    }
    // ── prefetch_batch tests ─────────────────────────────────────────

    #[test]
    fn prefetch_batch_empty_input() {
        let store = MemInodeAttributeStore::new();
        let cache = AttrCache::new(store, 64);
        let n = cache.prefetch_batch(&[]);
        assert_eq!(n, 0);
    }

    #[test]
    fn prefetch_batch_loads_single_entry_into_cache() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let cache = AttrCache::new(store, 64);
        assert!(cache.get(1).is_none(), "cache miss before prefetch");

        let n = cache.prefetch_batch(&[1]);
        assert_eq!(n, 1, "one entry newly cached");
        assert!(cache.get(1).is_some(), "cache hit after prefetch");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn prefetch_batch_full_window_64_entries() {
        let store = MemInodeAttributeStore::new();
        for i in 0..64u64 {
            store.insert(i, dummy_attrs(i));
        }
        let cache = AttrCache::new(store, 128);
        let inos: Vec<u64> = (0..64).collect();

        let n = cache.prefetch_batch(&inos);
        assert_eq!(n, 64);
        assert_eq!(cache.len(), 64);
        for i in 0..64u64 {
            assert!(cache.get(i).is_some(), "ino {i} should be cached");
        }
    }

    #[test]
    fn prefetch_batch_already_cached_not_counted_as_new() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let cache = AttrCache::new(store, 64);

        // First prefetch: loads into cache
        let n1 = cache.prefetch_batch(&[1]);
        assert_eq!(n1, 1);

        // Second prefetch: already cached, not counted
        let n2 = cache.prefetch_batch(&[1]);
        assert_eq!(n2, 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn prefetch_batch_skips_missing_inodes() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let cache = AttrCache::new(store, 64);

        let n = cache.prefetch_batch(&[1, 999, 2, 888]);
        assert_eq!(n, 1, "only ino 1 exists in store");
        assert!(cache.get(1).is_some());
        assert!(cache.get(999).is_none());
        assert!(cache.get(2).is_none());
        assert!(cache.get(888).is_none());
    }

    #[test]
    fn prefetch_batch_mixed_cached_and_uncached() {
        let store = MemInodeAttributeStore::new();
        for i in 1..=5u64 {
            store.insert(i, dummy_attrs(i));
        }
        let cache = AttrCache::new(store, 64);

        // Pre-load some inodes
        cache.prefetch_batch(&[1, 2]);

        // Now batch includes both cached and uncached
        let n = cache.prefetch_batch(&[1, 2, 3, 4, 5]);
        assert_eq!(n, 3, "only 3, 4, 5 are newly cached");
        for i in 1..=5 {
            assert!(cache.get(i).is_some(), "ino {i} should be cached");
        }
    }

    #[test]
    fn prefetch_batch_evicts_when_over_capacity() {
        let store = MemInodeAttributeStore::new();
        for i in 0..20u64 {
            store.insert(i, dummy_attrs(i));
        }
        // Small cache: only 5 entries
        let cache = AttrCache::new(store, 5);

        let n = cache.prefetch_batch(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        // 10 attempted, but max capacity is 5
        assert_eq!(n, 10);
        // After eviction, we should have at most 5 entries
        let len = cache.len();
        assert!(len <= 5, "cache len {len} should not exceed capacity 5");
        assert!(len > 0, "cache should have at least one entry");
    }

    #[test]
    fn prefetch_batch_bumps_lru_on_already_cached() {
        let store = MemInodeAttributeStore::new();
        // Insert all entries before moving the store into the cache.
        store.insert(1, dummy_attrs(1));
        store.insert(2, dummy_attrs(2));
        store.insert(3, dummy_attrs(3));
        let cache = AttrCache::new(store, 2);

        // Load first two entries
        cache.prefetch_batch(&[1, 2]);
        assert_eq!(cache.len(), 2);

        // Access 1 via prefetch (bumps LRU above 2), then load one more
        // to trigger eviction of the LRU entry (2).
        cache.prefetch_batch(&[1]);
        cache.prefetch_batch(&[3]);

        // After eviction, ino 1 should survive (recently bumped);
        // ino 2 should have been evicted (oldest LRU).
        assert_eq!(cache.len(), 2, "cache should be at capacity 2");
        assert!(
            cache.get(1).is_some(),
            "ino 1 should survive LRU eviction after bump"
        );
        assert!(
            cache.get(2).is_none(),
            "ino 2 should have been evicted as LRU"
        );
    }

    #[test]
    fn prefetch_batch_duplicate_inodes_in_input() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let cache = AttrCache::new(store, 64);

        // Same inode listed 3 times
        let n = cache.prefetch_batch(&[1, 1, 1]);
        // Only one insertion, but the first call loads from store,
        // subsequent duplicates are already cached
        assert_eq!(n, 1, "only the first is newly cached");
        assert_eq!(cache.len(), 1);
    }

    /// Helper: insert dummy attrs if not present, then return.
    fn store_get_or_insert(store: &MemInodeAttributeStore, ino: u64) -> InodeAttr {
        match store.getattr(ino) {
            Ok(a) => a,
            Err(AttrError::InoNotFound) => {
                store.insert(ino, dummy_attrs(ino));
                store.getattr(ino).unwrap()
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ===================================================================
    // Metadata operation tests (chmod, chown, utimens, truncate, statfs)
    // ===================================================================

    // -- chmod (setattr with FATTR_MODE) ----------------------------------

    #[test]
    fn chmod_sticky_setuid_setgid_bits_preserved() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = S_IFREG | 0o644;
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = S_ISUID | S_ISGID | S_ISVTX | 0o755;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(
            updated.posix.mode,
            S_IFREG | S_ISUID | S_ISGID | S_ISVTX | 0o755
        );
        assert!(updated.posix.mode & S_ISUID != 0);
        assert!(updated.posix.mode & S_ISGID != 0);
        assert!(updated.posix.mode & S_ISVTX != 0);
    }

    #[test]
    fn chmod_zero_permission_bits() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = S_IFREG | 0o644;
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o000;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mode & !S_IFMT, 0o000);
        assert_eq!(updated.posix.mode & S_IFMT, S_IFREG);
    }

    #[test]
    fn chmod_all_permission_bits() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = S_IFREG | 0o644;
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o7777;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mode & !S_IFMT, 0o7777);
    }

    #[test]
    fn chmod_directory_preserves_type() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(2);
        attrs.kind = NodeKind::Dir;
        attrs.posix.mode = S_IFDIR | 0o755;
        store.insert(2, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o700;
        let updated = store.setattr(2, &set).unwrap();
        assert_eq!(updated.posix.mode & S_IFMT, S_IFDIR);
        assert_eq!(updated.posix.mode & !S_IFMT, 0o700);
        assert_eq!(updated.kind, NodeKind::Dir);
    }

    #[test]
    fn chmod_symlink_preserves_type() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(3);
        attrs.kind = NodeKind::Symlink;
        attrs.posix.mode = S_IFLNK | 0o777;
        store.insert(3, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o644;
        let updated = store.setattr(3, &set).unwrap();
        assert_eq!(updated.posix.mode & S_IFMT, S_IFLNK);
        assert_eq!(updated.posix.mode & !S_IFMT, 0o644);
        assert_eq!(updated.kind, NodeKind::Symlink);
    }

    #[test]
    fn chmod_getattr_reflects_change() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o600;
        store.setattr(1, &set).unwrap();

        let attrs = store.getattr(1).unwrap();
        assert_eq!(attrs.posix.mode, S_IFREG | 0o600);
    }

    // -- chown (setattr with FATTR_UID / FATTR_GID) -----------------------

    #[test]
    fn chown_uid_only_gid_unchanged() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let original = store.getattr(1).unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_UID;
        set.uid = 2000;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.uid, 2000);
        assert_eq!(updated.posix.gid, original.posix.gid);
    }

    #[test]
    fn chown_gid_only_uid_unchanged() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let original = store.getattr(1).unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = 3000;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.gid, 3000);
        assert_eq!(updated.posix.uid, original.posix.uid);
    }

    #[test]
    fn chown_uid_zero_root() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_UID;
        set.uid = 0;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.uid, 0);
    }

    #[test]
    fn chown_gid_zero_root() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = 0;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.gid, 0);
    }

    #[test]
    fn chown_uid_u32_max() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_UID;
        set.uid = u32::MAX;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.uid, u32::MAX);
    }

    #[test]
    fn chown_gid_u32_max() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = u32::MAX;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.gid, u32::MAX);
    }

    #[test]
    fn chown_noop_when_uid_gid_unchanged_still_advances_ctime() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let original = store.getattr(1).unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = original.posix.uid;
        set.gid = original.posix.gid;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.uid, original.posix.uid);
        assert_eq!(updated.posix.gid, original.posix.gid);
        assert!(updated.posix.ctime_ns >= original.posix.ctime_ns);
    }

    #[test]
    fn chown_preserves_mode_and_size() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = S_IFREG | 0o644;
        attrs.posix.size = 4096;
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = 500;
        set.gid = 600;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mode, S_IFREG | 0o644);
        assert_eq!(updated.posix.size, 4096);
    }

    // -- utimens (setattr with timestamp fields) --------------------------

    #[test]
    fn utimens_set_atime_to_zero_epoch() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME;
        set.atime_ns = 0;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, 0);
    }

    #[test]
    fn utimens_set_mtime_to_zero_epoch() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME;
        set.mtime_ns = 0;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mtime_ns, 0);
    }

    #[test]
    fn utimens_set_both_to_far_future() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = i64::MAX;
        set.mtime_ns = i64::MAX;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, i64::MAX);
        assert_eq!(updated.posix.mtime_ns, i64::MAX);
    }

    #[test]
    fn utimens_omit_atime_keep_existing() {
        let store = MemInodeAttributeStore::new();
        let original = store_get_or_insert(&store, 1);
        let before = now_ns();

        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME;
        set.mtime_ns = 999;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, original.posix.atime_ns);
        assert_eq!(updated.posix.mtime_ns, 999);
        assert!(updated.posix.ctime_ns >= before);
    }

    #[test]
    fn utimens_omit_mtime_keep_existing() {
        let store = MemInodeAttributeStore::new();
        let original = store_get_or_insert(&store, 1);
        let before = now_ns();

        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME;
        set.atime_ns = 888;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mtime_ns, original.posix.mtime_ns);
        assert_eq!(updated.posix.atime_ns, 888);
        assert!(updated.posix.ctime_ns >= before);
    }

    #[test]
    fn utimens_omit_both_no_timestamp_change() {
        let store = MemInodeAttributeStore::new();
        let original = store_get_or_insert(&store, 1);

        let set = SetAttr::new(); // valid = 0
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.atime_ns, original.posix.atime_ns);
        assert_eq!(updated.posix.mtime_ns, original.posix.mtime_ns);
        assert_eq!(updated.posix.ctime_ns, original.posix.ctime_ns);
    }

    #[test]
    fn utimens_now_atime_uses_current_time() {
        let store = MemInodeAttributeStore::new();
        let original = store_get_or_insert(&store, 1);
        let before = now_ns();

        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME_NOW;
        let updated = store.setattr(1, &set).unwrap();
        assert!(updated.posix.atime_ns >= before);
        assert_ne!(updated.posix.atime_ns, original.posix.atime_ns);
        assert!(updated.posix.ctime_ns >= before);
    }

    #[test]
    fn utimens_now_mtime_uses_current_time() {
        let store = MemInodeAttributeStore::new();
        let original = store_get_or_insert(&store, 1);
        let before = now_ns();

        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME_NOW;
        let updated = store.setattr(1, &set).unwrap();
        assert!(updated.posix.mtime_ns >= before);
        assert_ne!(updated.posix.mtime_ns, original.posix.mtime_ns);
        assert!(updated.posix.ctime_ns >= before);
    }

    #[test]
    fn utimens_nanosecond_granularity_preserved() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let test_cases: &[(i64, &str)] = &[
            (1, "one nanosecond"),
            (999_999_999, "just under one second"),
            (1_000_000_000, "exactly one second"),
            (1_000_000_001, "one nanosecond past one second"),
            (-1, "one nanosecond before epoch"),
        ];
        for &(ns, label) in test_cases {
            let mut set = SetAttr::new();
            set.valid = FATTR_ATIME;
            set.atime_ns = ns;
            let updated = store.setattr(1, &set).unwrap();
            assert_eq!(updated.posix.atime_ns, ns, "failed at: {label}");
        }
    }

    #[test]
    fn utimens_explicit_ctime_set() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_CTIME;
        set.ctime_ns = 42;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.ctime_ns, 42);
    }

    // -- truncate (setattr with FATTR_SIZE) -------------------------------

    #[test]
    fn truncate_to_zero() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.size = 8192;
        attrs.posix.blocks_512 = blocks_512_for_size(8192);
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 0;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.size, 0);
        assert_eq!(updated.posix.blocks_512, 0);
    }

    #[test]
    fn truncate_shrink() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.size = 8192;
        attrs.posix.blocks_512 = blocks_512_for_size(8192);
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 1024;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.size, 1024);
        assert_eq!(updated.posix.blocks_512, blocks_512_for_size(1024));
        assert!(updated.posix.blocks_512 < blocks_512_for_size(8192));
    }

    #[test]
    fn truncate_extend() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.size = 1024;
        attrs.posix.blocks_512 = blocks_512_for_size(1024);
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 65536;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.size, 65536);
        assert_eq!(updated.posix.blocks_512, blocks_512_for_size(65536));
        assert!(updated.posix.blocks_512 > blocks_512_for_size(1024));
    }

    #[test]
    fn truncate_preserves_mode_uid_gid() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.mode = S_IFREG | 0o644;
        attrs.posix.uid = 1000;
        attrs.posix.gid = 1000;
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 0;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.mode, S_IFREG | 0o644);
        assert_eq!(updated.posix.uid, 1000);
        assert_eq!(updated.posix.gid, 1000);
    }

    #[test]
    fn truncate_advances_ctime() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));
        let original_ctime = store.getattr(1).unwrap().posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 1024;
        let updated = store.setattr(1, &set).unwrap();
        assert!(updated.posix.ctime_ns > original_ctime);
    }

    #[test]
    fn truncate_idempotent_same_size() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.size = 4096;
        attrs.posix.blocks_512 = blocks_512_for_size(4096);
        store.insert(1, attrs);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 4096;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.size, 4096);
        assert_eq!(updated.posix.blocks_512, blocks_512_for_size(4096));
    }

    #[test]
    fn truncate_to_one_byte() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 1;
        let updated = store.setattr(1, &set).unwrap();
        assert_eq!(updated.posix.size, 1);
        assert_eq!(updated.posix.blocks_512, 1);
    }

    // -- statfs (via to_stat and store.to_stat) ---------------------------

    #[test]
    fn statfs_to_stat_for_file() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.kind = NodeKind::File;
        attrs.posix.mode = S_IFREG | 0o644;
        attrs.posix.size = 4096;
        attrs.posix.blocks_512 = blocks_512_for_size(4096);
        store.insert(1, attrs);

        let st = store.to_stat(1).unwrap();
        assert_eq!(st.st_ino, 1);
        assert_eq!(st.st_mode & S_IFMT, S_IFREG);
        assert_eq!(st.st_size, 4096);
        assert_eq!(st.st_blocks, blocks_512_for_size(4096) as i64);
    }

    #[test]
    fn statfs_to_stat_for_directory() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(2);
        attrs.kind = NodeKind::Dir;
        attrs.posix.mode = S_IFDIR | 0o755;
        store.insert(2, attrs);

        let st = store.to_stat(2).unwrap();
        assert_eq!(st.st_ino, 2);
        assert_eq!(st.st_mode & S_IFMT, S_IFDIR);
        assert_eq!(st.st_mode & !S_IFMT, 0o755);
    }

    #[test]
    fn statfs_to_stat_for_symlink() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(3);
        attrs.kind = NodeKind::Symlink;
        attrs.posix.mode = S_IFLNK | 0o777;
        store.insert(3, attrs);

        let st = store.to_stat(3).unwrap();
        assert_eq!(st.st_ino, 3);
        assert_eq!(st.st_mode & S_IFMT, S_IFLNK);
    }

    #[test]
    fn statfs_to_stat_zero_size() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.size = 0;
        attrs.posix.blocks_512 = 0;
        store.insert(1, attrs);

        let st = store.to_stat(1).unwrap();
        assert_eq!(st.st_size, 0);
        assert_eq!(st.st_blocks, 0);
    }

    #[test]
    fn statfs_to_stat_max_size() {
        let store = MemInodeAttributeStore::new();
        let mut attrs = dummy_attrs(1);
        attrs.posix.size = u64::MAX;
        attrs.posix.blocks_512 = blocks_512_for_size(u64::MAX);
        store.insert(1, attrs);

        let st = store.to_stat(1).unwrap();
        assert_eq!(st.st_size as u64, u64::MAX);
        assert_eq!(st.st_blocks, blocks_512_for_size(u64::MAX) as i64);
    }

    #[test]
    fn statfs_idempotent_across_calls() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let st1 = store.to_stat(1).unwrap();
        let st2 = store.to_stat(1).unwrap();
        assert_eq!(st1.st_ino, st2.st_ino);
        assert_eq!(st1.st_mode, st2.st_mode);
        assert_eq!(st1.st_nlink, st2.st_nlink);
        assert_eq!(st1.st_uid, st2.st_uid);
        assert_eq!(st1.st_gid, st2.st_gid);
        assert_eq!(st1.st_size, st2.st_size);
        assert_eq!(st1.st_blocks, st2.st_blocks);
        assert_eq!(st1.st_atime, st2.st_atime);
        assert_eq!(st1.st_mtime, st2.st_mtime);
        assert_eq!(st1.st_ctime, st2.st_ctime);
    }

    #[test]
    fn statfs_reflects_after_chmod() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o700;
        store.setattr(1, &set).unwrap();

        let st = store.to_stat(1).unwrap();
        assert_eq!(st.st_mode & !S_IFMT, 0o700);
    }

    #[test]
    fn statfs_reflects_after_truncate() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 12345;
        store.setattr(1, &set).unwrap();

        let st = store.to_stat(1).unwrap();
        assert_eq!(st.st_size, 12345);
        assert_eq!(st.st_blocks, blocks_512_for_size(12345) as i64);
    }

    #[test]
    fn statfs_reflects_after_chown() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = 42;
        set.gid = 84;
        store.setattr(1, &set).unwrap();

        let st = store.to_stat(1).unwrap();
        assert_eq!(st.st_uid, 42);
        assert_eq!(st.st_gid, 84);
    }

    #[test]
    fn statfs_st_dev_is_zero() {
        let store = MemInodeAttributeStore::new();
        store.insert(1, dummy_attrs(1));

        let st = store.to_stat(1).unwrap();
        assert_eq!(st.st_dev, 0);
    }

    // -- proptest: randomized attribute mutation properties ---------------

    use proptest::prelude::*;

    proptest! {
        /// Random mode changes always preserve the file type bits (S_IFMT).
        #[test]
        fn prop_chmod_preserves_type_bits(
            initial_mode in 0u32..0o777_777u32,
            new_perm_bits in 0u32..0o777_777u32,
        ) {
            let store = MemInodeAttributeStore::new();
            let mut attrs = dummy_attrs(1);
            attrs.posix.mode = (attrs.posix.mode & S_IFMT) | (initial_mode & !S_IFMT);
            let original_type = attrs.posix.mode & S_IFMT;
            store.insert(1, attrs);

            let mut set = SetAttr::new();
            set.valid = FATTR_MODE;
            set.mode = new_perm_bits;
            let updated = store.setattr(1, &set).unwrap();
            prop_assert_eq!(updated.posix.mode & S_IFMT, original_type);
        }

        /// Random size changes always produce correct blocks_512.
        #[test]
        fn prop_truncate_size_blocks_consistent(new_size in 0u64..u64::MAX) {
            let store = MemInodeAttributeStore::new();
            store.insert(1, dummy_attrs(1));

            let mut set = SetAttr::new();
            set.valid = FATTR_SIZE;
            set.size = new_size;
            let updated = store.setattr(1, &set).unwrap();
            prop_assert_eq!(updated.posix.size, new_size);
            prop_assert_eq!(updated.posix.blocks_512, blocks_512_for_size(new_size));
        }

        /// Random uid changes are reflected exactly.
        #[test]
        fn prop_chown_uid_roundtrip(new_uid in 0u32..u32::MAX) {
            let store = MemInodeAttributeStore::new();
            store.insert(1, dummy_attrs(1));

            let mut set = SetAttr::new();
            set.valid = FATTR_UID;
            set.uid = new_uid;
            let updated = store.setattr(1, &set).unwrap();
            prop_assert_eq!(updated.posix.uid, new_uid);
        }

        /// Random gid changes are reflected exactly.
        #[test]
        fn prop_chown_gid_roundtrip(new_gid in 0u32..u32::MAX) {
            let store = MemInodeAttributeStore::new();
            store.insert(1, dummy_attrs(1));

            let mut set = SetAttr::new();
            set.valid = FATTR_GID;
            set.gid = new_gid;
            let updated = store.setattr(1, &set).unwrap();
            prop_assert_eq!(updated.posix.gid, new_gid);
        }

        /// Random timestamp values are stored exactly.
        #[test]
        fn prop_utimens_atime_roundtrip(ns in any::<i64>()) {
            let store = MemInodeAttributeStore::new();
            store.insert(1, dummy_attrs(1));

            let mut set = SetAttr::new();
            set.valid = FATTR_ATIME;
            set.atime_ns = ns;
            let updated = store.setattr(1, &set).unwrap();
            prop_assert_eq!(updated.posix.atime_ns, ns);
        }

        #[test]
        fn prop_utimens_mtime_roundtrip(ns in any::<i64>()) {
            let store = MemInodeAttributeStore::new();
            store.insert(1, dummy_attrs(1));

            let mut set = SetAttr::new();
            set.valid = FATTR_MTIME;
            set.mtime_ns = ns;
            let updated = store.setattr(1, &set).unwrap();
            prop_assert_eq!(updated.posix.mtime_ns, ns);
        }
    }
}
