//! Mounted replay integration cut point (#6252).
//!
//! Wires committed-root/object/extent/inode/intent contracts into one
//! mounted POSIX kmod readback path.  Under cargo the module uses the
//! child library crates (tidefs-inode-table, tidefs-extent-map,
//! tidefs-intent-log) directly.  Under Kbuild those crates are not yet
//! linked into the kernel module (see #6257-#6263), so the Kbuild path
//! uses conservative stubs.

// --- blake3 (cargo vs Kbuild) ------------------------------------------
#[cfg(CONFIG_RUST)]
use crate::blake3;
#[cfg(not(CONFIG_RUST))]
use blake3;

// --- KernelStorageIo and RawBlockIo (test-only under cargo) ------------

// --- Errno (cargo vs Kbuild) -------------------------------------------
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::Errno;

#[cfg(CONFIG_RUST)]
pub use crate::tidefs_kmod_bridge::kernel_types::InodeAttr as InodeRecord;

// ── VRBT constants ─────────────────────────────────────────────────────

const VRBT_MAGIC: [u8; 4] = *b"VRBT";
const VRBT_VERSION: u32 = 1;
const VRBT_HEADER_SIZE: usize = 56;
pub const VRBT_WIRE_SIZE: usize = 88;
const VRBT_HASH_OFFSET: usize = 56;

// ── VrbtRoot ───────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrbtRoot {
    pub committed_txg: u64,
    pub root_ino: u64,
    pub inode_table_root: u64,
    pub extent_map_root: u64,
    pub intent_log_head: u64,
    pub intent_log_tail: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VrbtError {
    BufferTooSmall,
    BadMagic,
    UnsupportedVersion(u32),
    HashMismatch,
    DigestUnavailable,
}

pub fn decode_vrbt(bytes: &[u8]) -> Result<VrbtRoot, VrbtError> {
    if bytes.len() < VRBT_WIRE_SIZE {
        return Err(VrbtError::BufferTooSmall);
    }
    let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
    if magic != VRBT_MAGIC {
        return Err(VrbtError::BadMagic);
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != VRBT_VERSION {
        return Err(VrbtError::UnsupportedVersion(version));
    }

    #[cfg(CONFIG_RUST)]
    {
        if !blake3::blake3_available() {
            return Err(VrbtError::DigestUnavailable);
        }
    }
    let stored: [u8; 32] = bytes[VRBT_HASH_OFFSET..VRBT_WIRE_SIZE].try_into().unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes[..VRBT_HEADER_SIZE]);
    let computed: [u8; 32] = hasher.finalize().into();
    if computed != stored {
        return Err(VrbtError::HashMismatch);
    }

    let committed_txg = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let root_ino = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let inode_table_root = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let extent_map_root = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let intent_log_head = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let intent_log_tail = u64::from_le_bytes(bytes[48..56].try_into().unwrap());

    Ok(VrbtRoot {
        committed_txg,
        root_ino,
        inode_table_root,
        extent_map_root,
        intent_log_head,
        intent_log_tail,
    })
}

// ── Inline VINO-format inode record parser (cargo + Kbuild) ──────────
// Parses the 116-byte on-disk inode record (VINO format) from a byte
// buffer without requiring child crate linking.  Works under both
// cargo and Kbuild using only core primitives.

/// Decoded VINO-format inode record.
#[derive(Clone, Copy, Debug)]
pub struct VinoRecord {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub blocks: u64,
    pub atime_secs: u64,
    pub atime_nanos: u32,
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    pub ctime_secs: u64,
    pub ctime_nanos: u32,
    pub nlink: u32,
    pub generation: u64,
    pub kind: u8,
    pub object_store_locator: u64,
    pub extent_map_root: u64,
    pub btime_secs: u64,
    pub btime_nanos: u32,
    pub flags: u32,
}

const VINO_MAGIC: [u8; 4] = *b"VINO";
const VINO_RECORD_BYTES: usize = 116;

/// Parse a 116-byte VINO-format inode record from `buf`.
///
/// Returns `None` if the buffer is too short, magic doesn't match,
/// or the kind byte is invalid (not 0/1/2).
pub fn parse_vino_record(buf: &[u8]) -> Option<VinoRecord> {
    if buf.len() < VINO_RECORD_BYTES {
        return None;
    }
    if buf[0..4] != VINO_MAGIC {
        return None;
    }
    let kind = buf[80];
    if kind > 2 {
        return None; // invalid kind
    }
    // Format version at offset 81 is informational; accept any.
    let mode = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let uid = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let gid = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let size = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let blocks = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let atime_secs = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    let atime_nanos = u32::from_le_bytes(buf[40..44].try_into().unwrap());
    let mtime_secs = u64::from_le_bytes(buf[44..52].try_into().unwrap());
    let mtime_nanos = u32::from_le_bytes(buf[52..56].try_into().unwrap());
    let ctime_secs = u64::from_le_bytes(buf[56..64].try_into().unwrap());
    let ctime_nanos = u32::from_le_bytes(buf[64..68].try_into().unwrap());
    let nlink = u32::from_le_bytes(buf[68..72].try_into().unwrap());
    let generation = u64::from_le_bytes(buf[72..80].try_into().unwrap());
    let object_store_locator = u64::from_le_bytes(buf[84..92].try_into().unwrap());
    let extent_map_root = u64::from_le_bytes(buf[92..100].try_into().unwrap());
    let btime_secs = u64::from_le_bytes(buf[100..108].try_into().unwrap());
    let btime_nanos = u32::from_le_bytes(buf[108..112].try_into().unwrap());
    let flags = u32::from_le_bytes(buf[112..116].try_into().unwrap());

    Some(VinoRecord {
        mode,
        uid,
        gid,
        size,
        blocks,
        atime_secs,
        atime_nanos,
        mtime_secs,
        mtime_nanos,
        ctime_secs,
        ctime_nanos,
        nlink,
        generation,
        kind,
        object_store_locator,
        extent_map_root,
        btime_secs,
        btime_nanos,
        flags,
    })
}

/// Locate a VINO record within an inode-table buffer.
///
/// `inode_table_buf` contains the raw inode table region (starting at
/// inode 1). Inode numbers are 1-based. Returns the parsed record
/// if the inode's 116-byte slot fits within the buffer and contains
/// valid VINO magic.
pub fn read_vino_inode(inode_table_buf: &[u8], ino: u64) -> Option<VinoRecord> {
    if ino == 0 {
        return None;
    }
    let idx = (ino - 1) as usize;
    let start = idx.checked_mul(VINO_RECORD_BYTES)?;
    let end = start.checked_add(VINO_RECORD_BYTES)?;
    if end > inode_table_buf.len() {
        return None; // inode slot outside buffer
    }
    parse_vino_record(&inode_table_buf[start..end])
}

// ── Inline DirPage directory lookup (cargo + Kbuild) ─────────────────
// Scans a DirPage buffer (4 KiB, VDIR format) for a named entry.
// Works under both cargo and Kbuild using only core primitives.

const DIR_PAGE_MAGIC: [u8; 4] = *b"VDIR";
const DIR_PAGE_HEADER_LEN: usize = 16;
const DIR_ENTRY_HEADER_LEN: usize = 26;

/// Result of a DirPage entry lookup.
#[derive(Clone, Copy, Debug)]
pub struct DirPageLookup {
    pub ino: u64,
    pub entry_type: u8,
    pub kind: u8,
}

/// Scan a DirPage buffer for an entry with `name`.
///
/// The buffer must be at least DIR_PAGE_HEADER_LEN bytes and start
/// with "VDIR" magic. Entries are scanned linearly; the first
/// matching name wins. Returns `None` if the buffer is invalid or
/// the name is not found.
pub fn lookup_dir_page(dir_page_buf: &[u8], name: &[u8]) -> Option<DirPageLookup> {
    if dir_page_buf.len() < DIR_PAGE_HEADER_LEN {
        return None;
    }
    if dir_page_buf[0..4] != DIR_PAGE_MAGIC {
        return None;
    }
    // entry_count at offset 8 (u16 LE)
    let entry_count = u16::from_le_bytes(dir_page_buf[8..10].try_into().unwrap()) as usize;

    let mut pos: usize = DIR_PAGE_HEADER_LEN;
    for _ in 0..entry_count {
        if pos + DIR_ENTRY_HEADER_LEN > dir_page_buf.len() {
            return None;
        }
        let name_len = dir_page_buf[pos] as usize;
        let entry_end = pos + DIR_ENTRY_HEADER_LEN + name_len;
        if entry_end > dir_page_buf.len() {
            return None;
        }
        let entry_name = &dir_page_buf[pos + DIR_ENTRY_HEADER_LEN..entry_end];
        if entry_name == name {
            let ino = u64::from_le_bytes(dir_page_buf[pos + 1..pos + 9].try_into().unwrap());
            let entry_type = dir_page_buf[pos + 9];
            // entry_type follows DirPage convention: DT_DIR=0, DT_FILE=1, DT_SYMLINK=2
            let kind = entry_type;
            return Some(DirPageLookup {
                ino,
                entry_type,
                kind,
            });
        }
        pos = entry_end;
    }
    None
}

// ── Inline DirPage sequential iteration (cargo + Kbuild) ─────────────
// Iterates DirPage entries in cookie order for readdir/iterate_shared.
// Works under both cargo and Kbuild using only core primitives.

/// Result of a DirPage entry iteration step.
#[derive(Clone, Copy, Debug)]
pub struct DirPageIterEntry {
    pub ino: u64,
    pub entry_type: u8,
    pub kind: u8,
    pub name_offset: u32,
    pub name_len: u8,
    /// Cookie for the next call (0 = end of page).
    pub next_cookie: u32,
}

/// Iterate DirPage entries starting from `cookie`.
///
/// `cookie` is the byte offset within the entries area of the DirPage.
/// Cookie 0 means start from the first entry. The returned entry
/// includes the cookie for the next call in `next_cookie`.
///
/// Returns `None` if the buffer is invalid, or when all entries have
/// been returned (cookie past the last entry).
pub fn iterate_dir_page(dir_page_buf: &[u8], cookie: u32) -> Option<DirPageIterEntry> {
    if dir_page_buf.len() < DIR_PAGE_HEADER_LEN {
        return None;
    }
    if dir_page_buf[0..4] != DIR_PAGE_MAGIC {
        return None;
    }
    let entry_count = u16::from_le_bytes(dir_page_buf[8..10].try_into().unwrap()) as usize;
    if entry_count == 0 {
        return None;
    }

    // cookie is a byte offset within entries; map to the entry index.
    let mut pos: usize = DIR_PAGE_HEADER_LEN;

    for current_cookie in 0..entry_count as u32 {
        if pos + DIR_ENTRY_HEADER_LEN > dir_page_buf.len() {
            return None;
        }
        let name_len = dir_page_buf[pos] as usize;
        let entry_end = pos + DIR_ENTRY_HEADER_LEN + name_len;
        if entry_end > dir_page_buf.len() {
            return None;
        }

        if current_cookie >= cookie {
            // Found the next entry to emit.
            let ino = u64::from_le_bytes(dir_page_buf[pos + 1..pos + 9].try_into().unwrap());
            let entry_type = dir_page_buf[pos + 9];
            let entry = DirPageIterEntry {
                ino,
                entry_type,
                kind: entry_type,
                name_offset: (pos + DIR_ENTRY_HEADER_LEN) as u32,
                name_len: name_len as u8,
                next_cookie: current_cookie + 1,
            };
            return Some(entry);
        }

        pos = entry_end;
    }
    None // end of page
}

// ── Inline EXMP extent-map leaf page parser (cargo + Kbuild) ─────────
// Parses the on-disk extent map page format (54-byte header + 89-byte
// ExtentMapEntryV2 records) and resolves a logical file offset to a
// physical extent mapping. Works under both cargo and Kbuild using
// only core primitives and BLAKE3 from kmod-bridge.

pub const EXMP_MAGIC: [u8; 4] = *b"EXMP";
pub const EXMP_PAGE_HEADER_SIZE: usize = 54;
pub const EXMP_ENTRY_V2_SIZE: usize = 89;
pub const EXMP_PAGE_HASHED_HEADER_LEN: usize = 22;
pub const EXMP_PAGE_CHECKSUM_OFFSET: usize = 22;
#[allow(dead_code)]
const EXMP_DEFAULT_PAGE_SIZE: usize = 4096;

/// Decoded extent map leaf page.
#[derive(Clone, Debug)]
pub struct ExmpLeafPage {
    pub entry_count: u16,
    pub level: u8,
}

/// A single extent map entry (V2 on-disk format, 89 bytes).
#[derive(Clone, Copy, Debug)]
pub struct ExmpEntry {
    pub logical_offset: u64,
    pub length: u64,
    pub extent_kind: u8,
    pub locator_id: u64,
    pub birth_commit_group: u64,
}

impl ExmpEntry {
    /// End offset of this extent (logical_offset + length).
    #[must_use]
    pub const fn end_offset(&self) -> u64 {
        self.logical_offset + self.length
    }

    /// Whether this extent covers the given logical offset.
    #[must_use]
    pub fn covers(&self, offset: u64) -> bool {
        offset >= self.logical_offset && offset < self.end_offset()
    }

    /// Whether this is a data extent (not unwritten, not hole).
    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.extent_kind == 0
    }

    /// Whether this is an unwritten extent.
    #[must_use]
    pub const fn is_unwritten(&self) -> bool {
        self.extent_kind == 1
    }
}

/// Errors from EXMP page parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExmpError {
    BufferTooSmall,
    BadMagic,
    NotLeafPage,
    ChecksumMismatch,
    DigestUnavailable,
    CorruptEntry,
    NotFound,
}

/// Parse the EXMP page header (first 54 bytes) and verify BLAKE3 checksum.
///
/// `page_buf` must be at least EXMP_PAGE_HEADER_SIZE bytes. On success
/// returns the page metadata. The checksum covers bytes 0..22 (hashed
/// header) + the body bytes (from offset 54 to end of used area).
pub fn parse_exmp_header(page_buf: &[u8]) -> Result<ExmpLeafPage, ExmpError> {
    if page_buf.len() < EXMP_PAGE_HEADER_SIZE {
        return Err(ExmpError::BufferTooSmall);
    }
    if page_buf[0..4] != EXMP_MAGIC {
        return Err(ExmpError::BadMagic);
    }
    let page_kind = page_buf[4];
    if page_kind != 0 {
        // 0 = leaf; internal pages (1) are not supported by this inline parser.
        return Err(ExmpError::NotLeafPage);
    }
    let entry_count = u16::from_le_bytes(page_buf[6..8].try_into().unwrap());
    let level = page_buf[8];

    // Verify BLAKE3-256 checksum: hash of hashed_header[0..22] + body data.
    #[cfg(CONFIG_RUST)]
    {
        if !blake3::blake3_available() {
            return Err(ExmpError::DigestUnavailable);
        }
    }

    // Body starts at offset 54 and extends to entry_count * 89 bytes.
    let body_end = EXMP_PAGE_HEADER_SIZE
        .checked_add(
            EXMP_ENTRY_V2_SIZE
                .checked_mul(entry_count as usize)
                .unwrap_or(0),
        )
        .ok_or(ExmpError::CorruptEntry)?;
    if body_end > page_buf.len() {
        return Err(ExmpError::BufferTooSmall);
    }

    let stored_checksum: [u8; 32] = page_buf[EXMP_PAGE_CHECKSUM_OFFSET..EXMP_PAGE_HEADER_SIZE]
        .try_into()
        .unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&page_buf[..EXMP_PAGE_HASHED_HEADER_LEN]);
    hasher.update(&page_buf[EXMP_PAGE_HEADER_SIZE..body_end]);
    let computed: [u8; 32] = hasher.finalize().into();
    if computed != stored_checksum {
        return Err(ExmpError::ChecksumMismatch);
    }

    Ok(ExmpLeafPage { entry_count, level })
}

/// Decode a single ExtentMapEntryV2 from a byte slice.
///
/// `buf` must be at least 89 bytes.
pub fn decode_exmp_entry(buf: &[u8]) -> Option<ExmpEntry> {
    if buf.len() < EXMP_ENTRY_V2_SIZE {
        return None;
    }
    let logical_offset = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let length = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let extent_kind = buf[16];
    // byte 17 = flags (skip)
    let locator_id = u64::from_le_bytes(buf[18..26].try_into().unwrap());
    // bytes 26..58 = checksum (32 bytes, skip)
    let birth_commit_group = u64::from_le_bytes(buf[58..66].try_into().unwrap());
    // bytes 66..89 = reserved (15 bytes, skip)

    // Validate kind: 0=data, 1=unwritten. Others are invalid.
    if extent_kind > 1 {
        return None;
    }
    // Validate length is non-zero.
    if length == 0 {
        return None;
    }

    Some(ExmpEntry {
        logical_offset,
        length,
        extent_kind,
        locator_id,
        birth_commit_group,
    })
}

/// Look up an extent in a leaf page for a given logical offset.
///
/// `page_buf` is a full EXMP page (4096 bytes typically). Returns the
/// first entry whose byte range covers `logical_offset`, or `NotFound`
/// if no entry matches. Entries are assumed sorted by logical_offset.
pub fn lookup_exmp_extent(page_buf: &[u8], logical_offset: u64) -> Result<ExmpEntry, ExmpError> {
    let page = parse_exmp_header(page_buf)?;
    let mut pos = EXMP_PAGE_HEADER_SIZE;
    for _ in 0..page.entry_count {
        let entry = decode_exmp_entry(&page_buf[pos..]).ok_or(ExmpError::CorruptEntry)?;
        if entry.covers(logical_offset) {
            return Ok(entry);
        }
        pos = pos
            .checked_add(EXMP_ENTRY_V2_SIZE)
            .ok_or(ExmpError::CorruptEntry)?;
    }
    Err(ExmpError::NotFound)
}
// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(all(test, not(CONFIG_RUST)))]
mod tests {
    use super::*;

    fn make_vrbt(
        txg: u64,
        root_ino: u64,
        inode_table_root: u64,
        extent_map_root: u64,
    ) -> [u8; VRBT_WIRE_SIZE] {
        let mut buf = [0u8; VRBT_WIRE_SIZE];
        buf[0..4].copy_from_slice(&VRBT_MAGIC);
        buf[4..8].copy_from_slice(&VRBT_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&txg.to_le_bytes());
        buf[16..24].copy_from_slice(&root_ino.to_le_bytes());
        buf[24..32].copy_from_slice(&inode_table_root.to_le_bytes());
        buf[32..40].copy_from_slice(&extent_map_root.to_le_bytes());
        let mut hasher = blake3::Hasher::new();
        hasher.update(&buf[..VRBT_HEADER_SIZE]);
        buf[VRBT_HASH_OFFSET..VRBT_WIRE_SIZE].copy_from_slice(hasher.finalize().as_bytes());
        buf
    }

    #[test]
    fn decode_vrbt_valid() {
        let vrbt = make_vrbt(42, 1, 4096, 8192);
        let d = decode_vrbt(&vrbt).unwrap();
        assert_eq!(d.committed_txg, 42);
        assert_eq!(d.root_ino, 1);
        assert_eq!(d.inode_table_root, 4096);
        assert_eq!(d.extent_map_root, 8192);
    }

    #[test]
    fn decode_vrbt_bad_magic() {
        let mut vrbt = make_vrbt(1, 1, 0, 0);
        vrbt[0] = b'X';
        assert!(matches!(
            decode_vrbt(&vrbt).unwrap_err(),
            VrbtError::BadMagic
        ));
    }

    #[test]
    fn decode_vrbt_buffer_too_small() {
        assert!(matches!(
            decode_vrbt(&[0u8; 40]).unwrap_err(),
            VrbtError::BufferTooSmall
        ));
    }

    #[test]
    fn decode_vrbt_hash_mismatch() {
        let mut vrbt = make_vrbt(42, 1, 4096, 8192);
        vrbt[10] ^= 0xFF;
        assert!(matches!(
            decode_vrbt(&vrbt).unwrap_err(),
            VrbtError::HashMismatch
        ));
    }

    #[test]
    fn mounted_replay_root_inode_readback_via_inline() {
        // Use the inline VINO parser directly instead of
        // MountedReplayContext (which requires KernelInodeTableReader).
        let mut storage = alloc::vec![0u8; 16384usize];
        let record_bytes: [u8; 100] = {
            let mut r = [0u8; 100];
            r[0..4].copy_from_slice(b"VINO");
            r[4..8].copy_from_slice(&0o040755u32.to_le_bytes()); // dir mode
            r[16..24].copy_from_slice(&4096u64.to_le_bytes());
            r[68..72].copy_from_slice(&1u32.to_le_bytes()); // nlink
            r[80] = 1; // kind = Directory
            r[81] = 1; // format_version
            r
        };
        storage[0..100].copy_from_slice(&record_bytes);
        // Read inode 1 from the raw buffer.
        let rec = read_vino_inode(&storage, 1).unwrap();
        assert_eq!(rec.kind, 1); // Directory
        assert_eq!(rec.nlink, 1);
        assert_eq!(rec.size, 4096);
    }
    #[test]
    fn parse_vino_record_valid() {
        let mut buf = [0u8; VINO_RECORD_BYTES];
        buf[0..4].copy_from_slice(b"VINO");
        buf[4..8].copy_from_slice(&0o100755u32.to_le_bytes()); // mode
        buf[8..12].copy_from_slice(&1000u32.to_le_bytes()); // uid
        buf[12..16].copy_from_slice(&1000u32.to_le_bytes()); // gid
        buf[16..24].copy_from_slice(&4096u64.to_le_bytes()); // size
        buf[24..32].copy_from_slice(&8u64.to_le_bytes()); // blocks
        buf[32..40].copy_from_slice(&1700000000u64.to_le_bytes()); // atime
        buf[44..52].copy_from_slice(&1700000001u64.to_le_bytes()); // mtime
        buf[56..64].copy_from_slice(&1700000002u64.to_le_bytes()); // ctime
        buf[68..72].copy_from_slice(&1u32.to_le_bytes()); // nlink
        buf[72..80].copy_from_slice(&5u64.to_le_bytes()); // generation
        buf[80] = 1; // kind = Directory
        buf[81] = 1; // format_version
        buf[84..92].copy_from_slice(&0x1000u64.to_le_bytes()); // object_store_locator
        buf[92..100].copy_from_slice(&0x2000u64.to_le_bytes()); // extent_map_root
        let rec = parse_vino_record(&buf).unwrap();
        assert_eq!(rec.mode, 0o100755);
        assert_eq!(rec.uid, 1000);
        assert_eq!(rec.gid, 1000);
        assert_eq!(rec.size, 4096);
        assert_eq!(rec.blocks, 8);
        assert_eq!(rec.nlink, 1);
        assert_eq!(rec.generation, 5);
        assert_eq!(rec.kind, 1);
        assert_eq!(rec.object_store_locator, 0x1000);
        assert_eq!(rec.extent_map_root, 0x2000);
    }

    #[test]
    fn parse_vino_record_bad_magic() {
        let mut buf = [0u8; VINO_RECORD_BYTES];
        buf[80] = 0;
        buf[81] = 1;
        assert!(parse_vino_record(&buf).is_none());
    }

    #[test]
    fn parse_vino_record_buffer_too_small() {
        assert!(parse_vino_record(&[0u8; 50]).is_none());
    }

    #[test]
    fn parse_vino_record_invalid_kind() {
        let mut buf = [0u8; VINO_RECORD_BYTES];
        buf[0..4].copy_from_slice(b"VINO");
        buf[80] = 5; // invalid kind
        buf[81] = 1;
        assert!(parse_vino_record(&buf).is_none());
    }

    #[test]
    fn read_vino_inode_ino_zero() {
        assert!(read_vino_inode(&[0u8; 200], 0).is_none());
    }

    #[test]
    fn read_vino_inode_out_of_range() {
        let buf = [0u8; 100]; // only room for inode 1
        assert!(read_vino_inode(&buf, 2).is_none());
    }

    #[test]
    fn lookup_dir_page_finds_entry() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"VDIR");
        page[4..8].copy_from_slice(&0u32.to_le_bytes()); // page_number
        page[8..10].copy_from_slice(&1u16.to_le_bytes()); // entry_count = 1
        let pos = DIR_PAGE_HEADER_LEN;
        page[pos] = 5; // name_len = 5
        page[pos + 1..pos + 9].copy_from_slice(&42u64.to_le_bytes()); // ino = 42
        page[pos + 9] = 0; // entry_type = DT_DIR
        page[pos + 26..pos + 31].copy_from_slice(b"hello");
        let result = lookup_dir_page(&page, b"hello").unwrap();
        assert_eq!(result.ino, 42);
        assert_eq!(result.entry_type, 0);
        assert_eq!(result.kind, 0);
    }

    #[test]
    fn lookup_dir_page_not_found() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"VDIR");
        // entry_count stays 0
        assert!(lookup_dir_page(&page, b"nope").is_none());
    }

    #[test]
    fn lookup_dir_page_bad_magic() {
        let page = [0u8; 4096]; // no VDIR magic
        assert!(lookup_dir_page(&page, b"test").is_none());
    }

    #[test]
    fn lookup_dir_page_buffer_too_small() {
        assert!(lookup_dir_page(&[0u8; 8], b"test").is_none());
    }

    #[test]
    fn iterate_dir_page_basic_iteration() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"VDIR");
        page[8..10].copy_from_slice(&3u16.to_le_bytes()); // 3 entries
                                                          // Entry 0: name "aaa", ino 10
        let pos0 = DIR_PAGE_HEADER_LEN;
        page[pos0] = 3;
        page[pos0 + 1..pos0 + 9].copy_from_slice(&10u64.to_le_bytes());
        page[pos0 + 9] = 1; // DT_FILE
        page[pos0 + 26..pos0 + 29].copy_from_slice(b"aaa");
        // Entry 1: name "bbb", ino 20
        let pos1 = pos0 + DIR_ENTRY_HEADER_LEN + 3;
        page[pos1] = 3;
        page[pos1 + 1..pos1 + 9].copy_from_slice(&20u64.to_le_bytes());
        page[pos1 + 9] = 0; // DT_DIR
        page[pos1 + 26..pos1 + 29].copy_from_slice(b"bbb");
        // Entry 2: name "ccc", ino 30
        let pos2 = pos1 + DIR_ENTRY_HEADER_LEN + 3;
        page[pos2] = 3;
        page[pos2 + 1..pos2 + 9].copy_from_slice(&30u64.to_le_bytes());
        page[pos2 + 9] = 1; // DT_FILE
        page[pos2 + 26..pos2 + 29].copy_from_slice(b"ccc");

        let e0 = iterate_dir_page(&page, 0).unwrap();
        assert_eq!(e0.ino, 10);
        assert_eq!(e0.next_cookie, 1);
        let e1 = iterate_dir_page(&page, e0.next_cookie).unwrap();
        assert_eq!(e1.ino, 20);
        assert_eq!(e1.next_cookie, 2);
        let e2 = iterate_dir_page(&page, e1.next_cookie).unwrap();
        assert_eq!(e2.ino, 30);
        assert_eq!(e2.next_cookie, 3);
        assert!(iterate_dir_page(&page, 3).is_none());
    }

    #[test]
    fn iterate_dir_page_resume_from_cookie() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"VDIR");
        page[8..10].copy_from_slice(&2u16.to_le_bytes());
        let pos0 = DIR_PAGE_HEADER_LEN;
        page[pos0] = 3;
        page[pos0 + 1..pos0 + 9].copy_from_slice(&10u64.to_le_bytes());
        page[pos0 + 9] = 1;
        page[pos0 + 26..pos0 + 29].copy_from_slice(b"aaa");
        let pos1 = pos0 + DIR_ENTRY_HEADER_LEN + 3;
        page[pos1] = 3;
        page[pos1 + 1..pos1 + 9].copy_from_slice(&20u64.to_le_bytes());
        page[pos1 + 9] = 1;
        page[pos1 + 26..pos1 + 29].copy_from_slice(b"bbb");
        // Start from cookie 1 (second entry)
        let e1 = iterate_dir_page(&page, 1).unwrap();
        assert_eq!(e1.ino, 20);
        assert_eq!(e1.next_cookie, 2);
    }

    #[test]
    fn iterate_dir_page_empty() {
        let mut page = [0u8; 4096];
        page[0..4].copy_from_slice(b"VDIR");
        // entry_count = 0
        assert!(iterate_dir_page(&page, 0).is_none());
    }

    #[test]
    fn iterate_dir_page_bad_magic() {
        let page = [0u8; 4096];
        assert!(iterate_dir_page(&page, 0).is_none());
    }

    #[test]
    fn iterate_dir_page_buffer_too_small() {
        assert!(iterate_dir_page(&[0u8; 8], 0).is_none());
    }

    // ── Helper: build a valid EXMP leaf page with entries ─────────────
    fn make_exmp_page(entries: &[ExmpEntry]) -> alloc::vec::Vec<u8> {
        let body_bytes = entries.len() * EXMP_ENTRY_V2_SIZE;
        let total = EXMP_PAGE_HEADER_SIZE + body_bytes;
        let mut page = alloc::vec![0u8; total];
        // Header
        page[0..4].copy_from_slice(b"EXMP");
        page[4] = 0; // page_kind = leaf
                     // byte 5 = flags = 0
        let count: u16 = entries.len() as u16;
        page[6..8].copy_from_slice(&count.to_le_bytes());
        page[8] = 0; // level = 0
                     // bytes 9..21 = zero padding
                     // Body
        for (i, e) in entries.iter().enumerate() {
            let off = EXMP_PAGE_HEADER_SIZE + i * EXMP_ENTRY_V2_SIZE;
            page[off..off + 8].copy_from_slice(&e.logical_offset.to_le_bytes());
            page[off + 8..off + 16].copy_from_slice(&e.length.to_le_bytes());
            page[off + 16] = e.extent_kind;
            // byte 17 = flags = 0
            page[off + 18..off + 26].copy_from_slice(&e.locator_id.to_le_bytes());
            // bytes 26..58 = checksum (zero — we'll compute below)
            page[off + 58..off + 66].copy_from_slice(&e.birth_commit_group.to_le_bytes());
        }
        // Compute BLAKE3 checksum: hash of hashed_header + body
        let mut hasher = blake3::Hasher::new();
        hasher.update(&page[..EXMP_PAGE_HASHED_HEADER_LEN]);
        hasher.update(&page[EXMP_PAGE_HEADER_SIZE..]);
        let digest: [u8; 32] = hasher.finalize().into();
        page[EXMP_PAGE_CHECKSUM_OFFSET..EXMP_PAGE_HEADER_SIZE].copy_from_slice(&digest);
        page
    }

    #[test]
    fn parse_exmp_header_valid() {
        let page = make_exmp_page(&[ExmpEntry {
            logical_offset: 0,
            length: 4096,
            extent_kind: 0,
            locator_id: 42,
            birth_commit_group: 1,
        }]);
        let hdr = parse_exmp_header(&page).unwrap();
        assert_eq!(hdr.entry_count, 1);
        assert_eq!(hdr.level, 0);
    }

    #[test]
    fn parse_exmp_header_bad_magic() {
        let mut page = make_exmp_page(&[]);
        page[0] = b'X';
        assert!(matches!(
            parse_exmp_header(&page).unwrap_err(),
            ExmpError::BadMagic
        ));
    }

    #[test]
    fn parse_exmp_header_buffer_too_small() {
        assert!(matches!(
            parse_exmp_header(&[0u8; 10]).unwrap_err(),
            ExmpError::BufferTooSmall
        ));
    }

    #[test]
    fn parse_exmp_header_checksum_mismatch() {
        let mut page = make_exmp_page(&[ExmpEntry {
            logical_offset: 0,
            length: 4096,
            extent_kind: 0,
            locator_id: 1,
            birth_commit_group: 1,
        }]);
        // Flip a body byte to break checksum.
        page[EXMP_PAGE_HEADER_SIZE] ^= 0xFF;
        assert!(matches!(
            parse_exmp_header(&page).unwrap_err(),
            ExmpError::ChecksumMismatch
        ));
    }

    #[test]
    fn decode_exmp_entry_valid() {
        let page = make_exmp_page(&[ExmpEntry {
            logical_offset: 4096,
            length: 8192,
            extent_kind: 0,
            locator_id: 0xABCD,
            birth_commit_group: 7,
        }]);
        let entry = decode_exmp_entry(&page[EXMP_PAGE_HEADER_SIZE..]).unwrap();
        assert_eq!(entry.logical_offset, 4096);
        assert_eq!(entry.length, 8192);
        assert_eq!(entry.extent_kind, 0);
        assert_eq!(entry.locator_id, 0xABCD);
        assert_eq!(entry.birth_commit_group, 7);
    }

    #[test]
    fn decode_exmp_entry_unwritten() {
        let page = make_exmp_page(&[ExmpEntry {
            logical_offset: 0,
            length: 4096,
            extent_kind: 1,
            locator_id: 0,
            birth_commit_group: 1,
        }]);
        let entry = decode_exmp_entry(&page[EXMP_PAGE_HEADER_SIZE..]).unwrap();
        assert!(entry.is_unwritten());
        assert!(!entry.is_data());
    }

    #[test]
    fn lookup_exmp_extent_finds_match() {
        let page = make_exmp_page(&[
            ExmpEntry {
                logical_offset: 0,
                length: 4096,
                extent_kind: 0,
                locator_id: 10,
                birth_commit_group: 1,
            },
            ExmpEntry {
                logical_offset: 4096,
                length: 4096,
                extent_kind: 0,
                locator_id: 20,
                birth_commit_group: 1,
            },
            ExmpEntry {
                logical_offset: 8192,
                length: 4096,
                extent_kind: 0,
                locator_id: 30,
                birth_commit_group: 1,
            },
        ]);
        let e = lookup_exmp_extent(&page, 5000).unwrap();
        assert_eq!(e.locator_id, 20);
        assert_eq!(e.logical_offset, 4096);
    }

    #[test]
    fn lookup_exmp_extent_not_found() {
        let page = make_exmp_page(&[ExmpEntry {
            logical_offset: 0,
            length: 4096,
            extent_kind: 0,
            locator_id: 42,
            birth_commit_group: 1,
        }]);
        assert!(matches!(
            lookup_exmp_extent(&page, 8192).unwrap_err(),
            ExmpError::NotFound
        ));
    }

    #[test]
    fn exmp_entry_covers_boundary() {
        let e = ExmpEntry {
            logical_offset: 0,
            length: 4096,
            extent_kind: 0,
            locator_id: 1,
            birth_commit_group: 1,
        };
        assert!(e.covers(0));
        assert!(e.covers(4095));
        assert!(!e.covers(4096));
    }
}
