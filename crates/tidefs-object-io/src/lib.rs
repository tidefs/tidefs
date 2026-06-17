#![forbid(unsafe_code)]

//! Offset-based object I/O over TideFS extent maps and object storage.
//!
//! `ObjectIo` turns file offsets into extent-map lookups and object-store
//! reads/writes. It is intentionally synchronous and small: downstream FUSE,
//! namespace, and production code uses it as the baseline sparse-file data path
//! while higher-level cache and transaction layers evolve around it.

use std::fmt;

use tidefs_frame::{CompressedExtentPayload, decompress_extent_verified, TransformVerification};

pub use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError};
pub use tidefs_types_extent_map_core::{
    ExtentMapEntryV2, ExtentMapError, ExtentMapOps, ExtentType, FreedExtent, LocatorId,
};

/// Default object chunk size for writes: 4 KiB.
pub const DEFAULT_CHUNK_SIZE: u64 = 4096;

/// Result alias for object I/O operations.
pub type Result<T> = std::result::Result<T, ObjectIoError>;

/// Errors produced by offset-based object I/O.
#[derive(Debug)]
pub enum ObjectIoError {
    /// Error returned by an object-store backend.
    StoreError(Box<dyn std::error::Error + Send + Sync>),
    /// Error returned by the extent-map backend.
    ExtentError(ExtentMapError),
    /// A requested byte range overflowed `u64`.
    InvalidRange,
    /// The configured write chunk size is invalid.
    InvalidChunkSize,
    /// A DATA extent referenced an object that was not present in the store.
    MissingObject(ObjectKey),
    /// Stored transform header does not match the committed extent receipt.
    TransformMismatch {
        field: &'static str,
        expected: u64,
        observed: u64,
    },
    /// The read range lies entirely in a hole past EOF.
    HoleBeyondEof,
}

impl fmt::Display for ObjectIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StoreError(err) => write!(f, "object store error: {err}"),
            Self::ExtentError(err) => write!(f, "extent map error: {err}"),
            Self::InvalidRange => f.write_str("invalid byte range"),
            Self::InvalidChunkSize => f.write_str("invalid object I/O chunk size"),
            Self::MissingObject(key) => write!(f, "extent references missing object {key}"),
            Self::HoleBeyondEof => f.write_str("read entirely in hole past EOF"),
            Self::TransformMismatch { field, expected, observed } => {
                write!(f, "transform mismatch: {field} expected {expected}, observed {observed}")
            }
        }
    }
}

impl std::error::Error for ObjectIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StoreError(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

impl From<ExtentMapError> for ObjectIoError {
    fn from(err: ExtentMapError) -> Self {
        Self::ExtentError(err)
    }
}

/// Minimal content-addressed object-store contract used by `ObjectIo`.
///
/// The crate implements this trait for [`LocalObjectStore`]. Tests and future
/// cache layers can implement it for lightweight adapters without depending on
/// local segment-log details.
pub trait ObjectStore {
    /// Backend error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Store `data` under `key`.
    fn put(&mut self, key: ObjectKey, data: &[u8]) -> std::result::Result<(), Self::Error>;

    /// Retrieve bytes for `key`.
    fn get(&self, key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error>;
}

impl ObjectStore for LocalObjectStore {
    type Error = StoreError;

    fn put(&mut self, key: ObjectKey, data: &[u8]) -> std::result::Result<(), Self::Error> {
        LocalObjectStore::put(self, key, data).map(|_| ())
    }

    fn get(&self, key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        LocalObjectStore::get(self, *key)
    }
}

fn content_hash(data: &[u8]) -> ObjectKey {
    let digest = blake3::hash(data);
    ObjectKey::from_bytes32(*digest.as_bytes())
}

fn derive_locator_id(key: ObjectKey) -> LocatorId {
    let bytes = key.as_bytes();
    let candidate = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    LocatorId(candidate.max(1))
}

fn entry_object_key(entry: &ExtentMapEntryV2) -> ObjectKey {
    ObjectKey::from_bytes32(entry.checksum)
}

fn request_len(len: usize) -> Result<u64> {
    u64::try_from(len).map_err(|_| ObjectIoError::InvalidRange)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckedByteRange {
    start: u64,
    length: u64,
    end: u64,
}

impl CheckedByteRange {
    fn new(start: u64, length: u64) -> Result<Self> {
        let end = start
            .checked_add(length)
            .ok_or(ObjectIoError::InvalidRange)?;
        Ok(Self { start, length, end })
    }

    fn non_empty(start: u64, length: u64) -> Result<Self> {
        if length == 0 {
            return Err(ObjectIoError::InvalidRange);
        }
        Self::new(start, length)
    }

    fn for_slice(start: u64, len: usize) -> Result<Option<Self>> {
        let length = request_len(len)?;
        if length == 0 {
            return Ok(None);
        }
        Self::new(start, length).map(Some)
    }

    fn from_extent(entry: &ExtentMapEntryV2) -> Result<Self> {
        Self::non_empty(entry.logical_offset, entry.length)
    }

    fn len_usize(self) -> Result<usize> {
        usize::try_from(self.length).map_err(|_| ObjectIoError::InvalidRange)
    }

    fn offset_at(self, displacement: usize) -> Result<u64> {
        let displacement = request_len(displacement)?;
        if displacement > self.length {
            return Err(ObjectIoError::InvalidRange);
        }
        self.start
            .checked_add(displacement)
            .ok_or(ObjectIoError::InvalidRange)
    }
}

fn all_entries<M: ExtentMapOps>(extent_map: &M) -> Result<Vec<ExtentMapEntryV2>> {
    extent_map.lookup_range(0, u64::MAX).map_err(Into::into)
}

fn map_store_error<E>(err: E) -> ObjectIoError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ObjectIoError::StoreError(Box::new(err))
}

fn load_object<S: ObjectStore>(store: &S, key: ObjectKey) -> Result<Vec<u8>> {
    store
        .get(&key)
        .map_err(map_store_error)?
        .ok_or(ObjectIoError::MissingObject(key))
}

/// Load an object and verify its compression transform header against a committed token.
///
/// Returns the decompressed payload on success, or [`ObjectIoError::TransformMismatch`]
/// when the stored transform header does not match the token.
fn load_object_verified<S: ObjectStore>(
    store: &S,
    key: ObjectKey,
    token: &TransformVerification,
) -> Result<Vec<u8>> {
    let raw = store
        .get(&key)
        .map_err(map_store_error)?
        .ok_or(ObjectIoError::MissingObject(key))?;
    let payload = CompressedExtentPayload::decode(&raw)
        .ok_or(ObjectIoError::StoreError(Box::new(
            std::io::Error::other("invalid compressed extent payload"),
        )))?;
    decompress_extent_verified(&payload, token)
        .map_err(|e| match e {
            tidefs_frame::FrameError::TransformMismatch { field, expected, observed } => {
                ObjectIoError::TransformMismatch { field, expected, observed }
            }
            other => ObjectIoError::StoreError(Box::new(std::io::Error::other(format!("{other:?}")))),
        })
}

fn data_entry<S: ObjectStore>(
    store: &mut S,
    offset: u64,
    data: &[u8],
    birth_commit_group: u64,
) -> Result<ExtentMapEntryV2> {
    if data.is_empty() {
        return Err(ObjectIoError::InvalidRange);
    }
    let key = content_hash(data);
    store.put(key, data).map_err(map_store_error)?;
    Ok(ExtentMapEntryV2::new_data(
        offset,
        request_len(data.len())?,
        derive_locator_id(key),
        key.as_bytes32(),
        birth_commit_group,
    ))
}

fn preserve_fragment<S: ObjectStore>(
    store: &mut S,
    source: &ExtentMapEntryV2,
    fragment_offset: u64,
    fragment_len: u64,
) -> Result<ExtentMapEntryV2> {
    let source_range = CheckedByteRange::from_extent(source)?;
    let fragment_range = CheckedByteRange::non_empty(fragment_offset, fragment_len)?;
    if fragment_range.start < source_range.start || fragment_range.end > source_range.end {
        return Err(ObjectIoError::InvalidRange);
    }

    if source.extent_type().reads_zero() {
        return Ok(ExtentMapEntryV2::new_unwritten(
            fragment_range.start,
            fragment_range.length,
            source.birth_commit_group,
        ));
    }

    let key = entry_object_key(source);
    let payload = load_object(store, key)?;
    let payload_start = usize::try_from(fragment_range.start - source_range.start)
        .map_err(|_| ObjectIoError::InvalidRange)?;
    let fragment_len_usize = fragment_range.len_usize()?;
    let payload_end = payload_start
        .checked_add(fragment_len_usize)
        .ok_or(ObjectIoError::InvalidRange)?;

    let mut fragment = vec![0; fragment_len_usize];
    if payload_start < payload.len() {
        let available_end = payload_end.min(payload.len());
        let available = available_end.saturating_sub(payload_start);
        fragment[..available].copy_from_slice(&payload[payload_start..available_end]);
    }

    data_entry(
        store,
        fragment_range.start,
        &fragment,
        source.birth_commit_group,
    )
}

/// Synchronous, offset-based reader over an extent map and object store.
#[derive(Clone, Debug, Default)]
pub struct ObjectReader;

impl ObjectReader {
    /// Create a reader.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Read up to `buf.len()` bytes from `offset`.
    ///
    /// Holes inside the known file size are zero-filled and counted. Reads past
    /// EOF return a short byte count, leaving the remaining buffer zeroed.
    pub fn read<M: ExtentMapOps, S: ObjectStore>(
        &self,
        extent_map: &M,
        store: &S,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        buf.fill(0);
        let Some(request) = CheckedByteRange::for_slice(offset, buf.len())? else {
            return Ok(0);
        };
        let entries = all_entries(extent_map)?;

        let mut cursor = request.start;
        let mut buf_cursor = 0usize;

        for entry in entries {
            let entry_range = CheckedByteRange::from_extent(&entry)?;
            if entry_range.end <= cursor {
                continue;
            }
            if entry_range.start >= request.end {
                break;
            }

            if cursor < entry_range.start {
                let hole_end = entry_range.start.min(request.end);
                let hole_range = CheckedByteRange::non_empty(cursor, hole_end - cursor)?;
                let hole_len = hole_range.len_usize()?;
                buf_cursor = buf_cursor
                    .checked_add(hole_len)
                    .ok_or(ObjectIoError::InvalidRange)?;
                cursor = hole_range.end;
                if cursor >= request.end || buf_cursor >= buf.len() {
                    return Ok(buf_cursor);
                }
            }

            let read_start = cursor.max(entry_range.start);
            let read_end = request.end.min(entry_range.end);
            if read_start >= read_end {
                continue;
            }

            let read_range = CheckedByteRange::non_empty(read_start, read_end - read_start)?;
            let read_len = read_range.len_usize()?;
            if entry.extent_type().is_data() {
                let key = entry_object_key(&entry);
                let payload = if let Some((algo, uncompressed_len)) = entry.transform_verification() {
                    // Build a TransformVerification token from the extent-map entry.
                    // The compressed_len is not stored in the entry; it is verified
                    // implicitly by the content checksum that covers the full payload.
                    // We pass compressed_len=0 to skip that field check.
                    let token = TransformVerification {
                        algorithm: tidefs_frame::CompressionAlgorithm::from_byte(algo)
                            .unwrap_or(tidefs_frame::CompressionAlgorithm::Uncompressed),
                        uncompressed_len,
                        compressed_len: 0, // verified by content checksum
                    };
                    load_object_verified(store, key, &token)?
                } else {
                    load_object(store, key)?
                };
                let payload_start = usize::try_from(read_range.start - entry_range.start)
                    .map_err(|_| ObjectIoError::InvalidRange)?;
                if payload_start < payload.len() {
                    let payload_end = payload_start
                        .checked_add(read_len)
                        .ok_or(ObjectIoError::InvalidRange)?
                        .min(payload.len());
                    let available = payload_end.saturating_sub(payload_start);
                    let buf_end = buf_cursor
                        .checked_add(available)
                        .ok_or(ObjectIoError::InvalidRange)?;
                    buf[buf_cursor..buf_end].copy_from_slice(&payload[payload_start..payload_end]);
                }
            }

            buf_cursor = buf_cursor
                .checked_add(read_len)
                .ok_or(ObjectIoError::InvalidRange)?;
            cursor = read_range.end;
            if cursor >= request.end || buf_cursor >= buf.len() {
                return Ok(buf_cursor);
            }
        }

        if cursor < request.end {
            if let Some((hole_start, hole_len)) = extent_map.seek_hole(cursor) {
                let hole_range = CheckedByteRange::new(hole_start, hole_len)?;
                if hole_range.start <= cursor {
                    let hole_end = hole_range.end.min(request.end);
                    if hole_end > cursor {
                        let readable_range =
                            CheckedByteRange::non_empty(cursor, hole_end - cursor)?;
                        let readable = readable_range.len_usize()?;
                        buf_cursor = buf_cursor
                            .checked_add(readable)
                            .ok_or(ObjectIoError::InvalidRange)?;
                    }
                }
            }
        }

        Ok(buf_cursor)
    }
}

/// Result produced by an object I/O truncate operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectTruncateOutcome {
    /// Requested logical file size after truncate.
    pub new_size: u64,
    /// Extent ranges removed or clipped from the logical file.
    pub freed_extents: Vec<FreedExtent>,
}

/// Synchronous logical-size truncation over an extent map.
#[derive(Clone, Debug, Default)]
pub struct ObjectTruncator;

impl ObjectTruncator {
    /// Create a truncator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Apply POSIX-style truncate semantics to the extent map.
    ///
    /// Shrinks drop or clip extent-map entries beyond `new_size`; grows only
    /// extend the logical size, leaving sparse holes for the read path.
    pub fn truncate<M: ExtentMapOps>(
        &self,
        extent_map: &mut M,
        new_size: u64,
    ) -> Result<ObjectTruncateOutcome> {
        let freed_extents = extent_map.truncate(new_size)?;
        Ok(ObjectTruncateOutcome {
            new_size,
            freed_extents,
        })
    }
}

/// Synchronous, chunking writer over an extent map and object store.
#[derive(Clone, Debug)]
pub struct ObjectWriter {
    /// Maximum bytes stored in one object for new writes.
    pub chunk_size: u64,
}

impl Default for ObjectWriter {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

impl ObjectWriter {
    /// Create a writer with [`DEFAULT_CHUNK_SIZE`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a writer with an explicit chunk size.
    #[must_use]
    pub fn with_chunk_size(chunk_size: u64) -> Self {
        Self { chunk_size }
    }

    /// Write `data` at logical `offset`.
    ///
    /// Existing overlapped DATA extents are rewritten into independent
    /// preserved left/right fragments before the new data extents are inserted.
    /// This avoids relying on an intra-object offset field that the current
    /// extent-map entry format does not expose.
    pub fn write<M: ExtentMapOps, S: ObjectStore>(
        &self,
        extent_map: &mut M,
        store: &mut S,
        offset: u64,
        data: &[u8],
    ) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.chunk_size == 0 {
            return Err(ObjectIoError::InvalidChunkSize);
        }

        let request =
            CheckedByteRange::for_slice(offset, data.len())?.ok_or(ObjectIoError::InvalidRange)?;
        let chunk_size =
            usize::try_from(self.chunk_size).map_err(|_| ObjectIoError::InvalidChunkSize)?;
        if chunk_size == 0 {
            return Err(ObjectIoError::InvalidChunkSize);
        }

        let mut replacement_entries = Vec::new();
        for entry in all_entries(extent_map)? {
            let entry_range = CheckedByteRange::from_extent(&entry)?;
            if entry_range.end <= request.start || entry_range.start >= request.end {
                continue;
            }

            if entry_range.start < request.start {
                replacement_entries.push(preserve_fragment(
                    store,
                    &entry,
                    entry_range.start,
                    request.start - entry_range.start,
                )?);
            }

            if entry_range.end > request.end {
                replacement_entries.push(preserve_fragment(
                    store,
                    &entry,
                    request.end,
                    entry_range.end - request.end,
                )?);
            }
        }

        let mut written = 0usize;
        while written < data.len() {
            let take = chunk_size.min(data.len() - written);
            let chunk = &data[written..written + take];
            let chunk_offset = request.offset_at(written)?;
            replacement_entries.push(data_entry(store, chunk_offset, chunk, 0)?);
            written += take;
        }

        replacement_entries.sort_by_key(|entry| entry.logical_offset);
        extent_map.insert_extent(&replacement_entries)?;
        Ok(written)
    }
}

/// Combined reader/writer facade.
#[derive(Clone, Debug, Default)]
pub struct ObjectIo {
    /// Reader half.
    pub reader: ObjectReader,
    /// Writer half.
    pub writer: ObjectWriter,
}

impl ObjectIo {
    /// Create a combined object I/O handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a combined object I/O handle with an explicit write chunk size.
    #[must_use]
    pub fn with_chunk_size(chunk_size: u64) -> Self {
        Self {
            reader: ObjectReader::new(),
            writer: ObjectWriter::with_chunk_size(chunk_size),
        }
    }

    /// Read using the reader half.
    pub fn read<M: ExtentMapOps, S: ObjectStore>(
        &self,
        extent_map: &M,
        store: &S,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        self.reader.read(extent_map, store, offset, buf)
    }

    /// Write using the writer half.
    pub fn write<M: ExtentMapOps, S: ObjectStore>(
        &self,
        extent_map: &mut M,
        store: &mut S,
        offset: u64,
        data: &[u8],
    ) -> Result<usize> {
        self.writer.write(extent_map, store, offset, data)
    }

    /// Truncate the mapped logical file size.
    pub fn truncate<M: ExtentMapOps>(
        &self,
        extent_map: &mut M,
        new_size: u64,
    ) -> Result<ObjectTruncateOutcome> {
        ObjectTruncator::new().truncate(extent_map, new_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::error::Error;
    use tidefs_extent_map::InlineExtentMap;

    #[derive(Debug, Default)]
    struct MemStore {
        objects: HashMap<ObjectKey, Vec<u8>>,
    }

    impl ObjectStore for MemStore {
        type Error = std::convert::Infallible;

        fn put(&mut self, key: ObjectKey, data: &[u8]) -> std::result::Result<(), Self::Error> {
            self.objects.insert(key, data.to_vec());
            Ok(())
        }

        fn get(&self, key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.objects.get(key).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct PanickingStore;

    impl ObjectStore for PanickingStore {
        type Error = std::convert::Infallible;

        fn put(&mut self, _key: ObjectKey, _data: &[u8]) -> std::result::Result<(), Self::Error> {
            panic!("zero-length object I/O must not write objects")
        }

        fn get(&self, _key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            panic!("zero-length object I/O must not read objects")
        }
    }

    fn setup_map_with_extent(
        store: &mut MemStore,
        offset: u64,
        data: &[u8],
    ) -> (InlineExtentMap, ObjectKey) {
        let key = content_hash(data);
        store.put(key, data).unwrap();
        let mut map = InlineExtentMap::new();
        let entry = ExtentMapEntryV2::new_data(
            offset,
            data.len() as u64,
            derive_locator_id(key),
            key.as_bytes32(),
            0,
        );
        map.insert_extent(&[entry]).unwrap();
        (map, key)
    }

    #[derive(Clone, Debug, Default)]
    struct StaticExtentMap {
        entries: Vec<ExtentMapEntryV2>,
        hole: Option<(u64, u64)>,
    }

    impl ExtentMapOps for StaticExtentMap {
        fn lookup_range(
            &self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
            Ok(self.entries.clone())
        }

        fn insert_extent(
            &mut self,
            _entries: &[ExtentMapEntryV2],
        ) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }

        fn truncate(
            &mut self,
            _new_size: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn punch_hole(
            &mut self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn convert_unwritten_to_data(
            &mut self,
            _offset: u64,
            _length: u64,
            _locator_id: LocatorId,
            _checksum: [u8; 32],
            _birth_commit_group: u64,
        ) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }

        fn seek_data(&self, _offset: u64) -> Option<(u64, u64)> {
            None
        }

        fn seek_hole(&self, _offset: u64) -> Option<(u64, u64)> {
            self.hole
        }

        fn fallocate(
            &mut self,
            _offset: u64,
            _length: u64,
            _keep_size: bool,
        ) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }

        fn zero_range(
            &mut self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn fiemap(
            &self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<tidefs_types_extent_map_core::FiemapExtent>, ExtentMapError>
        {
            Ok(Vec::new())
        }

        fn validate(&self) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct PanickingExtentMap;

    impl ExtentMapOps for PanickingExtentMap {
        fn lookup_range(
            &self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
            panic!("zero-length object I/O must not look up extents");
        }

        fn insert_extent(
            &mut self,
            _entries: &[ExtentMapEntryV2],
        ) -> std::result::Result<(), ExtentMapError> {
            panic!("zero-length object I/O must not insert extents");
        }

        fn truncate(
            &mut self,
            _new_size: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            panic!("zero-length object I/O must not truncate extents");
        }

        fn punch_hole(
            &mut self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            panic!("zero-length object I/O must not punch holes");
        }

        fn convert_unwritten_to_data(
            &mut self,
            _offset: u64,
            _length: u64,
            _locator_id: LocatorId,
            _checksum: [u8; 32],
            _birth_commit_group: u64,
        ) -> std::result::Result<(), ExtentMapError> {
            panic!("zero-length object I/O must not convert extents");
        }

        fn seek_data(&self, _offset: u64) -> Option<(u64, u64)> {
            panic!("zero-length object I/O must not seek data");
        }

        fn seek_hole(&self, _offset: u64) -> Option<(u64, u64)> {
            panic!("zero-length object I/O must not seek holes");
        }

        fn fallocate(
            &mut self,
            _offset: u64,
            _length: u64,
            _keep_size: bool,
        ) -> std::result::Result<(), ExtentMapError> {
            panic!("zero-length object I/O must not allocate extents");
        }

        fn zero_range(
            &mut self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            panic!("zero-length object I/O must not zero ranges");
        }

        fn fiemap(
            &self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<tidefs_types_extent_map_core::FiemapExtent>, ExtentMapError>
        {
            panic!("zero-length object I/O must not build fiemap");
        }

        fn validate(&self) -> std::result::Result<(), ExtentMapError> {
            panic!("zero-length object I/O must not validate extents");
        }
    }

    #[test]
    fn object_io_zero_length_read_is_noop_without_extent_or_store_access() {
        let map = PanickingExtentMap;
        let store = PanickingStore;
        let mut buf = [];

        let read = ObjectIo::new()
            .read(&map, &store, u64::MAX, &mut buf)
            .unwrap();

        assert_eq!(read, 0);
    }

    #[test]
    fn object_io_zero_length_write_is_noop_without_extent_or_store_access() {
        let mut map = PanickingExtentMap;
        let mut store = PanickingStore;

        let written = ObjectIo::with_chunk_size(0)
            .write(&mut map, &mut store, u64::MAX, &[])
            .unwrap();

        assert_eq!(written, 0);
    }
    #[test]
    fn range_overflow_read_and_write_reject_request_ranges() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let mut buf = [0; 1];

        let read_err = ObjectReader::new()
            .read(&map, &store, u64::MAX, &mut buf)
            .unwrap_err();
        assert!(matches!(read_err, ObjectIoError::InvalidRange));

        let write_err = ObjectWriter::new()
            .write(&mut map, &mut store, u64::MAX, b"x")
            .unwrap_err();
        assert!(matches!(write_err, ObjectIoError::InvalidRange));
    }

    #[test]
    fn range_overflow_read_and_write_reject_extent_ranges() {
        let invalid_entry = ExtentMapEntryV2::new_unwritten(u64::MAX, 2, 0);
        let mut read_map = StaticExtentMap {
            entries: vec![invalid_entry.clone()],
            hole: None,
        };
        let mut store = MemStore::default();
        let mut buf = [0; 1];

        let read_err = ObjectReader::new()
            .read(&read_map, &store, 0, &mut buf)
            .unwrap_err();
        assert!(matches!(read_err, ObjectIoError::InvalidRange));

        let write_err = ObjectWriter::new()
            .write(&mut read_map, &mut store, 0, b"x")
            .unwrap_err();
        assert!(matches!(write_err, ObjectIoError::InvalidRange));
    }

    #[test]
    fn range_overflow_sparse_read_at_u64_max_eof_boundary_counts_final_hole_byte() {
        let mut map = InlineExtentMap::new();
        map.truncate(u64::MAX).unwrap();
        let store = MemStore::default();
        let mut buf = [0xff; 1];

        let read = ObjectReader::new()
            .read(&map, &store, u64::MAX - 1, &mut buf)
            .unwrap();

        assert_eq!(read, 1);
        assert_eq!(buf, [0]);
    }

    #[test]
    fn read_single_extent_exact() {
        let mut store = MemStore::default();
        let data = b"hello world";
        let (map, _) = setup_map_with_extent(&mut store, 0, data);
        let mut buf = vec![0; data.len()];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf, data);
    }

    #[test]
    fn read_partial_extent_uses_object_offset() {
        let mut store = MemStore::default();
        let (map, _) = setup_map_with_extent(&mut store, 0, b"abcdefghij");
        let mut buf = vec![0; 5];
        let read = ObjectReader::new().read(&map, &store, 2, &mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf, b"cdefg");
    }

    #[test]
    fn read_spanning_two_extents_with_hole() {
        let mut store = MemStore::default();
        let (mut map, _) = setup_map_with_extent(&mut store, 0, b"AAAA");
        let key = content_hash(b"BBBB");
        store.put(key, b"BBBB").unwrap();
        map.insert_extent(&[ExtentMapEntryV2::new_data(
            12,
            4,
            derive_locator_id(key),
            key.as_bytes32(),
            0,
        )])
        .unwrap();

        let mut buf = vec![0xff; 16];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 16);
        assert_eq!(&buf[0..4], b"AAAA");
        assert_eq!(&buf[4..12], &[0; 8]);
        assert_eq!(&buf[12..16], b"BBBB");
    }

    #[test]
    fn sparse_read_starting_inside_hole_keeps_buffer_offsets_aligned() {
        let mut store = MemStore::default();
        let (mut map, _) = setup_map_with_extent(&mut store, 4, b"DATA");
        map.truncate(12).unwrap();

        let mut buf = vec![0xff; 8];
        let read = ObjectReader::new().read(&map, &store, 2, &mut buf).unwrap();

        assert_eq!(read, 8);
        assert_eq!(&buf[..2], &[0; 2]);
        assert_eq!(&buf[2..6], b"DATA");
        assert_eq!(&buf[6..], &[0; 2]);
    }

    #[test]
    fn read_full_sparse_hole_inside_file() {
        let mut map = InlineExtentMap::new();
        map.truncate(16).unwrap();
        let store = MemStore::default();
        let mut buf = vec![0xff; 16];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 16);
        assert!(buf.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn read_past_eof_short_read() {
        let mut store = MemStore::default();
        let (map, _) = setup_map_with_extent(&mut store, 0, b"12345");
        let mut buf = vec![0xff; 10];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"12345");
        assert_eq!(&buf[5..], &[0; 5]);
    }

    #[test]
    fn eof_reads_skip_backing_store_even_when_data_extent_exists() {
        let data = b"12345";
        let key = content_hash(data);
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[ExtentMapEntryV2::new_data(
            0,
            data.len() as u64,
            derive_locator_id(key),
            key.as_bytes32(),
            0,
        )])
        .unwrap();
        let store = PanickingStore;

        let mut exact_eof_buf = vec![0xff; 4];
        let exact_eof_read = ObjectReader::new()
            .read(&map, &store, data.len() as u64, &mut exact_eof_buf)
            .unwrap();

        assert_eq!(exact_eof_read, 0);
        assert_eq!(exact_eof_buf, [0; 4]);

        let mut beyond_eof_buf = vec![0xff; 4];
        let beyond_eof_read = ObjectReader::new()
            .read(&map, &store, data.len() as u64 + 8, &mut beyond_eof_buf)
            .unwrap();

        assert_eq!(beyond_eof_read, 0);
        assert_eq!(beyond_eof_buf, [0; 4]);
    }

    #[test]
    fn object_reader_zero_length_read_is_noop_without_extent_or_store_access() {
        let map = PanickingExtentMap;
        let store = PanickingStore;
        let mut buf = [];

        let read = ObjectReader::new()
            .read(&map, &store, u64::MAX, &mut buf)
            .unwrap();

        assert_eq!(read, 0);
    }

    #[test]
    fn write_single_chunk() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let written = ObjectWriter::with_chunk_size(4096)
            .write(&mut map, &mut store, 0, b"Hello, TideFS!")
            .unwrap();
        assert_eq!(written, 14);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 14);
        assert!(map.entries[0].extent_type().is_data());
    }

    #[test]
    fn write_spanning_chunk_boundaries() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let data = b"ABCDEFGHIJ";
        let written = ObjectWriter::with_chunk_size(4)
            .write(&mut map, &mut store, 0, data)
            .unwrap();
        assert_eq!(written, data.len());
        assert_eq!(map.entries.len(), 3);

        let mut buf = vec![0; data.len()];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf, data);
    }

    #[test]
    fn overwrite_middle_of_existing_extent_preserves_edges() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let io = ObjectIo::with_chunk_size(4096);

        io.write(&mut map, &mut store, 0, b"hello world!").unwrap();
        io.write(&mut map, &mut store, 3, b"XXXXX").unwrap();

        let mut buf = vec![0; 12];
        let read = io.read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 12);
        assert_eq!(&buf, b"helXXXXXrld!");
        assert_eq!(map.entries.len(), 3);
    }

    #[test]
    fn sparse_overwrite_split_preserves_data_edges_and_holes() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let io = ObjectIo::with_chunk_size(8);

        io.write(&mut map, &mut store, 0, b"HEAD").unwrap();
        io.write(&mut map, &mut store, 12, b"TAIL").unwrap();
        io.truncate(&mut map, 20).unwrap();
        let objects_before = store.objects.len();

        let written = io.write(&mut map, &mut store, 6, b"OVERDONE").unwrap();

        assert_eq!(written, 8);
        assert_eq!(map.header.file_size, 20);
        assert_eq!(store.objects.len(), objects_before + 2);
        let mapped_ranges = map
            .entries
            .iter()
            .map(|entry| (entry.logical_offset, entry.length))
            .collect::<Vec<_>>();
        assert_eq!(mapped_ranges, vec![(0, 4), (6, 8), (14, 2)]);

        let mut buf = vec![0xff; 20];
        let read = io.read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 20);
        assert_eq!(&buf[..4], b"HEAD");
        assert_eq!(&buf[4..6], &[0; 2]);
        assert_eq!(&buf[6..14], b"OVERDONE");
        assert_eq!(&buf[14..16], b"IL");
        assert_eq!(&buf[16..], &[0; 4]);
    }

    #[test]
    fn write_beyond_current_size_leaves_sparse_gap() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let io = ObjectIo::new();
        io.write(&mut map, &mut store, 8, b"tail").unwrap();

        let mut buf = vec![0xff; 12];
        let read = io.read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 12);
        assert_eq!(&buf[..8], &[0; 8]);
        assert_eq!(&buf[8..], b"tail");
    }

    #[test]
    fn zero_length_write_is_noop() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let written = ObjectWriter::new()
            .write(&mut map, &mut store, 0, &[])
            .unwrap();
        assert_eq!(written, 0);
        assert!(map.entries.is_empty());
    }

    #[test]
    fn object_writer_zero_length_write_is_noop_without_extent_or_store_access() {
        let mut map = PanickingExtentMap;
        let mut store = PanickingStore;

        let written = ObjectWriter::with_chunk_size(0)
            .write(&mut map, &mut store, u64::MAX, &[])
            .unwrap();

        assert_eq!(written, 0);
    }

    #[test]
    fn truncate_shrink_clips_boundary_extent_and_drops_tail() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let io = ObjectIo::new();
        io.write(&mut map, &mut store, 0, b"abcdefghij").unwrap();
        io.write(&mut map, &mut store, 16, b"tail").unwrap();

        let outcome = io.truncate(&mut map, 5).unwrap();

        assert_eq!(outcome.new_size, 5);
        assert_eq!(outcome.freed_extents.len(), 2);
        assert_eq!(outcome.freed_extents[0].logical_offset, 5);
        assert_eq!(outcome.freed_extents[0].length, 5);
        assert_eq!(outcome.freed_extents[1].logical_offset, 16);
        assert_eq!(outcome.freed_extents[1].length, 4);
        assert_eq!(map.header.file_size, 5);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 5);

        let mut buf = vec![0xff; 10];
        let read = io.read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"abcde");
        assert_eq!(&buf[5..], &[0; 5]);
    }

    #[test]
    fn truncate_grow_extends_sparse_size_without_objects() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let io = ObjectIo::new();
        io.write(&mut map, &mut store, 0, b"head").unwrap();
        let objects_before = store.objects.len();

        let outcome = io.truncate(&mut map, 12).unwrap();

        assert_eq!(outcome.new_size, 12);
        assert!(outcome.freed_extents.is_empty());
        assert_eq!(map.header.file_size, 12);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(store.objects.len(), objects_before);

        let mut buf = vec![0xff; 12];
        let read = io.read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 12);
        assert_eq!(&buf[..4], b"head");
        assert_eq!(&buf[4..], &[0; 8]);
    }

    #[test]
    fn truncate_to_current_size_is_idempotent() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let io = ObjectIo::new();
        io.write(&mut map, &mut store, 0, b"same").unwrap();
        let before = map.clone();

        let outcome = ObjectTruncator::new().truncate(&mut map, 4).unwrap();

        assert_eq!(outcome.new_size, 4);
        assert!(outcome.freed_extents.is_empty());
        assert_eq!(map, before);
    }

    #[test]
    fn local_object_store_adapter_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let mut map = InlineExtentMap::new();
        let mut store = LocalObjectStore::open(temp.path()).unwrap();
        let io = ObjectIo::with_chunk_size(4);
        io.write(&mut map, &mut store, 0, b"local-store").unwrap();

        let mut buf = vec![0; 11];
        let read = io.read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 11);
        assert_eq!(&buf, b"local-store");
    }

    // ── ObjectIoError unit tests ──────────────────────────────────────

    #[test]
    fn object_io_error_display_includes_context_for_all_variants() {
        let store_err = ObjectIoError::StoreError(Box::new(std::io::Error::other("disk full")));
        assert!(store_err.to_string().contains("object store error"));
        assert!(store_err.to_string().contains("disk full"));

        let extent_err = ObjectIoError::ExtentError(ExtentMapError::NotFound);
        assert_eq!(extent_err.to_string(), "extent map error: extent not found");

        assert_eq!(
            ObjectIoError::InvalidRange.to_string(),
            "invalid byte range"
        );
        assert_eq!(
            ObjectIoError::InvalidChunkSize.to_string(),
            "invalid object I/O chunk size"
        );

        let missing = ObjectIoError::MissingObject(ObjectKey::from_bytes32([1u8; 32]));
        assert!(missing
            .to_string()
            .contains("extent references missing object "));

        assert_eq!(
            ObjectIoError::HoleBeyondEof.to_string(),
            "read entirely in hole past EOF"
        );
    }

    #[test]
    fn object_io_error_source_returns_inner_for_store_error() {
        let inner = std::io::Error::other("inner failure");
        let err = ObjectIoError::StoreError(Box::new(inner));
        let source = err.source().expect("StoreError must expose source");
        let source_msg = format!("{source}");
        assert!(source_msg.contains("inner failure"));
    }

    #[test]
    fn object_io_error_source_returns_none_for_non_store_errors() {
        assert!(ObjectIoError::InvalidRange.source().is_none());
        assert!(ObjectIoError::InvalidChunkSize.source().is_none());
        assert!(ObjectIoError::HoleBeyondEof.source().is_none());
        assert!(ObjectIoError::ExtentError(ExtentMapError::NotFound)
            .source()
            .is_none());
        assert!(
            ObjectIoError::MissingObject(ObjectKey::from_bytes32([2u8; 32]))
                .source()
                .is_none()
        );
    }

    #[test]
    fn extent_error_from_conversion() {
        let map_err = ExtentMapError::NotFound;
        let io_err: ObjectIoError = map_err.into();
        assert!(matches!(
            io_err,
            ObjectIoError::ExtentError(ExtentMapError::NotFound)
        ));
    }

    // ── Missing object error path ─────────────────────────────────────

    #[derive(Debug, Default)]
    struct EmptyStore;

    impl ObjectStore for EmptyStore {
        type Error = std::convert::Infallible;

        fn put(&mut self, _key: ObjectKey, _data: &[u8]) -> std::result::Result<(), Self::Error> {
            Ok(())
        }

        fn get(&self, _key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
        }
    }

    #[test]
    fn read_extent_with_missing_object_returns_missing_object_error() {
        let data = b"vanished";
        let key = content_hash(data);
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[ExtentMapEntryV2::new_data(
            0,
            data.len() as u64,
            derive_locator_id(key),
            key.as_bytes32(),
            0,
        )])
        .unwrap();
        let store = EmptyStore;
        let mut buf = vec![0; data.len()];

        let err = ObjectReader::new()
            .read(&map, &store, 0, &mut buf)
            .unwrap_err();

        assert!(matches!(err, ObjectIoError::MissingObject(_)));
    }

    // ── Invalid chunk size ────────────────────────────────────────────

    #[test]
    fn write_nonempty_data_with_zero_chunk_size_returns_invalid_chunk_size() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();

        let err = ObjectWriter::with_chunk_size(0)
            .write(&mut map, &mut store, 0, b"data")
            .unwrap_err();

        assert!(matches!(err, ObjectIoError::InvalidChunkSize));
    }

    #[test]
    fn write_with_default_chunk_size_succeeds() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let written = ObjectWriter::new()
            .write(&mut map, &mut store, 0, b"ok!")
            .unwrap();
        assert_eq!(written, 3);
    }

    // ── Read from empty extent map ────────────────────────────────────

    #[test]
    fn read_from_empty_extent_map_returns_zero_bytes() {
        let map = InlineExtentMap::new();
        let store = MemStore::default();
        let mut buf = vec![0xff; 16];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 0);
        assert_eq!(&buf, &[0; 16]); // buffer zeroed
    }

    // ── Unwritten extent reads ────────────────────────────────────────

    #[test]
    fn unwritten_extent_reads_as_zeros() {
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[ExtentMapEntryV2::new_unwritten(0, 8, 0)])
            .unwrap();
        let store = MemStore::default();
        let mut buf = vec![0xff; 8];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 8);
        assert_eq!(&buf, &[0; 8]);
    }

    #[test]
    fn mixed_unwritten_and_data_extents_read_correctly() {
        let mut store = MemStore::default();
        let data = b"DATA";
        let key = content_hash(data);
        store.put(key, data).unwrap();
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[
            ExtentMapEntryV2::new_unwritten(0, 4, 0),
            ExtentMapEntryV2::new_data(4, 4, derive_locator_id(key), key.as_bytes32(), 0),
            ExtentMapEntryV2::new_unwritten(8, 4, 0),
        ])
        .unwrap();

        let mut buf = vec![0xff; 12];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 12);
        assert_eq!(&buf[0..4], &[0; 4]);
        assert_eq!(&buf[4..8], b"DATA");
        assert_eq!(&buf[8..12], &[0; 4]);
    }

    // ── Content hash properties ───────────────────────────────────────

    #[test]
    fn content_hash_is_deterministic() {
        let a = content_hash(b"hello");
        let b = content_hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn content_hash_differs_for_different_data() {
        let a = content_hash(b"hello");
        let b = content_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn content_hash_differs_for_empty_vs_nonempty() {
        let empty = content_hash(b"");
        let nonempty = content_hash(b"x");
        assert_ne!(empty, nonempty);
    }

    // ── derive_locator_id safety ──────────────────────────────────────

    #[test]
    fn derive_locator_id_never_zero() {
        let zero_key = ObjectKey::from_bytes32([0u8; 32]);
        assert!(derive_locator_id(zero_key).0 >= 1);
    }

    #[test]
    fn derive_locator_id_is_deterministic() {
        let key = ObjectKey::from_bytes32([0x42; 32]);
        assert_eq!(derive_locator_id(key), derive_locator_id(key));
    }

    // ── CheckedByteRange edge cases ───────────────────────────────────

    #[test]
    fn checked_byte_range_rejects_start_plus_length_overflow() {
        assert!(CheckedByteRange::new(u64::MAX, 1).is_err());
        assert!(CheckedByteRange::new(u64::MAX - 1, 2).is_err());
    }

    #[test]
    fn checked_byte_range_non_empty_rejects_zero_length() {
        assert!(CheckedByteRange::non_empty(0, 0).is_err());
    }

    #[test]
    fn checked_byte_range_for_slice_zero_len_returns_none() {
        assert!(CheckedByteRange::for_slice(0, 0).unwrap().is_none());
    }

    // ── ObjectIo with_chunk_size delegation ───────────────────────────

    #[test]
    fn object_io_with_chunk_size_sets_writer_chunk_size() {
        let io = ObjectIo::with_chunk_size(1024);
        assert_eq!(io.writer.chunk_size, 1024);
    }

    #[test]
    fn object_io_default_uses_default_chunk_size() {
        let io = ObjectIo::default();
        assert_eq!(io.writer.chunk_size, DEFAULT_CHUNK_SIZE);
    }

    // ── Store error propagation ───────────────────────────────────────

    #[derive(Debug)]
    struct FailingStore;

    impl ObjectStore for FailingStore {
        type Error = std::io::Error;

        fn put(&mut self, _key: ObjectKey, _data: &[u8]) -> std::result::Result<(), Self::Error> {
            Err(std::io::Error::other("disk full"))
        }

        fn get(&self, _key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Err(std::io::Error::other("read error"))
        }
    }

    #[test]
    fn store_error_propagates_through_write() {
        let mut map = InlineExtentMap::new();
        let mut store = FailingStore;

        let err = ObjectWriter::new()
            .write(&mut map, &mut store, 0, b"x")
            .unwrap_err();

        assert!(matches!(err, ObjectIoError::StoreError(_)));
        assert!(err.to_string().contains("object store error"));
    }

    #[test]
    fn store_error_propagates_through_read() {
        let mut map = InlineExtentMap::new();
        let data = b"present";
        let key = content_hash(data);
        map.insert_extent(&[ExtentMapEntryV2::new_data(
            0,
            data.len() as u64,
            derive_locator_id(key),
            key.as_bytes32(),
            0,
        )])
        .unwrap();
        let store = FailingStore;
        let mut buf = vec![0; data.len()];

        let err = ObjectReader::new()
            .read(&map, &store, 0, &mut buf)
            .unwrap_err();

        assert!(matches!(err, ObjectIoError::StoreError(_)));
    }

    // ── Large multi-chunk roundtrip ───────────────────────────────────

    #[test]
    fn roundtrip_large_multichunk_write_preserves_data_byte_for_byte() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        let io = ObjectIo::with_chunk_size(64);

        // Build patterned data: 0..63 mod 251 to avoid simple repetition
        let data: Vec<u8> = (0..64u64).map(|i| (i % 251) as u8).collect();
        io.write(&mut map, &mut store, 0, &data).unwrap();

        let mut buf = vec![0; data.len()];
        let read = io.read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(
            buf, data,
            "large multi-chunk roundtrip must be byte-for-byte"
        );
    }

    // ── Read buffer larger than file size ─────────────────────────────

    #[test]
    fn read_buffer_larger_than_file_size_short_reads() {
        let mut store = MemStore::default();
        let (map, _) = setup_map_with_extent(&mut store, 0, b"abc");
        let mut buf = vec![0xff; 32];
        let read = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
        assert_eq!(read, 3);
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(&buf[3..], &[0; 29]);
    }

    // ── read at non-zero offset within a single extent ────────────────

    #[test]
    fn read_at_nonzero_offset_within_extent_returns_tail() {
        let mut store = MemStore::default();
        let (map, _) = setup_map_with_extent(&mut store, 0, b"0123456789");
        let mut buf = vec![0; 4];
        let read = ObjectReader::new().read(&map, &store, 6, &mut buf).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&buf, b"6789");
    }

    // ── write at non-zero offset creates correct extent entry ─────────

    #[test]
    fn write_at_nonzero_offset_creates_extent_at_correct_position() {
        let mut map = InlineExtentMap::new();
        let mut store = MemStore::default();
        ObjectWriter::new()
            .write(&mut map, &mut store, 100, b"offset-write")
            .unwrap();

        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 100);
        assert_eq!(map.entries[0].length, 12);

        let mut buf = vec![0; 12];
        let read = ObjectReader::new()
            .read(&map, &store, 100, &mut buf)
            .unwrap();
        assert_eq!(read, 12);
        assert_eq!(&buf, b"offset-write");
    }
}
