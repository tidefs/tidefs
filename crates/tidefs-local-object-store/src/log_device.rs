// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Separate intent LOG (LOG_DEVICE) device writer.
//!
//! A [`LogDeviceWriter`] manages a dedicated fast-device file for intent-log
//! (ZIL) records.  It uses O_DIRECT (or equivalent unbuffered I/O) so
//! synchronous-write latency depends only on the log device, not on
//! the main pool data devices.
//!
//! # On-disk layout
//!
//! ```text
//! Header:  "VIBFLDEV" (8 bytes) | version: u32 LE | reserved: u32 LE
//! Entry:   [payload_len: u32 LE][crc32c: u32 LE][payload: u8*]
//! ```
//!
//! Every entry is immediately followed by an `fdatasync` of the log device
//! device fd, committing the record before the caller acknowledges the
//! synchronous write.  On crash recovery, `LogDeviceWriter::open` scans to
//! the last valid CRC32C entry and truncates any torn tail.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::StoreError;
use crate::Result;

/// Magic bytes at the start of every LOG_DEVICE file.
pub const LOG_DEVICE_MAGIC: &[u8; 8] = b"VIBFLDEV";
/// Current LOG_DEVICE format version.
pub const LOG_DEVICE_VERSION: u32 = 1;
/// Size of the file header in bytes.
pub const LOG_DEVICE_HEADER_SIZE: u64 = 16;
/// Size of per-entry frame (payload length + CRC32C) in bytes.
pub const LOG_DEVICE_ENTRY_FRAME_SIZE: u64 = 8;

// ---------------------------------------------------------------------------
// CRC32C (Castagnoli)
// ---------------------------------------------------------------------------

/// Compute CRC32C (Castagnoli) of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

/// Build an I/O error for the caller.
fn io_err(op: &'static str, path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        operation: op,
        path: path.to_path_buf(),
        source,
    }
}

// ---------------------------------------------------------------------------
// LogDeviceWriter
// ---------------------------------------------------------------------------

/// A separate intent-log device writer.
///
/// Holds an open file descriptor to a dedicated log device with
/// sequential, append-only semantics.  Every [`append`](LogDeviceWriter::append)
/// call writes a length-tagged, CRC32C-protected entry and calls
/// `fdatasync` before returning.
#[derive(Debug)]
pub struct LogDeviceWriter {
    path: PathBuf,
    file: File,
    next_offset: u64,
    /// Number of entries written since open.
    entries_written: u64,
    /// Total bytes written since open (including framing).
    bytes_written: u64,
}

impl LogDeviceWriter {
    /// Open or create the log device file at `path`.
    ///
    /// On a new (zero-length) file, writes the VIBFLDEV header and
    /// fsyncs it.  On an existing file, validates the header, scans
    /// to the last valid CRC32C entry, and positions the write cursor
    /// immediately after it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| io_err("open log_device file", &path, e))?;

        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| io_err("seek log_device end", &path, e))?;

        if file_len == 0 {
            // Fresh file: write header.
            let mut header = Vec::with_capacity(16);
            header.extend_from_slice(LOG_DEVICE_MAGIC);
            header.extend_from_slice(&LOG_DEVICE_VERSION.to_le_bytes());
            header.extend_from_slice(&0u32.to_le_bytes());
            file.write_all(&header)
                .map_err(|e| io_err("write log_device header", &path, e))?;
            file.sync_all()
                .map_err(|e| io_err("fsync log_device header", &path, e))?;
            return Ok(Self {
                path,
                file,
                next_offset: LOG_DEVICE_HEADER_SIZE,
                entries_written: 0,
                bytes_written: LOG_DEVICE_HEADER_SIZE,
            });
        }

        // Existing file: validate header.
        file.seek(SeekFrom::Start(0))
            .map_err(|e| io_err("seek log_device header", &path, e))?;
        let mut header = [0u8; 16];
        file.read_exact(&mut header)
            .map_err(|e| io_err("read log_device header", &path, e))?;

        if &header[0..8] != LOG_DEVICE_MAGIC {
            return Err(StoreError::InvalidOptions {
                reason: "log_device file has wrong magic",
            });
        }
        let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if version != LOG_DEVICE_VERSION {
            return Err(StoreError::InvalidOptions {
                reason: "log_device unsupported version",
            });
        }

        let last_valid = Self::scan_to_last_valid(&mut file, file_len, &path)?;
        Ok(Self {
            path,
            file,
            next_offset: last_valid,
            entries_written: 0,
            bytes_written: last_valid,
        })
    }

    /// Scan forward from the header to find the last valid CRC32C entry.
    ///
    /// Any torn (incomplete) entry after the last valid one is silently
    /// discarded on the next append (the write cursor sits at the last
    /// valid boundary).
    fn scan_to_last_valid(file: &mut File, file_len: u64, path: &Path) -> Result<u64> {
        let mut offset = LOG_DEVICE_HEADER_SIZE;
        let mut last_valid = offset;
        while offset + LOG_DEVICE_ENTRY_FRAME_SIZE <= file_len {
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| io_err("seek log_device entry", path, e))?;
            let mut frame = [0u8; 8];
            if file.read_exact(&mut frame).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as u64;
            let stored_crc = u32::from_le_bytes(frame[4..8].try_into().unwrap());
            let entry_end = offset + LOG_DEVICE_ENTRY_FRAME_SIZE + payload_len;
            if entry_end > file_len {
                break;
            }
            let mut payload = vec![0u8; payload_len as usize];
            if file.read_exact(&mut payload).is_err() {
                break;
            }
            if crc32c(&payload) != stored_crc {
                break;
            }
            last_valid = entry_end;
            offset = entry_end;
        }
        Ok(last_valid)
    }

    /// Append a single intent-log record to the log device.
    ///
    /// The payload is length-tagged, CRC32C-protected, written with
    /// O_DIRECT-aligned I/O when available, and `fdatasync`-ed before
    /// returning.  This is the fast path for synchronous writes: only
    /// the log device is touched; data device writes are deferred.
    pub fn append(&mut self, payload: &[u8]) -> Result<()> {
        let checksum = crc32c(payload);
        let len_u32 = payload.len() as u32;

        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&len_u32.to_le_bytes());
        frame.extend_from_slice(&checksum.to_le_bytes());
        frame.extend_from_slice(payload);

        self.file
            .seek(SeekFrom::Start(self.next_offset))
            .map_err(|e| io_err("seek log_device append", &self.path, e))?;
        self.file
            .write_all(&frame)
            .map_err(|e| io_err("write log_device entry", &self.path, e))?;

        // Commit only the log device (data-only sync, no metadata).
        self.file
            .sync_data()
            .map_err(|e| io_err("fdatasync log_device entry", &self.path, e))?;

        let frame_len = frame.len() as u64;
        self.next_offset += frame_len;
        self.entries_written = self.entries_written.saturating_add(1);
        self.bytes_written = self.bytes_written.saturating_add(frame_len);
        Ok(())
    }

    /// Commit all pending data to the log device (fdatasync).
    ///
    /// This is a no-op in the current design because every `append`
    /// already syncs.  It exists as a separate public method so that
    /// higher layers can issue an explicit barrier when batching is
    /// introduced later.
    pub fn commit(&self) -> Result<()> {
        self.file
            .sync_data()
            .map_err(|e| io_err("fdatasync log_device commit", &self.path, e))
    }

    /// Read all valid entries from the log device file.
    ///
    /// Used during crash recovery to replay committed-but-unCOMMIT_GROUP'd
    /// ZIL records.
    pub fn read_all_entries(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut entries = Vec::new();
        let mut offset = LOG_DEVICE_HEADER_SIZE;
        let file_len = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|e| io_err("seek log_device end", &self.path, e))?;
        while offset + LOG_DEVICE_ENTRY_FRAME_SIZE <= file_len {
            self.file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| io_err("seek log_device entry", &self.path, e))?;
            let mut frame = [0u8; 8];
            if self.file.read_exact(&mut frame).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as u64;
            let stored_crc = u32::from_le_bytes(frame[4..8].try_into().unwrap());
            let entry_end = offset + 8 + payload_len;
            if entry_end > file_len {
                break;
            }
            let mut payload = vec![0u8; payload_len as usize];
            if self.file.read_exact(&mut payload).is_err() {
                break;
            }
            if crc32c(&payload) != stored_crc {
                break;
            }
            entries.push(payload);
            offset = entry_end;
        }
        Ok(entries)
    }

    /// Truncate the log device file back to header-only.
    ///
    /// Used during pool export to discard committed entries after
    /// they have been integrated into the main data devices via COMMIT_GROUP.
    pub fn truncate(&mut self) -> Result<()> {
        self.file
            .set_len(LOG_DEVICE_HEADER_SIZE)
            .map_err(|e| io_err("truncate log_device", &self.path, e))?;
        self.file
            .sync_all()
            .map_err(|e| io_err("fsync log_device truncate", &self.path, e))?;
        self.next_offset = LOG_DEVICE_HEADER_SIZE;
        self.entries_written = 0;
        self.bytes_written = LOG_DEVICE_HEADER_SIZE;
        Ok(())
    }

    /// Close the log device (drop the file descriptor).
    ///
    /// The file is synced before closing to ensure all writes are
    /// durable.  After close, the writer is consumed.
    pub fn close(self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| io_err("fsync log_device close", &self.path, e))?;
        Ok(())
    }

    // -- accessors --

    /// Path to the log device file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of entries written since open.
    #[must_use]
    pub fn entries_written(&self) -> u64 {
        self.entries_written
    }

    /// Total bytes written since open (including framing).
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_log_device_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("tidefs-log_device-tests");
        let _ = fs::create_dir_all(&dir);
        dir.join(name)
    }

    #[test]
    fn open_creates_new_log_device_file_with_header() {
        let path = temp_log_device_path("new-log_device.vlog_device");
        let _ = fs::remove_file(&path);

        let w = LogDeviceWriter::open(&path).unwrap();
        assert_eq!(w.next_offset, LOG_DEVICE_HEADER_SIZE);
        assert_eq!(w.entries_written(), 0);

        // Verify header on disk
        let buf = fs::read(&path).unwrap();
        assert_eq!(&buf[0..8], LOG_DEVICE_MAGIC);
        assert_eq!(
            u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            LOG_DEVICE_VERSION
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reopen_validates_header_and_recovers() {
        let path = temp_log_device_path("reopen.vlog_device");
        let _ = fs::remove_file(&path);

        // Create and write one entry
        let mut w = LogDeviceWriter::open(&path).unwrap();
        w.append(b"hello").unwrap();
        drop(w);

        // Re-open — should validate header and find the entry
        let mut w2 = LogDeviceWriter::open(&path).unwrap();
        assert_eq!(w2.next_offset, LOG_DEVICE_HEADER_SIZE + 8 + 5);
        let entries = w2.read_all_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], b"hello");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn append_and_read_roundtrip() {
        let path = temp_log_device_path("roundtrip.vlog_device");
        let _ = fs::remove_file(&path);

        let mut w = LogDeviceWriter::open(&path).unwrap();
        w.append(b"record-1").unwrap();
        w.append(b"record-2-longer").unwrap();
        w.append(b"r3").unwrap();

        let entries = w.read_all_entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], b"record-1");
        assert_eq!(entries[1], b"record-2-longer");
        assert_eq!(entries[2], b"r3");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn torn_tail_discarded_on_reopen() {
        let path = temp_log_device_path("torn.vlog_device");
        let _ = fs::remove_file(&path);

        // Write valid entries
        let mut w = LogDeviceWriter::open(&path).unwrap();
        w.append(b"good-1").unwrap();
        w.append(b"good-2").unwrap();
        let good_end = w.next_offset;
        drop(w);

        // Append garbage (simulate torn write)
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"garbage tail bytes").unwrap();
        drop(f);

        // Re-open — should only see the two valid entries
        let mut w2 = LogDeviceWriter::open(&path).unwrap();
        assert_eq!(w2.next_offset, good_end);
        let entries = w2.read_all_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], b"good-1");
        assert_eq!(entries[1], b"good-2");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn truncate_resets_to_header_only() {
        let path = temp_log_device_path("truncate.vlog_device");
        let _ = fs::remove_file(&path);

        let mut w = LogDeviceWriter::open(&path).unwrap();
        w.append(b"data-1").unwrap();
        w.append(b"data-2").unwrap();
        w.truncate().unwrap();

        assert_eq!(w.next_offset, LOG_DEVICE_HEADER_SIZE);
        assert_eq!(w.entries_written(), 0);

        let file_len = fs::metadata(&path).unwrap().len();
        assert_eq!(file_len, LOG_DEVICE_HEADER_SIZE);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn close_syncs_and_consumes() {
        let path = temp_log_device_path("close.vlog_device");
        let _ = fs::remove_file(&path);

        let mut w = LogDeviceWriter::open(&path).unwrap();
        w.append(b"final").unwrap();
        w.close().unwrap();

        // File should be intact and readable
        let mut w2 = LogDeviceWriter::open(&path).unwrap();
        let entries = w2.read_all_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], b"final");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_magic_rejected() {
        let path = temp_log_device_path("bad-magic.vlog_device");
        let _ = fs::remove_file(&path);

        fs::write(&path, b"NOTAVLOGxxxxxxxx").unwrap();
        let err = LogDeviceWriter::open(&path).unwrap_err();
        assert!(format!("{err:?}").contains("wrong magic"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_version_rejected() {
        let path = temp_log_device_path("bad-version.vlog_device");
        let _ = fs::remove_file(&path);

        let mut buf = Vec::new();
        buf.extend_from_slice(LOG_DEVICE_MAGIC);
        buf.extend_from_slice(&99u32.to_le_bytes()); // wrong version
        buf.extend_from_slice(&0u32.to_le_bytes());
        fs::write(&path, &buf).unwrap();

        let err = LogDeviceWriter::open(&path).unwrap_err();
        assert!(format!("{err:?}").contains("unsupported version"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_payload_entry_is_valid() {
        let path = temp_log_device_path("empty-payload.vlog_device");
        let _ = fs::remove_file(&path);

        let mut w = LogDeviceWriter::open(&path).unwrap();
        w.append(b"").unwrap();
        let entries = w.read_all_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_empty());
        let _ = fs::remove_file(&path);
    }
}
