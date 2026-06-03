//! Transport outbound writev frame-coalescing dispatch: merges consecutive
//! queued wire-frame buffers into vectored I/O calls to reduce per-frame
//! send(2)/write(2) syscall overhead on the transport outbound hot path.
//!
//! ## Design
//!
//! The [`WritevBatcher`] accumulates framed byte payloads (`Vec<u8>`) into a
//! pending batch. When the batch reaches `max_iovec` frames or a barrier
//! marker arrives, the entire batch is flushed to the socket in a single
//! `write_vectored` call. Frame ordering is preserved — the batcher never
//! reorders.
//!
//! ## Integration
//!
//! Inserted between `SendQueue::dequeue()` and the socket write in
//! [`crate::send_dispatch::SendDrainer`]. The batcher is per-connection:
//! frames destined for different connections use separate batchers.
//!
//! ## Platform note
//!
//! Uses `tokio::io::AsyncWriteExt::write_vectored`, which delegates to
//! `writev(2)` on Unix and `WSASend` with multiple buffers on Windows.
//!
//! ## Configuration
//!
//! `max_iovec` (default 128) bounds kernel iov copy overhead. The default
//! matches typical `IOV_MAX` limits while keeping batch latency low under
//! mixed-priority workloads.

use std::io;

use tokio::io::AsyncWriteExt;

// ---------------------------------------------------------------------------
// WritevBatcherConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`WritevBatcher`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritevBatcherConfig {
    /// Maximum number of iovecs per `writev` call.
    ///
    /// Default: 128.
    pub max_iovec: usize,
}

impl Default for WritevBatcherConfig {
    fn default() -> Self {
        Self { max_iovec: 128 }
    }
}

impl WritevBatcherConfig {
    /// Create a new config, validating that `max_iovec` is nonzero.
    ///
    /// Returns `None` if `max_iovec` is zero.
    #[must_use]
    pub fn new(max_iovec: usize) -> Option<Self> {
        if max_iovec == 0 {
            return None;
        }
        Some(Self { max_iovec })
    }
}

// ---------------------------------------------------------------------------
// WritevBatcher
// ---------------------------------------------------------------------------

/// Accumulates framed wire-byte buffers into a batch and flushes them via
/// vectored I/O.
///
/// Frame ordering is preserved: frames are written in the exact order they
/// were pushed. A barrier marker (represented by calling [`flush`](Self::flush))
/// forces the current batch to be written before subsequent frames.
///
/// # Example
///
/// ```ignore
/// let mut batcher = WritevBatcher::new(WritevBatcherConfig::default());
/// for frame in frames {
///     batcher.push(frame);
///     if batcher.is_full() {
///         batcher.flush(&mut tcp_stream).await?;
///     }
/// }
/// if !batcher.is_empty() {
///     batcher.flush(&mut tcp_stream).await?;
/// }
/// ```
pub struct WritevBatcher {
    config: WritevBatcherConfig,
    /// Accumulated framed payloads (already wire-encoded, ready for writev).
    pending: Vec<Vec<u8>>,
}

impl WritevBatcher {
    /// Create a new batcher with the given configuration.
    #[must_use]
    pub fn new(config: WritevBatcherConfig) -> Self {
        Self {
            config,
            pending: Vec::with_capacity(config.max_iovec.min(64)),
        }
    }

    /// Push a framed wire-byte buffer into the batch.
    ///
    /// Returns `true` if the batcher is now full (`max_iovec` reached),
    /// signalling that the caller should [`flush`](Self::flush).
    #[must_use]
    pub fn push(&mut self, frame: Vec<u8>) -> bool {
        self.pending.push(frame);
        self.pending.len() >= self.config.max_iovec
    }

    /// Number of pending frames awaiting flush.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the batcher has no pending frames.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Whether the batcher is at `max_iovec` capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.pending.len() >= self.config.max_iovec
    }

    /// Total bytes pending across all accumulated frames.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.pending.iter().map(|b| b.len()).sum()
    }

    /// Flush all pending frames to `writer` via a single vectored I/O call.
    ///
    /// If only one frame is pending, uses a normal `write_all`. For two or
    /// more frames, uses `write_vectored` to reduce syscall overhead.
    ///
    /// Returns the total number of bytes written. Clears the pending batch
    /// on success. On error, the pending batch is NOT cleared — the caller
    /// can retry or call [`clear`](Self::clear) to discard.
    pub async fn flush<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> io::Result<usize> {
        if self.pending.is_empty() {
            return Ok(0);
        }

        let total = self.total_bytes();

        if self.pending.len() == 1 {
            writer.write_all(&self.pending[0]).await?;
        } else {
            // write_vectored may perform partial writes; loop until all
            // bytes are written, advancing offsets into each buffer.
            let mut written = 0usize;
            while written < total {
                let mut bufs: Vec<io::IoSlice<'_>> = Vec::with_capacity(self.pending.len());
                let mut skipped = 0usize;
                for frame in &self.pending {
                    let len = frame.len();
                    if skipped + len <= written {
                        skipped += len;
                        continue;
                    }
                    let start = written.saturating_sub(skipped);
                    bufs.push(io::IoSlice::new(&frame[start..]));
                    skipped += len;
                }

                let n = writer.write_vectored(&bufs).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write_vectored returned 0 with pending data",
                    ));
                }
                written += n;
            }
        }

        self.pending.clear();
        Ok(total)
    }

    /// Discard all pending frames without writing them.
    ///
    /// Useful after a write error when the caller intends to tear down the
    /// connection rather than retry.
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

impl std::fmt::Debug for WritevBatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritevBatcher")
            .field("max_iovec", &self.config.max_iovec)
            .field("pending", &self.pending.len())
            .field("total_bytes", &self.total_bytes())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // Config tests
    // -------------------------------------------------------------------

    #[test]
    fn config_default() {
        let cfg = WritevBatcherConfig::default();
        assert_eq!(cfg.max_iovec, 128);
    }

    #[test]
    fn config_new_zero_rejected() {
        assert!(WritevBatcherConfig::new(0).is_none());
    }

    #[test]
    fn config_new_valid() {
        let cfg = WritevBatcherConfig::new(64).unwrap();
        assert_eq!(cfg.max_iovec, 64);
    }

    // -------------------------------------------------------------------
    // Batcher: basic operations
    // -------------------------------------------------------------------

    #[test]
    fn new_batcher_empty() {
        let b = WritevBatcher::new(WritevBatcherConfig::default());
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
        assert_eq!(b.total_bytes(), 0);
        assert!(!b.is_full());
    }

    #[test]
    fn push_increments_count() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::new(10).unwrap());
        assert!(!b.push(vec![1, 2, 3]));
        assert_eq!(b.len(), 1);
        assert_eq!(b.total_bytes(), 3);
        assert!(!b.is_empty());
    }

    #[test]
    fn push_reports_full_at_max_iovec() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::new(3).unwrap());
        assert!(!b.push(vec![0; 1]));
        assert!(!b.push(vec![0; 2]));
        assert!(b.push(vec![0; 3])); // 3rd frame → full
        assert!(b.is_full());
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn push_beyond_max_iovec_still_grows() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::new(2).unwrap());
        let _ = b.push(vec![1]);
        let _ = b.push(vec![2]); // full
        let _ = b.push(vec![3]); // beyond full — caller responsibility to flush
        assert_eq!(b.len(), 3);
        assert!(b.is_full());
    }

    #[test]
    fn total_bytes_accurate() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let _ = b.push(vec![0; 10]);
        let _ = b.push(vec![0; 25]);
        let _ = b.push(vec![0; 7]);
        assert_eq!(b.total_bytes(), 42);
    }

    #[test]
    fn clear_discards_pending() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let _ = b.push(vec![1, 2]);
        let _ = b.push(vec![3, 4]);
        assert_eq!(b.len(), 2);
        b.clear();
        assert!(b.is_empty());
        assert_eq!(b.total_bytes(), 0);
    }

    // -------------------------------------------------------------------
    // Batcher: flush with tokio_test mock writer
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn flush_empty_returns_zero() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let mut writer = tokio_test::io::Builder::new().build();
        let written = b.flush(&mut writer).await.unwrap();
        assert_eq!(written, 0);
    }

    #[tokio::test]
    async fn flush_single_frame_uses_write() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let _ = b.push(b"hello".to_vec());

        let mut writer = Vec::new();

        let written = b.flush(&mut writer).await.unwrap();
        assert_eq!(written, 5);
        assert!(b.is_empty());
        assert_eq!(&writer[..], b"hello");
    }

    #[tokio::test]
    async fn flush_multiple_frames_uses_write_vectored() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let _ = b.push(b"abc".to_vec());
        let _ = b.push(b"def".to_vec());
        let _ = b.push(b"ghi".to_vec());

        let mut writer = Vec::new();

        let written = b.flush(&mut writer).await.unwrap();
        assert_eq!(written, 9); // 3 + 3 + 3
        assert!(b.is_empty());
        assert_eq!(&writer[..], b"abcdefghi");
    }

    #[tokio::test]
    async fn flush_clears_pending_on_success() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let _ = b.push(b"data".to_vec());
        assert_eq!(b.len(), 1);

        let mut writer = Vec::new();

        b.flush(&mut writer).await.unwrap();
        assert!(b.is_empty());
        assert_eq!(b.total_bytes(), 0);
        assert_eq!(&writer[..], b"data");
    }

    #[tokio::test]
    async fn flush_error_preserves_pending() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let _ = b.push(b"doomed".to_vec());

        let mut writer = tokio_test::io::Builder::new()
            .write_error(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pipe closed",
            ))
            .build();

        let result = b.flush(&mut writer).await;
        assert!(result.is_err());
        // Pending frames should still be present after error.
        assert_eq!(b.len(), 1);
        assert_eq!(b.pending[0], b"doomed");
    }

    // -------------------------------------------------------------------
    // Batcher: integration scenarios
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn push_flush_push_flush_cycle() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::new(2).unwrap());

        // Batch 1: accumulate 2 frames, flush.
        let _ = b.push(b"a".to_vec());
        let _ = b.push(b"b".to_vec());
        assert!(b.is_full());

        let mut writer = Vec::new();
        b.flush(&mut writer).await.unwrap();
        assert!(b.is_empty());
        assert_eq!(&writer[..], b"ab");

        // Batch 2: another set of frames.
        let mut writer2 = Vec::new();
        let _ = b.push(b"c".to_vec());
        assert!(!b.is_empty());

        b.flush(&mut writer2).await.unwrap();
        assert!(b.is_empty());
        assert_eq!(&writer2[..], b"c");
    }

    #[tokio::test]
    async fn barrier_flush_semantics() {
        // Barriers are modelled by the caller flushing explicitly before
        // pushing post-barrier frames.
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());

        // Pre-barrier frames.
        let _ = b.push(b"before1".to_vec());
        let _ = b.push(b"before2".to_vec());

        // Flush (barrier).
        let mut writer = Vec::new();
        b.flush(&mut writer).await.unwrap();
        assert_eq!(&writer[..], b"before1before2");

        // Post-barrier frames — start fresh batch.
        let mut writer2 = Vec::new();
        let _ = b.push(b"after1".to_vec());

        b.flush(&mut writer2).await.unwrap();
        assert_eq!(&writer2[..], b"after1");
    }

    #[tokio::test]
    async fn max_iovec_split_large_batch() {
        let max = 4;
        let mut b = WritevBatcher::new(WritevBatcherConfig::new(max).unwrap());
        let total_frames = 10;

        let mut all_written = Vec::new();
        let mut frame_data: Vec<Vec<u8>> = Vec::new();

        for i in 0..total_frames {
            let data = vec![b'0' + i as u8];
            frame_data.push(data.clone());
            let full = b.push(data);
            if full {
                b.flush(&mut all_written).await.unwrap();
                assert!(b.is_empty());
            }
        }
        if !b.is_empty() {
            b.flush(&mut all_written).await.unwrap();
        }

        let expected: Vec<u8> = frame_data.iter().flatten().cloned().collect();
        assert_eq!(&all_written[..], &expected[..]);
    }

    #[tokio::test]
    async fn empty_queue_no_op() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        assert!(b.is_empty());
        let mut writer = tokio_test::io::Builder::new().build();
        let written = b.flush(&mut writer).await.unwrap();
        assert_eq!(written, 0);
    }

    #[tokio::test]
    async fn mixed_frame_sizes_coalescing() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let sizes = [1, 64, 256, 4096, 7];
        let expected_total: usize = sizes.iter().sum();
        let mut expected_bytes = Vec::new();

        for &sz in &sizes {
            let data = vec![(sz % 256) as u8; sz];
            expected_bytes.extend_from_slice(&data);
            let _ = b.push(data);
        }

        assert_eq!(b.total_bytes(), expected_total);

        let mut writer = Vec::new();
        let written = b.flush(&mut writer).await.unwrap();
        assert_eq!(written, expected_total);
        assert_eq!(&writer[..], &expected_bytes[..]);
    }

    // -------------------------------------------------------------------
    // Debug output
    // -------------------------------------------------------------------

    #[test]
    fn debug_output() {
        let mut b = WritevBatcher::new(WritevBatcherConfig::default());
        let _ = b.push(vec![1, 2]);
        let s = format!("{b:?}");
        assert!(s.contains("max_iovec"));
        assert!(s.contains("pending"));
        assert!(s.contains("total_bytes"));
    }
}
