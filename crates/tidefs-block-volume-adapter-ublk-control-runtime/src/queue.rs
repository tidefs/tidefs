// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ublk queue mapper: per-queue io_uring access over a shared data-queue.
//!
//! The [`UblkQueueMapper`] manages access to the ublk data-queue file
//! descriptor, io_uring ring, and mmap'd I/O buffer region for a single
//! ublk block device. All hardware queues share one `/dev/ublkcN` fd and
//! one mmap region; the mapper tracks per-queue lifecycle and provides
//! scoped [`UblkQueueHandle`] references for I/O dispatch.

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use io_uring::{cqueue, squeue, IoUring};
use tidefs_ublk_abi::{UblkSrvIoDesc, UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH};

use crate::{
    ublk_data_queue_device_path, UblkDataQueueRuntime, UblkDataQueueRuntimeOpenError,
    UblkDataQueueRuntimeOpenInput,
};

/// Configuration for the queue mapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkQueueMapperConfig {
    /// Kernel-assigned device ID for the ublk block device.
    pub dev_id: u32,
    /// Number of hardware queues to expose.
    pub nr_hw_queues: u16,
    /// Maximum in-flight commands per hardware queue.
    pub queue_depth: u16,
}

impl UblkQueueMapperConfig {
    /// New.
    #[must_use]
    pub const fn new(dev_id: u32, nr_hw_queues: u16, queue_depth: u16) -> Self {
        Self {
            dev_id,
            nr_hw_queues,
            queue_depth,
        }
    }
}

/// Errors from queue mapper operations.
#[derive(Debug)]
pub enum UblkQueueMapperError {
    /// Dataqueueopen.
    DataQueueOpen(UblkDataQueueRuntimeOpenError),
    /// The requested queue ID exceeds the configured hardware queue count.
    QueueIdOutOfRange {
        /// Queue id.
        q_id: u16,
        /// Nr hw queues.
        nr_hw_queues: u16,
    },
    /// The requested tag exceeds the configured queue depth.
    TagOutOfRange {
        /// Tag.
        tag: u16,
        /// Queue depth.
        queue_depth: u16,
    },
    /// Noqueuehandlesregistered.
    NoQueueHandlesRegistered,
    /// Io.
    Io(io::Error),
    /// A queue operation was attempted in an invalid state.
    InvalidQueueState {
        /// Queue id.
        q_id: u16,
        /// Reason.
        reason: &'static str,
    },
    /// The queue was already torn down.
    AlreadyClosed,
}

impl fmt::Display for UblkQueueMapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataQueueOpen(e) => write!(f, "data_queue_open: {e:?}"),
            Self::QueueIdOutOfRange { q_id, nr_hw_queues } => {
                write!(f, "q_id={q_id} out of range (0..{nr_hw_queues})")
            }
            Self::TagOutOfRange { tag, queue_depth } => {
                write!(f, "tag={tag} out of range (0..{queue_depth})")
            }
            Self::NoQueueHandlesRegistered => {
                write!(f, "no queue handles registered")
            }
            Self::Io(e) => write!(f, "io: {e}"),
            Self::InvalidQueueState { q_id, reason } => {
                write!(f, "queue {q_id} invalid: {reason}")
            }
            Self::AlreadyClosed => write!(f, "queue mapper already closed"),
        }
    }
}

impl std::error::Error for UblkQueueMapperError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<UblkDataQueueRuntimeOpenError> for UblkQueueMapperError {
    fn from(e: UblkDataQueueRuntimeOpenError) -> Self {
        Self::DataQueueOpen(e)
    }
}

impl From<io::Error> for UblkQueueMapperError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// State tracked for each hardware queue.
#[derive(Clone, Debug, Eq, PartialEq)]
enum UblkQueueSlotState {
    /// Queue was registered but no FETCH_REQ have been submitted.
    Registered,
    /// FETCH_REQ commands have been submitted for this queue.
    FetchReqsInFlight { submitted: u32 },
    /// Queue has been torn down.
    Closed,
}

/// A handle to a specific hardware queue within the mapper.
///
/// Provides queue-scoped I/O submission and buffer access without
/// allowing cross-queue leakage.
#[derive(Debug)]
pub struct UblkQueueHandle<'a> {
    mapper: &'a UblkQueueMapper,
    q_id: u16,
}

impl<'a> UblkQueueHandle<'a> {
    /// Return the hardware queue ID this handle binds.
    #[must_use]
    pub const fn q_id(&self) -> u16 {
        self.q_id
    }

    /// Return the queue depth for this handle's queue.
    #[must_use]
    pub fn queue_depth(&self) -> u16 {
        self.mapper.config.queue_depth
    }

    /// Access the `UblkSrvIoDesc` for the given tag on this queue.
    ///
    /// Returns `None` if the tag is out of range.
    #[must_use]
    pub fn io_desc(&self, tag: u16) -> Option<&UblkSrvIoDesc> {
        self.mapper.runtime.io_desc_for_queue(self.q_id, tag)
    }

    /// Access the data buffer for the given tag on this queue.
    ///
    /// Returns `None` if the tag is out of range.
    #[must_use]
    pub fn data_buffer(&self, tag: u16) -> Option<&[u8]> {
        self.mapper.runtime.data_buffer_for_queue(self.q_id, tag)
    }

    /// Return the global slot index for a tag on this queue.
    #[must_use]
    pub const fn tag_to_slot(&self, tag: u16) -> Option<usize> {
        self.mapper.runtime.queue_tag_to_slot(self.q_id, tag)
    }
}

impl<'a> fmt::Display for UblkQueueHandle<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ublk queue handle q_id={}", self.q_id)
    }
}

/// Manages the ublk data-queue file descriptor, io_uring ring, and
/// per-queue state for a single ublk device.
///
/// All hardware queues share one `/dev/ublkcN` fd and one mmap'd I/O
/// buffer region. The mapper tracks per-queue lifecycle and provides
/// scoped handles for I/O dispatch.
pub struct UblkQueueMapper {
    config: UblkQueueMapperConfig,
    runtime: UblkDataQueueRuntime,
    queue_states: Vec<UblkQueueSlotState>,
    closed: bool,
}

impl UblkQueueMapper {
    /// Open the ublk data-queue device, set up io_uring, and mmap the
    /// I/O buffer. Initializes per-queue state tracking.
    ///
    /// # Errors
    ///
    /// Returns [`UblkQueueMapperError`] if the data queue cannot be opened
    /// or the mmap fails.
    pub fn open(config: UblkQueueMapperConfig) -> Result<Self, UblkQueueMapperError> {
        let queue_path = ublk_data_queue_device_path(config.dev_id);
        Self::open_at(&queue_path, config)
    }

    /// Open the ublk data-queue at a specific path (useful for testing
    /// with mocked device nodes).
    ///
    /// # Errors
    ///
    /// Returns [`UblkQueueMapperError`] on failure.
    pub fn open_at(
        path: &Path,
        config: UblkQueueMapperConfig,
    ) -> Result<Self, UblkQueueMapperError> {
        if config.nr_hw_queues == 0 || config.nr_hw_queues > UBLK_MAX_NR_QUEUES {
            return Err(UblkQueueMapperError::QueueIdOutOfRange {
                q_id: 0,
                nr_hw_queues: config.nr_hw_queues,
            });
        }
        if config.queue_depth == 0 || config.queue_depth > UBLK_MAX_QUEUE_DEPTH {
            return Err(UblkQueueMapperError::TagOutOfRange {
                tag: 0,
                queue_depth: config.queue_depth,
            });
        }

        let open_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
            config.dev_id,
            0, // q_id 0 for the shared runtime
            config.nr_hw_queues,
            config.queue_depth,
        );

        let runtime = crate::open_data_queue_runtime(path, open_input)?;

        let queue_states = (0..config.nr_hw_queues)
            .map(|_| UblkQueueSlotState::Registered)
            .collect();

        Ok(Self {
            config,
            runtime,
            queue_states,
            closed: false,
        })
    }

    /// Return the configuration this mapper was created with.
    #[must_use]
    pub const fn config(&self) -> &UblkQueueMapperConfig {
        &self.config
    }

    /// Return the number of hardware queues.
    #[must_use]
    pub fn nr_hw_queues(&self) -> u16 {
        self.config.nr_hw_queues
    }

    /// Return the queue depth.
    #[must_use]
    pub fn queue_depth(&self) -> u16 {
        self.config.queue_depth
    }

    /// Return whether the mapper is still open (not closed/consumed).
    #[must_use]
    pub const fn is_open(&self) -> bool {
        !self.closed
    }

    /// Get a handle for a specific hardware queue.
    ///
    /// Returns `None` if `q_id` is out of range or the mapper is closed.
    #[must_use]
    pub fn queue_handle(&self, q_id: u16) -> Option<UblkQueueHandle<'_>> {
        if self.closed || q_id >= self.config.nr_hw_queues {
            return None;
        }
        if self.queue_states[q_id as usize] == UblkQueueSlotState::Closed {
            return None;
        }
        Some(UblkQueueHandle { mapper: self, q_id })
    }

    /// Return the total number of tags across all queues.
    #[must_use]
    pub fn total_slots(&self) -> usize {
        (self.config.nr_hw_queues as usize) * (self.config.queue_depth as usize)
    }

    /// Access the underlying runtime's ring mutably (for advanced use).
    pub fn ring_mut(&mut self) -> &mut IoUring<squeue::Entry128, cqueue::Entry> {
        self.runtime.ring_mut()
    }

    /// Access the underlying runtime's file descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.runtime.as_fd()
    }

    /// Mark a specific queue's FETCH_REQ as submitted.
    pub fn mark_queue_fetch_reqs_submitted(
        &mut self,
        q_id: u16,
        count: u32,
    ) -> Result<(), UblkQueueMapperError> {
        if self.closed {
            return Err(UblkQueueMapperError::AlreadyClosed);
        }
        if q_id as usize >= self.queue_states.len() {
            return Err(UblkQueueMapperError::QueueIdOutOfRange {
                q_id,
                nr_hw_queues: self.config.nr_hw_queues,
            });
        }
        self.queue_states[q_id as usize] =
            UblkQueueSlotState::FetchReqsInFlight { submitted: count };
        Ok(())
    }

    /// Return the number of queues that have submitted FETCH_REQ.
    #[must_use]
    pub fn queues_with_fetches(&self) -> usize {
        self.queue_states
            .iter()
            .filter(|s| matches!(s, UblkQueueSlotState::FetchReqsInFlight { .. }))
            .count()
    }

    /// Return whether all queues have submitted FETCH_REQ.
    #[must_use]
    pub fn all_queues_have_fetches(&self) -> bool {
        !self.closed
            && !self.queue_states.is_empty()
            && self
                .queue_states
                .iter()
                .all(|s| matches!(s, UblkQueueSlotState::FetchReqsInFlight { .. }))
    }

    /// Close (tear down) a specific queue. After this, handles for
    /// that queue are no longer valid.
    pub fn close_queue(&mut self, q_id: u16) -> Result<(), UblkQueueMapperError> {
        if self.closed {
            return Err(UblkQueueMapperError::AlreadyClosed);
        }
        if q_id as usize >= self.queue_states.len() {
            return Err(UblkQueueMapperError::QueueIdOutOfRange {
                q_id,
                nr_hw_queues: self.config.nr_hw_queues,
            });
        }
        if self.queue_states[q_id as usize] == UblkQueueSlotState::Closed {
            return Err(UblkQueueMapperError::AlreadyClosed);
        }
        self.queue_states[q_id as usize] = UblkQueueSlotState::Closed;
        Ok(())
    }

    /// Consume the mapper, returning the underlying runtime.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyClosed` if the mapper was already consumed.
    pub fn into_runtime(mut self) -> Result<UblkDataQueueRuntime, UblkQueueMapperError> {
        if self.closed {
            return Err(UblkQueueMapperError::AlreadyClosed);
        }
        self.closed = true;
        Ok(self.runtime)
    }
}

impl fmt::Debug for UblkQueueMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UblkQueueMapper")
            .field("config", &self.config)
            .field("queue_states", &self.queue_states)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── UblkQueueMapperConfig ─────────────────────────────────────────

    #[test]
    fn mapper_config_new_preserves_values() {
        let config = UblkQueueMapperConfig::new(42, 4, 128);
        assert_eq!(config.dev_id, 42);
        assert_eq!(config.nr_hw_queues, 4);
        assert_eq!(config.queue_depth, 128);
    }

    #[test]
    fn mapper_config_clone_eq() {
        let a = UblkQueueMapperConfig::new(7, 2, 64);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── UblkQueueMapperError ──────────────────────────────────────────

    #[test]
    fn mapper_error_display() {
        let e = UblkQueueMapperError::QueueIdOutOfRange {
            q_id: 5,
            nr_hw_queues: 4,
        };
        let s = e.to_string();
        assert!(s.contains("5"));
        assert!(s.contains("4"));

        let e2 = UblkQueueMapperError::TagOutOfRange {
            tag: 128,
            queue_depth: 64,
        };
        let s2 = e2.to_string();
        assert!(s2.contains("128"));
        assert!(s2.contains("64"));

        let e3 = UblkQueueMapperError::AlreadyClosed;
        assert!(e3.to_string().contains("closed"));
    }

    #[test]
    fn mapper_error_from_io() {
        let io_err = io::Error::other("test");
        let mapper_err: UblkQueueMapperError = io_err.into();
        assert!(matches!(mapper_err, UblkQueueMapperError::Io(_)));
    }

    // ── UblkQueueMapper structural tests ──────────────────────────────

    #[test]
    fn mapper_open_rejects_zero_hw_queues() {
        let config = UblkQueueMapperConfig::new(1, 0, 64);
        let result = UblkQueueMapper::open(config);
        assert!(result.is_err());
    }

    #[test]
    fn mapper_open_rejects_zero_queue_depth() {
        let config = UblkQueueMapperConfig::new(1, 1, 0);
        let result = UblkQueueMapper::open(config);
        assert!(result.is_err());
    }

    #[test]
    fn mapper_open_rejects_too_many_hw_queues() {
        let config = UblkQueueMapperConfig::new(1, UBLK_MAX_NR_QUEUES + 1, 64);
        let result = UblkQueueMapper::open(config);
        assert!(result.is_err());
    }

    #[test]
    fn mapper_open_rejects_too_large_queue_depth() {
        let config = UblkQueueMapperConfig::new(1, 1, UBLK_MAX_QUEUE_DEPTH + 1);
        let result = UblkQueueMapper::open(config);
        assert!(result.is_err());
    }

    // ── UblkQueueHandle (structural, no real ublk device) ─────────────

    #[test]
    fn queue_handle_q_id_and_depth() {
        // We can't create a real UblkQueueMapper without /dev/ublkcN,
        // but we can test handle properties structurally.
        // Create a runtime with /dev/null for structural testing.
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(0, 4, 64),
            runtime: {
                // We need a DataQueueRuntime for structural tests.
                // Since we can't open a real ublk device in unit tests,
                // construct one by hand via /dev/null backing.
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(64)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 0,
                    q_id: 0,
                    nr_hw_queues: 4,
                    queue_depth: 64,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 64,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 64,
                    io_buf_nr_hw_queues: 4,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered; 4],
            closed: false,
        };

        let handle = mapper.queue_handle(0).expect("q_id 0");
        assert_eq!(handle.q_id(), 0);
        assert_eq!(handle.queue_depth(), 64);

        let handle3 = mapper.queue_handle(3).expect("q_id 3");
        assert_eq!(handle3.q_id(), 3);

        assert!(mapper.queue_handle(4).is_none());
        assert!(mapper.queue_handle(u16::MAX).is_none());
    }

    #[test]
    fn queue_handle_display() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(0, 2, 32),
            runtime: {
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(32)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 0,
                    q_id: 0,
                    nr_hw_queues: 2,
                    queue_depth: 32,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 32,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 32,
                    io_buf_nr_hw_queues: 2,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered; 2],
            closed: false,
        };

        let h = mapper.queue_handle(1).expect("q_id 1");
        let s = h.to_string();
        assert!(s.contains("1"));
        assert!(s.contains("ublk"));
    }

    // ── Mapper state tracking ─────────────────────────────────────────

    #[test]
    fn mapper_mark_queue_fetch_reqs_and_query() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mut mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(0, 4, 64),
            runtime: {
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(64)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 0,
                    q_id: 0,
                    nr_hw_queues: 4,
                    queue_depth: 64,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 64,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 64,
                    io_buf_nr_hw_queues: 4,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered; 4],
            closed: false,
        };

        assert_eq!(mapper.total_slots(), 256);
        assert_eq!(mapper.queues_with_fetches(), 0);
        assert!(!mapper.all_queues_have_fetches());

        mapper.mark_queue_fetch_reqs_submitted(0, 64).unwrap();
        assert_eq!(mapper.queues_with_fetches(), 1);
        assert!(!mapper.all_queues_have_fetches());

        mapper.mark_queue_fetch_reqs_submitted(1, 64).unwrap();
        mapper.mark_queue_fetch_reqs_submitted(2, 64).unwrap();
        mapper.mark_queue_fetch_reqs_submitted(3, 64).unwrap();
        assert_eq!(mapper.queues_with_fetches(), 4);
        assert!(mapper.all_queues_have_fetches());
    }

    #[test]
    fn mapper_mark_queue_rejects_out_of_range() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mut mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(0, 2, 64),
            runtime: {
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(64)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 0,
                    q_id: 0,
                    nr_hw_queues: 2,
                    queue_depth: 64,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 64,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 64,
                    io_buf_nr_hw_queues: 2,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered; 2],
            closed: false,
        };

        assert!(mapper.mark_queue_fetch_reqs_submitted(2, 64).is_err());
        assert!(mapper.mark_queue_fetch_reqs_submitted(100, 64).is_err());
    }

    #[test]
    fn mapper_close_queue_then_handle_returns_none() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mut mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(0, 2, 32),
            runtime: {
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(32)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 0,
                    q_id: 0,
                    nr_hw_queues: 2,
                    queue_depth: 32,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 32,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 32,
                    io_buf_nr_hw_queues: 2,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered; 2],
            closed: false,
        };

        // Handle exists before close
        assert!(mapper.queue_handle(1).is_some());

        // Closing the queue doesn't remove handles (they borrow the mapper),
        // but subsequent closes are tracked
        mapper.close_queue(1).unwrap();
        assert!(mapper.close_queue(1).is_err()); // Already closed

        // Handle for a different queue still works
        assert!(mapper.queue_handle(0).is_some());
    }

    #[test]
    fn mapper_into_runtime_consumes_and_prevents_reuse() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(0, 1, 32),
            runtime: {
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(32)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 0,
                    q_id: 0,
                    nr_hw_queues: 1,
                    queue_depth: 32,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 32,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 32,
                    io_buf_nr_hw_queues: 1,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered],
            closed: false,
        };

        assert!(mapper.is_open());
        let _runtime = mapper.into_runtime().expect("first into_runtime");
        // Can't call into_runtime again (moved)
    }

    #[test]
    fn mapper_closed_rejects_queue_handle() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(0, 1, 32),
            runtime: {
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(32)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 0,
                    q_id: 0,
                    nr_hw_queues: 1,
                    queue_depth: 32,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 32,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 32,
                    io_buf_nr_hw_queues: 1,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered],
            closed: true,
        };

        assert!(mapper.queue_handle(0).is_none());
    }

    #[test]
    fn mapper_total_slots_computes_correctly() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        for (nr, depth, expected) in [(1, 64, 64), (2, 32, 64), (4, 16, 64), (4, 64, 256)] {
            let mapper = UblkQueueMapper {
                config: UblkQueueMapperConfig::new(0, nr, depth),
                runtime: {
                    let data_file = control_file.try_clone().expect("clone fd");
                    let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                        .build(depth as u32)
                        .expect("io_uring create");
                    let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                        dev_id: 0,
                        q_id: 0,
                        nr_hw_queues: nr,
                        queue_depth: depth,
                        data_queue_path: PathBuf::from("/dev/null"),
                        ring_entries: depth as u32,
                        data_queue_fd_open: true,
                        io_uring_ready: true,
                        runtime_live: true,
                    };
                    UblkDataQueueRuntime {
                        data_queue_file: data_file.try_clone().expect("clone fd"),
                        ring,
                        outcome,
                        cmd_buf_ptrs: Vec::new(),
                        cmd_buf_lens: Vec::new(),
                        io_buf_queue_depth: depth,
                        io_buf_nr_hw_queues: nr,
                        in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                        nodrop_enabled: true,
                        cq_overflow_count: 0,
                    }
                },
                queue_states: vec![UblkQueueSlotState::Registered; nr as usize],
                closed: false,
            };
            assert_eq!(mapper.total_slots(), expected, "nr={nr} depth={depth}");
        }
    }

    #[test]
    fn mapper_config_accessors() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mapper = UblkQueueMapper {
            config: UblkQueueMapperConfig::new(99, 2, 128),
            runtime: {
                let data_file = control_file.try_clone().expect("clone fd");
                let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
                    .build(128)
                    .expect("io_uring create");
                let outcome = crate::UblkDataQueueRuntimeOpenOutcome {
                    dev_id: 99,
                    q_id: 0,
                    nr_hw_queues: 2,
                    queue_depth: 128,
                    data_queue_path: PathBuf::from("/dev/null"),
                    ring_entries: 128,
                    data_queue_fd_open: true,
                    io_uring_ready: true,
                    runtime_live: true,
                };
                UblkDataQueueRuntime {
                    data_queue_file: data_file,
                    ring,
                    outcome,
                    cmd_buf_ptrs: Vec::new(),
                    cmd_buf_lens: Vec::new(),
                    io_buf_queue_depth: 128,
                    io_buf_nr_hw_queues: 2,
                    in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
                    nodrop_enabled: true,
                    cq_overflow_count: 0,
                }
            },
            queue_states: vec![UblkQueueSlotState::Registered; 2],
            closed: false,
        };

        assert_eq!(mapper.config().dev_id, 99);
        assert_eq!(mapper.nr_hw_queues(), 2);
        assert_eq!(mapper.queue_depth(), 128);
    }
}
