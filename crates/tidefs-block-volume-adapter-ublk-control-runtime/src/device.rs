// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ublk device builder: orchestrates the full device lifecycle.
//!
//! The [`UblkDeviceBuilder`] sequences the kernel ublk control commands
//! to bring a block device from registration through to I/O readiness:
//!
//! ```text
//! ADD_DEV -> open data queue -> SET_PARAMS -> FETCH_REQ* -> START_DEV
//! ```
//!
//! On any failure the builder tears down partially-constructed state
//! (DEL_DEV + closed queue runtime) so the kernel is not left with an
//! unusable device.

use std::io;

use tidefs_ublk_abi::{UblkFeatureFlags, UblkParams};

use crate::{
    issue_set_params, issue_start_dev, open_data_queue_runtime,
    submit_runtime_all_queues_fetch_reqs_without_wait, ublk_data_queue_device_path,
    UblkControlAddDevError, UblkControlAddDevInput, UblkControlDelDevError,
    UblkControlRemoveDeviceError, UblkControlRuntime, UblkControlSetParamsError,
    UblkControlSetParamsInput, UblkControlStartDevError, UblkControlStartDevInput,
    UblkControlStartDevReadiness, UblkDataQueueFetchReqSubmissionError, UblkDataQueueRuntime,
    UblkDataQueueRuntimeOpenError, UblkDataQueueRuntimeOpenInput, UblkManagedDevice,
    TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID, TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES,
    TIDEFS_UBLK_ADD_DEV_DEFAULT_NR_HW_QUEUES, TIDEFS_UBLK_ADD_DEV_DEFAULT_QUEUE_DEPTH,
    TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
};

/// Configuration for building a ublk block device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkDeviceConfig {
    /// Number of hardware queues exposed to the kernel ublk driver.
    pub nr_hw_queues: u16,
    /// Maximum in-flight commands per hardware queue.
    pub queue_depth: u16,
    /// Maximum I/O buffer bytes in the mmap'd data region.
    pub max_io_buf_bytes: u32,
    /// Feature flags negotiated during ADD_DEV.
    pub flags: UblkFeatureFlags,
    /// Device parameters including capacity, sector size, and geometry.
    pub params: UblkParams,
}

impl Default for UblkDeviceConfig {
    fn default() -> Self {
        Self {
            nr_hw_queues: TIDEFS_UBLK_ADD_DEV_DEFAULT_NR_HW_QUEUES,
            queue_depth: TIDEFS_UBLK_ADD_DEV_DEFAULT_QUEUE_DEPTH,
            max_io_buf_bytes: TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES,
            flags: TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES,
            params: UblkParams::default(),
        }
    }
}

impl UblkDeviceConfig {
    /// Conservative TideFS defaults with io_uring completion-in-task enabled.
    #[must_use]
    pub fn conservative_tidefs() -> Self {
        Self {
            nr_hw_queues: TIDEFS_UBLK_ADD_DEV_DEFAULT_NR_HW_QUEUES,
            queue_depth: TIDEFS_UBLK_ADD_DEV_DEFAULT_QUEUE_DEPTH,
            max_io_buf_bytes: TIDEFS_UBLK_ADD_DEV_DEFAULT_MAX_IO_BUF_BYTES,
            flags: TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES
                .union(UblkFeatureFlags::URING_CMD_COMP_IN_TASK),
            params: UblkParams::default(),
        }
    }
}

/// Outcome of a successful device build.
///
/// `data_queue_runtime` is intentionally not `Clone`/`Eq` — the runtime
/// owns an mmap and an io_uring instance; it is consumed on success.
#[derive(Debug)]
pub struct UblkDeviceBuildOutcome {
    /// The fully-initialized managed device registered in the control runtime.
    pub managed_device: UblkManagedDevice,
    /// The live data-queue runtime owning the io_uring ring and mmap.
    pub data_queue_runtime: UblkDataQueueRuntime,
    /// Number of FETCH_REQ commands submitted during the build.
    pub submitted_fetch_commands: u32,
}

/// Errors that can occur during the device build lifecycle.
#[derive(Debug)]
pub enum UblkDeviceBuildError {
    /// ADD_DEV ioctl failed.
    AddDev(UblkControlAddDevError),
    /// Opening the data-queue device or io_uring setup failed.
    DataQueueOpen(UblkDataQueueRuntimeOpenError),
    /// SET_PARAMS ioctl failed.
    SetParams(UblkControlSetParamsError),
    /// Submitting FETCH_REQ commands to the data-queue ring failed.
    FetchReqSubmit(UblkDataQueueFetchReqSubmissionError),
    /// START_DEV ioctl failed.
    StartDev(UblkControlStartDevError),
    /// Cleanup after a build failure itself encountered an error.
    Cleanup {
        /// The kernel-assigned device ID being cleaned up.
        dev_id: u32,
        /// The original error that triggered cleanup.
        cause: Box<UblkDeviceBuildError>,
        /// The DEL_DEV error encountered during cleanup.
        del_dev_error: UblkControlDelDevError,
    },
    /// An I/O error occurred during the build lifecycle.
    Io(io::Error),
}

impl std::fmt::Display for UblkDeviceBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddDev(e) => write!(f, "add_dev: {e:?}"),
            Self::DataQueueOpen(e) => write!(f, "data_queue_open: {e:?}"),
            Self::SetParams(e) => write!(f, "set_params: {e:?}"),
            Self::FetchReqSubmit(e) => write!(f, "fetch_req_submit: {e:?}"),
            Self::StartDev(e) => write!(f, "start_dev: {e:?}"),
            Self::Cleanup {
                dev_id,
                cause,
                del_dev_error,
            } => {
                write!(
                    f,
                    "cleanup for dev_id={dev_id} failed after {cause}: del_dev error {del_dev_error:?}"
                )
            }
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for UblkDeviceBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<UblkControlAddDevError> for UblkDeviceBuildError {
    fn from(e: UblkControlAddDevError) -> Self {
        Self::AddDev(e)
    }
}

impl From<UblkDataQueueRuntimeOpenError> for UblkDeviceBuildError {
    fn from(e: UblkDataQueueRuntimeOpenError) -> Self {
        Self::DataQueueOpen(e)
    }
}

impl From<UblkControlSetParamsError> for UblkDeviceBuildError {
    fn from(e: UblkControlSetParamsError) -> Self {
        Self::SetParams(e)
    }
}

impl From<UblkControlStartDevError> for UblkDeviceBuildError {
    fn from(e: UblkControlStartDevError) -> Self {
        Self::StartDev(e)
    }
}

impl From<io::Error> for UblkDeviceBuildError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Builder that orchestrates the full ublk device lifecycle through the
/// control runtime.
///
/// ```text
/// ADD_DEV -> open data queue -> SET_PARAMS -> FETCH_REQ* -> START_DEV
/// ```
///
/// On any failure the builder tears down partially-constructed state
/// (DEL_DEV + closed queue runtime) so the kernel is not left with an
/// unusable device.
pub struct UblkDeviceBuilder<'a> {
    runtime: &'a mut UblkControlRuntime,
    config: UblkDeviceConfig,
}

impl<'a> UblkDeviceBuilder<'a> {
    /// Create a new builder bound to the given control runtime.
    #[must_use]
    pub fn new(runtime: &'a mut UblkControlRuntime, config: UblkDeviceConfig) -> Self {
        Self { runtime, config }
    }

    /// Execute the full build sequence.
    ///
    /// # Errors
    ///
    /// Returns [`UblkDeviceBuildError`] on any step failure. Partially-built
    /// state is cleaned up before returning.
    pub fn build(mut self) -> Result<UblkDeviceBuildOutcome, UblkDeviceBuildError> {
        let dev_id = self.add_device()?;
        self.build_with_dev_id(dev_id)
    }

    /// Try to build, resuming from an already-added device identified by
    /// `dev_id`. Used when ADD_DEV was already issued by another path.
    ///
    /// # Errors
    ///
    /// Returns [`UblkDeviceBuildError`] on failure. The `dev_id` is cleaned
    /// up via DEL_DEV on error.
    pub fn build_from_existing_device(
        self,
        dev_id: u32,
    ) -> Result<UblkDeviceBuildOutcome, UblkDeviceBuildError> {
        if dev_id == TIDEFS_UBLK_ADD_DEV_AUTO_DEV_ID {
            return Err(UblkDeviceBuildError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dev_id must be a concrete kernel-assigned id, not AUTO",
            )));
        }
        self.build_with_dev_id(dev_id)
    }

    // ── private helpers ───────────────────────────────────────────────

    fn add_device(&mut self) -> Result<u32, UblkDeviceBuildError> {
        let input = UblkControlAddDevInput {
            nr_hw_queues: self.config.nr_hw_queues,
            queue_depth: self.config.queue_depth,
            max_io_buf_bytes: self.config.max_io_buf_bytes,
            flags: self.config.flags,
        };
        let device = self.runtime.add_device(input)?;
        Ok(device.dev_id)
    }

    fn build_with_dev_id(
        mut self,
        dev_id: u32,
    ) -> Result<UblkDeviceBuildOutcome, UblkDeviceBuildError> {
        // Open data queue and submit FETCH_REQ for all queues.
        let data_queue_result = self.open_data_queue(dev_id);

        let (data_queue_runtime, submitted_count) = match data_queue_result {
            Ok((rt, count)) => (rt, count),
            Err(e) => {
                self.cleanup(dev_id, e)?;
                unreachable!();
            }
        };

        // Issue SET_PARAMS.
        let set_params_result = self.set_params(dev_id);
        if let Err(e) = set_params_result {
            let cause = UblkDeviceBuildError::SetParams(e);
            return self.cleanup(dev_id, cause);
        }

        // Issue START_DEV.
        let start_dev_result = self.start_dev(dev_id, &data_queue_runtime, submitted_count);
        match start_dev_result {
            Ok(()) => {
                self.runtime.mark_attached(dev_id).map_err(|e| {
                    UblkDeviceBuildError::Io(io::Error::other(format!(
                        "mark_attached after successful START_DEV: {e:?}"
                    )))
                })?;
                let managed = self.runtime.lookup_device(dev_id).cloned().ok_or_else(|| {
                    UblkDeviceBuildError::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        "device disappeared from registry after mark_attached",
                    ))
                })?;
                Ok(UblkDeviceBuildOutcome {
                    managed_device: managed,
                    data_queue_runtime,
                    submitted_fetch_commands: submitted_count,
                })
            }
            Err(e) => {
                let cause = UblkDeviceBuildError::StartDev(e);
                self.cleanup(dev_id, cause)
            }
        }
    }

    fn open_data_queue(
        &self,
        dev_id: u32,
    ) -> Result<(UblkDataQueueRuntime, u32), UblkDeviceBuildError> {
        let queue_path = ublk_data_queue_device_path(dev_id);
        let open_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
            dev_id,
            0, // q_id
            self.config.nr_hw_queues,
            self.config.queue_depth,
        );
        let mut runtime = open_data_queue_runtime(&queue_path, open_input)?;

        // Submit FETCH_REQ for all queues at full depth.
        let submission_outcome = submit_runtime_all_queues_fetch_reqs_without_wait(&mut runtime)
            .map_err(UblkDeviceBuildError::FetchReqSubmit)?;

        Ok((runtime, submission_outcome.submitted_fetch_commands))
    }

    fn set_params(&self, dev_id: u32) -> Result<(), UblkControlSetParamsError> {
        let input = UblkControlSetParamsInput {
            dev_id,
            params: self.config.params,
        };
        issue_set_params(self.runtime.control_fd(), input)?;
        Ok(())
    }

    fn start_dev(
        &self,
        dev_id: u32,
        data_queue: &UblkDataQueueRuntime,
        submitted_fetch_commands: u32,
    ) -> Result<(), UblkControlStartDevError> {
        let readiness = UblkControlStartDevReadiness::from_queue_geometry_with_runtime(
            self.config.nr_hw_queues,
            self.config.queue_depth,
            submitted_fetch_commands,
            data_queue.runtime_live(),
        );
        let input = UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(
            dev_id,
            std::process::id() as i32,
        );
        issue_start_dev(self.runtime.control_fd(), input, readiness)?;
        Ok(())
    }

    /// Tear down a partially-built device: issue DEL_DEV and unregister.
    /// Always returns `Err` so callers can use the `?` operator.
    fn cleanup(
        &mut self,
        dev_id: u32,
        cause: UblkDeviceBuildError,
    ) -> Result<UblkDeviceBuildOutcome, UblkDeviceBuildError> {
        let del_result = self.runtime.remove_device(dev_id);
        match del_result {
            Ok(_) | Err(UblkControlRemoveDeviceError::DeviceAlreadyRemoved { .. }) => Err(cause),
            Err(UblkControlRemoveDeviceError::UblkDelDevError(del_err)) => {
                Err(UblkDeviceBuildError::Cleanup {
                    dev_id,
                    cause: Box::new(cause),
                    del_dev_error: del_err,
                })
            }
            Err(other) => Err(UblkDeviceBuildError::Io(io::Error::other(format!(
                "cleanup for dev_id={dev_id} failed with {other:?} after {cause}"
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── UblkDeviceConfig ──────────────────────────────────────────────

    #[test]
    fn device_config_default_has_sensible_values() {
        let config = UblkDeviceConfig::default();
        assert_eq!(config.nr_hw_queues, 1);
        assert_eq!(config.queue_depth, 64);
        assert!(config.max_io_buf_bytes > 0);
        assert!(config.flags.contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES));
    }

    #[test]
    fn device_config_conservative_tidefs_includes_uring_cmd_comp_in_task() {
        let config = UblkDeviceConfig::conservative_tidefs();
        assert!(config
            .flags
            .contains(UblkFeatureFlags::URING_CMD_COMP_IN_TASK));
        assert!(config.flags.contains(TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES));
    }

    // ── UblkDeviceBuilder construction ────────────────────────────────

    #[test]
    fn builder_new_stores_config() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null for test");
        let mut runtime = crate::UblkControlRuntime {
            control_file,
            devices: std::collections::HashMap::new(),
        };
        let config = UblkDeviceConfig::default();
        let builder = UblkDeviceBuilder::new(&mut runtime, config.clone());
        assert_eq!(builder.config, config);
    }

    #[test]
    fn builder_build_from_existing_device_rejects_auto_dev_id() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null for test");
        let mut runtime = crate::UblkControlRuntime {
            control_file,
            devices: std::collections::HashMap::new(),
        };
        let config = UblkDeviceConfig::default();
        let builder = UblkDeviceBuilder::new(&mut runtime, config);
        let result = builder.build_from_existing_device(u32::MAX);
        assert!(result.is_err());
    }

    // ── Error conversions ─────────────────────────────────────────────

    #[test]
    fn build_error_from_add_dev_error() {
        let err = UblkControlAddDevError::ZeroHardwareQueues;
        let build_err: UblkDeviceBuildError = err.into();
        assert!(matches!(build_err, UblkDeviceBuildError::AddDev(_)));
    }

    #[test]
    fn build_error_from_set_params_error() {
        let err = UblkControlSetParamsError::AutoDeviceId;
        let build_err: UblkDeviceBuildError = err.into();
        assert!(matches!(build_err, UblkDeviceBuildError::SetParams(_)));
    }

    #[test]
    fn build_error_from_start_dev_error() {
        let err = UblkControlStartDevError::AutoDeviceId;
        let build_err: UblkDeviceBuildError = err.into();
        assert!(matches!(build_err, UblkDeviceBuildError::StartDev(_)));
    }

    #[test]
    fn build_error_from_io_error() {
        let err = io::Error::other("test");
        let build_err: UblkDeviceBuildError = err.into();
        assert!(matches!(build_err, UblkDeviceBuildError::Io(_)));
    }

    #[test]
    fn build_error_display_includes_cause() {
        let err = UblkDeviceBuildError::AddDev(UblkControlAddDevError::ZeroHardwareQueues);
        let s = err.to_string();
        assert!(s.contains("add_dev"));
        assert!(s.contains("ZeroHardwareQueues"));
    }

    #[test]
    fn build_error_display_cleanup_includes_info() {
        let cause = UblkDeviceBuildError::StartDev(UblkControlStartDevError::AutoDeviceId);
        let del_err = crate::UblkControlDelDevError::AutoDeviceId;
        let err = UblkDeviceBuildError::Cleanup {
            dev_id: 42,
            cause: Box::new(cause),
            del_dev_error: del_err,
        };
        let s = err.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("cleanup"));
    }

    // ── UblkDeviceBuildOutcome ────────────────────────────────────────

    #[test]
    fn build_outcome_structural_properties() {
        let dev_info = tidefs_ublk_abi::UblkSrvCtrlDevInfo {
            dev_id: 1,
            nr_hw_queues: 2,
            queue_depth: 128,
            ..Default::default()
        };
        let managed = UblkManagedDevice {
            lifecycle: crate::queue_lifecycle::QueueLifecycle::attached(),
            dev_id: 1,
            state: crate::UblkDeviceLifecycleState::Attached,
            dev_info,
            block_path: crate::ublk_block_device_path(1),
            blake3_state_hash: None,
        };
        assert_eq!(managed.dev_id, 1);
        assert_eq!(managed.state, crate::UblkDeviceLifecycleState::Attached);
        assert_eq!(managed.block_path, std::path::PathBuf::from("/dev/ublkb1"));
    }
}
