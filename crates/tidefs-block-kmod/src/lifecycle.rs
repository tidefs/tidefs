// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified block device lifecycle state machine.
//!
//! This module implements the gendisk registration and device-add lifecycle
//! for the block-kmod crate. It models the full device state machine:
//!
//! ```text
//! Unloaded -> Allocated -> QueueReady -> Active -> Removing -> Removed
//!              ^            ^          |         |
//!              +------------+----------+---------+
//!                        (error -> Failed)
//! ```
//!
//! Every state transition produces a BLAKE3-256 domain-separated digest
//! (domain: `tidefs-block-kmod-lifecycle-v1`) for deterministic verification.
//!
//! # Lifecycle Phases
//!
//! 1. **Unloaded** - No device resources allocated.
//! 2. **Allocated** - Gendisk structure allocated; capacity, sector size,
//!    and device name validated. No queue yet.
//! 3. **QueueReady** - Request queue allocated and bound. Device is fully
//!    configured but not yet visible to userspace.
//! 4. **Active** - Device added to the block layer (add_disk). Accepting I/O.
//! 5. **Removing** - Device removal initiated (del_gendisk). I/O is quiesced.
//! 6. **Removed** - Device fully removed. Resources can be freed.
//! 7. **Failed** - Terminal error state reached from any non-terminal state.

use core::fmt;

// -- Domain separator -----------------------------------------------------

/// Domain separator for BLAKE3-256 lifecycle state hashing.
const DOMAIN: &str = "tidefs-block-kmod-lifecycle-v1";

// -- LifecycleState -------------------------------------------------------

/// States in the block device registration lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleState {
    /// No device resources allocated. Initial state.
    Unloaded = 0,
    /// Gendisk structure allocated with validated parameters.
    Allocated = 1,
    /// Request queue allocated and bound to the gendisk.
    QueueReady = 2,
    /// Device added to the block layer and accepting I/O.
    Active = 3,
    /// Device removal in progress; I/O is quiesced.
    Removing = 4,
    /// Device fully removed; resources can be freed.
    Removed = 5,
    /// Terminal error state.
    Failed = 6,
}

impl LifecycleState {
    /// Whether this state permits device parameter configuration.
    #[must_use]
    pub fn can_configure(&self) -> bool {
        matches!(self, Self::Unloaded | Self::Allocated)
    }

    /// Whether this state permits I/O submission.
    #[must_use]
    pub fn accepts_io(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether this is a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Removed | Self::Failed)
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unloaded => write!(f, "Unloaded"),
            Self::Allocated => write!(f, "Allocated"),
            Self::QueueReady => write!(f, "QueueReady"),
            Self::Active => write!(f, "Active"),
            Self::Removing => write!(f, "Removing"),
            Self::Removed => write!(f, "Removed"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// -- DeviceLifecycle ------------------------------------------------------

/// BLAKE3-verified block device lifecycle state machine.
///
/// Tracks the device through its full registration lifecycle and produces
/// deterministic BLAKE3-256 digests for every state transition.
///
/// # State Transition Rules
///
/// | From       | To          | Condition                               |
/// |------------|-------------|-----------------------------------------|
/// | Unloaded   | Allocated   | Valid device parameters provided        |
/// | Allocated  | QueueReady  | Request queue allocation succeeds       |
/// | QueueReady | Active      | add_disk() succeeds                     |
/// | Active     | Removing    | del_gendisk() initiated                 |
/// | Removing   | Removed     | Device fully removed                    |
/// | Any*       | Failed      | Allocation or registration failure      |
///
/// *Except terminal states (Removed, Failed).
pub struct DeviceLifecycle {
    /// Current state.
    state: LifecycleState,
    /// Device name (e.g., "tidefs0").
    name: &'static str,
    /// Device capacity in sectors.
    capacity_sectors: u64,
    /// Logical block size in bytes.
    sector_size: u32,
    /// Transition counter (monotonically increasing).
    transition_count: u64,
    /// BLAKE3-256 digest of the most recent transition.
    last_digest: [u8; 32],
}

impl DeviceLifecycle {
    /// Create a new lifecycle in the Unloaded state.
    #[must_use]
    pub fn new(name: &'static str, capacity_sectors: u64, sector_size: u32) -> Self {
        Self {
            state: LifecycleState::Unloaded,
            name,
            capacity_sectors,
            sector_size,
            transition_count: 0,
            last_digest: [0u8; 32],
        }
    }

    // -- Accessors --------------------------------------------------------

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// Device name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Device capacity in sectors.
    #[must_use]
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// Logical block size.
    #[must_use]
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Number of transitions executed.
    #[must_use]
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// BLAKE3-256 digest of the most recent transition.
    #[must_use]
    pub fn last_digest(&self) -> &[u8; 32] {
        &self.last_digest
    }

    // -- Transition: alloc_gendisk ----------------------------------------

    /// Transition from Unloaded to Allocated.
    ///
    /// Validates device parameters and records the transition.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError` if the current state is not Unloaded,
    /// the capacity is zero, the sector size is not 512 or 4096,
    /// or the device name is empty.
    pub fn alloc_gendisk(&mut self) -> Result<[u8; 32], LifecycleError> {
        self.require_state(LifecycleState::Unloaded, "alloc_gendisk")?;

        if self.capacity_sectors == 0 {
            return Err(LifecycleError::InvalidCapacity {
                capacity: self.capacity_sectors,
            });
        }
        if self.sector_size != 512 && self.sector_size != 4096 {
            return Err(LifecycleError::InvalidSectorSize {
                sector_size: self.sector_size,
            });
        }
        if self.name.is_empty() {
            return Err(LifecycleError::InvalidDeviceName);
        }

        let digest = self.record_transition(LifecycleState::Allocated);
        Ok(digest)
    }

    // -- Transition: alloc_queue ------------------------------------------

    /// Transition from Allocated to QueueReady.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError` if the current state is not Allocated.
    pub fn alloc_queue(&mut self) -> Result<[u8; 32], LifecycleError> {
        self.require_state(LifecycleState::Allocated, "alloc_queue")?;
        let digest = self.record_transition(LifecycleState::QueueReady);
        Ok(digest)
    }

    // -- Transition: add_disk ---------------------------------------------

    /// Transition from QueueReady to Active.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError` if the current state is not QueueReady.
    pub fn add_disk(&mut self) -> Result<[u8; 32], LifecycleError> {
        self.require_state(LifecycleState::QueueReady, "add_disk")?;
        let digest = self.record_transition(LifecycleState::Active);
        Ok(digest)
    }

    // -- Transition: del_gendisk ------------------------------------------

    /// Transition from Active to Removing.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError` if the current state is not Active.
    pub fn del_gendisk(&mut self) -> Result<[u8; 32], LifecycleError> {
        self.require_state(LifecycleState::Active, "del_gendisk")?;
        let digest = self.record_transition(LifecycleState::Removing);
        Ok(digest)
    }

    // -- Transition: complete_removal -------------------------------------

    /// Transition from Removing to Removed.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError` if the current state is not Removing.
    pub fn complete_removal(&mut self) -> Result<[u8; 32], LifecycleError> {
        self.require_state(LifecycleState::Removing, "complete_removal")?;
        let digest = self.record_transition(LifecycleState::Removed);
        Ok(digest)
    }

    // -- Transition: fail -------------------------------------------------

    /// Transition to the terminal Failed state from any non-terminal state.
    ///
    /// The failure reason is incorporated into the BLAKE3 transition digest.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError` if already in a terminal state.
    pub fn fail(&mut self, reason: &'static str) -> Result<[u8; 32], LifecycleError> {
        if self.state.is_terminal() {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: LifecycleState::Failed,
                reason: "already in terminal state",
            });
        }
        let digest = self.compute_digest(self.state, LifecycleState::Failed, Some(reason));
        self.commit_transition(LifecycleState::Failed, digest);
        Ok(digest)
    }

    // -- Internal helpers -------------------------------------------------

    fn require_state(
        &self,
        expected: LifecycleState,
        op: &'static str,
    ) -> Result<(), LifecycleError> {
        if self.state != expected {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: expected,
                reason: op,
            });
        }
        Ok(())
    }

    fn record_transition(&mut self, to: LifecycleState) -> [u8; 32] {
        let digest = self.compute_digest(self.state, to, None);
        self.commit_transition(to, digest);
        digest
    }

    /// Compute a BLAKE3-256 domain-separated digest for a state transition.
    fn compute_digest(
        &self,
        from: LifecycleState,
        to: LifecycleState,
        extra_context: Option<&str>,
    ) -> [u8; 32] {
        #[cfg(CONFIG_RUST)]
        use crate::tidefs_kmod_bridge::kernel_types::blake3::Hasher;
        #[cfg(not(CONFIG_RUST))]
        use blake3::Hasher;

        let mut hasher = Hasher::new_derive_key(DOMAIN);
        hasher.update(&(from as u8).to_le_bytes());
        hasher.update(&(to as u8).to_le_bytes());
        hasher.update(self.name.as_bytes());
        hasher.update(&self.capacity_sectors.to_le_bytes());
        hasher.update(&self.sector_size.to_le_bytes());
        hasher.update(&self.transition_count.to_le_bytes());
        if let Some(ctx) = extra_context {
            hasher.update(ctx.as_bytes());
        }
        hasher.finalize().into()
    }

    fn commit_transition(&mut self, to: LifecycleState, digest: [u8; 32]) {
        self.state = to;
        self.transition_count += 1;
        self.last_digest = digest;
    }
}

impl fmt::Debug for DeviceLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLifecycle")
            .field("state", &self.state)
            .field("name", &self.name)
            .field("capacity_sectors", &self.capacity_sectors)
            .field("sector_size", &self.sector_size)
            .field("transition_count", &self.transition_count)
            .field("last_digest", &hex_digest(&self.last_digest))
            .finish()
    }
}

// -- LifecycleError -------------------------------------------------------

/// Errors that can occur during device lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    /// Attempted an invalid state transition.
    InvalidTransition {
        from: LifecycleState,
        to: LifecycleState,
        reason: &'static str,
    },
    /// Device capacity was zero.
    InvalidCapacity { capacity: u64 },
    /// Sector size was not 512 or 4096.
    InvalidSectorSize { sector_size: u32 },
    /// Device name was empty.
    InvalidDeviceName,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to, reason } => {
                write!(f, "invalid lifecycle transition {from} -> {to}: {reason}")
            }
            Self::InvalidCapacity { capacity } => {
                write!(f, "invalid capacity: {capacity} sectors (must be > 0)")
            }
            Self::InvalidSectorSize { sector_size } => {
                write!(
                    f,
                    "invalid sector size: {sector_size} (must be 512 or 4096)"
                )
            }
            Self::InvalidDeviceName => {
                write!(f, "invalid device name: must be non-empty")
            }
        }
    }
}

// -- Helpers --------------------------------------------------------------

/// Format a 32-byte digest as a hex string (first 16 bytes for debug).
#[cfg(not(CONFIG_RUST))]
fn hex_digest(digest: &[u8; 32]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(32);
    for byte in &digest[..16] {
        write!(&mut s, "{byte:02x}").ok();
    }
    s
}

#[cfg(CONFIG_RUST)]
fn hex_digest(digest: &[u8; 32]) -> crate::tidefs_kmod_bridge::kernel_types::KmodString {
    use core::fmt::Write;
    let mut s = crate::tidefs_kmod_bridge::kernel_types::KmodString::new();
    for byte in &digest[..16] {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

// -- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper: compute digest for verification -------------------------

    fn transition_digest(
        name: &str,
        capacity: u64,
        sector_size: u32,
        from: LifecycleState,
        to: LifecycleState,
        count: u64,
    ) -> [u8; 32] {
        #[cfg(CONFIG_RUST)]
        use crate::tidefs_kmod_bridge::kernel_types::blake3::Hasher;
        #[cfg(not(CONFIG_RUST))]
        use blake3::Hasher;
        let mut hasher = Hasher::new_derive_key(DOMAIN);
        hasher.update(&(from as u8).to_le_bytes());
        hasher.update(&(to as u8).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&capacity.to_le_bytes());
        hasher.update(&sector_size.to_le_bytes());
        hasher.update(&count.to_le_bytes());
        hasher.finalize().into()
    }

    fn fail_digest(
        name: &str,
        capacity: u64,
        sector_size: u32,
        from: LifecycleState,
        count: u64,
        reason: &str,
    ) -> [u8; 32] {
        #[cfg(CONFIG_RUST)]
        use crate::tidefs_kmod_bridge::kernel_types::blake3::Hasher;
        #[cfg(not(CONFIG_RUST))]
        use blake3::Hasher;
        let mut hasher = Hasher::new_derive_key(DOMAIN);
        hasher.update(&(from as u8).to_le_bytes());
        hasher.update(&(LifecycleState::Failed as u8).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&capacity.to_le_bytes());
        hasher.update(&sector_size.to_le_bytes());
        hasher.update(&count.to_le_bytes());
        hasher.update(reason.as_bytes());
        hasher.finalize().into()
    }

    // -- Happy-path lifecycle tests --------------------------------------

    #[test]
    fn full_lifecycle_happy_path() {
        let mut lc = DeviceLifecycle::new("tidefs0", 1024, 512);
        assert_eq!(lc.state(), LifecycleState::Unloaded);
        assert_eq!(lc.transition_count(), 0);

        // Unloaded -> Allocated
        let d1 = lc.alloc_gendisk().unwrap();
        assert_eq!(lc.state(), LifecycleState::Allocated);
        assert_eq!(lc.transition_count(), 1);
        let expected = transition_digest(
            "tidefs0",
            1024,
            512,
            LifecycleState::Unloaded,
            LifecycleState::Allocated,
            0,
        );
        assert_eq!(d1, expected);

        // Allocated -> QueueReady
        let d2 = lc.alloc_queue().unwrap();
        assert_eq!(lc.state(), LifecycleState::QueueReady);
        assert_eq!(lc.transition_count(), 2);
        let expected2 = transition_digest(
            "tidefs0",
            1024,
            512,
            LifecycleState::Allocated,
            LifecycleState::QueueReady,
            1,
        );
        assert_eq!(d2, expected2);

        // QueueReady -> Active
        let d3 = lc.add_disk().unwrap();
        assert_eq!(lc.state(), LifecycleState::Active);
        assert_eq!(lc.transition_count(), 3);
        let expected3 = transition_digest(
            "tidefs0",
            1024,
            512,
            LifecycleState::QueueReady,
            LifecycleState::Active,
            2,
        );
        assert_eq!(d3, expected3);
        assert!(lc.state().accepts_io());

        // Active -> Removing
        lc.del_gendisk().unwrap();
        assert_eq!(lc.state(), LifecycleState::Removing);
        assert_eq!(lc.transition_count(), 4);

        // Removing -> Removed
        lc.complete_removal().unwrap();
        assert_eq!(lc.state(), LifecycleState::Removed);
        assert_eq!(lc.transition_count(), 5);
        assert!(lc.state().is_terminal());
    }

    #[test]
    fn lifecycle_4k_sector_size() {
        let mut lc = DeviceLifecycle::new("tidefs4k", 256, 4096);
        assert!(lc.alloc_gendisk().is_ok());
        assert_eq!(lc.sector_size(), 4096);
        assert!(lc.alloc_queue().is_ok());
        assert!(lc.add_disk().is_ok());
        assert!(lc.state().accepts_io());
    }

    #[test]
    fn lifecycle_transition_count_monotonic() {
        let mut lc = DeviceLifecycle::new("mono", 100, 512);
        assert_eq!(lc.transition_count(), 0);
        lc.alloc_gendisk().unwrap();
        assert_eq!(lc.transition_count(), 1);
        lc.alloc_queue().unwrap();
        assert_eq!(lc.transition_count(), 2);
        lc.add_disk().unwrap();
        assert_eq!(lc.transition_count(), 3);
        lc.del_gendisk().unwrap();
        assert_eq!(lc.transition_count(), 4);
        lc.complete_removal().unwrap();
        assert_eq!(lc.transition_count(), 5);
    }

    // -- BLAKE3 digest determinism tests --------------------------------

    #[test]
    fn blake3_digest_deterministic_same_params() {
        let mut lc1 = DeviceLifecycle::new("test", 2048, 512);
        let d1 = lc1.alloc_gendisk().unwrap();

        let mut lc2 = DeviceLifecycle::new("test", 2048, 512);
        let d2 = lc2.alloc_gendisk().unwrap();

        assert_eq!(d1, d2, "same parameters should produce identical digests");
    }

    #[test]
    fn blake3_digest_different_name() {
        let mut lc1 = DeviceLifecycle::new("dev-a", 1024, 512);
        let d1 = lc1.alloc_gendisk().unwrap();

        let mut lc2 = DeviceLifecycle::new("dev-b", 1024, 512);
        let d2 = lc2.alloc_gendisk().unwrap();

        assert_ne!(d1, d2, "different names should produce different digests");
    }

    #[test]
    fn blake3_digest_different_capacity() {
        let mut lc1 = DeviceLifecycle::new("test", 1024, 512);
        let d1 = lc1.alloc_gendisk().unwrap();

        let mut lc2 = DeviceLifecycle::new("test", 2048, 512);
        let d2 = lc2.alloc_gendisk().unwrap();

        assert_ne!(
            d1, d2,
            "different capacities should produce different digests"
        );
    }

    #[test]
    fn blake3_digest_different_sector_size() {
        let mut lc1 = DeviceLifecycle::new("test", 1024, 512);
        lc1.alloc_gendisk().unwrap();
        let d1 = lc1.alloc_queue().unwrap();

        let mut lc2 = DeviceLifecycle::new("test", 1024, 4096);
        lc2.alloc_gendisk().unwrap();
        let d2 = lc2.alloc_queue().unwrap();

        assert_ne!(
            d1, d2,
            "different sector sizes should produce different digests"
        );
    }

    #[test]
    fn blake3_digest_changes_per_transition() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);

        let d1 = lc.alloc_gendisk().unwrap();
        let d2 = lc.alloc_queue().unwrap();
        let d3 = lc.add_disk().unwrap();
        let d4 = lc.del_gendisk().unwrap();
        let d5 = lc.complete_removal().unwrap();

        // All 5 digests should be distinct
        let digests = [d1, d2, d3, d4, d5];
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(
                    digests[i], digests[j],
                    "digests at positions {i} and {j} should differ"
                );
            }
        }
    }

    #[test]
    fn blake3_fail_digest_differs_from_normal_transition() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();

        let fail_d = lc.fail("allocation failure").unwrap();

        // Compare with what Active transition would have been
        let mut lc2 = DeviceLifecycle::new("test", 1024, 512);
        lc2.alloc_gendisk().unwrap();
        let normal_d = lc2.alloc_queue().unwrap(); // Allocated -> QueueReady, not -> Failed

        assert_ne!(
            fail_d, normal_d,
            "fail digest should differ from normal transition digest"
        );
    }

    // -- Error path tests -----------------------------------------------

    #[test]
    fn alloc_gendisk_zero_capacity_rejected() {
        let mut lc = DeviceLifecycle::new("test", 0, 512);
        let result = lc.alloc_gendisk();
        assert!(result.is_err());
        match result {
            Err(LifecycleError::InvalidCapacity { capacity }) => {
                assert_eq!(capacity, 0);
            }
            other => panic!("expected InvalidCapacity, got {other:?}"),
        }
        assert_eq!(lc.state(), LifecycleState::Unloaded);
    }

    #[test]
    fn alloc_gendisk_invalid_sector_size_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 1024);
        let result = lc.alloc_gendisk();
        assert!(result.is_err());
        match result {
            Err(LifecycleError::InvalidSectorSize { sector_size }) => {
                assert_eq!(sector_size, 1024);
            }
            other => panic!("expected InvalidSectorSize, got {other:?}"),
        }
        assert_eq!(lc.state(), LifecycleState::Unloaded);
    }

    #[test]
    fn alloc_gendisk_invalid_sector_size_8192_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 8192);
        let result = lc.alloc_gendisk();
        assert!(result.is_err());
    }

    #[test]
    fn alloc_gendisk_empty_name_rejected() {
        let mut lc = DeviceLifecycle::new("", 1024, 512);
        let result = lc.alloc_gendisk();
        assert!(result.is_err());
        match result {
            Err(LifecycleError::InvalidDeviceName) => {}
            other => panic!("expected InvalidDeviceName, got {other:?}"),
        }
    }

    #[test]
    fn alloc_gendisk_wrong_state_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        // Cannot call alloc_gendisk again from Allocated
        let result = lc.alloc_gendisk();
        assert!(result.is_err());
    }

    #[test]
    fn double_add_disk_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        lc.alloc_queue().unwrap();
        lc.add_disk().unwrap();
        // Cannot call add_disk again from Active
        let result = lc.add_disk();
        assert!(result.is_err());
    }

    #[test]
    fn del_gendisk_without_add_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        lc.alloc_queue().unwrap();
        // State is QueueReady, not Active
        let result = lc.del_gendisk();
        assert!(result.is_err());
    }

    #[test]
    fn alloc_queue_before_gendisk_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        // Cannot alloc_queue from Unloaded
        let result = lc.alloc_queue();
        assert!(result.is_err());
    }

    #[test]
    fn add_disk_before_queue_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        // Cannot add_disk from Allocated
        let result = lc.add_disk();
        assert!(result.is_err());
    }

    #[test]
    fn complete_removal_before_del_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        lc.alloc_queue().unwrap();
        lc.add_disk().unwrap();
        // Cannot complete_removal from Active
        let result = lc.complete_removal();
        assert!(result.is_err());
    }

    #[test]
    fn fail_from_terminal_rejected() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        lc.alloc_queue().unwrap();
        lc.add_disk().unwrap();
        lc.del_gendisk().unwrap();
        lc.complete_removal().unwrap();
        // Already Removed, cannot fail
        let result = lc.fail("late error");
        assert!(result.is_err());
    }

    #[test]
    fn fail_from_allocated_transitions_to_failed() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        assert_eq!(lc.state(), LifecycleState::Allocated);

        let d = lc.fail("queue allocation failed").unwrap();
        assert_eq!(lc.state(), LifecycleState::Failed);
        assert!(lc.state().is_terminal());

        // Verify the fail digest matches expectation
        let expected = fail_digest(
            "test",
            1024,
            512,
            LifecycleState::Allocated,
            1,
            "queue allocation failed",
        );
        assert_eq!(d, expected);

        // Cannot transition further
        assert!(lc.alloc_queue().is_err());
    }

    #[test]
    fn fail_from_unloaded() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        let d = lc.fail("gendisk allocation failed").unwrap();
        assert_eq!(lc.state(), LifecycleState::Failed);
        assert_eq!(lc.transition_count(), 1);

        let expected = fail_digest(
            "test",
            1024,
            512,
            LifecycleState::Unloaded,
            0,
            "gendisk allocation failed",
        );
        assert_eq!(d, expected);
    }

    // -- State query tests ----------------------------------------------

    #[test]
    fn can_configure_in_unloaded_and_allocated() {
        let lc = DeviceLifecycle::new("test", 1024, 512);
        assert!(lc.state().can_configure());

        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        assert!(lc.state().can_configure());
    }

    #[test]
    fn cannot_configure_in_later_states() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        lc.alloc_gendisk().unwrap();
        lc.alloc_queue().unwrap();
        assert!(!lc.state().can_configure());
    }

    #[test]
    fn accepts_io_only_in_active() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        assert!(!lc.state().accepts_io());
        lc.alloc_gendisk().unwrap();
        assert!(!lc.state().accepts_io());
        lc.alloc_queue().unwrap();
        assert!(!lc.state().accepts_io());
        lc.add_disk().unwrap();
        assert!(lc.state().accepts_io());
        lc.del_gendisk().unwrap();
        assert!(!lc.state().accepts_io());
    }

    #[test]
    fn is_terminal_removed_and_failed() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        assert!(!lc.state().is_terminal());

        lc.alloc_gendisk().unwrap();
        lc.alloc_queue().unwrap();
        lc.add_disk().unwrap();
        lc.del_gendisk().unwrap();
        lc.complete_removal().unwrap();
        assert!(lc.state().is_terminal());

        let mut lc2 = DeviceLifecycle::new("test", 1024, 512);
        lc2.fail("error").unwrap();
        assert!(lc2.state().is_terminal());
    }

    // -- Debug output tests ---------------------------------------------

    #[test]
    fn lifecycle_debug_output() {
        let mut lc = DeviceLifecycle::new("dbg0", 1024, 512);
        lc.alloc_gendisk().unwrap();
        let dbg = alloc::format!("{lc:?}");
        assert!(dbg.contains("DeviceLifecycle"));
        assert!(dbg.contains("Allocated"));
        assert!(dbg.contains("dbg0"));
    }

    #[test]
    fn lifecycle_error_display() {
        let err = LifecycleError::InvalidTransition {
            from: LifecycleState::Unloaded,
            to: LifecycleState::Active,
            reason: "skip ahead",
        };
        let msg = alloc::format!("{err}");
        assert!(msg.contains("Unloaded"));
        assert!(msg.contains("Active"));
        assert!(msg.contains("skip ahead"));

        let err2 = LifecycleError::InvalidCapacity { capacity: 0 };
        assert!(alloc::format!("{err2}").contains("0"));

        let err3 = LifecycleError::InvalidSectorSize { sector_size: 1024 };
        assert!(alloc::format!("{err3}").contains("1024"));

        let err4 = LifecycleError::InvalidDeviceName;
        assert!(alloc::format!("{err4}").contains("non-empty"));
    }

    // -- Accessor tests -------------------------------------------------

    #[test]
    fn accessors_return_configured_values() {
        let lc = DeviceLifecycle::new("access-test", 4096, 4096);
        assert_eq!(lc.name(), "access-test");
        assert_eq!(lc.capacity_sectors(), 4096);
        assert_eq!(lc.sector_size(), 4096);
        assert_eq!(lc.transition_count(), 0);
        assert_eq!(lc.last_digest(), &[0u8; 32]);
    }

    #[test]
    fn last_digest_updates_after_transition() {
        let mut lc = DeviceLifecycle::new("test", 1024, 512);
        assert_eq!(lc.last_digest(), &[0u8; 32]);

        let d1 = lc.alloc_gendisk().unwrap();
        assert_eq!(lc.last_digest(), &d1);

        let d2 = lc.alloc_queue().unwrap();
        assert_eq!(lc.last_digest(), &d2);
        assert_ne!(d1, d2);
    }
}
