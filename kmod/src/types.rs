// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Opaque kernel-object facades for the bridge stratum (s2 / c6).
//!
//! These are type-level placeholders that downstream leaf modules (s3) will
//! bind to actual Linux kernel objects (super_block, dentry, inode, file,
//! folio, bio, request_queue, etc.) via Rust-for-Linux wrappers. The bridge
//! stratum owns the facade definitions; the kernel build environment (K7-02)
//! supplies the concrete types.
//!
//! Invariant: these facades are newtype wrappers around `*const core::ffi::c_void`
//! or equivalent opaque handles. They intentionally expose no methods that
//! assume Linux kernel ABI — that binding happens in the kernel build
//! environment through trait implementations on the concrete Linux types.
//!
//! # Safety: opaque-pointer constructors
//!
//! Every `from_ptr` constructor is `unsafe fn` because the caller must
//! guarantee the raw pointer is a valid, live kernel object of the matching
//! type.  These facades do not dereference the pointer, but they carry the
//! pointer into contexts where later dereference is expected.  A null,
//! dangling, or type-mismatched pointer stored here is a latent UB risk.
//!
//! # Safety: lock-class and workqueue-family discriminants
//!
//! `KernelLockClass` discriminants encode the canonical P7-03 lockdep
//! partial order.  `WorkqueueFamily` names match the P7-03 canonical
//! workqueue families.  Leaf modules must not invent new lock classes or
//! workqueue families without updating P7-03 and this bridge definition.

use core::fmt;

// ---------------------------------------------------------------------------
// VFS / superblock facades
// ---------------------------------------------------------------------------

/// Opaque handle for a mounted filesystem superblock.
///
/// Maps to `struct super_block *` in the Linux kernel build environment.
#[derive(Clone, Copy)]
pub struct OpaqueSuperBlock {
    _ptr: *const core::ffi::c_void,
}

impl OpaqueSuperBlock {
    /// Construct an opaque superblock handle from a raw pointer.
    ///
    /// # Safety
    /// The caller must ensure `ptr` is a valid, live `struct super_block *`
    /// from the Linux kernel.  Null pointers are permitted only when the
    /// handle is a sentinel and will never be dereferenced.
    pub unsafe fn from_ptr(ptr: *const core::ffi::c_void) -> Self {
        Self { _ptr: ptr }
    }

    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self._ptr
    }
}

impl fmt::Debug for OpaqueSuperBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueSuperBlock")
            .field("ptr", &self._ptr)
            .finish()
    }
}

/// Opaque handle for a directory entry (dentry).
///
/// Maps to `struct dentry *` in the Linux kernel build environment.
#[derive(Clone, Copy)]
pub struct OpaqueDentry {
    _ptr: *const core::ffi::c_void,
}

impl OpaqueDentry {
    /// # Safety
    /// The caller must ensure `ptr` is a valid, live `struct dentry *`
    /// from the Linux kernel.  Null pointers are permitted only when the
    /// handle is a sentinel and will never be dereferenced.
    pub unsafe fn from_ptr(ptr: *const core::ffi::c_void) -> Self {
        Self { _ptr: ptr }
    }

    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self._ptr
    }
}

impl fmt::Debug for OpaqueDentry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueDentry")
            .field("ptr", &self._ptr)
            .finish()
    }
}

/// Opaque handle for a VFS inode.
///
/// Maps to `struct inode *` in the Linux kernel build environment.
#[derive(Clone, Copy)]
pub struct OpaqueInode {
    _ptr: *const core::ffi::c_void,
}

impl OpaqueInode {
    /// # Safety
    /// The caller must ensure `ptr` is a valid, live `struct inode *`
    /// from the Linux kernel.  Null pointers are permitted only when the
    /// handle is a sentinel and will never be dereferenced.
    pub unsafe fn from_ptr(ptr: *const core::ffi::c_void) -> Self {
        Self { _ptr: ptr }
    }

    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self._ptr
    }
}

impl fmt::Debug for OpaqueInode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueInode")
            .field("ptr", &self._ptr)
            .finish()
    }
}

/// Opaque handle for an open file description.
///
/// Maps to `struct file *` in the Linux kernel build environment.
#[derive(Clone, Copy)]
pub struct OpaqueFile {
    _ptr: *const core::ffi::c_void,
}

impl OpaqueFile {
    /// # Safety
    /// The caller must ensure `ptr` is a valid, live `struct file *`
    /// from the Linux kernel.  Null pointers are permitted only when the
    /// handle is a sentinel and will never be dereferenced.
    pub unsafe fn from_ptr(ptr: *const core::ffi::c_void) -> Self {
        Self { _ptr: ptr }
    }

    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self._ptr
    }
}

impl fmt::Debug for OpaqueFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueFile")
            .field("ptr", &self._ptr)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Page-cache / folio facades
// ---------------------------------------------------------------------------

/// Opaque handle for a memory folio (page-cache leaf).
///
/// Maps to `struct folio *` in the Linux kernel build environment.
#[derive(Clone, Copy)]
pub struct OpaqueFolio {
    _ptr: *const core::ffi::c_void,
}

impl OpaqueFolio {
    /// # Safety
    /// The caller must ensure `ptr` is a valid, live `struct folio *`
    /// from the Linux kernel.  Null pointers are permitted only when the
    /// handle is a sentinel and will never be dereferenced.
    pub unsafe fn from_ptr(ptr: *const core::ffi::c_void) -> Self {
        Self { _ptr: ptr }
    }

    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self._ptr
    }
}

impl fmt::Debug for OpaqueFolio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueFolio")
            .field("ptr", &self._ptr)
            .finish()
    }
}

/// A byte range within a folio that a kernel leaf may read or populate.
#[derive(Debug, Clone, Copy)]
pub struct FolioWindow {
    /// Offset into the file (bytes).
    pub file_offset: u64,
    /// Length of this window (bytes).
    pub length: u32,
    /// The folio this window references.
    pub folio: OpaqueFolio,
    /// Byte offset within the folio.
    pub folio_offset: u32,
}

// ---------------------------------------------------------------------------
// Block / bio facades
// ---------------------------------------------------------------------------

/// Opaque handle for a block I/O request.
///
/// Maps to `struct bio *` or `struct request *` in the Linux kernel build
/// environment, depending on the leaf module (block_volume_adapter uses bio).
#[derive(Clone, Copy)]
pub struct OpaqueBio {
    _ptr: *const core::ffi::c_void,
}

impl OpaqueBio {
    /// # Safety
    /// The caller must ensure `ptr` is a valid, live `struct bio *` or
    /// `struct request *` from the Linux kernel.  Null pointers are
    /// permitted only when the handle is a sentinel and will never be
    /// dereferenced.
    pub unsafe fn from_ptr(ptr: *const core::ffi::c_void) -> Self {
        Self { _ptr: ptr }
    }

    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self._ptr
    }
}

impl fmt::Debug for OpaqueBio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueBio")
            .field("ptr", &self._ptr)
            .finish()
    }
}

/// Opaque handle for a block request queue.
///
/// Maps to `struct request_queue *` in the Linux kernel build environment.
#[derive(Clone, Copy)]
pub struct OpaqueRequestQueue {
    _ptr: *const core::ffi::c_void,
}

impl OpaqueRequestQueue {
    /// # Safety
    /// The caller must ensure `ptr` is a valid, live
    /// `struct request_queue *` from the Linux kernel.  Null pointers are
    /// permitted only when the handle is a sentinel and will never be
    /// dereferenced.
    pub unsafe fn from_ptr(ptr: *const core::ffi::c_void) -> Self {
        Self { _ptr: ptr }
    }

    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self._ptr
    }
}

impl fmt::Debug for OpaqueRequestQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueRequestQueue")
            .field("ptr", &self._ptr)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Lock / synchronisation facades
// ---------------------------------------------------------------------------

/// Lock class identifier encoding the canonical P7-03 lockdep partial order.
///
/// Discriminants form the global acquisition order: lower values are
/// acquired first (outer locks), higher values are acquired later (inner
/// locks).  This ordering is enforced by `derive(Ord)` and must match the
/// canonical P7-03 §2.1 hierarchy:
///
///   `PolicyRwsem` → `DomainMutex` → `RangeRwsem` → `PinMutex`
///   → `ObjectSpin` → `SeqCountEpoch` / `RcuAnchor`
///
/// `EmergencyRaw` is IRQ-only and may never nest with sleepable locks.
/// `WorkGate` coordinates drains outside data fast paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KernelLockClass {
    /// `rw_semaphore` — policy/control-plane mirror visibility in-kernel.
    PolicyRwsem = 0,
    /// `mutex` — authority-domain state machine, publication/cutover staging.
    DomainMutex = 1,
    /// `rw_semaphore` — object/range mutation exclusion for heavy paths.
    RangeRwsem = 2,
    /// `mutex` — pin-broker bookkeeping, loan drain, DMA arena transitions.
    PinMutex = 3,
    /// `spinlock_t` — tiny per-object state transitions, queue/shard cursors.
    ObjectSpin = 4,
    /// `seqcount_t` — epoch/fence generation stamps for optimistic readers.
    SeqCountEpoch = 5,
    /// RCU read section — read-mostly mirror root visibility.
    RcuAnchor = 6,
    /// Completion / wait-queue + gate mutex.
    WorkGate = 7,
    /// `raw_spinlock_t` — hard-IRQ / completion-edge emergency accounting.
    EmergencyRaw = 8,
}

impl KernelLockClass {
    /// Whether code holding this lock may sleep.
    pub const fn is_sleepable(self) -> bool {
        // Per P7-03 §2: PolicyRwsem, DomainMutex, RangeRwsem, PinMutex,
        // and WorkGate are sleepable; SeqCountEpoch, RcuAnchor, ObjectSpin,
        // and EmergencyRaw are not.
        !matches!(
            self,
            Self::SeqCountEpoch | Self::RcuAnchor | Self::ObjectSpin | Self::EmergencyRaw
        )
    }
}

// ---------------------------------------------------------------------------
// Pin / drain facades
// ---------------------------------------------------------------------------

/// A pin epoch token, representing an obligation to release pinned resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PinEpoch {
    pub epoch_id: u64,
    pub pin_class: PinClass,
}

/// Canonical pin classes from P4-04 and P7-03.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinClass {
    /// Folio refs for page-cache residency.
    FolioRef = 0,
    /// Page pins for DMA / direct-map loans.
    PagePin = 1,
    /// Bio vector lifetimes.
    BioVec = 2,
    /// DMA mapping lifetimes.
    DmaMapping = 3,
    /// Registered buffer leases.
    RegisteredBuffer = 4,
    /// Kernel direct-map loans.
    DirectMapLoan = 5,
}

// ---------------------------------------------------------------------------
// Workqueue facades
// ---------------------------------------------------------------------------

/// Workqueue family identifier from P7-03 §5 (canonical workqueue families).
///
/// Names and discriminants match the 8 canonical families defined in
/// `docs/KERNEL_LOCKING_RCU_PINNING_WORKQUEUE_MODEL_P7-03.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkqueueFamily {
    /// Authority/cutover/fence staging hooks — ordered, low parallelism.
    ControlSerial = 0,
    /// Heavyweight namespace/object mutation continuation — ordered by key.
    NamespaceMut = 1,
    /// Page dirty-epoch sealing and writeback completion — sharded.
    PageWriteback = 2,
    /// Block submit/completion continuation — sharded / CPU-local.
    BlockSubmitComplete = 3,
    /// Pin/loan drain and invalidate completion — bounded parallel.
    PinDrain = 4,
    /// Reclaim/relocation/repair assist workers — bounded parallel.
    ReclaimRelocate = 5,
    /// Telemetry/export/trace compaction — low priority, yields first.
    ObserveExport = 6,
    /// Reserve-protect/cutover-critical fallbacks — reserved, throttled.
    EmergencyRecovery = 7,
}

// ---------------------------------------------------------------------------
// Filesystem registration facade
// ---------------------------------------------------------------------------

/// Opaque handle for a registered Linux filesystem type.
///
/// Created by [`FilesystemRegistration::register_filesystem`] and consumed
/// by its `unregister_filesystem` counterpart. In the kernel build
/// environment, this wraps a `struct file_system_type *` registration
/// handle; in the userspace shim, it is a stack-allocated token that
/// tracks registration state for the module lifecycle.
///
/// The handle is intentionally opaque: downstream code must not inspect
/// or fabricate the handle fields. Only the bridge is authorised to
/// create and consume these handles.
#[derive(Clone, Copy, Debug)]
pub struct FilesystemRegHandle {
    /// Non-zero when a filesystem registration is active.
    ///
    /// In the kernel build environment, this is the raw `struct
    /// file_system_type *` pointer cast to `u64`. In the userspace
    /// shim, this is a simple registered/not-registered flag.
    _raw: u64,
}

impl FilesystemRegHandle {
    /// Construct a new active registration handle.
    ///
    /// # Safety
    /// Only the bridge may create active handles. In the kernel build
    /// environment, `raw` must be a valid, live `struct file_system_type *`
    /// pointer cast to `u64`.  An invalid pointer stored here will be
    /// dereferenced during unregistration, resulting in undefined behaviour.
    pub unsafe fn new_active(raw: u64) -> Self {
        Self { _raw: raw }
    }

    /// Safe constructor: create a sentinel registration handle for the
    /// userspace model path.  Must never be used in the kernel build
    /// environment where the handle wraps a real kernel pointer.
    pub fn new_sentinel() -> Self {
        Self { _raw: 1 }
    }

    /// Sentinel for "no registration held."
    pub const NONE: Self = Self { _raw: 0 };

    /// Whether this handle represents an active registration.
    pub fn is_active(&self) -> bool {
        self._raw != 0
    }
}
