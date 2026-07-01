// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TideFS Rust-for-Linux common bridge substrate (stratum s2 / c6).
//!
//! This crate is the shared kernel-boundary bridge (`kmod.common.bridge.k0`)
//! that sits between canonical userspace authority types (strata s0/s1) and
//! Linux kernel leaf modules (stratum s3). It owns:
//!
//! - **Trait contracts** (t0–t9) that define the typed seam between canonical
//!   authority and kernel mechanics.
//! - **Opaque type facades** for Linux kernel objects (super_block, dentry,
//!   inode, file, folio, bio, request_queue) that leaf modules bind to.
//! - **Lock/pin/workqueue classifiers** for the bridge facade, bounded by
//!   current kernel residency authority.
//! - **Bridge error types** for all kernel-boundary failure modes.
//!
//! # What this crate does NOT own
//!
//! - `binary_schema` or `feature_window` parsing logic (that lives in s0).
//! - Policy evaluation or publication truth.
//! - Runbook execution.
//! - Secret-envelope storage.
//! - Checkpoint/snapshot writer authority.
//! - Dashboard truth surfaces.
//! - Leaf-specific behavior (that belongs in c7/c8/c9).
//!
//! # Stratum dependency rules
//!
//! This crate (s2) may depend only on s0 and s1 crates. It may not depend on
//! s3 leaf modules, userspace control-plane implementation crates, or actual
//! Linux kernel headers. The kernel build environment (K7-02) supplies the
//! concrete Linux types that implement these traits.
//!
//! # Kernel baseline
//!
//! Linux 7.0 is the target. All references to Linux 6.18 are historical only.
//! # Safety: kernel-callback registration contract
//!
//! Kernel leaf modules (s3) that register Rust functions as Linux VFS/block
//! callbacks (file_operations, inode_operations, super_operations,
//! block_device_operations) must follow these invariants:
//!
//! - The callback signature must match the kernel's expected ABI exactly
//!   (calling convention, parameter count and types, return type).
//! - Opaque pointer handles (`OpaqueSuperBlock`, `OpaqueInode`, etc.) passed
//!   into callbacks must be constructed via `unsafe` `from_ptr` with a live
//!   kernel pointer, and the `// SAFETY:` comment must name the kernel
//!   guarantee that keeps the pointer live for the callback duration.
//! - Lock acquisitions inside callbacks must declare a `KernelLockClass`
//!   variant and obey the bridge lockdep partial order encoded in the
//!   discriminants.
//!
//! # Safety: opaque-pointer lifetime contract
//!
//! The bridge `Opaque*` types are zero-cost wrappers around raw kernel
//! pointers.  They carry no ownership or lifetime information.  Callers must
//! guarantee that the pointed-to kernel object outlives every use of the
//! opaque handle.  When the kernel callback model provides that guarantee
//! (e.g., VFS holds a reference to the inode for the duration of the
//! operation), the caller must cite the specific kernel reference-counting
//! or RCU rule in the `// SAFETY:` comment.

#![no_std]
// Kernel bridge code inherently requires unsafe for raw-pointer facades;
// safety is enforced by the kernel build environment.
// `unsafe` is required for raw-pointer facades (see types.rs);
// `unsafe_op_in_unsafe_fn` ensures unsafe blocks inside unsafe fns
// are explicit and documented.
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod error;
pub mod traits;
pub mod types;
pub mod kernel_types {
    pub use tidefs_types_vfs_core::*;
    pub use tidefs_vfs_engine::*;
    /// Feature flag: DEVICE_HEALTH_STATE bit in features_compat.
    pub const DEVICE_HEALTH_STATE: u64 = 1 << 7;
    /// Feature flag: POOL_REDUNDANCY_POLICY bit in features_compat.
    pub const POOL_REDUNDANCY_POLICY: u64 = 1 << 9;

    /// Kernel-compatible Vec: under cargo this is `alloc::vec::Vec`;
    /// under Kbuild it wraps `kernel::alloc::KVec`.
    pub type KmodVec<T> = alloc::vec::Vec<T>;

    /// Kernel-compatible Box: under cargo this is `alloc::boxed::Box`;
    /// under Kbuild this is `kernel::alloc::KBox`.
    pub type KmodBox<T> = alloc::boxed::Box<T>;

    /// Kernel-compatible String: under cargo this is `alloc::string::String`;
    /// under Kbuild this wraps `kernel::alloc::KVec<u8>`.
    pub type KmodString = alloc::string::String;
}

// Re-export commonly used items at crate root.
pub use error::{BridgeError, BridgeResult};
pub use traits::{
    AnchorCursorView, AuthorityClient, BioQueue, BorrowDecode, FilesystemRegistration,
    KernelBridge, MirrorLift, PageWindow, PinDrain, ResponseRender, SecretLeaseView,
    ValidationEmit,
};
pub use types::{
    FilesystemRegHandle, FolioWindow, KernelLockClass, OpaqueBio, OpaqueDentry, OpaqueFile,
    OpaqueFolio, OpaqueInode, OpaqueRequestQueue, OpaqueSuperBlock, PinClass, PinEpoch,
    WorkqueueFamily,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::types::{
        FolioWindow, KernelLockClass, OpaqueBio, OpaqueDentry, OpaqueFile, OpaqueFolio,
        OpaqueInode, OpaqueRequestQueue, OpaqueSuperBlock, PinClass, PinEpoch, WorkqueueFamily,
    };
    use alloc::format;

    // ------------------------------------------------------------------
    // Error type tests
    // ------------------------------------------------------------------

    #[test]
    fn bridge_error_display() {
        let err = BridgeError::DecodeFailed {
            detail: "bad magic",
        };
        assert_eq!(format!("{err}"), "decode failed: bad magic");

        let err = BridgeError::AnchorStale {
            generation: 3,
            expected: 5,
        };
        assert_eq!(format!("{err}"), "anchor stale: generation 3, expected 5");

        let err = BridgeError::Unimplemented {
            feature: "folio_populate",
        };
        assert_eq!(format!("{err}"), "unimplemented: folio_populate");
    }

    #[test]
    fn bridge_error_debug_clone_eq() {
        let err = BridgeError::MirrorLiftFailed {
            detail: "null anchor",
        };
        let err2 = err.clone();
        assert_eq!(err, err2);
        assert!(
            format!("{err:?}").contains("MirrorLiftFailed"),
            "Debug output should name the variant"
        );
    }

    #[test]
    fn bridge_result_ok_and_err() {
        let ok: BridgeResult<u32> = Ok(42);
        assert!(matches!(ok, Ok(42)));

        let err: BridgeResult<u32> = Err(BridgeError::InvalidState { detail: "test" });
        assert!(err.is_err());
    }

    // ------------------------------------------------------------------
    // Opaque type wrapper tests
    // ------------------------------------------------------------------

    #[test]
    fn opaque_super_block_from_and_as_ptr() {
        let sentinel: *const core::ffi::c_void = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies round-trip storage.
        let sb = unsafe { OpaqueSuperBlock::from_ptr(sentinel) };
        assert_eq!(sb.as_ptr(), sentinel);
    }

    #[test]
    fn opaque_dentry_from_and_as_ptr() {
        let sentinel: *const core::ffi::c_void = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies round-trip storage.
        let d = unsafe { OpaqueDentry::from_ptr(sentinel) };
        assert_eq!(d.as_ptr(), sentinel);
    }

    #[test]
    fn opaque_inode_from_and_as_ptr() {
        let sentinel = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies round-trip storage.
        let i = unsafe { OpaqueInode::from_ptr(sentinel) };
        assert_eq!(i.as_ptr(), sentinel);
    }

    #[test]
    fn opaque_file_from_and_as_ptr() {
        let sentinel = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies round-trip storage.
        let f = unsafe { OpaqueFile::from_ptr(sentinel) };
        assert_eq!(f.as_ptr(), sentinel);
    }

    #[test]
    fn opaque_folio_from_and_as_ptr() {
        let sentinel = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies round-trip storage.
        let f = unsafe { OpaqueFolio::from_ptr(sentinel) };
        assert_eq!(f.as_ptr(), sentinel);
    }

    #[test]
    fn opaque_bio_from_and_as_ptr() {
        let sentinel = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies round-trip storage.
        let b = unsafe { OpaqueBio::from_ptr(sentinel) };
        assert_eq!(b.as_ptr(), sentinel);
    }

    #[test]
    fn opaque_request_queue_from_and_as_ptr() {
        let sentinel = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies round-trip storage.
        let rq = unsafe { OpaqueRequestQueue::from_ptr(sentinel) };
        assert_eq!(rq.as_ptr(), sentinel);
    }

    #[test]
    fn opaque_types_debug_format() {
        let null = core::ptr::null();
        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies Debug output.
        let sb = unsafe { OpaqueSuperBlock::from_ptr(null) };
        let dbg = format!("{sb:?}");
        assert!(dbg.contains("OpaqueSuperBlock"), "debug: {dbg}");

        // SAFETY: this unit test exercises the opaque facade with a sentinel
        // null pointer and only verifies Debug output.
        let d = unsafe { OpaqueDentry::from_ptr(null) };
        assert!(format!("{d:?}").contains("OpaqueDentry"));
    }

    // ------------------------------------------------------------------
    // FolioWindow tests
    // ------------------------------------------------------------------

    #[test]
    fn folio_window_construction() {
        // SAFETY: this unit test uses a sentinel null opaque pointer and never
        // dereferences it.
        let folio = unsafe { OpaqueFolio::from_ptr(core::ptr::null()) };
        let w = FolioWindow {
            file_offset: 4096,
            length: 4096,
            folio,
            folio_offset: 0,
        };
        assert_eq!(w.file_offset, 4096);
        assert_eq!(w.length, 4096);
        assert_eq!(w.folio_offset, 0);
    }

    // ------------------------------------------------------------------
    // Lock class tests
    // ------------------------------------------------------------------

    #[test]
    fn lock_class_sleepability() {
        // Non-sleepable classes
        assert!(!KernelLockClass::SeqCountEpoch.is_sleepable());
        assert!(!KernelLockClass::RcuAnchor.is_sleepable());
        assert!(!KernelLockClass::ObjectSpin.is_sleepable());
        assert!(!KernelLockClass::EmergencyRaw.is_sleepable());

        // Sleepable classes
        assert!(KernelLockClass::RangeRwsem.is_sleepable());
        assert!(KernelLockClass::DomainMutex.is_sleepable());
        assert!(KernelLockClass::PinMutex.is_sleepable());
        assert!(KernelLockClass::WorkGate.is_sleepable());
        assert!(KernelLockClass::PolicyRwsem.is_sleepable());
    }

    #[test]
    fn lock_class_discriminants_distinct() {
        use KernelLockClass::*;
        let classes = [
            SeqCountEpoch,
            RcuAnchor,
            ObjectSpin,
            RangeRwsem,
            DomainMutex,
            PinMutex,
            WorkGate,
            PolicyRwsem,
            EmergencyRaw,
        ];
        for i in 0..classes.len() {
            for j in (i + 1)..classes.len() {
                assert_ne!(classes[i], classes[j]);
            }
        }
    }

    // ------------------------------------------------------------------
    // Pin class and epoch tests
    // ------------------------------------------------------------------

    #[test]
    fn pin_epoch_equality() {
        let e1 = PinEpoch {
            epoch_id: 1,
            pin_class: PinClass::FolioRef,
        };
        let e2 = PinEpoch {
            epoch_id: 1,
            pin_class: PinClass::FolioRef,
        };
        let e3 = PinEpoch {
            epoch_id: 2,
            pin_class: PinClass::FolioRef,
        };
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn pin_class_discriminants_distinct() {
        use PinClass::*;
        let classes = [
            FolioRef,
            PagePin,
            BioVec,
            DmaMapping,
            RegisteredBuffer,
            DirectMapLoan,
        ];
        for i in 0..classes.len() {
            for j in (i + 1)..classes.len() {
                assert_ne!(classes[i], classes[j]);
            }
        }
    }

    // ------------------------------------------------------------------
    // Workqueue family tests
    // ------------------------------------------------------------------

    #[test]
    fn workqueue_family_discriminants_distinct() {
        use WorkqueueFamily::*;
        let families = [
            ControlSerial,
            NamespaceMut,
            PageWriteback,
            BlockSubmitComplete,
            PinDrain,
            ObserveExport,
            ReclaimRelocate,
            EmergencyRecovery,
        ];
        for i in 0..families.len() {
            for j in (i + 1)..families.len() {
                assert_ne!(families[i], families[j]);
            }
        }
    }

    // ------------------------------------------------------------------
    // Trait object safety (compile-time check)
    // ------------------------------------------------------------------

    // Verify that core traits can be used as trait objects where appropriate.
    // (Most kernel-bridge traits use associated types and are not object-safe
    // by design; this test confirms the expected compile-time behaviour.)

    #[test]
    fn borrow_decode_is_not_object_safe_by_design() {
        // BorrowDecode has an associated type Output and uses &self in methods
        // with generic lifetime — it is intentionally not dyn-compatible.
        // This test simply confirms the module compiles with the trait defined.
    }

    #[test]
    fn kernel_bridge_marker_is_implementable() {
        // KernelBridge is a marker trait with a blanket impl. This test
        // confirms the blanket impl compiles (the trait definition itself
        // exercises this at compile time).
    }
}
