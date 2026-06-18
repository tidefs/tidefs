// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-boundary trait contracts (t0–t9).
//!
//! These traits define the typed seam between canonical userspace authority
//! (strata s0/s1) and Linux kernel mechanics (stratum s2). Downstream leaf
//! modules (s3 — posix_filesystem_adapter, block_volume_adapter, optional
//! policy_authority) consume these traits through the bridge; the
//! Rust-for-Linux kernel build environment supplies concrete implementations
//! that bind to actual Linux kernel object types.
//!
//! # Stratum ownership
//!
//! | Trait | Name | Owning crate family | Legal implementors |
//! |-------|------|---------------------|--------------------|
//! | t0    | BorrowDecode        | c1 / c2 (s0) | c0 / c1 / c2 |
//! | t1    | AnchorCursorView    | c2 (s0)      | c2 / c3 |
//! | t2    | MirrorLift          | c3 (s1)      | c3 |
//! | t3    | AuthorityClient     | c3 (s1)      | c6 |
//! | t4    | ResponseRender      | c4 (s1)      | c4, consumed by c7/c8 via c6 |
//! | t5    | ValidationEmit        | c5 (s1)      | c6 / c7 / c8 / c9 |
//! | t6    | PinDrain            | c6 (s2)      | c6 / c7 / c8 / c9 |
//! | t7    | PageWindow          | c6 (s2)      | c7 |
//! | t8    | BioQueue            | c6 (s2)      | c8 |
//! | t9    | SecretLeaseView     | c6 (s2)      | c6, c9, read-only c7/c8 |

use crate::error::BridgeResult;
use crate::types::{FolioWindow, OpaqueBio, OpaqueInode, PinClass, PinEpoch};

// Kbuild-compatible Vec type
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::KmodVec;
#[cfg(not(CONFIG_RUST))]
use alloc::vec::Vec as KmodVec;

// =========================================================================
// t0 — BorrowDecode: borrowed decode and continuity checks
// =========================================================================

/// Borrowed decode and continuity-check contract for canonical artifacts.
///
/// Implementations parse `binary_schema` envelopes, `feature_window` continuity
/// windows, `schema_codec` receipts, and `canonical_schema` anchors without
/// allocation. This trait lives at s0 (no_std core); the bridge re-exports it
/// for kernel consumers.
pub trait BorrowDecode<'a> {
    /// The type produced by decoding.
    type Output;

    /// Attempt to decode a borrowed byte slice into `Self::Output`.
    fn borrow_decode(input: &'a [u8]) -> BridgeResult<Self::Output>;

    /// Check whether the decoded artifact is continuous with a prior epoch.
    fn check_continuity(&self, prior_epoch: u64) -> bool;
}

// =========================================================================
// t1 — AnchorCursorView: typed access to checkpoint/snapshot/replay-cursor frontiers
// =========================================================================

/// Typed access to a checkpoint, snapshot, or replay-cursor frontier.
///
/// Kernel leaves use this to locate the current canonical position without
/// owning checkpoint-writer authority. The actual anchor storage lives in
/// userspace; the kernel bridge mirrors it via this read-only trait.
pub trait AnchorCursorView {
    /// The anchor type (checkpoint, snapshot, or replay-cursor identifier).
    type Anchor;

    /// Return the current committed anchor generation.
    fn current_generation(&self) -> u64;

    /// Read the anchor at a given generation, if it exists and is committed.
    fn read_anchor(&self, generation: u64) -> BridgeResult<Self::Anchor>;

    /// Return the most recent anchor that is <= the given generation.
    fn nearest_anchor_le(&self, generation: u64) -> BridgeResult<(u64, Self::Anchor)>;
}

// =========================================================================
// t2 — MirrorLift: convert borrowed canonical views into owned mirror payloads
// =========================================================================

/// Convert a borrowed canonical view into an owned kernel-mirror payload.
///
/// This is the kernel-side equivalent of deserializing a canonical envelope
/// into a heap-allocated mirror that the kernel can cache, pin, and render.
/// Implementations live at s1 (alloc); the bridge re-exports the trait for
/// kernel consumers that need to construct mirror payloads from borrowed views.
pub trait MirrorLift {
    /// The canonical (borrowed) input type.
    type Canonical<'a>
    where
        Self: 'a;

    /// The owned mirror output type.
    type Mirror;

    /// Lift a borrowed canonical view into an owned mirror.
    fn lift(canonical: &Self::Canonical<'_>) -> BridgeResult<Self::Mirror>;
}

// =========================================================================
// t3 — AuthorityClient: carrier-agnostic request/receipt/response exchange
// =========================================================================

/// Carrier-agnostic authority-client contract.
///
/// Kernel leaves send requests (e.g., "authorize this open", "validate this
/// write intent") to the userspace authority surfaces and receive canonical
/// responses. The bridge (c6) implements this trait by binding to a transport
/// stub; leaf modules call it without knowing the carrier details.
pub trait AuthorityClient {
    /// A canonical request payload.
    type Request;

    /// A canonical response payload.
    type Response;

    /// A receipt proving the response was accepted.
    type Receipt;

    /// Send a request and block until a response (or refusal) is received.
    ///
    /// This is a blocking call from the kernel's perspective; the bridge
    /// implementation must respect the kernel's sleepability rules for the
    /// calling context.
    fn send_request(
        &self,
        request: &Self::Request,
    ) -> BridgeResult<(Self::Response, Self::Receipt)>;

    /// Check whether this client is still connected to the authority.
    fn is_connected(&self) -> bool;
}

// =========================================================================
// t4 — ResponseRender: canonical response → Linux render plan
// =========================================================================

/// Map a canonical response envelope into a Linux-kernel render plan.
///
/// The render plan is a set of typed field assignments (errno, flags, ioctl
/// codes, queue limits, statx fields, etc.) that the leaf module applies to
/// Linux kernel objects. The bridge (c6) wraps the s1 render helpers; leaf
/// modules consume the rendered plan.
pub trait ResponseRender {
    /// The canonical response type consumed by this renderer.
    type Response;

    /// The Linux render plan produced.
    type RenderPlan;

    /// Convert a canonical response into a Linux render plan.
    fn render(response: &Self::Response) -> BridgeResult<Self::RenderPlan>;
}

// =========================================================================
// t5 — ValidationEmit: shared row/bucket/artifact fragment emission
// =========================================================================

/// Emit validation fragments (rows, buckets, artifact manifests) for operator
/// truth surfaces, cutover control, performance budgets, and validation
/// preservation sinks.
///
/// Kernel leaves call this to record operational validation without owning
/// dashboard storage/indexing truth. The bridge routes fragments to the
/// userspace validation_output pipeline.
pub trait ValidationEmit {
    /// An validation fragment (row, bucket summary, or artifact manifest).
    type Fragment;

    /// Emit a single validation fragment.
    ///
    /// Must be non-blocking in hot paths; may drop fragments silently under
    /// memory pressure rather than blocking kernel execution.
    fn emit(&self, fragment: Self::Fragment);

    /// Flush any buffered fragments to the validation sink.
    fn flush(&self) -> BridgeResult<()>;
}

// =========================================================================
// t6 — PinDrain: shared pin/fence/drain operations
// =========================================================================

/// Shared pin, fence, and drain operations for kernel objects.
///
/// Governed by P4-04 (zero-copy DMA pinning) and P7-03 (kernel locking model).
/// Every mutable kernel object that holds pins must be drainable through this
/// contract.
pub trait PinDrain {
    /// Acquire a pin in the given class, returning an epoch token.
    fn pin_acquire(&self, class: PinClass) -> BridgeResult<PinEpoch>;

    /// Release a pin by its epoch token.
    fn pin_release(&self, epoch: PinEpoch) -> BridgeResult<()>;

    /// Drain all pins of the given class, blocking until none remain.
    ///
    /// This is used during quiesce, fence, and cutover transitions.
    fn drain_class(&self, class: PinClass) -> BridgeResult<()>;

    /// Return the number of outstanding pins in a class.
    fn pin_count(&self, class: PinClass) -> usize;
}

// =========================================================================
// t7 — PageWindow: page-window / folio / invalidate / clean-read helpers
// =========================================================================

/// Page-window operations for the posix_filesystem_adapter leaf (c7).
///
/// Covers folio population, invalidation, and clean-read window mapping.
/// Only the posix_filesystem_adapter leaf may implement or consume this.
pub trait PageWindow {
    /// Map a byte range into one or more FolioWindows backed by folios.
    fn map_windows(
        &self,
        inode: OpaqueInode,
        offset: u64,
        length: u32,
    ) -> BridgeResult<KmodVec<FolioWindow>>;

    /// Populate a page window with data from canonical storage.
    fn populate_window(&self, window: &FolioWindow, data: &[u8]) -> BridgeResult<()>;

    /// Invalidate (truncate / hole-punch) a byte range in the page cache.
    fn invalidate_range(&self, inode: OpaqueInode, offset: u64, length: u64) -> BridgeResult<()>;

    /// Check whether a byte range is fully populated (no holes).
    fn is_range_populated(&self, inode: OpaqueInode, offset: u64, length: u64) -> bool;
}

// =========================================================================
// t8 — BioQueue: request/bio queue, barrier, and completion helpers
// =========================================================================

/// Block-I/O queue operations for the block_volume_adapter leaf (c8).
///
/// Covers bio submission, completion, barrier insertion, and queue-limit
/// querying. Only the block_volume_adapter leaf may implement or consume this.
pub trait BioQueue {
    /// Submit a bio for I/O.
    fn submit_bio(&self, bio: OpaqueBio) -> BridgeResult<()>;

    /// Insert a barrier: all prior bios must complete before subsequent bios start.
    fn insert_barrier(&self) -> BridgeResult<()>;

    /// Wait for all outstanding bios to complete.
    fn drain_queue(&self) -> BridgeResult<()>;

    /// Return the queue depth (outstanding bios).
    fn queue_depth(&self) -> u32;
}

// =========================================================================
// t9 — SecretLeaseView: read-only handle / lease / capability / keyring views
// =========================================================================

/// Read-only access to secret handles, leases, capabilities, and keyring
/// residency under the `secret_key_policy_0` law (P9-04).
///
/// Kernel leaves may inspect handle ids, epochs, digest fragments, and
/// capability classes, but they must never hold long-lived plaintext secrets.
/// The bridge (c6) and optional policy_authority leaf (c9) implement this;
/// client leaves (c7, c8) consume it read-only.
pub trait SecretLeaseView {
    /// A handle identifier.
    type HandleId;

    /// A lease capability descriptor.
    type Capability;

    /// Resolve a handle id to its current epoch and capability class.
    fn resolve_handle(&self, handle_id: Self::HandleId) -> BridgeResult<(u64, Self::Capability)>;

    /// Check whether a handle is still valid (not revoked, not expired).
    fn is_handle_valid(&self, handle_id: Self::HandleId) -> bool;

    /// Return the digest fragment for a handle (never the full secret).
    fn handle_digest_fragment(&self, handle_id: Self::HandleId) -> BridgeResult<[u8; 8]>;
}

// =========================================================================
// Composite bridge capability marker
// =========================================================================

/// Marker trait asserting that a type provides the full kernel-bridge
/// capability set required by a given leaf module family.
///
/// This is a compile-time gate: a leaf module's generic context bounds on
/// this trait, and the kernel build environment provides a concrete
/// implementation that satisfies all constituent trait contracts.
pub trait KernelBridge:
    AnchorCursorView
    + AuthorityClient
    + ValidationEmit
    + PinDrain
    + SecretLeaseView
    + FilesystemRegistration
{
}

// Blanket impl for any type that satisfies all constituent traits.
impl<T> KernelBridge for T where
    T: AnchorCursorView
        + AuthorityClient
        + ValidationEmit
        + PinDrain
        + SecretLeaseView
        + FilesystemRegistration
{
}

// =========================================================================
// t10 — FilesystemRegistration: register/unregister a Linux filesystem type
// =========================================================================

/// Register and unregister a Linux filesystem type.
///
/// Kernel leaf modules (s3) call this contract during module init/exit to
/// make the filesystem visible to the Linux VFS (e.g., `/proc/filesystems`,
/// `mount -t tidefs`). In the kernel build environment, this delegates to
/// `kernel::filesystem::Registration`; in the userspace shim, it records
/// registration state for compile-time and unit-test verification.
///
/// # Safety (kernel callback ABI)
///
/// When a filesystem is registered, the kernel VFS may call the module's
/// `fill_super` callback at any time. The module must be prepared to handle
/// the full mount lifecycle before registration completes. The
/// `unregister_filesystem` method must block until all outstanding mounts
/// have been torn down (or return `EBUSY` if mounts remain).
pub trait FilesystemRegistration {
    /// The handle type representing an active registration.
    type Handle;

    /// Register a filesystem with the given name.
    ///
    /// On success, returns a handle that must be passed to
    /// [`unregister_filesystem`] during module exit.
    fn register_filesystem(name: &[u8]) -> BridgeResult<Self::Handle>;

    /// Unregister a previously registered filesystem.
    ///
    /// Returns `EBUSY` if one or more superblocks are still mounted.
    fn unregister_filesystem(handle: &Self::Handle) -> BridgeResult<()>;
}
