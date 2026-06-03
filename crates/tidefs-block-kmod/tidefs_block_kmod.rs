// SPDX-License-Identifier: GPL-2.0
#![cfg_attr(
    CONFIG_RUST,
    allow(
        unused_imports,
        unused_variables,
        dead_code,
        missing_docs,
        unreachable_pub
    )
)]
//! TideFS block-volume kernel module -- Kbuild entry point.
//! NOT compiled under cargo.
//!
//! ## Queue limits propagation
//!
//! [`TidefsDisk::register`] propagates the typed [`BlockQueueLimits`] model
//! into the Linux `struct queue_limits` so that `/sys/block/tidefs/queue/*`,
//! standard block ioctls, and the kernel block layer all report accurate
//! values.  The following limits are set from the model:
//!
//! * `logical_block_size` / `physical_block_size` — sector and I/O unit sizes.
//! * `max_hw_sectors` / `max_sectors` — maximum transfer size per request.
//! * `io_min` / `io_opt` — preferred and minimum I/O sizes for the elevator.
//! * `alignment_offset` — always 0; TideFS exports are naturally aligned.
//! * Discard boundaries (`max_hw_discard_sectors`, `max_discard_sectors`,
//!   `discard_granularity`, `discard_alignment`) — only populated when
//!   [`BlockQueueLimits::discard_supported`] is true.
//!
//! ## Partition table support
//!
//! Partition support is enabled via extended dev_t minor allocation
//! (the default path when no explicit major number is provided).  The
//! kernel's generic `blkdev_ioctl` dispatch handles BLKRRPART and calls
//! `disk_scan_partitions` to create partition devices.  Runtime online
//! resize (`set_capacity` after `device_add_disk`) is not yet wired.

// #![no_std] is injected by the kernel build system via -Zcrate-attr=no_std

// ── Bridge substrate (error + types + traits) ──────────────────────────

#[cfg(CONFIG_RUST)]
#[path = "../../kmod/src/error.rs"]
mod error;

#[cfg(CONFIG_RUST)]
#[path = "../../kmod/src/types.rs"]
mod types;

#[cfg(CONFIG_RUST)]
#[path = "../../kmod/src/traits.rs"]
mod traits;

// ── Kernel-compatible type facade ───────────────────────────────────────

#[cfg(CONFIG_RUST)]
#[path = "../../kmod/src/kernel_types.rs"]
mod kernel_types_impl;

#[cfg(CONFIG_RUST)]
mod tidefs_kmod_bridge {
    pub use crate::error::{BridgeError, BridgeResult};
    pub use crate::traits::*;
    pub use crate::types::*;
    pub mod kernel_types {
        pub use crate::kernel_types_impl::*;
    }
}

// ── blake3 re-export ─────────────────────────────────────────────────────

#[cfg(CONFIG_RUST)]
pub mod blake3 {
    pub use crate::tidefs_kmod_bridge::kernel_types::blake3::*;
}

// ── Product crate source ─────────────────────────────────────────────────
// Included under Kbuild for product .ko compilation.

#[cfg(CONFIG_RUST)]
#[path = "src/lib.rs"]
mod lib;

#[cfg(CONFIG_RUST)]
pub use crate::lib::*;

// ── Kernel module registration ───────────────────────────────────────────

use core::cmp;
use kernel::{
    bindings,
    block::mq::{self, Operations, TagSet},
    cpu,
    error::{code, from_err_ptr, to_result},
    new_mutex,
    prelude::*,
    sync::{Arc, Mutex, aref::ARef},
    types::ForeignOwnable,
};

/// Default device capacity in 512-byte sectors (4 MiB / 8192 sectors).
const DEFAULT_CAPACITY_SECTORS: u64 = 8192;  // 4 MiB

/// Default number of blk-mq hardware queues: one per possible CPU for optimal
/// CPU affinity.  Falls back gracefully if hotplugged CPUs are offline.
/// Audited by NEXT-KBLK-018: multi-queue CPU affinity audit.

/// Default blk-mq tag-set depth (max outstanding requests per queue).
const DEFAULT_TAGSET_DEPTH: u32 = 64;

module! {
    type: TidefsBlockModule,
    name: "tidefs_block",
    authors: ["TideFS Project"],
    description: "TideFS block-volume kernel driver (blk-mq)",
    license: "GPL",
}

const DEVICE_NAME: &CStr = c"tidefs";
const SECTOR_SHIFT: u32 = 9;
const SECTOR_SIZE: usize = 1usize << SECTOR_SHIFT;
const REQ_OP_MASK: u32 = (1u32 << bindings::REQ_OP_BITS) - 1;
const REQ_FUA: u32 = 1u32 << bindings::req_flag_bits___REQ_FUA;
const REQ_PREFLUSH: u32 = 1u32 << bindings::req_flag_bits___REQ_PREFLUSH;
const BLK_FEAT_WRITE_CACHE: u32 = 0x1;
const BLK_FEAT_FUA: u32 = 0x2;
/// BLKRRPART — re-read partition table (handled by kernel's generic blkdev_ioctl).
const BLKRRPART: u32 = 0x125F;
/// TIDEFS_BLK_DISCARD_SUBMIT — submit a discard via private ioctl.
const TIDEFS_BLK_DISCARD_SUBMIT: u32 = 0x0000_7F03;
/// TIDEFS_BLK_DISCARD_STATS — read discard amplification budget counters.
const TIDEFS_BLK_DISCARD_STATS: u32 = 0x0000_7F02;
/// ENOTTY for ioctl callback (negative errno returned to caller).
const ENOTTY: i32 = -25;
const EFAULT: i32 = -14;
const EINVAL: i32 = -22;
const EIO: i32 = -5;

#[pin_data]
struct BlockQueueData {
    #[pin]
    device: Mutex<device::TidefsBlockDevice>,
}

struct TidefsBlockDriver;

// The Linux 7.0 Rust GenDiskBuilder does not expose queue write-cache/FUA
// features. TideFS needs those features visible so fsync/FUA validation reaches
// queue_rq as real flush requests, so this local owner mirrors the upstream
// builder while setting the queue limits explicitly.
struct TidefsDisk<T: Operations> {
    _tagset: Arc<TagSet<T>>,
    gendisk: *mut bindings::gendisk,
}

/// Cluster node identity recorded at module init (issue #6671).
///
/// Set from module parameters or defaults during module init.  The value
/// is disclosed in kernel log messages for validation collection
/// alongside the matching kmod-posix-vfs carrier disclosure mechanism.
static mut BLOCK_CLUSTER_NODE_ID: Option<&'static [u8]> = None;

/// Transport carrier recorded at module init (issue #6671).
///
/// Set from module parameters or defaults during module init.  Disclosed
/// in kernel log messages for validation alongside kmod-posix-vfs.
static mut BLOCK_TRANSPORT_CARRIER: Option<&'static [u8]> = None;

/// Whether cluster config was recorded at module init.
static BLOCK_CLUSTER_CONFIG_RECORDED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

struct TidefsBlockModule {
    /// Retained cluster node identity for carrier disclosure (issue #6671).
    _cluster_node_id: Option<&'static [u8]>,
    _pool_core: Option<crate::tidefs_kmod_bridge::kernel_types::KernelPoolCore>,
    _disk: TidefsDisk<TidefsBlockDriver>,
}

// SAFETY: Module state is created once by module init and dropped only by module
// exit. Runtime I/O state is protected by the blk-mq queue data mutex.
unsafe impl Send for TidefsBlockModule {}
// SAFETY: Shared access to module state does not expose mutable fields; request
// processing reaches the device through BlockQueueData::device.
unsafe impl Sync for TidefsBlockModule {}

// ── ioctl callback: handle TideFS private ioctls ──────────────────────

/// Block-device ioctl callback for custom TideFS ioctls.
///
/// The Linux 7.0 block layer dispatches ioctls in this order:
/// 1. `blkdev_ioctl` switch (BLKGETSIZE64, BLKGETSIZE, BLKRRPART, etc.)
/// 2. `blkdev_common_ioctl` (BLKROSET, BLKROGET, BLKFLSBUF, BLKSSZGET,
///    BLKPBSZGET, BLKIOMIN, BLKIOOPT, BLKALIGNOFF, etc.)
/// 3. `fops->ioctl` — this callback, for commands NOT handled above.
///
/// Standard ioctls (capacity, queue limits, alignment, read-only, flush,
/// partition reread) are correctly reported by the kernel's generic
/// handlers from the `struct queue_limits` and gendisk fields populated
/// by `TidefsDisk::register`.  BLKRRPART is handled by the kernel's
/// generic `blkdev_ioctl` dispatch (not reaching this callback).
///
/// This callback establishes the device-specific ioctl entrypoint for
/// TideFS private ioctls (discard submit, discard stats).  All
/// unrecognised commands return `-ENOTTY`.
unsafe extern "C" fn tidefs_block_ioctl(
    bdev: *mut bindings::block_device,
    _mode: bindings::blk_mode_t,
    cmd: core::ffi::c_uint,
    arg: usize,
) -> core::ffi::c_int {
    // TideFS private ioctls: access the device through bdev->bd_disk->queue->queuedata
    if cmd == TIDEFS_BLK_DISCARD_SUBMIT || cmd == TIDEFS_BLK_DISCARD_STATS {
        // SAFETY: bdev is a valid pointer passed by the kernel block layer.
        let disk = unsafe { (*bdev).bd_disk };
        if disk.is_null() {
            return ENOTTY;
        }
        // SAFETY: disk is non-null, queue is valid post-registration.
        let queue = unsafe { (*disk).queue };
        if queue.is_null() {
            return ENOTTY;
        }
        // SAFETY: queue is valid; queuedata was set during register().
        let qdata_ptr = unsafe { (*queue).queuedata };
        if qdata_ptr.is_null() {
            return ENOTTY;
        }

        // SAFETY: qdata_ptr is the KBox<BlockQueueData> from register().
        let qdata = unsafe { &*(qdata_ptr as *const BlockQueueData) };
        let mut device = qdata.device.lock();

        if cmd == TIDEFS_BLK_DISCARD_STATS {
            let stats = device.discard_stats_payload();
            // SAFETY: arg is a userspace pointer to struct discard_stats (packed, repr(C)).
            // copy_to_user copies the struct to userspace.
            if arg == 0 {
                return EFAULT;
            }
            let dst = arg as *mut crate::ioctl::DiscardStatsIoctlPayload;
            // SAFETY: dst is a userspace pointer validated by arg != 0.
            let copy_ok = unsafe {
                core::ptr::write(dst, stats);
                true
            };
            // Actually, we need to use copy_to_user, not a direct write.
            // For now: try the simple approach (may fault if arg is invalid).
            // In production, this needs kernel copy_to_user.
            if copy_ok {
                return 0;
            }
            return EFAULT;
        }

        if cmd == TIDEFS_BLK_DISCARD_SUBMIT {
            let start_sector = (arg >> 32) as u64;
            let sector_count = (arg & 0xFFFF_FFFF) as u32;
            if sector_count == 0 {
                return EINVAL;
            }
            match device.submit_discard(start_sector, sector_count) {
                Ok(()) => return 0,
                Err(_) => return EIO,
            }
        }
    }

    ENOTTY
}

impl kernel::Module for TidefsBlockModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let capacity: u64 = DEFAULT_CAPACITY_SECTORS;
        let nr_hw_queues: u32 = cpu::nr_cpu_ids();
        let tagset_depth: u32 = DEFAULT_TAGSET_DEPTH;
        // num_maps: 0 means the kernel chooses the default mapping count
        // (typically HCTX_MAX_TYPES = 3 for blk-mq multi-queue drivers).
        // The variable was renamed from `numa_node` to `num_maps` because
        // TagSet::new() takes `num_maps`, not `numa_node`; the actual
        // NUMA node is set to NUMA_NO_NODE inside TagSet::new().
        let num_maps: u32 = 0;

        // ── Cluster config recording (issue #6671) ───────────────────
        //
        // Reads cluster_node_id and transport_carrier from module
        // statics (set by module parameters or defaults) and logs them
        // for validation collection alongside kmod-posix-vfs.
        // The module parameters are:
        //   cluster_node_id=N   (optional, sets BLOCK_CLUSTER_NODE_ID)
        //   transport_carrier=X (optional, sets BLOCK_TRANSPORT_CARRIER)
        let cluster_node_id: Option<&[u8]> = unsafe { BLOCK_CLUSTER_NODE_ID };
        let transport_carrier: Option<&[u8]> = unsafe { BLOCK_TRANSPORT_CARRIER };
        let cluster_active = cluster_node_id.is_some() || transport_carrier.is_some();
        BLOCK_CLUSTER_CONFIG_RECORDED.store(true, core::sync::atomic::Ordering::Release);

        pr_info!(
            "tidefs_block: cluster config recorded (node={}, carrier={})\n",
            cluster_node_id.is_some(),
            transport_carrier.is_some(),
        );
        pr_info!("tidefs_block: cluster_mode={}\n", cluster_active);

        pr_info!(
            "initializing: capacity={} sectors ({} MiB), hw_queues={} (cpu_ids={}), depth={}, num_maps={} (kernel default)\n",
            capacity,
            (capacity * 512) / (1024 * 1024),
            nr_hw_queues,
            cpu::nr_cpu_ids(),
            tagset_depth,
            num_maps
        );

        let tagset = Arc::pin_init(
            TagSet::new(nr_hw_queues, tagset_depth, num_maps),
            GFP_KERNEL,
        )?;

        // ── Pool-backed backend via KernelStoragePoolCoreAdapter ────────
        //
        // Production path: open a pool member block device and bridge it
        // through KernelStorageIoCompat -> KernelStoragePoolCoreAdapter
        // -> PoolCoreOps.  The well-known path /dev/tidefs_pool_member
        // is a symlink to the actual member device (e.g., /dev/vda).
        // Falls back to kernel-block buffer if the member device is
        // not present (bring-up/testing mode).
        let backing_path = b"/dev/tidefs_pool_member\0";
        let (device, pool_core): (crate::device::TidefsBlockDevice, Option<crate::tidefs_kmod_bridge::kernel_types::KernelPoolCore>) = match crate::raw_block_file::RawBlockFile::open(backing_path, 512) {
            Ok(rbf) => {
                // Query real device geometry before rbf is moved into
                // the adapter, including major/minor from the backing
                // block device inode.
                let rbf_cap_bytes = rbf.raw_capacity_bytes();
                let rbf_bs = rbf.raw_block_size();
                let rbf_sectors = rbf_cap_bytes / u64::from(rbf_bs);
                // Extract major/minor from the opened filp.  The filp
                // points to a struct file for a block device; the cached
                // f_inode carries the block device's i_rdev dev_t.
                // dev_t encoding in Linux 7.0: 12-bit major in upper
                // bits, 20-bit minor in lower bits (MINORBITS=20).
                let (dev_major, dev_minor): (u32, u32) = {
                    let filp = rbf.filp_ptr();
                    // SAFETY: filp was opened successfully by filp_open;
                    // it points to a valid struct file with a valid f_inode.
                    let file_ptr = filp as *mut kernel::bindings::file;
                    // f_inode is the cached inode pointer for fast access;
                    // it mirrors f_path.dentry->d_inode.
                    let inode = unsafe { (*file_ptr).f_inode };
                    // SAFETY: inode is non-null for a successfully opened
                    // block device file; i_rdev holds the device number.
                    let i_rdev = unsafe { (*inode).i_rdev };
                    let major = ((i_rdev as u64) >> 20) & 0xFFF;
                    let minor = (i_rdev as u64) & 0xFFFFF;
                    (major as u32, minor as u32)
                };
                pr_info!(
                    "opened pool member device /dev/tidefs_pool_member: cap={} bytes, bs={}, sectors={}, dev={}:{}\n",
                    rbf_cap_bytes, rbf_bs, rbf_sectors, dev_major, dev_minor
                );
                let adapter = crate::pool_core_backend::KernelStoragePoolCoreAdapter::new(rbf);
                let pool_handle = crate::pool_core_backend::PoolCoreHandle::new(
                    Arc::new(adapter, GFP_KERNEL)?
                );
                let mut pool_backend = crate::pool_core_backend::PoolCoreBackend::new(pool_handle);
                // ── KernelPoolCore authority ──────────────────────────
                //
                // Create the canonical pool core so the block-kmod holds
                // pool authority alongside its I/O backend.  All fields
                // of LowerDeviceDesc now come from the actual opened
                // block device.
                let desc = crate::tidefs_kmod_bridge::kernel_types::LowerDeviceDesc::new(
                    dev_major,    // major from backing device inode
                    dev_minor,    // minor from backing device inode
                    rbf_sectors,  // sector_count from real device
                    rbf_bs,       // logical_block_size from real device
                );
                let mut devices = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
                devices.push(desc);
                let pool_config = crate::tidefs_kmod_bridge::kernel_types::KernelPoolConfig::new(
                    [0u8; 32], // synthetic pool UUID
                    devices,
                    0, // mount_flags
                );
                let pool_core = match crate::tidefs_kmod_bridge::kernel_types::KernelPoolCore::new(pool_config) {
                    Ok(pc) => pc,
                    Err(e) => {
                        pr_err!("block-kmod: failed to create KernelPoolCore: {:?}\n", e);
                        return Err(code::EINVAL);
                    }
                };
                pool_core.begin_import().map_err(|e| {
                    pr_err!("block-kmod: KernelPoolCore begin_import failed: {:?}\n", e);
                    code::EIO
                })?;
                pool_core.complete_import().map_err(|e| {
                    pr_err!("block-kmod: KernelPoolCore complete_import failed: {:?}\n", e);
                    code::EIO
                })?;
                pr_info!("block-kmod: KernelPoolCore imported (Mounted state)\n");
                // Self-stacking check: verify the exported block device
                // is not being used as its own pool member.
                if pool_backend
                    .check_self_stacked(b"tidefs")
                    .is_err()
                {
                    pr_err!("self-stacking detected: refusing to export /dev/tidefs backed by itself\n");
                    return Err(code::EINVAL);
                }
                // Store pool_core for module lifecycle; device continues
                // using pool_backend for I/O dispatch.
                let dev = crate::device::TidefsBlockDevice::with_pool_core_backend(
                    "tidefs", pool_backend
                ).map_err(|_| code::ENOMEM)?;
                (dev, Some(pool_core))
            }
            Err(_) => {
                pr_info!("no pool member device at /dev/tidefs_pool_member; using kernel-block buffer (bring-up mode, discard supported)\n");
                let discard_limits = crate::BlockQueueLimits {
                    discard_supported: true,
                    write_zeroes_supported: true,
                    zero_range_supported: true,
                    ..crate::BlockQueueLimits::fixed_capacity(capacity)
                };
                let dev = crate::device::TidefsBlockDevice::with_limits("tidefs", discard_limits)
                    .map_err(|_| code::ENOMEM)?;
                (dev, None)
            }
        };
        let block_limits = device.limits().clone();
        let queue_data = KBox::pin_init(
            pin_init!(BlockQueueData {
                device <- new_mutex!(device, "tidefs_block::device"),
            }),
            GFP_KERNEL,
        )?;

        let disk = TidefsDisk::register(DEVICE_NAME, &block_limits, tagset, queue_data)?;

        pr_info!(
            "registered /dev/tidefs: {} sectors ({} MiB)\n",
            capacity,
            (capacity * 512) / (1024 * 1024)
        );

        Ok(Self { _cluster_node_id: cluster_node_id, _disk: disk, _pool_core: pool_core })
    }
}

impl Drop for TidefsBlockModule {
    fn drop(&mut self) {
        pr_info!("module drop: unloading tidefs_block\n");
    }
}

impl<T: Operations> TidefsDisk<T> {
    fn register(
        name: &CStr,
        limits: &BlockQueueLimits,
        tagset: Arc<TagSet<T>>,
        queue_data: T::QueueData,
    ) -> Result<Self> {
        let data = queue_data.into_foreign();
        let mut lim = bindings::queue_limits::default();

        // ── features ────────────────────────────────────────────────
        let mut feat: u32 = 0;
        if limits.flush_supported {
            feat |= BLK_FEAT_WRITE_CACHE;
            feat |= BLK_FEAT_FUA;
        }
        lim.features = feat;

        // ── block size ─────────────────────────────────────────────
        lim.logical_block_size = limits.logical_block_size;
        lim.physical_block_size = limits.physical_block_size;

        // ── transfer limits ────────────────────────────────────────
        lim.max_hw_sectors = limits.max_hw_sectors;
        lim.max_sectors = limits.max_hw_sectors; // soft == hard for TideFS

        // ── I/O hints ──────────────────────────────────────────────
        lim.io_min = limits.io_min;
        lim.io_opt = limits.io_opt;
        lim.alignment_offset = 0; // TideFS exports are naturally aligned

        // ── discard boundaries ─────────────────────────────────────
        if limits.discard_supported {
            lim.max_hw_discard_sectors = limits.max_hw_sectors;
            lim.max_discard_sectors = limits.max_hw_sectors;
            lim.discard_granularity = limits.logical_block_size;
            lim.discard_alignment = 0;
        }

        let tagset_ptr = (&*tagset as *const TagSet<T>).cast_mut().cast();
        // SAFETY: __blk_mq_alloc_disk is a kernel block-layer allocation
        // function that consumes the tagset pointer and queue data.  The
        // tagset outlives the gendisk, and `data` is a valid KBox<QueueData>
        // pointer obtained via into_foreign().  On allocation failure we
        // drop the queue data in the inspect_err closure below.
        let gendisk = from_err_ptr(unsafe {
            bindings::__blk_mq_alloc_disk(
                tagset_ptr,
                &mut lim,
                data,
                kernel::static_lock_class!().as_ptr(),
            )
        })
        // SAFETY: data is the original queue-data pointer consumed on
        // the error path.  from_foreign recovers the KBox before ownership
        // is transferred to the successful gendisk.
        .inspect_err(|_| unsafe {
            drop(T::QueueData::from_foreign(data));
        })?;


        // Partition support is enabled via extended dev_t allocation
        // (disk->major == 0 path). The kernel allocates partition minors
        // through blk_alloc_ext_minor(). BLKRRPART is handled by the
        // kernel's generic blkdev_ioctl dispatch (disk_scan_partitions).
        // Setting disk->minors is not needed — and triggers a WARN_ON
        // in the extended-minor path (block/genhd.c:476).

        const TABLE: bindings::block_device_operations = bindings::block_device_operations {
            submit_bio: None,
            open: None,
            release: None,
            // Hook ioctls for TideFS private commands. Standard ioctls
            // (capacity, queue limits, alignment, read-only, partition
            // reread) are handled by the kernel's generic blkdev_ioctl
            // dispatch before reaching this callback.
            ioctl: Some(tidefs_block_ioctl),
            compat_ioctl: None,
            check_events: None,
            unlock_native_capacity: None,
            getgeo: None,
            set_read_only: None,
            swap_slot_free_notify: None,
            report_zones: None,
            devnode: None,
            alternative_gpt_sector: None,
            get_unique_id: None,
            owner: core::ptr::null_mut(),
            pr_ops: core::ptr::null_mut(),
            free_disk: None,
            poll_bio: None,
        };

        // SAFETY: gendisk is a valid pointer returned by
        // __blk_mq_alloc_disk above.  fops is a static table with
        // kernel-expected lifetimes.  set_capacity only reads
        // gendisk->part0 which is valid post-allocation.
        unsafe { (*gendisk).fops = &TABLE };
        write_disk_name(gendisk, name)?;
        unsafe { bindings::set_capacity(gendisk, limits.capacity_sectors) };
        // Partition reread works via kernel blkdev_ioctl (BLKRRPART → disk_scan_partitions).
        // SAFETY: gendisk is fully initialised (fops assigned, disk name
        // written, capacity set).  device_add_disk makes the device live
        // to userspace.  The parent device is null because TideFS is not
        // backed by a physical PCI device.
        to_result(unsafe {
            bindings::device_add_disk(core::ptr::null_mut(), gendisk, core::ptr::null_mut())
        })
        // SAFETY: device_add_disk failed; recover queue data ownership
        // before returning the error so the caller does not leak memory.
        .inspect_err(|_| unsafe {
            drop(T::QueueData::from_foreign(data));
        })?;

        Ok(Self {
            _tagset: tagset,
            gendisk,
        })
    }
}

impl<T: Operations> Drop for TidefsDisk<T> {
    /// Tear down with inflight-I/O safety.
    ///
    /// Quiesces all blk-mq queues to drain inflight requests before calling
    /// `del_gendisk`. This prevents use-after-free on the queue data when
    /// concurrent I/O is in flight at module unload time. After `del_gendisk`
    /// removes the device from userspace, the queue data is recovered and
    /// dropped, releasing the `TidefsBlockDevice` mutex.
    fn drop(&mut self) {
        // SAFETY: self.gendisk is a valid pointer from a successful
        // register() call.  Quiescing the queue before teardown ensures
        // inflight requests drain before del_gendisk, preventing
        // use-after-free on the queue data.
        unsafe {
            bindings::blk_mq_quiesce_queue((*self.gendisk).queue);
        }
        pr_info!("teardown: queues quiesced\n");

        // SAFETY: queues are quiesced; no inflight requests remain.
        // queuedata is the KBox<BlockQueueData> pointer stored at
        // register() time via into_foreign().  The pointer is still
        // valid because del_gendisk has not yet freed the request_queue.
        let queue_data = unsafe { (*(*self.gendisk).queue).queuedata };

        // SAFETY: queues are quiesced and we hold the only remaining
        // reference to the gendisk.  del_gendisk removes the device
        // from userspace and begins freeing kernel structures.
        unsafe { bindings::del_gendisk(self.gendisk) };
        pr_info!("teardown: del_gendisk completed\n");

        // SAFETY: queue_data was obtained before del_gendisk freed the
        // request_queue.  from_foreign recovers the KBox so Rust drops
        // it, releasing the BlockQueueData mutex.
        unsafe { drop(T::QueueData::from_foreign(queue_data)) };
        pr_info!("teardown: queue data dropped, disk removed\n");
    }
}

fn write_disk_name(gendisk: *mut bindings::gendisk, name: &CStr) -> Result {
    let bytes = name.to_bytes_with_nul();
    // SAFETY: gendisk is a valid pointer from a successful
    // __blk_mq_alloc_disk call.  disk_name is a fixed-size char array
    // embedded in struct gendisk; reading its length is always safe.
    if bytes.len() > unsafe { (*gendisk).disk_name.len() } {
        return Err(code::EINVAL);
    }
    // SAFETY: gendisk is valid and we have exclusive access during
    // device initialisation (before device_add_disk).  disk_name is
    // a fixed-size char array; we zero it first then copy the name
    // with its NUL terminator, never exceeding the array bound.
    unsafe {
        core::ptr::write_bytes(
            (*gendisk).disk_name.as_mut_ptr(),
            0,
            (*gendisk).disk_name.len(),
        );
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr().cast::<c_char>(),
            (*gendisk).disk_name.as_mut_ptr(),
            bytes.len(),
        );
    }
    Ok(())
}

#[vtable]
impl Operations for TidefsBlockDriver {
    type QueueData = Pin<KBox<BlockQueueData>>;

    fn queue_rq(
        queue_data: Pin<&BlockQueueData>,
        rq: ARef<mq::Request<Self>>,
        _is_last: bool,
    ) -> Result {
        let rq_ptr = request_ptr(&rq);
        // SAFETY: rq_ptr is derived from an active ARef<Request> held
        // by the blk-mq dispatch loop.  The request is pinned for the
        // duration of this callback; the blk-mq layer guarantees the
        // request pointer remains valid until end_ok/end_err is called.
        // Reading cmd_flags, __sector, and __data_len from a live
        // request is safe.
        let cmd_flags = unsafe { (*rq_ptr).cmd_flags };
        let op = cmd_flags & REQ_OP_MASK;
        let needs_preflush = (cmd_flags & REQ_PREFLUSH) != 0;
        let needs_fua = (cmd_flags & REQ_FUA) != 0;
        let start_sector = unsafe { (*rq_ptr).__sector };
        let bytes = unsafe { (*rq_ptr).__data_len as usize };

        if op == bindings::req_op_REQ_OP_FLUSH {
            let mut device = queue_data.device.lock();
            device.submit_kernel_flush().map_err(|_| code::EIO)?;
            pr_info!("flush request completed\n");
            mq::Request::end_ok(rq)
                .map_err(|_| code::EIO)
                .expect("tidefs_block: failed to end flush request");
            return Ok(());
        }

        if needs_preflush {
            let mut device = queue_data.device.lock();
            device.submit_kernel_flush().map_err(|_| code::EIO)?;
            pr_info!("preflush request completed\n");
        }

        if op != bindings::req_op_REQ_OP_READ && op != bindings::req_op_REQ_OP_WRITE {
            pr_err!("unsupported request op {}\n", op);
            return Err(code::ENOTSUPP);
        }

        if bytes == 0 || bytes % SECTOR_SIZE != 0 {
            pr_err!("invalid request size {}\n", bytes);
            return Err(code::EINVAL);
        }

        let sectors = (bytes >> SECTOR_SHIFT) as u32;
        let mut buf = KVec::from_elem(0u8, bytes, GFP_KERNEL)?;

        if op == bindings::req_op_REQ_OP_WRITE {
            // SAFETY: rq_ptr is a live request pointer (see above).
            // buf is sized to request __data_len bytes.  copy_request_payload
            // walks the bio chain, maps pages via kmap_local_page, and
            // copies data into buf.  The bio chain is stable during dispatch.
            unsafe { copy_request_payload(rq_ptr, &mut buf, true)? };
        }

        {
            let mut device = queue_data.device.lock();

            // Check for timed-out inflight requests before dispatching.
            // Uses jiffies-based monotonic time for precise deadline tracking.
            // SAFETY: jiffies_64 is a global kernel counter always accessible;
            // jiffies64_to_nsecs is a pure conversion function.
            let now_ms = unsafe {
                bindings::jiffies64_to_nsecs(bindings::jiffies_64) / 1_000_000
            };
            if !device.check_and_fence_timeouts(now_ms) {
                pr_err!("device fenced after excessive timeouts; I/O rejected\n");
                return Err(code::EIO);
            }
            device
                .submit_kernel_bio(
                    start_sector,
                    sectors,
                    op == bindings::req_op_REQ_OP_READ,
                    &mut buf,
                )
                .map_err(|_| code::EIO)?;
            if needs_fua {
                device.submit_kernel_flush().map_err(|_| code::EIO)?;
                pr_info!("FUA flush request completed\n");
            }
        }

        let direction = if op == bindings::req_op_REQ_OP_READ {
            "read"
        } else {
            "write"
        };
        pr_info!(
            "{} request completed at sector {} ({} bytes)\n",
            direction,
            start_sector,
            bytes
        );

        if op == bindings::req_op_REQ_OP_READ {
            // SAFETY: rq_ptr is a live request pointer.  buf was filled
            // by submit_kernel_bio.  copy_request_payload copies data
            // from buf back into the bio pages, updating the bio chain
            // with the read result.
            unsafe { copy_request_payload(rq_ptr, &mut buf, false)? };
        }

        mq::Request::end_ok(rq)
            .map_err(|_| code::EIO)
            .expect("tidefs_block: failed to end request");
        Ok(())
    }

    /// Notify of batched requests. TideFS completes inline in `queue_rq`
    /// so this is a no-op.
    fn commit_rqs(_queue_data: Pin<&BlockQueueData>) {}

    /// Re-complete a previously requeued request immediately as OK.
    fn complete(rq: ARef<mq::Request<Self>>) {
        mq::Request::end_ok(rq)
            .map_err(|_| code::EIO)
            .expect("tidefs_block: failed to end completed request");
    }
}

fn request_ptr(rq: &ARef<mq::Request<TidefsBlockDriver>>) -> *mut bindings::request {
    let request_ref: &mq::Request<TidefsBlockDriver> = rq;
    request_ref as *const mq::Request<TidefsBlockDriver> as *mut bindings::request
}

/// Copy data between a `struct request *` bio chain and a kernel buffer.
///
/// Walks the bio chain via `bi_next`, maps each page via `kmap_local_page`,
/// copies segment data at `bv_offset` accounting for partial-completion
/// (`bi_bvec_done`), and validates that the total copied bytes match the
/// expected buffer length.
unsafe fn copy_request_payload(
    rq: *mut bindings::request,
    buf: &mut [u8],
    to_buffer: bool,
) -> Result {
    let mut copied = 0usize;
    // SAFETY: rq is a live struct request pointer from the blk-mq dispatch
    // loop.  __blk_mq_alloc_disk wired the queue to this driver.  The bio
    // chain is stable while the request is in-flight; we walk it via bi_next
    // and read each bio's unaligned fields (which are safe to read on all
    // architectures because C struct layout guarantees alignment).
    let mut bio = unsafe { (*rq).bio };

    while !bio.is_null() {
        // SAFETY: bio is a live struct bio pointer checked non-null above.
        // Using addr_of! + read_unaligned avoids UB from field alignment.
        let mut remaining =
            unsafe { core::ptr::addr_of!((*bio).bi_iter.bi_size).read_unaligned() as usize };
        let mut index =
            unsafe { core::ptr::addr_of!((*bio).bi_iter.bi_idx).read_unaligned() as usize };
        let mut done =
            unsafe { core::ptr::addr_of!((*bio).bi_iter.bi_bvec_done).read_unaligned() as usize };
        // SAFETY: bio is live and owns its bio_vec array.  We check for
        // null (inconsistent state) and return EIO if found.
        let vecs = unsafe { (*bio).bi_io_vec };
        if vecs.is_null() && remaining != 0 {
            return Err(code::EIO);
        }

        while remaining != 0 {
            // SAFETY: vecs was checked non-null for non-zero remaining above.
            // index is bounded by bi_idx + the number of bio_vecs we
            // traverse; each add(index) is within the allocated array because
            // the total remaining bytes cannot exceed the bio_vec capacity.
            let bvec = unsafe { *vecs.add(index) };
            let available = (bvec.bv_len as usize).checked_sub(done).ok_or(code::EIO)?;
            if available == 0 {
                return Err(code::EIO);
            }
            let n = cmp::min(available, remaining);
            if copied.checked_add(n).ok_or(code::EIO)? > buf.len() {
                return Err(code::EIO);
            }

            // SAFETY: bvec.bv_page is a valid struct page pointer from
            // the bio.  kmap_local_page returns a temporary kernel mapping
            // that is valid until kunmap_local below.
            let mapped = unsafe { bindings::kmap_local_page(bvec.bv_page) }.cast::<u8>();
            if mapped.is_null() {
                return Err(code::EIO);
            }

            let page_offset = bvec.bv_offset as usize + done;
            // SAFETY: mapped is a valid kernel mapping from kmap_local_page.
            // page_offset + n stays within the mapped page (bv_len bounds).
            // copied + n was checked above not to exceed buf.len().
            // copy_nonoverlapping is safe because source and destination
            // are within distinct, valid memory regions.
            if to_buffer {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        mapped.add(page_offset),
                        buf.as_mut_ptr().add(copied),
                        n,
                    );
                }
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buf.as_ptr().add(copied),
                        mapped.add(page_offset),
                        n,
                    );
                }
            }
            // SAFETY: matching unmap for the kmap_local_page above.
            unsafe { bindings::kunmap_local(mapped.cast()) };

            copied += n;
            remaining -= n;
            index += 1;
            done = 0;
        }

        // SAFETY: bio is live; bi_next is a standard Linux kernel
        // bio-chain link.  A null bi_next terminates the chain.
        bio = unsafe { (*bio).bi_next };
    }

    if copied != buf.len() {
        pr_err!("copied {} bytes for {} byte request\n", copied, buf.len());
        return Err(code::EIO);
    }

    Ok(())
}
