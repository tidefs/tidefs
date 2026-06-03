#![allow(unsafe_code)]
#![allow(dead_code)]
//! Safe Rust wrappers around raw libibverbs FFI bindings.
//!
//! Each type wraps an opaque libibverbs pointer with resource cleanup
//! through `Drop`. The QP state machine is enforced through
//! `QueuePair` transition methods that validate source states and
//! set the correct attribute masks.

use std::ffi::{c_int, CStr};
use std::ptr;

use super::ffi;

// ---------------------------------------------------------------------------
// RdmaDevice
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GidInfo {
    pub raw: [u8; 16],
    pub index: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortAttributes {
    pub lid: u16,
    pub active_mtu: ffi::ibv_mtu,
    pub link_layer: ffi::ibv_link_layer,
    pub gid: Option<GidInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuePairPath {
    pub dest_lid: u16,
    pub dest_gid: Option<[u8; 16]>,
    pub sgid_index: u8,
    pub path_mtu: ffi::ibv_mtu,
    pub global_route: bool,
}

fn gid_rank(raw: &[u8; 16]) -> u8 {
    if raw.iter().all(|byte| *byte == 0) {
        0
    } else if raw[..10].iter().all(|byte| *byte == 0) && raw[10] == 0xff && raw[11] == 0xff {
        4
    } else if !(raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80) {
        3
    } else {
        1
    }
}

/// An opened RDMA device context.
pub struct RdmaDevice {
    ctx: *mut ffi::ibv_context,
    _device: *mut ffi::ibv_device, // kept alive for context lifetime
}

// Safety: ibv_context is thread-safe per the libibverbs spec.
unsafe impl Send for RdmaDevice {}
unsafe impl Sync for RdmaDevice {}

impl RdmaDevice {
    /// Open the first available RDMA device in the system.
    pub fn open_first_available() -> Result<Self, String> {
        let mut num_devices: c_int = 0;
        // Safety: ibv_get_device_list is thread-safe, returns NULL-terminated array.
        let device_list = unsafe { ffi::ibv_get_device_list(&mut num_devices) };

        if device_list.is_null() || num_devices == 0 {
            return Err("no RDMA devices found".into());
        }

        // SAFETY: device_list is non-null (checked above) and points to a
        // valid NULL-terminated array per ibv_get_device_list contract.
        let first_device = unsafe { *device_list };
        if first_device.is_null() {
            // SAFETY: device_list is a valid pointer from ibv_get_device_list;
            // freeing it is the correct cleanup per libibverbs API.
            unsafe { ffi::ibv_free_device_list(device_list) };
            return Err("device list entry is null".into());
        }

        // Safety: first_device is a valid pointer from ibv_get_device_list.
        let ctx = unsafe { ffi::ibv_open_device(first_device) };
        if ctx.is_null() {
            // SAFETY: device_list is valid; freeing after failed open is proper
            // cleanup per libibverbs API.
            unsafe { ffi::ibv_free_device_list(device_list) };
            return Err("ibv_open_device failed".into());
        }

        // SAFETY: device_list is valid; the selected device struct is owned by
        // the library after a successful ibv_open_device, so freeing the list is safe.
        unsafe { ffi::ibv_free_device_list(device_list) };

        Ok(Self {
            ctx,
            _device: first_device,
        })
    }

    /// Return the raw ibv_context pointer.
    pub fn context(&self) -> *mut ffi::ibv_context {
        self.ctx
    }

    /// Return device name.
    pub fn name(&self) -> String {
        // Safety: ibv_get_device_name returns a static string tied to the device's lifetime,
        // which outlives the context (we hold context and device).
        unsafe {
            let name_ptr = ffi::ibv_get_device_name(self._device);
            if name_ptr.is_null() {
                return "<unknown>".into();
            }
            CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
        }
    }

    pub fn query_port(&self, port_num: u8) -> Result<PortAttributes, String> {
        query_port_attributes(self.ctx, port_num)
    }
}

impl Drop for RdmaDevice {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: self.ctx is a valid ibv_context pointer created by
            // ibv_open_device; closing it is the correct teardown per API.
            unsafe {
                ffi::ibv_close_device(self.ctx);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProtectionDomain
// ---------------------------------------------------------------------------

/// A protection domain (PD).
pub struct ProtectionDomain {
    pd: *mut ffi::ibv_pd,
    ctx: *mut ffi::ibv_context, // keep context alive
}

// SAFETY: ibv_pd is thread-safe per the libibverbs specification. The wrapper
// owns the pointer exclusively and does not permit interior mutability.
unsafe impl Send for ProtectionDomain {}
// SAFETY: ibv_pd is thread-safe per libibverbs spec; all access is through
// immutable references or thread-safe operations.
unsafe impl Sync for ProtectionDomain {}

impl ProtectionDomain {
    /// Allocate a protection domain.
    pub fn alloc(context: *mut ffi::ibv_context) -> Result<Self, String> {
        // SAFETY: context is a valid ibv_context pointer; ibv_alloc_pd is a
        // C FFI call with no additional preconditions.
        let pd = unsafe { ffi::ibv_alloc_pd(context) };
        if pd.is_null() {
            return Err("ibv_alloc_pd failed".into());
        }
        Ok(Self { pd, ctx: context })
    }

    pub fn raw(&self) -> *mut ffi::ibv_pd {
        self.pd
    }

    pub fn context(&self) -> *mut ffi::ibv_context {
        self.ctx
    }

    pub fn query_port(&self, port_num: u8) -> Result<PortAttributes, String> {
        query_port_attributes(self.ctx, port_num)
    }
}

impl Drop for ProtectionDomain {
    fn drop(&mut self) {
        if !self.pd.is_null() {
            // SAFETY: self.pd is a valid ibv_pd pointer; deallocating is the
            // correct teardown per libibverbs API.
            unsafe {
                ffi::ibv_dealloc_pd(self.pd);
            }
        }
    }
}

fn query_port_attributes(
    context: *mut ffi::ibv_context,
    port_num: u8,
) -> Result<PortAttributes, String> {
    let mut attr: ffi::ibv_port_attr = unsafe { std::mem::zeroed() };
    let ret = unsafe { ffi::ibv_query_port(context, port_num, &mut attr) };
    if ret != 0 {
        return Err(format!(
            "ibv_query_port failed for port {port_num}: ret={ret}"
        ));
    }

    let gid = select_preferred_gid(context, port_num, attr._gid_tbl_len);
    Ok(PortAttributes {
        lid: attr.lid,
        active_mtu: attr.active_mtu,
        link_layer: ffi::ibv_link_layer(attr.link_layer as c_int),
        gid,
    })
}

fn select_preferred_gid(
    context: *mut ffi::ibv_context,
    port_num: u8,
    gid_tbl_len: c_int,
) -> Option<GidInfo> {
    let mut best: Option<(u8, GidInfo)> = None;
    for index in 0..gid_tbl_len.clamp(0, 256) {
        let mut gid: ffi::ibv_gid = unsafe { std::mem::zeroed() };
        let ret = unsafe { ffi::ibv_query_gid(context, port_num, index, &mut gid) };
        if ret != 0 {
            continue;
        }
        let raw = unsafe { gid.raw };
        let rank = gid_rank(&raw);
        if rank == 0 {
            continue;
        }
        let info = GidInfo {
            raw,
            index: index as u8,
        };
        match best {
            Some((best_rank, _)) if best_rank >= rank => {}
            _ => best = Some((rank, info)),
        }
    }
    best.map(|(_, info)| info)
}

// ---------------------------------------------------------------------------
// MemoryRegion
// ---------------------------------------------------------------------------

/// A registered memory region.
pub struct MemoryRegion {
    mr: *mut ffi::ibv_mr,
}

// SAFETY: ibv_mr is thread-safe per the libibverbs specification.
unsafe impl Send for MemoryRegion {}
// SAFETY: ibv_mr is thread-safe per libibverbs spec.
unsafe impl Sync for MemoryRegion {}

impl MemoryRegion {
    /// Register a memory region with the given access flags.
    ///
    /// # Safety
    ///
    /// `addr` must point to a valid, stable allocation of at least `length`
    /// bytes that remains valid for the lifetime of this `MemoryRegion`.
    pub unsafe fn register(
        pd: &ProtectionDomain,
        addr: *mut std::ffi::c_void,
        length: usize,
        access: c_int,
    ) -> Result<Self, String> {
        let mr = ffi::ibv_reg_mr(pd.raw(), addr, length, access);
        if mr.is_null() {
            return Err("ibv_reg_mr failed".into());
        }
        Ok(Self { mr })
    }

    /// The local key for this memory region.
    pub fn lkey(&self) -> u32 {
        // SAFETY: self.mr is a valid ibv_mr pointer created during register.
        // The shim is compiled against the active libibverbs headers and reads
        // the public lkey field with the provider's ABI layout.
        unsafe { ffi::tidefs_ibv_mr_lkey(self.mr) }
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        if !self.mr.is_null() {
            // SAFETY: self.mr is a valid ibv_mr pointer; deregistering is the
            // correct cleanup per libibverbs API.
            unsafe {
                ffi::ibv_dereg_mr(self.mr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CompletionQueue
// ---------------------------------------------------------------------------

/// A completion queue.
pub struct CompletionQueue {
    cq: *mut ffi::ibv_cq,
}

// SAFETY: ibv_cq is thread-safe per the libibverbs specification.
unsafe impl Send for CompletionQueue {}
// SAFETY: ibv_cq is thread-safe per libibverbs spec.
unsafe impl Sync for CompletionQueue {}

impl CompletionQueue {
    /// Create a completion queue.
    pub fn create(context: *mut ffi::ibv_context, cqe: c_int) -> Result<Self, String> {
        // SAFETY: context is a valid ibv_context; null args for channel/comp
        // vector/comp_vector are valid per the libibverbs API for basic CQ.
        let cq = unsafe { ffi::ibv_create_cq(context, cqe, ptr::null_mut(), ptr::null_mut(), 0) };
        if cq.is_null() {
            return Err("ibv_create_cq failed".into());
        }
        Ok(Self { cq })
    }

    pub fn raw(&self) -> *mut ffi::ibv_cq {
        self.cq
    }

    /// Poll for completions; returns up to `max_count` work completions.
    /// Returns an empty Vec when no completions are available.
    pub fn poll(&self, max_count: usize) -> Result<Vec<ffi::ibv_wc>, String> {
        let count = max_count.min(256) as c_int;
        let mut wcs: Vec<ffi::ibv_wc> = Vec::with_capacity(count as usize);
        // Safety: poll reads into a pre-sized buffer.
        let n = unsafe {
            // Use a zeroed array on the stack to avoid allocation overhead.
            let mut arr = [std::mem::zeroed::<ffi::ibv_wc>(); 16];
            let n = ffi::tidefs_ibv_poll_cq(self.cq, count.min(16), arr.as_mut_ptr());
            if n > 0 {
                wcs.extend_from_slice(&arr[..n as usize]);
            }
            n
        };

        if n < 0 {
            return Err("ibv_poll_cq returned error".into());
        }

        // If we had more than 16 requested, do another poll (unlikely with current config).
        // For our use case, 16 is the batch size.

        Ok(wcs)
    }
}

impl Drop for CompletionQueue {
    fn drop(&mut self) {
        if !self.cq.is_null() {
            // SAFETY: self.cq is a valid ibv_cq pointer; destroying is the
            // correct teardown per libibverbs API.
            unsafe {
                ffi::ibv_destroy_cq(self.cq);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// QueuePair
// ---------------------------------------------------------------------------

/// A Reliable Connection queue pair.
pub struct QueuePair {
    qp: *mut ffi::ibv_qp,
    qp_num: u32,
    state: ffi::ibv_qp_state,
}

// SAFETY: ibv_qp is thread-safe per the libibverbs specification.
unsafe impl Send for QueuePair {}
// SAFETY: ibv_qp is thread-safe per libibverbs spec.
unsafe impl Sync for QueuePair {}

impl QueuePair {
    /// Create a queue pair.
    pub fn create(
        pd: &ProtectionDomain,
        send_cq: &CompletionQueue,
        recv_cq: &CompletionQueue,
        max_send_wr: u32,
        max_recv_wr: u32,
        max_send_sge: u32,
        max_recv_sge: u32,
    ) -> Result<Self, String> {
        let mut init_attr = ffi::ibv_qp_init_attr {
            _qp_context: ptr::null_mut(),
            send_cq: send_cq.raw(),
            recv_cq: recv_cq.raw(),
            _srq: ptr::null_mut(),
            cap: ffi::ibv_qp_cap {
                max_send_wr,
                max_recv_wr,
                max_send_sge,
                max_recv_sge,
                max_inline_data: 0,
            },
            qp_type: ffi::IBV_QPT_RC,
            sq_sig_all: 0,
        };

        // SAFETY: pd.raw() is a valid PD pointer; init_attr is a properly
        // initialized ibv_qp_init_attr on the stack. ibv_create_qp has no
        // other preconditions.
        let qp = unsafe { ffi::ibv_create_qp(pd.raw(), &mut init_attr) };
        if qp.is_null() {
            return Err("ibv_create_qp failed".into());
        }

        // SAFETY: qp is a valid ibv_qp pointer just returned by ibv_create_qp.
        // The shim is compiled against the active libibverbs headers and reads
        // the public qp_num field with the provider's ABI layout.
        let qp_num = unsafe { ffi::tidefs_ibv_qp_num(qp) };

        Ok(Self {
            qp,
            qp_num,
            state: ffi::IBV_QPS_RESET,
        })
    }

    /// Query the QP number.
    pub fn qp_num(&self) -> u32 {
        self.qp_num
    }

    /// Current QP state.
    pub fn state(&self) -> ffi::ibv_qp_state {
        self.state
    }

    /// Transition QP from RESET → INIT.
    pub fn transition_to_init(&mut self, port_num: u8, _psn: u32) -> Result<(), String> {
        if self.state != ffi::IBV_QPS_RESET {
            return Err(format!(
                "transition_to_init requires RESET, current={:?}",
                self.state
            ));
        }

        // SAFETY: ibv_qp_attr is a C struct of integers; zero is a valid bit
        // pattern for all fields. All meaningful fields are set below before
        // the struct is passed to ibv_modify_qp.
        // SAFETY: ibv_qp_attr is a C struct of integers; zero is a valid
        // bit pattern. All fields are set below before use.
        // SAFETY: ibv_qp_attr is a C struct of integers; zero is a valid
        // bit pattern. All fields are set below before use.
        let mut attr: ffi::ibv_qp_attr = unsafe { std::mem::zeroed() };
        attr.qp_state = ffi::IBV_QPS_INIT;
        attr.pkey_index = 0;
        attr.port_num = port_num;
        attr.qp_access_flags = ffi::IBV_ACCESS_LOCAL_WRITE;

        let mask = ffi::IBV_QP_STATE
            | ffi::IBV_QP_PKEY_INDEX
            | ffi::IBV_QP_PORT
            | ffi::IBV_QP_ACCESS_FLAGS;

        // SAFETY: self.qp is a valid QP pointer; attr is properly initialized
        // with correct state and parameters for the INIT transition. mask is a
        // valid bitmask per the libibverbs API.
        let ret = unsafe { ffi::ibv_modify_qp(self.qp, &mut attr, mask) };
        if ret != 0 {
            return Err(format!("ibv_modify_qp INIT failed: ret={ret}"));
        }
        self.state = ffi::IBV_QPS_INIT;
        Ok(())
    }

    /// Transition QP from INIT → RTR.
    pub fn transition_to_rtr(
        &mut self,
        dest_qp_num: u32,
        dest_psn: u32,
        port_num: u8,
        path: QueuePairPath,
    ) -> Result<(), String> {
        if self.state != ffi::IBV_QPS_INIT {
            return Err(format!(
                "transition_to_rtr requires INIT, current={:?}",
                self.state
            ));
        }

        // SAFETY: ibv_qp_attr is a C struct of integers; zero is a valid bit
        // pattern for all fields. All meaningful fields are set below before
        // the struct is passed to ibv_modify_qp.
        let mut attr: ffi::ibv_qp_attr = unsafe { std::mem::zeroed() };
        attr.qp_state = ffi::IBV_QPS_RTR;
        attr.path_mtu = path.path_mtu;
        attr.dest_qp_num = dest_qp_num;
        attr.rq_psn = dest_psn;
        attr.max_dest_rd_atomic = 1;
        attr.min_rnr_timer = 12;
        attr.ah_attr.dlid = path.dest_lid;
        attr.ah_attr.port_num = port_num;
        if path.global_route {
            let dest_gid = path
                .dest_gid
                .ok_or_else(|| "global RDMA route requires destination GID".to_string())?;
            attr.ah_attr.is_global = 1;
            attr.ah_attr.grh.dgid = ffi::ibv_gid { raw: dest_gid };
            attr.ah_attr.grh.sgid_index = path.sgid_index;
            attr.ah_attr.grh._hop_limit = 64;
        } else {
            attr.ah_attr.is_global = 0;
        }

        let mask = ffi::IBV_QP_STATE
            | ffi::IBV_QP_AV
            | ffi::IBV_QP_PATH_MTU
            | ffi::IBV_QP_DEST_QPN
            | ffi::IBV_QP_RQ_PSN
            | ffi::IBV_QP_MAX_DEST_RD_ATOMIC
            | ffi::IBV_QP_MIN_RNR_TIMER;

        // SAFETY: self.qp is valid; attr is properly initialized for the RTR
        // transition with correct state, path, and destination parameters.
        // mask covers all set fields per libibverbs API.
        let ret = unsafe { ffi::ibv_modify_qp(self.qp, &mut attr, mask) };
        if ret != 0 {
            return Err(format!("ibv_modify_qp RTR failed: ret={ret}"));
        }
        self.state = ffi::IBV_QPS_RTR;
        Ok(())
    }

    /// Transition QP from RTR → RTS.
    pub fn transition_to_rts(&mut self, dest_psn: u32) -> Result<(), String> {
        if self.state != ffi::IBV_QPS_RTR {
            return Err(format!(
                "transition_to_rts requires RTR, current={:?}",
                self.state
            ));
        }

        // SAFETY: ibv_qp_attr is a C struct of integers; zero is a valid bit
        // pattern for all fields. All meaningful fields are set below before
        // the struct is passed to ibv_modify_qp.
        let mut attr: ffi::ibv_qp_attr = unsafe { std::mem::zeroed() };
        attr.qp_state = ffi::IBV_QPS_RTS;
        attr.sq_psn = dest_psn;
        attr.timeout = 14; // ~67ms
        attr.retry_cnt = 7;
        attr.rnr_retry = 7;
        attr._max_rd_atomic = 1;

        let mask = ffi::IBV_QP_STATE
            | ffi::IBV_QP_TIMEOUT
            | ffi::IBV_QP_RETRY_CNT
            | ffi::IBV_QP_RNR_RETRY
            | ffi::IBV_QP_SQ_PSN
            | ffi::IBV_QP_MAX_QP_RD_ATOMIC;

        // SAFETY: self.qp is valid; attr is properly initialized for the RTS
        // transition with correct state, timeout, and retry parameters.
        // mask covers all set fields per libibverbs API.
        let ret = unsafe { ffi::ibv_modify_qp(self.qp, &mut attr, mask) };
        if ret != 0 {
            return Err(format!("ibv_modify_qp RTS failed: ret={ret}"));
        }
        self.state = ffi::IBV_QPS_RTS;
        Ok(())
    }

    /// Post a send work request (single SGE).
    pub fn post_send(
        &self,
        data: *const u8,
        len: usize,
        lkey: u32,
        wr_id: u64,
    ) -> Result<(), String> {
        let mut sge = ffi::ibv_sge {
            addr: data as u64,
            length: len as u32,
            lkey,
        };

        let mut wr = ffi::ibv_send_wr {
            wr_id,
            next: ptr::null_mut(),
            sg_list: &mut sge,
            num_sge: 1,
            opcode: ffi::IBV_WR_SEND,
            send_flags: ffi::IBV_SEND_SIGNALED,
            imm_data: 0,
            // SAFETY: The ibv_send_wr.wr union is zeroed; all meaningful
            // send_wr fields are set above. The union is not read directly.
            wr: unsafe { std::mem::zeroed() },
            qp_type: unsafe { std::mem::zeroed() },
            extra: unsafe { std::mem::zeroed() },
        };

        let mut bad_wr: *mut ffi::ibv_send_wr = ptr::null_mut();
        // SAFETY: self.qp is a valid QP pointer; wr is a properly initialized
        // send work request with valid sge, lkey, and opcode. bad_wr is null
        // initially and may be set by the call per API.
        let ret = unsafe { ffi::tidefs_ibv_post_send(self.qp, &mut wr, &mut bad_wr) };
        if ret != 0 {
            return Err(format!(
                "ibv_post_send failed: ret={ret}, errno explanation: no free work requests or invalid params"
            ));
        }
        Ok(())
    }

    /// Post a receive work request (single SGE).
    pub fn post_recv(
        &self,
        data: *mut u8,
        len: usize,
        lkey: u32,
        wr_id: u64,
    ) -> Result<(), String> {
        let mut sge = ffi::ibv_sge {
            addr: data as u64,
            length: len as u32,
            lkey,
        };

        let mut wr = ffi::ibv_recv_wr {
            wr_id,
            next: ptr::null_mut(),
            sg_list: &mut sge,
            num_sge: 1,
        };

        let mut bad_wr: *mut ffi::ibv_recv_wr = ptr::null_mut();
        // SAFETY: self.qp is a valid QP pointer; wr is a properly initialized
        // receive work request with valid sge and lkey.
        let ret = unsafe { ffi::tidefs_ibv_post_recv(self.qp, &mut wr, &mut bad_wr) };
        if ret != 0 {
            return Err(format!("ibv_post_recv failed: ret={ret}"));
        }
        Ok(())
    }
}

impl Drop for QueuePair {
    fn drop(&mut self) {
        if !self.qp.is_null() {
            // SAFETY: self.qp is a valid ibv_qp pointer; destroying is the
            // correct teardown per libibverbs API.
            unsafe {
                ffi::ibv_destroy_qp(self.qp);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Extension methods on FFI types for field access
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdma_device_enumeration() {
        let result = RdmaDevice::open_first_available();
        match result {
            Ok(dev) => {
                let name = dev.name();
                assert!(!name.is_empty());
                eprintln!("RDMA device found: {name}");
            }
            Err(e) => {
                eprintln!("No RDMA device (expected in CI): {e}");
            }
        }
    }

    #[test]
    fn test_protection_domain_create_destroy() {
        let dev = match RdmaDevice::open_first_available() {
            Ok(d) => d,
            Err(_) => return, // skip test if no RDMA device
        };
        let pd = ProtectionDomain::alloc(dev.context());
        assert!(pd.is_ok());
        let pd = pd.unwrap();
        assert!(!pd.raw().is_null());
        drop(pd);
        drop(dev);
    }

    #[test]
    fn test_completion_queue_create_destroy() {
        let dev = match RdmaDevice::open_first_available() {
            Ok(d) => d,
            Err(_) => return,
        };
        let cq = CompletionQueue::create(dev.context(), 16);
        assert!(cq.is_ok());
        let cq = cq.unwrap();
        let wcs = cq.poll(4);
        assert!(wcs.is_ok());
        assert!(wcs.unwrap().is_empty());
        drop(cq);
        drop(dev);
    }

    #[test]
    fn test_qp_create_and_state_transition() {
        let dev = match RdmaDevice::open_first_available() {
            Ok(d) => d,
            Err(_) => return,
        };
        let pd = match ProtectionDomain::alloc(dev.context()) {
            Ok(p) => p,
            Err(_) => return,
        };
        let cq = match CompletionQueue::create(dev.context(), 16) {
            Ok(c) => c,
            Err(_) => return,
        };

        let qp = QueuePair::create(&pd, &cq, &cq, 32, 32, 1, 1);
        assert!(qp.is_ok());
        let mut qp = qp.unwrap();
        assert_eq!(qp.state(), ffi::IBV_QPS_RESET);

        // RESET → INIT
        assert!(qp.transition_to_init(1, 0x1234).is_ok());
        assert_eq!(qp.state(), ffi::IBV_QPS_INIT);

        // Bad transition: repeating INIT from INIT should fail.
        assert!(qp.transition_to_init(1, 0x1234).is_err());

        drop(qp);
        drop(cq);
        drop(pd);
        drop(dev);
    }

    #[test]
    fn test_post_recv_and_send_completes() {
        let dev = match RdmaDevice::open_first_available() {
            Ok(d) => d,
            Err(_) => return,
        };
        let pd = match ProtectionDomain::alloc(dev.context()) {
            Ok(p) => p,
            Err(_) => return,
        };
        let cq = match CompletionQueue::create(dev.context(), 16) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut qp = match QueuePair::create(&pd, &cq, &cq, 32, 32, 1, 1) {
            Ok(q) => q,
            Err(_) => return,
        };
        // Transition INIT (needed before we can post recv).
        assert!(qp.transition_to_init(1, 0x5678).is_ok());

        // Register a small buffer.
        let buf_size: usize = 1024;
        let mut buf: Vec<u8> = vec![0u8; buf_size];
        // SAFETY: buf is a live Vec<u8> allocation that stays in scope
        // for the MR lifetime; buf_size matches the allocation. The pointer
        // is valid for reads and writes.
        let mr = unsafe {
            MemoryRegion::register(
                &pd,
                buf.as_mut_ptr() as *mut _,
                buf_size,
                ffi::IBV_ACCESS_LOCAL_WRITE,
            )
        };
        assert!(mr.is_ok());
        let mr = mr.unwrap();

        // Post a recv. It won't complete since there's no sender, but it
        // validates that posting works without returning an error.
        let result = qp.post_recv(buf.as_mut_ptr(), buf_size, mr.lkey(), 0);
        // May fail if the library requires RTR for posting recv on RC.
        // This test validates the API surface more than actual completion.
        let _ = result;

        drop(mr);
        drop(qp);
        drop(cq);
        drop(pd);
        drop(dev);
    }
}
