// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(unsafe_code)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::ffi::{c_int, c_uint, c_void};
use std::mem::ManuallyDrop;

// ---------------------------------------------------------------------------
// Opaque handle types
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct ibv_device {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_context {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_pd {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_mr {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_cq {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_qp {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_comp_channel {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_ah {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ibv_mw {
    _private: [u8; 0],
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const IBV_ACCESS_LOCAL_WRITE: c_int = 1;
pub const IBV_ACCESS_REMOTE_WRITE: c_int = 2;
pub const IBV_ACCESS_REMOTE_READ: c_int = 4;
pub const IBV_ACCESS_REMOTE_ATOMIC: c_int = 8;

pub const IBV_QPT_RC: ibv_qp_type = ibv_qp_type(2);

pub const IBV_QPS_RESET: ibv_qp_state = ibv_qp_state(0);
pub const IBV_QPS_INIT: ibv_qp_state = ibv_qp_state(1);
pub const IBV_QPS_RTR: ibv_qp_state = ibv_qp_state(2);
pub const IBV_QPS_RTS: ibv_qp_state = ibv_qp_state(3);
pub const IBV_QPS_SQD: ibv_qp_state = ibv_qp_state(4);
pub const IBV_QPS_SQE: ibv_qp_state = ibv_qp_state(5);
pub const IBV_QPS_ERR: ibv_qp_state = ibv_qp_state(6);

pub const IBV_SEND_FENCE: c_uint = 1 << 0;
pub const IBV_SEND_SIGNALED: c_uint = 1 << 1;
pub const IBV_SEND_SOLICITED: c_uint = 1 << 2;
pub const IBV_SEND_INLINE: c_uint = 1 << 3;
pub const IBV_SEND_IP_CSUM: c_uint = 1 << 4;

pub const IBV_WC_SEND: ibv_wc_opcode = ibv_wc_opcode(0);
pub const IBV_WC_RDMA_WRITE: ibv_wc_opcode = ibv_wc_opcode(1);
pub const IBV_WC_RDMA_READ: ibv_wc_opcode = ibv_wc_opcode(2);
pub const IBV_WC_RECV: ibv_wc_opcode = ibv_wc_opcode(128);
pub const IBV_WC_RECV_RDMA_WITH_IMM: ibv_wc_opcode = ibv_wc_opcode(129);

pub const IBV_WC_SUCCESS: ibv_wc_status = ibv_wc_status(0);

pub const IBV_WR_RDMA_WRITE: ibv_wr_opcode = ibv_wr_opcode(0);
pub const IBV_WR_RDMA_WRITE_WITH_IMM: ibv_wr_opcode = ibv_wr_opcode(1);
pub const IBV_WR_SEND: ibv_wr_opcode = ibv_wr_opcode(2);
pub const IBV_WR_SEND_WITH_IMM: ibv_wr_opcode = ibv_wr_opcode(3);
pub const IBV_WR_RDMA_READ: ibv_wr_opcode = ibv_wr_opcode(4);

pub const IBV_QP_STATE: c_int = 1;
pub const IBV_QP_CUR_STATE: c_int = 2;
pub const IBV_QP_ACCESS_FLAGS: c_int = 8;
pub const IBV_QP_PKEY_INDEX: c_int = 16;
pub const IBV_QP_PORT: c_int = 32;
pub const IBV_QP_QKEY: c_int = 64;
pub const IBV_QP_AV: c_int = 128;
pub const IBV_QP_PATH_MTU: c_int = 256;
pub const IBV_QP_TIMEOUT: c_int = 512;
pub const IBV_QP_RETRY_CNT: c_int = 1024;
pub const IBV_QP_RNR_RETRY: c_int = 2048;
pub const IBV_QP_RQ_PSN: c_int = 4096;
pub const IBV_QP_MAX_QP_RD_ATOMIC: c_int = 8192;
pub const IBV_QP_ALT_PATH: c_int = 1 << 14;
pub const IBV_QP_MIN_RNR_TIMER: c_int = 1 << 15;
pub const IBV_QP_SQ_PSN: c_int = 1 << 16;
pub const IBV_QP_MAX_DEST_RD_ATOMIC: c_int = 1 << 17;
pub const IBV_QP_PATH_MIG_STATE: c_int = 1 << 18;
pub const IBV_QP_CAP: c_int = 1 << 19;
pub const IBV_QP_DEST_QPN: c_int = 1 << 20;

pub const IBV_MTU_256: ibv_mtu = ibv_mtu(1);
pub const IBV_MTU_512: ibv_mtu = ibv_mtu(2);
pub const IBV_MTU_1024: ibv_mtu = ibv_mtu(3);
pub const IBV_MTU_2048: ibv_mtu = ibv_mtu(4);
pub const IBV_MTU_4096: ibv_mtu = ibv_mtu(5);

pub const IBV_LINK_LAYER_UNSPECIFIED: ibv_link_layer = ibv_link_layer(0);
pub const IBV_LINK_LAYER_INFINIBAND: ibv_link_layer = ibv_link_layer(1);
pub const IBV_LINK_LAYER_ETHERNET: ibv_link_layer = ibv_link_layer(2);

// ---------------------------------------------------------------------------
// Newtype wrappers (purposefully matching C names for ABI clarity)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ibv_qp_type(pub c_int);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ibv_qp_state(pub c_int);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ibv_wc_opcode(pub c_int);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ibv_wr_opcode(pub c_int);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ibv_wc_status(pub c_int);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ibv_mtu(pub c_int);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ibv_link_layer(pub c_int);

// ---------------------------------------------------------------------------
// SGE and work completions
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_sge {
    pub addr: u64,
    pub length: u32,
    pub lkey: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_wc {
    pub wr_id: u64,
    pub status: ibv_wc_status,
    pub opcode: ibv_wc_opcode,
    pub vendor_err: u32,
    pub byte_len: u32,
    pub qp_num: u32,
    pub src_qp: u32,
    pub wc_flags: c_int,
    pub pkey_index: u16,
    pub slid: u16,
    pub sl: u8,
    pub dlid_path_bits: u8,
}

// ---------------------------------------------------------------------------
// Work request types
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_send_wr_rdma {
    pub remote_addr: u64,
    pub rkey: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_send_wr_atomic {
    pub remote_addr: u64,
    pub compare_add: u64,
    pub swap: u64,
    pub rkey: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_send_wr_ud {
    pub ah: *mut ibv_ah,
    pub remote_qpn: u32,
    pub remote_qkey: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ibv_send_wr_union {
    pub rdma: ManuallyDrop<ibv_send_wr_rdma>,
    pub atomic: ManuallyDrop<ibv_send_wr_atomic>,
    pub ud: ManuallyDrop<ibv_send_wr_ud>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_send_wr_xrc {
    pub remote_srqn: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ibv_send_wr_qp_type {
    pub xrc: ManuallyDrop<ibv_send_wr_xrc>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_mw_bind_info {
    pub mr: *mut ibv_mr,
    pub addr: u64,
    pub length: u64,
    pub mw_access_flags: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_send_wr_bind_mw {
    pub mw: *mut ibv_mw,
    pub rkey: u32,
    pub bind_info: ibv_mw_bind_info,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ibv_send_wr_tso {
    pub hdr: *mut c_void,
    pub hdr_sz: u16,
    pub mss: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ibv_send_wr_extra {
    pub bind_mw: ManuallyDrop<ibv_send_wr_bind_mw>,
    pub tso: ManuallyDrop<ibv_send_wr_tso>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_send_wr {
    pub wr_id: u64,
    pub next: *mut ibv_send_wr,
    pub sg_list: *mut ibv_sge,
    pub num_sge: c_int,
    pub opcode: ibv_wr_opcode,
    pub send_flags: c_uint,
    pub imm_data: u32,
    pub wr: ibv_send_wr_union,
    pub qp_type: ibv_send_wr_qp_type,
    pub extra: ibv_send_wr_extra,
}

impl std::fmt::Debug for ibv_send_wr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_send_wr")
            .field("wr_id", &self.wr_id)
            .field("num_sge", &self.num_sge)
            .field("send_flags", &self.send_flags)
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ibv_recv_wr {
    pub wr_id: u64,
    pub next: *mut ibv_recv_wr,
    pub sg_list: *mut ibv_sge,
    pub num_sge: c_int,
}

// ---------------------------------------------------------------------------
// Device/port attributes
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_device_attr {
    pub _fw_ver: [u8; 64],
    pub _node_guid: u64,
    pub _sys_image_guid: u64,
    pub max_mr_size: u64,
    pub _page_size_cap: u64,
    pub _vendor_id: u32,
    pub _vendor_part_id: u32,
    pub _hw_ver: u32,
    pub max_qp: c_int,
    pub max_qp_wr: c_int,
    pub _device_cap_flags: c_int,
    pub max_sge: c_int,
    pub _max_sge_rd: c_int,
    pub max_cq: c_int,
    pub max_cqe: c_int,
    pub max_mr: c_int,
    pub max_pd: c_int,
    pub _max_qp_rd_atom: c_int,
    pub _max_ee_rd_atom: c_int,
    pub _max_res_rd_atom: c_int,
    pub _max_qp_init_rd_atom: c_int,
    pub _max_ee_init_rd_atom: c_int,
    pub _atomic_cap: c_int,
    pub _max_ee: c_int,
    pub _max_rdd: c_int,
    pub _max_mw: c_int,
    pub _max_raw_ipv6_qp: c_int,
    pub _max_raw_ethy_qp: c_int,
    pub _max_mcast_grp: c_int,
    pub _max_mcast_qp_attach: c_int,
    pub _max_total_mcast_qp_attach: c_int,
    pub _max_ah: c_int,
    pub _max_fmr: c_int,
    pub _max_map_per_fmr: c_int,
    pub _max_srq: c_int,
    pub _max_srq_wr: c_int,
    pub _max_srq_sge: c_int,
    pub _max_pkeys: u16,
    pub _local_ca_ack_delay: u8,
    pub phys_port_cnt: u8,
}

impl std::fmt::Debug for ibv_device_attr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_device_attr")
            .field("max_qp", &self.max_qp)
            .field("max_cq", &self.max_cq)
            .field("phys_port_cnt", &self.phys_port_cnt)
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_port_attr {
    pub state: c_int,
    pub max_mtu: ibv_mtu,
    pub active_mtu: ibv_mtu,
    pub _gid_tbl_len: c_int,
    pub _port_cap_flags: u32,
    pub max_msg_sz: u32,
    pub _bad_pkey_cntr: u32,
    pub _qkey_viol_cntr: u32,
    pub _pkey_tbl_len: u16,
    pub lid: u16,
    pub _sm_lid: u16,
    pub _lmc: u8,
    pub _max_vl_num: u8,
    pub _sm_sl: u8,
    pub _subnet_timeout: u8,
    pub _init_type_reply: u8,
    pub _active_width: u8,
    pub _active_speed: u8,
    pub _phys_state: u8,
    pub link_layer: u8,
    pub _flags: u8,
}

impl std::fmt::Debug for ibv_port_attr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_port_attr")
            .field("state", &self.state)
            .field("lid", &self.lid)
            .field("max_msg_sz", &self.max_msg_sz)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// QP init attributes, QP attributes
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_qp_cap {
    pub max_send_wr: u32,
    pub max_recv_wr: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub max_inline_data: u32,
}

impl std::fmt::Debug for ibv_qp_cap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_qp_cap")
            .field("max_send_wr", &self.max_send_wr)
            .field("max_recv_wr", &self.max_recv_wr)
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_qp_init_attr {
    pub _qp_context: *mut c_void,
    pub send_cq: *mut ibv_cq,
    pub recv_cq: *mut ibv_cq,
    pub _srq: *mut c_void,
    pub cap: ibv_qp_cap,
    pub qp_type: ibv_qp_type,
    pub sq_sig_all: c_int,
}

impl std::fmt::Debug for ibv_qp_init_attr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_qp_init_attr")
            .field("qp_type", &self.qp_type)
            .field("cap", &self.cap)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Address handle, global route, GID
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_gid_global {
    pub _subnet_prefix: u64,
    pub _interface_id: u64,
}

impl std::fmt::Debug for ibv_gid_global {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_gid_global").finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ibv_gid {
    pub raw: [u8; 16],
    pub _global: std::mem::ManuallyDrop<ibv_gid_global>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_global_route {
    pub dgid: ibv_gid,
    pub _flow_label: u32,
    pub sgid_index: u8,
    pub _hop_limit: u8,
    pub _traffic_class: u8,
}

impl std::fmt::Debug for ibv_global_route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_global_route")
            .field("sgid_index", &self.sgid_index)
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_ah_attr {
    pub grh: ibv_global_route,
    pub dlid: u16,
    pub sl: u8,
    pub _src_path_bits: u8,
    pub _static_rate: u8,
    pub is_global: u8,
    pub port_num: u8,
}

impl std::fmt::Debug for ibv_ah_attr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_ah_attr")
            .field("dlid", &self.dlid)
            .field("sl", &self.sl)
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_qp_attr {
    pub qp_state: ibv_qp_state,
    pub cur_qp_state: ibv_qp_state,
    pub path_mtu: ibv_mtu,
    pub _path_mig_state: c_int,
    pub _qkey: u32,
    pub rq_psn: u32,
    pub sq_psn: u32,
    pub dest_qp_num: u32,
    pub qp_access_flags: c_int,
    pub cap: ibv_qp_cap,
    pub ah_attr: ibv_ah_attr,
    pub _alt_ah_attr: ibv_ah_attr,
    pub pkey_index: u16,
    pub _alt_pkey_index: u16,
    pub _en_sqd_async_notify: u8,
    pub _sq_draining: u8,
    pub _max_rd_atomic: u8,
    pub max_dest_rd_atomic: u8,
    pub min_rnr_timer: u8,
    pub port_num: u8,
    pub timeout: u8,
    pub retry_cnt: u8,
    pub rnr_retry: u8,
    pub _alt_port_num: u8,
    pub _alt_timeout: u8,
    pub _rate_limit: u32,
}

impl std::fmt::Debug for ibv_qp_attr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ibv_qp_attr")
            .field("qp_state", &self.qp_state)
            .field("dest_qp_num", &self.dest_qp_num)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Extern "C" function declarations
// ---------------------------------------------------------------------------

extern "C" {
    pub fn ibv_get_device_list(num_devices: *mut c_int) -> *mut *mut ibv_device;
    pub fn ibv_free_device_list(list: *mut *mut ibv_device);
    pub fn ibv_get_device_name(device: *mut ibv_device) -> *const std::ffi::c_char;
    pub fn ibv_open_device(device: *mut ibv_device) -> *mut ibv_context;
    pub fn ibv_close_device(context: *mut ibv_context) -> c_int;
    pub fn ibv_query_device(context: *mut ibv_context, attr: *mut ibv_device_attr) -> c_int;
    pub fn ibv_query_port(
        context: *mut ibv_context,
        port_num: u8,
        attr: *mut ibv_port_attr,
    ) -> c_int;
    pub fn ibv_query_gid(
        context: *mut ibv_context,
        port_num: u8,
        index: c_int,
        gid: *mut ibv_gid,
    ) -> c_int;
    pub fn ibv_alloc_pd(context: *mut ibv_context) -> *mut ibv_pd;
    pub fn ibv_dealloc_pd(pd: *mut ibv_pd) -> c_int;
    pub fn ibv_reg_mr(
        pd: *mut ibv_pd,
        addr: *mut c_void,
        length: usize,
        access: c_int,
    ) -> *mut ibv_mr;
    pub fn ibv_dereg_mr(mr: *mut ibv_mr) -> c_int;
    pub fn tidefs_ibv_mr_lkey(mr: *mut ibv_mr) -> u32;
    pub fn ibv_create_cq(
        context: *mut ibv_context,
        cqe: c_int,
        cq_context: *mut c_void,
        channel: *mut ibv_comp_channel,
        comp_vector: c_int,
    ) -> *mut ibv_cq;
    pub fn ibv_destroy_cq(cq: *mut ibv_cq) -> c_int;
    pub fn ibv_create_qp(pd: *mut ibv_pd, attr: *mut ibv_qp_init_attr) -> *mut ibv_qp;
    pub fn ibv_modify_qp(qp: *mut ibv_qp, attr: *mut ibv_qp_attr, attr_mask: c_int) -> c_int;
    pub fn ibv_destroy_qp(qp: *mut ibv_qp) -> c_int;
    pub fn tidefs_ibv_qp_num(qp: *mut ibv_qp) -> u32;
    pub fn ibv_query_qp(
        qp: *mut ibv_qp,
        attr: *mut ibv_qp_attr,
        attr_mask: c_int,
        init_attr: *mut ibv_qp_init_attr,
    ) -> c_int;
    pub fn tidefs_ibv_post_send(
        qp: *mut ibv_qp,
        wr: *mut ibv_send_wr,
        bad_wr: *mut *mut ibv_send_wr,
    ) -> c_int;
    pub fn tidefs_ibv_post_recv(
        qp: *mut ibv_qp,
        wr: *mut ibv_recv_wr,
        bad_wr: *mut *mut ibv_recv_wr,
    ) -> c_int;
    pub fn tidefs_ibv_poll_cq(cq: *mut ibv_cq, num_entries: c_int, wc: *mut ibv_wc) -> c_int;
}
