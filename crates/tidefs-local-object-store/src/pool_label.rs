// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Bridge module that re-exports the on-disk pool label types from
//! `tidefs-types-pool-label-core`.
//!
//! This module exists so that `PoolImporter`, `PoolExporter`, and
//! `DeviceManager` can import label types from a single crate.
//!
//! The PoolLabelV1 on-device label format, PoolState/DeviceClass enums,
//! and BLAKE3-256 encode/decode/checksum routines are implemented in
//! `tidefs-types-pool-label-core`.

pub use tidefs_types_pool_label_core::{
    decode_device_layout_v1_bytes, decode_label, decode_pool_lifecycle_v1,
    decode_topology_roster_v1, encode_label, encode_label_with_all_extensions,
    encode_label_with_device_layout, encode_label_with_extensions, features,
    pool_lifecycle_v1_wire_size, seal_label, seal_label_with_all_extensions,
    seal_label_with_device_layout, seal_label_with_extensions, verify_label_checksum,
    DeviceClass as LabelDeviceClass, LabelError, PoolLabelV1, PoolLifecycleKindV1,
    PoolLifecycleRecordV1, PoolRedundancyPolicy, PoolState as LabelPoolState, PoolTopologyRosterV1,
    POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE, POOL_LABEL_LIFECYCLE_V1_CHECKSUM_SIZE,
    POOL_LABEL_LIFECYCLE_V1_HEADER_SIZE, POOL_LABEL_MAGIC, POOL_LABEL_SIZE,
    POOL_LABEL_TOPOLOGY_ROSTER_V1_CHECKSUM_SIZE, POOL_LABEL_TOPOLOGY_ROSTER_V1_HEADER_SIZE,
    POOL_LABEL_TOPOLOGY_ROSTER_V1_MEMBER_SIZE, POOL_LABEL_TOPOLOGY_ROSTER_V1_OFFSET,
    POOL_LABEL_V1_WIRE_SIZE, POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE, POOL_NAME_MAX,
};
