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
    decode_label, encode_label, features, seal_label, verify_label_checksum,
    DeviceClass as LabelDeviceClass, LabelError, PoolLabelV1, PoolRedundancyPolicy,
    PoolState as LabelPoolState, POOL_LABEL_MAGIC, POOL_LABEL_SIZE, POOL_LABEL_V1_EXT_WIRE_SIZE,
    POOL_LABEL_V1_WIRE_SIZE, POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE, POOL_NAME_MAX,
};
