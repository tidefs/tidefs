// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! On-disk layout specification for the V1 locator table.
//!
//! This module documents the binary format of locator table blobs
//! stored in the object store.  Constants are re-exported from
//! [`crate::locator_table_types`] for discoverability.

use crate::locator_table_types;

/// The spec version identifier for this on-disk format.
pub const SPEC: &str = locator_table_types::LOCATOR_TABLE_SPEC;

/// Magic bytes at the start of every locator-table page.
pub const PAGE_MAGIC: [u8; 4] = locator_table_types::LOCATOR_TABLE_PAGE_MAGIC;

/// Default page size in bytes.
pub const DEFAULT_PAGE_SIZE: usize = locator_table_types::LOCATOR_TABLE_DEFAULT_PAGE_SIZE;

/// Fixed on-disk size of one `ExtentLocatorValueV1` in bytes.
pub const VALUE_V1_FIXED_SIZE: usize = locator_table_types::LOCATOR_VALUE_V1_FIXED_SIZE;

/// Size of a page header in bytes.
pub const PAGE_HEADER_SIZE: usize = locator_table_types::LOCATOR_TABLE_PAGE_HEADER_SIZE;
