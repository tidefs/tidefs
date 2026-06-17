//! Userspace validation support for TideFS.
//!
//! This crate keeps helpers that run product behavior directly or summarize
//! ephemeral validation output. Repository-tracked validation-output authority
//! is intentionally not part of TideFS.

pub mod allocator_space_accounting_validation;
#[cfg(feature = "transport")]
pub mod cache_coherency;
pub mod carrier_comparison;
pub mod concurrent_ops;
pub mod crash_recovery;
pub mod evidence_artifact_manifest;
pub mod failure_blocker_triage;
pub mod fault_injection_scenario_catalog;
pub mod fio_integrity;
pub mod fuse_inode_metadata_validation;
pub mod fuse_read_validation;
pub mod fuse_vm_test;
pub mod host_validation_queue;
pub mod kernel_dir_namespace_validation;
pub mod kernel_pagecache_writeback_validation;
pub mod kernel_readdir_validation;
pub mod kernel_validation_matrix;
pub mod kmod_crash_consistency_e2e;
pub mod kmod_mmap_fault;
pub mod kmod_no_daemon_fullstack_validation;
pub mod local_vfs_runtime_crash_artifact;
pub mod metadata_durability;
pub mod mount_harness;
pub mod performance_gate;
pub mod pool_rollback_import_validation;
pub mod qemu;
pub mod qemu_pin_manifest;
pub mod runtime_artifact_source;
pub mod smoke;
pub mod support_bundle;
pub mod trace;
pub mod two_node_harness_fuse_integrity;
pub mod ublk_completion_artifact;
pub mod ublk_discard_validation;
pub mod ublk_started_export_admission_artifact;
pub mod validation_schema;
pub mod validation_status;
pub mod workers_ns;
pub mod write_durability;
pub mod xattr_durability;
pub mod xfstests_lock_group;
pub mod xfstests_scoreboard;
pub mod xfstests_tiering;
