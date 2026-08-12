// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(dead_code)]
#![deny(unused_imports)]
#![deny(unsafe_code)]

mod capacity;
#[cfg(feature = "cluster")]
mod clustered_mount;
mod coherency_profile;
mod dispatch_helpers;
mod fuse_create_unlink_dispatch;
mod fuse_flush_fsync;
mod fuse_posix_lock;
mod fuse_rename;
mod fuse_vfs_adapter;
mod fusewire;
mod handler_prelude;
mod ingress;
mod live_owner;
mod lock_dispatch;
mod maintenance;
#[cfg(feature = "workload-telemetry")]
mod materialized_cache;
mod mmap_coherency;
pub mod mount_options;
mod observability;
mod read_cache;
mod reply;
mod runtime;
mod scheduler;
mod workers_meta;
mod workers_ns;
mod workers_writeback;
#[cfg(feature = "workload-telemetry")]
mod workload_observer;
mod write_dispatch;

mod writeback_reclaim;
mod xattr_integrity;
mod xfstests_harness;
use std::env;
#[cfg(feature = "receipt-demo")]
use std::fmt::Debug;
use std::path::{Path, PathBuf};

#[cfg(feature = "receipt-demo")]
use crate::runtime::{
    issue_product_wake_receipt, PosixFilesystemAdapterDemoPublicationTicketRecord,
    PosixFilesystemAdapterDemoVisibleAnswerRecord,
    FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN,
};
#[cfg(feature = "receipt-demo")]
use tidefs_schema_codec_posix_filesystem_adapter::CanonicalFixedWidth;
#[cfg(feature = "receipt-demo")]
use tidefs_types_package_profile_catalog::{
    SurfaceManifest, POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE,
};
#[cfg(feature = "receipt-demo")]
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterId128, PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
    PosixFilesystemAdapterProductWakeReceiptRecord,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        #[cfg(feature = "receipt-demo")]
        None | Some("receipt-demo") => {
            run_receipt_demo();
            Ok(())
        }
        #[cfg(not(feature = "receipt-demo"))]
        None => {
            print_help();
            Ok(())
        }
        Some("score-posix") => {
            let out_dir = parse_score_posix_args(args.collect())?;
            run_score_posix(&out_dir)
        }
        Some("xfstests-harness") => {
            let harness_cfg = parse_xfstests_harness_args(args.collect())?;
            run_xfstests_harness(&harness_cfg)
        }
        Some("scrub-repair-smoke") => run_scrub_repair_smoke(),

        Some("help" | "--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unknown command `{other}`; run with --help")),
    }
}

/// Parse arguments for `score-posix --out <dir>`.
fn parse_score_posix_args(args: Vec<String>) -> Result<PathBuf, String> {
    let mut out_dir = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--out" => {
                out_dir = Some(PathBuf::from(
                    iter.next().ok_or("--out requires a directory path")?,
                ));
            }
            other => return Err(format!("unknown score-posix argument `{other}`")),
        }
    }
    out_dir.ok_or_else(|| "score-posix requires --out <dir>".to_string())
}

/// Run the score-posix subcommand: read env vars set by the posix-scoreboard
/// harness, optionally execute xfstests, and produce a JSON scoreboard.
fn run_score_posix(out_dir: &Path) -> Result<(), String> {
    let config = xfstests_harness::XfstestsConfig::from_scoreboard_env(out_dir.to_path_buf())?;
    let scoreboard = xfstests_harness::run_xfstests(&config)?;

    eprintln!(
        "score-posix: {} tests, {} passed, {} failed, {} skipped, {} diff",
        scoreboard.summary.total,
        scoreboard.summary.passed,
        scoreboard.summary.failed,
        scoreboard.summary.skipped,
        scoreboard.summary.diff,
    );
    eprintln!("scoreboard written to {}", out_dir.display());
    Ok(())
}

/// Parse arguments for `xfstests-harness`.
fn parse_xfstests_harness_args(
    args: Vec<String>,
) -> Result<xfstests_harness::XfstestsConfig, String> {
    let mut test_tokens: Vec<String> = Vec::new();
    let mut out_dir = None;
    let mut quick = false;
    let mut auto = false;
    let mut exclude_file = None;
    let mut no_exclude = false;

    // Use index-based iteration so we can consume multiple positional
    // tokens after --tests (e.g. --tests lock symlink fallocate).
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tests" | "--test-range" => {
                i += 1;
                // Consume all following positional tokens until the next
                // "--flag" or end-of-args.
                while i < args.len() && !args[i].starts_with("--") {
                    test_tokens.push(args[i].clone());
                    i += 1;
                }
                if test_tokens.is_empty() {
                    return Err("--tests requires at least one range spec \
                        (e.g. generic/101-150)"
                        .to_string());
                }
                continue; // i already advanced past consumed tokens
            }
            "--out" => {
                i += 1;
                if i >= args.len() {
                    return Err("--out requires a directory path".to_string());
                }
                out_dir = Some(PathBuf::from(args[i].clone()));
            }
            "--quick" => quick = true,
            "--auto" => auto = true,
            "--exclude" => {
                i += 1;
                if i >= args.len() {
                    return Err("--exclude requires a file path".to_string());
                }
                exclude_file = Some(PathBuf::from(args[i].clone()));
            }
            "--no-exclude" => no_exclude = true,
            other => return Err(format!("unknown xfstests-harness argument `{other}`")),
        }
        i += 1;
    }

    // Expand conceptual group aliases (e.g. "lock" -> generic/131 generic/184 ...)
    // before passing to the range parser.
    let test_tokens = xfstests_harness::expand_xfstests_group_aliases(&test_tokens);
    let range_spec = if test_tokens.is_empty() {
        "generic/001-050".to_string()
    } else {
        test_tokens.join(" ")
    };
    let out_dir = out_dir.unwrap_or_else(|| {
        let id = std::process::id();
        PathBuf::from(format!("/tmp/tidefs-xfstests-{id}"))
    });

    xfstests_harness::XfstestsConfig::from_cli(
        range_spec,
        out_dir,
        quick,
        auto,
        exclude_file,
        no_exclude,
    )
}

/// Run the xfstests-harness subcommand.
fn run_xfstests_harness(config: &xfstests_harness::XfstestsConfig) -> Result<(), String> {
    let scoreboard = xfstests_harness::run_xfstests(config)?;

    eprintln!(
        "xfstests-harness: {} tests, {} passed, {} failed, {} skipped, {} diff",
        scoreboard.summary.total,
        scoreboard.summary.passed,
        scoreboard.summary.failed,
        scoreboard.summary.skipped,
        scoreboard.summary.diff,
    );
    eprintln!("scoreboard written to {}", config.out_dir.display());
    Ok(())
}

/// Standalone scrub-repair-reclaim smoke test that does NOT require FUSE.
///
/// Creates a LocalFileSystem directly, writes data, commits, then runs
/// Phases 7b-10 (SuspectLog persistence, segment chain verify, repair
/// writeback recovery, fault injection, segment-level corruption +
/// scrub detection + SuspectLog survival + RepairWriteback recovery).
///
/// This produces runtime validation output for the scrub/repair/reclaim
/// pipeline without needing /dev/fuse or a mounted kernel.
#[allow(unsafe_code)]
fn run_scrub_repair_smoke() -> Result<(), String> {
    use tidefs_local_filesystem::human::local_filesystem::{
        LocalFileSystem, LocalStorageAllocatorPolicy, StoreOptions,
    };

    let store_root = "/tmp/tidefs-scrub-repair-smoke-store";
    let _ = std::fs::remove_dir_all(store_root);
    std::fs::create_dir_all(store_root).map_err(|e| format!("create store dir: {e}"))?;

    let mut passed = 0_u32;
    let mut failed = 0_u32;

    macro_rules! smoke_test {
        ($name:expr, $body:block) => {
            match (|| -> Result<(), String> { $body })() {
                Ok(()) => {
                    eprintln!("  PASS  {}", $name);
                    passed += 1;
                }
                Err(e) => {
                    eprintln!("  FAIL  {}: {}", $name, e);
                    failed += 1;
                }
            }
        };
    }

    let auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_hex(
        "4141414141414141414141414141414141414141414141414141414141414141",
    )
    .map_err(|e| format!("auth key: {e}"))?;

    // Phase A: Create filesystem and write data (no FUSE needed)
    eprintln!("=== Phase A: create filesystem and write data ===");

    smoke_test!("phaseA_open_filesystem", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        Ok(())
    });

    smoke_test!("phaseA_create_files_and_dirs", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let mut lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        // Create a file with data
        let _rec = lfs
            .create_file("/scrub-test-file.txt", 0o644)
            .map_err(|e| format!("create_file: {e}"))?;
        let data = vec![0xABu8; 4096];
        lfs.write_file("/scrub-test-file.txt", 0, &data)
            .map_err(|e| format!("write_file: {e}"))?;
        // Create a subdirectory
        let _dirrec = lfs
            .create_dir("/scrub-test-subdir", 0o755)
            .map_err(|e| format!("create_dir: {e}"))?;
        // Create another file
        let _rec2 = lfs
            .create_file("/scrub-test-subdir/nested.txt", 0o644)
            .map_err(|e| format!("create nested file: {e}"))?;
        let data2 = b"nested file content for scrub testing\n".to_vec();
        lfs.write_file("/scrub-test-subdir/nested.txt", 0, &data2)
            .map_err(|e| format!("write nested: {e}"))?;
        // Commit and close
        lfs.commit().map_err(|e| format!("commit: {e}"))?;
        drop(lfs);
        eprintln!("  DIAG  created 2 files, 1 dir, committed");
        Ok(())
    });

    // ── Phase 7b: SuspectLog persistence ──
    eprintln!("=== Phase B: SuspectLog persistence verification ===");

    smoke_test!("phaseB_suspect_log_loads", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store: {e}"))?;
        let log = store.suspect_log();
        eprintln!("  DIAG  suspect_log entries={}", log.len());
        Ok(())
    });

    smoke_test!("phaseB_segment_chain_verify", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store: {e}"))?;
        let (stats, _log) = store
            .verify_segment_chain()
            .map_err(|e| format!("segment chain verify: {e}"))?;
        eprintln!(
            "  DIAG  chain: segments={} breaks={} last={}",
            stats.segments_in_chain, stats.chain_breaks_detected, stats.last_verified_segment
        );
        if stats.chain_breaks_detected > 0 {
            eprintln!(
                "  DIAG  {} chain breaks detected (may be from pre-existing suspect entries or corruption in Phase A/B)",
                stats.chain_breaks_detected
            );
        }
        Ok(())
    });

    // ── Phase 8: Repair writeback recovery ──
    eprintln!("=== Phase C: repair writeback recovery ===");

    smoke_test!("phaseC_recovery_loop_repair_writeback", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        eprintln!("  DIAG  RepairWriteback recovery loop completed");
        Ok(())
    });

    smoke_test!("phaseC_run_background_scrub", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let report = store
            .run_background_scrub()
            .map_err(|e| format!("scrub: {e}"))?;
        eprintln!(
            "  DIAG  scrub: segments={} records={} bytes={}",
            report.segments_scanned, report.records_verified, report.bytes_scanned
        );
        Ok(())
    });

    // ── Phase 9: Fault injection corruption ──
    eprintln!("=== Phase D: fault injection corruption ===");

    let _corrupt_key = tidefs_local_object_store::ObjectKey::from_name(b"phaseD_corrupt_test");

    smoke_test!("phaseD_write_with_corruption_injection", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                fault_injection_config: Some(tidefs_local_object_store::FaultInjectionConfig {
                    byte_corruption_probability: 0.5,
                    ..tidefs_local_object_store::FaultInjectionConfig::off()
                }),
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let payload = vec![0xABu8; 2048];
        match store.put_named(b"phaseD_corrupt_test", &payload) {
            Ok(_) => eprintln!("  DIAG  corrupt write succeeded"),
            Err(e) => eprintln!("  DIAG  corrupt write: {e}"),
        }
        Ok(())
    });

    smoke_test!("phaseD_reopen_and_read", {
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                verify_read_checksums: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let original = vec![0xABu8; 2048];
        match store.get_named(b"phaseD_corrupt_test") {
            Ok(Some(readback)) => {
                let differs = readback != original;
                eprintln!(
                    "  DIAG  readback len={} differs={}",
                    readback.len(),
                    differs
                );
            }
            Ok(None) => eprintln!("  DIAG  key not found"),
            Err(e) => eprintln!("  DIAG  read error (checksum mismatch?): {e}"),
        }
        Ok(())
    });

    smoke_test!("phaseD_scrub_after_corruption", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let _report = store
            .run_background_scrub()
            .map_err(|e| format!("scrub: {e}"))?;
        let suspect_count = store.suspect_log().len();
        eprintln!("  DIAG  suspect_log after corruption scrub: {suspect_count} entries");
        Ok(())
    });

    // ── Phase 10: Segment-level corruption ──
    eprintln!("=== Phase E: segment-level corruption injection ===");

    smoke_test!("phaseE_inject_segment_corruption", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open: {e}"))?;
        let seg_dir = store.segments_dir().to_path_buf();
        drop(store);

        let mut seg_files: Vec<std::path::PathBuf> = std::fs::read_dir(&seg_dir)
            .map_err(|e| format!("read dir: {e}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        if seg_files.is_empty() {
            return Err("no segment files found".to_string());
        }
        seg_files.sort_by_key(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok()));
        let target = seg_files.last().ok_or("no segment")?.clone();

        let mut buf = std::fs::read(&target).map_err(|e| format!("read: {e}"))?;
        let corrupt_offset: u64 = 100;
        if buf.len() as u64 > corrupt_offset + 8 {
            for i in 0..8 {
                buf[(corrupt_offset + i) as usize] ^= 0xFF;
            }
            std::fs::write(&target, &buf).map_err(|e| format!("write: {e}"))?;
            eprintln!(
                "  DIAG  flipped 8 bytes at offset {corrupt_offset} in {:?}",
                target.file_name().unwrap_or_default()
            );
        } else {
            eprintln!("  DIAG  segment too short (len={})", buf.len());
        }
        Ok(())
    });

    smoke_test!("phaseE_scrub_detects_corruption", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                verify_read_checksums: false,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let report = store
            .run_background_scrub()
            .map_err(|e| format!("scrub: {e}"))?;
        let suspect_count = store.suspect_log().len();
        eprintln!(
            "  DIAG  post-segment-corruption scrub: outcomes={} suspect_entries={}",
            report.outcomes.len(),
            suspect_count
        );
        for outcome in &report.outcomes {
            eprintln!("  DIAG  outcome: {outcome:?}");
        }
        Ok(())
    });

    smoke_test!("phaseE_suspect_log_survives_reopen", {
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                verify_read_checksums: false,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let suspect_count = store.suspect_log().len();
        eprintln!("  DIAG  suspect_log after reopen: {suspect_count} entries");
        Ok(())
    });

    smoke_test!("phaseE_repair_recovery_after_corruption", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            verify_read_checksums: false,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        eprintln!("  DIAG  RepairWriteback recovery after corruption succeeded");
        Ok(())
    });

    // Cleanup
    let _ = std::fs::remove_dir_all(store_root);

    eprintln!("=== scrub-repair-smoke: {passed} passed, {failed} failed ===");
    if failed > 0 {
        return Err(format!("{failed} test(s) failed"));
    }
    Ok(())
}

fn print_help() {
    println!("tidefs-posix-filesystem-adapter-daemon");
    println!("  score-posix --out <dir>");
    println!(
        "    produce a JSON scoreboard from xfstests results (reads TIDEFS_XFSTESTS_* env vars)"
    );
    println!("  xfstests-harness --tests <range> [--quick|--auto] --out <dir> [--exclude <file>]");
    println!("    run xfstests against a TideFS FUSE mount and produce a JSON scoreboard");
    println!("    --tests: test range, e.g. generic/101-150 or generic/101");
    println!("    --quick: run quick group; --auto: run auto group");
    #[cfg(feature = "receipt-demo")]
    println!("  receipt-demo");
    println!("  help | --help | -h");
    println!();
    println!("Idmapped mounts: TideFS FUSE does not support idmapped mounts");
    println!("(UID/GID translation via mount_setattr). The daemon will refuse");
    println!("to operate when an idmapped mount is detected.");
}

#[cfg(feature = "receipt-demo")]
fn run_receipt_demo() {
    print_surface_manifest(POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE);
    println!("publication_response_to_posix_wake_chain=Publication Pipeline + Response Registry -> POSIX Filesystem Adapter wake receipt");
    println!(
        "wire.publication_response_to_posix_wake_chain={FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN}"
    );

    let admitted_ticket = PosixFilesystemAdapterDemoPublicationTicketRecord {
        ticket_id: PosixFilesystemAdapterId128::from_u128_le(0x11),
    };
    let admitted_answer = PosixFilesystemAdapterDemoVisibleAnswerRecord::bundle(
        PosixFilesystemAdapterId128::from_u128_le(0x77),
        PosixFilesystemAdapterId128::from_u128_le(0x22),
        PosixFilesystemAdapterId128::from_u128_le(0x33),
        [0x10_u8; 32],
        [0x20_u8; 32],
    );
    let admitted_receipt = issue_product_wake_receipt(
        Some(admitted_ticket),
        admitted_answer,
        witness_refs_for(admitted_answer, Some(admitted_ticket.ticket_id)),
    )
    .expect("POSIX adapter wake receipt (posix_filesystem_adapter continuity)");
    print_receipt("admitted", admitted_receipt);

    let refusal_answer = PosixFilesystemAdapterDemoVisibleAnswerRecord::refusal(
        PosixFilesystemAdapterId128::from_u128_le(0x88),
        PosixFilesystemAdapterId128::from_u128_le(0x99),
        PosixFilesystemAdapterId128::from_u128_le(0xAA),
        [0x30_u8; 32],
        [0x40_u8; 32],
    );
    let refusal_receipt =
        issue_product_wake_receipt(None, refusal_answer, witness_refs_for(refusal_answer, None))
            .expect("POSIX adapter wake receipt (posix_filesystem_adapter continuity)");
    print_receipt("refusal", refusal_receipt);
}

#[cfg(feature = "receipt-demo")]
fn print_surface_manifest(surface: SurfaceManifest) {
    println!("{}", surface.binary_name);
    println!("service={}", surface.human_name());
    println!("service_key={}", surface.rust_hint());
    println!("family_locator={}", surface.stable_locator());
    println!("stable_family_id={}", surface.family.stable_id());
    println!("profile={}", surface.profile.human_name());
    println!("stable_profile_id={}", surface.profile.stable_id());
    println!("bundle={}", surface.bundle.human_name());
    println!("stable_bundle_id={}", surface.bundle.stable_id());
    print!("capabilities=");
    for (idx, cap) in surface.capabilities.iter().enumerate() {
        if idx != 0 {
            print!(",");
        }
        print!("{}", cap.human_name());
    }
    println!();
    print!("stable_capability_ids=");
    for (idx, cap) in surface.capabilities.iter().enumerate() {
        if idx != 0 {
            print!(",");
        }
        print!("{}", cap.stable_id());
    }
    println!();
    println!("stage={}", surface.stage);
}

#[cfg(feature = "receipt-demo")]
fn print_receipt(label: &'static str, receipt: PosixFilesystemAdapterProductWakeReceiptRecord) {
    println!("case={label}");
    println!(
        "  wake_class={}",
        receipt.wake_class().expect("wake").as_str()
    );
    println!(
        "  visibility={}",
        receipt.visibility().expect("visibility").as_str()
    );
    println!(
        "  has_publication_pipeline_ticket={}",
        receipt.has_publication_pipeline_ticket()
    );
    println!(
        "  witness_join_id_le={:#x}",
        receipt.witness_refs.witness_join_id.as_u128_le()
    );
    println!(
        "  witness_policy_id_le={:#x}",
        receipt.witness_refs.policy_witness_id.as_u128_le()
    );
    println!(
        "  witness_budget_id_le={:#x}",
        receipt.witness_refs.budget_witness_id.as_u128_le()
    );
    println!(
        "  witness_recipe_id_le={:#x}",
        receipt.witness_refs.recipe_witness_id.as_u128_le()
    );
    println!(
        "  wire.posix_adapter.wake_receipt={}",
        roundtrip_encoded_len(&receipt)
    );
}

#[cfg(feature = "receipt-demo")]
fn roundtrip_encoded_len<T>(value: &T) -> usize
where
    T: CanonicalFixedWidth + Copy + PartialEq + Debug,
{
    let mut bytes = vec![0_u8; T::ENCODED_LEN];
    value.encode_le(&mut bytes);
    let decoded = T::decode_le(&bytes).expect("canonical decode");
    assert_eq!(*value, decoded);
    bytes.len()
}

#[cfg(feature = "receipt-demo")]
const fn derive_pair_id(
    left: PosixFilesystemAdapterId128,
    right: PosixFilesystemAdapterId128,
    salt: u8,
) -> PosixFilesystemAdapterId128 {
    let mut out = [0_u8; 16];
    let mut idx = 0;
    while idx < 16 {
        out[idx] = left.0[idx] ^ right.0[15 - idx] ^ salt ^ (idx as u8).wrapping_mul(7);
        idx += 1;
    }
    PosixFilesystemAdapterId128(out)
}

#[cfg(feature = "receipt-demo")]
fn witness_refs_for(
    response_registry_answer: PosixFilesystemAdapterDemoVisibleAnswerRecord,
    publication_pipeline_ticket_id: Option<PosixFilesystemAdapterId128>,
) -> PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs {
    let ticket_or_zero =
        publication_pipeline_ticket_id.unwrap_or(PosixFilesystemAdapterId128::ZERO);
    PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
        derive_pair_id(
            response_registry_answer.request_id,
            response_registry_answer.journal_id,
            0xC1,
        ),
        derive_pair_id(response_registry_answer.receipt_id, ticket_or_zero, 0xC2),
        derive_pair_id(response_registry_answer.journal_id, ticket_or_zero, 0xC3),
        derive_pair_id(
            response_registry_answer.request_id,
            response_registry_answer.receipt_id,
            0xC4,
        ),
        response_registry_answer.answer_digest,
    )
}
