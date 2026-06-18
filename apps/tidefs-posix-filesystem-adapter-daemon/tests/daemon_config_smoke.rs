// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lightweight daemon configuration smoke tests.
//!
//! These drive the compiled daemon binary far enough to validate CLI parsing
//! and pre-mount configuration handling without requiring a working FUSE mount.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT_AUTH_KEY_HEX: &str = "4141414141414141414141414141414141414141414141414141414141414141";
const ROOT_AUTH_ENV: &str = "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX";
const CACHE_PROFILE_ENV: &str = "TIDEFS_CACHE_PROFILE";

fn daemon_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tidefs-posix-filesystem-adapter-daemon")
}

fn unique_root(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-daemon-config-smoke-{test_name}-{}-{nanos}",
        std::process::id()
    ))
}

fn run_daemon(args: &[&str]) -> Output {
    Command::new(daemon_bin())
        .env_remove(ROOT_AUTH_ENV)
        .env_remove(CACHE_PROFILE_ENV)
        .args(args)
        .output()
        .expect("run daemon binary")
}

fn run_daemon_with_root_env(args: &[&str]) -> Output {
    Command::new(daemon_bin())
        .env(ROOT_AUTH_ENV, ROOT_AUTH_KEY_HEX)
        .env_remove(CACHE_PROFILE_ENV)
        .args(args)
        .output()
        .expect("run daemon binary")
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn create_file_mountpoint(path: &Path) {
    fs::write(path, b"not a directory").expect("create file mountpoint");
}

#[test]
fn daemon_config_help_advertises_mount_startup_knobs() {
    let output = run_daemon(&["--help"]);
    assert!(output.status.success(), "stderr: {}", stderr_text(&output));

    let stdout = stdout_text(&output);
    assert!(stdout.contains("mount --store <path> --mount <path>"));
    assert!(stdout.contains("[--vfs-adapter]"));
    assert!(stdout.contains("[--root-auth-key-hex <64 hex>]"));
    assert!(stdout.contains("[--cache-profile strict|perf|cluster|auto]"));
    assert!(stdout.contains(ROOT_AUTH_ENV));
    assert!(stdout.contains("TIDEFS_CACHE_PROFILE"));
}

#[test]
fn daemon_config_mount_parses_store_mount_profile_and_root_key_flag() {
    let root = unique_root("preview");
    let store = root.join("store");
    let mountpoint = root.join("mnt-file");
    fs::create_dir_all(&root).expect("create test root");
    create_file_mountpoint(&mountpoint);

    let store_arg = store.display().to_string();
    let mount_arg = mountpoint.display().to_string();
    let output = run_daemon(&[
        "mount",
        "--store",
        &store_arg,
        "--mount",
        &mount_arg,
        "--root-auth-key-hex",
        ROOT_AUTH_KEY_HEX,
        "--cache-profile",
        "strict",
    ]);

    assert!(!output.status.success(), "mount should fail before FUSE");
    let stdout = stdout_text(&output);
    assert!(stdout.contains(&format!("fuse_mount.store={}", store.display())));
    assert!(stdout.contains(&format!("fuse_mount.mountpoint={}", mountpoint.display())));
    assert!(stdout.contains("fuse_mount.adapter=preview"));
    assert!(stdout.contains("fuse_mount.mode=foreground"));

    let stderr = stderr_text(&output);
    assert!(stderr.contains("FUSE mount failed"), "stderr: {stderr}");
    assert!(stderr.contains("File exists"), "stderr: {stderr}");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn daemon_config_mountpoint_alias_vfs_adapter_and_root_key_env_are_accepted() {
    let root = unique_root("vfs");
    let store = root.join("store");
    let mountpoint = root.join("mnt-file");
    fs::create_dir_all(&root).expect("create test root");
    create_file_mountpoint(&mountpoint);

    let store_arg = store.display().to_string();
    let mount_arg = mountpoint.display().to_string();
    let output = run_daemon_with_root_env(&[
        "mount",
        "--vfs-adapter",
        "--store",
        &store_arg,
        "--mountpoint",
        &mount_arg,
        "--cache-profile",
        "perf",
    ]);

    assert!(!output.status.success(), "mount should fail before FUSE");
    let stdout = stdout_text(&output);
    assert!(stdout.contains(&format!("fuse_mount.store={}", store.display())));
    assert!(stdout.contains(&format!("fuse_mount.mountpoint={}", mountpoint.display())));
    assert!(stdout.contains("fuse_mount.adapter=vfs"));
    assert!(stdout.contains("fuse_mount.mode=foreground"));

    let stderr = stderr_text(&output);
    assert!(stderr.contains("FUSE VFS mount failed"), "stderr: {stderr}");
    assert!(stderr.contains("File exists"), "stderr: {stderr}");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn daemon_config_mount_rejects_missing_required_paths_after_root_key_resolution() {
    let root = unique_root("missing-required");
    let store = root.join("store");
    let mountpoint = root.join("mnt");
    let store_arg = store.display().to_string();
    let mount_arg = mountpoint.display().to_string();

    let missing_store = run_daemon(&[
        "mount",
        "--mount",
        &mount_arg,
        "--root-auth-key-hex",
        ROOT_AUTH_KEY_HEX,
    ]);
    assert!(!missing_store.status.success());
    assert!(
        stderr_text(&missing_store).contains("mount requires --store <path>"),
        "stderr: {}",
        stderr_text(&missing_store)
    );

    let missing_mount = run_daemon(&[
        "mount",
        "--store",
        &store_arg,
        "--root-auth-key-hex",
        ROOT_AUTH_KEY_HEX,
    ]);
    assert!(!missing_mount.status.success());
    assert!(
        stderr_text(&missing_mount).contains("mount requires --mount <path>"),
        "stderr: {}",
        stderr_text(&missing_mount)
    );
}

#[test]
fn daemon_config_mount_rejects_invalid_startup_arguments() {
    let root = unique_root("invalid-args");
    let store = root.join("store");
    let mountpoint = root.join("mnt");
    let store_arg = store.display().to_string();
    let mount_arg = mountpoint.display().to_string();

    let invalid_profile = run_daemon(&[
        "mount",
        "--store",
        &store_arg,
        "--mount",
        &mount_arg,
        "--root-auth-key-hex",
        ROOT_AUTH_KEY_HEX,
        "--cache-profile",
        "eventual",
    ]);
    assert!(!invalid_profile.status.success());
    assert!(
        stderr_text(&invalid_profile).contains("invalid --cache-profile"),
        "stderr: {}",
        stderr_text(&invalid_profile)
    );

    let invalid_root_key = run_daemon(&[
        "mount",
        "--store",
        &store_arg,
        "--mount",
        &mount_arg,
        "--root-auth-key-hex",
        "not-hex",
    ]);
    assert!(!invalid_root_key.status.success());
    assert!(
        stderr_text(&invalid_root_key).contains("invalid root authentication key"),
        "stderr: {}",
        stderr_text(&invalid_root_key)
    );

    let unknown_arg = run_daemon(&[
        "mount",
        "--store",
        &store_arg,
        "--mount",
        &mount_arg,
        "--root-auth-key-hex",
        ROOT_AUTH_KEY_HEX,
        "--foreground",
    ]);
    assert!(!unknown_arg.status.success());
    assert!(
        stderr_text(&unknown_arg).contains("unknown mount argument `--foreground`"),
        "stderr: {}",
        stderr_text(&unknown_arg)
    );
}
