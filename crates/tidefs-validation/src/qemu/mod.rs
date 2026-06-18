// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! QEMU smoke test entry points and RDMA carrier validation.
//!
//! Tests in this module drive TideFS NixOS VM tests defined in the
//! workspace flake. Each test shells out to `nix build` and skips
//! gracefully when Nix is not available or the test is opt-in via
//! environment variable.
//!
//! The `qemu_ublk_data_queue_smoke` test validates the ublk block-volume
//! adapter inside a real kernel via QEMU + NixOS VM, running fio with
//! verify=crc32c against /dev/ublkb0 and asserting zero data corruption.
//!
//! RDMA carrier tests validate the Nix/QEMU SoftRoCE infrastructure without
//! requiring KVM: host probe classification, two-node topology dry-run, and
//! structural flake.nix config inspection.

#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::process::Command;

/// Run `nix/tidefs-rdma-probe.sh` in non-mutating probe mode and assert
/// carrier classification output is produced.
#[test]
fn rdma_carrier_probe_host() {
    let scripts_dir = workspace_scripts_dir();
    let probe_script = scripts_dir.join("tidefs-rdma-probe.sh");
    assert!(
        probe_script.exists(),
        "rdma-probe.sh not found at {}",
        probe_script.display()
    );

    let output = Command::new("bash")
        .arg(&probe_script)
        .output()
        .expect("failed to run rdma-probe.sh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("tool_ibv_devices=") || stdout.contains("tool_ibv_devinfo="),
        "rdma-probe should report tool presence; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("rdma_carrier_probe_result="),
        "rdma-probe should classify carrier result; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("transport_session_0_fallback="),
        "rdma-probe should report transport fallback; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Run `nix/tidefs-qemu-rdma-two-node.sh --dry-run` and validate the
/// planned two-node topology output.
#[test]
fn qemu_rdma_two_node_dry_run() {
    let scripts_dir = workspace_scripts_dir();
    let two_node_script = scripts_dir.join("tidefs-qemu-rdma-two-node.sh");
    assert!(
        two_node_script.exists(),
        "qemu-rdma-two-node.sh not found at {}",
        two_node_script.display()
    );

    let output = Command::new("bash")
        .arg(&two_node_script)
        .arg("--dry-run")
        .output()
        .expect("failed to run qemu-rdma-two-node.sh --dry-run");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("node_a:"),
        "dry-run should describe node_a; output:\n{stdout}"
    );
    assert!(
        stdout.contains("node_b:"),
        "dry-run should describe node_b; output:\n{stdout}"
    );
    assert!(
        stdout.contains("192.168.77.10"),
        "dry-run should assign node_a IP 192.168.77.10; output:\n{stdout}"
    );
    assert!(
        stdout.contains("192.168.77.20"),
        "dry-run should assign node_b IP 192.168.77.20; output:\n{stdout}"
    );
    assert!(
        stdout.contains("rxe"),
        "dry-run should reference rxe software RDMA; output:\n{stdout}"
    );
    assert!(
        stdout.contains("qemu_socket_netdev"),
        "dry-run should describe QEMU socket netdev; output:\n{stdout}"
    );
}

/// Validate the `flake.nix` contains all required RDMA carrier
/// configuration: the NixOS guest system with necessary kernel modules
/// and initrd tools, the `rdmaCarrierTwoNodeTest` package, and the
/// `rdma-carrier-test` app.
#[test]
fn qemu_rdma_guest_system_config() {
    let flake_path = workspace_flake();
    assert!(flake_path.exists(), "flake.nix not found");

    let flake_content = std::fs::read_to_string(&flake_path).expect("failed to read flake.nix");

    // NixOS guest system must include all required RDMA kernel modules.
    let required_modules = [
        "rdma_rxe",
        "siw",
        "ib_core",
        "ib_uverbs",
        "rdma_cm",
        "rdma_ucm",
        "virtio_pci",
        "virtio_net",
    ];
    for module in &required_modules {
        assert!(
            flake_content.contains(module),
            "flake.nix qemuRdmaGuestSystem missing kernel module {module}"
        );
    }

    // Initrd extra-utils must include RDMA tools.
    let required_tools = ["ibv_devices", "ibv_devinfo", "rping"];
    for tool in &required_tools {
        assert!(
            flake_content.contains(tool),
            "flake.nix qemuRdmaGuestSystem initrd missing tool {tool}"
        );
    }

    // rdma-carrier-test app must exist.
    assert!(
        flake_content.contains("rdma-carrier-test"),
        "flake.nix missing rdma-carrier-test app"
    );

    // rdmaCarrierTwoNodeTest package must exist with two nodes.
    assert!(
        flake_content.contains("rdmaCarrierTwoNodeTest"),
        "flake.nix missing rdmaCarrierTwoNodeTest package"
    );
    assert!(
        flake_content.contains("nodes.server"),
        "flake.nix rdmaCarrierTwoNodeTest missing nodes.server"
    );
    assert!(
        flake_content.contains("nodes.client"),
        "flake.nix rdmaCarrierTwoNodeTest missing nodes.client"
    );

    // Two-node test must include cross-node rping.
    assert!(
        flake_content.contains("rping -s -v") || flake_content.contains("rping -s"),
        "flake.nix rdmaCarrierTwoNodeTest missing rping server"
    );
    assert!(
        flake_content.contains("rping -c -a 192.168.77.10"),
        "flake.nix rdmaCarrierTwoNodeTest missing rping client to 192.168.77.10"
    );

    // rdmaCarrierTwoNode check must exist (structural validation, non-KVM).
    assert!(
        flake_content.contains("rdmaCarrierTwoNode"),
        "flake.nix missing rdmaCarrierTwoNode check"
    );
}

/// Run xfstests generic/101-150 quick group via the posix daemon harness.
///
/// Invokes the daemon's `xfstests-harness` subcommand with the 101-150 test
/// range.  When the daemon binary or xfstests is unavailable, the harness
/// produces a skip-only scoreboard and this test still passes.
#[test]
fn qemu_xfstests_quick_smoke() {
    use std::path::PathBuf;

    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("xfstests-101-150");
    let daemon_bin = std::env::var("TIDEFS_DAEMON_BIN")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tidefs-posix-filesystem-adapter-daemon"));

    let scoreboard = crate::xfstests_scoreboard::invoke_xfstests_harness(
        &daemon_bin,
        "generic/101-150",
        &out_dir,
        true,
    )
    .expect("invoke_xfstests_harness should not error");

    assert_eq!(
        scoreboard.results.len(),
        50,
        "expected 50 tests in generic/101-150 range"
    );

    for entry in &scoreboard.results {
        let num: u32 = entry.test["generic/".len()..].parse().unwrap_or(0);
        assert!(
            (101..=150).contains(&num),
            "test {} outside 101-150 range",
            entry.test
        );
    }
}

/// NixOS ublk block-volume QEMU smoke test.
///
/// Boots a NixOS QEMU VM with the ublk_drv kernel module, starts the
/// block-volume adapter daemon to expose a /dev/ublkb0 node backed by
/// a TideFS pool, runs fio with `verify=crc32c` patterns, and asserts
/// zero data corruption.
///
/// Opt-in via `TIDEFS_RUN_QEMU_UBLK_SMOKE=1` because the NixOS VM build
/// is expensive. Skips silently when the env var is not set or Nix is
/// unavailable.
#[test]
fn qemu_ublk_data_queue_smoke() {
    if std::env::var("TIDEFS_RUN_QEMU_UBLK_SMOKE").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: TIDEFS_RUN_QEMU_UBLK_SMOKE not set to 1 -- \
             set it to opt into the NixOS QEMU ublk smoke test"
        );
        return;
    }

    if !crate::fuse_vm_test::nix_available() {
        eprintln!(
            "SKIP: nix not found on PATH -- \
             qemu_ublk_data_queue_smoke requires a Nix environment"
        );
        return;
    }

    let root =
        crate::fuse_vm_test::workspace_root().expect("cannot find workspace root (flake.nix)");

    let output = std::process::Command::new("nix")
        .args([
            "build",
            &format!("{}#packages.x86_64-linux.qemuUblkSmoke", root.display()),
            "-L",
        ])
        .output()
        .map_err(|e| format!("failed to run nix build: {e}"))
        .unwrap();

    if output.status.success() {
        eprintln!("PASS: NixOS QEMU ublk smoke test completed successfully");
        return;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Skip on read-only store (common in sandboxes) rather than panic.
    if stderr.contains("readonly database")
        || stderr.contains("read-only file system")
        || stdout.contains("readonly database")
        || stdout.contains("read-only file system")
    {
        eprintln!(
            "SKIP: Nix daemon/store not writable in this \
             environment -- qemu_ublk_data_queue_smoke skipped"
        );
        return;
    }

    panic!(
        "NixOS QEMU ublk smoke test failed (exit {:?}):\n\
         stdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code(),
    );
}

/// NixOS ublk ext4 filesystem QEMU smoke test.
///
/// Boots a NixOS QEMU VM with the ublk_drv kernel module, starts the
/// block-volume adapter daemon to expose a /dev/ublkb0 node, creates an
/// ext4 filesystem on it, mounts it, runs fio with `verify=crc32c`
/// through the mounted filesystem, unmounts, and runs fsck.ext4 to
/// verify filesystem metadata consistency.
///
/// Opt-in via `TIDEFS_RUN_QEMU_UBLK_EXT4_SMOKE=1`.
#[test]
fn qemu_ublk_ext4_smoke() {
    if std::env::var("TIDEFS_RUN_QEMU_UBLK_EXT4_SMOKE").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: TIDEFS_RUN_QEMU_UBLK_EXT4_SMOKE not set to 1 -- \
             set it to opt into the NixOS QEMU ublk ext4 smoke test"
        );
        return;
    }

    if !crate::fuse_vm_test::nix_available() {
        eprintln!(
            "SKIP: nix not found on PATH -- \
             qemu_ublk_ext4_smoke requires a Nix environment"
        );
        return;
    }

    let root =
        crate::fuse_vm_test::workspace_root().expect("cannot find workspace root (flake.nix)");

    let output = std::process::Command::new("nix")
        .args([
            "build",
            &format!("{}#packages.x86_64-linux.qemuUblkExt4Smoke", root.display()),
            "-L",
        ])
        .output()
        .map_err(|e| format!("failed to run nix build: {e}"))
        .unwrap();

    if output.status.success() {
        eprintln!("PASS: NixOS QEMU ublk ext4 smoke test completed successfully");
        return;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stderr.contains("readonly database")
        || stderr.contains("read-only file system")
        || stdout.contains("readonly database")
        || stdout.contains("read-only file system")
    {
        eprintln!(
            "SKIP: Nix daemon/store not writable in this \
             environment -- qemu_ublk_ext4_smoke skipped"
        );
        return;
    }

    panic!(
        "NixOS QEMU ublk ext4 smoke test failed (exit {:?}):\n\
         stdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code(),
    );
}

/// Validate that every ublk NixOS QEMU test target in `flake.nix`
/// refuses non-7.x guest kernels before producing passing validation.
///
/// For each named ublk target this test extracts the per-target definition
/// block (from the target name line up to the next top-level ublk target or
/// the end of the NixOS test section) and verifies four refusal-guard pieces
/// within that block:
/// G1: `boot.kernelPackages` pinned to `linuxKernel_7_0`;
/// G2: runtime `kernel_ver.startswith("7.")` check;
/// G3: `environment-refusal` row recorded when the check fails;
/// G4: `raise Exception` that stops the test.
///
/// This is a Tier 0 source/validation guard: it protects the ublk
/// validation authority from non-7.x kernel validation leakage.
#[test]
fn ublk_qemu_kernel_version_refusal_guard() {
    let flake_path = workspace_flake();
    assert!(flake_path.exists(), "flake.nix not found");

    let flake_content = std::fs::read_to_string(&flake_path).expect("failed to read flake.nix");
    let lines: Vec<&str> = flake_content.lines().collect();

    // Tuples of (target_name, line_search_key).
    let ublk_targets: &[(&str, &str)] = &[
        ("qemuUblkSmoke", "qemuUblkSmoke = pkgs"),
        ("qemuUblkExt4Smoke", "qemuUblkExt4Smoke = pkgs"),
        (
            "qemuUblkMultiDevicePlacement",
            "qemuUblkMultiDevicePlacement = pkgs",
        ),
        (
            "qemuUblkCrashConsistency",
            "qemuUblkCrashConsistency = pkgs",
        ),
        ("qemuUblkFsMatrix", "qemuUblkFsMatrix = pkgs"),
    ];

    // Find the start line of every target definition.
    let mut target_starts: Vec<(usize, &str)> = Vec::new();
    for &(_name, search_key) in ublk_targets {
        let pos = lines.iter().position(|l| l.contains(search_key));
        assert!(
            pos.is_some(),
            "flake.nix missing ublk target definition line containing '{search_key}'"
        );
        target_starts.push((pos.unwrap(), search_key));
    }
    target_starts.sort_by_key(|(line, _)| *line);

    // Terminal line for the last ublk target: the first app-target line
    // that references ublk targets (around line ~2756 in flake.nix).
    let terminal_marker = "self.packages.${system}.qemuUblkSmoke";
    let terminal_pos = lines.iter().position(|l| l.contains(terminal_marker));

    for i in 0..target_starts.len() {
        let (start_line, search_key) = target_starts[i];
        let target_name = ublk_targets
            .iter()
            .find(|(_, sk)| *sk == search_key)
            .map(|(n, _)| *n)
            .unwrap();

        let end_line = if i + 1 < target_starts.len() {
            target_starts[i + 1].0
        } else if let Some(tpos) = terminal_pos {
            tpos
        } else {
            lines.len()
        };

        let block: String = lines[start_line..end_line].join("\n");

        // G1: kernel package pinned to linuxKernel_7_0.
        assert!(
            block.contains("linuxKernel_7_0"),
            "{target_name}: must reference linuxKernel_7_0"
        );

        // G2: runtime kernel version check.
        assert!(
            block.contains("kernel_ver.startswith(\"7.\")")
                || block.contains("kernel_ver.startswith('7.')"),
            "{target_name}: must check kernel_ver.startswith('7.') at runtime"
        );

        // G3: environment-refusal row recorded.
        assert!(
            block.contains("environment-refusal"),
            "{target_name}: must record environment-refusal when kernel check fails"
        );

        // G4: Exception raised to stop the test.
        assert!(
            block.contains("raise Exception"),
            "{target_name}: must raise Exception when kernel is not Linux 7.x"
        );
    }

    // The fuse-ublk-storage-integrated-workflow inline test also refuses
    // non-7.x guests (line ~238 in flake.nix).
    if flake_content.contains("fuse-ublk-storage-integrated-workflow") {
        assert!(
            flake_content.contains(
                "fuse-ublk-storage-integrated-workflow validation requires Linux 7.0 guest kernel"
            ),
            "fuse-ublk-storage-integrated-workflow must refuse non-7.x kernels"
        );
    }

    // Standalone nix/vm/ublk-*.nix scripts: runtime kernel version refusal.
    // These scripts embed busybox init scripts that run inside QEMU guests
    // booted with linuxKernel_7_0; the runtime check guards against a
    // non-Nix invocation that substitutes a different kernel image.
    let scripts_dir = workspace_scripts_dir();
    let vm_dir = scripts_dir.join("vm");

    let standalone_ublk_scripts: &[(&str, &str)] = &[
        ("ublk-product-demo-workflow.nix", "product-demo"),
        ("ublk-discard-validation.nix", "discard"),
        ("ublk-resize-validation.nix", "resize"),
    ];

    for (filename, label) in standalone_ublk_scripts {
        let script_path = vm_dir.join(filename);
        assert!(
            script_path.exists(),
            "standalone ublk script not found: {}",
            script_path.display()
        );
        let content = std::fs::read_to_string(&script_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", script_path.display()));

        // G-s1: runtime kernel version check via case pattern.
        assert!(
            content.contains("case \"$KVER\" in") || content.contains("case $KVER in"),
            "{label}: must check kernel version at runtime via case pattern"
        );
        // G-s2: 7.x pattern match for the pass branch.
        assert!(
            content.contains("7.*)"),
            "{label}: must match 7.x kernel versions (7.*) in case statement"
        );
        // G-s3: refusal message on non-7.x.
        assert!(
            content.contains("ENVIRONMENT REFUSAL")
                || content.contains("BLOCKED: linux_7_0_kernel"),
            "{label}: must produce refusal/blocked message for non-7.x kernel"
        );
        // G-s4: exit or poweroff that stops the test on non-7.x.
        assert!(
            content.contains("exit 1") || content.contains("poweroff -f"),
            "{label}: must stop the test (exit 1 or poweroff) on non-7.x kernel"
        );
    }
}
#[cfg(test)]
fn workspace_flake() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("flake.nix");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("cannot find workspace flake.nix from CARGO_MANIFEST_DIR");
}

/// Helper: locate the `nix/` scripts directory relative to the workspace root.
#[cfg(test)]
fn workspace_scripts_dir() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("flake.nix");
        if candidate.exists() {
            return ancestor.join("nix");
        }
    }
    panic!("cannot find workspace root from CARGO_MANIFEST_DIR");
}
