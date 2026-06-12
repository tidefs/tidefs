{
  system,
  repoRoot,
  modulePath,
  testsJson,
  timeoutSec,
  perTestTimeoutSec,
  diskSizeMb,
}:

let
  flake = builtins.getFlake ("path:" + repoRoot);
  pkgs = import flake.inputs.nixpkgs {
    inherit system;
    overlays = [ (import flake.inputs."rust-overlay") ];
  };
  linuxKernel_7_0 = flake.packages.${system}.linuxKernel_7_0;
  tidefsPackage = flake.packages.${system}.tidefsCtlRuntime;
  xfstests = flake.packages.${system}.xfstests;
  requestedTests = builtins.fromJSON (builtins.readFile testsJson);
  effectiveModulePath = modulePath;

  guestHarness = pkgs.writeText "tidefs-k7-vfs-xfstests-guest.py" ''
    import json
    import os
    import re
    import shlex
    import signal
    import shutil
    import subprocess
    import sys
    import tempfile
    import textwrap
    import time

    requested_tests = ${builtins.toJSON requestedTests}
    per_test_timeout = ${toString perTestTimeoutSec}
    overall_timeout = ${toString timeoutSec}
    disk_size_mb = ${toString diskSizeMb}
    step_timeout = max(30, min(120, per_test_timeout))
    mount_probe_timeout = max(10, min(30, step_timeout))
    shared_dir = os.environ.get("TIDEFS_SHARED_DIR", "/tmp/shared")
    artifact_dir = os.path.join(shared_dir, "tidefs-validation")
    os.makedirs(artifact_dir, exist_ok=True)

    validation = {
        "test": "tidefs-k7-vfs-xfstests-validation",
        "version": 4,
        "harness": "nixos-vm-outside-nix-sandbox-upstream-xfstests",
        "scope": "kernel-vfs-linux-7.0",
        "requested_tests": requested_tests,
        "per_test_timeout_secs": per_test_timeout,
        "overall_timeout_secs": overall_timeout,
        "disk_size_mb": disk_size_mb,
        "execution_boundary": "qemu-launched-outside-nix-build-sandbox",
        "local_host_kernel_used": False,
        "results": [],
    }

    valid_statuses = {
        "pass",
        "product-fail",
        "harness-fail",
        "environment-refusal",
        "skip",
        "unsupported",
        "deferred",
    }

    requested_test_set = set(requested_tests)

    def requested_row(row):
        return row.get("name") in requested_test_set

    def count_status(status, *, requested_only):
        return sum(
            1
            for row in validation["results"]
            if row.get("status") == status
            and requested_row(row) == requested_only
        )

    def finalize_counts():
        validation["passed"] = count_status("pass", requested_only=True)
        validation["product_failures"] = count_status("product-fail", requested_only=True)
        validation["harness_failures"] = count_status("harness-fail", requested_only=True)
        validation["environment_refusals"] = count_status("environment-refusal", requested_only=True)
        validation["skipped"] = count_status("skip", requested_only=True)
        validation["unsupported"] = count_status("unsupported", requested_only=True)
        validation["deferred"] = count_status("deferred", requested_only=True)
        validation["failed"] = validation["product_failures"] + validation["harness_failures"]
        validation["requested_result_count"] = sum(
            1 for row in validation["results"] if requested_row(row)
        )
        validation["infrastructure_result_count"] = sum(
            1 for row in validation["results"] if not requested_row(row)
        )
        validation["infrastructure_passed"] = count_status("pass", requested_only=False)
        validation["infrastructure_product_failures"] = count_status("product-fail", requested_only=False)
        validation["infrastructure_harness_failures"] = count_status("harness-fail", requested_only=False)
        validation["infrastructure_environment_refusals"] = count_status("environment-refusal", requested_only=False)
        validation["infrastructure_skipped"] = count_status("skip", requested_only=False)
        validation["infrastructure_unsupported"] = count_status("unsupported", requested_only=False)
        validation["infrastructure_deferred"] = count_status("deferred", requested_only=False)
        validation["artifacts"] = {
            "dmesg": "dmesg.log",
            "journal": "journal.log",
            "qemu": "qemu.log",
            "qemu_wrapper": "qemu-wrapper.log",
        }

    def write_validation_json():
        finalize_counts()
        tmp_path = os.path.join(artifact_dir, "validation.json.tmp")
        final_path = os.path.join(artifact_dir, "validation.json")
        with open(tmp_path, "w") as fh:
            json.dump(validation, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_path, final_path)

    def run(args, timeout=None, check=False):
        timed_out = False
        output_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w+", encoding="utf-8", errors="replace", delete=False
            ) as output_file:
                output_path = output_file.name
                proc = subprocess.Popen(
                    args,
                    stdout=output_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True,
                )

                try:
                    rc = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    rc = 124
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass

                output_file.flush()

            with open(output_path, "r", errors="replace") as output_file:
                output = output_file.read()
        finally:
            if output_path:
                try:
                    os.unlink(output_path)
                except FileNotFoundError:
                    pass

        if timed_out:
            output = output + f"\nTIMEOUT after {timeout}s\n"

        if check and rc != 0:
            raise RuntimeError(output)

        return rc, output

    def shell(script, timeout=None):
        return run(["bash", "-lc", script], timeout=timeout)

    def record(name, status, output=None, tier="MountedKernelVfs",
               failure_class=None, duration_secs=None, log_path=None):
        assert status in valid_statuses, f"invalid validation status: {status}"
        entry = {
            "name": name,
            "status": status,
            "tier": tier,
        }
        if output:
            entry["output"] = output[-6000:]
        if failure_class:
            entry["failure_class"] = failure_class
        if duration_secs is not None:
            entry["duration_secs"] = duration_secs
        if log_path:
            entry["log_path"] = log_path
        validation["results"].append(entry)
        write_validation_json()

    def already_recorded(name):
        return any(row["name"] == name for row in validation["results"])

    def set_active_xfstest(test_name, case_name, stage):
        validation["active_xfstest"] = test_name
        validation["active_xfstest_case"] = case_name
        validation["active_xfstest_stage"] = stage
        validation["active_xfstest_started_monotonic_secs"] = round(time.monotonic(), 3)
        write_validation_json()

    def clear_active_xfstest(test_name):
        if validation.get("active_xfstest") == test_name:
            validation.pop("active_xfstest", None)
            validation.pop("active_xfstest_case", None)
            validation.pop("active_xfstest_stage", None)
            validation.pop("active_xfstest_started_monotonic_secs", None)
            write_validation_json()

    def record_remaining(status, reason, tier="MountedKernelVfs", failure_class=None):
        for test_name in requested_tests:
            if not already_recorded(test_name):
                record(test_name, status, reason, tier=tier, failure_class=failure_class)

    def classify_notrun(reason):
        lower = reason.lower()
        unsupported_needles = [
            "not supported",
            "unsupported",
            "no support",
            "requires a scratch device",
            "scratch device",
            "no scratch",
            "does not support",
            "old kernel/wrong fs",
            "wrong fs",
        ]
        if any(needle in lower for needle in unsupported_needles):
            return "unsupported"
        return "skip"

    def classify_failure(text, rc):
        lower = text.lower()
        if rc in (124, 137):
            return "Hang"
        if "input/output error" in lower or " eio" in lower:
            return "EIOOnValidOp"
        if "wrong errno" in lower:
            return "WrongErrno"
        if "data" in lower and ("mismatch" in lower or "diff" in lower):
            return "SilentDataLoss"
        if "mount" in lower and "failed" in lower:
            return "MountFailure"
        return "XfstestsFailure"

    def read_file(path, limit=20000):
        try:
            with open(path, "r", errors="replace") as fh:
                data = fh.read()
        except FileNotFoundError:
            return ""
        if len(data) > limit:
            return data[-limit:]
        return data

    def read_xfstests_sidecars(results_dir, test_name, limit_per_file=12000, total_limit=60000):
        if not os.path.isdir(results_dir):
            return ""
        interesting_suffixes = (
            ".dmesg",
            ".fsxlog",
            ".fsxops",
            ".full",
            ".log",
            ".notrun",
            ".out.bad",
        )
        candidates = []
        for root, _dirs, files in os.walk(results_dir):
            for filename in files:
                path = os.path.join(root, filename)
                rel = os.path.relpath(path, results_dir)
                rel_lower = rel.lower()
                if not rel.startswith(test_name + "."):
                    continue
                if not rel_lower.endswith(interesting_suffixes):
                    continue
                candidates.append((rel, path))

        parts = []
        total = 0
        for rel, path in sorted(candidates):
            data = read_file(path, limit=limit_per_file)
            if not data:
                continue
            chunk = f"### {rel}\n{data}"
            parts.append(chunk)
            total += len(chunk)
            if total >= total_limit:
                break
        combined = "\n".join(parts)
        if len(combined) > total_limit:
            return combined[-total_limit:]
        return combined

    def copy_tree(src, dst):
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copytree(src, dst, dirs_exist_ok=True)

    def collect_failure_diagnostics(case_name):
        diag_rel = os.path.join("xfstests", case_name, "diagnostics")
        diag_dir = os.path.join(artifact_dir, diag_rel)
        os.makedirs(diag_dir, exist_ok=True)
        commands = {
            "mount-info.txt": (
                "set -u; "
                "printf '%s\\n' '### /proc/self/mountinfo'; "
                "awk '$5 == \"/mnt/tidefs\" || $5 == \"/mnt/tidefs-scratch\" {print}' "
                "/proc/self/mountinfo 2>&1 || true; "
                "printf '%s\\n' '### findmnt /mnt'; "
                "findmnt -R /mnt -o TARGET,SOURCE,FSTYPE,OPTIONS -n 2>&1 || true"
            ),
            "dmesg-tidefs-tail.txt": (
                "dmesg --color=never 2>&1 | "
                "grep -iE 'tidefs|VFS|BUG|WARNING|hung|blocked|rcu|I/O error' | "
                "tail -n 400 || true"
            ),
            "processes.txt": (
                "ps -eo pid,ppid,pgid,stat,etimes,wchan:32,comm,args 2>&1 | "
                "grep -E 'tidefs|xfstests|find|stat|mount|umount|python|bash' | "
                "grep -v grep || true"
            ),
            "mount-target-state.txt": (
                "set -u; "
                "printf '%s\\n' '### /mnt/tidefs'; "
                "stat -Lc 'mode=%F inode=%i dev=%D nlink=%h path=%n' /mnt/tidefs 2>&1 || true; "
                "printf '%s\\n' '### /mnt/tidefs/nosuchdir'; "
                "stat -Lc 'mode=%F inode=%i dev=%D nlink=%h path=%n' /mnt/tidefs/nosuchdir 2>&1 || true; "
                "printf '%s\\n' '### root entries'; "
                "ls -lai /mnt/tidefs 2>&1 | sed -n '1,80p' || true; "
                "printf '%s\\n' '### shallow find'; "
                "find /mnt/tidefs -xdev -maxdepth 2 -printf '%y %i %m %p\\n' 2>&1 | sed -n '1,160p' || true"
            ),
            "hung-task-stacks.txt": (
                "set -u; "
                "for pid in $(pgrep -f 'xfstests-check|tests/generic|/mnt/tidefs/nosuchdir|mount|umount|mountpoint' 2>/dev/null || true); do "
                "printf '### pid=%s\\n' \"$pid\"; "
                "ps -o pid,ppid,pgid,stat,etimes,wchan:32,comm,args -p \"$pid\" 2>&1 || true; "
                "printf '%s\\n' '--- syscall'; "
                "cat /proc/$pid/syscall 2>&1 || true; "
                "printf '%s\\n' '--- stack'; "
                "cat /proc/$pid/stack 2>&1 || true; "
                "done"
            ),
            "sysrq-t.txt": (
                "set -u; "
                "echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true; "
                "before=$(dmesg --color=never 2>/dev/null | wc -l || echo 0); "
                "echo t > /proc/sysrq-trigger 2>/dev/null || true; "
                "sleep 1; "
                "dmesg --color=never 2>&1 | tail -n 800; "
                "printf 'dmesg_lines_before_sysrq=%s\\n' \"$before\""
            ),
            "xfstests-result-files.txt": (
                f"find /tmp/xfstests-runs/{shlex.quote(case_name)}/results "
                "-maxdepth 4 -type f -printf '%p %s bytes\\n' 2>&1 | sort || true"
            ),
            "mount-tree.txt": (
                "if mountpoint -q /mnt/tidefs; then "
                "find /mnt/tidefs -xdev -mindepth 1 -maxdepth 80 "
                "-printf '%y %i %s %p\\n' 2>&1 | sort; "
                "else echo '(not mounted)'; fi"
            ),
            "mount-tree-ls.txt": (
                "if mountpoint -q /mnt/tidefs; then "
                "ls -laiR /mnt/tidefs 2>&1 | head -n 20000; "
                "else echo '(not mounted)'; fi"
            ),
            "mount-find-errors.txt": (
                "if mountpoint -q /mnt/tidefs; then "
                "find /mnt/tidefs -xdev -depth -mindepth 1 -maxdepth 80 "
                "-exec stat -c '%F %i %n' {} \\; 2>&1 >/dev/null; "
                "else echo '(not mounted)'; fi"
            ),
        }
        for filename, script in commands.items():
            wrapped = (
                f"timeout -k 5s {mount_probe_timeout}s "
                f"bash -lc {shlex.quote(script)}"
            )
            rc, out = shell(wrapped, timeout=mount_probe_timeout + 10)
            with open(os.path.join(diag_dir, filename), "w") as fh:
                fh.write(out)
                if out and not out.endswith("\n"):
                    fh.write("\n")
                fh.write(f"exit_code={rc}\n")
                if rc == 124:
                    fh.write(f"diagnostic_timeout_after={mount_probe_timeout}s\n")
        return diag_rel

    def cleanup_xfstests_timeout(test_name, case_name):
        cleanup_rel = os.path.join("xfstests", case_name, "timeout-cleanup.txt")
        cleanup_path = os.path.join(artifact_dir, cleanup_rel)
        os.makedirs(os.path.dirname(cleanup_path), exist_ok=True)

        units = ["fstests-check.scope"]
        for unit_seed in ["fs" + test_name]:
            rc, out = shell(
                "systemd-escape --suffix=scope "
                + shlex.quote(unit_seed)
                + " 2>/dev/null || true",
                timeout=mount_probe_timeout,
            )
            if rc == 0 and out.strip():
                units.append(out.strip().splitlines()[-1])

        process_needles = [
            "xfstests-check",
            f"tests/{test_name}",
            f"/tmp/xfstests-runs/{case_name}",
            "/mnt/tidefs/nosuchdir",
        ]

        with open(cleanup_path, "w") as fh:
            for unit in sorted(set(units)):
                script = (
                    "set +e; "
                    f"systemctl kill --kill-whom=all --signal=KILL {shlex.quote(unit)} 2>&1; "
                    "kill_rc=$?; "
                    f"systemctl reset-failed {shlex.quote(unit)} 2>&1; "
                    "reset_rc=$?; "
                    "printf 'kill_rc=%s reset_rc=%s\\n' \"$kill_rc\" \"$reset_rc\""
                )
                wrapped = (
                    f"timeout -k 5s {mount_probe_timeout}s "
                    f"bash -lc {shlex.quote(script)}"
                )
                rc, out = shell(wrapped, timeout=mount_probe_timeout + 10)
                fh.write(f"### unit {unit}\n")
                fh.write(out)
                if out and not out.endswith("\n"):
                    fh.write("\n")
                fh.write(f"exit_code={rc}\n")
            for needle in process_needles:
                script = f"pkill -KILL -f {shlex.quote(needle)} 2>&1 || true"
                wrapped = (
                    f"timeout -k 5s {mount_probe_timeout}s "
                    f"bash -lc {shlex.quote(script)}"
                )
                rc, out = shell(wrapped, timeout=mount_probe_timeout + 10)
                fh.write(f"### pkill -f {needle}\n")
                fh.write(out)
                if out and not out.endswith("\n"):
                    fh.write("\n")
                fh.write(f"exit_code={rc}\n")
        return cleanup_rel

    def append_record_output(name, suffix):
        for row in reversed(validation["results"]):
            if row["name"] == name:
                row["output"] = (row.get("output", "") + suffix)[-6000:]
                return

    def write_artifacts():
        # Publish a structured checkpoint before collecting logs. Dmesg,
        # journalctl, or diagnostic file copies can hang when the tested
        # filesystem wedged the guest, but the host wrapper still needs a
        # truthful validation.json instead of a generic QEMU timeout.
        write_validation_json()
        shell("dmesg --color=never > /tmp/shared/tidefs-validation/dmesg.log 2>&1 || true",
              timeout=step_timeout)
        shell("journalctl -b --no-pager -n 20000 > /tmp/shared/tidefs-validation/journal.log 2>&1 || true",
              timeout=step_timeout)
        write_validation_json()

    def list_unmounted_disk_devices():
        rc, out = shell("lsblk -dn -o NAME,TYPE 2>/dev/null || true")
        if rc != 0:
            return []
        devices = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) != 2 or parts[1] != "disk":
                continue
            name = parts[0]
            if name.startswith("sr") or name.startswith("loop"):
                continue
            dev = "/dev/" + name
            mount_rc, mount_out = shell(f"lsblk -nr -o MOUNTPOINT {dev} 2>/dev/null | grep -q .")
            if mount_rc == 0:
                continue
            devices.append(dev)
        return devices

    try:
        rc, kernel_ver = run(["uname", "-r"])
        kernel_ver = kernel_ver.strip()
        validation["kernel_version"] = kernel_ver
        record("qemu_boot", "pass", kernel_ver, tier="QemuGuest")
        if not kernel_ver.startswith("7."):
            reason = f"expected Linux 7.0 guest kernel, got {kernel_ver}"
            record("linux_7_0_kernel", "environment-refusal", reason, tier="QemuGuest")
            record_remaining("environment-refusal", reason, tier="QemuGuest")
            write_artifacts()
            sys.exit(0)
        record("linux_7_0_kernel", "pass", kernel_ver, tier="QemuGuest")

        rc, xfstests_path = shell("command -v xfstests-check || true")
        xfstests_path = xfstests_path.strip()
        if not xfstests_path:
            reason = "xfstests-check not found"
            record("xfstests_check_present", "harness-fail", reason,
                   tier="QemuGuest", failure_class="MissingXfstests")
            record_remaining("harness-fail", reason,
                             tier="QemuGuest", failure_class="MissingXfstests")
            write_artifacts()
            sys.exit(0)
        record("xfstests_check_present", "pass", xfstests_path, tier="QemuGuest")

        module_path = "/etc/tidefs/tidefs_posix_vfs.ko"
        rc, modinfo = shell(f"modinfo {module_path} 2>&1 || true")
        record("module_metadata", "pass" if "filename:" in modinfo or "vermagic:" in modinfo else "skip",
               modinfo.strip(), tier="QemuGuest")

        rc, out = shell(f"insmod {module_path} 2>&1")
        if rc != 0:
            reason = f"insmod failed with rc={rc}\n{out}"
            record("module_load", "environment-refusal", reason,
                   tier="QemuGuest", failure_class="KmodLoadFailure")
            record_remaining("environment-refusal", reason,
                             tier="QemuGuest", failure_class="KmodLoadFailure")
            write_artifacts()
            sys.exit(0)
        rc, lsmod = shell("lsmod | grep '^tidefs_posix_vfs' || true")
        record("module_load", "pass", lsmod.strip(), tier="QemuGuest")

        pool_devices = list_unmounted_disk_devices()
        if len(pool_devices) < 2:
            reason = "fewer than two unmounted QEMU empty disk devices found for TideFS TEST_DEV and SCRATCH_DEV"
            record("pool_device", "harness-fail", reason,
                   tier="QemuGuest", failure_class="MissingPoolDevice")
            record_remaining("harness-fail", reason,
                             tier="QemuGuest", failure_class="MissingPoolDevice")
            write_artifacts()
            sys.exit(0)
        pool_dev = pool_devices[0]
        scratch_dev = pool_devices[1]
        record("pool_device", "pass", pool_dev, tier="QemuGuest")
        record("scratch_device", "pass", scratch_dev, tier="QemuGuest")

        setup_script = textwrap.dedent(f"""
          set -euo pipefail
          mkdir -p /mnt/tidefs /mnt/tidefs-scratch /tmp/xfstests-runs /run/tidefs-xfstests-bin
          mkdir -p /sys/kernel/debug
          mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
          cat > /run/tidefs-xfstests-bin/mkfs.tidefs <<'MKFSTIDEFS'
          #! /bin/sh
          set -eu
          dev=""
          size_bytes=""
          while [ "$#" -gt 0 ]; do
            case "$1" in
              --size-bytes)
                if [ "$#" -lt 2 ]; then
                  echo "mkfs.tidefs: --size-bytes requires a value" >&2
                  exit 2
                fi
                size_bytes="$2"
                shift 2
                ;;
              --size-bytes=*)
                size_bytes="$(printf '%s' "$1" | sed 's/^--size-bytes=//')"
                shift
                ;;
              --)
                shift
                ;;
              -*)
                shift
                ;;
              *)
                dev="$1"
                shift
                ;;
            esac
          done
          if [ -z "$dev" ] || [ ! -b "$dev" ]; then
            echo "mkfs.tidefs: missing block device" >&2
            exit 2
          fi
          if [ -n "$size_bytes" ]; then
            case "$size_bytes" in
              *[!0-9]*)
                echo "mkfs.tidefs: invalid --size-bytes value: $size_bytes" >&2
                exit 2
                ;;
            esac
          fi
          findmnt -rn -S "$dev" -o TARGET 2>/dev/null | while IFS= read -r target; do
            umount "$target" 2>/dev/null || true
          done
          wipefs -a "$dev" >/dev/null 2>&1 || true
          dd if=/dev/zero of="$dev" bs=1M count=8 conv=fsync >/dev/null 2>&1 || true
          target_dev="$dev"
          dm_name=""
          settle_dm() {{
            if command -v udevadm >/dev/null 2>&1; then
              udevadm settle --timeout=10 >/dev/null 2>&1 || true
            fi
          }}
          remove_dm() {{
            remove_dm_name="$1"
            if [ "$#" -ge 2 ]; then
              remove_dm_attempts="$2"
            else
              remove_dm_attempts=60
            fi
            remove_dm_i=0
            while [ "$remove_dm_i" -lt "$remove_dm_attempts" ]; do
              if dmsetup remove --retry "$remove_dm_name" >/dev/null 2>&1; then
                return 0
              fi
              settle_dm
              sleep 0.1
              remove_dm_i=$((remove_dm_i + 1))
            done
            if dmsetup remove --deferred "$remove_dm_name" >/dev/null 2>&1; then
              settle_dm
              remove_dm_i=0
              while [ "$remove_dm_i" -lt "$remove_dm_attempts" ]; do
                if ! dmsetup info "$remove_dm_name" >/dev/null 2>&1; then
                  return 0
                fi
                sleep 0.1
                remove_dm_i=$((remove_dm_i + 1))
              done
            fi
            echo "mkfs.tidefs: failed to remove temporary dm device $remove_dm_name" >&2
            dmsetup info "$remove_dm_name" >&2 || true
            dmsetup deps "$remove_dm_name" >&2 || true
            dmsetup remove --retry "$remove_dm_name" >/dev/null
          }}
          cleanup_dm() {{
            if [ -n "$dm_name" ]; then
              remove_dm "$dm_name" 10 >/dev/null 2>&1 || true
            fi
          }}
          trap cleanup_dm EXIT
          if [ -n "$size_bytes" ]; then
            sector_size="$(blockdev --getss "$dev" 2>/dev/null || echo 512)"
            dev_size="$(blockdev --getsize64 "$dev")"
            if [ "$size_bytes" -gt "$dev_size" ]; then
              echo "mkfs.tidefs: requested size $size_bytes exceeds $dev size $dev_size" >&2
              exit 2
            fi
            if [ "$size_bytes" -gt 0 ] && [ "$size_bytes" -lt "$dev_size" ]; then
              if [ $((size_bytes % sector_size)) -ne 0 ]; then
                echo "mkfs.tidefs: requested size $size_bytes is not aligned to sector size $sector_size" >&2
                exit 2
              fi
              sectors=$((size_bytes / sector_size))
              dm_name="tidefs-xfstests-$(basename "$dev")-$$"
              printf '0 %s linear %s 0\\n' "$sectors" "$dev" | dmsetup create "$dm_name" >/dev/null
              target_dev="/dev/mapper/$dm_name"
            fi
          fi
          pool_name="k7_vfs_xfstests_scratch_$(date +%s%N)"
          tidefsctl pool create "$pool_name" --devices "$target_dev" --json
          if [ -n "$dm_name" ]; then
            blockdev --flushbufs "$target_dev" >/dev/null 2>&1 || true
            remove_dm "$dm_name" 80
            dm_name=""
            settle_dm
          fi
          MKFSTIDEFS
          chmod 0755 /run/tidefs-xfstests-bin/mkfs.tidefs
          mount_tidefs_test_dev() {{
            local dev="$1"
            local mnt="$2"
            echo "=== mount_tidefs_test_dev begin dev=$dev mnt=$mnt ==="
            command -v mount || true
            mount --version | head -n 1 || true
            grep -w tidefs /proc/filesystems || true
            findmnt -rn "$mnt" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true
            timeout -k 10s 90s mount -i -v -t tidefs "$dev" "$mnt"
            local mount_rc="$?"
            findmnt -rn "$mnt" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true
            if [ "$mount_rc" -ne 0 ]; then
              echo "mount -i -v -t tidefs returned rc=$mount_rc" >&2
              dmesg --color=never | grep -iE 'tidefs|mount|VFS' | tail -120 >&2 || true
              return "$mount_rc"
            fi
            if ! mountpoint -q "$mnt"; then
              echo "mount -i -v -t tidefs returned success but $mnt is not a mountpoint" >&2
              cat /proc/filesystems >&2 || true
              dmesg --color=never | grep -iE 'tidefs|mount|VFS' | tail -120 >&2 || true
              return 32
            fi
            echo "=== mount_tidefs_test_dev mounted ==="
          }}
          tidefsctl pool create k7_vfs_xfstests_pool --devices {pool_dev} --json
          mount_tidefs_test_dev {pool_dev} /mnt/tidefs
          chmod 0777 /mnt/tidefs
          cat > /tmp/xfstests-tidefs.config <<'EOF'
          export FSTYP=tidefs
          export TEST_DEV={pool_dev}
          export TEST_DIR=/mnt/tidefs
          export SCRATCH_DEV={scratch_dev}
          export SCRATCH_MNT=/mnt/tidefs-scratch
          export EMAIL=root@localhost
          export RECREATE_TEST_DEV=true
          export KEEP_DMESG=yes
          EOF
        """)
        rc, out = shell(setup_script, timeout=max(180, step_timeout * 2))
        if rc != 0:
            reason = f"TideFS mount/setup failed with rc={rc}\n{out}"
            failure = classify_failure(reason, rc)
            record("mount_kernel_vfs", "product-fail", reason, failure_class=failure)
            record_remaining("product-fail", reason, failure_class=failure)
            write_artifacts()
            sys.exit(0)
        mount_rc, mountpoint_out = shell("mountpoint -q /mnt/tidefs 2>&1",
                                         timeout=mount_probe_timeout)
        rc, mount_out = shell("findmnt -rn /mnt/tidefs -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true",
                              timeout=mount_probe_timeout)
        if mount_rc != 0 or not mount_out.strip():
            _, findmnt_diag = shell("findmnt -R /mnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 || true",
                                    timeout=mount_probe_timeout)
            _, mount_diag = shell("mount 2>&1 | sed -n '1,80p' || true",
                                  timeout=mount_probe_timeout)
            reason = (
                "TideFS mount setup returned success but /mnt/tidefs is not a mountpoint\n"
                f"mountpoint_rc={mount_rc}\n"
                f"mountpoint_output_tail:\n{mountpoint_out[-4000:]}\n"
                f"setup_output_tail:\n{out[-4000:]}\n"
                f"findmnt_mnt:\n{findmnt_diag[-4000:]}\n"
                f"mount_table_tail:\n{mount_diag[-4000:]}"
            )
            record("mount_kernel_vfs", "product-fail", reason,
                   failure_class="MountFailure")
            record_remaining("product-fail", reason,
                             failure_class="MountFailure")
            write_artifacts()
            sys.exit(0)
        record("mount_kernel_vfs", "pass", mount_out.strip())

        def ensure_test_mount(row_name):
            mount_rc, mountpoint_out = shell("mountpoint -q /mnt/tidefs 2>&1",
                                             timeout=mount_probe_timeout)
            if mount_rc == 0:
                return True
            if mount_rc == 124:
                reason = (
                    "TideFS mountpoint probe timed out while checking /mnt/tidefs\n"
                    f"{mountpoint_out}"
                )
                record(row_name, "product-fail", reason, failure_class="Hang")
                return False

            rc, out = shell(textwrap.dedent(f"""
              timeout -k 10s {step_timeout}s mount -i -v -t tidefs {pool_dev} /mnt/tidefs
              mount_rc="$?"
              timeout -k 5s {mount_probe_timeout}s findmnt -rn /mnt/tidefs -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true
              if [ "$mount_rc" -ne 0 ]; then
                exit "$mount_rc"
              fi
              timeout -k 5s {mount_probe_timeout}s mountpoint -q /mnt/tidefs || exit 32
              chmod 0777 /mnt/tidefs
            """), timeout=step_timeout + mount_probe_timeout + 15)
            if rc != 0:
                reason = f"TideFS remount failed before continuing xfstests with rc={rc}\n{out}"
                record(row_name, "product-fail", reason, failure_class=classify_failure(reason, rc))
                return False

            rc, mount_out = shell("findmnt -rn /mnt/tidefs -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true",
                                  timeout=mount_probe_timeout)
            if not mount_out.strip():
                reason = "TideFS remount returned success but /mnt/tidefs is not a mountpoint"
                record(row_name, "product-fail", reason, failure_class="MountFailure")
                return False
            record(row_name, "pass", (mount_out.strip() or "remounted TideFS test device"))
            return True

        safe_test_re = re.compile(r"^[A-Za-z0-9_.+/-]+$")
        for index, test_name in enumerate(requested_tests):
            if not safe_test_re.match(test_name):
                record(test_name, "harness-fail",
                       f"refusing unsafe xfstests name: {test_name}",
                       failure_class="InvalidTestName")
                continue

            case_name = test_name.replace("/", "_")
            before_row = "mount_kernel_vfs_before_" + case_name
            if not ensure_test_mount(before_row):
                reason = f"TideFS mount unavailable before {test_name}"
                for remaining in requested_tests[index:]:
                    if not already_recorded(remaining):
                        record(remaining, "product-fail", reason,
                               failure_class="MountFailure")
                break

            case_dir = f"/tmp/xfstests-runs/{case_name}"
            quoted_test = shlex.quote(test_name)
            run_script = textwrap.dedent(f"""
              set -u
              rm -rf {case_dir}
              mkdir -p {case_dir}
              timeout -k 5s {mount_probe_timeout}s umount /mnt/tidefs-scratch 2>/dev/null || true
              timeout -k 5s {step_timeout}s find /mnt/tidefs -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} + 2>/dev/null || true
              cd {case_dir}
              PATH=/run/tidefs-xfstests-bin:$PATH \\
                HOST_OPTIONS=/tmp/xfstests-tidefs.config \\
                timeout -k 15s {per_test_timeout}s xfstests-check {quoted_test}
            """)

            set_active_xfstest(test_name, case_name, "xfstests-check")
            start = time.time()
            rc, stdout = shell(run_script, timeout=per_test_timeout + 45)
            duration = time.time() - start
            results_dir = os.path.join(case_dir, "results")
            check_text = read_file(os.path.join(results_dir, "check")) + read_file(os.path.join(results_dir, "check.log"))
            bad_path = os.path.join(results_dir, test_name + ".out.bad")
            full_path = os.path.join(results_dir, test_name + ".full")
            notrun_path = os.path.join(results_dir, test_name + ".notrun")
            bad_text = read_file(bad_path)
            full_text = read_file(full_path)
            notrun_text = read_file(notrun_path)
            sidecar_text = read_xfstests_sidecars(results_dir, test_name)
            combined = "\n".join(
                part for part in [stdout, check_text, bad_text, full_text, sidecar_text] if part
            )
            guest_log_path = f"xfstests/{case_name}"
            copy_tree(results_dir, os.path.join(artifact_dir, guest_log_path, "results"))

            zero_test_run = (
                rc == 0
                and re.search(r"Passed all\s+0\s+tests", combined, re.IGNORECASE)
            )
            completed_pass_run = (
                not bad_text.strip()
                and re.search(r"Passed all\s+[1-9][0-9]*\s+tests", combined, re.IGNORECASE)
            )

            if notrun_text.strip():
                status = classify_notrun(notrun_text)
                record(test_name, status, notrun_text.strip(),
                       duration_secs=round(duration, 3),
                       log_path=guest_log_path)
                clear_active_xfstest(test_name)
            elif zero_test_run:
                output = combined or "xfstests-check reported success without running a row"
                record(test_name, "harness-fail", output,
                       failure_class="NoXfstestsRows",
                       duration_secs=round(duration, 3),
                       log_path=guest_log_path)
                clear_active_xfstest(test_name)
            elif rc == 0 and not bad_text.strip():
                record(test_name, "pass", check_text.strip() or stdout.strip(),
                       duration_secs=round(duration, 3),
                       log_path=guest_log_path)
                clear_active_xfstest(test_name)
            elif completed_pass_run:
                record(test_name, "pass", check_text.strip() or stdout.strip(),
                       duration_secs=round(duration, 3),
                       log_path=guest_log_path)
                clear_active_xfstest(test_name)
            elif rc in (124, 137):
                output = combined or f"xfstests timed out with rc={rc}"
                record(test_name, "product-fail", output,
                       failure_class="Hang",
                       duration_secs=round(duration, 3),
                       log_path=guest_log_path)
                clear_active_xfstest(test_name)
                write_validation_json()
                diag_rel = collect_failure_diagnostics(case_name)
                cleanup_rel = cleanup_xfstests_timeout(test_name, case_name)
                append_record_output(
                    test_name,
                    f"\n\nfailure_diagnostics={diag_rel}"
                    f"\ntimeout_cleanup={cleanup_rel}",
                )
                write_validation_json()
                reason = (
                    f"not run after {test_name} timed out; rerun remaining rows "
                    "in a fresh QEMU validation invocation to avoid contaminated "
                    "kernel, mount, or xfstests child-process state"
                )
                for remaining in requested_tests[index + 1:]:
                    if not already_recorded(remaining):
                        record(remaining, "deferred", reason,
                               failure_class="TimeoutContaminatedVm")
                break
            elif "no qualified output" in combined.lower():
                output = combined or "xfstests did not provide qualified golden output"
                record(test_name, "harness-fail", output,
                       failure_class="MissingQualifiedOutput",
                       duration_secs=round(duration, 3),
                       log_path=guest_log_path)
                clear_active_xfstest(test_name)
                write_validation_json()
                diag_rel = collect_failure_diagnostics(case_name)
                append_record_output(test_name, f"\n\nfailure_diagnostics={diag_rel}")
                write_validation_json()
            else:
                output = combined or f"xfstests exited with rc={rc}"
                record(test_name, "product-fail", output,
                       failure_class=classify_failure(combined, rc),
                       duration_secs=round(duration, 3),
                       log_path=guest_log_path)
                clear_active_xfstest(test_name)
                write_validation_json()
                diag_rel = collect_failure_diagnostics(case_name)
                append_record_output(test_name, f"\n\nfailure_diagnostics={diag_rel}")
                write_validation_json()

            if index + 1 < len(requested_tests):
                after_row = "mount_kernel_vfs_after_" + case_name
                if not ensure_test_mount(after_row):
                    reason = f"TideFS mount unavailable after {test_name}"
                    for remaining in requested_tests[index + 1:]:
                        if not already_recorded(remaining):
                            record(remaining, "product-fail", reason,
                                   failure_class="MountFailure")
                    break

        write_artifacts()
        shell("timeout -k 5s 30s umount /mnt/tidefs-scratch 2>/dev/null || true", timeout=40)
        shell("timeout -k 5s 30s umount /mnt/tidefs 2>/dev/null || true", timeout=40)
    except Exception as exc:
        reason = f"harness exception: {exc}"
        record("guest_harness_exception", "harness-fail", reason,
               tier="QemuGuest", failure_class="HarnessException")
        record_remaining("harness-fail", reason,
                         tier="QemuGuest", failure_class="HarnessException")
        write_artifacts()
  '';

  nixos = pkgs.nixos ({ lib, pkgs, ... }: {
    imports = [
      "${flake.inputs.nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
    ];

    system.stateVersion = "25.11";
    boot.kernelPackages = lib.mkForce (pkgs.linuxPackagesFor linuxKernel_7_0);
    boot.initrd.availableKernelModules = lib.mkForce [
      "9p"
      "9pnet"
      "9pnet_virtio"
      "virtio_pci"
      "virtio_blk"
      "virtio_console"
    ];
    boot.initrd.kernelModules = lib.mkForce [
      "9p"
      "9pnet"
      "9pnet_virtio"
      "virtio_balloon"
      "virtio_console"
    ];
    boot.kernelParams = [
      "systemd.default_device_timeout_sec=600s"
      "rd.systemd.default_device_timeout_sec=600s"
      "nosmp"
      "maxcpus=1"
      "clocksource=acpi_pm"
      "tsc=unstable"
      "rcu_cpu_stall_timeout=120"
    ];

    environment.etc."tidefs/tidefs_posix_vfs.ko".source = effectiveModulePath;
    environment.etc."tidefs/xfstests-requested.json".source = testsJson;
    environment.etc."tidefs/k7-vfs-xfstests-guest.py".source = guestHarness;
    environment.systemPackages = [
      tidefsPackage
      xfstests
      pkgs.acl
      pkgs.attr
      pkgs.bash
      pkgs.bc
      pkgs.coreutils
      pkgs.diffutils
      pkgs.e2fsprogs
      pkgs.file
      pkgs.findutils
      pkgs.fio
      pkgs.gawk
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
      pkgs.kmod
      pkgs.lvm2
      pkgs.perl
      pkgs.procps
      pkgs.psmisc
      pkgs.python3
      pkgs.util-linux
      pkgs.which
      pkgs.xfsprogs
    ];

    networking.useDHCP = lib.mkForce false;
    users.users.root.initialHashedPassword = "";
    systemd.services."getty@tty1".enable = lib.mkForce false;
    systemd.services."serial-getty@ttyS0".enable = lib.mkForce false;
    virtualisation.cores = 1;
    virtualisation.emptyDiskImages = [ diskSizeMb diskSizeMb ];
    virtualisation.graphics = false;
    virtualisation.memorySize = 4096;
    virtualisation.mountHostNixStore = true;

    systemd.services.tidefs-k7-vfs-xfstests = {
      description = "TideFS Linux 7.0 kernel VFS xfstests validation";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      path = [
        pkgs.bash
        pkgs.coreutils
        pkgs.systemd
      ];
      script = ''
        set +e
        export TIDEFS_SHARED_DIR=/tmp/shared
        mkdir -p /tmp/shared/tidefs-validation
        ${pkgs.python3}/bin/python3 /etc/tidefs/k7-vfs-xfstests-guest.py
        rc=$?
        echo "$rc" > /tmp/shared/tidefs-validation/guest-exit-code
        sync
        systemctl poweroff --force --force --no-wall || poweroff -f || true
        exit 0
      '';
    };
  });

  vm = nixos.config.system.build.vm;
  vmRunner = pkgs.lib.getExe vm;
in
pkgs.writeShellScriptBin "tidefs-k7-vfs-xfstests-vm-runner" ''
  set -euo pipefail

  shared_dir=""

  usage() {
    cat <<EOF
Usage: tidefs-k7-vfs-xfstests-vm-runner --shared-dir DIR

Launch the generated NixOS VM outside the Nix build sandbox and write validation
to DIR/tidefs-validation.
EOF
  }

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --shared-dir)
        [ "$#" -ge 2 ] || { echo "ERROR: --shared-dir requires a path" >&2; exit 2; }
        shared_dir="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "ERROR: unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done

  if [ -z "$shared_dir" ]; then
    echo "ERROR: missing --shared-dir" >&2
    usage >&2
    exit 2
  fi

  shared_dir="$(${pkgs.coreutils}/bin/realpath -m "$shared_dir")"
  mkdir -p "$shared_dir/tidefs-validation"

  run_dir="$(${pkgs.coreutils}/bin/mktemp -d "''${TMPDIR:-/tmp}/tidefs-k7-vfs-xfstests-vm.XXXXXXXXXX")"
  cleanup() {
    rm -rf "$run_dir"
  }
  trap cleanup EXIT

  export SHARED_DIR="$shared_dir"
  export TMPDIR="$run_dir/tmp"
  export USE_TMPDIR=1
  export NIX_DISK_IMAGE="$run_dir/nixos.qcow2"
  export QEMU_KERNEL_PARAMS="console=ttyS0 systemd.journald.forward_to_console=1 nosmp maxcpus=1 clocksource=acpi_pm tsc=unstable rcu_cpu_stall_timeout=120 ''${QEMU_KERNEL_PARAMS:-}"
  export TIDEFS_K7_TFS_XFSTESTS_QEMU_ACCEL="''${TIDEFS_K7_TFS_XFSTESTS_QEMU_ACCEL:-kvm:tcg}"
  export TIDEFS_K7_TFS_XFSTESTS_DISABLE_HOST_TIMEOUT="''${TIDEFS_K7_TFS_XFSTESTS_DISABLE_HOST_TIMEOUT:-0}"
  case "$TIDEFS_K7_TFS_XFSTESTS_QEMU_ACCEL" in
    *[!A-Za-z0-9:._-]*|"")
      echo "ERROR: unsafe TIDEFS_K7_TFS_XFSTESTS_QEMU_ACCEL: $TIDEFS_K7_TFS_XFSTESTS_QEMU_ACCEL" >&2
      exit 2
      ;;
  esac
  case "$TIDEFS_K7_TFS_XFSTESTS_DISABLE_HOST_TIMEOUT" in
    0|1)
      ;;
    *)
      echo "ERROR: unsafe TIDEFS_K7_TFS_XFSTESTS_DISABLE_HOST_TIMEOUT: $TIDEFS_K7_TFS_XFSTESTS_DISABLE_HOST_TIMEOUT" >&2
      exit 2
      ;;
  esac
  mkdir -p "$TMPDIR"

  qemu_log="$shared_dir/tidefs-validation/qemu.log"
  qemu_wrapper_log="$shared_dir/tidefs-validation/qemu-wrapper.log"

  local_vm_runner="$run_dir/run-nixos-vm"
  cp ${vmRunner} "$local_vm_runner"
  chmod u+w "$local_vm_runner"
  qemu_log_sed="$(${pkgs.coreutils}/bin/printf '%s' "$qemu_log" | ${pkgs.gnused}/bin/sed 's/[&\\]/\\&/g')"
  ${pkgs.gnused}/bin/sed -i \
    -e "s/-machine accel=kvm:tcg/-machine accel=$TIDEFS_K7_TFS_XFSTESTS_QEMU_ACCEL/" \
    -e "s|-nographic|-display none -serial file:$qemu_log_sed -monitor none|" \
    "$local_vm_runner"

  echo "tidefs_k7_xfstests.boundary=outside-nix-build-sandbox"
  echo "tidefs_k7_xfstests.vm_runner=${vmRunner}"
  echo "tidefs_k7_xfstests.qemu_accel=$TIDEFS_K7_TFS_XFSTESTS_QEMU_ACCEL"
  echo "tidefs_k7_xfstests.qemu_log=$qemu_log"
  echo "tidefs_k7_xfstests.qemu_wrapper_log=$qemu_wrapper_log"
  echo "tidefs_k7_xfstests.shared_dir=$shared_dir"
  echo "tidefs_k7_xfstests.timeout_seconds=${toString timeoutSec}"
  echo "tidefs_k7_xfstests.host_timeout_disabled=$TIDEFS_K7_TFS_XFSTESTS_DISABLE_HOST_TIMEOUT"
  echo "tidefs_k7_xfstests.local_host_kernel_used=false"

  write_interrupted_json() {
    local signal_name="$1"
    local reason="$2"
    local validation_json="$shared_dir/tidefs-validation/validation.json"

    if [ -f "$validation_json" ]; then
      return 0
    fi
    ${pkgs.jq}/bin/jq -n \
      --arg signal "$signal_name" \
      --arg reason "$reason" \
      --argjson requested '${builtins.toJSON requestedTests}' \
      '{
        test: "tidefs-k7-vfs-xfstests-validation",
        version: 4,
        harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
        scope: "kernel-vfs-linux-7.0",
        execution_boundary: "qemu-launched-outside-nix-build-sandbox",
        local_host_kernel_used: false,
        requested_tests: $requested,
        results: ([{
          name: "qemu_launcher_interrupted",
          status: "harness-fail",
          tier: "QemuGuest",
          failure_class: "QemuLauncherInterrupted",
          output: ($reason + " (" + $signal + ")")
        }] + ($requested | map({
          name: .,
          status: "harness-fail",
          tier: "QemuGuest",
          failure_class: "QemuLauncherInterrupted",
          output: ($reason + " (" + $signal + ")")
        }))),
        passed: 0,
        product_failures: 0,
        harness_failures: ($requested | length),
        environment_refusals: 0,
        skipped: 0,
        unsupported: 0,
        deferred: 0,
        failed: ($requested | length),
        requested_result_count: ($requested | length),
        infrastructure_result_count: 1,
        infrastructure_passed: 0,
        infrastructure_product_failures: 0,
        infrastructure_harness_failures: 1,
        infrastructure_environment_refusals: 0,
        infrastructure_skipped: 0,
        infrastructure_unsupported: 0,
        infrastructure_deferred: 0,
        artifacts: { qemu: "qemu.log", qemu_wrapper: "qemu-wrapper.log" }
      }' > "$validation_json"
  }

  write_missing_validation_json() {
    local reason="$1"
    local validation_json="$shared_dir/tidefs-validation/validation.json"

    if [ -f "$validation_json" ]; then
      return 0
    fi
    ${pkgs.jq}/bin/jq -n \
      --arg reason "$reason" \
      --argjson requested '${builtins.toJSON requestedTests}' \
      '{
        test: "tidefs-k7-vfs-xfstests-validation",
        version: 4,
        harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
        scope: "kernel-vfs-linux-7.0",
        execution_boundary: "qemu-launched-outside-nix-build-sandbox",
        local_host_kernel_used: false,
        requested_tests: $requested,
        results: ([{
          name: "guest_validation_missing",
          status: "harness-fail",
          tier: "QemuGuest",
          failure_class: "QemuGuestValidationMissing",
          output: $reason
        }] + ($requested | map({
          name: .,
          status: "harness-fail",
          tier: "QemuGuest",
          failure_class: "QemuGuestValidationMissing",
          output: $reason
        }))),
        passed: 0,
        product_failures: 0,
        harness_failures: ($requested | length),
        environment_refusals: 0,
        skipped: 0,
        unsupported: 0,
        deferred: 0,
        failed: ($requested | length),
        requested_result_count: ($requested | length),
        infrastructure_result_count: 1,
        infrastructure_passed: 0,
        infrastructure_product_failures: 0,
        infrastructure_harness_failures: 1,
        infrastructure_environment_refusals: 0,
        infrastructure_skipped: 0,
        infrastructure_unsupported: 0,
        infrastructure_deferred: 0,
        artifacts: { qemu: "qemu.log", qemu_wrapper: "qemu-wrapper.log" }
      }' > "$validation_json"
  }

  mark_partial_timeout_json() {
    local rc="$1"
    local validation_json="$shared_dir/tidefs-validation/validation.json"

    if [ ! -f "$validation_json" ]; then
      return 0
    fi

    ${pkgs.python3}/bin/python3 - "$validation_json" "$rc" <<'PY'
import json
import os
import sys

path, rc = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8", errors="replace") as fh:
    validation = json.load(fh)

requested = [str(item) for item in validation.get("requested_tests", [])]
requested_set = set(requested)
results = validation.setdefault("results", [])
seen = {str(row.get("name", "")) for row in results}
missing = [name for name in requested if name not in seen]
if not missing:
    sys.exit(0)

active_xfstest = str(validation.get("active_xfstest") or "")
active_case = str(validation.get("active_xfstest_case") or "")
active_stage = str(validation.get("active_xfstest_stage") or "")
active_note = ""
if active_xfstest:
    active_note = (
        f"; active_xfstest={active_xfstest}"
        f" active_case={active_case or 'unknown'}"
        f" active_stage={active_stage or 'unknown'}"
    )

if rc in {"124", "137"}:
    failure_class = "QemuGuestTimeout"
    reason = (
        f"QEMU runner timed out with rc={rc} after partial guest validation; "
        "missing requested rows did not reach structured guest classification; "
        "inspect qemu.log and qemu-wrapper.log"
        f"{active_note}"
    )
    marker_name = "qemu_guest_timeout_after_partial_validation"
else:
    failure_class = "QemuGuestExitAfterPartialValidation"
    reason = (
        f"QEMU runner exited with rc={rc} after partial guest validation; "
        "missing requested rows did not reach structured guest classification; "
        "inspect qemu.log and qemu-wrapper.log"
        f"{active_note}"
    )
    marker_name = "qemu_guest_exit_after_partial_validation"

if marker_name not in seen:
    results.append({
        "name": marker_name,
        "status": "harness-fail",
        "tier": "QemuGuest",
        "failure_class": failure_class,
        "output": reason,
    })

for name in missing:
    row_failure_class = failure_class
    if rc in {"124", "137"} and active_xfstest and name == active_xfstest:
        row_failure_class = "QemuGuestTimeoutDuringActiveXfstest"
    results.append({
        "name": name,
        "status": "harness-fail",
        "tier": "QemuGuest",
        "failure_class": row_failure_class,
        "output": reason,
    })

def requested_row(row):
    return str(row.get("name", "")) in requested_set

def count(status, *, requested_only):
    return sum(
        1
        for row in results
        if row.get("status") == status
        and requested_row(row) == requested_only
    )

validation["passed"] = count("pass", requested_only=True)
validation["product_failures"] = count("product-fail", requested_only=True)
validation["harness_failures"] = count("harness-fail", requested_only=True)
validation["environment_refusals"] = count("environment-refusal", requested_only=True)
validation["skipped"] = count("skip", requested_only=True)
validation["unsupported"] = count("unsupported", requested_only=True)
validation["deferred"] = count("deferred", requested_only=True)
validation["failed"] = validation["product_failures"] + validation["harness_failures"]
validation["requested_result_count"] = sum(1 for row in results if requested_row(row))
validation["infrastructure_result_count"] = sum(1 for row in results if not requested_row(row))
validation["infrastructure_passed"] = count("pass", requested_only=False)
validation["infrastructure_product_failures"] = count("product-fail", requested_only=False)
validation["infrastructure_harness_failures"] = count("harness-fail", requested_only=False)
validation["infrastructure_environment_refusals"] = count("environment-refusal", requested_only=False)
validation["infrastructure_skipped"] = count("skip", requested_only=False)
validation["infrastructure_unsupported"] = count("unsupported", requested_only=False)
validation["infrastructure_deferred"] = count("deferred", requested_only=False)
validation["artifacts"] = {
    "dmesg": "dmesg.log",
    "journal": "journal.log",
    "qemu": "qemu.log",
    "qemu_wrapper": "qemu-wrapper.log",
}

tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(validation, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(tmp, path)
PY
  }

  QEMU_RUNNER_PID=""
  interrupt_qemu_runner() {
    local rc="$1"
    local signal_name="$2"
    local reason="host VM launcher interrupted before guest completed validation"

    if [ -n "$QEMU_RUNNER_PID" ]; then
      kill -TERM "$QEMU_RUNNER_PID" 2>/dev/null || true
      wait "$QEMU_RUNNER_PID" 2>/dev/null || true
      QEMU_RUNNER_PID=""
    fi
    write_interrupted_json "$signal_name" "$reason"
    exit "$rc"
  }
  trap 'interrupt_qemu_runner 129 HUP' HUP
  trap 'interrupt_qemu_runner 130 INT' INT
  trap 'interrupt_qemu_runner 143 TERM' TERM

  set +e
  if [ "$TIDEFS_K7_TFS_XFSTESTS_DISABLE_HOST_TIMEOUT" = 1 ]; then
    "$local_vm_runner" > "$qemu_wrapper_log" 2>&1 &
  else
    ${pkgs.coreutils}/bin/timeout --foreground --kill-after=60s ${toString timeoutSec} \
      "$local_vm_runner" > "$qemu_wrapper_log" 2>&1 &
  fi
  QEMU_RUNNER_PID=$!
  wait "$QEMU_RUNNER_PID"
  vm_rc=$?
  QEMU_RUNNER_PID=""
  set -e

  if [ "$vm_rc" -ne 0 ]; then
    echo "tidefs_k7_xfstests.qemu_exit=$vm_rc"
    echo "tidefs_k7_xfstests.qemu_log=$qemu_log"
    echo "tidefs_k7_xfstests.qemu_wrapper_log=$qemu_wrapper_log"
    ${pkgs.coreutils}/bin/tail -n 80 "$qemu_wrapper_log" >&2 || true
    ${pkgs.coreutils}/bin/tail -n 200 "$qemu_log" >&2 || true
  fi

  if [ "$vm_rc" -ne 0 ] && [ ! -f "$shared_dir/tidefs-validation/validation.json" ]; then
    if [ "$vm_rc" -eq 124 ] || [ "$vm_rc" -eq 137 ]; then
      ${pkgs.jq}/bin/jq -n \
        --arg rc "$vm_rc" \
        --arg log "qemu.log" \
        --argjson requested '${builtins.toJSON requestedTests}' \
        '{
          test: "tidefs-k7-vfs-xfstests-validation",
          version: 4,
          harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
          scope: "kernel-vfs-linux-7.0",
          execution_boundary: "qemu-launched-outside-nix-build-sandbox",
          local_host_kernel_used: false,
          requested_tests: $requested,
          results: ([{
            name: "qemu_guest_timeout",
            status: "harness-fail",
            tier: "QemuGuest",
            failure_class: "QemuGuestTimeout",
            output: ("QEMU runner timed out before guest validation JSON with rc=" + $rc + "; inspect qemu.log and qemu-wrapper.log")
          }] + ($requested | map({
            name: .,
            status: "harness-fail",
            tier: "QemuGuest",
            failure_class: "QemuGuestTimeout",
            output: ("QEMU runner timed out before guest validation JSON with rc=" + $rc + "; inspect qemu.log and qemu-wrapper.log")
          }))),
          passed: 0,
          product_failures: 0,
          harness_failures: ($requested | length),
          environment_refusals: 0,
          skipped: 0,
          unsupported: 0,
          deferred: 0,
          failed: ($requested | length),
          requested_result_count: ($requested | length),
          infrastructure_result_count: 1,
          infrastructure_passed: 0,
          infrastructure_product_failures: 0,
          infrastructure_harness_failures: 1,
          infrastructure_environment_refusals: 0,
          infrastructure_skipped: 0,
          infrastructure_unsupported: 0,
          infrastructure_deferred: 0,
          artifacts: { qemu: $log, qemu_wrapper: "qemu-wrapper.log" }
        }' > "$shared_dir/tidefs-validation/validation.json"
    else
      ${pkgs.jq}/bin/jq -n \
        --arg rc "$vm_rc" \
        --arg log "qemu.log" \
        --argjson requested '${builtins.toJSON requestedTests}' \
        '{
          test: "tidefs-k7-vfs-xfstests-validation",
          version: 4,
          harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
          scope: "kernel-vfs-linux-7.0",
          execution_boundary: "qemu-launched-outside-nix-build-sandbox",
          local_host_kernel_used: false,
          requested_tests: $requested,
          results: ([{
            name: "qemu_launch",
            status: "environment-refusal",
            tier: "QemuGuest",
            failure_class: "QemuLaunchFailure",
            output: ("QEMU runner exited before guest validation with rc=" + $rc)
          }] + ($requested | map({
            name: .,
            status: "environment-refusal",
            tier: "QemuGuest",
            failure_class: "QemuLaunchFailure",
            output: ("QEMU runner exited before guest validation with rc=" + $rc)
          }))),
          passed: 0,
          product_failures: 0,
          harness_failures: 0,
          environment_refusals: ($requested | length),
          skipped: 0,
          unsupported: 0,
          deferred: 0,
          failed: 0,
          requested_result_count: ($requested | length),
          infrastructure_result_count: 1,
          infrastructure_passed: 0,
          infrastructure_product_failures: 0,
          infrastructure_harness_failures: 0,
          infrastructure_environment_refusals: 1,
          infrastructure_skipped: 0,
          infrastructure_unsupported: 0,
          infrastructure_deferred: 0,
          artifacts: { qemu: $log, qemu_wrapper: "qemu-wrapper.log" }
      }' > "$shared_dir/tidefs-validation/validation.json"
    fi
  elif [ "$vm_rc" -ne 0 ]; then
    mark_partial_timeout_json "$vm_rc"
  fi

  if [ ! -f "$shared_dir/tidefs-validation/validation.json" ]; then
    echo "ERROR: VM completed without validation.json; writing harness-fail validation" >&2
    ${pkgs.coreutils}/bin/tail -n 80 "$qemu_wrapper_log" >&2 || true
    ${pkgs.coreutils}/bin/tail -n 200 "$qemu_log" >&2 || true
    write_missing_validation_json "VM completed without guest validation.json; inspect qemu.log and qemu-wrapper.log"
  fi

  exit 0
''
