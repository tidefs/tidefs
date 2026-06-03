# TideFS: kernel VFS xfstests validation in a NixOS VM.
#
# This wrapper keeps the historical CLI name but delegates validation to a
# generated NixOS VM runner. Nix realizes the VM closure and scripts only; the
# wrapper launches QEMU outside the Nix build sandbox so /dev/kvm and all kernel
# runtime state belong to the disposable guest boundary, not the Nix builder or
# local host kernel.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
  xfstests,
  tidefsPosixVfsKmod ? null,
}:

let
  nixosTestTemplate = ./k7-vfs-xfstests-nixos-test.nix;

  script = pkgs.writeShellScriptBin "tidefs-k7-vfs-xfstests-validation" ''
    set -euo pipefail

    DEFAULT_TESTS="generic/001 generic/002 generic/003 generic/004 generic/005 generic/006 generic/007 generic/008 generic/009 generic/010 generic/011 generic/012 generic/013"
    TIMEOUT_SEC="''${TIDEFS_K7_TFS_XFSTESTS_TIMEOUT:-1800}"
    PER_TEST_TIMEOUT_SEC="''${TIDEFS_K7_TFS_XFSTESTS_PER_TEST_TIMEOUT:-180}"
    DISK_SIZE_MB="''${TIDEFS_K7_TFS_XFSTESTS_DISK_SIZE_MB:-2048}"
    REQUIRE_KVM="''${TIDEFS_K7_TFS_XFSTESTS_REQUIRE_KVM:-1}"
    ISOLATE_ROWS="''${TIDEFS_K7_TFS_XFSTESTS_ISOLATE_ROWS:-0}"
    TMPDIR_ROOT="''${TIDEFS_K7_TFS_XFSTESTS_TMPDIR:-/tmp/tidefs-k7-vfs-xfstests-validation}"

    usage() {
      cat <<EOF
Usage: tidefs-k7-vfs-xfstests-validation [--timeout SECONDS] [--per-test-timeout SECONDS]
       [--disk-size-mb MB] [--keep-tmp] [--isolate-rows] [--module PATH]
       [--tests "generic/001 ..."|"generic/001-013"] [--output JSON]

Run real upstream xfstests-check inside a NixOS VM booted with Linux 7.0 and a
loaded tidefs_posix_vfs.ko. Nix builds the runner artifacts, then QEMU starts
outside the Nix build sandbox. The requested xfstests rows are written in
JSON validation with pass/product-fail/harness-fail/environment-refusal/skip/
unsupported/deferred classification.

Options:
  --module PATH              tidefs_posix_vfs.ko built for the Linux 7.0 guest
                             (default: Nix-built module matching this VM kernel)
  --tests "T1 T2 ..."        Space-separated tests or simple numeric ranges to run
                             (default: generic/001-generic/013 smoke subset)
  --timeout SECONDS          Artifact realization and VM runtime timeout
                             (default: $TIMEOUT_SEC)
  --per-test-timeout SECONDS Per xfstests row timeout in the guest
                             (default: $PER_TEST_TIMEOUT_SEC)
  --disk-size-mb MB          Empty TideFS pool disk size (default: $DISK_SIZE_MB)
  --output PATH              Copy validation JSON to PATH
  --keep-tmp                 Keep wrapper temp directory
  --isolate-rows             Boot one fresh QEMU VM per requested xfstests row,
                             then merge row validation into one output JSON
  --help, -h                 Show this message

Exit codes:
  0   No product, harness, or environment failures were recorded
  1   One or more product or harness failures were recorded
  2   Argument or environment refusal before a complete run
EOF
    }

    KEEP_TMP=0
    TEST_LIST="$DEFAULT_TESTS"
    AUTO_KO_PATH="${if tidefsPosixVfsKmod == null then "" else "${tidefsPosixVfsKmod}/tidefs_posix_vfs.ko"}"
    KO_PATH_ARG="''${TIDEFS_K7_TFS_XFSTESTS_MODULE:-}"
    JSON_OUT=""

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --per-test-timeout) PER_TEST_TIMEOUT_SEC="$2"; shift 2 ;;
        --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --tests) TEST_LIST="$2"; shift 2 ;;
        --module) KO_PATH_ARG="$2"; shift 2 ;;
        --output) JSON_OUT="$2"; shift 2 ;;
        --isolate-rows) ISOLATE_ROWS=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    numeric_re='^[0-9]+$'
    for value_name in TIMEOUT_SEC PER_TEST_TIMEOUT_SEC DISK_SIZE_MB; do
      value="''${!value_name}"
      if ! [[ "$value" =~ $numeric_re ]]; then
        echo "ERROR: $value_name must be numeric, got: $value" >&2
        exit 2
      fi
    done
    case "$ISOLATE_ROWS" in
      0|1) ;;
      *) echo "ERROR: TIDEFS_K7_TFS_XFSTESTS_ISOLATE_ROWS must be 0 or 1, got: $ISOLATE_ROWS" >&2; exit 2 ;;
    esac

    RUN_DIR="$TMPDIR_ROOT/run-$$"
    mkdir -p "$RUN_DIR"
    RUN_COMPLETE=0
    JSON_DIR=""
    if [ -n "$JSON_OUT" ]; then
      JSON_DIR="$(${pkgs.coreutils}/bin/dirname "$JSON_OUT")"
      mkdir -p "$JSON_DIR"
      VALIDATION_DIR="$JSON_DIR/vm-shared"
    else
      VALIDATION_DIR="$RUN_DIR/validation"
    fi
    cleanup() {
      local rc=$?
      if [ -n "$JSON_OUT" ] && [ -d "$VALIDATION_DIR/tidefs-validation" ]; then
        mkdir -p "$JSON_DIR"
        cp -a "$VALIDATION_DIR/tidefs-validation"/. "$JSON_DIR"/ 2>/dev/null || true
      fi
      if [ "$KEEP_TMP" -eq 1 ] || [ -z "$JSON_OUT" ]; then
        echo "Keeping temp directory: $RUN_DIR"
      else
        rm -rf "$RUN_DIR"
      fi
      if [ "$RUN_COMPLETE" -eq 1 ] && [ "$KEEP_TMP" -eq 0 ] && [ -n "$JSON_OUT" ]; then
        rm -rf "$VALIDATION_DIR"
      fi
      exit "$rc"
    }
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    REPO_ROOT="''${TIDEFS_REPO_ROOT:-}"
    if [ -z "$REPO_ROOT" ]; then
      REPO_ROOT="$(${pkgs.git}/bin/git -C "$PWD" rev-parse --show-toplevel 2>/dev/null || pwd)"
    fi
    REPO_ROOT="$(${pkgs.coreutils}/bin/realpath "$REPO_ROOT")"

    TESTS_JSON="$RUN_DIR/tests.json"
    TEST_LIST_RAW="$TEST_LIST" ${pkgs.python3}/bin/python3 - "$RUN_DIR/tests.list" <<'PY'
import os
import re
import sys

out_path = sys.argv[1]
raw = os.environ.get("TEST_LIST_RAW", "")
safe_re = re.compile(r"^[A-Za-z0-9_.+/-]+$")
range_re = re.compile(r"^([A-Za-z0-9_.+-]+)/([0-9]+)-([0-9]+)$")
qualified_range_re = re.compile(
    r"^([A-Za-z0-9_.+-]+)/([0-9]+)-([A-Za-z0-9_.+-]+)/([0-9]+)$"
)

expanded = []
for token in raw.split():
    if not token or not safe_re.fullmatch(token):
        print(f"ERROR: refusing unsafe xfstests name: {token}", file=sys.stderr)
        sys.exit(2)

    match = qualified_range_re.fullmatch(token)
    if match:
        group_a, start_s, group_b, end_s = match.groups()
        if group_a != group_b:
            print(f"ERROR: refusing cross-group xfstests range: {token}", file=sys.stderr)
            sys.exit(2)
        group = group_a
    else:
        match = range_re.fullmatch(token)
        if not match:
            expanded.append(token)
            continue
        group, start_s, end_s = match.groups()

    start = int(start_s, 10)
    end = int(end_s, 10)
    if end < start:
        print(f"ERROR: refusing descending xfstests range: {token}", file=sys.stderr)
        sys.exit(2)
    if end - start > 999:
        print(f"ERROR: refusing oversized xfstests range: {token}", file=sys.stderr)
        sys.exit(2)

    width = max(len(start_s), len(end_s))
    for number in range(start, end + 1):
        expanded.append(f"{group}/{number:0{width}d}")

if not expanded:
    print("ERROR: no xfstests rows requested", file=sys.stderr)
    sys.exit(2)

with open(out_path, "w", encoding="utf-8") as out:
    for test_name in expanded:
        out.write(test_name + "\n")
PY
    ${pkgs.jq}/bin/jq -R -s -c 'split("\n") | map(select(length > 0))' \
      < "$RUN_DIR/tests.list" > "$TESTS_JSON"

    write_refusal_json() {
      local reason="$1"
      local out="$2"
      if [ -z "$out" ]; then
        return 0
      fi
      mkdir -p "$(${pkgs.coreutils}/bin/dirname "$out")"
      ${pkgs.jq}/bin/jq -n \
        --slurpfile tests "$TESTS_JSON" \
        --arg reason "$reason" \
        '{
          test: "tidefs-k7-vfs-xfstests-validation",
          version: 4,
          harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
          scope: "kernel-vfs-linux-7.0",
          execution_boundary: "qemu-launched-outside-nix-build-sandbox",
          local_host_kernel_used: false,
          requested_tests: $tests[0],
          results: ($tests[0] | map({
            name: .,
            status: "environment-refusal",
            tier: "QemuGuest",
            failure_class: "EnvironmentRefusal",
            output: $reason
          })),
          passed: 0,
          product_failures: 0,
          harness_failures: 0,
          environment_refusals: ($tests[0] | length),
          skipped: 0,
          unsupported: 0,
          deferred: 0,
          failed: 0,
          requested_result_count: ($tests[0] | length),
          infrastructure_result_count: 0,
          infrastructure_passed: 0,
          infrastructure_product_failures: 0,
          infrastructure_harness_failures: 0,
          infrastructure_environment_refusals: 0,
          infrastructure_skipped: 0,
          infrastructure_unsupported: 0,
          infrastructure_deferred: 0
        }' > "$out"
    }

    write_interrupted_json() {
      local signal_name="$1"
      local reason="$2"
      local validation_json="$VALIDATION_DIR/tidefs-validation/validation.json"

      if [ -f "$validation_json" ]; then
        return 0
      fi
      mkdir -p "$VALIDATION_DIR/tidefs-validation"
      ${pkgs.jq}/bin/jq -n \
        --slurpfile tests "$TESTS_JSON" \
        --arg signal "$signal_name" \
        --arg reason "$reason" \
        '{
          test: "tidefs-k7-vfs-xfstests-validation",
          version: 4,
          harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
          scope: "kernel-vfs-linux-7.0",
          execution_boundary: "qemu-launched-outside-nix-build-sandbox",
          local_host_kernel_used: false,
          requested_tests: $tests[0],
          results: ([{
            name: "host_wrapper_interrupted",
            status: "harness-fail",
            tier: "QemuGuest",
            failure_class: "HostRunnerInterrupted",
            output: ($reason + " (" + $signal + ")")
          }] + ($tests[0] | map({
            name: .,
            status: "harness-fail",
            tier: "QemuGuest",
            failure_class: "HostRunnerInterrupted",
            output: ($reason + " (" + $signal + ")")
          }))),
          passed: 0,
          product_failures: 0,
          harness_failures: ($tests[0] | length),
          environment_refusals: 0,
          skipped: 0,
          unsupported: 0,
          deferred: 0,
          failed: ($tests[0] | length),
          requested_result_count: ($tests[0] | length),
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

    write_vm_runner_failure_json() {
      local runner_rc="$1"
      local reason="$2"
      local validation_json="$VALIDATION_DIR/tidefs-validation/validation.json"

      if [ -f "$validation_json" ]; then
        return 0
      fi
      mkdir -p "$VALIDATION_DIR/tidefs-validation"
      ${pkgs.jq}/bin/jq -n \
        --slurpfile tests "$TESTS_JSON" \
        --argjson runner_rc "$runner_rc" \
        --arg reason "$reason" \
        '{
          test: "tidefs-k7-vfs-xfstests-validation",
          version: 4,
          harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
          scope: "kernel-vfs-linux-7.0",
          execution_boundary: "qemu-launched-outside-nix-build-sandbox",
          local_host_kernel_used: false,
          requested_tests: $tests[0],
          results: ([{
            name: "qemu_runner",
            status: "harness-fail",
            tier: "QemuGuest",
            failure_class: "MissingGuestValidation",
            output: ($reason + " (runner_rc=" + ($runner_rc|tostring) + ")")
          }] + ($tests[0] | map({
            name: .,
            status: "harness-fail",
            tier: "MountedKernelVfs",
            failure_class: "MissingGuestValidation",
            output: ($reason + " (runner_rc=" + ($runner_rc|tostring) + ")")
          }))),
          passed: 0,
          product_failures: 0,
          harness_failures: ($tests[0] | length),
          environment_refusals: 0,
          skipped: 0,
          unsupported: 0,
          deferred: 0,
          failed: ($tests[0] | length),
          requested_result_count: ($tests[0] | length),
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

    write_pre_guest_failure_json() {
      local tests_json="$1"
      local validation_json="$2"
      local rc="$3"
      local failure_class="$4"
      local marker_name="$5"
      local reason="$6"
      local build_log_rel="$7"

      if [ -f "$validation_json" ]; then
        return 0
      fi
      mkdir -p "$(${pkgs.coreutils}/bin/dirname "$validation_json")"
      ${pkgs.jq}/bin/jq -n \
        --slurpfile tests "$tests_json" \
        --arg rc "$rc" \
        --arg failure_class "$failure_class" \
        --arg marker_name "$marker_name" \
        --arg reason "$reason" \
        --arg build_log_rel "$build_log_rel" \
        '{
          test: "tidefs-k7-vfs-xfstests-validation",
          version: 4,
          harness: "nixos-vm-outside-nix-sandbox-upstream-xfstests",
          scope: "kernel-vfs-linux-7.0",
          execution_boundary: "qemu-launched-outside-nix-build-sandbox",
          local_host_kernel_used: false,
          requested_tests: $tests[0],
          results: ([{
            name: $marker_name,
            status: "harness-fail",
            tier: "QemuGuest",
            failure_class: $failure_class,
            output: ($reason + " (rc=" + $rc + ")"),
            log_path: $build_log_rel
          }] + ($tests[0] | map({
            name: .,
            status: "harness-fail",
            tier: "QemuGuest",
            failure_class: $failure_class,
            output: ($reason + " (rc=" + $rc + ")"),
            log_path: $build_log_rel
          }))),
          passed: 0,
          product_failures: 0,
          harness_failures: ($tests[0] | length),
          environment_refusals: 0,
          skipped: 0,
          unsupported: 0,
          deferred: 0,
          failed: ($tests[0] | length),
          requested_result_count: ($tests[0] | length),
          infrastructure_result_count: 1,
          infrastructure_passed: 0,
          infrastructure_product_failures: 0,
          infrastructure_harness_failures: 1,
          infrastructure_environment_refusals: 0,
          infrastructure_skipped: 0,
          infrastructure_unsupported: 0,
          infrastructure_deferred: 0,
          artifacts: {
            qemu: "qemu.log",
            qemu_wrapper: "qemu-wrapper.log",
            nix_vm_build: $build_log_rel
          }
        }' > "$validation_json"
    }

    VM_RUNNER_PID=""
    interrupt_run() {
      local rc="$1"
      local signal_name="$2"
      local reason="host xfstests wrapper interrupted before guest completed validation"

      if [ -n "$VM_RUNNER_PID" ]; then
        kill -TERM "$VM_RUNNER_PID" 2>/dev/null || true
        wait "$VM_RUNNER_PID" 2>/dev/null || true
        VM_RUNNER_PID=""
      fi
      write_interrupted_json "$signal_name" "$reason"
      exit "$rc"
    }
    trap 'interrupt_run 129 HUP' HUP
    trap 'interrupt_run 130 INT' INT
    trap 'interrupt_run 143 TERM' TERM

    REPO_SOURCE_ROOT="$REPO_ROOT"
    REPO_SOURCE_SNAPSHOT_DIR="$RUN_DIR/repo-source"
    mkdir -p "$REPO_SOURCE_SNAPSHOT_DIR"
    if ! (
      cd "$REPO_ROOT"
      ${pkgs.gnutar}/bin/tar \
        --exclude=.git \
        --exclude=.direnv \
        --exclude=target \
        --exclude=result \
        --exclude='result-*' \
        --exclude='validation/runs' \
        -cf - .
    ) | ${pkgs.gnutar}/bin/tar -C "$REPO_SOURCE_SNAPSHOT_DIR" -xf -; then
      reason="failed to snapshot TideFS source tree before validation"
      echo "ERROR: $reason" >&2
      write_refusal_json "$reason" "$JSON_OUT"
      exit 2
    fi
    REPO_SOURCE_ROOT="$(${pkgs.nix}/bin/nix store add-path --name tidefs-validation-source "$REPO_SOURCE_SNAPSHOT_DIR")"

    if [ "$REQUIRE_KVM" = "1" ] && [ ! -e /dev/kvm ]; then
      reason="/dev/kvm not available; set TIDEFS_K7_TFS_XFSTESTS_REQUIRE_KVM=0 to allow software QEMU"
      echo "ENVIRONMENT-REFUSAL: $reason" >&2
      write_refusal_json "$reason" "$JSON_OUT"
      exit 2
    fi

    if [ -z "$KO_PATH_ARG" ] && [ -n "$AUTO_KO_PATH" ]; then
      KO_PATH_ARG="$AUTO_KO_PATH"
    fi

    if [ -z "$KO_PATH_ARG" ]; then
      reason="--module PATH is required; build tidefs_posix_vfs.ko for the Linux 7.0 guest before running xfstests"
      echo "ERROR: $reason" >&2
      write_refusal_json "$reason" "$JSON_OUT"
      exit 2
    fi
    if [ ! -f "$KO_PATH_ARG" ]; then
      reason="module file does not exist: $KO_PATH_ARG"
      echo "ERROR: $reason" >&2
      write_refusal_json "$reason" "$JSON_OUT"
      exit 2
    fi
    KO_PATH="$(${pkgs.coreutils}/bin/realpath "$KO_PATH_ARG")"
    MODULE_STORE="$(nix store add-file "$KO_PATH")"
    MODULE_NIX_EXPR="$MODULE_STORE"
    HOST_SYSTEM="${pkgs.stdenv.hostPlatform.system}"

    echo "=== TideFS Kernel VFS xfstests Validation (NixOS) ==="
    echo "  Repo:       $REPO_ROOT"
    echo "  Source:     $REPO_SOURCE_ROOT"
    echo "  Kernel:     ${linuxKernel_7_0.version}"
    echo "  Module:     $KO_PATH"
    echo "  xfstests:   upstream xfstests-check from generated NixOS VM"
    echo "  Boundary:   QEMU launched outside Nix build sandbox"
    echo "  Tests:      $TEST_LIST"
    echo "  Timeout:    ''${TIMEOUT_SEC}s overall, ''${PER_TEST_TIMEOUT_SEC}s per test"
    echo "  Disk:       ''${DISK_SIZE_MB} MiB"
    echo "  Isolation:  ''${ISOLATE_ROWS}"
    echo ""

    # shellcheck disable=SC2206
    NIX_BUILD_ARGS=( ''${TIDEFS_K7_TFS_XFSTESTS_NIX_ARGS:---max-jobs 2 --cores 4} )

    build_vm_runner() {
      local tests_json="$1"
      local vm_timeout_sec="$2"
      local tests_store
      local expr
      tests_store="$(nix store add-file "$tests_json")"
      expr="import ${nixosTestTemplate} { system = \"$HOST_SYSTEM\"; repoRoot = \"$REPO_SOURCE_ROOT\"; modulePath = $MODULE_NIX_EXPR; testsJson = $tests_store; timeoutSec = $vm_timeout_sec; perTestTimeoutSec = $PER_TEST_TIMEOUT_SEC; diskSizeMb = $DISK_SIZE_MB; }"
      ${pkgs.coreutils}/bin/timeout "$vm_timeout_sec" \
        nix build --impure --no-link --print-out-paths \
        "''${NIX_BUILD_ARGS[@]}" --expr "$expr"
    }

    run_vm_runner() {
      local result_path="$1"
      local shared_dir="$2"
      mkdir -p "$shared_dir"
      set +e
      "$result_path/bin/tidefs-k7-vfs-xfstests-vm-runner" --shared-dir "$shared_dir" &
      VM_RUNNER_PID=$!
      wait "$VM_RUNNER_PID"
      vm_runner_rc=$?
      VM_RUNNER_PID=""
      set -e
      return "$vm_runner_rc"
    }

    aggregate_isolated_rows() {
      ${pkgs.python3}/bin/python3 - "$TESTS_JSON" "$VALIDATION_DIR/tidefs-validation" "$RUN_DIR/isolated-rows.tsv" <<'PY'
import json
import os
import sys

tests_json, artifact_root, rows_tsv = sys.argv[1:4]
with open(tests_json, "r", encoding="utf-8") as fh:
    requested = json.load(fh)

rows = []
if os.path.exists(rows_tsv):
    with open(rows_tsv, "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                rows.append((parts[0], parts[1], parts[2]))

requested_set = set(requested)
results = []
row_artifacts = {}
kernel_versions = []

for test_name, case_name, row_rc in rows:
    row_rel = os.path.join("rows", case_name)
    row_dir = os.path.join(artifact_root, row_rel)
    row_json_path = os.path.join(row_dir, "validation.json")
    row_artifacts[test_name] = row_rel

    try:
        with open(row_json_path, "r", encoding="utf-8", errors="replace") as fh:
            row_validation = json.load(fh)
    except FileNotFoundError:
        results.append({
            "name": test_name,
            "status": "harness-fail",
            "tier": "QemuGuest",
            "failure_class": "MissingIsolatedRowValidation",
            "output": f"isolated row VM exited with rc={row_rc} without validation.json",
            "isolated_row": test_name,
            "log_path": row_rel,
        })
        continue

    kernel_version = row_validation.get("kernel_version")
    if kernel_version and kernel_version not in kernel_versions:
        kernel_versions.append(kernel_version)

    for row in row_validation.get("results", []):
        entry = dict(row)
        original_name = str(entry.get("name", "unnamed"))
        if original_name not in requested_set:
            entry["name"] = f"{test_name}::{original_name}"
        if entry.get("log_path"):
            entry["log_path"] = os.path.join(row_rel, entry["log_path"])
        entry["isolated_row"] = test_name
        results.append(entry)

attempted_tests = [row[0] for row in rows]
seen_tests = {row.get("name") for row in results if row.get("name") in requested_set}
for test_name in attempted_tests:
    if test_name not in seen_tests:
        case_name = test_name.replace("/", "_")
        row_rel = os.path.join("rows", case_name)
        results.append({
            "name": test_name,
            "status": "harness-fail",
            "tier": "QemuGuest",
            "failure_class": "MissingRequestedRow",
            "output": "isolated aggregate did not contain a structured row for the requested test",
            "isolated_row": test_name,
            "log_path": row_rel,
        })
        row_artifacts.setdefault(test_name, row_rel)

def count(status):
    return sum(
        1 for row in results
        if row.get("name") in requested_set and row.get("status") == status
    )

def count_infrastructure(status):
    return sum(
        1 for row in results
        if row.get("name") not in requested_set and row.get("status") == status
    )

validation = {
    "test": "tidefs-k7-vfs-xfstests-validation",
    "version": 4,
    "harness": "nixos-vm-outside-nix-sandbox-upstream-xfstests",
    "scope": "kernel-vfs-linux-7.0",
    "requested_tests": requested,
    "execution_boundary": "qemu-launched-outside-nix-build-sandbox",
    "local_host_kernel_used": False,
    "row_isolation": "fresh-qemu-per-xfstest",
    "kernel_versions": kernel_versions,
    "results": results,
}
validation["passed"] = count("pass")
validation["product_failures"] = count("product-fail")
validation["harness_failures"] = count("harness-fail")
validation["environment_refusals"] = count("environment-refusal")
validation["skipped"] = count("skip")
validation["unsupported"] = count("unsupported")
validation["deferred"] = count("deferred")
validation["failed"] = validation["product_failures"] + validation["harness_failures"]
validation["requested_result_count"] = sum(1 for row in results if row.get("name") in requested_set)
validation["infrastructure_result_count"] = sum(1 for row in results if row.get("name") not in requested_set)
validation["infrastructure_passed"] = count_infrastructure("pass")
validation["infrastructure_product_failures"] = count_infrastructure("product-fail")
validation["infrastructure_harness_failures"] = count_infrastructure("harness-fail")
validation["infrastructure_environment_refusals"] = count_infrastructure("environment-refusal")
validation["infrastructure_skipped"] = count_infrastructure("skip")
validation["infrastructure_unsupported"] = count_infrastructure("unsupported")
validation["infrastructure_deferred"] = count_infrastructure("deferred")
validation["artifacts"] = {
    "row_index": "isolated-rows.tsv",
    "rows": row_artifacts,
}

os.makedirs(artifact_root, exist_ok=True)
with open(os.path.join(artifact_root, "isolated-rows.tsv"), "w", encoding="utf-8") as out:
    for test_name, case_name, row_rc in rows:
        out.write(f"{test_name}\t{case_name}\t{row_rc}\n")
tmp = os.path.join(artifact_root, "validation.json.tmp")
with open(tmp, "w", encoding="utf-8") as out:
    json.dump(validation, out, indent=2, sort_keys=True)
    out.write("\n")
os.replace(tmp, os.path.join(artifact_root, "validation.json"))
PY
    }

    mkdir -p "$VALIDATION_DIR"
    if [ "$ISOLATE_ROWS" -eq 1 ]; then
      mkdir -p "$VALIDATION_DIR/tidefs-validation/rows"
      : > "$RUN_DIR/isolated-rows.tsv"
      ROW_VM_TIMEOUT_SEC="$((PER_TEST_TIMEOUT_SEC + 300))"
      if [ "$ROW_VM_TIMEOUT_SEC" -gt "$TIMEOUT_SEC" ]; then
        ROW_VM_TIMEOUT_SEC="$TIMEOUT_SEC"
      fi
      while IFS= read -r test_name; do
        [ -n "$test_name" ] || continue
        case_name="$(${pkgs.coreutils}/bin/printf '%s' "$test_name" | ${pkgs.gnused}/bin/sed 's#[^A-Za-z0-9_.+-]#_#g')"
        row_tests_json="$RUN_DIR/tests-$case_name.json"
        ${pkgs.jq}/bin/jq -n --arg test "$test_name" '[$test]' > "$row_tests_json"
        row_shared="$VALIDATION_DIR/row-shared/$case_name"
        row_artifact_dir="$VALIDATION_DIR/tidefs-validation/rows/$case_name"
        row_build_log="$row_artifact_dir/nix-vm-build.log"

        echo "=== Isolated xfstests row: $test_name ==="
        mkdir -p "$row_artifact_dir"
        set +e
        row_result_path="$(build_vm_runner "$row_tests_json" "$ROW_VM_TIMEOUT_SEC" 2> "$row_build_log")"
        row_build_rc=$?
        set -e
        if [ "$row_build_rc" -ne 0 ]; then
          ${pkgs.coreutils}/bin/tail -n 120 "$row_build_log" >&2 || true
          write_pre_guest_failure_json "$row_tests_json" \
            "$row_artifact_dir/validation.json" \
            "$row_build_rc" \
            "NixVmArtifactBuildFailure" \
            "nix_vm_artifact_build" \
            "NixOS xfstests VM artifact build failed before QEMU launch" \
            "nix-vm-build.log"
          printf '%s\t%s\t%s\n' "$test_name" "$case_name" "$row_build_rc" >> "$RUN_DIR/isolated-rows.tsv"
          aggregate_isolated_rows
          continue
        fi
        set +e
        run_vm_runner "$row_result_path" "$row_shared"
        row_rc=$?
        set -e
        if [ -d "$row_shared/tidefs-validation" ]; then
          cp -a "$row_shared/tidefs-validation"/. "$row_artifact_dir"/ 2>/dev/null || true
        fi
        printf '%s\t%s\t%s\n' "$test_name" "$case_name" "$row_rc" >> "$RUN_DIR/isolated-rows.tsv"
        aggregate_isolated_rows
      done < "$RUN_DIR/tests.list"
    else
      BUILD_LOG="$VALIDATION_DIR/tidefs-validation/nix-vm-build.log"
      mkdir -p "$VALIDATION_DIR/tidefs-validation"
      set +e
      RESULT_PATH="$(build_vm_runner "$TESTS_JSON" "$TIMEOUT_SEC" 2> "$BUILD_LOG")"
      build_rc=$?
      set -e
      if [ "$build_rc" -ne 0 ]; then
        ${pkgs.coreutils}/bin/tail -n 120 "$BUILD_LOG" >&2 || true
        write_pre_guest_failure_json "$TESTS_JSON" \
          "$VALIDATION_DIR/tidefs-validation/validation.json" \
          "$build_rc" \
          "NixVmArtifactBuildFailure" \
          "nix_vm_artifact_build" \
          "NixOS xfstests VM artifact build failed before QEMU launch" \
          "nix-vm-build.log"
      else
        set +e
        run_vm_runner "$RESULT_PATH" "$VALIDATION_DIR"
        vm_runner_rc=$?
        set -e
        if [ "$vm_runner_rc" -ne 0 ]; then
          write_vm_runner_failure_json "$vm_runner_rc" \
            "NixOS xfstests VM runner exited before producing guest validation"
        fi
      fi
    fi

    VALIDATION_JSON="$VALIDATION_DIR/tidefs-validation/validation.json"
    if [ ! -f "$VALIDATION_JSON" ]; then
      echo "ERROR: NixOS xfstests VM did not produce $VALIDATION_JSON" >&2
      write_vm_runner_failure_json 2 \
        "NixOS xfstests VM ended without a guest validation file"
    fi

    if [ -n "$JSON_OUT" ]; then
      mkdir -p "$JSON_DIR"
      cp -a "$VALIDATION_DIR/tidefs-validation"/. "$JSON_DIR"/
      cp "$VALIDATION_JSON" "$JSON_OUT"
      RUN_COMPLETE=1
      echo "Validation JSON: $JSON_OUT"
    else
      echo "Validation JSON: $VALIDATION_JSON"
    fi

    product_failures="$(${pkgs.jq}/bin/jq -r '.product_failures // 0' "$VALIDATION_JSON")"
    harness_failures="$(${pkgs.jq}/bin/jq -r '.harness_failures // 0' "$VALIDATION_JSON")"
    environment_refusals="$(${pkgs.jq}/bin/jq -r '.environment_refusals // 0' "$VALIDATION_JSON")"
    passed="$(${pkgs.jq}/bin/jq -r '.passed // 0' "$VALIDATION_JSON")"
    skipped="$(${pkgs.jq}/bin/jq -r '.skipped // 0' "$VALIDATION_JSON")"
    unsupported="$(${pkgs.jq}/bin/jq -r '.unsupported // 0' "$VALIDATION_JSON")"
    deferred="$(${pkgs.jq}/bin/jq -r '.deferred // 0' "$VALIDATION_JSON")"

    echo "Summary: pass=$passed product_fail=$product_failures harness_fail=$harness_failures env_refusal=$environment_refusals skip=$skipped unsupported=$unsupported deferred=$deferred"
    if [ "$environment_refusals" -gt 0 ]; then
      exit 2
    fi
    if [ "$product_failures" -gt 0 ] || [ "$harness_failures" -gt 0 ]; then
      exit 1
    fi
  '';
in
script
