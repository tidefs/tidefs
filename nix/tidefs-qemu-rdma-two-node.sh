#!/usr/bin/env bash
set -euo pipefail


# --- artifact & process cleanup trap ----------------------------------------
_qemu_cleanup() {
  local exit_code=$?
  # Kill any QEMU child processes
  if [[ -n "${_qemu_node_a_pid:-}" ]] && kill -0 "$_qemu_node_a_pid" 2>/dev/null; then
    kill -TERM "$_qemu_node_a_pid" 2>/dev/null || true
    wait "$_qemu_node_a_pid" 2>/dev/null || true
  fi
  if [[ -n "${_qemu_node_b_pid:-}" ]] && kill -0 "$_qemu_node_b_pid" 2>/dev/null; then
    kill -TERM "$_qemu_node_b_pid" 2>/dev/null || true
    wait "$_qemu_node_b_pid" 2>/dev/null || true
  fi
  # Remove temp overlay directory
  if [[ -n "${overlay_dir:-}" ]] && [[ -d "$overlay_dir" ]]; then
    rm -rf "$overlay_dir"
  fi
  # Remove any pid/sock files placed in the working directory
  rm -f qemu.pid qemu.sock qemu-*.pid qemu-*.sock 2>/dev/null || true
  exit "$exit_code"
}
trap _qemu_cleanup EXIT INT TERM
# TideFS two-node QEMU software-RDMA carrier validation harness.
# Boots a disposable node pair with QEMU socket networking, enables
# software RDMA (rxe) inside each guest, runs rdma-probe, and writes
# carrier-classification validation under /root/ai/tmp/tidefs-validation/.

usage() {
  cat <<'EOF'
Usage:
  tidefs-qemu-rdma-two-node --dry-run
  tidefs-qemu-rdma-two-node --validation-dir DIR
    [--kernel KERNEL] [--initrd INITRD] [--nixos-system SYSTEM]
    [--timeout SECONDS]

Boots two QEMU VMs connected via socket networking (node-a listens on
127.0.0.1:19901, node-b connects), enables software RDMA (rxe) on each
node's virtio-net interface, runs rdma-probe inside both guests, and
writes node-pair carrier validation under --validation-dir.

--dry-run prints the planned two-node topology and exits without booting.

Environment:
  TIDEFS_QEMU_KERNEL         path to guest kernel (required for real mode)
  TIDEFS_QEMU_INITRD         path to guest initrd (required for real mode)
  TIDEFS_QEMU_NIXOS_SYSTEM   NixOS system closure exposing kernel/initrd
  TIDEFS_RDMA_ALLOW_MUTATION  must be 1 for any mutating RDMA operation

The mutating --enable-rxe path runs only inside the disposable QEMU
guests. Host-side rdma-probe remains non-mutating.
EOF
}

# --- argument parsing --------------------------------------------------------

mode="run"
validation_dir=""
kernel="${TIDEFS_QEMU_KERNEL:-}"
initrd="${TIDEFS_QEMU_INITRD:-}"
nixos_system="${TIDEFS_QEMU_NIXOS_SYSTEM:-}"
timeout_sec="${TIDEFS_QEMU_TIMEOUT:-120}"
qemu_bin="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --dry-run) mode="dry-run"; shift ;;
    --validation-dir)
      [[ "$#" -lt 2 ]] && { echo "--validation-dir requires a path" >&2; exit 2; }
      validation_dir="$2"; shift 2 ;;
    --kernel)
      [[ "$#" -lt 2 ]] && { echo "--kernel requires a path" >&2; exit 2; }
      kernel="$2"; shift 2 ;;
    --initrd)
      [[ "$#" -lt 2 ]] && { echo "--initrd requires a path" >&2; exit 2; }
      initrd="$2"; shift 2 ;;
    --nixos-system)
      [[ "$#" -lt 2 ]] && { echo "--nixos-system requires a path" >&2; exit 2; }
      nixos_system="$2"; shift 2 ;;
    --timeout)
      [[ "$#" -lt 2 ]] && { echo "--timeout requires seconds" >&2; exit 2; }
      timeout_sec="$2"; shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done

# --- helpers -----------------------------------------------------------------

command_exists() { command -v "$1" >/dev/null 2>&1; }

emit_kv() {
  local key="$1" value="$2"
  printf '%s=%s\n' "$key" "$value"
  if [[ -n "${summary_file:-}" ]]; then
    printf '%s=%s\n' "$key" "$value" >> "$summary_file"
  fi
}

safe_name() { printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'; }

command_line() {
  printf '$'
  printf ' %q' "$@"
  printf '\n'
}

wait_pid_status() {
  local pid="$1"
  if wait "$pid" 2>/dev/null; then
    printf '0\n'
  else
    printf '%s\n' "$?"
  fi
}

# --- dry-run: print planned topology -----------------------------------------

print_topology() {
  cat <<'TOPOLOGY'
two_node_qemu_rdma_topology:
  interconnect: qemu_socket_netdev (virtio-net over TCP 127.0.0.1:19901)
  node_a:
    role: listener
    qemu_netdev: "socket,id=net0,listen=127.0.0.1:19901"
    virtio_net: "virtio-net-pci,netdev=net0,mac=52:54:00:12:34:10"
    software_rdma: rxe on eth0
    guest_ip: 192.168.77.10/24
  node_b:
    role: connector
    qemu_netdev: "socket,id=net0,connect=127.0.0.1:19901"
    virtio_net: "virtio-net-pci,netdev=net0,mac=52:54:00:12:34:20"
    software_rdma: rxe on eth0
    guest_ip: 192.168.77.20/24
  carrier_classification:
    transport: software_rdma_over_virtio_net
    fallback: tcp
    mutating_ops: guarded_by_TIDEFS_RDMA_ALLOW_MUTATION_inside_qemu
  validation_layout:
    root: <validation_dir>
    node_a: <validation_dir>/node-a/
    node_b: <validation_dir>/node-b/
    summary: <validation_dir>/summary.env
TOPOLOGY
}

if [[ "$mode" == "dry-run" ]]; then
  print_topology
  exit 0
fi

# --- run mode ----------------------------------------------------------------

if [[ -z "$validation_dir" ]]; then
  echo "fatal: --validation-dir is required in run mode" >&2
  usage >&2
  exit 2
fi

mkdir -p "$validation_dir"
validation_dir="$(cd "$validation_dir" && pwd -P)"
summary_file="$validation_dir/summary.env"
: > "$summary_file"

emit_kv "harness" "tidefs-qemu-rdma-two-node"
emit_kv "utc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit_kv "mode" "run"

# --- structured refusal builder ----------------------------------------------

refusal_issue_body=""

append_refusal() {
  local component="$1" detail="$2"
  refusal_issue_body+="  - $component: $detail"$'\n'
}

write_reproduction() {
  local args=(nix run .#qemu-rdma-two-node -- --validation-dir "$validation_dir")
  [[ -n "$nixos_system" ]] && args+=(--nixos-system "$nixos_system")
  [[ -n "$kernel" ]] && args+=(--kernel "$kernel")
  [[ -n "$initrd" ]] && args+=(--initrd "$initrd")
  command_line "${args[@]}" | sed 's/^/    /'
}

emit_refusal() {
  local reason="$1"
  local follow_on="${2:-}"

  emit_kv "qemu_rdma_two_node_result" "refused"
  emit_kv "qemu_rdma_two_node_refusal_reason" "$reason"

  cat > "$validation_dir/REFUSAL.md" <<REFUSAL
# QEMU RDMA Two-Node Carrier: Structured Refusal

**Reason**: $reason

## Missing Components

$refusal_issue_body

## Follow-On Issue Body

$follow_on

## Reproduction

$(write_reproduction)

## Environment Snapshot

$(uname -a)
QEMU: $(command_exists "$qemu_bin" && "$qemu_bin" --version 2>&1 | head -1 || echo "not found")
Kernel: ${kernel:-not set}
Initrd: ${initrd:-not set}
NixOS system: ${nixos_system:-not set}
REFUSAL

  echo "refusing: $reason" >&2
  echo "validation output written under $validation_dir/REFUSAL.md" >&2
  exit 3
}

# --- prerequisite probes -----------------------------------------------------

if ! command_exists "$qemu_bin"; then
  append_refusal "qemu_binary" "$qemu_bin not found in PATH"
  emit_refusal \
    "qemu_binary_missing" \
    "Add QEMU system-x86_64 to the validation host packages and re-run."
fi

emit_kv "qemu_binary" "$(command -v "$qemu_bin")"
emit_kv "qemu_version" "$("$qemu_bin" --version 2>&1 | head -1)"

if ! command_exists cpio; then
  append_refusal "cpio" "cpio not found in PATH"
  emit_refusal \
    "cpio_missing" \
    "Add cpio to the qemu-rdma-two-node Nix app so the guest script can be packed into an initramfs overlay."
fi

if ! command_exists gzip; then
  append_refusal "gzip" "gzip not found in PATH"
  emit_refusal \
    "gzip_missing" \
    "Add gzip to the qemu-rdma-two-node Nix app so compressed initrd overlays can be built."
fi

if [[ -n "$nixos_system" ]]; then
  emit_kv "nixos_system" "$nixos_system"
  if [[ ! -d "$nixos_system" ]]; then
    append_refusal "nixos_system" "$nixos_system does not exist or is not a directory"
    emit_refusal \
      "nixos_system_not_found" \
      "Build a NixOS guest system closure and pass its output path via --nixos-system or TIDEFS_QEMU_NIXOS_SYSTEM."
  fi

  if [[ -z "$kernel" ]]; then
    for candidate in "$nixos_system/kernel" "$nixos_system/bzImage"; do
      if [[ -f "$candidate" ]]; then
        kernel="$candidate"
        emit_kv "kernel_source" "nixos_system"
        break
      fi
    done
    if [[ -z "$kernel" ]]; then
      append_refusal "nixos_system.kernel" "$nixos_system has no kernel or bzImage file"
    fi
  else
    emit_kv "kernel_source" "explicit"
  fi

  if [[ -z "$initrd" ]]; then
    for candidate in "$nixos_system/initrd" "$nixos_system/initrd.gz"; do
      if [[ -f "$candidate" ]]; then
        initrd="$candidate"
        emit_kv "initrd_source" "nixos_system"
        break
      fi
    done
    if [[ -z "$initrd" ]]; then
      append_refusal "nixos_system.initrd" "$nixos_system has no initrd or initrd.gz file"
    fi
  else
    emit_kv "initrd_source" "explicit"
  fi

  if [[ -z "$kernel" || -z "$initrd" ]]; then
    emit_refusal \
      "nixos_system_missing_guest_inputs" \
      "Use a NixOS system closure that exposes kernel and initrd symlinks, or pass --kernel and --initrd explicitly."
  fi
fi

if [[ -z "$kernel" ]]; then
  append_refusal "kernel" "TIDEFS_QEMU_KERNEL not set and --kernel not given"
  emit_refusal \
    "kernel_not_provided" \
    "Provide a Linux kernel with RDMA support via TIDEFS_QEMU_KERNEL or --kernel."
fi

if [[ ! -f "$kernel" ]]; then
  append_refusal "kernel" "$kernel does not exist"
  emit_refusal \
    "kernel_not_found" \
    "The kernel image '$kernel' was not found. Provide a valid path."
fi

emit_kv "kernel" "$kernel"

if [[ -z "$initrd" ]]; then
  append_refusal "initrd" "TIDEFS_QEMU_INITRD not set and --initrd not given"
  emit_refusal \
    "initrd_not_provided" \
    "Provide a Linux initrd with busybox, kmod, and rdma-core via TIDEFS_QEMU_INITRD or --initrd."
fi

if [[ ! -f "$initrd" ]]; then
  append_refusal "initrd" "$initrd does not exist"
  emit_refusal \
    "initrd_not_found" \
    "The initrd image '$initrd' was not found. Provide a valid path."
fi

emit_kv "initrd" "$initrd"

# Check for rdma_rxe kernel module on host (proxy for guest availability)
if command_exists modinfo; then
  if modinfo rdma_rxe >/dev/null 2>&1; then
    emit_kv "host_module_rdma_rxe" "available"
  else
    emit_kv "host_module_rdma_rxe" "unavailable"
    append_refusal "rdma_rxe_module" "rdma_rxe kernel module not available on host"
  fi
else
  emit_kv "host_module_rdma_rxe" "modinfo_missing"
fi

# --- build guest overlay initrd ----------------------------------------------

# Create a small extra initrd that layers on top of the base initrd.
# It contains a /tidefs-guest-rdma.sh script that the guest runs on boot.

overlay_dir="$(mktemp -d /tmp/tidefs-qemu-rdma-overlay.XXXXXX)"

cat > "$overlay_dir/tidefs-guest-rdma.sh" <<'GUEST_SCRIPT'
#!/bin/sh
# TideFS guest RDMA setup script -- runs inside disposable QEMU guest.
# Enables software RDMA on eth0 and outputs carrier validation.
set -e

for candidate in /nix/store/*-extra-utils/bin; do
  if [ -d "$candidate" ]; then
    PATH="$candidate:$PATH"
  fi
done
export PATH

echo "=== tidefs-guest-rdma node=$(hostname 2>/dev/null || echo unknown) ==="

# Mount essential filesystems
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /proc /sys
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true

# Bring up virtio networking before assigning the node address.
echo "--- virtio module probe ---"
for mod in virtio_pci virtio_net; do
  if modprobe "$mod" 2>/dev/null; then
    echo "module_$mod=loaded"
  else
    echo "module_$mod=not_available"
  fi
done

# Basic network setup
ip link set lo up 2>/dev/null || true
ip link set eth0 up 2>/dev/null || true

HOSTNAME="$(hostname 2>/dev/null || echo "")"
echo "guest_identity hostname=$HOSTNAME"

# Use kernel hostname parameter for node identity (set via QEMU -append hostname=)
if [ "${HOSTNAME:-}" = "node-a" ] || [ "${HOSTNAME:-}" = "node-b" ]; then
  NODE_NAME="$HOSTNAME"
  echo "guest_node_from_hostname=$NODE_NAME"
fi
NODE_NAME="${NODE_NAME:-unknown}"
NODE_IP=""
for arg in $(cat /proc/cmdline 2>/dev/null); do
  case "$arg" in
    tidefs_node=*) NODE_NAME="${arg#tidefs_node=}" ;;
    tidefs_node_ip=*) NODE_IP="${arg#tidefs_node_ip=}" ;;
  esac
done
echo "guest_identity node=$NODE_NAME"
echo "guest_network_requested_ip=${NODE_IP:-none}"

# Map node name to IP (assigned via hostname= kernel param)
if [ "$NODE_NAME" = "node-a" ]; then
  NODE_IP="192.168.77.10/24"
elif [ "$NODE_NAME" = "node-b" ]; then
  NODE_IP="192.168.77.20/24"
fi
if [ -n "$NODE_IP" ]; then
  ip addr add "$NODE_IP" dev eth0 2>/dev/null || true
fi
echo "--- network state ---"
ip -br addr show dev eth0 2>/dev/null || echo "guest_network_addr=unavailable"
ip route show 2>/dev/null || echo "guest_network_route=unavailable"

# Probe for RDMA kernel modules
echo "--- module probe ---"
for mod in rdma_rxe siw ib_core ib_uverbs rdma_cm rdma_ucm; do
  if modprobe "$mod" 2>/dev/null; then
    echo "module_$mod=loaded"
  else
    echo "module_$mod=not_available"
  fi
done

# Enable software RDMA on eth0 if rxe is available
echo "--- rdma enable ---"
ETH0_EXISTS=false
if [ -d /sys/class/net/eth0 ]; then
  ETH0_EXISTS=true
  echo "netdev_eth0=present"
else
  echo "netdev_eth0=missing"
fi

if $ETH0_EXISTS && modprobe rdma_rxe 2>/dev/null; then
  if rdma link show rxe_eth0 >/dev/null 2>&1; then
    echo "rdma_link_rxe_eth0=already_exists"
  else
    if rdma link add rxe_eth0 type rxe netdev eth0 2>/dev/null; then
      echo "rdma_link_rxe_eth0=created"
    else
      echo "rdma_link_rxe_eth0=failed_to_create"
    fi
  fi
fi

configure_libibverbs_driver_path() {
  # NixOS initrds can rewrite rdma-core's default config path to a placeholder.
  # Export the bundled driver config before any verbs or rping command runs.
  if [ -z "${RDMAV_DRIVERS:-}" ]; then
    for rxe_provider in /nix/store/*-extra-utils/lib/libibverbs/librxe-rdmav*.so; do
      if [ -f "$rxe_provider" ]; then
        provider_prefix="${rxe_provider%-rdmav*.so}"
        export RDMAV_DRIVERS="$provider_prefix"
        export IBV_DRIVERS="$provider_prefix"
        echo "rdma_libibverbs_provider=$rxe_provider"
        break
      fi
    done
  else
    echo "rdma_libibverbs_provider=$RDMAV_DRIVERS"
  fi

  if [ -n "${IBV_DRIVERS_PATH:-}" ]; then
    echo "rdma_libibverbs_config=$IBV_DRIVERS_PATH"
    return
  fi

  for libverbs_cfg in $(find /nix/store -maxdepth 4 -name "libibverbs.d" -type d 2>/dev/null); do
    echo "rdma_libibverbs_config=$libverbs_cfg"
    export IBV_DRIVERS_PATH="$libverbs_cfg"
    return
  done

  if [ -d /dev/infiniband ] && [ -c /dev/infiniband/uverbs0 ]; then
    mkdir -p /tmp/libibverbs.d
    echo "driver rxe" > /tmp/libibverbs.d/rxe.driver 2>/dev/null || true
    export IBV_DRIVERS_PATH=/tmp/libibverbs.d
    echo "rdma_libibverbs_fallback_config=created"
    return
  fi

  echo "rdma_libibverbs_config=not_found"
}

configure_libibverbs_driver_path

# Report RDMA state
echo "--- rdma state ---"
rdma link show 2>/dev/null || echo "rdma_link_show=failed"

# Report verbs devices
echo "--- verbs devices ---"
if command -v ibv_devices >/dev/null 2>&1; then
  ibv_devices 2>/dev/null || echo "ibv_devices=failed"
else
  echo "ibv_devices=not_installed"
fi

if command -v ibv_devinfo >/dev/null 2>&1; then
  ibv_devinfo 2>/dev/null || echo "ibv_devinfo=failed"
else
  echo "ibv_devinfo=not_installed"
fi

# RDMA readiness classification
echo "--- readiness ---"
LINK_COUNT=0
RDMA_LINKS="$(rdma link show 2>/dev/null || true)"
while IFS= read -r link_line; do
  [ -n "$link_line" ] && LINK_COUNT=$((LINK_COUNT + 1))
done <<EOF_RDMA_LINKS
$RDMA_LINKS
EOF_RDMA_LINKS
IB_COUNT=0
if [ -d /sys/class/infiniband ]; then
  for ib_dev in /sys/class/infiniband/*; do
    [ -e "$ib_dev" ] && IB_COUNT=$((IB_COUNT + 1))
  done
fi
echo "rdma_link_count=$LINK_COUNT"
echo "infiniband_device_count=$IB_COUNT"

if [ "$LINK_COUNT" -gt 0 ] && [ "$IB_COUNT" -gt 0 ]; then
  echo "carrier_result=active_link_visible"
  echo "transport_session_rdma_status=candidate_validated_in_disposable_qemu"
  echo "transport_session_fallback=tcp_still_required"
elif modprobe rdma_rxe 2>/dev/null; then
  echo "carrier_result=blocked_no_active_link"
  echo "transport_session_rdma_status=software_rdma_module_available_but_not_enabled"
  echo "transport_session_fallback=tcp_required"
else
  echo "carrier_result=blocked_no_software_module"
  echo "transport_session_rdma_status=rdma_unavailable_in_guest"
  echo "transport_session_fallback=tcp_required"
fi


# --- cross-node rping RDMA CM connectivity test ---
echo "--- cross-node rping ---"

RPING_SERVER_PID=""
if [ "$NODE_NAME" = "node-a" ] && command -v rping >/dev/null 2>&1; then
  echo "rping_role=server"
  rping -s -v -a 192.168.77.10 > /dev/null 2>&1 &
  RPING_SERVER_PID=$!
  echo "rping_server_pid=$RPING_SERVER_PID"
  sleep 2
elif [ "$NODE_NAME" = "node-b" ] && command -v rping >/dev/null 2>&1; then
  echo "rping_role=client"
  sleep 5
  if rping -c -a 192.168.77.10 -C 5 -v 2>&1; then
    echo "rping_result=pass"
    echo "rping_connectivity=two_node_rdma_cm_established"
  else
    echo "rping_result=fail"
    echo "rping_connectivity=could_not_establish_rdma_cm_connection"
  fi
elif ! command -v rping >/dev/null 2>&1; then
  echo "rping_role=none"
  echo "rping_result=skipped"
  echo "rping_connectivity=rping_tool_not_installed_in_guest"
else
  echo "rping_role=none"
  echo "rping_result=skipped"
  echo "rping_connectivity=unknown_node_name"
fi

if [ -n "$RPING_SERVER_PID" ]; then
  RPING_WAITED=0
  while kill -0 "$RPING_SERVER_PID" 2>/dev/null && [ "$RPING_WAITED" -lt 30 ]; do
    sleep 1
    RPING_WAITED=$((RPING_WAITED + 1))
  done
  echo "rping_server_wait_seconds=$RPING_WAITED"
  if kill -0 "$RPING_SERVER_PID" 2>/dev/null; then
    echo "rping_server_timeout=30s"
    kill "$RPING_SERVER_PID" 2>/dev/null || true
  fi
  if wait "$RPING_SERVER_PID" 2>/dev/null; then
    echo "rping_server_exit=0"
  else
    echo "rping_server_exit=$?"
  fi
fi

# --- TideFS RDMA data-path smoke test ---
echo "--- tidefs rdma data-path smoke ---"

TIDEFS_BIN=""
if command -v tidefs-storage-node >/dev/null 2>&1; then
  TIDEFS_BIN="tidefs-storage-node"
fi
configure_libibverbs_driver_path

# --- RDMA userspace device diagnostic ---
echo "--- rdma userspace device diagnostic ---"
echo "rdma_diag_phase=pre_data_path"
echo "rdma_diag_ibv_drivers_path=${IBV_DRIVERS_PATH:-not_set}"
if [ -d /dev/infiniband ]; then
  echo "rdma_diag_dev_infiniband_dir=present"
  ls -la /dev/infiniband/ 2>/dev/null || echo "rdma_diag_dev_listing=failed"
else
  echo "rdma_diag_dev_infiniband_dir=missing"
fi
if [ -d /sys/class/infiniband ]; then
  echo "rdma_diag_sysfs_infiniband=present"
  for ibdev in /sys/class/infiniband/*; do
    if [ -e "$ibdev" ]; then
      IBDEV_NAME="$(basename "$ibdev")"
      echo "rdma_diag_sysfs_ibdev=$IBDEV_NAME"
    fi
  done
else
  echo "rdma_diag_sysfs_infiniband=missing"
fi
if command -v ibv_devices >/dev/null 2>&1; then
  echo "rdma_diag_ibv_devices_binary=available"
  ibv_devices 2>&1 || true; IBV_RC=$?; echo "rdma_diag_ibv_devices_rc=$IBV_RC"
else
  echo "rdma_diag_ibv_devices_binary=not_found"
fi
if command -v ibv_devinfo >/dev/null 2>&1; then
  echo "rdma_diag_ibv_devinfo_binary=available"
  ibv_devinfo 2>&1 || true; IBV_RC=$?; echo "rdma_diag_ibv_devinfo_rc=$IBV_RC"
else
  echo "rdma_diag_ibv_devinfo_binary=not_found"
fi
echo "tidefs_data_path_smoke=started"

if [ -z "$TIDEFS_BIN" ]; then
  echo "tidefs_storage_node_binary=not_found"
  echo "tidefs_data_path_smoke=blocked_no_binary"
else
  echo "tidefs_storage_node_binary=$TIDEFS_BIN"
  STORE_DIR="/tmp/tidefs-rdma-store"
  TIDEFS_SMOKE_WINDOW_SECS=45
  TIDEFS_CLIENT_TIMEOUT_SECS=30
  TIDEFS_CLIENT_START_DELAY_SECS=35
  mkdir -p "$STORE_DIR"

  if [ "$NODE_NAME" = "node-a" ]; then
    echo "tidefs_data_path_role=server"
    echo "tidefs_data_path_probe=health"
    "$TIDEFS_BIN" server \
      --node-id 1 \
      --bind "192.168.77.10:9800" \
      --store "$STORE_DIR" \
      --rdma \
      > "/tmp/tidefs-server.log" 2>&1 &
    TIDEFS_SERVER_PID=$!
    echo "tidefs_server_pid=$TIDEFS_SERVER_PID"
    sleep 3
    if kill -0 "$TIDEFS_SERVER_PID" 2>/dev/null; then
      echo "tidefs_server_status=started"
      echo "tidefs_server_smoke_window_seconds=$TIDEFS_SMOKE_WINDOW_SECS"
      sleep "$TIDEFS_SMOKE_WINDOW_SECS"
      if kill -0 "$TIDEFS_SERVER_PID" 2>/dev/null; then
        echo "tidefs_server_status=survived_smoke_window"
        echo "tidefs_data_path_smoke=pass"
        kill "$TIDEFS_SERVER_PID" 2>/dev/null || true
        TIDEFS_SERVER_STOP_WAITED=0
        while kill -0 "$TIDEFS_SERVER_PID" 2>/dev/null && [ "$TIDEFS_SERVER_STOP_WAITED" -lt 5 ]; do
          sleep 1
          TIDEFS_SERVER_STOP_WAITED=$((TIDEFS_SERVER_STOP_WAITED + 1))
        done
        echo "tidefs_server_stop_wait_seconds=$TIDEFS_SERVER_STOP_WAITED"
        if kill -0 "$TIDEFS_SERVER_PID" 2>/dev/null; then
          echo "tidefs_server_stop=forced_after_smoke_window"
          kill -KILL "$TIDEFS_SERVER_PID" 2>/dev/null || true
        else
          echo "tidefs_server_stop=terminated_after_smoke_window"
        fi
        if wait "$TIDEFS_SERVER_PID" 2>/dev/null; then
          TIDEFS_SERVER_RC=0
        else
          TIDEFS_SERVER_RC=$?
        fi
      else
        if wait "$TIDEFS_SERVER_PID" 2>/dev/null; then
          TIDEFS_SERVER_RC=0
        else
          TIDEFS_SERVER_RC=$?
        fi
        echo "tidefs_server_status=exited_during_smoke_window"
        echo "tidefs_data_path_smoke=fail"
      fi
    else
      if wait "$TIDEFS_SERVER_PID" 2>/dev/null; then
        TIDEFS_SERVER_RC=0
      else
        TIDEFS_SERVER_RC=$?
      fi
      if [ "$TIDEFS_SERVER_RC" -eq 0 ]; then
        echo "tidefs_server_status=completed_successfully"
      else
        echo "tidefs_server_status=failed_to_start"
      fi
      echo "tidefs_data_path_smoke=fail"
    fi
    echo "tidefs_server_exit=$TIDEFS_SERVER_RC"
  elif [ "$NODE_NAME" = "node-b" ]; then
    echo "tidefs_data_path_role=client"
    echo "tidefs_data_path_probe=health"
    echo "tidefs_client_start_delay_seconds=$TIDEFS_CLIENT_START_DELAY_SECS"
    sleep "$TIDEFS_CLIENT_START_DELAY_SECS"
    if command -v timeout >/dev/null 2>&1; then
      echo "tidefs_client_timeout_seconds=$TIDEFS_CLIENT_TIMEOUT_SECS"
      if timeout "$TIDEFS_CLIENT_TIMEOUT_SECS" "$TIDEFS_BIN" client \
           --node-id 2 \
           --server-node-id 1 \
           --connect "192.168.77.10:9800" \
           --rdma \
           health > "/tmp/tidefs-client.log" 2>&1; then
        TIDEFS_CLIENT_RC=0
        echo "tidefs_data_path_smoke=pass"
      else
        TIDEFS_CLIENT_RC=$?
        echo "tidefs_data_path_smoke=fail"
      fi
      echo "tidefs_client_exit=$TIDEFS_CLIENT_RC"
    else
      echo "tidefs_client_timeout=not_found"
      echo "tidefs_data_path_smoke=blocked_no_timeout"
    fi
  fi
  if [ -e "/tmp/tidefs-server.log" ]; then
    echo "--- tidefs-server.log begin ---"
    cat "/tmp/tidefs-server.log" 2>/dev/null || true
    echo "--- tidefs-server.log end ---"
  else
    echo "tidefs_server_log=missing"
  fi
  if [ -e "/tmp/tidefs-client.log" ]; then
    echo "--- tidefs-client.log begin ---"
    cat "/tmp/tidefs-client.log" 2>/dev/null || true
    echo "--- tidefs-client.log end ---"
  else
    echo "tidefs_client_log=missing"
  fi
fi
echo "=== tidefs-guest-rdma complete ==="
poweroff -f 2>/dev/null || reboot -f 2>/dev/null || halt -f 2>/dev/null || true
GUEST_SCRIPT
chmod +x "$overlay_dir/tidefs-guest-rdma.sh"

overlay_initrd="$overlay_dir/tidefs-guest-rdma.cpio"
combined_initrd="$overlay_dir/combined-initrd"
(
  cd "$overlay_dir"
  find tidefs-guest-rdma.sh -print | cpio -o -H newc > "$overlay_initrd"
) >/dev/null 2>&1
# Detect base initrd compression so the concatenated stream is consistent.
# If the base is gzip, compress the overlay too; the kernel gunzip handles
# multi-member gzip streams. Raw cpio is concatenated as-is.
base_magic="$(od -A n -t x1 -N 2 "$initrd" 2>/dev/null | tr -d ' ')"
if [[ "$base_magic" == "1f8b" ]]; then
  gzip -f "$overlay_initrd"
  cat "$initrd" "${overlay_initrd}.gz" > "$combined_initrd"
  emit_kv "initrd_concat_strategy" "gzip_gzip"
elif [[ "$base_magic" == "0707" ]]; then
  cat "$initrd" "$overlay_initrd" > "$combined_initrd"
  emit_kv "initrd_concat_strategy" "raw_cpio_concatenation"
elif [[ "${base_magic:0:4}" == "3037" ]]; then
  cat "$initrd" "$overlay_initrd" > "$combined_initrd"
  emit_kv "initrd_concat_strategy" "raw_cpio_concatenation_odc"
elif [[ "$base_magic" == "28b5" ]]; then
  if ! command_exists zstd; then
    append_refusal "zstd" "zstd not found in PATH for zstd-compressed base initrd"
    emit_refusal \
      "zstd_missing" \
      "Add zstd to the qemu-rdma-two-node Nix app so NixOS zstd initrds can receive the guest script overlay."
  fi
  base_raw_initrd="$overlay_dir/base-initrd.cpio"
  base_unpack_dir="$overlay_dir/base-root"
  combined_raw_initrd="$overlay_dir/combined-initrd.cpio"
  zstd -q -f -d -c "$initrd" > "$base_raw_initrd"
  mkdir -p "$base_unpack_dir"
  if ! (cd "$base_unpack_dir" && cpio -id --quiet < "$base_raw_initrd"); then
    append_refusal "zstd_initrd" "failed to unpack zstd-compressed base initrd"
    emit_refusal \
      "zstd_initrd_unpack_failed" \
      "Inspect the NixOS initrd format and update the qemu-rdma-two-node overlay builder."
  fi
  cp "$overlay_dir/tidefs-guest-rdma.sh" "$base_unpack_dir/tidefs-guest-rdma.sh"
  chmod 0755 "$base_unpack_dir/tidefs-guest-rdma.sh"
  extra_utils_sh=""
  for candidate in "$base_unpack_dir"/nix/store/*-extra-utils/bin/sh; do
    if [[ -x "$candidate" ]]; then
      extra_utils_sh="${candidate#"$base_unpack_dir"/}"
      break
    fi
  done
  if [[ -z "$extra_utils_sh" ]]; then
    append_refusal "zstd_initrd.shell" "no extra-utils shell found in unpacked base initrd"
    emit_refusal \
      "zstd_initrd_shell_missing" \
      "Ensure the NixOS guest initrd includes a POSIX shell for rdinit guest probes."
  fi
  mkdir -p "$base_unpack_dir/bin"
  ln -sf "/$extra_utils_sh" "$base_unpack_dir/bin/sh"
  (cd "$base_unpack_dir" && find . -print | cpio -o -H newc > "$combined_raw_initrd") >/dev/null 2>&1
  zstd -q -f "$combined_raw_initrd" -o "$combined_initrd"
  emit_kv "initrd_concat_strategy" "zstd_repacked_cpio"
else
  emit_kv "initrd_base_magic" "$base_magic"
  emit_kv "initrd_concat_strategy" "raw_concatenation_unknown_base_format"
  cat "$initrd" "$overlay_initrd" > "$combined_initrd"
fi

# --- boot two QEMU nodes -----------------------------------------------------

emit_kv "qemu_rdma_two_node_phase" "booting_nodes"

# Node A (listener)
node_a_dir="$validation_dir/node-a"
mkdir -p "$node_a_dir"
node_a_serial="$node_a_dir/serial.log"
node_a_qemu_pid_file="$node_a_dir/qemu.pid"

# Node B (connector)
node_b_dir="$validation_dir/node-b"
mkdir -p "$node_b_dir"
node_b_serial="$node_b_dir/serial.log"
node_b_qemu_pid_file="$node_b_dir/qemu.pid"

bind_port=19901
port_in_use() {
  local port="$1"
  if command_exists ss; then
    ss -H -tln "sport = :$port" 2>/dev/null | grep -q .
    return
  fi
  if command_exists netstat; then
    netstat -tln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$port$"
    return
  fi
  return 1
}

# Find an available port, starting from the default.
while port_in_use "$bind_port"; do
  bind_port=$((bind_port + 1))
  if [[ "$bind_port" -gt 19999 ]]; then
    emit_refusal \
      "no_free_port" \
      "No free port found in range 19901-19999 for QEMU socket networking."
  fi
done

emit_kv "node_pair_bind_port" "$bind_port"
emit_kv "node_a_mac" "52:54:00:12:34:10"
emit_kv "node_b_mac" "52:54:00:12:34:20"

# Build QEMU command lines
qemu_common_args=(
  -machine "q35,accel=kvm:tcg"
  -cpu max
  -m 512M
  -smp 1
  -nographic
  -no-reboot
  -serial "file:PLACEHOLDER_SERIAL"
  -kernel "$kernel"
  -initrd "$combined_initrd"
)

guest_common_append="console=ttyS0 panic=30 rdinit=/tidefs-guest-rdma.sh"

# Node A
node_a_args=(
  "${qemu_common_args[@]//PLACEHOLDER_SERIAL/$node_a_serial}"
  -append "$guest_common_append hostname=node-a"
  -netdev "socket,id=net0,listen=127.0.0.1:$bind_port"
  -device "virtio-net-pci,netdev=net0,mac=52:54:00:12:34:10"
)

# Node B
node_b_args=(
  "${qemu_common_args[@]//PLACEHOLDER_SERIAL/$node_b_serial}"
  -append "$guest_common_append hostname=node-b"
  -netdev "socket,id=net0,connect=127.0.0.1:$bind_port"
  -device "virtio-net-pci,netdev=net0,mac=52:54:00:12:34:20"
)

# Write reproduction command lines to validation
{
  command_line "$qemu_bin" "${node_a_args[@]}"
  command_line "$qemu_bin" "${node_b_args[@]}"
} > "$validation_dir/reproduction.sh"
chmod +x "$validation_dir/reproduction.sh"

command_line "$qemu_bin" "${node_a_args[@]}" > "$node_a_dir/qemu_cmd.sh"
command_line "$qemu_bin" "${node_b_args[@]}" > "$node_b_dir/qemu_cmd.sh"

emit_kv "node_a_qemu_cmd" "$node_a_dir/qemu_cmd.sh"
emit_kv "node_b_qemu_cmd" "$node_b_dir/qemu_cmd.sh"

# Start node A (listener first)
echo "booting node-a (listener on 127.0.0.1:$bind_port)..." >&2
"$qemu_bin" "${node_a_args[@]}" &
node_a_pid=$!
_qemu_node_a_pid="$node_a_pid"
echo "$node_a_pid" > "$node_a_qemu_pid_file"
emit_kv "node_a_pid" "$node_a_pid"

# Give listener a moment to bind
sleep 2

# Verify node A is still running
if ! kill -0 "$node_a_pid" 2>/dev/null; then
  emit_kv "node_a_exit_code" "$(wait_pid_status "$node_a_pid")"
  emit_kv "qemu_rdma_two_node_result" "node_a_died_early"
  echo "Node A (listener) died immediately after boot. See $node_a_serial" >&2
  exit 3
fi

# Start node B (connector)
echo "booting node-b (connector to 127.0.0.1:$bind_port)..." >&2
"$qemu_bin" "${node_b_args[@]}" &
node_b_pid=$!
_qemu_node_b_pid="$node_b_pid"
echo "$node_b_pid" > "$node_b_qemu_pid_file"
emit_kv "node_b_pid" "$node_b_pid"

sleep 2

if ! kill -0 "$node_b_pid" 2>/dev/null; then
  emit_kv "node_b_exit_code" "$(wait_pid_status "$node_b_pid")"
  emit_kv "qemu_rdma_two_node_result" "node_b_died_early"
  echo "Node B (connector) died immediately after boot. See $node_b_serial" >&2
  kill "$node_a_pid" 2>/dev/null || true
  exit 3
fi

# Wait for both nodes to complete (or timeout)
emit_kv "qemu_rdma_two_node_phase" "waiting_for_nodes"
deadline=$((SECONDS + timeout_sec))
node_a_done=false
node_b_done=false

while [[ "$SECONDS" -lt "$deadline" ]]; do
  if ! $node_a_done && ! kill -0 "$node_a_pid" 2>/dev/null; then
    node_a_exit="$(wait_pid_status "$node_a_pid")"
    emit_kv "node_a_exit_code" "$node_a_exit"
    node_a_done=true
    echo "node-a exited with code $node_a_exit" >&2
  fi
  if ! $node_b_done && ! kill -0 "$node_b_pid" 2>/dev/null; then
    node_b_exit="$(wait_pid_status "$node_b_pid")"
    emit_kv "node_b_exit_code" "$node_b_exit"
    node_b_done=true
    echo "node-b exited with code $node_b_exit" >&2
  fi
  if $node_a_done && $node_b_done; then
    break
  fi
  sleep 1
done

# Timeout handling
if ! $node_a_done; then
  emit_kv "node_a_exit_code" "timeout"
  kill "$node_a_pid" 2>/dev/null || true
  wait "$node_a_pid" 2>/dev/null || true
  node_a_done=true
fi
if ! $node_b_done; then
  emit_kv "node_b_exit_code" "timeout"
  kill "$node_b_pid" 2>/dev/null || true
  wait "$node_b_pid" 2>/dev/null || true
  node_b_done=true
fi

emit_kv "qemu_rdma_two_node_phase" "collecting_validation"

# --- analyze serial output and classify --------------------------------------

classify_node() {
  local label="$1" serial_log="$2" out_dir="$3"

  emit_kv "${label}_serial_bytes" "$(wc -c < "$serial_log" 2>/dev/null || echo 0)"
  emit_kv "${label}_serial_lines" "$(wc -l < "$serial_log" 2>/dev/null || echo 0)"

  # Extract key carrier lines from serial output
  if grep -q "carrier_result=active_link_visible" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_carrier_result" "active_link_visible"
  elif grep -q "carrier_result=blocked_no_active_link" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_carrier_result" "blocked_no_active_link"
  elif grep -q "carrier_result=blocked_no_software_module" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_carrier_result" "blocked_no_software_module"
  elif grep -q "Kernel panic" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_carrier_result" "guest_boot_failed_kernel_panic"
  else
    emit_kv "${label}_carrier_result" "unknown_no_guest_script_output"
  fi

  # Extract rping cross-node connectivity result
  if grep -q "rping_result=pass" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_rping_result" "pass"
  elif grep -q "rping_result=fail" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_rping_result" "fail"
  elif grep -q "rping_result=skipped" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_rping_result" "skipped"
  fi
  if grep -q "rping_connectivity=" "$serial_log" 2>/dev/null; then
    RPING_CONN="$(grep "rping_connectivity=" "$serial_log" 2>/dev/null | head -1 | cut -d= -f2-)"
    emit_kv "${label}_rping_connectivity" "$RPING_CONN"
  fi

  # Look for guest RDMA script validation
  if grep -q "=== tidefs-guest-rdma" "$serial_log" 2>/dev/null; then
    emit_kv "${label}_guest_script_ran" "yes"
    grep "module_\|rdma_link\|rdma_diag\|carrier_result\|transport_session\|infiniband_device\|netdev_\|rping_\|tidefs_data_path\|tidefs_storage_node\|tidefs_server\|tidefs_client\|guest_node_from\|rdma_libibverbs" \
      "$serial_log" 2>/dev/null > "$out_dir/guest_carrier.env" || true

    # Extract TideFS RDMA data-path smoke result
    if grep -q "tidefs_data_path_smoke=pass" "$serial_log" 2>/dev/null; then
      emit_kv "${label}_data_path_smoke" "pass"
    elif grep -q "tidefs_data_path_smoke=fail" "$serial_log" 2>/dev/null; then
      emit_kv "${label}_data_path_smoke" "fail"
    elif grep -q "tidefs_data_path_smoke=blocked_no_timeout" "$serial_log" 2>/dev/null; then
      emit_kv "${label}_data_path_smoke" "blocked_no_timeout"
    elif grep -q "tidefs_data_path_smoke=blocked_no_binary" "$serial_log" 2>/dev/null; then
      emit_kv "${label}_data_path_smoke" "blocked_no_binary"
    elif grep -q "tidefs_server_status=failed_to_start" "$serial_log" 2>/dev/null; then
      emit_kv "${label}_data_path_smoke" "server_failed_to_start"
    fi
    if grep -q "tidefs_server_exit=" "$serial_log" 2>/dev/null; then
      SRV_EXIT="$(grep "tidefs_server_exit=" "$serial_log" 2>/dev/null | head -1 | cut -d= -f2)"
      emit_kv "${label}_server_exit" "$SRV_EXIT"
    fi
    if grep -q "tidefs_client_exit=" "$serial_log" 2>/dev/null; then
      CLIENT_EXIT="$(grep "tidefs_client_exit=" "$serial_log" 2>/dev/null | head -1 | cut -d= -f2)"
      emit_kv "${label}_client_exit" "$CLIENT_EXIT"
    fi
  else
    emit_kv "${label}_guest_script_ran" "no"
    emit_kv "${label}_guest_script_refusal" \
      "guest_initrd_may_not_include_tidefs_guest_rdma_script_or_busybox"
  fi
}

classify_node "node_a" "$node_a_serial" "$node_a_dir"
classify_node "node_b" "$node_b_serial" "$node_b_dir"

# --- overall classification --------------------------------------------------

node_a_ok=false
node_b_ok=false
node_a_boot_failed=false
node_b_boot_failed=false
grep -q "node_a_carrier_result=active_link_visible" "$summary_file" 2>/dev/null && node_a_ok=true
grep -q "node_b_carrier_result=active_link_visible" "$summary_file" 2>/dev/null && node_b_ok=true
grep -q "node_a_carrier_result=guest_boot_failed" "$summary_file" 2>/dev/null && node_a_boot_failed=true
grep -q "node_b_carrier_result=guest_boot_failed" "$summary_file" 2>/dev/null && node_b_boot_failed=true

if $node_a_ok && $node_b_ok; then
  emit_kv "qemu_rdma_two_node_result" "both_nodes_active_link_visible"
  emit_kv "transport_session_rdma_status" "two_node_qemu_carrier_validated"
  emit_kv "transport_session_fallback" "tcp_still_required"
elif $node_a_ok || $node_b_ok; then
  emit_kv "qemu_rdma_two_node_result" "partial_one_node_active"
  emit_kv "transport_session_rdma_status" "partial_qemu_validation"
elif $node_a_boot_failed || $node_b_boot_failed; then
  emit_kv "qemu_rdma_two_node_result" "guest_boot_failed_before_carrier_probe"
  emit_kv "transport_session_rdma_status" "qemu_guest_boot_failed"
else
  emit_kv "qemu_rdma_two_node_result" "no_active_rdma_link_in_either_node"
  emit_kv "transport_session_rdma_status" "qemu_carrier_inconclusive"
fi

# --- rping cross-node connectivity classification ---
node_a_rping_pass=false
node_b_rping_pass=false
grep -q "node_a_rping_result=pass" "$summary_file" 2>/dev/null && node_a_rping_pass=true
grep -q "node_b_rping_result=pass" "$summary_file" 2>/dev/null && node_b_rping_pass=true

if $node_a_ok && $node_b_ok && { $node_a_rping_pass || $node_b_rping_pass; }; then
  emit_kv "qemu_rdma_two_node_rping" "client_server_rping_pass"
  emit_kv "rdma_cm_connectivity" "two_node_rdma_cm_validated"
elif $node_a_rping_pass || $node_b_rping_pass; then
  emit_kv "qemu_rdma_two_node_rping" "partial_one_node_rping_pass"
  emit_kv "rdma_cm_connectivity" "partial_rdma_cm_validation"
else
  emit_kv "qemu_rdma_two_node_rping" "no_rping_pass"
  emit_kv "rdma_cm_connectivity" "rdma_cm_not_validated"
fi

# --- TideFS RDMA data-path smoke classification ---
node_a_data_path_pass=false
node_b_data_path_pass=false
grep -q "node_a_data_path_smoke=pass" "$summary_file" 2>/dev/null && node_a_data_path_pass=true
grep -q "node_b_data_path_smoke=pass" "$summary_file" 2>/dev/null && node_b_data_path_pass=true

if $node_a_data_path_pass && $node_b_data_path_pass; then
  emit_kv "tidefs_rdma_data_path_smoke" "client_server_health_pass"
elif $node_a_data_path_pass || $node_b_data_path_pass; then
  emit_kv "tidefs_rdma_data_path_smoke" "partial_one_node_pass"
else
  emit_kv "tidefs_rdma_data_path_smoke" "not_validated"
fi

# --- emit validation manifest ------------------------------------------------

cat > "$validation_dir/MANIFEST.md" <<MANIFEST
# QEMU RDMA Two-Node Carrier Validation

- **node-a serial**: $node_a_serial
- **node-b serial**: $node_b_serial
- **summary**: $summary_file
- **reproduction**: $validation_dir/reproduction.sh

$(grep 'qemu_rdma_two_node_result=' "$summary_file" 2>/dev/null || echo "result: unknown")
MANIFEST

emit_kv "validation_dir" "$validation_dir"
emit_kv "validation_manifest" "$validation_dir/MANIFEST.md"

echo "qemu-rdma-two-node complete: result=$(grep 'qemu_rdma_two_node_result=' "$summary_file" | cut -d= -f2-)"
echo "validation output written under $validation_dir"
