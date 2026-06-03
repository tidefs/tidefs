#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tidefs-rdma-probe [--validation-dir DIR]
  TIDEFS_RDMA_ALLOW_MUTATION=1 tidefs-rdma-probe --enable-rxe NETDEV [--validation-dir DIR]
  TIDEFS_RDMA_ALLOW_MUTATION=1 tidefs-rdma-probe --enable-siw NETDEV [--validation-dir DIR]
  TIDEFS_RDMA_ALLOW_MUTATION=1 tidefs-rdma-probe --delete-link LINK [--validation-dir DIR]

Default mode is non-mutating: it reports installed RDMA tools, visible RDMA
links, verbs visibility, loaded modules, available software-RDMA kernel modules,
and the required transport-session fallback classification.

The --enable-* modes load kernel modules and create a software RDMA link on the
named netdev. Use those only on disposable validation hosts or inside QEMU.
They require TIDEFS_RDMA_ALLOW_MUTATION=1 so a host probe cannot mutate the
network/RDMA stack by accident.
EOF
}

mode="probe"
netdev=""
link_name=""
validation_dir=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --validation-dir)
      if [[ "$#" -lt 2 ]]; then
        echo "--validation-dir requires a path" >&2
        exit 2
      fi
      validation_dir="$2"
      shift 2
      ;;
    --enable-rxe)
      if [[ "$#" -lt 2 ]]; then
        usage >&2
        exit 2
      fi
      mode="enable-rxe"
      netdev="$2"
      link_name="rxe-${netdev}"
      shift 2
      ;;
    --enable-siw)
      if [[ "$#" -lt 2 ]]; then
        usage >&2
        exit 2
      fi
      mode="enable-siw"
      netdev="$2"
      link_name="siw-${netdev}"
      shift 2
      ;;
    --delete-link)
      if [[ "$#" -lt 2 ]]; then
        usage >&2
        exit 2
      fi
      mode="delete-link"
      link_name="$2"
      shift 2
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

summary_file=""
if [[ -n "$validation_dir" ]]; then
  mkdir -p "$validation_dir"
  validation_dir="$(cd "$validation_dir" && pwd -P)"
  summary_file="$validation_dir/summary.env"
  : > "$summary_file"
fi


rdma_probe_timeout="${TIDEFS_RDMA_PROBE_TIMEOUT:-30s}"
rdma_probe_soft_failures=0
emit_kv() {
  local key="$1"
  local value="$2"
  printf '%s=%s\n' "$key" "$value"
  if [[ -n "$summary_file" ]]; then
    printf '%s=%s\n' "$key" "$value" >> "$summary_file"
  fi
}

safe_name() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

command_line() {
  printf '$'
  printf ' %q' "$@"
  printf '\n'
}

run_optional() {
  local label
  label="$(safe_name "$1")"
  shift
  command_line "$@"

  local status=0
  local timeout_val="$rdma_probe_timeout"
  if [[ -n "$validation_dir" ]]; then
    set +e
    timeout "$timeout_val" "$@" > "$validation_dir/$label.stdout.log" 2> "$validation_dir/$label.stderr.log"
    status=$?
    set -e
    sed -i 's/[[:space:]]\+$//' "$validation_dir/$label.stdout.log" "$validation_dir/$label.stderr.log"
    emit_kv "command_${label}_status" "$status"
    sed -n '1,120p' "$validation_dir/$label.stdout.log"
    if [[ "$status" -ne 0 ]]; then
      sed -n '1,120p' "$validation_dir/$label.stderr.log" >&2
    fi
  else
    set +e
    timeout "$timeout_val" "$@"
    status=$?
    set -e
  fi
  if [[ "$status" -ne 0 ]]; then
    rdma_probe_soft_failures=$((rdma_probe_soft_failures + 1))
  fi
  return 0
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

module_available() {
  command_exists modinfo || return 1
  modinfo "$1" >/dev/null 2>&1
}

module_loaded() {
  command_exists lsmod || return 1
  command_exists awk || return 1
  command_exists grep || return 1
  lsmod | awk '{print $1}' | grep -qx "$1"
}

count_lines() {
  sed '/^[[:space:]]*$/d' | wc -l | tr -d ' '
}

rdma_link_count() {
  local links
  if ! command_exists rdma; then
    printf '0\n'
    return
  fi
  links="$(rdma link show 2>/dev/null || true)"
  printf '%s\n' "$links" | count_lines
}

ib_device_count() {
  local devices
  if [[ ! -d /sys/class/infiniband ]] || ! command_exists find; then
    printf '0\n'
    return
  fi
  devices="$(find /sys/class/infiniband -mindepth 1 -maxdepth 1 2>/dev/null || true)"
  printf '%s\n' "$devices" | count_lines
}

emit_tool_presence() {
  for tool in rdma ip modprobe lsmod modinfo ibv_devices ibv_devinfo rping; do
    if command_exists "$tool"; then
      emit_kv "tool_${tool}" "present:$(command -v "$tool")"
    else
      emit_kv "tool_${tool}" "missing"
    fi
  done
}

emit_module_state() {
  for module in rdma_rxe siw ib_core ib_uverbs; do
    if module_available "$module"; then
      emit_kv "module_${module}_available" "yes"
    else
      emit_kv "module_${module}_available" "no"
    fi
    if module_loaded "$module"; then
      emit_kv "module_${module}_loaded" "yes"
    else
      emit_kv "module_${module}_loaded" "no"
    fi
  done
}

emit_readiness_classification() {
  local links
  local ib_devices
  links="$(rdma_link_count)"
  ib_devices="$(ib_device_count)"
  emit_kv "rdma_links_visible" "$links"
  emit_kv "infiniband_devices_visible" "$ib_devices"

  if [[ "$links" -gt 0 && "$ib_devices" -gt 0 ]]; then
    emit_kv "rdma_carrier_probe_result" "active_link_visible"
    emit_kv "transport_session_0_rdma_status" "candidate_requires_disposable_two_node_validation"
    emit_kv "transport_session_0_fallback" "tcp_still_required"
  elif module_available rdma_rxe || module_available siw; then
    emit_kv "rdma_carrier_probe_result" "blocked_no_active_link"
    emit_kv "transport_session_0_rdma_status" "software_rdma_modules_available_but_not_enabled_here"
    emit_kv "transport_session_0_fallback" "tcp_required"
  else
    emit_kv "rdma_carrier_probe_result" "blocked_no_active_link_no_software_module"
    emit_kv "transport_session_0_rdma_status" "rdma_unavailable"
    emit_kv "transport_session_0_fallback" "tcp_required"
  fi
}

require_mutation_allowed() {
  if [[ "${TIDEFS_RDMA_ALLOW_MUTATION:-}" != "1" ]]; then
    emit_kv "mutation_allowed" "no"
    emit_kv "mutation_refusal" "set_TIDEFS_RDMA_ALLOW_MUTATION_1_only_on_disposable_or_qemu_hosts"
    echo "refusing mutating RDMA operation without TIDEFS_RDMA_ALLOW_MUTATION=1" >&2
    exit 3
  fi
  emit_kv "mutation_allowed" "yes"
}

emit_kv "rdma_probe_mode" "$mode"
emit_kv "utc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_optional uname uname -a
emit_tool_presence
run_optional rdma_version rdma -V
run_optional rdma_system rdma system
run_optional rdma_link_show rdma link show
run_optional rdma_resource_show rdma resource show
run_optional sys_class_infiniband ls -la /sys/class/infiniband
run_optional ip_brief_link ip -brief link
printf '$ lsmod | awk '\''NR == 1 || $1 ~ /^(ib_|rdma_|siw|iw_|mlx|rxe)/'\''\n'
run_optional rdma_lsmod bash -lc "lsmod | awk 'NR == 1 || \$1 ~ /^(ib_|rdma_|siw|iw_|mlx|rxe)/'"
run_optional modinfo_rdma_rxe modinfo rdma_rxe
run_optional modinfo_siw modinfo siw
if command_exists ibv_devices; then
  run_optional ibv_devices ibv_devices
fi
if command_exists ibv_devinfo; then
  run_optional ibv_devinfo ibv_devinfo
fi
emit_module_state
emit_readiness_classification

case "$mode" in
  probe)
    exit 0
    ;;
  delete-link)
    require_mutation_allowed
    run_optional rdma_link_delete rdma link delete "$link_name"
    emit_readiness_classification
    exit 0
    ;;
  enable-rxe)
    module="rdma_rxe"
    rdma_type="rxe"
    ;;
  enable-siw)
    module="siw"
    rdma_type="siw"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

require_mutation_allowed

if [[ -z "$netdev" ]]; then
  usage >&2
  exit 2
fi

if [[ ! -e "/sys/class/net/$netdev" ]]; then
  printf 'netdev not found: %s\n' "$netdev" >&2
  exit 2
fi

emit_kv "software_rdma_module" "$module"
emit_kv "software_rdma_netdev" "$netdev"
emit_kv "software_rdma_link" "$link_name"
printf 'enabling_software_rdma module=%s netdev=%s link=%s\n' "$module" "$netdev" "$link_name"
modprobe "$module"

if ! rdma link show "$link_name" >/dev/null 2>&1; then
  rdma link add "$link_name" type "$rdma_type" netdev "$netdev"
fi

run_optional rdma_link_show_enabled rdma link show "$link_name"
if command_exists ibv_devices; then
  run_optional ibv_devices_after_enable ibv_devices
fi
if command_exists ibv_devinfo; then
  run_optional ibv_devinfo_after_enable ibv_devinfo
fi
emit_readiness_classification
