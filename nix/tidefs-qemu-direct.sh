#!/usr/bin/env bash
set -euo pipefail

# --- cleanup trap: ensure no QEMU artifacts leak into the repo tree ----------
_cleanup() {
  local exit_code=$?
  # Kill any QEMU process started by this script
  if [[ -n "${_qemu_pid:-}" ]] && kill -0 "$_qemu_pid" 2>/dev/null; then
    kill -TERM "$_qemu_pid" 2>/dev/null || true
    wait "$_qemu_pid" 2>/dev/null || true
  fi
  # Remove pid/sock files this script may have placed in the current directory
  rm -f qemu.pid qemu.sock qemu-*.pid qemu-*.sock 2>/dev/null || true
  exit "$exit_code"
}
trap _cleanup EXIT INT TERM

qemu_bin="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
timeout_bin="${TIMEOUT:-timeout}"

if ! command -v "$qemu_bin" >/dev/null 2>&1; then
  printf 'missing qemu binary: %s\n' "$qemu_bin" >&2
  exit 2
fi

"$qemu_bin" --version

if [[ -z "${TIDEFS_QEMU_KERNEL:-}" ]]; then
  cat >&2 <<'EOF'
TIDEFS_QEMU_KERNEL is not set.

Use this direct-boot helper only when a specific kernel/initrd pair is part of
an outside-sandbox QEMU validation run. For the current Linux 7.0 kmod
xfstests NixOS guest runner, use:

  nix run .#k7-vfs-xfstests-validation -- --module /path/to/tidefs_posix_vfs.ko

Legacy runNixOSTest QEMU apps are refused until ported to outside-sandbox
runners.
EOF
  exit 2
fi

args=(
  -machine "${TIDEFS_QEMU_MACHINE:-q35,accel=kvm:tcg}"
  -cpu "${TIDEFS_QEMU_CPU:-max}"
  -m "${TIDEFS_QEMU_MEMORY:-1024M}"
  -smp "${TIDEFS_QEMU_SMP:-2}"
  -nographic
  -no-reboot
  -serial mon:stdio
  -kernel "$TIDEFS_QEMU_KERNEL"
  -append "${TIDEFS_QEMU_APPEND:-console=ttyS0 panic=-1}"
)

if [[ -n "${TIDEFS_QEMU_INITRD:-}" ]]; then
  args+=( -initrd "$TIDEFS_QEMU_INITRD" )
fi

if [[ -n "${TIDEFS_QEMU_DRIVE:-}" ]]; then
  args+=( -drive "file=$TIDEFS_QEMU_DRIVE,format=raw,if=virtio" )
fi

"$timeout_bin" "${TIDEFS_QEMU_TIMEOUT:-60s}" "$qemu_bin" "${args[@]}" &
_qemu_pid=$!
wait "$_qemu_pid" || true
