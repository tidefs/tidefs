# tidefs-block-volume-adapter-daemon

Block-volume adapter daemon smoke surface for TideFS.  Exposes bounded
ublk-data-plane probes and command-line entry points for device lifecycle
management, data-queue I/O dispatch, and host-preflight checks.

## Retired In-Process Validation

The previous in-process simulator, file-backed durability module, simulated
multiqueue tests, and cargo-only digest checks were removed. They exercised
local models, not a Linux ublk device, so they could not close ublk lifecycle,
discard, fio, durability, multiqueue, or data-integrity release gates. Product
closure for this app now requires real ublk/QEMU/device-backed artifacts or a
precise blocker from that path.

## Discard Implementation

The daemon's `FileBackedVolume::discard_sectors()` implementation was fixed
from a no-op (`Ok(())`) to a zero-fill implementation matching
`write_zeroes_sectors()`: sector-range conversion via `sectors_to_bytes()`,
capacity-bounds clamping, and `write_all_at()` with zeroes.  The daemon was
previously advertising discard support via ublk parameters while silently
accepting discard bios without deallocating data — this gap forced a
FUSE-level hole path to skip deallocation entirely.
