# Block Volume Adapter Host Preflight OW-301H

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301H executable block-volume adapter host preflight surface is implemented in
`apps/tidefs-block-volume-adapter-daemon`.

The `preflight-host` command reads the real host kernel release, classifies it
through the daemon-local host/kernel preflight model, and checks non-mutating
Linux `ublk` readiness signals:

- `/proc/sys/kernel/osrelease`;
- `/dev/ublk-control`;
- `/sys/module/ublk_drv`;
- `/sys/class/ublk-char`;
- `/sys/class/block`.

The command does not load modules, open an `ublk` control session, create a
device, issue ioctls, run fio, run mkfs/mount, or attach/list/detach an export.
It emits an explicit admission class and refusal class so a host that cannot
support live `ublk` attachment is refused before any block-device claim exists.


The implementation-tracked non-release tests and commands cover:

- `tidefs-block-volume-adapter-daemon preflight-host`;
- daemon-local host/kernel classification for Linux baseline admission;
- synthetic admitted host coverage;
- synthetic missing `/dev/ublk-control` refusal;
- synthetic pre-7.0 kernel refusal;
- `tidefs-xtask check-block-volume-host-preflight`;
  marker gate.


```text
tidefs-block-volume-adapter-daemon preflight-host
tidefs-xtask check-block-volume-host-preflight
```

## Relationship To Parent Gates

This is a prerequisite for OW-301. It is below the PC-012 Linux block-device acceptance gates: it records whether the host can
not create `/dev/ublkbN`.

On hosts without Linux 7.0+ and `/dev/ublk-control`, the correct outcome is an
remains blocked, not a skipped pass.

OW-301I follows this host preflight with a typed `ublk` ABI dry-run control plan.
The host preflight decides whether a host can admit live work; the ABI plan
defines the control commands and record layouts a future live daemon must use
after admission succeeds.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
