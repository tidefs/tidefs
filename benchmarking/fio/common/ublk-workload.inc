; ublk-path workload settings
; Usage: fio --filename=/dev/ublkbN job.fio
; Operates directly on the block device.

[global]
ioengine=psync
direct=1

; ublk workload defaults — single block device, no filesystem layer
; filename=/dev/ublkb0
