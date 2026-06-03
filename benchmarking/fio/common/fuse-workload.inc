; FUSE-path workload settings
; Usage: fio --filename=/path/to/mount job.fio
; Creates test files inside the mount point.

[global]
ioengine=psync
direct=1

; FUSE workload defaults — use directory mode for multi-file workloads
; directory=/path/to/tidefs/mount
; For single-file workloads: filename=/path/to/tidefs/mount/testfile
