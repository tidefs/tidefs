; Common global settings for TideFS fio benchmarking profiles
; These settings are included by all profile job files.

; IO engine selection:
;   FUSE path: psync (synchronous POSIX I/O — works with any filesystem)
;   ublk path: psync with direct=1 (bypasses page cache, exercises the block path)
[global]
; Defaults — individual jobs may override
ioengine=psync
direct=1
group_reporting=1
time_based=0
ramp_time=0
norandommap=1
randrepeat=0
refill_buffers=1

; Verification settings (disabled by default for benchmarking, enabled for verify profiles)
; verify=crc32c
; verify_fatal=1

; Latency logging for percentile analysis
log_avg_msec=100
disable_lat=0
disable_clat=0
disable_slat=0
