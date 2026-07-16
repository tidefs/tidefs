# Unsafe Code Audit

Issue: #1077
Audit date: 2026-06-23

This inventory covers Rust source under `crates/`, `apps/`, `kmod/`, and
`xtask/`. It counts `unsafe` blocks, `unsafe fn`, `unsafe impl`, and
`unsafe extern` items found in live source. It excludes prose-only mentions of
the word `unsafe`.

Summary:

- Total unsafe sites: 796 across 71 Rust files.
- TideFS-owned unsafe sites: 758 across 62 Rust files.
- Vendored `crates/tidefs-fuser` unsafe sites: 38 across 9 Rust files.
- Root workspace lint policy now includes `unsafe_op_in_unsafe_fn = "deny"`.
- This slice normalized several existing local `SAFETY:` comments but did not
  refactor unsafe code or change runtime behavior.

The live source surface is too broad for one safe comment-only branch. Rows
whose status names a follow-up comment issue are explicitly flagged as not yet
fully locally documented:

- #1158 locally documents POSIX/FUSE syscall harness and validation unsafe
  comments. Its review found C-string pointer fix work tracked separately in
  #1447 and #1448, without changing behavior in the comment-only branch.
- #1159 locally documents kernel, RDMA, block, ublk, daemon-signal, and ioctl
  unsafe contract comments.

Status meanings:

- "Local SAFETY comment normalized" means this slice only standardized an
  existing clear invariant marker to `SAFETY:`.
- "Partly locally documented" means some nearby `SAFETY:`/`# Safety` comments
  already exist, but the full per-site contract review is split to the named
  follow-up.
- "Follow-up per-site comments" means the row needs local comments in the
  named follow-up before #1077 can be considered complete.
- "Locally documented by #1158 contract review" and "Locally documented by
  #1159 contract review" mean unsafe blocks, unsafe
  functions, unsafe extern callback boundaries, and unsafe impls in that row
  now have nearby `SAFETY:` comments or `# Safety` docs naming the local
  foreign API contract reviewed in the named issue.
- "Vendored inventory only" means the row is in vendored third-party source and
  is intentionally not edited by this audit slice.

| Path | Unsafe site lines | Kind(s) | Purpose | Status |
| --- | --- | --- | --- | --- |
| `apps/tidefs-block-volume-adapter-daemon/src/main.rs` | 1702, 1703, 1727, 1728, 1737, 1903 | block | ublk/io_uring/block-device syscall or shared-buffer boundary. | Locally documented by #1159 contract review. |
| `apps/tidefs-block-volume-adapter-daemon/src/signal_shutdown.rs` | 16, 36, 37, 49, 50, 59 | block | ublk/io_uring/block-device syscall or shared-buffer boundary. | Locally documented by #1159 contract review. |
| `apps/tidefs-block-volume-adapter-daemon/src/ublk_io_uring.rs` | 181, 212, 235, 290, 316, 334, 358, 382, 494, 543 | block | ublk/io_uring/block-device syscall or shared-buffer boundary. | Locally documented by #1159 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/lib.rs` | 740, 748, 758, 762, 770, 815 | block | FFI/syscall boundary in TideFS-owned code. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs` | 596, 600, 611, 1569, 1589, 1603, 1614, 1618, 1624, 1635, 1646, 1652, 2033, 2049, 2550, 2558, 2566, 2580, 2588, 2592, 2827, 2831, 2837, 2844, 2848, 2851, 2857, 2868, 2872, 2878, 2885, 2888, 2891, 2898, 2902, 2907, 2913, 2920, 2924, 2934, 2938, 2946, 2957, 2961, 2967, 2974, 2977, 2980, 2987, 2991, 2996, 3002, 3009, 3012, 3015, 3024, 3036, 3044, 3055, 3059, 3065, 3072, 3075, 3078, 3086, 3089, 3092, 3100, 3103, 3106, 3112, 3122, 3126, 3131, 3134, 3137, 3143, 3154, 3158, 3163, 3166, 3169, 3176, 3180, 3185, 3191, 3195, 3206, 3210, 3220, 3232, 3236, 3244, 3251, 3254, 3257, 3264, 3268, 3273, 3279, 3286, 3289, 3297, 3301, 3311, 3322, 3326, 3336, 3343, 3346, 3349, 3356, 3360, 3365, 3371, 3378, 3381, 3384, 3393, 3404 | block | FFI/syscall boundary in TideFS-owned code. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/access_mount_smoke.rs` | 43, 45, 113 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/concurrent_ops.rs` | 105, 107 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/copy_file_range_smoke.rs` | 86, 88, 151 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/data_integrity_lifecycle_smoke.rs` | 143, 145 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fallocate_punch_hole_integration.rs` | 59, 61, 138, 149, 304, 308, 336, 383 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/file_locking_smoke.rs` | 109, 116, 154, 166, 179, 230, 245, 255, 271, 291, 310, 322, 335, 346, 381, 396, 410, 430, 449, 656, 662, 688, 705, 720, 726, 732, 748, 768, 782, 794, 800, 814, 825, 964, 970 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/flush_release_mount_smoke.rs` | 113, 124, 130 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_crash_recovery.rs` | 1105 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_lock_recovery.rs` | 35, 47, 59 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_mount_harness/mod.rs` | 56, 58 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_sync_smoke.rs` | 158, 160 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_vfs_link_smoke.rs` | 41, 43 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_vfs_read_write_smoke.rs` | 78, 80 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_vfs_statfs_smoke.rs` | 42, 46 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_xattr.rs` | 90, 109, 122, 140, 282, 288, 316, 323, 362, 401, 442, 513, 529 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_xattr_smoke.rs` | 109, 126, 145, 163, 176, 193, 206, 246, 252, 275, 282, 299, 318, 340, 358, 378, 385, 413, 419, 441, 461, 479, 496, 533, 559, 586, 639, 664 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/getattr_stat_smoke.rs` | 107, 108, 117 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/intent_log_write_mount_smoke.rs` | 32, 34 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/lseek_smoke.rs` | 45, 47, 171, 302 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/mknod_fifo_smoke.rs` | 99, 108, 119 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/mknod_smoke.rs` | 95, 107, 117 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/open_release_smoke.rs` | 53, 55, 142, 153, 164, 176 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/orphan_tmpfile_rename_crash_recovery.rs` | 51, 70, 83, 94, 105 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/poll_mount_smoke.rs` | 45, 47, 120, 218, 273 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/rename_exchange_smoke.rs` | 107 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/rename_mount_integration.rs` | 106 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/rename_noreplace_smoke.rs` | 107 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/setattr_flush_mount_smoke.rs` | 129, 151, 163, 164, 357, 371, 384, 387, 391, 394, 399, 405 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/symlink_readlink_tests.rs` | 89, 91 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/xattr_acl_locks_integration.rs` | 127, 146, 164, 186, 200, 249, 260, 270, 292, 310, 364, 378, 404, 437 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/xattr_statx_blake3_integration.rs` | 106, 130, 156, 217, 269, 298, 359, 382, 454 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-storage-node/src/main.rs` | 182, 192, 196, 230 | block | Daemon signal/pidfd process-control syscall boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-block-kmod/src/lib.rs` | 393, 434, 470, 506, 959, 972 | block | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-block-kmod/src/pool_core_backend.rs` | 757, 992, 1144 | unsafe impl | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-block-kmod/src/raw_block_file.rs` | 59, 61, 82, 86, 88, 144, 177, 199, 278, 315, 347 | block, unsafe impl | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-block-kmod/tidefs_block_kmod.rs` | 189, 192, 213, 222, 227, 232, 238, 250, 299, 300, 360, 363, 527, 538, 579, 581, 587, 592, 616, 625, 630, 636, 646, 653, 684, 688, 689, 725, 735, 773, 805, 816, 822, 824, 826, 829, 839, 852, 864, 872, 881, 891 | block, unsafe extern, unsafe fn, unsafe impl | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs` | 1059, 1306, 1602, 1914, 2428, 2913, 3436, 3457, 3484, 3508, 3535, 3590, 3660, 3672, 4153, 4238, 4624, 4685, 4959, 5143, 5289, 5814, 8452 | block | ublk/io_uring/block-device syscall or shared-buffer boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-fuser/examples/simple.rs` | 529, 530, 1864 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/channel.rs` | 24, 56 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/ll/mod.rs` | 29 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/mnt/fuse2.rs` | 37, 43, 78 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/mnt/fuse3.rs` | 40, 47, 53, 60, 66, 75, 87 | block, unsafe impl | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/mnt/fuse_pure.rs` | 103, 113, 164, 189, 217, 244, 276, 351, 368, 384, 402, 464, 467, 536 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/mnt/mod.rs` | 70, 116, 126, 149, 188, 214 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/open.rs` | 685 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-fuser/src/session.rs` | 116 | block | Vendored fuser FFI/syscall wrapper code retained as third-party source. | Vendored inventory only; not edited by #1077. |
| `crates/tidefs-inode-attributes/src/lib.rs` | 621 | block | libc stat layout initialization for FUSE reply translation. | Locally documented by #1159 contract review. |
| `crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs` | 2766, 2785, 2861, 3024, 3036, 3094, 3117, 3133, 3177, 3196, 3497, 4074, 4121, 4162, 4546, 4591, 4769, 4809, 5751, 5803, 5829, 5908, 5950, 6935, 6958, 7057, 7164, 7180, 7268, 7276, 7325, 7542, 7550, 7581, 7597, 7710, 7789, 7804, 7885, 7971, 7986, 7999, 8075, 8076, 8079, 8084, 8146, 8156, 8231, 8295, 8298, 8305, 8372, 8374, 8384, 8421, 8440, 8468, 8469, 8470, 8471, 8517, 8618, 8664, 8665, 8666, 8667, 8668, 8669, 8685, 8768, 8776, 8837, 8842, 8893, 8898, 8948, 8992, 9062, 9145, 9175, 9204, 9263, 9273, 9283, 9319, 9329, 9383, 9384, 9429, 9475, 9484, 9521, 9560, 9569, 9604, 9643, 9683, 9685, 9725, 9732, 9770, 9772, 9779, 9805, 9812, 9840, 9903, 9939, 10077, 10088, 10179, 10206, 10258, 10291, 10292, 10301 | block, unsafe extern | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-pool-scan/src/lib.rs` | 1172 | block | Linux block-device ioctl sizing probe. | Locally documented by #1159 contract review. |
| `crates/tidefs-transport/src/rdma/verbs.rs` | 62, 63, 70, 78, 82, 87, 91, 97, 114, 133, 152, 155, 162, 187, 198, 199, 222, 223, 227, 254, 256, 265, 283, 292, 309, 311, 318, 335, 361, 380, 382, 414, 422, 457, 471, 497, 529, 549, 567, 599, 600, 601, 608, 641, 654, 779 | block, unsafe fn, unsafe impl | libibverbs/RDMA FFI resource ownership, queue pair, completion, and memory registration boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-transport/src/rdma.rs` | 178, 203, 209, 339, 363, 441, 1025 | block | libibverbs/RDMA FFI resource ownership, queue pair, completion, and memory registration boundary. | Locally documented by #1159 contract review. |
| `crates/tidefs-validation/src/concurrent_ops.rs` | 599, 625, 640 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/src/host_validation_queue.rs` | 123 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/src/mount_harness.rs` | 318, 355, 373, 392, 421, 438, 463, 467, 487, 536, 567, 580, 606, 618, 657, 721, 785, 924, 927, 937, 946 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/src/smoke/fuse_xattr_acl_locks.rs` | 62, 76, 91, 527, 544, 580, 749, 767, 774, 793, 852, 942, 959, 966 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/crash_recovery_tests.rs` | 745, 816, 832 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_locking.rs` | 44, 58, 74, 99, 182, 269, 272, 283, 289, 325, 328, 343, 349, 380, 383, 407, 413, 487, 490, 496, 502, 539, 545, 552, 559, 561, 573, 574, 580, 584, 594, 598, 605, 610, 628, 634, 660, 663, 677, 683, 764, 770, 777, 784, 786, 798, 799, 805, 809, 818, 822, 829, 834, 851, 857 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_mknod_validation.rs` | 78, 86 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_readdir_statfs_xattr.rs` | 731, 849, 865, 876, 920 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_rename.rs` | 719, 780, 932 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/metadata_ops.rs` | 320, 349, 364, 435, 530, 573, 682, 809, 908, 919, 928, 935, 938, 953, 959, 968, 984, 993, 1028, 1048, 1057 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/remount_persistence.rs` | 287 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/write_durability.rs` | 428, 433, 492, 679, 722, 751, 791, 927, 932, 934 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `kmod/src/kernel_types.rs` | 2778, 2780, 2781, 2782, 2872, 2881, 3057, 3065, 3069, 3073 | block, unsafe extern | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `kmod/src/lib.rs` | 170, 177, 184, 191, 198, 205, 212, 219, 223, 233 | block | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `kmod/src/types.rs` | 51, 81, 111, 141, 175, 224, 255, 412 | unsafe fn | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
