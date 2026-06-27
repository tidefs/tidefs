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
| `apps/tidefs-posix-filesystem-adapter-daemon/src/lib.rs` | 816, 821, 829, 831, 836, 881 | block | FFI/syscall boundary in TideFS-owned code. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs` | 593, 594, 603, 1558, 1576, 1588, 1597, 1599, 1603, 1612, 1621, 1625, 2004, 2018, 2517, 2523, 2529, 2541, 2547, 2549, 2782, 2784, 2788, 2793, 2795, 2796, 2801, 2810, 2812, 2816, 2821, 2822, 2823, 2828, 2830, 2833, 2837, 2842, 2844, 2852, 2854, 2860, 2869, 2871, 2875, 2880, 2881, 2882, 2887, 2889, 2892, 2896, 2901, 2902, 2903, 2910, 2920, 2926, 2935, 2937, 2941, 2946, 2947, 2948, 2954, 2955, 2956, 2962, 2963, 2964, 2969, 2977, 2979, 2983, 2984, 2985, 2990, 2999, 3001, 3005, 3006, 3007, 3012, 3014, 3017, 3021, 3023, 3032, 3034, 3042, 3052, 3054, 3060, 3065, 3066, 3067, 3072, 3074, 3077, 3081, 3086, 3087, 3093, 3095, 3103, 3112, 3114, 3122, 3127, 3128, 3129, 3134, 3136, 3139, 3143, 3148, 3149, 3150, 3157, 3166 | block | FFI/syscall boundary in TideFS-owned code. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/access_mount_smoke.rs` | 41, 43, 109 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/concurrent_ops.rs` | 103, 105 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/copy_file_range_smoke.rs` | 84, 86, 146 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/data_integrity_lifecycle_smoke.rs` | 141, 143 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fallocate_punch_hole_integration.rs` | 57, 59, 134, 143, 296, 298, 324, 369 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/file_locking_smoke.rs` | 107, 112, 148, 158, 169, 218, 231, 239, 253, 271, 288, 298, 309, 318, 351, 365, 377, 395, 412, 617, 621, 645, 660, 673, 677, 681, 695, 713, 725, 735, 739, 751, 760, 897, 901 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/flush_release_mount_smoke.rs` | 111, 120, 124 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_crash_recovery.rs` | 1103 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_lock_recovery.rs` | 33, 43, 53 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_mount_harness/mod.rs` | 54, 56 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_sync_smoke.rs` | 156, 158 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_vfs_link_smoke.rs` | 39, 41 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_vfs_read_write_smoke.rs` | 76, 78 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_vfs_statfs_smoke.rs` | 40, 42 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_xattr.rs` | 86, 101, 110, 124, 264, 268, 294, 299, 336, 373, 412, 481, 495 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_xattr_smoke.rs` | 107, 120, 135, 149, 158, 171, 180, 218, 222, 243, 248, 263, 280, 300, 316, 334, 339, 365, 369, 389, 407, 423, 438, 473, 497, 522, 573, 596 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/getattr_stat_smoke.rs` | 105, 106, 113 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/intent_log_write_mount_smoke.rs` | 30, 32 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/lseek_smoke.rs` | 43, 45, 167, 296 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/mknod_fifo_smoke.rs` | 97, 104, 113 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/mknod_smoke.rs` | 93, 103, 111 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/open_release_smoke.rs` | 51, 53, 138, 147, 156, 166 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/orphan_tmpfile_rename_crash_recovery.rs` | 51, 70, 83, 94, 105 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/poll_mount_smoke.rs` | 43, 45, 116, 211, 264 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/rename_exchange_smoke.rs` | 105 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/rename_mount_integration.rs` | 104 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/rename_noreplace_smoke.rs` | 105 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/setattr_flush_mount_smoke.rs` | 127, 147, 157, 158, 349, 361, 372, 373, 375, 376, 379, 383 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/symlink_readlink_tests.rs` | 87, 89 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/xattr_acl_locks_integration.rs` | 123, 138, 152, 172, 184, 231, 240, 248, 268, 284, 336, 348, 372, 403 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `apps/tidefs-posix-filesystem-adapter-daemon/tests/xattr_statx_blake3_integration.rs` | 102, 122, 143, 202, 252, 279, 338, 358, 427 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
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
| `crates/tidefs-validation/src/host_validation_queue.rs` | 121 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/src/mount_harness.rs` | 329, 366, 384, 403, 432, 449, 474, 478, 498, 547, 578, 591, 617, 629, 668, 685, 688, 743, 807, 926, 935 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/src/smoke/fuse_xattr_acl_locks.rs` | 62, 76, 91, 527, 544, 580, 749, 767, 774, 793, 852, 942, 959, 964 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/crash_recovery_tests.rs` | 745, 816, 832 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_locking.rs` | 44, 58, 74, 98, 181, 268, 271, 282, 288, 324, 327, 342, 348, 379, 382, 406, 412, 486, 489, 495, 501, 538, 544, 551, 558, 560, 572, 573, 579, 583, 593, 597, 604, 609, 627, 633, 659, 662, 676, 682, 763, 769, 774, 781, 783, 795, 796, 802, 806, 815, 819, 826, 831, 848, 854 | block, unsafe fn | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_mknod_validation.rs` | 78, 86 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_readdir_statfs_xattr.rs` | 731, 849, 865, 876, 920 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/fuse_rename.rs` | 719, 780, 932 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/metadata_ops.rs` | 320, 349, 364, 435, 530, 573, 682, 809, 908, 919, 928, 935, 938, 953, 959, 968, 984, 993, 1028, 1048, 1057 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/remount_persistence.rs` | 265 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `crates/tidefs-validation/tests/write_durability.rs` | 428, 433, 492, 679, 722, 751, 791, 927, 932, 934 | block | POSIX/FUSE validation syscall harness or process-control helper. | Locally documented by #1158 contract review. |
| `kmod/src/kernel_types.rs` | 2778, 2780, 2781, 2782, 2872, 2881, 3057, 3065, 3069, 3073 | block, unsafe extern | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `kmod/src/lib.rs` | 170, 177, 184, 191, 198, 205, 212, 219, 223, 233 | block | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
| `kmod/src/types.rs` | 51, 81, 111, 141, 175, 224, 255, 412 | unsafe fn | Kernel/module FFI, opaque kernel handles, raw pointer facades, or callback boundary. | Locally documented by #1159 contract review. |
