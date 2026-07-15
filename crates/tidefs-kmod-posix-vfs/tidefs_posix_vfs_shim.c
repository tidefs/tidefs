// SPDX-License-Identifier: GPL-2.0
/*
 * Linux VFS registration shim for the Rust TideFS POSIX module.
 *
 * Linux 7.0 does not expose a stable Rust filesystem registration API in this
 * tree, so the Rust module entry point calls this C shim during init/drop.
 *
 * Mount paths (four tiers):
 *   Tier 0: -o bootstrap  → fail-closed; the historical synthetic root is not
 *                            an authoritative no-daemon pool mount.
 *   Tier 1: default        → fail-closed when no block device is supplied.
 *   Tier 2: mount /dev/... → engine-backed mount: reads PoolLabelV1,
 *                            parses label via Rust bridge, locates and reads
 *                            committed-root ledger from superblock region,
 *                            selects the most recent valid committed root,
 *                            creates real root inode with engine-derived
 *                            superblock parameters, stores kernel-resident
 *                            context in sb->s_fs_info.  statfs reports
 *                            pool-backed capacity.  kill_sb releases context.
 *   Tier 3: full-kernel    → (future) no usermode daemon for normal I/O.
 *
 * The durable TideFS storage engine and full operation tables are wired in
 * later tiers.
 */

#include <linux/errno.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/falloc.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/err.h>
#include <linux/refcount.h>
#include <linux/uaccess.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/exportfs.h>
#include <linux/splice.h>
#include <linux/highmem.h>
#include <linux/uio.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/limits.h>
#include <linux/math64.h>
/* ilog2 computed inline; no linux/log2.h include needed */
#include <linux/seq_file.h>

/*
 * Older kernel trees do not expose the newer fserror reporting API.
 * Keep the module buildable by treating those callbacks as optional.
 */
#ifndef __has_include
#define __has_include(x) 0
#endif

#if __has_include(<linux/fserror.h>)
#include <linux/fserror.h>
#define TIDEFS_HAVE_FSERROR 1
#else
#define TIDEFS_HAVE_FSERROR 0
struct fserror_event {
	struct super_block *sb;
	int error;
	int type;
};
static inline void fserror_report_shutdown(struct super_block *sb, int flags)
{
	(void)sb;
	(void)flags;
}
#endif

int tidefs_posix_vfs_register_fs(void);
void tidefs_posix_vfs_unregister_fs(void);

#define TIDEFS_POSIX_VFS_FATTR_MODE  0x01u
#define TIDEFS_POSIX_VFS_FATTR_UID   0x02u
#define TIDEFS_POSIX_VFS_FATTR_GID   0x04u
#define TIDEFS_POSIX_VFS_FATTR_SIZE  0x08u
#define TIDEFS_POSIX_VFS_FATTR_ATIME 0x10u
#define TIDEFS_POSIX_VFS_FATTR_MTIME 0x20u
#define TIDEFS_POSIX_VFS_FATTR_CTIME 0x80u
#define TIDEFS_POSIX_VFS_FATTR_TIMES \
	(TIDEFS_POSIX_VFS_FATTR_ATIME | TIDEFS_POSIX_VFS_FATTR_MTIME | \
	 TIDEFS_POSIX_VFS_FATTR_CTIME)
#define TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME \
	(TIDEFS_POSIX_VFS_FATTR_MTIME | TIDEFS_POSIX_VFS_FATTR_CTIME)

/*
 * Linux 7.0 exposes exclusive filemap invalidation helpers, but not shared
 * wrappers.  The VFS mapping still carries the rwsem that those helpers use.
 */
static void tidefs_posix_vfs_filemap_invalidate_lock_shared(
	struct address_space *mapping)
{
	down_read(&mapping->invalidate_lock);
}

static void tidefs_posix_vfs_filemap_invalidate_unlock_shared(
	struct address_space *mapping)
{
	up_read(&mapping->invalidate_lock);
}

/* Forward declaration for the block-device-backed fill_super. */
static int tidefs_posix_vfs_fill_super_bdev(struct super_block *sb,
					    struct fs_context *fc);

/*
 * Rust-side engine bridge functions -- defined in tidefs_posix_vfs_main.rs.
 *
 * Active Tier 2 mount-path bridges:
 *   tidefs_posix_vfs_engine_parse_label      -- parse label buffer, return
 *                                               superblock region location
 *   tidefs_posix_vfs_engine_mount_with_label -- validate label + committed-root
 *                                               ledger, return mount params
 *
 * Legacy bridges:
 *   tidefs_posix_vfs_engine_fill_super       -- mount validation (legacy)
 *   tidefs_posix_vfs_engine_fill_super_label -- label-backed mount (legacy,
 *                                               forwards to mount_with_label)
 *   tidefs_posix_vfs_engine_statfs           -- engine-backed statfs
 *   tidefs_posix_vfs_engine_sync_fs          -- engine-backed sync_fs callback
 *   tidefs_posix_vfs_engine_kill_sb          -- engine teardown with final syncfs flush
 *   tidefs_posix_vfs_engine_getxattr        -- xattr value read (REL-KTFS-010)
 *   tidefs_posix_vfs_engine_listxattr       -- xattr name list (REL-KTFS-010)
 *   tidefs_posix_vfs_engine_setxattr        -- xattr value set (REL-KTFS-010)
 *   tidefs_posix_vfs_engine_removexattr     -- xattr removal (REL-KTFS-010)
 */

/* Label parse output struct -- repr(C) matching TidefsLabelParseOut in Rust. */
struct tidefs_posix_vfs_label_parse_out {
	unsigned long long superblock_offset;
	unsigned long long superblock_size;
	unsigned long long recovery_commit_group;
	unsigned char label_copy;
	unsigned long long device_capacity_bytes;
	unsigned long long topology_generation;
	unsigned char _pad[7];
};

/* Mount output struct -- repr(C) matching TidefsMountOut in Rust. */
struct tidefs_posix_vfs_mount_out {
	unsigned long long root_ino;
	unsigned long long fsid_hi;
	unsigned long long fsid_lo;
	unsigned int block_size;
	unsigned long long committed_txg;
	unsigned long long total_blocks;
	unsigned long long free_blocks;
	unsigned long long avail_blocks;
	unsigned long long total_inodes;
	unsigned long long free_inodes;
	unsigned int name_max;
	unsigned char pool_uuid[32];
};

/* Kernel replay mount output struct -- repr(C) matching TidefsReplayMountOut in Rust.
 * Replaces the legacy fixed-table handoff (tidefs_kernel_pool_load_state).
 * The C shim treats this as authoritative mount-time namespace state. */
/* Engine-backed open output (#6274). */
struct TidefsEngineOpenOut {
	u8 ok;
	u64 fh_ino;
	u64 fh_id;
};

/* Per-open file state stored in file->private_data for engine-backed files.
 * Carries the real engine file handle so read/write/release/copy/fsync/llseek
 * can use the same authoritative session instead of fabricating handles or
 * falling back to the C fixed-table buffer. */
struct tidefs_posix_vfs_open_file_state {
	u64 fh_ino;          /* inode number from engine open */
	u64 fh_id;           /* file handle id from engine open */
	u32 open_flags;      /* O_* flags captured at open */
	bool engine_backed;  /* true when engine open succeeded */
	bool times_dirty;    /* mtime/ctime need one engine persist on fsync/release */
};

struct tidefs_posix_vfs_replay_mount_out {
	unsigned long long root_ino;
	unsigned long long fsid_hi;
	unsigned long long fsid_lo;
	unsigned int block_size;
	unsigned long long committed_txg;
	unsigned long long total_blocks;
	unsigned long long free_blocks;
	unsigned long long avail_blocks;
	unsigned long long total_inodes;
	unsigned long long free_inodes;
	unsigned int name_max;
	unsigned char pool_uuid[32];
	unsigned long long replay_replayed;
	unsigned long long replay_skipped;
	unsigned long long replay_errored;
	unsigned char clean_export;
	unsigned long long inode_table_root;
	unsigned long long extent_map_root;
	unsigned long long intent_log_head;
	unsigned long long intent_log_tail;
	unsigned char _pad[7];
};

/* statfs handoff structs -- repr(C) layout matching Rust bridge structs. */
struct tidefs_posix_vfs_statfs_in {
	unsigned int f_bsize;
	unsigned int f_frsize;
	unsigned long long f_blocks;
	unsigned long long f_bfree;
	unsigned long long f_bavail;
	unsigned long long f_files;
	unsigned long long f_ffree;
	unsigned long long f_favail;
	unsigned int f_namelen;
	unsigned long long f_fsid_hi;
	unsigned long long f_fsid_lo;
};

struct tidefs_posix_vfs_statfs_out {
	unsigned int f_bsize;
	unsigned int f_frsize;
	unsigned long long f_blocks;
	unsigned long long f_bfree;
	unsigned long long f_bavail;
	unsigned long long f_files;
	unsigned long long f_ffree;
	unsigned long long f_favail;
	unsigned int f_namelen;
	unsigned long long f_fsid_hi;
	unsigned long long f_fsid_lo;
};


/* Replay getattr output struct -- repr(C) matching TidefsReplayGetattrOut in Rust (#6252). */
struct tidefs_posix_vfs_replay_getattr_out {
	unsigned int mode;
	unsigned int uid;
	unsigned int gid;
	unsigned long long size;
	unsigned long long blocks;
	unsigned int nlink;
	unsigned char kind;
	unsigned long long object_store_locator;
	unsigned long long extent_map_root;
	unsigned long long generation;
	long long atime_secs;
	long long mtime_secs;
	long long ctime_secs;
	unsigned long long btime_secs;
	unsigned int btime_nsec;
	unsigned int flags;
	unsigned int blksize;
};

int tidefs_posix_vfs_engine_replay_getattr(
	const void *vrbt_buf, unsigned long vrbt_len,
	const void *inode_table_buf, unsigned long ino_table_len,
	unsigned int block_size,
	unsigned long long ino,
	struct tidefs_posix_vfs_replay_getattr_out *out);

/* Replay directory lookup output struct (#6260). */
struct tidefs_posix_vfs_replay_lookup_out {
	unsigned long long ino;
	unsigned char entry_type;
	unsigned char kind;
};

int tidefs_posix_vfs_engine_replay_lookup(
	const void *dir_page_buf, unsigned long dir_page_len,
	unsigned int block_size,
	const void *name_buf, unsigned long name_len,
	struct tidefs_posix_vfs_replay_lookup_out *out);

/* Replay readdir output struct (#6252). */
struct tidefs_posix_vfs_replay_readdir_out {
	unsigned long long ino;
	unsigned char entry_type;
	unsigned char kind;
	unsigned char name_len;
	unsigned int next_cookie;
};

int tidefs_posix_vfs_engine_replay_readdir(
	const void *dir_page_buf, unsigned long dir_page_len,
	unsigned int cookie,
	struct tidefs_posix_vfs_replay_readdir_out *out);

/* Engine-backed readdir output struct for cookie-based directory iteration. */
struct tidefs_posix_vfs_engine_readdir_out {
	unsigned long long ino;
	unsigned char entry_type;
	unsigned char kind;
	unsigned char name_len;
	unsigned int next_cookie;
};

struct tidefs_posix_vfs_engine_fiemap_extent {
	unsigned long long logical;
	unsigned long long physical;
	unsigned long long length;
	unsigned int flags;
	unsigned int _pad;
};

struct tidefs_posix_vfs_engine_attr_out {
	unsigned long long ino;
	unsigned long long generation;
	unsigned long long size;
	unsigned long long blocks;
	unsigned int mode;
	unsigned int uid;
	unsigned int gid;
	unsigned int nlink;
	long long atime_ns;
	long long mtime_ns;
	long long ctime_ns;
};

int tidefs_posix_vfs_engine_lookup(
	unsigned long long parent_ino,
	const unsigned char *name_buf,
	unsigned int name_len,
	struct tidefs_posix_vfs_engine_attr_out *out);

int tidefs_posix_vfs_engine_getattr(
	unsigned long long ino,
	struct tidefs_posix_vfs_engine_attr_out *out);

int tidefs_posix_vfs_engine_get_parent(
	unsigned long long child_ino,
	unsigned long long *out_parent_ino);

int tidefs_posix_vfs_engine_readdir(
	unsigned long long directory_ino,
	unsigned int cookie,
	struct tidefs_posix_vfs_engine_readdir_out *out);

int tidefs_posix_vfs_engine_readdir_name(
	unsigned long long directory_ino,
	unsigned int cookie,
	unsigned char *out_buf,
	unsigned int out_buf_size,
	unsigned int *out_name_len);

/* Replay extent lookup output struct (#6252 file read). */
struct tidefs_posix_vfs_replay_extent_out {
	unsigned long long locator_id;
	unsigned long long extent_internal_offset;
	unsigned long long extent_length;
	unsigned char extent_kind;
	unsigned char _pad[7];
};

/* Engine-backed open/release bridges (#6274). */
int tidefs_posix_vfs_engine_open(
	u64 ino, u32 flags,
	struct TidefsEngineOpenOut *out);
int tidefs_posix_vfs_engine_release(
	u64 ino, u64 fh_id);
int tidefs_posix_vfs_engine_opendir(
	u64 ino, struct TidefsEngineOpenOut *out);
int tidefs_posix_vfs_engine_releasedir(
	u64 ino, u64 dh_id);

/* Engine-backed write bridge (#6046 / #6642). */
int tidefs_posix_vfs_engine_write(
	u64 fh_ino,
	u64 fh_id,
	u64 offset,
	const unsigned char *buf,
	u32 buf_len);

/* Engine-backed read bridge (#6642). */
int tidefs_posix_vfs_engine_read(
	u64 fh_ino,
	u64 fh_id,
	u64 offset,
	unsigned char *buf,
	u32 buf_len);

/* Engine-backed fsync bridge (#6642). */
int tidefs_posix_vfs_engine_fsync(
	u64 fh_ino,
	u64 fh_id,
	u64 start,
	u64 end,
	int datasync);

/* Engine-backed llseek bridge for SEEK_DATA/SEEK_HOLE. */
int tidefs_posix_vfs_engine_llseek(
	u64 fh_ino,
	u64 fh_id,
	s64 offset,
	u32 whence,
	s64 current_pos);

/* Engine-backed fallocate bridge (#6642). */
int tidefs_posix_vfs_engine_fallocate(
	u64 fh_ino,
	u64 fh_id,
	u32 mode,
	u64 offset,
	u64 length,
	s64 mtime_ns,
	s64 ctime_ns,
	u64 *out_size,
	u64 *out_blocks);

int tidefs_posix_vfs_engine_fiemap(
	u64 fh_ino,
	u64 fh_id,
	u64 start,
	u64 length,
	u32 max_extents,
	struct tidefs_posix_vfs_engine_fiemap_extent *extents,
	u32 *mapped_extents,
	u32 *available_extents);

	int tidefs_posix_vfs_engine_replay_extent_lookup(
	const void *extent_page_buf, unsigned long extent_page_len,
	unsigned long long logical_offset,
	struct tidefs_posix_vfs_replay_extent_out *out);


int tidefs_posix_vfs_engine_copy_file_range(
	u64 fh_ino_in, u64 fh_id_in, u64 offset_in,
	u64 fh_ino_out, u64 fh_id_out, u64 offset_out,
	u64 length, u32 *out_copied);
int tidefs_posix_vfs_engine_parse_label(
	const void *label_buf, unsigned long label_len,
	struct tidefs_posix_vfs_label_parse_out *out);
int tidefs_posix_vfs_engine_mount_with_label(
	const void *label_buf, unsigned long label_len,
	const void *ledger_buf, unsigned long ledger_len,
	struct tidefs_posix_vfs_mount_out *out);

int tidefs_posix_vfs_kernel_replay_mount(
	const void *label_buf, unsigned long label_len,
	const void *ledger_buf, unsigned long ledger_len,
	const void *intent_buf, unsigned long intent_len,
	int recovery_mode,
	struct tidefs_posix_vfs_replay_mount_out *out);

unsigned long long tidefs_posix_vfs_engine_get_vrbt_intent_tail(
	const void *superblock_buf, unsigned long superblock_len,
	unsigned int block_size);

int tidefs_posix_vfs_engine_fill_super(const char *mount_opts,
				       unsigned long long committed_txg);
int tidefs_posix_vfs_engine_fill_super_label(
	const void *label_buf, unsigned long label_len,
	const void *ledger_buf, unsigned long ledger_len,
	unsigned long long committed_txg);
int tidefs_posix_vfs_engine_statfs(
	const struct tidefs_posix_vfs_statfs_in *in,
	struct tidefs_posix_vfs_statfs_out *out);
int tidefs_posix_vfs_engine_sync_fs(int wait);
/* Sync C pool inode table to Rust KernelEngine in-memory namespace. */
int tidefs_posix_vfs_engine_sync_namespace(
	unsigned int count,
	const unsigned long long *inos,
	const unsigned long long *parent_inos,
	const unsigned int *modes,
	const unsigned char *const *names,
	const unsigned int *name_lens,
	const unsigned long long *data_lens);

int tidefs_posix_vfs_engine_init_mounted(
	int (*write_fn)(unsigned long long, const unsigned char *, unsigned int),
	int (*read_fn)(unsigned long long, unsigned char *, unsigned int),
	int (*flush_fn)(void),
	int (*teardown_fn)(void),
	unsigned int sector_size,
	unsigned long long sb_offset,
	unsigned long long sb_size,
	unsigned long long device_capacity_bytes,
	unsigned long long committed_txg,
	unsigned long long root_ino,
	const unsigned char *pool_uuid,
	unsigned int major,
	unsigned int minor,
	unsigned long long inode_table_root,
	unsigned long long extent_map_root,
	unsigned long long intent_log_head,
	unsigned long long intent_log_tail,
	unsigned long long replay_replayed,
	unsigned long long replay_skipped,
	unsigned long long replay_errored,
	unsigned char clean_export);
int tidefs_posix_vfs_engine_teardown_mounted(void);
void tidefs_posix_vfs_engine_record_cluster_config(
	const char *cluster_node_id,
	const char *transport_carrier);
int tidefs_posix_vfs_engine_kill_sb(void);
/* Validate mount options (features and authority_mode) through Rust parser.
 * Returns 0 on success, or a negative errno with a TideFS-specific kernel
 * log message on feature-refusal or invalid-value refusal. */
int tidefs_posix_vfs_engine_validate_mount_options(
	const char *features,
	unsigned int features_len,
	const char *authority_mode,
	unsigned int authority_mode_len);
int tidefs_posix_vfs_engine_encode_committed_root_ledger(
	unsigned long long root_ino,
	const unsigned char *pool_uuid,
	unsigned long pool_uuid_len,
	unsigned long long committed_txg,
	unsigned char *out_buf,
	unsigned long out_len,
	unsigned long *written_len);
/* Xattr bridge declarations (REL-KVFS-010) -- read-side only for this slice. */
int tidefs_posix_vfs_engine_getxattr(
	unsigned long long ino,
	const unsigned char *name_buf, unsigned int name_len,
	unsigned char *value_buf, unsigned int value_size,
	unsigned int *out_len);
int tidefs_posix_vfs_engine_listxattr(
	unsigned long long ino,
	unsigned char *buf, unsigned int buf_size,
	unsigned int *out_len);
int tidefs_posix_vfs_engine_setxattr(
	unsigned long long ino,
	const unsigned char *name_buf, unsigned int name_len,
	const unsigned char *value_buf, unsigned int value_len,
	unsigned int flags);
int tidefs_posix_vfs_engine_removexattr(
	unsigned long long ino,
	const unsigned char *name_buf, unsigned int name_len);
/* Inode generation lookup for exportfs file handles. */
int tidefs_posix_vfs_engine_get_generation(
	unsigned long long ino,
	unsigned long long *out_generation);

int tidefs_posix_vfs_engine_encode_committed_root_vrbt(
	unsigned long long commit_group_id,
	unsigned long long namespace_root,
	unsigned long long inode_table_root,
	unsigned long long extent_map_root,
	unsigned long long intent_log_tail,
	unsigned long long pointer_sequence,
	unsigned long long root_sector,
	unsigned char *root_buf,
	unsigned long root_len,
	unsigned long *root_written_len,
	unsigned char *pointer_buf,
	unsigned long pointer_len,
	unsigned long *pointer_written_len);
/* Engine-backed namespace mutation bridges (#6270 REL-KVFS-002).
 * Replace the fixed-table approach for create, mkdir, rmdir, unlink
 * when the mount context has engine_backed set. */
int tidefs_posix_vfs_engine_create(
	unsigned long long parent_ino,
	const unsigned char *name_buf, unsigned int name_len,
	unsigned int mode, unsigned int flags,
	unsigned long long *out_ino, unsigned int *out_mode,
	unsigned long long *out_generation);
int tidefs_posix_vfs_engine_mkdir(
	unsigned long long parent_ino,
	const unsigned char *name_buf, unsigned int name_len,
	unsigned int mode,
	unsigned long long *out_ino, unsigned int *out_mode,
	unsigned long long *out_generation);
int tidefs_posix_vfs_engine_rmdir(
	unsigned long long parent_ino,
	const unsigned char *name_buf, unsigned int name_len);
int tidefs_posix_vfs_engine_unlink(
	unsigned long long parent_ino,
	const unsigned char *name_buf, unsigned int name_len);
/* Engine-backed rename, link, symlink, readlink bridges (#6271 REL-KVFS-003). */
int tidefs_posix_vfs_engine_rename(
	unsigned long long old_parent_ino,
	const unsigned char *old_name_buf, unsigned int old_name_len,
	unsigned long long new_parent_ino,
	const unsigned char *new_name_buf, unsigned int new_name_len,
	unsigned int flags);
int tidefs_posix_vfs_engine_link(
	unsigned long long target_ino,
	unsigned long long new_parent_ino,
	const unsigned char *new_name_buf, unsigned int new_name_len,
	unsigned long long *out_ino, unsigned int *out_mode);
int tidefs_posix_vfs_engine_symlink(
	unsigned long long parent_ino,
	const unsigned char *name_buf, unsigned int name_len,
	const unsigned char *target_buf, unsigned int target_len,
	unsigned long long *out_ino, unsigned int *out_mode,
	unsigned long long *out_generation);

int tidefs_posix_vfs_engine_mknod(
	unsigned long long parent_ino,
	const unsigned char *name_buf, unsigned int name_len,
	unsigned int mode, unsigned int rdev,
	unsigned long long *out_ino, unsigned int *out_mode,
	unsigned long long *out_generation);
int tidefs_posix_vfs_engine_readlink(
	unsigned long long ino,
	unsigned char *out_buf, unsigned int out_buf_size,
	unsigned int *out_len);
/* Engine-backed O_TMPFILE unnamed temporary file bridge. */
int tidefs_posix_vfs_engine_tmpfile(
	unsigned long long parent_ino,
	unsigned int mode, unsigned int flags,
	unsigned long long *out_ino, unsigned int *out_mode,
	unsigned long long *out_generation);


/* Engine-backed setattr bridge (#6143): chmod, chown, truncate, utimes. */
int tidefs_posix_vfs_engine_setattr(
	unsigned long long ino,
	unsigned int valid,
	unsigned int mode,
	unsigned int uid,
	unsigned int gid,
	unsigned long long size,
	long long atime_ns,
	long long mtime_ns,
	long long ctime_ns,
	unsigned int *out_mode,
	unsigned int *out_uid,
	unsigned int *out_gid,
	unsigned long long *out_size,
	unsigned long long *out_blocks);


/*
 * First kernel-resident pool core slice for the POSIX front-end.
 *
 * This is deliberately still a skeleton: it owns the imported lower block
 * device identity, committed-root selection, capacity counters, and lifetime
 * state for one mounted pool, but individual VFS operation engines are still
 * wired in later issue slices. Unsupported operations therefore fail through
 * this context instead of pretending the mount has no pool.
 */
struct tidefs_posix_vfs_kernel_pool_core {
	bool imported;
	refcount_t refs;
	struct block_device *bdev;
	struct super_block *sb;
	u64 root_ino;
	u8 pool_uuid[32];
	u64 fsid;
	u64 committed_txg;
	u64 topology_generation;
	u64 device_capacity_bytes;
	u64 superblock_offset;
	u64 superblock_size;
	u32 block_size;
	u64 total_blocks;
	u64 free_blocks;
	u64 avail_blocks;
	u64 total_inodes;
	u64 free_inodes;
	u32 name_max;
	u64 inode_table_root;
	u64 extent_map_root;
	u64 intent_log_head;
	u64 intent_log_tail;
	u64 replay_replayed;
	u64 replay_skipped;
	u64 replay_errored;
	bool clean_export;
	/*
	 * Legacy kernel-resident namespace/data table retained for older fixed
	 * table operations.  Engine-backed replay mounts do not load this table as
	 * successful mount authority; they must import committed-root object,
	 * extent, inode, and replay state before the root dentry is created.
	 */
	u64 next_ino;
	u64 next_generation;
#define TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE 128
#define TIDEFS_KERNEL_POOL_NAME_MAX NAME_MAX
#define TIDEFS_KERNEL_POOL_FILE_DATA_SIZE 4096
	struct {
		u64 ino;
		u64 parent_ino;
		umode_t mode;
		u64 data_len;
		u8 data[TIDEFS_KERNEL_POOL_FILE_DATA_SIZE];
		u8 name[TIDEFS_KERNEL_POOL_NAME_MAX + 1];
		u8 name_len;
		u64 generation;
	} inode_table[TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE];
	int nr_inodes;
};

#define TIDEFS_KERNEL_POOL_STATE_MAGIC 0x3146534eU /* "NSF1" LE */
#define TIDEFS_KERNEL_POOL_STATE_VERSION 1U
#define TIDEFS_KERNEL_POOL_STATE_RECORD_NAME (TIDEFS_KERNEL_POOL_NAME_MAX + 1)
#define TIDEFS_KERNEL_POOL_STATE_RECORD_REGION_BYTES (128ULL * 1024ULL)
#define TIDEFS_KERNEL_POOL_STATE_BLOCK_OFFSET 0ULL
#define TIDEFS_KERNEL_POOL_STATE_DATA_OFFSET TIDEFS_KERNEL_POOL_STATE_RECORD_REGION_BYTES
#define TIDEFS_KERNEL_POOL_ENGINE_DATA_OFFSET (1024ULL * 1024ULL)
#define TIDEFS_KERNEL_POOL_ENGINE_INTENT_LOG_OFFSET 4096ULL
#define TIDEFS_KERNEL_POOL_COMMITTED_LEDGER_MIN_SIZE (12U + 80U + 32U)
#define TIDEFS_KERNEL_POOL_VRBT_WIRE_SIZE 88U
#define TIDEFS_KERNEL_POOL_VCRP_RECORD_SIZE 96U

struct tidefs_kernel_pool_state_header {
	__le32 magic;
	__le32 version;
	__le32 nr_inodes;
	__le32 record_size;
	__le64 next_ino;
	__le64 committed_txg;
} __packed;

struct tidefs_kernel_pool_state_record {
	__le64 ino;
	__le64 parent_ino;
	__le64 data_len;
	__le32 mode;
	__le16 name_len;
	__le16 flags;
	u8 name[TIDEFS_KERNEL_POOL_STATE_RECORD_NAME];
} __packed;

/*
 * Temporary kernel-resident mount state for the first real Linux VFS root.
 *
 * This is intentionally narrow: it is not full-kernel TideFS storage and it
 * does not claim read/write/page-cache/crash-consistency readiness. It gives
 * the mounted superblock a concrete in-kernel context, root inode, statfs
 * source, and teardown path so later clean-read operations have real VFS
 * objects to attach to.
 */
#define TIDEFS_POSIX_VFS_PAGECACHE_FENCE_SLOTS 128

struct tidefs_posix_vfs_pagecache_fence {
	unsigned long ino;
	loff_t start;
	loff_t end;
	u64 generation;
};

struct tidefs_posix_vfs_mount {
	bool bootstrap_only;
	bool engine_backed;
	bool read_only;
	bool recovery_mode;
	bool debug;
	bool engine_activated;
	unsigned int commit_timeout_ms;
	u64 root_ino;
	u64 fsid;
	u64 committed_txg;
	u32 block_size;
	u64 total_blocks;
	u64 free_blocks;
	u64 avail_blocks;
	u64 total_inodes;
	u64 free_inodes;
	u32 name_max;
	u32 sync_fs_calls;
	u32 put_super_calls;
	u32 umount_begin_calls;
	u32 evict_inode_calls;
	u32 write_inode_calls;
	u32 evict_orphan_calls;
	u32 shutdown_calls;
	u32 freeze_fs_refusals;
	u32 unfreeze_fs_refusals;
	u32 remount_fs_refusals;
	u32 report_error_calls;
	u32 dentry_delete_calls;
	u32 dentry_release_calls;
	u32 dentry_iput_calls;
	u32 dentry_iput_orphan_calls;
	u32 write_begin_calls;
	u32 write_end_calls;
	u32 dirty_folio_calls;
	u32 writepages_calls;
	spinlock_t pagecache_fence_lock;
	u64 pagecache_fence_generation;
	u64 pagecache_fence_overflow_generation;
	u32 pagecache_fence_cursor;
	struct tidefs_posix_vfs_pagecache_fence
		pagecache_fences[TIDEFS_POSIX_VFS_PAGECACHE_FENCE_SLOTS];
	struct tidefs_posix_vfs_kernel_pool_core pool;
	char *cluster_node_id;
	char *transport_carrier;
};

#define TIDEFS_POSIX_TFS_MAGIC 0x56494653 /* "VIFS" */
#define TIDEFS_POSIX_TFS_POOL_LABEL_SIZE (256 * 1024) /* 256 KiB */

enum {
	Opt_bootstrap,
	Opt_engine_backed,
	Opt_device,
	Opt_ro,
	Opt_rw,
	Opt_recovery,
	Opt_debug,
	Opt_commit_timeout_ms,
	Opt_features,
	Opt_authority_mode,
	Opt_cluster_node_id,
	Opt_transport_carrier,
};

struct tidefs_posix_vfs_fs_context {
	bool bootstrap;
	char *device_path;
	bool read_only;
	bool recovery_mode;
	bool debug;
	unsigned int commit_timeout_ms;
	char *features;
	char *authority_mode;
	char *cluster_node_id;
	char *transport_carrier;
};

static const struct fs_parameter_spec tidefs_posix_vfs_fs_parameters[] = {
	fsparam_flag("bootstrap", Opt_bootstrap),
	fsparam_flag("engine-backed", Opt_engine_backed),
	fsparam_string("device", Opt_device),
	fsparam_flag("ro", Opt_ro),
	fsparam_flag("rw", Opt_rw),
	fsparam_flag("recovery", Opt_recovery),
	fsparam_flag("debug", Opt_debug),
	fsparam_u32("commit_timeout_ms", Opt_commit_timeout_ms),
	fsparam_string("features", Opt_features),
	fsparam_string("authority_mode", Opt_authority_mode),
	fsparam_string("cluster_node_id", Opt_cluster_node_id),
	fsparam_string("transport_carrier", Opt_transport_carrier),
	{}
};

static const struct super_operations tidefs_posix_vfs_super_ops;
static const struct inode_operations tidefs_posix_vfs_dir_inode_operations;
static const struct file_operations tidefs_posix_vfs_dir_file_operations;
static const struct inode_operations tidefs_posix_vfs_file_inode_operations;
static const struct file_operations tidefs_posix_vfs_file_operations;
static const struct address_space_operations tidefs_posix_vfs_aops;
static u64 tidefs_posix_vfs_pagecache_fence_snapshot(struct inode *inode,
						     loff_t pos,
						     size_t len);
static bool tidefs_posix_vfs_pagecache_fence_still_current(struct inode *inode,
							   loff_t pos,
							   size_t len,
							   u64 snapshot);
static int tidefs_posix_vfs_drop_fenced_pagecache_range(struct inode *inode,
							loff_t pos,
							size_t len,
							const char *reason);

static void tidefs_posix_vfs_pagecache_fences_init(
	struct tidefs_posix_vfs_mount *ctx)
{
	if (!ctx)
		return;

	spin_lock_init(&ctx->pagecache_fence_lock);
	ctx->pagecache_fence_generation = 1;
	ctx->pagecache_fence_overflow_generation = 0;
	ctx->pagecache_fence_cursor = 0;
}

static void tidefs_posix_vfs_mount_free(struct tidefs_posix_vfs_mount *ctx)
{
	if (!ctx)
		return;

	kfree(ctx->cluster_node_id);
	kfree(ctx->transport_carrier);
	kfree(ctx);
}

static int tidefs_posix_vfs_mount_copy_cluster_options(
	struct tidefs_posix_vfs_mount *ctx,
	const struct tidefs_posix_vfs_fs_context *tidefs_fc)
{
	if (!ctx || !tidefs_fc)
		return 0;

	if (tidefs_fc->cluster_node_id) {
		ctx->cluster_node_id = kstrdup(tidefs_fc->cluster_node_id, GFP_KERNEL);
		if (!ctx->cluster_node_id)
			return -ENOMEM;
	}

	if (tidefs_fc->transport_carrier) {
		ctx->transport_carrier = kstrdup(tidefs_fc->transport_carrier, GFP_KERNEL);
		if (!ctx->transport_carrier) {
			kfree(ctx->cluster_node_id);
			ctx->cluster_node_id = NULL;
			return -ENOMEM;
		}
	}

	return 0;
}

/* Create an engine-backed mount context from the Rust bridge mount output. */
__attribute__((unused))
static struct tidefs_posix_vfs_mount *tidefs_posix_vfs_mount_new_engine(
	struct super_block *sb,
	const struct tidefs_posix_vfs_label_parse_out *lo,
	const struct tidefs_posix_vfs_mount_out *mo)
{
	struct tidefs_posix_vfs_mount *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	tidefs_posix_vfs_pagecache_fences_init(ctx);
	ctx->bootstrap_only = false;
	ctx->engine_backed = true;
	ctx->root_ino = mo->root_ino;
	ctx->fsid = ((u64)mo->fsid_hi << 32) | (mo->fsid_lo & 0xFFFFFFFFULL);
	ctx->committed_txg = mo->committed_txg;
	ctx->block_size = mo->block_size;
	ctx->total_blocks = mo->total_blocks;
	ctx->free_blocks = mo->free_blocks;
	ctx->avail_blocks = mo->avail_blocks;
	ctx->total_inodes = mo->total_inodes;
	ctx->free_inodes = mo->free_inodes;
	ctx->name_max = mo->name_max;
	ctx->pool.imported = true;
	refcount_set(&ctx->pool.refs, 1);
	ctx->pool.sb = sb;
	ctx->pool.bdev = sb->s_bdev;
	ctx->pool.root_ino = ctx->root_ino;
	memcpy(ctx->pool.pool_uuid, mo->pool_uuid, sizeof(ctx->pool.pool_uuid));
	ctx->pool.fsid = ctx->fsid;
	ctx->pool.committed_txg = ctx->committed_txg;
	ctx->pool.topology_generation = lo->topology_generation;
	ctx->pool.device_capacity_bytes = lo->device_capacity_bytes;
	ctx->pool.superblock_offset = lo->superblock_offset;
	ctx->pool.superblock_size = lo->superblock_size;
	ctx->pool.block_size = ctx->block_size;
	ctx->pool.total_blocks = ctx->total_blocks;
	ctx->pool.free_blocks = ctx->free_blocks;
	ctx->pool.avail_blocks = ctx->avail_blocks;
	ctx->pool.total_inodes = ctx->total_inodes;
	ctx->pool.free_inodes = ctx->free_inodes;
	ctx->pool.name_max = ctx->name_max;
	ctx->pool.next_ino = mo->root_ino + 1;
	ctx->pool.next_generation = 1;
	ctx->pool.nr_inodes = 0;
	return ctx;
}

/* Create an engine-backed mount context from the Rust replay mount output.
 * Replaces tidefs_kernel_pool_load_state with authoritative replay results.
 * The replay output carries the committed-root anchor, capacity, and
 * intent-replay outcome; the C shim stores these as the mounted namespace. */
static struct tidefs_posix_vfs_mount *tidefs_posix_vfs_mount_new_engine_replay(
	struct super_block *sb,
	const struct tidefs_posix_vfs_label_parse_out *lo,
	const struct tidefs_posix_vfs_replay_mount_out *mo)
{
	struct tidefs_posix_vfs_mount *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	tidefs_posix_vfs_pagecache_fences_init(ctx);
	ctx->bootstrap_only = false;
	ctx->engine_backed = true;
	ctx->root_ino = mo->root_ino;
	ctx->fsid = ((u64)mo->fsid_hi << 32) | (mo->fsid_lo & 0xFFFFFFFFULL);
	ctx->committed_txg = mo->committed_txg;
	ctx->block_size = mo->block_size;
	ctx->total_blocks = mo->total_blocks;
	ctx->free_blocks = mo->free_blocks;
	ctx->avail_blocks = mo->avail_blocks;
	ctx->total_inodes = mo->total_inodes;
	ctx->free_inodes = mo->free_inodes;
	ctx->name_max = mo->name_max;
	ctx->pool.imported = true;
	refcount_set(&ctx->pool.refs, 1);
	ctx->pool.sb = sb;
	ctx->pool.bdev = sb->s_bdev;
	ctx->pool.root_ino = ctx->root_ino;
	memcpy(ctx->pool.pool_uuid, mo->pool_uuid, sizeof(ctx->pool.pool_uuid));
	ctx->pool.fsid = ctx->fsid;
	ctx->pool.committed_txg = ctx->committed_txg;
	ctx->pool.topology_generation = lo->topology_generation;
	ctx->pool.device_capacity_bytes = lo->device_capacity_bytes;
	ctx->pool.superblock_offset = lo->superblock_offset;
	ctx->pool.superblock_size = lo->superblock_size;
	ctx->pool.block_size = ctx->block_size;
	ctx->pool.total_blocks = ctx->total_blocks;
	ctx->pool.free_blocks = ctx->free_blocks;
	ctx->pool.avail_blocks = ctx->avail_blocks;
	ctx->pool.total_inodes = ctx->total_inodes;
	ctx->pool.free_inodes = ctx->free_inodes;
	ctx->pool.name_max = ctx->name_max;
	ctx->pool.inode_table_root = mo->inode_table_root;
	ctx->pool.extent_map_root = mo->extent_map_root;
	ctx->pool.intent_log_head = mo->intent_log_head;
	ctx->pool.intent_log_tail = mo->intent_log_tail;
	ctx->pool.replay_replayed = mo->replay_replayed;
	ctx->pool.replay_skipped = mo->replay_skipped;
	ctx->pool.replay_errored = mo->replay_errored;
	ctx->pool.clean_export = mo->clean_export != 0;
	ctx->pool.next_ino = mo->root_ino + 1;
	ctx->pool.next_generation = 1;
	ctx->pool.nr_inodes = 0;
	return ctx;
}

static int tidefs_posix_vfs_activate_engine(struct tidefs_posix_vfs_mount *ctx);

static struct tidefs_posix_vfs_kernel_pool_core *
tidefs_posix_vfs_pool_core_from_sb(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx;
	int ret;

	if (!sb)
		return ERR_PTR(-ENODEV);

	ctx = sb->s_fs_info;
	if (!ctx || !ctx->engine_backed || !ctx->pool.imported)
		return ERR_PTR(-ENODEV);

	ret = tidefs_posix_vfs_activate_engine(ctx);
	if (ret < 0)
		return ERR_PTR(ret);

	return &ctx->pool;
}

static u64 tidefs_kernel_pool_state_base(
	const struct tidefs_posix_vfs_kernel_pool_core *pool)
{
	return pool->superblock_offset + pool->superblock_size;
}

static int tidefs_kernel_pool_rw(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	u64 offset,
	void *buf,
	size_t len,
	bool write);

static int tidefs_kernel_pool_publish_committed_root(
	struct tidefs_posix_vfs_kernel_pool_core *pool)
{
	unsigned long written = 0;
	unsigned long vrbt_written = 0;
	unsigned long vcrp_written = 0;
	size_t ledger_len;
	u64 pointer_offset;
	u64 root_offset;
	u64 pointer_sector;
	u64 root_sector;
	u8 *ledger;
	u8 *vrbt = NULL;
	u8 *vcrp = NULL;
	bool publish_vrbt = true;
	int ret;

	if (!pool || !pool->imported)
		return -ENODEV;
	if (pool->superblock_size < TIDEFS_KERNEL_POOL_COMMITTED_LEDGER_MIN_SIZE)
		return -EINVAL;
	if (!pool->block_size)
		return -EINVAL;
	if (pool->superblock_offset % pool->block_size)
		return -EINVAL;
	if (pool->superblock_size < (4ULL * pool->block_size)) {
		pr_warn("tidefs_posix_vfs: committed-root VRBT/VCRP publish skipped: superblock region too small sb_sz=%llu block=%u\n",
			pool->superblock_size, pool->block_size);
		publish_vrbt = false;
	}
	if (pool->block_size < TIDEFS_KERNEL_POOL_VCRP_RECORD_SIZE ||
	    pool->block_size < TIDEFS_KERNEL_POOL_VRBT_WIRE_SIZE) {
		pr_warn("tidefs_posix_vfs: committed-root VRBT/VCRP publish skipped: block size too small block=%u vcrp=%u vrbt=%u\n",
			pool->block_size, TIDEFS_KERNEL_POOL_VCRP_RECORD_SIZE,
			TIDEFS_KERNEL_POOL_VRBT_WIRE_SIZE);
		publish_vrbt = false;
	}

	ledger_len = min_t(u64, pool->superblock_size, pool->block_size);
	if (ledger_len < TIDEFS_KERNEL_POOL_COMMITTED_LEDGER_MIN_SIZE)
		return -EINVAL;

	ledger = kzalloc(ledger_len, GFP_KERNEL);
	if (!ledger)
		return -ENOMEM;

	ret = tidefs_posix_vfs_engine_encode_committed_root_ledger(
		pool->root_ino,
		pool->pool_uuid,
		sizeof(pool->pool_uuid),
		pool->committed_txg,
		ledger,
		ledger_len,
		&written);
	if (ret < 0)
		goto out_free;
	if (written == 0 || written > ledger_len) {
		ret = -EINVAL;
		goto out_free;
	}

	ret = tidefs_kernel_pool_rw(pool, pool->superblock_offset, ledger,
				    ledger_len, true);
	if (ret)
		goto out_free;

	if (!publish_vrbt) {
		pr_info("tidefs_posix_vfs: published committed-root ledger txg=%llu root=%llu bytes=%lu (VRBT/VCRP skipped)\n",
			pool->committed_txg, pool->root_ino, written);
		goto out_free;
	}

	pointer_offset = pool->superblock_offset + pool->block_size;
	root_offset = pool->superblock_offset + (3ULL * pool->block_size);
	pointer_sector = pointer_offset / pool->block_size;
	root_sector = root_offset / pool->block_size;

	vrbt = kzalloc(pool->block_size, GFP_KERNEL);
	if (!vrbt) {
		ret = -ENOMEM;
		goto out_free;
	}
	vcrp = kzalloc(pool->block_size, GFP_KERNEL);
	if (!vcrp) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = tidefs_posix_vfs_engine_encode_committed_root_vrbt(
		pool->committed_txg,
		pool->root_ino,
		tidefs_kernel_pool_state_base(pool),
		tidefs_kernel_pool_state_base(pool),
		pool->intent_log_tail,
		pool->committed_txg,
		root_sector,
		vrbt,
		pool->block_size,
		&vrbt_written,
		vcrp,
		pool->block_size,
		&vcrp_written);
	if (ret < 0)
		goto out_free;
	if (vrbt_written != TIDEFS_KERNEL_POOL_VRBT_WIRE_SIZE ||
	    vcrp_written != TIDEFS_KERNEL_POOL_VCRP_RECORD_SIZE) {
		ret = -EINVAL;
		goto out_free;
	}

	ret = tidefs_kernel_pool_rw(pool, pointer_offset, vcrp,
				    pool->block_size, true);
	if (ret)
		goto out_free;
	ret = tidefs_kernel_pool_rw(pool, pointer_offset + pool->block_size,
				    vcrp, pool->block_size, true);
	if (ret)
		goto out_free;
	ret = tidefs_kernel_pool_rw(pool, root_offset, vrbt,
				    pool->block_size, true);
	if (ret)
		goto out_free;

	pr_info("tidefs_posix_vfs: published committed roots txg=%llu root=%llu vcrl_bytes=%lu vcrp_sector=%llu vrbt_sector=%llu\n",
		pool->committed_txg, pool->root_ino, written,
		pointer_sector, root_sector);

out_free:
	kfree(vcrp);
	kfree(vrbt);
	kfree(ledger);
	return ret;
}

static int tidefs_kernel_pool_rw(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	u64 offset,
	void *buf,
	size_t len,
	bool write)
{
	u8 *cursor = buf;

	unsigned int io_block_size;
	if (!pool || !pool->sb || !pool->block_size)
		return -ENODEV;

	io_block_size = pool->sb->s_blocksize;
	while (len > 0) {
		sector_t block = offset / io_block_size;
		unsigned int block_off = offset % io_block_size;
		size_t chunk = min_t(size_t, len, (size_t)io_block_size - block_off);
		struct buffer_head *bh;

		bh = sb_bread(pool->sb, block);
		if (!bh)
			return -EIO;

		if (write) {
			memcpy(bh->b_data + block_off, cursor, chunk);
			set_buffer_uptodate(bh);
			mark_buffer_dirty(bh);
			sync_dirty_buffer(bh);
			if (buffer_write_io_error(bh)) {
				brelse(bh);
				return -EIO;
			}
		} else {
			memcpy(cursor, bh->b_data + block_off, chunk);
		}

		brelse(bh);
		cursor += chunk;
		offset += chunk;
		len -= chunk;
	}

	return 0;
}


/* C-side write callback for the Rust engine committed-root persistence.
 * Signature matches CommittedRootIoCtx.write_sectors_fn:
 *   int write_fn(u64 start_sector, const u8 *data, u32 len)
 * Returns 0 on success, -errno on failure.
 * Placed after tidefs_kernel_pool_rw so it is visible. */
static struct tidefs_posix_vfs_kernel_pool_core *g_engine_pool;
static struct tidefs_posix_vfs_mount *g_active_engine_ctx;
static DEFINE_MUTEX(tidefs_posix_vfs_engine_switch_lock);

/* Forward declaration for module-parameter emergency-shutdown trigger. */
static struct file_system_type tidefs_posix_vfs_type;

static void tidefs_emergency_shutdown_cb(struct super_block *sb, void *arg)
{
	if (sb && !sb_rdonly(sb)) {
		pr_info("tidefs_posix_vfs: emergency_shutdown: triggering fserror_report_shutdown on sb=%s\n",
			sb->s_id);
		fserror_report_shutdown(sb, GFP_KERNEL);
	}
}

static int tidefs_emergency_shutdown_set(const char *val, const struct kernel_param *kp)
{
	int v;
	if (kstrtoint(val, 0, &v) != 0 || v != 1)
		return -EINVAL;

	pr_warn("tidefs_posix_vfs: emergency_shutdown trigger: reporting shutdown on all mounted TideFS superblocks\n");
	iterate_supers_type(&tidefs_posix_vfs_type, tidefs_emergency_shutdown_cb, NULL);
	return 0;
}

static const struct kernel_param_ops tidefs_emergency_shutdown_ops = {
	.set = tidefs_emergency_shutdown_set,
	.get = NULL,
};
module_param_cb(emergency_shutdown, &tidefs_emergency_shutdown_ops, NULL, 0200);
MODULE_PARM_DESC(emergency_shutdown, "Write 1 to trigger emergency shutdown on all mounted TideFS superblocks");

static int tidefs_posix_vfs_engine_write_sectors(
	unsigned long long start_sector,
	const unsigned char *data,
	unsigned int len)
{
	if (!g_engine_pool)
		return -19; /* ENODEV */
	/* tidefs_kernel_pool_rw expects byte offset, not sector */
	unsigned long long offset = start_sector * g_engine_pool->block_size;
	return tidefs_kernel_pool_rw(g_engine_pool, offset,
				     (void *)data, len, true);
}
/* C-side read callback for the Rust engine replay read path.
 * Signature matches CommittedRootIoCtx.read_sectors_fn:
 *   int read_fn(u64 start_sector, u8 *buf, u32 len)
 * Returns 0 on success, -errno on failure.
 * Placed after tidefs_posix_vfs_engine_write_sectors. */
static int tidefs_posix_vfs_engine_read_sectors(
	unsigned long long start_sector,
	unsigned char *buf,
	unsigned int len)
{
	if (!g_engine_pool)
		return -19; /* ENODEV */
	/* tidefs_kernel_pool_rw expects byte offset, not sector */
	unsigned long long offset = start_sector * g_engine_pool->block_size;
	return tidefs_kernel_pool_rw(g_engine_pool, offset,
				     buf, len, false /* write=0 read */);
}

static int tidefs_posix_vfs_engine_flush(void)
{
	if (!g_engine_pool || !g_engine_pool->bdev)
		return -ENODEV;

	return sync_blockdev(g_engine_pool->bdev);
}

static int tidefs_posix_vfs_engine_teardown_pool_authority(void)
{
	if (!g_engine_pool || !g_engine_pool->bdev)
		return -ENODEV;

	/*
	 * The Linux VFS owns the block-device lifetime for get_tree_bdev().
	 * Rust owns the mounted engine state. This callback makes teardown
	 * authority explicit without dropping the bdev behind the VFS.
	 */
	return 0;
}

static int tidefs_posix_vfs_activate_engine(struct tidefs_posix_vfs_mount *ctx)
{
	int (*write_fn)(unsigned long long, const unsigned char *, unsigned int) = NULL;
	int (*read_fn)(unsigned long long, unsigned char *, unsigned int) = NULL;
	int (*flush_fn)(void) = NULL;
	int (*teardown_fn)(void) = NULL;
	unsigned int major = 0;
	unsigned int minor = 0;
	int ret;

	if (!ctx || !ctx->engine_backed || !ctx->pool.imported)
		return -ENODEV;
	if (ctx->root_ino == 0 ||
	    ctx->pool.inode_table_root == 0 ||
	    ctx->pool.extent_map_root == 0) {
		pr_err("tidefs_posix_vfs: engine activation refused missing committed-root import root=%llu inode_root=%llu extent_root=%llu\n",
		       ctx->root_ino,
		       ctx->pool.inode_table_root,
		       ctx->pool.extent_map_root);
		return -EINVAL;
	}

	mutex_lock(&tidefs_posix_vfs_engine_switch_lock);
	if (g_active_engine_ctx == ctx && g_engine_pool == &ctx->pool) {
		ctx->engine_activated = true;
		mutex_unlock(&tidefs_posix_vfs_engine_switch_lock);
		return 0;
	}

	if (g_active_engine_ctx && g_active_engine_ctx != ctx) {
		ret = tidefs_posix_vfs_engine_sync_fs(1);
		if (ret < 0)
			pr_warn("tidefs_posix_vfs: active engine switch sync returned %d\n",
				ret);
		ret = tidefs_posix_vfs_engine_teardown_mounted();
		if (ret < 0)
			pr_warn("tidefs_posix_vfs: active engine switch teardown returned %d\n",
				ret);
		g_active_engine_ctx = NULL;
		g_engine_pool = NULL;
	}

	g_engine_pool = &ctx->pool;
	if (ctx->pool.bdev) {
		write_fn = tidefs_posix_vfs_engine_write_sectors;
		read_fn = tidefs_posix_vfs_engine_read_sectors;
		flush_fn = tidefs_posix_vfs_engine_flush;
		teardown_fn = tidefs_posix_vfs_engine_teardown_pool_authority;
		major = MAJOR(ctx->pool.bdev->bd_dev);
		minor = MINOR(ctx->pool.bdev->bd_dev);
	}
	ret = tidefs_posix_vfs_engine_init_mounted(
		write_fn,
		read_fn,
		flush_fn,
		teardown_fn,
		ctx->block_size,
		ctx->pool.superblock_offset,
		ctx->pool.superblock_size,
		ctx->pool.device_capacity_bytes,
		ctx->committed_txg,
		ctx->root_ino,
		ctx->pool.pool_uuid,
		major,
		minor,
		ctx->pool.inode_table_root,
		ctx->pool.extent_map_root,
		ctx->pool.intent_log_head,
		ctx->pool.intent_log_tail,
		ctx->pool.replay_replayed,
		ctx->pool.replay_skipped,
		ctx->pool.replay_errored,
		ctx->pool.clean_export ? 1 : 0);
	if (ret == 0) {
		tidefs_posix_vfs_engine_record_cluster_config(
			ctx->cluster_node_id,
			ctx->transport_carrier);
		ctx->engine_activated = true;
		g_active_engine_ctx = ctx;
	} else if (g_active_engine_ctx) {
		g_engine_pool = &g_active_engine_ctx->pool;
	} else {
		g_engine_pool = NULL;
	}

	mutex_unlock(&tidefs_posix_vfs_engine_switch_lock);
	return ret;
}

static void tidefs_posix_vfs_abort_active_engine(
	struct tidefs_posix_vfs_mount *ctx)
{
	int ret;

	if (!ctx || !ctx->engine_activated)
		return;

	mutex_lock(&tidefs_posix_vfs_engine_switch_lock);
	if (g_active_engine_ctx == ctx) {
		ret = tidefs_posix_vfs_engine_teardown_mounted();
		if (ret < 0)
			pr_warn("tidefs_posix_vfs: mount-error engine teardown returned %d\n",
				ret);
		g_active_engine_ctx = NULL;
		g_engine_pool = NULL;
	}
	ctx->engine_activated = false;
	mutex_unlock(&tidefs_posix_vfs_engine_switch_lock);
}

static int tidefs_kernel_pool_persist_state(
	struct tidefs_posix_vfs_kernel_pool_core *pool)
{
	struct tidefs_kernel_pool_state_header *hdr;
	struct tidefs_kernel_pool_state_record *rec;
	u8 *block;
	u64 base;
	size_t state_len;
	u32 max_records;
	u32 persisted_inodes;
	u32 i;
	int ret;

	if (!pool || !pool->imported)
		return -ENODEV;
	if (pool->block_size < 4096)
		return -EINVAL;
	if (pool->block_size <= sizeof(*hdr))
		return -EINVAL;

	state_len = TIDEFS_KERNEL_POOL_STATE_RECORD_REGION_BYTES;
	if (state_len <= sizeof(*hdr))
		return -EINVAL;

	max_records = (u32)((state_len - sizeof(*hdr)) / sizeof(*rec));
	persisted_inodes = min_t(u32, (u32)pool->nr_inodes, max_records);

	block = kzalloc(state_len, GFP_KERNEL);
	if (!block)
		return -ENOMEM;

	hdr = (struct tidefs_kernel_pool_state_header *)block;
	hdr->magic = cpu_to_le32(TIDEFS_KERNEL_POOL_STATE_MAGIC);
	hdr->version = cpu_to_le32(TIDEFS_KERNEL_POOL_STATE_VERSION);
	hdr->nr_inodes = cpu_to_le32(persisted_inodes);
	hdr->record_size = cpu_to_le32(sizeof(*rec));
	hdr->next_ino = cpu_to_le64(pool->next_ino);
	hdr->committed_txg = cpu_to_le64(pool->committed_txg);

	rec = (struct tidefs_kernel_pool_state_record *)(block + sizeof(*hdr));
	for (i = 0; i < persisted_inodes; i++) {
		rec[i].ino = cpu_to_le64(pool->inode_table[i].ino);
		rec[i].parent_ino = cpu_to_le64(pool->inode_table[i].parent_ino);
		rec[i].data_len = cpu_to_le64(pool->inode_table[i].data_len);
		rec[i].mode = cpu_to_le32(pool->inode_table[i].mode);
		rec[i].name_len = cpu_to_le16(pool->inode_table[i].name_len);
		rec[i].flags = cpu_to_le16(S_ISDIR(pool->inode_table[i].mode) ? 1 : 0);
		memcpy(rec[i].name, pool->inode_table[i].name,
		       min_t(size_t, pool->inode_table[i].name_len,
			     TIDEFS_KERNEL_POOL_STATE_RECORD_NAME));
	}

	base = tidefs_kernel_pool_state_base(pool);
	ret = tidefs_kernel_pool_rw(pool,
				    base + TIDEFS_KERNEL_POOL_STATE_BLOCK_OFFSET,
				    block, state_len, true);
	kfree(block);
	if (ret)
		return ret;

	for (i = 0; i < persisted_inodes; i++) {
		if (!S_ISREG(pool->inode_table[i].mode))
			continue;
		ret = tidefs_kernel_pool_rw(
			pool,
			base + TIDEFS_KERNEL_POOL_STATE_DATA_OFFSET +
				((u64)i * TIDEFS_KERNEL_POOL_FILE_DATA_SIZE),
			pool->inode_table[i].data,
			TIDEFS_KERNEL_POOL_FILE_DATA_SIZE,
			true);
		if (ret)
			return ret;
	}

	ret = tidefs_kernel_pool_publish_committed_root(pool);
	if (ret)
		return ret;

	pr_info("tidefs_posix_vfs: persisted kernel pool state namespace txg=%llu entries=%u live_entries=%d\n",
		pool->committed_txg, persisted_inodes, pool->nr_inodes);
	return 0;
}

__attribute__((unused))
/* Sync C pool inode table to Rust KernelEngine in-memory namespace. */
static void tidefs_posix_vfs_sync_pool_to_engine(
	struct tidefs_posix_vfs_kernel_pool_core *pool)
{
	unsigned int nr = (unsigned int)pool->nr_inodes;
	unsigned long long *inos;
	unsigned long long *parent_inos;
	unsigned int *modes;
	const unsigned char **names;
	unsigned int *name_lens;
	unsigned long long *data_lens;
	unsigned int i;

	if (nr == 0)
		return;
	if (nr > TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE)
		nr = TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE;

	inos = kcalloc(nr, sizeof(*inos), GFP_KERNEL);
	parent_inos = kcalloc(nr, sizeof(*parent_inos), GFP_KERNEL);
	modes = kcalloc(nr, sizeof(*modes), GFP_KERNEL);
	names = kcalloc(nr, sizeof(*names), GFP_KERNEL);
	name_lens = kcalloc(nr, sizeof(*name_lens), GFP_KERNEL);
	data_lens = kcalloc(nr, sizeof(*data_lens), GFP_KERNEL);
	if (!inos || !parent_inos || !modes || !names || !name_lens || !data_lens)
		goto out_free;

	for (i = 0; i < nr; i++) {
		inos[i] = pool->inode_table[i].ino;
		parent_inos[i] = pool->inode_table[i].parent_ino;
		modes[i] = (unsigned int)pool->inode_table[i].mode;
		names[i] = pool->inode_table[i].name;
		name_lens[i] = (unsigned int)pool->inode_table[i].name_len;
		data_lens[i] = pool->inode_table[i].data_len;
	}
	tidefs_posix_vfs_engine_sync_namespace(
		nr, inos, parent_inos, modes, names, name_lens, data_lens);

out_free:
	kfree(data_lens);
	kfree(name_lens);
	kfree(names);
	kfree(modes);
	kfree(parent_inos);
	kfree(inos);
}

__attribute__((unused))
static int tidefs_kernel_pool_load_state(
	struct tidefs_posix_vfs_kernel_pool_core *pool)
{
	struct tidefs_kernel_pool_state_header *hdr;
	struct tidefs_kernel_pool_state_record *rec;
	u8 *block;
	u32 nr_inodes;
	size_t state_len;
	u32 max_records;
	u64 base;
	int i;
	int ret;

	if (!pool || !pool->imported)
		return -ENODEV;
	if (pool->block_size < 4096)
		return -EINVAL;
	if (pool->block_size <= sizeof(*hdr))
		return -EINVAL;

	state_len = TIDEFS_KERNEL_POOL_STATE_RECORD_REGION_BYTES;
	if (state_len <= sizeof(*hdr))
		return -EINVAL;

	block = kzalloc(state_len, GFP_KERNEL);
	if (!block)
		return -ENOMEM;

	base = tidefs_kernel_pool_state_base(pool);
	ret = tidefs_kernel_pool_rw(pool,
				    base + TIDEFS_KERNEL_POOL_STATE_BLOCK_OFFSET,
				    block, state_len, false);
	if (ret) {
		kfree(block);
		return ret;
	}

	hdr = (struct tidefs_kernel_pool_state_header *)block;
	if (le32_to_cpu(hdr->magic) != TIDEFS_KERNEL_POOL_STATE_MAGIC) {
		kfree(block);
		pr_info("tidefs_posix_vfs: no persisted kernel namespace state; starting empty table\n");
		return 0;
	}
	if (le32_to_cpu(hdr->version) != TIDEFS_KERNEL_POOL_STATE_VERSION ||
	    le32_to_cpu(hdr->record_size) != sizeof(*rec)) {
		kfree(block);
		return -EINVAL;
	}

	nr_inodes = le32_to_cpu(hdr->nr_inodes);
	max_records = (u32)((state_len - sizeof(*hdr)) / sizeof(*rec));
	if (nr_inodes > TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE ||
	    nr_inodes > max_records) {
		kfree(block);
		return -EINVAL;
	}

	pool->nr_inodes = nr_inodes;
	pool->next_ino = max_t(u64, pool->next_ino, le64_to_cpu(hdr->next_ino));
	pool->committed_txg = max_t(u64, pool->committed_txg,
				    le64_to_cpu(hdr->committed_txg));

	rec = (struct tidefs_kernel_pool_state_record *)(block + sizeof(*hdr));
	for (i = 0; i < pool->nr_inodes; i++) {
		u64 data_len = le64_to_cpu(rec[i].data_len);
		u16 name_len = le16_to_cpu(rec[i].name_len);

		if (name_len > TIDEFS_KERNEL_POOL_NAME_MAX ||
		    data_len > TIDEFS_KERNEL_POOL_FILE_DATA_SIZE) {
			kfree(block);
			return -EINVAL;
		}

		pool->inode_table[i].ino = le64_to_cpu(rec[i].ino);
		pool->inode_table[i].parent_ino = le64_to_cpu(rec[i].parent_ino);
		pool->inode_table[i].mode = le32_to_cpu(rec[i].mode);
		pool->inode_table[i].data_len = data_len;
		pool->inode_table[i].name_len = name_len;
		memcpy(pool->inode_table[i].name, rec[i].name, name_len);
		pool->inode_table[i].name[name_len] = '\0';

		if (S_ISREG(pool->inode_table[i].mode)) {
			ret = tidefs_kernel_pool_rw(
				pool,
				base + TIDEFS_KERNEL_POOL_STATE_DATA_OFFSET +
					((u64)i * TIDEFS_KERNEL_POOL_FILE_DATA_SIZE),
				pool->inode_table[i].data,
				TIDEFS_KERNEL_POOL_FILE_DATA_SIZE,
				false);
			if (ret) {
				kfree(block);
				return ret;
			}
		}
	}

	kfree(block);
	pr_info("tidefs_posix_vfs: loaded kernel pool namespace state txg=%llu entries=%d\n",
		pool->committed_txg, pool->nr_inodes);
	return 0;
}

static void tidefs_posix_vfs_pool_core_teardown(
	struct tidefs_posix_vfs_mount *ctx)
{
	if (!ctx || !ctx->pool.imported)
		return;

	ctx->pool.imported = false;
	ctx->pool.sb = NULL;
	ctx->pool.bdev = NULL;
}

static int tidefs_posix_vfs_require_engine_inode(struct inode *inode,
						 const char *op)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;

	if (!inode || !inode->i_sb)
		return -ENODEV;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	pr_debug("tidefs_posix_vfs: %s reached mounted KernelPoolCore txg=%llu root=%llu; operation backend not wired yet\n",
		 op, pool->committed_txg, pool->root_ino);
	return -ENOSYS;
}

/* Allocate a new inode number from the pool inode table.
 * Returns 0 if the table is full. */
static int tidefs_kernel_pool_find_index_by_ino(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	u64 ino)
{
	int i;

	for (i = 0; i < pool->nr_inodes; i++) {
		if (pool->inode_table[i].ino == ino)
			return i;
	}
	return -ENOENT;
}

static int tidefs_kernel_pool_find_index(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	u64 parent_ino,
	const char *name,
	unsigned int name_len)
{
	int i;

	for (i = 0; i < pool->nr_inodes; i++) {
		if (pool->inode_table[i].parent_ino == parent_ino &&
		    pool->inode_table[i].name_len == name_len &&
		    memcmp(pool->inode_table[i].name, name, name_len) == 0)
			return i;
	}
	return -ENOENT;
}

static void tidefs_kernel_pool_set_entry_name(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	int idx,
	u64 parent_ino,
	const unsigned char *name,
	unsigned int name_len)
{
	unsigned int copy_len;

	if (!pool || idx < 0 || idx >= pool->nr_inodes)
		return;

	copy_len = min_t(unsigned int, name_len, TIDEFS_KERNEL_POOL_NAME_MAX);
	pool->inode_table[idx].parent_ino = parent_ino;
	memset(pool->inode_table[idx].name, 0,
	       TIDEFS_KERNEL_POOL_NAME_MAX + 1);
	if (name && copy_len > 0)
		memcpy(pool->inode_table[idx].name, name, copy_len);
	pool->inode_table[idx].name_len = copy_len;
}

static int tidefs_kernel_pool_mirror_engine_inode(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	u64 ino,
	u64 parent_ino,
	umode_t mode,
	u64 data_len,
	const unsigned char *name,
	unsigned int name_len)
{
	unsigned int copy_len = min_t(unsigned int, name_len,
				      TIDEFS_KERNEL_POOL_NAME_MAX);
	int idx;

	idx = tidefs_kernel_pool_find_index_by_ino(pool, ino);
	if (idx < 0) {
		if (pool->nr_inodes >= TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE)
			return -ENOSPC;
		idx = pool->nr_inodes++;
	}

	pool->inode_table[idx].ino = ino;
	pool->inode_table[idx].parent_ino = parent_ino;
	pool->inode_table[idx].mode = mode;
	pool->inode_table[idx].data_len = data_len;
	memset(pool->inode_table[idx].data, 0,
	       TIDEFS_KERNEL_POOL_FILE_DATA_SIZE);
	tidefs_kernel_pool_set_entry_name(pool, idx, parent_ino, name, copy_len);

	return idx;
}

static void tidefs_kernel_pool_remove_index(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	int idx)
{
	if (idx < 0 || idx >= pool->nr_inodes)
		return;
	if (idx < pool->nr_inodes - 1)
		memmove(&pool->inode_table[idx], &pool->inode_table[idx + 1],
			(pool->nr_inodes - idx - 1) * sizeof(pool->inode_table[0]));
	pool->nr_inodes--;
}

static u64 tidefs_kernel_pool_alloc_ino(struct tidefs_posix_vfs_kernel_pool_core *pool,
					u64 parent_ino,
					umode_t mode,
					const char *name,
					u8 name_len)
{
	if (pool->nr_inodes >= TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE)
		return 0;
	if (name_len > TIDEFS_KERNEL_POOL_NAME_MAX)
		return 0;

	u64 ino = pool->next_ino++;
	int idx = pool->nr_inodes++;
	pool->inode_table[idx].ino = ino;
	pool->inode_table[idx].parent_ino = parent_ino;
	pool->inode_table[idx].mode = mode;
	pool->inode_table[idx].data_len = 0;
	memset(pool->inode_table[idx].data, 0,
	       TIDEFS_KERNEL_POOL_FILE_DATA_SIZE);
	memcpy(pool->inode_table[idx].name, name, name_len);
	pool->inode_table[idx].name[name_len] = '\0';
	pool->inode_table[idx].name_len = name_len;

	return ino;
}

/* Look up an inode by name in the pool inode table.
 * Returns 0 if not found. */
static u64 tidefs_kernel_pool_find_ino(struct tidefs_posix_vfs_kernel_pool_core *pool,
				       u64 parent_ino,
				       const char *name,
				       unsigned int name_len)
{
	int idx = tidefs_kernel_pool_find_index(pool, parent_ino, name, name_len);

	return idx < 0 ? 0 : pool->inode_table[idx].ino;
}

__attribute__((unused)) static int tidefs_kernel_pool_ensure_file_entry(
	struct tidefs_posix_vfs_kernel_pool_core *pool,
	struct file *file)
{
	struct inode *inode = file_inode(file);
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *parent;
	struct inode *parent_inode;
	unsigned int name_len = 0;
	const unsigned char *name = NULL;
	int idx;

	idx = tidefs_kernel_pool_find_index_by_ino(pool, inode->i_ino);
	if (idx >= 0)
		return idx;

	if (pool->nr_inodes >= TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE)
		return -ENOSPC;

	if (dentry && dentry->d_name.name &&
	    dentry->d_name.len <= TIDEFS_KERNEL_POOL_NAME_MAX) {
		name = dentry->d_name.name;
		name_len = dentry->d_name.len;
	}

	parent = dentry ? dentry->d_parent : NULL;
	parent_inode = parent ? d_inode(parent) : NULL;

	idx = pool->nr_inodes++;
	pool->inode_table[idx].ino = inode->i_ino;
	pool->inode_table[idx].parent_ino = parent_inode ? parent_inode->i_ino : pool->root_ino;
	pool->inode_table[idx].mode = S_IFREG | (inode->i_mode & 07777);
	pool->inode_table[idx].data_len = 0;
	memset(pool->inode_table[idx].data, 0,
	       TIDEFS_KERNEL_POOL_FILE_DATA_SIZE);
	memset(pool->inode_table[idx].name, 0,
	       TIDEFS_KERNEL_POOL_NAME_MAX + 1);
	if (name && name_len > 0)
		memcpy(pool->inode_table[idx].name, name, name_len);
	pool->inode_table[idx].name_len = name_len;
	return idx;
}

/* Return the mode for an inode in the pool table, or 0. */
static umode_t tidefs_kernel_pool_ino_mode(struct tidefs_posix_vfs_kernel_pool_core *pool,
					   u64 ino)
{
	int idx = tidefs_kernel_pool_find_index_by_ino(pool, ino);

	return idx < 0 ? 0 : pool->inode_table[idx].mode;
}

static u64 tidefs_kernel_pool_ino_size(struct tidefs_posix_vfs_kernel_pool_core *pool,
				       u64 ino)
{
	int idx = tidefs_kernel_pool_find_index_by_ino(pool, ino);

	return idx < 0 ? 0 : pool->inode_table[idx].data_len;
}

/* Forward declaration for symlink inode operations (defined below). */
static const struct inode_operations tidefs_posix_vfs_symlink_inode_operations;

static s64 tidefs_posix_vfs_timespec64_to_ns(struct timespec64 ts)
{
	if (ts.tv_sec > S64_MAX / 1000000000LL)
		return S64_MAX;
	if (ts.tv_sec < S64_MIN / 1000000000LL)
		return S64_MIN;
	if (ts.tv_sec == S64_MAX / 1000000000LL &&
	    ts.tv_nsec > S64_MAX % 1000000000LL)
		return S64_MAX;
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void tidefs_posix_vfs_ns_to_sec_nsec(s64 ns, s64 *sec, u32 *nsec)
{
	s32 rem;

	*sec = div_s64_rem(ns, 1000000000, &rem);
	if (rem < 0) {
		(*sec)--;
		rem += 1000000000;
	}
	*nsec = (u32)rem;
}

static void tidefs_posix_vfs_set_inode_time_ns(struct inode *inode,
					       s64 atime_ns,
					       s64 mtime_ns,
					       s64 ctime_ns)
{
	s64 sec;
	u32 nsec;

	tidefs_posix_vfs_ns_to_sec_nsec(atime_ns, &sec, &nsec);
	inode_set_atime(inode, sec, nsec);

	tidefs_posix_vfs_ns_to_sec_nsec(mtime_ns, &sec, &nsec);
	inode_set_mtime(inode, sec, nsec);

	tidefs_posix_vfs_ns_to_sec_nsec(ctime_ns, &sec, &nsec);
	inode_set_ctime(inode, sec, nsec);
}

static int tidefs_posix_vfs_engine_persist_inode_times(struct inode *inode,
						       unsigned int valid)
{
	struct tidefs_posix_vfs_mount *ctx;
	unsigned int out_mode = 0;
	unsigned int out_uid = 0;
	unsigned int out_gid = 0;
	unsigned long long out_size = 0;
	unsigned long long out_blocks = 0;
	int ret;

	if (!inode || !inode->i_sb || !inode->i_sb->s_fs_info || valid == 0)
		return 0;
	ctx = inode->i_sb->s_fs_info;
	if (!ctx->engine_backed)
		return 0;
	ret = tidefs_posix_vfs_activate_engine(ctx);
	if (ret < 0)
		return ret;

	return tidefs_posix_vfs_engine_setattr(
		inode->i_ino, valid, 0, 0, 0, 0,
		(valid & TIDEFS_POSIX_VFS_FATTR_ATIME) ?
			tidefs_posix_vfs_timespec64_to_ns(inode_get_atime(inode)) : 0,
		(valid & TIDEFS_POSIX_VFS_FATTR_MTIME) ?
			tidefs_posix_vfs_timespec64_to_ns(inode_get_mtime(inode)) : 0,
		(valid & TIDEFS_POSIX_VFS_FATTR_CTIME) ?
			tidefs_posix_vfs_timespec64_to_ns(inode_get_ctime(inode)) : 0,
		&out_mode, &out_uid, &out_gid, &out_size, &out_blocks);
}

static void tidefs_posix_vfs_persist_inode_times_best_effort(struct inode *inode,
							     unsigned int valid)
{
	int ret = tidefs_posix_vfs_engine_persist_inode_times(inode, valid);

	if (ret < 0)
		pr_debug("tidefs_posix_vfs: persist inode times ino=%lu valid=0x%x ret=%d\n",
			 inode ? inode->i_ino : 0, valid, ret);
}

static void tidefs_posix_vfs_init_new_inode_times(struct inode *inode)
{
	simple_inode_init_ts(inode);
	tidefs_posix_vfs_persist_inode_times_best_effort(
		inode, TIDEFS_POSIX_VFS_FATTR_TIMES);
}

static void tidefs_posix_vfs_touch_dirent_parent(struct inode *dir)
{
	if (!dir)
		return;
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	mark_inode_dirty(dir);
	tidefs_posix_vfs_persist_inode_times_best_effort(
		dir, TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME);
}

static void tidefs_posix_vfs_touch_inode_ctime(struct inode *inode)
{
	if (!inode)
		return;
	inode_set_ctime_current(inode);
	mark_inode_dirty(inode);
	tidefs_posix_vfs_persist_inode_times_best_effort(
		inode, TIDEFS_POSIX_VFS_FATTR_CTIME);
}

static void tidefs_posix_vfs_apply_inode_ops(struct inode *inode, umode_t mode,
					     u64 size)
{
	if (S_ISDIR(mode)) {
		inode->i_op = &tidefs_posix_vfs_dir_inode_operations;
		inode->i_fop = &tidefs_posix_vfs_dir_file_operations;
		set_nlink(inode, 2);
	} else if (S_ISLNK(mode)) {
		inode->i_op = &tidefs_posix_vfs_symlink_inode_operations;
		set_nlink(inode, 1);
		i_size_write(inode, size);
	} else {
		inode->i_op = &tidefs_posix_vfs_file_inode_operations;
		inode->i_fop = &tidefs_posix_vfs_file_operations;
		inode->i_mapping->a_ops = &tidefs_posix_vfs_aops;
		set_nlink(inode, 1);
		i_size_write(inode, size);
	}
}

static void tidefs_posix_vfs_apply_engine_attr(
	struct inode *inode,
	const struct tidefs_posix_vfs_engine_attr_out *attr)
{
	if (!inode || !attr)
		return;

	inode->i_ino = attr->ino;
	inode->i_generation = attr->generation ? attr->generation : attr->ino;
	inode->i_mode = attr->mode;
	inode->i_uid = make_kuid(&init_user_ns, attr->uid);
	inode->i_gid = make_kgid(&init_user_ns, attr->gid);
	tidefs_posix_vfs_apply_inode_ops(inode, attr->mode, attr->size);
	set_nlink(inode, attr->nlink);
	i_size_write(inode, attr->size);
	inode->i_blocks = attr->blocks;
	tidefs_posix_vfs_set_inode_time_ns(
		inode, attr->atime_ns, attr->mtime_ns, attr->ctime_ns);
}

static struct inode *tidefs_posix_vfs_iget_engine_attr(
	struct super_block *sb,
	const struct tidefs_posix_vfs_engine_attr_out *attr)
{
	struct inode *inode;

	if (!attr || !attr->ino || !attr->generation)
		return ERR_PTR(-EIO);

	if (sb->s_root && d_inode(sb->s_root) &&
	    d_inode(sb->s_root)->i_ino == attr->ino) {
		inode = igrab(d_inode(sb->s_root));
		if (!inode)
			return ERR_PTR(-ESTALE);
	} else {
		inode = iget_locked(sb, attr->ino);
		if (!inode)
			return ERR_PTR(-ENOMEM);
		if (inode_state_read_once(inode) & I_NEW) {
			tidefs_posix_vfs_apply_engine_attr(inode, attr);
			unlock_new_inode(inode);
			return inode;
		}
	}

	if (inode->i_generation != (u32)attr->generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return inode;
}

static int tidefs_posix_vfs_require_live_dir(struct inode *dir)
{
	if (!dir)
		return -ENOENT;
	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;
	if (dir->i_nlink == 0)
		return -ENOENT;
	return 0;
}

static struct dentry *tidefs_posix_vfs_add_negative_dentry(struct dentry *dentry)
{
	d_add(dentry, NULL);
	return NULL;
}

static struct dentry *tidefs_posix_vfs_lookup(struct inode *dir,
				      struct dentry *dentry,
				      unsigned int flags)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct tidefs_posix_vfs_replay_lookup_out lo;
	struct inode *inode;
	u64 ino;
	u64 size = 0;
	u64 generation = 0;
	u32 nlink = 0;
	umode_t mode;

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return ERR_PTR(PTR_ERR(pool));

	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		struct tidefs_posix_vfs_engine_attr_out ea;
		int ret;

		if (mctx && mctx->engine_backed) {
			memset(&ea, 0, sizeof(ea));
			ret = tidefs_posix_vfs_engine_lookup(
				dir->i_ino, dentry->d_name.name,
				dentry->d_name.len, &ea);
			if (ret == -ENOENT)
				return tidefs_posix_vfs_add_negative_dentry(dentry);
			if (ret < 0)
				return ERR_PTR(ret);
			if (ea.ino == 0)
				return tidefs_posix_vfs_add_negative_dentry(dentry);

			inode = tidefs_posix_vfs_iget_engine_attr(dir->i_sb, &ea);
			if (IS_ERR(inode))
				return ERR_CAST(inode);
			return d_splice_alias(inode, dentry);
		}
	}

	/*
	 * Engine-backed replay path (#6260): attempt canonical directory
	 * lookup through KernelRootDirReader. Falls back to fixed table.
	 * The on-disk directory at state_base uses fixed-table format, so
	 * the replay bridge will return ino=0 (not-found) until real
	 * DirPage data is persisted by the write path (#6253/#6270).
	 */
	{
		u64 dir_page_offset = tidefs_kernel_pool_state_base(pool) +
				      TIDEFS_KERNEL_POOL_STATE_BLOCK_OFFSET;
		u8 *dir_page_block = NULL;
		int ret;

		if (pool->block_size >= 512 && pool->superblock_size > 0) {
			dir_page_block = kzalloc(pool->block_size, GFP_KERNEL);
			if (dir_page_block) {
				ret = tidefs_kernel_pool_rw(pool,
					dir_page_offset, dir_page_block,
					pool->block_size, false);
				if (ret == 0) {
					ret = tidefs_posix_vfs_engine_replay_lookup(
						dir_page_block, pool->block_size,
						pool->block_size,
						dentry->d_name.name,
						dentry->d_name.len,
						&lo);
					if (ret == 0 && lo.ino != 0) {
						/* Replay found the entry through KernelRootDirReader. */
						kfree(dir_page_block);
						ino = lo.ino;
						mode = lo.kind == 1 ? (S_IFDIR | 0755) :
						       lo.kind == 2 ? (S_IFLNK | 0777) :
						       (S_IFREG | 0644);
						goto replay_found;
					}
				}
				kfree(dir_page_block);
			}
		}
		/*
		 * Replay lookup did not find the entry — expected while the
		 * on-disk directory data is still in fixed-table format.
		 * Fall through to the fixed-table lookup.
		 */
		pr_debug("tidefs_posix_vfs: lookup name='%.*s' replay not-found (expected); falling back to fixed table\n",
			 dentry->d_name.len, dentry->d_name.name);
	}

	ino = tidefs_kernel_pool_find_ino(pool, dir->i_ino, dentry->d_name.name,
					 dentry->d_name.len);
	if (ino == 0) {
		pr_debug("tidefs_posix_vfs: lookup name='%.*s' not found in pool table root_ino=%llu txg=%llu\n",
			 dentry->d_name.len, dentry->d_name.name,
			 pool->root_ino, pool->committed_txg);
		return tidefs_posix_vfs_add_negative_dentry(dentry);
	}

	mode = tidefs_kernel_pool_ino_mode(pool, ino);
	size = tidefs_kernel_pool_ino_size(pool, ino);

	replay_found:

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = ino;
	inode->i_generation = generation ? generation : ino;
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	tidefs_posix_vfs_apply_inode_ops(inode, mode, size);
	if (nlink)
		set_nlink(inode, nlink);
	simple_inode_init_ts(inode);

	pr_debug("tidefs_posix_vfs: lookup name='%.*s' found ino=%llu mode=0%o txg=%llu\n",
		 dentry->d_name.len, dentry->d_name.name, ino, mode,
		 pool->committed_txg);
	return d_splice_alias(inode, dentry);
}

static int tidefs_posix_vfs_create(struct mnt_idmap *idmap,
				   struct inode *dir, struct dentry *dentry,
				   umode_t mode, bool excl)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct inode *inode;
	u64 ino;

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return -EROFS;
	}


	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);


	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			u64 out_ino;
			u32 out_mode;
			u64 out_generation = 0;
			int ret;
			int pool_idx;

			ret = tidefs_posix_vfs_require_live_dir(dir);
			if (ret < 0)
				return ret;

			ret = tidefs_posix_vfs_engine_create(
				dir->i_ino,
				dentry->d_name.name,
				dentry->d_name.len,
				mode, excl ? 1 : 0,
				&out_ino, &out_mode, &out_generation);
			if (ret < 0)
				return ret;
			if (!out_generation)
				return -EIO;

			/* Keep the legacy fixed table as a best-effort mirror only.
			 * Live lookup/getattr/readdir route through the mounted engine,
			 * so mirror exhaustion must not impose a 128-entry ENOSPC. */
			pool_idx = tidefs_kernel_pool_mirror_engine_inode(
				pool, out_ino, dir->i_ino, out_mode, 0,
				dentry->d_name.name, dentry->d_name.len);
			if (pool_idx == -ENOSPC)
				pr_debug("tidefs_posix_vfs: create skipped full C mirror for ino=%llu\n",
					 out_ino);

			inode = new_inode(dir->i_sb);
			if (!inode)
				return -ENOMEM;
			inode->i_ino = out_ino;
			inode->i_generation = out_generation;
			inode_init_owner(idmap, inode, dir, out_mode);
			tidefs_posix_vfs_apply_inode_ops(inode, out_mode, 0);
			tidefs_posix_vfs_init_new_inode_times(inode);
			tidefs_posix_vfs_touch_dirent_parent(dir);
			insert_inode_hash(inode);
			d_instantiate(dentry, inode);

			pr_debug("tidefs_posix_vfs: create (engine-backed) name='%.*s' ino=%llu\n",
				 (unsigned int)dentry->d_name.len, dentry->d_name.name, out_ino);
			return 0;
		}
	}
	(void)excl;

	/* Reject exclusive creation if the name already exists. */
	if (tidefs_kernel_pool_find_ino(pool, dir->i_ino, dentry->d_name.name,
						dentry->d_name.len))
		return -EEXIST;

	ino = tidefs_kernel_pool_alloc_ino(pool, dir->i_ino,
					  S_IFREG | (mode & 0777),
					  dentry->d_name.name, dentry->d_name.len);
	if (ino == 0)
		return -ENOSPC;  /* inode table full (#6192) */

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = ino;
	inode->i_generation = ino;
	inode_init_owner(idmap, inode, dir, S_IFREG | (mode & 0777));
	tidefs_posix_vfs_apply_inode_ops(inode, S_IFREG | (mode & 0777), 0);
	simple_inode_init_ts(inode);

	pool->committed_txg++;
	if (tidefs_kernel_pool_persist_state(pool) != 0) {
		tidefs_kernel_pool_remove_index(
			pool, tidefs_kernel_pool_find_index_by_ino(pool, ino));
		iput(inode);
		return -EIO;
	}

	d_instantiate(dentry, inode);

	pr_debug("tidefs_posix_vfs: create name='%.*s' ino=%llu txg=%llu\n",
		 (unsigned int)dentry->d_name.len, dentry->d_name.name, ino, pool->committed_txg);
	return 0;
}
/*
 * Engine-backed O_TMPFILE unnamed temporary file creation.
 *
 * Creates an unnamed regular file in the parent directory.  No dentry name
 * is needed — d_tmpfile() links the resulting inode into the open file.
 * Returns via finish_open_simple() so that finish_open()->dget(dentry)
 * prevents vfs_tmpfile's dput(child) from freeing the dentry before
 * may_open().  Matches the ext4/xfs/btrfs pattern.
 */
static int tidefs_posix_vfs_tmpfile(struct mnt_idmap *idmap,
				     struct inode *dir,
				     struct file *file, umode_t mode)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct tidefs_posix_vfs_mount *ctx;
	struct inode *inode;
	u64 out_ino;
	u32 out_mode;
	u64 out_generation = 0;
	int ret, pool_idx;

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	ctx = dir->i_sb->s_fs_info;
	if (!ctx || !ctx->engine_backed)
		return -EOPNOTSUPP;

	ret = tidefs_posix_vfs_engine_tmpfile(
		dir->i_ino, mode, file->f_flags,
		&out_ino, &out_mode, &out_generation);
	if (ret < 0)
		return ret;
	if (!out_generation)
		return -EIO;

	pool_idx = tidefs_kernel_pool_mirror_engine_inode(
		pool, out_ino, dir->i_ino, out_mode, 0, NULL, 0);
	if (pool_idx == -ENOSPC)
		pr_debug("tidefs_posix_vfs: tmpfile skipped full C mirror for ino=%llu\n",
			 out_ino);

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;
	inode->i_ino = out_ino;
	inode->i_generation = out_generation;
	inode_init_owner(idmap, inode, dir, out_mode);
	tidefs_posix_vfs_apply_inode_ops(inode, out_mode, 0);
	tidefs_posix_vfs_init_new_inode_times(inode);
	insert_inode_hash(inode);
	d_tmpfile(file, inode);

	/*
	 * finish_open_simple -> finish_open -> dget(dentry) holds an
	 * extra reference on the slash dentry so that vfs_tmpfile's
	 * dput(child) does not free it before may_open().
	 */
	return finish_open_simple(file, 0);
}

static struct dentry *tidefs_posix_vfs_mkdir(struct mnt_idmap *idmap,
				    struct inode *dir,
				    struct dentry *dentry,
				    umode_t mode)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct inode *inode;
	u64 ino;

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return ERR_PTR(-EROFS);
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return ERR_PTR(PTR_ERR(pool));


	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			u64 out_ino;
			u32 out_mode;
			u64 out_generation = 0;
			int ret;

			ret = tidefs_posix_vfs_require_live_dir(dir);
			if (ret < 0)
				return ERR_PTR(ret);

			ret = tidefs_posix_vfs_engine_mkdir(
				dir->i_ino,
				dentry->d_name.name,
				dentry->d_name.len,
				mode,
				&out_ino, &out_mode, &out_generation);
			if (ret < 0)
				return ERR_PTR(ret);
			if (!out_generation)
				return ERR_PTR(-EIO);

			/* Keep the C-level table as a best-effort bring-up mirror.
			 * The mounted engine is the live namespace authority. */
			{
				int pool_idx = tidefs_kernel_pool_mirror_engine_inode(
					pool, out_ino, dir->i_ino, out_mode, 0,
					dentry->d_name.name, dentry->d_name.len);
				if (pool_idx == -ENOSPC)
					pr_debug("tidefs_posix_vfs: mkdir skipped full C mirror for ino=%llu\n",
						 out_ino);
			}

			inode = new_inode(dir->i_sb);
			if (!inode)
				return ERR_PTR(-ENOMEM);
			inode->i_ino = out_ino;
			inode->i_generation = out_generation;
			inode_init_owner(idmap, inode, dir, out_mode);
			tidefs_posix_vfs_apply_inode_ops(inode, out_mode, 0);
			if (dir->i_nlink > 0)
				inc_nlink(dir);
			tidefs_posix_vfs_init_new_inode_times(inode);
			tidefs_posix_vfs_touch_dirent_parent(dir);
			insert_inode_hash(inode);

			pr_debug("tidefs_posix_vfs: mkdir (engine-backed) name='%.*s' ino=%llu\n",
				 (unsigned int)dentry->d_name.len, dentry->d_name.name, out_ino);
			d_instantiate(dentry, inode);
			return NULL;
		}
	}

	if (tidefs_kernel_pool_find_ino(pool, dir->i_ino, dentry->d_name.name,
					dentry->d_name.len))
		return ERR_PTR(-EEXIST);

	ino = tidefs_kernel_pool_alloc_ino(pool, dir->i_ino,
					  S_IFDIR | (mode & 0777),
					  dentry->d_name.name, dentry->d_name.len);
	if (ino == 0)
		return ERR_PTR(-ENOSPC);  /* inode table full (#6192) */

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = ino;
	inode->i_generation = ino;
	inode_init_owner(idmap, inode, dir, S_IFDIR | (mode & 0777));
	tidefs_posix_vfs_apply_inode_ops(inode, S_IFDIR | (mode & 0777), 0);
	inc_nlink(dir);
	simple_inode_init_ts(inode);

	pool->committed_txg++;
	if (tidefs_kernel_pool_persist_state(pool) != 0) {
		tidefs_kernel_pool_remove_index(
			pool, tidefs_kernel_pool_find_index_by_ino(pool, ino));
		iput(inode);
		return ERR_PTR(-EIO);
	}

	pr_debug("tidefs_posix_vfs: mkdir name='%.*s' ino=%llu txg=%llu\n",
		 (unsigned int)dentry->d_name.len, dentry->d_name.name, ino, pool->committed_txg);
	d_instantiate(dentry, inode);
	return NULL;
}
static int tidefs_posix_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct inode *inode = d_inode(dentry);
	int idx;
	int pool_idx;

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return -EROFS;
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);


	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			int ret;

			ret = tidefs_posix_vfs_require_live_dir(dir);
			if (ret < 0)
				return ret;

			ret = tidefs_posix_vfs_engine_unlink(
				dir->i_ino,
				dentry->d_name.name,
				dentry->d_name.len);
			if (ret < 0)
				return ret;

			/* Remove the entry from the C-level pool inode table
			 * so that the getattr/lookup fallback paths see the
			 * deletion. The legacy fixed-table path does this via
			 * tidefs_kernel_pool_remove_index; the engine-backed
			 * path was missing this synchronisation. */
			pool_idx = tidefs_kernel_pool_find_index(
				pool, dir->i_ino, dentry->d_name.name, dentry->d_name.len);
			if (pool_idx >= 0)
				tidefs_kernel_pool_remove_index(pool, pool_idx);
			if (inode) {
				tidefs_posix_vfs_touch_inode_ctime(inode);
				clear_nlink(inode);
			}
			tidefs_posix_vfs_touch_dirent_parent(dir);
			d_drop(dentry);
			pr_debug("tidefs_posix_vfs: unlink (engine-backed) name='%.*s'\n",
				 (unsigned int)dentry->d_name.len, dentry->d_name.name);
			return 0;
		}
	}

	idx = tidefs_kernel_pool_find_index(pool, dir->i_ino,
					    dentry->d_name.name,
					    dentry->d_name.len);
	if (idx < 0)
		return -ENOENT;
	if (S_ISDIR(pool->inode_table[idx].mode))
		return -EISDIR;

	tidefs_kernel_pool_remove_index(pool, idx);
	pool->committed_txg++;
	if (tidefs_kernel_pool_persist_state(pool) != 0)
		return -EIO;

	if (inode)
		clear_nlink(inode);
	d_drop(dentry);
	pr_debug("tidefs_posix_vfs: unlink name='%.*s' txg=%llu\n",
		 (unsigned int)dentry->d_name.len, dentry->d_name.name,
		 pool->committed_txg);
	return 0;
}

static int tidefs_posix_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct inode *inode = d_inode(dentry);
	int idx;
	int pool_idx;
	int i;

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return -EROFS;
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);


	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			int ret;

			ret = tidefs_posix_vfs_require_live_dir(dir);
			if (ret < 0)
				return ret;

			ret = tidefs_posix_vfs_engine_rmdir(
				dir->i_ino,
				dentry->d_name.name,
				dentry->d_name.len);
			if (ret < 0)
				return ret;

			/* Remove the entry from the C-level pool inode table
			 * so that the getattr/lookup fallback paths see the
			 * deletion. Keep the same synchronisation discipline
			 * as the unlink engine-backed path. */
			pool_idx = tidefs_kernel_pool_find_index(
				pool, dir->i_ino, dentry->d_name.name, dentry->d_name.len);
			if (pool_idx >= 0)
				tidefs_kernel_pool_remove_index(pool, pool_idx);
			if (inode) {
				tidefs_posix_vfs_touch_inode_ctime(inode);
				clear_nlink(inode);
			}
			if (dir->i_nlink > 0)
				drop_nlink(dir);
			tidefs_posix_vfs_touch_dirent_parent(dir);
			d_drop(dentry);
			pr_debug("tidefs_posix_vfs: rmdir (engine-backed) name='%.*s'\n",
				 (unsigned int)dentry->d_name.len, dentry->d_name.name);
			return 0;
		}
	}

	idx = tidefs_kernel_pool_find_index(pool, dir->i_ino,
					    dentry->d_name.name,
					    dentry->d_name.len);
	if (idx < 0)
		return -ENOENT;
	if (!S_ISDIR(pool->inode_table[idx].mode))
		return -ENOTDIR;

	for (i = 0; i < pool->nr_inodes; i++) {
		if (pool->inode_table[i].parent_ino == pool->inode_table[idx].ino)
			return -ENOTEMPTY;
	}

	tidefs_kernel_pool_remove_index(pool, idx);
	pool->committed_txg++;
	if (tidefs_kernel_pool_persist_state(pool) != 0)
		return -EIO;

	if (inode)
		clear_nlink(inode);
	drop_nlink(dir);
	d_drop(dentry);
	pr_debug("tidefs_posix_vfs: rmdir name='%.*s' txg=%llu\n",
		 (unsigned int)dentry->d_name.len, dentry->d_name.name,
		 pool->committed_txg);
	return 0;
}

static int tidefs_posix_vfs_rename(struct mnt_idmap *idmap,
				   struct inode *old_dir,
				   struct dentry *old_dentry,
				   struct inode *new_dir,
				   struct dentry *new_dentry,
				   unsigned int flags)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	int idx;
	int ret;

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = old_dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return -EROFS;
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(old_dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = old_dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			ret = tidefs_posix_vfs_require_live_dir(old_dir);
			if (ret < 0)
				return ret;
			ret = tidefs_posix_vfs_require_live_dir(new_dir);
			if (ret < 0)
				return ret;

			ret = tidefs_posix_vfs_engine_rename(
				old_dir->i_ino,
				old_dentry->d_name.name, old_dentry->d_name.len,
				new_dir->i_ino,
				new_dentry->d_name.name, new_dentry->d_name.len,
				flags);
			if (ret < 0)
				return ret;

			/* Update the C-level inode table so the rename survives
			 * crash/persist cycles. Mirror the legacy fixed-table
			 * rename logic. */
			{
				int src_idx = tidefs_kernel_pool_find_index(
					pool, old_dir->i_ino,
					old_dentry->d_name.name,
					old_dentry->d_name.len);
				int dst_idx = tidefs_kernel_pool_find_index(
					pool, new_dir->i_ino,
					new_dentry->d_name.name,
					new_dentry->d_name.len);

				if ((flags & RENAME_EXCHANGE) && src_idx >= 0 && dst_idx >= 0) {
					tidefs_kernel_pool_set_entry_name(
						pool, src_idx, new_dir->i_ino,
						new_dentry->d_name.name,
						new_dentry->d_name.len);
					tidefs_kernel_pool_set_entry_name(
						pool, dst_idx, old_dir->i_ino,
						old_dentry->d_name.name,
						old_dentry->d_name.len);
				} else {
					if (dst_idx >= 0)
						tidefs_kernel_pool_remove_index(pool, dst_idx);
					src_idx = tidefs_kernel_pool_find_index(
						pool, old_dir->i_ino,
						old_dentry->d_name.name,
						old_dentry->d_name.len);
					if (src_idx >= 0)
						tidefs_kernel_pool_set_entry_name(
							pool, src_idx, new_dir->i_ino,
							new_dentry->d_name.name,
							new_dentry->d_name.len);
				}
			}

			/* Handle target overwrite */
			if (!(flags & RENAME_EXCHANGE) && new_inode) {
				d_drop(new_dentry);
				if (S_ISDIR(new_inode->i_mode)) {
					clear_nlink(new_inode);
				} else if (new_inode->i_nlink > 0) {
					drop_nlink(new_inode);
				}
				tidefs_posix_vfs_touch_inode_ctime(new_inode);
				if (S_ISDIR(new_inode->i_mode) && new_dir->i_nlink > 0)
					drop_nlink(new_dir);
			}
			if (old_inode)
				tidefs_posix_vfs_touch_inode_ctime(old_inode);
			tidefs_posix_vfs_touch_dirent_parent(old_dir);
			if (new_dir != old_dir)
				tidefs_posix_vfs_touch_dirent_parent(new_dir);
			/* Cross-directory subdirectory nlink adjustment */
			if (old_dir != new_dir) {
				if (old_inode && S_ISDIR(old_inode->i_mode)) {
					if (old_dir->i_nlink > 0)
						drop_nlink(old_dir);
					if (new_dir->i_nlink > 0)
						inc_nlink(new_dir);
				}
				if ((flags & RENAME_EXCHANGE) && new_inode &&
				    S_ISDIR(new_inode->i_mode)) {
					if (new_dir->i_nlink > 0)
						drop_nlink(new_dir);
					if (old_dir->i_nlink > 0)
						inc_nlink(old_dir);
				}
			}
			pr_debug("tidefs_posix_vfs: rename (engine-backed) old='%.*s' new='%.*s' flags=%u\n",
				 (unsigned int)old_dentry->d_name.len, old_dentry->d_name.name,
				 (unsigned int)new_dentry->d_name.len, new_dentry->d_name.name,
				 flags);
			return 0;
		}
	}

	/* Fixed-table path: perform rename against inode_table. */
	/* Find source entry */
	idx = tidefs_kernel_pool_find_index(pool, old_dir->i_ino,
					    old_dentry->d_name.name,
					    old_dentry->d_name.len);
	if (idx < 0)
		return -ENOENT;

	/* Check for RENAME_NOREPLACE */
	if (flags & RENAME_NOREPLACE) {
		int dst_idx = tidefs_kernel_pool_find_index(pool, new_dir->i_ino,
							    new_dentry->d_name.name,
							    new_dentry->d_name.len);
		if (dst_idx >= 0)
			return -EEXIST;
	}

	/* Remove destination if it exists */
	if (new_inode) {
		int dst_idx = tidefs_kernel_pool_find_index(pool, new_dir->i_ino,
							    new_dentry->d_name.name,
							    new_dentry->d_name.len);
		d_drop(new_dentry);
		if (dst_idx >= 0)
			tidefs_kernel_pool_remove_index(pool, dst_idx);
	}

	/* Update source entry: change parent and name */
	pool->inode_table[idx].parent_ino = new_dir->i_ino;
	strncpy((char *)pool->inode_table[idx].name,
		(const char *)new_dentry->d_name.name,
		new_dentry->d_name.len);
	pool->inode_table[idx].name[new_dentry->d_name.len] = '\0';
	pool->inode_table[idx].name_len = new_dentry->d_name.len;
	pool->committed_txg++;
	if (tidefs_kernel_pool_persist_state(pool) != 0)
		return -EIO;

	if (new_inode) {
		if (S_ISDIR(new_inode->i_mode))
			clear_nlink(new_inode);
		else if (new_inode->i_nlink > 0)
			drop_nlink(new_inode);
	}
	pr_debug("tidefs_posix_vfs: rename old='%.*s' new='%.*s' txg=%llu\n",
		 (unsigned int)old_dentry->d_name.len, old_dentry->d_name.name,
		 (unsigned int)new_dentry->d_name.len, new_dentry->d_name.name,
		 pool->committed_txg);
	return 0;
}

static int tidefs_posix_vfs_mknod(struct mnt_idmap *idmap,
				 struct inode *dir,
				 struct dentry *dentry,
				 umode_t mode, dev_t rdev)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct inode *inode;
	unsigned long long out_ino = 0;
	unsigned int out_mode = 0;
	unsigned long long out_generation = 0;
	int ret;

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return -EROFS;
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			ret = tidefs_posix_vfs_require_live_dir(dir);
			if (ret < 0)
				return ret;

			ret = tidefs_posix_vfs_engine_mknod(
				dir->i_ino,
				dentry->d_name.name,
				dentry->d_name.len,
				mode, rdev,
				&out_ino, &out_mode, &out_generation);
			if (ret < 0)
				return ret;
			if (!out_generation)
				return -EIO;

			/* Best-effort legacy mirror only; the engine owns live lookup. */
			{
				int pool_idx = tidefs_kernel_pool_mirror_engine_inode(
					pool, out_ino, dir->i_ino, out_mode, 0,
					dentry->d_name.name, dentry->d_name.len);
				if (pool_idx == -ENOSPC)
					pr_debug("tidefs_posix_vfs: mknod skipped full C mirror for ino=%llu\n",
						 out_ino);
			}

			inode = new_inode(dir->i_sb);
			if (!inode)
				return -ENOMEM;
			inode->i_ino = out_ino;
			inode->i_generation = out_generation;
			inode_init_owner(idmap, inode, dir, out_mode);
			tidefs_posix_vfs_apply_inode_ops(inode, out_mode, 0);
			tidefs_posix_vfs_init_new_inode_times(inode);
			tidefs_posix_vfs_touch_dirent_parent(dir);
			insert_inode_hash(inode);
			d_instantiate(dentry, inode);

			pr_debug("tidefs_posix_vfs: mknod (engine-backed) name=%.*s ino=%llu mode=0%o\n",
				 (unsigned int)dentry->d_name.len, dentry->d_name.name,
				 out_ino, out_mode);
			return 0;
		}
	}

	return tidefs_posix_vfs_require_engine_inode(dir, "mknod");
}

static int tidefs_posix_vfs_link(struct dentry *old_dentry,
			     struct inode *dir,
			     struct dentry *new_dentry)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct inode *inode = d_inode(old_dentry);
	unsigned long long out_ino = 0;
	unsigned int out_mode = 0;
	int ret;

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return -EROFS;
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			ret = tidefs_posix_vfs_require_live_dir(dir);
			if (ret < 0)
				return ret;
			if (!inode)
				return -ENOENT;

			ret = tidefs_posix_vfs_engine_link(
				inode->i_ino,
				dir->i_ino,
				new_dentry->d_name.name,
				new_dentry->d_name.len,
				&out_ino, &out_mode);
			if (ret < 0)
				return ret;

			/* Add a C-level inode table entry for the new link name
			 * so it survives crash/persist cycles. The target inode
			 * already exists; we only add the directory entry. */
			{
				int new_idx = -1;

				if (pool->nr_inodes < TIDEFS_KERNEL_POOL_INODE_TABLE_SIZE)
					new_idx = pool->nr_inodes++;
				if (new_idx >= 0) {
					pool->inode_table[new_idx].ino = out_ino;
					pool->inode_table[new_idx].mode = out_mode;
					pool->inode_table[new_idx].data_len = 0;
					memset(pool->inode_table[new_idx].data, 0,
					       TIDEFS_KERNEL_POOL_FILE_DATA_SIZE);
					tidefs_kernel_pool_set_entry_name(
						pool, new_idx, dir->i_ino,
						new_dentry->d_name.name,
						new_dentry->d_name.len);
				}
			}

			inc_nlink(inode);
			tidefs_posix_vfs_touch_inode_ctime(inode);
			tidefs_posix_vfs_touch_dirent_parent(dir);
			ihold(inode);
			d_instantiate(new_dentry, inode);
			pr_debug("tidefs_posix_vfs: link (engine-backed) name='%.*s' target_ino=%lu\n",
				 (unsigned int)new_dentry->d_name.len,
				 new_dentry->d_name.name,
				 inode->i_ino);
			return 0;
		}
	}

	return tidefs_posix_vfs_require_engine_inode(dir, "link");
}

static int tidefs_posix_vfs_symlink(struct mnt_idmap *idmap,
				    struct inode *dir,
				    struct dentry *dentry,
				    const char *symname)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	unsigned long long out_ino = 0;
	unsigned int out_mode = 0;
	unsigned long long out_generation = 0;
	int ret;
	size_t target_len = strlen(symname);

	/* Refuse write operations on read-only mounts. */
	{
		struct tidefs_posix_vfs_mount *mctx = dir->i_sb->s_fs_info;
		if (mctx && mctx->read_only)
			return -EROFS;
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(dir->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = dir->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			ret = tidefs_posix_vfs_require_live_dir(dir);
			if (ret < 0)
				return ret;

			ret = tidefs_posix_vfs_engine_symlink(
				dir->i_ino,
				dentry->d_name.name, dentry->d_name.len,
				(const unsigned char *)symname, (unsigned int)target_len,
				&out_ino, &out_mode, &out_generation);
			if (ret < 0)
				return ret;
			if (!out_generation)
				return -EIO;

			/* Best-effort legacy mirror only; the engine owns live lookup. */
			{
				int pool_idx = tidefs_kernel_pool_mirror_engine_inode(
					pool, out_ino, dir->i_ino, out_mode, 0,
					dentry->d_name.name, dentry->d_name.len);
				if (pool_idx == -ENOSPC)
					pr_debug("tidefs_posix_vfs: symlink skipped full C mirror for ino=%llu\n",
						 out_ino);
			}

			/* Instantiate the dentry with a proper inode so that
			 * subsequent lookups resolve through the dcache.
			 * d_instantiate(dentry, NULL) would create a negative
			 * dentry causing readlink to return ENOENT. */
			{
				struct inode *sym_inode = new_inode(dir->i_sb);
				if (!sym_inode)
					return -ENOMEM;
				sym_inode->i_ino = out_ino;
				sym_inode->i_generation = out_generation;
				inode_init_owner(idmap, sym_inode, dir, out_mode);
				tidefs_posix_vfs_apply_inode_ops(sym_inode, out_mode, target_len);
				tidefs_posix_vfs_init_new_inode_times(sym_inode);
				tidefs_posix_vfs_touch_dirent_parent(dir);
				insert_inode_hash(sym_inode);
				d_instantiate(dentry, sym_inode);
			}
			pr_debug("tidefs_posix_vfs: symlink (engine-backed) name='%.*s' target='%s' ino=%llu\n",
				 (unsigned int)dentry->d_name.len,
				 dentry->d_name.name,
				 symname, out_ino);
			return 0;
		}
	}

	return tidefs_posix_vfs_require_engine_inode(dir, "symlink");
}

static const char *tidefs_posix_vfs_get_link(struct dentry *dentry,
					     struct inode *inode,
					     struct delayed_call *done)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	unsigned int out_len = 0;
	int ret;

	if (!dentry || !inode)
		return ERR_PTR(-ECHILD);

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return ERR_PTR(PTR_ERR(pool));

	/* Engine-backed path: delegate to the Rust KernelEngine. */
	{
		struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
		if (ctx && ctx->engine_backed) {
			char *link_target;

			link_target = kzalloc(4097, GFP_KERNEL);
			if (!link_target)
				return ERR_PTR(-ENOMEM);

			ret = tidefs_posix_vfs_engine_readlink(
				inode->i_ino,
				(unsigned char *)link_target,
				4096,
				&out_len);
			if (ret < 0) {
				kfree(link_target);
				return ERR_PTR(ret);
			}
			if (out_len > 4096) {
				kfree(link_target);
				return ERR_PTR(-EOVERFLOW);
			}

			link_target[out_len] = '\0';
			if (!*link_target) {
				kfree(link_target);
				return ERR_PTR(-ENOENT);
			}
			set_delayed_call(done, kfree_link, link_target);
			pr_debug("tidefs_posix_vfs: get_link (engine-backed) ino=%lu target='%s'\n",
				 inode->i_ino, link_target);
			return link_target;
		}
	}

	return ERR_PTR(-ENOSYS);
}

static int tidefs_posix_vfs_dir_open(struct inode *inode, struct file *file)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	if (ctx && ctx->engine_backed) {
		struct TidefsEngineOpenOut eng_out;
		struct tidefs_posix_vfs_open_file_state *ofs;
		int ret = tidefs_posix_vfs_engine_opendir(inode->i_ino, &eng_out);
		if (ret < 0)
			return ret;
		if (!eng_out.ok)
			return -ENOENT;

		ofs = kzalloc(sizeof(*ofs), GFP_KERNEL);
		if (!ofs) {
			tidefs_posix_vfs_engine_releasedir(
				eng_out.fh_ino, eng_out.fh_id);
			return -ENOMEM;
		}
		ofs->fh_ino = eng_out.fh_ino;
		ofs->fh_id = eng_out.fh_id;
		ofs->open_flags = file->f_flags;
		ofs->engine_backed = true;
		file->private_data = ofs;
	}

	pr_debug("tidefs_posix_vfs: opendir root_ino=%llu txg=%llu\n",
		 pool->root_ino, pool->committed_txg);
	return 0;
}

static int tidefs_posix_vfs_dir_release(struct inode *inode,
					struct file *file)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct tidefs_posix_vfs_open_file_state *ofs = file->private_data;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	if (ofs && ofs->engine_backed) {
		int ret = tidefs_posix_vfs_engine_releasedir(
			ofs->fh_ino, ofs->fh_id);
		kfree(ofs);
		file->private_data = NULL;
		return ret;
	}
	file->private_data = NULL;

	return 0;
}

static int tidefs_posix_vfs_iterate_shared(struct file *file,
					   struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_kernel_pool_core *pool;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	/* Emit synthetic dot and dot-dot entries anchored at the pool root. */
	if (ctx->pos == 0) {
		if (!dir_emit_dots(file, ctx))
			return 0;
	}

	/*
	 * Engine-backed readdir path: when the mount
	 * context has engine_backed set, iterate directory entries through the
	 * mounted KernelEngine.  This path supports large directories (no
	 * fixed-table limit) and provides cookie-based seekdir stability.
	 */
	{
		struct tidefs_posix_vfs_mount *mctx;
		mctx = inode->i_sb->s_fs_info;
		if (mctx && mctx->engine_backed) {
			/* The engine stores directory entries keyed by parent_ino
			 * with stable per-mount cookies. ctx->pos 0/1 are dots;
			 * ctx->pos >= 2 stores last_seen_cookie + 2. */
			unsigned int cookie = (ctx->pos >= 2) ? (unsigned int)(ctx->pos - 2) : 0;
			while (1) {
				struct tidefs_posix_vfs_engine_readdir_out eo;
				int rr;
				unsigned char name_buf[256];
				unsigned int name_len;

				rr = tidefs_posix_vfs_engine_readdir(
					inode->i_ino, cookie, &eo);
				if (rr != 0 || eo.ino == 0)
					break; /* end of directory or error */

				/* Retrieve the entry name. */
				name_len = 0;
				rr = tidefs_posix_vfs_engine_readdir_name(
					inode->i_ino, eo.next_cookie,
					name_buf, sizeof(name_buf),
					&name_len);
				if (rr != 0 || name_len == 0)
					break;

				/* Emit the entry. */
				{
					unsigned char dtype;
					dtype = (eo.entry_type == 0) ? DT_DIR :
						(eo.entry_type == 2) ? DT_LNK : DT_REG;
					if (!dir_emit(ctx, name_buf, name_len,
						      eo.ino, dtype))
						break;
				}
				cookie = eo.next_cookie;
				ctx->pos = (loff_t)cookie + 2;
			}
			return 0;
		}
	}

	/*
	 * Engine-backed replay path (#6252): attempt DirPage iteration
	 * through the inline DirPage scanner. Falls back to the fixed
	 * table on any failure or when the on-disk DirPage is not valid
	 * VDIR format.
	 */
	if (pool->block_size >= 512 && pool->superblock_size > 0) {
		u64 dir_page_offset = tidefs_kernel_pool_state_base(pool) +
				      TIDEFS_KERNEL_POOL_STATE_BLOCK_OFFSET;
		u8 *dir_page_block = kzalloc(pool->block_size, GFP_KERNEL);
		if (dir_page_block) {
			int ret = tidefs_kernel_pool_rw(pool,
				dir_page_offset, dir_page_block,
				pool->block_size, false);
			if (ret == 0) {
				/* Iterate DirPage entries using cookie-based
				 * replay bridge. ctx->pos - 2 maps to the
				 * DirPage entry cookie (pos 0,1 are dots). */
				u32 cookie = (u32)(ctx->pos - 2);
				while (1) {
					struct tidefs_posix_vfs_replay_readdir_out ro;
					int rr;

					rr = tidefs_posix_vfs_engine_replay_readdir(
						dir_page_block, pool->block_size,
						cookie, &ro);
					if (rr != 0)
						break;
					if (ro.ino == 0)
						break; /* end of page */

					/* Emit the entry. */
					{
						/* Name is inline in the DirPage
						 * buffer at the entry's name offset.
						 * For the replay bridge, the name
						 * bytes are in dir_page_block at
						 * a computed offset. We pass the
						 * name buffer directly. */
						u8 name[256];
						/* Compute name position from entry layout:
						 *   pos = DIR_PAGE_HEADER_LEN + cookie * (DIR_ENTRY_HEADER_LEN + name_len_avg)
						 * But we don't track entry positions here.
						 * Instead, reconstruct from known layout:
						 *   entry header at: pos = 16 + sum of prior entry sizes.
						 * Since we use cookie to track progress,
						 * we can scan to the right entry.
						 *
						 * Simpler: the replay bridge returns name_len;
						 * the name bytes are in dir_page_block at
						 * a computed offset based on the cookie.
						 * We need to locate them by scanning.
						 */
						unsigned int pos = 16; /* DIR_PAGE_HEADER_LEN */
						u32 scan_cookie = 0;
						unsigned int dtype;
						u32 name_len;

						/* Scan to find the entry matching cookie. */
						while (scan_cookie < cookie && pos < pool->block_size) {
							if (pos + 26 > pool->block_size)
								goto replay_done;
							name_len = dir_page_block[pos];
							pos += 26 + name_len;
							scan_cookie++;
						}
						if (pos + 26 > pool->block_size)
							goto replay_done;
						name_len = dir_page_block[pos];
						if (pos + 26 + name_len > pool->block_size)
							goto replay_done;
						memcpy(name, dir_page_block + pos + 26, name_len);

						dtype = (ro.entry_type == 0) ? DT_DIR :
							(ro.entry_type == 2) ? DT_LNK : DT_REG;
						if (!dir_emit(ctx, name, name_len,
							      ro.ino, dtype))
							goto replay_done;
						ctx->pos++;
					}
					cookie = ro.next_cookie;
				}
			}
replay_done:
			kfree(dir_page_block);
		}
	}

	/*
	 * Fallback: fixed-table iteration.
	 * ctx->pos may have been advanced by the replay path above.
	 * If DirPage replay was attempted and we reach here, it means either
	 * the DirPage was exhausted or the on-disk format wasn't VDIR.
	 * Continue with the fixed table from the same ctx->pos.
	 */
	{
		loff_t wanted = ctx->pos - 2;
		loff_t seen = 0;
		int i;

		for (i = 0; i < pool->nr_inodes; i++) {
			unsigned int dtype;

			if (pool->inode_table[i].parent_ino != inode->i_ino)
				continue;
			if (seen++ < wanted)
				continue;

			dtype = S_ISDIR(pool->inode_table[i].mode) ? DT_DIR : DT_REG;
			if (!dir_emit(ctx,
				      pool->inode_table[i].name,
				      pool->inode_table[i].name_len,
				      pool->inode_table[i].ino,
				      dtype))
				return 0;
			ctx->pos++;
		}
	}
	return 0;
}

static int tidefs_posix_vfs_dir_fsync(struct file *file, loff_t start,
				      loff_t end, int datasync)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct tidefs_posix_vfs_mount *ctx;

	ctx = file_inode(file)->i_sb->s_fs_info;
	if (ctx && ctx->engine_backed) {
		int ret = tidefs_posix_vfs_activate_engine(ctx);
		if (ret < 0)
			return ret;
		/* fsync and fdatasync are both wait barriers for directory state. */
		return tidefs_posix_vfs_engine_sync_fs(1);
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(file_inode(file)->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);
	return tidefs_kernel_pool_persist_state(pool);
}

static int tidefs_posix_vfs_getattr(struct mnt_idmap *idmap,
				     const struct path *path,
				     struct kstat *stat,
				     u32 request_mask,
				     unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct tidefs_posix_vfs_kernel_pool_core *pool;

	struct tidefs_posix_vfs_replay_getattr_out ga;
	u64 btime_secs_saved = 0;
	u32 btime_nsec_saved = 0;
	umode_t mode;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	{
		struct tidefs_posix_vfs_mount *mctx = inode->i_sb->s_fs_info;
		struct tidefs_posix_vfs_engine_attr_out ea;
		int ret;

		if (mctx && mctx->engine_backed) {
			memset(&ea, 0, sizeof(ea));
			ret = tidefs_posix_vfs_engine_getattr(inode->i_ino, &ea);
			if (ret < 0)
				return ret;
			if (ea.ino == 0)
				return -ENOENT;
			tidefs_posix_vfs_apply_engine_attr(inode, &ea);
			goto fill;
		}
	}

	/*
	 * Engine-backed replay path (#6252): attempt to read inode
	 * attributes through the canonical KernelInodeTableReader.
	 * Falls back to the fixed table on any failure.
	 *
	 * The VRBT is at root_offset = superblock_offset + 3*block_size.
	 * The inode table is at inode_table_root (currently state_base).
	 * On-disk format at that location is still the fixed-table header,
	 * so KernelInodeTableReader will reject it (SlotEmpty). This path
	 * is exercised but not yet authoritative until the write path
	 * (#6253) persists real VINO-format records.
	 */
	{
		u64 vrbt_offset = pool->superblock_offset +
				  (3ULL * pool->block_size);
		u64 ino_table_offset = tidefs_kernel_pool_state_base(pool) +
				       TIDEFS_KERNEL_POOL_STATE_BLOCK_OFFSET;
		u8 *vrbt_block = NULL;
		u8 *inode_table_block = NULL;
		int ret;

		if (pool->block_size < 88)
			goto fallback;
		if (pool->superblock_size < (4ULL * pool->block_size)) {
			pr_debug("tidefs_posix_vfs: getattr: superblock too small for VRBT replay\n");
			goto fallback;
		}

		vrbt_block = kzalloc(pool->block_size, GFP_KERNEL);
		if (!vrbt_block)
			goto fallback;
		inode_table_block = kzalloc(pool->block_size, GFP_KERNEL);
		if (!inode_table_block) {
			kfree(vrbt_block);
			goto fallback;
		}

		/* Read VRBT block from the superblock region. */
		ret = tidefs_kernel_pool_rw(pool, vrbt_offset,
					    vrbt_block, pool->block_size,
					    false);
		if (ret) {
			kfree(inode_table_block);
			kfree(vrbt_block);
			goto fallback;
		}

		/* Read the inode table region from disk. */
		ret = tidefs_kernel_pool_rw(pool, ino_table_offset,
					    inode_table_block,
					    pool->block_size,
					    false);
		if (ret) {
			kfree(inode_table_block);
			kfree(vrbt_block);
			goto fallback;
		}

		/* Call the Rust replay bridge. */
		ret = tidefs_posix_vfs_engine_replay_getattr(
			vrbt_block, 88,
			inode_table_block, pool->block_size,
			pool->block_size,
			inode->i_ino,
			&ga);
		kfree(inode_table_block);
		kfree(vrbt_block);

		if (ret == 0) {
			/*
			 * Replay succeeded: apply canonical attributes.
			 * This path becomes authoritative once the on-disk
			 * inode table contains real VINO-format records.
			 */
			inode->i_mode = ga.mode;
			inode->i_uid = make_kuid(&init_user_ns, ga.uid);
			inode->i_gid = make_kgid(&init_user_ns, ga.gid);
			i_size_write(inode, ga.size);
			set_nlink(inode, ga.nlink);
			inode->i_blocks = ga.blocks;
			inode_set_atime(inode, ga.atime_secs, 0);
			inode_set_mtime(inode, ga.mtime_secs, 0);
			inode_set_ctime(inode, ga.ctime_secs, 0);
			if (ga.flags != 0)
				inode->i_flags = ga.flags;
			if (ga.btime_secs != 0 || ga.btime_nsec != 0) {
				btime_secs_saved = ga.btime_secs;
				btime_nsec_saved = ga.btime_nsec;
			}

			pr_debug("tidefs_posix_vfs: getattr ino=%lu replay ok kind=%u size=%llu\n",
				 inode->i_ino, ga.kind, ga.size);
			goto fill;
		}
		/*
		 * Replay failed — expected while the on-disk format at
		 * inode_table_root is still the fixed-table header rather
		 * than real VINO 100-byte records. Fall through to the
		 * fixed-table path.
		 */
		pr_debug("tidefs_posix_vfs: getattr ino=%lu replay returned %d; falling back to fixed table\n",
			 inode->i_ino, ret);
	}

fallback:
	/* For non-root inodes, sync mode from pool table. */
	if (inode->i_ino != pool->root_ino) {
		mode = tidefs_kernel_pool_ino_mode(pool, inode->i_ino);
		if (mode != 0)
			inode->i_mode = mode;
		i_size_write(inode, tidefs_kernel_pool_ino_size(pool, inode->i_ino));
	}

fill:
	generic_fillattr(idmap, request_mask, inode, stat);

	/* Wire btime and attributes from the replay path. */
	if (btime_secs_saved != 0 || btime_nsec_saved != 0) {
		stat->btime.tv_sec = btime_secs_saved;
		stat->btime.tv_nsec = btime_nsec_saved;
		stat->result_mask |= STATX_BTIME;
	}
	generic_fill_statx_attr(inode, stat);
	if (inode->i_flags & FS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;

	pr_debug("tidefs_posix_vfs: getattr ino=%lu txg=%llu mode=0%o\n",
		 inode->i_ino, pool->committed_txg, stat->mode);
	return 0;
}

static int tidefs_posix_vfs_file_open(struct inode *inode, struct file *file)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;

	/* Engine-backed path (#6274): delegate to the Rust KernelEngine
	 * so that engine-backed inodes (create/mkdir through Rust) are
	 * visible to the VFS open path. */
	if (ctx && ctx->engine_backed) {
		struct TidefsEngineOpenOut eng_out;
		struct tidefs_posix_vfs_open_file_state *ofs;
		int ret = tidefs_posix_vfs_activate_engine(ctx);
		if (ret < 0)
			return ret;
		ret = tidefs_posix_vfs_engine_open(inode->i_ino,
						   file->f_flags, &eng_out);
		if (ret < 0)
			return ret;
		if (!eng_out.ok)
			return -ENOENT;

		ofs = kzalloc(sizeof(*ofs), GFP_KERNEL);
		if (!ofs) {
			tidefs_posix_vfs_engine_release(
				eng_out.fh_ino, eng_out.fh_id);
			return -ENOMEM;
		}
		ofs->fh_ino = eng_out.fh_ino;
		ofs->fh_id = eng_out.fh_id;
		ofs->open_flags = file->f_flags;
		ofs->engine_backed = true;
		file->private_data = ofs;

		/* O_TRUNC size reset is now handled by the engine on open;
		 * the C fixed-table data_len reset is only needed for the
		 * bootstrap path below. */
		return 0;
	}

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);
	if (tidefs_kernel_pool_find_index_by_ino(pool, inode->i_ino) < 0)
		return -ENOENT;
	return 0;
}

static int tidefs_posix_vfs_file_release(struct inode *inode, struct file *file)
{
	struct tidefs_posix_vfs_open_file_state *ofs = file->private_data;

	/* Engine-backed path (#6274): release the real engine file handle
	 * stored in file->private_data by tidefs_posix_vfs_file_open. */
	if (ofs && ofs->engine_backed) {
		struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
		int wb_ret = 0;
		int ret;

		if ((file->f_mode & FMODE_WRITE) &&
		    (mapping_tagged(inode->i_mapping, PAGECACHE_TAG_DIRTY) ||
		     mapping_tagged(inode->i_mapping, PAGECACHE_TAG_WRITEBACK)))
			wb_ret = filemap_write_and_wait(inode->i_mapping);
		if (ofs->times_dirty) {
			int ts_ret = tidefs_posix_vfs_engine_persist_inode_times(
				inode, TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME);

			if (ts_ret == 0)
				ofs->times_dirty = false;
			else if (wb_ret == 0)
				wb_ret = ts_ret;
		}
		if (ctx && ctx->engine_backed) {
			ret = tidefs_posix_vfs_activate_engine(ctx);
			if (ret < 0) {
				kfree(ofs);
				file->private_data = NULL;
				return ret;
			}
		}
		ret = tidefs_posix_vfs_engine_release(
			ofs->fh_ino, ofs->fh_id);
		kfree(ofs);
		file->private_data = NULL;
		if (ret < 0)
			return ret;
		if (wb_ret < 0)
			return wb_ret;
		return 0;
	}

	/* Non-engine path: nothing to release. */
	if (ofs)
		kfree(ofs);
	file->private_data = NULL;
	return 0;
}


static ssize_t tidefs_posix_vfs_file_read_into(struct file *file,
					       void *buf,
					       size_t len,
					       loff_t *ppos,
					       bool user_buffer)
{
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	u64 available;
	size_t to_copy;
	int idx;

	if (*ppos < 0)
		return -EINVAL;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	idx = tidefs_kernel_pool_find_index_by_ino(pool, inode->i_ino);
	if (idx < 0)
		return -ENOENT;
	if (!S_ISREG(pool->inode_table[idx].mode))
		return -EISDIR;

	/*
	 * Engine-backed replay path (#6252): attempt extent-map lookup
	 * through the inline EXMP leaf page parser.  The extent_map_root
	 * field in the on-disk inode record would normally point to the
	 * root of the extent B-tree.  For the initial cut point, we
	 * read the extent page from the pool state area (same as the
	 * inode table / directory).  The locator_id returned is an
	 * object-store locator that requires block-allocator translation
	 * before physical I/O is possible; that translation is not yet
	 * implemented in the kernel module.
	 *
	 * When the replay extent lookup succeeds, we record the result
	 * but still serve data from the fixed table.  When block-allocator
	 * translation is available (#6253 / #6274), this path will
	 * perform real physical I/O through tidefs_kernel_pool_rw.
	 */
	if (pool->block_size >= 512 && pool->superblock_size > 0) {
		u64 extent_page_offset = tidefs_kernel_pool_state_base(pool) +
			TIDEFS_KERNEL_POOL_STATE_BLOCK_OFFSET;
		u8 *extent_page_buf;
		int ret;
		struct tidefs_posix_vfs_replay_extent_out eo;

		/* Use the inode's extent_map_root as the page offset when
		 * the on-disk inode table contains real VINO records.
		 * For now, read the same state_base area used by getattr. */
		extent_page_buf = kzalloc(pool->block_size, GFP_KERNEL);
		if (extent_page_buf) {
			ret = tidefs_kernel_pool_rw(pool,
				extent_page_offset, extent_page_buf,
				pool->block_size, false);
			if (ret == 0) {
				ret = tidefs_posix_vfs_engine_replay_extent_lookup(
					extent_page_buf, pool->block_size,
					*ppos, &eo);
				if (ret == 0 && eo.locator_id != 0 &&
				    eo.extent_kind == 0) {
					/* Extent found: locator_id would be
					 * translated to physical block address
					 * by the block allocator (#6274).
					 * For now, record success and fall
					 * through to the fixed-table read. */
					pr_debug("tidefs_posix_vfs: file_read ino=%lu off=%lld extent found locator=%llu len=%llu\n",
						 inode->i_ino, *ppos,
						 eo.locator_id,
						 eo.extent_length);
				}
			}
			kfree(extent_page_buf);
		}
	}

	if (*ppos >= pool->inode_table[idx].data_len)
		return 0;

	available = pool->inode_table[idx].data_len - *ppos;
	to_copy = min_t(size_t, len, available);
	if (user_buffer) {
		if (copy_to_user((char __user *)buf,
				 pool->inode_table[idx].data + *ppos,
				 to_copy))
			return -EFAULT;
	} else {
		memcpy(buf, pool->inode_table[idx].data + *ppos, to_copy);
	}

	*ppos += to_copy;
	return to_copy;
}


/*
 * read_iter -- vectored read through iov_iter (K7-IOVEC-001).
 *
 * Replaces the legacy .read callback with a kernel-iov_iter-aware
 * read path.  Data is copied directly from the pool inode table into
 * user-space iovecs via copy_to_iter, eliminating the per-segment
 * copy_to_user round-trip.
 *
 * Called by the Linux VFS for read(2), readv(2), preadv(2),
 * preadv2(2), and kernel-internal callers (splice_read when
 * no custom .splice_read is set, sendfile, etc.).
 */
static ssize_t tidefs_posix_vfs_file_read_iter(struct kiocb *iocb,
						struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_open_file_state *ofs = file->private_data;
	loff_t pos = iocb->ki_pos;
	ssize_t total = 0;

	if (pos < 0)
		return -EINVAL;

	/*
	 * Engine-backed buffered reads must use the Linux page cache so dirty
	 * folios remain the read authority until writeback drains them.  Direct
	 * reads keep the explicit engine bridge after reconciling overlapping
	 * cached writeback state below.
	 */
	if (ofs && ofs->engine_backed) {
		struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
		struct timespec64 old_atime = inode_get_atime(inode);
		size_t requested = iov_iter_count(to);
		int ret;

		if (ctx && ctx->engine_backed) {
			ret = tidefs_posix_vfs_activate_engine(ctx);
			if (ret < 0)
				return ret;
		}

		if (!(iocb->ki_flags & IOCB_DIRECT)) {
			ssize_t read_ret;

			if (requested > 0) {
				u64 fence_generation;

				fence_generation =
					tidefs_posix_vfs_pagecache_fence_snapshot(
						inode, pos, requested);
				filemap_invalidate_lock(inode->i_mapping);
				ret = tidefs_posix_vfs_drop_fenced_pagecache_range(
					inode, pos, requested,
					"cached-read-fence-drop-failed");
				filemap_invalidate_unlock(inode->i_mapping);
				if (ret)
					return ret;

				tidefs_posix_vfs_filemap_invalidate_lock_shared(
					inode->i_mapping);
				if (!tidefs_posix_vfs_pagecache_fence_still_current(
					    inode, pos, requested,
					    fence_generation)) {
					tidefs_posix_vfs_filemap_invalidate_unlock_shared(
						inode->i_mapping);
					return -EAGAIN;
				}
				read_ret = generic_file_read_iter(iocb, to);
				tidefs_posix_vfs_filemap_invalidate_unlock_shared(
					inode->i_mapping);
			} else {
				read_ret = generic_file_read_iter(iocb, to);
			}
			if (read_ret > 0) {
				struct timespec64 new_atime;

				new_atime = inode_get_atime(inode);
				if (!timespec64_equal(&old_atime, &new_atime))
					tidefs_posix_vfs_persist_inode_times_best_effort(
						inode, TIDEFS_POSIX_VFS_FATTR_ATIME);
			}
			return read_ret;
		}

		if (requested > 0) {
			loff_t end = pos + (loff_t)requested - 1;
			int wb_ret;

			if (end < pos)
				end = LLONG_MAX;
			wb_ret = filemap_write_and_wait_range(
				inode->i_mapping, pos, end);
			if (wb_ret < 0)
				return wb_ret;
		}

		while (iov_iter_count(to) > 0) {
			size_t chunk;
			unsigned char *kbuf;

			chunk = min_t(size_t, iov_iter_count(to), 131072);
			kbuf = kmalloc(chunk, GFP_KERNEL);
			if (!kbuf)
				return total > 0 ? total : -ENOMEM;

			ret = tidefs_posix_vfs_engine_read(
				ofs->fh_ino, ofs->fh_id,
				(u64)pos, kbuf, (u32)chunk);
			if (ret < 0) {
				kfree(kbuf);
				return total > 0 ? total : ret;
			}
			if (ret == 0) {
				kfree(kbuf);
				break; /* EOF */
			}

			{
				size_t copied = copy_to_iter(kbuf, (size_t)ret, to);
				kfree(kbuf);
				if (copied == 0)
					break;
				pos += (loff_t)copied;
				total += (ssize_t)copied;
			}
		}

		iocb->ki_pos = pos;
		if (total > 0) {
			struct timespec64 new_atime;

			file_accessed(file);
			new_atime = inode_get_atime(inode);
			if (!timespec64_equal(&old_atime, &new_atime))
				tidefs_posix_vfs_persist_inode_times_best_effort(
					inode, TIDEFS_POSIX_VFS_FATTR_ATIME);
		}
		return total;
	}

	/* Bootstrap fixed-table path: read from the C-level inode table.
	 * Only reached for non-engine mounts (bootstrap, recovery, or
	 * pool import without a mounted engine). */
	{
		struct tidefs_posix_vfs_kernel_pool_core *pool;
		int idx;

		pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
		if (IS_ERR(pool))
			return PTR_ERR(pool);

		idx = tidefs_kernel_pool_find_index_by_ino(pool, inode->i_ino);
		if (idx < 0)
			return -ENOENT;
		if (!S_ISREG(pool->inode_table[idx].mode))
			return -EISDIR;

		while (iov_iter_count(to) > 0) {
			u64 available;
			size_t chunk;
			size_t copied;

			if (pos >= pool->inode_table[idx].data_len)
				break;

			available = pool->inode_table[idx].data_len - pos;
			if (available == 0)
				break;
			chunk = min_t(size_t, iov_iter_count(to),
				      (size_t)available);

			copied = copy_to_iter(pool->inode_table[idx].data + pos,
					      chunk, to);
			if (copied == 0)
				break;

			pos += copied;
			total += copied;
		}
	}

	iocb->ki_pos = pos;
	return total;
}

static loff_t tidefs_posix_vfs_pagecache_range_end(loff_t pos, size_t len)
{
	if (len == 0 || pos < 0)
		return pos;
	if ((loff_t)len < 0 || pos > LLONG_MAX - (loff_t)len)
		return LLONG_MAX;
	return pos + (loff_t)len;
}

static bool tidefs_posix_vfs_pagecache_ranges_overlap(loff_t a_start,
						      loff_t a_end,
						      loff_t b_start,
						      loff_t b_end)
{
	return a_start < b_end && b_start < a_end;
}

static u64 tidefs_posix_vfs_pagecache_raise_fence(struct inode *inode,
						  loff_t pos,
						  size_t len,
						  const char *reason)
{
	struct tidefs_posix_vfs_mount *ctx;
	struct tidefs_posix_vfs_pagecache_fence *fence;
	unsigned long flags;
	loff_t start;
	loff_t end;
	u32 slot;
	u64 generation;

	if (!inode || !inode->i_sb || len == 0 || pos < 0)
		return 0;

	ctx = inode->i_sb->s_fs_info;
	if (!ctx)
		return 0;

	start = round_down(pos, PAGE_SIZE);
	end = tidefs_posix_vfs_pagecache_range_end(pos, len);
	if (end > LLONG_MAX - (PAGE_SIZE - 1))
		end = LLONG_MAX;
	else
		end = round_up(end, PAGE_SIZE);
	if (end <= start)
		return 0;

	spin_lock_irqsave(&ctx->pagecache_fence_lock, flags);
	generation = ++ctx->pagecache_fence_generation;
	if (generation == 0)
		generation = ++ctx->pagecache_fence_generation;
	slot = ctx->pagecache_fence_cursor++ %
		TIDEFS_POSIX_VFS_PAGECACHE_FENCE_SLOTS;
	fence = &ctx->pagecache_fences[slot];
	/* On ring wrap, promote the evicted fence to a mount-wide drop fence. */
	if (fence->generation != 0 &&
	    ctx->pagecache_fence_overflow_generation < generation)
		ctx->pagecache_fence_overflow_generation = generation;
	fence->ino = inode->i_ino;
	fence->start = start;
	fence->end = end;
	fence->generation = generation;
	spin_unlock_irqrestore(&ctx->pagecache_fence_lock, flags);

	pr_debug("tidefs_posix_vfs: pagecache fence ino=%lu start=%lld end=%lld gen=%llu reason=%s\n",
		 inode->i_ino, start, end, generation, reason ? reason : "unknown");
	return generation;
}

static u64 tidefs_posix_vfs_pagecache_fence_snapshot(struct inode *inode,
						     loff_t pos,
						     size_t len)
{
	struct tidefs_posix_vfs_mount *ctx;
	unsigned long flags;
	loff_t start;
	loff_t end;
	u64 generation;
	int i;

	if (!inode || !inode->i_sb || len == 0 || pos < 0)
		return 0;

	ctx = inode->i_sb->s_fs_info;
	if (!ctx)
		return 0;

	start = round_down(pos, PAGE_SIZE);
	end = tidefs_posix_vfs_pagecache_range_end(pos, len);
	if (end > LLONG_MAX - (PAGE_SIZE - 1))
		end = LLONG_MAX;
	else
		end = round_up(end, PAGE_SIZE);
	if (end <= start)
		return 0;

	spin_lock_irqsave(&ctx->pagecache_fence_lock, flags);
	generation = ctx->pagecache_fence_overflow_generation;
	for (i = 0; i < TIDEFS_POSIX_VFS_PAGECACHE_FENCE_SLOTS; i++) {
		const struct tidefs_posix_vfs_pagecache_fence *fence =
			&ctx->pagecache_fences[i];

		if (fence->generation == 0 || fence->ino != inode->i_ino)
			continue;
		if (!tidefs_posix_vfs_pagecache_ranges_overlap(
			    start, end, fence->start, fence->end))
			continue;
		generation = max(generation, fence->generation);
	}
	spin_unlock_irqrestore(&ctx->pagecache_fence_lock, flags);

	return generation;
}

static bool tidefs_posix_vfs_pagecache_fence_still_current(struct inode *inode,
							   loff_t pos,
							   size_t len,
							   u64 snapshot)
{
	return tidefs_posix_vfs_pagecache_fence_snapshot(inode, pos, len) ==
	       snapshot;
}

static int tidefs_posix_vfs_drop_fenced_pagecache_range(struct inode *inode,
							loff_t pos,
							size_t len,
							const char *reason)
{
	struct address_space *mapping;
	loff_t start;
	loff_t end;
	loff_t invalidate_end;
	int ret;

	if (!inode || len == 0 || pos < 0)
		return 0;
	if (!tidefs_posix_vfs_pagecache_fence_snapshot(inode, pos, len))
		return 0;

	mapping = inode->i_mapping;
	if (!mapping)
		return 0;

	start = round_down(pos, PAGE_SIZE);
	end = tidefs_posix_vfs_pagecache_range_end(pos, len);
	if (end > LLONG_MAX - (PAGE_SIZE - 1))
		invalidate_end = LLONG_MAX;
	else
		invalidate_end = round_up(end, PAGE_SIZE) - 1;
	if (invalidate_end < start)
		return 0;

	unmap_mapping_range(mapping, start,
			    invalidate_end == LLONG_MAX ? 0 :
			    invalidate_end - start + 1, 0);
	ret = invalidate_inode_pages2_range(mapping,
					    start >> PAGE_SHIFT,
					    invalidate_end >> PAGE_SHIFT);
	if (ret)
		tidefs_posix_vfs_pagecache_raise_fence(
			inode, pos, len, reason);
	return ret;
}

static int tidefs_posix_vfs_flush_invalidate_pagecache_range(
	struct inode *inode,
	loff_t pos,
	size_t len)
{
	struct address_space *mapping;
	loff_t end;
	loff_t flush_start;
	loff_t flush_end;
	int ret;

	if (!inode || len == 0 || pos < 0)
		return 0;

	mapping = inode->i_mapping;
	if (!mapping)
		return 0;

	if ((loff_t)len < 0 || pos > LLONG_MAX - (loff_t)len + 1)
		end = LLONG_MAX;
	else
		end = pos + (loff_t)len - 1;

	flush_start = round_down(pos, PAGE_SIZE);
	if (end > LLONG_MAX - (PAGE_SIZE - 1))
		flush_end = LLONG_MAX;
	else
		flush_end = round_up(end + 1, PAGE_SIZE) - 1;

	ret = filemap_write_and_wait_range(mapping, flush_start, flush_end);
	if (ret) {
		tidefs_posix_vfs_pagecache_raise_fence(
			inode, pos, len, "write-and-wait-failed");
		return ret;
	}

	unmap_mapping_range(mapping, flush_start,
			    flush_end == LLONG_MAX ? 0 :
			    flush_end - flush_start + 1, 0);
	ret = invalidate_inode_pages2_range(mapping,
					    flush_start >> PAGE_SHIFT,
					    flush_end >> PAGE_SHIFT);
	if (ret)
		tidefs_posix_vfs_pagecache_raise_fence(
			inode, pos, len, "invalidate-failed");
	return ret;
}

static int tidefs_posix_vfs_invalidate_pagecache_range(
	struct inode *inode,
	loff_t pos,
	size_t len)
{
	struct address_space *mapping;
	loff_t end;
	loff_t start;
	loff_t invalidate_end;

	if (!inode || len == 0 || pos < 0)
		return 0;

	mapping = inode->i_mapping;
	if (!mapping)
		return 0;

	if ((loff_t)len < 0 || pos > LLONG_MAX - (loff_t)len + 1)
		end = LLONG_MAX;
	else
		end = pos + (loff_t)len - 1;

	start = round_down(pos, PAGE_SIZE);
	if (end > LLONG_MAX - (PAGE_SIZE - 1))
		invalidate_end = LLONG_MAX;
	else
		invalidate_end = round_up(end + 1, PAGE_SIZE) - 1;

	unmap_mapping_range(mapping, start,
			    invalidate_end == LLONG_MAX ? 0 :
			    invalidate_end - start + 1, 0);
	{
		int ret = invalidate_inode_pages2_range(mapping,
							start >> PAGE_SHIFT,
							invalidate_end >> PAGE_SHIFT);
		tidefs_posix_vfs_pagecache_raise_fence(
			inode, pos, len,
			ret ? "post-mutation-invalidate-failed" :
			      "post-mutation-invalidate");
		return ret;
	}
}

static int tidefs_posix_vfs_prepare_truncate_pagecache(
	struct inode *inode,
	loff_t old_size,
	loff_t new_size)
{
	if (!inode || old_size < 0 || new_size < 0 || old_size == new_size)
		return 0;

	/*
	 * Review debt TFR-018: the mounted product path does not register the
	 * Rust source-model invalidate_folio/page-authority bridge. Truncate
	 * therefore owns live cleanup here: wait for dirty mapped or buffered
	 * folios in the size-change range, unmap them, and discard the page
	 * cache before the engine-visible size changes.
	 */
	if (new_size < old_size)
		return tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode, new_size, old_size - new_size);

	return tidefs_posix_vfs_flush_invalidate_pagecache_range(
		inode, old_size, new_size - old_size);
}

static ssize_t tidefs_posix_vfs_file_direct_engine_write(
	struct kiocb *iocb,
	struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct tidefs_posix_vfs_open_file_state *ofs = file->private_data;
	loff_t pos = iocb->ki_pos;
	size_t len = iov_iter_count(from);
	size_t copied;
	unsigned char stack_buf[256];
	unsigned char *kbuf = stack_buf;
	int ret;
	ssize_t written;
	u64 write_pos;

	if (pos < 0)
		return -EINVAL;
	if (!ctx || !ctx->engine_backed)
		return -EIO;

	ret = tidefs_posix_vfs_activate_engine(ctx);
	if (ret < 0)
		return ret;

	if (len > 1024 * 1024)
		len = 1024 * 1024;
	if (len == 0)
		return 0;

	write_pos = pos;
	if (file->f_flags & O_APPEND)
		write_pos = i_size_read(inode);
	if (write_pos > (u64)LLONG_MAX ||
	    (u64)len > (u64)LLONG_MAX - write_pos) {
		return -EFBIG;
	}

	ret = file_remove_privs(file);
	if (ret)
		return ret;
	ret = file_update_time(file);
	if (ret)
		return ret;

	ret = tidefs_posix_vfs_flush_invalidate_pagecache_range(
		inode, (loff_t)write_pos, len);
	if (ret)
		return ret;

	if (len > sizeof(stack_buf)) {
		kbuf = kmalloc(len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
	}
	copied = copy_from_iter(kbuf, len, from);
	if (copied == 0) {
		if (kbuf != stack_buf)
			kfree(kbuf);
		return -EFAULT;
	}

	ret = tidefs_posix_vfs_engine_write(
		ofs ? ofs->fh_ino : inode->i_ino,
		ofs ? ofs->fh_id : inode->i_ino,
		write_pos,
		(const unsigned char *)kbuf, (u32)copied);
	if (kbuf != stack_buf)
		kfree(kbuf);
	if (ret < 0) {
		iov_iter_revert(from, copied);
		return ret;
	}
	if ((size_t)ret > copied) {
		iov_iter_revert(from, copied);
		return -EIO;
	}
	if (ret == 0) {
		iov_iter_revert(from, copied);
		return -EIO;
	}
	if ((size_t)ret < copied)
		iov_iter_revert(from, copied - (size_t)ret);

	written = ret;
	tidefs_posix_vfs_pagecache_raise_fence(
		inode, (loff_t)write_pos, (size_t)written, "direct-write");
	write_pos += ret;
	iocb->ki_pos = write_pos;
	i_size_write(inode, max_t(u64, i_size_read(inode), write_pos));
	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	mark_inode_dirty(inode);
	if (ofs)
		ofs->times_dirty = true;
	else
		tidefs_posix_vfs_persist_inode_times_best_effort(
			inode, TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME);

	ret = tidefs_posix_vfs_flush_invalidate_pagecache_range(
		inode, (loff_t)(write_pos - written), (size_t)written);
	if (ret)
		mapping_set_error(inode->i_mapping, ret);
	return written;
}

/*
 * write_iter -- vectored write through iov_iter.
 *
 * Replaces the legacy .write callback with a kernel-iov_iter-aware
 * write path.  Data is copied from user-space iovecs into the pool
 * inode table via copy_from_iter for fixed-table files, or staged in
 * a kernel buffer and dispatched to the Rust engine for engine-backed
 * mounts.
 *
 * Called by the Linux VFS for write(2), writev(2), pwritev(2),
 * pwritev2(2), and kernel-internal callers (splice_write actor via
 * kernel_write, etc.).
 */
static ssize_t tidefs_posix_vfs_file_write_iter(struct kiocb *iocb,
						 struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	loff_t pos = iocb->ki_pos;
	ssize_t total = 0;

	if (pos < 0)
		return -EINVAL;

	if (!iov_iter_count(from))
		return 0;

	/* Engine-backed path: buffered writes enter the Linux page cache and
	 * direct writes reconcile that cache before dispatching to the engine. */
	if (ctx && ctx->engine_backed && iov_iter_count(from) > 0) {
		ssize_t ret;

		ret = tidefs_posix_vfs_activate_engine(ctx);
		if (ret < 0)
			return ret;

		if (iocb->ki_flags & IOCB_DIRECT) {
			inode_lock(inode);
			ret = generic_write_checks(iocb, from);
			if (ret > 0) {
				filemap_invalidate_lock(inode->i_mapping);
				ret = tidefs_posix_vfs_file_direct_engine_write(
					iocb, from);
				filemap_invalidate_unlock(inode->i_mapping);
			}
			inode_unlock(inode);
			if (ret > 0)
				ret = generic_write_sync(iocb, ret);
			return ret;
		}

		return generic_file_write_iter(iocb, from);
	}

	/* Fixed-table path: copy directly from iov_iter into pool data. */
	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	{
		int idx = tidefs_kernel_pool_find_index_by_ino(pool, inode->i_ino);
		if (idx < 0)
			return -ENOENT;
		if (!S_ISREG(pool->inode_table[idx].mode))
			return -EISDIR;

		while (iov_iter_count(from) > 0) {
			size_t chunk;
			size_t copied;

			if (pos >= TIDEFS_KERNEL_POOL_FILE_DATA_SIZE)
				break;
			if (iov_iter_count(from) == 0)
				break;

			chunk = min_t(size_t, iov_iter_count(from),
				      TIDEFS_KERNEL_POOL_FILE_DATA_SIZE -
				      (size_t)pos);
			if (chunk == 0)
				break;

			copied = copy_from_iter(
				pool->inode_table[idx].data + pos, chunk, from);
			if (copied == 0)
				break;

			pos += copied;
			total += copied;
		}

		if (total > 0) {
			pool->inode_table[idx].data_len =
				max_t(u64, pool->inode_table[idx].data_len, pos);
			i_size_write(inode, pool->inode_table[idx].data_len);
			pool->committed_txg++;

			if (tidefs_kernel_pool_persist_state(pool) != 0)
				return -EIO;
		}
	}

	iocb->ki_pos = pos;
	return total > 0 ? total : -ENOSPC;
}
static int tidefs_posix_vfs_file_fsync(struct file *file, loff_t start,
				       loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;

	/* Engine-backed path (#6642): delegate fsync to the Rust engine
	 * using the real file handle from file->private_data. */
	if (ctx && ctx->engine_backed) {
		struct tidefs_posix_vfs_open_file_state *ofs =
			file->private_data;
		int wb_ret = filemap_write_and_wait_range(
			inode->i_mapping, start, end);
		if (wb_ret < 0)
			return wb_ret;
		if (ofs && ofs->times_dirty) {
			wb_ret = tidefs_posix_vfs_engine_persist_inode_times(
				inode, TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME);
			if (wb_ret < 0)
				return wb_ret;
			ofs->times_dirty = false;
		}
		if (ofs) {
			return tidefs_posix_vfs_engine_fsync(
				ofs->fh_ino, ofs->fh_id,
				(u64)start, (u64)end, datasync);
		}
	}

	/* Bootstrap/fallback: persist C fixed-table state. */
	{
		struct tidefs_posix_vfs_kernel_pool_core *pool;
		pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
		if (IS_ERR(pool))
			return PTR_ERR(pool);
		return tidefs_kernel_pool_persist_state(pool);
	}
}

/*
 * Xattr and permission VFS callbacks (REL-KVFS-010).
 *
 * listxattr returns an empty list via the Rust bridge (KernelEngine
 * has no xattr persistence yet).  permission implements standard
 * UNIX DAC.  getxattr/setxattr/removexattr are deferred: Linux 7.0
 * uses xattr_handler arrays on the superblock, not inode_operations.
 */
static ssize_t tidefs_posix_vfs_listxattr(struct dentry *dentry, char *buffer,
					   size_t size)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	unsigned int out_len = 0;
	int ret;

	pool = tidefs_posix_vfs_pool_core_from_sb(d_inode(dentry)->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	ret = tidefs_posix_vfs_engine_listxattr(
		d_inode(dentry)->i_ino,
		(unsigned char *)buffer, (unsigned int)size,
		&out_len);
	if (ret < 0)
		return ret;
	return (ssize_t)out_len;
}

static int tidefs_posix_vfs_permission(struct mnt_idmap *idmap,
					struct inode *inode, int mask)
{
	return generic_permission(idmap, inode, mask);
}
/*
 * Xattr handler callbacks (REL-KVFS-010).
 *
 * These implement the get/set callbacks for the xattr_handler array.
 * get calls tidefs_posix_vfs_engine_getxattr; set calls
 * tidefs_posix_vfs_engine_setxattr (returns ENOSYS until intent-log
 * is wired via #6270).  Both require a valid pool.
 */
static int tidefs_posix_vfs_xattr_get(const struct xattr_handler *handler,
				       struct dentry *dentry, struct inode *inode,
				       const char *name, void *buffer, size_t size)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	char full_name[288];
	const char *query_name;
	unsigned int query_len;
	unsigned int out_len = 0;
	int plen, nlen;
	int ret;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	plen = (int)strlen(handler->prefix);
	nlen = name ? (int)strnlen(name, 255) : 0;
	if (plen + nlen >= (int)sizeof(full_name))
		return -ENAMETOOLONG;
	if (nlen) {
		memcpy(full_name, handler->prefix, plen);
		memcpy(full_name + plen, name, nlen);
		full_name[plen + nlen] = '\0';
		query_name = full_name;
		query_len = (unsigned int)(plen + nlen);
	} else {
		query_name = handler->prefix;
		query_len = (unsigned int)plen;
	}

	ret = tidefs_posix_vfs_engine_getxattr(
		inode->i_ino,
		(const unsigned char *)query_name,
		query_len,
		(unsigned char *)buffer, (unsigned int)size,
		&out_len);
	if (ret < 0)
		return ret;
	return (int)out_len;
}

static int tidefs_posix_vfs_xattr_set(const struct xattr_handler *handler,
				       struct mnt_idmap *idmap,
				       struct dentry *dentry, struct inode *inode,
				       const char *name, const void *buffer,
				       size_t size, int flags)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	char full_name[288];
	int plen, nlen;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	plen = (int)strlen(handler->prefix);
	nlen = name ? (int)strnlen(name, 255) : 0;
	if (plen + nlen >= (int)sizeof(full_name))
		return -ENAMETOOLONG;
	memcpy(full_name, handler->prefix, plen);
	if (nlen)
		memcpy(full_name + plen, name, nlen);
	full_name[plen + nlen] = '\0';

	return tidefs_posix_vfs_engine_setxattr(
		inode->i_ino,
		(const unsigned char *)full_name,
		(unsigned int)(plen + nlen),
		(const unsigned char *)buffer,
		(unsigned int)size,
		(unsigned int)flags);
}

/*
 * Xattr handler array for TideFS kernel VFS.
 *
 * One handler per supported namespace (user, trusted, security, system).
 * The handlers are registered via sb->s_xattr during fill_super.
 * listxattr is still handled by inode_operations::listxattr (above).
 */
static const struct xattr_handler tidefs_posix_vfs_xattr_user_handler = {
	.prefix = "user.",
	.name   = "user.",
	.get    = tidefs_posix_vfs_xattr_get,
	.set    = tidefs_posix_vfs_xattr_set,
};

static const struct xattr_handler tidefs_posix_vfs_xattr_trusted_handler = {
	.prefix = "trusted.",
	.name   = "trusted.",
	.get    = tidefs_posix_vfs_xattr_get,
	.set    = tidefs_posix_vfs_xattr_set,
};

static const struct xattr_handler tidefs_posix_vfs_xattr_security_handler = {
	.prefix = "security.",
	.name   = "security.",
	.get    = tidefs_posix_vfs_xattr_get,
	.set    = tidefs_posix_vfs_xattr_set,
};

static const struct xattr_handler tidefs_posix_vfs_xattr_system_handler = {
	.prefix = "system.",
	.name   = "system.",
	.get    = tidefs_posix_vfs_xattr_get,
	.set    = tidefs_posix_vfs_xattr_set,
};

static const struct xattr_handler *tidefs_posix_vfs_xattr_handlers[] = {
	&tidefs_posix_vfs_xattr_user_handler,
	&tidefs_posix_vfs_xattr_trusted_handler,
	&tidefs_posix_vfs_xattr_security_handler,
	&tidefs_posix_vfs_xattr_system_handler,
	NULL,
};

/*
 * POSIX ACL callbacks (REL-KVFS-010).
 *
 * get_acl reads the ACL xattr via the engine and decodes it with the
 * kernel's posix_acl_from_xattr.  When no ACL is stored (ENODATA),
 * returns NULL so the VFS falls back to mode bits.
 * set_acl stores or removes the ACL xattr via the engine. Access ACL updates
 * use posix_acl_update_mode so the stored ACL and inode mode stay synchronized
 * with Linux filesystem semantics.
 */
static struct posix_acl *tidefs_posix_vfs_get_acl(struct mnt_idmap *idmap,
					    struct dentry *dentry, int type)
{
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	const char *xattr_name;
	unsigned char *value_buf = NULL;
	struct posix_acl *acl = NULL;
	unsigned int out_len = 0;
	unsigned int buf_size = 4096;
	int ret;

	pool = tidefs_posix_vfs_pool_core_from_sb(d_inode(dentry)->i_sb);
	if (IS_ERR(pool))
		return ERR_CAST(pool);

	if (type == ACL_TYPE_ACCESS)
		xattr_name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		xattr_name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return ERR_PTR(-EINVAL);

	value_buf = kmalloc(buf_size, GFP_KERNEL);
	if (!value_buf)
		return ERR_PTR(-ENOMEM);

	/* Read the binary ACL xattr from the engine. */
	ret = tidefs_posix_vfs_engine_getxattr(
		d_inode(dentry)->i_ino,
		(const unsigned char *)xattr_name,
		(unsigned int)strlen(xattr_name),
		value_buf, buf_size,
		&out_len);
	if (ret == -ENODATA || ret == -ENOSYS) {
		kfree(value_buf);
		return NULL;  /* no ACL stored: fall back to mode bits */
	}
	if (ret < 0) {
		kfree(value_buf);
		return ERR_PTR(ret);
	}
	if (out_len == 0 || out_len > buf_size) {
		kfree(value_buf);
		return NULL;
	}

	/* Decode using the kernel's built-in POSIX ACL xattr parser. */
	acl = posix_acl_from_xattr(&init_user_ns, value_buf, out_len);
	kfree(value_buf);
	return acl;
}

static int tidefs_posix_vfs_set_acl(struct mnt_idmap *idmap,
				     struct dentry *dentry,
				     struct posix_acl *acl, int type)
{
	struct inode *inode = d_inode(dentry);
	struct tidefs_posix_vfs_kernel_pool_core *pool;
	struct posix_acl *acl_to_store = acl;
	struct posix_acl *cloned_acl = NULL;
	const char *xattr_name;
	umode_t mode = inode->i_mode;
	unsigned int out_mode = 0;
	unsigned int out_uid = 0;
	unsigned int out_gid = 0;
	unsigned long long out_size = 0;
	unsigned long long out_blocks = 0;
	struct timespec64 ctime;
	bool mode_changed = false;
	void *value = NULL;
	size_t size = 0;
	int ret;

	pool = tidefs_posix_vfs_pool_core_from_sb(inode->i_sb);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	if (type == ACL_TYPE_ACCESS)
		xattr_name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		xattr_name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return -EINVAL;

	if (type == ACL_TYPE_ACCESS && acl) {
		cloned_acl = posix_acl_clone(acl, GFP_KERNEL);
		if (!cloned_acl)
			return -ENOMEM;
		acl_to_store = cloned_acl;

		ret = posix_acl_update_mode(idmap, inode, &mode, &acl_to_store);
		if (ret)
			goto out_release_acl;
		mode_changed = mode != inode->i_mode;
	}

	if (!acl_to_store) {
		/* Remove the ACL xattr. */
		ret = tidefs_posix_vfs_engine_removexattr(
			inode->i_ino,
			(const unsigned char *)xattr_name,
			(unsigned int)strlen(xattr_name));
		if (ret == -ENOSYS)
			ret = -EOPNOTSUPP;
		if (ret == -ENODATA)
			ret = 0;
		if (ret)
			goto out_release_acl;
		goto sync_mode;
	}

	/* Encode the ACL into binary xattr format. */
	value = posix_acl_to_xattr(&init_user_ns, acl_to_store, &size, GFP_KERNEL);
	if (!value) {
		ret = -ENOMEM;
		goto out_release_acl;
	}

	/* Store via the engine. */
	ret = tidefs_posix_vfs_engine_setxattr(
		inode->i_ino,
		(const unsigned char *)xattr_name,
		(unsigned int)strlen(xattr_name),
		(const unsigned char *)value,
		(unsigned int)size,
		0);
	kfree(value);
	if (ret == -ENOSYS)
		ret = -EOPNOTSUPP;
	if (ret)
		goto out_release_acl;

sync_mode:
	if (mode_changed) {
		ctime = current_time(inode);
		ret = tidefs_posix_vfs_engine_setattr(
			inode->i_ino,
			0x01 | 0x80,  /* FATTR_MODE | FATTR_CTIME */
			mode,
			0, 0, 0, 0, 0,
			tidefs_posix_vfs_timespec64_to_ns(ctime),
			&out_mode, &out_uid, &out_gid, &out_size, &out_blocks);
		if (ret == -ENOSYS)
			ret = -EOPNOTSUPP;
		if (ret)
			goto out_release_acl;
		inode->i_mode = out_mode;
		inode_set_ctime_to_ts(inode, ctime);
		mark_inode_dirty(inode);
	}

	forget_cached_acl(inode, type);
	ret = 0;

out_release_acl:
	if (cloned_acl)
		posix_acl_release(cloned_acl);
	return ret;
}


/*
 * Engine-backed setattr: chmod, chown, truncate, utimes.
 *
 * Maps Linux ATTR_* flags to the Rust FATTR_* bitmask and calls
 * the MOUNTED_ENGINE.setattr() bridge.  Updates the kernel inode
 * from the returned canonical attributes.  Falls through to
 * simple_setattr for the fixed-table / bootstrap path.
 */
static int tidefs_posix_vfs_setattr(struct mnt_idmap *idmap,
				     struct dentry *dentry,
				     struct iattr *iattr)
{
	struct inode *inode = d_inode(dentry);
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;

	if (ctx && ctx->read_only)
		return -EROFS;

	/* Engine-backed path. */
	if (ctx && ctx->engine_backed) {
		unsigned int valid = 0;
		unsigned int out_mode = 0;
		unsigned int out_uid = 0;
		unsigned int out_gid = 0;
		unsigned long long out_size = 0;
		unsigned long long out_blocks = 0;
		bool size_update;
		bool invalidate_locked = false;
		loff_t old_size = 0;
		int ret;

		ret = setattr_prepare(idmap, dentry, iattr);
		if (ret)
			return ret;

		size_update = (iattr->ia_valid & ATTR_SIZE) != 0;

		/*
		 * Translate Linux ATTR_* flags to the Rust FATTR_* bitmask.
		 * FATTR_CTIME is bit 7, while Linux ATTR_CTIME is
		 * bit 6 (0x40).  Other bits are identical.
		 */
		if (iattr->ia_valid & ATTR_MODE)
			valid |= TIDEFS_POSIX_VFS_FATTR_MODE;
		if (iattr->ia_valid & ATTR_UID)
			valid |= TIDEFS_POSIX_VFS_FATTR_UID;
		if (iattr->ia_valid & ATTR_GID)
			valid |= TIDEFS_POSIX_VFS_FATTR_GID;
		if (iattr->ia_valid & ATTR_SIZE)
			valid |= TIDEFS_POSIX_VFS_FATTR_SIZE;
		if (iattr->ia_valid & ATTR_ATIME)
			valid |= TIDEFS_POSIX_VFS_FATTR_ATIME;
		if (iattr->ia_valid & ATTR_MTIME)
			valid |= TIDEFS_POSIX_VFS_FATTR_MTIME;
		if (iattr->ia_valid & ATTR_CTIME)
			valid |= TIDEFS_POSIX_VFS_FATTR_CTIME;

		if (valid == 0)
			return 0;

		if (size_update) {
			old_size = i_size_read(inode);
			if (iattr->ia_size != old_size) {
				filemap_invalidate_lock(inode->i_mapping);
				invalidate_locked = true;
				ret = tidefs_posix_vfs_prepare_truncate_pagecache(
					inode, old_size, iattr->ia_size);
				if (ret)
					goto out_invalidate_unlock;
			}
		}

		ret = tidefs_posix_vfs_engine_setattr(
			inode->i_ino,
			valid,
			iattr->ia_valid & ATTR_MODE  ? iattr->ia_mode  : 0,
			iattr->ia_valid & ATTR_UID   ? from_kuid(&init_user_ns, iattr->ia_uid)  : 0,
			iattr->ia_valid & ATTR_GID   ? from_kgid(&init_user_ns, iattr->ia_gid)  : 0,
			iattr->ia_valid & ATTR_SIZE  ? iattr->ia_size  : 0,
			iattr->ia_valid & ATTR_ATIME ? tidefs_posix_vfs_timespec64_to_ns(iattr->ia_atime) : 0,
			iattr->ia_valid & ATTR_MTIME ? tidefs_posix_vfs_timespec64_to_ns(iattr->ia_mtime) : 0,
			iattr->ia_valid & ATTR_CTIME ? tidefs_posix_vfs_timespec64_to_ns(iattr->ia_ctime) : 0,
			&out_mode, &out_uid, &out_gid, &out_size, &out_blocks);

		if (ret < 0)
			goto out_invalidate_unlock;

		/* Apply canonical attributes returned by the engine.
		 * Clear the bits we handled so simple_setattr skips them. */
		if (iattr->ia_valid & ATTR_MODE) {
			inode->i_mode = out_mode;
			iattr->ia_valid &= ~ATTR_MODE;
		}
		if (iattr->ia_valid & ATTR_UID) {
			inode->i_uid = make_kuid(&init_user_ns, out_uid);
			iattr->ia_valid &= ~ATTR_UID;
		}
		if (iattr->ia_valid & ATTR_GID) {
			inode->i_gid = make_kgid(&init_user_ns, out_gid);
			iattr->ia_valid &= ~ATTR_GID;
		}
		if (iattr->ia_valid & ATTR_SIZE) {
			truncate_setsize(inode, out_size);
			inode->i_blocks = out_blocks;
			if (size_update && out_size != old_size) {
				loff_t fence_start = min_t(loff_t, old_size, out_size);
				loff_t fence_end = max_t(loff_t, old_size, out_size);

				if (fence_end > fence_start)
					tidefs_posix_vfs_pagecache_raise_fence(
						inode, fence_start,
						(size_t)(fence_end - fence_start),
						"truncate-size");
			}
			iattr->ia_valid &= ~ATTR_SIZE;
		}

		/* Let simple_setattr handle any remaining bits (timestamps
		 * set to "now" and any bits we did not clear). */
		setattr_copy(idmap, inode, iattr);
		mark_inode_dirty(inode);
		ret = 0;
out_invalidate_unlock:
		if (invalidate_locked)
			filemap_invalidate_unlock(inode->i_mapping);
		return ret;
	}

	/* Non-engine path: delegate to simple_setattr. */
	return simple_setattr(idmap, dentry, iattr);
}

static const struct inode_operations tidefs_posix_vfs_symlink_inode_operations = {
	.getattr    = tidefs_posix_vfs_getattr,
	.listxattr  = tidefs_posix_vfs_listxattr,
	.permission = tidefs_posix_vfs_permission,
	.get_link   = tidefs_posix_vfs_get_link,
	.setattr    = tidefs_posix_vfs_setattr,
};

static int tidefs_posix_vfs_fiemap(struct inode *inode,
				   struct fiemap_extent_info *fieinfo,
				   u64 start, u64 len)
{
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct tidefs_posix_vfs_engine_fiemap_extent *extents = NULL;
	u32 mapped_extents = 0;
	u32 available_extents = 0;
	u64 map_len = len;
	u32 i;
	int ret;

	ret = fiemap_prep(inode, fieinfo, start, &map_len, 0);
	if (ret)
		return ret;

	if (fieinfo->fi_extents_max > 0) {
		extents = kcalloc(fieinfo->fi_extents_max, sizeof(*extents),
				  GFP_KERNEL);
		if (!extents)
			return -ENOMEM;
	}

	if (ctx && ctx->engine_backed) {
		ret = tidefs_posix_vfs_engine_fiemap(
			inode->i_ino, inode->i_ino, start, map_len,
			fieinfo->fi_extents_max, extents, &mapped_extents,
			&available_extents);
		if (ret < 0)
			goto out;
	} else {
		u64 size = i_size_read(inode);
		u64 end = (map_len > ~0ULL - start) ? ~0ULL : start + map_len;
		u64 logical_end;

		if (start >= size)
			goto out;
		logical_end = min_t(u64, end, size);
		available_extents = 1;
		if (fieinfo->fi_extents_max > 0) {
			extents[0].logical = start;
			extents[0].physical = start;
			extents[0].length = logical_end - start;
			extents[0].flags = FIEMAP_EXTENT_LAST |
					    FIEMAP_EXTENT_UNKNOWN |
					    FIEMAP_EXTENT_MERGED;
			mapped_extents = 1;
		}
	}

	if (fieinfo->fi_extents_max == 0) {
		fieinfo->fi_extents_mapped = available_extents;
		goto out;
	}

	for (i = 0; i < mapped_extents; i++) {
		ret = fiemap_fill_next_extent(fieinfo,
					      extents[i].logical,
					      extents[i].physical,
					      extents[i].length,
					      extents[i].flags);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			ret = 0;
			goto out;
		}
	}

out:
	kfree(extents);
	return ret;
}

static const struct inode_operations tidefs_posix_vfs_file_inode_operations = {
	.getattr    = tidefs_posix_vfs_getattr,
	.listxattr  = tidefs_posix_vfs_listxattr,
	.permission = tidefs_posix_vfs_permission,
	.get_acl    = tidefs_posix_vfs_get_acl,
	.set_acl    = tidefs_posix_vfs_set_acl,
	.link       = tidefs_posix_vfs_link,
	.setattr    = tidefs_posix_vfs_setattr,
	.fiemap     = tidefs_posix_vfs_fiemap,
};
/*
 * splice pipe-desc release callback -- puts a single page from the
 * splice_pipe_desc that was not consumed by splice_to_pipe.
 */
static void tidefs_splice_spd_release(struct splice_pipe_desc *spd,
				       unsigned int idx)
{
	put_page(spd->pages[idx]);
}

/*
 * copy_file_range delegation.
 *
 * Delegates server-side copy to the Rust engine bridge when the mount is
 * engine-backed.  Falls back to do_splice_direct (splice-based
 * kernel-generic copy) for non-engine mounts so that the syscall is never a
 * hard failure.
 */
static ssize_t tidefs_posix_vfs_file_copy_file_range(struct file *file_in,
						      loff_t pos_in,
						      struct file *file_out,
						      loff_t pos_out,
						      size_t len,
						      unsigned int flags)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	struct tidefs_posix_vfs_mount *ctx;
	ssize_t copied_ret = 0;
	u32 copied = 0;
	int ret;

	if (flags)
		return -EINVAL;
	if (pos_in < 0 || pos_out < 0)
		return -EINVAL;
	if (len == 0)
		return 0;

	ctx = inode_in->i_sb->s_fs_info;
	if (ctx && ctx->engine_backed) {
		struct tidefs_posix_vfs_open_file_state *ofs_in =
			file_in->private_data;
		struct tidefs_posix_vfs_open_file_state *ofs_out =
			file_out->private_data;
		u64 fh_ino_in  = ofs_in  ? ofs_in->fh_ino  : inode_in->i_ino;
		u64 fh_id_in   = ofs_in  ? ofs_in->fh_id   : inode_in->i_ino;
		u64 fh_ino_out = ofs_out ? ofs_out->fh_ino : inode_out->i_ino;
		u64 fh_id_out  = ofs_out ? ofs_out->fh_id  : inode_out->i_ino;
		loff_t end_pos;

		if (inode_in->i_sb != inode_out->i_sb)
			return -EXDEV;
		ret = tidefs_posix_vfs_activate_engine(ctx);
		if (ret < 0)
			return ret;

		lock_two_nondirectories(inode_in, inode_out);
		filemap_invalidate_lock_two(inode_in->i_mapping,
					    inode_out->i_mapping);
		ret = tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode_in, pos_in, len);
		if (ret)
			goto out_copy_unlock;
		ret = tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode_out, pos_out, len);
		if (ret)
			goto out_copy_unlock;
		ret = tidefs_posix_vfs_engine_copy_file_range(
			fh_ino_in, fh_id_in, (u64)pos_in,
			fh_ino_out, fh_id_out, (u64)pos_out,
			(u64)len, &copied);
		if (ret < 0)
			goto out_copy_unlock;
		if ((u64)copied > (u64)len) {
			ret = -EIO;
			goto out_copy_unlock;
		}
		if (copied == 0) {
			ret = 0;
			goto out_copy_unlock;
		}
		if (pos_out > LLONG_MAX - (loff_t)copied) {
			ret = -EFBIG;
			goto out_copy_unlock;
		}
		tidefs_posix_vfs_pagecache_raise_fence(
			inode_out, pos_out, copied, "copy-file-range-dest");
		end_pos = pos_out + (loff_t)copied;
		if (end_pos > i_size_read(inode_out))
			i_size_write(inode_out, end_pos);
		inode_set_mtime_to_ts(inode_out,
				      inode_set_ctime_current(inode_out));
		mark_inode_dirty(inode_out);
		if (ofs_out)
			ofs_out->times_dirty = true;
		else
			tidefs_posix_vfs_persist_inode_times_best_effort(
				inode_out, TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME);
		ret = tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode_out, pos_out, copied);
		if (ret)
			mapping_set_error(inode_out->i_mapping, ret);
		copied_ret = (ssize_t)copied;
out_copy_unlock:
		filemap_invalidate_unlock_two(inode_in->i_mapping,
					      inode_out->i_mapping);
		unlock_two_nondirectories(inode_in, inode_out);
		return copied_ret ? copied_ret : ret;
	}

	/* Engine not mounted: use kernel-generic splice-based copy. */
	return do_splice_direct(file_in, &pos_in, file_out, &pos_out,
				len, flags);
}

/*
 * splice_read -- splice data from a TideFS file into a pipe.
 *
 * Allocates up to 16 pages, reads file data into them through the same
 * fixed-table/engine-backed read helper used by .read, and pipes the
 * populated pages into the pipe via splice_to_pipe.
 */
static ssize_t tidefs_posix_vfs_file_splice_read(struct file *in, loff_t *ppos,
						  struct pipe_inode_info *pipe,
						  size_t len,
						  unsigned int flags)
{
	struct inode *inode_in = file_inode(in);
	struct tidefs_posix_vfs_mount *ctx = inode_in->i_sb->s_fs_info;
	struct tidefs_posix_vfs_open_file_state *ofs = in->private_data;
	struct page *pages[16];
	struct partial_page partial[16];
	struct splice_pipe_desc spd = {
		.pages        = pages,
		.partial      = partial,
		.nr_pages_max = 16,
		.nr_pages     = 0,
		.ops          = &nosteal_pipe_buf_ops,
		.spd_release  = tidefs_splice_spd_release,
	};
	ssize_t total = 0;
	unsigned int max_pages;
	int allocated_pages;
	int used_pages = 0;
	int i;

	if (!len)
		return 0;

	max_pages = pipe->max_usage - pipe_buf_usage(pipe);
	if (max_pages == 0)
		return -EAGAIN;
	max_pages = min_t(unsigned int, max_pages, 16);
	len = min_t(size_t, len, (size_t)max_pages * PAGE_SIZE);

	for (i = 0; i < (int)max_pages; i++) {
		pages[i] = alloc_page(GFP_USER);
		if (!pages[i])
			break;
	}
	spd.nr_pages = i;
	if (spd.nr_pages == 0)
		return -ENOMEM;
	allocated_pages = spd.nr_pages;

	for (i = 0; i < allocated_pages && (size_t)total < len; i++) {
		void *kaddr = kmap(pages[i]);
		size_t chunk = min_t(size_t, PAGE_SIZE, len - (size_t)total);
		ssize_t rd;

		/* Engine-backed path (#6642): read through the engine
		 * using the real file handle from file->private_data. */
		if (ctx && ctx->engine_backed && ofs) {
			int ret = tidefs_posix_vfs_engine_read(
				ofs->fh_ino, ofs->fh_id,
				(u64)*ppos, (unsigned char *)kaddr,
				(u32)chunk);
			rd = (ssize_t)ret;
		} else {
			rd = tidefs_posix_vfs_file_read_into(in, kaddr,
							     chunk, ppos,
							     false);
		}
		kunmap(pages[i]);
		if (rd < 0) {
			if (total == 0)
				total = rd;
			break;
		}
		if (rd == 0)
			break;
		partial[used_pages].offset = 0;
		partial[used_pages].len    = (unsigned int)rd;
		used_pages++;
		total += rd;
		if (ctx && ctx->engine_backed && ofs)
			*ppos += rd;
	}

	while (i < allocated_pages)
		put_page(pages[i++]);
	spd.nr_pages = used_pages;

	if (spd.nr_pages > 0 && total > 0) {
		ssize_t piped;

		piped = splice_to_pipe(pipe, &spd);
		if (piped > 0)
			return piped;
		if (piped < 0)
			total = piped;
	}
	return total;
}

/*
 * splice_write actor -- writes each pipe buffer to the file via
 * kernel_write (-> .write).  Called by __splice_from_pipe for each
 * populated pipe buffer.
 */
static int tidefs_splice_write_actor(struct pipe_inode_info *pipe,
				      struct pipe_buffer *buf,
				      struct splice_desc *sd)
{
	void *kaddr;
	ssize_t written;

	(void)pipe;

	kaddr = kmap(buf->page);
	written = kernel_write(sd->u.file,
			       (const char *)kaddr + buf->offset,
			       buf->len,
			       &sd->pos);
	kunmap(buf->page);

	if (written < 0)
		return (int)written;
	if ((size_t)written != buf->len)
		return -EIO;
	return (int)written;
}

/*
 * splice_write -- splice data from a pipe into a TideFS file.
 *
 * Locks the pipe, calls __splice_from_pipe with the actor above, unlocks,
 * and updates the file position.  Extent allocation, hole semantics, and
 * committed-root consistency are preserved because the actor delegates to
 * kernel_write (-> .write -> engine.write).
 */
static ssize_t tidefs_posix_vfs_file_splice_write(struct pipe_inode_info *pipe,
						   struct file *out,
						   loff_t *ppos,
						   size_t len,
						   unsigned int flags)
{
	struct splice_desc sd = {
		.total_len = len,
		.flags     = flags,
		.u.file    = out,
		.pos       = *ppos,
	};
	ssize_t ret;

	pipe_lock(pipe);
	ret = __splice_from_pipe(pipe, &sd, tidefs_splice_write_actor);
	pipe_unlock(pipe);

	if (ret >= 0)
		*ppos = sd.pos;
	return ret;
}


/*
 * Lease/delegation refusal contract: TideFS does not
 * support kernel file leases or delegations.  Return -EOPNOTSUPP on
 * every fcntl(F_SETLEASE/F_GETLEASE) so callers get a clear and
 * consistent refusal instead of the kernel default -EINVAL.
 */
static int tidefs_posix_vfs_setlease_nosupport(
	struct file *file, int arg, struct file_lease **lease, void **priv)
{
	(void)file;
	(void)arg;
	(void)lease;
	(void)priv;
	return -EOPNOTSUPP;
}

/*
 * Reflink/remap refusal contract (KTFS-REMAP-001): TideFS does not yet
 * support reflink (FICLONE/FICLONERANGE).  Return -EOPNOTSUPP on every
 * remap_file_range call so callers get a clear and consistent refusal
 * instead of -EINVAL from a missing callback.
 */
static loff_t tidefs_posix_vfs_remap_file_range_nosupport(
	struct file *file_in, loff_t pos_in,
	struct file *file_out, loff_t pos_out,
	loff_t len, unsigned int remap_flags)
{
	(void)file_in;
	(void)pos_in;
	(void)file_out;
	(void)pos_out;
	(void)len;
	(void)remap_flags;
	return -EOPNOTSUPP;
}

/*
 * mmap admission through the generic filemap VM operations.  The mounted
 * engine supplies read_folio/write_begin/write_end address-space callbacks,
 * so page faults and shared writable mappings still resolve through the same
 * kernel-resident VfsEngine read/write path as ordinary buffered I/O.
 *
 * This C shim does not install the Rust KmodVfsVmOps model as vma->vm_ops;
 * unsupported runtime rows for that custom bridge must stay explicit until a
 * real vm_operations_struct registration exists.
 */
static int tidefs_posix_vfs_file_mmap(
	struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct timespec64 old_atime = inode_get_atime(inode);
	int ret;

	/*
	 * Only the engine-backed mounted pool has a writeback authority for
	 * mmap dirties.  Bootstrap/fixed-table files fail closed instead of
	 * admitting a mapping whose dirty folios would have no durable sink.
	 */
	if (!ctx || !ctx->engine_backed)
		return -EOPNOTSUPP;

	ret = generic_file_mmap(file, vma);
	if (ret == 0) {
		struct timespec64 new_atime = inode_get_atime(inode);

		if (!timespec64_equal(&old_atime, &new_atime))
			tidefs_posix_vfs_persist_inode_times_best_effort(
				inode, TIDEFS_POSIX_VFS_FATTR_ATIME);
	}
	return ret;
}

/*
 * Engine-backed llseek with SEEK_DATA/SEEK_HOLE extent resolution (#6644).
 *
 * SEEK_SET/CUR/END delegate to generic_file_llseek for inode-based
 * bounds checking.
 * SEEK_DATA/SEEK_HOLE route through the engine llseek bridge when
 * engine-backed, calling VfsEngine::data_ranges() for real extent
 * resolution. Falls back to dense-file behavior (data from offset
 * through EOF, hole only past EOF) when the engine path is unavailable.
 */
static loff_t tidefs_posix_vfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);

	if (whence == SEEK_SET || whence == SEEK_CUR || whence == SEEK_END)
		return generic_file_llseek(file, offset, whence);
	if (whence != SEEK_DATA && whence != SEEK_HOLE)
		return -EINVAL;

	{
		struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;

		if (ctx && ctx->engine_backed) {
			struct tidefs_posix_vfs_open_file_state *ofs =
				file->private_data;

			if (ofs && ofs->engine_backed) {
				s64 result;

				result = (s64)tidefs_posix_vfs_engine_llseek(
					ofs->fh_ino, ofs->fh_id,
					(s64)offset, (u32)whence,
					(s64)file->f_pos);
				return (loff_t)result;
			}
		}
	}

	/* Dense-file fallback when engine bridge is unavailable. */
	if (whence == SEEK_DATA) {
		if (offset >= (loff_t)i_size_read(inode))
			return -ENXIO;
		return offset;
	}
	/* SEEK_HOLE: return i_size (hole at EOF) */
	return i_size_read(inode);
}

#define TIDEFS_POSIX_TFS_FALLOC_SUPPORTED \
	(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | \
	 FALLOC_FL_ZERO_RANGE | FALLOC_FL_COLLAPSE_RANGE | \
	 FALLOC_FL_INSERT_RANGE)

static int tidefs_posix_vfs_validate_fallocate_mode(int mode)
{
	int op_count = 0;

	if (mode & ~TIDEFS_POSIX_TFS_FALLOC_SUPPORTED)
		return -EOPNOTSUPP;
	if (mode & FALLOC_FL_PUNCH_HOLE)
		op_count++;
	if (mode & FALLOC_FL_ZERO_RANGE)
		op_count++;
	if (mode & FALLOC_FL_COLLAPSE_RANGE)
		op_count++;
	if (mode & FALLOC_FL_INSERT_RANGE)
		op_count++;
	if (op_count > 1)
		return -EOPNOTSUPP;
	if ((mode & FALLOC_FL_PUNCH_HOLE) &&
	    !(mode & FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;
	if ((mode & FALLOC_FL_COLLAPSE_RANGE) &&
	    (mode & FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;
	if ((mode & FALLOC_FL_INSERT_RANGE) &&
	    (mode & FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;
	return 0;
}

static int tidefs_posix_vfs_prepare_fallocate_pagecache(struct inode *inode,
							int mode,
							loff_t offset,
							loff_t len,
							loff_t old_size)
{
	loff_t range_end = offset + len;

	if (old_size < 0)
		return 0;
	if (offset >= old_size) {
		loff_t eof_page;

		if (old_size == 0)
			return 0;

		eof_page = round_down(old_size - 1, PAGE_SIZE);
		if (round_down(offset, PAGE_SIZE) != eof_page)
			return 0;

		/*
		 * Review debt TFR-018: an extending fallocate can start past EOF
		 * while still sharing the dirty EOF folio from a prior buffered
		 * write. Flush it before the size extension so the final
		 * invalidation does not fail with -EBUSY.
		 */
		return tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode, eof_page, old_size - eof_page);
	}

	if (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE))
		return tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode, offset, old_size - offset);

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE))
		return tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode, offset, min_t(loff_t, len, old_size - offset));

	if (range_end > offset)
		return tidefs_posix_vfs_flush_invalidate_pagecache_range(
			inode, offset, min_t(loff_t, len, old_size - offset));

	return 0;
}

static int tidefs_posix_vfs_finish_fallocate_pagecache(struct inode *inode,
						       int mode,
						       loff_t offset,
						       loff_t len,
						       loff_t old_size,
						       loff_t new_size)
{
	loff_t end;

	if (old_size < 0 || new_size < 0)
		return 0;

	if (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)) {
		end = max(old_size, new_size);
		if (offset >= end)
			return 0;
		return tidefs_posix_vfs_invalidate_pagecache_range(
			inode, offset, end - offset);
	}

	end = max(old_size, new_size);
	if (offset >= end)
		return 0;
	return tidefs_posix_vfs_invalidate_pagecache_range(
		inode, offset, min_t(loff_t, len, end - offset));
}

/*
 * Engine-backed fallocate for space reservation, hole punch, zero range, and
 * collapse/insert range.
 */
static long tidefs_posix_vfs_file_fallocate(struct file *file, int mode,
					    loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	loff_t old_size;
	int ret;

	if (offset < 0 || len <= 0)
		return -EINVAL;
	if (offset > LLONG_MAX - len)
		return -EFBIG;
	if (!ctx || !ctx->engine_backed)
		return -EOPNOTSUPP;
	ret = tidefs_posix_vfs_validate_fallocate_mode(mode);
	if (ret)
		return ret;
	inode_lock(inode);
	{
		struct tidefs_posix_vfs_open_file_state *ofs =
			file->private_data;
		struct timespec64 mutation_time;
		s64 mutation_time_ns;
		u64 out_size = 0;
		u64 out_blocks = 0;

		filemap_invalidate_lock(inode->i_mapping);
		old_size = i_size_read(inode);
		if ((mode & FALLOC_FL_COLLAPSE_RANGE) &&
		    offset + len >= old_size) {
			ret = -EINVAL;
			goto out_invalidate_unlock;
		}
		if ((mode & FALLOC_FL_INSERT_RANGE) && offset >= old_size) {
			ret = -EINVAL;
			goto out_invalidate_unlock;
		}
		if ((mode & FALLOC_FL_INSERT_RANGE) &&
		    old_size > inode->i_sb->s_maxbytes - len) {
			ret = -EFBIG;
			goto out_invalidate_unlock;
		}
		ret = tidefs_posix_vfs_prepare_fallocate_pagecache(
			inode, mode, offset, len, old_size);
		if (ret)
			goto out_invalidate_unlock;

		mutation_time = current_time(inode);
		mutation_time_ns =
			tidefs_posix_vfs_timespec64_to_ns(mutation_time);
		ret = tidefs_posix_vfs_engine_fallocate(
			ofs ? ofs->fh_ino : inode->i_ino,
			ofs ? ofs->fh_id : inode->i_ino,
			(u32)mode, (u64)offset, (u64)len,
			mutation_time_ns, mutation_time_ns,
			&out_size, &out_blocks);
		if (ret < 0)
			goto out_invalidate_unlock;

		if (out_size < old_size)
			truncate_setsize(inode, out_size);
		else
			i_size_write(inode, out_size);
		inode->i_blocks = out_blocks;
		inode_set_ctime_to_ts(inode, mutation_time);
		inode_set_mtime_to_ts(inode, mutation_time);
		mark_inode_dirty(inode);
		ret = tidefs_posix_vfs_finish_fallocate_pagecache(
			inode, mode, offset, len, old_size, out_size);
		if (ret)
			mapping_set_error(inode->i_mapping, ret);
out_invalidate_unlock:
		filemap_invalidate_unlock(inode->i_mapping);
		inode_unlock(inode);
		return ret;
	}
}

static const struct file_operations tidefs_posix_vfs_file_operations = {
	.open = tidefs_posix_vfs_file_open,
	.release = tidefs_posix_vfs_file_release,
	.read_iter = tidefs_posix_vfs_file_read_iter,
	.write_iter = tidefs_posix_vfs_file_write_iter,
	.fsync = tidefs_posix_vfs_file_fsync,
	.fallocate = tidefs_posix_vfs_file_fallocate,
	.llseek = tidefs_posix_vfs_file_llseek,
	.copy_file_range = tidefs_posix_vfs_file_copy_file_range,
	.splice_read    = tidefs_posix_vfs_file_splice_read,
	.splice_write   = tidefs_posix_vfs_file_splice_write,
	.remap_file_range = tidefs_posix_vfs_remap_file_range_nosupport,
	.mmap    = tidefs_posix_vfs_file_mmap,
	.setlease = tidefs_posix_vfs_setlease_nosupport,
};
/*
 * Dentry operations for dcache coherency.
 *
 * d_revalidate: checks positive and negative dentries against the live
 * engine namespace.
 * fsstress can keep paths to unlinked directories and concurrent symlink
 * targets; stale positive dentries must be invalidated before VFS calls a
 * non-directory inode operation table as a directory.
 *
 * d_delete: returns 0 to let the VFS drop the dentry; tracks deletion
 * count for lifecycle validation.
 *
 * d_release: no-op cleanup tracking dentry free events for lifecycle
 * validation.
 *
 * d_iput: calls the standard iput() and tracks the call plus orphan
 * (nlink==0) counts for open-unlink lifecycle validation.
 */
static int tidefs_posix_vfs_d_revalidate(struct inode *dir,
					 const struct qstr *name, struct dentry *dentry,
					 unsigned int flags)
{
	struct tidefs_posix_vfs_mount *ctx;
	struct tidefs_posix_vfs_engine_attr_out ea;
	struct inode *inode;
	int ret;

	if (flags & LOOKUP_RCU)
		return -ECHILD;
	if (!dentry || !dentry->d_sb)
		return 0;
	if (dentry == dentry->d_sb->s_root)
		return 1;

	ctx = dentry->d_sb->s_fs_info;
	if (!ctx || !ctx->engine_backed)
		return 1;

	inode = d_inode(dentry);
	if (inode && inode->i_nlink == 0)
		return 0;
	/*
	 * TFR-018: a negative dentry is valid only while the live engine still
	 * reports ENOENT.  If the name now resolves, invalidate it and let VFS
	 * retry through ->lookup() so the dcache attaches a positive inode.
	 */
	if (!dir || dir->i_nlink == 0)
		return 0;
	if (!name)
		name = &dentry->d_name;
	if (!name->name || name->len == 0)
		return 0;

	memset(&ea, 0, sizeof(ea));
	ret = tidefs_posix_vfs_engine_lookup(dir->i_ino, name->name, name->len, &ea);
	if (ret == -ENOENT)
		return inode ? 0 : 1;
	if (ret < 0 || ea.ino == 0)
		return 0;
	if (!inode)
		return 0;
	if (ea.ino != inode->i_ino)
		return 0;
	if ((ea.mode & S_IFMT) != (inode->i_mode & S_IFMT))
		return 0;
	return 1;
}

static int tidefs_posix_vfs_d_delete(const struct dentry *dentry)
{
	struct tidefs_posix_vfs_mount *ctx;

	ctx = dentry->d_sb ? dentry->d_sb->s_fs_info : NULL;
	if (ctx)
		ctx->dentry_delete_calls++;
	pr_debug("tidefs_posix_vfs: d_delete ino=%lu name=%.*s count=%u\n",
		 dentry->d_inode ? dentry->d_inode->i_ino : 0,
		 dentry->d_name.len, dentry->d_name.name,
		 ctx ? ctx->dentry_delete_calls : 0);
	/* Return 0: let the VFS drop the dentry via d_drop. */
	return 0;
}

static void tidefs_posix_vfs_d_release(struct dentry *dentry)
{
	struct tidefs_posix_vfs_mount *ctx;

	ctx = dentry->d_sb ? dentry->d_sb->s_fs_info : NULL;
	if (ctx)
		ctx->dentry_release_calls++;
	pr_debug("tidefs_posix_vfs: d_release ino=%lu name=%.*s count=%u\n",
		 dentry->d_inode ? dentry->d_inode->i_ino : 0,
		 dentry->d_name.len, dentry->d_name.name,
		 ctx ? ctx->dentry_release_calls : 0);
}

static void tidefs_posix_vfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct tidefs_posix_vfs_mount *ctx;

	ctx = dentry->d_sb ? dentry->d_sb->s_fs_info : NULL;
	if (ctx) {
		ctx->dentry_iput_calls++;
		if (inode->i_nlink == 0)
			ctx->dentry_iput_orphan_calls++;
	}
	pr_debug("tidefs_posix_vfs: d_iput ino=%lu nlink=%u name=%.*s iput_total=%u orphan=%u\n",
		 inode->i_ino, inode->i_nlink,
		 dentry->d_name.len, dentry->d_name.name,
		 ctx ? ctx->dentry_iput_calls : 0,
		 ctx ? ctx->dentry_iput_orphan_calls : 0);
	iput(inode);
}

static const struct dentry_operations tidefs_posix_vfs_dentry_ops = {
	.d_revalidate = tidefs_posix_vfs_d_revalidate,
	.d_delete     = tidefs_posix_vfs_d_delete,
	.d_release    = tidefs_posix_vfs_d_release,
	.d_iput       = tidefs_posix_vfs_d_iput,
};


static const struct inode_operations tidefs_posix_vfs_dir_inode_operations = {
	.getattr    = tidefs_posix_vfs_getattr,
	.listxattr  = tidefs_posix_vfs_listxattr,
	.permission = tidefs_posix_vfs_permission,
	.get_acl    = tidefs_posix_vfs_get_acl,
	.set_acl    = tidefs_posix_vfs_set_acl,
	.lookup     = tidefs_posix_vfs_lookup,
	.create = tidefs_posix_vfs_create,
	.mkdir = tidefs_posix_vfs_mkdir,
	.unlink = tidefs_posix_vfs_unlink,
	.rmdir = tidefs_posix_vfs_rmdir,
	.rename = tidefs_posix_vfs_rename,
	.symlink = tidefs_posix_vfs_symlink,
	.link = tidefs_posix_vfs_link,
	.mknod = tidefs_posix_vfs_mknod,
	.tmpfile    = tidefs_posix_vfs_tmpfile,
	.setattr    = tidefs_posix_vfs_setattr,
};

static const struct file_operations tidefs_posix_vfs_dir_file_operations = {
	.open = tidefs_posix_vfs_dir_open,
	.release = tidefs_posix_vfs_dir_release,
	.iterate_shared = tidefs_posix_vfs_iterate_shared,
	.fsync = tidefs_posix_vfs_dir_fsync,
	.llseek = generic_file_llseek,
	.setlease = tidefs_posix_vfs_setlease_nosupport,
};

static char tidefs_posix_vfs_write_begin_zeroed;

/*
 * write_begin -- address_space_operations callback for buffered-write prepare.
 *
 * Called when the kernel page cache prepares a folio for a buffered write.
 * Reads the existing data from VfsEngine::read() into the folio so the
 * kernel can merge the incoming write with existing page contents for
 * partial-page or unaligned writes.
 *
 * This callback allocates and locks the target folio, fills it with current
 * engine data (or zeros for holes), and sets *fsdata to NULL because no
 * per-write filesystem state is needed.
 *
 * No userspace daemon required: VfsEngine::read resolves within kernel
 * authority.
 */
static int tidefs_posix_vfs_write_begin(const struct kiocb *iocb,
		struct address_space *mapping, loff_t pos, unsigned len,
		struct folio **foliop, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct tidefs_posix_vfs_open_file_state *ofs;
	struct file *file = iocb ? iocb->ki_filp : NULL;
	struct folio *folio;
	void *kbuf;
	loff_t folio_file_pos;
	loff_t folio_end;
	loff_t isize;
	loff_t visible_end;
	loff_t write_end;
	size_t fsize;
	size_t read_len;
	int ret;
	u64 fh_ino, fh_id;
	u64 fence_generation;

	if (!ctx)
		return -EIO;

	ctx->write_begin_calls++;

	if (pos < 0 || len == 0) {
		*fsdata = NULL;
		return -EINVAL;
	}

	folio = __filemap_get_folio(mapping, pos >> PAGE_SHIFT,
				    FGP_WRITEBEGIN, mapping_gfp_mask(mapping));
	if (IS_ERR(folio)) {
		*fsdata = NULL;
		return PTR_ERR(folio);
	}

	ofs = file ? file->private_data : NULL;
	fh_ino = ofs ? ofs->fh_ino : inode->i_ino;
	fh_id = ofs ? ofs->fh_id : inode->i_ino;
	folio_file_pos = folio_pos(folio);
	fsize = folio_size(folio);

	if (folio_test_uptodate(folio)) {
		if (!tidefs_posix_vfs_pagecache_fence_snapshot(
			    inode, folio_file_pos, fsize)) {
			*foliop = folio;
			*fsdata = NULL;
			return 0;
		}
		folio_clear_uptodate(folio);
	}

	isize = i_size_read(inode);
	if ((loff_t)len > LLONG_MAX - pos) {
		folio_unlock(folio);
		folio_put(folio);
		*fsdata = NULL;
		return -EFBIG;
	}
	write_end = pos + (loff_t)len;
	if (folio_file_pos >= isize) {
		folio_zero_range(folio, 0, fsize);
		folio_mark_uptodate(folio);
		*foliop = folio;
		*fsdata = NULL;
		return 0;
	}

	if ((loff_t)fsize > LLONG_MAX - folio_file_pos)
		folio_end = LLONG_MAX;
	else
		folio_end = folio_file_pos + (loff_t)fsize;
	visible_end = min_t(loff_t, folio_end, isize);
	if (ctx->engine_backed && pos == folio_file_pos &&
	    write_end >= visible_end) {
		folio_zero_range(folio, 0, fsize);
		folio_mark_uptodate(folio);
		*foliop = folio;
		*fsdata = &tidefs_posix_vfs_write_begin_zeroed;
		return 0;
	}

	read_len = min_t(loff_t, (loff_t)fsize, isize - folio_file_pos);
	fence_generation = tidefs_posix_vfs_pagecache_fence_snapshot(
		inode, folio_file_pos, read_len);
	kbuf = kmalloc(read_len, GFP_KERNEL);
	if (!kbuf) {
		folio_unlock(folio);
		folio_put(folio);
		*fsdata = NULL;
		return -ENOMEM;
	}

	memset(kbuf, 0, read_len);

	ret = tidefs_posix_vfs_engine_read(
		fh_ino, fh_id, (u64)folio_file_pos, kbuf, (u32)read_len);
	if (ret < 0) {
		kfree(kbuf);
		folio_unlock(folio);
		folio_put(folio);
		*fsdata = NULL;
		return ret;
	}

	if (!tidefs_posix_vfs_pagecache_fence_still_current(
		    inode, folio_file_pos, read_len, fence_generation)) {
		kfree(kbuf);
		folio_clear_uptodate(folio);
		folio_unlock(folio);
		folio_put(folio);
		*fsdata = NULL;
		return -EAGAIN;
	}

	if (ret > 0 || fsize > 0) {
		void *addr = kmap_local_folio(folio, 0);
		size_t copy_len = min_t(size_t, (size_t)ret, read_len);

		if (copy_len > 0)
			memcpy(addr, kbuf, copy_len);
		kunmap_local(addr);
		if (copy_len < fsize)
			folio_zero_range(folio, copy_len, fsize - copy_len);
	}
	folio_mark_uptodate(folio);

	kfree(kbuf);
	*foliop = folio;
	*fsdata = NULL;
	return 0;
}

/*
 * write_end -- address_space_operations callback for buffered-write commit.
 *
 * Called after the kernel has written data into a folio prepared by
 * write_begin.  Commits ordinary buffered writes to the engine immediately so
 * close/remount durability does not depend on a later superblock-wide
 * writeback pass, while mmap dirties still flow through dirty_folio/writepages.
 *
 * The kernel passes `copied` bytes actually written; this may be less
 * than `len` for partial writes.  Only `copied` bytes are committed.
 *
 * No userspace daemon required.
 *
 * Returns the number of bytes committed (should be `copied` on success).
 */
static int tidefs_posix_vfs_write_end(const struct kiocb *iocb,
		struct address_space *mapping, loff_t pos, unsigned len,
		unsigned copied, struct folio *folio, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct tidefs_posix_vfs_open_file_state *ofs;
	struct file *file = iocb ? iocb->ki_filp : NULL;
	void *kbuf = NULL;
	size_t folio_off;
	int ret;
	bool i_size_changed = false;
	bool engine_backed = false;
	bool zeroed_existing_folio;
	loff_t old_size;
	loff_t last_pos;
	u64 fh_ino;
	u64 fh_id;

	zeroed_existing_folio =
		fsdata == &tidefs_posix_vfs_write_begin_zeroed;

	if (!ctx) {
		folio_unlock(folio);
		folio_put(folio);
		return -EIO;
	}

	ctx->write_end_calls++;

	if (copied == 0) {
		if (zeroed_existing_folio)
			folio_clear_uptodate(folio);
		folio_unlock(folio);
		folio_put(folio);
		return 0;
	}
	folio_off = offset_in_folio(folio, pos);
	if (folio_off + copied > folio_size(folio)) {
		if (zeroed_existing_folio)
			folio_clear_uptodate(folio);
		folio_unlock(folio);
		folio_put(folio);
		return -EIO;
	}
	if (pos > LLONG_MAX - (loff_t)copied) {
		mapping_set_error(mapping, -EFBIG);
		if (zeroed_existing_folio)
			folio_clear_uptodate(folio);
		folio_unlock(folio);
		folio_put(folio);
		return -EFBIG;
	}

	ofs = file ? file->private_data : NULL;
	engine_backed = ctx->engine_backed;
	fh_ino = (ofs && ofs->engine_backed) ? ofs->fh_ino : inode->i_ino;
	fh_id = (ofs && ofs->engine_backed) ? ofs->fh_id : inode->i_ino;

	if (engine_backed) {
		kbuf = kmalloc(copied, GFP_KERNEL);
		if (!kbuf) {
			mapping_set_error(mapping, -ENOMEM);
			if (zeroed_existing_folio)
				folio_clear_uptodate(folio);
			folio_unlock(folio);
			folio_put(folio);
			return -ENOMEM;
		}

		{
			void *addr = kmap_local_folio(folio, 0);
			memcpy(kbuf, (char *)addr + folio_off, copied);
			kunmap_local(addr);
		}

		ret = tidefs_posix_vfs_engine_write(
			fh_ino, fh_id, (u64)pos, kbuf, (u32)copied);
		kfree(kbuf);
		kbuf = NULL;

		if (ret < 0) {
			mapping_set_error(mapping, ret);
			if (zeroed_existing_folio)
				folio_clear_uptodate(folio);
			folio_unlock(folio);
			folio_put(folio);
			return ret;
		}
		if ((unsigned int)ret != copied) {
			mapping_set_error(mapping, -EIO);
			if (zeroed_existing_folio)
				folio_clear_uptodate(folio);
			folio_unlock(folio);
			folio_put(folio);
			return -EIO;
		}
	}

	old_size = i_size_read(inode);
	last_pos = pos + copied;
	if (last_pos > old_size) {
		i_size_write(inode, last_pos);
		i_size_changed = true;
	}
	if (zeroed_existing_folio && copied < len)
		folio_clear_uptodate(folio);
	else
		folio_mark_uptodate(folio);
	if (!engine_backed)
		folio_mark_dirty(folio);
	folio_unlock(folio);
	folio_put(folio);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);

	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	if (engine_backed && ofs && ofs->engine_backed)
		ofs->times_dirty = true;
	if (i_size_changed || !engine_backed)
		mark_inode_dirty(inode);
	if (!engine_backed)
		tidefs_posix_vfs_persist_inode_times_best_effort(
			inode, TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME);

	return copied;
}

/*
 * dirty_folio -- address_space_operations callback for dirty-folio notification.
 *
 * Called by the kernel page-cache layer when a folio is marked dirty
 * (e.g., via mmap page_mkwrite, set_page_dirty, or buffered writes).
 * Registers the dirty event with the generic filemap so writeback can later
 * discover the folio through PAGECACHE_TAG_DIRTY, then increments the
 * lifecycle counter.
 *
 * Returns true only when this call dirtied the folio.
 *
 * No userspace daemon required.
 */
static bool tidefs_posix_vfs_dirty_folio(struct address_space *mapping,
		struct folio *folio)
{
	struct inode *inode = mapping->host;
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	bool dirtied;

	if (ctx)
		ctx->dirty_folio_calls++;
	dirtied = filemap_dirty_folio(mapping, folio);
	/* Do not call into the engine here: dirty_folio can run from atomic
	 * MM paths, and the engine bridge may sleep on its mutex or block I/O. */

	return dirtied;
}


/*
 * writepages -- address_space_operations callback for dirty-page writeback.
 *
 * Drains Linux page-cache dirty folios into the Rust engine.  This is the
 * mmap/writeback counterpart to write_end(): page_mkwrite dirties the folio,
 * writeback_iter prepares it for I/O, and this callback copies the folio bytes
 * into VfsEngine::write so later reads and fsync/syncfs observe the data.
 *
 * No userspace daemon required.
 */
static int tidefs_posix_vfs_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct TidefsEngineOpenOut write_handle = { 0 };
	u64 fh_ino = inode->i_ino;
	u64 fh_id = inode->i_ino;
	struct folio *folio = NULL;
	int error = 0;
	bool close_write_handle = false;
	bool wrote_any = false;

	if (ctx)
		ctx->writepages_calls++;
	if (!ctx || !ctx->engine_backed)
		return 0;

	error = tidefs_posix_vfs_engine_open(inode->i_ino, O_WRONLY,
					     &write_handle);
	if (error < 0)
		return error;
	if (!write_handle.ok)
		return -EIO;
	fh_ino = write_handle.fh_ino;
	fh_id = write_handle.fh_id;
	close_write_handle = true;

	while ((folio = writeback_iter(mapping, wbc, folio, &error))) {
		loff_t pos = folio_pos(folio);
		loff_t isize = i_size_read(inode);
		size_t len;
		void *kbuf;
		void *addr;
		u64 fence_generation;
		int ret;

		if (pos < 0 || pos >= isize) {
			folio_unlock(folio);
			continue;
		}

		len = min_t(loff_t, (loff_t)folio_size(folio), isize - pos);
		if (len == 0) {
			folio_unlock(folio);
			continue;
		}
		fence_generation = tidefs_posix_vfs_pagecache_fence_snapshot(
			inode, pos, len);

		kbuf = kmalloc(len, GFP_NOFS);
		if (!kbuf) {
			folio_redirty_for_writepage(wbc, folio);
			folio_unlock(folio);
			error = -ENOMEM;
			continue;
		}

		addr = kmap_local_folio(folio, 0);
		memcpy(kbuf, addr, len);
		kunmap_local(addr);

		ret = tidefs_posix_vfs_engine_write(
			fh_ino, fh_id, (u64)pos,
			(const unsigned char *)kbuf, (u32)len);
		kfree(kbuf);

		if (ret < 0) {
			pr_err("tidefs_posix_vfs: writepages engine_write failed ino=%lu pos=%lld len=%zu ret=%d\n",
			       inode->i_ino, pos, len, ret);
			mapping_set_error(mapping, ret);
			folio_redirty_for_writepage(wbc, folio);
			error = ret;
		} else if ((size_t)ret != len) {
			pr_err("tidefs_posix_vfs: writepages short engine_write ino=%lu pos=%lld len=%zu ret=%d\n",
			       inode->i_ino, pos, len, ret);
			mapping_set_error(mapping, -EIO);
			folio_redirty_for_writepage(wbc, folio);
			error = -EIO;
		} else {
			wrote_any = true;
		}

		if (ret >= 0 &&
		    !tidefs_posix_vfs_pagecache_fence_still_current(
			    inode, pos, len, fence_generation)) {
			pr_err("tidefs_posix_vfs: writepages stale generation ino=%lu pos=%lld len=%zu\n",
			       inode->i_ino, pos, len);
			mapping_set_error(mapping, -EIO);
			folio_redirty_for_writepage(wbc, folio);
			error = -EIO;
		}

		folio_unlock(folio);
	}

	if (wrote_any && !error) {
		int ts_ret = tidefs_posix_vfs_engine_persist_inode_times(
			inode, TIDEFS_POSIX_VFS_FATTR_MTIME_CTIME);
		if (ts_ret < 0) {
			pr_err("tidefs_posix_vfs: writepages persist times failed ino=%lu ret=%d\n",
			       inode->i_ino, ts_ret);
			error = ts_ret;
		}
	}

	if (close_write_handle) {
		int release_ret = tidefs_posix_vfs_engine_release(
			fh_ino, fh_id);
		if (release_ret < 0 && !error) {
			pr_err("tidefs_posix_vfs: writepages release failed ino=%lu fh=%llu ret=%d\n",
			       inode->i_ino, fh_id, release_ret);
			error = release_ret;
		}
	}

	return error;
}

/*
 * read_folio -- address_space_operations callback for page-cache population.
 *
 * Reads a folio-sized chunk of data from the TideFS engine into the
 * kernel page cache.  The folio is already locked by the kernel VFS;
 * this callback fills it with data from VfsEngine::read(), marks it
 * uptodate, and unlocks the folio for the kernel to use.
 *
 * No userspace daemon is required: VfsEngine::read resolves within
 * kernel authority through KernelPoolCore.
 *
 * Registered on regular-file inodes as inode->i_mapping->a_ops->read_folio.
 */
static int tidefs_posix_vfs_read_folio(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	struct tidefs_posix_vfs_open_file_state *ofs;
	loff_t pos = folio_pos(folio);
	loff_t isize;
	size_t fsize = folio_size(folio);
	size_t read_len;
	void *kbuf;
	int ret;
	u64 fh_ino, fh_id;
	u64 fence_generation;

	if (!ctx)
		return -EIO;

	if (pos < 0 || fsize == 0) {
		folio_unlock(folio);
		return 0;
	}

	ofs = file ? file->private_data : NULL;
	fh_ino = ofs ? ofs->fh_ino : inode->i_ino;
	fh_id = ofs ? ofs->fh_id : inode->i_ino;

	isize = i_size_read(inode);
	if (pos >= isize) {
		folio_zero_range(folio, 0, fsize);
		folio_mark_uptodate(folio);
		folio_unlock(folio);
		return 0;
	}

	read_len = min_t(loff_t, (loff_t)fsize, isize - pos);
	fence_generation = tidefs_posix_vfs_pagecache_fence_snapshot(
		inode, pos, read_len);
	kbuf = kmalloc(read_len, GFP_KERNEL);
	if (!kbuf) {
		folio_unlock(folio);
		return -ENOMEM;
	}

	memset(kbuf, 0, read_len);

	ret = tidefs_posix_vfs_engine_read(fh_ino, fh_id, (u64)pos, kbuf, (u32)read_len);
	if (ret < 0) {
		kfree(kbuf);
		mapping_set_error(folio->mapping, ret);
		folio_unlock(folio);
		return ret;
	}

	/* Copy engine data into the folio pages. */
	if (ret > 0) {
		void *addr = kmap_local_folio(folio, 0);
		size_t copy_len = min_t(size_t, (size_t)ret, read_len);
		memcpy(addr, kbuf, copy_len);
		kunmap_local(addr);
		/* Zero-fill remainder for short reads (holes, EOF). */
		if (copy_len < fsize)
			folio_zero_range(folio, copy_len, fsize - copy_len);
	} else {
		/* Zero-length read: the entire folio represents a hole. */
		folio_zero_range(folio, 0, fsize);
	}

	if (!tidefs_posix_vfs_pagecache_fence_still_current(
		    inode, pos, read_len, fence_generation)) {
		kfree(kbuf);
		folio_clear_uptodate(folio);
		folio_unlock(folio);
		return -EAGAIN;
	}

	kfree(kbuf);
	folio_mark_uptodate(folio);
	folio_unlock(folio);
	return 0;
}


/*
 * Engine-backed readahead for regular files.  Populates clean page-cache
 * folios from the engine for the range described by rac.  The folios are
 * populated and marked uptodate after a complete in-file engine read.  Engine
 * failures, allocation failures, and short in-file reads leave the folio
 * non-uptodate so the kernel will fall back to synchronous read_folio on
 * demand.  Folios wholly beyond EOF are zero-filled and marked uptodate.
 *
 * This is advisory: no mapping_set_error is recorded and dirty state is
 * never set.  Short reads, holes, EOF, and engine-read errors are handled
 * as advisory prefetch outcomes without exposing stale bytes or poisoning
 * later demand reads.
 */
static void tidefs_posix_vfs_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->mapping->host;
	struct tidefs_posix_vfs_mount *ctx;
	struct folio *folio;
	loff_t isize;

	if (!inode || !inode->i_sb)
		return;

	ctx = inode->i_sb->s_fs_info;
	if (!ctx)
		return;

	isize = i_size_read(inode);

	while ((folio = readahead_folio(rac)) != NULL) {
		loff_t pos = folio_pos(folio);
		size_t fsize = folio_size(folio);
		size_t read_len;
		void *kbuf;
		u64 fence_generation;
		int ret;
		u64 fh_ino;

		fh_ino = inode->i_ino;

		if (fsize == 0) {
			folio_unlock(folio);
			continue;
		}

		/* Beyond EOF: zero-fill the folio and mark it uptodate.
		 * This avoids leaving an unlocked, non-uptodate folio
		 * that would trigger an unnecessary read_folio fallback
		 * for a known hole or EOF region.
		 */
		if (pos >= isize) {
			folio_zero_range(folio, 0, fsize);
			folio_mark_uptodate(folio);
			folio_unlock(folio);
			continue;
		}

		read_len = min_t(loff_t, (loff_t)fsize, isize - pos);
		fence_generation = tidefs_posix_vfs_pagecache_fence_snapshot(
			inode, pos, read_len);
		kbuf = kmalloc(read_len, GFP_KERNEL);
		if (!kbuf) {
			/* Advisory: skip this folio on transient alloc
			 * failure; the kernel will retry via read_folio.
			 */
			folio_unlock(folio);
			continue;
		}

		memset(kbuf, 0, read_len);

		ret = tidefs_posix_vfs_engine_read(fh_ino,
						   fh_ino, /* fh_id */
						   (u64)pos,
						   kbuf,
						   (u32)read_len);
		if (ret < 0) {
			kfree(kbuf);
			/* Advisory: do not call mapping_set_error.
			 * Unlock without marking uptodate so the kernel
			 * falls back to synchronous read_folio on demand.
			 */
			folio_unlock(folio);
			continue;
		}

		if ((size_t)ret < read_len) {
			kfree(kbuf);
			/* Advisory short in-file read: leave the folio
			 * non-uptodate so demand read_folio resolves the
			 * range through engine authority later.
			 */
			folio_unlock(folio);
			continue;
		}

		if (!tidefs_posix_vfs_pagecache_fence_still_current(
			    inode, pos, read_len, fence_generation)) {
			kfree(kbuf);
			folio_unlock(folio);
			continue;
		}

		if (ret > 0) {
			void *addr = kmap_local_folio(folio, 0);
			size_t copy_len = min_t(size_t, (size_t)ret, read_len);

			memcpy(addr, kbuf, copy_len);
			kunmap_local(addr);

			/* Zero-fill folio bytes past the known file size. */
			if (copy_len < fsize)
				folio_zero_range(folio, copy_len,
						 fsize - copy_len);
		}

		kfree(kbuf);
		folio_mark_uptodate(folio);
		folio_unlock(folio);
	}
}

/*
 * address_space_operations vtable for TideFS regular files.
 *
 * Wires the kernel page cache to the Rust VfsEngine bridge for page-cache
 * population, buffered writes, mmap fault population, and writeback.
 *
 * Implemented: read_folio, write_begin, write_end, dirty_folio,
 * writepages.  `dirty_folio` records Linux dirty accounting only; writeback
 * copies the folio contents to the engine and re-dirties on engine failure for
 * retry. `.invalidate_folio` remains unregistered: mounted truncate,
 * fallocate, direct-write, and copy mutations own live cleanup through the C
 * filemap write-and-wait, unmap, invalidate, and truncate_setsize helpers.
 * Remaining: C-to-Rust invalidate_folio/page-authority bridge
 * work under Review debt TFR-018; readahead is now wired.
 */
static const struct address_space_operations tidefs_posix_vfs_aops = {
	.write_begin = tidefs_posix_vfs_write_begin,
	.write_end   = tidefs_posix_vfs_write_end,
	.dirty_folio = tidefs_posix_vfs_dirty_folio,
	.writepages = tidefs_posix_vfs_writepages,
	.read_folio  = tidefs_posix_vfs_read_folio,
	.readahead  = tidefs_posix_vfs_readahead,
	/* Remaining fields default to NULL; kernel falls back to
	 * generic implementations or skips the operation. */
};
static int tidefs_posix_vfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct tidefs_posix_vfs_mount *ctx = dentry->d_sb->s_fs_info;
	struct tidefs_posix_vfs_kernel_pool_core *pool = NULL;

	if (!ctx)
		return -EIO;

	if (ctx->engine_backed && !ctx->bootstrap_only) {
		if (!ctx->pool.imported)
			return -ENODEV;

		pool = &ctx->pool;
		buf->f_type = dentry->d_sb->s_magic;
		buf->f_bsize = pool->block_size;
		buf->f_frsize = pool->block_size;
		buf->f_blocks = pool->total_blocks;
		buf->f_bfree = pool->free_blocks;
		buf->f_bavail = pool->avail_blocks;
		buf->f_files = pool->total_inodes;
		buf->f_ffree = pool->free_inodes;
		buf->f_fsid = u64_to_fsid(pool->fsid);
		buf->f_namelen = pool->name_max;
		return 0;
	}

	buf->f_type = dentry->d_sb->s_magic;
	buf->f_bsize = ctx->block_size;
	buf->f_frsize = ctx->block_size;
	buf->f_blocks = ctx->total_blocks;
	buf->f_bfree = ctx->free_blocks;
	buf->f_bavail = ctx->avail_blocks;
	buf->f_files = ctx->total_inodes;
	buf->f_ffree = ctx->free_inodes;
	buf->f_fsid = u64_to_fsid(ctx->fsid);
	buf->f_namelen = ctx->name_max;
	return 0;
}

static int tidefs_posix_vfs_sync_fs(struct super_block *sb, int wait)
{
	struct tidefs_posix_vfs_mount *ctx = sb->s_fs_info;
	int ret = 0;

	if (!ctx) {
		pr_warn("tidefs_posix_vfs: sync_fs super_operation without mount context\n");
		return -EIO;
	}

	ctx->sync_fs_calls++;

	if (!wait) {
		pr_debug("tidefs_posix_vfs: sync_fs super_operation: wait=0 deferred call=%u\n",
			 ctx->sync_fs_calls);
		return 0;
	}

	if (ctx->engine_backed) {
		ret = tidefs_posix_vfs_activate_engine(ctx);
		if (ret == 0)
			ret = tidefs_posix_vfs_engine_sync_fs(wait);
		ctx->committed_txg = ctx->pool.committed_txg;
	}

	pr_info("tidefs_posix_vfs: sync_fs super_operation: wait=%d txg=%llu call=%u ret=%d\n",
		wait, ctx->committed_txg, ctx->sync_fs_calls, ret);
	return ret;
}

/*
 * shutdown -- deferred FS_IOC_GOINGDOWN support.
 *
 * Keep the implementation stub out of the registered super_operations table
 * until it can force a complete engine-wide shutdown. Registering a no-op
 * callback makes xfstests shutdown rows treat the feature as available and can
 * leave the guest stuck in post-shutdown cleanup.
 */
static void __maybe_unused tidefs_posix_vfs_shutdown(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx = sb->s_fs_info;

	if (!ctx) {
		pr_warn("tidefs_posix_vfs: shutdown super_operation without mount context\n");
		return;
	}

	ctx->shutdown_calls++;
	pr_info("tidefs_posix_vfs: shutdown super_operation: txg=%llu call=%u\n",
		ctx->committed_txg, ctx->shutdown_calls);

	ctx->pool.imported = false;
	ctx->pool.sb = NULL;
	ctx->pool.bdev = NULL;
}

/*
 * freeze_fs / unfreeze_fs -- explicit unsupported administrative operations.
 *
 * TideFS does not yet have mounted-kernel authority to stop new mutating work,
 * drain dirty/writeback state into a coherent frozen point, and then restart
 * admission on thaw. Register refusal callbacks so Linux sees EOPNOTSUPP
 * instead of interpreting a missing path as implemented product behavior.
 */
static int tidefs_posix_vfs_freeze_fs(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx = sb ? sb->s_fs_info : NULL;

	if (!ctx) {
		pr_warn("tidefs_posix_vfs: freeze_fs refused without mount context\n");
		return -EIO;
	}

	ctx->freeze_fs_refusals++;
	pr_info("tidefs_posix_vfs: freeze_fs refused: dirty/writeback freeze authority unsupported txg=%llu refusal=%u ret=%d\n",
		ctx->committed_txg, ctx->freeze_fs_refusals, -EOPNOTSUPP);
	return -EOPNOTSUPP;
}

static int tidefs_posix_vfs_unfreeze_fs(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx = sb ? sb->s_fs_info : NULL;

	if (!ctx) {
		pr_warn("tidefs_posix_vfs: unfreeze_fs refused without mount context\n");
		return -EIO;
	}

	ctx->unfreeze_fs_refusals++;
	pr_info("tidefs_posix_vfs: unfreeze_fs refused: no TideFS frozen state exists txg=%llu refusal=%u ret=%d\n",
		ctx->committed_txg, ctx->unfreeze_fs_refusals, -EOPNOTSUPP);
	return -EOPNOTSUPP;
}

/*
 * remount/reconfigure -- explicit unsupported option-reconfiguration path.
 *
 * The mounted adapter can display its initial options but cannot yet apply
 * option changes, ro/rw transitions, recovery toggles, or commit-timeout
 * changes to the live engine. Refuse every remount request instead of leaving
 * callers with a silent flags-only no-op.
 */
static int tidefs_posix_vfs_refuse_remount(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx = sb ? sb->s_fs_info : NULL;

	if (!ctx) {
		pr_warn("tidefs_posix_vfs: remount_fs refused without mount context\n");
		return -EIO;
	}

	ctx->remount_fs_refusals++;
	pr_info("tidefs_posix_vfs: remount_fs refused: live option changes unsupported txg=%llu refusal=%u ret=%d\n",
		ctx->committed_txg, ctx->remount_fs_refusals, -EOPNOTSUPP);
	return -EOPNOTSUPP;
}

#if TIDEFS_HAVE_FSERROR
/*
 * report_error -- kernel VFS callback for filesystem error reporting.
 */
static void tidefs_posix_vfs_report_error(const struct fserror_event *event)
{
	struct super_block *sb = event->sb;
	struct tidefs_posix_vfs_mount *ctx = sb ? sb->s_fs_info : NULL;

	if (ctx)
		ctx->report_error_calls++;

	pr_warn("tidefs_posix_vfs: report_error: errno=%d type=%d call=%u\n",
		event->error, event->type,
		ctx ? ctx->report_error_calls : 0);
}
#endif

static void tidefs_posix_vfs_put_super(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx = sb->s_fs_info;

	if (!ctx) {
		pr_warn("tidefs_posix_vfs: put_super super_operation without mount context\n");
		return;
	}

	ctx->put_super_calls++;
	pr_info("tidefs_posix_vfs: put_super super_operation: txg=%llu call=%u sync_fs_calls=%u umount_begin_calls=%u\n",
		ctx->committed_txg, ctx->put_super_calls, ctx->sync_fs_calls,
		ctx->umount_begin_calls);
}


/*
 * write_inode -- kernel VFS callback to flush dirty inode metadata.
 *
 * Called by the VFS writeback machinery when an inode is marked dirty
 * (I_DIRTY_SYNC, I_DIRTY_DATASYNC, or I_DIRTY_TIME).  The kernel expects
 * the filesystem to persist the current inode metadata to stable storage.
 *
 * Explicit metadata mutations (chmod, chown, truncate, utimes) are handled
 * by .setattr, which persists through the engine bridge immediately.
 * This callback handles lazy timestamp updates and periodic sync-driven
 * writeback.  For engine-backed mounts, timestamps are synced through the
 * setattr bridge; bootstrap mounts acknowledge immediately.
 */
static int tidefs_posix_vfs_write_inode(struct inode *inode,
					struct writeback_control *wbc)
{
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	int ret;

	(void)wbc;

	if (ctx)
		ctx->write_inode_calls++;

	if (!ctx || !ctx->engine_backed)
		return 0;

	ret = tidefs_posix_vfs_engine_persist_inode_times(
		inode, TIDEFS_POSIX_VFS_FATTR_TIMES);
	if (ret < 0)
		pr_debug("tidefs_posix_vfs: write_inode persist failed ino=%lu ret=%d\n",
			 inode->i_ino, ret);
	return ret;
}

/*
 * evict_inode -- kernel VFS callback for inode eviction.
 *
 * Called by the VFS when an inode is evicted from the inode cache:
 * all references are dropped and i_nlink is zero. This is the final
 * cleanup opportunity before the inode is freed.
 *
 * Actions:
 *   - Truncate all remaining page-cache pages via
 *     truncate_inode_pages_final.
 *   - Clear the inode via clear_inode (generic VFS cleanup).
 *   - Track eviction and orphan (nlink==0) counts.
 *   - Log orphan evictions for open-unlink lifecycle validation.
 *
 * This is the canonical kernel VFS lifecycle callback that closes
 * the REL-KVFS-009 dentry/inode eviction gap.
 */
static void tidefs_posix_vfs_evict_inode(struct inode *inode)
{
	struct tidefs_posix_vfs_mount *ctx = inode->i_sb->s_fs_info;
	bool orphan = inode->i_nlink == 0;

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	if (ctx) {
		ctx->evict_inode_calls++;
		if (orphan)
			ctx->evict_orphan_calls++;
	}

	pr_debug("tidefs_posix_vfs: evict_inode ino=%lu nlink=%u mode=0%o orphan=%d evict_total=%u evict_orphans=%u\n",
		 inode->i_ino, inode->i_nlink, inode->i_mode,
		 orphan ? 1 : 0,
		 ctx ? ctx->evict_inode_calls : 0,
		 ctx ? ctx->evict_orphan_calls : 0);
}

/*
 * free_inode -- kernel VFS callback to deallocate a custom inode.
 *
 * Called by the VFS after evict_inode has completed. Since the current
 * module does not embed a custom inode_info struct, this is a no-op
 * that relies on the generic slab deallocation of struct inode.
 *
 * When a custom inode_info is added, this callback must free it.
 */
static void tidefs_posix_vfs_free_inode(struct inode *inode)
{
	/* Generic slab deallocation covers struct inode; no custom data to free. */
}

static void tidefs_posix_vfs_umount_begin(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx = sb->s_fs_info;

	if (!ctx) {
		pr_warn("tidefs_posix_vfs: umount_begin super_operation without mount context\n");
		return;
	}

	ctx->umount_begin_calls++;
	pr_info("tidefs_posix_vfs: umount_begin super_operation: txg=%llu call=%u\n",
		ctx->committed_txg, ctx->umount_begin_calls);
}

static void tidefs_posix_vfs_kill_sb(struct super_block *sb)
{
	struct tidefs_posix_vfs_mount *ctx = sb->s_fs_info;
	bool engine_backed = ctx && ctx->engine_backed;
	bool block_backed = engine_backed || sb->s_bdev;

	if (block_backed)
		kill_block_super(sb);
	else
		kill_anon_super(sb);

	/* Engine teardown after Linux has run sync_fs/put_super with s_fs_info live. */
	if (engine_backed && ctx && ctx->engine_activated) {
		mutex_lock(&tidefs_posix_vfs_engine_switch_lock);
		if (g_active_engine_ctx == ctx) {
			int ret = tidefs_posix_vfs_engine_kill_sb();
			if (ret != 0)
				pr_warn("tidefs_posix_vfs: engine kill_sb returned %d (non-fatal)\n", ret);
			g_active_engine_ctx = NULL;
			g_engine_pool = NULL;
		}
		mutex_unlock(&tidefs_posix_vfs_engine_switch_lock);
	}

	pr_info("tidefs_posix_vfs: lifecycle summary: txg=%llu sync_fs_calls=%u put_super_calls=%u umount_begin_calls=%u evict_inode_calls=%u evict_orphan_calls=%u write_inode_calls=%u write_begin_calls=%u write_end_calls=%u dirty_folio_calls=%u writepages_calls=%u dentry_delete=%u dentry_release=%u dentry_iput=%u dentry_iput_orphan=%u shutdown_calls=%u freeze_fs_refusals=%u unfreeze_fs_refusals=%u remount_fs_refusals=%u report_error_calls=%u\n",
		ctx ? ctx->committed_txg : 0,
		ctx ? ctx->sync_fs_calls : 0,
		ctx ? ctx->put_super_calls : 0,
		ctx ? ctx->umount_begin_calls : 0,
		ctx ? ctx->evict_inode_calls : 0,
		ctx ? ctx->evict_orphan_calls : 0,
		ctx ? ctx->write_inode_calls : 0,
		ctx ? ctx->write_begin_calls : 0,
		ctx ? ctx->write_end_calls : 0,
		ctx ? ctx->dirty_folio_calls : 0,
		ctx ? ctx->writepages_calls : 0,
		ctx ? ctx->dentry_delete_calls : 0,
		ctx ? ctx->dentry_release_calls : 0,
		ctx ? ctx->dentry_iput_calls : 0,
		ctx ? ctx->dentry_iput_orphan_calls : 0,
		ctx ? ctx->shutdown_calls : 0,
		ctx ? ctx->freeze_fs_refusals : 0,
		ctx ? ctx->unfreeze_fs_refusals : 0,
		ctx ? ctx->remount_fs_refusals : 0,
		ctx ? ctx->report_error_calls : 0);
	sb->s_fs_info = NULL;
	tidefs_posix_vfs_pool_core_teardown(ctx);
	tidefs_posix_vfs_mount_free(ctx);
	pr_info("tidefs_posix_vfs: killed %sbacked kernel VFS context\n",
		block_backed ? "block-" : (engine_backed ? "engine-" : "bootstrap-"));
}



/*
 * Export operations for NFS file-handle support.
 *
 * encode_fh: produces a file handle, encoding {ino, generation}
 *   plus optional parent inode for directory reconnection.
 * fh_to_dentry: resolves a file handle back to a dentry.
 * fh_to_parent: extracts the parent inode from a directory file handle.
 */
static int tidefs_posix_vfs_encode_fh(struct inode *inode, __u32 *fh,
				       int *max_len, struct inode *parent)
{
	u64 ino = inode->i_ino;
	u64 gen = inode->i_generation;
	int len;

	if (parent && S_ISDIR(inode->i_mode) && *max_len >= 6) {
		len = 6;
		fh[0] = (__u32)(ino >> 32);
		fh[1] = (__u32)(ino & 0xFFFFFFFF);
		fh[2] = (__u32)(gen >> 32);
		fh[3] = (__u32)(gen & 0xFFFFFFFF);
		fh[4] = (__u32)(parent->i_ino >> 32);
		fh[5] = (__u32)(parent->i_ino & 0xFFFFFFFF);
		*max_len = len;
		return 1;
	}

	len = 4;
	if (*max_len < 4)
		return FILEID_INVALID;
	fh[0] = (__u32)(ino >> 32);
	fh[1] = (__u32)(ino & 0xFFFFFFFF);
	fh[2] = (__u32)(gen >> 32);
	fh[3] = (__u32)(gen & 0xFFFFFFFF);
	*max_len = len;
	return 2;
}

static struct inode *tidefs_posix_vfs_export_iget(struct super_block *sb,
						   u64 ino)
{
	struct tidefs_posix_vfs_mount *ctx = sb->s_fs_info;
	struct tidefs_posix_vfs_engine_attr_out attr;
	struct inode *inode;
	int ret;

	inode = ilookup(sb, ino);
	if (inode)
		return inode;
	if (!ctx || !ctx->engine_backed)
		return ERR_PTR(-ESTALE);

	memset(&attr, 0, sizeof(attr));
	ret = tidefs_posix_vfs_engine_getattr(ino, &attr);
	if (ret == -ENOENT)
		return ERR_PTR(-ESTALE);
	if (ret < 0)
		return ERR_PTR(ret);
	if (attr.ino != ino)
		return ERR_PTR(-EIO);

	return tidefs_posix_vfs_iget_engine_attr(sb, &attr);
}

static struct dentry *tidefs_posix_vfs_fh_to_dentry(struct super_block *sb,
	struct fid *fid, int fh_len, int fh_type)
{
	u64 ino, gen;
	struct inode *inode;

	if (fh_type == 1) {
		if (fh_len < 6)
			return ERR_PTR(-EINVAL);
		ino = ((u64)fid->raw[0] << 32) | fid->raw[1];
		gen = ((u64)fid->raw[2] << 32) | fid->raw[3];
	} else if (fh_type == 2) {
		if (fh_len < 4)
			return ERR_PTR(-EINVAL);
		ino = ((u64)fid->raw[0] << 32) | fid->raw[1];
		gen = ((u64)fid->raw[2] << 32) | fid->raw[3];
	} else {
		return ERR_PTR(-EINVAL);
	}

	inode = tidefs_posix_vfs_export_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (inode->i_generation != gen) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return d_obtain_alias(inode);
}

static struct dentry *tidefs_posix_vfs_fh_to_parent(struct super_block *sb,
	struct fid *fid, int fh_len, int fh_type)
{
	u64 parent_ino;
	struct inode *inode;

	if (fh_type != 1 || fh_len < 6)
		return ERR_PTR(-EINVAL);

	parent_ino = ((u64)fid->raw[4] << 32) | fid->raw[5];

	inode = tidefs_posix_vfs_export_iget(sb, parent_ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	return d_obtain_alias(inode);
}

static struct dentry *tidefs_posix_vfs_get_parent(struct dentry *child)
{
	struct inode *child_inode = d_inode(child);
	struct tidefs_posix_vfs_mount *ctx;
	struct inode *parent_inode;
	u64 parent_ino = 0;
	int ret;

	if (!child_inode)
		return ERR_PTR(-ESTALE);
	ctx = child_inode->i_sb->s_fs_info;
	if (!ctx || !ctx->engine_backed)
		return ERR_PTR(-ESTALE);

	ret = tidefs_posix_vfs_engine_get_parent(child_inode->i_ino,
						 &parent_ino);
	if (ret == -ENOENT)
		return ERR_PTR(-ESTALE);
	if (ret < 0)
		return ERR_PTR(ret);
	if (!parent_ino)
		return ERR_PTR(-EIO);

	parent_inode = tidefs_posix_vfs_export_iget(child_inode->i_sb,
						       parent_ino);
	if (IS_ERR(parent_inode))
		return ERR_CAST(parent_inode);
	return d_obtain_alias(parent_inode);
}

static const struct export_operations tidefs_posix_vfs_export_ops = {
	.encode_fh      = tidefs_posix_vfs_encode_fh,
	.fh_to_dentry   = tidefs_posix_vfs_fh_to_dentry,
	.fh_to_parent   = tidefs_posix_vfs_fh_to_parent,
	.get_parent     = tidefs_posix_vfs_get_parent,
};


/*
 * show_options — report mount options in /proc/mounts via seq_file.
 *
 * Outputs the mode (bootstrap / engine-backed), ro/rw flag, and
 * recovery mode when active.  This makes TideFS mounts legible in
 * mountinfo and mount-stats tooling without reading kernel logs.
 */
static int tidefs_posix_vfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct tidefs_posix_vfs_mount *ctx;

	if (!sb || !sb->s_fs_info)
		return -EINVAL;

	ctx = sb->s_fs_info;

	if (ctx->bootstrap_only)
		seq_puts(seq, ",bootstrap");
	else if (ctx->engine_backed)
		seq_puts(seq, ",engine-backed");

	if (sb->s_flags & SB_RDONLY)
		seq_puts(seq, ",ro");
	else
		seq_puts(seq, ",rw");

	if (ctx->debug)
		seq_puts(seq, ",debug");
	if (ctx->commit_timeout_ms != 5000)
		seq_printf(seq, ",commit_timeout_ms=%u", ctx->commit_timeout_ms);
	if (ctx->recovery_mode)
		seq_puts(seq, ",recovery");

	if (ctx->bootstrap_only && !ctx->engine_backed) {
		seq_printf(seq, ",blocks=%llu", ctx->total_blocks);
		seq_printf(seq, ",block_size=%u", ctx->block_size);
	}

	return 0;
}

static const struct super_operations tidefs_posix_vfs_super_ops = {
	.put_super = tidefs_posix_vfs_put_super,
	.sync_fs = tidefs_posix_vfs_sync_fs,
	.evict_inode = tidefs_posix_vfs_evict_inode,
	.write_inode = tidefs_posix_vfs_write_inode,
	.free_inode = tidefs_posix_vfs_free_inode,
	.statfs = tidefs_posix_vfs_statfs,
	.umount_begin = tidefs_posix_vfs_umount_begin,
	.freeze_fs = tidefs_posix_vfs_freeze_fs,
	.unfreeze_fs = tidefs_posix_vfs_unfreeze_fs,
	/*
	 * .shutdown intentionally remains unregistered: Linux cannot surface an
	 * errno from this callback, so FS_IOC_GOINGDOWN must stay unsupported
	 * until TideFS has a full quiesce/no-new-work shutdown implementation.
	 */
#if TIDEFS_HAVE_FSERROR
	.report_error = tidefs_posix_vfs_report_error,
#endif
	.show_options = tidefs_posix_vfs_show_options,
};


/*
 * Engine-backed block-device fill_super (Tier 2 mount path).
 *
 * Phase 1: Read the pool label (first 256 KiB) from the block device.
 * Phase 2: Call Rust bridge to parse label and locate superblock region.
 * Phase 3: Read the superblock region from the block device.
 * Phase 4: Call Rust bridge to validate label + committed-root ledger
 *          and return mount parameters (root inode, capacity, etc.).
 * Phase 5: Create real root inode/dentry with committed-root inode
 *          number and store kernel-resident context in sb->s_fs_info.
 *
 * On failure at any phase, returns a negative errno with pr_err.
 */
static int tidefs_posix_vfs_fill_super_bdev(struct super_block *sb,
					    struct fs_context *fc)
{
	struct tidefs_posix_vfs_label_parse_out label_out;
	struct tidefs_posix_vfs_fs_context *tidefs_fc = fc->fs_private;
	bool mount_read_only = tidefs_fc ? tidefs_fc->read_only : false;
	/* mount_out replaced by replay_out in Phase 4 */
	struct tidefs_posix_vfs_mount *ctx = NULL;
	struct buffer_head *bh = NULL;
	void *label_buf = NULL;
	void *ledger_buf = NULL;
	struct inode *root;
	struct tidefs_posix_vfs_engine_attr_out root_attr;
	int ret;

	if (!sb->s_bdev) {
		pr_err("tidefs_posix_vfs: no block device for engine-backed mount\n");
		return -ENODEV;
	}

	/* ── Phase 1: Read the pool label (first 256 KiB) ────────────────── */
	label_buf = kzalloc(TIDEFS_POSIX_TFS_POOL_LABEL_SIZE, GFP_KERNEL);
	if (!label_buf)
		return -ENOMEM;

	{
		unsigned int block_size = sb->s_blocksize;
		unsigned int blocks_to_read =
			TIDEFS_POSIX_TFS_POOL_LABEL_SIZE / block_size;
		unsigned int i;
		sector_t block = 0;
		unsigned long offset = 0;

		for (i = 0; i < blocks_to_read; i++) {
			bh = sb_bread(sb, block + i);
			if (!bh) {
				pr_err("tidefs_posix_vfs: failed to read label block %llu\n",
				       (unsigned long long)(block + i));
				ret = -EIO;
				goto out_free;
			}
			memcpy(label_buf + offset, bh->b_data, block_size);
			offset += block_size;
			brelse(bh);
			bh = NULL;
		}
	}

	/* ── Phase 2: Parse the label to locate the superblock region ────── */
	memset(&label_out, 0, sizeof(label_out));
	ret = tidefs_posix_vfs_engine_parse_label(
		label_buf, TIDEFS_POSIX_TFS_POOL_LABEL_SIZE, &label_out);
	if (ret < 0) {
		pr_err("tidefs_posix_vfs: label parse failed (err=%d)\n", ret);
		goto out_free;
	}

	pr_info("tidefs_posix_vfs: label parsed: sb_ofs=%llu sb_sz=%llu txg=%llu cap=%llu\n",
		label_out.superblock_offset, label_out.superblock_size,
		label_out.recovery_commit_group, label_out.device_capacity_bytes);

	/* ── Phase 3: Read the superblock region from the block device ───── */
	if (label_out.superblock_size == 0) {
		pr_err("tidefs_posix_vfs: superblock region is empty (no committed-root ledger)\n");
		ret = -ENOENT;
		goto out_free;
	}

	/* Reject unreasonably large superblock regions. */
	if (label_out.superblock_size > (4ULL * 1024 * 1024)) {
		pr_err("tidefs_posix_vfs: superblock region too large (%llu bytes)\n",
		       label_out.superblock_size);
		ret = -EINVAL;
		goto out_free;
	}

	ledger_buf = kzalloc(label_out.superblock_size, GFP_KERNEL);
	if (!ledger_buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	{
		unsigned int block_size = sb->s_blocksize;
		sector_t start_block = label_out.superblock_offset / block_size;
		unsigned long remaining = label_out.superblock_size;
		unsigned int blocks_to_read =
			(remaining + block_size - 1) / block_size;
		unsigned int i;
		unsigned long offset = 0;

		for (i = 0; i < blocks_to_read && remaining > 0; i++) {
			unsigned long chunk = min_t(unsigned long, block_size, remaining);

			bh = sb_bread(sb, start_block + i);
			if (!bh) {
				pr_err("tidefs_posix_vfs: failed to read superblock block %llu\n",
				       (unsigned long long)(start_block + i));
				ret = -EIO;
				goto out_free;
			}
			memcpy(ledger_buf + offset, bh->b_data, chunk);
			offset += chunk;
			remaining -= chunk;
			brelse(bh);
			bh = NULL;
		}
	}

	/* ── Phase 3.5: Check for persisted intent-log records ───────── */
	{
		unsigned int block_size = sb->s_blocksize;
		unsigned long long data_area_offset;
		unsigned long long intent_tail;
		void *intent_buf = NULL;
		unsigned long intent_len = 0;
		int recovery_mode = 0;

		/*
		 * Mount option logic for read-only / recovery-mode control:
		 *
		 * - read-only mount (-o ro) without explicit -o recovery:
		 *   skip intent replay; mount the committed-root state as-is.
		 * - read-only mount (-o ro) with explicit -o recovery:
		 *   force intent replay (emergency recovery mode).
		 * - read-write mount (default) without -o recovery:
		 *   auto-detect intent records and replay if present.
		 * - read-write mount with -o recovery:
		 *   force intent replay (same as explicit recovery_mode).
		 */
		bool explicit_recovery = tidefs_fc ? tidefs_fc->recovery_mode : false;

		if (mount_read_only && !explicit_recovery) {
			/* Read-only mount: skip intent replay entirely.
			 * Do not read or replay intent-log records. */
			goto skip_intent_replay;
		}

			/* Compute the Rust engine intent-log offset. The C fixed
			 * namespace mirror owns the beginning of the pool data
			 * area, so engine-local allocator/intent/writeback data
			 * starts at TIDEFS_KERNEL_POOL_ENGINE_DATA_OFFSET. */
			data_area_offset = label_out.superblock_offset + label_out.superblock_size;
			if (block_size > 0) {
				unsigned long long rem = data_area_offset % block_size;
				if (rem)
					data_area_offset += block_size - rem;
			}
			data_area_offset += TIDEFS_KERNEL_POOL_ENGINE_DATA_OFFSET +
					    TIDEFS_KERNEL_POOL_ENGINE_INTENT_LOG_OFFSET;

		/* Extract intent_log_tail from the VRBT embedded in the
		 * superblock region (offset 3*block_size within ledger_buf). */
		intent_tail = tidefs_posix_vfs_engine_get_vrbt_intent_tail(
			ledger_buf, label_out.superblock_size,
			block_size);

		if (intent_tail > 0 && intent_tail <= (4ULL * 1024 * 1024)) {
			/* Read persisted intent-log records from the data area.
			 * Intent records are written starting at data_area_offset;
			 * intent_log_tail tracks the cumulative byte offset. */
			sector_t start_sector = data_area_offset / block_size;
			unsigned int sectors_to_read =
				(unsigned int)((intent_tail + block_size - 1) / block_size);
			unsigned int i;

			intent_buf = kzalloc(intent_tail, GFP_KERNEL);
			if (!intent_buf) {
				ret = -ENOMEM;
				goto out_free;
			}
			intent_len = intent_tail;
			recovery_mode = 1;

			{
				unsigned long offset = 0;
				for (i = 0; i < sectors_to_read && offset < intent_tail; i++) {
					struct buffer_head *bh = sb_bread(sb, start_sector + i);
					unsigned long chunk;

					if (!bh) {
						pr_err("tidefs_posix_vfs: failed to read intent sector %llu\n",
						       (unsigned long long)(start_sector + i));
						ret = -EIO;
						kfree(intent_buf);
						goto out_free;
					}
					chunk = min_t(unsigned long, block_size, intent_tail - offset);
					memcpy(intent_buf + offset, bh->b_data, chunk);
					offset += chunk;
					brelse(bh);
				}
			}

			pr_info("tidefs_posix_vfs: read %lu intent bytes from data area (tail=%llu)\n",
				intent_len, intent_tail);
		} else if (explicit_recovery) {
			/*
			 * Explicit -o recovery flag but no intent records found
			 * on disk. Set recovery_mode anyway so the Rust mount
			 * sequence knows we're in recovery mode (allows clean
			 * mount with empty intent log).
			 */
			recovery_mode = 1;
			pr_info("tidefs_posix_vfs: explicit recovery mode, no intent records on disk\n");
		}

	skip_intent_replay:
		/* ── Phase 4: Validate label + select committed root (Rust replay adapter) ─ */
		{
		struct tidefs_posix_vfs_replay_mount_out replay_out;

		memset(&replay_out, 0, sizeof(replay_out));
		ret = tidefs_posix_vfs_kernel_replay_mount(
			label_buf, TIDEFS_POSIX_TFS_POOL_LABEL_SIZE,
			ledger_buf, label_out.superblock_size,
			intent_buf, intent_len,
			recovery_mode,
			&replay_out);
		if (intent_buf)
			kfree(intent_buf);
		if (ret < 0) {
			pr_err("tidefs_posix_vfs: kernel replay mount failed (err=%d)\n", ret);
			goto out_free;
		}

		pr_info("tidefs_posix_vfs: replay mount: root_ino=%llu txg=%llu inode_root=%llu extent_root=%llu replay=%llu/%llu/%llu clean=%u\n",
			replay_out.root_ino, replay_out.committed_txg,
			replay_out.inode_table_root, replay_out.extent_map_root,
			replay_out.replay_replayed, replay_out.replay_skipped,
			replay_out.replay_errored, replay_out.clean_export);
		if (replay_out.root_ino == 0 ||
		    replay_out.inode_table_root == 0 ||
		    replay_out.extent_map_root == 0) {
			pr_err("tidefs_posix_vfs: replay mount refused missing committed-root import root=%llu inode_root=%llu extent_root=%llu\n",
			       replay_out.root_ino,
			       replay_out.inode_table_root,
			       replay_out.extent_map_root);
			ret = -ENODEV;
			goto out_free;
		}

		/* ── Phase 5: Create root inode/dentry and store context ─────────── */
		ctx = tidefs_posix_vfs_mount_new_engine_replay(sb, &label_out, &replay_out);
		if (!ctx) {
			ret = -ENOMEM;
			goto out_free;
		}
		/* Store read-only and recovery-mode flags from mount options. */
		ctx->read_only = mount_read_only;
		ctx->recovery_mode = explicit_recovery;
		/* Store debug, commit_timeout_ms, and validate features/authority_mode
		 * from the Linux fs_context path. Feature-refusal produces a
		 * TideFS-specific kernel log message instead of generic Unknown parameter. */
		if (tidefs_fc) {
			ctx->debug = tidefs_fc->debug;
			ctx->commit_timeout_ms = tidefs_fc->commit_timeout_ms ? tidefs_fc->commit_timeout_ms : 5000;
			ret = tidefs_posix_vfs_engine_validate_mount_options(
				tidefs_fc->features,
				tidefs_fc->features ? (unsigned int)strlen(tidefs_fc->features) : 0,
				tidefs_fc->authority_mode,
				tidefs_fc->authority_mode ? (unsigned int)strlen(tidefs_fc->authority_mode) : 0);
			if (ret < 0) {
				pr_err("tidefs_posix_vfs: mount option validation failed (err=%d)\n", ret);
				goto out_free;
			}
			ret = tidefs_posix_vfs_mount_copy_cluster_options(
				ctx, tidefs_fc);
			if (ret < 0)
				goto out_free;
		}
		ctx->committed_txg = ctx->pool.committed_txg;
		pr_info("tidefs_posix_vfs: imported committed-root authority: inode_root=%llu extent_root=%llu intent=%llu..%llu replay=%llu/%llu/%llu\n",
			ctx->pool.inode_table_root,
			ctx->pool.extent_map_root,
			ctx->pool.intent_log_head,
			ctx->pool.intent_log_tail,
			ctx->pool.replay_replayed,
			ctx->pool.replay_skipped,
			ctx->pool.replay_errored);
		}

	} /* ── end Phase 3.5 (intent-log read + replay mount) ──────────── */

	sb->s_fs_info = ctx;
	sb->s_magic = TIDEFS_POSIX_TFS_MAGIC;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = ctx->block_size;
	/* Compute log2 of block_size. block_size is a power of 2 (e.g. 4096).
	 * Use fls() which is always available via kernel headers. */
	sb->s_blocksize_bits = fls(ctx->block_size) - 1;
	sb->s_op = &tidefs_posix_vfs_super_ops;
	set_default_d_op(sb, &tidefs_posix_vfs_dentry_ops);
	sb->s_export_op = &tidefs_posix_vfs_export_ops;
	sb->s_xattr = tidefs_posix_vfs_xattr_handlers;
	sb->s_time_gran = 1;

	ret = tidefs_posix_vfs_activate_engine(ctx);
	if (ret < 0) {
		pr_err("tidefs_posix_vfs: committed-root engine activation failed before root dentry (err=%d)\n",
		       ret);
		goto err_mount;
	}

	memset(&root_attr, 0, sizeof(root_attr));
	ret = tidefs_posix_vfs_engine_getattr(ctx->root_ino, &root_attr);
	if (ret < 0) {
		pr_err("tidefs_posix_vfs: imported root getattr failed before root dentry (err=%d)\n",
		       ret);
		goto err_mount;
	}
	if (root_attr.ino != ctx->root_ino || !S_ISDIR(root_attr.mode)) {
		pr_err("tidefs_posix_vfs: imported root refused ino=%llu expected=%llu mode=%o\n",
		       root_attr.ino, ctx->root_ino, root_attr.mode);
		ret = -EIO;
		goto err_mount;
	}

	root = new_inode(sb);
	if (!root)
		goto err_nomem;

	tidefs_posix_vfs_apply_engine_attr(root, &root_attr);

	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		goto err_nomem;

	pr_info("tidefs_posix_vfs: engine-backed mount succeeded: root_ino=%llu txg=%llu blk=%llu/%llu\n",
		ctx->root_ino, ctx->committed_txg,
		ctx->total_blocks, ctx->free_blocks);

	kfree(label_buf);
	kfree(ledger_buf);
	return 0;

err_nomem:
	ret = -ENOMEM;
err_mount:
	sb->s_fs_info = NULL;
	tidefs_posix_vfs_abort_active_engine(ctx);
	tidefs_posix_vfs_pool_core_teardown(ctx);
	tidefs_posix_vfs_mount_free(ctx);
	ctx = NULL;

out_free:
	if (bh)
		brelse(bh);
	if (ctx && sb->s_fs_info != ctx)
		tidefs_posix_vfs_mount_free(ctx);
	kfree(label_buf);
	kfree(ledger_buf);
	return ret;
}

static int tidefs_posix_vfs_get_tree(struct fs_context *fc)
{
	struct tidefs_posix_vfs_fs_context *ctx = fc->fs_private;

	if (!ctx)
		return -EINVAL;

	/* Tier 0: Bootstrap path — retired for product no-daemon mounts. */
	if (ctx->bootstrap) {
		pr_warn("tidefs_posix_vfs: mount refused: -o bootstrap has no explicit kernel pool I/O authority; supply a TideFS block device\n");
		return -EOPNOTSUPP;
	}

	/* If device= was passed as a mount option, use it as the source. */
	if (!fc->source && ctx->device_path) {
		fc->source = kstrdup(ctx->device_path, GFP_KERNEL);
		if (!fc->source)
			return -ENOMEM;
	}

	/* Tier 2: Engine-backed path — requires a block device. */
	if (fc->source)
		return get_tree_bdev(fc, tidefs_posix_vfs_fill_super_bdev);

	/* Tier 1: No device and no bootstrap — fail-closed. */
	pr_warn("tidefs_posix_vfs: mount refused: no block device supplied; supply a TideFS block device\n");
	return -ENODEV;
}

static int tidefs_posix_vfs_parse_param(struct fs_context *fc,
					struct fs_parameter *param)
{
	struct tidefs_posix_vfs_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, tidefs_posix_vfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_bootstrap:
		ctx->bootstrap = true;
		return 0;
	case Opt_engine_backed:
		/*
		 * show_options reports engine-backed mounts so remount(8) can
		 * replay the token. Accept it only as descriptive input; the
		 * actual engine-backed authority still comes from the block
		 * device mount path, and reconfigure refuses remount below.
		 */
		return 0;
	case Opt_device:
		kfree(ctx->device_path);
		ctx->device_path = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->device_path)
			return -ENOMEM;
		return 0;
	case Opt_ro:
		ctx->read_only = true;
		return 0;
	case Opt_rw:
		ctx->read_only = false;
		return 0;
	case Opt_recovery:
		ctx->recovery_mode = true;
		return 0;
	case Opt_debug:
		ctx->debug = true;
		return 0;
	case Opt_commit_timeout_ms:
		ctx->commit_timeout_ms = result.uint_32;
		return 0;
	case Opt_features:
		kfree(ctx->features);
		ctx->features = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->features)
			return -ENOMEM;
		return 0;
	case Opt_authority_mode:
		kfree(ctx->authority_mode);
		ctx->authority_mode = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->authority_mode)
			return -ENOMEM;
		return 0;
	case Opt_cluster_node_id:
		kfree(ctx->cluster_node_id);
		ctx->cluster_node_id = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->cluster_node_id)
			return -ENOMEM;
		return 0;
	case Opt_transport_carrier:
		kfree(ctx->transport_carrier);
		ctx->transport_carrier = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->transport_carrier)
			return -ENOMEM;
		return 0;
	default:
		return -EINVAL;
	}
}

static int tidefs_posix_vfs_reconfigure(struct fs_context *fc)
{
	struct super_block *sb = NULL;

	if (fc && fc->root)
		sb = fc->root->d_sb;

	return tidefs_posix_vfs_refuse_remount(sb);
}

static void tidefs_posix_vfs_free_fs_context(struct fs_context *fc)
{
	struct tidefs_posix_vfs_fs_context *ctx = fc->fs_private;
	if (ctx) {
		kfree(ctx->device_path);
		kfree(ctx->features);
		kfree(ctx->authority_mode);
		kfree(ctx->cluster_node_id);
		kfree(ctx->transport_carrier);
		kfree(ctx);
	}
}

static const struct fs_context_operations tidefs_posix_vfs_context_ops = {
	.free = tidefs_posix_vfs_free_fs_context,
	.parse_param = tidefs_posix_vfs_parse_param,
	.get_tree = tidefs_posix_vfs_get_tree,
	.reconfigure = tidefs_posix_vfs_reconfigure,
};

static int tidefs_posix_vfs_init_fs_context(struct fs_context *fc)
{
	struct tidefs_posix_vfs_fs_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->fs_private = ctx;
	fc->ops = &tidefs_posix_vfs_context_ops;
	return 0;
}

static struct file_system_type tidefs_posix_vfs_type = {
	.owner = THIS_MODULE,
	.name = "tidefs",
	.init_fs_context = tidefs_posix_vfs_init_fs_context,
	.kill_sb = tidefs_posix_vfs_kill_sb,
	/* FS_ALLOW_IDMAP is explicitly refused until mounted-kernel Tier 7+
	 * validation proves idmapped mount ownership translation, permission
	 * checks, getattr/statx uid/gid mapping, and setattr/chown behavior.
	 * See #6651 (KVFS-IDMAP-VALIDATION-001) for removal rationale and
	 * re-admission requirements. */
	.fs_flags = FS_REQUIRES_DEV | FS_USERNS_MOUNT,
};

int tidefs_posix_vfs_register_fs(void)
{
	int ret;

	ret = register_filesystem(&tidefs_posix_vfs_type);
	if (ret)
		pr_err("tidefs_posix_vfs: register_filesystem(tidefs) failed: %d\n", ret);
	else
		pr_info("tidefs_posix_vfs: registered filesystem type 'tidefs'\n");

	return ret;
}

void tidefs_posix_vfs_unregister_fs(void)
{
	int ret;

	ret = unregister_filesystem(&tidefs_posix_vfs_type);
	if (ret)
		pr_warn("tidefs_posix_vfs: unregister_filesystem(tidefs) failed: %d\n", ret);
	else
		pr_info("tidefs_posix_vfs: unregistered filesystem type 'tidefs'\n");
}
