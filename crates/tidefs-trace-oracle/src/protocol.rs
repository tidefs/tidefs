//! Wire-stable trace protocol constants.
//!
//! These op name strings are the cross-implementation contract. The Rust
//! implementation MUST use these exact strings for trace reading and writing.

/// Schema identifier for single-pool (non-distributed) traces.
pub const POOL_TRACE_SCHEMA: &str = "pool_trace_v1";

/// Schema identifier for cluster (distributed) traces (deferred).
pub const CLUSTER_TRACE_SCHEMA: &str = "cluster_trace_v1";

/// Trace format version supported by this implementation.
pub const TRACE_VERSION: u64 = 1;

// ── Control ops ────────────────────────────────────────────────────────────

pub const OP_TRACE_META: &str = "trace_meta";
pub const OP_CREATE_POOL: &str = "create_pool";
pub const OP_OPEN_POOL: &str = "open_pool";
pub const OP_RESTART_POOL: &str = "restart_pool";
pub const OP_CLOSE_POOL: &str = "close_pool";
pub const OP_ASSERT_FINGERPRINT: &str = "assert_fingerprint";

// ── Namespace ops ──────────────────────────────────────────────────────────

pub const OP_CREATE_DATASET: &str = "create_dataset";
pub const OP_MKDIR: &str = "mkdir";
pub const OP_CREATE_FILE: &str = "create_file";
pub const OP_UNLINK: &str = "unlink";
pub const OP_RENAME: &str = "rename";
pub const OP_REFLINK: &str = "reflink";
pub const OP_LOOKUP: &str = "lookup";

// ── File data ops ──────────────────────────────────────────────────────────

pub const OP_PUT: &str = "put";
pub const OP_GET: &str = "get";
pub const OP_WRITE_RANGE: &str = "write_range";
pub const OP_GET_RANGE: &str = "get_range";
pub const OP_FSYNC: &str = "fsync";

// ── Snapshot ops ───────────────────────────────────────────────────────────

pub const OP_CREATE_SNAPSHOT: &str = "create_snapshot";
pub const OP_DESTROY_SNAPSHOT: &str = "destroy_snapshot";

// ── Directory/introspection ops ────────────────────────────────────────────

pub const OP_READDIR: &str = "readdir";
pub const OP_WALK: &str = "walk";
pub const OP_STAT: &str = "stat";
pub const OP_STAT_BATCH: &str = "stat_batch";

// ── Page cache, readahead, and statx ops ───────────────────────────────────
//
// These operations exercise the page-cache, readahead, and statx paths
// for cross-implementation (userspace ↔ kernel) parity validation per
// the K7 kernel module rollout plan.

pub const OP_STATX: &str = "statx";
pub const OP_READAHEAD: &str = "readahead";
pub const OP_PAGE_CACHE_STATS: &str = "page_cache_stats";

// ── Maintenance ops ────────────────────────────────────────────────────────

pub const OP_SERVICE_BACKGROUND: &str = "service_background";

/// All wire-stable op names for `pool_trace_v1`.
pub const POOL_TRACE_OPS: &[&str] = &[
    OP_TRACE_META,
    OP_CREATE_POOL,
    OP_OPEN_POOL,
    OP_RESTART_POOL,
    OP_CLOSE_POOL,
    OP_ASSERT_FINGERPRINT,
    OP_CREATE_DATASET,
    OP_MKDIR,
    OP_CREATE_FILE,
    OP_UNLINK,
    OP_RENAME,
    OP_REFLINK,
    OP_LOOKUP,
    OP_PUT,
    OP_FSYNC,
    OP_GET,
    OP_WRITE_RANGE,
    OP_GET_RANGE,
    OP_CREATE_SNAPSHOT,
    OP_DESTROY_SNAPSHOT,
    OP_READDIR,
    OP_WALK,
    OP_STAT,
    OP_STAT_BATCH,
    OP_STATX,
    OP_READAHEAD,
    OP_PAGE_CACHE_STATS,
    OP_SERVICE_BACKGROUND,
];

// ── JSON key constants ─────────────────────────────────────────────────────

pub const KEY_OP: &str = "op";
pub const KEY_ARGS: &str = "args";
pub const KEY_EXPECT: &str = "expect";
pub const KEY_SCHEMA: &str = "schema";
pub const KEY_VERSION: &str = "version";
pub const KEY_DATASET: &str = "dataset";
pub const KEY_NAME: &str = "name";
pub const KEY_PATH: &str = "path";
pub const KEY_KEY: &str = "key";
pub const KEY_VALUE_B64: &str = "value_b64";
pub const KEY_DATA_B64: &str = "data_b64";
pub const KEY_BOOTSTRAP_B64: &str = "bootstrap_b64";
pub const KEY_DEVICE_COUNT: &str = "device_count";
pub const KEY_DEVICE_SIZE_BYTES: &str = "device_size_bytes";
pub const KEY_OFFSET: &str = "offset";
pub const KEY_LENGTH: &str = "length";
pub const KEY_DATASYNC: &str = "datasync";
pub const KEY_SRC: &str = "src";
pub const KEY_DST: &str = "dst";
pub const KEY_START_AFTER: &str = "start_after";
pub const KEY_MAX_ENTRIES: &str = "max_entries";
pub const KEY_MAX_TASKS: &str = "max_tasks";
pub const KEY_FINGERPRINT: &str = "fingerprint";
pub const KEY_DIR_PATH: &str = "dir_path";
pub const KEY_NAMES: &str = "names";
pub const KEY_NAMES_ARR: &str = "names";
pub const KEY_NEXT_AFTER: &str = "next_after";
pub const KEY_RESULT: &str = "result";

// ── statx / readahead / page-cache key constants ───────────────────────────

/// statx request mask (what fields the caller wants).
pub const KEY_STATX_MASK: &str = "statx_mask";
/// statx synchronization flags (AT_STATX_SYNC_AS_STAT, etc.).
pub const KEY_STATX_SYNC_FLAGS: &str = "statx_sync_flags";
/// Number of bytes to read ahead.
pub const KEY_READAHEAD_COUNT: &str = "readahead_count";
/// Advisory hint for readahead (POSIX_FADV_NORMAL, SEQUENTIAL, RANDOM, etc.).
pub const KEY_FADVISE_ADVICE: &str = "fadvise_advice";
/// Page cache hit count.
pub const KEY_PC_HIT: &str = "pc_hit";
/// Page cache miss count.
pub const KEY_PC_MISS: &str = "pc_miss";
/// Page cache populate (fill) count.
pub const KEY_PC_POPULATE: &str = "pc_populate";
/// Page cache prefetch (readahead) count.
pub const KEY_PC_PREFETCH: &str = "pc_prefetch";
/// Page cache eviction count.
pub const KEY_PC_EVICT: &str = "pc_evict";
