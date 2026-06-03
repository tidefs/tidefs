pub const FILESYSTEM_FORMAT_VERSION: u16 = 5;
pub const CURRENT_FORMAT_VERSION: u16 = FILESYSTEM_FORMAT_VERSION;
/// Oldest format version this code can read (backward-compat window).
pub const FORMAT_COMPAT_WINDOW_MIN: u16 = 1;
pub const ROOT_PATH: &str = "/";
pub const MAX_NAME_BYTES: usize = 255;
pub const PATH_MAX_BYTES: usize = 4096;
pub const DEFAULT_FILE_PERMISSIONS: u32 = 0o644;
pub const CONTENT_INLINE_CHECKSUM_ENCODING_VERSION: u16 = 1;
pub const DEFAULT_DIRECTORY_PERMISSIONS: u32 = 0o755;
pub const DEFAULT_SYMLINK_PERMISSIONS: u32 = 0o777;
pub const FILESYSTEM_SUPERBLOCK_OBJECT_NAME: &str = "tidefs.local-filesystem.v1.superblock";
/// Pool-wide dataset catalog object key for durable B+tree path-to-ID mapping.
/// Persisted through the pool object store; the canonical dataset catalog authority.
pub const DATASET_CATALOG_OBJECT_NAME: &str = "tidefs.local-filesystem.v1.dataset-catalog";
pub const POOL_PROPERTIES_OBJECT_NAME: &str = "tidefs.local-filesystem.v1.pool-properties";
pub const FILESYSTEM_INODE_OBJECT_PREFIX: &str = "tidefs.local-filesystem.v1.inode";
pub const FILESYSTEM_DIRECTORY_OBJECT_PREFIX: &str = "tidefs.local-filesystem.v1.directory";
pub const FILESYSTEM_CONTENT_OBJECT_PREFIX: &str = "tidefs.local-filesystem.v1.content";
pub const FILESYSTEM_ORPHAN_INDEX_OBJECT_NAME: &str = "tidefs.local-filesystem.v1.orphan-index";

// Chunk size is now runtime-configurable via content_chunk_size() below.
// Default: DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE (64 KiB).
// Override with TIDEFS_CONTENT_CHUNK_SIZE env var.
pub const DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE: u32 = 65536;

static CONTENT_CHUNK_SIZE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// Returns the current content chunk size.
///
/// On first call reads `TIDEFS_CONTENT_CHUNK_SIZE` from the environment.
/// Falls back to [`DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE`] (64 KiB).
pub fn content_chunk_size() -> u32 {
    *CONTENT_CHUNK_SIZE.get_or_init(|| {
        if let Ok(val) = std::env::var("TIDEFS_CONTENT_CHUNK_SIZE") {
            if let Ok(parsed) = val.parse::<u32>() {
                if (512..=1_048_576).contains(&parsed) && parsed % 512 == 0 {
                    return parsed;
                }
            }
        }
        DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE
    })
}

pub const HOT_READ_CACHE_SPEC: &str = "publishing checklist item PC-003 hot read cache: LocalFileSystem read_file/read_symlink use a bounded, non-authoritative, inode/data-version/size keyed cache that accelerates reads without becoming publication, recovery, or allocator truth";
pub const DEFAULT_HOT_READ_CACHE_MAX_ENTRIES: usize = 64;
pub const DEFAULT_HOT_READ_CACHE_MAX_BYTES: u64 = 256 * 1024;
pub const LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES: u64 = DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE as u64;

/// PC-009: inode metadata cache: default max entries (adaptive ARC).
pub const DEFAULT_INODE_CACHE_MAX_ENTRIES: usize = 1024;
pub const DEFAULT_INODE_CACHE_MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const FILESYSTEM_CONTENT_CHUNK_SIZE: usize = DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE as usize;
pub const CONTENT_COMPRESSION_SPEC: &str = "Content chunks are compressed according to the per-dataset ContentCompressionPolicy (None, Zstd, or Lz4) with threshold gating. The policy is resolved from dataset feature flags at mount time and governs all mounted-filesystem content writes. Compression is transparent to readers; the content chunk header records the algorithm so decompression is self-describing.";
pub const CONTENT_COMPRESSION_ALGORITHM_NONE: u16 = 0;
pub const CONTENT_COMPRESSION_ALGORITHM_ZSTD: u16 = 1;
pub const CONTENT_COMPRESSION_ZSTD_LEVEL: i32 = 3;
pub const CONTENT_COMPRESSION_MIN_SAVINGS_BYTES: usize = 32;
pub const DEFAULT_LOCAL_FILESYSTEM_CONTENT_CAPACITY_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY: u64 = 65_536;
pub const FILESYSTEM_ROOT_SLOT_COUNT: u64 = 4;
pub const FILESYSTEM_ROOT_OBJECT_PREFIX: &str = "tidefs.local-filesystem.v1.root-slot";
pub const FILESYSTEM_TRANSACTION_OBJECT_PREFIX: &str = "tidefs.local-filesystem.v1.transaction";
pub const PRODUCTION_RECOVERY_DOCTRINE: &str = "automatic previous-or-new committed-root selection; production recovery never requires an operator fsck repair pass";
pub const FORMAL_NO_PRODUCTION_FSCK_FAILURE_MODEL: &str = "TideFS storage item 004 formal failure model: sync semantics, write reordering, torn writes, lost writes, media corruption, and explicit-error behavior all converge to previous root, new root, or explicit integrity/media error without production fsck";
pub const RECOVERY_AUDIT_IS_NOT_FSCK: &str = "recovery audit reports validation only; it must not guess repairs, rewrite namespace truth, or become a production fsck requirement";
pub const MOUNT_INVARIANT_GATE_IS_NOT_FSCK: &str = "mount invariant gate validates committed roots before they become live; it does not repair, rewrite, or require production fsck";
pub const LOCAL_STORAGE_ALLOCATOR_SPEC: &str = "TideFS storage item 102 local storage allocator: finite content-grain and inode capacity are admitted before publication, statfs reports the same allocator truth, and reusable free space excludes content still protected by committed fallback roots";
pub const CLAIM_LEDGER_SPEC: &str = "design rule items Rule 3 and Rule 8: every block allocation must be traceable to a claim against a budget domain (Rule 8); the obligation ledger gates writes before the allocator run — writes are rejected when committed blocks (claims + reserves) would exceed capacity (Rule 3: authority is scarce); reserves guarantee minimums; witnesses prove authorization; the reverse explainer answers what would be freed if a domain were reclaimed";
pub const SAFE_LOCAL_RECLAMATION_GC_SPEC: &str = "TideFS storage item 103 safe local reclamation: mutating GC requires a clear retained-root plan, preserves exact protected root-slot locations, copies protected non-root objects before segment retirement, and verifies recovery after mutation";
pub const ROOT_AUTHENTICATION_SPEC: &str = "TideFS storage item 015 root authentication: committed filesystem roots are mountable only when a keyed BLAKE3-256 authentication record validates root slot, generation, transaction id, manifest digest, superblock digest, policy epoch, and algorithm suite";
pub const ROOT_AUTHENTICATION_ENV_VAR: &str = "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX";
pub const ROOT_AUTHENTICATION_KEY_LEN: usize = 32;
pub const ROOT_AUTHENTICATION_CODE_LEN: usize = 32;
pub const ROOT_AUTHENTICATION_DIGEST_LEN: usize = 32;
pub const ROOT_AUTHENTICATION_RECORD_VERSION: u16 = 1;
pub const ROOT_AUTHENTICATION_ALGORITHM_SUITE_ID: u16 = 1;
pub const ROOT_AUTHENTICATION_POLICY_EPOCH: u64 = 1;
pub const ROOT_AUTHENTICATION_MAGIC_ASCII: &str = "VFSRATH1";
pub const ROOT_AUTHENTICATION_MAGIC_BYTES: [u8; 8] = *b"VFSRATH1";
pub const LOCAL_SNAPSHOT_ROLLBACK_SPEC: &str = "TideFS storage item 108 local snapshots and rollback: named snapshots are authenticated committed-root references in the superblock catalog, rollback publishes a new authenticated root from the snapshot state, and safe reclamation protects snapshot roots";
pub const SNAPSHOT_CATALOG_MAGIC_ASCII: &str = "VFSSNAP1";
pub const SNAPSHOT_CATALOG_MAGIC_BYTES: [u8; 8] = *b"VFSSNAP1";
pub const SNAPSHOT_RECORD_V2_MAGIC_ASCII: &str = "VFSSNP20";
pub const SNAPSHOT_RECORD_V2_MAGIC_BYTES: [u8; 8] = *b"VFSSNP20";
/// VFSSEND1 changed-record stream spec: the live storage-node daemon wire format
/// for SEND/RECEIVE frames. The canonical send/receive format is VFSSEND2
/// (defined in `tidefs-send-stream`) which is validated through the two-node
/// harness but not yet wired into the daemon (see #5949).
pub const SEND_RECEIVE_CHANGED_RECORD_SPEC: &str = "TideFS storage item 109 send/receive: a VFSSEND1 changed-record stream exports authenticated committed-root transaction records, receive validates the stream in staging, re-signs imported roots with the destination root-authentication key, and publishes the received root without operator repair";
pub const SEND_RECEIVE_STREAM_MAGIC_ASCII: &str = "VFSSEND1";
pub const SEND_RECEIVE_STREAM_MAGIC_BYTES: [u8; 8] = *b"VFSSEND1";
pub const SEND_RECEIVE_STREAM_VERSION: u16 = 1;
pub const ONLINE_VERIFIER_SPEC: &str = "TideFS storage item 110 online verifier: non-mutating verification walks committed root candidates, transaction manifests, authenticated roots, namespace invariants, content checksums, and snapshot references without rewriting namespace truth";
pub const ONLINE_VERIFIER_IS_NOT_FSCK: &str = "online verification reports issues only; it must not rewrite root slots, transaction objects, namespace records, or content objects and must stay separate from production recovery/repair";
pub const POSIX_SUBSET_SPEC: &str = "TideFS storage item 104 POSIX subset: first FUSE work must use an explicit included, blocked, deferred, or unsupported syscall and semantic matrix before claiming userspace mount capability";
pub const POSIX_SUBSET_POLICY_VERSION: u16 = 1;

pub const FILESYSTEM_INTENT_LOG_OBJECT_PREFIX: &str = "tidefs.local-filesystem.v1.intent-log";
pub const INTENT_LOG_MAGIC_ASCII: &str = "VFSILOG1";
pub const INTENT_LOG_MAGIC_BYTES: [u8; 8] = *b"VFSILOG1";
pub const INTENT_LOG_ENTRY_VERSION: u16 = 2;

pub const FORMAT_VERSION_EXTENSION_MAGIC_ASCII: &str = "VFSFMTV1";
pub const FORMAT_VERSION_EXTENSION_MAGIC_BYTES: [u8; 8] = *b"VFSFMTV1";

pub const DEFAULT_AUTO_COMPACTION_WASTE_THRESHOLD: f64 = 0.25;
/// Default cap on deferred (non-auto-commit) mutations before the
/// filesystem forces a synchronous commit to bound memory usage and
/// crash-loss exposure.  ZFS uses a similar commit_group open/quiesce
/// threshold for the same reason.
pub const DEFAULT_MAX_UNCOMMITTED_MUTATIONS: u64 = 256;

pub const CONTENT_DEDUP_SPEC: &str = "content-addressed deduplication: gated by `integrity.dedup` dataset property (default off via dataset-properties registry). When enabled, BLAKE3-256 fingerprints of uncompressed chunk content are mapped through an in-memory DedupIndex and cross-session canonical-object probing to prevent duplicate chunk writes; redirect records point to content-addressed canonical chunk objects. When disabled (default), chunk writes skip fingerprint computation and store inline chunk data only. The tidefs-dedup crate (DDT/scanner design) is not yet the live write-path authority.";
pub const CONTENT_DEDUP_MAGIC_ASCII: &str = "VFSDEDUP";
pub const CONTENT_DEDUP_MAGIC_BYTES: [u8; 8] = *b"VFSDEDUP";
pub const CONTENT_DEDUP_REDIRECT_FORMAT_VERSION: u16 = 1;
pub const CONTENT_DEDUP_REDIRECT_RECORD_BYTES: usize = 44;
pub const CONTENT_DEDUP_FINGERPRINT_DOMAIN: &[u8] =
    b"tidefs.local-filesystem.content-dedup.fingerprint.v1";

pub const FILESYSTEM_SNAPSHOT_CATALOG_OBJECT_PREFIX: &str =
    "tidefs.local-filesystem.v1.snapshot-catalog";
pub const SPACE_COUNTERS_MAGIC_ASCII: &str = "VFSSPAC1";
pub const SPACE_COUNTERS_MAGIC_BYTES: [u8; 8] = *b"VFSSPAC1";

/// Receive-checkpoint magic: durable marker written to the staging store so a
/// crashed receive can resume without duplicating or dropping records.
pub const RECEIVE_CHECKPOINT_MAGIC_ASCII: &str = "VFSRCPT1";
pub const RECEIVE_CHECKPOINT_MAGIC_BYTES: [u8; 8] = *b"VFSRCPT1";
pub const RECEIVE_CHECKPOINT_VERSION: u16 = 1;
/// Well-known name used to store the checkpoint inside the staging object
/// store.  Must not collide with transaction/root-slot keys.
pub const RECEIVE_CHECKPOINT_NAMED_KEY: &str = "tidefs-receive-checkpoint";
