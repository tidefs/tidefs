# tidefs-namespace

TideFS namespace layer: directory entry management with optional intent-log
recording.

## Overview

The namespace crate is the primary directory-entry primitive that the FUSE
adapter and higher-level filesystem consumers call. It maps directory paths
to inodes through the polymorphic directory index and provides entry types for
insert, lookup, and remove operations. Entry content hashing uses
`rustc-hash`'s fast non-cryptographic `FxHasher` for in-memory lookup
checks; storage persistence and cryptographic integrity are outside this
crate's directory-entry API.

## Architecture

```
FUSE handlers (tidefs-fuser)
         │
         ▼
  Namespace::create_file / create_dir / unlink / rename / lookup / resolve
         │
    ┌────┴────────────────────────────┐
    │  entry.rs       insert.rs       │
    │  lookup.rs      remove.rs       │
    │  (FxHasher content hash, intent)│
    └────┬────────────────────────────┘
         │
         ▼
  DirIndex (polymorphic: in-memory / persistent)
         │
         ▼
  tidefs-intent-log (optional IntentLogBuffer records)
```

## Modules

| Module | Purpose |
|--------|---------|
| `lib.rs` | `Namespace` struct, inode table, `MemInodeTable`, path resolution, create/lookup/unlink/rename/hard-link/symlink operations |
| `entry.rs` | `NamespaceEntry` with `rustc_hash::FxHasher` u64 content hash, `NamespaceEntryTombstone`, compute_entry_hash |
| `insert.rs` | `insert_entry()` and `insert_directory_entry()` with intent-log recording (Create, Mkdir, Symlink records) |
| `lookup.rs` | `lookup_entry()` and `lookup_path()` with multi-component traversal, `.`/`..` support, and symlink expansion up to `MAX_SYMLINK_DEPTH` |
| `remove.rs` | `remove_entry()` with intent-log recording (Unlink, Rmdir records) and `NamespaceEntryTombstone` creation |
| `metadata_engine.rs` | Multi-core metadata engine with per-core work queues and partitioned directory B-tree sharding |
| `persistence.rs` | `PersistentInodeStore` and `PersistentDirectoryStore` traits with in-memory implementations |
| `local_fs_persist.rs` | Local filesystem persistence backend (behind `local-fs-persist` feature flag) |

## Content Hash

Every `NamespaceEntry` carries a u64 content hash computed over
`(parent, name, ino, kind)` using `rustc_hash::FxHasher`, a fast
non-cryptographic hash function. This enables:

- **Field-change detection**: `entry.verify()` returns false if any hashed
  field changes.
- **Record comparison**: identical entries produce identical hashes, so
  consumers can compare already-applied operations.
- **Tombstone verification**: `NamespaceEntryTombstone` carries the removed
  entry's hash.

The namespace hash is not a storage-integrity check; it is only for in-memory
lookup performance.

## Intent-Log Recording

`insert_entry`, `insert_directory_entry`, and `remove_entry` accept an optional
`Arc<IntentLogBuffer>`. When provided, each operation appends a corresponding
`IntentLogRecord` variant:

| Operation | Record variant |
|-----------|---------------|
| File insert | `IntentLogRecord::Create` |
| Directory insert | `IntentLogRecord::Mkdir` |
| Symlink insert | `IntentLogRecord::Symlink` |
| File/symlink remove | `IntentLogRecord::Unlink` |
| Directory remove | `IntentLogRecord::Rmdir` |

The records are inputs to replay consumers. They do not settle rename atomicity
or higher-level replay behavior by themselves.

## Usage

```rust
use tidefs_namespace::{Namespace, ROOT_INODE, InodeAttributes};

let ns = Namespace::new();

// Create a file
let file_ino = ns.create_file(ROOT_INODE, "hello.txt",
    InodeAttributes::new_file(0))?;

// Look up by parent + name
assert_eq!(ns.lookup(ROOT_INODE, "hello.txt")?, Some(file_ino));

// Create a directory
let dir_ino = ns.create_dir(ROOT_INODE, "mydir",
    InodeAttributes::new_dir(0))?;

// Unlink a file
ns.unlink(ROOT_INODE, "hello.txt")?;
```

For operations with intent-log integration, use the module-level functions:

```rust
use tidefs_namespace::insert::insert_entry;
use tidefs_namespace::lookup::lookup_entry;
use tidefs_namespace::remove::remove_entry;
```

## Testing

```bash
cargo test -p tidefs-namespace
```

192 unit tests covering entry hashing, insert/remove CRUD, lookup with
multi-component paths, symlink expansion, intent-log round-trip, tamper
detection, tombstone verification, and content hash idempotency.
