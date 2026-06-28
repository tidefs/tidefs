# VFS_RPC Wire Protocol — Design Specification

**Issue**: [#1234](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1234)
**Status**: design-spec
**Priority**: P1
**Lane**: transport
**Depends on**: #1213 (VFS Engine contract), #1210 (transport boundedness), #1228 (security model)

## Abstract

This document defines the VFS_RPC wire protocol: the canonical encoding for
forwarding VfsEngine operations (#1213) over the cluster transport. Every VFS
operation receives a stable 6-bit method ID, a common request/response framing
with term/epoch fencing, an idempotency contract via per-peer op_id dedup
windows, a unified payload model (InlineOrBulkV1) that delegates large data to
the BULK plane (#1229), and serializable handle encoding that makes in-process
file/dir handles transferable across nodes.

VFS_RPC is service_id `0x06` in the tidefs cluster service registry. It is the
primary data-plane protocol: all POSIX filesystem operations that require
cluster forwarding flow through this service.

---

## 1. Service Definition

### 1.1 Wire identity

```
service_id   = 0x06
service_name = "vfs_rpc"
message_type = request | response
```

Each VFS_RPC frame is a standard cluster message (#1210) with `service_id = 0x06`.
The method is encoded in the low 6 bits of the message-type byte. The high 2 bits
distinguish request (0b00) from response (0b01), leaving 0b10 and 0b11 reserved.

### 1.2 Dispatch rule

A VfsEngine operation is dispatched by its method ID. The receiver parses the
message type byte, extracts `method_id = msg_type & 0x3F`, and routes to the
appropriate VfsEngine handler. Unknown method IDs return `ENOSYS`.

### 1.3 Method space

The 6-bit method space (0x00–0x3F, 64 slots) is allocated as follows:

| Range | Allocation |
|---|---|
| 0x00–0x2F | VfsEngine ops (46 slots reserved for expansion) |
| 0x30–0x37 | Future VFS_RPC control messages |
| 0x38–0x3F | Reserved for transport-layer extensions |

---

## 2. Method ID Table

### 2.1 Complete method catalog

Every VfsEngine operation has a stable method ID. The assignment is NOT
sequential — it groups related operations so the 6-bit space has room for
future additions within each group.

#### 2.1.1 Namespace operations (0x00–0x0F)

| Method | ID  | VfsEngine op | Semantics |
|---|---|---|---|
| `LOOKUP`        | 0x00 | `lookup(dir_handle, name)` | Single-component name resolution; returns `(ino, attr)` or `ENOENT` |
| `MKNOD`         | 0x01 | `mknod(dir_handle, name, mode, rdev)` | Create special file; parent dir must be writable |
| `MKDIR`         | 0x02 | `mkdir(dir_handle, name, mode)` | Create subdirectory; `nlink++` on parent |
| `UNLINK`        | 0x03 | `unlink(dir_handle, name)` | Remove directory entry; decrement `nlink` |
| `RMDIR`         | 0x04 | `rmdir(dir_handle, name)` | Remove empty subdirectory |
| `SYMLINK`       | 0x05 | `symlink(dir_handle, name, target)` | Create symbolic link with `target` content |
| `READLINK`      | 0x06 | `readlink(inode)` | Read symlink target; may split across multiple reads for long targets |
| `RENAME`        | 0x07 | `rename(src_dir, src_name, dst_dir, dst_name)` | Atomic rename; `RENAME_NOREPLACE`/`RENAME_EXCHANGE` via flags |
| `LINK`          | 0x08 | `link(inode, new_dir, new_name)` | Hard link; `nlink++` on inode; `EMLINK` if at limit |
| `CREATE`        | 0x0E | `create(dir_handle, name, mode, flags)` | Combined lookup + create + open; returns `(ino, attr, fh)` |

Reserved in namespace block: 0x09–0x0D, 0x0F (6 slots for future namespace ops).

#### 2.1.2 Attribute operations (0x10–0x1F)

| Method | ID  | VfsEngine op | Semantics |
|---|---|---|---|
| `GETATTR`       | 0x10 | `getattr(inode)` | Returns full `VfsAttr` struct |
| `SETATTR`       | 0x11 | `setattr(inode, attr_mask, attr)` | Partial attribute update; validity mask controls which fields |
| `GETXATTR`      | 0x09 | `getxattr(inode, name)` | Extended attribute read; `ERANGE` if buffer too small |
| `SETXATTR`      | 0x0A | `setxattr(inode, name, value, flags)` | XATTR_CREATE / XATTR_REPLACE via flags |
| `LISTXATTR`     | 0x0B | `listxattr(inode)` | Return concatenated null-terminated xattr names |
| `REMOVEXATTR`   | 0x0C | `removexattr(inode, name)` | Remove extended attribute; `ENODATA` if absent |
| `ACCESS`        | 0x0D | `access(inode, mask)` | Permission check against caller credentials |

Reserved in attribute block: 0x12–0x1F (14 slots for future attribute ops).

#### 2.1.3 Handle lifecycle (0x14–0x1D)

| Method | ID  | VfsEngine op | Semantics |
|---|---|---|---|
| `OPEN`          | 0x12 | `open(inode, flags)` | Open file; returns `fh`; `O_CREAT` handled via CREATE |
| `CLOSE`         | 0x13 | `close(fh)` | Close file handle; release locks |
| `FLUSH`         | 0x19 | `flush(fh, lock_owner)` | Flush dirty cache for handle; may return cached write errors |
| `RELEASE`       | 0x1A | `release(fh, flags)` | Final close; file handle is invalid after this call |
| `OPENDIR`       | 0x14 | `opendir(inode)` | Open directory for reading; returns `dh` |
| `CLOSEDIR`      | 0x15 | `closedir(dh)` | Close directory handle |
| `RELEASEDIR`    | 0x1B | `releasedir(dh)` | Final close of directory handle |
| `FORGET`        | 0x1C | `forget(inode, nlookup)` | Drop `nlookup` references; inode may be evicted when count reaches 0 |

#### 2.1.4 Data operations (0x20–0x2F)

| Method | ID  | VfsEngine op | Semantics |
|---|---|---|---|
| `READ`          | 0x20 | `read(fh, offset, len)` | Read file data; returns `InlineOrBulkV1` |
| `WRITE`         | 0x21 | `write(fh, offset, data)` | Write file data; `data` is `InlineOrBulkV1` |
| `FSYNC`         | 0x22 | `fsync(fh, datasync)` | Flush dirty data for handle; `datasync=true` → fdatasync |
| `FALLOCATE`     | 0x23 | `fallocate(fh, mode, offset, len)` | Allocate/deallocate/punch space; mode from `FALLOC_FL_*` |
| `LSEEK_DATA`    | 0x24 | `lseek(fh, offset, SEEK_DATA)` | Find next data offset ≥ `offset` |
| `LSEEK_HOLE`    | 0x25 | `lseek(fh, offset, SEEK_HOLE)` | Find next hole offset ≥ `offset` |
| `FIEMAP`        | 0x26 | `fiemap(fh, start, len)` | Return extent map for byte range |
| `TRUNCATE`      | 0x27 | `truncate(inode, len)` | Set file size; may free extents |
| `COPY_FILE_RANGE` | 0x28 | `copy_file_range(src_fh, src_off, dst_fh, dst_off, len, flags)` | Server-side copy; may use reflink |

Reserved in data block: 0x29–0x2F (7 slots for future data ops).

#### 2.1.5 Locking operations (within data block)

| Method | ID  | VfsEngine op | Semantics |
|---|---|---|---|
| `LOCK_GET`      | 0x29 | `getlk(fh, lock)` | Test for conflicting lock |
| `LOCK_SET`      | 0x2A | `setlk(fh, lock, block)` | Acquire lock; `block=false` → non-blocking `setlk` |

#### 2.1.6 Directory operations (0x16–0x1E)

| Method | ID  | VfsEngine op | Semantics |
|---|---|---|---|
| `READDIR`       | 0x16 | `readdir(dh, offset)` | Read directory entries; offset is cookie |
| `READDIRPLUS`   | 0x17 | `readdirplus(dh, offset)` | Read dir entries + stat each; reduces round-trips |
| `DIR_REV`       | 0x1E | `dir_rev(dh)` | Get directory revision cookie for change detection |
| `STATFS`        | 0x18 | `statfs(inode)` | Filesystem statistics |

### 2.2 Future allocation policy

New methods are assigned to the next available slot within their semantic block.
When a block is exhausted, the next contiguous free block is allocated. A method
ID is never reassigned — deprecated ops retain their ID, and the method handler
returns `ENOSYS` if the feature is disabled.

---

## 3. Common Request Framing

### 3.1 VfsRpcReqCommonV1 (fixed prefix for every request)

Every VFS_RPC request opens with this 44-byte common prefix:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           op_id                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           term                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           epoch                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          flags               |        method_id             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        payload_len                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         creds_len                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Size | Description |
|---|---:|---:|---|
| `op_id` | 0 | 8 | Idempotency key; stable across retries; u64 LE |
| `term` | 8 | 8 | Writer lease term; u64 LE |
| `epoch` | 16 | 8 | Writer lease epoch; u64 LE |
| `flags` | 24 | 2 | Request flags (see §3.2) |
| `method_id` | 26 | 2 | Method ID from §2; u16 LE (full width, not 6-bit) |
| `payload_len` | 28 | 4 | Length of method-specific payload; u32 LE |
| `creds_len` | 32 | 4 | Length of credential blob; u32 LE; 0 = no credentials |
| `reserved` | 36 | 8 | Reserved; must be zero |

Total fixed prefix: 44 bytes. Minimum alignment: 8 bytes.

### 3.2 Request flags

| Bit | Name | Description |
|---|---:|---|
| 0 | `REQ_FLAG_BULK_PENDING` | WRITE with BULK payload: bulk transfer not yet complete; responder must wait |
| 1 | `REQ_FLAG_NO_DEDUP` | Bypass idempotency dedup for this request (one-shot ops) |
| 2 | `REQ_FLAG_UPTODATE_OK` | Read: locally-served stale data is acceptable (relaxes coherency) |
| 3–15 | reserved | Must be zero |

### 3.3 Credential blob

The credential blob follows the method-specific payload. It carries the
authenticated peer identity from the security model (#1228):

```
credential_blob:
  peer_id: u64        -- stable peer identifier
  auth_tag: [u8; 16]  -- HMAC tag covering (peer_id, op_id, method-specific payload)
  uid: u32            -- caller UID (or NOBODY if forwarded)
  gid: u32            -- caller GID
  groups_len: u16     -- number of supplementary groups
  groups: [u32; groups_len]
```

method handler is invoked. Mismatch → `EACCES`.

---

## 4. Common Response Framing

### 4.1 VfsRpcRespCommonV1 (fixed prefix for every response)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           op_id                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            errno             |           flags               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        payload_len                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Size | Description |
|---|---:|---:|---|
| `op_id` | 0 | 8 | Echo of request op_id (for response matching) |
| `errno` | 8 | 2 | POSIX errno; 0 = success; u16 LE |
| `flags` | 10 | 2 | Response flags (see §4.2) |
| `payload_len` | 12 | 4 | Length of method-specific response payload; u32 LE |
| `reserved` | 16 | 8 | Reserved; must be zero |

Total fixed prefix: 24 bytes. Minimum alignment: 8 bytes.

### 4.2 Response flags

| Bit | Name | Description |
|---|---:|---|
| 0 | `RESP_FLAG_BULK` | Response payload uses BULK path; `payload` is a `BulkToken` |
| 1 | `RESP_FLAG_DEDUP_REPLAY` | This response is replayed from the dedup cache |
| 2 | `RESP_FLAG_TRUNCATED` | Inline response was truncated to fit max_frame_bytes |
| 3–15 | reserved | Must be zero |

---

## 5. Idempotency Contract

### 5.1 op_id generation

The forwarding daemon (typically the FUSE daemon on the client node) generates
a monotonically increasing `op_id` per operation. The `op_id` is unique within
a `(peer_identity, lifespan)` scope and is stable across retries of the same
logical operation.

Consequence: if the FUSE daemon resends the same `LOOKUP(dir_handle, "foo")`
after a transport timeout, it reuses the same `op_id`. The writer sees the
duplicate and replays the cached response.

### 5.2 Per-peer dedup window

The writer maintains a per-peer LRU dedup cache:

| Parameter | Value | Rationale |
|---|---|---|
| Window size | 65536 entries | Enough to cover worst-case in-flight ops under congestion |
| Key | `(peer_identity_bytes, op_id)` | Peer identity from transport handshake (#1228) |
| Value | `(errno, flags, response_payload)` | Full response as serialized bytes |
| Eviction | LRU; oldest entry dropped first | Simpler than time-based; bounds memory |
| TTL | Not used | Dedup by eviction only; retry window is bounded by transport timeout |

Retry handling:

1. Writer receives request with `(peer_identity, op_id)` in dedup cache.
2. If `REQ_FLAG_NO_DEDUP` is set: skip cache lookup; process as new request.
3. If match found: respond with cached `(errno, payload)` with `RESP_FLAG_DEDUP_REPLAY` set.
4. If no match: process normally, cache the response before sending.

### 5.3 Idempotency boundaries

Idempotent by construction (same inputs → same outputs):
- `READ`, `GETATTR`, `ACCESS`, `STATFS` — pure reads
- `LSEEK_DATA`, `LSEEK_HOLE`, `FIEMAP` — read-only extent queries
- `GETXATTR`, `LISTXATTR` — read-only xattr queries
- `READDIR`, `READDIRPLUS`, `DIR_REV` — read-only directory queries
- `READLINK` — read-only symlink resolution

Idempotent via dedup replay (must go through dedup cache):
- `WRITE` — same `(fh, offset, data)` → same result
- `MKDIR`, `UNLINK`, `RMDIR`, `SYMLINK`, `RENAME`, `LINK`, `MKNOD`, `CREATE` — first execution succeeds; replay returns original result
- `SETATTR`, `SETXATTR`, `REMOVEXATTR` — same mutation, same result
- `TRUNCATE`, `FALLOCATE` — same extent operation
- `LOCK_SET` — lock state is deterministic for same input

Not idempotent — `REQ_FLAG_NO_DEDUP` recommended:
- `RELEASE`, `RELEASEDIR` — handle is destroyed after first call; retry gets `EBADF`
- These are terminal operations; retry is handled at the FUSE layer, not RPC


- The peer disconnects (transport layer teardown)
- The writer's term/epoch changes (lease lost → all cached responses stale)
- The per-peer window fills and oldest entries are evicted (LRU)

---

## 6. Fencing Contract

### 6.1 Term and epoch

Every request carries a `(term, epoch)` tuple from the writer lease. These are
obtained by the forwarding daemon from the cluster membership service and
refreshed on lease changes.

- `term`: monotonically increasing writer lease number. Incremented on leader
  election. A higher term always supersedes a lower term.
- `epoch`: sub-counter within a term. Incremented on lease refresh. Enables
  fine-grained staleness detection without term churn.

### 6.2 Fence check

On receipt of a mutating request:

```
function fence_check(req):
    current = cluster_state.get_writer_lease(dataset_id)
    if req.term < current.term:
        return ESTALE
    if req.term == current.term and req.epoch < current.epoch:
        return ESTALE
    return OK
```

If the fence check fails, the writer responds with `ESTALE` and does not
execute the operation. The forwarding daemon must re-resolve the writer
location (the membership service will point to the new leader), obtain the
current `(term, epoch)`, and retry.

### 6.3 Which ops require fencing

| Operation class | Fencing required | Rationale |
|---|---|---|
| Mutations (WRITE, UNLINK, RENAME, MKDIR, TRUNCATE, FALLOCATE, etc.) | Yes | Prevent split-brain writes from stale writers |
| Handle lifecycle (OPEN, CREATE, CLOSE, RELEASE) | Yes | Handle state must be consistent with current writer |
| Locking (LOCK_SET, LOCK_GET) | Yes | Lock state is writer-local |
| Reads (READ, GETATTR, READDIR) | No | Served locally or forwarded without fence; coherency via generation (#1242) |
| Stateless reads (ACCESS, STATFS, READLINK) | No | No side effects |

### 6.4 Fencing on read forwarding

When reads are forwarded to the writer (e.g., when the client lacks a SHARED
lease), fencing is NOT required — the writer serves reads regardless of
term/epoch. This is because a stale writer that still holds the lease can
legitimately serve reads, and reads don't create split-brain risk.

---

## 7. Handle Serialization

### 7.1 Transferable handles

All handles (`EngineFileHandle`, `EngineDirHandle`) are serializable opaque
blobs, not in-process pointers. A handle received from one node can be sent
to another node, and the receiving node can resolve it to internal state.

### 7.2 Handle wire format

```
VfsHandleV1:
  handle_type: u8    -- 0=FILE, 1=DIR
  flags: u8          -- handle flags (see §7.3)
  dataset_id: u128   -- dataset UUID
  inode: u64         -- inode number
  generation: u64    -- inode generation (detects reuse)
  writer_node: u64   -- owning writer node id
  handle_cookie: u64 -- opaque writer-local handle identifier
```

Total: 48 bytes. Fixed size, no variable-length fields.

### 7.3 Handle flags

| Bit | Name | Description |
|---|---:|---|
| 0 | `HANDLE_FLAG_READ` | Handle was opened for reading |
| 1 | `HANDLE_FLAG_WRITE` | Handle was opened for writing |
| 2 | `HANDLE_FLAG_APPEND` | Handle is append-only |
| 3 | `HANDLE_FLAG_DIRECT` | O_DIRECT semantics |
| 4 | `HANDLE_FLAG_DSYNC` | O_DSYNC semantics |
| 5 | `HANDLE_FLAG_SYNC` | O_SYNC semantics |
| 7 | reserved | Must be zero |

### 7.4 Handle resolution

When a node receives a handle in a VFS_RPC request:

1. Extract `writer_node`. If `writer_node != self.node_id`: this request was
   forwarded to the wrong node. Return `ESTALE` with no payload — the caller
   re-resolves.
3. Look up `(inode, generation)` in the inode cache. If `generation` doesn't
   match: return `ESTALE` (inode was deleted and reallocated).
4. Resolve `handle_cookie` to the writer-local handle state. If not found:
   return `EBADF`.

### 7.5 Handle scoping

Handles are scoped to an authenticated peer context (§3.3). The writer
associates each handle with the peer that created it. Operations on a handle
from a different peer are rejected with `EACCES` — handles are NOT transferable
across clients. Cross-client operations must open their own handles.

---

## 8. InlineOrBulkV1 Payload Encoding

### 8.1 Format

```
InlineOrBulkV1:
  kind: u8             -- 0=INLINE, 1=BULK
  // INLINE variant (kind=0):
  data_len: u32        -- length of inline data
  data: [u8; data_len] -- inline payload
  // BULK variant (kind=1):
  bulk_token: BulkToken -- opaque 32-byte bulk transfer token
  bulk_len: u64         -- total bytes available via BULK
```

### 8.2 Threshold rule

The inline threshold is `max_frame_bytes` from the transport boundedness
contract (#1210). Default: 128 KiB. Payloads ≤ threshold use INLINE; larger
payloads MUST use BULK.

### 8.3 WRITE with BULK

When a WRITE carries `InlineOrBulkV1 { kind: BULK }`, the prepended
common request has `REQ_FLAG_BULK_PENDING` set. The writer knows the bulk
transfer is in progress (via the BULK service, #1229) and waits for it to
complete before processing the WRITE.

Sequence:
1. Client sends WRITE RPC with `InlineOrBulkV1 { kind: BULK, bulk_token, bulk_len }`
2. Client initiates bulk transfer via BULK service with same `bulk_token`
3. Writer receives WRITE RPC, sees `REQ_FLAG_BULK_PENDING`, waits for BULK service to signal completion
4. BULK transfer completes; writer processes WRITE, caches response, sends reply

If the bulk transfer fails or times out, the writer discards the WRITE and
returns `ETIMEDOUT`. The client may retry with a new `op_id`.

### 8.4 READ with BULK

When the writer's response would exceed the inline threshold:

1. Writer allocates a `bulk_token` via the BULK service.
2. Writer sends response with `InlineOrBulkV1 { kind: BULK, bulk_token, bulk_len }`
   and `RESP_FLAG_BULK` set.
3. Writer initiates bulk transfer of the read data via BULK service.
4. Client receives response, extracts `bulk_token`, and pulls data via BULK service.

If the BULK transfer fails, the client retries the READ with a new `op_id`.

### 8.5 Small-read optimization

For reads ≤ inline threshold: the response uses `InlineOrBulkV1 { kind: INLINE, data }`.
No BULK overhead. This is the common case for FUSE reads (typically 128 KiB or
less per FUSE_READ request).

---

## 9. Read Forwarding Policy

### 9.1 Decision matrix

Whether a read is forwarded to the writer or served locally depends on the
dataset's coherency profile (#1184) and the client's lease state:

| Profile | Client has SHARED lease? | Served by | Notes |
|---|---|---|---|
| `strict` | No | Forward to writer | Forwarded GETATTR/READ |
| `perf` | Yes or No | Client local (best-effort) | Uses generation check; stale data possible |
| `cluster` | No | Forward to writer | As `strict` |
| `auto` | Yes | Client local | Heuristic; may forward under write contention |
| `auto` | No | Forward to writer | Default behavior |

### 9.2 Local read serving prerequisites

To serve reads locally, a client must:

1. Hold a SHARED dataset lease (acquired from membership service)
3. Track per-inode generation numbers for staleness detection (#1242)

### 9.3 Forwarded read request format

A forwarded read uses the same VfsRpcReqCommonV1 framing as any other request.
The forwarding daemon sets `REQ_FLAG_UPTODATE_OK` if the client's coherency
profile allows best-effort stale reads. The writer may ignore this flag for
strict profiles.

---

## 10. Error Codes

All standard POSIX errno values are supported. VFS_RPC adds these protocol-level
error codes:

| Errno | Value | Meaning |
|---|---|---|
| `ESTALE` | 116 | Term/epoch mismatch; writer lease changed; re-resolve and retry |
| `ENOSYS` | 38 | Unknown method ID; feature not supported by this writer |
| `ETIMEDOUT` | 110 | BULK transfer timed out before WRITE could complete |
| `EBADF` | 9 | Handle cookie not found; handle was released or never valid |
| `EACCES` | 13 | Peer identity mismatch; handle belongs to different peer |
| `ERANGE` | 34 | `GETXATTR`/`LISTXATTR`: value too large for provided buffer |

---

## 11. Integration with Cluster Services

### 11.1 Transport service (#1210)

VFS_RPC frames are transported as standard cluster messages. Frame limits:
- Max request frame: `max_frame_bytes` (default 128 KiB) — inline payloads
- Max response frame: `max_frame_bytes` — inline responses
- Larger payloads MUST use BULK path

### 11.2 BULK service (#1229)

The `InlineOrBulkV1 { kind: BULK }` variant delegates data transfer to the BULK
service. The VFS_RPC handler only processes the control path; data flows
through BULK. Credit management, RDMA scheduling, and flow control are the
BULK service's responsibility.

### 11.3 Security service (#1228)

Peer identity from the transport handshake is carried in the credential blob
- `auth_tag` matches `HMAC(peer_key, op_id || payload)`
- `peer_id` in credential matches transport-layer peer identity
- `uid`/`gid` are authorized for the requested operation

### 11.4 Membership service

The `(term, epoch)` tuple in every request is obtained from the writer lease.
The membership service provides the current writer location and lease state.
Clients refresh on ESTALE response.



---

## 12. Live Transport-Binding Decision (#1518)

### 12.1 Evidence reviewed

Issue #1518 reviewed the current VFS_RPC integration boundary from these
sources:

- Closed #836 and the `docs/workspace-package-classification.md` row: the
  `tidefs-vfs-rpc` crate is current wire-protocol authority, but service
  integration remains a follow-up claim.
- This document, `docs/design/cluster-bulk-plane-protocol.md`, and TFR-017 in
  `docs/REVIEW_TODO_REGISTER.md`: VFS_RPC carries control frames and
  `InlineOrBulkV1` descriptors; BULK owns byte movement, credit accounting, and
  RDMA scheduling; transport/cluster authority remains open before multi-node
  product claims.
- Source inspection: `crates/tidefs-vfs-rpc` implements service id `0x06`,
  stable methods, request/response headers, credentials, transferable handles,
  `InlineOrBulk`, transport frame wrappers, client correlation, and a bounded
  dedup window. The repo has `tidefs-transport`, `tidefs-vfs-engine`, and
  transport-session models, but no `tidefs-bulk-service` crate yet.
- Live GitHub state on 2026-06-28: the initial overlap search for VFS_RPC,
  `tidefs-vfs-rpc`, `BulkToken`, BULK/RDMA, cluster forwarding, VFS Engine
  forwarding, and transport binding found #1518 as the only open
  VFS_RPC-specific issue before this decision branch opened. The resulting
  child map is #1521-#1524, with non-overlapping implementation/evidence write
  sets for the transport adapter, VFS Engine bridge, BULK/RDMA handoff, and
  validation records. Current open PR file inspection found only the #1525
  decision PR touching this document or `docs/workspace-package-classification.md`.

### 12.2 Alternatives

1. **TCP-only VFS_RPC binding**. Bind service `0x06` directly to the existing
   TCP-backed transport and carry every operation inline.

   Rejected as the complete boundary. TCP is the right first transport substrate
   for control/inline frames, but a pure TCP-only design either pushes large
   file data through the control path or invents a second byte-mover outside
   the BULK contract. It may be used only as the initial carrier for frames
   whose payload fits `max_frame_bytes`.

2. **VFS_RPC control path with BULK-plane data movement**.

   Selected. The first live boundary is a VFS_RPC control/inline forwarding path
   over the current transport envelope, with `InlineOrBulkV1` preserving the
   explicit handoff to the BULK plane. Until #1523 lands a live BULK service
   handoff, implementations must reject or defer `REQ_FLAG_BULK_PENDING` and
   `RESP_FLAG_BULK` rather than treating missing byte movement as success.

3. **RDMA-capable VFS_RPC/BULK boundary**.

   Deferred. RDMA belongs behind BULK and transport/security/runtime evidence
   gates: peer authentication, pinned-memory budgets, rkey/addr credit
   lifecycle, abort cleanup, hardware/runtime validation, and TFR-017 transport
   authority. No VFS_RPC implementation may claim RDMA readiness by selecting a
   TCP fallback or by moving inline data only.

### 12.3 Selected first implementation boundary

The first implementation boundary is:

- A transport adapter for VFS_RPC service `0x06` control frames (#1521).
- A writer-side VFS Engine bridge for inline operations (#1522).
- An explicit unsupported/deferred result for BULK descriptors until the
  `InlineOrBulkV1`/`BulkToken` handoff is implemented (#1523).
- Focused validation evidence for exactly the landed forwarding surface (#1524).

This boundary is safe to implement because it does not require source behavior
outside the VFS_RPC transport adapter and VFS Engine bridge, and it preserves
BULK/RDMA as separate evidence-gated work. It is not safe to advertise as
multi-node product readiness, release-candidate readiness, RDMA readiness, or
storage semantics authority.

### 12.4 Minimum forwarding contract

The selected boundary requires the following contract before any forwarded
operation reaches a writer-side engine:

- **Writer discovery and lease input**: callers obtain the writer node,
  dataset identity, and writer lease from membership/runtime authority before
  emitting a VFS_RPC request. VFS_RPC consumes that input; it does not choose a
  writer or originate a lease.
- **Term/epoch handling**: every request carries the `(term, epoch)` from the
  writer lease. The writer validates the tuple before side effects. Stale,
  mismatched, or wrong-writer requests return `ESTALE` so the caller
  re-resolves membership and retries as a new lease attempt.
- **`op_id` dedup window**: the writer keeps the existing bounded per-peer
  dedup cache. Retries of the same logical operation reuse `op_id`; completed
  responses may be replayed with `RESP_FLAG_DEDUP_REPLAY`; entries are evicted
  by the fixed window; `REQ_FLAG_NO_DEDUP` bypasses this cache only for
  explicitly one-shot paths. A BULK failure before engine dispatch inserts no
  success entry.
- **Peer credentials**: the transport-authenticated peer identity must match
  `VfsRpcCredentials.peer_id`. The credential `auth_tag` covers the peer,
  `op_id`, and method payload; uid, gid, and supplementary groups become the
  writer-side request context. Mismatch returns `EACCES`.
- **Transferable handles**: a received file or directory handle must match the
  local writer node, dataset, inode generation, handle cookie, and
  authenticated peer. Wrong writer or generation returns `ESTALE`; unknown or
  released cookies return `EBADF`; cross-peer handle use returns `EACCES`.
- **`InlineOrBulkV1` handoff**: inline payloads stay inside VFS_RPC frames and
  must fit `max_frame_bytes`. BULK payloads carry only a same-connection
  `BulkToken` and length. WRITE with `REQ_FLAG_BULK_PENDING` waits for BULK
  DONE before engine dispatch; READ with `RESP_FLAG_BULK` requires the writer
  to create the BULK transfer and make the token readable by the requester.
  Without a live BULK handoff, the VFS_RPC implementation must return an
  explicit unsupported/deferred error rather than silently truncating,
  inlining, or claiming success.

### 12.5 Follow-up map

- #1521, `vfs-rpc-transport-adapter`: owns service `0x06` transport wrapping,
  dispatch registration, frame-size enforcement, session/peer errors, and
  control/inline-only behavior.
- #1522, `vfs-rpc-vfs-engine-bridge`: owns writer lease validation, VFS Engine
  dispatch, per-peer dedup replay, credentials, and handle resolution for
  inline operations.
- #1523, `vfs-rpc-bulk-rdma-handoff`: owns the `InlineOrBulkV1`/`BulkToken`
  handoff and keeps RDMA behind BULK, security, transport, memory-budget, and
  runtime evidence gates.
- #1524, `vfs-rpc-forwarding-validation`: owns focused evidence records and
  workflow run URLs for the forwarding boundary after the implementation
  issues land.

### 12.6 Residual unknowns

- The exact transport service-registration API may require a small adapter
  module or a dispatch hook in `tidefs-transport`; #1521 owns that choice.
- The VFS Engine bridge must map the VFS_RPC method catalog to the current
  `VfsDispatch`/`VfsEngine` response types without changing storage semantics;
  #1522 owns any method-level gaps.
- A live BULK service API is absent in the current workspace; #1523 must either
  introduce or identify that surface before VFS_RPC accepts BULK descriptors as
  live.
- RDMA runtime proof, partition recovery, cross-replica repair closure, and
  distributed transaction authority remain outside this boundary under TFR-017.

## 13. Non-Claims

This design does not cover:

- **ADMIN_RPC protocol**: admin operations (pool management, device control) use
  a separate service (#1243) with its own method table.
- **VFS_RPC service discovery**: how clients discover the writer node for a
  dataset is the membership service's responsibility.
- **Transport encryption**: wire encryption is handled by the transport layer,
  not VFS_RPC. The credential blob is authenticated but not encrypted in-band.
- **Flow control**: backpressure and per-connection scheduling are handled by
  the unified scheduling classes (#1241), not VFS_RPC.
- **Method versioning**: method IDs are stable. Behavior changes are gated by
  dataset-level feature flags. A `METHOD_CAPABILITIES` control message (slot
  0x30) is reserved for future capability negotiation.
- **Compound operations**: multi-op transactions (e.g., RENAME + SETATTR) are
  deferred to a future design. VFS_RPC carries single operations only.
- **RDMA readiness**: VFS_RPC does not claim RDMA transport readiness; RDMA is
  gated by the BULK handoff and TFR-017 transport evidence.
- **Multi-node product readiness**: a service `0x06` forwarding path is not a
  complete clustered POSIX, placement, recovery, repair, or operator UAPI
  claim.
- **Release-candidate status**: this design and its follow-up issues do not
  imply release-candidate readiness or broad runtime validation.
- **Storage semantics authority**: VFS_RPC carries requests and responses; the
  VFS Engine, storage, placement, recovery, and transaction layers retain
  authority for filesystem semantics and durability.

---

## 14. References

- `docs/design/on-media-format-strategy.md` — V1 format framework (#1220)
- Issue #1213 — VFS Engine API contract
- Issue #1210 — Transport boundedness
- Issue #1229 — BULK plane protocol
- Issue #1228 — Security and identity model
- Issue #1184 — Named coherency profiles
- Issue #1241 — Unified scheduling classes
- Issue #1242 — Generation-based staleness discipline
- Issue #1243 — ADMIN service wire protocol
