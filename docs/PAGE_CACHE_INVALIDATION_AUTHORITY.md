# Page Cache Invalidation Authority

Maturity: current design decision for TFR-008 and GitHub issue #736.

Decision id: `tfr-008.page_cache_invalidation_authority.v1`.

This document decides when TideFS implementations must invalidate or fence page
cache mirrors after local filesystem mutations, kernel cache events, storage
engine generation changes, lease revocation, and cluster epoch transitions. It
is a design authority boundary only. It does not implement invalidation,
eviction, lease protocols, kernel page-cache notifications, mmap fault
handling, or runtime validation.

The dirty/writeback durability contract remains in
`docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`. This document defines the trigger and
coherency side of that boundary: which event makes cached bytes stale, what
granularity is required, and what generation a reader must prove before serving
cached bytes.

## Scope

This authority covers:

- clean page-cache mirrors in the FUSE adapter, kernel module, and shared cache
  crates;
- dirty or writeback ranges that overlap a coherency event and therefore must
  be fenced, drained, retried, or classified before stale bytes can be served;
- metadata and dentry invalidation only where they decide whether page bytes
  are still reachable through the same dataset/inode identity;
- lease-revocation and epoch-transition events that clustered mounts will
  consume for cross-node cache coherency.

This authority does not cover:

- writeback persistence, `fsync`, `fdatasync`, `syncfs`, `flush`, or crash
  recovery ordering, except to say when invalidation must wait for them;
- private mmap copy-on-write bytes;
- FUSE lookup/forget durable inode ownership, which is decided by
  `docs/INODE_NAMESPACE_AUTHORITY.md` and issue #665;
- POSIX lock identity or lock transport behavior from issues #618 and #633;
- cache admission and memory-budget policy from issue #685;
- claim-gate evidence reconciliation from issue #697.

## Authority Terms

| Term | Authority meaning |
|---|---|
| Invalidation intent | A coherency event that removes or fences stale clean cache and waits for dirty/writeback state instead of silently discarding it. |
| Clean mirror | Cached bytes that match the generation from which they were filled and have no local dirty or writeback owner. |
| Dirty owner | The writeback authority responsible for bytes that differ from the currently committed storage view. |
| Writeback owner | The active writeback operation that may turn dirty bytes into clean bytes only if the cache generation still matches at completion. |
| Destructive data mutation | A committed operation that changes which bytes are reachable at an inode/range, such as truncate shrink, hole punch, collapse range, insert range, zero range, or last-close removal. |
| Generation fence | A token that prevents cached bytes from being served after a newer dataset, inode, range, or lease generation supersedes them. |
| Advisory invalidation | A best-effort hint to evict clean cache. Correctness still depends on the stale-generation rule before reads. |
| Mandatory invalidation | A required fence before an operation, lease grant, or epoch transition may publish success to a caller or peer. |

## Evidence Reviewed

The decision is based on the following current evidence.

Documentation:

- `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` defines invalidation as removing or
  fencing stale clean cache while waiting for dirty/writeback state instead of
  discarding it. It also records that `tidefs-cache-coherency` may evict clean,
  unpinned entries while preserving dirty and writeback entries.
- `docs/INODE_NAMESPACE_AUTHORITY.md` decides that mounted inode identity is
  dataset scoped. FUSE lookup counts, forget refcounts, path lookup caches, and
  negative caches are projections, not durable inode ownership.
- `docs/REVIEW_TODO_REGISTER.md` keeps TFR-008 open because recovery, fsync,
  writeback, mmap, and page-cache authority are not yet proven as one runtime
  contract.

Current source:

- `crates/tidefs-cache-coherency/src/lib.rs` provides an invalidation event bus
  with range, inode, and full-cache subscriber callbacks for lease revocation
  and membership epoch transitions.
- `crates/tidefs-cache-core/src/page_cache.rs` invalidates clean, unpinned,
  non-writeback pages for ordinary coherency invalidation. It also has
  truncate and unlink helpers that remove dirty/writeback pages only after the
  destructive operation has made that range or inode unreachable and the dirty
  tracking is cleared.
- `crates/tidefs-cache-core/src/path_lookup_cache.rs` caches positive and
  negative dentries with explicit child, parent, inode, and full-cache
  invalidation hooks.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs`
  records dentry invalidation generations for child mutations and renames,
  invalidates metadata caches after engine writes, invalidates read-side caches
  after direct writes, and reconciles dirty mirrors after authoritative range
  mutations.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_lookup_forget.rs`
  still treats lookup/forget reference accounting separately from durable inode
  identity. Issue #665 owns the implementation cleanup for that projection.

Issue evidence:

- Closed issue #443 proved the cache-core dirty/writeback/clean lifecycle and
  current invalidation behavior in focused cache tests.
- Closed issue #511 created the page-cache writeback authority document.
- Open issues #618, #633, #665, #685, and #697 own non-overlapping adjacent
  slices. This decision does not implement or preempt their write sets.
- Open issues #597 and #720 keep rename and orphan-index admission evidence
  separate from invalidation authority.

## Decision

TideFS page-cache invalidation is generation based and dataset scoped.

The dataset inode authority owns the identity tuple for cached page bytes:

```text
(dataset_id, inode_id, inode_generation)
```

The storage or mounted engine authority owns the byte-generation tuple for a
specific cached range:

```text
(file_size_generation, range_generation, lease_epoch)
```

A cache entry may serve a read only while both tuples still match the current
mounted authority and the reader holds, or can acquire, the required local
lease for the requested access. A stale clean entry is dropped or refilled. A
dirty or writeback entry whose generation is superseded is not silently
discarded as durable data; it is fenced and handed to the writeback authority
for drain, retry, or a classified superseded result.

The generation rule is the correctness boundary. Kernel notifications, FUSE
TTL expiration, daemon cache eviction, and cluster invalidation messages are
delivery mechanisms. Missing or delayed delivery must not allow stale cached
bytes to be served after a generation mismatch is visible to the mount.

## Trigger Surface

The following operations must advance or check page-cache invalidation
authority at the named granularity.

| Trigger | Required granularity | Authority rule |
|---|---|---|
| Buffered write accepted by the mounted engine | Written byte range, plus inode metadata when size or privilege bits change | The written range becomes the current range generation. Read-side clean mirrors overlapping the range must be refreshed or invalidated before later reads can use them. Dirty trackers for the same range stay with the writeback authority. |
| Direct I/O write or any engine write that bypasses the adapter page cache | Written byte range | Mandatory range invalidation or reconciliation. Dirty mirrors overlapping the range must be fenced so later writeback cannot replay older bytes over the authoritative write. |
| `truncate` shrink | `[new_size, old_size)` plus the boundary page and inode size metadata | Mandatory range invalidation. Dirty/writeback ranges beyond the new EOF must be drained, retried against the new EOF, or classified as superseded by the successful truncate before success is published. |
| `truncate` grow | `[old_size, new_size)` plus inode size metadata | Newly exposed bytes are authoritative zeroes or holes under a new range generation. Any speculative clean mirror in that span is stale. |
| Hole punch or zero range | Punched or zeroed byte range | Mandatory range invalidation or clean zero reconciliation. Dirty/writeback overlap must not be written back later as old data. |
| Collapse range | From collapse offset to EOF, plus inode size metadata | Mandatory suffix invalidation because byte offsets after the collapse shift. A narrow invalidation of only the removed span is insufficient. |
| Insert range | From insert offset to EOF, plus inode size metadata | Mandatory suffix invalidation because byte offsets after the insertion shift and the inserted span has a new zero or hole generation. |
| Server-side copy or clone into a file | Destination byte range, plus metadata if size changes | Destination clean mirrors are stale. Source clean mirrors remain valid unless the operation also mutates the source. |
| Rename without overwrite | Old and new dentries only | Page data stays valid because inode identity and range generations do not change. Path, negative, and parent-dir caches must invalidate the old and new names. |
| Rename with overwrite | Old and new dentries; overwritten target inode under unlink rules | Source inode page data stays valid. The overwritten target follows unlink/orphan invalidation semantics. |
| Unlink while links remain or open handles keep the inode alive | Dentry and metadata invalidation; data remains handle/inode-generation scoped | Path lookups must stop resolving the name. Page data remains valid only through the still-live inode generation and open-handle authority. |
| Last-link removal with no live handle, or orphan last close | Whole inode | Mandatory inode invalidation. Cached data for that inode generation is no longer reachable. |
| Lease revocation for a conflicting writer or reader | Lease range, inode, or dataset according to the revoked lease | Mandatory before granting the conflicting lease. Clean mirrors are removed or fenced. Dirty/writeback overlap must drain, transfer authority, or reject/fence the conflicting grant. |
| Dataset epoch transition, snapshot rollback, receive publication, or mount generation change | Dataset, or the affected inode/range set when the transition supplies a narrower map | Mandatory generation fence. A mount must not serve cache from the old epoch unless the transition explicitly proves the same dataset/inode/range generation remains current. |
| FUSE forget | No page-data invalidation by itself | Forget releases kernel lookup references. It may make later metadata cleanup possible, but it does not decide byte reachability or dirty-data durability. |
| Kernel TTL expiration or advisory FUSE notification | Advisory range, inode, or dentry | Useful for memory pressure and prompt coherency, but not sufficient as the correctness rule. Reads still validate the generation tuple. |

## FUSE And Kernel Coherency Contract

FUSE lookup, forget, dentry TTLs, attribute TTLs, kernel page-cache state, and
daemon page-cache state are projections of mounted dataset authority.

FUSE forget is advisory for page data. It releases kernel references and may
allow reclaim, but it must not drop dirty data or decide that an inode's page
bytes are no longer reachable. Unlink, orphan last-close, truncate, range
mutation, lease revocation, or epoch transition must provide that authority.

Kernel page-cache invalidation is mandatory when the kernel could otherwise
serve bytes from an older generation after a destructive mutation or external
lease revocation. If the adapter cannot prove the kernel accepted a precise
notification, the mount must record a generation fence so the next read, fault,
or writeback completion cannot trust the old cache state.

Daemon read caches and cache-core page caches follow the same rule. Clean
entries may be evicted eagerly. Dirty and writeback entries may be removed
only when the owning operation has made the bytes unreachable or has reconciled
them with the current authoritative payload; otherwise they remain fenced
until writeback, retry, or error classification finishes.

## Race Rules

### Invalidation Versus Writeback

Writeback completion may mark a page clean only when the page still belongs to
the same dataset, inode, range, file-size, and lease generation that the
writeback owner started with. If any generation changed, completion must
reconcile against the new authority. The result is one of:

- retry writeback for the new range generation;
- keep the page dirty and report or retain a writeback error;
- classify the range as superseded by a successful destructive mutation;
- drop only clean state that no longer carries dirty/writeback authority.

### Invalidation Versus Direct I/O

Direct I/O and other authoritative engine writes bypass cached byte mirrors.
Before a later buffered read or writeback can use a cached page overlapping the
direct-write range, the cache must either hold the direct-write payload as the
current range generation or have no readable cached page for that range.

### Invalidation Versus Mmap Faults

An mmap fault takes a generation snapshot before installing or returning a
page. If an invalidation races with the fault, the fault must retry against
the new generation or install a fenced page that cannot satisfy reads until
refreshed. Shared writable mmap dirties join the writeback authority before
they can be invalidated as clean cache.

### Invalidation Versus Kernel Notifications

FUSE or kmod notification failure is not a reason to serve stale bytes. It is
a reason to keep or raise a generation fence and force refault/refill on the
next access. Best-effort notification may improve latency, but generation
validation owns correctness.

## Lease And Epoch Model

Clustered mounts consume a monotonically increasing cache epoch for each
dataset authority. A future lease implementation must be able to express:

- dataset id and mount/session id;
- inode id and inode generation;
- byte range, or whole-inode/dataset scope;
- old and new range generations;
- lease epoch and membership epoch;
- invalidation reason;
- wait policy: advisory, wait-for-clean-eviction, wait-for-dirty-drain, or
  fence-and-error.

Before a node grants a conflicting write lease or publishes a new membership
epoch, it must know that old clean mirrors are invalidated or fenced and that
dirty/writeback overlap is drained, transferred, rejected, or fenced. The
model is dataset/inode/range scoped; it does not authorize a global
cross-dataset cache lock as the default coherency mechanism.

## Follow-Up Implementation Map

The implementation work is intentionally split so each issue has a
non-overlapping owner. These issues implement the decision after this document
lands; they are not part of this slice.

| Issue | Slice | Primary write set | Boundary |
|---|---|---|---|
| #752 | FUSE data-cache invalidation and generation fences. | `apps/tidefs-posix-filesystem-adapter-daemon/src/` data-cache, notification, mmap-coherency, and adapter tests only. | Must wait until active issue #665 / PR #709 clears or records an explicit non-overlap. Does not edit durable lookup/forget ownership. |
| #753 | Kernel page-cache coherency notifications and stale-generation checks. | `kmod/`, `crates/tidefs-kmod-posix-vfs/`, kernel-facing validation hooks, and focused kernel cache tests. | Owns kernel invalidation/fault/writeback checks. Does not change FUSE adapter policy or clustered lease transport. |
| #754 | Clustered cache lease and epoch invalidation plumbing. | `crates/tidefs-cache-coherency/`, `crates/tidefs-lease/`, `crates/tidefs-lease-manager/`, `crates/tidefs-membership-epoch/`, `crates/tidefs-transport/`, and focused lease/transport tests as needed. | Owns cross-node invalidation messages and wait policies. Does not implement POSIX lock forwarding from #633 or cache admission from #685. |

## Validation For This Decision

This issue is documentation/design work. The required validation is bounded
source and issue inspection against the evidence above and `git diff --check`.

No runtime, Cargo, Nix, QEMU, xfstests, RDMA, kernel, or mounted validation is
required for this authority document.
