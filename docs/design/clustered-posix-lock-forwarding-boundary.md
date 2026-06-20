# Clustered POSIX LOCK Forwarding Boundary

Date: 2026-06-20
Status: Current spec, scoped to issue #626

This record decides the mounted clustered POSIX boundary that may construct and
own `tidefs_lock_service::LockServiceHandle`. It is not implementation proof
that a clustered POSIX mount exists today. It is the contract that follow-up
issues must satisfy before clustered FUSE/VFS lock forwarding can replace the
current placeholder handle identity.

## Evidence Reviewed

- ADR-0007, `docs/adr/0007-local-and-clustered-posix-block-modes.md`, accepts
  explicit local and clustered POSIX modes.
- `docs/ARCHITECTURE.md` states that local POSIX uses in-process
  mount/session state while clustered POSIX uses MEMBERSHIP, lease, and LOCK
  services.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs` opens
  `LocalFileSystem` in `mount_vfs`.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs`
  constructs `DaemonLockDispatch` in `FuseVfsAdapter::new` and forwards FUSE
  lock operations to that in-process dispatch.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/lock_dispatch.rs` owns
  the current local daemon lock state. It uses the lock-service model types
  in-process, not a cluster transport handle.
- `crates/tidefs-lock-service/src/lib.rs` defines `LockServiceHandle`,
  `LockServiceTransport<S: LockFrameSink>`, and the LOCK leader model. The
  current handle still builds acquire and release frames with
  `DatasetMountId(0)` and accepts grants against `DatasetMountIdentity::ZERO`.
- `crates/tidefs-membership-epoch/src/lib.rs` defines
  `DatasetMountIdentity { dataset_id, mount_id, committed_epoch }` and
  `EpochId`.
- GitHub history #444/#456 added dataset mount scoping to lock-service
  protocol state and left `LockServiceHandle` with the zero placeholder.
- GitHub history #469/#490 added committed mount identity and epoch binding
  to lease lifecycle types.
- GitHub #615/#617 produced ADR-0007 and split local POSIX (#618) from
  clustered POSIX (#619).
- GitHub #619 investigation found no current clustered mounted boundary that
  can provide identity, epoch, term, and LOCK transport without rerouting
  local POSIX locks.

## Decision

Clustered POSIX lock forwarding gets an explicit mounted boundary. The owner
of clustered `LockServiceHandle` construction is a new clustered mount runtime
inside `apps/tidefs-posix-filesystem-adapter-daemon`, not the existing local
`mount_vfs` path and not `FuseVfsAdapter::new`.

The implementation issues must introduce this boundary, or update this design
record before choosing different names:

- `clustered_mount::ClusteredPosixMountRuntime::open_committed_mount(...)`
  admits a clustered POSIX mount after cluster admission and lease bootstrap
  produce committed identity and authority evidence.
- `clustered_mount::ClusteredPosixLockForwarder::new(...)` constructs and owns
  the identity-bound `LockServiceHandle` plus its `LockServiceTransport`.
- Local `mount_vfs` continues to construct `LocalFileSystem` and
  `FuseVfsAdapter::new`; that local adapter continues to own
  `DaemonLockDispatch`.

`ClusteredPosixMountRuntime` is the mounted boundary. It owns the identity and
authority snapshot for the mounted clustered dataset. `ClusteredPosixLockForwarder`
is the lock-specific child of that boundary. It may be implemented as a FUSE
lock dispatch adapter, a VFS lock-forwarding adapter, or a narrower helper
below FUSE, but it must be selected only by the clustered mount runtime.

## Identity Supplier

The clustered mount boundary supplies one committed mount identity and one
current authority snapshot.

The committed identity is `DatasetMountIdentity` from
`tidefs-membership-epoch`:

- `dataset_id`: the dataset admitted for this clustered POSIX mount.
- `mount_id`: the unique clustered mount instance admitted for this session.
- `committed_epoch`: the membership epoch in which that mount identity became
  committed.

The current authority snapshot must include:

- `current_epoch: EpochId`, read from the committed membership epoch source
  used by the mounted clustered runtime.
- `current_term: u64`, read from the current LOCK/lease authority term source
  for the clustered dataset.
- `lock_leader: MemberId`, or the equivalent routed authority endpoint for
  the current LOCK service leader.
- Enough admission generation or session binding evidence to prove that the
  cached `DatasetMountIdentity` is still the identity admitted for this mount.

The clustered lock forwarder passes the committed mount id into
`LockServiceHandle` and passes the current term and epoch into each LOCK frame.
It must not derive those values from command-line flags, local single-node
defaults, or the local POSIX `MountIdentity` used by permission checks.

## LOCK Transport Boundary

The forwarding boundary is `tidefs_lock_service::LockServiceTransport<S>`
where `S: LockFrameSink`. The clustered POSIX implementation supplies a
transport sink over the TideFS CONTROL lane, or the current equivalent
clustered transport route, to the LOCK leader named by the authority snapshot.

`ClusteredPosixLockForwarder` owns:

- an identity-bound `LockServiceHandle`;
- a `LockServiceTransport<ClusterLockFrameSink>` or equivalent sink wrapper;
- the current authority snapshot needed to build and route request frames.

The lock-service crate may provide the handle and frame validation, but it
does not own mounted identity admission. The transport sink may serialize and
route frames, but it does not invent dataset id, mount id, epoch, or term.

## Refusal Rules

The clustered mounted boundary must fail closed before forwarding when any of
these facts are unavailable or stale:

- `DatasetMountIdentity::ZERO` or any zero placeholder is selected for a
  normal clustered mounted request.
- `current_epoch` is older than the identity `committed_epoch`.
- The cached identity no longer matches the cluster admission or session
  binding for the mounted dataset.
- The current term or LOCK leader snapshot is missing or known stale.
- The request target dataset does not match the committed identity dataset.

The LOCK service authority remains the final fence. #619 narrows
`tidefs-lock-service` work so the leader rejects mismatched request identity
where the crate can check it:

- request `DatasetMountId` must match
  `LockServiceConfig.current_mount_identity.mount_id` when that config is
  set;
- request target dataset id must match
  `LockServiceConfig.current_mount_identity.dataset_id` for dataset, inode,
  and byte-range targets;
- request term and epoch continue through the existing fencing path and
  return fenced denial when they do not match the authority.

Implementations may choose the exact POSIX errno mapping at the FUSE boundary,
but they must not convert a stale clustered identity or fenced LOCK reply into
local in-process success.

## Local POSIX Boundary

The existing local FUSE/VFS path remains outside clustered LOCK transport:

- `mount_vfs` opens `LocalFileSystem`.
- `FuseVfsAdapter::new` constructs `DaemonLockDispatch`.
- FUSE `getlk`, `setlk`, `setlkw`, and `flock` calls dispatch to
  `DaemonLockDispatch`.
- Local POSIX does not construct `LockServiceHandle`, does not open
  `LockServiceTransport`, and does not depend on MEMBERSHIP, lease-manager,
  or cluster leader availability.

This is required by ADR-0007. Sharing helper code with clustered mode is
allowed only after the local mode remains in-process and the ADR-0007
non-regression evidence is satisfied.

## Alternatives

### Explicit Clustered FUSE Mount Mode

Accepted. A clustered mount mode is the only boundary that has all required
facts: committed mounted dataset identity, current epoch, current term, and
transport route. It also keeps the local `mount_vfs` path direct.

### VFS Lock-Forwarding Adapter Below FUSE

Accepted only as an internal child of the clustered mount runtime. FUSE can
hand parsed lock requests to a lower adapter, but the lower adapter must
receive identity and authority from the clustered mounted boundary. It cannot
be the outer owner by itself because it does not admit the mount.

### Handle Owner In A Lock-Service Transport Client Crate

Rejected as the mounted owner. A transport client can serialize frames and may
hold a reusable sink, but it cannot decide which dataset mount identity is
committed or which epoch/term is current. Putting ownership there would either
invent identity or require local POSIX callers to carry clustered state they
must not use.

### Defer All Work Until Cluster Admission Exists

Partially accepted as an implementation gate. Product source must not add
placeholder clustered FUSE plumbing until the mounted boundary can produce
committed identity and authority evidence. The design boundary is still
recorded now so #619 can be narrowed and future issues do not overlap.

## Follow-Up Map

- #618 owns local POSIX in-process mount identity. It must not construct
  `LockServiceHandle`, use MEMBERSHIP, or open LOCK transport.
- #619 is narrowed to `crates/tidefs-lock-service/src/lib.rs`: make
  `LockServiceHandle` identity-bound, stop emitting `DatasetMountId(0)` for
  normal clustered handles, record grants with the handle identity, and add
  leader-side identity/epoch refusal tests where the lock-service crate has
  authority.
- #632 owns the clustered POSIX mounted admission boundary in
  `apps/tidefs-posix-filesystem-adapter-daemon`, including committed
  `DatasetMountIdentity`, current `EpochId`, current term, and LOCK authority
  endpoint exposure. It must not implement lock-service handle/frame behavior.
- #633 owns the later clustered FUSE/VFS LOCK transport forwarding adapter.
  It depends on #632 for mounted identity/authority and on #619 for the
  identity-bound handle. It must keep local POSIX on `DaemonLockDispatch`.

This split leaves #626 as a design and coordination issue. Product source
changes belong to the follow-up issues above.
