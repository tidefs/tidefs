// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Clustered POSIX lock-forwarding adapter over LOCK transport.
//!
//! [`ClusteredPosixLockForwarder`] implements [`FusePosixLockDispatch`]
//! for clustered POSIX mounts by building identity-bound LOCK frames
//! (via [`LockServiceHandle`]) and sending them through a
//! [`LockServiceTransport`] / [`LockFrameSink`] transport boundary.
//!
//! Local POSIX mounts continue to use in-process [`DaemonLockDispatch`];
//! this forwarder is selected only for clustered mounts that have been
//! admitted through [`ClusteredPosixMountRuntime`].

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};

use tidefs_lock_service::{
    AcquireRequest, GetlkRequest, LeaseTarget, LockFrame, LockFrameSink, LockMode, LockPayload,
    LockServiceError, LockServiceHandle, LockServiceHandleError, LockServiceStatus,
    LockServiceTransport, MemberId, ReleaseRequest, ServiceLockOwner as LockOwner,
    ServiceRangeLockType as RangeLockType, SetlkRequest,
};
use tidefs_posix_filesystem_adapter_workers_locks::{LockConflict, LockRange, LockType};

use crate::clustered_mount::ClusteredPosixMountRuntime;
use crate::fuse_posix_lock::{FusePosixLockDispatch, FusePosixLockRequest};
use crate::lock_dispatch::LockDispatchError;

// ── Pending request state for synchronous dispatch ──────────────────

/// Outcome of a pending clustered lock dispatch that completed.
#[derive(Clone, Debug)]
enum ClusteredLockOutcome {
    /// getlk completed: `None` means no conflict, `Some(range)` describes
    /// the conflicting lock.
    Getlk(Option<LockRange>),
    /// setlk / setlkw / flock completed successfully.
    Acquired,
}

/// Grant-tracking key: (ino, owner_key, start, len).
type GrantKey = (u64, u64, u64, u64);

const FUSE_LOCK_TYPE_UNLCK: i32 = 2;

/// Inner state for a pending synchronous request.
struct PendingInner {
    result: Option<Result<ClusteredLockOutcome, LockDispatchError>>,
    /// When set, maps this pending request to a grant key so that
    /// [`handle_response`] can store the granted `lock_id`.
    request_key: Option<GrantKey>,
    /// True for blocking setlkw requests that remain pending after Queue acks.
    blocking: bool,
}

/// A synchronous pending request: the FUSE thread blocks on `signal`
/// until `result` is populated by [`handle_response`].
struct PendingRequest {
    signal: Arc<(Mutex<bool>, Condvar)>,
    inner: Mutex<PendingInner>,
}

impl PendingRequest {
    fn new(request_key: Option<GrantKey>, blocking: bool) -> Self {
        Self {
            signal: Arc::new((Mutex::new(false), Condvar::new())),
            inner: Mutex::new(PendingInner {
                result: None,
                request_key,
                blocking,
            }),
        }
    }

    /// Block the calling thread until a result is available or `timeout`
    /// elapses.  Returns `true` when a result was stored, `false` on timeout.
    fn wait_timeout(&self, timeout: std::time::Duration) -> bool {
        let (lock, cvar) = &*self.signal;
        let guard = lock.lock().unwrap();
        if *guard {
            return true;
        }
        let (new_guard, _timeout_result) = cvar.wait_timeout(guard, timeout).unwrap();
        *new_guard
    }

    fn set_result(&self, result: Result<ClusteredLockOutcome, LockDispatchError>) {
        let mut inner = self.inner.lock().unwrap();
        inner.result = Some(result);
        let (lock, cvar) = &*self.signal;
        let mut guard = lock.lock().unwrap();
        *guard = true;
        cvar.notify_all();
    }

    fn take_result(&self) -> Result<ClusteredLockOutcome, LockDispatchError> {
        self.inner
            .lock()
            .unwrap()
            .result
            .take()
            .expect("PendingRequest result not set")
    }

    fn request_key(&self) -> Option<GrantKey> {
        self.inner.lock().unwrap().request_key
    }

    fn blocking(&self) -> bool {
        self.inner.lock().unwrap().blocking
    }
}

// ── ClusteredPosixLockForwarder ──────────────────────────────────────

/// Clustered POSIX lock-forwarding adapter.
///
/// Implements [`FusePosixLockDispatch`] for clustered POSIX mounts by
/// building identity-bound LOCK frames and sending them through a
/// transport sink `S`.  Responses are delivered via [`handle_response`]
/// and wake blocked FUSE threads.
#[allow(dead_code)]
pub struct ClusteredPosixLockForwarder<S: LockFrameSink> {
    /// Committed mount identity and authority evidence from #632.
    runtime: ClusteredPosixMountRuntime,
    /// Identity-bound frame builder from #619.
    handle: LockServiceHandle,
    /// Transport adapter for sending encoded LOCK frames.
    transport: LockServiceTransport<S>,
    /// Local cluster member id used for per-request [`LockOwner`] construction.
    node_id: MemberId,
    /// Map from op_id → pending synchronous request.
    pending: BTreeMap<u64, Arc<PendingRequest>>,
    /// Tracked granted leases: (ino, owner_key, start, len) → lease_id.
    granted: BTreeMap<GrantKey, u64>,
    /// Terminal blocking setlkw responses surfaced on the FUSE retry path.
    terminal_failures: BTreeMap<GrantKey, LockDispatchError>,
    /// Default timeout for synchronous dispatch waits.
    dispatch_timeout: std::time::Duration,
    /// Leader endpoint for LOCK frames.
    leader: MemberId,
}

impl<S: LockFrameSink> ClusteredPosixLockForwarder<S> {
    /// Create a new forwarder.
    ///
    /// The [`LockServiceHandle`] is constructed from the mount identity
    /// committed by [`ClusteredPosixMountRuntime`].  `node_id` is the
    /// local cluster member identifier used in per-request [`LockOwner`]
    /// construction.  The LOCK leader endpoint is taken from the admitted
    /// runtime authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the mount identity is not committed.
    pub fn new(
        runtime: ClusteredPosixMountRuntime,
        node_id: MemberId,
        transport: LockServiceTransport<S>,
    ) -> Result<Self, LockServiceHandleError> {
        let handle =
            LockServiceHandle::new(LockOwner::new(node_id, 0, 0), runtime.mount_identity())?;
        let leader = runtime.lock_leader();
        Ok(Self {
            runtime,
            handle,
            transport,
            node_id,
            leader,
            pending: BTreeMap::new(),
            granted: BTreeMap::new(),
            terminal_failures: BTreeMap::new(),
            dispatch_timeout: std::time::Duration::from_secs(30),
        })
    }

    /// Return the committed mount runtime for inspection.
    pub fn runtime(&self) -> &ClusteredPosixMountRuntime {
        &self.runtime
    }

    /// Return a reference to the underlying transport.
    #[allow(dead_code)]
    pub fn transport(&self) -> &LockServiceTransport<S> {
        &self.transport
    }

    /// Return a mutable reference to the underlying transport.
    #[allow(dead_code)]
    pub fn transport_mut(&mut self) -> &mut LockServiceTransport<S> {
        &mut self.transport
    }

    /// Build a [`LockOwner`] for a specific FUSE lock request.
    fn lock_owner(&self, pid: u32, owner_key: u64) -> LockOwner {
        LockOwner::new(self.node_id, pid, owner_key)
    }

    /// Build and send a lock frame, then block on the response.
    ///
    /// `request_key` is stored alongside the pending entry so that
    /// [`handle_response`] can update the granted-lease map when the
    /// response includes a `lock_id`.
    fn dispatch_sync(
        &mut self,
        op_id: u64,
        frame: LockFrame,
        request_key: Option<GrantKey>,
    ) -> Result<ClusteredLockOutcome, LockDispatchError> {
        let pending = Arc::new(PendingRequest::new(request_key, false));
        self.pending.insert(op_id, Arc::clone(&pending));

        if let Err(err) = self.transport.send(self.leader, &frame) {
            self.pending.remove(&op_id);
            return Err(map_transport_error(err));
        }

        let outcome = if pending.wait_timeout(self.dispatch_timeout) {
            pending.take_result()
        } else {
            Err(LockDispatchError::Internal(
                "clustered lock dispatch timed out".into(),
            ))
        };

        self.pending.remove(&op_id);
        outcome
    }

    /// Handle a response frame received from the transport.
    ///
    /// Looks up the pending request by `op_id`, maps the response
    /// status to a [`ClusteredLockOutcome`] or [`LockDispatchError`],
    /// and wakes the blocked FUSE thread.
    pub fn handle_response(&mut self, response: LockFrame) {
        let op_id = match &response.payload {
            LockPayload::LockGrantEvent(event) => event.request_id,
            _ => response.op_id,
        };
        let result = match &response.payload {
            LockPayload::GetlkAck(ack) => match ack.status {
                LockServiceStatus::Granted => {
                    let conflict = ack.conflict.as_ref().map(|c| {
                        let (start, len) = match &c.target {
                            LeaseTarget::ByteRange { start, len, .. } => (*start, *len),
                            _ => (0, 0),
                        };
                        LockRange {
                            start,
                            len,
                            lock_type: lock_mode_to_lock_type(c.mode),
                            owner: 0,
                            pid: c.holder.0 as u32,
                        }
                    });
                    Ok(ClusteredLockOutcome::Getlk(conflict))
                }
                LockServiceStatus::DeniedConflict => {
                    Ok(ClusteredLockOutcome::Getlk(Some(LockRange {
                        start: 0,
                        len: 0,
                        lock_type: LockType::Write,
                        owner: 0,
                        pid: 0,
                    })))
                }
                _ => Err(map_lock_status(ack.status)),
            },
            LockPayload::SetlkAck(ack) => match ack.status {
                LockServiceStatus::Granted => {
                    // Track the granted lease for future release.
                    if let Some(p) = self.pending.get(&op_id) {
                        if let Some(key) = p.request_key() {
                            self.granted.insert(key, ack.lock_id);
                        }
                    }
                    Ok(ClusteredLockOutcome::Acquired)
                }
                LockServiceStatus::Queued => {
                    if self.pending.get(&op_id).is_some_and(|p| p.blocking()) {
                        return;
                    }
                    Err(LockDispatchError::Conflict(build_empty_conflict()))
                }
                LockServiceStatus::DeniedConflict => {
                    Err(LockDispatchError::Conflict(build_empty_conflict()))
                }
                _ => Err(map_lock_status(ack.status)),
            },
            LockPayload::AcquireAck(ack) => match ack.status {
                tidefs_lock_service::ServiceLockStatus::Granted => {
                    if let Some(p) = self.pending.get(&op_id) {
                        if let Some(key) = p.request_key() {
                            self.granted.insert(key, ack.lease_id);
                        }
                    }
                    Ok(ClusteredLockOutcome::Acquired)
                }
                tidefs_lock_service::ServiceLockStatus::DeniedConflict => {
                    Err(LockDispatchError::WouldBlock)
                }
                _ => Err(map_lease_status(ack.status)),
            },
            LockPayload::ReleaseAck(ack) => match ack.status {
                LockServiceStatus::Released | LockServiceStatus::NotFound => {
                    Ok(ClusteredLockOutcome::Acquired)
                }
                _ => Err(map_lock_status(ack.status)),
            },
            LockPayload::LockGrantEvent(event) => {
                if let Some(p) = self.pending.get(&op_id) {
                    if let Some(key) = p.request_key() {
                        self.granted.insert(key, event.lease_id);
                    }
                }
                Ok(ClusteredLockOutcome::Acquired)
            }
            _ => {
                // Unexpected response payload for a synchronous dispatch.
                return;
            }
        };

        if let Some(pending) = self.pending.remove(&op_id) {
            if pending.blocking() {
                if let Some(key) = pending.request_key() {
                    match &result {
                        Ok(_) => {
                            self.terminal_failures.remove(&key);
                        }
                        Err(err) => {
                            self.terminal_failures.insert(key, err.clone());
                        }
                    }
                }
            }
            pending.set_result(result);
        }
    }

    fn build_release_frame(&self, op_id: u64, lease_id: u64, owner: LockOwner) -> LockFrame {
        LockFrame::new(
            op_id,
            LockPayload::Release(ReleaseRequest {
                lease_id,
                owner,
                dataset_mount_id: self.handle.dataset_mount_id(),
                epoch: self.runtime.current_epoch(),
            }),
        )
    }
}

// ── FusePosixLockDispatch impl ──────────────────────────────────────

#[allow(dead_code)]
impl<S: LockFrameSink> FusePosixLockDispatch for ClusteredPosixLockForwarder<S> {
    fn getlk(
        &mut self,
        request: FusePosixLockRequest,
    ) -> Result<Option<LockRange>, LockDispatchError> {
        // F_UNLCK on getlk: no conflict to report.
        if request.typ == FUSE_LOCK_TYPE_UNLCK {
            return Ok(None);
        }

        let lock_type = fuse_type_to_range_lock_type(request.typ)
            .ok_or(LockDispatchError::InvalidLockType(request.typ as u32))?;

        let len = safe_len(request.start, request.end);
        let owner = self.lock_owner(request.pid, request.lock_owner);
        let op_id = fresh_op_id(&self.pending);
        let frame = LockFrame::new(
            op_id,
            LockPayload::Getlk(GetlkRequest {
                dataset_id: self.runtime.mount_identity().dataset_id,
                dataset_mount_id: self.handle.dataset_mount_id(),
                ino: request.ino,
                owner,
                lock_type,
                start: request.start,
                len,
                term: self.runtime.current_term(),
                epoch: self.runtime.current_epoch(),
            }),
        );

        match self.dispatch_sync(op_id, frame, None)? {
            ClusteredLockOutcome::Getlk(conflict) => Ok(conflict),
            _ => Ok(None),
        }
    }

    fn setlk(&mut self, request: FusePosixLockRequest) -> Result<(), LockDispatchError> {
        let len = safe_len(request.start, request.end);
        let owner = self.lock_owner(request.pid, request.lock_owner);

        // Unlock path: find the lease_id and send ReleaseRequest.
        if request.typ == FUSE_LOCK_TYPE_UNLCK {
            let key = (request.ino, request.lock_owner, request.start, len);
            if let Some(lease_id) = self.granted.remove(&key) {
                let op_id = fresh_op_id(&self.pending);
                let frame = self.build_release_frame(op_id, lease_id, owner);
                self.dispatch_sync(op_id, frame, None)?;
            }
            // If no lease found, treat as success (idempotent release).
            return Ok(());
        }

        let lock_type = fuse_type_to_range_lock_type(request.typ)
            .ok_or(LockDispatchError::InvalidLockType(request.typ as u32))?;

        let op_id = fresh_op_id(&self.pending);
        let frame = LockFrame::new(
            op_id,
            LockPayload::Setlk(SetlkRequest {
                dataset_id: self.runtime.mount_identity().dataset_id,
                dataset_mount_id: self.handle.dataset_mount_id(),
                ino: request.ino,
                owner,
                lock_type,
                start: request.start,
                len,
                term: self.runtime.current_term(),
                epoch: self.runtime.current_epoch(),
                blocking: false,
                callback_opaque: 0,
            }),
        );

        let key = (request.ino, request.lock_owner, request.start, len);
        self.dispatch_sync(op_id, frame, Some(key))?;
        Ok(())
    }

    fn setlkw(&mut self, request: FusePosixLockRequest) -> Result<(), LockDispatchError> {
        if request.typ == FUSE_LOCK_TYPE_UNLCK {
            return self.setlk(request);
        }

        let len = safe_len(request.start, request.end);
        let key = (request.ino, request.lock_owner, request.start, len);
        if let Some(err) = self.terminal_failures.remove(&key) {
            return Err(err);
        }
        if self.granted.contains_key(&key) {
            return Ok(());
        }

        let lock_type = fuse_type_to_range_lock_type(request.typ)
            .ok_or(LockDispatchError::InvalidLockType(request.typ as u32))?;

        let owner = self.lock_owner(request.pid, request.lock_owner);

        let op_id = fresh_op_id(&self.pending);
        let frame = LockFrame::new(
            op_id,
            LockPayload::Setlkw(SetlkRequest {
                dataset_id: self.runtime.mount_identity().dataset_id,
                dataset_mount_id: self.handle.dataset_mount_id(),
                ino: request.ino,
                owner,
                lock_type,
                start: request.start,
                len,
                term: self.runtime.current_term(),
                epoch: self.runtime.current_epoch(),
                blocking: true,
                callback_opaque: 0,
            }),
        );

        // For blocking setlkw, send the frame but do NOT block the
        // FUSE thread.  Spawn a thread that waits for the response
        // and notifies the WaiterSignal.
        let pending = Arc::new(PendingRequest::new(Some(key), true));
        self.pending.insert(op_id, Arc::clone(&pending));

        if let Err(e) = self.transport.send(self.leader, &frame) {
            self.pending.remove(&op_id);
            return Err(map_transport_error(e));
        }

        let signal = crate::lock_dispatch::WaiterSignal::new();
        let signal_clone = signal.clone();

        std::thread::spawn(move || {
            if pending.wait_timeout(std::time::Duration::from_secs(300)) {
                let _ = pending.take_result();
            }
            signal_clone.notify_all();
        });

        Err(LockDispatchError::Blocked { signal })
    }

    fn flock(
        &mut self,
        ino: u64,
        _fh: u64,
        lock_owner: u64,
        typ: u32,
    ) -> Result<(), LockDispatchError> {
        // F_UNLCK or unrecognised: release path.
        if typ > 1 {
            let key = (ino, lock_owner, 0, 0);
            if let Some(lease_id) = self.granted.remove(&key) {
                let op_id = fresh_op_id(&self.pending);
                let owner = self.lock_owner(0, lock_owner);
                let frame = self.build_release_frame(op_id, lease_id, owner);
                self.dispatch_sync(op_id, frame, None)?;
            }
            return Ok(());
        }

        let mode = if typ == 0 {
            LockMode::Shared
        } else {
            LockMode::Exclusive
        };
        let owner = self.lock_owner(0, lock_owner);
        let op_id = fresh_op_id(&self.pending);
        let frame = LockFrame::new(
            op_id,
            LockPayload::Acquire(AcquireRequest::new(
                LeaseTarget::Inode {
                    dataset_id: self.runtime.mount_identity().dataset_id,
                    ino,
                    parent_lease_id: 0,
                },
                mode,
                owner,
                self.handle.dataset_mount_id(),
                self.runtime.current_term(),
                self.runtime.current_epoch(),
            )),
        );

        let key = (ino, lock_owner, 0, 0);
        self.dispatch_sync(op_id, frame, Some(key))?;
        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Map a [`LockServiceStatus`] to [`LockDispatchError`].
fn map_lock_status(status: LockServiceStatus) -> LockDispatchError {
    match status {
        LockServiceStatus::DeniedFenced => {
            LockDispatchError::Internal("clustered lock denied: fenced".into())
        }
        LockServiceStatus::DeniedNotLeader => {
            LockDispatchError::Internal("clustered lock denied: not leader".into())
        }
        LockServiceStatus::DeniedQuota => {
            LockDispatchError::Internal("clustered lock denied: quota".into())
        }
        LockServiceStatus::InvalidRequest => {
            LockDispatchError::Internal("clustered lock denied: invalid request".into())
        }
        LockServiceStatus::NotFound => {
            LockDispatchError::Internal("clustered lock: not found".into())
        }
        LockServiceStatus::DeniedConflict => LockDispatchError::Conflict(build_empty_conflict()),
        _ => LockDispatchError::Internal(format!("clustered lock unexpected status: {status:?}")),
    }
}

/// Map a [`tidefs_lock_service::ServiceLockStatus`] to [`LockDispatchError`].
fn map_lease_status(status: tidefs_lock_service::ServiceLockStatus) -> LockDispatchError {
    match status {
        tidefs_lock_service::ServiceLockStatus::DeniedFenced => {
            LockDispatchError::Internal("clustered lock denied: fenced".into())
        }
        tidefs_lock_service::ServiceLockStatus::DeniedNotLeader => {
            LockDispatchError::Internal("clustered lock denied: not leader".into())
        }
        tidefs_lock_service::ServiceLockStatus::DeniedConflict => LockDispatchError::WouldBlock,
        tidefs_lock_service::ServiceLockStatus::DeniedQuota => {
            LockDispatchError::Internal("clustered lock denied: quota".into())
        }
        _ => LockDispatchError::Internal(format!(
            "clustered lock unexpected lease status: {status:?}"
        )),
    }
}

/// Map a [`LockServiceError`] from transport send failures to
/// [`LockDispatchError`].
fn map_transport_error(err: LockServiceError) -> LockDispatchError {
    LockDispatchError::Internal(format!("clustered lock transport error: {err}"))
}

/// Build an empty [`LockConflict`] for error responses that do not
/// carry detailed conflict information.
fn build_empty_conflict() -> LockConflict {
    let empty = LockRange {
        start: 0,
        len: 0,
        lock_type: LockType::Write,
        owner: 0,
        pid: 0,
    };
    LockConflict {
        requested: empty,
        existing: empty,
    }
}

/// Convert a FUSE lock type (`F_RDLCK` / `F_WRLCK`) to [`RangeLockType`].
fn fuse_type_to_range_lock_type(typ: i32) -> Option<RangeLockType> {
    match typ {
        0 => Some(RangeLockType::Read),  // F_RDLCK
        1 => Some(RangeLockType::Write), // F_WRLCK
        _ => None,
    }
}

/// Convert lock-service conflict mode into the POSIX range lock type reported
/// back through getlk.
fn lock_mode_to_lock_type(mode: LockMode) -> LockType {
    match mode {
        LockMode::None | LockMode::Shared => LockType::Read,
        LockMode::Exclusive => LockType::Write,
    }
}

/// Compute a safe length from start/end, treating `end == u64::MAX` as EOF.
fn safe_len(start: u64, end: u64) -> u64 {
    if end == u64::MAX {
        0
    } else {
        end.saturating_sub(start).saturating_add(1)
    }
}

/// Generate a fresh op_id that is not in the pending map.
fn fresh_op_id(pending: &BTreeMap<u64, Arc<PendingRequest>>) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(1_000_000);
    loop {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            continue;
        }
        if !pending.contains_key(&id) {
            return id;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clustered_mount::{
        ClusteredPosixAuthoritySnapshot, ClusteredPosixMountAdmissionError,
    };
    use tidefs_lock_service::{
        ConflictInfo, DatasetMountIdentity, EpochId, GetlkAck, QueuedLockFrameSink,
    };

    fn test_runtime() -> ClusteredPosixMountRuntime {
        let identity = DatasetMountIdentity {
            dataset_id: 1,
            mount_id: 2,
            committed_epoch: 5,
        };
        let authority = ClusteredPosixAuthoritySnapshot {
            current_epoch: EpochId::new(5),
            current_term: 7,
            lock_leader: MemberId::new(3),
            admission_generation: 11,
        };
        ClusteredPosixMountRuntime::open_committed_mount(identity, authority).unwrap()
    }

    fn test_forwarder() -> ClusteredPosixLockForwarder<QueuedLockFrameSink> {
        let runtime = test_runtime();
        let node_id = MemberId::new(1);
        let sink = QueuedLockFrameSink::default();
        let transport = LockServiceTransport::new(sink);
        ClusteredPosixLockForwarder::new(runtime, node_id, transport).unwrap()
    }

    #[derive(Debug, Default)]
    struct FailingLockFrameSink;

    impl LockFrameSink for FailingLockFrameSink {
        fn send_lock_frame(
            &mut self,
            peer: MemberId,
            _frame: Vec<u8>,
        ) -> Result<(), LockServiceError> {
            Err(LockServiceError::TransportClosed {
                peer,
                reason: "test sink closed".into(),
            })
        }
    }

    fn lock_request(
        ino: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
    ) -> FusePosixLockRequest {
        FusePosixLockRequest {
            ino,
            fh: 1,
            lock_owner,
            start,
            end,
            typ,
            pid,
        }
    }

    // ── Construction and admission ──────────────────────────────────

    #[test]
    fn forwarder_rejects_uncommitted_mount_identity() {
        let identity = DatasetMountIdentity {
            dataset_id: 0,
            mount_id: 0,
            committed_epoch: 0,
        };
        let err = ClusteredPosixMountRuntime::open_committed_mount(
            identity,
            ClusteredPosixAuthoritySnapshot {
                current_epoch: EpochId::new(5),
                current_term: 7,
                lock_leader: MemberId::new(3),
                admission_generation: 11,
            },
        )
        .unwrap_err();
        assert_eq!(err, ClusteredPosixMountAdmissionError::MissingIdentity);
    }

    #[test]
    fn forwarder_accepts_valid_mount_runtime() {
        let f = test_forwarder();
        assert_eq!(f.runtime().mount_identity().dataset_id, 1);
        assert_eq!(f.runtime().mount_identity().mount_id, 2);
        assert_eq!(f.runtime().current_epoch(), EpochId::new(5));
        assert_eq!(f.leader, f.runtime().lock_leader());
    }

    // ── Same-inode different mount identities ───────────────────────

    #[test]
    fn different_mount_identities_produce_different_dataset_mount_ids() {
        let rt1 = ClusteredPosixMountRuntime::open_committed_mount(
            DatasetMountIdentity {
                dataset_id: 1,
                mount_id: 10,
                committed_epoch: 5,
            },
            ClusteredPosixAuthoritySnapshot {
                current_epoch: EpochId::new(5),
                current_term: 7,
                lock_leader: MemberId::new(3),
                admission_generation: 11,
            },
        )
        .unwrap();

        let _rt2 = ClusteredPosixMountRuntime::open_committed_mount(
            DatasetMountIdentity {
                dataset_id: 1,
                mount_id: 20,
                committed_epoch: 5,
            },
            ClusteredPosixAuthoritySnapshot {
                current_epoch: EpochId::new(5),
                current_term: 7,
                lock_leader: MemberId::new(3),
                admission_generation: 11,
            },
        )
        .unwrap();

        let node_id = MemberId::new(1);
        let handle1 = LockServiceHandle::new(
            LockOwner::new(node_id, 0, 0),
            DatasetMountIdentity {
                dataset_id: 1,
                mount_id: 10,
                committed_epoch: 5,
            },
        )
        .unwrap();
        let handle2 = LockServiceHandle::new(
            LockOwner::new(node_id, 0, 0),
            DatasetMountIdentity {
                dataset_id: 1,
                mount_id: 20,
                committed_epoch: 5,
            },
        )
        .unwrap();

        assert_ne!(
            handle1.dataset_mount_id(),
            handle2.dataset_mount_id(),
            "different mount identities must produce different DatasetMountIds"
        );
        assert_eq!(rt1.mount_identity().mount_id, 10);
    }

    // ── Stale / fenced authority refusal ───────────────────────────

    #[test]
    fn stale_authority_epoch_refused_by_mount_runtime() {
        let identity = DatasetMountIdentity {
            dataset_id: 1,
            mount_id: 2,
            committed_epoch: 10,
        };
        let authority = ClusteredPosixAuthoritySnapshot {
            current_epoch: EpochId::new(5), // behind committed_epoch=10
            current_term: 7,
            lock_leader: MemberId::new(3),
            admission_generation: 11,
        };
        let err =
            ClusteredPosixMountRuntime::open_committed_mount(identity, authority).unwrap_err();
        assert_eq!(err, ClusteredPosixMountAdmissionError::StaleAuthorityEpoch);
    }

    #[test]
    fn fenced_authority_term_refused_by_mount_runtime() {
        let identity = DatasetMountIdentity {
            dataset_id: 1,
            mount_id: 2,
            committed_epoch: 5,
        };
        let authority = ClusteredPosixAuthoritySnapshot {
            current_epoch: EpochId::new(5),
            current_term: 0,
            lock_leader: MemberId::new(3),
            admission_generation: 11,
        };
        let err =
            ClusteredPosixMountRuntime::open_committed_mount(identity, authority).unwrap_err();
        assert_eq!(err, ClusteredPosixMountAdmissionError::MissingAuthorityTerm);
    }

    #[test]
    fn missing_lock_leader_refused_by_mount_runtime() {
        let identity = DatasetMountIdentity {
            dataset_id: 1,
            mount_id: 2,
            committed_epoch: 5,
        };
        let authority = ClusteredPosixAuthoritySnapshot {
            current_epoch: EpochId::new(5),
            current_term: 7,
            lock_leader: MemberId::new(0),
            admission_generation: 11,
        };
        let err =
            ClusteredPosixMountRuntime::open_committed_mount(identity, authority).unwrap_err();
        assert_eq!(
            err,
            ClusteredPosixMountAdmissionError::MissingLockAuthorityEndpoint
        );
    }

    // ── Forwarder rejects invalid lock types ───────────────────────

    #[test]
    fn forwarder_rejects_invalid_lock_type_on_getlk() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, 99, 1234);
        let result = f.getlk(req);
        assert!(matches!(
            result,
            Err(LockDispatchError::InvalidLockType(99))
        ));
    }

    #[test]
    fn forwarder_rejects_invalid_lock_type_on_setlk() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, 99, 1234);
        let result = f.setlk(req);
        assert!(matches!(
            result,
            Err(LockDispatchError::InvalidLockType(99))
        ));
    }

    #[test]
    fn getlk_unlock_reports_no_conflict_without_pending_request() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, FUSE_LOCK_TYPE_UNLCK, 1234);

        assert_eq!(f.getlk(req).unwrap(), None);
        assert!(f.pending.is_empty());
    }

    #[test]
    fn setlk_unlock_without_tracked_grant_is_idempotent_success() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, FUSE_LOCK_TYPE_UNLCK, 1234);

        f.setlk(req).unwrap();
        assert!(f.pending.is_empty());
        assert!(f.granted.is_empty());
    }

    #[test]
    fn setlkw_unlock_without_tracked_grant_uses_release_path() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, FUSE_LOCK_TYPE_UNLCK, 1234);

        f.setlkw(req).unwrap();
        assert!(f.pending.is_empty());
        assert!(f.granted.is_empty());
    }

    #[test]
    fn release_frame_uses_request_owner_and_mount_identity() {
        let f = test_forwarder();
        let owner = f.lock_owner(1234, 42);
        let frame = f.build_release_frame(7, 55, owner);

        match frame.payload {
            LockPayload::Release(request) => {
                assert_eq!(request.lease_id, 55);
                assert_eq!(request.owner, owner);
                assert_eq!(request.dataset_mount_id, f.handle.dataset_mount_id());
                assert_eq!(request.epoch, f.runtime.current_epoch());
            }
            payload => panic!("unexpected release payload: {payload:?}"),
        }
    }

    #[test]
    fn getlk_ack_conflict_preserves_reported_lock_mode() {
        fn delivered_conflict(mode: LockMode) -> LockRange {
            let mut f = test_forwarder();
            let op_id = fresh_op_id(&f.pending);
            let pending = Arc::new(PendingRequest::new(None, false));
            f.pending.insert(op_id, Arc::clone(&pending));

            f.handle_response(LockFrame::new(
                op_id,
                LockPayload::GetlkAck(GetlkAck {
                    status: LockServiceStatus::Granted,
                    conflict: Some(ConflictInfo {
                        lease_id: 77,
                        holder: MemberId::new(9),
                        target: LeaseTarget::ByteRange {
                            dataset_id: 1,
                            ino: 100,
                            start: 11,
                            len: 23,
                        },
                        mode,
                    }),
                }),
            ));

            match pending.take_result() {
                Ok(ClusteredLockOutcome::Getlk(Some(range))) => range,
                other => panic!("unexpected getlk result: {other:?}"),
            }
        }

        let shared = delivered_conflict(LockMode::Shared);
        assert_eq!(shared.start, 11);
        assert_eq!(shared.len, 23);
        assert_eq!(shared.lock_type, LockType::Read);

        let exclusive = delivered_conflict(LockMode::Exclusive);
        assert_eq!(exclusive.lock_type, LockType::Write);
    }

    #[test]
    fn send_failure_removes_pending_request() {
        let runtime = test_runtime();
        let mut f = ClusteredPosixLockForwarder::new(
            runtime,
            MemberId::new(1),
            LockServiceTransport::new(FailingLockFrameSink),
        )
        .unwrap();
        let req = lock_request(100, 42, 0, 99, 1, 1234);

        let err = f.setlk(req).unwrap_err();
        assert!(matches!(err, LockDispatchError::Internal(_)));
        assert!(f.pending.is_empty());
    }

    #[test]
    fn setlkw_granted_ack_tracks_lease_for_retry_and_unlock() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, 1, 1234);

        let signal = match f.setlkw(req) {
            Err(LockDispatchError::Blocked { signal }) => signal,
            other => panic!("expected blocked setlkw, got {other:?}"),
        };
        let op_id = *f.pending.keys().next().unwrap();

        f.handle_response(LockFrame::new(
            op_id,
            LockPayload::SetlkAck(tidefs_lock_service::SetlkAck {
                status: LockServiceStatus::Granted,
                lock_id: 77,
                conflict: None,
            }),
        ));

        assert!(signal.wait_timeout(std::time::Duration::from_millis(100)));
        assert!(f.pending.is_empty());
        assert_eq!(f.granted.get(&(100, 42, 0, 100)), Some(&77));

        f.setlkw(req).unwrap();
    }

    #[test]
    fn setlkw_queued_ack_waits_for_grant_event() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, 1, 1234);

        let signal = match f.setlkw(req) {
            Err(LockDispatchError::Blocked { signal }) => signal,
            other => panic!("expected blocked setlkw, got {other:?}"),
        };
        let op_id = *f.pending.keys().next().unwrap();

        f.handle_response(LockFrame::new(
            op_id,
            LockPayload::SetlkAck(tidefs_lock_service::SetlkAck {
                status: LockServiceStatus::Queued,
                lock_id: 0,
                conflict: None,
            }),
        ));
        assert!(f.pending.contains_key(&op_id));
        assert!(!signal.wait_timeout(std::time::Duration::from_millis(1)));

        f.handle_response(LockFrame::new(
            999,
            LockPayload::LockGrantEvent(tidefs_lock_service::LockGrantEvent {
                request_id: op_id,
                lease_id: 88,
                callback_opaque: 0,
                expires_at_millis: 123,
            }),
        ));

        assert!(signal.wait_timeout(std::time::Duration::from_millis(100)));
        assert!(f.pending.is_empty());
        assert_eq!(f.granted.get(&(100, 42, 0, 100)), Some(&88));
        f.setlkw(req).unwrap();
    }

    #[test]
    fn setlkw_terminal_ack_is_returned_on_retry() {
        let mut f = test_forwarder();
        let req = lock_request(100, 42, 0, 99, 1, 1234);

        let signal = match f.setlkw(req) {
            Err(LockDispatchError::Blocked { signal }) => signal,
            other => panic!("expected blocked setlkw, got {other:?}"),
        };
        let op_id = *f.pending.keys().next().unwrap();

        f.handle_response(LockFrame::new(
            op_id,
            LockPayload::SetlkAck(tidefs_lock_service::SetlkAck {
                status: LockServiceStatus::DeniedFenced,
                lock_id: 0,
                conflict: None,
            }),
        ));

        assert!(signal.wait_timeout(std::time::Duration::from_millis(100)));
        assert!(f.pending.is_empty());
        assert!(matches!(f.setlkw(req), Err(LockDispatchError::Internal(_))));
        assert!(f.pending.is_empty());
    }

    // ── Local-mode dispatch stays in-process ────────────────────────

    #[test]
    fn daemon_lock_dispatch_is_not_clustered_forwarder() {
        // Verify that DaemonLockDispatch does not have a transport field
        // and is a distinct type from ClusteredPosixLockForwarder.
        let daemon = crate::lock_dispatch::DaemonLockDispatch::new();
        assert!(daemon.is_empty());

        let _forwarder = test_forwarder();
        // Forwarder has transport; daemon does not.  They are separate
        // implementations of FusePosixLockDispatch.
    }

    // ── Pending request lifecycle ──────────────────────────────────

    #[test]
    fn pending_request_stores_and_retrieves_result() {
        let pending = PendingRequest::new(None, false);
        assert!(!pending.wait_timeout(std::time::Duration::from_millis(1)));
        pending.set_result(Ok(ClusteredLockOutcome::Acquired));
        assert!(pending.wait_timeout(std::time::Duration::from_millis(1)));
        let result = pending.take_result();
        assert!(matches!(result, Ok(ClusteredLockOutcome::Acquired)));
    }

    #[test]
    fn pending_request_stores_request_key() {
        let key = (1, 100, 0, 50);
        let pending = PendingRequest::new(Some(key), true);
        assert_eq!(pending.request_key(), Some(key));
        assert!(pending.blocking());
    }

    #[test]
    fn pending_request_no_key_returns_none() {
        let pending = PendingRequest::new(None, false);
        assert_eq!(pending.request_key(), None);
        assert!(!pending.blocking());
    }
}
