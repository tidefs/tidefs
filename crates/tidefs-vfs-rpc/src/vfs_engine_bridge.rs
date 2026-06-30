// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Admission hook for the future VFS_RPC-to-VFS-Engine bridge.
//!
//! This module intentionally does not forward requests. Issue #1570 only wires
//! the dependency/export hook so #1522 can implement the bridge without editing
//! crate wiring outside its expected write set. Any request reaching this hook
//! receives `ENOSYS` until that implementation lands.

use tidefs_types_vfs_core::Errno;
use tidefs_vfs_engine::VfsDispatch;

use crate::{VfsRpcError, VfsRpcRequest, VfsRpcResponse};

/// Fail-closed errno returned until the forwarding bridge lands.
pub const BRIDGE_FORWARDING_UNSUPPORTED: Errno = Errno::ENOSYS;

/// Dispatch target type consumed by the future bridge implementation.
pub type VfsEngineDispatchTarget = dyn VfsDispatch;

/// Build the placeholder response for a request that reached the bridge hook.
pub fn unavailable_response(request: &VfsRpcRequest) -> Result<VfsRpcResponse, VfsRpcError> {
    VfsRpcResponse::error(
        request.header.op_id,
        request.header.method,
        BRIDGE_FORWARDING_UNSUPPORTED,
    )
}

#[cfg(test)]
mod tests {
    use tidefs_types_vfs_core::{Errno, InodeId};

    use crate::{OpId, VfsRpcRequest, VfsRpcRequestPayload, VfsRpcResponsePayload};

    use super::{unavailable_response, BRIDGE_FORWARDING_UNSUPPORTED};

    #[test]
    fn bridge_hook_fails_closed_without_forwarding() {
        let request = VfsRpcRequest::new(
            OpId::new(42),
            7,
            9,
            0,
            VfsRpcRequestPayload::Lookup {
                parent: InodeId::new(1),
                name: b"child".to_vec(),
            },
            None,
        )
        .unwrap();

        let response = unavailable_response(&request).unwrap();

        assert_eq!(BRIDGE_FORWARDING_UNSUPPORTED, Errno::ENOSYS);
        assert_eq!(response.method, request.header.method);
        assert_eq!(response.header.op_id, request.header.op_id);
        assert_eq!(response.header.errno, Errno::ENOSYS);
        assert_eq!(response.payload, VfsRpcResponsePayload::Empty);
    }
}
