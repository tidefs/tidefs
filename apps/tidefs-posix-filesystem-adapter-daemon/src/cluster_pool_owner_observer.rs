// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Authenticated read-only observation of the current clustered Pool owner.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tidefs_auth::{NodeKeyStore, NodePrivateCredential, NodePublicIdentity};
use tidefs_cluster::{
    ClusterPoolMessage, ClusterPoolOwnerObservationRequest, ClusterPoolOwnerObservationResponse,
};
use tidefs_transport::{
    EndpointFamily, NodeInfo, SessionCloseReason, Transport, TransportAddr, TransportError,
};

const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);
const OBSERVATION_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const CLUSTER_POOL_MAGIC: &[u8; 4] = b"CP01";

/// Current owner evidence measured conservatively onto this process's clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPoolOwnerObservation {
    /// Pool whose current owner was observed.
    pub pool_guid: [u8; 16],
    /// Current committed Pool owner node.
    pub owner_node_id: u64,
    /// Membership epoch in which ownership is valid.
    pub membership_epoch: u64,
    /// Current single-writer fence generation.
    pub write_fence_generation: u64,
    /// Conservative process-local end of the observed lease lifetime.
    pub valid_until: Instant,
}

impl AuthenticatedPoolOwnerObservation {
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.valid_until.saturating_duration_since(Instant::now())
    }
}

/// Authenticate the exact configured lease authority and observe one Pool.
pub fn observe_pool_owner(
    authority_addr: SocketAddr,
    expected_pool_guid: [u8; 16],
    local_credential: &NodePrivateCredential,
    trusted_authority_identity: &NodePublicIdentity,
) -> Result<AuthenticatedPoolOwnerObservation, String> {
    if expected_pool_guid == [0; 16] {
        return Err("Pool owner observation expected Pool GUID must be nonzero".to_string());
    }
    let local_identity = local_credential.public_identity().into_identity();
    let authority_identity = trusted_authority_identity.identity();
    if local_identity.node_id == authority_identity.node_id && &local_identity != authority_identity
    {
        return Err(format!(
            "Pool observer credential conflicts with trusted authority identity for node {}",
            local_identity.node_id
        ));
    }

    let local_node_id = local_credential.node_id();
    let authority_node_id = trusted_authority_identity.node_id();
    let mut exact_trust = NodeKeyStore::new();
    exact_trust
        .register(local_identity.clone())
        .map_err(|error| format!("register local Pool observer identity: {error}"))?;
    exact_trust
        .register(authority_identity.clone())
        .map_err(|error| format!("register trusted Pool lease authority: {error}"))?;
    let mut transport = Transport::new(local_node_id)
        .with_attestation(
            local_credential
                .keypair()
                .map_err(|error| format!("load Pool observer credential: {error}"))?,
            local_identity,
        )
        .with_known_identities(exact_trust);
    transport.set_endpoint_family(EndpointFamily::Control);
    transport.set_attestation_bootstrap_from_handshake(false);
    transport.add_node(NodeInfo::new(
        authority_node_id,
        vec![TransportAddr::Tcp(authority_addr)],
        0,
    ));
    let session_id = transport
        .connect(authority_node_id)
        .map_err(|error| format!("connect to Pool lease authority {authority_addr}: {error:?}"))?;
    transport.perform_handshake(session_id).map_err(|error| {
        format!("handshake with Pool lease authority {authority_addr}: {error:?}")
    })?;
    if transport.peer_node(session_id) != Some(authority_node_id) {
        let _ = transport.close_session(session_id, SessionCloseReason::TransportError);
        return Err("Pool owner observation session authenticated the wrong authority".to_string());
    }

    let request_started = Instant::now();
    let response_deadline = request_started
        .checked_add(OBSERVATION_TIMEOUT)
        .ok_or_else(|| "Pool owner observation response deadline overflowed".to_string())?;
    let request = ClusterPoolMessage::OwnerObservationRequest(ClusterPoolOwnerObservationRequest {
        request_id: 1,
        pool_guid: expected_pool_guid,
        requesting_node_id: local_node_id,
    });
    let encoded = request
        .encode()
        .map_err(|error| format!("encode Pool owner observation request: {error:?}"))?;
    let mut wire = Vec::with_capacity(CLUSTER_POOL_MAGIC.len() + encoded.len());
    wire.extend_from_slice(CLUSTER_POOL_MAGIC);
    wire.extend_from_slice(&encoded);
    transport
        .send_message(session_id, &wire)
        .map_err(|error| format!("send Pool owner observation request: {error:?}"))?;

    let raw = loop {
        match transport.recv_message(session_id) {
            Ok(response) => break response,
            Err(TransportError::WouldBlock(_)) => {
                let now = Instant::now();
                if now >= response_deadline {
                    let _ = transport.close_session(session_id, SessionCloseReason::TransportError);
                    return Err(
                        "Pool lease authority did not answer owner observation before the deadline"
                            .to_string(),
                    );
                }
                std::thread::sleep(
                    response_deadline
                        .saturating_duration_since(now)
                        .min(OBSERVATION_RETRY_INTERVAL),
                );
            }
            Err(error) => {
                let _ = transport.close_session(session_id, SessionCloseReason::TransportError);
                return Err(format!(
                    "receive Pool owner observation response: {error:?}"
                ));
            }
        }
    };
    let response_received = Instant::now();
    let _ = transport.close_session(session_id, SessionCloseReason::LocalShutdown);
    if raw.len() < CLUSTER_POOL_MAGIC.len()
        || &raw[..CLUSTER_POOL_MAGIC.len()] != CLUSTER_POOL_MAGIC
    {
        return Err("Pool owner observation response has invalid CP01 framing".to_string());
    }
    let response = ClusterPoolMessage::decode(&raw[CLUSTER_POOL_MAGIC.len()..])
        .map_err(|error| format!("decode Pool owner observation response: {error:?}"))?;
    let ClusterPoolMessage::OwnerObservationResponse(response) = response else {
        return Err(format!(
            "Pool owner observation received unexpected response: {response:?}"
        ));
    };
    validate_response(
        response,
        authority_node_id,
        expected_pool_guid,
        request_started,
        response_received,
    )
}

fn validate_response(
    response: ClusterPoolOwnerObservationResponse,
    authority_node_id: u64,
    expected_pool_guid: [u8; 16],
    request_started: Instant,
    response_received: Instant,
) -> Result<AuthenticatedPoolOwnerObservation, String> {
    if response.request_id != 1 {
        return Err(format!(
            "Pool owner observation request ID mismatch: expected 1, got {}",
            response.request_id
        ));
    }
    if response.node_id != authority_node_id {
        return Err(format!(
            "Pool owner observation authority mismatch: expected {authority_node_id}, got {}",
            response.node_id
        ));
    }
    if response.pool_guid != expected_pool_guid {
        return Err("Pool owner observation Pool GUID mismatch".to_string());
    }
    if !response.success {
        return Err(response
            .error
            .unwrap_or_else(|| "Pool owner observation was refused".to_string()));
    }
    if response.error.is_some() {
        return Err("successful Pool owner observation also carried an error".to_string());
    }
    let (
        Some(owner_node_id),
        Some(membership_epoch),
        Some(write_fence_generation),
        Some(remaining_ms),
    ) = (
        response.owner_node_id,
        response.membership_epoch,
        response.write_fence_generation,
        response.lease_remaining_ms,
    )
    else {
        return Err("Pool owner observation omitted required authority fields".to_string());
    };
    if owner_node_id == 0
        || membership_epoch == 0
        || write_fence_generation == 0
        || remaining_ms == 0
    {
        return Err("Pool owner observation contains a zero authority field".to_string());
    }
    let measured_round_trip = response_received.saturating_duration_since(request_started);
    let safety_margin = measured_round_trip
        .checked_add(Duration::from_millis(1))
        .unwrap_or(Duration::MAX);
    let local_remaining = Duration::from_millis(remaining_ms)
        .checked_sub(safety_margin)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            "Pool owner observation expired during authenticated transport".to_string()
        })?;
    let valid_until = response_received
        .checked_add(local_remaining)
        .ok_or_else(|| "Pool owner observation local deadline overflowed".to_string())?;
    Ok(AuthenticatedPoolOwnerObservation {
        pool_guid: expected_pool_guid,
        owner_node_id,
        membership_epoch,
        write_fence_generation,
        valid_until,
    })
}
