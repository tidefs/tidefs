// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Authenticated Pool-lease transport shared by clustered product carriers.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use tidefs_auth::NodeKeyStore;
use tidefs_cluster::{
    ClusterLeaseGrant, ClusterLeaseSession, ClusterPoolLeaseAction, ClusterPoolLeaseRequest,
    ClusterPoolMessage, PoolLeaseToken,
};
use tidefs_transport::{EndpointFamily, NodeInfo, SessionId, Transport, TransportAddr};

#[derive(Debug)]
pub(crate) struct TransportPoolLeaseSession {
    transport: Transport,
    session_id: SessionId,
    pub(crate) authority_node_id: u64,
    pub(crate) owner_node_id: u64,
    pool_guid: [u8; 16],
    next_request_id: u64,
    lease_valid_until: Option<Instant>,
}

pub(crate) fn validate_cluster_identity_consistency(
    identities: &[(&str, &tidefs_auth::NodeIdentity)],
) -> Result<(), String> {
    for (index, (left_role, left)) in identities.iter().enumerate() {
        for (right_role, right) in &identities[index + 1..] {
            if left.node_id == right.node_id && left != right {
                return Err(format!(
                    "{left_role} and {right_role} provide conflicting identities for node {}",
                    left.node_id
                ));
            }
        }
    }
    Ok(())
}

impl TransportPoolLeaseSession {
    pub(crate) fn connect(
        authority_addr: SocketAddr,
        pool_guid: [u8; 16],
        local_credential: &tidefs_auth::NodePrivateCredential,
        trusted_authority_identity: &tidefs_auth::NodePublicIdentity,
    ) -> Result<Self, String> {
        let owner_node_id = local_credential.node_id();
        let authority_node_id = trusted_authority_identity.node_id();
        let local_identity = local_credential.public_identity().into_identity();
        validate_cluster_identity_consistency(&[
            ("Pool owner credential", &local_identity),
            (
                "trusted Pool lease authority",
                trusted_authority_identity.identity(),
            ),
        ])?;
        let mut exact_trust = NodeKeyStore::new();
        exact_trust
            .register(local_identity.clone())
            .map_err(|error| format!("register local Pool owner identity: {error}"))?;
        exact_trust
            .register(trusted_authority_identity.identity().clone())
            .map_err(|error| format!("register trusted Pool lease authority: {error}"))?;
        let mut transport = Transport::new(owner_node_id)
            .with_attestation(
                local_credential
                    .keypair()
                    .map_err(|error| format!("load Pool owner credential: {error}"))?,
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
            .map_err(|error| format!("connect to cluster authority {authority_addr}: {error:?}"))?;
        transport.perform_handshake(session_id).map_err(|error| {
            format!("handshake with cluster authority {authority_addr}: {error:?}")
        })?;
        Ok(Self {
            transport,
            session_id,
            authority_node_id,
            owner_node_id,
            pool_guid,
            next_request_id: 1,
            lease_valid_until: None,
        })
    }

    pub(crate) fn acquire(&mut self) -> Result<ClusterLeaseGrant, String> {
        self.exchange(ClusterPoolLeaseAction::Acquire)?
            .ok_or_else(|| {
                "cluster authority granted acquire without a Pool lease token".to_string()
            })
    }

    fn exchange(
        &mut self,
        action: ClusterPoolLeaseAction,
    ) -> Result<Option<ClusterLeaseGrant>, String> {
        let release_action = matches!(&action, ClusterPoolLeaseAction::Release { .. });
        let request_started = Instant::now();
        let response_deadline = match &action {
            ClusterPoolLeaseAction::Renew { .. } => self
                .lease_valid_until
                .and_then(|deadline| deadline.checked_sub(Duration::from_millis(1)))
                .ok_or_else(|| {
                    "cluster Pool lease renewal has no live process-local deadline".to_string()
                })?,
            ClusterPoolLeaseAction::Acquire | ClusterPoolLeaseAction::Release { .. } => {
                request_started
                    .checked_add(Duration::from_secs(5))
                    .ok_or_else(|| "cluster Pool lease response deadline overflowed".to_string())?
            }
        };
        if response_deadline <= request_started {
            return Err("cluster Pool lease request has no safe response window".to_string());
        }

        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| "cluster Pool lease request ID space is exhausted".to_string())?;
        let request = ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id,
            pool_guid: self.pool_guid,
            requesting_node_id: self.owner_node_id,
            action,
        });
        let encoded = request
            .encode()
            .map_err(|error| format!("encode cluster Pool lease request: {error:?}"))?;
        let mut wire = Vec::with_capacity(4 + encoded.len());
        wire.extend_from_slice(b"CP01");
        wire.extend_from_slice(&encoded);
        self.transport
            .send_message(self.session_id, &wire)
            .map_err(|error| format!("send cluster Pool lease request: {error:?}"))?;

        let raw = loop {
            match self.transport.recv_message(self.session_id) {
                Ok(response) => break response,
                Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                    let now = Instant::now();
                    if now >= response_deadline {
                        return Err(
                            "cluster Pool lease authority did not respond before the safe deadline"
                                .to_string(),
                        );
                    }
                    std::thread::sleep(
                        response_deadline
                            .saturating_duration_since(now)
                            .min(Duration::from_millis(10)),
                    );
                }
                Err(error) => {
                    return Err(format!("receive cluster Pool lease response: {error:?}"));
                }
            }
        };
        if raw.len() < 4 || &raw[..4] != b"CP01" {
            return Err("cluster Pool lease response has invalid CP01 framing".to_string());
        }
        let response = ClusterPoolMessage::decode(&raw[4..])
            .map_err(|error| format!("decode cluster Pool lease response: {error:?}"))?;
        let ClusterPoolMessage::LeaseResponse(response) = response else {
            return Err(format!(
                "cluster Pool lease request received unexpected response: {response:?}"
            ));
        };
        if response.request_id != request_id {
            return Err(format!(
                "cluster Pool lease response request ID mismatch: expected {request_id}, got {}",
                response.request_id
            ));
        }
        if response.node_id != self.authority_node_id {
            return Err(format!(
                "cluster Pool lease response authority mismatch: expected {}, got {}",
                self.authority_node_id, response.node_id
            ));
        }
        if response.pool_guid != self.pool_guid {
            return Err("cluster Pool lease response Pool GUID mismatch".to_string());
        }
        if !response.success {
            return Err(response
                .error
                .unwrap_or_else(|| "cluster Pool lease request was refused".to_string()));
        }

        let token = response
            .lease_token_bytes
            .map(|bytes| {
                bincode::deserialize::<PoolLeaseToken>(&bytes)
                    .map_err(|error| format!("deserialize cluster Pool lease token: {error}"))
            })
            .transpose()?;
        let mut response_error = if response.error.is_some() {
            Some("successful cluster Pool lease response also carried an error".to_string())
        } else if token.as_ref().is_some_and(|token| {
            token.node_id != self.owner_node_id || token.pool_guid != self.pool_guid
        }) {
            Some("cluster Pool lease token owner or Pool GUID mismatch".to_string())
        } else if release_action {
            if token.is_some()
                || response.lease_expiration_ms.is_some()
                || response.lease_remaining_ms.is_some()
            {
                Some("cluster Pool lease release response carried grant material".to_string())
            } else {
                None
            }
        } else {
            match (
                token.as_ref(),
                response.lease_expiration_ms,
                response.lease_remaining_ms,
            ) {
                (Some(token), Some(authority_deadline), Some(_authority_remaining))
                    if token.expiration_deadline_ms != authority_deadline =>
                {
                    Some(
                        "cluster Pool lease response deadline disagrees with its token".to_string(),
                    )
                }
                (Some(_), Some(authority_deadline), Some(authority_remaining))
                    if authority_remaining == 0 || authority_remaining > authority_deadline =>
                {
                    Some(
                        "cluster Pool lease response carried inconsistent remaining validity"
                            .to_string(),
                    )
                }
                (Some(_), Some(_), Some(_)) => None,
                _ => Some(
                    "cluster Pool lease grant omitted or mismatched token, deadline, and remaining validity"
                        .to_string(),
                ),
            }
        };

        let mut valid_until = None;
        if response_error.is_none() && !release_action {
            let authority_remaining = Duration::from_millis(
                response
                    .lease_remaining_ms
                    .expect("validated grant remaining validity"),
            );
            let validation_now = Instant::now();
            let measured_round_trip = validation_now.saturating_duration_since(request_started);
            let safety_margin = measured_round_trip
                .checked_add(Duration::from_millis(1))
                .unwrap_or(Duration::MAX);
            match authority_remaining.checked_sub(safety_margin) {
                Some(remaining) if !remaining.is_zero() => {
                    match validation_now.checked_add(remaining) {
                        Some(deadline) => valid_until = Some(deadline),
                        None => {
                            response_error =
                                Some("cluster Pool lease local deadline overflowed".to_string())
                        }
                    }
                }
                _ => {
                    response_error = Some(
                        "cluster Pool lease grant had no safe process-local validity after transport delay"
                            .to_string(),
                    );
                }
            }
        }
        if let Some(error) = response_error {
            if !release_action
                && token.as_ref().is_some_and(|token| {
                    token.node_id == self.owner_node_id && token.pool_guid == self.pool_guid
                })
            {
                let token = token.expect("checked above");
                let cleanup = self.exchange(ClusterPoolLeaseAction::Release { token });
                return Err(match cleanup {
                    Ok(None) => error,
                    Ok(Some(_)) => {
                        format!("{error}; rejected Pool lease cleanup returned another token")
                    }
                    Err(cleanup_error) => {
                        format!("{error}; rejected Pool lease cleanup failed: {cleanup_error}")
                    }
                });
            }
            return Err(error);
        }
        if release_action {
            self.lease_valid_until = None;
            return Ok(None);
        }

        let valid_until = valid_until.expect("validated non-release local deadline");
        self.lease_valid_until = Some(valid_until);
        Ok(Some(ClusterLeaseGrant {
            token: token.expect("validated non-release grant token"),
            valid_until,
        }))
    }
}

impl ClusterLeaseSession for TransportPoolLeaseSession {
    fn renew(&mut self, token: &PoolLeaseToken) -> Result<ClusterLeaseGrant, String> {
        self.exchange(ClusterPoolLeaseAction::Renew {
            token: token.clone(),
        })?
        .ok_or_else(|| "cluster authority renewed without returning a Pool lease token".to_string())
    }

    fn release(&mut self, token: &PoolLeaseToken) -> Result<(), String> {
        if self
            .exchange(ClusterPoolLeaseAction::Release {
                token: token.clone(),
            })?
            .is_some()
        {
            return Err("cluster authority returned a token for Pool lease release".to_string());
        }
        Ok(())
    }
}

pub(crate) fn load_cluster_node_credential(
    path: &Path,
) -> Result<tidefs_auth::NodePrivateCredential, String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("read local node credential {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "local node credential {} is not a regular file",
            path.display()
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "local node credential {} grants group or other permissions",
            path.display()
        ));
    }
    let mut bytes = std::fs::read(path)
        .map_err(|error| format!("read local node credential {}: {error}", path.display()))?;
    let credential = tidefs_auth::NodePrivateCredential::decode_fixed(&bytes)
        .map_err(|error| format!("validate local node credential {}: {error}", path.display()));
    bytes.fill(0);
    credential
}

pub(crate) fn load_cluster_public_identity(
    path: &Path,
) -> Result<tidefs_auth::NodePublicIdentity, String> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        format!(
            "read trusted cluster peer identity {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "trusted cluster peer identity {} is not a regular file",
            path.display()
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "read trusted cluster peer identity {}: {error}",
            path.display()
        )
    })?;
    tidefs_auth::NodePublicIdentity::decode_fixed(&bytes).map_err(|error| {
        format!(
            "validate trusted cluster peer identity {}: {error}",
            path.display()
        )
    })
}
