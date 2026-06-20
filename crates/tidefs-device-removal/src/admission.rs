// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Admission evidence required before an operator device-removal request can
//! be accepted.
//!
//! The CLI only names a pool and target device. A live owner must turn that
//! request into committed evacuation receipt authority before removal is
//! accepted. This module is intentionally narrow: it validates the receipt
//! shape that crosses the CLI/live-owner boundary without driving evacuation.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::EvacuationReceipt;

/// Live-owner response field containing device-removal authority evidence.
pub const DEVICE_REMOVAL_AUTHORITY_FIELD: &str = "device_removal_authority";

/// Authority kind required by `tidefsctl device remove`.
pub const DEVICE_REMOVAL_AUTHORITY_KIND: &str = "committed-evacuation-receipt";

/// Operator request that must be admitted by live-owner evacuation authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRemovalAdmissionRequest {
    /// Imported pool name supplied by the operator.
    pub pool_name: String,

    /// Target device path supplied by the operator.
    pub device_path: String,
}

impl DeviceRemovalAdmissionRequest {
    /// Create an admission request from explicit pool and device strings.
    #[must_use]
    pub fn new(pool_name: impl Into<String>, device_path: impl Into<String>) -> Self {
        Self {
            pool_name: pool_name.into(),
            device_path: device_path.into(),
        }
    }

    /// Create an admission request from a filesystem path.
    #[must_use]
    pub fn from_path(pool_name: impl Into<String>, device_path: &Path) -> Self {
        Self::new(pool_name, device_path.to_string_lossy())
    }

    /// Validate live-owner evidence for this admission request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalAdmissionError`] when the live owner did not
    /// provide committed, current receipt authority for this exact pool member.
    pub fn validate(
        &self,
        evidence: &DeviceRemovalAdmissionEvidence,
    ) -> Result<(), DeviceRemovalAdmissionError> {
        if evidence.kind != DEVICE_REMOVAL_AUTHORITY_KIND {
            return Err(DeviceRemovalAdmissionError::UnsupportedAuthority {
                pool_name: self.pool_name.clone(),
                device_path: self.device_path.clone(),
                expected_kind: DEVICE_REMOVAL_AUTHORITY_KIND.to_string(),
                actual_kind: evidence.kind.clone(),
            });
        }

        if evidence.pool_name != self.pool_name {
            return Err(DeviceRemovalAdmissionError::MismatchedPool {
                expected_pool_name: self.pool_name.clone(),
                actual_pool_name: evidence.pool_name.clone(),
            });
        }

        if evidence.device_path != self.device_path {
            return Err(DeviceRemovalAdmissionError::MismatchedDevice {
                pool_name: self.pool_name.clone(),
                expected_device_path: self.device_path.clone(),
                actual_device_path: evidence.device_path.clone(),
            });
        }

        if !evidence.committed {
            return Err(DeviceRemovalAdmissionError::Uncommitted {
                pool_name: self.pool_name.clone(),
                device_path: self.device_path.clone(),
            });
        }

        let receipt = evidence.evacuation_receipt.as_ref().ok_or_else(|| {
            DeviceRemovalAdmissionError::MissingReceipt {
                pool_name: self.pool_name.clone(),
                device_path: self.device_path.clone(),
            }
        })?;

        if evidence.target_device_guid != receipt.target_device_guid {
            return Err(DeviceRemovalAdmissionError::MismatchedDeviceGuid {
                pool_name: self.pool_name.clone(),
                device_path: self.device_path.clone(),
                authority_device_guid: hex_uuid(&evidence.target_device_guid),
                receipt_device_guid: hex_uuid(&receipt.target_device_guid),
            });
        }

        if evidence.current_topology_generation != receipt.topology_generation {
            return Err(DeviceRemovalAdmissionError::Stale {
                pool_name: self.pool_name.clone(),
                device_path: self.device_path.clone(),
                receipt_topology_generation: receipt.topology_generation,
                current_topology_generation: evidence.current_topology_generation,
            });
        }

        if !receipt.verify_digest() {
            return Err(DeviceRemovalAdmissionError::InvalidReceiptDigest {
                pool_name: self.pool_name.clone(),
                device_path: self.device_path.clone(),
            });
        }

        Ok(())
    }
}

/// Live-owner evidence proving a device removal request is authorized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRemovalAdmissionEvidence {
    /// Evidence kind; must be [`DEVICE_REMOVAL_AUTHORITY_KIND`].
    pub kind: String,

    /// Pool name whose live owner committed the receipt.
    pub pool_name: String,

    /// Pool member path whose evacuation is authorized.
    pub device_path: String,

    /// Current target device GUID resolved by the live owner.
    pub target_device_guid: [u8; 16],

    /// Current live topology generation observed by the live owner.
    pub current_topology_generation: u64,

    /// Whether the receipt evidence is committed to live placement authority.
    pub committed: bool,

    /// Committed evacuation receipt for the target pool member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evacuation_receipt: Option<EvacuationReceipt>,
}

impl DeviceRemovalAdmissionEvidence {
    /// Create committed evidence for the matching pool member and receipt.
    #[must_use]
    pub fn committed(
        pool_name: impl Into<String>,
        device_path: impl Into<String>,
        current_topology_generation: u64,
        receipt: EvacuationReceipt,
    ) -> Self {
        Self {
            kind: DEVICE_REMOVAL_AUTHORITY_KIND.to_string(),
            pool_name: pool_name.into(),
            device_path: device_path.into(),
            target_device_guid: receipt.target_device_guid,
            current_topology_generation,
            committed: true,
            evacuation_receipt: Some(receipt),
        }
    }
}

/// Admission refusal for missing or invalid evacuation receipt authority.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceRemovalAdmissionError {
    /// Live-owner response did not include the required authority object.
    #[error(
        "missing committed evacuation receipt authority for pool '{pool_name}' device '{device_path}'"
    )]
    MissingAuthority {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
    },

    /// Live-owner response included malformed authority evidence.
    #[error(
        "malformed committed evacuation receipt authority for pool '{pool_name}' device '{device_path}': {reason}"
    )]
    MalformedAuthority {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
        /// Decode or shape failure.
        reason: String,
    },

    /// Authority object used an unsupported evidence kind.
    #[error(
        "unsupported evacuation receipt authority for pool '{pool_name}' device '{device_path}': expected '{expected_kind}', got '{actual_kind}'"
    )]
    UnsupportedAuthority {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
        /// Required evidence kind.
        expected_kind: String,
        /// Actual evidence kind.
        actual_kind: String,
    },

    /// Authority evidence did not include a receipt payload.
    #[error(
        "missing committed evacuation receipt authority for pool '{pool_name}' device '{device_path}': receipt payload is absent"
    )]
    MissingReceipt {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
    },

    /// Authority evidence names a different pool.
    #[error(
        "mismatched-pool evacuation receipt authority: requested pool '{expected_pool_name}', authority names '{actual_pool_name}'"
    )]
    MismatchedPool {
        /// Requested pool name.
        expected_pool_name: String,
        /// Pool name from authority evidence.
        actual_pool_name: String,
    },

    /// Authority evidence names a different device path.
    #[error(
        "mismatched-device evacuation receipt authority for pool '{pool_name}': requested device '{expected_device_path}', authority names '{actual_device_path}'"
    )]
    MismatchedDevice {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        expected_device_path: String,
        /// Device path from authority evidence.
        actual_device_path: String,
    },

    /// Authority device GUID differs from the receipt device GUID.
    #[error(
        "mismatched-device evacuation receipt authority for pool '{pool_name}' device '{device_path}': authority guid {authority_device_guid} does not match receipt guid {receipt_device_guid}"
    )]
    MismatchedDeviceGuid {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
        /// Device GUID resolved by the authority wrapper.
        authority_device_guid: String,
        /// Device GUID bound by the receipt.
        receipt_device_guid: String,
    },

    /// Authority evidence is not committed.
    #[error(
        "uncommitted evacuation receipt authority for pool '{pool_name}' device '{device_path}': removal requires committed evidence"
    )]
    Uncommitted {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
    },

    /// Receipt topology is stale compared with the live owner topology.
    #[error(
        "stale evacuation receipt authority for pool '{pool_name}' device '{device_path}': receipt topology {receipt_topology_generation} does not match current topology {current_topology_generation}"
    )]
    Stale {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
        /// Topology generation bound by the receipt.
        receipt_topology_generation: u64,
        /// Current live topology generation.
        current_topology_generation: u64,
    },

    /// Receipt digest does not verify.
    #[error(
        "invalid committed evacuation receipt authority for pool '{pool_name}' device '{device_path}': receipt digest verification failed"
    )]
    InvalidReceiptDigest {
        /// Requested pool name.
        pool_name: String,
        /// Requested device path.
        device_path: String,
    },
}

/// Validate a live-owner JSON response for device-removal admission authority.
///
/// # Errors
///
/// Returns [`DeviceRemovalAdmissionError`] when the response omits, malforms,
/// or fails to validate committed evacuation receipt authority.
pub fn validate_live_owner_response(
    request: &DeviceRemovalAdmissionRequest,
    response: &serde_json::Value,
) -> Result<DeviceRemovalAdmissionEvidence, DeviceRemovalAdmissionError> {
    let authority = response
        .get(DEVICE_REMOVAL_AUTHORITY_FIELD)
        .or_else(|| {
            response
                .get("json")
                .and_then(|json| json.get(DEVICE_REMOVAL_AUTHORITY_FIELD))
        })
        .ok_or_else(|| DeviceRemovalAdmissionError::MissingAuthority {
            pool_name: request.pool_name.clone(),
            device_path: request.device_path.clone(),
        })?;
    let evidence: DeviceRemovalAdmissionEvidence = serde_json::from_value(authority.clone())
        .map_err(|err| DeviceRemovalAdmissionError::MalformedAuthority {
            pool_name: request.pool_name.clone(),
            device_path: request.device_path.clone(),
            reason: err.to_string(),
        })?;
    request.validate(&evidence)?;
    Ok(evidence)
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvacuationCompletionGeneration, EvacuationReceipt};

    fn receipt(device_guid: [u8; 16], topology_generation: u64) -> EvacuationReceipt {
        EvacuationReceipt::new(
            EvacuationCompletionGeneration {
                target_device_guid: device_guid,
                target_topology_generation: topology_generation,
                evacuation_set_digest: [0x55; 32],
                removal_chain_digest: [0x66; 32],
            },
            vec![],
            7,
        )
    }

    fn matching_request() -> DeviceRemovalAdmissionRequest {
        DeviceRemovalAdmissionRequest::new("tank", "/dev/disk2")
    }

    #[test]
    fn committed_matching_receipt_admits_removal() {
        let request = matching_request();
        let receipt = receipt([0x42; 16], 9);
        let evidence = DeviceRemovalAdmissionEvidence::committed("tank", "/dev/disk2", 9, receipt);

        request.validate(&evidence).unwrap();
    }

    #[test]
    fn live_owner_response_accepts_receipt_shaped_authority() {
        let request = matching_request();
        let receipt = receipt([0x42; 16], 9);
        let mut response = serde_json::json!({"ok": true});
        response[DEVICE_REMOVAL_AUTHORITY_FIELD] = serde_json::to_value(
            DeviceRemovalAdmissionEvidence::committed("tank", "/dev/disk2", 9, receipt),
        )
        .unwrap();

        let evidence = validate_live_owner_response(&request, &response).unwrap();

        assert!(evidence.committed);
    }

    #[test]
    fn missing_authority_fails_closed() {
        let request = matching_request();
        let err =
            validate_live_owner_response(&request, &serde_json::json!({"ok": true})).unwrap_err();

        assert!(matches!(
            err,
            DeviceRemovalAdmissionError::MissingAuthority { .. }
        ));
        assert!(err
            .to_string()
            .contains("committed evacuation receipt authority"));
    }

    #[test]
    fn uncommitted_authority_fails_closed() {
        let request = matching_request();
        let mut evidence = DeviceRemovalAdmissionEvidence::committed(
            "tank",
            "/dev/disk2",
            9,
            receipt([0x42; 16], 9),
        );
        evidence.committed = false;

        let err = request.validate(&evidence).unwrap_err();

        assert!(matches!(
            err,
            DeviceRemovalAdmissionError::Uncommitted { .. }
        ));
    }

    #[test]
    fn stale_authority_fails_closed() {
        let request = matching_request();
        let evidence = DeviceRemovalAdmissionEvidence::committed(
            "tank",
            "/dev/disk2",
            10,
            receipt([0x42; 16], 9),
        );

        let err = request.validate(&evidence).unwrap_err();

        assert!(matches!(err, DeviceRemovalAdmissionError::Stale { .. }));
    }

    #[test]
    fn mismatched_pool_and_device_fail_closed() {
        let request = matching_request();
        let pool_mismatch = DeviceRemovalAdmissionEvidence::committed(
            "other",
            "/dev/disk2",
            9,
            receipt([0x42; 16], 9),
        );
        let device_mismatch = DeviceRemovalAdmissionEvidence::committed(
            "tank",
            "/dev/disk3",
            9,
            receipt([0x42; 16], 9),
        );

        assert!(matches!(
            request.validate(&pool_mismatch).unwrap_err(),
            DeviceRemovalAdmissionError::MismatchedPool { .. }
        ));
        assert!(matches!(
            request.validate(&device_mismatch).unwrap_err(),
            DeviceRemovalAdmissionError::MismatchedDevice { .. }
        ));
    }

    #[test]
    fn mismatched_guid_and_bad_digest_fail_closed() {
        let request = matching_request();
        let matching_receipt = receipt([0x42; 16], 9);
        let mut guid_mismatch = DeviceRemovalAdmissionEvidence::committed(
            "tank",
            "/dev/disk2",
            9,
            matching_receipt,
        );
        guid_mismatch.target_device_guid = [0x24; 16];

        assert!(matches!(
            request.validate(&guid_mismatch).unwrap_err(),
            DeviceRemovalAdmissionError::MismatchedDeviceGuid { .. }
        ));

        let mut bad_digest = DeviceRemovalAdmissionEvidence::committed(
            "tank",
            "/dev/disk2",
            9,
            receipt([0x42; 16], 9),
        );
        bad_digest
            .evacuation_receipt
            .as_mut()
            .unwrap()
            .receipt_digest[0] ^= 0xff;

        assert!(matches!(
            request.validate(&bad_digest).unwrap_err(),
            DeviceRemovalAdmissionError::InvalidReceiptDigest { .. }
        ));
    }
}
