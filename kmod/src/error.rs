//! Bridge error types for kernel-boundary operations.
//!
//! These error types represent failures that can occur at the kernel bridge
//! stratum (s2) when mapping canonical (s0) and mirror (s1) artifacts onto
//! Linux kernel mechanics. They are deliberately abstract — concrete Linux
//! errno rendering happens in leaf modules (s3) through the response-render
//! trait contract (`t4`).

use core::fmt;

/// Top-level bridge error covering all kernel-boundary failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// A borrowed canonical decode failed (t0 trait contract violation).
    DecodeFailed { detail: &'static str },
    /// An anchor/cursor view is stale or inconsistent (t1).
    AnchorStale { generation: u64, expected: u64 },
    /// Mirror payload construction failed (t2).
    MirrorLiftFailed { detail: &'static str },
    /// Authority-client request was refused or timed out (t3).
    AuthorityRefused { reason: &'static str },
    /// Response-render plan was rejected (t4).
    RenderRejected { field: &'static str },
    /// Validation-emission sideband is full or blocked (t5).
    ValidationEmitFailed { detail: &'static str },
    /// Pin/drain operation timed out or was fenced (t6).
    PinDrainFailed { detail: &'static str },
    /// Page-window operation failed (t7).
    PageWindowFailed { detail: &'static str },
    /// Bio-queue operation failed (t8).
    BioQueueFailed { detail: &'static str },
    /// Secret-lease view is expired or revoked (t9).
    SecretLeaseExpired { handle_id: u64 },
    /// A kernel object wrapper encountered an invalid state.
    InvalidState { detail: &'static str },
    /// Operation is not yet implemented in this bridge version.
    Unimplemented { feature: &'static str },
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecodeFailed { detail } => write!(f, "decode failed: {detail}"),
            Self::AnchorStale {
                generation,
                expected,
            } => {
                write!(
                    f,
                    "anchor stale: generation {generation}, expected {expected}"
                )
            }
            Self::MirrorLiftFailed { detail } => write!(f, "mirror lift failed: {detail}"),
            Self::AuthorityRefused { reason } => write!(f, "authority refused: {reason}"),
            Self::RenderRejected { field } => write!(f, "render rejected: field {field}"),
            Self::ValidationEmitFailed { detail } => write!(f, "validation emit failed: {detail}"),
            Self::PinDrainFailed { detail } => write!(f, "pin drain failed: {detail}"),
            Self::PageWindowFailed { detail } => write!(f, "page window failed: {detail}"),
            Self::BioQueueFailed { detail } => write!(f, "bio queue failed: {detail}"),
            Self::SecretLeaseExpired { handle_id } => {
                write!(f, "secret lease expired: handle {handle_id}")
            }
            Self::InvalidState { detail } => write!(f, "invalid state: {detail}"),
            Self::Unimplemented { feature } => write!(f, "unimplemented: {feature}"),
        }
    }
}

/// Result alias for bridge operations.
pub type BridgeResult<T> = Result<T, BridgeError>;
