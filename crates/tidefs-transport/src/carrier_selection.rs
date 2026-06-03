//! Deterministic transport carrier selection from membership peer capability
//! advertisements.
//!
//! [`CarrierSelector`] consumes local preferences and peer-advertised
//! [`tidefs_membership_types::capabilities::TransportCarrier`] bitmasks to
//! select the best mutually-supported transport backend. RDMA is preferred
//! when both sides advertise it; TCP is the universal fallback.
//!
//! # Selection order
//!
//! 1. RDMA (when both sides advertise it and local backend supports RDMA)
//! 2. TCP (always available as a fallback when advertised by the peer)
//! 3. TLS over TCP (when the peer advertises TCP and local requires TLS)
//!
//! # Errors
//!
//! - [`CarrierSelectionError::NoMutualCarrier`] when no overlap exists.
//! - [`CarrierSelectionError::PeerAdvertisesNone`] when the peer advertised
//!   no carriers.
//! - [`CarrierSelectionError::UnsupportedLocalCarrier`] when the local
//!   backend cannot serve any of the peer's advertised carriers.
//! - [`CarrierSelectionError::CarrierPolicyViolation`] when the selected
//!   carrier violates the configured [`CarrierPolicy`] (e.g. RDMA was
//!   required but only TCP could be negotiated).
//!
//! # Carrier policy
//!
//! [`CarrierPolicy`] controls whether carrier selection falls back
//! gracefully or fails closed when the preferred carrier is unavailable:
//!
//! - [`CarrierPolicy::Prefer`] (default): fall back to TCP when RDMA is
//!   unavailable — silent fallback is permitted.
//! - [`CarrierPolicy::Enforce`]: fail closed when the configured backend
//!   kind cannot be satisfied — silent fallback is forbidden.  An RDMA
//!   claim that lands on TCP is a policy violation.

use core::fmt;

use crate::backend::TransportBackendKind;

// ---------------------------------------------------------------------------
// CarrierPolicy -- fail-closed enforcement for RDMA claims (#6672)
// ---------------------------------------------------------------------------

/// Controls whether carrier selection permits silent fallback to TCP
/// when the configured backend (e.g. RDMA) cannot be satisfied.
///
/// Implements the "fail closed on silent TCP fallback when an RDMA claim
/// is being made" requirement from #6672.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CarrierPolicy {
    /// Permit silent fallback to TCP (default, historical behaviour).
    #[default]
    Prefer,
    /// Refuse any fallback: fail with [`CarrierSelectionError::CarrierPolicyViolation`].
    Enforce,
}

impl CarrierPolicy {
    /// Whether this policy enforces strict carrier matching.
    #[must_use]
    pub fn is_enforce(&self) -> bool {
        matches!(self, Self::Enforce)
    }

    /// Check whether `selected` satisfies this policy given the `configured` backend.
    pub fn check(
        self,
        configured: TransportBackendKind,
        selected: TransportBackendKind,
    ) -> Result<(), CarrierSelectionError> {
        match self {
            Self::Prefer => Ok(()),
            Self::Enforce => {
                if configured == selected
                    || (!configured.is_rdma() && !selected.is_rdma())
                {
                    Ok(())
                } else if configured.is_rdma() && !selected.is_rdma() {
                    Err(CarrierSelectionError::CarrierPolicyViolation {
                        configured: configured.preferred_carrier_name(),
                        selected: selected.preferred_carrier_name(),
                        detail: "enforce carrier policy: RDMA was required but negotiated backend is not RDMA",
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl fmt::Display for CarrierPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prefer => write!(f, "prefer"),
            Self::Enforce => write!(f, "enforce"),
        }
    }
}

// ---------------------------------------------------------------------------
// CarrierSelectionError
// ---------------------------------------------------------------------------

/// Errors that can occur during carrier selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CarrierSelectionError {
    /// The peer advertised no transport carriers.
    PeerAdvertisesNone,
    /// No mutually-supported carrier: the peer's advertised carriers do not
    /// overlap with any local backend.
    NoMutualCarrier,
    /// The local backend does not support any of the peer's advertised
    /// carriers (e.g., peer only advertises a future carrier the local node
    /// hasn't been upgraded for).
    UnsupportedLocalCarrier,
    /// The selected carrier violates the configured [`CarrierPolicy`].
    /// E.g. an RDMA claim was made but the negotiated backend is TCP.
    CarrierPolicyViolation {
        /// The configured (required) carrier name.
        configured: &'static str,
        /// The selected (actual) carrier name.
        selected: &'static str,
        /// Human-readable detail about the violation.
        detail: &'static str,
    },
}

impl fmt::Display for CarrierSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerAdvertisesNone => {
                write!(f, "peer advertised no transport carriers")
            }
            Self::NoMutualCarrier => {
                write!(f, "no mutually-supported transport carrier")
            }
            Self::UnsupportedLocalCarrier => {
                write!(
                    f,
                    "local backend does not support any peer-advertised carrier"
                )
            }
            Self::CarrierPolicyViolation {
                configured,
                selected,
                detail,
            } => {
                write!(
                    f,
                    "carrier policy violation: configured={configured} selected={selected}: {detail}",
                )
            }
        }
    }
}

impl std::error::Error for CarrierSelectionError {}

// ---------------------------------------------------------------------------
// CarrierSelectionFallback
// ---------------------------------------------------------------------------

/// Records which fallback path was taken during carrier selection.
///
/// Useful for observability so operators can see when an RDMA session
/// degrades to TCP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierSelectionFallback {
    /// Both sides support the preferred carrier; no fallback occurred.
    Direct,
    /// The preferred carrier was unavailable; a fallback carrier was
    /// selected instead.
    Fallback {
        /// The carrier that was requested but unavailable.
        requested: &'static str,
        /// Why the fallback happened.
        reason: &'static str,
    },
}

impl fmt::Display for CarrierSelectionFallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Fallback { requested, reason } => {
                write!(f, "fallback from {requested}: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CarrierSelectionResult
// ---------------------------------------------------------------------------

/// The outcome of a carrier selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierSelectionResult {
    /// The selected backend kind.
    pub backend_kind: TransportBackendKind,
    /// Whether a fallback occurred and why.
    pub fallback: CarrierSelectionFallback,
    /// Whether a carrier policy was applied and passed.
    /// `None` means no policy was configured.
    pub policy_applied: Option<CarrierPolicy>,
}

// ---------------------------------------------------------------------------
// CarrierSelector
// ---------------------------------------------------------------------------

/// Deterministic carrier selector that maps membership peer capability
/// advertisements to a concrete [`TransportBackendKind`].
///
/// # Mapping
///
/// | Membership carrier bit | Transport backend |
/// |---|---|
/// | `TCP` (bit 0) | `Tcp` or `Tls` |
/// | `RDMA` (bit 1) | `Rdma` |
///
/// # Example
///
/// ```
/// use tidefs_transport::carrier_selection::CarrierSelector;
/// use tidefs_transport::backend::TransportBackendKind;
/// use tidefs_membership_types::capabilities::TransportCarrier;
///
/// let selector = CarrierSelector::new(TransportBackendKind::Tcp);
/// let peer_caps = TransportCarrier::TCP;
/// let result = selector.select(peer_caps).unwrap();
/// assert_eq!(result.backend_kind, TransportBackendKind::Tcp);
/// ```
pub struct CarrierSelector {
    /// The local transport backend kind.
    local_backend: TransportBackendKind,
    /// Optional carrier policy for fail-closed enforcement.
    policy: Option<CarrierPolicy>,
}

impl CarrierSelector {
    /// Create a new selector bound to the given local backend.
    #[must_use]
    pub fn new(local_backend: TransportBackendKind) -> Self {
        Self { local_backend, policy: None }
    }

    /// Return the local backend kind.
    #[must_use]
    pub fn local_backend(&self) -> TransportBackendKind {
        self.local_backend
    }

    /// Set the carrier policy for this selector.
    #[must_use]
    pub fn with_policy(mut self, policy: CarrierPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Select the best mutually-supported transport carrier given the
    /// peer's advertised capabilities.
    ///
    /// # Selection algorithm
    ///
    /// 1. If peer advertises no carriers → `PeerAdvertisesNone`.
    /// 2. Try RDMA first: if both local and peer support RDMA → RDMA direct.
    /// 3. Try TCP fallback: if peer advertises TCP → TCP (or TLS) fallback.
    /// 4. If the local backend doesn't support any advertised carrier →
    ///    `UnsupportedLocalCarrier`.
    /// 5. Otherwise → `NoMutualCarrier`.
    ///
    /// # Determinism
    ///
    /// The selection is deterministic given the same local backend and peer
    /// capabilities. RDMA is always preferred over TCP; within equal-preference
    /// carriers, the bit order is followed.
    pub fn select(
        &self,
        peer_carriers: tidefs_membership_types::capabilities::TransportCarrier,
    ) -> Result<CarrierSelectionResult, CarrierSelectionError> {
        let policy = self.policy;
        use tidefs_membership_types::capabilities::TransportCarrier;

        // Gate: peer must advertise at least one carrier.
        if peer_carriers.is_empty() {
            return Err(CarrierSelectionError::PeerAdvertisesNone);
        }

        // 1. RDMA preferred when both sides support it.
        if peer_carriers.contains(TransportCarrier::RDMA) && self.local_backend.is_rdma() {
            let result = CarrierSelectionResult {
                backend_kind: TransportBackendKind::Rdma,
                fallback: CarrierSelectionFallback::Direct,
                policy_applied: policy,
            };
            if let Some(p) = policy {
                p.check(self.local_backend, result.backend_kind)?;
            }
            return Ok(result);
        }

        // 2. If peer advertises RDMA but local doesn't support it,
        //    fall back to TCP if the peer also advertises it.
        let selected_backend: TransportBackendKind;
        let fallback: CarrierSelectionFallback;
        if peer_carriers.contains(TransportCarrier::RDMA)
            && !self.local_backend.is_rdma()
            && peer_carriers.contains(TransportCarrier::TCP)
        {
            selected_backend = self.tcp_backend_kind();
            fallback = CarrierSelectionFallback::Fallback {
                requested: "rdma",
                reason: "local backend does not support RDMA",
            };
        } else if peer_carriers.contains(TransportCarrier::TCP) {
            // 3. TCP: always available when peer advertises it.
            selected_backend = self.tcp_backend_kind();
            fallback = CarrierSelectionFallback::Direct;
        } else if peer_carriers.contains(TransportCarrier::RDMA) && !self.local_backend.is_rdma() {
            // 4. Peer advertised only RDMA but local is TCP-only:
            //    no mutually-supported carrier.
            return Err(CarrierSelectionError::NoMutualCarrier);
        } else {
            // 5. Peer advertised some unrecognised carrier bits without TCP or
            //    RDMA. This is a future-carrier scenario.
            return Err(CarrierSelectionError::UnsupportedLocalCarrier);
        }

        let result = CarrierSelectionResult {
            backend_kind: selected_backend,
            fallback,
            policy_applied: policy,
        };

        // Apply carrier policy after selection.
        if let Some(p) = policy {
            p.check(self.local_backend, result.backend_kind)?;
        }

        Ok(result)
    }

    /// Map the local backend to the TCP-or-TLS backend kind used for
    /// TCP-based sessions.
    fn tcp_backend_kind(&self) -> TransportBackendKind {
        match self.local_backend {
            TransportBackendKind::Tls => TransportBackendKind::Tls,
            _ => TransportBackendKind::Tcp,
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityMismatch
// ---------------------------------------------------------------------------

/// Records a capability mismatch between local and peer transport carriers.
///
/// Produced when carrier selection encounters a peer advertising carriers
/// the local node cannot serve, or when a preferred carrier is unavailable
/// on one side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityMismatch {
    /// The carrier the peer advertised but the local node does not support
    /// (e.g. `"rdma"` when peer has RDMA but local is TCP-only).
    pub peer_advertised: &'static str,
    /// Whether the local node does not support the advertised carrier.
    pub local_unsupported: bool,
    /// Human-readable detail string.
    pub detail: &'static str,
}

impl fmt::Display for CapabilityMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "capability mismatch: peer advertises {}, local {}",
            self.peer_advertised,
            if self.local_unsupported {
                "does not support it"
            } else {
                "supports it"
            }
        )?;
        if !self.detail.is_empty() {
            write!(f, " ({})", self.detail)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CarrierDisclosure
// ---------------------------------------------------------------------------

/// Structured disclosure of a carrier selection outcome.
///
/// Records the selected backend, fallback path, any capability mismatch,
/// and the deterministic selection rationale. Every [`Transport::connect`]
/// call that consults peer capabilities produces a disclosure and logs it
/// via `tracing` for operator observability.
///
/// [`Transport::connect`]: crate::transport::Transport::connect
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarrierDisclosure {
    /// The selected transport backend kind for the session.
    pub selected_backend: TransportBackendKind,
    /// Whether a fallback occurred and why.
    pub fallback: CarrierSelectionFallback,
    /// The local backend kind at selection time.
    pub local_backend: TransportBackendKind,
    /// The peer's advertised transport carriers at selection time.
    pub peer_carriers: tidefs_membership_types::capabilities::TransportCarrier,
    /// The carrier requested by the local side (always the local backend's
    /// preferred carrier).
    pub local_requested: &'static str,
    /// Present when the local and peer capabilities do not fully overlap.
    pub mismatch: Option<CapabilityMismatch>,
    /// Rationale for the deterministic choice (e.g. "rdma preferred", "tcp fallback").
    pub rationale: &'static str,
    /// The carrier policy that was in effect during selection.
    /// `None` when no policy was configured.
    pub policy: Option<CarrierPolicy>,
}

impl CarrierDisclosure {
    /// Produce a disclosure from the raw selection inputs and output.
    pub fn from_selection(
        result: CarrierSelectionResult,
        local_backend: TransportBackendKind,
        peer_carriers: tidefs_membership_types::capabilities::TransportCarrier,
    ) -> Self {
        use tidefs_membership_types::capabilities::TransportCarrier;

        let local_requested = local_backend.preferred_carrier_name();

        // Pick up the policy from the result.
        let policy = result.policy_applied;

        let (mismatch, rationale) = match result.fallback {
            CarrierSelectionFallback::Direct => {
                if result.backend_kind.is_rdma() {
                    (None, "rdma direct: both sides support RDMA")
                } else if peer_carriers.contains(TransportCarrier::RDMA) && !local_backend.is_rdma()
                {
                    (
                        Some(CapabilityMismatch {
                            peer_advertised: "rdma",
                            local_unsupported: true,
                            detail: "peer has RDMA, local is TCP-only; selected TCP",
                        }),
                        "tcp direct with rdma capability mismatch: peer has RDMA, local TCP-only",
                    )
                } else {
                    (None, "tcp direct: mutually supported")
                }
            }
            CarrierSelectionFallback::Fallback { requested, reason } => {
                let mismatch = Some(CapabilityMismatch {
                    peer_advertised: requested,
                    local_unsupported: true,
                    detail: reason,
                });
                (
                    mismatch,
                    "rdma fallback to tcp: peer advertises RDMA but local does not support it",
                )
            }
        };

        Self {
            selected_backend: result.backend_kind,
            fallback: result.fallback,
            local_backend,
            peer_carriers,
            local_requested,
            mismatch,
            rationale,
            policy,
        }
    }

    /// Produce a disclosure for a runtime carrier fallback (e.g. RDMA carrier
    /// degraded or lost at runtime, requiring fallback to TCP).
    ///
    /// Unlike [`from_selection`], this records a runtime degradation event,
    /// not an initial capability-negotiation mismatch.  The disclosure
    /// captures the configured backend, the fallback carrier, and a reason
    /// string.
    pub fn from_runtime_fallback(
        configured_backend: TransportBackendKind,
        reason: &'static str,
    ) -> Self {
        let requested = configured_backend.preferred_carrier_name();
        Self {
            selected_backend: TransportBackendKind::Tcp,
            fallback: CarrierSelectionFallback::Fallback { requested, reason },
            local_backend: configured_backend,
            peer_carriers: tidefs_membership_types::capabilities::TransportCarrier::NONE,
            local_requested: requested,
            mismatch: None,
            rationale: "rdma runtime fallback to tcp: carrier degraded or lost",
            policy: None,
        }
    }
}

impl fmt::Display for CarrierDisclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "carrier: {} (local={} peer={} requested={}{})",
            self.selected_backend, self.local_backend, self.peer_carriers, self.local_requested,
            self.policy.map_or("", |p| if p.is_enforce() { " enforce" } else { "" }),
        )?;
        match self.fallback {
            CarrierSelectionFallback::Direct => write!(f, " direct"),
            CarrierSelectionFallback::Fallback { requested, reason } => {
                write!(f, " fallback from {requested}: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience free function
// ---------------------------------------------------------------------------

/// Convenience: select a carrier given a local backend and peer-advertised
/// carrier bitmask.
///
/// Equivalent to constructing a [`CarrierSelector`] and calling
/// [`CarrierSelector::select`].
pub fn select_carrier(
    local_backend: TransportBackendKind,
    peer_carriers: tidefs_membership_types::capabilities::TransportCarrier,
) -> Result<CarrierSelectionResult, CarrierSelectionError> {
    CarrierSelector::new(local_backend).select(peer_carriers)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_types::capabilities::TransportCarrier;

    // ── RDMA-preferred paths ──────────────────────────────────────

    #[test]
    fn rdma_preferred_when_both_sides_support() {
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Rdma);
        assert!(matches!(result.fallback, CarrierSelectionFallback::Direct));
    }

    #[test]
    fn rdma_selected_when_both_only_rdma() {
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        let peer = TransportCarrier::RDMA;
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Rdma);
        assert!(matches!(result.fallback, CarrierSelectionFallback::Direct));
    }

    // ── TCP fallback paths ────────────────────────────────────────

    #[test]
    fn tcp_fallback_when_local_tcp_peer_rdma_and_tcp() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Tcp);
        assert!(matches!(
            result.fallback,
            CarrierSelectionFallback::Fallback {
                requested: "rdma",
                reason: "local backend does not support RDMA",
            }
        ));
    }

    #[test]
    fn tcp_direct_when_both_tcp_only() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::TCP;
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Tcp);
        assert!(matches!(result.fallback, CarrierSelectionFallback::Direct));
    }

    #[test]
    fn tcp_direct_when_local_rdma_peer_tcp_only() {
        // Even though local prefers RDMA, peer only has TCP.
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        let peer = TransportCarrier::TCP;
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Tcp);
        assert!(matches!(result.fallback, CarrierSelectionFallback::Direct));
    }

    #[test]
    fn tls_fallback_when_local_tls_peer_rdma_and_tcp() {
        let selector = CarrierSelector::new(TransportBackendKind::Tls);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Tls);
        assert!(matches!(
            result.fallback,
            CarrierSelectionFallback::Fallback {
                requested: "rdma",
                reason: "local backend does not support RDMA",
            }
        ));
    }

    #[test]
    fn tls_direct_when_local_tls_peer_tcp_only() {
        let selector = CarrierSelector::new(TransportBackendKind::Tls);
        let peer = TransportCarrier::TCP;
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Tls);
        assert!(matches!(result.fallback, CarrierSelectionFallback::Direct));
    }

    // ── Error paths ───────────────────────────────────────────────

    #[test]
    fn error_peer_advertises_none() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let err = selector.select(TransportCarrier::NONE).unwrap_err();
        assert!(matches!(err, CarrierSelectionError::PeerAdvertisesNone));
    }

    #[test]
    fn error_no_mutual_when_local_tcp_peer_rdma_only() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::RDMA;
        let err = selector.select(peer).unwrap_err();
        assert!(matches!(err, CarrierSelectionError::NoMutualCarrier));
    }

    #[test]
    fn error_no_mutual_when_local_tls_peer_rdma_only() {
        let selector = CarrierSelector::new(TransportBackendKind::Tls);
        let peer = TransportCarrier::RDMA;
        let err = selector.select(peer).unwrap_err();
        assert!(matches!(err, CarrierSelectionError::NoMutualCarrier));
    }

    #[test]
    fn error_unsupported_when_peer_only_unknown_bits() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        // Bit 2 (value 4): not TCP, not RDMA.
        let peer = TransportCarrier(1 << 2);
        let err = selector.select(peer).unwrap_err();
        assert!(matches!(
            err,
            CarrierSelectionError::UnsupportedLocalCarrier
        ));
    }

    // ── Deterministic tie-break ───────────────────────────────────

    #[test]
    fn deterministic_rdma_over_tcp_regardless_of_bit_order() {
        // RDMA is always preferred over TCP even when both bits are set.
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        // TCP + RDMA in the bitmask
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let result = selector.select(peer).unwrap();
        assert_eq!(result.backend_kind, TransportBackendKind::Rdma);
    }

    #[test]
    fn deterministic_same_result_repeat() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let r1 = selector.select(peer).unwrap();
        let r2 = selector.select(peer).unwrap();
        assert_eq!(r1.backend_kind, r2.backend_kind);
        assert_eq!(r1.fallback, r2.fallback);
    }

    // ── Convenience free function ─────────────────────────────────

    #[test]
    fn free_function_matches_selector() {
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        let r1 = selector.select(peer).unwrap();
        let r2 = select_carrier(TransportBackendKind::Rdma, peer).unwrap();
        assert_eq!(r1.backend_kind, r2.backend_kind);
    }

    // ── Display impls ─────────────────────────────────────────────

    #[test]
    fn error_display_non_empty() {
        let e = CarrierSelectionError::NoMutualCarrier;
        assert!(!format!("{e}").is_empty());
        let e = CarrierSelectionError::PeerAdvertisesNone;
        assert!(!format!("{e}").is_empty());
        let e = CarrierSelectionError::UnsupportedLocalCarrier;
        assert!(!format!("{e}").is_empty());
    }

    #[test]
    fn fallback_display_non_empty() {
        let f = CarrierSelectionFallback::Direct;
        assert!(!format!("{f}").is_empty());
        let f = CarrierSelectionFallback::Fallback {
            requested: "rdma",
            reason: "no local RDMA device",
        };
        assert!(!format!("{f}").is_empty());
    }

    // ── Selector properties ───────────────────────────────────────

    #[test]
    fn local_backend_accessor() {
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        assert_eq!(selector.local_backend(), TransportBackendKind::Rdma);
    }

    // ── CarrierDisclosure tests ────────────────────────────────────

    #[test]
    fn disclosure_rdma_direct() {
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let result = selector.select(peer).unwrap();
        let d = CarrierDisclosure::from_selection(result, TransportBackendKind::Rdma, peer);
        assert_eq!(d.selected_backend, TransportBackendKind::Rdma);
        assert!(matches!(d.fallback, CarrierSelectionFallback::Direct));
        assert!(d.mismatch.is_none());
        assert!(d.rationale.contains("rdma direct"));
    }

    #[test]
    fn disclosure_tcp_fallback_from_rdma() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let result = selector.select(peer).unwrap();
        let d = CarrierDisclosure::from_selection(result, TransportBackendKind::Tcp, peer);
        assert_eq!(d.selected_backend, TransportBackendKind::Tcp);
        assert!(matches!(
            d.fallback,
            CarrierSelectionFallback::Fallback { .. }
        ));
        assert!(d.mismatch.is_some());
        let m = d.mismatch.unwrap();
        assert_eq!(m.peer_advertised, "rdma");
        assert!(m.local_unsupported);
    }

    #[test]
    fn disclosure_tcp_direct_no_mismatch() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::TCP;
        let result = selector.select(peer).unwrap();
        let d = CarrierDisclosure::from_selection(result, TransportBackendKind::Tcp, peer);
        assert_eq!(d.selected_backend, TransportBackendKind::Tcp);
        assert!(matches!(d.fallback, CarrierSelectionFallback::Direct));
        assert!(d.mismatch.is_none());
        assert!(d.rationale.contains("tcp direct"));
    }

    #[test]
    fn disclosure_mismatch_rdma_peer_tcp_local() {
        // Local is RDMA but peer only advertises TCP: no mismatch.
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        let peer = TransportCarrier::TCP;
        let result = selector.select(peer).unwrap();
        let d = CarrierDisclosure::from_selection(result, TransportBackendKind::Rdma, peer);
        assert_eq!(d.selected_backend, TransportBackendKind::Tcp);
        assert!(matches!(d.fallback, CarrierSelectionFallback::Direct));
        assert!(d.mismatch.is_none());
    }

    #[test]
    fn disclosure_display_non_empty() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let result = selector.select(peer).unwrap();
        let d = CarrierDisclosure::from_selection(result, TransportBackendKind::Tcp, peer);
        let s = format!("{d}");
        assert!(!s.is_empty());
        assert!(s.contains("carrier:"));
        assert!(s.contains("tcp"));
    }

    #[test]
    fn mismatch_display_non_empty() {
        let m = CapabilityMismatch {
            peer_advertised: "rdma",
            local_unsupported: true,
            detail: "no RDMA device present",
        };
        let s = format!("{m}");
        assert!(s.contains("rdma"));
        assert!(s.contains("does not support"));
    }

    #[test]
    fn disclosure_deterministic_same_inputs_same_output() {
        let selector = CarrierSelector::new(TransportBackendKind::Tcp);
        let peer = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let r1 = selector.select(peer).unwrap();
        let r2 = selector.select(peer).unwrap();
        let d1 = CarrierDisclosure::from_selection(r1, TransportBackendKind::Tcp, peer);
        let d2 = CarrierDisclosure::from_selection(r2, TransportBackendKind::Tcp, peer);
        assert_eq!(d1, d2);
    }

    #[test]
    fn disclosure_local_requested_matches_backend() {
        let selector = CarrierSelector::new(TransportBackendKind::Rdma);
        let peer = TransportCarrier::RDMA;
        let result = selector.select(peer).unwrap();
        let d = CarrierDisclosure::from_selection(result, TransportBackendKind::Rdma, peer);
        assert_eq!(d.local_requested, "rdma");
        assert!(d.rationale.contains("rdma"));
    }

    #[test]
    fn disclosure_from_runtime_fallback_rdma_to_tcp() {
        let d = CarrierDisclosure::from_runtime_fallback(
            TransportBackendKind::Rdma,
            "permanent RDMA carrier loss",
        );
        assert_eq!(d.selected_backend, TransportBackendKind::Tcp);
        assert_eq!(d.local_backend, TransportBackendKind::Rdma);
        assert_eq!(d.local_requested, "rdma");
        assert!(matches!(
            d.fallback,
            CarrierSelectionFallback::Fallback {
                requested: "rdma",
                ..
            }
        ));
        assert!(d.mismatch.is_none());
        assert!(d.rationale.contains("runtime fallback"));
        let s = format!("{d}");
        assert!(s.contains("tcp"));
        assert!(s.contains("fallback"));
    }

    #[test]
    fn disclosure_from_runtime_fallback_uses_configured_reason() {
        let d = CarrierDisclosure::from_runtime_fallback(
            TransportBackendKind::Rdma,
            "reconnect exhausted after 3 attempts",
        );
        match d.fallback {
            CarrierSelectionFallback::Fallback { reason, .. } => {
                assert!(reason.contains("reconnect exhausted"));
            }
            _ => panic!("expected fallback"),
        }
    }
}
