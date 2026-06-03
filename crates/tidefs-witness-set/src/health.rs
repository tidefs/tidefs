// Per-member health tracking for witness set members.
//
// WitnessHealth tracks the liveness state of each witness set member.
// Health transitions are driven by external heartbeat/timeout events
// and feed into quorum_available() for runtime quorum evaluation.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// WitnessHealth
// ---------------------------------------------------------------------------

/// Health state of a single witness set member.
///
/// Members transition through Online, Suspect, and Offline based on
/// heartbeat responsiveness. Only Online members contribute their full
/// voting weight to quorum calculations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessHealth {
    /// Member is responding to heartbeats and participating normally.
    /// Contributes full weight to quorum.
    Online,
    /// Member has missed recent heartbeats but has not yet timed out.
    /// Does not contribute weight to quorum; may recover to Online.
    Suspect,
    /// Member is unresponsive and has exceeded the suspect timeout.
    /// Does not contribute weight; requires explicit rejoin to recover.
    Offline,
}

impl WitnessHealth {
    /// Transition from the current health state given an event.
    /// Returns the new health state.
    pub fn transition(self, event: HealthEvent) -> Self {
        match (self, event) {
            // Online -> Suspect on heartbeat miss.
            (Self::Online, HealthEvent::HeartbeatMissed) => Self::Suspect,
            // Suspect -> Offline on timeout.
            (Self::Suspect, HealthEvent::Timeout) => Self::Offline,
            // Suspect -> Online on rejoin (heartbeat recovered).
            (Self::Suspect, HealthEvent::Rejoined) => Self::Online,
            // Offline -> Online on explicit rejoin.
            (Self::Offline, HealthEvent::Rejoined) => Self::Online,
            // All other transitions are no-ops.
            (other, _) => other,
        }
    }

    /// Whether this state is considered healthy for quorum calculations.
    /// Only Online members contribute to healthy weight.
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Online)
    }
}

impl Default for WitnessHealth {
    fn default() -> Self {
        Self::Online
    }
}

// ---------------------------------------------------------------------------
// HealthEvent
// ---------------------------------------------------------------------------

/// An event that can trigger a health state transition for a witness member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthEvent {
    /// A heartbeat was missed (triggers Online -> Suspect).
    HeartbeatMissed,
    /// The suspect grace period expired (triggers Suspect -> Offline).
    Timeout,
    /// The member rejoined or heartbeats resumed (triggers Suspect/Offline -> Online).
    Rejoined,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_online() {
        assert_eq!(WitnessHealth::default(), WitnessHealth::Online);
        assert!(WitnessHealth::Online.is_healthy());
    }

    #[test]
    fn test_online_to_suspect_on_heartbeat_miss() {
        let s = WitnessHealth::Online.transition(HealthEvent::HeartbeatMissed);
        assert_eq!(s, WitnessHealth::Suspect);
        assert!(!s.is_healthy());
    }

    #[test]
    fn test_suspect_to_offline_on_timeout() {
        let s = WitnessHealth::Suspect.transition(HealthEvent::Timeout);
        assert_eq!(s, WitnessHealth::Offline);
        assert!(!s.is_healthy());
    }

    #[test]
    fn test_suspect_to_online_on_rejoin() {
        let s = WitnessHealth::Suspect.transition(HealthEvent::Rejoined);
        assert_eq!(s, WitnessHealth::Online);
        assert!(s.is_healthy());
    }

    #[test]
    fn test_offline_to_online_on_rejoin() {
        let s = WitnessHealth::Offline.transition(HealthEvent::Rejoined);
        assert_eq!(s, WitnessHealth::Online);
        assert!(s.is_healthy());
    }

    #[test]
    fn test_online_stays_online_on_timeout() {
        // Timeout is only meaningful from Suspect; Online ignores it.
        let s = WitnessHealth::Online.transition(HealthEvent::Timeout);
        assert_eq!(s, WitnessHealth::Online);
        assert!(s.is_healthy());
    }

    #[test]
    fn test_offline_stays_offline_on_heartbeat_miss() {
        let s = WitnessHealth::Offline.transition(HealthEvent::HeartbeatMissed);
        assert_eq!(s, WitnessHealth::Offline);
    }

    #[test]
    fn test_online_rejoin_is_noop() {
        let s = WitnessHealth::Online.transition(HealthEvent::Rejoined);
        assert_eq!(s, WitnessHealth::Online);
    }

    #[test]
    fn test_suspect_heartbeat_miss_is_noop() {
        let s = WitnessHealth::Suspect.transition(HealthEvent::HeartbeatMissed);
        assert_eq!(s, WitnessHealth::Suspect);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut h = WitnessHealth::Online;
        assert!(h.is_healthy());

        h = h.transition(HealthEvent::HeartbeatMissed);
        assert_eq!(h, WitnessHealth::Suspect);
        assert!(!h.is_healthy());

        h = h.transition(HealthEvent::Timeout);
        assert_eq!(h, WitnessHealth::Offline);
        assert!(!h.is_healthy());

        h = h.transition(HealthEvent::Rejoined);
        assert_eq!(h, WitnessHealth::Online);
        assert!(h.is_healthy());
    }

    #[test]
    fn test_recovery_from_suspect_without_timeout() {
        let mut h = WitnessHealth::Online;
        h = h.transition(HealthEvent::HeartbeatMissed);
        assert_eq!(h, WitnessHealth::Suspect);
        // Heartbeat resumes before timeout.
        h = h.transition(HealthEvent::Rejoined);
        assert_eq!(h, WitnessHealth::Online);
        assert!(h.is_healthy());
    }

    // -- Serialization -------------------------------------------------------

    #[test]
    fn test_serialize_deserialize_health() {
        for state in &[
            WitnessHealth::Online,
            WitnessHealth::Suspect,
            WitnessHealth::Offline,
        ] {
            let json = serde_json::to_string(state).unwrap();
            let s2: WitnessHealth = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, s2);
        }
    }
}
