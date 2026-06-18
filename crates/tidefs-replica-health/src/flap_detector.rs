// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Flap detection with exponential backoff.
//!
//! TideFS detects flap episodes and applies exponential backoff:
//! 30s -> 60s -> 120s -> 240s -> 480s -> capped at 600s.
//! During backoff, the cluster does NOT react to the flapping node.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::suspicion::SuspicionLevel;
use crate::NodeId;

#[derive(Clone, Debug)]
pub struct FlapDetector {
    flap_window_ns: u64,
    backoffs: BTreeMap<NodeId, FlapBackoff>,
}

#[derive(Clone, Debug)]
pub struct FlapBackoff {
    pub in_backoff: bool,
    pub backoff_duration: Duration,
    pub backoff_started: u64,
    pub backoff_until: u64,
    pub flap_episodes: u32,
    pub last_flap: u64,
    pub last_stable_state: SuspicionLevel,
}

#[derive(Clone, Copy, Debug)]
pub struct FlapEvent {
    pub previous_state: SuspicionLevel,
    pub new_state: SuspicionLevel,
    pub at_ns: u64,
}

impl FlapDetector {
    pub fn new(flap_window: Duration) -> Self {
        FlapDetector {
            flap_window_ns: flap_window.as_nanos() as u64,
            backoffs: BTreeMap::new(),
        }
    }

    pub fn record_transition(&mut self, node_id: NodeId, event: FlapEvent) -> bool {
        let backoff = self.backoffs.entry(node_id).or_insert_with(|| FlapBackoff {
            in_backoff: false,
            backoff_duration: Duration::from_secs(0),
            backoff_started: 0,
            backoff_until: 0,
            flap_episodes: 0,
            last_flap: 0,
            last_stable_state: SuspicionLevel::Healthy,
        });

        let now = event.at_ns;

        if !Self::is_flapping_transition(event.previous_state, event.new_state) {
            backoff.last_stable_state = event.previous_state;
            backoff.last_flap = now;
            return false;
        }

        let time_since_last = if backoff.last_flap > 0 && now >= backoff.last_flap {
            now - backoff.last_flap
        } else {
            // First ever transition — record baseline but don't flag as flap
            backoff.last_flap = now;
            return false;
        };

        let is_flap = time_since_last < self.flap_window_ns;

        if is_flap {
            backoff.flap_episodes += 1;
            backoff.in_backoff = true;
            backoff.backoff_duration = Self::compute_backoff(backoff.flap_episodes);
            backoff.backoff_started = now;
            let dur_ns = backoff.backoff_duration.as_nanos() as u64;
            backoff.backoff_until = now.saturating_add(dur_ns);
        }

        backoff.last_flap = now;
        is_flap
    }

    pub fn is_in_backoff(&self, node_id: NodeId, now_ns: u64) -> bool {
        self.backoffs
            .get(&node_id)
            .is_some_and(|b| b.in_backoff && now_ns < b.backoff_until)
    }

    pub fn get_backoff(&self, node_id: NodeId) -> Option<&FlapBackoff> {
        self.backoffs.get(&node_id)
    }

    pub fn check_backoff_expiry(&mut self, now_ns: u64) -> Vec<NodeId> {
        let mut expired = Vec::new();
        for (node_id, backoff) in &mut self.backoffs {
            if backoff.in_backoff && now_ns >= backoff.backoff_until {
                backoff.in_backoff = false;
                expired.push(*node_id);
            }
        }
        expired
    }

    pub fn remove_node(&mut self, node_id: NodeId) {
        self.backoffs.remove(&node_id);
    }

    fn is_flapping_transition(from: SuspicionLevel, to: SuspicionLevel) -> bool {
        matches!(
            (from, to),
            (SuspicionLevel::Down, _)
                | (SuspicionLevel::Degraded, SuspicionLevel::Healthy)
                | (SuspicionLevel::Degraded, SuspicionLevel::Sluggish)
                | (SuspicionLevel::Suspect, SuspicionLevel::Healthy)
        ) || (from != SuspicionLevel::Down && to == SuspicionLevel::Down)
    }

    fn compute_backoff(episodes: u32) -> Duration {
        let secs = (30u64).saturating_mul(2u64.saturating_pow(episodes.saturating_sub(1)));
        Duration::from_secs(secs.min(600))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS_PER_SEC: u64 = 1_000_000_000;

    #[test]
    fn two_rapid_down_up_transitions_triggers_flap() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);

        // First transition sets baseline
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: NS_PER_SEC,
            },
        );

        // Second within 60s flap window -> flap
        let is_flap = detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert!(is_flap);
        let backoff = detector.get_backoff(node).unwrap();
        assert!(backoff.in_backoff);
        assert_eq!(backoff.flap_episodes, 1);
    }

    #[test]
    fn backoff_is_exponential() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);

        // Episode 1
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: NS_PER_SEC,
            },
        );
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert_eq!(detector.get_backoff(node).unwrap().flap_episodes, 1);

        // Episode 2 (after backoff expires)
        let mut t = 100 * NS_PER_SEC;
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: t,
            },
        );
        t += NS_PER_SEC;
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: t,
            },
        );
        assert_eq!(detector.get_backoff(node).unwrap().flap_episodes, 2);
        // 2nd episode: 30 * 2^1 = 60s
        assert_eq!(
            detector.get_backoff(node).unwrap().backoff_duration,
            Duration::from_secs(60)
        );

        // Episode 3
        t = 200 * NS_PER_SEC;
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: t,
            },
        );
        t += NS_PER_SEC;
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: t,
            },
        );
        assert_eq!(detector.get_backoff(node).unwrap().flap_episodes, 3);
        // 3rd episode: 30 * 2^2 = 120s
        assert_eq!(
            detector.get_backoff(node).unwrap().backoff_duration,
            Duration::from_secs(120)
        );
    }

    #[test]
    fn non_flapping_transition_not_detected() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);

        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Sluggish,
                new_state: SuspicionLevel::Suspect,
                at_ns: NS_PER_SEC,
            },
        );

        let is_flap = detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Sluggish,
                new_state: SuspicionLevel::Suspect,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert!(!is_flap);
        assert!(!detector.get_backoff(node).unwrap().in_backoff);
    }

    #[test]
    fn slow_transitions_not_detected_as_flap() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: NS_PER_SEC,
            },
        );
        let is_flap = detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: 62 * NS_PER_SEC,
            },
        );
        assert!(!is_flap);
    }

    #[test]
    fn is_in_backoff_during_active_backoff() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: NS_PER_SEC,
            },
        );
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert!(detector.is_in_backoff(node, 3 * NS_PER_SEC));
        assert!(!detector.is_in_backoff(node, 33 * NS_PER_SEC));
    }

    #[test]
    fn check_backoff_expiry_returns_expired_nodes() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);
        for &node in &[n1, n2] {
            detector.record_transition(
                node,
                FlapEvent {
                    previous_state: SuspicionLevel::Down,
                    new_state: SuspicionLevel::Healthy,
                    at_ns: NS_PER_SEC,
                },
            );
            detector.record_transition(
                node,
                FlapEvent {
                    previous_state: SuspicionLevel::Down,
                    new_state: SuspicionLevel::Healthy,
                    at_ns: 2 * NS_PER_SEC,
                },
            );
        }
        assert!(detector.is_in_backoff(n1, 3 * NS_PER_SEC));
        let expired = detector.check_backoff_expiry(35 * NS_PER_SEC);
        assert_eq!(expired.len(), 2);
        assert!(!detector.is_in_backoff(n1, 35 * NS_PER_SEC));
        let expired2 = detector.check_backoff_expiry(40 * NS_PER_SEC);
        assert!(expired2.is_empty());
    }

    #[test]
    fn remove_node_cleans_up_backoff_state() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: NS_PER_SEC,
            },
        );
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Down,
                new_state: SuspicionLevel::Healthy,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert!(detector.get_backoff(node).is_some());
        detector.remove_node(node);
        assert!(detector.get_backoff(node).is_none());
        assert!(!detector.is_in_backoff(node, 3 * NS_PER_SEC));
    }

    #[test]
    fn suspected_to_healthy_is_flapping_transition() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Suspect,
                new_state: SuspicionLevel::Healthy,
                at_ns: NS_PER_SEC,
            },
        );
        let is_flap = detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Suspect,
                new_state: SuspicionLevel::Healthy,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert!(is_flap);
        assert!(detector.get_backoff(node).unwrap().in_backoff);
    }

    #[test]
    fn degraded_to_healthy_is_flapping() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Degraded,
                new_state: SuspicionLevel::Healthy,
                at_ns: NS_PER_SEC,
            },
        );
        let is_flap = detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Degraded,
                new_state: SuspicionLevel::Healthy,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert!(is_flap);
    }

    #[test]
    fn degraded_to_sluggish_is_flapping() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Degraded,
                new_state: SuspicionLevel::Sluggish,
                at_ns: NS_PER_SEC,
            },
        );
        let is_flap = detector.record_transition(
            node,
            FlapEvent {
                previous_state: SuspicionLevel::Degraded,
                new_state: SuspicionLevel::Sluggish,
                at_ns: 2 * NS_PER_SEC,
            },
        );
        assert!(is_flap);
    }

    #[test]
    fn flap_backoff_capped_at_600_seconds() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        // Simulate many episodes - each requires 2 rapid transitions
        // Episode 1-8
        for episode in 1u64..=8 {
            let t = episode * 1000 * NS_PER_SEC;
            detector.record_transition(
                node,
                FlapEvent {
                    previous_state: SuspicionLevel::Down,
                    new_state: SuspicionLevel::Healthy,
                    at_ns: t,
                },
            );
            detector.record_transition(
                node,
                FlapEvent {
                    previous_state: SuspicionLevel::Down,
                    new_state: SuspicionLevel::Healthy,
                    at_ns: t + NS_PER_SEC,
                },
            );
        }
        let backoff = detector.get_backoff(node).unwrap();
        assert!(
            backoff.backoff_duration <= Duration::from_secs(600),
            "backoff {:.0}s exceeds cap",
            backoff.backoff_duration.as_secs_f64()
        );
    }

    #[test]
    fn flap_episode_counter_increments() {
        let mut detector = FlapDetector::new(Duration::from_secs(60));
        let node = NodeId::new(1);
        for ep in 1u64..=4 {
            let t = ep * 100 * NS_PER_SEC;
            detector.record_transition(
                node,
                FlapEvent {
                    previous_state: SuspicionLevel::Down,
                    new_state: SuspicionLevel::Healthy,
                    at_ns: t,
                },
            );
            detector.record_transition(
                node,
                FlapEvent {
                    previous_state: SuspicionLevel::Down,
                    new_state: SuspicionLevel::Healthy,
                    at_ns: t + NS_PER_SEC,
                },
            );
            assert_eq!(detector.get_backoff(node).unwrap().flap_episodes, ep as u32);
        }
    }
}
