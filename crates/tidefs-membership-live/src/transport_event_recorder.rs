// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport event recorder for deterministic epoch-transition testing.
//!
//! Records `MembershipTransportEvent` instances into a thread-safe event log
//! that can be exported and replayed deterministically. Bridges the gap
//! between live transport-driven membership behavior and reproducible
//! integration tests.
//!
//! ## Event Schema
//!
//! - [`MembershipTransportEvent`]: six event kinds covering the full transport-
//!   to-membership bridge: peer connect/disconnect, health-score changes,
//!   protocol message send/receive, and connection errors.
//! - Every event carries a monotonic sequence number and wall-clock timestamp.
//!
//! ## Recording Lifecycle
//!
//! 1. Create a `TransportEventRecorder` (starts in recording state).
//! 2. Call `record(event)` each time a transport event arrives that should
//!    be captured for later replay.
//! 3. Call `drain_events()` to obtain the recorded `EventLog` for export.
//! 4. Call `stop_recording()` to cease capture; `start_recording()` to resume.
//!
//! ## Thread Safety
//!
//! The recorder wraps an `Arc<RwLock<EventLog>>`, safe for concurrent recording
//! from multiple threads alongside a live transport stack.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::MemberId;

use crate::transport_wiring::MembershipWireMessage;

// ---------------------------------------------------------------------------
// MembershipTransportEvent
// ---------------------------------------------------------------------------

/// A single transport-level event consumed by the membership layer.
///
/// Captures the complete set of transport-to-membership bridge events so
/// that epoch-transition logic can be recorded and deterministically replayed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MembershipTransportEvent {
    /// A peer's transport session became ready (connected + handshake done).
    PeerConnected {
        peer_id: MemberId,
        /// Human-readable label for the event log; not used during replay.
        label: String,
    },
    /// A peer's transport session was torn down (graceful close or failure).
    PeerDisconnected { peer_id: MemberId, label: String },
    /// The transport health score for a peer changed.
    HealthScoreChanged {
        peer_id: MemberId,
        /// Score in [0.0, 1.0]; 1.0 = optimal.
        score: f64,
    },
    /// A membership protocol message arrived over the transport.
    MessageReceived {
        from_peer: MemberId,
        /// The wire-level membership message payload.
        wire_msg: MembershipWireMessage,
    },
    /// A membership protocol message was successfully sent to a peer.
    MessageSendCompleted {
        to_peer: MemberId,
        /// Monotonic send sequence number assigned by the transport.
        send_seq: u64,
    },
    /// A transport error was observed for a peer's connection.
    ConnectionError {
        peer_id: MemberId,
        /// Human-readable error description.
        error_kind: String,
    },
}

impl MembershipTransportEvent {
    /// Return the peer this event pertains to, if any.
    pub fn peer_id(&self) -> Option<MemberId> {
        match self {
            Self::PeerConnected { peer_id, .. }
            | Self::PeerDisconnected { peer_id, .. }
            | Self::HealthScoreChanged { peer_id, .. }
            | Self::ConnectionError { peer_id, .. } => Some(*peer_id),
            Self::MessageReceived { from_peer, .. } => Some(*from_peer),
            Self::MessageSendCompleted { to_peer, .. } => Some(*to_peer),
        }
    }
}

// ---------------------------------------------------------------------------
// TimestampedEvent
// ---------------------------------------------------------------------------

/// A recorded event with its monotonic sequence number and wall-clock timestamp.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimestampedEvent {
    /// Monotonic sequence number assigned at record time.
    pub seq: u64,
    /// Wall-clock timestamp in milliseconds since UNIX epoch.
    pub at_millis: u64,
    /// The transport event.
    pub event: MembershipTransportEvent,
}

// ---------------------------------------------------------------------------
// EventLog
// ---------------------------------------------------------------------------

/// A complete log of recorded membership transport events.
///
/// Serializable for bug-reproduction export: save to JSON/bincode, reload
/// in a deterministic replay harness.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventLog {
    /// Ordered sequence of timestamped events.
    pub events: Vec<TimestampedEvent>,
    /// Total number of events recorded (may exceed `events.len()` after drain).
    pub total_recorded: u64,
}

impl EventLog {
    /// Create an empty event log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of events currently in the log.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl IntoIterator for EventLog {
    type Item = TimestampedEvent;
    type IntoIter = std::vec::IntoIter<TimestampedEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.into_iter()
    }
}

// ---------------------------------------------------------------------------
// TransportEventRecorder
// ---------------------------------------------------------------------------

/// Thread-safe recorder for membership transport events.
///
/// Wraps an `Arc<RwLock<EventLog>>` so it can be shared across threads
/// alongside a live transport stack. Cloning the recorder shares the
/// underlying log.
#[derive(Clone, Debug)]
pub struct TransportEventRecorder {
    log: Arc<RwLock<EventLog>>,
    recording: Arc<RwLock<bool>>,
}

impl TransportEventRecorder {
    /// Create a new recorder, starting in recording state.
    pub fn new() -> Self {
        Self {
            log: Arc::new(RwLock::new(EventLog::new())),
            recording: Arc::new(RwLock::new(true)),
        }
    }

    /// Start recording events. Idempotent: does nothing if already recording.
    pub fn start_recording(&self) {
        if let Ok(mut r) = self.recording.write() {
            *r = true;
        }
    }

    /// Stop recording events. Subsequent `record()` calls will be silently
    /// dropped until `start_recording()` is called again.
    pub fn stop_recording(&self) {
        if let Ok(mut r) = self.recording.write() {
            *r = false;
        }
    }

    /// Whether the recorder is currently recording.
    pub fn is_recording(&self) -> bool {
        self.recording.read().map(|r| *r).unwrap_or(false)
    }

    /// Record a transport event.
    ///
    /// If the recorder is stopped, the event is silently dropped.
    /// Returns the sequence number assigned to the event, or `None` if
    /// recording is stopped.
    pub fn record(&self, event: MembershipTransportEvent) -> Option<u64> {
        if !self.is_recording() {
            return None;
        }

        let at_millis = now_millis();

        if let Ok(mut log) = self.log.write() {
            log.total_recorded += 1;
            let seq = log.total_recorded;
            log.events.push(TimestampedEvent {
                seq,
                at_millis,
                event,
            });
            Some(seq)
        } else {
            None
        }
    }

    /// Drain all recorded events from the log, returning them as an `EventLog`.
    ///
    /// After draining, the recorder's internal log is empty and ready to
    /// capture new events. Draining does not affect the recording state.
    pub fn drain_events(&self) -> EventLog {
        if let Ok(mut log) = self.log.write() {
            let drained = log.clone();
            log.events.clear();
            // Keep total_recorded so sequence numbers continue monotonically.
            drained
        } else {
            EventLog::new()
        }
    }

    /// Return a clone of the current event log without clearing it.
    pub fn snapshot(&self) -> EventLog {
        self.log.read().map(|log| log.clone()).unwrap_or_default()
    }

    /// Return the number of events currently in the log.
    pub fn event_count(&self) -> usize {
        self.log.read().map(|log| log.events.len()).unwrap_or(0)
    }

    /// Export the current log as a JSON string for bug-reproduction sharing.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let log = self.log.read().map(|log| log.clone()).unwrap_or_default();
        serde_json::to_string_pretty(&log)
    }

    /// Import a previously exported JSON event log, appending its events
    /// to the current log (preserving existing events).
    pub fn import_json(&self, json: &str) -> Result<usize, serde_json::Error> {
        let imported: EventLog = serde_json::from_str(json)?;
        let count = imported.events.len();
        if let Ok(mut log) = self.log.write() {
            log.events.extend(imported.events);
            log.total_recorded += count as u64;
        }
        Ok(count)
    }
}

impl Default for TransportEventRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the current wall-clock time in milliseconds since UNIX epoch.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(peer: u64) -> MembershipTransportEvent {
        MembershipTransportEvent::PeerConnected {
            peer_id: MemberId::new(peer),
            label: format!("peer-{peer}"),
        }
    }

    // -- start / stop / drain lifecycle

    #[test]
    fn record_stores_event_and_assigns_monotonic_seq() {
        let rec = TransportEventRecorder::new();
        let s1 = rec.record(make_event(1)).expect("seq");
        let s2 = rec.record(make_event(2)).expect("seq");
        assert!(s2 > s1, "sequences must be monotonic");
        assert_eq!(rec.event_count(), 2);
    }

    #[test]
    fn stop_recording_silently_drops_events() {
        let rec = TransportEventRecorder::new();
        rec.record(make_event(1));
        rec.stop_recording();
        assert!(rec.record(make_event(2)).is_none());
        assert_eq!(rec.event_count(), 1);
    }

    #[test]
    fn start_recording_resumes_after_stop() {
        let rec = TransportEventRecorder::new();
        rec.record(make_event(1));
        rec.stop_recording();
        rec.record(make_event(2));
        rec.start_recording();
        let s = rec.record(make_event(3)).expect("seq after resume");
        assert!(s > 0);
        assert_eq!(rec.event_count(), 2);
    }

    #[test]
    fn drain_returns_recorded_events_and_clears_log() {
        let rec = TransportEventRecorder::new();
        rec.record(make_event(1));
        rec.record(make_event(2));

        let drained = rec.drain_events();
        assert_eq!(drained.events.len(), 2);
        assert_eq!(drained.events[0].event.peer_id(), Some(MemberId::new(1)));
        assert_eq!(drained.events[1].event.peer_id(), Some(MemberId::new(2)));

        assert_eq!(rec.event_count(), 0);
    }

    #[test]
    fn drain_preserves_monotonic_total() {
        let rec = TransportEventRecorder::new();
        rec.record(make_event(1));
        let _drained = rec.drain_events();
        let s = rec.record(make_event(2)).expect("seq after drain");
        // total_recorded is preserved across drains, so seq continues
        assert_eq!(s, 2);
    }

    #[test]
    fn empty_drain_returns_empty_log() {
        let rec = TransportEventRecorder::new();
        let drained = rec.drain_events();
        assert!(drained.is_empty());
    }

    #[test]
    fn snapshot_does_not_clear() {
        let rec = TransportEventRecorder::new();
        rec.record(make_event(1));
        let snap = rec.snapshot();
        assert_eq!(snap.events.len(), 1);
        assert_eq!(rec.event_count(), 1);
    }

    // -- threading

    #[test]
    fn concurrent_recording_produces_coherent_log() {
        let rec = TransportEventRecorder::new();
        let rec2 = rec.clone();

        let h = std::thread::spawn(move || {
            for i in 0..10 {
                rec2.record(make_event(100 + i));
            }
        });
        for i in 0..10 {
            rec.record(make_event(200 + i));
        }
        h.join().unwrap();

        let drained = rec.drain_events();
        assert_eq!(drained.events.len(), 20);
    }

    // -- JSON export / import

    #[test]
    fn json_roundtrip_preserves_events() {
        let rec = TransportEventRecorder::new();
        rec.record(make_event(1));
        rec.record(MembershipTransportEvent::HealthScoreChanged {
            peer_id: MemberId::new(2),
            score: 0.75,
        });

        let json = rec.export_json().expect("export");
        assert!(json.contains("PeerConnected"));
        assert!(json.contains("HealthScoreChanged"));

        let rec2 = TransportEventRecorder::new();
        let count = rec2.import_json(&json).expect("import");
        assert_eq!(count, 2);
        assert_eq!(rec2.event_count(), 2);
    }

    // -- all event variants serialize

    #[test]
    fn all_event_variants_serialize() {
        let msg = MembershipWireMessage::Ping(crate::types::SwimPing {
            pinger: MemberId::new(1),
            ping_target: MemberId::new(2),
            seq_no: 1,
            pinger_epoch: tidefs_membership_epoch::EpochId::new(1),
            pinger_epoch_receipt: 0,
            sent_at_millis: 100,
            indirect_via: vec![],
            signature: vec![0x42],
        });

        let events = vec![
            MembershipTransportEvent::PeerConnected {
                peer_id: MemberId::new(1),
                label: "test".into(),
            },
            MembershipTransportEvent::PeerDisconnected {
                peer_id: MemberId::new(1),
                label: "test".into(),
            },
            MembershipTransportEvent::HealthScoreChanged {
                peer_id: MemberId::new(1),
                score: 0.5,
            },
            MembershipTransportEvent::MessageReceived {
                from_peer: MemberId::new(2),
                wire_msg: msg,
            },
            MembershipTransportEvent::MessageSendCompleted {
                to_peer: MemberId::new(2),
                send_seq: 42,
            },
            MembershipTransportEvent::ConnectionError {
                peer_id: MemberId::new(1),
                error_kind: "timeout".into(),
            },
        ];

        let json = serde_json::to_string_pretty(&events).expect("serialize");
        let decoded: Vec<MembershipTransportEvent> =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.len(), events.len());
    }

    // -- peer_id extraction

    #[test]
    fn peer_id_returns_correct_peer_for_each_variant() {
        assert_eq!(
            MembershipTransportEvent::PeerConnected {
                peer_id: MemberId::new(1),
                label: "".into()
            }
            .peer_id(),
            Some(MemberId::new(1))
        );
        assert_eq!(
            MembershipTransportEvent::MessageReceived {
                from_peer: MemberId::new(3),
                wire_msg: MembershipWireMessage::View(crate::types::MembershipView {
                    epoch: tidefs_membership_epoch::EpochId::new(1),
                    config_class: tidefs_membership_epoch::ConfigClass::Normal,
                    local_member: MemberId::new(1),
                    placement_version: 0,
                    nodes: vec![],
                }),
            }
            .peer_id(),
            Some(MemberId::new(3))
        );
        assert_eq!(
            MembershipTransportEvent::MessageSendCompleted {
                to_peer: MemberId::new(5),
                send_seq: 1,
            }
            .peer_id(),
            Some(MemberId::new(5))
        );
    }
}
