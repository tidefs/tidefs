// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport send-priority scheduler with per-class queuing and starvation
//! prevention for the outbound send path.
//!
//! ## Design
//!
//! Five priority classes (`Control`, `Membership`, `IntentLog`, `Data`, `Bulk`)
//! each have an independent FIFO sub-queue. Dequeue uses weighted round-robin:
//! each class gets a budget of consecutive dequeues proportional to its
//! configured weight. Starvation is prevented by a guard counter: after N
//! higher-priority dequeues, a lower-priority message is forcibly promoted.
//!
//! ## Message classes
//!
//! | Class      | Priority | Use cases                                  |
//! |------------|----------|--------------------------------------------|
//! | Control    | highest  | membership liveness, epoch transitions     |
//! | Membership | high     | roster changes, peer admission             |
//! | IntentLog  | medium   | intent-log commits, durability barriers    |
//! | Data       | normal   | data transfer, control-plane messages      |
//! | Bulk       | low      | scrub, rebuild, backfill                   |

use std::collections::VecDeque;
use std::time::Instant;

// ---------------------------------------------------------------------------
// SendPriority
// ---------------------------------------------------------------------------

/// Message priority class for transport send scheduling.
///
/// Messages are classified by their importance to system liveness and
/// durability. The scheduler dequeues higher-priority classes more
/// frequently using weighted round-robin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SendPriority {
    /// Membership liveness, epoch transition messages.
    /// Starvation of this class causes false peer-failure detection.
    Control = 0,
    /// Roster changes, peer admission messages.
    Membership = 1,
    /// Intent-log commits, durability barrier messages.
    IntentLog = 2,
    /// Normal data I/O and control-plane messages.
    Data = 3,
    /// Scrub, rebuild, backfill traffic.
    /// Lowest priority; starvation is acceptable for longer intervals.
    Bulk = 4,
}

impl SendPriority {
    /// Number of distinct priority classes.
    pub const fn count() -> usize {
        5
    }

    /// All classes in priority order (highest first).
    pub fn all() -> [SendPriority; 5] {
        [
            SendPriority::Control,
            SendPriority::Membership,
            SendPriority::IntentLog,
            SendPriority::Data,
            SendPriority::Bulk,
        ]
    }

    fn from_index(idx: usize) -> Self {
        match idx {
            0 => SendPriority::Control,
            1 => SendPriority::Membership,
            2 => SendPriority::IntentLog,
            3 => SendPriority::Data,
            4 => SendPriority::Bulk,
            _ => panic!("invalid SendPriority index: {idx}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SendSchedulerConfig
// ---------------------------------------------------------------------------

/// Configuration for the send-priority scheduler.
///
/// Weights control how many messages are dequeued from each class per
/// round-robin round. A weight of 0 means the class is skipped entirely.
/// Max-burst limits prevent a single class from hogging the scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendSchedulerConfig {
    /// Weight for the Control class in weighted round-robin.
    pub control_weight: u32,
    /// Weight for the Membership class.
    pub membership_weight: u32,
    /// Weight for the IntentLog class.
    pub intent_log_weight: u32,
    /// Weight for the Data class.
    pub data_weight: u32,
    /// Weight for the Bulk class.
    pub bulk_weight: u32,
    /// Maximum consecutive dequeues from Control before yielding.
    pub control_max_burst: usize,
    /// Maximum consecutive dequeues from Membership before yielding.
    pub membership_max_burst: usize,
    /// Maximum consecutive dequeues from IntentLog before yielding.
    pub intent_log_max_burst: usize,
    /// Maximum consecutive dequeues from Data before yielding.
    pub data_max_burst: usize,
    /// Maximum consecutive dequeues from Bulk before yielding.
    pub bulk_max_burst: usize,
    /// Messages older than this (in milliseconds) trigger starvation
    /// prevention and are dequeued regardless of class.
    pub starvation_threshold_ms: u64,
}

impl Default for SendSchedulerConfig {
    fn default() -> Self {
        Self {
            control_weight: 10,
            membership_weight: 6,
            intent_log_weight: 3,
            data_weight: 2,
            bulk_weight: 1,
            control_max_burst: 16,
            membership_max_burst: 8,
            intent_log_max_burst: 4,
            data_max_burst: 4,
            bulk_max_burst: 2,
            starvation_threshold_ms: 1000,
        }
    }
}

impl SendSchedulerConfig {
    /// Validate the configuration. Returns `Err` on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        let total_weight = self.control_weight
            + self.membership_weight
            + self.intent_log_weight
            + self.data_weight
            + self.bulk_weight;
        if total_weight == 0 {
            return Err("total weight across all classes must be > 0".into());
        }
        if self.control_max_burst == 0
            || self.membership_max_burst == 0
            || self.intent_log_max_burst == 0
            || self.data_max_burst == 0
            || self.bulk_max_burst == 0
        {
            return Err("max_burst must be > 0 for all classes".into());
        }
        if self.starvation_threshold_ms == 0 {
            return Err("starvation_threshold_ms must be > 0".into());
        }
        Ok(())
    }

    /// Weight for a given priority class.
    pub fn weight(&self, pri: SendPriority) -> u32 {
        match pri {
            SendPriority::Control => self.control_weight,
            SendPriority::Membership => self.membership_weight,
            SendPriority::IntentLog => self.intent_log_weight,
            SendPriority::Data => self.data_weight,
            SendPriority::Bulk => self.bulk_weight,
        }
    }

    /// Max burst for a given priority class.
    pub fn max_burst(&self, pri: SendPriority) -> usize {
        match pri {
            SendPriority::Control => self.control_max_burst,
            SendPriority::Membership => self.membership_max_burst,
            SendPriority::IntentLog => self.intent_log_max_burst,
            SendPriority::Data => self.data_max_burst,
            SendPriority::Bulk => self.bulk_max_burst,
        }
    }
}

// ---------------------------------------------------------------------------
// QueuedMessage
// ---------------------------------------------------------------------------

/// A message held in a priority sub-queue, annotated with its class and
/// enqueue time for starvation detection.
#[derive(Debug)]
pub struct QueuedMessage<M> {
    /// The payload message.
    pub message: M,
    /// Priority class assigned at enqueue time.
    pub priority: SendPriority,
    /// Instant when the message was enqueued.
    pub enqueue_time: Instant,
    /// Optional send-completion handle resolved after socket write.
    pub completion: Option<crate::send_completion::SendCompletion>,
}

impl<M: Clone> Clone for QueuedMessage<M> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            priority: self.priority,
            enqueue_time: self.enqueue_time,
            completion: None, // Clones don't carry completion handles
        }
    }
}

impl<M> QueuedMessage<M> {
    fn new(message: M, priority: SendPriority) -> Self {
        Self {
            message,
            priority,
            enqueue_time: Instant::now(),
            completion: None,
        }
    }

    /// Age of this message since enqueue, in milliseconds.
    pub fn age_ms(&self) -> u64 {
        self.enqueue_time.elapsed().as_millis() as u64
    }
}

// ---------------------------------------------------------------------------
// SendScheduler
// ---------------------------------------------------------------------------

/// Priority scheduler with per-class queuing, weighted round-robin dequeue,
/// and starvation prevention.
///
/// # Type parameters
///
/// * `M` - The message type held in queues.
pub struct SendScheduler<M> {
    config: SendSchedulerConfig,
    control: VecDeque<QueuedMessage<M>>,
    membership: VecDeque<QueuedMessage<M>>,
    intent_log: VecDeque<QueuedMessage<M>>,
    data: VecDeque<QueuedMessage<M>>,
    bulk: VecDeque<QueuedMessage<M>>,
    /// Per-class burst counters tracking remaining budget for this round.
    burst_counters: [usize; 5],
    /// Next class index for round-robin (0=Control..4=Bulk).
    round_robin_next: usize,
    /// Total messages ever enqueued.
    total_enqueued: u64,
    /// Total messages ever dequeued.
    total_dequeued: u64,
}

impl<M> SendScheduler<M> {
    /// Create a new scheduler with the given configuration.
    pub fn new(config: SendSchedulerConfig) -> Self {
        config
            .validate()
            .expect("SendSchedulerConfig validation failed");
        Self {
            config,
            control: VecDeque::new(),
            membership: VecDeque::new(),
            intent_log: VecDeque::new(),
            data: VecDeque::new(),
            bulk: VecDeque::new(),
            burst_counters: [0; 5],
            round_robin_next: 0,
            total_enqueued: 0,
            total_dequeued: 0,
        }
    }

    /// Create a new scheduler with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SendSchedulerConfig::default())
    }

    // ------------------------------------------------------------------
    // Enqueue
    // ------------------------------------------------------------------

    /// Enqueue a message with the given priority class and a send-completion
    /// handle that will be resolved after the framed message is written to
    /// the socket.
    ///
    /// Returns the new length of the class-specific queue.
    pub fn enqueue_with_completion(
        &mut self,
        message: M,
        priority: SendPriority,
        completion: crate::send_completion::SendCompletion,
    ) -> usize {
        let mut msg = QueuedMessage::new(message, priority);
        msg.completion = Some(completion);
        let len = match priority {
            SendPriority::Control => {
                self.control.push_back(msg);
                self.control.len()
            }
            SendPriority::Membership => {
                self.membership.push_back(msg);
                self.membership.len()
            }
            SendPriority::IntentLog => {
                self.intent_log.push_back(msg);
                self.intent_log.len()
            }
            SendPriority::Data => {
                self.data.push_back(msg);
                self.data.len()
            }
            SendPriority::Bulk => {
                self.bulk.push_back(msg);
                self.bulk.len()
            }
        };
        self.total_enqueued += 1;
        len
    }

    /// Enqueue a message with the given priority class.
    ///
    /// Returns the new length of the class-specific queue.
    pub fn enqueue(&mut self, message: M, priority: SendPriority) -> usize {
        let msg = QueuedMessage::new(message, priority);
        let len = match priority {
            SendPriority::Control => {
                self.control.push_back(msg);
                self.control.len()
            }
            SendPriority::Membership => {
                self.membership.push_back(msg);
                self.membership.len()
            }
            SendPriority::IntentLog => {
                self.intent_log.push_back(msg);
                self.intent_log.len()
            }
            SendPriority::Data => {
                self.data.push_back(msg);
                self.data.len()
            }
            SendPriority::Bulk => {
                self.bulk.push_back(msg);
                self.bulk.len()
            }
        };
        self.total_enqueued += 1;
        len
    }

    // ------------------------------------------------------------------
    // Dequeue
    // ------------------------------------------------------------------

    /// Dequeue the next message using weighted round-robin with starvation
    /// prevention.
    ///
    /// Returns `None` when all queues are empty.
    pub fn dequeue(&mut self) -> Option<QueuedMessage<M>> {
        // 1. Starvation prevention: dequeue the oldest expired message.
        if let Some(msg) = self.try_starvation_dequeue() {
            return Some(msg);
        }

        // 2. Ensure we have burst budgets; refill if all are drained.
        if self.total_burst_remaining() == 0 {
            self.refill_burst_budgets();
        }

        // 3. Weighted round-robin: scan classes from current position.
        for offset in 0..5 {
            let idx = (self.round_robin_next + offset) % 5;
            if self.burst_counters[idx] == 0 {
                continue;
            }
            let pri = SendPriority::from_index(idx);
            if self.is_class_empty(pri) {
                continue;
            }
            let msg = self.pop_front_for(pri);
            self.burst_counters[idx] -= 1;
            self.total_dequeued += 1;
            if self.burst_counters[idx] == 0 {
                self.advance_to_next_budgeted_class();
            }
            return msg;
        }

        // 4. All classes with budget are empty; refill and retry once.
        self.refill_burst_budgets();
        for offset in 0..5 {
            let idx = (self.round_robin_next + offset) % 5;
            if self.burst_counters[idx] == 0 {
                continue;
            }
            let pri = SendPriority::from_index(idx);
            if self.is_class_empty(pri) {
                continue;
            }
            let msg = self.pop_front_for(pri);
            self.burst_counters[idx] -= 1;
            self.total_dequeued += 1;
            if self.burst_counters[idx] == 0 {
                self.advance_to_next_budgeted_class();
            }
            return msg;
        }

        None
    }

    /// Check for messages that have exceeded the starvation threshold and
    /// dequeue the oldest one regardless of class.
    fn try_starvation_dequeue(&mut self) -> Option<QueuedMessage<M>> {
        let threshold = self.config.starvation_threshold_ms;

        let mut oldest_pri: Option<SendPriority> = None;
        let mut oldest_age: u64 = 0;

        for pri in SendPriority::all() {
            if let Some(msg) = self.peek_front_for(pri) {
                let age = msg.age_ms();
                if age >= threshold && age >= oldest_age {
                    oldest_age = age;
                    oldest_pri = Some(pri);
                }
            }
        }

        if let Some(pri) = oldest_pri {
            let msg = self.pop_front_for(pri)?;
            self.total_dequeued += 1;
            return Some(msg);
        }
        None
    }

    // ------------------------------------------------------------------
    // Round-robin mechanics
    // ------------------------------------------------------------------

    fn total_burst_remaining(&self) -> usize {
        self.burst_counters.iter().sum()
    }

    /// Refill all per-class burst budgets from the config.
    fn refill_burst_budgets(&mut self) {
        self.burst_counters[0] = self.config.control_max_burst;
        self.burst_counters[1] = self.config.membership_max_burst;
        self.burst_counters[2] = self.config.intent_log_max_burst;
        self.burst_counters[3] = self.config.data_max_burst;
        self.burst_counters[4] = self.config.bulk_max_burst;
        self.round_robin_next = 0;
    }

    /// Advance round-robin pointer to the next class that has non-zero
    /// burst budget and a non-empty queue.
    fn advance_to_next_budgeted_class(&mut self) {
        for offset in 1..=5 {
            let idx = (self.round_robin_next + offset) % 5;
            let pri = SendPriority::from_index(idx);
            if self.burst_counters[idx] > 0
                && self.config.weight(pri) > 0
                && !self.is_class_empty(pri)
            {
                self.round_robin_next = idx;
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // Queue access helpers
    // ------------------------------------------------------------------

    fn queue_for(&self, pri: SendPriority) -> &VecDeque<QueuedMessage<M>> {
        match pri {
            SendPriority::Control => &self.control,
            SendPriority::Membership => &self.membership,
            SendPriority::IntentLog => &self.intent_log,
            SendPriority::Data => &self.data,
            SendPriority::Bulk => &self.bulk,
        }
    }

    fn queue_for_mut(&mut self, pri: SendPriority) -> &mut VecDeque<QueuedMessage<M>> {
        match pri {
            SendPriority::Control => &mut self.control,
            SendPriority::Membership => &mut self.membership,
            SendPriority::IntentLog => &mut self.intent_log,
            SendPriority::Data => &mut self.data,
            SendPriority::Bulk => &mut self.bulk,
        }
    }

    fn peek_front_for(&self, pri: SendPriority) -> Option<&QueuedMessage<M>> {
        self.queue_for(pri).front()
    }

    fn pop_front_for(&mut self, pri: SendPriority) -> Option<QueuedMessage<M>> {
        self.queue_for_mut(pri).pop_front()
    }

    fn is_class_empty(&self, pri: SendPriority) -> bool {
        self.queue_for(pri).is_empty()
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /// Total number of messages across all queues.
    pub fn len(&self) -> usize {
        self.control.len()
            + self.membership.len()
            + self.intent_log.len()
            + self.data.len()
            + self.bulk.len()
    }

    /// Whether all queues are empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of messages in a specific priority class queue.
    pub fn class_len(&self, pri: SendPriority) -> usize {
        self.queue_for(pri).len()
    }

    /// Total messages ever enqueued.
    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued
    }

    /// Total messages ever dequeued.
    pub fn total_dequeued(&self) -> u64 {
        self.total_dequeued
    }

    /// The scheduler configuration (read-only).
    pub fn config(&self) -> &SendSchedulerConfig {
        &self.config
    }
}

impl<M> Default for SendScheduler<M> {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SendPriority discriminant values --

    #[test]
    fn send_priority_discriminants() {
        assert_eq!(SendPriority::Control as u8, 0);
        assert_eq!(SendPriority::Membership as u8, 1);
        assert_eq!(SendPriority::IntentLog as u8, 2);
        assert_eq!(SendPriority::Data as u8, 3);
        assert_eq!(SendPriority::Bulk as u8, 4);
    }

    #[test]
    fn send_priority_all_order() {
        let all = SendPriority::all();
        assert_eq!(all[0], SendPriority::Control);
        assert_eq!(all[1], SendPriority::Membership);
        assert_eq!(all[2], SendPriority::IntentLog);
        assert_eq!(all[3], SendPriority::Data);
        assert_eq!(all[4], SendPriority::Bulk);
    }

    #[test]
    fn send_priority_ord_reflects_priority() {
        assert!(SendPriority::Control < SendPriority::Membership);
        assert!(SendPriority::Membership < SendPriority::IntentLog);
        assert!(SendPriority::IntentLog < SendPriority::Data);
        assert!(SendPriority::Data < SendPriority::Bulk);
    }

    // -- Config validation --

    #[test]
    fn config_default_is_valid() {
        let config = SendSchedulerConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_zero_total_weight_rejected() {
        let config = SendSchedulerConfig {
            control_weight: 0,
            membership_weight: 0,
            intent_log_weight: 0,
            data_weight: 0,
            bulk_weight: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_zero_burst_rejected() {
        let config = SendSchedulerConfig {
            control_max_burst: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config2 = SendSchedulerConfig {
            membership_max_burst: 0,
            ..Default::default()
        };
        assert!(config2.validate().is_err());
    }

    #[test]
    fn config_zero_starvation_threshold_rejected() {
        let config = SendSchedulerConfig {
            starvation_threshold_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_weight_lookup() {
        let config = SendSchedulerConfig::default();
        assert_eq!(config.weight(SendPriority::Control), 10);
        assert_eq!(config.weight(SendPriority::Membership), 6);
        assert_eq!(config.weight(SendPriority::IntentLog), 3);
        assert_eq!(config.weight(SendPriority::Data), 2);
        assert_eq!(config.weight(SendPriority::Bulk), 1);
    }

    // -- Enqueue / basic empty-scheduler --

    #[test]
    fn empty_scheduler_dequeue_returns_none() {
        let mut s: SendScheduler<&str> = SendScheduler::with_defaults();
        assert!(s.dequeue().is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn enqueue_increases_class_length() {
        let mut s = SendScheduler::with_defaults();
        assert_eq!(s.enqueue("a", SendPriority::Control), 1);
        assert_eq!(s.class_len(SendPriority::Control), 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn per_class_fifo_ordering() {
        let mut s = SendScheduler::with_defaults();
        s.enqueue("c1", SendPriority::Control);
        s.enqueue("c2", SendPriority::Control);
        s.enqueue("h1", SendPriority::Membership);
        s.enqueue("h2", SendPriority::Membership);

        let mut control_vals = Vec::new();
        let mut membership_vals = Vec::new();

        for _ in 0..10 {
            if let Some(msg) = s.dequeue() {
                match msg.priority {
                    SendPriority::Control => control_vals.push(msg.message),
                    SendPriority::Membership => membership_vals.push(msg.message),
                    _ => {}
                }
            }
        }

        assert_eq!(control_vals, vec!["c1", "c2"]);
        assert_eq!(membership_vals, vec!["h1", "h2"]);
    }

    // -- Weighted round-robin fairness --

    #[test]
    fn all_messages_eventually_dequeued() {
        let mut s = SendScheduler::with_defaults();
        for i in 0..100 {
            s.enqueue(i, SendPriority::Control);
            s.enqueue(i + 1000, SendPriority::Membership);
            s.enqueue(i + 2000, SendPriority::IntentLog);
            s.enqueue(i + 3000, SendPriority::Data);
            s.enqueue(i + 4000, SendPriority::Bulk);
        }

        let mut counts = [0usize; 5];
        while let Some(msg) = s.dequeue() {
            counts[msg.priority as usize] += 1;
        }

        assert_eq!(counts[0], 100);
        assert_eq!(counts[1], 100);
        assert_eq!(counts[2], 100);
        assert_eq!(counts[3], 100);
        assert_eq!(counts[4], 100);
        assert!(s.is_empty());
    }

    #[test]
    fn high_priority_favored_in_initial_dequeues() {
        let mut s = SendScheduler::with_defaults();
        for i in 0..50 {
            s.enqueue(i, SendPriority::Control);
            s.enqueue(i + 100, SendPriority::Bulk);
        }

        let first_20: Vec<SendPriority> = (0..20)
            .filter_map(|_| s.dequeue())
            .map(|m| m.priority)
            .collect();

        let control_in_first_20 = first_20
            .iter()
            .filter(|c| **c == SendPriority::Control)
            .count();
        assert!(
            control_in_first_20 >= 10,
            "first 20 should be mostly Control, got {control_in_first_20} Control out of 20"
        );
    }

    // -- Empty-queue skip --

    #[test]
    fn empty_queue_skipped_in_round_robin() {
        let mut s = SendScheduler::with_defaults();
        s.enqueue("b1", SendPriority::Bulk);
        s.enqueue("b2", SendPriority::Bulk);

        let msg1 = s.dequeue().unwrap();
        assert_eq!(msg1.priority, SendPriority::Bulk);
        assert_eq!(msg1.message, "b1");

        let msg2 = s.dequeue().unwrap();
        assert_eq!(msg2.priority, SendPriority::Bulk);
        assert_eq!(msg2.message, "b2");

        assert!(s.dequeue().is_none());
    }

    #[test]
    fn empty_scheduler_returns_none_repeatedly() {
        let mut s: SendScheduler<u32> = SendScheduler::with_defaults();
        assert!(s.dequeue().is_none());
        assert!(s.dequeue().is_none());
        assert!(s.dequeue().is_none());
    }

    // -- Starvation prevention --

    #[test]
    fn starvation_prevention_dequeues_oldest_expired_message() {
        let config = SendSchedulerConfig {
            starvation_threshold_ms: 5,
            control_weight: 100,
            bulk_weight: 1,
            ..Default::default()
        };

        let mut s = SendScheduler::<&str>::new(config);

        s.enqueue("starving-bulk", SendPriority::Bulk);
        for _ in 0..50 {
            s.enqueue("control", SendPriority::Control);
        }

        std::thread::sleep(std::time::Duration::from_millis(20));

        let mut found_starving = false;
        for _ in 0..15 {
            if let Some(msg) = s.dequeue() {
                if msg.message == "starving-bulk" {
                    found_starving = true;
                    break;
                }
            }
        }
        assert!(
            found_starving,
            "starving bulk message should be dequeued early via starvation prevention"
        );
    }

    #[test]
    fn starvation_does_not_trigger_below_threshold() {
        let config = SendSchedulerConfig {
            starvation_threshold_ms: 60_000,
            control_max_burst: 100,
            bulk_max_burst: 1,
            ..Default::default()
        };

        let mut s = SendScheduler::<&str>::new(config);

        s.enqueue("bulk-msg", SendPriority::Bulk);
        for _ in 0..100 {
            s.enqueue("control", SendPriority::Control);
        }

        let mut bulk_seen = false;
        for _ in 0..5 {
            if let Some(msg) = s.dequeue() {
                if msg.message == "bulk-msg" {
                    bulk_seen = true;
                }
            }
        }
        assert!(!bulk_seen);
    }

    // -- Interleaved enqueue/dequeue --

    #[test]
    fn interleaved_enqueue_dequeue_maintains_ordering() {
        let mut s = SendScheduler::with_defaults();
        s.enqueue("a", SendPriority::Control);
        s.enqueue("b", SendPriority::Membership);
        assert_eq!(s.dequeue().unwrap().message, "a");
        s.enqueue("c", SendPriority::Control);
        s.enqueue("d", SendPriority::Bulk);
        assert_eq!(s.dequeue().unwrap().message, "c");
        assert_eq!(s.dequeue().unwrap().message, "b");
        assert_eq!(s.dequeue().unwrap().message, "d");
        assert!(s.dequeue().is_none());
    }

    // -- Total counters --

    #[test]
    fn total_enqueued_and_dequeued_counters() {
        let mut s = SendScheduler::with_defaults();
        assert_eq!(s.total_enqueued(), 0);
        assert_eq!(s.total_dequeued(), 0);

        s.enqueue(1, SendPriority::Control);
        s.enqueue(2, SendPriority::Control);
        s.enqueue(3, SendPriority::Data);
        assert_eq!(s.total_enqueued(), 3);

        s.dequeue();
        s.dequeue();
        assert_eq!(s.total_dequeued(), 2);
        assert_eq!(s.total_enqueued(), 3);
    }

    // -- Max-burst enforcement --

    #[test]
    fn max_burst_limits_consecutive_same_class_dequeues() {
        let config = SendSchedulerConfig {
            control_max_burst: 3,
            membership_max_burst: 3,
            intent_log_max_burst: 3,
            data_max_burst: 3,
            bulk_max_burst: 3,
            control_weight: 1,
            membership_weight: 1,
            intent_log_weight: 1,
            data_weight: 1,
            bulk_weight: 1,
            ..Default::default()
        };

        let mut s = SendScheduler::<&str>::new(config);
        for _ in 0..20 {
            s.enqueue("control", SendPriority::Control);
            s.enqueue("data", SendPriority::Data);
        }

        let mut classes = Vec::new();
        for _ in 0..40 {
            if let Some(msg) = s.dequeue() {
                classes.push(msg.priority);
            }
        }

        for window in classes.windows(4) {
            let all_same = window.iter().all(|c| *c == window[0]);
            assert!(!all_same, "found 4 consecutive {:?}", window[0]);
        }
    }

    // -- QueuedMessage age --

    #[test]
    fn queued_message_age_increases() {
        let msg = QueuedMessage::new("test", SendPriority::Control);
        let age1 = msg.age_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let age2 = msg.age_ms();
        assert!(age2 > age1);
    }

    // -- Default scheduler via Default trait --

    #[test]
    fn default_scheduler_is_empty() {
        let s = SendScheduler::<u32>::default();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    // -- Enqueue across all five classes --

    #[test]
    fn enqueue_all_classes_and_verify_lengths() {
        let mut s = SendScheduler::with_defaults();
        s.enqueue(1, SendPriority::Control);
        s.enqueue(2, SendPriority::Membership);
        s.enqueue(3, SendPriority::IntentLog);
        s.enqueue(4, SendPriority::Data);
        s.enqueue(5, SendPriority::Bulk);

        assert_eq!(s.class_len(SendPriority::Control), 1);
        assert_eq!(s.class_len(SendPriority::Membership), 1);
        assert_eq!(s.class_len(SendPriority::IntentLog), 1);
        assert_eq!(s.class_len(SendPriority::Data), 1);
        assert_eq!(s.class_len(SendPriority::Bulk), 1);
        assert_eq!(s.len(), 5);
    }

    // -- Single-priority-only regression --

    #[test]
    fn single_priority_only_still_dequeues_correctly() {
        let mut s = SendScheduler::with_defaults();
        for i in 0..50u32 {
            s.enqueue(i, SendPriority::Data);
        }
        let mut results = Vec::new();
        while let Some(msg) = s.dequeue() {
            results.push(msg.message);
        }
        assert_eq!(results.len(), 50);
        assert!(
            results.windows(2).all(|w| w[0] < w[1]),
            "FIFO order preserved"
        );
    }

    // -- Mixed-priority drain after backpressure simulation --

    #[test]
    fn mixed_priority_drain_prioritizes_control() {
        let mut s = SendScheduler::with_defaults();
        // Simulate backpressure release: flood with Data then add Control.
        for i in 0..20 {
            s.enqueue(format!("data-{i}"), SendPriority::Data);
        }
        s.enqueue("urgent".to_string(), SendPriority::Control);
        s.enqueue("rostery".to_string(), SendPriority::Membership);

        // First dequeue should be Control.
        let first = s.dequeue().unwrap();
        assert_eq!(first.priority, SendPriority::Control);
        assert_eq!(first.message, "urgent".to_string());

        // Second should be Membership.
        let second = s.dequeue().unwrap();
        assert_eq!(second.priority, SendPriority::Membership);
        assert_eq!(second.message, "rostery".to_string());
    }

    // -- Weighted fairness distribution check --

    #[test]
    fn weighted_fairness_control_gets_more_than_bulk() {
        let config = SendSchedulerConfig {
            control_max_burst: 20,
            bulk_max_burst: 2,
            ..Default::default()
        };

        let mut s = SendScheduler::<&str>::new(config);
        for _ in 0..100 {
            s.enqueue("control", SendPriority::Control);
            s.enqueue("bulk", SendPriority::Bulk);
        }

        let mut control_count = 0usize;
        let mut bulk_count = 0usize;
        for _ in 0..50 {
            if let Some(msg) = s.dequeue() {
                match msg.priority {
                    SendPriority::Control => control_count += 1,
                    SendPriority::Bulk => bulk_count += 1,
                    _ => {}
                }
            }
        }

        assert!(
            control_count > bulk_count,
            "Control ({control_count}) should be dequeued more than Bulk ({bulk_count}) in first 50"
        );
    }
}
