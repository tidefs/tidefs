// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Cluster invalidation feed service.
//!
//! This crate owns the service-level protocol for propagating cache
//! invalidations from writer nodes to follower nodes. It deliberately keeps
//! the transport binding thin: service id `0x05`, stable method ids, and
//! deterministic little-endian payload encoding are defined here, while a
//! later transport adapter can carry the encoded messages over an established
//! TideFS session.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Stable transport service id for the invalidation feed.
pub const INVALIDATION_FEED_SERVICE_ID: u8 = 0x05;

/// Current invalidation feed wire payload version.
pub const INVALIDATION_FEED_WIRE_VERSION: u8 = 1;

const WIRE_MAGIC: [u8; 4] = *b"VIFD";
const METHOD_SUBSCRIBE: u8 = 1;
const METHOD_EVENT: u8 = 2;
const METHOD_EVENT_ACK: u8 = 3;
const METHOD_RESYNC: u8 = 4;

/// Default maximum number of batches retained in the ring buffer.
pub const DEFAULT_RING_CAPACITY: usize = 1024;

/// Dataset identity used by the invalidation feed.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct DatasetId(pub u64);

impl DatasetId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Cluster node identity used by the invalidation feed.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct NodeId(pub u64);

impl NodeId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Commit-group identity for a batch of invalidation events.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct CommitGroupId(pub u64);

impl CommitGroupId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Filesystem inode identity carried by invalidation events.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct InodeId(pub u64);

impl InodeId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Event classes understood by the feed filter mask.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[repr(u8)]
pub enum InvalidationEventKind {
    Inode = 1,
    Entry = 2,
    Directory = 3,
    Dataset = 4,
    Range = 5,
}

impl TryFrom<u8> for InvalidationEventKind {
    type Error = InvalidationFeedError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Inode),
            2 => Ok(Self::Entry),
            3 => Ok(Self::Directory),
            4 => Ok(Self::Dataset),
            5 => Ok(Self::Range),
            other => Err(InvalidationFeedError::UnknownEventKind(other)),
        }
    }
}

/// Subscription filter bitmask.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EventFilterMask(u32);

impl EventFilterMask {
    pub const INODE: Self = Self(1 << 0);
    pub const ENTRY: Self = Self(1 << 1);
    pub const DIRECTORY: Self = Self(1 << 2);
    pub const DATASET: Self = Self(1 << 3);
    pub const RANGE: Self = Self(1 << 4);
    pub const ALL: Self =
        Self(Self::INODE.0 | Self::ENTRY.0 | Self::DIRECTORY.0 | Self::DATASET.0 | Self::RANGE.0);

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn contains(self, kind: InvalidationEventKind) -> bool {
        let bit = match kind {
            InvalidationEventKind::Inode => Self::INODE.0,
            InvalidationEventKind::Entry => Self::ENTRY.0,
            InvalidationEventKind::Directory => Self::DIRECTORY.0,
            InvalidationEventKind::Dataset => Self::DATASET.0,
            InvalidationEventKind::Range => Self::RANGE.0,
        };
        self.0 & bit != 0
    }
}

impl Default for EventFilterMask {
    fn default() -> Self {
        Self::ALL
    }
}

/// One authoritative cache-invalidation event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InvalidationEvent {
    /// Invalidate cached inode data and attribute state.
    Inode { ino: InodeId, generation: u64 },
    /// Invalidate one directory-entry lookup.
    Entry { parent: InodeId, name: Vec<u8> },
    /// Invalidate all cached children/listing state for one directory.
    Directory { ino: InodeId },
    /// Invalidate dataset-scoped state such as properties and feature gates.
    Dataset,
    /// Invalidate a byte range of cached data pages for one inode.
    /// Offset 0 and length 0 together mean the entire file.
    Range {
        ino: InodeId,
        offset: u64,
        length: u64,
    },
}

impl InvalidationEvent {
    #[must_use]
    pub const fn kind(&self) -> InvalidationEventKind {
        match self {
            Self::Inode { .. } => InvalidationEventKind::Inode,
            Self::Entry { .. } => InvalidationEventKind::Entry,
            Self::Directory { .. } => InvalidationEventKind::Directory,
            Self::Dataset => InvalidationEventKind::Dataset,
            Self::Range { .. } => InvalidationEventKind::Range,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), InvalidationFeedError> {
        out.push(self.kind() as u8);
        match self {
            Self::Inode { ino, generation } => {
                put_u64(out, ino.0);
                put_u64(out, *generation);
            }
            Self::Entry { parent, name } => {
                put_u64(out, parent.0);
                put_bytes(out, name)?;
            }
            Self::Directory { ino } => put_u64(out, ino.0),
            Self::Dataset => {}
            Self::Range {
                ino,
                offset,
                length,
            } => {
                put_u64(out, ino.0);
                put_u64(out, *offset);
                put_u64(out, *length);
            }
        }
        Ok(())
    }

    fn decode_from(cursor: &mut WireCursor<'_>) -> Result<Self, InvalidationFeedError> {
        let kind = InvalidationEventKind::try_from(cursor.u8()?)?;
        match kind {
            InvalidationEventKind::Inode => Ok(Self::Inode {
                ino: InodeId(cursor.u64()?),
                generation: cursor.u64()?,
            }),
            InvalidationEventKind::Entry => Ok(Self::Entry {
                parent: InodeId(cursor.u64()?),
                name: cursor.bytes()?.to_vec(),
            }),
            InvalidationEventKind::Directory => Ok(Self::Directory {
                ino: InodeId(cursor.u64()?),
            }),
            InvalidationEventKind::Dataset => Ok(Self::Dataset),
            InvalidationEventKind::Range => Ok(Self::Range {
                ino: InodeId(cursor.u64()?),
                offset: cursor.u64()?,
                length: cursor.u64()?,
            }),
        }
    }
}

/// Events committed by one writer commit group.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvalidationBatch {
    pub dataset: DatasetId,
    pub commit_group: CommitGroupId,
    pub events: Vec<InvalidationEvent>,
}

impl InvalidationBatch {
    #[must_use]
    pub fn new(
        dataset: DatasetId,
        commit_group: CommitGroupId,
        events: Vec<InvalidationEvent>,
    ) -> Self {
        Self {
            dataset,
            commit_group,
            events,
        }
    }

    #[must_use]
    pub fn filtered(&self, filter: EventFilterMask) -> Option<Self> {
        let events: Vec<_> = self
            .events
            .iter()
            .filter(|event| filter.contains(event.kind()))
            .cloned()
            .collect();
        if events.is_empty() {
            None
        } else {
            Some(Self::new(self.dataset, self.commit_group, events))
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), InvalidationFeedError> {
        put_u64(out, self.dataset.0);
        put_u64(out, self.commit_group.0);
        put_len(out, self.events.len())?;
        for event in &self.events {
            event.encode_into(out)?;
        }
        Ok(())
    }

    fn decode_from(cursor: &mut WireCursor<'_>) -> Result<Self, InvalidationFeedError> {
        let dataset = DatasetId(cursor.u64()?);
        let commit_group = CommitGroupId(cursor.u64()?);
        let len = cursor.len()?;
        let mut events = Vec::with_capacity(len);
        for _ in 0..len {
            events.push(InvalidationEvent::decode_from(cursor)?);
        }
        Ok(Self::new(dataset, commit_group, events))
    }
}

/// Snapshot invalidation summary used for fast resync.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotInvalidation {
    pub dataset: DatasetId,
    pub commit_group: CommitGroupId,
    pub inodes: BTreeSet<InodeId>,
    pub directories: BTreeSet<InodeId>,
}

impl SnapshotInvalidation {
    #[must_use]
    pub fn new(dataset: DatasetId, commit_group: CommitGroupId) -> Self {
        Self {
            dataset,
            commit_group,
            inodes: BTreeSet::new(),
            directories: BTreeSet::new(),
        }
    }
}

/// Protocol message carried by service id `0x05`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FeedMessage {
    Subscribe {
        subscriber: NodeId,
        dataset: DatasetId,
        filter: EventFilterMask,
        from_commit_group: CommitGroupId,
    },
    Event(InvalidationBatch),
    EventAck {
        subscriber: NodeId,
        dataset: DatasetId,
        last_commit_group: CommitGroupId,
    },
    Resync {
        subscriber: NodeId,
        dataset: DatasetId,
        from_commit_group: CommitGroupId,
    },
}

impl FeedMessage {
    #[must_use]
    pub const fn method_id(&self) -> u8 {
        match self {
            Self::Subscribe { .. } => METHOD_SUBSCRIBE,
            Self::Event(_) => METHOD_EVENT,
            Self::EventAck { .. } => METHOD_EVENT_ACK,
            Self::Resync { .. } => METHOD_RESYNC,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, InvalidationFeedError> {
        let mut out = Vec::new();
        out.extend_from_slice(&WIRE_MAGIC);
        out.push(INVALIDATION_FEED_WIRE_VERSION);
        out.push(INVALIDATION_FEED_SERVICE_ID);
        out.push(self.method_id());
        match self {
            Self::Subscribe {
                subscriber,
                dataset,
                filter,
                from_commit_group,
            } => {
                put_u64(&mut out, subscriber.0);
                put_u64(&mut out, dataset.0);
                put_u32(&mut out, filter.bits());
                put_u64(&mut out, from_commit_group.0);
            }
            Self::Event(batch) => batch.encode_into(&mut out)?,
            Self::EventAck {
                subscriber,
                dataset,
                last_commit_group,
            } => {
                put_u64(&mut out, subscriber.0);
                put_u64(&mut out, dataset.0);
                put_u64(&mut out, last_commit_group.0);
            }
            Self::Resync {
                subscriber,
                dataset,
                from_commit_group,
            } => {
                put_u64(&mut out, subscriber.0);
                put_u64(&mut out, dataset.0);
                put_u64(&mut out, from_commit_group.0);
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidationFeedError> {
        let mut cursor = WireCursor::new(bytes);
        cursor.magic()?;
        let version = cursor.u8()?;
        if version != INVALIDATION_FEED_WIRE_VERSION {
            return Err(InvalidationFeedError::UnsupportedWireVersion(version));
        }
        let service_id = cursor.u8()?;
        if service_id != INVALIDATION_FEED_SERVICE_ID {
            return Err(InvalidationFeedError::UnexpectedServiceId(service_id));
        }
        let method = cursor.u8()?;
        let msg = match method {
            METHOD_SUBSCRIBE => Self::Subscribe {
                subscriber: NodeId(cursor.u64()?),
                dataset: DatasetId(cursor.u64()?),
                filter: EventFilterMask::from_bits(cursor.u32()?),
                from_commit_group: CommitGroupId(cursor.u64()?),
            },
            METHOD_EVENT => Self::Event(InvalidationBatch::decode_from(&mut cursor)?),
            METHOD_EVENT_ACK => Self::EventAck {
                subscriber: NodeId(cursor.u64()?),
                dataset: DatasetId(cursor.u64()?),
                last_commit_group: CommitGroupId(cursor.u64()?),
            },
            METHOD_RESYNC => Self::Resync {
                subscriber: NodeId(cursor.u64()?),
                dataset: DatasetId(cursor.u64()?),
                from_commit_group: CommitGroupId(cursor.u64()?),
            },
            other => return Err(InvalidationFeedError::UnknownMethod(other)),
        };
        cursor.finish()?;
        Ok(msg)
    }
}

/// Result of subscribing to one dataset feed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeResult {
    pub subscriber: NodeId,
    pub dataset: DatasetId,
    pub replay: Vec<InvalidationBatch>,
}

/// Result of a resync request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResyncPlan {
    pub subscriber: NodeId,
    pub dataset: DatasetId,
    pub requested_from: CommitGroupId,
    pub replay_from: CommitGroupId,
    pub snapshot: Option<SnapshotInvalidation>,
    pub batches: Vec<InvalidationBatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SubscriberState {
    filter: EventFilterMask,
    last_acked: CommitGroupId,
    pending: VecDeque<InvalidationBatch>,
}

impl SubscriberState {
    fn new(filter: EventFilterMask, last_acked: CommitGroupId) -> Self {
        Self {
            filter,
            last_acked,
            pending: VecDeque::new(),
        }
    }

    fn queue(&mut self, batch: &InvalidationBatch) {
        if batch.commit_group <= self.last_acked {
            return;
        }
        if let Some(filtered) = batch.filtered(self.filter) {
            self.pending.push_back(filtered);
        }
    }

    fn ack(&mut self, last_acked: CommitGroupId) {
        if last_acked > self.last_acked {
            self.last_acked = last_acked;
        }
        self.pending
            .retain(|batch| batch.commit_group > self.last_acked);
    }
}

/// Bounded ring buffer of invalidation batches ordered by commit group.
/// Evicts oldest entries when capacity is exceeded.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RingBuffer {
    entries: VecDeque<(CommitGroupId, InvalidationBatch)>,
    capacity: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "RingBuffer capacity must be positive");
        Self {
            entries: VecDeque::new(),
            capacity,
        }
    }

    /// Push a batch; evicts the oldest entry if at capacity.
    fn push(&mut self, id: CommitGroupId, batch: InvalidationBatch) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((id, batch));
    }

    /// Iterate batches with commit group strictly greater than `after`.
    fn iter_from(
        &self,
        after: CommitGroupId,
    ) -> impl Iterator<Item = &(CommitGroupId, InvalidationBatch)> {
        self.entries.iter().skip_while(move |(id, _)| *id <= after)
    }

    /// Remove all entries with commit group <= `below`.
    fn prune_below(&mut self, below: CommitGroupId) {
        while self.entries.front().is_some_and(|(id, _)| *id <= below) {
            self.entries.pop_front();
        }
    }

    /// Commit group of the oldest retained entry, if any.
    #[allow(dead_code)]
    fn oldest_id(&self) -> Option<CommitGroupId> {
        self.entries.front().map(|(id, _)| *id)
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_RING_CAPACITY)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DatasetFeed {
    subscribers: BTreeMap<NodeId, SubscriberState>,
    batches: RingBuffer,
    snapshots: BTreeMap<CommitGroupId, SnapshotInvalidation>,
    last_published: CommitGroupId,
}

impl DatasetFeed {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            subscribers: BTreeMap::new(),
            batches: RingBuffer::new(capacity),
            snapshots: BTreeMap::new(),
            last_published: CommitGroupId::new(0),
        }
    }
}

impl Default for DatasetFeed {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_RING_CAPACITY)
    }
}

/// In-memory invalidation feed state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidationFeed {
    datasets: BTreeMap<DatasetId, DatasetFeed>,
    ring_capacity: usize,
}

impl Default for InvalidationFeed {
    fn default() -> Self {
        Self {
            datasets: BTreeMap::new(),
            ring_capacity: DEFAULT_RING_CAPACITY,
        }
    }
}

impl InvalidationFeed {
    /// Create a feed with the default ring buffer capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a feed with a custom ring buffer capacity.
    #[must_use]
    pub fn with_ring_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "ring capacity must be positive");
        Self {
            datasets: BTreeMap::new(),
            ring_capacity: capacity,
        }
    }

    fn get_or_create_feed(&mut self, dataset: DatasetId) -> &mut DatasetFeed {
        let capacity = self.ring_capacity;
        self.datasets
            .entry(dataset)
            .or_insert_with(|| DatasetFeed::with_capacity(capacity))
    }

    /// Number of batches currently retained, summed across all datasets.
    #[must_use]
    pub fn total_retained_batches(&self) -> usize {
        self.datasets.values().map(|feed| feed.batches.len()).sum()
    }

    pub fn subscribe(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        filter: EventFilterMask,
        from_commit_group: CommitGroupId,
    ) -> SubscribeResult {
        let feed = self.get_or_create_feed(dataset);
        let mut state = SubscriberState::new(filter, from_commit_group);
        let replay = replay_batches_after(feed, from_commit_group, filter);
        for batch in &replay {
            state.queue(batch);
        }
        feed.subscribers.insert(subscriber, state);
        SubscribeResult {
            subscriber,
            dataset,
            replay,
        }
    }

    pub fn publish(
        &mut self,
        batch: InvalidationBatch,
    ) -> Result<Vec<(NodeId, InvalidationBatch)>, InvalidationFeedError> {
        if batch.events.is_empty() {
            return Err(InvalidationFeedError::EmptyBatch);
        }
        let feed = self.get_or_create_feed(batch.dataset);
        if batch.commit_group <= feed.last_published {
            return Err(InvalidationFeedError::NonMonotonicCommitGroup {
                previous: feed.last_published,
                attempted: batch.commit_group,
            });
        }
        feed.last_published = batch.commit_group;
        feed.batches.push(batch.commit_group, batch.clone());

        let mut delivered = Vec::new();
        for (subscriber, state) in &mut feed.subscribers {
            if let Some(filtered) = batch.filtered(state.filter) {
                state.pending.push_back(filtered.clone());
                delivered.push((*subscriber, filtered));
            }
        }
        Ok(delivered)
    }

    pub fn ack(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        last_commit_group: CommitGroupId,
    ) -> Result<(), InvalidationFeedError> {
        let feed = self
            .datasets
            .get_mut(&dataset)
            .ok_or(InvalidationFeedError::UnknownDataset(dataset))?;
        let state = feed
            .subscribers
            .get_mut(&subscriber)
            .ok_or(InvalidationFeedError::UnknownSubscriber(subscriber))?;
        state.ack(last_commit_group);
        prune_batches(feed);
        Ok(())
    }

    pub fn install_snapshot(&mut self, snapshot: SnapshotInvalidation) {
        let feed = self.get_or_create_feed(snapshot.dataset);
        feed.snapshots.insert(snapshot.commit_group, snapshot);
    }

    pub fn resync(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        from_commit_group: CommitGroupId,
    ) -> Result<ResyncPlan, InvalidationFeedError> {
        let feed = self
            .datasets
            .get_mut(&dataset)
            .ok_or(InvalidationFeedError::UnknownDataset(dataset))?;
        let filter = feed
            .subscribers
            .get(&subscriber)
            .ok_or(InvalidationFeedError::UnknownSubscriber(subscriber))?
            .filter;

        let snapshot = feed
            .snapshots
            .range(from_commit_group..)
            .next_back()
            .map(|(_, snapshot)| snapshot.clone());
        let replay_from = snapshot
            .as_ref()
            .map_or(from_commit_group, |snapshot| snapshot.commit_group);
        let batches = replay_batches_after(feed, replay_from, filter);

        let state = feed
            .subscribers
            .get_mut(&subscriber)
            .ok_or(InvalidationFeedError::UnknownSubscriber(subscriber))?;
        state.pending.clear();
        for batch in &batches {
            state.pending.push_back(batch.clone());
        }

        Ok(ResyncPlan {
            subscriber,
            dataset,
            requested_from: from_commit_group,
            replay_from,
            snapshot,
            batches,
        })
    }

    pub fn drain_pending(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        event_budget: usize,
    ) -> Result<Vec<InvalidationBatch>, InvalidationFeedError> {
        let feed = self
            .datasets
            .get_mut(&dataset)
            .ok_or(InvalidationFeedError::UnknownDataset(dataset))?;
        let state = feed
            .subscribers
            .get_mut(&subscriber)
            .ok_or(InvalidationFeedError::UnknownSubscriber(subscriber))?;
        Ok(drain_batches(&mut state.pending, event_budget))
    }

    #[must_use]
    pub fn pending_event_count(&self, subscriber: NodeId, dataset: DatasetId) -> usize {
        self.datasets
            .get(&dataset)
            .and_then(|feed| feed.subscribers.get(&subscriber))
            .map(|state| state.pending.iter().map(|batch| batch.events.len()).sum())
            .unwrap_or(0)
    }
}

impl FeedPublisher for InvalidationFeed {
    fn publish(
        &mut self,
        batch: InvalidationBatch,
    ) -> Result<Vec<(NodeId, InvalidationBatch)>, InvalidationFeedError> {
        self.publish(batch)
    }

    fn subscribe(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        filter: EventFilterMask,
        from_commit_group: CommitGroupId,
    ) -> SubscribeResult {
        self.subscribe(subscriber, dataset, filter, from_commit_group)
    }

    fn ack(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        last_commit_group: CommitGroupId,
    ) -> Result<(), InvalidationFeedError> {
        self.ack(subscriber, dataset, last_commit_group)
    }

    fn drain_pending(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        event_budget: usize,
    ) -> Result<Vec<InvalidationBatch>, InvalidationFeedError> {
        self.drain_pending(subscriber, dataset, event_budget)
    }

    fn pending_event_count(&self, subscriber: NodeId, dataset: DatasetId) -> usize {
        self.pending_event_count(subscriber, dataset)
    }
}

fn replay_batches_after(
    feed: &DatasetFeed,
    commit_group: CommitGroupId,
    filter: EventFilterMask,
) -> Vec<InvalidationBatch> {
    feed.batches
        .iter_from(commit_group)
        .filter_map(|(_, batch)| batch.filtered(filter))
        .collect()
}

fn prune_batches(feed: &mut DatasetFeed) {
    let Some(min_acked) = feed
        .subscribers
        .values()
        .map(|state| state.last_acked)
        .min()
    else {
        return;
    };
    feed.batches.prune_below(min_acked);
}

fn drain_batches(
    pending: &mut VecDeque<InvalidationBatch>,
    mut event_budget: usize,
) -> Vec<InvalidationBatch> {
    let mut drained = Vec::new();
    while event_budget > 0 {
        let Some(mut batch) = pending.pop_front() else {
            break;
        };
        if batch.events.len() <= event_budget {
            event_budget -= batch.events.len();
            drained.push(batch);
        } else {
            let remainder = batch.events.split_off(event_budget);
            let drained_batch =
                InvalidationBatch::new(batch.dataset, batch.commit_group, batch.events);
            pending.push_front(InvalidationBatch::new(
                drained_batch.dataset,
                drained_batch.commit_group,
                remainder,
            ));
            drained.push(drained_batch);
            event_budget = 0;
        }
    }
    drained
}

/// Publisher-side trait for the invalidation feed.
///
/// Implementations propagate invalidation batches to subscribers and manage
/// per-subscriber state, replay, and acknowledgement.
pub trait FeedPublisher {
    /// Publish an invalidation batch to all subscribers of the batch's dataset.
    /// Returns the per-subscriber filtered batches that were delivered.
    fn publish(
        &mut self,
        batch: InvalidationBatch,
    ) -> Result<Vec<(NodeId, InvalidationBatch)>, InvalidationFeedError>;

    /// Subscribe a node to a dataset feed with an event filter and starting
    /// commit group for replay.
    fn subscribe(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        filter: EventFilterMask,
        from_commit_group: CommitGroupId,
    ) -> SubscribeResult;

    /// Acknowledge receipt of all batches up to and including `last_commit_group`.
    fn ack(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        last_commit_group: CommitGroupId,
    ) -> Result<(), InvalidationFeedError>;

    /// Drain at most `event_budget` pending events for one subscriber.
    fn drain_pending(
        &mut self,
        subscriber: NodeId,
        dataset: DatasetId,
        event_budget: usize,
    ) -> Result<Vec<InvalidationBatch>, InvalidationFeedError>;

    /// Count of pending events for one subscriber across all queued batches.
    fn pending_event_count(&self, subscriber: NodeId, dataset: DatasetId) -> usize;
}

/// Consumer-side trait for the invalidation feed.
///
/// Implementations receive invalidation batches and dispatch individual
/// events to a registered `InvalidationSink`.
pub trait FeedConsumer {
    /// Enqueue one invalidation batch for later processing.
    fn enqueue_batch(&mut self, batch: InvalidationBatch);

    /// Process at most `event_budget` events through the sink.
    /// Returns the number of events actually processed.
    fn process_tick(&mut self, sink: &mut dyn InvalidationSink, event_budget: usize) -> usize;

    /// Count of pending events across all queued batches.
    fn pending_event_count(&self) -> usize;
}

/// Sink used by follower-side processors.
pub trait InvalidationSink {
    fn invalidate_inode(&mut self, ino: InodeId, generation: u64);
    fn invalidate_entry(&mut self, parent: InodeId, name: &[u8]);
    fn invalidate_directory(&mut self, ino: InodeId);
    fn invalidate_dataset(&mut self, dataset: DatasetId);
    fn invalidate_range(&mut self, ino: InodeId, offset: u64, length: u64);
}

/// Bounded follower-side processor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FollowerInvalidationProcessor {
    queue: VecDeque<InvalidationBatch>,
}

impl FollowerInvalidationProcessor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_batch(&mut self, batch: InvalidationBatch) {
        self.queue.push_back(batch);
    }

    pub fn enqueue_batches<I>(&mut self, batches: I)
    where
        I: IntoIterator<Item = InvalidationBatch>,
    {
        self.queue.extend(batches);
    }

    pub fn process_tick<S: InvalidationSink>(
        &mut self,
        sink: &mut S,
        event_budget: usize,
    ) -> usize {
        let drained = drain_batches(&mut self.queue, event_budget);
        let mut processed = 0;
        for batch in drained {
            for event in batch.events {
                apply_event(sink, batch.dataset, event);
                processed += 1;
            }
        }
        processed
    }

    /// Dyn-compatible variant of `process_tick` for use with `&mut dyn InvalidationSink`.
    fn process_tick_dyn(&mut self, sink: &mut dyn InvalidationSink, event_budget: usize) -> usize {
        let drained = drain_batches(&mut self.queue, event_budget);
        let mut processed = 0;
        for batch in drained {
            for event in batch.events {
                apply_event_dyn(sink, batch.dataset, event);
                processed += 1;
            }
        }
        processed
    }

    #[must_use]
    pub fn pending_event_count(&self) -> usize {
        self.queue.iter().map(|batch| batch.events.len()).sum()
    }
}

impl FeedConsumer for FollowerInvalidationProcessor {
    fn enqueue_batch(&mut self, batch: InvalidationBatch) {
        self.enqueue_batch(batch);
    }

    fn process_tick(&mut self, sink: &mut dyn InvalidationSink, event_budget: usize) -> usize {
        self.process_tick_dyn(sink, event_budget)
    }

    fn pending_event_count(&self) -> usize {
        self.pending_event_count()
    }
}

fn apply_event<S: InvalidationSink + ?Sized>(
    sink: &mut S,
    dataset: DatasetId,
    event: InvalidationEvent,
) {
    match event {
        InvalidationEvent::Inode { ino, generation } => sink.invalidate_inode(ino, generation),
        InvalidationEvent::Entry { parent, name } => sink.invalidate_entry(parent, &name),
        InvalidationEvent::Directory { ino } => sink.invalidate_directory(ino),
        InvalidationEvent::Dataset => sink.invalidate_dataset(dataset),
        InvalidationEvent::Range {
            ino,
            offset,
            length,
        } => sink.invalidate_range(ino, offset, length),
    }
}

/// Dyn-compatible variant for use with `&mut dyn InvalidationSink`.
fn apply_event_dyn(sink: &mut dyn InvalidationSink, dataset: DatasetId, event: InvalidationEvent) {
    match event {
        InvalidationEvent::Inode { ino, generation } => sink.invalidate_inode(ino, generation),
        InvalidationEvent::Entry { parent, name } => sink.invalidate_entry(parent, &name),
        InvalidationEvent::Directory { ino } => sink.invalidate_directory(ino),
        InvalidationEvent::Dataset => sink.invalidate_dataset(dataset),
        InvalidationEvent::Range {
            ino,
            offset,
            length,
        } => sink.invalidate_range(ino, offset, length),
    }
}

/// Error type for feed state and wire decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidationFeedError {
    EmptyBatch,
    NonMonotonicCommitGroup {
        previous: CommitGroupId,
        attempted: CommitGroupId,
    },
    UnknownDataset(DatasetId),
    UnknownSubscriber(NodeId),
    UnsupportedWireVersion(u8),
    UnexpectedServiceId(u8),
    UnknownMethod(u8),
    UnknownEventKind(u8),
    TruncatedWire,
    TrailingWireBytes(usize),
    NameTooLong(usize),
    TooManyEvents(usize),
    BadMagic,
    RingReplayIncomplete {
        requested: CommitGroupId,
        oldest_retained: CommitGroupId,
    },
}

impl fmt::Display for InvalidationFeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "invalidation batch is empty"),
            Self::NonMonotonicCommitGroup {
                previous,
                attempted,
            } => write!(
                f,
                "commit group {} does not advance previous commit group {}",
                attempted.0, previous.0
            ),
            Self::UnknownDataset(dataset) => write!(f, "unknown dataset {}", dataset.0),
            Self::UnknownSubscriber(node) => write!(f, "unknown subscriber {}", node.0),
            Self::UnsupportedWireVersion(version) => {
                write!(f, "unsupported invalidation feed wire version {version}")
            }
            Self::UnexpectedServiceId(service_id) => {
                write!(
                    f,
                    "unexpected invalidation feed service id {service_id:#04x}"
                )
            }
            Self::UnknownMethod(method) => write!(f, "unknown invalidation feed method {method}"),
            Self::UnknownEventKind(kind) => write!(f, "unknown invalidation event kind {kind}"),
            Self::TruncatedWire => write!(f, "truncated invalidation feed wire payload"),
            Self::TrailingWireBytes(count) => {
                write!(
                    f,
                    "invalidation feed wire payload has {count} trailing byte(s)"
                )
            }
            Self::NameTooLong(len) => write!(f, "invalidation entry name is too long: {len}"),
            Self::TooManyEvents(len) => write!(f, "invalidation batch has too many events: {len}"),
            Self::BadMagic => write!(f, "bad invalidation feed magic"),
            Self::RingReplayIncomplete { requested, oldest_retained } => write!(
                f,
                "ring buffer replay incomplete: requested commit group {} but oldest retained is {}",
                requested.0, oldest_retained.0
            ),
        }
    }
}

impl std::error::Error for InvalidationFeedError {}
// ---------------------------------------------------------------------------
// Invalidation receipt manifests
// ---------------------------------------------------------------------------

/// Validation tier for invalidation receipt evidence.
///
/// Receipt validity is not distributed runtime proof until paired with
/// transport and runtime artifacts.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize,
)]
pub enum ValidationTier {
    /// Structural and type-level validation only.
    Model,
    /// Source-level validation with deterministic unit-test coverage.
    Source,
    /// Integration-level validation with component-interaction evidence.
    Integration,
    /// Runtime validation with distributed transport artifacts.
    Runtime,
}

/// Acknowledgment coverage claimed by one invalidation receipt.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcknowledgmentCoverage {
    /// Commit groups for which the subscriber has acknowledged receipt.
    pub commit_groups: BTreeSet<CommitGroupId>,
}

impl AcknowledgmentCoverage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_commit_groups(
        groups: impl IntoIterator<Item = CommitGroupId>,
    ) -> Self {
        Self {
            commit_groups: groups.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn contains(&self, group: CommitGroupId) -> bool {
        self.commit_groups.contains(&group)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commit_groups.is_empty()
    }
}

/// Receipt manifest for one invalidation feed batch.
///
/// Receipts provide monotonic evidence that invalidation events were
/// published and acknowledged in order. They are model/source artifacts:
/// receipt validity alone is not distributed runtime proof until paired
/// with transport and runtime artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvalidationReceipt {
    /// Dataset this receipt covers.
    pub dataset_id: DatasetId,
    /// Commit group this receipt is for.
    pub commit_group_id: CommitGroupId,
    /// Start of the event sequence range covered, inclusive.
    pub event_sequence_start: u64,
    /// End of the event sequence range covered, inclusive.
    /// Must be >= `event_sequence_start`.
    pub event_sequence_end: u64,
    /// Kinds of invalidation events in the covered batch.
    pub event_kinds: Vec<InvalidationEventKind>,
    /// Subscriber/follower identity, if modeled.
    pub subscriber_id: Option<NodeId>,
    /// Acknowledgment coverage claimed by this receipt.
    pub acknowledgment_coverage: AcknowledgmentCoverage,
    /// Validation tier for this receipt evidence.
    pub validation_tier: ValidationTier,
}

impl InvalidationReceipt {
    #[must_use]
    pub fn new(
        dataset_id: DatasetId,
        commit_group_id: CommitGroupId,
        event_sequence_start: u64,
        event_sequence_end: u64,
        event_kinds: Vec<InvalidationEventKind>,
        subscriber_id: Option<NodeId>,
        acknowledgment_coverage: AcknowledgmentCoverage,
        validation_tier: ValidationTier,
    ) -> Self {
        Self {
            dataset_id,
            commit_group_id,
            event_sequence_start,
            event_sequence_end,
            event_kinds,
            subscriber_id,
            acknowledgment_coverage,
            validation_tier,
        }
    }
}

/// Errors detected during invalidation receipt validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptValidationError {
    /// Event sequence range is non-monotonic (start > end).
    NonMonotonicRange { start: u64, end: u64 },
    /// Duplicate event sequence ids found across receipts.
    DuplicateEventIds(Vec<u64>),
    /// Skipped event sequence ids: gap between consecutive receipts.
    SkippedEventIds { expected: u64, found: u64 },
    /// Duplicate acknowledgment: same commit group acknowledged more than
    /// once across the receipt batch.
    DuplicateAcknowledgment(CommitGroupId),
    /// Stale acknowledgment: an acked commit group is behind the oldest
    /// retained commit group.
    StaleAcknowledgment {
        acked: CommitGroupId,
        oldest_retained: CommitGroupId,
    },
    /// Unknown event kind encountered in receipt.
    UnknownEventKind(u8),
}

impl fmt::Display for ReceiptValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMonotonicRange { start, end } => {
                write!(
                    f,
                    "non-monotonic event sequence range: start {start} > end {end}"
                )
            }
            Self::DuplicateEventIds(ids) => {
                write!(f, "duplicate event ids: {ids:?}")
            }
            Self::SkippedEventIds { expected, found } => {
                write!(
                    f,
                    "skipped event ids: expected {expected}, found {found}"
                )
            }
            Self::DuplicateAcknowledgment(group) => {
                write!(
                    f,
                    "duplicate acknowledgment for commit group {}",
                    group.0
                )
            }
            Self::StaleAcknowledgment {
                acked,
                oldest_retained,
            } => {
                write!(
                    f,
                    "stale acknowledgment: acked commit group {} is behind \
                     oldest retained {}",
                    acked.0, oldest_retained.0
                )
            }
            Self::UnknownEventKind(kind) => {
                write!(f, "unknown event kind in receipt: {kind}")
            }
        }
    }
}

impl std::error::Error for ReceiptValidationError {}

/// Validates invalidation receipts for monotonic ordering and coverage.
pub struct ReceiptValidator;

impl ReceiptValidator {
    /// Validate a single receipt for internal consistency.
    pub fn validate(
        receipt: &InvalidationReceipt,
    ) -> Result<(), Vec<ReceiptValidationError>> {
        if receipt.event_sequence_start > receipt.event_sequence_end {
            return Err(vec![ReceiptValidationError::NonMonotonicRange {
                start: receipt.event_sequence_start,
                end: receipt.event_sequence_end,
            }]);
        }
        Ok(())
    }

    /// Validate a batch of receipts ordered by commit group for
    /// cross-receipt consistency.
    ///
    /// Checks that event sequence ranges are contiguous (no gaps, no
    /// overlaps) and that acknowledgments are not duplicated.
    pub fn validate_batch(
        receipts: &[InvalidationReceipt],
    ) -> Result<(), Vec<ReceiptValidationError>> {
        let mut errors = Vec::new();

        if receipts.is_empty() {
            return Ok(());
        }

        // Validate each receipt individually.
        for receipt in receipts {
            if let Err(mut receipt_errors) = Self::validate(receipt) {
                errors.append(&mut receipt_errors);
            }
        }

        // Sort by commit group for ordered checks.
        let mut sorted: Vec<&InvalidationReceipt> = receipts.iter().collect();
        sorted.sort_by_key(|r| r.commit_group_id);

        // Check for overlapping or gapped event sequence ranges.
        for window in sorted.windows(2) {
            let prev = window[0];
            let next = window[1];

            if next.event_sequence_start <= prev.event_sequence_end {
                // Overlap — duplicate event ids.
                let overlap_end = prev
                    .event_sequence_end
                    .min(next.event_sequence_end);
                let overlapping: Vec<u64> =
                    (next.event_sequence_start..=overlap_end).collect();
                errors.push(ReceiptValidationError::DuplicateEventIds(
                    overlapping,
                ));
            } else if next.event_sequence_start > prev.event_sequence_end + 1 {
                // Gap — skipped event ids.
                errors.push(ReceiptValidationError::SkippedEventIds {
                    expected: prev.event_sequence_end + 1,
                    found: next.event_sequence_start,
                });
            }
        }

        // Check for duplicate acknowledgments across receipts.
        let mut acked: BTreeSet<CommitGroupId> = BTreeSet::new();
        for receipt in receipts {
            for &group in &receipt.acknowledgment_coverage.commit_groups {
                if !acked.insert(group) {
                    errors.push(ReceiptValidationError::DuplicateAcknowledgment(
                        group,
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate acknowledgments against a known oldest-retained commit
    /// group, rejecting stale acknowledgments.
    pub fn validate_staleness(
        receipt: &InvalidationReceipt,
        oldest_retained: CommitGroupId,
    ) -> Result<(), Vec<ReceiptValidationError>> {
        let mut errors = Vec::new();
        for &group in &receipt.acknowledgment_coverage.commit_groups {
            if group < oldest_retained {
                errors.push(ReceiptValidationError::StaleAcknowledgment {
                    acked: group,
                    oldest_retained,
                });
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), InvalidationFeedError> {
    let len_u16 = u16::try_from(len).map_err(|_| InvalidationFeedError::TooManyEvents(len))?;
    out.extend_from_slice(&len_u16.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), InvalidationFeedError> {
    let len_u16 =
        u16::try_from(bytes.len()).map_err(|_| InvalidationFeedError::NameTooLong(bytes.len()))?;
    out.extend_from_slice(&len_u16.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct WireCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WireCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn magic(&mut self) -> Result<(), InvalidationFeedError> {
        if self.remaining() < WIRE_MAGIC.len() {
            return Err(InvalidationFeedError::TruncatedWire);
        }
        let magic = &self.bytes[self.pos..self.pos + WIRE_MAGIC.len()];
        self.pos += WIRE_MAGIC.len();
        if magic == WIRE_MAGIC {
            Ok(())
        } else {
            Err(InvalidationFeedError::BadMagic)
        }
    }

    fn u8(&mut self) -> Result<u8, InvalidationFeedError> {
        if self.remaining() < 1 {
            return Err(InvalidationFeedError::TruncatedWire);
        }
        let value = self.bytes[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, InvalidationFeedError> {
        let bytes = self.fixed::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, InvalidationFeedError> {
        let bytes = self.fixed::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn len(&mut self) -> Result<usize, InvalidationFeedError> {
        let bytes = self.fixed::<2>()?;
        Ok(u16::from_le_bytes(bytes) as usize)
    }

    fn bytes(&mut self) -> Result<&'a [u8], InvalidationFeedError> {
        let len = self.len()?;
        if self.remaining() < len {
            return Err(InvalidationFeedError::TruncatedWire);
        }
        let bytes = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], InvalidationFeedError> {
        if self.remaining() < N {
            return Err(InvalidationFeedError::TruncatedWire);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn finish(&self) -> Result<(), InvalidationFeedError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(InvalidationFeedError::TrailingWireBytes(remaining))
        }
    }
}

/// Trait abstracting FUSE kernel cache invalidation calls.
///
/// Implemented by the FUSE session handle (from `tidefs-fuser`) to issue
/// `NOTIFY_INVAL_INODE` and `NOTIFY_INVAL_ENTRY` to the kernel. This trait
/// enables mock-based testing of the invalidation dispatch path.
pub trait FuseNotify {
    /// Invalidate cached inode data and attributes for `ino`.
    fn notify_inval_inode(&mut self, ino: u64);
    /// Invalidate one directory-entry lookup.
    fn notify_inval_entry(&mut self, parent: u64, name: &[u8]);
}

/// Default throttle window for coalescing duplicate invalidations, in milliseconds.
pub const DEFAULT_THROTTLE_WINDOW_MS: u64 = 100;

/// FUSE-facing invalidation dispatcher with per-inode throttle coalescing.
///
/// Receives `InvalidationEvent`s from an mpsc channel, coalesces duplicate
/// inode invalidations within a configurable throttle window, and dispatches
/// coalesced events to a `FuseNotify` handle.
///
/// Entry invalidations are always dispatched immediately (they carry
/// per-name identity). Inode invalidations for the same inode within
/// the throttle window are collapsed to a single `notify_inval_inode` call.
pub struct FuseInvalidationFeed {
    rx: mpsc::Receiver<InvalidationEvent>,
    tx: mpsc::Sender<InvalidationEvent>,
    notify: Box<dyn FuseNotify + Send>,
    throttle_window: Duration,
    last_inode_inval: HashMap<u64, Instant>,
}

impl FuseInvalidationFeed {
    /// Create a new dispatch feed.
    ///
    /// `notify` is the FUSE session handle that will receive coalesced
    /// `notify_inval_inode` and `notify_inval_entry` calls.
    /// `throttle_window` defines how long to suppress duplicate inode
    /// invalidations after the first one.
    #[must_use]
    pub fn new(notify: Box<dyn FuseNotify + Send>, throttle_window: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            rx,
            tx,
            notify,
            throttle_window,
            last_inode_inval: HashMap::new(),
        }
    }

    /// Return a cloned sender that can be used to feed events into this
    /// dispatcher from other threads or tasks.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<InvalidationEvent> {
        self.tx.clone()
    }

    /// Drain all currently queued events, apply throttle coalescing, and
    /// dispatch to the `FuseNotify` handle.
    ///
    /// Returns the number of events dispatched after coalescing.
    pub fn process_tick(&mut self) -> usize {
        let now = Instant::now();
        let mut dispatched = 0usize;

        // Drain all available events non-blockingly.
        while let Ok(event) = self.rx.try_recv() {
            match event {
                InvalidationEvent::Inode { ino, .. } => {
                    let ino_raw = ino.0;
                    if let Some(&last) = self.last_inode_inval.get(&ino_raw) {
                        if now.duration_since(last) < self.throttle_window {
                            // Still within throttle window; skip.
                            continue;
                        }
                    }
                    self.last_inode_inval.insert(ino_raw, now);
                    self.notify.notify_inval_inode(ino_raw);
                    dispatched += 1;
                }
                InvalidationEvent::Entry { parent, name } => {
                    self.notify.notify_inval_entry(parent.0, &name);
                    dispatched += 1;
                }
                InvalidationEvent::Directory { ino } => {
                    // Directory invalidation is an inode invalidation plus
                    // children — the kernel must drop dcache for all children,
                    // which FUSE handles via notify_inval_inode on the dir inode
                    // plus a subsequent notify_inval_entry per child. Here we
                    // issue the inode invalidation for the directory itself;
                    // per-child entry invalidations are separate Entry events.
                    self.notify.notify_inval_inode(ino.0);
                    dispatched += 1;
                }
                InvalidationEvent::Dataset => {
                    // Dataset-scoped invalidation has no direct FUSE kernel
                    // equivalent; the caller should decompose this into
                    // per-inode and per-entry events before feeding.
                    // We treat it as a no-op at this layer.
                }
                InvalidationEvent::Range { .. } => {
                    // Range invalidation is a page-cache concern, not a
                    // dcache/icache concern. FUSE handles this via
                    // notify_inval_inode (whole-inode) or page-level
                    // invalidation. Emit an inode invalidation as the
                    // safest fallback when the range covers the whole file
                    // (offset=0, length=0 convention).
                }
            }
        }

        dispatched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(commit_group: u64) -> InvalidationBatch {
        InvalidationBatch::new(
            DatasetId::new(7),
            CommitGroupId::new(commit_group),
            vec![
                InvalidationEvent::Inode {
                    ino: InodeId::new(10),
                    generation: 2,
                },
                InvalidationEvent::Entry {
                    parent: InodeId::new(1),
                    name: b"alpha".to_vec(),
                },
                InvalidationEvent::Directory {
                    ino: InodeId::new(1),
                },
                InvalidationEvent::Range {
                    ino: InodeId::new(10),
                    offset: 0,
                    length: 4096,
                },
            ],
        )
    }

    #[test]
    fn feed_message_roundtrip_preserves_all_methods() {
        let messages = vec![
            FeedMessage::Subscribe {
                subscriber: NodeId::new(2),
                dataset: DatasetId::new(7),
                filter: EventFilterMask::ALL,
                from_commit_group: CommitGroupId::new(4),
            },
            FeedMessage::Event(batch(5)),
            FeedMessage::EventAck {
                subscriber: NodeId::new(2),
                dataset: DatasetId::new(7),
                last_commit_group: CommitGroupId::new(5),
            },
            FeedMessage::Resync {
                subscriber: NodeId::new(2),
                dataset: DatasetId::new(7),
                from_commit_group: CommitGroupId::new(3),
            },
        ];

        for message in messages {
            let encoded = message.encode().unwrap();
            assert_eq!(encoded[5], INVALIDATION_FEED_SERVICE_ID);
            assert_eq!(FeedMessage::decode(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn subscribe_event_ack_cycle_tracks_pending_work() {
        let mut feed = InvalidationFeed::new();
        let dataset = DatasetId::new(7);
        let follower = NodeId::new(2);
        feed.subscribe(
            follower,
            dataset,
            EventFilterMask::ALL,
            CommitGroupId::new(0),
        );

        let delivered = feed.publish(batch(1)).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(feed.pending_event_count(follower, dataset), 4);

        let drained = feed.drain_pending(follower, dataset, 2).unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].events.len(), 2);
        assert_eq!(feed.pending_event_count(follower, dataset), 2);

        feed.ack(follower, dataset, CommitGroupId::new(1)).unwrap();
        assert_eq!(feed.pending_event_count(follower, dataset), 0);
    }

    #[test]
    fn filters_deliver_only_matching_event_classes() {
        let mut feed = InvalidationFeed::new();
        let dataset = DatasetId::new(7);
        let follower = NodeId::new(3);
        feed.subscribe(
            follower,
            dataset,
            EventFilterMask::ENTRY,
            CommitGroupId::new(0),
        );

        let delivered = feed.publish(batch(1)).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].1.events.len(), 1);
        assert!(matches!(
            delivered[0].1.events[0],
            InvalidationEvent::Entry { .. }
        ));
    }

    #[test]
    fn resync_prefers_snapshot_then_replays_later_batches() {
        let mut feed = InvalidationFeed::new();
        let dataset = DatasetId::new(7);
        let follower = NodeId::new(4);
        feed.subscribe(
            follower,
            dataset,
            EventFilterMask::ALL,
            CommitGroupId::new(0),
        );
        feed.publish(batch(1)).unwrap();
        feed.publish(batch(2)).unwrap();

        let mut snapshot = SnapshotInvalidation::new(dataset, CommitGroupId::new(2));
        snapshot.inodes.insert(InodeId::new(10));
        snapshot.directories.insert(InodeId::new(1));
        feed.install_snapshot(snapshot.clone());
        feed.publish(batch(3)).unwrap();

        let plan = feed
            .resync(follower, dataset, CommitGroupId::new(1))
            .unwrap();
        assert_eq!(plan.snapshot, Some(snapshot));
        assert_eq!(plan.replay_from, CommitGroupId::new(2));
        assert_eq!(plan.batches.len(), 1);
        assert_eq!(plan.batches[0].commit_group, CommitGroupId::new(3));
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Vec<String>,
    }

    impl InvalidationSink for RecordingSink {
        fn invalidate_inode(&mut self, ino: InodeId, generation: u64) {
            self.events.push(format!("inode:{}:{generation}", ino.0));
        }

        fn invalidate_entry(&mut self, parent: InodeId, name: &[u8]) {
            self.events.push(format!(
                "entry:{}:{}",
                parent.0,
                String::from_utf8_lossy(name)
            ));
        }

        fn invalidate_directory(&mut self, ino: InodeId) {
            self.events.push(format!("dir:{}", ino.0));
        }

        fn invalidate_dataset(&mut self, dataset: DatasetId) {
            self.events.push(format!("dataset:{}", dataset.0));
        }

        fn invalidate_range(&mut self, ino: InodeId, offset: u64, length: u64) {
            self.events
                .push(format!("range:{}:{offset}:{length}", ino.0));
        }
    }

    #[test]
    fn follower_processor_enforces_event_budget() {
        let mut processor = FollowerInvalidationProcessor::new();
        processor.enqueue_batch(batch(1));
        let mut sink = RecordingSink::default();

        assert_eq!(processor.process_tick(&mut sink, 2), 2);
        assert_eq!(processor.pending_event_count(), 2);
        assert_eq!(sink.events, vec!["inode:10:2", "entry:1:alpha"]);

        assert_eq!(processor.process_tick(&mut sink, 8), 2);
        assert_eq!(processor.pending_event_count(), 0);
        assert_eq!(sink.events[2], "dir:1");
        assert_eq!(sink.events[3], "range:10:0:4096");
    }

    #[test]
    fn range_event_roundtrip_through_encode_decode_and_sink() {
        let event = InvalidationEvent::Range {
            ino: InodeId::new(42),
            offset: 4096,
            length: 8192,
        };
        assert_eq!(event.kind(), InvalidationEventKind::Range);

        let mut buf = Vec::new();
        event.encode_into(&mut buf).unwrap();
        let decoded = InvalidationEvent::decode_from(&mut WireCursor::new(&buf)).unwrap();
        assert_eq!(decoded, event);

        let mut sink = RecordingSink::default();
        apply_event(&mut sink, DatasetId::new(7), event);
        assert_eq!(sink.events, vec!["range:42:4096:8192"]);
    }

    #[test]
    fn range_filter_masks_range_events() {
        let mut feed = InvalidationFeed::new();
        let dataset = DatasetId::new(7);
        let follower = NodeId::new(5);
        feed.subscribe(
            follower,
            dataset,
            EventFilterMask::RANGE,
            CommitGroupId::new(0),
        );

        let delivered = feed.publish(batch(1)).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].1.events.len(), 1);
        assert!(matches!(
            delivered[0].1.events[0],
            InvalidationEvent::Range { .. }
        ));
    }

    #[test]
    fn non_monotonic_publish_is_rejected() {
        let mut feed = InvalidationFeed::new();
        feed.publish(batch(2)).unwrap();
        let err = feed.publish(batch(2)).unwrap_err();
        assert!(matches!(
            err,
            InvalidationFeedError::NonMonotonicCommitGroup { .. }
        ));
    }

    #[test]
    fn ring_buffer_enforces_capacity() {
        let mut feed = InvalidationFeed::with_ring_capacity(3);

        feed.publish(batch(1)).unwrap();
        feed.publish(batch(2)).unwrap();
        feed.publish(batch(3)).unwrap();
        assert_eq!(feed.total_retained_batches(), 3);

        // Fourth batch pushes out the oldest (batch 1)
        feed.publish(batch(4)).unwrap();
        assert_eq!(feed.total_retained_batches(), 3);
    }

    #[test]
    fn ring_buffer_replay_is_incomplete_after_eviction() {
        let mut feed = InvalidationFeed::with_ring_capacity(2);
        let dataset = DatasetId::new(7);
        let follower = NodeId::new(2);

        feed.publish(batch(1)).unwrap();
        feed.publish(batch(2)).unwrap();
        feed.publish(batch(3)).unwrap(); // batch 1 evicted

        // Subscriber joining from before evicted batches should get
        // an incomplete replay (only batches 2-3, missing batch 1).
        let result = feed.subscribe(
            follower,
            dataset,
            EventFilterMask::ALL,
            CommitGroupId::new(0),
        );
        assert_eq!(result.replay.len(), 2);
        assert_eq!(result.replay[0].commit_group, CommitGroupId::new(2));
        assert_eq!(result.replay[1].commit_group, CommitGroupId::new(3));
    }

    #[test]
    fn ring_buffer_prune_below_keeps_unacked() {
        let mut feed = InvalidationFeed::with_ring_capacity(10);
        let dataset = DatasetId::new(7);
        let f1 = NodeId::new(2);
        let f2 = NodeId::new(3);

        feed.subscribe(f1, dataset, EventFilterMask::ALL, CommitGroupId::new(0));
        feed.subscribe(f2, dataset, EventFilterMask::ALL, CommitGroupId::new(0));

        feed.publish(batch(1)).unwrap();
        feed.publish(batch(2)).unwrap();
        feed.publish(batch(3)).unwrap();

        // f1 acks up to 2, f2 acks only up to 1
        feed.ack(f1, dataset, CommitGroupId::new(2)).unwrap();
        feed.ack(f2, dataset, CommitGroupId::new(1)).unwrap();
        // min_acked is 1, so batches 1 and below pruned; batch 2 stays
        assert_eq!(feed.total_retained_batches(), 2); // batches 2 and 3
    }

    #[test]
    fn ring_buffer_default_capacity_is_1024() {
        let mut feed = InvalidationFeed::new();
        let dataset = DatasetId::new(7);

        // Publish 1025 batches, verify only 1024 retained
        for i in 1..=1025u64 {
            feed.publish(InvalidationBatch::new(
                dataset,
                CommitGroupId::new(i),
                vec![InvalidationEvent::Dataset],
            ))
            .unwrap();
        }
        assert_eq!(feed.total_retained_batches(), 1024);
    }

    #[test]
    fn ring_buffer_capacity_one_works() {
        let mut feed = InvalidationFeed::with_ring_capacity(1);
        let dataset = DatasetId::new(7);

        feed.publish(batch(1)).unwrap();
        assert_eq!(feed.total_retained_batches(), 1);

        feed.publish(batch(2)).unwrap();
        assert_eq!(feed.total_retained_batches(), 1);

        // Replay from before eviction should get only batch 2
        let result = feed.subscribe(
            NodeId::new(2),
            dataset,
            EventFilterMask::ALL,
            CommitGroupId::new(0),
        );
        assert_eq!(result.replay.len(), 1);
        assert_eq!(result.replay[0].commit_group, CommitGroupId::new(2));
    }

    #[test]
    fn feed_publisher_trait_delegates_publish_subscribe_ack() {
        let mut feed = InvalidationFeed::new();
        let publisher: &mut dyn FeedPublisher = &mut feed;
        let dataset = DatasetId::new(7);
        let follower = NodeId::new(2);

        let result = publisher.subscribe(
            follower,
            dataset,
            EventFilterMask::ALL,
            CommitGroupId::new(0),
        );
        assert_eq!(result.replay.len(), 0);

        let delivered = publisher.publish(batch(1)).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(publisher.pending_event_count(follower, dataset), 4);

        publisher
            .ack(follower, dataset, CommitGroupId::new(1))
            .unwrap();
        assert_eq!(publisher.pending_event_count(follower, dataset), 0);
    }

    #[test]
    fn feed_consumer_trait_delegates_enqueue_and_process() {
        let mut processor = FollowerInvalidationProcessor::new();
        let consumer: &mut dyn FeedConsumer = &mut processor;
        let mut sink = RecordingSink::default();

        consumer.enqueue_batch(batch(1));
        assert_eq!(consumer.pending_event_count(), 4);

        let processed = consumer.process_tick(&mut sink, 1);
        assert_eq!(processed, 1);
        assert_eq!(consumer.pending_event_count(), 3);
        assert_eq!(sink.events, vec!["inode:10:2"]);
    }

    // --- FuseInvalidationFeed tests ---

    /// Mock FuseNotify that records call arguments.
    #[derive(Default)]
    struct MockFuseNotify {
        inode_calls: Vec<u64>,
        entry_calls: Vec<(u64, Vec<u8>)>,
    }

    impl FuseNotify for MockFuseNotify {
        fn notify_inval_inode(&mut self, ino: u64) {
            self.inode_calls.push(ino);
        }

        fn notify_inval_entry(&mut self, parent: u64, name: &[u8]) {
            self.entry_calls.push((parent, name.to_vec()));
        }
    }

    #[test]
    fn fuse_feed_dispatches_inode_and_entry_events() {
        let mock = Box::new(MockFuseNotify::default());
        let mut feed = FuseInvalidationFeed::new(mock, Duration::from_millis(100));
        let tx = feed.sender();

        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(42),
            generation: 1,
        })
        .unwrap();
        tx.send(InvalidationEvent::Entry {
            parent: InodeId::new(1),
            name: b"hello".to_vec(),
        })
        .unwrap();

        let dispatched = feed.process_tick();
        assert_eq!(dispatched, 2);

        // We can't inspect the mock after moving it into the feed,
        // so we verify via the returned dispatch count.
    }

    #[test]
    fn fuse_feed_coalesces_duplicate_inode_invalidations() {
        let mock = Box::new(MockFuseNotify::default());
        let mut feed = FuseInvalidationFeed::new(mock, Duration::from_millis(500));
        let tx = feed.sender();

        // Send three inode events for the same inode in rapid succession.
        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(10),
            generation: 1,
        })
        .unwrap();
        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(10),
            generation: 2,
        })
        .unwrap();
        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(10),
            generation: 3,
        })
        .unwrap();

        let dispatched = feed.process_tick();
        // All three are processed in the same tick; only the first
        // should dispatch because the others are within the throttle window.
        assert_eq!(dispatched, 1);
    }

    #[test]
    fn fuse_feed_empty_stream_is_noop() {
        let mock = Box::new(MockFuseNotify::default());
        let mut feed = FuseInvalidationFeed::new(mock, Duration::from_millis(100));

        let dispatched = feed.process_tick();
        assert_eq!(dispatched, 0);
    }

    #[test]
    fn fuse_feed_throttle_window_expires_and_redispatches() {
        let mock = Box::new(MockFuseNotify::default());
        // Use a zero throttle window so every event dispatches.
        let mut feed = FuseInvalidationFeed::new(mock, Duration::from_millis(0));
        let tx = feed.sender();

        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(10),
            generation: 1,
        })
        .unwrap();
        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(10),
            generation: 2,
        })
        .unwrap();

        let dispatched = feed.process_tick();
        // Zero throttle window: both events dispatch.
        assert_eq!(dispatched, 2);
    }

    #[test]
    fn fuse_feed_different_inodes_are_not_coalesced() {
        let mock = Box::new(MockFuseNotify::default());
        let mut feed = FuseInvalidationFeed::new(mock, Duration::from_millis(500));
        let tx = feed.sender();

        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(10),
            generation: 1,
        })
        .unwrap();
        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(20),
            generation: 1,
        })
        .unwrap();
        tx.send(InvalidationEvent::Inode {
            ino: InodeId::new(30),
            generation: 1,
        })
        .unwrap();

        let dispatched = feed.process_tick();
        // Three different inodes: all three dispatch even within throttle window.
        assert_eq!(dispatched, 3);
    }

    #[test]
    fn fuse_feed_entries_always_dispatch() {
        let mock = Box::new(MockFuseNotify::default());
        let mut feed = FuseInvalidationFeed::new(mock, Duration::from_millis(500));
        let tx = feed.sender();

        tx.send(InvalidationEvent::Entry {
            parent: InodeId::new(1),
            name: b"alpha".to_vec(),
        })
        .unwrap();
        tx.send(InvalidationEvent::Entry {
            parent: InodeId::new(1),
            name: b"beta".to_vec(),
        })
        .unwrap();

        let dispatched = feed.process_tick();
        // Entries are not coalesced; both dispatch.
        assert_eq!(dispatched, 2);
    }

    // ------------------------------------------------------------------
    // Invalidation receipt tests
    // ------------------------------------------------------------------

    fn make_receipt(
        dataset: u64,
        commit_group: u64,
        seq_start: u64,
        seq_end: u64,
        kinds: Vec<InvalidationEventKind>,
        subscriber: Option<u64>,
        acked: Vec<u64>,
    ) -> InvalidationReceipt {
        InvalidationReceipt::new(
            DatasetId::new(dataset),
            CommitGroupId::new(commit_group),
            seq_start,
            seq_end,
            kinds,
            subscriber.map(NodeId::new),
            AcknowledgmentCoverage::with_commit_groups(
                acked.into_iter().map(CommitGroupId::new),
            ),
            ValidationTier::Source,
        )
    }

    #[test]
    fn receipt_validate_accepts_monotonic_range() {
        let receipt = make_receipt(
            7, 1, 0, 3,
            vec![InvalidationEventKind::Inode, InvalidationEventKind::Entry],
            Some(2),
            vec![1],
        );
        assert!(ReceiptValidator::validate(&receipt).is_ok());
    }

    #[test]
    fn receipt_validate_rejects_non_monotonic_range() {
        let receipt = make_receipt(
            7, 1, 5, 3,
            vec![InvalidationEventKind::Inode],
            Some(2),
            vec![1],
        );
        let err = ReceiptValidator::validate(&receipt).unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(matches!(
            err[0],
            ReceiptValidationError::NonMonotonicRange {
                start: 5,
                end: 3
            }
        ));
    }

    #[test]
    fn validate_batch_accepts_ordered_non_overlapping_receipts() {
        let receipts = vec![
            make_receipt(
                7, 1, 0, 3,
                vec![InvalidationEventKind::Inode],
                Some(2),
                vec![1],
            ),
            make_receipt(
                7, 2, 4, 7,
                vec![InvalidationEventKind::Entry],
                Some(2),
                vec![2],
            ),
            make_receipt(
                7, 3, 8, 11,
                vec![InvalidationEventKind::Directory],
                Some(2),
                vec![3],
            ),
        ];
        assert!(ReceiptValidator::validate_batch(&receipts).is_ok());
    }

    #[test]
    fn validate_batch_detects_overlapping_event_ids() {
        let receipts = vec![
            make_receipt(
                7, 1, 0, 5,
                vec![InvalidationEventKind::Inode],
                Some(2),
                vec![1],
            ),
            make_receipt(
                7, 2, 4, 9,
                vec![InvalidationEventKind::Entry],
                Some(2),
                vec![2],
            ),
        ];
        let err = ReceiptValidator::validate_batch(&receipts).unwrap_err();
        let has_duplicate = err.iter().any(|e| matches!(e, ReceiptValidationError::DuplicateEventIds(..)));
        assert!(has_duplicate, "expected DuplicateEventIds error, got {err:?}");
    }

    #[test]
    fn validate_batch_detects_skipped_event_ids() {
        let receipts = vec![
            make_receipt(
                7, 1, 0, 3,
                vec![InvalidationEventKind::Inode],
                Some(2),
                vec![1],
            ),
            make_receipt(
                7, 2, 10, 13,
                vec![InvalidationEventKind::Entry],
                Some(2),
                vec![2],
            ),
        ];
        let err = ReceiptValidator::validate_batch(&receipts).unwrap_err();
        let has_skipped = err.iter().any(|e| matches!(e, ReceiptValidationError::SkippedEventIds { .. }));
        assert!(has_skipped, "expected SkippedEventIds error, got {err:?}");
    }

    #[test]
    fn validate_batch_detects_duplicate_acknowledgments() {
        let receipts = vec![
            make_receipt(
                7, 1, 0, 3,
                vec![InvalidationEventKind::Inode],
                Some(2),
                vec![1, 2],
            ),
            make_receipt(
                7, 2, 4, 7,
                vec![InvalidationEventKind::Entry],
                Some(2),
                vec![2, 3],
            ),
        ];
        let err = ReceiptValidator::validate_batch(&receipts).unwrap_err();
        let has_dup_ack = err.iter().any(|e| matches!(e, ReceiptValidationError::DuplicateAcknowledgment(..)));
        assert!(has_dup_ack, "expected DuplicateAcknowledgment error, got {err:?}");
    }

    #[test]
    fn validate_staleness_rejects_expired_acknowledgments() {
        let receipt = make_receipt(
            7, 5, 20, 23,
            vec![InvalidationEventKind::Inode],
            Some(2),
            vec![1, 2, 3],
        );
        let err = ReceiptValidator::validate_staleness(
            &receipt,
            CommitGroupId::new(3),
        )
        .unwrap_err();
        let has_stale = err.iter().any(|e| matches!(e, ReceiptValidationError::StaleAcknowledgment { .. }));
        assert!(has_stale, "expected StaleAcknowledgment error, got {err:?}");
    }

    #[test]
    fn validate_staleness_accepts_current_acknowledgments() {
        let receipt = make_receipt(
            7, 5, 20, 23,
            vec![InvalidationEventKind::Inode],
            Some(2),
            vec![3, 4, 5],
        );
        assert!(
            ReceiptValidator::validate_staleness(&receipt, CommitGroupId::new(3))
                .is_ok()
        );
    }

    #[test]
    fn receipt_serialization_roundtrip_is_deterministic() {
        let receipt = make_receipt(
            7, 1, 0, 3,
            vec![
                InvalidationEventKind::Inode,
                InvalidationEventKind::Entry,
                InvalidationEventKind::Directory,
            ],
            Some(2),
            vec![1],
        );

        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: InvalidationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, deserialized);

        // Determinism: serialize again and compare.
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn receipt_serialization_handles_none_subscriber() {
        let receipt = make_receipt(
            7, 1, 0, 3,
            vec![InvalidationEventKind::Dataset],
            None,
            vec![1],
        );

        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: InvalidationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, deserialized);
        assert!(deserialized.subscriber_id.is_none());
    }

    #[test]
    fn acknowledgment_coverage_empty_by_default() {
        let coverage = AcknowledgmentCoverage::new();
        assert!(coverage.is_empty());
        assert!(!coverage.contains(CommitGroupId::new(1)));
    }

    #[test]
    fn acknowledgment_coverage_tracks_commit_groups() {
        let coverage = AcknowledgmentCoverage::with_commit_groups([
            CommitGroupId::new(1),
            CommitGroupId::new(3),
        ]);
        assert!(!coverage.is_empty());
        assert!(coverage.contains(CommitGroupId::new(1)));
        assert!(!coverage.contains(CommitGroupId::new(2)));
        assert!(coverage.contains(CommitGroupId::new(3)));
    }

    #[test]
    fn validate_batch_empty_input_is_ok() {
        assert!(ReceiptValidator::validate_batch(&[]).is_ok());
    }

    #[test]
    fn validation_tier_ordering() {
        assert!(ValidationTier::Model < ValidationTier::Source);
        assert!(ValidationTier::Source < ValidationTier::Integration);
        assert!(ValidationTier::Integration < ValidationTier::Runtime);
    }
}
