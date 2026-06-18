// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Bounded pure uBLK qid/tag lifecycle model.
//!
//! The model owns no runtime file descriptors and never submits block I/O. It
//! records qid/tag ownership, emits TideFS request-contract envelopes for legal
//! uBLK I/O submissions, and emits exactly one terminal TideFS completion for
//! each request token.
pub mod started_export;

use std::fmt;

use tidefs_types_vfs_core::{
    AdmissionIntent, BlockDeviceId, BlockRequest, BudgetIntent, CompletionDisposition,
    CompletionStatus, ContractEpoch, DeadlineNs, DispositionIntent, Errno, FenceIntent,
    RequestEnvelope, RequestId, RequestMetadata, RetryIntent, TideCompletion, TideRequest,
    TimeoutNs, TraceId, WorkClass,
};
use tidefs_ublk_abi::{
    UblkSrvIoCmd, UblkSrvIoDesc, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ,
    UBLK_IO_OP_WRITE, UBLK_IO_RES_OK, UBLK_MAX_NR_QUEUES, UBLK_MAX_QUEUE_DEPTH,
};

pub const UBLK_QID_TAG_MODEL_CLAIM_ID: &str = "ublk.qid_tag.exactly_once_completion.v1";
pub const UBLK_QID_TAG_MODEL_EVIDENCE_CLASS: &str = "qid-tag-state-model";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UblkSlotKey {
    pub qid: u16,
    pub tag: u16,
}

impl UblkSlotKey {
    #[must_use]
    pub const fn new(qid: u16, tag: u16) -> Self {
        Self { qid, tag }
    }

    #[must_use]
    pub const fn queue_tag(self) -> u64 {
        ((self.qid as u64) << 16) | self.tag as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UblkRequestToken {
    pub key: UblkSlotKey,
    pub generation: u64,
}

impl UblkRequestToken {
    #[must_use]
    pub const fn new(key: UblkSlotKey, generation: u64) -> Self {
        Self { key, generation }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkModelConfig {
    pub device_id: BlockDeviceId,
    pub queue_count: u16,
    pub queue_depth: u16,
    pub sector_size: u64,
    pub trace_id: TraceId,
}

impl UblkModelConfig {
    #[must_use]
    pub const fn bounded(queue_count: u16, queue_depth: u16) -> Self {
        Self {
            device_id: BlockDeviceId::new(1),
            queue_count,
            queue_depth,
            sector_size: 512,
            trace_id: TraceId::ZERO,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkModelError {
    ZeroQueues,
    ZeroQueueDepth,
    QueueCountTooLarge {
        queue_count: u16,
        max: u16,
    },
    QueueDepthTooLarge {
        queue_depth: u16,
        max: u16,
    },
    SectorSizeZero,
    SectorRangeOverflow,
    GenerationOverflow,
    QidOutOfBounds {
        qid: u16,
        queue_count: u16,
    },
    TagOutOfBounds {
        tag: u16,
        queue_depth: u16,
    },
    SlotAlreadyInFlight {
        token: UblkRequestToken,
    },
    SlotNotInFlight {
        key: UblkSlotKey,
    },
    DuplicateCompletion {
        token: UblkRequestToken,
    },
    StaleGeneration {
        attempted: UblkRequestToken,
        current: UblkRequestToken,
    },
    WrongQid {
        token: UblkRequestToken,
        command_qid: u16,
    },
    WrongTag {
        token: UblkRequestToken,
        command_tag: u16,
    },
    CompletionAfterAbort {
        token: UblkRequestToken,
    },
    CompletionAfterTimeout {
        token: UblkRequestToken,
    },
    CompletionAfterRelease {
        token: UblkRequestToken,
    },
    ReleaseWhileInFlight {
        token: UblkRequestToken,
    },
    ReissueRequiresTimeout {
        key: UblkSlotKey,
    },
    UnsupportedOpcode {
        opcode: u8,
    },
}

impl fmt::Display for UblkModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroQueues => f.write_str("uBLK model queue count must be non-zero"),
            Self::ZeroQueueDepth => f.write_str("uBLK model queue depth must be non-zero"),
            Self::QueueCountTooLarge { queue_count, max } => {
                write!(f, "uBLK model queue count {queue_count} exceeds {max}")
            }
            Self::QueueDepthTooLarge { queue_depth, max } => {
                write!(f, "uBLK model queue depth {queue_depth} exceeds {max}")
            }
            Self::SectorSizeZero => f.write_str("uBLK model sector size must be non-zero"),
            Self::SectorRangeOverflow => f.write_str("uBLK descriptor sector range overflow"),
            Self::GenerationOverflow => f.write_str("uBLK model generation overflow"),
            Self::QidOutOfBounds { qid, queue_count } => {
                write!(f, "uBLK qid {qid} is outside queue count {queue_count}")
            }
            Self::TagOutOfBounds { tag, queue_depth } => {
                write!(f, "uBLK tag {tag} is outside queue depth {queue_depth}")
            }
            Self::SlotAlreadyInFlight { token } => {
                write!(f, "uBLK slot {:?} is already in flight", token.key)
            }
            Self::SlotNotInFlight { key } => write!(f, "uBLK slot {key:?} is not in flight"),
            Self::DuplicateCompletion { token } => {
                write!(f, "uBLK token {token:?} already completed")
            }
            Self::StaleGeneration { attempted, current } => write!(
                f,
                "uBLK token {attempted:?} is stale; current token is {current:?}"
            ),
            Self::WrongQid { token, command_qid } => {
                write!(
                    f,
                    "uBLK completion qid {command_qid} does not match {token:?}"
                )
            }
            Self::WrongTag { token, command_tag } => {
                write!(
                    f,
                    "uBLK completion tag {command_tag} does not match {token:?}"
                )
            }
            Self::CompletionAfterAbort { token } => {
                write!(f, "uBLK token {token:?} cannot complete after abort")
            }
            Self::CompletionAfterTimeout { token } => {
                write!(f, "uBLK token {token:?} cannot complete after timeout")
            }
            Self::CompletionAfterRelease { token } => {
                write!(f, "uBLK token {token:?} cannot complete after release")
            }
            Self::ReleaseWhileInFlight { token } => {
                write!(f, "uBLK token {token:?} cannot release while in flight")
            }
            Self::ReissueRequiresTimeout { key } => {
                write!(f, "uBLK slot {key:?} can reissue only after timeout")
            }
            Self::UnsupportedOpcode { opcode } => write!(f, "unsupported uBLK opcode {opcode}"),
        }
    }
}

impl std::error::Error for UblkModelError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkRequestClass {
    Read,
    Write,
    Flush,
    Discard,
}

impl UblkRequestClass {
    #[must_use]
    pub const fn from_ublk_opcode(opcode: u8) -> Result<Self, UblkModelError> {
        match opcode {
            UBLK_IO_OP_READ => Ok(Self::Read),
            UBLK_IO_OP_WRITE => Ok(Self::Write),
            UBLK_IO_OP_FLUSH => Ok(Self::Flush),
            UBLK_IO_OP_DISCARD => Ok(Self::Discard),
            other => Err(UblkModelError::UnsupportedOpcode { opcode: other }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkIoIntent {
    pub request_class: UblkRequestClass,
    pub offset: u64,
    pub length: u64,
    pub deadline: DeadlineNs,
    pub timeout: TimeoutNs,
}

impl UblkIoIntent {
    #[must_use]
    pub const fn new(request_class: UblkRequestClass, offset: u64, length: u64) -> Self {
        Self {
            request_class,
            offset,
            length,
            deadline: DeadlineNs::NONE,
            timeout: TimeoutNs::NONE,
        }
    }

    /// Convert a Linux ublk I/O descriptor into the bounded model vocabulary.
    ///
    /// # Errors
    ///
    /// Returns [`UblkModelError::UnsupportedOpcode`] for uBLK operations that
    /// the current TideFS block contract does not model, and
    /// [`UblkModelError::SectorRangeOverflow`] if sector-to-byte conversion
    /// wraps.
    pub fn from_ublk_desc(desc: UblkSrvIoDesc, sector_size: u64) -> Result<Self, UblkModelError> {
        if sector_size == 0 {
            return Err(UblkModelError::SectorSizeZero);
        }
        let request_class = UblkRequestClass::from_ublk_opcode(desc.op())?;
        let offset = desc
            .start_sector
            .checked_mul(sector_size)
            .ok_or(UblkModelError::SectorRangeOverflow)?;
        let length = if request_class == UblkRequestClass::Flush {
            0
        } else {
            u64::from(desc.count_or_zones)
                .checked_mul(sector_size)
                .ok_or(UblkModelError::SectorRangeOverflow)?
        };
        Ok(Self::new(request_class, offset, length))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkSubmission {
    pub token: UblkRequestToken,
    pub envelope: RequestEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkTerminal {
    pub token: UblkRequestToken,
    pub completion: TideCompletion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UblkModelStep {
    Request(UblkSubmission),
    Completion(UblkTerminal),
    Released(UblkRequestToken),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkSlotSnapshot {
    pub key: UblkSlotKey,
    pub state: UblkSlotStateKind,
    pub current_token: Option<UblkRequestToken>,
    pub terminal_completions: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkSlotStateKind {
    Free,
    InFlight,
    Completed,
    Aborted,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InFlightSlot {
    token: UblkRequestToken,
    intent: UblkIoIntent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TerminalSlot {
    token: UblkRequestToken,
    intent: UblkIoIntent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    InFlight(InFlightSlot),
    Completed(TerminalSlot),
    Aborted(TerminalSlot),
    TimedOut(TerminalSlot),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Slot {
    next_generation: u64,
    state: SlotState,
}

impl Slot {
    const fn new() -> Self {
        Self {
            next_generation: 1,
            state: SlotState::Free,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkEnvironmentModel {
    config: UblkModelConfig,
    slots: Vec<Slot>,
}

impl UblkEnvironmentModel {
    /// Construct a bounded model environment.
    ///
    /// # Errors
    ///
    /// Returns an error when queue bounds exceed the Linux ublk ABI constants
    /// mirrored by `tidefs-ublk-abi`.
    pub fn new(config: UblkModelConfig) -> Result<Self, UblkModelError> {
        if config.queue_count == 0 {
            return Err(UblkModelError::ZeroQueues);
        }
        if config.queue_depth == 0 {
            return Err(UblkModelError::ZeroQueueDepth);
        }
        if config.queue_count > UBLK_MAX_NR_QUEUES {
            return Err(UblkModelError::QueueCountTooLarge {
                queue_count: config.queue_count,
                max: UBLK_MAX_NR_QUEUES,
            });
        }
        if config.queue_depth > UBLK_MAX_QUEUE_DEPTH {
            return Err(UblkModelError::QueueDepthTooLarge {
                queue_depth: config.queue_depth,
                max: UBLK_MAX_QUEUE_DEPTH,
            });
        }
        if config.sector_size == 0 {
            return Err(UblkModelError::SectorSizeZero);
        }

        let mut slots =
            Vec::with_capacity(usize::from(config.queue_count) * usize::from(config.queue_depth));
        for _qid in 0..config.queue_count {
            for _tag in 0..config.queue_depth {
                slots.push(Slot::new());
            }
        }
        Ok(Self { config, slots })
    }

    #[must_use]
    pub const fn config(&self) -> UblkModelConfig {
        self.config
    }

    /// Submit a legal uBLK descriptor through the bounded environment model.
    ///
    /// # Errors
    ///
    /// Fails closed if the qid/tag is outside the configured bounds, the slot
    /// is still owned by another in-flight request, or the uBLK opcode is not
    /// represented by the current TideFS block request contract.
    pub fn submit_desc(
        &mut self,
        key: UblkSlotKey,
        desc: UblkSrvIoDesc,
    ) -> Result<UblkSubmission, UblkModelError> {
        let intent = UblkIoIntent::from_ublk_desc(desc, self.config.sector_size)?;
        self.submit(key, intent)
    }

    /// Submit an already decoded model I/O intent.
    ///
    /// # Errors
    ///
    /// Fails closed if the qid/tag is outside the configured bounds or the slot
    /// is still owned by another in-flight request.
    pub fn submit(
        &mut self,
        key: UblkSlotKey,
        intent: UblkIoIntent,
    ) -> Result<UblkSubmission, UblkModelError> {
        let config = self.config;
        let slot = self.slot_mut(key)?;
        match &slot.state {
            SlotState::Free => {}
            SlotState::InFlight(inflight) => {
                return Err(UblkModelError::SlotAlreadyInFlight {
                    token: inflight.token,
                });
            }
            SlotState::Completed(terminal)
            | SlotState::Aborted(terminal)
            | SlotState::TimedOut(terminal) => {
                return Err(UblkModelError::SlotAlreadyInFlight {
                    token: terminal.token,
                });
            }
        }

        let generation = slot.next_generation;
        slot.next_generation = generation
            .checked_add(1)
            .ok_or(UblkModelError::GenerationOverflow)?;
        let token = UblkRequestToken::new(key, generation);
        let envelope = request_envelope(config, token, intent);
        slot.state = SlotState::InFlight(InFlightSlot { token, intent });
        Ok(UblkSubmission { token, envelope })
    }

    /// Complete an in-flight uBLK token.
    ///
    /// # Errors
    ///
    /// Duplicate, stale-generation, wrong-qid, wrong-tag, and
    /// completion-after-abort/timeout/release attempts all fail closed.
    pub fn complete(
        &mut self,
        token: UblkRequestToken,
        command: UblkSrvIoCmd,
    ) -> Result<UblkTerminal, UblkModelError> {
        if command.q_id != token.key.qid {
            return Err(UblkModelError::WrongQid {
                token,
                command_qid: command.q_id,
            });
        }
        if command.tag != token.key.tag {
            return Err(UblkModelError::WrongTag {
                token,
                command_tag: command.tag,
            });
        }

        let trace_id = self.config.trace_id;
        let slot = self.slot_mut(token.key)?;
        let inflight = match &slot.state {
            SlotState::Free => {
                return Err(UblkModelError::CompletionAfterRelease { token });
            }
            SlotState::InFlight(inflight) if inflight.token == token => inflight.clone(),
            SlotState::InFlight(inflight) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: inflight.token,
                });
            }
            SlotState::Completed(terminal) if terminal.token == token => {
                return Err(UblkModelError::DuplicateCompletion { token });
            }
            SlotState::Completed(terminal) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: terminal.token,
                });
            }
            SlotState::Aborted(terminal) if terminal.token == token => {
                return Err(UblkModelError::CompletionAfterAbort { token });
            }
            SlotState::Aborted(terminal) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: terminal.token,
                });
            }
            SlotState::TimedOut(terminal) if terminal.token == token => {
                return Err(UblkModelError::CompletionAfterTimeout { token });
            }
            SlotState::TimedOut(terminal) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: terminal.token,
                });
            }
        };

        let completion = completion_from_ublk_command(trace_id, &inflight, command);
        let terminal = UblkTerminal { token, completion };
        slot.state = SlotState::Completed(TerminalSlot {
            token,
            intent: inflight.intent,
        });
        Ok(terminal)
    }

    /// Abort an in-flight token and emit one cancelled contract completion.
    ///
    /// # Errors
    ///
    /// Fails closed if the token is not the current owner of the slot.
    pub fn abort(&mut self, token: UblkRequestToken) -> Result<UblkTerminal, UblkModelError> {
        self.terminal_transition(
            token,
            CompletionStatus::Cancelled,
            CompletionDisposition::Final,
            Errno::ECANCELED,
        )
    }

    /// Timeout an in-flight token and emit one timed-out contract completion.
    ///
    /// # Errors
    ///
    /// Fails closed if the token is not the current owner of the slot.
    pub fn timeout(&mut self, token: UblkRequestToken) -> Result<UblkTerminal, UblkModelError> {
        self.terminal_transition(
            token,
            CompletionStatus::TimedOut,
            CompletionDisposition::Retryable,
            Errno::ETIMEDOUT,
        )
    }

    /// Recover a timed-out slot by reissuing the same intent with a new token.
    ///
    /// # Errors
    ///
    /// Fails closed unless the slot is in the timed-out terminal state for the
    /// provided token.
    pub fn reissue_after_timeout(
        &mut self,
        token: UblkRequestToken,
    ) -> Result<UblkSubmission, UblkModelError> {
        let config = self.config;
        let slot = self.slot_mut(token.key)?;
        let intent = match &slot.state {
            SlotState::TimedOut(terminal) if terminal.token == token => terminal.intent,
            SlotState::TimedOut(terminal) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: terminal.token,
                });
            }
            SlotState::InFlight(inflight) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: inflight.token,
                });
            }
            SlotState::Completed(_) | SlotState::Aborted(_) | SlotState::Free => {
                return Err(UblkModelError::ReissueRequiresTimeout { key: token.key });
            }
        };
        let generation = slot.next_generation;
        slot.next_generation = generation
            .checked_add(1)
            .ok_or(UblkModelError::GenerationOverflow)?;
        let new_token = UblkRequestToken::new(token.key, generation);
        let envelope = request_envelope(config, new_token, intent);
        slot.state = SlotState::InFlight(InFlightSlot {
            token: new_token,
            intent,
        });
        Ok(UblkSubmission {
            token: new_token,
            envelope,
        })
    }

    /// Release a terminal slot so the same qid/tag can accept a later request.
    ///
    /// # Errors
    ///
    /// Fails closed if the slot is still in flight or the token is stale.
    pub fn release(&mut self, token: UblkRequestToken) -> Result<UblkModelStep, UblkModelError> {
        let slot = self.slot_mut(token.key)?;
        match &slot.state {
            SlotState::Free => Err(UblkModelError::CompletionAfterRelease { token }),
            SlotState::InFlight(inflight) if inflight.token == token => {
                Err(UblkModelError::ReleaseWhileInFlight { token })
            }
            SlotState::InFlight(inflight) => Err(UblkModelError::StaleGeneration {
                attempted: token,
                current: inflight.token,
            }),
            SlotState::Completed(terminal)
            | SlotState::Aborted(terminal)
            | SlotState::TimedOut(terminal)
                if terminal.token == token =>
            {
                slot.state = SlotState::Free;
                Ok(UblkModelStep::Released(token))
            }
            SlotState::Completed(terminal)
            | SlotState::Aborted(terminal)
            | SlotState::TimedOut(terminal) => Err(UblkModelError::StaleGeneration {
                attempted: token,
                current: terminal.token,
            }),
        }
    }

    /// Return a stable slot snapshot for tests and evidence generators.
    ///
    /// # Errors
    ///
    /// Fails when the key is outside the configured model bounds.
    pub fn snapshot(&self, key: UblkSlotKey) -> Result<UblkSlotSnapshot, UblkModelError> {
        let slot = self.slot(key)?;
        let (state, current_token, terminal_completions) = match &slot.state {
            SlotState::Free => (UblkSlotStateKind::Free, None, 0),
            SlotState::InFlight(inflight) => (UblkSlotStateKind::InFlight, Some(inflight.token), 0),
            SlotState::Completed(terminal) => {
                (UblkSlotStateKind::Completed, Some(terminal.token), 1)
            }
            SlotState::Aborted(terminal) => (UblkSlotStateKind::Aborted, Some(terminal.token), 1),
            SlotState::TimedOut(terminal) => (UblkSlotStateKind::TimedOut, Some(terminal.token), 1),
        };
        Ok(UblkSlotSnapshot {
            key,
            state,
            current_token,
            terminal_completions,
        })
    }

    fn terminal_transition(
        &mut self,
        token: UblkRequestToken,
        status: CompletionStatus,
        disposition: CompletionDisposition,
        errno: Errno,
    ) -> Result<UblkTerminal, UblkModelError> {
        let trace_id = self.config.trace_id;
        let slot = self.slot_mut(token.key)?;
        let inflight = match &slot.state {
            SlotState::Free => return Err(UblkModelError::CompletionAfterRelease { token }),
            SlotState::InFlight(inflight) if inflight.token == token => inflight.clone(),
            SlotState::InFlight(inflight) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: inflight.token,
                });
            }
            SlotState::Completed(terminal) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: terminal.token,
                });
            }
            SlotState::Aborted(terminal) if terminal.token == token => {
                return Err(UblkModelError::CompletionAfterAbort { token });
            }
            SlotState::Aborted(terminal) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: terminal.token,
                });
            }
            SlotState::TimedOut(terminal) if terminal.token == token => {
                return Err(UblkModelError::CompletionAfterTimeout { token });
            }
            SlotState::TimedOut(terminal) => {
                return Err(UblkModelError::StaleGeneration {
                    attempted: token,
                    current: terminal.token,
                });
            }
        };

        let mut completion = TideCompletion::success(
            request_id_for_token(token),
            trace_id,
            ContractEpoch::new(token.generation),
        );
        completion.status = status;
        completion.disposition = disposition;
        completion.errno = errno;
        let terminal = UblkTerminal { token, completion };
        let terminal_slot = TerminalSlot {
            token,
            intent: inflight.intent,
        };
        slot.state = match status {
            CompletionStatus::Cancelled => SlotState::Aborted(terminal_slot),
            CompletionStatus::TimedOut => SlotState::TimedOut(terminal_slot),
            _ => SlotState::Completed(terminal_slot),
        };
        Ok(terminal)
    }

    fn slot(&self, key: UblkSlotKey) -> Result<&Slot, UblkModelError> {
        let index = self.slot_index(key)?;
        Ok(&self.slots[index])
    }

    fn slot_mut(&mut self, key: UblkSlotKey) -> Result<&mut Slot, UblkModelError> {
        let index = self.slot_index(key)?;
        Ok(&mut self.slots[index])
    }

    fn slot_index(&self, key: UblkSlotKey) -> Result<usize, UblkModelError> {
        if key.qid >= self.config.queue_count {
            return Err(UblkModelError::QidOutOfBounds {
                qid: key.qid,
                queue_count: self.config.queue_count,
            });
        }
        if key.tag >= self.config.queue_depth {
            return Err(UblkModelError::TagOutOfBounds {
                tag: key.tag,
                queue_depth: self.config.queue_depth,
            });
        }
        Ok(usize::from(key.qid) * usize::from(self.config.queue_depth) + usize::from(key.tag))
    }
}

fn request_envelope(
    config: UblkModelConfig,
    token: UblkRequestToken,
    intent: UblkIoIntent,
) -> RequestEnvelope {
    let request_id = request_id_for_token(token);
    let mut metadata = RequestMetadata::new(
        request_id,
        ContractEpoch::new(token.generation),
        config.trace_id,
    );
    metadata.work_class = WorkClass::Foreground;
    metadata.admission = AdmissionIntent::RequirePermit;
    metadata.budget = BudgetIntent::Foreground;
    metadata.fence = match intent.request_class {
        UblkRequestClass::Read | UblkRequestClass::Flush => FenceIntent::Read,
        UblkRequestClass::Write | UblkRequestClass::Discard => FenceIntent::Write,
    };
    metadata.retry = RetryIntent::AdapterOnly;
    metadata.disposition = DispositionIntent::CompleteOnce;
    metadata.deadline = intent.deadline;
    metadata.timeout = intent.timeout;
    RequestEnvelope::new(
        metadata,
        TideRequest::Block(block_request_for_intent(
            config.device_id,
            token.key,
            intent,
        )),
    )
}

fn block_request_for_intent(
    device_id: BlockDeviceId,
    key: UblkSlotKey,
    intent: UblkIoIntent,
) -> BlockRequest {
    match intent.request_class {
        UblkRequestClass::Read => BlockRequest::Read {
            device_id,
            offset: intent.offset,
            length: intent.length,
            queue_tag: key.queue_tag(),
        },
        UblkRequestClass::Write => BlockRequest::Write {
            device_id,
            offset: intent.offset,
            length: intent.length,
            queue_tag: key.queue_tag(),
        },
        UblkRequestClass::Flush => BlockRequest::Flush {
            device_id,
            queue_tag: key.queue_tag(),
        },
        UblkRequestClass::Discard => BlockRequest::Discard {
            device_id,
            offset: intent.offset,
            length: intent.length,
            queue_tag: key.queue_tag(),
        },
    }
}

fn completion_from_ublk_command(
    trace_id: TraceId,
    inflight: &InFlightSlot,
    command: UblkSrvIoCmd,
) -> TideCompletion {
    let token = inflight.token;
    let mut completion = TideCompletion::success(
        request_id_for_token(token),
        trace_id,
        ContractEpoch::new(token.generation),
    );
    completion.result_words = [
        u64::from(command.q_id),
        u64::from(command.tag),
        command.addr_or_zone_append_lba,
    ];
    if command.result == UBLK_IO_RES_OK {
        completion.completed_bytes = inflight.intent.length;
    } else if command.result < 0 {
        completion.status = CompletionStatus::Failed;
        completion.errno = Errno::from_raw(command.result.unsigned_abs() as u16);
    } else {
        completion.status = CompletionStatus::Deferred;
        completion.disposition = CompletionDisposition::Deferred;
        completion.result_flags = command.result as u32;
    }
    completion
}

#[must_use]
pub fn request_id_for_token(token: UblkRequestToken) -> RequestId {
    let mut bytes = [0_u8; 16];
    bytes[0..2].copy_from_slice(&token.key.qid.to_le_bytes());
    bytes[2..4].copy_from_slice(&token.key.tag.to_le_bytes());
    bytes[4..12].copy_from_slice(&token.generation.to_le_bytes());
    RequestId::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QIDS: u16 = 2;
    const TAGS: u16 = 3;

    fn model() -> UblkEnvironmentModel {
        UblkEnvironmentModel::new(UblkModelConfig::bounded(QIDS, TAGS)).expect("model config")
    }

    fn desc(opcode: u8) -> UblkSrvIoDesc {
        UblkSrvIoDesc {
            op_flags: u32::from(opcode),
            count_or_zones: 8,
            start_sector: 16,
            addr: 0,
        }
    }

    fn complete_cmd(token: UblkRequestToken) -> UblkSrvIoCmd {
        UblkSrvIoCmd {
            q_id: token.key.qid,
            tag: token.key.tag,
            result: UBLK_IO_RES_OK,
            addr_or_zone_append_lba: 0,
        }
    }

    fn submit_one(env: &mut UblkEnvironmentModel, key: UblkSlotKey, opcode: u8) -> UblkSubmission {
        env.submit_desc(key, desc(opcode)).expect("submit")
    }

    fn every_key() -> impl Iterator<Item = UblkSlotKey> {
        (0..QIDS).flat_map(|qid| (0..TAGS).map(move |tag| UblkSlotKey::new(qid, tag)))
    }

    #[test]
    fn bounded_generated_legal_traces_translate_to_contract_requests_and_completions() {
        for key in every_key() {
            for opcode in [
                UBLK_IO_OP_READ,
                UBLK_IO_OP_WRITE,
                UBLK_IO_OP_FLUSH,
                UBLK_IO_OP_DISCARD,
            ] {
                let mut env = model();
                let submission = submit_one(&mut env, key, opcode);
                assert_eq!(submission.token.key, key);
                assert_eq!(
                    submission.envelope.metadata.request_id,
                    request_id_for_token(submission.token)
                );
                assert_eq!(
                    submission.envelope.metadata.disposition,
                    DispositionIntent::CompleteOnce
                );

                match submission.envelope.request {
                    TideRequest::Block(BlockRequest::Read {
                        offset,
                        length,
                        queue_tag,
                        ..
                    }) if opcode == UBLK_IO_OP_READ => {
                        assert_eq!(offset, 16 * 512);
                        assert_eq!(length, 8 * 512);
                        assert_eq!(queue_tag, key.queue_tag());
                    }
                    TideRequest::Block(BlockRequest::Write {
                        offset,
                        length,
                        queue_tag,
                        ..
                    }) if opcode == UBLK_IO_OP_WRITE => {
                        assert_eq!(offset, 16 * 512);
                        assert_eq!(length, 8 * 512);
                        assert_eq!(queue_tag, key.queue_tag());
                    }
                    TideRequest::Block(BlockRequest::Flush { queue_tag, .. })
                        if opcode == UBLK_IO_OP_FLUSH =>
                    {
                        assert_eq!(queue_tag, key.queue_tag());
                    }
                    TideRequest::Block(BlockRequest::Discard {
                        offset,
                        length,
                        queue_tag,
                        ..
                    }) if opcode == UBLK_IO_OP_DISCARD => {
                        assert_eq!(offset, 16 * 512);
                        assert_eq!(length, 8 * 512);
                        assert_eq!(queue_tag, key.queue_tag());
                    }
                    other => panic!("unexpected request mapping: {other:?}"),
                }

                let terminal = env
                    .complete(submission.token, complete_cmd(submission.token))
                    .expect("complete");
                assert_eq!(terminal.completion.status, CompletionStatus::Success);
                assert_eq!(
                    terminal.completion.request_id,
                    request_id_for_token(submission.token)
                );
                assert_eq!(env.snapshot(key).expect("snapshot").terminal_completions, 1);
            }
        }
    }

    #[test]
    fn bounded_generated_duplicate_completions_fail_closed() {
        for key in every_key() {
            let mut env = model();
            let submission = submit_one(&mut env, key, UBLK_IO_OP_READ);
            env.complete(submission.token, complete_cmd(submission.token))
                .expect("first completion");

            let err = env
                .complete(submission.token, complete_cmd(submission.token))
                .expect_err("duplicate completion rejected");
            assert_eq!(
                err,
                UblkModelError::DuplicateCompletion {
                    token: submission.token
                }
            );
            assert_eq!(env.snapshot(key).expect("snapshot").terminal_completions, 1);
        }
    }

    #[test]
    fn bounded_generated_stale_tag_completions_fail_closed_after_reissue() {
        for key in every_key() {
            let mut env = model();
            let first = submit_one(&mut env, key, UBLK_IO_OP_WRITE);
            env.timeout(first.token).expect("timeout");
            let second = env
                .reissue_after_timeout(first.token)
                .expect("timeout reissue");
            assert_ne!(first.token, second.token);

            let err = env
                .complete(first.token, complete_cmd(first.token))
                .expect_err("stale completion rejected");
            assert_eq!(
                err,
                UblkModelError::StaleGeneration {
                    attempted: first.token,
                    current: second.token,
                }
            );
            assert_eq!(env.snapshot(key).expect("snapshot").terminal_completions, 0);

            env.complete(second.token, complete_cmd(second.token))
                .expect("reissued completion");
            assert_eq!(env.snapshot(key).expect("snapshot").terminal_completions, 1);
        }
    }

    #[test]
    fn bounded_generated_wrong_qid_completions_fail_closed() {
        for tag in 0..TAGS {
            let mut env = model();
            let key = UblkSlotKey::new(0, tag);
            let submission = submit_one(&mut env, key, UBLK_IO_OP_READ);
            let mut command = complete_cmd(submission.token);
            command.q_id = 1;

            let err = env
                .complete(submission.token, command)
                .expect_err("wrong qid rejected");
            assert_eq!(
                err,
                UblkModelError::WrongQid {
                    token: submission.token,
                    command_qid: 1,
                }
            );
            assert_eq!(
                env.snapshot(key).expect("snapshot").state,
                UblkSlotStateKind::InFlight
            );
        }
    }

    #[test]
    fn bounded_generated_wrong_tag_completions_fail_closed() {
        for qid in 0..QIDS {
            let mut env = model();
            let key = UblkSlotKey::new(qid, 0);
            let submission = submit_one(&mut env, key, UBLK_IO_OP_READ);
            let mut command = complete_cmd(submission.token);
            command.tag = 1;

            let err = env
                .complete(submission.token, command)
                .expect_err("wrong tag rejected");
            assert_eq!(
                err,
                UblkModelError::WrongTag {
                    token: submission.token,
                    command_tag: 1,
                }
            );
            assert_eq!(
                env.snapshot(key).expect("snapshot").state,
                UblkSlotStateKind::InFlight
            );
        }
    }

    #[test]
    fn bounded_generated_completion_after_abort_fails_closed() {
        for key in every_key() {
            let mut env = model();
            let submission = submit_one(&mut env, key, UBLK_IO_OP_DISCARD);
            let abort = env.abort(submission.token).expect("abort");
            assert_eq!(abort.completion.status, CompletionStatus::Cancelled);

            let err = env
                .complete(submission.token, complete_cmd(submission.token))
                .expect_err("completion after abort rejected");
            assert_eq!(
                err,
                UblkModelError::CompletionAfterAbort {
                    token: submission.token
                }
            );
            assert_eq!(env.snapshot(key).expect("snapshot").terminal_completions, 1);
        }
    }

    #[test]
    fn release_allows_later_allocation_with_new_generation() {
        let key = UblkSlotKey::new(1, 2);
        let mut env = model();
        let first = submit_one(&mut env, key, UBLK_IO_OP_FLUSH);
        env.complete(first.token, complete_cmd(first.token))
            .expect("complete");
        env.release(first.token).expect("release");
        let second = submit_one(&mut env, key, UBLK_IO_OP_FLUSH);

        assert_eq!(first.token.key, second.token.key);
        assert_ne!(first.token.generation, second.token.generation);
        let err = env
            .complete(first.token, complete_cmd(first.token))
            .expect_err("released token cannot complete");
        assert_eq!(
            err,
            UblkModelError::StaleGeneration {
                attempted: first.token,
                current: second.token,
            }
        );
    }
}
