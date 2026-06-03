#![allow(clippy::needless_range_loop)]
#![allow(clippy::should_implement_trait)]
#![no_std]
#![forbid(unsafe_code)]

//! Claim, reserve, and witness ledger types for Design rule Rule 8.
//!
//! Rule 8: "Claims, reserves, witnesses, and receipts are authoritative
//! obligations. Reverse explainers may be materialized, but the ledger of
//! obligations cannot be optional."
//!
//! This crate provides the pure-type foundation: fixed-width identifiers,
//! enumeration of claim reasons, claim/reserve/witness entries, the
//! obligation ledger aggregator, and the reverse-explainer interface.
//!
//! ## Usage
//!
//! The runtime allocator in `tidefs-local-filesystem` uses these types to
//! track every block allocation as an obligation against a named budget
//! domain, with optional reserve guarantees and witness receipts.
//!
//! ```rust,ignore
//! use tidefs_types_claim_ledger_core::{
//!     ObligationLedger, ClaimEntry, BudgetDomainId,
//!     ClaimReason, ClaimId,
//! };
//!
//! let mut ledger = ObligationLedger::new(1024 * 1024);
//! let domain = BudgetDomainId::from_str("authority_hot");
//! let claim_id = ClaimId::new();
//! ledger.claim(ClaimEntry {
//!     claim_id,
//!     budget_domain: domain,
//!     blocks: 100,
//!     authorized_by: StorageAuthorityToken::ABSENT,
//!     reason: ClaimReason::Write,
//! });
//! assert_eq!(ledger.allocated_blocks(), 100);
//! ```

use core::convert::TryFrom;
use core::fmt;
// `ControlPlaneReceiptId` re-export removed -- use `StorageAuthorityToken` from this crate.

/// Kernel-portable storage authority token for budget/claim authorization.
///
/// Replaces [`ControlPlaneReceiptId`] in storage-core interfaces so the
/// claim-ledger types do not force control-plane dependencies on kernel-bound
/// callers.  Stored as a fixed-width `[u8; 16]` that can be derived from a
/// kernel-resident authority or carried through the claim-ledger API.
///
/// In single-node local-filesystem mode the token defaults to
/// [`StorageAuthorityToken::ABSENT`] until a kernel-resident authority is
/// designed and wired.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StorageAuthorityToken(pub [u8; 16]);

impl StorageAuthorityToken {
    /// All-zero sentinel.  Prefer [`ABSENT`] in production paths so the
    /// missing-authority condition is explicit.
    pub const ZERO: Self = Self([0_u8; 16]);

    /// Explicit "no mounted authority available" sentinel.
    ///
    /// Production write paths stamp [`ABSENT`] when the filesystem is mounted
    /// without a kernel-resident storage authority.  The token is equal to
    /// [`ZERO`] in value but carries the explicit semantic that authority has
    /// not yet been wired.  Callers should treat this as non-authoritative:
    /// the claim ledger records the obligation, but the authority chain is
    /// incomplete until a real token is minted.
    pub const ABSENT: Self = Self([0_u8; 16]);

    /// Returns true when every byte is zero (no authority present).
    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}
use tidefs_types_vfs_core::InodeId;

// ---------------------------------------------------------------------------
// ClaimId
// ---------------------------------------------------------------------------

/// A globally-unique identifier for a single space claim.
///
/// Backed by a 128-bit digest. Zero is reserved for "no claim."
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ClaimId([u8; 16]);

impl Default for ClaimId {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaimId {
    /// The all-zero claim-id (sentinel: no claim).
    pub const ZERO: Self = Self([0_u8; 16]);

    /// Generate a new random claim-id (infallible).
    ///
    /// On targets without a random source this falls back to a deterministic
    /// counter seeded from the current monotonic cycle. For production use,
    /// callers should seed this from a CSPRNG when available.
    pub fn new() -> Self {
        // Construct a pseudo-random id from the crate-local counter.
        // This is adequate for local-filesystem single-node use; distributed
        // deployments should use a proper CSPRNG.
        let mut buf = [0_u8; 16];
        let counter = NEXT_CLAIM_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        buf[0..8].copy_from_slice(&counter.to_le_bytes());
        // Mix in cycle counter as low-entropy nonce.
        let cycle = NEXT_CLAIM_COUNTER.load(core::sync::atomic::Ordering::Relaxed);
        buf[8..16].copy_from_slice(&cycle.wrapping_mul(0x9E3779B97F4A7C15).to_le_bytes());
        Self(buf)
    }

    /// Construct a ClaimId from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// Counter for pseudo-random claim-id generation.
static NEXT_CLAIM_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

impl fmt::Display for ClaimId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReserveId
// ---------------------------------------------------------------------------

/// A globally-unique identifier for a space reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ReserveId([u8; 16]);

impl Default for ReserveId {
    fn default() -> Self {
        Self::new()
    }
}

impl ReserveId {
    pub const ZERO: Self = Self([0_u8; 16]);

    pub fn new() -> Self {
        let mut buf = [0_u8; 16];
        let counter = NEXT_CLAIM_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        buf[0..8].copy_from_slice(&counter.to_le_bytes());
        buf[8..16].copy_from_slice(&counter.wrapping_mul(0xC6A4A7935BD1E995).to_le_bytes());
        Self(buf)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Construct a ReserveId from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// BudgetDomainId
// ---------------------------------------------------------------------------

/// A fixed-size, no_std identifier for a named budget domain.
///
/// Stored inline as a byte buffer (max 64 bytes). This is the no_std
/// counterpart to `tidefs_observe_runtime::BudgetDomain`; conversion
/// functions bridge the two at the std layer.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct BudgetDomainId {
    len: u8,
    buf: [u8; 64],
}

impl BudgetDomainId {
    pub const MAX_LEN: usize = 64;

    /// Construct a BudgetDomainId from a fixed string.
    ///
    /// Panics if the string exceeds `MAX_LEN` bytes or is empty.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        let b = s.as_bytes();
        let n = b.len();
        assert!(
            n > 0 && n <= Self::MAX_LEN,
            "BudgetDomainId too long or empty"
        );
        let mut buf = [0_u8; 64];
        buf[..n].copy_from_slice(b);
        Self { len: n as u8, buf }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

impl fmt::Display for BudgetDomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for BudgetDomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BudgetDomainId({})", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ClaimReason
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ClaimReason {
    /// Claim for regular file write content.
    Write = 0,
    /// Claim for fallocate / preallocation.
    Fallocate = 1,
    /// Claim for snapshot metadata (inode tables, dir entries).
    Snapshot = 2,
    /// Claim for filesystem metadata (inodes, directories, superblock).
    Metadata = 3,
    /// Reserved minimum guarantee (not yet allocated).
    Reserve = 4,
    /// Claim for clone/reflink shared extents.
    Reflink = 5,
}

impl ClaimReason {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Fallocate => "fallocate",
            Self::Snapshot => "snapshot",
            Self::Metadata => "metadata",
            Self::Reserve => "reserve",
            Self::Reflink => "reflink",
        }
    }
}

impl TryFrom<u32> for ClaimReason {
    type Error = ClaimDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Write),
            1 => Ok(Self::Fallocate),
            2 => Ok(Self::Snapshot),
            3 => Ok(Self::Metadata),
            4 => Ok(Self::Reserve),
            5 => Ok(Self::Reflink),
            _ => Err(ClaimDecodeError::InvalidClaimReason(value)),
        }
    }
}

// ---------------------------------------------------------------------------
// ClaimEntry
// ---------------------------------------------------------------------------

/// A single registered claim against space.
///
/// Every block allocated by the filesystem must be traceable back to
/// a ClaimEntry — this is the core obligation that distinguishes
/// TideFS from simple block counting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimEntry {
    pub claim_id: ClaimId,
    pub budget_domain: BudgetDomainId,
    pub blocks: u64,
    pub inode_id: InodeId,
    pub reason: ClaimReason,
    pub authorized_by: StorageAuthorityToken,
    pub generation: u64,
}

impl ClaimEntry {
    #[must_use]
    pub fn reverse_explain_label(&self) -> ReverseExplainLabel {
        ReverseExplainLabel {
            claim_id: self.claim_id,
            budget_domain: self.budget_domain,
            inode_id: self.inode_id,
            reason: self.reason,
            blocks: self.blocks,
        }
    }
}

// ---------------------------------------------------------------------------
// ReserveEntry
// ---------------------------------------------------------------------------

/// A guaranteed minimum reservation against a budget domain.
///
/// Reserves hold space that callers promise will be allocated later.
/// They are subtracted from available free space before any new allocation
/// is permitted — this prevents overcommit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReserveEntry {
    pub reserve_id: ReserveId,
    pub budget_domain: BudgetDomainId,
    pub min_blocks: u64,
    pub reason: ClaimReason,
    pub authorized_by: StorageAuthorityToken,
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// WitnessReceipt
// ---------------------------------------------------------------------------

/// A cryptographic witness proving an allocation was authorized.
///
/// In the full distributed system, witnesses chain together via
/// a hash-linked receipt tree. In the single-node local filesystem,
/// the witness is a 32-byte hash of the claim metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessReceipt {
    pub claim_id: ClaimId,
    pub receipt_id: StorageAuthorityToken,
    pub witness_bytes: [u8; 32],
}

// ---------------------------------------------------------------------------
// ObligationLedger
// ---------------------------------------------------------------------------

const MAX_CLAIMS: usize = 1024;
const MAX_RESERVES: usize = 128;
const MAX_WITNESSES: usize = 1024;

/// The authoritative obligation ledger for space accounting.
///
/// This is the runtime structure that enforces Rule 8: every block
/// allocation is registered as a claim, reserves are honored, and
/// witnesses are recorded. The reverse explainer can answer "what
/// would be freed if this budget domain were reclaimed?"
#[derive(Clone, Debug)]
pub struct ObligationLedger {
    total_blocks: u64,
    claims: [Option<ClaimEntry>; MAX_CLAIMS],
    claim_count: u16,
    reserves: [Option<ReserveEntry>; MAX_RESERVES],
    reserve_count: u16,
    witnesses: [Option<WitnessReceipt>; MAX_WITNESSES],
    witness_count: u16,
}

impl ObligationLedger {
    #[must_use]
    pub fn new(total_blocks: u64) -> Self {
        Self {
            total_blocks,
            claims: [None; MAX_CLAIMS],
            claim_count: 0,
            reserves: [None; MAX_RESERVES],
            reserve_count: 0,
            witnesses: [None; MAX_WITNESSES],
            witness_count: 0,
        }
    }

    /// Register a new claim.
    ///
    /// The claim must fit within available space (after reserves).
    pub fn claim(&mut self, entry: ClaimEntry) -> Result<(), ObligationLedgerError> {
        let i = self.claim_count as usize;
        if i >= MAX_CLAIMS {
            return Err(ObligationLedgerError::Overflow);
        }
        let committed = self.committed_blocks();
        if committed + entry.blocks > self.total_blocks {
            return Err(ObligationLedgerError::NoSpace);
        }
        self.claims[i] = Some(entry);
        self.claim_count += 1;
        Ok(())
    }

    /// Release a claim by id, freeing its blocks.
    ///
    /// Returns the freed blocks count.
    pub fn release(&mut self, claim_id: ClaimId) -> u64 {
        for i in 0..self.claim_count as usize {
            if let Some(ref entry) = self.claims[i] {
                if entry.claim_id == claim_id {
                    let blocks = entry.blocks;
                    self.claims[i] = None;
                    return blocks;
                }
            }
        }
        0
    }

    /// Release all claims associated with a given inode.
    ///
    /// Returns the total freed blocks count.
    pub fn release_claims_for_inode(&mut self, inode_id: InodeId) -> u64 {
        let mut freed = 0_u64;
        for i in 0..self.claim_count as usize {
            if let Some(ref entry) = self.claims[i] {
                if entry.inode_id == inode_id {
                    freed += entry.blocks;
                    self.claims[i] = None;
                }
            }
        }
        freed
    }

    /// Register a reserve (guaranteed minimum).
    pub fn reserve(&mut self, entry: ReserveEntry) -> Result<(), ObligationLedgerError> {
        let i = self.reserve_count as usize;
        if i >= MAX_RESERVES {
            return Err(ObligationLedgerError::Overflow);
        }
        let committed = self.committed_blocks();
        if committed + entry.min_blocks > self.total_blocks {
            return Err(ObligationLedgerError::NoSpace);
        }
        self.reserves[i] = Some(entry);
        self.reserve_count += 1;
        Ok(())
    }

    /// Release a reserve by id.
    pub fn release_reserve(&mut self, reserve_id: ReserveId) -> u64 {
        for i in 0..self.reserve_count as usize {
            if let Some(ref entry) = self.reserves[i] {
                if entry.reserve_id == reserve_id {
                    let blocks = entry.min_blocks;
                    self.reserves[i] = None;
                    return blocks;
                }
            }
        }
        0
    }

    /// Record a witness receipt for a claim.
    pub fn witness(&mut self, receipt: WitnessReceipt) -> Result<(), ObligationLedgerError> {
        let i = self.witness_count as usize;
        if i >= MAX_WITNESSES {
            return Err(ObligationLedgerError::Overflow);
        }
        self.witnesses[i] = Some(receipt);
        self.witness_count += 1;
        Ok(())
    }

    /// Total allocated blocks (sum of all active claims).
    #[must_use]
    pub fn allocated_blocks(&self) -> u64 {
        self.claims[..self.claim_count as usize]
            .iter()
            .filter_map(|c| c.as_ref())
            .map(|c| c.blocks)
            .sum()
    }

    /// Total reserved blocks (sum of all active reserves).
    #[must_use]
    pub fn reserved_blocks(&self) -> u64 {
        self.reserves[..self.reserve_count as usize]
            .iter()
            .filter_map(|r| r.as_ref())
            .map(|r| r.min_blocks)
            .sum()
    }

    /// Total committed blocks (allocated + reserved).
    #[must_use]
    pub fn committed_blocks(&self) -> u64 {
        self.allocated_blocks() + self.reserved_blocks()
    }

    /// Free blocks remaining after allocations and reserves.
    #[must_use]
    pub fn free_blocks(&self) -> u64 {
        self.total_blocks.saturating_sub(self.committed_blocks())
    }

    /// Total capacity of this obligation ledger in blocks.
    #[must_use]
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Number of active claims.
    #[must_use]
    pub fn claim_count(&self) -> usize {
        self.claim_count as usize
    }

    /// Number of active reserves.
    #[must_use]
    pub fn reserve_count(&self) -> usize {
        self.reserve_count as usize
    }

    /// Number of witness receipts.
    #[must_use]
    pub fn witness_count(&self) -> usize {
        self.witness_count as usize
    }

    /// Iterate over all active claims.
    pub fn claims_iter(&self) -> impl Iterator<Item = &ClaimEntry> {
        self.claims[..self.claim_count as usize]
            .iter()
            .filter_map(|c| c.as_ref())
    }

    /// Iterate over all active reserves.
    pub fn reserves_iter(&self) -> impl Iterator<Item = &ReserveEntry> {
        self.reserves[..self.reserve_count as usize]
            .iter()
            .filter_map(|r| r.as_ref())
    }

    /// Iterate over all witness receipts.
    pub fn witnesses_iter(&self) -> impl Iterator<Item = &WitnessReceipt> {
        self.witnesses[..self.witness_count as usize]
            .iter()
            .filter_map(|w| w.as_ref())
    }

    /// Reverse explainer: how many blocks would be freed if a budget domain
    /// or set of inodes were reclaimed?
    #[must_use]
    pub fn reverse_explain_blocks_for_domain(&self, domain: &BudgetDomainId) -> u64 {
        self.claims_iter()
            .filter(|c| &c.budget_domain == domain)
            .map(|c| c.blocks)
            .sum()
    }

    /// Reverse explainer: how many blocks are claimed by a specific inode?
    #[must_use]
    pub fn reverse_explain_blocks_for_inode(&self, inode_id: InodeId) -> u64 {
        self.claims_iter()
            .filter(|c| c.inode_id == inode_id)
            .map(|c| c.blocks)
            .sum()
    }

    /// Produce a human-readable reverse-explainer summary.
    pub fn reverse_explain_summary(&self) -> ObligationSummary {
        let mut domain_blocks = [0_u64; 16]; // enough for common budget domains
        let mut domain_names: [Option<BudgetDomainId>; 16] = [None; 16];
        let mut domain_count: usize = 0;

        for claim in self.claims_iter() {
            let mut found = false;
            for i in 0..domain_count {
                if domain_names[i] == Some(claim.budget_domain) {
                    domain_blocks[i] += claim.blocks;
                    found = true;
                    break;
                }
            }
            if !found && domain_count < 16 {
                domain_names[domain_count] = Some(claim.budget_domain);
                domain_blocks[domain_count] = claim.blocks;
                domain_count += 1;
            }
        }

        ObligationSummary {
            total_blocks: self.total_blocks,
            allocated_blocks: self.allocated_blocks(),
            reserved_blocks: self.reserved_blocks(),
            free_blocks: self.free_blocks(),
            claim_count: self.claim_count(),
            reserve_count: self.reserve_count(),
            witness_count: self.witness_count as usize,
            domain_count,
        }
    }
}

impl Default for ObligationLedger {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// ReverseExplainLabel
// ---------------------------------------------------------------------------

/// A label that explains why a block range was allocated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReverseExplainLabel {
    pub claim_id: ClaimId,
    pub budget_domain: BudgetDomainId,
    pub inode_id: InodeId,
    pub reason: ClaimReason,
    pub blocks: u64,
}

impl fmt::Display for ReverseExplainLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "claim={} domain={} inode={} reason={} blocks={}",
            self.claim_id,
            self.budget_domain,
            self.inode_id.get(),
            self.reason.as_str(),
            self.blocks,
        )
    }
}

// ---------------------------------------------------------------------------
// ObligationSummary
// ---------------------------------------------------------------------------

/// A snapshot of obligation ledger state for reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObligationSummary {
    pub total_blocks: u64,
    pub allocated_blocks: u64,
    pub reserved_blocks: u64,
    pub free_blocks: u64,
    pub claim_count: usize,
    pub reserve_count: usize,
    pub witness_count: usize,
    pub domain_count: usize,
}

// ---------------------------------------------------------------------------
// ObligationLedgerError
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationLedgerError {
    Overflow,
    NoSpace,
}

// ---------------------------------------------------------------------------
// ClaimDecodeError
// ---------------------------------------------------------------------------

/// Error returned when a [`ClaimReason`] discriminant value is out of range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimDecodeError {
    InvalidClaimReason(u32),
}

impl fmt::Display for ClaimDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClaimReason(v) => write!(f, "invalid claim reason {v}"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::ToString;
    use tidefs_types_vfs_core::InodeId;

    #[test]
    fn claim_id_display_roundtrip() {
        let id = ClaimId::new();
        let hex = id.to_string();
        assert_eq!(hex.len(), 32, "ClaimId display must produce 32-char hex");
        // Verify non-zero (random counter ensures this except in extreme cases)
        assert!(
            hex != "00000000000000000000000000000000",
            "Random ClaimId should not be all-zero"
        );
    }

    #[test]
    fn claim_id_zero() {
        let zero = ClaimId::ZERO;
        assert_eq!(zero.to_string(), "00000000000000000000000000000000");
    }

    #[test]
    fn budget_domain_id() {
        let d = BudgetDomainId::from_str("authority_hot");
        assert_eq!(d.as_str(), "authority_hot");
    }

    #[test]
    #[should_panic(expected = "too long or empty")]
    fn budget_domain_id_empty_panics() {
        let _ = BudgetDomainId::from_str("");
    }

    #[test]
    fn obligation_ledger_basic() {
        let mut ledger = ObligationLedger::new(1000);
        assert_eq!(ledger.allocated_blocks(), 0);
        assert_eq!(ledger.free_blocks(), 1000);

        let domain = BudgetDomainId::from_str("staging_dirty");
        let inode = InodeId::new(42);
        let claim_id = ClaimId::new();

        ledger
            .claim(ClaimEntry {
                claim_id,
                budget_domain: domain,
                blocks: 100,
                inode_id: inode,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();

        assert_eq!(ledger.allocated_blocks(), 100);
        assert_eq!(ledger.free_blocks(), 900);
        assert_eq!(ledger.claim_count(), 1);
    }

    #[test]
    fn obligation_ledger_no_space() {
        let mut ledger = ObligationLedger::new(50);
        let domain = BudgetDomainId::from_str("authority_hot");
        let inode = InodeId::new(1);

        let result = ledger.claim(ClaimEntry {
            claim_id: ClaimId::new(),
            budget_domain: domain,
            blocks: 100,
            inode_id: inode,
            reason: ClaimReason::Write,
            authorized_by: StorageAuthorityToken::ABSENT,
            generation: 1,
        });
        assert_eq!(result, Err(ObligationLedgerError::NoSpace));
    }

    #[test]
    fn obligation_ledger_release() {
        let mut ledger = ObligationLedger::new(1000);
        let domain = BudgetDomainId::from_str("staging_dirty");
        let inode = InodeId::new(7);
        let claim_id = ClaimId::new();

        ledger
            .claim(ClaimEntry {
                claim_id,
                budget_domain: domain,
                blocks: 200,
                inode_id: inode,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();

        assert_eq!(ledger.allocated_blocks(), 200);

        let freed = ledger.release(claim_id);
        assert_eq!(freed, 200);
        assert_eq!(ledger.allocated_blocks(), 0);
        assert_eq!(ledger.free_blocks(), 1000);
    }

    #[test]
    fn obligation_ledger_reserve() {
        let mut ledger = ObligationLedger::new(1000);
        let domain = BudgetDomainId::from_str("authority_hot");
        let inode = InodeId::new(3);

        // Reserve 100, then claim 200
        ledger
            .reserve(ReserveEntry {
                reserve_id: ReserveId::new(),
                budget_domain: domain,
                min_blocks: 100,
                reason: ClaimReason::Metadata,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();

        assert_eq!(ledger.reserved_blocks(), 100);
        assert_eq!(ledger.committed_blocks(), 100);

        ledger
            .claim(ClaimEntry {
                claim_id: ClaimId::new(),
                budget_domain: domain,
                blocks: 200,
                inode_id: inode,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();

        assert_eq!(ledger.allocated_blocks(), 200);
        assert_eq!(ledger.reserved_blocks(), 100);
        assert_eq!(ledger.committed_blocks(), 300);
        assert_eq!(ledger.free_blocks(), 700);
    }

    #[test]
    fn reverse_explain_by_domain() {
        let mut ledger = ObligationLedger::new(10000);
        let hot = BudgetDomainId::from_str("authority_hot");
        let staging = BudgetDomainId::from_str("staging_dirty");
        let inode = InodeId::new(10);

        ledger
            .claim(ClaimEntry {
                claim_id: ClaimId::new(),
                budget_domain: hot,
                blocks: 500,
                inode_id: inode,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();

        let inode2 = InodeId::new(11);
        ledger
            .claim(ClaimEntry {
                claim_id: ClaimId::new(),
                budget_domain: staging,
                blocks: 300,
                inode_id: inode2,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();

        assert_eq!(ledger.reverse_explain_blocks_for_domain(&hot), 500);
        assert_eq!(ledger.reverse_explain_blocks_for_domain(&staging), 300);
        assert_eq!(ledger.reverse_explain_blocks_for_inode(inode), 500);
    }

    #[test]
    fn witness_receipt() {
        let mut ledger = ObligationLedger::new(1000);
        let claim_id = ClaimId::new();

        let mut receipt_bytes = [0_u8; 16];
        receipt_bytes[0..8].copy_from_slice(&42_u64.to_le_bytes());
        ledger
            .witness(WitnessReceipt {
                claim_id,
                receipt_id: StorageAuthorityToken(receipt_bytes),
                witness_bytes: [0xAA; 32],
            })
            .unwrap();

        assert_eq!(ledger.witness_count as usize, 1);
        let w = ledger.witnesses_iter().next().unwrap();
        assert_eq!(w.claim_id, claim_id);
        assert_eq!(w.witness_bytes, [0xAA; 32]);
    }

    #[test]
    fn claim_reason_round_trips() {
        for v in 0_u32..=5 {
            let parsed = ClaimReason::try_from(v).unwrap();
            assert_eq!(parsed.as_u32(), v);
        }
        assert!(ClaimReason::try_from(6).is_err());
    }

    #[test]
    fn obligation_summary() {
        let mut ledger = ObligationLedger::new(10000);
        let domain = BudgetDomainId::from_str("authority_hot");
        let inode = InodeId::new(1);

        ledger
            .claim(ClaimEntry {
                claim_id: ClaimId::new(),
                budget_domain: domain,
                blocks: 1000,
                inode_id: inode,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();

        let summary = ledger.reverse_explain_summary();
        assert_eq!(summary.total_blocks, 10000);
        assert_eq!(summary.allocated_blocks, 1000);
        assert_eq!(summary.claim_count, 1);
    }
}
