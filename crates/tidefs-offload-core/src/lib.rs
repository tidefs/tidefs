#![no_std]
#![forbid(unsafe_code)]

//! Non-authoritative offload descriptors, completions, leases, and CPU reference kernels.
//!
//! The CPU backend in this crate is the semantic reference. Future SIMD, GPU,
//! FPGA, DMA, kernel, RDMA, or storage-runtime integrations must validate
//! against these records instead of becoming independent authorities.

use core::convert::TryFrom;

pub use tidefs_types_vfs_core::{
    ContractEpoch, ContractVersion, RequestId, TIDE_CONTRACT_VERSION_V1,
};

pub const OFFLOAD_READY_NON_AUTHORITATIVE_CLAIM: &str = "offload.ready.non_authoritative.v1";

pub const OFFLOAD_DESC_V1_ENCODED_LEN: usize = 128;
pub const OFFLOAD_COMPLETION_V1_ENCODED_LEN: usize = 96;

const OFFLOAD_DESC_V1_ENCODED_LEN_U16: u16 = 128;
const OFFLOAD_COMPLETION_V1_ENCODED_LEN_U16: u16 = 96;

const CRC32C_REVERSED_POLY: u32 = 0x82f6_3b78;
const SCRUB_DIGEST_FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const SCRUB_DIGEST_FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const SCRUB_DIGEST_DOMAIN: &[u8] = b"tidefs-offload-scrub-digest-v1";

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OffloadDescId(pub u64);

impl OffloadDescId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BufferLeaseId(pub u64);

impl BufferLeaseId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BufferLeaseGeneration(pub u64);

impl BufferLeaseGeneration {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct OffloadDescFlags(u16);

impl OffloadDescFlags {
    pub const NONE: Self = Self(0);
    pub const CPU_REFERENCE_REQUIRED: Self = Self(1 << 0);
    pub const NON_AUTHORITATIVE: Self = Self(1 << 1);
    pub const INPUT_READ_ONLY: Self = Self(1 << 2);
    pub const EPOCH_FENCED: Self = Self(1 << 3);

    const VALID_MASK: u16 = Self::CPU_REFERENCE_REQUIRED.0
        | Self::NON_AUTHORITATIVE.0
        | Self::INPUT_READ_ONLY.0
        | Self::EPOCH_FENCED.0;

    #[must_use]
    pub const fn new(bits: u16) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_known(self) -> bool {
        (self.0 & !Self::VALID_MASK) == 0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct OffloadCompletionFlags(u32);

impl OffloadCompletionFlags {
    pub const NONE: Self = Self(0);
    pub const CPU_REFERENCE: Self = Self(1 << 0);
    pub const NON_AUTHORITATIVE: Self = Self(1 << 1);

    const VALID_MASK: u32 = Self::CPU_REFERENCE.0 | Self::NON_AUTHORITATIVE.0;

    #[must_use]
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn is_known(self) -> bool {
        (self.0 & !Self::VALID_MASK) == 0
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OffloadKernel {
    Crc32cChecksum = 1,
    XorParityShard = 2,
    ScrubDigest64 = 3,
}

impl OffloadKernel {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Crc32cChecksum),
            2 => Some(Self::XorParityShard),
            3 => Some(Self::ScrubDigest64),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OffloadStatus {
    Success = 0,
    Rejected = 1,
    InvalidDescriptor = 2,
    InvalidLease = 3,
    BufferMismatch = 4,
    KernelFailed = 5,
    Unsupported = 6,
}

impl OffloadStatus {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::Rejected),
            2 => Some(Self::InvalidDescriptor),
            3 => Some(Self::InvalidLease),
            4 => Some(Self::BufferMismatch),
            5 => Some(Self::KernelFailed),
            6 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadRequest {
    Crc32cChecksum { input_len: u64 },
    XorParityShard { data_shards: u16, shard_len: u64 },
    ScrubDigest64 { input_len: u64 },
}

impl OffloadRequest {
    /// Build a v1 descriptor for this typed request and lease.
    ///
    /// # Errors
    ///
    /// Returns [`OffloadValidationError`] when request lengths overflow, the
    /// descriptor would be invalid, or the lease cannot satisfy the descriptor.
    pub fn desc_v1(
        self,
        request_id: RequestId,
        epoch: ContractEpoch,
        desc_id: OffloadDescId,
        lease: BufferLeaseV1,
    ) -> Result<OffloadDescV1, OffloadValidationError> {
        let (kernel, input_len, output_len, param0, param1, param2, param3) =
            self.descriptor_fields()?;
        let desc = OffloadDescV1 {
            version: TIDE_CONTRACT_VERSION_V1,
            encoded_len: OFFLOAD_DESC_V1_ENCODED_LEN_U16,
            kernel,
            flags: default_desc_flags(),
            input_alignment: 1,
            output_alignment: 1,
            request_id,
            epoch,
            desc_id,
            lease_id: lease.id,
            lease_generation: lease.generation,
            input_len,
            output_len,
            param0,
            param1,
            param2,
            param3,
            reserved0: 0,
            reserved1: 0,
        };
        desc.validate_for_lease(lease)?;
        Ok(desc)
    }

    fn descriptor_fields(
        self,
    ) -> Result<(OffloadKernel, u64, u64, u64, u64, u64, u64), OffloadValidationError> {
        match self {
            Self::Crc32cChecksum { input_len } => {
                Ok((OffloadKernel::Crc32cChecksum, input_len, 4, 0, 0, 0, 0))
            }
            Self::XorParityShard {
                data_shards,
                shard_len,
            } => {
                if data_shards == 0 {
                    return Err(OffloadValidationError::InvalidKernelParameter {
                        field: OffloadKernelParamField::Param0,
                        value: 0,
                    });
                }
                if shard_len == 0 {
                    return Err(OffloadValidationError::InvalidKernelParameter {
                        field: OffloadKernelParamField::Param1,
                        value: 0,
                    });
                }
                let input_len = u64::from(data_shards).checked_mul(shard_len).ok_or(
                    OffloadValidationError::ArithmeticOverflow {
                        field: OffloadLengthField::Input,
                    },
                )?;
                Ok((
                    OffloadKernel::XorParityShard,
                    input_len,
                    shard_len,
                    u64::from(data_shards),
                    shard_len,
                    0,
                    0,
                ))
            }
            Self::ScrubDigest64 { input_len } => {
                Ok((OffloadKernel::ScrubDigest64, input_len, 8, 0, 0, 0, 0))
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferLeaseV1 {
    pub id: BufferLeaseId,
    pub generation: BufferLeaseGeneration,
    pub input_len: u64,
    pub output_len: u64,
    pub input_alignment: u32,
    pub output_alignment: u32,
}

impl BufferLeaseV1 {
    #[must_use]
    pub const fn new(
        id: BufferLeaseId,
        generation: BufferLeaseGeneration,
        input_len: u64,
        output_len: u64,
        input_alignment: u32,
        output_alignment: u32,
    ) -> Self {
        Self {
            id,
            generation,
            input_len,
            output_len,
            input_alignment,
            output_alignment,
        }
    }

    #[must_use]
    pub const fn next_generation(self) -> Self {
        Self {
            generation: BufferLeaseGeneration(self.generation.0.wrapping_add(1)),
            ..self
        }
    }

    fn validate(self) -> Result<(), OffloadValidationError> {
        if self.id.0 == 0 {
            return Err(OffloadValidationError::InvalidIdentity {
                field: OffloadIdentityField::LeaseId,
            });
        }
        validate_alignment(OffloadAlignmentField::Input, self.input_alignment)?;
        validate_alignment(OffloadAlignmentField::Output, self.output_alignment)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffloadDescV1 {
    pub version: ContractVersion,
    pub encoded_len: u16,
    pub kernel: OffloadKernel,
    pub flags: OffloadDescFlags,
    pub input_alignment: u32,
    pub output_alignment: u32,
    pub request_id: RequestId,
    pub epoch: ContractEpoch,
    pub desc_id: OffloadDescId,
    pub lease_id: BufferLeaseId,
    pub lease_generation: BufferLeaseGeneration,
    pub input_len: u64,
    pub output_len: u64,
    pub param0: u64,
    pub param1: u64,
    pub param2: u64,
    pub param3: u64,
    pub reserved0: u64,
    pub reserved1: u64,
}

impl OffloadDescV1 {
    /// Validate the descriptor's fixed-layout fields without consulting buffers.
    ///
    /// # Errors
    ///
    /// Returns [`OffloadValidationError`] for unsupported versions, invalid
    /// lengths, unknown flags, non-zero reserved fields, invalid alignments, or
    /// kernel-specific length/parameter mismatches.
    pub fn validate_fixed_layout(self) -> Result<(), OffloadValidationError> {
        expect_version(OffloadRecord::DescriptorV1, self.version)?;
        expect_encoded_len(
            OffloadRecord::DescriptorV1,
            self.encoded_len,
            OFFLOAD_DESC_V1_ENCODED_LEN_U16,
        )?;
        if !self.flags.is_known() {
            return Err(OffloadValidationError::UnknownDescFlags {
                bits: self.flags.bits(),
            });
        }
        if self.reserved0 != 0 {
            return Err(OffloadValidationError::NonZeroReserved {
                record: OffloadRecord::DescriptorV1,
                field: OffloadReservedField::DescriptorReserved0,
            });
        }
        if self.reserved1 != 0 {
            return Err(OffloadValidationError::NonZeroReserved {
                record: OffloadRecord::DescriptorV1,
                field: OffloadReservedField::DescriptorReserved1,
            });
        }
        if self.desc_id.0 == 0 {
            return Err(OffloadValidationError::InvalidIdentity {
                field: OffloadIdentityField::DescriptorId,
            });
        }
        if self.lease_id.0 == 0 {
            return Err(OffloadValidationError::InvalidIdentity {
                field: OffloadIdentityField::LeaseId,
            });
        }
        validate_alignment(OffloadAlignmentField::Input, self.input_alignment)?;
        validate_alignment(OffloadAlignmentField::Output, self.output_alignment)?;
        self.validate_kernel_layout()
    }

    /// Validate this descriptor against a current buffer lease.
    ///
    /// # Errors
    ///
    /// Returns [`OffloadValidationError`] when fixed-layout validation fails or
    /// the lease id, generation, lengths, or alignments do not match.
    pub fn validate_for_lease(self, lease: BufferLeaseV1) -> Result<(), OffloadValidationError> {
        self.validate_fixed_layout()?;
        lease.validate()?;
        if self.lease_id != lease.id {
            return Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::LeaseId,
            });
        }
        if self.lease_generation != lease.generation {
            return Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::LeaseGeneration,
            });
        }
        if self.input_len > lease.input_len {
            return Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::InputLen,
            });
        }
        if self.output_len > lease.output_len {
            return Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::OutputLen,
            });
        }
        if !alignment_satisfies(lease.input_alignment, self.input_alignment) {
            return Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::InputAlignment,
            });
        }
        if !alignment_satisfies(lease.output_alignment, self.output_alignment) {
            return Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::OutputAlignment,
            });
        }
        Ok(())
    }

    fn validate_kernel_layout(self) -> Result<(), OffloadValidationError> {
        match self.kernel {
            OffloadKernel::Crc32cChecksum => {
                expect_length(OffloadLengthField::Output, 4, self.output_len)?;
                expect_zero_param(OffloadKernelParamField::Param0, self.param0)?;
                expect_zero_param(OffloadKernelParamField::Param1, self.param1)?;
                expect_zero_param(OffloadKernelParamField::Param2, self.param2)?;
                expect_zero_param(OffloadKernelParamField::Param3, self.param3)?;
            }
            OffloadKernel::XorParityShard => {
                if self.param0 == 0 {
                    return Err(OffloadValidationError::InvalidKernelParameter {
                        field: OffloadKernelParamField::Param0,
                        value: self.param0,
                    });
                }
                if self.param1 == 0 {
                    return Err(OffloadValidationError::InvalidKernelParameter {
                        field: OffloadKernelParamField::Param1,
                        value: self.param1,
                    });
                }
                expect_zero_param(OffloadKernelParamField::Param2, self.param2)?;
                expect_zero_param(OffloadKernelParamField::Param3, self.param3)?;
                let expected_input = self.param0.checked_mul(self.param1).ok_or(
                    OffloadValidationError::ArithmeticOverflow {
                        field: OffloadLengthField::Input,
                    },
                )?;
                expect_length(OffloadLengthField::Input, expected_input, self.input_len)?;
                expect_length(OffloadLengthField::Output, self.param1, self.output_len)?;
            }
            OffloadKernel::ScrubDigest64 => {
                expect_length(OffloadLengthField::Output, 8, self.output_len)?;
                expect_zero_param(OffloadKernelParamField::Param0, self.param0)?;
                expect_zero_param(OffloadKernelParamField::Param1, self.param1)?;
                expect_zero_param(OffloadKernelParamField::Param2, self.param2)?;
                expect_zero_param(OffloadKernelParamField::Param3, self.param3)?;
            }
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffloadCompletionV1 {
    pub version: ContractVersion,
    pub encoded_len: u16,
    pub status: OffloadStatus,
    pub kernel: OffloadKernel,
    pub result_flags: OffloadCompletionFlags,
    pub reserved_header: u32,
    pub request_id: RequestId,
    pub epoch: ContractEpoch,
    pub desc_id: OffloadDescId,
    pub lease_id: BufferLeaseId,
    pub lease_generation: BufferLeaseGeneration,
    pub completed_len: u64,
    pub result0: u64,
    pub result1: u64,
    pub reserved_tail: u64,
}

impl OffloadCompletionV1 {
    #[must_use]
    pub const fn success_for(desc: OffloadDescV1, completed_len: u64, result0: u64) -> Self {
        Self {
            version: TIDE_CONTRACT_VERSION_V1,
            encoded_len: OFFLOAD_COMPLETION_V1_ENCODED_LEN_U16,
            status: OffloadStatus::Success,
            kernel: desc.kernel,
            result_flags: default_completion_flags(),
            reserved_header: 0,
            request_id: desc.request_id,
            epoch: desc.epoch,
            desc_id: desc.desc_id,
            lease_id: desc.lease_id,
            lease_generation: desc.lease_generation,
            completed_len,
            result0,
            result1: 0,
            reserved_tail: 0,
        }
    }

    /// Validate the completion's fixed-layout fields without consulting the
    /// descriptor that was issued.
    ///
    /// # Errors
    ///
    /// Returns [`OffloadValidationError`] for unsupported versions, invalid
    /// lengths, unknown flags, non-zero reserved fields, or invalid identities.
    pub fn validate_fixed_layout(self) -> Result<(), OffloadValidationError> {
        expect_version(OffloadRecord::CompletionV1, self.version)?;
        expect_encoded_len(
            OffloadRecord::CompletionV1,
            self.encoded_len,
            OFFLOAD_COMPLETION_V1_ENCODED_LEN_U16,
        )?;
        if !self.result_flags.is_known() {
            return Err(OffloadValidationError::UnknownCompletionFlags {
                bits: self.result_flags.bits(),
            });
        }
        if self.reserved_header != 0 {
            return Err(OffloadValidationError::NonZeroReserved {
                record: OffloadRecord::CompletionV1,
                field: OffloadReservedField::CompletionHeader,
            });
        }
        if self.reserved_tail != 0 {
            return Err(OffloadValidationError::NonZeroReserved {
                record: OffloadRecord::CompletionV1,
                field: OffloadReservedField::CompletionTail,
            });
        }
        if self.desc_id.0 == 0 {
            return Err(OffloadValidationError::InvalidIdentity {
                field: OffloadIdentityField::DescriptorId,
            });
        }
        if self.lease_id.0 == 0 {
            return Err(OffloadValidationError::InvalidIdentity {
                field: OffloadIdentityField::LeaseId,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffloadCompletionExpectation {
    pub status: OffloadStatus,
    pub completed_len: u64,
}

impl OffloadCompletionExpectation {
    #[must_use]
    pub const fn success(completed_len: u64) -> Self {
        Self {
            status: OffloadStatus::Success,
            completed_len,
        }
    }
}

/// Validate that a completion belongs to a descriptor and still-current lease.
///
/// # Errors
///
/// Returns [`OffloadValidationError`] when fixed-layout checks fail or any
/// request id, epoch, descriptor identity, lease token, status, or length does
/// not match the issued descriptor and expected completion shape.
pub fn validate_completion_v1(
    desc: OffloadDescV1,
    lease: BufferLeaseV1,
    completion: OffloadCompletionV1,
    expected: OffloadCompletionExpectation,
) -> Result<(), OffloadValidationError> {
    desc.validate_for_lease(lease)?;
    completion.validate_fixed_layout()?;
    if completion.request_id != desc.request_id {
        return Err(OffloadValidationError::CompletionMismatch {
            field: OffloadCompletionField::RequestId,
        });
    }
    if completion.epoch != desc.epoch {
        return Err(OffloadValidationError::CompletionMismatch {
            field: OffloadCompletionField::Epoch,
        });
    }
    if completion.desc_id != desc.desc_id {
        return Err(OffloadValidationError::CompletionMismatch {
            field: OffloadCompletionField::DescriptorId,
        });
    }
    if completion.kernel != desc.kernel {
        return Err(OffloadValidationError::CompletionMismatch {
            field: OffloadCompletionField::Kernel,
        });
    }
    if completion.lease_id != lease.id {
        return Err(OffloadValidationError::CompletionMismatch {
            field: OffloadCompletionField::LeaseId,
        });
    }
    if completion.lease_generation != lease.generation {
        return Err(OffloadValidationError::CompletionMismatch {
            field: OffloadCompletionField::LeaseGeneration,
        });
    }
    if completion.status != expected.status {
        return Err(OffloadValidationError::StatusMismatch {
            expected: expected.status,
            actual: completion.status,
        });
    }
    if completion.completed_len != expected.completed_len {
        return Err(OffloadValidationError::CompletionMismatch {
            field: OffloadCompletionField::CompletedLen,
        });
    }
    if completion.completed_len > desc.output_len {
        return Err(OffloadValidationError::LengthMismatch {
            field: OffloadLengthField::Completed,
            expected: desc.output_len,
            actual: completion.completed_len,
        });
    }
    Ok(())
}

pub struct CpuReferenceBackend;

impl CpuReferenceBackend {
    /// Execute an offload descriptor through the CPU reference backend.
    ///
    /// # Errors
    ///
    /// Returns [`OffloadValidationError`] if the descriptor/lease pair is
    /// invalid, the caller-provided slices cannot satisfy the descriptor, or
    /// kernel parameters overflow the host `usize`.
    pub fn execute(
        &self,
        desc: OffloadDescV1,
        lease: BufferLeaseV1,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<OffloadCompletionV1, OffloadValidationError> {
        desc.validate_for_lease(lease)?;
        let input_len = usize_from_u64(desc.input_len, OffloadLengthField::Input)?;
        let output_len = usize_from_u64(desc.output_len, OffloadLengthField::Output)?;
        expect_slice_len(OffloadSliceField::Input, input_len, input.len())?;
        expect_slice_capacity(OffloadSliceField::Output, output_len, output.len())?;

        let (completed_len, result0) = match desc.kernel {
            OffloadKernel::Crc32cChecksum => {
                let checksum = crc32c_reference(&input[..input_len]);
                output[..4].copy_from_slice(&checksum.to_le_bytes());
                (4_u64, u64::from(checksum))
            }
            OffloadKernel::XorParityShard => {
                let data_shards = usize_from_u64(desc.param0, OffloadLengthField::DataShards)?;
                let shard_len = usize_from_u64(desc.param1, OffloadLengthField::ShardLen)?;
                output[..shard_len].fill(0);
                for shard in 0..data_shards {
                    let start = shard.checked_mul(shard_len).ok_or(
                        OffloadValidationError::ArithmeticOverflow {
                            field: OffloadLengthField::Input,
                        },
                    )?;
                    let shard_bytes = &input[start..start + shard_len];
                    for (dst, src) in output[..shard_len].iter_mut().zip(shard_bytes) {
                        *dst ^= *src;
                    }
                }
                (desc.output_len, 0)
            }
            OffloadKernel::ScrubDigest64 => {
                let digest = scrub_digest64_reference(&input[..input_len]);
                output[..8].copy_from_slice(&digest.to_le_bytes());
                (8_u64, digest)
            }
        };

        let completion = OffloadCompletionV1::success_for(desc, completed_len, result0);
        validate_completion_v1(
            desc,
            lease,
            completion,
            OffloadCompletionExpectation::success(completed_len),
        )?;
        Ok(completion)
    }
}

/// Compute a pure-Rust CRC32C checksum for CPU reference comparisons.
#[must_use]
pub fn crc32c_reference(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC32C_REVERSED_POLY & mask);
        }
    }
    !crc
}

/// Compute a deterministic 64-bit scrub digest for CPU reference comparisons.
#[must_use]
pub fn scrub_digest64_reference(data: &[u8]) -> u64 {
    let mut hash = SCRUB_DIGEST_FNV_OFFSET;
    for byte in SCRUB_DIGEST_DOMAIN {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(SCRUB_DIGEST_FNV_PRIME);
    }
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(SCRUB_DIGEST_FNV_PRIME);
    }
    for byte in (data.len() as u64).to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(SCRUB_DIGEST_FNV_PRIME);
    }
    hash
}

/// Encode a descriptor into its exact v1 little-endian byte layout.
///
/// # Errors
///
/// Returns [`OffloadValidationError`] if `out` is not exactly
/// [`OFFLOAD_DESC_V1_ENCODED_LEN`] bytes or the descriptor is invalid.
pub fn encode_offload_desc_v1_le(
    desc: &OffloadDescV1,
    out: &mut [u8],
) -> Result<(), OffloadValidationError> {
    expect_record_len(
        OffloadRecord::DescriptorV1,
        out.len(),
        OFFLOAD_DESC_V1_ENCODED_LEN,
    )?;
    desc.validate_fixed_layout()?;
    out.fill(0);
    write_u16_le(out, 0, desc.version.raw());
    write_u16_le(out, 2, OFFLOAD_DESC_V1_ENCODED_LEN_U16);
    write_u16_le(out, 4, desc.kernel.as_u16());
    write_u16_le(out, 6, desc.flags.bits());
    write_u32_le(out, 8, desc.input_alignment);
    write_u32_le(out, 12, desc.output_alignment);
    write_bytes(out, 16, &desc.request_id.0);
    write_u64_le(out, 32, desc.epoch.raw());
    write_u64_le(out, 40, desc.desc_id.raw());
    write_u64_le(out, 48, desc.lease_id.raw());
    write_u64_le(out, 56, desc.lease_generation.raw());
    write_u64_le(out, 64, desc.input_len);
    write_u64_le(out, 72, desc.output_len);
    write_u64_le(out, 80, desc.param0);
    write_u64_le(out, 88, desc.param1);
    write_u64_le(out, 96, desc.param2);
    write_u64_le(out, 104, desc.param3);
    write_u64_le(out, 112, desc.reserved0);
    write_u64_le(out, 120, desc.reserved1);
    Ok(())
}

/// Decode an exact v1 descriptor from little-endian bytes.
///
/// # Errors
///
/// Returns [`OffloadValidationError`] for wrong length, unsupported version,
/// invalid encoded length, unknown tags, non-zero reserved fields, or invalid
/// kernel-specific parameters.
pub fn decode_offload_desc_v1_le(bytes: &[u8]) -> Result<OffloadDescV1, OffloadValidationError> {
    expect_record_len(
        OffloadRecord::DescriptorV1,
        bytes.len(),
        OFFLOAD_DESC_V1_ENCODED_LEN,
    )?;
    let version = ContractVersion(read_u16_le(bytes, 0));
    expect_version(OffloadRecord::DescriptorV1, version)?;
    expect_encoded_len(
        OffloadRecord::DescriptorV1,
        read_u16_le(bytes, 2),
        OFFLOAD_DESC_V1_ENCODED_LEN_U16,
    )?;
    let kernel_value = read_u16_le(bytes, 4);
    let kernel =
        OffloadKernel::from_u16(kernel_value).ok_or(OffloadValidationError::UnknownKernel {
            value: kernel_value,
        })?;
    let desc = OffloadDescV1 {
        version,
        encoded_len: OFFLOAD_DESC_V1_ENCODED_LEN_U16,
        kernel,
        flags: OffloadDescFlags::new(read_u16_le(bytes, 6)),
        input_alignment: read_u32_le(bytes, 8),
        output_alignment: read_u32_le(bytes, 12),
        request_id: RequestId(read_array::<16>(bytes, 16)),
        epoch: ContractEpoch(read_u64_le(bytes, 32)),
        desc_id: OffloadDescId(read_u64_le(bytes, 40)),
        lease_id: BufferLeaseId(read_u64_le(bytes, 48)),
        lease_generation: BufferLeaseGeneration(read_u64_le(bytes, 56)),
        input_len: read_u64_le(bytes, 64),
        output_len: read_u64_le(bytes, 72),
        param0: read_u64_le(bytes, 80),
        param1: read_u64_le(bytes, 88),
        param2: read_u64_le(bytes, 96),
        param3: read_u64_le(bytes, 104),
        reserved0: read_u64_le(bytes, 112),
        reserved1: read_u64_le(bytes, 120),
    };
    desc.validate_fixed_layout()?;
    Ok(desc)
}

/// Encode a completion into its exact v1 little-endian byte layout.
///
/// # Errors
///
/// Returns [`OffloadValidationError`] if `out` is not exactly
/// [`OFFLOAD_COMPLETION_V1_ENCODED_LEN`] bytes or the completion is invalid.
pub fn encode_offload_completion_v1_le(
    completion: &OffloadCompletionV1,
    out: &mut [u8],
) -> Result<(), OffloadValidationError> {
    expect_record_len(
        OffloadRecord::CompletionV1,
        out.len(),
        OFFLOAD_COMPLETION_V1_ENCODED_LEN,
    )?;
    completion.validate_fixed_layout()?;
    out.fill(0);
    write_u16_le(out, 0, completion.version.raw());
    write_u16_le(out, 2, OFFLOAD_COMPLETION_V1_ENCODED_LEN_U16);
    write_u16_le(out, 4, completion.status.as_u16());
    write_u16_le(out, 6, completion.kernel.as_u16());
    write_u32_le(out, 8, completion.result_flags.bits());
    write_u32_le(out, 12, completion.reserved_header);
    write_bytes(out, 16, &completion.request_id.0);
    write_u64_le(out, 32, completion.epoch.raw());
    write_u64_le(out, 40, completion.desc_id.raw());
    write_u64_le(out, 48, completion.lease_id.raw());
    write_u64_le(out, 56, completion.lease_generation.raw());
    write_u64_le(out, 64, completion.completed_len);
    write_u64_le(out, 72, completion.result0);
    write_u64_le(out, 80, completion.result1);
    write_u64_le(out, 88, completion.reserved_tail);
    Ok(())
}

/// Decode an exact v1 completion from little-endian bytes.
///
/// # Errors
///
/// Returns [`OffloadValidationError`] for wrong length, unsupported version,
/// invalid encoded length, unknown tags, non-zero reserved fields, or invalid
/// descriptor/lease identities.
pub fn decode_offload_completion_v1_le(
    bytes: &[u8],
) -> Result<OffloadCompletionV1, OffloadValidationError> {
    expect_record_len(
        OffloadRecord::CompletionV1,
        bytes.len(),
        OFFLOAD_COMPLETION_V1_ENCODED_LEN,
    )?;
    let version = ContractVersion(read_u16_le(bytes, 0));
    expect_version(OffloadRecord::CompletionV1, version)?;
    expect_encoded_len(
        OffloadRecord::CompletionV1,
        read_u16_le(bytes, 2),
        OFFLOAD_COMPLETION_V1_ENCODED_LEN_U16,
    )?;
    let status_value = read_u16_le(bytes, 4);
    let status =
        OffloadStatus::from_u16(status_value).ok_or(OffloadValidationError::UnknownStatus {
            value: status_value,
        })?;
    let kernel_value = read_u16_le(bytes, 6);
    let kernel =
        OffloadKernel::from_u16(kernel_value).ok_or(OffloadValidationError::UnknownKernel {
            value: kernel_value,
        })?;
    let completion = OffloadCompletionV1 {
        version,
        encoded_len: OFFLOAD_COMPLETION_V1_ENCODED_LEN_U16,
        status,
        kernel,
        result_flags: OffloadCompletionFlags::new(read_u32_le(bytes, 8)),
        reserved_header: read_u32_le(bytes, 12),
        request_id: RequestId(read_array::<16>(bytes, 16)),
        epoch: ContractEpoch(read_u64_le(bytes, 32)),
        desc_id: OffloadDescId(read_u64_le(bytes, 40)),
        lease_id: BufferLeaseId(read_u64_le(bytes, 48)),
        lease_generation: BufferLeaseGeneration(read_u64_le(bytes, 56)),
        completed_len: read_u64_le(bytes, 64),
        result0: read_u64_le(bytes, 72),
        result1: read_u64_le(bytes, 80),
        reserved_tail: read_u64_le(bytes, 88),
    };
    completion.validate_fixed_layout()?;
    Ok(completion)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadValidationError {
    Length {
        record: OffloadRecord,
        expected_len: usize,
        actual_len: usize,
    },
    UnsupportedVersion {
        record: OffloadRecord,
        version: u16,
    },
    InvalidEncodedLen {
        record: OffloadRecord,
        expected_len: u16,
        actual_len: u16,
    },
    UnknownKernel {
        value: u16,
    },
    UnknownStatus {
        value: u16,
    },
    UnknownDescFlags {
        bits: u16,
    },
    UnknownCompletionFlags {
        bits: u32,
    },
    NonZeroReserved {
        record: OffloadRecord,
        field: OffloadReservedField,
    },
    InvalidAlignment {
        field: OffloadAlignmentField,
        value: u32,
    },
    InvalidIdentity {
        field: OffloadIdentityField,
    },
    InvalidKernelParameter {
        field: OffloadKernelParamField,
        value: u64,
    },
    ArithmeticOverflow {
        field: OffloadLengthField,
    },
    LengthMismatch {
        field: OffloadLengthField,
        expected: u64,
        actual: u64,
    },
    LeaseMismatch {
        field: OffloadLeaseField,
    },
    CompletionMismatch {
        field: OffloadCompletionField,
    },
    StatusMismatch {
        expected: OffloadStatus,
        actual: OffloadStatus,
    },
    SliceTooShort {
        field: OffloadSliceField,
        expected_len: usize,
        actual_len: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadRecord {
    DescriptorV1,
    CompletionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadReservedField {
    DescriptorReserved0,
    DescriptorReserved1,
    CompletionHeader,
    CompletionTail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadAlignmentField {
    Input,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadIdentityField {
    DescriptorId,
    LeaseId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadKernelParamField {
    Param0,
    Param1,
    Param2,
    Param3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadLengthField {
    Input,
    Output,
    Completed,
    DataShards,
    ShardLen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadLeaseField {
    LeaseId,
    LeaseGeneration,
    InputLen,
    OutputLen,
    InputAlignment,
    OutputAlignment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadCompletionField {
    RequestId,
    Epoch,
    DescriptorId,
    Kernel,
    LeaseId,
    LeaseGeneration,
    CompletedLen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadSliceField {
    Input,
    Output,
}

#[must_use]
const fn default_desc_flags() -> OffloadDescFlags {
    OffloadDescFlags::CPU_REFERENCE_REQUIRED
        .union(OffloadDescFlags::NON_AUTHORITATIVE)
        .union(OffloadDescFlags::INPUT_READ_ONLY)
        .union(OffloadDescFlags::EPOCH_FENCED)
}

#[must_use]
const fn default_completion_flags() -> OffloadCompletionFlags {
    OffloadCompletionFlags::CPU_REFERENCE.union(OffloadCompletionFlags::NON_AUTHORITATIVE)
}

fn expect_version(
    record: OffloadRecord,
    version: ContractVersion,
) -> Result<(), OffloadValidationError> {
    if version == TIDE_CONTRACT_VERSION_V1 {
        Ok(())
    } else {
        Err(OffloadValidationError::UnsupportedVersion {
            record,
            version: version.raw(),
        })
    }
}

fn expect_record_len(
    record: OffloadRecord,
    actual_len: usize,
    expected_len: usize,
) -> Result<(), OffloadValidationError> {
    if actual_len == expected_len {
        Ok(())
    } else {
        Err(OffloadValidationError::Length {
            record,
            expected_len,
            actual_len,
        })
    }
}

fn expect_encoded_len(
    record: OffloadRecord,
    actual_len: u16,
    expected_len: u16,
) -> Result<(), OffloadValidationError> {
    if actual_len == expected_len {
        Ok(())
    } else {
        Err(OffloadValidationError::InvalidEncodedLen {
            record,
            expected_len,
            actual_len,
        })
    }
}

fn validate_alignment(
    field: OffloadAlignmentField,
    value: u32,
) -> Result<(), OffloadValidationError> {
    if value != 0 && value.is_power_of_two() {
        Ok(())
    } else {
        Err(OffloadValidationError::InvalidAlignment { field, value })
    }
}

fn alignment_satisfies(actual: u32, required: u32) -> bool {
    actual != 0
        && required != 0
        && actual.is_power_of_two()
        && required.is_power_of_two()
        && actual >= required
        && actual % required == 0
}

fn expect_zero_param(
    field: OffloadKernelParamField,
    value: u64,
) -> Result<(), OffloadValidationError> {
    if value == 0 {
        Ok(())
    } else {
        Err(OffloadValidationError::InvalidKernelParameter { field, value })
    }
}

fn expect_length(
    field: OffloadLengthField,
    expected: u64,
    actual: u64,
) -> Result<(), OffloadValidationError> {
    if expected == actual {
        Ok(())
    } else {
        Err(OffloadValidationError::LengthMismatch {
            field,
            expected,
            actual,
        })
    }
}

fn usize_from_u64(value: u64, field: OffloadLengthField) -> Result<usize, OffloadValidationError> {
    usize::try_from(value).map_err(|_| OffloadValidationError::ArithmeticOverflow { field })
}

fn expect_slice_len(
    field: OffloadSliceField,
    expected_len: usize,
    actual_len: usize,
) -> Result<(), OffloadValidationError> {
    if expected_len == actual_len {
        Ok(())
    } else {
        Err(OffloadValidationError::SliceTooShort {
            field,
            expected_len,
            actual_len,
        })
    }
}

fn expect_slice_capacity(
    field: OffloadSliceField,
    expected_len: usize,
    actual_len: usize,
) -> Result<(), OffloadValidationError> {
    if actual_len >= expected_len {
        Ok(())
    } else {
        Err(OffloadValidationError::SliceTooShort {
            field,
            expected_len,
            actual_len,
        })
    }
}

fn write_u16_le(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_bytes(out: &mut [u8], offset: usize, bytes: &[u8]) {
    out[offset..offset + bytes.len()].copy_from_slice(bytes);
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    let mut out = [0_u8; 2];
    out.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(out)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0_u8; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(out)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0_u8; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(out)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes[offset..offset + N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: RequestId =
        RequestId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const EPOCH: ContractEpoch = ContractEpoch(9);
    const DESC_ID: OffloadDescId = OffloadDescId(11);
    const LEASE_ID: BufferLeaseId = BufferLeaseId(13);
    const LEASE_GEN: BufferLeaseGeneration = BufferLeaseGeneration(17);

    fn lease(input_len: u64, output_len: u64) -> BufferLeaseV1 {
        BufferLeaseV1::new(LEASE_ID, LEASE_GEN, input_len, output_len, 64, 64)
    }

    fn checksum_desc() -> OffloadDescV1 {
        OffloadRequest::Crc32cChecksum { input_len: 9 }
            .desc_v1(REQUEST_ID, EPOCH, DESC_ID, lease(9, 4))
            .expect("descriptor")
    }

    #[test]
    fn descriptor_codec_round_trips_and_rejects_bad_layout() {
        let desc = checksum_desc();
        let mut buf = [0_u8; OFFLOAD_DESC_V1_ENCODED_LEN];
        encode_offload_desc_v1_le(&desc, &mut buf).expect("encode");
        assert_eq!(decode_offload_desc_v1_le(&buf).expect("decode"), desc);

        let mut bad = buf;
        bad[0] = 2;
        assert_eq!(
            decode_offload_desc_v1_le(&bad),
            Err(OffloadValidationError::UnsupportedVersion {
                record: OffloadRecord::DescriptorV1,
                version: 2,
            })
        );

        let mut bad = buf;
        bad[2] = 127;
        assert_eq!(
            decode_offload_desc_v1_le(&bad),
            Err(OffloadValidationError::InvalidEncodedLen {
                record: OffloadRecord::DescriptorV1,
                expected_len: OFFLOAD_DESC_V1_ENCODED_LEN_U16,
                actual_len: 127,
            })
        );

        let mut bad = buf;
        bad[4] = 99;
        assert_eq!(
            decode_offload_desc_v1_le(&bad),
            Err(OffloadValidationError::UnknownKernel { value: 99 })
        );

        let mut bad = buf;
        bad[112] = 1;
        assert_eq!(
            decode_offload_desc_v1_le(&bad),
            Err(OffloadValidationError::NonZeroReserved {
                record: OffloadRecord::DescriptorV1,
                field: OffloadReservedField::DescriptorReserved0,
            })
        );

        assert_eq!(
            decode_offload_desc_v1_le(&buf[..OFFLOAD_DESC_V1_ENCODED_LEN - 1]),
            Err(OffloadValidationError::Length {
                record: OffloadRecord::DescriptorV1,
                expected_len: OFFLOAD_DESC_V1_ENCODED_LEN,
                actual_len: OFFLOAD_DESC_V1_ENCODED_LEN - 1,
            })
        );
    }

    #[test]
    fn cpu_reference_crc32c_completes_with_matching_lease() {
        let desc = checksum_desc();
        let lease = lease(9, 4);
        let mut output = [0_u8; 4];
        let completion = CpuReferenceBackend
            .execute(desc, lease, b"123456789", &mut output)
            .expect("cpu checksum");

        assert_eq!(u32::from_le_bytes(output), 0xe306_9283);
        assert_eq!(completion.result0, 0xe306_9283);
        validate_completion_v1(
            desc,
            lease,
            completion,
            OffloadCompletionExpectation::success(4),
        )
        .expect("completion accepted");
    }

    #[test]
    fn cpu_reference_xor_parity_generates_single_shard() {
        let request = OffloadRequest::XorParityShard {
            data_shards: 3,
            shard_len: 4,
        };
        let lease = lease(12, 4);
        let desc = request
            .desc_v1(REQUEST_ID, EPOCH, DESC_ID, lease)
            .expect("descriptor");
        let input = [1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut output = [0_u8; 4];
        let completion = CpuReferenceBackend
            .execute(desc, lease, &input, &mut output)
            .expect("cpu parity");

        assert_eq!(output, [13, 14, 15, 0]);
        assert_eq!(completion.completed_len, 4);
    }

    #[test]
    fn scrub_digest_is_deterministic_and_length_sensitive() {
        let a = scrub_digest64_reference(b"abc");
        assert_eq!(a, scrub_digest64_reference(b"abc"));
        assert_ne!(a, scrub_digest64_reference(b"abc\0"));
    }

    #[test]
    fn completion_codec_and_validator_reject_mismatches() {
        let desc = checksum_desc();
        let lease = lease(9, 4);
        let completion = OffloadCompletionV1::success_for(desc, 4, 0xe306_9283);
        let mut buf = [0_u8; OFFLOAD_COMPLETION_V1_ENCODED_LEN];
        encode_offload_completion_v1_le(&completion, &mut buf).expect("encode");
        assert_eq!(
            decode_offload_completion_v1_le(&buf).expect("decode"),
            completion
        );

        let mut bad = completion;
        bad.request_id = RequestId([9; 16]);
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::CompletionMismatch {
                field: OffloadCompletionField::RequestId,
            })
        );

        let mut bad = completion;
        bad.epoch = ContractEpoch(99);
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::CompletionMismatch {
                field: OffloadCompletionField::Epoch,
            })
        );

        let mut bad = completion;
        bad.desc_id = OffloadDescId(99);
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::CompletionMismatch {
                field: OffloadCompletionField::DescriptorId,
            })
        );

        let mut bad = completion;
        bad.lease_generation = BufferLeaseGeneration(99);
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::CompletionMismatch {
                field: OffloadCompletionField::LeaseGeneration,
            })
        );

        let mut bad = completion;
        bad.status = OffloadStatus::Rejected;
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::StatusMismatch {
                expected: OffloadStatus::Success,
                actual: OffloadStatus::Rejected,
            })
        );

        let mut bad = completion;
        bad.completed_len = 8;
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::CompletionMismatch {
                field: OffloadCompletionField::CompletedLen,
            })
        );

        let mut bad = completion;
        bad.version = ContractVersion(2);
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::UnsupportedVersion {
                record: OffloadRecord::CompletionV1,
                version: 2,
            })
        );

        let mut bad = completion;
        bad.reserved_tail = 1;
        assert_eq!(
            validate_completion_v1(desc, lease, bad, OffloadCompletionExpectation::success(4)),
            Err(OffloadValidationError::NonZeroReserved {
                record: OffloadRecord::CompletionV1,
                field: OffloadReservedField::CompletionTail,
            })
        );
    }

    #[test]
    fn stale_or_short_leases_are_rejected() {
        let desc = checksum_desc();

        assert_eq!(
            desc.validate_for_lease(lease(9, 4).next_generation()),
            Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::LeaseGeneration,
            })
        );
        assert_eq!(
            desc.validate_for_lease(lease(8, 4)),
            Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::InputLen,
            })
        );
        assert_eq!(
            desc.validate_for_lease(lease(9, 3)),
            Err(OffloadValidationError::LeaseMismatch {
                field: OffloadLeaseField::OutputLen,
            })
        );
    }

    #[test]
    fn cpu_backend_rejects_mismatched_slices() {
        let desc = checksum_desc();
        let lease = lease(9, 4);
        let mut output = [0_u8; 4];
        assert_eq!(
            CpuReferenceBackend.execute(desc, lease, b"short", &mut output),
            Err(OffloadValidationError::SliceTooShort {
                field: OffloadSliceField::Input,
                expected_len: 9,
                actual_len: 5,
            })
        );

        let mut short_output = [0_u8; 3];
        assert_eq!(
            CpuReferenceBackend.execute(desc, lease, b"123456789", &mut short_output),
            Err(OffloadValidationError::SliceTooShort {
                field: OffloadSliceField::Output,
                expected_len: 4,
                actual_len: 3,
            })
        );
    }
}
