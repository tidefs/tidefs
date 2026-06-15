//! Fixed-width little-endian codecs for the TideFS request contract.
//!
//! Versioned v1 records are exact-size packets. Decoding rejects unsupported
//! versions, invalid length fields, unknown metadata tags, and non-zero
//! reserved fields. Unknown request opcodes remain explicit unsupported
//! payloads owned by `tidefs-types-vfs-core`.

use tidefs_types_vfs_core::{
    AdmissionIntent, BudgetIntent, CompletionDisposition, CompletionStatus, ContractEpoch,
    ContractPayloadWords, ContractVersion, DeadlineNs, DispositionIntent, Errno, FenceIntent,
    FileHandleId, InodeId, RequestEnvelope, RequestId, RequestMetadata, RetryIntent,
    TideCompletion, TideRequest, TimeoutNs, TraceId, VfsRequest, WorkClass,
    TIDE_CONTRACT_VERSION_V1,
};

pub const REQUEST_ENVELOPE_V1_ENCODED_LEN: usize = 128;
pub const TIDE_COMPLETION_V1_ENCODED_LEN: usize = 96;

const REQUEST_ENVELOPE_V1_ENCODED_LEN_U16: u16 = 128;
const TIDE_COMPLETION_V1_ENCODED_LEN_U16: u16 = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractCodecError {
    Length {
        expected_len: usize,
        actual_len: usize,
    },
    UnsupportedVersion {
        version: u16,
    },
    InvalidEncodedLen {
        expected_len: u16,
        actual_len: u16,
    },
    NonZeroReserved {
        field: ContractReservedField,
    },
    UnknownTag {
        field: ContractTagField,
        value: u16,
    },
    GoldenVectorMismatch {
        vector: ContractGoldenVector,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractReservedField {
    RequestEnvelopeTail,
    CompletionHeader,
    CompletionTail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractTagField {
    WorkClass,
    AdmissionIntent,
    BudgetIntent,
    FenceIntent,
    RetryIntent,
    DispositionIntent,
    CompletionStatus,
    CompletionDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractGoldenVector {
    RequestEnvelopeV1,
    TideCompletionV1,
    RequestReservedFailure,
    CompletionReservedFailure,
}

pub const GOLDEN_REQUEST_ENVELOPE_V1: [u8; REQUEST_ENVELOPE_V1_ENCODED_LEN] =
    build_golden_request_envelope_v1();

pub const GOLDEN_TIDE_COMPLETION_V1: [u8; TIDE_COMPLETION_V1_ENCODED_LEN] =
    build_golden_tide_completion_v1();

const fn build_golden_request_envelope_v1() -> [u8; REQUEST_ENVELOPE_V1_ENCODED_LEN] {
    let mut out = [0_u8; REQUEST_ENVELOPE_V1_ENCODED_LEN];
    const_write_u16(&mut out, 0, 1);
    const_write_u16(&mut out, 2, REQUEST_ENVELOPE_V1_ENCODED_LEN_U16);
    const_write_u16(&mut out, 4, 1);
    const_write_u16(&mut out, 6, 2);
    const_write_u16(&mut out, 8, 1);
    const_write_u16(&mut out, 10, 1);
    const_write_u16(&mut out, 12, 1);
    const_write_u16(&mut out, 14, 3);
    const_write_u16(&mut out, 16, 1);
    const_write_u16(&mut out, 18, 0);
    const_write_u32(&mut out, 20, 0xA5A5_0001);
    const_write_bytes(
        &mut out,
        24,
        [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ],
    );
    const_write_u64(&mut out, 40, 7);
    const_write_bytes(
        &mut out,
        48,
        [
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        ],
    );
    const_write_u64(&mut out, 64, 1000);
    const_write_u64(&mut out, 72, 250);
    const_write_u64(&mut out, 80, 42);
    const_write_u64(&mut out, 88, 9);
    const_write_u64(&mut out, 96, 4096);
    const_write_u64(&mut out, 104, 512);
    out
}

const fn build_golden_tide_completion_v1() -> [u8; TIDE_COMPLETION_V1_ENCODED_LEN] {
    let mut out = [0_u8; TIDE_COMPLETION_V1_ENCODED_LEN];
    const_write_u16(&mut out, 0, 1);
    const_write_u16(&mut out, 2, TIDE_COMPLETION_V1_ENCODED_LEN_U16);
    const_write_u32(&mut out, 12, 0xAA);
    const_write_bytes(
        &mut out,
        16,
        [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ],
    );
    const_write_bytes(
        &mut out,
        32,
        [
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        ],
    );
    const_write_u64(&mut out, 48, 8);
    const_write_u64(&mut out, 56, 512);
    const_write_u64(&mut out, 64, 42);
    out
}

const fn const_write_u16<const N: usize>(out: &mut [u8; N], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    out[offset] = bytes[0];
    out[offset + 1] = bytes[1];
}

const fn const_write_u32<const N: usize>(out: &mut [u8; N], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    out[offset] = bytes[0];
    out[offset + 1] = bytes[1];
    out[offset + 2] = bytes[2];
    out[offset + 3] = bytes[3];
}

const fn const_write_u64<const N: usize>(out: &mut [u8; N], offset: usize, value: u64) {
    let bytes = value.to_le_bytes();
    let mut index = 0;
    while index < 8 {
        out[offset + index] = bytes[index];
        index += 1;
    }
}

const fn const_write_bytes<const N: usize, const M: usize>(
    out: &mut [u8; N],
    offset: usize,
    bytes: [u8; M],
) {
    let mut index = 0;
    while index < M {
        out[offset + index] = bytes[index];
        index += 1;
    }
}

#[must_use]
pub const fn golden_request_envelope_v1() -> RequestEnvelope {
    RequestEnvelope {
        version: TIDE_CONTRACT_VERSION_V1,
        metadata: RequestMetadata {
            request_id: RequestId([
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            epoch: ContractEpoch(7),
            trace_id: TraceId([
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            ]),
            work_class: WorkClass::Foreground,
            admission: AdmissionIntent::RequirePermit,
            budget: BudgetIntent::Foreground,
            fence: FenceIntent::Epoch,
            retry: RetryIntent::Idempotent,
            disposition: DispositionIntent::CompleteOnce,
            deadline: DeadlineNs(1000),
            timeout: TimeoutNs(250),
        },
        request: TideRequest::Vfs(VfsRequest::Read {
            inode_id: InodeId(42),
            file_handle_id: FileHandleId(9),
            offset: 4096,
            length: 512,
        }),
        payload_flags: 0xA5A5_0001,
    }
}

#[must_use]
pub const fn golden_tide_completion_v1() -> TideCompletion {
    TideCompletion {
        version: TIDE_CONTRACT_VERSION_V1,
        request_id: RequestId([
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ]),
        trace_id: TraceId([
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        ]),
        epoch: ContractEpoch(8),
        status: CompletionStatus::Success,
        disposition: CompletionDisposition::Final,
        errno: Errno::SUCCESS,
        completed_bytes: 512,
        result_words: [42, 0, 0],
        result_flags: 0xAA,
    }
}

/// Encode a v1 request envelope into its exact fixed-width wire form.
///
/// # Errors
///
/// Returns [`ContractCodecError`] if `out` is not exactly
/// [`REQUEST_ENVELOPE_V1_ENCODED_LEN`] bytes or the envelope names an
/// unsupported contract version.
pub fn encode_request_envelope_v1_le(
    envelope: &RequestEnvelope,
    out: &mut [u8],
) -> Result<(), ContractCodecError> {
    expect_len(out.len(), REQUEST_ENVELOPE_V1_ENCODED_LEN)?;
    expect_version(envelope.version)?;

    out.fill(0);
    let (domain, opcode, words) = envelope.request.domain_opcode_words();

    write_u16_le(out, 0, envelope.version.raw());
    write_u16_le(out, 2, REQUEST_ENVELOPE_V1_ENCODED_LEN_U16);
    write_u16_le(out, 4, domain);
    write_u16_le(out, 6, opcode);
    write_u16_le(out, 8, envelope.metadata.work_class.as_u16());
    write_u16_le(out, 10, envelope.metadata.admission.as_u16());
    write_u16_le(out, 12, envelope.metadata.budget.as_u16());
    write_u16_le(out, 14, envelope.metadata.fence.as_u16());
    write_u16_le(out, 16, envelope.metadata.retry.as_u16());
    write_u16_le(out, 18, envelope.metadata.disposition.as_u16());
    write_u32_le(out, 20, envelope.payload_flags);
    write_bytes(out, 24, &envelope.metadata.request_id.0);
    write_u64_le(out, 40, envelope.metadata.epoch.0);
    write_bytes(out, 48, &envelope.metadata.trace_id.0);
    write_u64_le(out, 64, envelope.metadata.deadline.0);
    write_u64_le(out, 72, envelope.metadata.timeout.0);
    write_payload_words(out, 80, words);
    Ok(())
}

/// Decode an exact v1 request envelope from little-endian bytes.
///
/// # Errors
///
/// Returns [`ContractCodecError`] for wrong length, unsupported version,
/// invalid record length, unknown metadata tags, or non-zero reserved fields.
pub fn decode_request_envelope_v1_le(bytes: &[u8]) -> Result<RequestEnvelope, ContractCodecError> {
    expect_len(bytes.len(), REQUEST_ENVELOPE_V1_ENCODED_LEN)?;
    let version = read_u16_le(bytes, 0);
    expect_version(ContractVersion(version))?;
    expect_encoded_len(read_u16_le(bytes, 2), REQUEST_ENVELOPE_V1_ENCODED_LEN_U16)?;
    if read_u64_le(bytes, 120) != 0 {
        return Err(ContractCodecError::NonZeroReserved {
            field: ContractReservedField::RequestEnvelopeTail,
        });
    }

    let domain = read_u16_le(bytes, 4);
    let opcode = read_u16_le(bytes, 6);
    let words = read_payload_words(bytes, 80);

    Ok(RequestEnvelope {
        version: ContractVersion(version),
        metadata: RequestMetadata {
            request_id: RequestId(read_array::<16>(bytes, 24)),
            epoch: ContractEpoch(read_u64_le(bytes, 40)),
            trace_id: TraceId(read_array::<16>(bytes, 48)),
            work_class: decode_work_class(read_u16_le(bytes, 8))?,
            admission: decode_admission_intent(read_u16_le(bytes, 10))?,
            budget: decode_budget_intent(read_u16_le(bytes, 12))?,
            fence: decode_fence_intent(read_u16_le(bytes, 14))?,
            retry: decode_retry_intent(read_u16_le(bytes, 16))?,
            disposition: decode_disposition_intent(read_u16_le(bytes, 18))?,
            deadline: DeadlineNs(read_u64_le(bytes, 64)),
            timeout: TimeoutNs(read_u64_le(bytes, 72)),
        },
        request: TideRequest::from_domain_opcode_words(domain, opcode, words),
        payload_flags: read_u32_le(bytes, 20),
    })
}

/// Encode a v1 completion into its exact fixed-width wire form.
///
/// # Errors
///
/// Returns [`ContractCodecError`] if `out` is not exactly
/// [`TIDE_COMPLETION_V1_ENCODED_LEN`] bytes or the completion names an
/// unsupported contract version.
pub fn encode_tide_completion_v1_le(
    completion: &TideCompletion,
    out: &mut [u8],
) -> Result<(), ContractCodecError> {
    expect_len(out.len(), TIDE_COMPLETION_V1_ENCODED_LEN)?;
    expect_version(completion.version)?;

    out.fill(0);
    write_u16_le(out, 0, completion.version.raw());
    write_u16_le(out, 2, TIDE_COMPLETION_V1_ENCODED_LEN_U16);
    write_u16_le(out, 4, completion.status.as_u16());
    write_u16_le(out, 6, completion.disposition.as_u16());
    write_u16_le(out, 8, completion.errno.raw());
    write_u32_le(out, 12, completion.result_flags);
    write_bytes(out, 16, &completion.request_id.0);
    write_bytes(out, 32, &completion.trace_id.0);
    write_u64_le(out, 48, completion.epoch.0);
    write_u64_le(out, 56, completion.completed_bytes);
    write_u64_le(out, 64, completion.result_words[0]);
    write_u64_le(out, 72, completion.result_words[1]);
    write_u64_le(out, 80, completion.result_words[2]);
    Ok(())
}

/// Decode an exact v1 completion from little-endian bytes.
///
/// # Errors
///
/// Returns [`ContractCodecError`] for wrong length, unsupported version,
/// invalid record length, unknown status/disposition tags, or non-zero
/// reserved fields.
pub fn decode_tide_completion_v1_le(bytes: &[u8]) -> Result<TideCompletion, ContractCodecError> {
    expect_len(bytes.len(), TIDE_COMPLETION_V1_ENCODED_LEN)?;
    let version = read_u16_le(bytes, 0);
    expect_version(ContractVersion(version))?;
    expect_encoded_len(read_u16_le(bytes, 2), TIDE_COMPLETION_V1_ENCODED_LEN_U16)?;
    if read_u16_le(bytes, 10) != 0 {
        return Err(ContractCodecError::NonZeroReserved {
            field: ContractReservedField::CompletionHeader,
        });
    }
    if read_u64_le(bytes, 88) != 0 {
        return Err(ContractCodecError::NonZeroReserved {
            field: ContractReservedField::CompletionTail,
        });
    }

    Ok(TideCompletion {
        version: ContractVersion(version),
        status: decode_completion_status(read_u16_le(bytes, 4))?,
        disposition: decode_completion_disposition(read_u16_le(bytes, 6))?,
        errno: Errno::from_raw(read_u16_le(bytes, 8)),
        result_flags: read_u32_le(bytes, 12),
        request_id: RequestId(read_array::<16>(bytes, 16)),
        trace_id: TraceId(read_array::<16>(bytes, 32)),
        epoch: ContractEpoch(read_u64_le(bytes, 48)),
        completed_bytes: read_u64_le(bytes, 56),
        result_words: [
            read_u64_le(bytes, 64),
            read_u64_le(bytes, 72),
            read_u64_le(bytes, 80),
        ],
    })
}

/// Check the embedded v1 golden vectors and reserved-field rejection paths.
///
/// # Errors
///
/// Returns [`ContractCodecError`] when a golden vector changes, fails to
/// decode, or accepts a non-zero reserved field.
pub fn contract_codec_self_check() -> Result<(), ContractCodecError> {
    let request = golden_request_envelope_v1();
    let mut request_buf = [0_u8; REQUEST_ENVELOPE_V1_ENCODED_LEN];
    encode_request_envelope_v1_le(&request, &mut request_buf)?;
    if request_buf != GOLDEN_REQUEST_ENVELOPE_V1 {
        return Err(ContractCodecError::GoldenVectorMismatch {
            vector: ContractGoldenVector::RequestEnvelopeV1,
        });
    }
    if decode_request_envelope_v1_le(&GOLDEN_REQUEST_ENVELOPE_V1)? != request {
        return Err(ContractCodecError::GoldenVectorMismatch {
            vector: ContractGoldenVector::RequestEnvelopeV1,
        });
    }

    let mut corrupt_request = GOLDEN_REQUEST_ENVELOPE_V1;
    corrupt_request[120] = 1;
    match decode_request_envelope_v1_le(&corrupt_request) {
        Err(ContractCodecError::NonZeroReserved {
            field: ContractReservedField::RequestEnvelopeTail,
        }) => {}
        _ => {
            return Err(ContractCodecError::GoldenVectorMismatch {
                vector: ContractGoldenVector::RequestReservedFailure,
            });
        }
    }

    let completion = golden_tide_completion_v1();
    let mut completion_buf = [0_u8; TIDE_COMPLETION_V1_ENCODED_LEN];
    encode_tide_completion_v1_le(&completion, &mut completion_buf)?;
    if completion_buf != GOLDEN_TIDE_COMPLETION_V1 {
        return Err(ContractCodecError::GoldenVectorMismatch {
            vector: ContractGoldenVector::TideCompletionV1,
        });
    }
    if decode_tide_completion_v1_le(&GOLDEN_TIDE_COMPLETION_V1)? != completion {
        return Err(ContractCodecError::GoldenVectorMismatch {
            vector: ContractGoldenVector::TideCompletionV1,
        });
    }

    let mut corrupt_completion = GOLDEN_TIDE_COMPLETION_V1;
    corrupt_completion[88] = 1;
    match decode_tide_completion_v1_le(&corrupt_completion) {
        Err(ContractCodecError::NonZeroReserved {
            field: ContractReservedField::CompletionTail,
        }) => {}
        _ => {
            return Err(ContractCodecError::GoldenVectorMismatch {
                vector: ContractGoldenVector::CompletionReservedFailure,
            });
        }
    }

    Ok(())
}

fn expect_len(actual_len: usize, expected_len: usize) -> Result<(), ContractCodecError> {
    if actual_len == expected_len {
        Ok(())
    } else {
        Err(ContractCodecError::Length {
            expected_len,
            actual_len,
        })
    }
}

fn expect_version(version: ContractVersion) -> Result<(), ContractCodecError> {
    if version == TIDE_CONTRACT_VERSION_V1 {
        Ok(())
    } else {
        Err(ContractCodecError::UnsupportedVersion {
            version: version.raw(),
        })
    }
}

fn expect_encoded_len(actual_len: u16, expected_len: u16) -> Result<(), ContractCodecError> {
    if actual_len == expected_len {
        Ok(())
    } else {
        Err(ContractCodecError::InvalidEncodedLen {
            expected_len,
            actual_len,
        })
    }
}

fn decode_work_class(value: u16) -> Result<WorkClass, ContractCodecError> {
    WorkClass::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::WorkClass,
        value,
    })
}

fn decode_admission_intent(value: u16) -> Result<AdmissionIntent, ContractCodecError> {
    AdmissionIntent::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::AdmissionIntent,
        value,
    })
}

fn decode_budget_intent(value: u16) -> Result<BudgetIntent, ContractCodecError> {
    BudgetIntent::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::BudgetIntent,
        value,
    })
}

fn decode_fence_intent(value: u16) -> Result<FenceIntent, ContractCodecError> {
    FenceIntent::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::FenceIntent,
        value,
    })
}

fn decode_retry_intent(value: u16) -> Result<RetryIntent, ContractCodecError> {
    RetryIntent::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::RetryIntent,
        value,
    })
}

fn decode_disposition_intent(value: u16) -> Result<DispositionIntent, ContractCodecError> {
    DispositionIntent::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::DispositionIntent,
        value,
    })
}

fn decode_completion_status(value: u16) -> Result<CompletionStatus, ContractCodecError> {
    CompletionStatus::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::CompletionStatus,
        value,
    })
}

fn decode_completion_disposition(value: u16) -> Result<CompletionDisposition, ContractCodecError> {
    CompletionDisposition::from_u16(value).ok_or(ContractCodecError::UnknownTag {
        field: ContractTagField::CompletionDisposition,
        value,
    })
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

fn write_payload_words(out: &mut [u8], offset: usize, words: ContractPayloadWords) {
    write_u64_le(out, offset, words[0]);
    write_u64_le(out, offset + 8, words[1]);
    write_u64_le(out, offset + 16, words[2]);
    write_u64_le(out, offset + 24, words[3]);
    write_u64_le(out, offset + 32, words[4]);
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    let mut buf = [0_u8; 2];
    buf.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(buf)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0_u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes[offset..offset + N]);
    out
}

fn read_payload_words(bytes: &[u8], offset: usize) -> ContractPayloadWords {
    [
        read_u64_le(bytes, offset),
        read_u64_le(bytes, offset + 8),
        read_u64_le(bytes, offset + 16),
        read_u64_le(bytes, offset + 24),
        read_u64_le(bytes, offset + 32),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_vfs_core::VfsNameToken;

    #[test]
    fn request_envelope_golden_vector_matches() {
        let request = golden_request_envelope_v1();
        let mut buf = [0_u8; REQUEST_ENVELOPE_V1_ENCODED_LEN];
        encode_request_envelope_v1_le(&request, &mut buf).expect("encode");
        assert_eq!(buf, GOLDEN_REQUEST_ENVELOPE_V1);
        assert_eq!(
            decode_request_envelope_v1_le(&buf).expect("decode"),
            request
        );
    }

    #[test]
    fn completion_golden_vector_matches() {
        let completion = golden_tide_completion_v1();
        let mut buf = [0_u8; TIDE_COMPLETION_V1_ENCODED_LEN];
        encode_tide_completion_v1_le(&completion, &mut buf).expect("encode");
        assert_eq!(buf, GOLDEN_TIDE_COMPLETION_V1);
        assert_eq!(
            decode_tide_completion_v1_le(&buf).expect("decode"),
            completion
        );
    }

    #[test]
    fn version_and_length_are_checked() {
        let mut buf = GOLDEN_REQUEST_ENVELOPE_V1;
        buf[0] = 2;
        assert_eq!(
            decode_request_envelope_v1_le(&buf),
            Err(ContractCodecError::UnsupportedVersion { version: 2 })
        );

        let mut buf = GOLDEN_REQUEST_ENVELOPE_V1;
        buf[2] = 127;
        assert_eq!(
            decode_request_envelope_v1_le(&buf),
            Err(ContractCodecError::InvalidEncodedLen {
                expected_len: REQUEST_ENVELOPE_V1_ENCODED_LEN_U16,
                actual_len: 127,
            })
        );

        assert_eq!(
            decode_request_envelope_v1_le(&GOLDEN_REQUEST_ENVELOPE_V1[..127]),
            Err(ContractCodecError::Length {
                expected_len: REQUEST_ENVELOPE_V1_ENCODED_LEN,
                actual_len: 127,
            })
        );
    }

    #[test]
    fn request_reserved_tail_is_rejected() {
        let mut buf = GOLDEN_REQUEST_ENVELOPE_V1;
        buf[120] = 1;
        assert_eq!(
            decode_request_envelope_v1_le(&buf),
            Err(ContractCodecError::NonZeroReserved {
                field: ContractReservedField::RequestEnvelopeTail,
            })
        );
    }

    #[test]
    fn completion_reserved_fields_are_rejected() {
        let mut buf = GOLDEN_TIDE_COMPLETION_V1;
        buf[10] = 1;
        assert_eq!(
            decode_tide_completion_v1_le(&buf),
            Err(ContractCodecError::NonZeroReserved {
                field: ContractReservedField::CompletionHeader,
            })
        );

        let mut buf = GOLDEN_TIDE_COMPLETION_V1;
        buf[88] = 1;
        assert_eq!(
            decode_tide_completion_v1_le(&buf),
            Err(ContractCodecError::NonZeroReserved {
                field: ContractReservedField::CompletionTail,
            })
        );
    }

    #[test]
    fn unknown_metadata_tags_are_rejected() {
        let mut buf = GOLDEN_REQUEST_ENVELOPE_V1;
        buf[8] = 99;
        assert_eq!(
            decode_request_envelope_v1_le(&buf),
            Err(ContractCodecError::UnknownTag {
                field: ContractTagField::WorkClass,
                value: 99,
            })
        );

        let mut buf = GOLDEN_TIDE_COMPLETION_V1;
        buf[4] = 99;
        assert_eq!(
            decode_tide_completion_v1_le(&buf),
            Err(ContractCodecError::UnknownTag {
                field: ContractTagField::CompletionStatus,
                value: 99,
            })
        );
    }

    #[test]
    fn unknown_request_operation_decodes_as_explicit_unsupported() {
        let mut buf = GOLDEN_REQUEST_ENVELOPE_V1;
        buf[6] = 99;
        let decoded = decode_request_envelope_v1_le(&buf).expect("decode");
        assert!(matches!(
            decoded.request,
            TideRequest::Vfs(VfsRequest::Unsupported { opcode: 99, .. })
        ));
    }

    #[test]
    fn namespace_request_operations_round_trip_fixed_words() {
        let old_name = VfsNameToken::from_component_bytes(b"old");
        let new_name = VfsNameToken::from_component_bytes(b"new");
        let cases = [
            (
                VfsRequest::Create {
                    parent_id: InodeId::new(10),
                    name: old_name,
                },
                5_u16,
                [10, old_name.raw(), 0, 0, 0],
            ),
            (
                VfsRequest::Mkdir {
                    parent_id: InodeId::new(11),
                    name: old_name,
                },
                6_u16,
                [11, old_name.raw(), 0, 0, 0],
            ),
            (
                VfsRequest::Rename {
                    old_parent_id: InodeId::new(12),
                    old_name,
                    new_parent_id: InodeId::new(13),
                    new_name,
                },
                7_u16,
                [12, old_name.raw(), 13, new_name.raw(), 0],
            ),
            (
                VfsRequest::Link {
                    source_inode_id: InodeId::new(14),
                    target_parent_id: InodeId::new(15),
                    target_name: new_name,
                },
                8_u16,
                [14, 15, new_name.raw(), 0, 0],
            ),
            (
                VfsRequest::Unlink {
                    parent_id: InodeId::new(16),
                    name: old_name,
                },
                9_u16,
                [16, old_name.raw(), 0, 0, 0],
            ),
            (
                VfsRequest::Truncate {
                    inode_id: InodeId::new(17),
                    size: 4096,
                },
                10_u16,
                [17, 4096, 0, 0, 0],
            ),
        ];

        for (request, expected_opcode, expected_words) in cases {
            let envelope = RequestEnvelope::new(
                RequestMetadata::new(
                    RequestId::new([3; 16]),
                    ContractEpoch::new(9),
                    TraceId::new([4; 16]),
                ),
                TideRequest::Vfs(request),
            );
            let mut buf = [0_u8; REQUEST_ENVELOPE_V1_ENCODED_LEN];
            encode_request_envelope_v1_le(&envelope, &mut buf).expect("encode");

            assert_eq!(read_u16_le(&buf, 4), 1);
            assert_eq!(read_u16_le(&buf, 6), expected_opcode);
            assert_eq!(read_payload_words(&buf, 80), expected_words);
            assert_eq!(
                decode_request_envelope_v1_le(&buf).expect("decode"),
                envelope
            );
        }
    }

    #[test]
    fn self_check_covers_golden_and_reserved_paths() {
        contract_codec_self_check().expect("self check");
    }
}
