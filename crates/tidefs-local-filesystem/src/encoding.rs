use std::collections::{BTreeMap, BTreeSet};

use tidefs_local_object_store::{checksum64, IntegrityDigest64, ObjectKey};
use tidefs_types_vfs_core::{Generation, InodeId, NodeKind};

use crate::constants::*;
use crate::error::FileSystemError;
use crate::helpers::{kind_bits, validate_name, validate_snapshot_name};
use crate::records::SnapshotKind;
use crate::types::*;
use crate::Result;
use crate::{
    ContentChunkObject, ContentChunkRef, ContentManifestObject, ContentObject, RootCommitRecord,
    SnapshotRecord, SuperblockRecord,
};
use tidefs_types_polymorphic_xattr_core::{XATTR_BTREE_ROOT_MAGIC, XATTR_BUNDLE_MAGIC};

pub(crate) fn root_authentication_digest(domain: &[u8], bytes: &[u8]) -> RootAuthenticationDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    RootAuthenticationDigest::from_bytes32(*hasher.finalize().as_bytes())
}

pub(crate) fn root_authentication_record_for_bytes(
    superblock_bytes: &[u8],
    manifest_bytes: Option<&[u8]>,
) -> RootAuthenticationRecord {
    RootAuthenticationRecord {
        record_version: ROOT_AUTHENTICATION_RECORD_VERSION,
        algorithm_suite_id: ROOT_AUTHENTICATION_ALGORITHM_SUITE_ID,
        policy_epoch: ROOT_AUTHENTICATION_POLICY_EPOCH,
        superblock_digest: root_authentication_digest(
            ROOT_AUTHENTICATION_SUPERBLOCK_DOMAIN,
            superblock_bytes,
        ),
        manifest_digest: manifest_bytes
            .map(|bytes| root_authentication_digest(ROOT_AUTHENTICATION_MANIFEST_DOMAIN, bytes))
            .unwrap_or(RootAuthenticationDigest::ZERO),
        authentication_code: RootAuthenticationCode::ZERO,
    }
}

pub(crate) fn root_authentication_code(
    root: &RootCommitRecord,
    authentication: &RootAuthenticationRecord,
    key: RootAuthenticationKey,
) -> RootAuthenticationCode {
    let mut hasher = blake3::Hasher::new_keyed(&key.as_bytes32());
    hasher.update(ROOT_AUTHENTICATION_ROOT_DOMAIN);
    hasher.update(&FILESYSTEM_FORMAT_VERSION.to_le_bytes());
    hasher.update(&authentication.record_version.to_le_bytes());
    hasher.update(&authentication.algorithm_suite_id.to_le_bytes());
    hasher.update(&authentication.policy_epoch.to_le_bytes());
    hasher.update(&root.slot.to_le_bytes());
    hasher.update(&root.transaction_id.to_le_bytes());
    hasher.update(&root.generation.to_le_bytes());
    hasher.update(&root.next_inode_id.to_le_bytes());
    hasher.update(&root.inode_count.to_le_bytes());
    hasher.update(&root.superblock_checksum.get().to_le_bytes());
    hasher.update(&root.manifest_checksum.get().to_le_bytes());
    hasher.update(&root.manifest_entry_count.to_le_bytes());
    hasher.update(&authentication.superblock_digest.as_bytes32());
    hasher.update(&authentication.manifest_digest.as_bytes32());
    RootAuthenticationCode::from_bytes32(*hasher.finalize().as_bytes())
}

pub(crate) fn sign_root_commit(
    root: &RootCommitRecord,
    key: RootAuthenticationKey,
) -> Result<RootCommitRecord> {
    let mut signed = root.clone();
    let mut authentication = signed
        .root_authentication
        .ok_or(FileSystemError::CorruptState {
            reason: "root commit cannot be published without root authentication digests",
        })?;
    authentication.authentication_code = root_authentication_code(&signed, &authentication, key);
    signed.root_authentication = Some(authentication);
    Ok(signed)
}

pub(crate) fn validate_root_authentication_record(
    root: &RootCommitRecord,
    key: RootAuthenticationKey,
) -> Result<RootAuthenticationRecord> {
    let authentication = root
        .root_authentication
        .ok_or(FileSystemError::CorruptState {
            reason: "root commit is missing a root authentication record",
        })?;
    if authentication.record_version != ROOT_AUTHENTICATION_RECORD_VERSION {
        return Err(FileSystemError::CorruptState {
            reason: "root authentication record version is not supported",
        });
    }
    if authentication.algorithm_suite_id != ROOT_AUTHENTICATION_ALGORITHM_SUITE_ID {
        return Err(FileSystemError::CorruptState {
            reason: "root authentication algorithm suite is not supported",
        });
    }
    if authentication.policy_epoch != ROOT_AUTHENTICATION_POLICY_EPOCH {
        return Err(FileSystemError::CorruptState {
            reason: "root authentication policy epoch is not supported",
        });
    }
    let expected = root_authentication_code(root, &authentication, key);
    if expected != authentication.authentication_code {
        return Err(FileSystemError::CorruptState {
            reason: "root authentication code does not validate root commit",
        });
    }
    Ok(authentication)
}

pub(crate) fn encode_root_commit(root: &RootCommitRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ROOT_COMMIT_MAGIC);
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);
    push_u16(&mut out, ROOT_COMMIT_RESERVED);
    push_u64(&mut out, root.slot);
    push_u64(&mut out, root.transaction_id);
    push_u64(&mut out, root.generation);
    push_u64(&mut out, root.next_inode_id);
    push_u64(&mut out, root.inode_count);
    push_u64(&mut out, root.superblock_checksum.get());
    push_u64(&mut out, root.manifest_checksum.get());
    push_u64(&mut out, root.manifest_entry_count);
    if let Some(authentication) = root.root_authentication {
        out.extend_from_slice(&ROOT_AUTHENTICATION_MAGIC);
        push_u16(&mut out, authentication.record_version);
        push_u16(&mut out, authentication.algorithm_suite_id);
        push_u64(&mut out, authentication.policy_epoch);
        out.extend_from_slice(&authentication.superblock_digest.as_bytes32());
        out.extend_from_slice(&authentication.manifest_digest.as_bytes32());
        out.extend_from_slice(&authentication.authentication_code.as_bytes32());
    }
    out
}

pub(crate) fn decode_root_commit(bytes: &[u8]) -> Result<RootCommitRecord> {
    let mut decoder = Decoder::new("local filesystem root commit", bytes);
    decoder.expect_magic(ROOT_COMMIT_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem root commit",
            reason: "unsupported format version",
        });
    }
    if decoder.read_u16()? != ROOT_COMMIT_RESERVED {
        return Err(FileSystemError::Decode {
            object: "local filesystem root commit",
            reason: "reserved field is non-zero",
        });
    }
    let slot = decoder.read_u64()?;
    if slot >= FILESYSTEM_ROOT_SLOT_COUNT {
        return Err(FileSystemError::Decode {
            object: "local filesystem root commit",
            reason: "root slot is outside the root-slot ring",
        });
    }
    let transaction_id = decoder.read_u64()?;
    let generation = decoder.read_u64()?;
    let next_inode_id = decoder.read_u64()?;
    let inode_count = decoder.read_u64()?;
    let superblock_checksum = IntegrityDigest64(decoder.read_u64()?);
    let (manifest_checksum, manifest_entry_count, root_authentication) = if decoder.is_finished() {
        (IntegrityDigest64::ZERO, 0, None)
    } else {
        let manifest_checksum = IntegrityDigest64(decoder.read_u64()?);
        let manifest_entry_count = decoder.read_u64()?;
        let root_authentication = if decoder.is_finished() {
            None
        } else {
            decoder.expect_magic(ROOT_AUTHENTICATION_MAGIC)?;
            let record_version = decoder.read_u16()?;
            let algorithm_suite_id = decoder.read_u16()?;
            let policy_epoch = decoder.read_u64()?;
            let superblock_digest = digest_from_decoder(&mut decoder)?;
            let manifest_digest = digest_from_decoder(&mut decoder)?;
            let authentication_code = root_authentication_code_from_decoder(&mut decoder)?;
            Some(RootAuthenticationRecord {
                record_version,
                algorithm_suite_id,
                policy_epoch,
                superblock_digest,
                manifest_digest,
                authentication_code,
            })
        };
        (manifest_checksum, manifest_entry_count, root_authentication)
    };
    decoder.finish()?;
    Ok(RootCommitRecord {
        slot,
        transaction_id,
        generation,
        next_inode_id,
        inode_count,
        superblock_checksum,
        manifest_checksum,
        manifest_entry_count,
        root_authentication,
    })
}

pub(crate) fn digest_from_decoder(decoder: &mut Decoder<'_>) -> Result<RootAuthenticationDigest> {
    let bytes = decoder.read_bytes(ROOT_AUTHENTICATION_DIGEST_LEN)?;
    let mut out = [0_u8; ROOT_AUTHENTICATION_DIGEST_LEN];
    out.copy_from_slice(bytes);
    Ok(RootAuthenticationDigest::from_bytes32(out))
}

pub(crate) fn root_authentication_code_from_decoder(
    decoder: &mut Decoder<'_>,
) -> Result<RootAuthenticationCode> {
    let bytes = decoder.read_bytes(ROOT_AUTHENTICATION_CODE_LEN)?;
    let mut out = [0_u8; ROOT_AUTHENTICATION_CODE_LEN];
    out.copy_from_slice(bytes);
    Ok(RootAuthenticationCode::from_bytes32(out))
}

pub(crate) fn encode_transaction_manifest(manifest: &TransactionManifestRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TRANSACTION_MANIFEST_MAGIC);
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);
    push_u16(&mut out, 0); // reserved
    push_u64(&mut out, manifest.transaction_id);
    push_u64(&mut out, manifest.generation);
    push_u64(&mut out, manifest.entries.len() as u64);
    for entry in &manifest.entries {
        push_u16(&mut out, entry.role.as_u16());
        push_u16(&mut out, 0); // reserved
        out.extend_from_slice(&entry.object_key.as_bytes32());
        push_u64(&mut out, entry.checksum.get());
    }
    out
}

pub(crate) fn decode_transaction_manifest(bytes: &[u8]) -> Result<TransactionManifestRecord> {
    let mut decoder = Decoder::new("local filesystem transaction manifest", bytes);
    decoder.expect_magic(TRANSACTION_MANIFEST_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem transaction manifest",
            reason: "unsupported format version",
        });
    }
    if decoder.read_u16()? != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem transaction manifest",
            reason: "reserved field is non-zero",
        });
    }
    let transaction_id = decoder.read_u64()?;
    let generation = decoder.read_u64()?;
    let max_entries = decoder.remaining() / 44; // u16+u16+ObjectKey(32)+u64 per entry
    let count = decoder.read_count_bounded(max_entries)?;
    let mut entries = Vec::with_capacity(count);
    let mut seen_keys = BTreeSet::new();
    for _ in 0..count {
        let raw_role = decoder.read_u16()?;
        let role = TransactionManifestObjectRole::try_from(raw_role).map_err(|_| {
            FileSystemError::Decode {
                object: "local filesystem transaction manifest",
                reason: "unknown manifest object role",
            }
        })?;
        if decoder.read_u16()? != 0 {
            return Err(FileSystemError::Decode {
                object: "local filesystem transaction manifest",
                reason: "reserved entry field is non-zero",
            });
        }
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(decoder.read_bytes(32)?);
        let object_key = ObjectKey::from_bytes32(key_bytes);
        if !seen_keys.insert(object_key) {
            return Err(FileSystemError::Decode {
                object: "local filesystem transaction manifest",
                reason: "duplicate manifest object key",
            });
        }
        let checksum = IntegrityDigest64(decoder.read_u64()?);
        entries.push(TransactionManifestEntry {
            role,
            object_key,
            checksum,
        });
    }
    decoder.finish()?;
    Ok(TransactionManifestRecord {
        transaction_id,
        generation,
        entries,
    })
}

pub(crate) fn encode_snapshot_record(snapshot: &SnapshotRecord) -> Vec<u8> {
    let mut out = Vec::new();
    push_u32(&mut out, snapshot.name.len() as u32);
    out.extend_from_slice(&snapshot.name);
    push_u64(&mut out, snapshot.created_at_generation);
    encode_committed_root_summary(&mut out, &snapshot.root);
    out.extend_from_slice(&SNAPSHOT_RECORD_V2_MAGIC_BYTES);
    push_u16(&mut out, snapshot.kind as u16);
    if let Some(ref origin) = snapshot.origin {
        push_u16(&mut out, 1);
        push_u32(&mut out, origin.len() as u32);
        out.extend_from_slice(origin);
    } else {
        push_u16(&mut out, 0); // reserved
    }
    push_u32(&mut out, snapshot.hold_count);
    out
}

pub(crate) fn decode_snapshot_record(bytes: &[u8]) -> Result<SnapshotRecord> {
    let mut decoder = Decoder::new("snapshot record", bytes);
    let name_len = decoder.read_name_len()?;
    let name = decoder.read_bytes(name_len)?.to_vec();
    validate_snapshot_name(&name)?;
    let created_at_generation = decoder.read_u64()?;
    let root = decode_committed_root_summary(&mut decoder)?;
    let (kind, origin, hold_count) = if decoder.try_peek_magic(SNAPSHOT_RECORD_V2_MAGIC_BYTES) {
        decoder.expect_magic(SNAPSHOT_RECORD_V2_MAGIC_BYTES)?;
        let kind_val = decoder.read_u16()?;
        let kind = match kind_val {
            0 => SnapshotKind::Snapshot,
            1 => SnapshotKind::Clone,
            2 => SnapshotKind::Bookmark,
            _ => SnapshotKind::Snapshot,
        };
        let origin = if decoder.read_u16()? == 1 {
            let origin_len = decoder.read_u32()? as usize;
            Some(decoder.read_bytes(origin_len)?.to_vec())
        } else {
            None
        };
        let hold_count = decoder.read_u32()?;
        (kind, origin, hold_count)
    } else {
        (SnapshotKind::Snapshot, None, 0)
    };
    decoder.finish()?;
    Ok(SnapshotRecord {
        name,
        root,
        created_at_generation,
        kind,
        origin,
        hold_count,
    })
}

pub(crate) fn encode_superblock(superblock: &SuperblockRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SUPERBLOCK_MAGIC);
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);
    push_u16(&mut out, 0); // reserved
    push_u64(&mut out, superblock.next_inode_id);
    push_u64(&mut out, superblock.generation);
    push_u64(&mut out, superblock.inode_count);
    push_u64(&mut out, superblock.inode_allocation_bitmap.len() as u64);
    for word in &superblock.inode_allocation_bitmap {
        push_u64(&mut out, *word);
    }
    // Format-version-range extension (always written for v2+).
    out.extend_from_slice(&FORMAT_VERSION_EXTENSION_MAGIC_BYTES);
    push_u16(&mut out, superblock.format_version_min);
    push_u16(&mut out, superblock.format_version_max);
    out
}

pub(crate) fn decode_superblock(
    bytes: &[u8],
) -> Result<(SuperblockRecord, Option<Vec<SnapshotRecord>>)> {
    let mut decoder = Decoder::new("local filesystem superblock", bytes);
    decoder.expect_magic(SUPERBLOCK_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem superblock",
            reason: "unsupported format version",
        });
    }
    if decoder.read_u16()? != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem superblock",
            reason: "reserved field is non-zero",
        });
    }
    let next_inode_id = decoder.read_u64()?;
    let generation = decoder.read_u64()?;
    let inode_count = decoder.read_u64()?;
    let max_bitmap_words = decoder.remaining() / 8; // u64 per word
    let bitmap_word_count = decoder.read_count_bounded(max_bitmap_words)?;
    let mut inode_allocation_bitmap = Vec::with_capacity(bitmap_word_count);
    for _ in 0..bitmap_word_count {
        inode_allocation_bitmap.push(decoder.read_u64()?);
    }
    // v3+: snapshots are stored as separate transaction objects, not in the superblock.
    // Embedded snapshot catalogs in v1-v2 legacy superblocks are not supported;
    // TideFS has no public release, so there is no legacy data to decode.
    let legacy_snapshots: Option<Vec<SnapshotRecord>> = None;
    // Format-version-range extension (required for current format version).
    let (format_version_min, format_version_max) =
        if decoder.try_peek_magic(FORMAT_VERSION_EXTENSION_MAGIC_BYTES) {
            decoder.expect_magic(FORMAT_VERSION_EXTENSION_MAGIC_BYTES)?;
            (decoder.read_u16()?, decoder.read_u16()?)
        } else {
            return Err(FileSystemError::Decode {
                object: "local filesystem superblock",
                reason: "missing format-version-range extension",
            });
        };
    decoder.finish()?;
    Ok((
        SuperblockRecord {
            next_inode_id,
            generation,
            inode_count,
            inode_allocation_bitmap,
            format_version_min,
            format_version_max,
        },
        legacy_snapshots,
    ))
}

pub(crate) fn encode_committed_root_summary(out: &mut Vec<u8>, summary: &CommittedRootSummary) {
    push_u64(out, summary.slot);
    push_u64(out, summary.transaction_id);
    push_u64(out, summary.generation);
    push_u64(out, summary.next_inode_id);
    push_u64(out, summary.inode_count);
    push_u64(out, summary.superblock_checksum.get());
    push_u16(
        out,
        if summary.has_transaction_manifest {
            1
        } else {
            0
        },
    );
    push_u16(out, 0);
    push_u64(out, summary.manifest_checksum.get());
    push_u64(out, summary.manifest_entry_count);
    push_u16(
        out,
        if summary.has_root_authentication {
            1
        } else {
            0
        },
    );
    push_u16(
        out,
        summary.root_authentication_algorithm_suite_id.unwrap_or(0),
    );
    push_u64(out, summary.root_authentication_policy_epoch.unwrap_or(0));
    out.extend_from_slice(
        &summary
            .superblock_digest
            .unwrap_or(RootAuthenticationDigest::ZERO)
            .as_bytes32(),
    );
    out.extend_from_slice(
        &summary
            .manifest_digest
            .unwrap_or(RootAuthenticationDigest::ZERO)
            .as_bytes32(),
    );
    out.extend_from_slice(
        &summary
            .root_authentication_code
            .unwrap_or(RootAuthenticationCode::ZERO)
            .as_bytes32(),
    );
}

pub(crate) fn decode_committed_root_summary(
    decoder: &mut Decoder<'_>,
) -> Result<CommittedRootSummary> {
    let slot = decoder.read_u64()?;
    let transaction_id = decoder.read_u64()?;
    let generation = decoder.read_u64()?;
    let next_inode_id = decoder.read_u64()?;
    let inode_count = decoder.read_u64()?;
    let superblock_checksum = IntegrityDigest64(decoder.read_u64()?);
    let has_transaction_manifest = match decoder.read_u16()? {
        0 => false,
        1 => true,
        _ => {
            return Err(FileSystemError::Decode {
                object: "local filesystem superblock snapshot",
                reason: "invalid transaction-manifest flag",
            })
        }
    };
    if decoder.read_u16()? != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem superblock snapshot",
            reason: "reserved snapshot-root field is non-zero",
        });
    }
    let manifest_checksum = IntegrityDigest64(decoder.read_u64()?);
    let manifest_entry_count = decoder.read_u64()?;
    let has_root_authentication = match decoder.read_u16()? {
        0 => false,
        1 => true,
        _ => {
            return Err(FileSystemError::Decode {
                object: "local filesystem superblock snapshot",
                reason: "invalid root-authentication flag",
            })
        }
    };
    let algorithm_suite_id = decoder.read_u16()?;
    let policy_epoch = decoder.read_u64()?;
    let superblock_digest = digest_from_decoder(decoder)?;
    let manifest_digest = digest_from_decoder(decoder)?;
    let authentication_code = root_authentication_code_from_decoder(decoder)?;
    Ok(CommittedRootSummary {
        slot,
        transaction_id,
        generation,
        next_inode_id,
        inode_count,
        superblock_checksum,
        has_transaction_manifest,
        manifest_checksum,
        manifest_entry_count,
        has_root_authentication,
        root_authentication_policy_epoch: has_root_authentication.then_some(policy_epoch),
        root_authentication_algorithm_suite_id: has_root_authentication
            .then_some(algorithm_suite_id),
        superblock_digest: has_root_authentication.then_some(superblock_digest),
        manifest_digest: has_root_authentication.then_some(manifest_digest),
        root_authentication_code: has_root_authentication.then_some(authentication_code),
    })
}

pub(crate) fn encode_changed_record_export(export: &ChangedRecordExport) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SEND_RECEIVE_STREAM_MAGIC_BYTES);
    // stream_version encoding:
    //   full:     1 (none), 3 (with placement_epoch)
    //   incremental: 2 (none), 4 (with placement_epoch)
    let base_version: u16 = if export.incremental { 2 } else { 1 };
    let stream_version: u16 = if export.placement_epoch.is_some() {
        base_version + 2
    } else {
        base_version
    };
    push_u16(&mut out, stream_version);
    push_u16(&mut out, 0); // reserved
    encode_committed_root_summary(&mut out, &export.current_root);
    // For incremental streams (version >= 2), encode the baseline root.
    if let Some(ref from_root) = export.from_root {
        encode_committed_root_summary(&mut out, from_root);
    }
    // For placement-epoch streams (version >= 3), encode the epoch.
    if let Some(epoch) = export.placement_epoch {
        push_u64(&mut out, epoch);
    }
    push_u64(&mut out, export.roots.len() as u64);
    for root in &export.roots {
        encode_committed_root_summary(&mut out, &root.source_root);
        push_u64(&mut out, root.records.len() as u64);
        for record in &root.records {
            push_u16(&mut out, record.role.as_u16());
            push_u16(&mut out, 0); // reserved
            out.extend_from_slice(&record.object_key.as_bytes32());
            push_u64(&mut out, record.checksum.get());
            push_u64(&mut out, record.payload.len() as u64);
            out.extend_from_slice(&record.payload);
        }
    }
    out
}

pub(crate) fn decode_changed_record_export(bytes: &[u8]) -> Result<ChangedRecordExport> {
    let mut decoder = Decoder::new("local filesystem send/receive stream", bytes);
    decoder.expect_magic(SEND_RECEIVE_STREAM_MAGIC_BYTES)?;
    let stream_version = decoder.read_u16()?;
    if decoder.read_u16()? != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive stream",
            reason: "reserved field is non-zero",
        });
    }
    let current_root = decode_committed_root_summary(&mut decoder)?;
    // Decode optional from_root (versions 2 and 4 are incremental).
    let from_root = if stream_version == 2 || stream_version == 4 {
        Some(decode_committed_root_summary(&mut decoder)?)
    } else {
        None
    };
    // Decode optional placement_epoch (versions 3 and 4 carry it).
    let placement_epoch = if stream_version >= 3 {
        Some(decoder.read_u64()?)
    } else {
        None
    };
    let root_count = decoder.read_count()?;
    let mut roots = Vec::with_capacity(root_count);
    let mut total_records = 0_u64;
    let mut payload_bytes = 0_u64;
    for _ in 0..root_count {
        let source_root = decode_committed_root_summary(&mut decoder)?;
        let record_count = decoder.read_count()?;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let role = ChangedRecordObjectRole::try_from(decoder.read_u16()?).map_err(|_| {
                FileSystemError::Decode {
                    object: "local filesystem send/receive stream",
                    reason: "unknown changed-record role",
                }
            })?;
            if decoder.read_u16()? != 0 {
                return Err(FileSystemError::Decode {
                    object: "local filesystem send/receive stream",
                    reason: "reserved changed-record field is non-zero",
                });
            }
            let mut key_bytes = [0_u8; 32];
            key_bytes.copy_from_slice(decoder.read_bytes(32)?);
            let checksum = IntegrityDigest64(decoder.read_u64()?);
            let payload_len = decoder.read_count()?;
            let payload = decoder.read_bytes(payload_len)?.to_vec();
            payload_bytes = payload_bytes.checked_add(payload.len() as u64).ok_or(
                FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                },
            )?;
            total_records = total_records.saturating_add(1);
            records.push(ChangedObjectRecord {
                role,
                object_key: ObjectKey::from_bytes32(key_bytes),
                checksum,
                payload,
            });
        }
        roots.push(ChangedRecordRoot {
            source_root,
            records,
        });
    }
    decoder.finish()?;
    let incremental = from_root.is_some();
    Ok(ChangedRecordExport {
        spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
        stream_version,
        from_root,
        current_root,
        roots,
        total_records,
        payload_bytes,
        production_fsck_required: false,
        incremental,
        placement_epoch,
    })
}

// ── Polymorphic xattr encode/decode ────────────────────────────────────────

fn encode_xattr_bundle_v1(out: &mut Vec<u8>, xattrs: &BTreeMap<Vec<u8>, Vec<u8>>) {
    out.extend_from_slice(XATTR_BUNDLE_MAGIC);
    let entry_count = xattrs.len() as u16;
    let total_value_bytes: u32 = xattrs.values().map(|v| v.len() as u32).sum();
    push_u16(out, entry_count);
    push_u32(out, total_value_bytes);
    out.push(0); // flags
    out.extend_from_slice(&[0u8; 5]); // reserved
    for (name, value) in xattrs {
        push_u16(out, name.len() as u16);
        push_u32(out, value.len() as u32);
        out.extend_from_slice(name);
        out.extend_from_slice(value);
    }
}

fn decode_xattr_bundle_v1(decoder: &mut Decoder) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut magic = [0u8; 4];
    let magic_bytes = decoder.read_bytes(4)?;
    magic.copy_from_slice(magic_bytes);
    if magic != *XATTR_BUNDLE_MAGIC {
        return Err(FileSystemError::Decode {
            object: "XattrBundleV1",
            reason: "magic bytes do not match",
        });
    }
    let entry_count = decoder.read_u16()? as usize;
    let _total_value_bytes = decoder.read_u32()?;
    let _flags = decoder.read_u8()?;
    decoder.read_bytes(5)?; // reserved
    let mut xattrs = BTreeMap::new();
    for _ in 0..entry_count {
        let name_len = decoder.read_u16()? as usize;
        let value_len = decoder.read_u32()? as usize;
        let name = decoder.read_bytes(name_len)?.to_vec();
        let value = decoder.read_bytes(value_len)?.to_vec();
        xattrs.insert(name, value);
    }
    Ok(xattrs)
}

fn encode_xattr_btree_root_v1(out: &mut Vec<u8>, xattrs: &BTreeMap<Vec<u8>, Vec<u8>>) {
    out.extend_from_slice(XATTR_BTREE_ROOT_MAGIC);
    push_u64(out, xattrs.len() as u64);
    push_u64(out, xattrs.values().map(|v| v.len() as u64).sum());
    push_u64(out, 0); // root_page_locator (stub for Phase 1)
    out.push(0); // depth
    out.push(0); // flags
    out.extend_from_slice(&[0u8; 6]); // reserved
}

fn decode_xattr_btree_root_v1(decoder: &mut Decoder) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut magic = [0u8; 4];
    let magic_bytes = decoder.read_bytes(4)?;
    magic.copy_from_slice(magic_bytes);
    if magic != *XATTR_BTREE_ROOT_MAGIC {
        return Err(FileSystemError::Decode {
            object: "XattrBtreeRootV1",
            reason: "magic bytes do not match",
        });
    }
    let _entry_count = decoder.read_u64()?;
    let _total_value_bytes = decoder.read_u64()?;
    let _root_page_locator = decoder.read_u64()?;
    let _depth = decoder.read_u8()?;
    let _flags = decoder.read_u8()?;
    decoder.read_bytes(6)?; // reserved
                            // Phase 1: External xattrs return empty map (B-tree pages not yet traversable)
    Ok(BTreeMap::new())
}

pub(crate) fn encode_inode(inode: &InodeRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&INODE_MAGIC);
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);
    push_u16(&mut out, u16::from(inode.xattr_storage_kind));
    push_u64(&mut out, inode.inode_id.get());
    push_u64(&mut out, inode.generation.get());
    push_u32(&mut out, inode.kind().as_u32());
    push_u32(&mut out, inode.mode);
    push_u32(&mut out, inode.uid);
    push_u32(&mut out, inode.gid);
    push_u32(&mut out, inode.nlink);
    push_u32(&mut out, u32::from(inode.dir_storage_kind));
    push_u64(&mut out, inode.size);
    push_u64(&mut out, inode.data_version);
    push_u64(&mut out, inode.metadata_version);
    push_u32(&mut out, inode.rdev);
    push_i64(&mut out, inode.posix_time.atime_ns);
    push_i64(&mut out, inode.posix_time.mtime_ns);
    push_i64(&mut out, inode.posix_time.ctime_ns);
    push_i64(&mut out, inode.posix_time.btime_ns);
    match inode.xattr_storage_kind {
        0 => encode_xattr_bundle_v1(&mut out, &inode.xattrs),
        1 => encode_xattr_btree_root_v1(&mut out, &inode.xattrs),
        _ => encode_xattr_bundle_v1(&mut out, &inode.xattrs),
    }
    out
}

pub(crate) fn decode_inode(bytes: &[u8]) -> Result<InodeRecord> {
    let mut decoder = Decoder::new("local filesystem inode", bytes);
    decoder.expect_magic(INODE_MAGIC)?;
    let version = decoder.read_u16()?;
    if !(FORMAT_COMPAT_WINDOW_MIN..=FILESYSTEM_FORMAT_VERSION).contains(&version) {
        return Err(FileSystemError::Decode {
            object: "local filesystem inode",
            reason: "unsupported format version",
        });
    }
    let xattr_raw = decoder.read_u16()?;
    let xattr_storage_kind = (xattr_raw & 0xFF) as u8;
    if xattr_raw & !0xFFu16 != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem inode",
            reason: "reserved bytes in xattr_storage field are non-zero",
        });
    }
    let inode_id = InodeId::new(decoder.read_u64()?);
    let generation = Generation::new(decoder.read_u64()?);
    let kind_raw = decoder.read_u32()?;
    let kind = NodeKind::try_from(kind_raw).map_err(|_| FileSystemError::Decode {
        object: "local filesystem inode",
        reason: "unknown node kind",
    })?;
    let mode = decoder.read_u32()?;
    let uid = decoder.read_u32()?;
    let gid = decoder.read_u32()?;
    let nlink = decoder.read_u32()?;
    let dir_storage_raw = decoder.read_u32()?;
    let dir_storage_kind = (dir_storage_raw & 0xFF) as u8;
    if dir_storage_raw & !0xFFu32 != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem inode",
            reason: "reserved bytes in dir_storage field are non-zero",
        });
    }
    let size = decoder.read_u64()?;
    let data_version = decoder.read_u64()?;
    let metadata_version = decoder.read_u64()?;
    let rdev = if version >= 4 { decoder.read_u32()? } else { 0 };
    // Versions before 5 did not store explicit POSIX timestamps and
    // attempted to derive them from storage versions/generations.  That
    // authority shortcut has been removed; reject the old format.
    if version < 5 {
        return Err(FileSystemError::Decode {
            object: "local filesystem inode",
            reason: "format version below 5 lacks explicit POSIX timestamps; re-create with current format",
        });
    }
    let posix_time = PosixTimeRecord::new(
        decoder.read_i64()?,
        decoder.read_i64()?,
        decoder.read_i64()?,
        decoder.read_i64()?,
    );
    let xattrs = match xattr_storage_kind {
        0 => {
            // Try new bundle format first (magic XATB), fall back to old count-based format
            if decoder.bytes.len() - decoder.offset >= 4
                && &decoder.bytes[decoder.offset..decoder.offset + 4] == XATTR_BUNDLE_MAGIC
            {
                decode_xattr_bundle_v1(&mut decoder)?
            } else {
                decode_xattrs(&mut decoder)?
            }
        }
        1 => decode_xattr_btree_root_v1(&mut decoder)?,
        _ => {
            return Err(FileSystemError::Decode {
                object: "local filesystem inode",
                reason: "unknown xattr storage kind",
            })
        }
    };
    Ok(InodeRecord {
        inode_id,
        generation,
        facets: kind.to_facets(),
        mode,
        uid,
        gid,
        nlink,
        size,
        data_version,
        metadata_version,
        posix_time,
        xattrs,
        dir_storage_kind,
        xattr_storage_kind,
        dir_rev: 0,
        rdev,
    })
}

fn decode_xattrs(decoder: &mut Decoder) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let count = decoder.read_u32()? as usize;
    let mut xattrs = BTreeMap::new();
    for _ in 0..count {
        let name_len = decoder.read_u32()? as usize;
        let value_len = decoder.read_u32()? as usize;
        let name = decoder.read_bytes(name_len)?.to_vec();
        let value = decoder.read_bytes(value_len)?.to_vec();
        xattrs.insert(name, value);
    }
    Ok(xattrs)
}

pub(crate) fn encode_directory(
    inode: &InodeRecord,
    directory: &BTreeMap<Vec<u8>, NamespaceEntry>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&DIRECTORY_MAGIC);
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);
    push_u16(&mut out, 0); // reserved
    push_u64(&mut out, inode.inode_id.get());
    push_u64(&mut out, inode.metadata_version);
    push_u64(&mut out, directory.len() as u64);
    for entry in directory.values() {
        push_u32(&mut out, entry.name.len() as u32);
        out.extend_from_slice(&entry.name);
        push_u64(&mut out, entry.inode_id.get());
        push_u64(&mut out, entry.generation.get());
        push_u32(&mut out, entry.kind().as_u32());
    }
    out
}

pub(crate) fn decode_directory(bytes: &[u8]) -> Result<BTreeMap<Vec<u8>, NamespaceEntry>> {
    let mut decoder = Decoder::new("local filesystem directory", bytes);
    decoder.expect_magic(DIRECTORY_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem directory",
            reason: "unsupported format version",
        });
    }
    if decoder.read_u16()? != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem directory",
            reason: "reserved field is non-zero",
        });
    }
    let _directory_inode_id = decoder.read_u64()?;
    let _directory_version = decoder.read_u64()?;
    let count = decoder.read_count()?;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let name_len = decoder.read_name_len()?;
        let name = decoder.read_bytes(name_len)?.to_vec();
        validate_name(&name)?;
        let inode_id = InodeId::new(decoder.read_u64()?);
        let generation = Generation::new(decoder.read_u64()?);
        let kind_raw = decoder.read_u32()?;
        let kind = NodeKind::try_from(kind_raw).map_err(|_| FileSystemError::Decode {
            object: "local filesystem directory",
            reason: "unknown node kind",
        })?;
        let entry = NamespaceEntry {
            name: name.clone(),
            inode_id,
            generation,
            facets: kind.to_facets(),
            mode: kind_bits(kind),
        };
        if entries.insert(name, entry).is_some() {
            return Err(FileSystemError::Decode {
                object: "local filesystem directory",
                reason: "duplicate directory entry",
            });
        }
    }
    decoder.finish()?;
    Ok(entries)
}

/// Decode only the inode_id from a directory payload.
///
/// This is a fast-path extraction used during send/receive manifest
/// validation to map directory object keys to their owning inodes
/// without paying the cost of full directory decoding.
pub(crate) fn decode_directory_inode_id(bytes: &[u8]) -> Result<InodeId> {
    let mut decoder = Decoder::new("local filesystem directory (inode_id only)", bytes);
    decoder.expect_magic(DIRECTORY_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem directory",
            reason: "unsupported format version",
        });
    }
    let _reserved = decoder.read_u16()?;
    let directory_inode_id_value = decoder.read_u64()?;
    let _directory_version = decoder.read_u64()?;
    Ok(InodeId::new(directory_inode_id_value))
}

/// Split inline content bytes into body and optional checksum.
///
/// If the encoding version in the header is >= 1, the last 8 bytes are a
/// checksum covering all preceding bytes.
pub(crate) fn split_inline_checksum(bytes: &[u8]) -> Result<(&[u8], Option<IntegrityDigest64>)> {
    // Need at least 12 bytes to inspect the encoding version:
    // 8 (magic) + 2 (format version) + 2 (encoding version)
    if bytes.len() < 12 {
        return Ok((bytes, None));
    }
    let encoding_version = u16::from_le_bytes([bytes[10], bytes[11]]);
    if encoding_version == 0 {
        return Ok((bytes, None));
    }
    if bytes.len() < 20 {
        return Err(FileSystemError::Decode {
            object: "local filesystem content",
            reason: "record too short for checksum suffix",
        });
    }
    let split = bytes.len() - 8;
    let body = &bytes[..split];
    let checksum_raw: [u8; 8] = bytes[split..]
        .try_into()
        .map_err(|_| FileSystemError::Decode {
            object: "local filesystem content",
            reason: "checksum suffix is the wrong length",
        })?;
    let checksum = IntegrityDigest64(u64::from_le_bytes(checksum_raw));
    Ok((body, Some(checksum)))
}

pub(crate) fn encode_content(inode: &InodeRecord, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&CONTENT_MAGIC);
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);
    push_u16(&mut out, CONTENT_INLINE_CHECKSUM_ENCODING_VERSION);
    push_u64(&mut out, inode.inode_id.get());
    push_u64(&mut out, inode.data_version);
    push_u64(&mut out, bytes.len() as u64);
    out.extend_from_slice(bytes);
    let checksum = checksum64(&out);
    push_u64(&mut out, checksum.get());
    out
}

pub(crate) fn decode_content(bytes: &[u8]) -> Result<ContentObject> {
    let (body, stored_checksum) = split_inline_checksum(bytes)?;
    let mut decoder = Decoder::new("local filesystem content", body);
    decoder.expect_magic(CONTENT_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem content",
            reason: "unsupported format version",
        });
    }
    let encoding_version = decoder.read_u16()?;
    if encoding_version > CONTENT_INLINE_CHECKSUM_ENCODING_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem content",
            reason: "unsupported content encoding version",
        });
    }
    if encoding_version == 0 && stored_checksum.is_some() {
        return Err(FileSystemError::Decode {
            object: "local filesystem content",
            reason: "checksum present but encoding version is 0",
        });
    }
    let inode_id = InodeId::new(decoder.read_u64()?);
    let data_version = decoder.read_u64()?;
    let len = decoder.read_count()?;
    let payload = decoder.read_bytes(len)?.to_vec();
    decoder.finish()?;
    if let Some(expected) = stored_checksum {
        let actual = checksum64(body);
        if actual != expected {
            return Err(FileSystemError::CorruptState {
                reason: "inline content checksum does not match",
            });
        }
    }
    Ok(ContentObject {
        inode_id,
        data_version,
        bytes: payload,
    })
}

pub(crate) fn encode_content_manifest(manifest: &ContentManifestObject) -> Vec<u8> {
    encode_content_manifest_impl(manifest, false)
}

pub(crate) fn encode_content_manifest_sparse(manifest: &ContentManifestObject) -> Vec<u8> {
    encode_content_manifest_impl(manifest, true)
}

fn encode_content_manifest_impl(manifest: &ContentManifestObject, sparse: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if sparse {
        out.extend_from_slice(&CONTENT_MANIFEST_SPARSE_MAGIC);
    } else {
        out.extend_from_slice(&CONTENT_MANIFEST_MAGIC);
    }
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);
    push_u16(&mut out, if sparse { 1 } else { 0 });
    push_u64(&mut out, manifest.inode_id.get());
    push_u64(&mut out, manifest.data_version);
    push_u64(&mut out, manifest.file_size);
    push_u32(&mut out, manifest.chunk_size);
    push_u32(&mut out, 0);
    push_u64(&mut out, manifest.chunks.len() as u64);
    for chunk in &manifest.chunks {
        push_u64(&mut out, chunk.chunk_index);
        push_u64(&mut out, chunk.data_version);
        push_u32(&mut out, chunk.len);
        push_u32(&mut out, 0);
        push_u64(&mut out, chunk.checksum.get());
    }
    out
}

pub(crate) fn decode_content_manifest(bytes: &[u8]) -> Result<ContentManifestObject> {
    let mut decoder = Decoder::new("local filesystem content manifest", bytes);
    let sparse = if bytes.len() >= 8 && bytes[0..8] == CONTENT_MANIFEST_SPARSE_MAGIC {
        decoder.expect_magic(CONTENT_MANIFEST_SPARSE_MAGIC)?;
        true
    } else {
        decoder.expect_magic(CONTENT_MANIFEST_MAGIC)?;
        false
    };
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem content manifest",
            reason: "unsupported format version",
        });
    }
    let _sparse_flag = decoder.read_u16()?;
    if !sparse && _sparse_flag != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem content manifest",
            reason: "reserved field is non-zero",
        });
    }
    let inode_id = InodeId::new(decoder.read_u64()?);
    let data_version = decoder.read_u64()?;
    let file_size = decoder.read_u64()?;
    let chunk_size = decoder.read_u32()?;
    if decoder.read_u32()? != 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem content manifest",
            reason: "reserved chunk-size field is non-zero",
        });
    }
    // Each chunk entry is 32 bytes. Cap count from remaining bytes to
    // prevent OOM from corrupt or malicious count values.
    let max_chunks = decoder.remaining() / 32;
    let count = decoder.read_count_bounded(max_chunks)?;
    if count > file_size as usize {
        return Err(FileSystemError::Decode {
            object: "local filesystem content manifest",
            reason: "chunk count exceeds file size",
        });
    }
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        let chunk_index = decoder.read_u64()?;
        let chunk_data_version = decoder.read_u64()?;
        let len = decoder.read_u32()?;
        if decoder.read_u32()? != 0 {
            return Err(FileSystemError::Decode {
                object: "local filesystem content manifest",
                reason: "reserved chunk entry field is non-zero",
            });
        }
        let checksum = IntegrityDigest64(decoder.read_u64()?);
        chunks.push(ContentChunkRef {
            chunk_index,
            data_version: chunk_data_version,
            len,
            checksum,
        });
    }
    decoder.finish()?;
    Ok(ContentManifestObject {
        inode_id,
        data_version,
        file_size,
        chunk_size,
        chunks,
    })
}

pub(crate) fn encode_content_chunk(
    inode: &InodeRecord,
    chunk_index: u64,
    bytes: &[u8],
    policy: &ContentCompressionPolicy,
) -> Vec<u8> {
    // Validate policy parameters; on misconfiguration, treat as uncompressed.
    let policy = if policy.validate().is_ok() {
        policy
    } else {
        &ContentCompressionPolicy::off()
    };

    let mut out = Vec::new();
    out.extend_from_slice(&CONTENT_CHUNK_MAGIC);
    push_u16(&mut out, FILESYSTEM_FORMAT_VERSION);

    // Apply per-dataset compression policy with threshold gating.
    let (algorithm, stored) = match policy.algorithm {
        ContentCompressionAlgorithm::None => (ContentCompressionAlgorithm::None, bytes.to_vec()),
        ContentCompressionAlgorithm::Zstd => {
            if bytes.len() >= policy.min_savings_bytes {
                match zstd::encode_all(bytes, policy.level) {
                    Ok(compressed) if compressed.len() + policy.min_savings_bytes < bytes.len() => {
                        (ContentCompressionAlgorithm::Zstd, compressed)
                    }
                    _ => (ContentCompressionAlgorithm::None, bytes.to_vec()),
                }
            } else {
                (ContentCompressionAlgorithm::None, bytes.to_vec())
            }
        }
        ContentCompressionAlgorithm::Lz4 => {
            if bytes.len() >= policy.min_savings_bytes {
                // lz4_flex compress_prepend_size embeds the original size in the
                // compressed output; decompress_size_prepended recovers it.
                let compressed = lz4_flex::block::compress_prepend_size(bytes);
                if compressed.len() + policy.min_savings_bytes < bytes.len() {
                    (ContentCompressionAlgorithm::Lz4, compressed)
                } else {
                    (ContentCompressionAlgorithm::None, bytes.to_vec())
                }
            } else {
                (ContentCompressionAlgorithm::None, bytes.to_vec())
            }
        }
    };

    push_u16(&mut out, algorithm.as_u16());
    push_u64(&mut out, inode.inode_id.get());
    push_u64(&mut out, inode.data_version);
    push_u64(&mut out, chunk_index);
    push_u64(&mut out, stored.len() as u64);
    out.extend_from_slice(&stored);
    out
}

pub(crate) fn decode_content_chunk(bytes: &[u8]) -> Result<ContentChunkObject> {
    let mut decoder = Decoder::new("local filesystem content chunk", bytes);
    decoder.expect_magic(CONTENT_CHUNK_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != FILESYSTEM_FORMAT_VERSION {
        return Err(FileSystemError::Decode {
            object: "local filesystem content chunk",
            reason: "unsupported format version",
        });
    }
    let algorithm_raw = decoder.read_u16()?;
    let algorithm =
        ContentCompressionAlgorithm::from_u16(algorithm_raw).ok_or(FileSystemError::Decode {
            object: "local filesystem content chunk",
            reason: "unknown compression algorithm",
        })?;
    let inode_id = InodeId::new(decoder.read_u64()?);
    let data_version = decoder.read_u64()?;
    let chunk_index = decoder.read_u64()?;
    let stored_len = decoder.read_count()?;
    let stored_payload = decoder.read_bytes(stored_len)?.to_vec();
    decoder.finish()?;

    let result_bytes = match algorithm {
        ContentCompressionAlgorithm::None => stored_payload,
        ContentCompressionAlgorithm::Zstd => {
            zstd::decode_all(&stored_payload[..]).map_err(|_| FileSystemError::CorruptState {
                reason: "zstd decompression of content chunk payload failed",
            })?
        }
        ContentCompressionAlgorithm::Lz4 => {
            lz4_flex::block::decompress_size_prepended(&stored_payload[..]).map_err(|_| {
                FileSystemError::CorruptState {
                    reason: "lz4 decompression of content chunk payload failed",
                }
            })?
        }
    };

    Ok(ContentChunkObject {
        inode_id,
        data_version,
        chunk_index,
        bytes: result_bytes,
    })
}

pub(crate) struct Decoder<'a> {
    pub(crate) object: &'static str,
    pub(crate) bytes: &'a [u8],
    pub(crate) offset: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(object: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            object,
            bytes,
            offset: 0,
        }
    }

    pub(crate) fn expect_magic(&mut self, magic: [u8; 8]) -> Result<()> {
        let actual = self.read_bytes(8)?;
        if actual != &magic[..] {
            return Err(FileSystemError::Decode {
                object: self.object,
                reason: "magic bytes do not match",
            });
        }
        Ok(())
    }

    /// Peek ahead without advancing the offset: returns true if the next 8 bytes match magic.
    pub(crate) fn try_peek_magic(&self, magic: [u8; 8]) -> bool {
        let end = match self.offset.checked_add(8) {
            Some(e) => e,
            None => return false,
        };
        if end > self.bytes.len() {
            return false;
        }
        self.bytes[self.offset..end] == magic[..]
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(crate) fn read_i64(&mut self) -> Result<i64> {
        let bytes = self.read_bytes(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(crate) fn read_count(&mut self) -> Result<usize> {
        let value = self.read_u64()?;
        usize::try_from(value).map_err(|_| FileSystemError::Decode {
            object: self.object,
            reason: "count does not fit in usize",
        })
    }

    /// Read a count value with an explicit upper bound, preventing OOM from
    /// malicious or corrupt count fields that would cause oversized allocations.
    pub(crate) fn read_count_bounded(&mut self, max: usize) -> Result<usize> {
        let count = self.read_count()?;
        if count > max {
            return Err(FileSystemError::Decode {
                object: self.object,
                reason: "count exceeds maximum allowed value",
            });
        }
        Ok(count)
    }

    fn read_name_len(&mut self) -> Result<usize> {
        let value = self.read_u32()?;
        let len = usize::try_from(value).map_err(|_| FileSystemError::Decode {
            object: self.object,
            reason: "name length does not fit in usize",
        })?;
        if len == 0 || len > MAX_NAME_BYTES {
            return Err(FileSystemError::Decode {
                object: self.object,
                reason: "directory entry name length is invalid",
            });
        }
        Ok(len)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(FileSystemError::Decode {
                object: self.object,
                reason: "offset overflow",
            })?;
        if end > self.bytes.len() {
            return Err(FileSystemError::Decode {
                object: self.object,
                reason: "record ended early",
            });
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(FileSystemError::Decode {
                object: self.object,
                reason: "trailing bytes after record",
            });
        }
        Ok(())
    }
}

pub(crate) fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn push_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn compute_content_fingerprint(
    uncompressed_bytes: &[u8],
) -> crate::types::ContentFingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(crate::constants::CONTENT_DEDUP_FINGERPRINT_DOMAIN);
    hasher.update(&(uncompressed_bytes.len() as u64).to_le_bytes());
    hasher.update(uncompressed_bytes);
    crate::types::ContentFingerprint::from_bytes32(*hasher.finalize().as_bytes())
}

pub(crate) fn is_dedup_redirect(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[..8] == crate::constants::CONTENT_DEDUP_MAGIC_BYTES
}

pub(crate) fn encode_dedup_redirect(canonical_key: ObjectKey) -> Vec<u8> {
    use crate::encoding::push_u16;
    let mut out = Vec::with_capacity(crate::constants::CONTENT_DEDUP_REDIRECT_RECORD_BYTES);
    out.extend_from_slice(&crate::constants::CONTENT_DEDUP_MAGIC_BYTES);
    push_u16(
        &mut out,
        crate::constants::CONTENT_DEDUP_REDIRECT_FORMAT_VERSION,
    );
    push_u16(&mut out, 0); // reserved
    out.extend_from_slice(&canonical_key.as_bytes32());
    out
}

// encoding.rs imports above need ObjectKey and Decoder
pub(crate) fn decode_dedup_redirect(bytes: &[u8]) -> crate::Result<ObjectKey> {
    use crate::encoding::Decoder;
    let mut decoder = Decoder::new("content dedup redirect", bytes);
    decoder.expect_magic(crate::constants::CONTENT_DEDUP_MAGIC_BYTES)?;
    let version = decoder.read_u16()?;
    if version != crate::constants::CONTENT_DEDUP_REDIRECT_FORMAT_VERSION {
        return Err(crate::FileSystemError::Decode {
            object: "content dedup redirect",
            reason: "unsupported redirect format version",
        });
    }
    if decoder.read_u16()? != 0 {
        return Err(crate::FileSystemError::Decode {
            object: "content dedup redirect",
            reason: "reserved field is non-zero",
        });
    }
    let mut key_bytes = [0_u8; 32];
    key_bytes.copy_from_slice(decoder.read_bytes(32)?);
    decoder.finish()?;
    Ok(ObjectKey::from_bytes32(key_bytes))
}
