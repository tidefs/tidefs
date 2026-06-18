// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Encryption smoke: deterministic key derivation, encrypted object I/O,
//! wrong-key refusal, reopen recovery, and tamper detection over
//! `tidefs-encryption`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_encryption::tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_encryption::{
    EncryptedObjectStore, EncryptionConfig, EncryptionError, StoreKey, ENCRYPTION_OVERHEAD, KEY_LEN,
};

/// Run the full encryption smoke sequence and return the harness.
#[must_use]
pub fn run_encryption_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("encryption/smoke");
    smoke_key_derivation(&mut h);
    smoke_encrypted_object_roundtrip(&mut h);
    smoke_wrong_key_reopen_and_tamper_detection(&mut h);
    h.scenario_end("encryption/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized =
        serialize_trace(&trace_before_round_trip).expect("encryption smoke trace should serialize");
    let decoded =
        deserialize_trace(&serialized).expect("encryption smoke trace should deserialize");
    h.assert_eq_ev(
        "encryption smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_key_derivation(h: &mut SmokeHarness) {
    record_encryption_op(h, "encryption.key.generate", b"os-random");
    let generated = StoreKey::generate();
    h.assert_eq_ev(
        "generated key has expected length",
        generated.as_bytes().len(),
        KEY_LEN,
    );

    record_encryption_op(h, "encryption.key.derive", b"validation-smoke-passphrase");
    let derived_a = StoreKey::derive_from_passphrase("validation-smoke-passphrase");
    let derived_b = StoreKey::derive_from_passphrase("validation-smoke-passphrase");
    let derived_other = StoreKey::derive_from_passphrase("validation-smoke-other");
    h.assert_eq_ev(
        "passphrase derivation is deterministic",
        derived_a.as_bytes().to_vec(),
        derived_b.as_bytes().to_vec(),
    );
    h.assert_ev(
        "different passphrases derive different keys",
        derived_a.as_bytes() != derived_other.as_bytes(),
    );

    let strict = EncryptionConfig::strict_key_derivation();
    let rejected = StoreKey::derive_from_passphrase_with_config("blocked", &strict);
    h.assert_ev(
        "strict key derivation rejects passphrases",
        matches!(rejected, Err(EncryptionError::KeyDerivationRejected)),
    );
}

fn smoke_encrypted_object_roundtrip(h: &mut SmokeHarness) {
    let dir = tempfile::TempDir::new().expect("tempdir for encryption smoke");
    let key = StoreKey::derive_from_passphrase("validation-smoke-store");
    let config = EncryptionConfig::default();
    let mut store = open_encrypted_store(dir.path(), key, config);
    let key = ObjectKey::from_name("runtime-smoke");
    let plaintext = b"runtime-encryption-smoke-payload".to_vec();

    h.record(TraceEvent::ObjectPut {
        key_bytes: key.as_bytes().to_vec(),
        value: plaintext.clone(),
    });
    let stored = store
        .put(key, &plaintext)
        .expect("encrypted put should succeed");
    h.assert_eq_ev(
        "stored ciphertext includes encryption overhead",
        stored.len,
        (plaintext.len() + ENCRYPTION_OVERHEAD) as u64,
    );

    let ciphertext = store
        .inner()
        .get(key)
        .expect("inner get should succeed")
        .expect("ciphertext should exist");
    h.assert_ev("ciphertext differs from plaintext", ciphertext != plaintext);
    h.assert_eq_ev(
        "ciphertext length includes overhead",
        ciphertext.len(),
        plaintext.len() + ENCRYPTION_OVERHEAD,
    );

    h.record(TraceEvent::ObjectGet {
        key_bytes: key.as_bytes().to_vec(),
    });
    let got = store
        .get(key)
        .expect("encrypted get should succeed")
        .expect("plaintext should exist");
    h.assert_eq_ev("encrypted get round-trips plaintext", got, plaintext);

    let stats = store.encrypted_stats();
    h.assert_eq_ev(
        "encrypted stats count one object",
        stats.objects_encrypted,
        1,
    );
    h.assert_eq_ev(
        "encrypted stats count plaintext bytes",
        stats.bytes_in,
        b"runtime-encryption-smoke-payload".len() as u64,
    );
    h.assert_eq_ev(
        "encrypted stats count ciphertext bytes",
        stats.bytes_out,
        (b"runtime-encryption-smoke-payload".len() + ENCRYPTION_OVERHEAD) as u64,
    );
    h.assert_ev(
        "encrypted overhead ratio reports expansion",
        stats.overhead_ratio() > 1.0,
    );
}

fn smoke_wrong_key_reopen_and_tamper_detection(h: &mut SmokeHarness) {
    let dir = tempfile::TempDir::new().expect("tempdir for encryption reopen smoke");
    let correct_key = StoreKey::derive_from_passphrase("validation-smoke-correct-key");
    let wrong_key = StoreKey::derive_from_passphrase("validation-smoke-wrong-key");
    let config = EncryptionConfig::default();
    let key = ObjectKey::from_name("persistent-secret");

    {
        let mut store = open_encrypted_store(dir.path(), correct_key.clone(), config.clone());
        h.record(TraceEvent::ObjectPut {
            key_bytes: key.as_bytes().to_vec(),
            value: b"survives-reopen".to_vec(),
        });
        store
            .put(key, b"survives-reopen")
            .expect("encrypted persistent put should succeed");
        store.sync_all().expect("encrypted sync should succeed");
    }

    let reopened = open_encrypted_store(dir.path(), correct_key, config.clone());
    h.record(TraceEvent::ObjectGet {
        key_bytes: key.as_bytes().to_vec(),
    });
    let plain = reopened
        .get(key)
        .expect("reopen with correct key should decrypt")
        .expect("persistent object should exist");
    h.assert_eq_ev(
        "reopen with correct key recovers plaintext",
        plain,
        b"survives-reopen".to_vec(),
    );

    let wrong = open_encrypted_store(dir.path(), wrong_key, config.clone());
    h.assert_ev(
        "wrong key rejects stored ciphertext",
        matches!(wrong.get(key), Err(EncryptionError::DecryptionFailed)),
    );
    drop(wrong);

    let mut tampered = open_encrypted_store(
        dir.path(),
        StoreKey::derive_from_passphrase("validation-smoke-correct-key"),
        config,
    );
    let mut ciphertext = tampered
        .inner()
        .get(key)
        .expect("inner get before tamper should succeed")
        .expect("ciphertext should exist before tamper");
    ciphertext[ENCRYPTION_OVERHEAD] ^= 0x55;
    tampered
        .inner_mut()
        .put(key, &ciphertext)
        .expect("inner tamper write should succeed");
    h.assert_ev(
        "tampered ciphertext fails authentication",
        matches!(tampered.get(key), Err(EncryptionError::DecryptionFailed)),
    );
}

fn open_encrypted_store(
    root: &std::path::Path,
    key: StoreKey,
    config: EncryptionConfig,
) -> EncryptedObjectStore {
    let inner =
        LocalObjectStore::open_with_options(root, StoreOptions::test_fast()).expect("open store");
    EncryptedObjectStore::new_with_config(inner, key, config)
}

fn record_encryption_op(h: &mut SmokeHarness, op_name: &str, payload: &[u8]) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 0,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_smoke_passes() {
        let h = run_encryption_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
