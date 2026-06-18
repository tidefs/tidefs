// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Property-based integration tests for tidefs-encryption key manager.
//!
//! Exercises SealedDEK serialisation, KeyManager seal/unseal,
//! KeyStore persistence, and KeyRotation through the public API.
//!
//! NOTE: Tests involving Argon2 (PoolWrappingKey::derive) run with
//! reduced case counts because Argon2 is intentionally slow.
//! Non-Argon2 tests use default 256 cases.

use proptest::prelude::*;
use tempfile::TempDir;
use tidefs_encryption::key_hierarchy::*;
use tidefs_encryption::key_manager::*;
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

// ── Strategies ─────────────────────────────────────────────────────

fn arb_passphrase() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[[:print:]]{1,64}").unwrap()
}

fn arb_dataset_id() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z0-9_-]{1,32}").unwrap()
}

fn arb_kek_gen() -> impl Strategy<Value = u32> {
    any::<u32>()
}

fn test_keystore(salt: [u8; SALT_LEN]) -> (TempDir, KeyStore) {
    let dir = TempDir::new().unwrap();
    let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    let ks = KeyStore::new(store, salt);
    (dir, ks)
}

// ── SealedDEK wire format ──────────────────────────────────────────

proptest! {
    // Uses Argon2; 4 cases.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn sealed_dek_roundtrip(
        dataset_id in arb_dataset_id(),
        kek_generation in arb_kek_gen(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("test passphrase", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let sealed = KeyManager::seal_dek(&dek, &wk, &dataset_id, kek_generation).unwrap();
        let bytes = sealed.to_bytes();
        let restored = SealedDEK::from_bytes(&bytes).unwrap();

        prop_assert_eq!(sealed, restored.clone());
        prop_assert_eq!(restored.dataset_id, dataset_id);
        prop_assert_eq!(restored.kek_generation, kek_generation);
    }
}

proptest! {
    // No Argon2; full 256 cases.
    #[test]
    fn sealed_dek_rejects_garbage(
        garbage in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        prop_assume!(garbage.len() < 4 || garbage[..4] != *b"VSEK");
        let result = SealedDEK::from_bytes(&garbage);
        prop_assert!(result.is_err());
    }
}

proptest! {
    // Uses Argon2; 4 cases.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn seal_dek_nonce_unique(
        dataset_id in arb_dataset_id(),
        kek_generation in arb_kek_gen(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("test", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let s1 = KeyManager::seal_dek(&dek, &wk, &dataset_id, kek_generation).unwrap();
        let s2 = KeyManager::seal_dek(&dek, &wk, &dataset_id, kek_generation).unwrap();

        prop_assert_ne!(s1.wrapped_dek.as_bytes(), s2.wrapped_dek.as_bytes());

        let d1 = KeyManager::unseal_dek(&s1, &wk).unwrap();
        let d2 = KeyManager::unseal_dek(&s2, &wk).unwrap();
        prop_assert_eq!(d1.as_bytes(), d2.as_bytes());
    }
}

// ── KeyManager seal / unseal ────────────────────────────────────────

proptest! {
    // Uses Argon2; 4 cases.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn seal_unseal_roundtrip(
        passphrase in arb_passphrase(),
        dataset_id in arb_dataset_id(),
        kek_generation in arb_kek_gen(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let sealed = KeyManager::seal_dek(&dek, &wk, &dataset_id, kek_generation).unwrap();
        let unsealed = KeyManager::unseal_dek(&sealed, &wk).unwrap();
        prop_assert_eq!(dek.as_bytes(), unsealed.as_bytes());
    }

    #[test]
    fn unseal_wrong_passphrase_fails(
        correct_pw in arb_passphrase(),
        wrong_pw in arb_passphrase(),
        dataset_id in arb_dataset_id(),
    ) {
        prop_assume!(correct_pw != wrong_pw);
        let salt = PoolWrappingKey::generate_salt();
        let wk_correct = PoolWrappingKey::derive(&correct_pw, &salt).unwrap();
        let wk_wrong = PoolWrappingKey::derive(&wrong_pw, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let sealed = KeyManager::seal_dek(&dek, &wk_correct, &dataset_id, 0).unwrap();
        let result = KeyManager::unseal_dek(&sealed, &wk_wrong);
        prop_assert!(result.is_err());
    }
}

// ── KeyStore persistence ────────────────────────────────────────────

proptest! {
    // Uses Argon2; 4 cases.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn keystore_store_and_load(
        passphrase in arb_passphrase(),
        dataset_id in arb_dataset_id(),
        kek_generation in arb_kek_gen(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let (_dir, mut ks) = test_keystore(salt);
        let sealed = KeyManager::seal_dek(&dek, &wk, &dataset_id, kek_generation).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();

        let loaded = ks.load_sealed_dek(&dataset_id).unwrap().unwrap();
        let ds_id = loaded.dataset_id.clone();
        prop_assert_eq!(ds_id, dataset_id);
        prop_assert_eq!(loaded.kek_generation, kek_generation);

        let unsealed = KeyManager::unseal_dek(&loaded, &wk).unwrap();
        prop_assert_eq!(dek.as_bytes(), unsealed.as_bytes());
    }
}

proptest! {
    // No Argon2; full 256 cases.
    #[test]
    fn keystore_load_nonexistent(
        dataset_id in arb_dataset_id(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let (_dir, ks) = test_keystore(salt);
        let result = ks.load_sealed_dek(&dataset_id).unwrap();
        prop_assert!(result.is_none());
    }
}

proptest! {
    // Uses Argon2; 4 cases.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn keystore_list_datasets(
        passphrase in arb_passphrase(),
        id1 in arb_dataset_id(),
        id2 in arb_dataset_id(),
    ) {
        prop_assume!(id1 != id2);
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let (_dir, mut ks) = test_keystore(salt);

        let initial = ks.list_datasets().unwrap();
        prop_assert!(initial.is_empty());

        ks.store_sealed_dek(&KeyManager::seal_dek(&dek, &wk, &id1, 0).unwrap()).unwrap();
        ks.store_sealed_dek(&KeyManager::seal_dek(&dek, &wk, &id2, 0).unwrap()).unwrap();

        let mut ds = ks.list_datasets().unwrap();
        ds.sort();
        prop_assert_eq!(ds, {
            let mut v = vec![id1.clone(), id2.clone()];
            v.sort();
            v
        });

        prop_assert!(ks.delete_sealed_dek(&id1).unwrap());
        let after = ks.list_datasets().unwrap();
        prop_assert_eq!(after, vec![id2.clone()]);
    }
}

proptest! {
    // No Argon2; full 256 cases.
    #[test]
    fn keystore_delete_nonexistent(
        dataset_id in arb_dataset_id(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let (_dir, mut ks) = test_keystore(salt);
        prop_assert!(!ks.delete_sealed_dek(&dataset_id).unwrap());
    }
}

// ── KeyRotation ─────────────────────────────────────────────────────

proptest! {
    // Uses Argon2; 4 cases.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn rekey_preserves_deks(
        old_pass in arb_passphrase(),
        new_pass in arb_passphrase(),
        ds1 in arb_dataset_id(),
        ds2 in arb_dataset_id(),
    ) {
        prop_assume!(ds1 != ds2);
        let old_salt = PoolWrappingKey::generate_salt();
        let old_wk = PoolWrappingKey::derive(&old_pass, &old_salt).unwrap();
        let dek1 = DatasetDEK::generate();
        let dek2 = DatasetDEK::generate();

        let (_dir, mut ks) = test_keystore(old_salt);

        ks.store_sealed_dek(
            &KeyManager::seal_dek(&dek1, &old_wk, &ds1, 0).unwrap()
        ).unwrap();
        ks.store_sealed_dek(
            &KeyManager::seal_dek(&dek2, &old_wk, &ds2, 0).unwrap()
        ).unwrap();

        let new_salt = PoolWrappingKey::generate_salt();
        let stats = KeyRotation::rekey_wrapping_key(
            &old_pass, &new_pass, &new_salt, &mut ks
        ).unwrap();
        prop_assert_eq!(stats.keys_rotated, 2);

        let new_wk = PoolWrappingKey::derive(&new_pass, &new_salt).unwrap();
        for (ds_id, dek) in &[(&ds1, &dek1), (&ds2, &dek2)] {
            let loaded = ks.load_sealed_dek(ds_id).unwrap().unwrap();
            prop_assert_eq!(loaded.kek_generation, 1);
            let unsealed = KeyManager::unseal_dek(&loaded, &new_wk).unwrap();
            prop_assert_eq!(dek.as_bytes(), unsealed.as_bytes());
        }

        let old_wk2 = PoolWrappingKey::derive(&old_pass, &old_salt).unwrap();
        let loaded = ks.load_sealed_dek(&ds1).unwrap().unwrap();
        prop_assert!(KeyManager::unseal_dek(&loaded, &old_wk2).is_err());
    }

    #[test]
    fn rekey_empty_keystore(
        old_pass in arb_passphrase(),
        new_pass in arb_passphrase(),
    ) {
        let old_salt = PoolWrappingKey::generate_salt();
        let new_salt = PoolWrappingKey::generate_salt();
        let (_dir, mut ks) = test_keystore(old_salt);

        let stats = KeyRotation::rekey_wrapping_key(
            &old_pass, &new_pass, &new_salt, &mut ks
        ).unwrap();
        prop_assert_eq!(stats.keys_rotated, 0);
        prop_assert_eq!(ks.salt(), &new_salt);
    }

    #[test]
    fn rekey_wrong_old_passphrase_fails(
        correct_pw in arb_passphrase(),
        wrong_pw in arb_passphrase(),
        new_pass in arb_passphrase(),
        dataset_id in arb_dataset_id(),
    ) {
        prop_assume!(correct_pw != wrong_pw);
        let old_salt = PoolWrappingKey::generate_salt();
        let old_wk = PoolWrappingKey::derive(&correct_pw, &old_salt).unwrap();
        let dek = DatasetDEK::generate();

        let (_dir, mut ks) = test_keystore(old_salt);
        ks.store_sealed_dek(
            &KeyManager::seal_dek(&dek, &old_wk, &dataset_id, 0).unwrap()
        ).unwrap();

        let new_salt = PoolWrappingKey::generate_salt();
        let result = KeyRotation::rekey_wrapping_key(
            &wrong_pw, &new_pass, &new_salt, &mut ks
        );
        prop_assert!(result.is_err());
    }
}

// ── KeyManagerStats ─────────────────────────────────────────────────

proptest! {
    // No Argon2; full 256 cases.
    #[test]
    fn key_manager_stats_merge(
        a_enc in any::<u64>(),
        a_seal in any::<u64>(),
        a_rot in any::<u64>(),
        b_enc in any::<u64>(),
        b_seal in any::<u64>(),
        b_rot in any::<u64>(),
    ) {
        let mut a = KeyManagerStats {
            datasets_encrypted: a_enc,
            keys_sealed: a_seal,
            keys_rotated: a_rot,
        };
        let b = KeyManagerStats {
            datasets_encrypted: b_enc,
            keys_sealed: b_seal,
            keys_rotated: b_rot,
        };
        a.merge(&b);
        prop_assert_eq!(a.datasets_encrypted, a_enc.saturating_add(b_enc));
        prop_assert_eq!(a.keys_sealed, a_seal.saturating_add(b_seal));
        prop_assert_eq!(a.keys_rotated, a_rot.saturating_add(b_rot));
    }
}
