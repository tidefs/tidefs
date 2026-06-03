//! Property-based integration tests for tidefs-encryption key hierarchy.
//!
//! Exercises PoolWrappingKey, DatasetDEK, WrappedDEK, ExtentNonce,
//! extent encrypt/decrypt, and key rotation through the public API.

use proptest::prelude::*;
use tidefs_encryption::key_hierarchy::*;
use tidefs_encryption::{NONCE_LEN, TAG_LEN};

// ── Strategies ─────────────────────────────────────────────────────

fn arb_passphrase() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[[:print:]]{1,128}").unwrap()
}

fn arb_extent_id() -> impl Strategy<Value = u64> {
    any::<u64>()
}

fn arb_write_counter() -> impl Strategy<Value = u64> {
    any::<u64>()
}

fn arb_plaintext() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..4096)
}

// ── PoolWrappingKey derivation ──────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn wrapping_key_derivation_deterministic(
        passphrase in arb_passphrase(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let k1 = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        let k2 = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        prop_assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_passphrases_produce_different_keys(
        p1 in arb_passphrase(),
        p2 in arb_passphrase(),
    ) {
        prop_assume!(p1 != p2);
        let salt = PoolWrappingKey::generate_salt();
        let k1 = PoolWrappingKey::derive(&p1, &salt).unwrap();
        let k2 = PoolWrappingKey::derive(&p2, &salt).unwrap();
        prop_assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_salts_produce_different_keys(
        passphrase in arb_passphrase(),
    ) {
        let s1 = PoolWrappingKey::generate_salt();
        let s2 = PoolWrappingKey::generate_salt();
        prop_assume!(s1 != s2);
        let k1 = PoolWrappingKey::derive(&passphrase, &s1).unwrap();
        let k2 = PoolWrappingKey::derive(&passphrase, &s2).unwrap();
        prop_assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}

// ── wrap_dek / unwrap_dek round-trip ────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn wrap_unwrap_roundtrip_arbitrary_key(
        passphrase in arb_passphrase(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &wk).unwrap();
        prop_assert_eq!(wrapped.as_bytes().len(), WRAPPED_DEK_LEN);

        let unwrapped = unwrap_dek(&wrapped, &wk).unwrap();
        prop_assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn wrap_dek_nonce_unique(
        passphrase in arb_passphrase(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let w1 = wrap_dek(&dek, &wk).unwrap();
        let w2 = wrap_dek(&dek, &wk).unwrap();
        prop_assert_ne!(
            &w1.as_bytes()[..NONCE_LEN],
            &w2.as_bytes()[..NONCE_LEN]
        );
        let u1 = unwrap_dek(&w1, &wk).unwrap();
        let u2 = unwrap_dek(&w2, &wk).unwrap();
        prop_assert_eq!(u1.as_bytes(), u2.as_bytes());
    }
}

// ── Decryption failure modes ────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn unwrap_dek_wrong_key_fails(
        p_correct in arb_passphrase(),
        p_wrong in arb_passphrase(),
    ) {
        prop_assume!(p_correct != p_wrong);
        let salt = PoolWrappingKey::generate_salt();
        let wk_correct = PoolWrappingKey::derive(&p_correct, &salt).unwrap();
        let wk_wrong = PoolWrappingKey::derive(&p_wrong, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &wk_correct).unwrap();
        let result = unwrap_dek(&wrapped, &wk_wrong);
        prop_assert!(result.is_err());
    }

    #[test]
    fn unwrap_dek_truncated_fails(
        passphrase in arb_passphrase(),
        trunc in 0usize..(WRAPPED_DEK_LEN),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive(&passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();
        let wrapped = wrap_dek(&dek, &wk).unwrap();

        if trunc < NONCE_LEN {
            let short = WrappedDEK::from_bytes(wrapped.as_bytes()[..trunc].to_vec());
            prop_assert!(short.is_err());
        } else {
            let from_result = WrappedDEK::from_bytes(wrapped.as_bytes()[..trunc].to_vec());
            prop_assert!(from_result.is_err());
        }
    }
}

// ── ExtentNonce derivation ──────────────────────────────────────────

proptest! {
    // No Argon2 here; 256 cases is fast.
    #[test]
    fn extent_nonce_deterministic(
        extent_id in arb_extent_id(),
        write_counter in arb_write_counter(),
    ) {
        let dek = DatasetDEK::generate();
        let n1 = ExtentNonce::derive(extent_id, write_counter, &dek);
        let n2 = ExtentNonce::derive(extent_id, write_counter, &dek);
        prop_assert_eq!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn extent_nonce_different_id(
        eid1 in arb_extent_id(),
        eid2 in arb_extent_id(),
        wc in arb_write_counter(),
    ) {
        prop_assume!(eid1 != eid2);
        let dek = DatasetDEK::generate();
        let n1 = ExtentNonce::derive(eid1, wc, &dek);
        let n2 = ExtentNonce::derive(eid2, wc, &dek);
        prop_assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn extent_nonce_different_counter(
        eid in arb_extent_id(),
        wc1 in arb_write_counter(),
        wc2 in arb_write_counter(),
    ) {
        prop_assume!(wc1 != wc2);
        let dek = DatasetDEK::generate();
        let n1 = ExtentNonce::derive(eid, wc1, &dek);
        let n2 = ExtentNonce::derive(eid, wc2, &dek);
        prop_assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn extent_nonce_different_dek(
        extent_id in arb_extent_id(),
        write_counter in arb_write_counter(),
    ) {
        let da = DatasetDEK::generate();
        let db = DatasetDEK::generate();
        prop_assume!(da.as_bytes() != db.as_bytes());
        let n1 = ExtentNonce::derive(extent_id, write_counter, &da);
        let n2 = ExtentNonce::derive(extent_id, write_counter, &db);
        prop_assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn extent_nonce_length(
        extent_id in arb_extent_id(),
        write_counter in arb_write_counter(),
    ) {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(extent_id, write_counter, &dek);
        prop_assert_eq!(nonce.as_bytes().len(), NONCE_LEN);
    }
}

// ── Extent encrypt / decrypt round-trip ─────────────────────────────

proptest! {
    // No Argon2; 256 cases is fast.
    #[test]
    fn encrypt_decrypt_roundtrip(
        plaintext in arb_plaintext(),
        extent_id in arb_extent_id(),
        write_counter in arb_write_counter(),
    ) {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(extent_id, write_counter, &dek);

        let payload = encrypt_extent(&plaintext, &dek, &nonce).unwrap();
        let decrypted = decrypt_extent(&payload, &dek).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_payload_structure(
        plaintext in arb_plaintext(),
        extent_id in arb_extent_id(),
        write_counter in arb_write_counter(),
    ) {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(extent_id, write_counter, &dek);

        let payload = encrypt_extent(&plaintext, &dek, &nonce).unwrap();
        prop_assert_eq!(payload.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
        prop_assert_eq!(payload.is_empty(), plaintext.is_empty());
    }

    #[test]
    fn encrypt_different_nonce_different_ciphertext(
        plaintext in arb_plaintext(),
        eid in arb_extent_id(),
    ) {
        prop_assume!(!plaintext.is_empty());
        let dek = DatasetDEK::generate();
        let n1 = ExtentNonce::derive(eid, 0, &dek);
        let n2 = ExtentNonce::derive(eid, 1, &dek);

        let p1 = encrypt_extent(&plaintext, &dek, &n1).unwrap();
        let p2 = encrypt_extent(&plaintext, &dek, &n2).unwrap();
        prop_assert_ne!(p1.ciphertext, p2.ciphertext);
    }

    #[test]
    fn decrypt_wrong_dek_fails(
        plaintext in arb_plaintext(),
        extent_id in arb_extent_id(),
        write_counter in arb_write_counter(),
    ) {
        prop_assume!(!plaintext.is_empty());
        let da = DatasetDEK::generate();
        let db = DatasetDEK::generate();
        prop_assume!(da.as_bytes() != db.as_bytes());
        let nonce = ExtentNonce::derive(extent_id, write_counter, &da);

        let payload = encrypt_extent(&plaintext, &da, &nonce).unwrap();
        let result = decrypt_extent(&payload, &db);
        prop_assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails(
        plaintext in arb_plaintext(),
        extent_id in arb_extent_id(),
        write_counter in arb_write_counter(),
        tamper_idx in prop::option::of(any::<usize>()),
    ) {
        prop_assume!(!plaintext.is_empty());
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(extent_id, write_counter, &dek);

        let mut payload = encrypt_extent(&plaintext, &dek, &nonce).unwrap();
        let max_idx = payload.ciphertext.len().saturating_sub(1);
        let idx = tamper_idx.unwrap_or(0) % max_idx.max(1);
        payload.ciphertext[idx] ^= 0xFF;

        let result = decrypt_extent(&payload, &dek);
        prop_assert!(result.is_err());
    }

    #[test]
    fn decrypt_wrong_nonce_fails(
        plaintext in arb_plaintext(),
        eid in arb_extent_id(),
        wc in arb_write_counter(),
    ) {
        prop_assume!(!plaintext.is_empty());
        let dek = DatasetDEK::generate();
        let correct_nonce = ExtentNonce::derive(eid, wc, &dek);
        let wrong_nonce = ExtentNonce::derive(eid, wc.wrapping_add(1), &dek);

        let payload = encrypt_extent(&plaintext, &dek, &correct_nonce).unwrap();
        let tampered = EncryptedExtentPayload {
            nonce: wrong_nonce,
            ciphertext: payload.ciphertext,
        };
        let result = decrypt_extent(&tampered, &dek);
        prop_assert!(result.is_err());
    }
}

// ── Key rotation ────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn rewrap_dek_preserves_dek(
        old_pass in arb_passphrase(),
        new_pass in arb_passphrase(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let old_wk = PoolWrappingKey::derive(&old_pass, &salt).unwrap();
        let new_wk = PoolWrappingKey::derive(&new_pass, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped_old = wrap_dek(&dek, &old_wk).unwrap();
        let wrapped_new = rewrap_dek(&wrapped_old, &old_wk, &new_wk).unwrap();

        let d1 = unwrap_dek(&wrapped_old, &old_wk).unwrap();
        prop_assert_eq!(d1.as_bytes(), dek.as_bytes());

        let d2 = unwrap_dek(&wrapped_new, &new_wk).unwrap();
        prop_assert_eq!(d2.as_bytes(), dek.as_bytes());

        prop_assert!(unwrap_dek(&wrapped_new, &old_wk).is_err());
    }

    #[test]
    fn rewrap_dek_idempotent(
        old_pass in arb_passphrase(),
        new_pass in arb_passphrase(),
    ) {
        let salt = PoolWrappingKey::generate_salt();
        let old_wk = PoolWrappingKey::derive(&old_pass, &salt).unwrap();
        let new_wk = PoolWrappingKey::derive(&new_pass, &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &old_wk).unwrap();
        let r1 = rewrap_dek(&wrapped, &old_wk, &new_wk).unwrap();
        let r2 = rewrap_dek(&wrapped, &old_wk, &new_wk).unwrap();

        let d1 = unwrap_dek(&r1, &new_wk).unwrap();
        let d2 = unwrap_dek(&r2, &new_wk).unwrap();
        prop_assert_eq!(d1.as_bytes(), dek.as_bytes());
        prop_assert_eq!(d1.as_bytes(), d2.as_bytes());
    }
}
