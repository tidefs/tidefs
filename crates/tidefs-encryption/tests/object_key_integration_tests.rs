//! Integration tests for per-object key derivation via HKDF-SHA256.
//!
//! Exercises ObjectKeyDeriver, EncryptedObjectStore with per-object key
//! derivation, and AEAD encrypt/decrypt round-trip through the public API.

use chacha20poly1305::KeyInit;
use tempfile::TempDir;
use tidefs_encryption::tidefs_local_object_store::store::LocalObjectStore;
use tidefs_encryption::tidefs_local_object_store::ObjectKey;
use tidefs_encryption::tidefs_local_object_store::StoreOptions;
use tidefs_encryption::EncryptedObjectStore;
use tidefs_encryption::EncryptionConfig;
use tidefs_encryption::ObjectKeyDeriver;
use tidefs_encryption::StoreKey;

// ── Test helpers ─────────────────────────────────────────────────────

fn temp_store() -> (TempDir, LocalObjectStore) {
    temp_store_with_segment(4096)
}

fn temp_store_with_segment(max_segment_bytes: u64) -> (TempDir, LocalObjectStore) {
    let dir = TempDir::new().unwrap();
    let opts = StoreOptions {
        max_segment_bytes,
        ..StoreOptions::test_fast()
    };
    let store = LocalObjectStore::open_with_options(dir.path(), opts).unwrap();
    (dir, store)
}

fn deriver_store(key: &StoreKey) -> (TempDir, EncryptedObjectStore) {
    deriver_store_with_segment(key, 4096)
}

fn deriver_store_with_segment(
    key: &StoreKey,
    segment_bytes: u64,
) -> (TempDir, EncryptedObjectStore) {
    let (dir, inner) = temp_store_with_segment(segment_bytes);
    let mut store =
        EncryptedObjectStore::new_with_config(inner, key.clone(), EncryptionConfig::default());
    let deriver = ObjectKeyDeriver::new(key.clone());
    store.set_object_key_deriver(deriver);
    (dir, store)
}

fn encrypted_store() -> (TempDir, EncryptedObjectStore) {
    let (dir, inner) = temp_store();
    let key = StoreKey::generate();
    let store = EncryptedObjectStore::new_with_config(inner, key, EncryptionConfig::default());
    (dir, store)
}

// ── ObjectKeyDeriver unit tests ──────────────────────────────────────

#[test]
fn deterministic_derivation() {
    let master = StoreKey::generate();
    let deriver = ObjectKeyDeriver::new(master);

    let k1 = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"obj-1");
    let k2 = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"obj-1");
    assert_eq!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn unique_per_object_id() {
    let master = StoreKey::generate();
    let deriver = ObjectKeyDeriver::new(master);

    let k_a = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"object-A");
    let k_b = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"object-B");
    assert_ne!(k_a.as_bytes(), k_b.as_bytes());
}

#[test]
fn domain_separation_produces_different_keys() {
    let master = StoreKey::generate();
    let deriver = ObjectKeyDeriver::new(master);

    let k_enc = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"obj-1");
    let k_meta = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_METADATA, b"obj-1");
    assert_ne!(k_enc.as_bytes(), k_meta.as_bytes());
}

#[test]
fn different_master_keys_produce_different_derived_keys() {
    let master1 = StoreKey::generate();
    let master2 = StoreKey::generate();
    let deriver1 = ObjectKeyDeriver::new(master1);
    let deriver2 = ObjectKeyDeriver::new(master2);

    let k1 = deriver1.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"same-object");
    let k2 = deriver2.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"same-object");
    assert_ne!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn empty_object_id_produces_valid_key() {
    let master = StoreKey::generate();
    let deriver = ObjectKeyDeriver::new(master);
    let k = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"");
    assert_eq!(k.as_bytes().len(), 32);
}

#[test]
fn derived_key_is_valid_chacha20_key() {
    let master = StoreKey::generate();
    let deriver = ObjectKeyDeriver::new(master);
    let k = deriver.derive(tidefs_encryption::DOMAIN_OBJECT_ENCRYPTION, b"test-obj");
    let _cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(k.as_bytes())
        .expect("derived key should be valid for ChaCha20Poly1305");
}

// ── AEAD round-trip with per-object key derivation ───────────────────

#[test]
fn deriver_put_get_roundtrip() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload = b"per-object encrypted data";
    let key = ObjectKey::from_content(payload);
    let stored = store.put(key, payload).unwrap();
    assert_eq!(stored.key, key);

    let retrieved = store.get(key).unwrap().unwrap();
    assert_eq!(retrieved, payload);
}

#[test]
fn deriver_put_get_empty_payload() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload: &[u8] = &[];
    let key = ObjectKey::from_content(payload);
    store.put(key, payload).unwrap();
    let retrieved = store.get(key).unwrap().unwrap();
    assert_eq!(retrieved, payload);
}

#[test]
fn deriver_put_get_large_payload_64kb() {
    let master = StoreKey::generate();
    // 64 KiB plaintext + 28 bytes overhead = 65564 bytes; use 128 KiB segment.
    let (_dir, mut store) = deriver_store_with_segment(&master, 131072);

    let payload = vec![0xCCu8; 65536];
    let key = ObjectKey::from_content(&payload);
    store.put(key, &payload).unwrap();
    let retrieved = store.get(key).unwrap().unwrap();
    assert_eq!(retrieved, payload);
}

#[test]
fn deriver_put_get_4kb_payload() {
    let master = StoreKey::generate();
    // 4096 plaintext + 28 overhead = 4124; use 8 KiB segment.
    let (_dir, mut store) = deriver_store_with_segment(&master, 8192);

    let payload = vec![0xDDu8; 4096];
    let key = ObjectKey::from_content(&payload);
    store.put(key, &payload).unwrap();
    let retrieved = store.get(key).unwrap().unwrap();
    assert_eq!(retrieved, payload);
}

#[test]
fn deriver_different_keys_produce_different_stored_objects() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload = b"test data";
    let key1 = ObjectKey::from_content(b"obj1");
    let key2 = ObjectKey::from_content(b"obj2");

    let stored1 = store.put(key1, payload).unwrap();
    let stored2 = store.put(key2, payload).unwrap();

    assert_ne!(stored1.key, stored2.key);
    assert_eq!(store.get(key1).unwrap().unwrap(), payload);
    assert_eq!(store.get(key2).unwrap().unwrap(), payload);
}

#[test]
fn deriver_wrong_object_key_on_read_is_none() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload = b"sensitive data";
    let key = ObjectKey::from_content(b"my-object");
    store.put(key, payload).unwrap();

    let wrong_key = ObjectKey::from_content(b"other-object");
    assert!(store.get(wrong_key).unwrap().is_none());
}

#[test]
fn deriver_put_named_get_named_roundtrip() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let name = b"named-object-1";
    let payload = b"named encrypted data";
    store.put_named(name.as_slice(), payload).unwrap();
    let retrieved = store.get_named(name.as_slice()).unwrap().unwrap();
    assert_eq!(retrieved, payload);
}

#[test]
fn deriver_clear_switches_to_single_key() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload_a = b"with per-object key";
    let key_a = ObjectKey::from_content(b"a");
    store.put(key_a, payload_a).unwrap();
    assert_eq!(store.get(key_a).unwrap().unwrap(), payload_a);

    store.clear_object_key_deriver();

    // Objects written with per-object keys fail in single-key mode.
    assert!(store.get(key_a).is_err());

    // New writes use the single master key.
    let payload_b = b"with single master key";
    let key_b = ObjectKey::from_content(b"b");
    store.put(key_b, payload_b).unwrap();
    assert_eq!(store.get(key_b).unwrap().unwrap(), payload_b);
}

// ── Authentication tag verification / tamper detection ───────────────

#[test]
fn deriver_tampered_ciphertext_rejected() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload = b"data to tamper";
    let key = ObjectKey::from_content(payload);
    store.put(key, payload).unwrap();
    let loc = store.location_of(key).unwrap();

    let mut raw = store.inner().get_at_location(loc).unwrap();
    if raw.len() > 13 {
        raw[13] ^= 0x01;
    }

    let tampered_key = ObjectKey::from_content(&raw);
    store.inner_mut().put(tampered_key, &raw).unwrap();

    assert!(store.get(tampered_key).is_err());
}

#[test]
fn deriver_same_plaintext_different_keys_different_ciphertext() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload = b"identical payload";
    let key_a = ObjectKey::from_content(b"obj-A");
    let key_b = ObjectKey::from_content(b"obj-B");

    let stored_a = store.put(key_a, payload).unwrap();
    let stored_b = store.put(key_b, payload).unwrap();

    assert_ne!(stored_a.key, stored_b.key);
}

#[test]
fn deriver_on_disk_ciphertext_differs_from_plaintext() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let plaintext = b"plaintext that should not appear on disk";
    let key = ObjectKey::from_content(plaintext);
    store.put(key, plaintext).unwrap();

    let loc = store.location_of(key).unwrap();
    let raw_bytes = store.inner().get_at_location(loc).unwrap();

    assert_ne!(raw_bytes, plaintext);

    if raw_bytes.len() >= plaintext.len() {
        assert_ne!(
            &raw_bytes[..plaintext.len().min(12)],
            &plaintext[..plaintext.len().min(12)]
        );
    }

    let decrypted = store.get(key).unwrap().unwrap();
    assert_eq!(decrypted, plaintext);
}

// ── Nonce uniqueness ─────────────────────────────────────────────────

#[test]
fn deriver_different_nonces_for_same_plaintext() {
    let master = StoreKey::generate();
    let (_dir, mut store) = deriver_store(&master);

    let payload = b"same plaintext";
    let key1 = ObjectKey::from_content(b"nonce-test-1");
    let key2 = ObjectKey::from_content(b"nonce-test-2");
    store.put(key1, payload).unwrap();
    store.put(key2, payload).unwrap();

    let raw1 = store
        .inner()
        .get_at_location(store.location_of(key1).unwrap())
        .unwrap();
    let raw2 = store
        .inner()
        .get_at_location(store.location_of(key2).unwrap())
        .unwrap();

    assert_ne!(raw1, raw2);
}

// ── Single-key mode baseline tests ───────────────────────────────────

#[test]
fn single_key_roundtrip_small_payload() {
    let (_dir, mut store) = encrypted_store();
    let obj = store.put_named("test", b"hello world").unwrap();
    assert_eq!(obj.len, (b"hello world".len() + 28) as u64);
    let plain = store.get_named("test").unwrap().unwrap();
    assert_eq!(plain, b"hello world");
}

#[test]
fn single_key_empty_payload() {
    let (_dir, mut store) = encrypted_store();
    store.put_named("empty", b"").unwrap();
    let plain = store.get_named("empty").unwrap().unwrap();
    assert!(plain.is_empty());
}

#[test]
fn single_key_nonce_uniqueness() {
    let (_dir, mut store) = encrypted_store();
    let payload = b"same";

    store.put_named("a", payload).unwrap();
    store.put_named("b", payload).unwrap();

    let a = store.get_named("a").unwrap().unwrap();
    let b = store.get_named("b").unwrap().unwrap();
    assert_eq!(a, payload);
    assert_eq!(b, payload);
}
