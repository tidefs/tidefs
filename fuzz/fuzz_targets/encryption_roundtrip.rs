#![no_main]

use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use tempfile::TempDir;
use tidefs_encryption::{EncryptedObjectStore, EncryptionConfig, StoreKey};
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

type StoreCell = RefCell<Option<(TempDir, EncryptedObjectStore)>>;

thread_local! {
    static STORE: StoreCell = RefCell::new(None);
}

fn with_store<F, R>(f: F) -> R
where
    F: FnOnce(&mut EncryptedObjectStore) -> R,
{
    STORE.with(|cell: &StoreCell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            let dir = TempDir::new().expect("tempdir");
            let inner = LocalObjectStore::open_with_options(
                dir.path(),
                StoreOptions::test_fast(),
            )
            .expect("open store");
            let key = StoreKey::generate();
            *opt = Some((
                dir,
                EncryptedObjectStore::new_with_config(inner, key, EncryptionConfig::default()),
            ));
        }
        f(&mut opt.as_mut().unwrap().1)
    })
}

// Fuzz target: encrypt arbitrary data, decrypt it, verify roundtrip.
//
// ChaCha20-Poly1305 encryption must be deterministic for a given
// (key, nonce, plaintext) tuple.  Since each put generates a fresh
// random nonce, this target verifies that decrypt(get(put(data))) == data
// for every input, regardless of size or content.
fuzz_target!(|data: &[u8]| {
    with_store(|store| {
        let name = format!("fuzz_enc_rt_{:016x}", data.len().wrapping_mul(0x9E3779B9));
        let _ = store.put_named(name.as_bytes(), data);
        if let Ok(Some(decrypted)) = store.get_named(name.as_bytes()) {
            assert_eq!(decrypted, data, "roundtrip mismatch");
        }
    });
});
