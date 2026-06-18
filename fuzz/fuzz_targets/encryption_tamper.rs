// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
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

// Fuzz target: encrypt data, tamper with ciphertext, verify decryption
// fails gracefully (no panic, no undefined behavior).
//
// Tampering can target the nonce, ciphertext, or Poly1305 tag.  The
// fuzzer picks both the data and the tamper offset/corruption.
fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let payload = &data[..data.len() - 2];
    let tamper_offset_raw = data[data.len() - 2] as usize;
    let tamper_byte = data[data.len() - 1];

    with_store(|store| {
        let name = b"fuzz_tmp";
        store.put_named(name, payload).ok();

        // Read the stored ciphertext from the inner store.
        let Some(ct) = store.inner().get_named(name).unwrap() else {
            return;
        };

        // Corrupt the ciphertext at the fuzzer-chosen offset.
        let mut corrupted = ct;
        let len = corrupted.len();
        if len > 0 {
            let idx = tamper_offset_raw % len;
            corrupted[idx] ^= tamper_byte;
        }

        // Store the corrupted frame back via the inner store (bypassing encryption).
        store.inner_mut().put_named(name, &corrupted).ok();

        // Decryption must either succeed (if corruption didn't affect the tag)
        // or return an error — it must never panic.
        let _ = store.get_named(name);
    });
});
