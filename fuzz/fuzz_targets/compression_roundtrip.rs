#![no_main]

use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use tempfile::TempDir;
use tidefs_compression::{CompressedObjectStore, CompressionAlgorithm, CompressionConfig};
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

type ZstdCell = RefCell<Option<(TempDir, CompressedObjectStore)>>;
type Lz4Cell = RefCell<Option<(TempDir, CompressedObjectStore)>>;

thread_local! {
    static STORE_ZSTD: ZstdCell = RefCell::new(None);
    static STORE_LZ4: Lz4Cell = RefCell::new(None);
}

fn with_zstd<F, R>(f: F) -> R
where
    F: FnOnce(&mut CompressedObjectStore) -> R,
{
    STORE_ZSTD.with(|cell: &ZstdCell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            let dir = TempDir::new().expect("tempdir zstd");
            let inner = LocalObjectStore::open_with_options(
                dir.path(),
                StoreOptions::test_fast(),
            )
            .expect("open zstd store");
            *opt = Some((
                dir,
                CompressedObjectStore::new(
                    inner,
                    CompressionConfig {
                        algorithm: CompressionAlgorithm::Zstd,
                        level: 3,
                        min_compress_bytes: 0,
                    },
                ),
            ));
        }
        f(&mut opt.as_mut().unwrap().1)
    })
}

fn with_lz4<F, R>(f: F) -> R
where
    F: FnOnce(&mut CompressedObjectStore) -> R,
{
    STORE_LZ4.with(|cell: &Lz4Cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            let dir = TempDir::new().expect("tempdir lz4");
            let inner = LocalObjectStore::open_with_options(
                dir.path(),
                StoreOptions::test_fast(),
            )
            .expect("open lz4 store");
            *opt = Some((
                dir,
                CompressedObjectStore::new(
                    inner,
                    CompressionConfig {
                        algorithm: CompressionAlgorithm::Lz4,
                        level: 0,
                        min_compress_bytes: 0,
                    },
                ),
            ));
        }
        f(&mut opt.as_mut().unwrap().1)
    })
}

// Fuzz target: compress arbitrary data with both zstd and LZ4, decompress,
// verify roundtrip equality.
//
// The compression layer must be deterministic: identical plaintext with
// the same algorithm and level must produce identical decompressed output.
fuzz_target!(|data: &[u8]| {
    with_zstd(|store| {
        store.put_named(b"fuzz_zstd", data).ok();
        if let Ok(Some(decompressed)) = store.get_named(b"fuzz_zstd") {
            assert_eq!(decompressed, data, "zstd roundtrip mismatch");
        }
    });

    with_lz4(|store| {
        store.put_named(b"fuzz_lz4", data).ok();
        if let Ok(Some(decompressed)) = store.get_named(b"fuzz_lz4") {
            assert_eq!(decompressed, data, "lz4 roundtrip mismatch");
        }
    });
});
