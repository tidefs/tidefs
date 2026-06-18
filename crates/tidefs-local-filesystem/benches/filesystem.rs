// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::fs;
use std::path::PathBuf;
use tidefs_local_filesystem::LocalFileSystem;

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_root(name: &str) -> PathBuf {
    // Benchmarks may run without the auth key pre-configured.
    // Set it once so LocalFileSystem::open succeeds.
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
    let root = std::env::temp_dir().join(format!("tidefs-bench-{name}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create bench temp dir");
    root
}

fn bench_create_file(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-create-file");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    let mut counter = 0_u64;

    c.bench_function("filesystem/create_file", |b| {
        b.iter(|| {
            counter += 1;
            let path = format!("/file-{counter}");
            let _ = black_box(fs.create_file(&path, 0o644).expect("create file"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_write_read_small_file(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-write-read");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    let data = [0xAB_u8; 256];
    let mut counter = 0_u64;

    c.bench_function("filesystem/write_read_small", |b| {
        b.iter(|| {
            counter += 1;
            let path = format!("/f-{counter}");
            fs.create_file(&path, 0o644).expect("create");
            fs.write_file(&path, 0, &data).expect("write");
            let result = fs.read_file(&path).expect("read");
            assert_eq!(result, data);
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_create_dir(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-create-dir");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    let mut counter = 0_u64;

    c.bench_function("filesystem/create_dir", |b| {
        b.iter(|| {
            counter += 1;
            let path = format!("/dir-{counter}");
            let _ = black_box(fs.create_dir(&path, 0o755).expect("create dir"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_statfs(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-statfs");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");

    c.bench_function("filesystem/statfs", |b| {
        b.iter(|| {
            let _ = black_box(fs.statfs().expect("statfs"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_lookup(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-lookup");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    fs.create_file("/target", 0o644).expect("create");

    c.bench_function("filesystem/lookup", |b| {
        b.iter(|| {
            let _ = black_box(fs.lookup("/target").expect("lookup"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_list_dir(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-list-dir");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    for i in 0..100 {
        fs.create_file(format!("/f-{i}"), 0o644).expect("create");
    }

    c.bench_function("filesystem/list_dir", |b| {
        b.iter(|| {
            let _ = black_box(fs.list_dir("/").expect("list dir"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_read_file_standalone(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-read-standalone");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    fs.create_file("/data", 0o644).expect("create");
    fs.write_file("/data", 0, &[0xCD_u8; 4096]).expect("write");

    c.bench_function("filesystem/read_file", |b| {
        b.iter(|| {
            let _ = black_box(fs.read_file("/data").expect("read"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_unlink(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-unlink");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    let mut counter = 0_u64;

    c.bench_function("filesystem/unlink", |b| {
        b.iter(|| {
            counter += 1;
            let path = format!("/del-{counter}");
            fs.create_file(&path, 0o644).expect("create");
            {
                fs.unlink(&path).expect("unlink");
                black_box(())
            };
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_rename(c: &mut Criterion) {
    set_test_key();
    let root = temp_root("fs-rename");
    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    let mut counter = 0_u64;

    c.bench_function("filesystem/rename", |b| {
        b.iter(|| {
            counter += 1;
            let src = format!("/src-{counter}");
            let dst = format!("/dst-{counter}");
            fs.create_file(&src, 0o644).expect("create");
            {
                fs.rename(&src, &dst, false).expect("rename");
                black_box(())
            };
        })
    });

    let _ = fs::remove_dir_all(&root);
}

criterion_group!(
    benches,
    bench_create_file,
    bench_write_read_small_file,
    bench_create_dir,
    bench_statfs,
    bench_lookup,
    bench_list_dir,
    bench_read_file_standalone,
    bench_unlink,
    bench_rename,
);
criterion_main!(benches);
