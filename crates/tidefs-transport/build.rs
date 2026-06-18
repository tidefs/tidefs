// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
fn main() {
    let mut shim = cc::Build::new();
    shim.file("src/rdma/verbs_shim.c");

    if let Some(include_dir) = find_host_rdma_core_include() {
        shim.include(include_dir);
    }

    shim.compile("tidefs_rdma_verbs_shim");

    // RDMA linking: libibverbs.so.1 is present at runtime but the
    // .so symlink needed for compile-time linking is not. Create a
    // symlink in OUT_DIR and add it to the linker search path so
    // extern "C" declarations resolve against libibverbs.
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into());
    let verbs_lib = "/usr/lib/x86_64-linux-gnu/libibverbs.so.1";
    let link_sym = format!("{out_dir}/libibverbs.so");
    let _ = std::os::unix::fs::symlink(verbs_lib, &link_sym);
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=ibverbs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/rdma/verbs_shim.c");
}

fn find_host_rdma_core_include() -> Option<std::path::PathBuf> {
    let usr = std::path::Path::new("/usr/include/infiniband/verbs.h");
    if usr.exists() {
        return Some(std::path::PathBuf::from("/usr/include"));
    }

    let entries = std::fs::read_dir("/nix/store").ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name()?.to_string_lossy();
        if !name.contains("rdma-core") || !name.contains("-dev") {
            continue;
        }
        let include = path.join("include");
        if include.join("infiniband/verbs.h").exists() {
            return Some(include);
        }
    }

    None
}
