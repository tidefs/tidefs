// SPDX-License-Identifier: GPL-2.0
//! Minimal Rust-for-Linux out-of-tree smoke module.
//!
//! This module proves the hot-loop toolchain end-to-end: Linux 7.0 kernel build
//! tree, Rust support, out-of-tree module build, and disposable QEMU
//! load/verification. It exercises `kernel::prelude` and the `module!()` macro,
//! logs its presence, and exits cleanly.
//!
//! It is not a product kernel-module leaf; it is a build-system and load-path
//! smoke fixture for the K7-04B development loop.

use kernel::prelude::*;

module! {
    type: TidefsSmoke,
    name: "tidefs_smoke",
    authors: ["TideFS Project"],
    description: "TideFS K7-04B kernel-module hot-loop smoke module",
    license: "GPL",
}

struct TidefsSmoke;

impl kernel::Module for TidefsSmoke {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("tidefs_smoke: K7-04B hot-loop smoke module loaded (Linux 7.0 Rust-for-Linux)\n");
        Ok(TidefsSmoke)
    }
}

impl Drop for TidefsSmoke {
    fn drop(&mut self) {
        pr_info!("tidefs_smoke: K7-04B hot-loop smoke module unloaded\n");
    }
}
