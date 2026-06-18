// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(dead_code)]
//! Shared test helpers for tidefs-local-filesystem integration tests.
//!
//! Provides commonly-used setup utilities and a declarative directory-tree
//! builder so Review debt TFR-004 tests can construct known directory states without
//! repeating boilerplate.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

// ── Key setup ─────────────────────────────────────────────────────────

pub fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

// ── Temp dir + open ───────────────────────────────────────────────────

pub fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-do-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

pub fn open_fs(dir: &Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

// ── Directory-tree builder ────────────────────────────────────────────

/// Node in a declarative directory tree.
#[derive(Clone, Debug)]
pub enum TreeNode {
    /// An empty directory.
    Dir {
        name: &'static str,
        mode: u32,
        children: Vec<TreeNode>,
    },
    /// A regular file (no data written).
    File { name: &'static str, mode: u32 },
    /// A symlink with the given target bytes.
    Symlink {
        name: &'static str,
        target: &'static [u8],
    },
}

impl TreeNode {
    pub fn dir(name: &'static str) -> Self {
        TreeNode::Dir {
            name,
            mode: 0o755,
            children: vec![],
        }
    }

    pub fn file(name: &'static str) -> Self {
        TreeNode::File { name, mode: 0o644 }
    }

    pub fn symlink(name: &'static str, target: &'static [u8]) -> Self {
        TreeNode::Symlink { name, target }
    }

    /// Shortcut: add multiple children to a Dir node (builder-style).
    pub fn with(mut self, new_children: Vec<TreeNode>) -> Self {
        if let TreeNode::Dir {
            ref mut children, ..
        } = self
        {
            *children = new_children;
        }
        self
    }
}

/// Recursively create a directory tree under `prefix`.
///
/// Returns the list of absolute paths created (directories first, then
/// files and symlinks), so callers can verify them after a reopen.
pub fn create_tree(fs: &mut LocalFileSystem, prefix: &str, nodes: &[TreeNode]) -> Vec<String> {
    let mut created = Vec::new();
    let _ = fs.create_dir(prefix, 0o755); // ensure parent exists
    for node in nodes {
        create_tree_node(fs, prefix, node, &mut created);
    }
    created
}

fn create_tree_node(
    fs: &mut LocalFileSystem,
    prefix: &str,
    node: &TreeNode,
    out: &mut Vec<String>,
) {
    match node {
        TreeNode::Dir {
            name,
            mode,
            children,
        } => {
            let path = format!("{prefix}/{name}");
            let _ = fs.create_dir(&path, *mode);
            out.push(path.clone());
            for child in children {
                create_tree_node(fs, &path, child, out);
            }
        }
        TreeNode::File { name, mode } => {
            let path = format!("{prefix}/{name}");
            let _ = fs.create_file(&path, *mode);
            out.push(path);
        }
        TreeNode::Symlink { name, target } => {
            let path = format!("{prefix}/{name}");
            let _ = fs.create_symlink(&path, target);
            out.push(path);
        }
    }
}

/// Verify that every path in `paths` is reachable via `lookup` after a
/// fresh open of the store at `root_dir`.
pub fn verify_tree_after_reopen(root_dir: &Path, paths: &[String]) {
    let fs = LocalFileSystem::open(root_dir).expect("reopen for tree verification");
    for path in paths {
        assert!(fs.lookup(path).is_ok(), "path {path} must survive reopen");
    }
}

/// Create a flat directory with `count` numbered files and return their
/// absolute paths. Used by large-directory tests.
pub fn create_numbered_files(fs: &mut LocalFileSystem, dir_path: &str, count: u32) -> Vec<String> {
    fs.create_dir(dir_path, 0o755)
        .expect("create numbered-files dir");
    let mut paths = Vec::with_capacity(count as usize);
    for i in 0..count {
        let name = format!("f_{i:05}.dat");
        let path = format!("{dir_path}/{name}");
        fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
            .expect("create numbered file");
        paths.push(path);
    }
    paths
}
