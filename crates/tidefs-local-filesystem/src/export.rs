// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Read-only snapshot export sessions.

use std::mem;
use std::path::Path;

use tidefs_inode_attributes::timestamp::TimestampPolicy;
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_types_vfs_core::InodeId;

use crate::error::FileSystemError;
use crate::helpers::parse_absolute_path;
use crate::recovery::{load_state_from_transaction, root_commit_from_summary};
use crate::types::{CommittedRootSummary, SnapshotSummary};
use crate::vfs_engine_impl::VfsLocalFileSystem;
use crate::{FileSystemState, LocalFileSystem, LocalFileSystemOpenConfig, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotExportSummary {
    pub snapshot: SnapshotSummary,
    pub exported_root: CommittedRootSummary,
    pub root_inode_id: InodeId,
    pub generation: u64,
}

pub struct SnapshotExportSession {
    summary: SnapshotExportSummary,
    engine: Option<VfsLocalFileSystem>,
    /// Filesystem root path, stored for hold release on drop.
    root: std::path::PathBuf,
    /// Snapshot name, stored for hold release on drop.
    snapshot_name: String,
}

impl SnapshotExportSession {
    #[must_use]
    pub fn summary(&self) -> &SnapshotExportSummary {
        &self.summary
    }

    #[must_use]
    pub fn into_engine(mut self) -> VfsLocalFileSystem {
        self.engine
            .take()
            .expect("SnapshotExportSession engine already consumed")
    }
}

impl Drop for SnapshotExportSession {
    fn drop(&mut self) {
        // Release the export hold. If the engine is still present
        // (SnapshotExportSession dropped without into_engine()), close it
        // first so the filesystem handle is released, then reopen to
        // release the hold. If the engine was already consumed via
        // into_engine(), skip the reopen attempt and leave the hold
        // for stale-export-hold recovery on the next pool open.
        if self.engine.take().is_some() {
            // Engine dropped here (filesystem closed). Reopen to release.
            if let Ok(mut fs) = LocalFileSystem::open(&self.root) {
                let _ = fs.release_snapshot(&self.snapshot_name);
            }
        }
    }
}

impl LocalFileSystem {
    pub fn normalize_snapshot_extract_path(path: impl AsRef<str>) -> Result<String> {
        let path = path.as_ref();
        let normalized = if path.is_empty() {
            return Err(FileSystemError::InvalidPath {
                path: path.to_string(),
                reason: "path is empty",
            });
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        parse_absolute_path(&normalized)?;
        Ok(normalized)
    }

    pub fn open_snapshot_export(
        root: impl AsRef<Path>,
        snapshot_name: impl AsRef<str>,
        mut config: LocalFileSystemOpenConfig<'_>,
    ) -> Result<SnapshotExportSession> {
        let root = root.as_ref();
        let snapshot_name = snapshot_name.as_ref();
        if config.block_devices.is_none() {
            let device_path = Self::default_development_device_path(root);
            if !device_path.exists() {
                return Err(FileSystemError::SnapshotNotFound {
                    name: snapshot_name.to_string(),
                });
            }
        }
        config.recovery_policy = RecoveryPolicy::ReadOnly;
        config.log_device_device_path = None;

        let root_path = root.to_path_buf();
        let snapshot_name_owned = snapshot_name.to_string();
        let mut fs = Self::open_with_allocator_policy_and_root_authentication_key(root, config)?;
        let (summary, exported_state) = fs.load_snapshot_export_state(&snapshot_name_owned)?;

        // All fallible setup is complete. Acquire an export hold on the
        // snapshot so deletion is blocked while the export session is active.
        fs.hold_snapshot_tagged(&snapshot_name_owned, Some("export"))?;
        fs.stop_background_scheduler();
        fs.state = exported_state;
        fs.auto_commit = false;
        fs.uncommitted_mutation_count = 0;
        fs.recovery_policy = RecoveryPolicy::ReadOnly;
        fs.write_buffers.clear();
        fs.pending_permits.clear();
        fs.dirty_set = Default::default();

        let mut engine = VfsLocalFileSystem::new(fs).with_read_only();
        engine.set_timestamp_policy(TimestampPolicy::Noatime);
        Ok(SnapshotExportSession {
            summary,
            engine: Some(engine),
            root: root_path,
            snapshot_name: snapshot_name_owned,
        })
    }

    pub fn extract_snapshot_file(
        root: impl AsRef<Path>,
        snapshot_name: impl AsRef<str>,
        file_path: impl AsRef<str>,
        mut config: LocalFileSystemOpenConfig<'_>,
    ) -> Result<Vec<u8>> {
        let root = root.as_ref();
        let snapshot_name = snapshot_name.as_ref();
        if config.block_devices.is_none() {
            let device_path = Self::default_development_device_path(root);
            if !device_path.exists() {
                return Err(FileSystemError::SnapshotNotFound {
                    name: snapshot_name.to_string(),
                });
            }
        }
        config.recovery_policy = RecoveryPolicy::ReadOnly;
        config.log_device_device_path = None;

        let mut fs = Self::open_with_allocator_policy_and_root_authentication_key(root, config)?;
        fs.extract_snapshot_file_from_open_pool(snapshot_name, file_path)
    }

    pub fn extract_snapshot_file_from_open_pool(
        &mut self,
        snapshot_name: impl AsRef<str>,
        file_path: impl AsRef<str>,
    ) -> Result<Vec<u8>> {
        let snapshot_name = snapshot_name.as_ref();
        let file_path = Self::normalize_snapshot_extract_path(file_path)?;
        let (_summary, exported_state) = self.load_snapshot_export_state(snapshot_name)?;

        self.hold_snapshot_tagged(snapshot_name, Some("export"))?;
        self.stop_background_scheduler();
        let live_state = mem::replace(&mut self.state, exported_state);
        let live_write_buffers = mem::take(&mut self.write_buffers);
        let live_auto_commit = mem::replace(&mut self.auto_commit, false);
        let live_recovery_policy = mem::replace(&mut self.recovery_policy, RecoveryPolicy::ReadOnly);
        let live_pending_permits = mem::take(&mut self.pending_permits);
        let live_dirty_set = mem::take(&mut self.dirty_set);
        self.uncommitted_mutation_count = 0;
        self.clear_snapshot_extract_caches();

        let read_result = self.read_file(&file_path);

        self.auto_commit = live_auto_commit;
        self.recovery_policy = live_recovery_policy;
        self.pending_permits = live_pending_permits;
        self.dirty_set = live_dirty_set;
        self.state = live_state;
        self.write_buffers = live_write_buffers;
        self.clear_snapshot_extract_caches();

        let release_result = self.release_snapshot(snapshot_name);
        match (read_result, release_result) {
            (Ok(bytes), Ok(_)) => Ok(bytes),
            (Err(err), _) => Err(err),
            (Ok(_), Err(err)) => Err(err),
        }
    }

    fn load_snapshot_export_state(
        &mut self,
        snapshot_name: &str,
    ) -> Result<(SnapshotExportSummary, FileSystemState)> {
        let snapshot = self.snapshot_summary(snapshot_name)?;
        let exported_root = snapshot.source_root.clone();
        let root = root_commit_from_summary(&exported_root);
        let exported_state = load_state_from_transaction(
            self.store.raw_primary_store_mut(),
            &root,
            self.root_authentication_key,
        )?;
        let summary = SnapshotExportSummary {
            snapshot,
            exported_root,
            root_inode_id: exported_state.inode_authority.root_inode_id(),
            generation: exported_state.generation,
        };
        Ok((summary, exported_state))
    }

    fn clear_snapshot_extract_caches(&self) {
        self.inode_cache.borrow_mut().clear();
        self.hot_read_cache.borrow_mut().clear();
        self.content_layout_cache.borrow_mut().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_recovery_loop::RecoveryPolicy;
    use tidefs_types_vfs_core::{Errno, RequestCtx, ROOT_INODE_ID};
    use tidefs_vfs_engine::VfsEngine;

    use crate::human::local_filesystem::StoreOptions;
    use crate::{default_root_authentication_key, LocalStorageAllocatorPolicy};

    fn ctx() -> RequestCtx {
        RequestCtx {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![0],
        }
    }

    fn open_config() -> LocalFileSystemOpenConfig<'static> {
        LocalFileSystemOpenConfig {
            options: StoreOptions::test_fast(),
            allocator_policy: LocalStorageAllocatorPolicy::default(),
            root_authentication_key: default_root_authentication_key().expect("auth key"),
            encryption: None,
            compression: None,
            log_device_device_path: None,
            recovery_policy: RecoveryPolicy::default(),
            block_devices: None,
        }
    }

    #[test]
    fn snapshot_export_session_reads_snapshot_and_rejects_mutations() {
        let root = tempfile::tempdir().expect("tempdir");
        {
            let mut fs = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
                .expect("open filesystem");
            fs.create_file("/before.txt", 0o644).expect("create file");
            fs.write_file("/before.txt", 0, b"snapshot bytes")
                .expect("write file");
            fs.create_dir("/dir", 0o755).expect("create dir");
            fs.create_symlink("/link", b"before.txt")
                .expect("create symlink");
            fs.create_snapshot("snap0").expect("create snapshot");
            fs.unlink("/before.txt").expect("unlink live file");
            fs.create_file("/after.txt", 0o644).expect("create after");
        }

        let session = LocalFileSystem::open_snapshot_export(root.path(), "snap0", open_config())
            .expect("open export");
        let summary = session.summary().clone();
        assert_eq!(summary.snapshot.name, "snap0");
        assert_eq!(summary.exported_root, summary.snapshot.source_root);

        let engine = session.into_engine();
        assert!(engine.is_read_only());
        let ctx = ctx();
        let file = engine
            .lookup(ROOT_INODE_ID, b"before.txt", &ctx)
            .expect("snapshot file lookup");
        let handle = engine
            .open(file.inode_id, 0, &ctx)
            .expect("open snapshot file");
        assert_eq!(
            engine
                .read(&handle, 0, 64, &ctx)
                .expect("read snapshot file"),
            b"snapshot bytes"
        );
        engine.release(&handle).expect("release handle");

        let link = engine
            .lookup(ROOT_INODE_ID, b"link", &ctx)
            .expect("snapshot symlink lookup");
        assert_eq!(
            engine.readlink(link.inode_id, &ctx).expect("read symlink"),
            b"before.txt"
        );
        assert!(engine.lookup(ROOT_INODE_ID, b"dir", &ctx).is_ok());
        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"after.txt", &ctx),
            Err(Errno::ENOENT)
        );

        assert_eq!(
            engine.create(ROOT_INODE_ID, b"new.txt", 0o644, 0, &ctx),
            Err(Errno::EROFS)
        );
        assert_eq!(engine.write(&handle, 0, b"nope", &ctx), Err(Errno::EROFS));
        assert_eq!(
            engine.unlink(ROOT_INODE_ID, b"before.txt", &ctx),
            Err(Errno::EROFS)
        );

        let live = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
            .expect("reopen live");
        assert!(live.lookup("/before.txt").is_err());
        assert!(live.lookup("/after.txt").is_ok());
    }

    #[test]
    fn snapshot_extract_reads_file_bytes_from_snapshot_root() {
        let root = tempfile::tempdir().expect("tempdir");
        {
            let mut fs = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
                .expect("open filesystem");
            fs.create_dir("/dir", 0o755).expect("create dir");
            fs.create_file("/dir/lost.txt", 0o644).expect("create file");
            fs.write_file("/dir/lost.txt", 0, b"snapshot payload")
                .expect("write file");
            fs.create_snapshot("snap0").expect("create snapshot");
            fs.write_file("/dir/lost.txt", 0, b"live payloaddata")
                .expect("mutate live file");
        }

        let relative = LocalFileSystem::extract_snapshot_file(
            root.path(),
            "snap0",
            "dir/lost.txt",
            open_config(),
        )
        .expect("extract relative path");
        assert_eq!(relative, b"snapshot payload");

        let absolute = LocalFileSystem::extract_snapshot_file(
            root.path(),
            "snap0",
            "/dir/lost.txt",
            open_config(),
        )
        .expect("extract absolute path");
        assert_eq!(absolute, b"snapshot payload");
    }

    #[test]
    fn snapshot_extract_from_open_pool_ignores_live_inode_cache() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut fs = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
            .expect("open filesystem");
        fs.create_file("/lost.txt", 0o644).expect("create file");
        fs.write_file("/lost.txt", 0, b"snapshot payload")
            .expect("write snapshot file");
        fs.create_snapshot("snap0").expect("create snapshot");
        fs.write_file("/lost.txt", 0, b"live payloaddata")
            .expect("mutate live file");

        assert_eq!(
            fs.read_file("/lost.txt").expect("prime live inode cache"),
            b"live payloaddata"
        );

        let extracted = fs
            .extract_snapshot_file_from_open_pool("snap0", "/lost.txt")
            .expect("extract snapshot file");
        assert_eq!(extracted, b"snapshot payload");
        assert_eq!(
            fs.read_file("/lost.txt")
                .expect("read live file after extract"),
            b"live payloaddata"
        );
    }

    #[test]
    fn snapshot_extract_reports_missing_snapshot_and_path() {
        let root = tempfile::tempdir().expect("tempdir");
        {
            let mut fs = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
                .expect("open filesystem");
            fs.create_snapshot("snap0").expect("create snapshot");
        }

        let missing_snapshot = LocalFileSystem::extract_snapshot_file(
            root.path(),
            "missing",
            "/file.txt",
            open_config(),
        )
        .expect_err("missing snapshot must fail");
        assert!(matches!(
            missing_snapshot,
            FileSystemError::SnapshotNotFound { name } if name == "missing"
        ));

        let missing_path = LocalFileSystem::extract_snapshot_file(
            root.path(),
            "snap0",
            "/missing.txt",
            open_config(),
        )
        .expect_err("missing path must fail");
        assert!(matches!(
            missing_path,
            FileSystemError::NotFound { path } if path == "/missing.txt"
        ));
    }

    #[test]
    fn snapshot_extract_rejects_non_regular_files() {
        let root = tempfile::tempdir().expect("tempdir");
        {
            let mut fs = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
                .expect("open filesystem");
            fs.create_dir("/dir", 0o755).expect("create dir");
            fs.create_symlink("/link", b"dir").expect("create symlink");
            fs.create_snapshot("snap0").expect("create snapshot");
        }

        let dir_err =
            LocalFileSystem::extract_snapshot_file(root.path(), "snap0", "/dir", open_config())
                .expect_err("directory extract must fail");
        assert!(matches!(
            dir_err,
            FileSystemError::IsDirectory { path } if path == "/dir"
        ));

        let link_err =
            LocalFileSystem::extract_snapshot_file(root.path(), "snap0", "/link", open_config())
                .expect_err("symlink extract must fail");
        assert!(matches!(
            link_err,
            FileSystemError::NotFile { path, kind } if path == "/link" && kind == tidefs_types_vfs_core::NodeKind::Symlink
        ));
    }

    #[test]
    fn snapshot_extract_does_not_mutate_live_namespace_or_expose_dot_snapshot() {
        let root = tempfile::tempdir().expect("tempdir");
        {
            let mut fs = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
                .expect("open filesystem");
            fs.create_file("/before.txt", 0o644).expect("create before");
            fs.write_file("/before.txt", 0, b"before")
                .expect("write before");
            fs.create_snapshot("snap0").expect("create snapshot");
            fs.unlink("/before.txt").expect("unlink live before");
            fs.create_file("/after.txt", 0o644).expect("create after");
            fs.write_file("/after.txt", 0, b"after")
                .expect("write after");
        }

        let extracted = LocalFileSystem::extract_snapshot_file(
            root.path(),
            "snap0",
            "/before.txt",
            open_config(),
        )
        .expect("extract removed live file");
        assert_eq!(extracted, b"before");

        let dot_snapshot = LocalFileSystem::extract_snapshot_file(
            root.path(),
            "snap0",
            "/.snapshot/snap0/before.txt",
            open_config(),
        )
        .expect_err("transparent .snapshot browsing must not appear");
        assert!(matches!(dot_snapshot, FileSystemError::NotFound { .. }));

        let live = LocalFileSystem::open_with_options(root.path(), StoreOptions::test_fast())
            .expect("reopen live");
        assert!(live.lookup("/before.txt").is_err());
        assert_eq!(
            live.read_file("/after.txt").expect("read live after"),
            b"after"
        );
    }
}
