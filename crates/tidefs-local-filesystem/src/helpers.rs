use tidefs_types_vfs_core::{
    NodeKind, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK,
};

use crate::constants::*;
use crate::error::FileSystemError;
use crate::Result;
pub fn parse_absolute_path(path: &str) -> Result<Vec<Vec<u8>>> {
    if path.is_empty() {
        return Err(FileSystemError::InvalidPath {
            path: path.to_string(),
            reason: "path is empty",
        });
    }
    if !path.starts_with('/') {
        return Err(FileSystemError::InvalidPath {
            path: path.to_string(),
            reason: "path must be absolute",
        });
    }
    if path != ROOT_PATH
        && path.as_bytes()[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty())
    {
        return Err(FileSystemError::InvalidPath {
            path: path.to_string(),
            reason: "empty path components are not accepted",
        });
    }
    let mut parts = Vec::new();
    for raw in path.as_bytes().split(|byte| *byte == b'/') {
        if raw.is_empty() {
            continue;
        }
        validate_name(raw)?;
        parts.push(raw.to_vec());
    }
    Ok(parts)
}

pub fn validate_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(FileSystemError::InvalidName {
            name: Vec::new(),
            reason: "path component is empty",
        });
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(FileSystemError::InvalidName {
            name: name.to_vec(),
            reason: "path component name too long (exceeds 255 bytes)",
        });
    }
    if name == b"." || name == b".." {
        return Err(FileSystemError::InvalidName {
            name: name.to_vec(),
            reason: ". and .. are not stored as real directory entries",
        });
    }
    if name.contains(&0) {
        return Err(FileSystemError::InvalidName {
            name: name.to_vec(),
            reason: "path component contains a NUL byte",
        });
    }
    if name.contains(&b'/') {
        return Err(FileSystemError::InvalidName {
            name: name.to_vec(),
            reason: "path component contains a slash",
        });
    }
    Ok(())
}

pub fn validate_snapshot_name(name: &[u8]) -> Result<()> {
    validate_name(name)
}

pub fn snapshot_name_bytes(name: &str) -> Result<Vec<u8>> {
    let bytes = name.as_bytes().to_vec();
    validate_snapshot_name(&bytes)?;
    Ok(bytes)
}

pub fn render_path(parts: &[Vec<u8>]) -> String {
    if parts.is_empty() {
        return ROOT_PATH.to_string();
    }
    let mut out = String::new();
    for part in parts {
        out.push('/');
        out.push_str(&String::from_utf8_lossy(part));
    }
    out
}

pub fn mode_for_kind(kind: NodeKind, permissions: u32) -> u32 {
    let default_permissions = match kind {
        NodeKind::Dir => DEFAULT_DIRECTORY_PERMISSIONS,
        NodeKind::Symlink => DEFAULT_SYMLINK_PERMISSIONS,
        _ => DEFAULT_FILE_PERMISSIONS,
    };
    kind_bits(kind)
        | if permissions == 0 {
            default_permissions
        } else {
            permissions & 0o7777
        }
}

pub fn kind_bits(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Dir => S_IFDIR,
        NodeKind::File => S_IFREG,
        NodeKind::Symlink => S_IFLNK,
        NodeKind::CharDev => S_IFCHR,
        NodeKind::BlockDev => S_IFBLK,
        NodeKind::Fifo => S_IFIFO,
        NodeKind::Socket => S_IFSOCK,
        NodeKind::Whiteout => 0,
    }
}
