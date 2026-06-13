pub mod block;
pub mod classification;
pub mod cluster;
pub mod dataset;
pub mod defrag;
pub mod device;
pub mod diag;
pub mod kernel;
mod live_owner;
pub mod mount;
mod offline_pool;
pub mod pool;
pub mod snapshot;

pub(crate) use offline_pool::refuse_runtime_pool_path;

use std::path::PathBuf;

pub(crate) fn reject_directory_pool_media_value(raw: &str) -> Result<PathBuf, String> {
    Err(retired_directory_pool_media_message(raw))
}

pub(crate) fn retired_directory_pool_media_message(raw: &str) -> String {
    format!(
        "directory-backed object-store pool media `{raw}` is retired; use a pool name routed to the live owner, or explicit --devices block-device / regular-file development pool media where offline access is supported"
    )
}
