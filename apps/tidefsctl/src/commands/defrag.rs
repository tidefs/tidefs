//! `tidefs defrag` -- trigger online extent map defragmentation via
//! the `TIDEFS_IOC_DEFRAG` ioctl.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Handle `tidefs defrag <path> [--recursive]`.
pub fn handle_defrag(path: &Path, recursive: bool) {
    match run_defrag(path, recursive) {
        Ok((before, after, reduction, inodes)) => {
            println!("extents_before: {before}");
            println!("extents_after: {after}");
            println!("fragmentation_reduction: {:.2}%", reduction as f64 / 100.0);
            println!("inodes_defragmented: {inodes}");
        }
        Err(e) => {
            eprintln!("tidefs defrag: {e}");
            std::process::exit(1);
        }
    }
}

/// Open `path`, stat for inode, issue `TIDEFS_IOC_DEFRAG`, decode reply.
fn run_defrag(path: &Path, recursive: bool) -> io::Result<(u64, u64, u32, u64)> {
    let meta = fs::symlink_metadata(path)?;
    let ino = meta.ino();

    let file = fs::OpenOptions::new().read(true).open(path)?;
    let fd = file.as_raw_fd();

    tidefs_posix_filesystem_adapter_daemon::tidefs_defrag_ioctl(fd, ino, recursive)
}
