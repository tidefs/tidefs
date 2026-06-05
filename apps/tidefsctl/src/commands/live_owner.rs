//! Imported-pool live-owner routing helpers.
//!
//! A pool name is an identity for state already owned by a runtime, not a
//! filesystem path. Until the kernel UAPI and userspace daemon clients are
//! wired here, imported-pool commands must fail closed instead of reopening
//! local storage behind the owner.

use std::process;

pub(crate) fn exit_missing_client(command: &str, operation: &str, pool: &str) -> ! {
    eprintln!(
        "tidefsctl {command} {operation}: pool '{pool}' is an imported-pool identity, not a backing path"
    );
    eprintln!(
        "tidefsctl {command} {operation}: live pool state is cached and owned by the active runtime"
    );
    eprintln!(
        "tidefsctl {command} {operation}: wire the kernel UAPI or userspace daemon owner client before using this pool-name form"
    );
    eprintln!(
        "tidefsctl {command} {operation}: use explicit --devices or --backing-dir only for offline, discovery, import, or not-yet-imported work"
    );
    process::exit(1);
}
