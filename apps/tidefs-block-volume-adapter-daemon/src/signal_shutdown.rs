// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Safe wrapper around the POSIX sigwait shutdown pattern used by live ublk
/// entrypoints.
pub struct SignalShutdownThread {
    handle: Option<JoinHandle<()>>,
}

impl SignalShutdownThread {
    pub fn finish(mut self) {
        // SAFETY: raise(3) targets the current process with SIGUSR1, which this
        // module reserves for waking the sigwait thread during orderly join.
        unsafe {
            libc::raise(libc::SIGUSR1);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Block SIGTERM/SIGINT in the caller and spawn a sigwait thread that flips
/// `shutdown` when either signal arrives. SIGUSR1 is reserved for
/// [`SignalShutdownThread::finish`].
///
/// # Errors
///
/// Returns an error string if `pthread_sigmask` rejects the signal mask.
pub fn install_signal_shutdown_thread(
    log_prefix: &'static str,
    shutdown: Arc<AtomicBool>,
) -> Result<SignalShutdownThread, String> {
    // SAFETY: sigset_t is a plain C signal-set object; POSIX requires callers
    // to initialize it with sigemptyset before passing it to pthread_sigmask.
    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: sigemptyset/sigaddset initialize only the stack sigset above,
    // and pthread_sigmask reads that initialized mask in the calling thread.
    unsafe {
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGINT);
        libc::sigaddset(&mut sigset, libc::SIGTERM);
        libc::sigaddset(&mut sigset, libc::SIGUSR1);
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
        if rc != 0 {
            return Err(format!("failed to block shutdown signals: {rc}"));
        }
    }

    let handle = std::thread::spawn(move || {
        // SAFETY: sigset_t is zeroed only to allocate the C object; the
        // following sigemptyset/sigaddset calls establish the valid mask.
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: the thread owns this stack sigset while building the mask
        // consumed by sigwait below.
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGINT);
            libc::sigaddset(&mut sigset, libc::SIGTERM);
            libc::sigaddset(&mut sigset, libc::SIGUSR1);
        }

        loop {
            let mut caught_sig: libc::c_int = 0;
            // SAFETY: sigwait writes one c_int to caught_sig and reads the
            // initialized mask local to this signal thread.
            let rc = unsafe { libc::sigwait(&sigset, &mut caught_sig) };
            if rc != 0 {
                continue;
            }
            if caught_sig == libc::SIGUSR1 {
                break;
            }
            eprintln!("{log_prefix}: received signal {caught_sig}, initiating graceful shutdown");
            shutdown.store(true, Ordering::Relaxed);
            break;
        }
    });

    Ok(SignalShutdownThread {
        handle: Some(handle),
    })
}
