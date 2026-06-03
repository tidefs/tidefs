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
    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
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
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGINT);
            libc::sigaddset(&mut sigset, libc::SIGTERM);
            libc::sigaddset(&mut sigset, libc::SIGUSR1);
        }

        loop {
            let mut caught_sig: libc::c_int = 0;
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
