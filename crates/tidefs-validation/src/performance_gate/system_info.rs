// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::gate_entry::{EnvironmentManifest, NoisePolicy};
use std::process::Command;

pub fn capture_environment(
    profile_ref: &str,
    storage_backend: &str,
    cache_mode: &str,
) -> EnvironmentManifest {
    EnvironmentManifest {
        profile_ref: profile_ref.to_string(),
        host_class: hostname(),
        cpu_count: ncpus(),
        memory_bytes: mem(),
        kernel_version: kver(),
        storage_backend: storage_backend.to_string(),
        cache_mode: cache_mode.to_string(),
        feature_flags: Vec::new(),
        background_load: None,
        noise_policy: NoisePolicy {
            ref_id: "noise.n0".into(),
            warmup_samples: 3,
            min_samples: 10,
            max_cv: 0.10,
        },
    }
}
fn ncpus() -> u32 {
    if let Ok(o) = Command::new("nproc").output() {
        if let Ok(s) = String::from_utf8(o.stdout) {
            if let Ok(n) = s.trim().parse::<u32>() {
                return n;
            }
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}
fn mem() -> u64 {
    if let Ok(c) = std::fs::read_to_string("/proc/meminfo") {
        for l in c.lines() {
            if l.starts_with("MemTotal:") {
                let kb: Vec<&str> = l.split_whitespace().collect();
                if kb.len() >= 2 {
                    if let Ok(v) = kb[1].parse::<u64>() {
                        return v * 1024;
                    }
                }
            }
        }
    }
    0
}
fn kver() -> String {
    if let Ok(o) = Command::new("uname").arg("-r").output() {
        if let Ok(s) = String::from_utf8(o.stdout) {
            return s.trim().to_string();
        }
    }
    "unknown".into()
}
fn hostname() -> String {
    if let Ok(o) = Command::new("hostname").output() {
        if let Ok(s) = String::from_utf8(o.stdout) {
            return s.trim().to_string();
        }
    }
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_manifest() {
        let e = capture_environment("e0", "los", "none");
        assert!(!e.kernel_version.is_empty());
        assert!(e.cpu_count > 0);
    }
    #[test]
    fn noise_defaults() {
        assert_eq!(
            capture_environment("e0", "t", "w")
                .noise_policy
                .warmup_samples,
            3
        );
    }
}
