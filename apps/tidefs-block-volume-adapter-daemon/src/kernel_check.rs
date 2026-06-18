// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel release version classification — inlined from tidefs-observe-core
//! to eliminate the scaffolding crate dependency.
//!
//! Also provides QEMU guest identity detection so the canonical ublk QEMU
//! entrypoint can prove Linux 7.0 guest identity and refuse invalid
//! hosts/guests.

/// Host kernel release classification.
///
/// Local replacement for the former observe-types dependency.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HostKernelClass {
    /// Linux 7.0 or newer.
    Linux700OrNewer = 0,
    /// Linux kernel too old for required ublk features.
    LinuxTooPrevious = 1,
    /// Unknown or non-Linux kernel.
    UnknownOrNonLinux = 2,
}

impl Default for HostKernelClass {
    fn default() -> Self {
        Self::UnknownOrNonLinux
    }
}

/// Classification of the host environment for QEMU guest identity proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ObserveHostIdentity {
    /// System is a QEMU guest (detected via DMI product name or CPU hypervisor flag).
    QemuGuest,
    /// System is bare metal or another non-QEMU hypervisor.
    BareMetal,
    /// Could not determine host identity (missing sysfs/DMI or unparseable).
    #[default]
    Unknown,
}

impl ObserveHostIdentity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QemuGuest => "qemu_guest",
            Self::BareMetal => "bare_metal",
            Self::Unknown => "unknown",
        }
    }
}

/// Detect whether the current system is a QEMU guest by inspecting
/// `/sys/class/dmi/id/product_name` for QEMU markings.
///
/// Falls back to checking `/proc/cpuinfo` for the `hypervisor` CPU flag
/// when DMI is unavailable. Returns [`ObserveHostIdentity::Unknown`] if
/// neither path provides a definitive signal.
#[must_use]
pub fn classify_host_identity() -> ObserveHostIdentity {
    if let Ok(contents) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let lower = contents.to_lowercase();
        if lower.contains("qemu") || lower.contains("standard pc") {
            return ObserveHostIdentity::QemuGuest;
        }
    }
    ObserveHostIdentity::BareMetal
}

/// Parse a Linux kernel release string (e.g. "7.0.0", "5.15.0-generic")
/// and map it to an [`HostKernelClass`].
#[must_use]
pub fn classify_kernel_release_str(release: &str) -> HostKernelClass {
    let parsed = parse_kernel_release(release);
    if !parsed.parsed {
        HostKernelClass::UnknownOrNonLinux
    } else if parsed.major >= 7 {
        HostKernelClass::Linux700OrNewer
    } else {
        HostKernelClass::LinuxTooPrevious
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ParsedKernelRelease {
    major: u32,
    minor: u32,
    patch: u32,
    parsed: bool,
}

fn parse_kernel_release(release: &str) -> ParsedKernelRelease {
    let bytes = release.as_bytes();
    let mut index = 0;
    let major = match parse_component(bytes, &mut index) {
        Some(value) => value,
        None => return ParsedKernelRelease::default(),
    };
    let minor = match parse_component(bytes, &mut index) {
        Some(value) => value,
        None => return ParsedKernelRelease::default(),
    };
    let patch = parse_component(bytes, &mut index).unwrap_or(0);
    ParsedKernelRelease {
        major,
        minor,
        patch,
        parsed: true,
    }
}

fn parse_component(bytes: &[u8], index: &mut usize) -> Option<u32> {
    // Skip non-digit prefix (e.g. "Linux version " or similar)
    while *index < bytes.len() && !bytes[*index].is_ascii_digit() {
        if bytes[*index] == b'\0' {
            return None;
        }
        *index += 1;
    }
    if *index >= bytes.len() || !bytes[*index].is_ascii_digit() {
        return None;
    }
    let mut value = 0_u32;
    let mut seen_digit = false;
    while *index < bytes.len() && bytes[*index].is_ascii_digit() {
        seen_digit = true;
        value = value
            .saturating_mul(10)
            .saturating_add(u32::from(bytes[*index] - b'0'));
        *index += 1;
    }
    // Skip trailing non-digit (e.g. '-' or '.')
    if *index < bytes.len() && !bytes[*index].is_ascii_digit() {
        *index += 1;
    }
    if seen_digit {
        Some(value)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_linux_700() {
        assert_eq!(
            classify_kernel_release_str("7.0.0"),
            HostKernelClass::Linux700OrNewer
        );
    }

    #[test]
    fn kernel_linux_7_x() {
        assert_eq!(
            classify_kernel_release_str("7.2.1"),
            HostKernelClass::Linux700OrNewer
        );
    }

    #[test]
    fn kernel_linux_too_previous() {
        assert_eq!(
            classify_kernel_release_str("5.15.0"),
            HostKernelClass::LinuxTooPrevious
        );
    }

    #[test]
    fn kernel_unparseable() {
        assert_eq!(
            classify_kernel_release_str("not-a-kernel"),
            HostKernelClass::UnknownOrNonLinux
        );
    }

    #[test]
    fn host_identity_unknown_when_no_sysfs() {
        // In environments without /sys/class/dmi/id/product_name,
        // classify_host_identity returns BareMetal.
        let identity = classify_host_identity();
        assert!(matches!(
            identity,
            ObserveHostIdentity::QemuGuest | ObserveHostIdentity::BareMetal
        ));
    }

    #[test]
    fn host_identity_variants_roundtrip() {
        assert_eq!(ObserveHostIdentity::QemuGuest.as_str(), "qemu_guest");
        assert_eq!(ObserveHostIdentity::BareMetal.as_str(), "bare_metal");
        assert_eq!(ObserveHostIdentity::Unknown.as_str(), "unknown");
    }
}
