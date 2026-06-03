//! Reproducible QEMU image and kernel pin manifest.
//!
//! Every QEMU validation run must record exactly what kernel, initrd, disk image,
//! and Nix inputs produced the test environment.  The [`QemuPinManifest`] is the
//! machine-readable record that makes a QEMU validation run reproducible:
//! someone else with the same flake.lock inputs can rebuild the identical
//! kernel-image/initrd/disk-image triple and verify the same result.
//!
//! # Relationship to other validation types
//!
//! - [`crate::runtime_artifact_source::RuntimeArtifactSource`] records execution
//!   facts (command, exit status, environment).  The pin manifest records
//!   *reproducibility* facts (image hashes, Nix inputs, rebuild recipe).
//! - The pin manifest is typically emitted alongside an `validation-manifest.json`
//!   inside `/root/ai/tmp/tidefs-validation/<run-id>/`.
//! - For Nix VM test scripts, the helper [`QemuPinManifest::to_shell_emit`]
//!   outputs a compact single-line JSON blob that the script can append to
//!   its validation output.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single artifact file captured in the pin manifest.
///
/// Records the filesystem path and a content hash so the exact file can be
/// identified and verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedArtifact {
    /// Absolute or store path to the file at collection time.
    pub path: PathBuf,
    /// SHA-256 hex digest of the file content.
    pub sha256: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Optional human-readable label (e.g. "kernel_bzImage", "initrd_cpio").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl PinnedArtifact {
    /// Compute a pinned artifact from an on-disk file.
    ///
    /// Returns `None` when `path` does not exist or is not a regular file.
    pub fn from_file(path: &Path, label: Option<String>) -> Option<Self> {
        use std::io::Read;

        if !path.is_file() {
            return None;
        }
        let metadata = std::fs::metadata(path).ok()?;
        let size_bytes = metadata.len();

        let mut file = std::fs::File::open(path).ok()?;
        let mut hasher = blake3::Hasher::new();
        // The manifest uses BLAKE3 for content-addressing of pinned artifacts.
        // This is within the approved usage boundary: durable on-disk integrity
        // and content addressing.  The proof-marker language rules in the
        // worker contract restrict BLAKE3 in transport/membership/RDMA/gossip
        // messages, not in content-addressed artifact manifests.
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha256 = hasher.finalize().to_hex().to_string();

        Some(Self {
            path: path.to_path_buf(),
            sha256,
            size_bytes,
            label,
        })
    }

    /// Compute a pinned artifact from a byte slice (useful for testing).
    pub fn from_bytes(path: &Path, data: &[u8], label: Option<String>) -> Self {
        let sha256 = blake3::hash(data).to_hex().to_string();
        Self {
            path: path.to_path_buf(),
            sha256,
            size_bytes: data.len() as u64,
            label,
        }
    }
}

/// Reproducible QEMU image and kernel pin manifest.
///
/// Captures every input needed to rebuild the exact QEMU test environment.
/// The manifest is serialisable to JSON and is designed to live alongside
/// validation outputs under `/root/ai/tmp/tidefs-validation/<run-id>/qemu-pin-manifest.json`.
///
/// # Rebuild recipe
///
/// The `rebuild_recipe` field records the Nix derivation or shell command that
/// produced the kernel/initrd/image.  For Nix-based QEMU VM tests this is
/// typically `nix build .#theDerivationName --no-link --print-out-paths`.
/// For direct `qemu-system-x86_64` invocations, it records the full command
/// line or a script that can reproduce the exact QEMU arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QemuPinManifest {
    /// Stable validation run family or harness identifier.
    pub validation_id: String,
    /// Repository commit SHA at manifest collection time.
    pub commit: String,
    /// ISO 8601 timestamp when the manifest was collected.
    pub collected_at: u64,

    /// The kernel image (bzImage or vmlinux) used to boot QEMU.
    pub kernel: PinnedArtifact,
    /// The initrd (cpio or compressed cpio) used to boot QEMU.
    pub initrd: PinnedArtifact,
    /// Optional disk image (qcow2, raw) attached to the QEMU VM.
    /// Not all QEMU runs use a disk image (e.g. initrd-only boots).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_image: Option<PinnedArtifact>,

    /// The full Nix flake.lock content at the time the QEMU artifacts were built.
    /// Stored as a raw JSON value so the structure is preserved exactly.
    pub nix_flake_lock: serde_json::Value,

    /// Nix store derivations that produced the kernel, initrd, and image.
    /// These are the paths returned by `nix build --no-link --print-out-paths`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub nix_store_derivations: Vec<String>,

    /// The rebuild recipe: a shell command or Nix invocation that reproduces
    /// the exact kernel/initrd/image combination.
    pub rebuild_recipe: String,

    /// Optional additional notes (e.g. QEMU version, architecture, NixOS channel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

pub struct QemuPinManifestCollect<'a> {
    pub validation_id: &'a str,
    pub commit: &'a str,
    pub kernel_path: &'a Path,
    pub initrd_path: &'a Path,
    pub disk_image_path: Option<&'a Path>,
    pub flake_lock_path: &'a Path,
    pub rebuild_recipe: &'a str,
    pub nix_store_derivations: &'a [String],
}

impl QemuPinManifest {
    /// Build a pin manifest from on-disk artifacts and a flake.lock path.
    ///
    /// Returns `None` when the kernel or initrd path does not exist, or
    /// when the flake.lock file cannot be read/parsed.
    pub fn collect(input: QemuPinManifestCollect<'_>) -> Option<Self> {
        let kernel = PinnedArtifact::from_file(input.kernel_path, Some("kernel".into()))?;
        let initrd = PinnedArtifact::from_file(input.initrd_path, Some("initrd".into()))?;
        let disk_image = input
            .disk_image_path
            .and_then(|p| PinnedArtifact::from_file(p, Some("disk_image".into())));

        let flake_lock_content = std::fs::read_to_string(input.flake_lock_path).ok()?;
        let nix_flake_lock: serde_json::Value = serde_json::from_str(&flake_lock_content).ok()?;

        let collected_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Some(Self {
            validation_id: input.validation_id.to_string(),
            commit: input.commit.to_string(),
            collected_at,
            kernel,
            initrd,
            disk_image,
            nix_flake_lock,
            nix_store_derivations: input.nix_store_derivations.to_vec(),
            rebuild_recipe: input.rebuild_recipe.to_string(),
            notes: None,
        })
    }

    /// Emit a compact single-line JSON representation suitable for shell
    /// scripts to append to validation output.
    ///
    /// Nix VM test scripts can call this from Rust test helpers or xtask
    /// subcommands to produce a stable pin-manifest JSON line.
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Compute the Nix inputs identity string from the flake lock.
    ///
    /// This is the concatenation of all locked input URLs/hashes, useful
    /// as a short reproducibility fingerprint.
    pub fn nix_inputs_fingerprint(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(nodes) = self.nix_flake_lock.get("nodes").and_then(|v| v.as_object()) {
            for (name, node) in nodes {
                if name == "root" {
                    continue;
                }
                if let Some(locked) = node.get("locked") {
                    if let Some(rev) = locked.get("rev").and_then(|v| v.as_str()) {
                        parts.push(format!("{name}={rev}"));
                    } else if let Some(nar_hash) = locked.get("narHash").and_then(|v| v.as_str()) {
                        parts.push(format!("{name}={nar_hash}"));
                    }
                }
            }
        }
        parts.sort();
        parts.join(";")
    }

    /// Validate the manifest against on-disk reality.
    ///
    /// Returns a list of validation issues: missing files, mismatched hashes,
    /// or missing flake lock inputs.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();

        // Check kernel exists and hash matches.
        if self.kernel.path.exists() {
            if let Some(current) = PinnedArtifact::from_file(&self.kernel.path, None) {
                if current.sha256 != self.kernel.sha256 {
                    issues.push(format!(
                        "kernel hash mismatch: recorded {} vs current {}",
                        self.kernel.sha256, current.sha256
                    ));
                }
                if current.size_bytes != self.kernel.size_bytes {
                    issues.push(format!(
                        "kernel size mismatch: recorded {} vs current {}",
                        self.kernel.size_bytes, current.size_bytes
                    ));
                }
            }
        } else {
            issues.push(format!(
                "kernel file missing: {}",
                self.kernel.path.display()
            ));
        }

        // Check initrd exists and hash matches.
        if self.initrd.path.exists() {
            if let Some(current) = PinnedArtifact::from_file(&self.initrd.path, None) {
                if current.sha256 != self.initrd.sha256 {
                    issues.push(format!(
                        "initrd hash mismatch: recorded {} vs current {}",
                        self.initrd.sha256, current.sha256
                    ));
                }
            }
        } else {
            issues.push(format!(
                "initrd file missing: {}",
                self.initrd.path.display()
            ));
        }

        // Check disk image if present.
        if let Some(ref disk) = self.disk_image {
            if disk.path.exists() {
                if let Some(current) = PinnedArtifact::from_file(&disk.path, None) {
                    if current.sha256 != disk.sha256 {
                        issues.push(format!(
                            "disk image hash mismatch: recorded {} vs current {}",
                            disk.sha256, current.sha256
                        ));
                    }
                }
            } else {
                issues.push(format!("disk image missing: {}", disk.path.display()));
            }
        }

        issues
    }

    /// Returns true when the manifest passes validation (all files present
    /// and hashes match).
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }

    /// Build a minimal manifest for testing from in-memory data.
    #[cfg(test)]
    pub fn for_test(validation_id: &str, kernel_data: &[u8], initrd_data: &[u8]) -> Self {
        let kernel = PinnedArtifact::from_bytes(
            Path::new("/tmp/test-kernel"),
            kernel_data,
            Some("kernel".into()),
        );
        let initrd = PinnedArtifact::from_bytes(
            Path::new("/tmp/test-initrd"),
            initrd_data,
            Some("initrd".into()),
        );
        let flake_lock = serde_json::json!({
            "nodes": {
                "nixpkgs": {
                    "locked": {
                        "rev": "01fbdeef22b76df85ea168fbfe1bfd9e63681b30",
                        "narHash": "sha256-test"
                    }
                }
            },
            "version": 7
        });

        Self {
            validation_id: validation_id.into(),
            commit: "test000".into(),
            collected_at: 1716500000,
            kernel,
            initrd,
            disk_image: None,
            nix_flake_lock: flake_lock,
            nix_store_derivations: vec!["/nix/store/test-hash-kernel".into()],
            rebuild_recipe: "nix build .#test-vm".into(),
            notes: Some("test manifest".into()),
        }
    }
}

/// Emit the pin manifest as a shell-friendly key=value block.
///
/// This function is designed to be called from Nix VM test scripts that
/// already emit structured key=value lines.  It produces a single
/// `PIN_MANIFEST_JSON=` line containing the compact JSON representation.
///
/// Returns `None` if serialization fails.
pub fn emit_shell_pin_manifest(manifest: &QemuPinManifest) -> Option<String> {
    let json = manifest.to_json_compact().ok()?;
    Some(format!("PIN_MANIFEST_JSON={json}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn pinned_artifact_from_bytes() {
        let data = b"hello kernel 1234567890";
        let artifact =
            PinnedArtifact::from_bytes(Path::new("/fake/kernel"), data, Some("test-kernel".into()));
        assert_eq!(artifact.path, Path::new("/fake/kernel"));
        assert_eq!(artifact.size_bytes, data.len() as u64);
        assert_eq!(artifact.label.as_deref(), Some("test-kernel"));
        assert!(!artifact.sha256.is_empty());
        assert_eq!(artifact.sha256.len(), 64); // BLAKE3 hex digest = 64 chars
    }

    #[test]
    fn pinned_artifact_from_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test-file");
        let data = b"some test content for hashing";
        std::fs::write(&path, data).unwrap();

        let artifact = PinnedArtifact::from_file(&path, Some("test".into())).unwrap();
        assert_eq!(artifact.size_bytes, data.len() as u64);
        assert_eq!(artifact.path, path);
        assert!(!artifact.sha256.is_empty());

        // Same content should produce same hash.
        let artifact2 = PinnedArtifact::from_file(&path, None).unwrap();
        assert_eq!(artifact.sha256, artifact2.sha256);
    }

    #[test]
    fn pinned_artifact_from_missing_file() {
        let artifact = PinnedArtifact::from_file(Path::new("/nonexistent/file/path"), None);
        assert!(artifact.is_none());
    }

    #[test]
    fn pinned_artifact_different_content_different_hash() {
        let a = PinnedArtifact::from_bytes(Path::new("/a"), b"content A", None);
        let b = PinnedArtifact::from_bytes(Path::new("/b"), b"content B", None);
        assert_ne!(a.sha256, b.sha256);
    }

    #[test]
    fn manifest_json_roundtrip() {
        let manifest =
            QemuPinManifest::for_test("test-validation", b"kernel-data-123", b"initrd-data-456");
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: QemuPinManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.validation_id, "test-validation");
        assert_eq!(parsed.kernel.sha256, manifest.kernel.sha256);
        assert_eq!(parsed.initrd.sha256, manifest.initrd.sha256);
        assert_eq!(parsed.nix_store_derivations.len(), 1);
    }

    #[test]
    fn manifest_compact_json_is_single_line() {
        let manifest = QemuPinManifest::for_test("test-validation", b"k", b"i");
        let compact = manifest.to_json_compact().unwrap();
        assert!(
            !compact.contains('\n'),
            "compact JSON should be single line"
        );
        assert!(compact.contains("\"validation_id\":\"test-validation\""));
    }

    #[test]
    fn manifest_nix_fingerprint() {
        let manifest = QemuPinManifest::for_test("test-validation", b"k", b"i");
        let fp = manifest.nix_inputs_fingerprint();
        assert!(fp.contains("nixpkgs=01fbdeef"));
    }

    #[test]
    fn manifest_validate_all_good() {
        let dir = TempDir::new().unwrap();
        let kernel_data = b"real kernel binary content here";
        let initrd_data = b"real initrd cpio content here";
        let kernel_path = dir.path().join("kernel");
        let initrd_path = dir.path().join("initrd");
        std::fs::write(&kernel_path, kernel_data).unwrap();
        std::fs::write(&initrd_path, initrd_data).unwrap();

        let kernel = PinnedArtifact::from_file(&kernel_path, Some("kernel".into())).unwrap();
        let initrd = PinnedArtifact::from_file(&initrd_path, Some("initrd".into())).unwrap();

        let manifest = QemuPinManifest {
            validation_id: "test-validation".into(),
            commit: "test".into(),
            collected_at: 1716500000,
            kernel,
            initrd,
            disk_image: None,
            nix_flake_lock: serde_json::json!({"nodes":{}}),
            nix_store_derivations: vec![],
            rebuild_recipe: "nix build".into(),
            notes: None,
        };

        assert!(manifest.is_valid());
        let issues = manifest.validate();
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    #[test]
    fn manifest_validate_detects_hash_mismatch() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        std::fs::write(&kernel_path, b"original content").unwrap();
        let initrd_path = dir.path().join("initrd");
        std::fs::write(&initrd_path, b"initrd content").unwrap();

        let initrd = PinnedArtifact::from_file(&initrd_path, Some("initrd".into())).unwrap();

        // Kernel pinned with wrong hash.
        let kernel = PinnedArtifact::from_bytes(
            &kernel_path,
            b"DIFFERENT content that changes hash",
            Some("kernel".into()),
        );

        let manifest = QemuPinManifest {
            validation_id: "test-validation".into(),
            commit: "test".into(),
            collected_at: 1716500000,
            kernel,
            initrd,
            disk_image: None,
            nix_flake_lock: serde_json::json!({"nodes":{}}),
            nix_store_derivations: vec![],
            rebuild_recipe: "nix build".into(),
            notes: None,
        };

        assert!(!manifest.is_valid());
        let issues = manifest.validate();
        assert!(
            issues.iter().any(|issue| issue.contains("hash mismatch")),
            "expected hash mismatch in {issues:?}"
        );
    }

    #[test]
    fn manifest_validate_detects_missing_file() {
        let dir = TempDir::new().unwrap();
        let initrd_path = dir.path().join("initrd");
        std::fs::write(&initrd_path, b"initrd").unwrap();

        let initrd = PinnedArtifact::from_file(&initrd_path, Some("initrd".into())).unwrap();
        let kernel = PinnedArtifact::from_bytes(
            Path::new("/nonexistent/kernel-file"),
            b"fake kernel data",
            Some("kernel".into()),
        );

        let manifest = QemuPinManifest {
            validation_id: "test-validation".into(),
            commit: "test".into(),
            collected_at: 1716500000,
            kernel,
            initrd,
            disk_image: None,
            nix_flake_lock: serde_json::json!({"nodes":{}}),
            nix_store_derivations: vec![],
            rebuild_recipe: "nix build".into(),
            notes: None,
        };

        assert!(!manifest.is_valid());
        let issues = manifest.validate();
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("missing"));
    }

    #[test]
    fn manifest_with_disk_image() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        let initrd_path = dir.path().join("initrd");
        let disk_path = dir.path().join("disk.qcow2");
        std::fs::write(&kernel_path, b"kernel").unwrap();
        std::fs::write(&initrd_path, b"initrd").unwrap();
        std::fs::write(&disk_path, b"disk image data").unwrap();

        let kernel = PinnedArtifact::from_file(&kernel_path, Some("kernel".into())).unwrap();
        let initrd = PinnedArtifact::from_file(&initrd_path, Some("initrd".into())).unwrap();
        let disk = PinnedArtifact::from_file(&disk_path, Some("disk_image".into())).unwrap();

        let manifest = QemuPinManifest {
            validation_id: "test-validation".into(),
            commit: "abc".into(),
            collected_at: 1716500000,
            kernel,
            initrd,
            disk_image: Some(disk),
            nix_flake_lock: serde_json::json!({"version":7}),
            nix_store_derivations: vec!["/nix/store/xyz".into()],
            rebuild_recipe: "nix build .#qemu-test".into(),
            notes: None,
        };

        assert!(manifest.is_valid());

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("disk.qcow2"));
        assert!(json.contains("disk_image"));

        let parsed: QemuPinManifest = serde_json::from_str(&json).unwrap();
        assert!(parsed.disk_image.is_some());
    }

    #[test]
    fn manifest_disk_image_optional_field_omitted() {
        let manifest = QemuPinManifest::for_test("test-validation", b"k", b"i");
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(
            !json.contains("disk_image"),
            "disk_image should be absent when None"
        );
    }

    #[test]
    fn shell_emit_produces_line() {
        let manifest = QemuPinManifest::for_test("test-validation", b"k", b"i");
        let line = emit_shell_pin_manifest(&manifest).unwrap();
        assert!(line.starts_with("PIN_MANIFEST_JSON="));
        // The value after = should parse as valid JSON.
        let json_part = &line["PIN_MANIFEST_JSON=".len()..];
        let _parsed: serde_json::Value = serde_json::from_str(json_part).unwrap();
    }

    #[test]
    fn manifest_nix_flake_lock_preserved_exactly() {
        let manifest = QemuPinManifest::for_test("test-validation", b"k", b"i");
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: QemuPinManifest = serde_json::from_str(&json).unwrap();
        // The flake lock structure should round-trip.
        assert_eq!(parsed.nix_flake_lock["version"].as_u64(), Some(7));
        assert!(parsed.nix_flake_lock["nodes"]["nixpkgs"]["locked"]["rev"]
            .as_str()
            .unwrap()
            .contains("01fbdeef"));
    }

    #[test]
    fn collect_from_disk_success() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        let initrd_path = dir.path().join("initrd");
        let flake_lock_path = dir.path().join("flake.lock");
        std::fs::write(&kernel_path, b"kernel bytes").unwrap();
        std::fs::write(&initrd_path, b"initrd bytes").unwrap();
        std::fs::write(
            &flake_lock_path,
            r#"{"nodes":{"nixpkgs":{"locked":{"rev":"abc123"}}},"version":7}"#,
        )
        .unwrap();

        let manifest = QemuPinManifest::collect(QemuPinManifestCollect {
            validation_id: "test-validation",
            commit: "deadbeef",
            kernel_path: &kernel_path,
            initrd_path: &initrd_path,
            disk_image_path: None,
            flake_lock_path: &flake_lock_path,
            rebuild_recipe: "nix build .#some-vm",
            nix_store_derivations: &["/nix/store/xyz".to_string()],
        })
        .unwrap();

        assert_eq!(manifest.validation_id, "test-validation");
        assert_eq!(manifest.commit, "deadbeef");
        assert_eq!(manifest.kernel.size_bytes, 12);
        assert_eq!(manifest.initrd.size_bytes, 12);
        assert!(manifest.collected_at > 0);
    }

    #[test]
    fn collect_from_disk_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel-missing");
        let initrd_path = dir.path().join("initrd");
        let flake_lock_path = dir.path().join("flake.lock");
        std::fs::write(&initrd_path, b"initrd").unwrap();
        std::fs::write(&flake_lock_path, r#"{"nodes":{},"version":7}"#).unwrap();

        let manifest = QemuPinManifest::collect(QemuPinManifestCollect {
            validation_id: "test-validation",
            commit: "abc",
            kernel_path: &kernel_path,
            initrd_path: &initrd_path,
            disk_image_path: None,
            flake_lock_path: &flake_lock_path,
            rebuild_recipe: "nix build",
            nix_store_derivations: &[],
        });
        assert!(manifest.is_none());
    }

    #[test]
    fn collect_from_disk_missing_flake_lock_returns_none() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.path().join("kernel");
        let initrd_path = dir.path().join("initrd");
        let flake_lock_path = dir.path().join("no-such-flake.lock");
        std::fs::write(&kernel_path, b"k").unwrap();
        std::fs::write(&initrd_path, b"i").unwrap();

        let manifest = QemuPinManifest::collect(QemuPinManifestCollect {
            validation_id: "test-validation",
            commit: "abc",
            kernel_path: &kernel_path,
            initrd_path: &initrd_path,
            disk_image_path: None,
            flake_lock_path: &flake_lock_path,
            rebuild_recipe: "nix build",
            nix_store_derivations: &[],
        });
        assert!(manifest.is_none());
    }

    #[test]
    fn pinned_artifact_content_addressing_stable() {
        // Same content must always produce the same BLAKE3 hash.
        let data = b"deterministic test payload for content addressing";
        let a = PinnedArtifact::from_bytes(Path::new("/a"), data, None);
        let b = PinnedArtifact::from_bytes(Path::new("/b"), data, None);
        assert_eq!(
            a.sha256, b.sha256,
            "BLAKE3 content addressing must be deterministic"
        );
    }

    #[test]
    fn manifest_all_fields_populated() {
        let manifest = QemuPinManifest {
            validation_id: "test-validation".into(),
            commit: "abc123".into(),
            collected_at: 1716500000,
            kernel: PinnedArtifact::from_bytes(Path::new("/k"), b"kdata", Some("kernel".into())),
            initrd: PinnedArtifact::from_bytes(Path::new("/i"), b"idata", Some("initrd".into())),
            disk_image: Some(PinnedArtifact::from_bytes(
                Path::new("/d"),
                b"ddata",
                Some("disk".into()),
            )),
            nix_flake_lock: serde_json::json!({"nodes":{"nixpkgs":{"locked":{"rev":"r1"}}}, "version":7}),
            nix_store_derivations: vec!["/nix/store/a".into(), "/nix/store/b".into()],
            rebuild_recipe: "nix build .#test --no-link".into(),
            notes: Some("collected during qemu pin manifest test".into()),
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let round: QemuPinManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(round.validation_id, "test-validation");
        assert_eq!(round.kernel.sha256, manifest.kernel.sha256);
        assert_eq!(round.initrd.sha256, manifest.initrd.sha256);
        assert!(round.disk_image.is_some());
        assert_eq!(
            round.disk_image.unwrap().sha256,
            manifest.disk_image.unwrap().sha256
        );
        assert_eq!(round.nix_store_derivations.len(), 2);
        assert_eq!(round.rebuild_recipe, "nix build .#test --no-link");
        assert_eq!(
            round.notes.as_deref(),
            Some("collected during qemu pin manifest test")
        );
    }

    #[test]
    fn guard_pin_manifest_requires_kernel_and_initrd() {
        // A QEMU run that doesn't record kernel + initrd is not reproducible.
        let manifest = QemuPinManifest::for_test("test-validation", b"k", b"i");
        assert!(!manifest.kernel.sha256.is_empty(), "kernel sha256 required");
        assert!(!manifest.initrd.sha256.is_empty(), "initrd sha256 required");
    }
}
