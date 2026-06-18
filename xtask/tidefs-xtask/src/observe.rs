// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ObserveCheckError {
    missing: Vec<String>,
}

struct SourceSurface {
    rel: &'static str,
    markers: &'static [&'static str],
}

const CURRENT_OBSERVATION_SURFACES: &[SourceSurface] = &[SourceSurface {
    rel: "crates/tidefs-types-vfs-core/src/lib.rs",
    markers: &[
        "TruthViewLiveViewClass",
        "TruthViewDistributedOperatorSignalClass",
        "TruthViewDistributedOperatorStatusClass",
        "TruthViewDistributedOperatorSurfaceRecord",
        "TruthViewTruthBundleRecord",
        "operator.truth_view.distributed.placement.o0",
        "operator.truth_view.distributed.health.o1",
        "operator.truth_view.distributed.rebuild.o2",
        "operator.truth_view.distributed.risk.o3",
        "exposes_distributed_operator_truth",
        "requires_operator_attention",
    ],
}];

const CURRENT_HOST_PROBE_SURFACES: &[SourceSurface] = &[
    SourceSurface {
        rel: "apps/tidefs-block-volume-adapter-daemon/src/kernel_check.rs",
        markers: &[
            "HostKernelClass",
            "ObserveHostIdentity",
            "classify_kernel_release_str",
            "classify_host_identity",
            "Linux700OrNewer",
            "QemuGuest",
        ],
    },
    SourceSurface {
        rel: "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        markers: &[
            "preflight-host",
            "HostPreflightReport",
            "HostPreflightAdmissionClass",
            "HostPreflightRefusalClass",
            "/dev/ublk-control",
            "host.attach_mutation_attempted",
            "host.observe_host_identity",
        ],
    },
];

impl fmt::Display for ObserveCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "observe gate check failed:")?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

pub fn check_observation_substrate_current_workspace() -> Result<(), ObserveCheckError> {
    let root = find_workspace_root().ok_or_else(|| ObserveCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for surface in CURRENT_OBSERVATION_SURFACES {
        check_required_file(&root, surface.rel, &mut missing);
        check_source_markers(&root, surface.rel, surface.markers, &mut missing);
    }

    if missing.is_empty() {
        println!(
            "observation substrate ok: current workspace VFS truth-view record surfaces are present"
        );
        Ok(())
    } else {
        Err(ObserveCheckError { missing })
    }
}

pub fn check_validation_packaging_host_probe_current_workspace() -> Result<(), ObserveCheckError> {
    let root = find_workspace_root().ok_or_else(|| ObserveCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for surface in CURRENT_HOST_PROBE_SURFACES {
        check_required_file(&root, surface.rel, &mut missing);
        check_source_markers(&root, surface.rel, surface.markers, &mut missing);
    }

    if missing.is_empty() {
        println!(
            "host preflight probe ok: current block-volume host classification and ublk refusal surfaces are present"
        );
        Ok(())
    } else {
        Err(ObserveCheckError { missing })
    }
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let manifest = current.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return Some(current);
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

fn check_required_file(root: &Path, rel: &str, missing: &mut Vec<String>) {
    if !root.join(rel).is_file() {
        missing.push(format!("missing required file `{rel}`"));
    }
}

fn check_source_markers(root: &Path, rel: &str, markers: &[&str], missing: &mut Vec<String>) {
    let path = root.join(rel);
    let Ok(text) = fs::read_to_string(&path) else {
        missing.push(format!("could not read `{rel}`"));
        return;
    };
    for marker in markers {
        if !text.contains(marker) {
            missing.push(format!("`{rel}` missing marker `{marker}`"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_checks_use_current_workspace_surfaces() {
        for surface in CURRENT_OBSERVATION_SURFACES
            .iter()
            .chain(CURRENT_HOST_PROBE_SURFACES.iter())
        {
            assert!(
                !surface.rel.contains("observe-core-truth-view-render")
                    && !surface.rel.contains("control-plane-daemon")
                    && !surface.rel.contains("policy-authority-daemon")
                    && !surface.rel.contains("DISTRIBUTED_OPERATOR_TRUTH_SURFACES")
            );
            assert!(!surface.markers.is_empty());
        }
    }
}
