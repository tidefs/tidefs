use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AuthorityCheckError {
    missing: Vec<String>,
}

struct SourceSurface {
    rel: &'static str,
    markers: &'static [&'static str],
}

const CURRENT_AUTHORITY_PUBLICATION_SURFACES: &[SourceSurface] = &[
    SourceSurface {
        rel: "crates/tidefs-types-control-plane-core/src/lib.rs",
        markers: &[
            "ControlPlaneRequestEnvelopeHead",
            "ControlPlaneRouteTerminalReceiptRecord",
            "ControlPlaneWriteManualProductAdmissionPayload",
            "pub mod control_plane",
            "pub mod human",
        ],
    },
    SourceSurface {
        rel: "crates/tidefs-types-publication-pipeline-core/src/lib.rs",
        markers: &[
            "PublicationPipelineEmissionTicketRecord",
            "PublicationPipelineQueueClass",
            "PublicationPipelineEmissionTicketKind",
            "pub mod publication_pipeline",
            "pub mod human",
        ],
    },
    SourceSurface {
        rel: "crates/tidefs-types-response-registry-core/src/lib.rs",
        markers: &[
            "ResponseRegistryVisibleAnswerRecord",
            "ResponseRegistryResponseIndexEntryRecord",
            "ResponseRegistryResponseRecallBindingRecord",
            "ResponseRegistryAnswerKind::Refusal",
            "pub mod response_registry",
            "pub mod human",
        ],
    },
    SourceSurface {
        rel: "crates/tidefs-types-posix-filesystem-adapter-core/src/lib.rs",
        markers: &[
            "PosixFilesystemAdapterProductWakeReceiptRecord",
            "response_registry_receipt_id",
            "publication_pipeline_ticket_id_or_zero",
            "pub mod posix_filesystem_adapter",
            "pub mod human",
        ],
    },
    SourceSurface {
        rel: "apps/tidefs-posix-filesystem-adapter-daemon/src/runtime/mod.rs",
        markers: &[
            "FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN",
            "issue_product_wake_receipt",
            "BundleWithoutTicket",
            "RefusalWithTicket",
            "pub mod posix_filesystem_adapter_runtime",
            "pub mod human",
        ],
    },
];

impl fmt::Display for AuthorityCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "authority publication spine check failed:")?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

pub fn check_authority_publication_spine_current_workspace() -> Result<(), AuthorityCheckError> {
    let root = find_workspace_root().ok_or_else(|| AuthorityCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for surface in CURRENT_AUTHORITY_PUBLICATION_SURFACES {
        check_required_file(&root, surface.rel, &mut missing);
        check_source_markers(&root, surface.rel, surface.markers, &mut missing);
    }

    if missing.is_empty() {
        println!(
            "authority publication spine ok: current workspace control-plane, publication, response-registry, and POSIX wake surfaces are present"
        );
        Ok(())
    } else {
        Err(AuthorityCheckError { missing })
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
    fn current_spine_uses_existing_workspace_surfaces() {
        for surface in CURRENT_AUTHORITY_PUBLICATION_SURFACES {
            assert!(
                !surface.rel.contains("policy-authority-client")
                    && !surface.rel.contains("policy-authority-runtime")
                    && !surface.rel.contains("control-plane-runtime")
                    && !surface.rel.contains("response-registry-query")
                    && !surface.rel.contains("truth-view-render")
            );
            assert!(!surface.markers.is_empty());
        }
    }
}
