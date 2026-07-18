// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Linux QEMU-guest data-shape helper evidence producer for issue #1981.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_validation::storage_intent_data_shape_runtime::{
    write_runtime_evidence, DataShapeRunProvenance, PERFORMANCE_ARTIFACT_PATH,
    PERFORMANCE_MANIFEST_PATH, TRANSFORM_ARTIFACT_PATH, TRANSFORM_MANIFEST_PATH,
};

const OUTPUT_DIR_ENV: &str = "TIDEFS_DATA_SHAPE_RUNTIME_OUTPUT_DIR";

fn provenance(name: &str, fallback: String) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(fallback)
}

fn main() {
    let output_dir = env::var_os(OUTPUT_DIR_ENV)
        .map(PathBuf::from)
        .expect("TIDEFS_DATA_SHAPE_RUNTIME_OUTPUT_DIR must name the evidence output directory");
    let run = DataShapeRunProvenance {
        run_id: provenance(
            "TIDEFS_DATA_SHAPE_RUNTIME_RUN_ID",
            format!("local-run/{}", std::process::id()),
        ),
        source_ref: provenance(
            "TIDEFS_DATA_SHAPE_RUNTIME_SOURCE_REF",
            "local-source-not-for-claim".to_string(),
        ),
        generated_at: provenance(
            "TIDEFS_DATA_SHAPE_RUNTIME_GENERATED_AT",
            "1970-01-01T00:00:00Z".to_string(),
        ),
        carrier: provenance(
            "TIDEFS_DATA_SHAPE_RUNTIME_CARRIER",
            "direct-host-helper-runtime".to_string(),
        ),
        kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unavailable-local-kernel".to_string())
            .trim()
            .to_string(),
    };
    let written = write_runtime_evidence(&output_dir, &run)
        .expect("write storage-intent data-shape runtime evidence");
    eprintln!(
        "data-shape helper runtime evidence: transform={} transform_manifest={} performance={} performance_manifest={} registered_paths={TRANSFORM_ARTIFACT_PATH},{TRANSFORM_MANIFEST_PATH},{PERFORMANCE_ARTIFACT_PATH},{PERFORMANCE_MANIFEST_PATH}",
        written.transform_artifact.display(),
        written.transform_manifest.display(),
        written.performance_artifact.display(),
        written.performance_manifest.display(),
    );
}
