// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AuthorityCheckError {
    missing: Vec<String>,
}

struct SourceSurface {
    rel: &'static str,
    structs: &'static [StructExpectation],
    enums: &'static [EnumExpectation],
    modules: &'static [ModuleExpectation],
    functions: &'static [FunctionExpectation],
    consts: &'static [ConstExpectation],
}

struct StructExpectation {
    name: &'static str,
    fields: &'static [&'static str],
    methods: &'static [&'static str],
}

struct EnumExpectation {
    name: &'static str,
    variants: &'static [&'static str],
}

struct ModuleExpectation {
    path: &'static [&'static str],
    reexports: &'static [ReexportExpectation],
}

struct ReexportExpectation {
    source: &'static str,
    alias: &'static str,
}

struct FunctionExpectation {
    name: &'static str,
    returns: &'static str,
    errors: &'static [&'static str],
}

struct ConstExpectation {
    name: &'static str,
    value_terms: &'static [&'static str],
}

const CURRENT_AUTHORITY_PUBLICATION_SURFACES: &[SourceSurface] = &[
    SourceSurface {
        rel: "crates/tidefs-types-vfs-core/src/lib.rs",
        structs: &[StructExpectation {
            name: "ControlPlaneRequestEnvelopeHead",
            fields: &[
                "request_id",
                "session_id",
                "idempotency_key",
                "normalized_request_digest",
            ],
            methods: &["carrier", "route", "render", "visibility"],
        }],
        enums: &[],
        modules: &[ModuleExpectation {
            path: &["control_plane"],
            reexports: &[
                ReexportExpectation {
                    source: "ControlPlaneRequestEnvelopeHead",
                    alias: "RequestEnvelopeHead",
                },
                ReexportExpectation {
                    source: "ControlPlaneRouteTerminalReceiptRecord",
                    alias: "RouteTerminalReceiptRecord",
                },
                ReexportExpectation {
                    source: "ControlPlaneWriteManualProductAdmissionPayload",
                    alias: "ManualProductAdmissionPayload",
                },
            ],
        }],
        functions: &[],
        consts: &[],
    },
    SourceSurface {
        rel: "crates/tidefs-types-vfs-core/src/lib.rs",
        structs: &[StructExpectation {
            name: "PublicationPipelineEmissionTicketRecord",
            fields: &[
                "ticket_id",
                "request_id",
                "journal_id",
                "queue_class",
                "ticket_kind",
                "render_receipt_seed",
                "outcome_digest",
            ],
            methods: &["queue", "batch", "ticket_kind"],
        }],
        enums: &[
            EnumExpectation {
                name: "PublicationPipelineQueueClass",
                variants: &["ProductWake"],
            },
            EnumExpectation {
                name: "PublicationPipelineEmissionTicketKind",
                variants: &["ControlWriteMutation"],
            },
        ],
        modules: &[ModuleExpectation {
            path: &["publication_pipeline"],
            reexports: &[ReexportExpectation {
                source: "PublicationPipelineEmissionTicketRecord",
                alias: "EmissionTicketRecord",
            }],
        }],
        functions: &[],
        consts: &[],
    },
    SourceSurface {
        rel: "crates/tidefs-types-vfs-core/src/lib.rs",
        structs: &[
            StructExpectation {
                name: "ResponseRegistryVisibleAnswerRecord",
                fields: &[
                    "receipt_id",
                    "request_id",
                    "journal_id",
                    "answer_kind",
                    "answer_digest",
                    "artifact_locator_digest",
                ],
                methods: &["bundle", "refusal"],
            },
            StructExpectation {
                name: "ResponseRegistryResponseIndexEntryRecord",
                fields: &[
                    "index_entry_id",
                    "response_receipt_id",
                    "bundle_receipt_id_or_zero",
                    "terminal_receipt_id_or_zero",
                    "route_class",
                    "index_class",
                    "retention_class",
                ],
                methods: &[
                    "route",
                    "index_class",
                    "retention",
                    "has_bundle_receipt",
                    "has_terminal_receipt",
                    "has_supersession",
                ],
            },
            StructExpectation {
                name: "ResponseRegistryResponseRecallBindingRecord",
                fields: &[
                    "binding_id",
                    "response_receipt_id",
                    "bundle_receipt_id",
                    "terminal_receipt_id_or_zero",
                    "answer_kind",
                ],
                methods: &["answer_kind", "has_terminal_receipt"],
            },
        ],
        enums: &[EnumExpectation {
            name: "ResponseRegistryAnswerKind",
            variants: &["Bundle", "Refusal"],
        }],
        modules: &[ModuleExpectation {
            path: &["response_registry"],
            reexports: &[ReexportExpectation {
                source: "ResponseRegistryRenderClass",
                alias: "RenderClass",
            }],
        }],
        functions: &[],
        consts: &[],
    },
    SourceSurface {
        rel: "crates/tidefs-types-posix-filesystem-adapter-core/src/lib.rs",
        structs: &[StructExpectation {
            name: "PosixFilesystemAdapterProductWakeReceiptRecord",
            fields: &[
                "wake_receipt_id",
                "request_id",
                "journal_id",
                "response_registry_receipt_id",
                "publication_pipeline_ticket_id_or_zero",
                "witness_refs",
            ],
            methods: &["wake_class", "visibility", "has_publication_pipeline_ticket"],
        }],
        enums: &[],
        modules: &[
            ModuleExpectation {
                path: &["posix_filesystem_adapter"],
                reexports: &[ReexportExpectation {
                    source: "PosixFilesystemAdapterProductWakeReceiptRecord",
                    alias: "ProductWakeReceiptRecord",
                }],
            },
            ModuleExpectation {
                path: &["human", "posix_filesystem_adapter"],
                reexports: &[ReexportExpectation {
                    source: "crate::posix_filesystem_adapter::*",
                    alias: "*",
                }],
            },
        ],
        functions: &[],
        consts: &[],
    },
    SourceSurface {
        rel: "apps/tidefs-posix-filesystem-adapter-daemon/src/runtime/mod.rs",
        structs: &[],
        enums: &[EnumExpectation {
            name: "PosixFilesystemAdapterProjectionError",
            variants: &["BundleWithoutTicket", "RefusalWithTicket"],
        }],
        modules: &[
            ModuleExpectation {
                path: &["posix_filesystem_adapter_runtime"],
                reexports: &[
                    ReexportExpectation {
                        source: "issue_product_wake_receipt",
                        alias: "issue_product_wake_receipt",
                    },
                    ReexportExpectation {
                        source:
                            "FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN",
                        alias: "FIRST_PUBLICATION_AND_RESPONSE_TO_POSIX_WAKE_CHAIN",
                    },
                ],
            },
            ModuleExpectation {
                path: &["human", "posix_filesystem_adapter_runtime"],
                reexports: &[ReexportExpectation {
                    source: "crate::runtime::posix_filesystem_adapter_runtime::*",
                    alias: "*",
                }],
            },
        ],
        functions: &[FunctionExpectation {
            name: "issue_product_wake_receipt",
            returns: "Result<PosixFilesystemAdapterProductWakeReceiptRecord, PosixFilesystemAdapterProjectionError>",
            errors: &["BundleWithoutTicket", "RefusalWithTicket"],
        }],
        consts: &[ConstExpectation {
            name: "FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN",
            value_terms: &[
                "queue.publication_pipeline.product_wake",
                "render.response_registry.posix_filesystem_adapter_wire",
                "receipt.posix_filesystem_adapter.wake.namespace_projection",
            ],
        }],
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
        check_source_surface(&root, surface, &mut missing);
    }

    if missing.is_empty() {
        println!(
            "authority publication spine ok: structured current-workspace source contracts for VFS control-plane, publication, response-registry, and POSIX wake adapter are present"
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

fn check_source_surface(root: &Path, surface: &SourceSurface, missing: &mut Vec<String>) {
    let missing_before = missing.len();
    check_required_file(root, surface.rel, missing);
    if missing.len() != missing_before {
        return;
    }

    let Ok(text) = fs::read_to_string(root.join(surface.rel)) else {
        missing.push(format!("could not read `{}`", surface.rel));
        return;
    };

    for expected in surface.structs {
        check_struct_expectation(surface.rel, &text, expected, missing);
    }
    for expected in surface.enums {
        check_enum_expectation(surface.rel, &text, expected, missing);
    }
    for expected in surface.modules {
        check_module_expectation(surface.rel, &text, expected, missing);
    }
    for expected in surface.functions {
        check_function_expectation(surface.rel, &text, expected, missing);
    }
    for expected in surface.consts {
        check_const_expectation(surface.rel, &text, expected, missing);
    }
}

fn check_struct_expectation(
    rel: &str,
    text: &str,
    expected: &StructExpectation,
    missing: &mut Vec<String>,
) {
    let Some(struct_block) = find_item_block(text, "struct", expected.name) else {
        missing.push(format!("`{rel}` missing public record `{}`", expected.name));
        return;
    };

    for field in expected.fields {
        if !has_named_field(struct_block, field) {
            missing.push(format!(
                "`{rel}` record `{}` missing field `{field}`",
                expected.name
            ));
        }
    }

    for method in expected.methods {
        if !has_impl_method(text, expected.name, method) {
            missing.push(format!(
                "`{rel}` record `{}` missing method `{method}`",
                expected.name
            ));
        }
    }
}

fn check_enum_expectation(
    rel: &str,
    text: &str,
    expected: &EnumExpectation,
    missing: &mut Vec<String>,
) {
    let Some(enum_block) = find_item_block(text, "enum", expected.name) else {
        missing.push(format!("`{rel}` missing public enum `{}`", expected.name));
        return;
    };

    for variant in expected.variants {
        if !has_enum_variant(enum_block, variant) {
            missing.push(format!(
                "`{rel}` enum `{}` missing variant `{variant}`",
                expected.name
            ));
        }
    }
}

fn check_module_expectation(
    rel: &str,
    text: &str,
    expected: &ModuleExpectation,
    missing: &mut Vec<String>,
) {
    let Some(module_block) = find_module_path_block(text, expected.path) else {
        missing.push(format!(
            "`{rel}` missing public module `{}`",
            expected.path.join("::")
        ));
        return;
    };

    for reexport in expected.reexports {
        if !has_reexport(module_block, reexport) {
            missing.push(format!(
                "`{rel}` module `{}` missing re-export `{}` as `{}`",
                expected.path.join("::"),
                reexport.source,
                reexport.alias
            ));
        }
    }
}

fn check_function_expectation(
    rel: &str,
    text: &str,
    expected: &FunctionExpectation,
    missing: &mut Vec<String>,
) {
    let Some(function_block) = find_function_block(text, expected.name) else {
        missing.push(format!(
            "`{rel}` missing public function `{}`",
            expected.name
        ));
        return;
    };

    let normalized_block = normalize_rustish(function_block);
    let normalized_return = normalize_rustish(expected.returns);
    if !normalized_block.contains(&format!("-> {normalized_return}")) {
        missing.push(format!(
            "`{rel}` function `{}` return type does not expose `{}`",
            expected.name, expected.returns
        ));
    }

    for error in expected.errors {
        if !function_block.contains(error) {
            missing.push(format!(
                "`{rel}` function `{}` missing error branch `{error}`",
                expected.name
            ));
        }
    }
}

fn check_const_expectation(
    rel: &str,
    text: &str,
    expected: &ConstExpectation,
    missing: &mut Vec<String>,
) {
    let Some(const_decl) = find_const_decl(text, expected.name) else {
        missing.push(format!("`{rel}` missing public const `{}`", expected.name));
        return;
    };

    for term in expected.value_terms {
        if !const_decl.contains(term) {
            missing.push(format!(
                "`{rel}` const `{}` missing value term `{term}`",
                expected.name
            ));
        }
    }
}

fn find_item_block<'a>(text: &'a str, kind: &str, name: &str) -> Option<&'a str> {
    let needle = format!("pub {kind} {name}");
    let start = text.find(&needle)?;
    let brace = text[start..].find('{')? + start;
    let end = matching_brace(text, brace)?;
    Some(&text[start..=end])
}

fn find_function_block<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("pub fn {name}");
    let start = text.find(&needle)?;
    let brace = text[start..].find('{')? + start;
    let end = matching_brace(text, brace)?;
    Some(&text[start..=end])
}

fn find_const_decl<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("pub const {name}");
    let start = text.find(&needle)?;
    let end = text[start..].find(';')? + start;
    Some(&text[start..=end])
}

fn find_module_path_block<'a>(text: &'a str, path: &[&str]) -> Option<&'a str> {
    let mut block = text;
    for module in path {
        block = find_item_block(block, "mod", module)?;
    }
    Some(block)
}

fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0_u32;
    for (offset, byte) in text.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn has_named_field(block: &str, field: &str) -> bool {
    block
        .lines()
        .any(|line| line.trim_start().starts_with(&format!("pub {field}:")))
}

fn has_enum_variant(block: &str, variant: &str) -> bool {
    block.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed == variant
            || trimmed.starts_with(&format!("{variant},"))
            || trimmed.starts_with(&format!("{variant} ="))
            || trimmed.starts_with(&format!("{variant}("))
            || trimmed.starts_with(&format!("{variant} {{"))
    })
}

fn has_impl_method(text: &str, type_name: &str, method: &str) -> bool {
    let needle = format!("impl {type_name}");
    let method_needle = format!("fn {method}");
    let mut offset = 0;

    while let Some(found) = text[offset..].find(&needle) {
        let start = offset + found;
        let Some(brace) = text[start..].find('{').map(|brace| start + brace) else {
            return false;
        };
        let Some(end) = matching_brace(text, brace) else {
            return false;
        };
        let impl_block = &text[start..=end];
        if impl_block
            .lines()
            .any(|line| line.trim_start().starts_with("pub ") && line.contains(&method_needle))
        {
            return true;
        }
        offset = end + 1;
    }

    false
}

fn has_reexport(block: &str, expected: &ReexportExpectation) -> bool {
    let normalized = normalize_rustish(block);
    let source = normalize_rustish(expected.source);

    if expected.alias == "*" {
        return normalized.contains(&format!("pub use {source};"));
    }

    let alias = normalize_rustish(expected.alias);
    normalized.contains(&format!("{source} as {alias}"))
        || (expected.source == expected.alias
            && (normalized.contains(&format!("pub use super::{source};"))
                || normalized.contains(&format!("pub use super::{{ {source},"))
                || normalized.contains(&format!(", {source},"))
                || normalized.contains(&format!(", {source} }}"))))
}

fn normalize_rustish(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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
            assert!(
                !surface.structs.is_empty()
                    || !surface.enums.is_empty()
                    || !surface.modules.is_empty()
                    || !surface.functions.is_empty()
                    || !surface.consts.is_empty()
            );
        }
    }
}
