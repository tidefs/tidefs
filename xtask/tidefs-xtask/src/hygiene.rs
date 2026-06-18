// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run all workspace hygiene checks. Returns Ok(()) when no duplicates are
/// found, or Err with a multi-line report of every duplicate found.
pub fn check_workspace_hygiene() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let mut errors: Vec<String> = Vec::new();

    if let Err(e) = check_duplicate_toml_deps(&workspace_root) {
        errors.push(e);
    }
    if let Err(e) = check_duplicate_mod_decls(&workspace_root) {
        errors.push(e);
    }
    if let Err(e) = check_duplicate_use_imports(&workspace_root) {
        errors.push(e);
    }
    if let Err(e) = check_no_build_artifacts(&workspace_root) {
        errors.push(e);
    }
    if let Err(e) = check_duplicate_test_names(&workspace_root) {
        errors.push(e);
    }

    if errors.is_empty() {
        println!(
            "workspace hygiene ok: no duplicate deps, mod decls, use imports, or test names found"
        );
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

// ---------------------------------------------------------------------------
// Workspace root discovery
// ---------------------------------------------------------------------------

fn workspace_root() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
    for ancestor in cwd.ancestors() {
        if ancestor.join("Cargo.toml").exists() && ancestor.join("Cargo.lock").exists() {
            return Ok(ancestor.to_path_buf());
        }
    }
    Err("workspace root not found (no Cargo.toml + Cargo.lock in ancestors)".to_string())
}

// ---------------------------------------------------------------------------
// Duplicate TOML dependency check
// ---------------------------------------------------------------------------

/// Walk every `Cargo.toml` under the workspace root (excluding `target/`),
/// parse `[dependencies]`, `[dev-dependencies]`, and `[build-dependencies]`
/// sections, and flag any package name that appears more than once in the
/// same section of the same file.
pub fn check_duplicate_toml_deps(workspace_root: &Path) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    for entry in walk_cargo_tomls(workspace_root) {
        let path = entry;
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: read error: {e}", path.display()));
                continue;
            }
        };

        let sections = [
            ("[dependencies]", "[dependencies]"),
            ("[dev-dependencies]", "[dev-dependencies]"),
            ("[build-dependencies]", "[build-dependencies]"),
        ];

        for &(header, label) in &sections {
            // Find section start, collect dep names until next section or EOF
            if let Some(dup_errors) = find_duplicate_deps_in_section(&content, &path, header, label)
            {
                errors.extend(dup_errors);
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Collect dep names from a TOML section (line-oriented), return duplicates.
fn find_duplicate_deps_in_section(
    content: &str,
    path: &Path,
    header: &str,
    label: &str,
) -> Option<Vec<String>> {
    let mut in_section = false;
    let mut seen: BTreeMap<String, usize> = BTreeMap::new(); // name -> first line number
    let mut line_num: usize = 0;

    for line in content.lines() {
        line_num += 1;
        let trimmed = line.trim();

        // Detect section header
        if trimmed == header {
            in_section = true;
            continue;
        }

        // Detect next section (any line starting with '[' that isn't the current header)
        if in_section && trimmed.starts_with('[') {
            break; // next section reached
        }

        if !in_section {
            continue;
        }

        // Skip empty lines, comments, and lines without '='
        if trimmed.is_empty() || trimmed.starts_with('#') || !trimmed.contains('=') {
            continue;
        }

        // Extract dep name: "name = ..." or name = ... (quoted or bare)
        let name = extract_toml_key(trimmed);
        if name.is_empty() {
            continue;
        }

        seen.entry(name.to_string())
            .and_modify(|_first_line| {
                // Only report the duplicate, not the first occurrence
            })
            .or_insert(line_num);
    }

    // Now scan again to find duplicates and report them
    let mut errors: Vec<String> = Vec::new();
    let mut seen_count: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    let mut in_section2 = false;
    let mut ln2: usize = 0;
    for line in content.lines() {
        ln2 += 1;
        let trimmed = line.trim();
        if trimmed == header {
            in_section2 = true;
            continue;
        }
        if in_section2 && trimmed.starts_with('[') {
            break;
        }
        if !in_section2 || trimmed.is_empty() || trimmed.starts_with('#') || !trimmed.contains('=')
        {
            continue;
        }
        let name = extract_toml_key(trimmed);
        if name.is_empty() {
            continue;
        }
        seen_count.entry(name.to_string()).or_default().push(ln2);
    }

    for (name, lines) in &seen_count {
        if lines.len() > 1 {
            let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
            errors.push(format!(
                "{}:{}: duplicate dependency '{}' in {} (lines {})",
                path.display(),
                lines[1], // report second occurrence
                name,
                label,
                line_list.join(", ")
            ));
        }
    }

    if errors.is_empty() {
        None
    } else {
        Some(errors)
    }
}

/// Extract the key (dependency name) from a TOML key = value line.
/// Handles: `"name" = ...`, `name = ...`, `name=...`
fn extract_toml_key(line: &str) -> &str {
    let line = line.trim();

    // Quoted key: "name" = ...
    if let Some(rest) = line.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return &rest[..end];
        }
    }

    // Bare key: name = ... (stop at first '=' or whitespace before it)
    if let Some(eq_pos) = line.find('=') {
        let key_part = line[..eq_pos].trim();
        // Handle optional whitespace before =
        if !key_part.is_empty() && !key_part.contains(' ') {
            return key_part;
        }
    }

    ""
}

/// Yield every `Cargo.toml` under `root`, excluding `target/`.
fn walk_cargo_tomls(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    walk_cargo_tomls_recursive(root, &mut results);
    results
}

fn walk_cargo_tomls_recursive(dir: &Path, results: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Skip target directories
        if file_name == "target" && path.is_dir() {
            continue;
        }

        if path.is_dir() {
            // Only recurse into dirs that could contain Cargo.toml (skip hidden dirs)
            if !file_name.starts_with('.') || file_name == ".config" {
                walk_cargo_tomls_recursive(&path, results);
            }
        } else if file_name == "Cargo.toml" {
            results.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Duplicate mod declaration check
// ---------------------------------------------------------------------------

/// Walk every `.rs` file under the workspace root (excluding `target/`)
/// and flag any `mod <name>;` declaration that appears more than once
/// in the same file.
pub fn check_duplicate_mod_decls(workspace_root: &Path) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    for path in walk_rs_files(workspace_root) {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: read error: {e}", path.display()));
                continue;
            }
        };

        let mut seen: BTreeMap<String, Vec<usize>> = BTreeMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Match `mod name;` or `pub mod name;` or `pub(crate) mod name;`
            if let Some(mod_name) = extract_mod_name(trimmed) {
                seen.entry(mod_name.to_string()).or_default().push(line_num);
            }
        }

        for (mod_name, lines) in &seen {
            if lines.len() > 1 {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                errors.push(format!(
                    "{}:{}: duplicate mod declaration '{}' (lines {})",
                    path.display(),
                    lines[1],
                    mod_name,
                    line_list.join(", ")
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Extract module name from a `mod <name>;` declaration, if present.
fn extract_mod_name(line: &str) -> Option<&str> {
    let line = line.trim();

    // Must end with ';'
    if !line.ends_with(';') {
        return None;
    }

    // Strip leading visibility modifiers
    let after_vis = line
        .strip_prefix("pub(crate) mod ")
        .or_else(|| line.strip_prefix("pub(in crate) mod "))
        .or_else(|| line.strip_prefix("pub(super) mod "))
        .or_else(|| line.strip_prefix("pub mod "))
        .or_else(|| line.strip_prefix("mod "))?;

    // after_vis should be like "name;" or "name ;"
    let name = after_vis.trim_end_matches(';').trim();
    if name.is_empty() || name.contains(' ') || name.contains("::") {
        return None;
    }

    // Valid Rust identifier check: must start with a letter or underscore
    let first = name.chars().next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }

    Some(name)
}

// ---------------------------------------------------------------------------
// Duplicate use import check
// ---------------------------------------------------------------------------

/// Walk every `.rs` file under the workspace root (excluding `target/`)
/// and flag any `use ...;` statement whose normalized path appears more
/// than once in the same file.
pub fn check_duplicate_use_imports(workspace_root: &Path) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    for path in walk_rs_files(workspace_root) {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: read error: {e}", path.display()));
                continue;
            }
        };

        let mut seen: BTreeMap<String, Vec<usize>> = BTreeMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Match `use ...;` (but not `use` inside strings or comments)
            // Simple heuristic: line starts with "use " and ends with ";"
            if let Some(use_path) = extract_use_path(trimmed) {
                let normalized = normalize_use_path(use_path);
                if !normalized.is_empty() {
                    seen.entry(normalized).or_default().push(line_num);
                }
            }
        }

        for (use_path, lines) in &seen {
            if lines.len() > 1 {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                errors.push(format!(
                    "{}:{}: duplicate use import '{}' (lines {})",
                    path.display(),
                    lines[1],
                    use_path,
                    line_list.join(", ")
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Extract the use path from a `use ...;` line.
fn extract_use_path(line: &str) -> Option<&str> {
    let line = line.trim();

    if !line.starts_with("use ") || !line.ends_with(';') {
        return None;
    }

    // Strip 'use ' prefix and ';' suffix
    let inner = line
        .strip_prefix("use ")
        .and_then(|s| s.strip_suffix(';'))?;

    Some(inner.trim())
}

/// Normalize a use path by collapsing whitespace around `::` and trimming.
/// For braced imports like `foo::{a, b}`, we keep only the prefix plus
/// a marker to detect duplicates of the same braced group.
fn normalize_use_path(path: &str) -> String {
    let path = path.trim();

    // Collapse multiple whitespace chars
    let path = path.split_whitespace().collect::<Vec<_>>().join(" ");

    // Collapse whitespace around ::

    path.replace(" :: ", "::")
        .replace(":: ", "::")
        .replace(" ::", "::")
}

// ---------------------------------------------------------------------------
// File walking helpers
// ---------------------------------------------------------------------------

/// Yield every `.rs` file under `root`, excluding `target/` and hidden dirs.
fn walk_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    walk_rs_files_recursive(root, &mut results);
    results
}

fn walk_rs_files_recursive(dir: &Path, results: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if file_name == "target" && path.is_dir() {
            continue;
        }

        if path.is_dir() {
            if !file_name.starts_with('.') || file_name == ".config" || file_name == ".cargo" {
                walk_rs_files_recursive(&path, results);
            }
        } else if file_name.ends_with(".rs") {
            results.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Duplicate test name check
// ---------------------------------------------------------------------------

/// Walk every `.rs` file under the workspace root (excluding `target/`) and
/// flag any `#[test]` function whose name appears more than once in the same
/// file.
pub fn check_duplicate_test_names(workspace_root: &Path) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    for path in walk_rs_files(workspace_root) {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: read error: {e}", path.display()));
                continue;
            }
        };

        let mut seen: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut pending_test: Option<usize> = None;

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Detect a #[test] attribute line (standalone, with parens, or inline-before-fn).
            let is_test_attr = trimmed == "#[test]"
                || trimmed.starts_with("#[test](")
                || (trimmed.starts_with("#[test]") && {
                    let rest = &trimmed["#[test]".len()..];
                    let rest = rest.trim_start();
                    rest.starts_with("fn ")
                });

            if is_test_attr {
                // Try to extract inline fn name on the same line
                if let Some(rest) = trimmed.strip_prefix("#[test]") {
                    // Strip paren content if present: #[test] or #[test(something)]
                    let rest = if let Some(after_paren) = rest.strip_prefix('(') {
                        if let Some(idx) = after_paren.find(')') {
                            &after_paren[idx + 1..]
                        } else {
                            rest
                        }
                    } else {
                        rest
                    };
                    let rest = rest.trim_start();
                    if rest.starts_with("fn ") {
                        if let Some(name) = extract_test_fn_name(rest) {
                            seen.entry(name.to_string()).or_default().push(line_num);
                            pending_test = None;
                            continue;
                        }
                    }
                }
                pending_test = Some(line_num);
                continue;
            }

            // Skip other attribute lines while waiting for the fn
            if pending_test.is_some() && trimmed.starts_with("#[") {
                continue;
            }

            // Extract fn name after a pending #[test]
            if let Some(_test_line) = pending_test.take() {
                if trimmed.starts_with("fn ") {
                    if let Some(name) = extract_test_fn_name(trimmed) {
                        seen.entry(name.to_string()).or_default().push(line_num);
                    }
                }
            }
        }

        for (test_name, lines) in &seen {
            if lines.len() > 1 {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                errors.push(format!(
                    "{}:{}: duplicate test function name '{}' (lines {})",
                    path.display(),
                    lines[1],
                    test_name,
                    line_list.join(", ")
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Extract the function name from a line starting with `fn`.
fn extract_test_fn_name(line: &str) -> Option<&str> {
    let line = line.trim();
    let after_fn = line.strip_prefix("fn ")?;
    let name_end = after_fn.find('(')?;
    let name = &after_fn[..name_end].trim();
    if name.is_empty() {
        return None;
    }
    let first = name.chars().next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }
    Some(name)
}

// ---------------------------------------------------------------------------
// Build-artifact gate: prevent committing build products
// ---------------------------------------------------------------------------

/// Reject tracked `*.orig`, `target/`, `result`, `.tidefs_*`, and editor
/// turds (`*.bak`, `*.tmp`).  Scans `git ls-files --cached --others
/// --exclude-standard` so only files that would be committed are checked.
pub fn check_no_build_artifacts(workspace_root: &Path) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();
    let banned_suffixes = [".orig", ".bak", ".tmp"];
    let banned_components = ["target", "result"];

    let output = std::process::Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(workspace_root)
        .output();

    let files = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Err("git ls-files failed".to_string()),
    };

    for line in files.lines() {
        let p = line.trim();
        if p.is_empty() {
            continue;
        }
        for suffix in &banned_suffixes {
            if p.ends_with(suffix) {
                errors.push(format!(
                    "build-artifact {p}: {suffix} files are never committed"
                ));
            }
        }
        if p.starts_with(".tidefs_") {
            errors.push(format!(
                "build-artifact {p}: .tidefs_* device files are never committed"
            ));
        }
        for seg in p.split('/') {
            if banned_components.contains(&seg) {
                errors.push(format!(
                    "build-artifact {p}: {seg}/ directories are never committed"
                ));
            }
        }
        if p.ends_with("~") {
            errors.push(format!(
                "build-artifact {p}: editor backup files are never committed"
            ));
        }
    }

    if errors.is_empty() {
        println!("build-artifact gate ok: no *.orig, target/, result, .tidefs_*, or editor turds tracked");
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- extract_toml_key --

    #[test]
    fn toml_key_quoted() {
        assert_eq!(extract_toml_key(r#""serde" = "1.0""#), "serde");
    }

    #[test]
    fn toml_key_bare() {
        assert_eq!(extract_toml_key("serde = \"1.0\""), "serde");
    }

    #[test]
    fn toml_key_with_version_brace() {
        assert_eq!(extract_toml_key("serde = { version = \"1.0\" }"), "serde");
    }

    #[test]
    fn toml_key_with_path() {
        assert_eq!(
            extract_toml_key("tidefs-foo = { path = \"../tidefs-foo\" }"),
            "tidefs-foo"
        );
    }

    #[test]
    fn toml_key_optional() {
        assert_eq!(
            extract_toml_key("tidefs-foo = { path = \"../tidefs-foo\", optional = true }"),
            "tidefs-foo"
        );
    }

    #[test]
    fn toml_key_not_a_dep_line() {
        assert_eq!(extract_toml_key("# serde = \"1.0\""), "");
        assert_eq!(extract_toml_key(""), "");
        assert_eq!(extract_toml_key("[dependencies]"), "");
    }

    // -- extract_mod_name --

    #[test]
    fn mod_name_simple() {
        assert_eq!(extract_mod_name("mod foo;"), Some("foo"));
    }

    #[test]
    fn mod_name_pub() {
        assert_eq!(extract_mod_name("pub mod foo;"), Some("foo"));
    }

    #[test]
    fn mod_name_pub_crate() {
        assert_eq!(extract_mod_name("pub(crate) mod foo;"), Some("foo"));
    }

    #[test]
    fn mod_name_not_a_mod() {
        assert_eq!(extract_mod_name("let x = 1;"), None);
        assert_eq!(extract_mod_name("// mod foo;"), None);
        assert_eq!(extract_mod_name("use mod;"), None);
    }

    #[test]
    fn mod_name_with_path_rejected() {
        assert_eq!(extract_mod_name("mod foo::bar;"), None);
    }

    // -- extract_use_path + normalize_use_path --

    #[test]
    fn use_path_simple() {
        assert_eq!(extract_use_path("use std::fs;"), Some("std::fs"));
    }

    #[test]
    fn use_path_with_braces() {
        assert_eq!(
            extract_use_path("use std::{fs, io};"),
            Some("std::{fs, io}")
        );
    }

    #[test]
    fn use_path_with_self() {
        assert_eq!(extract_use_path("use crate::foo;"), Some("crate::foo"));
    }

    #[test]
    fn use_path_not_use() {
        assert_eq!(extract_use_path("let x = 1;"), None);
        assert_eq!(extract_use_path("// use std::fs;"), None);
    }

    #[test]
    fn normalize_collapses_whitespace() {
        let path = "std :: fs";
        assert_eq!(normalize_use_path(path), "std::fs");
    }

    #[test]
    fn normalize_trims() {
        assert_eq!(normalize_use_path("  std::fs  "), "std::fs");
    }

    // -- check_duplicate_toml_deps integration test --

    #[test]
    fn detects_duplicate_dep_in_toml() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("Cargo.toml");
        std::fs::write(
            &toml_path,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\ntokio = \"1.0\"\nserde = \"1.0\"\n",
        )
        .unwrap();

        let result = check_duplicate_toml_deps(dir.path());
        assert!(result.is_err(), "should detect duplicate serde");
        let err = result.unwrap_err();
        assert!(
            err.contains("duplicate dependency"),
            "unexpected error: {err}"
        );
        assert!(err.contains("serde"), "unexpected error: {err}");
    }

    #[test]
    fn no_duplicate_dep_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("Cargo.toml");
        std::fs::write(
            &toml_path,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\ntokio = \"1.0\"\n",
        )
        .unwrap();

        let result = check_duplicate_toml_deps(dir.path());
        assert!(result.is_ok(), "no duplicates expected, got: {result:?}");
    }

    // -- check_duplicate_mod_decls integration test --

    #[test]
    fn detects_duplicate_mod_decl() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(&rs_path, "mod foo;\nmod bar;\nmod foo;\n").unwrap();

        let result = check_duplicate_mod_decls(dir.path());
        assert!(result.is_err(), "should detect duplicate mod foo");
        let err = result.unwrap_err();
        assert!(
            err.contains("duplicate mod declaration"),
            "unexpected error: {err}"
        );
        assert!(err.contains("foo"), "unexpected error: {err}");
    }

    #[test]
    fn no_duplicate_mod_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(&rs_path, "mod foo;\nmod bar;\nmod baz;\n").unwrap();

        let result = check_duplicate_mod_decls(dir.path());
        assert!(result.is_ok(), "no duplicates: {result:?}");
    }

    // -- check_duplicate_use_imports integration test --

    #[test]
    fn detects_duplicate_use_import() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(&rs_path, "use std::fs;\nuse std::io;\nuse std::fs;\n").unwrap();

        let result = check_duplicate_use_imports(dir.path());
        assert!(result.is_err(), "should detect duplicate use std::fs");
        let err = result.unwrap_err();
        assert!(
            err.contains("duplicate use import"),
            "unexpected error: {err}"
        );
        assert!(err.contains("std::fs"), "unexpected error: {err}");
    }

    #[test]
    fn no_duplicate_use_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(&rs_path, "use std::fs;\nuse std::io;\nuse std::path;\n").unwrap();

        let result = check_duplicate_use_imports(dir.path());
        assert!(result.is_ok(), "no duplicates: {result:?}");
    }

    // -- extract_test_fn_name --

    #[test]
    fn extract_test_fn_simple() {
        assert_eq!(extract_test_fn_name("fn test_foo() {"), Some("test_foo"));
    }

    #[test]
    fn extract_test_fn_with_args() {
        assert_eq!(
            extract_test_fn_name("fn test_bar(a: u32, b: &str) {"),
            Some("test_bar")
        );
    }

    #[test]
    fn extract_test_fn_whitespace() {
        assert_eq!(
            extract_test_fn_name("  fn   test_baz  (  ) {"),
            Some("test_baz")
        );
    }

    #[test]
    fn extract_test_fn_not_fn() {
        assert_eq!(extract_test_fn_name("let x = 1;"), None);
        assert_eq!(extract_test_fn_name("// fn test_foo() {"), None);
    }

    #[test]
    fn extract_test_fn_empty_name() {
        assert_eq!(extract_test_fn_name("fn () {"), None);
    }

    // -- check_duplicate_test_names integration tests --

    #[test]
    fn detects_duplicate_test_names() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(
            &rs_path,
            "#[test]\nfn test_foo() {}\n\n#[test]\nfn test_bar() {}\n\n#[test]\nfn test_foo() {}\n",
        )
        .unwrap();

        let result = check_duplicate_test_names(dir.path());
        assert!(result.is_err(), "should detect duplicate test_foo");
        let err = result.unwrap_err();
        assert!(
            err.contains("duplicate test function name"),
            "unexpected error: {err}"
        );
        assert!(err.contains("test_foo"), "unexpected error: {err}");
    }

    #[test]
    fn detects_duplicate_test_names_inline() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(
            &rs_path,
            "#[test] fn test_x() {}\n#[test] fn test_y() {}\n#[test] fn test_x() {}\n",
        )
        .unwrap();

        let result = check_duplicate_test_names(dir.path());
        assert!(result.is_err(), "should detect duplicate test_x");
        let err = result.unwrap_err();
        assert!(
            err.contains("duplicate test function name"),
            "unexpected: {err}"
        );
        assert!(err.contains("test_x"), "unexpected: {err}");
    }

    #[test]
    fn detects_duplicate_with_other_attrs() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(
            &rs_path,
            "#[test]\n#[should_panic]\nfn test_panic() {}\n\n#[test]\nfn test_panic() {}\n",
        )
        .unwrap();

        let result = check_duplicate_test_names(dir.path());
        assert!(result.is_err(), "should detect duplicate test_panic");
        let err = result.unwrap_err();
        assert!(
            err.contains("duplicate test function name"),
            "unexpected: {err}"
        );
        assert!(err.contains("test_panic"), "unexpected: {err}");
    }

    #[test]
    fn no_duplicate_test_names_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(
            &rs_path,
            "#[test]\nfn test_a() {}\n\n#[test]\nfn test_b() {}\n\n#[test]\nfn test_c() {}\n",
        )
        .unwrap();

        let result = check_duplicate_test_names(dir.path());
        assert!(result.is_ok(), "no duplicates expected, got: {result:?}");
    }

    #[test]
    fn ignores_non_test_functions() {
        let dir = tempfile::tempdir().unwrap();
        let rs_path = dir.path().join("lib.rs");
        std::fs::write(
            &rs_path,
            "fn helper() {}\n\n#[test]\nfn test_ok() {}\n\nfn helper() {}\n",
        )
        .unwrap();

        let result = check_duplicate_test_names(dir.path());
        assert!(
            result.is_ok(),
            "should not flag non-#[test] duplicates, got: {result:?}"
        );
    }
}
