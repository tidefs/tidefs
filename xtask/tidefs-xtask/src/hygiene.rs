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
    if let Err(e) = check_validation_harness_review_debt_markers(&workspace_root) {
        errors.push(e);
    }

    if errors.is_empty() {
        println!(
            "workspace hygiene ok: no duplicate deps, mod decls, use imports, test names, \
             or anonymous validation debt markers found"
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
// Review-debt marker gate for active validation and harness text
// ---------------------------------------------------------------------------

/// Reject anonymous debt-marker wording in active validation scripts and
/// harness surfaces. Negative-test/refusal fixtures remain allowed when the
/// surrounding text classifies them explicitly.
pub fn check_validation_harness_review_debt_markers(workspace_root: &Path) -> Result<(), String> {
    let paths = tracked_validation_harness_files(workspace_root)?;
    check_review_debt_markers_in_paths(workspace_root, &paths)
}

fn tracked_validation_harness_files(workspace_root: &Path) -> Result<Vec<PathBuf>, String> {
    let output = std::process::Command::new("git")
        .args(["ls-files", "--", "nix/vm", "scripts", "validation"])
        .current_dir(workspace_root)
        .output();

    let files = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Err("git ls-files failed for validation harness debt scan".to_string()),
    };

    Ok(files
        .lines()
        .map(str::trim)
        .filter(|p| is_active_validation_harness_path(p))
        .map(|p| workspace_root.join(p))
        .collect())
}

fn check_review_debt_markers_in_paths(
    workspace_root: &Path,
    paths: &[PathBuf],
) -> Result<(), String> {
    let mut errors = Vec::new();

    for path in paths {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: read error: {e}", path.display()));
                continue;
            }
        };
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            if !line_can_carry_review_marker(path, line) {
                continue;
            }
            let Some(marker) = review_debt_marker_in_line(line) else {
                continue;
            };
            if marker_context_is_classified(&lines, idx) {
                continue;
            }
            let display_path = path.strip_prefix(workspace_root).unwrap_or(path);
            errors.push(format!(
                "{}:{}: anonymous review-debt marker '{}'; use a TFR id/register entry or \
                 classify negative-test/refusal fixture text",
                display_path.display(),
                idx + 1,
                marker
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

fn is_active_validation_harness_path(path: &str) -> bool {
    let scanned_root = path.starts_with("nix/vm/")
        || path.starts_with("scripts/")
        || path.starts_with("validation/");
    if !scanned_root {
        return false;
    }

    if path.starts_with("validation/artifacts/") || path.starts_with("validation/format-golden/") {
        return false;
    }

    let Some(file_name) = Path::new(path).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if file_name == "README.md" || file_name == "claims.toml" || file_name == "xfstests_git_rev.txt"
    {
        return true;
    }

    matches!(
        Path::new(path).extension().and_then(|e| e.to_str()),
        Some(
            "bash"
                | "c"
                | "cfg"
                | "conf"
                | "fio"
                | "h"
                | "json"
                | "md"
                | "nix"
                | "py"
                | "rs"
                | "sh"
                | "toml"
                | "txt"
                | "yaml"
                | "yml"
        )
    )
}

fn line_can_carry_review_marker(path: &Path, line: &str) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "c" | "h" | "rs" => {
            let trimmed = line.trim_start();
            trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
                || trimmed.contains("//")
                || trimmed.contains("/*")
                || trimmed.contains('"')
        }
        _ => true,
    }
}

fn review_debt_marker_in_line(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    for marker in [
        "todo",
        "fixme",
        "hack",
        "tbd",
        "placeholder",
        "fake",
        "dummy",
        "continuation",
    ] {
        if contains_ascii_word(&lower, marker) {
            return Some(marker);
        }
    }
    if contains_debt_later_phrase(&lower) {
        return Some("later");
    }
    None
}

fn marker_context_is_classified(lines: &[&str], marker_idx: usize) -> bool {
    let start = marker_idx.saturating_sub(2);
    let end = (marker_idx + 3).min(lines.len());
    lines[start..end]
        .iter()
        .any(|line| line_has_fixture_or_refusal_classification(line))
}

fn line_has_fixture_or_refusal_classification(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let negative_test = lower.contains("negative-test") || lower.contains("negative test");
    let fixture_text =
        contains_ascii_word(&lower, "fixture") || contains_ascii_word(&lower, "text");
    let refusal = contains_ascii_word(&lower, "refusal") || lower.contains("refuse");
    let refusal_context = contains_ascii_word(&lower, "fixture")
        || contains_ascii_word(&lower, "placeholder")
        || contains_ascii_word(&lower, "sandbox")
        || contains_ascii_word(&lower, "text");

    (negative_test && fixture_text) || (refusal && refusal_context)
}

fn contains_debt_later_phrase(line: &str) -> bool {
    [
        "do later",
        "fix later",
        "implement later",
        "remove later",
        "replace later",
        "clean later",
        "wire later",
        "later todo",
        "later fix",
    ]
    .iter()
    .any(|phrase| line.contains(phrase))
}

fn contains_ascii_word(line: &str, needle: &str) -> bool {
    let mut rest = line;
    while let Some(pos) = rest.find(needle) {
        let before = rest[..pos].chars().next_back();
        let after = rest[pos + needle.len()..].chars().next();
        if !is_ascii_word_char(before) && !is_ascii_word_char(after) {
            return true;
        }
        rest = &rest[pos + needle.len()..];
    }
    false
}

fn is_ascii_word_char(ch: Option<char>) -> bool {
    ch.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
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

    #[test]
    fn rejects_anonymous_validation_marker_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nix/vm/example-validation.nix");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# TODO: wire this validation later\n").unwrap();

        let result = check_review_debt_markers_in_paths(dir.path(), &[path]);
        assert!(result.is_err(), "anonymous marker should fail");
        let err = result.unwrap_err();
        assert!(err.contains("anonymous review-debt marker"), "{err}");
        assert!(err.contains("nix/vm/example-validation.nix:1"), "{err}");
    }

    #[test]
    fn allows_classified_refusal_placeholder_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nix/vm/example-validation.nix");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "echo \"WARNING: placeholder for Nix sandbox\"\n\
             echo \"REFUSAL: kernel module unavailable in this sandbox\"\n",
        )
        .unwrap();

        let result = check_review_debt_markers_in_paths(dir.path(), &[path]);
        assert!(
            result.is_ok(),
            "classified refusal text should pass: {result:?}"
        );
    }

    #[test]
    fn allows_classified_negative_test_fixture_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validation/review-marker-negative.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "# negative-test fixture for debt-marker policy\nmarker = \"TODO\"\n",
        )
        .unwrap();

        let result = check_review_debt_markers_in_paths(dir.path(), &[path]);
        assert!(
            result.is_ok(),
            "classified fixture text should pass: {result:?}"
        );
    }

    #[test]
    fn rejects_bare_fixture_context_for_validation_marker_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validation/review-marker-fixture.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# fixture setup\nmarker = \"TODO\"\n").unwrap();

        let result = check_review_debt_markers_in_paths(dir.path(), &[path]);
        assert!(
            result.is_err(),
            "bare fixture wording should not classify debt markers"
        );
    }

    #[test]
    fn rejects_bare_refusal_context_for_validation_marker_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validation/review-marker-refusal.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# refusal path\nmarker = \"TODO\"\n").unwrap();

        let result = check_review_debt_markers_in_paths(dir.path(), &[path]);
        assert!(
            result.is_err(),
            "bare refusal wording should not classify debt markers"
        );
    }

    #[test]
    fn ignores_non_text_code_identifiers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scripts/identifier-fixture.c");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "char dummy = vp[PAGE + 1];\n(void)dummy;\n").unwrap();

        let result = check_review_debt_markers_in_paths(dir.path(), &[path]);
        assert!(
            result.is_ok(),
            "ordinary code identifier should pass: {result:?}"
        );
    }
}
