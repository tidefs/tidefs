// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

const PACKAGE_CLASSIFICATION_DOC: &str = "docs/workspace-package-classification.md";
const DOCUMENTATION_AUTHORITY_REGISTER: &str = "docs/DOCUMENTATION_AUTHORITY_REGISTER.md";
const REVIEW_TODO_REGISTER: &str = "docs/REVIEW_TODO_REGISTER.md";

const AUTHORITY_EVIDENCE_DOCS: &[&str] = &[
    PACKAGE_CLASSIFICATION_DOC,
    DOCUMENTATION_AUTHORITY_REGISTER,
    REVIEW_TODO_REGISTER,
    "docs/WHOLE_REPO_REVIEW.md",
];

#[derive(Debug)]
pub struct DocAuthorityDriftError {
    violations: Vec<String>,
}

impl fmt::Display for DocAuthorityDriftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "doc authority drift check failed:")?;
        for violation in &self.violations {
            writeln!(f, "- {violation}")?;
        }
        Ok(())
    }
}

pub fn check_current_workspace() -> Result<(), DocAuthorityDriftError> {
    let root = find_workspace_root().ok_or_else(|| DocAuthorityDriftError {
        violations: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    check_workspace_root(&root)
}

fn check_workspace_root(root: &Path) -> Result<(), DocAuthorityDriftError> {
    let current_package_names = load_current_package_names(root).map_err(single_violation)?;
    let retired_crates =
        load_retired_crate_names(root, &current_package_names).map_err(single_violation)?;
    let authority_states = load_documentation_authority_states(root).map_err(single_violation)?;
    let valid_register_ids = load_review_register_ids(root).map_err(single_violation)?;
    let docs = collect_markdown_docs(root).map_err(single_violation)?;

    let mut violations = BTreeSet::new();
    let mut scanned_docs = 0_usize;
    for rel_path in docs {
        if !should_scan_doc(&rel_path, &authority_states) {
            continue;
        }
        scanned_docs += 1;
        scan_doc(
            root,
            &rel_path,
            &retired_crates,
            &valid_register_ids,
            &mut violations,
        );
    }

    if violations.is_empty() {
        println!(
            "doc authority drift ok: scanned {scanned_docs} live Markdown docs; retired_crates={}; register_ids={}",
            retired_crates.len(),
            valid_register_ids.len()
        );
        Ok(())
    } else {
        Err(DocAuthorityDriftError {
            violations: violations.into_iter().collect(),
        })
    }
}

fn single_violation(message: String) -> DocAuthorityDriftError {
    DocAuthorityDriftError {
        violations: vec![message],
    }
}

fn should_scan_doc(rel_path: &str, authority_states: &BTreeMap<String, AuthorityState>) -> bool {
    if AUTHORITY_EVIDENCE_DOCS.contains(&rel_path) {
        return false;
    }
    !matches!(
        authority_states.get(rel_path),
        Some(AuthorityState::HistoricalInput | AuthorityState::DeleteCandidate)
    )
}

fn scan_doc(
    root: &Path,
    rel_path: &str,
    retired_crates: &BTreeSet<String>,
    valid_register_ids: &BTreeSet<String>,
    violations: &mut BTreeSet<String>,
) {
    let path = root.join(rel_path);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            violations.insert(format!("{rel_path}:0: cannot read Markdown doc: {err}"));
            return;
        }
    };

    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;

        for crate_name in extract_tidefs_crate_names(line) {
            if retired_crates.contains(&crate_name) {
                violations.insert(format!(
                    "{rel_path}:{line_number}: retired crate reference `{crate_name}`; expected a current crate from {PACKAGE_CLASSIFICATION_DOC} or a historical-input classification in {DOCUMENTATION_AUTHORITY_REGISTER}"
                ));
            }
        }

        for doc_ref in extract_doc_references(line, rel_path) {
            if !root.join(&doc_ref.rel_target).exists() {
                violations.insert(format!(
                    "{rel_path}:{line_number}: missing doc path `{}`; expected retargeting to an existing path, restoring the path, or classifying this document as historical input in {DOCUMENTATION_AUTHORITY_REGISTER}",
                    doc_ref.raw
                ));
            }
        }

        for register_id in extract_register_ids(line) {
            if !valid_register_ids.contains(&register_id) {
                violations.insert(format!(
                    "{rel_path}:{line_number}: stale register id `{register_id}`; expected a live row in {REVIEW_TODO_REGISTER} or an updated reference"
                ));
            }
        }
    }
}

fn load_current_package_names(root: &Path) -> Result<BTreeSet<String>, String> {
    let text = read_repo_file(root, PACKAGE_CLASSIFICATION_DOC)?;
    let rows = parse_package_classification_rows(&text)?;
    let mut names = BTreeSet::new();
    for row in rows {
        names.insert(row.package_name);
        if let Some(root_name) = row.package_root.rsplit('/').next() {
            names.insert(root_name.to_string());
        }
    }
    Ok(names)
}

fn load_retired_crate_names(
    root: &Path,
    current_package_names: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let text = read_repo_file(root, PACKAGE_CLASSIFICATION_DOC)?;
    let mut names = BTreeSet::new();
    for name in extract_tidefs_crate_names(&text) {
        if !current_package_names.contains(&name) {
            names.insert(name);
        }
    }
    Ok(names)
}

fn load_documentation_authority_states(
    root: &Path,
) -> Result<BTreeMap<String, AuthorityState>, String> {
    let text = read_repo_file(root, DOCUMENTATION_AUTHORITY_REGISTER)?;
    let mut states = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        let cells = split_markdown_table_row(trimmed);
        if cells.len() < 3 || cells.iter().all(|cell| is_markdown_separator_cell(cell)) {
            continue;
        }
        let path = strip_markdown_code(&cells[0]);
        if !path.starts_with("docs/") {
            continue;
        }
        if let Some(state) = AuthorityState::parse(&cells[1]) {
            states.insert(path, state);
        }
    }
    Ok(states)
}

fn load_review_register_ids(root: &Path) -> Result<BTreeSet<String>, String> {
    let text = read_repo_file(root, REVIEW_TODO_REGISTER)?;
    let mut ids = BTreeSet::new();
    let mut in_table = false;
    let mut saw_header = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "| Id | Area | Finding | Required Direction |" {
            in_table = true;
            saw_header = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !trimmed.starts_with('|') {
            break;
        }
        let cells = split_markdown_table_row(trimmed);
        if cells.iter().all(|cell| is_markdown_separator_cell(cell)) {
            continue;
        }
        if let Some(id) = cells.first().map(|cell| strip_markdown_code(cell)) {
            if is_register_id(&id) {
                ids.insert(id);
            }
        }
    }
    if !saw_header {
        return Err(format!(
            "{REVIEW_TODO_REGISTER} must contain the review-register table header"
        ));
    }
    Ok(ids)
}

fn collect_markdown_docs(root: &Path) -> Result<Vec<String>, String> {
    let docs_root = root.join("docs");
    let mut docs = Vec::new();
    collect_markdown_docs_in(root, &docs_root, &mut docs)?;
    docs.sort();
    Ok(docs)
}

fn collect_markdown_docs_in(root: &Path, dir: &Path, docs: &mut Vec<String>) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|err| format!("cannot read docs directory {}: {err}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("cannot read docs directory entry: {err}"))?;
        paths.push(entry.path());
    }
    paths.sort();

    for path in paths {
        if path.is_dir() {
            collect_markdown_docs_in(root, &path, docs)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
            docs.push(rel_path(root, &path)?);
        }
    }
    Ok(())
}

fn read_repo_file(root: &Path, rel_path: &str) -> Result<String, String> {
    fs::read_to_string(root.join(rel_path)).map_err(|err| format!("cannot read {rel_path}: {err}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageClassificationRow {
    package_root: String,
    package_name: String,
}

fn parse_package_classification_rows(text: &str) -> Result<Vec<PackageClassificationRow>, String> {
    const HEADER: &str = "| Package root | Package | Cargo status | Role | Disposition |";

    let mut rows = Vec::new();
    let mut in_table = false;
    let mut saw_header = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == HEADER {
            in_table = true;
            saw_header = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !line.starts_with('|') {
            break;
        }
        let cells = split_markdown_table_row(line);
        if cells.iter().all(|cell| is_markdown_separator_cell(cell)) {
            continue;
        }
        if cells.len() != 5 {
            return Err(format!(
                "{PACKAGE_CLASSIFICATION_DOC} package table row has {} cells, expected 5: {line}",
                cells.len()
            ));
        }
        let package_root = strip_markdown_code(&cells[0]);
        let package_name = strip_markdown_code(&cells[1]);
        if package_root.is_empty() || package_name.is_empty() {
            return Err(format!(
                "{PACKAGE_CLASSIFICATION_DOC} package table row must have a package root and name: {line}"
            ));
        }
        rows.push(PackageClassificationRow {
            package_root,
            package_name,
        });
    }

    if !saw_header {
        return Err(format!(
            "{PACKAGE_CLASSIFICATION_DOC} must contain package classification table header `{HEADER}`"
        ));
    }
    Ok(rows)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityState {
    CurrentPolicy,
    CurrentSpec,
    HistoricalInput,
    DeleteCandidate,
}

impl AuthorityState {
    fn parse(value: &str) -> Option<Self> {
        let normalized = strip_markdown_code(value);
        match normalized.as_str() {
            "Current policy" => Some(Self::CurrentPolicy),
            "Current spec" => Some(Self::CurrentSpec),
            "Historical input" => Some(Self::HistoricalInput),
            "Delete candidate" => Some(Self::DeleteCandidate),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct DocReference {
    raw: String,
    rel_target: String,
}

fn extract_doc_references(line: &str, source_rel_path: &str) -> BTreeSet<DocReference> {
    let mut refs = BTreeSet::new();
    collect_markdown_link_targets(line, source_rel_path, &mut refs);
    collect_reference_definition_target(line, source_rel_path, &mut refs);
    collect_inline_doc_tokens(line, source_rel_path, &mut refs);
    refs
}

fn collect_markdown_link_targets(
    line: &str,
    source_rel_path: &str,
    refs: &mut BTreeSet<DocReference>,
) {
    let mut rest = line;
    while let Some(start) = rest.find("](") {
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find(')') else {
            break;
        };
        add_doc_reference(&after_start[..end], source_rel_path, refs);
        rest = &after_start[end + 1..];
    }
}

fn collect_reference_definition_target(
    line: &str,
    source_rel_path: &str,
    refs: &mut BTreeSet<DocReference>,
) {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('[') {
        return;
    }
    if let Some((_, target)) = trimmed.split_once("]:") {
        if let Some(first) = target.split_whitespace().next() {
            add_doc_reference(first, source_rel_path, refs);
        }
    }
}

fn collect_inline_doc_tokens(line: &str, source_rel_path: &str, refs: &mut BTreeSet<DocReference>) {
    for token in line.split(|ch: char| ch.is_whitespace()) {
        let trimmed = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '`' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';' | ':'
            )
        });
        if trimmed.contains("docs/") || has_doc_extension(trimmed) {
            add_doc_reference(trimmed, source_rel_path, refs);
        }
    }
}

fn add_doc_reference(raw: &str, source_rel_path: &str, refs: &mut BTreeSet<DocReference>) {
    let cleaned = clean_reference(raw);
    if let Some(rel_target) = resolve_doc_reference(&cleaned, source_rel_path) {
        refs.insert(DocReference {
            raw: cleaned,
            rel_target,
        });
    }
}

fn clean_reference(raw: &str) -> String {
    let without_anchor = raw
        .split('#')
        .next()
        .unwrap_or(raw)
        .split('?')
        .next()
        .unwrap_or(raw);
    without_anchor
        .trim()
        .trim_matches(|ch: char| {
            matches!(
                ch,
                '`' | '"'
                    | '\''
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '<'
                    | '>'
                    | ','
                    | '.'
                    | ';'
                    | ':'
            )
        })
        .to_string()
}

fn resolve_doc_reference(raw: &str, source_rel_path: &str) -> Option<String> {
    if raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("http://")
        || raw.starts_with("https://")
        || raw.starts_with("mailto:")
    {
        return None;
    }

    let path = if raw.starts_with("/docs/") {
        PathBuf::from(raw.trim_start_matches('/'))
    } else if raw.starts_with("docs/") {
        PathBuf::from(raw)
    } else if raw.starts_with("./") || raw.starts_with("../") || has_doc_extension(raw) {
        let source_dir = Path::new(source_rel_path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        source_dir.join(raw)
    } else {
        return None;
    };

    let normalized = normalize_rel_path(&path)?;
    if normalized.starts_with("docs/") {
        Some(normalized)
    } else {
        None
    }
}

fn has_doc_extension(value: &str) -> bool {
    value.ends_with(".md") || value.ends_with(".adoc")
}

fn normalize_rel_path(path: &Path) -> Option<String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => components.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                components.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if components.is_empty() {
        None
    } else {
        Some(components.join("/"))
    }
}

fn extract_tidefs_crate_names(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut names = BTreeSet::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        let rest = &text[index..];
        let Some(offset) = rest.find("tidefs-") else {
            break;
        };
        let start = index + offset;
        let mut end = start + "tidefs-".len();
        while end < bytes.len() {
            let byte = bytes[end];
            if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        names.insert(text[start..end].to_string());
        index = end;
    }
    names
}

fn extract_register_ids(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut ids = BTreeSet::new();
    let mut index = 0_usize;
    while index + 7 <= bytes.len() {
        if &bytes[index..index + 4] == b"TFR-"
            && bytes[index + 4].is_ascii_digit()
            && bytes[index + 5].is_ascii_digit()
            && bytes[index + 6].is_ascii_digit()
        {
            let next_is_digit = index + 7 < bytes.len() && bytes[index + 7].is_ascii_digit();
            if !next_is_digit {
                ids.insert(text[index..index + 7].to_string());
                index += 7;
                continue;
            }
        }
        index += 1;
    }
    ids
}

fn is_register_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7
        && &bytes[..4] == b"TFR-"
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
}

fn split_markdown_table_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn is_markdown_separator_cell(cell: &str) -> bool {
    let trimmed = cell.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch == '-' || ch == ':' || ch == ' ')
}

fn strip_markdown_code(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed
        .strip_prefix('`')
        .and_then(|value| value.strip_suffix('`'))
    {
        stripped.to_string()
    } else {
        trimmed.to_string()
    }
}

fn rel_path(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path.strip_prefix(root).map_err(|err| {
        format!(
            "cannot make {} relative to {}: {err}",
            path.display(),
            root.display()
        )
    })?;
    Ok(rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        if current.join("Cargo.toml").is_file()
            && current.join("xtask/tidefs-xtask/Cargo.toml").is_file()
        {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(root: &Path, rel_path: &str, text: &str) {
        let path = root.join(rel_path);
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        fs::write(path, text).expect("write file");
    }

    fn write_minimal_authority(root: &Path, extra_register_rows: &str) {
        write_file(root, "Cargo.toml", "[workspace]\nmembers = []\n");
        write_file(
            root,
            "xtask/tidefs-xtask/Cargo.toml",
            "[package]\nname = \"xtask-fixture\"\n",
        );
        write_file(
            root,
            PACKAGE_CLASSIFICATION_DOC,
            "\
# Workspace Package Classification

| Package root | Package | Cargo status | Role | Disposition |
| --- | --- | --- | --- | --- |
| `crates/tidefs-current-core` | `tidefs-current-core` | `workspace-member` | `product-code` | current fixture. |

Retired scaffold roots include `tidefs-old-core`.
",
        );
        write_file(
            root,
            DOCUMENTATION_AUTHORITY_REGISTER,
            "\
# Documentation Authority Register

| Path | State | Classification note |
|---|---|---|
| `docs/historical.md` | Historical input | fixture. |
",
        );
        write_file(
            root,
            REVIEW_TODO_REGISTER,
            &format!(
                "\
# TideFS Review Todo Register

| Id | Area | Finding | Required Direction |
| --- | --- | --- | --- |
| TFR-002 | Workspace authority | fixture. | fixture. |
{extra_register_rows}
"
            ),
        );
    }

    #[test]
    fn clean_live_doc_passes() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_minimal_authority(temp.path(), "");
        write_file(temp.path(), "docs/existing.md", "# Existing\n");
        write_file(
            temp.path(),
            "docs/live.md",
            "See `docs/existing.md`, `tidefs-current-core`, and TFR-002.\n",
        );

        check_workspace_root(temp.path()).expect("clean fixture");
    }

    #[test]
    fn retired_crate_reference_is_reported() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_minimal_authority(temp.path(), "");
        write_file(temp.path(), "docs/live.md", "Uses `tidefs-old-core`.\n");

        let err = check_workspace_root(temp.path()).expect_err("retired crate drift");
        let rendered = err.to_string();
        assert!(rendered.contains("docs/live.md:1"));
        assert!(rendered.contains("retired crate reference `tidefs-old-core`"));
    }

    #[test]
    fn missing_doc_reference_is_reported() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_minimal_authority(temp.path(), "");
        write_file(temp.path(), "docs/live.md", "See `docs/missing.md`.\n");

        let err = check_workspace_root(temp.path()).expect_err("missing doc drift");
        let rendered = err.to_string();
        assert!(rendered.contains("docs/live.md:1"));
        assert!(rendered.contains("missing doc path `docs/missing.md`"));
    }

    #[test]
    fn stale_register_id_is_reported() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_minimal_authority(temp.path(), "");
        write_file(temp.path(), "docs/live.md", "Review debt TFR-999.\n");

        let err = check_workspace_root(temp.path()).expect_err("stale register id");
        let rendered = err.to_string();
        assert!(rendered.contains("docs/live.md:1"));
        assert!(rendered.contains("stale register id `TFR-999`"));
    }

    #[test]
    fn historical_input_docs_are_skipped() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_minimal_authority(temp.path(), "");
        write_file(
            temp.path(),
            "docs/historical.md",
            "Old `tidefs-old-core`, `docs/missing.md`, and TFR-999.\n",
        );

        check_workspace_root(temp.path()).expect("historical fixture is skipped");
    }
}
