use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const REGISTRY_PATH: &str = "validation/performance/no-hidden-queues.toml";
const QUEUE_ROOT_MARKER: &str = "tidefs-queue-root:";

const VALID_WORK_CLASSES: &[&str] = &[
    "foreground-read",
    "foreground-write",
    "metadata-mutation",
    "writeback-flush",
    "scrub",
    "reclaim",
    "compaction",
    "control-plane",
];

const VALID_RESOURCE_DOMAINS: &[&str] = &[
    "foreground-io",
    "background-io",
    "dirty-bytes",
    "dirty-operations",
    "dirty-age",
    "metadata",
    "queue-slots",
    "cpu",
];

const VALID_HARD_CAPS: &[&str] = &[
    "dirty-bytes",
    "dirty-operations",
    "dirty-age",
    "queue-slots",
];

#[derive(Debug)]
pub struct NoHiddenQueuesError {
    failures: Vec<String>,
}

impl fmt::Display for NoHiddenQueuesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "no-hidden-queues check failed:")?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct QueueRegistry {
    schema_version: u32,
    queue_roots: Vec<QueueRoot>,
}

#[derive(Debug, Deserialize)]
struct QueueRoot {
    id: String,
    package: String,
    path: String,
    symbol: String,
    work_class: String,
    resource_domains: Vec<String>,
    admission: String,
    service_curve: String,
    hard_caps: Vec<String>,
}

pub fn check_current_workspace() -> Result<(), NoHiddenQueuesError> {
    let root = find_workspace_root().ok_or_else(|| NoHiddenQueuesError {
        failures: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut failures = Vec::new();
    let registry = load_registry(&root, &mut failures);
    let touched_files = touched_implementation_files(&root, &mut failures);
    let (scanned_files, touched_package_count) =
        scanned_source_files_for_touched_packages(&root, &touched_files, &mut failures);

    if let Some(registry) = registry {
        validate_registry(&root, &registry, &mut failures);
        scan_source_files(&root, &registry, &scanned_files, &mut failures);

        if failures.is_empty() {
            println!(
                "no-hidden-queues ok: {} registered queue root(s), {} touched implementation package(s), {} source file(s) scanned",
                registry.queue_roots.len(),
                touched_package_count,
                scanned_files.len()
            );
            return Ok(());
        }
    }

    Err(NoHiddenQueuesError { failures })
}

fn load_registry(root: &Path, failures: &mut Vec<String>) -> Option<QueueRegistry> {
    let path = root.join(REGISTRY_PATH);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!("could not read `{REGISTRY_PATH}`: {err}"));
            return None;
        }
    };
    match toml::from_str::<QueueRegistry>(&text) {
        Ok(registry) => Some(registry),
        Err(err) => {
            failures.push(format!("could not parse `{REGISTRY_PATH}`: {err}"));
            None
        }
    }
}

fn validate_registry(root: &Path, registry: &QueueRegistry, failures: &mut Vec<String>) {
    if registry.schema_version != 1 {
        failures.push(format!(
            "`{REGISTRY_PATH}` schema_version must be 1, found {}",
            registry.schema_version
        ));
    }
    if registry.queue_roots.is_empty() {
        failures.push(format!(
            "`{REGISTRY_PATH}` must register at least one queue root"
        ));
    }

    let mut ids = BTreeSet::new();
    for queue in &registry.queue_roots {
        if !ids.insert(queue.id.as_str()) {
            failures.push(format!("duplicate queue root id `{}`", queue.id));
        }
        validate_queue_root(root, queue, failures);
    }
}

fn validate_queue_root(root: &Path, queue: &QueueRoot, failures: &mut Vec<String>) {
    if queue.id.trim().is_empty() {
        failures.push("queue root id must not be empty".to_string());
    }
    if !VALID_WORK_CLASSES.contains(&queue.work_class.as_str()) {
        failures.push(format!(
            "queue root `{}` has unknown work_class `{}`",
            queue.id, queue.work_class
        ));
    }
    for domain in &queue.resource_domains {
        if !VALID_RESOURCE_DOMAINS.contains(&domain.as_str()) {
            failures.push(format!(
                "queue root `{}` has unknown resource domain `{domain}`",
                queue.id
            ));
        }
    }
    for cap in &queue.hard_caps {
        if !VALID_HARD_CAPS.contains(&cap.as_str()) {
            failures.push(format!(
                "queue root `{}` has unknown hard cap `{cap}`",
                queue.id
            ));
        }
    }
    for required_cap in VALID_HARD_CAPS {
        if !queue.hard_caps.iter().any(|cap| cap == required_cap) {
            failures.push(format!(
                "queue root `{}` must classify hard cap `{required_cap}`",
                queue.id
            ));
        }
    }

    let rel = Path::new(&queue.path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        failures.push(format!(
            "queue root `{}` path `{}` must be workspace-relative",
            queue.id, queue.path
        ));
        return;
    }

    let path = root.join(rel);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!(
                "queue root `{}` cannot read source `{}`: {err}",
                queue.id, queue.path
            ));
            return;
        }
    };

    let marker = queue_marker(&queue.id);
    for required in [
        marker.as_str(),
        queue.symbol.as_str(),
        queue.admission.as_str(),
        queue.service_curve.as_str(),
    ] {
        if !text.contains(required) {
            failures.push(format!(
                "queue root `{}` source `{}` does not contain required marker `{required}`",
                queue.id, queue.path
            ));
        }
    }

    match package_name_for_path(root, rel) {
        Some(package_name) if package_name == queue.package => {}
        Some(package_name) => failures.push(format!(
            "queue root `{}` declares package `{}`, but `{}` belongs to `{package_name}`",
            queue.id, queue.package, queue.path
        )),
        None => failures.push(format!(
            "queue root `{}` path `{}` is not under a Cargo package root",
            queue.id, queue.path
        )),
    }
}

fn scan_source_files(
    root: &Path,
    registry: &QueueRegistry,
    source_files: &[PathBuf],
    failures: &mut Vec<String>,
) {
    let mut roots_by_path: BTreeMap<String, Vec<&QueueRoot>> = BTreeMap::new();
    for queue in &registry.queue_roots {
        roots_by_path
            .entry(queue.path.clone())
            .or_default()
            .push(queue);
    }

    for rel in source_files {
        let rel_display = rel.to_string_lossy().replace('\\', "/");
        let text = match fs::read_to_string(root.join(rel)) {
            Ok(text) => text,
            Err(err) => {
                failures.push(format!(
                    "could not read touched source `{rel_display}`: {err}"
                ));
                continue;
            }
        };
        let candidates = queue_candidate_lines(&text);
        if candidates.is_empty() {
            continue;
        }
        let registered = roots_by_path.get(&rel_display);
        let classified = registered
            .map(|queues| {
                queues
                    .iter()
                    .any(|queue| text.contains(&queue_marker(&queue.id)))
            })
            .unwrap_or(false);
        if classified {
            continue;
        }

        let package = package_name_for_path(root, rel).unwrap_or_else(|| "unknown".to_string());
        for (line, pattern) in candidates {
            failures.push(format!(
                "touched package `{package}` has unclassified queue-like root in `{rel_display}` line {line}: matched `{pattern}`; add `{REGISTRY_PATH}` metadata and a `{QUEUE_ROOT_MARKER}` marker"
            ));
        }
    }
}

fn touched_implementation_files(root: &Path, failures: &mut Vec<String>) -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    let mut diff_errors = Vec::new();
    let mut successful_diffs = 0usize;
    for args in [
        &[
            "diff",
            "--name-only",
            "--diff-filter=ACMRTUXB",
            "origin/master...HEAD",
        ][..],
        &["diff", "--name-only", "--diff-filter=ACMRTUXB"][..],
        &["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"][..],
    ] {
        match git_lines(root, args) {
            Ok(lines) => {
                successful_diffs += 1;
                for line in lines {
                    let path = PathBuf::from(line);
                    if is_implementation_source(&path) {
                        files.insert(path);
                    }
                }
            }
            Err(err) => diff_errors.push(err),
        }
    }
    if successful_diffs == 0 {
        failures.extend(diff_errors);
    }
    files.into_iter().collect()
}

fn scanned_source_files_for_touched_packages(
    root: &Path,
    touched_files: &[PathBuf],
    failures: &mut Vec<String>,
) -> (Vec<PathBuf>, usize) {
    let mut package_roots = BTreeSet::new();
    for rel in touched_files {
        match package_root_for_path(root, rel) {
            Some(package_root) => {
                package_roots.insert(package_root);
            }
            None => failures.push(format!(
                "touched implementation source `{}` is not under a Cargo package root",
                rel.to_string_lossy().replace('\\', "/")
            )),
        }
    }

    let mut source_files = BTreeSet::new();
    for package_root in &package_roots {
        collect_package_source_files(root, package_root, &mut source_files, failures);
    }

    (source_files.into_iter().collect(), package_roots.len())
}

fn collect_package_source_files(
    root: &Path,
    package_root: &Path,
    files: &mut BTreeSet<PathBuf>,
    failures: &mut Vec<String>,
) {
    let source_root = package_root.join("src");
    if !source_root.is_dir() {
        return;
    }
    collect_rs_files(root, &source_root, files, failures);
}

fn collect_rs_files(
    root: &Path,
    dir: &Path,
    files: &mut BTreeSet<PathBuf>,
    failures: &mut Vec<String>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            failures.push(format!(
                "could not read source directory `{}`: {err}",
                dir.display()
            ));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                failures.push(format!(
                    "could not read source directory entry in `{}`: {err}",
                    dir.display()
                ));
                continue;
            }
        };
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(root, &path, files, failures);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        match path.strip_prefix(root) {
            Ok(rel) => {
                files.insert(rel.to_path_buf());
            }
            Err(err) => failures.push(format!(
                "could not make source path `{}` workspace-relative: {err}",
                path.display()
            )),
        }
    }
}

fn git_lines(root: &Path, args: &[&str]) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|err| format!("cannot run git {}: {err}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn is_implementation_source(path: &Path) -> bool {
    let rel = path.to_string_lossy().replace('\\', "/");
    rel.ends_with(".rs")
        && rel.contains("/src/")
        && (rel.starts_with("crates/") || rel.starts_with("apps/") || rel.starts_with("kmod/"))
}

fn queue_candidate_lines(text: &str) -> Vec<(usize, String)> {
    let patterns = queue_patterns();
    let mut candidates = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }
        for pattern in &patterns {
            if line.contains(pattern) {
                candidates.push((index + 1, pattern.clone()));
            }
        }
    }
    candidates
}

fn queue_patterns() -> Vec<String> {
    [
        ("Vec", "Deque<"),
        ("Binary", "Heap<"),
        ("Seg", "Queue<"),
        ("Array", "Queue<"),
        ("mpsc::", "channel"),
        ("sync::", "mpsc"),
        ("crossbeam_channel", "::"),
        ("flume::", ""),
        ("async_channel::", ""),
    ]
    .into_iter()
    .map(|(left, right)| format!("{left}{right}"))
    .collect()
}

fn queue_marker(id: &str) -> String {
    format!("{QUEUE_ROOT_MARKER} {id}")
}

fn package_name_for_path(root: &Path, rel: &Path) -> Option<String> {
    let package_root = package_root_for_path(root, rel)?;
    manifest_package_name(&package_root.join("Cargo.toml"))
}

fn package_root_for_path(root: &Path, rel: &Path) -> Option<PathBuf> {
    let mut dir = root.join(rel).parent()?.to_path_buf();
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() && manifest_package_name(&manifest).is_some() {
            return Some(dir);
        }
        if dir == root || !dir.pop() {
            return None;
        }
    }
}

fn manifest_package_name(manifest: &Path) -> Option<String> {
    let text = fs::read_to_string(manifest).ok()?;
    let mut in_package = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "name" {
            return parse_manifest_string(value.trim());
        }
    }
    None
}

fn parse_manifest_string(value: &str) -> Option<String> {
    let quote = value.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut out = String::new();
    for ch in value.chars().skip(1) {
        if ch == quote {
            return Some(out);
        }
        out.push(ch);
    }
    None
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            let text = fs::read_to_string(&manifest).ok()?;
            if text.contains("[workspace]") {
                return Some(dir);
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_implementation_source, queue_candidate_lines};
    use std::path::Path;

    #[test]
    fn queue_candidate_scan_ignores_comments() {
        let candidates = queue_candidate_lines(
            r#"
// VecDeque<NotAQueue>
struct Root {
    pending: VecDeque<Item>,
}
"#,
        );
        assert_eq!(candidates, vec![(4, "VecDeque<".to_string())]);
    }

    #[test]
    fn implementation_source_scan_stays_on_package_src_roots() {
        assert!(is_implementation_source(Path::new(
            "crates/tidefs-performance-contract/src/lib.rs"
        )));
        assert!(is_implementation_source(Path::new(
            "apps/tidefsctl/src/main.rs"
        )));
        assert!(is_implementation_source(Path::new("kmod/src/lib.rs")));
        assert!(!is_implementation_source(Path::new(
            "crates/tidefs-transport/tests/harness.rs"
        )));
        assert!(!is_implementation_source(Path::new(
            "xtask/tidefs-xtask/src/no_hidden_queues.rs"
        )));
    }
}
