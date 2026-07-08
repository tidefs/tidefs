// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Worktree ownership and claim-gate validation.
//
// Provides checks that validate:
//   - Worktree ownership: the current directory is a valid tidefs worktree
//     with a branch matching an accepted codexN/issue-N-* or dsN/issue-N-*
//     identity pattern.
//   - GitHub issue state: the corresponding issue is open on GitHub.
//   - Abandoned worktrees: no stale worktree directories exist locally.
//
// Legacy Forgejo claim-tracker commands (check-stale-claims,
// check-stale-forgejo-claims, check-duplicate-claims,
// check-duplicate-forgejo-claims, coordination-health,
// auto-release-stale-claims, acquire-claim, claim-issue) fail closed with an explicit
// unsupported message.
//
// GitHub issue checks use the `gh` CLI; no hard-coded API credentials.

use serde::Deserialize;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// Expected worktree root directory, relative to $HOME.
const WORKTREE_ROOT: &str = "tidefs-worktrees";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ForgejoWorkError {
    violations: Vec<String>,
}

impl fmt::Display for ForgejoWorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "worktree claim gate check failed:")?;
        for violation in &self.violations {
            writeln!(f, "- {violation}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GitHub issue response type (serde)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitHubIssue {
    state: String,
}

// ---------------------------------------------------------------------------
// check-claim-gate -- validates the current worktree has a valid issue claim
// ---------------------------------------------------------------------------

pub fn check_claim_gate_current_workspace() -> Result<(), ForgejoWorkError> {
    let cwd = std::env::current_dir().map_err(|err| ForgejoWorkError {
        violations: vec![format!("could not determine current directory: {err}")],
    })?;

    let home = home_dir()?;
    if let Some(repo_root) = foreground_main_checkout_root(&cwd, &home) {
        return check_foreground_main_claim(&repo_root);
    }

    let worktree_root = home.join(WORKTREE_ROOT);
    let mut violations = Vec::new();

    // 1. Detect issue number from cwd.
    let issue_num = match detect_issue_number_from_path(&cwd, &worktree_root) {
        Some(num) => num,
        None => {
            violations.push(format!(
                "current directory '{}' is not a tidefs worktree under '{}/'",
                cwd.display(),
                worktree_root.display()
            ));
            return Err(ForgejoWorkError { violations });
        }
    };

    // 2. Find the matching worktree directory.
    let wt_dir = match find_worktree_dir(&worktree_root, issue_num) {
        Some(dir) => dir,
        None => {
            violations.push(format!(
                "no worktree directory found for issue #{issue_num} under '{}/'",
                worktree_root.display()
            ));
            return Err(ForgejoWorkError { violations });
        }
    };

    // 3. Validate the worktree directory exists and has a valid git branch.
    match validate_worktree_branch(&wt_dir, issue_num) {
        Ok(()) => {}
        Err(err) => violations.push(err),
    }

    // 4. Check the GitHub issue is open.
    match check_github_issue_open(issue_num) {
        Ok(true) => {}
        Ok(false) => violations.push(format!("issue #{issue_num} is not open on GitHub")),
        Err(err) => violations.push(format!("could not verify GitHub issue #{issue_num}: {err}")),
    }

    if violations.is_empty() {
        println!(
            "claim gate ok: worktree '{}' has valid claim for issue #{}",
            wt_dir.display(),
            issue_num,
        );
        Ok(())
    } else {
        Err(ForgejoWorkError { violations })
    }
}

fn check_foreground_main_claim(repo_root: &Path) -> Result<(), ForgejoWorkError> {
    let mut violations = Vec::new();

    match git_branch(repo_root) {
        Ok(branch) if branch == "master" => {}
        Ok(branch) => violations.push(format!(
            "foreground checkout '{}' is on branch '{}', expected master",
            repo_root.display(),
            branch
        )),
        Err(err) => violations.push(format!(
            "could not determine foreground checkout branch in '{}': {err}",
            repo_root.display()
        )),
    }

    if violations.is_empty() {
        println!(
            "claim gate ok: foreground checkout '{}' on master",
            repo_root.display(),
        );
        Ok(())
    } else {
        Err(ForgejoWorkError { violations })
    }
}

// ---------------------------------------------------------------------------
// check-stale-claims -- legacy Forgejo command, now unsupported
// ---------------------------------------------------------------------------

pub fn check_stale_claims_command(command: &str) -> Result<(), ForgejoWorkError> {
    Err(retired_forgejo_command_error(
        command,
        "Stale-work coordination is now managed through GitHub issues, pull requests, and the \
         current Codex Nexus controller.",
    ))
}

// ---------------------------------------------------------------------------
// check-duplicate-claims -- legacy Forgejo command, now unsupported
// ---------------------------------------------------------------------------

pub fn check_duplicate_claims_command(command: &str) -> Result<(), ForgejoWorkError> {
    Err(retired_forgejo_command_error(
        command,
        "Duplicate-work coordination is now managed through GitHub issues, pull requests, and the \
         current Codex Nexus controller.",
    ))
}

// ---------------------------------------------------------------------------
// check-abandoned-worktrees -- local-only worktree directory scan
// ---------------------------------------------------------------------------

pub fn check_abandoned_worktrees_current_workspace() -> Result<(), ForgejoWorkError> {
    let home = home_dir()?;
    let worktree_root = home.join(WORKTREE_ROOT);
    let mut violations = Vec::new();

    if !worktree_root.exists() {
        return Ok(());
    }

    let worktrees = match list_issue_worktree_dirs(&worktree_root) {
        Ok(worktrees) => worktrees,
        Err(err) => {
            violations.push(err);
            return Err(ForgejoWorkError { violations });
        }
    };

    for path in worktrees {
        let dir_name = worktree_display_name(&worktree_root, &path);
        let issue_num = match path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(issue_number_from_worktree_name)
        {
            Some(issue_num) => issue_num,
            None => continue,
        };

        let branch = match git_branch(&path) {
            Ok(b) => b,
            Err(_) => {
                violations.push(format!(
                    "abandoned worktree: '{dir_name}' has no valid git branch"
                ));
                continue;
            }
        };

        match branch_issue_authority(&branch, issue_num) {
            Some(WorktreeIssueAuthority::GitHub) => match check_github_issue_open(issue_num) {
                Ok(true) => {}
                Ok(false) => violations.push(format!(
                    "worktree '{dir_name}' exists but issue #{issue_num} is not open on GitHub"
                )),
                Err(err) => violations.push(format!(
                    "worktree '{dir_name}': could not verify GitHub issue #{issue_num}: {err}"
                )),
            },
            None => {
                if branch == "HEAD" {
                    violations.push(format!(
                        "abandoned worktree: '{dir_name}' has detached HEAD (stale or uninitialized worktree)"
                    ));
                } else {
                    violations.push(format!(
                        "worktree '{dir_name}' has unsupported branch '{branch}' (only codexN/issue-N-* or dsN/issue-N-* patterns are supported)"
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        println!("abandoned worktrees ok: no stale or orphaned worktrees found");
        Ok(())
    } else {
        Err(ForgejoWorkError { violations })
    }
}

// ---------------------------------------------------------------------------
// auto-release-stale-claims -- legacy Forgejo command, now unsupported
// ---------------------------------------------------------------------------

pub fn auto_release_stale_claims() -> Result<(), ForgejoWorkError> {
    Err(retired_forgejo_command_error(
        "auto-release-stale-claims",
        "Stale-claim release is now managed through GitHub issue state and the current Codex Nexus \
         controller.",
    ))
}

// ---------------------------------------------------------------------------
// coordination-health -- legacy Forgejo command, now unsupported
// ---------------------------------------------------------------------------

pub fn print_coordination_health_report() -> Result<(), ForgejoWorkError> {
    Err(retired_forgejo_command_error(
        "coordination-health",
        "Coordination health is now reported through GitHub Actions CI posture, Codex Nexus \
         dashboard state, and live GitHub issue/PR state.",
    ))
}

// ---------------------------------------------------------------------------
// acquire-claim/claim-issue -- legacy Forgejo command, now unsupported
// ---------------------------------------------------------------------------

pub fn acquire_claim_command(command: &str, _issue_num: u64) -> Result<bool, String> {
    Err(retired_forgejo_command_message(
        command,
        "Issue claim is now managed through GitHub issue assignment and the current Codex Nexus \
         worker pool.",
    ))
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf, ForgejoWorkError> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| ForgejoWorkError {
            violations: vec!["cannot determine home directory ($HOME not set)".to_string()],
        })
}

fn retired_forgejo_command_error(command: &str, current_authority: &str) -> ForgejoWorkError {
    ForgejoWorkError {
        violations: vec![retired_forgejo_command_message(command, current_authority)],
    }
}

fn retired_forgejo_command_message(command: &str, current_authority: &str) -> String {
    format!(
        "{command} is no longer supported: the legacy Forgejo claim tracker has been retired. \
         {current_authority}"
    )
}

fn detect_issue_number_from_path(cwd: &Path, worktree_root: &Path) -> Option<u64> {
    let relative = cwd.strip_prefix(worktree_root).ok()?;
    relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .find_map(issue_number_from_worktree_name)
}

fn foreground_main_checkout_root(cwd: &Path, home: &Path) -> Option<PathBuf> {
    let repo_root = git_toplevel(cwd).ok()?;
    if repo_root == home.join("tidefs") {
        Some(repo_root)
    } else {
        None
    }
}

fn issue_number_from_worktree_name(name: &str) -> Option<u64> {
    name.strip_prefix("issue-")?
        .split('-')
        .next()?
        .parse::<u64>()
        .ok()
}

fn worktree_name_matches_issue(name: &str, issue_num: u64) -> bool {
    issue_number_from_worktree_name(name) == Some(issue_num)
}

fn find_worktree_dir(worktree_root: &Path, issue_num: u64) -> Option<PathBuf> {
    list_issue_worktree_dirs(worktree_root)
        .ok()?
        .into_iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| worktree_name_matches_issue(name, issue_num))
        })
}

fn list_issue_worktree_dirs(worktree_root: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(worktree_root).map_err(|err| {
        format!(
            "could not read worktree root '{}': {err}",
            worktree_root.display()
        )
    })?;
    let mut worktrees = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if issue_number_from_worktree_name(&name_str).is_some() {
            worktrees.push(path);
            continue;
        }
        if is_codex_identity_dir(&name_str) {
            let children = fs::read_dir(&path).map_err(|err| {
                format!(
                    "could not read worktree owner dir '{}': {err}",
                    path.display()
                )
            })?;
            for child in children.flatten() {
                let child_path = child.path();
                if !child_path.is_dir() {
                    continue;
                }
                let child_name = child.file_name();
                let child_name_str = child_name.to_string_lossy();
                if issue_number_from_worktree_name(&child_name_str).is_some() {
                    worktrees.push(child_path);
                }
            }
        }
    }

    Ok(worktrees)
}

fn worktree_display_name(worktree_root: &Path, path: &Path) -> String {
    path.strip_prefix(worktree_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorktreeIssueAuthority {
    GitHub,
}

fn validate_worktree_branch(wt_dir: &Path, issue_num: u64) -> Result<(), String> {
    let branch = git_branch(wt_dir).map_err(|err| {
        format!(
            "could not determine branch in '{}': {err}",
            wt_dir.display()
        )
    })?;

    if branch_issue_authority(&branch, issue_num).is_some() {
        return Ok(());
    }

    Err(format!(
        "worktree branch '{}' does not match expected prefix 'codexN/issue-{}-*' or 'dsN/issue-{}-*' in '{}'",
        branch,
        issue_num,
        issue_num,
        wt_dir.display()
    ))
}

fn branch_issue_authority(branch: &str, issue_num: u64) -> Option<WorktreeIssueAuthority> {
    let (owner, rest) = branch.split_once('/')?;
    if is_codex_identity_dir(owner) && rest.starts_with(&format!("issue-{issue_num}-")) {
        return Some(WorktreeIssueAuthority::GitHub);
    }
    None
}

fn is_codex_identity_dir(name: &str) -> bool {
    // Accept codexN (e.g. codex0) and dsN (e.g. ds10) identity dirs.
    if let Some(suffix) = name.strip_prefix("codex") {
        return !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_alphanumeric());
    }
    if let Some(suffix) = name.strip_prefix("ds") {
        return !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_alphanumeric());
    }
    false
}

fn git_toplevel(dir: &Path) -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(dir)
        .output()
        .map_err(|err| format!("git rev-parse --show-toplevel failed: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

fn git_branch(dir: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(dir)
        .output()
        .map_err(|err| format!("git rev-parse failed: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn check_github_issue_open(issue_num: u64) -> Result<bool, String> {
    let issue_arg = issue_num.to_string();
    let output = Command::new("gh")
        .args([
            "-R",
            "tidefs/tidefs",
            "issue",
            "view",
            &issue_arg,
            "--json",
            "state",
        ])
        .output()
        .map_err(|err| format!("gh issue view failed to start: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "gh issue view failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let issue: GitHubIssue = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse GitHub issue #{issue_num} JSON: {err}"))?;
    Ok(issue.state == "OPEN")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_retired_forgejo_command_error(result: Result<(), ForgejoWorkError>, command: &str) {
        let message = format!(
            "{}",
            result.expect_err("retired command should fail closed")
        );
        assert!(
            message.contains(command),
            "retired diagnostic should name command: {message}"
        );
        assert!(
            message.contains("no longer supported"),
            "retired diagnostic should reject use: {message}"
        );
        assert!(
            message.contains("legacy Forgejo claim tracker"),
            "retired diagnostic should name retired tracker: {message}"
        );
        assert!(
            message.contains("retired"),
            "retired diagnostic should name retirement: {message}"
        );
        assert!(
            message.contains("GitHub"),
            "retired diagnostic should name current GitHub authority: {message}"
        );
        assert!(
            message.contains("Codex Nexus"),
            "retired diagnostic should name current Codex Nexus authority: {message}"
        );
    }

    #[test]
    fn retired_legacy_forgejo_commands_fail_closed() {
        assert_retired_forgejo_command_error(
            check_stale_claims_command("check-stale-claims"),
            "check-stale-claims",
        );
        assert_retired_forgejo_command_error(
            check_stale_claims_command("check-stale-forgejo-claims"),
            "check-stale-forgejo-claims",
        );
        assert_retired_forgejo_command_error(
            check_duplicate_claims_command("check-duplicate-claims"),
            "check-duplicate-claims",
        );
        assert_retired_forgejo_command_error(
            check_duplicate_claims_command("check-duplicate-forgejo-claims"),
            "check-duplicate-forgejo-claims",
        );
        assert_retired_forgejo_command_error(
            auto_release_stale_claims(),
            "auto-release-stale-claims",
        );
        assert_retired_forgejo_command_error(
            print_coordination_health_report(),
            "coordination-health",
        );

        let message = acquire_claim_command("acquire-claim", 1805)
            .expect_err("retired acquire-claim should fail closed");
        for fragment in [
            "acquire-claim",
            "no longer supported",
            "legacy Forgejo claim tracker",
            "retired",
            "GitHub",
            "Codex Nexus",
        ] {
            assert!(
                message.contains(fragment),
                "retired acquire-claim diagnostic should contain '{fragment}': {message}"
            );
        }

        let message = acquire_claim_command("claim-issue", 1805)
            .expect_err("retired claim-issue should fail closed");
        for fragment in [
            "claim-issue",
            "no longer supported",
            "legacy Forgejo claim tracker",
            "retired",
            "GitHub",
            "Codex Nexus",
        ] {
            assert!(
                message.contains(fragment),
                "retired claim-issue diagnostic should contain '{fragment}': {message}"
            );
        }
    }

    #[test]
    fn detect_issue_number_from_valid_path() {
        let worktree_root = Path::new("/root/tidefs-worktrees");
        let cwd = Path::new("/root/tidefs-worktrees/issue-730-claim-gates");
        assert_eq!(detect_issue_number_from_path(cwd, worktree_root), Some(730));

        let cwd2 = Path::new("/root/tidefs-worktrees/issue-123-something");
        assert_eq!(
            detect_issue_number_from_path(cwd2, worktree_root),
            Some(123)
        );

        let cwd3 = Path::new("/root/tidefs-worktrees/codex0/issue-8-xtask-claim-gate");
        assert_eq!(detect_issue_number_from_path(cwd3, worktree_root), Some(8));

        let cwd4 = Path::new("/root/tidefs-worktrees/ds10/issue-1805-retire-forgejo-xtask");
        assert_eq!(
            detect_issue_number_from_path(cwd4, worktree_root),
            Some(1805)
        );
    }

    #[test]
    fn detect_issue_number_from_invalid_path() {
        let worktree_root = Path::new("/root/tidefs-worktrees");
        let cwd = Path::new("/root/tidefs");
        assert_eq!(detect_issue_number_from_path(cwd, worktree_root), None);

        let cwd2 = Path::new("/root/tidefs-worktrees/no-issue-here");
        assert_eq!(detect_issue_number_from_path(cwd2, worktree_root), None);

        let cwd3 = Path::new("/root/tidefs-worktrees/codex0/no-issue-here");
        assert_eq!(detect_issue_number_from_path(cwd3, worktree_root), None);
    }

    #[test]
    fn branch_issue_authority_accepts_current_prefixes() {
        assert_eq!(
            branch_issue_authority("codex0/issue-8-xtask-claim-gate", 8),
            Some(WorktreeIssueAuthority::GitHub)
        );
        assert_eq!(
            branch_issue_authority("codex12/issue-123-storage", 123),
            Some(WorktreeIssueAuthority::GitHub)
        );
        assert_eq!(
            branch_issue_authority("ds10/issue-1805-retire-forgejo", 1805),
            Some(WorktreeIssueAuthority::GitHub)
        );
        // Legacy codex/ prefix (no numeric suffix) is no longer supported.
        assert_eq!(
            branch_issue_authority("codex/issue-730-claim-gates", 730),
            None
        );
        assert_eq!(branch_issue_authority("codex0/issue-9-wrong", 8), None);
        assert_eq!(branch_issue_authority("feature/issue-8-wrong", 8), None);
    }

    #[test]
    fn list_issue_worktree_dirs_finds_direct_and_nested_layouts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let direct = root.join("issue-123-direct");
        let nested = root.join("codex0").join("issue-8-xtask-claim-gate");
        let ds_nested = root.join("ds10").join("issue-1805-retire-forgejo");
        let ignored = root.join("codex0").join("scratch");
        fs::create_dir_all(&direct).expect("direct worktree dir");
        fs::create_dir_all(&nested).expect("nested worktree dir");
        fs::create_dir_all(&ds_nested).expect("ds nested worktree dir");
        fs::create_dir_all(&ignored).expect("ignored dir");

        let mut dirs = list_issue_worktree_dirs(root).expect("list worktrees");
        dirs.sort();

        assert_eq!(dirs, vec![nested, ds_nested, direct]);
    }

    #[test]
    fn is_codex_identity_dir_recognizes_codex_and_ds_prefixes() {
        assert!(is_codex_identity_dir("codex0"));
        assert!(is_codex_identity_dir("codex12"));
        assert!(is_codex_identity_dir("ds10"));
        assert!(is_codex_identity_dir("ds0"));
        // Legacy bare "codex" without numeric suffix is not an identity dir.
        assert!(!is_codex_identity_dir("codex"));
        assert!(!is_codex_identity_dir("codex-"));
        assert!(!is_codex_identity_dir("ds"));
        assert!(!is_codex_identity_dir("foreground"));
        assert!(!is_codex_identity_dir("gpt0")); // other prefixes are not identity dirs
    }
}
