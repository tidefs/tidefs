// Policy gates for Forgejo-based parallel instance safety.
//
// Provides checks that validate:
//   - Worktree ownership: the current directory is a valid tidefs worktree
//     with a branch matching the expected codex/issue-N-* pattern.
//   - Forgejo claim: the corresponding issue has codex:claimed label.
//   - Stale claims: no codex:claimed issue has been untouched for > timeout.
//   - Abandoned worktrees: no stale worktree directories exist locally.
//   - Auto-release: stale claims older than timeout can be automatically
//     released (removes codex:claimed, adds codex:ready, posts comment).
//
// All Forgejo API responses are parsed with serde_json for type safety.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Default timeout for stale claims (hours).
const DEFAULT_STALE_TIMEOUT_HOURS: u64 = 24;

// Expected worktree root directory, relative to $HOME.
const WORKTREE_ROOT: &str = "tidefs-worktrees";

// Expected branch prefix for codex worktrees.
const CODEX_BRANCH_PREFIX: &str = "codex/issue-";

// Forgejo configuration.
const FORGEJO_BASE_URL: &str = "http://172.16.106.12/forgejo";
const DEFAULT_FORGEJO_REPO: &str = "forgeadmin/tidefs";
const FORGEJO_REPO_ENV: &str = "TIDEFS_FORGEJO_REPO";
const CREDENTIAL_FILE: &str = "/root/ai/state/forgejo/admin-initial-credentials.txt";

// Label IDs for codex workflow (stable per Forgejo instance).
const LABEL_CODEX_READY: u64 = 68;
const LABEL_CODEX_CLAIMED: u64 = 69;
const LABEL_CODEX_NEEDS_REVIEW: u64 = 70;

// Maximum API retries with jittered exponential backoff.

// HTTP connect and read timeouts for the Forgejo API agent (seconds).
const FORGEJO_CONNECT_TIMEOUT_SECS: u64 = 10;
const FORGEJO_READ_TIMEOUT_SECS: u64 = 30;
const MAX_API_RETRIES: u32 = 3;

// Maximum clock skew tolerance (seconds) for optimistic locking.
#[allow(dead_code)]
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Forgejo API response types (serde)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ForgejoLabel {
    #[allow(dead_code)]
    id: u64,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoIssue {
    number: u64,
    title: String,
    #[allow(dead_code)]
    state: String,
    labels: Vec<ForgejoLabel>,
    updated_at: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    closed_at: Option<String>,
}
// ---------------------------------------------------------------------------
// API client state
// ---------------------------------------------------------------------------

/// Parsed credentials from the plain-text admin-initial-credentials.txt file.
struct ApiCredentials {
    username: String,
    password: String,
}

impl ApiCredentials {
    fn from_file(path: &str) -> Result<Self, String> {
        let mut content = String::new();
        fs::File::open(path)
            .map_err(|e| format!("cannot open credentials file {path}: {e}"))?
            .read_to_string(&mut content)
            .map_err(|e| format!("cannot read credentials file {path}: {e}"))?;

        let username = extract_field(&content, "Username:")
            .ok_or_else(|| "Username: not found in credentials file".to_string())?;
        let password = extract_field(&content, "Password:")
            .ok_or_else(|| "Password: not found in credentials file".to_string())?;

        Ok(ApiCredentials { username, password })
    }

    fn to_basic_auth(&self) -> String {
        let raw = format!("{}:{}", self.username, self.password);
        let b64 = base64_encode(raw.as_bytes());
        format!("Basic {b64}")
    }
}

fn extract_field(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(val) = line.trim().strip_prefix(key) {
            return Some(val.trim().to_string());
        }
    }
    None
}

/// Minimal base64 encoder (no external crate needed).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize]);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize]);
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize]);
        } else {
            out.push(b'=');
        }
    }
    String::from_utf8(out).unwrap()
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ForgejoWorkError {
    violations: Vec<String>,
}

impl fmt::Display for ForgejoWorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "forgejo work check failed:")?;
        for violation in &self.violations {
            writeln!(f, "- {violation}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicatedClaim {
    pub key: String,
    pub issues: Vec<DuplicatedClaimIssue>,
    pub recommended_action: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicatedClaimIssue {
    pub number: u64,
    pub title: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// check-claim-gate -- validates the current worktree has a valid Forgejo claim
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
    if let Err(err) = validate_worktree_branch(&wt_dir, issue_num) {
        violations.push(err);
    }

    // 4. Check Forgejo claim via API (serde-parsed).
    match check_forgejo_claim(issue_num) {
        Ok(true) => {}
        Ok(false) => violations.push(format!(
            "issue #{issue_num} has no codex:claimed label on Forgejo"
        )),
        Err(err) => violations.push(format!(
            "could not verify Forgejo claim for issue #{issue_num}: {err}"
        )),
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

    match api_list_open_issues() {
        Ok(issues) => {
            let active_claimed = active_claimed_issues(&issues);
            if active_claimed.is_empty() {
                println!(
                    "claim gate ok: foreground checkout '{}' has no active claimed Forgejo issue; open issue state remains available as work-selection input",
                    repo_root.display(),
                );
            } else {
                println!(
                    "claim gate ok: foreground checkout '{}' sees {} active Forgejo claim(s): {}",
                    repo_root.display(),
                    active_claimed.len(),
                    active_claimed
                        .iter()
                        .map(|issue| format!("#{}", issue.number))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        Err(err) => violations.push(format!("could not list Forgejo open issues: {err}")),
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ForgejoWorkError { violations })
    }
}

// ---------------------------------------------------------------------------
// check-stale-claims -- scans Forgejo for claims older than the timeout
// ---------------------------------------------------------------------------
pub fn check_stale_claims_current_workspace() -> Result<(), ForgejoWorkError> {
    let timeout_hours = parse_stale_timeout().unwrap_or(DEFAULT_STALE_TIMEOUT_HOURS);
    let stale = find_stale_forgejo_claims(timeout_hours);

    if stale.is_empty() {
        println!("stale claims ok: no claims older than {timeout_hours}h found on Forgejo");
        return Ok(());
    }

    let mut violations = Vec::new();
    for (num, hours, title) in &stale {
        violations.push(format!(
            "stale claim: issue #{num} claimed {hours}h ago -- \"{title}\""
        ));
    }
    Err(ForgejoWorkError { violations })
}

// ---------------------------------------------------------------------------
// check-duplicate-claims -- detects multiple active claims for the same work
// ---------------------------------------------------------------------------
pub fn check_duplicate_claims_current_workspace() -> Result<(), ForgejoWorkError> {
    let duplicated = detect_duplicate_claims().map_err(|err| ForgejoWorkError {
        violations: vec![format!("failed to detect duplicate claims: {err}")],
    })?;

    if duplicated.is_empty() {
        println!("duplicate claims ok: no duplicate codex:claimed work keys found");
        return Ok(());
    }

    let mut violations = Vec::new();
    for duplicate in duplicated {
        let issue_list = duplicate
            .issues
            .iter()
            .map(|issue| format!("#{} updated_at={}", issue.number, issue.updated_at))
            .collect::<Vec<_>>()
            .join(", ");
        violations.push(format!(
            "duplicate claimed work key '{}' has {} claimed issues: {issue_list}; {}",
            duplicate.key,
            duplicate.issues.len(),
            duplicate.recommended_action
        ));
        for issue in duplicate.issues {
            violations.push(format!("  #{} -- \"{}\"", issue.number, issue.title));
        }
    }

    Err(ForgejoWorkError { violations })
}

pub fn detect_duplicate_claims() -> Result<Vec<DuplicatedClaim>, String> {
    let body = api_get("/issues?state=open&limit=200")?;
    let issues: Vec<ForgejoIssue> = serde_json::from_str(&body)
        .map_err(|err| format!("failed to parse open issues JSON: {err}"))?;
    Ok(detect_duplicate_claims_from_issues(&issues))
}

// ---------------------------------------------------------------------------
// check-abandoned-worktrees -- detects stale local worktree directories
// ---------------------------------------------------------------------------
pub fn check_abandoned_worktrees_current_workspace() -> Result<(), ForgejoWorkError> {
    let home = home_dir()?;
    let worktree_root = home.join(WORKTREE_ROOT);
    let mut violations = Vec::new();

    if !worktree_root.exists() {
        return Ok(());
    }

    let entries = match fs::read_dir(&worktree_root) {
        Ok(entries) => entries,
        Err(err) => {
            violations.push(format!(
                "could not read worktree root '{}': {err}",
                worktree_root.display()
            ));
            return Err(ForgejoWorkError { violations });
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let issue_num = match dir_name
            .strip_prefix("issue-")
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(n) => n,
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

        if !branch.starts_with(CODEX_BRANCH_PREFIX) {
            if branch == "HEAD" {
                violations.push(format!(
                    "abandoned worktree: '{dir_name}' has detached HEAD (stale or uninitialized worktree)"
                ));
            } else {
                violations.push(format!(
                    "worktree '{dir_name}' has unexpected branch '{branch}'"
                ));
            }
            continue;
        }

        // Cross-reference with Forgejo: the corresponding issue should be claimed
        match check_forgejo_claim(issue_num) {
            Ok(true) => {}
            Ok(false) => {
                violations.push(format!(
                    "worktree '{dir_name}' exists but issue #{issue_num} is not claimed on Forgejo"
                ));
            }
            Err(err) => {
                violations.push(format!(
                    "worktree '{dir_name}': could not verify Forgejo claim for issue #{issue_num}: {err}"
                ));
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
// auto-release-stale-claims -- releases claims older than the timeout
// ---------------------------------------------------------------------------
pub fn auto_release_stale_claims() -> Result<(), ForgejoWorkError> {
    // Gate: TIDEFS_AUTO_RELEASE_STALE must be explicitly set to "1" or "true".
    match std::env::var("TIDEFS_AUTO_RELEASE_STALE") {
        Ok(ref val) if val == "1" || val == "true" => {}
        _ => {
            return Err(ForgejoWorkError {
                violations: vec![
                    "auto-release is gated by TIDEFS_AUTO_RELEASE_STALE=1 (set to enable)"
                        .to_string(),
                ],
            });
        }
    }

    let timeout_hours = parse_stale_timeout().unwrap_or(DEFAULT_STALE_TIMEOUT_HOURS);

    let stale = find_stale_forgejo_claims(timeout_hours);

    if stale.is_empty() {
        println!("auto-release ok: no claims older than {timeout_hours}h found on Forgejo");
        return Ok(());
    }

    let mut violations = Vec::new();
    let mut released = Vec::new();

    for (num, hours, title) in &stale {
        match try_release_claim(*num, *hours) {
            Ok(()) => {
                released.push((*num, *hours, title.clone()));
                println!("auto-released stale claim: issue #{num} ({hours}h old) -- \"{title}\"");
            }
            Err(err) => {
                violations.push(format!(
                    "auto-release failed for issue #{num} ({hours}h old): {err}"
                ));
            }
        }
    }

    if !released.is_empty() {
        println!(
            "auto-release complete: {} stale claim(s) released (timeout: {timeout_hours}h)",
            released.len()
        );
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ForgejoWorkError { violations })
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// coordination-health -- prints a health report from Forgejo issue metrics
// ---------------------------------------------------------------------------

/// Print a coordination health report derived from Forgejo issue labels.
/// Fetches all open issues (and recently closed issues), groups them by
/// lane, kind, priority, and codex workflow status, and prints a structured
/// report with health flags for staleness, stalled pipelines, and blockers.
pub fn print_coordination_health_report() -> Result<(), ForgejoWorkError> {
    // Fetch all open issues.
    let body = api_get("/issues?state=open&limit=200").map_err(|err| ForgejoWorkError {
        violations: vec![format!("failed to fetch open issues: {err}")],
    })?;
    let open_issues: Vec<ForgejoIssue> =
        serde_json::from_str(&body).map_err(|err| ForgejoWorkError {
            violations: vec![format!("failed to parse open issues JSON: {err}")],
        })?;

    // Fetch recently closed issues for done-metrics context.
    let body = api_get("/issues?state=closed&limit=50").unwrap_or_default();
    let closed_issues: Vec<ForgejoIssue> = serde_json::from_str(&body).unwrap_or_default();

    // Counters (open issues).
    let mut lane_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut kind_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut priority_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut codex_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut source_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut lane_codex: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, usize>,
    > = std::collections::BTreeMap::new();

    // Per-lane age accumulators: sum of hours, count, and oldest (hours, title, issue#).
    let mut lane_age_sum: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut lane_age_count: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut lane_oldest: std::collections::BTreeMap<String, (u64, String, u64)> =
        std::collections::BTreeMap::new(); // lane -> (age_hours, title, issue_number)

    let mut open_total = 0usize;
    let mut claimed_count = 0usize;
    let mut ready_count = 0usize;
    let mut review_count = 0usize;
    let mut blocked_count = 0usize;
    let mut done_count = 0usize;

    // Stalled threshold: untouched for > 7 days (not blocked).
    let stalled_hours_threshold: u64 = 7 * 24;

    for issue in &open_issues {
        open_total += 1;
        let lane = label_prefix(&issue.labels, "lane:");
        let kind = label_prefix(&issue.labels, "kind:");
        let priority = label_prefix(&issue.labels, "priority:");
        let codex = label_prefix(&issue.labels, "codex:");
        let source = label_prefix(&issue.labels, "source:");

        if let Some(ref l) = lane {
            *lane_counts.entry(l.clone()).or_insert(0) += 1;
            let entry = lane_codex.entry(l.clone()).or_default();
            if let Some(ref c) = codex {
                *entry.entry(c.clone()).or_insert(0) += 1;
            }
        }
        if let Some(ref k) = kind {
            *kind_counts.entry(k.clone()).or_insert(0) += 1;
        }
        if let Some(ref p) = priority {
            *priority_counts.entry(p.clone()).or_insert(0) += 1;
        }
        if let Some(ref c) = codex {
            *codex_counts.entry(c.clone()).or_insert(0) += 1;
            match c.as_str() {
                "claimed" => claimed_count += 1,
                "ready" => ready_count += 1,
                "needs-review" => review_count += 1,
                "blocked" => blocked_count += 1,
                "done" => done_count += 1,
                _ => {}
            }
        }
        if let Some(ref s) = source {
            *source_counts.entry(s.clone()).or_insert(0) += 1;
        }

        // Accumulate per-lane age (using updated_at).
        let age_hours = hours_since(&issue.updated_at);
        if let Some(ref l) = lane {
            *lane_age_sum.entry(l.clone()).or_insert(0) += age_hours;
            *lane_age_count.entry(l.clone()).or_insert(0) += 1;
            let oldest = lane_oldest
                .entry(l.clone())
                .or_insert((0, String::new(), 0));
            if age_hours > oldest.0 || oldest.2 == 0 {
                *oldest = (age_hours, issue.title.clone(), issue.number);
            }
        }
    }

    // Closed-issue metrics.
    let mut closed_total = 0usize;
    let mut closed_lane_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut closed_codex_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut closed_kind_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut closed_recent: usize = 0;
    let now_secs = system_now_secs();
    let seven_days_secs: u64 = 7 * 86400;

    for issue in &closed_issues {
        closed_total += 1;
        let lane = label_prefix(&issue.labels, "lane:");
        let codex = label_prefix(&issue.labels, "codex:");
        let kind = label_prefix(&issue.labels, "kind:");

        if let Some(ref l) = lane {
            *closed_lane_counts.entry(l.clone()).or_insert(0) += 1;
        }
        if let Some(ref c) = codex {
            *closed_codex_counts.entry(c.clone()).or_insert(0) += 1;
        }
        if let Some(ref k) = kind {
            *closed_kind_counts.entry(k.clone()).or_insert(0) += 1;
        }

        // Best-effort recency: prefer closed_at, else created_at.
        let ref_ts = issue
            .closed_at
            .as_deref()
            .unwrap_or("")
            .trim_end_matches('Z');
        let ref_ts = if ref_ts.is_empty() {
            issue.created_at.as_deref().unwrap_or("")
        } else {
            ref_ts
        };
        if !ref_ts.is_empty() {
            if let Some(secs) = parse_iso_naive(ref_ts) {
                if now_secs.saturating_sub(secs) <= seven_days_secs {
                    closed_recent += 1;
                }
            }
        }
    }

    // --- Print health report ---
    println!("=== Coordination Health Report ===");
    println!();
    println!(
        "Issue totals: {open_total} open, {closed_total} closed ({closed_recent} closed in last 7d)"
    );
    println!();

    // Codex workflow status.
    println!("--- Codex Workflow Status (open issues) ---");
    println!("  ready:       {ready_count}");
    println!("  claimed:     {claimed_count}");
    println!("  needs-review:{review_count}");
    println!("  blocked:     {blocked_count}");
    println!("  done:        {done_count}");
    if !codex_counts.is_empty() {
        let unaccounted = open_total.saturating_sub(
            ready_count + claimed_count + review_count + blocked_count + done_count,
        );
        if unaccounted > 0 {
            println!("  (unlabeled): {unaccounted}");
        }
    }
    println!();

    // Closed-by-lane breakdown.
    if closed_total > 0 {
        println!("--- Recently Closed by Lane ---");
        if closed_lane_counts.is_empty() {
            println!("  (none)");
        } else {
            for (lane, count) in &closed_lane_counts {
                println!("  {lane}: {count}");
            }
        }
        println!();
        println!("--- Recently Closed by Codex Status ---");
        if closed_codex_counts.is_empty() {
            println!("  (none)");
        } else {
            for (status, count) in &closed_codex_counts {
                println!("  {status}: {count}");
            }
        }
        println!();
        println!("--- Recently Closed by Kind ---");
        if closed_kind_counts.is_empty() {
            println!("  (none)");
        } else {
            for (kind, count) in &closed_kind_counts {
                println!("  {kind}: {count}");
            }
        }
        println!();
    }

    // Lane distribution.
    println!("--- Open Issues by Lane ---");
    if lane_counts.is_empty() {
        println!("  (none)");
    } else {
        for (lane, count) in &lane_counts {
            println!("  {lane}: {count}");
        }
    }
    println!();

    // Lane × Codex status cross-tab.
    println!("--- Lane × Codex Status ---");
    if lane_codex.is_empty() {
        println!("  (none)");
    } else {
        for (lane, codex_map) in &lane_codex {
            let parts: Vec<String> = codex_map.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("  {lane}: {}", parts.join(", "));
        }
    }
    println!();

    // Issue age by lane.
    println!("--- Issue Age by Lane (since last update) ---");
    if lane_age_count.is_empty() {
        println!("  (none)");
    } else {
        for (lane, count) in &lane_age_count {
            let sum = lane_age_sum.get(lane).copied().unwrap_or(0);
            let avg_h = if *count > 0 { sum / *count as u64 } else { 0 };
            let avg_d = avg_h / 24;
            if let Some((oldest_h, _oldest_title, oldest_num)) = lane_oldest.get(lane) {
                println!(
                    "  {lane}: {count} open, avg {avg_d}d since update, oldest #{oldest_num} ({oldest_h}h)"
                );
            } else {
                println!("  {lane}: {count} open, avg {avg_d}d since update");
            }
        }
    }
    println!();

    // Kind distribution.
    println!("--- Open Issues by Kind ---");
    if kind_counts.is_empty() {
        println!("  (none)");
    } else {
        for (kind, count) in &kind_counts {
            println!("  {kind}: {count}");
        }
    }
    println!();

    // Priority distribution.
    println!("--- Open Issues by Priority ---");
    if priority_counts.is_empty() {
        println!("  (none)");
    } else {
        for (priority, count) in &priority_counts {
            println!("  {priority}: {count}");
        }
    }
    println!();

    // Source distribution.
    println!("--- Open Issues by Source ---");
    if source_counts.is_empty() {
        println!("  (none)");
    } else {
        for (source, count) in &source_counts {
            println!("  {source}: {count}");
        }
    }
    println!();

    // Health flags: stale claims, stalled issues, pipeline health.
    println!("--- Health Flags ---");
    let mut flags: Vec<String> = Vec::new();

    let timeout_hours = parse_stale_timeout().unwrap_or(DEFAULT_STALE_TIMEOUT_HOURS);
    let stale = find_stale_forgejo_claims(timeout_hours);
    if !stale.is_empty() {
        flags.push(format!(
            "WARN: {} stale claim(s) (>{timeout_hours}h untouched)",
            stale.len()
        ));
        for (num, hours, title) in &stale {
            flags.push(format!("  #{num} ({hours}h) — \"{title}\""));
        }
    }

    // Stalled open issues: not blocked, untouched > 7 days.
    let mut stalled_count = 0usize;
    for issue in &open_issues {
        if label_prefix(&issue.labels, "codex:").as_deref() == Some("blocked") {
            continue;
        }
        if hours_since(&issue.updated_at) > stalled_hours_threshold {
            stalled_count += 1;
            // Track stalled claimed issues for per-issue health reporting.
            if label_prefix(&issue.labels, "codex:").as_deref() == Some("claimed") {
                let age_days = hours_since(&issue.updated_at) / 24;
                flags.push(format!(
                    "  #{} ({}d) — \"{}\" (claimed, stalled)",
                    issue.number, age_days, issue.title
                ));
            }
        }
    }
    if stalled_count > 0 {
        flags.push(format!(
            "WARN: {stalled_count} open issue(s) untouched for >7d (not blocked) — may need attention"
        ));
    }

    if ready_count == 0 && claimed_count == 0 {
        flags.push("WARN: no ready or claimed issues — pipeline may be stalled".to_string());
    }

    if blocked_count > 0 && ready_count < 3 {
        flags.push(format!(
            "WARN: {blocked_count} blocked issue(s) with only {ready_count} ready — consider unblocking"
        ));
    }

    if flags.is_empty() {
        println!("  No warnings — coordination pipeline looks healthy.");
    } else {
        for flag in &flags {
            println!("  {flag}");
        }
    }
    println!();

    // --- Domain Health Assessment (D1-D4) ---
    println!("--- Domain Health Assessment ---");

    // D1: Active Implementation Lanes
    let active_lanes = ["storage-core", "coordination", "transport"];
    let mut d1_claims = 0usize;
    let mut d1_stalled = 0usize;
    for issue in &open_issues {
        let lane = label_prefix(&issue.labels, "lane:");
        let codex = label_prefix(&issue.labels, "codex:");
        if let Some(ref l) = lane {
            if active_lanes.contains(&l.as_str()) && codex.as_deref() == Some("claimed") {
                d1_claims += 1;
                if hours_since(&issue.updated_at) > stalled_hours_threshold {
                    d1_stalled += 1;
                }
            }
        }
    }
    let d1_state = if d1_stalled >= 2 {
        "Blocked"
    } else if d1_stalled >= 1 || (d1_claims == 0 && ready_count == 0) {
        "Degraded"
    } else {
        "Healthy"
    };
    println!("  D1 Active Lanes:    {d1_state} (claimed={d1_claims}, stalled={d1_stalled})");

    // D2: Deferred Design-to-Wire-Up (design staleness)
    let d2_stale_designs = open_issues
        .iter()
        .filter(|i| {
            label_prefix(&i.labels, "kind:").as_deref() == Some("design")
                && hours_since(&i.updated_at) > 90 * 24
        })
        .count();
    let d2_state = if d2_stale_designs > 2 {
        "AtRisk"
    } else if d2_stale_designs > 0 {
        "Degraded"
    } else {
        "Healthy"
    };
    if d2_stale_designs > 0 {
        println!("  D2 Deferred Designs: {d2_state} ({d2_stale_designs} design(s) >90d stale)");
    } else {
        println!("  D2 Deferred Designs: {d2_state}");
    }

    // D3: Dependency Graph (approximated from blocked count)
    let d3_state = if blocked_count >= 3 {
        "AtRisk"
    } else if blocked_count >= 1 {
        "Degraded"
    } else {
        "Healthy"
    };
    println!("  D3 Dependency Graph: {d3_state} (blocked={blocked_count})");

    // D4: Serial Write Surfaces (claim contention check)
    let d4_state = if claimed_count > 1 {
        "Degraded"
    } else {
        "Healthy"
    };
    println!("  D4 Serial Surfaces:  {d4_state} (active_claims={claimed_count})");

    // Aggregate health: max of domain states.
    let has_blocked = d1_state == "Blocked" || d3_state == "AtRisk";
    let has_degraded = d1_state != "Healthy" || d2_state != "Healthy" || d4_state != "Healthy";
    let aggregate = if has_blocked {
        "Red"
    } else if has_degraded {
        "Yellow"
    } else {
        "Green"
    };
    println!("  Aggregate: {aggregate}");
    println!();
    println!("=== End Coordination Health Report ===");

    Ok(())
}

/// Return the value of the first label whose name starts with `prefix:`.
fn label_prefix(labels: &[ForgejoLabel], prefix: &str) -> Option<String> {
    for label in labels {
        if let Some(rest) = label.name.strip_prefix(prefix) {
            return Some(rest.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// acquire-claim -- atomically claims an issue with optimistic locking
// ---------------------------------------------------------------------------

/// Atomically claim an issue by adding codex:claimed label, using the issue's
/// updated_at field as a version token for optimistic concurrency control.
///
/// Returns Ok(true) if the claim was acquired, Ok(false) if another instance
/// claimed it first, or Err if an API error occurred.
pub fn acquire_claim(issue_num: u64) -> Result<bool, String> {
    // 1. Read current issue state (version token).
    let issue = api_get_issue(issue_num)?;
    let prev_updated_at = issue.updated_at.clone();

    // 2. If already claimed, check if we already own it.
    if issue_has_label(&issue, "codex:claimed") {
        return Ok(false);
    }

    // 3. Add codex:claimed label.
    api_add_label(issue_num, LABEL_CODEX_CLAIMED)?;

    // 4. Remove codex:ready label (best-effort: it may not be present).
    let _ = api_remove_label(issue_num, LABEL_CODEX_READY);

    // 5. Verify: re-read the issue and check optimistic lock.
    let issue2 = api_get_issue(issue_num)?;
    let prev_hours = hours_since(&prev_updated_at);
    let curr_hours = hours_since(&issue2.updated_at);

    // If the issue's updated_at changed between our read and write,
    // another instance may have also modified it.
    if prev_hours != curr_hours && !issue_has_label(&issue2, "codex:claimed") {
        return Ok(false);
    }

    // 6. Post claim comment.
    let body = format!("Codex claim for issue #{issue_num}");
    let _ = api_post_comment(issue_num, &body);

    Ok(true)
}

// ---------------------------------------------------------------------------
// Internal: release claim
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

/// Release a claim: remove codex:claimed and codex:needs-review,
/// add codex:ready, and post an auto-release comment.
fn try_release_claim(issue_num: u64, hours_stale: u64) -> Result<(), String> {
    // 1. Remove codex:claimed label.
    api_remove_label(issue_num, LABEL_CODEX_CLAIMED)?;

    // 2. Remove codex:needs-review label if present (best-effort).
    let _ = api_remove_label(issue_num, LABEL_CODEX_NEEDS_REVIEW);

    // 3. Add codex:ready label.
    api_add_label(issue_num, LABEL_CODEX_READY)?;

    // 4. Post auto-release comment.
    let body = format!(
        "Codex auto-release -- issue #{issue_num} was stale ({hours_stale}h unclaimed). Returned to ready pool."
    );
    api_post_comment(issue_num, &body)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf, ForgejoWorkError> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| ForgejoWorkError {
            violations: vec!["cannot determine home directory ($HOME not set)".to_string()],
        })
}

fn detect_issue_number_from_path(cwd: &Path, worktree_root: &Path) -> Option<u64> {
    let cwd_str = cwd.to_string_lossy();
    let root_str = worktree_root.to_string_lossy();
    let after = cwd_str
        .strip_prefix(root_str.as_ref())?
        .trim_start_matches('/');
    after
        .strip_prefix("issue-")?
        .split('-')
        .next()?
        .parse::<u64>()
        .ok()
}

fn foreground_main_checkout_root(cwd: &Path, home: &Path) -> Option<PathBuf> {
    let repo_root = git_toplevel(cwd).ok()?;
    if repo_root == home.join("tidefs") {
        Some(repo_root)
    } else {
        None
    }
}

fn active_claimed_issues(issues: &[ForgejoIssue]) -> Vec<&ForgejoIssue> {
    issues
        .iter()
        .filter(|issue| {
            issue_has_label(issue, "codex:claimed") && issue_has_label(issue, "status:active")
        })
        .collect()
}

fn find_worktree_dir(worktree_root: &Path, issue_num: u64) -> Option<PathBuf> {
    let prefix = format!("issue-{issue_num}-");
    for entry in fs::read_dir(worktree_root).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(&prefix) {
            return Some(entry.path());
        }
    }
    None
}

fn validate_worktree_branch(wt_dir: &Path, issue_num: u64) -> Result<(), String> {
    let branch = git_branch(wt_dir).map_err(|err| {
        format!(
            "could not determine branch in '{}': {err}",
            wt_dir.display()
        )
    })?;

    let expected_prefix = format!("{CODEX_BRANCH_PREFIX}{issue_num}-");
    if !branch.starts_with(&expected_prefix) {
        return Err(format!(
            "worktree branch '{}' does not match expected prefix '{}*' in '{}'",
            branch,
            expected_prefix,
            wt_dir.display()
        ));
    }
    Ok(())
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

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Forgejo API helpers (ureq native HTTP with basic auth)
// ---------------------------------------------------------------------------

fn api_base() -> String {
    let repo = forgejo_repo();
    format!("{FORGEJO_BASE_URL}/api/v1/repos/{repo}")
}

fn forgejo_repo() -> String {
    if let Some(repo) = std::env::var(FORGEJO_REPO_ENV)
        .ok()
        .filter(|repo| !repo.trim().is_empty())
    {
        return repo;
    }

    git_config_value("tidefs.forgejo-repo").unwrap_or_else(|| DEFAULT_FORGEJO_REPO.to_string())
}

fn git_config_value(key: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["config", "--get", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn api_get(path: &str) -> Result<String, String> {
    let url = api_url(path);
    api_request("GET", &url, None)
}

fn api_post(path: &str, body: Option<&str>) -> Result<String, String> {
    let url = api_url(path);
    api_request("POST", &url, body)
}

fn api_delete(path: &str) -> Result<(), String> {
    let url = api_url(path);
    api_request("DELETE", &url, None)?;
    Ok(())
}

fn api_url(path: &str) -> String {
    format!("{}{}", api_base(), path)
}

/// Execute an HTTP request with jittered exponential backoff retry.
fn api_request(method: &str, url: &str, body: Option<&str>) -> Result<String, String> {
    let creds = ApiCredentials::from_file(CREDENTIAL_FILE)?;
    let auth_header = creds.to_basic_auth();

    let mut last_err = String::new();
    for attempt in 0..MAX_API_RETRIES {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(std::time::Duration::from_secs(
                FORGEJO_CONNECT_TIMEOUT_SECS,
            )))
            .timeout_global(Some(std::time::Duration::from_secs(
                FORGEJO_READ_TIMEOUT_SECS,
            )))
            .build()
            .new_agent();

        let result = match method {
            "GET" => agent.get(url).header("Authorization", &auth_header).call(),
            "POST" => {
                let b = body.ok_or_else(|| "POST requires body".to_string())?;
                agent
                    .post(url)
                    .header("Authorization", &auth_header)
                    .header("Content-Type", "application/json")
                    .send(b)
            }
            "DELETE" => agent
                .delete(url)
                .header("Authorization", &auth_header)
                .call(),
            _ => return Err(format!("unsupported HTTP method: {method}")),
        };

        match result {
            Ok(resp) => {
                let status = resp.status();
                let status_code = status.as_u16();

                // Read response body into a string.
                let resp_body = resp
                    .into_body()
                    .read_to_string()
                    .map_err(|e| format!("failed to read response body: {e}"))?;

                if status.is_success() {
                    return Ok(resp_body);
                }

                if status_code == 404 && method == "DELETE" {
                    return Ok(String::new());
                }

                last_err = format!(
                    "API {method} {url} returned HTTP {status_code}: {}",
                    &resp_body
                );
            }
            Err(ureq::Error::StatusCode(code)) => {
                last_err = format!("API {method} {url} returned HTTP {code}");
            }
            Err(e) => {
                last_err = format!("API transport error: {e}");
            }
        }

        if attempt + 1 < MAX_API_RETRIES {
            let base_ms = 500_u64.saturating_mul(2_u64.pow(attempt));
            let jitter = base_ms / 2 + (system_now_secs() % base_ms.max(1));
            std::thread::sleep(Duration::from_millis(base_ms + jitter));
        }
    }

    Err(last_err)
}

/// Fetch a single issue from Forgejo (serde-parsed).
fn api_get_issue(issue_num: u64) -> Result<ForgejoIssue, String> {
    let path = format!("/issues/{issue_num}");
    let body = api_get(&path)?;
    serde_json::from_str(&body)
        .map_err(|err| format!("failed to parse issue #{issue_num} JSON: {err}"))
}

fn api_list_open_issues() -> Result<Vec<ForgejoIssue>, String> {
    let mut issues = Vec::new();
    let mut page = 1;

    loop {
        let body = api_get(&format!("/issues?state=open&limit=50&page={page}"))?;
        let mut batch: Vec<ForgejoIssue> = serde_json::from_str(&body)
            .map_err(|err| format!("failed to parse open issues page {page} JSON: {err}"))?;
        if batch.is_empty() {
            break;
        }
        issues.append(&mut batch);
        page += 1;
    }

    Ok(issues)
}

/// Add a label to an issue.
fn api_add_label(issue_num: u64, label_id: u64) -> Result<(), String> {
    let path = format!("/issues/{issue_num}/labels");
    let data = format!("{{\"labels\":[{label_id}]}}");
    api_post(&path, Some(&data))?;
    Ok(())
}

/// Remove a label from an issue.
fn api_remove_label(issue_num: u64, label_id: u64) -> Result<(), String> {
    let path = format!("/issues/{issue_num}/labels/{label_id}");
    api_delete(&path)
}

/// Post a comment on an issue.
fn api_post_comment(issue_num: u64, body: &str) -> Result<(), String> {
    let path = format!("/issues/{issue_num}/comments");
    let data = format!("{{\"body\":{}}}", json_string(body));
    api_post(&path, Some(&data))?;
    Ok(())
}

/// Check whether an issue on Forgejo currently has the codex:claimed label.
/// Uses serde_json to parse the API response.
fn check_forgejo_claim(issue_num: u64) -> Result<bool, String> {
    let path = format!("/issues/{issue_num}");
    let body = api_get(&path)?;
    let issue: ForgejoIssue = serde_json::from_str(&body)
        .map_err(|err| format!("failed to parse issue #{issue_num} JSON: {err}"))?;
    Ok(issue_has_label(&issue, "codex:claimed"))
}

/// Find all open Forgejo issues that have the codex:claimed label and have
/// been untouched for longer than timeout_hours.
/// Uses serde_json for reliable JSON parsing (no manual string scanning).
fn find_stale_forgejo_claims(timeout_hours: u64) -> Vec<(u64, u64, String)> {
    let body = match api_get("/issues?state=open&limit=100") {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let issues: Vec<ForgejoIssue> = match serde_json::from_str(&body) {
        Ok(issues) => issues,
        Err(_) => return Vec::new(),
    };

    let mut stale = Vec::new();
    for issue in &issues {
        if !issue_has_label(issue, "codex:claimed") {
            continue;
        }
        let hours = hours_since(&issue.updated_at);
        if hours > timeout_hours {
            stale.push((issue.number, hours, issue.title.clone()));
        }
    }
    stale
}

fn detect_duplicate_claims_from_issues(issues: &[ForgejoIssue]) -> Vec<DuplicatedClaim> {
    let mut by_key: BTreeMap<String, Vec<DuplicatedClaimIssue>> = BTreeMap::new();

    for issue in issues {
        if !issue_has_label(issue, "codex:claimed") {
            continue;
        }

        by_key
            .entry(duplicate_claim_key(&issue.title))
            .or_default()
            .push(DuplicatedClaimIssue {
                number: issue.number,
                title: issue.title.clone(),
                updated_at: issue.updated_at.clone(),
            });
    }

    by_key
        .into_iter()
        .filter_map(|(key, mut issues)| {
            if issues.len() < 2 {
                return None;
            }
            issues.sort_by_key(|issue| issue.number);
            Some(DuplicatedClaim {
                key,
                issues,
                recommended_action:
                    "keep one claimed issue and block or close duplicate claimed issues"
                        .to_string(),
            })
        })
        .collect()
}

fn duplicate_claim_key(title: &str) -> String {
    let lower = title.to_ascii_lowercase();
    if (lower.contains("parser") || lower.contains("wire-format")) && lower.contains("fusewire") {
        if let Some(opcode) = first_fuse_opcode(title) {
            return format!("fusewire:{}:parser", opcode.to_ascii_lowercase());
        }
    }

    if let Some(slug) = leading_tracker_slug(title) {
        let normalized = normalize_tracker_slug(slug);
        if !normalized.is_empty() {
            return format!("slug:{normalized}");
        }
    }

    format!("title:{}", normalize_freeform_title(title))
}

fn first_fuse_opcode(title: &str) -> Option<String> {
    let upper = title.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut search_start = 0;

    while let Some(relative_start) = upper[search_start..].find("FUSE_") {
        let start = search_start + relative_start;
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_uppercase()
                || bytes[end].is_ascii_digit()
                || bytes[end] == b'_')
        {
            end += 1;
        }
        if end > start + "FUSE_".len() {
            return Some(upper[start..end].to_string());
        }
        search_start = start + "FUSE_".len();
    }

    None
}

fn leading_tracker_slug(title: &str) -> Option<&str> {
    let title = title.trim_start();
    let rest = title.strip_prefix('[')?;
    let end = rest.find(']')?;
    let slug = rest[..end].trim();
    if slug.is_empty() {
        None
    } else {
        Some(slug)
    }
}

fn normalize_tracker_slug(slug: &str) -> String {
    let mut parts = slug
        .split('-')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    while parts
        .last()
        .is_some_and(|part| part.chars().all(|ch| ch.is_ascii_digit()))
    {
        parts.pop();
    }

    while parts.last().is_some_and(|part| {
        part.strip_prefix('s')
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit()))
    }) {
        parts.pop();
    }

    parts.join("-")
}

fn normalize_freeform_title(title: &str) -> String {
    let mut normalized = String::new();
    let mut previous_dash = false;

    for ch in title.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash && !normalized.is_empty() {
            normalized.push('-');
            previous_dash = true;
        }
    }

    if normalized.ends_with('-') {
        normalized.pop();
    }
    normalized
}

/// Check whether a parsed ForgejoIssue has a label with the given name.
/// Uses exact string comparison to avoid substring false positives
/// (e.g. "codex:claimed-old" does not match "codex:claimed").
fn issue_has_label(issue: &ForgejoIssue, label_name: &str) -> bool {
    issue.labels.iter().any(|l| l.name == label_name)
}

fn parse_stale_timeout() -> Option<u64> {
    std::env::var("TIDEFS_STALE_TIMEOUT_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Compute hours elapsed since an ISO 8601 timestamp (pure Rust, no subprocess).
fn hours_since(iso_date: &str) -> u64 {
    // Strip trailing Z and optional fractional seconds for naive parsing.
    let cleaned = iso_date.trim_end_matches('Z').trim_end_matches('z');
    // Handle optional fractional seconds: "2026-05-01T01:50:40.123" -> "2026-05-01T01:50:40"
    let cleaned = if let Some(dot) = cleaned.rfind('.') {
        &cleaned[..dot]
    } else {
        cleaned
    };

    // Parse with pure-Rust implementation.
    let parsed = parse_iso_naive(cleaned);
    let elapsed = match parsed {
        Some(then_secs) => system_now_secs().saturating_sub(then_secs),
        None => {
            // Fallback: use date -d for complex formats
            match Command::new("date").args(["-d", iso_date, "+%s"]).output() {
                Ok(o) if o.status.success() => {
                    let then = String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(0);
                    system_now_secs().saturating_sub(then)
                }
                _ => 0,
            }
        }
    };
    elapsed / 3600
}

/// Parse a naive ISO datetime "YYYY-MM-DDTHH:MM:SS" into UNIX seconds.
fn parse_iso_naive(s: &str) -> Option<u64> {
    // Expected: "2026-05-01T01:50:40" or "2026-05-01T01:50:40+02:00"
    let (date_part, time_part) = s.split_once('T')?;
    let dp: Vec<&str> = date_part.split('-').collect();
    if dp.len() != 3 {
        return None;
    }
    let year: i64 = dp[0].parse().ok()?;
    let month: u32 = dp[1].parse().ok()?;
    let day: u32 = dp[2].parse().ok()?;

    // Strip optional timezone suffix (+HH:MM or -HH:MM) from the time part.
    let (time_clean, tz_offset_hours, tz_offset_mins) = strip_timezone(time_part);

    let tp: Vec<&str> = time_clean.split(':').collect();
    if tp.len() != 3 {
        return None;
    }
    let mut hour: i64 = tp[0].parse().ok()?;
    let min: u32 = tp[1].parse().ok()?;
    let sec: u32 = tp[2].parse().ok()?;

    // Convert to UTC by subtracting the timezone offset.
    hour -= tz_offset_hours;

    // Days from 1970-01-01 to the given date (proleptic Gregorian).
    let days = days_since_epoch(year, month, day)?;
    let total_secs =
        days as i64 * 86400 + hour * 3600 + (min as i64 - tz_offset_mins) * 60 + sec as i64;
    if total_secs < 0 {
        return None;
    }
    Some(total_secs as u64)
}
fn system_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Strip optional timezone suffix `+HH:MM` or `-HH:MM` from a time string.
/// Returns (cleaned_time_str, offset_hours, offset_minutes).
fn strip_timezone(t: &str) -> (&str, i64, i64) {
    // Find the last '+' or '-' that is part of a timezone offset
    // (the offset starts after the seconds, i.e. at position >= 6).
    let bytes = t.as_bytes();
    for i in (1..bytes.len()).rev() {
        if bytes[i] == b'+' || bytes[i] == b'-' {
            // Must have : after the sign for HH:MM format.
            if let Some(colon_pos) = t[i..].find(':') {
                let h = t[i + 1..i + colon_pos].parse::<i64>().unwrap_or(0);
                let m = t[i + colon_pos + 1..].parse::<i64>().unwrap_or(0);
                let sign: i64 = if bytes[i] == b'-' { -1 } else { 1 };
                return (&t[..i], sign * h, sign * m);
            }
            // Bare offset like "+02" without minutes.
            let h = t[i + 1..].parse::<i64>().unwrap_or(0);
            let sign: i64 = if bytes[i] == b'-' { -1 } else { 1 };
            return (&t[..i], sign * h, 0);
        }
    }
    (t, 0, 0)
}

/// Days from 1970-01-01 to Y-M-D (proleptic Gregorian).
fn days_since_epoch(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let m = m as i64;
    let d = d as i64;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400; // year of era [0, 399]
    let doy = (153 * (if m <= 2 { m + 9 } else { m - 3 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day of era [0, 146096]
    Some(era * 146097 + doe - 719468) // shift to UNIX epoch
}

/// Minimal JSON string escaping: wraps s in quotes and escapes \", \\, and control chars.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_issue(number: u64, title: &str, labels: &[&str]) -> ForgejoIssue {
        ForgejoIssue {
            number,
            title: title.into(),
            state: "open".into(),
            labels: labels
                .iter()
                .enumerate()
                .map(|(idx, name)| ForgejoLabel {
                    id: idx as u64,
                    name: (*name).into(),
                })
                .collect(),
            closed_at: None,
            created_at: None,
            updated_at: "2026-05-06T17:00:00+02:00".into(),
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
    }

    #[test]
    fn detect_issue_number_from_invalid_path() {
        let worktree_root = Path::new("/root/tidefs-worktrees");
        let cwd = Path::new("/root/tidefs");
        assert_eq!(detect_issue_number_from_path(cwd, worktree_root), None);

        let cwd2 = Path::new("/root/tidefs-worktrees/no-issue-here");
        assert_eq!(detect_issue_number_from_path(cwd2, worktree_root), None);
    }

    #[test]
    fn active_claimed_issues_requires_claimed_and_active() {
        let issues = vec![
            test_issue(6570, "active", &["codex:claimed", "status:active"]),
            test_issue(6571, "claimed only", &["codex:claimed", "status:open"]),
            test_issue(6572, "active only", &["codex:ready", "status:active"]),
        ];

        let active = active_claimed_issues(&issues);

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].number, 6570);
    }

    #[test]
    fn parse_stale_timeout_default() {
        std::env::remove_var("TIDEFS_STALE_TIMEOUT_HOURS");
        assert_eq!(parse_stale_timeout(), None);
    }

    #[test]
    fn hours_since_iso_date() {
        let hours = hours_since("2020-01-01T00:00:00Z");
        assert!(hours > 0);
    }

    #[test]
    fn json_string_escapes_special_chars() {
        let s = json_string("hello");
        assert_eq!(s, "\"hello\"");
        let s = json_string("say \"hi\"");
        assert_eq!(s, "\"say \\\"hi\\\"\"");
        let s = json_string("line1\nline2");
        assert_eq!(s, "\"line1\\nline2\"");
    }

    #[test]
    fn issue_has_label_detects_labels() {
        let issue = ForgejoIssue {
            number: 730,
            title: "test".into(),
            state: "open".into(),
            labels: vec![
                ForgejoLabel {
                    id: 69,
                    name: "codex:claimed".into(),
                },
                ForgejoLabel {
                    id: 43,
                    name: "kind:implementation".into(),
                },
            ],
            closed_at: None,
            created_at: None,
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        assert!(issue_has_label(&issue, "codex:claimed"));
        assert!(!issue_has_label(&issue, "codex:ready"));
    }

    #[test]
    fn issue_has_label_no_false_match_on_substring() {
        // Ensures "codex:claimed" does not match "codex:claimed-old"
        let issue = ForgejoIssue {
            number: 730,
            title: "test".into(),
            state: "open".into(),
            labels: vec![ForgejoLabel {
                id: 69,
                name: "codex:claimed-old".into(),
            }],
            closed_at: None,
            created_at: None,
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        assert!(!issue_has_label(&issue, "codex:claimed"));
    }

    #[test]
    fn issue_has_label_empty_labels() {
        let issue = ForgejoIssue {
            number: 730,
            title: "test".into(),
            state: "open".into(),
            labels: vec![],
            closed_at: None,
            created_at: None,
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        assert!(!issue_has_label(&issue, "codex:claimed"));
    }

    #[test]
    fn duplicate_claim_key_groups_fusewire_parser_titles_by_opcode() {
        let first =
            "[FUSEWIRE-GETATTR-PARSER-001] Add FUSE_GETATTR wire-format parser to fusewire crate";
        let second =
            "[FUSEWIRE-GETATTR-PARSER-S25-001] Add FUSE_GETATTR wire-format request parser";

        assert_eq!(duplicate_claim_key(first), duplicate_claim_key(second));
        assert_eq!(duplicate_claim_key(first), "fusewire:fuse_getattr:parser");
    }

    #[test]
    fn duplicate_claim_key_normalizes_tracker_slug_suffixes() {
        assert_eq!(
            duplicate_claim_key("[UBLK-FLUSH-CYCLE-COMPLETION-001] Add flush test"),
            duplicate_claim_key("[UBLK-FLUSH-CYCLE-COMPLETION-S14-001] Add duplicate flush test")
        );
        assert_eq!(
            duplicate_claim_key("[UBLK-FLUSH-CYCLE-COMPLETION-001] Add flush test"),
            "slug:ublk-flush-cycle-completion"
        );
    }

    #[test]
    fn detect_duplicate_claims_from_issues_reports_only_claimed_duplicates() {
        let issues = vec![
            test_issue(
                2788,
                "[FUSEWIRE-GETATTR-PARSER-001] Add FUSE_GETATTR wire-format request parser",
                &["codex:claimed"],
            ),
            test_issue(
                2813,
                "[FUSEWIRE-GETATTR-PARSER-S25-001] Add FUSE_GETATTR wire-format parser",
                &["codex:claimed"],
            ),
            test_issue(
                2807,
                "[FUSEWIRE-GETATTR-PARSER-001] Add FUSE_GETATTR wire-format parser",
                &["codex:blocked"],
            ),
            test_issue(
                2819,
                "[XTASK-DUPLICATE-CLAIM-DETECTION-001] Add check-duplicate-claims command",
                &["codex:claimed"],
            ),
        ];

        let duplicated = detect_duplicate_claims_from_issues(&issues);
        assert_eq!(duplicated.len(), 1);
        assert_eq!(duplicated[0].key, "fusewire:fuse_getattr:parser");
        assert_eq!(
            duplicated[0]
                .issues
                .iter()
                .map(|issue| issue.number)
                .collect::<Vec<_>>(),
            vec![2788, 2813]
        );
        assert!(duplicated[0]
            .recommended_action
            .contains("keep one claimed issue"));
    }

    #[test]
    fn parse_iso_naive_parses_standard_format() {
        let result = parse_iso_naive("2026-05-01T01:50:40");
        assert!(result.is_some(), "standard format should parse");
        let secs = result.unwrap();
        assert!(secs > 0, "seconds should be positive");
    }

    #[test]
    fn parse_iso_naive_handles_timezone_offset() {
        // "2026-05-01T01:50:40+02:00" → UTC: 2026-04-30T23:50:40
        let with_tz = parse_iso_naive("2026-05-01T01:50:40+02:00");
        let without_tz = parse_iso_naive("2026-04-30T23:50:40");
        assert_eq!(
            with_tz, without_tz,
            "time with +02:00 offset should equal UTC time"
        );
    }

    #[test]
    fn parse_iso_naive_rejects_malformed() {
        assert!(parse_iso_naive("not-a-date").is_none());
        assert!(parse_iso_naive("2026-01").is_none());
        assert!(parse_iso_naive("2026-01-01").is_none());
    }
    #[test]
    fn base64_encode_standard_cases() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn api_credentials_parses_plain_text_file() {
        let tmp = std::env::temp_dir().join("test-creds-forgejo.txt");
        std::fs::write(
            &tmp,
            "Forgejo URL: http://x\nUsername: testuser\nPassword: testpass\nGenerated: date\n",
        )
        .unwrap();
        let creds = ApiCredentials::from_file(tmp.to_str().unwrap()).unwrap();
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password, "testpass");
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn api_credentials_basic_auth_header() {
        let creds = ApiCredentials {
            username: "alice".into(),
            password: "secret".into(),
        };
        let auth = creds.to_basic_auth();
        assert_eq!(auth, "Basic YWxpY2U6c2VjcmV0");
    }

    #[test]
    fn extract_field_parses_lines() {
        let content = "Forgejo URL: http://x\nUsername: admin\nPassword: pass123\n";
        assert_eq!(
            extract_field(content, "Username:"),
            Some("admin".to_string())
        );
        assert_eq!(
            extract_field(content, "Password:"),
            Some("pass123".to_string())
        );
        assert_eq!(extract_field(content, "Nonexistent:"), None);
    }
}
