// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_POOL_ID: AtomicU64 = AtomicU64::new(0);

fn run_status(command: &str, json: bool) -> (String, Output) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let pool_name = format!(
        "status-boundary-{}-{now}-{}-{command}",
        std::process::id(),
        NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed)
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_tidefsctl"));
    process.args([command, "status", &pool_name]);
    if json {
        process.arg("--json");
    }
    let output = process.output().expect("run tidefsctl status command");
    (pool_name, output)
}

#[test]
fn no_owner_status_is_an_operator_refusal() {
    for command in ["cluster", "device"] {
        let (pool_name, output) = run_status(command, false);
        assert_eq!(output.status.code(), Some(1), "{command} status");
        assert!(output.stdout.is_empty(), "{command} status wrote stdout");

        let stderr = String::from_utf8(output.stderr).expect("human refusal is UTF-8");
        for expected in [
            format!("tidefsctl {command} status"),
            pool_name,
            "[source:unavailable-live-owner]".to_string(),
            "[source:unsupported-local-mode]".to_string(),
            "cached local metadata".to_string(),
            "non-authoritative".to_string(),
        ] {
            assert!(
                stderr.contains(&expected),
                "{command} status stderr omitted {expected:?}:\n{stderr}"
            );
        }
    }
}

#[test]
fn no_owner_status_json_is_a_machine_refusal() {
    for command in ["cluster", "device"] {
        let (pool_name, output) = run_status(command, true);
        assert_eq!(output.status.code(), Some(1), "{command} status --json");
        assert!(
            output.stderr.is_empty(),
            "{command} status --json wrote stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON refusal is parseable");
        assert_eq!(value["ok"], false, "{command} status --json");
        assert_eq!(value["command"], command, "{command} status --json");
        assert_eq!(value["operation"], "status", "{command} status --json");
        assert_eq!(value["pool_name"], pool_name, "{command} status --json");
        assert_eq!(
            value["source_classification"], "source:unavailable-live-owner",
            "{command} status --json"
        );
        assert_eq!(
            value["source:status"], "source:unavailable-live-owner",
            "{command} status --json"
        );
        assert_eq!(
            value["local_mode_classification"], "source:unsupported-local-mode",
            "{command} status --json"
        );
        assert!(
            value["error"].as_str().is_some_and(|error| {
                error.contains("no live status evidence obtained")
                    && error.contains("cached local metadata is non-authoritative")
            }),
            "{command} status --json omitted the refusal error: {value}"
        );
        assert!(
            value["recovery"]
                .as_str()
                .is_some_and(|recovery| recovery.contains("start or repair")),
            "{command} status --json omitted recovery guidance: {value}"
        );
    }
}
