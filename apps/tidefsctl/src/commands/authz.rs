//! Local-only admission for privileged `tidefsctl` command handlers.

use tidefs_auth::local_only::{LocalOnlyError, LocalOnlyGuard};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandAdmission {
    LocalOnly,
    LocalOnlyWhenMutating,
    Unguarded,
}

impl CommandAdmission {
    pub(crate) const fn requires_local_only(self) -> bool {
        matches!(self, Self::LocalOnly | Self::LocalOnlyWhenMutating)
    }
}

const LOCAL_ONLY_COMMANDS: &[&str] = &[
    "pool create",
    "pool import",
    "pool export",
    "pool destroy",
    "pool set",
    "device remove",
    "snapshot create",
    "snapshot destroy",
    "snapshot rollback",
    "snapshot send",
    "snapshot receive",
    "block attach",
    "block detach",
    "block send",
    "block receive",
    "dataset create",
    "dataset destroy",
    "dataset rename",
    "dataset seal-key",
    "dataset rotate-key",
    "dataset upgrade",
    "dataset set",
    "defrag",
];

const LOCAL_ONLY_WHEN_MUTATING_COMMANDS: &[&str] = &["dataset set-strategy"];

const UNGUARDED_COMMANDS: &[&str] = &[
    "pool scan",
    "pool status",
    "pool get",
    "pool list-props",
    "snapshot list",
    "device rebuild",
    "block list",
    "dataset list",
    "dataset get",
    "dataset list-props",
    "mount",
    "pool mount",
    "pool integrity-check",
    "kernel status",
    "diag",
    "cluster pool create",
    "cluster placement exercise",
    "cluster heal exercise",
    "pool list",
    "directory-backed pool media",
    "pool integrity-check --backing-dir",
    "snapshot --backing-dir",
    "block --backing-dir",
    "device remove --backing-dir",
    "device remove --surviving-dirs",
];

pub(crate) fn command_admission(command: &str) -> Option<CommandAdmission> {
    if LOCAL_ONLY_COMMANDS.contains(&command) {
        Some(CommandAdmission::LocalOnly)
    } else if LOCAL_ONLY_WHEN_MUTATING_COMMANDS.contains(&command) {
        Some(CommandAdmission::LocalOnlyWhenMutating)
    } else if UNGUARDED_COMMANDS.contains(&command) {
        Some(CommandAdmission::Unguarded)
    } else {
        None
    }
}

pub(crate) fn require_local_only(command: &'static str) -> LocalOnlyGuard {
    debug_assert!(
        matches!(
            command_admission(command),
            Some(CommandAdmission::LocalOnly | CommandAdmission::LocalOnlyWhenMutating)
        ),
        "missing local-only admission for privileged command {command}"
    );
    LocalOnlyGuard::new(command).unwrap_or_else(|err| refuse(command, err))
}

pub(crate) fn require_local_only_when_mutating(
    command: &'static str,
    mutating: bool,
) -> Option<LocalOnlyGuard> {
    if mutating {
        Some(require_local_only(command))
    } else {
        None
    }
}

fn refuse(command: &'static str, err: LocalOnlyError) -> ! {
    eprintln!("tidefsctl {command}: {err}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::classification::{CommandClass, COMMAND_SURFACES};

    #[test]
    fn issue_239_privileged_commands_require_local_only() {
        for command in [
            "pool create",
            "pool destroy",
            "device remove",
            "snapshot create",
            "snapshot destroy",
            "block attach",
            "block detach",
            "dataset create",
            "dataset destroy",
            "dataset rename",
            "dataset set-strategy",
            "dataset seal-key",
            "dataset rotate-key",
            "dataset upgrade",
            "dataset set",
            "defrag",
        ] {
            let admission = command_admission(command).expect("classified command admission");
            assert!(
                admission.requires_local_only(),
                "{command} should require LocalOnlyGuard"
            );
        }
    }

    #[test]
    fn read_only_and_diagnostic_commands_stay_unguarded() {
        for command in [
            "pool scan",
            "pool status",
            "pool get",
            "pool list-props",
            "snapshot list",
            "block list",
            "dataset list",
            "dataset get",
            "dataset list-props",
            "pool integrity-check",
            "kernel status",
            "diag",
            "cluster pool create",
            "cluster placement exercise",
            "cluster heal exercise",
        ] {
            assert_eq!(
                command_admission(command),
                Some(CommandAdmission::Unguarded),
                "{command} should not acquire the privileged guard"
            );
        }
    }

    #[test]
    fn dataset_set_strategy_only_guards_mutation_mode() {
        assert_eq!(
            command_admission("dataset set-strategy"),
            Some(CommandAdmission::LocalOnlyWhenMutating)
        );
    }

    #[test]
    fn all_command_surfaces_have_an_admission_decision() {
        for surface in COMMAND_SURFACES {
            assert!(
                command_admission(surface.path).is_some(),
                "missing admission decision for {}",
                surface.path
            );
        }
    }

    #[test]
    fn public_operator_mutations_are_not_silent_unguarded_entries() {
        for surface in COMMAND_SURFACES
            .iter()
            .filter(|surface| surface.class == CommandClass::PublicOperator)
        {
            assert!(
                command_admission(surface.path).is_some(),
                "public operator command {} lacks admission metadata",
                surface.path
            );
        }
    }
}
