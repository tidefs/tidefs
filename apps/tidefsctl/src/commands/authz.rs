// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Local-only admission for privileged `tidefsctl` command handlers.

#[cfg(test)]
use crate::commands::classification::COMMAND_SURFACES;
use tidefs_auth::local_only::{LocalOnlyError, LocalOnlyGuard};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandAdmission {
    LocalOnly,
    LocalOnlyWhenMutating,
    Unguarded,
}

impl CommandAdmission {
    #[cfg(test)]
    pub(crate) const fn requires_local_only(self) -> bool {
        matches!(self, Self::LocalOnly | Self::LocalOnlyWhenMutating)
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::LocalOnly => "local-only",
            Self::LocalOnlyWhenMutating => "local-only-when-mutating",
            Self::Unguarded => "unguarded",
        }
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
    "snapshot export",
    "snapshot extract",
    "snapshot rollback",
    "snapshot send",
    "snapshot receive",
    "snapshot clone create",
    "snapshot clone delete",
    "snapshot clone promote",
    "snapshot bookmark create",
    "snapshot bookmark delete",
    "snapshot hold",
    "snapshot release",
    "snapshot prune",
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
    "storage-intent policy set",
    "storage-intent policy clear",
    "defrag",
];

const LOCAL_ONLY_WHEN_MUTATING_COMMANDS: &[&str] = &["dataset set-strategy"];

const UNGUARDED_COMMANDS: &[&str] = &[
    "pool scan",
    "pool status",
    "pool get",
    "pool list-props",
    "snapshot list",
    "snapshot holds",
    "device rebuild",
    "block list",
    "dataset list",
    "dataset get",
    "dataset list-props",
    "storage-intent explain",
    "storage-intent policy show",
    "storage-intent policy dry-run",
    "mount",
    "pool mount",
    "pool integrity-check",
    "kernel status",
    "cluster status",
    "device status",
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

#[cfg(test)]
pub(crate) fn command_surface_authority_table() -> String {
    let mut out = String::from("| Command | Class | Routing | Admission | Help | Summary |\n");
    out.push_str("|---|---|---|---|---|---|\n");

    for surface in COMMAND_SURFACES {
        let admission =
            command_admission(surface.path).expect("classified command surface admission");
        out.push_str("| `");
        out.push_str(surface.path);
        out.push_str("` | `");
        out.push_str(surface.class.label());
        out.push_str("` | `");
        out.push_str(surface.routing.label());
        out.push_str("` | `");
        out.push_str(admission.label());
        out.push_str("` | `");
        out.push_str(if surface.visible_in_root_help() {
            "visible"
        } else {
            "hidden"
        });
        out.push_str("` | ");
        out.push_str(surface.summary);
        out.push_str(" |\n");
    }

    out
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
    use crate::commands::classification::CommandClass;

    #[test]
    fn issue_239_privileged_commands_require_local_only() {
        for command in [
            "pool create",
            "pool destroy",
            "device remove",
            "snapshot create",
            "snapshot destroy",
            "snapshot export",
            "snapshot extract",
            "snapshot clone create",
            "snapshot clone delete",
            "snapshot clone promote",
            "snapshot bookmark create",
            "snapshot bookmark delete",
            "snapshot hold",
            "snapshot release",
            "snapshot prune",
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
            "snapshot holds",
            "block list",
            "dataset list",
            "dataset get",
            "dataset list-props",
            "storage-intent explain",
            "pool integrity-check",
            "kernel status",
            "cluster status",
            "device status",
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

    /// Return true when `path` names a command that mutates pool, device,
    /// dataset, snapshot, block, or cluster state.
    ///
    /// Matches on individual space-separated words so that read-only
    /// variants (e.g. "snapshot holds" vs the mutation "snapshot hold")
    /// are not misclassified.
    #[cfg(test)]
    fn is_mutating_command_path(path: &str) -> bool {
        const MUTATION_VERBS: &[&str] = &[
            "create",
            "destroy",
            "delete",
            "set",
            "remove",
            "attach",
            "detach",
            "send",
            "receive",
            "rollback",
            "prune",
            "defrag",
            "rename",
            "seal-key",
            "rotate-key",
            "upgrade",
            "promote",
            "hold",
            "release",
            "import",
            "export",
        ];
        path.split_whitespace()
            .any(|word| MUTATION_VERBS.contains(&word))
    }

    #[test]
    fn public_operator_mutations_are_not_silent_unguarded_entries() {
        for surface in COMMAND_SURFACES
            .iter()
            .filter(|surface| surface.class == CommandClass::PublicOperator)
        {
            let admission = command_admission(surface.path).unwrap_or_else(|| {
                panic!(
                    "public operator command {} lacks admission metadata",
                    surface.path
                )
            });
            // Mutating public-operator commands must not be Unguarded.
            if is_mutating_command_path(surface.path) {
                assert!(
                    admission.requires_local_only(),
                    "mutating public operator command `{}` is silently unguarded \
                     (admission: {}); privileged mutation must require local-only",
                    surface.path,
                    admission.label()
                );
            }
        }
    }

    #[test]
    fn admission_entries_all_point_at_registered_command_surfaces() {
        for command in LOCAL_ONLY_COMMANDS
            .iter()
            .copied()
            .chain(LOCAL_ONLY_WHEN_MUTATING_COMMANDS.iter().copied())
            .chain(UNGUARDED_COMMANDS.iter().copied())
        {
            assert!(
                COMMAND_SURFACES
                    .iter()
                    .any(|surface| surface.path == command),
                "admission entry {command} is missing from COMMAND_SURFACES"
            );
        }
    }

    #[test]
    fn non_final_and_removed_surfaces_do_not_inherit_privileged_claims() {
        for surface in COMMAND_SURFACES.iter().filter(|surface| {
            matches!(
                surface.class,
                CommandClass::Prototype
                    | CommandClass::DevelopmentDiagnostic
                    | CommandClass::RemovedOrUnsupported
            )
        }) {
            assert_eq!(
                command_admission(surface.path),
                Some(CommandAdmission::Unguarded),
                "{} should stay explicitly unguarded rather than borrowing privileged/public claims",
                surface.path
            );
        }
    }

    #[test]
    fn command_surface_authority_table_carries_registry_and_admission_facts() {
        let table = command_surface_authority_table();
        assert!(table.contains("| Command | Class | Routing | Admission | Help | Summary |"));

        for surface in COMMAND_SURFACES {
            assert!(
                table.contains(surface.path),
                "authority table missing command {}",
                surface.path
            );
            assert!(
                table.contains(surface.class.label()),
                "authority table missing class {}",
                surface.class.label()
            );
            assert!(
                table.contains(surface.routing.label()),
                "authority table missing routing {}",
                surface.routing.label()
            );
            let admission = command_admission(surface.path).expect("admission decision");
            assert!(
                table.contains(admission.label()),
                "authority table missing admission {}",
                admission.label()
            );
            assert!(
                table.contains(surface.summary),
                "authority table missing summary for {}",
                surface.path
            );
        }
    }

    #[test]
    fn operator_authz_boundary_contains_exact_command_authority_table() {
        let doc_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/security/operator-authz-boundary.md");
        let doc = std::fs::read_to_string(&doc_path).expect("read operator authz boundary doc");
        let table = command_surface_authority_table();

        assert!(
            doc.contains(&table),
            "operator authz boundary doc must carry the exact command registry/admission table"
        );
    }
}
