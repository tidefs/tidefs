//! Command classification authority for `tidefsctl`.
//!
//! This module is the single source of truth for the public/operator,
//! harness, diagnostic, prototype, and removed command surfaces. Help text,
//! docs, and claim gates must either consume this registry or check their
//! wording against it.

use std::fmt;

pub(crate) const COMMAND_CLASSIFICATION_DOC_MARKER: &str = "tidefsctl-command-classification-v1";
pub(crate) const COMMAND_CLASSIFICATION_SOURCE_PATH: &str =
    "apps/tidefsctl/src/commands/classification.rs";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandClass {
    PublicOperator,
    UserspaceHarness,
    OperatorDiagnostic,
    Prototype,
    DevelopmentDiagnostic,
    RemovedOrUnsupported,
}

impl CommandClass {
    const HELP_ORDER: [Self; 5] = [
        Self::PublicOperator,
        Self::UserspaceHarness,
        Self::OperatorDiagnostic,
        Self::Prototype,
        Self::DevelopmentDiagnostic,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::PublicOperator => "public-operator",
            Self::UserspaceHarness => "userspace-harness",
            Self::OperatorDiagnostic => "operator-diagnostic",
            Self::Prototype => "prototype",
            Self::DevelopmentDiagnostic => "development-diagnostic",
            Self::RemovedOrUnsupported => "removed-or-unsupported",
        }
    }

    const fn heading(self) -> &'static str {
        match self {
            Self::PublicOperator => "Public operator commands",
            Self::UserspaceHarness => "Userspace harnesses",
            Self::OperatorDiagnostic => "Diagnostics",
            Self::Prototype => "Prototype surfaces",
            Self::DevelopmentDiagnostic => "Development diagnostics",
            Self::RemovedOrUnsupported => "Removed or unsupported surfaces",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RoutingSemantics {
    NoLivePoolState,
    LiveOwner,
    LiveOwnerOrOfflineInput,
    OfflineDiscoveryOrImportInput,
    UserspaceHarness,
    PassiveDiagnostic,
    PrototypeOnly,
    DevelopmentExercise,
    Removed,
}

impl RoutingSemantics {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NoLivePoolState => "no-live-pool-state",
            Self::LiveOwner => "live-owner",
            Self::LiveOwnerOrOfflineInput => "live-owner-or-offline-input",
            Self::OfflineDiscoveryOrImportInput => "offline-discovery-or-import-input",
            Self::UserspaceHarness => "userspace-harness",
            Self::PassiveDiagnostic => "passive-diagnostic",
            Self::PrototypeOnly => "prototype-only",
            Self::DevelopmentExercise => "development-exercise",
            Self::Removed => "removed",
        }
    }
}

impl fmt::Display for RoutingSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}


/// Authority source for a reported status fact.
///
/// Every status fact emitted by `tidefsctl cluster status` or
/// `tidefsctl device status` must carry one of these classifications
/// so operators can distinguish live evidence from cached or
/// unavailable data.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StatusSource {
    /// Fact obtained directly from a reachable live owner (kernel,
    /// FUSE daemon, or ublk runtime).
    LiveOwner,
    /// Fact read from a kernel UAPI control surface.
    KernelUapi,
    /// Fact obtained from a running userspace daemon endpoint.
    UserspaceDaemon,
    /// Fact read from cached local metadata that is not a live
    /// runtime interface; non-authoritative for current cluster or
    /// device state.
    CachedLocalMetadata,
    /// Fact derived from command-line arguments; not cluster or
    /// device authority.
    CommandLineParse,
    /// Fact sourced from a static configuration file or embedded
    /// default; not live state evidence.
    StaticConfiguration,
    /// Fact is an unsupported or offline placeholder; no live
    /// evidence was obtained and the reported data is not
    /// authoritative.
    UnsupportedOrOffline,
}

impl StatusSource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::LiveOwner => "source:live-owner",
            Self::KernelUapi => "source:kernel-uapi",
            Self::UserspaceDaemon => "source:userspace-daemon",
            Self::CachedLocalMetadata => "source:cached-local-metadata",
            Self::CommandLineParse => "source:command-line-parse",
            Self::StaticConfiguration => "source:static-configuration",
            Self::UnsupportedOrOffline => "source:unsupported-or-offline",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommandSurface {
    pub(crate) path: &'static str,
    pub(crate) class: CommandClass,
    pub(crate) routing: RoutingSemantics,
    pub(crate) summary: &'static str,
}

impl CommandSurface {
    pub(crate) const fn visible_in_root_help(self) -> bool {
        !matches!(self.class, CommandClass::RemovedOrUnsupported)
    }
}

pub(crate) const COMMAND_SURFACES: &[CommandSurface] = &[
    CommandSurface {
        path: "pool create",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::OfflineDiscoveryOrImportInput,
        summary: "create an exported pool from explicit byte-addressable devices",
    },
    CommandSurface {
        path: "pool scan",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::OfflineDiscoveryOrImportInput,
        summary: "scan explicit devices for pool labels",
    },
    CommandSurface {
        path: "pool status",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "query the live owner by pool name, or scan explicit offline devices",
    },
    CommandSurface {
        path: "pool import",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "request owner-mediated import; explicit devices are import inputs",
    },
    CommandSurface {
        path: "pool export",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "export through the live owner, or operate on exported explicit devices",
    },
    CommandSurface {
        path: "pool destroy",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "destroy through the live owner, or operate on exported explicit devices",
    },
    CommandSurface {
        path: "pool get",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "read pool properties through owner authority or explicit offline devices",
    },
    CommandSurface {
        path: "pool set",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "set pool properties through owner authority or explicit offline devices",
    },
    CommandSurface {
        path: "pool list-props",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "list pool property definitions and effective values",
    },
    CommandSurface {
        path: "snapshot create",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "create snapshots through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot list",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary:
            "list local snapshot catalog entries with kind, origin, hold, and generation metadata",
    },
    CommandSurface {
        path: "snapshot clone create",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "create local snapshot clones through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot clone delete",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "delete local snapshot clones through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot clone promote",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "promote local snapshot clones through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot bookmark create",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary:
            "create local snapshot bookmarks through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot bookmark delete",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary:
            "delete local snapshot bookmarks through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot hold",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "place local deletion-prevention holds on snapshots or clones",
    },
    CommandSurface {
        path: "snapshot release",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "release local deletion-prevention holds on snapshots or clones",
    },
    CommandSurface {
        path: "snapshot holds",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "inspect local snapshot and clone hold counts",
    },
    CommandSurface {
        path: "snapshot prune",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary:
            "prune regular local snapshots by retention policy while excluding clones and bookmarks",
    },
    CommandSurface {
        path: "snapshot destroy",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "destroy snapshots through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot rollback",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "roll back through the live owner or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot send",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "export snapshot streams through owner authority or explicit offline devices",
    },
    CommandSurface {
        path: "snapshot receive",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwner,
        summary: "receive snapshot streams through the live owner; offline receive is unsupported",
    },
    CommandSurface {
        path: "device remove",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwner,
        summary: "route device evacuation/removal through live placement and refcount authority",
    },
    CommandSurface {
        path: "device status",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwner,
        summary: "query live device status through the live owner; fail closed when no live owner is reachable",
    },
    CommandSurface {
        path: "defrag",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::NoLivePoolState,
        summary: "request online extent-map defragmentation for a path",
    },
    CommandSurface {
        path: "block attach",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwner,
        summary: "attach an imported pool as a ublk block device through owner authority",
    },
    CommandSurface {
        path: "block detach",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::NoLivePoolState,
        summary: "detach an existing ublk device by numeric id",
    },
    CommandSurface {
        path: "block list",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::NoLivePoolState,
        summary: "list attached ublk devices",
    },
    CommandSurface {
        path: "block send",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwner,
        summary: "send block-volume state through live owner and transport authority",
    },
    CommandSurface {
        path: "block receive",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwner,
        summary: "receive block-volume state through live owner and transport authority",
    },
    CommandSurface {
        path: "dataset create",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "create catalog-backed datasets through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset list",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "list catalog-backed datasets through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset destroy",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "destroy catalog entries through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset rename",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "rename catalog entries through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset set-strategy",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "set dataset feature strategy through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset seal-key",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "seal dataset keys through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset rotate-key",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "rotate dataset wrapping keys through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset upgrade",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "enable supported dataset features through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset get",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "read dataset properties through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset set",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "set dataset properties through owner authority or explicit devices",
    },
    CommandSurface {
        path: "dataset list-props",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "list dataset property definitions and effective values",
    },
    CommandSurface {
        path: "mount",
        class: CommandClass::UserspaceHarness,
        routing: RoutingSemantics::UserspaceHarness,
        summary: "launch the current direct FUSE development harness",
    },
    CommandSurface {
        path: "pool mount",
        class: CommandClass::UserspaceHarness,
        routing: RoutingSemantics::UserspaceHarness,
        summary: "import explicit devices and launch the current FUSE owner harness",
    },
    CommandSurface {
        path: "pool integrity-check",
        class: CommandClass::OperatorDiagnostic,
        routing: RoutingSemantics::LiveOwnerOrOfflineInput,
        summary: "run live-owner or explicit-device integrity diagnostics",
    },
    CommandSurface {
        path: "kernel status",
        class: CommandClass::OperatorDiagnostic,
        routing: RoutingSemantics::PassiveDiagnostic,
        summary: "passively inspect the declared kernel control endpoint",
    },
    CommandSurface {
        path: "diag",
        class: CommandClass::OperatorDiagnostic,
        routing: RoutingSemantics::PassiveDiagnostic,
        summary: "collect a redacted diagnostic support bundle",
    },
    CommandSurface {
        path: "cluster pool create",
        class: CommandClass::Prototype,
        routing: RoutingSemantics::PrototypeOnly,
        summary: "prototype clustered pool creation; not final distributed operator UAPI",
    },
    CommandSurface {
        path: "cluster placement exercise",
        class: CommandClass::DevelopmentDiagnostic,
        routing: RoutingSemantics::DevelopmentExercise,
        summary: "development diagnostic exercise for placement-map code",
    },
    CommandSurface {
        path: "cluster heal exercise",
        class: CommandClass::DevelopmentDiagnostic,
        routing: RoutingSemantics::DevelopmentExercise,
        summary: "development diagnostic exercise for placement-heal code",
    },
    CommandSurface {
        path: "cluster status",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::LiveOwner,
        summary: "query live cluster status through the live owner; fail closed when no live owner is reachable",
    },
    CommandSurface {
        path: "pool list",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary:
            "no authoritative pool registry exists; use pool scan --devices or pool status <pool>",
    },
    CommandSurface {
        path: "device rebuild",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary:
            "offline directory object-store rebuild is retired; use live pool repair authority",
    },
    CommandSurface {
        path: "directory-backed pool media",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary: "directory object-store pool media is retired for operator pool commands",
    },
    CommandSurface {
        path: "pool integrity-check --backing-dir",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary:
            "directory object-store integrity scan mode is retired; use --devices or live owner",
    },
    CommandSurface {
        path: "snapshot --backing-dir",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary: "directory object-store snapshot mode is retired",
    },
    CommandSurface {
        path: "block --backing-dir",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary: "directory object-store block-volume mode is retired",
    },
    CommandSurface {
        path: "device remove --backing-dir",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary: "offline directory device removal is retired",
    },
    CommandSurface {
        path: "device remove --surviving-dirs",
        class: CommandClass::RemovedOrUnsupported,
        routing: RoutingSemantics::Removed,
        summary: "offline directory survivor-device removal is retired",
    },
];

pub(crate) fn find_surface(path: &str) -> Option<&'static CommandSurface> {
    COMMAND_SURFACES.iter().find(|surface| surface.path == path)
}

pub(crate) fn removed_surface_error(path: &str) -> String {
    match find_surface(path) {
        Some(surface) if surface.class == CommandClass::RemovedOrUnsupported => format!(
            "tidefsctl {path}: removed or unsupported command surface; {}",
            surface.summary
        ),
        Some(surface) => format!(
            "tidefsctl {path}: command is classified as {}; refusing removed-surface error generation",
            surface.class.label()
        ),
        None => format!("tidefsctl {path}: unknown command surface"),
    }
}

pub(crate) fn root_long_about() -> String {
    let mut out = String::from(
        "TideFS command-line interface.\n\n\
         Command classification source of truth: ",
    );
    out.push_str(COMMAND_CLASSIFICATION_SOURCE_PATH);
    out.push_str(" (");
    out.push_str(COMMAND_CLASSIFICATION_DOC_MARKER);
    out.push_str(").\n\n");

    for class in CommandClass::HELP_ORDER {
        push_help_section(&mut out, class);
    }

    out.push_str(
        "Pool routing rule:\n  A pool name identifies an imported pool. Imported state is cached and must\n  be queried or changed through the live owner: the kernel UAPI in kernel\n  mode, or the userspace daemon owner in userspace mode. Explicit --devices,\n  --backing-dir, and similar inputs are for offline, discovery, import, or\n  not-yet-imported work; they are not overrides for an imported pool.\n  Directory object-store backing is not pool media.\n\n\
         Removed/unsupported surfaces are hidden from command help and fail closed.\n\n\
         TideFS is pre-alpha. Help text marks harnesses and prototypes instead of\n  treating them as final kernel or distributed operator UAPI.",
    );

    out
}

fn push_help_section(out: &mut String, class: CommandClass) {
    out.push_str(class.heading());
    out.push_str(":\n");
    for surface in COMMAND_SURFACES
        .iter()
        .filter(|surface| surface.class == class && surface.visible_in_root_help())
    {
        out.push_str("  ");
        out.push_str(surface.path);
        out.push_str(" [");
        out.push_str(surface.routing.label());
        out.push_str("] - ");
        out.push_str(surface.summary);
        out.push('\n');
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_surface_paths_are_unique() {
        for (index, surface) in COMMAND_SURFACES.iter().enumerate() {
            assert!(
                COMMAND_SURFACES
                    .iter()
                    .skip(index + 1)
                    .all(|other| other.path != surface.path),
                "duplicate command classification path {}",
                surface.path
            );
        }
    }

    #[test]
    fn classification_covers_required_stability_classes() {
        for class in [
            CommandClass::PublicOperator,
            CommandClass::UserspaceHarness,
            CommandClass::OperatorDiagnostic,
            CommandClass::Prototype,
            CommandClass::DevelopmentDiagnostic,
            CommandClass::RemovedOrUnsupported,
        ] {
            assert!(
                COMMAND_SURFACES
                    .iter()
                    .any(|surface| surface.class == class),
                "missing classification class {}",
                class.label()
            );
        }
    }

    #[test]
    fn cluster_exercises_are_not_public_operator_uapi() {
        for path in ["cluster placement exercise", "cluster heal exercise"] {
            let surface = find_surface(path).expect("classified cluster exercise");
            assert_eq!(surface.class, CommandClass::DevelopmentDiagnostic);
            assert_eq!(surface.routing, RoutingSemantics::DevelopmentExercise);
            assert!(
                surface.summary.contains("development diagnostic"),
                "exercise summary should stay diagnostic: {}",
                surface.summary
            );
        }

        let cluster_create = find_surface("cluster pool create").expect("cluster pool classified");
        assert_eq!(cluster_create.class, CommandClass::Prototype);
        assert!(
            cluster_create
                .summary
                .contains("not final distributed operator UAPI"),
            "cluster pool create must not claim final distributed UAPI"
        );
    }

    #[test]
    fn imported_pool_commands_keep_live_owner_routing_classification() {
        for path in [
            "pool status",
            "pool export",
            "pool destroy",
            "pool get",
            "pool set",
            "pool list-props",
            "dataset create",
            "snapshot create",
            "snapshot clone create",
            "snapshot bookmark create",
            "snapshot prune",
            "device remove",
            "block attach",
        ] {
            let surface = find_surface(path).expect("classified imported-pool command");
            assert!(
                matches!(
                    surface.routing,
                    RoutingSemantics::LiveOwner | RoutingSemantics::LiveOwnerOrOfflineInput
                ),
                "{path} must route imported pools through the live owner, got {}",
                surface.routing
            );
        }
    }

    #[test]
    fn snapshot_receive_classification_is_live_owner_only() {
        let surface = find_surface("snapshot receive").expect("snapshot receive classified");
        assert_eq!(surface.routing, RoutingSemantics::LiveOwner);
        assert!(surface.summary.contains("live owner"));
        assert!(surface.summary.contains("offline receive is unsupported"));
        assert!(!surface.summary.contains("explicit offline devices"));
    }

    #[test]
    fn removed_surfaces_are_classified_and_error_clearly() {
        for path in [
            "pool list",
            "device rebuild",
            "directory-backed pool media",
            "pool integrity-check --backing-dir",
        ] {
            let surface = find_surface(path).expect("classified removed surface");
            assert_eq!(surface.class, CommandClass::RemovedOrUnsupported);
            assert_eq!(surface.routing, RoutingSemantics::Removed);
            let error = removed_surface_error(path);
            assert!(error.contains("removed or unsupported"));
            assert!(error.contains(surface.summary));
        }
    }

    #[test]
    fn root_long_help_is_generated_from_classification() {
        let help = root_long_about();
        assert!(help.contains(COMMAND_CLASSIFICATION_SOURCE_PATH));
        assert!(help.contains(COMMAND_CLASSIFICATION_DOC_MARKER));

        for surface in COMMAND_SURFACES
            .iter()
            .filter(|surface| surface.visible_in_root_help())
        {
            assert!(
                help.contains(surface.path),
                "root help missing classified command {}",
                surface.path
            );
            assert!(
                help.contains(surface.routing.label()),
                "root help missing routing label {}",
                surface.routing.label()
            );
        }

        assert!(!help.contains("pool list [removed]"));
        assert!(!help.contains("device rebuild [removed]"));
    }

    // -- StatusSource tests --

    #[test]
    fn status_source_labels_are_distinct_and_stable() {
        use super::StatusSource;
        let sources = [
            (StatusSource::LiveOwner, "source:live-owner"),
            (StatusSource::KernelUapi, "source:kernel-uapi"),
            (StatusSource::UserspaceDaemon, "source:userspace-daemon"),
            (StatusSource::CachedLocalMetadata, "source:cached-local-metadata"),
            (StatusSource::CommandLineParse, "source:command-line-parse"),
            (StatusSource::StaticConfiguration, "source:static-configuration"),
            (StatusSource::UnsupportedOrOffline, "source:unsupported-or-offline"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (source, label) in &sources {
            assert_eq!(source.label(), *label, "StatusSource label mismatch");
            assert!(seen.insert(*label), "duplicate StatusSource label: {}", label);
        }
        assert_eq!(seen.len(), sources.len(), "all StatusSource labels must be covered");
    }

    #[test]
    fn cluster_and_device_status_are_classified_as_public_operator_live_owner() {
        for path in ["cluster status", "device status"] {
            let surface = super::find_surface(path)
                .unwrap_or_else(|| panic!("classified command surface for {path}"));
            assert_eq!(surface.class, super::CommandClass::PublicOperator,
                "{path} must be public-operator");
            assert_eq!(surface.routing, super::RoutingSemantics::LiveOwner,
                "{path} must route through live owner");
            assert!(surface.summary.contains("fail closed"),
                "{path} summary must state fail-closed behavior");
        }
    }

    #[test]
    fn status_commands_appear_in_root_help() {
        let help = super::root_long_about();
        for path in ["cluster status", "device status"] {
            assert!(help.contains(path),
                "root help must include classified command {path}");
        }
    }

}
