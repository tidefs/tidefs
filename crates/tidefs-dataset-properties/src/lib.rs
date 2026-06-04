#![forbid(unsafe_code)]

//! Per-dataset unified property framework.
//!
//! Provides a hierarchical property system where datasets inherit properties
//! from parents, can override them, and property changes are validated.
//! The runtime registry (via [`build_registry`]) defines all known properties
//! with their types, defaults, inheritance mode, and validation rules.
//!

//!
//! ## Authority boundary (non-claim)
//!
//! The `compression.algorithm` property registered in this crate is a
//! **property-library surface** — it defines metadata, types, defaults,
//! and inheritance rules for the unified property framework.  It does **not**
//! directly drive mounted content writes.
//!
//! The **live mounted-write compression authority** is:
//!
//! ```text
//! resolve_compression_policy(FeatureFlags)  [tidefs-local-filesystem/src/lib.rs]
//!   -> ContentCompressionPolicy
//!   -> encode_content_chunk                  [encoding.rs]
//! ```
//!
//! The property registry and the feature-flag system are separate layers.
//! Do not use the presence of `compression.algorithm` in this crate as
//! validation that per-dataset compression policy is wired into mounted
//! content writes.
//!
//! # Key types
//!
//! - [`PropertyType`] — wire-type discriminant for property values.
//! - [`PropertyValue`] — tagged union for property value storage.
//! - [`InheritanceMode`] — controls parent-chain walk semantics.
//! - [`ChangePolicy`] — when a property change takes effect.
//! - [`PropertySource`] — whether a value is Local, Inherited, or Default.
//! - [`PropertySet`] — per-dataset BTreeMap of property entries.
//! - [`PropertyDefinitionV1`] — compile-time registry entry.
//! - [`resolve_effective`] — walk the parent chain to resolve a property value.
//! - [`validate_set`] — check a proposed value against the registry and constraints.

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// PropertyType — wire-type discriminant
// ---------------------------------------------------------------------------

/// Wire-type discriminant for property values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum PropertyType {
    /// Unsigned 64-bit integer (quota, recordsize, limits).
    U64 = 0x01,
    /// Signed 64-bit integer (reservation deltas).
    I64 = 0x02,
    /// Variable-length UTF-8 string (compression algorithm name, key location).
    String = 0x03,
    /// Boolean (readonly, dedup, atime).
    Bool = 0x04,
    /// Enumeration from a fixed set (checksum, acltype, xattr).
    Enum = 0x05,
    /// Opaque byte array (key-format raw bytes).
    Bytes = 0x06,
    /// Human-readable size with suffix, stored as u64 bytes internally.
    Size = 0x07,
}

impl PropertyType {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            PropertyType::U64 => "u64",
            PropertyType::I64 => "i64",
            PropertyType::String => "string",
            PropertyType::Bool => "bool",
            PropertyType::Enum => "enum",
            PropertyType::Bytes => "bytes",
            PropertyType::Size => "size",
        }
    }
}

// ---------------------------------------------------------------------------
// PropertyValue — tagged union for values
// ---------------------------------------------------------------------------

/// Tagged union for property values stored in a [`PropertySet`].
///
/// The `None` variant means the property is not locally set.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum PropertyValue {
    /// Property not set locally; inherits or uses default.
    #[default]
    None,
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Signed 64-bit integer.
    I64(i64),
    /// UTF-8 string (up to 255 bytes per design spec).
    String(String),
    /// Boolean.
    Bool(bool),
    /// Index into an enum's variant list.
    EnumVariant(u8),
    /// Opaque byte array (up to 1024 bytes per design spec).
    Bytes(Vec<u8>),
    /// Size in bytes (stored as u64).
    Size(u64),
}

impl PropertyValue {
    /// Return the [`PropertyType`] discriminant for this value.
    #[must_use]
    pub fn property_type(&self) -> PropertyType {
        match self {
            PropertyValue::None => PropertyType::U64, // fallback
            PropertyValue::U64(_) => PropertyType::U64,
            PropertyValue::I64(_) => PropertyType::I64,
            PropertyValue::String(_) => PropertyType::String,
            PropertyValue::Bool(_) => PropertyType::Bool,
            PropertyValue::EnumVariant(_) => PropertyType::Enum,
            PropertyValue::Bytes(_) => PropertyType::Bytes,
            PropertyValue::Size(_) => PropertyType::Size,
        }
    }

    /// Whether this value represents "not set".
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, PropertyValue::None)
    }

    /// Whether this value is a concrete (non-None) value.
    #[must_use]
    pub const fn is_some(&self) -> bool {
        !self.is_none()
    }
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertyValue::None => write!(f, "-"),
            PropertyValue::U64(v) => write!(f, "{v}"),
            PropertyValue::I64(v) => write!(f, "{v}"),
            PropertyValue::String(v) => write!(f, "{v}"),
            PropertyValue::Bool(v) => {
                if *v {
                    write!(f, "on")
                } else {
                    write!(f, "off")
                }
            }
            PropertyValue::EnumVariant(v) => write!(f, "variant({v})"),
            PropertyValue::Bytes(v) => write!(f, "{v:?}"),
            PropertyValue::Size(v) => write!(f, "{v}"),
        }
    }
}

// ---------------------------------------------------------------------------
// InheritanceMode
// ---------------------------------------------------------------------------

/// Controls how a property inherits from ancestor datasets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum InheritanceMode {
    /// Property is local-only; never inherits from parent.
    None_ = 0x00,
    /// Inherits from parent dataset if not locally set.
    Parent = 0x01,
    /// Inherits from send/recv source (for replication scenarios).
    ParentReceived = 0x02,
}

// ---------------------------------------------------------------------------
// ChangePolicy
// ---------------------------------------------------------------------------

/// When a property change takes effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum ChangePolicy {
    /// Property can be changed any time, takes effect immediately.
    Always = 0x00,
    /// Only settable when dataset is read-only or at creation.
    ReadonlyDataset = 0x01,
    /// Change takes effect at the next commit-group boundary.
    CommitGroupBoundary = 0x02,
}

// ---------------------------------------------------------------------------
// PropertyScope — dataset vs directory scope
// ---------------------------------------------------------------------------

/// Whether a property applies at dataset or directory granularity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum PropertyScope {
    /// Property applies to a dataset anchor (most properties).
    Dataset = 0x00,
    /// Property applies to a directory within a dataset.
    Directory = 0x01,
}

// ---------------------------------------------------------------------------
// PropertyFamily — logical grouping for presentation
// ---------------------------------------------------------------------------

/// Logical family for grouping related properties in CLI output and docs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum PropertyFamily {
    Compression = 0x00,
    Encryption = 0x01,
    Space = 0x02,
    Layout = 0x03,
    Integrity = 0x04,
    Access = 0x05,
    Performance = 0x06,
    Snapshot = 0x07,
}

impl PropertyFamily {
    /// Return the registry key prefix for this family.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            PropertyFamily::Compression => "compression.",
            PropertyFamily::Encryption => "encryption.",
            PropertyFamily::Space => "space.",
            PropertyFamily::Layout => "layout.",
            PropertyFamily::Integrity => "integrity.",
            PropertyFamily::Access => "access.",
            PropertyFamily::Performance => "perf.",
            PropertyFamily::Snapshot => "snapshot.",
        }
    }

    /// Return a human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            PropertyFamily::Compression => "Compression",
            PropertyFamily::Encryption => "Encryption",
            PropertyFamily::Space => "Space",
            PropertyFamily::Layout => "Layout",
            PropertyFamily::Integrity => "Integrity",
            PropertyFamily::Access => "Access",
            PropertyFamily::Performance => "Performance",
            PropertyFamily::Snapshot => "Snapshot",
        }
    }
}

// ---------------------------------------------------------------------------
// PropertySource — provenance of a property value
// ---------------------------------------------------------------------------

/// Tracks where a property value came from.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PropertySource {
    /// Value was explicitly set on this dataset.
    Local,
    /// Value was inherited from a parent dataset.
    Inherited { parent_dataset_id: u64 },
    /// Value is the compile-time registry default.
    Default,
}

impl PropertySource {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            PropertySource::Local => "local",
            PropertySource::Inherited { .. } => "inherited from parent",
            PropertySource::Default => "default",
        }
    }
}

impl fmt::Display for PropertySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertySource::Local => write!(f, "local"),
            PropertySource::Inherited { parent_dataset_id } => {
                write!(f, "inherited from {parent_dataset_id}")
            }
            PropertySource::Default => write!(f, "default"),
        }
    }
}

// ---------------------------------------------------------------------------
// PropertyKey — property name
// ---------------------------------------------------------------------------

/// A property name stored as a dot-separated hierarchical string.
///
/// Maximum length is 127 bytes per the design spec.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PropertyKey {
    name: String,
}

impl PropertyKey {
    /// Maximum length of a property name in bytes.
    pub const MAX_LEN: usize = 127;

    /// Create a new `PropertyKey` from a string.
    ///
    /// # Panics
    /// Panics if the name exceeds [`MAX_LEN`] bytes or is empty.
    #[must_use]
    pub fn new(name: &str) -> Self {
        assert!(!name.is_empty(), "property name must not be empty");
        assert!(
            name.len() <= Self::MAX_LEN,
            "property name exceeds max length of {} bytes",
            Self::MAX_LEN
        );
        PropertyKey {
            name: String::from(name),
        }
    }

    /// Return the property name as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.name.len()
    }

    /// Whether the key is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
    }
}

impl fmt::Debug for PropertyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PropertyKey(\"{}\")", self.name)
    }
}

impl fmt::Display for PropertyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// PropertyEntryV1 — entry in a PropertySet
// ---------------------------------------------------------------------------

/// A single property entry in a dataset's [`PropertySet`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertyEntryV1 {
    /// The effective value.
    pub value: PropertyValue,
    /// Where this value came from.
    pub source: PropertySource,
}

impl PropertyEntryV1 {
    /// Create a new entry with a local value.
    #[must_use]
    pub fn local(value: PropertyValue) -> Self {
        PropertyEntryV1 {
            value,
            source: PropertySource::Local,
        }
    }

    /// Create a new entry with an inherited value.
    #[must_use]
    pub fn inherited(value: PropertyValue, parent_dataset_id: u64) -> Self {
        PropertyEntryV1 {
            value,
            source: PropertySource::Inherited { parent_dataset_id },
        }
    }

    /// Create a new entry with the registry default.
    #[must_use]
    pub fn default_value(value: PropertyValue) -> Self {
        PropertyEntryV1 {
            value,
            source: PropertySource::Default,
        }
    }
}

// ---------------------------------------------------------------------------
// PropertySet — per-dataset property collection
// ---------------------------------------------------------------------------

/// A per-dataset collection of properties backed by a [`BTreeMap`].
#[derive(Clone, Debug, Default)]
pub struct PropertySet {
    entries: BTreeMap<PropertyKey, PropertyEntryV1>,
}

impl PropertySet {
    /// Create an empty property set.
    #[must_use]
    pub fn new() -> Self {
        PropertySet {
            entries: BTreeMap::new(),
        }
    }

    /// Set a local property value (override).
    pub fn set_local(&mut self, key: PropertyKey, value: PropertyValue) {
        self.entries.insert(key, PropertyEntryV1::local(value));
    }

    /// Set a property with an explicit source.
    pub fn set_with_source(
        &mut self,
        key: PropertyKey,
        value: PropertyValue,
        source: PropertySource,
    ) {
        self.entries.insert(key, PropertyEntryV1 { value, source });
    }

    /// Get a property entry by key.
    #[must_use]
    pub fn get(&self, key: &PropertyKey) -> Option<&PropertyEntryV1> {
        self.entries.get(key)
    }

    /// Get the locally-set value for a property (only if source is Local).
    #[must_use]
    pub fn get_local(&self, key: &PropertyKey) -> Option<&PropertyValue> {
        self.entries.get(key).and_then(|e| {
            if matches!(e.source, PropertySource::Local) {
                Some(&e.value)
            } else {
                None
            }
        })
    }

    /// Remove a local override, reverting to inheritance.
    ///
    /// Returns the removed entry if it was a local override.
    pub fn remove_local_override(&mut self, key: &PropertyKey) -> Option<PropertyEntryV1> {
        if let Some(entry) = self.entries.get(key) {
            if matches!(entry.source, PropertySource::Local) {
                return self.entries.remove(key);
            }
        }
        None
    }

    /// Check if a property has a local override.
    #[must_use]
    pub fn has_local_override(&self, key: &PropertyKey) -> bool {
        self.entries
            .get(key)
            .is_some_and(|e| matches!(e.source, PropertySource::Local))
    }

    /// Number of entries in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&PropertyKey, &PropertyEntryV1)> {
        self.entries.iter()
    }

    /// List all properties with source annotations.
    #[must_use]
    pub fn list(&self) -> Vec<(PropertyKey, PropertyEntryV1)> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    // ------------------------------------------------------------------
    // Key-value blob serialization for catalog persistence
    // ------------------------------------------------------------------

    /// Serialize local overrides into a `key=value\n` blob for storage in
    /// `CatalogEntry.properties`. Only entries with `PropertySource::Local`
    /// are written; inherited and default entries are discarded.
    ///
    /// The output is sorted by key for deterministic ordering.
    #[must_use]
    pub fn to_key_value_blob(&self) -> Vec<u8> {
        let mut pairs: Vec<(&PropertyKey, &PropertyEntryV1)> = self
            .entries
            .iter()
            .filter(|(_, e)| matches!(e.source, PropertySource::Local))
            .collect();
        // Sort by key for deterministic output.
        pairs.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));

        let mut out = Vec::new();
        for (key, entry) in &pairs {
            out.extend_from_slice(key.as_str().as_bytes());
            out.push(b'=');
            let val_str = entry.value.to_string();
            out.extend_from_slice(val_str.as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// Deserialize a `key=value\n` blob (as stored in `CatalogEntry.properties`)
    /// into a `PropertySet` with all entries marked as `PropertySource::Local`.
    ///
    /// Lines that cannot be parsed as `key=value` are silently skipped.
    /// Empty keys are ignored.
    #[must_use]
    pub fn from_key_value_blob(blob: &[u8]) -> Self {
        let mut set = PropertySet::new();
        for line in blob.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            if let Ok(s) = core::str::from_utf8(line) {
                if let Some((k, v)) = s.split_once('=') {
                    let k = k.trim();
                    let v = v.trim();
                    if k.is_empty() {
                        continue;
                    }
                    let key = PropertyKey::new(k);
                    let value = Self::parse_value_from_str(v);
                    set.set_local(key, value);
                }
            }
        }
        set
    }

    /// Best-effort parse a string into a `PropertyValue`.
    ///
    /// The blob format stores values as their Display representation, so
    /// we guess the type heuristically. The caller should validate the
    /// parsed value against the registry's `PropertyDefinitionV1` before
    /// relying on it.
    #[must_use]
    pub fn parse_value_from_str(s: &str) -> PropertyValue {
        // Boolean: "on" or "off"
        if s.eq_ignore_ascii_case("on") {
            return PropertyValue::Bool(true);
        }
        if s.eq_ignore_ascii_case("off") {
            return PropertyValue::Bool(false);
        }
        // Numeric: try u64 then i64
        if let Ok(n) = s.parse::<u64>() {
            return PropertyValue::U64(n);
        }
        if let Ok(n) = s.parse::<i64>() {
            return PropertyValue::I64(n);
        }
        // Fallback: string
        PropertyValue::String(s.to_string())
    }
}

// ---------------------------------------------------------------------------
// Cross-property validation types
// ---------------------------------------------------------------------------

/// A cross-property constraint: one property's value gates another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossPropertyPredicate {
    /// Property name that must satisfy the requirement.
    pub property_name: PropertyKey,
    /// What the property must satisfy.
    pub requirement: CrossPropertyRequirement,
    /// Human-readable error message.
    pub error_message: &'static str,
}

/// What a cross-property check requires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossPropertyRequirement {
    /// The target property must not be in this state.
    MustNotBe(PropertyValueDiscriminant),
    /// The target property must equal this value.
    MustEqual(PropertyValueDiscriminant),
}

/// A lightweight discriminant for matching without full value comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyValueDiscriminant {
    None,
    Bool(bool),
    AnyValue,
}

/// Validation error returned when a property set fails validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// Value is out of the allowed range.
    Range {
        property: PropertyKey,
        value: u64,
        min: u64,
        max: u64,
    },
    /// A cross-property constraint failed.
    CrossProperty {
        property: PropertyKey,
        depends_on: PropertyKey,
        message: &'static str,
    },
    /// Type mismatch.
    TypeMismatch {
        property: PropertyKey,
        expected: PropertyType,
        actual: PropertyType,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Range {
                property,
                value,
                min,
                max,
            } => {
                write!(f, "{property}: value {value} out of range [{min}, {max}]")
            }
            ValidationError::CrossProperty {
                property,
                depends_on,
                message,
            } => {
                write!(f, "{property}: {message} (depends on {depends_on})")
            }
            ValidationError::TypeMismatch {
                property,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{property}: type mismatch, expected {}, got {}",
                    expected.label(),
                    actual.label()
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PropertyDefinitionV1 — compile-time registry entry
// ---------------------------------------------------------------------------

/// A compile-time definition for a property in the registry.
#[derive(Clone, Debug)]
pub struct PropertyDefinitionV1 {
    /// Canonical property name.
    pub name: PropertyKey,
    /// Expected value type.
    pub value_type: PropertyType,
    /// Default value when not explicitly set and not inherited.
    pub default_value: PropertyValue,
    /// How this property inherits.
    pub inheritance: InheritanceMode,
    /// When a property change takes effect.
    pub change_policy: ChangePolicy,
    /// Dataset or directory scope.
    pub scope: PropertyScope,
    /// Logical family for presentation grouping.
    pub family: PropertyFamily,
    /// Optional feature flag required to set this property.
    pub feature_flag: Option<&'static str>,
    /// Cross-property constraints.
    pub cross_constraints: Vec<CrossPropertyPredicate>,
    /// Allowed range for numeric types (min, max).
    pub range: Option<(u64, u64)>,
}

impl PropertyDefinitionV1 {
    /// Create a new property definition with no constraints.
    #[must_use]
    pub fn new(
        name: PropertyKey,
        value_type: PropertyType,
        default_value: PropertyValue,
        inheritance: InheritanceMode,
        change_policy: ChangePolicy,
        scope: PropertyScope,
        family: PropertyFamily,
    ) -> Self {
        PropertyDefinitionV1 {
            name,
            value_type,
            default_value,
            inheritance,
            change_policy,
            scope,
            family,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        }
    }
}

// ---------------------------------------------------------------------------
// PropertyInheritance — resolution and propagation
// ---------------------------------------------------------------------------

/// Resolve the effective value of a property for a dataset.
///
/// Resolution order:
/// 1. Local override always wins.
/// 2. For `PARENT` / `PARENT_RECEIVED` mode: walk parent chain.
/// 3. Fall back to the registry default.
///
/// `parent_sets` is ordered from immediate parent to root ancestor.
#[must_use]
pub fn resolve_effective(
    property_key: &PropertyKey,
    local_set: &PropertySet,
    parent_sets: &[&PropertySet],
    def: &PropertyDefinitionV1,
) -> PropertyEntryV1 {
    // 1. Local override always wins.
    if let Some(entry) = local_set.get(property_key) {
        if matches!(entry.source, PropertySource::Local) && entry.value.is_some() {
            return entry.clone();
        }
    }

    // 2. Walk parent chain.
    match def.inheritance {
        InheritanceMode::None_ => PropertyEntryV1::default_value(def.default_value.clone()),
        InheritanceMode::Parent | InheritanceMode::ParentReceived => {
            for (depth, parent) in parent_sets.iter().enumerate() {
                if let Some(entry) = parent.get(property_key) {
                    if entry.value.is_some() {
                        let mut inherited = entry.clone();
                        if matches!(inherited.source, PropertySource::Local) {
                            inherited.source = PropertySource::Inherited {
                                parent_dataset_id: depth as u64,
                            };
                        }
                        return inherited;
                    }
                }
            }
            PropertyEntryV1::default_value(def.default_value.clone())
        }
    }
}

/// Propagate a property change from a parent to a child dataset.
///
/// If the child has a local override, the change is NOT propagated.
pub fn propagate_change(
    property_key: &PropertyKey,
    child_set: &mut PropertySet,
    new_parent_value: &PropertyValue,
    parent_dataset_id: u64,
) {
    if child_set.has_local_override(property_key) {
        return;
    }
    child_set.set_with_source(
        property_key.clone(),
        new_parent_value.clone(),
        PropertySource::Inherited { parent_dataset_id },
    );
}

// ---------------------------------------------------------------------------
// PropertyValidation
// ---------------------------------------------------------------------------

/// Validate a proposed property set operation.
///
/// Checks:
/// 1. Value type matches the property definition.
/// 2. Value is within range (for numeric types).
/// 3. Cross-property constraints are satisfied against the current set.
pub fn validate_set(
    property_key: &PropertyKey,
    proposed_value: &PropertyValue,
    def: &PropertyDefinitionV1,
    current_set: &PropertySet,
) -> Result<(), ValidationError> {
    // Type check (skip for None — it means "clear override").
    if proposed_value.is_some() {
        let actual_type = proposed_value.property_type();
        let type_ok = actual_type == def.value_type
            || matches!(
                (&def.value_type, &actual_type),
                (PropertyType::U64, PropertyType::Size) | (PropertyType::Size, PropertyType::U64)
            );
        if !type_ok {
            return Err(ValidationError::TypeMismatch {
                property: property_key.clone(),
                expected: def.value_type,
                actual: actual_type,
            });
        }
    }

    // Range check for numeric types.
    if let Some((min, max)) = def.range {
        if proposed_value.is_some() {
            let val = match proposed_value {
                PropertyValue::U64(v) | PropertyValue::Size(v) => *v,
                _ => 0,
            };
            if val < min || val > max {
                return Err(ValidationError::Range {
                    property: property_key.clone(),
                    value: val,
                    min,
                    max,
                });
            }
        }
    }

    // Cross-property constraints.
    for constraint in &def.cross_constraints {
        let depends_on_key = &constraint.property_name;
        let dep_value = if depends_on_key == property_key {
            proposed_value
        } else if let Some(entry) = current_set.get(depends_on_key) {
            &entry.value
        } else {
            &PropertyValue::None
        };

        let satisfied = match constraint.requirement {
            CrossPropertyRequirement::MustNotBe(ref disc) => !discriminant_matches(dep_value, disc),
            CrossPropertyRequirement::MustEqual(ref disc) => discriminant_matches(dep_value, disc),
        };

        if !satisfied {
            return Err(ValidationError::CrossProperty {
                property: property_key.clone(),
                depends_on: depends_on_key.clone(),
                message: constraint.error_message,
            });
        }
    }

    Ok(())
}

/// Check whether a property value matches a discriminant.
fn discriminant_matches(value: &PropertyValue, disc: &PropertyValueDiscriminant) -> bool {
    match disc {
        PropertyValueDiscriminant::None => value.is_none(),
        PropertyValueDiscriminant::Bool(expected) => {
            matches!(value, PropertyValue::Bool(v) if v == expected)
        }
        PropertyValueDiscriminant::AnyValue => value.is_some(),
    }
}

// ---------------------------------------------------------------------------
// Property registry
// ---------------------------------------------------------------------------

/// Build the standard property registry.
///
/// Returns a `Vec<PropertyDefinitionV1>` with all standard properties
/// defined in the per-dataset unified property framework design.
#[must_use]
pub fn build_registry() -> Vec<PropertyDefinitionV1> {
    vec![
        // -- Compression family --
        PropertyDefinitionV1 {
            name: PropertyKey::new("compression.algorithm"),
            value_type: PropertyType::String,
            default_value: PropertyValue::None,
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Compression,
            feature_flag: Some("org.tidefs:compression_lz4"),
            cross_constraints: Vec::new(),
            range: None,
        },
        // -- Access family --
        PropertyDefinitionV1 {
            name: PropertyKey::new("access.readonly"),
            value_type: PropertyType::Bool,
            default_value: PropertyValue::Bool(false),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Access,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        },
        PropertyDefinitionV1 {
            name: PropertyKey::new("access.atime"),
            value_type: PropertyType::Bool,
            default_value: PropertyValue::Bool(true),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Access,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        },
        PropertyDefinitionV1 {
            name: PropertyKey::new("access.relatime"),
            value_type: PropertyType::Bool,
            default_value: PropertyValue::Bool(false),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Access,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        },
        PropertyDefinitionV1 {
            name: PropertyKey::new("access.exec"),
            value_type: PropertyType::Bool,
            default_value: PropertyValue::Bool(true),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Access,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        },
        PropertyDefinitionV1 {
            name: PropertyKey::new("access.setuid"),
            value_type: PropertyType::Bool,
            default_value: PropertyValue::Bool(true),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Access,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        },
        // -- Layout family --
        PropertyDefinitionV1 {
            name: PropertyKey::new("layout.recordsize"),
            value_type: PropertyType::Size,
            default_value: PropertyValue::Size(131_072),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::ReadonlyDataset,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Layout,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: Some((512, 1_048_576)),
        },
        // -- Integrity family --
        PropertyDefinitionV1 {
            name: PropertyKey::new("integrity.checksum"),
            value_type: PropertyType::Enum,
            default_value: PropertyValue::EnumVariant(0),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Integrity,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        },
        PropertyDefinitionV1 {
            name: PropertyKey::new("integrity.dedup"),
            value_type: PropertyType::Bool,
            default_value: PropertyValue::Bool(false),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Integrity,
            feature_flag: Some("org.tidefs:dedup"),
            cross_constraints: vec![CrossPropertyPredicate {
                property_name: PropertyKey::new("integrity.checksum"),
                requirement: CrossPropertyRequirement::MustNotBe(PropertyValueDiscriminant::Bool(
                    false,
                )),
                error_message: "dedup requires checksum to be enabled",
            }],
            range: None,
        },
        // -- Space family --
        PropertyDefinitionV1 {
            name: PropertyKey::new("space.quota"),
            value_type: PropertyType::Size,
            default_value: PropertyValue::None,
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Space,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: Some((0, i64::MAX as u64)),
        },
        // -- Snapshot family --
        PropertyDefinitionV1 {
            name: PropertyKey::new("snapshot.retention"),
            value_type: PropertyType::Enum,
            default_value: PropertyValue::EnumVariant(0),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Snapshot,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: None,
        },
    ]
}

/// Look up a property definition in a registry slice.
#[must_use]
pub fn lookup_property<'a>(
    registry: &'a [PropertyDefinitionV1],
    name: &PropertyKey,
) -> Option<&'a PropertyDefinitionV1> {
    registry.iter().find(|def| &def.name == name)
}

/// Filter a registry slice to properties belonging to a specific family.
#[must_use]
pub fn filter_registry_by_family(
    registry: &[PropertyDefinitionV1],
    family: PropertyFamily,
) -> Vec<&PropertyDefinitionV1> {
    registry.iter().filter(|def| def.family == family).collect()
}

/// Infer the [] from a property key prefix.
#[must_use]
pub fn get_family(key: &PropertyKey) -> Option<PropertyFamily> {
    let name = key.as_str();
    if name.starts_with("compression.") {
        Some(PropertyFamily::Compression)
    } else if name.starts_with("encryption.") {
        Some(PropertyFamily::Encryption)
    } else if name.starts_with("space.") {
        Some(PropertyFamily::Space)
    } else if name.starts_with("layout.") {
        Some(PropertyFamily::Layout)
    } else if name.starts_with("integrity.") {
        Some(PropertyFamily::Integrity)
    } else if name.starts_with("access.") {
        Some(PropertyFamily::Access)
    } else if name.starts_with("perf.") {
        Some(PropertyFamily::Performance)
    } else if name.starts_with("snapshot.") {
        Some(PropertyFamily::Snapshot)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── PropertyKey ───────────────────────────────────────────────

    #[test]
    fn property_key_new_and_display() {
        let key = PropertyKey::new("access.readonly");
        assert_eq!(key.as_str(), "access.readonly");
        assert_eq!(key.len(), 15);
        assert!(!key.is_empty());
        assert_eq!(format!("{key}"), "access.readonly");
        assert_eq!(format!("{key:?}"), "PropertyKey(\"access.readonly\")");
    }

    #[test]
    fn property_key_equality() {
        let a = PropertyKey::new("compression.algorithm");
        let b = PropertyKey::new("compression.algorithm");
        let c = PropertyKey::new("access.readonly");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn property_key_ordering() {
        let a = PropertyKey::new("access.readonly");
        let b = PropertyKey::new("compression.algorithm");
        assert!(a < b); // "access" < "compression" lexicographically
    }

    #[test]
    fn property_key_clone() {
        let a = PropertyKey::new("layout.recordsize");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    #[should_panic(expected = "property name must not be empty")]
    fn property_key_empty_panics() {
        let _ = PropertyKey::new("");
    }

    #[test]
    #[should_panic(expected = "property name exceeds max length")]
    fn property_key_too_long_panics() {
        let long = "x".repeat(128);
        let _ = PropertyKey::new(&long);
    }

    #[test]
    fn property_key_max_len_fits() {
        let max_name = "x".repeat(127);
        let key = PropertyKey::new(&max_name);
        assert_eq!(key.len(), 127);
    }

    // ── PropertyValue ────────────────────────────────────────────

    #[test]
    fn property_value_is_none() {
        assert!(PropertyValue::None.is_none());
        assert!(!PropertyValue::None.is_some());
        assert!(PropertyValue::Bool(true).is_some());
        assert!(!PropertyValue::Bool(true).is_none());
    }

    #[test]
    fn property_value_default() {
        assert_eq!(PropertyValue::default(), PropertyValue::None);
    }

    #[test]
    fn property_value_display() {
        assert_eq!(format!("{}", PropertyValue::None), "-");
        assert_eq!(format!("{}", PropertyValue::U64(42)), "42");
        assert_eq!(format!("{}", PropertyValue::Bool(true)), "on");
        assert_eq!(format!("{}", PropertyValue::Bool(false)), "off");
        assert_eq!(format!("{}", PropertyValue::String("lz4".into())), "lz4");
        assert_eq!(format!("{}", PropertyValue::Size(131072)), "131072");
        assert_eq!(format!("{}", PropertyValue::EnumVariant(2)), "variant(2)");
    }

    #[test]
    fn property_value_type_discriminants() {
        assert_eq!(PropertyValue::U64(0).property_type(), PropertyType::U64);
        assert_eq!(PropertyValue::I64(0).property_type(), PropertyType::I64);
        assert_eq!(
            PropertyValue::String(String::new()).property_type(),
            PropertyType::String
        );
        assert_eq!(
            PropertyValue::Bool(true).property_type(),
            PropertyType::Bool
        );
        assert_eq!(
            PropertyValue::EnumVariant(0).property_type(),
            PropertyType::Enum
        );
        assert_eq!(
            PropertyValue::Bytes(Vec::new()).property_type(),
            PropertyType::Bytes
        );
        assert_eq!(PropertyValue::Size(0).property_type(), PropertyType::Size);
    }

    #[test]
    fn property_value_ordering() {
        assert!(PropertyValue::None < PropertyValue::Bool(false));
        assert!(PropertyValue::Bool(false) < PropertyValue::Bool(true));
        assert!(PropertyValue::U64(1) < PropertyValue::U64(2));
    }

    // ── PropertySource ────────────────────────────────────────────

    #[test]
    fn property_source_labels() {
        assert_eq!(PropertySource::Local.label(), "local");
        assert_eq!(
            PropertySource::Inherited {
                parent_dataset_id: 7
            }
            .label(),
            "inherited from parent"
        );
        assert_eq!(PropertySource::Default.label(), "default");
    }

    #[test]
    fn property_source_display() {
        assert_eq!(format!("{}", PropertySource::Local), "local");
        assert_eq!(
            format!(
                "{}",
                PropertySource::Inherited {
                    parent_dataset_id: 42
                }
            ),
            "inherited from 42"
        );
        assert_eq!(format!("{}", PropertySource::Default), "default");
    }

    // ── PropertyEntryV1 ──────────────────────────────────────────

    #[test]
    fn entry_constructors() {
        let local = PropertyEntryV1::local(PropertyValue::Bool(true));
        assert_eq!(local.value, PropertyValue::Bool(true));
        assert!(matches!(local.source, PropertySource::Local));

        let inherited = PropertyEntryV1::inherited(PropertyValue::U64(100), 5);
        assert_eq!(inherited.value, PropertyValue::U64(100));
        assert!(matches!(
            inherited.source,
            PropertySource::Inherited {
                parent_dataset_id: 5
            }
        ));

        let default = PropertyEntryV1::default_value(PropertyValue::Size(4096));
        assert_eq!(default.value, PropertyValue::Size(4096));
        assert!(matches!(default.source, PropertySource::Default));
    }

    // ── PropertySet ──────────────────────────────────────────────

    #[test]
    fn property_set_new_is_empty() {
        let ps = PropertySet::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn property_set_set_and_get_local() {
        let mut ps = PropertySet::new();
        let key = PropertyKey::new("access.readonly");
        ps.set_local(key.clone(), PropertyValue::Bool(true));

        assert_eq!(ps.len(), 1);
        assert!(!ps.is_empty());

        let entry = ps.get(&key).unwrap();
        assert_eq!(entry.value, PropertyValue::Bool(true));
        assert!(matches!(entry.source, PropertySource::Local));

        let local_val = ps.get_local(&key).unwrap();
        assert_eq!(*local_val, PropertyValue::Bool(true));
    }

    #[test]
    fn property_set_set_with_source() {
        let mut ps = PropertySet::new();
        let key = PropertyKey::new("access.readonly");
        ps.set_with_source(
            key.clone(),
            PropertyValue::Bool(false),
            PropertySource::Default,
        );

        let entry = ps.get(&key).unwrap();
        assert_eq!(entry.value, PropertyValue::Bool(false));
        assert!(matches!(entry.source, PropertySource::Default));

        // get_local returns None because source is not Local.
        assert!(ps.get_local(&key).is_none());
    }

    #[test]
    fn property_set_has_local_override() {
        let mut ps = PropertySet::new();
        let key = PropertyKey::new("access.atime");

        assert!(!ps.has_local_override(&key));

        ps.set_local(key.clone(), PropertyValue::Bool(false));
        assert!(ps.has_local_override(&key));

        ps.remove_local_override(&key);
        assert!(!ps.has_local_override(&key));
    }

    #[test]
    fn property_set_remove_local_override() {
        let mut ps = PropertySet::new();
        let key = PropertyKey::new("layout.recordsize");

        // Removing non-existent returns None.
        assert!(ps.remove_local_override(&key).is_none());

        ps.set_local(key.clone(), PropertyValue::Size(65536));
        assert_eq!(ps.len(), 1);

        let removed = ps.remove_local_override(&key).unwrap();
        assert_eq!(removed.value, PropertyValue::Size(65536));
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn property_set_remove_local_override_only_removes_local() {
        let mut ps = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        // Set with Inherited source — remove_local_override should NOT remove.
        ps.set_with_source(
            key.clone(),
            PropertyValue::Bool(true),
            PropertySource::Inherited {
                parent_dataset_id: 1,
            },
        );
        assert_eq!(ps.len(), 1);
        assert!(ps.remove_local_override(&key).is_none());
        assert_eq!(ps.len(), 1); // still there
    }

    #[test]
    fn property_set_overwrite_local() {
        let mut ps = PropertySet::new();
        let key = PropertyKey::new("access.exec");

        ps.set_local(key.clone(), PropertyValue::Bool(true));
        ps.set_local(key.clone(), PropertyValue::Bool(false));

        let entry = ps.get(&key).unwrap();
        assert_eq!(entry.value, PropertyValue::Bool(false));
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn property_set_iter_and_list() {
        let mut ps = PropertySet::new();
        let k1 = PropertyKey::new("access.readonly");
        let k2 = PropertyKey::new("access.atime");

        ps.set_local(k1.clone(), PropertyValue::Bool(true));
        ps.set_local(k2.clone(), PropertyValue::Bool(false));

        let list = ps.list();
        assert_eq!(list.len(), 2);

        let count = ps.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn property_set_multiple_keys() {
        let mut ps = PropertySet::new();
        for i in 0..5 {
            ps.set_local(
                PropertyKey::new(&format!("test.prop{i}")),
                PropertyValue::U64(i),
            );
        }
        assert_eq!(ps.len(), 5);

        for i in 0..5 {
            let key = PropertyKey::new(&format!("test.prop{i}"));
            let entry = ps.get(&key).unwrap();
            assert_eq!(entry.value, PropertyValue::U64(i));
        }
    }

    // ── InheritanceMode / ChangePolicy enums ───────────────────

    #[test]
    fn inheritance_mode_discriminants() {
        assert_eq!(InheritanceMode::None_ as u8, 0x00);
        assert_eq!(InheritanceMode::Parent as u8, 0x01);
        assert_eq!(InheritanceMode::ParentReceived as u8, 0x02);
    }

    #[test]
    fn change_policy_discriminants() {
        assert_eq!(ChangePolicy::Always as u8, 0x00);
        assert_eq!(ChangePolicy::ReadonlyDataset as u8, 0x01);
        assert_eq!(ChangePolicy::CommitGroupBoundary as u8, 0x02);
    }

    // ── resolve_effective ──────────────────────────────────────

    fn make_def(
        name: &str,
        value_type: PropertyType,
        default: PropertyValue,
        inheritance: InheritanceMode,
    ) -> PropertyDefinitionV1 {
        PropertyDefinitionV1::new(
            PropertyKey::new(name),
            value_type,
            default,
            inheritance,
            ChangePolicy::Always,
            PropertyScope::Dataset,
            PropertyFamily::Access,
        )
    }

    #[test]
    fn resolve_local_override_wins() {
        let mut local = PropertySet::new();
        let key = PropertyKey::new("access.readonly");
        local.set_local(key.clone(), PropertyValue::Bool(true));

        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );

        let parent = PropertySet::new();
        let result = resolve_effective(&key, &local, &[&parent], &def);
        assert_eq!(result.value, PropertyValue::Bool(true));
        assert!(matches!(result.source, PropertySource::Local));
    }

    #[test]
    fn resolve_inherits_from_parent() {
        let local = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        let mut parent = PropertySet::new();
        parent.set_local(key.clone(), PropertyValue::Bool(true));

        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );

        let result = resolve_effective(&key, &local, &[&parent], &def);
        assert_eq!(result.value, PropertyValue::Bool(true));
        assert!(matches!(result.source, PropertySource::Inherited { .. }));
    }

    #[test]
    fn resolve_inherits_from_grandparent() {
        let local = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        let mut grandparent = PropertySet::new();
        grandparent.set_local(key.clone(), PropertyValue::Bool(true));

        let parent = PropertySet::new(); // parent has no override

        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );

        let result = resolve_effective(&key, &local, &[&parent, &grandparent], &def);
        assert_eq!(result.value, PropertyValue::Bool(true));
    }

    #[test]
    fn resolve_falls_back_to_default() {
        let local = PropertySet::new();
        let parent = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );

        let result = resolve_effective(&key, &local, &[&parent], &def);
        assert_eq!(result.value, PropertyValue::Bool(false));
        assert!(matches!(result.source, PropertySource::Default));
    }

    #[test]
    fn resolve_none_inheritance_uses_default() {
        let local = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        let mut parent = PropertySet::new();
        parent.set_local(key.clone(), PropertyValue::Bool(true));

        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::None_,
        );

        // NONE inheritance: parent value is ignored, default is used.
        let result = resolve_effective(&key, &local, &[&parent], &def);
        assert_eq!(result.value, PropertyValue::Bool(false));
        assert!(matches!(result.source, PropertySource::Default));
    }

    #[test]
    fn resolve_parent_received_behaves_like_parent_for_local() {
        let local = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        let mut parent = PropertySet::new();
        parent.set_local(key.clone(), PropertyValue::Bool(true));

        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::ParentReceived,
        );

        let result = resolve_effective(&key, &local, &[&parent], &def);
        assert_eq!(result.value, PropertyValue::Bool(true));
    }

    // ── propagate_change ──────────────────────────────────────

    #[test]
    fn propagate_updates_child_without_override() {
        let mut child = PropertySet::new();
        let key = PropertyKey::new("access.readonly");
        // Child has no local override — initially empty.

        propagate_change(&key, &mut child, &PropertyValue::Bool(true), 10);

        let entry = child.get(&key).unwrap();
        assert_eq!(entry.value, PropertyValue::Bool(true));
        assert!(matches!(
            entry.source,
            PropertySource::Inherited {
                parent_dataset_id: 10
            }
        ));
    }

    #[test]
    fn propagate_does_not_update_child_with_local_override() {
        let mut child = PropertySet::new();
        let key = PropertyKey::new("access.readonly");
        child.set_local(key.clone(), PropertyValue::Bool(false));

        propagate_change(&key, &mut child, &PropertyValue::Bool(true), 10);

        let entry = child.get(&key).unwrap();
        assert_eq!(entry.value, PropertyValue::Bool(false)); // unchanged
        assert!(matches!(entry.source, PropertySource::Local));
    }

    #[test]
    fn propagate_writes_new_entry_if_empty() {
        let mut child = PropertySet::new();
        let key = PropertyKey::new("compression.algorithm");

        propagate_change(&key, &mut child, &PropertyValue::String("zstd".into()), 5);

        assert_eq!(child.len(), 1);
        let entry = child.get(&key).unwrap();
        assert_eq!(entry.value, PropertyValue::String("zstd".into()));
    }

    // ── validate_set ──────────────────────────────────────────

    fn make_def_with_constraints(
        name: &str,
        value_type: PropertyType,
        default: PropertyValue,
        cross_constraints: Vec<CrossPropertyPredicate>,
    ) -> PropertyDefinitionV1 {
        PropertyDefinitionV1 {
            name: PropertyKey::new(name),
            value_type,
            default_value: default,
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::Always,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Integrity,
            feature_flag: None,
            cross_constraints,
            range: None,
        }
    }

    #[test]
    fn validate_accepts_valid_value() {
        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );
        let set = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        let result = validate_set(&key, &PropertyValue::Bool(true), &def, &set);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rejects_type_mismatch() {
        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );
        let set = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        let err = validate_set(&key, &PropertyValue::U64(1), &def, &set).unwrap_err();
        assert!(matches!(err, ValidationError::TypeMismatch { .. }));
    }

    #[test]
    fn validate_accepts_none_as_clear_override() {
        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );
        let set = PropertySet::new();
        let key = PropertyKey::new("access.readonly");

        // Setting None means "clear my local override" — type check skipped.
        let result = validate_set(&key, &PropertyValue::None, &def, &set);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_range_check_too_low() {
        let def = PropertyDefinitionV1 {
            name: PropertyKey::new("layout.recordsize"),
            value_type: PropertyType::Size,
            default_value: PropertyValue::Size(131072),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::ReadonlyDataset,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Layout,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: Some((512, 1_048_576)),
        };
        let set = PropertySet::new();
        let key = PropertyKey::new("layout.recordsize");

        let err = validate_set(&key, &PropertyValue::Size(256), &def, &set).unwrap_err();
        assert!(matches!(err, ValidationError::Range { value: 256, .. }));
    }

    #[test]
    fn validate_range_check_too_high() {
        let def = PropertyDefinitionV1 {
            name: PropertyKey::new("layout.recordsize"),
            value_type: PropertyType::Size,
            default_value: PropertyValue::Size(131072),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::ReadonlyDataset,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Layout,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: Some((512, 1_048_576)),
        };
        let set = PropertySet::new();
        let key = PropertyKey::new("layout.recordsize");

        let err = validate_set(&key, &PropertyValue::Size(2_000_000), &def, &set).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::Range {
                value: 2_000_000,
                ..
            }
        ));
    }

    #[test]
    fn validate_range_ok() {
        let def = PropertyDefinitionV1 {
            name: PropertyKey::new("layout.recordsize"),
            value_type: PropertyType::Size,
            default_value: PropertyValue::Size(131072),
            inheritance: InheritanceMode::Parent,
            change_policy: ChangePolicy::ReadonlyDataset,
            scope: PropertyScope::Dataset,
            family: PropertyFamily::Layout,
            feature_flag: None,
            cross_constraints: Vec::new(),
            range: Some((512, 1_048_576)),
        };
        let set = PropertySet::new();
        let key = PropertyKey::new("layout.recordsize");

        let result = validate_set(&key, &PropertyValue::Size(65536), &def, &set);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_cross_property_dedup_requires_checksum() {
        // integrity.dedup requires integrity.checksum != off (Bool(false)).
        let dedup_key = PropertyKey::new("integrity.dedup");
        let checksum_key = PropertyKey::new("integrity.checksum");

        let dedup_def = make_def_with_constraints(
            "integrity.dedup",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            vec![CrossPropertyPredicate {
                property_name: checksum_key.clone(),
                requirement: CrossPropertyRequirement::MustNotBe(PropertyValueDiscriminant::Bool(
                    false,
                )),
                error_message: "dedup requires checksum to be enabled",
            }],
        );

        // Case 1: checksum is off (Bool(false)) → dedup should be rejected.
        let mut set = PropertySet::new();
        set.set_local(checksum_key.clone(), PropertyValue::Bool(false));

        let err =
            validate_set(&dedup_key, &PropertyValue::Bool(true), &dedup_def, &set).unwrap_err();
        assert!(
            matches!(err, ValidationError::CrossProperty { .. }),
            "expected CrossProperty error, got {err:?}"
        );

        // Case 2: checksum is on (Bool(true)) → dedup should be accepted.
        let mut set2 = PropertySet::new();
        set2.set_local(checksum_key.clone(), PropertyValue::Bool(true));

        let result = validate_set(&dedup_key, &PropertyValue::Bool(true), &dedup_def, &set2);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn validate_cross_property_dep_not_set() {
        // When the dependency is not set in the property set, we treat it as None.
        let dedup_key = PropertyKey::new("integrity.dedup");
        let checksum_key = PropertyKey::new("integrity.checksum");

        let dedup_def = make_def_with_constraints(
            "integrity.dedup",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            vec![CrossPropertyPredicate {
                property_name: checksum_key.clone(),
                requirement: CrossPropertyRequirement::MustNotBe(PropertyValueDiscriminant::Bool(
                    false,
                )),
                error_message: "dedup requires checksum to be enabled",
            }],
        );

        let set = PropertySet::new(); // checksum not set

        let result = validate_set(&dedup_key, &PropertyValue::Bool(true), &dedup_def, &set);
        // None != Bool(false), so MustNotBe(Bool(false)) is satisfied.
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn validation_error_display() {
        let e = ValidationError::Range {
            property: PropertyKey::new("layout.recordsize"),
            value: 256,
            min: 512,
            max: 1_048_576,
        };
        let msg = format!("{e}");
        assert!(msg.contains("layout.recordsize"));
        assert!(msg.contains("256"));
        assert!(msg.contains("512"));
        assert!(msg.contains("1048576"));

        let e2 = ValidationError::CrossProperty {
            property: PropertyKey::new("integrity.dedup"),
            depends_on: PropertyKey::new("integrity.checksum"),
            message: "dedup requires checksum",
        };
        let msg2 = format!("{e2}");
        assert!(msg2.contains("dedup requires checksum"));

        let e3 = ValidationError::TypeMismatch {
            property: PropertyKey::new("access.readonly"),
            expected: PropertyType::Bool,
            actual: PropertyType::U64,
        };
        let msg3 = format!("{e3}");
        assert!(msg3.contains("type mismatch"));
        assert!(msg3.contains("bool"));
        assert!(msg3.contains("u64"));
    }

    // ── Registry ──────────────────────────────────────────────

    #[test]
    fn registry_has_expected_properties() {
        let registry = build_registry();
        assert!(registry.len() >= 10);

        let names: Vec<&str> = registry.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"access.readonly"));
        assert!(names.contains(&"access.atime"));
        assert!(names.contains(&"access.relatime"));
        assert!(names.contains(&"access.exec"));
        assert!(names.contains(&"access.setuid"));
        assert!(names.contains(&"layout.recordsize"));
        assert!(names.contains(&"integrity.checksum"));
        assert!(names.contains(&"integrity.dedup"));
        assert!(names.contains(&"compression.algorithm"));
        assert!(names.contains(&"space.quota"));
        assert!(names.contains(&"snapshot.retention"));
    }

    #[test]
    fn lookup_property_finds_and_misses() {
        let registry = build_registry();
        let key = PropertyKey::new("access.readonly");
        let found = lookup_property(&registry, &key).unwrap();
        assert_eq!(found.value_type, PropertyType::Bool);
        assert_eq!(found.default_value, PropertyValue::Bool(false));
        assert_eq!(found.inheritance, InheritanceMode::Parent);

        let unknown = PropertyKey::new("nonexistent.property");
        assert!(lookup_property(&registry, &unknown).is_none());
    }

    #[test]
    fn registry_inheritance_modes() {
        let registry = build_registry();

        // recordsize should be ReadonlyDataset change policy.
        let rec = lookup_property(&registry, &PropertyKey::new("layout.recordsize")).unwrap();
        assert_eq!(rec.change_policy, ChangePolicy::ReadonlyDataset);

        // compression has a feature flag.
        let comp = lookup_property(&registry, &PropertyKey::new("compression.algorithm")).unwrap();
        assert_eq!(comp.feature_flag, Some("org.tidefs:compression_lz4"));
    }

    #[test]
    fn property_scope_discriminants() {
        assert_eq!(PropertyScope::Dataset as u8, 0x00);
        assert_eq!(PropertyScope::Directory as u8, 0x01);
    }

    #[test]
    fn property_family_discriminants_and_label() {
        assert_eq!(PropertyFamily::Compression.label(), "Compression");
        assert_eq!(PropertyFamily::Access.label(), "Access");
        assert_eq!(PropertyFamily::Space.label(), "Space");
        assert_eq!(PropertyFamily::Layout.label(), "Layout");
        assert_eq!(PropertyFamily::Integrity.label(), "Integrity");
        assert_eq!(PropertyFamily::Performance.label(), "Performance");
        assert_eq!(PropertyFamily::Snapshot.label(), "Snapshot");
        assert_eq!(PropertyFamily::Encryption.label(), "Encryption");
    }

    #[test]
    fn property_family_prefix() {
        assert_eq!(PropertyFamily::Compression.prefix(), "compression.");
        assert_eq!(PropertyFamily::Access.prefix(), "access.");
        assert_eq!(PropertyFamily::Layout.prefix(), "layout.");
        assert_eq!(PropertyFamily::Integrity.prefix(), "integrity.");
        assert_eq!(PropertyFamily::Space.prefix(), "space.");
    }

    #[test]
    fn get_family_infers_correctly() {
        assert_eq!(
            get_family(&PropertyKey::new("compression.algorithm")),
            Some(PropertyFamily::Compression)
        );
        assert_eq!(
            get_family(&PropertyKey::new("access.readonly")),
            Some(PropertyFamily::Access)
        );
        assert_eq!(
            get_family(&PropertyKey::new("layout.recordsize")),
            Some(PropertyFamily::Layout)
        );
        assert_eq!(
            get_family(&PropertyKey::new("integrity.checksum")),
            Some(PropertyFamily::Integrity)
        );
        assert_eq!(
            get_family(&PropertyKey::new("space.quota")),
            Some(PropertyFamily::Space)
        );
        assert_eq!(
            get_family(&PropertyKey::new("snapshot.retention")),
            Some(PropertyFamily::Snapshot)
        );
        assert_eq!(get_family(&PropertyKey::new("unknown.prop")), None);
    }

    #[test]
    fn filter_registry_by_family_works() {
        let registry = build_registry();
        let access_props = filter_registry_by_family(&registry, PropertyFamily::Access);
        // Should find: access.readonly, access.atime, access.relatime, access.exec, access.setuid
        assert!(access_props.len() >= 5);
        for def in &access_props {
            assert!(def.name.as_str().starts_with("access."));
        }

        let integrity_props = filter_registry_by_family(&registry, PropertyFamily::Integrity);
        assert!(integrity_props.len() >= 2);
        for def in &integrity_props {
            assert!(def.name.as_str().starts_with("integrity."));
        }
    }

    #[test]
    fn registry_scope_is_dataset_for_all() {
        let registry = build_registry();
        for def in &registry {
            assert_eq!(
                def.scope,
                PropertyScope::Dataset,
                "expected Dataset scope for {}",
                def.name
            );
        }
    }

    #[test]
    fn registry_family_matches_key_prefix() {
        let registry = build_registry();
        for def in &registry {
            let inferred = get_family(&def.name);
            assert_eq!(
                Some(def.family),
                inferred,
                "family mismatch for {}",
                def.name
            );
        }
    }

    // ── Integration: inheritance chain ────────────────────────

    #[test]
    fn inheritance_chain_grandparent_to_child() {
        let key = PropertyKey::new("access.readonly");
        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );

        // Grandparent sets true.
        let mut gp = PropertySet::new();
        gp.set_local(key.clone(), PropertyValue::Bool(true));

        // Parent has no override.
        let parent = PropertySet::new();

        // Child — also no override.
        let child = PropertySet::new();

        let result = resolve_effective(&key, &child, &[&parent, &gp], &def);
        assert_eq!(result.value, PropertyValue::Bool(true));
    }

    #[test]
    fn override_and_revert_cycle() {
        let key = PropertyKey::new("access.readonly");
        let def = make_def(
            "access.readonly",
            PropertyType::Bool,
            PropertyValue::Bool(false),
            InheritanceMode::Parent,
        );

        // Parent sets true.
        let mut parent = PropertySet::new();
        parent.set_local(key.clone(), PropertyValue::Bool(true));

        // Child overrides to false.
        let mut child = PropertySet::new();
        child.set_local(key.clone(), PropertyValue::Bool(false));

        let result = resolve_effective(&key, &child, &[&parent], &def);
        assert_eq!(result.value, PropertyValue::Bool(false)); // local wins

        // Child removes override → reverts to parent's true.
        child.remove_local_override(&key);
        let result2 = resolve_effective(&key, &child, &[&parent], &def);
        assert_eq!(result2.value, PropertyValue::Bool(true));
    }

    #[test]
    fn property_list_with_source_annotations() {
        let mut ps = PropertySet::new();

        ps.set_local(
            PropertyKey::new("access.readonly"),
            PropertyValue::Bool(true),
        );
        ps.set_with_source(
            PropertyKey::new("access.atime"),
            PropertyValue::Bool(false),
            PropertySource::Inherited {
                parent_dataset_id: 2,
            },
        );
        ps.set_with_source(
            PropertyKey::new("layout.recordsize"),
            PropertyValue::Size(131072),
            PropertySource::Default,
        );

        let list = ps.list();
        assert_eq!(list.len(), 3);

        // Find the local one.
        let local_entry = list
            .iter()
            .find(|(k, _)| k.as_str() == "access.readonly")
            .unwrap();
        assert!(matches!(local_entry.1.source, PropertySource::Local));

        // Find the inherited one.
        let inherited_entry = list
            .iter()
            .find(|(k, _)| k.as_str() == "access.atime")
            .unwrap();
        assert!(matches!(
            inherited_entry.1.source,
            PropertySource::Inherited {
                parent_dataset_id: 2
            }
        ));

        // Find the default one.
        let default_entry = list
            .iter()
            .find(|(k, _)| k.as_str() == "layout.recordsize")
            .unwrap();
        assert!(matches!(default_entry.1.source, PropertySource::Default));
    }

    #[test]
    fn property_value_clone_and_eq() {
        let a = PropertyValue::String("zstd".into());
        let b = a.clone();
        assert_eq!(a, b);

        let c = PropertyValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let d = c.clone();
        assert_eq!(c, d);
    }

    // ── Blob serialization ───────────────────────────────────

    #[test]
    fn blob_round_trip_local_properties() {
        let mut ps = PropertySet::new();
        ps.set_local(
            PropertyKey::new("access.readonly"),
            PropertyValue::Bool(true),
        );
        ps.set_local(
            PropertyKey::new("layout.recordsize"),
            PropertyValue::Size(131072),
        );
        ps.set_local(
            PropertyKey::new("compression.algorithm"),
            PropertyValue::String("zstd".into()),
        );

        let blob = ps.to_key_value_blob();
        let restored = PropertySet::from_key_value_blob(&blob);

        // All three local entries should round-trip.
        assert_eq!(restored.len(), 3);

        let ro = restored.get(&PropertyKey::new("access.readonly")).unwrap();
        assert_eq!(ro.value, PropertyValue::Bool(true));
        assert!(matches!(ro.source, PropertySource::Local));

        let rs = restored
            .get(&PropertyKey::new("layout.recordsize"))
            .unwrap();
        // Size values round-trip as u64 (parsed numerically from string).
        assert_eq!(rs.value, PropertyValue::U64(131072));

        let comp = restored
            .get(&PropertyKey::new("compression.algorithm"))
            .unwrap();
        assert_eq!(comp.value, PropertyValue::String("zstd".into()));
    }

    #[test]
    fn blob_round_trip_empty() {
        let ps = PropertySet::new();
        let blob = ps.to_key_value_blob();
        assert!(blob.is_empty());
        let restored = PropertySet::from_key_value_blob(&blob);
        assert!(restored.is_empty());
    }

    #[test]
    fn blob_only_serializes_local_entries() {
        let mut ps = PropertySet::new();
        ps.set_local(
            PropertyKey::new("access.readonly"),
            PropertyValue::Bool(true),
        );
        ps.set_with_source(
            PropertyKey::new("access.atime"),
            PropertyValue::Bool(false),
            PropertySource::Inherited {
                parent_dataset_id: 1,
            },
        );
        ps.set_with_source(
            PropertyKey::new("layout.recordsize"),
            PropertyValue::Size(512),
            PropertySource::Default,
        );

        let blob = ps.to_key_value_blob();
        // Only the Local entry should be serialized.
        let restored = PropertySet::from_key_value_blob(&blob);
        assert_eq!(restored.len(), 1);
        assert!(restored.get(&PropertyKey::new("access.readonly")).is_some());
        assert!(restored.get(&PropertyKey::new("access.atime")).is_none());
        assert!(restored
            .get(&PropertyKey::new("layout.recordsize"))
            .is_none());
    }
}
