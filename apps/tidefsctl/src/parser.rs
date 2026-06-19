// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Shared TideFS CLI value parsers.

use tidefs_dataset_properties::{
    lookup_property, validate_set, PropertyKey, PropertySet, PropertyType, PropertyValue,
};
use tidefs_types_dataset_feature_flags_core::{get_feature_class, FeatureName};

const MAX_POOL_NAME_LEN: usize = 63;
const MAX_DATASET_PATH_LEN: usize = 4096;
const MAX_DATASET_COMPONENT_LEN: usize = 255;
const MAX_PROPERTY_STRING_LEN: usize = 255;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DatasetTarget {
    pub(crate) pool: String,
    pub(crate) dataset: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PropertyAssignment {
    pub(crate) key: String,
    pub(crate) raw_value: String,
    pub(crate) value: PropertyValue,
    pub(crate) clear: bool,
}

pub(crate) fn parse_dataset_target(raw: &str) -> Result<DatasetTarget, String> {
    let (pool, dataset) = raw
        .split_once('/')
        .ok_or_else(|| "expected dataset target in <pool>/<name> form".to_string())?;
    let pool = parse_pool_name(pool)?;
    let dataset = parse_dataset_path(dataset)?;
    Ok(DatasetTarget { pool, dataset })
}

pub(crate) fn parse_pool_name(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("pool name must not be empty".to_string());
    }
    if raw.trim() != raw {
        return Err("pool name must not contain leading or trailing whitespace".to_string());
    }
    if raw.len() > MAX_POOL_NAME_LEN {
        return Err(format!(
            "pool name exceeds {MAX_POOL_NAME_LEN} bytes: {raw}"
        ));
    }
    if matches!(raw, "." | "..") {
        return Err("pool name must not be . or ..".to_string());
    }
    let mut bytes = raw.bytes();
    let first = bytes.next().expect("checked nonempty pool name");
    if !first.is_ascii_alphanumeric() {
        return Err("pool name must start with an ASCII letter or digit".to_string());
    }
    if !bytes.all(is_identity_byte) {
        return Err(
            "pool name may contain only ASCII letters, digits, '.', '_', and '-'".to_string(),
        );
    }
    Ok(raw.to_string())
}

pub(crate) fn parse_dataset_path(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("dataset name must not be empty".to_string());
    }
    if raw.trim() != raw {
        return Err("dataset name must not contain leading or trailing whitespace".to_string());
    }
    if raw.len() > MAX_DATASET_PATH_LEN {
        return Err(format!("dataset path exceeds {MAX_DATASET_PATH_LEN} bytes"));
    }
    if raw.starts_with('/') || raw.ends_with('/') || raw.contains("//") {
        return Err(
            "dataset path must be relative and must not contain empty components".to_string(),
        );
    }
    if raw.contains('\0') {
        return Err("dataset path must not contain NUL bytes".to_string());
    }
    if raw.contains('@') {
        return Err("dataset lifecycle commands do not accept snapshot selectors".to_string());
    }
    for component in raw.split('/') {
        parse_dataset_component(component)?;
    }
    Ok(raw.to_string())
}

pub(crate) fn dataset_parent_and_leaf(path: &str) -> (Option<&str>, &str) {
    path.rsplit_once('/')
        .map_or((None, path), |(parent, leaf)| (Some(parent), leaf))
}

pub(crate) fn parse_property_key(raw: &str) -> Result<String, String> {
    let key = raw.trim();
    if key.is_empty() {
        return Err("property key must not be empty".to_string());
    }
    if key.len() > PropertyKey::MAX_LEN {
        return Err(format!(
            "property key exceeds {} bytes: {key}",
            PropertyKey::MAX_LEN
        ));
    }
    let registry = tidefs_dataset_properties::build_registry();
    let property_key = PropertyKey::new(key);
    if lookup_property(&registry, &property_key).is_none() {
        return Err(format!("unsupported dataset property key: {key}"));
    }
    Ok(key.to_string())
}

pub(crate) fn parse_property_assignment(raw: &str) -> Result<PropertyAssignment, String> {
    let (key_raw, value_raw) = raw
        .split_once('=')
        .ok_or_else(|| "property assignment must use key=value form".to_string())?;
    let key = parse_property_key(key_raw)?;
    let raw_value = value_raw.trim().to_string();
    let clear = raw_value.is_empty() || raw_value == "-";
    let value = if clear {
        PropertyValue::None
    } else {
        let registry = tidefs_dataset_properties::build_registry();
        let property_key = PropertyKey::new(&key);
        let definition = lookup_property(&registry, &property_key)
            .expect("parse_property_key already checked registry membership");
        let value = parse_property_value(&raw_value, definition.value_type)?;
        validate_set(&property_key, &value, definition, &PropertySet::new())
            .map_err(|err| format!("invalid value for {key}: {err}"))?;
        value
    };
    Ok(PropertyAssignment {
        key,
        raw_value,
        value,
        clear,
    })
}

pub(crate) fn parse_dataset_feature_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    let parsed = FeatureName::from_str(name)
        .ok_or_else(|| format!("invalid dataset feature flag name: {name}"))?;
    if get_feature_class(&parsed).is_none() {
        return Err(format!("unsupported dataset feature flag: {name}"));
    }
    Ok(name.to_string())
}

fn parse_dataset_component(component: &str) -> Result<(), String> {
    if component.is_empty() {
        return Err("dataset component must not be empty".to_string());
    }
    if component.len() > MAX_DATASET_COMPONENT_LEN {
        return Err(format!(
            "dataset component exceeds {MAX_DATASET_COMPONENT_LEN} bytes: {component}"
        ));
    }
    if matches!(component, "." | "..") {
        return Err("dataset component must not be . or ..".to_string());
    }
    if !component.bytes().all(is_identity_byte) {
        return Err(
            "dataset components may contain only ASCII letters, digits, '.', '_', and '-'"
                .to_string(),
        );
    }
    Ok(())
}

fn is_identity_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn parse_property_value(raw: &str, value_type: PropertyType) -> Result<PropertyValue, String> {
    match value_type {
        PropertyType::Bool => parse_bool(raw).map(PropertyValue::Bool),
        PropertyType::U64 => raw
            .parse::<u64>()
            .map(PropertyValue::U64)
            .map_err(|err| format!("expected unsigned integer: {err}")),
        PropertyType::I64 => raw
            .parse::<i64>()
            .map(PropertyValue::I64)
            .map_err(|err| format!("expected signed integer: {err}")),
        PropertyType::String => {
            if raw.len() > MAX_PROPERTY_STRING_LEN {
                Err(format!(
                    "string value exceeds {MAX_PROPERTY_STRING_LEN} bytes"
                ))
            } else {
                Ok(PropertyValue::String(raw.to_string()))
            }
        }
        PropertyType::Enum => parse_enum_variant(raw).map(PropertyValue::EnumVariant),
        PropertyType::Bytes => parse_hex_bytes(raw).map(PropertyValue::Bytes),
        PropertyType::Size => parse_size(raw).map(PropertyValue::Size),
    }
}

fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err("expected on/off, true/false, yes/no, or 1/0".to_string()),
    }
}

fn parse_enum_variant(raw: &str) -> Result<u8, String> {
    let raw = raw.trim();
    let raw = raw
        .strip_prefix("variant(")
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(raw);
    raw.parse::<u8>()
        .map_err(|err| format!("expected enum variant number 0..255: {err}"))
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() % 2 != 0 {
        return Err("hex byte value must contain an even number of digits".to_string());
    }
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let part = std::str::from_utf8(chunk).map_err(|err| format!("invalid UTF-8: {err}"))?;
            u8::from_str_radix(part, 16).map_err(|err| format!("invalid hex byte {part}: {err}"))
        })
        .collect()
}

fn parse_size(raw: &str) -> Result<u64, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    let (number, multiplier) = match normalized.as_str() {
        value if value.ends_with("kib") => (&value[..value.len() - 3], 1024),
        value if value.ends_with("kb") => (&value[..value.len() - 2], 1024),
        value if value.ends_with('k') => (&value[..value.len() - 1], 1024),
        value if value.ends_with("mib") => (&value[..value.len() - 3], 1024_u64.pow(2)),
        value if value.ends_with("mb") => (&value[..value.len() - 2], 1024_u64.pow(2)),
        value if value.ends_with('m') => (&value[..value.len() - 1], 1024_u64.pow(2)),
        value if value.ends_with("gib") => (&value[..value.len() - 3], 1024_u64.pow(3)),
        value if value.ends_with("gb") => (&value[..value.len() - 2], 1024_u64.pow(3)),
        value if value.ends_with('g') => (&value[..value.len() - 1], 1024_u64.pow(3)),
        value if value.ends_with("tib") => (&value[..value.len() - 3], 1024_u64.pow(4)),
        value if value.ends_with("tb") => (&value[..value.len() - 2], 1024_u64.pow(4)),
        value if value.ends_with('t') => (&value[..value.len() - 1], 1024_u64.pow(4)),
        value if value.ends_with('b') => (&value[..value.len() - 1], 1),
        value => (value, 1),
    };
    if number.is_empty() {
        return Err("size value must include a number".to_string());
    }
    let base = number
        .parse::<u64>()
        .map_err(|err| format!("expected size in bytes or KiB/MiB/GiB/TiB form: {err}"))?;
    base.checked_mul(multiplier)
        .ok_or_else(|| "size value overflows u64".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_target_accepts_pool_and_nested_dataset() {
        let target = parse_dataset_target("tank/projects/app").unwrap();
        assert_eq!(target.pool, "tank");
        assert_eq!(target.dataset, "projects/app");
    }

    #[test]
    fn dataset_target_rejects_invalid_pool_names() {
        assert!(parse_dataset_target("/data").is_err());
        assert!(parse_dataset_target("bad pool/data").is_err());
        assert!(parse_dataset_target("-tank/data").is_err());
    }

    #[test]
    fn dataset_target_rejects_invalid_dataset_paths() {
        assert!(parse_dataset_target("tank/").is_err());
        assert!(parse_dataset_target("tank//data").is_err());
        assert!(parse_dataset_target("tank/../data").is_err());
        assert!(parse_dataset_target("tank/data@snap").is_err());
    }

    #[test]
    fn property_assignment_validates_registry_keys_and_values() {
        let assignment = parse_property_assignment("access.readonly=on").unwrap();
        assert_eq!(assignment.key, "access.readonly");
        assert_eq!(assignment.value, PropertyValue::Bool(true));

        let size = parse_property_assignment("layout.recordsize=128K").unwrap();
        assert_eq!(size.value, PropertyValue::Size(131_072));
    }

    #[test]
    fn property_assignment_rejects_unknown_keys_and_bad_types() {
        assert!(parse_property_assignment("not.a.property=on").is_err());
        assert!(parse_property_assignment("access.readonly=maybe").is_err());
        assert!(parse_property_assignment("layout.recordsize=128").is_err());
    }

    #[test]
    fn feature_parser_accepts_only_supported_feature_names() {
        assert_eq!(
            parse_dataset_feature_name("org.tidefs:compression_zstd").unwrap(),
            "org.tidefs:compression_zstd"
        );
        assert!(parse_dataset_feature_name("com.example:future").is_err());
        assert!(parse_dataset_feature_name("org.tidefs:BAD").is_err());
    }
}
