#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::human::local_object_store::{
    checksum64, local_object_store_on_disk_format_rules, production_integrity_policy_rules,
    segment_file_name, LocalObjectStore, ObjectKey, LOCAL_OBJECT_STORE_ON_DISK_FORMAT_SPEC,
    PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM, PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION,
    PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM, PRODUCTION_INTEGRITY_POLICY_SPEC,
    PRODUCTION_INTEGRITY_RECORD_DIGEST_ALGORITHM,
    PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM, PRODUCTION_INTEGRITY_TRAILER_LEN,
    PRODUCTION_INTEGRITY_TRAILER_MAGIC_ASCII, RECORD_FOOTER_LEN, RECORD_FOOTER_MAGIC_ASCII,
    RECORD_FORMAT_VERSION, RECORD_FORMAT_VERSION_V1_NO_FOOTER, RECORD_FORMAT_VERSION_V2_FOOTER,
    RECORD_HEADER_LEN, RECORD_MAGIC_ASCII, SEGMENT_FILE_EXTENSION, STORE_DIR_NAME,
};

fn main() -> Result<(), Box<dyn Error>> {
    let (root, ephemeral) = demo_root();
    if ephemeral {
        let _ = fs::remove_dir_all(&root);
    }

    println!("tidefs durable local object-store demo");
    println!("store_root={}", root.display());
    println!("segment_dir={STORE_DIR_NAME}");
    println!("segment_file_example={}", segment_file_name(0));
    println!("segment_extension={SEGMENT_FILE_EXTENSION}");
    println!("record_magic={RECORD_MAGIC_ASCII}");
    println!("record_footer_magic={RECORD_FOOTER_MAGIC_ASCII}");
    println!("record_format_version_v1_no_footer={RECORD_FORMAT_VERSION_V1_NO_FOOTER}");
    println!("record_format_version_v2_footer={RECORD_FORMAT_VERSION_V2_FOOTER}");
    println!("record_format_version={RECORD_FORMAT_VERSION}");
    println!("record_header_len={RECORD_HEADER_LEN}");
    println!("record_footer_len={RECORD_FOOTER_LEN}");
    println!("production_integrity.trailer_magic={PRODUCTION_INTEGRITY_TRAILER_MAGIC_ASCII}");
    println!("production_integrity.trailer_len={PRODUCTION_INTEGRITY_TRAILER_LEN}");
    println!("on_disk_format_spec={LOCAL_OBJECT_STORE_ON_DISK_FORMAT_SPEC}");
    let format_rules = local_object_store_on_disk_format_rules();
    println!("on_disk_format.rules={}", format_rules.len());
    for rule in format_rules {
        println!(
            "on_disk_format.rule topic={} marker={}",
            rule.topic.stable_id(),
            rule.source_marker
        );
    }
    println!("production_integrity_policy={PRODUCTION_INTEGRITY_POLICY_SPEC}");
    println!("production_integrity.object_digest={PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM}");
    println!("production_integrity.record_digest={PRODUCTION_INTEGRITY_RECORD_DIGEST_ALGORITHM}");
    println!(
        "production_integrity.root_authentication={PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM}"
    );
    println!("production_integrity.key_derivation={PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM}");
    println!("production_integrity.migration_record_version={PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION}");
    let integrity_rules = production_integrity_policy_rules();
    println!("production_integrity.rules={}", integrity_rules.len());
    for rule in integrity_rules {
        println!(
            "production_integrity.rule topic={} marker={}",
            rule.topic.stable_id(),
            rule.source_marker
        );
    }

    let key = ObjectKey::from_name("demo/file/extent/0");
    let payload = b"tidefs durable local object-store demo bytes";
    println!("payload_checksum={}", checksum64(payload));

    let mut store = LocalObjectStore::open(&root)?;
    let stored = store.put(key, payload)?;
    store.sync_all()?;
    println!("write.object_key={}", stored.key);
    println!("write.object_key_short={}", stored.key.short_hex());
    println!("write.sequence={}", stored.sequence);
    println!("write.len={}", stored.len);
    println!("write.checksum={}", stored.checksum);

    let immediate_read = store
        .get(key)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "object missing after write"))?;
    println!(
        "read.immediate_utf8={}",
        String::from_utf8_lossy(&immediate_read)
    );
    drop(store);

    let reopened = LocalObjectStore::open(&root)?;
    let replayed = reopened
        .get(key)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "object missing after replay"))?;
    let stats = reopened.stats();
    println!("replay.live_objects={}", stats.live_objects);
    println!("replay.live_bytes={}", stats.live_bytes);
    println!("replay.segment_count={}", stats.segment_count);
    println!("replay.records_seen={}", stats.replay.records_seen);
    println!("replay.v1_records_seen={}", stats.replay.v1_records_seen);
    println!("replay.v2_records_seen={}", stats.replay.v2_records_seen);
    println!("replay.v3_records_seen={}", stats.replay.v3_records_seen);
    println!(
        "replay.production_integrity_records_seen={}",
        stats.replay.production_integrity_records_seen
    );
    println!("replay.puts_seen={}", stats.replay.puts_seen);
    println!("replay.deletes_seen={}", stats.replay.deletes_seen);
    println!(
        "replay.repaired_tail_bytes={}",
        stats.replay.repaired_tail_bytes
    );
    println!(
        "read.after_replay_utf8={}",
        String::from_utf8_lossy(&replayed)
    );

    Ok(())
}

fn demo_root() -> (PathBuf, bool) {
    if let Some(path) = env::args_os().nth(1) {
        return (PathBuf::from(path), false);
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut root = env::temp_dir();
    root.push(format!("tidefs-store-demo-{}-{nanos}", std::process::id()));
    (root, true)
}
