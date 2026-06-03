// Integration tests for tidefs-fuser covering reply framing validation,
// file I/O lifecycle (create/write/read/unlink), lookup paths, error
// propagation, and concurrent reply accumulation.
//
// These tests use CapturingSender to validate framed FUSE reply bytes
// without requiring /dev/fuse.  Filesystem trait dispatch tests that
// need &Request live in src/request.rs (internal tests).

use std::collections::HashMap;
use std::convert::TryInto;

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use fuser::{
    CapturingSender, FileAttr, FileType, Filesystem, Reply, ReplyAttr, ReplyCreate, ReplyData,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite,
};

// ---------------------------------------------------------------------------
// Wire-format helpers
//   fuse_out_header { len: u32, error: i32, unique: u64 } = 16 bytes
// ---------------------------------------------------------------------------

fn reply_error(raw: &[u8]) -> i32 {
    assert!(raw.len() >= 16, "reply too short: {} bytes", raw.len());
    let bytes: [u8; 4] = raw[4..8].try_into().unwrap();
    i32::from_ne_bytes(bytes)
}

fn reply_unique(raw: &[u8]) -> u64 {
    assert!(raw.len() >= 16);
    let bytes: [u8; 8] = raw[8..16].try_into().unwrap();
    u64::from_ne_bytes(bytes)
}

fn reply_payload(raw: &[u8]) -> &[u8] {
    &raw[16..]
}

// ===================================================================
// Reply Framing Validation
// ===================================================================

#[test]
fn reply_empty_ok_frames_success_header() {
    let sender = CapturingSender::new();
    let reply: ReplyEmpty = Reply::new(42, sender.clone());
    reply.ok();
    let raw = sender.take_data();
    assert_eq!(raw.len(), 16);
    assert_eq!(reply_error(&raw), 0);
    assert_eq!(reply_unique(&raw), 42);
}

#[test]
fn reply_empty_error_frames_negative_errno() {
    let sender = CapturingSender::new();
    let reply: ReplyEmpty = Reply::new(7, sender.clone());
    reply.error(libc::ENOENT);
    let raw = sender.take_data();
    assert_eq!(raw.len(), 16);
    assert_eq!(reply_error(&raw), -libc::ENOENT);
    assert_eq!(reply_unique(&raw), 7);
}

#[test]
fn reply_data_frames_header_plus_payload() {
    let sender = CapturingSender::new();
    let reply: ReplyData = Reply::new(99, sender.clone());
    reply.data(b"hello FUSE");
    let raw = sender.take_data();
    assert!(raw.len() > 16);
    assert_eq!(reply_error(&raw), 0);
    assert_eq!(reply_unique(&raw), 99);
    assert_eq!(reply_payload(&raw), b"hello FUSE");
}

#[test]
fn reply_data_empty_payload() {
    let sender = CapturingSender::new();
    let reply: ReplyData = Reply::new(100, sender.clone());
    reply.data(&[]);
    let raw = sender.take_data();
    assert_eq!(raw.len(), 16);
    assert_eq!(reply_error(&raw), 0);
}

#[test]
fn reply_write_frames_size_field() {
    let sender = CapturingSender::new();
    let reply: ReplyWrite = Reply::new(1, sender.clone());
    reply.written(4096);
    let raw = sender.take_data();
    assert_eq!(reply_error(&raw), 0);
    let payload = reply_payload(&raw);
    assert_eq!(
        payload.len(),
        8,
        "fuse_write_out = size(u32) + padding(u32)"
    );
    let written = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
    assert_eq!(written, 4096);
    let padding = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
    assert_eq!(padding, 0);
}

#[test]
fn reply_write_zero_length() {
    let sender = CapturingSender::new();
    let reply: ReplyWrite = Reply::new(2, sender.clone());
    reply.written(0);
    let raw = sender.take_data();
    let payload = reply_payload(&raw);
    let written = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
    assert_eq!(written, 0);
}

#[test]
fn reply_open_frames_fh_and_flags() {
    let sender = CapturingSender::new();
    let reply: ReplyOpen = Reply::new(3, sender.clone());
    reply.opened(0xdead, 0xbeef);
    let raw = sender.take_data();
    assert_eq!(reply_error(&raw), 0);
    let payload = reply_payload(&raw);
    assert_eq!(
        payload.len(),
        16,
        "fuse_open_out = fh(u64) + flags(u32) + padding(u32)"
    );
    let fh = u64::from_ne_bytes(payload[0..8].try_into().unwrap());
    assert_eq!(fh, 0xdead);
    let flags = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
    assert_eq!(flags, 0xbeef);
}

#[test]
fn reply_create_frames_entry_and_open() {
    let attr = FileAttr {
        ino: 100,
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    };
    let sender = CapturingSender::new();
    let reply: ReplyCreate = Reply::new(10, sender.clone());
    reply.created(&Duration::from_secs(5), &attr, 7, 0x1234, 0x1);
    let raw = sender.take_data();
    assert_eq!(reply_error(&raw), 0);
    let payload = reply_payload(&raw);
    // fuse_entry_out.nodeid at offset 0
    let ino_bytes = u64::from_ne_bytes(payload[0..8].try_into().unwrap());
    assert_eq!(ino_bytes, 100);
    let gen_bytes = u64::from_ne_bytes(payload[8..16].try_into().unwrap());
    assert_eq!(gen_bytes, 7);
}

#[test]
fn reply_entry_frames_entry_out() {
    let attr = FileAttr {
        ino: 42,
        size: 2048,
        blocks: 4,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    };
    let sender = CapturingSender::new();
    let reply: ReplyEntry = Reply::new(50, sender.clone());
    reply.entry(&Duration::from_millis(500), &attr, 3);
    let raw = sender.take_data();
    assert_eq!(reply_error(&raw), 0);
    let payload = reply_payload(&raw);
    // fuse_entry_out: nodeid(8) + generation(8) + entry_valid(8) + attr_valid(8) + ...
    // entry_valid should encode 0.5s = 0 sec + 500_000_000 nsec
    let entry_valid_secs = u64::from_ne_bytes(payload[16..24].try_into().unwrap());
    assert_eq!(entry_valid_secs, 0);
    let entry_valid_nsec = u32::from_ne_bytes(payload[32..36].try_into().unwrap());
    assert_eq!(entry_valid_nsec, 500_000_000);
}

#[test]
fn reply_attr_frames_attr_out() {
    let attr = FileAttr {
        ino: 99,
        size: 4096,
        blocks: 8,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o600,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        blksize: 512,
        flags: 0,
    };
    let sender = CapturingSender::new();
    let reply: ReplyAttr = Reply::new(60, sender.clone());
    reply.attr(&Duration::from_secs(1), &attr);
    let raw = sender.take_data();
    assert_eq!(reply_error(&raw), 0);
    let payload = reply_payload(&raw);
    // attr_valid at offset 0 in fuse_attr_out
    let attr_valid = u64::from_ne_bytes(payload[0..8].try_into().unwrap());
    assert_eq!(attr_valid, 1);
}

// ===================================================================
// Error Propagation at Reply Level
// ===================================================================

#[test]
fn reply_error_codes_roundtrip() {
    let errno_cases: &[(i32, &str)] = &[
        (libc::EPERM, "EPERM"),
        (libc::ENOENT, "ENOENT"),
        (libc::EIO, "EIO"),
        (libc::EACCES, "EACCES"),
        (libc::EEXIST, "EEXIST"),
        (libc::ENOSPC, "ENOSPC"),
        (libc::ENOTEMPTY, "ENOTEMPTY"),
        (libc::EISDIR, "EISDIR"),
        (libc::ENOTDIR, "ENOTDIR"),
        (libc::EINVAL, "EINVAL"),
        (libc::EROFS, "EROFS"),
        (libc::EBADF, "EBADF"),
        (libc::ENOMEM, "ENOMEM"),
        (libc::EBUSY, "EBUSY"),
    ];
    for &(errno, _name) in errno_cases {
        let sender = CapturingSender::new();
        let reply: ReplyEmpty = Reply::new(400, sender.clone());
        reply.error(errno);
        let raw = sender.take_data();
        assert_eq!(reply_error(&raw), -errno);
    }
}

#[test]
fn reply_multiple_error_types_across_reply_kinds() {
    // ReplyWrite::error
    let s = CapturingSender::new();
    let r: ReplyWrite = Reply::new(1, s.clone());
    r.error(libc::ENOSPC);
    assert_eq!(reply_error(&s.take_data()), -libc::ENOSPC);

    // ReplyData::error
    let s = CapturingSender::new();
    let r: ReplyData = Reply::new(2, s.clone());
    r.error(libc::EIO);
    assert_eq!(reply_error(&s.take_data()), -libc::EIO);

    // ReplyCreate::error
    let s = CapturingSender::new();
    let r: ReplyCreate = Reply::new(3, s.clone());
    r.error(libc::EPERM);
    assert_eq!(reply_error(&s.take_data()), -libc::EPERM);

    // ReplyEntry::error
    let s = CapturingSender::new();
    let r: ReplyEntry = Reply::new(4, s.clone());
    r.error(libc::ENOENT);
    assert_eq!(reply_error(&s.take_data()), -libc::ENOENT);

    // ReplyOpen::error
    let s = CapturingSender::new();
    let r: ReplyOpen = Reply::new(5, s.clone());
    r.error(libc::EACCES);
    assert_eq!(reply_error(&s.take_data()), -libc::EACCES);
}

// ===================================================================
// Unique Preservation
// ===================================================================

#[test]
fn reply_unique_preserved_across_single_sender() {
    let sender = CapturingSender::new();
    let unique_values: &[u64] = &[0, 1, 42, u64::MAX / 2, u64::MAX - 1, u64::MAX];
    for &uniq in unique_values {
        let reply: ReplyEmpty = Reply::new(uniq, sender.clone());
        reply.ok();
        let raw = sender.take_data();
        assert_eq!(reply_unique(&raw), uniq);
    }
}

#[test]
fn reply_unique_zero_is_valid() {
    let sender = CapturingSender::new();
    let reply: ReplyEmpty = Reply::new(0, sender.clone());
    reply.ok();
    let raw = sender.take_data();
    assert_eq!(reply_unique(&raw), 0);
}

// ===================================================================
// Accumulated Buffer: data() and take_data()
// ===================================================================

#[test]
fn capturing_sender_data_returns_copy_without_clearing() {
    let sender = CapturingSender::new();
    let reply: ReplyEmpty = Reply::new(500, sender.clone());
    reply.ok();

    let d1 = sender.data();
    let d2 = sender.data();
    assert_eq!(d1.len(), 16);
    assert_eq!(d1, d2, "data() should return same contents each call");
}

#[test]
fn capturing_sender_take_data_drains_buffer() {
    let sender = CapturingSender::new();

    let r1: ReplyEmpty = Reply::new(600, sender.clone());
    r1.ok();
    assert_eq!(sender.take_data().len(), 16);

    let r2: ReplyEmpty = Reply::new(601, sender.clone());
    r2.ok();
    assert_eq!(sender.take_data().len(), 16);

    assert!(
        sender.data().is_empty(),
        "buffer should be empty after take_data"
    );
}

#[test]
fn capturing_sender_accumulates_sequential_replies() {
    let sender = CapturingSender::new();

    let r1: ReplyEmpty = Reply::new(1, sender.clone());
    r1.ok();

    let r2: ReplyData = Reply::new(2, sender.clone());
    r2.data(b"second");

    let raw = sender.data();
    assert!(raw.len() >= 32);
    // First reply: unique=1, error=0
    assert_eq!(reply_error(&raw[0..16]), 0);
    assert_eq!(reply_unique(&raw[0..16]), 1);
    // Second reply: unique=2, error=0, payload="second"
    assert_eq!(reply_error(&raw[16..32]), 0);
    assert_eq!(reply_unique(&raw[16..32]), 2);
    assert_eq!(&raw[32..38], b"second");
}

#[test]
fn capturing_sender_new_is_empty() {
    let sender = CapturingSender::new();
    assert!(sender.data().is_empty());
}

#[test]
fn capturing_sender_default_is_empty() {
    let sender = CapturingSender::default();
    assert!(sender.data().is_empty());
}

// ===================================================================
// Concurrent Sender
// ===================================================================

#[test]
fn capturing_sender_is_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<CapturingSender>();
    assert_sync::<CapturingSender>();
}

#[test]
fn concurrent_replies_dont_panic() {
    use std::thread;

    let sender = CapturingSender::new();
    let s1 = sender.clone();
    let s2 = sender.clone();

    let t1 = thread::spawn(move || {
        for i in 0..50u64 {
            let reply: ReplyEmpty = Reply::new(i, s1.clone());
            reply.ok();
        }
    });
    let t2 = thread::spawn(move || {
        for i in 50..100u64 {
            let reply: ReplyEmpty = Reply::new(i, s2.clone());
            reply.ok();
        }
    });

    t1.join().unwrap();
    t2.join().unwrap();

    let raw = sender.take_data();
    assert_eq!(raw.len(), 1600, "100 replies * 16 bytes = 1600");
}

#[test]
fn concurrent_take_data_and_send() {
    use std::thread;

    let sender = CapturingSender::new();
    let s_write = sender.clone();
    let s_read = sender.clone();

    let writer = thread::spawn(move || {
        for i in 0..20u64 {
            let reply: ReplyEmpty = Reply::new(i, s_write.clone());
            reply.ok();
        }
    });

    // Meanwhile, take_data on the reader should not panic
    for _ in 0..5 {
        let _snap = s_read.data();
        thread::yield_now();
    }

    writer.join().unwrap();
    assert!(!sender.data().is_empty());
}

// ===================================================================
// File I/O Lifecycle via Internal Filesystem State
// ===================================================================
/// In-memory filesystem node
#[allow(dead_code)]
struct Inode {
    ino: u64,
    kind: FileType,
    data: Vec<u8>,
    nlink: u32,
}

/// A minimal test filesystem that tracks inodes and directory entries.
/// Used to verify inter-operation state consistency.
struct TestFS {
    inodes: Mutex<HashMap<u64, Inode>>,
    dir_entries: Mutex<HashMap<(u64, String), u64>>,
    next_ino: Mutex<u64>,
}

impl TestFS {
    fn new() -> Self {
        let mut inodes = HashMap::new();
        let root = Inode {
            ino: 1,
            kind: FileType::Directory,
            data: Vec::new(),
            nlink: 2,
        };
        inodes.insert(1, root);
        Self {
            inodes: Mutex::new(inodes),
            dir_entries: Mutex::new(HashMap::new()),
            next_ino: Mutex::new(2),
        }
    }

    fn alloc_ino(&self) -> u64 {
        let mut next = self.next_ino.lock().unwrap();
        let ino = *next;
        *next += 1;
        ino
    }

    fn create_file(&self, parent: u64, name: &str) -> u64 {
        let ino = self.alloc_ino();
        let inode = Inode {
            ino,
            kind: FileType::RegularFile,
            data: vec![],
            nlink: 1,
        };
        self.inodes.lock().unwrap().insert(ino, inode);
        self.dir_entries
            .lock()
            .unwrap()
            .insert((parent, name.to_string()), ino);
        ino
    }

    fn write_data(&self, ino: u64, offset: usize, data: &[u8]) {
        let mut inodes = self.inodes.lock().unwrap();
        let inode = inodes.get_mut(&ino).expect("inode not found");
        let end = offset + data.len();
        if end > inode.data.len() {
            inode.data.resize(end, 0);
        }
        inode.data[offset..end].copy_from_slice(data);
    }

    fn read_data(&self, ino: u64, offset: usize, len: usize) -> Vec<u8> {
        let inodes = self.inodes.lock().unwrap();
        let inode = inodes.get(&ino).expect("inode not found");
        let end = (offset + len).min(inode.data.len());
        if offset >= inode.data.len() {
            vec![]
        } else {
            inode.data[offset..end].to_vec()
        }
    }

    fn lookup(&self, parent: u64, name: &str) -> Option<u64> {
        let entries = self.dir_entries.lock().unwrap();
        entries.get(&(parent, name.to_string())).copied()
    }

    fn unlink(&self, parent: u64, name: &str) -> bool {
        let mut entries = self.dir_entries.lock().unwrap();
        if let Some(&ino) = entries.get(&(parent, name.to_string())) {
            entries.remove(&(parent, name.to_string()));
            let mut inodes = self.inodes.lock().unwrap();
            if let Some(inode) = inodes.get_mut(&ino) {
                inode.nlink -= 1;
            }
            true
        } else {
            false
        }
    }

    fn get_size(&self, ino: u64) -> u64 {
        let inodes = self.inodes.lock().unwrap();
        inodes.get(&ino).map(|i| i.data.len() as u64).unwrap_or(0)
    }
}

#[test]
fn testfs_create_write_read_unlink_lifecycle() {
    let fs = TestFS::new();
    let parent = 1u64;
    let name = "test.txt";

    // Create
    let ino = fs.create_file(parent, name);
    assert!(ino >= 2);
    assert_eq!(fs.lookup(parent, name), Some(ino));
    assert_eq!(fs.get_size(ino), 0);

    // Write
    let data = b"Hello TideFS! This is integration test data.";
    fs.write_data(ino, 0, data);
    assert_eq!(fs.get_size(ino), data.len() as u64);

    // Read full
    let read_back = fs.read_data(ino, 0, data.len());
    assert_eq!(&read_back, data);

    // Read partial at offset 6
    let partial = fs.read_data(ino, 6, 10);
    assert_eq!(&partial, b"TideFS! Th");

    // Write at offset (overwrite middle)
    fs.write_data(ino, 6, b"WORLD!");
    let modified = fs.read_data(ino, 0, data.len());
    assert_eq!(&modified[0..6], b"Hello ");
    assert_eq!(&modified[6..12], b"WORLD!");

    // Extend the file
    let append = b" Extended!";
    let current_len = fs.get_size(ino) as usize;
    fs.write_data(ino, current_len, append);
    assert_eq!(fs.get_size(ino), (current_len + append.len()) as u64);

    // Read the full extended content
    let full = fs.read_data(ino, 0, current_len + append.len());
    assert_eq!(&full[0..6], b"Hello ");
    assert_eq!(&full[6..12], b"WORLD!");
    assert_eq!(&full[full.len() - append.len()..], append);

    // Unlink
    assert!(fs.unlink(parent, name));
    assert_eq!(fs.lookup(parent, name), None);
}

#[test]
fn testfs_create_multiple_files_in_same_directory() {
    let fs = TestFS::new();
    let parent = 1u64;

    let f1 = fs.create_file(parent, "a.txt");
    let f2 = fs.create_file(parent, "b.txt");
    let f3 = fs.create_file(parent, "c.txt");

    assert_ne!(f1, f2);
    assert_ne!(f2, f3);
    assert_ne!(f1, f3);

    assert_eq!(fs.lookup(parent, "a.txt"), Some(f1));
    assert_eq!(fs.lookup(parent, "b.txt"), Some(f2));
    assert_eq!(fs.lookup(parent, "c.txt"), Some(f3));
    assert_eq!(fs.lookup(parent, "d.txt"), None);
}

#[test]
fn testfs_write_at_offset_past_end_pads_with_zeroes() {
    let fs = TestFS::new();
    let ino = fs.create_file(1, "sparse");

    // Write at offset 100
    fs.write_data(ino, 100, b"tail");
    assert_eq!(fs.get_size(ino), 104);

    let data = fs.read_data(ino, 0, 104);
    assert_eq!(&data[0..100], &vec![0u8; 100][..]);
    assert_eq!(&data[100..104], b"tail");
}

#[test]
fn testfs_read_at_offset_past_end_returns_empty() {
    let fs = TestFS::new();
    let ino = fs.create_file(1, "small");
    fs.write_data(ino, 0, b"data");

    let result = fs.read_data(ino, 100, 50);
    assert!(result.is_empty());
}

#[test]
fn testfs_write_at_offset_zero_on_empty_file() {
    let fs = TestFS::new();
    let ino = fs.create_file(1, "empty_write");
    fs.write_data(ino, 0, b"first bytes");
    assert_eq!(fs.read_data(ino, 0, 11), b"first bytes");
}

#[test]
fn testfs_overwrite_exact_boundary() {
    let fs = TestFS::new();
    let ino = fs.create_file(1, "boundary");
    fs.write_data(ino, 0, b"AAAA");
    fs.write_data(ino, 4, b"BBBB");
    assert_eq!(fs.read_data(ino, 0, 8), b"AAAABBBB");
    // Overwrite exactly at boundary
    fs.write_data(ino, 4, b"CCCC");
    assert_eq!(fs.read_data(ino, 0, 8), b"AAAACCCC");
}

// ===================================================================
// Unlink: state consistency
// ===================================================================

#[test]
fn testfs_unlink_nonexistent_returns_false() {
    let fs = TestFS::new();
    assert!(!fs.unlink(1, "no_such_file"));
}

#[test]
fn testfs_unlink_twice_second_fails() {
    let fs = TestFS::new();
    let ino = fs.create_file(1, "unlink_me");
    assert!(fs.unlink(1, "unlink_me"));
    assert!(!fs.unlink(1, "unlink_me"));
    // nlink should be 0 after unlink
    let inodes = fs.inodes.lock().unwrap();
    assert_eq!(inodes.get(&ino).unwrap().nlink, 0);
}

#[test]
fn testfs_lookup_nonexistent_returns_none() {
    let fs = TestFS::new();
    assert_eq!(fs.lookup(1, "nonexistent"), None);
}

#[test]
fn testfs_create_unlink_recreate_same_name() {
    let fs = TestFS::new();
    let ino1 = fs.create_file(1, "recreate");
    fs.write_data(ino1, 0, b"version 1");
    assert!(fs.unlink(1, "recreate"));

    let ino2 = fs.create_file(1, "recreate");
    assert_ne!(ino1, ino2, "new inode should be different");
    fs.write_data(ino2, 0, b"version 2");
    assert_eq!(fs.read_data(ino2, 0, 9), b"version 2");
}

// ===================================================================
// FileAttr round-trip and FileType coverage
// ===================================================================

#[test]
fn file_attr_inode_roundtrips_through_attr() {
    let attr = FileAttr {
        ino: 0xdeadbeef,
        size: 8192,
        blocks: 16,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    };
    assert_eq!(attr.ino, 0xdeadbeef);
    assert_eq!(attr.size, 8192);
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.perm, 0o644);
}

#[test]
fn file_type_all_variants_distinct() {
    let types = [
        FileType::NamedPipe,
        FileType::CharDevice,
        FileType::BlockDevice,
        FileType::Directory,
        FileType::RegularFile,
        FileType::Symlink,
        FileType::Socket,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

// ===================================================================
// Filesystem trait object-safety with various types
// ===================================================================

#[test]
fn filesystem_trait_send_impl() {
    struct SendFS;
    impl Filesystem for SendFS {}
    let fs = SendFS;
    let _: &dyn Filesystem = &fs;
}

#[test]
fn filesystem_trait_nonsend_impl() {
    use std::rc::Rc;
    #[allow(dead_code)]
    struct NonSendFS(Rc<Vec<u8>>);
    #[allow(dead_code)]
    impl Filesystem for NonSendFS {}
    let fs = NonSendFS(Rc::new(Vec::new()));
    let _: &dyn Filesystem = &fs;
}

#[test]
fn filesystem_with_default_impls_compiles() {
    struct MinimalFS;
    impl Filesystem for MinimalFS {}
    let _fs = MinimalFS;
}
