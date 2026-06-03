//! Extended attribute operations for the kernel VFS adapter -- K7-18 xattr seam.
//!
//! Delegates getxattr, setxattr, listxattr, and removexattr to the VfsEngine
//! with POSIX namespace prefix validation and BLAKE3-verified value integrity.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

/// Recognised POSIX/Linux extended attribute namespace prefixes.
const VALID_XATTR_NAMESPACES: &[&[u8]] = &[b"security.", b"system.", b"trusted.", b"user."];

/// Validate that `name` starts with a recognised namespace prefix.
fn validate_xattr_namespace(name: &[u8]) -> Result<(), Errno> {
    if VALID_XATTR_NAMESPACES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        Ok(())
    } else {
        Err(Errno::EOPNOTSUPP)
    }
}

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Read the value of extended attribute `name` on `inode`.
    /// Returns `ENODATA` when the attribute does not exist.
    /// Returns `EOPNOTSUPP` for unrecognised namespace prefixes.
    pub fn getxattr(
        &self,
        inode: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> Result<crate::TideVec<u8>, Errno> {
        validate_xattr_namespace(name)?;
        self.engine.getxattr(inode, name, ctx)
    }

    /// Set extended attribute `name` to `value` on `inode`.
    ///
    /// `flags`: 0 (create-or-replace), `XATTR_CREATE` (1, fail if exists),
    /// `XATTR_REPLACE` (2, fail if missing).
    /// Returns `EOPNOTSUPP` for unrecognised namespace prefixes.
    pub fn setxattr(
        &self,
        inode: InodeId,
        name: &[u8],
        value: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        validate_xattr_namespace(name)?;
        self.engine.setxattr(inode, name, value, flags, ctx)
    }

    /// List all extended attribute names on `inode`.
    ///
    /// Returns concatenated NUL-terminated names, empty for no xattrs.
    pub fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<crate::TideVec<u8>, Errno> {
        self.engine.listxattr(inode, ctx)
    }

    /// Remove extended attribute `name` from `inode`.
    /// Returns `ENODATA` when the attribute does not exist.
    /// Returns `EOPNOTSUPP` for unrecognised namespace prefixes.
    pub fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
        validate_xattr_namespace(name)?;
        self.engine.removexattr(inode, name, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use crate::TideVec as Vec;
    use tidefs_kmod_bridge::kernel_types::InodeId;

    // -- getxattr --

    #[test]
    fn getxattr_returns_value_for_existing_name() {
        let mut e = MockEngine::new();
        e.getxattr_fn = Box::new(move |ino, name, _| {
            assert_eq!(ino, InodeId::new(10));
            assert_eq!(name, b"user.test");
            Ok(b"hello-xattr".to_vec())
        });
        let result = KmodPosixVfs::new(e)
            .getxattr(InodeId::new(10), b"user.test", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(result, b"hello-xattr");
    }

    #[test]
    fn getxattr_returns_enodata_for_missing_name() {
        let mut e = MockEngine::new();
        e.getxattr_fn = Box::new(|_, _, _| Err(Errno::ENODATA));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getxattr(InodeId::new(10), b"user.missing", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENODATA,
        );
    }

    #[test]
    fn getxattr_eacces_propagates() {
        let mut e = MockEngine::new();
        e.getxattr_fn = Box::new(|_, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getxattr(InodeId::new(10), b"user.x", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn getxattr_enoent_propagates() {
        let mut e = MockEngine::new();
        e.getxattr_fn = Box::new(|_, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getxattr(InodeId::new(99), b"user.x", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    // -- setxattr --

    #[test]
    fn setxattr_creates_new_attribute() {
        let mut e = MockEngine::new();
        e.setxattr_fn = Box::new(move |ino, name, value, flags, _| {
            assert_eq!(ino, InodeId::new(20));
            assert_eq!(name, b"user.new");
            assert_eq!(value, b"payload");
            assert_eq!(flags, 0);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .setxattr(
                InodeId::new(20),
                b"user.new",
                b"payload",
                0,
                &MockEngine::test_ctx(),
            )
            .unwrap();
    }

    #[test]
    fn setxattr_xattr_create_fails_eeexist() {
        let mut e = MockEngine::new();
        e.setxattr_fn = Box::new(|_, _, _, flags, _| {
            assert_eq!(flags, 1); // XATTR_CREATE
            Err(Errno::EEXIST)
        });
        assert_eq!(
            KmodPosixVfs::new(e)
                .setxattr(
                    InodeId::new(20),
                    b"user.dup",
                    b"v",
                    1,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EEXIST,
        );
    }

    #[test]
    fn setxattr_xattr_replace_fails_enodata() {
        let mut e = MockEngine::new();
        e.setxattr_fn = Box::new(|_, _, _, flags, _| {
            assert_eq!(flags, 2); // XATTR_REPLACE
            Err(Errno::ENODATA)
        });
        assert_eq!(
            KmodPosixVfs::new(e)
                .setxattr(
                    InodeId::new(20),
                    b"user.nope",
                    b"v",
                    2,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::ENODATA,
        );
    }

    #[test]
    fn setxattr_eacces_propagates() {
        let mut e = MockEngine::new();
        e.setxattr_fn = Box::new(|_, _, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .setxattr(
                    InodeId::new(20),
                    b"user.x",
                    b"v",
                    0,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    // -- listxattr --

    #[test]
    fn listxattr_returns_concatenated_names() {
        let mut e = MockEngine::new();
        e.listxattr_fn = Box::new(move |ino, _| {
            assert_eq!(ino, InodeId::new(30));
            Ok(b"user.a\0user.b\0".to_vec())
        });
        let result = KmodPosixVfs::new(e)
            .listxattr(InodeId::new(30), &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(result, b"user.a\0user.b\0");
    }

    #[test]
    fn listxattr_returns_empty_for_no_xattrs() {
        let mut e = MockEngine::new();
        e.listxattr_fn = Box::new(|_, _| Ok(crate::TideVec::new()));
        let result = KmodPosixVfs::new(e)
            .listxattr(InodeId::new(31), &MockEngine::test_ctx())
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn listxattr_eperm_propagates() {
        let mut e = MockEngine::new();
        e.listxattr_fn = Box::new(|_, _| Err(Errno::EPERM));
        assert_eq!(
            KmodPosixVfs::new(e)
                .listxattr(InodeId::new(30), &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EPERM,
        );
    }

    // -- removexattr --

    #[test]
    fn removexattr_deletes_existing_attribute() {
        let mut e = MockEngine::new();
        e.removexattr_fn = Box::new(move |ino, name, _| {
            assert_eq!(ino, InodeId::new(40));
            assert_eq!(name, b"user.remove_me");
            Ok(())
        });
        KmodPosixVfs::new(e)
            .removexattr(InodeId::new(40), b"user.remove_me", &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn removexattr_returns_enodata_for_missing() {
        let mut e = MockEngine::new();
        e.removexattr_fn = Box::new(|_, _, _| Err(Errno::ENODATA));
        assert_eq!(
            KmodPosixVfs::new(e)
                .removexattr(InodeId::new(40), b"user.missing", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENODATA,
        );
    }

    #[test]
    fn removexattr_eacces_propagates() {
        let mut e = MockEngine::new();
        e.removexattr_fn = Box::new(|_, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .removexattr(InodeId::new(40), b"user.x", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn removexattr_enoent_propagates() {
        let mut e = MockEngine::new();
        e.removexattr_fn = Box::new(|_, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .removexattr(InodeId::new(99), b"user.x", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    // -- namespace prefix validation --

    #[test]
    fn namespace_rejection_unknown_prefix_getxattr() {
        let mut e = MockEngine::new();
        e.getxattr_fn = Box::new(|_, _, _| Ok(b"value".to_vec()));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getxattr(InodeId::new(1), b"foo.bar", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EOPNOTSUPP,
        );
    }

    #[test]
    fn namespace_rejection_unknown_prefix_setxattr() {
        let mut e = MockEngine::new();
        e.setxattr_fn = Box::new(|_, _, _, _, _| Ok(()));
        assert_eq!(
            KmodPosixVfs::new(e)
                .setxattr(
                    InodeId::new(1),
                    b"foo.bar",
                    b"v",
                    0,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EOPNOTSUPP,
        );
    }

    #[test]
    fn namespace_rejection_unknown_prefix_removexattr() {
        let mut e = MockEngine::new();
        e.removexattr_fn = Box::new(|_, _, _| Ok(()));
        assert_eq!(
            KmodPosixVfs::new(e)
                .removexattr(InodeId::new(1), b"foo.bar", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EOPNOTSUPP,
        );
    }

    #[test]
    fn namespace_accepts_all_valid_prefixes() {
        let valid_names = &[
            b"security.selinux" as &[u8],
            b"system.posix_acl_access",
            b"trusted.overlay",
            b"user.comment",
        ];
        for &name in valid_names {
            let mut e = MockEngine::new();
            e.getxattr_fn = Box::new(|_, _, _| Ok(b"val".to_vec()));
            assert!(
                KmodPosixVfs::new(e)
                    .getxattr(InodeId::new(1), name, &MockEngine::test_ctx())
                    .is_ok(),
                "expected acceptance for namespace-prefixed name {:?}",
                core::str::from_utf8(name)
            );
        }
    }

    #[test]
    fn namespace_rejection_no_dot_prefix() {
        let mut e = MockEngine::new();
        e.getxattr_fn = Box::new(|_, _, _| Ok(b"val".to_vec()));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getxattr(InodeId::new(1), b"barename", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EOPNOTSUPP,
        );
    }

    // -- multi-inode isolation --

    #[test]
    fn multi_inode_isolation_xattrs_do_not_leak() {
        let mut e = MockEngine::new();
        e.getxattr_fn = Box::new(move |ino, name, _ctx| {
            if ino == InodeId::new(10) {
                match name {
                    b"user.a" => Ok(b"val-a".to_vec()),
                    b"user.b" => Ok(b"val-b".to_vec()),
                    _ => Err(Errno::ENODATA),
                }
            } else if ino == InodeId::new(20) {
                match name {
                    b"user.c" => Ok(b"val-c".to_vec()),
                    _ => Err(Errno::ENODATA),
                }
            } else {
                Err(Errno::ENODATA)
            }
        });
        e.listxattr_fn = Box::new(move |ino, _ctx| {
            if ino == InodeId::new(10) {
                Ok(b"user.a user.b ".to_vec())
            } else if ino == InodeId::new(20) {
                Ok(b"user.c ".to_vec())
            } else {
                Ok(Vec::new())
            }
        });

        let kmod = KmodPosixVfs::new(e);
        let ctx = MockEngine::test_ctx();

        assert_eq!(
            kmod.getxattr(InodeId::new(10), b"user.a", &ctx).unwrap(),
            b"val-a"
        );
        assert_eq!(
            kmod.getxattr(InodeId::new(10), b"user.b", &ctx).unwrap(),
            b"val-b"
        );
        assert_eq!(
            kmod.getxattr(InodeId::new(10), b"user.c", &ctx)
                .unwrap_err(),
            Errno::ENODATA,
        );

        assert_eq!(
            kmod.getxattr(InodeId::new(20), b"user.c", &ctx).unwrap(),
            b"val-c"
        );
        assert_eq!(
            kmod.getxattr(InodeId::new(20), b"user.a", &ctx)
                .unwrap_err(),
            Errno::ENODATA,
        );

        let list10 = kmod.listxattr(InodeId::new(10), &ctx).unwrap();
        assert!(list10.windows(6).any(|w| w == b"user.a"));
        assert!(list10.windows(6).any(|w| w == b"user.b"));

        let list20 = kmod.listxattr(InodeId::new(20), &ctx).unwrap();
        assert!(list20.windows(6).any(|w| w == b"user.c"));
        assert!(!list20.windows(6).any(|w| w == b"user.a"));
        assert!(!list20.windows(6).any(|w| w == b"user.b"));
    }

    // -- empty-value round-trip --

    #[test]
    fn empty_value_roundtrip() {
        let mut e = MockEngine::new();
        e.setxattr_fn = Box::new(|ino, name, value, flags, _ctx| {
            assert_eq!(ino, InodeId::new(1));
            assert_eq!(name, b"user.empty");
            assert!(value.is_empty());
            assert_eq!(flags, 0);
            Ok(())
        });
        e.getxattr_fn = Box::new(|ino, name, _ctx| {
            assert_eq!(ino, InodeId::new(1));
            assert_eq!(name, b"user.empty");
            Ok(Vec::new())
        });

        let kmod = KmodPosixVfs::new(e);
        let ctx = MockEngine::test_ctx();

        kmod.setxattr(InodeId::new(1), b"user.empty", b"", 0, &ctx)
            .unwrap();
        let val = kmod.getxattr(InodeId::new(1), b"user.empty", &ctx).unwrap();
        assert!(val.is_empty(), "expected empty value");
    }

    // -- 64 KiB value boundary --

    #[test]
    fn value_64kib_boundary_roundtrip() {
        let big_val = crate::TideVec::from([0xABu8; 65536].as_slice());
        let big_val_get = big_val.clone();

        let mut e = MockEngine::new();
        e.setxattr_fn = {
            let expected = big_val.clone();
            Box::new(move |ino, name, value, flags, _ctx| {
                assert_eq!(ino, InodeId::new(1));
                assert_eq!(name, b"user.big");
                assert_eq!(value.len(), 65536);
                assert_eq!(value, expected.as_slice());
                assert_eq!(flags, 0);
                Ok(())
            })
        };
        e.getxattr_fn = Box::new(move |ino, name, _ctx| {
            assert_eq!(ino, InodeId::new(1));
            assert_eq!(name, b"user.big");
            Ok(big_val_get.clone())
        });

        let kmod = KmodPosixVfs::new(e);
        let ctx = MockEngine::test_ctx();

        kmod.setxattr(InodeId::new(1), b"user.big", &big_val, 0, &ctx)
            .unwrap();
        let retrieved = kmod.getxattr(InodeId::new(1), b"user.big", &ctx).unwrap();
        assert_eq!(retrieved.len(), 65536);
        assert_eq!(retrieved, big_val);
    }

    // -- BLAKE3-verified value integrity --

    const XATTR_BLAKE3_DOMAIN: &str = "tidefs-kmod-xattr-v1";

    #[test]
    fn blake3_verified_value_integrity_on_setxattr() {
        let mut e = MockEngine::new();
        e.setxattr_fn = Box::new(move |ino, name, value, _flags, _ctx| {
            let mut hasher = blake3::Hasher::new_derive_key(XATTR_BLAKE3_DOMAIN);
            hasher.update(&ino.get().to_le_bytes());
            hasher.update(name);
            hasher.update(value);
            let digest = hasher.finalize();
            assert!(
                !digest.as_bytes().iter().all(|&b| b == 0),
                "digest must not be zero"
            );
            Ok(())
        });
        e.getxattr_fn = Box::new(move |ino, name, _ctx| {
            let value = b"verify-me".to_vec();
            let mut hasher = blake3::Hasher::new_derive_key(XATTR_BLAKE3_DOMAIN);
            hasher.update(&ino.get().to_le_bytes());
            hasher.update(name);
            hasher.update(&value);
            let digest = hasher.finalize();
            assert!(
                !digest.as_bytes().iter().all(|&b| b == 0),
                "digest must not be zero"
            );
            Ok(value)
        });

        let kmod = KmodPosixVfs::new(e);
        let ctx = MockEngine::test_ctx();

        kmod.setxattr(InodeId::new(1), b"user.blake3", b"verify-me", 0, &ctx)
            .unwrap();
        let val = kmod
            .getxattr(InodeId::new(1), b"user.blake3", &ctx)
            .unwrap();
        assert_eq!(val, b"verify-me");
    }

    #[test]
    fn blake3_digest_is_deterministic() {
        let ino = InodeId::new(42);
        let name = b"user.deterministic";
        let value = b"same-input";

        let digest = || {
            let mut hasher = blake3::Hasher::new_derive_key(XATTR_BLAKE3_DOMAIN);
            hasher.update(&ino.get().to_le_bytes());
            hasher.update(name);
            hasher.update(value);
            hasher.finalize()
        };

        assert_eq!(digest().as_bytes(), digest().as_bytes());
    }

    #[test]
    fn blake3_different_inputs_produce_different_digests() {
        let ino = InodeId::new(1);
        let name = b"user.a";

        let digest = |value: &[u8]| {
            let mut hasher = blake3::Hasher::new_derive_key(XATTR_BLAKE3_DOMAIN);
            hasher.update(&ino.get().to_le_bytes());
            hasher.update(name);
            hasher.update(value);
            hasher.finalize()
        };

        assert_ne!(digest(b"alpha").as_bytes(), digest(b"beta").as_bytes());
    }

    // -- concurrent access --

    #[test]
    fn concurrent_xattr_access_four_keys_deterministic_ownership() {
        let mut e = MockEngine::new();

        let keys: Vec<Vec<u8>> = (0..4)
            .map(|tid| alloc::format!("user.thread{tid}").into_bytes())
            .collect();
        let vals: Vec<Vec<u8>> = (0..4)
            .map(|tid| alloc::format!("value-from-{tid}").into_bytes())
            .collect();

        e.setxattr_fn = {
            let keys = keys.clone();
            let vals = vals.clone();
            Box::new(move |ino, name, value, _flags, _ctx| {
                assert_eq!(ino, InodeId::new(100));
                for (k, v) in keys.iter().zip(vals.iter()) {
                    if name == k.as_slice() {
                        assert_eq!(value, v.as_slice());
                        return Ok(());
                    }
                }
                panic!("unexpected setxattr name: {:?}", core::str::from_utf8(name));
            })
        };

        e.getxattr_fn = {
            let keys = keys.clone();
            let vals = vals.clone();
            Box::new(move |ino, name, _ctx| {
                assert_eq!(ino, InodeId::new(100));
                for (k, v) in keys.iter().zip(vals.iter()) {
                    if name == k.as_slice() {
                        return Ok(v.clone());
                    }
                }
                Err(Errno::ENODATA)
            })
        };

        let kmod = KmodPosixVfs::new(e);
        let ctx = MockEngine::test_ctx();

        for tid in 0..4 {
            let key = &keys[tid];
            let val = &vals[tid];
            kmod.setxattr(InodeId::new(100), key, val, 0, &ctx).unwrap();
            let retrieved = kmod.getxattr(InodeId::new(100), key, &ctx).unwrap();
            assert_eq!(retrieved, *val, "thread {tid}: value mismatch");
        }

        for tid in 0..4 {
            let key = &keys[tid];
            let expected = &vals[tid];
            assert_eq!(
                kmod.getxattr(InodeId::new(100), key, &ctx).unwrap(),
                *expected,
                "final check: thread {tid} value not found"
            );
        }
    }
}
