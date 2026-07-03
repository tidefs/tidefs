// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unreachable_pub,
    clippy::derivable_impls,
    clippy::double_must_use,
    clippy::empty_line_after_doc_comments,
    clippy::manual_div_ceil,
    clippy::needless_range_loop,
    clippy::result_unit_err,
    clippy::wrong_self_convention
)]

extern crate alloc as rust_alloc;
extern crate self as kernel;

pub mod alloc {
    use core::marker::PhantomData;

    pub mod allocator {
        #[derive(Debug)]
        pub struct Kmalloc;
    }

    pub mod flags {
        pub const GFP_KERNEL: u32 = 0;
    }

    pub type KBox<T> = ::rust_alloc::boxed::Box<T>;

    #[derive(Debug, PartialEq, Eq)]
    pub struct KVec<T> {
        inner: ::rust_alloc::vec::Vec<T>,
    }

    impl<T> KVec<T> {
        pub const fn new() -> Self {
            Self {
                inner: ::rust_alloc::vec::Vec::new(),
            }
        }

        pub fn with_capacity(capacity: usize, _flags: u32) -> Result<Self, ()> {
            Ok(Self {
                inner: ::rust_alloc::vec::Vec::with_capacity(capacity),
            })
        }

        pub fn from_elem(value: T, n: usize, _flags: u32) -> Result<Self, ()>
        where
            T: Clone,
        {
            Ok(Self {
                inner: ::rust_alloc::vec![value; n],
            })
        }

        pub fn push(&mut self, value: T, _flags: u32) -> Result<(), ()> {
            self.inner.push(value);
            Ok(())
        }

        pub fn resize(&mut self, new_len: usize, value: T, _flags: u32) -> Result<(), ()>
        where
            T: Clone,
        {
            self.inner.resize(new_len, value);
            Ok(())
        }

        pub fn extend_from_slice(&mut self, other: &[T], _flags: u32) -> Result<(), ()>
        where
            T: Clone,
        {
            self.inner.extend_from_slice(other);
            Ok(())
        }

        pub fn len(&self) -> usize {
            self.inner.len()
        }

        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub fn capacity(&self) -> usize {
            self.inner.capacity()
        }

        pub fn clear(&mut self) {
            self.inner.clear();
        }

        pub fn pop(&mut self) -> Option<T> {
            self.inner.pop()
        }

        pub fn reserve(&mut self, additional: usize, _flags: u32) -> Result<(), ()> {
            self.inner.reserve(additional);
            Ok(())
        }

        pub fn truncate(&mut self, len: usize) {
            self.inner.truncate(len);
        }

        pub fn remove(&mut self, index: usize) -> Result<T, ()> {
            if index < self.inner.len() {
                Ok(self.inner.remove(index))
            } else {
                Err(())
            }
        }

        pub fn insert_within_capacity(&mut self, index: usize, element: T) -> Result<(), ()> {
            if index <= self.inner.len() {
                self.inner.insert(index, element);
                Ok(())
            } else {
                Err(())
            }
        }

        pub fn retain(&mut self, f: impl FnMut(&mut T) -> bool) {
            self.inner.retain_mut(f);
        }

        pub fn as_slice(&self) -> &[T] {
            self.inner.as_slice()
        }

        pub fn as_mut_slice(&mut self) -> &mut [T] {
            self.inner.as_mut_slice()
        }
    }

    impl<T> Default for KVec<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<T> core::ops::Deref for KVec<T> {
        type Target = [T];

        fn deref(&self) -> &[T] {
            self.inner.as_slice()
        }
    }

    impl<T> core::ops::DerefMut for KVec<T> {
        fn deref_mut(&mut self) -> &mut [T] {
            self.inner.as_mut_slice()
        }
    }

    impl<T: Clone> Clone for KVec<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    pub struct IntoIter<T, A = allocator::Kmalloc> {
        inner: ::rust_alloc::vec::IntoIter<T>,
        _allocator: PhantomData<A>,
    }

    impl<T, A> Iterator for IntoIter<T, A> {
        type Item = T;

        fn next(&mut self) -> Option<Self::Item> {
            self.inner.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            self.inner.size_hint()
        }
    }

    impl<T, A> ExactSizeIterator for IntoIter<T, A> {}

    impl<T> IntoIterator for KVec<T> {
        type Item = T;
        type IntoIter = IntoIter<T, allocator::Kmalloc>;

        fn into_iter(self) -> Self::IntoIter {
            IntoIter {
                inner: self.inner.into_iter(),
                _allocator: PhantomData,
            }
        }
    }
}

mod tidefs_kmod_bridge {
    pub mod kernel_types {
        pub use crate::kernel_types_impl::*;
    }
}

#[path = "../src/kernel_types.rs"]
mod kernel_types_impl;

use kernel_types_impl::{
    pack_posix_xattr_name_list, DatasetXattrPolicy, KmodVec, XattrNameListError, XattrStore,
    XattrStoreError,
};

const XATTR_CREATE: u32 = 0x01;
const XATTR_REPLACE: u32 = 0x02;

fn policy() -> DatasetXattrPolicy {
    DatasetXattrPolicy::new(32, 4096, 0, 0)
}

fn kvec(bytes: &[u8]) -> KmodVec<u8> {
    let mut out = KmodVec::<u8>::with_capacity(bytes.len());
    out.extend_from_slice(bytes);
    out
}

fn bridge_like_set(
    store: &mut XattrStore,
    name: &[u8],
    value: &[u8],
    flags: u32,
) -> Result<(), &'static str> {
    if flags > XATTR_REPLACE || flags == (XATTR_CREATE | XATTR_REPLACE) {
        return Err("EINVAL");
    }

    let exists = store.contains(name);
    match flags {
        XATTR_CREATE if exists => return Err("EEXIST"),
        XATTR_REPLACE if !exists => return Err("ENODATA"),
        _ => {}
    }

    store.set(name, value, flags as u8);
    Ok(())
}

#[test]
fn kbuild_xattr_store_roundtrips_and_updates() {
    let mut store = XattrStore::new(policy());
    assert!(store.is_empty());
    assert!(!store.has_acl());

    let acl_store = XattrStore::new_with_acl(policy());
    assert!(acl_store.has_acl());

    assert_eq!(store.set(b"user.key", b"one", 0), None);
    assert_eq!(store.len(), 1);
    assert_eq!(store.version(), 1);
    assert_eq!(&store.get(b"user.key").unwrap()[..], b"one");

    let previous = store.set(b"user.key", b"two", 0).unwrap();
    assert_eq!(&previous[..], b"one");
    assert_eq!(store.len(), 1);
    assert_eq!(store.version(), 2);
    assert_eq!(&store.get(b"user.key").unwrap()[..], b"two");

    assert_eq!(store.remove(b"user.key"), Ok(()));
    assert_eq!(
        store.remove(b"user.key"),
        Err(XattrStoreError::EntryNotFound)
    );
    assert!(store.is_empty());
    assert_eq!(store.version(), 3);
}

#[test]
fn kbuild_xattr_store_supports_bridge_create_replace_preconditions() {
    let mut store = XattrStore::new(policy());

    assert_eq!(
        bridge_like_set(&mut store, b"user.missing", b"v", XATTR_REPLACE),
        Err("ENODATA")
    );
    assert_eq!(
        bridge_like_set(&mut store, b"user.dup", b"first", XATTR_CREATE),
        Ok(())
    );
    assert_eq!(
        bridge_like_set(&mut store, b"user.dup", b"second", XATTR_CREATE),
        Err("EEXIST")
    );
    assert_eq!(
        bridge_like_set(&mut store, b"user.dup", b"second", XATTR_REPLACE),
        Ok(())
    );
    assert_eq!(&store.get(b"user.dup").unwrap()[..], b"second");
}

#[test]
fn kbuild_xattr_store_lists_packed_names_deterministically() {
    let mut store = XattrStore::new(policy());
    assert_eq!(store.list_posix_name_bytes(), Ok(KmodVec::<u8>::new()));

    store.set(b"user.z", b"last", 0);
    store.set(b"security.selinux", b"context", 0);
    store.set(b"user.a", b"first", 0);

    assert_eq!(
        store.list_posix_name_bytes(),
        Ok(kvec(b"security.selinux\0user.a\0user.z\0"))
    );
}

#[test]
fn kbuild_xattr_store_keeps_per_inode_store_isolation() {
    let mut ino_one = XattrStore::new(policy());
    let mut ino_two = XattrStore::new(policy());

    ino_one.set(b"user.shared", b"one", 0);
    ino_two.set(b"user.shared", b"two", 0);
    ino_one.remove(b"user.shared").unwrap();

    assert_eq!(ino_one.get(b"user.shared"), None);
    assert_eq!(&ino_two.get(b"user.shared").unwrap()[..], b"two");
}

#[test]
fn kbuild_pack_posix_xattr_name_list_rejects_invalid_or_duplicate_names() {
    let duplicate = [kvec(b"user.a"), kvec(b"user.a")];
    assert_eq!(
        pack_posix_xattr_name_list(&duplicate),
        Err(XattrNameListError::DuplicateName)
    );

    let embedded_nul = [kvec(b"user.\0bad")];
    assert_eq!(
        pack_posix_xattr_name_list(&embedded_nul),
        Err(XattrNameListError::NameContainsNul)
    );

    let empty = [KmodVec::<u8>::new()];
    assert_eq!(
        pack_posix_xattr_name_list(&empty),
        Err(XattrNameListError::EmptyName)
    );

    let too_long = [kvec(&[b'a'; 256])];
    assert_eq!(
        pack_posix_xattr_name_list(&too_long),
        Err(XattrNameListError::NameTooLong { len: 256, max: 255 })
    );
}
