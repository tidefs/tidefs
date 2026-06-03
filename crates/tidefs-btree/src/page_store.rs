//! Page-level persistent storage for B+tree pages.
//!
//! The [`PageStore`] trait provides write and read operations on
//! fixed-size 4096-byte [`BtreePage`] objects keyed by a `u32`
//! page identifier. Implementations may back pages with segment
//! files, raw devices, or in-memory buffers.
//!
//! [`MemPageStore`] is an in-memory implementation suitable for
//! testing and single-node operation.

use crate::page::BtreePage;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// PageStore trait
// ---------------------------------------------------------------------------

/// Trait for persistent page storage.
///
/// Each page is a full [`BtreePage`] (4096 bytes). The page identifier
/// space is managed by the caller; the store returns an error when
/// asked for a page that was never written.
pub trait PageStore {
    /// Persist a full page.  Returns `Ok(())` on success.
    fn write_page(&mut self, page_id: u32, page: &BtreePage) -> Result<(), PageStoreError>;

    /// Read back a previously written page.
    fn read_page(&self, page_id: u32) -> Result<BtreePage, PageStoreError>;
}

// ---------------------------------------------------------------------------
// PageStoreError
// ---------------------------------------------------------------------------

/// Errors from [`PageStore`] operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageStoreError {
    /// The requested page was not found.
    NotFound(u32),
    /// I/O or storage-layer error.
    Io(alloc::string::String),
}

impl fmt::Display for PageStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "page {id} not found"),
            Self::Io(s) => write!(f, "page store I/O error: {s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// MemPageStore
// ---------------------------------------------------------------------------

/// An in-memory [`PageStore`] backed by a `Vec<Option<BtreePage>>`.
///
/// Useful for testing persistence logic without a real storage backend.
#[derive(Clone, Debug, Default)]
pub struct MemPageStore {
    pages: Vec<Option<BtreePage>>,
}

impl MemPageStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self { pages: Vec::new() }
    }

    /// Number of pages stored (including holes).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.pages.len()
    }
}

impl PageStore for MemPageStore {
    fn write_page(&mut self, page_id: u32, page: &BtreePage) -> Result<(), PageStoreError> {
        let idx = page_id as usize;
        if idx >= self.pages.len() {
            self.pages.resize(idx + 1, None);
        }
        self.pages[idx] = Some(*page);
        Ok(())
    }

    fn read_page(&self, page_id: u32) -> Result<BtreePage, PageStoreError> {
        let idx = page_id as usize;
        self.pages
            .get(idx)
            .and_then(|o| *o)
            .ok_or(PageStoreError::NotFound(page_id))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::blank_page;
    use alloc::format;

    #[test]
    fn mem_store_write_and_read() {
        let mut store = MemPageStore::new();
        let mut page = blank_page();
        page[0] = 0xAB;
        store.write_page(0, &page).unwrap();
        let read = store.read_page(0).unwrap();
        assert_eq!(read[0], 0xAB);
    }

    #[test]
    fn mem_store_not_found() {
        let store = MemPageStore::new();
        assert!(matches!(
            store.read_page(42),
            Err(PageStoreError::NotFound(42))
        ));
    }

    #[test]
    fn mem_store_overwrite() {
        let mut store = MemPageStore::new();
        let mut page1 = blank_page();
        page1[0] = 1;
        store.write_page(0, &page1).unwrap();

        let mut page2 = blank_page();
        page2[0] = 2;
        store.write_page(0, &page2).unwrap();

        assert_eq!(store.read_page(0).unwrap()[0], 2);
    }

    #[test]
    fn mem_store_sparse_pages() {
        let mut store = MemPageStore::new();
        let page = blank_page();
        store.write_page(5, &page).unwrap();
        // Pages 0-4 are holes
        assert!(matches!(
            store.read_page(0),
            Err(PageStoreError::NotFound(0))
        ));
        assert!(store.read_page(5).is_ok());
        assert_eq!(store.capacity(), 6);
    }

    #[test]
    fn page_store_error_display() {
        let e = PageStoreError::NotFound(7);
        assert!(!format!("{e}").is_empty());

        let e = PageStoreError::Io("disk full".into());
        assert!(!format!("{e}").is_empty());
    }
}
