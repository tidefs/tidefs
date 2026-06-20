// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_types_vfs_core::{InodeId, ROOT_INODE_ID};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatasetInodeAuthority {
    dataset_id: [u8; 16],
    root_inode_id: InodeId,
    next_inode_id: u64,
}

impl Default for DatasetInodeAuthority {
    fn default() -> Self {
        Self {
            dataset_id: [0u8; 16],
            root_inode_id: ROOT_INODE_ID,
            next_inode_id: 0,
        }
    }
}

impl DatasetInodeAuthority {
    pub(crate) fn fresh_root(dataset_id: [u8; 16]) -> Self {
        Self::from_recovered_next_inode_id(dataset_id, ROOT_INODE_ID.get().saturating_add(1))
    }

    pub(crate) fn from_recovered_next_inode_id(dataset_id: [u8; 16], next_inode_id: u64) -> Self {
        Self {
            dataset_id,
            root_inode_id: ROOT_INODE_ID,
            next_inode_id: next_inode_id.max(ROOT_INODE_ID.get().saturating_add(1)),
        }
    }

    pub(crate) fn from_recovered_inode_ids(
        dataset_id: [u8; 16],
        next_inode_id: u64,
        inode_ids: impl IntoIterator<Item = InodeId>,
    ) -> Self {
        let mut authority = Self::from_recovered_next_inode_id(dataset_id, next_inode_id);
        for inode_id in inode_ids {
            authority.observe_explicit_inode(inode_id);
        }
        authority
    }

    pub(crate) fn with_dataset_id(mut self, dataset_id: [u8; 16]) -> Self {
        self.dataset_id = dataset_id;
        self
    }

    pub(crate) fn dataset_id(&self) -> [u8; 16] {
        self.dataset_id
    }

    pub(crate) fn root_inode_id(&self) -> InodeId {
        self.root_inode_id
    }

    pub(crate) fn next_inode_id(&self) -> InodeId {
        InodeId::new(
            self.next_inode_id
                .max(self.root_inode_id.get().saturating_add(1)),
        )
    }

    pub(crate) fn next_inode_id_raw(&self) -> u64 {
        self.next_inode_id
    }

    pub(crate) fn allocate(&mut self) -> InodeId {
        let inode_id = self.next_inode_id();
        self.next_inode_id = inode_id.get().saturating_add(1);
        inode_id
    }

    pub(crate) fn observe_explicit_inode(&mut self, inode_id: InodeId) {
        if inode_id.get() == 0 {
            return;
        }
        self.next_inode_id = self.next_inode_id.max(inode_id.get().saturating_add(1));
    }
}
