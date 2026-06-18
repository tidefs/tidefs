//! Pure deterministic VFS model for TideFS trace and oracle work.
//!
//! This crate owns no runtime storage and never resolves host paths. It keeps
//! all namespace, inode, content, and fingerprint state in memory so traces can
//! compare observable filesystem semantics without depending on local runtime
//! files.
//!
//! Contract request envelopes from `tidefs-types-vfs-core` are accepted for
//! the VFS operations in the canonical contract seed, including namespace
//! mutation records that identify component operands through fixed-width
//! `VfsNameToken` values. [`ModelRequest`] remains as a path-oriented helper
//! for model tests and callers that have not moved to contract envelopes yet.

mod receipt;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

pub use receipt::{
    is_known_model_operation, ModelRunEvidenceScope, ModelRunEvidenceScopeKind, ModelRunReceipt,
    ModelRunReceiptSerializeError, ModelRunReceiptValidationError, ModelRunValidationTier,
    MODEL_RUN_RECEIPT_KNOWN_OPERATIONS,
};

use tidefs_types_vfs_core::{
    CompletionDisposition, CompletionStatus, ContractEpoch, Errno, InodeId, RequestEnvelope,
    RequestId, TideCompletion, TideRequest, TraceId, VfsNameToken, VfsRequest,
    TIDE_CONTRACT_VERSION_V1,
};

pub const ROOT_INODE_ID: InodeId = InodeId(1);
pub const MAX_MODEL_FILE_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ModelPath {
    components: Vec<String>,
}

impl ModelPath {
    #[must_use]
    pub fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Parse a model path from an absolute slash-separated string.
    ///
    /// # Errors
    ///
    /// Returns stable POSIX errno classes for model-path syntax errors:
    /// `EINVAL` for relative paths, empty components, `.`/`..`, NUL bytes, or
    /// component separators inside a component, and `ENAMETOOLONG` for a
    /// component longer than 255 bytes.
    pub fn parse_absolute(path: &str) -> Result<Self, Errno> {
        if !path.starts_with('/') {
            return Err(Errno::EINVAL);
        }
        if path == "/" {
            return Ok(Self::root());
        }

        let mut components = Vec::new();
        for component in path.split('/').skip(1) {
            validate_component(component)?;
            components.push(component.to_string());
        }

        Ok(Self { components })
    }

    /// Build a model path from already split components.
    ///
    /// # Errors
    ///
    /// Returns the same stable errno classes as [`Self::parse_absolute`].
    pub fn from_components<I, S>(components: I) -> Result<Self, Errno>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Vec::new();
        for component in components {
            let component = component.as_ref();
            validate_component(component)?;
            out.push(component.to_string());
        }
        Ok(Self { components: out })
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    #[must_use]
    pub fn display(&self) -> ModelPathDisplay<'_> {
        ModelPathDisplay(self)
    }
}

impl FromStr for ModelPath {
    type Err = Errno;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_absolute(s)
    }
}

impl fmt::Display for ModelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.display().fmt(f)
    }
}

pub struct ModelPathDisplay<'a>(&'a ModelPath);

impl fmt::Display for ModelPathDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.components.is_empty() {
            return f.write_str("/");
        }
        for component in &self.0.components {
            f.write_str("/")?;
            f.write_str(component)?;
        }
        Ok(())
    }
}

fn validate_component(component: &str) -> Result<(), Errno> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\0')
    {
        return Err(Errno::EINVAL);
    }
    if component.len() > 255 {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelNodeKind {
    Directory,
    File,
}

impl ModelNodeKind {
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        match self {
            Self::Directory => 1,
            Self::File => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelAttr {
    pub inode_id: InodeId,
    pub kind: ModelNodeKind,
    pub nlink: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelOutput {
    None,
    Bytes(Vec<u8>),
    Attr(ModelAttr),
}

impl ModelOutput {
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::None | Self::Attr(_) => None,
        }
    }

    #[must_use]
    pub fn as_attr(&self) -> Option<&ModelAttr> {
        match self {
            Self::Attr(attr) => Some(attr),
            Self::None | Self::Bytes(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelRequest {
    Create {
        path: ModelPath,
    },
    Mkdir {
        path: ModelPath,
    },
    Write {
        path: ModelPath,
        offset: u64,
        bytes: Vec<u8>,
    },
    Read {
        path: ModelPath,
        offset: u64,
        length: u64,
    },
    Fsync {
        path: ModelPath,
    },
    Rename {
        from: ModelPath,
        to: ModelPath,
    },
    Link {
        from: ModelPath,
        to: ModelPath,
    },
    Unlink {
        path: ModelPath,
    },
    Truncate {
        path: ModelPath,
        size: u64,
    },
    GetAttr {
        path: ModelPath,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractNameBinding<'a> {
    pub token: VfsNameToken,
    pub component: &'a str,
}

impl<'a> ContractNameBinding<'a> {
    #[must_use]
    pub const fn new(token: VfsNameToken, component: &'a str) -> Self {
        Self { token, component }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractModelContext<'a> {
    pub write_bytes: &'a [u8],
}

impl<'a> ContractModelContext<'a> {
    #[must_use]
    pub const fn empty() -> Self {
        Self { write_bytes: &[] }
    }

    #[must_use]
    pub const fn with_write_bytes(write_bytes: &'a [u8]) -> Self {
        Self { write_bytes }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractNameContext<'a> {
    pub bindings: &'a [ContractNameBinding<'a>],
}

impl<'a> ContractNameContext<'a> {
    #[must_use]
    pub const fn empty() -> Self {
        Self { bindings: &[] }
    }

    #[must_use]
    pub const fn new(bindings: &'a [ContractNameBinding<'a>]) -> Self {
        Self { bindings }
    }

    fn component_for(self, token: VfsNameToken) -> Result<&'a str, Errno> {
        if token == VfsNameToken::NONE {
            return Err(Errno::EINVAL);
        }

        let mut found = None;
        for binding in self.bindings {
            if binding.token != token {
                continue;
            }
            validate_component(binding.component)?;
            if VfsNameToken::from_component_bytes(binding.component.as_bytes()) != token {
                return Err(Errno::EINVAL);
            }
            match found {
                Some(existing) if existing != binding.component => return Err(Errno::EINVAL),
                Some(_) => {}
                None => found = Some(binding.component),
            }
        }

        found.ok_or(Errno::EINVAL)
    }
}

impl Default for ContractModelContext<'_> {
    fn default() -> Self {
        Self::empty()
    }
}

impl Default for ContractNameContext<'_> {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelStep {
    pub completion: TideCompletion,
    pub output: ModelOutput,
    pub fingerprint: ModelFingerprint,
}

impl ModelStep {
    #[must_use]
    pub const fn errno(&self) -> Errno {
        self.completion.errno
    }

    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.completion.errno.is_success()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ModelFingerprint([u8; 32]);

impl ModelFingerprint {
    pub const BYTE_LEN: usize = 32;

    #[must_use]
    pub const fn new(bytes: [u8; Self::BYTE_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; Self::BYTE_LEN] {
        self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(Self::BYTE_LEN * 2);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

impl fmt::Display for ModelFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelInvariantError {
    MissingRoot,
    RootWrongKind,
    RootHasParent {
        parent: InodeId,
    },
    DirectoryHasContent {
        inode_id: InodeId,
    },
    FileHasChildren {
        inode_id: InodeId,
    },
    FileHasParent {
        inode_id: InodeId,
        parent: InodeId,
    },
    ChildTargetMissing {
        parent: InodeId,
        name: String,
        target: InodeId,
    },
    DirectoryCycle {
        inode_id: InodeId,
    },
    ParentChildMismatch {
        child: InodeId,
        expected_parent: InodeId,
        actual_parent: Option<InodeId>,
    },
    DirectoryParentMissing {
        child: InodeId,
        parent: InodeId,
    },
    DirectoryParentNotDirectory {
        child: InodeId,
        parent: InodeId,
    },
    DirectoryParentDoesNotNameChild {
        child: InodeId,
        parent: InodeId,
    },
    LinkCountMismatch {
        inode_id: InodeId,
        recorded: u64,
        observed: u64,
    },
    UnreachableNode {
        inode_id: InodeId,
    },
    FileSizeOutOfBounds {
        inode_id: InodeId,
        size: u64,
    },
}

impl fmt::Display for ModelInvariantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRoot => f.write_str("model root inode is missing"),
            Self::RootWrongKind => f.write_str("model root inode is not a directory"),
            Self::RootHasParent { parent } => {
                write!(f, "model root unexpectedly has parent inode {}", parent.0)
            }
            Self::DirectoryHasContent { inode_id } => {
                write!(f, "directory inode {} has file content", inode_id.0)
            }
            Self::FileHasChildren { inode_id } => {
                write!(f, "file inode {} has directory children", inode_id.0)
            }
            Self::FileHasParent { inode_id, parent } => {
                write!(
                    f,
                    "file inode {} has directory parent {}",
                    inode_id.0, parent.0
                )
            }
            Self::ChildTargetMissing {
                parent,
                name,
                target,
            } => write!(
                f,
                "directory inode {} child {name:?} targets missing inode {}",
                parent.0, target.0
            ),
            Self::DirectoryCycle { inode_id } => {
                write!(f, "directory graph cycle at inode {}", inode_id.0)
            }
            Self::ParentChildMismatch {
                child,
                expected_parent,
                actual_parent,
            } => write!(
                f,
                "directory inode {} parent mismatch: expected {}, actual {:?}",
                child.0,
                expected_parent.0,
                actual_parent.map(|inode| inode.0)
            ),
            Self::DirectoryParentMissing { child, parent } => write!(
                f,
                "directory inode {} names missing parent inode {}",
                child.0, parent.0
            ),
            Self::DirectoryParentNotDirectory { child, parent } => write!(
                f,
                "directory inode {} parent inode {} is not a directory",
                child.0, parent.0
            ),
            Self::DirectoryParentDoesNotNameChild { child, parent } => write!(
                f,
                "directory inode {} parent inode {} does not name the child",
                child.0, parent.0
            ),
            Self::LinkCountMismatch {
                inode_id,
                recorded,
                observed,
            } => write!(
                f,
                "inode {} nlink mismatch: recorded {recorded}, observed {observed}",
                inode_id.0
            ),
            Self::UnreachableNode { inode_id } => {
                write!(f, "inode {} is unreachable from root", inode_id.0)
            }
            Self::FileSizeOutOfBounds { inode_id, size } => write!(
                f,
                "file inode {} size {size} exceeds model bound",
                inode_id.0
            ),
        }
    }
}

impl std::error::Error for ModelInvariantError {}

#[derive(Clone, Debug)]
pub struct ModelFs {
    nodes: BTreeMap<InodeId, Node>,
    next_inode: u64,
}

impl Default for ModelFs {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelFs {
    #[must_use]
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT_INODE_ID, Node::root());
        Self {
            nodes,
            next_inode: ROOT_INODE_ID.0 + 1,
        }
    }

    #[must_use]
    pub const fn root_inode(&self) -> InodeId {
        ROOT_INODE_ID
    }

    /// Apply a temporary model request and check invariants after the step.
    ///
    /// # Errors
    ///
    /// Returns [`ModelInvariantError`] only when the model's internal state is
    /// inconsistent after the step. Invalid filesystem operations complete as
    /// normal model steps with stable errno classes in the returned
    /// [`TideCompletion`].
    pub fn apply(&mut self, request: ModelRequest) -> Result<ModelStep, ModelInvariantError> {
        let outcome = self.apply_model_inner(request);
        self.check_invariants()?;
        Ok(self.finish_step(None, outcome))
    }

    /// Apply a canonical contract request envelope for the model-supported VFS
    /// operations and check invariants after the step.
    ///
    /// # Errors
    ///
    /// Returns [`ModelInvariantError`] only when the model's internal state is
    /// inconsistent after the step. Unsupported or invalid contract operations
    /// complete as normal model steps with stable errno classes.
    pub fn apply_contract(
        &mut self,
        envelope: &RequestEnvelope,
        context: ContractModelContext<'_>,
    ) -> Result<ModelStep, ModelInvariantError> {
        self.apply_contract_with_names(envelope, context, ContractNameContext::empty())
    }

    /// Apply a canonical contract request envelope with namespace token
    /// bindings for operations that need component material.
    ///
    /// # Errors
    ///
    /// Returns [`ModelInvariantError`] only when the model's internal state is
    /// inconsistent after the step. Unsupported or invalid contract operations
    /// complete as normal model steps with stable errno classes.
    pub fn apply_contract_with_names(
        &mut self,
        envelope: &RequestEnvelope,
        context: ContractModelContext<'_>,
        name_context: ContractNameContext<'_>,
    ) -> Result<ModelStep, ModelInvariantError> {
        let outcome = if envelope.version != TIDE_CONTRACT_VERSION_V1 {
            OperationOutcome::failed(Errno::EINVAL)
        } else {
            match envelope.request {
                TideRequest::Vfs(VfsRequest::GetAttr { inode_id }) => self.getattr_inode(inode_id),
                TideRequest::Vfs(VfsRequest::Read {
                    inode_id,
                    offset,
                    length,
                    ..
                }) => self.read_inode(inode_id, offset, length),
                TideRequest::Vfs(VfsRequest::Write {
                    inode_id,
                    offset,
                    length,
                    ..
                }) => {
                    if length != context.write_bytes.len() as u64 {
                        OperationOutcome::failed(Errno::EINVAL)
                    } else {
                        self.write_inode(inode_id, offset, context.write_bytes)
                    }
                }
                TideRequest::Vfs(VfsRequest::Sync { inode_id, .. }) => self.fsync_inode(inode_id),
                TideRequest::Vfs(VfsRequest::Create { parent_id, name }) => {
                    match name_context.component_for(name) {
                        Ok(name) => self.create_child(parent_id, name),
                        Err(errno) => OperationOutcome::failed(errno),
                    }
                }
                TideRequest::Vfs(VfsRequest::Mkdir { parent_id, name }) => {
                    match name_context.component_for(name) {
                        Ok(name) => self.mkdir_child(parent_id, name),
                        Err(errno) => OperationOutcome::failed(errno),
                    }
                }
                TideRequest::Vfs(VfsRequest::Rename {
                    old_parent_id,
                    old_name,
                    new_parent_id,
                    new_name,
                }) => match (
                    name_context.component_for(old_name),
                    name_context.component_for(new_name),
                ) {
                    (Ok(old_name), Ok(new_name)) => {
                        self.rename_child(old_parent_id, old_name, new_parent_id, new_name)
                    }
                    (Err(errno), _) | (_, Err(errno)) => OperationOutcome::failed(errno),
                },
                TideRequest::Vfs(VfsRequest::Link {
                    source_inode_id,
                    target_parent_id,
                    target_name,
                }) => match name_context.component_for(target_name) {
                    Ok(target_name) => {
                        self.link_inode(source_inode_id, target_parent_id, target_name)
                    }
                    Err(errno) => OperationOutcome::failed(errno),
                },
                TideRequest::Vfs(VfsRequest::Unlink { parent_id, name }) => {
                    match name_context.component_for(name) {
                        Ok(name) => self.unlink_child(parent_id, name),
                        Err(errno) => OperationOutcome::failed(errno),
                    }
                }
                TideRequest::Vfs(VfsRequest::Truncate { inode_id, size }) => {
                    self.truncate_inode(inode_id, size)
                }
                TideRequest::Vfs(VfsRequest::Unsupported { .. })
                | TideRequest::Block(_)
                | TideRequest::Control(_)
                | TideRequest::Offload(_)
                | TideRequest::Unsupported(_) => OperationOutcome::unsupported(),
            }
        };

        self.check_invariants()?;
        Ok(self.finish_step(Some(envelope), outcome))
    }

    /// Check all model invariants without applying a step.
    ///
    /// # Errors
    ///
    /// Returns [`ModelInvariantError`] with the first deterministic invariant
    /// failure found.
    pub fn check_invariants(&self) -> Result<(), ModelInvariantError> {
        let root = self
            .nodes
            .get(&ROOT_INODE_ID)
            .ok_or(ModelInvariantError::MissingRoot)?;
        if root.kind != ModelNodeKind::Directory {
            return Err(ModelInvariantError::RootWrongKind);
        }
        if let Some(parent) = root.parent {
            return Err(ModelInvariantError::RootHasParent { parent });
        }

        let mut observed_links = BTreeMap::new();
        observed_links.insert(ROOT_INODE_ID, 1_u64);
        let mut visited_dirs = BTreeSet::new();
        let mut stack = BTreeSet::new();
        self.walk_directory(
            ROOT_INODE_ID,
            &mut visited_dirs,
            &mut stack,
            &mut observed_links,
        )?;

        for (inode_id, node) in &self.nodes {
            match node.kind {
                ModelNodeKind::Directory => {
                    if !node.content.is_empty() {
                        return Err(ModelInvariantError::DirectoryHasContent {
                            inode_id: *inode_id,
                        });
                    }
                    if *inode_id != ROOT_INODE_ID {
                        let parent = node.parent.ok_or(ModelInvariantError::UnreachableNode {
                            inode_id: *inode_id,
                        })?;
                        let parent_node = self.nodes.get(&parent).ok_or(
                            ModelInvariantError::DirectoryParentMissing {
                                child: *inode_id,
                                parent,
                            },
                        )?;
                        if parent_node.kind != ModelNodeKind::Directory {
                            return Err(ModelInvariantError::DirectoryParentNotDirectory {
                                child: *inode_id,
                                parent,
                            });
                        }
                        if !parent_node.children.values().any(|child| child == inode_id) {
                            return Err(ModelInvariantError::DirectoryParentDoesNotNameChild {
                                child: *inode_id,
                                parent,
                            });
                        }
                    }
                }
                ModelNodeKind::File => {
                    if !node.children.is_empty() {
                        return Err(ModelInvariantError::FileHasChildren {
                            inode_id: *inode_id,
                        });
                    }
                    if let Some(parent) = node.parent {
                        return Err(ModelInvariantError::FileHasParent {
                            inode_id: *inode_id,
                            parent,
                        });
                    }
                    let size = node.size();
                    if size > MAX_MODEL_FILE_SIZE {
                        return Err(ModelInvariantError::FileSizeOutOfBounds {
                            inode_id: *inode_id,
                            size,
                        });
                    }
                }
            }

            let observed = observed_links.get(inode_id).copied().unwrap_or(0);
            if node.nlink != observed {
                return Err(ModelInvariantError::LinkCountMismatch {
                    inode_id: *inode_id,
                    recorded: node.nlink,
                    observed,
                });
            }
        }

        for inode_id in observed_links.keys() {
            if !self.nodes.contains_key(inode_id) {
                return Err(ModelInvariantError::UnreachableNode {
                    inode_id: *inode_id,
                });
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn fingerprint(&self) -> ModelFingerprint {
        let mut digest = StableDigest::new();
        digest.write_bytes(b"tidefs-model-core-v1");
        digest.write_u64(self.next_inode);
        for (inode_id, node) in &self.nodes {
            digest.write_u64(inode_id.0);
            digest.write_u64(node.kind.as_u64());
            digest.write_u64(node.nlink);
            digest.write_u64(node.parent.map_or(0, |parent| parent.0));
            digest.write_u64(node.size());
            match node.kind {
                ModelNodeKind::Directory => {
                    digest.write_u64(node.children.len() as u64);
                    for (name, child) in &node.children {
                        digest.write_str(name);
                        digest.write_u64(child.0);
                    }
                }
                ModelNodeKind::File => {
                    digest.write_bytes(&node.content);
                }
            }
        }
        digest.finish()
    }

    pub fn attr(&self, path: &ModelPath) -> Result<ModelAttr, Errno> {
        let inode_id = self.resolve_path(path)?;
        self.attr_inode(inode_id)
    }

    /// Resolve an absolute model path to the inode id used by canonical VFS
    /// contract requests.
    ///
    /// # Errors
    ///
    /// Returns the same stable errno classes as path-oriented model requests.
    pub fn resolve_path_inode(&self, path: &ModelPath) -> Result<InodeId, Errno> {
        self.resolve_path(path)
    }

    /// Resolve the parent inode and final component for an absolute model path.
    ///
    /// # Errors
    ///
    /// Returns `EINVAL` for the root path and the same stable errno classes as
    /// path-oriented namespace requests for missing or non-directory parents.
    pub fn resolve_parent_inode(&self, path: &ModelPath) -> Result<(InodeId, String), Errno> {
        self.resolve_parent(path)
    }

    fn apply_model_inner(&mut self, request: ModelRequest) -> OperationOutcome {
        match request {
            ModelRequest::Create { path } => self.create(&path),
            ModelRequest::Mkdir { path } => self.mkdir(&path),
            ModelRequest::Write {
                path,
                offset,
                bytes,
            } => match self.resolve_path(&path) {
                Ok(inode_id) => self.write_inode(inode_id, offset, &bytes),
                Err(errno) => OperationOutcome::failed(errno),
            },
            ModelRequest::Read {
                path,
                offset,
                length,
            } => match self.resolve_path(&path) {
                Ok(inode_id) => self.read_inode(inode_id, offset, length),
                Err(errno) => OperationOutcome::failed(errno),
            },
            ModelRequest::Fsync { path } => match self.resolve_path(&path) {
                Ok(inode_id) => self.fsync_inode(inode_id),
                Err(errno) => OperationOutcome::failed(errno),
            },
            ModelRequest::Rename { from, to } => self.rename(&from, &to),
            ModelRequest::Link { from, to } => self.link(&from, &to),
            ModelRequest::Unlink { path } => self.unlink(&path),
            ModelRequest::Truncate { path, size } => match self.resolve_path(&path) {
                Ok(inode_id) => self.truncate_inode(inode_id, size),
                Err(errno) => OperationOutcome::failed(errno),
            },
            ModelRequest::GetAttr { path } => match self.resolve_path(&path) {
                Ok(inode_id) => self.getattr_inode(inode_id),
                Err(errno) => OperationOutcome::failed(errno),
            },
        }
    }

    fn finish_step(
        &self,
        envelope: Option<&RequestEnvelope>,
        outcome: OperationOutcome,
    ) -> ModelStep {
        let (request_id, trace_id, epoch) = envelope.map_or(
            (RequestId::ZERO, TraceId::ZERO, ContractEpoch::new(0)),
            |envelope| {
                (
                    envelope.metadata.request_id,
                    envelope.metadata.trace_id,
                    envelope.metadata.epoch,
                )
            },
        );
        let mut completion = TideCompletion::success(request_id, trace_id, epoch);
        completion.errno = outcome.errno;
        completion.status = if outcome.errno.is_success() {
            CompletionStatus::Success
        } else if outcome.unsupported {
            CompletionStatus::Unsupported
        } else {
            CompletionStatus::Failed
        };
        completion.disposition = if outcome.unsupported {
            CompletionDisposition::Unsupported
        } else {
            CompletionDisposition::Final
        };
        completion.completed_bytes = outcome.completed_bytes;
        completion.result_words = outcome.result_words;

        ModelStep {
            completion,
            output: outcome.output,
            fingerprint: self.fingerprint(),
        }
    }

    fn create(&mut self, path: &ModelPath) -> OperationOutcome {
        let (parent, name) = match self.resolve_parent(path) {
            Ok(parent) => parent,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        self.create_child(parent, &name)
    }

    fn mkdir(&mut self, path: &ModelPath) -> OperationOutcome {
        let (parent, name) = match self.resolve_parent(path) {
            Ok(parent) => parent,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        self.mkdir_child(parent, &name)
    }

    fn link(&mut self, from: &ModelPath, to: &ModelPath) -> OperationOutcome {
        let source = match self.resolve_path(from) {
            Ok(source) => source,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        let (parent, name) = match self.resolve_parent(to) {
            Ok(parent) => parent,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        self.link_inode(source, parent, &name)
    }

    fn unlink(&mut self, path: &ModelPath) -> OperationOutcome {
        if path.is_root() {
            return OperationOutcome::failed(Errno::EISDIR);
        }
        let (parent, name) = match self.resolve_parent(path) {
            Ok(parent) => parent,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        self.unlink_child(parent, &name)
    }

    fn rename(&mut self, from: &ModelPath, to: &ModelPath) -> OperationOutcome {
        if from.is_root() || to.is_root() {
            return OperationOutcome::failed(Errno::EINVAL);
        }
        let (from_parent, from_name) = match self.resolve_parent(from) {
            Ok(parent) => parent,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        let (to_parent, to_name) = match self.resolve_parent(to) {
            Ok(parent) => parent,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        self.rename_child(from_parent, &from_name, to_parent, &to_name)
    }

    fn create_child(&mut self, parent_id: InodeId, name: &str) -> OperationOutcome {
        if let Err(errno) = validate_component(name) {
            return OperationOutcome::failed(errno);
        }
        match self.nodes.get(&parent_id) {
            Some(parent) if parent.kind != ModelNodeKind::Directory => {
                return OperationOutcome::failed(Errno::ENOTDIR);
            }
            Some(parent) if parent.children.contains_key(name) => {
                return OperationOutcome::failed(Errno::EEXIST);
            }
            Some(_) => {}
            None => return OperationOutcome::failed(Errno::ENOENT),
        }

        let inode_id = self.allocate_inode();
        self.nodes.insert(inode_id, Node::file(inode_id));
        self.node_mut(parent_id)
            .children
            .insert(name.to_string(), inode_id);
        self.getattr_inode(inode_id)
    }

    fn mkdir_child(&mut self, parent_id: InodeId, name: &str) -> OperationOutcome {
        if let Err(errno) = validate_component(name) {
            return OperationOutcome::failed(errno);
        }
        match self.nodes.get(&parent_id) {
            Some(parent) if parent.kind != ModelNodeKind::Directory => {
                return OperationOutcome::failed(Errno::ENOTDIR);
            }
            Some(parent) if parent.children.contains_key(name) => {
                return OperationOutcome::failed(Errno::EEXIST);
            }
            Some(_) => {}
            None => return OperationOutcome::failed(Errno::ENOENT),
        }

        let inode_id = self.allocate_inode();
        self.nodes
            .insert(inode_id, Node::dir(inode_id, Some(parent_id)));
        self.node_mut(parent_id)
            .children
            .insert(name.to_string(), inode_id);
        self.getattr_inode(inode_id)
    }

    fn link_inode(
        &mut self,
        source_inode_id: InodeId,
        target_parent_id: InodeId,
        target_name: &str,
    ) -> OperationOutcome {
        if let Err(errno) = validate_component(target_name) {
            return OperationOutcome::failed(errno);
        }
        match self.nodes.get(&source_inode_id) {
            Some(source) if source.kind == ModelNodeKind::Directory => {
                return OperationOutcome::failed(Errno::EPERM);
            }
            Some(_) => {}
            None => return OperationOutcome::failed(Errno::ENOENT),
        }
        match self.nodes.get(&target_parent_id) {
            Some(parent) if parent.kind != ModelNodeKind::Directory => {
                return OperationOutcome::failed(Errno::ENOTDIR);
            }
            Some(parent) if parent.children.contains_key(target_name) => {
                return OperationOutcome::failed(Errno::EEXIST);
            }
            Some(_) => {}
            None => return OperationOutcome::failed(Errno::ENOENT),
        }

        let nlink = self.node(source_inode_id).nlink.saturating_add(1);
        self.node_mut(source_inode_id).nlink = nlink;
        self.node_mut(target_parent_id)
            .children
            .insert(target_name.to_string(), source_inode_id);
        self.getattr_inode(source_inode_id)
    }

    fn unlink_child(&mut self, parent_id: InodeId, name: &str) -> OperationOutcome {
        if let Err(errno) = validate_component(name) {
            return OperationOutcome::failed(errno);
        }
        let target = match self.nodes.get(&parent_id) {
            Some(parent) if parent.kind != ModelNodeKind::Directory => {
                return OperationOutcome::failed(Errno::ENOTDIR);
            }
            Some(parent) => match parent.children.get(name) {
                Some(target) => *target,
                None => return OperationOutcome::failed(Errno::ENOENT),
            },
            None => return OperationOutcome::failed(Errno::ENOENT),
        };
        if self.node(target).kind == ModelNodeKind::Directory {
            return OperationOutcome::failed(Errno::EISDIR);
        }

        self.node_mut(parent_id).children.remove(name);
        self.drop_link(target);
        OperationOutcome::success(ModelOutput::None, 0, [0; 3])
    }

    fn rename_child(
        &mut self,
        old_parent_id: InodeId,
        old_name: &str,
        new_parent_id: InodeId,
        new_name: &str,
    ) -> OperationOutcome {
        if let Err(errno) = validate_component(old_name) {
            return OperationOutcome::failed(errno);
        }
        if let Err(errno) = validate_component(new_name) {
            return OperationOutcome::failed(errno);
        }
        let source = match self.nodes.get(&old_parent_id) {
            Some(parent) if parent.kind != ModelNodeKind::Directory => {
                return OperationOutcome::failed(Errno::ENOTDIR);
            }
            Some(parent) => match parent.children.get(old_name) {
                Some(source) => *source,
                None => return OperationOutcome::failed(Errno::ENOENT),
            },
            None => return OperationOutcome::failed(Errno::ENOENT),
        };
        match self.nodes.get(&new_parent_id) {
            Some(parent) if parent.kind != ModelNodeKind::Directory => {
                return OperationOutcome::failed(Errno::ENOTDIR);
            }
            Some(_) => {}
            None => return OperationOutcome::failed(Errno::ENOENT),
        }
        if old_parent_id == new_parent_id && old_name == new_name {
            return self.getattr_inode(source);
        }

        let source_kind = self.node(source).kind;
        if source_kind == ModelNodeKind::Directory && self.is_dir_descendant(new_parent_id, source)
        {
            return OperationOutcome::failed(Errno::EINVAL);
        }

        let existing_target = self.child(new_parent_id, new_name);
        if existing_target == Some(source) {
            return self.getattr_inode(source);
        }
        if let Some(target) = existing_target {
            let target_kind = self.node(target).kind;
            match (source_kind, target_kind) {
                (ModelNodeKind::File, ModelNodeKind::Directory) => {
                    return OperationOutcome::failed(Errno::EISDIR);
                }
                (ModelNodeKind::Directory, ModelNodeKind::File) => {
                    return OperationOutcome::failed(Errno::ENOTDIR);
                }
                (ModelNodeKind::Directory, ModelNodeKind::Directory)
                    if !self.node(target).children.is_empty() =>
                {
                    return OperationOutcome::failed(Errno::ENOTEMPTY);
                }
                _ => {}
            }
        }

        self.node_mut(old_parent_id).children.remove(old_name);

        if let Some(target) = existing_target {
            self.node_mut(new_parent_id).children.remove(new_name);
            self.drop_link(target);
        }

        self.node_mut(new_parent_id)
            .children
            .insert(new_name.to_string(), source);
        if source_kind == ModelNodeKind::Directory {
            self.node_mut(source).parent = Some(new_parent_id);
        }
        self.getattr_inode(source)
    }

    fn write_inode(&mut self, inode_id: InodeId, offset: u64, bytes: &[u8]) -> OperationOutcome {
        let length = match u64::try_from(bytes.len()) {
            Ok(length) => length,
            Err(_) => return OperationOutcome::failed(Errno::EFBIG),
        };
        let end = match checked_file_end(offset, length) {
            Ok(end) => end,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        let end_usize = match usize::try_from(end) {
            Ok(end) => end,
            Err(_) => return OperationOutcome::failed(Errno::EFBIG),
        };
        let offset_usize = match usize::try_from(offset) {
            Ok(offset) => offset,
            Err(_) => return OperationOutcome::failed(Errno::EFBIG),
        };
        let node = match self.nodes.get_mut(&inode_id) {
            Some(node) => node,
            None => return OperationOutcome::failed(Errno::ENOENT),
        };
        if node.kind == ModelNodeKind::Directory {
            return OperationOutcome::failed(Errno::EISDIR);
        }
        if node.content.len() < end_usize {
            node.content.resize(end_usize, 0);
        }
        node.content[offset_usize..end_usize].copy_from_slice(bytes);
        OperationOutcome::success(ModelOutput::None, length, [length, end, 0])
    }

    fn read_inode(&self, inode_id: InodeId, offset: u64, length: u64) -> OperationOutcome {
        let length_usize = match checked_read_len(length) {
            Ok(length) => length,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        let offset_usize = match usize::try_from(offset) {
            Ok(offset) => offset,
            Err(_) => return OperationOutcome::failed(Errno::EFBIG),
        };
        let node = match self.nodes.get(&inode_id) {
            Some(node) => node,
            None => return OperationOutcome::failed(Errno::ENOENT),
        };
        if node.kind == ModelNodeKind::Directory {
            return OperationOutcome::failed(Errno::EISDIR);
        }

        let bytes = if offset_usize >= node.content.len() {
            Vec::new()
        } else {
            let end = node
                .content
                .len()
                .min(offset_usize.saturating_add(length_usize));
            node.content[offset_usize..end].to_vec()
        };
        let completed = bytes.len() as u64;
        OperationOutcome::success(ModelOutput::Bytes(bytes), completed, [completed, 0, 0])
    }

    fn fsync_inode(&self, inode_id: InodeId) -> OperationOutcome {
        match self.nodes.get(&inode_id) {
            Some(_) => OperationOutcome::success(ModelOutput::None, 0, [0; 3]),
            None => OperationOutcome::failed(Errno::ENOENT),
        }
    }

    fn truncate_inode(&mut self, inode_id: InodeId, size: u64) -> OperationOutcome {
        let size = match checked_read_len(size) {
            Ok(size) => size,
            Err(errno) => return OperationOutcome::failed(errno),
        };
        let node = match self.nodes.get_mut(&inode_id) {
            Some(node) => node,
            None => return OperationOutcome::failed(Errno::ENOENT),
        };
        if node.kind == ModelNodeKind::Directory {
            return OperationOutcome::failed(Errno::EISDIR);
        }
        node.content.resize(size, 0);
        OperationOutcome::success(ModelOutput::None, size as u64, [size as u64, 0, 0])
    }

    fn getattr_inode(&self, inode_id: InodeId) -> OperationOutcome {
        match self.attr_inode(inode_id) {
            Ok(attr) => OperationOutcome::success(
                ModelOutput::Attr(attr.clone()),
                0,
                [attr.inode_id.0, attr.kind.as_u64(), attr.size],
            ),
            Err(errno) => OperationOutcome::failed(errno),
        }
    }

    fn attr_inode(&self, inode_id: InodeId) -> Result<ModelAttr, Errno> {
        let node = self.nodes.get(&inode_id).ok_or(Errno::ENOENT)?;
        Ok(ModelAttr {
            inode_id,
            kind: node.kind,
            nlink: node.nlink,
            size: node.size(),
        })
    }

    fn resolve_path(&self, path: &ModelPath) -> Result<InodeId, Errno> {
        let mut current = ROOT_INODE_ID;
        for component in path.components() {
            let node = self.node(current);
            if node.kind != ModelNodeKind::Directory {
                return Err(Errno::ENOTDIR);
            }
            current = node.children.get(component).copied().ok_or(Errno::ENOENT)?;
        }
        Ok(current)
    }

    fn resolve_parent(&self, path: &ModelPath) -> Result<(InodeId, String), Errno> {
        if path.is_root() {
            return Err(Errno::EINVAL);
        }
        let name = path.components.last().cloned().ok_or(Errno::EINVAL)?;
        let mut current = ROOT_INODE_ID;
        for component in &path.components[..path.components.len() - 1] {
            let node = self.node(current);
            if node.kind != ModelNodeKind::Directory {
                return Err(Errno::ENOTDIR);
            }
            current = node.children.get(component).copied().ok_or(Errno::ENOENT)?;
        }
        if self.node(current).kind != ModelNodeKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok((current, name))
    }

    fn walk_directory(
        &self,
        inode_id: InodeId,
        visited_dirs: &mut BTreeSet<InodeId>,
        stack: &mut BTreeSet<InodeId>,
        observed_links: &mut BTreeMap<InodeId, u64>,
    ) -> Result<(), ModelInvariantError> {
        if !stack.insert(inode_id) {
            return Err(ModelInvariantError::DirectoryCycle { inode_id });
        }
        visited_dirs.insert(inode_id);
        let node = self.node(inode_id);
        for (name, child) in &node.children {
            let child_node =
                self.nodes
                    .get(child)
                    .ok_or_else(|| ModelInvariantError::ChildTargetMissing {
                        parent: inode_id,
                        name: name.clone(),
                        target: *child,
                    })?;
            let counter = observed_links.entry(*child).or_insert(0);
            *counter = counter.saturating_add(1);
            if child_node.kind == ModelNodeKind::Directory {
                if child_node.parent != Some(inode_id) {
                    return Err(ModelInvariantError::ParentChildMismatch {
                        child: *child,
                        expected_parent: inode_id,
                        actual_parent: child_node.parent,
                    });
                }
                if visited_dirs.contains(child) {
                    return Err(ModelInvariantError::DirectoryCycle { inode_id: *child });
                }
                self.walk_directory(*child, visited_dirs, stack, observed_links)?;
            }
        }
        stack.remove(&inode_id);
        Ok(())
    }

    fn is_dir_descendant(&self, candidate: InodeId, ancestor: InodeId) -> bool {
        let mut current = Some(candidate);
        while let Some(inode_id) = current {
            if inode_id == ancestor {
                return true;
            }
            current = self.nodes.get(&inode_id).and_then(|node| node.parent);
        }
        false
    }

    fn allocate_inode(&mut self) -> InodeId {
        let inode_id = InodeId(self.next_inode);
        self.next_inode = self.next_inode.saturating_add(1);
        inode_id
    }

    fn child(&self, parent: InodeId, name: &str) -> Option<InodeId> {
        self.node(parent).children.get(name).copied()
    }

    fn node(&self, inode_id: InodeId) -> &Node {
        self.nodes
            .get(&inode_id)
            .expect("model invariant: inode exists")
    }

    fn node_mut(&mut self, inode_id: InodeId) -> &mut Node {
        self.nodes
            .get_mut(&inode_id)
            .expect("model invariant: inode exists")
    }

    fn drop_link(&mut self, inode_id: InodeId) {
        let remove = {
            let node = self.node_mut(inode_id);
            node.nlink = node.nlink.saturating_sub(1);
            node.nlink == 0
        };
        if remove {
            self.nodes.remove(&inode_id);
        }
    }
}

#[derive(Clone, Debug)]
struct Node {
    kind: ModelNodeKind,
    nlink: u64,
    parent: Option<InodeId>,
    children: BTreeMap<String, InodeId>,
    content: Vec<u8>,
}

impl Node {
    fn root() -> Self {
        Self::dir(ROOT_INODE_ID, None)
    }

    fn dir(_inode_id: InodeId, parent: Option<InodeId>) -> Self {
        Self {
            kind: ModelNodeKind::Directory,
            nlink: 1,
            parent,
            children: BTreeMap::new(),
            content: Vec::new(),
        }
    }

    fn file(_inode_id: InodeId) -> Self {
        Self {
            kind: ModelNodeKind::File,
            nlink: 1,
            parent: None,
            children: BTreeMap::new(),
            content: Vec::new(),
        }
    }

    fn size(&self) -> u64 {
        self.content.len() as u64
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationOutcome {
    errno: Errno,
    output: ModelOutput,
    completed_bytes: u64,
    result_words: [u64; 3],
    unsupported: bool,
}

impl OperationOutcome {
    fn success(output: ModelOutput, completed_bytes: u64, result_words: [u64; 3]) -> Self {
        Self {
            errno: Errno::SUCCESS,
            output,
            completed_bytes,
            result_words,
            unsupported: false,
        }
    }

    fn failed(errno: Errno) -> Self {
        Self {
            errno,
            output: ModelOutput::None,
            completed_bytes: 0,
            result_words: [0; 3],
            unsupported: false,
        }
    }

    fn unsupported() -> Self {
        Self {
            unsupported: true,
            ..Self::failed(Errno::EOPNOTSUPP)
        }
    }
}

fn checked_file_end(offset: u64, length: u64) -> Result<u64, Errno> {
    let end = offset.checked_add(length).ok_or(Errno::EFBIG)?;
    if end > MAX_MODEL_FILE_SIZE {
        return Err(Errno::EFBIG);
    }
    Ok(end)
}

fn checked_read_len(length: u64) -> Result<usize, Errno> {
    if length > MAX_MODEL_FILE_SIZE {
        return Err(Errno::EFBIG);
    }
    usize::try_from(length).map_err(|_| Errno::EFBIG)
}

#[derive(Clone, Debug)]
struct StableDigest {
    lanes: [u64; 4],
    len: u64,
}

impl StableDigest {
    fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            len: 0,
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn write_str(&mut self, value: &str) {
        self.write_u64(value.len() as u64);
        self.write_bytes(value.as_bytes());
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        const PRIMES: [u64; 4] = [
            0x1000_0000_01b3,
            0x9e37_79b1_85eb_ca87,
            0xc2b2_ae3d_27d4_eb4f,
            0x1656_67b1_9e37_79f9,
        ];

        for byte in bytes {
            let input = u64::from(*byte).wrapping_add(self.len.rotate_left(17));
            for (lane_index, lane) in self.lanes.iter_mut().enumerate() {
                let salt = ((lane_index as u64) << 32) ^ self.len;
                let rotate = 11 + (lane_index as u32 * 7);
                *lane ^= input.wrapping_add(salt).rotate_left(rotate);
                *lane = lane
                    .wrapping_mul(PRIMES[lane_index])
                    .rotate_left(13 + lane_index as u32);
            }
            self.len = self.len.wrapping_add(1);
        }
    }

    fn finish(mut self) -> ModelFingerprint {
        for (lane_index, lane) in self.lanes.iter_mut().enumerate() {
            *lane ^= self.len.wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane = lane.rotate_left(17 + lane_index as u32 * 3);
        }

        let mut bytes = [0_u8; ModelFingerprint::BYTE_LEN];
        for (index, lane) in self.lanes.iter().enumerate() {
            let start = index * 8;
            bytes[start..start + 8].copy_from_slice(&lane.to_le_bytes());
        }
        ModelFingerprint::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_vfs_core::{
        BlockRequest, ContractVersion, FileHandleId, RequestMetadata, TideRequest,
        UnsupportedRequest,
    };

    fn path(value: &str) -> ModelPath {
        ModelPath::parse_absolute(value).unwrap()
    }

    fn apply(fs: &mut ModelFs, request: ModelRequest) -> ModelStep {
        fs.apply(request).unwrap()
    }

    fn envelope(request: TideRequest) -> RequestEnvelope {
        RequestEnvelope::new(
            RequestMetadata::new(
                RequestId::new([1; 16]),
                ContractEpoch::new(7),
                TraceId::new([2; 16]),
            ),
            request,
        )
    }

    fn token(component: &str) -> VfsNameToken {
        VfsNameToken::from_component_bytes(component.as_bytes())
    }

    fn binding(component: &'static str) -> ContractNameBinding<'static> {
        ContractNameBinding::new(token(component), component)
    }

    #[test]
    fn valid_trace_covers_namespace_content_and_sync_ops() {
        let mut fs = ModelFs::new();

        assert!(apply(&mut fs, ModelRequest::Mkdir { path: path("/dir") }).is_success());
        let created = apply(
            &mut fs,
            ModelRequest::Create {
                path: path("/dir/file"),
            },
        );
        let file_inode = created.output.as_attr().unwrap().inode_id;

        assert!(apply(
            &mut fs,
            ModelRequest::Write {
                path: path("/dir/file"),
                offset: 0,
                bytes: b"hello".to_vec(),
            },
        )
        .is_success());
        let read = apply(
            &mut fs,
            ModelRequest::Read {
                path: path("/dir/file"),
                offset: 1,
                length: 3,
            },
        );
        assert_eq!(read.output.as_bytes().unwrap(), b"ell");

        assert!(apply(
            &mut fs,
            ModelRequest::Fsync {
                path: path("/dir/file"),
            },
        )
        .is_success());
        assert!(apply(
            &mut fs,
            ModelRequest::Link {
                from: path("/dir/file"),
                to: path("/dir/link"),
            },
        )
        .is_success());
        assert_eq!(fs.attr(&path("/dir/link")).unwrap().nlink, 2);

        assert!(apply(
            &mut fs,
            ModelRequest::Truncate {
                path: path("/dir/link"),
                size: 2,
            },
        )
        .is_success());
        assert!(apply(
            &mut fs,
            ModelRequest::Rename {
                from: path("/dir/file"),
                to: path("/renamed"),
            },
        )
        .is_success());
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Read {
                    path: path("/dir/file"),
                    offset: 0,
                    length: 1,
                },
            )
            .errno(),
            Errno::ENOENT
        );
        assert!(apply(
            &mut fs,
            ModelRequest::Unlink {
                path: path("/dir/link"),
            },
        )
        .is_success());

        let read = apply(
            &mut fs,
            ModelRequest::Read {
                path: path("/renamed"),
                offset: 0,
                length: 8,
            },
        );
        assert_eq!(read.output.as_bytes().unwrap(), b"he");
        let attr = fs.attr(&path("/renamed")).unwrap();
        assert_eq!(attr.inode_id, file_inode);
        assert_eq!(attr.nlink, 1);
        fs.check_invariants().unwrap();
    }

    #[test]
    fn contract_envelope_io_ops_replay_against_inodes() {
        let mut fs = ModelFs::new();
        let created = apply(
            &mut fs,
            ModelRequest::Create {
                path: path("/file"),
            },
        );
        let inode_id = created.output.as_attr().unwrap().inode_id;

        let write = envelope(TideRequest::Vfs(VfsRequest::Write {
            inode_id,
            file_handle_id: FileHandleId::new(11),
            offset: 0,
            length: 3,
        }));
        let step = fs
            .apply_contract(&write, ContractModelContext::with_write_bytes(b"abc"))
            .unwrap();
        assert_eq!(step.completion.completed_bytes, 3);
        assert!(step.is_success());

        let read = envelope(TideRequest::Vfs(VfsRequest::Read {
            inode_id,
            file_handle_id: FileHandleId::new(11),
            offset: 0,
            length: 8,
        }));
        let step = fs
            .apply_contract(&read, ContractModelContext::empty())
            .unwrap();
        assert_eq!(step.output.as_bytes().unwrap(), b"abc");
        assert_eq!(step.completion.request_id, RequestId::new([1; 16]));
        assert_eq!(step.completion.trace_id, TraceId::new([2; 16]));

        let sync = envelope(TideRequest::Vfs(VfsRequest::Sync {
            inode_id,
            file_handle_id: FileHandleId::new(11),
        }));
        assert!(fs
            .apply_contract(&sync, ContractModelContext::empty())
            .unwrap()
            .is_success());

        let unsupported = envelope(TideRequest::Unsupported(UnsupportedRequest::new(
            99, 1, [0; 5],
        )));
        let step = fs
            .apply_contract(&unsupported, ContractModelContext::empty())
            .unwrap();
        assert_eq!(step.completion.status, CompletionStatus::Unsupported);
        assert_eq!(step.errno(), Errno::EOPNOTSUPP);

        let block = envelope(TideRequest::Block(BlockRequest::Unsupported {
            opcode: 99,
            words: [0; 5],
        }));
        assert_eq!(
            fs.apply_contract(&block, ContractModelContext::empty())
                .unwrap()
                .errno(),
            Errno::EOPNOTSUPP
        );
    }

    #[test]
    fn contract_envelope_namespace_ops_replay_with_name_tokens() {
        let mut fs = ModelFs::new();
        let names = [
            binding("dir"),
            binding("file"),
            binding("alias"),
            binding("moved"),
        ];
        let name_context = ContractNameContext::new(&names);

        let mkdir = envelope(TideRequest::Vfs(VfsRequest::Mkdir {
            parent_id: ROOT_INODE_ID,
            name: token("dir"),
        }));
        let mkdir_step = fs
            .apply_contract_with_names(&mkdir, ContractModelContext::empty(), name_context)
            .unwrap();
        assert!(mkdir_step.is_success());
        let dir_inode = mkdir_step.output.as_attr().unwrap().inode_id;

        let create = envelope(TideRequest::Vfs(VfsRequest::Create {
            parent_id: dir_inode,
            name: token("file"),
        }));
        let create_step = fs
            .apply_contract_with_names(&create, ContractModelContext::empty(), name_context)
            .unwrap();
        assert!(create_step.is_success());
        let file_inode = create_step.output.as_attr().unwrap().inode_id;

        let write = envelope(TideRequest::Vfs(VfsRequest::Write {
            inode_id: file_inode,
            file_handle_id: FileHandleId::new(11),
            offset: 0,
            length: 6,
        }));
        assert!(fs
            .apply_contract_with_names(
                &write,
                ContractModelContext::with_write_bytes(b"abcdef"),
                name_context,
            )
            .unwrap()
            .is_success());

        let link = envelope(TideRequest::Vfs(VfsRequest::Link {
            source_inode_id: file_inode,
            target_parent_id: dir_inode,
            target_name: token("alias"),
        }));
        let link_step = fs
            .apply_contract_with_names(&link, ContractModelContext::empty(), name_context)
            .unwrap();
        assert!(link_step.is_success());
        assert_eq!(link_step.output.as_attr().unwrap().nlink, 2);

        let truncate = envelope(TideRequest::Vfs(VfsRequest::Truncate {
            inode_id: file_inode,
            size: 3,
        }));
        assert!(fs
            .apply_contract(&truncate, ContractModelContext::empty())
            .unwrap()
            .is_success());

        let rename = envelope(TideRequest::Vfs(VfsRequest::Rename {
            old_parent_id: dir_inode,
            old_name: token("alias"),
            new_parent_id: ROOT_INODE_ID,
            new_name: token("moved"),
        }));
        assert!(fs
            .apply_contract_with_names(&rename, ContractModelContext::empty(), name_context)
            .unwrap()
            .is_success());

        let unlink = envelope(TideRequest::Vfs(VfsRequest::Unlink {
            parent_id: dir_inode,
            name: token("file"),
        }));
        assert!(fs
            .apply_contract_with_names(&unlink, ContractModelContext::empty(), name_context)
            .unwrap()
            .is_success());

        let read = envelope(TideRequest::Vfs(VfsRequest::Read {
            inode_id: file_inode,
            file_handle_id: FileHandleId::new(11),
            offset: 0,
            length: 8,
        }));
        let read_step = fs
            .apply_contract(&read, ContractModelContext::empty())
            .unwrap();
        assert_eq!(read_step.output.as_bytes().unwrap(), b"abc");
        assert_eq!(fs.attr(&path("/moved")).unwrap().nlink, 1);
        fs.check_invariants().unwrap();
    }

    #[test]
    fn path_resolution_helpers_expose_contract_inode_inputs() {
        let mut fs = ModelFs::new();
        assert!(apply(&mut fs, ModelRequest::Mkdir { path: path("/dir") }).is_success());
        let dir_inode = fs.resolve_path_inode(&path("/dir")).unwrap();

        let (parent_id, component) = fs.resolve_parent_inode(&path("/dir/file")).unwrap();
        assert_eq!(parent_id, dir_inode);
        assert_eq!(component, "file");
        assert_eq!(fs.resolve_parent_inode(&path("/")), Err(Errno::EINVAL));
    }

    #[test]
    fn invalid_operations_return_stable_errno_classes() {
        let mut fs = ModelFs::new();
        assert!(apply(
            &mut fs,
            ModelRequest::Create {
                path: path("/file"),
            },
        )
        .is_success());
        assert!(apply(&mut fs, ModelRequest::Mkdir { path: path("/dir") },).is_success());
        assert!(apply(
            &mut fs,
            ModelRequest::Mkdir {
                path: path("/dir/sub"),
            },
        )
        .is_success());

        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Create {
                    path: path("/file"),
                },
            )
            .errno(),
            Errno::EEXIST
        );
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Mkdir {
                    path: path("/file/child"),
                },
            )
            .errno(),
            Errno::ENOTDIR
        );
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Read {
                    path: path("/missing"),
                    offset: 0,
                    length: 1,
                },
            )
            .errno(),
            Errno::ENOENT
        );
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Read {
                    path: path("/dir"),
                    offset: 0,
                    length: 1,
                },
            )
            .errno(),
            Errno::EISDIR
        );
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Link {
                    from: path("/dir"),
                    to: path("/dir-link"),
                },
            )
            .errno(),
            Errno::EPERM
        );
        assert_eq!(
            apply(&mut fs, ModelRequest::Unlink { path: path("/dir") },).errno(),
            Errno::EISDIR
        );
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Rename {
                    from: path("/dir"),
                    to: path("/dir/sub/moved"),
                },
            )
            .errno(),
            Errno::EINVAL
        );
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Truncate {
                    path: path("/dir"),
                    size: 0,
                },
            )
            .errno(),
            Errno::EISDIR
        );
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Write {
                    path: path("/file"),
                    offset: MAX_MODEL_FILE_SIZE + 1,
                    bytes: Vec::new(),
                },
            )
            .errno(),
            Errno::EFBIG
        );

        let inode_id = fs.attr(&path("/file")).unwrap().inode_id;
        let write = envelope(TideRequest::Vfs(VfsRequest::Write {
            inode_id,
            file_handle_id: FileHandleId::new(1),
            offset: 0,
            length: 4,
        }));
        assert_eq!(
            fs.apply_contract(&write, ContractModelContext::with_write_bytes(b"abc"),)
                .unwrap()
                .errno(),
            Errno::EINVAL
        );

        let mut wrong_version = envelope(TideRequest::Vfs(VfsRequest::GetAttr { inode_id }));
        wrong_version.version = ContractVersion::new(99);
        assert_eq!(
            fs.apply_contract(&wrong_version, ContractModelContext::empty())
                .unwrap()
                .errno(),
            Errno::EINVAL
        );

        fs.check_invariants().unwrap();
    }

    #[test]
    fn rename_between_hard_links_is_a_noop() {
        let mut fs = ModelFs::new();
        let created = apply(
            &mut fs,
            ModelRequest::Create {
                path: path("/file"),
            },
        );
        let inode_id = created.output.as_attr().unwrap().inode_id;
        assert!(apply(
            &mut fs,
            ModelRequest::Write {
                path: path("/file"),
                offset: 0,
                bytes: b"same".to_vec(),
            },
        )
        .is_success());
        assert!(apply(
            &mut fs,
            ModelRequest::Link {
                from: path("/file"),
                to: path("/alias"),
            },
        )
        .is_success());

        let before = fs.fingerprint();
        let step = apply(
            &mut fs,
            ModelRequest::Rename {
                from: path("/file"),
                to: path("/alias"),
            },
        );

        assert!(step.is_success());
        assert_eq!(step.fingerprint, before);
        assert_eq!(fs.attr(&path("/file")).unwrap().inode_id, inode_id);
        assert_eq!(fs.attr(&path("/alias")).unwrap().inode_id, inode_id);
        assert_eq!(fs.attr(&path("/file")).unwrap().nlink, 2);
        assert_eq!(
            apply(
                &mut fs,
                ModelRequest::Read {
                    path: path("/alias"),
                    offset: 0,
                    length: 4,
                },
            )
            .output
            .as_bytes()
            .unwrap(),
            b"same"
        );
        fs.check_invariants().unwrap();
    }

    #[test]
    fn path_parser_returns_errno_without_host_path_leakage() {
        assert_eq!(ModelPath::parse_absolute("relative"), Err(Errno::EINVAL));
        assert_eq!(ModelPath::parse_absolute("/a//b"), Err(Errno::EINVAL));
        assert_eq!(ModelPath::parse_absolute("/a/./b"), Err(Errno::EINVAL));
        assert_eq!(
            ModelPath::parse_absolute(&format!("/{}", "x".repeat(256))),
            Err(Errno::ENAMETOOLONG)
        );
    }

    #[test]
    fn fingerprints_are_deterministic_and_ordered() {
        fn run_trace() -> ModelFingerprint {
            let mut fs = ModelFs::new();
            apply(&mut fs, ModelRequest::Mkdir { path: path("/dir") });
            apply(
                &mut fs,
                ModelRequest::Create {
                    path: path("/dir/b"),
                },
            );
            apply(
                &mut fs,
                ModelRequest::Create {
                    path: path("/dir/a"),
                },
            );
            apply(
                &mut fs,
                ModelRequest::Write {
                    path: path("/dir/a"),
                    offset: 0,
                    bytes: b"stable".to_vec(),
                },
            );
            fs.fingerprint()
        }

        let first = run_trace();
        let second = run_trace();
        assert_eq!(first, second);
        assert_eq!(first.to_hex().len(), ModelFingerprint::BYTE_LEN * 2);

        let mut fs = ModelFs::new();
        let before = fs.fingerprint();
        let failed = apply(
            &mut fs,
            ModelRequest::Read {
                path: path("/missing"),
                offset: 0,
                length: 1,
            },
        );
        assert_eq!(failed.errno(), Errno::ENOENT);
        assert_eq!(before, failed.fingerprint);
    }
}
