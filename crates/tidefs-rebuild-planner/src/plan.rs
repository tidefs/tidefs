//! RebuildPlan with BLAKE3-verified sealed-header format.
//!
//! A [`RebuildPlan`] is an ordered list of [`ReconstructionTask`] entries.
//! The plan is self-verifying: `seal()` produces `[hash:32][plan_body]`
//! and `verify()` checks integrity before deserializing.

const REBUILD_PLAN_CONTEXT: &str = "TideFS RebuildPlan v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructionTask {
    pub object_id: u64,
    pub source_nodes: Vec<u64>,
    pub target_nodes: Vec<u64>,
    pub data_range: Option<(u64, u64)>,
    pub priority: u8,
}

impl ReconstructionTask {
    pub fn new_full(
        object_id: u64,
        source_nodes: Vec<u64>,
        target_nodes: Vec<u64>,
        priority: u8,
    ) -> Self {
        Self {
            object_id,
            source_nodes,
            target_nodes,
            data_range: None,
            priority,
        }
    }
    pub fn has_viable_sources(&self) -> bool {
        !self.source_nodes.is_empty()
    }
    pub fn target_count(&self) -> usize {
        self.target_nodes.len()
    }
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.object_id.to_le_bytes());
        buf.extend_from_slice(&(self.source_nodes.len() as u32).to_le_bytes());
        for &n in &self.source_nodes {
            buf.extend_from_slice(&n.to_le_bytes());
        }
        buf.extend_from_slice(&(self.target_nodes.len() as u32).to_le_bytes());
        for &n in &self.target_nodes {
            buf.extend_from_slice(&n.to_le_bytes());
        }
        match &self.data_range {
            None => buf.push(0),
            Some((start, end)) => {
                buf.push(1);
                buf.extend_from_slice(&start.to_le_bytes());
                buf.extend_from_slice(&end.to_le_bytes());
            }
        }
        buf.push(self.priority);
        buf
    }
    fn decode(buf: &[u8]) -> Result<(Self, usize), String> {
        if buf.len() < 12 {
            return Err("too short".into());
        }
        let object_id = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let src_count = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        let mut pos = 12;
        let mut source_nodes = Vec::with_capacity(src_count);
        if buf.len() < pos + src_count * 8 + 4 {
            return Err("too short for sources".into());
        }
        for _ in 0..src_count {
            source_nodes.push(u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()));
            pos += 8;
        }
        let tgt_count = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut target_nodes = Vec::with_capacity(tgt_count);
        if buf.len() < pos + tgt_count * 8 + 1 {
            return Err("too short for targets".into());
        }
        for _ in 0..tgt_count {
            target_nodes.push(u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()));
            pos += 8;
        }
        let has_range = buf[pos];
        pos += 1;
        let data_range = if has_range == 1 {
            if buf.len() < pos + 16 {
                return Err("too short for data_range".into());
            }
            let start = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
            let end = u64::from_le_bytes(buf[pos + 8..pos + 16].try_into().unwrap());
            pos += 16;
            Some((start, end))
        } else {
            None
        };
        if buf.len() < pos + 1 {
            return Err("too short for priority".into());
        }
        let priority = buf[pos];
        pos += 1;
        Ok((
            Self {
                object_id,
                source_nodes,
                target_nodes,
                data_range,
                priority,
            },
            pos,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuildPlan {
    pub plan_id: u64,
    pub tasks: Vec<ReconstructionTask>,
    pub created_at_ns: u64,
}

impl RebuildPlan {
    pub fn new(plan_id: u64, tasks: Vec<ReconstructionTask>, created_at_ns: u64) -> Self {
        Self {
            plan_id,
            tasks,
            created_at_ns,
        }
    }
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
    pub fn total_target_replicas(&self) -> usize {
        self.tasks.iter().map(|t| t.target_nodes.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.plan_id.to_le_bytes());
        buf.extend_from_slice(&self.created_at_ns.to_le_bytes());
        buf.extend_from_slice(&(self.tasks.len() as u32).to_le_bytes());
        for task in &self.tasks {
            buf.extend_from_slice(&task.encode());
        }
        buf
    }

    pub fn seal(&self) -> Vec<u8> {
        let body = self.encode_body();
        let hash = {
            let mut hasher = blake3::Hasher::new_derive_key(REBUILD_PLAN_CONTEXT);
            hasher.update(&body);
            hasher.finalize()
        };
        let mut sealed = Vec::with_capacity(32 + body.len());
        sealed.extend_from_slice(hash.as_bytes());
        sealed.extend_from_slice(&body);
        sealed
    }

    pub fn verify_and_decode(sealed: &[u8]) -> Result<Self, String> {
        if sealed.len() < 32 {
            return Err("too short".into());
        }
        let expected_hash: [u8; 32] = sealed[0..32].try_into().unwrap();
        let body = &sealed[32..];
        let computed = {
            let mut hasher = blake3::Hasher::new_derive_key(REBUILD_PLAN_CONTEXT);
            hasher.update(body);
            hasher.finalize()
        };
        if expected_hash != *computed.as_bytes() {
            return Err("BLAKE3 integrity check failed".into());
        }
        Self::decode_body(body)
    }

    pub fn verify_integrity(sealed: &[u8]) -> bool {
        if sealed.len() < 32 {
            return false;
        }
        let expected_hash: [u8; 32] = sealed[0..32].try_into().unwrap();
        let body = &sealed[32..];
        let computed = {
            let mut hasher = blake3::Hasher::new_derive_key(REBUILD_PLAN_CONTEXT);
            hasher.update(body);
            hasher.finalize()
        };
        expected_hash == *computed.as_bytes()
    }

    fn decode_body(body: &[u8]) -> Result<Self, String> {
        if body.len() < 20 {
            return Err("body too short".into());
        }
        let plan_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let created_at_ns = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let task_count = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
        let mut tasks = Vec::with_capacity(task_count);
        let mut pos = 20;
        for _ in 0..task_count {
            let (task, bytes_read) = ReconstructionTask::decode(&body[pos..])?;
            tasks.push(task);
            pos += bytes_read;
        }
        Ok(Self {
            plan_id,
            tasks,
            created_at_ns,
        })
    }
}

#[cfg(test)]
mod tests;
