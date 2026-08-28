//! A small file-backed matcher for unit-valued host indexes.
//!
//! The route compiler needs two different kinds of trie. The primary rule
//! index stores `RouteRule` values and must stay in memory. Host-list and
//! predicate indexes only store membership, though, so keeping their whole
//! node graph in the heap is unnecessary. This module stores sorted fixed
//! width records on disk and performs binary searches directly through the
//! file. Construction uses bounded external sorting, so a large pattern set
//! is not first materialized in a heap-backed set. Read-only mmap is isolated
//! to this module and keeps query memory bounded by the small root index and
//! query candidates.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use doradus_core::{DomainName, Endpoint, Error, ErrorKind, Result};
use memmap2::{Mmap, MmapOptions};

use crate::{CombinedTrie, pattern_labels};

const MAGIC: &[u8; 8] = b"YHTRIE01";
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 32;
const DOMAIN_RECORD_SIZE: usize = 256;
const CIDR_RECORD_SIZE: usize = 32;
const DOMAIN_KEY_SIZE: usize = DOMAIN_RECORD_SIZE - 2;
const CIDR_KEY_SIZE: usize = 18;
const ROOT_RECORD_SIZE: usize = 68;
const ROOT_KEY_SIZE: usize = ROOT_RECORD_SIZE - 2;
const SORT_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const MERGE_FAN_IN: usize = 32;

static NEXT_INDEX_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
enum HostTrieStorage {
    Memory(CombinedTrie<()>),
    Disk(Arc<DiskFiles>),
}

/// Membership-only host/CIDR matcher.
///
/// `new` remains available for small transient indexes. Production route-list
/// and predicate builders use `from_patterns`, which creates a disk-backed
/// index without retaining its node graph in the heap.
#[derive(Debug, Clone)]
pub struct HostTrie {
    storage: HostTrieStorage,
}

impl PartialEq for HostTrie {
    fn eq(&self, other: &Self) -> bool {
        match (&self.storage, &other.storage) {
            (HostTrieStorage::Memory(left), HostTrieStorage::Memory(right)) => left == right,
            (HostTrieStorage::Disk(left), HostTrieStorage::Disk(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for HostTrie {}

impl Default for HostTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl HostTrie {
    pub fn new() -> Self {
        Self {
            storage: HostTrieStorage::Memory(CombinedTrie::new()),
        }
    }

    /// Build the default disk-backed matcher from a complete set of patterns.
    /// The temporary directory is owned by the returned matcher and removed
    /// after the last clone is dropped.
    pub fn from_patterns<I, S>(patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::from_checked(
            patterns
                .into_iter()
                .map(|pattern| Ok::<String, Error>(pattern.as_ref().to_owned())),
        )
    }

    fn from_checked<I>(patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = Result<String>>,
    {
        let dir = std::env::temp_dir().join(format!(
            "doradus-trie-{}-{}",
            std::process::id(),
            NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).map_err(io_error)?;
        match DiskFiles::build_checked(&dir, patterns, true) {
            Ok(files) => Ok(Self {
                storage: HostTrieStorage::Disk(Arc::new(files)),
            }),
            Err(error) => {
                let _ = fs::remove_dir_all(&dir);
                Err(error)
            }
        }
    }

    /// Build an index in a caller-owned directory. This is useful when the
    /// index should survive a process restart or when a test needs to reopen
    /// the exact same files.
    pub fn build_at<I, S>(dir: impl AsRef<Path>, patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(io_error)?;
        let files = DiskFiles::build(dir, patterns, false)?;
        Ok(Self {
            storage: HostTrieStorage::Disk(Arc::new(files)),
        })
    }

    /// Reopen an existing `build_at` directory without taking ownership of
    /// the directory. `from_patterns` is the normal runtime path.
    pub fn open_at(dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            storage: HostTrieStorage::Disk(Arc::new(DiskFiles::open(
                dir.as_ref().to_owned(),
                false,
            )?)),
        })
    }

    pub fn is_on_disk(&self) -> bool {
        matches!(self.storage, HostTrieStorage::Disk(_))
    }

    pub fn insert(&mut self, pattern: &str, value: ()) -> Result<Option<()>> {
        if let HostTrieStorage::Memory(index) = &mut self.storage {
            return index.insert(pattern, value);
        }
        let pattern = canonical_pattern(pattern)?;
        let files = match &self.storage {
            HostTrieStorage::Disk(files) => Arc::clone(files),
            HostTrieStorage::Memory(_) => unreachable!("memory host trie handled above"),
        };
        if files.contains_pattern(&pattern)? {
            return Ok(Some(value));
        }
        let patterns = files.pattern_iter().chain(std::iter::once(Ok(pattern)));
        self.replace_with_checked(patterns).map(|()| None)
    }

    pub fn remove(&mut self, pattern: &str) -> Result<Option<()>> {
        if let HostTrieStorage::Memory(index) = &mut self.storage {
            return {
                if let Some((address, prefix)) = pattern.split_once('/') {
                    let address = address
                        .parse::<IpAddr>()
                        .map_err(|_| Error::invalid("invalid CIDR address"))?;
                    let prefix = prefix
                        .parse::<u8>()
                        .map_err(|_| Error::invalid("invalid CIDR prefix length"))?;
                    index
                        .cidrs
                        .remove(mask_address(address, prefix), prefix)
                        .map(|value| value.map(|_| ()))
                } else {
                    index.domains.remove(pattern).map(|value| value.map(|_| ()))
                }
            };
        }
        let pattern = canonical_pattern(pattern)?;
        let files = match &self.storage {
            HostTrieStorage::Disk(files) => Arc::clone(files),
            HostTrieStorage::Memory(_) => unreachable!("memory host trie handled above"),
        };
        if !files.contains_pattern(&pattern)? {
            return Ok(None);
        }
        let patterns = files.pattern_iter().filter_map(move |result| match result {
            Ok(existing) if existing == pattern => None,
            other => Some(other),
        });
        self.replace_with_checked(patterns).map(|()| Some(()))
    }

    pub fn search(&self, endpoint: &Endpoint) -> Option<()> {
        match &self.storage {
            HostTrieStorage::Memory(index) => index.search(endpoint).map(|_| ()),
            HostTrieStorage::Disk(files) => files.matches(endpoint, false).then_some(()),
        }
    }

    pub fn search_parent(&self, endpoint: &Endpoint) -> Option<()> {
        match &self.storage {
            HostTrieStorage::Memory(index) => index.search_parent(endpoint).map(|_| ()),
            HostTrieStorage::Disk(files) => files.matches(endpoint, true).then_some(()),
        }
    }

    fn replace_with_checked<I>(&mut self, patterns: I) -> Result<()>
    where
        I: IntoIterator<Item = Result<String>>,
    {
        let replacement = Self::from_checked(patterns)?;
        self.storage = replacement.storage;
        Ok(())
    }
}

#[derive(Debug)]
struct DiskFiles {
    dir: PathBuf,
    owned: bool,
    domains: DiskTable,
    cidrs: DiskTable,
}

impl Drop for DiskFiles {
    fn drop(&mut self) {
        if self.owned {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

impl DiskFiles {
    fn build<I, S>(dir: &Path, patterns: I, owned: bool) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::build_checked(
            dir,
            patterns
                .into_iter()
                .map(|pattern| Ok::<String, Error>(pattern.as_ref().to_owned())),
            owned,
        )
    }

    fn build_checked<I>(dir: &Path, patterns: I, owned: bool) -> Result<Self>
    where
        I: IntoIterator<Item = Result<String>>,
    {
        let mut domain_records = Vec::new();
        let mut cidr_records = Vec::new();
        let mut domain_bytes = 0;
        let mut cidr_bytes = 0;
        let mut domain_runs = Vec::new();
        let mut cidr_runs = Vec::new();
        for pattern in patterns {
            let pattern = canonical_pattern(&pattern?)?;
            if let Some((address, prefix)) = pattern.split_once('/') {
                let address = address
                    .parse::<IpAddr>()
                    .map_err(|_| Error::invalid("invalid CIDR address"))?;
                let prefix = prefix
                    .parse::<u8>()
                    .map_err(|_| Error::invalid("invalid CIDR prefix length"))?;
                let max_bits = if address.is_ipv4() { 32 } else { 128 };
                if prefix > max_bits {
                    return Err(Error::invalid("CIDR prefix length exceeds address width"));
                }
                let mut record = vec![0u8; CIDR_RECORD_SIZE];
                record[..CIDR_KEY_SIZE].copy_from_slice(&cidr_key(address, prefix));
                cidr_bytes += record.len();
                cidr_records.push(record);
                if cidr_bytes >= SORT_CHUNK_BYTES {
                    flush_run(
                        dir,
                        "cidrs",
                        CIDR_KEY_SIZE,
                        &mut cidr_records,
                        &mut cidr_runs,
                    )?;
                    cidr_bytes = 0;
                }
            } else {
                let labels = pattern_labels(&pattern)?;
                let key = domain_key(&labels);
                if key.len() > DOMAIN_KEY_SIZE {
                    return Err(Error::invalid("domain pattern is too large for disk index"));
                }
                let mut record = vec![0u8; DOMAIN_RECORD_SIZE];
                record[..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
                record[2..2 + key.len()].copy_from_slice(&key);
                domain_bytes += record.len();
                domain_records.push(record);
                if domain_bytes >= SORT_CHUNK_BYTES {
                    flush_run(
                        dir,
                        "domains",
                        DOMAIN_KEY_SIZE,
                        &mut domain_records,
                        &mut domain_runs,
                    )?;
                    domain_bytes = 0;
                }
            }
        }
        flush_run(
            dir,
            "domains",
            DOMAIN_KEY_SIZE,
            &mut domain_records,
            &mut domain_runs,
        )?;
        flush_run(
            dir,
            "cidrs",
            CIDR_KEY_SIZE,
            &mut cidr_records,
            &mut cidr_runs,
        )?;

        let domain_path = dir.join("domains.idx");
        let cidr_path = dir.join("cidrs.idx");
        let result = (|| {
            merge_runs_to_table(
                &domain_path,
                1,
                DOMAIN_RECORD_SIZE,
                DOMAIN_KEY_SIZE,
                std::mem::take(&mut domain_runs),
            )?;
            write_root_index(&domain_path, &dir.join("domains.roots"))?;
            merge_runs_to_table(
                &cidr_path,
                2,
                CIDR_RECORD_SIZE,
                CIDR_KEY_SIZE,
                std::mem::take(&mut cidr_runs),
            )?;
            Self::open(dir.to_owned(), owned)
        })();
        for path in domain_runs.into_iter().chain(cidr_runs) {
            let _ = fs::remove_file(path);
        }
        result
    }

    fn open(dir: PathBuf, owned: bool) -> Result<Self> {
        let domains = DiskTable::open(
            dir.join("domains.idx"),
            1,
            DOMAIN_RECORD_SIZE,
            Some(dir.join("domains.roots")),
        )?;
        let cidrs = DiskTable::open(dir.join("cidrs.idx"), 2, CIDR_RECORD_SIZE, None)?;
        Ok(Self {
            dir,
            owned,
            domains,
            cidrs,
        })
    }

    fn matches(&self, endpoint: &Endpoint, parent: bool) -> bool {
        match endpoint {
            Endpoint::Domain { host, .. } => self.domains.matches_domain_name(host, parent),
            Endpoint::Ip { addr, .. } => self.cidrs.matches_ip(addr.ip()),
        }
    }

    fn pattern_iter(&self) -> impl Iterator<Item = Result<String>> + '_ {
        (0..self.domains.count)
            .map(|index| self.domains.pattern_at(index))
            .chain((0..self.cidrs.count).map(|index| self.cidrs.pattern_at(index)))
    }

    fn contains_pattern(&self, pattern: &str) -> Result<bool> {
        if let Some((address, prefix)) = pattern.split_once('/') {
            let address = address
                .parse::<IpAddr>()
                .map_err(|_| Error::invalid("invalid CIDR address"))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| Error::invalid("invalid CIDR prefix length"))?;
            return Ok(self
                .cidrs
                .contains(&cidr_key(mask_address(address, prefix), prefix)));
        }
        let labels = pattern_labels(pattern)?;
        Ok(self.domains.contains(&domain_key(&labels)))
    }
}

#[derive(Debug)]
struct DiskTable {
    map: Mmap,
    kind: u32,
    record_size: usize,
    count: u64,
    root_labels: Vec<Vec<u8>>,
}

impl DiskTable {
    fn open(
        path: PathBuf,
        kind: u32,
        record_size: usize,
        root_path: Option<PathBuf>,
    ) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(io_error)?;
        let mut header = [0u8; HEADER_SIZE];
        read_exact_at(&file, &mut header, 0).map_err(io_error)?;
        if &header[..8] != MAGIC
            || u32::from_le_bytes(header[8..12].try_into().unwrap()) != VERSION
            || u32::from_le_bytes(header[12..16].try_into().unwrap()) != kind
            || u32::from_le_bytes(header[16..20].try_into().unwrap()) != record_size as u32
        {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("invalid doradus trie index: {}", path.display()),
            ));
        }
        let count = u64::from_le_bytes(header[24..32].try_into().unwrap());
        let expected = HEADER_SIZE as u64 + count.saturating_mul(record_size as u64);
        let actual = file.metadata().map_err(io_error)?.len();
        if actual != expected {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("truncated doradus trie index: {}", path.display()),
            ));
        }
        let map = unsafe { MmapOptions::new().map(&file) }.map_err(io_error)?;
        let root_labels = root_path
            .map(load_root_labels)
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            map,
            kind,
            record_size,
            count,
            root_labels,
        })
    }

    fn contains(&self, key: &[u8]) -> bool {
        let mut low = 0;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let start = HEADER_SIZE + middle as usize * self.record_size;
            let Some(record) = self.map.get(start..start + self.record_size) else {
                return false;
            };
            let record_key = if self.kind == 1 {
                let length = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
                &record[2..2 + length.min(DOMAIN_KEY_SIZE)]
            } else {
                &record[..CIDR_KEY_SIZE]
            };
            match record_key.cmp(key) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    /// Check whether the domain table contains a complete path below
    /// `prefix`. The records are sorted by reversed domain key, so a lower
    /// bound plus one delimiter check replaces a heap-backed child map.
    fn has_prefix(&self, prefix: &[u8]) -> bool {
        if self.kind == 1 && !prefix.contains(&b'.') {
            return self
                .root_labels
                .binary_search_by(|root| root.as_slice().cmp(prefix))
                .is_ok();
        }
        let mut low = 0;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let start = HEADER_SIZE + middle as usize * self.record_size;
            let Some(record) = self.map.get(start..start + self.record_size) else {
                return false;
            };
            let length = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
            let key = &record[2..2 + length.min(DOMAIN_KEY_SIZE)];
            if key < prefix {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let start = HEADER_SIZE + low as usize * self.record_size;
        let Some(record) = self.map.get(start..start + self.record_size) else {
            return false;
        };
        let length = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
        let key = &record[2..2 + length.min(DOMAIN_KEY_SIZE)];
        key.starts_with(prefix)
            && (key.len() == prefix.len() || key.get(prefix.len()) == Some(&b'.'))
    }

    fn pattern_at(&self, index: u64) -> Result<String> {
        let start = HEADER_SIZE + index as usize * self.record_size;
        let record = self
            .map
            .get(start..start + self.record_size)
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid disk trie record offset"))?;
        if self.kind == 1 {
            let length = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
            let key = std::str::from_utf8(&record[2..2 + length])
                .map_err(|_| Error::new(ErrorKind::Protocol, "invalid domain key in disk trie"))?;
            let mut labels = key.split('.').collect::<Vec<_>>();
            labels.reverse();
            Ok(labels.join("."))
        } else {
            let address = match record[0] {
                4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&record[2..6]).unwrap())),
                6 => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&record[2..18]).unwrap(),
                )),
                _ => {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "invalid address family in disk trie",
                    ));
                }
            };
            Ok(format!("{address}/{}", record[1]))
        }
    }

    fn matches_domain_name(&self, name: &DomainName, parent: bool) -> bool {
        if !parent {
            let Some(root) = name.labels().next_back() else {
                return false;
            };
            if !self.has_prefix(root.as_bytes()) && !self.has_prefix(b"*") {
                return false;
            }
        }
        let mut labels = name.labels().collect::<Vec<_>>();
        labels.reverse();
        if labels.is_empty() {
            return false;
        }

        if parent {
            (1..=labels.len())
                .rev()
                .any(|end| self.matches_domain_path(&labels[..end]))
        } else {
            self.matches_domain_path(&labels)
        }
    }

    fn matches_domain_path(&self, labels: &[&str]) -> bool {
        let mut path = Vec::new();
        self.matches_domain_node(labels, 0, &mut path)
    }

    fn matches_domain_node(&self, labels: &[&str], depth: usize, path: &mut Vec<u8>) -> bool {
        if depth == labels.len() {
            if self.contains(path) {
                return true;
            }
            let length = path.len();
            append_label(path, "*");
            let matched = self.contains(path);
            path.truncate(length);
            return matched;
        }

        let length = path.len();
        append_label(path, labels[depth]);
        if self.has_prefix(path) && self.matches_domain_node(labels, depth + 1, path) {
            return true;
        }
        path.truncate(length);

        append_label(path, "*");
        if self.has_prefix(path)
            && (self.contains(path) || self.matches_domain_node(labels, depth + 1, path))
        {
            return true;
        }
        path.truncate(length);
        false
    }

    fn matches_ip(&self, address: IpAddr) -> bool {
        let width = if address.is_ipv4() { 32 } else { 128 };
        (0..=width).any(|prefix| self.contains(&cidr_key(mask_address(address, prefix), prefix)))
    }
}

fn canonical_pattern(pattern: &str) -> Result<String> {
    if let Some((address, prefix)) = pattern.split_once('/') {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| Error::invalid("invalid CIDR address"))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| Error::invalid("invalid CIDR prefix length"))?;
        let max_bits = if address.is_ipv4() { 32 } else { 128 };
        if prefix > max_bits {
            return Err(Error::invalid("CIDR prefix length exceeds address width"));
        }
        Ok(format!("{}/{}", mask_address(address, prefix), prefix))
    } else {
        Ok(pattern_labels(pattern)?.join("."))
    }
}

fn append_label(path: &mut Vec<u8>, label: &str) {
    if !path.is_empty() {
        path.push(b'.');
    }
    path.extend_from_slice(label.as_bytes());
}

fn domain_key(labels: &[String]) -> Vec<u8> {
    labels
        .iter()
        .rev()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(".")
        .into_bytes()
}

fn cidr_key(address: IpAddr, prefix: u8) -> [u8; CIDR_KEY_SIZE] {
    let mut key = [0u8; CIDR_KEY_SIZE];
    key[0] = if address.is_ipv4() { 4 } else { 6 };
    key[1] = prefix;
    match address {
        IpAddr::V4(address) => key[2..6].copy_from_slice(&address.octets()),
        IpAddr::V6(address) => key[2..18].copy_from_slice(&address.octets()),
    }
    key
}

fn mask_address(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mut octets = address.octets();
            let full = usize::from(prefix / 8);
            let remainder = prefix % 8;
            if full < octets.len() {
                if remainder != 0 {
                    octets[full] &= 0xff << (8 - remainder);
                }
                for byte in &mut octets[full + usize::from(remainder != 0)..] {
                    *byte = 0;
                }
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(address) => {
            let mut octets = address.octets();
            let full = usize::from(prefix / 8);
            let remainder = prefix % 8;
            if full < octets.len() {
                if remainder != 0 {
                    octets[full] &= 0xff << (8 - remainder);
                }
                for byte in &mut octets[full + usize::from(remainder != 0)..] {
                    *byte = 0;
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(unix)]
fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    let mut read = 0;
    while read < buffer.len() {
        let count = file.read_at(&mut buffer[read..], offset + read as u64)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short disk trie read",
            ));
        }
        read += count;
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut read = 0;
    while read < buffer.len() {
        let count = file.seek_read(&mut buffer[read..], offset + read as u64)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short disk trie read",
            ));
        }
        read += count;
    }
    Ok(())
}

#[path = "ondisk_build.rs"]
mod build;

use build::{flush_run, load_root_labels, merge_runs_to_table, write_root_index};

#[cfg(test)]
#[path = "ondisk_tests.rs"]
mod tests;
