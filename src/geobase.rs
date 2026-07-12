//! Bounded parsing and durable storage for user-managed geographic bases.
//!
//! Payloads live outside `HincyrayState`. A manifest points at immutable,
//! revisioned generations, so an interrupted update leaves the previous
//! generation usable.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

pub const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TOTAL_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_BASES: usize = 32;
pub const MAX_DOMAINS_PER_BASE: usize = 20_000;
pub const MAX_LINES: usize = 200_000;
pub const MAX_ENTRIES: usize = 200_000;
pub const MAX_LINE_BYTES: usize = 512;

const MANIFEST_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const SOURCE_FILE: &str = "source";
const DIRECT_FILE: &str = "direct";
const ACTIVE_FILE: &str = "active";
const UNRESOLVED_FILE: &str = "unresolved";
const STATIC_DIRECT_FILE: &str = "static-direct";
const STATIC_ACTIVE_FILE: &str = "static-active";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoBaseSourceKind {
    Url,
    Upload,
    Manual,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseSource {
    pub kind: GeoBaseSourceKind,
    /// URL, original upload name, or a short user-entered description.
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoBaseStatus {
    Ready,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Direct,
    Active,
    Unresolved,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseCounts {
    pub source_domains: usize,
    pub source_networks: usize,
    pub direct: usize,
    pub active: usize,
    pub unresolved: usize,
    pub static_direct: usize,
    pub static_active: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseListMetadata {
    pub file: String,
    pub count: usize,
    #[serde(default)]
    pub fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoBaseArtifactKind {
    Domain,
    Ipcidr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseListsMetadata {
    pub direct: GeoBaseListMetadata,
    pub active: GeoBaseListMetadata,
    pub unresolved: GeoBaseListMetadata,
    pub static_direct: Option<GeoBaseListMetadata>,
    pub static_active: Option<GeoBaseListMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseRecord {
    pub id: String,
    pub name: String,
    pub source: GeoBaseSource,
    pub enabled: bool,
    pub status: GeoBaseStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub revision: u64,
    pub fingerprint: String,
    pub counts: GeoBaseCounts,
    pub lists: GeoBaseListsMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseManifest {
    pub version: u32,
    pub updated_at: u64,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub applied_generation: u64,
    pub bases: Vec<GeoBaseRecord>,
    /// Exact snapshot used by the last successfully activated config.
    #[serde(default)]
    pub applied_bases: Vec<GeoBaseRecord>,
}

impl GeoBaseManifest {
    pub fn requires_apply(&self) -> bool {
        self.generation != self.applied_generation || self.bases != self.applied_bases
    }
}

impl Default for GeoBaseManifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            updated_at: 0,
            generation: 0,
            applied_generation: 0,
            bases: Vec::new(),
            applied_bases: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseUpsertRequest {
    pub id: String,
    pub name: String,
    pub source: GeoBaseSource,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainClassification {
    pub domain: String,
    pub classification: Classification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticRouteEntry {
    pub network: String,
    /// Static routes are deliberate overrides and cannot be unresolved.
    pub target: Classification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBaseGenerationInput {
    pub classifications: Vec<DomainClassification>,
    #[serde(default)]
    pub static_entries: Vec<StaticRouteEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedGeoBase {
    /// Unique apex names passed to the online analyzer.
    pub domains: Vec<String>,
    /// Matching-aware source entries used for provider output and diffs.
    pub domain_entries: Vec<ParsedDomain>,
    /// Valid public IP/CIDR source entries, reported for review only.
    pub networks: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "match", content = "domain", rename_all = "snake_case")]
pub enum ParsedDomain {
    Exact(String),
    Suffix(String),
}

impl ParsedDomain {
    fn domain(&self) -> &str {
        match self {
            Self::Exact(domain) | Self::Suffix(domain) => domain,
        }
    }

    fn provider_line(&self) -> String {
        match self {
            Self::Exact(domain) => domain.clone(),
            Self::Suffix(domain) => format!("+.{domain}"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDiff {
    pub added_domains: Vec<String>,
    pub removed_domains: Vec<String>,
    pub added_networks: Vec<String>,
    pub removed_networks: Vec<String>,
}

#[derive(Debug)]
pub enum GeoBaseError {
    InvalidId(String),
    InvalidInput(String),
    LimitExceeded(String),
    NotFound(String),
    AlreadyExists(String),
    Conflict(String),
    Io(io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for GeoBaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId(message)
            | Self::InvalidInput(message)
            | Self::LimitExceeded(message)
            | Self::NotFound(message)
            | Self::AlreadyExists(message)
            | Self::Conflict(message) => f.write_str(message),
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Json(error) => write!(f, "JSON error: {error}"),
        }
    }
}

impl std::error::Error for GeoBaseError {}

impl From<io::Error> for GeoBaseError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for GeoBaseError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub type Result<T> = std::result::Result<T, GeoBaseError>;

/// Create a deterministic ID suitable for use as an on-disk component.
pub fn stable_id(seed: &str) -> String {
    format!("geobase-{:016x}", fingerprint_bytes(seed.as_bytes()))
}

/// Deterministic corruption-detection fingerprint used by immutable artifacts.
pub fn artifact_fingerprint(bytes: &[u8]) -> String {
    format!("fnv1a64:{:016x}", fingerprint_bytes(bytes))
}

/// Strictly validate generated provider bytes and return their entry count.
pub fn validate_artifact(bytes: &[u8], kind: GeoBaseArtifactKind) -> Result<usize> {
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(GeoBaseError::LimitExceeded(format!(
            "artifact exceeds {MAX_SOURCE_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GeoBaseError::InvalidInput("artifact must be valid UTF-8".to_owned()))?;
    let mut count = 0usize;
    for (index, raw) in text.lines().enumerate() {
        if raw.len() > MAX_LINE_BYTES {
            return Err(GeoBaseError::LimitExceeded(format!(
                "artifact line {} exceeds {MAX_LINE_BYTES} bytes",
                index + 1
            )));
        }
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line != raw {
            return Err(GeoBaseError::InvalidInput(format!(
                "artifact line {} has surrounding whitespace",
                index + 1
            )));
        }
        match kind {
            GeoBaseArtifactKind::Domain => {
                let domain = line.strip_prefix("+.").unwrap_or(line);
                parse_domain(domain, index + 1)?;
            }
            GeoBaseArtifactKind::Ipcidr => {
                validate_public_network(line, index + 1)?;
            }
        }
        count += 1;
        if count > MAX_ENTRIES {
            return Err(GeoBaseError::LimitExceeded(format!(
                "artifact exceeds {MAX_ENTRIES} entries"
            )));
        }
    }
    Ok(count)
}

pub fn validate_id(id: &str) -> Result<()> {
    let valid = (1..=64).contains(&id.len())
        && id.is_ascii()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && id.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric);
    if valid {
        Ok(())
    } else {
        Err(GeoBaseError::InvalidId(format!(
            "invalid GeoBase id {id:?}: use 1-64 lowercase ASCII letters, digits, or internal hyphens"
        )))
    }
}

pub fn parse_source(source: &[u8]) -> Result<ParsedGeoBase> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(GeoBaseError::LimitExceeded(format!(
            "source exceeds {MAX_SOURCE_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(source)
        .map_err(|_| GeoBaseError::InvalidInput("source must be valid UTF-8".to_owned()))?;
    let mut domains = BTreeSet::new();
    let mut domain_entries = BTreeSet::new();
    let mut networks = BTreeSet::new();
    let mut line_count = 0usize;

    for (index, raw_line) in text.lines().enumerate() {
        line_count += 1;
        if line_count > MAX_LINES {
            return Err(GeoBaseError::LimitExceeded(format!(
                "source exceeds {MAX_LINES} lines"
            )));
        }
        if raw_line.len() > MAX_LINE_BYTES {
            return Err(GeoBaseError::LimitExceeded(format!(
                "line {} exceeds {MAX_LINE_BYTES} bytes",
                index + 1
            )));
        }
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let (kind, value) = split_mihomo_line(line);
        match kind {
            InputKind::ExactDomain => {
                let domain = parse_domain(value, index + 1)?;
                domains.insert(domain.clone());
                domain_entries.insert(ParsedDomain::Exact(domain));
            }
            InputKind::SuffixDomain => {
                let domain = parse_domain(value, index + 1)?;
                domains.insert(domain.clone());
                domain_entries.insert(ParsedDomain::Suffix(domain));
            }
            InputKind::Network => {
                networks.insert(validate_public_network(value, index + 1)?);
            }
            InputKind::Auto => {
                if value.parse::<IpAddr>().is_ok() || value.contains('/') {
                    networks.insert(validate_public_network(value, index + 1)?);
                } else {
                    let domain = parse_domain(value, index + 1)?;
                    domains.insert(domain.clone());
                    domain_entries.insert(ParsedDomain::Exact(domain));
                }
            }
        }
        if domain_entries.len() + networks.len() > MAX_ENTRIES {
            return Err(GeoBaseError::LimitExceeded(format!(
                "source exceeds {MAX_ENTRIES} unique entries"
            )));
        }
        if domain_entries.len() > MAX_DOMAINS_PER_BASE {
            return Err(GeoBaseError::LimitExceeded(format!(
                "source exceeds {MAX_DOMAINS_PER_BASE} unique domains"
            )));
        }
    }

    Ok(ParsedGeoBase {
        domains: domains.into_iter().collect(),
        domain_entries: domain_entries.into_iter().collect(),
        networks: networks.into_iter().collect(),
    })
}

/// Classify only domains. Source IP/CIDR entries are never passed to the
/// analyzer and require explicit `StaticRouteEntry` selection to be stored.
pub fn classify_domains<F>(parsed: &ParsedGeoBase, mut analyzer: F) -> Vec<DomainClassification>
where
    F: FnMut(&str) -> Classification,
{
    parsed
        .domains
        .iter()
        .map(|domain| DomainClassification {
            domain: domain.clone(),
            classification: analyzer(domain),
        })
        .collect()
}

pub fn diff_sources(previous: &ParsedGeoBase, current: &ParsedGeoBase) -> SourceDiff {
    SourceDiff {
        added_domains: domain_difference(&current.domain_entries, &previous.domain_entries),
        removed_domains: domain_difference(&previous.domain_entries, &current.domain_entries),
        added_networks: difference(&current.networks, &previous.networks),
        removed_networks: difference(&previous.networks, &current.networks),
    }
}

#[derive(Clone, Debug)]
pub struct GeoBaseStore {
    root: PathBuf,
    transaction: Arc<Mutex<()>>,
}

impl GeoBaseStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            transaction: Arc::new(Mutex::new(())),
        }
    }

    pub fn load_manifest(&self) -> Result<GeoBaseManifest> {
        let _transaction = self.lock_transaction()?;
        self.load_manifest_unlocked()
    }

    fn load_manifest_unlocked(&self) -> Result<GeoBaseManifest> {
        let path = self.root.join(MANIFEST_FILE);
        if !path.exists() {
            return Ok(GeoBaseManifest::default());
        }
        let manifest: GeoBaseManifest = serde_json::from_slice(&fs::read(path)?)?;
        validate_manifest(&manifest)?;
        Ok(manifest)
    }

    pub fn save_manifest(&self, manifest: &GeoBaseManifest) -> Result<()> {
        let _transaction = self.lock_transaction()?;
        let current = self.load_manifest_unlocked()?;
        if manifest.generation != current.generation {
            return Err(GeoBaseError::Conflict(format!(
                "GeoBase manifest generation is {}, expected {}",
                current.generation, manifest.generation
            )));
        }
        let mut next = manifest.clone();
        next.generation = next_generation(current.generation)?;
        next.updated_at = unix_now()?;
        self.save_manifest_unlocked(&next)
    }

    pub fn create(
        &self,
        request: GeoBaseUpsertRequest,
        source: &[u8],
        generation: GeoBaseGenerationInput,
    ) -> Result<GeoBaseRecord> {
        validate_request(&request)?;
        let _transaction = self.lock_transaction()?;
        let mut manifest = self.load_manifest_unlocked()?;
        if manifest.bases.iter().any(|record| record.id == request.id) {
            return Err(GeoBaseError::AlreadyExists(format!(
                "GeoBase {} already exists",
                request.id
            )));
        }
        if manifest.bases.len() >= MAX_BASES {
            return Err(GeoBaseError::LimitExceeded(format!(
                "GeoBase manifest cannot contain more than {MAX_BASES} bases"
            )));
        }
        self.replace_generation(&mut manifest, request, source, generation, None)
    }

    pub fn update(
        &self,
        request: GeoBaseUpsertRequest,
        expected_revision: u64,
        source: &[u8],
        generation: GeoBaseGenerationInput,
    ) -> Result<GeoBaseRecord> {
        validate_request(&request)?;
        let _transaction = self.lock_transaction()?;
        let mut manifest = self.load_manifest_unlocked()?;
        let current = manifest
            .bases
            .iter()
            .find(|record| record.id == request.id)
            .cloned()
            .ok_or_else(|| GeoBaseError::NotFound(format!("GeoBase {} not found", request.id)))?;
        if current.revision != expected_revision {
            return Err(GeoBaseError::Conflict(format!(
                "GeoBase {} revision is {}, expected {expected_revision}",
                request.id, current.revision
            )));
        }
        self.replace_generation(&mut manifest, request, source, generation, Some(current))
    }

    pub fn delete(&self, id: &str) -> Result<GeoBaseRecord> {
        validate_id(id)?;
        let _transaction = self.lock_transaction()?;
        let mut manifest = self.load_manifest_unlocked()?;
        let index = manifest
            .bases
            .iter()
            .position(|record| record.id == id)
            .ok_or_else(|| GeoBaseError::NotFound(format!("GeoBase {id} not found")))?;
        let removed = manifest.bases.remove(index);
        manifest.updated_at = unix_now()?;
        manifest.generation = next_generation(manifest.generation)?;
        self.save_manifest_unlocked(&manifest)?;
        Ok(removed)
    }

    pub fn set_enabled(
        &self,
        id: &str,
        enabled: bool,
        expected_revision: Option<u64>,
    ) -> Result<GeoBaseRecord> {
        validate_id(id)?;
        let _transaction = self.lock_transaction()?;
        let mut manifest = self.load_manifest_unlocked()?;
        let record = manifest
            .bases
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| GeoBaseError::NotFound(format!("GeoBase {id} not found")))?;
        if let Some(expected) = expected_revision
            && record.revision != expected
        {
            return Err(GeoBaseError::Conflict(format!(
                "GeoBase {id} revision is {}, expected {expected}",
                record.revision
            )));
        }
        record.enabled = enabled;
        record.status = if enabled {
            GeoBaseStatus::Ready
        } else {
            GeoBaseStatus::Disabled
        };
        record.updated_at = unix_now()?;
        let response = record.clone();
        manifest.updated_at = response.updated_at;
        manifest.generation = next_generation(manifest.generation)?;
        self.save_manifest_unlocked(&manifest)?;
        Ok(response)
    }

    pub fn mark_applied(&self, expected_generation: u64) -> Result<GeoBaseManifest> {
        let _transaction = self.lock_transaction()?;
        let mut manifest = self.load_manifest_unlocked()?;
        if manifest.generation != expected_generation {
            return Err(GeoBaseError::Conflict(format!(
                "GeoBase manifest generation is {}, expected {expected_generation}",
                manifest.generation
            )));
        }
        manifest.applied_bases = manifest.bases.clone();
        manifest.applied_generation = expected_generation;
        manifest.updated_at = unix_now()?;
        self.save_manifest_unlocked(&manifest)?;
        Ok(manifest)
    }

    /// Record the exact snapshot that was activated without changing newer
    /// desired state. Callers normally serialize apply and mutations, but this
    /// transaction keeps acknowledgement correct if that invariant changes.
    pub fn commit_applied_snapshot(
        &self,
        expected_generation: u64,
        activated_bases: Vec<GeoBaseRecord>,
    ) -> Result<GeoBaseManifest> {
        let _transaction = self.lock_transaction()?;
        let mut manifest = self.load_manifest_unlocked()?;
        if expected_generation > manifest.generation {
            return Err(GeoBaseError::Conflict(format!(
                "GeoBase manifest generation is {}, cannot apply future generation {expected_generation}",
                manifest.generation
            )));
        }
        validate_records(&activated_bases)?;
        manifest.applied_generation = expected_generation;
        manifest.applied_bases = activated_bases;
        manifest.updated_at = unix_now()?;
        self.save_manifest_unlocked(&manifest)?;
        Ok(manifest)
    }

    /// Remove only artifacts referenced by neither desired nor applied state.
    pub fn garbage_collect(&self) -> Result<usize> {
        let _transaction = self.lock_transaction()?;
        let manifest = self.load_manifest_unlocked()?;
        let retained: BTreeSet<PathBuf> = manifest
            .bases
            .iter()
            .chain(manifest.applied_bases.iter())
            .map(|record| self.generation_dir(record))
            .collect::<Result<_>>()?;
        let mut removed = 0;
        if !self.root.exists() {
            return Ok(removed);
        }
        for base in fs::read_dir(&self.root)? {
            let base = base?;
            if !base.file_type()?.is_dir() {
                continue;
            }
            for artifact in fs::read_dir(base.path())? {
                let artifact = artifact?;
                if artifact.file_type()?.is_dir() && !retained.contains(&artifact.path()) {
                    fs::remove_dir_all(artifact.path())?;
                    removed += 1;
                }
            }
            if fs::read_dir(base.path())?.next().is_none() {
                fs::remove_dir(base.path())?;
            }
        }
        sync_dir(&self.root)?;
        Ok(removed)
    }

    pub fn load_source(&self, id: &str) -> Result<Vec<u8>> {
        let record = self.record(id)?;
        Ok(fs::read(self.generation_dir(&record)?.join(SOURCE_FILE))?)
    }

    pub fn load_lists(&self, id: &str) -> Result<GeoBaseGenerationInput> {
        let record = self.record(id)?;
        let dir = self.generation_dir(&record)?;
        let mut classifications = Vec::new();
        for (file, classification) in [
            (DIRECT_FILE, Classification::Direct),
            (ACTIVE_FILE, Classification::Active),
            (UNRESOLVED_FILE, Classification::Unresolved),
        ] {
            classifications.extend(read_lines(&dir.join(file))?.into_iter().map(|domain| {
                DomainClassification {
                    domain: domain.strip_prefix("+.").unwrap_or(&domain).to_owned(),
                    classification,
                }
            }));
        }
        let mut static_entries = Vec::new();
        for (file, target) in [
            (STATIC_DIRECT_FILE, Classification::Direct),
            (STATIC_ACTIVE_FILE, Classification::Active),
        ] {
            static_entries.extend(
                read_lines(&dir.join(file))?
                    .into_iter()
                    .map(|network| StaticRouteEntry { network, target }),
            );
        }
        Ok(GeoBaseGenerationInput {
            classifications,
            static_entries,
        })
    }

    pub fn diff_with_stored(&self, id: &str, new_source: &[u8]) -> Result<SourceDiff> {
        let previous = parse_source(&self.load_source(id)?)?;
        let current = parse_source(new_source)?;
        Ok(diff_sources(&previous, &current))
    }

    fn record(&self, id: &str) -> Result<GeoBaseRecord> {
        validate_id(id)?;
        self.load_manifest()?
            .bases
            .into_iter()
            .find(|record| record.id == id)
            .ok_or_else(|| GeoBaseError::NotFound(format!("GeoBase {id} not found")))
    }

    fn generation_dir(&self, record: &GeoBaseRecord) -> Result<PathBuf> {
        let relative = Path::new(&record.lists.direct.file);
        let directory = relative.parent().ok_or_else(|| {
            GeoBaseError::InvalidInput(format!(
                "list path has no generation directory: {}",
                record.lists.direct.file
            ))
        })?;
        Ok(self.root.join(directory))
    }

    fn replace_generation(
        &self,
        manifest: &mut GeoBaseManifest,
        request: GeoBaseUpsertRequest,
        source: &[u8],
        generation: GeoBaseGenerationInput,
        previous: Option<GeoBaseRecord>,
    ) -> Result<GeoBaseRecord> {
        let parsed = parse_source(source)?;
        let lists = validate_generation(&parsed, generation)?;
        self.enforce_retained_source_quota(source.len() as u64)?;
        let now = unix_now()?;
        let revision = previous.as_ref().map_or(1, |record| record.revision + 1);
        let manifest_generation = next_generation(manifest.generation)?;
        let base_dir = self.root.join(&request.id);
        fs::create_dir_all(&base_dir)?;
        let unique = UNIQUE_GENERATION.fetch_add(1, Ordering::Relaxed);
        let nanos = unix_now_nanos()?;
        let directory_name = format!(
            "g{manifest_generation}-r{revision}-{nanos}-{}-{unique}",
            std::process::id()
        );
        let final_dir = base_dir.join(&directory_name);
        let temp_dir = base_dir.join(format!(".{directory_name}.tmp"));
        fs::create_dir(&temp_dir)?;
        let write_result = write_generation(&temp_dir, source, &lists);
        if let Err(error) = write_result {
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temp_dir, &final_dir) {
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(error.into());
        }
        sync_dir(&final_dir)?;
        sync_dir(&base_dir)?;
        sync_dir(&self.root)?;

        let counts = GeoBaseCounts {
            source_domains: parsed.domain_entries.len(),
            source_networks: parsed.networks.len(),
            direct: lists.direct.len(),
            active: lists.active.len(),
            unresolved: lists.unresolved.len(),
            static_direct: lists.static_direct.len(),
            static_active: lists.static_active.len(),
        };
        let prefix = format!("{}/{directory_name}/", request.id);
        let record = GeoBaseRecord {
            id: request.id.clone(),
            name: request.name,
            source: request.source,
            enabled: request.enabled,
            status: if request.enabled {
                GeoBaseStatus::Ready
            } else {
                GeoBaseStatus::Disabled
            },
            created_at: previous.as_ref().map_or(now, |record| record.created_at),
            updated_at: now,
            revision,
            fingerprint: artifact_fingerprint(source),
            counts,
            lists: GeoBaseListsMetadata {
                direct: list_metadata(&prefix, DIRECT_FILE, &lists.direct),
                active: list_metadata(&prefix, ACTIVE_FILE, &lists.active),
                unresolved: list_metadata(&prefix, UNRESOLVED_FILE, &lists.unresolved),
                static_direct: optional_list_metadata(
                    &prefix,
                    STATIC_DIRECT_FILE,
                    &lists.static_direct,
                ),
                static_active: optional_list_metadata(
                    &prefix,
                    STATIC_ACTIVE_FILE,
                    &lists.static_active,
                ),
            },
        };
        if let Some(index) = manifest
            .bases
            .iter()
            .position(|existing| existing.id == request.id)
        {
            manifest.bases[index] = record.clone();
        } else {
            manifest.bases.push(record.clone());
            manifest.bases.sort_by(|left, right| left.id.cmp(&right.id));
        }
        manifest.updated_at = now;
        manifest.generation = manifest_generation;
        // A published orphan is harmless if this fails and its unique name
        // guarantees the next transaction can proceed. Explicit GC removes it.
        self.save_manifest_unlocked(manifest)?;
        Ok(record)
    }

    fn save_manifest_unlocked(&self, manifest: &GeoBaseManifest) -> Result<()> {
        validate_manifest(manifest)?;
        fs::create_dir_all(&self.root)?;
        atomic_json(&self.root.join(MANIFEST_FILE), manifest)
    }

    fn enforce_retained_source_quota(&self, added: u64) -> Result<()> {
        let retained = retained_source_bytes(&self.root)?;
        if retained.saturating_add(added) > MAX_TOTAL_SOURCE_BYTES {
            return Err(GeoBaseError::LimitExceeded(format!(
                "retained GeoBase sources exceed {MAX_TOTAL_SOURCE_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn lock_transaction(&self) -> Result<MutexGuard<'_, ()>> {
        self.transaction
            .lock()
            .map_err(|_| GeoBaseError::Conflict("GeoBase transaction lock is poisoned".to_owned()))
    }
}

static UNIQUE_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct ValidatedLists {
    direct: Vec<String>,
    active: Vec<String>,
    unresolved: Vec<String>,
    static_direct: Vec<String>,
    static_active: Vec<String>,
}

fn validate_generation(
    parsed: &ParsedGeoBase,
    generation: GeoBaseGenerationInput,
) -> Result<ValidatedLists> {
    let source_domains: BTreeSet<&str> = parsed.domains.iter().map(String::as_str).collect();
    let mut classified = BTreeMap::new();
    for item in generation.classifications {
        let domain = parse_domain(&item.domain, 0)?;
        if !source_domains.contains(domain.as_str()) {
            return Err(GeoBaseError::InvalidInput(format!(
                "classification contains domain absent from source: {domain}"
            )));
        }
        if classified
            .insert(domain.clone(), item.classification)
            .is_some()
        {
            return Err(GeoBaseError::InvalidInput(format!(
                "domain classified more than once: {domain}"
            )));
        }
    }
    let mut lists = ValidatedLists::default();
    for entry in &parsed.domain_entries {
        let domain = entry.domain();
        let provider_line = entry.provider_line();
        match classified
            .get(domain)
            .copied()
            .unwrap_or(Classification::Unresolved)
        {
            Classification::Direct => lists.direct.push(provider_line),
            Classification::Active => lists.active.push(provider_line),
            Classification::Unresolved => lists.unresolved.push(provider_line),
        }
    }
    let mut static_routes = BTreeMap::new();
    let source_networks: BTreeSet<&str> = parsed.networks.iter().map(String::as_str).collect();
    for entry in generation.static_entries {
        if entry.target == Classification::Unresolved {
            return Err(GeoBaseError::InvalidInput(
                "static route target must be direct or active".to_owned(),
            ));
        }
        let network = validate_public_network(&entry.network, 0)?;
        if !source_networks.contains(network.as_str()) {
            return Err(GeoBaseError::InvalidInput(format!(
                "static route contains network absent from source: {network}"
            )));
        }
        if let Some(previous) = static_routes.insert(network.clone(), entry.target)
            && previous != entry.target
        {
            return Err(GeoBaseError::InvalidInput(format!(
                "static route has conflicting targets: {network}"
            )));
        }
    }
    for (network, target) in static_routes {
        match target {
            Classification::Direct => lists.static_direct.push(network),
            Classification::Active => lists.static_active.push(network),
            Classification::Unresolved => unreachable!(),
        }
    }
    Ok(lists)
}

fn write_generation(dir: &Path, source: &[u8], lists: &ValidatedLists) -> Result<()> {
    write_synced(&dir.join(SOURCE_FILE), source)?;
    write_lines(&dir.join(DIRECT_FILE), &lists.direct)?;
    write_lines(&dir.join(ACTIVE_FILE), &lists.active)?;
    write_lines(&dir.join(UNRESOLVED_FILE), &lists.unresolved)?;
    write_lines(&dir.join(STATIC_DIRECT_FILE), &lists.static_direct)?;
    write_lines(&dir.join(STATIC_ACTIVE_FILE), &lists.static_active)?;
    sync_dir(dir)
}

fn write_lines(path: &Path, lines: &[String]) -> Result<()> {
    let mut data = lines.join("\n").into_bytes();
    if !data.is_empty() {
        data.push(b'\n');
    }
    write_synced(path, &data)
}

fn write_synced(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        GeoBaseError::InvalidInput("manifest path has no parent directory".to_owned())
    })?;
    let mut temp = NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temp, value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| GeoBaseError::Io(error.error))?;
    sync_dir(parent)?;
    Ok(())
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    Ok(text.lines().map(str::to_owned).collect())
}

fn list_bytes(lines: &[String]) -> Vec<u8> {
    let mut data = lines.join("\n").into_bytes();
    if !data.is_empty() {
        data.push(b'\n');
    }
    data
}

fn list_metadata(prefix: &str, file: &str, lines: &[String]) -> GeoBaseListMetadata {
    let bytes = list_bytes(lines);
    GeoBaseListMetadata {
        file: format!("{prefix}{file}"),
        count: lines.len(),
        fingerprint: artifact_fingerprint(&bytes),
    }
}

fn optional_list_metadata(
    prefix: &str,
    file: &str,
    lines: &[String],
) -> Option<GeoBaseListMetadata> {
    (!lines.is_empty()).then(|| list_metadata(prefix, file, lines))
}

fn validate_request(request: &GeoBaseUpsertRequest) -> Result<()> {
    validate_id(&request.id)?;
    if request.name.trim().is_empty() || request.name.len() > 128 {
        return Err(GeoBaseError::InvalidInput(
            "GeoBase name must contain 1-128 bytes".to_owned(),
        ));
    }
    if request.source.value.len() > 2048 {
        return Err(GeoBaseError::InvalidInput(
            "GeoBase source value exceeds 2048 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_record_paths(record: &GeoBaseRecord) -> Result<()> {
    let expected_files = [
        (&record.lists.direct, DIRECT_FILE),
        (&record.lists.active, ACTIVE_FILE),
        (&record.lists.unresolved, UNRESOLVED_FILE),
    ];
    let mut generation_dir = None;
    for (metadata, expected_file) in expected_files {
        let path = validate_list_path(&record.id, metadata, expected_file)?;
        let parent = path.parent().expect("validated list path has parent");
        if generation_dir.as_ref().is_some_and(|value| value != parent) {
            return Err(GeoBaseError::InvalidInput(format!(
                "GeoBase {} list paths use different generations",
                record.id
            )));
        }
        generation_dir = Some(parent.to_path_buf());
    }
    for (metadata, expected_file) in [
        (record.lists.static_direct.as_ref(), STATIC_DIRECT_FILE),
        (record.lists.static_active.as_ref(), STATIC_ACTIVE_FILE),
    ] {
        if let Some(metadata) = metadata {
            let path = validate_list_path(&record.id, metadata, expected_file)?;
            if path.parent() != generation_dir.as_deref() {
                return Err(GeoBaseError::InvalidInput(format!(
                    "GeoBase {} list paths use different generations",
                    record.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_list_path(
    id: &str,
    metadata: &GeoBaseListMetadata,
    expected_file: &str,
) -> Result<PathBuf> {
    if metadata.fingerprint.is_empty() {
        return Err(GeoBaseError::InvalidInput(format!(
            "GeoBase artifact {} has no fingerprint",
            metadata.file
        )));
    }
    if !metadata.fingerprint.starts_with("fnv1a64:") || metadata.fingerprint.len() != 24 {
        return Err(GeoBaseError::InvalidInput(format!(
            "GeoBase artifact {} has invalid fingerprint",
            metadata.file
        )));
    }
    let path = Path::new(&metadata.file);
    let components: Vec<_> = path.components().collect();
    let valid = components.len() == 3
        && components
            .iter()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        && components[0].as_os_str() == id
        && components[1].as_os_str().to_str().is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        })
        && components[2].as_os_str() == expected_file;
    if !valid {
        return Err(GeoBaseError::InvalidInput(format!(
            "unsafe list path in manifest: {}",
            metadata.file
        )));
    }
    Ok(path.to_path_buf())
}

fn validate_manifest(manifest: &GeoBaseManifest) -> Result<()> {
    if manifest.version != MANIFEST_VERSION {
        return Err(GeoBaseError::InvalidInput(format!(
            "unsupported GeoBase manifest version {}",
            manifest.version
        )));
    }
    if manifest.applied_generation > manifest.generation {
        return Err(GeoBaseError::InvalidInput(
            "applied GeoBase generation cannot exceed current generation".to_owned(),
        ));
    }
    validate_records(&manifest.bases)?;
    validate_records(&manifest.applied_bases)?;
    Ok(())
}

fn validate_records(records: &[GeoBaseRecord]) -> Result<()> {
    if records.len() > MAX_BASES {
        return Err(GeoBaseError::LimitExceeded(format!(
            "GeoBase manifest cannot contain more than {MAX_BASES} bases"
        )));
    }
    let mut ids = BTreeSet::new();
    for record in records {
        validate_id(&record.id)?;
        validate_record_paths(record)?;
        if !ids.insert(&record.id) {
            return Err(GeoBaseError::InvalidInput(format!(
                "duplicate GeoBase id in manifest: {}",
                record.id
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum InputKind {
    ExactDomain,
    SuffixDomain,
    Network,
    Auto,
}

fn split_mihomo_line(line: &str) -> (InputKind, &str) {
    let Some((prefix, rest)) = line.split_once(',') else {
        return (InputKind::Auto, line);
    };
    let value = rest.split(',').next().unwrap_or_default().trim();
    match prefix.trim().to_ascii_uppercase().as_str() {
        "DOMAIN" => (InputKind::ExactDomain, value),
        "DOMAIN-SUFFIX" => (InputKind::SuffixDomain, value),
        "IP-CIDR" | "IP-CIDR6" => (InputKind::Network, value),
        _ => (InputKind::Auto, line),
    }
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(value, _)| value)
}

fn parse_domain(value: &str, line: usize) -> Result<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let context = if line == 0 {
        String::new()
    } else {
        format!(" on line {line}")
    };
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || domain.parse::<IpAddr>().is_ok()
    {
        return Err(GeoBaseError::InvalidInput(format!(
            "invalid ASCII domain{context}: {value:?}"
        )));
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || (label.starts_with("xn--") && label.len() <= 4)
        })
        || labels
            .last()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(GeoBaseError::InvalidInput(format!(
            "invalid ASCII/punycode domain{context}: {value:?}"
        )));
    }
    Ok(domain)
}

fn validate_public_network(value: &str, line: usize) -> Result<String> {
    let context = if line == 0 {
        String::new()
    } else {
        format!(" on line {line}")
    };
    let value = value.trim();
    let (ip_text, prefix_text) = value
        .split_once('/')
        .map_or((value, None), |(ip, prefix)| (ip, Some(prefix)));
    let ip: IpAddr = ip_text
        .parse()
        .map_err(|_| GeoBaseError::InvalidInput(format!("invalid IP/CIDR{context}: {value:?}")))?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_text {
        Some(text) => text.parse::<u8>().map_err(|_| {
            GeoBaseError::InvalidInput(format!("invalid CIDR prefix{context}: {value:?}"))
        })?,
        None => bits,
    };
    if prefix > bits || (ip.is_ipv4() && prefix < 8) || (ip.is_ipv6() && prefix < 16) {
        return Err(GeoBaseError::InvalidInput(format!(
            "broad or invalid CIDR{context}: {value:?}"
        )));
    }
    let (network, last) = network_bounds(ip, prefix);
    if network != ip {
        return Err(GeoBaseError::InvalidInput(format!(
            "CIDR has host bits set{context}: {value:?}"
        )));
    }
    if range_is_dangerous(network, last) {
        return Err(GeoBaseError::InvalidInput(format!(
            "non-public IP/CIDR is not allowed for routing imports{context}: {value:?}"
        )));
    }
    Ok(if prefix_text.is_some() {
        format!("{network}/{prefix}")
    } else {
        network.to_string()
    })
}

fn network_bounds(ip: IpAddr, prefix: u8) -> (IpAddr, IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            let value = u32::from(ip);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (
                IpAddr::V4(Ipv4Addr::from(value & mask)),
                IpAddr::V4(Ipv4Addr::from(value | !mask)),
            )
        }
        IpAddr::V6(ip) => {
            let value = u128::from(ip);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (
                IpAddr::V6(Ipv6Addr::from(value & mask)),
                IpAddr::V6(Ipv6Addr::from(value | !mask)),
            )
        }
    }
}

fn range_is_dangerous(first: IpAddr, last: IpAddr) -> bool {
    match (first, last) {
        (IpAddr::V4(first), IpAddr::V4(last)) => {
            const BLOCKED: [(u32, u8); 11] = [
                (0x0000_0000, 8),  // unspecified/current network
                (0x0a00_0000, 8),  // private
                (0x6440_0000, 10), // shared address space
                (0x7f00_0000, 8),  // loopback
                (0xa9fe_0000, 16), // link-local
                (0xac10_0000, 12), // private
                (0xc000_0000, 24), // IETF protocol assignments
                (0xc000_0200, 24), // documentation
                (0xc0a8_0000, 16), // private
                (0xe000_0000, 4),  // multicast
                (0xf000_0000, 4),  // reserved/broadcast
            ];
            overlaps_any(u128::from(u32::from(first)), u128::from(u32::from(last)), &BLOCKED)
                || overlaps_v4(first, last, 0xc612_0000, 15) // benchmark tests
                || overlaps_v4(first, last, 0xc633_6400, 24) // documentation
                || overlaps_v4(first, last, 0xcb00_7100, 24) // documentation
        }
        (IpAddr::V6(first), IpAddr::V6(last)) => {
            let first = u128::from(first);
            let last = u128::from(last);
            overlaps(first, last, 0, 128, 128) // unspecified
                || overlaps(first, last, 1, 128, 128) // loopback
                || overlaps(
                    first,
                    last,
                    0xfc00_0000_0000_0000_0000_0000_0000_0000,
                    7,
                    128,
                )
                || overlaps(
                    first,
                    last,
                    0xfe80_0000_0000_0000_0000_0000_0000_0000,
                    10,
                    128,
                )
                || overlaps(
                    first,
                    last,
                    0xff00_0000_0000_0000_0000_0000_0000_0000,
                    8,
                    128,
                )
                || overlaps(
                    first,
                    last,
                    0x2001_0db8_0000_0000_0000_0000_0000_0000,
                    32,
                    128,
                )
        }
        _ => true,
    }
}

fn overlaps_any(first: u128, last: u128, blocks: &[(u32, u8)]) -> bool {
    blocks
        .iter()
        .any(|&(base, prefix)| overlaps(first, last, u128::from(base), prefix, 32))
}

fn overlaps_v4(first: Ipv4Addr, last: Ipv4Addr, base: u32, prefix: u8) -> bool {
    overlaps(
        u128::from(u32::from(first)),
        u128::from(u32::from(last)),
        u128::from(base),
        prefix,
        32,
    )
}

fn overlaps(first: u128, last: u128, base: u128, prefix: u8, bits: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX >> (128 - bits) << (bits - prefix)
    };
    let block_first = base & mask;
    let block_last = block_first | (!mask & (u128::MAX >> (128 - bits)));
    first <= block_last && last >= block_first
}

fn difference(left: &[String], right: &[String]) -> Vec<String> {
    let right: BTreeSet<&str> = right.iter().map(String::as_str).collect();
    left.iter()
        .filter(|value| !right.contains(value.as_str()))
        .cloned()
        .collect()
}

fn domain_difference(left: &[ParsedDomain], right: &[ParsedDomain]) -> Vec<String> {
    let right: BTreeSet<&ParsedDomain> = right.iter().collect();
    left.iter()
        .filter(|value| !right.contains(value))
        .map(ParsedDomain::provider_line)
        .collect()
}

fn retained_source_bytes(root: &Path) -> Result<u64> {
    if !root.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for base in fs::read_dir(root)? {
        let base = base?;
        if !base.file_type()?.is_dir() {
            continue;
        }
        for generation in fs::read_dir(base.path())? {
            let generation = generation?;
            if !generation.file_type()?.is_dir() {
                continue;
            }
            match fs::metadata(generation.path().join(SOURCE_FILE)) {
                Ok(metadata) => {
                    total = total.checked_add(metadata.len()).ok_or_else(|| {
                        GeoBaseError::LimitExceeded(
                            "retained GeoBase source byte count overflowed".to_owned(),
                        )
                    })?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(total)
}

fn next_generation(generation: u64) -> Result<u64> {
    generation.checked_add(1).ok_or_else(|| {
        GeoBaseError::LimitExceeded("GeoBase manifest generation overflowed".to_owned())
    })
}

fn sync_dir(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn fingerprint_bytes(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            GeoBaseError::InvalidInput(format!("system clock before Unix epoch: {error}"))
        })
}

fn unix_now_nanos() -> Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| {
            GeoBaseError::InvalidInput(format!("system clock before Unix epoch: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    fn request(id: &str) -> GeoBaseUpsertRequest {
        GeoBaseUpsertRequest {
            id: id.to_owned(),
            name: "Regional routes".to_owned(),
            source: GeoBaseSource {
                kind: GeoBaseSourceKind::Upload,
                value: "routes.txt".to_owned(),
            },
            enabled: true,
        }
    }

    #[test]
    fn artifact_validation_and_fingerprint_detect_corruption() {
        let original = b"example.com\n+.suffix.example\n";
        let tampered = b"example.net\n+.suffix.example\n";
        assert_eq!(
            validate_artifact(original, GeoBaseArtifactKind::Domain).expect("valid artifact"),
            2
        );
        assert_ne!(
            artifact_fingerprint(original),
            artifact_fingerprint(tampered)
        );
        assert!(validate_artifact(b"not a domain!\n", GeoBaseArtifactKind::Domain).is_err());
        assert!(validate_artifact(b"127.0.0.0/8\n", GeoBaseArtifactKind::Ipcidr).is_err());
    }

    fn empty_generation() -> GeoBaseGenerationInput {
        GeoBaseGenerationInput {
            classifications: Vec::new(),
            static_entries: Vec::new(),
        }
    }

    fn artifact_dir(root: &Path, record: &GeoBaseRecord) -> PathBuf {
        root.join(
            Path::new(&record.lists.direct.file)
                .parent()
                .expect("generation path"),
        )
    }

    #[test]
    fn parser_accepts_plain_and_mihomo_lines_and_deduplicates() {
        let parsed = parse_source(
            b"# comment\nExample.COM.\nDOMAIN,example.com\nDOMAIN-SUFFIX,xn--e1afmkfd.xn--p1ai,no-resolve\nIP-CIDR,8.8.8.0/24\n1.1.1.1 # dns\n",
        )
        .expect("source should parse");
        assert_eq!(parsed.domains, vec!["example.com", "xn--e1afmkfd.xn--p1ai"]);
        assert_eq!(
            parsed.domain_entries,
            vec![
                ParsedDomain::Exact("example.com".to_owned()),
                ParsedDomain::Suffix("xn--e1afmkfd.xn--p1ai".to_owned()),
            ]
        );
        assert_eq!(parsed.networks, vec!["1.1.1.1", "8.8.8.0/24"]);
    }

    #[test]
    fn suffix_semantics_survive_analysis_provider_output_and_diff() {
        let parsed =
            parse_source(b"plain.example\nDOMAIN,exact.example\nDOMAIN-SUFFIX,suffix.example\n")
                .expect("source");
        let mut probes = Vec::new();
        let generation = GeoBaseGenerationInput {
            classifications: classify_domains(&parsed, |domain| {
                probes.push(domain.to_owned());
                Classification::Direct
            }),
            static_entries: Vec::new(),
        };
        assert_eq!(
            probes,
            vec!["exact.example", "plain.example", "suffix.example"]
        );
        let lists = validate_generation(&parsed, generation).expect("valid generation");
        assert_eq!(
            lists.direct,
            vec!["exact.example", "plain.example", "+.suffix.example"]
        );

        let exact = parse_source(b"DOMAIN,same.example\n").expect("exact");
        let suffix = parse_source(b"DOMAIN-SUFFIX,same.example\n").expect("suffix");
        assert_eq!(
            diff_sources(&exact, &suffix),
            SourceDiff {
                added_domains: vec!["+.same.example".to_owned()],
                removed_domains: vec!["same.example".to_owned()],
                ..SourceDiff::default()
            }
        );
    }

    #[test]
    fn parser_rejects_unicode_wildcards_bad_labels_and_limits() {
        for source in [
            "пример.рф",
            "*.example.com",
            "-bad.example",
            "singlelabel",
            "xn--.example",
        ] {
            assert!(
                parse_source(source.as_bytes()).is_err(),
                "accepted {source}"
            );
        }
        let long_line = format!("{}\n", "a".repeat(MAX_LINE_BYTES + 1));
        assert!(matches!(
            parse_source(long_line.as_bytes()),
            Err(GeoBaseError::LimitExceeded(_))
        ));
    }

    #[test]
    fn dangerous_and_broad_networks_are_rejected() {
        for network in [
            "0.0.0.0",
            "10.0.0.0/8",
            "127.0.0.1",
            "169.254.1.0/24",
            "192.168.0.0/16",
            "224.0.0.0/4",
            "8.0.0.0/7",
            "8.8.8.1/24",
            "::",
            "::1",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
            "2001:db8::/32",
        ] {
            assert!(
                validate_public_network(network, 1).is_err(),
                "accepted {network}"
            );
        }
        assert_eq!(
            validate_public_network("8.8.8.0/24", 1).expect("public CIDR"),
            "8.8.8.0/24"
        );
        assert!(validate_public_network("2606:4700:4700::/48", 1).is_ok());
    }

    #[test]
    fn classification_only_receives_domains_and_defaults_to_unresolved() {
        let parsed = parse_source(b"a.example\nb.example\nIP-CIDR,8.8.8.0/24\n")
            .expect("source should parse");
        let mut seen = Vec::new();
        let classified = classify_domains(&parsed, |domain| {
            seen.push(domain.to_owned());
            if domain == "a.example" {
                Classification::Direct
            } else {
                Classification::Active
            }
        });
        assert_eq!(seen, vec!["a.example", "b.example"]);
        assert_eq!(classified[0].classification, Classification::Direct);
        assert_eq!(classified[1].classification, Classification::Active);
    }

    #[test]
    fn source_diff_is_sorted_and_separates_networks() {
        let old = parse_source(b"a.example\nb.example\n8.8.8.8\n").expect("old");
        let new = parse_source(b"b.example\nc.example\n1.1.1.1\n").expect("new");
        assert_eq!(
            diff_sources(&old, &new),
            SourceDiff {
                added_domains: vec!["c.example".to_owned()],
                removed_domains: vec!["a.example".to_owned()],
                added_networks: vec!["1.1.1.1".to_owned()],
                removed_networks: vec!["8.8.8.8".to_owned()],
            }
        );
    }

    #[test]
    fn atomic_store_roundtrip_update_and_delete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = GeoBaseStore::new(temp.path());
        let source = b"a.example\nb.example\n8.8.8.0/24\n";
        let created = store
            .create(
                request("regional-1"),
                source,
                GeoBaseGenerationInput {
                    classifications: vec![DomainClassification {
                        domain: "a.example".to_owned(),
                        classification: Classification::Direct,
                    }],
                    static_entries: vec![StaticRouteEntry {
                        network: "8.8.8.0/24".to_owned(),
                        target: Classification::Active,
                    }],
                },
            )
            .expect("create");
        assert_eq!(created.revision, 1);
        assert_eq!(created.counts.unresolved, 1);
        assert_eq!(store.load_source("regional-1").expect("source"), source);
        let lists = store.load_lists("regional-1").expect("lists");
        assert_eq!(lists.classifications.len(), 2);
        assert_eq!(lists.static_entries.len(), 1);
        assert_eq!(lists.static_entries[0].target, Classification::Active);
        let created_generation = store.load_manifest().expect("manifest").generation;
        store
            .mark_applied(created_generation)
            .expect("apply created generation");

        let updated = store
            .update(
                request("regional-1"),
                1,
                b"c.example\n",
                GeoBaseGenerationInput {
                    classifications: classify_domains(
                        &parse_source(b"c.example\n").expect("new source"),
                        |_| Classification::Active,
                    ),
                    static_entries: Vec::new(),
                },
            )
            .expect("update");
        assert_eq!(updated.revision, 2);
        assert!(artifact_dir(temp.path(), &created).is_dir());
        assert!(artifact_dir(temp.path(), &updated).is_dir());
        assert_eq!(
            store.load_manifest().expect("manifest").bases,
            vec![updated.clone()]
        );
        store.delete("regional-1").expect("delete");
        assert!(
            store
                .load_manifest()
                .expect("empty manifest")
                .bases
                .is_empty()
        );
        assert!(artifact_dir(temp.path(), &created).is_dir());
        assert!(artifact_dir(temp.path(), &updated).is_dir());
        assert_eq!(store.garbage_collect().expect("collect pending"), 1);
        assert!(artifact_dir(temp.path(), &created).is_dir());
        assert!(!artifact_dir(temp.path(), &updated).is_dir());
        let generation = store.load_manifest().expect("deleted manifest").generation;
        store.mark_applied(generation).expect("mark applied");
        assert_eq!(store.garbage_collect().expect("collect"), 1);
        assert!(!temp.path().join("regional-1").exists());
    }

    #[test]
    fn failed_update_preserves_previous_generation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = GeoBaseStore::new(temp.path());
        let created = store
            .create(
                request("safe"),
                b"a.example\n",
                GeoBaseGenerationInput {
                    classifications: Vec::new(),
                    static_entries: Vec::new(),
                },
            )
            .expect("create");
        let result = store.update(
            request("safe"),
            1,
            b"b.example\n",
            GeoBaseGenerationInput {
                classifications: Vec::new(),
                static_entries: vec![StaticRouteEntry {
                    network: "192.168.0.0/16".to_owned(),
                    target: Classification::Direct,
                }],
            },
        );
        assert!(result.is_err());
        assert_eq!(
            store.load_source("safe").expect("old source"),
            b"a.example\n"
        );
        assert_eq!(
            store.load_manifest().expect("manifest").bases[0].revision,
            1
        );
        assert!(
            artifact_dir(temp.path(), &created)
                .join(SOURCE_FILE)
                .is_file()
        );
        assert_eq!(
            fs::read_dir(temp.path().join("safe"))
                .expect("base dir")
                .count(),
            1
        );
    }

    #[test]
    fn cloned_stores_serialize_concurrent_create_and_toggle_transactions() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = GeoBaseStore::new(temp.path());
        let workers = 12;
        let barrier = Arc::new(Barrier::new(workers));
        let handles: Vec<_> = (0..workers)
            .map(|index| {
                let store = store.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    store.create(
                        request(&format!("base-{index}")),
                        format!("d{index}.example\n").as_bytes(),
                        empty_generation(),
                    )
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("worker").expect("create");
        }
        assert_eq!(
            store.load_manifest().expect("manifest").bases.len(),
            workers
        );

        let barrier = Arc::new(Barrier::new(workers));
        let handles: Vec<_> = (0..workers)
            .map(|index| {
                let store = store.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    store.set_enabled(&format!("base-{index}"), false, Some(1))
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("worker").expect("toggle");
        }
        let manifest = store.load_manifest().expect("manifest");
        assert!(manifest.bases.iter().all(|record| !record.enabled));
        assert_eq!(manifest.generation, (workers * 2) as u64);
    }

    #[test]
    fn generation_apply_is_cas_and_old_manifests_default_safely() {
        let old: GeoBaseManifest =
            serde_json::from_str(r#"{"version":1,"updated_at":123,"bases":[]}"#)
                .expect("v1 manifest");
        assert_eq!(old.generation, 0);
        assert_eq!(old.applied_generation, 0);
        assert!(old.applied_bases.is_empty());
        assert!(!old.requires_apply());

        let temp = tempfile::tempdir().expect("temp dir");
        let store = GeoBaseStore::new(temp.path());
        store
            .create(request("apply-cas"), b"a.example\n", empty_generation())
            .expect("create");
        let generation = store.load_manifest().expect("manifest").generation;
        assert!(store.load_manifest().expect("manifest").requires_apply());
        assert!(matches!(
            store.mark_applied(generation + 1),
            Err(GeoBaseError::Conflict(_))
        ));
        let applied = store.mark_applied(generation).expect("apply");
        assert_eq!(applied.generation, generation);
        assert_eq!(applied.applied_generation, generation);
        assert!(!applied.requires_apply());
    }

    #[test]
    fn orphan_generation_does_not_wedge_update_and_is_collectable() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = GeoBaseStore::new(temp.path());
        let created = store
            .create(request("orphan-safe"), b"a.example\n", empty_generation())
            .expect("create");
        let orphan = temp.path().join("orphan-safe/g2-r2-crash-orphan");
        fs::create_dir_all(&orphan).expect("orphan dir");
        fs::write(orphan.join(SOURCE_FILE), b"orphan").expect("orphan source");
        let updated = store
            .update(
                request("orphan-safe"),
                created.revision,
                b"b.example\n",
                empty_generation(),
            )
            .expect("update after orphan");
        assert_ne!(artifact_dir(temp.path(), &updated), orphan);
        let generation = store.load_manifest().expect("manifest").generation;
        store.mark_applied(generation).expect("apply");
        assert_eq!(store.garbage_collect().expect("collect"), 2);
        assert!(!orphan.exists());
        assert!(artifact_dir(temp.path(), &updated).exists());
    }

    #[test]
    fn delete_then_recreate_uses_new_artifact_and_retains_deleted_one_until_gc() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = GeoBaseStore::new(temp.path());
        let old = store
            .create(request("recreate"), b"old.example\n", empty_generation())
            .expect("create");
        let old_dir = artifact_dir(temp.path(), &old);
        store.delete("recreate").expect("delete");
        let new = store
            .create(request("recreate"), b"new.example\n", empty_generation())
            .expect("recreate");
        let new_dir = artifact_dir(temp.path(), &new);
        assert_ne!(old_dir, new_dir);
        assert!(old_dir.exists());
        assert!(new_dir.exists());
        let generation = store.load_manifest().expect("manifest").generation;
        store.mark_applied(generation).expect("apply");
        assert_eq!(store.garbage_collect().expect("collect"), 1);
        assert!(!old_dir.exists());
        assert!(new_dir.exists());
    }

    #[test]
    fn aggregate_and_domain_quotas_are_enforced() {
        let domains = (0..=MAX_DOMAINS_PER_BASE)
            .map(|index| format!("d{index}.example\n"))
            .collect::<String>();
        assert!(matches!(
            parse_source(domains.as_bytes()),
            Err(GeoBaseError::LimitExceeded(_))
        ));

        let temp = tempfile::tempdir().expect("temp dir");
        let retained = temp.path().join("old/orphan/source");
        fs::create_dir_all(retained.parent().expect("parent")).expect("retained dir");
        fs::File::create(&retained)
            .expect("retained source")
            .set_len(MAX_TOTAL_SOURCE_BYTES)
            .expect("size retained source");
        let store = GeoBaseStore::new(temp.path());
        assert!(matches!(
            store.create(request("over-quota"), b"a.example\n", empty_generation()),
            Err(GeoBaseError::LimitExceeded(_))
        ));
        assert!(store.load_manifest().expect("manifest").bases.is_empty());

        let temp = tempfile::tempdir().expect("base limit dir");
        let store = GeoBaseStore::new(temp.path());
        for index in 0..MAX_BASES {
            store
                .create(
                    request(&format!("limit-{index}")),
                    format!("d{index}.example\n").as_bytes(),
                    empty_generation(),
                )
                .expect("within base count quota");
        }
        assert!(matches!(
            store.create(
                request("one-too-many"),
                b"extra.example\n",
                empty_generation()
            ),
            Err(GeoBaseError::LimitExceeded(_))
        ));
    }

    #[test]
    fn ids_and_duplicate_classification_are_strict() {
        assert!(validate_id("valid-id-1").is_ok());
        for id in ["", "../bad", "Bad", "bad_thing", "-bad", "bad-"] {
            assert!(validate_id(id).is_err(), "accepted {id}");
        }
        let parsed = parse_source(b"a.example\n").expect("source");
        let duplicate = GeoBaseGenerationInput {
            classifications: vec![
                DomainClassification {
                    domain: "a.example".to_owned(),
                    classification: Classification::Direct,
                },
                DomainClassification {
                    domain: "A.EXAMPLE".to_owned(),
                    classification: Classification::Active,
                },
            ],
            static_entries: Vec::new(),
        };
        assert!(validate_generation(&parsed, duplicate).is_err());
        let absent_static = GeoBaseGenerationInput {
            classifications: Vec::new(),
            static_entries: vec![StaticRouteEntry {
                network: "8.8.8.0/24".to_owned(),
                target: Classification::Direct,
            }],
        };
        assert!(validate_generation(&parsed, absent_static).is_err());
        assert_eq!(stable_id("same seed"), stable_id("same seed"));
    }
}
