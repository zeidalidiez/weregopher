//! Bounded, integrity-checked reading and deterministic rewriting of Electron ASAR archives.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, de::MapAccess};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const ASAR_MAGIC: u32 = 4;
const INTEGRITY_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Resource ceilings applied while parsing and rebuilding an ASAR archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit max prefixes make every security ceiling unambiguous"
)]
pub struct AsarLimits {
    max_archive_bytes: usize,
    max_header_bytes: usize,
    max_entries: usize,
    max_file_bytes: usize,
    max_total_file_bytes: usize,
    max_path_bytes: usize,
    max_depth: usize,
}

impl AsarLimits {
    /// Returns the bounded limits used by the initial desktop-application profile.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            max_archive_bytes: 1024 * 1024 * 1024,
            max_header_bytes: 16 * 1024 * 1024,
            max_entries: 100_000,
            max_file_bytes: 512 * 1024 * 1024,
            max_total_file_bytes: 1024 * 1024 * 1024,
            max_path_bytes: 4_096,
            max_depth: 128,
        }
    }

    /// Returns the maximum complete archive size accepted before parsing.
    #[must_use]
    pub const fn max_archive_bytes(&self) -> usize {
        self.max_archive_bytes
    }
}

/// A fully validated packed-file ASAR archive retained in memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsarArchive {
    files: BTreeMap<String, PackedFile>,
    limits: AsarLimits,
}

impl AsarArchive {
    /// Parses an archive, validates its complete body layout and every SHA-256 integrity record.
    ///
    /// The initial implementation accepts packed regular files only. Archives containing symbolic
    /// links, unpacked members, or empty directories fail closed rather than losing their semantics
    /// during rewriting.
    ///
    /// # Errors
    ///
    /// Returns a closed [`AsarError`] when framing, paths, limits, layout, or integrity validation
    /// fails.
    pub fn parse(bytes: &[u8], limits: AsarLimits) -> Result<Self, AsarError> {
        if bytes.len() > limits.max_archive_bytes {
            return Err(AsarError::ArchiveTooLarge);
        }
        let header = parse_header(bytes, limits)?;
        let mut state = CollectionState::new(bytes, header.data_start, limits);
        collect_entries(&header.root, "", 0, &mut state)?;
        state.finish()
    }

    /// Returns the validated bytes for one canonical archive-relative path.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        canonical_archive_path(path, self.limits)
            .ok()
            .and_then(|canonical| self.files.get(&canonical))
            .map(|file| file.bytes.as_slice())
    }

    /// Returns the canonical file paths in bytewise lexical order.
    pub fn file_paths(&self) -> impl ExactSizeIterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// Replaces one existing packed member after applying the archive's byte ceilings.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical or absent path, an oversized replacement, or an
    /// aggregate-size overflow.
    pub fn replace_file(&mut self, path: &str, replacement: Vec<u8>) -> Result<(), AsarError> {
        let canonical = canonical_archive_path(path, self.limits)?;
        if replacement.len() > self.limits.max_file_bytes {
            return Err(AsarError::FileTooLarge);
        }
        let previous_size = self
            .files
            .get(&canonical)
            .ok_or(AsarError::MemberNotFound)?
            .bytes
            .len();
        let current_total = self
            .files
            .values()
            .try_fold(0_usize, |total, file| total.checked_add(file.bytes.len()))
            .ok_or(AsarError::AggregateTooLarge)?;
        let replacement_total = current_total
            .checked_sub(previous_size)
            .and_then(|total| total.checked_add(replacement.len()))
            .ok_or(AsarError::AggregateTooLarge)?;
        if replacement_total > self.limits.max_total_file_bytes {
            return Err(AsarError::AggregateTooLarge);
        }
        let file = self
            .files
            .get_mut(&canonical)
            .ok_or(AsarError::MemberNotFound)?;
        file.bytes = replacement;
        Ok(())
    }

    /// Emits a deterministic archive with canonical paths, offsets, and integrity records.
    ///
    /// # Errors
    ///
    /// Returns an error if output layout construction, size arithmetic, or JSON serialization
    /// fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AsarError> {
        let mut root = BTreeMap::new();
        let mut body = Vec::new();
        for (path, file) in &self.files {
            let offset = body.len();
            body.extend_from_slice(&file.bytes);
            let entry = OutputEntry::File(OutputFile {
                size: u64::try_from(file.bytes.len()).map_err(|_| AsarError::FileTooLarge)?,
                offset: offset.to_string(),
                executable: file.executable,
                integrity: OutputIntegrity::for_bytes(&file.bytes),
            });
            insert_output_entry(&mut root, path, entry)?;
        }
        if body.len() > self.limits.max_total_file_bytes {
            return Err(AsarError::AggregateTooLarge);
        }

        let header = OutputEntry::Directory(OutputDirectory { files: root });
        let mut json = serde_json::to_vec(&header).map_err(AsarError::SerializeHeader)?;
        if json.len() > self.limits.max_header_bytes {
            return Err(AsarError::HeaderTooLarge);
        }
        let json_size = u32::try_from(json.len()).map_err(|_| AsarError::HeaderTooLarge)?;
        while json.len() % 4 != 0 {
            json.push(0);
        }
        let padded_size = u32::try_from(json.len()).map_err(|_| AsarError::HeaderTooLarge)?;
        let outer_size = padded_size
            .checked_add(8)
            .ok_or(AsarError::HeaderTooLarge)?;
        let inner_size = padded_size
            .checked_add(4)
            .ok_or(AsarError::HeaderTooLarge)?;
        let output_size = 16_usize
            .checked_add(json.len())
            .and_then(|size| size.checked_add(body.len()))
            .ok_or(AsarError::ArchiveTooLarge)?;
        if output_size > self.limits.max_archive_bytes {
            return Err(AsarError::ArchiveTooLarge);
        }

        let mut output = Vec::with_capacity(output_size);
        output.extend_from_slice(&ASAR_MAGIC.to_le_bytes());
        output.extend_from_slice(&outer_size.to_le_bytes());
        output.extend_from_slice(&inner_size.to_le_bytes());
        output.extend_from_slice(&json_size.to_le_bytes());
        output.extend_from_slice(&json);
        output.extend_from_slice(&body);
        Ok(output)
    }
}

/// Fail-closed ASAR parsing and rewriting errors.
#[derive(Debug, Error)]
pub enum AsarError {
    /// The complete archive exceeds the configured ceiling.
    #[error("ASAR archive exceeds the configured byte limit")]
    ArchiveTooLarge,
    /// The serialized header exceeds the configured ceiling.
    #[error("ASAR header exceeds the configured byte limit")]
    HeaderTooLarge,
    /// The Pickle framing or root entry is malformed.
    #[error("ASAR header framing is invalid")]
    InvalidHeader,
    /// The JSON header cannot be decoded into the supported closed shape.
    #[error("ASAR header JSON is invalid: {0}")]
    InvalidHeaderJson(#[source] serde_json::Error),
    /// A member name or path is noncanonical or ambiguous on Windows.
    #[error("ASAR member name is invalid")]
    InvalidMemberName,
    /// The archive contains too many entries.
    #[error("ASAR archive exceeds the configured entry limit")]
    TooManyEntries,
    /// The archive tree is nested too deeply.
    #[error("ASAR archive exceeds the configured depth limit")]
    TooDeep,
    /// Canonical member paths exceed the aggregate path budget.
    #[error("ASAR member paths exceed the configured byte limit")]
    PathBudgetExceeded,
    /// The initial rewriter does not preserve this entry shape.
    #[error("ASAR archive contains an unsupported entry shape")]
    UnsupportedEntry,
    /// Packed member offsets or sizes are malformed, overlapping, sparse, or out of bounds.
    #[error("ASAR packed-file layout is invalid")]
    InvalidLayout,
    /// One member exceeds the configured byte ceiling.
    #[error("ASAR member exceeds the configured byte limit")]
    FileTooLarge,
    /// The sum of packed member bytes exceeds the configured ceiling.
    #[error("ASAR packed members exceed the configured aggregate byte limit")]
    AggregateTooLarge,
    /// A packed member does not match its declared integrity data.
    #[error("ASAR member integrity verification failed")]
    IntegrityMismatch,
    /// The requested canonical member does not exist.
    #[error("ASAR member was not found")]
    MemberNotFound,
    /// Header serialization failed.
    #[error("failed to serialize ASAR header: {0}")]
    SerializeHeader(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackedFile {
    bytes: Vec<u8>,
    executable: bool,
}

struct ParsedHeader {
    root: InputDirectory,
    data_start: usize,
}

fn parse_header(bytes: &[u8], limits: AsarLimits) -> Result<ParsedHeader, AsarError> {
    if bytes.len() < 16 {
        return Err(AsarError::InvalidHeader);
    }
    let magic = read_u32(bytes, 0)?;
    let outer_size = read_u32(bytes, 4)?;
    let inner_size = read_u32(bytes, 8)?;
    let json_size = read_u32(bytes, 12)?;
    if magic != ASAR_MAGIC || outer_size != inner_size.saturating_add(4) {
        return Err(AsarError::InvalidHeader);
    }
    let padded_size = inner_size.checked_sub(4).ok_or(AsarError::InvalidHeader)?;
    if padded_size % 4 != 0 || json_size > padded_size {
        return Err(AsarError::InvalidHeader);
    }
    let data_start = 16_usize
        .checked_add(usize::try_from(padded_size).map_err(|_| AsarError::InvalidHeader)?)
        .ok_or(AsarError::InvalidHeader)?;
    if data_start > bytes.len() || data_start > limits.max_header_bytes {
        return Err(AsarError::HeaderTooLarge);
    }
    let json_end = 16_usize
        .checked_add(usize::try_from(json_size).map_err(|_| AsarError::InvalidHeader)?)
        .ok_or(AsarError::InvalidHeader)?;
    let json = bytes.get(16..json_end).ok_or(AsarError::InvalidHeader)?;
    let padding = bytes
        .get(json_end..data_start)
        .ok_or(AsarError::InvalidHeader)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(AsarError::InvalidHeader);
    }
    let root_entry: InputEntry =
        serde_json::from_slice(json).map_err(AsarError::InvalidHeaderJson)?;
    let InputEntry::Directory(root) = root_entry else {
        return Err(AsarError::InvalidHeader);
    };
    Ok(ParsedHeader { root, data_start })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AsarError> {
    let end = offset.checked_add(4).ok_or(AsarError::InvalidHeader)?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(AsarError::InvalidHeader)?
        .try_into()
        .map_err(|_| AsarError::InvalidHeader)?;
    Ok(u32::from_le_bytes(raw))
}

struct CollectionState<'a> {
    archive: &'a [u8],
    data_start: usize,
    limits: AsarLimits,
    files: BTreeMap<String, PendingFile>,
    case_keys: BTreeSet<String>,
    entries: usize,
    path_bytes: usize,
    total_file_bytes: usize,
}

impl<'a> CollectionState<'a> {
    fn new(archive: &'a [u8], data_start: usize, limits: AsarLimits) -> Self {
        Self {
            archive,
            data_start,
            limits,
            files: BTreeMap::new(),
            case_keys: BTreeSet::new(),
            entries: 0,
            path_bytes: 0,
            total_file_bytes: 0,
        }
    }

    fn register_entry(&mut self, path: &str) -> Result<(), AsarError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(AsarError::TooManyEntries)?;
        if self.entries > self.limits.max_entries {
            return Err(AsarError::TooManyEntries);
        }
        self.path_bytes = self
            .path_bytes
            .checked_add(path.len())
            .ok_or(AsarError::PathBudgetExceeded)?;
        let aggregate_path_limit = self
            .limits
            .max_entries
            .checked_mul(self.limits.max_path_bytes)
            .ok_or(AsarError::PathBudgetExceeded)?;
        if self.path_bytes > aggregate_path_limit {
            return Err(AsarError::PathBudgetExceeded);
        }
        let case_key = path.to_ascii_lowercase();
        if !self.case_keys.insert(case_key) {
            return Err(AsarError::InvalidMemberName);
        }
        Ok(())
    }

    fn finish(self) -> Result<AsarArchive, AsarError> {
        let body = self
            .archive
            .get(self.data_start..)
            .ok_or(AsarError::InvalidLayout)?;
        let mut by_offset: Vec<(&String, &PendingFile)> = self.files.iter().collect();
        by_offset.sort_by(|(left_path, left), (right_path, right)| {
            left.offset
                .cmp(&right.offset)
                .then_with(|| left_path.cmp(right_path))
        });
        let mut cursor = 0_usize;
        for (_, file) in &by_offset {
            if file.offset != cursor {
                return Err(AsarError::InvalidLayout);
            }
            cursor = cursor
                .checked_add(file.size)
                .ok_or(AsarError::InvalidLayout)?;
        }
        if cursor != body.len() {
            return Err(AsarError::InvalidLayout);
        }

        let mut files = BTreeMap::new();
        for (path, file) in self.files {
            let end = file
                .offset
                .checked_add(file.size)
                .ok_or(AsarError::InvalidLayout)?;
            let bytes = body.get(file.offset..end).ok_or(AsarError::InvalidLayout)?;
            verify_integrity(bytes, &file.integrity)?;
            files.insert(
                path,
                PackedFile {
                    bytes: bytes.to_vec(),
                    executable: file.executable,
                },
            );
        }
        Ok(AsarArchive {
            files,
            limits: self.limits,
        })
    }
}

#[derive(Debug)]
struct PendingFile {
    offset: usize,
    size: usize,
    executable: bool,
    integrity: InputIntegrity,
}

fn collect_entries(
    directory: &InputDirectory,
    parent: &str,
    depth: usize,
    state: &mut CollectionState<'_>,
) -> Result<(), AsarError> {
    if depth > state.limits.max_depth {
        return Err(AsarError::TooDeep);
    }
    if depth > 0 && directory.files.is_empty() {
        return Err(AsarError::UnsupportedEntry);
    }
    for (name, entry) in &directory.files {
        validate_member_name(name)?;
        let path = if parent.is_empty() {
            name.clone()
        } else {
            format!("{parent}/{name}")
        };
        if path.len() > state.limits.max_path_bytes {
            return Err(AsarError::InvalidMemberName);
        }
        state.register_entry(&path)?;
        match entry {
            InputEntry::Directory(child) => {
                collect_entries(child, &path, depth + 1, state)?;
            }
            InputEntry::File(file) => {
                if file.unpacked {
                    return Err(AsarError::UnsupportedEntry);
                }
                let offset = file
                    .offset
                    .as_deref()
                    .ok_or(AsarError::InvalidLayout)?
                    .parse::<usize>()
                    .map_err(|_| AsarError::InvalidLayout)?;
                let size = usize::try_from(file.size).map_err(|_| AsarError::FileTooLarge)?;
                if size > state.limits.max_file_bytes {
                    return Err(AsarError::FileTooLarge);
                }
                state.total_file_bytes = state
                    .total_file_bytes
                    .checked_add(size)
                    .ok_or(AsarError::AggregateTooLarge)?;
                if state.total_file_bytes > state.limits.max_total_file_bytes {
                    return Err(AsarError::AggregateTooLarge);
                }
                let integrity = file.integrity.clone().ok_or(AsarError::IntegrityMismatch)?;
                state.files.insert(
                    path,
                    PendingFile {
                        offset,
                        size,
                        executable: file.executable,
                        integrity,
                    },
                );
            }
            InputEntry::Link(link) => {
                if link.link.is_empty() {
                    return Err(AsarError::InvalidMemberName);
                }
                return Err(AsarError::UnsupportedEntry);
            }
        }
    }
    Ok(())
}

fn canonical_archive_path(path: &str, limits: AsarLimits) -> Result<String, AsarError> {
    if path.is_empty() || path.len() > limits.max_path_bytes || path.starts_with('/') {
        return Err(AsarError::InvalidMemberName);
    }
    let mut count = 0_usize;
    for component in path.split('/') {
        validate_member_name(component)?;
        count = count.checked_add(1).ok_or(AsarError::TooDeep)?;
        if count > limits.max_depth {
            return Err(AsarError::TooDeep);
        }
    }
    Ok(path.to_owned())
}

fn validate_member_name(name: &str) -> Result<(), AsarError> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
        || name.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(
                    character,
                    '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'
                )
        })
    {
        return Err(AsarError::InvalidMemberName);
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        stem.as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    ) {
        return Err(AsarError::InvalidMemberName);
    }
    Ok(())
}

fn verify_integrity(bytes: &[u8], integrity: &InputIntegrity) -> Result<(), AsarError> {
    if integrity.algorithm != "SHA256"
        || integrity.block_size != INTEGRITY_BLOCK_SIZE
        || integrity.hash != hex_digest(bytes)
    {
        return Err(AsarError::IntegrityMismatch);
    }
    let expected_blocks: Vec<String> = bytes.chunks(INTEGRITY_BLOCK_SIZE).map(hex_digest).collect();
    if integrity.blocks != expected_blocks {
        return Err(AsarError::IntegrityMismatch);
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn insert_output_entry(
    root: &mut BTreeMap<String, OutputEntry>,
    path: &str,
    entry: OutputEntry,
) -> Result<(), AsarError> {
    let components: Vec<&str> = path.split('/').collect();
    insert_output_components(root, &components, entry)
}

fn insert_output_components(
    current: &mut BTreeMap<String, OutputEntry>,
    components: &[&str],
    entry: OutputEntry,
) -> Result<(), AsarError> {
    let (component, remaining) = components
        .split_first()
        .ok_or(AsarError::InvalidMemberName)?;
    if remaining.is_empty() {
        if current.insert((*component).to_owned(), entry).is_some() {
            return Err(AsarError::InvalidLayout);
        }
        return Ok(());
    }
    let directory = current.entry((*component).to_owned()).or_insert_with(|| {
        OutputEntry::Directory(OutputDirectory {
            files: BTreeMap::new(),
        })
    });
    let OutputEntry::Directory(directory) = directory else {
        return Err(AsarError::InvalidLayout);
    };
    insert_output_components(&mut directory.files, remaining, entry)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InputEntry {
    Directory(InputDirectory),
    File(InputFile),
    Link(InputLink),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDirectory {
    #[serde(deserialize_with = "deserialize_unique_files")]
    files: BTreeMap<String, InputEntry>,
}

fn deserialize_unique_files<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, InputEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueFilesVisitor;

    impl<'de> serde::de::Visitor<'de> for UniqueFilesVisitor {
        type Value = BTreeMap<String, InputEntry>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an ASAR files object with unique member names")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut files = BTreeMap::new();
            while let Some((name, entry)) = access.next_entry::<String, InputEntry>()? {
                if files.insert(name, entry).is_some() {
                    return Err(serde::de::Error::custom("duplicate ASAR member name"));
                }
            }
            Ok(files)
        }
    }

    deserializer.deserialize_map(UniqueFilesVisitor)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputFile {
    size: u64,
    #[serde(default)]
    offset: Option<String>,
    #[serde(default)]
    executable: bool,
    #[serde(default)]
    unpacked: bool,
    #[serde(default)]
    integrity: Option<InputIntegrity>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InputIntegrity {
    algorithm: String,
    hash: String,
    block_size: usize,
    blocks: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputLink {
    link: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum OutputEntry {
    Directory(OutputDirectory),
    File(OutputFile),
}

#[derive(Serialize)]
struct OutputDirectory {
    files: BTreeMap<String, OutputEntry>,
}

#[derive(Serialize)]
struct OutputFile {
    size: u64,
    offset: String,
    #[serde(skip_serializing_if = "is_false")]
    executable: bool,
    integrity: OutputIntegrity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputIntegrity {
    algorithm: &'static str,
    hash: String,
    block_size: usize,
    blocks: Vec<String>,
}

impl OutputIntegrity {
    fn for_bytes(bytes: &[u8]) -> Self {
        Self {
            algorithm: "SHA256",
            hash: hex_digest(bytes),
            block_size: INTEGRITY_BLOCK_SIZE,
            blocks: bytes.chunks(INTEGRITY_BLOCK_SIZE).map(hex_digest).collect(),
        }
    }
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip predicates receive references"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}
