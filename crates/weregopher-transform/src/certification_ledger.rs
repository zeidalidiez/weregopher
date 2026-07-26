//! Bounded canonical hash-chained persistence for local certification attestations.

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use thiserror::Error;
use weregopher_domain::{
    CertificationControlPolicy, CertificationPolicyRevocationDigest,
    CertificationRunnerPolicyRevocationDigest, LocalCertificationLedgerContractError,
    LocalCertificationLedgerDocumentError, LocalCertificationLedgerEvent,
    LocalCertificationLedgerGenesis, LocalCertificationLedgerRecord,
    LocalCertificationLedgerRecordDigest, LocalCertificationRunAttestation,
    MAX_LOCAL_CERTIFICATION_LEDGER_BYTES, MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES,
    MAX_LOCAL_CERTIFICATION_LEDGER_RECORDS,
};

use crate::AttestedLocalCertificationPublication;

const RECORD_FILE_DIGITS: usize = 20;
const RECORD_FILE_SUFFIX: &str = ".json";

/// Durable append result and the new exact rollback anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCertificationLedgerAppendReceipt {
    sequence: u64,
    record_digest: LocalCertificationLedgerRecordDigest,
    record_count: usize,
    total_record_bytes: usize,
}

impl LocalCertificationLedgerAppendReceipt {
    /// Returns the one-based appended sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the new exact ledger-head identity.
    #[must_use]
    pub const fn record_digest(&self) -> LocalCertificationLedgerRecordDigest {
        self.record_digest
    }

    /// Returns the bounded record count after append.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Returns aggregate canonical record bytes after append.
    #[must_use]
    pub const fn total_record_bytes(&self) -> usize {
        self.total_record_bytes
    }
}

#[derive(Clone, Debug)]
struct LedgerProjection {
    policy: CertificationControlPolicy,
    runner_generation: u64,
    certification_generation: u64,
    runner_revoked: bool,
    certification_revoked: bool,
    freshness_challenges: BTreeSet<uuid::Uuid>,
}

impl LedgerProjection {
    fn from_genesis(genesis: &LocalCertificationLedgerGenesis) -> Self {
        let challenge = genesis.attestation().freshness().challenge();
        let mut freshness_challenges = BTreeSet::new();
        freshness_challenges.insert(challenge);
        Self {
            policy: genesis.policy().clone(),
            runner_generation: genesis.policy().runner().policy_generation(),
            certification_generation: genesis.policy().policy_generation(),
            runner_revoked: false,
            certification_revoked: false,
            freshness_challenges,
        }
    }

    fn apply(
        &mut self,
        event: &LocalCertificationLedgerEvent,
    ) -> Result<(), LocalCertificationLedgerError> {
        match event {
            LocalCertificationLedgerEvent::Genesis(_) => {
                Err(LocalCertificationLedgerError::UnexpectedGenesis)
            }
            LocalCertificationLedgerEvent::Publication(publication) => {
                self.apply_publication(publication.attestation())
            }
            LocalCertificationLedgerEvent::PolicyReplacement(replacement) => {
                let policy = replacement.policy();
                let expected_runner = self
                    .runner_generation
                    .checked_add(1)
                    .ok_or(LocalCertificationLedgerError::PolicyGenerationExhausted)?;
                let expected_certification = self
                    .certification_generation
                    .checked_add(1)
                    .ok_or(LocalCertificationLedgerError::PolicyGenerationExhausted)?;
                let actual_runner = policy.runner().policy_generation();
                let actual_certification = policy.policy_generation();
                if actual_runner != expected_runner
                    || actual_certification != expected_certification
                {
                    return Err(
                        LocalCertificationLedgerError::NonMonotonicPolicyGeneration {
                            expected_runner,
                            actual_runner,
                            expected_certification,
                            actual_certification,
                        },
                    );
                }
                self.policy = policy.clone();
                self.runner_generation = actual_runner;
                self.certification_generation = actual_certification;
                self.runner_revoked = false;
                self.certification_revoked = false;
                Ok(())
            }
            LocalCertificationLedgerEvent::CertificationRevocation(_) => {
                self.certification_generation = self
                    .certification_generation
                    .checked_add(1)
                    .ok_or(LocalCertificationLedgerError::PolicyGenerationExhausted)?;
                self.certification_revoked = true;
                Ok(())
            }
            LocalCertificationLedgerEvent::RunnerRevocation(_) => {
                self.runner_generation = self
                    .runner_generation
                    .checked_add(1)
                    .ok_or(LocalCertificationLedgerError::PolicyGenerationExhausted)?;
                self.runner_revoked = true;
                Ok(())
            }
        }
    }

    fn apply_publication(
        &mut self,
        attestation: &LocalCertificationRunAttestation,
    ) -> Result<(), LocalCertificationLedgerError> {
        if self.runner_revoked {
            return Err(LocalCertificationLedgerError::RunnerPolicyRevoked);
        }
        if self.certification_revoked {
            return Err(LocalCertificationLedgerError::CertificationPolicyRevoked);
        }
        if !self.policy.accepts_attestation(attestation) {
            return Err(LocalCertificationLedgerError::ControlPolicyMismatch);
        }
        let challenge = attestation.freshness().challenge();
        if self.freshness_challenges.contains(&challenge) {
            return Err(LocalCertificationLedgerError::FreshnessChallengeReplayed);
        }
        self.freshness_challenges.insert(challenge);
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct LedgerState {
    last_record: LocalCertificationLedgerRecord,
    head_digest: LocalCertificationLedgerRecordDigest,
    record_count: usize,
    total_record_bytes: usize,
    projection: LedgerProjection,
}

/// Open local certification ledger accepted under one independently supplied exact head.
///
/// The directory path is not itself a rollback anchor and ordinary filesystem state is not a
/// same-user sandbox. Every append replays the bounded canonical directory before attempting a
/// create-new next record.
pub struct LocalCertificationLedger {
    root: PathBuf,
    state: Mutex<LedgerState>,
}

impl fmt::Debug for LocalCertificationLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCertificationLedger")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl LocalCertificationLedger {
    /// Creates a new ledger directory and synchronized genesis record.
    ///
    /// The first attested publication must exactly match the supplied combined policy snapshot.
    /// Existing paths are never reused or overwritten.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched genesis relationship, existing or unsafe root, canonicalization
    /// failure, create-new write failure, or failed post-write replay.
    pub fn create(
        root: &Path,
        policy: CertificationControlPolicy,
        publication: &AttestedLocalCertificationPublication,
    ) -> Result<Self, LocalCertificationLedgerError> {
        let genesis =
            LocalCertificationLedgerGenesis::new(policy, publication.attestation().clone())
                .map_err(LocalCertificationLedgerError::Contract)?;
        let record = LocalCertificationLedgerRecord::genesis(genesis)
            .map_err(LocalCertificationLedgerError::Contract)?;
        fs::create_dir(root).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                LocalCertificationLedgerError::LedgerRootAlreadyExists {
                    path: root.to_path_buf(),
                }
            } else {
                LocalCertificationLedgerError::CreateLedgerRoot {
                    path: root.to_path_buf(),
                    source,
                }
            }
        })?;
        validate_ledger_root(root)?;
        let bytes = canonical_record_bytes(&record)?;
        write_record_create_new(root, record.sequence(), &bytes)?;
        let head = record
            .canonical_document_digest()
            .map_err(LocalCertificationLedgerError::CanonicalRecordUnavailable)?;
        let state = replay_directory(root, Some(head))?;
        Ok(Self {
            root: root.to_path_buf(),
            state: Mutex::new(state),
        })
    }

    /// Opens and completely replays a ledger under an independently pinned exact head identity.
    ///
    /// # Errors
    ///
    /// Rejects unsafe entries, bounds violations, malformed or noncanonical records, chain or
    /// policy failures, replayed challenges, and a head mismatch.
    pub fn open(
        root: &Path,
        expected_head: LocalCertificationLedgerRecordDigest,
    ) -> Result<Self, LocalCertificationLedgerError> {
        let state = replay_directory(root, Some(expected_head))?;
        Ok(Self {
            root: root.to_path_buf(),
            state: Mutex::new(state),
        })
    }

    /// Returns the current exact head identity for separately trusted pin persistence.
    ///
    /// # Errors
    ///
    /// Returns an error if in-memory state synchronization was poisoned.
    pub fn head_digest(
        &self,
    ) -> Result<LocalCertificationLedgerRecordDigest, LocalCertificationLedgerError> {
        self.state
            .lock()
            .map_err(|_| LocalCertificationLedgerError::StatePoisoned)
            .map(|state| state.head_digest)
    }

    /// Returns the accepted bounded record count.
    ///
    /// # Errors
    ///
    /// Returns an error if in-memory state synchronization was poisoned.
    pub fn record_count(&self) -> Result<usize, LocalCertificationLedgerError> {
        self.state
            .lock()
            .map_err(|_| LocalCertificationLedgerError::StatePoisoned)
            .map(|state| state.record_count)
    }

    /// Returns aggregate canonical record bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if in-memory state synchronization was poisoned.
    pub fn total_record_bytes(&self) -> Result<usize, LocalCertificationLedgerError> {
        self.state
            .lock()
            .map_err(|_| LocalCertificationLedgerError::StatePoisoned)
            .map(|state| state.total_record_bytes)
    }

    /// Returns the current exact combined policy projection.
    ///
    /// # Errors
    ///
    /// Returns an error if in-memory state synchronization was poisoned.
    pub fn control_policy(
        &self,
    ) -> Result<CertificationControlPolicy, LocalCertificationLedgerError> {
        self.state
            .lock()
            .map_err(|_| LocalCertificationLedgerError::StatePoisoned)
            .map(|state| state.projection.policy.clone())
    }

    /// Appends one exact attested local publication.
    ///
    /// # Errors
    ///
    /// Fails closed for stale or corrupt disk state, policy mismatch or revocation, challenge
    /// replay, bounds violations, and create-new write or synchronization failure.
    pub fn append_publication(
        &self,
        publication: &AttestedLocalCertificationPublication,
    ) -> Result<LocalCertificationLedgerAppendReceipt, LocalCertificationLedgerError> {
        let event = LocalCertificationLedgerEvent::publication(publication.attestation().clone())
            .map_err(LocalCertificationLedgerError::Contract)?;
        self.append_event(event)
    }

    /// Appends an exact next-generation combined policy replacement.
    ///
    /// # Errors
    ///
    /// Rejects stale disk state, nonmonotonic generations, invalid policy, bounds violations, and
    /// create-new write or synchronization failure.
    pub fn replace_policy(
        &self,
        policy: CertificationControlPolicy,
    ) -> Result<LocalCertificationLedgerAppendReceipt, LocalCertificationLedgerError> {
        self.append_event(LocalCertificationLedgerEvent::policy_replacement(policy))
    }

    /// Appends local certification-policy revocation evidence.
    ///
    /// # Errors
    ///
    /// Rejects stale or corrupt disk state, exhausted generation or ledger bounds, and create-new
    /// write or synchronization failure.
    pub fn revoke_certification(
        &self,
        evidence_digest: CertificationPolicyRevocationDigest,
    ) -> Result<LocalCertificationLedgerAppendReceipt, LocalCertificationLedgerError> {
        self.append_event(LocalCertificationLedgerEvent::certification_revocation(
            evidence_digest,
        ))
    }

    /// Appends local runner-policy revocation evidence.
    ///
    /// # Errors
    ///
    /// Rejects stale or corrupt disk state, exhausted generation or ledger bounds, and create-new
    /// write or synchronization failure.
    pub fn revoke_runner(
        &self,
        evidence_digest: CertificationRunnerPolicyRevocationDigest,
    ) -> Result<LocalCertificationLedgerAppendReceipt, LocalCertificationLedgerError> {
        self.append_event(LocalCertificationLedgerEvent::runner_revocation(
            evidence_digest,
        ))
    }

    fn append_event(
        &self,
        event: LocalCertificationLedgerEvent,
    ) -> Result<LocalCertificationLedgerAppendReceipt, LocalCertificationLedgerError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LocalCertificationLedgerError::StatePoisoned)?;
        let observed = replay_directory(&self.root, None)?;
        if observed.head_digest != state.head_digest
            || observed.record_count != state.record_count
            || observed.total_record_bytes != state.total_record_bytes
        {
            return Err(LocalCertificationLedgerError::StaleWriter {
                expected: state.head_digest,
                actual: observed.head_digest,
            });
        }
        if state.record_count >= MAX_LOCAL_CERTIFICATION_LEDGER_RECORDS {
            return Err(LocalCertificationLedgerError::TooManyRecords);
        }

        let mut projection = state.projection.clone();
        projection.apply(&event)?;
        let record = LocalCertificationLedgerRecord::next(&state.last_record, event)
            .map_err(LocalCertificationLedgerError::Contract)?;
        let bytes = canonical_record_bytes(&record)?;
        let total_record_bytes = state
            .total_record_bytes
            .checked_add(bytes.len())
            .ok_or(LocalCertificationLedgerError::TotalRecordBytesExceeded)?;
        if total_record_bytes > MAX_LOCAL_CERTIFICATION_LEDGER_BYTES {
            return Err(LocalCertificationLedgerError::TotalRecordBytesExceeded);
        }
        write_record_create_new(&self.root, record.sequence(), &bytes)?;
        let head_digest = record
            .canonical_document_digest()
            .map_err(LocalCertificationLedgerError::CanonicalRecordUnavailable)?;
        let record_count = state
            .record_count
            .checked_add(1)
            .ok_or(LocalCertificationLedgerError::TooManyRecords)?;
        state.last_record = record;
        state.head_digest = head_digest;
        state.record_count = record_count;
        state.total_record_bytes = total_record_bytes;
        state.projection = projection;
        Ok(LocalCertificationLedgerAppendReceipt {
            sequence: state.last_record.sequence(),
            record_digest: head_digest,
            record_count,
            total_record_bytes,
        })
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "bounded directory enumeration and sequential chain replay form one linear audit"
)]
fn replay_directory(
    root: &Path,
    expected_head: Option<LocalCertificationLedgerRecordDigest>,
) -> Result<LedgerState, LocalCertificationLedgerError> {
    validate_ledger_root(root)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(MAX_LOCAL_CERTIFICATION_LEDGER_RECORDS.min(256))
        .map_err(|_| LocalCertificationLedgerError::EntryAllocationFailed)?;
    for result in
        fs::read_dir(root).map_err(
            |source| LocalCertificationLedgerError::ReadLedgerDirectory {
                path: root.to_path_buf(),
                source,
            },
        )?
    {
        let entry = result.map_err(LocalCertificationLedgerError::ReadLedgerEntry)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| {
            LocalCertificationLedgerError::InspectLedgerEntry {
                path: path.clone(),
                source,
            }
        })?;
        if has_unsafe_link_metadata(&metadata) || !metadata.file_type().is_file() {
            return Err(LocalCertificationLedgerError::UnsafeLedgerEntry { path });
        }
        let sequence = parse_record_filename(&entry.file_name()).ok_or_else(|| {
            LocalCertificationLedgerError::UnknownLedgerEntry { path: entry.path() }
        })?;
        if entries.len() >= MAX_LOCAL_CERTIFICATION_LEDGER_RECORDS {
            return Err(LocalCertificationLedgerError::TooManyRecords);
        }
        entries
            .try_reserve(1)
            .map_err(|_| LocalCertificationLedgerError::EntryAllocationFailed)?;
        entries.push((sequence, entry.path()));
    }
    entries.sort_unstable_by_key(|(sequence, _)| *sequence);
    if entries.is_empty() {
        return Err(LocalCertificationLedgerError::MissingGenesis);
    }

    let mut total_record_bytes = 0_usize;
    let mut previous_record: Option<LocalCertificationLedgerRecord> = None;
    let mut previous_digest: Option<LocalCertificationLedgerRecordDigest> = None;
    let mut projection: Option<LedgerProjection> = None;
    for (index, (sequence, path)) in entries.into_iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(LocalCertificationLedgerError::TooManyRecords)?;
        if sequence != expected_sequence {
            return Err(LocalCertificationLedgerError::SequenceGap {
                expected: expected_sequence,
                actual: sequence,
            });
        }
        let bytes = read_record_bytes(&path, sequence)?;
        total_record_bytes = total_record_bytes
            .checked_add(bytes.len())
            .ok_or(LocalCertificationLedgerError::TotalRecordBytesExceeded)?;
        if total_record_bytes > MAX_LOCAL_CERTIFICATION_LEDGER_BYTES {
            return Err(LocalCertificationLedgerError::TotalRecordBytesExceeded);
        }
        let record = LocalCertificationLedgerRecord::from_json_slice(&bytes)
            .map_err(|source| LocalCertificationLedgerError::InvalidRecord { sequence, source })?;
        let canonical = record
            .canonical_json_bytes()
            .map_err(LocalCertificationLedgerError::CanonicalRecordUnavailable)?;
        if bytes != canonical {
            return Err(LocalCertificationLedgerError::NonCanonicalRecord { sequence });
        }
        if record.sequence() != sequence {
            return Err(LocalCertificationLedgerError::RecordSequenceMismatch {
                filename_sequence: sequence,
                record_sequence: record.sequence(),
            });
        }
        if record.previous_record_digest() != previous_digest {
            return Err(LocalCertificationLedgerError::PreviousRecordMismatch { sequence });
        }
        match (&mut projection, record.event()) {
            (None, LocalCertificationLedgerEvent::Genesis(genesis)) => {
                projection = Some(LedgerProjection::from_genesis(genesis));
            }
            (None, _) => return Err(LocalCertificationLedgerError::MissingGenesis),
            (Some(existing), event) => existing.apply(event)?,
        }
        previous_digest = Some(
            record
                .canonical_document_digest()
                .map_err(LocalCertificationLedgerError::CanonicalRecordUnavailable)?,
        );
        previous_record = Some(record);
    }

    let head_digest = previous_digest.ok_or(LocalCertificationLedgerError::MissingGenesis)?;
    if let Some(expected) = expected_head
        && expected != head_digest
    {
        return Err(LocalCertificationLedgerError::HeadMismatch {
            expected,
            actual: head_digest,
        });
    }
    let last_record = previous_record.ok_or(LocalCertificationLedgerError::MissingGenesis)?;
    let record_count = usize::try_from(last_record.sequence())
        .map_err(|_| LocalCertificationLedgerError::TooManyRecords)?;
    Ok(LedgerState {
        last_record,
        head_digest,
        record_count,
        total_record_bytes,
        projection: projection.ok_or(LocalCertificationLedgerError::MissingGenesis)?,
    })
}

fn canonical_record_bytes(
    record: &LocalCertificationLedgerRecord,
) -> Result<Vec<u8>, LocalCertificationLedgerError> {
    let bytes = record
        .canonical_json_bytes()
        .map_err(LocalCertificationLedgerError::CanonicalRecordUnavailable)?;
    if bytes.len() > MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES {
        return Err(LocalCertificationLedgerError::RecordTooLarge {
            sequence: record.sequence(),
        });
    }
    Ok(bytes)
}

fn write_record_create_new(
    root: &Path,
    sequence: u64,
    bytes: &[u8],
) -> Result<(), LocalCertificationLedgerError> {
    validate_ledger_root(root)?;
    let path = root.join(record_filename(sequence));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                LocalCertificationLedgerError::RecordAlreadyExists { sequence }
            } else {
                LocalCertificationLedgerError::CreateRecord {
                    sequence,
                    path: path.clone(),
                    source,
                }
            }
        })?;
    file.write_all(bytes)
        .map_err(|source| LocalCertificationLedgerError::WriteRecord { sequence, source })?;
    file.sync_all()
        .map_err(|source| LocalCertificationLedgerError::SyncRecord { sequence, source })
}

fn read_record_bytes(path: &Path, sequence: u64) -> Result<Vec<u8>, LocalCertificationLedgerError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        LocalCertificationLedgerError::InspectLedgerEntry {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if has_unsafe_link_metadata(&metadata) || !metadata.file_type().is_file() {
        return Err(LocalCertificationLedgerError::UnsafeLedgerEntry {
            path: path.to_path_buf(),
        });
    }
    if metadata.len()
        > u64::try_from(MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES)
            .map_err(|_| LocalCertificationLedgerError::RecordTooLarge { sequence })?
    {
        return Err(LocalCertificationLedgerError::RecordTooLarge { sequence });
    }
    let file = File::open(path).map_err(|source| LocalCertificationLedgerError::OpenRecord {
        sequence,
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    let reserve_bytes = usize::try_from(metadata.len())
        .map_or(MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES, |length| {
            length.min(MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES)
        });
    bytes
        .try_reserve_exact(reserve_bytes)
        .map_err(|_| LocalCertificationLedgerError::RecordAllocationFailed { sequence })?;
    let limit = u64::try_from(MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(LocalCertificationLedgerError::RecordTooLarge { sequence })?;
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| LocalCertificationLedgerError::ReadRecord { sequence, source })?;
    if bytes.len() > MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES {
        return Err(LocalCertificationLedgerError::RecordTooLarge { sequence });
    }
    Ok(bytes)
}

fn validate_ledger_root(root: &Path) -> Result<(), LocalCertificationLedgerError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| {
        LocalCertificationLedgerError::InspectLedgerRoot {
            path: root.to_path_buf(),
            source,
        }
    })?;
    if has_unsafe_link_metadata(&metadata) || !metadata.file_type().is_dir() {
        return Err(LocalCertificationLedgerError::UnsafeLedgerRoot {
            path: root.to_path_buf(),
        });
    }
    Ok(())
}

fn has_unsafe_link_metadata(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn parse_record_filename(name: &OsStr) -> Option<u64> {
    let name = name.to_str()?;
    let digits = name.strip_suffix(RECORD_FILE_SUFFIX)?;
    if digits.len() != RECORD_FILE_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = digits.parse::<u64>().ok()?;
    if sequence == 0 || record_filename(sequence) != name {
        return None;
    }
    Some(sequence)
}

fn record_filename(sequence: u64) -> String {
    format!("{sequence:020}{RECORD_FILE_SUFFIX}")
}

/// Failure to create, replay, validate, or append a local certification ledger.
#[derive(Debug, Error)]
pub enum LocalCertificationLedgerError {
    /// Requested root already exists and will not be overwritten.
    #[error("local certification ledger root already exists: {path}")]
    LedgerRootAlreadyExists {
        /// Existing path.
        path: PathBuf,
    },
    /// New ledger root could not be created.
    #[error("failed to create local certification ledger root {path}")]
    CreateLedgerRoot {
        /// Requested root.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Ledger-root metadata could not be inspected.
    #[error("failed to inspect local certification ledger root {path}")]
    InspectLedgerRoot {
        /// Requested root.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Root was a symbolic link or not a directory.
    #[error("local certification ledger root is unsafe: {path}")]
    UnsafeLedgerRoot {
        /// Unsafe root.
        path: PathBuf,
    },
    /// Ledger directory could not be enumerated.
    #[error("failed to read local certification ledger directory {path}")]
    ReadLedgerDirectory {
        /// Ledger root.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// One directory entry could not be read.
    #[error("failed to read a local certification ledger entry")]
    ReadLedgerEntry(#[source] std::io::Error),
    /// One entry's metadata could not be inspected.
    #[error("failed to inspect local certification ledger entry {path}")]
    InspectLedgerEntry {
        /// Entry path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Entry was a symbolic link or not a regular file.
    #[error("unsafe local certification ledger entry {path}")]
    UnsafeLedgerEntry {
        /// Unsafe entry.
        path: PathBuf,
    },
    /// Entry did not use the fixed sequence-only filename.
    #[error("unknown local certification ledger entry {path}")]
    UnknownLedgerEntry {
        /// Unknown entry.
        path: PathBuf,
    },
    /// Directory entries could not be retained within the fixed bound.
    #[error("local certification ledger entry allocation failed")]
    EntryAllocationFailed,
    /// Ledger exceeded the fixed record count.
    #[error("local certification ledger has too many records")]
    TooManyRecords,
    /// Ledger was empty or did not start with genesis.
    #[error("local certification ledger is missing genesis")]
    MissingGenesis,
    /// A later event attempted another genesis.
    #[error("local certification ledger contains an unexpected genesis")]
    UnexpectedGenesis,
    /// Fixed filenames had a missing sequence.
    #[error("local certification ledger sequence gap: expected {expected}, found {actual}")]
    SequenceGap {
        /// Required sequence.
        expected: u64,
        /// Observed sequence.
        actual: u64,
    },
    /// A record exceeded its fixed serialized ceiling.
    #[error("local certification ledger record {sequence} exceeds its byte ceiling")]
    RecordTooLarge {
        /// Record sequence.
        sequence: u64,
    },
    /// Aggregate serialized record bytes exceeded the fixed ceiling.
    #[error("local certification ledger exceeds its aggregate byte ceiling")]
    TotalRecordBytesExceeded,
    /// Record could not be opened.
    #[error("failed to open local certification ledger record {sequence} at {path}")]
    OpenRecord {
        /// Record sequence.
        sequence: u64,
        /// Record path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Record buffer could not be allocated.
    #[error("local certification ledger record {sequence} allocation failed")]
    RecordAllocationFailed {
        /// Record sequence.
        sequence: u64,
    },
    /// Record bytes could not be read.
    #[error("failed to read local certification ledger record {sequence}")]
    ReadRecord {
        /// Record sequence.
        sequence: u64,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Record bytes did not parse and validate.
    #[error("local certification ledger record {sequence} is invalid")]
    InvalidRecord {
        /// Record sequence.
        sequence: u64,
        /// Document failure.
        #[source]
        source: LocalCertificationLedgerDocumentError,
    },
    /// Stored bytes differed from canonical compact encoding.
    #[error("local certification ledger record {sequence} is not canonical")]
    NonCanonicalRecord {
        /// Record sequence.
        sequence: u64,
    },
    /// Internal sequence differed from the fixed filename.
    #[error(
        "local certification ledger filename sequence {filename_sequence} differs from record {record_sequence}"
    )]
    RecordSequenceMismatch {
        /// Fixed filename sequence.
        filename_sequence: u64,
        /// Serialized sequence.
        record_sequence: u64,
    },
    /// Hash-chain link differed from the exact predecessor.
    #[error("local certification ledger record {sequence} has the wrong previous-record link")]
    PreviousRecordMismatch {
        /// Record sequence.
        sequence: u64,
    },
    /// Canonical record bytes or identity could not be produced.
    #[error("canonical local certification ledger record is unavailable")]
    CanonicalRecordUnavailable(#[source] serde_json::Error),
    /// Independently pinned head differed from replayed state.
    #[error("local certification ledger head mismatch: expected {expected}, found {actual}")]
    HeadMismatch {
        /// Independently pinned head.
        expected: LocalCertificationLedgerRecordDigest,
        /// Replayed head.
        actual: LocalCertificationLedgerRecordDigest,
    },
    /// Another writer advanced the directory after this instance's accepted head.
    #[error("local certification ledger writer is stale: expected {expected}, found {actual}")]
    StaleWriter {
        /// Instance head.
        expected: LocalCertificationLedgerRecordDigest,
        /// Current directory head.
        actual: LocalCertificationLedgerRecordDigest,
    },
    /// A new fixed sequence file already existed.
    #[error("local certification ledger record {sequence} already exists")]
    RecordAlreadyExists {
        /// Colliding next sequence.
        sequence: u64,
    },
    /// Create-new record open failed.
    #[error("failed to create local certification ledger record {sequence} at {path}")]
    CreateRecord {
        /// Record sequence.
        sequence: u64,
        /// Record path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Record bytes could not be completely written.
    #[error("failed to write local certification ledger record {sequence}")]
    WriteRecord {
        /// Record sequence.
        sequence: u64,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Record file synchronization failed.
    #[error("failed to synchronize local certification ledger record {sequence}")]
    SyncRecord {
        /// Record sequence.
        sequence: u64,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Domain record relationships were invalid.
    #[error("local certification ledger contract failed")]
    Contract(#[source] LocalCertificationLedgerContractError),
    /// Publication did not match the current exact control policy.
    #[error("local certification publication does not match current ledger policy")]
    ControlPolicyMismatch,
    /// Current runner policy is revoked.
    #[error("local certification runner policy is revoked")]
    RunnerPolicyRevoked,
    /// Current certification policy is revoked.
    #[error("local certification policy is revoked")]
    CertificationPolicyRevoked,
    /// Freshness challenge already appeared in ledger history.
    #[error("local certification freshness challenge was replayed")]
    FreshnessChallengeReplayed,
    /// Replacement or revocation generation arithmetic exhausted.
    #[error("local certification ledger policy generation is exhausted")]
    PolicyGenerationExhausted,
    /// Replacement generations were not the exact next values.
    #[error(
        "local certification policy generation mismatch: runner expected {expected_runner}, found {actual_runner}; certification expected {expected_certification}, found {actual_certification}"
    )]
    NonMonotonicPolicyGeneration {
        /// Expected runner generation.
        expected_runner: u64,
        /// Replacement runner generation.
        actual_runner: u64,
        /// Expected certification generation.
        expected_certification: u64,
        /// Replacement certification generation.
        actual_certification: u64,
    },
    /// In-memory state synchronization failed.
    #[error("local certification ledger state is poisoned")]
    StatePoisoned,
}
