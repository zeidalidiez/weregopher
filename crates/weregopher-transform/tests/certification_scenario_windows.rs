//! Native Windows behavior proof for the shared disposable-state scenario runner.

#![cfg(windows)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    process::Command,
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use weregopher_domain::{
    AdapterId, ApplicationFamilyId, CertificationRunnerArtifactName,
    CertificationRunnerComponentArtifact, CertificationRunnerComponentDescriptor,
    CertificationRunnerComponentId, CertificationRunnerComponentProvenanceDigest,
    CertificationRunnerComponentRole, CertificationRunnerComponentVersion,
    CertificationRunnerEnvironmentIdentity, CertificationRunnerIdentity,
    CertificationRunnerPolicyRevisionDigest, CertificationRunnerProvenanceIdentity,
    CertificationRunnerToolingIdentity, DisposableCertificationScenario,
    DisposableScenarioArgument, DisposableScenarioLimits, DisposableScenarioStateRoot,
    ExecutionArgument, ExecutionPackagePath, ExecutionResourceLimits, FeatureId, ScenarioId,
    ScenarioStateRootId, Sha256Digest,
};
use weregopher_fingerprint::{PackageTreeObservationLimits, observe_package_tree};
use weregopher_transform::{
    CertificationRunnerComponentVerificationLimits, DisposableCertificationScenarioExecutionError,
    DisposableCertificationScenarioRunMode, LocalCertificationRunnerPolicy,
    LocalCertificationRunnerPolicyStore, ManagedArtifactStore, ManagedStoreRootLimits,
    PackageSnapshotWriteLimits, approve_local_certification_runner,
    execute_disposable_certification_scenario, verify_certification_runner_components,
    verify_disposable_certification_scenario,
};
use weregopher_windows::FileIdentityLease;

const EXECUTABLE_NAME: &str = "scenario-fixture.exe";
const SCENARIO_ARTIFACT_NAME: &str = "scenarios/windows-fixture.json";
const SUCCESS_BYTES: &[u8] = b"weregopher-scenario-fixture\n";
const FIXTURE_SOURCE: &[u8] = br#"
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let Some(path) = arguments.next() else {
        std::process::exit(2);
    };
    let Some(state_directory) = arguments.next() else {
        std::process::exit(5);
    };
    let Ok(mut state_entries) = std::fs::read_dir(&state_directory) else {
        std::process::exit(6);
    };
    if state_entries.next().is_some() {
        std::process::exit(7);
    }
    let mut linger_after_success = false;
    if let Some(mode) = arguments.next() {
        let Some(mode) = mode.to_str() else {
            std::process::exit(4);
        };
        if let Some(delay) = mode.strip_prefix("child:") {
            let Ok(executable) = std::env::current_exe() else {
                std::process::exit(8);
            };
            if std::process::Command::new(executable)
                .arg(path)
                .arg(state_directory)
                .arg(format!("worker:{delay}"))
                .spawn()
                .is_err()
            {
                std::process::exit(9);
            }
            return;
        }
        let mode = if let Some(delay) = mode.strip_prefix("worker:") {
            linger_after_success = true;
            delay
        } else {
            mode
        };
        let Ok(delay) = mode.parse::<u64>() else {
            std::process::exit(4);
        };
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }
    if std::fs::write(path, b"weregopher-scenario-fixture\n").is_err() {
        std::process::exit(3);
    }
    if linger_after_success {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let sentinel = std::path::PathBuf::from(state_directory).join("survived-job-termination");
        if std::fs::write(sentinel, b"unexpected survivor").is_err() {
            std::process::exit(10);
        }
    }
}
"#;

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native proof keeps the shared snapshot and three process-tree outcomes in a single retained-lifetime scope"
)]
fn shared_runner_executes_verified_scenario_in_disposable_state_and_revalidates_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let package_root = temporary.path().join("package");
    let store_root = temporary.path().join("store");
    fs::create_dir(&package_root)?;
    fs::create_dir(&store_root)?;
    let source_path = package_root.join("fixture.rs");
    let executable_path = package_root.join(EXECUTABLE_NAME);
    fs::write(&source_path, FIXTURE_SOURCE)?;
    let status = Command::new("rustc")
        .arg("--edition=2024")
        .arg("-o")
        .arg(&executable_path)
        .arg(&source_path)
        .status()?;
    if !status.success() {
        return Err("failed to compile the native disposable-scenario fixture".into());
    }

    let package = observe_package_tree(
        &package_root,
        PackageTreeObservationLimits::new(8, 8, 4, 64 * 1024 * 1024, 128 * 1024 * 1024, 4_096)?,
    )?;
    let store =
        ManagedArtifactStore::open(&store_root, &package_root, ManagedStoreRootLimits::new(32)?)?;
    let snapshot = store.snapshot_package(
        &package,
        PackageSnapshotWriteLimits::new(8, 8, 64 * 1024 * 1024, 128 * 1024 * 1024, 16)?,
    )?;
    let snapshot_executable = snapshot.lock_executable(EXECUTABLE_NAME, 16)?;

    let scenario = scenario_fixture(None)?;
    let scenario_bytes = scenario.canonical_json_bytes()?;
    let scenario_name = CertificationRunnerArtifactName::new(SCENARIO_ARTIFACT_NAME)?;
    let runner = RunnerFixture::new(&scenario_name, &scenario_bytes)?;
    let runner_policy = LocalCertificationRunnerPolicy::new(
        runner.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x90)),
    );
    let runner_store = LocalCertificationRunnerPolicyStore::new(runner_policy);
    let approved = approve_local_certification_runner(runner.identity.clone(), &runner_store)?;
    let borrowed = runner.borrowed_artifacts();
    let verified_runner = verify_certification_runner_components(
        approved,
        &runner.descriptors,
        &borrowed,
        CertificationRunnerComponentVerificationLimits::new(128 * 1024, 128 * 1024, 512 * 1024)?,
    )?;
    let verified_scenario = verify_disposable_certification_scenario(
        verified_runner,
        CertificationRunnerArtifactName::new(SCENARIO_ARTIFACT_NAME)?,
    )?;
    assert_eq!(verified_scenario.scenario(), &scenario);

    let success_path = temporary.path().join("scenario-success.txt");
    let state_directory = temporary.path().join("scenario-state");
    let state_paths = BTreeMap::from([
        (ScenarioStateRootId::new("success")?, success_path.clone()),
        (ScenarioStateRootId::new("state")?, state_directory.clone()),
    ]);
    let completed = execute_disposable_certification_scenario(
        verified_scenario,
        DisposableCertificationScenarioRunMode::Candidate,
        snapshot_executable,
        &state_paths,
        Duration::from_secs(10),
    )?;
    let (report, pending, diagnostics) = completed.into_parts();

    assert!(pending.is_none());
    let reported_success_file =
        FileIdentityLease::from_file(fs::File::open(diagnostics.success_file_path())?)?;
    let requested_success_file = FileIdentityLease::from_file(fs::File::open(&success_path)?)?;
    assert!(reported_success_file.has_same_identity(&requested_success_file));
    assert_eq!(diagnostics.process_exit_code(), 0);
    assert_eq!(fs::read(success_path)?, SUCCESS_BYTES);
    assert!(state_directory.is_dir());
    assert!(fs::read_dir(state_directory)?.next().is_none());
    assert_eq!(report.scenario(), &scenario);
    assert_eq!(
        report.package().package_tree_merkle(),
        *snapshot.package_tree_merkle()
    );
    assert!(report.execution().job_membership_confirmed());
    assert!(report.execution().job_tree_termination_confirmed());
    assert!(report.execution().primary_process_exit_confirmed());
    assert!(report.execution().snapshot_revalidated());
    snapshot.verify_current_view()?;

    let delayed_scenario = scenario_fixture(Some("250"))?;
    let delayed_scenario_bytes = delayed_scenario.canonical_json_bytes()?;
    let delayed_runner = RunnerFixture::new(&scenario_name, &delayed_scenario_bytes)?;
    let delayed_policy = LocalCertificationRunnerPolicy::new(
        delayed_runner.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x91)),
    );
    let delayed_store = LocalCertificationRunnerPolicyStore::new(delayed_policy);
    let delayed_approved =
        approve_local_certification_runner(delayed_runner.identity.clone(), &delayed_store)?;
    let delayed_borrowed = delayed_runner.borrowed_artifacts();
    let delayed_verified_runner = verify_certification_runner_components(
        delayed_approved,
        &delayed_runner.descriptors,
        &delayed_borrowed,
        CertificationRunnerComponentVerificationLimits::new(128 * 1024, 128 * 1024, 512 * 1024)?,
    )?;
    let delayed_verified_scenario = verify_disposable_certification_scenario(
        delayed_verified_runner,
        CertificationRunnerArtifactName::new(SCENARIO_ARTIFACT_NAME)?,
    )?;
    let delayed_executable = snapshot.lock_executable(EXECUTABLE_NAME, 16)?;
    let delayed_success_path = temporary.path().join("scenario-late-success.txt");
    let delayed_state_directory = temporary.path().join("scenario-delayed-state");
    let delayed_state_paths = BTreeMap::from([
        (
            ScenarioStateRootId::new("success")?,
            delayed_success_path.clone(),
        ),
        (
            ScenarioStateRootId::new("state")?,
            delayed_state_directory.clone(),
        ),
    ]);
    assert!(matches!(
        execute_disposable_certification_scenario(
            delayed_verified_scenario,
            DisposableCertificationScenarioRunMode::Candidate,
            delayed_executable,
            &delayed_state_paths,
            Duration::from_millis(20),
        ),
        Err(DisposableCertificationScenarioExecutionError::SuccessFileMissing)
    ));
    assert!(!delayed_success_path.exists());
    assert!(delayed_state_directory.is_dir());
    snapshot.verify_current_view()?;

    let child_scenario = scenario_fixture(Some("child:100"))?;
    let child_scenario_bytes = child_scenario.canonical_json_bytes()?;
    let child_runner = RunnerFixture::new(&scenario_name, &child_scenario_bytes)?;
    let child_policy = LocalCertificationRunnerPolicy::new(
        child_runner.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x92)),
    );
    let child_store = LocalCertificationRunnerPolicyStore::new(child_policy);
    let child_approved =
        approve_local_certification_runner(child_runner.identity.clone(), &child_store)?;
    let child_borrowed = child_runner.borrowed_artifacts();
    let child_verified_runner = verify_certification_runner_components(
        child_approved,
        &child_runner.descriptors,
        &child_borrowed,
        CertificationRunnerComponentVerificationLimits::new(128 * 1024, 128 * 1024, 512 * 1024)?,
    )?;
    let child_verified_scenario = verify_disposable_certification_scenario(
        child_verified_runner,
        CertificationRunnerArtifactName::new(SCENARIO_ARTIFACT_NAME)?,
    )?;
    let child_executable = snapshot.lock_executable(EXECUTABLE_NAME, 16)?;
    let child_success_path = temporary.path().join("scenario-child-success.txt");
    let child_state_directory = temporary.path().join("scenario-child-state");
    let child_state_paths = BTreeMap::from([
        (
            ScenarioStateRootId::new("success")?,
            child_success_path.clone(),
        ),
        (
            ScenarioStateRootId::new("state")?,
            child_state_directory.clone(),
        ),
    ]);
    let child_completed = execute_disposable_certification_scenario(
        child_verified_scenario,
        DisposableCertificationScenarioRunMode::Candidate,
        child_executable,
        &child_state_paths,
        Duration::from_secs(1),
    )?;
    assert_eq!(fs::read(child_success_path)?, SUCCESS_BYTES);
    assert!(
        child_completed
            .report()
            .execution()
            .job_tree_termination_confirmed()
    );
    std::thread::sleep(Duration::from_millis(700));
    assert!(
        !child_state_directory
            .join("survived-job-termination")
            .exists()
    );
    snapshot.verify_current_view()?;
    Ok(())
}

fn scenario_fixture(
    mode: Option<&str>,
) -> Result<DisposableCertificationScenario, Box<dyn std::error::Error>> {
    let success = ScenarioStateRootId::new("success")?;
    let state = ScenarioStateRootId::new("state")?;
    let mut arguments = vec![
        DisposableScenarioArgument::state_path(success.clone(), ExecutionArgument::new("")?),
        DisposableScenarioArgument::state_path(state.clone(), ExecutionArgument::new("")?),
    ];
    if let Some(mode) = mode {
        arguments.push(DisposableScenarioArgument::literal(ExecutionArgument::new(
            mode,
        )?));
    }
    let (scenario_id, adapter_id) = match mode {
        Some(mode) if mode.starts_with("child:") => (
            "test.windows-disposable-child-success",
            "test.windows-disposable-child-success.v1",
        ),
        Some(_) => (
            "test.windows-disposable-delayed-success",
            "test.windows-disposable-delayed-success.v1",
        ),
        None => (
            "test.windows-disposable-success",
            "test.windows-disposable-success.v1",
        ),
    };
    Ok(DisposableCertificationScenario::new(
        ScenarioId::new(scenario_id)?,
        ApplicationFamilyId::new("test-app")?,
        AdapterId::new(adapter_id)?,
        FeatureId::new(scenario_id)?,
        ExecutionPackagePath::new(EXECUTABLE_NAME)?,
        vec![
            DisposableScenarioStateRoot::success_file(
                success,
                sha256(SUCCESS_BYTES),
                u64::try_from(SUCCESS_BYTES.len())?,
                256,
            )?,
            DisposableScenarioStateRoot::empty_directory(state),
        ],
        arguments,
        DisposableScenarioLimits::new(
            Duration::from_secs(10),
            Duration::from_millis(50),
            Duration::from_secs(2),
            4,
            8_192,
            32_767,
            ExecutionResourceLimits::new(4, 512 * 1024 * 1024, 1024 * 1024 * 1024)?,
        )?,
    )?)
}

struct RunnerFixture {
    identity: CertificationRunnerIdentity,
    descriptors: BTreeMap<CertificationRunnerComponentRole, CertificationRunnerComponentDescriptor>,
    artifacts: BTreeMap<
        CertificationRunnerComponentRole,
        BTreeMap<CertificationRunnerArtifactName, Vec<u8>>,
    >,
}

impl RunnerFixture {
    fn new(
        scenario_name: &CertificationRunnerArtifactName,
        scenario_bytes: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut descriptors = BTreeMap::new();
        let mut artifacts = BTreeMap::new();
        let mut descriptor_digests = BTreeMap::new();
        for (index, role) in runner_roles().into_iter().enumerate() {
            let tag = u8::try_from(index + 1)?;
            let (name, bytes) = if role == CertificationRunnerComponentRole::ProbeAssetSet {
                (scenario_name.clone(), scenario_bytes.to_owned())
            } else {
                (
                    CertificationRunnerArtifactName::new(format!("role/{tag:02}.bin"))?,
                    vec![tag; 3],
                )
            };
            let descriptor = CertificationRunnerComponentDescriptor::new(
                role,
                CertificationRunnerComponentId::new(format!("weregopher.test.{tag:02}"))?,
                CertificationRunnerComponentVersion::new(format!("1.0.{tag}"))?,
                CertificationRunnerComponentProvenanceDigest::new(digest(tag)),
                BTreeSet::from([CertificationRunnerComponentArtifact::new(
                    name.clone(),
                    sha256(&bytes),
                    u64::try_from(bytes.len())?,
                )?]),
            )?;
            descriptor_digests.insert(role, *descriptor.canonical_document_digest()?.as_sha256());
            descriptors.insert(role, descriptor);
            artifacts.insert(role, BTreeMap::from([(name, bytes)]));
        }
        let identity = CertificationRunnerIdentity::new(
            CertificationRunnerEnvironmentIdentity::windows_x86_64(
                weregopher_domain::CertificationRunnerImageDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::RunnerImage,
                )?),
                weregopher_domain::CertificationHostImageDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::HostImage,
                )?),
                weregopher_domain::CertificationHostPatchSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::HostPatchSet,
                )?),
                weregopher_domain::CertificationElectronRuntimeDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ElectronRuntime,
                )?),
                weregopher_domain::CertificationLanguageRuntimeSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::LanguageRuntimeSet,
                )?),
            ),
            CertificationRunnerToolingIdentity::new(
                weregopher_domain::CertificationToolchainSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ToolchainSet,
                )?),
                weregopher_domain::CertificationHostAgentDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::HostAgent,
                )?),
                weregopher_domain::CertificationVerifierDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::Verifier,
                )?),
                weregopher_domain::CertificationProbeAssetSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ProbeAssetSet,
                )?),
            ),
            CertificationRunnerProvenanceIdentity::new(
                weregopher_domain::CertificationSourceRevisionDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::SourceRevision,
                )?),
                weregopher_domain::CertificationExceptionProvenanceDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ExceptionProvenance,
                )?),
            ),
        );
        Ok(Self {
            identity,
            descriptors,
            artifacts,
        })
    }

    fn borrowed_artifacts(
        &self,
    ) -> BTreeMap<CertificationRunnerComponentRole, BTreeMap<CertificationRunnerArtifactName, &[u8]>>
    {
        self.artifacts
            .iter()
            .map(|(role, artifacts)| {
                (
                    *role,
                    artifacts
                        .iter()
                        .map(|(name, bytes)| (name.clone(), bytes.as_slice()))
                        .collect(),
                )
            })
            .collect()
    }
}

fn descriptor_digest(
    digests: &BTreeMap<CertificationRunnerComponentRole, Sha256Digest>,
    role: CertificationRunnerComponentRole,
) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
    digests
        .get(&role)
        .copied()
        .ok_or_else(|| format!("missing descriptor digest for {role:?}").into())
}

const fn runner_roles() -> [CertificationRunnerComponentRole; 11] {
    [
        CertificationRunnerComponentRole::RunnerImage,
        CertificationRunnerComponentRole::HostImage,
        CertificationRunnerComponentRole::HostPatchSet,
        CertificationRunnerComponentRole::ElectronRuntime,
        CertificationRunnerComponentRole::LanguageRuntimeSet,
        CertificationRunnerComponentRole::ToolchainSet,
        CertificationRunnerComponentRole::HostAgent,
        CertificationRunnerComponentRole::Verifier,
        CertificationRunnerComponentRole::ProbeAssetSet,
        CertificationRunnerComponentRole::SourceRevision,
        CertificationRunnerComponentRole::ExceptionProvenance,
    ]
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

const fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
