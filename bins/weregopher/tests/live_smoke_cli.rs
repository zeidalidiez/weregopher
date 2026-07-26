//! Discord live-smoke command boundary tests.

use std::process::Command;

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn local_smoke_certification_requires_both_exact_report_and_policy_revision()
-> Result<(), Box<dyn std::error::Error>> {
    assert_missing_pair("--expected-certification-report", "--local-policy-revision")?;
    assert_missing_pair("--local-policy-revision", "--expected-certification-report")
}

#[test]
fn runner_bundle_requires_exact_identity_policy_and_snapshot_store_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    assert_missing_option(&["--runner-bundle", "runner"], "--expected-runner-identity")?;
    assert_missing_option(
        &["--expected-runner-identity", DIGEST],
        "--runner-policy-revision",
    )?;
    assert_missing_option(&["--runner-policy-revision", DIGEST], "--runner-bundle")?;
    assert_missing_option(&["--snapshot-store-root", "snapshots"], "--runner-bundle")
}

#[test]
fn trusted_report_inputs_require_a_ledger_and_pinned_existing_head()
-> Result<(), Box<dyn std::error::Error>> {
    assert_missing_option(
        &[
            "--expected-certification-report",
            DIGEST,
            "--local-policy-revision",
            DIGEST,
        ],
        "--certification-ledger",
    )?;
    assert_missing_option(
        &["--expected-ledger-head", DIGEST],
        "--certification-ledger",
    )
}

fn assert_missing_pair(
    supplied_option: &str,
    required_option: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .args([
            "live-smoke-discord",
            "vendor",
            "managed",
            "marker",
            "--allow-uncertified-local-smoke",
            supplied_option,
            DIGEST,
        ])
        .output()?;

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr)?;
    assert!(
        stderr.contains(required_option),
        "missing paired-option diagnostic in: {stderr}"
    );
    Ok(())
}

fn assert_missing_option(
    supplied: &[&str],
    required_option: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = vec![
        "live-smoke-discord",
        "vendor",
        "managed",
        "marker",
        "--allow-uncertified-local-smoke",
    ];
    arguments.extend_from_slice(supplied);
    let result = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .args(arguments)
        .output()?;
    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr)?;
    assert!(
        stderr.contains(required_option),
        "missing option diagnostic `{required_option}` in: {stderr}"
    );
    Ok(())
}
