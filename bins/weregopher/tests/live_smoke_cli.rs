//! Discord live-smoke command boundary tests.

use std::process::Command;

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn local_smoke_certification_requires_both_exact_report_and_policy_revision()
-> Result<(), Box<dyn std::error::Error>> {
    assert_missing_pair("--expected-certification-report", "--local-policy-revision")?;
    assert_missing_pair("--local-policy-revision", "--expected-certification-report")
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
