//! End-to-end tests for the package fingerprint CLI slice.

use std::{
    fs,
    process::{Command, Stdio},
};

use tempfile::tempdir;

#[test]
fn fingerprint_command_emits_a_canonical_build_and_tree_report()
-> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    fs::create_dir_all(package.path().join("resources"))?;
    fs::write(package.path().join("resources/app.asar"), b"fixture")?;

    let output = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .arg("fingerprint")
        .arg(package.path())
        .args([
            "--family",
            "openai.chatgpt",
            "--installation-kind",
            "portable",
            "--architecture",
            "x86_64",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["fingerprint"]["family"], "openai.chatgpt");
    assert_eq!(report["fingerprint"]["installation_kind"], "portable");
    assert_eq!(report["package_tree"]["format_version"], 1);
    assert_eq!(
        report["package_tree"]["files"][0]["normalized_path"],
        "resources/app.asar"
    );
    assert_eq!(
        report["fingerprint"]["package_tree_merkle"],
        report["package_tree"]["package_tree_merkle"]
    );
    Ok(())
}

#[test]
fn fingerprint_command_rejects_noncanonical_family_ids() -> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .arg("fingerprint")
        .arg(package.path())
        .args([
            "--family",
            "OpenAI.ChatGPT",
            "--installation-kind",
            "portable",
            "--architecture",
            "x86_64",
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid application family"));
    Ok(())
}

#[test]
fn fingerprint_command_rejects_uncertified_path_exclusions()
-> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    fs::create_dir_all(package.path().join("resources"))?;
    fs::write(package.path().join("resources/app.asar"), b"fixture")?;

    let output = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .arg("fingerprint")
        .arg(package.path())
        .args([
            "--family",
            "openai.chatgpt",
            "--installation-kind",
            "portable",
            "--architecture",
            "x86_64",
            "--exclude",
            "resources",
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--exclude'"));
    Ok(())
}

#[test]
fn fingerprint_command_reports_a_closed_stdout_without_panicking()
-> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    fs::write(package.path().join("app.js"), b"fixture")?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .arg("fingerprint")
        .arg(package.path())
        .args([
            "--family",
            "openai.chatgpt",
            "--installation-kind",
            "portable",
            "--architecture",
            "x86_64",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(child.stdout.take());
    let output = child.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(
        stderr.contains("failed to serialize fingerprint report")
            || stderr.contains("failed to finish fingerprint report"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn fingerprint_command_does_not_promote_a_symbolic_link_to_app_asar_content()
-> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    let resources = package.path().join("resources");
    fs::create_dir_all(&resources)?;
    fs::write(resources.join("real.asar"), b"fixture")?;
    if let Err(error) = create_file_symlink("real.asar", &resources.join("app.asar")) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(error.into());
    }

    let output = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .arg("fingerprint")
        .arg(package.path())
        .args([
            "--family",
            "openai.chatgpt",
            "--installation-kind",
            "portable",
            "--architecture",
            "x86_64",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert!(report["fingerprint"]["app_asar_sha256"].is_null());
    let link = report["package_tree"]["files"]
        .as_array()
        .and_then(|files| {
            files
                .iter()
                .find(|record| record["normalized_path"] == "resources/app.asar")
        })
        .ok_or("symbolic-link record was not emitted")?;
    assert_eq!(link["kind"], "symbolic_link");
    Ok(())
}

#[cfg(windows)]
fn create_file_symlink(target: &str, link: &std::path::Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(unix)]
fn create_file_symlink(target: &str, link: &std::path::Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}
