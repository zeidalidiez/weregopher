//! `OpenAI` G2 feasibility CLI behavior.

use std::process::Command;

#[test]
fn app_server_execution_requires_explicit_same_user_acknowledgement()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .args(["feasibility", "open-ai", "--probe-app-server"])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("--allow-unrestricted-same-user-probe"));
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn installed_openai_feasibility_fails_closed_off_windows() -> Result<(), Box<dyn std::error::Error>>
{
    let output = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .args(["feasibility", "open-ai"])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("supported only on native Windows"));
    Ok(())
}
