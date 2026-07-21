//! Platform-contract tests for package-file observation.

#[cfg(not(windows))]
#[test]
fn direct_file_observation_fails_closed_off_windows() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    use weregopher_fingerprint::{ObservationError, ObservationLimits, observe_package_file};

    assert!(matches!(
        observe_package_file(
            Path::new("unused-package-file"),
            "main.js",
            ObservationLimits::new(64)?,
        ),
        Err(ObservationError::UnsupportedPlatform)
    ));
    Ok(())
}
