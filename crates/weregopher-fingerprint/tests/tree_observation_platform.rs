//! Non-Windows package-tree observation contract.

#![cfg(not(windows))]

use std::path::Path;

use weregopher_fingerprint::{
    PackageTreeObservationError, PackageTreeObservationLimits, observe_package_tree,
};

#[test]
fn complete_tree_observation_is_explicitly_unsupported() -> Result<(), PackageTreeObservationError>
{
    let limits = PackageTreeObservationLimits::new(1, 1, 1, 1, 1, 1)?;
    assert!(matches!(
        observe_package_tree(Path::new("/package"), limits),
        Err(PackageTreeObservationError::UnsupportedPlatform)
    ));
    Ok(())
}
