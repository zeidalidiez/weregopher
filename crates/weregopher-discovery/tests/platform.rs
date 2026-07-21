//! Platform behavior for current-user known-location discovery.

use weregopher_discovery::{
    discover_current_user_candidate_evidence, discover_current_user_known_locations,
    discover_windows_package_catalog, discover_windows_uninstall_registry,
};

#[cfg(not(windows))]
use weregopher_discovery::DiscoveryError;

#[cfg(windows)]
#[test]
fn current_user_known_location_discovery_is_bounded_and_read_only()
-> Result<(), Box<dyn std::error::Error>> {
    let discovered = discover_current_user_known_locations()?;
    assert!(discovered.len() <= 5);
    Ok(())
}

#[cfg(windows)]
#[test]
fn uninstall_registry_discovery_is_bounded_and_read_only() -> Result<(), Box<dyn std::error::Error>>
{
    let discovered = discover_windows_uninstall_registry()?;
    assert!(discovered.len() <= 20);
    Ok(())
}

#[cfg(windows)]
#[test]
fn package_catalog_discovery_is_bounded_and_read_only() -> Result<(), Box<dyn std::error::Error>> {
    let discovered = discover_windows_package_catalog()?;
    assert!(discovered.len() <= 16);
    Ok(())
}

#[cfg(windows)]
#[test]
fn current_user_evidence_discovery_correlates_all_bounded_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let groups = discover_current_user_candidate_evidence()?;
    assert!(groups.len() <= 41);
    assert!(groups.iter().all(|group| !group.observations().is_empty()));
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn current_user_known_location_discovery_fails_closed_off_windows() {
    assert!(matches!(
        discover_current_user_known_locations(),
        Err(DiscoveryError::UnsupportedPlatform)
    ));
}

#[cfg(not(windows))]
#[test]
fn uninstall_registry_discovery_fails_closed_off_windows() {
    assert!(matches!(
        discover_windows_uninstall_registry(),
        Err(DiscoveryError::UnsupportedPlatform)
    ));
}

#[cfg(not(windows))]
#[test]
fn package_catalog_discovery_fails_closed_off_windows() {
    assert!(matches!(
        discover_windows_package_catalog(),
        Err(DiscoveryError::UnsupportedPlatform)
    ));
}

#[cfg(not(windows))]
#[test]
fn current_user_evidence_discovery_fails_closed_off_windows() {
    assert!(matches!(
        discover_current_user_candidate_evidence(),
        Err(DiscoveryError::UnsupportedPlatform)
    ));
}
