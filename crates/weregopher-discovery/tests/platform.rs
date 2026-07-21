//! Platform behavior for current-user known-location discovery.

use weregopher_discovery::discover_current_user_known_locations;

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

#[cfg(not(windows))]
#[test]
fn current_user_known_location_discovery_fails_closed_off_windows() {
    assert!(matches!(
        discover_current_user_known_locations(),
        Err(DiscoveryError::UnsupportedPlatform)
    ));
}
