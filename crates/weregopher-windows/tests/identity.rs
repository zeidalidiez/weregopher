//! Windows full-width file identity tests.

#![cfg(windows)]

use std::fs::{self, File};

use tempfile::tempdir;
use weregopher_windows::FileIdentityLease;

#[test]
fn distinct_files_have_distinct_full_identities() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let first_path = root.path().join("first.bin");
    let second_path = root.path().join("second.bin");
    fs::write(&first_path, b"same bytes")?;
    fs::write(&second_path, b"same bytes")?;

    let first = FileIdentityLease::from_file(File::open(first_path)?)?;
    let second = FileIdentityLease::from_file(File::open(second_path)?)?;
    assert!(!first.has_same_identity(&second));
    Ok(())
}

#[test]
fn hard_links_share_one_full_identity() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let first_path = root.path().join("first.bin");
    let link_path = root.path().join("link.bin");
    fs::write(&first_path, b"linked")?;
    fs::hard_link(&first_path, &link_path)?;

    let first = FileIdentityLease::from_file(File::open(first_path)?)?;
    let link = FileIdentityLease::from_file(File::open(link_path)?)?;
    assert!(first.has_same_identity(&link));
    Ok(())
}
