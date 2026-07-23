//! Windows ordinal case-key integration tests.

#![cfg(windows)]

use weregopher_windows::windows_ordinal_case_key;

#[test]
fn ordinal_case_keys_match_windows_case_insensitive_aliases()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        windows_ordinal_case_key("Node_Modules/Mód.js")?,
        windows_ordinal_case_key("node_modules/mÓD.JS")?
    );
    assert_ne!(
        windows_ordinal_case_key("node_modules/a.js")?,
        windows_ordinal_case_key("node_modules/b.js")?
    );
    Ok(())
}
