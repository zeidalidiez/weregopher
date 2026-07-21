//! Pure package-entry classification.

use std::path::Path;

use crate::PackageFileKind;

/// Filesystem entry shape observed before content classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageEntryType {
    /// A regular file whose extension may carry package semantics.
    RegularFile,
    /// A symbolic link whose target semantics are hashed separately.
    SymbolicLink,
}

/// Classifies one normalized package path without reading the filesystem.
///
/// Symbolic links always retain link identity; regular-file extensions are
/// compared case-insensitively to match Windows package behavior.
#[must_use]
pub fn classify_package_file(
    normalized_path: &str,
    entry_type: PackageEntryType,
) -> PackageFileKind {
    if entry_type == PackageEntryType::SymbolicLink {
        return PackageFileKind::SymbolicLink;
    }

    let extension = Path::new(normalized_path)
        .extension()
        .and_then(|value| value.to_str());
    if extension.is_some_and(|value| value.eq_ignore_ascii_case("asar")) {
        PackageFileKind::Asar
    } else if extension.is_some_and(|value| value.eq_ignore_ascii_case("node")) {
        PackageFileKind::NativeModule
    } else if extension.is_some_and(|value| {
        ["exe", "dll", "com", "scr", "cpl"]
            .iter()
            .any(|candidate| value.eq_ignore_ascii_case(candidate))
    }) {
        PackageFileKind::Executable
    } else {
        PackageFileKind::Regular
    }
}
