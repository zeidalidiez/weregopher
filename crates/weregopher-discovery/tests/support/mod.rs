//! Portable physical roots for filesystem-observation fixtures.

use std::{io, path::PathBuf};

use tempfile::TempDir;

/// Temporary directory whose exposed path has no symlink ancestors on platforms
/// where the system temporary directory may be reached through an alias.
pub struct PhysicalTempDir {
    _guard: TempDir,
    path: PathBuf,
}

impl PhysicalTempDir {
    /// Physical fixture root retained for the lifetime of the temporary directory.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// Creates a temporary fixture rooted at a physical path.
pub fn physical_tempdir() -> io::Result<PhysicalTempDir> {
    let guard = tempfile::tempdir()?;
    #[cfg(windows)]
    let path = guard.path().to_path_buf();
    #[cfg(not(windows))]
    let path = guard.path().canonicalize()?;

    Ok(PhysicalTempDir {
        _guard: guard,
        path,
    })
}
