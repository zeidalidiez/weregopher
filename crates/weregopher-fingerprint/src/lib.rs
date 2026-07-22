//! Deterministic construction of package manifests from pre-observed records.

#![forbid(unsafe_code)]

mod builder;
mod classifier;
mod model;
mod observation;

pub use builder::{ManifestError, build_package_manifest};
pub use classifier::{PackageEntryType, classify_package_file};
pub use model::{
    MAX_NORMALIZED_PACKAGE_PATH_CHARS, MAX_PACKAGE_FILE_RECORDS, MAX_PACKAGE_RECORD_PATH_BYTES,
    PACKAGE_TREE_FORMAT_VERSION, PackageFileKind, PackageFileRecord, PackageTreeManifest,
};
pub use observation::{
    ObservationError, ObservationLimits, PackageFileObservation, observe_package_file,
};
