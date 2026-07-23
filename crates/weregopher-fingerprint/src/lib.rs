//! Deterministic construction of package manifests from pre-observed records.

#![forbid(unsafe_code)]

mod acquisition;
mod builder;
mod classifier;
mod model;
mod observation;

pub use acquisition::{
    MAX_PACKAGE_TREE_DEPTH, MAX_PACKAGE_TREE_DIRECTORIES, PackageFileReader,
    PackageTreeObservation, PackageTreeObservationError, PackageTreeObservationLimits,
    observe_package_tree,
};
pub use builder::{ManifestError, build_package_manifest};
pub use classifier::{PackageEntryType, classify_package_file};
pub use model::{
    MAX_NORMALIZED_PACKAGE_PATH_CHARS, MAX_NORMALIZED_PACKAGE_PATH_COMPONENTS,
    MAX_PACKAGE_FILE_RECORDS, MAX_PACKAGE_RECORD_PATH_BYTES, PACKAGE_TREE_FORMAT_VERSION,
    PackageFileKind, PackageFileRecord, PackageTreeManifest,
};
pub use observation::{
    ObservationError, ObservationLimits, PackageFileObservation, observe_package_file,
};
