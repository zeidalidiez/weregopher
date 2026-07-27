//! `OpenAI`-family target-feasibility analysis.

#![forbid(unsafe_code)]

mod app_server;
#[cfg(windows)]
mod app_server_windows;
mod package;

pub use app_server::{
    AppServerClientInfo, AppServerHandshakeEvidence, AppServerProtocolError,
    AppServerProtocolLimits, AppServerSchemaBundleEvidence, AppServerSchemaError,
    hash_app_server_schema_bundle, probe_app_server_handshake,
};
#[cfg(windows)]
pub use app_server_windows::{ExactAppServerProbeError, probe_exact_app_server};
pub use package::{
    OPENAI_APP_SERVER_PATH, OPENAI_APPLICATION_ARCHIVE_PATH, OPENAI_DESKTOP_ENTRY_PATH,
    OPENAI_WINDOWS_FAMILY, OpenAiPackageAnalysisError, analyze_openai_package,
};
