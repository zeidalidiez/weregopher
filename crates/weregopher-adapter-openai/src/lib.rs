//! `OpenAI`-family feasibility evidence and bounded app-server prerequisites.

#![forbid(unsafe_code)]

mod app_server;
mod app_server_process;
mod app_server_proxy;
#[cfg(windows)]
mod app_server_windows;
mod package;
mod preload;
#[cfg(any(windows, test))]
mod preload_probe;
#[cfg(windows)]
mod preload_windows;

pub use app_server::{
    AppServerClientInfo, AppServerHandshakeEvidence, AppServerProtocolError,
    AppServerProtocolLimits, AppServerSchemaBundleEvidence, AppServerSchemaError,
    hash_app_server_schema_bundle, probe_app_server_handshake,
};
pub use app_server_process::{
    AppServerInitializationPhase, AppServerProcessDiagnostics, AppServerProcessError,
    AppServerProcessExitReport, AppServerProcessLimits, AppServerProcessOutcome,
    AppServerProcessPoll, AppServerProcessSession, AppServerProcessState, AppServerShutdownMode,
};
pub use app_server_proxy::{
    AppServerExpiredRequest, AppServerJsonLimits, AppServerMessageObservation,
    AppServerProxyCloseReport, AppServerProxyDiagnostics, AppServerProxyDirection,
    AppServerProxyError, AppServerProxyFrame, AppServerProxyLimits, AppServerProxyMessageKind,
    AppServerProxyState, AppServerQueueLimits, AppServerRequestId, TransparentAppServerProxy,
};
#[cfg(windows)]
pub use app_server_windows::{ExactAppServerProbeError, probe_exact_app_server};
pub use package::{
    MAX_OPENAI_PRELOAD_SOURCE_BYTES, OPENAI_APP_SERVER_PATH, OPENAI_APPLICATION_ARCHIVE_PATH,
    OPENAI_DESKTOP_ENTRY_PATH, OPENAI_WINDOWS_FAMILY, OpenAiPackageAnalysisError,
    analyze_openai_package,
};
pub use preload::{ExactPreloadPreparationError, ExactPreloadSource, prepare_exact_preload};
#[cfg(windows)]
pub use preload_windows::{ExactPreloadProbeError, probe_exact_preload};
