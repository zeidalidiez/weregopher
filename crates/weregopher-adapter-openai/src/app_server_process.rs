//! Portable process-session ownership for the transparent app-server proxy.

use std::{
    fmt,
    io::{self, BufRead as _, BufReader, Read as _, Write as _},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::{
    AppServerMessageObservation, AppServerProxyCloseReport, AppServerProxyDiagnostics,
    AppServerProxyError, AppServerProxyFrame, AppServerProxyLimits, AppServerProxyMessageKind,
    AppServerRequestId, TransparentAppServerProxy,
};

const ABSOLUTE_MAX_IO_QUEUE_MESSAGES: usize = 4;
const ABSOLUTE_MAX_POLL_EVENTS: usize = 1_024;
const ABSOLUTE_MAX_INITIALIZATION_TIMEOUT: Duration = Duration::from_mins(5);
const ABSOLUTE_MAX_RUNTIME_TIMEOUT: Duration = Duration::from_hours(24);
const ABSOLUTE_MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const ABSOLUTE_MAX_EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_OBSERVATION_INTERVAL: Duration = Duration::from_millis(10);

/// Bounded worker queues and lifecycle deadlines for one attached process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerProcessLimits {
    io_queue_messages: usize,
    poll_events: usize,
    initialization_timeout: Duration,
    runtime_timeout: Duration,
    shutdown_timeout: Duration,
    exit_drain_timeout: Duration,
}

impl AppServerProcessLimits {
    /// Constructs a bounded process-session policy.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerProcessError::InvalidLimits`] for a zero dimension
    /// or a value above its fixed hard ceiling.
    pub fn new(
        io_queue_messages: usize,
        poll_events: usize,
        initialization_timeout: Duration,
        runtime_timeout: Duration,
        shutdown_timeout: Duration,
        exit_drain_timeout: Duration,
    ) -> Result<Self, AppServerProcessError> {
        if io_queue_messages == 0
            || io_queue_messages > ABSOLUTE_MAX_IO_QUEUE_MESSAGES
            || poll_events == 0
            || poll_events > ABSOLUTE_MAX_POLL_EVENTS
            || initialization_timeout.is_zero()
            || initialization_timeout > ABSOLUTE_MAX_INITIALIZATION_TIMEOUT
            || runtime_timeout.is_zero()
            || runtime_timeout > ABSOLUTE_MAX_RUNTIME_TIMEOUT
            || shutdown_timeout.is_zero()
            || shutdown_timeout > ABSOLUTE_MAX_SHUTDOWN_TIMEOUT
            || exit_drain_timeout.is_zero()
            || exit_drain_timeout > ABSOLUTE_MAX_EXIT_DRAIN_TIMEOUT
        {
            return Err(AppServerProcessError::InvalidLimits);
        }
        Ok(Self {
            io_queue_messages,
            poll_events,
            initialization_timeout,
            runtime_timeout,
            shutdown_timeout,
            exit_drain_timeout,
        })
    }

    /// Returns the initial conservative process-session policy.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            io_queue_messages: 4,
            poll_events: 64,
            initialization_timeout: Duration::from_secs(30),
            runtime_timeout: Duration::from_hours(24),
            shutdown_timeout: Duration::from_secs(2),
            exit_drain_timeout: Duration::from_secs(2),
        }
    }

    /// Returns the maximum frames retained in each process worker channel.
    #[must_use]
    pub const fn io_queue_messages(self) -> usize {
        self.io_queue_messages
    }

    /// Returns the maximum worker events consumed by one nonblocking poll.
    #[must_use]
    pub const fn max_poll_events(self) -> usize {
        self.poll_events
    }

    /// Returns the deadline for completing initialization.
    #[must_use]
    pub const fn initialization_timeout(self) -> Duration {
        self.initialization_timeout
    }

    /// Returns the maximum attached process-session lifetime.
    #[must_use]
    pub const fn runtime_timeout(self) -> Duration {
        self.runtime_timeout
    }

    /// Returns the graceful interval before forced process termination.
    #[must_use]
    pub const fn shutdown_timeout(self) -> Duration {
        self.shutdown_timeout
    }

    /// Returns the interval allowed to drain stdout after process exit.
    #[must_use]
    pub const fn exit_drain_timeout(self) -> Duration {
        self.exit_drain_timeout
    }
}

/// Visible initialization phase of one attached app-server session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerInitializationPhase {
    /// No `initialize` request has been accepted.
    AwaitingInitialize,
    /// The sole `initialize` request is queued for the process.
    InitializeQueued,
    /// The `initialize` request was released and awaits its response.
    AwaitingInitializeResponse,
    /// A successful response is queued behind the client-facing FIFO boundary.
    InitializeResponseQueued,
    /// A successful response was accepted and `initialized` is required.
    AwaitingInitialized,
    /// The sole `initialized` notification is queued for the process.
    InitializedQueued,
}

/// Public lifecycle state of one attached app-server process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerProcessState {
    /// The documented initialization sequence is incomplete.
    Initializing(AppServerInitializationPhase),
    /// Initialization completed and transparent traffic is permitted.
    Ready,
    /// Input is closed or forced process termination is underway.
    ShuttingDown,
    /// The child was reaped and proxy state was closed.
    Exited,
}

/// Caller-selected process shutdown behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerShutdownMode {
    /// Drain already-accepted client frames, close stdin, then enforce a grace deadline.
    Graceful,
    /// Request immediate primary-process termination.
    Immediate,
}

/// Payload-free terminal classification for one attached process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerProcessOutcome {
    /// A caller-requested graceful shutdown exited successfully.
    CleanShutdown,
    /// The primary process was terminated after an immediate request or grace expiry.
    ForcedShutdown,
    /// The process exited successfully without a caller shutdown request.
    UnexpectedExit,
    /// The process exited unsuccessfully without supervisor-requested termination.
    Crash,
    /// Initialization did not complete before its deadline.
    InitializationTimeout,
    /// The complete attached session reached its maximum lifetime.
    RuntimeTimeout,
    /// Initialization order or peer protocol behavior failed closed.
    ProtocolFailure,
    /// A standard-I/O worker or framing boundary failed closed.
    TransportFailure,
    /// A forwarded request exceeded its response deadline.
    RequestTimeout,
}

/// Terminal process and proxy accounting without payloads or identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerProcessExitReport {
    outcome: AppServerProcessOutcome,
    exit_code: Option<i32>,
    initialized: bool,
    stdout_bytes: u64,
    stderr_bytes: u64,
    streams_drained: bool,
    abandoned_writer_frames: usize,
    proxy_close: AppServerProxyCloseReport,
}

impl AppServerProcessExitReport {
    /// Returns the terminal lifecycle classification.
    #[must_use]
    pub const fn outcome(self) -> AppServerProcessOutcome {
        self.outcome
    }

    /// Returns the portable process exit code, when the platform supplies one.
    #[must_use]
    pub const fn exit_code(self) -> Option<i32> {
        self.exit_code
    }

    /// Reports whether `initialized` was released to the bounded stdin worker.
    #[must_use]
    pub const fn was_initialized(self) -> bool {
        self.initialized
    }

    /// Returns total bytes consumed from stdout, including JSONL delimiters.
    #[must_use]
    pub const fn stdout_bytes(self) -> u64 {
        self.stdout_bytes
    }

    /// Returns total discarded stderr bytes.
    #[must_use]
    pub const fn stderr_bytes(self) -> u64 {
        self.stderr_bytes
    }

    /// Reports whether both output workers reached EOF before the drain deadline.
    #[must_use]
    pub const fn streams_drained(self) -> bool {
        self.streams_drained
    }

    /// Returns stdin frames dispatched but not acknowledged before exit.
    #[must_use]
    pub const fn abandoned_writer_frames(self) -> usize {
        self.abandoned_writer_frames
    }

    /// Returns proxy state abandoned or cleared at terminal closure.
    #[must_use]
    pub const fn proxy_close(self) -> AppServerProxyCloseReport {
        self.proxy_close
    }
}

/// Payload-free current process, worker, and proxy observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerProcessDiagnostics {
    state: AppServerProcessState,
    proxy: AppServerProxyDiagnostics,
    dispatched_client_frames: u64,
    written_client_frames: u64,
    written_client_bytes: u64,
    writer_outstanding: usize,
    stdout_bytes: u64,
    stderr_bytes: u64,
}

impl AppServerProcessDiagnostics {
    /// Returns the current process-session lifecycle.
    #[must_use]
    pub const fn state(self) -> AppServerProcessState {
        self.state
    }

    /// Returns the underlying payload-free transparent proxy snapshot.
    #[must_use]
    pub const fn proxy(self) -> AppServerProxyDiagnostics {
        self.proxy
    }

    /// Returns frames released to the bounded stdin worker.
    #[must_use]
    pub const fn dispatched_client_frames(self) -> u64 {
        self.dispatched_client_frames
    }

    /// Returns frames fully written and flushed by the stdin worker.
    #[must_use]
    pub const fn written_client_frames(self) -> u64 {
        self.written_client_frames
    }

    /// Returns delimiter-free client JSON bytes fully written.
    #[must_use]
    pub const fn written_client_bytes(self) -> u64 {
        self.written_client_bytes
    }

    /// Returns frames released but not yet acknowledged by the writer.
    #[must_use]
    pub const fn writer_outstanding(self) -> usize {
        self.writer_outstanding
    }

    /// Returns bytes consumed from stdout, including delimiters.
    #[must_use]
    pub const fn stdout_bytes(self) -> u64 {
        self.stdout_bytes
    }

    /// Returns bytes discarded from stderr.
    #[must_use]
    pub const fn stderr_bytes(self) -> u64 {
        self.stderr_bytes
    }
}

/// Bounded work completed by one nonblocking session poll.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AppServerProcessPoll {
    server_messages: usize,
    dispatched_client_frames: usize,
    written_client_frames: usize,
    expired_requests: usize,
}

impl AppServerProcessPoll {
    /// Returns server lines validated and admitted during this poll.
    #[must_use]
    pub const fn server_messages(self) -> usize {
        self.server_messages
    }

    /// Returns client frames handed to the stdin worker during this poll.
    #[must_use]
    pub const fn dispatched_client_frames(self) -> usize {
        self.dispatched_client_frames
    }

    /// Returns stdin write acknowledgements consumed during this poll.
    #[must_use]
    pub const fn written_client_frames(self) -> usize {
        self.written_client_frames
    }

    /// Returns request deadlines observed during this poll.
    #[must_use]
    pub const fn expired_requests(self) -> usize {
        self.expired_requests
    }
}

/// Process-session construction, protocol, worker, or lifecycle failure.
#[derive(Debug, Error)]
pub enum AppServerProcessError {
    /// A process-session resource dimension was invalid.
    #[error("invalid app-server process-session limits")]
    InvalidLimits,
    /// A configured lifecycle deadline overflowed the monotonic clock.
    #[error("app-server process-session deadline overflowed")]
    DeadlineOverflow,
    /// The attached child did not expose all three required piped streams.
    #[error("app-server process-session requires piped stdin, stdout, and stderr")]
    MissingPipedStdio,
    /// A bounded worker thread could not be created.
    #[error("app-server {worker} worker could not start: {kind:?}")]
    WorkerSpawn {
        /// Sanitized worker role.
        worker: &'static str,
        /// Platform I/O error class without path or payload context.
        kind: io::ErrorKind,
    },
    /// Client traffic contradicted the required initialization sequence.
    #[error("app-server client message violates initialization ordering")]
    InitializationSequenceViolation,
    /// The app-server rejected its initialize request.
    #[error("app-server rejected initialization")]
    InitializeRejected,
    /// Server traffic contradicted the required initialization sequence.
    #[error("app-server server message violates initialization ordering")]
    UnexpectedServerInitializationMessage,
    /// One stdout line exceeded the proxy line ceiling before retention.
    #[error("app-server stdout JSONL line exceeds its byte limit")]
    StdoutLineTooLarge,
    /// Stdout ended with a nonempty record lacking a JSONL delimiter.
    #[error("app-server stdout ended with an unterminated JSONL record")]
    UnterminatedStdoutLine,
    /// Stdout reached EOF while the primary process remained live.
    #[error("app-server stdout closed before the primary process exited")]
    StdoutClosedBeforeExit,
    /// A bounded line buffer could not reserve its validated capacity.
    #[error("app-server stdout bounded allocation failed")]
    StdoutAllocationFailed,
    /// A standard-I/O or process worker failed.
    #[error("app-server {worker} worker failed: {kind:?}")]
    WorkerIo {
        /// Sanitized worker role.
        worker: &'static str,
        /// Platform I/O error class without raw stream content.
        kind: io::ErrorKind,
    },
    /// A worker channel closed before its terminal event.
    #[error("app-server {worker} worker disconnected unexpectedly")]
    WorkerDisconnected {
        /// Sanitized worker role.
        worker: &'static str,
    },
    /// The caller attempted traffic after shutdown began.
    #[error("app-server process-session is not accepting client traffic")]
    NotRunning,
    /// A caller supplied a monotonic time earlier than prior session work.
    #[error("app-server process-session monotonic clock moved backward")]
    NonMonotonicClock,
    /// A payload-free diagnostic counter overflowed.
    #[error("app-server process-session diagnostic counter overflowed")]
    DiagnosticCounterOverflow,
    /// The transparent framing/correlation core rejected a transition.
    #[error(transparent)]
    Proxy(#[from] AppServerProxyError),
}

#[derive(Clone)]
enum InitializationState {
    AwaitingInitialize,
    InitializeQueued(AppServerRequestId),
    AwaitingInitializeResponse(AppServerRequestId),
    InitializeResponseQueued(AppServerRequestId),
    AwaitingInitialized,
    InitializedQueued,
    Ready,
}

enum LifecycleState {
    Running,
    GracefulShutdown { deadline: Instant },
    Terminating,
    Exited,
}

enum WriterCommand {
    Frame(AppServerProxyFrame),
    Close,
}

enum WriterEvent {
    Written { bytes: usize },
    Closed,
    Failed(io::ErrorKind),
}

enum ReaderEvent {
    Line(Vec<u8>),
    Eof,
    LineTooLarge,
    UnterminatedLine,
    AllocationFailed,
    Failed(io::ErrorKind),
}

enum StderrEvent {
    Eof,
    Failed(io::ErrorKind),
}

enum ProcessCommand {
    Terminate,
}

struct ProcessExit {
    success: bool,
    code: Option<i32>,
}

enum ProcessEvent {
    Exited(ProcessExit),
    Failed(io::ErrorKind),
}

/// Single-owner nonblocking session around an already-launched piped child.
///
/// This type does not authorize or launch an executable and does not establish
/// an OS sandbox. The attached process is unrestricted same-user code unless a
/// separately tested platform owner supplied stronger lifecycle boundaries.
/// Dedicated bounded workers own standard I/O and process reaping so
/// [`Self::poll`] never waits for pipe or process completion.
pub struct AppServerProcessSession {
    limits: AppServerProcessLimits,
    proxy: TransparentAppServerProxy,
    initialization: InitializationState,
    lifecycle: LifecycleState,
    initialization_deadline: Instant,
    runtime_deadline: Instant,
    last_observed_time: Instant,
    writer_tx: Option<SyncSender<WriterCommand>>,
    writer_rx: Receiver<WriterEvent>,
    reader_rx: Receiver<ReaderEvent>,
    stderr_rx: Receiver<StderrEvent>,
    process_tx: Option<SyncSender<ProcessCommand>>,
    process_rx: Receiver<ProcessEvent>,
    writer_worker: Option<JoinHandle<()>>,
    reader_worker: Option<JoinHandle<()>>,
    stderr_worker: Option<JoinHandle<()>>,
    process_worker: Option<JoinHandle<()>>,
    writer_outstanding: usize,
    writer_close_requested: bool,
    stdout_finished: bool,
    stdout_without_exit_deadline: Option<Instant>,
    stderr_finished: bool,
    process_exit: Option<ProcessExit>,
    process_exit_deadline: Option<Instant>,
    requested_outcome: Option<AppServerProcessOutcome>,
    dispatched_client_frames: u64,
    written_client_frames: u64,
    written_client_bytes: u64,
    stdout_bytes: Arc<AtomicU64>,
    stderr_bytes: Arc<AtomicU64>,
    exit_report: Option<AppServerProcessExitReport>,
}

impl fmt::Debug for AppServerProcessSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerProcessSession")
            .field("limits", &self.limits)
            .field("diagnostics", &self.diagnostics())
            .field("has_exit_report", &self.exit_report.is_some())
            .finish_non_exhaustive()
    }
}

impl AppServerProcessSession {
    /// Attaches to an already-launched child with piped stdin/stdout/stderr.
    ///
    /// The method takes ownership of the process and streams. The child is
    /// terminated if required stream ownership or worker creation fails.
    /// "Unverified" is intentional: executable identity, launch authority, Job
    /// ownership, disposable state, and sandbox posture remain caller evidence.
    ///
    /// # Errors
    ///
    /// Returns an explicit stdio, deadline, or worker-construction failure.
    pub fn attach_unverified_child(
        mut child: Child,
        proxy_limits: AppServerProxyLimits,
        limits: AppServerProcessLimits,
        now: Instant,
    ) -> Result<Self, AppServerProcessError> {
        let Some(initialization_deadline) = now.checked_add(limits.initialization_timeout) else {
            terminate_child(&mut child);
            return Err(AppServerProcessError::DeadlineOverflow);
        };
        let Some(runtime_deadline) = now.checked_add(limits.runtime_timeout) else {
            terminate_child(&mut child);
            return Err(AppServerProcessError::DeadlineOverflow);
        };
        let (stdin, stdout, stderr) = take_piped_stdio(&mut child)?;

        let (process_tx, process_command_rx) = sync_channel(1);
        let (process_event_tx, process_rx) = sync_channel(1);
        let shared_child = Arc::new(Mutex::new(Some(child)));
        let process_child = Arc::clone(&shared_child);
        let process_worker = match thread::Builder::new()
            .name("weregopher-app-server-process".to_owned())
            .spawn(move || {
                process_worker(&process_child, &process_command_rx, &process_event_tx);
            }) {
            Ok(worker) => worker,
            Err(source) => {
                terminate_shared_child(&shared_child);
                return Err(AppServerProcessError::WorkerSpawn {
                    worker: "process",
                    kind: source.kind(),
                });
            }
        };

        let (writer_tx, writer_command_rx) = sync_channel(limits.io_queue_messages);
        let (writer_event_tx, writer_rx) = sync_channel(limits.io_queue_messages);
        let writer_worker = match spawn_worker("weregopher-app-server-stdin", move || {
            writer_worker(stdin, &writer_command_rx, &writer_event_tx);
        }) {
            Ok(worker) => worker,
            Err(error) => {
                request_process_termination(&process_tx);
                return Err(error);
            }
        };

        let stdout_bytes = Arc::new(AtomicU64::new(0));
        let reader_bytes = Arc::clone(&stdout_bytes);
        let (reader_event_tx, reader_rx) = sync_channel(limits.io_queue_messages);
        let max_line_bytes = proxy_limits.max_line_bytes();
        let reader_worker = match spawn_worker("weregopher-app-server-stdout", move || {
            reader_worker(stdout, max_line_bytes, &reader_bytes, &reader_event_tx);
        }) {
            Ok(worker) => worker,
            Err(error) => {
                request_process_termination(&process_tx);
                drop(writer_tx);
                return Err(error);
            }
        };

        let stderr_bytes = Arc::new(AtomicU64::new(0));
        let drain_bytes = Arc::clone(&stderr_bytes);
        let (stderr_event_tx, stderr_rx) = sync_channel(1);
        let stderr_worker = match spawn_worker("weregopher-app-server-stderr", move || {
            stderr_worker(stderr, &drain_bytes, &stderr_event_tx);
        }) {
            Ok(worker) => worker,
            Err(error) => {
                request_process_termination(&process_tx);
                drop(writer_tx);
                return Err(error);
            }
        };
        drop(shared_child);

        Ok(Self {
            limits,
            proxy: TransparentAppServerProxy::new(proxy_limits),
            initialization: InitializationState::AwaitingInitialize,
            lifecycle: LifecycleState::Running,
            initialization_deadline,
            runtime_deadline,
            last_observed_time: now,
            writer_tx: Some(writer_tx),
            writer_rx,
            reader_rx,
            stderr_rx,
            process_tx: Some(process_tx),
            process_rx,
            writer_worker: Some(writer_worker),
            reader_worker: Some(reader_worker),
            stderr_worker: Some(stderr_worker),
            process_worker: Some(process_worker),
            writer_outstanding: 0,
            writer_close_requested: false,
            stdout_finished: false,
            stdout_without_exit_deadline: None,
            stderr_finished: false,
            process_exit: None,
            process_exit_deadline: None,
            requested_outcome: None,
            dispatched_client_frames: 0,
            written_client_frames: 0,
            written_client_bytes: 0,
            stdout_bytes,
            stderr_bytes,
            exit_report: None,
        })
    }

    /// Validates and queues one exact client JSON line.
    ///
    /// Before readiness, only one `initialize` request followed by one
    /// `initialized` notification is accepted. An ordering violation is
    /// terminal because the validated frame was already admitted atomically to
    /// the underlying proxy.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, initialization-order, or proxy boundary error.
    pub fn send_client(
        &mut self,
        json_line: &[u8],
    ) -> Result<AppServerMessageObservation, AppServerProcessError> {
        if !matches!(self.lifecycle, LifecycleState::Running) {
            return Err(AppServerProcessError::NotRunning);
        }
        let observation = self.proxy.ingest_client(json_line)?;
        let next = match &self.initialization {
            InitializationState::AwaitingInitialize
                if observation.kind() == AppServerProxyMessageKind::Request
                    && observation.method() == Some("initialize") =>
            {
                observation
                    .request_id()
                    .cloned()
                    .map(InitializationState::InitializeQueued)
            }
            InitializationState::AwaitingInitialized
                if observation.kind() == AppServerProxyMessageKind::Notification
                    && observation.method() == Some("initialized") =>
            {
                Some(InitializationState::InitializedQueued)
            }
            InitializationState::Ready
                if !matches!(observation.method(), Some("initialize" | "initialized")) =>
            {
                Some(InitializationState::Ready)
            }
            InitializationState::AwaitingInitialize
            | InitializationState::InitializeQueued(_)
            | InitializationState::AwaitingInitializeResponse(_)
            | InitializationState::InitializeResponseQueued(_)
            | InitializationState::AwaitingInitialized
            | InitializationState::InitializedQueued
            | InitializationState::Ready => None,
        };
        let Some(next) = next else {
            self.begin_termination(AppServerProcessOutcome::ProtocolFailure);
            return Err(AppServerProcessError::InitializationSequenceViolation);
        };
        self.initialization = next;
        Ok(observation)
    }

    /// Consumes bounded worker events and advances process/session state without
    /// waiting for pipe or process completion.
    ///
    /// # Errors
    ///
    /// Returns an explicit proxy, protocol, worker, framing, or monotonic-clock
    /// failure. Fatal peer/worker failures also begin process termination.
    pub fn poll(&mut self, now: Instant) -> Result<AppServerProcessPoll, AppServerProcessError> {
        self.ensure_monotonic(now)?;
        self.last_observed_time = now;
        if matches!(self.lifecycle, LifecycleState::Exited) {
            return Ok(AppServerProcessPoll::default());
        }

        let mut progress = AppServerProcessPoll::default();
        self.consume_process_event(now)?;
        self.consume_writer_events(&mut progress)?;
        self.consume_stderr_event()?;
        self.consume_reader_events(now, &mut progress)?;
        self.advance_stream_closure(now)?;

        let expired = if self.process_exit.is_none()
            && !matches!(self.lifecycle, LifecycleState::Terminating)
        {
            self.proxy.expire_requests(now)?
        } else {
            Vec::new()
        };
        progress.expired_requests = expired.len();
        if !expired.is_empty() {
            self.begin_termination(AppServerProcessOutcome::RequestTimeout);
        }

        self.dispatch_client_frames(now, &mut progress)?;
        self.advance_shutdown(now)?;
        self.advance_deadlines(now);
        self.finish_process_exit(now);
        self.join_finished_workers();
        Ok(progress)
    }

    /// Releases the next exact server frame toward the packaged client.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, monotonic-clock, or proxy transition error.
    pub fn next_for_client(
        &mut self,
        now: Instant,
    ) -> Result<Option<AppServerProxyFrame>, AppServerProcessError> {
        self.ensure_monotonic(now)?;
        if matches!(self.lifecycle, LifecycleState::Exited) {
            self.last_observed_time = now;
            return Ok(None);
        }
        let frame = self.proxy.next_for_client(now)?;
        if let Some(frame) = frame.as_ref() {
            self.observe_client_delivery(frame)?;
        }
        self.last_observed_time = now;
        Ok(frame)
    }

    /// Begins graceful or immediate shutdown.
    ///
    /// Graceful mode stops accepting new client input, drains already-admitted
    /// frames, closes stdin, and requests termination at the configured grace
    /// deadline. Immediate mode requests primary-process termination now.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, deadline, or monotonic-clock failure.
    pub fn shutdown(
        &mut self,
        mode: AppServerShutdownMode,
        now: Instant,
    ) -> Result<(), AppServerProcessError> {
        self.ensure_monotonic(now)?;
        if matches!(self.lifecycle, LifecycleState::Exited) {
            self.last_observed_time = now;
            return Ok(());
        }
        match mode {
            AppServerShutdownMode::Graceful => {
                if matches!(self.lifecycle, LifecycleState::Running) {
                    let deadline = now
                        .checked_add(self.limits.shutdown_timeout)
                        .ok_or(AppServerProcessError::DeadlineOverflow)?;
                    self.lifecycle = LifecycleState::GracefulShutdown { deadline };
                }
            }
            AppServerShutdownMode::Immediate => {
                self.begin_termination(AppServerProcessOutcome::ForcedShutdown);
            }
        }
        self.last_observed_time = now;
        Ok(())
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> AppServerProcessState {
        match self.lifecycle {
            LifecycleState::GracefulShutdown { .. } | LifecycleState::Terminating => {
                AppServerProcessState::ShuttingDown
            }
            LifecycleState::Exited => AppServerProcessState::Exited,
            LifecycleState::Running => match self.initialization {
                InitializationState::AwaitingInitialize => AppServerProcessState::Initializing(
                    AppServerInitializationPhase::AwaitingInitialize,
                ),
                InitializationState::InitializeQueued(_) => AppServerProcessState::Initializing(
                    AppServerInitializationPhase::InitializeQueued,
                ),
                InitializationState::AwaitingInitializeResponse(_) => {
                    AppServerProcessState::Initializing(
                        AppServerInitializationPhase::AwaitingInitializeResponse,
                    )
                }
                InitializationState::InitializeResponseQueued(_) => {
                    AppServerProcessState::Initializing(
                        AppServerInitializationPhase::InitializeResponseQueued,
                    )
                }
                InitializationState::AwaitingInitialized => AppServerProcessState::Initializing(
                    AppServerInitializationPhase::AwaitingInitialized,
                ),
                InitializationState::InitializedQueued => AppServerProcessState::Initializing(
                    AppServerInitializationPhase::InitializedQueued,
                ),
                InitializationState::Ready => AppServerProcessState::Ready,
            },
        }
    }

    /// Returns payload-free process, worker, and proxy observations.
    #[must_use]
    pub fn diagnostics(&self) -> AppServerProcessDiagnostics {
        AppServerProcessDiagnostics {
            state: self.state(),
            proxy: self.proxy.diagnostics(),
            dispatched_client_frames: self.dispatched_client_frames,
            written_client_frames: self.written_client_frames,
            written_client_bytes: self.written_client_bytes,
            writer_outstanding: self.writer_outstanding,
            stdout_bytes: self.stdout_bytes.load(Ordering::Relaxed),
            stderr_bytes: self.stderr_bytes.load(Ordering::Relaxed),
        }
    }

    /// Returns terminal accounting after process reaping and proxy closure.
    #[must_use]
    pub const fn exit_report(&self) -> Option<AppServerProcessExitReport> {
        self.exit_report
    }

    fn consume_writer_events(
        &mut self,
        progress: &mut AppServerProcessPoll,
    ) -> Result<(), AppServerProcessError> {
        for _ in 0..self.limits.poll_events {
            match self.writer_rx.try_recv() {
                Ok(WriterEvent::Written { bytes }) => {
                    self.writer_outstanding = self
                        .writer_outstanding
                        .checked_sub(1)
                        .ok_or(AppServerProcessError::DiagnosticCounterOverflow)?;
                    self.written_client_frames = increment(self.written_client_frames)?;
                    self.written_client_bytes = add_usize(self.written_client_bytes, bytes)?;
                    progress.written_client_frames = progress
                        .written_client_frames
                        .checked_add(1)
                        .ok_or(AppServerProcessError::DiagnosticCounterOverflow)?;
                }
                Ok(WriterEvent::Closed) => {
                    self.writer_close_requested = true;
                    break;
                }
                Ok(WriterEvent::Failed(kind)) => {
                    self.writer_close_requested = true;
                    if self.process_exit.is_some() {
                        break;
                    }
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::WorkerIo {
                        worker: "stdin",
                        kind,
                    });
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) if self.writer_close_requested => break,
                Err(TryRecvError::Disconnected) => {
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::WorkerDisconnected { worker: "stdin" });
                }
            }
        }
        Ok(())
    }

    fn consume_stderr_event(&mut self) -> Result<(), AppServerProcessError> {
        if self.stderr_finished {
            return Ok(());
        }
        match self.stderr_rx.try_recv() {
            Ok(StderrEvent::Eof) => {
                self.stderr_finished = true;
                Ok(())
            }
            Ok(StderrEvent::Failed(kind)) => {
                self.stderr_finished = true;
                self.begin_termination(AppServerProcessOutcome::TransportFailure);
                Err(AppServerProcessError::WorkerIo {
                    worker: "stderr",
                    kind,
                })
            }
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => {
                self.stderr_finished = true;
                self.begin_termination(AppServerProcessOutcome::TransportFailure);
                Err(AppServerProcessError::WorkerDisconnected { worker: "stderr" })
            }
        }
    }

    fn consume_reader_events(
        &mut self,
        now: Instant,
        progress: &mut AppServerProcessPoll,
    ) -> Result<(), AppServerProcessError> {
        if self.stdout_finished {
            return Ok(());
        }
        for _ in 0..self.limits.poll_events {
            match self.reader_rx.try_recv() {
                Ok(ReaderEvent::Line(line)) => {
                    let observation = match self.proxy.ingest_server(&line) {
                        Ok(observation) => observation,
                        Err(error) => {
                            self.begin_termination(AppServerProcessOutcome::ProtocolFailure);
                            return Err(error.into());
                        }
                    };
                    if let Err(error) = self.observe_server_initialization(&observation) {
                        self.begin_termination(AppServerProcessOutcome::ProtocolFailure);
                        return Err(error);
                    }
                    progress.server_messages = progress
                        .server_messages
                        .checked_add(1)
                        .ok_or(AppServerProcessError::DiagnosticCounterOverflow)?;
                }
                Ok(ReaderEvent::Eof) => {
                    self.stdout_finished = true;
                    let Some(deadline) = now.checked_add(self.limits.exit_drain_timeout) else {
                        self.begin_termination(AppServerProcessOutcome::TransportFailure);
                        return Err(AppServerProcessError::DeadlineOverflow);
                    };
                    self.stdout_without_exit_deadline = Some(deadline);
                    break;
                }
                Ok(ReaderEvent::LineTooLarge) => {
                    self.stdout_finished = true;
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::StdoutLineTooLarge);
                }
                Ok(ReaderEvent::UnterminatedLine) => {
                    self.stdout_finished = true;
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::UnterminatedStdoutLine);
                }
                Ok(ReaderEvent::AllocationFailed) => {
                    self.stdout_finished = true;
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::StdoutAllocationFailed);
                }
                Ok(ReaderEvent::Failed(kind)) => {
                    self.stdout_finished = true;
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::WorkerIo {
                        worker: "stdout",
                        kind,
                    });
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) if self.stdout_finished => break,
                Err(TryRecvError::Disconnected) => {
                    self.stdout_finished = true;
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::WorkerDisconnected { worker: "stdout" });
                }
            }
        }
        Ok(())
    }

    fn observe_server_initialization(
        &mut self,
        observation: &AppServerMessageObservation,
    ) -> Result<(), AppServerProcessError> {
        if matches!(self.initialization, InitializationState::Ready)
            || matches!(self.lifecycle, LifecycleState::Terminating)
        {
            return Ok(());
        }
        if observation.kind() == AppServerProxyMessageKind::Notification {
            return Ok(());
        }
        let InitializationState::AwaitingInitializeResponse(expected_id) = &self.initialization
        else {
            return Err(AppServerProcessError::UnexpectedServerInitializationMessage);
        };
        if observation.request_id() != Some(expected_id) {
            return Err(AppServerProcessError::UnexpectedServerInitializationMessage);
        }
        match observation.kind() {
            AppServerProxyMessageKind::SuccessResponse => {
                self.initialization =
                    InitializationState::InitializeResponseQueued(expected_id.clone());
                Ok(())
            }
            AppServerProxyMessageKind::ErrorResponse => {
                Err(AppServerProcessError::InitializeRejected)
            }
            AppServerProxyMessageKind::Request | AppServerProxyMessageKind::Notification => {
                Err(AppServerProcessError::UnexpectedServerInitializationMessage)
            }
        }
    }

    fn consume_process_event(&mut self, now: Instant) -> Result<(), AppServerProcessError> {
        if self.process_exit.is_some() {
            return Ok(());
        }
        match self.process_rx.try_recv() {
            Ok(ProcessEvent::Exited(exit)) => {
                self.process_exit = Some(exit);
                self.stdout_without_exit_deadline = None;
                if let Some(deadline) = now.checked_add(self.limits.exit_drain_timeout) {
                    self.process_exit_deadline = Some(deadline);
                    Ok(())
                } else {
                    self.process_exit_deadline = Some(now);
                    Err(AppServerProcessError::DeadlineOverflow)
                }
            }
            Ok(ProcessEvent::Failed(kind)) => {
                self.begin_termination(AppServerProcessOutcome::TransportFailure);
                Err(AppServerProcessError::WorkerIo {
                    worker: "process",
                    kind,
                })
            }
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => {
                self.begin_termination(AppServerProcessOutcome::TransportFailure);
                Err(AppServerProcessError::WorkerDisconnected { worker: "process" })
            }
        }
    }

    fn advance_stream_closure(&mut self, now: Instant) -> Result<(), AppServerProcessError> {
        if self.process_exit.is_none()
            && matches!(
                self.lifecycle,
                LifecycleState::Running | LifecycleState::GracefulShutdown { .. }
            )
            && self
                .stdout_without_exit_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            self.begin_termination(AppServerProcessOutcome::TransportFailure);
            return Err(AppServerProcessError::StdoutClosedBeforeExit);
        }
        Ok(())
    }

    fn dispatch_client_frames(
        &mut self,
        now: Instant,
        progress: &mut AppServerProcessPoll,
    ) -> Result<(), AppServerProcessError> {
        if matches!(
            self.lifecycle,
            LifecycleState::Terminating | LifecycleState::Exited
        ) || self.writer_close_requested
        {
            return Ok(());
        }
        while self.writer_outstanding < self.limits.io_queue_messages
            && progress.dispatched_client_frames < self.limits.poll_events
        {
            let Some(frame) = self.proxy.next_for_server(now)? else {
                break;
            };
            self.observe_dispatched_frame(&frame)?;
            let Some(writer) = self.writer_tx.as_ref() else {
                self.begin_termination(AppServerProcessOutcome::TransportFailure);
                return Err(AppServerProcessError::WorkerDisconnected { worker: "stdin" });
            };
            match writer.try_send(WriterCommand::Frame(frame)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::WorkerDisconnected {
                        worker: "stdin-capacity",
                    });
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::WorkerDisconnected { worker: "stdin" });
                }
            }
            self.writer_outstanding = self
                .writer_outstanding
                .checked_add(1)
                .ok_or(AppServerProcessError::DiagnosticCounterOverflow)?;
            self.dispatched_client_frames = increment(self.dispatched_client_frames)?;
            progress.dispatched_client_frames = progress
                .dispatched_client_frames
                .checked_add(1)
                .ok_or(AppServerProcessError::DiagnosticCounterOverflow)?;
        }
        Ok(())
    }

    fn observe_dispatched_frame(
        &mut self,
        frame: &AppServerProxyFrame,
    ) -> Result<(), AppServerProcessError> {
        match &self.initialization {
            InitializationState::InitializeQueued(request_id)
                if frame.observation().kind() == AppServerProxyMessageKind::Request
                    && frame.observation().method() == Some("initialize")
                    && frame.observation().request_id() == Some(request_id) =>
            {
                self.initialization =
                    InitializationState::AwaitingInitializeResponse(request_id.clone());
                Ok(())
            }
            InitializationState::InitializedQueued
                if frame.observation().kind() == AppServerProxyMessageKind::Notification
                    && frame.observation().method() == Some("initialized") =>
            {
                self.initialization = InitializationState::Ready;
                Ok(())
            }
            InitializationState::Ready => Ok(()),
            InitializationState::AwaitingInitialize
            | InitializationState::InitializeQueued(_)
            | InitializationState::AwaitingInitializeResponse(_)
            | InitializationState::InitializeResponseQueued(_)
            | InitializationState::AwaitingInitialized
            | InitializationState::InitializedQueued => {
                self.begin_termination(AppServerProcessOutcome::ProtocolFailure);
                Err(AppServerProcessError::InitializationSequenceViolation)
            }
        }
    }

    fn observe_client_delivery(
        &mut self,
        frame: &AppServerProxyFrame,
    ) -> Result<(), AppServerProcessError> {
        let InitializationState::InitializeResponseQueued(expected_id) = &self.initialization
        else {
            return Ok(());
        };
        if frame.observation().kind() == AppServerProxyMessageKind::SuccessResponse
            && frame.observation().request_id() == Some(expected_id)
        {
            self.initialization = InitializationState::AwaitingInitialized;
            Ok(())
        } else if frame.observation().kind() == AppServerProxyMessageKind::Notification {
            Ok(())
        } else {
            self.begin_termination(AppServerProcessOutcome::ProtocolFailure);
            Err(AppServerProcessError::UnexpectedServerInitializationMessage)
        }
    }

    fn advance_shutdown(&mut self, now: Instant) -> Result<(), AppServerProcessError> {
        let LifecycleState::GracefulShutdown { deadline } = self.lifecycle else {
            return Ok(());
        };
        if self.process_exit.is_some() {
            return Ok(());
        }
        if now >= deadline {
            self.begin_termination(AppServerProcessOutcome::ForcedShutdown);
            return Ok(());
        }
        if self.proxy.diagnostics().queued_to_server_messages() == 0
            && self.writer_outstanding == 0
            && !self.writer_close_requested
        {
            let Some(writer) = self.writer_tx.take() else {
                self.begin_termination(AppServerProcessOutcome::TransportFailure);
                return Err(AppServerProcessError::WorkerDisconnected { worker: "stdin" });
            };
            match writer.try_send(WriterCommand::Close) {
                Ok(()) => {
                    self.writer_close_requested = true;
                }
                Err(TrySendError::Full(_)) => {
                    self.writer_tx = Some(writer);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.begin_termination(AppServerProcessOutcome::TransportFailure);
                    return Err(AppServerProcessError::WorkerDisconnected { worker: "stdin" });
                }
            }
        }
        Ok(())
    }

    fn advance_deadlines(&mut self, now: Instant) {
        if !matches!(self.lifecycle, LifecycleState::Running) || self.process_exit.is_some() {
            return;
        }
        if !matches!(self.initialization, InitializationState::Ready)
            && now >= self.initialization_deadline
        {
            self.begin_termination(AppServerProcessOutcome::InitializationTimeout);
        } else if now >= self.runtime_deadline {
            self.begin_termination(AppServerProcessOutcome::RuntimeTimeout);
        }
    }

    fn finish_process_exit(&mut self, now: Instant) {
        let Some(exit) = self.process_exit.as_ref() else {
            return;
        };
        let drain_expired = self
            .process_exit_deadline
            .is_some_and(|deadline| now >= deadline);
        let streams_drained = self.stdout_finished && self.stderr_finished;
        if !streams_drained && !drain_expired {
            return;
        }
        let mut outcome = match self.requested_outcome {
            Some(outcome) => outcome,
            None if matches!(self.lifecycle, LifecycleState::GracefulShutdown { .. })
                && exit.success =>
            {
                AppServerProcessOutcome::CleanShutdown
            }
            None if exit.success => AppServerProcessOutcome::UnexpectedExit,
            None => AppServerProcessOutcome::Crash,
        };
        if !streams_drained
            && matches!(
                outcome,
                AppServerProcessOutcome::CleanShutdown | AppServerProcessOutcome::UnexpectedExit
            )
        {
            outcome = AppServerProcessOutcome::TransportFailure;
        }
        let initialized = matches!(self.initialization, InitializationState::Ready);
        let close = self.proxy.close();
        self.initialization = InitializationState::AwaitingInitialize;
        let (_reader_sender, empty_reader) = sync_channel(1);
        self.reader_rx = empty_reader;
        self.exit_report = Some(AppServerProcessExitReport {
            outcome,
            exit_code: exit.code,
            initialized,
            stdout_bytes: self.stdout_bytes.load(Ordering::Relaxed),
            stderr_bytes: self.stderr_bytes.load(Ordering::Relaxed),
            streams_drained,
            abandoned_writer_frames: self.writer_outstanding,
            proxy_close: close,
        });
        self.lifecycle = LifecycleState::Exited;
        self.writer_tx.take();
        self.process_tx.take();
    }

    fn begin_termination(&mut self, outcome: AppServerProcessOutcome) {
        if matches!(self.lifecycle, LifecycleState::Exited) {
            return;
        }
        if self.requested_outcome.is_none() {
            self.requested_outcome = Some(outcome);
        }
        self.lifecycle = LifecycleState::Terminating;
        self.writer_close_requested = true;
        self.writer_tx.take();
        if let Some(process) = self.process_tx.as_ref() {
            request_process_termination(process);
        }
    }

    fn ensure_monotonic(&self, now: Instant) -> Result<(), AppServerProcessError> {
        if now < self.last_observed_time {
            Err(AppServerProcessError::NonMonotonicClock)
        } else {
            Ok(())
        }
    }

    fn join_finished_workers(&mut self) {
        join_if_finished(&mut self.writer_worker);
        join_if_finished(&mut self.reader_worker);
        join_if_finished(&mut self.stderr_worker);
        join_if_finished(&mut self.process_worker);
    }
}

impl Drop for AppServerProcessSession {
    fn drop(&mut self) {
        self.proxy.close();
        self.writer_tx.take();
        if let Some(process) = self.process_tx.take() {
            request_process_termination(&process);
        }
        self.join_finished_workers();
    }
}

fn take_piped_stdio(
    child: &mut Child,
) -> Result<(ChildStdin, ChildStdout, ChildStderr), AppServerProcessError> {
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
        terminate_child(child);
        return Err(AppServerProcessError::MissingPipedStdio);
    };
    Ok((stdin, stdout, stderr))
}

fn spawn_worker(
    name: &'static str,
    work: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>, AppServerProcessError> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(work)
        .map_err(|source| AppServerProcessError::WorkerSpawn {
            worker: name,
            kind: source.kind(),
        })
}

fn writer_worker(
    mut stdin: ChildStdin,
    commands: &Receiver<WriterCommand>,
    events: &SyncSender<WriterEvent>,
) {
    while let Ok(command) = commands.recv() {
        match command {
            WriterCommand::Frame(frame) => {
                let result = stdin
                    .write_all(frame.json_bytes())
                    .and_then(|()| stdin.write_all(b"\n"))
                    .and_then(|()| stdin.flush());
                if let Err(source) = result {
                    let _ = events.send(WriterEvent::Failed(source.kind()));
                    return;
                }
                if events
                    .send(WriterEvent::Written {
                        bytes: frame.json_bytes().len(),
                    })
                    .is_err()
                {
                    return;
                }
            }
            WriterCommand::Close => {
                let _ = events.send(WriterEvent::Closed);
                return;
            }
        }
    }
}

fn reader_worker(
    stdout: ChildStdout,
    max_line_bytes: usize,
    observed_bytes: &Arc<AtomicU64>,
    events: &SyncSender<ReaderEvent>,
) {
    let mut reader = BufReader::with_capacity(8 * 1_024, stdout);
    let mut line = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(source) => {
                let _ = events.send(ReaderEvent::Failed(source.kind()));
                return;
            }
        };
        if available.is_empty() {
            let event = if line.is_empty() {
                ReaderEvent::Eof
            } else {
                ReaderEvent::UnterminatedLine
            };
            let _ = events.send(event);
            return;
        }
        let delimiter = available.iter().position(|byte| *byte == b'\n');
        let consumed = delimiter.map_or(available.len(), |position| position + 1);
        add_atomic(observed_bytes, consumed);
        let content = delimiter.unwrap_or(available.len());
        let Some(next_length) = line.len().checked_add(content) else {
            let _ = events.send(ReaderEvent::LineTooLarge);
            return;
        };
        if next_length > max_line_bytes {
            let _ = events.send(ReaderEvent::LineTooLarge);
            return;
        }
        if line.try_reserve_exact(content).is_err() {
            let _ = events.send(ReaderEvent::AllocationFailed);
            return;
        }
        line.extend_from_slice(&available[..content]);
        reader.consume(consumed);
        if delimiter.is_some()
            && events
                .send(ReaderEvent::Line(std::mem::take(&mut line)))
                .is_err()
        {
            return;
        }
    }
}

fn stderr_worker(
    mut stderr: ChildStderr,
    observed_bytes: &Arc<AtomicU64>,
    events: &SyncSender<StderrEvent>,
) {
    let mut buffer = [0_u8; 8 * 1_024];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => {
                let _ = events.send(StderrEvent::Eof);
                return;
            }
            Ok(read) => add_atomic(observed_bytes, read),
            Err(source) => {
                let _ = events.send(StderrEvent::Failed(source.kind()));
                return;
            }
        }
    }
}

fn process_worker(
    child: &Arc<Mutex<Option<Child>>>,
    commands: &Receiver<ProcessCommand>,
    events: &SyncSender<ProcessEvent>,
) {
    loop {
        match commands.recv_timeout(PROCESS_OBSERVATION_INTERVAL) {
            Ok(ProcessCommand::Terminate)
            | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let result = terminate_and_wait_shared(child);
                send_process_result(events, result);
                return;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        let result = try_wait_shared(child);
        match result {
            Ok(Some(status)) => {
                let _ = events.send(ProcessEvent::Exited(process_exit(status)));
                return;
            }
            Ok(None) => {}
            Err(source) => {
                let _ = events.send(ProcessEvent::Failed(source.kind()));
                return;
            }
        }
    }
}

fn try_wait_shared(child: &Arc<Mutex<Option<Child>>>) -> io::Result<Option<ExitStatus>> {
    let mut guard = lock_child(child);
    let Some(process) = guard.as_mut() else {
        return Ok(None);
    };
    let status = process.try_wait()?;
    if status.is_some() {
        guard.take();
    }
    Ok(status)
}

fn terminate_and_wait_shared(child: &Arc<Mutex<Option<Child>>>) -> io::Result<ExitStatus> {
    let mut guard = lock_child(child);
    let Some(mut process) = guard.take() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "app-server child owner is absent",
        ));
    };
    if let Err(source) = process.kill()
        && source.kind() != io::ErrorKind::InvalidInput
    {
        return Err(source);
    }
    process.wait()
}

fn lock_child(child: &Arc<Mutex<Option<Child>>>) -> std::sync::MutexGuard<'_, Option<Child>> {
    match child.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn send_process_result(events: &SyncSender<ProcessEvent>, result: io::Result<ExitStatus>) {
    let event = match result {
        Ok(status) => ProcessEvent::Exited(process_exit(status)),
        Err(source) => ProcessEvent::Failed(source.kind()),
    };
    let _ = events.send(event);
}

fn process_exit(status: ExitStatus) -> ProcessExit {
    ProcessExit {
        success: status.success(),
        code: status.code(),
    }
}

fn request_process_termination(sender: &SyncSender<ProcessCommand>) {
    match sender.try_send(ProcessCommand::Terminate) {
        Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
    }
}

fn terminate_shared_child(child: &Arc<Mutex<Option<Child>>>) {
    let _ = terminate_and_wait_shared(child);
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn add_atomic(counter: &AtomicU64, value: usize) {
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

fn increment(value: u64) -> Result<u64, AppServerProcessError> {
    value
        .checked_add(1)
        .ok_or(AppServerProcessError::DiagnosticCounterOverflow)
}

fn add_usize(value: u64, increment: usize) -> Result<u64, AppServerProcessError> {
    let increment =
        u64::try_from(increment).map_err(|_| AppServerProcessError::DiagnosticCounterOverflow)?;
    value
        .checked_add(increment)
        .ok_or(AppServerProcessError::DiagnosticCounterOverflow)
}

fn join_if_finished(worker: &mut Option<JoinHandle<()>>) {
    if worker.as_ref().is_some_and(JoinHandle::is_finished)
        && let Some(worker) = worker.take()
    {
        let _ = worker.join();
    }
}
