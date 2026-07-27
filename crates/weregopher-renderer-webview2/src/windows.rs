//! Isolated Win32/WebView2 implementation for the packaged-renderer fixture.

use std::{
    fmt,
    path::Path,
    sync::mpsc::{self, Receiver, TryRecvError},
    time::{Duration, Instant},
};

use tempfile::TempDir;
use thiserror::Error;
use webview2_com::{
    AddScriptToExecuteOnDocumentCreatedCompletedHandler, BrowserProcessExitedEventHandler,
    CallDevToolsProtocolMethodCompletedHandler, CoTaskMemPWSTR, CoreWebView2EnvironmentOptions,
    CreateCoreWebView2ControllerCompletedHandler, CreateCoreWebView2EnvironmentCompletedHandler,
    DOMContentLoadedEventHandler, ExecuteScriptCompletedHandler,
    Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL, CreateCoreWebView2EnvironmentWithOptions,
        ICoreWebView2, ICoreWebView2_2, ICoreWebView2Controller, ICoreWebView2Environment,
        ICoreWebView2Environment5, ICoreWebView2EnvironmentOptions,
    },
    NavigationCompletedEventHandler, WebMessageReceivedEventHandler,
    WebResourceRequestedEventHandler, take_pwstr,
};
use weregopher_domain::{RendererBridgeNonce, RendererBridgeReply};
use weregopher_renderer::{
    NavigationGeneration, PackageOrigin, PackageOriginResponse, RendererLifecycle,
    RendererLifecycleError, RendererLifecycleState,
};
use windows::{
    Win32::{
        Foundation::{
            E_FAIL, E_POINTER, ERROR_CLASS_ALREADY_EXISTS, GetLastError, HINSTANCE, HWND, LPARAM,
            LRESULT, RECT, WPARAM,
        },
        System::{
            Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize},
            LibraryLoader::GetModuleHandleW,
        },
        UI::{
            Shell::SHCreateMemStream,
            WindowsAndMessaging::{
                CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW,
                DestroyWindow, DispatchMessageW, MSG, MWMO_INPUTAVAILABLE,
                MsgWaitForMultipleObjectsEx, PM_REMOVE, PeekMessageW, QS_ALLINPUT, RegisterClassW,
                TranslateMessage, WINDOW_EX_STYLE, WM_QUIT, WNDCLASSW, WS_OVERLAPPEDWINDOW,
            },
        },
    },
    core::{BOOL, Error as WindowsError, HRESULT, Interface as _, PCWSTR, PWSTR, w},
};

const WINDOW_CLASS: PCWSTR = w!("WeregopherG1RendererFixture");
const DEFAULT_WINDOW_WIDTH: i32 = 800;
const DEFAULT_WINDOW_HEIGHT: i32 = 600;
const MAX_BROWSER_VERSION_BYTES: usize = 128;
const MAX_WEB_MESSAGE_SOURCE_BYTES: usize = 4_096;
const MAX_WEB_MESSAGE_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_DOCUMENT_START_SCRIPT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ISOLATED_WORLD_NAME_BYTES: usize = 64;
const MAX_DEVTOOLS_RESPONSE_BYTES: usize = 1024 * 1024;

/// One renderer message together with the source URL reported by `WebView2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedWebMessage {
    source: String,
    json: String,
}

impl ObservedWebMessage {
    /// Backend-reported document source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Raw JSON supplied by the constrained `WebView2` message channel.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }
}

enum CapturedWebMessage {
    Accepted(ObservedWebMessage),
    Rejected {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
}

/// Deterministic fixture shutdown evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebView2ShutdownObservation {
    browser_process_exited: bool,
    user_data_removed: bool,
    final_state: RendererLifecycleState,
}

impl WebView2ShutdownObservation {
    /// Whether the exclusive `WebView2` browser process reported exit.
    #[must_use]
    pub const fn browser_process_exited(self) -> bool {
        self.browser_process_exited
    }

    /// Whether the ephemeral user-data directory was removed after browser exit.
    #[must_use]
    pub const fn user_data_removed(self) -> bool {
        self.user_data_removed
    }

    /// Final portable lifecycle state.
    #[must_use]
    pub const fn final_state(self) -> RendererLifecycleState {
        self.final_state
    }
}

struct ComApartment;

impl ComApartment {
    #[allow(
        unsafe_code,
        reason = "initializes one STA on the current fixture thread and pairs it with Drop"
    )]
    fn initialize() -> Result<Self, WindowsError> {
        // SAFETY: the current test thread is initialized exactly once by this owner as an STA.
        // The successful call is paired with one `CoUninitialize` in `Drop` on the same thread.
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()? };
        Ok(Self)
    }
}

impl Drop for ComApartment {
    #[allow(
        unsafe_code,
        reason = "balances the successful current-thread CoInitializeEx owned by this value"
    )]
    fn drop(&mut self) {
        // SAFETY: this owner is dropped on the creating thread after every dependent COM object.
        unsafe { CoUninitialize() };
    }
}

struct HiddenWindow(HWND);

impl HiddenWindow {
    #[allow(
        unsafe_code,
        reason = "registers one fixed window class and adopts one checked HWND for WebView2 parenting"
    )]
    fn create() -> Result<Self, WebView2FixtureError> {
        let module = unsafe { GetModuleHandleW(None)? };
        let class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: HINSTANCE(module.0),
            lpszClassName: WINDOW_CLASS,
            ..Default::default()
        };
        // SAFETY: `class` is fully initialized and its static class-name pointer outlives the
        // registration. A zero atom is rejected before attempting window creation.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            // SAFETY: the immediately preceding registration call failed, so this observes its
            // thread-local extended error before any other fallible platform call.
            let error = unsafe { GetLastError() };
            if error != ERROR_CLASS_ALREADY_EXISTS {
                return Err(WindowsError::from_hresult(HRESULT::from_win32(error.0)).into());
            }
        }
        // SAFETY: the registered class and module remain valid. No raw creation parameter is
        // supplied, and the generated wrapper rejects a null/invalid result before ownership.
        let window = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                WINDOW_CLASS,
                w!("Weregopher G1 renderer fixture"),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                DEFAULT_WINDOW_WIDTH,
                DEFAULT_WINDOW_HEIGHT,
                None,
                None,
                Some(HINSTANCE(module.0)),
                None,
            )?
        };
        Ok(Self(window))
    }

    const fn handle(&self) -> HWND {
        self.0
    }
}

impl Drop for HiddenWindow {
    #[allow(
        unsafe_code,
        reason = "destroys the uniquely owned hidden HWND if it remains live"
    )]
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: this wrapper uniquely owns the checked HWND and destroys it at most once.
            let _ = unsafe { DestroyWindow(self.0) };
            self.0 = HWND::default();
        }
    }
}

#[allow(
    unsafe_code,
    reason = "implements the documented Win32 window-procedure ABI and forwards every message"
)]
unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    // SAFETY: Windows invokes this function with the documented window-procedure ABI and arguments;
    // forwarding unhandled messages to DefWindowProcW preserves default semantics.
    unsafe { DefWindowProcW(window, message, w_param, l_param) }
}

/// Hidden Windows `WebView2` host bound to one immutable private package origin.
pub struct WebView2Fixture {
    window: Option<HiddenWindow>,
    environment: Option<ICoreWebView2Environment>,
    environment5: Option<ICoreWebView2Environment5>,
    controller: Option<ICoreWebView2Controller>,
    webview: Option<ICoreWebView2>,
    resource_token: i64,
    message_token: i64,
    browser_exit_token: i64,
    browser_exit_rx: Receiver<()>,
    message_rx: Receiver<CapturedWebMessage>,
    browser_version: String,
    lifecycle: RendererLifecycle,
    user_data: Option<TempDir>,
    closed: bool,
    _apartment: ComApartment,
}

impl fmt::Debug for WebView2Fixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebView2Fixture")
            .field("state", &self.lifecycle.state())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl WebView2Fixture {
    /// Creates a hidden controller with an exclusive ephemeral profile and immutable origin.
    ///
    /// All `WebView2` web requests are intercepted. Requests outside `package` receive a closed
    /// denial response rather than reaching the network. Native host objects and developer tools
    /// are disabled; only `WebView2`'s JSON message channel remains enabled.
    ///
    /// # Errors
    ///
    /// Returns a typed Windows, `WebView2`, filesystem, or lifecycle error.
    #[allow(
        unsafe_code,
        reason = "isolates checked WebView2 COM creation/configuration over owned STA objects"
    )]
    pub fn create(
        package: PackageOrigin,
        renderer: weregopher_domain::RendererId,
    ) -> Result<Self, WebView2FixtureError> {
        let apartment = ComApartment::initialize()?;
        let user_data = tempfile::Builder::new()
            .prefix("weregopher-g1-webview2-")
            .tempdir()?;
        let window = HiddenWindow::create()?;
        let environment = create_environment(user_data.path())?;
        let browser_version = read_browser_version(&environment)?;
        let environment5: ICoreWebView2Environment5 = environment.cast()?;
        let (browser_exit_tx, browser_exit_rx) = mpsc::channel();
        let browser_handler =
            BrowserProcessExitedEventHandler::create(Box::new(move |_environment, _args| {
                let _ = browser_exit_tx.send(());
                Ok(())
            }));
        let mut browser_exit_token = 0;
        // SAFETY: the environment and callback are live COM objects and token points to initialized
        // writable storage retained for later removal.
        unsafe {
            environment5.add_BrowserProcessExited(&browser_handler, &raw mut browser_exit_token)?;
        }

        let controller = create_controller(&environment, window.handle())?;
        // SAFETY: the live controller receives a bounded rectangle and remains parented by the
        // owned hidden window. Visibility enables document execution without showing the parent.
        unsafe {
            controller.SetBounds(RECT {
                left: 0,
                top: 0,
                right: DEFAULT_WINDOW_WIDTH,
                bottom: DEFAULT_WINDOW_HEIGHT,
            })?;
            controller.SetIsVisible(true)?;
        }
        // SAFETY: a successfully created controller owns exactly one initialized CoreWebView2.
        let webview = unsafe { controller.CoreWebView2()? };
        // SAFETY: settings is a live COM object owned by the webview; every boolean narrows the
        // fixture surface except the required JSON message channel.
        unsafe {
            let settings = webview.Settings()?;
            settings.SetIsScriptEnabled(true)?;
            settings.SetIsWebMessageEnabled(true)?;
            settings.SetAreHostObjectsAllowed(false)?;
            settings.SetAreDevToolsEnabled(false)?;
            settings.SetAreDefaultContextMenusEnabled(false)?;
        }

        let resource_token = install_package_origin(&environment, &webview, package)?;
        let (message_token, message_rx) = install_message_capture(&webview)?;
        let mut lifecycle = RendererLifecycle::new(renderer);
        lifecycle.mark_initialized()?;
        Ok(Self {
            window: Some(window),
            environment: Some(environment),
            environment5: Some(environment5),
            controller: Some(controller),
            webview: Some(webview),
            resource_token,
            message_token,
            browser_exit_token,
            browser_exit_rx,
            message_rx,
            browser_version,
            lifecycle,
            user_data: Some(user_data),
            closed: false,
            _apartment: apartment,
        })
    }

    /// Installs the per-navigation document-start bridge without exposing a native host object.
    ///
    /// # Errors
    ///
    /// Returns a `WebView2` error if the script cannot be registered.
    pub fn install_bridge(&self, nonce: RendererBridgeNonce) -> Result<(), WebView2FixtureError> {
        let script = bridge_bootstrap(nonce);
        add_document_start_script(self.webview()?, &script)
    }

    /// Installs a bounded fixture script in the page main world at document start.
    ///
    /// This is used by renderer compatibility fixtures to model the explicitly
    /// projected page-facing half of `contextBridge`. It does not expose a
    /// native host object.
    ///
    /// # Errors
    ///
    /// Returns a closed size error or the underlying `WebView2` registration
    /// failure.
    pub fn install_main_world_document_start_script(
        &self,
        source: &str,
    ) -> Result<(), WebView2FixtureError> {
        validate_document_start_script(source)?;
        add_document_start_script(self.webview()?, source)
    }

    /// Installs a bounded script into a named Chromium isolated world for each
    /// new document.
    ///
    /// Registration uses the host-side `DevTools` protocol and a fixed
    /// `Page.addScriptToEvaluateOnNewDocument` request. The raw protocol
    /// channel and response are not exposed to page content.
    ///
    /// # Errors
    ///
    /// Returns a closed validation error for an invalid world/script or an
    /// underlying `WebView2`/`DevTools` callback failure.
    pub fn install_isolated_world_document_start_script(
        &self,
        world_name: &str,
        source: &str,
    ) -> Result<(), WebView2FixtureError> {
        validate_isolated_world_name(world_name)?;
        validate_document_start_script(source)?;
        let parameters = serde_json::to_string(&serde_json::json!({
            "source": source,
            "worldName": world_name,
            "includeCommandLineAPI": false,
            "runImmediately": false
        }))?;
        let response = call_devtools_protocol(
            self.webview()?,
            "Page.addScriptToEvaluateOnNewDocument",
            &parameters,
        )?;
        if response.len() > MAX_DEVTOOLS_RESPONSE_BYTES {
            return Err(WebView2FixtureError::DevToolsResponseTooLarge {
                maximum: MAX_DEVTOOLS_RESPONSE_BYTES,
                actual: response.len(),
            });
        }
        let response: serde_json::Value = serde_json::from_str(&response)?;
        if response.get("error").is_some()
            || response
                .get("identifier")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(WebView2FixtureError::InvalidDevToolsResponse);
        }
        Ok(())
    }

    /// Navigates to one private package URL and records DOM/load lifecycle events.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, `WebView2`, timeout, or navigation failure.
    #[allow(
        unsafe_code,
        reason = "registers and removes checked WebView2 navigation callbacks on live COM objects"
    )]
    pub fn navigate(
        &mut self,
        url: &str,
        timeout: Duration,
    ) -> Result<NavigationGeneration, WebView2FixtureError> {
        let generation = self.lifecycle.begin_navigation()?;
        let webview = self.webview()?.clone();
        let webview2: ICoreWebView2_2 = webview.cast()?;
        let (dom_tx, dom_rx) = mpsc::channel();
        let dom_handler = DOMContentLoadedEventHandler::create(Box::new(move |_sender, _args| {
            let _ = dom_tx.send(());
            Ok(())
        }));
        let mut dom_token = 0;
        // SAFETY: live COM object/callback and initialized token storage.
        unsafe { webview2.add_DOMContentLoaded(&dom_handler, &raw mut dom_token)? };

        let (completed_tx, completed_rx) = mpsc::channel();
        let completed_handler =
            NavigationCompletedEventHandler::create(Box::new(move |_sender, args| {
                let mut succeeded = BOOL::default();
                if let Some(args) = args {
                    // SAFETY: callback supplies a live event-args object and writable BOOL.
                    unsafe { args.IsSuccess(&raw mut succeeded)? };
                }
                let _ = completed_tx.send(succeeded.as_bool());
                Ok(())
            }));
        let mut completed_token = 0;
        // SAFETY: live COM object/callback and initialized token storage.
        unsafe { webview.add_NavigationCompleted(&completed_handler, &raw mut completed_token)? };

        let navigation_result = (|| {
            let target = CoTaskMemPWSTR::from(url);
            // SAFETY: the target guard keeps its NUL-terminated UTF-16 storage alive for Navigate.
            unsafe { webview.Navigate(*target.as_ref().as_pcwstr())? };
            pump_receiver(&dom_rx, timeout, "DOMContentLoaded")?;
            self.lifecycle.mark_dom_content_loaded(generation)?;
            if !pump_receiver(&completed_rx, timeout, "navigation completion")? {
                return Err(WebView2FixtureError::NavigationFailed);
            }
            self.lifecycle.mark_loaded(generation)?;
            Ok(generation)
        })();

        // SAFETY: each token was issued by the same still-live object above. Cleanup errors are
        // returned only when the navigation itself otherwise succeeded.
        let remove_dom = unsafe { webview2.remove_DOMContentLoaded(dom_token) };
        // SAFETY: same invariant as above for the completion token.
        let remove_completed = unsafe { webview.remove_NavigationCompleted(completed_token) };
        navigation_result?;
        remove_dom?;
        remove_completed?;
        Ok(generation)
    }

    /// Waits for one page message while pumping the STA message queue.
    ///
    /// # Errors
    ///
    /// Returns a timeout or Windows message-loop error.
    pub fn wait_for_message(
        &self,
        timeout: Duration,
    ) -> Result<ObservedWebMessage, WebView2FixtureError> {
        match pump_receiver(&self.message_rx, timeout, "renderer message")? {
            CapturedWebMessage::Accepted(message) => Ok(message),
            CapturedWebMessage::Rejected {
                field,
                maximum,
                actual,
            } => Err(WebView2FixtureError::WebMessageTooLarge {
                field,
                maximum,
                actual,
            }),
        }
    }

    /// Posts one bounded bridge reply to the active document.
    ///
    /// # Errors
    ///
    /// Returns a JSON or `WebView2` error.
    #[allow(
        unsafe_code,
        reason = "passes one validated NUL-terminated JSON string to the live WebView2 message API"
    )]
    pub fn post_reply(&self, reply: &RendererBridgeReply) -> Result<(), WebView2FixtureError> {
        let json = serde_json::to_string(reply)?;
        let encoded = CoTaskMemPWSTR::from(json.as_str());
        // SAFETY: `encoded` retains valid NUL-terminated UTF-16 for the duration of the COM call.
        unsafe {
            self.webview()?
                .PostWebMessageAsJson(*encoded.as_ref().as_pcwstr())?;
        }
        Ok(())
    }

    /// Executes one diagnostic script and returns `WebView2`'s JSON-encoded result.
    ///
    /// # Errors
    ///
    /// Returns a `WebView2` callback or channel error.
    pub fn execute_script(&self, source: &str) -> Result<String, WebView2FixtureError> {
        execute_script(self.webview()?, source)
    }

    /// Installed `WebView2` runtime version reported by the created environment.
    #[must_use]
    pub fn browser_version(&self) -> &str {
        &self.browser_version
    }

    /// Active portable lifecycle state.
    #[must_use]
    pub const fn lifecycle_state(&self) -> RendererLifecycleState {
        self.lifecycle.state()
    }

    /// Closes the controller, waits for its exclusive browser process, and removes ephemeral data.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, `WebView2`, timeout, or filesystem cleanup error.
    #[allow(
        unsafe_code,
        reason = "removes issued event tokens and closes owned WebView2 COM/controller objects"
    )]
    pub fn close(
        &mut self,
        timeout: Duration,
    ) -> Result<WebView2ShutdownObservation, WebView2FixtureError> {
        if self.closed {
            return Err(WebView2FixtureError::AlreadyClosed);
        }
        self.lifecycle.begin_close()?;
        if let Some(webview) = &self.webview {
            // SAFETY: both tokens and the filter were issued by this live webview and are removed
            // at most once. Releasing the webview below remains the authoritative cleanup if a
            // best-effort explicit removal reports an error.
            unsafe {
                let _ = webview.remove_WebResourceRequested(self.resource_token);
                let _ = webview.remove_WebMessageReceived(self.message_token);
                let _ = webview.RemoveWebResourceRequestedFilter(
                    w!("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                );
            }
        }
        let controller_close = if let Some(controller) = self.controller.take() {
            // SAFETY: uniquely owned controller is closed at most once before being dropped.
            unsafe { controller.Close() }
        } else {
            Ok(())
        };
        self.webview.take();
        self.window.take();
        let browser_process_exited =
            pump_receiver(&self.browser_exit_rx, timeout, "WebView2 browser exit").is_ok();
        if let Some(environment5) = &self.environment5 {
            // SAFETY: token was issued by this live environment and is removed at most once.
            // Releasing the environment below also releases a handler if explicit removal fails.
            let _ = unsafe { environment5.remove_BrowserProcessExited(self.browser_exit_token) };
        }
        self.environment5.take();
        self.environment.take();
        let user_data_removed = if let Some(user_data) = self.user_data.take() {
            user_data.close().is_ok()
        } else {
            false
        };
        self.closed = true;
        controller_close?;
        if !browser_process_exited {
            return Err(WebView2FixtureError::Timeout {
                operation: "WebView2 browser exit",
            });
        }
        if !user_data_removed {
            return Err(WebView2FixtureError::UserDataCleanupFailed);
        }
        self.lifecycle.mark_closed()?;
        Ok(WebView2ShutdownObservation {
            browser_process_exited,
            user_data_removed,
            final_state: self.lifecycle.state(),
        })
    }

    fn webview(&self) -> Result<&ICoreWebView2, WebView2FixtureError> {
        self.webview
            .as_ref()
            .ok_or(WebView2FixtureError::AlreadyClosed)
    }
}

impl Drop for WebView2Fixture {
    #[allow(
        unsafe_code,
        reason = "best-effort at-most-once close of an owned controller during error unwinding"
    )]
    fn drop(&mut self) {
        if let Some(controller) = self.controller.take() {
            // SAFETY: this path owns the controller and ignores only best-effort shutdown errors.
            let _ = unsafe { controller.Close() };
        }
        self.webview.take();
        self.window.take();
    }
}

#[allow(
    unsafe_code,
    reason = "creates a WebView2 environment through its callback API over retained UTF-16/options"
)]
fn create_environment(path: &Path) -> Result<ICoreWebView2Environment, WebView2FixtureError> {
    let user_data = path
        .to_str()
        .ok_or(WebView2FixtureError::NonUnicodeUserDataPath)?
        .to_owned();
    let options = CoreWebView2EnvironmentOptions::default();
    // SAFETY: the options object has not been shared with WebView2 yet and this initialization is
    // single-threaded on the fixture STA.
    unsafe {
        options.set_exclusive_user_data_folder_access(true);
        options.set_allow_single_sign_on_using_os_primary_account(false);
        options.set_are_browser_extensions_enabled(false);
    }
    let options: ICoreWebView2EnvironmentOptions = options.into();
    let (sender, receiver) = mpsc::channel();
    CreateCoreWebView2EnvironmentCompletedHandler::wait_for_async_operation(
        Box::new(move |handler| {
            let user_data = CoTaskMemPWSTR::from(user_data.as_str());
            // SAFETY: the path guard, COM options, and completion handler are valid for this call.
            unsafe {
                CreateCoreWebView2EnvironmentWithOptions(
                    PCWSTR::null(),
                    *user_data.as_ref().as_pcwstr(),
                    &options,
                    &handler,
                )
                .map_err(webview2_com::Error::WindowsError)
            }
        }),
        Box::new(move |error_code, environment| {
            error_code?;
            let result = environment.ok_or_else(|| WindowsError::from(E_POINTER));
            sender
                .send(result)
                .map_err(|_| WindowsError::from(E_FAIL))?;
            Ok(())
        }),
    )?;
    receiver
        .recv()
        .map_err(|_| WebView2FixtureError::CallbackChannelClosed)?
        .map_err(WebView2FixtureError::from)
}

#[allow(
    unsafe_code,
    reason = "creates one WebView2 controller parented to the retained hidden HWND"
)]
fn create_controller(
    environment: &ICoreWebView2Environment,
    parent: HWND,
) -> Result<ICoreWebView2Controller, WebView2FixtureError> {
    let environment = environment.clone();
    let (sender, receiver) = mpsc::channel();
    CreateCoreWebView2ControllerCompletedHandler::wait_for_async_operation(
        Box::new(move |handler| {
            // SAFETY: environment/parent HWND remain live until callback completion.
            unsafe {
                environment
                    .CreateCoreWebView2Controller(parent, &handler)
                    .map_err(webview2_com::Error::WindowsError)
            }
        }),
        Box::new(move |error_code, controller| {
            error_code?;
            let result = controller.ok_or_else(|| WindowsError::from(E_POINTER));
            sender
                .send(result)
                .map_err(|_| WindowsError::from(E_FAIL))?;
            Ok(())
        }),
    )?;
    receiver
        .recv()
        .map_err(|_| WebView2FixtureError::CallbackChannelClosed)?
        .map_err(WebView2FixtureError::from)
}

#[allow(
    unsafe_code,
    reason = "adopts one environment-owned WebView2 version string through its documented getter"
)]
fn read_browser_version(
    environment: &ICoreWebView2Environment,
) -> Result<String, WebView2FixtureError> {
    let mut version = PWSTR::null();
    // SAFETY: `version` is initialized writable out storage; `take_pwstr` adopts and frees the
    // successful COM allocation exactly once.
    unsafe { environment.BrowserVersionString(&raw mut version)? };
    let version = take_pwstr(version);
    if version.is_empty() || version.len() > MAX_BROWSER_VERSION_BYTES {
        return Err(WebView2FixtureError::InvalidBrowserVersion {
            maximum: MAX_BROWSER_VERSION_BYTES,
            actual: version.len(),
        });
    }
    Ok(version)
}

#[allow(
    unsafe_code,
    reason = "registers a WebView2 resource callback that converts immutable bytes to copied IStream responses"
)]
fn install_package_origin(
    environment: &ICoreWebView2Environment,
    webview: &ICoreWebView2,
    package: PackageOrigin,
) -> Result<i64, WebView2FixtureError> {
    let environment = environment.clone();
    let handler = WebResourceRequestedEventHandler::create(Box::new(move |_sender, args| {
        let Some(args) = args else {
            return Err(WindowsError::from(E_POINTER));
        };
        // SAFETY: callback supplies live event args and request COM objects.
        let request = unsafe { args.Request()? };
        let mut uri = PWSTR::null();
        let mut method = PWSTR::null();
        // SAFETY: WebView2 allocates both out strings; `take_pwstr` adopts/frees each exactly once.
        unsafe {
            request.Uri(&raw mut uri)?;
            request.Method(&raw mut method)?;
        }
        let uri = take_pwstr(uri);
        let method = take_pwstr(method);
        let response = package.serve(&method, &uri);
        let response = match response {
            Ok(response) => create_resource_response(&environment, &response)?,
            Err(_) => create_denied_response(&environment)?,
        };
        // SAFETY: response and event args remain live for the duration of the setter call.
        unsafe { args.SetResponse(&response)? };
        Ok(())
    }));
    let mut token = 0;
    // SAFETY: the wildcard is static valid UTF-16; intercepting every context prevents fallback
    // network access for resources outside the private immutable package.
    unsafe {
        webview.AddWebResourceRequestedFilter(w!("*"), COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)?;
        webview.add_WebResourceRequested(&handler, &raw mut token)?;
    }
    Ok(token)
}

#[allow(
    unsafe_code,
    reason = "registers a JSON-only WebView2 callback and adopts callback-owned out strings"
)]
fn install_message_capture(
    webview: &ICoreWebView2,
) -> Result<(i64, Receiver<CapturedWebMessage>), WebView2FixtureError> {
    let (sender, receiver) = mpsc::channel();
    let handler = WebMessageReceivedEventHandler::create(Box::new(move |_sender, args| {
        let Some(args) = args else {
            return Err(WindowsError::from(E_POINTER));
        };
        let mut source = PWSTR::null();
        let mut json = PWSTR::null();
        // SAFETY: callback out pointers are writable; WebView2 allocates both returned strings and
        // `take_pwstr` adopts/frees each exactly once.
        unsafe {
            args.Source(&raw mut source)?;
            args.WebMessageAsJson(&raw mut json)?;
        }
        let source = take_pwstr(source);
        let json = take_pwstr(json);
        let captured = if source.len() > MAX_WEB_MESSAGE_SOURCE_BYTES {
            CapturedWebMessage::Rejected {
                field: "source",
                maximum: MAX_WEB_MESSAGE_SOURCE_BYTES,
                actual: source.len(),
            }
        } else if json.len() > MAX_WEB_MESSAGE_JSON_BYTES {
            CapturedWebMessage::Rejected {
                field: "JSON",
                maximum: MAX_WEB_MESSAGE_JSON_BYTES,
                actual: json.len(),
            }
        } else {
            CapturedWebMessage::Accepted(ObservedWebMessage { source, json })
        };
        let _ = sender.send(captured);
        Ok(())
    }));
    let mut token = 0;
    // SAFETY: live webview/callback and initialized writable token.
    unsafe { webview.add_WebMessageReceived(&handler, &raw mut token)? };
    Ok((token, receiver))
}

#[allow(
    unsafe_code,
    reason = "copies bounded immutable bytes into SHCreateMemStream and constructs a WebView2 response"
)]
fn create_resource_response(
    environment: &ICoreWebView2Environment,
    response: &PackageOriginResponse,
) -> windows::core::Result<
    webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2WebResourceResponse,
> {
    // SAFETY: response bodies are bounded below u32::MAX by the portable G1 limits and
    // SHCreateMemStream copies the supplied slice into a newly owned COM stream.
    let stream = unsafe { SHCreateMemStream(Some(response.body())) }
        .ok_or_else(|| WindowsError::from(E_FAIL))?;
    let mut headers = format!(
        "Content-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff",
        response.media_type(),
        response.content_length()
    );
    if !response.etag().is_empty() {
        headers.push_str("\r\nETag: ");
        headers.push_str(response.etag());
    }
    let reason = CoTaskMemPWSTR::from(response.reason());
    let headers = CoTaskMemPWSTR::from(headers.as_str());
    // SAFETY: stream and both UTF-16 guards remain live; status is a bounded portable u16.
    unsafe {
        environment.CreateWebResourceResponse(
            &stream,
            i32::from(response.status_code()),
            *reason.as_ref().as_pcwstr(),
            *headers.as_ref().as_pcwstr(),
        )
    }
}

#[allow(
    unsafe_code,
    reason = "constructs a fixed empty denial response through the checked WebView2 response API"
)]
fn create_denied_response(
    environment: &ICoreWebView2Environment,
) -> windows::core::Result<
    webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2WebResourceResponse,
> {
    // SAFETY: an empty slice is valid and copied into a newly owned COM stream.
    let stream =
        unsafe { SHCreateMemStream(Some(&[])) }.ok_or_else(|| WindowsError::from(E_FAIL))?;
    // SAFETY: all literals are static NUL-terminated UTF-16 and stream remains live.
    unsafe {
        environment.CreateWebResourceResponse(
            &stream,
            403,
            w!("Forbidden"),
            w!("Content-Length: 0\r\nCache-Control: no-store"),
        )
    }
}

fn bridge_bootstrap(nonce: RendererBridgeNonce) -> String {
    let nonce = nonce
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"
(() => {{
  "use strict";
  if (window !== window.top) return;
  const nonce = Object.freeze([{nonce}]);
  const post = window.chrome.webview.postMessage.bind(window.chrome.webview);
  const pending = new Map();
  let nextRequest = 1;
  window.chrome.webview.addEventListener("message", event => {{
    const reply = event.data;
    if (!reply || !Number.isSafeInteger(reply.request_id)) return;
    const callbacks = pending.get(reply.request_id);
    if (!callbacks) return;
    pending.delete(reply.request_id);
    if (reply.error) callbacks.reject(new Error(reply.error.message));
    else callbacks.resolve(reply.result);
  }});
  const invoke = (method, args = []) => new Promise((resolve, reject) => {{
    if (typeof method !== "string" || method.length === 0 || !Array.isArray(args)) {{
      reject(new TypeError("invalid Weregopher bridge invocation"));
      return;
    }}
    const request_id = nextRequest++;
    pending.set(request_id, {{ resolve, reject }});
    post({{ nonce, request_id, method, args }});
  }});
  Object.defineProperty(window, "weregopher", {{
    value: Object.freeze({{ invoke }}),
    writable: false,
    configurable: false,
    enumerable: false
  }});
}})();
"#
    )
}

fn validate_document_start_script(source: &str) -> Result<(), WebView2FixtureError> {
    if source.is_empty() || source.len() > MAX_DOCUMENT_START_SCRIPT_BYTES {
        return Err(WebView2FixtureError::InvalidDocumentStartScript {
            maximum: MAX_DOCUMENT_START_SCRIPT_BYTES,
            actual: source.len(),
        });
    }
    Ok(())
}

fn validate_isolated_world_name(world_name: &str) -> Result<(), WebView2FixtureError> {
    if world_name.is_empty()
        || world_name.len() > MAX_ISOLATED_WORLD_NAME_BYTES
        || !world_name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
    {
        return Err(WebView2FixtureError::InvalidIsolatedWorldName);
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "calls one fixed host-side DevTools method through its checked WebView2 callback API"
)]
fn call_devtools_protocol(
    webview: &ICoreWebView2,
    method: &str,
    parameters: &str,
) -> Result<String, WebView2FixtureError> {
    let webview = webview.clone();
    let method = method.to_owned();
    let parameters = parameters.to_owned();
    let (sender, receiver) = mpsc::channel();
    CallDevToolsProtocolMethodCompletedHandler::wait_for_async_operation(
        Box::new(move |handler| {
            let method = CoTaskMemPWSTR::from(method.as_str());
            let parameters = CoTaskMemPWSTR::from(parameters.as_str());
            // SAFETY: both UTF-16 guards and the completion handler remain live
            // for the complete protocol registration call.
            unsafe {
                webview
                    .CallDevToolsProtocolMethod(
                        *method.as_ref().as_pcwstr(),
                        *parameters.as_ref().as_pcwstr(),
                        &handler,
                    )
                    .map_err(webview2_com::Error::WindowsError)
            }
        }),
        Box::new(move |error_code, result| {
            error_code?;
            sender
                .send(result)
                .map_err(|_| WindowsError::from(E_FAIL))?;
            Ok(())
        }),
    )?;
    receiver
        .recv()
        .map_err(|_| WebView2FixtureError::CallbackChannelClosed)
}

#[allow(
    unsafe_code,
    reason = "registers one retained document-start script through the checked WebView2 callback API"
)]
fn add_document_start_script(
    webview: &ICoreWebView2,
    source: &str,
) -> Result<(), WebView2FixtureError> {
    let webview = webview.clone();
    let source = source.to_owned();
    AddScriptToExecuteOnDocumentCreatedCompletedHandler::wait_for_async_operation(
        Box::new(move |handler| {
            let source = CoTaskMemPWSTR::from(source.as_str());
            // SAFETY: source guard and completion handler remain valid for the registration call.
            unsafe {
                webview
                    .AddScriptToExecuteOnDocumentCreated(*source.as_ref().as_pcwstr(), &handler)
                    .map_err(webview2_com::Error::WindowsError)
            }
        }),
        Box::new(|error_code, _script_id| error_code),
    )?;
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "executes one diagnostic script through the checked WebView2 callback API"
)]
fn execute_script(webview: &ICoreWebView2, source: &str) -> Result<String, WebView2FixtureError> {
    let webview = webview.clone();
    let source = source.to_owned();
    let (sender, receiver) = mpsc::channel();
    ExecuteScriptCompletedHandler::wait_for_async_operation(
        Box::new(move |handler| {
            let source = CoTaskMemPWSTR::from(source.as_str());
            // SAFETY: source guard and completion handler remain valid for the execution call.
            unsafe {
                webview
                    .ExecuteScript(*source.as_ref().as_pcwstr(), &handler)
                    .map_err(webview2_com::Error::WindowsError)
            }
        }),
        Box::new(move |error_code, result| {
            error_code?;
            sender
                .send(result)
                .map_err(|_| WindowsError::from(E_FAIL))?;
            Ok(())
        }),
    )?;
    receiver
        .recv()
        .map_err(|_| WebView2FixtureError::CallbackChannelClosed)
}

#[allow(
    unsafe_code,
    reason = "pumps only the current STA queue through documented Peek/Translate/Dispatch calls"
)]
fn pump_receiver<T>(
    receiver: &Receiver<T>,
    timeout: Duration,
    operation: &'static str,
) -> Result<T, WebView2FixtureError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(WebView2FixtureError::InvalidTimeout)?;
    loop {
        match receiver.try_recv() {
            Ok(value) => return Ok(value),
            Err(TryRecvError::Disconnected) => {
                return Err(WebView2FixtureError::CallbackChannelClosed);
            }
            Err(TryRecvError::Empty) => {}
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(WebView2FixtureError::Timeout { operation });
        }
        let remaining = deadline.saturating_duration_since(now);
        let milliseconds = u32::try_from(remaining.as_millis().max(1))
            .unwrap_or(u32::MAX)
            .min(1_000);
        // SAFETY: no handle slice is supplied; this waits only for current-thread queue input.
        let _ = unsafe {
            MsgWaitForMultipleObjectsEx(None, milliseconds, QS_ALLINPUT, MWMO_INPUTAVAILABLE)
        };
        let mut message = MSG::default();
        // SAFETY: message points to initialized writable storage; each removed message is
        // translated/dispatched before the next queue check.
        while unsafe { PeekMessageW(&raw mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            if message.message == WM_QUIT {
                return Err(WebView2FixtureError::MessageLoopQuit);
            }
            // SAFETY: the message was populated by PeekMessageW for this thread.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
    }
}

/// Windows/`WebView2` fixture creation, navigation, bridge, or shutdown failure.
#[derive(Debug, Error)]
pub enum WebView2FixtureError {
    /// Windows API or COM call failed.
    #[error("Windows/WebView2 platform call failed: {0}")]
    Windows(#[from] WindowsError),
    /// `WebView2` callback helper failed.
    #[error("WebView2 callback failed: {0}")]
    WebView2(#[from] webview2_com::Error),
    /// Ephemeral user-data creation or cleanup failed.
    #[error("WebView2 fixture filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// Bridge reply JSON encoding failed.
    #[error("renderer bridge JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Portable renderer lifecycle rejected an event.
    #[error(transparent)]
    Lifecycle(#[from] RendererLifecycleError),
    /// An asynchronous operation did not complete before its bounded deadline.
    #[error("timed out waiting for {operation}")]
    Timeout {
        /// Timed-out operation.
        operation: &'static str,
    },
    /// A backend-delivered message field exceeded the fixture trust-boundary ceiling.
    #[error("renderer web message {field} exceeds {maximum} bytes: {actual}")]
    WebMessageTooLarge {
        /// Rejected message field.
        field: &'static str,
        /// Allowed bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// A fixture document-start script was empty or exceeded its byte ceiling.
    #[error("renderer document-start script must contain 1 to {maximum} bytes, got {actual}")]
    InvalidDocumentStartScript {
        /// Allowed maximum bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// A requested isolated-world name was empty or noncanonical.
    #[error("renderer isolated-world name is invalid")]
    InvalidIsolatedWorldName,
    /// A host-side `DevTools` response exceeded its byte ceiling.
    #[error("renderer DevTools response exceeds {maximum} bytes: {actual}")]
    DevToolsResponseTooLarge {
        /// Allowed maximum bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// The fixed `DevTools` registration returned no valid script identifier.
    #[error("renderer DevTools script registration response is invalid")]
    InvalidDevToolsResponse,
    /// Navigation completed with a `WebView2` failure result.
    #[error("WebView2 navigation failed")]
    NavigationFailed,
    /// A callback result sender or receiver disappeared unexpectedly.
    #[error("WebView2 callback channel closed unexpectedly")]
    CallbackChannelClosed,
    /// The STA received a quit message during a bounded operation.
    #[error("WebView2 fixture message loop quit unexpectedly")]
    MessageLoopQuit,
    /// Caller-supplied timeout overflowed monotonic deadline arithmetic.
    #[error("WebView2 fixture timeout is invalid")]
    InvalidTimeout,
    /// `TempDir` supplied a Windows path that could not be represented as UTF-8.
    #[error("WebView2 user-data path is not Unicode")]
    NonUnicodeUserDataPath,
    /// The created environment returned an empty or over-budget runtime version.
    #[error("WebView2 runtime version is empty or exceeds {maximum} bytes: {actual}")]
    InvalidBrowserVersion {
        /// Allowed bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// Fixture was closed or close was attempted more than once.
    #[error("WebView2 fixture is already closed")]
    AlreadyClosed,
    /// Exclusive user-data removal failed after browser exit.
    #[error("WebView2 ephemeral user-data cleanup failed")]
    UserDataCleanupFailed,
}
