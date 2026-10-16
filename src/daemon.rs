// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The daemon: the one process that owns all Ghidra sessions.
//!
//! The daemon serves these endpoints on one loopback TCP listener:
//!
//! - `/mcp`: MCP through Streamable HTTP or legacy SSE.
//! - `/ws/agent`: the bridge WebSocket (see [`crate::bridge`]).
//! - `/upload`: binary uploads (see [`crate::upload`]).
//!
//! It also serves MCP on a local socket for the stdio proxy and the CLI (see
//! [`ipc`]). One daemon runs for each runtime directory. A file lock enforces
//! this rule. The daemon runs until it gets a stop signal. Then it stops all
//! Ghidra processes.

mod ipc {
    //! The local endpoint of the daemon, its lifetime lock and its detached start.
    //!
    //! Clients find the daemon through `server.json` in the runtime directory.
    //! Local clients use MCP through a local socket: a Unix domain socket or a Windows named
    //! pipe. The daemon makes sure that the runtime directory is private to the
    //! current user. For this reason, no other user can put or replace files in it.

    use crate::paths::{atomic_write, runtime_dir};
    use anyhow::{bail, Context, Result};
    use interprocess::local_socket::tokio::{prelude::*, Listener, Stream};
    use interprocess::local_socket::{ListenerOptions, Name};
    use rmcp::{
        model::{CallToolRequestParams, CallToolResult},
        service::RunningService,
        RoleClient, ServiceExt,
    };
    use serde_json::{json, Map, Value};
    use std::fs::{self, File, OpenOptions, TryLockError};
    use std::io;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    /// The daemon keeps this object for its full lifetime. The system releases
    /// the lock if the daemon stops.
    pub struct DaemonControl {
        /// `daemon.lock`, which stays locked for the lifetime of the daemon.
        _lock: File,
        /// The private runtime directory whose lifetime lock this daemon owns.
        runtime: PathBuf,
    }

    impl DaemonControl {
        /// Takes the lifetime lock. Returns `None` if another daemon has the lock.
        pub fn claim() -> Result<Option<Self>> {
            let runtime = runtime_dir()?;
            let lock = private_file(&runtime.join("daemon.lock"))?;
            match lock.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => return Ok(None),
                Err(TryLockError::Error(error)) => {
                    return Err(error).context("locking daemon lifetime")
                }
            }
            crate::process::initialize_daemon_log(runtime.join("daemon.log"))?;
            Ok(Some(Self {
                _lock: lock,
                runtime,
            }))
        }

        /// Returns the runtime directory for this daemon.
        #[must_use]
        pub fn runtime_dir(&self) -> &Path {
            &self.runtime
        }

        /// Makes the local endpoint, and writes it with the address of the HTTP
        /// listener in `server.json`.
        pub fn listen(&self, address: SocketAddr, bridge_ws_url: &str) -> Result<Listener> {
            let runtime = &self.runtime;
            let endpoint = new_endpoint(runtime);
            let options = ListenerOptions::new().name(socket_name(&endpoint)?);
            // The daemon has the lifetime lock. For this reason, a socket that exists is
            // from a daemon that stopped. The private parent directory stops other users.
            #[cfg(unix)]
            let options = options.try_overwrite(true);
            // Only the owner of the pipe can connect. The pipe always refuses remote clients.
            #[cfg(windows)]
            let options = {
                use interprocess::os::windows::{
                    local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
                };
                let owner_only = widestring::u16cstr!("D:P(A;;GA;;;OW)");
                options.security_descriptor(SecurityDescriptor::deserialize(owner_only)?)
            };
            let listener = options
                .create_tokio()
                .context("creating daemon MCP socket")?;
            let server = json!({
                "pid": std::process::id(),
                "mcpUrl": format!("http://{address}/mcp"),
                "bridgeWsUrl": bridge_ws_url,
                "localSocket": endpoint,
            });
            atomic_write(
                &runtime.join("server.json"),
                &serde_json::to_vec_pretty(&server)?,
            )?;
            Ok(listener)
        }
    }

    /// Returns the socket path on Unix. On Windows, returns a new random pipe
    /// name. Then another user cannot make the pipe first.
    fn new_endpoint(runtime: &Path) -> String {
        #[cfg(unix)]
        {
            runtime.join("daemon.sock").to_string_lossy().into_owned()
        }
        #[cfg(windows)]
        {
            let _ = runtime;
            format!("ghidra-mcp-{}", uuid::Uuid::new_v4().simple())
        }
    }

    /// Changes a published endpoint into a socket name: a file path on Unix, and a
    /// pipe name on Windows.
    fn socket_name(endpoint: &str) -> io::Result<Name<'_>> {
        #[cfg(unix)]
        {
            endpoint.to_fs_name::<interprocess::local_socket::GenericFilePath>()
        }
        #[cfg(windows)]
        {
            endpoint.to_ns_name::<interprocess::local_socket::GenericNamespaced>()
        }
    }

    /// Time limits for the proxy connection manager lifecycle.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProxyTimeouts {
        /// Maximum time to wait for a new daemon to serve requests.
        pub daemon_start: Duration,
        /// Maximum time for the MCP handshake with a daemon that answers.
        pub handshake: Duration,
        /// Interval between daemon availability checks.
        pub poll_interval: Duration,
    }

    /// Manages persistent connections from the stdio proxy or CLI to the daemon.
    pub struct ProxyConnectionManager {
        /// The cached active MCP client connection.
        client: Mutex<Option<Arc<RunningService<RoleClient, ()>>>>,
        /// Time limits for daemon startup and IPC handshakes.
        timeouts: ProxyTimeouts,
        /// The runtime directory that contains `server.json` and the socket endpoints.
        runtime_dir: PathBuf,
    }

    impl ProxyConnectionManager {
        /// Creates a new connection manager with custom timeouts.
        ///
        /// # Errors
        ///
        /// Fails if the manager cannot find the runtime directory.
        pub fn new(daemon_start: Duration, handshake: Duration) -> Result<Self> {
            let runtime_dir = runtime_dir()?;
            Ok(Self {
                client: Mutex::new(None),
                timeouts: ProxyTimeouts {
                    daemon_start,
                    handshake,
                    poll_interval: Duration::from_millis(100),
                },
                runtime_dir,
            })
        }

        /// Creates a connection manager configured from `McpConfig`.
        ///
        /// # Errors
        ///
        /// Fails if the manager cannot find the runtime directory.
        pub fn from_config(config: &crate::config::McpConfig) -> Result<Self> {
            Self::new(config.timeouts.daemon_start, config.timeouts.ipc_handshake)
        }

        /// Returns the shared proxy connection manager for this process.
        ///
        /// # Errors
        ///
        /// Fails if the configuration or private runtime directory is invalid.
        pub fn global() -> Result<Arc<Self>> {
            static GLOBAL: std::sync::OnceLock<Arc<ProxyConnectionManager>> =
                std::sync::OnceLock::new();
            if let Some(manager) = GLOBAL.get() {
                return Ok(manager.clone());
            }
            let paths = crate::paths::McpPaths::new()?;
            let config = crate::config::McpConfig::load_or_create(&paths)?;
            let manager = Arc::new(Self::from_config(&config)?);
            let _ = GLOBAL.set(manager);
            Ok(GLOBAL.get().expect("proxy manager was initialized").clone())
        }

        /// Calls a tool through the daemon over the reused connection.
        ///
        /// # Errors
        ///
        /// Fails if the daemon connection or the tool call transmission fails.
        pub async fn call_tool(
            &self,
            name: String,
            arguments: Map<String, Value>,
        ) -> Result<CallToolResult> {
            let service = {
                let mut guard = self.client.lock().await;
                self.get_connection(&mut guard).await?
            };

            let params = CallToolRequestParams::new(name).with_arguments(arguments);
            // The daemon owns command deadlines. Launch and job waits can be long.
            // A proxy timeout can hide a successful mutation. It does not stop the mutation.
            match service.peer().call_tool(params).await {
                Ok(result) => Ok(result),
                Err(error) => {
                    if service.is_closed()
                        || matches!(
                            error,
                            rmcp::service::ServiceError::TransportClosed
                                | rmcp::service::ServiceError::TransportSend(_)
                        )
                    {
                        let mut guard = self.client.lock().await;
                        if guard
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &service))
                        {
                            *guard = None;
                        }
                    }
                    Err(anyhow::anyhow!(error)
                        .context("calling daemon tool; the request will not be replayed"))
                }
            }
        }

        /// Returns the cached connection, or opens a new connection when necessary.
        async fn get_connection(
            &self,
            guard: &mut Option<Arc<RunningService<RoleClient, ()>>>,
        ) -> Result<Arc<RunningService<RoleClient, ()>>> {
            if let Some(ref service) = *guard {
                if !service.is_closed() {
                    return Ok(service.clone());
                }
                *guard = None;
            }

            let service = if let Some(service) = self.connect_socket().await? {
                service
            } else {
                spawn_daemon()?;
                let deadline = tokio::time::Instant::now() + self.timeouts.daemon_start;
                loop {
                    if let Some(service) = self.connect_socket().await? {
                        break service;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        bail!(
                            "daemon did not start within {} seconds; inspect {}",
                            self.timeouts.daemon_start.as_secs(),
                            self.runtime_dir.join("daemon.log").display()
                        );
                    }
                    tokio::time::sleep(self.timeouts.poll_interval).await;
                }
            };

            let service = Arc::new(service);
            *guard = Some(service.clone());
            Ok(service)
        }

        /// Connects to the local socket and performs the MCP handshake.
        async fn connect_socket(&self) -> Result<Option<RunningService<RoleClient, ()>>> {
            let server_path = self.runtime_dir.join("server.json");
            let server = match fs::read(&server_path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error).context("reading daemon metadata"),
            };
            let server: Value =
                serde_json::from_slice(&server).context("reading daemon metadata")?;
            // The metadata of an older daemon has no local socket. Start a new daemon.
            let Some(endpoint) = server.get("localSocket").and_then(Value::as_str) else {
                return Ok(None);
            };
            let stream = match Stream::connect(socket_name(endpoint)?).await {
                Ok(stream) => stream,
                // The daemon that wrote the metadata stopped.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    return Ok(None)
                }
                Err(error) => return Err(error).context("connecting to daemon socket"),
            };
            let client = tokio::time::timeout(self.timeouts.handshake, ().serve(stream))
                .await
                .context("daemon MCP handshake timed out")?
                .context("initializing daemon MCP connection")?;
            Ok(Some(client))
        }
    }

    /// Opens a control file of the daemon to add data at its end. On Unix, a new
    /// file gets the mode `0600`.
    pub fn private_file(path: &Path) -> Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(path)
            .with_context(|| format!("opening private daemon file {}", path.display()))
    }

    /// Starts `ghidra-mcp --daemon` in a process separate from the caller.
    /// On Unix, the daemon runs in a new session. On Windows, it runs outside the
    /// console and the job of the caller. The daemon owns its log with rotation.
    fn spawn_daemon() -> Result<()> {
        let mut process =
            Command::new(std::env::current_exe().context("locating ghidra-mcp executable")?);
        process
            .arg("--daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Start a new session. Then the daemon continues after the terminal and the
            // process group of the caller stop.
            // SAFETY: The closure runs in the forked child before `exec`. It only calls
            // `setsid`, which is async-signal-safe, and reads `errno`.
            unsafe {
                process.pre_exec(|| {
                    if libc::setsid() == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::Foundation::{
                SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
            };
            use windows_sys::Win32::System::Threading::{
                CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
            };

            // `Command` sets the standard streams of the child. But the child also gets
            // all other inheritable handles. Keep the original pipe handles of the caller
            // out of the daemon. Then the readers get EOF when the caller stops.
            for handle in [
                io::stdin().as_raw_handle(),
                io::stdout().as_raw_handle(),
                io::stderr().as_raw_handle(),
            ] {
                if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                    continue;
                }
                // SAFETY: `handle` is a valid standard handle of this process. Only its
                // inheritance flag changes.
                if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
                    return Err(io::Error::last_os_error())
                        .context("preventing daemon inheritance of caller standard streams");
                }
            }
            // Leave the console and the job of the caller, also the job that OpenSSH
            // makes for each command. When the MCP client closes, the daemon must not stop.
            process.creation_flags(
                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
            );
        }
        let mut child = process.spawn().context("starting ghidra-mcp daemon")?;
        // A stdio proxy can continue after a failed daemon start. Reap these processes, and
        // do not delay the exit of the proxy.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

pub use ipc::ProxyConnectionManager;

use crate::bridge::AGENT_WS_PATH;
use crate::mcp::ToolServer;
use crate::state::McpState;
use crate::tools::Daemon;
use crate::upload::UploadService;
use anyhow::{ensure, Context, Result};
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use interprocess::local_socket::traits::tokio::Listener as _;
use rmcp::ServiceExt;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// The time for the servers to complete their connections during shutdown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs the daemon on `address` until a stop signal or a server failure.
/// Returns immediately if another daemon has the lock.
///
/// # Errors
///
/// Fails if the address is not loopback.
/// Also fails if the daemon cannot make a listener or initialize the state.
/// Fails if a server fails.
pub async fn run(address: SocketAddr) -> Result<()> {
    ensure!(
        address.ip().is_loopback(),
        "daemon must listen on a loopback address"
    );
    let Some(control) = ipc::DaemonControl::claim()? else {
        eprintln!("ghidra-mcp daemon is already running");
        return Ok(());
    };
    let tcp = TcpListener::bind(address)
        .await
        .context("binding daemon HTTP listener")?;
    let address = tcp.local_addr()?;
    let state = McpState::initialize(format!("ws://{address}{AGENT_WS_PATH}"))?;
    let cancellation = CancellationToken::new();
    let authorities = [address.to_string(), format!("localhost:{}", address.port())];
    let uploads = UploadService::new(
        state.clone(),
        authorities.clone(),
        cancellation.child_token(),
    )?;
    let server = ToolServer::local(Daemon {
        state: state.clone(),
        uploads: uploads.clone(),
    });
    let mcp = crate::mcp_http::router(
        server.clone(),
        authorities.clone(),
        cancellation.child_token(),
    );

    let bridge = Router::new()
        .route(AGENT_WS_PATH, get(crate::bridge::agent_ws))
        .with_state(state.clone());
    let upload = Router::new()
        .route("/upload", post(crate::upload::upload))
        .layer(DefaultBodyLimit::disable())
        .with_state(uploads);
    let app = Router::new().merge(mcp).merge(bridge).merge(upload);

    let mut servers = JoinSet::new();
    let socket = control.listen(address, &state.bridge_ws_url)?;
    servers.spawn(serve_socket(socket, server, cancellation.clone()));
    let http_cancel = cancellation.clone();
    servers.spawn(async move {
        axum::serve(tcp, app)
            .with_graceful_shutdown(http_cancel.cancelled_owned())
            .await
            .context("daemon HTTP server stopped")
    });
    crate::process::log_daemon(&format!(
        "ghidra-mcp daemon pid={} MCP http://{address}/mcp",
        std::process::id()
    ));

    let result = tokio::select! {
        signal = shutdown_signal() => signal,
        Some(joined) = servers.join_next() => {
          joined.context("joining daemon server").and_then(|result| result)
        }
    };
    state.begin_shutdown();
    cancellation.cancel();
    state.stop_all().await;
    let drained = async { while servers.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, drained)
        .await
        .is_err()
    {
        servers.abort_all();
        // Drop the socket listener while the daemon has the lock.
        // The drop removes the socket name.
        while servers.join_next().await.is_some() {}
    }
    let _ = std::fs::remove_file(control.runtime_dir().join("server.json"));
    result
}

/// Waits for Ctrl-C, or for a SIGTERM, SIGHUP or console close signal.
async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C")?,
            _ = sigterm.recv() => {}
            _ = sighup.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_logoff, ctrl_shutdown};
        let mut ctrl_break = ctrl_break().context("installing Ctrl-Break handler")?;
        let mut ctrl_close = ctrl_close().context("installing console close handler")?;
        let mut ctrl_logoff = ctrl_logoff().context("installing logoff handler")?;
        let mut ctrl_shutdown = ctrl_shutdown().context("installing system shutdown handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C")?,
            _ = ctrl_break.recv() => {}
            _ = ctrl_close.recv() => {}
            _ = ctrl_logoff.recv() => {}
            _ = ctrl_shutdown.recv() => {}
        }
    }
    Ok(())
}

/// Serves MCP to local socket clients until cancellation.
async fn serve_socket(
    listener: interprocess::local_socket::tokio::Listener,
    server: ToolServer,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let stream = accepted.context("accepting daemon MCP connection")?;
                let server = server.clone();
                let client_cancel = cancellation.child_token();
                clients.spawn(async move {
                    match server.serve_with_ct(stream, client_cancel).await {
                        Ok(service) => {
                          let _ = service.waiting().await;
                        }
                        Err(error) => crate::process::log_daemon(
                          &format!("daemon MCP connection failed: {error}"),
                        ),
                    }
                });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    while clients.join_next().await.is_some() {}
    Ok(())
}
