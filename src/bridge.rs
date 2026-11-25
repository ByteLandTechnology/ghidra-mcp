// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Manages the Ghidra bridge contract, embedded runtime, WebSocket, and requests.
//!
//! The bridge is a Java program (the `bridge/` submodule). It runs in
//! `analyzeHeadless` as a post-script. It connects to [`AGENT_WS_PATH`] with
//! the credential of its session as a bearer token, and sends `ghidra.ready`.
//! Then it answers JSON-RPC requests (see [`crate::jsonrpc`]) one at a time.
//!
//! This module only moves messages. [`crate::session`] decides when to launch
//! a bridge, relaunch it or wait for it.

use crate::error::DomainError;
use crate::jsonrpc::{self, Incoming};
use crate::model::{RpcEnvelope, SessionRecord};
use crate::paths::atomic_write;
use crate::state::{ConnectionHandle, McpState};
use anyhow::Result;
use axum::extract::ws::{Message, Utf8Bytes, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as ClientWsMessage;
use uuid::Uuid;

/// The HTTP path of the bridge WebSocket.
pub const AGENT_WS_PATH: &str = "/ws/agent";
/// Default loopback port of an embedded `Bridge.java` WebSocket listener.
pub const DEFAULT_GUI_WS_PORT: u16 = 8765;
/// The file name of the Ghidra post-script that loads the bridge JAR.
pub const BRIDGE_SCRIPT_NAME: &str = "Bridge.java";
/// The file name of the Ghidra script that starts the standalone MCP HTTP server.
pub const MCP_SCRIPT_NAME: &str = "GhidraMcp.java";
/// The post-script that safely opens a saved program before it loads the bridge.
pub const SAVED_PROJECT_SCRIPT_NAME: &str = "OpenSavedProject.java";
/// The file name of the bridge JAR in the runtime directory.
pub const BRIDGE_JAR_NAME: &str = "ghidra-bridge.jar";
/// The bridge JAR. `cargo xtask` builds it, and the executable contains it.
const EMBEDDED_BRIDGE_JAR: &[u8] =
    include_bytes!("../bridge/build/ghidra-script/ghidra-bridge.jar");
/// The bridge post-script. `cargo xtask` makes it, and the executable contains it.
const EMBEDDED_BRIDGE_SCRIPT: &str = include_str!("../bridge/build/ghidra-script/Bridge.java");
/// The standalone MCP script. `cargo xtask` makes it, and the executable contains it.
const EMBEDDED_MCP_SCRIPT: &str = include_str!("../bridge/build/ghidra-script/GhidraMcp.java");
/// The post-script that opens a saved project. The executable contains it.
const EMBEDDED_SAVED_PROJECT_SCRIPT: &str = include_str!("../java/OpenSavedProject.java");

/// The paths that [`install_user_scripts`] writes into a Ghidra script directory.
#[derive(Debug, Clone)]
pub struct InstalledScripts {
    /// Target script directory.
    pub directory: PathBuf,
    /// Installed script and runtime JAR paths.
    pub files: [PathBuf; 3],
}

/// Validated loopback WebSocket endpoint for an embedded `Bridge.java` server.
#[derive(Debug, Clone)]
pub struct ValidatedGuiEndpoint {
    /// Normalized WebSocket URL for the HTTP upgrade request.
    request_url: String,
    /// Sanitized URL without query credentials.
    display_url: String,
    /// Loopback host (`127.x.x.x`, `::1`, or `localhost`).
    host: String,
    /// Loopback TCP port (`1..=65535`).
    port: u16,
}

/// Metadata returned after a connection to an embedded `Bridge.java` endpoint completes.
#[derive(Debug, Clone)]
pub struct EndpointAttach {
    /// Sanitized endpoint URL without query credentials.
    pub display_url: String,
    /// Session ID that `ghidra.ready` reported.
    pub bridge_session_id: String,
}

/// Split stream of an outbound WebSocket client connection.
type ClientWsStream = SplitStream<tokio_tungstenite::WebSocketStream<TcpStream>>;

/// The bridge methods with their descriptions, input schemas and effects.
static METHODS: LazyLock<Map<String, Value>> = LazyLock::new(|| {
    let contract: Value = serde_saphyr::from_str(include_str!("../bridge/docs/asyncapi.yaml"))
        .expect("parse the bridge AsyncAPI contract");
    let methods = contract["x-ghidra-bridge-methods"]
        .as_object()
        .cloned()
        .expect("bridge method metadata");
    assert!(!methods.is_empty(), "bridge method contract is empty");
    methods
});

/// Returns all bridge methods from the contract, with the name as key. Each
/// method has `description`, `input_schema` and `effects.read_only`.
pub fn methods() -> &'static Map<String, Value> {
    &METHODS
}

/// Serializes installation of the embedded bridge files in each runtime directory.
static RUNTIME_INSTALL_LOCKS: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Writes the embedded bridge JAR and script into `dir`, if they are not
/// current. Returns the path of the JAR. The script directory is `dir`.
pub fn install_runtime(dir: &Path) -> Result<PathBuf> {
    if !dir.is_dir() {
        fs::create_dir_all(dir)?;
    }
    let key = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let dir_lock = {
        let mut locks = RUNTIME_INSTALL_LOCKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let _guard = dir_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let jar = dir.join(BRIDGE_JAR_NAME);
    if fs::read(&jar).ok().as_deref() != Some(EMBEDDED_BRIDGE_JAR) {
        atomic_write(&jar, EMBEDDED_BRIDGE_JAR)?;
    }
    for (name, source) in [
        (BRIDGE_SCRIPT_NAME, EMBEDDED_BRIDGE_SCRIPT),
        (SAVED_PROJECT_SCRIPT_NAME, EMBEDDED_SAVED_PROJECT_SCRIPT),
    ] {
        let script = dir.join(name);
        if fs::read(&script).ok().as_deref() != Some(source.as_bytes()) {
            atomic_write(&script, source.as_bytes())?;
        }
    }
    Ok(jar)
}

/// Extracts `Bridge.java`, `GhidraMcp.java` and `ghidra-bridge.jar` into `dir` for Ghidra GUI use.
///
/// # Errors
///
/// Fails if `dir` cannot be created or if any distribution file write fails.
pub fn install_user_scripts(dir: &Path) -> Result<InstalledScripts> {
    fs::create_dir_all(dir)?;
    let bridge_script = dir.join(BRIDGE_SCRIPT_NAME);
    let mcp_script = dir.join(MCP_SCRIPT_NAME);
    let jar = dir.join(BRIDGE_JAR_NAME);
    for (path, bytes) in [
        (&bridge_script, EMBEDDED_BRIDGE_SCRIPT.as_bytes()),
        (&mcp_script, EMBEDDED_MCP_SCRIPT.as_bytes()),
        (&jar, EMBEDDED_BRIDGE_JAR),
    ] {
        if fs::read(path).ok().as_deref() != Some(bytes) {
            atomic_write(path, bytes)?;
        }
    }
    Ok(InstalledScripts {
        directory: dir.to_path_buf(),
        files: [bridge_script, mcp_script, jar],
    })
}

/// Sends one request on the current connection of the session, and waits for its response.
pub async fn request(
    state: &McpState,
    md5: &str,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<RpcEnvelope> {
    if !METHODS.contains_key(method) {
        return Err(DomainError::invalid_argument(
            "method",
            format!("method is not on the ghidra-mcp allowlist: {method}"),
        )
        .into());
    }
    let request_lock = state.request_lock(md5)?;
    let start = Instant::now();
    let _guard = tokio::time::timeout(timeout, request_lock.lock_owned())
        .await
        .map_err(|_| DomainError::session_lock_timeout(md5, timeout.as_secs()))?;
    let remaining = timeout.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return Err(DomainError::AgentTimeout {
            md5: md5.to_string(),
            timeout_seconds: Some(0),
        }
        .into());
    }
    request_locked(state, md5, method, params, remaining, timeout.as_secs()).await
}

/// Sends one request when the caller already holds the `request_lock` of `md5`.
pub async fn request_locked(
    state: &McpState,
    md5: &str,
    method: &str,
    params: Value,
    timeout: Duration,
    reported_timeout_secs: u64,
) -> Result<RpcEnvelope> {
    if !METHODS.contains_key(method) {
        return Err(DomainError::invalid_argument(
            "method",
            format!("method is not on the ghidra-mcp allowlist: {method}"),
        )
        .into());
    }
    let request_id = Uuid::new_v4().to_string();
    let wire = jsonrpc::encode_request(&request_id, method, params)?;
    let (sender, receiver) = oneshot::channel();
    let connection = state.begin_request(md5, &request_id, sender)?;
    let mut guard = PendingRequestGuard::new(state, md5, &request_id);
    if connection.sender.send(Message::Text(wire.into())).is_err() {
        return Err(DomainError::disconnected(md5).into());
    }
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(response)) => {
            guard.defuse();
            Ok(response)
        }
        outcome => match outcome {
            Err(_) => Err(DomainError::AgentTimeout {
                md5: md5.to_string(),
                timeout_seconds: Some(reported_timeout_secs),
            }
            .into()),
            _ => Err(DomainError::disconnected(md5).into()),
        },
    }
}

/// RAII guard that cancels an in-flight request if the future drops before completion.
struct PendingRequestGuard<'a> {
    /// Reference to the shared state.
    state: &'a McpState,
    /// Target session MD5.
    md5: &'a str,
    /// Unique request identifier.
    request_id: &'a str,
    /// True when the guard cancels the request on drop.
    active: bool,
}

impl<'a> PendingRequestGuard<'a> {
    /// Creates a new guard for an active in-flight request.
    fn new(state: &'a McpState, md5: &'a str, request_id: &'a str) -> Self {
        Self {
            state,
            md5,
            request_id,
            active: true,
        }
    }

    /// Disables the guard when the response arrives.
    fn defuse(&mut self) {
        self.active = false;
    }
}

impl Drop for PendingRequestGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            self.state.abandon_request(self.md5, self.request_id);
        }
    }
}

/// Returns the credential of one `Authorization: Bearer <token>` header.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_string())
}

/// The query string of a bridge WebSocket request.
#[derive(Deserialize)]
pub struct WsQuery {
    /// The bridge sends its credential in a header. The daemon refuses a token in the query string.
    token: Option<String>,
}

/// Authenticates a bridge WebSocket request and upgrades its connection.
pub async fn agent_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<McpState>>,
    headers: HeaderMap,
    Query(query): Query<WsQuery>,
) -> Response {
    let reject = |status: StatusCode, message: &str| {
        (status, Json(json!({ "error": message }))).into_response()
    };
    if query.token.is_some() {
        return reject(
            StatusCode::BAD_REQUEST,
            "agent token must not be sent in the query string",
        );
    }
    let Some(token) = bearer_token(&headers) else {
        return reject(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let Some(md5) = state.session_for_token(&token) else {
        return reject(StatusCode::UNAUTHORIZED, "unknown or stale bearer token");
    };
    if state.connection(&md5).is_some() {
        return reject(
            StatusCode::CONFLICT,
            "session already has an active agent connection",
        );
    }
    ws.on_upgrade(move |socket| handle_socket(state, socket, md5, token))
}

/// The result of the handshake of a connection.
enum Handshake {
    /// The connection is now the bridge of the session.
    Accepted,
    /// A different connection is the bridge of the session.
    Duplicate,
    /// No valid `ghidra.ready` arrived in time, or the session does not wait for one now.
    Failed,
}

/// Runs one bridge connection, from its handshake to its cleanup.
async fn handle_socket(state: Arc<McpState>, socket: WebSocket, md5: String, token: String) {
    let conn_id = Uuid::new_v4().to_string();
    let (mut sink, mut stream) = socket.split();
    let (sender, mut outgoing) = mpsc::unbounded_channel::<Message>();
    let send_task = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });
    let handle = ConnectionHandle {
        conn_id: conn_id.clone(),
        sender,
    };
    match handshake(&state, &mut stream, &md5, &token, handle).await {
        Handshake::Accepted => {
            serve(&state, &mut stream, &md5, &conn_id).await;
            on_disconnect(&state, &md5, &token, &conn_id).await;
        }
        Handshake::Duplicate => {}
        Handshake::Failed => on_failed_handshake(&state, &md5, &token).await,
    }
    send_task.abort();
}

/// Waits for `ghidra.ready`. It must be the first message and must arrive in
/// time. Then the function attaches the connection and sets the session to
/// ready. The launch wait completes the job after the daemon records the process.
async fn handshake(
    state: &McpState,
    stream: &mut SplitStream<WebSocket>,
    md5: &str,
    token: &str,
    handle: ConnectionHandle,
) -> Handshake {
    let deadline = Instant::now() + state.config.timeouts.agent_ready;
    let Ok(Some(text)) = tokio::time::timeout_at(deadline, next_text(stream)).await else {
        return Handshake::Failed;
    };
    let Ok(Incoming::Ready { program_name }) = jsonrpc::decode_incoming(&text, md5) else {
        return Handshake::Failed;
    };
    let Ok(lock) = state.lifecycle_lock(md5) else {
        return Handshake::Failed;
    };
    let _guard = lock.lock_owned().await;
    let Some(current) = state
        .session_with_token(md5, token)
        .filter(|session| session.status.is_launching())
    else {
        return Handshake::Failed;
    };
    if !state.attach_bridge(md5, handle) {
        return Handshake::Duplicate;
    }
    let _ = state.update_session(md5, |session| {
        if session.attached
            && session.file_name == crate::session::DEFAULT_ATTACHED_NAME
            && crate::project::validate_file_name(&program_name).is_ok()
        {
            session.file_name.clone_from(&program_name);
        }
        session.mark_ready();
    });
    if current.attached {
        if let Some(job_id) = state.launch_job(md5) {
            state.finish_job(
                &job_id,
                Ok(json!({ "md5": md5, "status": crate::model::SessionStatus::Ready })),
            );
        }
    }
    Handshake::Accepted
}

/// Sends responses to their callers until the socket closes or sends an invalid message.
async fn serve(state: &McpState, stream: &mut SplitStream<WebSocket>, md5: &str, conn_id: &str) {
    while let Some(text) = next_text(stream).await {
        match jsonrpc::decode_incoming(&text, md5) {
            Ok(Incoming::Response { id, envelope }) => {
                state.deliver_response(md5, conn_id, &id, *envelope);
            }
            Ok(Incoming::ProtocolError(envelope)) => {
                state.deliver_protocol_error(md5, conn_id, *envelope);
            }
            Ok(_) => {}
            Err(err) => {
                crate::process::record_daemon_error(&format!(
                    "failed to decode incoming bridge message for {md5}: {err:#}"
                ));
                break;
            }
        }
    }
}

/// Returns the next text frame, and ignores other frames. Returns `None` when
/// the socket closes or fails.
async fn next_text(stream: &mut SplitStream<WebSocket>) -> Option<Utf8Bytes> {
    while let Some(Ok(message)) = stream.next().await {
        if let Message::Text(text) = message {
            return Some(text);
        }
    }
    None
}

/// Sets a connected session to disconnected. Stops its process after the grace period.
async fn on_disconnect(state: &McpState, md5: &str, token: &str, conn_id: &str) {
    let Ok(lock) = state.lifecycle_lock(md5) else {
        return;
    };
    let _guard = lock.lock_owned().await;
    // A relaunch replaced the session of this socket.
    if state.session_with_token(md5, token).is_none()
        || !state.detach_bridge_if_current(md5, conn_id, "bridge disconnected")
    {
        return;
    }
    state
        .stop_process(md5, state.config.timeouts.bridge_disconnect_grace)
        .await;
    let _ = state.update_session(md5, SessionRecord::mark_disconnected);
}

/// Fails a launch if its bridge did not complete the handshake.
async fn on_failed_handshake(state: &McpState, md5: &str, token: &str) {
    let Ok(lock) = state.lifecycle_lock(md5) else {
        return;
    };
    let job_id = {
        let _guard = lock.lock_owned().await;
        let launching = state
            .session_with_token(md5, token)
            .is_some_and(|session| session.status.is_launching());
        let Some(job_id) = state.launch_job(md5).filter(|_| launching) else {
            return;
        };
        state.stop_process(md5, Duration::ZERO).await;
        job_id
    };
    state
        .fail_launch(
            md5,
            &job_id,
            DomainError::Internal {
                message: "bridge failed to send a valid ghidra.ready message".to_string(),
            },
        )
        .await;
}

/// Formats the default loopback `Bridge.java` WebSocket URL for `port`.
///
/// # Errors
///
/// Fails if `port` is `0`.
pub fn gui_ws_url_for_port(port: u16) -> Result<String> {
    if port == 0 {
        return Err(
            DomainError::invalid_argument("port", "port must be between 1 and 65535").into(),
        );
    }
    Ok(format!("ws://127.0.0.1:{port}{AGENT_WS_PATH}"))
}

/// Validates an optional bearer token for an outbound `Authorization` header.
///
/// # Errors
///
/// Fails if `token` is blank or contains invalid HTTP header bytes.
pub fn validate_bearer_token(token: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = token else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(
            DomainError::invalid_argument("token", "bearer token must not be empty").into(),
        );
    }
    HeaderValue::from_str(&format!("Bearer {trimmed}")).map_err(|_| {
        DomainError::invalid_argument("token", "bearer token contains invalid header characters")
    })?;
    Ok(Some(trimmed.to_string()))
}

/// Parses and validates a loopback `ws://` URL for an embedded `Bridge.java` server.
///
/// # Errors
///
/// Fails if `raw` is not a loopback `ws://` URL or passes `token` in the query string.
pub fn parse_gui_ws_url(raw: &str) -> Result<ValidatedGuiEndpoint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DomainError::invalid_argument("wsUrl", "wsUrl must not be empty").into());
    }
    if trimmed.contains('#') {
        return Err(DomainError::invalid_argument(
            "wsUrl",
            "wsUrl must not contain a URL fragment",
        )
        .into());
    }
    let uri: Uri = trimmed
        .parse()
        .map_err(|err| DomainError::invalid_argument("wsUrl", format!("invalid wsUrl: {err}")))?;
    if !uri
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("ws"))
    {
        return Err(DomainError::invalid_argument(
            "wsUrl",
            "wsUrl must use the ws:// scheme on a loopback address",
        )
        .into());
    }
    let Some(authority) = uri.authority() else {
        return Err(DomainError::invalid_argument("wsUrl", "wsUrl must include a host").into());
    };
    if authority.as_str().contains('@') {
        return Err(DomainError::invalid_argument(
            "wsUrl",
            "wsUrl must not include user credentials",
        )
        .into());
    }
    let raw_host = authority.host();
    let bare_host = raw_host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(raw_host);
    let is_loopback = bare_host.eq_ignore_ascii_case("localhost")
        || bare_host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !is_loopback {
        return Err(DomainError::invalid_argument(
            "wsUrl",
            "wsUrl host must be a loopback address (127.0.0.1, ::1, or localhost)",
        )
        .into());
    }
    let port = match authority.port_u16() {
        Some(0) => {
            return Err(DomainError::invalid_argument(
                "wsUrl",
                "wsUrl port must be between 1 and 65535",
            )
            .into());
        }
        Some(port) => port,
        None => DEFAULT_GUI_WS_PORT,
    };
    let (request_suffix, display_suffix) = build_ws_path_and_query(&uri)?;
    let host_lower = bare_host.to_ascii_lowercase();
    let authority_host = if host_lower.contains(':') {
        format!("[{host_lower}]")
    } else {
        host_lower.clone()
    };
    Ok(ValidatedGuiEndpoint {
        request_url: format!("ws://{authority_host}:{port}{request_suffix}"),
        display_url: format!("ws://{authority_host}:{port}{display_suffix}"),
        host: host_lower,
        port,
    })
}

/// Normalizes the path and query string of a GUI `ws://` URI and rejects query tokens.
fn build_ws_path_and_query(uri: &Uri) -> Result<(String, String)> {
    let raw_path = uri.path();
    let path = if raw_path.is_empty() || raw_path == "/" {
        AGENT_WS_PATH
    } else {
        raw_path
    };
    let Some(query) = uri.query().filter(|query| !query.is_empty()) else {
        return Ok((path.to_string(), path.to_string()));
    };
    for pair in query.split('&') {
        let key = pair.split('=').next().unwrap_or("");
        if key.eq_ignore_ascii_case("token") {
            return Err(DomainError::invalid_argument(
                "wsUrl",
                "wsUrl must not pass token in the query string; use token instead",
            )
            .into());
        }
    }
    Ok((format!("{path}?{query}"), format!("{path}?<redacted>")))
}

/// Connects to an embedded `Bridge.java` server, reads `ghidra.ready`, and attaches the session.
///
/// # Errors
///
/// Fails if the socket, handshake, or initial `ghidra.ready` message fails or times out.
pub async fn connect_gui_endpoint(
    state: Arc<McpState>,
    md5: &str,
    session_token: &str,
    endpoint: ValidatedGuiEndpoint,
    bearer_token: Option<&str>,
    timeout: Duration,
) -> Result<EndpointAttach> {
    let mut request = endpoint
        .request_url
        .as_str()
        .into_client_request()
        .map_err(|err| {
            DomainError::invalid_argument("wsUrl", format!("invalid WebSocket request: {err}"))
        })?;
    if let Some(token) = bearer_token {
        let value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
            DomainError::invalid_argument("token", "bearer token contains invalid header bytes")
        })?;
        request.headers_mut().insert(header::AUTHORIZATION, value);
    }
    let deadline = Instant::now() + timeout;
    let (mut stream, sender, send_task, bridge_session_id, program_name) =
        dial_gui_endpoint(md5, &endpoint, request, deadline, timeout).await?;
    let conn_id = Uuid::new_v4().to_string();
    register_endpoint_connection(
        &state,
        md5,
        session_token,
        &conn_id,
        sender.clone(),
        &program_name,
        &send_task,
    )
    .await?;
    let md5_owned = md5.to_string();
    let token_owned = session_token.to_string();
    tokio::spawn(async move {
        serve_client(&state, &mut stream, &sender, &md5_owned, &conn_id).await;
        on_disconnect(&state, &md5_owned, &token_owned, &conn_id).await;
        send_task.abort();
    });
    Ok(EndpointAttach {
        display_url: endpoint.display_url,
        bridge_session_id,
    })
}

/// Dials the loopback TCP socket, upgrades to WebSocket, and decodes the first `ghidra.ready`.
async fn dial_gui_endpoint(
    md5: &str,
    endpoint: &ValidatedGuiEndpoint,
    request: axum::http::Request<()>,
    deadline: Instant,
    timeout: Duration,
) -> Result<(
    ClientWsStream,
    mpsc::UnboundedSender<Message>,
    tokio::task::JoinHandle<()>,
    String,
    String,
)> {
    let tcp = match tokio::time::timeout_at(
        deadline,
        open_loopback_socket(&endpoint.host, endpoint.port),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(DomainError::Internal {
                message: format!(
                    "cannot connect to Bridge.java at {}: {err}",
                    endpoint.display_url
                ),
            }
            .into());
        }
        Err(_) => {
            return Err(DomainError::AgentTimeout {
                md5: md5.to_string(),
                timeout_seconds: Some(timeout.as_secs()),
            }
            .into());
        }
    };
    let (ws_stream, _) = match tokio::time::timeout_at(
        deadline,
        tokio_tungstenite::client_async(request, tcp),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(err)) => {
            return Err(DomainError::Internal {
                message: format!(
                    "WebSocket handshake with {} failed: {err}",
                    endpoint.display_url
                ),
            }
            .into());
        }
        Err(_) => {
            return Err(DomainError::AgentTimeout {
                md5: md5.to_string(),
                timeout_seconds: Some(timeout.as_secs()),
            }
            .into());
        }
    };
    let (mut sink, mut stream) = ws_stream.split();
    let (sender, mut outgoing) = mpsc::unbounded_channel::<Message>();
    let send_task = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            if sink.send(axum_to_client_message(message)).await.is_err() {
                break;
            }
        }
    });
    let text = match tokio::time::timeout_at(deadline, next_client_text(&mut stream, &sender)).await
    {
        Ok(Some(text)) => text,
        Ok(None) => {
            send_task.abort();
            return Err(DomainError::Internal {
                message: format!(
                    "Bridge.java at {} closed before ghidra.ready",
                    endpoint.display_url
                ),
            }
            .into());
        }
        Err(_) => {
            send_task.abort();
            return Err(DomainError::AgentTimeout {
                md5: md5.to_string(),
                timeout_seconds: Some(timeout.as_secs()),
            }
            .into());
        }
    };
    match jsonrpc::decode_endpoint_ready(&text) {
        Ok((bridge_session_id, program_name)) => {
            Ok((stream, sender, send_task, bridge_session_id, program_name))
        }
        Err(err) => {
            send_task.abort();
            Err(DomainError::Internal {
                message: format!(
                    "Bridge.java at {} sent an invalid ghidra.ready frame: {err}",
                    endpoint.display_url
                ),
            }
            .into())
        }
    }
}

/// Attaches a verified GUI client connection to `md5` and marks its launch job complete.
async fn register_endpoint_connection(
    state: &McpState,
    md5: &str,
    session_token: &str,
    conn_id: &str,
    sender: mpsc::UnboundedSender<Message>,
    program_name: &str,
    send_task: &tokio::task::JoinHandle<()>,
) -> Result<()> {
    let lock = state.lifecycle_lock(md5)?;
    let _guard = lock.lock_owned().await;
    let current = state
        .session_with_token(md5, session_token)
        .is_some_and(|session| session.status.is_launching());
    if !current {
        send_task.abort();
        return Err(
            DomainError::missing_target(md5, "session attach was replaced or closed").into(),
        );
    }
    let handle = ConnectionHandle {
        conn_id: conn_id.to_string(),
        sender,
    };
    if !state.attach_bridge(md5, handle) {
        send_task.abort();
        return Err(DomainError::Internal {
            message: format!("session {md5} already has an active bridge connection"),
        }
        .into());
    }
    let _ = state.update_session(md5, |session| {
        if session.attached
            && session.file_name == crate::session::DEFAULT_ATTACHED_NAME
            && crate::project::validate_file_name(program_name).is_ok()
        {
            session.file_name = program_name.to_string();
        }
        session.mark_ready();
    });
    if let Some(job_id) = state.launch_job(md5) {
        state.finish_job(
            &job_id,
            Ok(json!({ "md5": md5, "status": crate::model::SessionStatus::Ready })),
        );
    }
    Ok(())
}

/// Opens a TCP connection strictly to a loopback IP address.
async fn open_loopback_socket(host: &str, port: u16) -> Result<TcpStream> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        anyhow::ensure!(ip.is_loopback(), "endpoint IP is not loopback");
        return Ok(TcpStream::connect(SocketAddr::new(ip, port)).await?);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await?
        .filter(|addr| addr.ip().is_loopback())
        .collect();
    anyhow::ensure!(
        !addrs.is_empty(),
        "localhost did not resolve to a loopback address"
    );
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.map_or_else(
        || anyhow::anyhow!("cannot connect to loopback endpoint"),
        anyhow::Error::from,
    ))
}

/// Converts an Axum WebSocket frame into a Tungstenite client frame.
fn axum_to_client_message(message: Message) -> ClientWsMessage {
    match message {
        Message::Text(text) => ClientWsMessage::Text(text.as_str().into()),
        Message::Binary(bytes) => ClientWsMessage::Binary(bytes),
        Message::Ping(bytes) => ClientWsMessage::Ping(bytes),
        Message::Pong(bytes) => ClientWsMessage::Pong(bytes),
        Message::Close(_) => ClientWsMessage::Close(None),
    }
}

/// Reads the next text frame from an outbound WebSocket stream and answers pings.
async fn next_client_text(
    stream: &mut ClientWsStream,
    sender: &mpsc::UnboundedSender<Message>,
) -> Option<String> {
    while let Some(Ok(frame)) = stream.next().await {
        match frame {
            ClientWsMessage::Text(text) => return Some(text.to_string()),
            ClientWsMessage::Ping(payload) => {
                let _ = sender.send(Message::Pong(payload));
            }
            ClientWsMessage::Close(_) => return None,
            _ => {}
        }
    }
    None
}

/// Dispatches responses from an outbound WebSocket stream until the socket closes.
async fn serve_client(
    state: &McpState,
    stream: &mut ClientWsStream,
    sender: &mpsc::UnboundedSender<Message>,
    md5: &str,
    conn_id: &str,
) {
    while let Some(text) = next_client_text(stream, sender).await {
        match jsonrpc::decode_incoming(&text, md5) {
            Ok(Incoming::Response { id, envelope }) => {
                state.deliver_response(md5, conn_id, &id, *envelope);
            }
            Ok(Incoming::ProtocolError(envelope)) => {
                state.deliver_protocol_error(md5, conn_id, *envelope);
            }
            Ok(_) => {}
            Err(err) => {
                crate::process::record_daemon_error(&format!(
                    "failed to decode incoming bridge message for {md5}: {err:#}"
                ));
                break;
            }
        }
    }
}
