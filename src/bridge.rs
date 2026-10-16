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
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use uuid::Uuid;

/// The HTTP path of the bridge WebSocket.
pub const AGENT_WS_PATH: &str = "/ws/agent";
/// The file name of the Ghidra post-script that loads the bridge JAR.
pub const BRIDGE_SCRIPT_NAME: &str = "Bridge.java";
/// The post-script that safely opens a saved program before it loads the bridge.
pub const SAVED_PROJECT_SCRIPT_NAME: &str = "OpenSavedProject.java";
/// The file name of the bridge JAR in the runtime directory.
pub const BRIDGE_JAR_NAME: &str = "ghidra-bridge.jar";
/// The bridge JAR. `cargo xtask` builds it, and the executable contains it.
const EMBEDDED_BRIDGE_JAR: &[u8] =
  include_bytes!("../bridge/build/ghidra-script/ghidra-bridge.jar");
/// The bridge post-script. `cargo xtask` makes it, and the executable contains it.
const EMBEDDED_BRIDGE_SCRIPT: &str = include_str!("../bridge/build/ghidra-script/Bridge.java");
/// The post-script that opens a saved project. The executable contains it.
const EMBEDDED_SAVED_PROJECT_SCRIPT: &str = include_str!("../java/OpenSavedProject.java");

/// The bridge methods with their descriptions, input schemas and effects.
static METHODS: LazyLock<Map<String, Value>> = LazyLock::new(|| {
  // The bridge build makes the AsyncAPI document in JSON syntax, which is also valid YAML.
  let contract: Value = serde_json::from_str(include_str!("../bridge/docs/asyncapi.yaml"))
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

/// Writes the embedded bridge JAR and script into `dir`, if they are not
/// current. Returns the path of the JAR. The script directory is `dir`.
pub fn install_runtime(dir: &Path) -> Result<PathBuf> {
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

/// Sends one request on the current connection of the session, and waits for its response.
pub async fn request(
  state: &McpState,
  md5: &str,
  method: &str,
  params: Value,
  timeout: Duration,
) -> Result<RpcEnvelope> {
  if !METHODS.contains_key(method) {
    return Err(
      DomainError::invalid_argument(
        "method",
        format!("method is not on the ghidra-mcp allowlist: {method}"),
      )
      .into(),
    );
  }
  let request_lock = state.request_lock(md5)?;
  let start = Instant::now();
  let _guard = tokio::time::timeout(timeout, request_lock.lock_owned())
    .await
    .map_err(|_| DomainError::session_lock_timeout(md5, timeout.as_secs()))?;
  let remaining = timeout.saturating_sub(start.elapsed());
  if remaining.is_zero() {
    return Err(
      DomainError::AgentTimeout {
        md5: md5.to_string(),
        timeout_seconds: Some(0),
      }
      .into(),
    );
  }
  let request_id = Uuid::new_v4().to_string();
  let wire = jsonrpc::encode_request(&request_id, method, params)?;
  let (sender, receiver) = oneshot::channel();
  let connection = state.begin_request(md5, &request_id, sender)?;
  let mut guard = PendingRequestGuard::new(state, md5, &request_id);
  if connection.sender.send(Message::Text(wire.into())).is_err() {
    return Err(DomainError::disconnected(md5).into());
  }
  match tokio::time::timeout(remaining, receiver).await {
    Ok(Ok(response)) => {
      guard.defuse();
      Ok(response)
    }
    outcome => match outcome {
      Err(_) => Err(
        DomainError::AgentTimeout {
          md5: md5.to_string(),
          timeout_seconds: Some(timeout.as_secs()),
        }
        .into(),
      ),
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
  let reject =
    |status: StatusCode, message: &str| (status, Json(json!({ "error": message }))).into_response();
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
  if !matches!(jsonrpc::decode_incoming(&text, md5), Ok(Incoming::Ready)) {
    return Handshake::Failed;
  }
  let _guard = state.lifecycle_lock.lock().await;
  if !state
    .session_with_token(md5, token)
    .is_some_and(|session| session.status.is_launching())
  {
    return Handshake::Failed;
  }
  if !state.attach_bridge(md5, handle) {
    return Handshake::Duplicate;
  }
  let _ = state.update_session(md5, SessionRecord::mark_ready);
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
  let _guard = state.lifecycle_lock.lock().await;
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
  let job_id = {
    let _guard = state.lifecycle_lock.lock().await;
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
