// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Outbound WebSocket client for a loopback Ghidra GUI bridge listener.

use super::{on_disconnect, AGENT_WS_PATH, DEFAULT_GUI_WS_PORT};
use crate::error::DomainError;
use crate::jsonrpc::{self, Incoming};
use crate::state::{ConnectionHandle, McpState};
use anyhow::Result;
use axum::extract::ws::Message;
use axum::http::{header, HeaderValue, Uri};
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as ClientWsMessage;
use uuid::Uuid;

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
