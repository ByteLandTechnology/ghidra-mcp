// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! MCP through Streamable HTTP and the legacy SSE transport.
//!
//! Both transports use `/mcp`. Streamable HTTP sends JSON-RPC requests directly
//! to that path. A legacy SSE client first opens `GET /mcp`. The server sends an
//! `endpoint` event with a session-specific path. The client sends its JSON-RPC
//! messages to that path, and receives responses as `message` events.

use crate::mcp::ToolServer;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, uri::Authority, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Router,
};
use futures::Stream;
use rmcp::{
    handler::server::ServerHandler,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ServiceExt,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The maximum size of an MCP POST body.
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The capacity of each side of a legacy SSE in-process transport.
const LEGACY_TRANSPORT_CAPACITY: usize = 64 * 1024;

/// The number of queued events that one legacy SSE session can keep.
const LEGACY_EVENT_CAPACITY: usize = 1;

/// The interval between comments that maintain a legacy SSE connection.
const SSE_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// The maximum time to queue an event for a legacy SSE client.
const SSE_EVENT_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Makes the MCP HTTP router.
pub fn router(
    server: ToolServer,
    authorities: [String; 2],
    cancellation: CancellationToken,
) -> Router {
    router_for(server, authorities, cancellation)
}

/// Makes the MCP HTTP router for one server handler.
fn router_for<S>(server: S, authorities: [String; 2], cancellation: CancellationToken) -> Router
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    let config = StreamableHttpServerConfig::default()
        .with_cancellation_token(cancellation.child_token())
        .with_allowed_hosts(authorities.iter().cloned())
        .disable_allowed_origins()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        // The compatibility middleware already put each POST in a bounded buffer.
        .with_max_request_body_bytes(usize::MAX);
    let http_server = server.clone();
    let http = StreamableHttpService::new(
        move || Ok::<_, std::io::Error>(http_server.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let compatibility = Compatibility::new(server, authorities, cancellation);
    Router::new()
        .route_service("/mcp", http)
        .layer(middleware::from_fn_with_state(
            compatibility,
            compatibility_middleware::<S>,
        ))
}

/// Shared state for the HTTP compatibility layer.
#[derive(Clone)]
struct Compatibility<S> {
    /// Makes a server for each legacy SSE session.
    server: S,
    /// The permitted `host:port` forms of the listener.
    authorities: [String; 2],
    /// Stops all legacy SSE sessions during daemon shutdown.
    cancellation: CancellationToken,
    /// Active legacy SSE sessions, by their query parameter.
    sessions: Arc<Mutex<HashMap<String, LegacySession>>>,
}

impl<S> Compatibility<S>
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    /// Makes an empty compatibility layer.
    fn new(server: S, authorities: [String; 2], cancellation: CancellationToken) -> Self {
        Self {
            server,
            authorities,
            cancellation,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Opens a legacy SSE session and returns its event stream.
    fn open_legacy_sse(&self) -> Response {
        let id = Uuid::new_v4().to_string();
        let endpoint = format!("?sessionId={id}");
        let session_cancel = self.cancellation.child_token();
        let (server_io, client_io) = tokio::io::duplex(LEGACY_TRANSPORT_CAPACITY);
        let (output, input) = tokio::io::split(client_io);
        let (events, receiver) = mpsc::channel(LEGACY_EVENT_CAPACITY);
        let session = LegacySession {
            input: Arc::new(tokio::sync::Mutex::new(input)),
            cancellation: session_cancel.clone(),
        };
        self.sessions
            .lock()
            .expect("legacy SSE sessions lock poisoned")
            .insert(id.clone(), session);

        spawn_legacy_server(self.server.clone(), server_io, session_cancel.clone());
        tokio::spawn(forward_legacy_output(output, events, session_cancel));

        let stream = LegacyEventStream {
            endpoint: Some(endpoint),
            receiver,
            id,
            sessions: self.sessions.clone(),
        };
        let mut response = Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(SSE_KEEP_ALIVE).text("keepalive"))
            .into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-transform"),
        );
        response
            .headers_mut()
            .insert("x-accel-buffering", HeaderValue::from_static("no"));
        response
    }

    /// Sends one JSON-RPC message to a legacy SSE session.
    async fn send_legacy(&self, id: &str, body: Body) -> Response {
        let Some(session) = self
            .sessions
            .lock()
            .expect("legacy SSE sessions lock poisoned")
            .get(id)
            .cloned()
        else {
            return legacy_rpc_error(StatusCode::NOT_FOUND, "SSE session not found or expired");
        };
        let bytes = match tokio::select! {
          biased;
          () = session.cancellation.cancelled() => None,
          result = to_bytes(body, MAX_REQUEST_BODY_BYTES) => Some(result),
        } {
            None => {
                return rejection(StatusCode::SERVICE_UNAVAILABLE, "MCP session is closed")
                    .into_response()
            }
            Some(Ok(bytes)) => normalize_message_body(&bytes),
            Some(Err(_)) => {
                return rejection(StatusCode::PAYLOAD_TOO_LARGE, "MCP request is too large")
                    .into_response()
            }
        };
        let write = async {
            let mut input = session.input.lock().await;
            input.write_all(&bytes).await?;
            input.write_all(b"\n").await?;
            input.flush().await
        };
        let sent = tokio::select! {
          biased;
          () = session.cancellation.cancelled() => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "MCP session is closed",
          )),
          result = write => result,
        };
        if sent.is_err() {
            self.remove_session(id);
            return legacy_rpc_error(StatusCode::NOT_FOUND, "SSE session not found or expired");
        }
        StatusCode::ACCEPTED.into_response()
    }

    /// Removes and stops one legacy SSE session.
    fn remove_session(&self, id: &str) {
        if let Some(session) = self
            .sessions
            .lock()
            .expect("legacy SSE sessions lock poisoned")
            .remove(id)
        {
            session.cancellation.cancel();
        }
    }
}

/// One active legacy SSE session.
#[derive(Clone)]
struct LegacySession {
    /// Receives JSON-RPC messages from HTTP POST requests.
    input: Arc<tokio::sync::Mutex<WriteHalf<DuplexStream>>>,
    /// Stops the in-process MCP server for this session.
    cancellation: CancellationToken,
}

/// Adapts HTTP requests before the Streamable HTTP service receives them.
async fn compatibility_middleware<S>(
    State(state): State<Compatibility<S>>,
    mut request: Request,
    next: Next,
) -> Response
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    let origin = match validate_request(request.uri(), request.headers(), &state.authorities) {
        Ok(origin) => origin,
        Err(error) => return error.into_response(),
    };
    let method = request.method().clone();
    let mut response = if method == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else if method == Method::HEAD {
        StatusCode::OK.into_response()
    } else if method == Method::GET && opens_legacy_sse(request.headers()) {
        state.open_legacy_sse()
    } else if method == Method::POST {
        if is_json_content_type(request.headers()) {
            request.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if let Some(id) = legacy_session_id(request.uri()).map(str::to_owned) {
                state.send_legacy(&id, request.into_body()).await
            } else {
                match normalize_message_request(request, &state.cancellation).await {
                    Ok(request) => next.run(request).await,
                    Err(error) => error.into_response(),
                }
            }
        } else {
            rejection(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json",
            )
            .into_response()
        }
    } else {
        let mut response = legacy_rpc_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Only GET, POST, HEAD and OPTIONS are supported for this MCP endpoint",
        );
        response.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static("POST, GET, HEAD, OPTIONS"),
        );
        response
    };
    add_cors_headers(response.headers_mut(), origin.as_ref());
    response
}

/// Starts rmcp for one legacy SSE session.
fn spawn_legacy_server<S>(server: S, io: DuplexStream, cancellation: CancellationToken)
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    tokio::spawn(async move {
        match server.serve_with_ct(io, cancellation).await {
            Ok(service) => {
                let _ = service.waiting().await;
            }
            Err(error) => {
                crate::process::log_daemon(&format!("legacy SSE MCP connection failed: {error}"));
            }
        }
    });
}

/// Sends newline-delimited rmcp output to the SSE event queue.
async fn forward_legacy_output(
    output: ReadHalf<DuplexStream>,
    events: mpsc::Sender<String>,
    cancellation: CancellationToken,
) {
    let mut lines = BufReader::new(output).lines();
    loop {
        let line = tokio::select! {
          biased;
          () = cancellation.cancelled() => break,
          result = lines.next_line() => result,
        };
        let Ok(Some(line)) = line else {
            break;
        };
        if line.is_empty() {
            continue;
        }
        let sent = tokio::select! {
          biased;
          () = cancellation.cancelled() => break,
          result = tokio::time::timeout(SSE_EVENT_SEND_TIMEOUT, events.send(line)) => result,
        };
        if !matches!(sent, Ok(Ok(()))) {
            cancellation.cancel();
            break;
        }
    }
}

/// The event stream and cleanup guard of a legacy SSE session.
struct LegacyEventStream {
    /// The endpoint event that the stream sends first.
    endpoint: Option<String>,
    /// JSON-RPC messages from rmcp.
    receiver: mpsc::Receiver<String>,
    /// The session to remove when the HTTP client disconnects.
    id: String,
    /// All active sessions.
    sessions: Arc<Mutex<HashMap<String, LegacySession>>>,
}

impl Stream for LegacyEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(endpoint) = this.endpoint.take() {
            return Poll::Ready(Some(Ok(Event::default().event("endpoint").data(endpoint))));
        }
        Pin::new(&mut this.receiver)
            .poll_recv(context)
            .map(|message| {
                message.map(|message| Ok(Event::default().event("message").data(message)))
            })
    }
}

impl Drop for LegacyEventStream {
    fn drop(&mut self) {
        if let Some(session) = self
            .sessions
            .lock()
            .expect("legacy SSE sessions lock poisoned")
            .remove(&self.id)
        {
            session.cancellation.cancel();
        }
    }
}

/// Normalizes one Streamable HTTP JSON-RPC message.
async fn normalize_message_request(
    request: Request,
    cancellation: &CancellationToken,
) -> Result<Request, HttpRejection> {
    let (mut parts, body) = request.into_parts();
    let bytes = tokio::select! {
      biased;
      () = cancellation.cancelled() => {
        return Err(rejection(StatusCode::SERVICE_UNAVAILABLE, "daemon is shutting down"));
      }
      result = to_bytes(body, MAX_REQUEST_BODY_BYTES) => result,
    }
    .map_err(|_| rejection(StatusCode::PAYLOAD_TOO_LARGE, "MCP request is too large"))?;
    let body = normalize_message_body(&bytes);
    parts.headers.remove(header::CONTENT_LENGTH);
    Ok(Request::from_parts(parts, Body::from(body)))
}

/// Compacts a JSON-RPC message and adds absent initialize client information.
fn normalize_message_body(bytes: &[u8]) -> Vec<u8> {
    let Ok(mut message) = serde_json::from_slice::<Value>(bytes) else {
        return bytes.to_vec();
    };
    if message.get("method").and_then(Value::as_str) == Some("initialize") {
        if let Some(params) = message.get_mut("params").and_then(Value::as_object_mut) {
            if params.get("clientInfo").is_none_or(Value::is_null) {
                params.insert(
                    "clientInfo".to_string(),
                    json!({ "name": "legacy-client", "version": "unknown" }),
                );
            }
        }
    }
    serde_json::to_vec(&message).expect("JSON value is serializable")
}

/// Returns `true` when a GET request opens a legacy SSE stream.
fn opens_legacy_sse(headers: &HeaderMap) -> bool {
    !headers.contains_key("mcp-session-id")
        && !headers.contains_key("last-event-id")
        && !headers.contains_key("mcp-protocol-version")
        && single_header(headers, header::ACCEPT).is_some_and(accepts_event_stream)
}

/// Returns `true` if an Accept header permits an SSE response.
fn accepts_event_stream(accept: &str) -> bool {
    accept.split(',').any(|range| {
        let mut parts = range.split(';');
        let is_event_stream = parts
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"));
        let refused = parts.any(|parameter| {
            parameter
                .trim()
                .split_once('=')
                .is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("q") && quality_is_zero(value)
                })
        });
        is_event_stream && !refused
    })
}

/// Returns `true` when an HTTP quality value is zero.
fn quality_is_zero(value: &str) -> bool {
    value
        .trim()
        .parse::<f32>()
        .is_ok_and(|quality| quality == 0.0)
}

/// Returns the legacy SSE session query parameter.
fn legacy_session_id(uri: &Uri) -> Option<&str> {
    uri.query()?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == "sessionId").then_some(value)
    })
}

/// Returns `true` for a JSON HTTP content type.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    single_header(headers, header::CONTENT_TYPE)
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

/// Validates Host and Origin, and returns the Origin header for CORS.
fn validate_request(
    uri: &Uri,
    headers: &HeaderMap,
    authorities: &[String; 2],
) -> Result<Option<HeaderValue>, HttpRejection> {
    let host = if headers.contains_key(header::HOST) {
        single_header(headers, header::HOST)
    } else {
        uri.authority().map(Authority::as_str)
    };
    if !host.is_some_and(|host| authority_allowed(host, authorities)) {
        return Err(rejection(StatusCode::FORBIDDEN, "MCP Host is not allowed"));
    }
    if !headers.contains_key(header::ORIGIN) {
        return Ok(None);
    }
    let origin = single_header(headers, header::ORIGIN)
        .filter(|origin| valid_origin(origin))
        .ok_or_else(|| rejection(StatusCode::FORBIDDEN, "MCP Origin is not allowed"))?;
    HeaderValue::from_str(origin)
        .map(Some)
        .map_err(|_| rejection(StatusCode::BAD_REQUEST, "MCP Origin is not valid"))
}

/// Returns `true` if a Host value names the listener.
fn authority_allowed(value: &str, authorities: &[String; 2]) -> bool {
    let Ok(authority) = value.parse::<Authority>() else {
        return false;
    };
    authorities.iter().any(|allowed| {
        let allowed: Authority = allowed.parse().expect("bound listener authority is valid");
        authority.host().eq_ignore_ascii_case(allowed.host())
            && authority.port_u16() == allowed.port_u16()
    })
}

/// Returns `true` for an absolute HTTP or HTTPS Origin.
fn valid_origin(value: &str) -> bool {
    value.parse::<Uri>().is_ok_and(|origin| {
        origin.scheme_str().is_some_and(|scheme| {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        }) && origin.authority().is_some()
            && origin.path() == "/"
            && origin.query().is_none()
    })
}

/// Adds headers for browser MCP clients.
fn add_cors_headers(headers: &mut HeaderMap, origin: Option<&HeaderValue>) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        origin
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("*")),
    );
    if origin.is_some() {
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, HEAD, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Accept",
        ),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("MCP-Protocol-Version, Mcp-Session-Id"),
    );
}

/// Returns a header that occurs exactly one time.
fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

/// A fixed HTTP error response.
struct HttpRejection {
    /// The HTTP status.
    status: StatusCode,
    /// The public response text.
    message: &'static str,
}

impl IntoResponse for HttpRejection {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

/// Makes a fixed HTTP rejection.
fn rejection(status: StatusCode, message: &'static str) -> HttpRejection {
    HttpRejection { status, message }
}

/// Makes a JSON-RPC error for a legacy SSE POST.
fn legacy_rpc_error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        axum::Json(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": -32600, "message": message }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use rmcp::{
        model::{
            ErrorData, Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
            ServerInfo,
        },
        service::RequestContext,
        RoleServer,
    };
    use std::future::Future;
    use tower::ServiceExt as TowerServiceExt;

    /// A server that supplies the public tool without daemon state.
    #[derive(Clone)]
    struct TestServer;

    impl ServerHandler for TestServer {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
                .with_server_info(Implementation::new("test-server", "1"))
        }

        fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
            std::future::ready(Ok(ListToolsResult::with_all_items(ToolServer::tools())))
        }
    }

    /// Makes a test router on the default listener authority.
    fn test_router() -> Router {
        router_for(
            TestServer,
            ["127.0.0.1:18489".to_string(), "localhost:18489".to_string()],
            CancellationToken::new(),
        )
    }

    /// Makes one HTTP request with the permitted Host.
    fn test_request(method: Method, uri: &str, body: impl Into<Body>) -> Request {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "127.0.0.1:18489")
            .body(body.into())
            .expect("test request")
    }

    /// Returns the next non-keepalive SSE event.
    async fn next_sse_event(stream: &mut axum::body::BodyDataStream) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let chunk = stream
                    .next()
                    .await
                    .expect("SSE stream ended")
                    .expect("SSE body error");
                let text = String::from_utf8(chunk.to_vec()).expect("SSE is UTF-8");
                if text.lines().any(|line| line.starts_with("event:")) {
                    return text;
                }
            }
        })
        .await
        .expect("SSE event timed out")
    }

    /// Returns the data of one SSE event.
    fn sse_data(event: &str) -> String {
        event
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Sends one legacy SSE message.
    async fn legacy_post(app: &Router, endpoint: &str, message: &str) -> Response {
        let mut request = test_request(Method::POST, endpoint, message.to_string());
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        app.clone().oneshot(request).await.expect("legacy POST")
    }

    /// Makes sure that the server accepts HEAD, OPTIONS, and an external Origin.
    #[tokio::test]
    async fn supports_reachability_and_external_origins() {
        let app = test_router();
        for method in [Method::HEAD, Method::OPTIONS] {
            let mut request = test_request(method.clone(), "/mcp", Body::empty());
            request.headers_mut().insert(
                header::ORIGIN,
                HeaderValue::from_static("https://gemini.google.com"),
            );
            let response = app.clone().oneshot(request).await.expect("HTTP response");
            let expected = if method == Method::HEAD {
                StatusCode::OK
            } else {
                StatusCode::NO_CONTENT
            };
            assert_eq!(response.status(), expected);
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                Some(&HeaderValue::from_static("https://gemini.google.com"))
            );
        }

        let response = app
            .oneshot(test_request(Method::PUT, "/mcp", Body::empty()))
            .await
            .expect("method response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(header::ALLOW),
            Some(&HeaderValue::from_static("POST, GET, HEAD, OPTIONS"))
        );
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BODY_BYTES)
            .await
            .expect("method body");
        let text = String::from_utf8(bytes.to_vec()).expect("method body text");
        assert!(text.contains("GET, POST, HEAD and OPTIONS"));

        let mut request = test_request(Method::GET, "/mcp", Body::empty());
        request
            .headers_mut()
            .insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let response = test_router().oneshot(request).await.expect("GET response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let mut request = test_request(Method::GET, "/mcp", Body::empty());
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        request.headers_mut().insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-11-25"),
        );
        let response = test_router()
            .oneshot(request)
            .await
            .expect("modern GET response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        assert!(accepts_event_stream("Text/Event-Stream; q=1"));
        assert!(!accepts_event_stream("text/event-stream-evil"));
        assert!(!accepts_event_stream("text/event-stream; q=0"));
    }

    /// Makes sure that old Streamable HTTP initialization can omit client information.
    #[tokio::test]
    async fn accepts_old_initialize_without_client_info() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {} }
        });
        let mut request = test_request(Method::POST, "/mcp", body.to_string());
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        let response = test_router()
            .oneshot(request)
            .await
            .expect("initialize response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("mcp-session-id"));
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BODY_BYTES)
            .await
            .expect("initialize body");
        let response: Value = serde_json::from_slice(&bytes).expect("initialize JSON");
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");

        let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} });
        let mut request = test_request(Method::POST, "/mcp", list.to_string());
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        request.headers_mut().insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2024-11-05"),
        );
        let response = test_router()
            .oneshot(request)
            .await
            .expect("tools/list response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BODY_BYTES)
            .await
            .expect("tools/list body");
        let response: Value = serde_json::from_slice(&bytes).expect("tools/list JSON");
        assert_eq!(response["result"]["tools"][0]["name"], "ghidra");
        assert!(response["result"].get("resultType").is_none());

        let mut request = test_request(Method::POST, "/mcp", "{}");
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json-evil"),
        );
        let response = test_router()
            .oneshot(request)
            .await
            .expect("media type response");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let mut request = test_request(Method::POST, "/mcp", body.to_string());
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; Charset=UTF-8"),
        );
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        let response = test_router()
            .oneshot(request)
            .await
            .expect("mixed-case media type response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Makes sure that the legacy SSE handshake, messages, and cleanup work.
    #[tokio::test]
    async fn serves_legacy_sse_sessions() {
        let app = test_router();
        let mut request = test_request(Method::GET, "/mcp", Body::empty());
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("legacy SSE response");
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let endpoint_event = next_sse_event(&mut stream).await;
        assert!(endpoint_event.contains("event: endpoint"));
        let relative_endpoint = sse_data(&endpoint_event);
        assert!(relative_endpoint.starts_with("?sessionId="));
        let endpoint = format!("/mcp{relative_endpoint}");

        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {} }
        });
        let initialize = serde_json::to_string_pretty(&initialize).expect("initialize JSON");
        assert_eq!(
            legacy_post(&app, &endpoint, &initialize).await.status(),
            StatusCode::ACCEPTED
        );
        let initialized = next_sse_event(&mut stream).await;
        assert!(initialized.contains("event: message"));
        let initialized: Value = serde_json::from_str(&sse_data(&initialized)).expect("initialize");
        assert_eq!(initialized["result"]["protocolVersion"], "2024-11-05");

        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let notification = notification.to_string();
        assert_eq!(
            legacy_post(&app, &endpoint, &notification).await.status(),
            StatusCode::ACCEPTED
        );
        let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} });
        let list = serde_json::to_string_pretty(&list).expect("tools/list JSON");
        assert_eq!(
            legacy_post(&app, &endpoint, &list).await.status(),
            StatusCode::ACCEPTED
        );
        let listed = next_sse_event(&mut stream).await;
        let listed: Value = serde_json::from_str(&sse_data(&listed)).expect("tools/list");
        assert_eq!(listed["result"]["tools"][0]["name"], "ghidra");
        assert!(listed["result"].get("resultType").is_none());

        drop(stream);
        tokio::task::yield_now().await;
        assert_eq!(
            legacy_post(&app, &endpoint, "{}").await.status(),
            StatusCode::NOT_FOUND
        );
    }
}
