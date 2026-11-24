// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Unit tests for the MCP HTTP transport.

use super::*;
use futures::StreamExt;
use rmcp::{
    model::{
        ErrorData, Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
        ServerConfig,
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
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
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

/// Makes sure that the server checks Host, Origin, HEAD, and OPTIONS.
#[tokio::test]
async fn enforces_origin_and_host_policies() {
    let app = test_router();
    for method in [Method::HEAD, Method::OPTIONS] {
        let mut request = test_request(method.clone(), "/mcp", Body::empty());
        request.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:6274"),
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
            Some(&HeaderValue::from_static("http://localhost:6274"))
        );
        assert_eq!(
            response.headers().get(header::VARY),
            Some(&HeaderValue::from_static("Origin"))
        );
    }

    let no_origin = app
        .clone()
        .oneshot(test_request(Method::HEAD, "/mcp", Body::empty()))
        .await
        .expect("HEAD without Origin");
    assert_eq!(no_origin.status(), StatusCode::OK);
    assert!(no_origin
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());

    for bad_origin in [
        "https://evil.example",
        "https://gemini.google.com",
        "http://evil.rebind.example:18489",
        "null",
    ] {
        let mut request = test_request(Method::POST, "/mcp", "{}");
        request
            .headers_mut()
            .insert(header::ORIGIN, HeaderValue::from_static(bad_origin));
        let response = app.clone().oneshot(request).await.expect("Origin check");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }

    for bad_host in ["evil.rebind.example", "evil.rebind.example:18489"] {
        let mut request = test_request(Method::POST, "/mcp", "{}");
        request
            .headers_mut()
            .insert(header::HOST, HeaderValue::from_static(bad_host));
        let response = app.clone().oneshot(request).await.expect("Host check");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
    assert_eq!(response["result"]["tools"][0]["name"], "ghidra_help");
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
    assert_eq!(listed["result"]["tools"][0]["name"], "ghidra_help");
    assert!(listed["result"].get("resultType").is_none());

    drop(stream);
    tokio::task::yield_now().await;
    assert_eq!(
        legacy_post(&app, &endpoint, "{}").await.status(),
        StatusCode::NOT_FOUND
    );
}
