// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Upload preparation through HTTP and legacy SSE, without Ghidra processes.

use super::*;
use crate::{mcp::ToolServer, mcp_http, tools::Daemon};
use axum::{extract::Request, http::Method, Router};
use tower::ServiceExt;

/// Makes a tool server with isolated upload credentials and no Ghidra processes.
fn test_server() -> (tempfile::TempDir, ToolServer) {
    let root = tempfile::tempdir().unwrap();
    let state = crate::state::test_state(root.path());
    fs::create_dir_all(&state.paths.tmp_dir).unwrap();
    let uploads =
        UploadService::new(state.clone(), authorities(), CancellationToken::new()).unwrap();
    (root, ToolServer::local(Daemon { state, uploads }))
}

/// Returns the permitted listener authorities.
fn authorities() -> [String; 2] {
    ["127.0.0.1:18489".to_string(), "localhost:18489".to_string()]
}

/// Makes an HTTP request with the required MCP headers.
fn request(method: Method, path: &str, body: &Value) -> Request {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "127.0.0.1:18489")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", "2024-11-05")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Makes a valid upload preparation message.
fn prepare(id: u32) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {
            "name": "ghidra_upload",
            "arguments": {
                "operation": "prepare",
                "md5": "0123456789abcdef0123456789abcdef",
                "params": { "fileName": "program.bin", "size": 1024 }
            }
        }
    })
}

/// Checks the upload URL and the other required response fields.
fn check_result(response: &Value, expected_url: &str) {
    assert!(response.get("error").is_none(), "{response}");
    let result = &response["result"];
    assert_ne!(result["isError"], true, "{result}");
    let upload = &result["structuredContent"];
    assert_eq!(upload["url"], expected_url);
    assert_eq!(upload["method"], "POST");
    assert_eq!(
        upload["headers"]["Content-Type"],
        "application/octet-stream"
    );
    assert!(upload["headers"]["Authorization"]
        .as_str()
        .unwrap()
        .starts_with("Bearer "));
    assert!(upload["expiresAt"].as_u64().is_some());
}

/// Makes sure that concurrent HTTP calls use their own public address.
#[tokio::test]
async fn returns_absolute_upload_urls_over_http() {
    let (_root, server) = test_server();
    let app = mcp_http::router(server.clone(), authorities(), CancellationToken::new());
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[], "http://127.0.0.1:18489/upload"),
        (
            &[("referer", "https://first.example/ghidra/mcp?secret=value")],
            "https://first.example/ghidra/upload",
        ),
        (
            &[
                ("x-forwarded-host", "second.example"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-prefix", "/reverse"),
                ("referer", "https://client.example/chat"),
            ],
            "https://second.example/reverse/upload",
        ),
    ];
    futures::future::join_all(cases.iter().map(|(headers, expected)| {
        let app = app.clone();
        async move {
            let mut request = request(Method::POST, "/mcp", &prepare(1));
            for (name, value) in *headers {
                request.headers_mut().insert(
                    name.parse::<header::HeaderName>().unwrap(),
                    value.parse().unwrap(),
                );
            }
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            check_result(&serde_json::from_slice(&body).unwrap(), expected);
        }
    }))
    .await;

    let arguments = prepare(1)["params"]["arguments"]
        .as_object()
        .unwrap()
        .clone();
    let result = server.call("ghidra_upload".into(), arguments).await;
    assert_eq!(result.structured_content.unwrap()["url"], "upload");
}

/// Returns the data from the next SSE event.
async fn next_event(stream: &mut BodyDataStream) -> String {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let bytes = stream.next().await.unwrap().unwrap();
            let event = String::from_utf8(bytes.to_vec()).unwrap();
            if let Some(data) = event.lines().find_map(|line| line.strip_prefix("data: ")) {
                return data.to_string();
            }
        }
    })
    .await
    .expect("SSE event timed out")
}

/// Sends one legacy SSE message, then checks its HTTP status.
async fn legacy_post(app: &Router, request: Request) {
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
}

/// Makes sure that each legacy SSE call keeps the headers of its own POST request.
#[tokio::test]
async fn returns_absolute_upload_urls_over_legacy_sse() {
    let (_root, server) = test_server();
    let app = mcp_http::router(server, authorities(), CancellationToken::new());
    let mut open = request(Method::GET, "/mcp", &Value::Null);
    open.headers_mut().remove("mcp-protocol-version");
    open.headers_mut()
        .insert(header::ACCEPT, "text/event-stream".parse().unwrap());
    let response = app.clone().oneshot(open).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let endpoint = format!("/mcp{}", next_event(&mut stream).await);
    let initialize = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": { "protocolVersion": "2024-11-05", "capabilities": {} }
    });
    legacy_post(&app, request(Method::POST, &endpoint, &initialize)).await;
    let initialized: Value = serde_json::from_str(&next_event(&mut stream).await).unwrap();
    assert!(initialized.get("error").is_none());
    let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    legacy_post(&app, request(Method::POST, &endpoint, &notification)).await;

    for (id, host) in [(1, "first.example"), (2, "second.example")] {
        let mut call = request(Method::POST, &endpoint, &prepare(id));
        call.headers_mut().insert(
            header::REFERER,
            format!("https://{host}/ghidra/mcp").parse().unwrap(),
        );
        legacy_post(&app, call).await;
        let response: Value = serde_json::from_str(&next_event(&mut stream).await).unwrap();
        check_result(&response, &format!("https://{host}/ghidra/upload"));
    }
}
