// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of outbound GUI session attach, handshake, calls, disconnect, and close.

use crate::bridge::{agent_ws, AGENT_WS_PATH};
use crate::error::DomainError;
use crate::model::{JobStatus, SessionStatus};
use crate::state::test_state_with_ws_url;
use axum::{routing::get, Router};
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// Sends an HTTP WebSocket upgrade request and returns the raw status line and stream.
async fn upgrade_bridge(address: SocketAddr, token: &str) -> (String, TcpStream) {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "GET {AGENT_WS_PATH} HTTP/1.1\r\nHost: {address}\r\n\
Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await.unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
            break;
        }
    }
    (status_line, reader.into_inner())
}

/// Connects an authenticated bridge WebSocket and asserts HTTP `101`.
async fn connect_bridge(address: SocketAddr, token: &str) -> TcpStream {
    let (status, stream) = upgrade_bridge(address, token).await;
    assert!(status.starts_with("HTTP/1.1 101 "), "{status}");
    stream
}

/// Sends one masked WebSocket text frame to the server.
async fn send_text(socket: &mut TcpStream, text: &str) {
    let length = u16::try_from(text.len()).unwrap();
    let mask: [u8; 4] = Uuid::new_v4().as_bytes()[..4].try_into().unwrap();
    let mut frame = vec![0x81];
    if length < 126 {
        frame.push(0x80 | u8::try_from(length).unwrap());
    } else {
        frame.push(0xfe);
        frame.extend_from_slice(&length.to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(
        text.bytes()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    socket.write_all(&frame).await.unwrap();
}

/// Reads one unmasked WebSocket text frame from the server.
async fn recv_text(socket: &mut TcpStream) -> Value {
    loop {
        let mut header = [0_u8; 2];
        socket.read_exact(&mut header).await.unwrap();
        let opcode = header[0] & 0x0f;
        assert_eq!(header[1] & 0x80, 0, "server frames must not be masked");
        let length = match header[1] & 0x7f {
            126 => {
                let mut ext = [0_u8; 2];
                socket.read_exact(&mut ext).await.unwrap();
                usize::from(u16::from_be_bytes(ext))
            }
            127 => {
                let mut ext = [0_u8; 8];
                socket.read_exact(&mut ext).await.unwrap();
                usize::try_from(u64::from_be_bytes(ext)).unwrap()
            }
            short => usize::from(short),
        };
        let mut payload = vec![0_u8; length];
        socket.read_exact(&mut payload).await.unwrap();
        if opcode == 0x1 {
            return serde_json::from_slice(&payload).unwrap();
        }
    }
}

/// Makes sure that an attached GUI session completes `ghidra.ready`, serves RPC calls,
/// and never starts headless recovery after disconnect.
#[tokio::test]
async fn attach_accepts_outbound_handshake_and_skips_headless_recovery() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ws_url = format!("ws://{address}{AGENT_WS_PATH}");
    let state = test_state_with_ws_url(root.path(), ws_url.clone());
    let router = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let md5 = "0123456789abcdef0123456789abcdef";

    let (_, attached) = super::attach(&state, md5.into(), None, None).await.unwrap();
    let token = attached["token"].as_str().unwrap().to_string();
    let job_id = attached["jobId"].as_str().unwrap().to_string();
    assert_eq!(attached["wsUrl"], ws_url);
    assert_eq!(attached["sessionId"], md5);
    assert_eq!(
        attached["bridgeArgs"],
        format!("ws_url={ws_url} session_id={md5} token={token}")
    );
    assert!(!attached["bridgeArgs"]
        .as_str()
        .unwrap()
        .contains("exit_deadline_sec"));
    assert!(attached["session"].get("token").is_none());

    let mut socket = connect_bridge(address, &token).await;
    send_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "method": "ghidra.ready",
            "params": { "session_id": md5, "program_name": "gui_target.exe" }
        })
        .to_string(),
    )
    .await;

    let job = state
        .await_job(&job_id, Some(Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(job.status, JobStatus::Completed);
    let session = state.session(md5).unwrap();
    assert_eq!(session.status, SessionStatus::Ready);
    assert!(session.ws_connected);
    assert!(session.attached);
    assert_eq!(session.file_name, "gui_target.exe");

    let rpc_state = state.clone();
    let call_task =
        tokio::spawn(async move { super::call(&rpc_state, md5, "program.get", json!({})).await });
    let rpc_request = recv_text(&mut socket).await;
    assert_eq!(rpc_request["method"], "program.get");
    let req_id = rpc_request["id"].as_str().unwrap();
    send_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": { "program_name": "gui_target.exe" }
        })
        .to_string(),
    )
    .await;
    let envelope = call_task.await.unwrap().unwrap();
    assert_eq!(
        envelope.result,
        Some(json!({ "program_name": "gui_target.exe" }))
    );

    drop(socket);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notified = state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if state.session(md5).unwrap().status == SessionStatus::Disconnected {
                break;
            }
            notified.await;
        }
    })
    .await
    .unwrap();

    let err = super::ensure_connected(&state, md5).await.unwrap_err();
    assert!(matches!(
        err.downcast_ref::<DomainError>(),
        Some(DomainError::Disconnected { md5: target }) if target == md5
    ));
    assert!(!state.paths.project_dir(md5).exists());

    server.abort();
    let _ = server.await;
}

/// Makes sure that `ghidra_session attach` with `wait=true` allocates an ID when omitted,
/// waits for `ghidra.ready`, and sends `session.shutdown` on close.
#[tokio::test]
async fn attach_wait_and_close_send_shutdown_and_invalidate_token() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ws_url = format!("ws://{address}{AGENT_WS_PATH}");
    let state = test_state_with_ws_url(root.path(), ws_url);
    std::fs::create_dir_all(&state.paths.tmp_dir).unwrap();
    let uploads = crate::upload::UploadService::new(
        state.clone(),
        [address.to_string(), format!("localhost:{}", address.port())],
        tokio_util::sync::CancellationToken::new(),
    )
    .unwrap();
    let daemon = crate::tools::Daemon {
        state: state.clone(),
        uploads,
        control: crate::tools::Control::default(),
    };
    let router = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let attach_task = tokio::spawn(async move {
        let Value::Object(args) = json!({
            "operation": "attach",
            "params": { "wait": true, "timeoutMs": 3000 }
        }) else {
            unreachable!();
        };
        crate::tools::call(&daemon, "ghidra_session", args).await
    });

    let (allocated_md5, token) = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notified = state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let sessions = state.sessions();
            if let Some(record) = sessions.first() {
                let full = state.session(&record.session_id).unwrap();
                if !full.agent_token.is_empty() {
                    break (full.session_id, full.agent_token);
                }
            }
            notified.await;
        }
    })
    .await
    .unwrap();
    assert_eq!(allocated_md5.len(), 32);

    let mut socket = connect_bridge(address, &token).await;
    send_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "method": "ghidra.ready",
            "params": { "session_id": &allocated_md5, "program_name": "codebrowser.bin" }
        })
        .to_string(),
    )
    .await;

    let (_, result) = attach_task.await.unwrap().unwrap();
    assert_eq!(result["md5"], allocated_md5);
    assert_eq!(result["session"]["status"], "ready");
    assert_eq!(result["session"]["connected"], true);
    assert_eq!(result["session"]["fileName"], "codebrowser.bin");
    assert_eq!(result["job"]["status"], "completed");

    let close_state = state.clone();
    let close_md5 = allocated_md5.clone();
    let close_task =
        tokio::spawn(async move { super::close(&close_state, &close_md5, false).await });
    let shutdown_req = recv_text(&mut socket).await;
    assert_eq!(shutdown_req["method"], "session.shutdown");
    let shutdown_id = shutdown_req["id"].as_str().unwrap();
    send_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "id": shutdown_id,
            "result": { "closed": true }
        })
        .to_string(),
    )
    .await;
    close_task.await.unwrap().unwrap();

    let closed = state.session(&allocated_md5).unwrap();
    assert_eq!(closed.status, SessionStatus::Closed);
    assert_eq!(closed.agent_token, "");
    let (status_line, _) = upgrade_bridge(address, &token).await;
    assert!(status_line.starts_with("HTTP/1.1 401 "), "{status_line}");
    let _: Map<String, Value> = serde_json::from_value(result).unwrap();

    server.abort();
    let _ = server.await;
}
