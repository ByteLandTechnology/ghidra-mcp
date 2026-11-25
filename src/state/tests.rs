// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Unit tests for bridge disconnect cleanup and state invariants.

use super::*;
use crate::bridge::{agent_ws, AGENT_WS_PATH};
use crate::model::SessionStatus;
use axum::{routing::get, Router};
use serde_json::json;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Opens an authenticated WebSocket through the bridge endpoint.
async fn connect_bridge(address: SocketAddr, token: &str) -> TcpStream {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "GET {AGENT_WS_PATH} HTTP/1.1\r\nHost: {address}\r\n\
   Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 101 "), "{line}");
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
    }
    reader.into_inner()
}

/// Sends a masked WebSocket text frame through the test connection.
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

/// Checks request failure, session state, and socket closure after an invalid bridge message.
#[tokio::test]
async fn disconnects_bridge_after_invalid_messages() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let md5 = "0123456789abcdef0123456789abcdef";

    for invalid in [
        "not JSON",
        r#"{"jsonrpc":"1.0","id":"request","result":{}}"#,
        r#"{"jsonrpc":"2.0","id":"request","result":{},"extra":true}"#,
        concat!(
            r#"{"jsonrpc":"2.0","id":"request","result":{},"error":{"#,
            r#""code":-32603,"message":"error"}}"#
        ),
    ] {
        tokio::time::timeout(Duration::from_secs(2), async {
            let token = Uuid::new_v4().to_string();
            state
                .put_session(&SessionRecord::launching(
                    md5.into(),
                    "binary".into(),
                    token.clone(),
                ))
                .unwrap();
            let mut socket = connect_bridge(address, &token).await;
            send_text(
                &mut socket,
                &json!({
                  "jsonrpc": "2.0", "method": "ghidra.ready",
                  "params": { "session_id": md5, "program_name": "binary" }
                })
                .to_string(),
            )
            .await;
            loop {
                let notified = state.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if state.session(md5).unwrap().status == SessionStatus::Ready {
                    break;
                }
                notified.await;
            }

            let (sender, receiver) = oneshot::channel();
            state.begin_request(md5, "valid", sender).unwrap();
            send_text(
                &mut socket,
                r#"{"jsonrpc":"2.0","id":"valid","result":{"ok":true}}"#,
            )
            .await;
            assert_eq!(receiver.await.unwrap().result, Some(json!({ "ok": true })));

            let (sender, receiver) = oneshot::channel();
            state.begin_request(md5, "request", sender).unwrap();
            send_text(&mut socket, invalid).await;
            let response = receiver.await.unwrap();
            assert_eq!(response.id.as_deref(), Some("request"));
            assert_eq!(response.status, Some(502));
            assert_eq!(response.error.unwrap().code, "BRIDGE_DISCONNECTED");
            assert_eq!(socket.read(&mut [0; 1]).await.unwrap(), 0);
            assert!(state.connection(md5).is_none());
            let session = state.session(md5).unwrap();
            assert_eq!(session.status, SessionStatus::Disconnected);
            assert!(!session.ws_connected);
        })
        .await
        .unwrap_or_else(|_| panic!("bridge did not disconnect after: {invalid}"));
    }
    server.abort();
    let _ = server.await;
}
