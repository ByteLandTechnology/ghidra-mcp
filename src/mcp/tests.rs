// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of raw IPC, external `localSocket` peers, `stdio` wire messages, and version negotiation.

use super::*;
use crate::daemon::{serve_client_stream, RawSocketClient};
use crate::model::SessionRecord;
use crate::state::ConnectionHandle;
use crate::tools::Control;
use crate::upload::UploadService;
use rmcp::model::CallToolRequestParams;
use rmcp::ServiceExt;
use serde_json::json;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Counts every byte written to the wrapped stream.
struct CountingStream<S> {
    /// Wrapped bidirectional stream.
    inner: S,
    /// Total bytes written through `poll_write`.
    written: Arc<AtomicUsize>,
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = poll {
            self.written.fetch_add(count, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Builds a local `ToolServer` backed by a simulated bridge session that answers
/// `function.list` and `decompilation.get` with large JSON payloads.
fn mock_bridge_server(
    function_list_json: String,
    decompilation_json: String,
) -> (tempfile::TempDir, &'static str, ToolServer) {
    let root = tempfile::tempdir().expect("tempdir");
    let state = crate::state::test_state(root.path());
    std::fs::create_dir_all(&state.paths.tmp_dir).expect("tmp dir");
    let md5 = "0123456789abcdef0123456789abcdef";
    let mut session = SessionRecord::launching(md5.into(), "target.elf".into(), "token".into());
    session.mark_ready();
    state.put_session(&session).expect("put session");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    assert!(state.attach_bridge(
        md5,
        ConnectionHandle {
            conn_id: "bridge-1".into(),
            sender: tx,
        },
    ));
    let responder_state = state.clone();
    tokio::spawn(async move {
        while let Some(frame_msg) = rx.recv().await {
            let request = frame_msg.into_text().expect("text frame");
            let parsed: Value = serde_json::from_str(&request).expect("valid bridge request");
            let id = parsed["id"].as_str().expect("id").to_string();
            let method = parsed["method"].as_str().expect("method");
            let body = match method {
                "function.list" => &function_list_json,
                "decompilation.get" => &decompilation_json,
                other => panic!("unexpected bridge method: {other}"),
            };
            let frame = format!(r#"{{"jsonrpc":"2.0","id":"{id}","result":{body}}}"#);
            if let Ok(crate::jsonrpc::Incoming::Response { id, envelope }) =
                crate::jsonrpc::decode_incoming(&frame, md5)
            {
                responder_state.deliver_response(md5, "bridge-1", &id, *envelope);
            }
        }
    });
    let authorities = ["127.0.0.1:18489".to_string(), "localhost:18489".to_string()];
    let uploads =
        UploadService::new(state.clone(), authorities, CancellationToken::new()).expect("uploads");
    let server = ToolServer::local(Daemon {
        state,
        uploads,
        control: Control::default(),
    });
    (root, md5, server)
}

/// Generates a deterministic JSON payload of at least `target_bytes`.
fn large_bridge_payload(kind: &str, target_bytes: usize) -> String {
    if kind == "function.list" {
        let mut body = String::with_capacity(target_bytes + 256);
        body.push_str(r#"{"functions":["#);
        let mut index = 0usize;
        while body.len() + 32 < target_bytes {
            if index > 0 {
                body.push(',');
            }
            let _ = write!(
                body,
                r#"{{"name":"sub_{index:06x}","address":"0x{:08x}","size":128,"thunk":false}}"#,
                0x0040_1000 + index * 16
            );
            index += 1;
        }
        body.push_str(r#"],"nextCursor":null}"#);
        body
    } else {
        let mut lines = String::with_capacity(target_bytes);
        let mut index = 0usize;
        while lines.len() + 96 < target_bytes {
            let _ = write!(
                lines,
                r"  uVar{} = *(uint *)(param_1 + 0x{:x}) ^ 0xdeadbeef;\n",
                index % 16,
                index * 4
            );
            index += 1;
        }
        format!(
            concat!(
                r#"{{"function":"main","address":"0x00401000","#,
                r#""c":"int main(long param_1) {{\n{lines}  return 0;\n}}"}}"#
            ),
            lines = lines
        )
    }
}

/// Makes sure that cache fields follow the protocol version that the client negotiated.
#[test]
fn tool_list_has_version_specific_cache_fields() {
    let legacy = list_tools_result(Some(&ProtocolVersion::V_2025_11_25));
    assert_eq!(legacy.ttl_ms, None);
    assert_eq!(legacy.cache_scope, None);

    let current = list_tools_result(Some(&ProtocolVersion::V_2026_07_28));
    assert_eq!(current.ttl_ms, Some(0));
    assert_eq!(current.cache_scope, Some(CacheScope::Private));
}

/// Checks that internal `daemon.sock` peers receive single-copy `structuredContent`
/// without `content[0].text` while external `localSocket` peers still receive both.
#[tokio::test]
async fn internal_socket_omits_text_copy_and_external_socket_keeps_dual_content() {
    let fn_payload = large_bridge_payload("function.list", 1_300_000);
    let decomp_payload = large_bridge_payload("decompilation.get", 1_260_000);
    assert!(fn_payload.len() >= 1_250_000);
    assert!(decomp_payload.len() >= 1_250_000);
    let (_root, md5, server) = mock_bridge_server(fn_payload.clone(), decomp_payload.clone());

    // 1. Inspect raw wire frame on internal socket connection.
    let (client_io, server_io) = tokio::io::duplex(4 * 1024 * 1024);
    let daemon_written = Arc::new(AtomicUsize::new(0));
    let counted_server = CountingStream {
        inner: server_io,
        written: daemon_written.clone(),
    };
    let cancel = CancellationToken::new();
    let server_clone = server.clone();
    let cancel_clone = cancel.clone();
    let task = tokio::spawn(async move {
        serve_client_stream(counted_server, server_clone, cancel_clone).await;
    });

    let (read_half, write_half) = tokio::io::split(client_io);
    let raw_client = RawSocketClient::connect_io(read_half, write_half)
        .await
        .expect("internal handshake");
    daemon_written.store(0, Ordering::SeqCst);

    let Value::Object(fn_args) = json!({ "operation": "list", "md5": md5, "params": {} }) else {
        unreachable!();
    };
    let fn_result = raw_client
        .call_tool("ghidra_function", &fn_args)
        .await
        .expect("raw function.list");
    assert!(!fn_result.is_error);
    let fn_ipc_bytes = daemon_written.swap(0, Ordering::SeqCst);
    let fn_struct_bytes = fn_result.structured_content.get().len();
    assert!(
        fn_ipc_bytes * 100 <= fn_struct_bytes * 101,
        "internal function.list IPC bytes ({fn_ipc_bytes}) must stay within 1% of {fn_struct_bytes}"
    );
    assert!(fn_result.structured_content.get().contains(&fn_payload));

    let Value::Object(decomp_args) = json!({
        "operation": "get",
        "md5": md5,
        "params": { "selector": { "entry": "0x00401000" } }
    }) else {
        unreachable!();
    };
    let decomp_result = raw_client
        .call_tool("ghidra_decompilation", &decomp_args)
        .await
        .expect("raw decompilation.get");
    assert!(!decomp_result.is_error);
    let decomp_ipc_bytes = daemon_written.swap(0, Ordering::SeqCst);
    let decomp_struct_bytes = decomp_result.structured_content.get().len();
    assert!(
        decomp_ipc_bytes * 100 <= decomp_struct_bytes * 101,
        "internal decompilation.get IPC bytes ({decomp_ipc_bytes}) must stay within 1% of \
         {decomp_struct_bytes}"
    );

    raw_client.close().await;
    let _ = task.await;

    // 2. Verify external `localSocket` MCP peer still gets `content[0].text == structuredContent`.
    let (ext_client_io, ext_server_io) = tokio::io::duplex(8 * 1024 * 1024);
    let ext_cancel = CancellationToken::new();
    let ext_server = server.clone();
    let ext_cancel_clone = ext_cancel.clone();
    let ext_task = tokio::spawn(async move {
        serve_client_stream(ext_server_io, ext_server, ext_cancel_clone).await;
    });

    let mcp_client = ().serve(ext_client_io).await.expect("external MCP client");
    let listed = mcp_client
        .peer()
        .list_all_tools()
        .await
        .expect("tools/list");
    assert_eq!(listed[0].name, "ghidra_help");

    let ext_result = mcp_client
        .peer()
        .call_tool(CallToolRequestParams::new("ghidra_function").with_arguments(fn_args))
        .await
        .expect("external tools/call");
    assert_eq!(ext_result.is_error, Some(false));
    let structured = ext_result.structured_content.expect("structuredContent");
    let text = &ext_result.content[0].as_text().expect("text block").text;
    let parsed_text: Value = serde_json::from_str(text).expect("valid content text JSON");
    assert_eq!(parsed_text, structured);

    mcp_client.cancellation_token().cancel();
    ext_cancel.cancel();
    let _ = ext_task.await;
}

/// Checks `serve_stream_with_ct` on a legacy `2025-11-25` session with pipelined EOF.
#[tokio::test]
async fn stdio_legacy_session_emits_dual_content_without_v2026_fields() {
    let fn_payload = r#"{"functions":[{"name":"entry","address":"0x401000"}],"nextCursor":null}"#;
    let (_root, md5, server) = mock_bridge_server(fn_payload.into(), "{}".into());

    let (mut client_write, server_read) = tokio::io::duplex(256 * 1024);
    let (server_write, client_read) = tokio::io::duplex(256 * 1024);
    let serve_task = tokio::spawn(async move {
        serve_stream_with_ct(server, server_read, server_write, CancellationToken::new())
            .await
            .expect("legacy stdio session");
    });

    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "ghidra-lsp", "version": "0.1.0" }
        }
    });
    let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} });
    let call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "ghidra_function",
            "arguments": { "operation": "list", "md5": md5, "params": {} }
        }
    });
    let mut reader = BufReader::new(client_read);
    let mut line = String::new();

    client_write
        .write_all(format!("{init}\n").as_bytes())
        .await
        .unwrap();
    reader.read_line(&mut line).await.unwrap();
    let init_reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(init_reply["result"]["protocolVersion"], "2025-11-25");

    // Pipeline `tools/list` + `tools/call` and close stdin immediately to verify EOF drain.
    client_write
        .write_all(format!("{list}\n{call}\n").as_bytes())
        .await
        .unwrap();
    drop(client_write);

    let mut replies = HashMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.unwrap() == 0 {
            break;
        }
        let msg: Value = serde_json::from_str(&line).unwrap();
        replies.insert(msg["id"].as_u64().unwrap(), msg);
    }
    serve_task.await.unwrap();

    let list_res = &replies[&2]["result"];
    assert!(list_res.get("resultType").is_none(), "{list_res}");
    assert!(list_res.get("ttlMs").is_none(), "{list_res}");
    assert!(list_res.get("cacheScope").is_none(), "{list_res}");

    let call_res = &replies[&3]["result"];
    assert!(call_res.get("resultType").is_none(), "{call_res}");
    assert_eq!(call_res["isError"], false);
    let text = call_res["content"][0]["text"].as_str().unwrap();
    let from_text: Value = serde_json::from_str(text).unwrap();
    assert_eq!(&from_text, &call_res["structuredContent"]);
    assert_eq!(
        call_res["structuredContent"]["response"]["result"]["functions"][0]["name"],
        "entry"
    );
}

/// Checks `serve_stream_with_ct` on an inline `2026-07-28` session.
#[tokio::test]
async fn stdio_inline_v2026_session_emits_result_type_and_cache_hints() {
    let fn_payload = r#"{"functions":[{"name":"entry","address":"0x401000"}],"nextCursor":null}"#;
    let (_root, md5, server) = mock_bridge_server(fn_payload.into(), "{}".into());

    let (mut modern_write, modern_server_read) = tokio::io::duplex(256 * 1024);
    let (modern_server_write, modern_read) = tokio::io::duplex(256 * 1024);
    let modern_task = tokio::spawn(async move {
        serve_stream_with_ct(
            server,
            modern_server_read,
            modern_server_write,
            CancellationToken::new(),
        )
        .await
        .expect("modern stdio session");
    });

    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "modern-client", "version": "1.0" },
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let modern_list = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/list",
        "params": { "_meta": meta }
    });
    let modern_call = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "_meta": meta,
            "name": "ghidra_function",
            "arguments": { "operation": "list", "md5": md5, "params": {} }
        }
    });
    modern_write
        .write_all(format!("{modern_list}\n{modern_call}\n").as_bytes())
        .await
        .unwrap();
    drop(modern_write);

    let mut modern_reader = BufReader::new(modern_read);
    let mut line = String::new();
    let mut modern_replies = HashMap::new();
    loop {
        line.clear();
        if modern_reader.read_line(&mut line).await.unwrap() == 0 {
            break;
        }
        let msg: Value = serde_json::from_str(&line).unwrap();
        modern_replies.insert(msg["id"].as_u64().unwrap(), msg);
    }
    modern_task.await.unwrap();

    let m_list = &modern_replies[&10]["result"];
    assert_eq!(m_list["resultType"], "complete");
    assert_eq!(m_list["ttlMs"], 0);
    assert_eq!(m_list["cacheScope"], "private");

    let m_call = &modern_replies[&11]["result"];
    assert_eq!(m_call["resultType"], "complete");
    let m_text = m_call["content"][0]["text"].as_str().unwrap();
    let m_parsed: Value = serde_json::from_str(m_text).unwrap();
    assert_eq!(&m_parsed, &m_call["structuredContent"]);
}

/// Checks that `RawSocketClient` works with an older `rmcp`-only daemon socket and maps
/// socket closures to `DomainError::Disconnected`.
#[tokio::test]
async fn raw_socket_client_handles_legacy_server_and_disconnects() {
    let (_root, _md5, server) = mock_bridge_server("{}".into(), "{}".into());
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let server_task = tokio::spawn(async move {
        let (r, w) = tokio::io::split(server_io);
        let _ = serve_stream_with_ct(server, r, w, cancel_clone).await;
    });

    let (read_half, write_half) = tokio::io::split(client_io);
    let client = RawSocketClient::connect_io(read_half, write_half)
        .await
        .expect("legacy MCP handshake");
    let help = client
        .call_tool("ghidra_help", &Map::new())
        .await
        .expect("help over legacy daemon stream");
    assert!(!help.is_error);
    let parsed: Value = serde_json::from_str(help.structured_content.get()).unwrap();
    assert!(parsed["domains"].is_array());

    cancel.cancel();
    let _ = server_task.await;
    let closed_err = client
        .call_tool("ghidra_help", &Map::new())
        .await
        .expect_err("closed daemon stream must fail")
        .into_error();
    assert_eq!(
        DomainError::from_error(&closed_err),
        DomainError::Disconnected {
            md5: "daemon".to_string()
        }
    );
}
