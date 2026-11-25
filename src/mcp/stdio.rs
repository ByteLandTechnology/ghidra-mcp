// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Zero-DOM MCP stream server for `stdio` and external `localSocket` clients.
//!
//! `rmcp` handles protocol negotiation, `tools/list`, `ping`, `server/discover`,
//! notifications, and invalid-request errors. Valid `tools/call` requests run
//! through [`ToolServer::call_raw`] and write `structuredContent` and
//! `content[0].text` once from `Box<RawValue>` without `serde_json::Value` trees.

use super::{RawToolResult, ToolServer};
use anyhow::Result;
use rmcp::{
    model::{
        ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcMessage, ProtocolVersion,
        RequestId, RequestMetaObject, ServerResult,
    },
    service::{RxJsonRpcMessage, ServerInitializeError, Service, TxJsonRpcMessage},
    transport::{async_rw::AsyncRwTransport, Transport},
    RoleServer, ServiceExt,
};
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Shared protocol state observed on one MCP stream session.
#[derive(Default)]
struct SessionState {
    /// Negotiated version from `InitializeResult`, when the session used `initialize`.
    initialized_version: Option<ProtocolVersion>,
    /// True if at least one inline `2026-07-28` `tools/call` ran without `initialize`.
    had_inline_call: bool,
    /// Cancellation tokens of in-flight fast-path `tools/call` requests.
    in_flight: HashMap<RequestId, CancellationToken>,
}

/// Buffers one outbound `rmcp` frame until `flush`, then sends it atomically.
struct ChannelWriter {
    /// Bytes accumulated for the current outbound JSON-RPC line.
    buf: Vec<u8>,
    /// Atomic frame channel consumed by the single stream writer task.
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.buf.is_empty() {
            let frame = std::mem::take(&mut self.buf);
            self.tx
                .send(frame)
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_mut().poll_flush(cx)
    }
}

/// Wraps `AsyncRwTransport` so `tools/call` writes raw `Box<RawValue>` responses.
struct RawMcpTransport<R: AsyncRead> {
    /// Standard `rmcp` line-delimited JSON-RPC transport.
    inner: AsyncRwTransport<RoleServer, R, ChannelWriter>,
    /// Tool server used by fast-path `tools/call` tasks.
    server: ToolServer,
    /// Protocol versions supported by `ToolServer`.
    supported_versions: Vec<ProtocolVersion>,
    /// Shared session version and cancellation map.
    state: Arc<StdMutex<SessionState>>,
    /// Atomic outbound frame sender shared with `ChannelWriter`.
    frame_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Active fast-path `tools/call` tasks.
    call_tasks: JoinSet<()>,
    /// Stream cancellation token.
    cancellation: CancellationToken,
}

/// Outbound JSON-RPC envelope for a fast-path `tools/call` result.
#[derive(Serialize)]
struct RawCallResponse<'a> {
    /// Always `"2.0"`.
    jsonrpc: &'static str,
    /// Request ID echoed from `tools/call`.
    id: &'a RequestId,
    /// MCP `CallToolResult` body.
    result: RawMcpCallResult<'a>,
}

/// MCP `CallToolResult` body backed directly by `&RawValue`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawMcpCallResult<'a> {
    /// `"complete"` on protocol `2026-07-28` or newer, absent on older versions.
    #[serde(skip_serializing_if = "Option::is_none")]
    result_type: Option<&'static str>,
    /// Single text content block whose text equals `structuredContent`.
    content: [RawMcpTextBlock<'a>; 1],
    /// Unescaped structured JSON payload.
    structured_content: &'a RawValue,
    /// Whether the tool call produced a domain or bridge error.
    is_error: bool,
}

/// Text content block serialized directly from `raw.get()`.
#[derive(Serialize)]
struct RawMcpTextBlock<'a> {
    /// Always `"text"`.
    r#type: &'static str,
    /// Raw JSON slice written with JSON string escapes in one pass.
    text: &'a str,
}

impl<R> Transport<RoleServer> for RawMcpTransport<R>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl std::future::Future<Output = std::result::Result<(), Self::Error>> + Send + 'static
    {
        if let JsonRpcMessage::Response(response) = &item {
            if let ServerResult::InitializeResult(init) = &response.result {
                self.state
                    .lock()
                    .expect("MCP session state poisoned")
                    .initialized_version = Some(init.protocol_version.clone());
            }
        }
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            while self.call_tasks.try_join_next().is_some() {}
            let Some(message) = self.inner.receive().await else {
                drain_call_tasks(&mut self.call_tasks, &self.cancellation).await;
                return None;
            };
            match message {
                ClientJsonRpcMessage::Notification(note) => {
                    if let ClientNotification::CancelledNotification(cancelled) = &note.notification
                    {
                        if let Some(request_id) = &cancelled.params.request_id {
                            let removed = self
                                .state
                                .lock()
                                .expect("MCP session state poisoned")
                                .in_flight
                                .remove(request_id);
                            if let Some(token) = removed {
                                token.cancel();
                                continue;
                            }
                        }
                    }
                    return Some(ClientJsonRpcMessage::Notification(note));
                }
                ClientJsonRpcMessage::Request(request) => {
                    let eligible_version = match &request.request {
                        ClientRequest::CallToolRequest(call)
                            if call.params.meta.as_ref().is_none_or(|meta| {
                                !meta.contains_key("io.modelcontextprotocol/task")
                            }) =>
                        {
                            fast_path_version(
                                &self.state,
                                &self.supported_versions,
                                call.params.meta.as_ref(),
                            )
                        }
                        _ => None,
                    };
                    let Some(version) = eligible_version else {
                        return Some(ClientJsonRpcMessage::Request(request));
                    };
                    let id = request.id;
                    let ClientRequest::CallToolRequest(call) = request.request else {
                        unreachable!("checked CallToolRequest above");
                    };
                    let call_cancel = self.cancellation.child_token();
                    self.state
                        .lock()
                        .expect("MCP session state poisoned")
                        .in_flight
                        .insert(id.clone(), call_cancel.clone());
                    let server = self.server.clone();
                    let state = self.state.clone();
                    let frame_tx = self.frame_tx.clone();
                    self.call_tasks.spawn(async move {
                        let outcome = server
                            .call_raw(
                                call.params.name.into_owned(),
                                call.params.arguments.unwrap_or_default(),
                            )
                            .await;
                        let active = state
                            .lock()
                            .expect("MCP session state poisoned")
                            .in_flight
                            .remove(&id)
                            .is_some();
                        if !active || call_cancel.is_cancelled() {
                            return;
                        }
                        let include_result_type =
                            version.as_str() >= ProtocolVersion::V_2026_07_28.as_str();
                        if let Some(frame) =
                            encode_raw_call_response(&id, &outcome, include_result_type)
                        {
                            let _ = frame_tx.send(frame);
                        }
                    });
                }
                other => return Some(other),
            }
        }
    }

    async fn close(&mut self) -> std::result::Result<(), Self::Error> {
        drain_call_tasks(&mut self.call_tasks, &self.cancellation).await;
        self.inner.close().await
    }
}

/// Waits for active `tools/call` tasks to finish, or aborts them if cancelled.
async fn drain_call_tasks(tasks: &mut JoinSet<()>, cancellation: &CancellationToken) {
    tokio::select! {
        () = cancellation.cancelled() => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        () = async { while tasks.join_next().await.is_some() {} } => {}
    }
}

/// Returns the effective protocol version when a `tools/call` request satisfies
/// all session or inline-metadata checks; returns `None` if `rmcp` must handle it.
fn fast_path_version(
    state: &StdMutex<SessionState>,
    supported_versions: &[ProtocolVersion],
    meta: Option<&RequestMetaObject>,
) -> Option<ProtocolVersion> {
    let empty_meta = RequestMetaObject::default();
    let meta = meta.unwrap_or(&empty_meta);
    let requested = meta.protocol_version();
    let mut guard = state.lock().expect("MCP session state poisoned");
    if let Some(init_version) = guard.initialized_version.clone() {
        let Some(override_version) = requested else {
            return Some(init_version);
        };
        if !supported_versions.contains(&override_version) {
            return None;
        }
        if override_version.as_str() >= ProtocolVersion::V_2026_07_28.as_str()
            && !meta
                .missing_required_keys(&ProtocolVersion::V_2026_07_28)
                .is_empty()
        {
            return None;
        }
        return Some(override_version);
    }

    let version = requested?;
    if !meta
        .missing_required_keys(&ProtocolVersion::V_2026_07_28)
        .is_empty()
        || !supported_versions.contains(&version)
    {
        return None;
    }
    guard.had_inline_call = true;
    Some(version)
}

/// Serializes one MCP `tools/call` response into a single newline-terminated buffer.
fn encode_raw_call_response(
    id: &RequestId,
    outcome: &RawToolResult,
    include_result_type: bool,
) -> Option<Vec<u8>> {
    let raw_str = outcome.structured_content.get();
    let response = RawCallResponse {
        jsonrpc: "2.0",
        id,
        result: RawMcpCallResult {
            result_type: include_result_type.then_some("complete"),
            content: [RawMcpTextBlock {
                r#type: "text",
                text: raw_str,
            }],
            structured_content: &outcome.structured_content,
            is_error: outcome.is_error,
        },
    };
    let mut out = Vec::with_capacity(raw_str.len().saturating_mul(2).saturating_add(160));
    serde_json::to_writer(&mut out, &response).ok()?;
    out.push(b'\n');
    Some(out)
}

/// Serves MCP over `(read, write)` with zero-DOM `tools/call` serialization.
///
/// # Errors
///
/// Fails if the MCP handshake or stream fails before clean shutdown.
pub async fn serve_stream_with_ct<R, W>(
    server: ToolServer,
    read: R,
    mut write: W,
    cancellation: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            if write.write_all(&frame).await.is_err() {
                break;
            }
            if write.flush().await.is_err() {
                break;
            }
        }
    });

    let supported_versions =
        <ToolServer as Service<RoleServer>>::supported_protocol_versions(&server);
    let state = Arc::new(StdMutex::new(SessionState::default()));
    let inner = AsyncRwTransport::new_server(
        read,
        ChannelWriter {
            buf: Vec::new(),
            tx: frame_tx.clone(),
        },
    );
    let transport = RawMcpTransport {
        inner,
        server: server.clone(),
        supported_versions: supported_versions.into_owned(),
        state: state.clone(),
        frame_tx,
        call_tasks: JoinSet::new(),
        cancellation: cancellation.clone(),
    };

    let serve_result = match server.serve_with_ct(transport, cancellation).await {
        Ok(running) => {
            running.waiting().await?;
            Ok(())
        }
        Err(ServerInitializeError::Cancelled) => Ok(()),
        Err(ServerInitializeError::ConnectionClosed(_))
            if state
                .lock()
                .expect("MCP session state poisoned")
                .had_inline_call =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    };

    let _ = writer_task.await;
    serve_result
}
