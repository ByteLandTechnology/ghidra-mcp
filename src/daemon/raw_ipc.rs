// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Raw JSON-RPC wire messages between internal peers and `daemon.sock`.
//!
//! Internal peers (`serve_stdio` and CLI subcommands) identify themselves in the
//! `initialize` handshake. The daemon then returns `structuredContent` as one
//! raw JSON value and omits `content[0].text`. External `localSocket` clients
//! take the standard MCP stream path.

use crate::error::DomainError;
use crate::mcp::{RawToolResult, ToolServer};
use anyhow::{anyhow, bail, Context, Result};
use rmcp::transport::async_rw::DEFAULT_MAX_LINE_LENGTH;
use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Map, Value};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Cursor};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex as StdMutex,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// The client name that selects the raw internal protocol on `daemon.sock`.
const INTERNAL_CLIENT_NAME: &str = "ghidra-mcp-internal";

/// Maximum byte length of one raw tool response line from the daemon.
const MAX_RESPONSE_LINE_BYTES: usize = 64 * 1024 * 1024;

/// A failure during an internal socket tool call.
#[derive(Debug)]
pub enum ClientCallError {
    /// The socket closed before or during the call.
    Closed(anyhow::Error),
    /// The daemon returned a JSON-RPC protocol error or invalid frame.
    Protocol(anyhow::Error),
}

impl ClientCallError {
    /// Converts this call failure into `anyhow::Error`.
    pub fn into_error(self) -> anyhow::Error {
        match self {
            Self::Closed(error) | Self::Protocol(error) => error,
        }
    }
}

/// Open caller channels indexed by request ID.
type PendingCalls =
    StdMutex<HashMap<u64, oneshot::Sender<std::result::Result<RawToolResult, ClientCallError>>>>;

/// A persistent, multiplexed raw JSON-RPC client connection to `daemon.sock`.
pub struct RawSocketClient {
    /// Monotonic JSON-RPC request ID generator.
    next_id: AtomicU64,
    /// Shared write half of the local socket stream, `None` after close.
    writer: Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    /// In-flight tool calls indexed by request ID.
    pending: Arc<PendingCalls>,
    /// True once the socket reader stops or a write fails.
    closed: Arc<AtomicBool>,
    /// Cancels the background line reader task on explicit close.
    cancel: CancellationToken,
}

/// Outbound `initialize` request sent by `RawSocketClient`.
#[derive(Serialize)]
struct InternalInitRequest<'a> {
    /// Always `"2.0"`.
    jsonrpc: &'static str,
    /// Request identifier `0`.
    id: u64,
    /// Always `"initialize"`.
    method: &'static str,
    /// Minimal MCP initialization parameters.
    params: InternalInitParams<'a>,
}

/// Parameters of [`InternalInitRequest`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InternalInitParams<'a> {
    /// Requested MCP protocol revision.
    protocol_version: &'static str,
    /// Empty capability map.
    capabilities: EmptyObject,
    /// Client identity marker.
    client_info: InternalPeerInfo<'a>,
}

/// Empty JSON object `{}`.
#[derive(Serialize)]
struct EmptyObject {}

/// Name and version of an internal peer or daemon.
#[derive(Serialize)]
struct InternalPeerInfo<'a> {
    /// Peer identifier.
    name: &'a str,
    /// Crate version string.
    version: &'a str,
}

/// Minimal validation shape of an `initialize` response.
#[derive(Deserialize)]
struct InitResponseCheck<'a> {
    /// Must equal `"2.0"`.
    #[serde(borrow)]
    jsonrpc: Cow<'a, str>,
    /// Present on success.
    result: Option<&'a RawValue>,
    /// Present on failure.
    error: Option<WireRpcError>,
}

/// Outbound `tools/call` request sent over `daemon.sock`.
#[derive(Serialize)]
struct WireCallRequest<'a> {
    /// Always `"2.0"`.
    jsonrpc: &'static str,
    /// Numeric request ID.
    id: u64,
    /// Always `"tools/call"`.
    method: &'static str,
    /// Tool name and arguments.
    params: WireCallParams<'a>,
}

/// Parameters of [`WireCallRequest`].
#[derive(Serialize)]
struct WireCallParams<'a> {
    /// Public MCP tool name.
    name: &'a str,
    /// Validated JSON object arguments.
    arguments: &'a Map<String, Value>,
}

/// Inbound JSON-RPC response read by `RawSocketClient`.
#[derive(Deserialize)]
struct WireResponse {
    /// Numeric request ID.
    id: Option<u64>,
    /// Tool call payload on success.
    result: Option<WireToolResult>,
    /// Protocol error on failure.
    error: Option<WireRpcError>,
}

/// Tool call result payload received over `daemon.sock`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireToolResult {
    /// Raw structured JSON content.
    #[serde(default)]
    structured_content: Option<Box<RawValue>>,
    /// Fallback text items from an older daemon version, empty on current daemons.
    #[serde(default)]
    content: Vec<WireTextContent>,
    /// Whether the tool result represents an error.
    #[serde(default)]
    is_error: Option<bool>,
}

/// Fallback text block for compatibility with older daemons.
#[derive(Deserialize)]
struct WireTextContent {
    /// Optional text message.
    #[serde(default)]
    text: Option<String>,
}

/// JSON-RPC error object on the internal socket.
#[derive(Deserialize, Serialize)]
struct WireRpcError {
    /// Numeric JSON-RPC error code.
    code: i64,
    /// Error description.
    message: String,
}

impl RawSocketClient {
    /// Completes the internal handshake over `(read, write)` and starts the reader task.
    ///
    /// # Errors
    ///
    /// Fails if the socket closes or returns an invalid `initialize` response.
    pub async fn connect_io<R, W>(read: R, mut write: W) -> Result<Self>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let init = InternalInitRequest {
            jsonrpc: "2.0",
            id: 0,
            method: "initialize",
            params: InternalInitParams {
                protocol_version: "2025-11-25",
                capabilities: EmptyObject {},
                client_info: InternalPeerInfo {
                    name: INTERNAL_CLIENT_NAME,
                    version: env!("CARGO_PKG_VERSION"),
                },
            },
        };
        let mut frame = serde_json::to_vec(&init)?;
        frame.push(b'\n');
        write
            .write_all(&frame)
            .await
            .context("failed to send daemon handshake")?;
        write
            .flush()
            .await
            .context("failed to flush daemon handshake")?;

        let mut reader = BufReader::new(read);
        let mut line = Vec::new();
        match read_bounded_line(&mut reader, &mut line, DEFAULT_MAX_LINE_LENGTH).await {
            LineOutcome::Line => {}
            LineOutcome::Eof => bail!("daemon closed socket before handshake reply"),
            LineOutcome::Oversized => bail!("daemon handshake reply exceeded size limit"),
            LineOutcome::Io(error) => return Err(error).context("failed to read daemon handshake"),
        }
        let trimmed = trim_line(&line);
        let reply: InitResponseCheck<'_> =
            serde_json::from_slice(trimmed).context("invalid daemon handshake JSON")?;
        if reply.jsonrpc != "2.0" {
            bail!("daemon handshake returned unsupported jsonrpc version");
        }
        if let Some(error) = reply.error {
            bail!(
                "daemon rejected handshake ({}): {}",
                error.code,
                error.message
            );
        }
        if reply.result.is_none() {
            bail!("daemon handshake response has no result");
        }
        write
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .context("failed to send daemon initialized notification")?;
        write
            .flush()
            .await
            .context("failed to flush daemon initialized notification")?;

        let pending: Arc<PendingCalls> = Arc::new(StdMutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        spawn_client_reader(reader, pending.clone(), closed.clone(), cancel.clone());

        Ok(Self {
            next_id: AtomicU64::new(1),
            writer: Mutex::new(Some(Box::new(write))),
            pending,
            closed,
            cancel,
        })
    }

    /// Returns `true` if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Closes the client connection immediately.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
        if let Some(mut writer) = self.writer.lock().await.take() {
            let _ = writer.shutdown().await;
        }
    }

    /// Sends one `tools/call` request and awaits its raw structured result.
    ///
    /// # Errors
    ///
    /// Returns [`ClientCallError::Closed`] if the transport is closed, or
    /// [`ClientCallError::Protocol`] if the daemon returns a protocol error.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<RawToolResult, ClientCallError> {
        if self.is_closed() {
            return Err(ClientCallError::Closed(
                io::Error::new(io::ErrorKind::NotConnected, "daemon socket is closed").into(),
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending IPC map poisoned")
            .insert(id, sender);

        let request = WireCallRequest {
            jsonrpc: "2.0",
            id,
            method: "tools/call",
            params: WireCallParams { name, arguments },
        };
        let mut frame = match serde_json::to_vec(&request) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.pending
                    .lock()
                    .expect("pending IPC map poisoned")
                    .remove(&id);
                return Err(ClientCallError::Protocol(error.into()));
            }
        };
        frame.push(b'\n');

        let write_result = {
            let mut guard = self.writer.lock().await;
            if let Some(writer) = guard.as_mut() {
                match writer.write_all(&frame).await {
                    Ok(()) => writer.flush().await,
                    Err(error) => Err(error),
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "daemon socket writer is closed",
                ))
            }
        };
        if let Err(error) = write_result {
            self.closed.store(true, Ordering::Release);
            self.pending
                .lock()
                .expect("pending IPC map poisoned")
                .remove(&id);
            return Err(ClientCallError::Closed(
                anyhow!(error).context("daemon socket write failed"),
            ));
        }

        receiver.await.unwrap_or_else(|_| {
            Err(ClientCallError::Closed(
                io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "daemon socket closed before reply",
                )
                .into(),
            ))
        })
    }
}

/// Spawns the background task that routes daemon replies to callers.
fn spawn_client_reader<R>(
    mut reader: BufReader<R>,
    pending: Arc<PendingCalls>,
    closed: Arc<AtomicBool>,
    cancel: CancellationToken,
) where
    R: AsyncRead + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let mut line = Vec::new();
        let exit_reason = loop {
            line.clear();
            let read_line = read_bounded_line(&mut reader, &mut line, MAX_RESPONSE_LINE_BYTES);
            let outcome = tokio::select! {
                biased;
                () = cancel.cancelled() => break "daemon socket cancelled",
                outcome = read_line => outcome,
            };
            match outcome {
                LineOutcome::Line => {
                    let trimmed = trim_line(&line);
                    if trimmed.is_empty() {
                        continue;
                    }
                    if !deliver_client_line(trimmed, &pending) {
                        break "daemon returned invalid JSON frame";
                    }
                }
                LineOutcome::Oversized => {
                    break "daemon response exceeded maximum line size";
                }
                LineOutcome::Eof => break "daemon closed socket",
                LineOutcome::Io(_) => break "daemon socket read error",
            }
        };
        closed.store(true, Ordering::Release);
        let waiters: Vec<_> = pending
            .lock()
            .expect("pending IPC map poisoned")
            .drain()
            .collect();
        for (_, sender) in waiters {
            let _ = sender.send(Err(ClientCallError::Closed(
                io::Error::new(io::ErrorKind::ConnectionReset, exit_reason).into(),
            )));
        }
    });
}

/// Parses one daemon reply frame and wakes the caller for that ID.
/// Returns `false` if the line is not valid JSON.
fn deliver_client_line(trimmed: &[u8], pending: &PendingCalls) -> bool {
    let Ok(response) = serde_json::from_slice::<WireResponse>(trimmed) else {
        return false;
    };
    let Some(id) = response.id else {
        return true;
    };
    let Some(sender) = pending
        .lock()
        .expect("pending IPC map poisoned")
        .remove(&id)
    else {
        return true;
    };
    if let Some(error) = response.error {
        let _ = sender.send(Err(ClientCallError::Protocol(anyhow!(
            "daemon JSON-RPC error ({}): {}",
            error.code,
            error.message
        ))));
        return true;
    }
    let Some(result) = response.result else {
        let _ = sender.send(Err(ClientCallError::Protocol(anyhow!(
            "daemon reply had neither result nor error"
        ))));
        return true;
    };
    let is_error = result.is_error == Some(true);
    let structured_content = if let Some(raw) = result.structured_content {
        raw
    } else {
        // Older daemon versions without `structuredContent` put error text in `content`.
        let fallback = result
            .content
            .into_iter()
            .find_map(|item| item.text)
            .unwrap_or_else(|| "null".to_string());
        if is_error {
            let envelope = DomainError::Internal { message: fallback }.to_envelope();
            serde_json::value::to_raw_value(&envelope).expect("error envelope is valid JSON")
        } else {
            serde_json::value::to_raw_value(&Value::Null).expect("null is valid JSON")
        }
    };
    let _ = sender.send(Ok(RawToolResult {
        structured_content,
        is_error,
    }));
    true
}

// Server side on `daemon.sock`.

/// Borrowed probe of the first line on a new `localSocket` connection.
#[derive(Deserialize)]
struct HandshakeProbe<'a> {
    /// JSON-RPC version string.
    #[serde(borrow)]
    jsonrpc: Option<Cow<'a, str>>,
    /// Raw JSON request ID.
    #[serde(borrow)]
    id: Option<&'a RawValue>,
    /// JSON-RPC method name.
    #[serde(borrow)]
    method: Option<Cow<'a, str>>,
    /// Optional `initialize` parameters.
    #[serde(borrow)]
    params: Option<HandshakeProbeParams<'a>>,
}

/// Optional parameters inside [`HandshakeProbe`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HandshakeProbeParams<'a> {
    /// Optional `clientInfo` object.
    #[serde(borrow)]
    client_info: Option<HandshakeClientInfo<'a>>,
}

/// Optional `clientInfo` inside [`HandshakeProbeParams`].
#[derive(Deserialize)]
struct HandshakeClientInfo<'a> {
    /// Client name string.
    #[serde(borrow)]
    name: Option<Cow<'a, str>>,
}

/// `initialize` reply sent to internal peers.
#[derive(Serialize)]
struct InternalInitResponse<'a> {
    /// Always `"2.0"`.
    jsonrpc: &'static str,
    /// Echoed request ID.
    id: &'a RawValue,
    /// Minimal `InitializeResult` body.
    result: InternalInitResult<'a>,
}

/// Result body of [`InternalInitResponse`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InternalInitResult<'a> {
    /// Negotiated protocol version.
    protocol_version: &'static str,
    /// Server capabilities object.
    capabilities: InternalCapabilities,
    /// Daemon identity.
    server_info: InternalPeerInfo<'a>,
}

/// Server capabilities in [`InternalInitResult`].
#[derive(Serialize)]
struct InternalCapabilities {
    /// Enabled `tools` capability.
    tools: EmptyObject,
}

/// Inbound JSON-RPC frame from an internal peer after initialization.
#[derive(Deserialize)]
struct InternalPeerMessage<'a> {
    /// Raw request ID (`None` for notifications).
    id: Option<&'a RawValue>,
    /// Method name.
    #[serde(borrow)]
    method: Option<Cow<'a, str>>,
    /// Raw parameters slice.
    params: Option<&'a RawValue>,
}

/// Parameters of an internal `tools/call` request.
#[derive(Deserialize)]
struct InternalCallParams {
    /// Public MCP tool name.
    name: String,
    /// Tool arguments map.
    #[serde(default)]
    arguments: Option<Map<String, Value>>,
}

/// Outbound raw `tools/call` response on `daemon.sock` without `content`.
#[derive(Serialize)]
struct InternalCallResponse<'a> {
    /// Always `"2.0"`.
    jsonrpc: &'static str,
    /// Request ID slice.
    id: &'a RawValue,
    /// Single-copy raw tool result.
    result: InternalToolResult<'a>,
}

/// Result body of [`InternalCallResponse`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InternalToolResult<'a> {
    /// Raw structured JSON content without a second text copy.
    structured_content: &'a RawValue,
    /// Whether the tool call produced an error.
    is_error: bool,
}

/// Outbound JSON-RPC protocol error frame on `daemon.sock`.
#[derive(Serialize)]
struct InternalErrorResponse<'a> {
    /// Always `"2.0"`.
    jsonrpc: &'static str,
    /// Request ID slice.
    id: &'a RawValue,
    /// JSON-RPC error object.
    error: WireRpcError,
}

/// Serves one accepted `localSocket` connection as either an internal raw peer
/// or a standard external MCP peer.
pub async fn serve_client_stream<S>(stream: S, server: ToolServer, cancellation: CancellationToken)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut first_line = Vec::new();
    let read_first = read_bounded_line(&mut reader, &mut first_line, DEFAULT_MAX_LINE_LENGTH);
    let outcome = tokio::select! {
        biased;
        () = cancellation.cancelled() => return,
        outcome = read_first => outcome,
    };
    match outcome {
        LineOutcome::Line => {}
        LineOutcome::Eof => return,
        LineOutcome::Oversized => {
            crate::process::log_daemon("daemon MCP connection rejected: oversized initial line");
            return;
        }
        LineOutcome::Io(error) => {
            crate::process::log_daemon(&format!("daemon MCP connection failed: {error}"));
            return;
        }
    }

    if let Some(init_reply) = internal_init_reply(trim_line(&first_line)) {
        if write_half.write_all(&init_reply).await.is_err() || write_half.flush().await.is_err() {
            return;
        }
        serve_internal_peer(reader, write_half, server, cancellation).await;
        return;
    }

    let chained = Cursor::new(first_line).chain(reader);
    if let Err(error) =
        crate::mcp::serve_stream_with_ct(server, chained, write_half, cancellation).await
    {
        crate::process::log_daemon(&format!("daemon MCP connection failed: {error}"));
    }
}

/// Returns the serialized handshake reply if `line` is an internal peer `initialize`.
fn internal_init_reply(line: &[u8]) -> Option<Vec<u8>> {
    let probe: HandshakeProbe<'_> = serde_json::from_slice(line).ok()?;
    if probe.jsonrpc.as_deref() != Some("2.0") || probe.method.as_deref() != Some("initialize") {
        return None;
    }
    let id = probe.id?;
    let client_name = probe
        .params
        .as_ref()
        .and_then(|params| params.client_info.as_ref())
        .and_then(|info| info.name.as_deref())?;
    if client_name != INTERNAL_CLIENT_NAME {
        return None;
    }
    let reply = InternalInitResponse {
        jsonrpc: "2.0",
        id,
        result: InternalInitResult {
            protocol_version: "2025-11-25",
            capabilities: InternalCapabilities {
                tools: EmptyObject {},
            },
            server_info: InternalPeerInfo {
                name: "ghidra-mcp",
                version: env!("CARGO_PKG_VERSION"),
            },
        },
    };
    let mut bytes = serde_json::to_vec(&reply).ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

/// Serves raw `tools/call` requests without `content[0].text` for an internal peer.
async fn serve_internal_peer<R, W>(
    mut reader: BufReader<R>,
    write_half: W,
    server: ToolServer,
    cancellation: CancellationToken,
) where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let writer = Arc::new(Mutex::new(write_half));
    let mut tasks = JoinSet::new();
    let mut line = Vec::new();
    loop {
        while tasks.try_join_next().is_some() {}
        line.clear();
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return;
            }
            outcome = read_bounded_line(&mut reader, &mut line, DEFAULT_MAX_LINE_LENGTH) => outcome,
        };
        match outcome {
            LineOutcome::Line => {
                let trimmed = trim_line(&line);
                if trimmed.is_empty() {
                    continue;
                }
                dispatch_internal_line(trimmed, &server, &writer, &mut tasks);
            }
            LineOutcome::Oversized | LineOutcome::Eof | LineOutcome::Io(_) => break,
        }
    }
    tokio::select! {
        () = cancellation.cancelled() => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        () = async { while tasks.join_next().await.is_some() {} } => {}
    }
}

/// Parses one internal peer request line and spawns its execution task.
fn dispatch_internal_line<W>(
    trimmed: &[u8],
    server: &ToolServer,
    writer: &Arc<Mutex<W>>,
    tasks: &mut JoinSet<()>,
) where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let Ok(message) = serde_json::from_slice::<InternalPeerMessage<'_>>(trimmed) else {
        return;
    };
    let Some(raw_id) = message.id else {
        return;
    };
    let id_box = raw_id.to_owned();
    if message.method.as_deref() != Some("tools/call") {
        let writer = writer.clone();
        tasks.spawn(async move {
            let response = InternalErrorResponse {
                jsonrpc: "2.0",
                id: &id_box,
                error: WireRpcError {
                    code: -32601,
                    message: "Method not found".to_string(),
                },
            };
            if let Ok(mut frame) = serde_json::to_vec(&response) {
                frame.push(b'\n');
                write_frame(&writer, &frame).await;
            }
        });
        return;
    }

    let parsed = message
        .params
        .and_then(|raw| serde_json::from_str::<InternalCallParams>(raw.get()).ok());
    let Some(params) = parsed else {
        let writer = writer.clone();
        tasks.spawn(async move {
            let response = InternalErrorResponse {
                jsonrpc: "2.0",
                id: &id_box,
                error: WireRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                },
            };
            if let Ok(mut frame) = serde_json::to_vec(&response) {
                frame.push(b'\n');
                write_frame(&writer, &frame).await;
            }
        });
        return;
    };

    let server = server.clone();
    let writer = writer.clone();
    tasks.spawn(async move {
        let outcome = server
            .call_raw(params.name, params.arguments.unwrap_or_default())
            .await;
        let response = InternalCallResponse {
            jsonrpc: "2.0",
            id: &id_box,
            result: InternalToolResult {
                structured_content: &outcome.structured_content,
                is_error: outcome.is_error,
            },
        };
        let mut frame = Vec::with_capacity(outcome.structured_content.get().len() + 96);
        if serde_json::to_writer(&mut frame, &response).is_ok() {
            frame.push(b'\n');
            write_frame(&writer, &frame).await;
        }
    });
}

/// Writes and flushes one complete JSON-RPC line under the socket writer lock.
async fn write_frame<W>(writer: &Mutex<W>, frame: &[u8])
where
    W: AsyncWrite + Unpin,
{
    let mut guard = writer.lock().await;
    if guard.write_all(frame).await.is_ok() {
        let _ = guard.flush().await;
    }
}

/// Outcome of one bounded newline-delimited read.
enum LineOutcome {
    /// A complete `\n`-terminated line is stored in `buf`.
    Line,
    /// The line exceeded `max_len` and its bytes were discarded.
    Oversized,
    /// End of stream.
    Eof,
    /// Stream read failure.
    Io(io::Error),
}

/// Decision for one buffered read slice.
enum ReadStep {
    /// Complete line buffered.
    Done,
    /// Need more bytes.
    More,
    /// Oversized line ended at this newline.
    OversizedDone,
    /// Oversized line continues past this buffer.
    OversizedMore,
}

/// Reads one `\n`-terminated line and keeps `buf` within `max_len`.
async fn read_bounded_line<R>(
    reader: &mut BufReader<R>,
    buf: &mut Vec<u8>,
    max_len: usize,
) -> LineOutcome
where
    R: AsyncRead + Unpin,
{
    let mut discard = false;
    loop {
        let (consumed, step) = {
            let available = match reader.fill_buf().await {
                Ok(slice) => slice,
                Err(error) => return LineOutcome::Io(error),
            };
            if available.is_empty() {
                return LineOutcome::Eof;
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(available.len(), |idx| idx + 1);
            if discard {
                (
                    take,
                    if newline.is_some() {
                        ReadStep::OversizedDone
                    } else {
                        ReadStep::OversizedMore
                    },
                )
            } else if buf.len().saturating_add(take) > max_len {
                buf.clear();
                (
                    take,
                    if newline.is_some() {
                        ReadStep::OversizedDone
                    } else {
                        ReadStep::OversizedMore
                    },
                )
            } else {
                buf.extend_from_slice(&available[..take]);
                (
                    take,
                    if newline.is_some() {
                        ReadStep::Done
                    } else {
                        ReadStep::More
                    },
                )
            }
        };
        reader.consume(consumed);
        match step {
            ReadStep::Done => return LineOutcome::Line,
            ReadStep::More => {}
            ReadStep::OversizedDone => return LineOutcome::Oversized,
            ReadStep::OversizedMore => discard = true,
        }
    }
}

/// Removes `\r\n` or `\n` at the end and any UTF-8 byte order mark at the start.
fn trim_line(line: &[u8]) -> &[u8] {
    let without_lf = line.strip_suffix(b"\n").unwrap_or(line);
    let without_crlf = without_lf.strip_suffix(b"\r").unwrap_or(without_lf);
    without_crlf
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(without_crlf)
}
