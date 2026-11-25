// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The MCP server handler. All transports use it.
//!
//! In the daemon, it runs the tool calls. In the stdio proxy, it sends them to
//! the daemon. In both roles, it shows the same tools (see [`crate::tools`]).

use crate::{error::DomainError, tools::Daemon};
use anyhow::Result;
use rmcp::{
    handler::server::ServerHandler,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
        ErrorData, Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
    RoleServer, ServiceExt,
};
use serde_json::{Map, Value};
use std::sync::Arc;

/// The location where tool calls run.
#[derive(Clone)]
enum Backend {
    /// In this process, the daemon.
    Local(Arc<Daemon>),
    /// The daemon through its local socket. The stdio proxy and the CLI use this backend.
    Proxy(Arc<crate::daemon::ProxyConnectionManager>),
}

/// The MCP handler of the daemon transports and of the stdio proxy.
#[derive(Clone)]
pub struct ToolServer {
    /// The location where tool calls run.
    backend: Backend,
}

impl ToolServer {
    /// Makes a handler that runs tool calls in this daemon.
    pub fn local(daemon: Daemon) -> Self {
        Self {
            backend: Backend::Local(Arc::new(daemon)),
        }
    }

    /// Makes a handler that sends tool calls through a persistent daemon connection.
    ///
    /// # Errors
    ///
    /// Fails if the configuration or private runtime directory is invalid.
    pub fn proxy() -> Result<Self> {
        Ok(Self {
            backend: Backend::Proxy(crate::daemon::ProxyConnectionManager::global()?),
        })
    }

    /// Returns the tool definitions. The list does not need the daemon.
    pub fn tools() -> Vec<Tool> {
        crate::tools::tool_definitions()
            .into_iter()
            .map(|definition| {
                serde_json::from_value(definition).expect("built-in tool definition is valid MCP")
            })
            .collect()
    }

    /// Runs one tool call. The result contains the failures, as MCP specifies.
    /// Failures are not protocol errors.
    pub async fn call(&self, name: String, arguments: Map<String, Value>) -> CallToolResult {
        match &self.backend {
            Backend::Local(daemon) => {
                if daemon.state.is_shutting_down() {
                    let err = DomainError::ShuttingDown;
                    let mut res = CallToolResult::error(Vec::new());
                    res.structured_content = Some(err.to_envelope());
                    res
                } else {
                    to_tool_result(crate::tools::call(daemon, &name, arguments).await)
                }
            }
            Backend::Proxy(manager) => match manager.call_tool(name, arguments).await {
                Ok(result) => result,
                Err(error) => {
                    if error.downcast_ref::<DomainError>().is_none() {
                        crate::process::record_daemon_error(&format!(
                            "proxy tool call failed: {error:#}"
                        ));
                    }
                    let domain_err = DomainError::from_error(&error);
                    let mut res = CallToolResult::error(Vec::new());
                    res.structured_content = Some(domain_err.to_envelope());
                    res
                }
            },
        }
    }
}

/// Keeps the structured result. If an error occurs, formats it with `DomainError`
/// into structured JSON-RPC error content.
fn to_tool_result(outcome: Result<(String, Value)>) -> CallToolResult {
    let (_text, structured) = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            if error.downcast_ref::<DomainError>().is_none() {
                crate::process::record_daemon_error(&format!("tool call failed: {error:#}"));
            }
            let domain_err = DomainError::from_error(&error);
            let mut result = CallToolResult::error(Vec::new());
            result.structured_content = Some(domain_err.to_envelope());
            return result;
        }
    };
    let bridge_error = structured
        .pointer("/response/error")
        .filter(|error| !error.is_null());
    let mut result = if bridge_error.is_some() {
        CallToolResult::error(Vec::new())
    } else {
        CallToolResult::success(Vec::new())
    };
    result.structured_content = Some(structured);
    result
}

impl ServerHandler for ToolServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ghidra-mcp", env!("CARGO_PKG_VERSION")))
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        let protocol_version = context.protocol_version();
        std::future::ready(Ok(list_tools_result(protocol_version.as_ref())))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        Self::tools().into_iter().find(|tool| tool.name == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResponse, ErrorData> {
        let http_parts = context.extensions.get::<axum::http::request::Parts>();
        let upload_url = (request.name == "ghidra_upload")
            .then_some(http_parts)
            .flatten()
            .and_then(|parts| crate::upload::request_url(&parts.uri, &parts.headers));
        let is_internal_proxy = matches!(self.backend, Backend::Local(_))
            && http_parts.is_none()
            && context
                .peer
                .peer_info()
                .is_some_and(|info| info.client_info.name == crate::daemon::PROXY_CLIENT_NAME);
        let mut result = self
            .call(
                request.name.into_owned(),
                request.arguments.unwrap_or_default(),
            )
            .await;
        if result.is_error != Some(true) {
            if let (Some(url), Some(structured)) = (upload_url, result.structured_content.as_mut())
            {
                if let Some(value) = structured.get_mut("url") {
                    *value = Value::String(url);
                }
            }
        }
        // Text-only MCP clients need the same data as structured-content clients.
        if !is_internal_proxy {
            if let Some(structured) = &result.structured_content {
                result.content = vec![ContentBlock::text(structured.to_string())];
            }
        }
        Ok(result.into())
    }
}

/// Makes the version-specific result of `tools/list`.
fn list_tools_result(protocol_version: Option<&ProtocolVersion>) -> ListToolsResult {
    let result = ListToolsResult::with_all_items(ToolServer::tools());
    if protocol_version.is_some_and(|version| version >= &ProtocolVersion::V_2026_07_28) {
        result.with_ttl_ms(0).with_cache_scope(CacheScope::Private)
    } else {
        result
    }
}

/// Serves MCP through stdio as a proxy to the daemon, until the client disconnects.
///
/// # Errors
///
/// Fails if the stdio transport fails.
pub async fn serve_stdio() -> Result<()> {
    ToolServer::proxy()?
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Makes an isolated local `ToolServer` without Ghidra processes.
    fn local_test_server(root: &std::path::Path) -> ToolServer {
        let state = crate::state::test_state(root);
        std::fs::create_dir_all(&state.paths.tmp_dir).unwrap();
        let authorities = ["127.0.0.1:18489".to_string(), "localhost:18489".to_string()];
        let uploads = crate::upload::UploadService::new(
            state.clone(),
            authorities,
            tokio_util::sync::CancellationToken::new(),
        )
        .unwrap();
        ToolServer::local(Daemon {
            state,
            uploads,
            control: crate::tools::Control::default(),
        })
    }

    /// Makes sure that internal proxy hops omit `content` while MCP edges format `content[0].text`.
    #[tokio::test]
    async fn omits_text_on_internal_socket_and_formats_at_mcp_edges() {
        use interprocess::local_socket::traits::tokio::Listener as _;
        use rmcp::model::{ClientCapabilities, ClientConfig};
        use tokio_util::sync::CancellationToken;

        let root = tempfile::tempdir().unwrap();
        let local = local_test_server(root.path());
        let runtime = root.path().join("run");
        let (endpoint, listener) = crate::daemon::test_listener(&runtime).unwrap();
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let socket_server = local.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = server_cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let stream = accepted.unwrap();
                        let server = socket_server.clone();
                        let ct = server_cancel.child_token();
                        tokio::spawn(async move {
                            if let Ok(service) = server.serve_with_ct(stream, ct).await {
                                let _ = service.waiting().await;
                            }
                        });
                    }
                }
            }
        });

        // 1. Internal ProxyConnectionManager over daemon.sock transfers empty content.
        let manager = Arc::new(crate::daemon::ProxyConnectionManager::with_runtime_dir(
            runtime,
        ));
        let internal_ok = manager
            .call_tool("ghidra_help".into(), Map::new())
            .await
            .unwrap();
        assert_eq!(internal_ok.content, Vec::new());
        assert!(internal_ok.structured_content.is_some());

        let internal_err = manager
            .call_tool("unknown_tool".into(), Map::new())
            .await
            .unwrap();
        assert_eq!(internal_err.is_error, Some(true));
        assert_eq!(internal_err.content, Vec::new());
        assert!(internal_err.structured_content.is_some());

        // 2. Proxy ToolServer (the stdio role) formats content[0].text once for external peers,
        // even if the stdio peer uses the internal proxy client name.
        let proxy_server = ToolServer {
            backend: Backend::Proxy(manager.clone()),
        };
        assert_eq!(
            proxy_server
                .call("ghidra_help".into(), Map::new())
                .await
                .content,
            Vec::new()
        );

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let stdio_task = tokio::spawn(async move {
            let service = proxy_server.serve(server_io).await.unwrap();
            let _ = service.waiting().await;
        });
        let spoofed_config = ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new(crate::daemon::PROXY_CLIENT_NAME, "1.0.0"),
        );
        let stdio_client = spoofed_config.serve(client_io).await.unwrap();
        let stdio_res = stdio_client
            .peer()
            .call_tool(CallToolRequestParams::new("ghidra_help"))
            .await
            .unwrap();
        let stdio_text = &stdio_res.content[0].as_text().unwrap().text;
        assert_eq!(
            serde_json::from_str::<Value>(stdio_text).unwrap(),
            stdio_res.structured_content.unwrap()
        );
        drop(stdio_client);
        let _ = stdio_task.await;

        // 3. External MCP client on localSocket receives populated content[0].text.
        let ext_stream = crate::daemon::test_connect(&endpoint).await.unwrap();
        let ext_client = ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("external-socket-client", "1.0.0"),
        )
        .serve(ext_stream)
        .await
        .unwrap();
        let ext_res = ext_client
            .peer()
            .call_tool(CallToolRequestParams::new("ghidra_help"))
            .await
            .unwrap();
        let ext_text = &ext_res.content[0].as_text().unwrap().text;
        assert_eq!(
            serde_json::from_str::<Value>(ext_text).unwrap(),
            ext_res.structured_content.unwrap()
        );
        drop(ext_client);

        cancel.cancel();
        let _ = accept_task.await;
    }

    /// Makes sure that HTTP clients still get `content[0].text` if they claim the proxy name.
    #[tokio::test]
    async fn http_peer_with_proxy_name_still_receives_text_content() {
        use axum::{
            body::{to_bytes, Body},
            extract::Request,
            http::{header, Method, StatusCode},
        };
        use serde_json::json;
        use tower::ServiceExt as _;

        let root = tempfile::tempdir().unwrap();
        let server = local_test_server(root.path());
        let authorities = ["127.0.0.1:18489".to_string(), "localhost:18489".to_string()];
        let app = crate::mcp_http::router(
            server,
            authorities,
            tokio_util::sync::CancellationToken::new(),
        );
        let init = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": crate::daemon::PROXY_CLIENT_NAME, "version": "2.1.0" }
            }
        });
        let init_req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1:18489")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(init.to_string()))
            .unwrap();
        let init_resp = app.clone().oneshot(init_req).await.unwrap();
        assert_eq!(init_resp.status(), StatusCode::OK);
        let session_id = init_resp
            .headers()
            .get("mcp-session-id")
            .and_then(|val| val.to_str().ok())
            .map(str::to_owned);

        let call = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "ghidra_help", "arguments": {} }
        });
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1:18489")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-03-26");
        if let Some(id) = session_id {
            builder = builder.header("mcp-session-id", id);
        }
        let call_resp = app
            .oneshot(builder.body(Body::from(call.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(call_resp.status(), StatusCode::OK);
        let bytes = to_bytes(call_resp.into_body(), 64 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let text = body["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            body["result"]["structuredContent"]
        );
    }
}
