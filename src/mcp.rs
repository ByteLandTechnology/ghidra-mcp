// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The MCP server handler. All transports use it.
//!
//! In the daemon, it runs the tool calls. In the stdio proxy, it sends them to
//! the daemon. In both roles, it shows the same tools (see [`crate::tools`]).

mod stdio;

pub use stdio::serve_stream_with_ct;

use crate::{
    error::DomainError,
    tools::{Daemon, ToolPayload},
};
use anyhow::Result;
use rmcp::{
    handler::server::ServerHandler,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
        ErrorData, Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
    RoleServer,
};
use serde_json::{value::RawValue, Map, Value};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// A structured tool response before external MCP text duplication.
#[derive(Debug, Clone)]
pub struct RawToolResult {
    /// Raw JSON value of `structuredContent`.
    pub structured_content: Box<RawValue>,
    /// Whether the tool call produced a domain or bridge error.
    pub is_error: bool,
}

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

    /// Runs one tool call without formatting `content[0].text` or `Value` trees
    /// for raw bridge payloads.
    pub async fn call_raw(&self, name: String, arguments: Map<String, Value>) -> RawToolResult {
        match &self.backend {
            Backend::Local(daemon) => {
                let (payload, is_error) = eval_local(daemon, &name, arguments).await;
                let structured_content = match payload {
                    ToolPayload::Raw(raw) => raw,
                    ToolPayload::Value(value) => serde_json::value::to_raw_value(&value)
                        .expect("tool Value serializes to RawValue"),
                };
                RawToolResult {
                    structured_content,
                    is_error,
                }
            }
            Backend::Proxy(manager) => match manager.call_tool_raw(name, arguments).await {
                Ok(result) => result,
                Err(error) => {
                    if error.downcast_ref::<DomainError>().is_none() {
                        crate::process::record_daemon_error(&format!(
                            "proxy tool call failed: {error:#}"
                        ));
                    }
                    let envelope = DomainError::from_error(&error).to_envelope();
                    let structured_content = serde_json::value::to_raw_value(&envelope)
                        .expect("error envelope serializes to RawValue");
                    RawToolResult {
                        structured_content,
                        is_error: true,
                    }
                }
            },
        }
    }

    /// Runs one tool call for external MCP handlers that need `CallToolResult`.
    /// The result contains the failures, as MCP specifies. Failures are not protocol errors.
    pub async fn call(&self, name: String, arguments: Map<String, Value>) -> CallToolResult {
        let (text, structured, is_error) = match &self.backend {
            Backend::Local(daemon) => {
                let (payload, is_error) = eval_local(daemon, &name, arguments).await;
                match payload {
                    ToolPayload::Raw(raw) => {
                        let text = raw.get().to_owned();
                        let value = serde_json::from_str(raw.get())
                            .expect("bridge RawValue contains valid JSON");
                        (text, value, is_error)
                    }
                    ToolPayload::Value(value) => (value.to_string(), value, is_error),
                }
            }
            Backend::Proxy(_) => {
                let raw = self.call_raw(name, arguments).await;
                let text = raw.structured_content.get().to_owned();
                let value = serde_json::from_str(raw.structured_content.get())
                    .expect("proxy RawValue contains valid JSON");
                (text, value, raw.is_error)
            }
        };
        // Text-only clients need the same data as structured-content clients.
        let content = vec![ContentBlock::text(text)];
        let mut result = if is_error {
            CallToolResult::error(content)
        } else {
            CallToolResult::success(content)
        };
        result.structured_content = Some(structured);
        result
    }
}

/// Evaluates one local daemon tool call into `(payload, is_error)`.
async fn eval_local(
    daemon: &Daemon,
    name: &str,
    arguments: Map<String, Value>,
) -> (ToolPayload, bool) {
    if daemon.state.is_shutting_down() {
        return (
            ToolPayload::Value(DomainError::ShuttingDown.to_envelope()),
            true,
        );
    }
    match crate::tools::call(daemon, name, arguments).await {
        Ok((_summary, ToolPayload::Raw(raw))) => (ToolPayload::Raw(raw), false),
        Ok((_summary, ToolPayload::Value(structured))) => {
            let is_error = structured
                .pointer("/response/error")
                .is_some_and(|error| !error.is_null());
            (ToolPayload::Value(structured), is_error)
        }
        Err(error) => {
            if error.downcast_ref::<DomainError>().is_none() {
                crate::process::record_daemon_error(&format!("tool call failed: {error:#}"));
            }
            let domain_err = DomainError::from_error(&error);
            (ToolPayload::Value(domain_err.to_envelope()), true)
        }
    }
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
        let upload_url = (request.name == "ghidra_upload")
            .then(|| context.extensions.get::<axum::http::request::Parts>())
            .flatten()
            .and_then(|parts| crate::upload::request_url(&parts.uri, &parts.headers));
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
                    result.content = vec![ContentBlock::text(structured.to_string())];
                }
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
    serve_stream_with_ct(
        ToolServer::proxy()?,
        tokio::io::stdin(),
        tokio::io::stdout(),
        CancellationToken::new(),
    )
    .await
}

#[cfg(test)]
mod tests;
