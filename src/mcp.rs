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
        ServerCapabilities, ServerInfo, Tool,
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
                    let mut res = CallToolResult::error(vec![ContentBlock::text(err.to_string())]);
                    res.structured_content = Some(err.to_envelope());
                    return res;
                }
                to_tool_result(crate::tools::call(daemon, &name, arguments).await)
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
                    let mut res =
                        CallToolResult::error(vec![ContentBlock::text(domain_err.to_string())]);
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
    let (text, structured) = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            if error.downcast_ref::<DomainError>().is_none() {
                crate::process::record_daemon_error(&format!("tool call failed: {error:#}"));
            }
            let domain_err = DomainError::from_error(&error);
            let mut result =
                CallToolResult::error(vec![ContentBlock::text(domain_err.to_string())]);
            result.structured_content = Some(domain_err.to_envelope());
            return result;
        }
    };
    let bridge_error = structured
        .pointer("/response/error")
        .filter(|error| !error.is_null());
    let text = bridge_error
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or(&text);
    let mut result = if bridge_error.is_some() {
        CallToolResult::error(vec![ContentBlock::text(text)])
    } else {
        CallToolResult::success(vec![ContentBlock::text(text)])
    };
    result.structured_content = Some(structured);
    result
}

impl ServerHandler for ToolServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
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
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResponse, ErrorData> {
        Ok(self
            .call(
                request.name.into_owned(),
                request.arguments.unwrap_or_default(),
            )
            .await
            .into())
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
}
