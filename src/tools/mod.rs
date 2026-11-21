// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The public MCP tools: `ghidra_help` and one flat tool for each operation.
//!
//! Each operation tool takes its parameter fields directly at the top level.
//! An operation that names one session also takes `md5`, the MD5 of that
//! session, at the top level. For compatibility with older clients, `tools/call`
//! also accepts legacy `ghidra_<domain>` calls with `(operation, md5, params)`.
//!
//! There are two types of operations:
//!
//! - The local operations (see [`local`]). The daemon runs them.
//! - The bridge methods of the bridge contract. The daemon sends them to the
//!   bridge of the session.
//!
//! [`call`] checks the required and unexpected top-level parameter fields
//! against the schema of the operation (see [`catalog`]). Local handlers and
//! the bridge check the other parameters.
//!
//! Each operation returns a short summary text and a structured JSON result.
//! Bridge methods return `{"response": …}`.

mod catalog;
mod help;
mod local;

pub use catalog::tool_definitions;

use crate::error::DomainError;
use crate::project::deserialize_optional_md5;
use crate::session;
use crate::state::McpState;
use crate::upload::UploadService;
use anyhow::Result;
use catalog::{Operation, Route, HELP_TOOL};
use futures::future::BoxFuture;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::SystemTime;
use tokio_util::sync::CancellationToken;

/// The objects that the operations use.
pub struct Daemon {
    /// The shared daemon state.
    pub state: Arc<McpState>,
    /// The upload credentials, for `ghidra_upload_prepare`.
    pub uploads: Arc<UploadService>,
    /// The process data and the shutdown trigger, for `ghidra_daemon_shutdown`.
    pub control: Control,
}

/// The process data of the daemon, and the trigger that stops it.
pub struct Control {
    /// `ghidra_daemon_shutdown` cancels this token. Then the daemon stops.
    pub shutdown: CancellationToken,
    /// The time when the daemon started.
    pub started_at: SystemTime,
    /// The URL of the HTTP MCP endpoint.
    pub mcp_url: String,
}

impl Default for Control {
    /// Makes control data with a new token, the current time and no URL.
    fn default() -> Self {
        Self {
            shutdown: CancellationToken::new(),
            started_at: SystemTime::now(),
            mcp_url: String::new(),
        }
    }
}

/// The summary text and the structured result of an operation.
type Output = (String, Value);

/// The validated input of one operation.
struct Request {
    /// The tool name (or legacy tool and operation name), for messages.
    label: String,
    /// The session that the operation names. The md5 rule of the operation
    /// controls if it has a value.
    md5: Option<String>,
    /// The parameters of the operation, as a JSON object.
    params: Value,
}

impl Request {
    /// Returns the session of an operation with a required md5.
    ///
    /// # Panics
    ///
    /// Panics if the request has no md5. The md5 rule of the operation
    /// prevents this.
    fn session(&self) -> String {
        self.md5
            .clone()
            .expect("the md5 rule makes sure that the request has md5")
    }
}

/// Runs a local operation.
type Handler = for<'a> fn(&'a Daemon, Request) -> BoxFuture<'a, Result<Output>>;

/// The optional top-level `md5` field of a flat operation tool call.
#[derive(Deserialize)]
struct Md5Field {
    /// The session that the operation names.
    #[serde(default, deserialize_with = "deserialize_optional_md5")]
    md5: Option<String>,
}

/// The arguments of a legacy domain tool.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCall {
    /// The operation in the domain.
    operation: String,
    /// The session that the operation names.
    #[serde(default, deserialize_with = "deserialize_optional_md5")]
    md5: Option<String>,
    /// The parameters of the operation.
    #[serde(default)]
    params: Map<String, Value>,
}

/// Runs one tool call.
///
/// # Errors
///
/// Fails if the tool, the operation or the arguments are not valid, or if the
/// operation fails.
pub async fn call(daemon: &Daemon, tool: &str, arguments: Map<String, Value>) -> Result<Output> {
    if tool == HELP_TOOL {
        return help::run(arguments);
    }
    let (operation, request) = prepare(tool, arguments)?;
    match &operation.route {
        Route::Local(run) => run(daemon, request).await,
        Route::Bridge(method) => {
            let md5 = request.session();
            let response = session::call(&daemon.state, &md5, method, request.params).await?;
            Ok((
                format!("{} completed", request.label),
                json!({ "response": response }),
            ))
        }
    }
}

/// Finds the operation of a flat tool call or a legacy domain tool call, and
/// validates its arguments.
///
/// # Errors
///
/// Fails if the tool or the operation is unknown. Also fails if the arguments
/// do not obey the md5 rule or the top-level field rules of the operation.
fn prepare(tool: &str, mut arguments: Map<String, Value>) -> Result<(&'static Operation, Request)> {
    if let Some((_, operation)) = catalog::operation_of_tool(tool) {
        let label = tool.to_string();
        let md5 = match arguments.remove("md5") {
            None => None,
            Some(raw_md5) => {
                let Md5Field { md5 } = parse(&label, json!({ "md5": raw_md5 }))?;
                md5
            }
        };
        operation.check_md5(&label, md5.as_deref())?;
        operation.validate(&label, &arguments)?;
        return Ok((
            operation,
            Request {
                label,
                md5,
                params: Value::Object(arguments),
            },
        ));
    }

    let domain = catalog::domain_of_tool(tool)
        .ok_or_else(|| DomainError::invalid_argument("tool", format!("unknown tool: {tool}")))?;
    let ToolCall {
        operation,
        md5,
        params,
    } = parse(tool, Value::Object(arguments))?;
    let label = format!("{tool} {operation}");
    let operation = domain.require_operation(&operation)?;
    operation.check_md5(&label, md5.as_deref())?;
    operation.validate(&label, &params)?;
    Ok((
        operation,
        Request {
            label,
            md5,
            params: Value::Object(params),
        },
    ))
}

/// Deserializes the arguments of a tool or the parameters of an operation.
/// `label` identifies the tool or the operation in the message.
///
/// # Errors
///
/// Fails with the label and the serde description of the problem.
fn parse<T: DeserializeOwned>(label: &str, value: Value) -> Result<T> {
    // Put the cause in the message. The client sees tool errors without their chain.
    T::deserialize(value).map_err(|error| {
        DomainError::invalid_argument(label, format!("invalid arguments for `{label}`: {error}"))
            .into()
    })
}

#[cfg(test)]
mod tests;
