// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The public MCP tools: `ghidra_help` and one tool for each domain.
//!
//! The bridge domains and operations use the names of the bridge MCP server.
//! A domain tool takes `operation` and `params`. An operation that names one
//! session also takes `md5`, the MD5 of that session.
//!
//! There are two types of operations:
//!
//! - The local operations (see [`local`]). The daemon runs them.
//! - The bridge methods of the bridge contract. The daemon sends them to the
//!   bridge of the session.
//!
//! [`call`] checks the required and unexpected top-level `params` fields
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

/// The objects that the operations use.
pub struct Daemon {
    /// The shared daemon state.
    pub state: Arc<McpState>,
    /// The upload credentials, for `ghidra_upload prepare`.
    pub uploads: Arc<UploadService>,
}

/// The summary text and the structured result of an operation.
type Output = (String, Value);

/// The validated input of one operation.
struct Request {
    /// The tool name and the operation name, for messages.
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

/// The arguments of a domain tool.
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

/// Finds the operation of a domain tool call and validates its arguments.
///
/// # Errors
///
/// Fails if the tool or the operation is unknown. Also fails if the arguments
/// do not obey the md5 rule or the top-level field rules of the operation.
fn prepare(tool: &str, arguments: Map<String, Value>) -> Result<(&'static Operation, Request)> {
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
