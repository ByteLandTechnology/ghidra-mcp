// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The `ghidra_help` tool: the domain tools, the operations of one domain, and
//! the parameter schema, the md5 rule and the effects of one operation.

use super::catalog::{self, HELP_TOOL};
use super::{parse, Output};
use crate::error::DomainError;
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The arguments of `ghidra_help`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelpArgs {
    /// A domain tool name or a domain name.
    domain: Option<String>,
    /// An operation of the domain.
    operation: Option<String>,
}

/// Runs `ghidra_help`.
///
/// # Errors
///
/// Fails with [`DomainError::InvalidArgument`] for an unknown argument or an
/// `operation` without `domain`, and with [`DomainError::MissingTarget`] for
/// an unknown domain or operation.
pub(super) fn run(arguments: Map<String, Value>) -> Result<Output> {
    let args: HelpArgs = parse(HELP_TOOL, Value::Object(arguments))?;
    let Some(name) = args.domain else {
        if args.operation.is_some() {
            return Err(DomainError::invalid_argument(
                "operation",
                format!("`{HELP_TOOL}` requires domain with operation"),
            )
            .into());
        }
        let tools: Vec<String> = catalog::domains()
            .iter()
            .map(catalog::Domain::tool)
            .collect();
        return Ok((
            format!("Found {} domain tool(s)", tools.len()),
            json!({ "domains": tools }),
        ));
    };
    let domain = catalog::domain(&name).ok_or_else(|| {
        DomainError::missing_target(name.clone(), format!("unknown domain: {name}"))
    })?;
    let tool = domain.tool();
    let Some(operation_name) = args.operation else {
        let operations: Vec<Value> = domain
            .operations
            .iter()
            .map(|operation| {
                json!({
                    "name": operation.name,
                    "description": operation.description,
                    "md5": operation.md5,
                    "effects": operation.effects
                })
            })
            .collect();
        return Ok((
            format!("Found {} operation(s) in {tool}", operations.len()),
            json!({ "domain": tool, "operations": operations }),
        ));
    };
    let operation = domain.require_operation(&operation_name)?;
    Ok((
        format!("Help for {tool} {operation_name}"),
        json!({
            "domain": tool,
            "operation": operation.name,
            "description": operation.description,
            "md5": operation.md5,
            "effects": operation.effects,
            "inputSchema": operation.schema
        }),
    ))
}
