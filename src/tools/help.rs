// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The `ghidra_help` tool: the domains, the operations of one domain, and the
//! parameter schema, the md5 rule and the effects of one operation.

use super::catalog::{self, Domain, Operation, HELP_TOOL};
use super::{parse, Output};
use crate::error::DomainError;
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The arguments of `ghidra_help`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelpArgs {
    /// A domain name, a legacy domain tool name, or an operation tool name.
    domain: Option<String>,
    /// An operation of the domain.
    operation: Option<String>,
}

/// Formats the help result of one operation.
fn operation_help(domain: &Domain, operation: &Operation) -> Output {
    let domain_tool = domain.tool();
    let operation_name = &operation.name;
    (
        format!("Help for {domain_tool} {operation_name}"),
        json!({
            "domain": domain_tool,
            "operation": operation.name,
            "tool": operation.tool(domain.name),
            "description": operation.description,
            "md5": operation.md5,
            "effects": operation.effects,
            "inputSchema": operation.schema
        }),
    )
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
        let tools: Vec<String> = catalog::domains().iter().map(Domain::tool).collect();
        return Ok((
            format!("Found {} domain tool(s)", tools.len()),
            json!({ "domains": tools }),
        ));
    };
    if args.operation.is_none() {
        if let Some((domain, operation)) = catalog::operation_of_tool(&name) {
            return Ok(operation_help(domain, operation));
        }
    }
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
                    "tool": operation.tool(domain.name),
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
    Ok(operation_help(domain, operation))
}
