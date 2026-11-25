// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The operation catalog: the domains, their operations, and the MCP tool
//! definitions.
//!
//! `tools/list` publishes `ghidra_help` and one underscored tool for each
//! operation (`ghidra_<domain>_<operation>`). Legacy `ghidra_<domain>` lookup
//! stays available for `tools/call` and `ghidra_help`.
//!
//! Each operation has the effects of the bridge contract, and a rule for the
//! `md5` argument of the tool. An operation that names one session takes the
//! MD5 of that session in `md5`.

use super::local::{Basis, LocalOperation, LOCAL_OPERATIONS};
use super::schema::operation_input_schema;
use super::Handler;
use crate::error::DomainError;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

/// The prefix of all tool names.
pub(super) const TOOL_PREFIX: &str = "ghidra_";

/// The name of the help tool.
pub(super) const HELP_TOOL: &str = "ghidra_help";

/// The domains in the sequence of `tools/list`. The domains of the bridge have
/// the sequence of the bridge MCP server.
const DOMAINS: &[&str] = &[
    "session",
    "upload",
    "job",
    "daemon",
    "bridge",
    "program",
    "address",
    "memory",
    "listing",
    "global_variable",
    "function",
    "analysis",
    "decompilation",
    "symbol",
    "reference",
    "comment",
    "data_type",
    "batch",
];

/// The catalog. The daemon makes it one time, at its first use.
static CATALOG: LazyLock<Vec<Domain>> = LazyLock::new(build);

/// The effects of an operation. The fields and their names are the same as the
/// `effects` of the bridge contract. `ghidra_help` shows them.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the fields are the independent flags of the bridge contract"
)]
pub(super) struct Effects {
    /// The operation changes nothing.
    pub read_only: bool,
    /// The operation can change the program in the Ghidra project.
    pub mutates_program: bool,
    /// The operation can delete or overwrite data, or stop a process.
    pub destructive: bool,
    /// A repeated call with the same arguments has no more effect.
    pub idempotent: bool,
    /// The operation can run while an auto-analysis runs.
    pub allowed_during_analysis: bool,
    /// The operation runs in a Ghidra database transaction.
    pub requires_transaction: bool,
}

/// The rule for the `md5` argument of an operation.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Md5Rule {
    /// The operation names one session. The call must have `md5`.
    Required,
    /// The operation can name one session, for example to open it by MD5.
    Optional,
    /// The operation does not name a session. The call must not have `md5`.
    Absent,
}

/// A group of operations in one domain.
pub(super) struct Domain {
    /// The domain name, for example `function`.
    pub name: &'static str,
    /// The operations, in the sequence of `ghidra_help` and `tools/list`.
    pub operations: Vec<Operation>,
}

impl Domain {
    /// Returns the legacy MCP domain tool name.
    pub fn tool(&self) -> String {
        format!("{TOOL_PREFIX}{}", self.name)
    }

    /// Returns the operation with the name `name`.
    pub fn operation(&self, name: &str) -> Option<&Operation> {
        self.operations
            .iter()
            .find(|operation| operation.name == name)
    }

    /// Returns the operation with the name `name`.
    ///
    /// # Errors
    ///
    /// Fails with [`DomainError::MissingTarget`] if the domain has no
    /// operation with this name.
    pub fn require_operation(&self, name: &str) -> Result<&Operation> {
        self.operation(name).ok_or_else(|| {
            let tool = self.tool();
            DomainError::missing_target(name, format!("unknown operation of {tool}: {name}")).into()
        })
    }
}

/// One operation of a domain.
pub(super) struct Operation {
    /// The operation name in the domain, for example `parameter.create`.
    pub name: String,
    /// The underscored MCP tool name, for example `ghidra_function_parameter_create`.
    pub tool: String,
    /// The description that `tools/list` and `ghidra_help` show.
    pub description: String,
    /// The JSON Schema of the operation parameters.
    pub schema: Value,
    /// The rule for the `md5` argument.
    pub md5: Md5Rule,
    /// The effects of the operation.
    pub effects: Effects,
    /// The location where the operation runs.
    pub route: Route,
}

/// The location where an operation runs.
pub(super) enum Route {
    /// The daemon runs the handler.
    Local(Handler),
    /// The daemon sends the bridge method to the bridge of the session.
    Bridge(String),
}

/// Returns the underscored MCP tool name for `domain` and `operation`.
fn operation_tool_name(domain: &str, operation: &str) -> String {
    format!("{TOOL_PREFIX}{domain}_{}", operation.replace('.', "_"))
}

/// Returns all domains.
pub(super) fn domains() -> &'static [Domain] {
    &CATALOG
}

/// Returns the operation of an underscored tool name, such as `ghidra_function_list`.
pub(super) fn operation_of_tool(tool: &str) -> Option<&'static Operation> {
    if !tool.starts_with(TOOL_PREFIX) {
        return None;
    }
    for domain in CATALOG.iter() {
        if let Some(operation) = domain.operations.iter().find(|item| item.tool == tool) {
            return Some(operation);
        }
    }
    None
}

/// Returns the domain of an exact legacy tool name, for example `ghidra_function`.
pub(super) fn domain_of_tool(tool: &str) -> Option<&'static Domain> {
    let name = tool.strip_prefix(TOOL_PREFIX)?;
    CATALOG.iter().find(|domain| domain.name == name)
}

/// Returns the domain of a tool name, or of a domain name without the prefix.
/// `ghidra_help` accepts the two forms.
pub(super) fn domain(name: &str) -> Option<&'static Domain> {
    domain_of_tool(name).or_else(|| CATALOG.iter().find(|domain| domain.name == name))
}

/// Returns the domain and the operation of a bridge method, or `None` if the
/// daemon does not show the method as an MCP operation. The bridge MCP server
/// uses the same domains and operation names.
///
/// # Panics
///
/// Panics if the method name has no `.`, or if its domain is not in [`DOMAINS`].
fn bridge_target(method: &str) -> Option<(&'static str, String)> {
    let (prefix, operation) = method.split_once('.').expect("bridge method has a domain");
    let target = match prefix {
        // The bridge MCP server also does not show the contract.
        "interface" => return None,
        // `ghidra_session_close` stops the bridge with the lifecycle lock and
        // records the new session status. A direct stop does not.
        "session" if operation == "shutdown" => return None,
        "session" => ("bridge", operation.to_string()),
        "program_language" => ("program", format!("language.{operation}")),
        "address_space" => ("address", format!("space.{operation}")),
        "memory_block" => ("memory", format!("block.{operation}")),
        "code_unit" | "data_unit" | "instruction" | "flow_override" => {
            ("listing", format!("{prefix}.{operation}"))
        }
        "function_call" => ("function", format!("call.{operation}")),
        "function_parameter" => ("function", format!("parameter.{operation}")),
        "function_local_variable" => ("function", format!("local_variable.{operation}")),
        "data_type_category" => ("data_type", format!("category.{operation}")),
        _ => (DOMAINS[domain_index(prefix)], operation.to_string()),
    };
    Some(target)
}

/// Returns the index of a domain in [`DOMAINS`].
///
/// # Panics
///
/// Panics if the domain is not in [`DOMAINS`].
fn domain_index(name: &str) -> usize {
    DOMAINS
        .iter()
        .position(|domain| *domain == name)
        .unwrap_or_else(|| panic!("domain `{name}` is not in the domain table"))
}

/// Returns the effects of a bridge method in the contract.
///
/// # Panics
///
/// Panics if the contract does not have the expected effects.
fn bridge_effects(method: &str, contract: &Value) -> Effects {
    serde_json::from_value(contract["effects"].clone())
        .unwrap_or_else(|error| panic!("effects of bridge method `{method}`: {error}"))
}

/// Returns the operation tool names of the bridge MCP server, in the sequence
/// of that server.
///
/// # Panics
///
/// Panics if the tool contract of the bridge is not valid.
fn bridge_tool_operations() -> Vec<String> {
    // The bridge build makes this contract. It gives the operation sequence,
    // which the method contract does not keep.
    let contract: Value = serde_json::from_str(include_str!("../../bridge/docs/mcp-tools.json"))
        .expect("parse the bridge MCP tool contract");
    contract["tools"]
        .as_array()
        .expect("bridge MCP tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("bridge tool name"))
        .filter(|&name| name != HELP_TOOL)
        .map(str::to_string)
        .collect()
}

/// Makes the catalog. The local operations come first, then the bridge
/// methods. The operations of a domain of the bridge MCP server then get the
/// sequence of that server.
///
/// # Panics
///
/// Panics if the local operations or the bridge contracts are not consistent,
/// for example for an unknown domain or a duplicate operation.
fn build() -> Vec<Domain> {
    let mut domains: Vec<Domain> = DOMAINS
        .iter()
        .map(|&name| Domain {
            name,
            operations: Vec::new(),
        })
        .collect();
    let mut add = |name: &str, operation: Operation| {
        let domain = &mut domains[domain_index(name)];
        assert!(
            domain.operation(&operation.name).is_none(),
            "duplicate operation {name} {}",
            operation.name
        );
        domain.operations.push(operation);
    };

    for local in LOCAL_OPERATIONS {
        add(local.domain, local_operation(local));
    }
    for (method, contract) in crate::bridge::methods() {
        if LOCAL_OPERATIONS
            .iter()
            .any(|local| local.extended_method() == Some(method.as_str()))
        {
            continue;
        }
        let Some((domain, name)) = bridge_target(method) else {
            continue;
        };
        let tool = operation_tool_name(domain, &name);
        let operation = Operation {
            name,
            tool,
            description: contract["description"]
                .as_str()
                .expect("bridge method description")
                .to_string(),
            schema: contract["input_schema"].clone(),
            md5: Md5Rule::Required,
            effects: bridge_effects(method, contract),
            route: Route::Bridge(method.clone()),
        };
        add(domain, operation);
    }
    let sequence = bridge_tool_operations();
    for domain in &mut domains {
        let position = |tool: &str| sequence.iter().position(|item| item == tool);
        // An operation that the bridge does not show goes last.
        domain
            .operations
            .sort_by_key(|operation| position(&operation.tool).unwrap_or(usize::MAX));
    }
    domains.retain(|domain| !domain.operations.is_empty());
    domains
}

/// Makes the catalog entry of a local operation. If the operation extends a
/// bridge method, it gets the parameters and the effects of that method too.
///
/// # Panics
///
/// Panics if the extended bridge method is not in the contract.
fn local_operation(local: &LocalOperation) -> Operation {
    let (schema, effects) = match local.basis {
        Basis::Own(effects) => ((local.schema)(), effects),
        Basis::Extends(method) => {
            let contract = crate::bridge::methods()
                .get(method)
                .unwrap_or_else(|| panic!("bridge method `{method}` is not in the contract"));
            let mut schema = contract["input_schema"].clone();
            let local_schema = (local.schema)();
            let local_properties = local_schema["properties"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            let properties = schema["properties"]
                .as_object_mut()
                .expect("bridge schema properties");
            for (field, field_schema) in local_properties {
                properties.entry(field).or_insert(field_schema);
            }
            (schema, bridge_effects(method, contract))
        }
    };
    Operation {
        name: local.name.to_string(),
        tool: operation_tool_name(local.domain, local.name),
        description: local.description.to_string(),
        schema,
        md5: local.md5,
        effects,
        route: Route::Local(local.run),
    }
}

/// Returns the MCP tool definitions: `ghidra_help`, then one underscored tool
/// for each operation.
pub fn tool_definitions() -> Vec<Value> {
    let mut tools = vec![json!({
        "name": HELP_TOOL,
        "description": concat!(
            "Get the domains, the operations and full schemas of one domain, or one ",
            "operation. Set domain to get the tool name, description, md5 rule, effects, ",
            "and full parameter inputSchema of each operation in a domain. Add operation ",
            "to get one operation. Pass no arguments to list the domains."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "A domain name, such as function, or a legacy domain tool name"
                },
                "operation": {
                    "type": "string",
                    "description": "An operation of the domain. Requires domain."
                }
            }
        },
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })];
    for domain in CATALOG.iter() {
        tools.extend(domain.operations.iter().map(Operation::definition));
    }
    tools
}

impl Operation {
    /// Returns the MCP tool definition of the operation.
    fn definition(&self) -> Value {
        json!({
            "name": self.tool,
            "description": self.description,
            "inputSchema": operation_input_schema(self),
            "annotations": {
                "readOnlyHint": self.effects.read_only,
                "destructiveHint": self.effects.destructive,
                "idempotentHint": self.effects.idempotent,
                "openWorldHint": false
            }
        })
    }
    /// Examines the `md5` argument against the md5 rule of the operation.
    /// `label` identifies the operation in the error messages.
    ///
    /// # Errors
    ///
    /// Fails with [`DomainError::InvalidArgument`] if `md5` is absent for a
    /// [`Md5Rule::Required`] operation, or present for a [`Md5Rule::Absent`]
    /// operation.
    pub fn check_md5(&self, label: &str, md5: Option<&str>) -> Result<()> {
        match (self.md5, md5) {
            (Md5Rule::Required, None) => {
                Err(DomainError::invalid_argument("md5", format!("`{label}` requires md5")).into())
            }
            (Md5Rule::Absent, Some(_)) => Err(DomainError::invalid_argument(
                "md5",
                format!("`{label}` does not name a session and does not accept md5"),
            )
            .into()),
            _ => Ok(()),
        }
    }

    /// Examines the required and unexpected parameters against the schema.
    /// `label` identifies the operation in the error messages.
    ///
    /// # Errors
    ///
    /// Fails with [`DomainError::InvalidArgument`] if a required parameter is
    /// absent, or if the schema does not accept a parameter.
    pub fn validate(&self, label: &str, params: &Map<String, Value>) -> Result<()> {
        let Some(properties) = self.schema.get("properties").and_then(Value::as_object) else {
            return Ok(());
        };
        let required = self.schema["required"].as_array().into_iter().flatten();
        let missing: Vec<&str> = required
            .filter_map(Value::as_str)
            .filter(|field| !params.contains_key(*field))
            .collect();
        if let Some(field) = missing.first() {
            let fields = missing
                .iter()
                .map(|field| format!("`{field}`"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(DomainError::invalid_argument(
                *field,
                format!(
                    "`{label}` requires parameter `{field}`. Missing parameters: {fields}. \
                     Call {HELP_TOOL} with the domain and operation to get the params schema"
                ),
            )
            .into());
        }
        if self.schema.get("additionalProperties") == Some(&json!(false)) {
            if let Some(key) = params.keys().find(|key| !properties.contains_key(*key)) {
                let mut valid_keys: Vec<&str> = properties.keys().map(String::as_str).collect();
                valid_keys.sort_unstable();
                let valid = if valid_keys.is_empty() {
                    "none".to_string()
                } else {
                    valid_keys
                        .into_iter()
                        .map(|name| format!("`{name}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                return Err(DomainError::invalid_argument(
                    key,
                    format!(
                        "`{label}` does not accept parameter `{key}`. Valid parameters: {valid}. \
                         Call {HELP_TOOL} with the domain and operation to get the params schema"
                    ),
                )
                .into());
            }
        }
        Ok(())
    }
}
