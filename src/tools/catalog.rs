// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The operation catalog: the domains, their operations, and the MCP tool
//! definitions.
//!
//! The catalog has the local operations and the bridge methods. The bridge
//! methods use the same domains and operation names as the MCP server of the
//! bridge (`McpToolRegistry` in the bridge repository).
//!
//! `tools/list` publishes `ghidra_help` and one flat tool for each operation,
//! such as `ghidra_decompilation_get`. Each operation tool merges its top-level
//! `md5` field with the operation properties based on [`Md5Rule`]. Legacy
//! `ghidra_<domain>` names remain available in `tools/call`.

use super::local::{Basis, LocalOperation, LOCAL_OPERATIONS};
use super::Handler;
use crate::error::DomainError;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
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

/// A group of operations. Legacy `ghidra_<domain>` calls dispatch by domain.
pub(super) struct Domain {
    /// The domain name, for example `function`.
    pub name: &'static str,
    /// The operations, in the sequence of `ghidra_help` and `tools/list`.
    pub operations: Vec<Operation>,
}

impl Domain {
    /// Returns the legacy domain tool name, for example `ghidra_function`.
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
    /// The description that `tools/list` and `ghidra_help` show.
    pub description: String,
    /// The JSON Schema of the operation parameters (without `md5`).
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

/// Returns all domains.
pub(super) fn domains() -> &'static [Domain] {
    &CATALOG
}

/// Returns the domain and operation of a per-operation tool name, such as
/// `ghidra_decompilation_get`.
pub(super) fn operation_of_tool(tool: &str) -> Option<(&'static Domain, &'static Operation)> {
    for domain in CATALOG.iter() {
        for operation in &domain.operations {
            if operation.tool(domain.name) == tool {
                return Some((domain, operation));
            }
        }
    }
    None
}

/// Returns the domain of an exact legacy domain tool name, such as `ghidra_function`.
pub(super) fn domain_of_tool(tool: &str) -> Option<&'static Domain> {
    let name = tool.strip_prefix(TOOL_PREFIX)?;
    CATALOG.iter().find(|domain| domain.name == name)
}

/// Returns the domain of a legacy domain tool name, or of a domain name without
/// the prefix. `ghidra_help` accepts the two forms.
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

/// Returns the tool names of the bridge MCP server in the sequence of
/// `bridge/docs/mcp-tools.json`.
///
/// # Panics
///
/// Panics if the tool contract of the bridge is not valid.
fn bridge_tool_sequence() -> Vec<String> {
    // The bridge build makes this contract. It gives the operation sequence,
    // which the method contract does not keep.
    let contract: Value = serde_json::from_str(include_str!("../../bridge/docs/mcp-tools.json"))
        .expect("parse the bridge MCP tool contract");
    contract["tools"]
        .as_array()
        .expect("bridge MCP tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("bridge tool name").to_string())
        .filter(|name| name != HELP_TOOL)
        .collect()
}

/// Makes the catalog. The local operations come first, then the bridge
/// methods. Operations that match tools of the bridge MCP server get the
/// sequence of that server.
///
/// # Panics
///
/// Panics if the local operations or the bridge contracts are not consistent.
/// Examples include an unknown domain, a duplicate tool name, or an `md5`
/// property collision.
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
        let operation = Operation {
            name,
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
    let sequence = bridge_tool_sequence();
    for domain in &mut domains {
        let domain_name = domain.name;
        let position = |operation: &Operation| {
            let tool_name = operation.tool(domain_name);
            sequence.iter().position(|item| item == &tool_name)
        };
        // An operation that the bridge does not show goes last.
        domain
            .operations
            .sort_by_key(|operation| position(operation).unwrap_or(usize::MAX));
    }
    domains.retain(|domain| !domain.operations.is_empty());

    let mut published = BTreeSet::from([HELP_TOOL.to_string()]);
    for domain in &domains {
        for operation in &domain.operations {
            let tool_name = operation.tool(domain.name);
            assert!(
                published.insert(tool_name.clone()),
                "duplicate tool name `{tool_name}`"
            );
            let _ = merge_input_schema(&tool_name, operation.md5, &operation.schema);
        }
    }
    for domain in &domains {
        let legacy = domain.tool();
        assert!(
            !published.contains(&legacy),
            "legacy domain tool `{legacy}` collides with an operation tool"
        );
    }
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
        description: local.description.to_string(),
        schema,
        md5: local.md5,
        effects,
        route: Route::Local(local.run),
    }
}

/// Returns `true` if `value` contains a nested JSON Schema `$ref`.
fn contains_ref(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(contains_ref),
        Value::Object(map) => map.contains_key("$ref") || map.values().any(contains_ref),
        _ => false,
    }
}

/// Merges the top-level `md5` property with the parameter schema of one
/// operation.
///
/// # Panics
///
/// Panics if `schema` is not an object schema with `properties`, or if `schema`
/// defines a top-level `md5` property.
pub(super) fn merge_input_schema(tool_name: &str, md5_rule: Md5Rule, schema: &Value) -> Value {
    let op_properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("operation `{tool_name}` schema has no `properties` object"));
    assert!(
        !op_properties.contains_key("md5"),
        "operation `{tool_name}` defines reserved top-level property `md5`"
    );

    let mut properties = Map::new();
    let mut required = Vec::new();
    if md5_rule != Md5Rule::Absent {
        properties.insert(
            "md5".into(),
            json!({
                "type": "string",
                "description": concat!(
                    "The binary MD5: exactly 32 hexadecimal characters. Use the actual ",
                    "file digest or the MD5 of an existing session, not a name or label."
                )
            }),
        );
        if md5_rule == Md5Rule::Required {
            required.push(json!("md5"));
        }
    }
    for (field, field_schema) in op_properties {
        properties.insert(field.clone(), field_schema.clone());
    }
    if let Some(op_required) = schema.get("required").and_then(Value::as_array) {
        required.extend(op_required.iter().cloned());
    }

    let properties_value = Value::Object(properties);
    let mut merged = Map::new();
    merged.insert("type".into(), json!("object"));
    if contains_ref(&properties_value) {
        if let Some(defs) = schema.get("$defs") {
            merged.insert("$defs".into(), defs.clone());
        }
    }
    merged.insert("properties".into(), properties_value);
    if !required.is_empty() {
        merged.insert("required".into(), Value::Array(required));
    }
    Value::Object(merged)
}

/// Returns the MCP tool definitions: `ghidra_help`, then one flat tool for each
/// operation.
pub fn tool_definitions() -> Vec<Value> {
    let mut tools = vec![json!({
        "name": HELP_TOOL,
        "description": concat!(
            "Get the domains, the operations of one domain, or the parameter schema, md5 ",
            "rule, and effects of one operation. Pass no arguments to list the domains. Set ",
            "domain to a domain name, or set domain to a tool name."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": concat!(
                        "A domain name, such as function, or a tool name, such as ",
                        "ghidra_function_list"
                    )
                },
                "operation": {
                    "type": "string",
                    "description": "An operation name in the domain, such as list"
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
        for operation in &domain.operations {
            tools.push(operation.definition(domain.name));
        }
    }
    tools
}

impl Operation {
    /// Returns the MCP tool name of this operation in `domain`.
    pub fn tool(&self, domain: &str) -> String {
        format!("{TOOL_PREFIX}{domain}_{}", self.name.replace('.', "_"))
    }

    /// Returns the flat MCP tool definition of this operation in `domain`.
    fn definition(&self, domain: &str) -> Value {
        let name = self.tool(domain);
        let input_schema = merge_input_schema(&name, self.md5, &self.schema);
        json!({
            "name": name,
            "description": self.description,
            "inputSchema": input_schema,
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
                format!("`{label}` requires parameter `{field}`. Missing parameters: {fields}."),
            )
            .into());
        }
        if self.schema.get("additionalProperties") == Some(&json!(false)) {
            if let Some(key) = params.keys().find(|key| !properties.contains_key(*key)) {
                return Err(DomainError::invalid_argument(
                    key,
                    format!("`{label}` does not accept parameter `{key}`"),
                )
                .into());
            }
        }
        Ok(())
    }
}
