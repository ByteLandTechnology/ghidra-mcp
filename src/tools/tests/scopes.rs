// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of list scopes and relation fields in tool schemas and help output.

use super::*;

/// Makes sure that `ghidra_help` and `prepare` accept list scopes and relation fields.
#[test]
fn list_scopes_and_relation_schemas_are_published() {
    let md5 = "0123456789abcdef0123456789abcdef";

    let tools = tool_definitions();
    let reference_tool = tools
        .iter()
        .find(|tool| tool["name"] == "ghidra_reference")
        .expect("ghidra_reference tool");
    let ref_params = &reference_tool["inputSchema"]["properties"]["params"]["properties"];
    assert!(ref_params["scan"].is_object());
    assert_eq!(
        ref_params["filter"]["properties"]["selector"]["properties"]["kind"]["enum"],
        json!(["address", "function", "range"])
    );

    let (_, reference_help) = help::run(object(
        json!({ "domain": "reference", "operation": "list" }),
    ))
    .expect("reference help");
    assert!(reference_help["inputSchema"]["properties"]["scan"].is_object());
    assert!(
        reference_help["inputSchema"]["properties"]["filter"]["properties"]["selector"].is_object()
    );
    let ref_fields = reference_help["inputSchema"]["properties"]["projection"]["properties"]
        ["fields"]["items"]["enum"]
        .as_array()
        .expect("reference fields");
    assert!(ref_fields.contains(&json!("from_function")));
    assert!(ref_fields.contains(&json!("to_function")));

    let (_, instruction_help) = help::run(object(json!({
        "domain": "listing",
        "operation": "instruction.list"
    })))
    .expect("instruction help");
    assert!(
        instruction_help["inputSchema"]["properties"]["filter"]["properties"]["selector"]
            .is_object()
    );

    let (_, code_unit_help) = help::run(object(json!({
        "domain": "listing",
        "operation": "code_unit.list"
    })))
    .expect("code_unit help");
    let unit_fields = code_unit_help["inputSchema"]["properties"]["projection"]["properties"]
        ["fields"]["items"]["enum"]
        .as_array()
        .expect("code_unit fields");
    assert!(unit_fields.contains(&json!("value")));
    assert!(unit_fields.contains(&json!("representation")));

    let (_, ref_call) = prepare(
        "ghidra_reference",
        object(json!({
            "operation": "list",
            "md5": md5,
            "params": {
                "filter": {
                    "direction": "from",
                    "selector": { "kind": "function", "entry": "0x401000" }
                },
                "scan": {
                    "range": { "start": "0x401000", "end": "0x402000" },
                    "timeout_ms": 5000
                }
            }
        })),
    )
    .expect("scoped reference.list call");
    assert_eq!(
        ref_call.params["filter"]["selector"]["entry"],
        json!("0x401000")
    );

    let (_, instr_call) = prepare(
        "ghidra_listing",
        object(json!({
            "operation": "instruction.list",
            "md5": md5,
            "params": {
                "filter": {
                    "selector": { "kind": "function", "entry": "0x401000" }
                }
            }
        })),
    )
    .expect("scoped instruction.list call");
    assert_eq!(
        instr_call.params["filter"]["selector"]["kind"],
        json!("function")
    );
}
