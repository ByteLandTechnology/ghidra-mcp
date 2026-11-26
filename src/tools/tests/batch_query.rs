// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of `ghidra_batch` `query` and the bridge tool annotations.

use super::*;

/// Makes sure that the bridge tool annotations match `ghidra-mcp`.
#[test]
fn bridge_tool_annotations_and_batch_operations_match_contract() {
    let contract: Value = serde_json::from_str(include_str!("../../../bridge/docs/mcp-tools.json"))
        .expect("contract");
    let bridge_tools = contract["tools"].as_array().expect("bridge tools");
    let actual_tools = tool_definitions();
    let actual = operations_by_tool(&actual_tools);
    assert_eq!(
        actual.get("ghidra_batch"),
        Some(&vec!["execute".to_string(), "query".to_string()])
    );

    for bridge_tool in bridge_tools {
        let name = bridge_tool["name"].as_str().expect("bridge tool name");
        let daemon_tool = actual_tools
            .iter()
            .find(|item| item["name"] == name)
            .unwrap_or_else(|| panic!("no daemon tool {name}"));
        if name == "ghidra_bridge" {
            // Without `shutdown`, `ghidra_bridge` only has `session.get`.
            assert_eq!(
                daemon_tool["annotations"],
                json!({
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                })
            );
        } else {
            assert_eq!(
                daemon_tool["annotations"], bridge_tool["annotations"],
                "annotations of {name}"
            );
        }
    }
}

/// Makes sure that `ghidra_batch query` goes to `batch.query` and has read-only effects.
#[test]
fn batch_query_uses_bridge_method_and_read_only_effects() {
    let tools = tool_definitions();
    let batch = tools
        .iter()
        .find(|item| item["name"] == "ghidra_batch")
        .expect("ghidra_batch");
    assert_eq!(
        batch["annotations"],
        json!({
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false,
            "openWorldHint": false
        })
    );

    let md5 = "0123456789abcdef0123456789abcdef";
    let (operation, request) = prepare(
        "ghidra_batch",
        object(json!({
            "operation": "query",
            "md5": md5,
            "params": {
                "items": [{ "method": "program.get", "params": {} }]
            }
        })),
    )
    .expect("valid batch query");
    match &operation.route {
        Route::Bridge(method) => assert_eq!(method, "batch.query"),
        Route::Local(_) => panic!("ghidra_batch query must go to the bridge"),
    }
    assert_eq!(request.label, "ghidra_batch query");

    let (_, query_help) = help::run(object(
        json!({ "domain": "ghidra_batch", "operation": "query" }),
    ))
    .expect("batch query help");
    assert_eq!(
        query_help["effects"],
        json!({
            "read_only": true,
            "mutates_program": false,
            "destructive": false,
            "idempotent": true,
            "allowed_during_analysis": true,
            "requires_transaction": false
        })
    );
}
