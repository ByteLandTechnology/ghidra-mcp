// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of `ghidra_listing` and `ghidra_memory` mutation schemas and routes.

use super::*;

/// Makes sure that `ghidra_listing` and `ghidra_memory` mutations validate parameters and route.
#[test]
fn listing_and_memory_mutations_validate_and_route() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let valid_cases = [
        (
            "ghidra_listing",
            "instruction.assemble",
            json!({
                "selector": { "address": "ram:00100000" },
                "instructions": ["NOP"],
                "pad_nop": true
            }),
            "instruction.assemble",
        ),
        (
            "ghidra_listing",
            "instruction.disassemble",
            json!({
                "selector": { "kind": "address", "address": "ram:00100000" },
                "follow_flow": false
            }),
            "instruction.disassemble",
        ),
        (
            "ghidra_listing",
            "code_unit.clear",
            json!({
                "selector": { "kind": "range", "start": "ram:00100000", "end": "ram:00100003" },
                "clear_context": true
            }),
            "code_unit.clear",
        ),
        (
            "ghidra_memory",
            "write",
            json!({
                "selector": { "address": "ram:00100000" },
                "patch": { "bytes": { "encoding": "hex", "data": "90", "length": 1 } },
                "clear_existing": true,
                "disassemble": true
            }),
            "memory.write",
        ),
    ];
    for (tool, name, params, expected_method) in valid_cases {
        let (operation, request) = prepare(
            tool,
            object(json!({ "operation": name, "md5": md5, "params": params })),
        )
        .expect("valid mutation call");
        match &operation.route {
            Route::Bridge(method) => assert_eq!(method, expected_method),
            Route::Local(_) => panic!("{tool} {name} must go to the bridge"),
        }
        assert_eq!(request.md5.as_deref(), Some(md5));
    }

    let missing = prepare(
        "ghidra_listing",
        object(json!({ "operation": "instruction.assemble", "md5": md5, "params": {} })),
    )
    .err()
    .expect("missing assemble parameters");
    assert!(reason(&missing).contains("`selector`, `instructions`"));
}

/// Makes sure that `ghidra_help` shows the new `ghidra_listing` and `ghidra_memory` schemas.
#[test]
fn help_shows_listing_and_memory_mutation_schemas() {
    let (_, write) =
        help::run(object(json!({ "domain": "memory", "operation": "write" }))).expect("operation");
    let write_props = &write["inputSchema"]["properties"];
    assert!(write_props["clear_existing"].is_object());
    assert!(write_props["disassemble"].is_object());

    let (_, assemble) = help::run(object(
        json!({ "domain": "listing", "operation": "instruction.assemble" }),
    ))
    .expect("assemble operation");
    assert_eq!(assemble["md5"], "required");
    assert_eq!(assemble["effects"]["destructive"], true);
    let assemble_props = &assemble["inputSchema"]["properties"];
    assert!(assemble_props["selector"].is_object());
    assert!(assemble_props["instructions"].is_object());
    assert!(assemble_props["pad_nop"].is_object());

    let (_, disassemble) = help::run(object(
        json!({ "domain": "ghidra_listing", "operation": "instruction.disassemble" }),
    ))
    .expect("disassemble operation");
    assert_eq!(disassemble["md5"], "required");
    assert_eq!(disassemble["effects"]["mutates_program"], true);
    assert_eq!(disassemble["effects"]["destructive"], false);
    assert!(disassemble["inputSchema"]["properties"]["follow_flow"].is_object());

    let (_, clear) = help::run(object(
        json!({ "domain": "listing", "operation": "code_unit.clear" }),
    ))
    .expect("clear operation");
    assert_eq!(clear["md5"], "required");
    assert_eq!(clear["effects"]["destructive"], true);
    assert!(clear["inputSchema"]["properties"]["clear_context"].is_object());
}
