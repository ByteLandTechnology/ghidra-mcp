// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of `ghidra_listing` `string.list` and `ghidra_memory` `find` operations.

use super::*;

/// Makes sure that `string.list` and `memory.find` use their bridge methods and help schemas.
#[test]
fn search_operations_route_to_bridge_and_expose_help_schemas() {
    let md5 = "0123456789abcdef0123456789abcdef";
    for (tool, op_name, bridge_method, params) in [
        (
            "ghidra_listing",
            "string.list",
            "string.list",
            json!({ "filter": { "regex": "https?://", "include_candidates": true } }),
        ),
        (
            "ghidra_memory",
            "find",
            "memory.find",
            json!({ "filter": { "pattern": "48 8B ?? ??" } }),
        ),
    ] {
        let (op, req) = prepare(
            tool,
            object(json!({ "operation": op_name, "md5": md5, "params": params })),
        )
        .expect("valid search call");
        assert!(op.md5 == Md5Rule::Required);
        assert!(op.effects.read_only);
        match &op.route {
            Route::Bridge(method) => assert_eq!(method, bridge_method),
            Route::Local(_) => panic!("{tool} {op_name} must go to the bridge"),
        }
        assert_eq!(req.md5.as_deref(), Some(md5));
        let (_, schema) =
            help::run(object(json!({ "domain": tool, "operation": op_name }))).expect("help");
        assert_eq!(schema["md5"], "required");
        assert!(schema["inputSchema"]["properties"]["filter"].is_object());
        assert!(schema["inputSchema"]["properties"]["scan"].is_object());
        assert!(schema["inputSchema"]["properties"]["page"].is_object());
    }
}
