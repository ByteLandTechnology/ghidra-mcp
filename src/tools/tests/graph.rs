// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of call graph and basic block tool routes.

use super::*;

/// Checks that call graph and basic block operations use their bridge methods.
#[test]
fn call_graph_and_basic_block_use_bridge_methods() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let (graph_op, _) = prepare(
        "ghidra_function",
        object(json!({
            "operation": "call_graph.get",
            "md5": md5,
            "params": { "selector": { "entry": "0x101000" } }
        })),
    )
    .expect("valid call_graph.get call");
    match &graph_op.route {
        Route::Bridge(method) => assert_eq!(method, "function_call_graph.get"),
        Route::Local(_) => panic!("call_graph.get must go to the bridge"),
    }

    let (block_op, _) = prepare(
        "ghidra_listing",
        object(json!({
            "operation": "basic_block.list",
            "md5": md5,
            "params": {
                "filter": {
                    "selector": { "kind": "function", "entry": "0x101000" }
                }
            }
        })),
    )
    .expect("valid basic_block.list call");
    match &block_op.route {
        Route::Bridge(method) => assert_eq!(method, "basic_block.list"),
        Route::Local(_) => panic!("basic_block.list must go to the bridge"),
    }
}
