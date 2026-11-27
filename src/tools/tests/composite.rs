// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of composite operations in `ghidra_listing`, `ghidra_function`, and
//! `ghidra_reference`.

use super::*;

/// Makes sure that `window.get` and `control_flow_graph.get` go to the bridge.
#[test]
fn composite_view_and_graph_operations_use_their_bridge_methods() {
    let md5 = "0123456789abcdef0123456789abcdef";

    let (window_op, window_req) = prepare(
        "ghidra_listing",
        object(json!({
            "operation": "window.get",
            "md5": md5,
            "params": {
                "filter": { "kind": "all" },
                "page": { "limit": 80 },
                "scan": { "range": { "start": "ram:00401000" }, "timeout_ms": 15000 }
            }
        })),
    )
    .expect("valid listing window call");
    match &window_op.route {
        Route::Bridge(method) => assert_eq!(method, "listing_window.get"),
        Route::Local(_) => panic!("ghidra_listing window.get must go to the bridge"),
    }
    assert!(window_op.effects.read_only);
    assert_eq!(window_req.md5.as_deref(), Some(md5));

    let extra_param = prepare(
        "ghidra_listing",
        object(json!({
            "operation": "window.get",
            "md5": md5,
            "params": { "unexpected": true }
        })),
    )
    .err()
    .expect("window.get rejects unknown parameter");
    assert!(reason(&extra_param).contains("Valid parameters: `filter`, `page`, `scan`."));

    let (cfg_op, cfg_req) = prepare(
        "ghidra_function",
        object(json!({
            "operation": "control_flow_graph.get",
            "md5": md5,
            "params": {
                "selector": { "entry": "ram:00401000" },
                "max_instructions": 2048,
                "scan": { "timeout_ms": 20000 }
            }
        })),
    )
    .expect("valid control_flow_graph.get call");
    match &cfg_op.route {
        Route::Bridge(method) => assert_eq!(method, "control_flow_graph.get"),
        Route::Local(_) => panic!("ghidra_function control_flow_graph.get must go to the bridge"),
    }
    assert!(cfg_op.effects.read_only);
    assert_eq!(cfg_req.params["selector"]["entry"], "ram:00401000");

    let cfg_missing = prepare(
        "ghidra_function",
        object(json!({
            "operation": "control_flow_graph.get",
            "md5": md5,
            "params": {}
        })),
    )
    .err()
    .expect("control_flow_graph.get requires selector");
    assert!(reason(&cfg_missing).contains("requires parameter `selector`"));
}

/// Makes sure that reference context queries and help entries match composite schemas.
#[test]
fn reference_context_and_composite_help_entries_match_catalog() {
    let md5 = "0123456789abcdef0123456789abcdef";

    let (ref_op, ref_req) = prepare(
        "ghidra_reference",
        object(json!({
            "operation": "context.list",
            "md5": md5,
            "params": {
                "filter": { "entry": "ram:00401000", "type": "UNCONDITIONAL_CALL" },
                "page": { "limit": 50 },
                "scan": { "timeout_ms": 10000 }
            }
        })),
    )
    .expect("valid reference context.list call");
    match &ref_op.route {
        Route::Bridge(method) => assert_eq!(method, "reference_context.list"),
        Route::Local(_) => panic!("ghidra_reference context.list must go to the bridge"),
    }
    assert!(ref_op.effects.read_only);
    assert_eq!(ref_req.params["filter"]["entry"], "ram:00401000");

    let ref_missing = prepare(
        "ghidra_reference",
        object(json!({
            "operation": "context.list",
            "md5": md5,
            "params": {}
        })),
    )
    .err()
    .expect("context.list requires filter");
    assert!(reason(&ref_missing).contains("requires parameter `filter`"));

    for (domain_name, op_name) in [
        ("ghidra_listing", "window.get"),
        ("ghidra_function", "control_flow_graph.get"),
        ("ghidra_reference", "context.list"),
    ] {
        let (_, doc) = help::run(object(json!({
            "domain": domain_name,
            "operation": op_name
        })))
        .expect("help entry");
        assert_eq!(doc["md5"], "required");
        assert_eq!(doc["effects"]["read_only"], true);
        assert_eq!(doc["inputSchema"]["type"], "object");
    }
}
