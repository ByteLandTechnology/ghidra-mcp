// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of C parser, C type string, and atomic function prototype schemas.

use super::*;

/// Checks `ghidra_data_type parse_c` schema, route, and parameter validation.
#[test]
fn data_type_parse_c_schema_and_call_preparation_work() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let (_, parse_help) = help::run(object(json!({
        "domain": "ghidra_data_type",
        "operation": "parse_c",
    })))
    .expect("parse_c help");
    assert_eq!(parse_help["md5"], "required");
    assert_eq!(parse_help["effects"]["mutates_program"], true);
    assert_eq!(parse_help["effects"]["idempotent"], false);
    assert_eq!(parse_help["inputSchema"]["required"], json!(["source"]));
    let props = &parse_help["inputSchema"]["properties"];
    assert_eq!(props["source"], json!({ "type": "string", "minLength": 1 }));
    assert!(props["category_path"].is_object());
    assert_eq!(
        props["conflict_mode"]["enum"],
        json!(["keep", "rename", "replace"])
    );

    let (parse_op, parse_req) = prepare(
        "ghidra_data_type",
        object(json!({
            "operation": "parse_c",
            "md5": md5,
            "params": {
                "source": "struct Node { const char *name; };",
                "category_path": "/parsed",
                "conflict_mode": "keep",
            },
        })),
    )
    .expect("valid parse_c call");
    assert!(matches!(
        &parse_op.route,
        Route::Bridge(method) if method == "data_type.parse_c"
    ));
    assert_eq!(parse_req.params["category_path"], "/parsed");
    assert_eq!(parse_req.params["conflict_mode"], "keep");

    let missing_err = prepare(
        "ghidra_data_type",
        object(json!({ "operation": "parse_c", "md5": md5, "params": {} })),
    )
    .err()
    .expect("missing required parameter");
    assert!(reason(&missing_err).contains("requires parameter `source`"));
}

/// Checks C type strings and atomic prototype fields across write schemas.
#[test]
fn atomic_prototype_and_c_type_schemas_are_available() {
    let md5 = "0123456789abcdef0123456789abcdef";
    for (domain, operation) in [
        ("ghidra_function", "patch"),
        ("ghidra_data_type", "create"),
        ("ghidra_global_variable", "create"),
    ] {
        let (_, op_help) = help::run(object(json!({
            "domain": domain,
            "operation": operation,
        })))
        .expect("operation help");
        let variants = op_help["inputSchema"]["$defs"]["data_type_reference"]["oneOf"]
            .as_array()
            .expect("data_type_reference oneOf");
        assert_eq!(variants.len(), 5, "{domain} {operation}");
        assert!(variants
            .iter()
            .any(|item| item == &json!({ "type": "string", "minLength": 1 })));
    }

    let (_, patch_help) = help::run(object(json!({
        "domain": "ghidra_function",
        "operation": "patch",
    })))
    .expect("function patch help");
    let patch_props = &patch_help["inputSchema"]["properties"]["patch"]["properties"];
    assert!(patch_props["signature"].is_object());
    assert!(patch_props["parameters"].is_object());

    let (_, sig_req) = prepare(
        "ghidra_function",
        object(json!({
            "operation": "patch",
            "md5": md5,
            "params": {
                "selector": { "entry": "0x401000" },
                "patch": { "signature": "int process(const char *buf, void (*cb)(int))" },
            },
        })),
    )
    .expect("valid signature patch");
    assert_eq!(
        sig_req.params["patch"]["signature"],
        "int process(const char *buf, void (*cb)(int))"
    );

    let (_, params_req) = prepare(
        "ghidra_function",
        object(json!({
            "operation": "patch",
            "md5": md5,
            "params": {
                "selector": { "entry": "0x401000" },
                "patch": {
                    "return_type": "const char *",
                    "parameters": [
                        {
                            "name": "matrix",
                            "data_type": "int (*)[4]",
                            "storage": { "kind": "register", "register": "RDI" },
                        },
                        {
                            "name": "count",
                            "data_type": { "kind": "named", "name": "/uint" },
                        },
                    ],
                },
            },
        })),
    )
    .expect("valid parameters patch");
    assert_eq!(params_req.params["patch"]["return_type"], "const char *");
    assert_eq!(
        params_req.params["patch"]["parameters"][0]["data_type"],
        "int (*)[4]"
    );

    let (_, global_req) = prepare(
        "ghidra_global_variable",
        object(json!({
            "operation": "create",
            "md5": md5,
            "params": {
                "resource": {
                    "address": "0x404000",
                    "name": "g_banner",
                    "data_type": "const char *",
                },
            },
        })),
    )
    .expect("valid global_variable create");
    assert_eq!(global_req.params["resource"]["data_type"], "const char *");
}

/// Checks that compact `tools/list` schemas accept polymorphic C type fields.
#[test]
fn compact_tool_schemas_keep_c_type_fields_untyped() {
    let tools = tool_definitions();
    let params_props = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))["inputSchema"]["properties"]["params"]
            ["properties"]
            .clone()
    };

    let fn_props = params_props("ghidra_function");
    let fn_patch = &fn_props["patch"]["properties"];
    assert!(fn_patch["signature"].is_object());
    assert!(fn_patch["parameters"].is_object());
    assert_eq!(fn_patch["return_type"], json!({}));
    assert_eq!(fn_patch["data_type"], json!({}));
    assert_eq!(fn_props["resource"]["properties"]["data_type"], json!({}));

    let dt_props = params_props("ghidra_data_type");
    assert!(dt_props["conflict_mode"].is_object());
    assert_eq!(dt_props["resource"]["properties"]["base_type"], json!({}));

    let gv_props = params_props("ghidra_global_variable");
    assert_eq!(gv_props["resource"]["properties"]["data_type"], json!({}));
    assert_eq!(gv_props["patch"]["properties"]["data_type"], json!({}));
}
