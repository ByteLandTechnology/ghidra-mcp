// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of `ghidra_function` local variable patches and `ghidra_decompilation` fields.

use super::*;

/// Makes sure that local variable patches accept optional storage selectors and
/// that decompilation exposes local variable fields.
#[test]
fn local_variable_patch_and_decompilation_contracts_include_storage() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let with_storage = json!({
        "operation": "local_variable.patch",
        "md5": md5,
        "params": {
            "selector": {
                "entry": "0x1000",
                "name": "uVar1",
                "storage": { "kind": "serialization", "serialization": "HASH:5ff83d9281:4" }
            },
            "patch": { "name": "saved_hash" }
        }
    });
    let (operation, request) = prepare("ghidra_function", object(with_storage)).expect("valid");
    match &operation.route {
        Route::Bridge(method) => assert_eq!(method, "function_local_variable.patch"),
        Route::Local(_) => panic!("local_variable.patch must go to the bridge"),
    }
    assert_eq!(
        request.params["selector"]["storage"]["serialization"],
        "HASH:5ff83d9281:4"
    );

    let without_storage = json!({
        "operation": "local_variable.patch",
        "md5": md5,
        "params": {
            "selector": { "entry": "0x1000", "name": "local_10" },
            "patch": { "name": "count" }
        }
    });
    assert!(prepare("ghidra_function", object(without_storage)).is_ok());

    let (_, patch_help) = help::run(object(json!({
        "domain": "ghidra_function",
        "operation": "local_variable.patch"
    })))
    .expect("local_variable.patch help");
    assert!(
        patch_help["inputSchema"]["properties"]["selector"]["properties"]["storage"].is_object()
    );

    let decomp_call = json!({
        "operation": "get",
        "md5": md5,
        "params": {
            "selector": { "entry": "0x1000" },
            "format": "document",
            "projection": {
                "fields": ["lines", "local_variables", "local_variables.storage"]
            }
        }
    });
    assert!(prepare("ghidra_decompilation", object(decomp_call)).is_ok());
}
