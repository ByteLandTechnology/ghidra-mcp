// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of `ghidra_program` import, export, and entry-point operations.

use super::*;

/// Makes sure that `ghidra_program` and `ghidra_help` expose the import,
/// export, and entry-point list operations as read-only session routes.
#[test]
fn program_import_export_and_entry_point_operations_are_read_only_with_md5() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let (_, list_help) =
        help::run(object(json!({ "domain": "ghidra_program" }))).expect("domain help");
    let listed: Vec<&str> = list_help["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .map(|item| {
            item["name"]
                .as_str()
                .unwrap_or_else(|| item.as_str().expect("name"))
        })
        .collect();
    for operation in ["import.list", "export.list", "entry_point.list"] {
        assert!(
            listed.contains(&operation),
            "absent {operation} in {listed:?}"
        );
        let (_, detail) = help::run(object(json!({
            "domain": "ghidra_program",
            "operation": operation
        })))
        .expect("operation help");
        assert_eq!(detail["domain"], "ghidra_program");
        assert_eq!(detail["operation"], operation);
        assert_eq!(detail["effects"]["read_only"], true);
        assert_eq!(detail["effects"]["mutates_program"], false);
        assert_eq!(detail["inputSchema"]["type"], "object");

        let (resolved, request) = prepare(
            "ghidra_program",
            object(json!({
                "operation": operation,
                "md5": md5,
                "params": { "page": { "limit": 25 } }
            })),
        )
        .expect("valid program call");
        assert!(resolved.md5 == Md5Rule::Required);
        assert!(resolved.effects.read_only);
        assert!(matches!(&resolved.route, Route::Bridge(method) if method == operation));
        assert_eq!(request.md5.as_deref(), Some(md5));
    }
}
