// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of `ghidra_job cancel` and `ghidra_analysis cancel` tool contracts.

use super::*;

/// Makes sure that `ghidra_job` and `ghidra_analysis` publish the expected
/// cancellation annotations, `md5` rules, help schemas, and bridge route.
#[test]
fn job_and_analysis_cancel_contracts_match() {
    let tools = tool_definitions();
    let job_tool = tools
        .iter()
        .find(|tool| tool["name"] == "ghidra_job")
        .expect("ghidra_job tool");
    assert_eq!(job_tool["annotations"]["readOnlyHint"], false);
    assert_eq!(job_tool["annotations"]["destructiveHint"], false);
    assert_eq!(job_tool["annotations"]["idempotentHint"], true);

    let rule = |tool: &str, operation: &str| {
        super::super::catalog::domain(tool)
            .and_then(|domain| domain.operation(operation))
            .map(|operation| operation.md5)
            .expect("operation")
    };
    assert!(rule("job", "cancel") == Md5Rule::Absent);
    assert!(rule("analysis", "cancel") == Md5Rule::Required);

    let (_, job_cancel_help) = help::run(object(json!({
        "domain": "ghidra_job",
        "operation": "cancel"
    })))
    .expect("ghidra_job cancel help");
    assert_eq!(job_cancel_help["md5"], "absent");
    assert_eq!(job_cancel_help["effects"]["read_only"], false);
    assert_eq!(job_cancel_help["effects"]["idempotent"], true);
    assert!(job_cancel_help["inputSchema"]["properties"]["jobId"].is_object());

    let (cancel_op, cancel_req) = prepare(
        "ghidra_analysis",
        object(json!({
            "operation": "cancel",
            "md5": "0123456789abcdef0123456789abcdef"
        })),
    )
    .expect("valid analysis cancel call");
    match &cancel_op.route {
        Route::Bridge(method) => assert_eq!(method, "analysis.cancel"),
        Route::Local(_) => panic!("ghidra_analysis cancel must go to the bridge"),
    }
    assert_eq!(cancel_req.params, json!({}));
}
