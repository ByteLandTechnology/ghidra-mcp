// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of the tool definitions, the catalog, `ghidra_help`, and the call validation.

use super::catalog::Md5Rule;
use super::{help, prepare, tool_definitions, Route};
use crate::error::DomainError;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Returns the arguments object of a JSON value.
fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        panic!("{value} is not a JSON object");
    };
    map
}

/// Returns the reason of a domain error.
fn reason(error: &anyhow::Error) -> String {
    match error.downcast_ref::<DomainError>() {
        Some(
            DomainError::InvalidArgument { reason, .. } | DomainError::MissingTarget { reason, .. },
        ) => reason.clone(),
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Returns the bridge operation tools and their annotations from a tool list.
fn bridge_operations(tools: &[Value]) -> Vec<(String, Value)> {
    tools
        .iter()
        .filter_map(|tool| {
            let name = tool["name"].as_str()?;
            (name != "ghidra_help").then(|| (name.to_string(), tool["annotations"].clone()))
        })
        .collect()
}

/// Makes sure that the bridge operations match the tools of the bridge MCP server.
#[test]
fn bridge_domains_match_the_bridge_mcp_server() {
    let contract: Value =
        serde_json::from_str(include_str!("../../bridge/docs/mcp-tools.json")).expect("contract");
    let bridge_tools = contract["tools"].as_array().expect("bridge tools");
    let mut expected = bridge_operations(bridge_tools);
    // The daemon hides `ghidra_bridge_shutdown`: `ghidra_session_close` stops the bridge.
    let count = expected.len();
    expected.retain(|(name, _)| name != "ghidra_bridge_shutdown");
    assert_eq!(
        expected.len() + 1,
        count,
        "the bridge contract has ghidra_bridge_shutdown"
    );

    let actual = bridge_operations(&tool_definitions());
    let expected_names: BTreeSet<&str> = expected.iter().map(|(name, _)| name.as_str()).collect();
    let shared: Vec<(String, Value)> = actual
        .iter()
        .filter(|(name, _)| expected_names.contains(name.as_str()))
        .cloned()
        .collect();
    assert_eq!(shared, expected);

    let local: Vec<&str> = actual
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !expected_names.contains(name))
        .collect();
    assert_eq!(
        local,
        vec![
            "ghidra_session_open",
            "ghidra_session_list",
            "ghidra_session_get",
            "ghidra_session_close",
            "ghidra_upload_prepare",
            "ghidra_job_get",
            "ghidra_job_wait",
            "ghidra_job_list",
            "ghidra_daemon_status",
            "ghidra_daemon_shutdown",
        ]
    );
}

/// Makes sure that the help tool is first, and that each operation tool has the
/// correct required arguments and annotations.
#[test]
fn tool_definitions_have_routes_and_annotations() {
    let tools = tool_definitions();
    assert_eq!(tools[0]["name"], "ghidra_help");
    assert_eq!(tools.len(), 65);
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    };
    assert!(tool("ghidra_session_open")["inputSchema"]["properties"]["md5"].is_object());
    assert!(tool("ghidra_session_open")["inputSchema"]
        .get("required")
        .is_none());
    assert_eq!(
        tool("ghidra_session_get")["inputSchema"]["required"],
        json!(["md5"])
    );
    assert!(tool("ghidra_session_list")["inputSchema"]["properties"]
        .get("md5")
        .is_none());
    assert_eq!(
        tool("ghidra_function_list")["inputSchema"]["required"],
        json!(["md5"])
    );
    assert_eq!(
        tool("ghidra_analysis_start")["inputSchema"]["required"],
        json!(["md5"])
    );
    assert!(tool("ghidra_daemon_status")["inputSchema"]["properties"]
        .get("md5")
        .is_none());
    assert!(tool("ghidra_job_list")["inputSchema"]["properties"]
        .get("md5")
        .is_none());

    for read_only in [
        "ghidra_decompilation_get",
        "ghidra_reference_list",
        "ghidra_memory_read",
        "ghidra_session_list",
        "ghidra_job_list",
        "ghidra_daemon_status",
    ] {
        assert_eq!(tool(read_only)["annotations"]["readOnlyHint"], true);
        assert_eq!(tool(read_only)["annotations"]["destructiveHint"], false);
        assert_eq!(tool(read_only)["annotations"]["openWorldHint"], false);
    }
    for additive in [
        "ghidra_function_create",
        "ghidra_comment_create",
        "ghidra_session_open",
        "ghidra_upload_prepare",
    ] {
        assert_eq!(tool(additive)["annotations"]["readOnlyHint"], false);
        assert_eq!(tool(additive)["annotations"]["destructiveHint"], false);
        assert_eq!(tool(additive)["annotations"]["openWorldHint"], false);
    }
    for destructive in [
        "ghidra_memory_write",
        "ghidra_function_delete",
        "ghidra_session_close",
        "ghidra_daemon_shutdown",
    ] {
        assert_eq!(tool(destructive)["annotations"]["readOnlyHint"], false);
        assert_eq!(tool(destructive)["annotations"]["destructiveHint"], true);
        assert_eq!(tool(destructive)["annotations"]["openWorldHint"], false);
    }
}

/// Makes sure that each operation tool has a clear description and md5 guidance.
#[test]
fn tool_definitions_explain_how_to_call_operations() {
    let tools = tool_definitions();
    for tool in &tools[1..] {
        let name = tool["name"].as_str().expect("tool name");
        let description = tool["description"].as_str().expect("description");
        assert!(!description.is_empty(), "{name} description");
        assert!(
            tool["inputSchema"]["properties"].get("params").is_none(),
            "{name} has legacy params wrapper"
        );
        if let Some(md5) = tool["inputSchema"]["properties"].get("md5") {
            let description = md5["description"].as_str().expect("md5 description");
            assert!(description.contains("32 hexadecimal characters"));
            assert!(description.contains("not a name or label"));
        }
    }
}

/// Makes sure that one error gives all absent parameters and the help tool.
#[test]
fn missing_parameters_are_reported_together() {
    let md5 = "0123456789abcdef0123456789abcdef";
    for (tool, arguments) in [
        ("ghidra_upload_prepare", json!({ "md5": md5 })),
        (
            "ghidra_upload",
            json!({ "operation": "prepare", "md5": md5, "params": {} }),
        ),
    ] {
        let error = prepare(tool, object(arguments))
            .err()
            .expect("absent parameters");
        let reason = reason(&error);
        assert!(reason.contains("`fileName`, `size`"), "{reason}");
        assert!(reason.contains("ghidra_help"), "{reason}");
    }
}

/// Makes sure that each operation that names one session takes `md5` at the
/// top level and never in `params`.
#[test]
fn session_md5_is_never_a_parameter() {
    for domain in super::catalog::domains() {
        for operation in &domain.operations {
            assert!(
                operation.schema["properties"].get("md5").is_none(),
                "{} {} has md5 in params",
                domain.name,
                operation.name
            );
        }
    }
    let rule = |tool: &str, operation: &str| {
        super::catalog::domain(tool)
            .and_then(|domain| domain.operation(operation))
            .map(|operation| operation.md5)
            .expect("operation")
    };
    assert!(rule("session", "open") == Md5Rule::Optional);
    assert!(rule("session", "get") == Md5Rule::Required);
    assert!(rule("session", "close") == Md5Rule::Required);
    assert!(rule("session", "list") == Md5Rule::Absent);
    assert!(rule("upload", "prepare") == Md5Rule::Required);
    assert!(rule("job", "wait") == Md5Rule::Absent);
}

/// Makes sure that Gemini can use each public tool as a function declaration.
#[test]
fn public_tool_contract_is_gemini_compatible() {
    let tools = tool_definitions();
    assert_eq!(tools.len(), 65);
    let mut names = BTreeSet::new();
    for tool in &tools {
        let name = tool["name"].as_str().expect("tool name");
        assert!(names.insert(name), "duplicate tool name {name}");
        assert!(valid_function_name(name), "tool name {name}");

        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].is_object());
        assert_no_unsupported_schema_keys(name, schema);
        assert!(tool.get("outputSchema").is_none());
    }

    let tool = |name: &str| {
        tools
            .iter()
            .find(|item| item["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    };
    assert!(tool("ghidra_listing_data_unit_list")["description"]
        .as_str()
        .expect("data unit list description")
        .contains("data unit"));
    assert_eq!(
        tool("ghidra_upload_prepare")["inputSchema"]["required"],
        json!(["md5", "fileName", "size"])
    );
    assert_eq!(
        tool("ghidra_decompilation_get")["inputSchema"]["required"],
        json!(["md5", "selector"])
    );
    assert_eq!(
        tool("ghidra_reference_list")["inputSchema"]["required"],
        json!(["md5", "filter"])
    );
    assert_eq!(
        tool("ghidra_batch_execute")["inputSchema"]["required"],
        json!(["md5", "items"])
    );
    assert_eq!(
        tool("ghidra_job_wait")["inputSchema"]["required"],
        json!(["jobId"])
    );
    assert!(
        tool("ghidra_function_parameter_create")["inputSchema"]["properties"]["resource"]
            ["properties"]["data_type"]["properties"]["target"]["properties"]["kind"]
            .is_object()
    );
}

/// Examines a schema tree to verify that unsupported provider keys never appear.
fn assert_no_unsupported_schema_keys(name: &str, value: &Value) {
    match value {
        Value::Object(map) => {
            for unsupported in [
                "oneOf",
                "anyOf",
                "allOf",
                "$ref",
                "$defs",
                "additionalProperties",
            ] {
                assert!(
                    map.get(unsupported).is_none(),
                    "{name} contains {unsupported}"
                );
            }
            for child in map.values() {
                assert_no_unsupported_schema_keys(name, child);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_unsupported_schema_keys(name, item);
            }
        }
        _ => {}
    }
}

/// Returns `true` for a Gemini function name that does not need conversion.
fn valid_function_name(name: &str) -> bool {
    name.len() <= 64
        && name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Makes sure that `analysis start` is local, has the bridge parameters, and takes `md5`.
#[test]
fn local_operation_extends_its_bridge_method() {
    for (tool, arguments, expected_label) in [
        (
            "ghidra_analysis_start",
            json!({
                "md5": "0123456789ABCDEF0123456789ABCDEF",
                "analyzers": ["Stack"],
                "wait": true
            }),
            "ghidra_analysis_start",
        ),
        (
            "ghidra_analysis",
            json!({
                "operation": "start",
                "md5": "0123456789ABCDEF0123456789ABCDEF",
                "params": { "analyzers": ["Stack"], "wait": true }
            }),
            "ghidra_analysis start",
        ),
    ] {
        let (operation, request) = prepare(tool, object(arguments)).expect("valid call");
        assert!(matches!(operation.route, Route::Local(_)));
        assert_eq!(
            request.md5.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(request.label, expected_label);
        assert_eq!(
            request.params,
            json!({ "analyzers": ["Stack"], "wait": true })
        );
    }
}

/// Makes sure that a bridge operation goes to its bridge method.
#[test]
fn bridge_operation_uses_its_bridge_method() {
    for (tool, arguments) in [
        (
            "ghidra_bridge_get",
            json!({ "md5": "0123456789abcdef0123456789abcdef" }),
        ),
        (
            "ghidra_bridge",
            json!({ "operation": "get", "md5": "0123456789abcdef0123456789abcdef" }),
        ),
    ] {
        let (operation, request) = prepare(tool, object(arguments)).expect("valid call");
        match &operation.route {
            Route::Bridge(method) => assert_eq!(method, "session.get"),
            Route::Local(_) => panic!("{tool} must go to the bridge"),
        }
        assert_eq!(request.params, json!({}));
    }
}

/// Makes sure that `md5: null` is the same as no `md5`.
#[test]
fn null_md5_is_no_md5() {
    let (_, flat_request) = prepare("ghidra_session_list", object(json!({ "md5": null })))
        .expect("null md5 on flat tool without md5");
    assert!(flat_request.md5.is_none());
    let flat_error = prepare("ghidra_session_get", object(json!({ "md5": null })))
        .err()
        .expect("null md5 on flat tool that requires md5");
    assert!(reason(&flat_error).contains("`ghidra_session_get` requires md5"));

    let (_, request) = prepare(
        "ghidra_session",
        object(json!({ "operation": "list", "md5": null })),
    )
    .expect("null md5 for an operation without md5");
    assert!(request.md5.is_none());
    let error = prepare(
        "ghidra_session",
        object(json!({ "operation": "get", "md5": null })),
    )
    .err()
    .expect("null md5 for an operation that requires md5");
    assert!(reason(&error).contains("`ghidra_session get` requires md5"));
}

/// Makes sure that `prepare` refuses calls that are not valid.
#[test]
fn prepare_refuses_invalid_calls() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let cases = [
        ("ghidra", json!({ "operation": "list" }), "unknown tool"),
        (
            "ghidra_ghidra_session",
            json!({ "operation": "list" }),
            "unknown tool",
        ),
        ("session", json!({ "operation": "list" }), "unknown tool"),
        (
            "ghidra_bridge",
            json!({ "operation": "shutdown", "md5": md5 }),
            "unknown operation",
        ),
        (
            "ghidra_bridge_shutdown",
            json!({ "md5": md5 }),
            "unknown tool",
        ),
        (
            "ghidra_session_list",
            json!({ "md5": md5 }),
            "does not accept md5",
        ),
        (
            "ghidra_session_get",
            json!({}),
            "`ghidra_session_get` requires md5",
        ),
        (
            "ghidra_function_list",
            json!({ "md5": "x" }),
            "invalid arguments",
        ),
        (
            "ghidra_session_list",
            json!({ "extra": 1 }),
            "does not accept parameter `extra`",
        ),
        (
            "ghidra_nothing",
            json!({ "operation": "list" }),
            "unknown tool",
        ),
        ("ghidra_session", json!({}), "missing field `operation`"),
        (
            "ghidra_session",
            json!({ "operation": "nothing" }),
            "unknown operation",
        ),
        (
            "ghidra_session",
            json!({ "operation": "list", "command": "x" }),
            "unknown field",
        ),
        (
            "ghidra_session",
            json!({ "operation": "list", "md5": md5 }),
            "does not accept md5",
        ),
        (
            "ghidra_session",
            json!({ "operation": "get" }),
            "`ghidra_session get` requires md5",
        ),
        (
            "ghidra_session",
            json!({ "operation": "get", "md5": md5, "params": { "md5": md5 } }),
            "does not accept parameter `md5`",
        ),
        (
            "ghidra_upload",
            json!({ "operation": "prepare", "params": { "fileName": "a", "size": 1 } }),
            "requires md5",
        ),
        (
            "ghidra_function",
            json!({ "operation": "list" }),
            "requires md5",
        ),
        (
            "ghidra_function",
            json!({ "operation": "list", "md5": "x" }),
            "invalid arguments",
        ),
        (
            "ghidra_session",
            json!({ "operation": "list", "params": { "extra": 1 } }),
            "does not accept parameter `extra`",
        ),
    ];
    for (tool, arguments, expected) in cases {
        let error = prepare(tool, object(arguments.clone()))
            .err()
            .unwrap_or_else(|| panic!("{tool} {arguments} must fail"));
        let reason = reason(&error);
        assert!(reason.contains(expected), "{tool} {arguments}: {reason}");
    }
}

/// Makes sure that `ghidra_help` lists domains, lists operations, and shows one schema.
#[test]
fn help_has_three_levels() {
    let (_, domains) = help::run(Map::new()).expect("domains");
    let domains = domains["domains"].as_array().expect("domain list");
    assert_eq!(domains.len(), 18);
    assert_eq!(domains[0], "ghidra_session");

    let (_, memory) = help::run(object(json!({ "domain": "memory" }))).expect("operations");
    assert_eq!(memory["domain"], "ghidra_memory");
    let memory_operations = memory["operations"].as_array().expect("operations");
    assert_ne!(memory_operations.len(), 0);
    for entry in memory_operations {
        assert!(entry["description"]
            .as_str()
            .is_some_and(|text| !text.is_empty()));
        assert!(entry["effects"].is_object());
        assert_eq!(entry["inputSchema"]["type"], "object");
    }
    let block_list = memory_operations
        .iter()
        .find(|operation| operation["name"] == "block.list")
        .expect("block.list");
    assert_eq!(block_list["tool"], "ghidra_memory_block_list");
    assert_eq!(block_list["md5"], "required");
    assert_eq!(block_list["effects"]["read_only"], true);
    assert!(block_list["inputSchema"]["properties"].is_object());

    let (_, open) = help::run(object(
        json!({ "domain": "ghidra_session", "operation": "open" }),
    ))
    .expect("operation");
    assert_eq!(open["tool"], "ghidra_session_open");
    assert_eq!(open["md5"], "optional");
    assert_eq!(open["effects"]["mutates_program"], true);
    assert_eq!(open["effects"]["read_only"], false);
    assert!(open["inputSchema"]["properties"]["path"].is_object());

    let (_, write) =
        help::run(object(json!({ "domain": "memory", "operation": "write" }))).expect("operation");
    assert_eq!(
        write["effects"],
        json!({
            "read_only": false,
            "mutates_program": true,
            "destructive": true,
            "idempotent": true,
            "allowed_during_analysis": false,
            "requires_transaction": true
        })
    );

    let (_, start) = help::run(object(
        json!({ "domain": "analysis", "operation": "start" }),
    ))
    .expect("operation");
    let properties = &start["inputSchema"]["properties"];
    assert!(properties["analyzers"].is_object() && properties["wait"].is_object());
    assert!(properties.get("md5").is_none());
    assert_eq!(start["md5"], "required");
    assert_eq!(start["effects"]["mutates_program"], true);

    let (_, upload) = help::run(object(
        json!({ "domain": "ghidra_upload", "operation": "prepare" }),
    ))
    .expect("upload operation");
    let upload_params = &upload["inputSchema"];
    assert_eq!(upload_params["required"], json!(["fileName", "size"]));
    assert!(upload_params["properties"]["fileName"]["description"]
        .as_str()
        .expect("file name description")
        .contains("without a directory"));
    assert!(upload_params["properties"]["size"]["description"]
        .as_str()
        .expect("size description")
        .contains("exact file size in bytes"));

    for (arguments, expected) in [
        (json!({ "operation": "get" }), "requires domain"),
        (json!({ "domain": "nothing" }), "unknown domain"),
        (
            json!({ "domain": "job", "operation": "nothing" }),
            "unknown operation",
        ),
        (json!({ "category": "job" }), "unknown field"),
    ] {
        let error = help::run(object(arguments.clone())).expect_err("invalid help");
        assert!(reason(&error).contains(expected), "{arguments}: {error}");
    }
}

/// Makes a daemon without Ghidra processes, for the local operations.
fn test_daemon(root: &std::path::Path) -> super::Daemon {
    let state = crate::state::test_state(root);
    std::fs::create_dir_all(&state.paths.tmp_dir).unwrap();
    let authorities = ["127.0.0.1:1".to_string(), "localhost:1".to_string()];
    let uploads = crate::upload::UploadService::new(
        state.clone(),
        authorities,
        tokio_util::sync::CancellationToken::new(),
    )
    .unwrap();
    super::Daemon {
        state,
        uploads,
        control: super::Control::default(),
    }
}

/// Makes sure that `ghidra_job list` and `ghidra_daemon status` show the jobs.
#[tokio::test]
async fn job_list_and_daemon_status_show_jobs() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let job = daemon.state.insert_job("analysis", None);
    let call = |tool: &'static str, operation: &'static str| {
        super::call(&daemon, tool, object(json!({ "operation": operation })))
    };

    let (_, listed) = super::call(&daemon, "ghidra_job_list", Map::new())
        .await
        .unwrap();
    assert_eq!(listed["jobs"][0]["id"], job.id);
    let (_, status) = super::call(&daemon, "ghidra_daemon_status", Map::new())
        .await
        .unwrap();
    assert_eq!(status["daemon"]["pid"], std::process::id());
    assert_eq!(status["jobs"][0]["id"], job.id);

    let (_, legacy_listed) = call("ghidra_job", "list").await.unwrap();
    assert_eq!(legacy_listed["jobs"][0]["id"], job.id);
    let (_, legacy_status) = call("ghidra_daemon", "status").await.unwrap();
    assert_eq!(legacy_status["daemon"]["pid"], std::process::id());
    assert_eq!(legacy_status["jobs"][0]["id"], job.id);
}

/// Makes sure that `ghidra_daemon shutdown` refuses live work without `force`.
#[tokio::test]
async fn daemon_shutdown_needs_force_for_live_work() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";
    let record = crate::model::SessionRecord::launching(md5.into(), "bin".into(), "t".into());
    daemon.state.put_session(&record).unwrap();
    let shutdown = |force: bool| {
        super::call(
            &daemon,
            "ghidra_daemon",
            object(json!({ "operation": "shutdown", "params": { "force": force } })),
        )
    };

    let error = shutdown(false).await.unwrap_err();
    assert!(reason(&error).contains(md5), "{error:#}");
    assert!(!daemon.control.shutdown.is_cancelled());

    let (_, result) = shutdown(true).await.unwrap();
    assert_eq!(result["sessions"], json!([md5]));
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        daemon.control.shutdown.cancelled(),
    )
    .await
    .expect("shutdown starts after the reply");
}

/// Makes sure that `params` accepts `null` and a JSON object string.
#[tokio::test]
async fn params_accepts_null_and_json_object_string() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let (_, null_request) = prepare(
        "ghidra_session",
        object(json!({ "operation": "list", "params": null })),
    )
    .expect("null params");
    assert_eq!(null_request.params, json!({}));

    let (_, string_request) = prepare(
        "ghidra_upload",
        object(json!({
            "operation": "prepare",
            "md5": md5,
            "params": "{\"fileName\":\"sample.bin\",\"size\":64}"
        })),
    )
    .expect("JSON object string params");
    assert_eq!(
        string_request.params,
        json!({ "fileName": "sample.bin", "size": 64 })
    );

    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let (_, result) = super::call(
        &daemon,
        "ghidra_daemon",
        object(json!({ "operation": "shutdown", "params": "{\"force\":true}" })),
    )
    .await
    .expect("local call with JSON object string params");
    assert_eq!(result["sessions"], json!([]));
}

/// Makes sure that `params` refuses non-object values and non-object JSON text.
#[test]
fn params_refuses_non_object_values_and_text() {
    let cases = [
        json!([1, 2]),
        json!(42),
        json!(true),
        json!("[1, 2]"),
        json!("123"),
        json!("\"hello\""),
        json!("true"),
        json!("null"),
        json!("{bad json"),
    ];
    for params in cases {
        let error = prepare(
            "ghidra_session",
            object(json!({ "operation": "list", "params": params })),
        )
        .err()
        .unwrap_or_else(|| panic!("params {params} must fail"));
        match error.downcast_ref::<DomainError>() {
            Some(domain @ DomainError::InvalidArgument { reason, .. }) => {
                assert_eq!(domain.rpc_code(), crate::error::RPC_CODE_INVALID_ARGUMENT);
                assert!(reason.contains("invalid_type"), "{params}: {reason}");
            }
            other => panic!("unexpected error for {params}: {other:?}"),
        }
    }
}

/// Makes sure that unknown parameters list sorted valid parameters and `ghidra_help`.
#[test]
fn unknown_parameter_lists_valid_parameters_and_help() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let upload_error = prepare(
        "ghidra_upload",
        object(json!({
            "operation": "prepare",
            "md5": md5,
            "params": { "fileName": "sample.bin", "size": 1, "extra": true }
        })),
    )
    .err()
    .expect("unknown upload parameter");
    let upload_reason = reason(&upload_error);
    assert!(
        upload_reason.contains("does not accept parameter `extra`"),
        "{upload_reason}"
    );
    assert!(
        upload_reason.contains("Valid parameters: `fileName`, `size`."),
        "{upload_reason}"
    );
    assert!(upload_reason.contains("ghidra_help"), "{upload_reason}");

    let empty_error = prepare(
        "ghidra_session",
        object(json!({ "operation": "list", "params": { "extra": 1 } })),
    )
    .err()
    .expect("unknown parameter on empty schema");
    let empty_reason = reason(&empty_error);
    assert!(
        empty_reason.contains("Valid parameters: none."),
        "{empty_reason}"
    );
    assert!(empty_reason.contains("ghidra_help"), "{empty_reason}");
}

/// Makes sure that `DomainError::from_bridge` forwards address `target` and spaces.
#[test]
fn bridge_address_error_preserves_target_and_spaces() {
    let rpc_error = crate::model::RpcError {
        code: "invalid_request".to_string(),
        message: "unable to parse address: bad (valid spaces: [EXTERNAL, ram])".to_string(),
        target: Some("/selector/address".to_string()),
    };
    let domain = DomainError::from_bridge(Some(400), &rpc_error);
    assert_eq!(
        domain,
        DomainError::InvalidArgument {
            param: "/selector/address".to_string(),
            reason: "unable to parse address: bad (valid spaces: [EXTERNAL, ram])".to_string(),
        }
    );
}
