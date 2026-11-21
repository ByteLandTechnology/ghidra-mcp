// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of the tool definitions, the catalog, `ghidra_help`, and the call validation.

use super::catalog::Md5Rule;
use super::{help, prepare, tool_definitions, Route};
use crate::error::DomainError;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

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

/// Returns the operation names of each tool in their sequence, by tool name.
fn operations_by_tool(tools: &[Value]) -> BTreeMap<String, Vec<String>> {
    tools
        .iter()
        .filter_map(|tool| {
            let names = tool["inputSchema"]["properties"]["operation"]["enum"].as_array()?;
            let names = names
                .iter()
                .map(|name| name.as_str().expect("name").to_string());
            Some((
                tool["name"].as_str().expect("tool name").to_string(),
                names.collect(),
            ))
        })
        .collect()
}

/// Makes sure that the bridge domains are the same as the tools of the bridge MCP server.
#[test]
fn bridge_domains_match_the_bridge_mcp_server() {
    let contract: Value =
        serde_json::from_str(include_str!("../../bridge/docs/mcp-tools.json")).expect("contract");
    let bridge_tools = contract["tools"].as_array().expect("bridge tools");
    let mut expected = operations_by_tool(bridge_tools);
    // The daemon hides `shutdown` because `ghidra_session_write close` stops the bridge.
    assert_eq!(
        expected.remove("ghidra_bridge_write"),
        Some(vec!["shutdown".to_string()]),
        "the bridge contract puts shutdown in ghidra_bridge_write"
    );
    let actual = operations_by_tool(&tool_definitions());

    for (tool, operations) in &expected {
        assert_eq!(actual.get(tool), Some(operations), "operations of {tool}");
    }
    let local: BTreeSet<&str> = actual
        .keys()
        .filter(|tool| !expected.contains_key(*tool))
        .map(String::as_str)
        .collect();
    assert_eq!(
        local,
        BTreeSet::from([
            "ghidra_daemon",
            "ghidra_daemon_write",
            "ghidra_job",
            "ghidra_session",
            "ghidra_session_write",
            "ghidra_upload"
        ])
    );
}

/// Makes sure that the help tool is first, and that each domain tool has the
/// correct required arguments and parameter schemas.
#[test]
fn tool_definitions_have_routes_and_schemas() {
    let tools = tool_definitions();
    assert_eq!(tools[0]["name"], "ghidra_help");
    assert_eq!(tools.len(), 31);
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    };
    assert_eq!(
        tool("ghidra_session")["inputSchema"]["required"],
        json!(["operation"])
    );
    assert_eq!(
        tool("ghidra_session_write")["inputSchema"]["required"],
        json!(["operation"])
    );
    assert_eq!(
        tool("ghidra_function")["inputSchema"]["required"],
        json!(["operation", "md5"])
    );
    assert_eq!(
        tool("ghidra_function_write")["inputSchema"]["required"],
        json!(["operation", "md5"])
    );
    assert_eq!(
        tool("ghidra_analysis")["inputSchema"]["required"],
        json!(["operation", "md5"])
    );
    assert_eq!(
        tool("ghidra_analysis_write")["inputSchema"]["required"],
        json!(["operation", "md5"])
    );
    assert_eq!(
        tool("ghidra_batch")["inputSchema"]["properties"]["operation"]["enum"],
        json!(["query"])
    );
    assert_eq!(
        tool("ghidra_batch_write")["inputSchema"]["properties"]["operation"]["enum"],
        json!(["execute"])
    );
    assert!(tool("ghidra_daemon")["inputSchema"]["properties"]
        .get("md5")
        .is_none());
    assert!(tool("ghidra_daemon_write")["inputSchema"]["properties"]
        .get("md5")
        .is_none());

    let session = &tool("ghidra_session")["inputSchema"]["properties"];
    assert!(session["md5"].is_object());
    let session_write = &tool("ghidra_session_write")["inputSchema"]["properties"];
    assert!(session_write["md5"].is_object());
    let job = &tool("ghidra_job")["inputSchema"]["properties"];
    assert!(job.get("md5").is_none());
}

/// Makes sure that each MCP tool publishes accurate read-only and destructive
/// hint annotations.
#[test]
fn tool_definitions_have_accurate_annotations() {
    let tools = tool_definitions();
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    };
    for read_tool in [
        "ghidra_help",
        "ghidra_session",
        "ghidra_job",
        "ghidra_daemon",
        "ghidra_bridge",
        "ghidra_program",
        "ghidra_address",
        "ghidra_memory",
        "ghidra_listing",
        "ghidra_global_variable",
        "ghidra_function",
        "ghidra_analysis",
        "ghidra_decompilation",
        "ghidra_symbol",
        "ghidra_reference",
        "ghidra_comment",
        "ghidra_data_type",
        "ghidra_batch",
    ] {
        assert_eq!(
            tool(read_tool)["annotations"]["readOnlyHint"],
            true,
            "{read_tool} readOnlyHint"
        );
        assert_eq!(
            tool(read_tool)["annotations"]["destructiveHint"],
            false,
            "{read_tool} destructiveHint"
        );
    }
    for non_destructive_write in [
        "ghidra_upload",
        "ghidra_program_write",
        "ghidra_analysis_write",
    ] {
        assert_eq!(
            tool(non_destructive_write)["annotations"]["readOnlyHint"],
            false,
            "{non_destructive_write} readOnlyHint"
        );
        assert_eq!(
            tool(non_destructive_write)["annotations"]["destructiveHint"],
            false,
            "{non_destructive_write} destructiveHint"
        );
    }
    for destructive_write in [
        "ghidra_session_write",
        "ghidra_daemon_write",
        "ghidra_memory_write",
        "ghidra_listing_write",
        "ghidra_global_variable_write",
        "ghidra_function_write",
        "ghidra_symbol_write",
        "ghidra_comment_write",
        "ghidra_data_type_write",
        "ghidra_batch_write",
    ] {
        assert_eq!(
            tool(destructive_write)["annotations"]["readOnlyHint"],
            false,
            "{destructive_write} readOnlyHint"
        );
        assert_eq!(
            tool(destructive_write)["annotations"]["destructiveHint"],
            true,
            "{destructive_write} destructiveHint"
        );
    }
}

/// Makes sure that each domain tool tells the client how to get its parameters.
#[test]
fn tool_definitions_explain_how_to_call_operations() {
    let tools = tool_definitions();
    for tool in &tools[1..] {
        let name = tool["name"].as_str().expect("tool name");
        let description = tool["description"].as_str().expect("description");
        assert!(description.contains(&format!("domain=\"{name}\"")));
        assert!(description.contains("ghidra_help"));
        assert!(description.contains("inputSchema"));
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
    let error = prepare(
        "ghidra_upload",
        object(json!({
            "operation": "prepare",
            "md5": "0123456789abcdef0123456789abcdef",
            "params": {}
        })),
    )
    .err()
    .expect("missing parameters");
    let reason = reason(&error);
    assert!(reason.contains("`fileName`, `size`"), "{reason}");
    assert!(reason.contains("ghidra_help"), "{reason}");
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
    assert!(rule("session_write", "open") == Md5Rule::Optional);
    assert!(rule("session", "get") == Md5Rule::Required);
    assert!(rule("session_write", "close") == Md5Rule::Required);
    assert!(rule("session", "list") == Md5Rule::Absent);
    assert!(rule("upload", "prepare") == Md5Rule::Required);
    assert!(rule("job", "wait") == Md5Rule::Absent);
}

/// Makes sure that Gemini can use each public tool as a function declaration.
#[test]
fn public_tool_contract_is_gemini_compatible() {
    for tool in tool_definitions() {
        let name = tool["name"].as_str().expect("tool name");
        assert!(valid_function_name(name), "tool name {name}");

        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].is_object());
        for unsupported in ["oneOf", "anyOf", "allOf", "$ref", "additionalProperties"] {
            assert!(
                schema.get(unsupported).is_none(),
                "{name} contains {unsupported}"
            );
        }
        assert!(tool.get("outputSchema").is_none());
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

/// Makes sure that `analysis_write start` is local, has the bridge parameters, and takes `md5`.
#[test]
fn local_operation_extends_its_bridge_method() {
    let prepared = prepare(
        "ghidra_analysis_write",
        object(json!({
            "operation": "start",
            "md5": "0123456789ABCDEF0123456789ABCDEF",
            "params": { "analyzers": ["Stack"], "wait": true }
        })),
    )
    .expect("valid call");
    let (operation, request) = prepared;
    assert!(matches!(operation.route, Route::Local(_)));
    assert_eq!(
        request.md5.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
    assert_eq!(request.label, "ghidra_analysis_write start");
}

/// Makes sure that a bridge operation goes to its bridge method.
#[test]
fn bridge_operation_uses_its_bridge_method() {
    let prepared = prepare(
        "ghidra_bridge",
        object(json!({ "operation": "get", "md5": "0123456789abcdef0123456789abcdef" })),
    )
    .expect("valid call");
    let (operation, request) = prepared;
    match &operation.route {
        Route::Bridge(method) => assert_eq!(method, "session.get"),
        Route::Local(_) => panic!("ghidra_bridge get must go to the bridge"),
    }
    assert_eq!(request.params, json!({}));
}

/// Makes sure that `md5: null` is the same as no `md5`.
#[test]
fn null_md5_is_no_md5() {
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

    for (tool, operation) in [
        ("ghidra_session", "open"),
        ("ghidra_session", "close"),
        ("ghidra_daemon", "shutdown"),
        ("ghidra_bridge", "shutdown"),
        ("ghidra_program", "save"),
        ("ghidra_analysis", "start"),
        ("ghidra_function", "create"),
        ("ghidra_memory", "write"),
        ("ghidra_batch", "execute"),
    ] {
        let error = prepare(tool, object(json!({ "operation": operation, "md5": md5 })))
            .err()
            .unwrap_or_else(|| panic!("{tool} {operation} must fail on read-only tool"));
        let domain_err = error.downcast_ref::<DomainError>().expect("domain error");
        assert_eq!(
            domain_err.rpc_code(),
            crate::error::RPC_CODE_INVALID_ARGUMENT,
            "{tool} {operation} must fail with -32602"
        );
    }
}

/// Makes sure that `ghidra_help` lists domains, lists operations, and shows one schema.
#[test]
fn help_has_three_levels() {
    let (_, domains) = help::run(Map::new()).expect("domains");
    let domains = domains["domains"].as_array().expect("domain list");
    assert_eq!(domains.len(), 30);
    assert_eq!(domains[0], "ghidra_session");

    let (_, memory) = help::run(object(json!({ "domain": "memory" }))).expect("operations");
    assert_eq!(memory["domain"], "ghidra_memory");
    let block_list = memory["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .find(|operation| operation["name"] == "block.list")
        .expect("block.list");
    assert_eq!(block_list["md5"], "required");
    assert_eq!(block_list["effects"]["read_only"], true);

    let (_, open) = help::run(object(
        json!({ "domain": "ghidra_session_write", "operation": "open" }),
    ))
    .expect("operation");
    assert_eq!(open["md5"], "optional");
    assert_eq!(open["effects"]["mutates_program"], true);
    assert_eq!(open["effects"]["read_only"], false);
    assert!(open["inputSchema"]["properties"]["path"].is_object());

    let (_, write) = help::run(object(
        json!({ "domain": "memory_write", "operation": "write" }),
    ))
    .expect("operation");
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
        json!({ "domain": "analysis_write", "operation": "start" }),
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

    let (_, listed) = call("ghidra_job", "list").await.unwrap();
    assert_eq!(listed["jobs"][0]["id"], job.id);
    let (_, status) = call("ghidra_daemon", "status").await.unwrap();
    assert_eq!(status["daemon"]["pid"], std::process::id());
    assert_eq!(status["jobs"][0]["id"], job.id);
}

/// Makes sure that `ghidra_daemon_write shutdown` refuses live work without `force`.
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
            "ghidra_daemon_write",
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
